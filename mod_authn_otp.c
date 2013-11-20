
/*
 * mod_authn_otp - Apache module for one-time password authentication
 *
 * Copyright 2009 Archie L. Cobbs <archie@dellroad.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * $Id$
 */

#include "apr_lib.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "mod_auth.h"

// Fix libapr pollution
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "config.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_time.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_md5.h"

#include <time.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

/* Apache backward-compat */
#ifndef AUTHN_PROVIDER_VERSION
#define AUTHN_PROVIDER_VERSION "0"
#endif
#if AP_MODULE_MAGIC_AT_LEAST(20111203, 0)
#define USER_AGENT_IP(req)  ((req)->useragent_ip)
#else
#define USER_AGENT_IP(req)  ((req)->connection->remote_ip)
#endif

/* Module definition */
module AP_MODULE_DECLARE_DATA authn_otp_module;

/* Our unique authentication provider name */
#define OTP_AUTHN_PROVIDER_NAME         "OTP"

/* Definitions related to users file */
#define WHITESPACE                      " \t\r\n\v"
#define NEWFILE_SUFFIX                  ".new"
#define LOCKFILE_SUFFIX                 ".lock"
#define PIN_EXTERNAL                    "+"
#define PIN_NONE                        "-"

/* Formatting of time values */
#if HAVE_STRPTIME
#define TIME_FORMAT                     "%Y-%m-%dT%H:%M:%SL"
#endif

/* OTP counter algorithms */
#define OTP_ALGORITHM_HOTP              1
#define OTP_ALGORITHM_MOTP              2

/* Default configuration settings */
#define DEFAULT_NUM_DIGITS              6
#define DEFAULT_MAX_OFFSET              4
#define DEFAULT_MAX_LINGER              (10 * 60)   /* 10 minutes */
#define DEFAULT_LOGOUT_IP_CHANGE        0
#define DEFAULT_ALLOW_FALLTHROUGH       0

/* PIN configuration */
#define PIN_CONFIG_LITERAL              0
#define PIN_CONFIG_NONE                 1           /* User has no PIN */
#define PIN_CONFIG_EXTERNAL             2           /* PIN must be gotten from OTPAuthPINAuthProvider */

/* MobileOTP defaults */
#define MOTP_TIME_INTERVAL              10

/* Buffer size for OTPs */
#define OTP_BUF_SIZE                    16

/* Other buffer sizes */
#define MAX_USERNAME                    128
#define MAX_PIN                         128
#define MAX_KEY                         256
#define MAX_OTP                         128
#define MAX_IP                          128
#define MAX_TOKEN                       128

/* Per-directory configuration */
struct otp_config {
    char                *users_file;            /* Name of the users file */
    int                 max_offset;             /* Maximum allowed counter offset from expected value */
    int                 max_linger;             /* Maximum time for which the same OTP can be used repeatedly */
    u_int               max_otp_failures;       /* Maximum wrong OTP values before account becomes locked, or zero for no limit */
    int                 logout_ip_change;       /* Auto-logout user if IP address changes */
    int                 allow_fallthrough;      /* Allow fall-through if OTP auth fails */
    authn_provider_list *provlist;              /* Authorization providers for checking PINs */
};

/* User info structure */
struct otp_user {
    int                 algorithm;              /* one of OTP_ALGORITHM_* */
    int                 time_interval;          /* in seconds, or zero for event-based tokens */
    int                 num_digits;
    char                username[MAX_USERNAME];
    u_char              key[MAX_KEY];
    int                 keylen;
    int                 pincfg;                 /* one of PIN_CONFIG_* */
    char                pin[MAX_PIN];
    long                offset;                 /* if event: next expected count; if time: time slew */
    char                last_otp[MAX_OTP];
    time_t              last_auth;
    char                last_ip[MAX_IP];
    u_int               num_otp_failures;
};

/* Internal functions */
static authn_status find_update_user(request_rec *r, const char *usersfile, struct otp_user *const user, int update);
static void         hotp(const u_char *key, size_t keylen, u_long counter, int ndigits, char *buf10, char *buf16, size_t buflen);
static void         motp(const u_char *key, size_t keylen, const char *pin, u_long counter, int ndigits, char *buf, size_t buflen);
static int          parse_token_type(const char *type, struct otp_user *tokinfo);
static apr_status_t print_user(apr_file_t *file, const struct otp_user *user);
static void         printhex(char *buf, size_t buflen, const u_char *data, size_t dlen, int max_digits);
static authn_status authn_otp_check_pin(request_rec *r, struct otp_config *const conf, struct otp_user *const user, const char *pin);
static authn_status authn_otp_check_pin_external(request_rec *r, struct otp_config *const conf, const char *user, const char *pin);
static authn_status authn_otp_check_password(request_rec *r, const char *username, const char *password);
static authn_status authn_otp_get_realm_hash(request_rec *r, const char *username, const char *realm, char **rethash);
static void         *create_authn_otp_dir_config(apr_pool_t *p, char *d);
static void         *merge_authn_otp_dir_config(apr_pool_t *p, void *base_conf, void *new_conf);
static const char   *add_authn_provider(cmd_parms *cmd, void *config, const char *provider_name);
static void         copy_provider_list(apr_pool_t *p, authn_provider_list **dstp, authn_provider_list *src);
static struct       otp_config *get_config(request_rec *r);
static void         register_hooks(apr_pool_t *p);

/* Powers of ten */
static const int    powers10[] = { 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 1000000000 };

/*
 * Find/update a user in the users file.
 *
 * Note: finding, the "user" structure must be initialized with zeroes.
 */
static authn_status
find_update_user(request_rec *r, const char *usersfile, struct otp_user *const user, int update)
{
    char invalid_reason[128];
    char newusersfile[APR_PATH_MAX];
    char lockusersfile[APR_PATH_MAX];
    char linebuf[1024];
    apr_file_t *file = NULL;
    apr_file_t *newfile = NULL;
    apr_file_t *lockfile = NULL;
    apr_status_t status;
    char errbuf[64];
    int found = 0;
    int linenum;

    /* If updating, open and lock lockfile */
    if (update) {
        apr_snprintf(lockusersfile, sizeof(lockusersfile), "%s%s", usersfile, LOCKFILE_SUFFIX);
        if ((status = apr_file_open(&lockfile, lockusersfile,
          APR_WRITE|APR_CREATE|APR_TRUNCATE, APR_UREAD|APR_UWRITE, r->pool)) != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "can't open OTP users lock file \"%s\": %s",
              lockusersfile, apr_strerror(status, errbuf, sizeof(errbuf)));
            goto fail;
        }
        if ((status = apr_file_lock(lockfile, APR_FLOCK_EXCLUSIVE)) != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "can't lock OTP users lock file \"%s\": %s",
              lockusersfile, apr_strerror(status, errbuf, sizeof(errbuf)));
            goto fail;
        }
    }

    /* Open existing users file */
    if ((status = apr_file_open(&file, usersfile, APR_READ, 0, r->pool)) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "can't open OTP users file \"%s\": %s",
          usersfile, apr_strerror(status, errbuf, sizeof(errbuf)));
        goto fail;
    }

    /* Open new users file if updating */
    if (update) {
        apr_snprintf(newusersfile, sizeof(newusersfile), "%s%s", usersfile, NEWFILE_SUFFIX);
        if ((status = apr_file_open(&newfile, newusersfile,
          APR_WRITE|APR_CREATE|APR_TRUNCATE, APR_UREAD|APR_UWRITE, r->pool)) != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "can't new open OTP users file \"%s\": %s", newusersfile,
              apr_strerror(status, errbuf, sizeof(errbuf)));
            goto fail;
        }
    }

    /* Scan entries */
    for (linenum = 1; apr_file_gets(linebuf, sizeof(linebuf), file) == 0; linenum++) {
        struct otp_user tokinfo;
        int nibs[2];
        char linecopy[1024];
        char *fields[4];
        int field_count;
        char *fail_count;
        char *timestamp;
        char *last_otp;
        char *last_ip;
        char *last;
        char *s;
        int i;

        /* Save a copy of the line */
        apr_snprintf(linecopy, sizeof(linecopy), "%s", linebuf);

        /* Ignore lines starting with '#' and empty lines */
        if (*linebuf == '#')
            goto copy;
        if ((s = apr_strtok(linebuf, WHITESPACE, &last)) == NULL)
            goto copy;

        /* Parse token type */
        if (parse_token_type(s, &tokinfo) != 0) {
            apr_snprintf(invalid_reason, sizeof(invalid_reason), "invalid token type \"%s\"", s);
            goto invalid;
        }

        /* Get username */
        if ((s = apr_strtok(NULL, WHITESPACE, &last)) == NULL) {
            apr_snprintf(invalid_reason, sizeof(invalid_reason), "missing username field");
            goto invalid;
        }

        /* Is this the user we're interested in? */
        if (strcmp(s, user->username) != 0)
            goto copy;
        found = 1;

        /* If we're updating, print out updated user info to new file */
        if (update) {
            if ((status = print_user(newfile, user)) != 0)
                goto write_error;
            continue;
        }

        /* Initialize user record */
        memset(user, 0, sizeof(*user));
        apr_snprintf(user->username, sizeof(user->username), "%s", s);
        user->algorithm = tokinfo.algorithm;
        user->time_interval = tokinfo.time_interval;
        user->num_digits = tokinfo.num_digits;

        /* Read PIN and decode special values */
        if ((s = apr_strtok(NULL, WHITESPACE, &last)) == NULL) {
            apr_snprintf(invalid_reason, sizeof(invalid_reason), "missing PIN field");
            goto invalid;
        }
        if (strcmp(s, PIN_NONE) == 0) {
            *s = '\0';
            user->pincfg = PIN_CONFIG_NONE;
        } else if (strcmp(s, PIN_EXTERNAL) == 0) {
            *s = '\0';
            user->pincfg = PIN_CONFIG_EXTERNAL;
        } else
            user->pincfg = PIN_CONFIG_LITERAL;
        apr_snprintf(user->pin, sizeof(user->pin), "%s", s);

        /* Read key */
        if ((s = apr_strtok(NULL, WHITESPACE, &last)) == NULL) {
            apr_snprintf(invalid_reason, sizeof(invalid_reason), "missing token key field");
            goto invalid;
        }
        for (user->keylen = 0; user->keylen < sizeof(user->key) && *s != '\0'; user->keylen++) {
            for (i = 0; i < 2; i++) {
                if (apr_isdigit(*s))
                    nibs[i] = *s - '0';
                else if (apr_isxdigit(*s))
                    nibs[i] = apr_tolower(*s) - 'a' + 10;
                else {
                    apr_snprintf(invalid_reason, sizeof(invalid_reason), "invalid key starting with \"%s\"", s);
                    goto invalid;
                }
                s++;
            }
            user->key[user->keylen] = (nibs[0] << 4) | nibs[1];
        }

        /* Read offset (optional) */
        if ((s = apr_strtok(NULL, WHITESPACE, &last)) == NULL)
            goto found;
        user->offset = atol(s);

        /*
         * At this point, we will read one of the following remaining field combinations. The reason
         * for these cases is because of backward compatibility with older versions of the users file.
         *
         * 0. No more fields
         * 1. Fail count
         * 2. Fail count, Last OTP, Timestamp, IP Address
         * 3. Last OTP, Timestamp
         * 4. Last OTP, Timestamp, IP Address
         *
         * Note that in each case, a different number of fields is found, so we can use the field count
         * to determine which case we're in.
         */
        for (i = field_count = 0; i < 4; i++) {
            if ((fields[i] = apr_strtok(NULL, WHITESPACE, &last)) != NULL)
                field_count++;
        }

        /* Interpret fields based on cases 0..4 */
        i = 0;
        fail_count = (field_count < 2 || field_count == 4) ? fields[i++] : NULL;
        last_otp = fields[i++];
        timestamp = fields[i++];
        last_ip = fields[i++];

        /* Parse OTP failure count (if any) */
        if (fail_count != NULL)
            user->num_otp_failures = atoi(fail_count);

        /* Parse last used OTP and parse last successful authentication timestamp (if any) */
        if (last_otp != NULL && timestamp != NULL) {
#if HAVE_STRPTIME
            struct tm tm;
#else
            char *eptr;
            u_long secs;
#endif

            /* Copy last used OTP */
            apr_snprintf(user->last_otp, sizeof(user->last_otp), "%s", last_otp);

            /* Parse last successful authentication timestamp */
#if HAVE_STRPTIME
            if ((s = strptime(timestamp, TIME_FORMAT, &tm)) == NULL || *s != '\0') {
                apr_snprintf(invalid_reason, sizeof(invalid_reason), "invalid auth timestamp \"%s\"", timestamp);
                goto invalid;
            }
            tm.tm_isdst = -1;
            user->last_auth = mktime(&tm);
#else
            secs = strtol(timestamp, &eptr, 10);
            if (secs == LONG_MIN || secs == LONG_MAX || *eptr != '\0') {
                apr_snprintf(invalid_reason, sizeof(invalid_reason), "invalid auth timestamp \"%s\"", timestamp);
                goto invalid;
            }
            user->last_auth = (time_t)secs;
#endif
        }

        /* Copy last used IP address (if any) */
        if (last_ip != NULL)
            apr_snprintf(user->last_ip, sizeof(user->last_ip), "%s", last_ip);

found:
        /* We are not updating; return the user we found */
        AP_DEBUG_ASSERT(!update);
        AP_DEBUG_ASSERT(newfile == NULL);
        AP_DEBUG_ASSERT(lockfile == NULL);
        apr_file_close(file);
        return AUTH_USER_FOUND;

invalid:
        /* Report invalid entry (but copy it anyway) */
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "ignoring invalid entry in OTP users file \"%s\" on line %d: %s",
          usersfile, linenum, invalid_reason);

copy:
        /* Copy line to new file */
        if (newfile != NULL) {
            if ((status = apr_file_puts(linecopy, newfile)) != 0)
                goto write_error;
        }
    }

    /* Close original file */
    apr_file_close(file);
    file = NULL;

    /* If we're not updating and we get here, then the user was not found */
    if (!update) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" not found in OTP users file \"%s\"", user->username, usersfile);
        return AUTH_USER_NOT_FOUND;
    }

    /* Close temporary file */
    if ((status = apr_file_close(newfile)) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "error closing new OTP users file \"%s\": %s",
          newusersfile, apr_strerror(status, errbuf, sizeof(errbuf)));
        goto fail;
    }
    newfile = NULL;

    /* Replace old file with new one */
    if ((status = apr_file_rename(newusersfile, usersfile, r->pool)) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "error renaming new OTP users file \"%s\" to \"%s\": %s",
          newusersfile, usersfile, apr_strerror(status, errbuf, sizeof(errbuf)));
        goto fail;
    }

    /* Close (and implicitly unlock) lock file */
    apr_file_close(lockfile);
    lockfile = NULL;

    /* Done updating */
    return found ? AUTH_USER_FOUND : AUTH_USER_NOT_FOUND;

write_error:
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "error writing to new OTP users file \"%s\": %s",
      newusersfile, apr_strerror(status, errbuf, sizeof(errbuf)));

fail:
    if (file != NULL)
        apr_file_close(file);
    if (newfile != NULL) {
        apr_file_close(newfile);
        (void)apr_file_remove(newusersfile, r->pool);
    }
    if (lockfile != NULL)
        apr_file_close(lockfile);
    return AUTH_GENERAL_ERROR;
}

/*
 * Parse a token type string such as "HOTP/T30/6".
 * Returns 0 if successful, else -1 on parse error.
 */
static int
parse_token_type(const char *type, struct otp_user *tokinfo)
{
    char tokbuf[MAX_TOKEN];
    char *last;
    char *eptr;
    char *t;

    /* Backwards compatibility hack */
    if (strcmp(type, "E") == 0)
        type = "HOTP/E";
    else if (strcmp(type, "T") == 0)
        type = "HOTP/T30";

    /* Initialize */
    memset(tokinfo, 0, sizeof(*tokinfo));
    apr_snprintf(tokbuf, sizeof(tokbuf), "%s", type);

    /* Parse algorithm */
    if ((t = apr_strtok(tokbuf, "/", &last)) == NULL)
        return -1;

    /* Apply per-algorithm defaults */
    if (strcasecmp(t, "HOTP") == 0) {
        tokinfo->algorithm = OTP_ALGORITHM_HOTP;
        tokinfo->time_interval = 0;
        tokinfo->num_digits = DEFAULT_NUM_DIGITS;
    } else if (strcasecmp(t, "MOTP") == 0) {
        tokinfo->algorithm = OTP_ALGORITHM_MOTP;
        tokinfo->time_interval = MOTP_TIME_INTERVAL;
        tokinfo->num_digits = DEFAULT_NUM_DIGITS;
    } else
        return -1;

    /* Parse token type: event or time-based */
    if ((t = apr_strtok(NULL, "/", &last)) == NULL)
        return 0;
    if (strcmp(t, "E") == 0)
        tokinfo->time_interval = 0;
    else if (*t == 'T') {
        if (!isdigit(*++t))
            return -1;
        tokinfo->time_interval = strtol(t, &eptr, 10);
        if (tokinfo->time_interval <= 0 || *eptr != '\0')
            return -1;
    } else
        return -1;

    /* Parse #digits */
    if ((t = apr_strtok(NULL, "/", &last)) == NULL)
        return 0;
    if (!isdigit(*t))
        return -1;
    tokinfo->num_digits = strtol(t, &eptr, 10);
    if (tokinfo->num_digits <= 0 || *eptr != '\0' || tokinfo->num_digits > sizeof(powers10) / sizeof(*powers10))
        return -1;

    /* Done */
    return 0;
}

static apr_status_t
print_user(apr_file_t *file, const struct otp_user *user)
{
    const char *pinstr = NULL;
    const char *alg;
    char cbuf[64];
    char nbuf[64];
    char tbuf[MAX_TOKEN];
    int i;

    /* Format token type sub-fields */
    switch (user->algorithm) {
    case OTP_ALGORITHM_HOTP:
        alg = "HOTP";
        break;
    case OTP_ALGORITHM_MOTP:
        alg = "MOTP";
        break;
    default:
        abort();
    }
    if (user->time_interval == 0)
        apr_snprintf(cbuf, sizeof(cbuf), "/E");
    else
        apr_snprintf(cbuf, sizeof(cbuf), "/T%d", user->time_interval);
    apr_snprintf(nbuf, sizeof(nbuf), "/%d", user->num_digits);

    /* Abbreviate when default values apply */
    if (user->num_digits == DEFAULT_NUM_DIGITS) {
        *nbuf = '\0';
        if (user->algorithm == OTP_ALGORITHM_HOTP && user->time_interval == 0)
            *cbuf = '\0';
        else if (user->algorithm == OTP_ALGORITHM_MOTP && user->time_interval == 10)
            *cbuf = '\0';
    }
    apr_snprintf(tbuf, sizeof(tbuf), "%s%s%s", alg, cbuf, nbuf);

    /* Get PIN representation */
    switch (user->pincfg) {
    case PIN_CONFIG_LITERAL:
        pinstr = user->pin;
        break;
    case PIN_CONFIG_NONE:
        pinstr = PIN_NONE;
        break;
    case PIN_CONFIG_EXTERNAL:
        pinstr = PIN_EXTERNAL;
        break;
    default:
        abort();
    }

    /* Print line in users file */
    apr_file_printf(file, "%-7s %-13s %-7s ", tbuf, user->username, pinstr);
    for (i = 0; i < user->keylen; i++)
        apr_file_printf(file, "%02x", user->key[i]);
    apr_file_printf(file, " %-3ld %-2u", user->offset, user->num_otp_failures);
    if (*user->last_otp != '\0') {
#if HAVE_STRPTIME
        strftime(tbuf, sizeof(tbuf), TIME_FORMAT, localtime(&user->last_auth));
#else
        apr_snprintf(tbuf, sizeof(tbuf), "%lu", (u_long)user->last_auth);
#endif
        apr_file_printf(file, " %-7s %s %s", user->last_otp, tbuf, user->last_ip);
    }
    return apr_file_putc('\n', file);
}

/*
 * Generate an OTP using the algorithm specified in RFC 4226,
 */
static void
hotp(const u_char *key, size_t keylen, u_long counter, int ndigits, char *buf10, char *buf16, size_t buflen)
{
    const int max10 = sizeof(powers10) / sizeof(*powers10);
    const int max16 = 8;
    const EVP_MD *sha1_md = EVP_sha1();
    u_char hash[EVP_MAX_MD_SIZE];
    u_int hash_len;
    u_char tosign[8];
    int offset;
    int value;
    int i;

    /* Encode counter */
    for (i = sizeof(tosign) - 1; i >= 0; i--) {
        tosign[i] = counter & 0xff;
        counter >>= 8;
    }

    /* Compute HMAC */
    HMAC(sha1_md, key, keylen, tosign, sizeof(tosign), hash, &hash_len);

    /* Extract selected bytes to get 32 bit integer value */
    offset = hash[hash_len - 1] & 0x0f;
    value = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
        | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

    /* Sanity check max # digits */
    if (ndigits < 1)
        ndigits = 1;

    /* Generate decimal digits */
    if (buf10 != NULL) {
        apr_snprintf(buf10, buflen, "%0*d", ndigits < max10 ? ndigits : max10,
          ndigits < max10 ? value % powers10[ndigits - 1] : value);
    }

    /* Generate hexadecimal digits */
    if (buf16 != NULL) {
        apr_snprintf(buf16, buflen, "%0*x", ndigits < max16 ? ndigits : max16,
          ndigits < max16 ? (value & ((1 << (4 * ndigits)) - 1)) : value);
    }
}

/*
 * Generate an OTP using the mOTP algorithm defined by http://motp.sourceforge.net/
 */
static void
motp(const u_char *key, size_t keylen, const char *pin, u_long counter, int ndigits, char *buf, size_t buflen)
{
    u_char hash[MD5_DIGEST_LENGTH];
    char hashbuf[256];
    char keybuf[256];

    printhex(keybuf, sizeof(keybuf), key, keylen, keylen * 2);
    apr_snprintf(hashbuf, sizeof(hashbuf), "%lu%s%s", counter, keybuf, pin);
    MD5((u_char *)hashbuf, strlen(hashbuf), hash);
    printhex(buf, buflen, hash, sizeof(hash), ndigits);
}

/*
 * Print hex digits into a buffer.
 */
static void
printhex(char *buf, size_t buflen, const u_char *data, size_t dlen, int max_digits)
{
    const char *hexdig = "0123456789abcdef";
    int i;

    if (buflen > 0)
        *buf = '\0';
    for (i = 0; i / 2 < (int)dlen && i < max_digits && i < (int)buflen - 1; i++) {
        u_int val = data[i / 2];
        if ((i & 1) == 0)
            val >>= 4;
        val &= 0x0f;
        *buf++ = hexdig[val];
        *buf = '\0';
    }
}

/*
 * Verify PIN using an external authn provider configured via "OTPAuthPINAuthProvider".
 */
static authn_status
authn_otp_check_pin_external(request_rec *r, struct otp_config *const conf, const char *username, const char *pin)
{
    authn_provider_list *pentry;
    authn_status status;

    /* Verify that at least one authn provider is configured */
    if ((pentry = conf->provlist) == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
          "user \"%s\" PIN to be verified externally but no \"OTPAuthPINAuthProvider\" was configured", username);
        return AUTH_DENIED;
    }

    /* Try each configured authn provider until we find one that recognizes this user */
    do {
        apr_table_setn(r->notes, AUTHN_PROVIDER_NAME_NOTE, pentry->provider_name);
        status = pentry->provider->check_password(r, username, pin);
        apr_table_unset(r->notes, AUTHN_PROVIDER_NAME_NOTE);
        if (status != AUTH_USER_NOT_FOUND)
            break;
        pentry = pentry->next;
    } while (pentry != NULL);

    /* Check result */
    switch (status) {
    case AUTH_GRANTED:
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "user \"%s\" PIN successfully validated by auth provider \"%s\"",
          username, pentry->provider_name);
        break;
    case AUTH_DENIED:
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" gave incorrect PIN according to PIN auth provider \"%s\"",
          username, pentry->provider_name);
        break;
    case AUTH_USER_NOT_FOUND:
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" is not known by any configured PIN auth provider", username);
        break;
    case AUTH_GENERAL_ERROR:                        /* assume the auth provider logged something interesting */
        break;
    case AUTH_USER_FOUND:
    default:
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
          "PIN auth provider \"%s\" returned unexpected value %d for user \"%s\"; treating as AUTH_DENIED",
            pentry->provider_name, status, username);
        status = AUTH_DENIED;
        break;
    }

    /* Done */
    return status;
}

/*
 * Verify PIN.
 */
static authn_status
authn_otp_check_pin(request_rec *r, struct otp_config *const conf, struct otp_user *const user, const char *pin)
{
    switch (user->pincfg) {
    case PIN_CONFIG_NONE:                               /* User has no PIN, so provided PIN must be the empty string */
        if (*pin != '\0') {
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
              "user \"%s\" supplied a PIN but none is configured in the users file", user->username);
            return AUTH_DENIED;
        }
        return AUTH_GRANTED;
    case PIN_CONFIG_EXTERNAL:                           /* User's PIN must be verified externally via an OTPAuthPINAuthProvider */
        return authn_otp_check_pin_external(r, conf, user->username, pin);
    case PIN_CONFIG_LITERAL:                            /* User's PIN was given explicitly in the users file */
        if (strcmp(pin, user->pin) != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" PIN does not match value in users file", user->username);
            return AUTH_DENIED;
        }
        return AUTH_GRANTED;
    default:                                            /* This should never happen */
        abort();
        return AUTH_DENIED;
    }
}

/*
 * HTTP basic authentication
 */
static authn_status
authn_otp_check_password(request_rec *r, const char *username, const char *otp_given)
{
    struct otp_config *const conf = get_config(r);
    struct otp_user userbuf;
    struct otp_user *const user = &userbuf;
    authn_status status;
    int window_start;
    int window_stop;
    char otpbuf10[32];
    char otpbuf16[32];
    int counter;
    int offset;
    time_t now;

    /* Is the users file defined? */
    if (conf->users_file == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No OTPAuthUsersFile has been configured");
        return AUTH_GENERAL_ERROR;
    }

    /* Lookup user in the users file */
    memset(user, 0, sizeof(*user));
    apr_snprintf(user->username, sizeof(user->username), "%s", username);
    if ((status = find_update_user(r, conf->users_file, user, 0)) != AUTH_USER_FOUND)
        return status;

    /* Check for max failures */
    if (conf->max_otp_failures != 0 && user->num_otp_failures >= conf->max_otp_failures) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" has reached the maximum wrong OTP limit of %u",
          user->username, conf->max_otp_failures);
        return conf->allow_fallthrough ? AUTH_USER_NOT_FOUND : AUTH_DENIED;
    }

    /* Check for a "logout" via empty password */
    if (*otp_given == '\0' && *user->last_otp != '\0' && *user->last_ip != '\0' && strcmp(user->last_ip, USER_AGENT_IP(r)) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "logout for user \"%s\" via empty password", user->username);

        /* Forget previous OTP */
        *user->last_otp = '\0';
        find_update_user(r, conf->users_file, user, 1);
        return conf->allow_fallthrough ? AUTH_USER_NOT_FOUND : AUTH_DENIED;
    }

    /* Check PIN prefix (if appropriate) */
    if (user->algorithm != OTP_ALGORITHM_MOTP) {
        char pinbuf[MAX_PIN];
        int pinlen;

        /* Determine the length of the PIN that the user supplied */
        pinlen = strlen(otp_given) - user->num_digits;
        if (pinlen < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" provided a too-short OTP", user->username);
            return conf->allow_fallthrough ? AUTH_USER_NOT_FOUND : AUTH_DENIED;
        }

        /* Extract the PIN from the password given */
        apr_snprintf(pinbuf, sizeof(pinbuf), "%.*s", pinlen, otp_given);
        otp_given += pinlen;

        /* Check the PIN */
        if ((status = authn_otp_check_pin(r, conf, user, pinbuf)) != AUTH_GRANTED) {
            if (status == AUTH_DENIED && conf->allow_fallthrough)
                status = AUTH_USER_NOT_FOUND;
            return status;
        }
    }

    /* Check OTP length */
    if (strlen(otp_given) != user->num_digits) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" OTP has the wrong length %d != %d",
          user->username, (int)strlen(otp_given), user->num_digits);
        return conf->allow_fallthrough ? AUTH_USER_NOT_FOUND : AUTH_DENIED;
    }

    /* Check for reuse of previous OTP */
    now = time(NULL);
    if (strcmp(otp_given, user->last_otp) == 0) {

        /* Did user's IP address change? */
        if (conf->logout_ip_change && *user->last_ip != '\0' && strcmp(user->last_ip, USER_AGENT_IP(r)) != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" provided the previous OTP"
              " but from a different IP address (was %s, now %s)", user->username, user->last_ip, USER_AGENT_IP(r));
            goto fail;
        }

        /* Is it within the configured linger time? */
        if (now >= user->last_auth && now < user->last_auth + conf->max_linger) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "accepting reuse of OTP for \"%s\" within %d sec. linger time",
              user->username, conf->max_linger);
            return AUTH_GRANTED;
        }

        /* Report failure to the log */
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" provided the previous OTP"
          " but it has expired (max linger is %d sec.)", user->username, conf->max_linger);
        goto fail;
    }

    /* Get expected counter value and offset window */
    if (user->time_interval == 0) {
        counter = user->offset;
        window_start = 1;
        window_stop = conf->max_offset;
    } else {
        counter = (int)now / user->time_interval + user->offset;
        window_start = -conf->max_offset;
        window_stop = conf->max_offset;

        /* Expand upper bound of window to ensure an absolute offset of zero is included in the search (issue #14) */
        if (window_stop < -user->offset)
            window_stop = -user->offset;
    }

    /* Test OTP using expected counter first */
    *otpbuf10 = '\0';
    if (user->algorithm == OTP_ALGORITHM_MOTP)
        motp(user->key, user->keylen, user->pin, counter, user->num_digits, otpbuf16, OTP_BUF_SIZE);
    else
        hotp(user->key, user->keylen, counter, user->num_digits, otpbuf10, otpbuf16, OTP_BUF_SIZE);
    if (strcmp(otp_given, otpbuf10) == 0 || strcasecmp(otp_given, otpbuf16) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "accepting OTP for \"%s\" at counter %d", user->username, counter);
        offset = 0;
        goto success;
    }

    /* Try other OTP counter values within the maximum allowed offset */
    for (offset = window_start; offset <= window_stop; offset++) {
        if (offset == 0)    /* already tried it */
            continue;
        if (user->algorithm == OTP_ALGORITHM_MOTP)
            motp(user->key, user->keylen, user->pin, counter + offset, user->num_digits, otpbuf16, OTP_BUF_SIZE);
        else
            hotp(user->key, user->keylen, counter + offset, user->num_digits, otpbuf10, otpbuf16, OTP_BUF_SIZE);
        if (strcmp(otp_given, otpbuf10) == 0 || strcasecmp(otp_given, otpbuf16) == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "accepting OTP for \"%s\" at counter %d (offset adjust %d)",
              user->username, counter + offset, offset);
            goto success;
        }
    }

    /* Report failure to the log */
    if (conf->max_otp_failures != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" provided the wrong OTP (%d/%d consecutive)",
          user->username, user->num_otp_failures + 1, conf->max_otp_failures);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" provided the wrong OTP (%d consecutive)",
          user->username, user->num_otp_failures + 1);
    }
    goto fail;

success:
    /* Update user's last auth information and next expected offset */
    user->offset = user->time_interval == 0 ? counter + offset + 1 : user->offset + offset;
    user->num_otp_failures = 0;
    apr_snprintf(user->last_otp, sizeof(user->last_otp), "%s", otp_given);
    user->last_auth = now;
    apr_snprintf(user->last_ip, sizeof(user->last_ip), "%s", USER_AGENT_IP(r));

    /* Update user's record */
    find_update_user(r, conf->users_file, user, 1);

    /* Done */
    return AUTH_GRANTED;

fail:
    /* Update user's failure count */
    if (user->num_otp_failures < UINT_MAX) {
        user->num_otp_failures++;
        find_update_user(r, conf->users_file, user, 1);
    }
    return AUTH_DENIED;
}

/*
 * HTTP digest authentication
 *
 * NOTE: OTPAuthMaxOTPFailure does not count digest authentication failures!
 */
static authn_status
authn_otp_get_realm_hash(request_rec *r, const char *username, const char *realm, char **rethash)
{
    struct otp_config *const conf = get_config(r);
    struct otp_user userbuf;
    struct otp_user *const user = &userbuf;
    authn_status status;
    char hashbuf[256];
    char otpbuf[32];
    int counter = 0;
    int linger;
    time_t now;

    /* Is the users file configured? */
    if (conf->users_file == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No OTPAuthUsersFile has been configured");
        return AUTH_GENERAL_ERROR;
    }

    /* Lookup the user in the users file */
    memset(user, 0, sizeof(*user));
    apr_snprintf(user->username, sizeof(user->username), "%s", username);
    if ((status = find_update_user(r, conf->users_file, user, 0)) != AUTH_USER_FOUND)
        return status;

    /* Check for max failures */
    if (conf->max_otp_failures != 0 && user->num_otp_failures >= conf->max_otp_failures) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" has reached the maximum wrong OTP limit of %u",
          user->username, conf->max_otp_failures);
        return conf->allow_fallthrough ? AUTH_USER_NOT_FOUND : AUTH_DENIED;
    }

    /* The user's PIN must be known to us */
    switch (user->pincfg) {
    case PIN_CONFIG_NONE:
    case PIN_CONFIG_LITERAL:
        break;
    default:
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
          "user \"%s\" has an externally verified PIN which is not compatible with digest authentication", user->username);
        return AUTH_USER_NOT_FOUND;
    }

    /* Determine the expected OTP, assuming OTP reuse if we are within the linger time and IP has not changed */
    now = time(NULL);
    if (now >= user->last_auth
      && now < user->last_auth + conf->max_linger
      && (!conf->logout_ip_change || *user->last_ip == '\0' || strcmp(user->last_ip, USER_AGENT_IP(r)) == 0)) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
          "generating digest hash for \"%s\" assuming reuse of OTP within %d sec. linger time",
          user->username, conf->max_linger);
        apr_snprintf(otpbuf, sizeof(otpbuf), "%s", user->last_otp);
        linger = 1;
    } else {

        /* Log note if previous OTP has expired */
        if (user->last_auth != 0 && *user->last_otp != '\0') {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "not using previous expired OTP for user \"%s\" (max linger is %d sec.)",
              user->username, conf->max_linger);
        }

        /* Get expected counter value */
        counter = user->time_interval == 0 ? user->offset : (int)now / user->time_interval + user->offset;

        /* Generate OTP using expected counter */
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "generating digest hash for \"%s\" assuming OTP counter %d",
          user->username, counter);
        if (user->algorithm == OTP_ALGORITHM_MOTP)
            motp(user->key, user->keylen, user->pin, counter, user->num_digits, otpbuf, OTP_BUF_SIZE);
        else
            hotp(user->key, user->keylen, counter, user->num_digits, otpbuf, NULL, OTP_BUF_SIZE);   /* assume decimal! */
        linger = 0;
    }

    /* Generate digest hash */
    apr_snprintf(hashbuf, sizeof(hashbuf), "%s:%s:%s%s", user->username, realm,
      user->algorithm == OTP_ALGORITHM_MOTP ? "" : user->pin, otpbuf);
    *rethash = ap_md5(r->pool, (void *)hashbuf);

#if 0
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "OTP=\"%s\" counter=%d user=\"%s\" realm=\"%s\" pin=\"%s\" digest=\"%s\"",
      otpbuf10, counter, user->username, realm, user->pin, *rethash);
#endif

    /* If we are past the previous linger time, assume counter advance and update user's info */
    if (!linger) {
        if (user->time_interval == 0)
            user->offset = counter + 1;
        apr_snprintf(user->last_otp, sizeof(user->last_otp), "%s", otpbuf);
        user->last_auth = now;
        find_update_user(r, conf->users_file, user, 1);
    }

    /* Done */
    return AUTH_USER_FOUND;
}

/*
 * Get configuration
 */
static struct otp_config *
get_config(request_rec *r)
{
    struct otp_config *dir_conf;
    struct otp_config *conf;

    /* I don't understand this bug: sometimes r->per_dir_config == NULL. Some weird linking problem. */
    if (r->per_dir_config == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Oops, bug detected in mod_authn_otp: r->per_dir_config == NULL?");
        dir_conf = create_authn_otp_dir_config(r->pool, NULL);
    } else
        dir_conf = ap_get_module_config(r->per_dir_config, &authn_otp_module);

    /* Make a copy of the current per-directory config */
    conf = apr_pcalloc(r->pool, sizeof(*conf));
    if (dir_conf->users_file != NULL)
        conf->users_file = apr_pstrdup(r->pool, dir_conf->users_file);
    conf->max_offset = dir_conf->max_offset;
    conf->max_linger = dir_conf->max_linger;
    conf->max_otp_failures = dir_conf->max_otp_failures;
    conf->logout_ip_change = dir_conf->logout_ip_change;
    conf->allow_fallthrough = dir_conf->allow_fallthrough;
    copy_provider_list(r->pool, &conf->provlist, dir_conf->provlist);

    /* Apply defaults for any unset values */
    if (conf->max_offset == -1)
        conf->max_offset = DEFAULT_MAX_OFFSET;
    if (conf->max_linger == -1)
        conf->max_linger = DEFAULT_MAX_LINGER;
    if (conf->logout_ip_change == -1)
        conf->logout_ip_change = DEFAULT_LOGOUT_IP_CHANGE;
    if (conf->allow_fallthrough == -1)
        conf->allow_fallthrough = DEFAULT_ALLOW_FALLTHROUGH;

    /* Done */
    return conf;
}

/*
 * Constructor for per-directory configuration
 */
static void *
create_authn_otp_dir_config(apr_pool_t *p, char *d)
{
    struct otp_config *conf = apr_pcalloc(p, sizeof(struct otp_config));

    conf->users_file = NULL;
    conf->max_offset = -1;
    conf->max_linger = -1;
    conf->max_otp_failures = 0;
    conf->logout_ip_change = -1;
    conf->allow_fallthrough = -1;
    conf->provlist = NULL;
    return conf;
}

static void *
merge_authn_otp_dir_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
    struct otp_config *const conf1 = base_conf;
    struct otp_config *const conf2 = new_conf;
    struct otp_config *conf = apr_pcalloc(p, sizeof(struct otp_config));

    if (conf2->users_file != NULL)
        conf->users_file = apr_pstrdup(p, conf2->users_file);
    else if (conf1->users_file != NULL)
        conf->users_file = apr_pstrdup(p, conf1->users_file);
    conf->max_offset = conf2->max_offset != -1 ? conf2->max_offset : conf1->max_offset;
    conf->max_linger = conf2->max_linger != -1 ? conf2->max_linger : conf1->max_linger;
    conf->max_otp_failures = conf2->max_otp_failures != 0 ? conf2->max_otp_failures : conf1->max_otp_failures;
    conf->logout_ip_change = conf2->logout_ip_change != -1 ? conf2->logout_ip_change : conf1->logout_ip_change;
    conf->allow_fallthrough = conf2->allow_fallthrough != -1 ? conf2->allow_fallthrough : conf1->allow_fallthrough;
    copy_provider_list(p, &conf->provlist, conf2->provlist != NULL ? conf2->provlist : conf1->provlist);
    return conf;
}

/*
 * This code is more-or-less copied from mod_auth_basic.c
 */
static const char *
add_authn_provider(cmd_parms *cmd, void *config, const char *provider_name)
{
    struct otp_config *const conf = (struct otp_config *)config;
    authn_provider_list *pentry;
    authn_provider_list *last;

    /* Sanity check */
    if (strcmp(provider_name, OTP_AUTHN_PROVIDER_NAME) == 0)
        return apr_psprintf(cmd->pool, "Invalid recursive Authn provider: %s", provider_name);

    /* Create new provider list entry */
    pentry = apr_pcalloc(cmd->pool, sizeof(*pentry));
    pentry->provider_name = apr_pstrdup(cmd->pool, provider_name);

    /* Lookup and cache the actual provider now */
    pentry->provider = ap_lookup_provider(AUTHN_PROVIDER_GROUP, pentry->provider_name, AUTHN_PROVIDER_VERSION);
    if (pentry->provider == NULL)
        return apr_psprintf(cmd->pool, "Unknown Authn provider: %s", pentry->provider_name);

    /* Verify this authentication provider can check plain passwords */
    if (pentry->provider->check_password == NULL) {
        return apr_psprintf(cmd->pool,
          "The '%s' Authn provider doesn't support plaintext password checks", pentry->provider_name);
    }

    /* Add it to the end of the list */
    if (conf->provlist == NULL)
        conf->provlist = pentry;
    else {
        for (last = conf->provlist; last->next != NULL; last = last->next)
            ;
        last->next = pentry;
    }

    /* Done */
    return NULL;
}

static void
copy_provider_list(apr_pool_t *p, authn_provider_list **dstp, authn_provider_list *src)
{
    while (src != NULL) {
        *dstp = apr_pcalloc(p, sizeof(**dstp));
        (*dstp)->provider_name = apr_pstrdup(p, src->provider_name);
        (*dstp)->provider = src->provider;
        dstp = &(*dstp)->next;
        src = src->next;
    }
}

/* Authorization provider information */
static const authn_provider authn_otp_provider =
{
    &authn_otp_check_password,
    &authn_otp_get_realm_hash
};

static void
register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, OTP_AUTHN_PROVIDER_NAME, AUTHN_PROVIDER_VERSION, &authn_otp_provider);
}

/* Configuration directives */
static const command_rec authn_otp_cmds[] =
{
    AP_INIT_TAKE1("OTPAuthUsersFile",
        ap_set_file_slot,
        (void *)APR_OFFSETOF(struct otp_config, users_file),
        OR_AUTHCFG,
        "pathname of the one-time password users file"),
    AP_INIT_TAKE1("OTPAuthMaxOffset",
        ap_set_int_slot,
        (void *)APR_OFFSETOF(struct otp_config, max_offset),
        OR_AUTHCFG,
        "maximum allowed offset from expected event or time counter value"),
    AP_INIT_TAKE1("OTPAuthMaxLinger",
        ap_set_int_slot,
        (void *)APR_OFFSETOF(struct otp_config, max_linger),
        OR_AUTHCFG,
        "maximum time (in seconds) for which a one-time password can be repeatedly used"),
    AP_INIT_TAKE1("OTPAuthMaxOTPFailure",
        ap_set_int_slot,
        (void *)APR_OFFSETOF(struct otp_config, max_otp_failures),
        OR_AUTHCFG,
        "maximum number of consecutive wrong OTP values before account becomes locked"),
    AP_INIT_FLAG("OTPAuthLogoutOnIPChange",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(struct otp_config, logout_ip_change),
        OR_AUTHCFG,
        "enable automatic logout of user if the user's IP address changes"),
    AP_INIT_ITERATE("OTPAuthPINAuthProvider",
        add_authn_provider,
        NULL,
        OR_AUTHCFG,
        "specify auth provider(s) to be used for PIN verification for a directory or location"),
    AP_INIT_FLAG("OTPAuthFallThrough",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(struct otp_config, allow_fallthrough),
        OR_AUTHCFG,
        "allow failed auth attempts to fall through to the next auth provider (if any)"),
    { NULL }
};

/* Module declaration */
module AP_MODULE_DECLARE_DATA authn_otp_module = {
    STANDARD20_MODULE_STUFF,
    create_authn_otp_dir_config,        /* create per-dir config */
    merge_authn_otp_dir_config,         /* merge per-dir config */
    NULL,                               /* create per-server config */
    NULL,                               /* merge per-server config */
    authn_otp_cmds,                     /* command apr_table_t */
    register_hooks                      /* register hooks */
};

