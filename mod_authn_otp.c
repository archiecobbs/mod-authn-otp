
/*
 * mod_authn_otp - Basic and digest authentication using one-time passwords
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
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* Module definition */
module AP_MODULE_DECLARE_DATA authn_otp_module;

/* Definitions related to users file */
#define WHITESPACE              " \t\r\n\v"
#define NEWFILE_SUFFIX          ".new"
#define LOCKFILE_SUFFIX         ".lock"
#define TIME_FORMAT             "%Y-%m-%dT%H:%M:%SZ"

/* OTP counter types */
#define OTP_TYPE_EVENT          1
#define OTP_TYPE_TIME           2

/* Default configuration settings */
#define DEFAULT_NUM_DIGITS      6
#define DEFAULT_TIME_INTERVAL   30
#define DEFAULT_MAX_OFFSET      4
#define DEFAULT_MAX_LINGER      (10 * 60)   /* 10 minutes */

/* Per-directory configuration */
struct otp_config {
    char    *users_file;        /* Name of the users file */
    int     ndigits;            /* Number of digits in the OTP (not counting PIN) */
    int     time_interval;      /* How long in seconds is a single time interval */
    int     max_offset;         /* Maximum allowed counter offset from expected value */
    int     max_linger;         /* Maximum time for which the same OTP can be used repeatedly */
};

/* User info structure */
struct otp_user {
    int             type;
    char            username[128];
    u_char          key[256];
    int             keylen;
    char            pin[128];
    long            offset;             /* if event: next expected count; if time: time slew */
    char            last_otp[128];
    time_t          last_auth;
};

/* Internal functions */
static authn_status find_update_user(request_rec *r, const char *usersfile, struct otp_user *const user, int update);
static void         genotp(const u_char *key, size_t keylen, u_long counter, int ndigits, char *buf, size_t buflen);
static void         print_user(apr_file_t *file, const struct otp_user *user);
static authn_status authn_otp_check_password(request_rec *r, const char *username, const char *password);
static authn_status authn_otp_get_realm_hash(request_rec *r, const char *username, const char *realm, char **rethash);
static void         *create_authn_otp_dir_config(apr_pool_t *p, char *d);
static void         *merge_authn_otp_dir_config(apr_pool_t *p, void *base_conf, void *new_conf);
static struct       otp_config *get_config(request_rec *r);
static void         register_hooks(apr_pool_t *p);

/* Powers of ten */
static const int    powers10[] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 1000000000 };

/*
 * Find/update a user in the users file.
 *
 * Note: if updating, the caller must ensure proper locking.
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
    struct tm tm;
    int found = 0;
    int linenum;
    int type;
    char *last;
    char *s;
    char *t;

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

        /* Ignore lines starting with '#' and empty lines */
        if (*linebuf == '#')
            goto copy;
        if ((s = apr_strtok(linebuf, WHITESPACE, &last)) == NULL)
            goto copy;

        /* Get type */
        if (strcmp(s, "E") == 0)
            type = OTP_TYPE_EVENT;
        else if (strcmp(s, "T") == 0)
            type = OTP_TYPE_TIME;
        else {
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
            print_user(newfile, user);
            continue;
        }

        /* Initialize user record */
        memset(user, 0, sizeof(*user));
        apr_snprintf(user->username, sizeof(user->username), "%s", s);
        user->type = type;

        /* Read PIN */
        if ((s = apr_strtok(NULL, WHITESPACE, &last)) == NULL) {
            apr_snprintf(invalid_reason, sizeof(invalid_reason), "missing PIN field");
            goto invalid;
        }
        if (strcmp(s, "-") == 0)
            *s = '\0';
        apr_snprintf(user->pin, sizeof(user->pin), "%s", s);

        /* Read key */
        if ((s = apr_strtok(NULL, WHITESPACE, &last)) == NULL) {
            apr_snprintf(invalid_reason, sizeof(invalid_reason), "missing token key field");
            goto invalid;
        }
        for (user->keylen = 0; user->keylen < sizeof(user->key) && *s != '\0'; user->keylen++) {
            int nibs[2];
            int i;

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

        /* Read last used OTP (optional) */
        if ((s = apr_strtok(NULL, WHITESPACE, &last)) == NULL)
            goto found;
        apr_snprintf(user->last_otp, sizeof(user->last_otp), "%s", s);

        /* Read last successful authentication timestamp */
        if ((s = apr_strtok(NULL, WHITESPACE, &last)) == NULL) {
            apr_snprintf(invalid_reason, sizeof(invalid_reason), "missing last auth timestamp field");
            goto invalid;
        }
        if ((t = strptime(s, TIME_FORMAT, &tm)) == NULL || *t != '\0') {
            apr_snprintf(invalid_reason, sizeof(invalid_reason), "invalid auth timestamp \"%s\"", s);
            goto invalid;
        }
        tm.tm_isdst = -1;
        user->last_auth = mktime(&tm);

found:
        /* We are not updating; return the user we found */
        apr_file_close(file);
        return AUTH_USER_FOUND;

invalid:
        /* Report invalid entry (but copy it anyway) */
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "ignoring invalid entry in OTP users file \"%s\" on line %d: %s",
          usersfile, linenum, invalid_reason);

copy:
        /* Copy line to new file */
        if (newfile != NULL)
            apr_file_puts(linebuf, newfile);
    }
    apr_file_close(file);
    file = NULL;

    /* If we're not updating and we get here, then the user was not found */
    if (!update) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" not found in OTP users file \"%s\"", user->username, usersfile);
        return AUTH_USER_NOT_FOUND;
    }

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

fail:
    if (file != NULL)
        apr_file_close(file);
    if (newfile != NULL) {
        (void)apr_file_remove(newusersfile, r->pool);
        apr_file_close(newfile);
    }
    if (lockfile != NULL)
        apr_file_close(lockfile);
    return AUTH_GENERAL_ERROR;
}

static void
print_user(apr_file_t *file, const struct otp_user *user)
{
    char timebuf[64];
    int i;

    apr_file_printf(file, "%c %-13s %-7s ",
      user->type == OTP_TYPE_EVENT ? 'E' : 'T', user->username, *user->pin == '\0' ? "-" : user->pin);
    for (i = 0; i < user->keylen; i++)
        apr_file_printf(file, "%02x", user->key[i]);
    apr_file_printf(file, " %-7ld", user->offset);
    if (*user->last_otp != '\0') {
        strftime(timebuf, sizeof(timebuf), TIME_FORMAT, localtime(&user->last_auth));
        apr_file_printf(file, " %-7s %s", user->last_otp, timebuf);
    }
    apr_file_printf(file, "\n");
}


/*
 * Generate an OTP using the algorithm specified in RFC 4226,
 */
static void
genotp(const u_char *key, size_t keylen, u_long counter, int ndigits, char *buf, size_t buflen)
{
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

    /* Get desired number of decimal digits */
    if (ndigits < 1)
        ndigits = 1;
    else if (ndigits >= sizeof(powers10) / sizeof(*powers10))
        ndigits = sizeof(powers10) / sizeof(*powers10) - 1;

    /* Print value */
    value %= powers10[ndigits];
    apr_snprintf(buf, buflen, "%0*d", ndigits, value);
}

/*
 * HTTP basic authentication
 */
static authn_status
authn_otp_check_password(request_rec *r, const char *username, const char *password)
{
    struct otp_config *const conf = get_config(r);
    struct otp_user userbuf;
    struct otp_user *const user = &userbuf;
    const char *otp_given;
    authn_status status;
    int window_start;
    int window_stop;
    char otpbuf[32];
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

    /* Compare PIN */
    if (strncmp(password, user->pin, strlen(user->pin)) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" PIN does not match", user->username);
        return AUTH_DENIED;
    }
    otp_given = password + strlen(user->pin);

    /* Check OTP length */
    if (strlen(otp_given) != conf->ndigits) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" OTP has the wrong length %d != %d",
          user->username, strlen(otp_given), conf->ndigits);
        return AUTH_DENIED;
    }

    /* Check for reuse of previous OTP within linger time */
    now = time(NULL);
    if (now >= user->last_auth && now < user->last_auth + conf->max_linger && strcmp(otp_given, user->last_otp) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "accepting reuse of OTP for \"%s\" within %d sec. linger time",
          user->username, conf->max_linger);
        return AUTH_GRANTED;
    }

    /* Get expected counter value and offset window */
    switch (user->type) {
    case OTP_TYPE_EVENT:
        counter = user->offset;
        window_start = 1;
        window_stop = conf->max_offset;
        break;
    case OTP_TYPE_TIME:
        counter = now / conf->time_interval + user->offset;
        window_start = -conf->max_offset;
        window_stop = conf->max_offset;
        break;
    default:
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_authn_otp internal error");
        return AUTH_GENERAL_ERROR;
    }

    /* Test OTP using expected counter first */
    genotp(user->key, user->keylen, counter, conf->ndigits, otpbuf, sizeof(otpbuf));
    if (strcmp(otp_given, otpbuf) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "accepting OTP for \"%s\" at counter %d", user->username, counter);
        offset = 0;
        goto success;
    }

    /* Try other OTP counter values within the maximum allowed offset */
    for (offset = window_start; offset <= window_stop; offset++) {
        if (offset == 0)    /* already tried it */
            continue;
        genotp(user->key, user->keylen, counter + offset, conf->ndigits, otpbuf, sizeof(otpbuf));
        if (strcmp(otp_given, otpbuf) == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "accepting OTP for \"%s\" at counter %d (offset %d)",
              user->username, counter + offset, offset);
            goto success;
        }
    }

    /* Report failure to the log */
    if (strcmp(otp_given, user->last_otp) == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" provided the previous OTP"
          " but it has expired (max linger is %d sec.)", user->username, conf->max_linger);
    } else
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "user \"%s\" provided the wrong OTP", user->username);
    return AUTH_DENIED;

success:
    /* Update user's last auth information and next expected offset */
    switch (user->type) {
    case OTP_TYPE_EVENT:                    /* advance counter by one */
        user->offset = counter + offset + 1;
        break;
    case OTP_TYPE_TIME:                     /* save user's current time offset */
        user->offset = offset;
        break;
    default:
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_authn_otp internal error");
        return AUTH_GENERAL_ERROR;
    }
    apr_snprintf(user->last_otp, sizeof(user->last_otp), "%s", otp_given);
    user->last_auth = now;

    /* Update user's record */
    find_update_user(r, conf->users_file, user, 1);

    /* Done */
    return AUTH_GRANTED;
}

/*
 * HTTP digest authentication
 */
static authn_status
authn_otp_get_realm_hash(request_rec *r, const char *username, const char *realm, char **rethash)
{
    struct otp_config *const conf = get_config(r);
    struct otp_user userbuf;
    struct otp_user *const user = &userbuf;
    authn_status status;
    char otpbuf[32];
    char hashbuf[1024];
    int counter;
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

    /* Determine the expected OTP, assuming OTP reuse within the linger time */
    now = time(NULL);
    if (user->last_auth >= now && user->last_auth - now < conf->max_linger)
        apr_snprintf(otpbuf, sizeof(otpbuf), "%s", user->last_otp);
    else {

        /* Get expected counter value */
        switch (user->type) {
        case OTP_TYPE_EVENT:
            counter = user->offset;
            break;
        case OTP_TYPE_TIME:
            counter = now / conf->time_interval + user->offset;
            break;
        default:
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_authn_otp internal error");
            return AUTH_GENERAL_ERROR;
        }

        /* Generate OTP using expected counter */
        genotp(user->key, user->keylen, counter, conf->ndigits, otpbuf, sizeof(otpbuf));
    }

    /* Generate digest hash */
    apr_snprintf(hashbuf, sizeof(hashbuf), "%s:%s:%s%s", user->username, realm, user->pin, otpbuf);
    *rethash = ap_md5(r->pool, (void *)hashbuf);
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

    /* XXX TEMPORARY HACK until I figure out this bug */
    if (r->per_dir_config != NULL)
        dir_conf = ap_get_module_config(r->per_dir_config, &authn_otp_module);
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "WTF?!? Why is r->per_dir_config NULL?");
        dir_conf = create_authn_otp_dir_config(r->pool, NULL);
        dir_conf->users_file = apr_pstrdup(r->pool, "/tmp/mod-authn-otp-users");
    }

    /* Duplicate per-directory config */
    conf = apr_pcalloc(r->pool, sizeof(*conf));
    if (dir_conf->users_file != NULL)
        conf->users_file = apr_pstrdup(r->pool, dir_conf->users_file);
    conf->ndigits = dir_conf->ndigits;
    conf->time_interval = dir_conf->time_interval;
    conf->max_offset = dir_conf->max_offset;
    conf->max_linger = dir_conf->max_linger;

    /* Apply defaults for unset values */
    if (conf->ndigits == -1)
        conf->ndigits = DEFAULT_NUM_DIGITS;
    if (conf->time_interval == -1)
        conf->time_interval = DEFAULT_TIME_INTERVAL;
    if (conf->max_offset == -1)
        conf->max_offset = DEFAULT_MAX_OFFSET;
    if (conf->max_linger == -1)
        conf->max_linger = DEFAULT_MAX_LINGER;

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
    conf->ndigits = -1;
    conf->time_interval = -1;
    conf->max_offset = -1;
    conf->max_linger = -1;
    return conf;
}

static void *
merge_authn_otp_dir_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
    struct otp_config *const conf1 = base_conf;
    struct otp_config *const conf2 = new_conf;
    struct otp_config *conf = apr_palloc(p, sizeof(struct otp_config));

    if (conf2->users_file != NULL)
        conf->users_file = apr_pstrdup(p, conf2->users_file);
    else if (conf1->users_file != NULL)
        conf->users_file = apr_pstrdup(p, conf1->users_file);
    conf->ndigits = conf2->ndigits != -1 ? conf2->ndigits : conf1->ndigits;
    conf->time_interval = conf2->time_interval != -1 ? conf2->time_interval : conf1->time_interval;
    conf->max_offset = conf2->max_offset != -1 ? conf2->max_offset : conf1->max_offset;
    conf->max_linger = conf2->max_linger != -1 ? conf2->max_linger : conf1->max_linger;
    return conf;
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
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "OTP", "0", &authn_otp_provider);
}

/* Configuration directives */
static const command_rec authn_otp_cmds[] =
{
    AP_INIT_TAKE1("OTPAuthUsersFile",
        ap_set_file_slot,
        (void *)APR_OFFSETOF(struct otp_config, users_file),
        OR_AUTHCFG,
        "pathname of the one-time password users file"),
    AP_INIT_TAKE1("OTPAuthNumDigits",
        ap_set_int_slot,
        (void *)APR_OFFSETOF(struct otp_config, ndigits),
        OR_AUTHCFG,
        "number of digits in the one-time passwords (not including PIN)"),
    AP_INIT_TAKE1("OTPAuthTimeInterval",
        ap_set_int_slot,
        (void *)APR_OFFSETOF(struct otp_config, time_interval),
        OR_AUTHCFG,
        "time interval (in seconds) for time-based one-time passwords"),
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

