
/*
 * otptool - HOTP/OATH one-time password utility
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

#include "otptool.h"

/* Definitions */
#define OTP_BUF_SIZE       16

/* Internal functions */
static void         usage(void);

int
main(int argc, char **argv)
{
    const char *otp = NULL;
    const char *key = NULL;
    const char *motp_pin = NULL;
    unsigned char keybuf[128];
    char otpbuf10[OTP_BUF_SIZE];
    char otpbuf16[OTP_BUF_SIZE];
    size_t keylen;
    int time_interval = DEFAULT_TIME_INTERVAL;
    int ndigits = -1;
    int counter_start;
    int counter_stop;
    int read_from_file = 0;
    int counter = -1;
    int use_time = 0;
    int window = 0;
    int ch;
    int i;

    /* Parse command line */
    while ((ch = getopt(argc, argv, "c:d:fhi:m:tvw:")) != -1) {
        switch (ch) {
        case 'c':
            if (use_time)
                errx(EXIT_USAGE_ERROR, "only one of `-c' or `-t' should be specified");
            counter = atoi(optarg);
            if (counter < 0)
                errx(EXIT_USAGE_ERROR, "invalid counter value `%s'", optarg);
            break;
        case 'd':
            ndigits = atoi(optarg);
            if (ndigits < 1)
                errx(EXIT_USAGE_ERROR, "invalid digit count `%s'", optarg);
            break;
        case 'f':
            read_from_file = 1;
            break;
        case 'h':
            usage();
            return 0;
        case 'i':
            time_interval = atoi(optarg);
            break;
        case 'm':
            ndigits = 6;
            time_interval = 10;
            motp_pin = optarg;
            *otpbuf10 = '\0';
            break;
        case 't':
            if (counter != -1)
                errx(EXIT_USAGE_ERROR, "only one of `-c' or `-t' should be specified");
            use_time = 1;
            break;
        case 'w':
            window = atoi(optarg);
            if (window < 0)
                errx(EXIT_USAGE_ERROR, "invalid counter window `%s'", optarg);
            break;
        default:
            warnx("unrecognized flag `-%c'", ch);
            usage();
            return EXIT_USAGE_ERROR;
        }
    }

    /* Parse command line arguments */
    switch (argc - optind) {
    case 2:
        otp = argv[optind + 1];
        if (ndigits == -1)
            ndigits = strlen(otp);
        if (strlen(otp) != ndigits)
            errx(EXIT_NOT_MATCHED, "the given OTP `%s' has the wrong length %d != %d", otp, (int)strlen(otp), ndigits);
        // FALLTHROUGH
    case 1:
        key = argv[optind];
        break;
    default:
        warnx("wrong number of command line arguments");
        usage();
        return EXIT_USAGE_ERROR;
    }

    /* Set default #digits */
    if (ndigits == -1)
        ndigits = DEFAULT_NUM_DIGITS;

    /* Read or parse key */
    if (read_from_file) {
        FILE *fp;

        if ((fp = fopen(key, "rb")) == NULL)
            err(EXIT_SYSTEM_ERROR, "error reading `%s'", key);
        keylen = fread(keybuf, 1, sizeof(keybuf), fp);
        if (ferror(fp))
            err(EXIT_SYSTEM_ERROR, "error reading `%s'", key);
        if (!feof(fp))
            errx(EXIT_SYSTEM_ERROR, "error reading `%s': %s", key, "key is too long");
        fclose(fp);
    } else {
        for (keylen = 0; keylen < sizeof(keybuf) && key[keylen * 2] != '\0'; keylen++) {
            const char *s = &key[keylen * 2];
            int nibs[2];

            for (i = 0; i < 2; i++) {
                if (isdigit(s[i]))
                    nibs[i] = s[i] - '0';
                else if (isxdigit(s[i]))
                    nibs[i] = tolower(s[i]) - 'a' + 10;
                else
                    errx(EXIT_USAGE_ERROR, "invalid key `%s'", key);
            }
            keybuf[keylen] = (nibs[0] << 4) | nibs[1];
        }
    }

    /* Determine target counter */
    if (use_time)
        counter = time(NULL) / time_interval;
    else if (counter < 0)
        counter = 0;

    /* Search or generate */
    if (otp == NULL) {
        if (use_time) {
            counter_start = counter - window;
            counter_stop = counter + window;
        } else {
            counter_start = counter;
            counter_stop = counter + window;
        }
        for (counter = counter_start; counter <= counter_stop; counter++) {
            if (motp_pin != NULL)
                motp(keybuf, keylen, motp_pin, counter, ndigits, otpbuf16, OTP_BUF_SIZE);
            else
                hotp(keybuf, keylen, counter, ndigits, otpbuf10, otpbuf16, OTP_BUF_SIZE);
            printf("%d: %s%s%s\n", counter, otpbuf10, *otpbuf10 != '\0' && *otpbuf16 != '\0' ? " " : "", otpbuf16);
        }
        return 0;
    } else {
        for (i = 0; i <= window; i++) {
            int try;

            try = counter + i;
            if (motp_pin != NULL)
                motp(keybuf, keylen, motp_pin, try, ndigits, otpbuf16, OTP_BUF_SIZE);
            else
                hotp(keybuf, keylen, try, ndigits, otpbuf10, otpbuf16, OTP_BUF_SIZE);
            if (strcasecmp(otp, otpbuf10) == 0 || strcasecmp(otp, otpbuf16) == 0)
                goto match;
            if (use_time && i != 0) {
                try = counter - i;
                if (motp_pin != NULL)
                    motp(keybuf, keylen, motp_pin, try, ndigits, otpbuf16, OTP_BUF_SIZE);
                else
                    hotp(keybuf, keylen, try, ndigits, otpbuf10, otpbuf16, OTP_BUF_SIZE);
                if (strcasecmp(otp, otpbuf10) == 0 || strcasecmp(otp, otpbuf16) == 0)
                    goto match;
            }
            continue;
match:
            printf("%d\n", try);
            return 0;
        }
    }

    /* Not found */
    fprintf(stderr, "one-time password \"%s\" was not found within the counter range %d ... %d\n", otp,
      use_time ? counter - window : counter, counter + window);
    return EXIT_NOT_MATCHED;
}

static void
usage()
{
    fprintf(stderr, "Usage: %s [-fht] [-c counter] [-d digits] [-i interval] [-m PIN] [-w window] key [otp]\n", PROG_NAME);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c\tSpecify the initial counter value (conflicts with `-t')\n");
    fprintf(stderr, "  -f\t`key' refers to the file containing the key\n");
    fprintf(stderr, "  -h\tDisplay this usage message\n");
    fprintf(stderr, "  -i\tSpecify time interval in seconds (default %d)\n", DEFAULT_TIME_INTERVAL);
    fprintf(stderr, "  -m\tUse mOTP algorithm with given PIN; also implies `-d 6' and `-i 10'\n");
    fprintf(stderr, "  -t\tDerive initial counter value from the current time (conflicts with `-c')\n");
    fprintf(stderr, "  -n\tSpecify number of digits in the generated OTP(s) (default %d)\n", DEFAULT_NUM_DIGITS);
    fprintf(stderr, "  -w\tSpecify size of window for additional counter values (default %d)\n", DEFAULT_WINDOW);
}

