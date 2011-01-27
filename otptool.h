
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

#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_ERR_H
#include <err.h>
#else
#define err(E, FMT...)          do {                                                \
                                    int _esave = (errno);                           \
                                    fprintf(stderr, "%s: ", PROG_NAME);             \
                                    fprintf(stderr, FMT);                           \
                                    fprintf(stderr, ": %s\n", strerror(_esave));    \
                                    exit(E);                                        \
                                } while (0)
#define errx(E, FMT...)         do {                                                \
                                    fprintf(stderr, "%s: ", PROG_NAME);             \
                                    fprintf(stderr, FMT);                           \
                                    fprintf(stderr, "\n");                          \
                                    exit(E);                                        \
                                } while (0)
#define warn(FMT...)            do {                                                \
                                    int _esave = (errno);                           \
                                    fprintf(stderr, "%s: ", PROG_NAME);             \
                                    fprintf(stderr, FMT);                           \
                                    fprintf(stderr, ": %s\n", strerror(_esave));    \
                                } while (0)
#define warnx(FMT...)           do {                                                \
                                    fprintf(stderr, "%s: ", PROG_NAME);             \
                                    fprintf(stderr, FMT);                           \
                                    fprintf(stderr, "\n");                          \
                                } while (0)
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

/* Program name */
#define PROG_NAME                   "otptool"

/* Error exit values */
#define EXIT_USAGE_ERROR            1           /* Incorrect command line usage */
#define EXIT_NOT_MATCHED            2           /* OTP failed to match */
#define EXIT_SYSTEM_ERROR           3           /* Could not open file, etc. */

/* Default settings */
#define DEFAULT_NUM_DIGITS          6
#define DEFAULT_TIME_INTERVAL       30
#define DEFAULT_WINDOW              0

/* hotp.c */
extern void         hotp(const u_char *key, size_t keylen, u_long counter, int ndigits, char *buf10, char *buf16, size_t buflen);

/* motp.c */
extern void         motp(const u_char *key, size_t keylen, const char *pin, u_long counter, int ndigits, char *buf, size_t buflen);

/* phex.c */
extern void         printhex(char *buf, size_t buflen, const u_char *data, size_t dlen, int max_digits);

