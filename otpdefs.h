
/*
 * otptool - HOTP/OATH one-time password utility
 *
 * Copyright 2009 Archie L. Cobbs <archie.cobbs@gmail.com>
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
 */

#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

#include "errinc.h"

/* Error exit values */
#define EXIT_USAGE_ERROR            1           /* Incorrect command line usage */
#define EXIT_NOT_MATCHED            2           /* OTP failed to match */
#define EXIT_SYSTEM_ERROR           3           /* Could not open file, etc. */

/* Default settings */
#define DEFAULT_NUM_DIGITS          6
#define DEFAULT_TIME_INTERVAL       30
#define DEFAULT_WINDOW              0

/* hotp.c */
extern void         hotp(const u_char *key, size_t keylen, uint64_t counter, int ndigits, char *buf10, char *buf16, size_t buflen);

/* motp.c */
extern void         motp(const u_char *key, size_t keylen, const char *pin, u_long counter, int ndigits, char *buf, size_t buflen);

/* phex.c */
extern void         printhex(char *buf, size_t buflen, const u_char *data, size_t dlen, int max_digits);

/* md5q.c */
extern void         md5_quick(const void *data, size_t len, u_char *result);

/* base32.c */
extern void         base32_encode(const unsigned char *plain, size_t len, unsigned char *coded);
extern size_t       base32_decode(const unsigned char *coded, unsigned char *plain);
