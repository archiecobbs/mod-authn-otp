
/*
 * otptool - one-time password utility
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

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

/* Program name */
#define PROG_NAME                   "otptool"

/* Error exit values */
#define EXIT_USAGE_ERROR            1           /* Incorrect command line usage */
#define EXIT_SYSTEM_ERROR           2           /* Could not open file, etc. */
#define EXIT_NOT_MATCHED            3           /* OTP failed to match */

/* Default settings */
#define DEFAULT_NUM_DIGITS          6
#define DEFAULT_TIME_INTERVAL       30
#define DEFAULT_WINDOW              0

/* genotp.c */
extern void         genotp(const u_char *key, size_t keylen, u_long counter, int ndigits, char *buf10, char *buf16, size_t buflen);

