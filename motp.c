
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

#include "otpdefs.h"

/* Definitions */
#define MOTP_NUM_BYTES      3

/*
 * Generate an OTP using the mOTP algorithm defined by http://motp.sourceforge.net/
 */
void
motp(const u_char *key, size_t keylen, const char *pin, u_long counter, int ndigits, char *buf, size_t buflen)
{
    u_char hash[MD5_DIGEST_LENGTH];
    char keybuf[keylen * 2 + 1];
    char hashbuf[64 + (keylen * 2) + strlen(pin)];

    printhex(keybuf, sizeof(keybuf), key, keylen, keylen * 2);
    snprintf(hashbuf, sizeof(hashbuf), "%lu%s%s", counter, keybuf, pin);
    md5_quick(hashbuf, strlen(hashbuf), hash);
    printhex(buf, buflen, hash, sizeof(hash), ndigits);
}

