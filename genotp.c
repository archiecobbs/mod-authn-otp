
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

#include "otptool.h"

/* Powers of ten */
static const int    powers10[] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000, 1000000000 };

/*
 * Generate a one-time password using the algorithm specified in RFC 4226,
 */
void
genotp(const unsigned char *key, size_t keylen, u_long counter, int ndigits, int hex, char *buf, size_t buflen)
{
    const EVP_MD *sha1_md = EVP_sha1();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    unsigned char tosign[8];
    int max_digits;
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

    /* Check max # digits */
    max_digits = hex ? 8 : sizeof(powers10) / sizeof(*powers10) - 1;
    if (ndigits < 1)
        ndigits = 1;
    else if (ndigits > max_digits)
        ndigits = max_digits;

    /* Generate decimal or hexadecimal digits */
    if (hex) {
        if (ndigits < 8)
            value &= (1 << (4 * ndigits)) - 1;
        snprintf(buf, buflen, "%0*x", ndigits, value);
    } else {
        value %= powers10[ndigits];
        snprintf(buf, buflen, "%0*d", ndigits, value);
    }
}

