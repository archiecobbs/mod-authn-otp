
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

void
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

