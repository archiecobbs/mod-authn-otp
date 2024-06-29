
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
md5_quick(const void *data, size_t len, u_char *result)
{
    EVP_MD_CTX *ctx;
    u_int md5_len;
    int r;

    ctx = EVP_MD_CTX_new();
    assert(ctx != NULL);
    r = EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    assert(r != 0);
    r = EVP_DigestUpdate(ctx, data, len);
    assert(r != 0);
    r = EVP_DigestFinal_ex(ctx, result, &md5_len);
    assert(r != 0);
    assert(md5_len == MD5_DIGEST_LENGTH);
    EVP_MD_CTX_free(ctx);
}
