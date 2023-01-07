
/*
 * otplock - Apache mod_authn_otp one-time users file locker
 *
 * Copyright 2023 Archie L. Cobbs <archie.cobbs@gmail.com>
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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "errinc.h"

/* Program name */
#define PROG_NAME                   "otplock"

/* Error exit values */
#define EXIT_USAGE_ERROR            85          /* Incorrect command line usage */
#define EXIT_SYSTEM_ERROR           86          /* Could not open file, etc. */
#define EXIT_CAUGHT_SIGNAL          87
