
/*
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
 */

#include <errno.h>

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

