
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

#include "otpdefs.h"
#include "config.h"

#if HAVE_APR_1_APR_FILE_IO_H
#include <apr-1/apr_file_io.h>
#include <apr-1/apr_lib.h>
#include <apr-1/apr_strings.h>
#include <apr-1/apr_thread_proc.h>
#elif HAVE_APR_1_0_APR_FILE_IO_H
#include <apr-1.0/apr_file_io.h>
#include <apr-1.0/apr_lib.h>
#include <apr-1.0/apr_strings.h>
#include <apr-1.0/apr_thread_proc.h>
#else
#error "libapr header files not found"
#endif

/* Program name */
#define PROG_NAME                   "otplock"

#define LOCKFILE_SUFFIX ".lock"
#define DEFAULT_EDITOR  "vim"

/* Error exit values */
#undef  EXIT_USAGE_ERROR
#undef  EXIT_SYSTEM_ERROR

#define EXIT_USAGE_ERROR            85          /* Incorrect command line usage */
#define EXIT_SYSTEM_ERROR           86          /* Could not open file, etc. */
#define EXIT_CAUGHT_SIGNAL          87

extern const char *const *environ;

static void usage(void);

int
main(int argc, const char *const *argv)
{
    char lockfile[APR_PATH_MAX];
    const char *usersfile;
    const char *editcmd[3];
    char errbuf[256];
    apr_pool_t *pool;
    apr_file_t *handle = NULL;
    apr_status_t status;
    int edit = 0;
    int ch;
    int r;

    // Initialize APR
	if ((status = apr_app_initialize(&argc, &argv, &environ)) != APR_SUCCESS) {
        warnx("%s: %s", "apr_app_initialize", apr_strerror(status, errbuf, sizeof(errbuf)));
        r = EXIT_SYSTEM_ERROR;
        goto out0;
    }
	if ((status = apr_pool_create(&pool, NULL)) != APR_SUCCESS) {
        warnx("%s: %s", "apr_pool_create", apr_strerror(status, errbuf, sizeof(errbuf)));
        r = EXIT_SYSTEM_ERROR;
        goto out1;
    }

    // Parse command line
    while ((ch = getopt(argc, (char **)(intptr_t)argv, "eh")) != -1) {
        switch (ch) {
        case 'e':
            edit = 1;
            break;
        case 'h':
            usage();
            r = 0;
            goto out2;
        default:
            usage();
            r = EXIT_USAGE_ERROR;
            goto out2;
        }
    }
    argc -= optind;
    argv += optind;
    switch (argc) {
    case 0:
        usage();
        r = EXIT_USAGE_ERROR;
        goto out2;
    default:
        argc--;
        usersfile = *argv++;
        break;
    }

    // Handle "-e" flag
    if (edit) {
        const char *const *ev;

        if (argc > 0) {
            r = EXIT_USAGE_ERROR;
            goto out2;
        }
        editcmd[0] = DEFAULT_EDITOR;
        for (ev = environ; *ev != NULL; ev++) {
            if (strncmp(*ev, "EDITOR=", 7) == 0) {
                editcmd[0] = *ev + 7;
                break;
            }
        }
        editcmd[1] = usersfile;
        editcmd[2] = NULL;
        argv = editcmd;
        argc = 2;
    }

    // Open the lock file
    apr_snprintf(lockfile, sizeof(lockfile), "%s%s", usersfile, LOCKFILE_SUFFIX);
    if ((status = apr_file_open(&handle, lockfile, APR_WRITE|APR_CREATE|APR_TRUNCATE, APR_UREAD|APR_UWRITE, pool)) != APR_SUCCESS) {
        warnx("can't open \"%s\": %s", lockfile, apr_strerror(status, errbuf, sizeof(errbuf)));
        r = EXIT_SYSTEM_ERROR;
        goto out2;
    }

    // Lock the lock file
    if ((status = apr_file_lock(handle, APR_FLOCK_EXCLUSIVE)) != APR_SUCCESS) {
        warnx("can't lock \"%s\": %s", lockfile, apr_strerror(status, errbuf, sizeof(errbuf)));
        r = EXIT_SYSTEM_ERROR;
        goto out3;
    }

    // Execute command, if any
    if (*argv != NULL) {
        apr_procattr_t *pattr;
        apr_exit_why_e why;
        apr_proc_t proc;
        int rval;

        if ((status = apr_procattr_create(&pattr, pool)) != APR_SUCCESS) {
            warnx("%s: %s", "apr_procattr_create", apr_strerror(status, errbuf, sizeof(errbuf)));
            r = EXIT_SYSTEM_ERROR;
            goto out4;
        }
        if ((status = apr_procattr_cmdtype_set(pattr, APR_SHELLCMD_ENV)) != APR_SUCCESS) {
            warnx("%s: %s", "apr_procattr_cmdtype_set", apr_strerror(status, errbuf, sizeof(errbuf)));
            r = EXIT_SYSTEM_ERROR;
            goto out4;
        }
        if ((status = apr_proc_create(&proc, *argv, argv, environ, pattr, pool)) != APR_SUCCESS) {
            warnx("%s: %s", "apr_proc_create", apr_strerror(status, errbuf, sizeof(errbuf)));
            r = EXIT_SYSTEM_ERROR;
            goto out4;
        }
        if ((status = apr_proc_wait(&proc, &rval, &why, APR_WAIT)) != APR_CHILD_DONE) {
            warnx("%s: %s", "apr_proc_wait", apr_strerror(status, errbuf, sizeof(errbuf)));
            r = EXIT_SYSTEM_ERROR;
            goto out4;
        }
        switch (why) {
        case APR_PROC_EXIT:
            if ((r = rval) == APR_ENOTIMPL)
                r = 0;
            break;
        case APR_PROC_SIGNAL:
        case APR_PROC_SIGNAL_CORE:
            r = EXIT_CAUGHT_SIGNAL;
            break;
        default:
            warnx("%s: %s", "apr_proc_wait", "unknown 'why' code");
            r = EXIT_SYSTEM_ERROR;
            break;
        }
    } else
        r = 0;

    // Clean up and exit
out4:
    apr_file_unlock(handle);
out3:
    apr_file_close(handle);
out2:
    apr_pool_destroy(pool);
out1:
    apr_terminate();
out0:
    return r;
}

static void
usage()
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s usersfile [ command ... ]\n", PROG_NAME);
    fprintf(stderr, "    %s -e usersfile\n", PROG_NAME);
    fprintf(stderr, "    %s -h\n", PROG_NAME);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "    -e\tInvoke $EDITOR with usersfile\n");
    fprintf(stderr, "    -h\tDisplay this usage message\n");
}
