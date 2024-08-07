
#
# mod_authn_otp - Apache module for one-time password authentication
#
# Copyright 2009 Archie L. Cobbs <archie.cobbs@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

AC_INIT([mod_authn_otp Apache2 authentication module supporting one-time passwords], [1.1.11], [https://github.com/archiecobbs/mod-authn-otp], [mod_authn_otp])
AC_CONFIG_AUX_DIR(scripts)
AM_INIT_AUTOMAKE
dnl AM_MAINTAINER_MODE
AC_PREREQ(2.59)
AC_PREFIX_DEFAULT(/usr)
AC_PROG_MAKE_SET

# Check for required programs
AC_PROG_CC
AC_PROG_INSTALL
AC_PATH_PROG(STRIP, strip)
AC_PATH_PROG(CP, cp)
AC_PATH_PROG(APXS, apxs, "no", [/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/local/apache/bin])
AC_PATH_PROG(APXS2, apxs2, "no", [/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/local/apache/bin])
[test x"$APXS2" = "xno" -a x"$APXS" = "xno" && ] AC_MSG_ERROR([cannot find apxs or apxs2])
[test x"$APXS2" != "xno" && APXS="$APXS2"]

# Add GCC flags
[GCC_WARN_FLAGS=""
CFLAGS=""
if test x"$GCC" = "xyes"; then
    GCC_WARN_FLAGS="-Wall -Waggregate-return -Wcast-align -Wchar-subscripts -Wcomment -Wformat \
        -Wimplicit -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wno-long-long \
        -Wparentheses -Wpointer-arith -Wredundant-decls -Wreturn-type -Wswitch -Wtrigraphs \
        -Wuninitialized -Wunused -Wwrite-strings -Wshadow -Wstrict-prototypes -Wcast-qual"
    CFLAGS="-O3 $GCC_WARN_FLAGS"
fi]
AC_SUBST(GCC_WARN_FLAGS)
AC_SUBST(CFLAGS)

# Check for required libraries
AC_CHECK_LIB(crypto, EVP_sha1,,
	[AC_MSG_ERROR([required library libcrypto missing])])
AC_CHECK_LIB(apr-1, apr_file_lock,,
	[AC_MSG_ERROR([required library libapr missing])])

# Check for optional functions
AC_CHECK_FUNCS(strptime)

# Check for required header files
AC_CHECK_HEADERS(ctype.h errno.h openssl/evp.h openssl/hmac.h openssl/md5.h stdio.h string.h time.h unistd.h, [],
	[AC_MSG_ERROR([required header file '$ac_header' not found])])
AC_CHECK_HEADERS(err.h, [], [])
AC_CHECK_HEADERS(apr-1/apr_file_io.h)
AC_CHECK_HEADERS(apr-1.0/apr_file_io.h)

# Command line flags
AC_ARG_ENABLE(Werror,
    AS_HELP_STRING([--enable-Werror],
        [enable compilation with -Werror flag (default NO)]),
    [test x"$enableval" = "xyes" && CFLAGS="${CFLAGS} -Werror"])

# Generated files
AC_CONFIG_FILES(Makefile)
AC_CONFIG_HEADERS(config.h)

# Go
AC_OUTPUT
