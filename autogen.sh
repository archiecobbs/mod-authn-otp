#!/bin/bash

#
# mod_authn_otp - Apache module for one-time password authentication
#
# Copyright 2009 Archie L. Cobbs <archie@dellroad.org>
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

#
# Script to regenerate all the GNU auto* gunk.
# Run this from the top directory of the source tree.
#

set -e

# Constants
ACLOCAL="aclocal"
AUTOHEADER="autoheader"
AUTOMAKE="automake"
AUTOCONF="autoconf"

# Clean up autojunk
echo "cleaning up"
rm -rf .libs autom4te*.cache scripts aclocal.m4 configure config.log config.status .deps stamp-h1
rm -f otptool *.o *.la *.lo *.slo Makefile.in Makefile
rm -f mod_authn_otp-?.?.?.tar.gz
rm -f config.h*
rm -f TAGS tags

if [ "$1" = "-C" ]; then
    echo "cleanup done, exiting"
    exit
fi

# Create scripts directory
mkdir -p scripts

echo "running aclocal"
${ACLOCAL} ${ACLOCAL_ARGS} -I scripts

echo "running autoheader"
${AUTOHEADER}

echo "running automake"
${AUTOMAKE} --add-missing -c --foreign

echo "running autoconf"
${AUTOCONF} -f -i

if [ "$1" = "-c" ]; then
    echo "running configure"
    ./configure
fi

