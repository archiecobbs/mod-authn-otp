
#
# mod_authn_otp - Basic and digest authentication using one-time passwords
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
# $Id$
#

all-local:    module

module: mod_authn_otp.c
		if test "$(srcdir)" != "."; then $(CP) $(srcdir)/mod_authn_otp.c .; fi
		$(APXS) -c -D_REENTRANT `echo $(GCC_WARN_FLAGS) | sed -r 's/ -/ -Wc,-/g'` mod_authn_otp.c

install-exec-local: module
		$(APXS) -S LIBEXECDIR="$(DESTDIR)`$(APXS) -q LIBEXECDIR`" -i mod_authn_otp.la

CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

EXTRA_DIST=         CHANGES LICENSE mod_authn_otp.c users.sample

