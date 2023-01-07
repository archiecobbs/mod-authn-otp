
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

all-local:    module

module: mod_authn_otp.c
		if test "$(srcdir)" != "."; then $(CP) $(srcdir)/mod_authn_otp.c .; fi
		$(APXS) -c -D_REENTRANT `echo $(GCC_WARN_FLAGS) | sed 's/ -/ -Wc,-/g'` -l crypto mod_authn_otp.c

install-exec-local: module
		mkdir -p "$(DESTDIR)`$(APXS) -q LIBEXECDIR`"
		$(APXS) -S LIBEXECDIR="$(DESTDIR)`$(APXS) -q LIBEXECDIR`" -i mod_authn_otp.la

install-exec-hook:
		test -z "$(STRIP)" || $(STRIP) $(DESTDIR)`$(APXS) -q LIBEXECDIR`/mod_authn_otp.so
		test -z "$(STRIP)" || $(STRIP) $(DESTDIR)$(bindir)/otptool
		test -z "$(STRIP)" || $(STRIP) $(DESTDIR)$(bindir)/genotpurl

bin_PROGRAMS=       otptool genotpurl

noinst_HEADERS=     otptool.h errinc.h base32.h

man_MANS=           otptool.1 genotpurl.1

otptool_SOURCES=    otptool.c hotp.c motp.c phex.c

genotpurl_SOURCES=  genotpurl.c base32.c

CLEANFILES=         *.la *.lo *.o *.so *.slo .libs/*

EXTRA_DIST=         CHANGES LICENSE mod_authn_otp.c genotpurl.c users.sample otptool.1 genotpurl.1 base32.c

