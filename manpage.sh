#!/bin/sh

cat << "xxEOFxx"
#summary Wiki-fied version of the otptool man page
#labels Featured

The *mod-authn-otp* distribution includes a command line utility called *otptool* which performs various operations using one-time passwords. The man page is reproduced here:

{{{
xxEOFxx

groff -r LL=131n -r LT=131n -Tlatin1 -man ../trunk/otptool.1 | sed -r -e 's/.\x08(.)/\1/g' -e 's/[[0-9]+m//g' 

echo -n '}}}'
