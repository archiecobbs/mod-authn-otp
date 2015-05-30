The **mod-authn-otp** distribution includes a command line utility called **otptool** which performs various operations using one-time passwords. The man page is reproduced here:

```
OTPTOOL(1)                                          BSD General Commands Manual                                          OTPTOOL(1)

NAME
     otptool - HOTP/OATH one-time password utility

SYNOPSIS
     otptool [-fht] [-c counter] [-d #digits] [-i secs] [-m PIN] [-w num] key [password]

DESCRIPTION
     otptool is a utility for generating, verifying, and synchronizing one-time passwords created using the HOTP/OATH algorithm
     defined by RFC 4226.

     The key is the token's binary secret key and is specified as a hexadecimal string.

     If no password is given, otptool generates the one-time password corresponding to the given key and target counter value and
     prints to standard output the counter followed by the decimal and hexadecimal one-time passwords.  If password is given, then
     otptool verifies that password is the correct one-time password for the given key and counter value.  If so, it outputs the
     counter value.  password may be either the decimal or hexadecimal one-time password.

     The target counter value is determined as follows: if the -t flag is given, use the current time in seconds since the UNIX
     epoch divided by the configured time interval (default 30 seconds); otherwise, if the -c flag is given, use the given counter;
     otherwise, use the value zero.

     In both cases, a range of target counter values may be specified using the -w flag.  When both -w and password are given,
     otptool will search the entire range for a matching counter value, starting with the target counter value and working away
     from it.  This mode can be used to resynchronize an unsychronized counter.

OPTIONS
     -c      Specify the starting target counter value for the one-time password generation or search.  This flag is incompatible
             with the -t flag; if neither flag is given, the default value is zero.

     -d      Specify the required number of digits in the one-time password.  Giving a password argument and specifying a different
             length here will result in no match being found (no search is performed).  Otherwise, the default value is the length
             of password, if given, or else six if not.

     -f      Read the key from the file named key instead of parsing key as a hexadecimal string.

     -h      Print the usage message and exit successfully.

     -i      Specify the length of a single time interval in seconds.  The default value is 30 seconds.  This flag is ignored
             unless the -t flag is also given.

     -m      Use the Mobile-OTP algorithm with the given PIN instead of the HOTP/OATH algorithm.  This flag imples -i 10 and -d 6.
             Normally you also want to specify -t.

     -t      Use the current time as the basis for the target counter value.  This flag is incompatible with the -c flag.

     -w      Specify the width of a window of counter values within which to iterate when generating or searching for one-time
             passwords.  When -t is used, the window extends the given distance both before and after the target counter value;
             otherwise, the window extends forward of the target counter value.  When both password and -t are given, the search
             starts with the initial target counter and works away from it in both directions.

RETURN VALUE
     otptool exits with one of the following return values:

     0    The one-time password(s) was/were successfully generated, or password correctly matched the password generated using (one
          of) the target counter value(s).

     1    otptool was invoked with invalid command line flags or parameters.

     2    The given password did not match any counter value(s) in the search window.

     3    A system error occurred.

SEE ALSO
     HOTP: An HMAC-Based One-Time Password Algorithm, http://www.ietf.org/rfc/rfc4226.txt.

     mod_authn_otp: Apache module for one-time password authentication, http://mod-authn-otp.googlecode.com/.

     Mobile-OTP: Mobile One Time Passwords, http://motp.sourceforge.net/.

AUTHOR
     Archie L. Cobbs <archie@dellroad.org>

BSD                                                        June 21, 2008                                                        BSD
```