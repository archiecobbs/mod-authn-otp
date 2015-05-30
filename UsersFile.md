## Overview ##

The users file contains the secret information about users, PINs, and token keys on the server. It's location is configured via the `OTPAuthUsersFile` directive. This file is updated (rewritten) whenever the server needs to save new information. Therefore, you should only edit it when the server is stopped (or no authentication is occurring).

You will need to create this file manually and be sure to set the permissions correctly (see below). Each line defines one user+token combination. Currently a user may only have a single associated token.

Users may have an arbitrary length PIN, or a dash ("-") for no PIN, or a plus ("+") if the PIN is verified externally using the configured `OTPAuthPINAuthProvider` list (see [Configuration](Configuration.md) for details on external PIN verification). It is strongly recommended to set all PIN's to a plus sign and configure a `OTPAuthPINAuthProvider` for PIN verification.

When a user has a PIN, it must precede the one-time password in the HTTP password field. For example, if a user has PIN "1234" and the token generates the one-time password of "567890", then the user must enter "1234567890" as their password for HTTP authentication.

Tokens must be configured as event tokens or time tokens and of course the token's key must be entered. In addition, you may optionally specify the initial counter value (for event tokens) or relative time period offset adjustment (for time tokens); both values default to zero if not specified.

For time based tokens, the length of a single time interval is specified as part of the token type (see below).

See OneTimePasswords and [Tokens](Tokens.md) for more information about how one-time passowords and tokens work.

## Permissions ##

The Apache web server must have permission to create files in the same directory as this file, and to delete (overwrite) this file with an updated copy. This is because the way **mod\_authn\_otp** updates the file is by writing out a new version under a temporary name and then renaming the temporary file to the real one.

For example, on [openSuSE Linux](http://www.opensuse.org/) this means the file and parent directory should be owned by user `wwwrun` and group `www`.

If it's not already obvious, because it contains sensitive security information **never put this file where it could be publicly visible**. For example, it should probably be in a directory that is only readable by the Apache process.

## Format ##

An example users file is included in the distribution and is reproduced here:
```
#
# Example users file for mod_authn_otp
#
# Blank lines and lines starting with '#' are ignored. Fields are whitespace-separated.
#
# Fields:
#
#   1. Token Type         See below
#   2. Username           User's username
#   3. PIN                User's PIN, or "-" if user has no PIN, or "+" to verify PIN via "OTPAuthPINAuthProvider"
#   4. Token Key          Secret key for the token algorithm (see RFC 4226)
#   5. Counter/Offset     Next expected counter value (event tokens) or counter offset (time tokens)
#   6. Failure counter    Number of consecutive wrong OTP's provided by this users (for "OTPAuthMaxOTPFailure")
#   7. Last OTP           The previous successfully used one-time password
#   8. Time of Last OTP   Local timestamp when the last OTP was generated (in the form 2009-06-12T17:52:32L)
#   9. Last IP address    IP address used during the most recent successful attempt
#
#   Fields 5 and beyond are optional. Fields 6 and beyond should be omitted for new users.
#
# Token Type Field:
#
#   This field contains a string in the format: ALGORITHM [ / COUNTERINFO [ / DIGITS ] ]
#
#   The ALGORITHM is either "HOTP" (RFC 4226) or "MOTP" (http://motp.sourceforge.net/).
#
#   The COUNTERINFO is either "E" for an event-based token, or "TNN" for a time based token
#   where "NN" is the number of seconds in one time interval. For HOTP, the default is "E";
#   for MOTP, the default is "T10".
#
#   The DIGITS is the number of digits in the one-time password; the default is six.
#
#   Examples:
#
#       HOTP            - HOTP event-based token with six digit OTP
#       HOTP/E          - HOTP event-based token with six digit OTP
#       HOTP/E/8        - HOTP event-based token with eight digit OTP
#       HOTP/T30        - HOTP time-based token with 30 second interval and six digit OTP
#       HOTP/T60        - HOTP time-based token with 60 second interval and six digit OTP
#       HOTP/T60/5      - HOTP time-based token with 60 second interval and five digit OTP
#       MOTP            - Mobile-OTP time-based token 10 second interval and six digit OTP
#       MOTP/E          - Mobile-OTP event-based token with six digit OTP
#
# For more info see: http://code.google.com/p/mod-authn-otp/wiki/UsersFile
#

# Some users who have logged in at least once.

HOTP    barney        1234    8a2d55707a9084982649dadc04b426a06df19ab2 21      0 820658  2009-06-12T17:52:32L 192.168.1.1
HOTP    fred          5678    acbd18db4cc2f85cedef654fccc4a4d8bd537891 78      0 617363  2009-06-04T21:17:03L 192.168.1.2
HOTP/T  joe           999999  ef654fccdef654fccc4a4d8acbd18db4cc2f85ce -2      2 883913  2009-06-04T21:17:03L 10.1.1.153

# Wilma and Betty are new users. Note betty does not have a PIN so "-" is used instead as a placeholder

HOTP    wilma         5678    a4d8acbddef654fccc418db4cc2f85cea6339f00
HOTP    betty         -       54fccc418a4d8acbddef6db4cc2f85ce99321d64

# Here is a user who's PIN is verified externally using whatever "OTPAuthPINAuthProvider" list you have configured.
# E.g. to use an htpasswd type file, specify "OTPAuthPINAuthProvider file" and then "AuthUserFile /some/file".
HOTP    bambam        +       d8acbddef6db4cc254fccc418a4f85ce99321d64

```

To add users, add new lines to the file containing only the first four or five fields (see for example `wilma`, `betty`, and `bambam`).

Some of the fields have been added to this file in newer **mod\_authn\_otp** versions. Newer versions of **mod\_authn\_otp**
are backward compatible with older versions' file formats and will automatically upgrade them the first time they are used.

## Locking ##

**mod\_authn\_otp** creates a lock file in the same directory as the users file in order to synchronize server threads so they don't try to update the users file at the same time. The file is empty; it just needs to be there so it can be locked.

## Mobile-OTP ##

**mod\_authn\_otp** supports using the [Mobile-OTP](http://motp.sourceforge.net/) algorithm instead of HOTP/OATH. In this case the PIN (if any) should be entered into the token when generating the one-time password and _not_ as a prefix to the HTTP password. Use token type "MOTP" instead of "HOTP".

Note: MOTP authentication is not compatible with the **OTPAuthPINAuthProvider** configuration directive. With MOTP tokens, the PIN must be explicitly provided in the users file.