## Overview ##

The **mod\_authn\_otp** module is an Apache [authentication provider](http://httpd.apache.org/docs/2.2/howto/auth.html). That basically means it knows how to retrieve the passwords corresponding to usernames when HTTP basic or digest authentication is performed.

## Configuring Apache ##

As such, the first thing to do to enable one-time passwords is to tell Apache to use the **OTP** provider for authentication.

For example, if you want basic authentication you'd do something like this:
```
<Directory "/protected/stuff">
    AuthType basic
    AuthName "My Protected Area"
    AuthBasicProvider OTP
    Require valid-user
    # other options...
</Directory>
```
For digest authentication, you'd do something like this:
```
<Directory "/protected/stuff">
    AuthType digest
    AuthName "My Protected Area"
    AuthDigestProvider OTP
    Require valid-user
    # other options...
</Directory>
```
(but **see the DigestAuthentication wiki page for limitations of OTP when used with digest authentication**)

Next, sprinkle in whatever additional usual Apache configuration directives you want.

Note that the number of digits in a one-time password and the length of a single timer interval (for time based tokens) is configured in the UsersFile on a per-token basis.

## Configuring mod\_authn\_otp ##

Finally, configure the **mod\_authn\_otp** specific directives:

| **Directive** | **Type** | **Default** | **Required?** | **Description** |
|:--------------|:---------|:------------|:--------------|:----------------|
| **OTPAuthUsersFile** | File     |  _N/A_      | Yes           | Specifies the users file containing user, PIN, and token information |
| **OTPAuthMaxOffset** | Number   | 4           | No            | Maximum allowed offset from the expected token counter value |
| **OTPAuthMaxLinger** | Number   | 600         | No            | Maximum allowed linger time in seconds |
| **OTPAuthLogoutOnIPChange** | Boolean  | Off         | No            | Auto-logout user if their IP address changes |
| **OTPAuthPINAuthProvider** | List     | Empty       | No            | One or more [authentication providers](http://httpd.apache.org/docs/2.2/howto/auth.html) to be used for external PIN verification |
| **OTPAuthMaxOTPFailure** | Number   | None        | No            | Maximum number of consecutive wrong OTP values before account is locked out |
| **OTPAuthFallThrough** | Boolean  | Off         | No            | Allow invalid login attempts to fall through to the next authorization provider |

A detailed description of each directive follows.

### OTPAuthUsersFile ###

This directive configures the **users file** which is plain text file that functions as **mod\_authn\_otp**'s database.

The system file permissions assigned to this file and its containing directory are important for proper operation. In order to function correctly, the Apache server must have permission to create files in the same directory as this file, and to delete (overwrite) this file with an updated copy.

See the UsersFile wiki page for more information about its format and required permissions.

### OTPAuthMaxOffset ###

For event based tokens, this is the maximum allowable number of "lost" one-time passwords before the next one-time password will fail to authenticate. The higher this value, the more likely the server will stay synchronized with the token even if you have users who get bored and generate one-time passwords just for fun and then throw them away. On the other hand, the amount of computation the server performs when an incorrect one-time password is used increases linearly with this number (note if the PIN is incorrect, we never get that far, so there's no denial of service attack without knowing at least the PIN).

For time based tokens, this is the maximum number of time intervals that the server will search before and after the current time interval for a matching one-time password. The performance implications are similar as with event based tokens.

The default value for this directive is 4.

See OneTimePasswords for more details about synchronization.

### OTPAuthMaxLinger ###

This defines the maximum "linger time" during which a previously entered one-time password will remain valid. The linger time allows browsing without requiring HTTP authentication on each page, image, etc. load.

The default value for this directive is 600 seconds, i.e., ten minutes. This is probably too low for extensive browsing (forcing your users to enter a password every ten minutes may be annoying).

Note that this is _not_ an idle time. It doesn't matter how active (or inactive) the user is during this time: the timer starts counting from the time the one-time password is first used and then continues to count up toward the limit. Once the linger time expires, the previously used one-time password is no longer accepted.

See OneTimePasswords for more details about why a linger time is required for HTTP authentication.

### OTPAuthLogoutOnIPChange ###

This option is an extra security safeguard that will refuse to allow re-use of a one-time password if the IP address from which the new request originates changes. This would prevent (for example) someone sniffing your password from an unencrypted HTTP request and reusing it.

Specify this setting as either `On` or `Off`. While the default value is `Off` for backward-compatibility, it is strongly recommended to enable this setting unless you have a reason not to (e.g., requests are going through a proxy farm).

Note that in Apache 2.4.x and later, the IP address being checked is the originating user agent's IP address instead of the IP address of whatever machine connects to the server via TCP. This only matters if the client is behind a proxy, in which case these will be different. In Apache 2.2.x, we track the IP address of the proxy, whereas in Apache 2.4.x, we track the IP of the originating client ([more info here](http://httpd.apache.org/docs/2.4/developer/new_api_2_4.html#upgrading)).

This configuration directive is supported in versions 1.1.2 or later of **mod\_authn\_otp**.

### OTPAuthPINAuthProvider ###

This directive configures the [authentication provider](http://httpd.apache.org/docs/2.2/howto/auth.html) list for external PIN verification. External PIN verification applies to any user who's PIN is set to `+` in the [UsersFile](UsersFile.md).

**Note:** External PIN verification is not compatible with digest authentication or MOTP tokens. Users whose PINs are set to `+` in the [UsersFile](UsersFile.md) will not be able to authenticate using digest authentication or MOTP tokens.

For example, to have all your PINs stored in `htpasswd`-style encrypted form in the file `/etc/pins` instead of in plaintext in the [UsersFile](UsersFile.md), you set all the PINs to `+` in the [UsersFile](UsersFile.md), and then configure Apache like this:
```
<Directory "/protected/stuff">
    AuthType                basic
    AuthName                "My Protected Area"
    AuthBasicProvider       OTP
    Require                 valid-user

    OTPAuthUsersFile        "/etc/otp-users.txt"
    OTPAuthPINAuthProvider  file
    AuthUserFile            "/etc/pins"
</Directory>
```
This can get a little confusing. Here the `AuthUserFile` directive is used to configure the `file` authentication provider, which is configured via `OTPAuthPINAuthProvider` as the external verification mechanism for PINs. The `file` authentication provider is _not_ used for HTTP Basic password verification; we've specified `OTP` for that instead via the `AuthBasicProvider` directive. Note that we could have chosen any other Apache authentication provider besides `file` for PIN verification.

To set a PIN in `/etc/pins`, you would use the `htpasswd` command like you normally would to set a password.

Apache allows you to configure multiple authentication providers in the `AuthBasicProvider` directive along with the `OTP` provider. If you specify the same provider in the `AuthBasicProvider` directive (along with `OTP`) as well as in the `OTPAuthPINAuthProvider` directive, then there will be a configuration directive conflict. In other words, the other provider-specific configuration directives for that provider will get used twice, once for HTTP basic authentication and again for OTP PIN verification; this is probably not what you want. For example if you specified `AuthBasicProvider OTP file`, `OTPAuthPINAuthProvider file`, and `AuthUserFile "/etc/pins"`, then `/etc/pins` would be used both for normal HTTP basic authentication and OTP PIN verification, so a user could login with just their PIN (because the `file` provider would accept it).

In order to avoid these problems, use authentication provider aliases (in Apache versions prior to 2.4, this functionality is provided by the [mod\_authn\_alias](http://httpd.apache.org/docs/2.2/mod/mod_authn_alias.html) module). Here is an example:

```
# Create the "my-pin" authn provider based on the "file" authn provider
<AuthnProviderAlias file my-pin>
    AuthUserfile            "/etc/otp-pins"
</AuthnProviderAlias>

# Create the "my-otp" authn provider based on "OTP" authn provider
<AuthnProviderAlias OTP my-otp>
    OTPAuthUsersFile        "/etc/otp-users.txt"
    OTPAuthLogoutOnIPChange On
    OTPAuthPINAuthProvider  my-pin
</AuthnProviderAlias>

# Protect directory using "my-otp" authn provider
<Directory "/protected/stuff">
    AuthType                basic
    AuthName                "My Protected Area"
    AuthBasicProvider       my-otp
    Require                 valid-user
</Directory>
```

This configuration directive is supported in versions 1.1.3 or later of **mod\_authn\_otp**.

### OTPAuthMaxOTPFailure ###

This directive sets a limit on how many consecutive incorrectly submitted OTP values **mod\_authn\_otp** will allow before locking out the user's account. This serves as a protecting against automated attacks that use a brute-force approach to try all possible OTP values.

Note that this limit applies to incorrect OTP values, not incorrect PIN values. When an incorrect PIN is submitted, we never get as far as checking the OTP. So necessarily, all attempts that count against this limit have a correct PIN. For example, this could happen in a situation where an attacker knows (or has guessed) the user's PIN, but does not have access to the user's token.

Look in the Apache server error log for a message at level `NOTICE` of the form `user "fred" has reached the maximum wrong OTP limit` to detect a lockout situation. When an account is locked out, a manual edit of the UsersFile is required to unlock it: simply delete the sixth and subsequent fields for that user.

The default value for this directive is zero, which means this check is disabled.

This configuration directive is supported in versions 1.1.4 or later of **mod\_authn\_otp**.

### OTPAuthFallThrough ###

This directive changes the behavior when a valid (i.e., known) username but an invalid password (PIN and/or OTP value) is provided. Normally that situation results in an immediate invalid login error and access is denied. Setting `OTPAuthFallThrough` to `On` changes this so that **mod\_authn\_otp** behaves as if the user is not recognized (i.e., unknown) in this case.

If **mod\_authn\_otp** is the only authorization provider configured, then the result is the same - access denied. However, if there are other authorization providers configured after **mod\_authn\_otp**, then setting `OTPAuthFallThrough` to `On` will allow those subsequent authorization providers to attempt to authorize the same user using a different password. This can be useful in situations where you want normal humans to use one-time passwords, but also allow automated logins on their behalf from devices that don't support generating one-time passwords. You would then configure a normal username/password authorization provider after **mod\_authn\_otp** with the fixed (and presumably much longer and harder to remember) device password.

Note: fall-through to a subsequent authorization provider only occurs when the supplied password contains an invalid PIN or has the wrong overall length. Otherwise **mod\_authn\_otp** handles the authentication itself.

The default value for this directive is `Off`, which means that an invalid password causes an immediate rejection.

This configuration directive is supported in versions 1.1.7 or later of **mod\_authn\_otp**.