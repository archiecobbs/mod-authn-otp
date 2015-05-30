## Overview ##

In a nutshell, for best security:
  * Only use **mod\_authn\_otp** with SSL-encrypted web sites when a non-zero maximum linger time is configured.
  * Set the `OTPAuthLogoutOnIPChange` directive to `On`.
  * Always use PINs and verify them externally using `OTPAuthPINAuthProvider`.

The security of one-time passwords themselves is well understood; see [RFC 4226](http://www.ietf.org/rfc/rfc4226.txt) for a discussion. When used for HTTP authentication, however, some additional security concerns arise.

On the other hand, the _lack_ of security in HTTP basic authentication is also well understood (your password is sent across the network unencrypted). At least, we can state that using one-time passwords for HTTP basic authentication is definitely better than using a static username/password pair with HTTP basic authentication.

HTTP digest authentication is much more secure that HTTP basic authentication, but itself has important limitations when used with **mod\_authn\_otp**; see DigestAuthentication for details.

Here are some other factors that affect security. Each server administrator will have to decide for themselves what is adequate.

## Linger Time ##

One-time passwords are, as the name implies, supposed to only be used once. Configuring a non-zero linger time means that the server will allow the same one-time password to be used multiple times within the defined time window. Clearly this weakens the security.

Therefore, it is recommended that when a non-zero maximum linger time is configured, **mod\_authn\_otp** only be used with SSL-encrypted web sites. This will protect you from someone sniffing the one-time password off the network and re-using it.

It is also recommeded to set the `OTPAuthLogoutOnIPChange` directive to `On` in all cases unless it causes problems.

## PINs ##

The use of PINs is strongly suggested; without them you only have "one-factor" authentication. Note that user PINs don't have to be numeric; any whitespace-free password can be used as a PIN.

More subtly, the use of PINs helps prevent denial-of-service attacks. This is because **mod\_authn\_otp** first verifies the user's PIN before examining the one-time password. Since the latter operation can be time-consuming (and, with digest authentication, cause event based tokens to get out of sync), we want to prevent attackers from forcing us to perform it. Using PINs will do this because we assume attackers don't know users' PINs.

Many software tokens themselves require the users to enter a PIN to generate a new one-time password. While this increases security, it's not a substitute for requiring the PIN to be entered as part of the HTTP password.

For best security, don't store your PINs in the [UsersFile](UsersFile.md) directly. Instead, set them to `+` and configure an `OTPAuthPINAuthProvider` (see [Configuration](Configuration.md) for details).

## Logout ##

Since HTTP authentication is essentially stateless, there's no actual "login" process. Each HTTP request requires its own authentication. Similarly, there is also no "logout" process. In other words, there is no way for the user or the server to force a "logout" of the user's browser, because the browser is never "logged in". With **mod\_authn\_otp**, the "logout" happens exactly when the maximum linger time is reached.

Actually, in practice there is a way for the server to "logout" the user: by returning a 401 Unauthorized HTTP error code. This will cause the brower to "forget" the username/password pair that it has been using and prompt for a new one. However, this would have to be done at the script level (e.g., via PHP script). Also, this only "logs out" that user's browser. An attacker who was able to use the same one-time password from a different browser within the maximum linger time would still be able to get in.

Starting in version 1.1.7, you can force **mod\_authn\_otp** to "forget" that you are logged in. To do this, first restart your web browser, which will cause your browser (but not **mod\_authn\_otp**) to forget your password. Then reconnect to the web server, and when it asks for you to login again, enter your username with an empty password. **mod\_authn\_otp** will then "forget" (i.e., cancel) your previous one-time password. To prevent denial-of-service attacks, this request must originate from the same IP address as your previous login.

## Digest Authentication DOS Attack ##

In the design of the Apache web server, a module is not able to directly verify the user's password when digest authentication is used. Instead, the module is given the username and realm, and must produce the digest hash using the user's _expected_ password. The server then compares this hash value with the value sent from the client.

With event based tokens, the server has to assume that the user is using the next one-time password, so the server increments its current counter value with each authentication attempt. This opens the door to a denial of service attack: assuming an attacker knows a user's username and knows that user's PIN (or the user doesn't have a PIN), then by repeatedly attempting to authenticate as that user using any random one-time password, the attacker can make the server's current counter value for that token grow hopelessly out of sync.

Another good reason to always use PINs.
