## How One-Time Passwords Work ##

The whole idea behind one-time passwords is that they are safer because you use them once and then throw them away. So even if a bad guy sees you entering your password, that knowledge is useless because the next time you login the required password will be different (this requires that knowing one password doesn't make it easy to figure out the next one).

Obviously this trick requires some coordination between the token generating the passwords for the user and the server that is checking them. This coordination basically consists of two things:
  * The token key
  * The current counter value
The token key is a random binary value typically 16 to 20 bytes long. It must be kept secure on (i.e., known only to) the server and the token.

The counter value is what changes every time you use the token to generate a new password. The (typically) six digit number that is the actual one-time password is generated in a cryptographically secure manner using both the token key and the counter.

Note that the token key is not the same thing as the token ID, which is typically a alphanumeric string like MATM89382348. The token ID is simply a identifier for the token.

It is critical that the token and the server have the same idea of the current counter value, or else they will generate different passwords and authentication will fail. This is the notion of **synchronization**.

## Types of Tokens ##

**mod\_authn\_otp** supports two types of tokens: **event based** and **time based**.

### Event Based Tokens ###

Each time you ask an event based token for a new password, it increments the internal counter value by one. On the server, each time you successfully authenticate, the server also increments its counter value by one. In this way (in theory) the token's and the server's counter values stay synchronized in lock step and always will generate the same one-time password.

Event based tokens can get out of sync if the token is asked to generate a bunch of one-time passwords that are never actually used in authentication attempts. Then the token's counter value is increased while the server, oblivious, never increments his. Finally a token-generated one-time password is used for an authentication attempt but it fails because the server doesn't recognize it.

### Time Based Tokens ###

Time based tokens handle the current counter value differently. Instead of incrementing it each time a one-time password is requested, they increment it based on the passing of time. Typically a time interval of 30 seconds is used, so every 30 seconds, the current counter value is incremented and the implied one-time password changes (whether it actually gets used or not). The actual counter value is the computed as the number of time intervals that have passed since the UNIX epoch (1/1/1970 0:00 GMT).

This avoids the synchronization scenario possible with time based tokens but creates a new out-of-sync possibility if the clock on the token and the clock on the server are out of sync.

## Auto-Synchronization ##

In both event-based tokens and time-based tokens it is possible for the server to auto-correct for synchronization problems, within certain limits.

For event based tokens, the server always knows a lower bound on the current counter value (i.e., the counter value used in the previous successful authentication attempt) but not an upper bound. Therefore, if an unrecognized one-time password is seen, the server can try several counter values beyond its expected counter value to see if any of them match. If one happens to work, then the server knows that the intervening counter values have been "lost" and it should skip over them.

For time based tokens, a similar strategy of trying out a few time intervals in the past and the future works to auto-synchronize with clock drift. Of course, regular use of the token is necessary to keep the drift within the recognized range.

## Adapting One-Time Passwords to HTTP Authentication ##

One-time passwords are not directly compatible with HTTP authentication. This is simply because in the HTTP protocol, every page (or image, stylesheet, etc.) loaded by the browser must be authenticated. With event based tokens, this would mean generating and entering multiple one-time passwords with each page load (or reload, or clicked link, etc.). With time based tokens, you would have to enter a password every 30 seconds while browsing.

To workaround this problem, **mod\_authn\_otp** includes a configurable maximum **linger** time. This is the length of time for which **mod\_authn\_otp** will permit the previously (successfully) used one-time password to be re-used. Because web browsers will keep sending the same username and password with each page load until they get an authentication error, the result is that once the user authenticates successfully using a one-time password, they remain "logged in" until the linger time expires.

Note the idea of being "logged in" is only how it appears, as there is really no explicit notion of a session with HTTP authentication. The linger time just creates that illusion.

As such, with HTTP authentication there is also no way to manually "logout". Your browser simply remains logged in until the maximum linger time is reached. However, you can also create the illusion of logging out by returning a `401 Unauthorized` error (e.g., from a PHP script). This will cause the browser to "forget" the current password and start prompting the user for a new one.

This all works fine for HTTP basic authentication. However, due to the design of the Apache web server, digest authentication has some limitations and **using digest authentication with event based tokens is not recommended**; see DigestAuthentication for more information.

See SecurityConsiderations for more information about security aspects. See [Tokens](Tokens.md) for information about the tokens themselves.

## Using PINs ##

Requiring users to prefix their one-time passwords with a PIN is not required by **mod\_authn\_otp** but highly recommended. If a user has a PIN defined, it must precede the one-time password in the HTTP password field. For example, if a user has PIN "1234" and the token generates the one-time password of "567890", then the user must enter "1234567890" as their password for HTTP authentication.