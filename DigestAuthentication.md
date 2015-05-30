## Overview ##

In the design of the Apache web server, an authentication provider is not able to directly verify the user's password when digest authentication is used. Instead, the module is given the username and realm, and must produce the digest hash using the user's _expected_ password. The server then compares this hash value with the value sent from the client, but the client's value is not visible to the authentication provider.

The key word here is _expected_. The server has to "know" the one-time password that the user is using _a priori_.

This has several negative implications for **mod\_authn\_otp** which make digest authentication difficult to use at best. In the real world, forcing it on your users will probably increase your support load beyond acceptible limits.

**A better solution than digest authentication is to use basic authentication with SSL encryption.**

If you really want to use digest authentication (e.g., SSL is not an option), the following is recommended:
  * Use time based software tokens running on a cell phone that automatically synchronizes its clock with the cell network.
  * Configure the network time protocol (NTP) on your server so its clock stays accurate.
  * Encourage your users to only use "fresh" one-time passwords as soon as possible after they appear on the token.

## Brittleness ##

The first negative result is that the client and server counter values must match _exactly_ on the first try for authentication to succeed. In other words, there is no way for the server to "search" for the correct counter value.

For time based tokens, this simply means that depending on how far the token and server clocks are out of sync, authentication will intermittently or consistently fail. You can manually adjust for this by editing the users file and editing the offset field, but this requires you knowing what the right correction value it (not usually easy to determine). It also means that if there is an appreciable delay between the time the user generates the one-time password and the time they actually send it to the server, authentication can fail.

For event based tokens, the token and server can get out of sync in two ways: if even one of the one-time passwords is "lost", authentication will fail on the next attempt because the token's current counter is higher than the server's. On the other hand, if an attempt to authenticate is made without actually generating a new one-time password, then the server's current counter will be higher than the token's. User's natural tendency to try the same thing over again repeatedly when it doesn't work exacerbates this situation. Note that for users without PINs, an attacker can also exploit this second scenario to create a denial of service attack.

So in both cases we have "brittleness" in the synchronization of counter values. But the event based tokens seem especially brittle with respect to synchronization when digest authentication is used.

Therefore **digest authentication with event-based tokens is not recommended**.

## Linger Time ##

When **mod\_authn\_otp** has to "guess" the expected counter value for digest authentication, it also looks at whether the request is still within the maximum linger time. If so, then it _assumes_ that the previously used one-time password is still going to be used. This means, for example, if the user has restarted their browser and it prompts for a password again and the user generates and enteres a new one-time password, then authentication will fail, and it will continue to fail until the linger time expires. This is true for both time and event based tokens.

However, for time based tokens the problem self-corrects eventually. For event-based tokens, the user has probably tried several times to login and pushed the token's current counter value even farther away from the server's.

Another reason **digest authentication with event-based tokens is not recommended**.

## Auto-Synchronization ##

Because the server never actually sees the one-time password the user entered, it can't auto-synchronize. Therefore, auto-synchronization simply doesn't work with digest authentication.

Manual synchronization is still possible, of course. This would mean editing the users file and setting the offset field directly. However, for many tokens it's difficult or impossible to retrieve the current counter value, so you'd essentially be guessing.

## Hex vs. Decimal ##

When doing HTTP basic authentication, **mod\_authn\_otp** will accept either the decimal or hexadecimal one-time password. With digest authentication, however, it must choose which format ahead of time. For HOTP/OATH, decimal is assumed, while for Mobile-OTP, hexadecimal is assumed.

## External PIN verification ##

Digest authentication is not compatible with external PIN verification. Users whose PINs are set to `+` in the [UsersFile](UsersFile.md) will not be able to authenticate using digest authentication.
