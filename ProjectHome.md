## Overview ##

**mod\_authn\_otp** is an [Apache web server](http://en.wikipedia.org/wiki/Apache_HTTP_Server) module for [two-factor authentication](http://en.wikipedia.org/wiki/Two_factor_authentication) using [one-time passwords](http://en.wikipedia.org/wiki/One-time_password) (OTP) generated via the [HOTP/OATH](http://en.wikipedia.org/wiki/HOTP) algorithm defined in [RFC 4226](http://www.ietf.org/rfc/rfc4226.txt). This creates a simple way to protect a web site with one-time passwords, using any RFC 4226-compliant [token device](http://code.google.com/p/mod-authn-otp/wiki/Tokens), including software tokens that run on cell phones such as [OATH Token](http://oathtoken.googlecode.com/). **mod\_authn\_otp** also supports the [Mobile-OTP](http://motp.sourceforge.net/) algorithm.

**mod\_authn\_otp** supports both event and time based one-time passwords. It also supports "lingering" which allows the repeated re-use of a previously used one-time password up to a configurable maximum linger time. This allows one-time passwords to be used directly in HTTP authentication without forcing the user to enter a new one-time password for every page load. No additional infrastructure other than the **mod\_authn\_otp** module is required to add one-time password support to any Apache web server.

**mod\_authn\_otp** supports both basic and digest authentication, and will auto-synchronize with the user's token within a configurable maximum offset (auto-synchronization is not supported with digest authentication).

**mod\_authn\_otp** is especially useful for setting up protected web sites that require more security than simple username/password authentication yet also don't require users to install special VPN software.

Also included is **otptool**, a one-time password command line utility. **otptool** can be used on a simple call-out basis to integrate two-factor authentication into any existing authentication solution.

## Details ##

See the wiki for a detailed description including supported Apache configuration directives.

  * [Configuration](Configuration.md): How to configure the Apache 2.x server
  * [OneTimePasswords](OneTimePasswords.md): How one-time passwords work and how they integrate with HTTP authentication
  * [Tokens](Tokens.md): Getting tokens for use with **mod\_authn\_otp**
  * [UsersFile](UsersFile.md): The users database
  * DigestAuthentication: Limitations of **mod\_authn\_otp** when used with HTTP digest authentication
  * SecurityConsiderations: Security considerations when using one-time passwords for HTTP authentication
  * [OTPTool](OTPTool.md): Man page for the **otptool** command line utility