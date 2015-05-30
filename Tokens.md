## Supported Tokens ##

Any [RFC 4226](http://www.ietf.org/rfc/rfc4226.txt) compatible one-time password generator from which you can access the token key should work with **mod\_authn\_otp**.

Note that the _token key_ is not the same thing as the _token ID_, which is typically a alphanumeric string like MATM89382348. The token ID is simply a identifier for the token, like a serial number. The token key on the other hand is typically 16 to 20 bytes of random binary data looking something like "f136803ab9c241079ba0cc1b5d02ee7765df3421". This is the actual cryptographic secret on which the security of the token rests. The token key must be provided to you separately and securely by the token vendor.

You will need a token that is not tied to a specific vendor by way of proprietary design or withholding of information. Of course, this means the token must be OATH-compliant. Many vendors do indeed sell "OATH-compliant" tokens, but they require you to also purchase their expensive, proprietary server-side software to use them. They won't give you the token keys unless you do.

For example, [Verisign's VIP](http://www.verisign.com/authentication/consumer-authentication/identity-protection/index.html) tokens are popular but are not compatible with **mod\_authn\_otp** because it is not possible to extract the token's key.

In any case, do you really think you can trust your security those so-called experts? If you do, [you might want to read some of these articles](http://www.google.com/search?q=rsa+security+breach).

Perhaps over time this "stay proprietary" strategy will evolve away, as it has done in so many other technology areas.

In the meantime, when you call a vendor to inquire, tell them that you are using the open-source authentication solution **mod\_authn\_otp** and that you require token keys.

### Hardware Tokens ###

  * [Gooze](http://www.gooze.eu/) sells the [c100 event based](http://www.gooze.eu/otp-c100-token-event-based) and the [c200 time based](http://www.gooze.eu/otp-c200-token-time-based) tokens which are compatible and have been tested. Note: The c200 should be configured for a 60 second interval. Gooze also has a [HOWTO document](http://www.gooze.eu/howto/feitian-oath-tokens-integration-howto/apache2-mod-authn-otp).
  * [Authenex's A-Key 3600](http://www.authworks.com/authenex-akey-3600.asp) is compatible and has been successfully tested.
  * [Aladdin's eToken PASS](http://www.aladdin.com/etoken/devices/pass.aspx) should work according to the description but has not actually been tested.
  * [Gemalto's Ezio](http://onlinenoram.gemalto.com/) time-based tokens should work but have not been tested.
  * The [YubiKey](http://www.yubico.com/yubikey) supports multiple authentication schemes, is OATH compatible, and has been tested.

### Software Tokens ###

  * [OATH Token](http://oathtoken.googlecode.com/) is a fully configurable iPhone software token app written by the author of this project.
  * [Google Authenticator](http://code.google.com/p/google-authenticator/) runs on Andriod, iOS, and Blackberry. Time-based authentication must use 30 second intervals. Use [this page](https://www.cnysupport.com/index.php/free-stuff/using-google-authenticator-with-apache-mod_authn_otp) to auto-generate `users.txt` lines and QR-codes; or, use [this page](http://darkfader.net/toolbox/convert/) to convert between hexadecimal and the Base-32 key encoding required by this app.
  * [Nordic Edge's Pledge](http://www.securethecloud.com/mobile-client-pledge/) is an event based software token that runs on the iPhone and cell phones. Follow the instructions for a free profile, then enter the token key into your **mod\_authn\_otp** users file.
  * [Mobile-OTP on the iPhone](http://itunes.apple.com/WebObjects/MZStore.woa/wa/viewSoftware?id=318414073&mt=8) is an iPhone app implementing the older [Mobile-OTP](http://motp.sourceforge.net/) algorithm.
  * [Android Token](http://code.google.com/p/androidtoken/) is an OATH token app for Android devices.