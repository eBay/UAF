# Release Notes

## 2016.02.23
### Proposition
This is a proposition on how to utilize standard Android SDK even further, to achieve wide adoption (Android 5 and 6) and best security. All code is in separate branch for now [f_android_uaf_client](https://github.com/eBay/UAF/tree/f_android_uaf_client)

### Proposition Goal
Main goal is to utilize the AndroidKeyStore as a security provider to generate the keys and to do the signatures. That way the keys are stored, and used in the most secure way. 

Usage of standard security interfaces, such as:
```
java.security.KeyPairGenerator
java.security.KeyStore
java.security.Signature
```

Usage of EC algorithm in Android 6, and falling back to standard RSA algorithm in case of Android 5.

### Proposition Implementation
The new Android module has been added: [Marvin - Android UAF client](https://github.com/eBay/UAF/tree/f_android_uaf_client/fidouafclient/marvin)

In this module you will see the UAF Client implemented with plain Android SDK. The only added compile dependency being GSON library.

Key generation example for UAF Reg operation:
- [Android 6](https://github.com/eBay/UAF/blob/f_android_uaf_client/fidouafclient/marvin/src/main/java/org/ebayopensource/fidouaf/marvin/client/op/Reg.java#L209)
- [Android 5](https://github.com/eBay/UAF/blob/f_android_uaf_client/fidouafclient/marvin/src/main/java/org/ebayopensource/fidouaf/marvin/client/op/Reg.java#L95)
 
Signature for UAF Auth operation
- [Android 6](https://github.com/eBay/UAF/blob/f_android_uaf_client/fidouafclient/marvin/src/main/java/org/ebayopensource/fidouaf/marvin/client/AuthAssertionBuilder.java#L205)
- [Android 5](https://github.com/eBay/UAF/blob/f_android_uaf_client/fidouafclient/marvin/src/main/java/org/ebayopensource/fidouaf/marvin/client/AuthAssertionBuilder.java#L183)

KeyguardManager example:
- [Android 5](https://github.com/eBay/UAF/blob/f_android_uaf_client/fidouafclient/marvin/src/main/java/org/ebayopensource/fidouaf/marvin/FidoUafOpActivity.java#L97)

Hope to hear your feedback and comments!

Cheers,
Neb.


## 2016.01.16
In this release of the eBay UAF implementation, in the test UAF client, Android SDK is bumped to version 21 (Android 5).

The reason for doing this is to enable one cool feature that is introduced with this version of Android: The use of KeyguardManager

```
android.app.KeyguardManager
```

Really, standards are everything. By utilizing this standard feature we can enable our UAF client to use fingerprint sensor in any Android phone running the Android 5 or later. Phones like Samsung S5, S6, or the new Nexus device like 5X and 6P. All will work the same.

How cool is that?

Even better, if your phone is not featuring the fingerprint sensor, you can use the feature all the same: Authenticate with pin or pattern the same way you would do as if the fingerprint sensor was available.

Give it a try.
