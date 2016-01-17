# Release Notes

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
