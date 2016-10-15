# Release Notes

## 2016.10.14
Added two new endpoints in order to help testing with inbuilt FIDO UAF clients.

Endpoint for whitelisting the UUID:
```
/fidouaf/v1/whitelistuuid/{URL_ENCODED_VALUE}
```

Endpoint for whitelisting the Facet Id:
```
/fidouaf/v1/whitelistfacetid/{URL_ENCODED_VALUE}
```

At a moment the new endpoints are deployed in: http://www.head2toes.org/fidouaf/v1/info

After whitelisting the Lenovo ZUK Z2 inbuilt client, tested all operation successfully
```
AAID: 001A#2121
```

## 2016.08.25
(Status: Waiting on feedback)

Since last time couple of notes:

Proposition to use KeyguardManager to achieve better coverage and adoption didn't find a lot of approvers.

I guess the main reason was in fact that we do not have info about what type of screen unlocking was performed. There is no API to tell us what is the currently selected screen lock mechanism.

It is just adding on to: "The list of things that makes the UAF adoption hard"

### Is it UAF 1.0 protocol too complex?
Let me start by setting the appropriate disclaimer: These are just my personal opinions, so do take them with the healthy dose of salt. Do not take my word for anything before you check it on your own. It all might be my imagination.

It seems to me that the current UAF spec is trying to do too much. This is making it too abstract.

If I start with this hypothesis, next question would be: How to make it less capable, but more desirable?

Where to cut?
- Attestation cert
- TLV
- Policies

#### Attestation cert
Remove the attestation certificate. Anyways only hardware UAF clients can really benefit from it.

Instead sign the public key with the private key.

#### TLV
It is too complex. Replace it with plain JSON.

#### Policies
Not very practical, especially if we do not use attestation together with it.

### Simple API with enough in it
#### Reg
POST /uaf/regRequest

In:
```
{
  "keyid":"somekeyid::Unique",
  "userid":"someuser::Descriptive"
}
```
Out:
```
{
  "challenge":"someting-server-knows-what-to-do-with",
  "status":"confirmation::Ex.Key Id registered"
}
```

POST /uaf/regResponse

In:
```
{
  "challenge":"someting-server-knows-what-to-do-with"
  "pub":"pubkey",
  "format":"key-format",
  "keyid":"somekeyid",
  "sig":"sign(pub+challenge+keyid)"
}
```
Out:
```
{
  "status":"confirmation"
}
```

#### Auth
POST /uaf/authRequest

In:
```
{
  "keyid":"somekeyid",
  "trxid":"some-transaction-id",
  "trxtype":"Description::id,pay,confirm..."
}
```
Out:
```
{
  "challenge":"someting-server-knows-what-to-do-with",
  "status":"confirmation::Ex.Key Id not active"
}
```

POST /uaf/authResponse

In:
```
{
  "challenge":"someting-server-knows-what-to-do-with"
  "trxid":"some-transaction-id",
  "trxtype":"reason-for-request",
  "keyid":"somekeyid",
  "sig":"sign(challenge+trxid+trxtype+keyid)"
}
```
Out:
```
{
  "status":"confirmation"
}
```

#### Dereg
POST /uaf/deregRequest

In:
```
{
  "keyid":"somekeyid:Unique"
}
```
Out:
```
{
  "status":"confirmation:Ex.Key Id not registered
}
```

#### Seek
POST /uaf/seekRequest

In:
```
{
  "keyid":"somekeyid:Unique",
  "userid":"someuser:Descriptive"
}
```
Out:
```
{
  "status":"confirmation:Ex.Key Id registered",
  "match":[
    {
      "keyid":"somekeyid:Unique",
      "pub":"pubkey",
      "format":"key-format",
      "status":"Ex. active|revoked|..."
    }
  ]
}
```

### How UAF server is used?
1) It can be accessed directly
It can be used as public directory if desired. For example users can register with one public IDP, and then register to other sites using the public IDP

2) It can be behind the enterprise authentication server
Enterprise server can:
- check if the userid is valid, and authorized
- ask for app Id
- link keyid with internal userid

In this case enterprise server will take care of app ID, TLS, app facet Id, etc.

### How far off this would be?
Comparing with the UAF 1.0 spec, how far off this would be?

It is simple enough. But not too simple?

Regarding the aspect to what is out of scope of the spec, we have more left out:
- Attestation mechanism
- App Id, and facet Id check
- TLS check
- Policies
- AAID management

This doesn't mean that all those cannot or should not be done, those are just moved out of the spec scope.

Is it less, or more secure? It seems that basic security has not changed. It is the same public/private key cryptography.

### Before we do it
Let me know your thoughts on this before doing any implementation. The closest thing to this rough draft would be this POC for [webauthn](https://github.com/eBay/UAF/tree/webauthn/webauthn)
You can try it out in Edge browser [here](http://www.head2toes.org/warthog/rest/v1/db/get/surface.html)

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
