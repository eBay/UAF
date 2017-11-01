[![Build Status](https://secure.travis-ci.org/neXenio/UAF.svg?branch=master)](https://travis-ci.org/eBay/UAF)

# FIDO UAF - Universal Authentication Framework

This projects provides a Java implementation of the [UAF protocol][uaf-protocol-overview] (as defined per [specification][uaf-specification-v1.0]) that can be used by [UAF Clients][uaf-client-overview] and [UAF Servers][uaf-server-overview].


## What is UAF?

The goal of the Universal Authentication Framework is to provide a unified and extensible authentication mechanism that supplants passwords while avoiding the shortcomings of current alternative authentication approaches. Read more at the [UAF Specification][uaf-specification-v1.0].

# Usage

## Integration

### Gradle
```groovy
repositories {
    maven {
        url  "http://dl.bintray.com/neXenio/UAF"
    }
}
dependencies {
    compile 'package.id.placeholder:0.0.0.0'
}
```

### Maven
```xml
<dependency>
  <groupId>package.id.placeholder</groupId>
  <artifactId>uaf</artifactId>
  <version>0.0.0.0</version>
</dependency>
```

### JAR
You can download the latest .jar files from [GitHub][releases] or [Bintray][bintray].


[releases]: https://github.com/neXenio/UAF/releases
[bintray]: https://bintray.com/neXenio/UAF/

[fido]: https://fidoalliance.org/
[fido-specifications-overview]: https://fidoalliance.org/specifications/overview/
[uaf-architectural-overview]: https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-overview-v1.0-ps-20141208.html
[uaf-specification-v1.0]: https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-protocol-v1.0-ps-20141208.html
[uaf-client-overview]: https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-overview-v1.0-ps-20141208.html#fido-uaf-client
[uaf-server-overview]: https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-overview-v1.0-ps-20141208.html#fido-uaf-server
[uaf-protocol-overview]: https://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-overview-v1.0-ps-20141208.html#fido-uaf-protocols
[tizen-uaf-guide]: https://developer.tizen.org/development/guides/native-application/personal-data/authentication-and-authorization/fido-universal-authentication-framework