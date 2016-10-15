[![Build Status](https://secure.travis-ci.org/eBay/UAF.svg?branch=master)](https://travis-ci.org/eBay/UAF)  [![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/eBay/UAF)
# UAF - Universal Authentication Framework

[UAF Architectural Overview](https://fidoalliance.org/wp-content/uploads/html/fido-uaf-overview-v1.0-ps-20141208.html)

[News & Release Notes](RELEASE.md)

- [2016.10.14 - Added endpoints for whitelisting AAID, and Facet Ids](https://github.com/eBay/UAF/blob/master/RELEASE.md#20161014)
- [2016.05.20 - Added wiki page for Maven build and Tomcat setup/run (using CLI only)](https://github.com/eBay/UAF/wiki/BuildingAndRunningUAFServerUsingMaven(CLIonly))
- [2016.03.28 - Started wiki pages](https://github.com/eBay/UAF/wiki)
- [2016.02.23](https://github.com/eBay/UAF/blob/master/RELEASE.md#20160223)
- [2016.01.16](https://github.com/eBay/UAF/blob/master/RELEASE.md#20160116)

## Vision
The main goal is the passwordless authentication experience

## Values
- Simple to authenticate using biometrics readings, such as fingerprint
- More secure authentication using the cryptography

## Methods
- Standardize the messages, and the message exchange sequence
- Standardize the way how biometric authenticators are receiving requests and giving out responses
- Define how cryptography can be used to secure messages that are exchanged

## Obstacles
- Identifying all required data that needs to be part of the protocol messages
- Correct implementation of message exchange sequence
- Correct implementation of cryptography sign/verify operations
- Correct implementation of encoding/decoding of the messages

## Measures
- Number of successful application of the protocol is high
- Number of protocol adaptations in comparing with password authentication is higher
- Number of security bugs equal to zero

# Implementation details
The code presented here is divided into three groups:

1. [fido-uaf-core](fido-uaf-core/README.md) - UAF protocol implementation
2. [fidouaf](fidouaf/README.md) - UAF server, a Jersey service application for demoing UAF protocol implementation use
3. [RP Client App](fidouafclient) - Android relying party client app for demoing UAF server
