# UAF - Universal Authentication Framework

[![Join the chat at https://gitter.im/eBay/UAF](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/eBay/UAF?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

[UAF Architectural Overview](https://fidoalliance.org/wp-content/uploads/html/fido-uaf-overview-v1.0-ps-20141208.html)

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
3. RP Client App - Android relying party client app for demoing UAF server
