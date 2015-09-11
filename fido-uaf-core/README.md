# Implementation of FIDO UAF Server Side
[FIDO Specification](http://fidoalliance.org/specifications/download)

# Message Object And Operations
[Fido UAF Protocol](http://fidoalliance.org/specs/fido-uaf-v1.0-ps-20141208/fido-uaf-protocol-v1.0-ps-20141208.html)

# Implementing Registration Data Storage
The storage where the registration data will be kept is something that is specific to the particular deployment.

It is opposite to how the UAF operations are set: The same operation implementation can be used in any deployment.

For that reason storage can be implemented separately by implementing this interface:
```
org.ebayopensource.fido.uaf.storage.StorageInterface
```

### Implementing Notary Service
Similar to the storage, the way how the server data will be authenticated by the server is matter of the particular deployment.

In this case it is assumed that if server data is signed with a key only known by the server, this would be good enough to verify data later on. By verifying the signature, server can decide if this was the server data produced by it earlier.

The actual implementation needs to be done for each use-case, by implementing the following interface:
```
org.ebayopensource.fido.uaf.crypto.Notary;
```

# References
- [FAQ](FAQ.md)
- [LICENSE](LICENSE.md)
