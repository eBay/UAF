# FIDO UAF Demo Server
[FIDO Specification](http://fidoalliance.org/specifications/download)

This code is to demo how the implementation of the FIDO UAF protocol can be used.
## UAF Server Endpoints
### UAF Operations
- Registration
  - GET /v1/public/regRequest/{username}
  - POST /v1/public/regResponse
- Authentication
  - GET /v1/public/authRequest
  - POST /v1/public/authResponse
- Deregistration
  - POST /v1/public/deregRequest

### Demo Server Utils
These endpoints are providing the quick info about what is happening with the server. You can see all registered keys, history of operations requests, etc.
- /v1/registrations
- /v1/stats
- /v1/history

## UAF Protocol Implementation Details
The UAF protocol implementation is included in Maven dependencies for the demo server like this:
```
<dependency>
  <groupId>org.ebayopensource</groupId>
  <artifactId>fido-uaf-core</artifactId>
  <version>0.0.1-SNAPSHOT</version>
</dependency>
```
### Implementing Registration Data Storage
The storage where the registration data will be kept is something that is specific to the particular deployment.

It is opposite to how the UAF operations are set: The same operation implementation can be used in any deployment.

For that reason storage can be implemented separately by implementing this interface:
```
org.ebayopensource.fido.uaf.storage.StorageInterface
```
To demo this, the demo server is implementing it in this class:
```
org.ebayopensource.fidouaf.res.util.StorageImpl
```
The most important methods would be:
```
public void store(RegistrationRecord[] records)
    throws DuplicateKeyException, SystemErrorException {
  if (records != null && records.length > 0) {
    for (int i = 0; i < records.length; i++) {
      if (db.containsKey(records[i].authenticator.toString())) {
        throw new DuplicateKeyException();
      }
      db.put(records[i].authenticator.toString(), records[i]);
    }

  }
}

public RegistrationRecord readRegistrationRecord(String key) {
  return db.get(key);
}
```
### Implementing Notary
Similar to the storage, the way how the server data will be authenticated by the server is matter of the particular deployment.

In this case it is assumed that if server data is signed with a key only known by the server, this would be good enough to verify data later on. By verifying the signature, server can decide if this was the server data produced by it earlier.

The actual implementation needs to be done for each use-case, by implementing the following interface:
```
org.ebayopensource.fido.uaf.crypto.Notary;
```
For demo server it is implemented like this:
```
public class NotaryImpl implements Notary {

	private static Notary instance = new NotaryImpl();

	private NotaryImpl() {
		// Init
	}

	public static Notary getInstance() {
		return instance;
	}

	public String sign(String signData) {
		return SHA.sha256(signData);
	}

	public boolean verify(String signData, String signature) {
		return signature.equals(SHA.sha256(signData));
	}

}
```
