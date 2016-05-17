package org.ebayopensource.webauthn.res.util;

import org.ebayopensource.webauthn.msg.RegistrationRecord;

public interface StorageInterface {
	
	public RegistrationRecord getRegRecord(String key);
	public void store(RegistrationRecord record) throws DuplicateKeyException, SystemErrorException ;

}
