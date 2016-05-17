package org.ebayopensource.webauthn.op;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.ebayopensource.webauthn.crypto.KeyUtil;
import org.ebayopensource.webauthn.crypto.SignatureUtil;
import org.ebayopensource.webauthn.msg.Assertion;
import org.ebayopensource.webauthn.msg.RegistrationRecord;
import org.ebayopensource.webauthn.res.util.StorageInterface;

public class AuthProcessor {
	
	private SignatureUtil signatureUtil = new SignatureUtil();
	private KeyUtil keyUtil = new KeyUtil();
	
	public RegistrationRecord auth (Assertion assertion, StorageInterface storage) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException, InvalidKeySpecException{
		RegistrationRecord res = storage.getRegRecord(assertion.key);
		if (res == null){
			return null;
		}
		
		verifyChallenge (assertion.clientData);
		
		if (signatureUtil.isValid(keyUtil.getPubKey(res.pubKey), assertion.signature, assertion.clientData, assertion.authnrData)){
			return res;
		}
		
		return null;
	}

	private void verifyChallenge(String clientData) {
		// TODO Auto-generated method stub
		
	}
	
	public String genChallenge (){
		return "changeIt";
	}
}
