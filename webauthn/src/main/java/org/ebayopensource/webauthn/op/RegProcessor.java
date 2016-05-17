package org.ebayopensource.webauthn.op;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.ebayopensource.webauthn.crypto.KeyUtil;
import org.ebayopensource.webauthn.msg.RegRequest;
import org.ebayopensource.webauthn.msg.RegResponse;
import org.ebayopensource.webauthn.msg.RegistrationRecord;
import org.ebayopensource.webauthn.res.util.DuplicateKeyException;
import org.ebayopensource.webauthn.res.util.StorageInterface;
import org.ebayopensource.webauthn.res.util.SystemErrorException;

public class RegProcessor {
	
	KeyUtil keyUtil = new KeyUtil();
	
	public RegResponse genRegRequest (RegRequest regRequest){
		RegResponse res = new RegResponse();
		
		return res;
	}

	public RegistrationRecord reg (RegResponse regResponse, StorageInterface storage) throws InvalidKeySpecException, NoSuchAlgorithmException, DuplicateKeyException, SystemErrorException{
		RegistrationRecord ret = new RegistrationRecord();
		if (!"RS256".equals(regResponse.alg)){
			throw new NoSuchAlgorithmException();
		}
		verifyChallenge(regResponse);
		ret.alg = regResponse.alg;
		ret.key = regResponse.key;
		ret.pubKey = keyUtil.getPubKeyAsPem(regResponse.n, regResponse.e);
		ret.processingStatus = "SUCCESS";
		ret.processingTimeInMillis = System.currentTimeMillis();
		storage.store(ret);
		return ret;
	}

	private void verifyChallenge(RegResponse regResponse) {
		// TODO Auto-generated method stub
		
	}
	
	public String genChallenge (){
		return "changeIt";
	}
}
