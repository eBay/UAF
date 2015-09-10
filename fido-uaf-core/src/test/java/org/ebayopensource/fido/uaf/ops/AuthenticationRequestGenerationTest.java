package org.ebayopensource.fido.uaf.ops;

import static org.junit.Assert.*;

import java.util.logging.Logger;

import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;
import org.junit.Test;

import com.google.gson.Gson;

public class AuthenticationRequestGenerationTest {
	
	private Logger logger = Logger.getLogger(this.getClass().getName());
	private static final String TEST_SIGNATURE = "test_signature";
	Gson gson = new Gson ();

	@Test
	public void notNull() {
		AuthenticationRequest authReq= new AuthenticationRequestGeneration().createAuthenticationRequest(new NotaryImpl());
		assertNotNull(authReq);
		logger.info(gson.toJson(authReq));
	}
	
	@Test
	public void withPolicy() {
		String[] aaids = {"ABCD#ABCD"};
		AuthenticationRequest authReq= new AuthenticationRequestGeneration("https://uaf.ebay.com/uaf/facets",aaids ).createAuthenticationRequest(new NotaryImpl());
		assertNotNull(authReq);
		logger.info(gson.toJson(authReq));
	}
	
	class NotaryImpl implements Notary {

		public boolean verify(String dataToSign, String signature) {
			return signature.startsWith(TEST_SIGNATURE);
		}
		
		public String sign(String dataToSign) {
			// For testing
			return TEST_SIGNATURE;
		}
	}

}
