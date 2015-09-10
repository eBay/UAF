package org.ebayopensource.fido.uaf.msg;

import static org.junit.Assert.*;

import java.util.logging.Logger;

import org.junit.Test;

import com.google.gson.Gson;

public class DeregisterAuthenticatorTest {

	private Logger logger = Logger.getLogger(this.getClass().getName());
	Gson gson = new Gson ();

	@Test
	public void test() {
		DeregisterAuthenticator deregAuth = gson.fromJson(getTestDeregAuth(), DeregisterAuthenticator.class);
		assertNotNull(deregAuth);
		logger.info(gson.toJson(deregAuth));
	}
	
	String getTestDeregAuth (){
		return "{\"aaid\": \"ABCD#ABCD\",\"keyID\": \"ZMCPn92yHv1Ip-iCiBb6i4ADq6ZOv569KFQCvYSJfNg\"}";
		}


}
