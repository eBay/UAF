package org.ebayopensource.fidouaf.marvin.client.op;

import static org.junit.Assert.*;

import org.ebayopensource.fidouaf.marvin.client.msg.DeregistrationRequest;
import org.junit.Assume;
import org.junit.Test;

public class DeregTest {

	@Test
	public void validRequest() throws UafRequestMsgParseException {
		Dereg dereg = new Dereg();
		String uafMsg = "[{\"header\": {\"op\": \"Dereg\",\"upv\": {\"major\": 1,\"minor\": 0},\"appID\": \"https://uaf-test-1.noknoktest.com:8443/SampleApp/uaf/facets\"},\"authenticators\": [{\"aaid\": \"ABCD#ABCD\",\"keyID\": \"ZMCPn92yHv1Ip-iCiBb6i4ADq6ZOv569KFQCvYSJfNg\"}]}]";
		DeregistrationRequest deregRequest = dereg.getDeregRequest(uafMsg);
		assertNotNull(deregRequest);
	}
	
	@Test
	public void emtyUafMsg() {
		Dereg dereg = new Dereg();
		String uafMsg = "";
		DeregistrationRequest deregRequest = null;
		try {
			deregRequest = dereg.getDeregRequest(uafMsg);
			fail("Should be UafRequestMsgParseException");
		} catch (UafRequestMsgParseException e) {
			assertNull(deregRequest);
		}
		
	}

}
