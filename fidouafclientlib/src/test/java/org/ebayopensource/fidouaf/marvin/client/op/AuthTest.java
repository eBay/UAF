package org.ebayopensource.fidouaf.marvin.client.op;

import static org.junit.Assert.*;

import org.ebayopensource.fidouaf.marvin.client.OperationalParams;
import org.ebayopensource.fidouaf.marvin.client.config.InitConfig;
import org.junit.Before;
import org.junit.Test;

public class AuthTest {
	
	private Auth auth = new Auth();
	private String uafMsg = "[{\"header\": {\"upv\": {\"major\": 1,\"minor\": 0},\"op\": \"Auth\",\"appID\": \"https://uaf-test-1.noknoktest.com:8443/SampleApp/uaf/facets\",\"serverData\": \"5s7n8-7_LDAtRIKKYqbAtTTOezVKCjl2mPorYzbpxRrZ-_3wWroMXsF_pLYjNVm_l7bplAx4bkEwK6ibil9EHGfdfKOQ1q0tyEkNJFOgqdjVmLioroxgThlj8Istpt7q\"},\"challenge\": \"HQ1VkTUQC1NJDOo6OOWdxewrb9i5WthjfKIehFxpeuU\",\"policy\": {\"accepted\": [[{\"userVerification\": 512,\"keyProtection\": 1,\"tcDisplay\": 1,\"authenticationAlgorithms\": [1],\"assertionSchemes\": [\"UAFV1TLV\"]}],[{\"userVerification\": 4,\"keyProtection\": 1,\"tcDisplay\": 1,\"authenticationAlgorithms\": [1],\"assertionSchemes\": [\"UAFV1TLV\"]}],[{\"userVerification\": 4,\"keyProtection\": 1,\"tcDisplay\": 1,\"authenticationAlgorithms\": [2]}],[{\"userVerification\": 2,\"keyProtection\": 4,\"tcDisplay\": 1,\"authenticationAlgorithms\": [2]}],[{\"userVerification\": 4,\"keyProtection\": 2,\"tcDisplay\": 1,\"authenticationAlgorithms\": [1,3]}],[{\"userVerification\": 2,\"keyProtection\": 2,\"authenticationAlgorithms\": [2]}],[{\"userVerification\": 32,\"keyProtection\": 2,\"assertionSchemes\": [\"UAFV1TLV\"]},{\"userVerification\": 2,\"authenticationAlgorithms\": [1,3],\"assertionSchemes\": [\"UAFV1TLV\"]},{\"userVerification\": 2,\"authenticationAlgorithms\": [1,3],\"assertionSchemes\": [\"UAFV1TLV\"]},{\"userVerification\": 4,\"keyProtection\": 1,\"authenticationAlgorithms\": [1,3],\"assertionSchemes\": [\"UAFV1TLV\"]}]],\"disallowed\": [{\"userVerification\": 512,\"keyProtection\": 16,\"assertionSchemes\": [\"UAFV1TLV\"]},{\"userVerification\": 256,\"keyProtection\": 16}]}}]";
	private OperationalParams operParams = new OperationalParams();
	
	@Before
	public void register(){
		operParams.genAndRecord("TestApp");
	}
	
	@Test
	public void emptyRequest() {
		InitConfig.getInstance().init(operParams.TEST_AAID, operParams.TestAttestCert, null, operParams, null);
		try {
			auth.auth("");
		} catch (UafMsgProcessException e) {
			fail ("Should have been UafRequestMsgParseException");
		} catch (UafResponseMsgParseException e) {
			fail ("Should have been UafRequestMsgParseException");
		} catch (UafRequestMsgParseException e) {
			assertNotNull(e);
		}
		
	}
	@Test
	public void validRequest() throws Exception {
		InitConfig.getInstance().init(operParams.TEST_AAID, operParams.TestAttestCert, null, operParams, null);
		String response = auth.auth(uafMsg);
		assertNotNull(response);
	}

}
