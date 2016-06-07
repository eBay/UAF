package org.ebayopensource.fidouaf.marvin.client;

import static org.junit.Assert.*;

import java.util.logging.Logger;

import org.ebayopensource.fidouaf.marvin.client.msg.AuthenticationRequest;
import org.ebayopensource.fidouaf.marvin.client.msg.AuthenticationResponse;
import org.junit.Before;
import org.junit.Test;

import com.google.gson.Gson;

public class AuthenticationRequestProcessorTest {

	private Logger logger = Logger.getLogger(this.getClass().getName());
	private Gson gson = new Gson();
	private OperationalParams operParams = new OperationalParams();
	
	@Before
	public void register(){
		operParams.genAndRecord("TestApp");
	}

	@Test
	public void testProcessRequest() throws Exception {
		AuthenticationRequestProcessor p = new AuthenticationRequestProcessor();
		AuthenticationRequest req = getTestRequest();

		AuthenticationResponse resp = p.processRequest(req, operParams);
		assertNotNull(resp);
		logger.info(gson.toJson(resp));
	}

	@Test
	public void testWithEmptyAppIdProcessRequest() throws Exception {
		AuthenticationRequestProcessor p = new AuthenticationRequestProcessor();
		AuthenticationRequest req = getTestRequestWithEmptyApp();

		AuthenticationResponse resp = p.processRequest(req, operParams);
		assertNotNull(resp);
		logger.info(gson.toJson(resp));
	}

	private AuthenticationRequest getTestRequest() {
		return gson.fromJson(getTestRequestAsJsonString(),
				AuthenticationRequest.class);
	}

	private String getTestRequestAsJsonString() {
		return "{\"header\": {\"upv\": {\"major\": 1,\"minor\": 0},\"op\": \"Auth\",\"appID\": \"https://uaf-test-1.noknoktest.com:8443/SampleApp/uaf/facets\",\"serverData\": \"5s7n8-7_LDAtRIKKYqbAtTTOezVKCjl2mPorYzbpxRrZ-_3wWroMXsF_pLYjNVm_l7bplAx4bkEwK6ibil9EHGfdfKOQ1q0tyEkNJFOgqdjVmLioroxgThlj8Istpt7q\"},\"challenge\": \"HQ1VkTUQC1NJDOo6OOWdxewrb9i5WthjfKIehFxpeuU\",\"policy\": {\"accepted\": [[{\"userVerification\": 512,\"keyProtection\": 1,\"tcDisplay\": 1,\"authenticationAlgorithms\": [1],\"assertionSchemes\": [\"UAFV1TLV\"]}],[{\"userVerification\": 4,\"keyProtection\": 1,\"tcDisplay\": 1,\"authenticationAlgorithms\": [1],\"assertionSchemes\": [\"UAFV1TLV\"]}],[{\"userVerification\": 4,\"keyProtection\": 1,\"tcDisplay\": 1,\"authenticationAlgorithms\": [2]}],[{\"userVerification\": 2,\"keyProtection\": 4,\"tcDisplay\": 1,\"authenticationAlgorithms\": [2]}],[{\"userVerification\": 4,\"keyProtection\": 2,\"tcDisplay\": 1,\"authenticationAlgorithms\": [1,3]}],[{\"userVerification\": 2,\"keyProtection\": 2,\"authenticationAlgorithms\": [2]}],[{\"userVerification\": 32,\"keyProtection\": 2,\"assertionSchemes\": [\"UAFV1TLV\"]},{\"userVerification\": 2,\"authenticationAlgorithms\": [1,3],\"assertionSchemes\": [\"UAFV1TLV\"]},{\"userVerification\": 2,\"authenticationAlgorithms\": [1,3],\"assertionSchemes\": [\"UAFV1TLV\"]},{\"userVerification\": 4,\"keyProtection\": 1,\"authenticationAlgorithms\": [1,3],\"assertionSchemes\": [\"UAFV1TLV\"]}]],\"disallowed\": [{\"userVerification\": 512,\"keyProtection\": 16,\"assertionSchemes\": [\"UAFV1TLV\"]},{\"userVerification\": 256,\"keyProtection\": 16}]}}";
	}

	private AuthenticationRequest getTestRequestWithEmptyApp() {
		return gson.fromJson(getTestRequestWithEmptyAppIdAsJsonString(),
				AuthenticationRequest.class);
	}

	private String getTestRequestWithEmptyAppIdAsJsonString() {
		return "{\"header\": {\"upv\": {\"major\": 1,\"minor\": 0},\"op\": \"Auth\",\"appID\": \"\",\"serverData\": \"5s7n8-7_LDAtRIKKYqbAtTTOezVKCjl2mPorYzbpxRrZ-_3wWroMXsF_pLYjNVm_l7bplAx4bkEwK6ibil9EHGfdfKOQ1q0tyEkNJFOgqdjVmLioroxgThlj8Istpt7q\"},\"challenge\": \"HQ1VkTUQC1NJDOo6OOWdxewrb9i5WthjfKIehFxpeuU\",\"policy\": {\"accepted\": [[{\"userVerification\": 512,\"keyProtection\": 1,\"tcDisplay\": 1,\"authenticationAlgorithms\": [1],\"assertionSchemes\": [\"UAFV1TLV\"]}],[{\"userVerification\": 4,\"keyProtection\": 1,\"tcDisplay\": 1,\"authenticationAlgorithms\": [1],\"assertionSchemes\": [\"UAFV1TLV\"]}],[{\"userVerification\": 4,\"keyProtection\": 1,\"tcDisplay\": 1,\"authenticationAlgorithms\": [2]}],[{\"userVerification\": 2,\"keyProtection\": 4,\"tcDisplay\": 1,\"authenticationAlgorithms\": [2]}],[{\"userVerification\": 4,\"keyProtection\": 2,\"tcDisplay\": 1,\"authenticationAlgorithms\": [1,3]}],[{\"userVerification\": 2,\"keyProtection\": 2,\"authenticationAlgorithms\": [2]}],[{\"userVerification\": 32,\"keyProtection\": 2,\"assertionSchemes\": [\"UAFV1TLV\"]},{\"userVerification\": 2,\"authenticationAlgorithms\": [1,3],\"assertionSchemes\": [\"UAFV1TLV\"]},{\"userVerification\": 2,\"authenticationAlgorithms\": [1,3],\"assertionSchemes\": [\"UAFV1TLV\"]},{\"userVerification\": 4,\"keyProtection\": 1,\"authenticationAlgorithms\": [1,3],\"assertionSchemes\": [\"UAFV1TLV\"]}]],\"disallowed\": [{\"userVerification\": 512,\"keyProtection\": 16,\"assertionSchemes\": [\"UAFV1TLV\"]},{\"userVerification\": 256,\"keyProtection\": 16}]}}";
	}

}
