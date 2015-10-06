package org.ebayopensource.fido.uaf.msg;

import static org.junit.Assert.*;

import java.util.logging.Logger;

import org.junit.Test;

import com.google.gson.Gson;

public class AuthenticationResponseTest {
	
	private Logger logger = Logger.getLogger(this.getClass().getName());
	Gson gson = new Gson ();

	@Test
	public void test() {
		AuthenticationResponse authResponse = gson.fromJson(getTestAuthResponse(), AuthenticationResponse.class);
		assertNotNull(authResponse);
		logger.info(gson.toJson(authResponse));
	}
	
	@Test
	public void extInAssertionsNotNull() {
		AuthenticationResponse authResponse = gson.fromJson(getTestAuthResponse(), AuthenticationResponse.class);
		assertNotNull(authResponse);
		String json = gson.toJson(authResponse);
		logger.info(json);
		assertTrue(!json.contains("null"));
	}
	
	@Test
	public void noNullInJson() {
		AuthenticationResponse authResponse = new AuthenticationResponse();
		authResponse.assertions = new AuthenticatorSignAssertion[1];
		authResponse.assertions[0] = new AuthenticatorSignAssertion();
		authResponse.assertions[0].assertion = "SOMETHING";
		String json = gson.toJson(authResponse);
		logger.info(json);
		assertTrue(!json.contains("null"));
		assertTrue(json.contains("SOMETHING"));
	}

	String getTestAuthResponse () {
		return "{\"assertions\": [{\"assertion\": \"Aj7WAAQ-jgALLgkAQUJDRCNBQkNEDi4FAAABAQEADy4gAHwyJAEX8t1b2wOxbaKOC5ZL7ACqbLo_TtiQfK3DzDsHCi4gAFwCUz-dOuafXKXJLbkUrIzjAU6oDbP8B9iLQRmCf58fEC4AAAkuIABkwI-f3bIe_Uin6IKIFvqLgAOrpk6_nr0oVAK9hIl82A0uBAACAAAABi5AADwDOcBvPslX2bRNy4SvFhAwhEAoBSGUitgMUNChgUSMxss3K3ukekq1paG7Fv1v5mBmDCZVPt2NCTnjUxrjTp4\",\"assertionScheme\": \"UAFV1TLV\"}],\"fcParams\": \"eyJhcHBJRCI6Imh0dHBzOi8vdWFmLXRlc3QtMS5ub2tub2t0ZXN0LmNvbTo4NDQzL1NhbXBsZUFwcC91YWYvZmFjZXRzIiwiY2hhbGxlbmdlIjoiSFExVmtUVVFDMU5KRE9vNk9PV2R4ZXdyYjlpNVd0aGpmS0llaEZ4cGV1VSIsImNoYW5uZWxCaW5kaW5nIjp7fSwiZmFjZXRJRCI6ImNvbS5ub2tub2suYW5kcm9pZC5zYW1wbGVhcHAifQ\",\"header\": {\"appID\": \"https://uaf-test-1.noknoktest.com:8443/SampleApp/uaf/facets\",\"op\": \"Auth\",\"serverData\": \"5s7n8-7_LDAtRIKKYqbAtTTOezVKCjl2mPorYzbpxRrZ-_3wWroMXsF_pLYjNVm_l7bplAx4bkEwK6ibil9EHGfdfKOQ1q0tyEkNJFOgqdjVmLioroxgThlj8Istpt7q\",\"upv\": {\"major\": 1,\"minor\": 0}}}";	
	}
}