package org.ebayopensource.fido.uaf.msg;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import com.google.gson.Gson;

public class FinalChallengeParamsTest {

	private Logger logger = Logger.getLogger(this.getClass().getName());
	Gson gson = new Gson();

	@Test
	public void test() throws UnsupportedEncodingException {
		String fcParamsAsJson = new String(
				Base64.decodeBase64(getTestfcParamsAsBase64()));
		// String fcParamsAsJson = new
		// String(Base64.decodeBase64(getTestfcParamsAsBase64().getBytes()));
		logger.info(fcParamsAsJson);
		FinalChallengeParams fromJson = gson.fromJson(fcParamsAsJson,
				FinalChallengeParams.class);
		assertNotNull(fromJson);
		logger.info(gson.toJson(fromJson));
	}

	String getTestfcParamsAsBase64() {
		return "eyJhcHBJRCI6Imh0dHBzOi8vdWFmLXRlc3QtMS5ub2tub2t0ZXN0LmNvbTo4NDQzL1NhbXBsZUFwcC91YWYvZmFjZXRzIiwiY2hhbGxlbmdlIjoiSDlpVzl5QTlhQVhGX2xlbFFvaV9EaFVrNTE0QWQ4VHF2MHpDbkNxS0RwbyIsImNoYW5uZWxCaW5kaW5nIjp7fSwiZmFjZXRJRCI6ImNvbS5ub2tub2suYW5kcm9pZC5zYW1wbGVhcHAifQ";
	}

}
