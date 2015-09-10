package org.ebayopensource.fido.uaf.ops;

import static org.junit.Assert.*;

import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.crypto.SHA;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.junit.Test;

import com.google.gson.Gson;

public class RegistrationResponseProcessingTest {
	
	private Logger logger = Logger.getLogger(this.getClass().getName());
	Gson gson = new Gson ();

	@Test
	public void test() throws Exception {
		RegistrationResponseProcessing rrp = new RegistrationResponseProcessing();
		RegistrationRecord[] processResponse = rrp.processResponse(getResponseWithLongerSignature());
		assertTrue(processResponse.length == 1);
		logger.info("AAID="+processResponse[0].authenticator.AAID);
	}
	
	@Test
	public void serverDataValidation() throws Exception{
		RegistrationResponseProcessing rrp = new RegistrationResponseProcessing(5*60*1000, new NotaryImpl());
		RegistrationResponse response = getResponse();
		response.header.serverData = prepareServerData ();
		RegistrationRecord[] processResponse = rrp.processResponse(response);
		assertTrue(processResponse.length == 1);
		logger.info("AAID="+processResponse[0].authenticator.AAID);
	}

	private String prepareServerData() {
		return generateServerData("testUsername", "challengeString", new NotaryImpl());
	}
	
	private String generateServerData(String username, String challenge,
			Notary notary) {
		String dataToSign = Base64.encodeBase64URLSafeString(("" + System
				.currentTimeMillis()).getBytes())
				+ "."
				+ Base64.encodeBase64URLSafeString(username.getBytes())
				+ "."
				+ Base64.encodeBase64URLSafeString(challenge.getBytes());
		String signature = notary.sign(dataToSign);

		return Base64.encodeBase64URLSafeString( (signature + "." + dataToSign).getBytes());
	}

	private RegistrationResponse getResponse() {
		return gson.fromJson(getTestRegResponse(), RegistrationResponse.class);
	}
	
	private RegistrationResponse getResponseWithLongerSignature() {
		return gson.fromJson(getTestRegResponse2(), RegistrationResponse.class);
	}
	
	String getTestRegResponse (){
		return "{\"assertions\":[{\"assertion\":\"AT7uAgM-sQALLgkAQUJDRCNBQkNEDi4HAAABAQEAAAEKLiAA9tBzZC64ecgVQBGSQb5QtEIPC8-Vav4HsHLZDflLaugJLiAAZMCPn92yHv1Ip-iCiBb6i4ADq6ZOv569KFQCvYSJfNgNLggAAQAAAAEAAAAMLkEABJsvEtUsVKh7tmYHhJ2FBm3kHU-OCdWiUYVijgYa81MfkjQ1z6UiHbKP9_nRzIN9anprHqDGcR6q7O20q_yctZAHPjUCBi5AACv8L7YlRMx10gPnszGO6rLFqZFmmRkhtV0TIWuWqYxd1jO0wxam7i5qdEa19u4sfpHFZ9RGI_WHxINkH8FfvAwFLu0BMIIB6TCCAY8CAQEwCQYHKoZIzj0EATB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExCzAJBgNVBAcMAlBBMRAwDgYDVQQKDAdOTkwsSW5jMQ0wCwYDVQQLDAREQU4xMRMwEQYDVQQDDApOTkwsSW5jIENBMRwwGgYJKoZIhvcNAQkBFg1ubmxAZ21haWwuY29tMB4XDTE0MDgyODIxMzU0MFoXDTE3MDUyNDIxMzU0MFowgYYxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEQMA4GA1UECgwHTk5MLEluYzENMAsGA1UECwwEREFOMTETMBEGA1UEAwwKTk5MLEluYyBDQTEcMBoGCSqGSIb3DQEJARYNbm5sQGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCGBt3CIjnDowzSiF68C2aErYXnDUsWXOYxqIPim0OWg9FFdUYCa6AgKjn1R99Ek2d803sGKROivnavmdVH-SnEwCQYHKoZIzj0EAQNJADBGAiEAzAQujXnSS9AIAh6lGz6ydypLVTsTnBzqGJ4ypIqy_qUCIQCFsuOEGcRV-o4GHPBph_VMrG3NpYh2GKPjsAim_cSNmQ\",\"assertionScheme\":\"UAFV1TLV\"}],\"fcParams\":\"eyJhcHBJRCI6Imh0dHBzOi8vdWFmLXRlc3QtMS5ub2tub2t0ZXN0LmNvbTo4NDQzL1NhbXBsZUFwcC91YWYvZmFjZXRzIiwiY2hhbGxlbmdlIjoiSDlpVzl5QTlhQVhGX2xlbFFvaV9EaFVrNTE0QWQ4VHF2MHpDbkNxS0RwbyIsImNoYW5uZWxCaW5kaW5nIjp7fSwiZmFjZXRJRCI6ImNvbS5ub2tub2suYW5kcm9pZC5zYW1wbGVhcHAifQ\",\"header\":{\"appID\":\"https://uaf-test-1.noknoktest.com:8443/SampleApp/uaf/facets\",\"op\":\"Reg\",\"serverData\":\"IjycjPZYiWMaQ1tKLrJROiXQHmYG0tSSYGjP5mgjsDaM17RQgq0dl3NNDDTx9d-aSR_6hGgclrU2F2Yj-12S67v5VmQHj4eWVseLulHdpk2v_hHtKSvv_DFqL4n2IiUY6XZWVbOnvg\",\"upv\":{\"major\":1,\"minor\":0}}}";
	}
	
	String getTestRegResponse2 (){
		return "{\"assertions\":[{\"assertion\":\"AT5HAwM-ywALLgkAMTM4QSM0MjAyDi4HAAEAAQIAAQEKLiAA8y7kunvd44-a9X2uorVkBXY9O2cBjq9eoMJ_dMHp9N8JLiAAzsfjhbCwYi_w-zHTiFvJj7cv-siLlds5DaqhxS9Wt9YNLggAAAAAAAAAAAAMLlsAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYF90PjVZI3r6boxoZU7coML95fq-aaBMiBlCtD1OakDWlyfOvy3XNGq0VgGi07907M7nbYQk4X7DxvRNw32i_gc-dAIGLkcAMEUCIA5ini_jQ_LbeISWDTjXySWZtFq5b5fJpd-ZPttbhfDtAiEA3n2RnSN-pE9GvQOyBv7CMAxvbTdro2dtQrYXwL0iuJQFLiUCMIICITCCAccCAQEwCQYHKoZIzj0EATCBnDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMREwDwYDVQQHEwhTYW4gSm9zZTEYMBYGA1UEChMPU3luYXB0aWNzLCBJbmMuMQwwCgYDVQQLEwNCUEQxGTAXBgNVBAMTEFNtYmF0IFRvbm95YW4gQ0ExKjAoBgkqhkiG9w0BCQEWG3NtYmF0LnRvbm95YW5Ac3luYXB0aWNzLmNvbTAeFw0xNDA5MTYxOTI3MjZaFw0xOTA5MTYxOTI3MjZaMIGcMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExETAPBgNVBAcTCFNhbiBKb3NlMRgwFgYDVQQKEw9TeW5hcHRpY3MsIEluYy4xDDAKBgNVBAsTA0JQRDEZMBcGA1UEAxMQU21iYXQgVG9ub3lhbiBDQTEqMCgGCSqGSIb3DQEJARYbc21iYXQudG9ub3lhbkBzeW5hcHRpY3MuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9_MKXwdtfkbsFR2kvtnSlnesBJdF5acPuUBswKcnQhAHDv7Btf9LHQppfTOrSl4ndkLasRfmoTANz7nEGM3RzTAJBgcqhkjOPQQBA0kAMEYCIQDqU8DxhlwEe4gfyJDVTyWNdbbzOuluMHk3j31DHYsyQgIhANkuIVsk9QcaiD-ZR-RDoGmUEIj97TUYCSiSTAXgACuW\",\"assertionScheme\":\"UAFV1TLV\"}],\"fcParams\":\"eyJhcHBJRCI6Imh0dHBzOi8vdWFmLXRlc3QtMS5ub2tub2t0ZXN0LmNvbTo4NDQzL1NhbXBsZUFwcC91YWYvZmFjZXRzIiwiY2hhbGxlbmdlIjoiSDlpVzl5QTlhQVhGX2xlbFFvaV9EaFVrNTE0QWQ4VHF2MHpDbkNxS0RwbyIsImNoYW5uZWxCaW5kaW5nIjp7fSwiZmFjZXRJRCI6ImNvbS5ub2tub2suYW5kcm9pZC5zYW1wbGVhcHAifQ\",\"header\":{\"appID\":\"https://uaf-test-1.noknoktest.com:8443/SampleApp/uaf/facets\",\"op\":\"Reg\",\"serverData\":\"IjycjPZYiWMaQ1tKLrJROiXQHmYG0tSSYGjP5mgjsDaM17RQgq0dl3NNDDTx9d-aSR_6hGgclrU2F2Yj-12S67v5VmQHj4eWVseLulHdpk2v_hHtKSvv_DFqL4n2IiUY6XZWVbOnvg\",\"upv\":{\"major\":1,\"minor\":0}}}";
	}
	
	class NotaryImpl implements Notary {

		public boolean verify(String dataToSign, String signature) {
			return signature.equals(SHA.sha256(dataToSign));
		}
		
		public String sign(String dataToSign) {
			return SHA.sha256(dataToSign);
		}
	}

}
