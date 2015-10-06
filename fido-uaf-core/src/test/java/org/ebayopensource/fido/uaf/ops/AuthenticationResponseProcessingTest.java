package org.ebayopensource.fido.uaf.ops;

import static org.junit.Assert.*;

import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.storage.StorageInterface;
import org.junit.Test;

import java.util.logging.Logger;

import com.google.gson.Gson;

public class AuthenticationResponseProcessingTest {
  private Logger logger = Logger.getLogger(this.getClass().getName());
  Gson gson = new Gson ();
  private static final String TEST_USERNAME = "testUsername";

	@Test
	public void basic() throws Exception {
		
		AuthenticationResponseProcessing p = new AuthenticationResponseProcessing();
		AuthenticationResponse response = getTestResponse();
		StorageInterface serverData = new ServerDataImpl();
		AuthenticatorRecord[] authenticatorRecords = p.verify(response, serverData);
		assertTrue(authenticatorRecords.length == 1);
		assertEquals(authenticatorRecords[0].username, TEST_USERNAME);
		assertEquals(authenticatorRecords[0].status, "SUCCESS");
		
	}

	private AuthenticationResponse getTestResponse() {
		return gson.fromJson(getTestResponseAsJsonString(), AuthenticationResponse.class);
	}

	private String getTestResponseAsJsonString() {
//		This assertions were generated using the TlvAssertionPaserTest
//		return "{\"assertions\":[{\"assertion\":\"BD5zAAsuDQALLgkAQUJDRCNBQkNEDi4FAAAAAAAACS4RAAsuDQBlYmF5LXRlc3Qta2V5Dy5AADNhMTRhYzUzMjU2OGM1OWNjMGE0YWFiNzg4NjFmODdjYjUwYjE2ZjQ3NGJhNWNmMzQ5YmZkZjgwYjQzNWUyNzkGLkYAMEQCIE0tRnqtIUlIcbXU10DjnHgmBbY4RdJ7DT0i_N_4l1UEAiBgHJa7WZc0QHOb2ytZoQSyxfQUBsnpXtYYQ3WtPkQIPA\",\"assertionScheme\":\"UAFV1TLV\"}],\"fcParams\":\"eyJhcHBJRCI6Imh0dHBzOi8vdWFmLXRlc3QtMS5ub2tub2t0ZXN0LmNvbTo4NDQzL1NhbXBsZUFwcC91YWYvZmFjZXRzIiwiY2hhbGxlbmdlIjoiSFExVmtUVVFDMU5KRE9vNk9PV2R4ZXdyYjlpNVd0aGpmS0llaEZ4cGV1VSIsImNoYW5uZWxCaW5kaW5nIjp7fSwiZmFjZXRJRCI6ImNvbS5ub2tub2suYW5kcm9pZC5zYW1wbGVhcHAifQ\",\"header\":{\"appID\":\"https://uaf-test-1.noknoktest.com:8443/SampleApp/uaf/facets\",\"op\":\"Auth\",\"serverData\":\"5s7n8-7_LDAtRIKKYqbAtTTOezVKCjl2mPorYzbpxRrZ-_3wWroMXsF_pLYjNVm_l7bplAx4bkEwK6ibil9EHGfdfKOQ1q0tyEkNJFOgqdjVmLioroxgThlj8Istpt7q\",\"upv\":{\"major\":1,\"minor\":0}}}";

		
		//		The assertions form example are still not passing in the test
//		return "{\"assertions\":[{\"assertion\":\"Aj7WAAQ-jgALLgkAQUJDRCNBQkNEDi4FAAABAQEADy4gAHwyJAEX8t1b2wOxbaKOC5ZL7ACqbLo_TtiQfK3DzDsHCi4gAFwCUz-dOuafXKXJLbkUrIzjAU6oDbP8B9iLQRmCf58fEC4AAAkuIABkwI-f3bIe_Uin6IKIFvqLgAOrpk6_nr0oVAK9hIl82A0uBAACAAAABi5AADwDOcBvPslX2bRNy4SvFhAwhEAoBSGUitgMUNChgUSMxss3K3ukekq1paG7Fv1v5mBmDCZVPt2NCTnjUxrjTp4\",\"assertionScheme\":\"UAFV1TLV\"}],\"fcParams\":\"eyJhcHBJRCI6Imh0dHBzOi8vdWFmLXRlc3QtMS5ub2tub2t0ZXN0LmNvbTo4NDQzL1NhbXBsZUFwcC91YWYvZmFjZXRzIiwiY2hhbGxlbmdlIjoiSFExVmtUVVFDMU5KRE9vNk9PV2R4ZXdyYjlpNVd0aGpmS0llaEZ4cGV1VSIsImNoYW5uZWxCaW5kaW5nIjp7fSwiZmFjZXRJRCI6ImNvbS5ub2tub2suYW5kcm9pZC5zYW1wbGVhcHAifQ\",\"header\":{\"appID\":\"https://uaf-test-1.noknoktest.com:8443/SampleApp/uaf/facets\",\"op\":\"Auth\",\"serverData\":\"5s7n8-7_LDAtRIKKYqbAtTTOezVKCjl2mPorYzbpxRrZ-_3wWroMXsF_pLYjNVm_l7bplAx4bkEwK6ibil9EHGfdfKOQ1q0tyEkNJFOgqdjVmLioroxgThlj8Istpt7q\",\"upv\":{\"major\":1,\"minor\":0}}}";
		return "{\"header\":{\"upv\":{\"major\":1,\"minor\":0},\"op\":\"Auth\",\"appID\":\"android:apk-key-hash:bE0f1WtRJrZv/C0y9CM73bAUqiI\",\"serverData\":\"MjBlNDkxM2ZkODg4YTcwYzEwYWRhMDAxZjNkYzA5MTgyNDg2NDE1MzgxMjljOGVhOTAwYThhMDhiYTMxMTU5OC5NVFEwTWpnNU1qRXhNalkyTVEuU2tSS2FFcEVSWGRLUlRRMVZHMWFZVnA2YkVaWlZtaDNZMGh3U0dKWFRuRmxhMDUzV1ZkVg\"},\"fcParams\":\"eyJhcHBJRCI6ICJhbmRyb2lkOmFway1rZXktaGFzaDpiRTBmMVd0UkpyWnYvQzB5OUNNNzNiQVVxaUkiLCAiY2hhbGxlbmdlIjogIkpESmhKREV3SkU0NVRtWmFaemxGWVZod2NIcEhiV05xZWtOd1lXVSIsICJmYWNldElEIjogImFuZHJvaWQ6YXBrLWtleS1oYXNoOmJFMGYxV3RSSnJadi9DMHk5Q003M2JBVXFpSSIsICJjaGFubmVsQmluZGluZyI6IHt9fQ==\",\"assertions\":[{\"assertionScheme\":\"UAFV1TLV\",\"assertion\":\"Aj7cAAQ-jgALLgkAREFCOCM4MDExDi4FAAEAAQIADy4gADTtvD7YbR3StOT1LwT04sb-V6EopmakXBK-3P4W1YbbCi4gACsUQcxM9uGW-4U0lg4Ph5O42KrWQXuMmXKRzLNrhWimEC4AAAkuIAAoS_GsukwMqV51f_fM3kvsUA8TE9gPQ3M7n1KQUauSFA0uBAAAAAAABi5GADBEAiBZURmUIIuqa4WKs9p0od-Yd_MMyl-7QiKHs8--9ovFUQIgdGgfTKKBS92JYhPLW7j6NyIug3igBTO9z0A3EovJvpk\"}]}";
	}
	
	class ServerDataImpl implements StorageInterface{

		

		public void storeServerDataString(String username,
				String serverDataString) {
			// TODO Auto-generated method stub
			
		}

		public String getUsername(String serverDataString) {
			// TODO Auto-generated method stub
			return null;
		}

		public void store(RegistrationRecord[] records) {
			// TODO Auto-generated method stub
			
		}

		public RegistrationRecord readRegistrationRecord(String key) {
			RegistrationRecord r = new RegistrationRecord();
			r.username = TEST_USERNAME;
			r.PublicKey = 
					"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAN6POEisT65JDZ_oHBXreI59W3BpISIrmYu9MzDD8ec9BCEgEOolypVx291mPg_Hv61AWKjCA6w_DaLCNKKC3g";
//					"BJsvEtUsVKh7tmYHhJ2FBm3kHU-OCdWiUYVijgYa81MfkjQ1z6UiHbKP9_nRzIN9anprHqDGcR6q7O20q_yctZA=";
//			r.PublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKJFyB4AHNtBlqc555yF_Xg9m7SvkfrllBYDirfJdu0XK6zq6ieurgjHzrhuCNbrFFDmu3_wNfb--BQvh7kgedA==";
			return r;
		}

		public void update(RegistrationRecord[] records) {
			// TODO Auto-generated method stub
			
		}
		
	}

}
