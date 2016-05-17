package org.ebayopensource.webauthn.op;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.ebayopensource.webauthn.msg.Assertion;
import org.ebayopensource.webauthn.msg.RegistrationRecord;
import org.ebayopensource.webauthn.res.util.StorageImpl;
import org.ebayopensource.webauthn.res.util.StorageImplTest;
import org.ebayopensource.webauthn.res.util.StorageInterface;
import org.junit.Test;

public class AuthProcessorTest {

	@Test
	public void validRequest() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException, InvalidKeySpecException {
		AuthProcessor authProcessor = new AuthProcessor();
		Assertion assertion = new Assertion();
		assertion.assertionType = "FIDO2.0";
		assertion.key = "TheSourceCode";
		assertion.signature = "PbCztulstyez8JSsY3E5nfkg4mtJ_o1KODDg_LBc3AP5jd4mcisZ6069ybfjZsepPJGGziew0WSjhFa1hcD30YHKZW_kn7K3VyDXjL4PMfeHUOfS6J_NvhULY3yl2OwqkdvuKC5JOBXHRy-MLDwM-P6MqxQsd3oUXTKikJv-HgTym3P4KLmXGXk3CCS8MoCa0RgXD7PBk31_ClrPGkMtUq4ei7-l-4OIgXiyheqj-_1jLWcL-L3F20sC4CKewXEncFv2p2h9vDJIAVaiLyA0f52knfQUFICZ3-slBDi2Fj99rRyEuVkUyd4PMXCDS8N01yEhNopbyzfpULo-h03nuQ";
		assertion.clientData = "ew0KCSJjaGFsbGVuZ2UiIDogIjEyMzQiDQp9AA";
		assertion.authnrData = "AQAAAAA";
		StorageInterface storage = StorageImpl.getInstance();
		RegistrationRecord regRecord = authProcessor.auth(assertion, storage);
		assertNotNull(regRecord);
	}

}
