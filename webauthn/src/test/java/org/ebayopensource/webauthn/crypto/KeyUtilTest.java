package org.ebayopensource.webauthn.crypto;

import static org.junit.Assert.*;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

public class KeyUtilTest {

	@Test
	public void keyFromModulusAndExponent() throws InvalidKeySpecException, NoSuchAlgorithmException {
		KeyUtil keyUtil = new KeyUtil();
		PublicKey pubKey = keyUtil.getPubKey(
				//"7vjaE_vNFz-FbQ4GNNh-OeY6K4qWyDIvLUfz0YlhjPKfpGSv3mrcatEbAL_vny_FdCgbg1Co_bb6t_p2B2iFdVjY5hr1bXkViPVA-77-F1Cx57ZozEBixNv1-6NbfEiA_OsaPR0kMdkI9iWhF7TokMleHF1RJ_2WR1vcRb-Z99x5LitYTZTmYkcjsZiQBs_YQOZ220WOYNywgg6Xd03ErqAkltucegb4XUkmVl9JxiHoDrXVAmRUj2stDSvE4b2XftNU86v1p8FMykaeQUUXz_8EcTPdt5SydUPtCcdspSFKbKJh4aP_Zp3Fv1iOyQOsF5WB8CO7FssKLBGElHEriQ"
				"x15EJFoDr-8r6_ZG_XxJH5olBL6ulPJb4x3-SQHopftZoc--bd72iBq_AVu4umHwLzuMJ1hwRuLEhRzhkWNL4y1-gbiT_g4EnCx0TLu9fY0nVMtkC1QJ4foOkvhnj5WBNPFvXay-uwLu32siqEfc9bMFmyLsb5PO9OwFRw5PlEEH7PzrUyZTGfd03hiP61D3b2iFdtzHml6d-ATcSJg9BQRg5QojJTdqjhDdrB2iLdbS1enMxkgHE_L8lSYZOHeIthWVLhlDSC6TsFd6NHgwnNqk4oVkfwydobK9RhG0hJwCyR2GoEy4s3VIHYzCaSoFnd9HYROssQn6CZwW_tzx-w"
				, "AQAB"
				);
		assertNotNull(pubKey);
		
		String pem = Base64.encodeBase64String(pubKey.getEncoded());
		System.out.println (pem);
		assertTrue(pem.equals("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx15EJFoDr+8r6/ZG/XxJH5olBL6ulPJb4x3+SQHopftZoc++bd72iBq/AVu4umHwLzuMJ1hwRuLEhRzhkWNL4y1+gbiT/g4EnCx0TLu9fY0nVMtkC1QJ4foOkvhnj5WBNPFvXay+uwLu32siqEfc9bMFmyLsb5PO9OwFRw5PlEEH7PzrUyZTGfd03hiP61D3b2iFdtzHml6d+ATcSJg9BQRg5QojJTdqjhDdrB2iLdbS1enMxkgHE/L8lSYZOHeIthWVLhlDSC6TsFd6NHgwnNqk4oVkfwydobK9RhG0hJwCyR2GoEy4s3VIHYzCaSoFnd9HYROssQn6CZwW/tzx+wIDAQAB"));
	}
	
	@Test
	public void keyFromPEM () throws InvalidKeySpecException, NoSuchAlgorithmException{
		KeyUtil keyUtil = new KeyUtil();
		String pemB64 = 
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx15EJFoDr+8r6/ZG/XxJH5olBL6ulPJb4x3+SQHopftZoc++bd72iBq/AVu4umHwLzuMJ1hwRuLEhRzhkWNL4y1+gbiT/g4EnCx0TLu9fY0nVMtkC1QJ4foOkvhnj5WBNPFvXay+uwLu32siqEfc9bMFmyLsb5PO9OwFRw5PlEEH7PzrUyZTGfd03hiP61D3b2iFdtzHml6d+ATcSJg9BQRg5QojJTdqjhDdrB2iLdbS1enMxkgHE/L8lSYZOHeIthWVLhlDSC6TsFd6NHgwnNqk4oVkfwydobK9RhG0hJwCyR2GoEy4s3VIHYzCaSoFnd9HYROssQn6CZwW/tzx+wIDAQAB";
		PublicKey pubKey = keyUtil.getPubKey(pemB64);
		String format = pubKey.getFormat();
		assertNotNull(pubKey);
	}

}
