package org.ebayopensource.webauthn.crypto;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.junit.Test;

public class SignatureUtilTest {

	@Test
	public void validSignature() throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		KeyUtil keyUtil = new KeyUtil();
		SignatureUtil signatureUtil = new SignatureUtil();
		
		PublicKey pubKey = keyUtil.getPubKey(
				"x15EJFoDr-8r6_ZG_XxJH5olBL6ulPJb4x3-SQHopftZoc--bd72iBq_AVu4umHwLzuMJ1hwRuLEhRzhkWNL4y1-gbiT_g4EnCx0TLu9fY0nVMtkC1QJ4foOkvhnj5WBNPFvXay-uwLu32siqEfc9bMFmyLsb5PO9OwFRw5PlEEH7PzrUyZTGfd03hiP61D3b2iFdtzHml6d-ATcSJg9BQRg5QojJTdqjhDdrB2iLdbS1enMxkgHE_L8lSYZOHeIthWVLhlDSC6TsFd6NHgwnNqk4oVkfwydobK9RhG0hJwCyR2GoEy4s3VIHYzCaSoFnd9HYROssQn6CZwW_tzx-w",
				"AQAB"
				);
		boolean isValid = signatureUtil.isValid(
				pubKey, 
//				"GMfWNpBVbFz-JdYAnDkWi7PTKO7xpiygLxjtBiOVyzk4oekFq_JV8UV9UKq5RiNpEco0tl7qoaWdZ4L0AjFjDBIRoSQB-8RvhPx9vKuPeD3HlyXYtyXRchvv3pD9nQf67dyfchA7sP4TcJ2qNZZkVxqjkNKvWtzXdCImA9ISkVKfahjGQOLnlg5zmhmHnO6TMucDdsKZQPDrVIRYfDvjaZJnLFVkAwwCRgg9O1nJ7GzDcnOxxjqiMNNCvh8mxKn7weNciQJqTa9ncNU3XvP3Nsi7hhden8VDynxfrweZlc2kardbjEt4BeMax",
				"PbCztulstyez8JSsY3E5nfkg4mtJ_o1KODDg_LBc3AP5jd4mcisZ6069ybfjZsepPJGGziew0WSjhFa1hcD30YHKZW_kn7K3VyDXjL4PMfeHUOfS6J_NvhULY3yl2OwqkdvuKC5JOBXHRy-MLDwM-P6MqxQsd3oUXTKikJv-HgTym3P4KLmXGXk3CCS8MoCa0RgXD7PBk31_ClrPGkMtUq4ei7-l-4OIgXiyheqj-_1jLWcL-L3F20sC4CKewXEncFv2p2h9vDJIAVaiLyA0f52knfQUFICZ3-slBDi2Fj99rRyEuVkUyd4PMXCDS8N01yEhNopbyzfpULo-h03nuQ", 
				"ew0KCSJjaGFsbGVuZ2UiIDogIjEyMzQiDQp9AA",
				"AQAAAAA"
				);
		assertTrue(isValid);
	}
	
	/**
	 * Source:
	 * https://github.com/adrianba/fido-snippets/blob/master/nodejs/fido.js
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void validSignatureFromGithub() throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		KeyUtil keyUtil = new KeyUtil();
		SignatureUtil signatureUtil = new SignatureUtil();
		
		PublicKey pubKey = keyUtil.getPubKey(
				"lylQRV6_MEurzIUqUHZ19vPk_WXIxkKAMKsrgVYZxQiuBGBOnsNqArkD0CDOON6Q1Wtlwmm-_BLRDQlFc4m1FQC6Tv5CbO4ojeb3a7mFbc7_C5vL-vmvr3-h3loev0Mg5id0_06M22dZ07tVfU64ySZNSBK44zQ1-0Net0tSKenf2cR_9vZIhaE3zMVrBnB1JXUFb5lpdHxkmLEtgzBtGe47Plvy0ghaUDNgpSNpYeK_czkDwCm6g_tMFd-kDYmB1LbA75f7gvR7d6o4-Q67CT-iqVUo0LqOXyQI1r6SJNGqM_5JoPi2ryQh5Hq1PIJJeuYr44h5Xz8A181Ga_JZCw",
				"AQAB"
				);
		boolean isValid = signatureUtil.isValid(
				pubKey, 
				"CHFTbWVDWGZQP1Y4ydO3wZSNVXqbXUDM2zEDkxsoLC661bgSkFzCPpXC_58YUla94EARnBhAeDQBKa1O12cp7K2E5sjn14cM9mfkCkxTAGzWe8Av5yiCN2JFnRZy02VWADuSVJzdOVEI8bwAWO713-WwltumDanFXA-Lwa6_9sNLJe9J4Sx5hM9joP-iVlth_pGxxILQhQR-3500zcuMYltwkcr0V5tYl7obOEEfPUhe0lxeSvBIiuCFqoPmouirEIFGKQ2o2PVh7bhfg03e2nWSWNOQ4kZV1ZkNxnoTGI90RapPnwYoWpucV3gyJBF-SJS9Y_yfu7EQkbdsuyv9Dw",
				"ew0KCSJjaGFsbGVuZ2UiIDogImFhYSINCn0A",
				"AQAAAAA"
				);
		assertTrue(isValid);
	}


}


