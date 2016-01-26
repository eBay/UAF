package org.ebayopensource.fido.uaf.crypto;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.ebayopensource.fido.uaf.tlv.Tag;
import org.ebayopensource.fido.uaf.tlv.Tags;
import org.ebayopensource.fido.uaf.tlv.TagsEnum;
import org.ebayopensource.fido.uaf.tlv.TestAssertions;
import org.ebayopensource.fido.uaf.tlv.TlvAssertionParser;
import org.ebayopensource.fido.uaf.tlv.UnsignedUtil;
import org.junit.Test;

public class X509Test {
	
	private Logger logger = Logger.getLogger(this.getClass().getName());
	TlvAssertionParser p = new TlvAssertionParser();

	@Test
	public void base() throws IOException, CertificateException {
		Tags tags = p.parse(TestAssertions.getExampleRegAssertions());
		X509Certificate x509Certificate = X509.parseDer(tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value);
		assertNotNull(x509Certificate);
		logger.info("From spec example: "+x509Certificate.toString());
	}
	
	@Test
	public void certFromMetadataExample() throws IOException, CertificateException {
		Tags tags = p.parse(TestAssertions.getExampleRegAssertions());
		X509Certificate x509Certificate = X509.parseDer(Base64.decodeBase64(getCertFromTestMetadata()));
		assertNotNull(x509Certificate);
		logger.info("Base64 of DER encoding : "+ Base64.encodeBase64URLSafeString(x509Certificate.getEncoded()));
		logger.info("From spec example: "+x509Certificate.toString());
	}
	
	@Test
	public void certFromAssertionExample() throws IOException, CertificateException {
		Tags tags = p.parse(TestAssertions.getExampleRegAssertions());
		X509Certificate x509Certificate = X509.parseDer(tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value);
		assertNotNull(x509Certificate);
		logger.info("Base64 of DER encoding : "+ Base64.encodeBase64URLSafeString(x509Certificate.getEncoded()));
		logger.info("From spec example: "+x509Certificate.toString());
	}
	
	@Test
	public void certFromRaonExample() throws IOException, CertificateException {
		Tags tags = p.parse(TestAssertions.regRequestAssertionsFromRaon());
		X509Certificate x509Certificate = X509.parseDer(tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value);
		assertNotNull(x509Certificate);
		logger.info("Base64 of DER encoding : "+ Base64.encodeBase64URLSafeString(x509Certificate.getEncoded()));
		logger.info("From spec example: "+x509Certificate.toString());
	}
	
	private String getCertFromTestMetadata() {
		//return "MIIBDzCBtgIBATAJBgcqhkjOPQQBMA8xDTALBgNVBAMTBGViYXkwHhcNMTUwNDA0MDAwNTQ1WhcNMTUwNDE0MDAwNTQ1WjAaMRgwFgYDVQQDDA9ucGVzaWNAZWJheS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARWR4c0b66nJGePdYjckKF0K1jciM1nC4HTmAtx3TP-pDBbpLQTVWr8W0AcI8pV7Ge7yl_dBqyOcfQQee3R9EdpMAkGByqGSM49BAEDSQAwRgIhAPRg_kupjPSW0xCT0sAPTK0bHhU-UIp3j9II0Ci4J0yFAiEAk0gnGXYz9xyZJjqUd0kqS2wkTJItgcn4oaDB8eUc8nI==";
		//return "MIICOjCCAeKgAwIBAgIJAPxU7oirf7v7MAkGByqGSM49BAEwezELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQswCQYDVQQHDAJQQTEQMA4GA1UECgwHTk5MLEluYzENMAsGA1UECwwEREFOMTETMBEGA1UEAwwKTk5MLEluYyBDQTEcMBoGCSqGSIb3DQEJARYNbm5sQGdtYWlsLmNvbTAeFw0xNDAyMjAwMDA4MjZaFw0xOTAyMjAwMDA4MjZaMHsxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTELMAkGA1UEBwwCUEExEDAOBgNVBAoMB05OTCxJbmMxDTALBgNVBAsMBERBTjExEzARBgNVBAMMCk5OTCxJbmMgQ0ExHDAaBgkqhkiG9w0BCQEWDW5ubEBnbWFpbC5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARKa6+rMLldZmm1xr/H9DTVrXUXfC4yGFGIl8212+wJxrvaGk3tEYG9p3+0DZqUl2RntmN1mW+bQnbcE3ZXbrD6o1AwTjAdBgNVHQ4EFgQU1U4i69T0RUguqvAZknxhvrXsbRwwHwYDVR0jBBgwFoAU1U4i69T0RUguqvAZknxhvrXsbRwwDAYDVR0TBAUwAwEB/zAJBgcqhkjOPQQBA0cAMEQCIGjB6DDd/dhCl6snwckSESMBMoljjkIc/q85czalwH+9AiArmzqBVKK/qWM+//zCNBtAaMHzX7xLiqqAAygaiY0pHg==";
//		return "MIIB+TCCAZ+gAwIBAgIEVTFM0zAJBgcqhkjOPQQBMIGEMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExETAPBgNVBAcMCFNhbiBKb3NlMRMwEQYDVQQKDAplQmF5LCBJbmMuMQwwCgYDVQQLDANUTlMxEjAQBgNVBAMMCWVCYXksIEluYzEeMBwGCSqGSIb3DQEJARYPbnBlc2ljQGViYXkuY29tMB4XDTE1MDQxNzE4MTEzMVoXDTE1MDQyNzE4MTEzMVowgYQxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTERMA8GA1UEBwwIU2FuIEpvc2UxEzARBgNVBAoMCmVCYXksIEluYy4xDDAKBgNVBAsMA1ROUzESMBAGA1UEAwwJZUJheSwgSW5jMR4wHAYJKoZIhvcNAQkBFg9ucGVzaWNAZWJheS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ8hw5lHTUXvZ3SzY9argbOOBD2pn5zAM4mbShwQyCL5bRskTL3HVPWPQxqYVM+3pJtJILYqOWsIMd5Rb/h8D+EMAkGByqGSM49BAEDSQAwRgIhAIpkop/L3fOtm79Q2lKrKxea+KcvA1g6qkzaj42VD2hgAiEArtPpTEADIWz2yrl5XGfJVcfcFmvpMAuMKvuE1J73jp4=";
		return "MIICCzCCAbCgAwIBAgIJALJQxwQdHZAUMAoGCCqGSM49BAMCMGMxCzAJBgNVBAYTAktSMRQwEgYDVQQIDAtHeWVvbmdnaS1EbzEUMBIGA1UEBwwLWW9uZ2luLUNpdHkxEzARBgNVBAoMClNhbXN1bmcgRFMxEzARBgNVBAMMClNhbXN1bmcgRFMwHhcNMTUwOTIxMDcxMzQ3WhcNNDMwMjA2MDcxMzQ3WjBjMQswCQYDVQQGEwJLUjEUMBIGA1UECAwLR3llb25nZ2ktRG8xFDASBgNVBAcMC1lvbmdpbi1DaXR5MRMwEQYDVQQKDApTYW1zdW5nIERTMRMwEQYDVQQDDApTYW1zdW5nIERTMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE+Glq/mvof8RRXd0tUIMx+57kUZmFLoIbiVfDDUpB2jTi05nPqFjJEd6FEn315HLLas6/nHoL/NxuRkCSUygzKKNQME4wHQYDVR0OBBYEFJ20gSze9taj3fML7DkNQ8MDKs03MB8GA1UdIwQYMBaAFJ20gSze9taj3fML7DkNQ8MDKs03MAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhALfH//9t4xrte3ZuxtdCfRRBoE4Z/ijX50k+dpJldZUkAiEAj5/Nt9UsdS7ccQhpYJw0NbilQ8cyS/U21bLRILFGnzU=";
	}

	@Test
	public void signatureValidation() throws Exception {
		Tags tags = p.parse(TestAssertions.getExampleRegAssertions());
		X509Certificate x509Certificate = X509.parseDer(tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value);
		assertNotNull(x509Certificate);
		
		Tag krd = tags.getTags().get(TagsEnum.TAG_UAFV1_KRD.id);
		Tag signature = tags.getTags().get(TagsEnum.TAG_SIGNATURE.id);
		
		byte[] signedBytes = new byte[krd.value.length+4];
		System.arraycopy(UnsignedUtil.encodeInt(krd.id), 0, signedBytes, 0, 2);
		System.arraycopy(UnsignedUtil.encodeInt(krd.length), 0, signedBytes, 2, 2);
		System.arraycopy(krd.value, 0, signedBytes, 4, krd.value.length);
		
		KeyPair keyPair = KeyCodec.getKeyPair();
		
		byte[] signature2 = NamedCurve.sign(signedBytes, keyPair.getPrivate());
		BigInteger[] signAndFromatToRS = NamedCurve.signAndFromatToRS(keyPair.getPrivate(), signedBytes);
		byte[] rawSignatureBytes = Asn1.toRawSignatureBytes(signAndFromatToRS);
		
		//	Example: Using generated keys with signature SHA256withECSDA		
		assertTrue( NamedCurve.checkSignature(keyPair.getPublic(), signedBytes, signature2));
		
		//assertTrue( NamedCurve.checkSignature(x509Certificate.getPublicKey(), signedBytes, signature.value));
		BigInteger[] transformRawSignature = Asn1.transformRawSignature(rawSignatureBytes);

		// Example: Key pair generated. Sig calculated as RS, then transformed to raw byte[64]. Pub key as 0x04 X Y
		assertTrue( NamedCurve.verify(KeyCodec.getKeyAsRawBytes((ECPublicKey)keyPair.getPublic()), signedBytes, transformRawSignature));
		
		
		/**
		 * Example:
		 * Pub Key - From X509 Cert
		 * Method: verify - using ECDSASigner - Needs pub key in form [0x04, X (32 bytes), Y (32 bytes)]
		 * Signed data - ECDSASigner - Needs data to be SHA256 first
		 * Signature: ECDSASigner - Needs raw signature from byte[64] to RS Big Integer representation 
		 *  
		 */
		assertTrue( NamedCurve.verify(KeyCodec.getKeyAsRawBytes((ECPublicKey)x509Certificate.getPublicKey()), SHA.sha(signedBytes, "SHA256"), Asn1.transformRawSignature(signature.value)));
		
		
		/**
		 * Example:
		 * Pub Key - From X509 Cert
		 * Method: checkSignature - using SHA256withECDSA 
		 * Signature: Method checkSignature needs signature in DER encoded SEQUENCE { r INTEGER, s INTEGER }
		 * Signature: Was presented in raw byte[64] format => transform to RS format => transform to DER encoded SEQUENCE { r INTEGER, s INTEGER }
		 */
		assertTrue( NamedCurve.checkSignature(x509Certificate.getPublicKey(), signedBytes, Asn1.getEncoded(Asn1.transformRawSignature(signature.value))));
	}
	
	@Test
	public void certV1Creation() throws Exception {
		
		KeyPair keyPair = KeyCodec.generate();
		X509Certificate x509Certificate = X509.generateV1Cert(keyPair);
		assertNotNull(x509Certificate);
		logger.info("V1 : "+x509Certificate.toString());
		logger.info("Base64 of DER encoding : "+ Base64.encodeBase64URLSafeString(x509Certificate.getEncoded()));
		logger.info("Pub : "+Base64.encodeBase64URLSafeString(keyPair.getPublic().getEncoded()));
		logger.info("Priv : "+Base64.encodeBase64URLSafeString(keyPair.getPrivate().getEncoded()));
	}

	@Test
	public void certV3Creation() throws Exception {
		
		KeyPair keyPair = KeyCodec.generate();
		X509Certificate x509Certificate = X509.generateV3Cert(keyPair);
		assertNotNull(x509Certificate);
		logger.info("Base64 of DER encoding : "+ Base64.encodeBase64String(x509Certificate.getEncoded()));
		logger.info("Pub : "+Base64.encodeBase64URLSafeString(keyPair.getPublic().getEncoded()));
		logger.info("Priv : "+Base64.encodeBase64URLSafeString(keyPair.getPrivate().getEncoded()));
		logger.info("V3 : "+x509Certificate.toString());
	}
}
