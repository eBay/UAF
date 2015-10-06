package org.ebayopensource.fido.uaf.crypto;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.Test;

public class NamedCurveTest {

	private Logger logger = Logger.getLogger(this.getClass().getName());

	@Test
	public void valuesFromGenerator() throws Exception {

		String dataForSigningStr = "BD6OAA==";
		byte[] dataForSigning = Base64.decodeBase64(dataForSigningStr);
		logger.info("dataForSigning length : " + dataForSigning.length);

		KeyPair keyPair = KeyCodec.getKeyPair();
		BCECPrivateKey priv = (BCECPrivateKey) keyPair.getPrivate();
		BCECPublicKey pub = (BCECPublicKey) keyPair.getPublic();

		byte[] pubByte = pub.getEncoded();
		byte[] privByte = priv.getEncoded();

		pub = (BCECPublicKey) KeyCodec.getPubKey(pubByte);
		priv = (BCECPrivateKey) KeyCodec.getPrivKey(privByte);
		logger.info("pubByte : " + pubByte.length + " privByte : "
				+ privByte.length);

		BigInteger[] signatureGen = NamedCurve.signAndFromatToRS(priv,
				dataForSigning);

		logger.info("Signature : " + signatureGen);
		byte[] signatureGenAsn1 = Asn1.getEncoded(signatureGen);
		logger.info("signatureGenAsn1 length : " + signatureGenAsn1.length
				+ " = " + Base64.encodeBase64URLSafeString(signatureGenAsn1));

		byte[] r = signatureGen[0].toByteArray();
		byte[] s = signatureGen[1].toByteArray();

		logger.info("s length : " + s.length + " r length : " + r.length);

		String signatureStr = "PAM5wG8-yVfZtE3LhK8WEDCEQCgFIZSK2AxQ0KGBRIzGyzcre6R6SrWlobsW_W_mYGYMJlU-3Y0JOeNTGuNOng==";
		byte[] signature = Base64.decodeBase64(signatureStr);
		logger.info("Signature length : " + signature.length);

		signatureGen = Asn1.decodeToBigIntegerArray(signatureGenAsn1);

		assertTrue(NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pub),
				dataForSigning, signatureGen));
	}

	@Test
	public void valuesFromExample() throws IOException, Exception {
		String privKey = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgzqOJl-rC0FFMMFM7w7sqp99jsBxgMx_fqwuaUc4CVv-gCgYIKoZIzj0DAQehRANCAAQokXIHgAc20GWpznnnIX9eD2btK-R-uWUFgOKt8l27RcrrOrqJ66uCMfOuG4I1usUUOa7f_A19v74FC-HuSB50";
		String pubKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKJFyB4AHNtBlqc555yF_Xg9m7SvkfrllBYDirfJdu0XK6zq6ieurgjHzrhuCNbrFFDmu3_wNfb--BQvh7kgedA==";

		PublicKey pub = KeyCodec.getPubKey(Base64.decodeBase64(pubKey));
		PrivateKey priv = KeyCodec.getPrivKey(Base64.decodeBase64(privKey));

		String dataForSigningStr = "BD6OAA==";
		byte[] dataForSigning = Base64.decodeBase64(dataForSigningStr);

		BigInteger[] signatureGen = NamedCurve.signAndFromatToRS(priv,
				dataForSigning);

		byte[] asn1EncodedSignature = Asn1.getEncoded(signatureGen);
		logger.info("asn1EncodedSignature="
				+ Base64.encodeBase64URLSafeString(asn1EncodedSignature));
		assertTrue(NamedCurve.verify(
				KeyCodec.getKeyAsRawBytes((BCECPublicKey) pub), dataForSigning,
				Asn1.decodeToBigIntegerArray(asn1EncodedSignature)));
	}

	@Test
	public void signatureAndPubKey() throws InvalidKeySpecException,
			NoSuchAlgorithmException, NoSuchProviderException, IOException,
			Exception {
//		String signatureB64 = "MEUCIQCw-7e95D8hqCC2fxw1ChrCBZ13ZDAtwpDV8f2DQx7G2wIgN0kTb0FShW5fzMHni3sge6PtZM2RMc8Hx-tp0B_2PXg=";
//		String pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKJFyB4AHNtBlqc555yF_Xg9m7SvkfrllBYDirfJdu0XK6zq6ieurgjHzrhuCNbrFFDmu3_wNfb--BQvh7kgedA==";
//		String dataForSigningStr = "BD6OAA==";
		String signatureB64 = "MEYCIQCQwRfcpxCPjqhg00JEcaSVU3VpG_X4vNO0oRHBOBvEyQIhALFn0S_nZcj3ynUgo8FirS7Ke2UDkRXCDSmuKIVrcUgx";
		String pubKeyB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIeVW7JZYG31LXlWdz2ShKr5YH-Ms-L2lZvVXxTUzTyX3Cenl9_T1VRUa-oBfzn4FTpI16HzET-mhvoomuRcttw";
		String dataForSigningStr = "BD6OAAsuCQBEQUI4IzgwMTEOLgUAAQABAgAPLiAAbFLbBK0MSSBEPYNO853JoMXlLw4T6yXp4FLPtP5aBnwKLiAA3WTfNdfUxBvSyweKIaDZNtaAlDRQ5-B4DBDcE5y7O0QQLgAACS4gAAHDA1An8EYamydS_Q8tJGT5Q4NDqtJ6PHUCbMOJ0v-qDS4EAAAAAAA";
		byte[] dataForSigning = SHA.sha(Base64.decodeBase64(dataForSigningStr), "SHA-256");

		assertTrue(NamedCurve
				.verify(KeyCodec.getKeyAsRawBytes(pubKeyB64), dataForSigning,
						Asn1.decodeToBigIntegerArray(Base64
								.decodeBase64(signatureB64))));

		// assertTrue(NamedCurve.verify(KeyCodec
		// .getPubKey(BaseEncoding.base64Url()
		// .decode(pubKeyB64)), dataForSigning, BaseEncoding.base64Url()
		// .decode(signatureB64)));
	}

	@Test
	public void testRawPubKey() throws Exception{
		String privKey = 
//				"UhCeQEsqYcby7UfjKWLxGePlag/RUTIAwYypF0K3ERU=";
				"nXCriWW3w9msxnrtOQYlYb+R51pI8zZyLTLhR8hxggk=";
		String pubKey = 
//				"BK4Qk0tQwU3zSfStH0ZTMKzC6ZfF3PBEqoGLWwJMYQVzvncvr8fv+S6POJ96oLZn0l4YS/OpqB19Of+l1qxwO9Q=";
				"BOg4fylDlzNxMFFTvtQBRsakfxaBJBPJf25sx8Iaim8v3h0ml9mnNCrUVJjBAeXyeGAX69NbAxbaAkNHT+6gJtU=";

		byte[] privKeyBytes = Base64.decodeBase64(privKey);
		byte[] pubKeysBytes = Base64.decodeBase64(pubKey);
		
		PublicKey pub = KeyCodec.getPubKeyFromCurve(pubKeysBytes, "secp256r1");
		PrivateKey priv = KeyCodec.getPrivKeyFromCurve(privKeyBytes, "secp256r1");
		assertNotNull(pub);
		assertNotNull(priv);
		
		String signature = "MEQCIAwtk4DStr2MqkrAlOVG+nyQxbS6tnBpVi7OcKCm8/5lAiBjVsv+b+7nI/306iNHrso/ruOaxY8IJy3jw2/zr17JEQ==";
		BigInteger[] rs = Asn1.decodeToBigIntegerArray(Base64.decodeBase64(signature));
		
		byte[] dataForSigning = Base64.decodeBase64("VGhpcyBpcyBzb21lIHJhbmRvbSBkYXRhIHRvIGJlIHNpZ25lZCBieSBhIHByaXZhdGUga2V5IGFuZCB0aGVuIHZlcmlmaWVkLg");
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(dataForSigning);
		dataForSigning = md.digest();
		boolean verify = NamedCurve.verify(KeyCodec.getKeyAsRawBytes((BCECPublicKey)pub), dataForSigning, rs);
		assertTrue(verify);
	}
}
