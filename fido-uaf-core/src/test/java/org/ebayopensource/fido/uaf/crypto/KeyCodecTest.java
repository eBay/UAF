package org.ebayopensource.fido.uaf.crypto;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

public class KeyCodecTest {

	private Logger logger = Logger.getLogger(this.getClass().getName());

	@Test
	public void test() throws InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchProviderException, IOException,
			InvalidKeySpecException {
		KeyPair keyPair = KeyCodec.getKeyPair();

		PrivateKey privKey = keyPair.getPrivate();
		byte[] encodedPrivKey = privKey.getEncoded();
		logger.info("priv=" + Base64.encodeBase64URLSafeString(encodedPrivKey));

		PublicKey pubKey = keyPair.getPublic();
		byte[] encodedPubKey = pubKey.getEncoded();
		logger.info("pub=" + Base64.encodeBase64URLSafeString(encodedPubKey));

		KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
		PublicKey pubKey2 = kf.generatePublic(new X509EncodedKeySpec(
				encodedPubKey));
		assertTrue(Arrays.equals(pubKey2.getEncoded(), encodedPubKey));

		PrivateKey privKey2 = kf.generatePrivate(new PKCS8EncodedKeySpec(
				encodedPrivKey));
		assertTrue(Arrays.equals(privKey2.getEncoded(), encodedPrivKey));
	}
	
	@Test
	public void pss() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, DataLengthException, CryptoException, InvalidKeyException, SignatureException, InvalidKeySpecException, IOException{
		KeyPair keyPair = KeyCodec.getRSAKeyPair();
		KeyPair keyPair2 = KeyCodec.getRSAKeyPair();
		
		PrivateKey privKey = keyPair.getPrivate();
		byte[] encodedPrivKey = privKey.getEncoded();
		logger.info("priv=" + Base64.encodeBase64URLSafeString(encodedPrivKey));

		PublicKey pubKey = keyPair.getPublic();
		byte[] encodedPubKey = pubKey.getEncoded();
		SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(encodedPubKey);
		ASN1Primitive primitive = spkInfo.parsePublicKey();
		
		PublicKey publicKey = KeyCodec.getRSAPublicKey(primitive.getEncoded());
		logger.info("pub=" + Base64.encodeBase64URLSafeString(encodedPubKey));
		logger.info("pub format=" + pubKey.getFormat());
		logger.info("pub alg=" + pubKey.getAlgorithm());
		
		byte[] slt = Hex.decode("dee959c7e06411361420ff80185ed57f3e6776af"); //a random salt
		
		byte[] signed = RSA.signPSS(privKey, slt);
		assertTrue(signed.length>0);
		RSA rsa = new RSA();
		Assert.assertTrue(rsa.verifyPSS(publicKey, slt, signed));
		byte[] slt2 = Hex.decode("dee959c7e06411361420ff80185ed57f3e6776aa"); //a random salt  
		
		byte[] signed2 = RSA.signPSS(keyPair2.getPrivate(), slt2);
		Assert.assertFalse(rsa.verifyPSS(publicKey, slt2, signed2));
		Assert.assertFalse(rsa.verifyPSS(keyPair2.getPublic(), slt, signed));
	}
	
	@Test
	public void pssDER() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, DataLengthException, CryptoException, InvalidKeyException, SignatureException, InvalidKeySpecException, IOException{
		KeyPair keyPair = KeyCodec.getRSAKeyPair();
		KeyPair keyPair2 = KeyCodec.getRSAKeyPair();
		
		PrivateKey privKey = keyPair.getPrivate();
		byte[] encodedPrivKey = privKey.getEncoded();
		logger.info("priv=" + Base64.encodeBase64URLSafeString(encodedPrivKey));

		PublicKey pubKey = keyPair.getPublic();
		byte[] encodedPubKey = pubKey.getEncoded();
		
		logger.info("pub=" + Base64.encodeBase64URLSafeString(encodedPubKey));
		logger.info("pub format=" + pubKey.getFormat());
		logger.info("pub alg=" + pubKey.getAlgorithm());
		
		byte[] slt = Hex.decode("dee959c7e06411361420ff80185ed57f3e6776af"); //a random salt
		
		byte[] signed = RSA.signPSS(privKey, slt);
		
		assertTrue(signed.length>0);
		RSA rsa = new RSA();
		Assert.assertTrue(rsa.verifyPSS(pubKey, slt, signed));
		byte[] slt2 = Hex.decode("dee959c7e06411361420ff80185ed57f3e6776aa"); //a random salt  
		
		byte[] signed2 = RSA.signPSS(keyPair2.getPrivate(), slt2);
		Assert.assertFalse(rsa.verifyPSS(pubKey, slt2, signed2));
		Assert.assertFalse(rsa.verifyPSS(keyPair2.getPublic(), slt, signed));
	}

}
