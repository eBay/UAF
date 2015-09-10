package org.ebayopensource.fido.uaf.crypto;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.util.encoders.Hex;
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
	public void pss() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, DataLengthException, CryptoException{
		KeyPair keyPair = KeyCodec.getRSAKeyPair();
		RSAKeyParameters privateKeyParameter = KeyCodec.generatePrivateKeyParameter((RSAPrivateKey)keyPair.getPrivate());
		byte[] slt = Hex.decode("dee959c7e06411361420ff80185ed57f3e6776af"); //a random salt  
		PSSSigner eng = new PSSSigner(new RSAEngine(), new SHA256Digest(), 20); //creation of PssSigner 
		eng.init(true, new ParametersWithRandom(privateKeyParameter , new SecureRandom(slt))); //initiation of PssSigner 
		eng.update(slt, 0, slt.length);
		byte[] signed = eng.generateSignature();
		assertTrue(signed.length>0);
	}

}
