package org.ebayopensource.webauthn.crypto;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;

public class KeyUtil {
	
	public PublicKey getPubKey(String modulusB64, String exponentB64) throws InvalidKeySpecException, NoSuchAlgorithmException{
		byte[] modulusBytesTmp = Base64.decodeBase64(modulusB64);
		byte[] modulusBytes = modulusBytesTmp;
		byte[] exponentBytes = Base64.decodeBase64(exponentB64);
		
		if (modulusBytes[0]!=0){
			modulusBytes = new byte[modulusBytesTmp.length+1];
			modulusBytes[0] = 0;
			System.arraycopy(modulusBytesTmp, 0, modulusBytes, 1, modulusBytesTmp.length);
		}
		RSAPublicKeySpec rsa = new RSAPublicKeySpec(new BigInteger(modulusBytes),
				new BigInteger(exponentBytes));
			return KeyFactory.getInstance("RSA").generatePublic(rsa);
	}
	
	public PublicKey getPubKey (String pemB64) throws InvalidKeySpecException, NoSuchAlgorithmException{
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(pemB64));
		return KeyFactory.getInstance("RSA").generatePublic(keySpec);
	}
	
	/**
	 * PEM is X509 encoded pub key as b64 string. It can have START, and END headers
	 * @param modulusB64
	 * @param exponentB64
	 * @return
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	public String getPubKeyAsPem (String modulusB64, String exponentB64) throws InvalidKeySpecException, NoSuchAlgorithmException{
		return Base64.encodeBase64URLSafeString(getPubKey(modulusB64, exponentB64).getEncoded());
	}
}
