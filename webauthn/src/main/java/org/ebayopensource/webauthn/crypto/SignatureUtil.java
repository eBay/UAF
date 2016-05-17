package org.ebayopensource.webauthn.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.apache.commons.codec.binary.Base64;


public class SignatureUtil {
	boolean isValid (PublicKey pubKey, String signatureB64, String messageB64) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, UnsupportedEncodingException{
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(pubKey);
		signature.update(Base64.decodeBase64(messageB64));
		return signature.verify((Base64.decodeBase64(signatureB64)));
	}
	
	
	public boolean isValid (PublicKey pubKey, String signatureB64, String clientDataB64, String authnrDataB64) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, UnsupportedEncodingException{
		byte[] clientData = sha(Base64.decodeBase64(clientDataB64));
		byte[] authnrData = Base64.decodeBase64(authnrDataB64);
		byte[] message = new byte[clientData.length + authnrData.length];
		System.arraycopy(authnrData, 0, message, 0, authnrData.length);
		System.arraycopy(clientData, 0, message, authnrData.length, clientData.length);
		String messageB64 = Base64.encodeBase64String(message);
		return isValid (pubKey, signatureB64, messageB64);
	}

	private byte[] sha(byte[] msg) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(msg);
		return hash;
	}
}
