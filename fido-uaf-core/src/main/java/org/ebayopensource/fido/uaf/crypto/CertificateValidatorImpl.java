package org.ebayopensource.fido.uaf.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.util.encoders.Base64;

public class CertificateValidatorImpl implements CertificateValidator {

	private Logger logger = Logger.getLogger(this.getClass().getName());

	/***
	 * Example implementation. It only knows to verify SHA256withEC algorithm.
	 */
	public boolean validate(String cert, String signedData, String signature)
			throws NoSuchAlgorithmException, IOException, Exception {
		byte[] certBytes = Base64.decode(cert);
		byte[] signedDataBytes = Base64.decode(signedData);
		byte[] signatureBytes = Base64.decode(signature);
		return validate(certBytes, signedDataBytes, signatureBytes);
	}

	public boolean validate(byte[] certBytes, byte[] signedDataBytes,
			byte[] signatureBytes) throws NoSuchAlgorithmException,
			IOException, Exception {
		X509Certificate x509Certificate = X509.parseDer(certBytes);
		logger.info(" : Attestation Cert : " + x509Certificate);

		String sigAlgOID = x509Certificate.getSigAlgName();
		logger.info(" : Cert Alg : " + sigAlgOID);

		try {
			if (sigAlgOID.contains("RSA")) {
				if (!RSA.verify(x509Certificate, signedDataBytes,
						signatureBytes)) {
					logger.info(" : Not verified; Cert Alg : " + sigAlgOID);
					return false;
					// throw new Exception(
					// "Signature is RSA - Alg RAWRSASSA-PSS fail - Requested alg:"
					// + sigAlgOID);
				} else {
					return true;
				}
			}

			BigInteger[] rs = null;
			if (signatureBytes.length == 64) {
				rs = Asn1.transformRawSignature(signatureBytes);
			} else {
				rs = Asn1.decodeToBigIntegerArray(signatureBytes);
			}
			try {
				if (!NamedCurve.verify(KeyCodec
						.getKeyAsRawBytes((ECPublicKey) x509Certificate
								.getPublicKey()), SHA.sha(signedDataBytes,
						"SHA-256"), rs)) {
					logger.info(" : Not verified; Cert Alg : " + sigAlgOID);
					return false;
					// throw new Exception(
					// "Signature is 64 bytes - Alg SHA256withEC fail - Requested alg:"
					// + sigAlgOID);
				} else {
					return true;
				}
			} catch (Exception fromVerify) {
				if (!NamedCurve.verifyUsingSecp256k1(KeyCodec
						.getKeyAsRawBytes((ECPublicKey) x509Certificate
								.getPublicKey()), SHA.sha(signedDataBytes,
						"SHA-256"), rs)) {
					logger.info(" : Not verified; Cert Alg : " + sigAlgOID);
					return false;
					// throw new Exception(
					// "Signature is 64 bytes - Alg SHA256withEC fail - Requested alg:"
					// + sigAlgOID);
				} else {
					return true;
				}
			}

		} catch (Exception thrown) {
			logger.log(Level.INFO, "Exception in attest cert validation!",
					thrown);
			return false;
		}
	}

}
