package com.nexenio.fido.uaf.core.crypto;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertificateValidatorImpl implements CertificateValidator {

    /***
     * Example implementation. It only knows to verify SHA256withEC algorithm.
     */
    public boolean validate(String cert, String signedData, String signature) throws NoSuchAlgorithmException, IOException, CertificateException, InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeyException, SignatureException {
        byte[] certBytes = Base64.decode(cert);
        byte[] signedDataBytes = Base64.decode(signedData);
        byte[] signatureBytes = Base64.decode(signature);
        return validate(certBytes, signedDataBytes, signatureBytes);
    }

    public boolean validate(byte[] certBytes, byte[] signedDataBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, IOException, CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, InvalidKeyException {
        X509Certificate x509Certificate = X509.parseDer(certBytes);
        String sigAlgOID = x509Certificate.getSigAlgName();

        if (sigAlgOID.contains(RSA.ALGORITHM_RSA)) {
            return RSA.verify(x509Certificate, signedDataBytes, signatureBytes);
        }

        BigInteger[] rs;
        if (signatureBytes.length == 64) {
            rs = Asn1.transformRawSignature(signatureBytes);
        } else {
            rs = Asn1.decodeToBigIntegerArray(signatureBytes);
        }
        return NamedCurve.verify(KeyCodec.getKeyAsRawBytes((ECPublicKey) x509Certificate.getPublicKey()), SHA.sha(signedDataBytes, "SHA-256"), rs);
    }

}
