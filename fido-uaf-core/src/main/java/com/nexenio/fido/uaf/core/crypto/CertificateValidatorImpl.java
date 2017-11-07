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
        X509Certificate certificate = X509.parseDer(certBytes);
        String algorithmName = certificate.getSigAlgName();
        if (algorithmName.contains(RSA.ALGORITHM_RSA)) {
            return RSA.verify(certificate, signedDataBytes, signatureBytes);
        }

        byte[] encodedPublicKey = KeyCodec.getKeyAsRawBytes((ECPublicKey) certificate.getPublicKey());
        byte[] data = SHA.sha(signedDataBytes, SHA.ALGORITHM_SHA_256);
        BigInteger[] rs;
        if (signatureBytes.length == 64) {
            rs = Asn1.transformRawSignature(signatureBytes);
        } else {
            rs = Asn1.decodeToBigIntegerArray(signatureBytes);
        }

        boolean verified;
        try {
            verified = NamedCurve.verifyUsingSecp256r1(encodedPublicKey, data, rs);
        } catch (Exception e) {
            verified = NamedCurve.verifyUsingSecp256k1(encodedPublicKey, data, rs);
        }
        return verified;
    }

}
