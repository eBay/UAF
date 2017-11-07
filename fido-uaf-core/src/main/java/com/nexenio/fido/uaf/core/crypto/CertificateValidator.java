package com.nexenio.fido.uaf.core.crypto;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public interface CertificateValidator {

    public boolean validate(String cert, String signedData, String signature) throws NoSuchAlgorithmException, IOException, CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, InvalidKeyException;

    public boolean validate(byte[] certBytes, byte[] signedDataBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, IOException, CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException, InvalidKeyException;

}
