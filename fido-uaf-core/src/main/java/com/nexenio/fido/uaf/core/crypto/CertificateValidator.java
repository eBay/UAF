package com.nexenio.fido.uaf.core.crypto;

public interface CertificateValidator {

    public boolean validate(String cert, String signedData, String signature) throws CertificateVerificationException;

    public boolean validate(byte[] certBytes, byte[] signedDataBytes, byte[] signatureBytes) throws CertificateVerificationException;

}
