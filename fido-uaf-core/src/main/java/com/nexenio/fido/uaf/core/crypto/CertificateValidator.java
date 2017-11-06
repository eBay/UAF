package com.nexenio.fido.uaf.core.crypto;

public interface CertificateValidator {
    public boolean validate(String cert, String signedData, String signature)
            throws Exception;

    public boolean validate(byte[] certBytes, byte[] signedDataBytes,
                            byte[] signatureBytes) throws Exception;
}
