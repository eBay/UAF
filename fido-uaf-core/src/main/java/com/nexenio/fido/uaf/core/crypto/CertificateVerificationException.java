package com.nexenio.fido.uaf.core.crypto;

import lombok.NoArgsConstructor;

import java.security.cert.CertificateException;

@NoArgsConstructor
public class CertificateVerificationException extends CertificateException {

    private static final long serialVersionUID = 1L;

    public CertificateVerificationException(String message) {
        super(message);
    }

    public CertificateVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

}
