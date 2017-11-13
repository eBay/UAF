package com.nexenio.fido.uaf.core.operation;

import lombok.NoArgsConstructor;

import java.security.SignatureException;

@NoArgsConstructor
public class SignatureVerificationException extends SignatureException {

    private static final long serialVersionUID = 1L;

    public SignatureVerificationException(String message) {
        super(message);
    }

    public SignatureVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

}
