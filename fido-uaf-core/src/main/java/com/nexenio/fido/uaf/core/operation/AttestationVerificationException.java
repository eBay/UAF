package com.nexenio.fido.uaf.core.operation;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class AttestationVerificationException extends Exception {

    private static final long serialVersionUID = 1L;

    public AttestationVerificationException(String message) {
        super(message);
    }

    public AttestationVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

}
