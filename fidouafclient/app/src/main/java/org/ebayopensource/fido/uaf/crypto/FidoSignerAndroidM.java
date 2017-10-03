package org.ebayopensource.fido.uaf.crypto;

import java.security.KeyPair;
import java.security.Signature;
import java.security.SignatureException;

public class FidoSignerAndroidM implements FidoSigner {

    private static final String TAG = FidoSignerAndroidM.class.getSimpleName();

    private Signature signature;

    // signature object needs to be initialized with proper keystore key
    public FidoSignerAndroidM(Signature signature) {
        this.signature = signature;
    }

    @Override
    public byte[] sign(byte[] dataToSign, KeyPair keyPair) {
        try {
            signature.update(dataToSign);

            return signature.sign();
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
