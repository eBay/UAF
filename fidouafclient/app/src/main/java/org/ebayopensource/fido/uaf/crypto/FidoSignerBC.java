package org.ebayopensource.fido.uaf.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class FidoSignerBC implements FidoSigner {

    @Override
    public byte[] sign(byte[] dataToSign, KeyPair keyPair) {
        try {
            BigInteger[] signatureGen = NamedCurve.signAndFromatToRS(keyPair.getPrivate(),
                    SHA.sha(dataToSign, "SHA-256"));

            boolean verify = NamedCurve.verify(
                    KeyCodec.getPubKeyAsRawBytes(keyPair.getPublic()),
                    SHA.sha(dataToSign, "SHA-256"),
                    Asn1.decodeToBigIntegerArray(Asn1.getEncoded(signatureGen)));
            if (!verify) {
                throw new RuntimeException("Signatire match fail");
            }
            byte[] ret = Asn1.toRawSignatureBytes(signatureGen);

            return ret;
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }


    }
}
