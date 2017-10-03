package org.ebayopensource.fido.uaf.crypto;

import android.util.Log;

import org.ebayopensource.fido.uaf.client.AttestCert;
import org.spongycastle.jce.interfaces.ECPublicKey;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

public class FixedCertFidoAttestationSigner implements FidoAttestationSigner {

    private static final String TAG = FixedCertFidoAttestationSigner.class.getSimpleName();

    public byte[] signWithAttestationCert(byte[] dataForSigning) {
        try {
            PrivateKey priv =
                    KeyCodec.getPrivKey(Base64url.decode(AttestCert.priv));

            Log.i(TAG, " : dataForSigning : "
                    + Base64url.encodeToString(dataForSigning));

            BigInteger[] signatureGen = NamedCurve.signAndFromatToRS(priv,
                    SHA.sha(dataForSigning, "SHA-256"));

            boolean verify = NamedCurve.verify(
                    KeyCodec.getBCKeyAsRawBytes((ECPublicKey) KeyCodec.getPubKey(Base64url.decode(AttestCert.pubCert))),
                    SHA.sha(dataForSigning, "SHA-256"),
                    Asn1.decodeToBigIntegerArray(Asn1.getEncoded(signatureGen)));
            if (!verify) {
                throw new RuntimeException("Signatire match fail");
            }
            byte[] ret = Asn1.toRawSignatureBytes(signatureGen);
            Log.i(TAG, " : signature : " + Base64url.encodeToString(ret));

            return ret;
        } catch(GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
