package org.ebayopensource.fido.uaf.crypto;

import org.ebayopensource.fidouafclient.util.Preferences;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

public class FidoKeyStoreBC extends FidoKeystore {

    private static final String TAG = FidoKeyStoreBC.class.getSimpleName();

    @Override
    public KeyPair generateKeyPair(String username) {
        try {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "SC");
            g.initialize(ecGenSpec, new SecureRandom());
            KeyPair keyPair = g.generateKeyPair();

            Preferences.setSettingsParam("pub", Base64url.encodeToString(keyPair.getPublic().getEncoded()));
            Preferences.setSettingsParam("priv", Base64url.encodeToString(keyPair.getPrivate().getEncoded()));

            return keyPair;
        } catch(GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyPair getKeyPair(String username) {
        try {
            PublicKey pubKey = getPublicKey(username);
            PrivateKey privKey =
                    KeyCodec.getPrivKey(Base64url.decode(Preferences.getSettingsParam("priv")));

            return new KeyPair(pubKey, privKey);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public PublicKey getPublicKey(String username) {
        try {
            PublicKey pub =
                    KeyCodec.getPubKey(Base64url.decode(Preferences.getSettingsParam("pub")));

            return pub;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public X509Certificate getCertificate(String username) {
        // XXX -- not implemented as no cert
        return null;
    }

    @Override
    public FidoSigner getSigner(String username) {
        // XXX doesn't use username ATM
        return new FidoSignerBC();
    }
}
