package org.ebayopensource.fido.uaf.crypto;

import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.util.Log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

@RequiresApi(api = Build.VERSION_CODES.M)
public class FidoKeystoreAndroidM extends FidoKeystore {

    private static final String TAG = FidoKeystoreAndroidM.class.getSimpleName();

    private static final int KEY_TIMEOUT_SECS = 60;

    private FingerprintManager fingerprintManager;

    public FidoKeystoreAndroidM(FingerprintManager fingerprintManager) {
        this.fingerprintManager = fingerprintManager;
    }

    public boolean isFingerprintAuthAvailable() {
        // The line below prevents the false positive inspection from Android Studio
        // noinspection ResourceType
        return fingerprintManager.isHardwareDetected()
                && fingerprintManager.hasEnrolledFingerprints();
    }

    private String getKeyId(String username) {
        return "org.ebayopensource.fidouafclient.keystore.key_" + username;
    }

    @Override
    public KeyPair generateKeyPair(String username) {
        Log.d(TAG, "generateKeyPair");

        try {
            String keyId = getKeyId(username);
            Log.d(TAG, "keyId = " + keyId);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    keyId,
                    KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA384,
                            KeyProperties.DIGEST_SHA512)
                    // Only permit the private key to be used if the user authenticated
                    // within the last five minutes.
                    .setUserAuthenticationRequired(true);
            if (!isFingerprintAuthAvailable()) {
                // make sure key can be used with PIN if no FP available or supported
                // authenticaton is done via the confirmCredentials() API
                builder = builder.setUserAuthenticationValidityDurationSeconds(KEY_TIMEOUT_SECS);
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                // XXX this needs to be the real server challenge
                builder = builder.setAttestationChallenge(new byte[16]);
                builder = builder.setInvalidatedByBiometricEnrollment(false);
            }
            keyPairGenerator.initialize(builder.build());

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Log.d(TAG, "Generated keypair : " + keyPair);

            KeyStore keyStore = getAndroidKeyStore();
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyId);
            Log.d(TAG, "certificate: " + cert);

            return keyPair;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public KeyPair getKeyPair(String username) {
        try {
            PublicKey pubKey = getPublicKey(username);
            PrivateKey privKey = (PrivateKey) getAndroidKeyStore().getKey(getKeyId(username), null);
            return new KeyPair(pubKey, privKey);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @NonNull
    private KeyStore getAndroidKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            return keyStore;
        } catch(GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public PublicKey getPublicKey(String username){
        return getCertificate(username).getPublicKey();
    }

    @Override
    public X509Certificate getCertificate (String username){
        try {
            return (X509Certificate) getAndroidKeyStore().getCertificate(getKeyId(username));
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public FidoSigner getSigner(String username){
        try {
            PrivateKey privateKey = (PrivateKey) getAndroidKeyStore().getKey(getKeyId(username), null);
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);

            return new FidoSignerAndroidM(signature);
        } catch (GeneralSecurityException e) {
           throw new RuntimeException(e);
        }
    }
}
