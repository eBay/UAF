package org.ebayopensource.fidouafclient.fp;

import android.hardware.fingerprint.FingerprintManager;

public interface FingerprintAuthProcessor {

    void processAuthentication(FingerprintManager.CryptoObject cryptObj);

}
