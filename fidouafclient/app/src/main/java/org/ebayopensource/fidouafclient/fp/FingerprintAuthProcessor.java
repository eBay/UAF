package org.ebayopensource.fidouafclient.fp;

import android.hardware.fingerprint.FingerprintManager;

/**
 * Created by JP20818 on 2017/09/26.
 */

public interface FingerprintAuthProcessor {

    void processAuthentication(FingerprintManager.CryptoObject cryptObj);

}
