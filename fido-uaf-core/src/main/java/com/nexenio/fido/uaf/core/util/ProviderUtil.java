package com.nexenio.fido.uaf.core.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

public abstract class ProviderUtil {

    /**
     * Calls {@link Security#addProvider(Provider)} with a new {@link BouncyCastleProvider},
     * if no provider named {@link BouncyCastleProvider#PROVIDER_NAME} is available yet.
     */
    public static void addBouncyCastleProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null) {
            return;
        }
        Security.addProvider(new BouncyCastleProvider());
    }

}
