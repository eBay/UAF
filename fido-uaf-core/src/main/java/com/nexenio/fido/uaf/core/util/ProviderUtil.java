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

    /**
     * Checks if {@link Security#getProvider(String)} returns a provider
     * named {@link BouncyCastleProvider#PROVIDER_NAME}. If not, a new
     * {@link BouncyCastleProvider} instance will be returned.
     */
    public static Provider getBouncyCastleProvider() {
        Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider != null) {
            return provider;
        } else {
            return new BouncyCastleProvider();
        }
    }

}
