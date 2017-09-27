package org.ebayopensource.fidouafclient.util;

import android.app.Application;
import android.content.Context;

import java.security.Security;

public class ApplicationContextProvider extends Application {

    static {
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
    }
 
    /**
     * Keeps a reference of the application context
     */
    private static Context sContext;
 
    @Override
    public void onCreate() {
        super.onCreate();
 
        sContext = getApplicationContext();
 
    }
 
    /**
     * Returns the application context
     *
     * @return application context
     */
    public static Context getContext() {
        return sContext;
    }
}
