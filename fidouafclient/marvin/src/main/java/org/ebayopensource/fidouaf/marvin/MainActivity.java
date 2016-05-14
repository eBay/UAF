package org.ebayopensource.fidouaf.marvin;

import android.app.Activity;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ContentResolver;
import android.content.Context;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import java.lang.reflect.Method;

/**
 * Created by npesic on 2/22/16.
 */
public class MainActivity extends Activity {


    private final static String PASSWORD_TYPE_KEY = "lockscreen.password_type";
    private TextView statusMsg;
    private KeyguardManager keyguardManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

            setContentView(R.layout.activity_main);
            statusMsg = (TextView)findViewById(R.id.textViewStatus);
            keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
    }

    public void check(View view) {
        StringBuffer msg = new StringBuffer();
        ContentResolver contentResolver = getContentResolver();
        long status = Settings.Secure.getLong(contentResolver, PASSWORD_TYPE_KEY,
                DevicePolicyManager.PASSWORD_QUALITY_SOMETHING);

        if (keyguardManager.isKeyguardSecure()){
            msg.append(" keyguardManager.isKeyguardSecure()=true; ");
        }

        if (status != DevicePolicyManager.PASSWORD_QUALITY_SOMETHING) {
            msg.append(" PASSWORD_TYPE_KEY =" + status + " ; ");
        }

        int activePasswordQuality = getActivePasswordQuality();
        msg.append(" activePasswordQuality =" + activePasswordQuality + " ; ");

        try {
            if (android.provider.Settings.Secure.getInt(contentResolver, Settings.Secure.LOCK_PATTERN_ENABLED, 0) == 1) {
                msg.append(" LOCK_PATTERN_ENABLED; ");
            }
        } catch (Exception e){
            msg.append(" Failed reading LOCK_PATTERN_ENABLED; ");
        }

        if (status == DevicePolicyManager.PASSWORD_QUALITY_BIOMETRIC_WEAK){
            msg.append(" PASSWORD_QUALITY_BIOMETRIC_WEAK; ");
        }

        statusMsg.setText(msg.toString());
    }

    private int getActivePasswordQuality (){
        String LOCKSCREEN_UTILS = "com.android.internal.widget.LockPatternUtils";
        try
        {
            Class<?> lockUtilsClass = Class.forName(LOCKSCREEN_UTILS);
            // "this" is a Context, in my case an Activity
            Object lockUtils = lockUtilsClass.getConstructor(Context.class).newInstance(this);

            Method method = lockUtilsClass.getMethod("getActivePasswordQuality");

            int lockProtectionLevel = (Integer)method.invoke(lockUtils);

            return lockProtectionLevel;
        }
        catch (Exception e)
        {
            Log.e("reflectInternalUtils", "ex:"+e);
            return 0;
        }
    }
}
