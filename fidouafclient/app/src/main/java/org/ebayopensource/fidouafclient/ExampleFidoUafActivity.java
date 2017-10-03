/*
 * Copyright 2015 eBay Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ebayopensource.fidouafclient;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;

import com.google.gson.Gson;

import org.ebayopensource.fido.uaf.client.op.Auth;
import org.ebayopensource.fido.uaf.client.op.Reg;
import org.ebayopensource.fido.uaf.crypto.FidoKeystore;
import org.ebayopensource.fido.uaf.crypto.FidoSigner;
import org.ebayopensource.fido.uaf.crypto.FidoSignerAndroidM;
import org.ebayopensource.fido.uaf.crypto.FidoSignerBC;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fidouafclient.fp.FingerprintAuthProcessor;
import org.ebayopensource.fidouafclient.fp.FingerprintAuthenticationDialogFragment;
import org.ebayopensource.fidouafclient.util.Preferences;
import org.json.JSONObject;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ExampleFidoUafActivity extends Activity implements FingerprintAuthProcessor {

    private static final String TAG = ExampleFidoUafActivity.class.getSimpleName();

    private static final Logger logger = Logger.getLogger(ExampleFidoUafActivity.class.getName());

    private Gson gson = new Gson();
    private TextView operation;
    private TextView uafMsg;
    private Reg regOp;
    private Auth authOp = new Auth();
    private KeyguardManager keyguardManager;
    private int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;

    private static final String DIALOG_FRAGMENT_TAG = "fpDialogFragment";

    private String authReq;

    private FidoKeystore fidoKeystore;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        fidoKeystore = FidoKeystore.createKeyStore(getApplicationContext());

        keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        Bundle extras = this.getIntent().getExtras();
        setContentView(R.layout.activity_fido_uaf);
        operation = (TextView) findViewById(R.id.textViewOperation);
        uafMsg = (TextView) findViewById(R.id.textViewOpMsg);
        operation.setText(extras.getString("UAFIntentType"));
        uafMsg.setText(extras.getString("message"));
    }

    private void processOpAndFinish() {
        String inMsg = this.getIntent().getExtras().getString("message");
        Log.d(TAG, "inMsg " + inMsg);

        if (inMsg != null && inMsg.length() > 0) {
            processOp(inMsg);
        } else {
            Log.w(TAG, "inMsg is empty");
        }
    }

    private void finishWithError(String errorMessage) {
        Bundle data = new Bundle();

        data.putString("message", errorMessage);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_CANCELED, intent);
        finish();
    }


    private void processOp(String inUafOperationMsg) {
        Log.d(TAG, "processOp: " + inUafOperationMsg);

        try {
            String msg = "";
            final String inMsg = extract(inUafOperationMsg);
            if (inMsg.contains("\"Reg\"")) {
                Log.d(TAG, "op=Reg");

                RegistrationRequest regRequest = gson.fromJson(inMsg, RegistrationRequest[].class)[0];
                regOp = new Reg(regRequest.username, fidoKeystore);
                msg = regOp.register(inMsg);

                returnResultAndFinish(msg);
            } else if (inMsg.contains("\"Auth\"")) {
                Log.d(TAG, "op=Auth");
                authReq = inMsg;

                String username = Preferences.getSettingsParam("username");
                Log.d(TAG, "username: " + username);

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    if (supportsFingerprintAuth()) {
                        startFingerprintAuth();
                    } else {
                        // assume already authenticated via confirmCredentials()
                        FidoSigner fidoSigner = createFidoSigner();
                        // fido signer doesn't need key pair, handled internally
                        String authMsg = authOp.auth(authReq, fidoSigner, null);

                        returnResultAndFinish(authMsg);
                    }
                } else {
                    FidoSigner fidoSigner = new FidoSignerBC();
                    KeyPair keyPair = fidoKeystore.getKeyPair(username);
                    msg = authOp.auth(authReq, fidoSigner, keyPair);

                    returnResultAndFinish(msg);
                }
            } else if (inMsg.contains("\"Dereg\"")) {
                Log.d(TAG, "op=Dereg");

                msg = inUafOperationMsg;
                returnResultAndFinish(msg);
            }
        } catch (GeneralSecurityException | SecurityException | IOException e) {
            String errorMessage = "Error : " + e.getMessage();
            Log.e(TAG, errorMessage, e);
            finishWithError(errorMessage);
        }
    }

    @NonNull
    private FidoSigner createFidoSigner() throws NoSuchAlgorithmException, InvalidKeyException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        PrivateKey privateKey = fidoKeystore.getKeyPair(Preferences.getSettingsParam("username")).getPrivate();
        signature.initSign(privateKey);

        return new FidoSignerAndroidM(signature);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void startFingerprintAuth() throws GeneralSecurityException, IOException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        PrivateKey privateKey = fidoKeystore.getKeyPair(Preferences.getSettingsParam("username")).getPrivate();
        signature.initSign(privateKey);

        FingerprintAuthenticationDialogFragment fragment
                = new FingerprintAuthenticationDialogFragment();
        FingerprintManager.CryptoObject cryptoObj = new FingerprintManager.CryptoObject(signature);
        fragment.setCryptoObject(cryptoObj);
        fragment.setStage(
                FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);

        Log.d(TAG, "Showing fragment: " + fragment);
        fragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
    }

    private void returnResultAndFinish(String msg) {
        Bundle data = new Bundle();
        data.putString("message", msg);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_OK, intent);
        finish();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void processAuthentication(FingerprintManager.CryptoObject cryptObj) {
        FidoSigner fidoSigner = new FidoSignerAndroidM(cryptObj.getSignature());
        // fido signer doesn't need key pair, handled internally
        String msg = authOp.auth(authReq, fidoSigner, null);

        returnResultAndFinish(msg);
    }

    private static boolean isAndroidM() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return true;
        }

        return false;
    }

    private boolean supportsFingerprintAuth() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            FingerprintManager fingerprintManager = getSystemService(FingerprintManager.class);

            // noinspection ResourceType
            return fingerprintManager.isHardwareDetected()
                    && fingerprintManager.hasEnrolledFingerprints();
        }

        return false;
     }

    public void proceed(View view) {
        if (isAuthOp() && isAndroidM() && supportsFingerprintAuth()) {
            // Android M does fingerprint auth internally, so we don't call confirmDeviceCredential()
            processOpAndFinish();
        } else {
            confirmDeviceCredential();
        }
    }

    private boolean isAuthOp() {
        // XXX uglish, needed to avoid double auth in case of Android M+
        String inMsg = extract(getIntent().getExtras().getString("message"));
        if (inMsg.contains("\"Auth\"")) {
            Log.d(TAG, "op=Auth");
            return true;
        }

        return false;
    }

    private void confirmDeviceCredential() {
        Intent intent = keyguardManager.createConfirmDeviceCredentialIntent("UAF", "Confirm Identity");
        if (intent != null) {
            startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        } else {
            finishWithError("Unable to complete local authentication, please setup android device authentication(pin, pattern, fingerprint..)");
        }
    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            // Challenge completed, proceed with using cipher
            if (resultCode == RESULT_OK) {
                processOpAndFinish();
            } else {
                // The user canceled or didn’t complete the lock screen
                // operation. Go to error/cancellation flow.
                String errorMessage = "User cancelled credential verification";
                Log.w(TAG, errorMessage);
                finishWithError(errorMessage);
            }
        }
    }

    public void back(View view) {
        Bundle data = new Bundle();
        String msg = "";
        logger.info("Registration canceled by user");
        data.putString("message", msg);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_OK, intent);
        finish();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            startActivity(new Intent(
                    "org.ebayopensource.fidouafclient.SettingsActivity"));
        }
        if (id == R.id.action_save_message) {
            SaveMessageDialog.show(this, uafMsg);
        }
        return super.onOptionsItemSelected(item);
    }

    private String extract(String inMsg) {
        try {
            JSONObject tmpJson = new JSONObject(inMsg);
            String uafMsg = tmpJson.getString("uafProtocolMessage");
            uafMsg.replace("\\\"", "\"");
            return uafMsg;
        } catch (Exception e) {
            logger.log(Level.WARNING, "Input message is invalid!", e);
            return "";
        }

    }
}
