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
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fidouafclient.fp.FingerprintAuthProcessor;
import org.ebayopensource.fidouafclient.fp.FingerprintAuthenticationDialogFragment;
import org.ebayopensource.fidouafclient.util.Preferences;
import org.json.JSONObject;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.logging.Level;
import java.util.logging.Logger;

import static android.content.ContentValues.TAG;

public class ExampleFidoUafActivity extends Activity implements FingerprintAuthProcessor {

    private Logger logger = Logger.getLogger(this.getClass().getName());
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

    private void finishWithResult() {
        String inMsg = this.getIntent().getExtras().getString("message");
        Log.d(TAG, "inMsg " + inMsg);

        String msg = "";
        try {
            if (inMsg != null && inMsg.length() > 0) {
                msg = processOp(inMsg);
            }
        } catch (Exception e) {
            logger.log(Level.WARNING, "Not able to get registration response", e);
        }

        Log.d(TAG, "msg " + msg);
    }

    private void finishWithError() {
        Bundle data = new Bundle();

        data.putString("message", "Unable to complete local authentication, please setup android device authentication(pin, pattern, fingerprint..)");
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_CANCELED, intent);
        finish();
    }


    private String processOp(String inUafOperationMsg) {
        Log.d(TAG, "processOp: " + inUafOperationMsg);

        try {
            String msg = "";
            final String inMsg = extract(inUafOperationMsg);
            if (inMsg.contains("\"Reg\"")) {
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
                    // XXX encapsulate
                    Signature signature = Signature.getInstance("SHA256withECDSA");
                    FingerprintManager.CryptoObject cryptoObj = new FingerprintManager.CryptoObject(signature);

                    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                    keyStore.load(null);
                    // XXX
                    String keyId = "org.ebayopensource.fidouafclient.keystore.key_" + Preferences.getSettingsParam("username");
                    PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyId, null);

                    signature.initSign(privateKey);

                    FingerprintAuthenticationDialogFragment fragment
                            = new FingerprintAuthenticationDialogFragment();
                    fragment.setCryptoObject(cryptoObj);
                    fragment.setStage(
                            FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);

                    Log.d(TAG, "Showing fragment: " + fragment);
                    fragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
                } else {

                }
            } else if (inMsg.contains("\"Dereg\"")) {
                returnResultAndFinish(msg);
            }

            return msg;
        } catch (GeneralSecurityException|SecurityException|IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void returnResultAndFinish(String msg) {
        Bundle data = new Bundle();
        data.putString("message", msg);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_OK, intent);
        finish();
    }

    @Override
    public void processAuthentication(FingerprintManager.CryptoObject cryptObj) {
        FidoSigner fidoSigner = new FidoSignerAndroidM(cryptObj.getSignature());
        // fido signer doesn't need key pair, handled internally
        String msg = authOp.auth(authReq, fidoSigner, null);

        returnResultAndFinish(msg);
    }

    public void proceed(View view) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            // XXX better naming
            finishWithResult();
        } else {
            confirmDeviceCredential();
        }
    }

    private void confirmDeviceCredential() {
        Intent intent = keyguardManager.createConfirmDeviceCredentialIntent("UAF", "Confirm Identity");
        if (intent != null) {
            startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        } else {
            finishWithError();
        }
    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            // Challenge completed, proceed with using cipher
            if (resultCode == RESULT_OK) {
                finishWithResult();
            } else {
                // The user canceled or didn’t complete the lock screen
                // operation. Go to error/cancellation flow.
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
