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

package org.ebayopensource.fidouaf.marvin;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.View;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.ebayopensource.fidouaf.marvin.client.config.InitConfig;
import org.ebayopensource.fidouaf.marvin.client.op.Auth;
import org.ebayopensource.fidouaf.marvin.client.op.Reg;
import org.json.JSONObject;

import java.util.logging.Level;
import java.util.logging.Logger;

public class FidoUafOpActivity extends Activity {

    private Logger logger = Logger.getLogger(this.getClass().getName());
    private Gson gson = new GsonBuilder().create();
    private Reg regOp = new Reg();
    private Auth authOp = new Auth();
    private KeyguardManager keyguardManager;
    private int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
//        setContentView(R.layout.activity_fido_uaf_consent);
        init();
        proceed();
    }

    private void init (){
        if (!InitConfig.getInstance().isInitialized()) {
            try {
                InitConfig.getInstance()
                        .init(OperationalParams.AAID,OperationalParams.defaultAttestCert, OperationalParams.defaultAttestPrivKey, new OperationalParams(), new Storage ());
            } catch (Exception e) {
                logger.info("Key generator init failed");
                back();
            }
        }
    }

    private void finishWithResult() {
        Bundle data = new Bundle();
        String inMsg = this.getIntent().getExtras().getString("message");
        String msg = "";
        try {
            if (inMsg != null && inMsg.length() > 0) {
                msg = processOp(inMsg);
            }
        } catch (Exception e) {
            logger.log(Level.WARNING, "Not able to get registration response", e);
            back();
            return;
        }
        data.putString("message", msg);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_OK, intent);
        finish();
    }

    private String processOp(String inUafOperationMsg) throws Exception {
        init();
        String msg = "";
        try {
            String inMsg = extract(inUafOperationMsg);
            if (inMsg.contains("\"Reg\"")) {
                msg = regOp.register(inMsg);
            } else if (inMsg.contains("\"Auth\"")) {
                msg = authOp.auth(inMsg);
            } else if (inMsg.contains("\"Dereg\"")) {

            }
        }catch (Exception e){
            logger.info("processOp failed. e="+e);
        }
        return msg;
    }

    public void proceed(View view) {
        proceed();
    }

    public void proceed() {
        if (keyguardManager.isKeyguardSecure()) {
            Intent intent = keyguardManager.createConfirmDeviceCredentialIntent("UAF", "Confirm Identity");
            if (intent != null) {
                startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
            }
        } else {
            finishWithResult();
        }

    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            if (resultCode == RESULT_CANCELED) {
                back();
            }

            // Challenge completed, proceed with using cipher
            if (resultCode == RESULT_OK) {
                finishWithResult();
            }
        }
        back();
    }

    public void back(View view) {
        back();
    }

    private void back() {
        Bundle data = new Bundle();
        String msg = "{}";
        logger.info("Operation canceled");
        data.putString("message", msg);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_OK, intent);
        finish();
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if ((keyCode == KeyEvent.KEYCODE_BACK)) {
            back();
        }
        return super.onKeyDown(keyCode, event);
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
