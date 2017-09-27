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
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.google.gson.Gson;

import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.msg.client.UAFIntentType;
import org.ebayopensource.fidouafclient.curl.Curl;
import org.ebayopensource.fidouafclient.op.Auth;
import org.ebayopensource.fidouafclient.op.Dereg;
import org.ebayopensource.fidouafclient.op.OpUtils;
import org.ebayopensource.fidouafclient.op.Reg;
import org.ebayopensource.fidouafclient.util.Endpoints;
import org.ebayopensource.fidouafclient.util.Preferences;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import static android.R.id.message;

public class MainActivity extends Activity {

    private static final int REG_ACTIVITY_RES_3 = 3;
    private static final int AUTH_ACTIVITY_RES_5 = 5;
    private static final int DEREG_ACTIVITY_RES_4 = 4;

    // XXX unify loggers
    private static final String TAG = MainActivity.class.getSimpleName();

    private static final Logger logger = Logger.getLogger(MainActivity.class.getName());

    private Gson gson = new Gson();
    private TextView facetID;
    private TextView msg;
    private TextView title;
    private TextView username;

    private Reg reg = new Reg();
    private Dereg dereg = new Dereg();
    private Auth auth = new Auth();
    private int authenticatorIndex = 1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (Preferences.getSettingsParam("keyID").equals("")) {
            setContentView(R.layout.activity_main);
            findFields();
        } else {
            setContentView(R.layout.activity_registered);
            findFields();
            username.setText(Preferences.getSettingsParam("username"));
        }
    }

    @Override
    public void onStart() {
        super.onStart();


    }

    private void findFields (){
        msg = (TextView) findViewById(R.id.textViewMsg);
        title = (TextView) findViewById(R.id.textViewTitle);
        username = (TextView) findViewById(R.id.textUsername);
    }
	
    public void facetIDRequest(View view) {
        String facetIDval = "";
        try {
            facetIDval = getFacetID(this.getPackageManager().getPackageInfo(this.getPackageName(), this.getPackageManager().GET_SIGNATURES));
            Log.d("facetID: ", facetIDval);
        } catch (NameNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        facetID = (TextView) findViewById(R.id.textViewFacetID);
        facetID.setText(facetIDval);
    }

    public void info(View view) {

        title.setText("Discovery info");
        String asmRequest = "{\"asmVersion\":{\"major\":1,\"minor\":0},\"requestType\":\"GetInfo\"}";
        Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
        i.addCategory("android.intent.category.DEFAULT");
        i.setType("application/fido.uaf_client+json");

        List<ResolveInfo> queryIntentActivities = this.getPackageManager().queryIntentActivities(i, PackageManager.GET_META_DATA);

//		i = new Intent ("com.sec.android.fido.org.ebayopensource.fido.uaf.asm.AsmActivity");
//		i.setType("application/fido.uaf_asm+json");

        Bundle data = new Bundle();
        data.putString("message", OpUtils.getEmptyUafMsgRegRequest());
        data.putString("UAFIntentType", UAFIntentType.DISCOVER.name());
        i.putExtras(data);
//		i.setComponent(new ComponentName(queryIntentActivities.get(0).activityInfo.packageName, queryIntentActivities.get(0).activityInfo.name));
        startActivityForResult(i, 1);
        return;
    }

    public void regRequest(View view) {
//        String username = Preferences.getSettingsParam("username");
        String username = ((EditText) findViewById(R.id.editTextName)).getText().toString();
        if (username.equals ("")) {
            msg.setText("Username cannot be empty.");
            return;
        }
        Preferences.setSettingsParam("username", username);


        title.setText("Registration operation executed, Username = " + username);

        Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
        i.addCategory("android.intent.category.DEFAULT");

        i.setType("application/fido.uaf_client+json");

        List<ResolveInfo> queryIntentActivities = this.getPackageManager().queryIntentActivities(i, PackageManager.MATCH_DEFAULT_ONLY);
        String facetID = "";
        try {
            facetID = getFacetID(this.getPackageManager().getPackageInfo(this.getPackageName(), this.getPackageManager().GET_SIGNATURES));
            title.setText("facetID=" + facetID);
        } catch (NameNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        String regRequest = reg.getUafMsgRegRequest(username, facetID, this);
        Log.d(TAG, "UAF reg request: " + regRequest);
        title.setText("{regRequest}" + regRequest);

        Bundle data = new Bundle();
        data.putString("message", regRequest);
        data.putString("UAFIntentType", UAFIntentType.UAF_OPERATION.name());
        data.putString("channelBindings", regRequest);
        i.putExtras(data);

//		i.setComponent(new ComponentName(queryIntentActivities.get(0).activityInfo.packageName, queryIntentActivities.get(0).activityInfo.name));
        startActivityForResult(i, REG_ACTIVITY_RES_3);
    }

    private String getFacetID(PackageInfo paramPackageInfo) {
        try {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(paramPackageInfo.signatures[0].toByteArray());
            Certificate certificate = CertificateFactory.getInstance("X509").generateCertificate(byteArrayInputStream);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
            String facetID = "android:apk-key-hash:" + Base64.encodeToString(((MessageDigest) messageDigest).digest(certificate.getEncoded()), 3);
            return facetID;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void dereg(View view) {

        title.setText("Deregistration operation executed");
        String uafMessage = dereg.getUafMsgRequest();
        Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
        i.addCategory("android.intent.category.DEFAULT");
        i.setType("application/fido.uaf_client+json");

        List<ResolveInfo> queryIntentActivities = this.getPackageManager().queryIntentActivities(i, PackageManager.MATCH_DEFAULT_ONLY);

        Bundle data = new Bundle();
        data.putString("message", uafMessage);
        data.putString("UAFIntentType", "UAF_OPERATION");
        data.putString("channelBindings", uafMessage);
        i.putExtras(data);
        startActivityForResult(i, DEREG_ACTIVITY_RES_4);
    }

    public void authRequest(View view) {
        title.setText("Authentication operation executed");
        String facetID = "";
        try {
            facetID = getFacetID(this.getPackageManager().getPackageInfo(this.getPackageName(), this.getPackageManager().GET_SIGNATURES));
        } catch (NameNotFoundException e) {
            e.printStackTrace();
        }
        String authRequest = auth.getUafMsgRequest(facetID,this,false);
        Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
        i.addCategory("android.intent.category.DEFAULT");
        i.setType("application/fido.uaf_client+json");
        Bundle data = new Bundle();
        data.putString("message", authRequest);
        data.putString("UAFIntentType", "UAF_OPERATION");
        data.putString("channelBindings", authRequest);
        i.putExtras(data);
        startActivityForResult(i, AUTH_ACTIVITY_RES_5);
    }

    public void trxRequest(View view) {
        title.setText("Authentication operation executed");
        String facetID = "";
        try {
            facetID = getFacetID(this.getPackageManager().getPackageInfo(this.getPackageName(), this.getPackageManager().GET_SIGNATURES));
        } catch (NameNotFoundException e) {
            e.printStackTrace();
        }
        String authRequest = auth.getUafMsgRequest(facetID,this,true);
        Intent i = new Intent("org.fidoalliance.intent.FIDO_OPERATION");
        i.addCategory("android.intent.category.DEFAULT");
        i.setType("application/fido.uaf_client+json");
        Bundle data = new Bundle();
        data.putString("message", authRequest);
        data.putString("UAFIntentType", "UAF_OPERATION");
        data.putString("channelBindings", authRequest);
        i.putExtras(data);
        startActivityForResult(i, AUTH_ACTIVITY_RES_5);
    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        Log.d(TAG, String.format("onActivityResult: requestCode=%d, resultCode=%d, data=%s",
                requestCode, resultCode, new ArrayList<>(data.getExtras().keySet())));

        if (data == null){
            msg.setText("UAF Client didn't return any data. resultCode="+resultCode);
            return;
        }

        Object[] array = data.getExtras().keySet().toArray();
        StringBuffer extras = new StringBuffer();
        extras.append("[resultCode="+resultCode+"]");
        for (int i = 0; i < array.length; i++) {
            extras.append("[" + array[i] + "=");
//            if ("message".equals(array[i])) {
//                continue;
//            }
            extras.append(""+data.getExtras().get((String) array[i]) + "]");
        }
        title.setText("extras=" + extras.toString());

        if (requestCode == 1) {
            if (resultCode == RESULT_OK) {
                String asmResponse = data.getStringExtra("message");
                Log.d(TAG, "UAF message: " + asmResponse);

                String discoveryData = data.getStringExtra("discoveryData");
                msg.setText("{message}" + asmResponse + "{discoveryData}" + discoveryData);
                //Prepare ReqResponse
                //post to server
            }
            if (resultCode == RESULT_CANCELED) {
                userCancelled();
            }
        }
        if (requestCode == 2) {
            if (resultCode == RESULT_OK) {
                String asmResponse = data.getStringExtra("message");
                Log.d(TAG, "UAF message: " + asmResponse);
                msg.setText(asmResponse);
                dereg.recordKeyId(asmResponse);
                //Prepare ReqResponse
                //post to server
            }
            if (resultCode == RESULT_CANCELED) {
                userCancelled();
            }
        } else if (requestCode == REG_ACTIVITY_RES_3) {
            if (resultCode == RESULT_OK) {
                try {
                    String uafMessage = data.getStringExtra("message");
                    Log.d(TAG, "UAF message: " + message);
                    msg.setText(uafMessage);
                    //Prepare ReqResponse
                    //post to server
                    //	            String res = reg.sendRegResponse(asmResponse);
                    String res = reg.clientSendRegResponse(uafMessage);
                    setContentView(R.layout.activity_registered);
                    findFields();
                    title.setText("extras=" + extras.toString());
                    msg.setText(res);
                    username.setText(Preferences.getSettingsParam("username"));
                } catch (Exception e){
                    msg.setText("Registration operation failed.\n"+e);
                }
            }
            if (resultCode == RESULT_CANCELED) {
                userCancelled();
            }
        } else if (requestCode == DEREG_ACTIVITY_RES_4) {
            if (resultCode == RESULT_OK) {
                Preferences.setSettingsParam("keyID", "");
                Preferences.setSettingsParam("username", "");
                setContentView(R.layout.activity_main);
                findFields();
                title.setText("extras=" + extras.toString());
                String message = data.getStringExtra("message");
                Log.d(TAG, String.format("UAF message: [%s]", message));
                if (message != null) {
                    String out = "Dereg done. Client msg=" + message;
                    out = out + ". Sent=" + dereg.clientSendDeregResponse(message);
                    msg.setText(out);
                } else {
                    String deregMsg = Preferences.getSettingsParam("deregMsg");
                    String out = "Dereg done. Client msg was empty. Dereg msg = " + deregMsg;
                    out = out + ". Response=" + dereg.post(deregMsg);
                    msg.setText(out);

                }

            }
            if (resultCode == RESULT_CANCELED) {
                userCancelled();
            }
        } else if (requestCode == AUTH_ACTIVITY_RES_5) {
            if (resultCode == RESULT_OK) {
                String uafMessage = data.getStringExtra("message");
                Log.d(TAG, "UAF message: " + uafMessage);
                if (uafMessage != null) {
                    msg.setText(uafMessage);
                    //Prepare ReqResponse
                    //post to server
//	            String res = auth.sendAuthResponse(asmResponse);
                    String res = auth.clientSendResponse(uafMessage);
                    msg.setText("\n" + res);
                }
            }
            if (resultCode == RESULT_CANCELED) {
                userCancelled();
            }
        }

    }

    private void userCancelled() {
        String warnMsg = "User cancelled";
        Log.w(TAG, warnMsg);
        Toast.makeText(this, warnMsg, Toast.LENGTH_SHORT).show();
    }

    public RegistrationRequest getRegistrationRequest(String username) {
        logger.info("  [UAF][1]Reg - getRegRequest  ");
        String regReq = Curl.getInSeparateThread(Endpoints.getRegRequestEndpoint() + username);
        logger.info("  [UAF][1]Reg - getRegRequest  : " + regReq);
        return gson.fromJson(regReq, RegistrationRequest[].class)[0];
    }


    public void deregRequest(View view) {
        startActivity(new Intent("info.gazers.log.FidoActivity"));
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
        if (id == R.id.action_discover) {
            info(this.getWindow().getCurrentFocus());
        }
        if (id == R.id.action_save_message) {
            SaveMessageDialog.show(this, msg);
        }
        return super.onOptionsItemSelected(item);
    }

}
