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
import android.os.Bundle;
import android.util.Base64;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import org.ebayopensource.fidouaf.marvin.client.OperationalParamsIntf;
import org.ebayopensource.fidouaf.marvin.client.RegRecord;
import org.ebayopensource.fidouaf.marvin.client.config.InitConfig;
import org.ebayopensource.fidouaf.marvin.client.crypto.SHA;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;

/**
 * Created by npesic on 2/22/16.
 */
public class MainActivity extends Activity {
    private Logger logger = Logger.getLogger(this.getClass().getName());
    private TextView msg;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);
        msg = (TextView)findViewById(R.id.textView);
    }

    public void diagnostics (){
        StringBuffer res = new StringBuffer();
        if (!InitConfig.getInstance().isInitialized()) {
            try {
                InitConfig.getInstance()
                        .init(OperationalParams.AAID, OperationalParams.defaultAttestCert, OperationalParams.defaultAttestPrivKey, new OperationalParams(), new Storage());
                res.append("Initialized...\n");
            } catch (Exception e) {
                logger.info("Init failed. e="+e);
                msg.setText("Init failed. e="+e);
                return;
            }
        }
        OperationalParamsIntf operationalParams = InitConfig.getInstance().getOperationalParams();
        PublicKey pub = null;
        try{
            X509Certificate x509Certificate = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(OperationalParams.defaultAttestCert));
            pub = x509Certificate.getPublicKey();
            res.append("Attest cert parsed...\n");
        } catch (Exception e){
            logger.info("Cert parsing failed. e="+e);
            msg.setText("Cert parsing failed. e="+e);
        }

        byte[] dataForSigning = "Eh, hi!".getBytes();
        dataForSigning = Base64.decode ("Az7oAAsuCQBBQUlEI0FBSUQOLgcAAAABAAAAAAouIACdQYzIfGz4-zHjWEDsb5njTLSEKm5mJD9by9Fal8wwQgkuPQBNbEI0VkRWck1tNUxTMHA2WVhJcmJreE9TM2RhTnpkNGNGRkpiWFUyU0c1Uk1tMU1PSFZKVTFFeVJUMEsKDS4IAAAAAQAAAAEADC5bADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABG0Z6lNnifwEqkbCLEPqkrCC9YYKQpxINAlnEhWNRrCQPhGoKHMRx76Nw7cL4BsksgzsGjwCaI8FN-DGQ90NPF4", Base64.URL_SAFE);
        byte[] sig = null;
        try{
            sig = operationalParams.signWithAttestationKey(dataForSigning);
            sig = Base64.decode("MEYCIQC9X2qSeqUv45o_D1i12nkhkHvFJG9CnxeS_ahGNJsxHwIhANM0vrbTpU2qkWllFP3zYmQDtMY8hWXFBXkIO3m5MnVc", Base64.URL_SAFE);
            res.append("Attest signature obtained...\n");
        } catch (Exception e){
            logger.info("signWithAttestationKey failed. e="+e);
            msg.setText("signWithAttestationKey failed. e="+e);
        }

        try{
            java.security.Signature s = java.security.Signature.getInstance("SHA256withECDSA");

            s.initVerify(pub);

            s.update(SHA.sha(dataForSigning, "SHA-256"));
            if(!s.verify(sig)){
                logger.info("cert verify failed.");
                msg.setText("cert verify failed.");
            }
            res.append("Attest signature verified...\n");
        } catch (Exception e){
            logger.info("signWithAttestationKey failed. e="+e);
            msg.setText("signWithAttestationKey failed. e="+e);
        }

        RegRecord testApp = null;
        try{
            testApp = operationalParams.genAndRecord("testApp");
            String keyId = operationalParams.getKeyId("testApp");
            msg.setText("KeyId="+keyId);
            if (!testApp.getKeyId().equals(keyId)) {
                msg.setText("KeyId not matching");
            }
            res.append("Key pair generated and recorded...\n");
            KeyFactory kf = KeyFactory.getInstance("EC");
//            KeyPair keyPair = operationalParams.getKeyPairGenerator(keyId).generateKeyPair();
            byte[] signature = operationalParams.getSignature(dataForSigning, keyId);
            res.append("Auth signature obtained...\n");
            java.security.Signature s = java.security.Signature.getInstance("SHA256withECDSA");

            s.initVerify(kf.generatePublic(new X509EncodedKeySpec(testApp.getPubKey())));

            s.update(SHA.sha(dataForSigning, "SHA-256"));
            if(!s.verify(signature)){
                logger.info("verify failed.");
                msg.setText("verify failed.");
            }
            res.append("Auth signature verified...\n");
            msg.setText(res.toString());
        } catch (Exception e){
            logger.info("signWithAttestationKey failed. e="+e);
            msg.setText("signWithAttestationKey failed. e="+e);
        }

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        super.onCreateOptionsMenu(menu);
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
        if (id == R.id.action_diagnostic) {
            diagnostics();
        }
        return super.onOptionsItemSelected(item);
    }
}
