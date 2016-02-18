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

package org.ebayopensource.fido.uaf.client.op;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.google.gson.Gson;
import com.google.gson.internal.Excluder;

import org.ebayopensource.fidouafclient.util.Preferences;
import org.ebayopensource.fido.uaf.client.RegistrationRequestProcessor;
import org.ebayopensource.fido.uaf.crypto.KeyCodec;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Calendar;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;


public class Reg {
	
	private Logger logger = Logger.getLogger(this.getClass().getName());
	private Gson gson = new Gson();
	
	public String register (String uafMsg, Context context){
	logger.info ("  [UAF][1]Reg  ");
	try {
		KeyPair keyPair = KeyCodec.getKeyPair();
		try {
			keyPair = genRsaPssKeys(context);
		} catch (Exception e){
			logger.info("Switched to RSA/PSS");
		}
		logger.info("  [UAF][2]Reg - KeyPair generated"+keyPair);
		RegistrationRequestProcessor p = new RegistrationRequestProcessor();
		RegistrationResponse[] ret = new RegistrationResponse[1];
		RegistrationResponse regResponse = p.processRequest(getRegistrationRequest(uafMsg), keyPair);
		logger.info ("  [UAF][4]Reg - Reg Response Formed  ");
		logger.info(regResponse.assertions[0].assertion);
		logger.info ("  [UAF][6]Reg - done  ");
//		Preferences.setSettingsParam("pub", Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.URL_SAFE));
//		Preferences.setSettingsParam("priv", Base64.encodeToString(keyPair.getPrivate().getEncoded(), Base64.URL_SAFE));
		logger.info ("  [UAF][7]Reg - keys stored  ");
		ret[0] = regResponse;
		return getUafProtocolMsg( gson.toJson(ret) );
	} catch (InvalidAlgorithmParameterException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchProviderException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
		return "";
	}
	
	public RegistrationRequest getRegistrationRequest(String uafMsg) {
		logger.info ("  [UAF][3]Reg - getRegRequest  : " + uafMsg);
		return gson.fromJson(uafMsg, RegistrationRequest[].class)[0];
	}

	public String getUafProtocolMsg (String uafMsg){
		String msg = "{\"uafProtocolMessage\":";
		msg = msg + "\"";
		msg = msg + uafMsg.replace("\"","\\\"");
		msg = msg + "\"";
		msg = msg + "}";
		return msg;
	}

	public KeyPair genRsaKeys (Context context) throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
				"RSA", "AndroidKeyStore");
//		keyPairGenerator.initialize(
//				new PSSParameterSpec ("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 20,1)
//		);

		Calendar start = Calendar.getInstance();
		Calendar end = Calendar.getInstance();
		end.add(Calendar.YEAR, 1);

		keyPairGenerator.initialize(
				new KeyPairGeneratorSpec.Builder(context)
						.setAlias("keyPair")
						.setSubject(new X500Principal("CN=myKey"))
						.setSerialNumber(BigInteger.valueOf(1337))
						.setStartDate(start.getTime())
						.setEndDate(end.getTime())
						.build());


		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		Signature signature =
//				Signature.getInstance("SHA256withRSAandMGF1");
				Signature.getInstance("SHA256withRSA");

		byte[] plain = "hello, PSS.".getBytes();
		try {
			signature.initSign(keyPair.getPrivate());
//			signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 20, 1));
			signature.update(plain);
			byte[] signed = signature.sign();
			signature.initVerify(keyPair.getPublic());
//			signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 20, 1));
			signature.update(plain);
			boolean verified = signature.verify(signed);
			if (verified){
				logger.info("Verified");
			}
		} catch (Exception e){
			e.printStackTrace();
		}
		return keyPair;
	}

	@TargetApi(Build.VERSION_CODES.M)
	public KeyPair genRsaPssKeys (Context context) throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
				KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
		keyPairGenerator.initialize(
				new KeyGenParameterSpec.Builder(
						"key1",
						KeyProperties.PURPOSE_SIGN)
						.setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
						.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
						.build());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		KeyStore ks = KeyStore.getInstance("AndroidKeyStore");

		// Weird artifact of Java API.  If you don't have an InputStream to load, you still need
		// to call "load", or it'll crash.
		ks.load(null);

		PrivateKey privateKey = (PrivateKey) ks.getKey("key1", null);
		PublicKey publicKey = ks.getCertificate("key1").getPublicKey();

		byte[] data = "SomeDataToSign".getBytes();
		Signature s = Signature.getInstance("SHA256withRSA/PSS");
		s.initSign(privateKey);
		s.update(data);
		byte[] signature = s.sign();


		s.initVerify(publicKey);
		s.update(data);

		boolean isMatching = s.verify(signature);

		return keyPair;
	}

}
