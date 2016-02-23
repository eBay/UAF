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

package org.ebayopensource.fidouaf.marvin.client.op;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.google.gson.Gson;

import org.ebayopensource.fidouaf.marvin.client.RegistrationRequestProcessor;
import org.ebayopensource.fidouaf.marvin.client.msg.RegistrationRequest;
import org.ebayopensource.fidouaf.marvin.client.msg.RegistrationResponse;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
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

	KeyPair keyPair = null;
	try {
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
			keyPair = genEcKeys(context);
		} else {
			keyPair = genRsaKeys(context); //Plain RSAwithSHA256
		}
		logger.info("  [UAF][2]Reg - KeyPair generated"+keyPair);
		RegistrationRequestProcessor p = new RegistrationRequestProcessor();
		RegistrationResponse[] ret = new RegistrationResponse[1];
		RegistrationResponse regResponse = p.processRequest(getRegistrationRequest(uafMsg), keyPair);
		logger.info ("  [UAF][4]Reg - Reg Response Formed  ");
		logger.info(regResponse.assertions[0].assertion);
		logger.info ("  [UAF][6]Reg - done  ");
		logger.info ("  [UAF][7]Reg - keys stored  ");
		ret[0] = regResponse;
		return getUafProtocolMsg( gson.toJson(ret) );
	} catch (Exception e) {
		logger.info("e="+e);
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

		Calendar start = Calendar.getInstance();
		Calendar end = Calendar.getInstance();
		end.add(Calendar.YEAR, 1);

		keyPairGenerator.initialize(
				new KeyPairGeneratorSpec.Builder(context)
						.setAlias("key1")
						.setSubject(new X500Principal("CN=myKey"))
						.setSerialNumber(BigInteger.valueOf(1337))
						.setStartDate(start.getTime())
						.setEndDate(end.getTime())
						.build());


		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		Signature signature =
				Signature.getInstance("SHA256withRSA");

		byte[] plain = "hello, PSS.".getBytes();
		try {
			signature.initSign(keyPair.getPrivate());
			signature.update(plain);
			byte[] signed = signature.sign();
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

	@TargetApi(Build.VERSION_CODES.M)
	public KeyPair gen2kRsaKeys (Context context) throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
				KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
		PSSParameterSpec spec = new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1);
		keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(
				"key1",
				KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
//				.setAlgorithmParameterSpec(spec1)
				.setDigests(KeyProperties.DIGEST_SHA256)
				.setKeySize(2048)
				.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
				.build()
		);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		KeyStore ks = KeyStore.getInstance("AndroidKeyStore");

		// Weird artifact of Java API.  If you don't have an InputStream to load, you still need
		// to call "load", or it'll crash.
		ks.load(null);

		PrivateKey privateKey = (PrivateKey) ks.getKey("key1", null);
		PublicKey publicKey = ks.getCertificate("key1").getPublicKey();

		byte[] data = "SomeDataToSign".getBytes();
		Signature s = Signature.getInstance("SHA256withRSA/PSS");
		s.setParameter(spec);

//		s.setParameter(spec1);
		s.initSign(privateKey);
		s.update(data);
		byte[] signature = s.sign();


		s.initVerify(publicKey);
		s.update(data);

		boolean isMatching = s.verify(signature);

		return keyPair;
	}

	@TargetApi(Build.VERSION_CODES.M)
	public KeyPair genEcKeys (Context context) throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
			KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
		keyPairGenerator.initialize(
				new KeyGenParameterSpec.Builder(
						"key1",
						KeyProperties.PURPOSE_SIGN)
						.setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
						.setDigests(KeyProperties.DIGEST_SHA256,
								KeyProperties.DIGEST_SHA384,
								KeyProperties.DIGEST_SHA512)
						// Only permit the private key to be used if the user authenticated
						// within the last five minutes.
						.setUserAuthenticationRequired(true)
						.setUserAuthenticationValidityDurationSeconds(5 * 60)
						.build());
		return keyPairGenerator.generateKeyPair();
	}

}
