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

package org.ebayopensource.fidouaf.marvin.client;

import android.util.Base64;

import org.ebayopensource.fidouaf.marvin.Preferences;
import org.ebayopensource.fidouaf.marvin.client.crypto.BCrypt;
import org.ebayopensource.fidouaf.marvin.client.crypto.SHA;
import org.ebayopensource.fidouaf.marvin.client.msg.RegistrationResponse;
import org.ebayopensource.fidouaf.marvin.client.tlv.Tags;
import org.ebayopensource.fidouaf.marvin.client.tlv.TagsEnum;
import org.ebayopensource.fidouaf.marvin.client.tlv.TlvAssertionParser;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;


public class RegAssertionBuilder {

	public static final String AAID = "EBA0#0003";
	private Logger logger = Logger.getLogger(this.getClass().getName());
	private KeyPair keyPair = null;
	private TlvAssertionParser parser = new TlvAssertionParser();
	
	public RegAssertionBuilder (KeyPair keyPair){
		this.keyPair  = keyPair;
		
	}

	public String getAssertions(RegistrationResponse response) throws Exception {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_UAFV1_REG_ASSERTION.id));
		value = getRegAssertion(response);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		String ret = Base64.encodeToString(byteout.toByteArray(), Base64.URL_SAFE);
		logger.info(" : assertion : " + ret);
		Tags tags = parser.parse(ret);
		String AAID = new String(tags.getTags().get(
				TagsEnum.TAG_AAID.id).value);
		String KeyID = new String(tags.getTags()
				.get(TagsEnum.TAG_KEYID.id).value);
		return ret;
	}

	private byte[] getRegAssertion(RegistrationResponse response) throws Exception {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_UAFV1_KRD.id));
		value = getSignedData(response);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		byte[] signedDataValue = byteout.toByteArray();

		byteout.write(encodeInt(TagsEnum.TAG_ATTESTATION_BASIC_FULL.id));
		value = getAttestationBasicFull(signedDataValue);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		return byteout.toByteArray();
	}
	
	private byte[] getAttestationBasicFull (byte[] signedDataValue) throws Exception {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;
		byteout.write(encodeInt(TagsEnum.TAG_SIGNATURE.id));
		value = getSignature(signedDataValue);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		
		byteout.write(encodeInt(TagsEnum.TAG_ATTESTATION_CERT.id));
//		value = Base64.decode(getAttestCert(), Base64.URL_SAFE);
		value = getAttestCert();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		return byteout.toByteArray();
	}

	private byte[] getAttestCert(){

		try{
			KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
			ks.load(null);
			return ks.getCertificate("UAFAttestKey").getEncoded();
		}catch(Exception e){
			return new byte[0];
		}
	}

	private byte[] getSignedData(RegistrationResponse response) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_AAID.id));
		value = getAAID();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		byteout.write(encodeInt(TagsEnum.TAG_ASSERTION_INFO.id));
		//2 bytes - vendor; 1 byte Authentication Mode; 2 bytes Sig Alg; 2 bytes Pub Key Alg 
		value = new byte[] { 0x00, 0x00, 0x01, 0x04, 0x00, 0x04, 0x01 }; // 04 RSASHA256_RAW
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		
		byteout.write(encodeInt(TagsEnum.TAG_FINAL_CHALLENGE.id));
		value = getFC(response);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		byteout.write(encodeInt(TagsEnum.TAG_KEYID.id));
		value = getKeyId();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		
		byteout.write(encodeInt(TagsEnum.TAG_COUNTERS.id));
		value = getCounters();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		
		byteout.write(encodeInt(TagsEnum.TAG_PUB_KEY.id));
		value = getPubKeyId();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		return byteout.toByteArray();
	}

	private byte[] getFC(RegistrationResponse response) throws NoSuchAlgorithmException {
		return SHA.sha(response.fcParams.getBytes(), "SHA-256");
	}

	private byte[] getPubKeyId() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return getPubKeyIdRsa();
	}

	private byte[] getPubKeyIdRsa (){
		return this.keyPair.getPublic().getEncoded();
	}

	private byte[] getSignature(byte[] dataForSigning) throws Exception {

		KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
		ks.load(null);

		PrivateKey privateKey = (PrivateKey) ks.getKey("UAFAttestKey", null);
		PublicKey publicKey = ks.getCertificate("UAFAttestKey").getPublicKey();

		byte[] signature = new byte[1];
		try {
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initSign(privateKey);

			s.update(SHA.sha(dataForSigning, "SHA-256"));
			signature = s.sign();
		}catch(Exception e){
			logger.info("e="+e);
		}
		return signature;
	}

	private byte[] getKeyId() throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		String keyId = "ebay-test-key-"+ Base64.encodeToString(BCrypt.gensalt().getBytes(), Base64.NO_WRAP);
		keyId = Base64.encodeToString(keyId.getBytes(), Base64.URL_SAFE);
		Preferences.setSettingsParam("keyId", keyId);
		byte[] value = keyId.getBytes();
		byteout.write(value);
		return byteout.toByteArray();
	}
	
	
	private byte[] getCounters() throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byteout.write(encodeInt(0));
		byteout.write(encodeInt(1));
		byteout.write(encodeInt(0));
		byteout.write(encodeInt(1));
		return byteout.toByteArray();
	}

	private byte[] getAAID() throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = AAID.getBytes();
		byteout.write(value);
		return byteout.toByteArray();
	}

	private byte[] encodeInt(int id) {

		byte[] bytes = new byte[2];
		bytes[0] = (byte) (id & 0x00ff);
		bytes[1] = (byte) ((id & 0xff00) >> 8);
		return bytes;
	}

}
