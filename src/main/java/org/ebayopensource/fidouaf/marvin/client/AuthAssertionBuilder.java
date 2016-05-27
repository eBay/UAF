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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import org.ebayopensource.fidouaf.marvin.client.crypto.BCrypt;
import org.ebayopensource.fidouaf.marvin.client.crypto.SHA;
import org.ebayopensource.fidouaf.marvin.client.msg.AuthenticationResponse;
import org.ebayopensource.fidouaf.marvin.client.tlv.TagsEnum;
import org.ebayopensource.util.Base64;

public class AuthAssertionBuilder {

	private Logger logger = Logger.getLogger(this.getClass().getName());
	private OperationalParamsIntf operationalParams;

	public String getAssertions(AuthenticationResponse response, OperationalParamsIntf operationalParams) throws Exception {
		this.operationalParams = operationalParams;
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_UAFV1_AUTH_ASSERTION.id));
		value = getAuthAssertion(response);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		String ret = Base64.encodeToString(byteout.toByteArray(), Base64.NO_PADDING);
		logger.info(" : assertion : " + ret);
		return ret;
	}

	private byte[] getAuthAssertion(AuthenticationResponse response) throws Exception {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_UAFV1_SIGNED_DATA.id));
		value = getSignedData(response);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		byte[] signedDataValue = byteout.toByteArray();

		byteout.write(encodeInt(TagsEnum.TAG_SIGNATURE.id));
		value = operationalParams.getSignature(signedDataValue, operationalParams.getKeyId(response.header.appID));
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		return byteout.toByteArray();
	}

	private byte[] getSignedData(AuthenticationResponse response) throws IOException, NoSuchAlgorithmException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_AAID.id));
		value = getAAID();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		byteout.write(encodeInt(TagsEnum.TAG_ASSERTION_INFO.id));
		//2 bytes - vendor; 1 byte Authentication Mode; 2 bytes Sig Alg 
		value = new byte[]{0x00, 0x00, 0x01, 0x01, 0x00}; //EC RAW
		
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		byteout.write(encodeInt(TagsEnum.TAG_AUTHENTICATOR_NONCE.id));
		value = SHA.sha256(BCrypt.gensalt()).getBytes();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		
		byteout.write(encodeInt(TagsEnum.TAG_FINAL_CHALLENGE.id));
		value = getFC(response);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		
		byteout.write(encodeInt(TagsEnum.TAG_TRANSACTION_CONTENT_HASH.id));
		length = 0;
		byteout.write(encodeInt(length));
		
		byteout.write(encodeInt(TagsEnum.TAG_KEYID.id));
		value = getKeyId(response.header.appID);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		
		byteout.write(encodeInt(TagsEnum.TAG_COUNTERS.id));
		value = getCounters();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		return byteout.toByteArray();
	}
	
	private byte[] getFC(AuthenticationResponse response) throws NoSuchAlgorithmException {
		return SHA.sha(response.fcParams.getBytes(), "SHA-256");
	}
	
	private byte[] getCounters() throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byteout.write(encodeInt(0));
		byteout.write(encodeInt(1));
		return byteout.toByteArray();
	}

	private byte[] getKeyId(String appId) throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		String keyId = Base64.encodeToString(operationalParams.getKeyId(appId).getBytes(), Base64.URL_SAFE);
		byte[] value = keyId.getBytes();
		byteout.write(value);
		return byteout.toByteArray();
	}

	private byte[] getAAID() throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = operationalParams.getAAID().getBytes();
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