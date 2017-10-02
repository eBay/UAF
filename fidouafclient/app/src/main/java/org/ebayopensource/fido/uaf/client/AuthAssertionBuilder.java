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

package org.ebayopensource.fido.uaf.client;

import android.os.Build;
import android.util.Log;

import org.ebayopensource.fido.uaf.crypto.BCrypt;
import org.ebayopensource.fido.uaf.crypto.Base64url;
import org.ebayopensource.fido.uaf.crypto.FidoSigner;
import org.ebayopensource.fido.uaf.crypto.SHA;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.tlv.AlgAndEncodingEnum;
import org.ebayopensource.fido.uaf.tlv.TagsEnum;
import org.ebayopensource.fidouafclient.util.Preferences;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

public class AuthAssertionBuilder {

	private static final String TAG = AuthAssertionBuilder.class.getSimpleName();

	private static final Logger logger = Logger.getLogger(AuthAssertionBuilder.class.getName());

	private FidoSigner fidoSigner;
	private KeyPair signingKeyPair;

	public AuthAssertionBuilder(FidoSigner fidoSigner, KeyPair signingKeyPair) {
		this.fidoSigner = fidoSigner;
		this.signingKeyPair = signingKeyPair;
	}

	public String getAssertions(AuthenticationResponse response) throws Exception {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_UAFV1_AUTH_ASSERTION.id));
		value = getAuthAssertion(response);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		String ret = Base64url.encodeToString(byteout.toByteArray());
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
		value = getSignature(signedDataValue);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		return byteout.toByteArray();
	}

	private static byte[] makeAssertionInfo() {
		//2 bytes - vendor; 1 byte Authentication Mode; 2 bytes Sig Alg
		// XXX -- ugly. make this smarter and use consts
		ByteBuffer bb = ByteBuffer.allocate(5);
		bb.order(ByteOrder.LITTLE_ENDIAN);
		//2 bytes - vendor
		bb.put((byte)0x0);
		bb.put((byte)0x0);
		// 1 byte Authentication Mode;
		bb.put((byte)0x1);
		// 2 bytes Sig Alg
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
			bb.putShort((short)AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER.id);
			//value = new byte[] { 0x00, 0x00, 0x01, 0x02, 0x00 };
		} else {
			//value = new byte[] { 0x00, 0x00, 0x01, 0x01, 0x00 };
			bb.putShort((short)AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW.id);
		}

		return bb.array().clone();
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
		value = makeAssertionInfo();

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
		value = getKeyId();
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

	private byte[] getSignature(byte[] dataForSigning) throws Exception {
		Log.d(TAG, "getSignature");

		Log.i(TAG, "dataForSigning : " + Base64url.encode(dataForSigning));
		byte[] ret = fidoSigner.sign(dataForSigning, signingKeyPair);

		Log.i(TAG, " : signature : " + Base64url.encode(ret));

		return ret;
	}

	private byte[] getKeyId() throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		String keyId = Preferences.getSettingsParam("keyId");
		byte[] value = keyId.getBytes();
		byteout.write(value);
		return byteout.toByteArray();
	}

	private byte[] getAAID() throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = "EBA0#0001".getBytes();
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

