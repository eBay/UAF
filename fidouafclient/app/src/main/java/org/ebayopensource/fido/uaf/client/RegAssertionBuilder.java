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

import android.util.Log;

import org.ebayopensource.fido.uaf.crypto.BCrypt;
import org.ebayopensource.fido.uaf.crypto.Base64url;
import org.ebayopensource.fido.uaf.crypto.FidoAttestationSigner;
import org.ebayopensource.fido.uaf.crypto.FixedCertFidoAttestationSigner;
import org.ebayopensource.fido.uaf.crypto.KeyCodec;
import org.ebayopensource.fido.uaf.crypto.SHA;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;
import org.ebayopensource.fido.uaf.tlv.AlgAndEncodingEnum;
import org.ebayopensource.fido.uaf.tlv.Tags;
import org.ebayopensource.fido.uaf.tlv.TagsEnum;
import org.ebayopensource.fido.uaf.tlv.TlvAssertionParser;
import org.ebayopensource.fidouafclient.util.Preferences;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.logging.Logger;


public class RegAssertionBuilder {

	private static final String TAG = RegAssertionBuilder.class.getSimpleName();

	public static final String AAID = "EBA0#0001";
	private Logger logger = Logger.getLogger(this.getClass().getName());
	private KeyPair keyPair = null;
	private TlvAssertionParser parser = new TlvAssertionParser();
	
	public RegAssertionBuilder (KeyPair keyPair) {
		this.keyPair = keyPair;
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

		String ret = Base64url.encodeToString(byteout.toByteArray());
		logger.info(" : assertion : " + ret);
		Tags tags = parser.parse(ret);
		Log.d(TAG, "tags: " + tags.toString());
		String AAID = new String(tags.getTags().get(
				TagsEnum.TAG_AAID.id).value);
		Log.d(TAG, "AAID: " + AAID);
		String KeyID = new String(tags.getTags()
				.get(TagsEnum.TAG_KEYID.id).value);
		Log.d(TAG, "keyID: " + KeyID);
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
		value = Base64url.decode(AttestCert.base64DERCert);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		return byteout.toByteArray();
	}

	private byte[] getSignedData(RegistrationResponse response) throws IOException, GeneralSecurityException {
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

	private byte[] makeAssertionInfo() {
		//2 bytes - vendor; 1 byte Authentication Mode; 2 bytes Sig Alg; 2 bytes Pub Key Alg
		ByteBuffer bb = ByteBuffer.allocate(7);
		bb.order(ByteOrder.LITTLE_ENDIAN);
		// 2 bytes - vendor assigned version
		bb.put((byte)0x0);
		bb.put((byte)0x0);
		// 1 byte Authentication Mode;
		bb.put((byte)0x1);
		// 2 bytes Sig Alg
		bb.putShort((short) AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW.id);
		// 2 bytes Pub Key Alg
		bb.putShort((short) AlgAndEncodingEnum.UAF_ALG_KEY_ECC_X962_RAW.id);

		return bb.array().clone();
	}

	private byte[] getFC(RegistrationResponse response) throws NoSuchAlgorithmException {
		return SHA.sha(response.fcParams.getBytes(), "SHA-256");
	}

	private byte[] getPubKeyId() throws GeneralSecurityException, IOException {
		PublicKey pubKey = keyPair.getPublic();
		Log.d(TAG, String.format("key: alg: %s enc: %s", pubKey.getAlgorithm(), pubKey.getFormat()));

		return KeyCodec.getPubKeyAsRawBytes(pubKey);
	}

	private byte[] getSignature(byte[] dataForSigning) throws Exception {
		FidoAttestationSigner attestSigner = new FixedCertFidoAttestationSigner();

		Log.d(TAG, "dataForSigning : " + Base64url.encodeToString(dataForSigning));
		byte[] ret = attestSigner.signWithAttestationCert(dataForSigning);
		Log.d(TAG, "signature: " + Base64url.encodeToString(ret));

		return ret;
	}

	private byte[] getKeyId() throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		String keyId = "ebay-test-key-"+ Base64url.encodeToString(BCrypt.gensalt().getBytes());
		keyId = Base64url.encodeToString(keyId.getBytes());
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
