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

import org.ebayopensource.fido.uaf.crypto.Base64url;
import org.ebayopensource.fidouafclient.util.Preferences;
import org.ebayopensource.fido.uaf.crypto.Asn1;
import org.ebayopensource.fido.uaf.crypto.BCrypt;
import org.ebayopensource.fido.uaf.crypto.KeyCodec;
import org.ebayopensource.fido.uaf.crypto.NamedCurve;
import org.ebayopensource.fido.uaf.crypto.SHA;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;
import org.ebayopensource.fido.uaf.tlv.Tags;
import org.ebayopensource.fido.uaf.tlv.TagsEnum;
import org.ebayopensource.fido.uaf.tlv.TlvAssertionParser;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.spongycastle.jce.interfaces.ECPublicKey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;


public class RegAssertionBuilder {

	public static final String AAID = "EBA0#0001";
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

		String ret = Base64url.encodeToString(byteout.toByteArray());
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
		value = Base64url.decode(AttestCert.base64DERCert);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		return byteout.toByteArray();
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
		value = new byte[] { 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01 };
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
		return KeyCodec.getKeyAsRawBytes((BCECPublicKey)this.keyPair.getPublic());
	}

	private byte[] getSignature(byte[] dataForSigning) throws Exception {

//		PublicKey pub = KeyCodec.getPubKey(
//				Base64.encode(this.keyPair.getPublic().getEncoded(), Base64.URL_SAFE))
//				;
//		PrivateKey priv = KeyCodec.getPrivKey(Base64
//				.encode(this.keyPair.getPrivate().getEncoded(),Base64.URL_SAFE));
//		PublicKey pub = this.keyPair.getPublic();
		PrivateKey priv =
				KeyCodec.getPrivKey(Base64url.decode(AttestCert.priv));
				//this.keyPair.getPrivate();

		logger.info(" : dataForSigning : "
				+ Base64url.encodeToString(dataForSigning));

		BigInteger[] signatureGen = NamedCurve.signAndFromatToRS(priv,
				SHA.sha(dataForSigning, "SHA-256"));

		boolean verify = NamedCurve.verify(
				KeyCodec.getKeyAsRawBytes((ECPublicKey)KeyCodec.getPubKey(Base64url.decode(AttestCert.pubCert))),
				//KeyCodec.getKeyAsRawBytes((ECPublicKey)this.keyPair.getPublic()),
				SHA.sha(dataForSigning, "SHA-256"),
				Asn1.decodeToBigIntegerArray(Asn1.getEncoded(signatureGen)));
		if (!verify) {
			throw new RuntimeException("Signatire match fail");
		}
		byte[] ret = Asn1.toRawSignatureBytes(signatureGen);
		logger.info(" : signature : " + Base64url.encodeToString(ret));

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
