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

package org.ebayopensource.fidouaf.res.util;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.ebayopensource.fido.uaf.crypto.*;
import org.apache.commons.codec.binary.Base64;
import org.ebayopensource.fido.uaf.tlv.AlgAndEncodingEnum;
import org.ebayopensource.fido.uaf.tlv.Tag;
import org.ebayopensource.fido.uaf.tlv.UnsignedUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;

/**
 * This is just en example implementation. You should implement this class based on your operational environment.
 */
public class NotaryImpl implements Notary {

	private Logger logger = Logger.getLogger(this.getClass().getName());
	private String hmacSecret = "HMAC-is-just-one-way";
	private static Notary instance = new NotaryImpl();

	private NotaryImpl() {
		// Init
	}

	public static Notary getInstance() {
		return instance;
	}

	public String sign(String signData) {
		try {
			return Base64.encodeBase64URLSafeString(HMAC.sign(signData, hmacSecret));
		} catch (Exception e) {
			logger.info(e.toString());
		}
		return null;
	}

	public boolean verify(String signData, String signature) {
		try {
			return MessageDigest.isEqual(Base64.decodeBase64(signature), HMAC.sign(signData, hmacSecret));
		} catch (Exception e) {
			logger.info(e.toString());
		}
		return false;
	}

	public boolean verifySignature(byte[] dataForSigning, byte[] signature,
								   String pubKey, AlgAndEncodingEnum algAndEncoding)
			throws Exception {
		// TODO Change to specific exceptions, maybe add some try/catch and then throw a more generic one

		logger.info(" : pub 		   : " + pubKey);
		logger.info(" : dataForSigning : "
				+ Base64.encodeBase64URLSafeString(dataForSigning));
		logger.info(" : signature 	   : "
				+ Base64.encodeBase64URLSafeString(signature));

		// This works
		// return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pubKey),
		// dataForSigning, Asn1.decodeToBigIntegerArray(signature));

		byte[] decodeBase64 = Base64.decodeBase64(pubKey);
		if(algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW) {
			PublicKey publicKey = KeyCodec.getRSAPublicKey(decodeBase64);
			return RSA.verifyPSS(publicKey,
					SHA.sha(dataForSigning, "SHA-256"),
					signature);
		} else if(algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER) {
			PublicKey publicKey = KeyCodec.getRSAPublicKey(new DEROctetString(decodeBase64).getOctets());
			return RSA.verifyPSS(publicKey,
					SHA.sha(dataForSigning, "SHA-256"),
					new DEROctetString(signature).getOctets());
		} else {
			if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER) {
				ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(
						decodeBase64, "secp256k1");
				return NamedCurve.verifyUsingSecp256k1(
						KeyCodec.getKeyAsRawBytes(decodedPub),
						SHA.sha(dataForSigning, "SHA-256"),
						Asn1.decodeToBigIntegerArray(signature));
			}
			if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER) {
				if (decodeBase64.length>65){
					return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pubKey),
							SHA.sha(dataForSigning, "SHA-256"),
							Asn1.decodeToBigIntegerArray(signature));
				} else {
					ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(
							decodeBase64, "secp256r1");
					return NamedCurve.verify(
							KeyCodec.getKeyAsRawBytes(decodedPub),
							SHA.sha(dataForSigning, "SHA-256"),
							Asn1.decodeToBigIntegerArray(signature));
				}
			}
			if (signature.length == 64) {
				ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(
						decodeBase64, "secp256r1");
				return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(decodedPub),
						SHA.sha(dataForSigning, "SHA-256"),
						Asn1.transformRawSignature(signature));
			} else if (65 == decodeBase64.length
					&& AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER == algAndEncoding) {
				ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(
						decodeBase64, "secp256r1");
				return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(decodedPub),
						SHA.sha(dataForSigning, "SHA-256"),
						Asn1.decodeToBigIntegerArray(signature));
			} else {
				return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pubKey),
						SHA.sha(dataForSigning, "SHA-256"),
						Asn1.decodeToBigIntegerArray(signature));
			}
		}
	}

	public AlgAndEncodingEnum getAlgAndEncoding(Tag info) {
		int id = (int) info.value[3] + (int) info.value[4] * 256;
		AlgAndEncodingEnum ret = null;
		AlgAndEncodingEnum[] values = AlgAndEncodingEnum.values();
		for (AlgAndEncodingEnum algAndEncodingEnum : values) {
			if (algAndEncodingEnum.id == id) {
				ret = algAndEncodingEnum;
				break;
			}
		}
		logger.info(" : SignatureAlgAndEncoding : " + ret);
		return ret;
	}

	public byte[] getDataForSigning(Tag signedData) throws IOException {
		byte[] signedBytes = new byte[signedData.value.length + 4];
		System.arraycopy(UnsignedUtil.encodeInt(signedData.id), 0, signedBytes, 0, 2);
		System.arraycopy(UnsignedUtil.encodeInt(signedData.length), 0, signedBytes, 2,
				2);
		System.arraycopy(signedData.value, 0, signedBytes, 4, signedData.value.length);
		return signedBytes;
	}

	public byte[] encodeInt(int id) {
		byte[] bytes = new byte[2];
		bytes[0] = (byte) (id & 0x00ff);
		bytes[1] = (byte) ((id & 0xff00) >> 8);
		return bytes;
	}
}
