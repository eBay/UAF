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

package org.ebayopensource.fido.uaf.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class HMAC {

	public static byte[] sign(String toSign, String secret) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException {
		validateParameters(toSign, secret);
		String password = secret;
		PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory kf = SecretKeyFactory
				.getInstance("PBEWithMD5AndDES");
		SecretKey passwordKey = kf.generateSecret(keySpec);

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(passwordKey);
		byte[] text = toSign.getBytes("UTF-8");
		byte[] signatureBytes = mac.doFinal(text);

		return signatureBytes;
	}

	private static void validateParameters(String toSign, String secret) {
		if (toSign == null || toSign.isEmpty()){
			throw new InvalidParameterException("Empty string for signing");
		}
		if (secret == null || secret.isEmpty()){
			throw new InvalidParameterException("Empty secret for signing");
		}
	}
}
