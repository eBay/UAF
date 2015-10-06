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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA {

	public static String sha1(String base) {
		return sha(base, "SHA-1");
	}

	public static String sha256(String base) {
		return sha(base, "SHA-256");
	}

	public static String sha(String base, String alg) {
		try {
			MessageDigest digest = MessageDigest.getInstance(alg);
			byte[] hash = digest.digest(base.getBytes("UTF-8"));
			StringBuffer hexString = new StringBuffer();

			for (int i = 0; i < hash.length; i++) {
				String hex = Integer.toHexString(0xff & hash[i]);
				if (hex.length() == 1)
					hexString.append('0');
				hexString.append(hex);
			}

			return hexString.toString();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	public static byte[] sha(byte[] base, String alg) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance(alg);
		return digest.digest(base);
	}

}
