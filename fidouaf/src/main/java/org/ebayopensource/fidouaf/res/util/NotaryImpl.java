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

import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.crypto.SHA;
import org.ebayopensource.fido.uaf.crypto.HMAC;
import org.apache.commons.codec.binary.Base64;
import java.security.MessageDigest;

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

}
