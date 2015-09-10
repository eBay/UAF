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

public class NotaryImpl implements Notary {

	private static Notary instance = new NotaryImpl();

	private NotaryImpl() {
		// Init
	}

	public static Notary getInstance() {
		return instance;
	}

	public String sign(String signData) {
		return SHA.sha256(signData);
	}

	public boolean verify(String signData, String signature) {
		return signature.equals(SHA.sha256(signData));
	}

}
