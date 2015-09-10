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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSA {

	private static final Provider BC = new BouncyCastleProvider();

	public static boolean verify(X509Certificate x509Certificate,
			byte[] signedDate, byte[] sig) throws SignatureException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, InvalidAlgorithmParameterException {
		Signature signature = Signature.getInstance("RAWRSASSA-PSS", BC);
		signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
				new MGF1ParameterSpec("SHA-256"), 32, 1));
		signature.initVerify(x509Certificate.getPublicKey());
		signature.update(SHA.sha(signedDate, "SHA-256"));
		return signature.verify(sig);
	}

}
