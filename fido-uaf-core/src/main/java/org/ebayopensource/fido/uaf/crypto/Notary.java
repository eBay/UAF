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

import org.ebayopensource.fido.uaf.tlv.AlgAndEncodingEnum;
import org.ebayopensource.fido.uaf.tlv.Tag;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public interface Notary {

	public String sign(String dataToSign);

	public boolean verify(String dataToSign, String signature);

	public boolean verifySignature(byte[] dataForSigning, byte[] signature,
							String pubKey, AlgAndEncodingEnum algAndEncoding) throws Exception;

	public AlgAndEncodingEnum getAlgAndEncoding(Tag info);

	public byte[] getDataForSigning(Tag signedData) throws IOException;

	public byte[] encodeInt(int id);
}
