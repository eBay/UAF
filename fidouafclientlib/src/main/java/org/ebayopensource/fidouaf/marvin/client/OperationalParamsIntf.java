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

package org.ebayopensource.fidouaf.marvin.client;

import java.security.KeyPairGenerator;

public interface OperationalParamsIntf {
	
	/**
	 * AAID === Facet ID === Pub key used for signing app, or signature of the public key with private key
	 * @return
	 */
	String getAAID ();
	byte[] getAttestCert ();
	long getRegCounter ();
	void incrementRegCounter ();
	long getAuthCounter ();
	void incrementAuthCounter ();
	/**
	 * Let server check if AAID and facet id is valid. Client can return true.
	 * That way one server call will be saved
	 * @param appId
	 * @param facetId
	 * @return
	 */
	boolean isFacetIdValid (String appId, String facetId);
	byte [] signWithAttestationKey (byte[] dataToSign) throws Exception;
	StorageInterface getStorage ();
	KeyPairGenerator getKeyPairGenerator(String keyId);
	RegRecord genAndRecord(String appId);
	/**
	 * Skip the check if faced Id is in the list of server trusted facet Ids.
	 * Just return the facet Id
	 * @param appId
	 * @return
	 */
	String getFacetId(String appId);
	String getKeyId(String appId);
	void init (String aaid, byte[] attestCert, byte[] attestPrivKey, StorageInterface storage);
	byte[] getSignature(byte[] signedDataValue, String keyId) throws Exception;
}
