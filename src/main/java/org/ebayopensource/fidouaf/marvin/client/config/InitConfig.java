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

package org.ebayopensource.fidouaf.marvin.client.config;

import org.ebayopensource.fidouaf.marvin.client.OperationalParamsIntf;
import org.ebayopensource.fidouaf.marvin.client.StorageInterface;

public class InitConfig {
	
	private static InitConfig instance = new InitConfig(); 
	
	private boolean initialized = false;

	private OperationalParamsIntf operationalParams;

	public OperationalParamsIntf getOperationalParams() {
		return operationalParams;
	}

	private InitConfig (){
		
	}

	public static InitConfig getInstance (){
		return instance;
	}
	
	public boolean isInitialized(){
		return initialized;
	}
	/**
	 * Example:
	@TargetApi(Build.VERSION_CODES.M)
	public KeyPair genEcKeys (Context context) throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
			KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
		keyPairGenerator.initialize(
				new KeyGenParameterSpec.Builder(
						"key1",
						KeyProperties.PURPOSE_SIGN)
						.setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
						.setDigests(KeyProperties.DIGEST_SHA256,
								KeyProperties.DIGEST_SHA384,
								KeyProperties.DIGEST_SHA512)
						// Only permit the private key to be used if the user authenticated
						// within the last five minutes.
						.setUserAuthenticationRequired(true)
						.setUserAuthenticationValidityDurationSeconds(5 * 60)
						.build());
		return keyPairGenerator.generateKeyPair();
	}
	 * @param keyPairGenerator
	 */
	public void init (
			String aaid, 
			byte[] attestCert, 
			byte[] attestPrivKey,
			OperationalParamsIntf operationalParams,
			StorageInterface storage
			){
		this.operationalParams = operationalParams;
		operationalParams.init(aaid, attestCert, attestPrivKey, storage);
		initialized = true;
	}
	
}
