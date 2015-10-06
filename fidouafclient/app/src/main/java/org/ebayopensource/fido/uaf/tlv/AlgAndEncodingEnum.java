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

package org.ebayopensource.fido.uaf.tlv;

public enum AlgAndEncodingEnum {
	
	UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW (0x01),
	UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER (0x02),
	UAF_ALG_KEY_ECC_X962_RAW (0x100),
	UAF_ALG_KEY_ECC_X962_DER (0x101)
	;
	
	public final int id;

	AlgAndEncodingEnum (int id){
		this.id = id;
	}
}
