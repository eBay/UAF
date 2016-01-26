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

import java.io.IOException;

public class TagAssertionInfo {
	
	private Tag t;
	private boolean isReg = false;
	private int authenticatorVersion = 0;
	private int authenticatorMode = 0;
	private int signatureAlgAndEncoding = 0;
	private int publicKeyAlgAndEncoding = 0;

	public TagAssertionInfo (Tag t) throws InvalidArgumentException, IOException {
		this.t = t;
		if (t.id != TagsEnum.TAG_ASSERTION_INFO.id){
			throw new InvalidArgumentException ("Not TAG_ASSERTION_INFO tag"); 
		}
		if (t.length != 5 && t.length != 7){
			throw new InvalidArgumentException ("Unrecognized tag structure. Length="+t.length); 
		}
		if (t.length == 7){
			isReg = true;
		}
		parse ();
	}

	private void parse() throws IOException {
		ByteInputStream bytes = new ByteInputStream(t.value);
		authenticatorVersion = UnsignedUtil.read_UAFV1_UINT16(bytes);
		authenticatorMode = bytes.readByte();
		signatureAlgAndEncoding = UnsignedUtil.read_UAFV1_UINT16(bytes);
		if (isReg){
			publicKeyAlgAndEncoding = UnsignedUtil.read_UAFV1_UINT16(bytes);
		}
	}

	public Tag getT() {
		return t;
	}

	public boolean isReg() {
		return isReg;
	}

	public int getAuthenticatorVersion() {
		return authenticatorVersion;
	}

	public int getAuthenticatorMode() {
		return authenticatorMode;
	}

	public int getSignatureAlgAndEncoding() {
		return signatureAlgAndEncoding;
	}

	public int getPublicKeyAlgAndEncoding() {
		return publicKeyAlgAndEncoding;
	}

	public String toString (){
		return " isReg="+isReg
				+ " authenticatorVersion="+authenticatorVersion
				+ " authenticatorMode="+authenticatorMode
				+ " signatureAlgAndEncoding="+signatureAlgAndEncoding
				+ " publicKeyAlgAndEncoding="+publicKeyAlgAndEncoding
				;
		
	}
	
}
