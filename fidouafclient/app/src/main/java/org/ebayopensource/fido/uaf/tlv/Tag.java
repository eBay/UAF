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

import org.apache.commons.codec.binary.Base64;


public class Tag {
	public int statusId = 0x00;
	public int id;
	public int length;
	public byte[] value;
	
	public String toString (){
		String ret = "Tag id:"+id;
		ret = ret + " Tag name: " + TagsEnum.get(id);
		if (value != null){
			ret = ret + " Tag value:"+ Base64.encodeBase64URLSafeString(value);
		}
		return ret;
	}

}
