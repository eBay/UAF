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

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

public class Tags {
	
	private Map<Integer,Tag> tags = new HashMap<Integer, Tag>();
	
	public void add (Tag t){
		tags.put(t.id, t);
	}
	
	public void addAll (Tags all){
		tags.putAll(all.getTags());
	}
	
	public Map<Integer,Tag> getTags (){
		return tags;
	}
	
	public String toString (){
		StringBuilder res = new StringBuilder();
		for (Entry<Integer, Tag> tag : tags.entrySet()) {
			res.append(", ");
			res.append(tag.getValue().toString());
		}
		if (res.length()>0){
			return "{" + res.substring(1) + "}";
		} else {
			return "{}";
		}
		
	}
	
	public String toUAFV1TLV (){
		return null;
	}
}
