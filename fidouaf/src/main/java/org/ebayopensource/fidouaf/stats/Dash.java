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

package org.ebayopensource.fidouaf.stats;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class Dash {
	
	public static String LAST_REG_REQ = "LAST_REG_REQ";
	public static String LAST_REG_RES = "LAST_REG_RES";
	public static String LAST_AUTH_REQ = "LAST_AUTH_REQ";
	public static String LAST_AUTH_RES = "LAST_AUTH_RES";
	public static String LAST_DEREG_REQ = "LAST_DEREG_REQ";
	
	private static Dash instance = new Dash();
	public Map<String, Object> stats = new  HashMap<String, Object>();
	public List<Object> history = new ArrayList<Object>(100);
	public List<String> uuids = new ArrayList<String>();
	public List<String> facetIds = new ArrayList<String>();
	
	private Dash (){
		//Init
	}

	public static Dash getInstance (){
		return instance;
	}
	
	public void add(Object o){
		if (history.size() >99){
			history.remove(0);
		}
		history.add(o);
	}
	
}
