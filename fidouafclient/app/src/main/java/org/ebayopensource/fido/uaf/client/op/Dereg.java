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

package org.ebayopensource.fido.uaf.client.op;

import com.google.gson.Gson;

import org.ebayopensource.fidouafclient.util.Preferences;
import org.ebayopensource.fido.uaf.client.RegAssertionBuilder;
import org.ebayopensource.fido.uaf.msg.DeregisterAuthenticator;
import org.ebayopensource.fido.uaf.msg.DeregistrationRequest;
import org.ebayopensource.fido.uaf.msg.Operation;
import org.ebayopensource.fido.uaf.msg.OperationHeader;
import org.ebayopensource.fido.uaf.msg.Version;

import java.util.logging.Logger;

public class Dereg {
	
	private Logger logger = Logger.getLogger(this.getClass().getName());
	private Gson gson = new Gson();
	
	public String dereg (String uafMsg){
	logger.info ("  [UAF][1]Dereg  ");
	try {
		DeregistrationRequest reg = new DeregistrationRequest();
		reg.header = new OperationHeader();
		reg.header.upv = new Version(1, 0);
		reg.header.op = Operation.Dereg;
		reg.header.appID = Preferences.getSettingsParam("appID");
		reg.authenticators = new DeregisterAuthenticator[1];
		DeregisterAuthenticator deregAuth = new DeregisterAuthenticator();
		deregAuth.aaid = RegAssertionBuilder.AAID;
		String tmp = Preferences.getSettingsParam("keyId");
		byte[] bytes = tmp.getBytes();
		deregAuth.keyID = tmp;
//				Base64.encodeToString(bytes, Base64.NO_WRAP);
		reg.authenticators[0] = deregAuth;
		
		logger.info ("  [UAF][2]Dereg - Reg Response Formed  ");
		Preferences.setSettingsParam("pub", "");
		Preferences.setSettingsParam("priv", "");
		Preferences.setSettingsParam("username", "");
		Preferences.setSettingsParam("keyId", "");
		logger.info ("  [UAF][5]Dereg - keys stored  ");
		return gson.toJson(reg);
	} catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
		return "";
	}
}
