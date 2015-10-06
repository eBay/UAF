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
import com.google.gson.GsonBuilder;

import org.ebayopensource.fido.uaf.client.AuthenticationRequestProcessor;
import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;

import java.util.logging.Logger;

public class Auth {
	
	private Logger logger = Logger.getLogger(this.getClass().getName());
	private Gson gson = new GsonBuilder().disableHtmlEscaping().create(); 
	
	public String auth (String uafMsg){
	logger.info ("  [UAF][1]Auth  ");
	try {
		logger.info("  [UAF][2]Auth - priv key retrieved");
		AuthenticationRequestProcessor p = new AuthenticationRequestProcessor();
		AuthenticationResponse[] ret = new AuthenticationResponse[1];
		AuthenticationResponse regResponse = p.processRequest(getAuthRequest(uafMsg));
		logger.info ("  [UAF][4]Auth - Auth Response Formed  ");
		logger.info(regResponse.assertions[0].assertion);
		logger.info ("  [UAF][6]Auth - done  ");
		ret[0] = regResponse;
		return getUafProtocolMsg( gson.toJson(ret) );
	} catch (Exception e) {
		e.printStackTrace();
		return "e="+e;
	} 
	}
	
	public AuthenticationRequest getAuthRequest(String uafMsg) {
		logger.info ("  [UAF][3]Reg - getAuthRequest  : " + uafMsg);
		return gson.fromJson(uafMsg, AuthenticationRequest[].class)[0];
	}

	public String getUafProtocolMsg (String uafMsg){
		String msg = "{\"uafProtocolMessage\":";
		msg = msg + "\"";
		msg = msg + uafMsg.replace("\"","\\\"");
		msg = msg + "\"";
		msg = msg + "}";
		return msg;
	}
}
