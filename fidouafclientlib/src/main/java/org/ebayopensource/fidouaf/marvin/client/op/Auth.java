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
package org.ebayopensource.fidouaf.marvin.client.op;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.ebayopensource.fidouaf.marvin.client.AuthenticationRequestProcessor;
import org.ebayopensource.fidouaf.marvin.client.config.InitConfig;
import org.ebayopensource.fidouaf.marvin.client.msg.AuthenticationRequest;
import org.ebayopensource.fidouaf.marvin.client.msg.AuthenticationResponse;

import java.util.logging.Logger;

public class Auth {
	
	private Logger logger = Logger.getLogger(this.getClass().getName());
	private Gson gson = new GsonBuilder().disableHtmlEscaping().create(); 
	
	public String auth (String uafMsg) throws UafMsgProcessException, UafResponseMsgParseException, UafRequestMsgParseException{
		logger.info ("  [UAF][1]Auth  ");
		AuthenticationRequestProcessor p = new AuthenticationRequestProcessor();
		AuthenticationResponse[] ret = new AuthenticationResponse[1];
		ret[0] = process(getAuthRequest(uafMsg), p);
		return getUafProtocolMsg( ret );
	}

	private AuthenticationResponse process(AuthenticationRequest uafMsg,
			AuthenticationRequestProcessor p)
			throws UafMsgProcessException {
		try{
			AuthenticationResponse regResponse = p.processRequest(uafMsg, InitConfig.getInstance().getOperationalParams());
			checkResult(regResponse);
			logger.info ("  [UAF][3]Auth - Auth Response Formed  ");
			logger.info(regResponse.assertions[0].assertion);
			logger.info ("  [UAF][4]Auth - done  ");
			return regResponse;
		} catch (Exception e){
			throw new UafMsgProcessException (e);
		}
	}

	private void checkResult(AuthenticationResponse regResponse) throws Exception {
		if (regResponse == null || regResponse.assertions == null || regResponse.assertions.length == 0 || regResponse.assertions[0] == null){
			throw new Exception ("Processing didn't return result");
		}
	}
	
	public AuthenticationRequest getAuthRequest(String uafMsg) throws UafRequestMsgParseException {
		try {
			logger.info ("  [UAF][2]Reg - getAuthRequest  : " + uafMsg);
			return gson.fromJson(uafMsg, AuthenticationRequest[].class)[0];
		} catch (Exception e){
			throw new UafRequestMsgParseException (e);
		}
	}

	public String getUafProtocolMsg (AuthenticationResponse[] ret) throws UafResponseMsgParseException{
		try{
			return getUafProtocolMsg(gson.toJson(ret));
		}catch (Exception e){
			throw new UafResponseMsgParseException(e);
		}
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
