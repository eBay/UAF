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

import java.util.logging.Logger;

import org.ebayopensource.fidouaf.marvin.client.RegistrationRequestProcessor;
import org.ebayopensource.fidouaf.marvin.client.config.InitConfig;
import org.ebayopensource.fidouaf.marvin.client.msg.RegistrationRequest;
import org.ebayopensource.fidouaf.marvin.client.msg.RegistrationResponse;

import com.google.gson.Gson;

public class Reg {

	private Logger logger = Logger.getLogger(this.getClass().getName());
	private Gson gson = new Gson();

	public String register(String uafMsg) throws UafMsgProcessException, UafRequestMsgParseException, UafResponseMsgParseException {
		logger.info("  [UAF][1]Reg  ");

		RegistrationResponse[] ret = new RegistrationResponse[1];
		RegistrationResponse regResponse = process(getRegistrationRequest(uafMsg));
		logger.info(regResponse.assertions[0].assertion);
		ret[0] = regResponse;
		return getUafProtocolMsg(ret);
	}

	public RegistrationResponse process(RegistrationRequest regRequest)
			throws UafMsgProcessException {
		try {
			RegistrationRequestProcessor p = new RegistrationRequestProcessor();
			return p.processRequest(regRequest, InitConfig.getInstance()
					.getOperationalParams());
		} catch (Exception e) {
			throw new UafMsgProcessException(e);
		}
	}

	public RegistrationRequest getRegistrationRequest(String uafMsg) throws UafRequestMsgParseException {
		try {
			logger.info("  [UAF][3]Reg - getRegRequest  : " + uafMsg);
			return gson.fromJson(uafMsg, RegistrationRequest[].class)[0];
		} catch (Exception e) {
			throw new UafRequestMsgParseException(e);
		}
	}

	public String getUafProtocolMsg(RegistrationResponse[] ret)
			throws UafResponseMsgParseException {
		try {
			return getUafProtocolMsg(gson.toJson(ret));
		} catch (Exception e) {
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
