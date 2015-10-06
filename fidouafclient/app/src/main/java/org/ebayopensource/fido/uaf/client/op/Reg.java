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

import android.util.Base64;

import com.google.gson.Gson;

import org.ebayopensource.fidouafclient.util.Preferences;
import org.ebayopensource.fido.uaf.client.RegistrationRequestProcessor;
import org.ebayopensource.fido.uaf.crypto.KeyCodec;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.logging.Logger;


public class Reg {
	
	private Logger logger = Logger.getLogger(this.getClass().getName());
	private Gson gson = new Gson();
	
	public String register (String uafMsg){
	logger.info ("  [UAF][1]Reg  ");
	try {
		KeyPair keyPair = KeyCodec.getKeyPair();
		logger.info("  [UAF][2]Reg - KeyPair generated"+keyPair);
		RegistrationRequestProcessor p = new RegistrationRequestProcessor();
		RegistrationResponse[] ret = new RegistrationResponse[1];
		RegistrationResponse regResponse = p.processRequest(getRegistrationRequest(uafMsg), keyPair);
		logger.info ("  [UAF][4]Reg - Reg Response Formed  ");
		logger.info(regResponse.assertions[0].assertion);
		logger.info ("  [UAF][6]Reg - done  ");
		Preferences.setSettingsParam("pub", Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.URL_SAFE));
		Preferences.setSettingsParam("priv", Base64.encodeToString(keyPair.getPrivate().getEncoded(), Base64.URL_SAFE));
		logger.info ("  [UAF][7]Reg - keys stored  ");
		ret[0] = regResponse;
		return getUafProtocolMsg( gson.toJson(ret) );
	} catch (InvalidAlgorithmParameterException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchProviderException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
		return "";
	}
	
	public RegistrationRequest getRegistrationRequest(String uafMsg) {
		logger.info ("  [UAF][3]Reg - getRegRequest  : " + uafMsg);
		return gson.fromJson(uafMsg, RegistrationRequest[].class)[0];
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
