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

package org.ebayopensource.fidouafclient.op;


import org.ebayopensource.fidouafclient.curl.Curl;
import org.ebayopensource.fidouafclient.util.Endpoints;
import org.ebayopensource.fidouafclient.util.Preferences;
import org.ebayopensource.fido.uaf.msg.DeregisterAuthenticator;
import org.ebayopensource.fido.uaf.msg.DeregistrationRequest;
import org.ebayopensource.fido.uaf.msg.Operation;
import org.ebayopensource.fido.uaf.msg.OperationHeader;
import org.ebayopensource.fido.uaf.msg.Version;
import org.ebayopensource.fido.uaf.msg.asm.ASMRequest;
import org.ebayopensource.fido.uaf.msg.asm.Request;
import org.ebayopensource.fido.uaf.msg.asm.obj.DeregisterIn;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.gson.Gson;

public class Dereg {

	private Gson gson = new Gson();
	
	public String getUafMsgRequest (){
		String msg = "{\"uafProtocolMessage\":\"";
		try {
			DeregistrationRequest regResponse = getDereg(); 
			String forSending = getDeregUafMessage(regResponse);
			Preferences.setSettingsParam("deregMsg", forSending);
//			post(forSending);
			JSONArray deregReq = new JSONArray(forSending);
			((JSONObject)deregReq.get(0)).getJSONObject("header").put("appID", "android:apk-key-hash:bE0f1WtRJrZv/C0y9CM73bAUqiI");
			((JSONObject)deregReq.get(0)).getJSONObject("header").remove("serverData");
			JSONObject uafMsg = new JSONObject();
			uafMsg.put("uafProtocolMessage", deregReq.toString());
			return uafMsg.toString();
		} catch (JSONException e) {
			e.printStackTrace();
		}
		msg = msg + "\"}";
		return msg;
	}

	public String getAsmRequestJson(int authenticatorIndex) {
		return gson.toJson(getAsmRequest(authenticatorIndex));
	}

	public ASMRequest<DeregisterIn> getAsmRequest(int authenticatorIndex) {
		ASMRequest<DeregisterIn> ret = new ASMRequest<DeregisterIn>();
		DeregisterIn arg = new DeregisterIn();
		arg.appID = Preferences.getSettingsParam("appID");
		arg.keyID = Preferences.getSettingsParam("keyID");
		ret.args = arg;
		ret.asmVersion = new Version(1, 0);
		ret.authenticatorIndex = authenticatorIndex;
		ret.requestType = Request.Deregister;
		sendDereg();
		return ret;
	}

	public void recordKeyId(String registrationsOut) {
		JSONObject asmResponse;
		try {
			asmResponse = new JSONObject(registrationsOut);

			if (asmResponse.get("responseData") == null) {
				return;
			}
			String keyId = asmResponse.getJSONObject("responseData")
					.getJSONArray("appRegs").getJSONObject(0)
					.getJSONArray("keyIDs").getString(0);
			Preferences.setSettingsParam("keyID", keyId);
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public String sendDereg() {
		return post(getDereg());
	}

	public DeregistrationRequest getDereg() {
		try {
			DeregistrationRequest dereg = new DeregistrationRequest();
			dereg.header = new OperationHeader();
			dereg.header.upv = new Version(1, 0);
			dereg.header.op = Operation.Dereg;
			//dereg.header.serverData = "";
			dereg.header.appID = Preferences.getSettingsParam("appID");
			dereg.authenticators = new DeregisterAuthenticator[1];
			DeregisterAuthenticator deregAuth = new DeregisterAuthenticator();
			deregAuth.aaid = Preferences.getSettingsParam("AAID");
			String tmp = Preferences.getSettingsParam("keyID");
			byte[] bytes = tmp.getBytes();
			deregAuth.keyID = 
					tmp;
					//Base64.encodeToString(bytes, Base64.NO_WRAP);
			dereg.authenticators[0] = deregAuth;

			//return post(dereg);
			return dereg;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	private String post(DeregistrationRequest regResponse) {
		String header = "Content-Type:Application/json Accept:Application/json";
		String json = getDeregUafMessage(regResponse);
		return Curl.postInSeparateThread(Endpoints.getDeregEndpoint(), header , json);
	}
	
	public String post(String json) {
		String header = "Content-Type:Application/json Accept:Application/json";
		return Curl.postInSeparateThread(Endpoints.getDeregEndpoint(), header , json);
	}

	public String getDeregUafMessage(DeregistrationRequest regResponse) {
		DeregistrationRequest[] forSending = new DeregistrationRequest[1];
		forSending[0] = regResponse;
		String json = gson.toJson(forSending, DeregistrationRequest[].class);
		return json;
	}

	public String clientSendDeregResponse (String uafMessage) {
		StringBuffer res = new StringBuffer();
		String decoded = null;
		try {
			JSONObject json = new JSONObject(uafMessage);
			decoded = json.getString("uafProtocolMessage").replace("\\", "");
			post(decoded);
			return decoded;
		} catch (JSONException e) {
			e.printStackTrace();
			return e.getMessage();
		}
	}
}
