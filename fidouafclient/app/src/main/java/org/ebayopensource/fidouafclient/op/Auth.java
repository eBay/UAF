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
import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.msg.AuthenticatorSignAssertion;
import org.ebayopensource.fido.uaf.msg.FinalChallengeParams;
import org.ebayopensource.fido.uaf.msg.OperationHeader;
import org.ebayopensource.fido.uaf.msg.Version;
import org.ebayopensource.fido.uaf.msg.asm.ASMRequest;
import org.ebayopensource.fido.uaf.msg.asm.Request;
import org.ebayopensource.fido.uaf.msg.asm.obj.AuthenticateIn;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.util.Base64;

import com.google.gson.Gson;

public class Auth {
	
	private Gson gson = new Gson();
	
	public String getAsmRequestJson (int authenticatorIndex){
		return gson.toJson(getAsmRequest(authenticatorIndex));
	}
	
	public ASMRequest<AuthenticateIn> getAsmRequest (int authenticatorIndex){
		ASMRequest<AuthenticateIn> ret = new ASMRequest<AuthenticateIn>();
		ret.args = getAuthenticateIn();
		ret.asmVersion = new Version(1, 0);
		ret.authenticatorIndex = authenticatorIndex;
		ret.requestType = Request.Authenticate;
		return ret;
	}
	
	public String getUafMsgRequest (boolean isTrx){
		String msg = "{\"uafProtocolMessage\":\"";
		try {
			String serverResponse = getAuthRequest();
			JSONArray authReq = new JSONArray(serverResponse);
			((JSONObject)authReq.get(0)).getJSONObject("header").put("appID", "android:apk-key-hash:bE0f1WtRJrZv/C0y9CM73bAUqiI");
			if (isTrx) {
				((JSONObject) authReq.get(0)).put("transaction", getTransaction());
			}
			JSONObject uafMsg = new JSONObject();
			uafMsg.put("uafProtocolMessage", authReq.toString());
			return uafMsg.toString();
		} catch (JSONException e) {
			e.printStackTrace();
		}
		msg = msg + "\"}";
		return msg;
	}

	private JSONArray getTransaction (){
		JSONArray ret = new JSONArray();
		JSONObject trx = new JSONObject();

		try {
			trx.put("contentType", "text/plain");
			trx.put("content", Base64.encodeToString("Authentication".getBytes(),Base64.URL_SAFE));
		} catch (JSONException e) {
			e.printStackTrace();
		}

		ret.put(trx);
		return ret;
	}
	
	public String clientSendResponse (String uafMessage){
		StringBuffer res = new StringBuffer();
		String decoded = null;
		try {
			JSONObject json = new JSONObject (uafMessage);
			decoded = json.getString("uafProtocolMessage").replace("\\", "");
		} catch (JSONException e) {
			e.printStackTrace();
		}
		
		res.append("#uafMessageOut");
		res.append("\n");
		res.append(decoded);
		String headerStr = "Content-Type:Application/json Accept:Application/json";
		res.append("\n");
		res.append("\n");
		res.append("\n");
		res.append("#ServerResponse");
		res.append("\n");
		String serverResponse = Curl.postInSeparateThread(Endpoints.getAuthResponseEndpoint(), headerStr , decoded);
		res.append(serverResponse);
		return res.toString();
	}

	private String getAuthRequest() {
		String url = Endpoints.getAuthRequestEndpoint();
		return Curl.getInSeparateThread(url);
	}

	private AuthenticateIn getAuthenticateIn() {
		AuthenticateIn ret = new AuthenticateIn();
		
		String url = Endpoints.getAuthRequestEndpoint();
		String respFromServer = Curl.getInSeparateThread(url);
		AuthenticationRequest request = null;
		try{
			request = gson.fromJson(respFromServer, AuthenticationRequest[].class)[0];
			ret.appID = request.header.appID;
			ret.finalChallenge = getFinalChalenge(request);
			ret.keyIDs = new String[1];
			ret.keyIDs[0] = Preferences.getSettingsParam("keyID");
			freezeAuthResponse(request);
		} catch (Exception e){
			
		}
		
		return ret;
	}
	
	private String getFinalChalenge(AuthenticationRequest request) {
		FinalChallengeParams fcParams = new FinalChallengeParams();
		fcParams.appID = request.header.appID;
		Preferences.setSettingsParam("appID", fcParams.appID);
		fcParams.facetID = getFacetId();
		fcParams.challenge = request.challenge;
		return Base64.encodeToString(gson.toJson(
				fcParams).getBytes(), Base64.URL_SAFE);
	}

	private String getFacetId() {
		return "";
	}
	
	public void freezeAuthResponse (AuthenticationRequest authRequest){
		String json = gson.toJson(getAuthResponse(authRequest), AuthenticationResponse.class);
		Preferences.setSettingsParam("authResponse", json);
	}

	private AuthenticationResponse getAuthResponse(AuthenticationRequest authRequest) {
		AuthenticationResponse response = new AuthenticationResponse();
		
		response.header = new OperationHeader();
		response.header.serverData = authRequest.header.serverData;
		response.header.appID = authRequest.header.appID;
		response.header.op = authRequest.header.op;
		response.header.upv = authRequest.header.upv;
		response.fcParams = getFinalChalenge(authRequest);
		
		return response;
	}
	
	public String sendAuthResponse (String authOut){
		String json = getAuthResponseForSending(authOut);
		String headerStr = "Content-Type:Application/json Accept:Application/json";
		String res = Curl.postInSeparateThread(Endpoints.getAuthResponseEndpoint(), headerStr , json);
		return res;
	}

	private String getAuthResponseForSending(String authOut) {
		String ret = null;
		try{
		AuthenticationResponse authResponse = gson.fromJson(Preferences.getSettingsParam("authResponse"), AuthenticationResponse.class);
		JSONObject assertions = new JSONObject(authOut);
		authResponse.assertions = new AuthenticatorSignAssertion[1];
		authResponse.assertions[0] = new AuthenticatorSignAssertion();
		authResponse.assertions[0].assertionScheme = assertions.getJSONObject("responseData").getString("assertionScheme");
		authResponse.assertions[0].assertion = assertions.getJSONObject("responseData").getString("assertion");
		AuthenticationResponse[] forSending = new AuthenticationResponse[1];
		forSending[0] = authResponse;
		return gson.toJson(forSending, AuthenticationResponse[].class);
		} catch (Exception e){
			e.printStackTrace();
		}
		
		return ret;
	}

}
