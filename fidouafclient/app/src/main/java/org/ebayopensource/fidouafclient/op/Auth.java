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

import org.ebayopensource.fido.uaf.crypto.Base64url;
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
import org.json.JSONObject;

import android.content.Context;

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
	
	public String getUafMsgRequest (String facetId, Context context, boolean isTrx){
		String serverResponse = getAuthRequest();
		return OpUtils.getUafRequest(serverResponse,facetId,context,isTrx);
	}
	
	public String clientSendResponse (String uafMessage){
		return  OpUtils.clientSendRegResponse(uafMessage,Endpoints.getAuthResponseEndpoint());
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
		return Base64url.encodeToString(gson.toJson(
				fcParams).getBytes());
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
