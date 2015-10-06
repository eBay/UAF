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

package org.ebayopensource.fido.uaf.client;

import android.util.Base64;

import com.google.gson.Gson;

import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.msg.AuthenticatorSignAssertion;
import org.ebayopensource.fido.uaf.msg.FinalChallengeParams;
import org.ebayopensource.fido.uaf.msg.OperationHeader;

public class AuthenticationRequestProcessor {
	
	public AuthenticationResponse processRequest(AuthenticationRequest request) {
		AuthenticationResponse response = new AuthenticationResponse();
		AuthAssertionBuilder builder = new AuthAssertionBuilder();
		Gson gson = new Gson();


		response.header = new OperationHeader();
		response.header.serverData = request.header.serverData;
		response.header.op = request.header.op;
		response.header.upv = request.header.upv;
		response.header.appID = request.header.appID;

		FinalChallengeParams fcParams = new FinalChallengeParams();
		fcParams.appID = request.header.appID;
		fcParams.facetID = getFacetId();
		fcParams.challenge = request.challenge;
		response.fcParams = Base64.encodeToString(gson.toJson(
				fcParams).getBytes(), Base64.URL_SAFE);
		setAssertions(response,builder);
		return response;
	}

	private String getFacetId() {
		return "";
	}

	private void setAssertions(AuthenticationResponse response, AuthAssertionBuilder builder) {
		response.assertions = new AuthenticatorSignAssertion[1];
		try {
			response.assertions[0] = new AuthenticatorSignAssertion();
			response.assertions[0].assertion = builder.getAssertions(response);
			response.assertions[0].assertionScheme = "UAFV1TLV";
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}



}
