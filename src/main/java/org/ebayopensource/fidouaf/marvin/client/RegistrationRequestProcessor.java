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

package org.ebayopensource.fidouaf.marvin.client;

import org.ebayopensource.util.Base64;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.ebayopensource.fidouaf.marvin.client.msg.AuthenticatorRegistrationAssertion;
import org.ebayopensource.fidouaf.marvin.client.msg.FinalChallengeParams;
import org.ebayopensource.fidouaf.marvin.client.msg.OperationHeader;
import org.ebayopensource.fidouaf.marvin.client.msg.RegistrationRequest;
import org.ebayopensource.fidouaf.marvin.client.msg.RegistrationResponse;

public class RegistrationRequestProcessor {

	public RegistrationResponse processRequest(RegistrationRequest regRequest,
			OperationalParamsIntf operationalParams) throws Exception {

		RegistrationResponse response = new RegistrationResponse();
		RegAssertionBuilder builder = new RegAssertionBuilder(operationalParams);
		Gson gson = new GsonBuilder().create();
		
		response.header = new OperationHeader();
		response.header.serverData = regRequest.header.serverData;
		response.header.appID = regRequest.header.appID;
		response.header.op = regRequest.header.op;
		response.header.upv = regRequest.header.upv;

		FinalChallengeParams fcParams = new FinalChallengeParams();
		fcParams.appID = regRequest.header.appID;
		fcParams.facetID = operationalParams.getFacetId(fcParams.appID);
		fcParams.challenge = regRequest.challenge;
		response.fcParams = Base64.encodeToString(gson.toJson(fcParams)
				.getBytes(), Base64.URL_SAFE);
		setAssertions(response, builder);
		return response;
	}

	private void setAssertions(RegistrationResponse response,
			RegAssertionBuilder builder) throws Exception {
		response.assertions = new AuthenticatorRegistrationAssertion[1];
			response.assertions[0] = new AuthenticatorRegistrationAssertion();
			response.assertions[0].assertion = builder.getAssertions(response);
			response.assertions[0].assertionScheme = "UAFV1TLV";
	}

}
