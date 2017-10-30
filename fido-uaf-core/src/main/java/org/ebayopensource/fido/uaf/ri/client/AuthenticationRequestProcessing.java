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

package org.ebayopensource.fido.uaf.ri.client;

import com.google.gson.Gson;
import org.apache.commons.codec.binary.Base64;
import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.msg.AuthenticatorSignAssertion;
import org.ebayopensource.fido.uaf.msg.FinalChallengeParams;
import org.ebayopensource.fido.uaf.msg.OperationHeader;

public class AuthenticationRequestProcessing {

	public AuthenticationResponse processRequest(AuthenticationRequest request) {
		AuthenticationResponse response = new AuthenticationResponse();
		Gson gson = new Gson();
		setAppId(request, response);
        response.setHeader(new OperationHeader());
        response.getHeader().setServerData(request.getHeader().getServerData());
        response.getHeader().setOp(request.getHeader().getOp());
        response.getHeader().setUpv(request.getHeader().getUpv());

		FinalChallengeParams fcParams = new FinalChallengeParams();
        fcParams.setAppID(Constants.APP_ID);
        fcParams.setFacetID(Constants.FACET_ID);
        fcParams.setChallenge(request.getChallenge());
        response.setFcParams(Base64.encodeBase64URLSafeString(gson.toJson(
            fcParams).getBytes()));
        setAssertions(response);
		return response;
	}

	private void setAssertions(AuthenticationResponse response) {
		AuthenticatorSignAssertion assertion = new AuthenticatorSignAssertion();
        assertion.setAssertionScheme("UAFV1TLV");
        // Example from specs doc
        assertion.setAssertion(
            "Aj7WAAQ-jgALLgkAQUJDRCNBQkNEDi4FAAABAQEADy4gAHwyJAEX8t1b2wOxbaKOC5ZL7ACqbLo_TtiQfK3DzDsHCi4gAFwCUz"
                + "-dOuafXKXJLbkUrIzjAU6oDbP8B9iLQRmCf58fEC4AAAkuIABkwI"
                + "-f3bIe_Uin6IKIFvqLgAOrpk6_nr0oVAK9hIl82A0uBAACAAAABi5AADwDOcBvPslX2bRNy4SvFhAwhEAoBSGUitgMUNChgUSMxss3K3ukekq1paG7Fv1v5mBmDCZVPt2NCTnjUxrjTp4");

        AuthenticatorSignAssertion[] assertions = new AuthenticatorSignAssertion[1];
		assertions[0] = assertion;
        response.setAssertions(assertions);
    }

	private void setAppId(AuthenticationRequest request,
			AuthenticationResponse response) {
        if (request.getHeader().getAppID() == null && request.getHeader().getAppID().isEmpty()) {
            response.getHeader().setAppID(Constants.APP_ID);
        } else {
			setAppID(request, response);
		}
	}

	private void setAppID(AuthenticationRequest request,
			AuthenticationResponse response) {
		// TODO Auto-generated method stub

	}
}
