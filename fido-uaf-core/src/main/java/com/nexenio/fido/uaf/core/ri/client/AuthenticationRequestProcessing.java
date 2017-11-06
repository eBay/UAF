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

package com.nexenio.fido.uaf.core.ri.client;

import com.google.gson.Gson;
import com.nexenio.fido.uaf.core.msg.*;
import org.apache.commons.codec.binary.Base64;

public class AuthenticationRequestProcessing {

    public AuthenticationResponse processRequest(AuthenticationRequest request) {
        AuthenticationResponse response = new AuthenticationResponse();
        Gson gson = new Gson();
        setAppId(request, response);
        response.setOperationHeader(new OperationHeader());
        response.getOperationHeader().setServerData(request.getOperationHeader().getServerData());
        response.getOperationHeader().setOperation(request.getOperationHeader().getOperation());
        response.getOperationHeader().setProtocolVersion(request.getOperationHeader().getProtocolVersion());

        FinalChallengeParams fcParams = new FinalChallengeParams();
        fcParams.setAppId(Constants.APP_ID);
        fcParams.setFacetId(Constants.FACET_ID);
        fcParams.setChallenge(request.getChallenge());

        String serializedFinalChallengeParams = gson.toJson(fcParams);
        response.setFinalChallengeParams(Base64.encodeBase64URLSafeString(serializedFinalChallengeParams.getBytes()));
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
        if (request.getOperationHeader().getAppId() == null && request.getOperationHeader().getAppId().isEmpty()) {
            response.getOperationHeader().setAppId(Constants.APP_ID);
        } else {
            setAppID(request, response);
        }
    }

    private void setAppID(AuthenticationRequest request,
                          AuthenticationResponse response) {
        // TODO Auto-generated method stub

    }
}
