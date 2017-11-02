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

package com.nexenio.fido.uaf.core.ops;

import com.nexenio.fido.uaf.core.crypto.BCrypt;
import com.nexenio.fido.uaf.core.crypto.Notary;
import com.nexenio.fido.uaf.core.msg.*;
import org.apache.commons.codec.binary.Base64;

public class AuthenticationRequestGeneration {

    private String appId = RegistrationRequestGeneration.APP_ID;
    private String[] acceptedAaids = null;

    public AuthenticationRequestGeneration() {
    }

    public AuthenticationRequestGeneration(String appId) {
        this.appId = appId;
    }

    public AuthenticationRequestGeneration(String appId, String[] acceptedAaids) {
        this.appId = appId;
        this.acceptedAaids = acceptedAaids;
    }

    public AuthenticationRequest createAuthenticationRequest(Notary notary) {
        AuthenticationRequest authRequest = new AuthenticationRequest();
        OperationHeader header = new OperationHeader();
        authRequest.setChallenge(generateChallenge());
        header.setServerData(generateServerData(authRequest.getChallenge(), notary));
        authRequest.setHeader(header);
        authRequest.getHeader().setOp(Operation.Auth);
        authRequest.getHeader().setAppID(appId);
        authRequest.getHeader().setUpv(new Version(1, 0));

        authRequest.setPolicy(constructAuthenticationPolicy());

        return authRequest;
    }

    private String generateChallenge() {
        return Base64.encodeBase64URLSafeString(BCrypt.gensalt().getBytes());
    }

    private String generateServerData(String challenge, Notary notary) {
        String dataToSign = Base64.encodeBase64URLSafeString(("" + System
                .currentTimeMillis()).getBytes())
                + "."
                + Base64.encodeBase64URLSafeString(challenge.getBytes());
        String signature = notary.sign(dataToSign);

        return Base64.encodeBase64URLSafeString((signature + "." + dataToSign)
                .getBytes());
    }

    public Policy constructAuthenticationPolicy() {
        if (acceptedAaids == null) {
            return null;
        }
        Policy p = new Policy();
        MatchCriteria[][] accepted = new MatchCriteria[acceptedAaids.length][1];
        for (int i = 0; i < accepted.length; i++) {
            MatchCriteria[] a = new MatchCriteria[1];
            MatchCriteria matchCriteria = new MatchCriteria();
            matchCriteria.setAaid(new String[1]);
            matchCriteria.getAaid()[0] = acceptedAaids[i];
            a[0] = matchCriteria;
            accepted[i] = a;
        }
        p.setAccepted(accepted);
        return p;
    }

}
