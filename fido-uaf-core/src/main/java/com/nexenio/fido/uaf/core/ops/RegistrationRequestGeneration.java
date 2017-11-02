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

import com.nexenio.fido.uaf.core.msg.Version;
import org.apache.commons.codec.binary.Base64;
import com.nexenio.fido.uaf.core.crypto.BCrypt;
import com.nexenio.fido.uaf.core.crypto.Notary;
import com.nexenio.fido.uaf.core.msg.MatchCriteria;
import com.nexenio.fido.uaf.core.msg.Operation;
import com.nexenio.fido.uaf.core.msg.OperationHeader;
import com.nexenio.fido.uaf.core.msg.Policy;
import com.nexenio.fido.uaf.core.msg.RegistrationRequest;

public class RegistrationRequestGeneration {

	public static final String APP_ID = "https://uaf.ebay.com/uaf/facets";
	private String appId = APP_ID;
	private String[] acceptedAaids;

	public RegistrationRequestGeneration() {

	}

	public RegistrationRequestGeneration(String appId) {
		this.appId = appId;
	}

	public RegistrationRequestGeneration(String appId, String[] acceptedAaids) {
		this.appId = appId;
		this.acceptedAaids = acceptedAaids;
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

	public RegistrationRequest createRegistrationRequest(String username,
			Notary notary) {
		String challenge = generateChallenge();
		String serverDataString = generateServerData(username, challenge,
				notary);
		return createRegistrationRequest(username, serverDataString, challenge);
	}

	private String generateServerData(String username, String challenge,
			Notary notary) {
		String dataToSign = Base64.encodeBase64URLSafeString(("" + System
				.currentTimeMillis()).getBytes())
				+ "."
				+ Base64.encodeBase64URLSafeString(username.getBytes())
				+ "."
				+ Base64.encodeBase64URLSafeString(challenge.getBytes());
		String signature = notary.sign(dataToSign);

		return Base64.encodeBase64URLSafeString((signature + "." + dataToSign)
				.getBytes());
	}

	private RegistrationRequest createRegistrationRequest(String username,
			String serverData, String challenge) {
		RegistrationRequest regRequest = new RegistrationRequest();
		OperationHeader header = new OperationHeader();
        header.setServerData(serverData);
		regRequest.setHeader(header);
		regRequest.getHeader().setOp(Operation.Reg);
		regRequest.getHeader().setAppID(appId);
		regRequest.getHeader().setUpv(new Version(1, 0));
		regRequest.setChallenge(challenge);
		regRequest.setPolicy(constructAuthenticationPolicy());
		regRequest.setUsername(username);
		return regRequest;
	}

	private String generateChallenge() {
		return Base64.encodeBase64URLSafeString(BCrypt.gensalt().getBytes());
	}

}
