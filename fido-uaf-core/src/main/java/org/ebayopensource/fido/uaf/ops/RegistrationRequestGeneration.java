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

package org.ebayopensource.fido.uaf.ops;

import org.apache.commons.codec.binary.Base64;
import org.ebayopensource.fido.uaf.crypto.BCrypt;
import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.msg.MatchCriteria;
import org.ebayopensource.fido.uaf.msg.Operation;
import org.ebayopensource.fido.uaf.msg.OperationHeader;
import org.ebayopensource.fido.uaf.msg.Policy;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.msg.Version;

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
			matchCriteria.aaid = new String[1];
			matchCriteria.aaid[0] = acceptedAaids[i];
			a[0] = matchCriteria;
			accepted[i] = a;
		}
		p.accepted = accepted;
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
		header.serverData = serverData;
		regRequest.header = header;
		regRequest.header.op = Operation.Reg;
		regRequest.header.appID = appId;
		regRequest.header.upv = new Version(1, 0);
		regRequest.challenge = challenge;
		regRequest.policy = constructAuthenticationPolicy();
		regRequest.username = username;
		return regRequest;
	}

	private String generateChallenge() {
		return Base64.encodeBase64URLSafeString(BCrypt.gensalt().getBytes());
	}

}
