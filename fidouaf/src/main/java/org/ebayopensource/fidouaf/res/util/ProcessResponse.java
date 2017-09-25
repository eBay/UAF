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

package org.ebayopensource.fidouaf.res.util;

import org.apache.commons.codec.binary.Base64;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;
import org.ebayopensource.fido.uaf.msg.TransactionAction;
import org.ebayopensource.fido.uaf.msg.TransactionResponse;
import org.ebayopensource.fido.uaf.ops.AuthenticationResponseProcessing;
import org.ebayopensource.fido.uaf.ops.RegistrationResponseProcessing;
import org.ebayopensource.fido.uaf.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.storage.StorageInterface;
import org.ebayopensource.fido.uaf.tlv.AlgAndEncodingEnum;
import org.ebayopensource.fido.uaf.tlv.ByteInputStream;
import sun.misc.IOUtils;

public class ProcessResponse {
	private static final int SERVER_DATA_EXPIRY_IN_MS = 5 * 60 * 1000;

	public AuthenticatorRecord[] processAuthResponse(AuthenticationResponse resp) {
		AuthenticatorRecord[] result;
		try {
			result = new AuthenticationResponseProcessing(
					SERVER_DATA_EXPIRY_IN_MS,
					NotaryImpl.getInstance()
			).verify(
					resp, StorageImpl.getInstance()
			);
		} catch (Exception e) {
			System.out.println("Error: " + e.getMessage());
			result = new AuthenticatorRecord[1];
			result[0] = new AuthenticatorRecord();
			result[0].status = e.getMessage();
		}
		return result;
	}

	public RegistrationRecord[] processRegResponse(RegistrationResponse resp) {
		RegistrationRecord[] result;
		try {
			result = new RegistrationResponseProcessing(
					SERVER_DATA_EXPIRY_IN_MS,
					NotaryImpl.getInstance()
			).processResponse(resp);
		} catch (Exception e) {
			System.out.println("Error: " + e.getMessage());
			result = new RegistrationRecord[1];
			result[0] = new RegistrationRecord();
			result[0].status = e.getMessage();
		}
		return result;
	}

	public boolean processTxResponse(TransactionAction resp, String registrationId) {
		boolean result;
		RegistrationRecord registrationRecord = null;

		try {
			AuthenticatorRecord authRecord = new AuthenticatorRecord();
			authRecord.registrationID = registrationId;
			registrationRecord = getRegistration(authRecord, StorageImpl.getInstance());
			String pubKey = registrationRecord.PublicKey;

			ByteInputStream response = new ByteInputStream(
					Base64.decodeBase64(resp.response));
			ByteInputStream signature = new ByteInputStream(
					Base64.decodeBase64(resp.signature));

			result = NotaryImpl.getInstance().verifySignature(response.readAll(), signature.readAll(), pubKey, AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER);

			return result;

		} catch (Exception e) {
			System.out.println("Error: " + e.getMessage());
		}
		return false;
	}

	private RegistrationRecord getRegistration(AuthenticatorRecord authRecord,
											   StorageInterface serverData) {
		return serverData.readRegistrationRecord(authRecord.toString());

	}
}