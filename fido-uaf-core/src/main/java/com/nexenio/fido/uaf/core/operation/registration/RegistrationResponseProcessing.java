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

package com.nexenio.fido.uaf.core.operation.registration;

import com.google.gson.Gson;
import com.nexenio.fido.uaf.core.crypto.CertificateValidator;
import com.nexenio.fido.uaf.core.crypto.CertificateValidatorImpl;
import com.nexenio.fido.uaf.core.crypto.CertificateVerificationException;
import com.nexenio.fido.uaf.core.crypto.Notary;
import com.nexenio.fido.uaf.core.message.*;
import com.nexenio.fido.uaf.core.operation.*;
import com.nexenio.fido.uaf.core.storage.AuthenticatorRecord;
import com.nexenio.fido.uaf.core.storage.RegistrationRecord;
import com.nexenio.fido.uaf.core.tlv.*;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.nexenio.fido.uaf.core.message.RecordStatus.INVALID_SERVER_DATA_EXPIRED;
import static com.nexenio.fido.uaf.core.message.RecordStatus.INVALID_SERVER_DATA_SIGNATURE_NO_MATCH;

public class RegistrationResponseProcessing {

    private long serverDataExpiryInMs = TimeUnit.MINUTES.toMillis(5);
    private Notary notary = null;
    private Gson gson = new Gson();
    private CertificateValidator certificateValidator;

    public RegistrationResponseProcessing() {
        this.certificateValidator = new CertificateValidatorImpl();
    }

    public RegistrationResponseProcessing(long serverDataExpiryInMs, Notary notary) {
        this.serverDataExpiryInMs = serverDataExpiryInMs;
        this.notary = notary;
        this.certificateValidator = new CertificateValidatorImpl();
    }

    public RegistrationResponseProcessing(long serverDataExpiryInMs, Notary notary, CertificateValidator certificateValidator) {
        this.serverDataExpiryInMs = serverDataExpiryInMs;
        this.notary = notary;
        this.certificateValidator = certificateValidator;
    }

    public RegistrationRecord[] processResponse(RegistrationResponse response) throws AssertionException, VersionException, ServerDataSignatureNotMatchException, ServerDataExpiredException {
        checkAssertions(response);
        RegistrationRecord[] records = new RegistrationRecord[response.getAssertions().length];
        checkVersion(response.getOperationHeader().getProtocolVersion());
        checkServerData(response.getOperationHeader().getServerData(), records);
        FinalChallengeParams fcp = getFcp(response);
        checkFcp(fcp);
        for (int i = 0; i < records.length; i++) {
            records[i] = processAssertions(response.getAssertions()[i], records[i]);
        }
        return records;
    }

    private RegistrationRecord processAssertions(AuthenticatorRegistrationAssertion authenticatorRegistrationAssertion, RegistrationRecord record) {
        if (record == null) {
            record = new RegistrationRecord();
            record.setStatus(RecordStatus.INVALID_USERNAME);
        }
        TlvAssertionParser parser = new TlvAssertionParser();
        try {
            Tags tags = parser.parse(authenticatorRegistrationAssertion.getAssertion());
            try {
                verifyAttestationSignature(tags, record);
            } catch (Exception e) {
                record.setAttestVerifiedStatus("NOT_VERIFIED");
            }
            AuthenticatorRecord authRecord = new AuthenticatorRecord();
            authRecord.setAaid(new String(tags.getTags().get(TagsEnum.TAG_AAID.id).value));
            authRecord.setKeyId(Base64.encodeBase64URLSafeString(tags.getTags().get(TagsEnum.TAG_KEYID.id).value));
            record.setAuthenticator(authRecord);
            record.setPublicKey(Base64.encodeBase64URLSafeString(tags.getTags().get(TagsEnum.TAG_PUB_KEY.id).value));
            record.setAuthenticatorVersion(getAuthenticatorVersion(tags));
            String fc = Base64.encodeBase64URLSafeString(tags.getTags().get(TagsEnum.TAG_FINAL_CHALLENGE.id).value);
            if (record.getStatus() == null) {
                record.setStatus(RecordStatus.SUCCESS);
            }
        } catch (Exception e) {
            record.setStatus(RecordStatus.ASSERTIONS_CHECK_FAILED);
        }
        return record;
    }

    private void verifyAttestationSignature(Tags tags, RegistrationRecord record) throws AttestationVerificationException {
        byte[] certBytes = tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value;
        record.setAttestCert(Base64.encodeBase64URLSafeString(certBytes));

        Tag krd = tags.getTags().get(TagsEnum.TAG_UAFV1_KRD.id);
        Tag signature = tags.getTags().get(TagsEnum.TAG_SIGNATURE.id);

        byte[] signedBytes = new byte[krd.value.length + 4];
        System.arraycopy(UnsignedUtil.encodeInt(krd.id), 0, signedBytes, 0, 2);
        System.arraycopy(UnsignedUtil.encodeInt(krd.length), 0, signedBytes, 2,2);
        System.arraycopy(krd.value, 0, signedBytes, 4, krd.value.length);

        record.setAttestDataToSign(Base64.encodeBase64URLSafeString(signedBytes));
        record.setAttestSignature(Base64.encodeBase64URLSafeString(signature.value));
        record.setAttestVerifiedStatus("FAILED_VALIDATION_ATTEMPT");

        try {
            if (certificateValidator.validate(certBytes, signedBytes, signature.value)) {
                record.setAttestVerifiedStatus("VALID");
            } else {
                record.setAttestVerifiedStatus("NOT_VERIFIED");
            }
        } catch (CertificateVerificationException e) {
            throw new AttestationVerificationException("Certificate validation failed", e);
        }
    }

    private String getAuthenticatorVersion(Tags tags) {
        return "" + tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id).value[0]
                + "."
                + tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id).value[1];
    }

    private void checkAssertions(RegistrationResponse response) throws AssertionException {
        if (response.getAssertions() == null || response.getAssertions().length <= 0) {
            throw new AssertionException("Missing assertions in registration response");
        }
    }

    private FinalChallengeParams getFcp(RegistrationResponse response) {
        String fcp = new String(Base64.decodeBase64(response.getFinalChallengeParams().getBytes()));
        return gson.fromJson(fcp, FinalChallengeParams.class);
    }

    private void checkFcp(FinalChallengeParams fcp) {

    }

    private void checkServerData(String serverDataB64, RegistrationRecord[] records) throws ServerDataSignatureNotMatchException, ServerDataExpiredException {
        if (notary == null) {
            return;
        }
        String serverData = new String(Base64.decodeBase64(serverDataB64));
        String[] tokens = serverData.split("\\.");
        String signature, timeStamp, username, challenge, dataToSign;
        signature = tokens[0];
        timeStamp = tokens[1];
        username = tokens[2];
        challenge = tokens[3];
        dataToSign = timeStamp + "." + username + "." + challenge;

        if (!notary.verify(dataToSign, signature)) {
            setErrorStatus(records, INVALID_SERVER_DATA_SIGNATURE_NO_MATCH);
            throw new ServerDataSignatureNotMatchException("Invalid server data - Signature not match");
        }
        if (isExpired(timeStamp)) {
            setErrorStatus(records, INVALID_SERVER_DATA_EXPIRED);
            throw new ServerDataExpiredException("Invalid server data - Expired data");
        }
        setUsernameAndTimeStamp(username, timeStamp, records);
    }

    private boolean isExpired(String timeStamp) {
        return Long.parseLong(new String(Base64.decodeBase64(timeStamp)))+ serverDataExpiryInMs < System.currentTimeMillis();
    }

    private void setUsernameAndTimeStamp(String username, String timeStamp, RegistrationRecord[] records) {
        if (records == null || records.length == 0) {
            return;
        }
        for (int i = 0; i < records.length; i++) {
            RegistrationRecord rec = records[i];
            if (rec == null) {
                rec = new RegistrationRecord();
            }
            rec.setUserName(new String(Base64.decodeBase64(username)));
            rec.setTimestamp(new String(Base64.decodeBase64(timeStamp)));
            records[i] = rec;
        }
    }

    private void setErrorStatus(RegistrationRecord[] records, RecordStatus status) {
        if (records == null || records.length == 0) {
            return;
        }
        for (RegistrationRecord rec : records) {
            if (rec == null) {
                rec = new RegistrationRecord();
            }
            rec.setStatus(status);
        }
    }

    private void checkVersion(Version upv) throws VersionException {
        if (upv.getMajor() != 1 || upv.getMinor() != 0) {
            throw new VersionException("Invalid version: " + upv.getMajor() + "." + upv.getMinor());
        }
    }

}
