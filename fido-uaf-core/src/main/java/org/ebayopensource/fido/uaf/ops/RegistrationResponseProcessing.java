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

import static org.ebayopensource.fido.uaf.msg.RecordStatus.INVALID_SERVER_DATA_EXPIRED;
import static org.ebayopensource.fido.uaf.msg.RecordStatus.INVALID_SERVER_DATA_SIGNATURE_NO_MATCH;

import com.google.gson.Gson;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.codec.binary.Base64;
import org.ebayopensource.fido.uaf.crypto.CertificateValidator;
import org.ebayopensource.fido.uaf.crypto.CertificateValidatorImpl;
import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.msg.AuthenticatorRegistrationAssertion;
import org.ebayopensource.fido.uaf.msg.FinalChallengeParams;
import org.ebayopensource.fido.uaf.msg.RecordStatus;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;
import org.ebayopensource.fido.uaf.msg.Version;
import org.ebayopensource.fido.uaf.ops.exception.AssertionException;
import org.ebayopensource.fido.uaf.ops.exception.ServerDataExpiredException;
import org.ebayopensource.fido.uaf.ops.exception.ServerDataSignatureNotMatchException;
import org.ebayopensource.fido.uaf.ops.exception.VersionException;
import org.ebayopensource.fido.uaf.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.tlv.Tag;
import org.ebayopensource.fido.uaf.tlv.Tags;
import org.ebayopensource.fido.uaf.tlv.TagsEnum;
import org.ebayopensource.fido.uaf.tlv.TlvAssertionParser;
import org.ebayopensource.fido.uaf.tlv.UnsignedUtil;

public class RegistrationResponseProcessing {

    private Logger logger = Logger.getLogger(this.getClass().getName());
    private long serverDataExpiryInMs = 5 * 60 * 1000;
    private Notary notary = null;
    private Gson gson = new Gson();
    private CertificateValidator certificateValidator;

    public RegistrationResponseProcessing() {
        this.certificateValidator = new CertificateValidatorImpl();
    }

    public RegistrationResponseProcessing(long serverDataExpiryInMs,
                                          Notary notary) {
        this.serverDataExpiryInMs = serverDataExpiryInMs;
        this.notary = notary;
        this.certificateValidator = new CertificateValidatorImpl();
    }

    public RegistrationResponseProcessing(long serverDataExpiryInMs,
                                          Notary notary, CertificateValidator certificateValidator) {
        this.serverDataExpiryInMs = serverDataExpiryInMs;
        this.notary = notary;
        this.certificateValidator = certificateValidator;
    }

    public RegistrationRecord[] processResponse(RegistrationResponse response)
        throws AssertionException, VersionException, ServerDataSignatureNotMatchException, ServerDataExpiredException {

        checkAssertions(response);
        RegistrationRecord[] records = new RegistrationRecord[response.getAssertions().length];

        checkVersion(response.getHeader().getUpv());
        checkServerData(response.getHeader().getServerData(), records);
        FinalChallengeParams fcp = getFcp(response);
        checkFcp(fcp);
        for (int i = 0; i < records.length; i++) {
            records[i] = processAssertions(response.getAssertions()[i], records[i]);
        }

        return records;
    }

    private RegistrationRecord processAssertions(
        AuthenticatorRegistrationAssertion authenticatorRegistrationAssertion,
        RegistrationRecord record) {
        if (record == null) {
            record = new RegistrationRecord();
            record.setStatus(RecordStatus.INVALID_USERNAME);
        }
        TlvAssertionParser parser = new TlvAssertionParser();
        try {
            Tags tags = parser
                .parse(authenticatorRegistrationAssertion.getAssertion());
            try {
                verifyAttestationSignature(tags, record);
            } catch (Exception e) {
                record.setAttestVerifiedStatus("NOT_VERIFIED");
            }

            AuthenticatorRecord authRecord = new AuthenticatorRecord();
            authRecord.setAaid(new String(tags.getTags().get(
                TagsEnum.TAG_AAID.id).value));
            authRecord.setKeyID(Base64.encodeBase64URLSafeString(tags.getTags().get(
                TagsEnum.TAG_KEYID.id).value));
            record.setAuthenticator(authRecord);
            record.setPublicKey(Base64.encodeBase64URLSafeString(tags.getTags()
                                                                     .get(TagsEnum.TAG_PUB_KEY.id).value));
            record.setAuthenticatorVersion(getAuthenticatorVersion(tags));
            String fc = Base64.encodeBase64URLSafeString(tags.getTags().get(
                TagsEnum.TAG_FINAL_CHALLENGE.id).value);
            logger.log(Level.INFO, "FC: " + fc);
            if (record.getStatus() == null) {
                record.setStatus(RecordStatus.SUCCESS);
            }
        } catch (Exception e) {
            record.setStatus(RecordStatus.ASSERTIONS_CHECK_FAILED);
            logger.log(Level.INFO, "Fail to parse assertion: "
                + authenticatorRegistrationAssertion.getAssertion(), e);
        }
        return record;
    }

    private void verifyAttestationSignature(Tags tags, RegistrationRecord record)
        throws NoSuchAlgorithmException, IOException, Exception {
        byte[] certBytes = tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value;
        record.setAttestCert(Base64.encodeBase64URLSafeString(certBytes));

        Tag krd = tags.getTags().get(TagsEnum.TAG_UAFV1_KRD.id);
        Tag signature = tags.getTags().get(TagsEnum.TAG_SIGNATURE.id);

        byte[] signedBytes = new byte[krd.value.length + 4];
        System.arraycopy(UnsignedUtil.encodeInt(krd.id), 0, signedBytes, 0, 2);
        System.arraycopy(UnsignedUtil.encodeInt(krd.length), 0, signedBytes, 2,
                         2);
        System.arraycopy(krd.value, 0, signedBytes, 4, krd.value.length);

        record.setAttestDataToSign(Base64.encodeBase64URLSafeString(signedBytes));
        record.setAttestSignature(Base64
                                      .encodeBase64URLSafeString(signature.value));
        record.setAttestVerifiedStatus("FAILED_VALIDATION_ATTEMPT");

        if (certificateValidator.validate(certBytes, signedBytes,
                                          signature.value)) {
            record.setAttestVerifiedStatus("VALID");
        } else {
            record.setAttestVerifiedStatus("NOT_VERIFIED");
        }
    }

    private String getAuthenticatorVersion(Tags tags) {
        return "" + tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id).value[0]
            + "."
            + tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id).value[1];
    }

    private void checkAssertions(RegistrationResponse response) throws AssertionException {
        if (response.getAssertions() == null && response.getAssertions().length <= 0) {
            throw new AssertionException("Missing assertions in registration response");
        }
    }

    private FinalChallengeParams getFcp(RegistrationResponse response) {
        String fcp = new String(Base64.decodeBase64(response.getFcParams()
                                                            .getBytes()));
        return gson.fromJson(fcp, FinalChallengeParams.class);
    }

    private void checkServerData(String serverDataB64, RegistrationRecord[] records)
        throws ServerDataSignatureNotMatchException, ServerDataExpiredException {

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

        if (! notary.verify(dataToSign, signature)) {
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
        return Long.parseLong(new String(Base64.decodeBase64(timeStamp)))
            + serverDataExpiryInMs < System.currentTimeMillis();
    }

    private void setUsernameAndTimeStamp(String username, String timeStamp,
                                         RegistrationRecord[] records) {
        if (records == null || records.length == 0) {
            return;
        }
        for (int i = 0; i < records.length; i++) {
            RegistrationRecord rec = records[i];
            if (rec == null) {
                rec = new RegistrationRecord();
            }
            rec.setUsername(new String(Base64.decodeBase64(username)));
            rec.setTimeStamp(new String(Base64.decodeBase64(timeStamp)));
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

    private void checkFcp(FinalChallengeParams fcp) {
        // TODO Auto-generated method stub

    }

}
