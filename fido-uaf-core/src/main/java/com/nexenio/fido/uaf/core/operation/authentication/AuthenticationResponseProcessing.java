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

package com.nexenio.fido.uaf.core.operation.authentication;

import com.nexenio.fido.uaf.core.crypto.*;
import com.nexenio.fido.uaf.core.message.AuthenticationResponse;
import com.nexenio.fido.uaf.core.message.AuthenticatorSignAssertion;
import com.nexenio.fido.uaf.core.message.FinalChallengeParams;
import com.nexenio.fido.uaf.core.message.Version;
import com.nexenio.fido.uaf.core.operation.*;
import com.nexenio.fido.uaf.core.storage.AuthenticatorRecord;
import com.nexenio.fido.uaf.core.storage.RegistrationRecord;
import com.nexenio.fido.uaf.core.storage.StorageInterface;
import com.nexenio.fido.uaf.core.tlv.*;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class AuthenticationResponseProcessing {

    private long serverDataExpiry;
    private Notary notary;

    public AuthenticationResponseProcessing() {

    }

    public AuthenticationResponseProcessing(long serverDataExpiry, Notary notary) {
        this.serverDataExpiry = serverDataExpiry;
        this.notary = notary;
    }

    public AuthenticatorRecord[] verify(AuthenticationResponse response, StorageInterface serverData) throws VersionException, ServerDataExpiredException, ServerDataSignatureNotMatchException, ServerDataCheckFailedException {
        AuthenticatorRecord[] result = new AuthenticatorRecord[response.getAssertions().length];
        checkVersion(response.getOperationHeader().getProtocolVersion());
        checkServerData(response.getOperationHeader().getServerData(), result);
        FinalChallengeParams fcp = getFcp(response);
        checkFcp(fcp);
        for (int i = 0; i < result.length; i++) {
            result[i] = processAssertions(response.getAssertions()[i], serverData);
        }
        return result;
    }

    private AuthenticatorRecord processAssertions(AuthenticatorSignAssertion authenticatorSignAssertion, StorageInterface storage) {
        TlvAssertionParser parser = new TlvAssertionParser();
        AuthenticatorRecord authRecord = new AuthenticatorRecord();
        RegistrationRecord registrationRecord;

        try {
            Tags tags = parser.parse(authenticatorSignAssertion.getAssertion());
            authRecord.setAaid(new String(tags.getTags().get(TagsEnum.TAG_AAID.id).value));
            authRecord.setKeyId(Base64.encodeBase64URLSafeString(tags.getTags().get(TagsEnum.TAG_KEYID.id).value));
            // authRecord.KeyID = new String(
            // tags.getTags().get(TagsEnum.TAG_KEYID.id).value);
            registrationRecord = getRegistration(authRecord, storage);
            Tag signnedData = tags.getTags().get(TagsEnum.TAG_UAFV1_SIGNED_DATA.id);
            Tag signature = tags.getTags().get(TagsEnum.TAG_SIGNATURE.id);
            Tag info = tags.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id);
            AlgAndEncodingEnum algAndEncoding = getAlgAndEncoding(info);
            String pubKey = registrationRecord.getPublicKey();
            try {
                if (!verifySignature(signnedData, signature, pubKey, algAndEncoding)) {
                    authRecord.setStatus("FAILED_SIGNATURE_NOT_VALID");
                    return authRecord;
                }
            } catch (SignatureVerificationException e) {
                authRecord.setStatus("FAILED_SIGNATURE_VERIFICATION");
                return authRecord;
            }
            authRecord.setUserName(registrationRecord.getUserName());
            authRecord.setDeviceId(registrationRecord.getDeviceId());
            authRecord.setStatus("SUCCESS");
            return authRecord;
        } catch (IOException e) {
            authRecord.setStatus("FAILED_ASSERTION_VERIFICATION");
            return authRecord;
        }
    }

    private AlgAndEncodingEnum getAlgAndEncoding(Tag info) {
        int id = (int) info.value[3] + (int) info.value[4] * 256;
        AlgAndEncodingEnum ret = null;
        AlgAndEncodingEnum[] values = AlgAndEncodingEnum.values();
        for (AlgAndEncodingEnum algAndEncodingEnum : values) {
            if (algAndEncodingEnum.id == id) {
                ret = algAndEncodingEnum;
                break;
            }
        }
        return ret;
    }

    private boolean verifySignature(Tag signedData, Tag signature, String pubKey, AlgAndEncodingEnum algAndEncoding) throws SignatureVerificationException {
        try {
            byte[] dataForSigning = getDataForSigning(signedData);

            // TODO: check if this works
            // return NamedCurve.verify(KeyCodec.getKeyAsRawBytes(pubKey), dataForSigning, Asn1.decodeToBigIntegerArray(signature.value));

            byte[] decodeBase64 = Base64.decodeBase64(pubKey);
            if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_RSASSA_PSS_SHA256_RAW) {
                PublicKey publicKey = KeyCodec.getRSAPublicKey(decodeBase64);
                return RSA.verifyPSS(publicKey, SHA.sha(dataForSigning, SHA.ALGORITHM_SHA_256), signature.value);
            } else if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_RSASSA_PSS_SHA256_DER) {
                PublicKey publicKey = KeyCodec.getRSAPublicKey(new DEROctetString(decodeBase64).getOctets());
                return RSA.verifyPSS(publicKey, SHA.sha(dataForSigning, SHA.ALGORITHM_SHA_256), new DEROctetString(signature.value).getOctets());
            } else {
                if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER) {
                    ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(decodeBase64, KeyCodec.CURVE_SECP256_K1);
                    return NamedCurve.verifyUsingSecp256k1(
                            KeyCodec.getKeyAsRawBytes(decodedPub),
                            SHA.sha(dataForSigning, SHA.ALGORITHM_SHA_256),
                            Asn1.decodeToBigIntegerArray(signature.value));
                }
                if (algAndEncoding == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER) {
                    if (decodeBase64.length > 65) {
                        return NamedCurve.verifyUsingSecp256r1(
                                KeyCodec.getKeyAsRawBytes(pubKey),
                                SHA.sha(dataForSigning, SHA.ALGORITHM_SHA_256),
                                Asn1.decodeToBigIntegerArray(signature.value));
                    } else {
                        ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(decodeBase64, KeyCodec.CURVE_SECP256_R1);
                        return NamedCurve.verifyUsingSecp256r1(
                                KeyCodec.getKeyAsRawBytes(decodedPub),
                                SHA.sha(dataForSigning, SHA.ALGORITHM_SHA_256),
                                Asn1.decodeToBigIntegerArray(signature.value));
                    }
                }
                if (signature.value.length == 64) {
                    ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(decodeBase64, KeyCodec.CURVE_SECP256_R1);
                    return NamedCurve.verifyUsingSecp256r1(KeyCodec.getKeyAsRawBytes(decodedPub),
                            SHA.sha(dataForSigning, SHA.ALGORITHM_SHA_256),
                            Asn1.transformRawSignature(signature.value));
                } else if (65 == decodeBase64.length && AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER == algAndEncoding) {
                    ECPublicKey decodedPub = (ECPublicKey) KeyCodec.getPubKeyFromCurve(decodeBase64, KeyCodec.CURVE_SECP256_R1);
                    return NamedCurve.verifyUsingSecp256r1(
                            KeyCodec.getKeyAsRawBytes(decodedPub),
                            SHA.sha(dataForSigning, SHA.ALGORITHM_SHA_256),
                            Asn1.decodeToBigIntegerArray(signature.value));
                } else {
                    return NamedCurve.verifyUsingSecp256r1(
                            KeyCodec.getKeyAsRawBytes(pubKey),
                            SHA.sha(dataForSigning, SHA.ALGORITHM_SHA_256),
                            Asn1.decodeToBigIntegerArray(signature.value));
                }
            }
        } catch (Exception e) {
            throw new SignatureVerificationException("Signature verification failed", e);
        }
    }

    private byte[] getDataForSigning(Tag signedData) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(encodeInt(signedData.id));
        out.write(encodeInt(signedData.length));
        out.write(signedData.value);
        return out.toByteArray();
    }

    private byte[] encodeInt(int id) {
        byte[] bytes = new byte[2];
        bytes[0] = (byte) (id & 0x00ff);
        bytes[1] = (byte) ((id & 0xff00) >> 8);
        return bytes;
    }

    private RegistrationRecord getRegistration(AuthenticatorRecord authRecord, StorageInterface serverData) {
        return serverData.readRegistrationRecord(authRecord.toString());
    }

    private FinalChallengeParams getFcp(AuthenticationResponse response) {
        // TODO: implement?
        return null;
    }

    private void checkFcp(FinalChallengeParams fcp) {
        // TODO: implement?
    }

    private void checkServerData(String serverDataB64, AuthenticatorRecord[] records) throws ServerDataExpiredException, ServerDataSignatureNotMatchException, ServerDataCheckFailedException {
        if (notary == null) {
            return;
        }
        String serverData = new String(Base64.decodeBase64(serverDataB64));
        String[] tokens = serverData.split("\\.");
        String signature, timeStamp, challenge, dataToSign;
        try {
            signature = tokens[0];
            timeStamp = tokens[1];
            challenge = tokens[2];
            dataToSign = timeStamp + "." + challenge;
            if (!notary.verify(dataToSign, signature)) {
                throw new ServerDataSignatureNotMatchException();
            }
            if (isExpired(timeStamp)) {
                throw new ServerDataExpiredException();
            }
        } catch (ServerDataExpiredException e) {
            setErrorStatus(records, "INVALID_SERVER_DATA_EXPIRED");
            throw new ServerDataExpiredException("Server data expired", e);
        } catch (ServerDataSignatureNotMatchException e) {
            setErrorStatus(records, "INVALID_SERVER_DATA_SIGNATURE_NO_MATCH");
            throw new ServerDataSignatureNotMatchException("Server data signature did not match", e);
        } catch (Exception e) {
            setErrorStatus(records, "INVALID_SERVER_DATA_CHECK_FAILED");
            throw new ServerDataCheckFailedException("Server data check failed", e);
        }

    }

    private boolean isExpired(String timeStamp) {
        return Long.parseLong(new String(Base64.decodeBase64(timeStamp))) + serverDataExpiry < System.currentTimeMillis();
    }

    private void setErrorStatus(AuthenticatorRecord[] records, String status) {
        if (records == null || records.length == 0) {
            return;
        }
        for (AuthenticatorRecord rec : records) {
            if (rec == null) {
                rec = new AuthenticatorRecord();
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
