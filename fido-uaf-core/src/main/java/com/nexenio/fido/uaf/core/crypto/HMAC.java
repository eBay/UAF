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

package com.nexenio.fido.uaf.core.crypto;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class HMAC {

    public static final String ALGORITHM_HMAC_SHA265 = "HmacSHA256";

    public static byte[] sign(String toSign, String secret) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException {
        validateParameters(toSign, secret);
        PBEKeySpec keySpec = new PBEKeySpec(secret.toCharArray());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey key = keyFactory.generateSecret(keySpec);
        Mac mac = Mac.getInstance(ALGORITHM_HMAC_SHA265);
        mac.init(key);
        byte[] text = toSign.getBytes(StandardCharsets.UTF_8);
        return mac.doFinal(text);
    }

    private static void validateParameters(String toSign, String secret) throws InvalidParameterException {
        if (toSign == null || toSign.isEmpty()) {
            throw new InvalidParameterException("Empty string for signing");
        }
        if (secret == null || secret.isEmpty()) {
            throw new InvalidParameterException("Empty secret for signing");
        }
    }
}
