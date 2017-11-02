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

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RSA {

    private static final Provider BC = new BouncyCastleProvider();

    public static boolean verify(X509Certificate x509Certificate,
                                 byte[] signedDate, byte[] sig) throws SignatureException,
            InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance("SHA256withRSA", BC);
        signature.initVerify(x509Certificate);
        signature.update(signedDate);
        signature.update(SHA.sha(signedDate, "SHA-256"));
        return signature.verify(sig);
    }

    public static byte[] sign(PrivateKey privateKey,
                              byte[] signedData) throws SignatureException,
            InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance("SHA256withRSA", BC);
        signature.initSign(privateKey);
        signature.update(signedData);
        return signature.sign();
    }

    public static byte[] signPSS(PrivateKey privateKey,
                                 byte[] signedData) throws SignatureException,
            InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance("SHA256withRSA/PSS", BC);
        signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
                new MGF1ParameterSpec("SHA-256"), 32, 1));
        signature.initSign(privateKey);
        signature.update(signedData);
        return signature.sign();
    }

    public static boolean verifyPSS(PublicKey publicKey,
                                    byte[] signedData, byte[] sig) throws SignatureException,
            InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        Signature signature = Signature.getInstance("SHA256withRSA/PSS", BC);
        signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1",
                new MGF1ParameterSpec("SHA-256"), 32, 1));
        signature.initVerify(publicKey);
        signature.update(signedData);
        return signature.verify(sig);
    }

}
