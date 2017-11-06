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

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;

public class NamedCurve {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW 0x01 An ECDSA signature on the
     * NIST secp256r1 curve which MUST have raw R and S buffers, encoded in
     * big-endian order. I.e. [R (32 bytes), S (32 bytes)]
     *
     * @param privateKey  - Private key
     * @param data - Data to sign
     * @return BigInteger[] - [R,S]
     */
    public static BigInteger[] signAndFormatToRS(PrivateKey privateKey, byte[] data) {
        X9ECParameters params = SECNamedCurves.getByName(KeyCodec.CURVE_SECP256_R1);
        ECDomainParameters ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        if (privateKey == null) {
            throw new IllegalStateException("This ECKey does not have the private key necessary for signing.");
        }
        ECDSASigner signer = new ECDSASigner();
        ECPrivateKeyParameters parameters = new ECPrivateKeyParameters(((ECPrivateKey) privateKey).getS(), ecParams);
        signer.init(true, parameters);
        BigInteger[] signature = signer.generateSignature(data);
        return signature;
    }

    public static boolean verify(byte[] encodedPublicKey, byte[] data, BigInteger[] rs) {
        return verifyUsingSecp256k1(encodedPublicKey, data, rs);
    }

    public static boolean verifyUsingSecp256k1(byte[] encodedPublicKey, byte[] data, BigInteger[] rs) {
        ECDSASigner signer = new ECDSASigner();
        X9ECParameters params = SECNamedCurves.getByName(KeyCodec.CURVE_SECP256_R1);
        ECDomainParameters ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        ECPublicKeyParameters parameters = new ECPublicKeyParameters(ecParams.getCurve().decodePoint(encodedPublicKey), ecParams);
        signer.init(false, parameters);
        return signer.verifySignature(data, rs[0].abs(), rs[1].abs());
    }

    public static boolean verify(PublicKey publicKey, byte[] signedData, byte[] encodedSignature) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
        Signature signature = Signature.getInstance(KeyCodec.ALGORITHM_SHA256_ECDSA, BouncyCastleProvider.PROVIDER_NAME);
        signature.initVerify(publicKey);
        signature.update(signedData);
        return signature.verify(encodedSignature);
    }

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(KeyCodec.ALGORITHM_SHA256_ECDSA);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

}