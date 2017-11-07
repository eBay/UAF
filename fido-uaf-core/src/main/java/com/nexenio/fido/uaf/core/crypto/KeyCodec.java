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

import com.nexenio.fido.uaf.core.util.ProviderUtil;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.*;

public class KeyCodec {

    public static final String ALGORITHM_ECDSA = "ECDSA";

    public static final String CURVE_SECP256_R1 = "secp256r1";

    public static final int KEY_SIZE = 2048;

    static {
        ProviderUtil.addBouncyCastleProvider();
    }

    public static KeyPair getKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(CURVE_SECP256_R1);
        KeyPairGenerator g = KeyPairGenerator.getInstance(ALGORITHM_ECDSA, BouncyCastleProvider.PROVIDER_NAME);
        g.initialize(ecGenSpec, new SecureRandom());
        return g.generateKeyPair();
    }

    public static KeyPair getRSAKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator g = KeyPairGenerator.getInstance(RSA.ALGORITHM_RSA, BouncyCastleProvider.PROVIDER_NAME);
        g.initialize(KEY_SIZE);
        return g.generateKeyPair();
    }

    static public RSAKeyParameters generatePrivateKeyParameter(RSAPrivateKey privateKey) {
        if (privateKey instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey k = (RSAPrivateCrtKey) privateKey;
            return new RSAPrivateCrtKeyParameters(k.getModulus(),
                    k.getPublicExponent(), k.getPrivateExponent(),
                    k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(),
                    k.getPrimeExponentQ(), k.getCrtCoefficient());
        } else {
            RSAPrivateKey k = privateKey;
            return new RSAKeyParameters(true, k.getModulus(), k.getPrivateExponent());
        }
    }

    public static byte[] getKeyAsRawBytes(String base64EncodedPubKey) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        return getKeyAsRawBytes((BCECPublicKey) getPubKey(Base64.decodeBase64(base64EncodedPubKey)));
    }

    /**
     * UAF_ALG_KEY_ECC_X962_RAW 0x100 Raw ANSI X9.62 formatted Elliptic Curve
     * public key [SEC1].
     * <p>
     * I.e. [0x04, X (32 bytes), Y (32 bytes)]. Where the byte 0x04 denotes the
     * uncompressed point compression method.
     *
     * @param publicKey - Public Key
     * @return bytes
     * @throws IOException
     */
    public static byte[] getKeyAsRawBytes(BCECPublicKey publicKey) throws IOException {
        byte[] raw;
        ByteArrayOutputStream bos = new ByteArrayOutputStream(65);

        bos.write(0x04);
        bos.write(publicKey.getQ().getXCoord().getEncoded());
        bos.write(publicKey.getQ().getYCoord().getEncoded());
        raw = bos.toByteArray();
        return raw;
    }

    @SuppressWarnings("deprecation")
    public static byte[] getKeyAsRawBytes(org.bouncycastle.jce.interfaces.ECPublicKey publicKey) throws IOException {
        byte[] raw;
        ByteArrayOutputStream bos = new ByteArrayOutputStream(65);

        bos.write(0x04);
        bos.write(asUnsignedByteArray(publicKey.getQ().getX().toBigInteger()));
        bos.write(asUnsignedByteArray(publicKey.getQ().getY().toBigInteger()));
        raw = bos.toByteArray();
        return raw;
    }

    /**
     * Return the passed in value as an unsigned byte array.
     *
     * @param value value to be converted.
     * @return a byte array without a leading zero byte if present in the signed
     * encoding.
     */
    public static byte[] asUnsignedByteArray(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            return tmp;
        }
        return bytes;
    }

    public static PublicKey getPubKey(byte[] bytes) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM_ECDSA, BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePublic(new X509EncodedKeySpec(bytes));
    }

    public static PrivateKey getPrivKey(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM_ECDSA, BouncyCastleProvider.PROVIDER_NAME);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    public static KeyPair generate() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        SecureRandom random = new SecureRandom();
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_SECP256_R1);
        KeyPairGenerator g = KeyPairGenerator.getInstance(ALGORITHM_ECDSA);
        g.initialize(ecSpec, random);
        return g.generateKeyPair();
    }

    /**
     * Decode based on X, Y 32 byte integers
     *
     * @param pubKey
     * @param curveName - Example secp256r1
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static PublicKey getPubKeyFromCurve(byte[] pubKey, String curveName) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM_ECDSA, new BouncyCastleProvider());
        ECNamedCurveSpec params = new ECNamedCurveSpec(curveName, spec.getCurve(), spec.getG(), spec.getN());
        ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
        return pk;
    }

    public static PublicKey getRSAPublicKey(byte[] encodedPubKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKey pubKey8 = RSAPublicKey.getInstance(encodedPubKey);
        SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(new RSAKeyParameters(false, pubKey8.getModulus(), pubKey8.getPublicExponent()));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(info.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance(RSA.ALGORITHM_RSA);
        return keyFactory.generatePublic(spec);
    }

    /**
     * Decode based on d - 32 byte integer
     *
     * @param privKey
     * @param curveName - Example secp256r1
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static PrivateKey getPrivKeyFromCurve(byte[] privKey, String curveName) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM_ECDSA, new BouncyCastleProvider());
        ECNamedCurveSpec params = new ECNamedCurveSpec(curveName, spec.getCurve(), spec.getG(), spec.getN());
        ECPrivateKeySpec priKey = new ECPrivateKeySpec(new BigInteger(privKey), params);
        return kf.generatePrivate(priKey);
    }

}
