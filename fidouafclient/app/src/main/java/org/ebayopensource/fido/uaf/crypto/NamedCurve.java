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

package org.ebayopensource.fido.uaf.crypto;

import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.signers.ECDSASigner;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;

public class NamedCurve {
	
	private static final Provider BC = new BouncyCastleProvider();
  
   	/**
	 * UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW 0x01
	 * An ECDSA signature on the NIST secp256r1 curve which MUST have raw R and S buffers, encoded in big-endian order.
	 * I.e. [R (32 bytes), S (32 bytes)]
	 * 
	 * @param priv - Private key
	 * @param input - Data to sign 
	 * @return BigInteger[] - [R,S]
	 */
	public static BigInteger[] signAndFromatToRS(PrivateKey priv, byte[] input) {
		X9ECParameters params = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters ecParams = new ECDomainParameters(params.getCurve(),
				params.getG(), params.getN(), params.getH());
		if (priv == null)
			throw new IllegalStateException(
					"This ECKey does not have the private key necessary for signing.");
		ECDSASigner signer = new ECDSASigner();
		ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(
				((ECPrivateKey) priv).getS(), ecParams);
		signer.init(true, privKey);
		BigInteger[] sigs = signer.generateSignature(input);
		return sigs;
	}
  
  
  public static boolean verify(byte[] pub, byte[] dataForSigning,
			BigInteger[] rs) {
		ECDSASigner signer = new ECDSASigner();
		X9ECParameters params = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters ecParams = new ECDomainParameters(params.getCurve(),
				params.getG(), params.getN(), params.getH());
		ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(ecParams
				.getCurve().decodePoint(pub), ecParams);
		signer.init(false, pubKeyParams);

		return signer.verifySignature(dataForSigning, rs[0].abs(), rs[1].abs());
	}
  
	public static boolean verify(PublicKey pub, byte[] dataForSigning,
			byte[] signature) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, SignatureException,
			UnsupportedEncodingException {
		Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
		ecdsaVerify.initVerify(pub);
		ecdsaVerify.update(dataForSigning);
		return ecdsaVerify.verify(signature);
	}
	
    public static boolean checkSignature(PublicKey publicKey, byte[] signedBytes, byte[] signature) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
            Signature ecdsaSignature = Signature.getInstance("SHA256withECDSA", BC);
            ecdsaSignature.initVerify(publicKey);
            ecdsaSignature.update(signedBytes);
            return ecdsaSignature.verify(signature);
    }
    
    public static byte[] sign(byte[] signedData, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(signedData);
        return signature.sign();
    }

}