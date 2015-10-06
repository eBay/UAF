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

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DERSequenceGenerator;
import org.spongycastle.asn1.DLSequence;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.Arrays;

public class Asn1 {
  
    static {
		Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
	}
 
  	/**
  	 * DER - From Big Integer rs to byte[]
  	 * UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER 0x06
  	 * DER [ITU-X690-2008] encoded ECDSA signature [RFC5480] on the secp256k1 curve.
  	 * I.e. a DER encoded SEQUENCE { r INTEGER, s INTEGER }
  	 * @param signature
  	 * @return
  	 * @throws IOException
  	 */
  	public static byte[] getEncoded(BigInteger[] sigs)
			throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream(72);
		DERSequenceGenerator seq = new DERSequenceGenerator(bos);
		seq.addObject(new ASN1Integer(sigs[0]));
		seq.addObject(new ASN1Integer(sigs[1]));
		seq.close();
		return bos.toByteArray();
	}

  	/**
  	 * DER - From byte[] to Big Integer rs
  	 * UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_DER 0x06
  	 * DER [ITU-X690-2008] encoded ECDSA signature [RFC5480] on the secp256k1 curve.
  	 * I.e. a DER encoded SEQUENCE { r INTEGER, s INTEGER }
  	 * @param signature
  	 * @return
  	 * @throws IOException
  	 */
	public static BigInteger[] decodeToBigIntegerArray(byte[] signature) throws IOException {
		ASN1InputStream decoder = new ASN1InputStream(signature);
		DLSequence seq = (DLSequence) decoder.readObject();
		ASN1Integer r = (ASN1Integer) seq.getObjectAt(0);
		ASN1Integer s = (ASN1Integer) seq.getObjectAt(1);
		decoder.close();
		BigInteger[] ret = new BigInteger[2];
		ret[0] = r.getPositiveValue();
		ret[1] = s.getPositiveValue();
		return ret;
	}
	
	/**
	 * From Big Integers r,s to byte[]
	 * UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW 0x05
	 * An ECDSA signature on the secp256k1 curve which must have raw R and S buffers, encoded in big-endian order.
	 * I.e.[R (32 bytes), S (32 bytes)]
	 * @param rs
	 * @return
	 * @throws IOException
	 */
	public static byte[] toRawSignatureBytes (BigInteger[] rs) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream(64);
		byte[] r = toUnsignedByteArray(rs[0]);
		byte[] s = toUnsignedByteArray(rs[1]);
		bos.write(r);
		bos.write(s);
		return bos.toByteArray();
	}
	
	/**
	 * From byte[] to Big Integers r,s
	 * UAF_ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW 0x05
	 * An ECDSA signature on the secp256k1 curve which must have raw R and S buffers, encoded in big-endian order.
	 * I.e.[R (32 bytes), S (32 bytes)]
	 * @param raw
	 * @return
	 * @throws IOException
	 */
	public static BigInteger[] transformRawSignature (byte[] raw) throws IOException {
		BigInteger[] output = new BigInteger[2];
		
		output[0] = new BigInteger(1, Arrays.copyOfRange(raw, 0, 32));
		output[1] = new BigInteger(1, Arrays.copyOfRange(raw, 32, 64));
		return output;
	}
	
	
	public static byte[] toUnsignedByteArray(BigInteger bi){
		  byte[] ba = bi.toByteArray();
		  if(ba[0] != 0){
		    return ba;
		  }
		  else
		  {
		    byte[] ba2 = new byte[ba.length - 1];
		    System.arraycopy(ba, 1, ba2, 0, ba.length - 1);
		    return ba2;
		  }
		}
}
