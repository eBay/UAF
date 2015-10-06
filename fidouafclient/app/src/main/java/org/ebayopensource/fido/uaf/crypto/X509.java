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

import org.spongycastle.jce.X509Principal;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.x509.X509V1CertificateGenerator;
import org.spongycastle.x509.X509V3CertificateGenerator;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

public class X509 {

	private static final Provider BC = new BouncyCastleProvider();
	private static final long VALIDITY_PERIOD = 10 * 24 * 60 * 60 * 1000;

	public static X509Certificate parseDer(byte[] derEncodedCert)
			throws CertificateException {
		return parseDer(new ByteArrayInputStream(derEncodedCert));
	}

	public static X509Certificate parseDer(InputStream is)
			throws CertificateException {
		return (X509Certificate) CertificateFactory.getInstance("X.509", BC)
				.generateCertificate(is);
	}

	public static X509Certificate generateV3Cert(KeyPair pair) {

		X509Certificate cert = null;
		try {
			X509V3CertificateGenerator gen = new X509V3CertificateGenerator();
			gen.setPublicKey(pair.getPublic());
			gen.setSerialNumber(new BigInteger(Long.toString(System
					.currentTimeMillis() / 1000)));
			Hashtable attrs = new Hashtable();
			Vector vOrder = new Vector();
			attrs.put(X509Principal.CN, "npesic@ebay.com");
			vOrder.add(0, X509Principal.CN);
			attrs.put(X509Principal.OU, "self");
			vOrder.add(0, X509Principal.OU);
			attrs.put(X509Principal.O, "eBay, Inc.");
			vOrder.add(0, X509Principal.O);
			attrs.put(X509Principal.L, "San Jose");
			vOrder.add(0, X509Principal.L);
			attrs.put(X509Principal.ST, "California");
			vOrder.add(0, X509Principal.ST);
			attrs.put(X509Principal.C, "USA");
			vOrder.add(0, X509Principal.C);
			gen.setIssuerDN(new X509Principal(vOrder, attrs));
			gen.setSubjectDN(new X509Principal(vOrder, attrs));
			gen.setNotBefore(new Date(System.currentTimeMillis()));
			gen.setNotAfter(new Date(System.currentTimeMillis()
					+ VALIDITY_PERIOD));
			gen.setSignatureAlgorithm("SHA1WithECDSA");
			cert = gen.generate(pair.getPrivate(), "BC");

		} catch (Exception e) {
			System.out.println("Unable to generate a X509Certificate." + e);
		}
		return cert;
	}

	public static X509Certificate generateV1Cert(KeyPair pair)
			throws Exception {

		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();

		certGen.setSerialNumber(BigInteger.valueOf(1));
		certGen.setIssuerDN(new X500Principal("CN=ebay"));
		certGen.setNotBefore(new Date(System.currentTimeMillis()));
		certGen.setNotAfter(new Date(System.currentTimeMillis()
				+ VALIDITY_PERIOD));
		certGen.setSubjectDN(new X500Principal("CN=npesic@ebay.com"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA1WithECDSA");

		return certGen.generate(pair.getPrivate(), "BC");
	}

}
