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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class X509 {

    public static final String TYPE_X509 = "X.509";

    private static final Provider BC = ProviderUtil.getBouncyCastleProvider();

    public static X509Certificate parseDer(byte[] derEncodedCert) throws CertificateException {
        return parseDer(new ByteArrayInputStream(derEncodedCert));
    }

    public static X509Certificate parseDer(InputStream is) throws CertificateException {
        return (X509Certificate) CertificateFactory.getInstance(TYPE_X509, BC).generateCertificate(is);
    }

}
