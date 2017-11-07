package com.nexenio.fido.uaf.core.crypto;

import com.nexenio.fido.uaf.core.tlv.*;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class X509Test {

    private static final long VALIDITY_PERIOD = TimeUnit.DAYS.toMillis(10);

    private Logger logger = Logger.getLogger(this.getClass().getName());
    private TlvAssertionParser assertionParser = new TlvAssertionParser();

    public static X509Certificate generateV1Cert(KeyPair pair) throws Exception {
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(1));
        certGen.setIssuerDN(new X500Principal("CN=ebay"));
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
        certGen.setSubjectDN(new X500Principal("CN=npesic@ebay.com"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA1WithECDSA");
        return certGen.generate(pair.getPrivate(), "BC");
    }

    public static X509Certificate generateV3Cert(KeyPair pair) {
        X509Certificate cert = null;
        try {
            X509V3CertificateGenerator gen = new X509V3CertificateGenerator();
            gen.setPublicKey(pair.getPublic());
            gen.setSerialNumber(new BigInteger(Long.toString(System.currentTimeMillis() / 1000)));
            Hashtable<ASN1ObjectIdentifier, String> attrs = new Hashtable<ASN1ObjectIdentifier, String>();
            Vector<ASN1ObjectIdentifier> vOrder = new Vector<ASN1ObjectIdentifier>();
            attrs.put(X509Principal.E, "npesic@ebay.com");
            vOrder.add(0, X509Principal.E);
            attrs.put(X509Principal.CN, "eBay, Inc");
            vOrder.add(0, X509Principal.CN);
            attrs.put(X509Principal.OU, "TNS");
            vOrder.add(0, X509Principal.OU);
            attrs.put(X509Principal.O, "eBay, Inc.");
            vOrder.add(0, X509Principal.O);
            attrs.put(X509Principal.L, "San Jose");
            vOrder.add(0, X509Principal.L);
            attrs.put(X509Principal.ST, "CA");
            vOrder.add(0, X509Principal.ST);
            attrs.put(X509Principal.C, "US");
            vOrder.add(0, X509Principal.C);
            gen.setIssuerDN(new X509Principal(vOrder, attrs));
            gen.setSubjectDN(new X509Principal(vOrder, attrs));
            gen.setNotBefore(new Date(System.currentTimeMillis()));
            gen.setNotAfter(new Date(System.currentTimeMillis() + VALIDITY_PERIOD));
            gen.setSignatureAlgorithm("SHA1WithECDSA");
            cert = gen.generate(pair.getPrivate(), "BC");
        } catch (Exception e) {
            System.out.println("Unable to generate a X509Certificate." + e);
        }
        return cert;
    }

    @Test
    public void base() throws IOException, CertificateException {
        Tags tags = assertionParser.parse(TestAssertions.getExampleRegAssertions());
        X509Certificate x509Certificate = X509.parseDer(tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value);
        assertNotNull(x509Certificate);
        logger.info("From spec example: " + x509Certificate.toString());
    }

    @Test
    public void certFromMetadataExample() throws IOException, CertificateException {
        Tags tags = assertionParser.parse(TestAssertions.getExampleRegAssertions());
        X509Certificate x509Certificate = X509.parseDer(Base64.decodeBase64(getCertFromTestMetadata()));
        assertNotNull(x509Certificate);
        logger.info("Base64 of DER encoding : " + Base64.encodeBase64URLSafeString(x509Certificate.getEncoded()));
        logger.info("From spec example: " + x509Certificate.toString());
    }

    @Test
    public void certFromAssertionExample() throws IOException, CertificateException {
        Tags tags = assertionParser.parse(TestAssertions.getExampleRegAssertions());
        X509Certificate x509Certificate = X509.parseDer(tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value);
        assertNotNull(x509Certificate);
        logger.info("Base64 of DER encoding : " + Base64.encodeBase64URLSafeString(x509Certificate.getEncoded()));
        logger.info("From spec example: " + x509Certificate.toString());
    }

    @Test
    public void certFromRaonExample() throws IOException, CertificateException {
        Tags tags = assertionParser.parse(TestAssertions.regRequestAssertionsFromRaon());
        X509Certificate x509Certificate = X509.parseDer(tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value);
        assertNotNull(x509Certificate);
        logger.info("Base64 of DER encoding : " + Base64.encodeBase64URLSafeString(x509Certificate.getEncoded()));
        logger.info("From spec example: " + x509Certificate.toString());
    }

    private String getCertFromTestMetadata() {
        return "MIICCzCCAbCgAwIBAgIJALJQxwQdHZAUMAoGCCqGSM49BAMCMGMxCzAJBgNVBAYTAktSMRQwEgYDVQQIDAtHeWVvbmdnaS1EbzEUMBIGA1UEBwwLWW9uZ2luLUNpdHkxEzARBgNVBAoMClNhbXN1bmcgRFMxEzARBgNVBAMMClNhbXN1bmcgRFMwHhcNMTUwOTIxMDcxMzQ3WhcNNDMwMjA2MDcxMzQ3WjBjMQswCQYDVQQGEwJLUjEUMBIGA1UECAwLR3llb25nZ2ktRG8xFDASBgNVBAcMC1lvbmdpbi1DaXR5MRMwEQYDVQQKDApTYW1zdW5nIERTMRMwEQYDVQQDDApTYW1zdW5nIERTMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE+Glq/mvof8RRXd0tUIMx+57kUZmFLoIbiVfDDUpB2jTi05nPqFjJEd6FEn315HLLas6/nHoL/NxuRkCSUygzKKNQME4wHQYDVR0OBBYEFJ20gSze9taj3fML7DkNQ8MDKs03MB8GA1UdIwQYMBaAFJ20gSze9taj3fML7DkNQ8MDKs03MAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhALfH//9t4xrte3ZuxtdCfRRBoE4Z/ijX50k+dpJldZUkAiEAj5/Nt9UsdS7ccQhpYJw0NbilQ8cyS/U21bLRILFGnzU=";
    }

    @Test
    public void signatureValidation() throws Exception {
        Tags tags = assertionParser.parse(TestAssertions.getExampleRegAssertions());
        X509Certificate x509Certificate = X509.parseDer(tags.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id).value);
        assertNotNull(x509Certificate);

        Tag krd = tags.getTags().get(TagsEnum.TAG_UAFV1_KRD.id);
        Tag signature = tags.getTags().get(TagsEnum.TAG_SIGNATURE.id);

        byte[] signedBytes = new byte[krd.value.length + 4];
        System.arraycopy(UnsignedUtil.encodeInt(krd.id), 0, signedBytes, 0, 2);
        System.arraycopy(UnsignedUtil.encodeInt(krd.length), 0, signedBytes, 2, 2);
        System.arraycopy(krd.value, 0, signedBytes, 4, krd.value.length);

        KeyPair keyPair = KeyCodec.getKeyPair();

        byte[] signature2 = NamedCurve.sign(signedBytes, keyPair.getPrivate());
        BigInteger[] signAndFromatToRS = NamedCurve.signAndFormatToRS(keyPair.getPrivate(), signedBytes);
        byte[] rawSignatureBytes = Asn1.toRawSignatureBytes(signAndFromatToRS);

        //	Example: Using generated keys with signature SHA256withECSDA
        assertTrue(NamedCurve.verify(keyPair.getPublic(), signedBytes, signature2));

        //assertTrue( NamedCurve.verify(x509Certificate.getPublicKey(), signedBytes, signature.value));
        BigInteger[] transformRawSignature = Asn1.transformRawSignature(rawSignatureBytes);

        // Example: Key pair generated. Sig calculated as RS, then transformed to raw byte[64]. Pub key as 0x04 X Y
        assertTrue(NamedCurve.verify(KeyCodec.getKeyAsRawBytes((ECPublicKey) keyPair.getPublic()), signedBytes, transformRawSignature));


        /**
         * Example:
         * Pub Key - From X509 Cert
         * Method: verify - using ECDSASigner - Needs pub key in form [0x04, X (32 bytes), Y (32 bytes)]
         * Signed data - ECDSASigner - Needs data to be SHA256 first
         * Signature: ECDSASigner - Needs raw signature from byte[64] to RS Big Integer representation
         *
         */
        assertTrue(NamedCurve.verify(KeyCodec.getKeyAsRawBytes((ECPublicKey) x509Certificate.getPublicKey()), SHA.sha(signedBytes, "SHA256"), Asn1.transformRawSignature(signature.value)));


        /**
         * Example:
         * Pub Key - From X509 Cert
         * Method: verify - using SHA256withECDSA
         * Signature: Method verify needs signature in DER encoded SEQUENCE { r INTEGER, s INTEGER }
         * Signature: Was presented in raw byte[64] format => transform to RS format => transform to DER encoded SEQUENCE { r INTEGER, s INTEGER }
         */
        assertTrue(NamedCurve.verify(x509Certificate.getPublicKey(), signedBytes, Asn1.getEncoded(Asn1.transformRawSignature(signature.value))));
    }

    @Test
    public void certV1Creation() throws Exception {

        KeyPair keyPair = KeyCodec.generate();
        X509Certificate x509Certificate = generateV1Cert(keyPair);
        assertNotNull(x509Certificate);
        logger.info("V1 : " + x509Certificate.toString());
        logger.info("Base64 of DER encoding : " + Base64.encodeBase64URLSafeString(x509Certificate.getEncoded()));
        logger.info("Pub : " + Base64.encodeBase64URLSafeString(keyPair.getPublic().getEncoded()));
        logger.info("Priv : " + Base64.encodeBase64URLSafeString(keyPair.getPrivate().getEncoded()));
    }

    @Test
    public void certV3Creation() throws Exception {

        KeyPair keyPair = KeyCodec.generate();
        X509Certificate x509Certificate = generateV3Cert(keyPair);
        assertNotNull(x509Certificate);
        logger.info("Base64 of DER encoding : " + Base64.encodeBase64String(x509Certificate.getEncoded()));
        logger.info("Pub : " + Base64.encodeBase64URLSafeString(keyPair.getPublic().getEncoded()));
        logger.info("Priv : " + Base64.encodeBase64URLSafeString(keyPair.getPrivate().getEncoded()));
        logger.info("V3 : " + x509Certificate.toString());
    }
}
