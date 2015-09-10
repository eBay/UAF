package org.ebayopensource.fido.uaf.tlv;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.ebayopensource.fido.uaf.crypto.Asn1;
import org.ebayopensource.fido.uaf.crypto.BCrypt;
import org.ebayopensource.fido.uaf.crypto.KeyCodec;
import org.ebayopensource.fido.uaf.crypto.NamedCurve;
import org.ebayopensource.fido.uaf.crypto.SHA;
import org.ebayopensource.fido.uaf.crypto.TestData;

public class RegAssertionBuilder {

	private Logger logger = Logger.getLogger(this.getClass().getName());

	public String getAssertions() throws Exception {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_UAFV1_REG_ASSERTION.id));
		value = getRegAssertion();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		String ret = Base64.encodeBase64String(byteout.toByteArray());
		logger.info(" : assertion : " + ret);
		return ret;
	}

	private byte[] getRegAssertion() throws Exception {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_UAFV1_KRD.id));
		value = getSignedData();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		byte[] signedDataValue = byteout.toByteArray();

		byteout.write(encodeInt(TagsEnum.TAG_SIGNATURE.id));
		value = getSignature(signedDataValue);
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		return byteout.toByteArray();
	}

	private byte[] getSignedData() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_AAID.id));
		value = getAAID();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		byteout.write(encodeInt(TagsEnum.TAG_ASSERTION_INFO.id));
		value = new byte[] { 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		byteout.write(encodeInt(TagsEnum.TAG_KEYID.id));
		value = getKeyId();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		
		byteout.write(encodeInt(TagsEnum.TAG_PUB_KEY.id));
		value = getPubKeyId();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		byteout.write(encodeInt(TagsEnum.TAG_AUTHENTICATOR_NONCE.id));
		value = SHA.sha256(BCrypt.gensalt()).getBytes();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		return byteout.toByteArray();
	}

	private byte[] getPubKeyId() throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
		PublicKey pub = KeyCodec.getPubKey(Base64
				.decodeBase64(TestData.TEST_PUB_KEY));
		return KeyCodec.getKeyAsRawBytes((BCECPublicKey)pub);
	}

	private byte[] getSignature(byte[] dataForSigning) throws Exception {

		PublicKey pub = KeyCodec.getPubKey(Base64
				.decodeBase64(TestData.TEST_PUB_KEY));
		PrivateKey priv = KeyCodec.getPrivKey(Base64
				.decodeBase64(TestData.TEST_PRIV_KEY));

		logger.info(" : dataForSigning : "
				+ Base64.encodeBase64URLSafeString(dataForSigning));

		BigInteger[] signatureGen = NamedCurve.signAndFromatToRS(priv,
				dataForSigning);

		boolean verify = NamedCurve.verify(
				KeyCodec.getKeyAsRawBytes(TestData.TEST_PUB_KEY),
				dataForSigning,
				Asn1.decodeToBigIntegerArray(Asn1.getEncoded(signatureGen)));
		if (!verify) {
			throw new RuntimeException("Signatire match fail");
		}
		byte[] ret = Asn1.getEncoded(signatureGen);
		logger.info(" : signature : " + Base64.encodeBase64URLSafeString(ret));

		return ret;
	}

	private byte[] getKeyId() throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = "ebay-test-key".getBytes();
		byteout.write(value);
		return byteout.toByteArray();
	}

	private byte[] getAAID() throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = "EBAY#0001".getBytes();
		byteout.write(value);
		return byteout.toByteArray();
	}

	private byte[] encodeInt(int id) {

		byte[] bytes = new byte[2];
		bytes[0] = (byte) (id & 0x00ff);
		bytes[1] = (byte) ((id & 0xff00) >> 8);
		return bytes;
	}

	
	public static void main(String[] args) throws Exception {
		RegAssertionBuilder builder = new RegAssertionBuilder();
		String assertions = builder.getAssertions();
		TlvAssertionParser parser = new TlvAssertionParser();
		Tags tags = parser.parse(assertions);
		String AAID = new String(tags.getTags().get(
				TagsEnum.TAG_AAID.id).value);
		String KeyID = new String(tags.getTags()
				.get(TagsEnum.TAG_KEYID.id).value);
		System.out.println (AAID);
		System.out.println (KeyID);
		
	}
}
