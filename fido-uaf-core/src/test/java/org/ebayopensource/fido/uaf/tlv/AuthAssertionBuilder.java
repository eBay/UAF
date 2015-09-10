package org.ebayopensource.fido.uaf.tlv;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;
import org.ebayopensource.fido.uaf.crypto.Asn1;
import org.ebayopensource.fido.uaf.crypto.BCrypt;
import org.ebayopensource.fido.uaf.crypto.KeyCodec;
import org.ebayopensource.fido.uaf.crypto.NamedCurve;
import org.ebayopensource.fido.uaf.crypto.SHA;
import org.ebayopensource.fido.uaf.crypto.TestData;

public class AuthAssertionBuilder {

	private Logger logger = Logger.getLogger(this.getClass().getName());

	public String getAssertions() throws Exception {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_UAFV1_AUTH_ASSERTION.id));
		value = getAuthAssertion();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		String ret = Base64.encodeBase64URLSafeString(byteout.toByteArray());
		logger.info(" : assertion : " + ret);
		return ret;
	}

	private byte[] getAuthAssertion() throws Exception {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_UAFV1_SIGNED_DATA.id));
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

	private byte[] getSignedData() throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byte[] value = null;
		int length = 0;

		byteout.write(encodeInt(TagsEnum.TAG_AAID.id));
		value = getAAID();
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		byteout.write(encodeInt(TagsEnum.TAG_ASSERTION_INFO.id));
		value = new byte[] { 0x00, 0x00, 0x01, 0x00, 0x00 };
		length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);

		byteout.write(encodeInt(TagsEnum.TAG_KEYID.id));
		value = getKeyId();
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
		byteout.write(encodeInt(TagsEnum.TAG_AAID.id));
		byte[] value = "ebay-test-key".getBytes();
		int length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		return byteout.toByteArray();
	}

	private byte[] getAAID() throws IOException {
		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
		byteout.write(encodeInt(TagsEnum.TAG_AAID.id));
		byte[] value = "ABCD#ABCD".getBytes();
		int length = value.length;
		byteout.write(encodeInt(length));
		byteout.write(value);
		return byteout.toByteArray();
	}

	private byte[] encodeInt(int id) {

		byte[] bytes = new byte[2];
		bytes[0] = (byte) (id & 0x00ff);
		bytes[1] = (byte) ((id & 0xff00) >> 8);
		return bytes;
	}

}
