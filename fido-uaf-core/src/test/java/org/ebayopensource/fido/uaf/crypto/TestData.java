package org.ebayopensource.fido.uaf.crypto;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.codec.binary.Base64;
import org.ebayopensource.fido.uaf.tlv.TagsEnum;


public class TestData {
	public static final String TEST_PRIV_KEY = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgzqOJl-rC0FFMMFM7w7sqp99jsBxgMx_fqwuaUc4CVv-gCgYIKoZIzj0DAQehRANCAAQokXIHgAc20GWpznnnIX9eD2btK-R-uWUFgOKt8l27RcrrOrqJ66uCMfOuG4I1usUUOa7f_A19v74FC-HuSB50";
	public static final String TEST_PUB_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKJFyB4AHNtBlqc555yF_Xg9m7SvkfrllBYDirfJdu0XK6zq6ieurgjHzrhuCNbrFFDmu3_wNfb--BQvh7kgedA==";
	public PublicKey pub = null;
	public PrivateKey priv = null;
	public byte[] dataForSigning = new byte[4];
	public byte[] signature = null;
	public BigInteger[] rsSignature = null;

	public TestData() throws NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchProviderException, InvalidKeyException, SignatureException,
			UnsupportedEncodingException, InvalidAlgorithmParameterException {
		this(
				KeyCodec.getPubKey(Base64.decodeBase64(
						TEST_PUB_KEY)),
				KeyCodec.getPrivKey(Base64.decodeBase64(
						TEST_PRIV_KEY)));
	}

	public TestData(PublicKey pubArg, PrivateKey privArg)
			throws NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchProviderException, InvalidKeyException, SignatureException,
			UnsupportedEncodingException, InvalidAlgorithmParameterException {
		pub = pubArg;
		priv = privArg;
		int signedDataId = TagsEnum.TAG_UAFV1_SIGNED_DATA.id;
		int signedDataLength = 200;
		dataForSigning[0] = (byte) (signedDataId & 0x00ff);
		dataForSigning[1] = (byte) (signedDataId & 0xff00);
		dataForSigning[2] = (byte) (signedDataLength & 0x00ff);
		dataForSigning[3] = (byte) (signedDataLength & 0xff00);
		//signature = NamedCurve.sign(priv, dataForSigning);
		rsSignature = NamedCurve.signAndFromatToRS(priv,
				SHA.sha(dataForSigning, "SHA-1"));
	}

}
