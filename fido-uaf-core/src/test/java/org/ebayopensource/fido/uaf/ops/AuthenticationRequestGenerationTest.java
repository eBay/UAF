package org.ebayopensource.fido.uaf.ops;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.logging.Logger;

import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.crypto.SHA;
import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;
import org.ebayopensource.fido.uaf.tlv.AlgAndEncodingEnum;
import org.ebayopensource.fido.uaf.tlv.Tag;
import org.junit.Test;

import com.google.gson.Gson;

public class AuthenticationRequestGenerationTest {
	
	private Logger logger = Logger.getLogger(this.getClass().getName());
	private static final String TEST_SIGNATURE = "test_signature";
	Gson gson = new Gson ();

	@Test
	public void notNull() {
		AuthenticationRequest authReq= new AuthenticationRequestGeneration().createAuthenticationRequest(new NotaryImpl());
		assertNotNull(authReq);
		logger.info(gson.toJson(authReq));
	}
	
	@Test
	public void withPolicy() {
		String[] aaids = {"ABCD#ABCD"};
		AuthenticationRequest authReq= new AuthenticationRequestGeneration("https://uaf.ebay.com/uaf/facets",aaids ).createAuthenticationRequest(new NotaryImpl());
		assertNotNull(authReq);
		logger.info(gson.toJson(authReq));
	}

	class NotaryImpl implements Notary {

		public boolean verify(String dataToSign, String signature) {
			return signature.startsWith(TEST_SIGNATURE);
		}

		@Override
		public boolean verifySignature(byte[] dataForSigning, byte[] signature, String pubKey, AlgAndEncodingEnum algAndEncoding) throws Exception {
			return true;
		}

		@Override
		public AlgAndEncodingEnum getAlgAndEncoding(Tag info) {
			return AlgAndEncodingEnum.UAF_ALG_KEY_ECC_X962_DER;
		}

		@Override
		public byte[] getDataForSigning(Tag signedData) throws IOException {
			return "".getBytes();
		}

		@Override
		public byte[] encodeInt(int id) {
			byte[] bytes = new byte[2];
			bytes[0] = (byte) (id & 0x00ff);
			bytes[1] = (byte) ((id & 0xff00) >> 8);
			return bytes;
		}

		public String sign(String dataToSign) {
			return SHA.sha256(dataToSign);
		}
	}

}
