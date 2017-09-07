package org.ebayopensource.fido.uaf.ops;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.logging.Logger;

import org.bouncycastle.util.encoders.Base64;
import org.ebayopensource.fido.uaf.crypto.Notary;
import org.ebayopensource.fido.uaf.crypto.SHA;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.tlv.AlgAndEncodingEnum;
import org.ebayopensource.fido.uaf.tlv.Tag;
import org.junit.Test;

import com.google.gson.Gson;

public class RegistrationRequestGenerationTest {

	private static final String TEST_SIGNATURE = "test_signature";
	private Logger logger = Logger.getLogger(this.getClass().getName());
	Gson gson = new Gson ();

	@Test
	public void notNull() {
		RegistrationRequest regReq = new RegistrationRequestGeneration().createRegistrationRequest("Username", new NotaryImpl());
		
		assertNotNull(regReq);
		logger.info(gson.toJson(regReq));
	}
	
	@Test
	public void basic() {
		Notary notary = new NotaryImpl();
		RegistrationRequest regReq = new RegistrationRequestGeneration().createRegistrationRequest("Username", notary);
		
		String serverData = regReq.header.serverData;
		serverData = new String (Base64.decode(serverData));
		assertTrue(notary.verify(serverData,serverData));
		assertTrue(RegistrationRequestGeneration.APP_ID.equals(regReq.header.appID));
		logger.info(gson.toJson(regReq));
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
