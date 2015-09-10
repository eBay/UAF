package org.ebayopensource.fido.uaf.tlv;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.logging.Logger;

import org.junit.Test;

public class TagAssertionInfoTest {

	private Logger logger = Logger.getLogger(this.getClass().getName());
	TlvAssertionParser p = new TlvAssertionParser();
	
	@Test
	public void parserForRegAssertion() throws IOException, InvalidArgumentException {
		String raw = null;
		Tags list = null;

		raw = TestAssertions.getExampleRegAssertions();
		list = p.parse(raw);
		assertNotNull(list);
		assertNotNull(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
		TagAssertionInfo info = new TagAssertionInfo(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
		assertTrue(info.getAuthenticatorMode() == 0x01);
		assertTrue(info.getSignatureAlgAndEncoding() == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW.id);
		assertTrue(info.getPublicKeyAlgAndEncoding() == AlgAndEncodingEnum.UAF_ALG_KEY_ECC_X962_RAW.id);
		logger.info(info.toString());
	}
	
	@Test
	public void parserForRegAssertionFromCertTool() throws IOException, InvalidArgumentException {
		String raw = null;
		Tags list = null;

		raw = TestAssertions.getSecondExampleRegAssertions();
		list = p.parse(raw);
		assertNotNull(list);
		assertNotNull(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
		TagAssertionInfo info = new TagAssertionInfo(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
		assertTrue(info.getAuthenticatorMode() == 0x01);
		assertTrue(info.getSignatureAlgAndEncoding() == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER.id);
		assertTrue(info.getPublicKeyAlgAndEncoding() == AlgAndEncodingEnum.UAF_ALG_KEY_ECC_X962_DER.id);
		logger.info(info.toString());
	}
	
	@Test
	public void parserForRegAssertionFromTestClient() throws IOException, InvalidArgumentException {
		String raw = null;
		Tags list = null;

		raw = TestAssertions.getExampleRegAssertionsFromClient();
		list = p.parse(raw);
		assertNotNull(list);
		assertNotNull(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
		TagAssertionInfo info = new TagAssertionInfo(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
		assertTrue(info.getAuthenticatorMode() == 0x01);
		assertTrue(info.getSignatureAlgAndEncoding() == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW.id);
		assertTrue(info.getPublicKeyAlgAndEncoding() == AlgAndEncodingEnum.UAF_ALG_KEY_ECC_X962_RAW.id);
		logger.info(info.toString());
	}

	@Test
	public void parserForAuthAssertion() throws IOException, InvalidArgumentException {
		String raw = null;
		Tags list = null;

		raw = TestAssertions.getExampleAuthAssertions();
		list = p.parse(raw);
		assertNotNull(list);
		assertNotNull(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
		TagAssertionInfo info = new TagAssertionInfo(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
		assertTrue(info.getAuthenticatorMode() == 0x01);
		assertTrue(info.getSignatureAlgAndEncoding() == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW.id);
		logger.info(info.toString());
	}

	@Test
	public void parserForAuthAssertionFromClient() throws IOException, InvalidArgumentException {
		String raw = null;
		Tags list = null;

		raw = TestAssertions.getExampleAuthAssertionsFromClient();
		list = p.parse(raw);
		assertNotNull(list);
		assertNotNull(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
		TagAssertionInfo info = new TagAssertionInfo(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
		assertTrue(info.getAuthenticatorMode() == 0x01);
		assertTrue(info.getSignatureAlgAndEncoding() == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW.id);
		logger.info(info.toString());
	}
	
	@Test
	public void parserForAuthAssertionFromCertTool() throws IOException, InvalidArgumentException {
		String raw = null;
		Tags list = null;

		raw = TestAssertions.getExampleAuthAssertionsFromCertTool();
		list = p.parse(raw);
		assertNotNull(list);
		assertNotNull(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
		TagAssertionInfo info = new TagAssertionInfo(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
		assertTrue(info.getAuthenticatorMode() == 0x01);
		assertTrue(info.getSignatureAlgAndEncoding() == AlgAndEncodingEnum.UAF_ALG_SIGN_SECP256R1_ECDSA_SHA256_DER.id);
		logger.info(info.toString());
	}
}
