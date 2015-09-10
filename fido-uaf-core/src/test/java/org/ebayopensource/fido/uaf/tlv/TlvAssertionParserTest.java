package org.ebayopensource.fido.uaf.tlv;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.logging.Logger;

import org.junit.Test;

import com.google.gson.Gson;

public class TlvAssertionParserTest {

	private Logger logger = Logger.getLogger(this.getClass().getName());
	Gson gson = new Gson();
	TlvAssertionParser p = new TlvAssertionParser();
	AuthAssertionBuilder authAssertionBuilder = new  AuthAssertionBuilder();
	RegAssertionBuilder reqAssertionBuilder = new  RegAssertionBuilder();

	@Test
	public void parserForAuthAssertion() throws IOException {
		String raw = null;
		Tags list = null;

		raw = TestAssertions.getExampleAuthAssertions();
		list = p.parse(raw);
		assertNotNull(list);
		assertTrue(list.getTags().size() > 0);
		assertTrue(list.getTags().get(TagsEnum.UAF_CMD_STATUS_ERR_UNKNOWN.id) == null);
		logger.info(list.toString());
	}
	
	@Test
	public void parserForAuthAssertionFromClient() throws IOException {
		String raw = null;
		Tags list = null;

		raw = TestAssertions.getExampleAuthAssertionsFromClient();
		list = p.parse(raw);
		assertNotNull(list);
		assertTrue(list.getTags().size() > 0);
		assertTrue(list.getTags().get(TagsEnum.UAF_CMD_STATUS_ERR_UNKNOWN.id) == null);
		logger.info(list.toString());
	}
	
	@Test
	public void parserForAuthAssertionFromCertTool() throws IOException {
		String raw = null;
		Tags list = null;

		raw = TestAssertions.getExampleAuthAssertionsFromCertTool();
		list = p.parse(raw);
		assertNotNull(list);
		assertTrue(list.getTags().size() > 0);
		assertTrue(list.getTags().get(TagsEnum.UAF_CMD_STATUS_ERR_UNKNOWN.id) == null);
		logger.info(list.toString());
	}

	@Test
	public void forGeneratedAssertion() throws Exception {

		String assertions = authAssertionBuilder.getAssertions();
		logger.info(" : Test auth assertion : " + assertions);
		Tags tags = p.parse(assertions);
		assertNotNull(tags);
		logger.info(tags.toString());

	}
	
	@Test
	public void parserForRegAssertion() throws IOException {
		String raw = null;
		Tags list = null;

		raw = TestAssertions.getExampleRegAssertions();
		list = p.parse(raw);
		checkRegTags(list);
		logger.info(list.toString());
	}
	
	@Test
	public void parserForRegAssertionTest2() throws IOException {
		String raw = null;
		Tags list = null;

		raw = TestAssertions.getSecondExampleRegAssertions();
		list = p.parse(raw);
		checkRegTags(list);
		logger.info(list.toString());
	}
	
	@Test
	public void parserForRegAssertionRaon() throws IOException {
		String raw = null;
		Tags list = null;

		raw = TestAssertions.regRequestAssertionsFromRaon();
		list = p.parse(raw);
		checkRegTags(list);
		logger.info(list.toString());
	}

	private void checkRegTags(Tags list) {
		assertNotNull(list);
		assertNotNull(list.getTags().get(TagsEnum.TAG_UAFV1_REG_ASSERTION.id));
		assertNotNull(list.getTags().get(TagsEnum.TAG_UAFV1_KRD.id));
		assertNotNull(list.getTags().get(TagsEnum.TAG_PUB_KEY.id));
		assertNotNull(list.getTags().get(TagsEnum.TAG_ASSERTION_INFO.id));
//		assertNotNull(list.getTags().get(TagsEnum.TAG_ATTESTATION_BASIC_FULL.id));
//		assertNotNull(list.getTags().get(TagsEnum.TAG_ATTESTATION_CERT.id));
		assertTrue(list.getTags().size() > 0);
		assertTrue(list.getTags().get(TagsEnum.UAF_CMD_STATUS_ERR_UNKNOWN.id) == null);
	}
	
	@Test
	public void forGeneratedRegAssertion() throws Exception {

		String assertions = reqAssertionBuilder.getAssertions();
		logger.info(" : Test reg assetion : " + assertions);
		Tags tags = p.parse(assertions);
		assertNotNull(tags);
		checkRegTags(tags);
		logger.info(tags.toString());

	}

}
