package org.ebayopensource.fido.uaf.crypto;

import static org.junit.Assert.*;

import org.junit.Test;

public class SHATest {

	private static final String SOME_OTHER_STRING = "SomeOtherString";
	private static final String SOME_STRING = "SomeString";

	@Test
	public void basic() {
		String sha256 = SHA.sha256(SOME_STRING);
		assertNotNull(sha256);
		assertTrue(!sha256.equals(SOME_STRING));
	}
	
	@Test
	public void uniqeResult() {
		String sha1 = SHA.sha256(SOME_STRING);
		String sha2 = SHA.sha256(SOME_OTHER_STRING);
		assertTrue(!sha1.equals(sha2));
	}
	
	@Test
	public void deterministic() {
		String sha1 = SHA.sha256(SOME_STRING);
		assertTrue(sha1.equals(SHA.sha256(SOME_STRING)));
	}

	@Test
	public void nullInput() {
		String sha256;
		try {
			sha256 = SHA.sha256(null);
		} catch (Exception e) {
			assertTrue(e instanceof RuntimeException);
		}
	}
}
