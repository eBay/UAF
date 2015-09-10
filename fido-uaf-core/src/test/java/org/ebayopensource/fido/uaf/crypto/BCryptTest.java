package org.ebayopensource.fido.uaf.crypto;

import static org.junit.Assert.*;

import org.junit.Test;

public class BCryptTest {

	@Test
	public void basic() {
		String hashpw = BCrypt.hashpw("password", BCrypt.gensalt());
		assertTrue(BCrypt.checkpw("password", hashpw));
		
		String gensalt = BCrypt.gensalt();
		hashpw = BCrypt.hashpw(gensalt, BCrypt.gensalt());
		assertTrue(BCrypt.checkpw(gensalt, hashpw));
	}

}
