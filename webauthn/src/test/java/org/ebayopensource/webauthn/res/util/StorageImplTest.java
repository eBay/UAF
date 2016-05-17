package org.ebayopensource.webauthn.res.util;

import static org.junit.Assert.*;

import org.ebayopensource.webauthn.res.util.StorageImpl;
import org.junit.Test;

public class StorageImplTest {

	@Test
	public void basic() {
		assertNotNull(StorageImpl.getInstance());
	}

}
