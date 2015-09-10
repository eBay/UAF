package org.ebayopensource.fidouaf.res.util;

import static org.junit.Assert.*;

import org.junit.Test;

public class StorageImplTest {

	@Test
	public void basic() {
		assertNotNull(StorageImpl.getInstance());
	}

}
