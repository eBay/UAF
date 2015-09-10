package org.ebayopensource.fido.uaf.ri.client;

import static org.junit.Assert.*;

import org.junit.Test;

public class AppTest {
	
	App app = new App();

	@Test
	public void end2end() throws Exception {
		app.startRegistration();
		String accessToken = app.uafAuthentication();
		assertNotNull(accessToken);
	}

}
