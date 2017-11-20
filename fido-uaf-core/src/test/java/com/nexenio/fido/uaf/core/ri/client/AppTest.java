package com.nexenio.fido.uaf.core.ri.client;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;

public class AppTest {

    App app = new App();

    @Test
    public void end2end() throws Exception {
        app.startRegistration();
        String accessToken = app.uafAuthentication();
        assertNotNull(accessToken);
    }

}
