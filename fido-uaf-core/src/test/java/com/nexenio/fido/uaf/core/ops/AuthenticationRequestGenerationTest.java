package com.nexenio.fido.uaf.core.ops;

import com.google.gson.Gson;
import com.nexenio.fido.uaf.core.operation.authentication.AuthenticationRequestGeneration;
import com.nexenio.fido.uaf.core.crypto.Notary;
import com.nexenio.fido.uaf.core.message.AuthenticationRequest;
import org.junit.Test;

import java.util.logging.Logger;

import static org.junit.Assert.assertNotNull;

public class AuthenticationRequestGenerationTest {

    private Logger logger = Logger.getLogger(this.getClass().getName());
    private static final String TEST_SIGNATURE = "test_signature";
    Gson gson = new Gson();

    @Test
    public void notNull() {
        AuthenticationRequest authReq = new AuthenticationRequestGeneration().createAuthenticationRequest(new NotaryImpl());
        assertNotNull(authReq);
        logger.info(gson.toJson(authReq));
    }

    @Test
    public void withPolicy() {
        String[] aaids = {"ABCD#ABCD"};
        AuthenticationRequest authReq = new AuthenticationRequestGeneration("https://uaf.ebay.com/uaf/facets", aaids).createAuthenticationRequest(new NotaryImpl());
        assertNotNull(authReq);
        logger.info(gson.toJson(authReq));
    }

    class NotaryImpl implements Notary {

        public boolean verify(String dataToSign, String signature) {
            return signature.startsWith(TEST_SIGNATURE);
        }

        public String sign(String dataToSign) {
            // For testing
            return TEST_SIGNATURE;
        }
    }

}
