package com.nexenio.fido.uaf.core.ops;

import com.google.gson.Gson;
import com.nexenio.fido.uaf.core.crypto.Notary;
import com.nexenio.fido.uaf.core.msg.RegistrationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import java.util.logging.Logger;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class RegistrationRequestGenerationTest {

    private static final String TEST_SIGNATURE = "test_signature";
    private Logger logger = Logger.getLogger(this.getClass().getName());
    Gson gson = new Gson();

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

        String serverData = regReq.getHeader().getServerData();
        serverData = new String(Base64.decode(serverData));
        assertTrue(notary.verify(serverData, serverData));
        assertTrue(RegistrationRequestGeneration.APP_ID.equals(regReq.getHeader().getAppID()));
        logger.info(gson.toJson(regReq));
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
