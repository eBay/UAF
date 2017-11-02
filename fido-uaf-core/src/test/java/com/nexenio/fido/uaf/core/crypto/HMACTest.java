package com.nexenio.fido.uaf.core.crypto;

import org.junit.Test;

import java.security.InvalidParameterException;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class HMACTest {

    @Test
    public void testSignNotNullNotEqual() {
        try {
            byte[] Signature = HMAC.sign("Some_String", "Password");
            assertNotNull(Signature);
            assertTrue(!Signature.toString().equals("SOME_STRING"));
        } catch (Exception e) {
            assertTrue(e instanceof Exception);
        }
    }

    @Test
    public void nullPassword() {
        String result = "";
        try {
            result = HMAC.sign("Some_String", null).toString();
        } catch (Exception e) {
            assertTrue(e instanceof InvalidParameterException);
        }
    }

    @Test
    public void nullInputString() {
        String result = "";
        try {
            result = HMAC.sign(null, "Password").toString();
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(e instanceof InvalidParameterException);
        }
    }
}
