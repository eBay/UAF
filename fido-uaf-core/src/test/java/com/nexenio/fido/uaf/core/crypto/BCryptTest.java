package com.nexenio.fido.uaf.core.crypto;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

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
