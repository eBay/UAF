package com.nexenio.fido.uaf.core.msg;

import com.google.gson.Gson;
import org.junit.Test;

import java.util.logging.Logger;

import static org.junit.Assert.assertNotNull;

public class MatchCriteriaTest {

    private Logger logger = Logger.getLogger(this.getClass().getName());
    Gson gson = new Gson();

    @Test
    public void test() {
        MatchCriteria matchCrit = gson.fromJson(getTestMatchCrit(), MatchCriteria.class);
        assertNotNull(matchCrit);
        logger.info(gson.toJson(matchCrit));
    }

    private String getTestMatchCrit() {
        return "{\"aaid\": [\"1234#5678\"], \"vendorID\": [\"1234\"], \"userVerificationDetails\": [ [ { \"userVerification\": 2, \"baDesc\": { \"FAR\": 0.001 } } ] ], \"keyProtection\": 6, \"matcherProtection\": 2, \"attachmentHint\": 1, \"tcDisplay\": 4, \"authenticationAlgorithms\": [1], \"assertionScheme\": \"UAFV1TLV\", \"attestationTypes\": [15879], \"authenticatorVersion\": 2 }";
    }

}
