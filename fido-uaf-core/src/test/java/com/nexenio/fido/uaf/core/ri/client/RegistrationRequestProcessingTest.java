package com.nexenio.fido.uaf.core.ri.client;

import com.google.gson.Gson;
import com.nexenio.fido.uaf.core.msg.RegistrationRequest;
import com.nexenio.fido.uaf.core.msg.RegistrationResponse;
import org.junit.Test;

import java.util.logging.Logger;

import static org.junit.Assert.assertNotNull;

public class RegistrationRequestProcessingTest {

    private Logger logger = Logger.getLogger(this.getClass().getName());
    Gson gson = new Gson();

    @Test
    public void testProcessRequest() {
        RegistrationRequestProcessing r = new RegistrationRequestProcessing();
        RegistrationRequest req = getTestRequest();
        assertNotNull(req);
        logger.info(gson.toJson(req));

        RegistrationResponse resp = r.processRequest(req);
        assertNotNull(resp);
        logger.info(gson.toJson(resp));
    }

    private RegistrationRequest getTestRequest() {
        return gson.fromJson(getTestRequestAsJsonString(), RegistrationRequest.class);
    }

    private String getTestRequestAsJsonString() {
        return "{\"header\":{\"upv\":{\"major\":1,\"minor\":0},\"op\":\"Reg\",\"appID\":\"https://uaf-test-1.noknoktest.com:8443/SampleApp/uaf/facets\",\"serverData\":\"IjycjPZYiWMaQ1tKLrJROiXQHmYG0tSSYGjP5mgjsDaM17RQgq0dl3NNDDTx9d-aSR_6hGgclrU2F2Yj-12S67v5VmQHj4eWVseLulHdpk2v_hHtKSvv_DFqL4n2IiUY6XZWVbOnvg\"},\"challenge\":\"H9iW9yA9aAXF_lelQoi_DhUk514Ad8Tqv0zCnCqKDpo\",\"username\":\"apa\",\"policy\":{\"accepted\":[[{\"userVerification\":512,\"keyProtection\":1,\"tcDisplay\":1,\"authenticationAlgorithms\":[1],\"assertionSchemes\":[\"UAFV1TLV\"]}],[{\"userVerification\":4,\"keyProtection\":1,\"tcDisplay\":1,\"authenticationAlgorithms\":[1],\"assertionSchemes\":[\"UAFV1TLV\"]}],[{\"userVerification\":4,\"keyProtection\":1,\"tcDisplay\":1,\"authenticationAlgorithms\":[2]}],[{\"userVerification\":2,\"keyProtection\":4,\"tcDisplay\":1,\"authenticationAlgorithms\":[2]}],[{\"userVerification\":4,\"keyProtection\":2,\"tcDisplay\":1,\"authenticationAlgorithms\":[1,3]}],[{\"userVerification\":2,\"keyProtection\":2,\"authenticationAlgorithms\":[2]}],[{\"userVerification\":32,\"keyProtection\":2,\"assertionSchemes\":[\"UAFV1TLV\"]},{\"userVerification\":2,\"authenticationAlgorithms\":[1,3],\"assertionSchemes\":[\"UAFV1TLV\"]},{\"userVerification\":2,\"authenticationAlgorithms\":[1,3],\"assertionSchemes\":[\"UAFV1TLV\"]},{\"userVerification\":4,\"keyProtection\":1,\"authenticationAlgorithms\":[1,3],\"assertionSchemes\":[\"UAFV1TLV\"]}]],\"disallowed\":[{\"userVerification\":512,\"keyProtection\":16,\"assertionSchemes\":[\"UAFV1TLV\"]},{\"userVerification\":256,\"keyProtection\":16},{\"aaid\":[\"ABCD#ABCD\"],\"keyIDs\":[\"RfY_RDhsf4z5PCOhnZExMeVloZZmK0hxaSi10tkY_c4\"]}]}}";
    }
}
