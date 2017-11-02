package com.nexenio.fido.uaf.core.msg;

import com.google.gson.Gson;
import org.junit.Test;

import java.util.logging.Logger;

import static org.junit.Assert.assertNotNull;

public class DeregistrationRequestTest {

    private Logger logger = Logger.getLogger(this.getClass().getName());
    Gson gson = new Gson();

    @Test
    public void test() {
        DeregistrationRequest deregRequest = gson.fromJson(getTestDeregRequest(), DeregistrationRequest.class);
        assertNotNull(deregRequest);
        logger.info(gson.toJson(deregRequest));
    }

    String getTestDeregRequest() {
        return "{\"operationHeader\": {\"operation\": \"DEREGISTRATION\",\"protocolVersion\": {\"major\": 1,\"minor\": 0},\"appId\": \"https://uaf-test-1.noknoktest.com:8443/SampleApp/uaf/facets\"},\"authenticators\": [{\"aaids\": \"ABCD#ABCD\",\"keyId\": \"ZMCPn92yHv1Ip-iCiBb6i4ADq6ZOv569KFQCvYSJfNg\"}]}";
    }

}
