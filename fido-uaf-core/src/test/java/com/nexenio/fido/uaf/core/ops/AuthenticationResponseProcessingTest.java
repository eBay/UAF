package com.nexenio.fido.uaf.core.ops;

import com.google.gson.Gson;
import com.nexenio.fido.uaf.core.msg.AuthenticationResponse;
import com.nexenio.fido.uaf.core.storage.AuthenticatorRecord;
import com.nexenio.fido.uaf.core.storage.RegistrationRecord;
import com.nexenio.fido.uaf.core.storage.StorageInterface;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AuthenticationResponseProcessingTest {

    private static final String TEST_USERNAME = "testUsername";

    private Gson gson = new Gson();

    @Test
    public void basic() throws Exception {
        AuthenticationResponseProcessing p = new AuthenticationResponseProcessing();
        AuthenticationResponse response = getTestResponse();
        StorageInterface serverData = new ServerDataImpl();
        AuthenticatorRecord[] authenticatorRecords = p.verify(response, serverData);
        assertTrue(authenticatorRecords.length == 1);
        assertEquals(authenticatorRecords[0].getUserName(), TEST_USERNAME);
        assertEquals(authenticatorRecords[0].getStatus(), "SUCCESS");

    }

    private AuthenticationResponse getTestResponse() {
        return gson.fromJson(getTestResponseAsJsonString(), AuthenticationResponse.class);
    }

    private String getTestResponseAsJsonString() {
        return "{\"header\":{\"upv\":{\"major\":1,\"minor\":0},\"op\":\"Auth\",\"appID\":\"android:apk-key-hash:bE0f1WtRJrZv/C0y9CM73bAUqiI\",\"serverData\":\"MjBlNDkxM2ZkODg4YTcwYzEwYWRhMDAxZjNkYzA5MTgyNDg2NDE1MzgxMjljOGVhOTAwYThhMDhiYTMxMTU5OC5NVFEwTWpnNU1qRXhNalkyTVEuU2tSS2FFcEVSWGRLUlRRMVZHMWFZVnA2YkVaWlZtaDNZMGh3U0dKWFRuRmxhMDUzV1ZkVg\"},\"fcParams\":\"eyJhcHBJRCI6ICJhbmRyb2lkOmFway1rZXktaGFzaDpiRTBmMVd0UkpyWnYvQzB5OUNNNzNiQVVxaUkiLCAiY2hhbGxlbmdlIjogIkpESmhKREV3SkU0NVRtWmFaemxGWVZod2NIcEhiV05xZWtOd1lXVSIsICJmYWNldElEIjogImFuZHJvaWQ6YXBrLWtleS1oYXNoOmJFMGYxV3RSSnJadi9DMHk5Q003M2JBVXFpSSIsICJjaGFubmVsQmluZGluZyI6IHt9fQ==\",\"assertions\":[{\"assertionScheme\":\"UAFV1TLV\",\"assertion\":\"Aj7cAAQ-jgALLgkAREFCOCM4MDExDi4FAAEAAQIADy4gADTtvD7YbR3StOT1LwT04sb-V6EopmakXBK-3P4W1YbbCi4gACsUQcxM9uGW-4U0lg4Ph5O42KrWQXuMmXKRzLNrhWimEC4AAAkuIAAoS_GsukwMqV51f_fM3kvsUA8TE9gPQ3M7n1KQUauSFA0uBAAAAAAABi5GADBEAiBZURmUIIuqa4WKs9p0od-Yd_MMyl-7QiKHs8--9ovFUQIgdGgfTKKBS92JYhPLW7j6NyIug3igBTO9z0A3EovJvpk\"}]}";
    }

    class ServerDataImpl implements StorageInterface {


        public void storeServerDataString(String userName, String serverData) {
            // TODO Auto-generated method stub
        }

        public String getUsername(String serverData) {
            // TODO Auto-generated method stub
            return null;
        }

        public void store(RegistrationRecord[] records) {
            // TODO Auto-generated method stub
        }

        public RegistrationRecord readRegistrationRecord(String key) {
            RegistrationRecord r = new RegistrationRecord();
            r.setUserName(TEST_USERNAME);
            r.setPublicKey("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAN6POEisT65JDZ_oHBXreI59W3BpISIrmYu9MzDD8ec9BCEgEOolypVx291mPg_Hv61AWKjCA6w_DaLCNKKC3g");
            return r;
        }

        public void update(RegistrationRecord[] records) {
            // TODO Auto-generated method stub
        }

    }

}
