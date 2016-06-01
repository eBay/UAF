package org.ebayopensource.fidouaf.marvin.client;

import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.Map;

public class OperationalParams implements OperationalParamsIntf{

	public static final String TEST_AAID = "TEST-AAID";

	public static final String TestKeyId = "TEST-KEYID";

	public static final byte[] TestPublicKey = "TEST_PUBLIC_KEY".getBytes();

	public static final String TestFacetId = "TEST-FACET-ID";

	public static final byte[] TestSignature = "TEST_SIGNATURE".getBytes();

	public static final byte[] TestAttestSignature = "TEST_ATTEST_SIGNATURE".getBytes();

	public static final byte[] TestAttestCert = "TEST-ATTEST-CERT".getBytes();
	
	private Map<String, RegRecord> regRecordMap = new HashMap<String, RegRecord>();

	public String getAAID() {
		return TEST_AAID;
	}

	public byte[] getAttestCert() {
		return TestAttestCert;
	}

	public long getRegCounter() {
		// TODO Auto-generated method stub
		return 0;
	}

	public void incrementRegCounter() {
		// TODO Auto-generated method stub
		
	}

	public long getAuthCounter() {
		// TODO Auto-generated method stub
		return 0;
	}

	public void incrementAuthCounter() {
		// TODO Auto-generated method stub
		
	}

	public boolean isFacetIdValid(String appId, String facetId) {
		return true;
	}

	public byte[] signWithAttestationKey(byte[] dataToSign) throws Exception {
		return TestAttestSignature;
	}

	public StorageInterface getStorage() {
		// TODO Auto-generated method stub
		return null;
	}

	public KeyPairGenerator getKeyPairGenerator(String keyId) {
		// TODO Auto-generated method stub
		return null;
	}

	public RegRecord genAndRecord(String appId) {
		RegRecord r = new RegRecord(TestKeyId, TestPublicKey);
		regRecordMap.put(appId, r);
		return r;
	}

	public String getFacetId(String appId) {
		return TestFacetId;
	}

	public String getKeyId(String appId) {
		return TestKeyId;
	}

	public void init(String aaid, byte[] attestCert, byte[] attestPrivKey,
			StorageInterface storage) {
		// TODO Auto-generated method stub
		
	}

	public byte[] getSignature(byte[] signedDataValue, String keyId)
			throws Exception {
		return TestSignature;
	}

}
