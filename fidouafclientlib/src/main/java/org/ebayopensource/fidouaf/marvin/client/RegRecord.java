package org.ebayopensource.fidouaf.marvin.client;

public class RegRecord {
	private String keyId;
	private byte[] publicKey;
	
	public RegRecord (String keyId, byte[] publicKey){
		this.publicKey = publicKey;
		this.keyId = keyId;
	}

	public byte[] getPubKey() {
		return publicKey;
	}
	
	public String getKeyId (){
		return keyId;
	}

}
