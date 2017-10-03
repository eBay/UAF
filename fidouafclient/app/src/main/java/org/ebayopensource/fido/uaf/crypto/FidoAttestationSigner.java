package org.ebayopensource.fido.uaf.crypto;

public interface FidoAttestationSigner {

    public byte[] signWithAttestationCert(byte[] dataForSigning);
}
