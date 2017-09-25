package org.ebayopensource.fido.uaf.crypto;

/**
 * Created by JP20818 on 2017/09/25.
 */

public interface FidoAttestationSigner {

    public byte[] signWithAttestationCert(byte[] dataForSigning);
}
