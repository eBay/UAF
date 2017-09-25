package org.ebayopensource.fido.uaf.crypto;

import java.security.KeyPair;

/**
 * Created by JP20818 on 2017/09/25.
 */

public interface FidoSigner {

    public abstract byte[] sign(byte[] dataToSign, KeyPair keyPair);

}
