/*
 * Copyright 2015 eBay Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.nexenio.fido.uaf.core.tlv;

import java.io.IOException;

public class TagAssertionInfo {

    private Tag tag;
    private boolean isReg = false;
    private int authenticatorVersion = 0;
    private int authenticatorMode = 0;
    private int signatureAlgAndEncoding = 0;
    private int publicKeyAlgAndEncoding = 0;

    public TagAssertionInfo(Tag tag) throws IllegalArgumentException, IOException {
        this.tag = tag;
        if (tag.id != TagsEnum.TAG_ASSERTION_INFO.id) {
            throw new IllegalArgumentException("Not TAG_ASSERTION_INFO tag");
        }
        if (tag.length != 5 && tag.length != 7) {
            throw new IllegalArgumentException("Unrecognized tag structure. Length=" + tag.length);
        }
        if (tag.length == 7) {
            isReg = true;
        }
        parse();
    }

    private void parse() throws IOException {
        ByteInputStream bytes = new ByteInputStream(tag.value);
        authenticatorVersion = UnsignedUtil.read_UAFV1_UINT16(bytes);
        authenticatorMode = bytes.readByte();
        signatureAlgAndEncoding = UnsignedUtil.read_UAFV1_UINT16(bytes);
        if (isReg) {
            publicKeyAlgAndEncoding = UnsignedUtil.read_UAFV1_UINT16(bytes);
        }
    }

    public Tag getTag() {
        return tag;
    }

    public boolean isReg() {
        return isReg;
    }

    public int getAuthenticatorVersion() {
        return authenticatorVersion;
    }

    public int getAuthenticatorMode() {
        return authenticatorMode;
    }

    public int getSignatureAlgAndEncoding() {
        return signatureAlgAndEncoding;
    }

    public int getPublicKeyAlgAndEncoding() {
        return publicKeyAlgAndEncoding;
    }

    public String toString() {
        return " isReg=" + isReg + " authenticatorVersion="
                + authenticatorVersion + " authenticatorMode="
                + authenticatorMode + " signatureAlgAndEncoding="
                + signatureAlgAndEncoding + " publicKeyAlgAndEncoding="
                + publicKeyAlgAndEncoding;

    }

}
