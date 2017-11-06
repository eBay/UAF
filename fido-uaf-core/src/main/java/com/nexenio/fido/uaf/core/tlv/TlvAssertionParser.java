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

import org.apache.commons.codec.binary.Base64;

import java.io.IOException;

public class TlvAssertionParser {

    public Tags parse(String base64OfRegResponse) throws IOException {
        ByteInputStream bytes = new ByteInputStream(Base64.decodeBase64(base64OfRegResponse));
        boolean isReg = false;
        return parse(bytes, isReg);
    }

    public Tags parse(ByteInputStream bytes, boolean isReg) throws IOException {
        Tags ret = new Tags();
        Tag tag;
        try {
            while (bytes.available() > 0) {
                tag = new Tag();
                tag.id = UnsignedUtil.read_UAFV1_UINT16(bytes);
                tag.length = UnsignedUtil.read_UAFV1_UINT16(bytes);

                if (tag.id == TagsEnum.TAG_UAFV1_AUTH_ASSERTION.id) {
                    // ret.add(t);
                    addTagAndValue(bytes, ret, tag);
                    addSubTags(isReg, ret, tag);
                } else if (tag.id == TagsEnum.TAG_UAFV1_SIGNED_DATA.id) {
                    // ret.add(t);
                    addTagAndValue(bytes, ret, tag);
                    addSubTags(isReg, ret, tag);
                } else if (tag.id == TagsEnum.TAG_UAFV1_REG_ASSERTION.id) {
                    isReg = true;
                    // ret.add(t);
                    addTagAndValue(bytes, ret, tag);
                    addSubTags(isReg, ret, tag);
                } else if (tag.id == TagsEnum.TAG_UAFV1_KRD.id) {
                    ret.add(tag);
                    addTagAndValue(bytes, ret, tag);
                    addSubTags(isReg, ret, tag);
                } else if (tag.id == TagsEnum.TAG_AAID.id) {
                    addTagAndValue(bytes, ret, tag);
                } else if (tag.id == TagsEnum.TAG_ASSERTION_INFO.id) {
                    // 2 - Vendor assigned authenticator version.
                    // 1 - Authentication Mode indicating whether user
                    // explicitly verified or not and indicating if there is a
                    // transaction content or not.
                    // 2 - Signature algorithm and encoding format.
                    if (isReg) {
                        tag.value = bytes.read(7);
                    } else {
                        tag.value = bytes.read(5);
                    }
                    ret.add(tag);
                } else if (tag.id == TagsEnum.TAG_AUTHENTICATOR_NONCE.id) {
                    addTagAndValue(bytes, ret, tag);
                } else if (tag.id == TagsEnum.TAG_FINAL_CHALLENGE.id) {
                    addTagAndValue(bytes, ret, tag);
                } else if (tag.id == TagsEnum.TAG_TRANSACTION_CONTENT_HASH.id) {
                    if (tag.length > 0) {
                        addTagAndValue(bytes, ret, tag);
                    } else {
                        // Length of Transaction Content Hash. This length is 0
                        // if AuthenticationMode == 0x01, i.e. authentication,
                        // not transaction confirmation.
                        ret.add(tag);
                    }
                } else if (tag.id == TagsEnum.TAG_KEYID.id) {
                    addTagAndValue(bytes, ret, tag);
                } else if (tag.id == TagsEnum.TAG_COUNTERS.id) {
                    // Indicates how many times this authenticator has performed
                    // signatures in the past
                    if (isReg) {
                        tag.value = bytes.read(8);
                    } else {
                        tag.value = bytes.read(4);
                    }
                    ret.add(tag);
                } else if (tag.id == TagsEnum.TAG_PUB_KEY.id) {
                    addTagAndValue(bytes, ret, tag);
                } else if (tag.id == TagsEnum.TAG_ATTESTATION_BASIC_FULL.id) {
                    ret.add(tag);
                } else if (tag.id == TagsEnum.TAG_SIGNATURE.id) {
                    addTagAndValue(bytes, ret, tag);
                } else if (tag.id == TagsEnum.TAG_ATTESTATION_CERT.id) {
                    addTagAndValue(bytes, ret, tag);
                } else if (tag.id == TagsEnum.TAG_ATTESTATION_BASIC_SURROGATE.id) {
                    ret.add(tag);
                } else {
                    tag.statusId = TagsEnum.UAF_CMD_STATUS_ERR_UNKNOWN.id;
                    tag.value = bytes.readAll();
                    ret.add(tag);
                }
            }
        } finally {
            bytes.close();
        }
        return ret;
    }

    private void addSubTags(boolean isReg, Tags ret, Tag t) throws IOException {
        ret.addAll(parse(new ByteInputStream(t.value), isReg));
    }

    private void addTagAndValue(ByteInputStream bytes, Tags ret, Tag t) {
        t.value = bytes.read(t.length);
        ret.add(t);
    }
}
