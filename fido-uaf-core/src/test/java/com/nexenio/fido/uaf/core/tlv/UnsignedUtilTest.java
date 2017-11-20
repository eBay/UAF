package com.nexenio.fido.uaf.core.tlv;

import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.fail;

public class UnsignedUtilTest {

    @Test
    public void test() throws IOException {
        TagsEnum t = TagsEnum.TAG_ASSERTION_INFO;
        int checkId = UnsignedUtil.read_UAFV1_UINT16(new ByteInputStream(UnsignedUtil.encodeInt(t.id)));
        if (checkId != t.id) {
            fail("Conversion error");
        }
    }

}
