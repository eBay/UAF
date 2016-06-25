package org.ebayopensource.fido.uaf.crypto;

import android.util.Base64;

/*
 * Copyright 2016 eBay Software Foundation
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

public final class Base64url {
    private static final int BASE64URL_FLAGS = Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP;

    public static String encodeToString(byte[] input) {
        return Base64.encodeToString(input, BASE64URL_FLAGS);
    }

    public static byte[] encode(byte[] input) {
        return Base64.encode(input, BASE64URL_FLAGS);
    }

    public static byte[] decode(String input) {
        return Base64.decode(input, BASE64URL_FLAGS);
    }

    private Base64url() {

    }
}
