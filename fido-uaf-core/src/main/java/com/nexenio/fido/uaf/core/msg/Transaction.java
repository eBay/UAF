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

package com.nexenio.fido.uaf.core.msg;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class Transaction {

    /**
     * Contains the MIME Content-Type supported by the authenticator according its metadata statement (see [UAFAuthnrMetadata]).
     * This version of the specification only supports the values text/plain or image/png.
     */
    @SerializedName("contentType")
    private String contentType;

    /**
     * Contains the base64-url encoded transaction content according to the contentType to be shown to the user.
     * If contentType is "text/plain" then the content must be the base64-url encoding of the ASCII encoded text with a maximum of 200 characters.
     */
    @SerializedName("content")
    private String content;

    /**
     * Transaction content PNG characteristics. For the definition of the DisplayPNGCharacteristicsDescriptor structure See [UAFAuthnrMetadata]. This field must be present if the contentType is "image/png".
     */
    @SerializedName("tcDisplayPNGCharacteristics")
    private DisplayPngCharacteristicsDescriptor displayPngCharacteristics;

}
