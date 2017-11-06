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
public class JwkKey {

    /**
     * Denotes the key type used for Channel ID. At this time only elliptic curve is supported by [ChannelID], so it must be set to "EC" [JWA].
     */
    @SerializedName("kty")
    private String keyType = "EC";

    /**
     * Denotes the elliptic curve on which this public key is defined. At this time only the NIST curve secp256r1 is supported by [ChannelID], so the ellipticCurve parameter must be set to "P-256".
     */
    @SerializedName("crv")
    private String ellipticCurve = "P-256";

    /**
     * Contains the base64url-encoding of the x coordinate of the public key (big-endian, 32-byte value).
     */
    @SerializedName("x")
    private String x;

    /**
     * Contains the base64url-encoding of the y coordinate of the public key (big-endian, 32-byte value).
     */
    @SerializedName("y")
    private String y;

}
