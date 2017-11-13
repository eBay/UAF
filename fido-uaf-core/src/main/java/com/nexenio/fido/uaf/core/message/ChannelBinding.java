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

package com.nexenio.fido.uaf.core.message;

import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class ChannelBinding {

    /**
     * The field serverEndPoint must be set to the base64url-encoded hash of the TLS server certificate if this is available. The hash function must be selected as follows:
     * <ul>
     * <li>if the certificate's signatureAlgorithm uses a single hash function and that hash function is either MD5 [RFC1321] or SHA-1 [RFC6234], then use SHA-256 [FIPS180-4];</li>
     * <li>if the certificate's signatureAlgorithm uses a single hash function and that hash function is neither MD5 nor SHA-1, then use the hash function associated with the certificate'ssignatureAlgorithm;</li>
     * <li>if the certificate's signatureAlgorithm uses no hash functions, or uses multiple hash functions, then this channel binding type's channel bindings are undefined at this time (updates to this channel binding type may occur to address this issue if it ever arises)</li>
     * </ul>
     * This field must be absent if the TLS server certificate is not available to the processing entity (e.g., the FIDO UAF Client) or the hash function cannot be determined as described.
     */
    @SerializedName("serverEndPoint")
    private String serverEndpoint;

    /**
     * This field must be absent if the TLS server certificate is not available to the FIDO UAF Client.
     * This field must be set to the base64url-encoded, DER-encoded TLS server certificate, if this data is available to the FIDO UAF Client.
     */
    @SerializedName("tlsServerCertificate")
    private String tlsServerCertificate;

    /**
     * Must be set to the base64url-encoded TLS channel Finished structure. It must, however, be absent, if this data is not available to the FIDO UAF Client [RFC5929].
     */
    @SerializedName("tlsUnique")
    private String tlsUnique;

    /**
     * Must be absent if the client TLS stack doesn't provide TLS ChannelID [ChannelID] information to the processing entity (e.g., the web browser or client application).
     * Must be set to "unused" if TLS ChannelID information is supported by the client-side TLS stack but has not been signaled by the TLS (web) server.
     * Otherwise, it must be set to the base64url-encoded serialized [RFC4627] JwkKey structure using UTF-8 encoding.
     */
    @SerializedName("cid_pubkey")
    private String channelIdPublicKey;

}
