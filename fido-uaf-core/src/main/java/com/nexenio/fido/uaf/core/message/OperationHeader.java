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
public class OperationHeader {

    /**
     * UAF protocol version. Major version must be 1 and minor version must be 0.
     */
    @SerializedName("upv")
    private Version protocolVersion;

    /**
     * Name of FIDO operation this message relates to.
     * Note: "Auth" is used for both authentication and transaction confirmation.
     */
    @SerializedName("op")
    private Operation operation;

    /**
     * The application identifier that the relying party would like to assert.
     * There are three ways to set the AppID [FIDOAppIDAndFacets]:
     * <ul>
     * <li>If the element is missing or empty in the request, the FIDO UAF Client must set it to theFacetID of the caller.</li>
     * <li>If the appID present in the message is identical to the FacetID of the caller, the FIDO UAF Client must accept it.</li>
     * <li>If it is an URI with HTTPS protocol scheme, the FIDO UAF Client must use it to load the list of trusted facet identifiers from the specified URI. The FIDO UAF Client must only accept the request, if the facet identifier of the caller matches one of the trusted facet identifiers in the list returned from dereferencing this URI.</li>
     * </ul>
     * <p>
     * The new key pair that the authenticator generates will be associated with this application identifier.
     * Security Relevance: The application identifier is used by the FIDO UAF Client to verify the eligibility of an application to trigger the use of a specific UAuth.Key. See [FIDOAppIDAndFacets].
     */
    @SerializedName("appID")
    private String appId;

    /**
     * A session identifier created by the relying party.
     * Note: The relying party can opaquely store things like expiration times for the registration session, protocol version used and other useful information in serverData. This data is opaque to FIDO UAF Clients. FIDO Servers may reject a response that is lacking this data or is containing unauthorized modifications to it.
     * Servers that depend on the integrity of serverData should apply appropriate security measures, as described in Registration Request Generation Rules for FIDO Server and section ServerData and KeyHandle.
     */
    @SerializedName("serverData")
    private String serverData;

}
