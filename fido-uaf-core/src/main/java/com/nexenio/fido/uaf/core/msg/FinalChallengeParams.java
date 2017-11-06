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
public class FinalChallengeParams {

    /**
     * The value must be taken from the appId field of the OperationHeader
     */
    @SerializedName("appID")
    private String appId;

    /**
     * The value must be taken from the challenge field of the request (e.g. RegistrationRequest.challenge, AuthenticationRequest.challenge).
     */
    @SerializedName("challenge")
    private String challenge;

    /**
     * The value is determined by the FIDO UAF Client and it depends on the calling application. See [FIDOAppIDAndFacets] for more details. Security Relevance: The facetID is determined by the FIDO UAF Client and verified against the list of trusted facets retrieved by dereferencing the appId of the calling application.
     */
    @SerializedName("facetID")
    private String facetId;

    /**
     * Contains the TLS information to be sent by the FIDO Client to the FIDO Server, binding the TLS channel to the FIDO operation.
     */
    @SerializedName("channelBinding")
    private ChannelBinding channelBinding;

}
