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
public class Policy {

    /**
     * This field is a two-dimensional array describing the required authenticator characteristics for the server to accept either a FIDO registration, or authentication operation for a particular purpose.
     * This two-dimensional array can be seen as a list of sets. List elements (i.e. the sets) are alternatives (OR condition).
     * All elements within a set must be combined:
     * The first array index indicates OR conditions (i.e. the list). Any set of authenticator(s) satisfying these MatchCriteria in the first index is acceptable to the server for this operation.
     * Sub-arrays of MatchCriteria in the second index (i.e. the set) indicate that multiple authenticators (i.e. each set element) must be registered or authenticated to be accepted by the server.
     * The MatchCriteria array represents ordered preferences by the server. Servers must put their preferred authenticators first, and FIDO UAF Clients should respect those preferences, either by presenting authenticator options to the user in the same order, or by offering to perform the operation using only the highest-preference authenticator(s).
     */
    @SerializedName("accepted")
    private MatchCriteria[][] accepted;

    /**
     * Any authenticator that matches any of MatchCriteria contained in the field disallowed must be excluded from eligibility for the operation, regardless of whether it matches any MatchCriteria present in the accepted list, or not.
     */
    @SerializedName("disallowed")
    public MatchCriteria[] disallowed;

}
