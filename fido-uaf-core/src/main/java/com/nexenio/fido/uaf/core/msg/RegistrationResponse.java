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

import lombok.Data;

@Data
public class RegistrationResponse {

    /**
     * Header.op must be "Reg".
     */
    private OperationHeader operationHeader;

    /**
     * The base64url-encoded serialized [RFC4627] FinalChallengeParams using UTF8 encoding (see FinalChallengeParams dictionary) which contains all parameters required for the server to verify the Final Challenge.
     */
    private String finalChallengeParams;

    /**
     * Response data for each Authenticator being registered.
     */
    private AuthenticatorRegistrationAssertion[] assertions;

}
