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
public class RegistrationRequest {

    /**
     * Operation operationHeader. Header.op must be "Reg".
     */
    private OperationHeader operationHeader;

    /**
     * Server-provided challenge value
     */
    private String challenge;

    /**
     * A human-readable user name intended to allow the user to distinguish and select from among different accounts at the same relying party.
     */
    private String userName;

    /**
     * Describes which types of authenticators are acceptable for this registration operation.
     */
    private Policy policy;

}
