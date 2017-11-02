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
public class AuthenticationRequest {

    /**
     * Must be "AUTHENTICATION"
     */
    private OperationHeader operationHeader;

    /**
     * Server-provided challenge value
     */
    private String challenge;

    /**
     * Transaction data to be explicitly confirmed by the user.
     * The list contains the same transactions content in various content types and various image sizes. Refer to UAFAuthnrMetadata for more information about Transaction Confirmation Display characteristics.
     */
    private Transaction[] transactions;

    /**
     * Server-provided policy defining what types of authenticators are acceptable for this authentication operation.
     */
    private Policy policy;

}
