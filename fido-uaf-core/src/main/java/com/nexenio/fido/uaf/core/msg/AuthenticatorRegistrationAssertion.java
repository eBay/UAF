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
public class AuthenticatorRegistrationAssertion {

    /**
     * The name of the Assertion Scheme used to encode the assertion. See UAF Supported Assertion Schemes for details.
     * Note: This assertionScheme is not part of a signed object and hence considered the suspected assertionScheme.
     */
    private String assertionScheme;

    /**
     * base64url(byte[1..4096]) Contains the TAG_UAFV1_REG_ASSERTION object containing the assertion scheme specific KeyRegistrationData (KRD) object which in turn contains the newly generated UAuth.pub and is signed by the Attestation Private Key.
     * This assertion must be generated by the authenticator and it must be used only in this Registration operation. The format of this assertion can vary from one assertion scheme to another (e.g. for "UAFV1TLV" assertion scheme it must be TAG_UAFV1_KRD).
     */
    private String assertion;

}
