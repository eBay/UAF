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

package com.nexenio.fido.uaf.core.storage;

import lombok.Data;

@Data
public class AuthenticatorRecord {

    private static final String DELIMITER = "#";

    private String aaid;
    private String keyId;
    private String deviceId;
    private String userName;
    private String status;

    public String toString() {
        return getAaid() + DELIMITER + getKeyId();
    }
}
