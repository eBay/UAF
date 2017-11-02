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
public class Extension {

    /**
     * Identifies the extension.
     */
    private String id;

    /**
     * Contains arbitrary data with a semantics agreed between server and client. The data is base64url-encoded.
     * This field may be empty.
     */
    private String data;

    /**
     * Indicates whether unknown extensions must be ignored (false) or must lead to an error (true).
     * <li>
     * <ul>A value of false indicates that unknown extensions must be ignored</ul>
     * <ul>A value of true indicates that unknown extensions must result in an error</ul>
     * </li>
     */
    private boolean failIfUnknown;

}
