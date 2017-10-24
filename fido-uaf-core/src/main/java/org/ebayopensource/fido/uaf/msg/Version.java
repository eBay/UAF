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

package org.ebayopensource.fido.uaf.msg;

public class Version {
    public int major;
    public int minor;
    
    public Version (int major, int minor){
		this.major = major;
		this.minor = minor;
    }

    public Version() {
    }

    /**
     * Getter for property 'major'.
     *
     * @return Value for property 'major'.
     */
    public int getMajor() {
        return major;
    }

    /**
     * Setter for property 'major'.
     *
     * @param major Value to set for property 'major'.
     */
    public void setMajor(int major) {
        this.major = major;
    }

    /**
     * Getter for property 'minor'.
     *
     * @return Value for property 'minor'.
     */
    public int getMinor() {
        return minor;
    }

    /**
     * Setter for property 'minor'.
     *
     * @param minor Value to set for property 'minor'.
     */
    public void setMinor(int minor) {
        this.minor = minor;
    }
}
