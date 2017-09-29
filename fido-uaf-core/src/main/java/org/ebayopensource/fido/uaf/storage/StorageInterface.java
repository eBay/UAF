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

package org.ebayopensource.fido.uaf.storage;

import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;

public interface StorageInterface {

	public void storeServerDataString(String username, String serverDataString);

	public String getUsername(String serverDataString);

	public void storeRegRecord(RegistrationRecord[] records)
			throws DuplicateKeyException, SystemErrorException;

	public RegistrationRecord readRegistrationRecord(String key);

	public void storeRegReq(RegistrationRequest[] regReq);
	public RegistrationRequest[] readRegReq();

	public void update(RegistrationRecord[] records);
}
