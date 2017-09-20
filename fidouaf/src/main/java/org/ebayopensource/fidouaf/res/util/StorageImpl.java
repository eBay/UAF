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

package org.ebayopensource.fidouaf.res.util;

import java.util.HashMap;
import java.util.Map;

import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.storage.DuplicateKeyException;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.storage.StorageInterface;
import org.ebayopensource.fido.uaf.storage.SystemErrorException;

public class StorageImpl implements StorageInterface {

	private RegistrationRequest[] lastRegReq = null;
	private static StorageImpl instance = new StorageImpl();
	private Map<String, RegistrationRecord> db = new HashMap<String, RegistrationRecord>();

	private StorageImpl() {
		// Init
		try {
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static StorageImpl getInstance() {
		return instance;
	}

	public void storeServerDataString(String username, String serverDataString) {
		// TODO Auto-generated method stub
	}

	public String getUsername(String serverDataString) {
		// TODO Auto-generated method stub
		return null;
	}

	public void storeRegRecord(RegistrationRecord[] records)
			throws DuplicateKeyException, SystemErrorException {
		if (records != null && records.length > 0) {
			for (int i = 0; i < records.length; i++) {
				if (db.containsKey(records[i].authenticator.toString())) {
					throw new DuplicateKeyException();
				}
				db.put(records[i].authenticator.toString(), records[i]);
			}

		}
	}

	public RegistrationRecord readRegistrationRecord(String key) {
		return db.get(key);
	}

	@Override
	public void storeRegReq(RegistrationRequest[] regReq) {
		this.lastRegReq = regReq;
	}

	@Override
	public RegistrationRequest[] readRegReq() {
		return lastRegReq;
	}

	public void update(RegistrationRecord[] records) {
		// TODO Auto-generated method stub

	}

	public void deleteRegistrationRecord(String key) {
		if (db != null && db.containsKey(key)) {
			System.out
					.println("!!!!!!!!!!!!!!!!!!!....................deleting object associated with key="
							+ key);
			db.remove(key);
		}
	}

	public Map<String, RegistrationRecord> dbDump() {
		return db;
	}

}
