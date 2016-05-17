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

package org.ebayopensource.webauthn.res.util;

import java.util.HashMap;
import java.util.Map;

import org.ebayopensource.webauthn.crypto.KeyUtil;
import org.ebayopensource.webauthn.msg.RegistrationRecord;

public class StorageImpl implements StorageInterface {

	private static StorageImpl instance = new StorageImpl();
	private Map<String, RegistrationRecord> db = new HashMap<String, RegistrationRecord>();
	private KeyUtil keyUtil = new KeyUtil();
	
	private StorageImpl() {
		// Init
		try {
			RegistrationRecord preZero = new RegistrationRecord();
			preZero.key = "TheSourceCode";
			preZero.pubKey =
					keyUtil.getPubKeyAsPem(
					"x15EJFoDr-8r6_ZG_XxJH5olBL6ulPJb4x3-SQHopftZoc--bd72iBq_AVu4umHwLzuMJ1hwRuLEhRzhkWNL4y1-gbiT_g4EnCx0TLu9fY0nVMtkC1QJ4foOkvhnj5WBNPFvXay-uwLu32siqEfc9bMFmyLsb5PO9OwFRw5PlEEH7PzrUyZTGfd03hiP61D3b2iFdtzHml6d-ATcSJg9BQRg5QojJTdqjhDdrB2iLdbS1enMxkgHE_L8lSYZOHeIthWVLhlDSC6TsFd6NHgwnNqk4oVkfwydobK9RhG0hJwCyR2GoEy4s3VIHYzCaSoFnd9HYROssQn6CZwW_tzx-w"
					, "AQAB"
					);
			this.store(preZero);
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

	public void store(RegistrationRecord record)
			throws DuplicateKeyException, SystemErrorException {
		if (record != null) {
				if (db.containsKey(record.key)) {
					throw new DuplicateKeyException();
				}
				db.put(record.key, record);
			}

	}

	public RegistrationRecord readRegistrationRecord(String key) {
		return db.get(key);
	}

	public void update(RegistrationRecord[] records) {
		// TODO Auto-generated method stub

	}

	public void deleteRegistrationRecord(String key) {
		if (db != null && db.containsKey(key)) {
			db.remove(key);
		}
	}

	public Map<String, RegistrationRecord> dbDump() {
		return db;
	}

	public RegistrationRecord getRegRecord(String key) {
		return db.get(key);
	}

}
