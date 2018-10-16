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
import org.ebayopensource.fido.uaf.storage.DuplicateKeyException;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.storage.StorageInterface;
import org.ebayopensource.fido.uaf.storage.SystemErrorException;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.amazonaws.services.dynamodbv2.document.DeleteItemOutcome;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.DeleteItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.GetItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.PutItemSpec;


public class StorageImpl implements StorageInterface {

	private static StorageImpl instance = new StorageImpl();
	private Map<String, RegistrationRecord> db = new HashMap<String, RegistrationRecord>();
	private Map<String, String> db_names = new HashMap<String, String>();

	protected Gson gson = new GsonBuilder().disableHtmlEscaping().create();

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
		System.out.println("Entered storeServerDataString with username " + username + " and serverDataString " + serverDataString);
		if (db_names.containsKey(serverDataString)){
			db_names.remove(serverDataString);
		}
		db_names.put(serverDataString, username);
	}

	public String getUsername(String serverDataString) {
		System.out.println("Entered getUsername with serverDataString " + serverDataString);
		if (db_names.containsKey(serverDataString)){
			return db_names.get(serverDataString);
		}
		return null;
	}

	public void store(RegistrationRecord[] records)
			throws DuplicateKeyException, SystemErrorException {
		if (records != null && records.length > 0) {
			for (int i = 0; i < records.length; i++) {
				if (db.containsKey(records[i].authenticator.toString())) {
					throw new DuplicateKeyException();
				}
				records[i].authenticator.username = records[i].username;
				db.put(records[i].authenticator.toString(), records[i]);
			}
			storeAWS(records);
		}
	}
	
	private void storeAWS(RegistrationRecord[] records)
	{
		System.out.println("Entered storeAWS to store ... " + records.length + " items");
		final AmazonDynamoDB ddb = AmazonDynamoDBClientBuilder.defaultClient();
		DynamoDB dynamoDB = new DynamoDB(ddb);
		Table registrationsTable = dynamoDB.getTable("fidoregistrations");
		//registrationsTable
		if (records != null && records.length > 0) {
			for (int i = 0; i < records.length; i++) {
				// check duplicate key
				//if (db.containsKey(records[i].authenticator.toString())) {
				//	throw new DuplicateKeyException();
				//}
				records[i].authenticator.username = records[i].username;
				Item regItem = new Item()
						.withPrimaryKey("authenticator_string", records[i].authenticator.toString())
						.withString("record", gson.toJson(records[i]));
				PutItemSpec putSpec = new PutItemSpec().withItem(regItem);
				registrationsTable.putItem(putSpec);
				System.out.println("Successfull put item ... " + i + " with key " + records[i].authenticator.toString());
			}

		}
	}

	public RegistrationRecord readRegistrationRecord(String key) {
		System.out.println("Got request for Registration Record with key " + key);
		RegistrationRecord rr = db.get(key);
		rr = readRegistrationRecordAWS(key);
		if (rr != null)
		{
			System.out.println("Registration Record username details are " + rr.username);
		}
		return rr;
	}
	
	private RegistrationRecord readRegistrationRecordAWS(String key)
	{
		System.out.println("Entered readRegistrationRecordAWS with key " + key);
		final AmazonDynamoDB ddb = AmazonDynamoDBClientBuilder.defaultClient();
		DynamoDB dynamoDB = new DynamoDB(ddb);
		Table registrationsTable = dynamoDB.getTable("fidoregistrations");
		GetItemSpec spec = new GetItemSpec().withPrimaryKey("authenticator_string", key);
        try {
    		System.out.println("Attempting to read the item with key... " + key);
        	//logger.log("Attempting to read the item...");
            Item outcome = registrationsTable.getItem(spec);
    		System.out.println("GetItem succeeded: " + outcome.toJSONPretty());
            return gson.fromJson(outcome.getString("record"), RegistrationRecord.class);
        }
        catch (Exception e) {
        	return null;
        }
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
			deleteRegistrationRecordAWS(key);
		}
	}

	private void deleteRegistrationRecordAWS(String key)
	{
		final AmazonDynamoDB ddb = AmazonDynamoDBClientBuilder.defaultClient();
		DynamoDB dynamoDB = new DynamoDB(ddb);
		Table registrationsTable = dynamoDB.getTable("fidoregistrations");
		DeleteItemSpec spec = new DeleteItemSpec().withPrimaryKey("authenticator_string", key);
        try {
        	//logger.log("Attempting to read the item...");
            DeleteItemOutcome outcome = registrationsTable.deleteItem(spec);
    		System.out.println("Deleted item from DynamoDB with key " + key);
            //logger.log("GetItem succeeded: " + outcome.toJSONPretty());
        }
        catch (Exception e) {
        }
	}

	public Map<String, RegistrationRecord> dbDump() {
		System.out.println("Entered dbDump");
		//TODO - return from DynamoDB
		return db;
	}

}
