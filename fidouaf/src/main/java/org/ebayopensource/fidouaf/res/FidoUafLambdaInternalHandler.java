package org.ebayopensource.fidouaf.res;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.GetItemSpec;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import java.util.Base64;

public class FidoUafLambdaInternalHandler extends FidoUafResource implements RequestStreamHandler{
	// Initialize the Log4j logger.
	//static final Logger logger = LogManager.getLogger(FidoUafLambdaHandler.class);

	//static final String UserTableName = System.getenv("DB_USER_TABLE_NAME");
	//static final String DefaultUser = System.getenv("DEFAULT_USER_IDENTITY"); // b342ff9c-9924-4421-9071-32763f907d9b
	
	JSONParser parser = new JSONParser();

	public FidoUafLambdaInternalHandler(){
		//logger.debug("Created FIDO UAF Server Lambda Handler");
		//logger.debug("Default user is " + DefaultUser);
		//logger.debug("User Table name user is " + UserTableName);
	}


	public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context) throws IOException {
    	LambdaLogger logger = context.getLogger();
		//This lambda will exercise all the different components utilised by the CID hub to ensure that their health is OK.
		//Returns 200 with output of each check
		//Returns 500 with output of each check if it fails
        //LambdaLogger logger = context.getLogger(); //basic cloudwatch logger
        logger.log("Loading Java Lambda handler");

        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        JSONArray event = null;
        try {
            event = (JSONArray)parser.parse(reader);
			logger.log("Successfully parsed the input stream to a JSONObject");
			logger.log(event.toJSONString());
			AuthenticatorRecord[] ar_response = processAuthResponse(event.toJSONString());
			//Simplification - only return the first authenticator record
			String json_body = gson.toJson(ar_response[0]);
			outputStream.write(json_body.getBytes());
            
        } catch(ParseException pex) {
	        //check if keep-alive event
            JSONObject event2 = null;
            try {
				event2 = (JSONObject)parser.parse(reader);
		        if (event2.containsKey("source") && 
		        		event2.containsKey("detail-type") && 
		        		event2.get("source").toString().equals("aws.events") && 
		        		event2.get("detail-type").toString().equals("Scheduled Event"))
		        {
		        	logger.log("Received a keep-alive event");
		            OutputStreamWriter writer = new OutputStreamWriter(outputStream, "UTF-8");
		            writer.write("{ \"response\" : \"OK\"}");  
		            writer.close();
		            return;
		        }
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				logger.log("Failed to parse the input stream to a JSONObject");
			}
        }
	}
}