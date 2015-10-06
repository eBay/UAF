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

package org.ebayopensource.fidouafclient;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.ebayopensource.fido.uaf.client.op.Auth;
import org.ebayopensource.fido.uaf.client.op.Reg;
import org.json.JSONObject;

import com.google.gson.Gson;

import android.os.Bundle;
import android.app.Activity;
import android.content.Intent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;

public class ExampleFidoUafActivity extends Activity {

	private Logger logger = Logger.getLogger(this.getClass().getName());
	private Gson gson = new Gson();
	private TextView operation;
	private TextView uafMsg;
	private Reg regOp = new Reg();
	private Auth authOp = new Auth();

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		Bundle extras = this.getIntent().getExtras();
		setContentView(R.layout.activity_fido_uaf);
		operation = (TextView)findViewById(R.id.textViewOperation);
		uafMsg = (TextView)findViewById(R.id.textViewOpMsg);
		operation.setText(extras.getString("UAFIntentType"));
		uafMsg.setText(extras.getString("message"));
	}
	
	private void finishWithResult(){
	    Bundle data = new Bundle();
		String inMsg = this.getIntent().getExtras().getString("message");
		String msg = "";
		try {
			if (inMsg != null && inMsg.length()>0) {
				msg = processOp (inMsg);
			}
		} catch (Exception e){
			logger.log(Level.WARNING, "Not able to get registration response", e);
		}
		data.putString("message", msg);
	    Intent intent = new Intent();
	    intent.putExtras(data);
	    setResult(RESULT_OK, intent);
	    finish();
	}

	private String processOp (String inUafOperationMsg){
		String msg = "";
		String inMsg = extract(inUafOperationMsg);
		if (inMsg.contains("\"Reg\"")) {
			msg = regOp.register(inMsg);
		} else if (inMsg.contains("\"Auth\"")) {
			msg = authOp.auth(inMsg);
		} else if (inMsg.contains("\"Dereg\"")) {

		}
		return msg;
	}



	public void proceed(View view) {
		finishWithResult();
	}
	
	public void back(View view) {
		Bundle data = new Bundle();
		String msg = "";
		logger.info("Registration canceled by user");
		data.putString("message", msg);
		Intent intent = new Intent();
		intent.putExtras(data);
		setResult(RESULT_OK, intent);
		finish();
	}
	
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			startActivity(new Intent(
					"org.ebayopensource.fidouafclient.SettingsActivity"));
		}
		return super.onOptionsItemSelected(item);
	}

	private String extract(String inMsg) {
		try {
			JSONObject tmpJson = new JSONObject(inMsg);
			String uafMsg = tmpJson.getString("uafProtocolMessage");
			uafMsg.replace("\\\"", "\"");
			return uafMsg;
		} catch (Exception e){
			logger.log(Level.WARNING, "Input message is invalid!", e);
			return "";
		}

	}
}
