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


import java.util.logging.Logger;

import org.ebayopensource.fidouafclient.util.Endpoints;
import org.ebayopensource.fidouafclient.util.Preferences;

import android.app.Activity;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;


public class SettingsActivity extends Activity {
	
	private Logger logger = Logger.getLogger(this.getClass().getName());
	private EditText username;
	private EditText regReqEndpoint;
	private EditText regResEndpoint;
	private EditText authReqEndpoint;
	private EditText authResEndpoint;
	private EditText dereqEndpoint;
	private EditText serverEndpoint;
	private TextView msgs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        logger.info("  [APP][SettingsActivity]  ");
        setContentView(R.layout.activity_settings);
        regReqEndpoint = (EditText) findViewById(R.id.regRequestEndpoint);
        regResEndpoint = (EditText) findViewById(R.id.regResponseEndpoint);
        authResEndpoint = (EditText) findViewById(R.id.authResponseEndpoint);
        authReqEndpoint = (EditText) findViewById(R.id.authRequestEndpoint);
        dereqEndpoint = (EditText) findViewById(R.id.deregEndpoint);
        serverEndpoint = (EditText) findViewById(R.id.server);
        username = (EditText) findViewById(R.id.username);
        msgs = (TextView) findViewById(R.id.settingsMsgs);
        populate();
    }
    
	private void populate() {
		this.username.setText(Preferences.getSettingsParam("username"));
		this.serverEndpoint.setText(Endpoints.getServer());
		this.authReqEndpoint.setText(Endpoints.getAuthRequestPath());
		this.authResEndpoint.setText(Endpoints.getAuthResponsePath());
		this.regReqEndpoint.setText(Endpoints.getRegRequestPath());
		this.regResEndpoint.setText(Endpoints.getRegResponsePath());
		this.dereqEndpoint.setText(Endpoints.getDeregPath());
	}

	public void back(View view) {
		finish();
	}
	
	public void reset(View view) {
		Endpoints.setDefaults();
		populate();
	}

	public void save(View view) {
		Preferences.setSettingsParam("username", this.username.getText().toString());
		Endpoints.save(
				this.serverEndpoint.getText().toString(),
				this.authReqEndpoint.getText().toString(),
				this.authResEndpoint.getText().toString(),
				this.regReqEndpoint.getText().toString(),
				this.regResEndpoint.getText().toString(),
				this.dereqEndpoint.getText().toString()
				);
		msgs.setText("Saved.");
	}   


    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
