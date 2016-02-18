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

package org.ebayopensource.fidouafclient.curl;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import android.os.AsyncTask;

public class Curl {

	public static String toStr(HttpURLConnection response) {

		String result = "";
		try {
			InputStream in = response.getInputStream();
			BufferedReader reader = new BufferedReader(
					new InputStreamReader(in));
			StringBuilder str = new StringBuilder();
			String line = null;
			while ((line = reader.readLine()) != null) {
				str.append(line + "\n");
			}
			in.close();
			result = str.toString();
		} catch (Exception ex) {
			result = "Error";
		}
		return result;
	}
	
	public static String getInSeparateThread(String url) {
		GetAsyncTask async = new GetAsyncTask();
		async.execute(url);
		while (!async.isDone()){
			try {
				Thread.sleep(1);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return async.getResult();
	}
	
	public static String postInSeparateThread(String url, String header, String data) {
		PostAsyncTask async = new PostAsyncTask();
		async.execute(url, header, data);
		while (!async.isDone()){
			try {
				Thread.sleep(1);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return async.getResult();
	}
	
	public static String get(String url) {
		return get(url,null);
	}

	public static String get(String urlStr, String[] header) {
		String ret = "";
		try {

			URL url = new URL(urlStr);
			HttpURLConnection connection = (HttpURLConnection)url.openConnection();

			try {
				if (header != null){
					for (String h : header){
						String[] split = h.split(":");
						connection.setRequestProperty(split[0], split[1]);
					}
				}
				connection.setRequestMethod("GET");
				connection.setDoInput(true);
				connection.setDoInput(true);
				connection.connect();

				ret = Curl.toStr(connection);

			} catch (Exception ex) {
				ex.printStackTrace();
				ret = "{'error_code':'connect_fail','url':'" + url + "'}";
			}
		} catch (Exception e) {
			e.printStackTrace();
			ret = "{'error_code':'connect_fail','e':'" + e + "'}";
		}

		return ret;
	}
	
	public static String post(String url, String header, String data) {
		return post (url, header.split(" "), data);
	}
	
	public static String post(String urlStr, String[] header, String data) {
		String ret = "";
		try {

			URL url = new URL(urlStr);
			HttpURLConnection connection = (HttpURLConnection)url.openConnection();

			if (header != null){
				for (String h : header){
					String[] split = h.split(":");
					connection.setRequestProperty(split[0], split[1]);
				}
			}
			connection.setRequestProperty("Content-Length", String.valueOf(data.length()));
			connection.setRequestMethod("POST");
			connection.setDoInput(true);
			connection.setDoInput(true);
			connection.connect();

			OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream());

			writer.write(data);
			writer.flush();

			try {
				ret = Curl.toStr(connection);

			} catch (Exception ex) {
				ex.printStackTrace();
				ret = "{'error_code':'connect_fail','url':'" + url + "'}";
			}
		} catch (Exception e) {
			e.printStackTrace();
			ret = "{'error_code':'connect_fail','e':'" + e + "'}";
		}

		return ret;
	}

}

class GetAsyncTask extends AsyncTask<String, Integer, String>{

	private String result = null;
	private boolean done = false;
	public boolean isDone() {
		return done;
	}
	public String getResult() {
		return result;
	}
	@Override
	protected String doInBackground(String... args) {
		result = Curl.get(args[0]);
		done = true;
		return result;
	}
	protected void onProgressUpdate(Integer... progress) {
    }
    protected void onPostExecute(String result) {
		this.result = result;
		done = true;
	}
}

class PostAsyncTask extends AsyncTask<String, Integer, String>{

	private String result = null;
	private boolean done = false;
	public boolean isDone() {
		return done;
	}
	public String getResult() {
		return result;
	}
	@Override
	protected String doInBackground(String... args) {
		result = Curl.post(args[0],args[1],args[2]);//(url, header, data)
		done = true;
		return result;
	}
	protected void onProgressUpdate(Integer... progress) {
    }
	@Override
	protected void onPostExecute(String result) {
		this.result = result;
		done = true;
	}
}
