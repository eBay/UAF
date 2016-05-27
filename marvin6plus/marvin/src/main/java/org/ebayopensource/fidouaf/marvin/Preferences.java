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

package org.ebayopensource.fidouaf.marvin;

import android.content.SharedPreferences;

public class Preferences {
	
	private static String PREFERENCES = "Preferences";

	public static String getSettingsParam(String paramName) {
		SharedPreferences settings = getPrefferences();
		return settings.getString(paramName, "");
	}

	public static long getSettingsParamLong(String paramName) {
		SharedPreferences settings = getPrefferences();
		return settings.getLong(paramName, 0);
	}

	public static SharedPreferences getPrefferences() {
		SharedPreferences settings = ApplicationContextProvider.getContext()
				.getSharedPreferences(PREFERENCES, 0);
		return settings;
	}

	public static void setSettingsParam(String paramName, String paramValue) {
		SharedPreferences settings = getPrefferences();
		SharedPreferences.Editor editor = settings.edit();
		editor.putString(paramName, paramValue);
		editor.commit();
	}

	public static void removeSettingsParam(String paramName) {
		SharedPreferences settings = getPrefferences();
		SharedPreferences.Editor editor = settings.edit();
		editor.remove(paramName);
		editor.commit();
	}

	public static void setSettingsParamLong(String paramName, long paramValue) {
		SharedPreferences settings = getPrefferences();
		SharedPreferences.Editor editor = settings.edit();
		editor.putLong(paramName, paramValue);
		editor.commit();
	}

}
