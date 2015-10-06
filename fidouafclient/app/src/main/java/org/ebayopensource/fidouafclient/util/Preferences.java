package org.ebayopensource.fidouafclient.util;

import android.content.SharedPreferences;

public class Preferences {
	
	private static String PREFERANCES = "Preferances";

	public static String getSettingsParam(String paramName) {
		SharedPreferences settings = getPrefferences();
		return settings.getString(paramName, "");
	}

	public static SharedPreferences getPrefferences() {
		SharedPreferences settings = ApplicationContextProvider.getContext()
				.getSharedPreferences(PREFERANCES, 0);
		return settings;
	}

	public static void setSettingsParam(String paramName, String paramValue) {
		SharedPreferences settings = getPrefferences();
		SharedPreferences.Editor editor = settings.edit();
		editor.putString(paramName, paramValue);
		editor.commit();
	}

	public static void setSettingsParamLong(String paramName, long paramValue) {
		SharedPreferences settings = getPrefferences();
		SharedPreferences.Editor editor = settings.edit();
		editor.putLong(paramName, paramValue);
		editor.commit();
	}

}
