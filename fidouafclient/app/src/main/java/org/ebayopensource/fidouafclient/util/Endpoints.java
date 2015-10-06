package org.ebayopensource.fidouafclient.util;

public class Endpoints {

	public static final String SERVER =
	"http://openidconnect.ebay.com";
	//"http://www.head2toes.org";
	public static final String GET_AUTH_REQUEST = "/fidouaf/v1/public/authRequest";
	public static final String POST_AUTH_RESPONSE = "/fidouaf/v1/public/authResponse";
	public static final String POST_DEREG_RESPONSE = "/fidouaf/v1/public/deregRequest";
	public static final String GET_REG_REQUEST = "/fidouaf/v1/public/regRequest/";
	public static final String POST_REG_RESPONSE = "/fidouaf/v1/public/regResponse";


	private static void check() {
		String serverEndpoint = Preferences.getSettingsParam("serverEndpoint");
		if (serverEndpoint!=null && serverEndpoint.length() == 0){
			setDefaults();
		}

	}

	public static String getServer() {
		check();
		return Preferences.getSettingsParam("serverEndpoint");
	}


	public static String getAuthResponseEndpoint() {
		check();
		return getServer()+Preferences.getSettingsParam("authRes");
	}


	public static String getAuthRequestEndpoint() {
		check();
		return getServer()+Preferences.getSettingsParam("authReg");
	}


	public static String getDeregEndpoint() {
		check();
		return getServer()+Preferences.getSettingsParam("dereg");
	}


	public static String getRegResponseEndpoint() {
		check();
		return getServer()+Preferences.getSettingsParam("regRes");
	}


	public static String getRegRequestEndpoint() {
		check();
		return getServer()+Preferences.getSettingsParam("regReg");
	}

	//Path
	public static String getAuthResponsePath() {
		check();
		return Preferences.getSettingsParam("authRes");
	}


	public static String getAuthRequestPath() {
		check();
		return Preferences.getSettingsParam("authReg");
	}


	public static String getDeregPath() {
		check();
		return Preferences.getSettingsParam("dereg");
	}


	public static String getRegResponsePath() {
		check();
		return Preferences.getSettingsParam("regRes");
	}


	public static String getRegRequestPath() {
		check();
		return Preferences.getSettingsParam("regReg");
	}

	public static void setDefaults (){
		Preferences.setSettingsParam("serverEndpoint", SERVER);
		Preferences.setSettingsParam("authReg", GET_AUTH_REQUEST);
		Preferences.setSettingsParam("authRes", POST_AUTH_RESPONSE);
		Preferences.setSettingsParam("regReg", GET_REG_REQUEST);
		Preferences.setSettingsParam("regRes", POST_REG_RESPONSE);
		Preferences.setSettingsParam("dereg", POST_DEREG_RESPONSE);
	}


	public static void save(String server, String authReq, String authRes,
			String regReq, String regRes, String dereg) {
		Preferences.setSettingsParam("serverEndpoint", server);
		Preferences.setSettingsParam("authReg", authReq);
		Preferences.setSettingsParam("authRes", authRes);
		Preferences.setSettingsParam("regReg", regReq);
		Preferences.setSettingsParam("regRes", regRes);
		Preferences.setSettingsParam("dereg", dereg);
	}
}
