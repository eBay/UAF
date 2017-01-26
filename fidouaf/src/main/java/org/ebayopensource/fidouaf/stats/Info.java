package org.ebayopensource.fidouaf.stats;

public class Info {
	public String description = "Example UAF server";
	public String regRequestEndpoint = "/fidouaf/v1/public/regRequest/{user}";
	public String regResponseEndpoint = "/fidouaf/v1/public/regResponse";
	public String authRequestEndpoint = "/fidouaf/v1/public/authRequest";
	public String authResponseEndpoint = "/fidouaf/v1/public/authResponse";
	public String whitelistuuidEndpoint = "/fidouaf/v1/whitelistuuid/{ure_encodedd_uuid}";
	public String whitelistfacetidEndpoint = "/fidouaf/v1/whitelistfacetid/{url_encoded_facedid}";
	public String historyEndpoint = "/fidouaf/v1/history";
	public String registrationsEndpoint = "/fidouaf/v1/registrations";
}
