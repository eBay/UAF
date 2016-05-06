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

package org.ebayopensource.fidouafclient.op;

import org.ebayopensource.fido.uaf.msg.TrustedFacets;
import org.ebayopensource.fido.uaf.msg.TrustedFacetsList;
import org.ebayopensource.fido.uaf.msg.Version;
import org.ebayopensource.fidouafclient.curl.Curl;
import org.ebayopensource.fidouafclient.util.Endpoints;
import org.ebayopensource.fidouafclient.util.Preferences;
import org.ebayopensource.fido.uaf.msg.AuthenticatorRegistrationAssertion;
import org.ebayopensource.fido.uaf.msg.ChannelBinding;
import org.ebayopensource.fido.uaf.msg.FinalChallengeParams;
import org.ebayopensource.fido.uaf.msg.OperationHeader;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;
import org.ebayopensource.fido.uaf.msg.asm.obj.RegisterIn;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Base64;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class Reg {
	
	private Gson gson = new GsonBuilder().disableHtmlEscaping().create();

	public String getUafMsgRegRequest (String username, String facetId, Context context){
		String msg = "{\"uafProtocolMessage\":\"";
		try {
			String serverResponse = getRegRequest(username);
			JSONArray reg = new JSONArray(serverResponse);
			String appID = ((JSONObject) reg.get(0)).getJSONObject("header").getString("appID");
			Version version = (new Gson()).fromJson(((JSONObject) reg.get(0)).getJSONObject("header").getString("upv"),Version.class);
			// If the AppID is null or empty, the client MUST set the AppID to be the FacetID of
			// the caller, and the operation may proceed without additional processing.
			if (appID == null || appID.isEmpty()) {
				if (this.checkAppSignature(facetId, context)) {
					((JSONObject) reg.get(0)).getJSONObject("header").put("appID", facetId);
				}
			}else {
				//If the AppID is not an HTTPS URL, and matches the FacetID of the caller, no additional
				// processing is necessary and the operation may proceed.
				if (!facetId.equals(appID)) {
					// Begin to fetch the Trusted Facet List using the HTTP GET method
					String trustedFacetsJson = this.getTrustedFacets(appID);
					TrustedFacetsList trustedFacets = (new Gson()).fromJson(trustedFacetsJson, TrustedFacetsList.class);
					// After processing the trustedFacets entry of the correct version and removing
					// any invalid entries, if the caller's FacetID matches one listed in ids,
					// the operation is allowed.
					boolean facetFound = this.processTrustedFacetsList(trustedFacets,version,facetId);
					if ((!facetFound) || (!this.checkAppSignature(facetId, context))){
						return msg;
					}
				} else {
					if (! this.checkAppSignature(facetId, context)) {
						return msg;
					}
				}
			}
			JSONObject uafMsg = new JSONObject();
			uafMsg.put("uafProtocolMessage", reg.toString());
			return uafMsg.toString();
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return msg;
	}
	
	public String getEmptyUafMsgRegRequest (){
		String msg = "{\"uafProtocolMessage\":";
		msg = msg + "\"\"";
		msg = msg + "}";
		return msg;
	}

	/**
	 * From among the objects in the trustedFacet array, select the one with the version matching
	 * that of the protocol message version. The scheme of URLs in ids MUST identify either an
	 * application identity (e.g. using the apk:, ios: or similar scheme) or an https: Web Origin [RFC6454].
	 * Entries in ids using the https:// scheme MUST contain only scheme, host and port components,
	 * with an optional trailing /. Any path, query string, username/password, or fragment information
	 * MUST be discarded.
	 * @param trustedFacetsList
	 * @param version
	 * @param facetId
     * @return true if appID list contains facetId (current Android application's signature).
     */
	public boolean processTrustedFacetsList(TrustedFacetsList trustedFacetsList, Version version, String facetId){
		for (TrustedFacets trustedFacets: trustedFacetsList.getTrustedFacets()){
			// select the one with the version matching that of the protocol message version
			if ((trustedFacets.getVersion().minor >= version.minor)
					&& (trustedFacets.getVersion().major <= version.major)) {
				//The scheme of URLs in ids MUST identify either an application identity
				// (e.g. using the apk:, ios: or similar scheme) or an https: Web Origin [RFC6454].
				for (String id : trustedFacets.getIds()) {
					if (id.equals(facetId)) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * A double check about app signature that was passed by MainActivity as facetID.
	 * @param facetId a string value composed by app hash. I.e. android:apk-key-hash:Lir5oIjf552K/XN4bTul0VS3GfM
	 * @param context Application Context
     * @return true if the signature executed on runtime matches if signature sent by MainActivity
     */
	public boolean checkAppSignature(String facetId, Context context){
		try {
			PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
			for (Signature sign: packageInfo.signatures) {
				byte[] sB = sign.toByteArray();
				MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
				messageDigest.update(sign.toByteArray());
				String currentSignature = Base64.encodeToString(messageDigest.digest(), Base64.DEFAULT);
				if (currentSignature.toLowerCase().contains(facetId.split(":")[2].toLowerCase())){
					return true;
				}
			}
		} catch (PackageManager.NameNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return false;
	}

	/**
	 * Fetches the Trusted Facet List using the HTTP GET method. The location MUST be identified with
	 * an HTTPS URL. A Trusted Facet List MAY contain an unlimited number of entries, but clients MAY
	 * truncate or decline to process large responses.
	 * @param appID an identifier for a set of different Facets of a relying party's application.
	 *              The AppID is a URL pointing to the TrustedFacets, i.e. list of FacetIDs related
	 *              to this AppID.
	 * @return  Trusted Facets List
     */
	public String getTrustedFacets(String appID){
		//TODO The caching related HTTP header fields in the HTTP response (e.g. “Expires”) SHOULD be respected when fetching a Trusted Facets List.
		return Curl.getInSeparateThread(appID);
	}

	public String getRegRequest (String username){
		String url = Endpoints.getRegRequestEndpoint()+username;
		return Curl.getInSeparateThread(url);
	}
	
	public RegisterIn getRegIn(String username){
		RegisterIn ret = new RegisterIn();
		String url = Endpoints.getRegRequestEndpoint()+username;
		String regRespFromServer = Curl.getInSeparateThread(url);
		RegistrationRequest regRequest = null;
		try{
			regRequest = gson.fromJson(regRespFromServer, RegistrationRequest[].class)[0];
			ret.appID = regRequest.header.appID;
			ret.attestationType = 15879;
			ret.finalChallenge = getFinalChalenge(regRequest);
			ret.username = username;
			freezeRegResponse(regRequest);
		} catch (Exception e){
			
		}
		
		return ret;
	}
	
	public String clientSendRegResponse (String uafMessage){
		StringBuffer res = new StringBuffer();
		String decoded = null;
		try {
			JSONObject json = new JSONObject (uafMessage);
			decoded = json.getString("uafProtocolMessage").replace("\\", "");
		} catch (JSONException e) {
			e.printStackTrace();
		}
		
		res.append("#uafMessageegOut\n"+decoded);
		String headerStr = "Content-Type:Application/json Accept:Application/json";
		res.append("\n\n#ServerResponse\n");
		String serverResponse = Curl.postInSeparateThread(Endpoints.getRegResponseEndpoint(), headerStr , decoded);
		res.append(serverResponse);
		saveAAIDandKeyID(serverResponse);
		return res.toString();
	}
	
	public String sendRegResponse (String regOut){
		StringBuffer res = new StringBuffer();
		res.append("{regOut}"+regOut);
		String json = getRegResponseForSending(regOut);
		res.append("{regResponse}"+json);
		String headerStr = "Content-Type:Application/json Accept:Application/json";
		res.append("{ServerResponse}");
		String serverResponse = Curl.postInSeparateThread(Endpoints.getRegResponseEndpoint(), headerStr , json);
		res.append(serverResponse);
		saveAAIDandKeyID(serverResponse);
		return res.toString();
	}
	
	
	private void saveAAIDandKeyID(String res) {
		try{
			JSONArray regRecord = new JSONArray(res);
			JSONObject authenticator = regRecord.getJSONObject(0).getJSONObject("authenticator");
			Preferences.setSettingsParam("AAID", authenticator.getString("AAID"));
			Preferences.setSettingsParam("keyID", authenticator.getString("KeyID"));
		} catch (Exception e){
			e.printStackTrace();
		}
	}

	public String getRegResponseForSending (String regOut){
		String ret = null;
		try{
		RegistrationResponse regResponse = gson.fromJson(Preferences.getSettingsParam("regResponse"), RegistrationResponse.class);
		JSONObject assertions = new JSONObject(regOut);
		regResponse.assertions = new AuthenticatorRegistrationAssertion[1];
		regResponse.assertions[0] = new AuthenticatorRegistrationAssertion();
		regResponse.assertions[0].assertionScheme = assertions.getJSONObject("responseData").getString("assertionScheme");
		regResponse.assertions[0].assertion = assertions.getJSONObject("responseData").getString("assertion");
		RegistrationResponse[] forSending = new RegistrationResponse[1];
		forSending[0] = regResponse;
		return gson.toJson(forSending, RegistrationResponse[].class);
		} catch (Exception e){
			e.printStackTrace();
		}
		
		return ret;
	}

	private String getFinalChalenge(RegistrationRequest regRequest) {
		FinalChallengeParams fcParams = new FinalChallengeParams();
		fcParams.appID = regRequest.header.appID;
		Preferences.setSettingsParam("appID", fcParams.appID);
		fcParams.facetID = getFacetId();
		fcParams.challenge = regRequest.challenge;
		fcParams.channelBinding = new ChannelBinding();
		fcParams.channelBinding.cid_pubkey = "";
		fcParams.channelBinding.serverEndPoint = "";
		fcParams.channelBinding.tlsServerCertificate = "";
		fcParams.channelBinding.tlsUnique = "";
		return Base64.encodeToString(gson.toJson(
				fcParams).getBytes(), Base64.URL_SAFE);
	}

	private String getFacetId() {
		return "";
	}
	
	public void freezeRegResponse (RegistrationRequest regRequest){
		String json = gson.toJson(getRegResponse(regRequest), RegistrationResponse.class);
		Preferences.setSettingsParam("regResponse", json);
	}
	
	public RegistrationResponse getRegResponse (RegistrationRequest regRequest){
		RegistrationResponse response = new RegistrationResponse();
		
		response.header = new OperationHeader();
		response.header.serverData = regRequest.header.serverData;
		response.header.appID = regRequest.header.appID;
		response.header.op = regRequest.header.op;
		response.header.upv = regRequest.header.upv;
		response.fcParams = getFinalChalenge(regRequest);
		
		return response;
	}

}
