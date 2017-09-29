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

package org.ebayopensource.fidouaf.res;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriInfo;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.ebayopensource.fido.uaf.msg.*;
import org.ebayopensource.fido.uaf.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.storage.DuplicateKeyException;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.storage.SystemErrorException;
import org.ebayopensource.fido.uaf.tlv.ByteInputStream;
import org.ebayopensource.fidouaf.facets.Facets;
import org.ebayopensource.fidouaf.facets.TrustedFacets;
import org.ebayopensource.fidouaf.res.util.DeregRequestProcessor;
import org.ebayopensource.fidouaf.res.util.FetchRequest;
import org.ebayopensource.fidouaf.res.util.ProcessResponse;
import org.ebayopensource.fidouaf.res.util.StorageImpl;
import org.ebayopensource.fidouaf.stats.Dash;
import org.ebayopensource.fidouaf.stats.Info;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

@Api
@Path("/v1")
public class FidoUafResource {

	protected Gson gson = new GsonBuilder().disableHtmlEscaping().create();

	@GET
	@Path("/info")
	@Produces(MediaType.APPLICATION_JSON)
	@ApiOperation(value = "Print information about the server")
	public Info info() {
		return new Info();
	}
	
	@GET
	@Path("/whitelistuuid/{uuid}")
	@Produces(MediaType.APPLICATION_JSON)
	@ApiOperation(value = "List all UUIDs that are whitelisted by the service")
	public List<String> whitelistuuad(@PathParam("uuid") String uuid) {
		Dash.getInstance().uuids.add(uuid);
		return Dash.getInstance().getInstance().uuids;
	}
	
	@GET
	@Path("/whitelistfacetid/{facetId}")
	@Produces(MediaType.APPLICATION_JSON)
	@ApiOperation(value = "List all Facet IDs that are whitelisted by the service")
	public List<String> whitelistfacetid(@PathParam("facetId") String facetId) {
		Dash.getInstance().facetIds.add(facetId);
		return Dash.getInstance().facetIds;
	}

//	@GET
//	@Path("/stats")
//	@Produces(MediaType.APPLICATION_JSON)
//	@ApiOperation(value = "Get usage information")
//	public Map<String, Object> getStats() {
//		return Dash.getInstance().stats;
//	}

	@GET
	@Path("/history")
	@Produces(MediaType.APPLICATION_JSON)
	@ApiOperation(value = "Get all the operations performed by the server")
	public List<Object> getHistory() {
		return Dash.getInstance().history;
	}

	@GET
	@Path("/pendingRegistrations")
	@Produces(MediaType.APPLICATION_JSON)
	@ApiOperation(value = "Get all valid registrations")
	public RegistrationRequest[] getPendingReg() {
		return StorageImpl.getInstance().readRegReq();
	}

	@GET
	@Path("/registrations")
	@Produces(MediaType.APPLICATION_JSON)
	@ApiOperation(value = "Get all valid registrations")
	public Map<String, RegistrationRecord> getDbDump() {
		return StorageImpl.getInstance().dbDump();
	}


	@POST
	@Path("/public/regRequest")
	@Produces(MediaType.APPLICATION_JSON)
	@ApiOperation(value = "Initiate a new registration")
	public RegistrationRequest[] getRegisReqPublic(UserRegRequest regRequest) {
		return regReqPublic(regRequest);
	}

	private RegistrationRequest[] regReqPublic(UserRegRequest regRequest){
		RegistrationRequest[] regReq = new RegistrationRequest[1];
		regReq[0] = new FetchRequest(getAppId(), getAllowedAaids())
				.getRegistrationRequest(regRequest);
		StorageImpl.getInstance().storeRegReq(regReq);
		Dash.getInstance().addStats("", Dash.LAST_REG_REQ, regReq);
//		Dash.getInstance().stats.put(Dash.LAST_REG_REQ, regReq);
		Dash.getInstance().history.add(regReq);
		return regReq;
	}

	/**
	 * List of allowed AAID - Authenticator Attestation ID.
	 * Authenticator Attestation ID / AAID.
	 * A unique identifier assigned to a model, class or batch of FIDO Authenticators
	 * that all share the same characteristics, and which a Relying Party can use
	 * to look up an Attestation Public Key and Authenticator Metadata for the device.
	 * The first 4 characters of the AAID are the vendorID.
	 *
	 * @return  list of allowed AAID - Authenticator Attestation ID.
	 */
	private String[] getAllowedAaids() {
		String[] ret = { "EBA0#0001", "0015#0001", "0012#0002", "0010#0001",
				"4e4e#0001", "5143#0001", "0011#0701", "0013#0001",
				"0014#0000", "0014#0001", "53EC#C002", "DAB8#8001",
				"DAB8#0011", "DAB8#8011", "5143#0111", "5143#0120",
				"4746#F816", "53EC#3801" };
		List<String> retList = new ArrayList<String>(Arrays.asList(ret));
		retList.addAll(Dash.getInstance().uuids);
		return retList.toArray(new String[0]);
	}

	/**
	 * List of trusted Application Facet ID.
	 * An (application) facet is how an application is implemented on various
	 * platforms. For example, the application MyBank may have an Android app,
	 * an iOS app, and a Web app. These are all facets of the MyBank application.
	 *
	 * A platform-specific identifier (URI) for an application facet.
	 * For Web applications, the facet id is the RFC6454 origin [RFC6454].
	 * For Android applications, the facet id is the URI
	 * android:apk-key-hash:<hash-of-apk-signing-cert>
	 * For iOS, the facet id is the URI ios:bundle-id:<ios-bundle-id-of-app>.
	 *
	 * @return List of trusted Application Facet ID.
	 */
	@GET
	@Path("/public/uaf/facets")
	@Produces("application/fido.trusted-apps+json")
	public Facets facets() {
		String timestamp = new Date().toString();
//		Dash.getInstance().stats.put(Dash.LAST_REG_REQ, timestamp);
		String[] trustedIds = { "https://ms.com" };
		List<String> trustedIdsList = new ArrayList<String>(Arrays.asList(trustedIds));
		trustedIdsList.addAll(Dash.getInstance().facetIds);
		trustedIdsList.add(readFacet());
		Facets facets = new Facets();
		facets.trustedFacets = new TrustedFacets[1];
		TrustedFacets trusted = new TrustedFacets();
		trusted.version = new Version(1, 0);
		trusted.ids = trustedIdsList.toArray(new String[0]);
		facets.trustedFacets[0] = trusted;
		return facets;
	}
	
	private String readFacet() {
		InputStream in = getClass().getResourceAsStream("config.properties");
		String facetVal = "";
		try {
			Properties props = new Properties();
			props.load(in);
			facetVal = props.getProperty("facetId");
		} catch (IOException e) {
			e.printStackTrace();
		} 
		return facetVal;
	}

	/**
	 * The AppID is an identifier for a set of different Facets of a relying
	 * party's application. The AppID is a URL pointing to the TrustedFacets,
	 * i.e. list of FacetIDs related to this AppID.
	 * @return a URL pointing to the TrustedFacets
	 */
	@Context UriInfo uriInfo;
	private String getAppId() {
		// You can get it dynamically.
		// It only works if your server is not behind a reverse proxy
		return uriInfo.getBaseUri() + "v1/public/uaf/facets";
		// Or you can define it statically
//		return "https://www.head2toes.org/fidouaf/v1/public/uaf/facets";
	}

	@PUT
	@Path("/public/regResponse")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public RegistrationRecord[] processRegResponse(String payload) {
		RegistrationRecord[] result;
		if (! payload.isEmpty()) {
			RegistrationResponse[] fromJson = (new Gson()).fromJson(payload,
					RegistrationResponse[].class);

			Dash.getInstance().addStats("", Dash.LAST_REG_RES, fromJson);
			Dash.getInstance().history.add(fromJson);

			RegistrationResponse registrationResponse = fromJson[0];
			result = new ProcessResponse().processRegResponse(registrationResponse);
			if (result[0].status.equals("SUCCESS")) {
				try {
					StorageImpl.getInstance().storeRegRecord(result);
					StorageImpl.getInstance().storeRegReq(null);
				} catch (DuplicateKeyException e) {
					result = new RegistrationRecord[1];
					result[0] = new RegistrationRecord();
					result[0].status = "Error: Duplicate Key";
				} catch (SystemErrorException e1) {
					result = new RegistrationRecord[1];
					result[0] = new RegistrationRecord();
					result[0].status = "Error: Data couldn't be stored in DB";
				}
			}
		}else{
			//TODO Could be interesting refactor this method (and its callers) and modify return type to javax.ws.rs.core.Response and send Response.Status.PRECONDITION_FAILED error code.
			result = new RegistrationRecord[1];
			result[0] = new RegistrationRecord();
			result[0].status = "Error: payload could not be empty";
		}
		return result;
	}

	@POST
	@Path("/public/deregRequest")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public String deregRequestPublic(String payload) {

		return new DeregRequestProcessor().process(payload);
	}

	// WE only want the one with tx content
//	@GET
//	@Path("/public/authRequest/{registrationId}")
//	@Produces(MediaType.APPLICATION_JSON)
//	public AuthenticationRequest[] getAuthForAppIdReq(@PathParam("registrationId") String registrationId) {
//		AuthenticationRequest[] authReqObj = getAuthReqObj();
////		setAppId(appId, authReqObj[0].header);
//
//		return authReqObj;
//	}
//
//	private void setAppId(String appId, OperationHeader header) {
//		if (appId == null || appId.isEmpty()){
//			return;
//		}
//		String decodedAppId = new String (Base64.decodeBase64(appId));
//		Facets facets = facets();
//		if (facets == null || facets.trustedFacets == null || facets.trustedFacets.length == 0
//				 || facets.trustedFacets[0] == null || facets.trustedFacets[0].ids == null){
//			return;
//		}
//		String[] ids = facets.trustedFacets[0].ids;
//		for (int i = 0; i < ids.length; i++) {
//
//			if (decodedAppId.equals(ids[i])){
//				header.appID = decodedAppId;
//				break;
//			}
//		}
//	}


	// we need an endpoint to get authentication requests by registrationId
	// and it will use the 3 way auth system described in the issue in github
	// @Path

	@POST
	@Path("/public/authRequest/{registrationId}")
	@Produces(MediaType.APPLICATION_JSON)
	public AuthenticationRequest[] getAuthTrxReq(@PathParam("registrationId") String registrationId, String trxContent) {
		AuthenticationRequest[] authReqObj = getAuthReqObj();
//		setAppId(registrationId, authReqObj[0].header);
		setTransaction(trxContent, authReqObj);
		Dash.getInstance().addStats(registrationId, Dash.LAST_AUTH_REQ, authReqObj[0]);
        Dash.getInstance().history.add(authReqObj);

		return authReqObj;
	}

	private void setTransaction(String trxContent, AuthenticationRequest[] authReqObj) {
		authReqObj[0].transaction = new Transaction[1];
		Transaction t = new Transaction();
		t.content = trxContent;
		t.contentType = MediaType.TEXT_PLAIN;
		t.id = System.currentTimeMillis();
		authReqObj[0].transaction[0] = t;
	}

	public AuthenticationRequest[] getAuthReqObj() {
		AuthenticationRequest[] ret = new AuthenticationRequest[1];
		ret[0] = new FetchRequest(getAppId(), getAllowedAaids())
				.getAuthenticationRequest();
		return ret;
	}

	@POST
	@Path("/public/authResponse")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public AuthenticationRequest[] processAuthResponse(String payload) {
		if (!payload.isEmpty()) {
//			Dash.getInstance().stats.put(Dash.LAST_AUTH_RES, payload);
			Gson gson = new Gson();
			AuthenticationResponse[] authResp = gson.fromJson(payload,
					AuthenticationResponse[].class);

//			Dash.getInstance().stats.put(Dash.LAST_AUTH_RES, authResp);
//			Dash.getInstance().addStats(authResp[0].registrationID, Dash.LAST_AUTH_RES, authResp);
			Dash.getInstance().history.add(authResp);
			AuthenticatorRecord[] result = new ProcessResponse()
					.processAuthResponse(authResp[0]);
			if(result[0].status.equals("SUCCESS")) {
				AuthenticationRequest[] response = Dash.getInstance().getAuthReqests(authResp[0].registrationID);
				return response;
			}
			return new AuthenticationRequest[0];
		}
		return new AuthenticationRequest[0];
	}

	@PUT
	@Path("/public/authResponse/{registrationId}/{txIndex}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public TransactionResponse[] processTxData(@PathParam("registrationId") String registrationId,
											   @PathParam("txIndex") Long txIndex, String payload) {
		if (!payload.isEmpty()) {
			TransactionAction[] txAction = gson.fromJson(payload,
					TransactionAction[].class);

			if(new ProcessResponse().processTxResponse(txAction[0], registrationId)) {

				TransactionResponse[] txResp = new TransactionResponse[1];
				txResp[0] = new TransactionResponse();

				AuthenticationRequest[] requests = Dash.getInstance().getAuthReqests(registrationId);
				AuthenticationRequest authReq = new AuthenticationRequest();
				for (AuthenticationRequest r : requests) {
					if (r.transaction[0].id.equals(txIndex)) {
						authReq = r;
						break;
					}
				}
				if (Dash.getInstance().removeAuthRequest(registrationId, authReq)) {

                    if (txAction[0].response.equals("U0lHTkVEX1RY")) {
                        Dash.getInstance().addTxResponse("SIGNED_TX", authReq.transaction[0]);
                        txResp[0].response = "SIGNED_TX";
                    }
                    else if (txAction[0].response.equals("REVDTElORURfVFg=")) {
                        Dash.getInstance().addTxResponse("DECLINED_TX", authReq.transaction[0]);
                        txResp[0].response = "DECLINED_TX";
                    }
                    else
                        return new TransactionResponse[0];
//                    Dash.getInstance().history.add(txResp);
					txResp[0].transactionId = txIndex;
					txResp[0].transaction = authReq.transaction[0];

					return txResp;
				}
			}
		}
		return new TransactionResponse[0];
	}

	@GET
	@Path("/public/getTransactions/{registrationId}")
	@Produces(MediaType.APPLICATION_JSON)
	public Transaction[] getTransactions(@PathParam("registrationId") String registrationId) {
		AuthenticationRequest[] requests = Dash.getInstance().getAuthReqests(registrationId);
		if (requests != null) {
			List<Transaction> transactions = new ArrayList<Transaction>();
			for (AuthenticationRequest r : requests) {
				transactions.add(r.transaction[0]);
			}
//			Dash.getInstance().history.add(transactions);
			return transactions.toArray(new Transaction[transactions.size()]);
		}
		return new Transaction[0];
	}
}
