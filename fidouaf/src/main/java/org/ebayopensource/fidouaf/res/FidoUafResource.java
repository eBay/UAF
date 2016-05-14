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

import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.commons.codec.binary.Base64;
import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;
import org.ebayopensource.fido.uaf.msg.AuthenticationResponse;
import org.ebayopensource.fido.uaf.msg.Operation;
import org.ebayopensource.fido.uaf.msg.OperationHeader;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fido.uaf.msg.RegistrationResponse;
import org.ebayopensource.fido.uaf.msg.Transaction;
import org.ebayopensource.fido.uaf.msg.Version;
import org.ebayopensource.fido.uaf.storage.AuthenticatorRecord;
import org.ebayopensource.fido.uaf.storage.DuplicateKeyException;
import org.ebayopensource.fido.uaf.storage.RegistrationRecord;
import org.ebayopensource.fido.uaf.storage.SystemErrorException;
import org.ebayopensource.fidouaf.RPserver.msg.ReturnUAFAuthenticationRequest;
import org.ebayopensource.fidouaf.RPserver.msg.ReturnUAFDeregistrationRequest;
import org.ebayopensource.fidouaf.RPserver.msg.ReturnUAFRegistrationRequest;
import org.ebayopensource.fidouaf.RPserver.msg.ServerResponse;
import org.ebayopensource.fidouaf.RPserver.msg.GetUAFRequest;
import org.ebayopensource.fidouaf.facets.Facets;
import org.ebayopensource.fidouaf.facets.TrustedFacets;
import org.ebayopensource.fidouaf.res.util.DeregRequestProcessor;
import org.ebayopensource.fidouaf.res.util.FetchRequest;
import org.ebayopensource.fidouaf.res.util.ProcessResponse;
import org.ebayopensource.fidouaf.res.util.StorageImpl;
import org.ebayopensource.fidouaf.stats.Dash;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

@Path("/v1")
public class FidoUafResource {

	Gson gson = new GsonBuilder().disableHtmlEscaping().create();

	@GET
	@Path("/stats")
	@Produces(MediaType.APPLICATION_JSON)
	public String getStats() {
		return gson.toJson(Dash.getInstance().stats);
	}

	@GET
	@Path("/history")
	@Produces(MediaType.APPLICATION_JSON)
	public List<Object> getHistory() {
		return Dash.getInstance().history;
	}

	@GET
	@Path("/registrations")
	@Produces(MediaType.APPLICATION_JSON)
	public Map<String, RegistrationRecord> getDbDump() {
		return StorageImpl.getInstance().dbDump();
	}

	@GET
	@Path("/public/regRequest/{username}")
	@Produces(MediaType.APPLICATION_JSON)
	public RegistrationRequest[] getRegisReqPublic(
			@PathParam("username") String username) {
		RegistrationRequest[] regReq = new RegistrationRequest[1];
		regReq[0] = new FetchRequest(getAppId(), getAllowedAaids())
				.getRegistrationRequest(username);
		Dash.getInstance().stats.put(Dash.LAST_REG_REQ, regReq);
		Dash.getInstance().history.add(regReq);
		return regReq;
	}
	
	@GET
	@Path("/public/regRequest/{username}/{appId}")
	@Produces(MediaType.APPLICATION_JSON)
	public String getRegReqForAppId(@PathParam("username") String username, 
			@PathParam("appId") String appId) {
		RegistrationRequest[] regReq = getRegisReqPublic(username);
		setAppId(appId, regReq[0].header);
		return gson.toJson(regReq);
	}

	@GET
	@Path("/public/regRequest")
	@Produces(MediaType.APPLICATION_JSON)
	public RegistrationRequest[] postRegisReqPublic(String username) {
		RegistrationRequest[] regReq = new RegistrationRequest[1];
		regReq[0] = new FetchRequest(getAppId(), getAllowedAaids())
				.getRegistrationRequest(username);
		Dash.getInstance().stats.put(Dash.LAST_REG_REQ, regReq);
		Dash.getInstance().history.add(regReq);
		return regReq;
	}

	private String[] getAllowedAaids() {
		String[] ret = { "EBA0#0001", "0015#0001", "0012#0002", "0010#0001",
				"4e4e#0001", "5143#0001", "0011#0701", "0013#0001",
				"0014#0000", "0014#0001", "53EC#C002", "DAB8#8001",
				"DAB8#0011", "DAB8#8011", "5143#0111", "5143#0120",
				"4746#F816", "53EC#3801", "CC36#0001" , "FACE#0001", 
				"002E#0001" };
		return ret;
	}

	@GET
	@Path("/public/uaf/facets")
	@Produces("application/fido.trusted-apps+json")
	public Facets facets() {
		String timestamp = new Date().toString();
		Dash.getInstance().stats.put(Dash.LAST_REG_REQ, timestamp);
		String[] trustedIds = { "https://www.head2toes.org",
				"android:apk-key-hash:Df+2X53Z0UscvUu6obxC3rIfFyk",
				"android:apk-key-hash:bE0f1WtRJrZv/C0y9CM73bAUqiI",
				"https://openidconnect.ebay.com" };
		Facets facets = new Facets();
		facets.trustedFacets = new TrustedFacets[1];
		TrustedFacets trusted = new TrustedFacets();
		trusted.version = new Version(1, 0);
		trusted.ids = trustedIds;
		facets.trustedFacets[0] = trusted;
		return facets;
	}

	private String getAppId() {
		return "https://www.head2toes.org/fidouaf/v1/public/uaf/facets";
	}

	@POST
	@Path("/public/regResponse")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public RegistrationRecord[] processRegResponse(String payload) {
		RegistrationRecord[] result = null;
		Gson gson = new Gson();

		RegistrationResponse[] fromJson = gson.fromJson(payload,
				RegistrationResponse[].class);
		Dash.getInstance().stats.put(Dash.LAST_REG_RES, fromJson);
		Dash.getInstance().history.add(fromJson);

		RegistrationResponse registrationResponse = fromJson[0];
		result = new ProcessResponse().processRegResponse(registrationResponse);
		if (result[0].status.equals("SUCCESS")) {
			try {
				StorageImpl.getInstance().store(result);
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
		return result;
	}

	@POST
	@Path("/public/deregRequest")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public String deregRequestPublic(String payload) {

		return new DeregRequestProcessor().process(payload);
	}

	@GET
	@Path("/public/authRequest")
	@Produces(MediaType.APPLICATION_JSON)
	public String getAuthReq() {
		return gson.toJson(getAuthReqObj());
	}

	@GET
	@Path("/public/authRequest/{appId}")
	@Produces(MediaType.APPLICATION_JSON)
	public String getAuthForAppIdReq(@PathParam("appId") String appId) {
		AuthenticationRequest[] authReqObj = getAuthReqObj();
		setAppId(appId, authReqObj[0].header);
		
		return gson.toJson(authReqObj);
	}

	private void setAppId(String appId, OperationHeader header) {
		if (appId == null || appId.isEmpty()){
			return;
		}
		String decodedAppId = new String (Base64.decodeBase64(appId));
		Facets facets = facets();
		if (facets == null || facets.trustedFacets == null || facets.trustedFacets.length == 0
				 || facets.trustedFacets[0] == null || facets.trustedFacets[0].ids == null){
			return;
		}
		String[] ids = facets.trustedFacets[0].ids;
		for (int i = 0; i < ids.length; i++) {
			
			if (decodedAppId.equals(ids[i])){
				header.appID = decodedAppId;
				break;
			}
		}
	}

	@GET
	@Path("/public/authRequest/{appId}/{trxContent}")
	@Produces(MediaType.APPLICATION_JSON)
	public String getAuthTrxReq(@PathParam("appId") String appId,
			@PathParam("trxContent") String trxContent) {
		AuthenticationRequest[] authReqObj = getAuthReqObj();
		setAppId(appId, authReqObj[0].header);
		setTransaction(trxContent, authReqObj);
		
		return gson.toJson(authReqObj);
	}

	private void setTransaction(String trxContent, AuthenticationRequest[] authReqObj) {
		authReqObj[0].transaction = new Transaction[1];
		Transaction t = new Transaction();
		t.content = trxContent;
		t.contentType = MediaType.TEXT_PLAIN;
		authReqObj[0].transaction[0] = t;
	}

	public AuthenticationRequest[] getAuthReqObj() {
		AuthenticationRequest[] ret = new AuthenticationRequest[1];
		ret[0] = new FetchRequest(getAppId(), getAllowedAaids())
				.getAuthenticationRequest();
		Dash.getInstance().stats.put(Dash.LAST_AUTH_REQ, ret);
		Dash.getInstance().history.add(ret);
		return ret;
	}

	@POST
	@Path("/public/authResponse")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public AuthenticatorRecord[] processAuthResponse(String payload) {
		Dash.getInstance().stats.put(Dash.LAST_AUTH_RES, payload);
		Gson gson = new Gson();
		AuthenticationResponse[] authResp = gson.fromJson(payload,
				AuthenticationResponse[].class);
		Dash.getInstance().stats.put(Dash.LAST_AUTH_RES, authResp);
		Dash.getInstance().history.add(authResp);
		AuthenticatorRecord[] result = new ProcessResponse()
				.processAuthResponse(authResp[0]);
		return result;
	}

	@POST
	@Path("/public/uafRegRequest")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ReturnUAFRegistrationRequest GetUAFRegistrationRequest(String payload) {
		RegistrationRequest[] result = getRegisReqPublic("iafuser01");
		ReturnUAFRegistrationRequest uafReq = null;
		if (result != null) {
			uafReq = new ReturnUAFRegistrationRequest();
			uafReq.statusCode = 1200;
			uafReq.uafRequest = result;
			uafReq.op = Operation.Reg;
			uafReq.lifetimeMillis = 5 * 60 * 1000;
		}
		return uafReq;
	}

	@POST
	@Path("/public/uafAuthRequest")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ReturnUAFAuthenticationRequest GetUAFAuthenticationRequest(
			String payload) {
		AuthenticationRequest[] result = getAuthReqObj();
		ReturnUAFAuthenticationRequest uafReq = null;
		if (result != null) {
			uafReq = new ReturnUAFAuthenticationRequest();
			uafReq.statusCode = 1200;
			uafReq.uafRequest = result;
			uafReq.op = Operation.Auth;
			uafReq.lifetimeMillis = 5 * 60 * 1000;
		}
		return uafReq;
	}

	@POST
	@Path("/public/uafDeregRequest")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ReturnUAFDeregistrationRequest GetUAFDeregistrationRequest(
			String payload) {
		String result = deregRequestPublic(payload);
		ReturnUAFDeregistrationRequest uafReq = new ReturnUAFDeregistrationRequest();
		if (result.equalsIgnoreCase("Success")) {
			uafReq.statusCode = 1200;
		} else if (result
				.equalsIgnoreCase("Failure: Problem in deleting record from local DB")) {
			uafReq.statusCode = 1404;
		} else if (result
				.equalsIgnoreCase("Failure: problem processing deregistration request")) {
			uafReq.statusCode = 1491;
		} else {
			uafReq.statusCode = 1500;

		}
		uafReq.uafRequest = null;
		uafReq.op = Operation.Dereg;
		uafReq.lifetimeMillis = 0;
		return uafReq;
	}

	@POST
	@Path("/public/uafAuthResponse")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ServerResponse UAFAuthResponse(String payload) {
		String findOp = payload;
		findOp = findOp.substring(findOp.indexOf("op") + 6,
				findOp.indexOf(",", findOp.indexOf("op")) - 1);
		System.out.println("findOp=" + findOp);

		AuthenticatorRecord[] result = processAuthResponse(payload);
		ServerResponse servResp = new ServerResponse();
		if (result[0].status.equals("SUCCESS")) {
			servResp.statusCode = 1200;
			servResp.Description = "OK. Operation completed";
		} else if (result[0].status.equals("FAILED_SIGNATURE_NOT_VALID")
				|| result[0].status.equals("FAILED_SIGNATURE_VERIFICATION")
				|| result[0].status.equals("FAILED_ASSERTION_VERIFICATION")) {
			servResp.statusCode = 1496;
			servResp.Description = result[0].status;
		} else if (result[0].status.equals("INVALID_SERVER_DATA_EXPIRED")
				|| result[0].status
						.equals("INVALID_SERVER_DATA_SIGNATURE_NO_MATCH")
				|| result[0].status.equals("INVALID_SERVER_DATA_CHECK_FAILED")) {
			servResp.statusCode = 1491;
			servResp.Description = result[0].status;
		} else {
			servResp.statusCode = 1500;
			servResp.Description = result[0].status;
		}

		return servResp;
	}

	@POST
	@Path("/public/uafRegResponse")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ServerResponse UAFRegResponse(String payload) {
		String findOp = payload;
		findOp = findOp.substring(findOp.indexOf("op") + 6,
				findOp.indexOf(",", findOp.indexOf("op")) - 1);
		System.out.println("findOp=" + findOp);

		RegistrationRecord[] result = processRegResponse(payload);
		ServerResponse servResp = new ServerResponse();
		if (result[0].status.equals("SUCCESS")) {
			servResp.statusCode = 1200;
			servResp.Description = "OK. Operation completed";
		} else if (result[0].status.equals("ASSERTIONS_CHECK_FAILED")) {
			servResp.statusCode = 1496;
			servResp.Description = result[0].status;
		} else if (result[0].status.equals("INVALID_SERVER_DATA_EXPIRED")
				|| result[0].status
						.equals("INVALID_SERVER_DATA_SIGNATURE_NO_MATCH")
				|| result[0].status.equals("INVALID_SERVER_DATA_CHECK_FAILED")) {
			servResp.statusCode = 1491;
			servResp.Description = result[0].status;
		} else {
			servResp.statusCode = 1500;
			servResp.Description = result[0].status;
		}

		return servResp;
	}

	@POST
	@Path("/public/uafRequest")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public String GetUAFRequest(String payload) {
		String uafReq = null;
		Gson gson = new Gson();
		GetUAFRequest req = gson.fromJson(payload, GetUAFRequest.class);

		if (req.op.name().equals("Reg")) {
			RegistrationRequest[] result = getRegisReqPublic("iafuser01");
			ReturnUAFRegistrationRequest uafRegReq = null;
			if (result != null) {
				uafRegReq = new ReturnUAFRegistrationRequest();
				uafRegReq.statusCode = 1200;
				uafRegReq.uafRequest = result;
				uafRegReq.op = Operation.Reg;
				uafRegReq.lifetimeMillis = 5 * 60 * 1000;
			}
			uafReq = gson.toJson(uafRegReq);
		} else if (req.op.name().equals("Auth")) {
			AuthenticationRequest[] result = getAuthReqObj();
			ReturnUAFAuthenticationRequest uafAuthReq = null;
			if (result != null) {
				uafAuthReq = new ReturnUAFAuthenticationRequest();
				uafAuthReq.statusCode = 1200;
				uafAuthReq.uafRequest = result;
				uafAuthReq.op = Operation.Auth;
				uafAuthReq.lifetimeMillis = 5 * 60 * 1000;
			}
			uafReq = gson.toJson(uafAuthReq);
		} else if (req.op.name().equals("Dereg")) {
			String result = deregRequestPublic(payload);
			ReturnUAFDeregistrationRequest uafDeregReq = new ReturnUAFDeregistrationRequest();
			if (result.equalsIgnoreCase("Success")) {
				uafDeregReq.statusCode = 1200;
			} else if (result
					.equalsIgnoreCase("Failure: Problem in deleting record from local DB")) {
				uafDeregReq.statusCode = 1404;
			} else if (result
					.equalsIgnoreCase("Failure: problem processing deregistration request")) {
				uafDeregReq.statusCode = 1491;
			} else {
				uafDeregReq.statusCode = 1500;

			}
			uafDeregReq.uafRequest = null;
			uafDeregReq.op = Operation.Dereg;
			uafDeregReq.lifetimeMillis = 0;
			uafReq = gson.toJson(uafDeregReq);
		}
		return uafReq;
	}

	@POST
	@Path("/public/uafResponse")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public ServerResponse UAFResponse(String payload) {
		String findOp = payload;
		findOp = findOp.substring(findOp.indexOf("op") + 6,
				findOp.indexOf(",", findOp.indexOf("op")) - 1);
		System.out.println("findOp=" + findOp);

		ServerResponse servResp = new ServerResponse();

		if (findOp.equals("Reg")) {
			RegistrationRecord[] result = processRegResponse(payload);

			if (result[0].status.equals("SUCCESS")) {
				servResp.statusCode = 1200;
				servResp.Description = "OK. Operation completed";
			} else if (result[0].status.equals("ASSERTIONS_CHECK_FAILED")) {
				servResp.statusCode = 1496;
				servResp.Description = result[0].status;
			} else if (result[0].status.equals("INVALID_SERVER_DATA_EXPIRED")
					|| result[0].status
							.equals("INVALID_SERVER_DATA_SIGNATURE_NO_MATCH")
					|| result[0].status
							.equals("INVALID_SERVER_DATA_CHECK_FAILED")) {
				servResp.statusCode = 1491;
				servResp.Description = result[0].status;
			} else {
				servResp.statusCode = 1500;
				servResp.Description = result[0].status;
			}
		} else if (findOp.equals("Auth")) {
			AuthenticatorRecord[] result = processAuthResponse(payload);

			if (result[0].status.equals("SUCCESS")) {
				servResp.statusCode = 1200;
				servResp.Description = "OK. Operation completed";
			} else if (result[0].status.equals("FAILED_SIGNATURE_NOT_VALID")
					|| result[0].status.equals("FAILED_SIGNATURE_VERIFICATION")
					|| result[0].status.equals("FAILED_ASSERTION_VERIFICATION")) {
				servResp.statusCode = 1496;
				servResp.Description = result[0].status;
			} else if (result[0].status.equals("INVALID_SERVER_DATA_EXPIRED")
					|| result[0].status
							.equals("INVALID_SERVER_DATA_SIGNATURE_NO_MATCH")
					|| result[0].status
							.equals("INVALID_SERVER_DATA_CHECK_FAILED")) {
				servResp.statusCode = 1491;
				servResp.Description = result[0].status;
			} else {
				servResp.statusCode = 1500;
				servResp.Description = result[0].status;
			}
		}
		return servResp;
	}
}
