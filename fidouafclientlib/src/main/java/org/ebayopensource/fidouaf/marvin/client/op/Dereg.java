package org.ebayopensource.fidouaf.marvin.client.op;

import java.util.logging.Logger;

import org.ebayopensource.fidouaf.marvin.client.config.InitConfig;
import org.ebayopensource.fidouaf.marvin.client.msg.DeregisterAuthenticator;
import org.ebayopensource.fidouaf.marvin.client.msg.DeregistrationRequest;
import org.ebayopensource.fidouaf.marvin.client.msg.Operation;
import org.ebayopensource.fidouaf.marvin.client.msg.OperationHeader;
import org.ebayopensource.fidouaf.marvin.client.msg.Version;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class Dereg {
	private Logger logger = Logger.getLogger(this.getClass().getName());
	private Gson gson = new GsonBuilder().create();
	
	public String dereg (String uafMsg) throws UafRequestMsgParseException{
		logger.info ("  [UAF][1]Dereg  ");
		DeregistrationRequest dereg = getDeregRequest(uafMsg);
		InitConfig.getInstance().getOperationalParams().getStorage().remove(getKeyId(dereg));
		return uafMsg;
	}

	private String getKeyId(DeregistrationRequest dereg) throws UafRequestMsgParseException {
		if (dereg == null || dereg.authenticators == null || dereg.authenticators.length == 0 || dereg.authenticators[0].keyID == null){
			throw new UafRequestMsgParseException(new Exception("Invalid DeregistrationRequest: Missing KeyId"));
		}
		return dereg.authenticators[0].keyID;
	}
	
	public DeregistrationRequest getDeregRequest(String uafMsg) throws UafRequestMsgParseException {
		try {
			logger.info ("  [UAF][2]Reg - getDeregRequest  : " + uafMsg);
			return gson.fromJson(uafMsg, DeregistrationRequest[].class)[0];
		} catch (Exception e){
			throw new UafRequestMsgParseException (e);
		}
	}

	private DeregistrationRequest formDeregRequest(String appId, String aaid, String keyId) {
		DeregistrationRequest reg = new DeregistrationRequest();
		reg.header = new OperationHeader();
		reg.header.upv = new Version(1, 0);
		reg.header.op = Operation.Dereg;
		reg.header.appID = appId;
		reg.authenticators = new DeregisterAuthenticator[1];
		DeregisterAuthenticator deregAuth = new DeregisterAuthenticator();
		deregAuth.aaid = aaid;
		deregAuth.keyID = keyId;
		reg.authenticators[0] = deregAuth;
		logger.info ("  [UAF][2]Dereg - Reg Response Formed  ");
		return reg;
	}
}
