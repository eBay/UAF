package org.ebayopensource.fidouaf.marvin.client.op;

import java.util.logging.Logger;

import org.ebayopensource.fidouaf.marvin.client.config.InitConfig;
import org.ebayopensource.fidouaf.marvin.client.msg.DeregistrationRequest;

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
}
