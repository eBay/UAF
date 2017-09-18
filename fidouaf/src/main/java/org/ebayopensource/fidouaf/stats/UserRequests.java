package org.ebayopensource.fidouaf.stats;

import com.sun.tools.internal.xjc.reader.xmlschema.bindinfo.BIConversion;
import org.ebayopensource.fido.uaf.msg.AuthenticationRequest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class UserRequests {
    private Map<String, List<AuthenticationRequest>> storage = new HashMap<String, List<AuthenticationRequest>>();

    public void add(String id, AuthenticationRequest authReq) {
        List<AuthenticationRequest> list = storage.get(id);

        if (list == null)
            list = new ArrayList<AuthenticationRequest>();

        list.add(authReq);
        storage.put(id, list);
    }
}
