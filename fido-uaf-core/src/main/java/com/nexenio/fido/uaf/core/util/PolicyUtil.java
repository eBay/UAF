package com.nexenio.fido.uaf.core.util;

import com.nexenio.fido.uaf.core.msg.MatchCriteria;
import com.nexenio.fido.uaf.core.msg.Policy;

public abstract class PolicyUtil {

    public static Policy constructAuthenticationPolicy(String[] acceptedAaids) {
        if (acceptedAaids == null) {
            return null;
        }
        Policy policy = new Policy();
        policy.setAccepted(createMatchCriteriaFromAaids(acceptedAaids));
        return policy;
    }

    public static MatchCriteria[][] createMatchCriteriaFromAaids(String[] aaids) {
        MatchCriteria[][] aaidMatchCriteria = new MatchCriteria[aaids.length][1];
        for (int i = 0; i < aaidMatchCriteria.length; i++) {
            MatchCriteria matchCriteria = new MatchCriteria();
            matchCriteria.setAaids(new String[]{aaids[i]});
            aaidMatchCriteria[i] = new MatchCriteria[]{matchCriteria};
        }
        return aaidMatchCriteria;
    }

}
