package org.ebayopensource.fidouafclient.op;


import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Base64;

import com.google.gson.Gson;

import org.ebayopensource.fido.uaf.crypto.Base64url;
import org.ebayopensource.fido.uaf.msg.TrustedFacets;
import org.ebayopensource.fido.uaf.msg.TrustedFacetsList;
import org.ebayopensource.fido.uaf.msg.Version;
import org.ebayopensource.fidouafclient.curl.Curl;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility Class for UaFRequest messages - Registration & Authentication
 */
public abstract class OpUtils {


    /**
     * Process Request Message
     * @param serverResponse Registration or Authentication request message
     * @param facetId Application facet Id
     * @param context Android Application Context
     * @param isTrx always false for Registration messages. For Authentication it should be true only for transactions
     * @return uafProtocolMessage
     */
    public static String getUafRequest(String serverResponse, String facetId, Context context, boolean isTrx){
        String msg = "{\"uafProtocolMessage\":\"";
        try {
            JSONArray requestArray = new JSONArray(serverResponse);
            String appID = ((JSONObject) requestArray.get(0)).getJSONObject("header").getString("appID");
            Version version = (new Gson()).fromJson(((JSONObject) requestArray.get(0)).getJSONObject("header").getString("upv"),Version.class);
            // If the AppID is null or empty, the client MUST set the AppID to be the FacetID of
            // the caller, and the operation may proceed without additional processing.
            if (appID == null || appID.isEmpty()) {
                if (checkAppSignature(facetId, context)) {
                    ((JSONObject) requestArray.get(0)).getJSONObject("header").put("appID", facetId);
                }
            }else {
                //If the AppID is not an HTTPS URL, and matches the FacetID of the caller, no additional
                // processing is necessary and the operation may proceed.
                if (!facetId.equals(appID)) {
                    // Begin to fetch the Trusted Facet List using the HTTP GET method
                    String trustedFacetsJson = getTrustedFacets(appID);
                    TrustedFacetsList trustedFacets = (new Gson()).fromJson(trustedFacetsJson, TrustedFacetsList.class);
                    if (trustedFacets.getTrustedFacets() == null){
                        return getEmptyUafMsgRegRequest();
                    }
                    // After processing the trustedFacets entry of the correct version and removing
                    // any invalid entries, if the caller's FacetID matches one listed in ids,
                    // the operation is allowed.
                    boolean facetFound = processTrustedFacetsList(trustedFacets,version,facetId);
                    if ((!facetFound) || (!checkAppSignature(facetId, context))){
                        return getEmptyUafMsgRegRequest();
                    }
                } else {
                    if (! checkAppSignature(facetId, context)) {
                        return getEmptyUafMsgRegRequest();
                    }
                }
            }
            if (isTrx){
                ((JSONObject) requestArray.get(0)).put("transaction", getTransaction());
            }
            JSONObject uafMsg = new JSONObject();
            uafMsg.put("uafProtocolMessage", requestArray.toString());
            return uafMsg.toString();
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return getEmptyUafMsgRegRequest();
    }

    public static String getEmptyUafMsgRegRequest (){
        String msg = "{\"uafProtocolMessage\":";
        msg = msg + "\"\"";
        msg = msg + "}";
        return msg;
    }

    private static JSONArray getTransaction (){
        JSONArray ret = new JSONArray();
        JSONObject trx = new JSONObject();

        try {
            trx.put("contentType", "text/plain");
            trx.put("content", Base64url.encodeToString("Authentication".getBytes()));
        } catch (JSONException e) {
            e.printStackTrace();
        }

        ret.put(trx);
        return ret;
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
    private static boolean processTrustedFacetsList(TrustedFacetsList trustedFacetsList, Version version, String facetId){
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
    private static boolean checkAppSignature(String facetId, Context context){
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
    private static String getTrustedFacets(String appID){
        //TODO The caching related HTTP header fields in the HTTP response (e.g. “Expires”) SHOULD be respected when fetching a Trusted Facets List.
        return Curl.getInSeparateThread(appID);
    }

    public static String clientSendRegResponse (String uafMessage, String endpoint){
        String decoded = "";
        try {
            JSONObject json = new JSONObject (uafMessage);
            decoded = json.getString("uafProtocolMessage").replace("\\", "");
        } catch (JSONException e) {
            e.printStackTrace();
        }

        String headerStr = "Content-Type:Application/json Accept:Application/json";
        String serverResponse = Curl.postInSeparateThread(endpoint, headerStr , decoded);
        return serverResponse;
    }



}
