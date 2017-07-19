Following these steps to run the demo code in local server.

1. Building and running UAF server by following the ways indicated in the Wiki tab of eBayUAF github or connect to the following link "https://github.com/eBay/UAF/wiki/BuildingAndRunningUAFServer" 
2. For the client side, you need to build and install the fidouafclient project into your android mobile.
3. Open the mobile application and then press the facetID button to get the value of the facetID.
4. Insert the value of the facetID obtained from step 5 into the config.properties file which is located at
   UAF\fidouaf\target\classes\org\ebayopensource\fidouaf\res.
5. Click the setting menu at the top-right of the mobile application and set the IP address and the port of the Server Endpoint
to your server, e.g. http://192.168.1.34:8080 then press the checkmark button to save the settings values.
6. All of the protocols can now be tested. 
