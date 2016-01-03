//
//  AuthorizationProcessManager.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 12/29/15.
//  Copyright © 2015 IBM. All rights reserved.
//

import BMSCore
internal class AuthorizationProcessManager {
    
    private static let HTTP_LOCALHOST:String = "http://localhost";
    private var preferences:AuthorizationManagerPreferences  = AuthorizationManagerPreferences()
    private var authorizationQueue:Queue<ResponseListener> = Queue<ResponseListener>()
    //    private var registrationKeyPair:KeyPair
    //    private var jsonSigner:DefaultJSONSigner
    
    //    private var certificateStore:CertificateStore
    private var logger:Logger
    private var sessionId:String = ""
    
    
    private func handleAuthorizationSuccess(response: Response, error: NSError?) {
        while !self.authorizationQueue.isEmpty() {
            let next:ResponseListener = authorizationQueue.remove()!
            next.onSuccess(response)
        }
    }
    
    
    
    internal init(preferences:AuthorizationManagerPreferences)
    {
        self.logger = Logger.getLoggerForName(MFP_PACKAGE_PREFIX+"AuthorizationProcessManager")
        
        self.preferences = preferences;
        self.authorizationQueue = Queue<ResponseListener>();
        //   this.jsonSigner = new DefaultJSONSigner();
        
        //     File keyStoreFile = new File(context.getFilesDir().getAbsolutePath(), "mfp.keystore");
        //    String uuid = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        //    certificateStore = new CertificateStore(keyStoreFile, uuid);
        
        //case where the shared preferences were deleted but the certificate is saved in the keystore
        //        if preferences.clientId.get() == null && certificateStore.isCertificateStored()) {
        //            try {
        //                X509Certificate certificate = certificateStore.getCertificate();
        //                preferences.clientId.set(CertificatesUtility.getClientIdFromCertificate(certificate));
        //            } catch (Exception e) {
        //                e.printStackTrace();
        //            }
        //        }
        
        //generate new random session id
        sessionId = NSUUID().UUIDString
    }
    internal func startAuthorizationProcess(listener:ResponseListener) {
        authorizationQueue.add(listener);
        
        //start the authorization process only if this is the first time we ask for authorization
        if (authorizationQueue.size == 1) {
            do {
                if (preferences.clientId?.get() == nil) {
                    logger.info("starting registration process");
                    try invokeInstanceRegistrationRequest();
                } else {
                    logger.info("starting authorization process");
                    try invokeAuthorizationRequest();
                }
            } catch {
                // TODO: handle failure
            }
        } else {
            logger.info("authorization process already running, adding response listener to the queue");
            logger.debug("authorization process currently handling \(authorizationQueue.size) requests")
        }
    }
    
    private func invokeInstanceRegistrationRequest() {
        var options:RequestOptions = RequestOptions();
        options.parameters = createRegistrationParams();
        options.headers = createRegistrationHeaders();
        options.requestMethod = HttpMethod.POST
        
        var listener:AuthorizationResponseListener = AuthorizationResponseListener( callback: {
            (response: Response?, error: NSError?) in
            self.saveCertificateFromResponse(response);
            self.invokeAuthorizationRequest();
        })
        
        //TODO:ilan fix callback
        authorizationRequestSend("clients/instance", options: options, listener: nil);
    }
    
    private  func createTokenRequestHeaders(grantCode:String) -> [String:String]{
        var payload = [String:String]()
        var headers = [String:String]()
        do {
            payload["code"] = grantCode
//            var KeyPair keyPair = certificateStore.getStoredKeyPair()
            var jws:String = "" //TODO: delete this line
            //            var jws:String = jsonSigner.sign(keyPair, payload)
            
            headers = [String:String]()
            headers["X-WL-Authenticate"] =  jws
            
        } catch  {
            //TODO: handle error
        }
        
        return headers;
    }
    
    private func createTokenRequestParams(grantCode:String) -> [String:String] {
        
        var params = [String:String]()
        params["code"] =  grantCode
        params["client_id"] = preferences.clientId!.get()
        params["grant_type"] = "authorization_code"
        params["redirect_uri"] = AuthorizationProcessManager.HTTP_LOCALHOST
        return params;
    }
    
    private func createAuthorizationParams() -> [String:String]{
        
        var params = [String:String]()
        params["response_type"] =  "code"
        params["client_id"] =  preferences.clientId!.get()
        params["redirect_uri"] =  AuthorizationProcessManager.HTTP_LOCALHOST
        
        return params;
    }
    
    private func invokeAuthorizationRequest() {
        
        var options:RequestOptions = RequestOptions();
        
        options.parameters = createAuthorizationParams();
        options.headers = [String:String]();
        addSessionIdHeader(&options.headers);
        options.requestMethod = HttpMethod.GET
        var listener:AuthorizationResponseListener = AuthorizationResponseListener( callback: { (response: Response?, error: NSError?) in
            var location:String? = self.extractLocationHeader(response!);
            var grantCode:String? = self.extractGrantCode(location);
            self.invokeTokenRequest(grantCode);
        })
        
        
        authorizationRequestSend("authorization", options: options, listener: nil);
    }
    
    private func invokeTokenRequest(grantCode:String?) {
        if let grantCode = grantCode {
            var options:RequestOptions  = RequestOptions();
            
            options.parameters = createTokenRequestParams(grantCode);
            options.headers = createTokenRequestHeaders(grantCode);
            addSessionIdHeader(&options.headers);
            options.requestMethod = HttpMethod.POST;
            
            var listener:AuthorizationResponseListener = AuthorizationResponseListener( callback: { (response: Response?, error: NSError?) in
                self.saveTokenFromResponse(response!);
                self.handleAuthorizationSuccess(response!, error: error);
            })
            
            //TODO:ilan - fix listener
            authorizationRequestSend("token", options: options, listener: listener);
        } else {
            //TODO: handle error
        }
    }
    
    private func authorizationRequestSend(path:String, options:RequestOptions ,listener: ResponseListener?) {
        
        do {
            let authorizationRequestManager:AuthorizationRequestAgent = AuthorizationRequestAgent();
            //            authorizationRequestManager.initialize(listener);
            //            try authorizationRequestManager.sendRequest(path, options: options);
            
            authorizationRequestManager.send(path, options: options, withListener: listener)
            
        } catch  {
            //            TODO: handle exception
        }
    }
    
    
    private func saveTokenFromResponse(response:Response) {
        do {
            if let data = response.responseData, responseJson =  try NSJSONSerialization.JSONObjectWithData(data, options: []) as? [String:AnyObject]{
                if let accessToken = responseJson["access_token"] as? String, idToken = responseJson["id_token"] as? String {
                    
                    //save the tokens
                    self.preferences.accessToken!.set(accessToken)
                    self.preferences.accessToken!.set(accessToken);
                    self.preferences.idToken!.set(idToken);
                    
                    //save the user identity separately
                    let fullNameArr = idToken.componentsSeparatedByString("\\.")
//                    byte[] decodedIdTokenData = Base64.decode(fullNameArr[1], Base64.DEFAULT);
                        var decodedIdTokenString:String = "" //TODO: delete this line
                    //                    var decodedIdTokenString:String = decodedIdTokenData;
                    if let decodedData = decodedIdTokenString.dataUsingEncoding(NSUTF8StringEncoding), idTokenJson = try NSJSONSerialization.JSONObjectWithData(decodedData, options: []) as? [String:AnyObject]{
                        if let imfUser = idTokenJson["imf.user"] as? String? {
                            self.preferences.userIdentity!.set(imfUser)
                        }
                    }
                }
                self.logger.debug("token successfully saved");
            }
        } catch  {
            // handle Exception
        }
    }
    
    private func createRegistrationParams() -> [String:String]{
//        registrationKeyPair = KeyPairUtility.generateRandomKeyPair();
        
        var csrJSON = [String:String]()
        var params = [String:String]()
        
        
        do {
            //TODO: do we really need this classes or just make them a dictionary
//            DeviceIdentity deviceData =  DeviceIdentity(preferences.deviceIdentity.getAsMap());
//            AppIdentity applicationData =  AppIdentity(preferences.appIdentity.getAsMap());
//            
//            csrJSON["deviceId"] =  deviceData.getId()
//            csrJSON["deviceOs"] =  deviceData.getOS()
//            csrJSON["deviceModel"] = deviceData.getModel()
//            csrJSON["applicationId"] = applicationData.getId()
//            csrJSON["applicationVersion"] = applicationData.getVersion()
//            csrJSON["environment"] =  "iOS" //TODO: is this ok?
//            
            var csrValue:String = "" //TODO: delete this line
//            csrValue:String = jsonSigner.sign(registrationKeyPair, csrJSON);
            
            
            params["CSR"] =  csrValue;
            
            return params;
        } catch {
            //TODO: handle error
        }
    }
    
    private func createRegistrationHeaders() -> [String:String]{
        var headers = [String:String]()
        addSessionIdHeader(&headers);
        
        return headers;
    }
    
    
    private func extractLocationHeader(response:Response) -> String? {
        
        
        //TODO: is it really a set or should I change to just string
        
        if let location = response.headers?["location"] as? Set<String> {
            logger.debug("Location header extracted successfully");
            return location.first;
        } else {
            //TODO: handle error
        }
        return nil
    }
    
    
    private func extractGrantCode(urlString:String?) -> String?{
        
        if let urlString = urlString {
            var url:NSURL = NSURL(fileURLWithPath: urlString)
            var code:String?
            //            var code:String? = Utils.getParameterValueFromQuery(url.getQuery(), "code");
            
            if let code = code {
                logger.debug("Grant code extracted successfully");
                return code;
            } else {
                //TODO: handle error
            }
        } else {
            //TODO: handle error
        }
        return nil
        
    }
    
    private func saveCertificateFromResponse(response:Response?) {
        do {
            var responseBody:String? = response?.responseText
            if let data = responseBody?.dataUsingEncoding(NSUTF8StringEncoding), jsonResponse = try NSJSONSerialization.JSONObjectWithData(data, options: []) as? [String : AnyObject] {
                //handle certificate
                if let certificateString = jsonResponse["certificate"] as? String {
//                    X509Certificate certificate = CertificatesUtility.base64StringToCertificate(certificateString);
                    
//                    CertificatesUtility.checkValidityWithPublicKey(certificate, registrationKeyPair.getPublic());
                    
//                    certificateStore.saveCertificate(registrationKeyPair, certificate);
                    
                //save the clientId separately
                    if let id = jsonResponse["clientId"] as? String? {
                        preferences.clientId!.set(id)
                    } else {
                        //TODO: handle error
                    }
                } else {
                    //TODO: handle error
                }
            }
        } catch {
            //TODO: handle error
        }
        
        logger.debug("certificate successfully saved");
    }
    private func addSessionIdHeader(inout headers:[String:String]) {
        headers["X-WL-Session"] =  self.sessionId //TODO: is this the right assignment
    }
    
    internal class AuthorizationResponseListener: ResponseListener {
        
        init(callback: MfpCompletionHandler?) {
            //in case of success call the callback
            self.handleAuthorizationSuccessResponseFunction = callback
        }
        
        private var handleAuthorizationSuccessResponseFunction: MfpCompletionHandler?
        internal func handleAuthorizationSuccessResponse(response: Response) {}
        
        internal func onSuccess(response: Response ) {
            do {
                try handleAuthorizationSuccessResponse(response);
            } catch {
               //TODO: handle error
            }
        }
        //TODO: not sure how to implement this
        //        public func onFailure(Response, Throwable t, JSONObject extendedInfo) {
        //            handleAuthorizationFailure(response, t, extendedInfo);
        //        }
    }
    
}