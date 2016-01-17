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
    private var authorizationQueue:Queue<MfpCompletionHandler> = Queue<MfpCompletionHandler>()
    private var registrationKeyPair:(privateKey : SecKey,publicKey : SecKey)?
//    private var securityUtils:SecurityUtils
    private var logger:Logger
    private var sessionId:String = ""

    private var privateKeyIdentifier : String {
        get{
            let nameAndVer = Utils.getApplicationDetails()
            return "\(BMSAuthorizationManager._PRIVATE_KEY_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
//           return key.dataUsingEncoding(NSUTF8StringEncoding)!
        }
    }
    
    private var publicKeyIdentifier : String {
        get{
            let nameAndVer = Utils.getApplicationDetails()
            return "\(BMSAuthorizationManager._PUBLIC_KEY_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
//            return key.dataUsingEncoding(NSUTF8StringEncoding)!
        }
    }
    
    private static let logger = Logger.getLoggerForName(MFP_SECURITY_PACKAGE)
    
    private func handleAuthorizationSuccess(response: Response, error: NSError?) {
        while !self.authorizationQueue.isEmpty() {
            let next:MfpCompletionHandler = authorizationQueue.remove()!
            next(response, error)
        }
    }
    
    internal init(preferences:AuthorizationManagerPreferences)
    {
        
        self.logger = Logger.getLoggerForName(MFP_PACKAGE_PREFIX+"AuthorizationProcessManager")
        self.preferences = preferences;
        self.authorizationQueue = Queue<MfpCompletionHandler>();
//        self.securityUtils = SecurityUtils()
        //    String uuid = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        
        //case where the shared preferences were deleted but the certificate is saved in the keystore
        if let _ = preferences.clientId!.get() {
            
        } else {
             do {
                //TODO : maybe change this label
                let certificate = try SecurityUtils.getCertificateFromKeyChain("certificateLabel")
                    try     preferences.clientId!.set(SecurityUtils.getClientIdFromCertificate(certificate));
                } catch  {
                    // handle exception
                }
                
            
        }
        //generate new random session id
        sessionId = NSUUID().UUIDString
    }
    
    internal func startAuthorizationProcess(callback:MfpCompletionHandler?) {
        
        //TODO:ILAN should this be check or should we NOT allow nil callback here?
        if let tempCallback = callback {
            authorizationQueue.add(tempCallback);
        }
        
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
        SecurityUtils.deleteCertificateFromKeyChain("certificateLabel")
        
        let options:RequestOptions = RequestOptions();
        options.parameters = createRegistrationParams();
        options.headers = createRegistrationHeaders();
        options.requestMethod = HttpMethod.POST
        
        let callBack:MfpCompletionHandler = {(response: Response?, error: NSError?) in
            if error == nil {
                if let unWrappedResponse = response where unWrappedResponse.isSuccessful {
                    self.saveCertificateFromResponse(response);
                    self.invokeAuthorizationRequest();
                }
                else {
                    //TODO : call on failure
                }
            }
        }
        //TODO:ilan fix callback
        authorizationRequestSend("clients/instance", options: options, completionHandler: callBack);
    }
    
    private  func createTokenRequestHeaders(grantCode:String) -> [String:String]{
        var payload = [String:String]()
        var headers = [String:String]()
        do {
            payload["code"] = grantCode
            var keyPair = registrationKeyPair // try SecurityUtils.getKeyPairRefFromKeyChain("fff", privateTag: "fff")
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
        let params : [String : String] = [
            "code" : grantCode,
            "client_id" : preferences.clientId!.get()!,
            "grant_type" : "authorization_code",
            "redirect_uri" :AuthorizationProcessManager.HTTP_LOCALHOST
        ]
        
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
        
        var options:RequestOptions = RequestOptions()
        
        options.parameters = createAuthorizationParams()
        options.headers = [String:String]()
        addSessionIdHeader(&options.headers)
        options.requestMethod = HttpMethod.GET
        var callBack:MfpCompletionHandler = {(response: Response?, error: NSError?) in
            if error == nil {
                if let unWrappedResponse = response where unWrappedResponse.isSuccessful {
                    var location:String? = self.extractLocationHeader(response!)
                    var grantCode:String? = self.extractGrantCode(location)
                    self.invokeTokenRequest(grantCode)
                    
                }
                else {
                    //TODO : call on failure
                }
            }
        }
        
        authorizationRequestSend("authorization", options: options,completionHandler: callBack)
    }
    
    private func invokeTokenRequest(grantCode:String?) {
        if let grantCode = grantCode {
            
            var options:RequestOptions  = RequestOptions();
            
            options.parameters = createTokenRequestParams(grantCode);
            options.headers = createTokenRequestHeaders(grantCode);
            addSessionIdHeader(&options.headers);
            options.requestMethod = HttpMethod.POST;
            
            var callback:MfpCompletionHandler = {(response: Response?, error: NSError?) in
                if error == nil {
                    if let unWrappedResponse = response where unWrappedResponse.isSuccessful {
                        self.saveTokenFromResponse(response!);
                        self.handleAuthorizationSuccess(response!, error: error);
                    }
                    else {
                        //TODO : call on failure
                    }
                }
            }
            
            authorizationRequestSend("token", options: options, completionHandler: callback)
        } else {
            //TODO: handle error
        }
    }
    
    private func authorizationRequestSend(path:String, options:RequestOptions, completionHandler: MfpCompletionHandler?) {
        
        do {
            let authorizationRequestManager:AuthorizationRequestAgent = AuthorizationRequestAgent();
            try authorizationRequestManager.send(path, options: options, completionHandler: completionHandler)
        } catch  {
            // TODO: handle exception
        }
    }
    
    
    private func saveTokenFromResponse(response:Response) {
        do {
            if let data = response.responseData, responseJson =  try NSJSONSerialization.JSONObjectWithData(data, options: []) as? [String:AnyObject]{
                if let accessToken = responseJson["access_token"] as? String, idToken = responseJson["id_token"] as? String {
                    
                    //save the tokens
                    self.preferences.accessToken!.set(accessToken)
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
        let nameAndVer = Utils.getApplicationDetails()
//        let privateTag = "\(BMSAuthorizationManager._PRIVATE_KEY_LABEL):\(nameAndVer.name):\(nameAndVer.version)"
//        let publicTag = "\(BMSAuthorizationManager._PUBLIC_KEY_LABEL):\(nameAndVer.name):\(nameAndVer.version)"
       
        var params = [String:String]()
        do {
             registrationKeyPair = try SecurityUtils.generateKeyPair(512, publicTag: publicKeyIdentifier, privateTag: privateKeyIdentifier)
            let csrValue:String = try SecurityUtils.signCsr(deviceDictionary(), keyIds: (publicKeyIdentifier, privateKeyIdentifier), keySize: 512)
//            var csrValue:String  = ""
            params["CSR"] = csrValue;
            return params;
        } catch {
            //TODO: handle error
        }
        return params
    }
    
    func deviceDictionary() -> [String : AnyObject] {
        var device = [String : AnyObject]()
        device[BMSAuthorizationManager.JSON_DEVICE_ID_KEY] =  UIDevice.currentDevice().systemVersion
        device[BMSAuthorizationManager.JSON_MODEL_KEY] =  UIDevice.currentDevice().model
        device[BMSAuthorizationManager.JSON_APPLICATION_ID_KEY] =  UIDevice.currentDevice().systemVersion
        let appInfo = Utils.getApplicationDetails()
        device[BMSAuthorizationManager.JSON_APPLICATION_ID_KEY] =  appInfo.name
        device[BMSAuthorizationManager.JSON_APPLICATION_VERSION_KEY] =  appInfo.version
        device[BMSAuthorizationManager.JSON_ENVIRONMENT_KEY] =  BMSAuthorizationManager.JSON_IOS_ENVIRONMENT_VALUE
        
        return device
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
            let responseBody:String? = response?.responseText
            if let data = responseBody?.dataUsingEncoding(NSUTF8StringEncoding), jsonResponse = try NSJSONSerialization.JSONObjectWithData(data, options: []) as? [String : AnyObject] {
                //handle certificate
                if let certificateString = jsonResponse["certificate"] as? String {
                    let certificate =  try SecurityUtils.getCertificateFromString(certificateString)
                    try  SecurityUtils.checkCertificatePublicKeyValidity(certificate, publicKeyTag: publicKeyIdentifier)
                    //TODO : maybe change label name
                    try SecurityUtils.saveCertificateToKeyChain(certificate, certificateLabel: "certificateLabel")
                    
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
    
}