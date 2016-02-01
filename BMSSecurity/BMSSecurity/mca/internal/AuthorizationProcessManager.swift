/*
*     Copyright 2015 IBM Corp.
*     Licensed under the Apache License, Version 2.0 (the "License");
*     you may not use this file except in compliance with the License.
*     You may obtain a copy of the License at
*     http://www.apache.org/licenses/LICENSE-2.0
*     Unless required by applicable law or agreed to in writing, software
*     distributed under the License is distributed on an "AS IS" BASIS,
*     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*     See the License for the specific language governing permissions and
*     limitations under the License.
*/

import BMSCore
internal class AuthorizationProcessManager {
    
    private static let HTTP_LOCALHOST:String = "http://localhost";
    private var preferences:AuthorizationManagerPreferences  = AuthorizationManagerPreferences()
    private var authorizationQueue:Queue<MfpCompletionHandler> = Queue<MfpCompletionHandler>()
    private var registrationKeyPair:(privateKey : SecKey,publicKey : SecKey)?
//    private var securityUtils:SecurityUtils
    private var logger:Logger
    private var sessionId:String = ""
    
    var completionHandler: MfpCompletionHandler?

    private var privateKeyIdentifier : String {
        get{
            let nameAndVer = Utils.getApplicationDetails()
            return "\(MCAAuthorizationManager._PRIVATE_KEY_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
//           return key.dataUsingEncoding(NSUTF8StringEncoding)!
        }
    }
    
    private var publicKeyIdentifier : String {
        get{
            let nameAndVer = Utils.getApplicationDetails()
            return "\(MCAAuthorizationManager._PUBLIC_KEY_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
//            return key.dataUsingEncoding(NSUTF8StringEncoding)!
        }
    }
    
    private static let logger = Logger.getLoggerForName(MFP_SECURITY_PACKAGE)
    
    enum AuthorizationProcessManagerError : ErrorType {
        case COULD_NOT_SAVE_TOKEN(String)
    }
    
    private func handleAuthorizationSuccess(response: Response, error: NSError?) {
        while !self.authorizationQueue.isEmpty() {
            let next:MfpCompletionHandler = authorizationQueue.remove()!
            next(response, error)
        }
    }
    
    private func handleAuthorizationFailure(response: Response?,  error: NSError?) {
        logger.error("Authorization process failed")
        if let unwrappedError = error {
            logger.error(unwrappedError.debugDescription)
        }
        
        while !self.authorizationQueue.isEmpty() {
            let next:MfpCompletionHandler = authorizationQueue.remove()!
            next(response, error)
        }
    }
    
    //TODO:ilan add completionhandler
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
                    self.handleAuthorizationFailure(response, error: error)
                }
            } else {
                self.handleAuthorizationFailure(response, error: error)
            }
        }
       
        authorizationRequestSend("clients/instance", options: options, completionHandler: callBack);
    }
    
    private  func createTokenRequestHeaders(grantCode:String) -> [String:String]{
        var payload = [String:String]()
        var headers = [String:String]()
        do {
            payload["code"] = grantCode
            let jws:String = try SecurityUtils.signCsr(payload, keyIds: (publicKeyIdentifier, privateKeyIdentifier), keySize: 512)
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
        let options:RequestOptions = RequestOptions()
        
        options.parameters = createAuthorizationParams()
        options.headers = [String:String]()
        addSessionIdHeader(&options.headers)
        options.requestMethod = HttpMethod.GET
        let callBack:MfpCompletionHandler = {(response: Response?, error: NSError?) in
            if error == nil {
                if let unWrappedResponse = response {
                    let location:String? = self.extractLocationHeader(unWrappedResponse)
                    let grantCode:String? = self.extractGrantCode(location)
                    self.invokeTokenRequest(grantCode)
                }
                else {
                    self.handleAuthorizationFailure(response, error: error)
                }
            } else {
                self.handleAuthorizationFailure(response, error: error)
            }
        }
        
        authorizationRequestSend("authorization", options: options,completionHandler: callBack)
    }
    
    private func invokeTokenRequest(grantCode:String?) {
        if let unWrappedGrantCode = grantCode {
            
            var options:RequestOptions  = RequestOptions();
            
            options.parameters = createTokenRequestParams(unWrappedGrantCode);
            options.headers = createTokenRequestHeaders(unWrappedGrantCode);
            addSessionIdHeader(&options.headers);
            options.requestMethod = HttpMethod.POST;
            
            var callback:MfpCompletionHandler = {(response: Response?, error: NSError?) in
                if error == nil {
                    if let unWrappedResponse = response where unWrappedResponse.isSuccessful {
                        do {
                            //TODO: ilan - this is not coded well, check on errors here
                            try self.saveTokenFromResponse(response!)
                            self.handleAuthorizationSuccess(response!, error: error)
                        } catch(let error2) {
                            self.handleAuthorizationFailure(nil, error: NSError(domain: "", code: -1, userInfo: [NSLocalizedDescriptionKey:"\(error2)"]))
                        }
                    }
                    else {
                        self.handleAuthorizationFailure(response, error: error)
                    }
                } else {
                    self.handleAuthorizationFailure(response, error: error)
                }

            }
            
            authorizationRequestSend("token", options: options, completionHandler: callback)
        } else {
            //TODO: handle error
        }
    }
    
    private func authorizationRequestSend(path:String, options:RequestOptions, completionHandler: MfpCompletionHandler?) {
        
        do {
            let authorizationRequestManager:AuthorizationRequestManager = AuthorizationRequestManager(completionHandler: completionHandler)
            try authorizationRequestManager.send(path, options: options )
        } catch  {
            // TODO: handle exception
        }
    }
    
    private func saveTokenFromResponse(response:Response) throws {
        do {
            if let data = response.responseData, responseJson =  try NSJSONSerialization.JSONObjectWithData(data, options: []) as? [String:AnyObject]{
                if let accessToken = responseJson["access_token"] as? String, idToken = responseJson["id_token"] as? String {
                    
                    //save the tokens
                    self.preferences.accessToken!.set(accessToken)
                    self.preferences.idToken!.set(idToken);
                    
                    //save the user identity separately
                    let fullNameArr = idToken.componentsSeparatedByString(".")
                    guard let decodedIdTokenData = SecurityUtils.decodeBase64WithString(fullNameArr[1]), let _ = NSString(data: decodedIdTokenData, encoding: NSUTF8StringEncoding) else {
                        throw AuthorizationProcessManagerError.COULD_NOT_SAVE_TOKEN("Could not decode input string")
                    }
                    
                    if let idTokenJson = try NSJSONSerialization.JSONObjectWithData(decodedIdTokenData, options: []) as? [String:AnyObject] {
                        if let imfUser = idTokenJson["imf.user"] {
                            self.preferences.userIdentity!.set(Utils.JSONStringify(imfUser))
                        }
                    }
                }
                self.logger.debug("token successfully saved");
            }
        } catch  {
            throw AuthorizationProcessManagerError.COULD_NOT_SAVE_TOKEN(("\(error)"))
        }
    }
   
    /**
     <#Description#>
     
     - returns: <#return value description#>
     */
    private func createRegistrationParams() -> [String:String]{
        var params = [String:String]()
        do {
             registrationKeyPair = try SecurityUtils.generateKeyPair(512, publicTag: publicKeyIdentifier, privateTag: privateKeyIdentifier)
            let csrValue:String = try SecurityUtils.signCsr(deviceDictionary(), keyIds: (publicKeyIdentifier, privateKeyIdentifier), keySize: 512)
            params["CSR"] = csrValue;
            return params;
        } catch {
            //TODO: handle error
        }
        return params
    }
    
    func deviceDictionary() -> [String : AnyObject] {
        var device = [String : AnyObject]()
        device[MCAAuthorizationManager.JSON_DEVICE_ID_KEY] =  UIDevice.currentDevice().identifierForVendor?.UUIDString
        device[MCAAuthorizationManager.JSON_MODEL_KEY] =  UIDevice.currentDevice().model
        let appInfo = Utils.getApplicationDetails()
        device[MCAAuthorizationManager.JSON_APPLICATION_ID_KEY] =  appInfo.name
        device[MCAAuthorizationManager.JSON_APPLICATION_VERSION_KEY] =  appInfo.version
        device[MCAAuthorizationManager.JSON_ENVIRONMENT_KEY] =  MCAAuthorizationManager.JSON_IOS_ENVIRONMENT_VALUE
        
        return device
    }
    
    private func createRegistrationHeaders() -> [String:String]{
        var headers = [String:String]()
        addSessionIdHeader(&headers);
        
        return headers;
    }
    
    private func extractLocationHeader(response:Response) -> String? {
          if let location = response.headers?["Location"], stringLocation = location as? String {
            logger.debug("Location header extracted successfully");
            return stringLocation;
        } else {
            //TODO: handle error
        }
        return nil
    }
    
    private func extractGrantCode(urlString:String?) -> String?{
        
        if let unWrappedUrlString = urlString, url:NSURL = NSURL(string: unWrappedUrlString) {
            let code:String? = Utils.getParameterValueFromQuery(url.query, paramName: "code");
            
            if let unWrappedCode = code {
                logger.debug("Grant code extracted successfully");
                return unWrappedCode;
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