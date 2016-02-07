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
    
    private static let HTTP_LOCALHOST:String = "http://localhost"
    private var authorizationQueue:Queue<MfpCompletionHandler> = Queue<MfpCompletionHandler>()
    private var registrationKeyPair:(privateKey : SecKey,publicKey : SecKey)?
    private var logger:Logger
    private var sessionId:String = ""
    private var preferences:AuthorizationManagerPreferences
    internal var authorizationPersistencePolicy:PersistencePolicy
    var completionHandler: MfpCompletionHandler?
    
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
        self.handleAuthorizationFailure(response, error: error, thrownError: nil)
    }
    
    private func handleAuthorizationFailure(response: Response?,  error: NSError?, thrownError: ErrorType?)
    {
        logger.error("Authorization process failed")
        if let unwrappedError = error {
            logger.error(unwrappedError.debugDescription)
        }
        if let unWrappedThrownError = thrownError {
            logger.error(String(unWrappedThrownError))
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
        self.authorizationQueue = Queue<MfpCompletionHandler>()
        self.authorizationPersistencePolicy = PersistencePolicy.ALWAYS
        //    String uuid = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID)
        self.preferences = preferences
        //generate new random session id
        sessionId = NSUUID().UUIDString
    }
    
    internal func startAuthorizationProcess(callback:MfpCompletionHandler?) {
        
        //TODO:ILAN should this be check or should we NOT allow nil callback here?
        if let tempCallback = callback {
            authorizationQueue.add(tempCallback)
        }
        
        //start the authorization process only if this is the first time we ask for authorization
        if (authorizationQueue.size == 1) {
            do {
            if (preferences.clientId!.get() == nil) {
                logger.info("starting registration process")
                try invokeInstanceRegistrationRequest()
            } else {
                logger.info("starting authorization process")
                /*try*/ invokeAuthorizationRequest()
            }
            } catch {
            self.handleAuthorizationFailure(nil , error: nil, thrownError: error)
           }
        } else {
            logger.info("authorization process already running, adding response listener to the queue");
            logger.debug("authorization process currently handling \(authorizationQueue.size) requests")
        }
    }
    
    private func invokeInstanceRegistrationRequest() throws {
        preferences.clientId!.clear()
        SecurityUtils.deleteCertificateFromKeyChain(certificateIdentifier)
        let options:RequestOptions = RequestOptions()
        options.parameters = try createRegistrationParams()
        options.headers = createRegistrationHeaders()
        options.requestMethod = HttpMethod.POST
        
        let callBack:MfpCompletionHandler = {(response: Response?, error: NSError?) in
            if error == nil {
                if let unWrappedResponse = response where unWrappedResponse.isSuccessful {
                    do {
                    try self.saveCertificateFromResponse(response)
                    self.invokeAuthorizationRequest()
                    } catch(let thrownError) {
                        self.handleAuthorizationFailure(response, error: error, thrownError: thrownError)
                        //TODO: Should I somehow propagate the error here?
                    }
                }
                else {
                    self.handleAuthorizationFailure(response, error: error)
                }
            } else {
                self.handleAuthorizationFailure(response, error: error)
            }
        }
        
        authorizationRequestSend("clients/instance", options: options, completionHandler: callBack)
    }
    
    private func createTokenRequestHeaders(grantCode:String) throws -> [String:String]{
        var payload = [String:String]()
        var headers = [String:String]()
        payload["code"] = grantCode
        let jws:String = try SecurityUtils.signCsr(payload, keyIds: (publicKeyIdentifier, privateKeyIdentifier), keySize: 512)
        headers = [String:String]()
        headers["X-WL-Authenticate"] =  jws
        return headers
    }
    
    private func createTokenRequestParams(grantCode:String) -> [String:String] {
        let params : [String : String] = [
            "code" : grantCode,
            "client_id" :  preferences.clientId!.get()!,
            "grant_type" : "authorization_code",
            "redirect_uri" :AuthorizationProcessManager.HTTP_LOCALHOST
        ]
        
        return params
    }
    
    private func createAuthorizationParams() -> [String:String]{
        
        var params = [String:String]()
        params["response_type"] =  "code"
        params["client_id"] =  preferences.clientId!.get()
        params["redirect_uri"] =  AuthorizationProcessManager.HTTP_LOCALHOST
        
        return params
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
                    do {
                    let location:String? = try self.extractLocationHeader(unWrappedResponse)
                    let grantCode:String? = try self.extractGrantCode(location)
                    self.invokeTokenRequest(grantCode)
                    } catch(let thrownError) {
                        self.handleAuthorizationFailure(response, error: error, thrownError: thrownError)
                    }
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
            
            let options:RequestOptions  = RequestOptions()
            
            options.parameters = createTokenRequestParams(unWrappedGrantCode)
            options.headers = try! createTokenRequestHeaders(unWrappedGrantCode)
            addSessionIdHeader(&options.headers)
            options.requestMethod = HttpMethod.POST
            
            let callback:MfpCompletionHandler = {(response: Response?, error: NSError?) in
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
    
    private func authorizationRequestSend(path:String, options:RequestOptions, completionHandler: MfpCompletionHandler?)  {
        
        //do {
        let authorizationRequestManager:AuthorizationRequestManager = AuthorizationRequestManager(completionHandler: completionHandler)
        
        /*   try */ authorizationRequestManager.send(path, options: options )
        //  } catch  {
        // TODO: handle exception
        //  }
    }
    
    private func saveTokenFromResponse(response:Response) throws {
        do {
            if let data = response.responseData, responseJson =  try NSJSONSerialization.JSONObjectWithData(data, options: []) as? [String:AnyObject]{
                if let accessTokenFromResponse = responseJson["access_token"] as? String, idTokenFromResponse = responseJson["id_token"] as? String {
                    //save the tokens
                    preferences.idToken!.set(idTokenFromResponse)
                    preferences.accessToken!.set(accessTokenFromResponse)
                    self.logger.debug("token successfully saved")
                    
                    guard let  decodedIdTokenData = Utils.decodeBase64WithString(idTokenFromResponse.componentsSeparatedByString(".")[1]), let _ = NSString(data: decodedIdTokenData, encoding: NSUTF8StringEncoding), decodedIdTokenString = String(data: decodedIdTokenData, encoding: NSUTF8StringEncoding), userIdentity = try Utils.parseJsonStringtoDictionary(decodedIdTokenString)["imf.user"] as? [String:AnyObject] else {
                        //TODO : handle error
                        return
                    }
                    preferences.userIdentity!.set(userIdentity)
                    
                }
            }
        } catch  {
            throw AuthorizationProcessManagerError.COULD_NOT_SAVE_TOKEN(("\(error)"))
        }
    }
    
    /**
     <#Description#>
     
     - returns: <#return value description#>
     */
    private func createRegistrationParams() throws -> [String:String]{
        var params = [String:String]()
        registrationKeyPair = try SecurityUtils.generateKeyPair(512, publicTag: publicKeyIdentifier, privateTag: privateKeyIdentifier)
        let csrValue:String = try SecurityUtils.signCsr(deviceDictionary(), keyIds: (publicKeyIdentifier, privateKeyIdentifier), keySize: 512)
        params["CSR"] = csrValue
        return params
    }
    
    func deviceDictionary() -> [String : AnyObject] {
        let deviceIdentity = DeviceIdentity()
        let appIdentity = AppIdentity()
        var device = [String : AnyObject]()
        device[MCAAuthorizationManager.JSON_DEVICE_ID_KEY] = deviceIdentity.getId()
        device[MCAAuthorizationManager.JSON_MODEL_KEY] =  deviceIdentity.getModel()
        device[MCAAuthorizationManager.JSON_OS_KEY] = deviceIdentity.getOS()
        device[MCAAuthorizationManager.JSON_APPLICATION_ID_KEY] =  appIdentity.getId()
        device[MCAAuthorizationManager.JSON_APPLICATION_VERSION_KEY] =  appIdentity.getVersion()
        device[MCAAuthorizationManager.JSON_ENVIRONMENT_KEY] =  MCAAuthorizationManager.JSON_IOS_ENVIRONMENT_VALUE
        
        return device
    }
    
    
    private func createRegistrationHeaders() -> [String:String]{
        var headers = [String:String]()
        addSessionIdHeader(&headers)
        
        return headers
    }
    
    private func extractLocationHeader(response:Response) throws -> String {
        if let location = response.headers?["Location"], stringLocation = location as? String {
            logger.debug("Location header extracted successfully")
            return stringLocation
        } else {
            throw AuthorizationError.CouldNotExtractLocationHeader
        }
    }
    
    
    private func extractGrantCode(urlString:String?) throws -> String{
        
        if let unWrappedUrlString = urlString, url:NSURL = NSURL(string: unWrappedUrlString), code = Utils.getParameterValueFromQuery(url.query, paramName: "code")  {
            logger.debug("Grant code extracted successfully")
            return code
        } else {
            throw AuthorizationError.CouldNotExtractGrantCode
        }
    }
    
    private func saveCertificateFromResponse(response:Response?) throws {
        guard let responseBody:String? = response?.responseText, data = responseBody?.dataUsingEncoding(NSUTF8StringEncoding) else {
            throw Errors.JsonIsMalformed
        }
        do {
            if let jsonResponse = try NSJSONSerialization.JSONObjectWithData(data, options: []) as? [String : AnyObject], certificateString = jsonResponse["certificate"] as? String {
                //handle certificate
                    let certificate =  try SecurityUtils.getCertificateFromString(certificateString)
                    try  SecurityUtils.checkCertificatePublicKeyValidity(certificate, publicKeyTag: publicKeyIdentifier)
                    try SecurityUtils.saveCertificateToKeyChain(certificate, certificateLabel: certificateIdentifier)
                    
                    //save the clientId separately
                    if let id = jsonResponse["clientId"] as? String? {
                        preferences.clientId!.set(id)
                    } else {
                       throw AuthorizationError.CertificateDoesNotIncludeClientId                     }
            }else {
                    throw AuthorizationError.ResponseDoesNotIncludeCertificate
            }
        }
        logger.debug("certificate successfully saved")
    }
    private func addSessionIdHeader(inout headers:[String:String]) {
        headers["X-WL-Session"] =  self.sessionId //TODO: is this the right assignment
    }
    
}