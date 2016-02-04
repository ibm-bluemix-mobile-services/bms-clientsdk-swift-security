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

import Foundation
import BMSCore

public class AuthorizationRequestManager {
       
    //MARK constants
    /**
    * Parts of the path to authorization endpoint.
    */
    static let AUTH_SERVER_NAME = "imf-authserver"
    static let AUTH_PATH = "authorization/v1/apps/"
    
    /**
    * The name of "result" parameter returned from authorization endpoint.
    */
    static let WL_RESULT = "wl_result";
    
    /**
    * Name of rewrite domain header. This header is added to authorization requests.
    */
    static let REWRITE_DOMAIN_HEADER_NAME = "X-REWRITE-DOMAIN"
    
    /**
    * Name of location header.
    */
    static let LOCATION_HEADER_NAME = "Location"
    
    /**
    * Name of the standard "www-authenticate" header.
    */
    static let AUTHENTICATE_HEADER_NAME = "WWW-Authenticate"
    
    /**
    * Name of "www-authenticate" header value.
    */
    static let AUTHENTICATE_HEADER_VALUE = "WL-Composite-Challenge"
    
    /**
    * Names of JSON values returned from the server.
    */
    static let AUTH_FAILURE_VALUE_NAME = "WL-Authentication-Failure"
    static let AUTH_SUCCESS_VALUE_NAME = "WL-Authentication-Success"
    static let CHALLENGES_VALUE_NAME = "challenges"
    
    //MARK vars (private)
    
    var requestPath : String?
    var requestOptions : RequestOptions?
    
    var answers: [String : AnyObject]?
    
    public static var overrideServerHost: String?
    
    
    private static let logger = Logger.getLoggerForName(MFP_SECURITY_PACKAGE)
    
    public enum AuthorizationRequestManagerErrors : ErrorType {
        case ERROR(String)
        
    }
    
    internal var defaultCompletionHandler : MfpCompletionHandler
    
    internal init(completionHandler: MfpCompletionHandler?) {
        
        if let handler = completionHandler {
            defaultCompletionHandler = handler
        } else {
            defaultCompletionHandler = {(response: Response?, error: NSError?) in
                AuthorizationRequestManager.logger.debug("ResponseListener is not specified. Defaulting to empty listener.")
            }

        }
        
        AuthorizationRequestManager.logger.debug("AuthorizationRequestAgent is initialized.")
    }
    
    public func send(path:String , options:RequestOptions){
        var rootUrl:String = ""
        var computedPath:String = path
        
        if path.hasPrefix(BMSClient.HTTP_SCHEME) && path.characters.indexOf(":") != nil {
            let url = NSURL(string: path)
            if let pathTemp = url?.path {
                rootUrl = (path as NSString).stringByReplacingOccurrencesOfString(pathTemp, withString: "")
                computedPath = pathTemp
            }
            else {
               rootUrl = ""
            }
        }
        else {
            //path is relative
            var serverHost = BMSClient.defaultProtocol
                + "://"
                + AuthorizationRequestManager.AUTH_SERVER_NAME
                + "."
                + BMSClient.sharedInstance.bluemixRegionSuffix!
            
            if let overrideServerHost = AuthorizationRequestManager.overrideServerHost {
                serverHost = overrideServerHost
            }
            
            rootUrl = serverHost
                + "/"
                + AuthorizationRequestManager.AUTH_SERVER_NAME
                + "/"
                + AuthorizationRequestManager.AUTH_PATH
                + BMSClient.sharedInstance.bluemixAppGUID!
        }
        do {
            try sendInternal(rootUrl, path: computedPath, options: options)
        }
        catch {
            print("something wrong")
        }
    }
    
    internal static func isAuthorizationRequired(response: Response?) -> Bool {
        if let header = response?.headers![MCAAuthorizationManager.WWW_AUTHENTICATE_HEADER] {
            if let authHeader : String = header as? String where authHeader == AuthorizationRequestManager.AUTHENTICATE_HEADER_VALUE{
                return true
            }
        }
        
        return false

    }
//    
//    /**
//    * Checks server response for MFP 401 error. This kind of response should contain MFP authentication challenges.
//    *
//    * @param response Server response.
//    * @return <code>true</code> if the server response contains 401 status code along with MFP challenges.
//    */
//    private boolean isAuthorizationRequired(Response response) {
//    if (response != null && response.getStatus() == 401) {
//    ResponseImpl responseImpl = (ResponseImpl)response;
//    String challengesHeader = responseImpl.getFirstHeader(AUTHENTICATE_HEADER_NAME);
//    
//    if (AUTHENTICATE_HEADER_VALUE.equalsIgnoreCase(challengesHeader)) {
//    return true;
//    }
//    }
    
//    return false;
//    }
    
    internal func sendInternal(rootUrl:String, path:String, options:RequestOptions?) throws {
        if let unWrappedOptions = options {
            self.requestOptions = unWrappedOptions
        }
        else {
            self.requestOptions = RequestOptions()
        }
        
        requestPath = Utils.concatenateUrls(rootUrl, path: path)
        
        var request = AuthorizationRequest(url:requestPath!, method:self.requestOptions!.requestMethod)
        
        if requestOptions!.timeout != 0 {
            request.timeout = requestOptions!.timeout
        } else {
            request.timeout = BMSClient.sharedInstance.defaultRequestTimeout
        }
        
        if let unwrappedHeaders = options?.headers {
            request.addHeaders(unwrappedHeaders)
        }
        
        if let unwrappedAnswers = answers {
                let ans = Utils.JSONStringify(unwrappedAnswers)
                let authorizationHeaderValue = "Bearer \(ans)"
                request.addHeader("Authorization", val: authorizationHeaderValue)
        }
        
        let callback: MfpCompletionHandler = { (response: Response?, error: NSError?) in
            
            func isRedirect(response: Response?) -> Bool{
                return 300..<399 ~= (response?.statusCode)!
            }
            
            func processResponseWrapper(response:Response?, isFailure:Bool) {
                let isRedirect:Bool = isRedirect(response)
                if isFailure || !isRedirect {
                    self.processResponse(response)
                }
                else {
                    do {
                        try self.processRedirectResponse(response!)
                    } catch {
                        print("something wrong 2")
                    }
                    
                }
            }
//            guard error != nil else {
//                AuthorizationRequestManager.logger.error("Error while getting response:\(error)")
//                return
//            }
            
            
            //check this is error failure
            if error != nil {
                if (AuthorizationRequestManager.isAuthorizationRequired(response)) {
                    processResponseWrapper(response,isFailure: true)
                } else {
                    self.defaultCompletionHandler(response, error)
                }
            }
            
            let successResponse = response?.isSuccessful
            if successResponse == true || isRedirect(response) {
                //process onSuccess
                processResponseWrapper(response!, isFailure: false)
            }
            else {
                //process onFailure
                if (AuthorizationRequestManager.isAuthorizationRequired(response)) {
                    processResponseWrapper(response,isFailure: true)
                } else {
                    self.defaultCompletionHandler(response, error)
                }
            }
        }
        
//        String rewriteDomainHeaderValue = BMSClient.getInstance().getRewriteDomain();
//        request.addHeader("X-REWRITE-DOMAIN", val:"ng.bluemix.net");
        
        if let method = options?.requestMethod where method == HttpMethod.GET{
            request.queryParameters = options?.parameters
            request.send(callback)
        } else {
            request.sendWithCompletionHandler((options?.parameters)!, callback: callback)
        }
    }
    
    /**
     Processes authentication failures.
     
     - parameter jsonFailures: Collection of authentication failures
     */
     //TODO: should this get optional ???
    internal func processFailures(jsonFailures: [String:AnyObject]?) {
        
        guard let failures = jsonFailures else {
            return
        }
        
        let mcaAuthManager = MCAAuthorizationManager.sharedInstance
        for (realm, challenge) in failures {
            if let handler = mcaAuthManager.getChallengeHandler(realm) {
                handler.handleFailure(challenge as? [String : AnyObject])
            }
            else {
                AuthorizationRequestManager.logger.error("Challenge handler for realm: \(realm), is not found");
            }
        }
    }
     //TODO: should this get optional ???
    internal func processSuccesses(jsonSuccesses: [String:AnyObject]?) {

        guard let successes = jsonSuccesses else {
            return
        }
        
        let mcaAuthManager = MCAAuthorizationManager.sharedInstance
        for (realm, challenge) in successes {
            if let handler = mcaAuthManager.getChallengeHandler(realm) {
                handler.handleSuccess(challenge as? [String : AnyObject])
            }
            else {
                AuthorizationRequestManager.logger.error("Challenge handler for realm: \(realm), is not found");
            }
        }
    }
    
    enum ResponseError: ErrorType {
        case NoLocation(String)
        case ChallengeHandlerNotFound(String)
    }
    
    internal func processResponse(response: Response?) {
        // at this point a server response should contain a secure JSON with challenges
        //TODO: ilan check if we need to send an errir here someplace or just onsuccces (like android)
        guard let responseJson = Utils.extractSecureJson(response) else {
            defaultCompletionHandler(response, nil)
            return
        }
        
        if let challanges = responseJson[AuthorizationRequestManager.CHALLENGES_VALUE_NAME]  as? [String: AnyObject]{
            do {
                try startHandleChallenges(challanges, response: response!)
            } catch {
                //TODO:ilan this is not checked, in startHandleChallenges it throws a runtime (android) so what here?
            }
            
        }
        else {
            defaultCompletionHandler(response, nil)
        }
    }
    
    internal func startHandleChallenges(jsonChallenges: [String: AnyObject], response: Response) throws {
        let challenges = Array(jsonChallenges.keys)
        
        if (AuthorizationRequestManager.isAuthorizationRequired(response)) {
            setExpectedAnswers(challenges)
        }
        let mcaAuthManager = MCAAuthorizationManager.sharedInstance
        for (realm, challenge) in jsonChallenges {
             if let handler = mcaAuthManager.getChallengeHandler(realm) {
                handler.handleChallenge(self, challenge: challenge as? [String : AnyObject])
            }
            else {
                throw ResponseError.ChallengeHandlerNotFound("Challenge handler for realm: \(realm), is not found")
            }
        }
    }
    
    internal func setExpectedAnswers(realms:[String]) {
        guard answers != nil else {
            return
        }
        
        for realm in realms {
            answers![realm] = ""
        }
    }
    
    public func removeExpectedAnswer(realm:String) {
        if answers != nil {
            answers!.removeValueForKey(realm)
        }
        
        if isAnswersFilled() {
            resendRequest()
        }
        
    }
    
    /**
     Adds an expected challenge answer to collection of answers.
     
     - parameter answer: Answer to add.
     - parameter realm:  Authentication realm for the answer.
     */
    public func submitAnswer(answer:[String:AnyObject]?, realm:String) {
        guard let unwrappedAnswer = answer else {
            AuthorizationRequestManager.logger.error("Cannot submit nil answer for realm \(realm)")
            return
        }
        
        if answers == nil {
            answers = [String:AnyObject]()
        }
        
        answers![realm] = unwrappedAnswer
        if isAnswersFilled() {
            resendRequest()
        }
    }
    
    public func isAnswersFilled() -> Bool {
        guard answers != nil else {
            return true
        }
        
        for (_, value) in answers! {
            if let sVal:String = value as? String where sVal == "" {
                return false
            }
        }
        
        return true
    }
    
    internal func resendRequest() {
//        send(path:String , options:RequestOptions, completionHandler: MfpCompletionHandler?)
        send(requestPath!, options: requestOptions!)
    }
    
    internal func processRedirectResponse(response:Response) throws {
        
        func getLocationString(obj:AnyObject?) -> String? {
            guard obj != nil else {
                return nil
            }
            
            if case let myObj as String = obj![0] {
                return myObj
            }
            else if case let str as String = obj{
                return str
            }
            return nil
        }
        
        guard let location = /*try*/ getLocationString(response.headers?[AuthorizationRequestManager.LOCATION_HEADER_NAME]) else {
           throw ResponseError.NoLocation("Redirect response does not contain 'Location' header.")
        }
        
        // the redirect location url should contain "wl_result" value in query parameters.
        guard let url:NSURL = NSURL(string: location)! else {
            throw ResponseError.NoLocation("Could not create URL from 'Location' header.")
        }
        
        let query = url.query
        
        if let q = query where q.containsString(AuthorizationRequestManager.WL_RESULT) {
            if let result = Utils.getParameterValueFromQuery(query, paramName: AuthorizationRequestManager.WL_RESULT), jsonResult = Utils.parseJsonStringtoDictionary(result) {
            
                // process failures if any
                
                if let jsonFailures = jsonResult[AuthorizationRequestManager.AUTH_FAILURE_VALUE_NAME] {
                    processFailures(jsonFailures as? [String : AnyObject])
                }
                
                if let jsonSuccesses = jsonResult[AuthorizationRequestManager.AUTH_SUCCESS_VALUE_NAME] {
                    processSuccesses(jsonSuccesses as? [String: AnyObject])
                }
            }
        }
        
        defaultCompletionHandler(response, nil)
    }
}
