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

public class MCAAuthorizationManager : AuthorizationManager {
    
    public static let BEARER = "Bearer"
    public static let AUTHORIZATION_HEADER = "Authorization"
    public static let WWW_AUTHENTICATE_HEADER = "WWW-Authenticate"
    
    //JSON keys
    public static let JSON_CERTIFICATE_KEY = "certificate"
    public static let JSON_CLIENT_ID_KEY = "clientId"
    public static let JSON_DEVICE_ID_KEY = "deviceId"
    public static let JSON_OS_KEY = "deviceOs"
    public static let JSON_ENVIRONMENT_KEY = "environment"
    public static let JSON_MODEL_KEY = "deviceModel"
    public static let JSON_APPLICATION_ID_KEY = "applicationId"
    public static let JSON_APPLICATION_VERSION_KEY = "applicationVersion"
    public static let JSON_IOS_ENVIRONMENT_VALUE = "iOSnative"
    public  static let JSON_ACCESS_TOKEN_KEY = "access_token"
    public static let JSON_ID_TOKEN_KEY = "id_token"
    
    //Keychain constants
        private var lockQueue = dispatch_queue_create("MCAAuthorizationManagerQueue", DISPATCH_QUEUE_CONCURRENT)
    private var challengeHandlers:[String:ChallengeHandler]
    
    var idToken : String {
        get{
            //            SecurityUtils.getDataForLable("\():\():\()")
            //            return [NSString stringWithFormat:"%:%:%", OAUTH_ID_TOKEN_LABEL, bundleID, appVersion]
            //               if (!_idToken) {
            //            NSString *token = [self getKeyChainItemForLabel:self.idTokenLabel]
            //            if (token.length > 0) {
            //            [self setIdToken:token]
            //            }
            //            }
            //            return _idToken
            //            }
            
            return ""
            
        }
    }
    
    public enum AutorizationError : ErrorType {
        case CANNOT_ADD_CHALLANGE_HANDLER(String)
    }
    
    public static let sharedInstance = MCAAuthorizationManager()
    
    var processManager : AuthorizationProcessManager
    
    private init() {
        processManager = AuthorizationProcessManager()
        self.challengeHandlers = [String:ChallengeHandler]()
        BMSClient.sharedInstance.sharedAuthorizationManager = self
        challengeHandlers = [String:ChallengeHandler]()
        
        //        if preferences.deviceIdentity == nil {
        //            preferences.deviceIdentity?.set(<#T##json: [String : AnyObject]##[String : AnyObject]#>)
        //        }
    }
    
    public func isAuthorizationRequired(httpResponse: Response?) -> Bool {
        if let header = httpResponse?.headers![MCAAuthorizationManager.WWW_AUTHENTICATE_HEADER] {
            if let authHeader : String = header as? String {
                return isAuthorizationRequired(httpResponse!.statusCode!, responseAuthorizationHeader: authHeader)
            }
        }
        
        return false
    }
    
    public func isAuthorizationRequired(statusCode: Int, responseAuthorizationHeader: String) -> Bool {
        
        if statusCode == 401 || statusCode == 403 {
            if responseAuthorizationHeader.containsString(MCAAuthorizationManager.BEARER){
                return true
            }
        }
        
        return false
    }
    
    
    public func isOAuthError(response: Response?) -> Bool {
        return false
    }
    
    public func clearAuthorizationData() {
        SecurityUtils.removeItemFromKeyChain(accessTokenLabel)
        SecurityUtils.removeItemFromKeyChain(idTokenLabel)
    }
    
    public func addCachedAuthorizationHeader(request: NSMutableURLRequest) {
        
    }
    
    public func getCachedAuthorizationHeader() -> String? {
        var returnedValue:String? = nil
       
        dispatch_barrier_sync(lockQueue){
            if let accessToken = SecurityUtils.getItemFromKeyChain(accessTokenLabel), idToken = SecurityUtils.getItemFromKeyChain(idTokenLabel) {
                print(self.getUserIdentity())
                print(self.getDeviceIdentity())
                print(self.getAppIdentity())
                returnedValue = "\(MCAAuthorizationManager.BEARER) \(accessToken) \(idToken)"
            }
        }
        return returnedValue
    }
    
    public func obtainAuthorization(completionHandler: MfpCompletionHandler?) {
        dispatch_barrier_async(lockQueue){
            self.processManager.startAuthorizationProcess(completionHandler)
        }
    }
    
    public func getUserIdentity() -> AnyObject? {
        return processManager.userIdentity
    }
    
    public func getDeviceIdentity() -> AnyObject? {
        return processManager.deviceIdentity
    }
    
    public func getAppIdentity() -> AnyObject? {
        return processManager.appIdentity
    }
    
    /**
     Registers a delegate that will handle authentication for the specified realm.
     
     - parameter delegate: The delegate that will handle authentication challenges
     - parameter forRealm: The realm name
     */
    public func registerAuthenticationDelegate(delegate: AuthenticationDelegate, realm: String) throws {
        guard realm.isEmpty == false else {
            throw AutorizationError.CANNOT_ADD_CHALLANGE_HANDLER("The realm name can't be empty.")
        }
        
        var handler = ChallengeHandler(realm: realm, authenticationDelegate: delegate)
        challengeHandlers[realm] = handler
    }
    
    /**
     Unregisters the authentication delegate for the specified realm.
     
     - parameter realm: The realm name
     */
    public func unregisterAuthenticationDelegate(realm: String) {
        guard realm.isEmpty == false else {
            return
        }
        
        challengeHandlers.removeValueForKey(realm)
    }
    
    /**
     <#Description#>
     
     - returns: <#return value description#>
     */
    public func getAuthorizationPersistencePolicy() -> PersistencePolicy {
        return PersistencePolicy.NEVER
    }
    
    /**
     Description
     
     - parameter policy: <#policy description#>
     */
    public func setAuthorizationPersistensePolicy(policy: PersistencePolicy) {
        
    }
    
    /**
     <#Description#>
     
     - parameter realm: <#realm description#>
     
     - returns: <#return value description#>
     */
    public func getChallengeHandler(realm:String) -> ChallengeHandler?{
        return challengeHandlers[realm]
    }
    
    
}
