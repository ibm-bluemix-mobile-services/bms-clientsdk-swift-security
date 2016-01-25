//
//  MCAAuthorizationManager.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 23/12/2015.
//  Copyright © 2015 IBM. All rights reserved.
//

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
    public static let OAUTH_CERT_LABEL = "com.worklight.oauth.certificate"
    public static let _PUBLIC_KEY_LABEL = "com.worklight.oauth.publickey"
    public static let CLIENT_ID_KEY_LABEL = "com.worklight.oauth.clientid"
    public  static let _PRIVATE_KEY_LABEL = "com.worklight.oauth.privatekey"
    public static let OAUTH_ACCESS_TOKEN_LABEL = "com.worklight.oauth.accesstoken"
    public static let OAUTH_ID_TOKEN_LABEL = "com.worklight.oauth.idtoken"
    
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
    var preferences : AuthorizationManagerPreferences
    
    internal init() {
        preferences = AuthorizationManagerPreferences()
        processManager = AuthorizationProcessManager(preferences: preferences)
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
        
    }
    
    public func addCachedAuthorizationHeader(request: NSMutableURLRequest) {
        
    }
    
    public func getCachedAuthorizationHeader() -> String? {
        return nil
    }
    
    public func obtainAuthorization(completionHandler: MfpCompletionHandler?) {
        processManager.startAuthorizationProcess(completionHandler)
    }
    
    public func getUserIdentity() -> AnyObject? {
        return nil
    }
    
    public func getDeviceIdentity() -> AnyObject? {
        return nil
    }
    
    public func getAppIdentity() -> AnyObject? {
        return nil
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
