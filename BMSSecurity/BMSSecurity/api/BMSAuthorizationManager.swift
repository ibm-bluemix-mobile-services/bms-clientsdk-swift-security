//
//  BMSAuthorizationManager.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 23/12/2015.
//  Copyright © 2015 IBM. All rights reserved.
//

import Foundation
import BMSCore

public class BMSAuthorizationManager : AuthorizationManager {
   
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
    
//    var uuidchain : IMFKeychainItemWrapper?

    public static let sharedInstance = BMSAuthorizationManager()
    
    var processManager : AuthorizationProcessManager
    var preferences : AuthorizationManagerPreferences
    
    internal init() {
        preferences = AuthorizationManagerPreferences()
        processManager = AuthorizationProcessManager(preferences: preferences)
        BMSClient.sharedInstance.sharedAuthorizationManager = self
        
        
//        if preferences.deviceIdentity == nil {
//            preferences.deviceIdentity?.set(<#T##json: [String : AnyObject]##[String : AnyObject]#>)
//        }
    }
    
    
//    func UUIDKeychainItem() -> IMFKeychainItemWrapper{
//        if (uuidchain != nil) {
//            return uuidchain!
//        }
//        else {
//            uuidchain = IMFKeychainItemWrapper(identifier: "WLUUID", accessGroup: nil)
//            return uuidchain!
//        }
//    }
//    
//    func getDeviceData() -> String{
//        let x = String()
//        
//        
//        return x
//    }

    
//    -(NSString *)getWLUniqueDeviceId {
//    NSString *tmpString
//    
//    // try to read UUID from keychain
//    IMFKeychainItemWrapper *wrapper = [self UUIDKeychainItem]
//    tmpString = [wrapper objectForKey:(__bridge id)(kSecValueData)]
//    if ((tmpString != nil) && ([tmpString length] > 0)) {
//    IMFLogTraceWithName(IMF_AUTH_PACKAGE, "returning UUID from the keychain")
//    return tmpString
//    }
//    
//    // If none exist, create UUID
//    IMFLogTraceWithName(IMF_AUTH_PACKAGE, "creating UUID and save it to the keychain")
//    tmpString = [self createUUID]
//    
//    // Save to keychain
//    [wrapper setObject:"IMFCoreBlueMix" forKey:(__bridge id)(kSecAttrService)]
//    [wrapper setObject:tmpString forKey:(__bridge id)(kSecValueData)]
//    
//    return tmpString
//    }
    
    public func isAuthorizationRequired(httpResponse: NSHTTPURLResponse) -> Bool {
        if let header = httpResponse.allHeaderFields[BMSAuthorizationManager.WWW_AUTHENTICATE_HEADER] {
            if let authHeader : String = header as? String {
                return isAuthorizationRequired(httpResponse.statusCode, responseAuthorizationHeader: authHeader)
            }
        }
        
        return false
    }
    
    public func isAuthorizationRequired(statusCode: Int, responseAuthorizationHeader: String) -> Bool {
       
            if statusCode == 401 || statusCode == 403 {
                if responseAuthorizationHeader.containsString(BMSAuthorizationManager.BEARER){
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
    
    public func obtainAuthorizationHeader(completionHandler: MfpCompletionHandler?) {
        
        processManager.startAuthorizationProcess(completionHandler)
//        completionHandler(nil, nil)
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
    
    public func getAuthorizationPersistencePolicy() -> PersistencePolicy {
        return PersistencePolicy.NEVER
    }
    
    public func setAuthorizationPersistensePolicy(policy: PersistencePolicy) {
        
    }
}