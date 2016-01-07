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
   
    static let BEARER = "Bearer"
    static let AUTHORIZATION_HEADER = "Authorization"
    static let WWW_AUTHENTICATE_HEADER = "WWW-Authenticate"
//    var uuidchain : IMFKeychainItemWrapper?

    public static let sharedInstance = BMSAuthorizationManager()
    
    var processManager : AuthorizationProcessManager
    var preferences : AuthorizationManagerPreferences
    
    internal init() {
        preferences = AuthorizationManagerPreferences()
        processManager = AuthorizationProcessManager(preferences: preferences)
        BMSClient.sharedInstance.sharedAuthorizationManager = self;
        
        
        if preferences.deviceIdentity == nil {
//            preferences.deviceIdentity
        }
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
    
    func getDeviceData() -> String{
        var x = String()
//        SecurityUtils.
//        SecurityUtils.saveStringParameterToKeyChain(String, label: <#T##String#>)
//        var wrapper : IMFKeychainItemWrapper = UUIDKeychainItem()
//        let tmp = wrapper.objectForKey(kSecValueData){
//                
//        }
//        let tmp = wrapper.objectForKey(kSecValueData){
//            if (!tmp.isEmpty) {
//                return tmp
//            }
        
        return x
    }
    
    

    
//    -(NSString *)getWLUniqueDeviceId {
//    NSString *tmpString;
//    
//    // try to read UUID from keychain
//    IMFKeychainItemWrapper *wrapper = [self UUIDKeychainItem];
//    tmpString = [wrapper objectForKey:(__bridge id)(kSecValueData)];
//    if ((tmpString != nil) && ([tmpString length] > 0)) {
//    IMFLogTraceWithName(IMF_AUTH_PACKAGE, @"returning UUID from the keychain");
//    return tmpString;
//    }
//    
//    // If none exist, create UUID
//    IMFLogTraceWithName(IMF_AUTH_PACKAGE, @"creating UUID and save it to the keychain");
//    tmpString = [self createUUID];
//    
//    // Save to keychain
//    [wrapper setObject:@"IMFCoreBlueMix" forKey:(__bridge id)(kSecAttrService)];
//    [wrapper setObject:tmpString forKey:(__bridge id)(kSecValueData)];
//    
//    return tmpString;
//    }

    
//    - (NSMutableDictionary *) deviceDictionary {
//    NSMutableDictionary *device = [[NSMutableDictionary alloc] init];
//    [device setValue:[[WLDeviceAuthManager sharedInstance] getWLUniqueDeviceId] forKey:JSON_DEVICE_ID_KEY];
//    [device setValue:[UIDevice currentDevice].systemVersion forKey:JSON_OS_KEY];
//    [device setValue:[UIDevice currentDevice].model forKey:JSON_MODEL_KEY];
//    [device setValue:[WLConfig getApplicationName] forKey:JSON_APPLICATION_ID_KEY];
//    [device setValue:[WLConfig getApplicationVersion] forKey:JSON_APPLICATION_VERSION_KEY];
//    [device setValue:JSON_IOS_ENVIRONMENT_VALUE forKey:JSON_ENVIRONMENT_KEY];
//    return device;
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
                    return true;
                }
            }
        
        return false;
    }
    
    
    public func isOAuthError(response: Response?) -> Bool {
        return false;
    }
    
    public func clearAuthorizationData() {
        
    }
    
    public func addCachedAuthorizationHeader(request: NSMutableURLRequest) {
        
    }
    
    public func getCachedAuthorizationHeader() -> String? {
        return nil;
    }
    
    public func obtainAuthorizationHeader(completionHandler: MfpCompletionHandler?) {
        
        processManager.startAuthorizationProcess(completionHandler)
//        completionHandler(nil, nil)
    }
    
    public func getUserIdentity() -> AnyObject? {
        return nil;
    }
    
    public func getDeviceIdentity() -> AnyObject? {
        return nil;
    }
    
    public func getAppIdentity() -> AnyObject? {
        return nil;
    }
    
    public func getAuthorizationPersistencePolicy() -> PersistencePolicy {
        return PersistencePolicy.NEVER
    }
    
    public func setAuthorizationPersistensePolicy(policy: PersistencePolicy) {
        
    }
}