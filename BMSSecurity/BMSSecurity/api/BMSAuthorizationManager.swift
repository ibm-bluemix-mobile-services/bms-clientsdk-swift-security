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

    public static let sharedInstance = BMSAuthorizationManager()
    
    var processManager : AuthorizationProcessManager
    var preferences : AuthorizationManagerPreferences
    
    internal init() {
        preferences = AuthorizationManagerPreferences()
        processManager = AuthorizationProcessManager(preferences: preferences)
        BMSClient.sharedInstance.sharedAuthorizationManager = self;        
    }
    
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