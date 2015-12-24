//
//  BMSAuthorizationManager.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 23/12/2015.
//  Copyright © 2015 IBM. All rights reserved.
//

import Foundation
import BMSCore

public class BMSAuthorizationManager : AuthorizationManagerProtocol {
   
    static let BEARER = "Bearer"
    static let AUTHORIZATION_HEADER = "Authorization"
    static let WWW_AUTHENTICATE_HEADER = "WWW-Authenticate"

    public static let sharedInstance = BMSAuthorizationManager()
    
    internal init() {
//        super.init()
//        BMSClient.sharedInstance.sharedAuthorizationManager = self;
    }
    
//    public func register(){
//        BMSClient.sharedInstance.sharedAuthorizationManager = self
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
}