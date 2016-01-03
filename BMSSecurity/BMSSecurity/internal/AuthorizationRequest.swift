//
//  AuthorizationRequest.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 29/12/2015.
//  Copyright © 2015 IBM. All rights reserved.
//

import Foundation
import BMSCore

//AuthorizationRequest is used internally to send authorization requests.
public class AuthorizationRequest : MFPRequest {
    
    static var networkSessionInternal: NSURLSession!
    
    //Do not allow redirects
//    public override var allowRedirects : Bool{
//        get{
//            return false
//        }
//    }
    
    
    public override func getNetworkSession() -> NSURLSession {
        return AuthorizationRequest.networkSessionInternal
    }
    
    public func send(listener: ResponseListener) {
        
        let callback: MfpCompletionHandler = { (response: Response?, error: NSError?) in
            if error != nil {
                if let response = response {
                    if response.isSuccessful {
                        listener.onSuccess(response);
                    } else {
//                        listener.
                    }
                }
            }
            else {
                //call on failure
                
            }
        }
      
        super.sendWithCompletionHandler(callback)
    }
    
    public init(url:String, method:HttpMethod) {
        super.init(url: url, headers: nil, queryParameters: nil, method: method, timeout: 0);
        allowRedirects = false
    }

    public func sendWithCompletionHandler(formParamaters : [String : String], callback: MfpCompletionHandler?) {
        for (key, val) in formParamaters.enumerate() {
            
        }
        
        
//
//        let authManager: AuthorizationManager = BMSClient.sharedInstance.sharedAuthorizationManager
//        
//        if let authHeader: String = authManager.getCachedAuthorizationHeader() {
//            self.headers["Authorization"] = authHeader
//        }
//        
//        func processResponse(response: Response?, error: NSError?) {
//            if (authManager.isOAuthError(response)) {
//                authManager.obtainAuthorizationHeader({
//                    (response: Response?, error: NSError?) in (response != nil) ? self.sendWithCompletionHandler(callback) : callback?(response, error)
//                });
//            } else {
//                callback?(response, error)
//            }
//        }
//        
//        super.sendWithCompletionHandler(processResponse)
    }
    
}