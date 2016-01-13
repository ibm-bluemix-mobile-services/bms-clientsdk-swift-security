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
    
    public func send(completionHandler: MfpCompletionHandler?) {
        
//        if let tempCompletionHandler = completionHandler {
//            if error == nil {
//                let
//            }
//        }
////        let callback: MfpCompletionHandler = { (response: Response?, error: NSError?) in
////            if error == nil {
////                if let response = response {
////                    if response.isSuccessful {
////                        listener.onSuccess(response);
////                    } else {
//////                        listener.
////                    }
////                }
////            }
////            else {
////                //call on failure
////                
////            }
////        }
      
        super.sendWithCompletionHandler(completionHandler)
    }
    
    public init(url:String, method:HttpMethod) {
        super.init(url: url, headers: nil, queryParameters: nil, method: method, timeout: 0);
        allowRedirects = false
        
        let configuration = NSURLSessionConfiguration.defaultSessionConfiguration()
        configuration.timeoutIntervalForRequest = timeout
        AuthorizationRequest.networkSessionInternal = NSURLSession(configuration: configuration)
    }

    /**
     * Send this resource request asynchronously, with the given form parameters as the request body.
     * This method will set the content type header to "application/x-www-form-urlencoded".
     *
     * @param formParameters The parameters to put in the request body
     * @param listener       The listener whose onSuccess or onFailure methods will be called when this request finishes.
     */
    public func sendWithCompletionHandler(formParamaters : [String : String], callback: MfpCompletionHandler?) {
        headers[MFPRequest.CONTENT_TYPE] = "application/x-www-form-urlencoded"
        super.sendString(String(formParamaters), withCompletionHandler: callback);
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