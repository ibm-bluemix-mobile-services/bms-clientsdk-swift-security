//
//  AuthorizationRequestAgent.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 29/12/2015.
//  Copyright © 2015 IBM. All rights reserved.
//

import Foundation
import BMSCore

public class AuthorizationRequestAgent {
       
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
    
    var answers = [String : String]?()
    
    init() {
        
    }
    
    public func send(path:String , options:RequestOptions, withListener: ResponseListener?) {
        
        var rootUrl : String = ""
        
        if path.hasPrefix(BMSClient.HTTP_SCHEME) && path.characters.indexOf(":") != nil {
            let url = NSURL(string: path)
            if let path = url?.path {
                rootUrl = (path as NSString).stringByReplacingOccurrencesOfString(path, withString: "")
            }
            else {
               rootUrl = ""
            }
        }
        else {
            //path is relative
            var backendRoute = BMSClient.sharedInstance.bluemixAppRoute!
            if backendRoute.hasSuffix("/") == false {
                backendRoute += "/"
            }
            
            rootUrl += backendRoute + AuthorizationRequestAgent.AUTH_SERVER_NAME
            
            let pathWithTenantId = AuthorizationRequestAgent.AUTH_PATH + BMSClient.sharedInstance.bluemixAppGUID!
            rootUrl += "/" + pathWithTenantId
            
            print(rootUrl)
            
        }
        
        if let region = BMSClient.sharedInstance.bluemixRegionSuffix {
                rootUrl = BMSClient.defaultProtocol
                    + "://" + AuthorizationRequestAgent.AUTH_SERVER_NAME + "." + region + "/" + AuthorizationRequestAgent.AUTH_SERVER_NAME + "/" + AuthorizationRequestAgent.AUTH_PATH + BMSClient.sharedInstance.bluemixAppGUID!
        }
        
        sendInternal(rootUrl, path: path, options: options)
    }
    
    
    internal func sendInternal(rootUrl:String, path:String, options:RequestOptions?) {
        if let unWrappedOptions = options {
            self.requestOptions = unWrappedOptions
        }
        else {
            self.requestOptions = RequestOptions()
        }
        
        requestPath = Utils.concatenateUrls(rootUrl, path: path)
        
        var request = AuthorizationRequest(url:rootUrl, method:self.requestOptions!.requestMethod)
        
        if requestOptions!.timeout != 0 {
            request.timeout = requestOptions!.timeout
        } else {
            request.timeout = BMSClient.sharedInstance.defaultRequestTimeout
        }
        
        if let unwrappedHeaders = options?.headers {
            request.addHeaders(unwrappedHeaders)
        }
        
        if let unwrappedAnswers = answers {
//            let authorizationHeaderValue = "Bearer \(answerr)"
//            String authorizationHeaderValue = String.format("Bearer %s", answer.replace("\n", ""));
//            request.addHeaders(["authorization" : authorizationHeaderValue])
//            logger.debug("Added authorization header to request: " + authorizationHeaderValue);
        }
        
    }

}