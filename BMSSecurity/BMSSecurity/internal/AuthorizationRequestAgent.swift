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
    
    var answers = [String : String]()
    
    init() {
        
    }
    
    public func initialize(listener:ResponseListener) { }
    
    public func sendRequest(path:String , options:RequestOptions ) throws {}
}