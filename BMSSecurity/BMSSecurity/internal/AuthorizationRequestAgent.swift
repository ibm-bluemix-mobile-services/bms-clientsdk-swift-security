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
    
    var answers = [String : AnyObject]?()
    
    init() {
        
    }
    
    public func send(path:String , options:RequestOptions, completionHandler: MfpCompletionHandler?) {
        
        var rootUrl : String = ""
        
        if path.hasPrefix(BMSClient.HTTP_SCHEME) && path.characters.indexOf(":") != nil {
            let url = NSURL(string: path)
            if let path = url?.path {
                rootUrl = (path as NSString).stringByReplacingOccurrencesOfString(path, withString: "")
            }
            else {
               rootUrl = ""
            }
            
            if let region = BMSClient.sharedInstance.bluemixRegionSuffix {
                rootUrl = BMSClient.defaultProtocol
                    + "://" + AuthorizationRequestAgent.AUTH_SERVER_NAME + "." + region + "/" + AuthorizationRequestAgent.AUTH_SERVER_NAME + "/" + AuthorizationRequestAgent.AUTH_PATH + BMSClient.sharedInstance.bluemixAppGUID!
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
        do {
            try sendInternal(rootUrl, path: path, options: options)
        }
        catch {
            print("something wrong")
        }
        
    }
    
    internal func sendInternal(rootUrl:String, path:String, options:RequestOptions?) throws {
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
                let ans = Utils.JSONStringify(unwrappedAnswers)
                let authorizationHeaderValue = "Bearer \(ans)"
                request.addHeader("Authorization", val: authorizationHeaderValue)
        }
        
        let callback: MfpCompletionHandler = { (response: Response?, error: NSError?) in
            let isRedirect:Bool = 300..<399 ~= (response?.statusCode)!
            
            if error != nil || !isRedirect {
                self.processRepponse(response)
            }
            else {
                do {
                    try self.processRedirectResponse(response!, callback: nil)
                } catch {
                    print("something wrong 2")
                }

            }
            
        }
        
        if let method = options?.requestMethod where method == HttpMethod.GET{
            request.queryParameters = options?.parameters
            request.send(callback)
        } else {
//            request.sendWithCompletionHandler(options?.parameters)
        }
    }
    
    enum ResponseError: ErrorType {
        case NoLocation
    }
    
    internal func processRepponse(response: Response?) {
        // at this point a server response should contain a secure JSON with challenges
        
    }
    
//    /**
//    * Process a response from the server.
//    *
//    * @param response Server response.
//    */
//    private void processResponse(Response response) {
//    // at this point a server response should contain a secure JSON with challenges
//    JSONObject jsonResponse = Utils.extractSecureJson(response);
//    JSONObject jsonChallenges = (jsonResponse == null) ? null : jsonResponse.optJSONObject(CHALLENGES_VALUE_NAME);
//    
//    if (jsonChallenges != null) {
//    startHandleChallenges(jsonChallenges, response);
//    } else {
//    listener.onSuccess(response);
//    }
//    }
    
    internal func processRedirectResponse(response:Response, callback:MfpCompletionHandler?) throws {
        
        func getLocationString(obj:AnyObject?) throws -> String? {
            guard obj != nil else {
                throw ResponseError.NoLocation
            }
            
            if case let myObj as String = obj![0] {
                return myObj
            }
            else if case let str as String = obj{
                return str
            }
            
            throw ResponseError.NoLocation
        }
        
        let location = try getLocationString(response.headers?[AuthorizationRequestAgent.LOCATION_HEADER_NAME])
        
        let url:NSURL = NSURL(string: location!)!
        let query = url.query
        let results = Utils.getParameterValueFromQuery(query, paramName: AuthorizationRequestAgent.WL_RESULT)
        
        //TODO:Ilan hadle succuss,and fail here
        //    // process failures if any
        //    JSONObject jsonFailures = jsonResult.optJSONObject(AUTH_FAILURE_VALUE_NAME);
        //
        //    if (jsonFailures != null) {
        //    processFailures(jsonFailures);
        //    listener.onFailure(response, null, null);
        //    return;
        //    }
        //
        //    // process successes if any
        //    JSONObject jsonSuccesses = jsonResult.optJSONObject(AUTH_SUCCESS_VALUE_NAME);
        //
        //    if (jsonSuccesses != null) {
        //    processSuccesses(jsonSuccesses);
        //    }
        //    }
        
        
        callback?(response, nil)
    }
}
