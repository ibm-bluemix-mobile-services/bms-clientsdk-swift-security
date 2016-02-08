/*
*     Copyright 2015 IBM Corp.
*     Licensed under the Apache License, Version 2.0 (the "License");
*     you may not use this file except in compliance with the License.
*     You may obtain a copy of the License at
*     http://www.apache.org/licenses/LICENSE-2.0
*     Unless required by applicable law or agreed to in writing, software
*     distributed under the License is distributed on an "AS IS" BASIS,
*     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*     See the License for the specific language governing permissions and
*     limitations under the License.
*/

import Foundation
import BMSCore

//AuthorizationRequest is used internally to send authorization requests.
public class AuthorizationRequest : MFPRequest {
    
    static var networkSessionInternal: NSURLSession!
    
    public override func getNetworkSession() -> NSURLSession {
        return AuthorizationRequest.networkSessionInternal
    }
    
    public func send(completionHandler: MfpCompletionHandler?) {
         super.sendWithCompletionHandler(completionHandler)
    }
    
    public init(url:String, method:HttpMethod) {
        super.init(url: url, headers: nil, queryParameters: nil, method: method, timeout: 0)
        allowRedirects = false
        
        let configuration = NSURLSessionConfiguration.defaultSessionConfiguration()
        configuration.timeoutIntervalForRequest = timeout
        AuthorizationRequest.networkSessionInternal = NSURLSession(configuration: configuration, delegate: self, delegateQueue: nil)
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
        var body = ""
        var i = 0
        //creating body params
        for (key, val) in formParamaters {
            body += "\(key)=\(val)"
            if i < formParamaters.count - 1 {
                body += "&"
            }
            i++
        }
        super.sendString(body, withCompletionHandler: callback)
    }
    
}