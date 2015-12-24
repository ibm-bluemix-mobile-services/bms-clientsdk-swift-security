//
//  AuthenticationContext.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 24/12/2015.
//  Copyright © 2015 IBM. All rights reserved.
//

import Foundation

protocol AuthenticationContextProtocol {
    /**
    * Submits authentication challenge response.
    * @param answer JSON with challenge response.
    */
//    func submitAuthenticationChallengeAnswer(JSONObject answer)
    func submitAuthenticationChallengeAnswer(answer : AnyObject?)
    
    /**
    * Informs about authentication success.
    */
    func submitAuthenticationSuccess ()
    
    /**
    * Informs about authentication failure. This function must be called from a custom challenge
    * handler when the authorization request should be canceled for any reason (for example,
    * when user clicks 'cancel' on login dialog). The original {@link BaseRequest}
    * will be failed.
    * @param info Extended information about the failure. It will be passed to {@link com.ibm.mobilefirstplatform.clientsdk.android.core.api.ResponseListener#onFailure(Response, Throwable, JSONObject)} of
    *             the resource request as 'extendedInfo' object.
    */
    func submitAuthenticationFailure (info : AnyObject?)
}