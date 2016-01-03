//
//  AuthenticationListener.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 24/12/2015.
//  Copyright © 2015 IBM. All rights reserved.
//

import Foundation
import BMSCore

protocol AuthenticationDelegate{
    /**
    * Called when authentication challenge was received. The implementor should handle the challenge and call
    * {@link com.ibm.mobilefirstplatform.clientsdk.android.security.api.AuthenticationContext#submitAuthenticationChallengeAnswer(JSONObject)}
    * with authentication challenge answer.
    * @param authContext Authentication context the answer should be sent to
    * @param challenge Information about authentication challenge.
    * @param context A {@link Context} object that was passed to
    * {@link Request#send(Context, ResponseListener)}, which triggered the
    * authentication challenge.
    */
    func onAuthenticationChallengeReceived(authContext : AuthorizationManager, challenge : AnyObject?)
    
    /**
    * Called when authentication succeeded.
    * @param context A {@link Context} object that was passed to
    * {@link Request#send(Context, ResponseListener)}, which triggered the
    * authentication challenge.
    * @param info Extended data describing the authentication success.
    */
//    func onAuthenticationSuccess(JSONObject info)
    func onAuthenticationSuccess(info : AnyObject?)
    
    /**
    * Called when authentication fails.
    * @param context A {@link Context} object that was passed to
    * {@link Request#send(Context, ResponseListener)}, which triggered the
    * authentication challenge.
    * @param info Extended data describing authentication failure.
    */
//    func onAuthenticationFailure(JSONObject info)
    func onAuthenticationFailure(info : AnyObject?)

}