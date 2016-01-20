//
//  AuthenticationContexts.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 20/01/2016.
//  Copyright © 2016 IBM. All rights reserved.
//

import Foundation

//TODO: ilan change name?
public protocol AuthenticationContext {

    /**
    * Submits authentication challenge response
    @param answer Dictionary with challenge responses
    */
    func /*synchronized*/ submitAuthenticationChallengeAnswer(answer:[String:AnyObject]?)

    /**
    * Informs client about successful authentication
    */
    func submitAuthenticationSuccess ()

    /**
    * Informs client about failed authentication
    @param userInfo Dictionary with extended information about failure
    */
    func /*synchronized */ submitAuthenticationFailure (info:[String:AnyObject]?)
}