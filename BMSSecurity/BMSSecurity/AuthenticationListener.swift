//
//  AuthenticationListener.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 1/20/16.
//  Copyright © 2016 IBM. All rights reserved.
//

public protocol AuthenticationListener {
    func onAuthenticationChallengeReceived(challengeHandler: ChallengeHandler , challenge:[String:AnyObject]?)
    func onAuthenticationSuccess(info:[String:AnyObject]?)
    func onAuthenticationFailure(info:[String:AnyObject]?)
}