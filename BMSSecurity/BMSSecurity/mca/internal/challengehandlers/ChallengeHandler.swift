//
//  ChallengeHandler.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 1/20/16.
//  Copyright © 2016 IBM. All rights reserved.
//
import BMSCore
public class ChallengeHandler : AuthenticationContext{
    
    private var realm:String
    private /*volatile*/ var authenticationDelegate:AuthenticationDelegate?
    private /*volatile*/ var waitingRequests:[AuthorizationRequestManager]
    private /*volatile*/ var activeRequest:AuthorizationRequestManager?
    
    public init(realm:String , authenticationDelegate:AuthenticationDelegate) {
        self.realm = realm
        self.authenticationDelegate = authenticationDelegate
        self.activeRequest = nil
        self.waitingRequests = [AuthorizationRequestManager]()
    }
    
    public func /*synchronized*/ submitAuthenticationChallengeAnswer(answer:[String:AnyObject]?) {
        guard let aRequest = activeRequest else {
            return
        }
        
        if answer != nil {
           aRequest.submitAnswer(answer, realm: realm)
        } else {
            aRequest.removeExpectedAnswer(realm)
        }
        activeRequest = nil
    }
    
   
    public /* synchronized*/ func submitAuthenticationSuccess () {
        if activeRequest != nil {
            activeRequest!.removeExpectedAnswer(realm)
            activeRequest = nil
        }
        
        releaseWaitingList()
    }
    
    
    public func /*synchronized */ submitAuthenticationFailure (info:[String:AnyObject]?) {
        if activeRequest != nil {
         //   activeRequest.requestFailed(info)
            activeRequest = nil
        }
        releaseWaitingList();
    }
    
    public func /*synchronized*/ handleChallenge(request:AuthorizationRequestManager , challenge:[String:AnyObject]?) {
         if activeRequest == nil {
            activeRequest = request
             if let unWrappedListener = self.authenticationDelegate{
                unWrappedListener.onAuthenticationChallengeReceived(self, challenge: challenge)
            }
        } else {
            waitingRequests.append(request)
        }
    }
    
    public /*synchronized*/ func handleSuccess(success:[String:AnyObject]?) {
        if let unWrappedListener = self.authenticationDelegate{
            unWrappedListener.onAuthenticationSuccess(success);
        }
        releaseWaitingList();
        activeRequest = nil
    }
    
    public /*synchronized*/ func handleFailure(failure:[String:AnyObject]?) {
        if let unWrappedListener = self.authenticationDelegate{
            unWrappedListener.onAuthenticationFailure(failure);
        }
        clearWaitingList();
        activeRequest = nil
    }
    
    private /*synchronized*/ func setActiveRequest(request:AuthorizationRequestManager) {
        activeRequest = request;
    }
    
    private func /*synchronized*/ releaseWaitingList() {
        for request in waitingRequests {
            request.removeExpectedAnswer(realm);
        }
        
        clearWaitingList();
    }
    
    private /*synchronized*/ func clearWaitingList() {
        waitingRequests.removeAll()
    }
}
