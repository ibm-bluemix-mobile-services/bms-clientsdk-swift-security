//
//  ChallengeHandlerTest.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 2/29/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import XCTest
import BMSCore
@testable import BMSSecurity

class ChallengeHandlerTest: XCTestCase {
    
    var delegate = MyAuthDelegate()
    var handler = ChallengeHandler(realm: ChallengeHandlerTest.realm,authenticationDelegate: MyAuthDelegate())
    let defaultCompletionHandler = {(response: Response?, error: NSError?) in }
    static let realm = "testrealm"
    override func setUp() {
        super.setUp()
        handler = ChallengeHandler(realm: ChallengeHandlerTest.realm,authenticationDelegate: MyAuthDelegate())
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        MyAuthDelegate.success = false
        MyAuthDelegate.failure = false
        MyAuthDelegate.received = false
        handler.authenticationDelegate = delegate
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func testHandleChallenge(){
        
        //with active request
        self.handler.waitingRequests = [MockAuthorizationRequestManager]()
        MyAuthDelegate.received = false
        self.handler.activeRequest =  MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: NSError?) in }), challenge: ["realm1" : "q1"])
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertEqual(self.handler.waitingRequests.count, 1)
            XCTAssertNotNil(self.handler.activeRequest)
        }
        
        //no active request and with auth delegate
        self.handler.waitingRequests = [MockAuthorizationRequestManager]()
        self.handler.activeRequest = nil
        MyAuthDelegate.received = true
        self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: NSError?) in }), challenge: MyAuthDelegate.challenge)
        dispatch_barrier_sync(self.handler.lockQueue){
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertNotNil(self.handler.activeRequest)
        }
        
        //with no active request and no auth delegate
        self.handler.waitingRequests = [MockAuthorizationRequestManager]()
        self.handler.authenticationDelegate = nil
        self.handler.activeRequest = nil
        MyAuthDelegate.received = false
        self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), challenge: ["realm1" : "q1"])
        dispatch_barrier_sync(self.handler.lockQueue){
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertNotNil(self.handler.activeRequest)
        }
    }
    
    func testHandleSuccess(){
        
        //with auth delegate
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        MyAuthDelegate.success = true
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        handler.handleSuccess(MyAuthDelegate.sucDictionary)
        dispatch_barrier_sync(handler.lockQueue){
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
        }
        
        //no auth delegate
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        self.handler.authenticationDelegate = nil
        MyAuthDelegate.success = false
        self.handler.handleSuccess(MyAuthDelegate.sucDictionary)
        dispatch_barrier_sync(handler.lockQueue){
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 0)
        }
    }
    
    func testHandleFailure(){
        
        //with auth delegate
        handler.waitingRequests = [MockAuthorizationRequestManager]()
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        MyAuthDelegate.failure = true
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        handler.handleFailure(MyAuthDelegate.failDictionary)
        dispatch_barrier_sync(handler.lockQueue){
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 0)
        }
        
        //no auth delegate
        MyAuthDelegate.failure = false
        self.handler.authenticationDelegate = nil
        self.handler.handleFailure(MyAuthDelegate.sucDictionary)
        
    }
    
    func testSubmitAuthenticationFailure(){
        
        //with active request
        handler.waitingRequests = [MockAuthorizationRequestManager]()
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        handler.submitAuthenticationFailure(MockAuthorizationRequestManager.failedInfo)
        dispatch_barrier_sync(handler.lockQueue){
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
        }
        
        //no active request
        self.handler.activeRequest = nil
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        self.handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        handler.submitAuthenticationFailure(MockAuthorizationRequestManager.failedInfo)
        dispatch_barrier_sync(handler.lockQueue){
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
            XCTAssertNil(self.handler.activeRequest)
        }
    }
    
    func testSubmitAuthenticationSuccess() {
        
        //with active request
        handler.waitingRequests = [MockAuthorizationRequestManager]()
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        handler.submitAuthenticationSuccess()
        dispatch_barrier_sync(handler.lockQueue){
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 3)
        }
        
        //no active request
        self.handler.activeRequest = nil
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        self.handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        handler.submitAuthenticationSuccess()
        dispatch_barrier_sync(handler.lockQueue){
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
            XCTAssertNil(self.handler.activeRequest)
        }
    }
    
    func testSubmitAuthenticationChallengeAnswer(){
        
        //with active request and an answer
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.submitAuthenticationChallengeAnswer(MockAuthorizationRequestManager.answer)
        MockAuthorizationRequestManager.submitAnswerCount = 0
        dispatch_barrier_sync(handler.lockQueue){
            XCTAssertEqual(MockAuthorizationRequestManager.submitAnswerCount,1)
            XCTAssertNil(self.handler.activeRequest)
        }
        
        //with active request and nil answer
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.submitAuthenticationChallengeAnswer(nil)
        dispatch_barrier_sync(handler.lockQueue){
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount,1)
            XCTAssertNil(self.handler.activeRequest)
        }
        
        //no active request
        handler.activeRequest = nil
        handler.submitAuthenticationChallengeAnswer(nil)
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        MockAuthorizationRequestManager.submitAnswerCount = 0
        dispatch_barrier_sync(handler.lockQueue){
            XCTAssertEqual(MockAuthorizationRequestManager.submitAnswerCount,0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount,0)
        }
    }
    
    
    
    
}
class MockAuthorizationRequestManager : AuthorizationRequestManager {
    static var removeExpectedAnswerCount = 0
    static var submitAnswerCount = 0
    static var requestFailedCount = 0
    static var answer = ["a1" : "1"]
    static var failedInfo = ["a2" : "2"]
    override func removeExpectedAnswer(realm: String) {
        XCTAssertEqual(realm, ChallengeHandlerTest.realm)
        MockAuthorizationRequestManager.removeExpectedAnswerCount++
    }
    override func submitAnswer(answer: [String : AnyObject]?, realm: String) {
        MockAuthorizationRequestManager.submitAnswerCount++
        XCTAssertEqual(answer, MockAuthorizationRequestManager.answer as NSDictionary)
        XCTAssertEqual(realm, ChallengeHandlerTest.realm)
    }
    override func requestFailed(info: [String : AnyObject]?) {
        XCTAssertEqual(info, MockAuthorizationRequestManager.failedInfo as NSDictionary)
        MockAuthorizationRequestManager.requestFailedCount++
    }
    
}

class MyAuthDelegate : AuthenticationDelegate {
    static var received = false
    static var success = false
    static var failure = false
    static let sucDictionary = ["a" : 1 , "b" : "2"]
    static let failDictionary = ["c" : 1 , "d" : "2"]
    static let challenge = ["realm1" : "q1"]
    func onAuthenticationChallengeReceived(authContext: AuthenticationContext, challenge: AnyObject){
        XCTAssertTrue(MyAuthDelegate.received)
    }
    func onAuthenticationSuccess(info: AnyObject?) {
        XCTAssertTrue(MyAuthDelegate.success)
        XCTAssertEqual(MyAuthDelegate.sucDictionary, info as? NSDictionary)
    }
    func onAuthenticationFailure(info: AnyObject?){
        XCTAssertTrue(MyAuthDelegate.failure)
        XCTAssertEqual(MyAuthDelegate.failDictionary, info as? NSDictionary)
        
    }
}



