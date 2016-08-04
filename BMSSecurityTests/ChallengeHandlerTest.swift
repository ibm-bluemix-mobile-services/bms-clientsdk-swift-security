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
        
#if swift(>=3.0)
        (self.handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(self.handler.waitingRequests.count, 1)
            XCTAssertNotNil(self.handler.activeRequest)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertEqual(self.handler.waitingRequests.count, 1)
            XCTAssertNotNil(self.handler.activeRequest)
        }
#endif
        
        //no active request and with auth delegate
        self.handler.waitingRequests = [MockAuthorizationRequestManager]()
        self.handler.activeRequest = nil
        MyAuthDelegate.received = true
        self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: NSError?) in }), challenge: MyAuthDelegate.challenge)
        
#if swift(>=3.0)
        (self.handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertNotNil(self.handler.activeRequest)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertNotNil(self.handler.activeRequest)
        }
#endif
        //with no active request and no auth delegate
        self.handler.waitingRequests = [MockAuthorizationRequestManager]()
        self.handler.authenticationDelegate = nil
        self.handler.activeRequest = nil
        MyAuthDelegate.received = false
        self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), challenge: ["realm1" : "q1"])
        
#if swift(>=3.0)
        (self.handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertNotNil(self.handler.activeRequest)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertNotNil(self.handler.activeRequest)
        }
#endif
    }
    
    func testHandleSuccess(){
        
        //with auth delegate
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        MyAuthDelegate.success = true
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        handler.handleSuccess(MyAuthDelegate.sucDictionary)
        
#if swift(>=3.0)
        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
        }
#endif
        
        //no auth delegate
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        self.handler.authenticationDelegate = nil
        MyAuthDelegate.success = false
        self.handler.handleSuccess(MyAuthDelegate.sucDictionary)
#if swift(>=3.0)
        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 0)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 0)
        }
#endif
    }
    
    func testHandleFailure(){
        
        //with auth delegate
        handler.waitingRequests = [MockAuthorizationRequestManager]()
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        MyAuthDelegate.failure = true
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        handler.handleFailure(MyAuthDelegate.failDictionary)
        
#if swift(>=3.0)
        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 0)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 0)
        }
#endif
    
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

#if swift(>=3.0)
        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
        }
#endif
        
        //no active request
        self.handler.activeRequest = nil
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        self.handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        handler.submitAuthenticationFailure(MockAuthorizationRequestManager.failedInfo)
        
#if swift(>=3.0)
        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
            XCTAssertNil(self.handler.activeRequest)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
            XCTAssertNil(self.handler.activeRequest)
        }
#endif
        
    }
    
    func testSubmitAuthenticationSuccess() {
        
        //with active request
        handler.waitingRequests = [MockAuthorizationRequestManager]()
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        handler.submitAuthenticationSuccess()

#if swift(>=3.0)
        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 3)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 3)
        }
#endif
        
        //no active request
        self.handler.activeRequest = nil
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        self.handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        handler.submitAuthenticationSuccess()
        
#if swift(>=3.0)
        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
            XCTAssertNil(self.handler.activeRequest)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
            XCTAssertNil(self.handler.activeRequest)
        }
#endif
    }
    
    func testSubmitAuthenticationChallengeAnswer(){
        
        //with active request and an answer
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.submitAuthenticationChallengeAnswer(MockAuthorizationRequestManager.answer)
        MockAuthorizationRequestManager.submitAnswerCount = 0
        
#if swift(>=3.0)
        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(MockAuthorizationRequestManager.submitAnswerCount,1)
            XCTAssertNil(self.handler.activeRequest)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertEqual(MockAuthorizationRequestManager.submitAnswerCount,1)
            XCTAssertNil(self.handler.activeRequest)
        }
#endif
        
        //with active request and nil answer
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.submitAuthenticationChallengeAnswer(nil)
     
#if swift(>=3.0)
        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount,1)
            XCTAssertNil(self.handler.activeRequest)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount,1)
            XCTAssertNil(self.handler.activeRequest)
        }
#endif
        
        //no active request
        handler.activeRequest = nil
        handler.submitAuthenticationChallengeAnswer(nil)
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        MockAuthorizationRequestManager.submitAnswerCount = 0
        
#if swift(>=3.0)
        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(MockAuthorizationRequestManager.submitAnswerCount,0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount,0)
        })
#else
        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertEqual(MockAuthorizationRequestManager.submitAnswerCount,0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount,0)
        }
#endif
    }
    
    
    
    
}
class MockAuthorizationRequestManager : AuthorizationRequestManager {
    static var removeExpectedAnswerCount = 0
    static var submitAnswerCount = 0
    static var requestFailedCount = 0
    static var answer = ["a1" : "1"]
    static var failedInfo = ["a2" : "2"]
    override func removeExpectedAnswer(_ realm: String) {
        XCTAssertEqual(realm, ChallengeHandlerTest.realm)
        MockAuthorizationRequestManager.removeExpectedAnswerCount += 1
    }
    override func submitAnswer(_ answer: [String : AnyObject]?, realm: String) {
        MockAuthorizationRequestManager.submitAnswerCount += 1
        XCTAssertEqual(answer, MockAuthorizationRequestManager.answer as NSDictionary)
        XCTAssertEqual(realm, ChallengeHandlerTest.realm)
    }
    override func requestFailed(_ info: [String : AnyObject]?) {
        XCTAssertEqual(info, MockAuthorizationRequestManager.failedInfo as NSDictionary)
        MockAuthorizationRequestManager.requestFailedCount += 1
    }
    
}

class MyAuthDelegate : AuthenticationDelegate {
    static var received = false
    static var success = false
    static var failure = false
    static let sucDictionary = ["a" : 1 , "b" : "2"]
    static let failDictionary = ["c" : 1 , "d" : "2"]
    static let challenge = ["realm1" : "q1"]
    func onAuthenticationChallengeReceived(_ authContext: AuthenticationContext, challenge: AnyObject){
        XCTAssertTrue(MyAuthDelegate.received)
    }
    func onAuthenticationSuccess(_ info: AnyObject?) {
        XCTAssertTrue(MyAuthDelegate.success)
        XCTAssertEqual(MyAuthDelegate.sucDictionary, info as? NSDictionary)
    }
    func onAuthenticationFailure(_ info: AnyObject?){
        XCTAssertTrue(MyAuthDelegate.failure)
        XCTAssertEqual(MyAuthDelegate.failDictionary, info as? NSDictionary)
        
    }
}



