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
    #if swift(>=3.0)
    let defaultCompletionHandler = {(response: Response?, error: Error?) in }
    #else
    let defaultCompletionHandler = {(response: Response?, error: NSError?) in }

    #endif
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
        #if swift(>=3.0)
        self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: Error?) in }), challenge: ["realm1" : "q1" as AnyObject])
            #else
             self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: NSError?) in }), challenge: ["realm1" : "q1"])
            #endif
        
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
        #if swift(>=3.0)
            self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: Error?) in }), challenge: MyAuthDelegate.challenge as [String : AnyObject])
        #else
            self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: NSError?) in }), challenge:MyAuthDelegate.challenge)
        #endif
       
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
        
#if swift(>=3.0)
    self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), challenge: ["realm1" : "q1" as AnyObject])
    
        (self.handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertNotNil(self.handler.activeRequest)
        })
#else
    self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), challenge: ["realm1" : "q1"])
    
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
#if swift(>=3.0)
    handler.handleSuccess(MyAuthDelegate.sucDictionary as [String : AnyObject])

        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
        })
#else
    handler.handleSuccess(MyAuthDelegate.sucDictionary)

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
#if swift(>=3.0)
        self.handler.handleSuccess(MyAuthDelegate.sucDictionary as [String : AnyObject])
        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 0)
        })
#else
        self.handler.handleSuccess(MyAuthDelegate.sucDictionary)
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
        
#if swift(>=3.0)
    handler.handleFailure(MyAuthDelegate.failDictionary as [String : AnyObject])

        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 0)
        })
    //no auth delegate
    MyAuthDelegate.failure = false
    self.handler.authenticationDelegate = nil
    self.handler.handleFailure(MyAuthDelegate.sucDictionary as [String : AnyObject])

#else
    handler.handleFailure(MyAuthDelegate.failDictionary)

        dispatch_barrier_sync(self.handler.lockQueue) {
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 0)
        }
    //no auth delegate
    MyAuthDelegate.failure = false
    self.handler.authenticationDelegate = nil
    self.handler.handleFailure(MyAuthDelegate.sucDictionary)

#endif
    
        
    }
    
    func testSubmitAuthenticationFailure(){
        
        //with active request
        handler.waitingRequests = [MockAuthorizationRequestManager]()
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0

#if swift(>=3.0)
    handler.submitAuthenticationFailure(MockAuthorizationRequestManager.failedInfo as [String : AnyObject]?)

    //with active request
    handler.waitingRequests = [MockAuthorizationRequestManager]()
    handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
    handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
    MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
    handler.submitAuthenticationFailure(MockAuthorizationRequestManager.failedInfo as [String : AnyObject]?)
        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertNil(self.handler.activeRequest)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
        })
#else
    handler.submitAuthenticationFailure(MockAuthorizationRequestManager.failedInfo)

    //with active request
    handler.waitingRequests = [MockAuthorizationRequestManager]()
    handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
    handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
    MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
    handler.submitAuthenticationFailure(MockAuthorizationRequestManager.failedInfo)
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
        
#if swift(>=3.0)
    handler.submitAuthenticationFailure(MockAuthorizationRequestManager.failedInfo as [String : AnyObject]?)

        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
            XCTAssertNil(self.handler.activeRequest)
        })
#else
    handler.submitAuthenticationFailure(MockAuthorizationRequestManager.failedInfo)

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
        
#if swift(>=3.0)
    handler.submitAuthenticationChallengeAnswer(MockAuthorizationRequestManager.answer as [String : AnyObject]?)
    MockAuthorizationRequestManager.submitAnswerCount = 0

        (handler.lockQueue).sync(flags: .barrier, execute: {
            XCTAssertEqual(MockAuthorizationRequestManager.submitAnswerCount,1)
            XCTAssertNil(self.handler.activeRequest)
        })
#else
    handler.submitAuthenticationChallengeAnswer(MockAuthorizationRequestManager.answer)
    MockAuthorizationRequestManager.submitAnswerCount = 0

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

#if swift(>=3.0)
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
    override func submitAnswer(_ answer: [String : Any]?, realm: String) {
        MockAuthorizationRequestManager.submitAnswerCount += 1
        XCTAssertEqual(answer! as NSDictionary, MockAuthorizationRequestManager.answer as NSDictionary)
        XCTAssertEqual(realm, ChallengeHandlerTest.realm)
    }
    override func requestFailed(_ info: [String : Any]?) {
        XCTAssertEqual(info! as NSDictionary, MockAuthorizationRequestManager.failedInfo as NSDictionary)
        MockAuthorizationRequestManager.requestFailedCount += 1
    }
    
}
    
    class MyAuthDelegate : AuthenticationDelegate {
        static var received = false
        static var success = false
        static var failure = false
        static let sucDictionary = ["a" : 1 , "b" : "2"] as [String : Any]
        static let failDictionary = ["c" : 1 , "d" : "2"] as [String : Any]
        static let challenge = ["realm1" : "q1"]
        
        func onAuthenticationChallengeReceived(_ authContext: AuthenticationContext, challenge: AnyObject){
            XCTAssertTrue(MyAuthDelegate.received)
        }
        func onAuthenticationSuccess(_ info: AnyObject?) {
            XCTAssertTrue(MyAuthDelegate.success)
            XCTAssertEqual(MyAuthDelegate.sucDictionary as NSDictionary, info as? NSDictionary)
        }
        func onAuthenticationFailure(_ info: AnyObject?){
            XCTAssertTrue(MyAuthDelegate.failure)
            XCTAssertEqual(MyAuthDelegate.failDictionary as NSDictionary, info as? NSDictionary)
        }
    }
    
#else
    class MockAuthorizationRequestManager : AuthorizationRequestManager {
        static var removeExpectedAnswerCount = 0
        static var submitAnswerCount = 0
        static var requestFailedCount = 0
        static var answer = ["a1" : "1"]
        static var failedInfo = ["a2" : "2"]
        
        override func removeExpectedAnswer(realm: String) {
            XCTAssertEqual(realm, ChallengeHandlerTest.realm)
            MockAuthorizationRequestManager.removeExpectedAnswerCount += 1
        }
        override func submitAnswer(answer: [String : AnyObject]?, realm: String) {
            MockAuthorizationRequestManager.submitAnswerCount += 1
            XCTAssertEqual(answer, MockAuthorizationRequestManager.answer as NSDictionary)
            XCTAssertEqual(realm, ChallengeHandlerTest.realm)
        }
        override func requestFailed(info: [String : AnyObject]?) {
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
#endif





