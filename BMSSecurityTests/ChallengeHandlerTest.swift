//
//  ChallengeHandlerTest.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 2/29/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import XCTest
@testable import BMSCore
@testable import BMSSecurity

class ChallengeHandlerTest: XCTestCase {
    var delegate = MyAuthDelegate()
    var handler = ChallengeHandler(realm: "testrealm",authenticationDelegate: MyAuthDelegate())
    var testQueue = dispatch_queue_create("testQueue", DISPATCH_QUEUE_CONCURRENT)
    let defaultCompletionHandler = {(response: Response?, error: NSError?) in }
    override func setUp() {
        super.setUp()
        MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
        MyAuthDelegate.success = false
        MyAuthDelegate.failure = false
        MyAuthDelegate.received = false
        handler.authenticationDelegate = delegate
        testQueue = handler.lockQueue
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testHandleChallenge1(){
        dispatch_barrier_async(testQueue){
            self.handler.waitingRequests = [MockAuthorizationRequestManager]()
            self.handler.lockQueue = self.testQueue
            self.delegate.lockQueue = self.testQueue
            MyAuthDelegate.received = false
            self.handler.activeRequest =  MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
            self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: NSError?) in }), challenge: ["realm1" : "q1"])
            dispatch_barrier_async(self.handler.lockQueue){
                XCTAssertEqual(self.handler.waitingRequests.count, 1)
            }
        }
    }
    
    func testHandleChallenge2(){
        dispatch_barrier_async(testQueue){
            self.handler.waitingRequests = [MockAuthorizationRequestManager]()
            self.handler.lockQueue = self.testQueue
            self.delegate.lockQueue = self.testQueue
            MyAuthDelegate.received = false
            self.handler.authenticationDelegate = nil
            self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: NSError?) in }), challenge: ["realm1" : "q1"])
            dispatch_barrier_async(self.handler.lockQueue){
                XCTAssertEqual(self.handler.waitingRequests.count, 0)
            }
        }
    }
    
    func testHandleChallenge3(){
        dispatch_barrier_sync(testQueue){
            
            self.handler.waitingRequests = [MockAuthorizationRequestManager]()
            self.handler.lockQueue = self.testQueue
            self.delegate.lockQueue = self.testQueue
            MyAuthDelegate.received = true
            self.handler.handleChallenge(MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), challenge: ["realm1" : "q1"])
            dispatch_barrier_async(self.handler.lockQueue){
                XCTAssertEqual(self.handler.waitingRequests.count, 0)
                XCTAssertNotNil(self.handler.activeRequest)
            }
        }
    }
    
    
    func testHandleSuccess(){
        
        handler.waitingRequests = [MockAuthorizationRequestManager]()
        handler.lockQueue = self.testQueue
        delegate.lockQueue = self.testQueue
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        MyAuthDelegate.success = true
        handler.handleSuccess(MyAuthDelegate.sucDictionary)
        dispatch_barrier_async(handler.lockQueue){
            XCTAssertNil( self.handler.activeRequest)
            XCTAssertEqual( self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 2)
            MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
            MyAuthDelegate.success = false
            self.handler.authenticationDelegate = nil
            self.handler.handleSuccess(MyAuthDelegate.sucDictionary)
        }
    }
    
    func testHandleFailure(){
        
        handler.waitingRequests = [MockAuthorizationRequestManager]()
        handler.lockQueue = self.testQueue
        delegate.lockQueue = self.testQueue
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        MyAuthDelegate.failure = true
        handler.handleFailure(MyAuthDelegate.failDictionary)
        dispatch_barrier_async(handler.lockQueue){
            XCTAssertNil( self.handler.activeRequest)
            XCTAssertEqual( self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 0)
            MyAuthDelegate.failure = false
            self.handler.authenticationDelegate = nil
            self.handler.handleSuccess(MyAuthDelegate.sucDictionary)
        }
    }
    //
    
    func testSubmitAuthenticationFailure(){
        
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        handler.submitAuthenticationFailure(nil)
        dispatch_barrier_async(handler.lockQueue){
            XCTAssertNil( self.handler.activeRequest)
            XCTAssertEqual( self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.requestFailedCount, 0)
            MockAuthorizationRequestManager.requestFailedCount = 0
            self.handler.activeRequest = nil
            self.handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
            self.handler.submitAuthenticationFailure(nil)
            XCTAssertEqual(self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 0)
            
        }
        
    }
    func testSubmitAuthenticationSuccess() {
        
        handler.waitingRequests = [MockAuthorizationRequestManager]()
        handler.lockQueue = self.testQueue
        delegate.lockQueue = self.testQueue
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
        handler.submitAuthenticationSuccess()
        dispatch_barrier_async(handler.lockQueue){
            XCTAssertNil( self.handler.activeRequest)
            XCTAssertEqual( self.handler.waitingRequests.count, 0)
            print(MockAuthorizationRequestManager.removeExpectedAnswerCount)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 3)
            MockAuthorizationRequestManager.removeExpectedAnswerCount = 0
            self.handler.waitingRequests = [MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler), MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)]
            XCTAssertEqual( self.handler.waitingRequests.count, 0)
            XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount, 0)
        }
    }
    func testSubmitAuthenticationChallengeAnswer(){
        
        handler.activeRequest = MockAuthorizationRequestManager(completionHandler: self.defaultCompletionHandler)
        handler.submitAuthenticationChallengeAnswer(MockAuthorizationRequestManager.answer)
        XCTAssertEqual(MockAuthorizationRequestManager.submitAnswerCount,1)
        handler.submitAuthenticationChallengeAnswer(nil)
        XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount,1)
        XCTAssertNil(handler.activeRequest)
        handler.activeRequest = nil
        XCTAssertEqual(MockAuthorizationRequestManager.submitAnswerCount,0)
        XCTAssertEqual(MockAuthorizationRequestManager.removeExpectedAnswerCount,0)
    }
    
    
    
    class MockAuthorizationRequestManager : AuthorizationRequestManager {
        static var removeExpectedAnswerCount = 0
        static var submitAnswerCount = 0
        static var requestFailedCount = 0
        static var answer = ["a1" : "1"]
        override func removeExpectedAnswer(realm: String) {
            MockAuthorizationRequestManager.removeExpectedAnswerCount++
        }
        override func submitAnswer(answer: [String : AnyObject]?, realm: String) {
            MockAuthorizationRequestManager.submitAnswerCount++
            //TODO: fix it
            //XCTAssertEqual(answer, MockAuthorizationRequestManager.answer as? NSDictionary)
            XCTAssertEqual(realm, "testrealm")
        }
        override func requestFailed(info: [String : AnyObject]?) {
            MockAuthorizationRequestManager.requestFailedCount++
        }
    }
    
    class MyAuthDelegate : AuthenticationDelegate {
        static var received = false
        static var success = false
        static var failure = false
        static let sucDictionary = ["a" : 1 , "b" : "2"]
        static let failDictionary = ["c" : 1 , "d" : "2"]
        var lockQueue:dispatch_queue_t?
        func onAuthenticationChallengeReceived(authContext: AuthenticationContext, challenge: AnyObject?){
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
    
    
}
