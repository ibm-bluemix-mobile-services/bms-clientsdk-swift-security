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

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    public func test(){
        class MyAuthDelegate : AuthenticationDelegate {
            func onAuthenticationChallengeReceived(authContext: AuthenticationContext, challenge: AnyObject?){
            }
            func onAuthenticationSuccess(info: AnyObject?) {
                
            }
            func onAuthenticationFailure(info: AnyObject?){
                
            }
        }
        let delegate = MyAuthDelegate()

        var handler:MockChallengeHandler = MockChallengeHandler(realm: "realm1", authenticationDelegate: delegate)
        handler.submitAuthenticationSuccess()
    }
    class MockAuthorizationRequestManager : AuthorizationRequestManager {
        
    }
    class MockChallengeHandler : ChallengeHandler {
         var realm:String = "yo"
         var authenticationDelegate:AuthenticationDelegate?
         var waitingRequests:[MockAuthorizationRequestManager] = []
         var activeRequest:MockAuthorizationRequestManager?
        private var lockQueue = dispatch_queue_create("MockChallengeHandlerQueue", DISPATCH_QUEUE_CONCURRENT)
        internal override init(realm: String, authenticationDelegate: AuthenticationDelegate) {
            super.init(realm: realm, authenticationDelegate: authenticationDelegate)
            self.realm = "yo"
        }
    }
   
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock {
            // Put the code you want to measure the time of here.
        }
    }

}
