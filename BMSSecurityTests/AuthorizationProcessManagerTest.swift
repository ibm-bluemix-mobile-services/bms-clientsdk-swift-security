//
//  AuthorizationProcessManagerTest.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 3/1/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import XCTest
import BMSCore
@testable import BMSSecurity

class AuthorizationProcessManagerTest: XCTestCase {

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
//    func testStartAuthorizationProcess(){
//        class MockAuthorizationProcessManager : AuthorizationProcessManager {
//            static var registration:Bool = true
//            
//            func invokeInstanceRegistrationRequest(){
//                XCTAssertTrue(MockAuthorizationProcessManager.registration)
//            }
//            func invokeAuthorizationRequest(){
//                XCTAssertFalse(MockAuthorizationProcessManager.registration)
//            }
//            
//        }
//        
//        var preferences = AuthorizationManagerPreferences()
//        var mockAuthProcessManager:MockAuthorizationProcessManager = MockAuthorizationProcessManager(preferences: preferences)
//        mockAuthProcessManager.startAuthorizationProcess({(response: Response?, error: NSError?) in })
//        MockAuthorizationProcessManager.registration = true
//        preferences.clientId.set("testclientid")
//        mockAuthProcessManager = MockAuthorizationProcessManager(preferences: preferences)
//        mockAuthProcessManager.startAuthorizationProcess({(response: Response?, error: NSError?) in })
//  
//    }

   
}
