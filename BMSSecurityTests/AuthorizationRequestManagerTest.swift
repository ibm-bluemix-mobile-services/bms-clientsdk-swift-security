//
//  AuthorizationRequestManagerTest.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 2/29/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import XCTest
import BMSCore
@testable import BMSSecurity

class AuthorizationRequestManagerTest: XCTestCase {
    
    
    
#if swift (>=3.0)
    var requestManager:AuthorizationRequestManager = AuthorizationRequestManager(completionHandler: {(response: Response?, error: Error?) in })
    override func setUp() {
        requestManager = AuthorizationRequestManager(completionHandler: {(response: Response?, error: Error?) in })
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    private func stringToBase64Data(_ str:String) -> Data {
        let utf8str = str.data(using: String.Encoding.utf8)
        let base64EncodedStr = utf8str?.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0))
        return Data(base64Encoded: base64EncodedStr!, options: NSData.Base64DecodingOptions(rawValue: 0))!
    }
#else
    var requestManager:AuthorizationRequestManager = AuthorizationRequestManager(completionHandler: {(response: Response?, error: NSError?) in })
    override func setUp() {
    requestManager = AuthorizationRequestManager(completionHandler: {(response: Response?, error: NSError?) in })
    super.setUp()
    // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    private func stringToBase64Data(str:String) -> NSData {
        let utf8str = str.dataUsingEncoding(NSUTF8StringEncoding)
        let base64EncodedStr = utf8str?.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        return NSData(base64EncodedString: base64EncodedStr!, options: NSDataBase64DecodingOptions(rawValue: 0))!
    }
#endif
    
//    func testSendInternal(){
//        XCTFail()
//    }
//    func testIsAuthorizationRequired(){
//       XCTFail()
//    }
    func testIsAnswersFilled(){
        class MockAuthorizationRequestManager: AuthorizationRequestManager {
            override func resendRequest() throws {
                return
            }
        }
        
        #if swift (>=3.0)
            BMSClient.sharedInstance.initialize(bluemixAppRoute: "www.test.com", bluemixAppGUID: "12345", bluemixRegion: BMSClient.Region.usSouth)
            let mockRequestManager = MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: Error?) in })
        #else
            BMSClient.sharedInstance.initializeWithBluemixAppRoute("www.test.com", bluemixAppGUID: "12345", bluemixRegion: BMSClient.REGION_US_SOUTH)
            let mockRequestManager = MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: NSError?) in })
        #endif
        XCTAssertTrue(mockRequestManager.isAnswersFilled())
        #if swift (>=3.0)
            mockRequestManager.submitAnswer(["q1" : "a1" as AnyObject], realm: "realm1")
        #else
            mockRequestManager.submitAnswer(["q1" : "a1"], realm: "realm1")
        #endif
        XCTAssertTrue(mockRequestManager.isAnswersFilled())
        mockRequestManager.setExpectedAnswers(["realm1", "realm2"])
        XCTAssertFalse((mockRequestManager.isAnswersFilled()))
        #if swift (>=3.0)
            mockRequestManager.submitAnswer(["q1" : "a1" as AnyObject], realm: "realm1")
        #else
            mockRequestManager.submitAnswer(["q1" : "a1"], realm: "realm1")
        #endif
        XCTAssertFalse((mockRequestManager.isAnswersFilled()))
    }
    
    func testRemoveAndSetAnswers(){
        class MockAuthorizationRequestManager: AuthorizationRequestManager {
            override func resendRequest() throws {
                return
            }
        }
        
        #if swift (>=3.0)
            BMSClient.sharedInstance.initialize(bluemixAppRoute: "www.test.com", bluemixAppGUID: "12345", bluemixRegion: BMSClient.Region.usSouth)
            let mockRequestManager = MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: Error?) in })
        #else
            BMSClient.sharedInstance.initializeWithBluemixAppRoute("www.test.com", bluemixAppGUID: "12345", bluemixRegion: BMSClient.REGION_US_SOUTH)
            let mockRequestManager = MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: NSError?) in })
        #endif
        mockRequestManager.setExpectedAnswers(["realm1", "realm2", "realm3"])
        XCTAssertNil(mockRequestManager.answers)
        #if swift (>=3.0)
            mockRequestManager.submitAnswer(["q1" : "a1" as AnyObject], realm: "realm1")
        #else
            mockRequestManager.submitAnswer(["q1" : "a1"], realm: "realm1")
        #endif
        mockRequestManager.setExpectedAnswers(["realm1", "realm2", "realm3"])
        XCTAssertNotNil(mockRequestManager.answers?["realm1"])
        XCTAssertNotNil(mockRequestManager.answers?["realm2"])
        XCTAssertNotNil(mockRequestManager.answers?["realm3"])
        mockRequestManager.removeExpectedAnswer("realm2")
        XCTAssertNil(mockRequestManager.answers?["realm2"])
        XCTAssertNotNil(mockRequestManager.answers?["realm3"])
        #if swift (>=3.0)
            mockRequestManager.submitAnswer(["q1" : "a1" as AnyObject], realm: "realm1")
        #else
            mockRequestManager.submitAnswer(["q1" : "a1"], realm: "realm1")
        #endif
        XCTAssertEqual(mockRequestManager.answers?["realm1"] as? NSDictionary, ["q1" : "a1"])
        
    }
    
    
    func testSend(){
        class MockAuthorizationRequestManager: AuthorizationRequestManager {
            static var override = false
            static var fullPath = false

            override func sendInternal(_ rootUrl: String, path: String, options: RequestOptions?) throws {
                 if !MockAuthorizationRequestManager.fullPath {
                    let prefix = MockAuthorizationRequestManager.override ? "override" : MCAAuthorizationManager.defaultProtocol
                        + "://"
                        + BMSSecurityConstants.AUTH_SERVER_NAME
                        + BMSClient.sharedInstance.bluemixRegion!
                    
                    XCTAssertEqual(rootUrl, prefix
                        + "/"
                        + BMSSecurityConstants.AUTH_SERVER_NAME
                        + "/"
                        + BMSSecurityConstants.AUTH_PATH
                        + BMSClient.sharedInstance.bluemixAppGUID!)
                    XCTAssertEqual(path, "/someEndPoint")
                } else {
                    XCTAssertEqual(rootUrl, MCAAuthorizationManager.HTTP_SCHEME + "://www.test.com")
                    XCTAssertEqual(path, "/a/b/c/someEndPoint")
                }
            }
        }
#if swift (>=3.0)
        BMSClient.sharedInstance.initialize(bluemixAppRoute: "www.test.com", bluemixAppGUID: "12345", bluemixRegion: BMSClient.Region.usSouth)
        let mockRequestManager = MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: Error?) in })
#else
        BMSClient.sharedInstance.initializeWithBluemixAppRoute("www.test.com", bluemixAppGUID: "12345", bluemixRegion: BMSClient.REGION_US_SOUTH)
        let mockRequestManager = MockAuthorizationRequestManager(completionHandler: {(response: Response?, error: NSError?) in })
#endif


        
        let endPoint = "/someEndPoint"
        XCTAssertNotNil(try? mockRequestManager.send(endPoint, options: RequestOptions()))
        MockAuthorizationRequestManager.overrideServerHost = "override"
        MockAuthorizationRequestManager.override = true
        XCTAssertNotNil(try? mockRequestManager.send(endPoint, options: RequestOptions()))
        let path = MCAAuthorizationManager.HTTP_SCHEME + "://www.test.com/a/b/c" + endPoint
        MockAuthorizationRequestManager.fullPath = true
        XCTAssertNotNil(try? mockRequestManager.send(path, options: RequestOptions()))
       
    }
    
}
