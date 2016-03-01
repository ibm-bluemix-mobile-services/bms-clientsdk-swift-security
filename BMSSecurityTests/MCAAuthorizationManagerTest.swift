//
//  MCAAuthorizationManagerTest.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 2/28/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import XCTest
@testable import BMSCore
@testable import BMSSecurity

class MCAAuthorizationManagerTest: XCTestCase {
    var mcaAuthManager = MCAAuthorizationManager.sharedInstance
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        mcaAuthManager.preferences = AuthorizationManagerPreferences()
        super.tearDown()
    }
    private func stringToBase64Data(str:String) -> NSData {
        let utf8str = str.dataUsingEncoding(NSUTF8StringEncoding)
        let base64EncodedStr = utf8str?.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        return NSData(base64EncodedString: base64EncodedStr!, options: NSDataBase64DecodingOptions(rawValue: 0))!
    }
    
    func testIsAuthorizationRequired() {
        //TODO complete this
        let authHeader = "ThisIsBEARer unittest"
        let noAuthHeader = "ThisIsBearr unittest"
        XCTAssertTrue(mcaAuthManager.isAuthorizationRequired(401, responseAuthorizationHeader: authHeader))
        XCTAssertTrue(mcaAuthManager.isAuthorizationRequired(403, responseAuthorizationHeader: authHeader))
        XCTAssertFalse(mcaAuthManager.isAuthorizationRequired(400, responseAuthorizationHeader: authHeader))
        XCTAssertFalse(mcaAuthManager.isAuthorizationRequired(401, responseAuthorizationHeader: noAuthHeader))
        let txt = "test"
        let response1:Response = Response(responseData: stringToBase64Data(txt), httpResponse: NSHTTPURLResponse(URL: NSURL(), statusCode: 401, HTTPVersion: nil, headerFields: [BMSSecurityConstants.WWW_AUTHENTICATE_HEADER : "Bearer"]), isRedirect: false)
        XCTAssertTrue(mcaAuthManager.isAuthorizationRequired(response1))
        let response2:Response = Response(responseData: stringToBase64Data(txt), httpResponse: NSHTTPURLResponse(URL: NSURL(), statusCode: 401, HTTPVersion: nil, headerFields: [BMSSecurityConstants.WWW_AUTHENTICATE_HEADER.lowercaseString : "Bearer"]), isRedirect: false)
        XCTAssertTrue(mcaAuthManager.isAuthorizationRequired(response2))
        let response3:Response = Response(responseData: stringToBase64Data(txt), httpResponse: NSHTTPURLResponse(), isRedirect: false)
        XCTAssertFalse(mcaAuthManager.isAuthorizationRequired(response3))
    }
    func testClearAuthorizationData(){
        mcaAuthManager.preferences.accessToken.set("testAccessToken")
        mcaAuthManager.preferences.idToken.set("testAccessToken")
        mcaAuthManager.preferences.userIdentity.set("testUserIdentity")
        mcaAuthManager.clearAuthorizationData()
        XCTAssertNil(mcaAuthManager.preferences.userIdentity.get())
        XCTAssertNil(mcaAuthManager.preferences.idToken.get())
        XCTAssertNil(mcaAuthManager.preferences.accessToken.get())
        //TODO: check cookies are cleared
    }
    
    func testPersistencePolicy(){
        mcaAuthManager.setAuthorizationPersistensePolicy(PersistencePolicy.ALWAYS)
        XCTAssertEqual(mcaAuthManager.getAuthorizationPersistencePolicy(),PersistencePolicy.ALWAYS)
        mcaAuthManager.setAuthorizationPersistensePolicy(PersistencePolicy.NEVER)
        XCTAssertEqual(mcaAuthManager.getAuthorizationPersistencePolicy(),PersistencePolicy.NEVER)
    }
    
    func testGetCachedAuthorizationHeader(){
        XCTAssertNil(mcaAuthManager.getCachedAuthorizationHeader())
        mcaAuthManager.preferences.idToken.set("testIdToken")
        XCTAssertNil(mcaAuthManager.getCachedAuthorizationHeader())
        mcaAuthManager.preferences.accessToken.set("testAccessToken")
        XCTAssertEqual(mcaAuthManager.getCachedAuthorizationHeader(), "\(BMSSecurityConstants.BEARER) testAccessToken testIdToken")
        mcaAuthManager.preferences.idToken.clear()
        XCTAssertNil(mcaAuthManager.getCachedAuthorizationHeader())
        
    }
    
    func testAddCachedAuthorizationHeader(){
        let request = NSMutableURLRequest()
        mcaAuthManager.preferences.idToken.set("testIdToken")
        mcaAuthManager.preferences.accessToken.set("testAccessToken")
        mcaAuthManager.addCachedAuthorizationHeader(request)
        XCTAssertEqual(request.valueForHTTPHeaderField(BMSSecurityConstants.AUTHORIZATION_HEADER), "\(BMSSecurityConstants.BEARER) testAccessToken testIdToken")
    }
    
    func testRegisterAndUnregisterAuthenticationDelegate(){
        
        class MyAuthDelegate : AuthenticationDelegate {
            func onAuthenticationChallengeReceived(authContext: AuthenticationContext, challenge: AnyObject?){
            }
            func onAuthenticationSuccess(info: AnyObject?) {
               
            }
            func onAuthenticationFailure(info: AnyObject?){
               
            }
        }
        let delegate = MyAuthDelegate()
        let realm = "testRealm"
        XCTAssertNil(try? mcaAuthManager.registerAuthenticationDelegate(delegate, realm: ""))
        mcaAuthManager.unregisterAuthenticationDelegate("")
        XCTAssertNotNil(try? mcaAuthManager.registerAuthenticationDelegate(delegate, realm: realm))
        XCTAssertNotNil(mcaAuthManager.getChallengeHandler(realm))
        mcaAuthManager.unregisterAuthenticationDelegate(realm)
        XCTAssertNil(mcaAuthManager.getChallengeHandler(realm))
    }
    
    func testGetIdentities(){
        var appId = mcaAuthManager.getAppIdentity().jsonData
        XCTAssertEqual(appId[BaseAppIdentity.ID], Utils.getApplicationDetails().name)
        XCTAssertEqual(appId[BaseAppIdentity.VERSION], Utils.getApplicationDetails().version)
        var deviceId = mcaAuthManager.getDeviceIdentity().jsonData
        XCTAssertEqual(deviceId[BaseDeviceIdentity.ID], UIDevice.currentDevice().identifierForVendor?.UUIDString)
        XCTAssertEqual(deviceId[BaseDeviceIdentity.OS], UIDevice.currentDevice().systemVersion)
        XCTAssertEqual(deviceId[BaseDeviceIdentity.MODEL], UIDevice.currentDevice().model)
        mcaAuthManager.preferences.userIdentity.set(["item1" : "one" , "item2" : "two"])
        var userId = mcaAuthManager.getUserIdentity().jsonData
        XCTAssertEqual(userId["item1"], "one")
        XCTAssertEqual(userId["item2"], "two")
    }
    
    func testObtainAuthorization(){
        //no need to check, it just calls AuthoriztionProcessManager's method - startAuthorizationProcess
    }
    
    
    
   
}
