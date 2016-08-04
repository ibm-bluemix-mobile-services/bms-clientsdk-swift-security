//
//  MCAAuthorizationManagerTest.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 2/28/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import XCTest
import BMSCore
@testable import BMSSecurity

class MCAAuthorizationManagerTest: XCTestCase {
    var mcaAuthManager = MCAAuthorizationManager.sharedInstance
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        mcaAuthManager.preferences = MockAuthorizationManagerPreference()
        super.tearDown()
    }
    
    
#if swift (>=3.0)
    private func stringToBase64Data(_ str:String) -> Data {
        let utf8str = str.data(using: String.Encoding.utf8)
        let base64EncodedStr = utf8str?.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0))
        return Data(base64Encoded: base64EncodedStr!, options: NSData.Base64DecodingOptions(rawValue: 0))!
    }
    
    func testIsAuthorizationRequired() {
        let authHeader = "ThisIsBEARer unittest"
        let noAuthHeader = "ThisIsBearr unittest"
        XCTAssertTrue(mcaAuthManager.isAuthorizationRequired(forStatusCode: 401, httpResponseAuthorizationHeader: authHeader))
        XCTAssertTrue(mcaAuthManager.isAuthorizationRequired(forStatusCode: 403, httpResponseAuthorizationHeader: authHeader))
        XCTAssertFalse(mcaAuthManager.isAuthorizationRequired(forStatusCode: 400, httpResponseAuthorizationHeader: authHeader))
        XCTAssertFalse(mcaAuthManager.isAuthorizationRequired(forStatusCode: 401, httpResponseAuthorizationHeader: noAuthHeader))
        let txt = "test"
        let response1:Response = Response(responseData: stringToBase64Data(txt), httpResponse: HTTPURLResponse(url: NSURL() as URL, statusCode: 401, httpVersion: nil, headerFields: [BMSSecurityConstants.WWW_AUTHENTICATE_HEADER : "Bearer"]), isRedirect: false)
        XCTAssertTrue(mcaAuthManager.isAuthorizationRequired(forHttpResponse:response1))
        let response2:Response = Response(responseData: stringToBase64Data(txt), httpResponse: HTTPURLResponse(url: NSURL() as URL, statusCode: 401, httpVersion: nil, headerFields: [BMSSecurityConstants.WWW_AUTHENTICATE_HEADER.lowercased() : "Bearer"]), isRedirect: false)
        XCTAssertTrue(mcaAuthManager.isAuthorizationRequired(forHttpResponse:response2))
        let response3:Response = Response(responseData: stringToBase64Data(txt), httpResponse: HTTPURLResponse(), isRedirect: false)
        XCTAssertFalse(mcaAuthManager.isAuthorizationRequired(forHttpResponse:response3))
    }
#else
    private func stringToBase64Data(str:String) -> NSData {
        let utf8str = str.dataUsingEncoding(NSUTF8StringEncoding)
        let base64EncodedStr = utf8str?.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        return NSData(base64EncodedString: base64EncodedStr!, options: NSDataBase64DecodingOptions(rawValue: 0))!
    }
    
    func testIsAuthorizationRequired() {
        let authHeader = "ThisIsBEARer unittest \"imfAuthentication\""
        let noAuthHeader = "ThisIsBearr unittest"
        XCTAssertTrue(mcaAuthManager.isAuthorizationRequired(forStatusCode: 401, httpResponseAuthorizationHeader: authHeader))
        XCTAssertTrue(mcaAuthManager.isAuthorizationRequired(forStatusCode: 403, httpResponseAuthorizationHeader: authHeader))
        XCTAssertFalse(mcaAuthManager.isAuthorizationRequired(forStatusCode: 400, httpResponseAuthorizationHeader: authHeader))
        XCTAssertFalse(mcaAuthManager.isAuthorizationRequired(forStatusCode: 401, httpResponseAuthorizationHeader: noAuthHeader))
        let txt = "test"
        let response1:Response = Response(responseData: stringToBase64Data(txt), httpResponse: NSHTTPURLResponse(URL: NSURL(), statusCode: 401, HTTPVersion: nil, headerFields: [BMSSecurityConstants.WWW_AUTHENTICATE_HEADER : "Bearer realm=\"imfAuthentication\""]), isRedirect: false)
        XCTAssertTrue(mcaAuthManager.isAuthorizationRequired(forHttpResponse:response1))
        let response2:Response = Response(responseData: stringToBase64Data(txt), httpResponse: NSHTTPURLResponse(URL: NSURL(), statusCode: 401, HTTPVersion: nil, headerFields: [BMSSecurityConstants.WWW_AUTHENTICATE_HEADER.lowercaseString : "Bearer realm=\"imfAuthentication\""]), isRedirect: false)
        XCTAssertTrue(mcaAuthManager.isAuthorizationRequired(forHttpResponse:response2))
        let response3:Response = Response(responseData: stringToBase64Data(txt), httpResponse: NSHTTPURLResponse(), isRedirect: false)
        XCTAssertFalse(mcaAuthManager.isAuthorizationRequired(forHttpResponse:response3))
    }
#endif
    
    
#if swift(>=3.0)
    func testClearAuthorizationData(){
        mcaAuthManager.preferences.accessToken.set("testAccessToken")
        mcaAuthManager.preferences.idToken.set("testAccessToken")
        mcaAuthManager.preferences.userIdentity.set("testUserIdentity")
        let cookiesStorage = HTTPCookieStorage.shared
        cookiesStorage.cookieAcceptPolicy = HTTPCookie.AcceptPolicy.always
        let cookieProperties:[HTTPCookiePropertyKey : AnyObject] = [
            HTTPCookiePropertyKey(rawValue: HTTPCookiePropertyKey.name.rawValue) : "JSESSIONID",
            HTTPCookiePropertyKey(rawValue: HTTPCookiePropertyKey.value.rawValue) : "value",
            HTTPCookiePropertyKey(rawValue: HTTPCookiePropertyKey.domain.rawValue) : "www.test.com",
            HTTPCookiePropertyKey(rawValue: HTTPCookiePropertyKey.originURL.rawValue) : "www.test.com",
            HTTPCookiePropertyKey(rawValue: HTTPCookiePropertyKey.path.rawValue) : "/",
            HTTPCookiePropertyKey(rawValue: HTTPCookiePropertyKey.version.rawValue) : "0"
        ]
        cookiesStorage.setCookie(HTTPCookie(properties: cookieProperties)!)
        XCTAssertEqual(numberOfCookiesForName("JSESSIONID"), 1)
        mcaAuthManager.clearAuthorizationData()
        XCTAssertEqual(numberOfCookiesForName("JSESSIONID"), 0)
        XCTAssertNil(mcaAuthManager.preferences.userIdentity.get())
        XCTAssertNil(mcaAuthManager.preferences.idToken.get())
        XCTAssertNil(mcaAuthManager.preferences.accessToken.get())
    }
    
    private func numberOfCookiesForName(_ name:String) -> Int {
        var count = 0
        let cookiesStorage = HTTPCookieStorage.shared
        if let cookies = cookiesStorage.cookies {
            for cookie in cookies {
                if cookie.name == name {
                    count += 1
                }
            }
        }
        return count
    }
#else
    func testClearAuthorizationData(){
        mcaAuthManager.preferences.accessToken.set("testAccessToken")
        mcaAuthManager.preferences.idToken.set("testAccessToken")
        mcaAuthManager.preferences.userIdentity.set("testUserIdentity")
        let cookiesStorage = NSHTTPCookieStorage.sharedHTTPCookieStorage()
        cookiesStorage.cookieAcceptPolicy = NSHTTPCookieAcceptPolicy.Always
        let cookieProperties:[String : AnyObject] = [
            NSHTTPCookieName : "JSESSIONID",
            NSHTTPCookieValue : "value",
            NSHTTPCookieDomain : "www.test.com",
            NSHTTPCookieOriginURL : "www.test.com",
            NSHTTPCookiePath : "/",
            NSHTTPCookieVersion : "0"
        ]
        cookiesStorage.setCookie(NSHTTPCookie(properties: cookieProperties)!)
        XCTAssertEqual(numberOfCookiesForName("JSESSIONID"), 1)
        mcaAuthManager.clearAuthorizationData()
        XCTAssertEqual(numberOfCookiesForName("JSESSIONID"), 0)
        XCTAssertNil(mcaAuthManager.preferences.userIdentity.get())
        XCTAssertNil(mcaAuthManager.preferences.idToken.get())
        XCTAssertNil(mcaAuthManager.preferences.accessToken.get())
    }
    
    private func numberOfCookiesForName(name:String) -> Int {
        var count = 0
        let cookiesStorage = NSHTTPCookieStorage.sharedHTTPCookieStorage()
        if let cookies = cookiesStorage.cookies {
            for cookie in cookies {
                if cookie.name == name {
                    count += 1
                }
            }
        }
        return count
    }
#endif
    
    func testPersistencePolicy(){
        mcaAuthManager.setAuthorizationPersistencePolicy(PersistencePolicy.ALWAYS)
        XCTAssertEqual(mcaAuthManager.authorizationPersistencePolicy(),PersistencePolicy.ALWAYS)
        mcaAuthManager.setAuthorizationPersistencePolicy(PersistencePolicy.NEVER)
        XCTAssertEqual(mcaAuthManager.authorizationPersistencePolicy(),PersistencePolicy.NEVER)
    }
    
    func testGetCachedAuthorizationHeader(){
        XCTAssertNil(mcaAuthManager.cachedAuthorizationHeader)
        mcaAuthManager.preferences.idToken.set("testIdToken")
        XCTAssertNil(mcaAuthManager.cachedAuthorizationHeader)
        mcaAuthManager.preferences.accessToken.set("testAccessToken")
        XCTAssertEqual(mcaAuthManager.cachedAuthorizationHeader, "\(BMSSecurityConstants.BEARER) testAccessToken testIdToken")
        mcaAuthManager.preferences.idToken.clear()
        XCTAssertNil(mcaAuthManager.cachedAuthorizationHeader)
        
    }
    
    func testAddCachedAuthorizationHeader(){
        let request = NSMutableURLRequest()
        mcaAuthManager.preferences.idToken.set("testIdToken")
        mcaAuthManager.preferences.accessToken.set("testAccessToken")
        mcaAuthManager.addCachedAuthorizationHeader(request)
#if swift(>=3.0)
        XCTAssertEqual(request.value(forHTTPHeaderField: BMSSecurityConstants.AUTHORIZATION_HEADER), "\(BMSSecurityConstants.BEARER) testAccessToken testIdToken")
#else
        XCTAssertEqual(request.valueForHTTPHeaderField(BMSSecurityConstants.AUTHORIZATION_HEADER), "\(BMSSecurityConstants.BEARER) testAccessToken testIdToken")
#endif
    }
    
    func testRegisterAndUnregisterAuthenticationDelegate(){
        
        class MyAuthDelegate : AuthenticationDelegate {
            func onAuthenticationChallengeReceived(_ authContext: AuthenticationContext, challenge: AnyObject){
            }
            func onAuthenticationSuccess(_ info: AnyObject?) {
                
            }
            func onAuthenticationFailure(_ info: AnyObject?){
                
            }
        }
        let delegate = MyAuthDelegate()
        let realm = "testRealm"
        mcaAuthManager.registerAuthenticationDelegate(delegate, realm: "")
        XCTAssertNil(mcaAuthManager.challengeHandlerForRealm(""))
        mcaAuthManager.unregisterAuthenticationDelegate("")
        XCTAssertNotNil(mcaAuthManager.registerAuthenticationDelegate(delegate, realm: realm))
        XCTAssertNotNil(mcaAuthManager.challengeHandlerForRealm(realm))
        mcaAuthManager.unregisterAuthenticationDelegate(realm)
        XCTAssertNil(mcaAuthManager.challengeHandlerForRealm(realm))
    }
    
    func testGetIdentities(){
        mcaAuthManager.preferences.appIdentity.set(["item1app" : "one" , "item2app" : "two"])
        var appId =  (mcaAuthManager.appIdentity as? MCAAppIdentity)?.jsonData
        XCTAssertEqual(appId?["item1app"], "one")
        XCTAssertEqual(appId?["item2app"], "two")
        mcaAuthManager.preferences.deviceIdentity.set(["item1device" : "one" , "item2device" : "two"])
        var deviceId = (mcaAuthManager.deviceIdentity as? MCADeviceIdentity)?.jsonData
        XCTAssertEqual(deviceId?["item1device"], "one")
        XCTAssertEqual(deviceId?["item2device"], "two")
        mcaAuthManager.preferences.userIdentity.set(["item1user" : "one" , "item2user" : "two"])
        var userId = (mcaAuthManager.userIdentity as? MCAUserIdentity)?.jsonData
        XCTAssertEqual(userId?["item1user"], "one")
        XCTAssertEqual(userId?["item2user"], "two")
    }
    
    class MockAuthorizationManagerPreference: AuthorizationManagerPreferences {
        
        override init(){
            super.init()
            persistencePolicy = MockPolicyPreference()
            idToken = MockTokenPreference()
            idToken.persistencePolicy = persistencePolicy
            accessToken = MockTokenPreference()
            accessToken.persistencePolicy = persistencePolicy
            clientId = MockStringPreference()
            userIdentity = MockJSONPreference()
            appIdentity = MockJSONPreference()
            deviceIdentity = MockJSONPreference()
        }
        class MockPolicyPreference : PolicyPreference{
            var mockValue:PersistencePolicy
            init() {
                self.mockValue = PersistencePolicy.ALWAYS
                super.init(prefName: "", defaultValue: PersistencePolicy.ALWAYS, idToken: nil, accessToken: nil)
            }
            override func set(_ value: PersistencePolicy, shouldUpdateTokens:Bool) {
                self.mockValue = value
            }
            override func get() -> PersistencePolicy {
                return self.mockValue
            }
        }
        class MockTokenPreference : TokenPreference {
            var mockValue:String? = nil
            init()
            {
                super.init(prefName: "", persistencePolicy: MockPolicyPreference())
            }
            override func set(_ value: String) {
                self.mockValue = value
            }
            override func get() -> String? {
                return self.mockValue
            }
            override func clear() {
                mockValue = nil
            }
        }
        class MockStringPreference : StringPreference {
            var mockValue:String? = nil
            init()
            {
                super.init(prefName: "", defaultValue: nil)
            }
            override func set(_ value: String?) {
                self.mockValue = value
            }
            override func get() -> String? {
                return self.mockValue
            }
            override func clear() {
                mockValue = nil
            }
        }
        class MockJSONPreference: JSONPreference {
            var mockValue:String? = nil
            init()
            {
                super.init(prefName: "")
            }
            override func set(_ value: String?) {
                self.mockValue = value
            }
            override func get() -> String? {
                return self.mockValue
            }
            override func clear() {
                mockValue = nil
            }
            
        }
    }
}
