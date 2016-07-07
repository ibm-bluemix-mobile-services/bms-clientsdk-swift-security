//
//  AuthorizationManagerPreferencesTest.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 2/28/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import XCTest
import BMSCore
@testable import BMSSecurity

class AuthorizationManagerPreferencesTest: XCTestCase {
    var preferences:AuthorizationManagerPreferences = AuthorizationManagerPreferences()
    var idToken = "123"
    var accessToken = "456"
    var clientId = "id2"
    
    override func setUp() {
        preferences = AuthorizationManagerPreferences()
        SecItemDelete([ kSecClass as String : kSecClassGenericPassword ]) //clears tokens from keychain
        super.setUp()
    }
    
    func testClientIdPreference() {
        preferences.clientId.set(clientId)
        XCTAssertEqual(preferences.clientId.get(),clientId)
        preferences.clientId.clear()
        XCTAssertNil(preferences.clientId.get())
    }
    
    func testIdentityPreferences() {
        preferences.appIdentity.set(MCAAppIdentity().jsonData)
        var appId = preferences.appIdentity.getAsMap()
        XCTAssertEqual(appId?[BaseAppIdentity.ID] as? String, Utils.getApplicationDetails().name)
        XCTAssertEqual(appId?[BaseAppIdentity.VERSION] as? String, Utils.getApplicationDetails().version)
        preferences.deviceIdentity.set(MCADeviceIdentity().jsonData)
        var deviceId = preferences.deviceIdentity.getAsMap()
        XCTAssertEqual(deviceId?[BaseDeviceIdentity.ID] as? String, UIDevice.currentDevice().identifierForVendor?.UUIDString)
        XCTAssertEqual(deviceId?[BaseDeviceIdentity.OS] as? String, UIDevice.currentDevice().systemName)
        XCTAssertEqual(deviceId?[BaseDeviceIdentity.OS_VERSION] as? String, UIDevice.currentDevice().systemVersion)
        XCTAssertEqual(deviceId?[BaseDeviceIdentity.MODEL] as? String, UIDevice.currentDevice().model)
        preferences.userIdentity.set(["item1" : "one" , "item2" : "two"])
        var userId = preferences.userIdentity.getAsMap()
        XCTAssertEqual(userId?["item1"] as? String, "one")
        XCTAssertEqual(userId?["item2"] as? String, "two")
    }
    
    func testTokenPreferences(){
        preferences = AuthorizationManagerPreferences()
        preferences.persistencePolicy.set(PersistencePolicy.ALWAYS, shouldUpdateTokens: true)
        preferences.accessToken.set(accessToken)
        preferences.idToken.set(idToken)
        assertTokens(true)
        preferences.persistencePolicy.set(PersistencePolicy.NEVER, shouldUpdateTokens: true)
        assertTokens(false)
        preferences.persistencePolicy.set(PersistencePolicy.ALWAYS, shouldUpdateTokens: true)
        assertTokens(true)
        preferences.idToken.clear()
        preferences.accessToken.clear()
        XCTAssertEqual(SecurityUtils.getItemFromKeyChain(preferences.idToken.prefName),nil)
        XCTAssertEqual(SecurityUtils.getItemFromKeyChain(preferences.accessToken.prefName),nil)
        XCTAssertNil(preferences.accessToken.get())
        XCTAssertNil(preferences.idToken.get())
    }
    
    private func assertTokens(TokensShouldExistInKeyChain:Bool) {
        XCTAssertEqual(preferences.accessToken.get(),accessToken)
        XCTAssertEqual(preferences.idToken.get(),idToken)
        if TokensShouldExistInKeyChain {
            XCTAssertEqual(SecurityUtils.getItemFromKeyChain(preferences.idToken.prefName),idToken)
            XCTAssertEqual(SecurityUtils.getItemFromKeyChain(preferences.accessToken.prefName),accessToken)
        } else {
            XCTAssertNil(SecurityUtils.getItemFromKeyChain(preferences.idToken.prefName))
            XCTAssertNil(SecurityUtils.getItemFromKeyChain(preferences.accessToken.prefName))
        }
    }
}
