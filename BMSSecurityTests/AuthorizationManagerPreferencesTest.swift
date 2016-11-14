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
#if swift (>=3.0)
        SecItemDelete([ kSecClass as String : kSecClassGenericPassword ] as CFDictionary) //clears tokens from keychain
#else
        SecItemDelete([ kSecClass as String : kSecClassGenericPassword ]) //clears tokens from keychain
#endif
        super.setUp()
    }
    
    func testClientIdPreference() {
        preferences.clientId.set(clientId)
        XCTAssertEqual(preferences.clientId.get(),clientId)
        preferences.clientId.clear()
        XCTAssertNil(preferences.clientId.get())
    }
    
    func testIdentityPreferences() {
#if swift (>=3.0)
    preferences.appIdentity.set(MCAAppIdentity().jsonData as [String:Any])
        var appId = preferences.appIdentity.getAsMap()
        XCTAssertEqual(appId?[BaseAppIdentity.Key.ID] as? String, Utils.getApplicationDetails().name)
        XCTAssertEqual(appId?[BaseAppIdentity.Key.version] as? String, Utils.getApplicationDetails().version)
    preferences.deviceIdentity.set(MCADeviceIdentity().jsonData as [String:Any])
        var deviceId = preferences.deviceIdentity.getAsMap()
        XCTAssertEqual(deviceId?[BaseDeviceIdentity.Key.ID] as? String, UIDevice.current.identifierForVendor?.uuidString)
        XCTAssertEqual(deviceId?[BaseDeviceIdentity.Key.OS] as? String, UIDevice.current.systemName)
        XCTAssertEqual(deviceId?[BaseDeviceIdentity.Key.OSVersion] as? String, UIDevice.current.systemVersion)
        XCTAssertEqual(deviceId?[BaseDeviceIdentity.Key.model] as? String, UIDevice.current.model)
    preferences.userIdentity.set(["item1" : "one" as AnyObject , "item2" : "two" as AnyObject] as [String:Any])

#else
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

#endif
        var userId = preferences.userIdentity.getAsMap()
        XCTAssertEqual(userId?["item1"] as? String, "one")
        XCTAssertEqual(userId?["item2"] as? String, "two")
    }
    
    func testTokenPreferences(){
#if swift (>=3.0)
        preferences = AuthorizationManagerPreferences()
        preferences.persistencePolicy.set(PersistencePolicy.always, shouldUpdateTokens: true)
        preferences.accessToken.set(accessToken)
        preferences.idToken.set(idToken)
        assertTokens(true)
        preferences.persistencePolicy.set(PersistencePolicy.never, shouldUpdateTokens: true)
        assertTokens(false)
        preferences.persistencePolicy.set(PersistencePolicy.always, shouldUpdateTokens: true)
#else
        preferences = AuthorizationManagerPreferences()
        preferences.persistencePolicy.set(PersistencePolicy.ALWAYS, shouldUpdateTokens: true)
        preferences.accessToken.set(accessToken)
        preferences.idToken.set(idToken)
        assertTokens(true)
        preferences.persistencePolicy.set(PersistencePolicy.NEVER, shouldUpdateTokens: true)
        assertTokens(false)
        preferences.persistencePolicy.set(PersistencePolicy.ALWAYS, shouldUpdateTokens: true)
#endif
        assertTokens(true)
        preferences.idToken.clear()
        preferences.accessToken.clear()
        XCTAssertEqual(SecurityUtils.getItemFromKeyChain(preferences.idToken.prefName),nil)
        XCTAssertEqual(SecurityUtils.getItemFromKeyChain(preferences.accessToken.prefName),nil)
        XCTAssertNil(preferences.accessToken.get())
        XCTAssertNil(preferences.idToken.get())

    }
#if swift(>=3.0)
    private func assertTokens(_ TokensShouldExistInKeyChain:Bool) {
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
#else
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
#endif
}
