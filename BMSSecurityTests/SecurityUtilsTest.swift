//
//  SecurityUtilsTest.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 2/28/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import XCTest
import BMSCore
@testable import BMSSecurity
class SecurityUtilsTest: XCTestCase {
    var keySize = 512
    var publicKeyTag = "publicKeyTag"
    var privateKeyTag = "privateKeyTag"
    var certificateString:String = "MIICnzCCAYegAwIBAgIJALdVcgacYBpvMA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAklMMQswCQYDVQQIEwJJTDERMA8GA1UEBxMIU2hlZmF5aW0xDDAKBgNVBAoTA0lCTTESMBAGA1UECxMJV29ya2xpZ2h0MQ8wDQYDVQQDEwZXTCBEZXYwIBcNMTYwMzAxMTAwMzA1WhgPMjA2NjAzMDExMDAzMDVaMIGDMUcwRQYKCZImiZPyLGQBGRY3Y29tLmlibS5tb2JpbGVmaXJzdHBsYXRmb3JtLmNsaWVudHNkay5zd2lmdC5CTVNTZWN1cml0eTE4MDYGCgmSJomT8ixkAQETKDgwMDc1MTY0MjBhYWYzM2NjNjNhZmZjOWY5ZWRmMzY5ODJjNzI2OWUwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA4f6cAJTdwKikDPr9LMm4O1TI3iceGeT3J8X0MWIY9y1c9vAxeh9m931ZxhCq3D7DdZX/KG6L0+s5V9UGGToKYwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQB7Cp+tCSxT0dr7quLsxchKiDIG2r9J+6vja/vW7YIrYMvL4aeFMraJCVSqSBcEwMQjEdDguW+ulZfcRJHDX2yqrXxU13s5UMTsukb2ARmf7wAG5sk+ZJLtPlWK0c4ZHerbuXCaqUq8v1b2LncOwcFZBMLDd6NKCPkBsmxCtXB02zhw9Y7KutkFJKBwkRlmf6SJTHSd13dSd6Pve/Xt+S7MlUoWuuMc7xec9RySkAd2610txOkiYH5Sv25h7TxfGZ3P3lCx7qWN4x74D4Np/CrhscB4+BahRcxJd1opAphI0SXRUX3YGJ10vuHbJlZ13byHCeMgv8IAzN19LsDXSHKW"
    
    var publicKeyData:NSData = NSData(base64EncodedString: "MEgCQQDh/pwAlN3AqKQM+v0sybg7VMjeJx4Z5PcnxfQxYhj3LVz28DF6H2b3fVnGEKrcPsN1lf8obovT6zlX1QYZOgpjAgMBAAE=", options: NSDataBase64DecodingOptions(rawValue:0))!
    var privateKeyData:NSData = NSData(base64EncodedString: "MIIBOgIBAAJBAOH+nACU3cCopAz6/SzJuDtUyN4nHhnk9yfF9DFiGPctXPbwMXofZvd9WcYQqtw+w3WV/yhui9PrOVfVBhk6CmMCAwEAAQJAJ4H8QbnEnoacz0wdcHP/ShgDWZrbD0nQz1oy22M73BHidwDvy1rIeM6PgkK1tyHNWrqyo1kAnp7DuNVmfGbJ0QIhAc3gVBJCrVbiO23OasUuYTN2y2KrZ2DUcjLp5ZOID1/LAiB9Qo1mx3yz4HT4wJvddb9AqSTlmSrrdXcNGNhWFRT8yQIhAbepkD3lrL2lEy8+q9JRiQOFVKvzP7Aj6yVeE0Sx4virAiAk2ITbrOajyuzdl1rCBDbkAF1YJHwZkw4YDizk9YKc8QIhAV0VZFoZidVBTsoi7xeufS0GSDqPxskq7gJGY70p4dco", options: NSDataBase64DecodingOptions(rawValue:0))!
    var jws = "eyJhbGciOiJSUzI1NiIsImpwayI6eyJhbGciOiJSU0EiLCJtb2QiOiJBT0grbkFDVTNjQ29wQXo2XC9Tekp1RHRVeU40bkhobms5eWZGOURGaUdQY3RYUGJ3TVhvZlp2ZDlXY1lRcXR3K3czV1ZcL3lodWk5UHJPVmZWQmhrNkNtTT0iLCJleHAiOiJBUUFCIn19.eyJjb2RlIjoiNTBzcWthZER6bTl6TjdFTEpDWXR1bnlLb3Raa1Y3SEJKdFBMSHJmZzAzY2Qtbk5JOEhnU1VicnpoNmJpa2ZLYl9MeVUwQU54UGkyWDA4OUNqV0syT3RDR3djRHJ2RjNlcEM5WFFHMXlwTlVMZHo4c2dWZWVmYkxob2JsZ2ltZ2JwN3M1X0dLSllWWmVGZ2JpbnFlWWhmMXpudEZOdHA0dVhsNmVaX1h1aTMwZ2VwTEEyT2pUcUhnM1VadV9xRVk0In0=.FqJBhAX1-4auIchN6Gk_1laA4zCS_Fpy1tRwa6Oeklv2ungnnSKL2VRuzRIwzAjyAhfyOSnlsOqL5r7K-RhF-Q=="
    var certificateLabel = "certificateLabel"
    var itemLabel = "itemLabel"
    var itemData = "testItemString"
    var grantCode = "50sqkadDzm9zN7ELJCYtunyKotZkV7HBJtPLHrfg03cd-nNI8HgSUbrzh6bikfKb_LyU0ANxPi2X089CjWK2OtCGwcDrvF3epC9XQG1ypNULdz8sgVeefbLhoblgimgbp7s5_GKJYVZeFgbinqeYhf1zntFNtp4uXl6eZ_Xui30gepLA2OjTqHg3UZu_qEY4"
    override func setUp() {
        super.setUp()
        SecurityUtils.clearDictValuesFromKeyChain([certificateLabel : kSecClassCertificate, publicKeyTag : kSecClassKey, privateKeyTag : kSecClassKey])
        savePublicKeyDataToKeyChain(publicKeyData, tag: publicKeyTag)
        savePrivateKeyDataToKeyChain(privateKeyData, tag: privateKeyTag)
    }
    
    
    func testKeyPairGeneration() {
        SecurityUtils.clearDictValuesFromKeyChain([publicKeyTag : kSecClassKey, privateKeyTag : kSecClassKey])
        XCTAssertNotNil(try? SecurityUtils.generateKeyPair(keySize, publicTag: publicKeyTag, privateTag: privateKeyTag))
    }
    
    func testGetCertificateFromString(){
        XCTAssertNotNil(try? SecurityUtils.getCertificateFromString(certificateString))
        //compare certificate
    }
    
    func testCheckCertificatePublicKeyValidity(){
        let certPublicKeyValidity = try? SecurityUtils.checkCertificatePublicKeyValidity(try! SecurityUtils.getCertificateFromString(certificateString), publicKeyTag: publicKeyTag)
        XCTAssertNotNil(certPublicKeyValidity)
        XCTAssertTrue(certPublicKeyValidity!)
    }
    func testSaveAndGetCertificateFromKeyChain(){
        XCTAssertNotNil(try? SecurityUtils.saveCertificateToKeyChain(try! SecurityUtils.getCertificateFromString(certificateString), certificateLabel: certificateLabel))
        XCTAssertNotNil(try? SecurityUtils.getCertificateFromKeyChain(certificateLabel))
    }
    
    func testSignCsr(){
        XCTAssertNotNil(try? SecurityUtils.saveCertificateToKeyChain(try! SecurityUtils.getCertificateFromString(certificateString), certificateLabel: certificateLabel))
        XCTAssertEqual(try? SecurityUtils.signCsr(["code": grantCode], keyIds: (publicKeyTag, privateKeyTag), keySize: keySize), jws)
    }
    func testDeleteCertificateFromKeyChain(){
        SecurityUtils.deleteCertificateFromKeyChain(certificateLabel)
        XCTAssertNil(try? SecurityUtils.getCertificateFromKeyChain(certificateLabel))
    }
    
    func testSaveItemToKeyChain(){
        SecurityUtils.saveItemToKeyChain(itemData, label: itemLabel)
        XCTAssertEqual(SecurityUtils.getItemFromKeyChain(itemLabel), itemData)
        SecurityUtils.removeItemFromKeyChain(itemLabel)
        XCTAssertNil(SecurityUtils.getItemFromKeyChain(itemLabel))
    }
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    private func savePublicKeyDataToKeyChain(key:NSData,tag:String) {
        let publicKeyAttr : [NSString:AnyObject] = [
            kSecValueData: key,
            kSecClass : kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyType : kSecAttrKeyTypeRSA,
            kSecAttrKeyClass : kSecAttrKeyClassPublic
            
        ]
        SecItemAdd(publicKeyAttr, nil)
    }
    
    private func savePrivateKeyDataToKeyChain(key:NSData,tag:String) {
        let publicKeyAttr : [NSString:AnyObject] = [
            kSecValueData: key,
            kSecClass : kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyType : kSecAttrKeyTypeRSA,
            kSecAttrKeyClass : kSecAttrKeyClassPrivate
            
        ]
        SecItemAdd(publicKeyAttr, nil)
    }
    
    
}
