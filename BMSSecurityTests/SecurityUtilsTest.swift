//
//  SecurityUtilsTest.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 2/28/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import XCTest
@testable import BMSCore
@testable import BMSSecurity
class SecurityUtilsTest: XCTestCase {
    var keySize = 512
    var publicKeyTag = "publicKeyTag"
    var privateKeyTag = "privateKeyTag"
    var certificateString:String = "MIICnjCCAYagAwIBAgIIO6P5aUib0kMwDQYJKoZIhvcNAQELBQAwYDELMAkGA1UEBhMCSUwxCzAJBgNVBAgTAklMMREwDwYDVQQHEwhTaGVmYXlpbTEMMAoGA1UEChMDSUJNMRIwEAYDVQQLEwlXb3JrbGlnaHQxDzANBgNVBAMTBldMIERldjAgFw0xNjAyMjkwNzIzNDRaGA8yMDY2MDIyODA3MjM0NFowgYMxRzBFBgoJkiaJk/IsZAEZFjdjb20uaWJtLm1vYmlsZWZpcnN0cGxhdGZvcm0uY2xpZW50c2RrLnN3aWZ0LkJNU1NlY3VyaXR5MTgwNgYKCZImiZPyLGQBARMoMWFlMTU5NGRhZmZhZDAxNmNmNjI4ZGNlMTNiY2FkOWJjNjQ0YTg5NjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCxTP8b5V73Tyuiw8oVCCnIba+7A+uQFvr7lcxaliBQxanrZwVFoGT2oVNSOCs4W8air3X1jbPr6eaq4vzvpmdzAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAAwjt5nojlO/pqIlMfo2HxMqn1rr56xVae2i1REX5WbqbBbR9YcLxQZlsKk5T2A/zoTe0ztalYhfCSq8eV1CNFNKWvdDu6NfJoeGnX2zi0aTevzY4lDqkUJxlFQuhD5plvXEdsR56wKFYDYHnHhcKIKJdVzBr0VOsgBYdOBEJM5HSw+/AoYHBG8Ls+H4oMmtWTSEIbcqFGeoIpJ/4FurgD8JPWWnBRVmFnb27yHoKowWdJRtQ989BzNMdvNdydJ2/JijTGM4HME1F7nJCeF4Zb//ORC8ZqGPMDhXgwcoPhVc4L1srdCnZHQDgycdyjFZaBq9PQT/E7+f0VRSygPZei0="

    var publicKeyData:NSData = NSData(base64EncodedString: "MEgCQQCxTP8b5V73Tyuiw8oVCCnIba+7A+uQFvr7lcxaliBQxanrZwVFoGT2oVNSOCs4W8air3X1jbPr6eaq4vzvpmdzAgMBAAE=", options: NSDataBase64DecodingOptions(rawValue:0))!
    var privateKeyData:NSData = NSData(base64EncodedString: "MIIBOgIBAAJBALFM/xvlXvdPK6LDyhUIKchtr7sD65AW+vuVzFqWIFDFqetnBUWgZPahU1I4KzhbxqKvdfWNs+vp5qri/O+mZ3MCAwEAAQJAK8JUKF9pG+LHY0mtY5l7LoOb3q1uA0cYtOVY5XauDSDtb6JBIZxiPv9g0p/4xdnojM3H3ESS3g+Ghb7b3DUAQQIhAY7tipZoTC1yf+0bq96k5rKGJ/26GWNtnVQfTAvdBUTTAiBxxwaZgR0D0ch8k5Dh8/mLFjWB6uN6+oCaHz+deV0u4QIhAMcaDXI2Cdcg73Iivmv3t2BgjrMW37b9LWmf2S+OlyObAiBqmbnSOwlPWc9JAQ1+1pLYwN8zMTsfLvMs89grl9k5oQIhARGafPHuF877M4NTEQN2Q1zJOJKgsXhhmeSbg9UPRnFR", options: NSDataBase64DecodingOptions(rawValue:0))!
    var savedPublicKeyTag = "savedPublicKeyTag"
    var savedPrivateKeyTag = "savedPrivateKeyTag"
    var jws = "eyJqcGsiOnsibW9kIjoiQUxhdVpoKzlLa0tzYlVcL0l4YXcrRm9KXC8xS05ISlwvVDBKZllwVmpleElQc1B3UmkxU3pYXC9ENTJsWTFDeUR2NVBjVjltMXZlbVNNeDVlVWpjQ2RKcldUVT0iLCJhbGciOiJSU0EiLCJleHAiOiJBUUFCIn0sImFsZyI6IlJTMjU2In0=.eyJjb2RlIjoiZEVUMHhsZG9SM0d0X183TWpYaEJtd1VvNU9uVGdBbUpobHdneDFoS2Y5ZFljNGdBNVJ5R2RqNXpGLWZUdU92S0tjQ2ZuZ1UyV2pIaFRFMTF4UnVhN1BTaThtMTlXNTZMQmkwc3V3R0JtZWpwRDRPbmJ1aUprSWZRdUhEOHRkTVR5cU9jcGNuWWpHUl8xLXpSQ1UtbEtpd3RQN0hBTVZYNHVRRGw4WVh4aGxGRHFsVUFhQ3FIb0N4YVhvTmFudk1OIn0=.qdLfP4JWYbDtr47wvgmJUUc_ikD_Jm7PuxF71JOr9dxF3cFCK8aQ5zksrlzqH6QO37lCB1pANjim80N1i_klRw=="
    var grantCode = "xsrtdXylAoszdQsWloKwQi8sQByH2MpeR6MGQBcwmSXAwyk4dHtb-q6rNuZ06N4T9ea-iheoXo9tde6qsPEUF5EkNBU1OSQCMJ6sDuF_fH2mykCx50YwiU1X2egb3o-2o9bgUO9cBYVTyU90_xi4yDFsT39w5HA3Xo4_bL4xJJvgHVjLB6qicwFZwpKCY7W-"
    var certificateLabel = "certificateLabel"
    var itemLabel = "itemLabel"
    var itemData = "testItemString"
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    func testKeyPairGeneration() {
        
        
//        guard let _ =  try? SecurityUtils.generateKeyPair(keySize, publicTag: publicKeyTag, privateTag: privateKeyTag) else {
//            
//            XCTFail("Could not generate keyPair")
//            return
//        }
// 
        let publicKeyAttr : [NSString:AnyObject] = [
            kSecValueData: publicKeyData,
            kSecAttrIsPermanent : true,
            kSecAttrApplicationTag : savedPublicKeyTag,
            kSecAttrKeyClass : kSecAttrKeyClassPublic
            
        ]
        let addStatus:OSStatus = SecItemAdd(publicKeyAttr, nil)
        
        let privateKeyAttr : [NSString:AnyObject] = [
            kSecValueData: privateKeyData,
            kSecAttrIsPermanent : true,
            kSecAttrApplicationTag : savedPrivateKeyTag,
            kSecAttrKeyClass : kSecAttrKeyClassPrivate
            
        ]
        let addStatus2:OSStatus = SecItemAdd(privateKeyAttr, nil)
        

        
        
        guard let certificate = try? SecurityUtils.getCertificateFromString(certificateString) else {
            XCTFail("Could not generate certificate from string")
            return
        }
        //        guard let _ = try? SecurityUtils.checkCertificatePublicKeyValidity(certificate, publicKeyTag: publicKeyTag) else {
        //            XCTFail("Could not validate certificate with public key")
        //            return
        //        }
        guard let _ = try?  SecurityUtils.saveCertificateToKeyChain(certificate, certificateLabel: certificateLabel) else {
            XCTFail("Could not save certificate")
            return
        }
        guard let cert = try? SecurityUtils.getCertificateFromKeyChain(certificateLabel) else{
            XCTFail("certificate does not exist in keychain")
            return
        }
        XCTAssertEqual(try? SecurityUtils.signCsr(["code": grantCode], keyIds: (savedPublicKeyTag, savedPrivateKeyTag), keySize: keySize), jws)
        //        XCTAssertEqual(cert.debugDescription, certificate.debugDescription)
        //sign csr
        
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
        SecurityUtils.clearKeyChain()
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
}
