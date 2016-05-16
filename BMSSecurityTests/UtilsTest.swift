//
//  UtilsTest.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 2/28/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import XCTest
import BMSCore
@testable import BMSSecurity
class UtilsTest: XCTestCase {
    
    func testInsensitiveDictionary(){
        var dict = ["a":"1", "b":"2", "C":"3"]
        XCTAssertNil(dict["c"])
        XCTAssertEqual(dict[caseInsensitive: "c"], "3")
    }
    
    func testConcatenateUrls() {
        XCTAssertEqual(Utils.concatenateUrls("", path: "testPath"), "testPath")
        XCTAssertEqual(Utils.concatenateUrls("http://unitTestSwiftSDK.com/", path: "/testPath"), "http://unitTestSwiftSDK.com/testPath")
        XCTAssertEqual(Utils.concatenateUrls("http://unitTestSwiftSDK.com", path: "/testPath"), "http://unitTestSwiftSDK.com/testPath")
        XCTAssertEqual(Utils.concatenateUrls("http://unitTestSwiftSDK.com", path: "testPath"), "http://unitTestSwiftSDK.com/testPath")
        XCTAssertEqual(Utils.concatenateUrls("http://unitTestSwiftSDK.com/", path: "testPath"), "http://unitTestSwiftSDK.com/testPath")
    }
    
    func testGetParameterValueFromQuery() {
        XCTAssertNil(Utils.getParameterValueFromQuery(nil, paramName: "testParam", caseSensitive: false))
        XCTAssertEqual(Utils.getParameterValueFromQuery("param1=8&param2=10&param3=11", paramName: "param2", caseSensitive: false),"10")
        XCTAssertEqual(Utils.getParameterValueFromQuery("param1=8&param2=10&param3=11", paramName: "PaRam3", caseSensitive: false),"11")
        XCTAssertNil(Utils.getParameterValueFromQuery("param1=8&param2=10&param3=11", paramName: "PaRam2", caseSensitive: true))
    }
    
    func testJSONStringify() {
        let dict:[String:AnyObject] = ["first":true,"second":3, "third" : ["item1","item2",["item3","item4"],"item5"]]
        let jsonStringOption1 = "{\"first\":true,\"second\":3,\"third\":[\"item1\",\"item2\",[\"item3\",\"item4\"],\"item5\"]}"
        let jsonStringOption2 = "{\"first\":true,\"third\":[\"item1\",\"item2\",[\"item3\",\"item4\"],\"item5\"],\"second\":3}"
        let jsonStringOption3 = "{\"third\":[\"item1\",\"item2\",[\"item3\",\"item4\"],\"item5\"],\"first\":true,\"second\":3}"
        let jsonStringOption4 = "{\"second\":3,\"third\":[\"item1\",\"item2\",[\"item3\",\"item4\"],\"item5\"],\"first\":true}"
        let jsonStringOption5 = "{\"second\":3,\"first\":true,\"third\":[\"item1\",\"item2\",[\"item3\",\"item4\"],\"item5\"]}"
        let jsonStringOption6 = "{\"third\":[\"item1\",\"item2\",[\"item3\",\"item4\"],\"item5\"],\"second\":3,\"first\":true}"
        let json = try? Utils.JSONStringify(dict)
        let cond = (jsonStringOption1 == json || jsonStringOption2 == json || jsonStringOption3 == json || jsonStringOption4 == json || jsonStringOption5 == json || jsonStringOption6 == json)
        XCTAssertTrue(cond)
    }
    
    func testParseJsonStringtoDictionary() {
        let jsonString = "{\"first\":true,\"second\":3,\"third\":[\"item1\",\"item2\",[\"item3\",\"item4\"],\"item5\"]}"
        let returnedDict:[String:AnyObject]? = try? Utils.parseJsonStringtoDictionary(jsonString)
        XCTAssertNotNil(returnedDict)
        XCTAssertEqual(returnedDict!["first"] as? Bool, true)
        XCTAssertEqual(returnedDict!["second"] as? Int, 3)
        XCTAssertEqual((returnedDict!["third"] as? Array)!, ["item1","item2",["item3","item4"],"item5"])
    }
    private func stringToBase64Data(str:String) -> NSData {
        let utf8str = str.dataUsingEncoding(NSUTF8StringEncoding)
        let base64EncodedStr = utf8str?.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        return NSData(base64EncodedString: base64EncodedStr!, options: NSDataBase64DecodingOptions(rawValue: 0))!
    }
    func testExtractSecureJson() {
        let json = "{\"challenges\":{\"customAuthRealm_1\":{\"message\":\"wrong_credentials\"}}}"
        let response1:Response = Response(responseData: stringToBase64Data(json), httpResponse: nil, isRedirect: false)
        XCTAssertNil(try? Utils.extractSecureJson(response1))
        let response2:Response = Response(responseData: stringToBase64Data("/*-secure-\n\(json)"), httpResponse: nil, isRedirect: false)
        XCTAssertNil(try? Utils.extractSecureJson(response2))
        let response3:Response = Response(responseData: stringToBase64Data("\(json)*/"), httpResponse: nil, isRedirect: false)
        XCTAssertNil(try? Utils.extractSecureJson(response3))
        let response4:Response = Response(responseData: stringToBase64Data("/*-secure-\n\(json)*/"), httpResponse: nil, isRedirect: false)
        var dict = try? Utils.extractSecureJson(response4)
        print(dict!["challenges"]!!)
        XCTAssertEqual((dict?["challenges"] as? NSDictionary)!,["customAuthRealm_1" : ["message":"wrong_credentials"]])
    }
    
    func testGetApplicationDetails() {
        let appInfo = Utils.getApplicationDetails()
        XCTAssertNotNil(appInfo.name)
        XCTAssertNotNil(appInfo.version)
    }
    func testGetDeviceDictionary() {
        let deviceIdentity = MCADeviceIdentity()
        let appIdentity = MCAAppIdentity()
        var dictionary = Utils.getDeviceDictionary()
        XCTAssertEqual(dictionary[BMSSecurityConstants.JSON_DEVICE_ID_KEY] as? String, deviceIdentity.id)
        XCTAssertEqual(dictionary[BMSSecurityConstants.JSON_MODEL_KEY] as? String, deviceIdentity.model)
        XCTAssertEqual(dictionary[BMSSecurityConstants.JSON_OS_KEY] as? String, deviceIdentity.OS)
        XCTAssertEqual(dictionary[BMSSecurityConstants.JSON_APPLICATION_ID_KEY] as? String, appIdentity.id)
        XCTAssertEqual(dictionary[BMSSecurityConstants.JSON_APPLICATION_VERSION_KEY] as? String, appIdentity.version)
        XCTAssertEqual(dictionary[BMSSecurityConstants.JSON_ENVIRONMENT_KEY] as? String, BMSSecurityConstants.JSON_IOS_ENVIRONMENT_VALUE)
    }
    func testDecodeBase64WithString(){
        let str = "VGhpcyBpcyBhIFV0aWxzIHVuaXRUZXN0IHR+c/Q="
        let strSafe = "VGhpcyBpcyBhIFV0aWxzIHVuaXRUZXN0IHR-c_Q="
        guard let data = Utils.decodeBase64WithString(str) else {
            XCTFail("failed to decode a base64 string")
            return
        }
        XCTAssertEqual(Utils.base64StringFromData(data, isSafeUrl: false),str)
        XCTAssertEqual(Utils.base64StringFromData(data, isSafeUrl: true),strSafe)
    }
    
}
