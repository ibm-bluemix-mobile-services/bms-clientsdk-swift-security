//
//  AuthoirzationRequestTest.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 2/29/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import XCTest
import BMSCore
@testable import BMSSecurity

class AuthoirzationRequestTest: XCTestCase {
    var request = AuthorizationRequest(url: "www.test.com", method: HttpMethod.POST)
    override func setUp() {
        request = AuthorizationRequest(url: "www.test.com", method: HttpMethod.POST)
        super.setUp()
    }
    func testAddHeaders(){
        let headersToBeAdded = ["header1" : "item1" , "header2" : "item2", "header3" : "item3"]
        request.addHeaders(headersToBeAdded)
        XCTAssertEqual(request.headers["header1"], "item1")
        XCTAssertEqual(request.headers["header2"], "item2")
        XCTAssertEqual(request.headers["header3"], "item3")
        let headersToBeAdded2 = ["header4" : "item4" , "header5" : "item5", "header6" : "item6"]
        request.addHeaders(headersToBeAdded2)
        XCTAssertEqual(request.headers["header1"], "item1")
        XCTAssertEqual(request.headers["header2"], "item2")
        XCTAssertEqual(request.headers["header3"], "item3")
        XCTAssertEqual(request.headers["header4"], "item4")
        XCTAssertEqual(request.headers["header5"], "item5")
        XCTAssertEqual(request.headers["header6"], "item6")
    }
    
    func testSend(){
         class AuthorizationRequestMock : AuthorizationRequest {
            override func sendString(requestBody: String, completionHandler callback: BmsCompletionHandler?) {
                let cond = (requestBody == "param2=value2&param%3F1=value%3A1" || requestBody == "param%3F1=value%3A1&param2=value2")
                XCTAssertTrue(cond)
                XCTAssertNotNil(callback)
            }
            override func sendWithCompletionHandler(callback: BmsCompletionHandler?) {
               XCTAssertNotNil(callback)
            }
        }
        let callback = {(response: Response?, error: NSError?) in }
        let mock = AuthorizationRequestMock(url: "www.test.com", method: HttpMethod.POST)
        mock.sendWithCompletionHandler(["param?1" : "value:1", "param\n2" : "value\r2"], callback: callback)
        mock.send(callback)
    }

}
