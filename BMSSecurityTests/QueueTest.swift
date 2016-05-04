//
//  QueueTest.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 2/28/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import XCTest
import BMSCore
@testable import BMSSecurity

class QueueTest: XCTestCase {
    var queue = Queue<String>()
    override func setUp() {
        super.setUp()
    }
    
    func testQueueMethods(){
        XCTAssertTrue(queue.isEmpty())
        queue.add("item1")
        XCTAssertFalse(queue.isEmpty())
        queue.add("item2")
        queue.add("item3")
        XCTAssertEqual(queue.size, 3)
        XCTAssertEqual(queue.element(),"item1")
        XCTAssertEqual(queue.size, 3)
        XCTAssertEqual(queue.remove(),"item1")
        XCTAssertEqual(queue.size, 2)
        XCTAssertEqual(queue.element(),"item2")
    }
    
    override func tearDown() {
        super.tearDown()
    }
}
