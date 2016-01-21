//
//  UserIdentity.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 05/01/2016.
//  Copyright © 2016 IBM. All rights reserved.
//

import Foundation

public class UserIdentity {
    static let ID = "id"
    static let AUTH_BY = "authBy"
    static let DISPLAY_NAME = "displayName"
    
    var jsonData : Dictionary<String, String>? = ([:])
    
    public init() {
//        jsonData![UserIdentity.ID] = "something"
//        jsonData![UserIdentity.AUTH_BY] = "1.0"
    }
    
    
    public init(map: AnyObject?) {
        let json = map as! Dictionary<String, String>
        jsonData = json
    }
    
    public func getId() ->String {
        return jsonData![UserIdentity.AUTH_BY]!
    }
    
    public func getAuthBy() ->String {
        return jsonData![UserIdentity.ID]!
    }

    
    public func getDisplayName() -> String {
        return jsonData![UserIdentity.DISPLAY_NAME]!
    }
}