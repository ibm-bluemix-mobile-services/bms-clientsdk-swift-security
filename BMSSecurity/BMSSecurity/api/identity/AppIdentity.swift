//
//  AppIdentity.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 05/01/2016.
//  Copyright © 2016 IBM. All rights reserved.
//

import Foundation


public class AppIdentity{
    
    static let ID = "id";
    static let VERSION = "version";
    
    var jsonData : Dictionary<String, String>? = ([:])
    
    public init() {
        jsonData![AppIdentity.ID] = "something"
        jsonData![AppIdentity.VERSION] = "1.0"
    }
    
    
    public init(map: AnyObject?) {
        let json = map as! Dictionary<String, String>
        jsonData = json
    }
    
    public func getId() ->String {
        return jsonData![AppIdentity.ID]!
    }
    
    
    public func getVersion() -> String {
        return jsonData![AppIdentity.VERSION]!
    }
    
}
