//
//  DeviceIdentity.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 05/01/2016.
//  Copyright © 2016 IBM. All rights reserved.
//

import Foundation

public class DeviceIdentity{
    
    static let ID = "id";
    static let OS = "platform";
    static let MODEL = "model";
    
    var jsonData : Dictionary<String, String>? = ([:])
    
    public init() {
        jsonData![DeviceIdentity.ID] = "something"
        jsonData![DeviceIdentity.OS] = "1.0"
        jsonData![DeviceIdentity.MODEL] = "1.0"
    }
    
    public init(map: AnyObject?) {
        let json = map as! Dictionary<String, String>
        jsonData = json
    }
    
    public func getId() ->String {
        return jsonData![DeviceIdentity.ID]!
    }
    
    public func getOS() -> String {
        return jsonData![DeviceIdentity.OS]!
    }
    
    public func getModel() -> String {
        return jsonData![DeviceIdentity.MODEL]!
    }
}