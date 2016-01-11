//
//  WLConfig.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 11/01/2016.
//  Copyright © 2016 IBM. All rights reserved.
//

import Foundation

public class WLConfig {
    
    //Return the App Name and Version
    public static func getApplicationDetails() -> (name:String?, version:String?) {
        let version = NSBundle.mainBundle().infoDictionary?["CFBundleShortVersionString"] as? String
        let name = NSBundle(forClass:object_getClass(self)).bundleIdentifier
        return (name, version)
    }
}