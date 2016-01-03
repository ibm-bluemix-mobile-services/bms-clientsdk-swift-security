//
//  Utils.swift
//  BMSCore
//
//  Created by Ilan Klein on 03/01/2016.
//  Copyright © 2016 IBM. All rights reserved.
//

import Foundation

public class Utils {
    
    public static func concatenateUrls(rootUrl:String, path:String) -> String {
        if rootUrl.isEmpty {
            return path
        }
     
        var final = rootUrl
        if !final.hasSuffix("/") {
            final += "/"
        }
        
        if path.hasPrefix("/") {            
            final += path.substringWithRange(Range<String.Index>(start: path.startIndex, end: path.endIndex.advancedBy(-1)))
        } else {
            final += path
        }
        
        return final
    }

}