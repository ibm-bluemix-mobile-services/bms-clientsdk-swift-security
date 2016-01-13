//
//  Utils.swift
//  BMSCore
//
//  Created by Ilan Klein on 03/01/2016.
//  Copyright © 2016 IBM. All rights reserved.
//

import Foundation
import BMSCore

public class Utils {
    
    private static let SECURE_PATTERN_START = "/*-secure-\n"
    private static let SECURE_PATTERN_END = "*/"
    
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
    
    public static func getParameterValueFromQuery(query:String?, paramName:String) -> String? {
        guard let query = query else {
            return nil
        }
        
        let paramaters = query.componentsSeparatedByString("&")
        
        for val in paramaters {
            let pairs = val.componentsSeparatedByString("=")
            print (pairs.endIndex)
            
            if (pairs.endIndex != 2) {
                continue
            }
            if let normal = pairs[0].stringByRemovingPercentEncoding where normal == paramName {
                return pairs[1].stringByRemovingPercentEncoding
            }
        }
        return nil
    }
    
    public static func JSONStringify(value: AnyObject, prettyPrinted:Bool = false) -> String{
        
        let options = prettyPrinted ? NSJSONWritingOptions.PrettyPrinted : NSJSONWritingOptions(rawValue: 0)
        
        
        if NSJSONSerialization.isValidJSONObject(value) {
            
            do{
                let data = try NSJSONSerialization.dataWithJSONObject(value, options: options)
                if let string = NSString(data: data, encoding: NSUTF8StringEncoding) {
                    return string as String
                }
            }catch {
                
                print("error")
                //Access error here
            }
            
        }
        return ""
    }
    
    
    public static func extractSecureJson(response: Response?) -> [String:AnyObject?]? {
        
        guard let responseText:String = response?.responseText else {
            return nil
        }
        
//        guard reponseText.hasPrefix(SECURE_PATTERN_START) && reponseText.hasSuffix(SECURE_PATTERN_END) else {
//            return nil
//        }
//        
//        let startIndex = responseText
//        guard responseText
//        
//        response
        return nil
    }
}