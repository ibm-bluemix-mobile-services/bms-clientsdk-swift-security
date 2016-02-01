/*
*     Copyright 2015 IBM Corp.
*     Licensed under the Apache License, Version 2.0 (the "License");
*     you may not use this file except in compliance with the License.
*     You may obtain a copy of the License at
*     http://www.apache.org/licenses/LICENSE-2.0
*     Unless required by applicable law or agreed to in writing, software
*     distributed under the License is distributed on an "AS IS" BASIS,
*     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*     See the License for the specific language governing permissions and
*     limitations under the License.
*/

import Foundation
import BMSCore

public class Utils {
    
    private static let SECURE_PATTERN_START = "/*-secure-\n"
    private static let SECURE_PATTERN_END = "*/"
    
    private static let BLUEMIX_NAME = "bluemix"
    private static let BLUEMIX_DOMAIN = "bluemix.net"
    private static let STAGE1_NAME = "stage1"
    
    public static func concatenateUrls(rootUrl:String, path:String) -> String {
        if rootUrl.isEmpty {
            return path
        }
     
        var final = rootUrl
        if !final.hasSuffix("/") {
            final += "/"
        }
        
        if path.hasPrefix("/") {            
            final += path.substringWithRange(Range<String.Index>(start: path.startIndex.advancedBy(1), end: path.endIndex))
        } else {
            final += path
        }
        
        return final
    }
    
    public static func getParameterValueFromQuery(query:String?, paramName:String) -> String? {
        guard let myQuery = query  else {
            return nil
        }
        
        let paramaters = myQuery.componentsSeparatedByString("&")
        
        for val in paramaters {
            let pairs = val.componentsSeparatedByString("=")
//            print (pairs.endIndex)
            
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
                
//                print("error")
                //Access error here
            }
            
        }
        return ""
    }
    
    public static func parseJsonStringtoDictionary(jsonString:String) ->[String:AnyObject]? {
        do {
            if let data = jsonString.dataUsingEncoding(NSUTF8StringEncoding), responseJson =  try NSJSONSerialization.JSONObjectWithData(data, options: []) as? [String:AnyObject]{
                return responseJson as [String:AnyObject]
            }
        } catch {
            return nil
        }
        
        return nil
    }
        
    /**
     <#Description#>
     
     - parameter response: <#response description#>
     
     - returns: <#return value description#>
     */
    public static func extractSecureJson(response: Response?) -> [String:AnyObject?]? {
        
        guard let responseText:String = response?.responseText else {
            return nil
        }
        
        guard responseText.hasPrefix(SECURE_PATTERN_START) && responseText.hasSuffix(SECURE_PATTERN_END) else {
            return nil
        }
        
        var jsonString : String = responseText.substringWithRange(Range<String.Index>(start: responseText.startIndex.advancedBy(Utils.SECURE_PATTERN_START.characters.count), end: responseText.endIndex.advancedBy(-Utils.SECURE_PATTERN_END.characters.count)))
        
        do {
        
            if let data = jsonString.dataUsingEncoding(NSUTF8StringEncoding), responseJson =  try NSJSONSerialization.JSONObjectWithData(data, options: []) as? [String:AnyObject]{
                return responseJson
            }
        } catch {
            return nil
        }
       
        return nil
    }
    
    //Return the App Name and Version
    public static func getApplicationDetails() -> (name:String?, version:String?) {
        let version = NSBundle.mainBundle().infoDictionary?["CFBundleShortVersionString"] as? String
        let name = NSBundle(forClass:object_getClass(self)).bundleIdentifier
        return (name, version)
    }
    
    public static func parseDictionaryToJson(dict: [String:AnyObject]? ) -> String?{
        if let myDict = dict{
            do{
                let jsonData:NSData =  try NSJSONSerialization.dataWithJSONObject(myDict, options: [])
                return String(data: jsonData, encoding:NSUTF8StringEncoding)
            } catch {
                return nil
            }
        }
        return nil
    }
}