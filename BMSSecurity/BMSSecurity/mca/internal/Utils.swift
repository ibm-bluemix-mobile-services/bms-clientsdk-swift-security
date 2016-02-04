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
    
    private static let  base64EncodingTable:[Character] = [
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
        "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f",
        "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
        "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/"
    ]
    
    private static let base64EncodingTableUrlSafe:[Character] = [
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
        "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f",
        "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
        "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "-", "_"
    ]
    
    
    private static let _base64DecodingTable: [Int8] = [
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -1, -1, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
        -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
        -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
    ]

    
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
        
        let jsonString : String = responseText.substringWithRange(Range<String.Index>(start: responseText.startIndex.advancedBy(Utils.SECURE_PATTERN_START.characters.count), end: responseText.endIndex.advancedBy(-Utils.SECURE_PATTERN_END.characters.count)))
        
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
    /**
     Decode base64 code
     
     - parameter strBase64: strBase64 the String to decode
     
     - returns: return decoded String
     */
    public static func decodeBase64WithString(strBase64:String) -> NSData? {
        
        guard let objPointerHelper = strBase64.cStringUsingEncoding(NSASCIIStringEncoding), objPointer = String(UTF8String: objPointerHelper) else {
            return nil
        }
        
        let intLengthFixed:Int = (objPointer.characters.count)
        var result:[Int8] = [Int8](count: intLengthFixed, repeatedValue : 1)
        
        var i:Int=0, j:Int=0, k:Int
        var count = 0
        var intLengthMutated:Int = (objPointer.characters.count)
        var current:Character
        
        for current = objPointer[objPointer.startIndex.advancedBy(count++)] ; current != "\0" && intLengthMutated-- > 0 ; current = objPointer[objPointer.startIndex.advancedBy(count++)]  {
            
            if current == "=" {
                if  count < intLengthFixed && objPointer[objPointer.startIndex.advancedBy(count)] != "=" && i%4 == 1 {
                    
                    return nil
                }
                if count == intLengthFixed {
                    break
                }
                
                continue
            }
            let stringCurrent = String(current)
            let singleValueArrayCurrent: [UInt8] = Array(stringCurrent.utf8)
            let intCurrent:Int = Int(singleValueArrayCurrent[0])
            let int8Current = _base64DecodingTable[intCurrent]
            
            if int8Current == -1 {
                continue
            } else if int8Current == -2 {
                return nil
            }
            
            switch (i % 4) {
            case 0:
                result[j] = int8Current << 2
            case 1:
                result[j++] |= int8Current >> 4
                result[j] = (int8Current & 0x0f) << 4
            case 2:
                result[j++] |= int8Current >> 2
                result[j] = (int8Current & 0x03) << 6
            case 3:
                result[j++] |= int8Current
            default:  break
            }
            i++;
            
            if count == intLengthFixed {
                break
            }
            
        }
        
        // mop things up if we ended on a boundary
        k = j;
        if (current == "=") {
            switch (i % 4) {
            case 1:
                // Invalid state
                return nil
            case 2:
                k++
                result[k] = 0
            case 3:
                result[k] = 0
            default:
                break
            }
        }
        
        // Setup the return NSData
        return NSData(bytes: result, length: j)
    }
    public static func base64StringFromData(data:NSData, length:Int, isSafeUrl:Bool) -> String {
        var ixtext:Int = 0
        var ctremaining:Int
        var input:[Int] = [Int](count: 3, repeatedValue: 0)
        var output:[Int] = [Int](count: 4, repeatedValue: 0)
        var i:Int, charsonline:Int = 0, ctcopy:Int
        guard data.length >= 1 else {
            return ""
        }
        var result:String = ""
        let count = data.length / sizeof(Int8)
        var raw = [Int8](count: count, repeatedValue: 0)
        data.getBytes(&raw, length:count * sizeof(Int8))
        while (true) {
            ctremaining = data.length - ixtext
            if ctremaining <= 0 {
                break
            }
            for i = 0; i < 3; i++ {
                let ix:Int = ixtext + i
                if ix < data.length {
                    input[i] = Int(raw[ix])
                } else {
                    input[i] = 0
                }
            }
            output[0] = (input[0] & 0xFC) >> 2
            output[1] = ((input[0] & 0x03) << 4) | ((input[1] & 0xF0) >> 4)
            output[2] = ((input[1] & 0x0F) << 2) | ((input[2] & 0xC0) >> 6)
            output[3] = input[2] & 0x3F
            ctcopy = 4
            switch (ctremaining) {
            case 1:
                ctcopy = 2
            case 2:
                ctcopy = 3
            default: break
            }
            for i = 0; i < ctcopy; i++ {
                let toAppend = isSafeUrl ? base64EncodingTableUrlSafe[output[i]]: base64EncodingTable[output[i]]
                result.append(toAppend)
            }
            for i = ctcopy; i < 4; i++ {
                result += "="
            }
            ixtext += 3
            charsonline += 4
            
            if (length > 0) && (charsonline >= length) {
                charsonline = 0
            }
            
        }
        
        return result
    }
    
    
    
    public static func base64StringFromData(data:NSData, isSafeUrl:Bool) -> String {
        let length = data.length
        var ixtext:Int = 0
        var ctremaining:Int
        var input:[Int] = [Int](count: 3, repeatedValue: 0)
        var output:[Int] = [Int](count: 4, repeatedValue: 0)
        var i:Int, charsonline:Int = 0, ctcopy:Int
        guard data.length >= 1 else {
            return ""
        }
        var result:String = ""
        let count = data.length / sizeof(Int8)
        var raw = [Int8](count: count, repeatedValue: 0)
        data.getBytes(&raw, length:count * sizeof(Int8))
        while (true) {
            ctremaining = data.length - ixtext
            if ctremaining <= 0 {
                break
            }
            for i = 0; i < 3; i++ {
                let ix:Int = ixtext + i
                if ix < data.length {
                    input[i] = Int(raw[ix])
                } else {
                    input[i] = 0
                }
            }
            output[0] = (input[0] & 0xFC) >> 2
            output[1] = ((input[0] & 0x03) << 4) | ((input[1] & 0xF0) >> 4)
            output[2] = ((input[1] & 0x0F) << 2) | ((input[2] & 0xC0) >> 6)
            output[3] = input[2] & 0x3F
            ctcopy = 4
            switch (ctremaining) {
            case 1:
                ctcopy = 2
            case 2:
                ctcopy = 3
            default: break
            }
            for i = 0; i < ctcopy; i++ {
                let toAppend = isSafeUrl ? base64EncodingTableUrlSafe[output[i]]: base64EncodingTable[output[i]]
                result.append(toAppend)
            }
            for i = ctcopy; i < 4; i++ {
                result += "="
            }
            ixtext += 3
            charsonline += 4
            
            if (length > 0) && (charsonline >= length) {
                charsonline = 0
            }
            
        }
        
        return result
    }
    

}