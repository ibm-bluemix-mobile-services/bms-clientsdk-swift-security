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
            final += path.substringWithRange(Range<String.Index>(start: path.startIndex, end: path.endIndex.advancedBy(-1)))
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
    * Builds rewrite domain from backend route url.
    *
    * @param backendRoute Backend route.
    * @param subzone      Subzone
    * @return Rewrite domain.
    * @throws MalformedURLException if backendRoute parameter has invalid format.
    */
    public static func buildRewriteDomain(backendRoute: String?, subzone: String?) throws -> String? {
//        guard let value = element.value as? Int8 where value != 0 else { return identifier }
        guard let route = backendRoute! as? String where route.isEmpty == false else {
            //log
            return nil
        }
        
        var applicationRoute: String = route
        if applicationRoute.hasPrefix(BMSClient.HTTP_SCHEME) {
            applicationRoute = "\(BMSClient.HTTPS_SCHEME)://\(applicationRoute)"
        }
        else if applicationRoute.hasPrefix(BMSClient.HTTPS_SCHEME) && applicationRoute.containsString(Utils.BLUEMIX_NAME) {
            applicationRoute = applicationRoute.stringByReplacingOccurrencesOfString(BMSClient.HTTP_SCHEME, withString: BMSClient.HTTPS_SCHEME)
        }
        
        var url: NSURL = NSURL(string: applicationRoute)!
        let host = url.host
        var rewriteDomain = ""
        var regionInDomain = "ng"
        let port = url.port
        
        var serviceUrl = "\(url.scheme)://\(host)"
        if port != 0 {
            serviceUrl += ":\(String(port))"
        }
        
//        host
        
//    //    String serviceUrl = String.format("%s://%s", url.getProtocol(), host);
//    
//    if (port != 0) {
//    serviceUrl += ":" + String.valueOf(port);
//    }
//    
//    String[] hostElements = host.split("\\.");
//    
//    if (!serviceUrl.contains(STAGE1_NAME)) {
//    // Multi-region: myApp.eu-gb.mybluemix.net
//    // US: myApp.mybluemix.net
//    if (hostElements.length == 4) {
//    regionInDomain = hostElements[hostElements.length - 3];
//    }
//    
//    // this is production, because STAGE1 is not found
//    // Multi-Region Eg: eu-gb.bluemix.net
//    // US Eg: ng.bluemix.net
//    rewriteDomain = String.format("%s.%s", regionInDomain, BLUEMIX_DOMAIN);
//    } else {
//    // Multi-region: myApp.stage1.eu-gb.mybluemix.net
//    // US: myApp.stage1.mybluemix.net
//    if (hostElements.length == 5) {
//    regionInDomain = hostElements[hostElements.length - 3];
//    }
//    
//    if (subzone != null && !subzone.isEmpty()) {
//    // Multi-region Dev subzone Eg: stage1-Dev.eu-gb.bluemix.net
//    // US Dev subzone Eg: stage1-Dev.ng.bluemix.net
//    rewriteDomain = String.format("%s-%s.%s.%s", STAGE1_NAME, subzone, regionInDomain, BLUEMIX_DOMAIN);
//    } else {
//    // Multi-region Eg: stage1.eu-gb.bluemix.net
//    // US  Eg: stage1.ng.bluemix.net
//    rewriteDomain = String.format("%s.%s.%s", STAGE1_NAME, regionInDomain, BLUEMIX_DOMAIN);
//    }
//    }
    
        return rewriteDomain;
    }
}