//
//  WLDeviceAuthManager.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 06/01/2016.
//  Copyright © 2016 IBM. All rights reserved.
//

import Foundation

public class WLDeviceAuthManager {
    
//    public static func getWLUniqueDeviceId() -> String {
//        var getQuery =  [String: AnyObject]()
//        getQuery[kSecClass as String] = kSecClassCertificate
//        getQuery[kSecReturnRef as String] = true
//    }
//    
//    func createUUID() -> String {
//        var uuid = NSUUID().UUIDString
//        
//        return uuid
//    }
    
    
    
    
//    //Return custom WL device ID since it is deprecate to return the iOS UUID
//    -(NSString *)getWLUniqueDeviceId {
//    NSString *tmpString;
//    
//    // try to read UUID from keychain
//    IMFKeychainItemWrapper *wrapper = [self UUIDKeychainItem];
//    tmpString = [wrapper objectForKey:(__bridge id)(kSecValueData)];
//    if ((tmpString != nil) && ([tmpString length] > 0)) {
//    IMFLogTraceWithName(IMF_AUTH_PACKAGE, @"returning UUID from the keychain");
//    return tmpString;
//    }
//    
//    // If none exist, create UUID
//    IMFLogTraceWithName(IMF_AUTH_PACKAGE, @"creating UUID and save it to the keychain");
//    tmpString = [self createUUID];
//    
//    // Save to keychain
//    [wrapper setObject:@"IMFCoreBlueMix" forKey:(__bridge id)(kSecAttrService)];
//    [wrapper setObject:tmpString forKey:(__bridge id)(kSecValueData)];
//    
//    return tmpString;
//    }
//    
//    -(IMFKeychainItemWrapper *)UUIDKeychainItem {
//    if (UUIDKeychainItem) {
//    return UUIDKeychainItem;
//    }
//    else {
//    UUIDKeychainItem = [[IMFKeychainItemWrapper alloc] initWithIdentifier:@"WLUUID" accessGroup:nil];
//    //ARC Refactoring - Removing retain from global variable , may need to be revisited
//    // [UUIDKeychainItem retain];
//    return UUIDKeychainItem;
//    }
//    }
//    
//    -(NSString *)createUUID {
//    CFUUIDRef theUUID = CFUUIDCreate(NULL);
//    CFStringRef string = CFUUIDCreateString(NULL, theUUID);
//    CFRelease(theUUID);
//    return (NSString *)CFBridgingRelease(string);
//    }
    
}
