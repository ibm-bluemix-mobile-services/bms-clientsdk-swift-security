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
