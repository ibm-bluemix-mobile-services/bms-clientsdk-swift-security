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

public class UserDataUtils {
    
    public var sharedPreferences:NSUserDefaults
    public var stringEncryption:StringEncryption?
    
    public init() {
        //TODO:check that this is indeed the correct thing to do here
        self.sharedPreferences = NSUserDefaults.standardUserDefaults()
        self.stringEncryption = AESStringEncryption()
    }
    
    internal func setStringEncryption(stringEncryption:StringEncryption) {
        self.stringEncryption = stringEncryption;
    }
}

/**
 * Holds single string preference value
 */
public class StringPreference {
    
    var prefName:String;
    var value:String?;
    var userDataUtils:UserDataUtils
    
    public convenience init(prefName:String, userDataUtils:UserDataUtils) {
        self.init(prefName: prefName, defaultValue: nil, userDataUtils:userDataUtils)
    }
    
    public init(prefName:String, defaultValue:String?, userDataUtils:UserDataUtils) {
        self.prefName = prefName;
        self.userDataUtils = userDataUtils
        if let val = userDataUtils.sharedPreferences.valueForKey(prefName) as? String {
            self.value = val
        } else {
            self.value = defaultValue
        }
    }
    
    public func get() ->String?{
        if let value = value, encryptedValue = self.userDataUtils.stringEncryption?.decrypt(value){
            return encryptedValue
        } else {
            return nil
        }
    }
    
    public func set(value:String?) {
        if let value = value, encryptedValue = self.userDataUtils.stringEncryption?.encrypt(value){
            self.value = encryptedValue
        } else {
            self.value = nil
        }
        commit();
    }
    
    public func clear() {
        self.value = nil;
        commit()
    }
    
    private func commit() {
        self.userDataUtils.sharedPreferences.setValue(value, forKey: prefName)
        self.userDataUtils.sharedPreferences.synchronize()
    }
}

/**
 * Holds single JSON preference value
 */
public class JSONPreference:StringPreference {
    
    public init(prefName:String, userDataUtils:UserDataUtils) {
        super.init(prefName: prefName, defaultValue: nil, userDataUtils:userDataUtils)
    }
    
    public func set(json:[String:AnyObject])
    {
        set(String(json))
    }

    public func getAsMap() -> [String:AnyObject]?{
        do {
            if let data = get()?.dataUsingEncoding(NSUTF8StringEncoding) {
                return try NSJSONSerialization.JSONObjectWithData(data, options: []) as? [String : AnyObject]
            }
        } catch {
            //TODO: handle error
            return nil
        }
        return nil
    }
}