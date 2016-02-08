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

import BMSCore

internal class AuthorizationManagerPreferences {

    internal var persistencePolicy:PolicyPreference
    internal var clientId:StringPreference
    internal var accessToken:TokenPreference
    internal var idToken:TokenPreference
    internal var userIdentity:JSONPreference
    internal var deviceIdentity:JSONPreference
    internal var appIdentity:JSONPreference
    
    
    internal init() {
        
        persistencePolicy = PolicyPreference(prefName: "persistencePolicy", defaultValue: PersistencePolicy.ALWAYS)
        clientId = StringPreference(prefName: clientIdLabel)
        accessToken  = TokenPreference(prefName: accessTokenLabel, persistencePolicy: persistencePolicy)
        idToken  = TokenPreference(prefName: idTokenLabel, persistencePolicy: persistencePolicy)
        userIdentity  = JSONPreference(prefName: "userIdentity")
        deviceIdentity  = JSONPreference(prefName : "deviceIdentity")
        appIdentity  = JSONPreference(prefName:"appIdentity")
        
        
        //        String uuid = Settings.Secure.getString(context.getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);
        //        setStringEncryption(new AESStringEncryption(uuid));
    }
}


/**
 * Holds single string preference value
 */
internal class StringPreference {
    private var sharedPreferences:NSUserDefaults = NSUserDefaults.standardUserDefaults()
    var prefName:String
    var value:String?
    
  internal convenience init(prefName:String) {
    self.init(prefName: prefName, defaultValue: nil)
   }
    
    internal init(prefName:String, defaultValue:String?) {
        self.prefName = prefName
        if let val = self.sharedPreferences.valueForKey(prefName) as? String {
            self.value = val
        } else {
            self.value = defaultValue
        }
    }
    
    internal func get() ->String?{
        return value
    }
    
    internal func set(value:String?) {
        self.value = value
        commit()
    }
    
    internal func clear() {
        self.value = nil
        commit()
    }
    
    private func commit() {
        self.sharedPreferences.setValue(value, forKey: prefName)
        self.sharedPreferences.synchronize()
    }
}

/**
 * Holds single JSON preference value
 */
internal class JSONPreference:StringPreference {
    internal init(prefName:String) {
        super.init(prefName: prefName, defaultValue: nil)
    }
    
    internal func set(json:[String:AnyObject])
    {
        set(try? Utils.JSONStringify(json))
    }
    
    internal func getAsMap() -> [String:AnyObject]?{
        do {
            if let json = get() {
            return try Utils.parseJsonStringtoDictionary(json)
            } else {
                return nil
            }
        } catch {
            print(error)
            return nil
        }
    }
}



/**
 * Holds authorization manager Policy preference
 */
internal class PolicyPreference {
    private var sharedPreferences:NSUserDefaults = NSUserDefaults.standardUserDefaults()
    private var value:PersistencePolicy
    private var prefName:String
    
    init(prefName:String, defaultValue:PersistencePolicy) {
        self.prefName = prefName
        if let rawValue = self.sharedPreferences.valueForKey(prefName) as? String , newValue = PersistencePolicy(rawValue: rawValue){
            self.value = newValue
        } else {
            self.value = defaultValue
        }
    }
    
    internal func get() -> PersistencePolicy {
        return self.value
    }
    
    internal func set(value:PersistencePolicy ) {
        self.value = value
        self.sharedPreferences.setValue(value.rawValue, forKey: prefName)
        self.sharedPreferences.synchronize()
    }
}
/**
 * Holds authorization manager Token preference
 */
internal class TokenPreference {
    private var sharedPreferences:NSUserDefaults = NSUserDefaults.standardUserDefaults()
    var runtimeValue:String?
    var prefName:String
    var persistencePolicy:PolicyPreference
    init(prefName:String, persistencePolicy:PolicyPreference){
        self.prefName = prefName
        self.persistencePolicy = persistencePolicy
    }

    internal func set(value:String) {
        runtimeValue = value
        if self.persistencePolicy.get() ==  PersistencePolicy.ALWAYS {
            SecurityUtils.saveItemToKeyChain(value, label: prefName)
        } else {
            SecurityUtils.removeItemFromKeyChain(prefName)
        }
    }
    
    internal func get() -> String?{
        if (self.runtimeValue == nil && self.persistencePolicy.get() == PersistencePolicy.ALWAYS) {
            return SecurityUtils.getItemFromKeyChain(prefName)
        }
        return runtimeValue
    }
    
    internal func updateStateByPolicy() {
        if (self.persistencePolicy.get() == PersistencePolicy.ALWAYS) {
            if let unWrappedRuntimeValue = runtimeValue {
                SecurityUtils.saveItemToKeyChain(unWrappedRuntimeValue, label: prefName)
            }
        } else {
            SecurityUtils.removeItemFromKeyChain(prefName)
        }
    }
    
    internal func clear() {
        SecurityUtils.removeItemFromKeyChain(prefName)
        runtimeValue = nil
    }
}
