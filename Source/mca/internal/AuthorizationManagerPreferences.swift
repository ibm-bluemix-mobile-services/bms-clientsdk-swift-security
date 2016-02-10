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
    
    private static var sharedPreferences:NSUserDefaults = NSUserDefaults.standardUserDefaults()

    internal var persistencePolicy:PolicyPreference
    internal var clientId:StringPreference
    internal var accessToken:TokenPreference
    internal var idToken:TokenPreference
    internal var userIdentity:JSONPreference
    internal var deviceIdentity:JSONPreference
    internal var appIdentity:JSONPreference
    
    
    internal init() {
        persistencePolicy = PolicyPreference(prefName: BMSSecurityConstants.DEVICE_IDENTITY_LABEL, defaultValue: PersistencePolicy.ALWAYS)
        clientId = StringPreference(prefName: BMSSecurityConstants.clientIdLabel)
        accessToken  = TokenPreference(prefName: BMSSecurityConstants.accessTokenLabel, persistencePolicy: persistencePolicy)
        idToken  = TokenPreference(prefName: BMSSecurityConstants.idTokenLabel, persistencePolicy: persistencePolicy)
        userIdentity  = JSONPreference(prefName: BMSSecurityConstants.USER_IDENTITY_LABEL)
        deviceIdentity  = JSONPreference(prefName : BMSSecurityConstants.DEVICE_IDENTITY_LABEL)
        appIdentity  = JSONPreference(prefName: BMSSecurityConstants.APP_IDENTITY_LABEL)
    }
}


/**
 * Holds single string preference value
 */
internal class StringPreference {
    
    var prefName:String
    var value:String?
    
  internal convenience init(prefName:String) {
    self.init(prefName: prefName, defaultValue: nil)
   }
    
    internal init(prefName:String, defaultValue:String?) {
        self.prefName = prefName
        if let val = AuthorizationManagerPreferences.sharedPreferences.valueForKey(prefName) as? String {
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
        AuthorizationManagerPreferences.sharedPreferences.setValue(value, forKey: prefName)
        AuthorizationManagerPreferences.sharedPreferences.synchronize()
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
    
    private var value:PersistencePolicy
    private var prefName:String
    
    init(prefName:String, defaultValue:PersistencePolicy) {
        self.prefName = prefName
        if let rawValue = AuthorizationManagerPreferences.sharedPreferences.valueForKey(prefName) as? String , newValue = PersistencePolicy(rawValue: rawValue){
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
        AuthorizationManagerPreferences.sharedPreferences.setValue(value.rawValue, forKey: prefName)
        AuthorizationManagerPreferences.sharedPreferences.synchronize()
    }
}
/**
 * Holds authorization manager Token preference
 */
internal class TokenPreference {
    
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
