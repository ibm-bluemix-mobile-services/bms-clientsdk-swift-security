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
    
    private var sharedPreferences:NSUserDefaults
    
    
    internal var persistencePolicy:PolicyPreference?
    internal var clientId:StringPreference?
    internal var accessToken:TokenPreference?
    internal var idToken:TokenPreference?
    internal var userIdentity:JSONPreference?
    internal var deviceIdentity:JSONPreference?
    internal var appIdentity:JSONPreference?
    
    
    internal init() {
        self.sharedPreferences = NSUserDefaults.standardUserDefaults()
        persistencePolicy = PolicyPreference(prefName: "persistencePolicy", defaultValue: PersistencePolicy.ALWAYS, authorizationManagerPreferences: self)
        clientId = StringPreference(prefName: clientIdLabel, authorizationManagerPreferences: self)
        accessToken  = TokenPreference(prefName: accessTokenLabel, authorizationManagerPreferences: self)
        idToken  = TokenPreference(prefName: idTokenLabel, authorizationManagerPreferences: self)
        
        userIdentity  = JSONPreference(prefName: "userIdentity", authorizationManagerPreferences:self)
        deviceIdentity  = JSONPreference(prefName : "deviceIdentity", authorizationManagerPreferences:self)
        appIdentity  = JSONPreference(prefName:"appIdentity", authorizationManagerPreferences:self)
        
        
        //        String uuid = Settings.Secure.getString(context.getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);
        //        setStringEncryption(new AESStringEncryption(uuid));
    }
}


/**
 * Holds single string preference value
 */
internal class StringPreference {
    
    var prefName:String;
    var value:String?;
    var authorizationManagerPreferences:AuthorizationManagerPreferences
    
  internal convenience init(prefName:String, authorizationManagerPreferences : AuthorizationManagerPreferences) {
    self.init(prefName: prefName, defaultValue: nil, authorizationManagerPreferences : authorizationManagerPreferences)
   }
    
    internal init(prefName:String, defaultValue:String?, authorizationManagerPreferences : AuthorizationManagerPreferences) {
        self.prefName = prefName;
        self.authorizationManagerPreferences = authorizationManagerPreferences
        if let val = authorizationManagerPreferences.sharedPreferences.valueForKey(prefName) as? String {
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
        self.value = nil;
        commit()
    }
    
    private func commit() {
        self.authorizationManagerPreferences.sharedPreferences.setValue(value, forKey: prefName)
        self.authorizationManagerPreferences.sharedPreferences.synchronize()
    }
}

/**
 * Holds single JSON preference value
 */
internal class JSONPreference:StringPreference {
    
    internal init(prefName:String, authorizationManagerPreferences:AuthorizationManagerPreferences) {
        super.init(prefName: prefName, defaultValue: nil, authorizationManagerPreferences: authorizationManagerPreferences)
    }
    
    internal func set(json:[String:AnyObject])
    {
        set(String(json))
    }
    
    internal func getAsMap() -> [String:AnyObject]?{
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



/**
 * Holds authorization manager Policy preference
 */
internal class PolicyPreference {
    
    private var value:PersistencePolicy
    private var prefName:String
    var authorizationManagerPreferences:AuthorizationManagerPreferences
    
    init(prefName:String, defaultValue:PersistencePolicy, authorizationManagerPreferences:AuthorizationManagerPreferences) {
        self.prefName = prefName;
        self.authorizationManagerPreferences = authorizationManagerPreferences
        if let rawValue = self.authorizationManagerPreferences.sharedPreferences.valueForKey(prefName) as? String , newValue = PersistencePolicy(rawValue: rawValue){
            self.value = newValue
        } else {
            self.value = defaultValue
        }
    }
    
    internal func get() -> PersistencePolicy {
        return self.value;
    }
    
    internal func set(value:PersistencePolicy ) {
        self.value = value;
        self.authorizationManagerPreferences.sharedPreferences.setValue(value.rawValue, forKey: prefName)
        self.authorizationManagerPreferences.sharedPreferences.synchronize()
    }
}
/**
 * Holds authorization manager Token preference
 */
internal class TokenPreference {
    
    var runtimeValue:String?
    var prefName:String
    var authorizationManagerPreferences:AuthorizationManagerPreferences
    
    init(prefName:String, authorizationManagerPreferences:AuthorizationManagerPreferences){
        self.prefName = prefName
        self.authorizationManagerPreferences = authorizationManagerPreferences
    }

    internal func set(value:String) {
        runtimeValue = value;
        if self.authorizationManagerPreferences.persistencePolicy!.get() ==  PersistencePolicy.ALWAYS {
            SecurityUtils.saveItemToKeyChain(value, label: prefName)
        } else {
            SecurityUtils.removeItemFromKeyChain(prefName)
        }
    }
    
    internal func get() -> String?{
        if (self.runtimeValue == nil && self.authorizationManagerPreferences.persistencePolicy!.get() == PersistencePolicy.ALWAYS) {
            return SecurityUtils.getItemFromKeyChain(prefName)
        }
        return runtimeValue;
    }
    
    internal func updateStateByPolicy() {
        if (self.authorizationManagerPreferences.persistencePolicy!.get() == PersistencePolicy.ALWAYS) {
            SecurityUtils.saveItemToKeyChain(runtimeValue!, label: prefName)
        } else {
            SecurityUtils.removeItemFromKeyChain(prefName)
        }
    }
    
    internal func clear() {
        SecurityUtils.removeItemFromKeyChain(prefName)
        runtimeValue = nil;
    }
}
