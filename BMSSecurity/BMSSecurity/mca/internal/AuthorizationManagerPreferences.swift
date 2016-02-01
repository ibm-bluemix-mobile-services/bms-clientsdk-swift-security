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

internal class AuthorizationManagerPreferences:UserDataUtils {
    
    //TODO: think if this vars should be "weak" or not
    
    
    internal var persistencePolicy:PolicyPreference?
    internal var clientId:StringPreference?
    internal var accessToken:TokenPreference?
    internal var idToken:TokenPreference?
    internal var userIdentity:JSONPreference?
    internal var deviceIdentity:JSONPreference?
    internal var appIdentity:JSONPreference?
    
//    public appName:String
//    public
    
    internal override init() {
        super.init()
        persistencePolicy = PolicyPreference(prefName: "persistencePolicy", defaultValue: PersistencePolicy.ALWAYS, authorizationManagerPreferences: self)
        clientId = StringPreference(prefName: "clientId", userDataUtils: self)
        accessToken  = TokenPreference(prefName: "accessToken", authorizationManagerPreferences: self)
        idToken  = TokenPreference(prefName: "idToken", authorizationManagerPreferences: self)
        
        userIdentity  = JSONPreference(prefName: "userIdentity", userDataUtils:self)
        deviceIdentity  = JSONPreference(prefName : "deviceIdentity", userDataUtils:self)
        appIdentity  = JSONPreference(prefName:"appIdentity", userDataUtils:self)
        
        
        //        String uuid = Settings.Secure.getString(context.getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);
        //        setStringEncryption(new AESStringEncryption(uuid));
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
    var savedValue:StringPreference
    var authorizationManagerPreferences:AuthorizationManagerPreferences
    
    init(prefName:String, authorizationManagerPreferences:AuthorizationManagerPreferences){
        self.savedValue = StringPreference(prefName: prefName, userDataUtils: authorizationManagerPreferences);
        self.authorizationManagerPreferences = authorizationManagerPreferences
    }
    // TODO: I don't like this ! workaround
    internal func set(value:String) {
        runtimeValue = value;
        if self.authorizationManagerPreferences.persistencePolicy!.get() == PersistencePolicy.ALWAYS {
            savedValue.set(value);
        } else {
            savedValue.clear();
        }
    }
    
    internal func get() -> String?{
        if (self.runtimeValue == nil && self.authorizationManagerPreferences.persistencePolicy!.get() == PersistencePolicy.ALWAYS) {
            return savedValue.get();
        }
        return runtimeValue;
    }
    
    internal func updateStateByPolicy() {
        if (self.authorizationManagerPreferences.persistencePolicy!.get() == PersistencePolicy.ALWAYS) {
            savedValue.set(runtimeValue);
        } else {
            savedValue.clear();
        }
    }
    
    internal func clear() {
        savedValue.clear();
        runtimeValue = nil;
    }
}
