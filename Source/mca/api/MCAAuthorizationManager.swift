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

public class MCAAuthorizationManager : AuthorizationManager {
    //
    public static var defaultProtocol: String = HTTPS_SCHEME
    public static let HTTP_SCHEME = "http"
    public static let HTTPS_SCHEME = "https"
    
    public static let CONTENT_TYPE = "Content-Type"
    
    private var preferences:AuthorizationManagerPreferences
    
    //lock constant
    private var lockQueue = dispatch_queue_create("MCAAuthorizationManagerQueue", DISPATCH_QUEUE_CONCURRENT)
    
    private var challengeHandlers:[String:ChallengeHandler]
    
    public static let sharedInstance = MCAAuthorizationManager()
    
    var processManager : AuthorizationProcessManager
    
    private init() {
        self.preferences = AuthorizationManagerPreferences()
        processManager = AuthorizationProcessManager(preferences: preferences)
        self.challengeHandlers = [String:ChallengeHandler]()
        
        BMSClient.sharedInstance.sharedAuthorizationManager = self
        
        challengeHandlers = [String:ChallengeHandler]()
        
        if preferences.deviceIdentity.get() == nil {
            preferences.deviceIdentity.set(DeviceIdentity().getAsJson())
        }
        if preferences.appIdentity.get() == nil {
            preferences.appIdentity.set(AppIdentity().getAsJson())
        }
    }
    
    public func isAuthorizationRequired(httpResponse: Response) -> Bool {
        if let header = httpResponse.headers![caseInsensitive : BMSSecurityConstants.WWW_AUTHENTICATE_HEADER], authHeader : String = header as? String {
            guard let statusCode = httpResponse.statusCode else {
                return false
            }
            
            return isAuthorizationRequired(statusCode, responseAuthorizationHeader: authHeader)
        }
        
        return false
    }
    
    public func isAuthorizationRequired(statusCode: Int, responseAuthorizationHeader: String) -> Bool {
        
        if (statusCode == 401 || statusCode == 403) && responseAuthorizationHeader.lowercaseString.containsString(BMSSecurityConstants.BEARER.lowercaseString){
            return true
        }
        
        return false
    }
    
    private func clearCookies() {
        let cookiesStorage = NSHTTPCookieStorage.sharedHTTPCookieStorage()
        if let cookies = cookiesStorage.cookies {
            for cookie in cookies {
                cookiesStorage.deleteCookie(cookie)
            }
        }
        NSUserDefaults.standardUserDefaults().synchronize()
    }
    public func clearAuthorizationData() {
        preferences.userIdentity.clear()
        preferences.idToken.clear()
        preferences.accessToken.clear()
        clearCookies()
    }
    
    public func addCachedAuthorizationHeader(request: NSMutableURLRequest) {
        MCAAuthorizationManager.addAuthorizationHeader(request, header: getCachedAuthorizationHeader())
    }
    
    public static func addAuthorizationHeader(request: NSMutableURLRequest, header:String?) {
        guard let unWrappedHeader = header else {
            return
        }
        request.setValue(unWrappedHeader, forHTTPHeaderField: BMSSecurityConstants.AUTHORIZATION_HEADER)
    }
    
    public func getCachedAuthorizationHeader() -> String? {
        var returnedValue:String? = nil
        dispatch_barrier_sync(lockQueue){
            if let accessToken = self.preferences.accessToken.get(), idToken = self.preferences.idToken.get() {
                returnedValue = "\(BMSSecurityConstants.BEARER) \(accessToken) \(idToken)"
            }
        }
        return returnedValue
    }
    
    public func obtainAuthorization(completionHandler: MfpCompletionHandler?) {
        dispatch_barrier_async(lockQueue){
            self.processManager.startAuthorizationProcess(completionHandler)
        }
    }
    
    public func getUserIdentity() -> UserIdentity? {
        guard let userIdentityJson = preferences.userIdentity.getAsMap() else {
            return nil
        }
        return UserIdentity(map: userIdentityJson)
    }
    
    public func getDeviceIdentity() -> DeviceIdentity? {
        guard let deviceIdentityJson = preferences.deviceIdentity.getAsMap() else {
            return nil
        }
        return DeviceIdentity(map: deviceIdentityJson)
    }
    
    public func getAppIdentity() -> AppIdentity? {
        guard let appIdentityJson = preferences.appIdentity.getAsMap() else {
            return nil
        }
        return AppIdentity(map: appIdentityJson)
        
    }
    
    /**
     Registers a delegate that will handle authentication for the specified realm.
     
     - parameter delegate: The delegate that will handle authentication challenges
     - parameter forRealm: The realm name
     */
    public func registerAuthenticationDelegate(delegate: AuthenticationDelegate, realm: String) throws {
        guard !realm.isEmpty else {
            throw AuthorizationError.CANNOT_ADD_CHALLANGE_HANDLER("The realm name can't be empty.")
        }
        
        let handler = ChallengeHandler(realm: realm, authenticationDelegate: delegate)
        challengeHandlers[realm] = handler
    }
    
    /**
     Unregisters the authentication delegate for the specified realm.
     
     - parameter realm: The realm name
     */
    public func unregisterAuthenticationDelegate(realm: String) {
        guard !realm.isEmpty else {
            return
        }
        
        challengeHandlers.removeValueForKey(realm)
    }
    
    /**
     <#Description#>
     
     - returns: <#return value description#>
     */
    public func getAuthorizationPersistencePolicy() -> PersistencePolicy {
        return preferences.persistencePolicy.get()
    }
    
    /**
     Description
     
     - parameter policy: <#policy description#>
     */
    public func setAuthorizationPersistensePolicy(policy: PersistencePolicy) {
        if preferences.persistencePolicy.get() != policy {
            preferences.persistencePolicy.set(policy)
            preferences.accessToken.updateStateByPolicy()
            preferences.idToken.updateStateByPolicy()
        }
    }
    
    /**
     <#Description#>
     
     - parameter realm: <#realm description#>
     
     - returns: <#return value description#>
     */
    public func getChallengeHandler(realm:String) -> ChallengeHandler?{
        return challengeHandlers[realm]
    }
    
    
}
