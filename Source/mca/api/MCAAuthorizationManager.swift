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
    
    /// Default scheme to use (default is https)
    public static var defaultProtocol: String = HTTPS_SCHEME
    public static let HTTP_SCHEME = "http"
    public static let HTTPS_SCHEME = "https"
    
    public static let CONTENT_TYPE = "Content-Type"
    
    internal var preferences:AuthorizationManagerPreferences
    
    //lock constant
    private var lockQueue = dispatch_queue_create("MCAAuthorizationManagerQueue", DISPATCH_QUEUE_CONCURRENT)
    
    private var challengeHandlers:[String:ChallengeHandler]
    
    /// @return the singelton instance
    public static let sharedInstance = MCAAuthorizationManager()
    
    var processManager : AuthorizationProcessManager
    
    private init() {
        self.preferences = AuthorizationManagerPreferences()
        processManager = AuthorizationProcessManager(preferences: preferences)
        self.challengeHandlers = [String:ChallengeHandler]()
        
        BMSClient.sharedInstance.sharedAuthorizationManager = self
        
        challengeHandlers = [String:ChallengeHandler]()
        
        if preferences.deviceIdentity.get() == nil {
            preferences.deviceIdentity.set(MCADeviceIdentity().getAsJson())
        }
        if preferences.appIdentity.get() == nil {
            preferences.appIdentity.set(MCAAppIdentity().getAsJson())
        }
    }
    
    /*!
        A response is an OAuth error response only if,
        1. it's status is 401 or 403
        2. The value of the "WWW-Authenticate" header contains 'Bearer'
    
        @param httpResponse response to check the authorization conditions for.
        @return true if the response satisfies both conditions
     */
    public func isAuthorizationRequired(httpResponse: Response) -> Bool {
        if let header = httpResponse.headers![caseInsensitive : BMSSecurityConstants.WWW_AUTHENTICATE_HEADER], authHeader : String = header as? String {
            guard let statusCode = httpResponse.statusCode else {
                return false
            }
            
            return isAuthorizationRequired(statusCode, responseAuthorizationHeader: authHeader)
        }
        
        return false
    }
    
    /*!
        @brief Check if the params came from response that requires authorization
        @param statusCode of the response
        @param headers response headers
        @return true if status is 401 or 403 and The value of the header contains 'Bearer'
     */
    public func isAuthorizationRequired(statusCode: Int, responseAuthorizationHeader: String) -> Bool {
        
        if (statusCode == 401 || statusCode == 403) && responseAuthorizationHeader.lowercaseString.containsString(BMSSecurityConstants.BEARER.lowercaseString){
            return true
        }
        
        return false
    }
    
    private func clearCookies() {  
        let cookiesStorage = NSHTTPCookieStorage.sharedHTTPCookieStorage()
        if let cookies = cookiesStorage.cookies {
            let jSessionCookies = cookies.filter() {$0.name == "JSESSIONID"}
            for cookie in jSessionCookies {
                cookiesStorage.deleteCookie(cookie)
            }
        }
    }
    
    /*!
        Clear the local stored authorization data
    */
    public func clearAuthorizationData() {
        preferences.userIdentity.clear()
        preferences.idToken.clear()
        preferences.accessToken.clear()
        processManager.authorizationFailureCount = 0
        clearCookies()
    }
    
    /*!
        @brief Adds the cached authorization header to the given URL connection object.
        int the cached authorization header is equals to null then this operation has no effect.
        @param request The request to add the header to.
    */
    public func addCachedAuthorizationHeader(request: NSMutableURLRequest) {
        addAuthorizationHeader(request, header: getCachedAuthorizationHeader())
    }
    
    private func addAuthorizationHeader(request: NSMutableURLRequest, header:String?) {
        guard let unWrappedHeader = header else {
            return
        }
        request.setValue(unWrappedHeader, forHTTPHeaderField: BMSSecurityConstants.AUTHORIZATION_HEADER)
    }
    
    /*!
        @return the locally stored authorization header or null if the value is not exist.
    */
    public func getCachedAuthorizationHeader() -> String? {
        var returnedValue:String? = nil
        dispatch_barrier_sync(lockQueue){
            if let accessToken = self.preferences.accessToken.get(), idToken = self.preferences.idToken.get() {
                returnedValue = "\(BMSSecurityConstants.BEARER) \(accessToken) \(idToken)"
            }
        }
        return returnedValue
    }
    
    /*!
        Invoke process for obtaining authorization header. during this process
     */
    public func obtainAuthorization(completionHandler: MfpCompletionHandler?) {
        dispatch_barrier_async(lockQueue){
            self.processManager.startAuthorizationProcess(completionHandler)
        }
    }
    
    /*!
        return user identity
    */
    public func getUserIdentity() -> BaseUserIdentity {
        let userIdentityJson = preferences.userIdentity.getAsMap()
        return MCAUserIdentity(map: userIdentityJson)
    }
    
    /*!
        return device identity
    */
    public func getDeviceIdentity() -> BaseDeviceIdentity {
        let deviceIdentityJson = preferences.deviceIdentity.getAsMap()
        return MCADeviceIdentity(map: deviceIdentityJson)
    }
    /*!
         @return application identity
     */
    public func getAppIdentity() -> BaseAppIdentity {
        let appIdentityJson = preferences.appIdentity.getAsMap()
        return MCAAppIdentity(map: appIdentityJson)
        
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
     
     
     - returns: <#return value description#>
     */
    public func getAuthorizationPersistencePolicy() -> PersistencePolicy {
        return preferences.persistencePolicy.get()
    }
    
    /**
     Description
     
     - parameter policy: <#policy description#>
     */
    public func setAuthorizationPersistencePolicy(policy: PersistencePolicy) {
        if preferences.persistencePolicy.get() != policy {
            preferences.persistencePolicy.set(policy)
            preferences.accessToken.updateStateByPolicy()
            preferences.idToken.updateStateByPolicy()
        }
    }
    
    /**
     
     
     - parameter realm: <#realm description#>
     
     - returns: <#return value description#>
     */
    public func getChallengeHandler(realm:String) -> ChallengeHandler?{
        return challengeHandlers[realm]
    }
    
    
}
