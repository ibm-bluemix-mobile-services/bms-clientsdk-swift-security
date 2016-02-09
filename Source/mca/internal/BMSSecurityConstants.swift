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

internal class BMSSecurityConstants {
    internal static var deviceInfo = Utils.getDeviceDictionary()
    internal static let nameAndVer = Utils.getApplicationDetails()
    internal static let MFP_PACKAGE_PREFIX = "mfpsdk."
    internal static let MFP_SECURITY_PACKAGE = MFP_PACKAGE_PREFIX + "security"
    
    internal static let BEARER = "Bearer"
    internal static let AUTHORIZATION_HEADER = "Authorization"
    internal static let WWW_AUTHENTICATE_HEADER = "WWW-Authenticate"
    
    internal static let HTTP_LOCALHOST = "http://localhost"
    /**
     * Parts of the path to authorization endpoint.
     */
    internal static let AUTH_SERVER_NAME = "imf-authserver"
    internal static let AUTH_PATH = "authorization/v1/apps/"
    
    /**
     * The name of "result" parameter returned from authorization endpoint.
     */
    internal static let WL_RESULT = "wl_result";
    
    /**
     * Name of rewrite domain header. This header is added to authorization requests.
     */
    internal static let REWRITE_DOMAIN_HEADER_NAME = "X-REWRITE-DOMAIN"
    
    /**
     * Name of location header.
     */
    internal static let LOCATION_HEADER_NAME = "Location"
    
    /**
     * Name of the standard "www-authenticate" header.
     */
    internal static let AUTHENTICATE_HEADER_NAME = "WWW-Authenticate"
    
    /**
     * Name of "www-authenticate" header value.
     */
    internal static let AUTHENTICATE_HEADER_VALUE = "WL-Composite-Challenge"
    
    /**
     * Names of JSON values returned from the server.
     */
    internal static let AUTH_FAILURE_VALUE_NAME = "WL-Authentication-Failure"
    internal static let AUTH_SUCCESS_VALUE_NAME = "WL-Authentication-Success"
    internal static let CHALLENGES_VALUE_NAME = "challenges"
    

    
    
    //JSON keys
    internal static let JSON_CERTIFICATE_KEY = "certificate"
    internal static let JSON_CLIENT_ID_KEY = "clientId"
    internal static let JSON_DEVICE_ID_KEY = "deviceId"
    internal static let JSON_OS_KEY = "deviceOs"
    internal static let JSON_ENVIRONMENT_KEY = "environment"
    internal static let JSON_MODEL_KEY = "deviceModel"
    internal static let JSON_APPLICATION_ID_KEY = "applicationId"
    internal static let JSON_APPLICATION_VERSION_KEY = "applicationVersion"
    internal static let JSON_IOS_ENVIRONMENT_VALUE = "iOSnative"
    internal static let JSON_ACCESS_TOKEN_KEY = "access_token"
    internal static let JSON_ID_TOKEN_KEY = "id_token"
    
    //label names
    internal static let OAUTH_CERT_LABEL = "com.worklight.oauth.certificate"
    internal static let _PUBLIC_KEY_LABEL = "com.worklight.oauth.publickey"
    internal static let CLIENT_ID_KEY_LABEL = "com.worklight.oauth.clientid"
    internal static let _PRIVATE_KEY_LABEL = "com.worklight.oauth.privatekey"
    internal static let OAUTH_ACCESS_TOKEN_LABEL = "com.worklight.oauth.accesstoken"
    internal static let OAUTH_ID_TOKEN_LABEL = "com.worklight.oauth.idtoken"
    
    
    //labels
    internal static let IMFClientErrorDomain = "com.ibm.mobilefoundation.client"
    internal static let privateKeyIdentifier = "\(_PRIVATE_KEY_LABEL):\(nameAndVer.name):\(nameAndVer.version)"
    internal static let publicKeyIdentifier = "\(_PUBLIC_KEY_LABEL):\(nameAndVer.name):\(nameAndVer.version)"
    internal static let idTokenLabel = "\(OAUTH_ID_TOKEN_LABEL):\(nameAndVer.name):\(nameAndVer.version)"
    internal static let accessTokenLabel = "\(OAUTH_ACCESS_TOKEN_LABEL):\(nameAndVer.name):\(nameAndVer.version)"
    internal static let clientIdLabel = "\(CLIENT_ID_KEY_LABEL):\(nameAndVer.name):\(nameAndVer.version)"
    internal static let certificateIdentifier = "\(OAUTH_CERT_LABEL):\(nameAndVer.name):\(nameAndVer.version)"
}



