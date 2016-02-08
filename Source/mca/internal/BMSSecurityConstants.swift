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

internal let nameAndVer = Utils.getApplicationDetails()
internal let MFP_PACKAGE_PREFIX = "mfpsdk."
internal let MFP_SECURITY_PACKAGE = MFP_PACKAGE_PREFIX + "security"

//MCAAuthorizationManager constants
internal let BEARER = "Bearer"
internal let AUTHORIZATION_HEADER = "Authorization"
internal let WWW_AUTHENTICATE_HEADER = "WWW-Authenticate"

//JSON keys
internal let JSON_CERTIFICATE_KEY = "certificate"
internal let JSON_CLIENT_ID_KEY = "clientId"
internal let JSON_DEVICE_ID_KEY = "deviceId"
internal let JSON_OS_KEY = "deviceOs"
internal let JSON_ENVIRONMENT_KEY = "environment"
internal let JSON_MODEL_KEY = "deviceModel"
internal let JSON_APPLICATION_ID_KEY = "applicationId"
internal let JSON_APPLICATION_VERSION_KEY = "applicationVersion"
internal let JSON_IOS_ENVIRONMENT_VALUE = "iOSnative"
internal let JSON_ACCESS_TOKEN_KEY = "access_token"
internal let JSON_ID_TOKEN_KEY = "id_token"

//label names
internal let OAUTH_CERT_LABEL = "com.worklight.oauth.certificate"
internal let _PUBLIC_KEY_LABEL = "com.worklight.oauth.publickey"
internal let CLIENT_ID_KEY_LABEL = "com.worklight.oauth.clientid"
internal let _PRIVATE_KEY_LABEL = "com.worklight.oauth.privatekey"
internal let OAUTH_ACCESS_TOKEN_LABEL = "com.worklight.oauth.accesstoken"
internal let OAUTH_ID_TOKEN_LABEL = "com.worklight.oauth.idtoken"


//labels 

internal let privateKeyIdentifier = "\(_PRIVATE_KEY_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
internal let publicKeyIdentifier = "\(_PUBLIC_KEY_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
internal let idTokenLabel = "\(OAUTH_ID_TOKEN_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
internal let accessTokenLabel = "\(OAUTH_ACCESS_TOKEN_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
internal let clientIdLabel = "\(CLIENT_ID_KEY_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
internal let certificateIdentifier = "\(OAUTH_CERT_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
