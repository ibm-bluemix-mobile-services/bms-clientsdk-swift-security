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
internal let OAUTH_CERT_LABEL = "com.worklight.oauth.certificate"
internal let _PUBLIC_KEY_LABEL = "com.worklight.oauth.publickey"
internal let CLIENT_ID_KEY_LABEL = "com.worklight.oauth.clientid"
internal let _PRIVATE_KEY_LABEL = "com.worklight.oauth.privatekey"
internal let OAUTH_ACCESS_TOKEN_LABEL = "com.worklight.oauth.accesstoken"
internal let OAUTH_ID_TOKEN_LABEL = "com.worklight.oauth.idtoken"



internal let privateKeyIdentifier = "\(_PRIVATE_KEY_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
internal let publicKeyIdentifier = "\(_PUBLIC_KEY_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
internal let idTokenLabel = "\(OAUTH_ID_TOKEN_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
internal let accessTokenLabel = "\(OAUTH_ACCESS_TOKEN_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
internal let clientIdLabel = "\(CLIENT_ID_KEY_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
internal let certificateIdentifier = "\(OAUTH_CERT_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
