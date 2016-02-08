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

internal enum BMSSecurityError:ErrorType {
    case generalError
}

internal enum Errors:ErrorType {
    case JsonIsMalformed
    case CouldNotParseDictionaryToJson
    case CouldNotExtractJsonFromResponse
}

internal enum SecurityError : ErrorType{
    case NoKeysGenerated
    case KeysNotFound
    case CertNotFound
    case CertCannotBeCreated
    case CertCannotBeSaved
    case CertificatePublicKeyValidationFailed
    case SignDataFailure
    case SigningFailure(String)
    case unableToSavePublicKey
    case CouldNotCreateHeaderFromPublicKey
}

internal enum AuthorizationError : ErrorType {
    case CANNOT_ADD_CHALLANGE_HANDLER(String)
        case CertificateDoesNotIncludeClientId
    case ResponseDoesNotIncludeCertificate
}

internal enum AuthorizationProcessManagerError : ErrorType {
    case CouldNotExtractGrantCode
    case CouldNotExtractLocationHeader
    case FailedToCreateTokenRequestHeaders
    case FailedToCreateRegistrationParams
    case FailedToSendAuthorizationRequest
    case COULD_NOT_SAVE_TOKEN(String)
}


