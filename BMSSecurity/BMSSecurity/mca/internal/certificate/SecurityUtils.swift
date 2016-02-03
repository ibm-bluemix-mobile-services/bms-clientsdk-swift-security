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

public class SecurityUtils {
       
    enum SecurityError : ErrorType{
        case NoKeysGenerated
        case KeysNotFound
        case CertNotFound
        case CertCannotBeCreated
        case CertCannotBeSaved
        case CertificatePublicKeyValidationFailed
        case SignDataFailure
        case SigningFailure(String)
        case unableToSavePublicKey
    }
    
    private static func savePublicKeyToKeyChain(key:SecKey,tag:String) throws {
        let publicKeyAttr : [NSString:AnyObject] = [
            kSecValueRef: key,
            kSecAttrIsPermanent : true,
            kSecAttrApplicationTag : tag,
            kSecAttrKeyClass : kSecAttrKeyClassPrivate
            
        ]
        let addStatus:OSStatus = SecItemAdd(publicKeyAttr, nil)
        guard addStatus == errSecSuccess else {
            throw SecurityError.unableToSavePublicKey
        }
        
        
    }
    private static func getKeyBitsFromKeyChain(tag:String) throws -> NSData {
        let keyAttr : [NSString:AnyObject] = [
            kSecClass : kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyType : kSecAttrKeyTypeRSA,
            kSecReturnData : true
        ]
        var result: AnyObject?
        
        let status = SecItemCopyMatching(keyAttr, &result)
        
        guard status == errSecSuccess else {
            throw SecurityError.KeysNotFound
        }
        
        return result! as! NSData
        
    }
    
    internal static func generateKeyPair(keySize:Int, publicTag:String, privateTag:String)throws -> (publicKey: SecKey, privateKey: SecKey) {
        var status:OSStatus = noErr
        var privateKey:SecKey?
        var publicKey:SecKey?
        
        let privateKeyAttr : [NSString:AnyObject] = [
            kSecAttrIsPermanent : true,
            kSecAttrApplicationTag : privateTag,
            kSecAttrKeyClass : kSecAttrKeyClassPrivate
        ]
        
        let publicKeyAttr : [NSString:AnyObject] = [
            kSecAttrIsPermanent : true,
            kSecAttrApplicationTag : publicTag,
            kSecAttrKeyClass : kSecAttrKeyClassPublic,
        ]
        
        let keyPairAttr : [NSString:AnyObject] = [
            kSecAttrKeyType : kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits : keySize,
            kSecPublicKeyAttrs : publicKeyAttr,
            kSecPrivateKeyAttrs : privateKeyAttr
        ]
        
        status = SecKeyGeneratePair(keyPairAttr, &publicKey, &privateKey)
        
        if (status != errSecSuccess) {
            throw SecurityError.NoKeysGenerated
            
            //TODO : handle error to logger . throw exception?
        } else {
            return (publicKey!, privateKey!)
            //TODO : write success to logger
        }
    }
    
    private static func getKeyPairBitsFromKeyChain(publicTag:String, privateTag:String) throws -> (publicKey: NSData, privateKey: NSData) {
        return try (getKeyBitsFromKeyChain(publicTag),getKeyBitsFromKeyChain(privateTag))
    }
    
    private static func getKeyPairRefFromKeyChain(publicTag:String, privateTag:String) throws -> (publicKey: SecKey, privateKey: SecKey) {
        return try (getKeyRefFromKeyChain(publicTag),getKeyRefFromKeyChain(privateTag))
    }
    
    private static func getKeyRefFromKeyChain(tag:String) throws -> SecKey {
        let keyAttr : [NSString:AnyObject] = [
            kSecClass : kSecClassKey,
            kSecAttrApplicationTag: tag,
            kSecAttrKeyType : kSecAttrKeyTypeRSA,
            kSecReturnRef : kCFBooleanTrue
        ]
        var result: AnyObject?
        
        let status = SecItemCopyMatching(keyAttr, &result)
        
        guard status == errSecSuccess else {
            throw SecurityError.KeysNotFound
        }
        
        return result! as! SecKey
        
    }
    
    internal static func getCertificateFromKeyChain(certificateLabel:String) throws -> SecCertificate {
        let getQuery :  [NSString: AnyObject] = [
            kSecClass : kSecClassCertificate,
            kSecReturnRef : true,
            kSecAttrLabel : certificateLabel
        ]
        var result: AnyObject?
        let getStatus = SecItemCopyMatching(getQuery, &result)
        
        guard getStatus == errSecSuccess else {
            throw SecurityError.CertNotFound
        }
        
        return result as! SecCertificate
    }
    
    func getDataFromKeyChain(label:String) ->  String? {
        //query
        let query: [NSString: AnyObject] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: label,
            kSecReturnData: kCFBooleanTrue
        ]
        var results: AnyObject?
        let status = SecItemCopyMatching(query, &results)
        if status == errSecSuccess {
            let data = results as! NSData
            let password = String(data: data, encoding: NSUTF8StringEncoding)!
            
            return password
        }
        
        return nil
    }
    
    internal static func signCsr(payloadJSON:[String : AnyObject]?, keyIds ids:(publicKey: String, privateKey: String), keySize: Int) throws -> String {
        do {
            try generateKeyPair(keySize, publicTag: ids.publicKey, privateTag: ids.privateKey)
            let base64Options = NSDataBase64EncodingOptions(rawValue:0)
            let strPayloadJSON = Utils.parseDictionaryToJson(payloadJSON)
            //            var publicKeyKey = ids.publicKey.dataUsingEncoding(NSUTF8StringEncoding)!
            //            var privateKeyKey = ids.privateKey.dataUsingEncoding(NSUTF8StringEncoding)!
            
            let keys = try getKeyPairBitsFromKeyChain(ids.publicKey, privateTag: ids.privateKey)
            let publicKey = keys.publicKey
            //            let privateKey = keys.privateKey
            
            let privateKeySec = try getKeyPairRefFromKeyChain(ids.publicKey, privateTag: ids.privateKey).privateKey
            
            guard let strJwsHeaderJSON = Utils.parseDictionaryToJson(getJWSHeaderForPublicKey(publicKey)) else {
                throw SecurityError.SigningFailure("Could not create JWS Header");
            }
            
            
            
            let plainData = strJwsHeaderJSON.dataUsingEncoding(NSUTF8StringEncoding)
            let base64String = plainData?.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
            
            let jwsHeaderData : NSData? = strJwsHeaderJSON.dataUsingEncoding(NSUTF8StringEncoding)
            //            let jwsHeaderBase64 = jwsHeaderData!.base64EncodedStringWithOptions(base64Options)
            let jwsHeaderBase64 = Utils.base64StringFromData(jwsHeaderData!, isSafeUrl: true)
            let payloadJSONData : NSData? = strPayloadJSON!.dataUsingEncoding(NSUTF8StringEncoding)
            //            let payloadJSONBase64 = payloadJSONData!.base64EncodedStringWithOptions(base64Options)
            let payloadJSONBase64 = Utils.base64StringFromData(payloadJSONData!, isSafeUrl: true)
            
            let jwsHeaderAndPayload = jwsHeaderBase64.stringByAppendingString(".".stringByAppendingString(payloadJSONBase64))
            let signedData = try signData(jwsHeaderAndPayload, privateKey:privateKeySec)
            
            //            let signedDataBase64 = signedData.base64EncodedStringWithOptions(base64Options)
            let signedDataBase64 = Utils.base64StringFromData(signedData, isSafeUrl: true)
            
            return jwsHeaderAndPayload.stringByAppendingString(".".stringByAppendingString(signedDataBase64))
        }
        catch {
            throw SecurityError.SigningFailure("\(error)")
        }
    }
    
    private static func getJWSHeaderForPublicKey(publicKey: NSData) ->[String:AnyObject]?
    {
        let base64Options = NSDataBase64EncodingOptions(rawValue:0)
        
        guard let pkModulus : NSData = getPublicKeyMod(publicKey) else {
            return nil
        }
        
        let mod:String = pkModulus.base64EncodedStringWithOptions(base64Options)
        
        guard let pkExponent : NSData = getPublicKeyExp(publicKey) else {
            return nil
        }
        
        let exp:String = pkExponent.base64EncodedStringWithOptions(base64Options)
        
        let publicKeyJSON : [String:AnyObject] = [
            "alg" : "RSA",
            "mod" : mod,
            "exp" : exp
        ]
        let jwsHeaderJSON :[String:AnyObject] = [
            "alg" : "RS256",
            "jpk" : publicKeyJSON
        ]
        return jwsHeaderJSON
        
    }
    
    private static func getPublicKeyMod(publicKeyBits: NSData) -> NSData? {
        var iterator : Int = 0;
        iterator++; // TYPE - bit stream - mod + exp
        derEncodingGetSizeFrom(publicKeyBits, at:&iterator) // Total size
        
        iterator++; // TYPE - bit stream mod
        let mod_size : Int = derEncodingGetSizeFrom(publicKeyBits, at:&iterator)
        if(mod_size == -1) {
            //            IMFLogWarnWithName(CERTMANAGER_PACKAGE, @"Cannot get modulus from publicKey");
            return nil;
        }
        return publicKeyBits.subdataWithRange(NSMakeRange(iterator, mod_size))
    }
    
    //Return public key exponent
    private static func getPublicKeyExp(publicKeyBits: NSData) -> NSData? {
        var iterator : Int = 0;
        iterator++; // TYPE - bit stream - mod + exp
        derEncodingGetSizeFrom(publicKeyBits, at:&iterator) // Total size
        
        iterator++; // TYPE - bit stream mod
        let mod_size : Int = derEncodingGetSizeFrom(publicKeyBits, at:&iterator)
        iterator += mod_size
        
        iterator++; // TYPE - bit stream exp
        let exp_size : Int = derEncodingGetSizeFrom(publicKeyBits, at:&iterator)
        //Ensure we got an exponent size
        if(exp_size == -1) {
            //            IMFLogWarnWithName(CERTMANAGER_PACKAGE, @"Cannot get modulus from publicKey");
            return nil;
        }
        return publicKeyBits.subdataWithRange(NSMakeRange(iterator, exp_size))
    }
    
    private static func derEncodingGetSizeFrom(buf : NSData, inout at iterator: Int) -> Int{
        
        // Have to cast the pointer to the right size
        let pointer = UnsafePointer<UInt8>(buf.bytes)
        let count = buf.length
        
        // Get our buffer pointer and make an array out of it
        let buffer = UnsafeBufferPointer<UInt8>(start:pointer, count:count)
        let data = [UInt8](buffer)
        
        var itr : Int = iterator
        var num_bytes :UInt8 = 1
        var ret : Int = 0
        if (data[itr] > 0x80) {
            num_bytes  = data[itr] - 0x80
            itr++
        }
        
        for var i = 0; i < Int(num_bytes); i++ {
            ret = (ret * 0x100) + Int(data[itr + i])
        }
        
        iterator = itr + Int(num_bytes)
        
        return ret
    }
    
    internal static func signData(payload:String, privateKey:SecKey) throws -> NSData {
        
        let data:NSData = payload.dataUsingEncoding(NSUTF8StringEncoding)!
        
        
        func doSha256(dataIn:NSData) -> NSData {
            var shaOut: NSMutableData! = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH));
            CC_SHA256(dataIn.bytes, CC_LONG(dataIn.length), UnsafeMutablePointer<UInt8>(shaOut.mutableBytes));
            
            return shaOut;
        }
        
        let digest:NSData = doSha256(data)
        
        let signedData: NSMutableData = NSMutableData(length: SecKeyGetBlockSize(privateKey))!
        var signedDataLength: Int = signedData.length
        
        let digestBytes = UnsafePointer<UInt8>(digest.bytes)
        let digestlen = digest.length
        
        let signStatus:OSStatus = SecKeyRawSign(privateKey, SecPadding.PKCS1SHA256, digestBytes, digestlen, UnsafeMutablePointer<UInt8>(signedData.mutableBytes),
            &signedDataLength)
        
        guard signStatus == errSecSuccess else {
            throw SecurityError.SignDataFailure
        }
        
        return signedData
    }
    
    internal static func storeDataInKeychain(data:String, label: String) -> Bool{
        //create
        let key: [NSString: AnyObject] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: label,
            //        kSecAttrAccount: "",
            kSecValueData: data.dataUsingEncoding(NSUTF8StringEncoding)!,
        ]
        let status = SecItemAdd(key, nil)
        
        return status == errSecSuccess
        
    }
    
    internal static func getCertificateFromString(stringData:String) throws -> SecCertificate{
        
        //TODO : oded : unsure about the ignoreUnknownCharacters
        if let data:NSData = NSData(base64EncodedString: stringData, options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters)  {
            if let certificate = SecCertificateCreateWithData(kCFAllocatorDefault, data) {
                return certificate
            }
        }
        throw SecurityError.CertCannotBeCreated
    }
    
    internal static func deleteCertificateFromKeyChain(certificateLabel:String) -> Bool{
        let delQuery : [NSString:AnyObject] = [
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: certificateLabel
        ]
        let delStatus:OSStatus = SecItemDelete(delQuery)
        
        return delStatus == errSecSuccess
        
    }
    
    private static func deleteKeyFromKeyChain(tag:String) -> Bool{
        let delQuery : [NSString:AnyObject] = [
            kSecClass  : kSecClassKey,
            kSecAttrApplicationTag : tag
        ]
        let delStatus:OSStatus = SecItemDelete(delQuery)
        return delStatus == errSecSuccess
    }
    
    
    internal static func saveCertificateToKeyChain(certificate:SecCertificate, certificateLabel:String) throws {
        deleteCertificateFromKeyChain(certificateLabel)
        //make sure certificate is deleted
        //set certificate in key chain
        //    var setQuery = [String:AnyObject]()
        let setQuery: [NSString: AnyObject] = [
            kSecClass: kSecClassCertificate,
            kSecValueRef: certificate,
            kSecAttrLabel: certificateLabel,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let addStatus:OSStatus = SecItemAdd(setQuery, nil)
        
        guard addStatus == errSecSuccess else {
            throw SecurityError.CertCannotBeSaved
        }
    }
    private var publicKeyIdentifier : String {
        get{
            let nameAndVer = Utils.getApplicationDetails()
            return "\(MCAAuthorizationManager._PUBLIC_KEY_LABEL):\(nameAndVer.name!):\(nameAndVer.version!)"
            //            return key.dataUsingEncoding(NSUTF8StringEncoding)!
        }
    }
    internal static func checkCertificatePublicKeyValidity(certificate:SecCertificate, publicKeyTag:String) throws -> Bool{
        let certificatePublicKeyTag = "checkCertificatePublicKeyValidity : publicKeyFromCertificate"
        var publicKeyBits = try getKeyBitsFromKeyChain(publicKeyTag)
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(certificate, policy, &trust)
        //TODO : read documentation and decide if secTrustEvaluate is needed here
        if let unWrappedTrust = trust where status == errSecSuccess {
            if let certificatePublicKey = SecTrustCopyPublicKey(unWrappedTrust) {
                defer {
                    SecurityUtils.deleteKeyFromKeyChain(certificatePublicKeyTag)
                }
                try savePublicKeyToKeyChain(certificatePublicKey, tag: certificatePublicKeyTag)
                var ceritificatePublicKeyBits = try getKeyBitsFromKeyChain(certificatePublicKeyTag)
                
                if(ceritificatePublicKeyBits == publicKeyBits){
                    return true
                }
            }
        }
        throw SecurityError.CertificatePublicKeyValidationFailed
    }
    
    internal static func clearKeyChain()  {
        let availableKSecClasses = [kSecClassCertificate, kSecClassGenericPassword, kSecClassIdentity, kSecClassInternetPassword, kSecClassKey]
        for availableKSecClass in availableKSecClasses {
            let query = [ kSecClass as String : availableKSecClass ]
            SecItemDelete(query)
        }
    }
    
    internal static func getClientIdFromCertificate(certificate:SecCertificate?) throws -> String{
        
        if let unWrappedCertificate = certificate {
            
        } else {
            //TODO : handle error
        }
        return ""
    }
    
    //    //subjectDN is of the form: "UID=<clientId>, DC=<some other value>" or "DC=<some other value>, UID=<clientId>"
    //    String clientId = null;
    //
    //    String subjectDN = certificate.getSubjectDN().getName();
    //    String[] parts = subjectDN.split(Pattern.quote(","));
    //    for (String part: parts){
    //    if (part.contains("UID=")){
    //    String uid=part.substring(part.indexOf("UID="));
    //    clientId = uid.split(Pattern.quote("="))[1];
    //    }
    //    }
    //
    //    return clientId;
    //    }
    
    
}