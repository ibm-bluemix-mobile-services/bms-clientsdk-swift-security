//
//  SecurityUtils.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 1/3/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import Foundation
import CryptoSwift
import CommonCrypto

public class SecurityUtils {
    
    
    static let _base64DecodingTable: [Int8] = [
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -1, -1, -2, -1, -1, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -1, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -2, -2, -2,
        -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
        -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
        -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
    ]
    
    static let base64EncodingTableString = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    static let base64EncodingTable = [Character](base64EncodingTableString.characters)
    static let base64EncodingTableUrlSafeString = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    static let base64EncodingTableUrlSafe = [Character](base64EncodingTableUrlSafeString.characters)
    
    static func _base64StringFromData(data: NSData, length:Int, isSafeUrl: Bool) -> String {
        
        
//        unsigned long ixtext, lentext;
//        long ctremaining;
//        unsigned char input[3], output[4];
//        short i, charsonline = 0, ctcopy;
//        const unsigned char *raw;
//        NSMutableString *result;
//        
//        lentext = [data length];
//        if (lentext < 1)
//        return @"";
//        result = [NSMutableString stringWithCapacity: lentext];
//        raw = [data bytes];
//        ixtext = 0;
//        
//        while (true) {
//            ctremaining = lentext - ixtext;
//            if (ctremaining <= 0)
//            break;
//            for (i = 0; i < 3; i++) {
//                unsigned long ix = ixtext + i;
//                if (ix < lentext)
//                input[i] = raw[ix];
//                else
//                input[i] = 0;
//            }
//            output[0] = (input[0] & 0xFC) >> 2;
//            output[1] = ((input[0] & 0x03) << 4) | ((input[1] & 0xF0) >> 4);
//            output[2] = ((input[1] & 0x0F) << 2) | ((input[2] & 0xC0) >> 6);
//            output[3] = input[2] & 0x3F;
//            ctcopy = 4;
//            switch (ctremaining) {
//            case 1:
//                ctcopy = 2;
//                break;
//            case 2:
//                ctcopy = 3;
//                break;
//            }
//            
//            for (i = 0; i < ctcopy; i++)
//            [result appendString: [NSString stringWithFormat: @"%c", isSafeUrl ? base64EncodingTableUrlSafe[output[i]]: base64EncodingTable[output[i]]]];
//            
//            for (i = ctcopy; i < 4; i++)
//            [result appendString: @"="];
//            
//            ixtext += 3;
//            charsonline += 4;
//            
//            if ((length > 0) && (charsonline >= length))
//            charsonline = 0;
//        }
//        return result;
        return ""
    }
    
    enum SecurityError : ErrorType{
        case NoKeysGenerated
        case KeysNotFound
        case CertNotFound
        case CertCannotBeCreated
        case CertCannotBeSaved
        case CertificatePublicKeyValidationFailed
        case SignDataFailure
        case SigningFailure(String)
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
    
    internal static func getKeyPairBitsFromKeyChain(publicTag:String, privateTag:String) throws -> (publicKey: NSData, privateKey: NSData) {
        var privateKey:NSData
        var publicKey:NSData
        
        let privateKeyAttr : [NSString:AnyObject] = [
            kSecClass : kSecClassKey,
            kSecAttrApplicationTag: privateTag,
            kSecAttrKeyType : kSecAttrKeyTypeRSA,
            kSecReturnData : true
        ]
        let publicKeyAttr : [NSString:AnyObject] = [
            kSecClass : kSecClassKey,
            kSecAttrApplicationTag: publicTag,
            kSecAttrKeyType : kSecAttrKeyTypeRSA,
            kSecReturnData : true
        ]
        var resultPublic: AnyObject?
        var resultPrivate: AnyObject?
       
        let getPrivateStatus = SecItemCopyMatching(privateKeyAttr, &resultPrivate)
        let getPublicStatus = SecItemCopyMatching(publicKeyAttr, &resultPublic)
        
        guard getPublicStatus == errSecSuccess && getPrivateStatus == errSecSuccess else {
            throw SecurityError.KeysNotFound
        }
       
        publicKey = resultPublic! as! NSData
        privateKey = resultPrivate! as! NSData
        
        return (publicKey, privateKey)
    }
    
    internal static func getKeyPairRefFromKeyChain(publicTag:String, privateTag:String) throws -> (publicKey: SecKey, privateKey: SecKey){
        var privateKey:SecKey
        var publicKey:SecKey
        
        let privateKeyAttr : [NSString:AnyObject] = [
            kSecClass : kSecClassKey,
            kSecAttrApplicationTag: privateTag,
            kSecAttrKeyType : kSecAttrKeyTypeRSA,
            kSecReturnRef : kCFBooleanTrue,
        ]
        let publicKeyAttr : [NSString:AnyObject] = [
            kSecClass : kSecClassKey,
            kSecAttrApplicationTag: publicTag,
            kSecAttrKeyType : kSecAttrKeyTypeRSA,
            kSecReturnRef : kCFBooleanTrue,
        ]
        var resultPublic: AnyObject?
        var resultPrivate: AnyObject?
        let getPublicStatus = SecItemCopyMatching(publicKeyAttr, &resultPublic)
        let getPrivateStatus = SecItemCopyMatching(privateKeyAttr, &resultPrivate)
        
        guard getPublicStatus == errSecSuccess && getPrivateStatus == errSecSuccess else {
            throw SecurityError.KeysNotFound
        }
        
        publicKey = resultPublic! as! SecKey
        privateKey = resultPrivate! as! SecKey

        return (publicKey, privateKey)
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
           
            func encodeSafe64(data:NSData) ->String {
                let signedNotSafe = data.base64EncodedStringWithOptions(base64Options)
                
                return signedNotSafe.stringByReplacingOccurrencesOfString("/", withString: "_").stringByReplacingOccurrencesOfString("+", withString: "-")
            }
            

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
            let jwsHeaderBase64 = encodeSafe64(jwsHeaderData!)
            let payloadJSONData : NSData? = strPayloadJSON!.dataUsingEncoding(NSUTF8StringEncoding)
//            let payloadJSONBase64 = payloadJSONData!.base64EncodedStringWithOptions(base64Options)
            let payloadJSONBase64 = encodeSafe64(payloadJSONData!)
            
            let jwsHeaderAndPayload = jwsHeaderBase64.stringByAppendingString(".".stringByAppendingString(payloadJSONBase64))
            let signedData = try signData(jwsHeaderAndPayload, privateKey:privateKeySec)
            
//            let signedDataBase64 = signedData.base64EncodedStringWithOptions(base64Options)
            let signedDataBase64 = encodeSafe64(signedData)
            
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
    
    private static func verifySignData(string: String, signature: NSData, publicKey: SecKey?) -> Bool {
      
        let stringData: NSData = string.dataUsingEncoding(NSUTF8StringEncoding)!
        let digest = stringData.sha256()!
        
        let digestBytes = UnsafePointer<UInt8>(digest.bytes)
        let digestlen = digest.length
        
        let verifyStatus: OSStatus = SecKeyRawVerify(publicKey!, SecPadding.PKCS1SHA256, digestBytes, digestlen, UnsafeMutablePointer<UInt8>(signature.bytes), signature.length
        )
        if verifyStatus == errSecSuccess {
            return true
        } else {
            //TODO handle failure
            return false
        }
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

    internal static func checkCertificatePublicKeyValidity(certificate:SecCertificate?, publicKey:SecKey?) throws -> Bool{
        
        if let unWrappedCertificate = certificate, unWrappedPublicKey = publicKey {
            let policy = SecPolicyCreateBasicX509()
            var trust: SecTrust?
            let status = SecTrustCreateWithCertificates(unWrappedCertificate, policy, &trust)
            //TODO : read documentation and decide if secTrustEvaluate is needed here
            if let unWrappedTrust = trust where status == errSecSuccess {
                let certificatePublicKey = SecTrustCopyPublicKey(unWrappedTrust)
                if(String(certificatePublicKey) == String(unWrappedPublicKey)){
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