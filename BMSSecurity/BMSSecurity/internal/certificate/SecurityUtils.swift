//
//  SecurityUtils.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 1/3/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import Foundation
import CryptoSwift

public class SecurityUtils {
    
    public func generateKeyPair(keySize:Int, publicTag:String, privateTag:String) -> (publicKey: SecKey?, privateKey: SecKey?){
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
            return (nil,nil)
            //TODO : handle error to logger . throw exception?
        } else {
            return (publicKey,privateKey)
            //TODO : write success to logger
        }
    }
    
    public func getKeyPairBitsFromKeyChain(publicTag:String, privateTag:String) -> (publicKey: NSData?, privateKey: NSData?){
        var privateKey:NSData?
        var publicKey:NSData?
        
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
        let getPublicStatus = SecItemCopyMatching(privateKeyAttr, &resultPublic)
        if (getPublicStatus == errSecSuccess) {
            publicKey = resultPublic! as! NSData
        } else {
            //TODO : throw exception
        }
        let getPrivateStatus = SecItemCopyMatching(publicKeyAttr, &resultPrivate)
        if (getPrivateStatus == errSecSuccess) {
            privateKey = resultPrivate! as! NSData
        } else {
            //TODO : throw exception
        }
        
        return (publicKey,privateKey)
    }
    
    public func getKeyPairRefFromKeyChain(publicTag:String, privateTag:String) -> (publicKey: SecKey?, privateKey: SecKey?){
        var privateKey:SecKey?
        var publicKey:SecKey?
        
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
        if (getPublicStatus == errSecSuccess) {
            publicKey = resultPublic! as! SecKey
        } else {
            //TODO : throw exception
        }
        let getPrivateStatus = SecItemCopyMatching(privateKeyAttr, &resultPrivate)
        if (getPrivateStatus == errSecSuccess) {
            privateKey = resultPrivate! as! SecKey
        } else {
            //TODO : throw exception
        }
        return (publicKey,privateKey)
    }
    
    public func getCertificateFromKeyChain(certificateLabel:String) -> SecCertificate?{
        let getQuery :  [NSString: AnyObject] = [
            kSecClass : kSecClassCertificate,
            kSecReturnRef : true,
            kSecAttrLabel : certificateLabel
        ]
        var result: AnyObject?
        let getStatus = SecItemCopyMatching(getQuery, &result)
        if getStatus == errSecSuccess && result != nil {
            return result as! SecCertificate
        } else {
            //TODO : throw exception?
            return nil
        }
    }
    
    func getDataForLable(lable:String) ->  String? {
        //query
        let query: [NSString: AnyObject] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: lable,
            //        kSecAttrAccount: "",
            kSecReturnData: kCFBooleanTrue,
            //        kSecMatchLimit: kSecMatchLimitOne,
        ]
        var results: AnyObject?
        let status2 = SecItemCopyMatching(query, &results)
        if status2 == errSecSuccess {
            let data = results as! NSData
            let password = String(data: data, encoding: NSUTF8StringEncoding)!
            
            return password
        }
        
        return nil
    }
    
    public func parseDictionaryToJson(dict: [String:AnyObject]? ) -> String?{
        if let myDict = dict{
            do{
                let jsonData:NSData =  try NSJSONSerialization.dataWithJSONObject(myDict, options: [])
                return String(data: jsonData, encoding:NSUTF8StringEncoding)
            } catch {
                //TODO : handle error
            }
        }
        return nil
    }
    
    func signCsr(payloadJSON:[String : AnyObject]?, withKeyLabels labels:(publicKey: String?, privateKey: String?), withKeySize keySize: Int) -> String?{
        generateKeyPair(keySize, publicTag: labels.publicKey!, privateTag: labels.privateKey!)
        let base64Options = NSDataBase64EncodingOptions(rawValue:0)

        let strPayloadJSON = parseDictionaryToJson(payloadJSON)
        var publicKeyKey = labels.publicKey?.dataUsingEncoding(NSUTF8StringEncoding)!
        var privateKeyKey = labels.privateKey?.dataUsingEncoding(NSUTF8StringEncoding)!
        
        let keys = getKeyPairBitsFromKeyChain(labels.publicKey!, privateTag: labels.privateKey!)
        let publicKey = keys.publicKey
        let privateKey = keys.privateKey
        
        let privateKeySec = getKeyPairRefFromKeyChain(labels.publicKey!, privateTag: labels.privateKey!).privateKey
        
        let strJwsHeaderJSON = parseDictionaryToJson (getJWSHeaderForPublicKey(publicKey))
        
        var jwsHeaderData : NSData? = strJwsHeaderJSON?.dataUsingEncoding(NSUTF8StringEncoding)
        let jwsHeaderBase64 = jwsHeaderData!.base64EncodedStringWithOptions(base64Options)
        let payloadJSONData : NSData? = strPayloadJSON!.dataUsingEncoding(NSUTF8StringEncoding)
        let payloadJSONBase64 = payloadJSONData!.base64EncodedStringWithOptions(base64Options)
        
        let jwsHeaderAndPayload = jwsHeaderBase64.stringByAppendingString(".".stringByAppendingString(payloadJSONBase64))
        var signedData = signData(jwsHeaderAndPayload, privateKey:privateKeySec)
        var signedDataBase64 = signedData!.base64EncodedStringWithOptions(base64Options)
        
        
        return jwsHeaderAndPayload.stringByAppendingString(".".stringByAppendingString(signedDataBase64))
    }
   
    public func getJWSHeaderForPublicKey(publicKey:NSData?) ->[String:AnyObject]?
    {
        let base64Options = NSDataBase64EncodingOptions(rawValue:0)
        
        guard let pkModulus : NSData = getPublicKeyMod(publicKey!) else {
            return nil
        }
        
        let mod:String = pkModulus.base64EncodedStringWithOptions(base64Options)
        
        guard let pkExponent : NSData = getPublicKeyExp(publicKey!) else {
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
    
    private func getPublicKeyMod(publicKeyBits: NSData) -> NSData? {
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
    private func getPublicKeyExp(publicKeyBits: NSData) -> NSData? {
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
    
    private func derEncodingGetSizeFrom(buf : NSData, inout at iterator: Int) -> Int{
        
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
    
    
//    //Helper function to return modulu/exponent
//    + (int)derEncodingGetSizeFrom:(NSData*)buf at:(int*)iterator {
//    if(buf == nil || [buf length] <= 0 ){
//    IMFLogWarnWithName(CERTMANAGER_PACKAGE, @"buffer was empty, unable to get encoding size");
//    return -1;
//    }
//    const uint8_t* data = [buf bytes];
//    int itr = *iterator;
//    int num_bytes = 1;
//    int ret = 0;
//    if (data[itr] > 0x80) {
//    num_bytes = data[itr] - 0x80;
//    itr++;
//    }
//    for (int i = 0 ; i < num_bytes; i++) ret = (ret * 0x100) + data[itr + i];
//    *iterator = itr + num_bytes;
//    return ret;
//    }

    
    public func verifySignData(string: String, signature: NSData, publicKey: SecKey?) -> Bool {
        //        let sha256DigestPrefix:[UInt8] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,0x48, 0x01, 0x65, 0x03,0x04, 0x02, 0x01, 0x05,0x00, 0x04, 0x20] as [UInt8]
        //        let sha256DigestPrefixAsData = NSData(bytes: sha256DigestPrefix, length: sha256DigestPrefix.count)
        //
        //
        
        //        let sha256DigestPrefix = "484948136996134721101342150432"
        //        let sha256DigestPrefixAsData = sha256DigestPrefix.dataUsingEncoding(NSUTF8StringEncoding)!
        
        let stringData: NSData = string.dataUsingEncoding(NSUTF8StringEncoding)!
        let digest = stringData.sha256()!
        
        //        let mutableFullDigest:NSMutableData = NSMutableData(length: sha256DigestPrefixAsData.length + digest.length)!
        //        mutableFullDigest.appendData(sha256DigestPrefixAsData)
        //        mutableFullDigest.appendData(digest)
        //        let fullDigest:NSData = NSData(data: mutableFullDigest)
        //
        //
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
    public func signData(payload:String, privateKey:SecKey?) -> NSData? {
        //
        ////        let sha256DigestPrefix:[UInt8] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,0x48, 0x01, 0x65, 0x03,0x04, 0x02, 0x01, 0x05,0x00, 0x04, 0x20] as [UInt8]
        //        let sha256DigestPrefix = "484948136996134721101342150432"
        //        let sha256DigestPrefixAsData = sha256DigestPrefix.dataUsingEncoding(NSUTF8StringEncoding)!
        ////        let sha256DigestPrefixAsData = NSData(bytes: sha256DigestPrefix, length: sha256DigestPrefix.count)
        
        
        let data:NSData = payload.dataUsingEncoding(NSUTF8StringEncoding)!
        let digest:NSData = data.sha256()!
        
        //
        //        let mutableFullDigest:NSMutableData = NSMutableData(data: sha256DigestPrefixAsData)
        //        mutableFullDigest.appendData(digest)
        //        let fullDigest:NSData = NSData(data: mutableFullDigest)
        //
        //
        let signedData: NSMutableData = NSMutableData(length: SecKeyGetBlockSize(privateKey!))!
        var signedDataLength: Int = signedData.length
        
        let digestBytes = UnsafePointer<UInt8>(digest.bytes)
        let digestlen = digest.length
        
        let signStatus:OSStatus = SecKeyRawSign(privateKey!, SecPadding.PKCS1SHA256, digestBytes, digestlen, UnsafeMutablePointer<UInt8>(signedData.mutableBytes),
            &signedDataLength)
        if signStatus == errSecSuccess {
            return signedData
        } else {
            //TODO handle failure
            return nil
        }
    }

    func addDataForLabel(data:String, label: String) {
        //create
        let key: [NSString: AnyObject] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: label,
            //        kSecAttrAccount: "",
            kSecValueData: data.dataUsingEncoding(NSUTF8StringEncoding)!,
        ]
        let status = SecItemAdd(key, nil)
    }
    
    public func getCertificateFromString(stringData:String) -> SecCertificate?{
        
        //TODO : oded : unsure about the ignoreUnknownCharacters
        if let data:NSData = NSData(base64EncodedString: stringData, options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters)  {
            let certificate = SecCertificateCreateWithData(kCFAllocatorDefault, data)
            return certificate
        }
        return nil
    }
    public func deleteCertificateFromKeyChain(certificateLabel:String){
        let delQuery : [NSString:AnyObject] = [
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: certificateLabel
        ]
        let delStatus:OSStatus = SecItemDelete(delQuery)
        
    }
    public func saveCertificateToKeyChain(certificate:SecCertificate, certificateLabel:String){
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
        if addStatus != errSecSuccess  {
            //TODO : throw exception?
        }
        //TODO : handle bad status
        
        //TODO : handle errors
        
    }

    public func checkCertificatePublicKeyValidity(certificate:SecCertificate?, publicKey:SecKey?) -> Bool{
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
        return false
    }
    public func clearKeyChain()  {
        let availableKSecClasses = [kSecClassCertificate, kSecClassGenericPassword, kSecClassIdentity, kSecClassInternetPassword, kSecClassKey]
        for availableKSecClass in availableKSecClasses {
            let query = [ kSecClass as String : availableKSecClass ]
            SecItemDelete(query)
        }
    }
    public func getClientIdFromCertificate(certificate:SecCertificate?) throws -> String{
        
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