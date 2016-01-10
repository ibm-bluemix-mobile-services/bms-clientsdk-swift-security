//
//  SecurityUtils.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 1/3/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import Foundation

public class SecurityUtils {
    
    public  func generateKeyPair(keySize:Int, publicTag:String, privateTag:String) -> (publicKey: SecKey?, privateKey: SecKey?){
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
    
    public  func getKeyPair(publicTag:String, privateTag:String) -> (publicKey: SecKey?, privateKey: SecKey?){
        var privateKey:SecKey?
        var publicKey:SecKey?
        
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
            publicKey = resultPublic! as! SecKey
        } else {
            //TODO : throw exception
        }
        let getPrivateStatus = SecItemCopyMatching(publicKeyAttr, &resultPrivate)
        if (getPrivateStatus == errSecSuccess) {
            privateKey = resultPrivate! as! SecKey
        } else {
            //TODO : throw exception
        }
        return (publicKey,privateKey)
    }
    
    public func getCertificateFromKeyChain(certificateLabel:String) -> SecCertificate?{
        var getQuery =  [String: AnyObject]()
        getQuery[kSecClass as String] = kSecClassCertificate
        getQuery[kSecReturnRef as String] = true
        getQuery[kSecAttrLabel as String] = certificateLabel
        var result: AnyObject?
        let getStatus = SecItemCopyMatching(getQuery, &result)
        if getStatus == errSecSuccess && result != nil {
            return result as! SecCertificate
        } else {
            //TODO : throw exception?
            return nil
        }
    }
    
    func get(lable:String) ->  String? {
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
    func add(data:String, label: String) {
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
    public func saveCertificateToKeyChain(certificate:SecCertificate, certificateLabel:String){
        
        //make sure certificate is deleted
        let delQuery : [NSString:AnyObject] = [
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: certificateLabel
        ]
        let delStatus:OSStatus = SecItemDelete(delQuery)
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