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
        
        let keyPair:[String:AnyObject] = [ kSecAttrKeyType as String : kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String : keySize]
        //TODO : should I save it to keychain? how?
        status = SecKeyGeneratePair(keyPair, &publicKey, &privateKey)
        
        
        
        
        if (status != errSecSuccess) {
            return (nil,nil)
            //TODO : handle error to logger . throw exception?
        } else {
            //TODO : currently deleting current keys for tags. is it ok?
            var delQuery = [String:AnyObject]()
            delQuery[kSecClass as String] = kSecClassKey
            delQuery[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
            delQuery[kSecAttrApplicationTag as String] =  privateTag
            SecItemDelete(delQuery)
            delQuery[kSecClass as String] = kSecClassKey
            delQuery[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
            delQuery[kSecAttrApplicationTag as String] =  publicTag
            SecItemDelete(delQuery)
            
            var setQueryPrivateKey = [String:AnyObject]()
            setQueryPrivateKey[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
            setQueryPrivateKey[kSecAttrKeySizeInBits as String] = keySize
            setQueryPrivateKey[kSecAttrApplicationTag as String] =  privateTag
            setQueryPrivateKey[kSecValueRef as String] = privateKey
            
            
            var setQueryPublicKey = [String:AnyObject]()
            setQueryPublicKey[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
            setQueryPublicKey[kSecAttrKeySizeInBits as String] = keySize
            setQueryPublicKey[kSecAttrApplicationTag as String] =  publicTag
            setQueryPublicKey[kSecValueRef as String] = publicKey
            
            
            var addStatus:OSStatus = SecItemAdd(setQueryPrivateKey, nil)
            addStatus = SecItemAdd(setQueryPublicKey, nil)
            
            //TODO : treat failure in add and delete
            return (publicKey,privateKey)
            //TODO : write success to logger
        }
    }
    
    public func getKeyPair(publicTag:String, privateTag:String) -> (SecKey?,SecKey?){
        var getQuery =  [String: AnyObject]()
        getQuery[kSecClass as String] = kSecClassKey
        getQuery[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        getQuery[kSecAttrApplicationTag as String] =  publicTag
        getQuery[kSecReturnRef as String] = true
        var resultPublic: AnyObject?
        var resultPrivate: AnyObject?
        var getStatus = SecItemCopyMatching(getQuery, &resultPublic)
        var publicKey = resultPublic! as! SecKey
        getQuery[kSecAttrApplicationTag as String] =  privateTag
        getStatus = SecItemCopyMatching(getQuery, &resultPrivate)
        var privateKey = resultPrivate! as! SecKey
        return (publicKey,privateKey)
        //TODO : handle failure status
    }
    
    public func getCertificateFromKeyChain(certificateTag:String) -> SecCertificate?{
        var getQuery =  [String: AnyObject]()
        getQuery[kSecClass as String] = kSecClassCertificate
        getQuery[kSecReturnRef as String] = true
        getQuery[kSecAttrLabel as String] = certificateTag
        var result: AnyObject?
        let getStatus = SecItemCopyMatching(getQuery, &result)
        
        //TODO : check type of result?
        if result != nil {
            return result as! SecCertificate
        } else {
            //TODO : throw exception?
            return nil
        }
    }
    
    public func saveCertificateToKeyChain(certificate:SecCertificate, certificateTag:String){
        
        //TODO : oded : unsure about the ignoreUnknownCharacters
        
        //make sure certificate is deleted
        var delQuery = [String:AnyObject]()
        delQuery[kSecClass as String] = kSecClassCertificate
        delQuery[kSecAttrLabel as String] = certificateTag
        SecItemDelete(delQuery)
        //set certificate in key chain
        var setQuery = [String:AnyObject]()
        setQuery[kSecClass as String] = kSecClassCertificate
        setQuery[kSecValueRef as String] = certificate
        setQuery[kSecAttrLabel as String] = certificateTag
        var addStatus:OSStatus = SecItemAdd(setQuery, nil)
        //TODO : handle bad status
        
        //TODO : handle errors
        
    }
    
    public func getCertificateFromString(stringData:String) -> SecCertificate?{
        
        //TODO : oded : unsure about the ignoreUnknownCharacters
        if let data:NSData = NSData(base64EncodedString: stringData, options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters)  {
            var certificate = SecCertificateCreateWithData(kCFAllocatorDefault, data)
            return certificate
        }
        return nil
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