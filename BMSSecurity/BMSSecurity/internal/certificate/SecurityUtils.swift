//
//  SecurityUtils.swift
//  BMSSecurity
//
//  Created by Oded Betzalel on 1/3/16.
//  Copyright © 2016 IBM. All rights reserved.
//

import Foundation

public class SecurityUtils {
    public private(set) var storedKeyPair:(publicKey:SecKey?,privateKey:SecKey?)?
    //    public private(set) var certificate:SecCertificate?
    public  func generateKeyPair(keySize:Int) -> (publicKey: SecKey?, privateKey: SecKey?){
        var status:OSStatus = noErr
        var privateKey:SecKey?
        var publicKey:SecKey?
        
        let keyPair:[String:AnyObject] = [ kSecAttrKeyType as String : kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String : keySize]
        //TODO : should I save it to keychain? how?
        status = SecKeyGeneratePair(keyPair, &publicKey, &privateKey)
        
        if (status != errSecSuccess) {
            self.storedKeyPair = (nil,nil)
            //TODO : handle error to logger
        } else {
            self.storedKeyPair = (publicKey,privateKey)
            //TODO : write success to logger
        }
        return self.storedKeyPair!
    }
    
    
    public func getCertificateFromKeyChain() -> SecCertificate?{
        var getQuery =  [String: AnyObject]()
        getQuery[kSecClass as String] = kSecClassCertificate
        getQuery[kSecReturnRef as String] = true
        var result: AnyObject?
        let getStatus = SecItemCopyMatching(getQuery, &result)
        print(getStatus)
        print(result!)
        //TODO : check type of result?
        if result != nil {
            return result as! SecCertificate
        } else {
            //TODO : throw exception?
            return nil
        }
    }
    
    public func saveCertificateToKeyChain(data:NSData){
        
        //TODO : oded : unsure about the ignoreUnknownCharacters
        if let cert = SecCertificateCreateWithData(kCFAllocatorDefault, data) {
            //make sure certificate is deleted
            var delQuery = [String:AnyObject]()
            delQuery[kSecClass as String] = kSecClassCertificate
            SecItemDelete(delQuery)
            //set certificate in key chain
            var setQuery = [String:AnyObject]()
            setQuery[kSecClass as String] = kSecClassCertificate
            setQuery[kSecValueRef as String] = cert
            var addStatus:OSStatus = SecItemAdd(setQuery, nil)
            //TODO : handle bad status
        }
        //TODO : handle errors
        
    }
    
    public func getCertificateFromString(stringData:String) -> SecCertificate?{
        
        //TODO : oded : unsure about the ignoreUnknownCharacters
        if let data:NSData = NSData(base64EncodedString: stringData, options: NSDataBase64DecodingOptions.IgnoreUnknownCharacters)  {
            var certificate = SecCertificateCreateWithData(kCFAllocatorDefault, data)
            saveCertificateToKeyChain(data)
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