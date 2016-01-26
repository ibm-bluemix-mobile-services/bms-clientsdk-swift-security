//
//  AESStringEncryption.swift
//  BMSSecurity
//
//  Created by Ilan Klein on 31/12/2015.
//  Copyright © 2015 IBM. All rights reserved.
//

import Foundation

public class AESStringEncryption : StringEncryption{
    public func encrypt(str:String)->String {
        
        //        var sec:SecurityUtils = SecurityUtils()
        //        sec.generateKeyPair(512, publicTag: "1", privateTag: "2").privateKey
        //        var cipherLen:size_t = 128; // currently RSA key length is set to 128 bytes
        //        var cipher:UnsafeMutablePointer<UInt8>? = nil
        //
        //        SecKeyEncrypt(sec.generateKeyPair(512, publicTag: "1", privateTag: "2").privateKey!, SecPadding.PKCS1, str, str.characters.count, cipher!, &cipherLen)
        //        return (cipher as! String)
        //    }
        //    public func decrypt(str:String)->String {
        //        return ""
        //    }
        return str
    }
    public func decrypt(str:String)->String {

        
        return str
    
    }
    
}