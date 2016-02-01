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