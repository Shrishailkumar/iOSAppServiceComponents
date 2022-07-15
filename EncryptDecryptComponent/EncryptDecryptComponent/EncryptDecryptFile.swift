//
//  EncryptDecryptFile.swift
//  EncryptDecryptComponent
//
//  Created by Prajakta Kiran Patil on 13/07/22.
//

import Foundation
import CryptoSwift

extension String {

    func cryptoSwiftAESEncrypt(key: String, iv: String ) -> String? {
        guard let dec = try? AES(key: key, iv: iv, padding: .pkcs7).encrypt(Array(self.utf8)) else {   return nil }
        let decData = Data(bytes: dec, count: Int(dec.count)).base64EncodedString(options: .lineLength64Characters)
        return decData
    }
    
    func cryptoSwiftAESDecrypt(key: String, iv: String) -> String? {
            guard let data = Data(base64Encoded: self),
                  let dec = try? AES(key: key, iv: iv, padding: .pkcs7).decrypt(data.bytes) else { return nil }
            
            let decData = Data(bytes: dec, count: Int(dec.count))
            return String(data: decData, encoding: .utf8)
    }
}
