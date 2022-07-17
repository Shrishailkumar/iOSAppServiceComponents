//
//  EncryptDecryptFile.swift
//  iOSEncryptDecryptLib
//
//  Created by Prajakta Kiran Patil on 16/07/22.
//

import Foundation
import CommonCrypto
import CryptoKit

// -------- Common Crypto -----------
protocol Cryptable {
    func encrypt(_ string: String) throws -> Data
    func decrypt(_ data: Data) throws -> String
}
//
public class AESClass : Cryptable {

     private let key: Data
     private let ivSize: Int         = kCCBlockSizeAES128
     private let options: CCOptions  = CCOptions(kCCOptionPKCS7Padding)

    public init(keyString: String) throws {
        guard keyString.count == kCCKeySizeAES256 else {
            throw Error.invalidKeySize
        }
        self.key = Data(keyString.utf8)
    }

   public func encrypt(_ string: String) throws -> Data {
       let dataToEncrypt = Data(string.utf8)

       let bufferSize: Int = ivSize + dataToEncrypt.count + kCCBlockSizeAES128
       var buffer = Data(count: bufferSize)
       try generateRandomIV(for: &buffer)

       var numberBytesEncrypted: Int = 0

       do {
           try key.withUnsafeBytes { keyBytes in
               try dataToEncrypt.withUnsafeBytes { dataToEncryptBytes in
                   try buffer.withUnsafeMutableBytes { bufferBytes in

                       guard let keyBytesBaseAddress = keyBytes.baseAddress,
                           let dataToEncryptBytesBaseAddress = dataToEncryptBytes.baseAddress,
                           let bufferBytesBaseAddress = bufferBytes.baseAddress else {
                               throw Error.encryptionFailed
                       }

                       let cryptStatus: CCCryptorStatus = CCCrypt( // Stateless, one-shot encrypt operation
                           CCOperation(kCCEncrypt),                // op: CCOperation
                           CCAlgorithm(kCCAlgorithmAES),           // alg: CCAlgorithm
                           options,                                // options: CCOptions
                           keyBytesBaseAddress,                    // key: the "password"
                           key.count,                              // keyLength: the "password" size
                           bufferBytesBaseAddress,                 // iv: Initialization Vector
                           dataToEncryptBytesBaseAddress,          // dataIn: Data to encrypt bytes
                           dataToEncryptBytes.count,               // dataInLength: Data to encrypt size
                           bufferBytesBaseAddress + ivSize,        // dataOut: encrypted Data buffer
                           bufferSize,                             // dataOutAvailable: encrypted Data buffer size
                           &numberBytesEncrypted                   // dataOutMoved: the number of bytes written
                       )

                       guard cryptStatus == CCCryptorStatus(kCCSuccess) else {
                           throw Error.encryptionFailed
                       }
                   }
               }
           }

       } catch {
           throw Error.encryptionFailed
       }

       let encryptedData: Data = buffer[..<(numberBytesEncrypted + ivSize)]
       return encryptedData
   }

   public func decrypt(_ data: Data) throws -> String {

       let bufferSize: Int = data.count - ivSize
       var buffer = Data(count: bufferSize)

       var numberBytesDecrypted: Int = 0

       do {
           try key.withUnsafeBytes { keyBytes in
               try data.withUnsafeBytes { dataToDecryptBytes in
                   try buffer.withUnsafeMutableBytes { bufferBytes in

                       guard let keyBytesBaseAddress = keyBytes.baseAddress,
                           let dataToDecryptBytesBaseAddress = dataToDecryptBytes.baseAddress,
                           let bufferBytesBaseAddress = bufferBytes.baseAddress else {
                               throw Error.encryptionFailed
                       }

                       let cryptStatus: CCCryptorStatus = CCCrypt( // Stateless, one-shot encrypt operation
                           CCOperation(kCCDecrypt),                // op: CCOperation
                           CCAlgorithm(kCCAlgorithmAES128),        // alg: CCAlgorithm
                           options,                                // options: CCOptions
                           keyBytesBaseAddress,                    // key: the "password"
                           key.count,                              // keyLength: the "password" size
                           dataToDecryptBytesBaseAddress,          // iv: Initialization Vector
                           dataToDecryptBytesBaseAddress + ivSize, // dataIn: Data to decrypt bytes
                           bufferSize,                             // dataInLength: Data to decrypt size
                           bufferBytesBaseAddress,                 // dataOut: decrypted Data buffer
                           bufferSize,                             // dataOutAvailable: decrypted Data buffer size
                           &numberBytesDecrypted                   // dataOutMoved: the number of bytes written
                       )

                       guard cryptStatus == CCCryptorStatus(kCCSuccess) else {
                           throw Error.decryptionFailed
                       }
                   }
               }
           }
       } catch {
           throw Error.encryptionFailed
       }

       let decryptedData: Data = buffer[..<numberBytesDecrypted]

       guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
           throw Error.dataToStringFailed
       }

       return decryptedString
   }

}

extension AESClass {
    enum Error: Swift.Error {
        case invalidKeySize
        case generateRandomIVFailed
        case encryptionFailed
        case decryptionFailed
        case dataToStringFailed
    }
}

private extension AESClass {

    func generateRandomIV(for data: inout Data) throws {

        try data.withUnsafeMutableBytes { dataBytes in

            guard let dataBytesBaseAddress = dataBytes.baseAddress else {
                throw Error.generateRandomIVFailed
            }

            let status: Int32 = SecRandomCopyBytes(
                kSecRandomDefault,
                kCCBlockSizeAES128,
                dataBytesBaseAddress
            )

            guard status == 0 else {
                throw Error.generateRandomIVFailed
            }
        }
    }
}


//-------- Cryptokit-----------

public class CryptoKitClass {

    var textString: String!

    
    let randomKey = SymmetricKey(size: .bits256)
    public struct PublicKeyExtraData: Codable {
        var publicKey: String?

    }
    
    public init(textString: String) {
            self.textString = textString
    }
    
    public func encryptFunc() throws -> String {
        let textData = textString.data(using: .utf8)!
        let encrypted = try AES.GCM.seal(textData, using: randomKey)
        return encrypted.combined!.base64EncodedString()
    }

    public func decryptFunc() -> String {
        do {
            guard let data = Data(base64Encoded: try encryptFunc()) else {
                return "Could not decode text: \(textString ?? "")"
            }

            let sealedBox = try AES.GCM.SealedBox(combined: data)
            let decryptedData = try AES.GCM.open(sealedBox, using: randomKey)

            guard let text = String(data: decryptedData, encoding: .utf8) else {
                return "Could not decode data: \(decryptedData)"
            }

            return text
        } catch let error {
            return "Error decrypting message: \(error.localizedDescription)"
        }
    }
    
}

//class chatEncryption {
//
//
//    func generatePrivateKey() -> P256.KeyAgreement.PrivateKey {
//        let privateKey = P256.KeyAgreement.PrivateKey()
//        return privateKey
//    }
//
//    func exportPrivateKey(_ privateKey: P256.KeyAgreement.PrivateKey) -> String {
//        let rawPrivateKey = privateKey.rawRepresentation
//        let privateKeyBase64 = rawPrivateKey.base64EncodedString()
//        let percentEncodedPrivateKey = privateKeyBase64.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
//        return percentEncodedPrivateKey
//    }
//
//    func importPrivateKey(_ privateKey: String) throws -> P256.KeyAgreement.PrivateKey {
//        let privateKeyBase64 = privateKey.removingPercentEncoding!
//        let rawPrivateKey = Data(base64Encoded: privateKeyBase64)!
//        return try P256.KeyAgreement.PrivateKey(rawRepresentation: rawPrivateKey)
//    }
//
//    func deriveSymmetricKey(privateKey: P256.KeyAgreement.PrivateKey, publicKey: P256.KeyAgreement.PublicKey) throws -> SymmetricKey {
//        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
//
//        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
//            using: SHA256.self,
//            salt: "My Key Agreement Salt".data(using: .utf8)!,
//            sharedInfo: Data(),
//            outputByteCount: 32
//        )
//
//        return symmetricKey
//    }
//
//  public func exportPublicKey(_ publicKey: P256.KeyAgreement.PublicKey) -> String {
//        let rawPublicKey = publicKey.rawRepresentation
//        let base64PublicKey = rawPublicKey.base64EncodedString()
//        let encodedPublicKey = base64PublicKey.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
//        return encodedPublicKey
//    }
//
//
//     public func importPublicKey(_ publicKey: String) throws -> P256.KeyAgreement.PublicKey {
//            let base64PublicKey = publicKey.removingPercentEncoding!
//            let rawPublicKey = Data(base64Encoded: base64PublicKey)!
//            let publicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: rawPublicKey)
//            return publicKey
//        }
//
//}




