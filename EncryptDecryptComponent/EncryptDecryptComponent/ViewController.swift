//
//  ViewController.swift
//  EncryptDecryptComponent
//
//  Created by Prajakta Kiran Patil on 12/07/22.
//

import UIKit
import CryptoSwift

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        let key = NSData.withBytes([])
        let iv = Cipher
        
        //"bbC2H19lkVbQDfakxcrtNMQdd0FloLyw" // length == 32
        let iv = "gqLOHUioQ0QjhuvI" // length == 16
        let s = "string to encrypt"
        let enc = try! s.cryptoSwiftAESEncrypt(key: key, iv: iv)
        let dec = try! enc?.cryptoSwiftAESDecrypt(key: key, iv: iv)
        print(s) // string to encrypt
        print("enc:\(enc)") // 2r0+KirTTegQfF4wI8rws0LuV8h82rHyyYz7xBpXIpM=
        print("dec:\(dec)") // string to encrypt
        print("\(s == dec)") // true
        
        // Do any additional setup after loading the view.
    }
}

