//
//  ViewController.swift
//  BiometricEncryption
//
//  Created by LONGPHAN on 29/09/2022.
//

import UIKit
import Security
import LocalAuthentication
enum BiometryState {
    case available, locked, notAvailable
}

class ViewController: UIViewController {
    private var keychainManager: KeyChainManager {
        let keyChain = KeyChain()
        return KeyChainManager(keyChain)
    }
    private var keyService: KeyServiceProtocol = KeyService()
    @IBOutlet weak var keyTF: UITextField!
    @IBOutlet weak var valueTF: UITextField!
    @IBOutlet weak var itemLabel: UILabel!
    
    
    override func viewDidLoad() {
        super.viewDidLoad()
        keyTF.resignFirstResponder()
        print(bio())
        
    }
    
    func addItemToKeychain(_ password: String) -> OSStatus? {
        guard let data = password.data(using: .utf16) else { return nil }
        return keychainManager.save(key: keyTF.text ?? "", data: data)
        
    }
    
    @IBAction func addAction(_ sender: Any) {
        let result = addItemToKeychain(valueTF.text ?? "")
        itemLabel.text! += "saved value \(valueTF.text ?? "") has status: \(result ?? -0) \n"
    }
    
    @IBAction func showItemAction(_ sender: Any) {
        let data = keychainManager.load(key: keyTF.text ?? "")
        guard let data = data else {
            itemLabel.text! += "value for \(keyTF.text ?? "") is nil \n"
            return }
        let value = String(data: data, encoding: .utf16)
        itemLabel.text! += "value for \(keyTF.text ?? "") is \(value ?? "nil") \n"
    }
    
    
    @IBAction func genNewKeyPairAction(_ sender: Any) {
        let privateKey = keyService.generateNewPrivateKeyPair()
        guard let privateKey = privateKey else {
            return
        }
        itemLabel.text! += "Generate private key pair success \n"
        
        let publicKey = keyService.getPublicKeyFromPrivateKey(privateKey: privateKey)
        
        guard let publicKey = publicKey else {
            return
        }
        
        itemLabel.text! += "get public key from private key success \n"
        
        let publicKeyString = keyService.publicKeyToString(publicKey: publicKey)
        
        guard let publicKeyString = publicKeyString else {
            return
        }
        
        itemLabel.text! += "get public key string success \(publicKeyString) \n"
        
        UserDefaults.standard.set(publicKeyString, forKey: "public_key")
        
        itemLabel.text! += "finish \n"
    }
    
    
    @IBAction func getPrivateKeyDataFromKeychain(_ sender: Any) {
        guard let data = keyService.queryPrivateKeyFromKeychain() else {
            itemLabel.text! += "no private key found \n"
            return
        }
        
        itemLabel.text! += "private key founded \n"
    }
    
    private func bio() -> BiometryState {
        var biometryState: BiometryState {
            let authContext = LAContext()
            var error: NSError?
            
            let biometryAvailable = authContext.canEvaluatePolicy(
                LAPolicy.deviceOwnerAuthenticationWithBiometrics, error: &error)
            if let laError = error as? LAError, laError.code == LAError.Code.biometryLockout {
                return .locked
            }
            return biometryAvailable ? .available : .notAvailable
        }
        
        return biometryState
    }
    
}
