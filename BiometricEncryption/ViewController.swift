//
//  ViewController.swift
//  BiometricEncryption
//
//  Created by LONGPHAN on 29/09/2022.
//

import UIKit
import Security
class ViewController: UIViewController {
    private var keychainManager: KeyChainManager?
    @IBOutlet weak var keyTF: UITextField!
    @IBOutlet weak var valueTF: UITextField!
    @IBOutlet weak var itemLabel: UILabel!
    
    
    override func viewDidLoad() {
        super.viewDidLoad()
        createKeychainManager()
        keyTF.resignFirstResponder()
    }
    
    func createKeychainManager() {
        let keychain = KeyChain()
        self.keychainManager = KeyChainManager(keychain)
    }
    
    func addItemToKeychain(_ password: String) -> OSStatus? {
        guard let data = password.data(using: .utf16) else { return nil }
        return keychainManager?.save(key: keyTF.text ?? "", data: data)
        
    }
    
    @IBAction func addAction(_ sender: Any) {
        let result = addItemToKeychain(valueTF.text ?? "")
        itemLabel.text! += "saved value \(valueTF.text ?? "") has status: \(result ?? -0) \n"
    }
    
    @IBAction func showItemAction(_ sender: Any) {
        let data = keychainManager?.load(key: keyTF.text ?? "")
        guard let data = data else {
            itemLabel.text! += "value for \(keyTF.text ?? "") is nil \n"
            return }
        let value = String(data: data, encoding: .utf16)
        itemLabel.text! += "value for \(keyTF.text ?? "") is \(value ?? "nil") \n"
    }
    
    
    
    
}
