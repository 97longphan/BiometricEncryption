//
//  KeyService.swift
//  BiometricEncryption
//
//  Created by LONGPHAN on 06/10/2022.
//

import Security
import Foundation
import LocalAuthentication
protocol KeyServiceProtocol {
    func generateNewPrivateKeyPair() -> SecKey?
    func getPublicKeyFromPrivateKey(privateKey: SecKey) -> SecKey?
    func publicKeyToString(publicKey: SecKey) -> String?
    func queryPrivateKeyFromKeychain() -> Data?
}

class KeyService: KeyServiceProtocol {
    func getBioSecAccessControl() -> SecAccessControl {
            var access: SecAccessControl?
            var error: Unmanaged<CFError>?
            
            if #available(iOS 11.3, *) {
                access = SecAccessControlCreateWithFlags(nil,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    .biometryCurrentSet,
                    &error)
            } else {
                access = SecAccessControlCreateWithFlags(nil,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    .touchIDCurrentSet,
                    &error)
            }
            precondition(access != nil, "SecAccessControlCreateWithFlags failed")
            return access!
        }
    
    func generateNewPrivateKeyPair() -> SecKey? {
        let tag = "com.example.keys.mykeys"
        let privateKeyAttrs: [String: Any] = [kSecAttrIsPermanent as String: true, // auto save to keychain when created
                                              kSecAttrApplicationTag as String: tag]
        
        guard let accessControl =
                SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    [.privateKeyUsage, .biometryCurrentSet],
                    nil) else { return nil }
        // Create Access Control for the key,
        // kSecAttrAccessibleWhenUnlockedThisDeviceOnly is the accessibility settings for the keys.
        // That means application can only access the keychain item when specific device has been unlocked.
        // .privateKeyUsage and .biometryCurrentSet are the authentication settings. To use the keychain item, user must provide biometric authentication.
        
        let keyPairAttrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                                           kSecAttrKeySizeInBits as String: 2048,
                                           kSecPrivateKeyAttrs as String: privateKeyAttrs,
                                           kSecAttrAccessControl as String: getBioSecAccessControl()]
        var error: Unmanaged<CFError>?
        
        let result = SecKeyCreateRandomKey(keyPairAttrs as CFDictionary, &error)
        
        return result
    }
    
    func getPublicKeyFromPrivateKey(privateKey: SecKey) -> SecKey? {
        return SecKeyCopyPublicKey(privateKey)
    }
    
    func publicKeyToString(publicKey: SecKey) -> String? {
        guard let keyCfData = SecKeyCopyExternalRepresentation(publicKey, nil) else { return nil }
        let keyData = keyCfData as Data
        return keyData.base64EncodedString()
    }
    
    func queryPrivateKeyFromKeychain() -> Data? {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 10
        
        // 1. Make Search Query
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrApplicationTag as String: "com.example.keys.mykeys",
            kSecUseAuthenticationContext as String: context,
            kSecReturnRef as String: true
        ]
        // 2. Copy Key Reference
        var item: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }
        
        return item as? Data
    }
}
