//
//  NewTryViewController.swift
//  EncryptPassDemo
//
//  Created by Rafael Ferrero on 16/05/2020.
//  Copyright © 2020 Alan Roldan . All rights reserved.
//

import UIKit
import LocalAuthentication

class NewTryViewController: UIViewController {
    enum Constants {
        static let privateLabel = "com.rafaelferrero.private.demoAuth.biometric"
    }

    @IBOutlet private weak var textView: UITextView! {
        didSet {
            textView.text = ""
            textView.isEditable = false
            textView.isSelectable = false
        }
    }
    @IBOutlet private weak var label: UILabel! {
        didSet {
            label.text = ""
        }
    }

    override func viewDidLoad() {
        super.viewDidLoad()
    }

    func addText(_ text: String?) {
        DispatchQueue.main.async {
            if let text = text {
                self.textView.text += "\n\n" + text
                let bottom = self.textView.contentSize.height - self.textView.bounds.size.height
                if bottom > 0 {
                    self.textView.setContentOffset(CGPoint(x: 0, y: bottom), animated: true)
                }
            } else {
                self.textView.text = ""
            }
        }
    }
}

// MARK: - Actions
extension NewTryViewController {
    @IBAction func savePassword() {
        let password = "Test1234!"
        guard let accessControl = createAccessControl(),
            let publicKey = createKeyPair(accessControl),
            let encryptedPassword = encryptPassword(password, publicKey: publicKey) else {
                return
        }

        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                               localizedReason: "only touch id") { (success, error) in
                                if success {
                                    self.storeEncryptedPassword(encryptedPassword, context: context)
                                }
        }

    }

    @IBAction func showPassword() {
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                               localizedReason: "only touch id") { (success, error) in
                                if success {
                                    if let privateKey = self.getPrivateKey(context: context),
                                        let encryptedPassword = self.getPasswordFromKeychain(context: context),
                                        let password = self.decryptPassword(encryptedPassword, with: privateKey) {
                                        self.addText("✅ Password desencriptado: \(String(describing: password))")

                                    }
                                }
        }
    }

    @IBAction func deleteSecureEnclaveKey() {
        deletePrivateKey()
    }
}

// MARK: - Keys
extension NewTryViewController {
    func createKeyPair(_ accessControl: SecAccessControl) -> SecKey? {
        let privateKeyParams: [String: Any] = [
            kSecAttrLabel as String: Constants.privateLabel,
            kSecAttrIsPermanent as String: true,
            kSecAttrAccessControl as String: accessControl
        ]

        let params: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: privateKeyParams,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
        ]

        // create the key pair
        var publicKey, privateKey: SecKey?

        let status = SecKeyGeneratePair(params as CFDictionary, &publicKey, &privateKey)

        guard status == errSecSuccess,
            let pubKey = publicKey else {
                addText("couldn't generate key pair")
                return nil
        }

        return pubKey
    }

    func getPrivateKey(context: LAContext) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: Constants.privateLabel,
            kSecReturnRef as String: true,
            // kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail
            kSecUseAuthenticationContext as String: context
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
            let res = result else {
            // couldn't get private key
            return nil
        }

        return res as! SecKey
    }

    func deletePrivateKey() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: Constants.privateLabel,
            kSecReturnRef as String: true,
        ]

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess else {
            addText("Error deleting private key")
            return
        }
    }

    func createAccessControl() -> SecAccessControl? {
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            nil) else {
                addText("couldn't create accessControl")
                return nil
        }

        return accessControl
    }
}

// MARK: - Keychain
extension NewTryViewController {
    func storeEncryptedPassword(_ password: Data, context: LAContext) {
        addText("Guardando password encriptado en Keychain...")

        let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .biometryCurrentSet,
            nil)
kSecClassInternetPassword
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrAccessControl as String: access,
                                    kSecUseAuthenticationContext as String: context,
                                    kSecValueData as String: password]

        var raw: CFTypeRef?
        var status = SecItemAdd(query as CFDictionary, nil)

        if status == errSecDuplicateItem {
            status = SecItemDelete(query as CFDictionary)
            status = SecItemAdd(query as CFDictionary, &raw)
        }

        guard status == errSecSuccess else {
            addText("❌ No se ha podido guardar: \(KeychainError(status: status).localizedDescription)")
            return
        }
        addText("✅ Password guardado")
    }

    func getPasswordFromKeychain(context: LAContext) -> Data? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecUseAuthenticationContext as String: context,
                                    kSecReturnData as String: true]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
            let existingItem = item as? [String: Any],
        let passwordData = existingItem[kSecValueData as String] as? Data else {
            addText("❌ No se ha podido recuperar la constraseña de Keychain")
            return nil
        }

        addText("✅ Password recuperado")
        return passwordData
    }
}

// MARK: - Encrypt / Decrypt password
extension NewTryViewController {
    func encryptPassword(_ password: String, publicKey: SecKey) -> Data? {
         var error : Unmanaged<CFError>?
         let passData = password.data(using: .utf8)!

         let result = SecKeyCreateEncryptedData(publicKey,
                                                .eciesEncryptionStandardX963SHA256AESGCM,
                                                passData as CFData,
                                                &error)
         guard let resultData = result else {
             addText("❌ No se ha podido encriptar el password")
             return nil
         }

         addText("✅ Password encriptado")
         return resultData as Data
     }

     func decryptPassword(_ pwdData: Data, with privateKey: SecKey) -> String? {
         var error : Unmanaged<CFError>?
         let result = SecKeyCreateDecryptedData(privateKey,
                                                .eciesEncryptionStandardX963SHA256AESGCM,
                                                pwdData as CFData, &error)
         if result == nil {
             addText("❌ No se ha podido desencriptar la constraseña")
             return nil
         }

         let password = String(data: result! as Data, encoding: String.Encoding.utf8)

         return password
     }
}
