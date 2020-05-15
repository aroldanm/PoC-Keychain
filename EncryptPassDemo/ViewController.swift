//
//  ViewController.swift
//  EncryptPassDemo
//
//  Created by Alan Roldan  on 15/05/2020.
//  Copyright © 2020 Alan Roldan . All rights reserved.
//

import UIKit
import LocalAuthentication

class ViewController: UIViewController {
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

    let user = "alan.roldan@promofarma.com"
    let server = "promofarma.com"
    let privateLabel = "clave-privada"
    let publicLabel = "clave-publica"

    override func viewDidLoad() {
        super.viewDidLoad()
    }

    @IBAction func didSelectSavePassword() {
        label.text = "Guardar Password"
        addText(nil)
        let password = "qwertyuiop"
        addText("User: \(user)\nPassword: \(password)\nServer: \(server)")
        guardarPassword(password)
    }

    @IBAction func didSelectRecoveryPassword() {
        label.text = "Recuperar Password"
        addText(nil)
        addText("User: \(user)\nServer: \(server)")
        recuperarPassword()
    }

    @IBAction func didSelectRemovePassword() {
        label.text = "Eliminar Password"
        addText(nil)
        eliminarPasswordRegistrado()
    }
}

private extension ViewController {
    func addText(_ text: String?) {
        if let text = text {
            textView.text += "\n\n" + text
            let bottom = textView.contentSize.height - self.textView.bounds.size.height
            if bottom > 0 {
                textView.setContentOffset(CGPoint(x: 0, y: bottom), animated: true)
            }
        } else {
            textView.text = ""
        }
    }

    func guardarPassword(_ password: String) {

        func guardarPublicEnKeychain(pk: SecKey) {
            addText("▶️ Guardando clave publica en Keychain...")
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
                kSecAttrApplicationTag as String: publicLabel,
                kSecValueRef as String: pk,
                kSecAttrIsPermanent as String: true,
                kSecReturnData as String: true,
            ]

            // add the public key to the Keychain
            var raw: CFTypeRef?
            var status = SecItemAdd(query as CFDictionary, &raw)

            // if it already exists, delete it and try to add it again
            if status == errSecDuplicateItem {
                status = SecItemDelete(query as CFDictionary)
                status = SecItemAdd(query as CFDictionary, &raw)
            }
            addText("✅ Clave pública guardada")
        }

        func guardarPasswordEncriptado(encPassword: Data) {
            addText("▶️ Guardando password encriptado en Keychain...")
            // Create an access control instance that dictates how the item can be read later.
            let access = SecAccessControlCreateWithFlags(nil, // Use the default allocator.
                                                         kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                         .userPresence,
                                                         nil) // Ignore any error.
            let context = LAContext()
            // Build the query for use in the add operation.
            let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                        kSecAttrAccount as String: user,
                                        kSecAttrServer as String: server,
                                        kSecAttrAccessControl as String: access as Any,
                                        kSecUseAuthenticationContext as String: context,
                                        kSecValueData as String: encPassword]

            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess else {
                addText("❌ No se ha podido guardar: \(KeychainError(status: status).localizedDescription)")
                return
            }
            addText("✅ Password guardado")
        }

        func generarClaves() -> (sk: SecKey, pk: SecKey)? {
            addText("▶️ Generando claves...")

            var accessControlError: Unmanaged<CFError>?
            guard let accessControl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                [SecAccessControlCreateFlags.biometryCurrentSet],
                &accessControlError) else {
                addText("❌ No se ha podido generar un AccessControl")
                return nil
            }

            var _publicKey, _privateKey: SecKey?
            let privateKeyParams: [String: Any] = [
                kSecAttrLabel as String: privateLabel,
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: accessControl,
            ]
            let params: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecPrivateKeyAttrs as String: privateKeyParams,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            ]
            let status = SecKeyGeneratePair(params as CFDictionary, &_publicKey, &_privateKey)

            guard status == errSecSuccess,
                let publicKey = _publicKey,
                let privateKey = _privateKey else {
                addText("❌ Couldn't generate key pair")
                return nil
            }
            addText("🔑 Clave privada: \(privateKey)")
            addText("🔑 Clave pública: \(publicKey)")

            //guardarPublicEnKeychain(pk: publicKey)

            return (sk: privateKey, pk: publicKey)
        }

        func encriptarPassword() {
            guard let keys = generarClaves() else {
                return
            }
            
            addText("▶️ Encriptando password...")

            var error : Unmanaged<CFError>?
            let passData = password.data(using: .utf8) ?? Data()
            let result = SecKeyCreateEncryptedData(keys.pk,
                                                   .eciesEncryptionStandardX963SHA256AESGCM,
                                                   passData as CFData,
                                                   &error)
            guard let resultData = result else {
                addText("❌ No se ha podido encriptar el password")
                return
            }
            
            addText("✅ Password encriptado")

            guardarPasswordEncriptado(encPassword: resultData as Data)
        }

        encriptarPassword()
    }

    func eliminarPasswordRegistrado() {
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: server]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess else {
            addText("❌ No se ha podido eliminar: \(KeychainError(status: status).localizedDescription)")
            return
        }
        addText("✅ El password ha sido eliminado de la Keychain")
    }

    func recuperarPassword() {
        func getPrivateKey(context: LAContext) -> SecKey? {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrLabel as String: privateLabel,
                kSecReturnRef as String: true,
                kSecUseOperationPrompt as String: "Access your private on the secure",
                kSecUseAuthenticationContext as String: context,
            ]

            var privateKey: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &privateKey)

            guard status == errSecSuccess else {
                addText("❌ No se ha podido recuperar la clave privada")
                return nil
            }

            return (privateKey as! SecKey)
        }
        
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: server,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecUseOperationPrompt as String: "Access your password on the keychain",
                                    kSecReturnData as String: true]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            addText("❌ No se ha podido recuperar la constraseña de Keychain")
            return
        }

        guard let existingItem = item as? [String: Any],
            let passwordData = existingItem[kSecValueData as String] as? Data
            else {
                addText("❌ No se ha podido recuperar la constraseña de Keychain")
                return
        }

        let context = LAContext()
        guard let sk = getPrivateKey(context: context) else {
            return
        }

        //Desencriptar password con sk
        var error : Unmanaged<CFError>?
        let result = SecKeyCreateDecryptedData(sk,
                                               .eciesEncryptionStandardX963SHA256AESGCM,
                                               passwordData as CFData, &error)
        if result == nil {
            addText("❌ No se ha podido desencriptar la constraseña")
            return
        }

        let password = String(data: result! as Data, encoding: String.Encoding.utf8)
        addText("✅ Password recuperado: \(String(describing: password))")
    }
}

struct KeychainError: Error {
    var status: OSStatus

    var localizedDescription: String {
        return SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error."
    }
}
