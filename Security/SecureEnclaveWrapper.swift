import Foundation
@preconcurrency import LocalAuthentication
import Security

enum SecureEnclaveWrapperError: LocalizedError {
    case keyUnavailable
    case algorithmUnavailable

    var errorDescription: String? {
        switch self {
        case .keyUnavailable:
            return String(localized: "The Secure Enclave key is unavailable.")
        case .algorithmUnavailable:
            return String(localized: "Secure Enclave key wrapping is unavailable.")
        }
    }
}

enum SecureEnclaveWrapper {
    private static var algorithm: SecKeyAlgorithm {
        SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
    }
    private static let privateKeyTag = Data(
        "org.kakahu.KeyAuth.SecureEnclaveWrapper.v1.private".utf8
    )

    static func wrap(_ plaintext: Data) throws -> Data {
        let privateKey = try privateKey(
            context: nil,
            createIfMissing: true
        )

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveWrapperError.keyUnavailable
        }

        guard SecKeyIsAlgorithmSupported(
            publicKey,
            .encrypt,
            algorithm
        ) else {
            throw SecureEnclaveWrapperError.algorithmUnavailable
        }

        var error: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(
            publicKey,
            algorithm,
            plaintext as CFData,
            &error
        ) as Data? else {
            if let error {
                throw error.takeRetainedValue()
            }
            throw SecureEnclaveWrapperError.keyUnavailable
        }
        return ciphertext
    }

    static func unwrap(_ ciphertext: Data, context: LAContext) throws -> Data {
        context.localizedReason = String(localized: "Unlock KeyAuth to read the master key.")
        let privateKey = try privateKey(context: context, createIfMissing: false)
        guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
            throw SecureEnclaveWrapperError.algorithmUnavailable
        }

        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(
            privateKey,
            algorithm,
            ciphertext as CFData,
            &error
        ) as Data? else {
            if let error {
                throw error.takeRetainedValue()
            }
            throw SecureEnclaveWrapperError.keyUnavailable
        }
        return plaintext
    }

    private static func privateKey(
        context: LAContext?,
        createIfMissing: Bool
    ) throws -> SecKey {
        var query = privateKeyQuery()
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let item {
            return item as! SecKey
        }
        guard status == errSecItemNotFound, createIfMissing else {
            if status == errSecItemNotFound {
                throw SecureEnclaveWrapperError.keyUnavailable
            }
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }

        return try createPrivateKey()
    }

    private static func createPrivateKey() throws -> SecKey {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .userPresence],
            &accessError
        ) else {
            if let accessError {
                throw accessError.takeRetainedValue()
            }
            throw SecureEnclaveWrapperError.keyUnavailable
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: privateKeyTag,
                kSecAttrAccessControl as String: access
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(
            attributes as CFDictionary,
            &error
        ) else {
            if let error {
                throw error.takeRetainedValue()
            }
            throw SecureEnclaveWrapperError.keyUnavailable
        }
        return privateKey
    }

    private static func privateKeyQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: privateKeyTag,
            kSecReturnRef as String: true,
            kSecUseDataProtectionKeychain as String: true
        ]
    }
}
