import Foundation
@preconcurrency import LocalAuthentication
import Security
import CryptoKit

enum KeychainError: LocalizedError {
    case unexpectedStatus(OSStatus)
    case malformedKeyData
    case accessControlUnavailable
    case masterKeyUnavailable

    var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let status):
            return "Keychain error: \(status)"
        case .malformedKeyData:
            return "Stored master key is malformed."
        case .accessControlUnavailable:
            return "This device needs a passcode to protect the KeyAuth master key."
        case .masterKeyUnavailable:
            return "The KeyAuth master key could not be unlocked."
        }
    }
}

actor KeychainManager {
    static let shared = KeychainManager()

    private let service = "KeyAuth.MasterKey.v2"
    private let legacyService = "KeyAuth.MasterKey.v1"
    private let account = "primary"
    private let simulatorStorageKey = "KeyAuth.SimulatorMasterKey.v1"

    /// Reads the device-bound master key. The Keychain access-control policy
    /// causes Security.framework to ask for Face ID, Touch ID, or the device
    /// passcode before returning the key.
    func readMasterKey(context: LAContext) throws -> SymmetricKey? {
#if targetEnvironment(simulator)
        guard let data = UserDefaults.standard.data(forKey: simulatorStorageKey) else {
            return nil
        }
        return try makeKey(from: data)
#else
        if let protectedData = try readProtectedMasterKeyData(context: context) {
            return try makeKey(from: protectedData)
        }

        // Migrate the previous synchronizable key only through this
        // authenticated path. The migrated device-only item is read with the
        // supplied LAContext before it is returned to the app.
        guard let legacyData = try readLegacyMasterKeyData() else {
            return nil
        }
        _ = try storeProtectedMasterKeyData(legacyData)
        guard let migratedData = try readProtectedMasterKeyData(context: context) else {
            throw KeychainError.masterKeyUnavailable
        }
        try deleteLegacyMasterKey()
        return try makeKey(from: migratedData)
#endif
    }

    /// Creates a new device-bound master key. Callers must immediately read it
    /// through readMasterKey(context:) so the newly-created userPresence item
    /// performs the system authentication before the key is used.
    func createMasterKey() throws -> SymmetricKey {
        let data = try randomKeyData()
#if targetEnvironment(simulator)
        // Unsigned simulator builds cannot use the real Keychain entitlement;
        // simulator storage is deliberately local-only development storage.
        UserDefaults.standard.set(data, forKey: simulatorStorageKey)
        return try makeKey(from: data)
#else
        _ = try storeProtectedMasterKeyData(data)
        return try makeKey(from: data)
#endif
    }

    private func makeKey(from data: Data) throws -> SymmetricKey {
        guard data.count == 32 else {
            throw KeychainError.malformedKeyData
        }
        return SymmetricKey(data: data)
    }

    private func randomKeyData() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
        return Data(bytes)
    }

#if !targetEnvironment(simulator)
    private func protectedAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.userPresence],
            &error
        ) else {
            throw KeychainError.accessControlUnavailable
        }
        return access
    }

    private func readProtectedMasterKeyData(
        context: LAContext
    ) throws -> Data? {
        context.localizedReason = "解锁 KeyAuth 以读取主密钥。"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                throw KeychainError.malformedKeyData
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }

    private func readLegacyMasterKeyData() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: legacyService,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                throw KeychainError.malformedKeyData
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unexpectedStatus(status)
        }
    }

    private func storeProtectedMasterKeyData(_ data: Data) throws -> Data {
        guard data.count == 32 else {
            throw KeychainError.malformedKeyData
        }

        let access = try protectedAccessControl()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: access,
            kSecUseDataProtectionKeychain as String: true
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw KeychainError.unexpectedStatus(status)
        }
        return data
    }

    private func deleteLegacyMasterKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: legacyService,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecUseDataProtectionKeychain as String: true
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
#endif
}
