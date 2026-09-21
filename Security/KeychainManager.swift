import Foundation
import Security
import CryptoKit

enum KeychainError: LocalizedError {
    case unexpectedStatus(OSStatus)
    case malformedKeyData

    var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let status):
            return "Keychain error: \(status)"
        case .malformedKeyData:
            return "Stored master key is malformed."
        }
    }
}

actor KeychainManager {
    static let shared = KeychainManager()

    private let service = "KeyAuth.MasterKey.v1"
    private let account = "primary"
    private let simulatorStorageKey = "KeyAuth.SimulatorMasterKey.v1"

    /// The key is available in the device Keychain for offline use. The
    /// synchronizable attribute is only for encrypted vault recovery on a
    /// trusted device using the same Apple Account.
    /// Do NOT store this key in CloudKit.
    func readMasterKey() throws -> SymmetricKey? {
#if targetEnvironment(simulator)
        guard let data = UserDefaults.standard.data(forKey: simulatorStorageKey) else {
            return nil
        }
        guard data.count == 32 else {
            throw KeychainError.malformedKeyData
        }
        return SymmetricKey(data: data)
#else
        if let existing = try readMasterKeyData() {
            guard existing.count == 32 else {
                throw KeychainError.malformedKeyData
            }
            return SymmetricKey(data: existing)
        }

        return nil
#endif
    }

    func createMasterKey() throws -> SymmetricKey {
        if let existing = try readMasterKey() {
            return existing
        }

        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }

        let data = Data(bytes)
#if targetEnvironment(simulator)
        // Simulator builds are intentionally local-only and may be unsigned,
        // so Security.framework can reject even a non-synchronizable item.
        UserDefaults.standard.set(data, forKey: simulatorStorageKey)
        return SymmetricKey(data: data)
#else
        let addStatus = SecItemAdd(
            masterKeyQuery(with: data) as CFDictionary,
            nil
        )

        if addStatus == errSecDuplicateItem {
            // A synchronizable item may have arrived between the read and add.
            // Never overwrite it with the locally generated key.
            guard let existing = try readMasterKey() else {
                throw KeychainError.unexpectedStatus(addStatus)
            }
            return existing
        }

        guard addStatus == errSecSuccess else {
            throw KeychainError.unexpectedStatus(addStatus)
        }

        return SymmetricKey(data: data)
#endif
    }

    private func readMasterKeyData() throws -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
#if targetEnvironment(simulator)
        // Unsigned simulator builds do not have the iCloud Keychain
        // entitlement. Keep simulator storage local so it can still exercise
        // the complete offline vault flow.
        query[kSecAttrSynchronizable as String] = false
#else
        query[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
        query[kSecUseDataProtectionKeychain as String] = true
#endif

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

    private func masterKeyQuery(with data: Data) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
#if targetEnvironment(simulator)
        query[kSecAttrSynchronizable as String] = false
#else
        query[kSecAttrSynchronizable as String] = true
        query[kSecUseDataProtectionKeychain as String] = true
#endif
        return query
    }
}
