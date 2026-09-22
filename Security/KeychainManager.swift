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

    private let legacyService = "KeyAuth.MasterKey.v1"
    private let account = "primary"
    private let simulatorStorageKey = "KeyAuth.SimulatorMasterKey.v1"
    private let currentKeyVersionKey = "KeyAuth.MasterKey.CurrentVersion"
    private let knownKeyVersionsKey = "KeyAuth.MasterKey.KnownVersions"
    private let pendingRotationKey = "KeyAuth.MasterKey.PendingRotation"
    private let recoveryService = "KeyAuth.RecoveryKey.v1"
    private let simulatorRecoveryKey = "KeyAuth.SimulatorRecoveryKey.v1"

    func currentMasterKeyVersion() -> Int {
        let value = UserDefaults.standard.integer(forKey: currentKeyVersionKey)
        return value == 0 ? 1 : value
    }

    func knownKeyVersions() -> [Int] {
        let values = UserDefaults.standard.array(
            forKey: knownKeyVersionsKey
        ) as? [Int]

        return values ?? [1]
    }

    func pendingRotationVersion() -> Int? {
        let value = UserDefaults.standard.integer(forKey: pendingRotationKey)
        return value == 0 ? nil : value
    }

    private func service(for version: Int) -> String {
        if version == 1 {
            // Keep compatibility with the existing device-bound key.
            return "KeyAuth.MasterKey.v2"
        }

        return "KeyAuth.MasterKey.v2.k\(version)"
    }

    private func simulatorStorageKey(for version: Int) -> String {
        if version == 1 {
            return simulatorStorageKey
        }

        return "\(simulatorStorageKey).k\(version)"
    }

    /// Reads the device-bound master key. The Keychain access-control policy
    /// causes Security.framework to ask for Face ID, Touch ID, or the device
    /// passcode before returning the key.
    func readMasterKey(
        version: Int,
        context: LAContext
    ) throws -> SymmetricKey? {
#if targetEnvironment(simulator)
        guard let data = UserDefaults.standard.data(
            forKey: simulatorStorageKey(for: version)
        ) else {
            return nil
        }
        return try makeKey(from: data)
#else
        if let protectedData = try readProtectedMasterKeyData(
            version: version,
            context: context
        ) {
            return try makeKey(from: protectedData)
        }

        // Migrate the previous synchronizable key only through this
        // authenticated path. The migrated device-only item is read with the
        // supplied LAContext before it is returned to the app.
        guard version == 1 else {
            return nil
        }
        guard let legacyData = try readLegacyMasterKeyData() else {
            return nil
        }
        _ = try storeProtectedMasterKeyData(
            legacyData,
            service: service(for: version)
        )
        guard let migratedData = try readProtectedMasterKeyData(
            version: version,
            context: context
        ) else {
            throw KeychainError.masterKeyUnavailable
        }
        try deleteLegacyMasterKey()
        return try makeKey(from: migratedData)
#endif
    }

    func readMasterKey(context: LAContext) throws -> SymmetricKey? {
        try readMasterKey(version: currentMasterKeyVersion(), context: context)
    }

    /// Creates a new device-bound master key. Callers must immediately read it
    /// through readMasterKey(version:context:) so the newly-created
    /// userPresence item performs system authentication before the key is used.
    func createMasterKey() throws {
        let data = try randomKeyData()
#if targetEnvironment(simulator)
        // Unsigned simulator builds cannot use the real Keychain entitlement;
        // simulator storage is deliberately local-only development storage.
        UserDefaults.standard.set(
            data,
            forKey: simulatorStorageKey(for: 1)
        )
#else
        _ = try storeProtectedMasterKeyData(
            data,
            service: service(for: 1)
        )
#endif
    }

    func createNextMasterKey(
        context: LAContext
    ) throws -> (Int, SymmetricKey) {
        let newVersion = currentMasterKeyVersion() + 1
        let data = try randomKeyData()

#if targetEnvironment(simulator)
        let storageKey = simulatorStorageKey(for: newVersion)
        if UserDefaults.standard.data(forKey: storageKey) == nil {
            UserDefaults.standard.set(data, forKey: storageKey)
        }
#else
        _ = try storeProtectedMasterKeyData(
            data,
            service: service(for: newVersion)
        )
#endif

        var known = knownKeyVersions()
        if !known.contains(newVersion) {
            known.append(newVersion)
            UserDefaults.standard.set(known, forKey: knownKeyVersionsKey)
        }

        UserDefaults.standard.set(newVersion, forKey: pendingRotationKey)

        guard let key = try readMasterKey(
            version: newVersion,
            context: context
        ) else {
            throw KeychainError.masterKeyUnavailable
        }

        return (newVersion, key)
    }

    func commitRotation(version: Int) {
        UserDefaults.standard.set(version, forKey: currentKeyVersionKey)
        UserDefaults.standard.removeObject(forKey: pendingRotationKey)
    }

    func deleteMasterKey(version: Int) throws {
        let currentVersion = currentMasterKeyVersion()

        // Only an obsolete key may be deleted. Never delete the current or a
        // future version.
        guard version < currentVersion else {
            return
        }

#if targetEnvironment(simulator)
        UserDefaults.standard.removeObject(
            forKey: simulatorStorageKey(for: version)
        )
#else
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service(for: version),
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
#endif

        var versions = knownKeyVersions()
        versions.removeAll { $0 == version }
        UserDefaults.standard.set(versions, forKey: knownKeyVersionsKey)
    }

    func readRecoveryKey(context: LAContext) throws -> SymmetricKey? {
#if targetEnvironment(simulator)
        guard let data = UserDefaults.standard.data(
            forKey: simulatorRecoveryKey
        ) else {
            return nil
        }

        return try makeKey(from: data)
#else
        context.localizedReason = "解锁 KeyAuth 恢复密钥。"

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: recoveryService,
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

            return try makeKey(from: data)
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.unexpectedStatus(status)
        }
#endif
    }

    func storeRecoveryKey(_ data: Data) throws {
        guard data.count == 32 else {
            throw KeychainError.malformedKeyData
        }

#if targetEnvironment(simulator)
        UserDefaults.standard.set(data, forKey: simulatorRecoveryKey)
#else
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: recoveryService,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]

        let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
        guard deleteStatus == errSecSuccess ||
              deleteStatus == errSecItemNotFound
        else {
            throw KeychainError.unexpectedStatus(deleteStatus)
        }

        _ = try storeProtectedMasterKeyData(
            data,
            service: recoveryService
        )
#endif
    }

    func installRecoveredKeyring(
        _ keys: [Int: Data],
        currentVersion: Int
    ) throws {
        guard currentVersion > 0,
              keys[currentVersion] != nil,
              !keys.isEmpty
        else {
            throw KeychainError.malformedKeyData
        }

        for (version, data) in keys {
            guard version > 0, data.count == 32 else {
                throw KeychainError.malformedKeyData
            }
        }

        for (version, data) in keys {
#if targetEnvironment(simulator)
            UserDefaults.standard.set(
                data,
                forKey: simulatorStorageKey(for: version)
            )
#else
            _ = try storeProtectedMasterKeyData(
                data,
                service: service(for: version)
            )
#endif
        }

        let versions = keys.keys.sorted()
        UserDefaults.standard.set(versions, forKey: knownKeyVersionsKey)
        UserDefaults.standard.set(currentVersion, forKey: currentKeyVersionKey)
        UserDefaults.standard.removeObject(forKey: pendingRotationKey)
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
        version: Int,
        context: LAContext
    ) throws -> Data? {
        context.localizedReason = "解锁 KeyAuth 以读取主密钥。"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service(for: version),
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

    private func storeProtectedMasterKeyData(
        _ data: Data,
        service: String
    ) throws -> Data {
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
