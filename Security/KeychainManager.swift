import Foundation
@preconcurrency import LocalAuthentication
import Security
import CryptoKit

enum KeychainError: LocalizedError {
    case unexpectedStatus(OSStatus)
    case malformedKeyData
    case accessControlUnavailable
    case masterKeyUnavailable
    case malformedRecoveryEpoch

    var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let status):
            return String(localized: "Keychain operation failed.") + " (\(status))"
        case .malformedKeyData:
            return String(localized: "Stored master key is malformed.")
        case .accessControlUnavailable:
            return String(
                localized: "This device needs a passcode to protect the KeyAuth master key."
            )
        case .masterKeyUnavailable:
            return String(localized: "The KeyAuth master key could not be unlocked.")
        case .malformedRecoveryEpoch:
            return String(localized: "The saved recovery version is invalid.")
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
    private let highestAcceptedRecoveryEpochService =
        "KeyAuth.Recovery.HighestAcceptedEpoch"

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

    func highestAcceptedRecoveryEpoch() throws -> UInt64 {
#if targetEnvironment(simulator)
        guard let value = UserDefaults.standard.string(
            forKey: highestAcceptedRecoveryEpochService
        ) else {
            return 0
        }
        guard let epoch = UInt64(value) else {
            throw KeychainError.malformedRecoveryEpoch
        }
        return epoch
#else
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: highestAcceptedRecoveryEpochService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return 0
        }
        guard status == errSecSuccess, let data = item as? Data,
              let value = String(data: data, encoding: .utf8),
              let epoch = UInt64(value)
        else {
            if status != errSecSuccess {
                throw KeychainError.unexpectedStatus(status)
            }
            throw KeychainError.malformedRecoveryEpoch
        }
        return epoch
#endif
    }

    func hasAcceptedRecoveryEpoch() throws -> Bool {
#if targetEnvironment(simulator)
        return UserDefaults.standard.object(
            forKey: highestAcceptedRecoveryEpochService
        ) != nil
#else
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: highestAcceptedRecoveryEpochService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecUseDataProtectionKeychain as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return false
        }
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
        return true
#endif
    }

    func recordAcceptedRecoveryEpoch(_ epoch: UInt64) throws {
        let highestEpoch = try highestAcceptedRecoveryEpoch()
        let hasStoredEpoch = try hasAcceptedRecoveryEpoch()
        guard epoch >= highestEpoch,
              epoch != highestEpoch || !hasStoredEpoch
        else {
            return
        }

#if targetEnvironment(simulator)
        UserDefaults.standard.set(
            String(epoch),
            forKey: highestAcceptedRecoveryEpochService
        )
#else
        let data = Data(String(epoch).utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: highestAcceptedRecoveryEpochService,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]
        let updates: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            updates as CFDictionary
        )
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(updateStatus)
        }

        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] =
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            if addStatus == errSecDuplicateItem {
                let retryStatus = SecItemUpdate(
                    query as CFDictionary,
                    updates as CFDictionary
                )
                guard retryStatus == errSecSuccess else {
                    throw KeychainError.unexpectedStatus(retryStatus)
                }
                return
            }
            throw KeychainError.unexpectedStatus(addStatus)
        }
#endif
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
            if protectedData.count == 32 {
                let wrappedData = try SecureEnclaveWrapper.wrap(protectedData)
                let verifiedData = try SecureEnclaveWrapper.unwrap(
                    wrappedData,
                    context: context
                )
                guard verifiedData == protectedData else {
                    throw KeychainError.malformedKeyData
                }
                try updateProtectedMasterKeyData(
                    wrappedData,
                    service: service(for: version),
                    context: context
                )
                return try makeKey(from: verifiedData)
            }

            let unwrappedData = try SecureEnclaveWrapper.unwrap(
                protectedData,
                context: context
            )
            return try makeKey(from: unwrappedData)
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
        guard legacyData.count == 32 else {
            throw KeychainError.malformedKeyData
        }
        let wrappedLegacyData = try SecureEnclaveWrapper.wrap(legacyData)
        let verifiedLegacyData = try SecureEnclaveWrapper.unwrap(
            wrappedLegacyData,
            context: context
        )
        guard verifiedLegacyData == legacyData else {
            throw KeychainError.malformedKeyData
        }
        _ = try storeProtectedMasterKeyData(
            wrappedLegacyData,
            service: service(for: version)
        )
        guard let migratedWrappedData = try readProtectedMasterKeyData(
            version: version,
            context: context
        ) else {
            throw KeychainError.masterKeyUnavailable
        }
        let migratedData = try SecureEnclaveWrapper.unwrap(
            migratedWrappedData,
            context: context
        )
        guard migratedData == legacyData else {
            throw KeychainError.malformedKeyData
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
        let wrappedData = try SecureEnclaveWrapper.wrap(data)
        _ = try storeProtectedMasterKeyData(
            wrappedData,
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
        let wrappedData = try SecureEnclaveWrapper.wrap(data)
        _ = try storeProtectedMasterKeyData(
            wrappedData,
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
        guard let data = try readProtectedRecoveryKeyData(context: context) else {
            return nil
        }

        if data.count == 32 {
            let wrappedData = try SecureEnclaveWrapper.wrap(data)
            let verifiedData = try SecureEnclaveWrapper.unwrap(
                wrappedData,
                context: context
            )
            guard verifiedData == data else {
                throw KeychainError.malformedKeyData
            }

            try updateProtectedMasterKeyData(
                wrappedData,
                service: recoveryService,
                context: context
            )
            guard let migratedWrappedData = try readProtectedRecoveryKeyData(
                context: context
            ) else {
                throw KeychainError.masterKeyUnavailable
            }
            let migratedData = try SecureEnclaveWrapper.unwrap(
                migratedWrappedData,
                context: context
            )
            guard migratedData == data else {
                throw KeychainError.malformedKeyData
            }
            return try makeKey(from: migratedData)
        }

        let rawData = try SecureEnclaveWrapper.unwrap(data, context: context)
        return try makeKey(from: rawData)
#endif
    }

    func storeRecoveryKey(_ data: Data) throws {
        guard data.count == 32 else {
            throw KeychainError.malformedKeyData
        }

#if targetEnvironment(simulator)
        UserDefaults.standard.set(data, forKey: simulatorRecoveryKey)
#else
        let wrappedData = try SecureEnclaveWrapper.wrap(data)
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
            wrappedData,
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
            let wrappedData = try SecureEnclaveWrapper.wrap(data)
            try replaceProtectedMasterKeyData(
                wrappedData,
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
        context.localizedReason = String(localized: "Unlock KeyAuth to read the master key.")
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

    private func readProtectedRecoveryKeyData(
        context: LAContext
    ) throws -> Data? {
        context.localizedReason = String(localized: "Unlock KeyAuth recovery key.")
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
        guard !data.isEmpty else {
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

    private func replaceProtectedMasterKeyData(
        _ data: Data,
        service: String
    ) throws {
        guard !data.isEmpty else {
            throw KeychainError.malformedKeyData
        }

        // SecItemUpdate cannot reliably replace an existing item's
        // kSecAttrAccessControl. Delete and re-add it so recovery always
        // restores WhenPasscodeSetThisDeviceOnly + userPresence.
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
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
            service: service
        )
    }

    private func updateProtectedMasterKeyData(
        _ data: Data,
        service: String,
        context: LAContext
    ) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context
        ]
        let updates: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(
            query as CFDictionary,
            updates as CFDictionary
        )
        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }
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
