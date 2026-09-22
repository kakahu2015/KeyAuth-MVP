import Foundation
import CryptoKit
import Security
import CloudKit

enum RecoveryError: LocalizedError {
    case invalidRecoveryKey
    case envelopeMissing
    case malformedEnvelope
    case recoveryKeyUnavailable

    var errorDescription: String? {
        switch self {
        case .invalidRecoveryKey:
            return "恢复密钥无效。"
        case .envelopeMissing:
            return "iCloud 中没有恢复数据。"
        case .malformedEnvelope:
            return "恢复数据无效或已损坏。"
        case .recoveryKeyUnavailable:
            return "本机恢复密钥不可用。"
        }
    }
}

struct RecoveryKeyringSnapshot: Sendable {
    let currentVersion: Int
    let keyData: [Int: Data]
}

struct RecoverySetupResult: Sendable {
    let code: String
    let key: SymmetricKey
}

actor RecoveryManager {
    static let shared = RecoveryManager()

    private static let aad = Data(
        "KeyAuth/RecoveryEnvelope/v1".utf8
    )

    func enableRecovery(
        keys: [Int: SymmetricKey],
        currentVersion: Int
    ) async throws -> RecoverySetupResult {
        let rawRecoveryKey = try random32()
        let recoveryKey = SymmetricKey(data: rawRecoveryKey)

        try await updateEnvelope(
            recoveryKey: recoveryKey,
            keys: keys,
            currentVersion: currentVersion
        )

        try await KeychainManager.shared.storeRecoveryKey(
            rawRecoveryKey
        )

        return RecoverySetupResult(
            code: Self.encodeRecoveryKey(rawRecoveryKey),
            key: recoveryKey
        )
    }

    func updateEnvelope(
        recoveryKey: SymmetricKey,
        keys: [Int: SymmetricKey],
        currentVersion: Int
    ) async throws {
        guard keys[currentVersion] != nil,
              !keys.isEmpty
        else {
            throw RecoveryError.malformedEnvelope
        }

        let bundle = RecoveryKeyBundle(
            currentVersion: currentVersion,
            keys: keys
                .sorted { $0.key < $1.key }
                .map {
                    RecoveryMasterKey(
                        version: $0.key,
                        keyData: Self.data(from: $0.value)
                    )
                }
        )

        let plaintext = try JSONEncoder().encode(bundle)
        let sealed = try AES.GCM.seal(
            plaintext,
            using: recoveryKey,
            authenticating: Self.aad
        )

        guard let combined = sealed.combined else {
            throw RecoveryError.malformedEnvelope
        }

        let envelope = RecoveryEnvelope(
            encryptedBlob: combined,
            formatVersion: RecoveryEnvelope.currentVersion,
            updatedAt: .now
        )

        try await CloudKitManager.shared.saveRecoveryEnvelope(envelope)
    }

    func fetchKeyring(
        recoveryKey: SymmetricKey
    ) async throws -> RecoveryKeyringSnapshot {
        guard let envelope = try await CloudKitManager.shared
            .fetchRecoveryEnvelope()
        else {
            throw RecoveryError.envelopeMissing
        }

        guard envelope.formatVersion == RecoveryEnvelope.currentVersion else {
            throw RecoveryError.malformedEnvelope
        }

        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(combined: envelope.encryptedBlob)
        } catch {
            throw RecoveryError.malformedEnvelope
        }

        let plaintext: Data
        do {
            plaintext = try AES.GCM.open(
                box,
                using: recoveryKey,
                authenticating: Self.aad
            )
        } catch {
            throw RecoveryError.invalidRecoveryKey
        }

        let bundle: RecoveryKeyBundle
        do {
            bundle = try JSONDecoder().decode(
                RecoveryKeyBundle.self,
                from: plaintext
            )
        } catch {
            throw RecoveryError.malformedEnvelope
        }

        guard bundle.currentVersion > 0,
              !bundle.keys.isEmpty
        else {
            throw RecoveryError.malformedEnvelope
        }

        var result: [Int: Data] = [:]

        for item in bundle.keys {
            guard item.version > 0,
                  item.keyData.count == 32,
                  result[item.version] == nil
            else {
                throw RecoveryError.malformedEnvelope
            }

            result[item.version] = item.keyData
        }

        guard result[bundle.currentVersion] != nil else {
            throw RecoveryError.malformedEnvelope
        }

        return RecoveryKeyringSnapshot(
            currentVersion: bundle.currentVersion,
            keyData: result
        )
    }

    func restore(recoveryCode: String) async throws {
        let rawRecoveryKey = try Self.decodeRecoveryKey(recoveryCode)
        let recoveryKey = SymmetricKey(data: rawRecoveryKey)
        let snapshot = try await fetchKeyring(recoveryKey: recoveryKey)

        try await KeychainManager.shared.installRecoveredKeyring(
            snapshot.keyData,
            currentVersion: snapshot.currentVersion
        )

        try await KeychainManager.shared.storeRecoveryKey(rawRecoveryKey)
    }

    func cloudRecoveryExists() async throws -> Bool {
        guard await CloudKitManager.shared.isConfigured else {
            return false
        }

        let status = try await CloudKitManager.shared.accountStatus()
        guard status == .available else {
            return false
        }

        return try await CloudKitManager.shared.fetchRecoveryEnvelope() != nil
    }

    private func random32() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(
            kSecRandomDefault,
            bytes.count,
            &bytes
        )

        guard status == errSecSuccess else {
            throw KeychainError.unexpectedStatus(status)
        }

        return Data(bytes)
    }

    private static func data(from key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    private static func encodeRecoveryKey(_ data: Data) -> String {
        let value = data
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        return "KA1-\(value)"
    }

    private static func decodeRecoveryKey(_ code: String) throws -> Data {
        var value = code.trimmingCharacters(in: .whitespacesAndNewlines)

        guard value.hasPrefix("KA1-") else {
            throw RecoveryError.invalidRecoveryKey
        }

        value.removeFirst(4)
        value = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        while value.count % 4 != 0 {
            value += "="
        }

        guard let data = Data(base64Encoded: value),
              data.count == 32
        else {
            throw RecoveryError.invalidRecoveryKey
        }

        return data
    }
}
