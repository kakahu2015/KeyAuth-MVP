import Foundation
import CryptoKit
import Security

enum VaultTransferError: LocalizedError {
    case invalidKey
    case invalidBackup
    case tooLarge
    case randomFailed

    var errorDescription: String? {
        switch self {
        case .invalidKey:
            return String(localized: "Enter the backup key saved when this file was exported.")
        case .invalidBackup:
            return String(localized: "The backup could not be opened. Check the file and backup key.")
        case .tooLarge:
            return String(localized: "This backup is too large to import.")
        case .randomFailed:
            return String(localized: "A secure backup key could not be generated.")
        }
    }
}

struct VaultTransferManager {
    static let maximumFileSize = 16 * 1024 * 1024
    private static let associatedData = Data("KeyAuth/EncryptedBackup/v1".utf8)

    private struct Envelope: Codable {
        let formatVersion: Int
        let encryptedBlob: Data
    }

    private struct Contents: Codable {
        let createdAt: Date
        let accounts: [OTPAccountPayload]
    }

    struct Export {
        let data: Data
        let key: String
    }

    static func export(accounts: [OTPAccountPayload]) throws -> Export {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw VaultTransferError.randomFailed
        }
        let keyData = Data(bytes)
        let blob = try CryptoManager.encrypt(
            Contents(createdAt: .now, accounts: accounts),
            using: SymmetricKey(data: keyData),
            associatedData: associatedData
        )
        let data = try JSONEncoder().encode(Envelope(formatVersion: 1, encryptedBlob: blob))
        guard data.count <= maximumFileSize else { throw VaultTransferError.tooLarge }
        let encoded = keyData.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return Export(data: data, key: "KAB1-" + encoded)
    }

    static func open(data: Data, key rawKey: String) throws -> [OTPAccountPayload] {
        guard data.count <= maximumFileSize else { throw VaultTransferError.tooLarge }
        var encoded = rawKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard encoded.hasPrefix("KAB1-") else { throw VaultTransferError.invalidKey }
        encoded.removeFirst(5)
        encoded = encoded.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        encoded += String(repeating: "=", count: (4 - encoded.count % 4) % 4)
        guard let keyData = Data(base64Encoded: encoded), keyData.count == 32 else {
            throw VaultTransferError.invalidKey
        }
        do {
            let envelope = try JSONDecoder().decode(Envelope.self, from: data)
            guard envelope.formatVersion == 1 else { throw VaultTransferError.invalidBackup }
            let contents = try CryptoManager.decrypt(
                Contents.self,
                from: envelope.encryptedBlob,
                using: SymmetricKey(data: keyData),
                associatedData: associatedData
            )
            for account in contents.accounts {
                guard !account.accountName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    throw VaultTransferError.invalidBackup
                }
                _ = try TOTPManager.code(
                    secretBase32: account.secretBase32,
                    algorithm: account.algorithm,
                    digits: account.digits,
                    period: account.period
                )
            }
            return contents.accounts
        } catch {
            throw VaultTransferError.invalidBackup
        }
    }
}
