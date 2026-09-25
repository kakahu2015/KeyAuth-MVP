import Foundation
import CryptoKit

enum CryptoManagerError: LocalizedError {
    case invalidCombinedBox

    var errorDescription: String? {
        switch self {
        case .invalidCombinedBox:
            return String(localized: "The encrypted account payload is invalid.")
        }
    }
}

struct CryptoManager {
    static func associatedData(
        for id: UUID,
        version: Int,
        keyVersion: Int
    ) -> Data {
        Data(
            "KeyAuth/EncryptedOTP/v\(version)/k\(keyVersion)/\(id.uuidString)".utf8
        )
    }

    static func associatedData(
        for id: UUID,
        version: Int,
        keyVersion: Int,
        createdAt: Date,
        updatedAt: Date
    ) -> Data {
        var data = associatedData(
            for: id,
            version: version,
            keyVersion: keyVersion
        )
        // Append fixed-width IEEE-754 date bits in network byte order. This
        // keeps the v4 AAD encoding deterministic across devices.
        var createdAtBits = createdAt.timeIntervalSinceReferenceDate.bitPattern.bigEndian
        var updatedAtBits = updatedAt.timeIntervalSinceReferenceDate.bitPattern.bigEndian
        withUnsafeBytes(of: &createdAtBits) {
            data.append(contentsOf: $0)
        }
        withUnsafeBytes(of: &updatedAtBits) {
            data.append(contentsOf: $0)
        }
        return data
    }

    static func legacyAssociatedData(for id: UUID, version: Int) -> Data {
        Data("KeyAuth/EncryptedOTP/v\(version)/\(id.uuidString)".utf8)
    }

    /// Encrypts the *entire* OTP payload. CloudKit never receives issuer,
    /// account name, TOTP secret, algorithm, digits, or period in plaintext.
    static func encrypt<T: Encodable>(
        _ value: T,
        using masterKey: SymmetricKey,
        associatedData: Data
    ) throws -> Data {
        let plaintext = try JSONEncoder().encode(value)
        let sealed = try AES.GCM.seal(
            plaintext,
            using: masterKey,
            authenticating: associatedData
        )

        guard let combined = sealed.combined else {
            throw CryptoManagerError.invalidCombinedBox
        }
        return combined
    }

    static func decrypt<T: Decodable>(
        _ type: T.Type,
        from encryptedBlob: Data,
        using masterKey: SymmetricKey,
        associatedData: Data
    ) throws -> T {
        let box = try AES.GCM.SealedBox(combined: encryptedBlob)
        let plaintext = try AES.GCM.open(
            box,
            using: masterKey,
            authenticating: associatedData
        )
        return try JSONDecoder().decode(type, from: plaintext)
    }

    /// Version 1 did not authenticate the record identifier or schema version.
    /// Keep this read-only fallback so existing MVP records remain recoverable.
    static func decryptLegacy<T: Decodable>(
        _ type: T.Type,
        from encryptedBlob: Data,
        using masterKey: SymmetricKey
    ) throws -> T {
        let box = try AES.GCM.SealedBox(combined: encryptedBlob)
        let plaintext = try AES.GCM.open(box, using: masterKey)
        return try JSONDecoder().decode(type, from: plaintext)
    }
}
