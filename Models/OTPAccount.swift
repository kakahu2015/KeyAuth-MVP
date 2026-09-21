import Foundation

enum OTPAlgorithm: String, Codable, CaseIterable, Sendable, Hashable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"
}

struct OTPAccountIdentity: Hashable, Sendable {
    let issuer: String
    let accountName: String
    let secretBase32: String
    let algorithm: OTPAlgorithm
    let digits: Int
    let period: Int
}

struct OTPAccountPayload: Codable, Sendable, Hashable {
    let issuer: String
    let accountName: String
    let secretBase32: String
    let algorithm: OTPAlgorithm
    let digits: Int
    let period: Int
    let displayName: String?

    init(
        issuer: String,
        accountName: String,
        secretBase32: String,
        algorithm: OTPAlgorithm,
        digits: Int,
        period: Int,
        displayName: String? = nil
    ) {
        self.issuer = issuer
        self.accountName = accountName
        self.secretBase32 = secretBase32
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.displayName = displayName
    }

    var identity: OTPAccountIdentity {
        OTPAccountIdentity(
            issuer: issuer,
            accountName: accountName,
            secretBase32: secretBase32,
            algorithm: algorithm,
            digits: digits,
            period: period
        )
    }

    var displayTitle: String {
        if let displayName,
           !displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return displayName
        }
        return issuer.isEmpty ? accountName : issuer
    }

    var displaySubtitle: String? {
        let values = [issuer, accountName].filter {
            !$0.isEmpty && $0 != displayTitle
        }
        guard !values.isEmpty else { return nil }
        return values.joined(separator: " · ")
    }
}

struct EncryptedOTPAccount: Identifiable, Codable, Hashable, Sendable {
    static let currentVersion = 2

    let id: UUID
    var encryptedBlob: Data
    var version: Int
    var createdAt: Date
    var updatedAt: Date

    init(
        id: UUID = UUID(),
        encryptedBlob: Data,
        version: Int = EncryptedOTPAccount.currentVersion,
        createdAt: Date = .now,
        updatedAt: Date = .now
    ) {
        self.id = id
        self.encryptedBlob = encryptedBlob
        self.version = version
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}
