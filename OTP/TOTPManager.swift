import Foundation
import CryptoKit

enum TOTPError: LocalizedError {
    case invalidSecret
    case invalidDigits
    case invalidPeriod
    case invalidDate

    var errorDescription: String? {
        switch self {
        case .invalidSecret:
            return String(localized: "The OTP secret is invalid.")
        case .invalidDigits:
            return String(localized: "OTP digits must be 6, 7, or 8.")
        case .invalidPeriod:
            return String(localized: "OTP period must be positive.")
        case .invalidDate:
            return String(localized: "The OTP date is invalid.")
        }
    }
}

struct TOTPManager {
    static func code(
        secretBase32: String,
        algorithm: OTPAlgorithm = .sha1,
        digits: Int = 6,
        period: Int = 30,
        date: Date = .now
    ) throws -> String {
        guard (6...8).contains(digits) else {
            throw TOTPError.invalidDigits
        }
        guard period > 0 else {
            throw TOTPError.invalidPeriod
        }
        guard date.timeIntervalSince1970 >= 0 else {
            throw TOTPError.invalidDate
        }

        let secret = try Base32.decode(secretBase32)
        let counter = UInt64(floor(date.timeIntervalSince1970 / Double(period)))

        var bigEndianCounter = counter.bigEndian
        let counterData = withUnsafeBytes(of: &bigEndianCounter) { Data($0) }

        let key = SymmetricKey(data: secret)
        let digest: Data

        switch algorithm {
        case .sha1:
            digest = Data(HMAC<Insecure.SHA1>.authenticationCode(
                for: counterData,
                using: key
            ))
        case .sha256:
            digest = Data(HMAC<SHA256>.authenticationCode(
                for: counterData,
                using: key
            ))
        case .sha512:
            digest = Data(HMAC<SHA512>.authenticationCode(
                for: counterData,
                using: key
            ))
        }

        guard let lastByte = digest.last else {
            throw TOTPError.invalidSecret
        }

        let offset = Int(lastByte & 0x0f)

        let binary =
            (UInt32(digest[offset]) & 0x7f) << 24 |
            UInt32(digest[offset + 1]) << 16 |
            UInt32(digest[offset + 2]) << 8 |
            UInt32(digest[offset + 3])

        var divisor: UInt32 = 1
        for _ in 0..<digits {
            divisor *= 10
        }
        let otp = binary % divisor

        let raw = String(otp)
        return String(repeating: "0", count: max(0, digits - raw.count)) + raw
    }

    static func secondsRemaining(period: Int = 30, date: Date = .now) -> Int {
        guard period > 0 else {
            return 0
        }
        let current = Int(date.timeIntervalSince1970)
        return period - (current % period)
    }
}
