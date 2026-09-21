import Foundation

enum OTPAuthParserError: LocalizedError {
    case invalidURL
    case unsupportedType
    case missingSecret
    case missingAccountName
    case duplicateParameter(String)
    case unsupportedAlgorithm(String)
    case invalidDigits
    case invalidPeriod

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid otpauth URL."
        case .unsupportedType:
            return "Only TOTP is supported in this MVP."
        case .missingSecret:
            return "The otpauth URL has no secret."
        case .missingAccountName:
            return "The otpauth URL has no account name."
        case .duplicateParameter(let name):
            return "The otpauth URL contains the parameter more than once: \(name)."
        case .unsupportedAlgorithm(let algorithm):
            return "Unsupported OTP algorithm: \(algorithm)."
        case .invalidDigits:
            return "OTP digits must be 6, 7, or 8."
        case .invalidPeriod:
            return "OTP period must be a positive number of seconds."
        }
    }
}

enum OTPAuthParser {
    static func parse(_ raw: String) throws -> OTPAccountPayload {
        guard let components = URLComponents(string: raw),
              components.scheme?.lowercased() == "otpauth"
        else {
            throw OTPAuthParserError.invalidURL
        }

        guard components.host?.lowercased() == "totp" else {
            throw OTPAuthParserError.unsupportedType
        }

        var queryItems: [String: String] = [:]
        for item in components.queryItems ?? [] {
            let name = item.name.lowercased()
            guard !name.isEmpty else {
                throw OTPAuthParserError.invalidURL
            }
            guard queryItems[name] == nil else {
                throw OTPAuthParserError.duplicateParameter(name)
            }
            queryItems[name] = item.value ?? ""
        }

        guard let secret = queryItems["secret"], !secret.isEmpty else {
            throw OTPAuthParserError.missingSecret
        }

        guard let decodedPath = components.path.removingPercentEncoding else {
            throw OTPAuthParserError.invalidURL
        }

        let rawLabel = decodedPath
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))

        let labelParts = rawLabel.split(
            separator: ":",
            maxSplits: 1,
            omittingEmptySubsequences: false
        )

        let issuerFromLabel = labelParts.count > 1 ? String(labelParts[0]) : ""
        let accountName = labelParts.count > 1 ? String(labelParts[1]) : rawLabel
        let issuer = queryItems["issuer"].flatMap { $0.isEmpty ? nil : $0 }
            ?? issuerFromLabel

        guard !accountName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw OTPAuthParserError.missingAccountName
        }

        let algorithmValue = queryItems["algorithm"]?.uppercased() ?? "SHA1"
        guard let algorithm = OTPAlgorithm(rawValue: algorithmValue) else {
            throw OTPAuthParserError.unsupportedAlgorithm(algorithmValue)
        }

        let digitsValue = queryItems["digits"] ?? "6"
        guard let digits = Int(digitsValue), (6...8).contains(digits) else {
            throw OTPAuthParserError.invalidDigits
        }

        let periodValue = queryItems["period"] ?? "30"
        guard let period = Int(periodValue), period > 0 else {
            throw OTPAuthParserError.invalidPeriod
        }

        _ = try Base32.decode(secret)

        return OTPAccountPayload(
            issuer: issuer,
            accountName: accountName,
            secretBase32: secret,
            algorithm: algorithm,
            digits: digits,
            period: period
        )
    }
}
