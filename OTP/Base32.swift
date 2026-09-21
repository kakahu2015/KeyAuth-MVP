import Foundation

enum Base32Error: LocalizedError {
    case empty
    case invalidCharacter(Character)
    case invalidLength
    case invalidPadding
    case nonZeroTrailingBits

    var errorDescription: String? {
        switch self {
        case .empty:
            return "The Base32 secret is empty."
        case .invalidCharacter(let character):
            return "The Base32 secret contains an invalid character: \(character)."
        case .invalidLength:
            return "The Base32 secret has an invalid length."
        case .invalidPadding:
            return "The Base32 secret has invalid padding."
        case .nonZeroTrailingBits:
            return "The Base32 secret has invalid trailing bits."
        }
    }
}

enum Base32 {
    private static let alphabet: [Character: UInt8] = {
        let chars = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        return Dictionary(uniqueKeysWithValues: chars.enumerated().map {
            ($0.element, UInt8($0.offset))
        })
    }()

    static func decode(_ input: String) throws -> Data {
        let compact = input
            .uppercased()
            .filter { !$0.isWhitespace && $0 != "-" }

        guard !compact.isEmpty else {
            throw Base32Error.empty
        }

        let normalized: String
        if let paddingStart = compact.firstIndex(of: "=") {
            guard compact[paddingStart...].allSatisfy({ $0 == "=" }) else {
                throw Base32Error.invalidPadding
            }
            normalized = String(compact[..<paddingStart])
        } else {
            normalized = compact
        }

        guard !normalized.isEmpty else {
            throw Base32Error.empty
        }

        switch normalized.count % 8 {
        case 1, 3, 6:
            throw Base32Error.invalidLength
        default:
            break
        }

        var buffer: UInt64 = 0
        var bitsInBuffer = 0
        var output = Data()

        for char in normalized {
            guard let value = alphabet[char] else {
                throw Base32Error.invalidCharacter(char)
            }

            buffer = (buffer << 5) | UInt64(value)
            bitsInBuffer += 5

            while bitsInBuffer >= 8 {
                bitsInBuffer -= 8
                let byte = UInt8((buffer >> UInt64(bitsInBuffer)) & 0xff)
                output.append(byte)

                if bitsInBuffer == 0 {
                    buffer = 0
                } else {
                    buffer &= (1 << UInt64(bitsInBuffer)) - 1
                }
            }
        }

        guard !output.isEmpty else {
            throw Base32Error.empty
        }
        guard bitsInBuffer == 0 || buffer == 0 else {
            throw Base32Error.nonZeroTrailingBits
        }

        return output
    }
}
