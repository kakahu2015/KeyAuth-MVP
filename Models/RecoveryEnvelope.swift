import Foundation

struct RecoveryEnvelope: Sendable {
    static let currentVersion = 1

    let encryptedBlob: Data
    let formatVersion: Int
    let updatedAt: Date
}

struct RecoveryMasterKey: Codable, Sendable {
    let version: Int
    let keyData: Data
}

struct RecoveryKeyBundle: Codable, Sendable {
    let epoch: UInt64
    let currentVersion: Int
    let keys: [RecoveryMasterKey]

    init(epoch: UInt64, currentVersion: Int, keys: [RecoveryMasterKey]) {
        self.epoch = epoch
        self.currentVersion = currentVersion
        self.keys = keys
    }

    private enum CodingKeys: String, CodingKey {
        case epoch
        case currentVersion
        case keys
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        epoch = try container.decodeIfPresent(UInt64.self, forKey: .epoch) ?? 0
        currentVersion = try container.decode(Int.self, forKey: .currentVersion)
        keys = try container.decode([RecoveryMasterKey].self, forKey: .keys)
    }
}
