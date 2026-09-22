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
    let currentVersion: Int
    let keys: [RecoveryMasterKey]
}
