import Foundation
import CloudKit

enum CloudKitManagerError: LocalizedError {
    case notConfigured
    case recordTypeMissing(String)
    case recordFetchFailed
    case malformedRecord(String)

    var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "CloudKit is not configured for this build."
        case .recordTypeMissing(let recordType):
            return "CloudKit record type \(recordType) is not available in the Development schema."
        case .recordFetchFailed:
            return "CloudKit returned a record that could not be read."
        case .malformedRecord(let recordName):
            return "CloudKit record \(recordName) is malformed."
        }
    }
}

actor CloudKitManager {
    static let shared = CloudKitManager()

    private let container: CKContainer?
    private let recordType = "EncryptedOTP"
    private let recoveryRecordType = "VaultRecovery"

    private var recoveryRecordID: CKRecord.ID {
        CKRecord.ID(recordName: "primary")
    }

    init() {
        container = Self.makeConfiguredContainer()
    }

    var isConfigured: Bool {
        container != nil
    }

    private func configuredDatabase() throws -> CKDatabase {
        guard let container else {
            throw CloudKitManagerError.notConfigured
        }
        return container.privateCloudDatabase
    }

    func accountStatus() async throws -> CKAccountStatus {
        guard let container else {
            throw CloudKitManagerError.notConfigured
        }
        return try await container.accountStatus()
    }

    func save(_ item: EncryptedOTPAccount) async throws {
        let database = try configuredDatabase()
        let recordID = CKRecord.ID(recordName: item.id.uuidString)
        let record = CKRecord(recordType: recordType, recordID: recordID)

        apply(item, to: record)
        do {
            _ = try await database.save(record)
        } catch let error as CKError where error.code == .serverRecordChanged {
            // Retrying an upload whose response was lost must be idempotent.
            let existing = try await database.record(for: recordID)
            guard existing["blob"] as? Data == item.encryptedBlob else { throw error }
        }
    }

    func upsert(_ item: EncryptedOTPAccount) async throws {
        let database = try configuredDatabase()
        let recordID = CKRecord.ID(recordName: item.id.uuidString)

        do {
            // Local changes are authoritative on this device. Reuse the
            // current server record so queued edits can be retried after an
            // offline period without requiring a second network round trip.
            let record = try await database.record(for: recordID)
            apply(item, to: record)
            _ = try await database.save(record)
        } catch let error as CKError where error.code == .unknownItem {
            try await save(item)
        }
    }

    func userIdentifier() async throws -> String {
        guard let container else { throw CloudKitManagerError.notConfigured }
        return try await container.userRecordID().recordName
    }

    func update(_ item: EncryptedOTPAccount) async throws {
        let database = try configuredDatabase()
        let recordID = CKRecord.ID(recordName: item.id.uuidString)
        // Reuse the server record so the current change tag is preserved for
        // CloudKit conflict checks when editing an existing account.
        let record = try await database.record(for: recordID)

        apply(item, to: record)
        _ = try await database.save(record)
    }

    func saveRecoveryEnvelope(
        _ envelope: RecoveryEnvelope
    ) async throws {
        let database = try configuredDatabase()
        let record: CKRecord

        do {
            record = try await database.record(for: recoveryRecordID)
        } catch let error as CKError where error.code == .unknownItem {
            record = CKRecord(
                recordType: recoveryRecordType,
                recordID: recoveryRecordID
            )
        }

        apply(envelope, to: record)

        do {
            _ = try await database.save(record)
        } catch let error as CKError where error.code == .serverRecordChanged {
            // Recovery Envelope is key state. Do not use last-write-wins;
            // the caller must fetch the latest keyring before deciding.
            throw error
        }
    }

    func fetchRecoveryEnvelope() async throws -> RecoveryEnvelope? {
        let database = try configuredDatabase()

        do {
            let record = try await database.record(for: recoveryRecordID)

            guard let blob = record["blob"] as? Data,
                  let formatVersion = record["formatVersion"] as? Int,
                  let updatedAt = record["updatedAt"] as? Date
            else {
                throw CloudKitManagerError.malformedRecord(
                    recoveryRecordID.recordName
                )
            }

            return RecoveryEnvelope(
                encryptedBlob: blob,
                formatVersion: formatVersion,
                updatedAt: updatedAt
            )
        } catch let error as CKError where error.code == .unknownItem {
            return nil
        }
    }

    private func apply(_ item: EncryptedOTPAccount, to record: CKRecord) {

        // SECURITY BOUNDARY:
        // encryptedBlob is already AES-GCM encrypted on-device.
        // No OTP secret or account metadata is uploaded in plaintext.
        record["blob"] = item.encryptedBlob as CKRecordValue
        record["version"] = item.version as CKRecordValue
        record["keyVersion"] = item.keyVersion as CKRecordValue
        record["createdAt"] = item.createdAt as CKRecordValue
        record["updatedAt"] = item.updatedAt as CKRecordValue
    }

    private func apply(_ envelope: RecoveryEnvelope, to record: CKRecord) {
        record["blob"] = envelope.encryptedBlob as CKRecordValue
        record["formatVersion"] = envelope.formatVersion as CKRecordValue
        record["updatedAt"] = envelope.updatedAt as CKRecordValue
    }

    func fetchAll() async throws -> [EncryptedOTPAccount] {
        let database = try configuredDatabase()

        // Query by an application field instead of TRUEPREDICATE. CloudKit's
        // all-record query can require a recordName queryable index, while
        // updatedAt is written on every record and is automatically indexed
        // in the Development environment.
        let query = CKQuery(
            recordType: recordType,
            predicate: NSPredicate(
                format: "updatedAt >= %@",
                Date(timeIntervalSince1970: 0) as NSDate
            )
        )

        var cursor: CKQueryOperation.Cursor?
        var isFirstPage = true
        var items: [EncryptedOTPAccount] = []

        do {
            repeat {
                if isFirstPage {
                    let page = try await database.records(
                        matching: query,
                        resultsLimit: CKQueryOperation.maximumResults
                    )
                    items.append(contentsOf: try decode(page.matchResults))
                    cursor = page.queryCursor
                    isFirstPage = false
                } else if let currentCursor = cursor {
                    let page = try await database.records(
                        continuingMatchFrom: currentCursor,
                        resultsLimit: CKQueryOperation.maximumResults
                    )
                    items.append(contentsOf: try decode(page.matchResults))
                    cursor = page.queryCursor
                } else {
                    break
                }
            } while cursor != nil
        } catch {
            if Self.isMissingRecordType(error) {
                throw CloudKitManagerError.recordTypeMissing(recordType)
            }
            throw error
        }

        return items
    }

    func delete(id: UUID) async throws {
        let database = try configuredDatabase()
        let recordID = CKRecord.ID(recordName: id.uuidString)
        do {
            _ = try await database.deleteRecord(withID: recordID)
        } catch let error as CKError where error.code == .unknownItem {
            // Another device may already have deleted this account.
            return
        }
    }

    private func decode(
        _ results: [(CKRecord.ID, Result<CKRecord, any Error>)]
    ) throws -> [EncryptedOTPAccount] {
        try results.map { recordID, result in
            guard case let .success(record) = result else {
                throw CloudKitManagerError.recordFetchFailed
            }

            guard let blob = record["blob"] as? Data,
                  let version = record["version"] as? Int,
                  let createdAt = record["createdAt"] as? Date,
                  let updatedAt = record["updatedAt"] as? Date,
                  let uuid = UUID(uuidString: recordID.recordName)
            else {
                throw CloudKitManagerError.malformedRecord(recordID.recordName)
            }

            let keyVersion = record["keyVersion"] as? Int ?? 1

            return EncryptedOTPAccount(
                id: uuid,
                encryptedBlob: blob,
                version: version,
                keyVersion: keyVersion,
                createdAt: createdAt,
                updatedAt: updatedAt
            )
        }
    }

    private static func makeConfiguredContainer() -> CKContainer? {
        #if targetEnvironment(simulator)
        // Simulator builds are intentionally local-only. This keeps an
        // unsigned development build from crashing inside CKContainer.default.
        return nil
        #else
        return CKContainer.default()
        #endif
    }

    private static func isMissingRecordType(_ error: Error) -> Bool {
        (error as NSError).localizedDescription
            .localizedCaseInsensitiveContains("did not find record type")
    }

}
