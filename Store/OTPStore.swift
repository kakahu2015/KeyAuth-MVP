import Foundation
import CryptoKit
import CloudKit
@preconcurrency import LocalAuthentication

enum OTPStoreError: LocalizedError {
    case cloudAccountUnavailable
    case masterKeyUnavailable
    case accountNotFound
    case syncIncomplete
    case undecryptableRecord

    var errorDescription: String? {
        switch self {
        case .cloudAccountUnavailable:
            return String(localized: "Sign in to iCloud before using KeyAuth sync.")
        case .masterKeyUnavailable:
            return String(localized: "The KeyAuth master key is unavailable.")
        case .accountNotFound:
            return String(localized: "The account is no longer available. Refresh and try again.")
        case .syncIncomplete:
            return String(localized: "Your data is available on this device, but iCloud has not synced yet. Tap to retry.")
        case .undecryptableRecord:
            return String(
                localized: "A CloudKit account could not be decrypted. The app kept the data instead of hiding it."
            )
        }
    }
}

@MainActor
final class OTPStore: ObservableObject {
    @Published private(set) var accounts: [DecryptedAccount] = []
    @Published private(set) var conflictingAccountID: UUID?
    @Published private(set) var conflictRemoteMissing = false
    @Published private(set) var isResolvingConflict = false
    @Published var lastError: String?
    @Published var isLoading = false
    @Published private(set) var isReady = false
    @Published private(set) var isCloudSyncEnabled = false
    @Published private(set) var syncMessage: String?
    @Published private(set) var recoveryEnabled = false

    struct DecryptedAccount: Identifiable {
        let id: UUID
        let payload: OTPAccountPayload
        let createdAt: Date
        let updatedAt: Date
    }

    private var masterKeys: [Int: SymmetricKey] = [:]
    private var vaultSessionID: UUID?
    private var currentKeyVersion = 1
    private var recoveryKey: SymmetricKey?

    private var masterKey: SymmetricKey? {
        masterKeys[currentKeyVersion]
    }

    private var cloudOwner: String?
    private var syncTask: Task<Void, Never>?
    private var syncID: UUID?
    private var syncRequested = false
    private let deletedIDsKey = "KeyAuth.ConfirmedDeletedAccountIDs"
    private let cloudOwnerKey = "KeyAuth.CloudOwner.v1"
    private var deletedIDs = Set(
        UserDefaults.standard.stringArray(forKey: "KeyAuth.ConfirmedDeletedAccountIDs") ?? []
    )

    private struct CloudFetchResult {
        let accounts: [EncryptedOTPAccount]
        let isAuthoritative: Bool
    }

    func bootstrap() async {
        await syncTask?.value
        isLoading = true
        lastError = nil
        syncMessage = nil
        isReady = false
        masterKeys = [:]
        currentKeyVersion = 1
        recoveryKey = nil
        recoveryEnabled = false
        accounts = []
        cloudOwner = UserDefaults.standard.string(forKey: cloudOwnerKey)
        isCloudSyncEnabled = await CloudKitManager.shared.isConfigured
        isLoading = false
    }

    @discardableResult
    func unlock(
        keys: [Int: SymmetricKey],
        currentVersion: Int,
        recoveryKey: SymmetricKey?
    ) async -> Bool {
        await syncTask?.value
        isLoading = true
        lastError = nil
        syncMessage = nil
        vaultSessionID = UUID()
        masterKeys = keys
        currentKeyVersion = currentVersion
        self.recoveryKey = recoveryKey
        recoveryEnabled = recoveryKey != nil
        isReady = false

        do {
            guard masterKey != nil else {
                throw OTPStoreError.masterKeyUnavailable
            }

            let localEncrypted = try LocalEncryptedStore.shared.fetchAll()
            let uniqueEncrypted = try removeExactDuplicates(
                from: localEncrypted
            )
            try installLocalAccounts(uniqueEncrypted)
            isReady = true
            isLoading = false
            startPendingUploads()
            return true
        } catch {
            masterKeys = [:]
            self.recoveryKey = nil
            recoveryEnabled = false
            accounts = []
            isReady = false
            isLoading = false
            lastError = error.localizedDescription
            return false
        }
    }

    func lock() {
        vaultSessionID = nil
        syncTask?.cancel()
        syncID = nil
        syncTask = nil
        syncRequested = false
        masterKeys = [:]
        recoveryKey = nil
        recoveryEnabled = false
        accounts = []
        isReady = false
        isLoading = false
        syncMessage = nil
    }

    func refresh() async throws {
        guard isReady, masterKey != nil else {
            throw OTPStoreError.masterKeyUnavailable
        }

        await syncTask?.value

        if isCloudSyncEnabled {
            startPendingUploads()
            await syncTask?.value
            if syncMessage != nil && conflictingAccountID == nil {
                throw OTPStoreError.syncIncomplete
            }
        } else {
            let localEncrypted = try LocalEncryptedStore.shared.fetchAll()
            try installLocalAccounts(localEncrypted)
        }
    }

    private func fetchRemoteAccounts() async throws -> CloudFetchResult {
        do {
#if DEBUG
            let remote = try await CloudKitManager.shared.fetchAll()
#else
            let remote = try await CloudKitManager.shared.fetchAll()
#endif
            // Queries may lag behind writes. Confirm missing or differing
            // local records directly before installing the cloud snapshot.
            var confirmed = Dictionary(uniqueKeysWithValues: remote.map { ($0.id, $0) })
            try Task.checkCancellation()
            let local = try LocalEncryptedStore.shared.fetchAll()
            for item in local {
                if let queried = confirmed[item.id],
                   queried.cloudChangeTag == item.cloudChangeTag,
                   queried.encryptedBlob == item.encryptedBlob { continue }
                let record = try await CloudKitManager.shared.fetch(id: item.id)
                try Task.checkCancellation()
                if let record {
                    confirmed[item.id] = record
                } else {
                    confirmed.removeValue(forKey: item.id)
                    if item.cloudChangeTag != nil {
                        if item.needsUpload {
                            conflictingAccountID = item.id
                            conflictRemoteMissing = true
                            throw CloudKitManagerError.accountMissing(item.id)
                        }
                        deletedIDs.insert(item.id.uuidString)
                        accounts.removeAll { $0.id == item.id }
                    }
                }
            }
            UserDefaults.standard.set(Array(deletedIDs), forKey: deletedIDsKey)
            return CloudFetchResult(accounts: Array(confirmed.values), isAuthoritative: true)
        } catch CloudKitManagerError.recordTypeMissing {
            // CloudKit Development creates the record type on the first save.
            // An absent schema is not an authoritative empty vault: preserve
            // local accounts and let the pending queue create the first record.
            return CloudFetchResult(accounts: [], isAuthoritative: false)
        }
    }

    private func saveEncryptedAccount(_ item: EncryptedOTPAccount) throws {
        try LocalEncryptedStore.shared.save(item)
        if isCloudSyncEnabled {
            do {
                try queueUpload(item)
                syncMessage = String(localized: "Saved locally; syncing with iCloud…")
            } catch {
                // needsUpload is in the vault itself, so a failed queue write
                // cannot lose the durable local change or its retry intent.
                syncMessage = String(localized: "Your data is available on this device, but iCloud has not synced yet. Tap to retry.")
            }
        }
    }

    private func updateEncryptedAccount(_ item: EncryptedOTPAccount) throws {
        try saveEncryptedAccount(item)
    }

    private func deleteEncryptedAccount(id: UUID) throws {
        try LocalEncryptedStore.shared.delete(id: id)

        if isCloudSyncEnabled {
            let owner = cloudOwner ?? PendingCloudUploads.unassignedOwner
            try PendingCloudUploads.shared.remove(id: id, owner: owner)
            try PendingCloudDeletes.shared.add(id: id, owner: owner)
        }
    }

    private func replaceAccounts(
        with encrypted: [EncryptedOTPAccount]
    ) throws {
        var decoded: [DecryptedAccount] = []
        decoded.reserveCapacity(encrypted.count)

        for item in encrypted where !deletedIDs.contains(item.id.uuidString) {
            let record = try decryptRecord(for: item)
            decoded.append(DecryptedAccount(
                id: item.id,
                payload: record.otp,
                createdAt: record.createdAt,
                updatedAt: record.updatedAt
            ))
        }

        accounts = decoded.sorted {
            $0.payload.displayTitle.localizedCaseInsensitiveCompare(
                $1.payload.displayTitle
            ) == .orderedAscending
        }
    }

    private func decryptRecord(for item: EncryptedOTPAccount) throws -> EncryptedOTPRecordPayload {
        guard let key = masterKeys[item.keyVersion] else { throw OTPStoreError.masterKeyUnavailable }
        do { return try OTPRecordCodec.decrypt(item, using: key) }
        catch { throw OTPStoreError.undecryptableRecord }
    }

    private func encryptRecord(
        _ record: EncryptedOTPRecordPayload,
        for id: UUID,
        using key: SymmetricKey,
        keyVersion: Int,
        cloudChangeTag: String? = nil,
        canCreateCloudRecord: Bool = true
    ) throws -> EncryptedOTPAccount {
        try OTPRecordCodec.encrypt(record, for: id, using: key,
                                   keyVersion: keyVersion, cloudChangeTag: cloudChangeTag,
                                   canCreateCloudRecord: canCreateCloudRecord)
    }

    private func removeExactDuplicates(
        from encrypted: [EncryptedOTPAccount]
    ) throws -> [EncryptedOTPAccount] {
        var decoded: [(item: EncryptedOTPAccount, record: EncryptedOTPRecordPayload)] = []
        decoded.reserveCapacity(encrypted.count)

        for item in encrypted {
            let record = try decryptRecord(for: item)
            decoded.append((item, record))
        }

        decoded.sort {
            if $0.record.createdAt != $1.record.createdAt {
                return $0.record.createdAt < $1.record.createdAt
            }

            return $0.item.id.uuidString < $1.item.id.uuidString
        }

        var seenAccounts = Set<OTPAccountIdentity>()
        var unique: [EncryptedOTPAccount] = []
        unique.reserveCapacity(decoded.count)

        for entry in decoded {
            let item = entry.item
            let record = entry.record
            guard seenAccounts.insert(record.otp.identity).inserted else {
                // Keep the oldest copy and remove later records for the same
                // OTP credential, even if their display names differ.
                try deleteEncryptedAccount(id: item.id)
                continue
            }
            unique.append(item)
        }

        return unique
    }

    @discardableResult
    func add(otpauthURL: String) async -> Bool {
        lastError = nil

        do {
            guard let masterKey else {
                throw OTPStoreError.masterKeyUnavailable
            }

            let payload = try OTPAuthParser.parse(otpauthURL)

            // Validate the secret before storing it.
            _ = try TOTPManager.code(
                secretBase32: payload.secretBase32,
                algorithm: payload.algorithm,
                digits: payload.digits,
                period: payload.period
            )

            // Scanning the same QR code again must not create another record.
            guard !accounts.contains(where: {
                $0.payload.identity == payload.identity
            }) else {
                return true
            }

            let id = UUID()
            let keyVersion = currentKeyVersion
            let now = Date()
            let protectedPayload = EncryptedOTPRecordPayload(
                otp: payload,
                createdAt: now,
                updatedAt: now
            )
            let item = try encryptRecord(
                protectedPayload,
                for: id,
                using: masterKey,
                keyVersion: keyVersion
            )

            try saveEncryptedAccount(item)
            publishSavedAccount(item, record: protectedPayload)
            startPendingUploads()
            return true
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    @discardableResult
    func updateDisplayName(for id: UUID, to rawName: String, groupName rawGroup: String? = nil) async -> Bool {
        lastError = nil

        do {
            guard let masterKey,
                  !deletedIDs.contains(id.uuidString),
                  let account = accounts.first(where: { $0.id == id })
            else {
                throw OTPStoreError.accountNotFound
            }

            let displayName = rawName.trimmingCharacters(
                in: .whitespacesAndNewlines
            )
            let payload = OTPAccountPayload(
                issuer: account.payload.issuer,
                accountName: account.payload.accountName,
                secretBase32: account.payload.secretBase32,
                algorithm: account.payload.algorithm,
                digits: account.payload.digits,
                period: account.payload.period,
                displayName: displayName.isEmpty ? nil : displayName,
                groupName: rawGroup.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) } ?? account.payload.groupName
            )
            let previous = try LocalEncryptedStore.shared.fetchAll().first { $0.id == id }
            let keyVersion = currentKeyVersion
            let protectedPayload = EncryptedOTPRecordPayload(
                otp: payload,
                createdAt: account.createdAt,
                updatedAt: .now
            )
            let item = try encryptRecord(
                protectedPayload,
                for: id,
                using: masterKey,
                keyVersion: keyVersion,
                cloudChangeTag: previous?.cloudChangeTag,
                canCreateCloudRecord: previous?.canCreateCloudRecord ?? false
            )

            try updateEncryptedAccount(item)
            publishSavedAccount(item, record: protectedPayload)
            startPendingUploads()
            return true
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    @discardableResult
    func delete(id: UUID) async -> Bool {
        await delete(ids: [id])
    }

    @discardableResult
    func delete(ids: [UUID]) async -> Bool {
        lastError = nil

        do {
            guard isReady, masterKey != nil else { throw OTPStoreError.masterKeyUnavailable }
            // Remove locally first. The cloud delete is queued and retried in
            // the background, so a network outage cannot block the vault.
            for id in ids {
                try deleteEncryptedAccount(id: id)
                deletedIDs.insert(id.uuidString)
                UserDefaults.standard.set(Array(deletedIDs), forKey: deletedIDsKey)
                accounts.removeAll { $0.id == id }
                if conflictingAccountID == id { conflictingAccountID = nil }
            }
            startPendingUploads()
            return true
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    func exportVault() throws -> VaultTransferManager.Export {
        guard isReady, masterKey != nil else { throw OTPStoreError.masterKeyUnavailable }
        return try VaultTransferManager.export(accounts: accounts.map(\.payload))
    }

    func importVault(data: Data, backupKey: String) throws -> Int {
        guard isReady, let masterKey else { throw OTPStoreError.masterKeyUnavailable }
        let imported = try VaultTransferManager.open(data: data, key: backupKey)
        var identities = Set(accounts.map { $0.payload.identity })
        var additions: [EncryptedOTPAccount] = []
        for payload in imported where identities.insert(payload.identity).inserted {
            let now = Date()
            additions.append(try encryptRecord(
                EncryptedOTPRecordPayload(otp: payload, createdAt: now, updatedAt: now),
                for: UUID(), using: masterKey, keyVersion: currentKeyVersion
            ))
        }
        guard !additions.isEmpty else { return 0 }
        let existing = try LocalEncryptedStore.shared.fetchAll()
        let merged = existing + additions
        try LocalEncryptedStore.shared.replaceAll(merged)
        try replaceAccounts(with: merged)
        if isCloudSyncEnabled {
            let owner = cloudOwner ?? PendingCloudUploads.unassignedOwner
            do { try PendingCloudUploads.shared.save(additions, owner: owner) }
            catch {
                syncMessage = String(localized: "Your data is available on this device, but iCloud has not synced yet. Tap to retry.")
            }
            startPendingUploads()
        }
        return additions.count
    }

    @discardableResult
    func enableRecovery() async -> String? {
        lastError = nil

        let session = vaultSessionID
        guard !recoveryEnabled else {
            lastError = String(
                localized: "Recovery feature is already enabled; this version does not support generating a new recovery key."
            )
            return nil
        }

        do {
            guard isReady, masterKey != nil else {
                throw OTPStoreError.masterKeyUnavailable
            }

            guard vaultSessionID == session, isReady else { return nil }
            UserDefaults.standard.set(false, forKey: "KeyAuth.RecoveryKeySaved")
            let result = try await RecoveryManager.shared.enableRecovery(
                keys: masterKeys,
                currentVersion: currentKeyVersion
            )

            guard vaultSessionID == session, isReady else { return nil }
            recoveryKey = result.key
            recoveryEnabled = true
            return result.code
        } catch {
            lastError = error.localizedDescription
            return nil
        }
    }

    func pendingRecoveryCode() -> String? {
        guard UserDefaults.standard.object(forKey: "KeyAuth.RecoveryKeySaved") != nil,
              !UserDefaults.standard.bool(forKey: "KeyAuth.RecoveryKeySaved"),
              let recoveryKey else { return nil }
        let encoded = recoveryKey.withUnsafeBytes { Data($0) }
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "KA1-\(encoded)"
    }

    func confirmRecoveryKeySaved() {
        UserDefaults.standard.set(true, forKey: "KeyAuth.RecoveryKeySaved")
    }

    @discardableResult
    func rotateMasterKey(context: LAContext) async -> Bool {
        let session = vaultSessionID
        lastError = nil

        do {
            guard isReady, masterKey != nil else {
                throw OTPStoreError.masterKeyUnavailable
            }

            // Fetch the latest global keyring before allocating a new version.
            // This prevents two devices from independently creating the same
            // version number from stale state.
            if isCloudSyncEnabled {
                try await refresh()
                guard conflictingAccountID == nil else { throw OTPStoreError.syncIncomplete }
            }

            try await refreshRecoveryKeyringIfNeeded()

            let (newVersion, newKey) = try await KeychainManager.shared
                .createNextMasterKey(context: context)

            guard vaultSessionID == session, isReady else { throw CancellationError() }
            var rotationKeyring = masterKeys
            rotationKeyring[newVersion] = newKey

            if let recoveryKey {
                try await RecoveryManager.shared.updateEnvelope(
                    recoveryKey: recoveryKey,
                    keys: rotationKeyring,
                    currentVersion: newVersion
                )
            } else if try await RecoveryManager.shared
                .cloudRecoveryExists() {
                // Recovery is enabled in CloudKit, but this device cannot
                // update the envelope safely without its Recovery Key.
                throw RecoveryError.recoveryKeyUnavailable
            }

            guard vaultSessionID == session, isReady else { throw CancellationError() }
            let encrypted = try LocalEncryptedStore.shared.fetchAll()
            var rotated: [EncryptedOTPAccount] = []
            rotated.reserveCapacity(encrypted.count)

            for item in encrypted {
                let record = try decryptRecord(for: item)
                let rotatedItem = try encryptRecord(
                    record,
                    for: item.id,
                    using: newKey,
                    keyVersion: newVersion,
                    cloudChangeTag: item.cloudChangeTag,
                    canCreateCloudRecord: item.canCreateCloudRecord
                )
                rotated.append(rotatedItem)
            }

            // Replace the local vault before making the new version current.
            try LocalEncryptedStore.shared.replaceAll(rotated)

            // Keep both keys available while queued uploads are sent.
            masterKeys[newVersion] = newKey

            for item in rotated {
                try queueUpload(item)
            }

            currentKeyVersion = newVersion
            await KeychainManager.shared.commitRotation(version: newVersion)

            guard vaultSessionID == session, isReady else { throw CancellationError() }
            try replaceAccounts(with: LocalEncryptedStore.shared.fetchAll())
            startPendingUploads()
            return true
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    func clearError() {
        lastError = nil
    }

    private func installLocalAccounts(
        _ encrypted: [EncryptedOTPAccount]
    ) throws {
        guard let currentKey = masterKey else {
            throw OTPStoreError.masterKeyUnavailable
        }

        let visible = encrypted.filter {
            !deletedIDs.contains($0.id.uuidString)
        }
        var current: [EncryptedOTPAccount] = []
        current.reserveCapacity(visible.count)

        for item in visible {
            let record = try decryptRecord(for: item)
            guard item.version != EncryptedOTPAccount.currentVersion ||
                    item.keyVersion != currentKeyVersion
            else {
                current.append(item)
                continue
            }

            let migrated = try encryptRecord(
                record,
                for: item.id,
                using: currentKey,
                keyVersion: currentKeyVersion,
                cloudChangeTag: item.cloudChangeTag,
                    canCreateCloudRecord: item.canCreateCloudRecord
            )
            current.append(migrated)
            if isCloudSyncEnabled {
                try queueUpload(migrated)
            }
        }

        try LocalEncryptedStore.shared.replaceAll(current)
        try replaceAccounts(with: current)
    }

    private func queueUpload(_ item: EncryptedOTPAccount) throws {
        let owner = cloudOwner ?? PendingCloudUploads.unassignedOwner
        try PendingCloudDeletes.shared.remove(id: item.id, owner: owner)
        try PendingCloudUploads.shared.save(item, owner: owner)
    }

    private func connectToCloud() async throws -> CloudFetchResult {
        guard isCloudSyncEnabled else {
            throw CloudKitManagerError.notConfigured
        }

        let accountStatus = try await CloudKitManager.shared.accountStatus()
        guard accountStatus == .available else {
            throw OTPStoreError.cloudAccountUnavailable
        }

        let owner = try await CloudKitManager.shared.userIdentifier()
        if let previousOwner = cloudOwner, previousOwner != owner {
            throw OTPStoreError.cloudAccountUnavailable
        }

        try Task.checkCancellation()
        cloudOwner = owner
        UserDefaults.standard.set(owner, forKey: cloudOwnerKey)

        try PendingCloudUploads.shared.move(
            from: PendingCloudUploads.unassignedOwner,
            to: owner
        )
        try PendingCloudDeletes.shared.move(
            from: PendingCloudUploads.unassignedOwner,
            to: owner
        )

        return try await fetchRemoteAccounts()
    }

    private func refreshRecoveryKeyringIfNeeded() async throws {
        guard let recoveryKey else {
            return
        }

        do {
            let snapshot = try await RecoveryManager.shared.fetchKeyring(
                recoveryKey: recoveryKey
            )

            try Task.checkCancellation()
            guard isReady, masterKey != nil else { throw CancellationError() }
            if snapshot.currentVersion > currentKeyVersion {
                try await KeychainManager.shared.installRecoveredKeyring(
                    snapshot.keyData,
                    currentVersion: snapshot.currentVersion
                )

                try Task.checkCancellation()
                guard isReady, masterKey != nil else { throw CancellationError() }
                for (version, data) in snapshot.keyData {
                    masterKeys[version] = SymmetricKey(data: data)
                }

                currentKeyVersion = snapshot.currentVersion
            } else if snapshot.currentVersion < currentKeyVersion {
                // This device is ahead. Repair a stale envelope rather than
                // downgrading the local vault or re-uploading old ciphertext.
                try await RecoveryManager.shared.updateEnvelope(
                    recoveryKey: recoveryKey,
                    keys: masterKeys,
                    currentVersion: currentKeyVersion
                )
            }
        } catch RecoveryError.envelopeMissing {
            try Task.checkCancellation()
            guard isReady, masterKey != nil else { throw CancellationError() }
            // A local Recovery Key without an envelope can safely recreate it
            // from the current in-memory key ring.
            try await RecoveryManager.shared.updateEnvelope(
                recoveryKey: recoveryKey,
                keys: masterKeys,
                currentVersion: currentKeyVersion
            )
        }
    }

    private func upgradePendingUploads(owner: String) throws {
        guard let currentKey = masterKey else {
            throw OTPStoreError.masterKeyUnavailable
        }

        let pending = try PendingCloudUploads.shared.fetch(owner: owner)

        for item in pending where
            item.version != EncryptedOTPAccount.currentVersion ||
                item.keyVersion != currentKeyVersion {
            let record = try decryptRecord(for: item)
            let migrated = try encryptRecord(
                record,
                for: item.id,
                using: currentKey,
                keyVersion: currentKeyVersion,
                cloudChangeTag: item.cloudChangeTag,
                    canCreateCloudRecord: item.canCreateCloudRecord
            )

            try PendingCloudUploads.shared.save(
                migrated,
                owner: owner
            )
            try LocalEncryptedStore.shared.save(migrated)
        }
    }

    private func synchronizeCloud() async throws {
        try await refreshRecoveryKeyringIfNeeded()

        let initialCloud = try await connectToCloud()
        try Task.checkCancellation()
        guard let owner = cloudOwner else {
            throw OTPStoreError.cloudAccountUnavailable
        }

        syncMessage = String(localized: "Syncing with iCloud…")
        for item in try LocalEncryptedStore.shared.fetchAll()
            where item.needsUpload && !deletedIDs.contains(item.id.uuidString) {
            try queueUpload(item)
        }
        let remoteIDs = Set(initialCloud.accounts.map(\.id))
        if initialCloud.isAuthoritative,
           let legacy = try LocalEncryptedStore.shared.fetchAll().first(where: {
               $0.cloudChangeTag == nil && !$0.canCreateCloudRecord &&
               !remoteIDs.contains($0.id) && !deletedIDs.contains($0.id.uuidString)
           }) {
            conflictingAccountID = legacy.id
            conflictRemoteMissing = true
            throw CloudKitManagerError.accountChanged(legacy.id)
        }
        try upgradePendingUploads(owner: owner)
        try await flushPendingChanges(owner: owner)

        let latestCloud = try await fetchRemoteAccounts()
        try Task.checkCancellation()
        let local = try LocalEncryptedStore.shared.fetchAll()
        let remainingUploads = try PendingCloudUploads.shared.fetch(owner: owner)
        let remainingDeletes = Set(
            try PendingCloudDeletes.shared.fetch(owner: owner)
        )
        let merged = merge(
            local: local,
            remote: latestCloud.accounts,
            remoteIsAuthoritative: initialCloud.isAuthoritative && latestCloud.isAuthoritative,
            pendingUploads: remainingUploads,
            pendingDeletes: remainingDeletes
        )
        let uniqueMerged = try removeExactDuplicates(from: merged)
        try installLocalAccounts(uniqueMerged)

        // Duplicate cleanup and changes made while the first sync was in
        // flight may have added more queued work. Flush once more, then use
        // the resulting cloud view as the final local snapshot.
        try await flushPendingChanges(owner: owner)
        let finalCloud = try await fetchRemoteAccounts()
        try Task.checkCancellation()
        let finalLocal = try LocalEncryptedStore.shared.fetchAll()
        let finalUploads = try PendingCloudUploads.shared.fetch(owner: owner)
        let finalDeletes = Set(
            try PendingCloudDeletes.shared.fetch(owner: owner)
        )
        let finalMerged = merge(
            local: finalLocal,
            remote: finalCloud.accounts,
            remoteIsAuthoritative: finalCloud.isAuthoritative,
            pendingUploads: finalUploads,
            pendingDeletes: finalDeletes
        )
        try installLocalAccounts(finalMerged)

        try await cleanupOldMasterKeysIfSafe(
            local: finalMerged,
            remote: finalCloud.accounts,
            remoteIsAuthoritative: finalCloud.isAuthoritative,
            pendingUploads: finalUploads,
            pendingDeletes: finalDeletes
        )

        syncMessage = nil
    }

    private func cleanupOldMasterKeysIfSafe(
        local: [EncryptedOTPAccount],
        remote: [EncryptedOTPAccount],
        remoteIsAuthoritative: Bool,
        pendingUploads: [EncryptedOTPAccount],
        pendingDeletes: Set<UUID>
    ) async throws {
        // Only a trusted complete CloudKit result can authorize key cleanup.
        guard remoteIsAuthoritative else {
            return
        }

        // Never delete an old key while any encrypted change is still pending.
        guard pendingUploads.isEmpty,
              pendingDeletes.isEmpty else {
            return
        }

        // Every local record must already use the current key.
        guard local.allSatisfy({
            $0.keyVersion == currentKeyVersion
        }) else {
            return
        }

        // Every cloud record must also use the current key.
        guard remote.allSatisfy({
            $0.keyVersion == currentKeyVersion
        }) else {
            return
        }

        // The two complete snapshots must contain the same records. This
        // prevents deleting an old key when CloudKit returned too few items.
        let localIDs = Set(local.map(\.id))
        let remoteIDs = Set(remote.map(\.id))
        guard localIDs == remoteIDs else {
            return
        }

        if let recoveryKey {
            guard let currentKey = masterKey else {
                throw OTPStoreError.masterKeyUnavailable
            }

            // The cloud is fully migrated; shrink the recovery envelope before
            // removing obsolete device-bound keys.
            try await RecoveryManager.shared.updateEnvelope(
                recoveryKey: recoveryKey,
                keys: [currentKeyVersion: currentKey],
                currentVersion: currentKeyVersion
            )
        } else if try await RecoveryManager.shared.cloudRecoveryExists() {
            // Recovery is enabled remotely, but this device cannot update the
            // envelope. Keep the old keys rather than breaking recovery.
            return
        }

        try Task.checkCancellation()
        let versions = await KeychainManager.shared.knownKeyVersions()
        let obsoleteVersions = versions.filter {
            $0 < currentKeyVersion
        }

        for version in obsoleteVersions {
            try Task.checkCancellation()
            try await KeychainManager.shared
                .deleteMasterKey(version: version)
            masterKeys.removeValue(forKey: version)
        }
    }

    private func flushPendingChanges(owner: String) async throws {
        while true {
            let pendingUploads = try PendingCloudUploads.shared.fetch(owner: owner)
            let pendingDeletes = try PendingCloudDeletes.shared.fetch(owner: owner)
            guard !pendingUploads.isEmpty || !pendingDeletes.isEmpty else { break }

            let deleted = Set(pendingDeletes)
            for id in pendingDeletes {
                try await CloudKitManager.shared.delete(id: id)
                try Task.checkCancellation()
                try PendingCloudDeletes.shared.remove(id: id, owner: owner)
                try PendingCloudUploads.shared.remove(id: id, owner: owner)
            }

            for item in pendingUploads where !deleted.contains(item.id) {
                try Task.checkCancellation()
                if deletedIDs.contains(item.id.uuidString) {
                    try PendingCloudUploads.shared.remove(id: item.id, owner: owner)
                    try LocalEncryptedStore.shared.delete(id: item.id)
                    continue
                }
                guard try PendingCloudUploads.shared.fetch(owner: owner).contains(where: {
                          $0.id == item.id && $0.encryptedBlob == item.encryptedBlob
                      }) else { continue }
                do {
                    let saved = try await CloudKitManager.shared.upsert(item)
                    try Task.checkCancellation()
                    if let saved {
                        try LocalEncryptedStore.shared.acknowledge(item, saved: saved)
                        try PendingCloudUploads.shared.acknowledge(item, saved: saved, owner: owner)
                    } else {
                        try LocalEncryptedStore.shared.delete(id: item.id)
                        deletedIDs.insert(item.id.uuidString)
                        accounts.removeAll { $0.id == item.id }
                        UserDefaults.standard.set(Array(deletedIDs), forKey: deletedIDsKey)
                        try PendingCloudUploads.shared.remove(id: item.id, owner: owner)
                    }
                } catch CloudKitManagerError.accountMissing(let id) {
                    try Task.checkCancellation()
                    if deletedIDs.contains(id.uuidString) { continue }
                    conflictingAccountID = id
                    conflictRemoteMissing = true
                    throw CloudKitManagerError.accountMissing(id)
                } catch CloudKitManagerError.accountChanged(let id) {
                    try Task.checkCancellation()
                    // Deletion on this device wins over a stale upload response.
                    if deletedIDs.contains(id.uuidString) { continue }
                    conflictingAccountID = id
                    conflictRemoteMissing = false
                    throw CloudKitManagerError.accountChanged(id)
                }
            }
        }
    }

    private func merge(
        local: [EncryptedOTPAccount],
        remote: [EncryptedOTPAccount],
        remoteIsAuthoritative: Bool,
        pendingUploads: [EncryptedOTPAccount],
        pendingDeletes: Set<UUID>
    ) -> [EncryptedOTPAccount] {
        let pendingByID = Dictionary(
            uniqueKeysWithValues: pendingUploads.map { ($0.id, $0) }
        )
        var merged = Dictionary(uniqueKeysWithValues: remote.map { ($0.id, $0) })

        for item in local {
            guard !deletedIDs.contains(item.id.uuidString),
                  !pendingDeletes.contains(item.id)
            else { continue }

            if let pending = pendingByID[item.id] {
                merged[item.id] = pending
            } else if !remoteIsAuthoritative || (merged[item.id] == nil && item.cloudChangeTag == nil) {
                // Local data is the primary vault. Keep records that have not
                // reached CloudKit yet, including while the schema is absent.
                merged[item.id] = item
            }
        }

        return merged.values.filter {
            !deletedIDs.contains($0.id.uuidString) &&
            !pendingDeletes.contains($0.id)
        }
    }

    func resolveConflict(keepLocal: Bool) async {
        guard let id = conflictingAccountID, let owner = cloudOwner,
              isReady, !isResolvingConflict else { return }
        isResolvingConflict = true
        lastError = nil
        defer { isResolvingConflict = false }
        do {
            let session = vaultSessionID
            let expected = try LocalEncryptedStore.shared.fetchAll().first { $0.id == id }
            let remote = try await CloudKitManager.shared.fetch(id: id)
            guard vaultSessionID == session, isReady, masterKey != nil,
                  let current = try LocalEncryptedStore.shared.fetchAll().first(where: { $0.id == id }),
                  current.encryptedBlob == expected?.encryptedBlob else { return }
            if keepLocal {
                var local = current
                local.cloudChangeTag = remote?.cloudChangeTag
                local.canCreateCloudRecord = remote == nil
                local.needsUpload = true
                deletedIDs.remove(id.uuidString)
                try PendingCloudUploads.shared.save(local, owner: owner)
                try LocalEncryptedStore.shared.save(local)
            } else {
                if let remote {
                    _ = try decryptRecord(for: remote)
                    try LocalEncryptedStore.shared.save(remote)
                } else {
                    try LocalEncryptedStore.shared.delete(id: id)
                    deletedIDs.insert(id.uuidString)
                }
                try PendingCloudUploads.shared.remove(id: id, owner: owner)
            }
            UserDefaults.standard.set(Array(deletedIDs), forKey: deletedIDsKey)
            conflictingAccountID = nil
            conflictRemoteMissing = false
            try replaceAccounts(with: LocalEncryptedStore.shared.fetchAll())
            startPendingUploads()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func startPendingUploads() {
        guard isCloudSyncEnabled, isReady, masterKey != nil,
              conflictingAccountID == nil else { return }
        if syncTask != nil {
            syncRequested = true
            return
        }

        let id = UUID()
        syncID = id
        syncTask = Task {
            var failed = false
            do {
                try await synchronizeCloud()
            } catch is CancellationError {
                return
            } catch {
                guard syncID == id else { return }
                failed = true
                syncMessage = String(
                    localized: "Your data is available on this device, but iCloud has not synced yet. Tap to retry."
                )
            }
            guard syncID == id else { return }
            syncID = nil
            syncTask = nil
            if syncRequested {
                syncRequested = false
                if !failed { startPendingUploads() }
            }
        }
    }

    private func publishSavedAccount(
        _ item: EncryptedOTPAccount,
        record: EncryptedOTPRecordPayload
    ) {
        // A successful write is authoritative; query indexing may lag behind it.
        accounts.removeAll { $0.id == item.id }
        accounts.append(DecryptedAccount(
            id: item.id,
            payload: record.otp,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt
        ))
        accounts.sort {
            $0.payload.displayTitle.localizedCaseInsensitiveCompare(
                $1.payload.displayTitle
            ) == .orderedAscending
        }
    }

    func code(for account: DecryptedAccount, date: Date = .now) -> String {
        (try? TOTPManager.code(
            secretBase32: account.payload.secretBase32,
            algorithm: account.payload.algorithm,
            digits: account.payload.digits,
            period: account.payload.period,
            date: date
        )) ?? "------"
    }
}
