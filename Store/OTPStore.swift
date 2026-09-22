import Foundation
import CryptoKit
import CloudKit
@preconcurrency import LocalAuthentication

enum OTPStoreError: LocalizedError {
    case cloudAccountUnavailable
    case masterKeyUnavailable
    case accountNotFound
    case undecryptableRecord

    var errorDescription: String? {
        switch self {
        case .cloudAccountUnavailable:
            return "Sign in to iCloud before using KeyAuth sync."
        case .masterKeyUnavailable:
            return "The KeyAuth master key is unavailable."
        case .accountNotFound:
            return "The account is no longer available. Refresh and try again."
        case .undecryptableRecord:
            return "A CloudKit account could not be decrypted. The app kept the data instead of hiding it."
        }
    }
}

@MainActor
final class OTPStore: ObservableObject {
    @Published private(set) var accounts: [DecryptedAccount] = []
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
    private var currentKeyVersion = 1
    private var recoveryKey: SymmetricKey?

    private var masterKey: SymmetricKey? {
        masterKeys[currentKeyVersion]
    }

    private var cloudOwner: String?
    private var syncTask: Task<Void, Never>?
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
        masterKeys = keys
        currentKeyVersion = currentVersion
        self.recoveryKey = recoveryKey
        recoveryEnabled = recoveryKey != nil
        isReady = false

        do {
            guard masterKey != nil else {
                throw OTPStoreError.masterKeyUnavailable
            }

            let localEncrypted = try await LocalEncryptedStore.shared.fetchAll()
            let uniqueEncrypted = try await removeExactDuplicates(
                from: localEncrypted
            )
            try await installLocalAccounts(uniqueEncrypted)
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
        syncTask?.cancel()
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
            try await synchronizeCloud()
        } else {
            let localEncrypted = try await LocalEncryptedStore.shared.fetchAll()
            try await installLocalAccounts(localEncrypted)
        }
    }

    private func fetchRemoteAccounts() async throws -> CloudFetchResult {
        do {
#if DEBUG
            let remote = try await CloudKitManager.shared.fetchAll()
#else
            let remote = try await CloudKitManager.shared.fetchAll()
#endif
            return CloudFetchResult(accounts: remote, isAuthoritative: true)
        } catch CloudKitManagerError.recordTypeMissing {
            // CloudKit Development creates the record type on the first save.
            // An absent schema is not an authoritative empty vault: preserve
            // local accounts and let the pending queue create the first record.
            return CloudFetchResult(accounts: [], isAuthoritative: false)
        }
    }

    private func saveEncryptedAccount(_ item: EncryptedOTPAccount) async throws {
        try await LocalEncryptedStore.shared.save(item)

        if isCloudSyncEnabled {
            try await queueUpload(item)
            syncMessage = "已保存到本机，正在同步 iCloud…"
        }
    }

    private func updateEncryptedAccount(_ item: EncryptedOTPAccount) async throws {
        try await LocalEncryptedStore.shared.save(item)

        if isCloudSyncEnabled {
            try await queueUpload(item)
            syncMessage = "已保存到本机，正在同步 iCloud…"
        }
    }

    private func deleteEncryptedAccount(id: UUID) async throws {
        try await LocalEncryptedStore.shared.delete(id: id)

        if isCloudSyncEnabled {
            let owner = cloudOwner ?? PendingCloudUploads.unassignedOwner
            try await PendingCloudUploads.shared.remove(id: id, owner: owner)
            try await PendingCloudDeletes.shared.add(id: id, owner: owner)
        }
    }

    private func replaceAccounts(
        with encrypted: [EncryptedOTPAccount]
    ) async throws {
        var decoded: [DecryptedAccount] = []
        decoded.reserveCapacity(encrypted.count)

        for item in encrypted where !deletedIDs.contains(item.id.uuidString) {
            let payload = try decryptPayload(for: item)
            decoded.append(DecryptedAccount(
                id: item.id,
                payload: payload,
                createdAt: item.createdAt,
                updatedAt: item.updatedAt
            ))
        }

        accounts = decoded.sorted {
            $0.payload.displayTitle.localizedCaseInsensitiveCompare(
                $1.payload.displayTitle
            ) == .orderedAscending
        }
    }

    private func decryptPayload(
        for item: EncryptedOTPAccount
    ) throws -> OTPAccountPayload {
        guard let key = masterKeys[item.keyVersion] else {
            throw OTPStoreError.masterKeyUnavailable
        }

        do {
            if item.version >= 3 {
                return try CryptoManager.decrypt(
                    OTPAccountPayload.self,
                    from: item.encryptedBlob,
                    using: key,
                    associatedData: CryptoManager.associatedData(
                        for: item.id,
                        version: item.version,
                        keyVersion: item.keyVersion
                    )
                )

            }

            return try CryptoManager.decrypt(
                OTPAccountPayload.self,
                from: item.encryptedBlob,
                using: key,
                associatedData: CryptoManager.legacyAssociatedData(
                    for: item.id,
                    version: item.version
                )
            )
        } catch {
            if item.version == 1 {
                return try CryptoManager.decryptLegacy(
                    OTPAccountPayload.self,
                    from: item.encryptedBlob,
                    using: key
                )
            }

            throw OTPStoreError.undecryptableRecord
        }
    }

    private func removeExactDuplicates(
        from encrypted: [EncryptedOTPAccount]
    ) async throws -> [EncryptedOTPAccount] {
        var seenAccounts = Set<OTPAccountIdentity>()
        var unique: [EncryptedOTPAccount] = []
        unique.reserveCapacity(encrypted.count)

        let ordered = encrypted.sorted {
            if $0.createdAt != $1.createdAt {
                return $0.createdAt < $1.createdAt
            }
            return $0.id.uuidString < $1.id.uuidString
        }

        for item in ordered {
            let payload = try decryptPayload(for: item)
            guard seenAccounts.insert(payload.identity).inserted else {
                // Keep the oldest copy and remove later records for the same
                // OTP credential, even if their display names differ.
                try await deleteEncryptedAccount(id: item.id)
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
            let version = EncryptedOTPAccount.currentVersion
            let encryptedBlob = try CryptoManager.encrypt(
                payload,
                using: masterKey,
                associatedData: CryptoManager.associatedData(
                    for: id,
                    version: version,
                    keyVersion: keyVersion
                )
            )

            let item = EncryptedOTPAccount(
                id: id,
                encryptedBlob: encryptedBlob,
                version: version,
                keyVersion: keyVersion
            )

            try await saveEncryptedAccount(item)
            publishSavedAccount(item, payload: payload)
            startPendingUploads()
            return true
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    @discardableResult
    func updateDisplayName(for id: UUID, to rawName: String) async -> Bool {
        lastError = nil

        do {
            guard let masterKey,
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
                displayName: displayName.isEmpty ? nil : displayName
            )
            let keyVersion = currentKeyVersion
            let version = EncryptedOTPAccount.currentVersion
            let encryptedBlob = try CryptoManager.encrypt(
                payload,
                using: masterKey,
                associatedData: CryptoManager.associatedData(
                    for: id,
                    version: version,
                    keyVersion: keyVersion
                )
            )
            let item = EncryptedOTPAccount(
                id: id,
                encryptedBlob: encryptedBlob,
                version: version,
                keyVersion: keyVersion,
                createdAt: account.createdAt,
                updatedAt: .now
            )

            try await updateEncryptedAccount(item)
            publishSavedAccount(item, payload: payload)
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
            // Remove locally first. The cloud delete is queued and retried in
            // the background, so a network outage cannot block the vault.
            for id in ids {
                try await deleteEncryptedAccount(id: id)
                deletedIDs.insert(id.uuidString)
                UserDefaults.standard.set(Array(deletedIDs), forKey: deletedIDsKey)
                accounts.removeAll { $0.id == id }
            }
            startPendingUploads()
            return true
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    @discardableResult
    func enableRecovery() async -> String? {
        lastError = nil

        guard !recoveryEnabled else {
            lastError = "恢复功能已经启用，当前版本不支持重新生成恢复密钥。"
            return nil
        }

        do {
            guard isReady, masterKey != nil else {
                throw OTPStoreError.masterKeyUnavailable
            }

            let result = try await RecoveryManager.shared.enableRecovery(
                keys: masterKeys,
                currentVersion: currentKeyVersion
            )

            recoveryKey = result.key
            recoveryEnabled = true
            return result.code
        } catch {
            lastError = error.localizedDescription
            return nil
        }
    }

    @discardableResult
    func rotateMasterKey(context: LAContext) async -> Bool {
        lastError = nil

        do {
            guard isReady, masterKey != nil else {
                throw OTPStoreError.masterKeyUnavailable
            }

            // Fetch the latest global keyring before allocating a new version.
            // This prevents two devices from independently creating the same
            // version number from stale state.
            if isCloudSyncEnabled {
                try await synchronizeCloud()
            }

            try await refreshRecoveryKeyringIfNeeded()

            let (newVersion, newKey) = try await KeychainManager.shared
                .createNextMasterKey(context: context)

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

            let encrypted = try await LocalEncryptedStore.shared.fetchAll()
            var rotated: [EncryptedOTPAccount] = []
            rotated.reserveCapacity(encrypted.count)

            for item in encrypted {
                let payload = try decryptPayload(for: item)
                let recordVersion = EncryptedOTPAccount.currentVersion
                let blob = try CryptoManager.encrypt(
                    payload,
                    using: newKey,
                    associatedData: CryptoManager.associatedData(
                        for: item.id,
                        version: recordVersion,
                        keyVersion: newVersion
                    )
                )

                rotated.append(EncryptedOTPAccount(
                    id: item.id,
                    encryptedBlob: blob,
                    version: recordVersion,
                    keyVersion: newVersion,
                    createdAt: item.createdAt,
                    updatedAt: .now
                ))
            }

            // Replace the local vault before making the new version current.
            try await LocalEncryptedStore.shared.replaceAll(rotated)

            // Keep both keys available while queued uploads are sent.
            masterKeys[newVersion] = newKey

            for item in rotated {
                try await queueUpload(item)
            }

            currentKeyVersion = newVersion
            await KeychainManager.shared.commitRotation(version: newVersion)

            try await replaceAccounts(with: rotated)
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
    ) async throws {
        let visible = encrypted.filter {
            !deletedIDs.contains($0.id.uuidString)
        }
        try await LocalEncryptedStore.shared.replaceAll(visible)
        try await replaceAccounts(with: visible)
    }

    private func queueUpload(_ item: EncryptedOTPAccount) async throws {
        let owner = cloudOwner ?? PendingCloudUploads.unassignedOwner
        try await PendingCloudDeletes.shared.remove(id: item.id, owner: owner)
        try await PendingCloudUploads.shared.save(item, owner: owner)
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

        cloudOwner = owner
        UserDefaults.standard.set(owner, forKey: cloudOwnerKey)

        try await PendingCloudUploads.shared.move(
            from: PendingCloudUploads.unassignedOwner,
            to: owner
        )
        try await PendingCloudDeletes.shared.move(
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

            if snapshot.currentVersion > currentKeyVersion {
                try await KeychainManager.shared.installRecoveredKeyring(
                    snapshot.keyData,
                    currentVersion: snapshot.currentVersion
                )

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
            // A local Recovery Key without an envelope can safely recreate it
            // from the current in-memory key ring.
            try await RecoveryManager.shared.updateEnvelope(
                recoveryKey: recoveryKey,
                keys: masterKeys,
                currentVersion: currentKeyVersion
            )
        }
    }

    private func upgradePendingUploads(owner: String) async throws {
        guard let currentKey = masterKey else {
            throw OTPStoreError.masterKeyUnavailable
        }

        let pending = try await PendingCloudUploads.shared.fetch(owner: owner)

        for item in pending where item.keyVersion != currentKeyVersion {
            let payload = try decryptPayload(for: item)
            let recordVersion = EncryptedOTPAccount.currentVersion
            let blob = try CryptoManager.encrypt(
                payload,
                using: currentKey,
                associatedData: CryptoManager.associatedData(
                    for: item.id,
                    version: recordVersion,
                    keyVersion: currentKeyVersion
                )
            )

            let migrated = EncryptedOTPAccount(
                id: item.id,
                encryptedBlob: blob,
                version: recordVersion,
                keyVersion: currentKeyVersion,
                createdAt: item.createdAt,
                // This is a re-encryption, not a user edit.
                updatedAt: item.updatedAt
            )

            try await PendingCloudUploads.shared.save(
                migrated,
                owner: owner
            )
            try await LocalEncryptedStore.shared.save(migrated)
        }
    }

    private func synchronizeCloud() async throws {
        try await refreshRecoveryKeyringIfNeeded()

        let initialCloud = try await connectToCloud()
        guard let owner = cloudOwner else {
            throw OTPStoreError.cloudAccountUnavailable
        }

        syncMessage = "正在同步 iCloud…"
        try await upgradePendingUploads(owner: owner)
        try await flushPendingChanges(owner: owner)

        let latestCloud = try await fetchRemoteAccounts()
        let local = try await LocalEncryptedStore.shared.fetchAll()
        let remainingUploads = try await PendingCloudUploads.shared.fetch(owner: owner)
        let remainingDeletes = Set(
            try await PendingCloudDeletes.shared.fetch(owner: owner)
        )
        let merged = merge(
            local: local,
            remote: latestCloud.accounts,
            remoteIsAuthoritative: initialCloud.isAuthoritative && latestCloud.isAuthoritative,
            pendingUploads: remainingUploads,
            pendingDeletes: remainingDeletes
        )
        let uniqueMerged = try await removeExactDuplicates(from: merged)
        try await installLocalAccounts(uniqueMerged)

        // Duplicate cleanup and changes made while the first sync was in
        // flight may have added more queued work. Flush once more, then use
        // the resulting cloud view as the final local snapshot.
        try await flushPendingChanges(owner: owner)
        let finalCloud = try await fetchRemoteAccounts()
        let finalLocal = try await LocalEncryptedStore.shared.fetchAll()
        let finalUploads = try await PendingCloudUploads.shared.fetch(owner: owner)
        let finalDeletes = Set(
            try await PendingCloudDeletes.shared.fetch(owner: owner)
        )
        let finalMerged = merge(
            local: finalLocal,
            remote: finalCloud.accounts,
            remoteIsAuthoritative: finalCloud.isAuthoritative,
            pendingUploads: finalUploads,
            pendingDeletes: finalDeletes
        )
        try await installLocalAccounts(finalMerged)

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

        let versions = await KeychainManager.shared.knownKeyVersions()
        let obsoleteVersions = versions.filter {
            $0 < currentKeyVersion
        }

        for version in obsoleteVersions {
            try await KeychainManager.shared
                .deleteMasterKey(version: version)
            masterKeys.removeValue(forKey: version)
        }
    }

    private func flushPendingChanges(owner: String) async throws {
        while true {
            let pendingUploads = try await PendingCloudUploads.shared.fetch(owner: owner)
            let pendingDeletes = try await PendingCloudDeletes.shared.fetch(owner: owner)
            guard !pendingUploads.isEmpty || !pendingDeletes.isEmpty else { break }

            let deleted = Set(pendingDeletes)
            for id in pendingDeletes {
                try await CloudKitManager.shared.delete(id: id)
                try await PendingCloudDeletes.shared.remove(id: id, owner: owner)
                try await PendingCloudUploads.shared.remove(id: id, owner: owner)
            }

            for item in pendingUploads where !deleted.contains(item.id) {
                try await CloudKitManager.shared.upsert(item)
                try await PendingCloudUploads.shared.remove(id: item.id, owner: owner)
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
            } else if !remoteIsAuthoritative || merged[item.id] == nil {
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

    func startPendingUploads() {
        guard isCloudSyncEnabled, isReady, masterKey != nil else { return }
        if syncTask != nil {
            syncRequested = true
            return
        }

        syncTask = Task {
            var failed = false
            do {
                try await synchronizeCloud()
            } catch {
                failed = true
                // The local vault stays ready and usable. This status is
                // intentionally non-blocking and can be retried by the user.
                syncMessage = "本机数据可用，iCloud 尚未同步。点击重试。"
            }
            syncTask = nil
            if syncRequested {
                syncRequested = false
                if !failed {
                    startPendingUploads()
                }
            }
        }
    }

    private func publishSavedAccount(
        _ item: EncryptedOTPAccount,
        payload: OTPAccountPayload
    ) {
        // A successful write is authoritative; query indexing may lag behind it.
        accounts.removeAll { $0.id == item.id }
        accounts.append(DecryptedAccount(
            id: item.id,
            payload: payload,
            createdAt: item.createdAt,
            updatedAt: item.updatedAt
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
