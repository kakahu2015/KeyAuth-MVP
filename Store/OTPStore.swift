import Foundation
import CryptoKit
import CloudKit

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

    struct DecryptedAccount: Identifiable {
        let id: UUID
        let payload: OTPAccountPayload
        let createdAt: Date
        let updatedAt: Date
    }

    private var masterKey: SymmetricKey?
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
        masterKey = nil
        accounts = []
        cloudOwner = UserDefaults.standard.string(forKey: cloudOwnerKey)
        isCloudSyncEnabled = await CloudKitManager.shared.isConfigured
        isLoading = false
    }

    @discardableResult
    func unlock(with key: SymmetricKey) async -> Bool {
        await syncTask?.value
        isLoading = true
        lastError = nil
        syncMessage = nil
        masterKey = key
        isReady = false

        do {
            let localEncrypted = try await LocalEncryptedStore.shared.fetchAll()
            let uniqueEncrypted = try await removeExactDuplicates(
                from: localEncrypted,
                using: key
            )
            try await installLocalAccounts(uniqueEncrypted, using: key)
            isReady = true
            isLoading = false
            startPendingUploads()
            return true
        } catch {
            masterKey = nil
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
        masterKey = nil
        accounts = []
        isReady = false
        isLoading = false
        syncMessage = nil
    }

    func refresh() async throws {
        guard isReady, let masterKey else {
            throw OTPStoreError.masterKeyUnavailable
        }

        await syncTask?.value

        if isCloudSyncEnabled {
            try await synchronizeCloud(using: masterKey)
        } else {
            let localEncrypted = try await LocalEncryptedStore.shared.fetchAll()
            try await installLocalAccounts(localEncrypted, using: masterKey)
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
        with encrypted: [EncryptedOTPAccount],
        using masterKey: SymmetricKey?
    ) async throws {
        guard let masterKey else {
            throw OTPStoreError.masterKeyUnavailable
        }

        var decoded: [DecryptedAccount] = []
        decoded.reserveCapacity(encrypted.count)

        for item in encrypted where !deletedIDs.contains(item.id.uuidString) {
            let payload = try decryptPayload(for: item, using: masterKey)
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
        for item: EncryptedOTPAccount,
        using masterKey: SymmetricKey
    ) throws -> OTPAccountPayload {
        do {
            return try CryptoManager.decrypt(
                OTPAccountPayload.self,
                from: item.encryptedBlob,
                using: masterKey,
                associatedData: CryptoManager.associatedData(
                    for: item.id,
                    version: item.version
                )
            )
        } catch {
            guard item.version == 1 else {
                throw OTPStoreError.undecryptableRecord
            }

            do {
                return try CryptoManager.decryptLegacy(
                    OTPAccountPayload.self,
                    from: item.encryptedBlob,
                    using: masterKey
                )
            } catch {
                throw OTPStoreError.undecryptableRecord
            }
        }
    }

    private func removeExactDuplicates(
        from encrypted: [EncryptedOTPAccount],
        using masterKey: SymmetricKey
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
            let payload = try decryptPayload(for: item, using: masterKey)
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
            let version = EncryptedOTPAccount.currentVersion
            let encryptedBlob = try CryptoManager.encrypt(
                payload,
                using: masterKey,
                associatedData: CryptoManager.associatedData(
                    for: id,
                    version: version
                )
            )

            let item = EncryptedOTPAccount(
                id: id,
                encryptedBlob: encryptedBlob,
                version: version
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
            let version = EncryptedOTPAccount.currentVersion
            let encryptedBlob = try CryptoManager.encrypt(
                payload,
                using: masterKey,
                associatedData: CryptoManager.associatedData(
                    for: id,
                    version: version
                )
            )
            let item = EncryptedOTPAccount(
                id: id,
                encryptedBlob: encryptedBlob,
                version: version,
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

    func clearError() {
        lastError = nil
    }

    private func installLocalAccounts(
        _ encrypted: [EncryptedOTPAccount],
        using masterKey: SymmetricKey
    ) async throws {
        let visible = encrypted.filter {
            !deletedIDs.contains($0.id.uuidString)
        }
        try await LocalEncryptedStore.shared.replaceAll(visible)
        try await replaceAccounts(with: visible, using: masterKey)
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

    private func synchronizeCloud(using masterKey: SymmetricKey) async throws {
        let initialCloud = try await connectToCloud()
        guard let owner = cloudOwner else {
            throw OTPStoreError.cloudAccountUnavailable
        }

        syncMessage = "正在同步 iCloud…"
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
        let uniqueMerged = try await removeExactDuplicates(
            from: merged,
            using: masterKey
        )
        try await installLocalAccounts(uniqueMerged, using: masterKey)

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
        try await installLocalAccounts(finalMerged, using: masterKey)
        syncMessage = nil
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
        guard isCloudSyncEnabled, isReady, let masterKey else { return }
        if syncTask != nil {
            syncRequested = true
            return
        }

        syncTask = Task {
            var failed = false
            do {
                try await synchronizeCloud(using: masterKey)
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
