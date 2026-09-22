import CryptoKit
import Foundation
@preconcurrency import LocalAuthentication
import UIKit

struct UnlockedKeyring {
    let currentVersion: Int
    let keys: [Int: SymmetricKey]
    let recoveryKey: SymmetricKey?
}

@MainActor
final class AppLockManager: ObservableObject {
    @Published private(set) var isLocked = true
    @Published private(set) var isAuthenticating = false
    @Published private(set) var needsRecovery = false
    @Published private(set) var lastError: String?

    private var context: LAContext?
    private var attemptID: UUID?
    private var pendingKeyring: UnlockedKeyring?

    /// The system authentication is performed by the protected Keychain
    /// query itself. The UI does not unlock until that query returns the key.
    func authenticate() {
        guard isLocked, !isAuthenticating,
              UIApplication.shared.applicationState == .active else { return }

        let context = LAContext()
        self.context = context
        let id = UUID()
        attemptID = id
        isAuthenticating = true
        lastError = nil

        Task { @MainActor [weak self] in
            do {
                var currentVersion = await KeychainManager.shared
                    .currentMasterKeyVersion()
                var versions = await KeychainManager.shared.knownKeyVersions()

                if let pendingVersion = await KeychainManager.shared
                    .pendingRotationVersion(),
                   !versions.contains(pendingVersion) {
                    versions.append(pendingVersion)
                }

                if !versions.contains(currentVersion) {
                    versions.append(currentVersion)
                }

                var keys: [Int: SymmetricKey] = [:]
                for version in versions.sorted() {
                    if let key = try await KeychainManager.shared.readMasterKey(
                        version: version,
                        context: context
                    ) {
                        keys[version] = key
                    }
                }

                // First launch: if a recovery envelope already exists, do not
                // silently create a different vault on this device.
                if keys.isEmpty, currentVersion == 1 {
                    let hasRecovery = (try? await RecoveryManager.shared
                        .cloudRecoveryExists()) ?? false

                    if hasRecovery {
                        guard let self,
                              self.attemptID == id
                        else {
                            return
                        }

                        self.needsRecovery = true
                        self.attemptID = nil
                        self.context = nil
                        self.isAuthenticating = false
                        return
                    }

                    try await KeychainManager.shared.createMasterKey()
                    if let key = try await KeychainManager.shared.readMasterKey(
                        version: 1,
                        context: context
                    ) {
                        keys[1] = key
                    }
                }

                let recoveryKey = try await KeychainManager.shared
                    .readRecoveryKey(context: context)

                if let recoveryKey,
                   let snapshot = try? await RecoveryManager.shared
                    .fetchKeyring(recoveryKey: recoveryKey),
                   keys[currentVersion] == nil ||
                    snapshot.currentVersion > currentVersion {
                    try await KeychainManager.shared.installRecoveredKeyring(
                        snapshot.keyData,
                        currentVersion: snapshot.currentVersion
                    )

                    for (version, data) in snapshot.keyData {
                        keys[version] = SymmetricKey(data: data)
                    }

                    currentVersion = snapshot.currentVersion
                }

                guard keys[currentVersion] != nil else {
                    throw KeychainError.masterKeyUnavailable
                }

                let keyring = UnlockedKeyring(
                    currentVersion: currentVersion,
                    keys: keys,
                    recoveryKey: recoveryKey
                )

                guard let self,
                      self.attemptID == id
                else { return }

                self.pendingKeyring = keyring
                self.needsRecovery = false
                self.attemptID = nil
                self.context = nil
                self.isAuthenticating = false
                self.isLocked = false
            } catch {
                guard let self, self.attemptID == id else { return }
                self.attemptID = nil
                self.context = nil
                self.isAuthenticating = false
                let nsError = error as NSError
                self.lastError = "解锁未完成，请重试。\n\(nsError.domain) (\(nsError.code))"
            }
        }
    }

    func recover(recoveryCode: String) {
        guard isLocked, !isAuthenticating else {
            return
        }

        isAuthenticating = true
        lastError = nil

        Task { @MainActor [weak self] in
            do {
                try await RecoveryManager.shared.restore(
                    recoveryCode: recoveryCode
                )

                guard let self else {
                    return
                }

                self.isAuthenticating = false
                self.needsRecovery = false
                self.authenticate()
            } catch {
                guard let self else {
                    return
                }

                self.isAuthenticating = false
                self.lastError = error.localizedDescription
            }
        }
    }

    func consumeKeyring() -> UnlockedKeyring? {
        defer { pendingKeyring = nil }
        return pendingKeyring
    }

    func lock() {
        attemptID = nil
        context?.invalidate()
        context = nil
        pendingKeyring = nil
        isLocked = true
        isAuthenticating = false
    }

    func clearError() {
        lastError = nil
    }
}
