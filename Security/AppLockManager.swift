import CryptoKit
import Foundation
@preconcurrency import LocalAuthentication
import UIKit

@MainActor
final class AppLockManager: ObservableObject {
    @Published private(set) var isLocked = true
    @Published private(set) var isAuthenticating = false
    @Published private(set) var lastError: String?

    private var context: LAContext?
    private var attemptID: UUID?
    private var pendingMasterKey: SymmetricKey?

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
                var masterKey = try await KeychainManager.shared.readMasterKey(
                    context: context
                )

                if masterKey == nil {
                    // First launch: create the device-bound item, then read it
                    // through the same authenticated Keychain path. The key
                    // is never handed to the app before that read succeeds.
                    try await KeychainManager.shared.createMasterKey()
                    masterKey = try await KeychainManager.shared.readMasterKey(
                        context: context
                    )
                }

                guard let self,
                      self.attemptID == id,
                      let masterKey
                else { return }

                self.pendingMasterKey = masterKey
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

    func consumeMasterKey() -> SymmetricKey? {
        defer { pendingMasterKey = nil }
        return pendingMasterKey
    }

    func lock() {
        attemptID = nil
        context?.invalidate()
        context = nil
        pendingMasterKey = nil
        isLocked = true
        isAuthenticating = false
    }

    func clearError() {
        lastError = nil
    }
}
