import Foundation
import LocalAuthentication
import Security
import UIKit

@MainActor
final class AppLockManager: ObservableObject {
    @Published private(set) var isLocked = true
    @Published private(set) var isAuthenticating = false
    @Published private(set) var lastError: String?

    private var context: LAContext?
    private var attemptID: UUID?

    func authenticate(usePasscode: Bool = false) {
        guard isLocked, !isAuthenticating,
              UIApplication.shared.applicationState == .active else { return }

        let context = LAContext()
        self.context = context
        let id = UUID()
        attemptID = id
        isAuthenticating = true
        lastError = nil

        let reply: @Sendable (Bool, Error?) -> Void = { [weak self] success, error in
            Task { @MainActor in
                guard let self, self.attemptID == id else { return }
                self.attemptID = nil
                self.context = nil
                self.isAuthenticating = false
                if success {
                    self.isLocked = false
                } else if let error {
                    let nsError = error as NSError
                    self.lastError = "解锁未完成，请重试或选择使用设备密码。\n\(nsError.domain) (\(nsError.code))"
                }
            }
        }

        if usePasscode {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                .devicePasscode, &error
            ) else {
                attemptID = nil
                self.context = nil
                isAuthenticating = false
                lastError = "无法创建设备密码认证，请确认已设置锁屏密码。"
                return
            }
            context.evaluateAccessControl(
                access, operation: .useItem,
                localizedReason: "输入设备锁屏密码以解锁 KeyAuth。",
                reply: reply
            )
        } else {
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "解锁 KeyAuth 以查看验证码。",
                reply: reply
            )
        }
    }

    func lock() {
        attemptID = nil
        context?.invalidate()
        context = nil
        isLocked = true
        isAuthenticating = false
    }

    func clearError() {
        lastError = nil
    }
}
