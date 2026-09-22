import SwiftUI

struct RecoverySetupView: View {
    @EnvironmentObject private var store: OTPStore
    @Environment(\.dismiss) private var dismiss

    @State private var recoveryCode: String?
    @State private var isWorking = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if let recoveryCode {
                    Text("请保存恢复密钥")
                        .font(.title2.bold())

                    Text("丢失所有设备后，只能使用此密钥恢复验证码。")
                        .foregroundStyle(.secondary)

                    Text(recoveryCode)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .padding()
                        .background(.secondary.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                } else if store.recoveryEnabled {
                    ContentUnavailableView(
                        "恢复已启用",
                        systemImage: "checkmark.shield.fill",
                        description: Text(
                            "恢复密钥已经配置。请妥善保管之前保存的恢复密钥。"
                        )
                    )
                } else {
                    Text("生成恢复密钥后，可在新的 iPhone / iPad 上恢复。")
                        .foregroundStyle(.secondary)

                    Button {
                        Task {
                            isWorking = true
                            recoveryCode = await store.enableRecovery()
                            isWorking = false
                        }
                    } label: {
                        Label(
                            "启用跨设备恢复",
                            systemImage: "key.horizontal.fill"
                        )
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isWorking)
                }

                Spacer()
            }
            .padding()
            .navigationTitle("恢复")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("完成") {
                        dismiss()
                    }
                }
            }
        }
    }
}
