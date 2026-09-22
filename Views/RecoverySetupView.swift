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
                    Text("Please save your recovery key")
                        .font(.title2.bold())

                    Text(
                        "If you lose all devices, this key is the only way to recover your codes."
                    )
                        .foregroundStyle(.secondary)

                    Text(recoveryCode)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .padding()
                        .background(.secondary.opacity(0.1))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                } else if store.recoveryEnabled {
                    ContentUnavailableView(
                        "Recovery enabled",
                        systemImage: "checkmark.shield.fill",
                        description: Text(
                            "A recovery key is configured. Keep the recovery key you saved previously safe."
                        )
                    )
                } else {
                    Text(
                        "After generating a recovery key, you can recover on a new iPhone or iPad."
                    )
                        .foregroundStyle(.secondary)

                    Button {
                        Task {
                            isWorking = true
                            recoveryCode = await store.enableRecovery()
                            isWorking = false
                        }
                    } label: {
                        Label(
                            "Enable cross-device recovery",
                            systemImage: "key.horizontal.fill"
                        )
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isWorking)
                }

                Spacer()
            }
            .padding()
            .navigationTitle("Recovery")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
    }
}
