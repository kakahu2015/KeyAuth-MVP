import SwiftUI
import VisionKit

struct AddAccountView: View {
    @EnvironmentObject private var store: OTPStore
    @Environment(\.dismiss) private var dismiss
    @Environment(\.isSceneCaptured) private var isSceneCaptured
    @Environment(\.scenePhase) private var scenePhase

    @State private var rawURL = ""
    @State private var showScanner = false
    @State private var scannerError: String?
    @State private var isSaving = false

    var body: some View {
        NavigationStack {
            Form {
                Section("otpauth URL") {
                    TextField(
                        "otpauth://totp/...",
                        text: $rawURL,
                        axis: .vertical
                    )
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                }

                if DataScannerViewController.isSupported,
                   DataScannerViewController.isAvailable {
                    Section {
                        Button {
                            showScanner = true
                        } label: {
                            Label("Scan QR Code", systemImage: "qrcode.viewfinder")
                        }
                    }
                }

                Section {
                    Text(
                        "Paste an otpauth:// URL or scan a TOTP QR code."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Add Account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        guard !isSaving else { return }
                        isSaving = true
                        Task {
                            if await store.add(otpauthURL: rawURL) {
                                dismiss()
                            }
                            isSaving = false
                        }
                    }
                    .disabled(isSaving || rawURL.trimmingCharacters(
                        in: .whitespacesAndNewlines
                    ).isEmpty)
                }
            }
            .sheet(isPresented: $showScanner) {
                QRScannerView(
                    onCode: { code in
                        rawURL = code
                        showScanner = false
                    },
                    onError: { message in
                        scannerError = message
                        showScanner = false
                    }
                )
                .ignoresSafeArea()
            }
            .alert(
                "QR Scanner",
                isPresented: Binding(
                    get: { scannerError != nil },
                    set: { if !$0 { scannerError = nil } }
                )
            ) {
                Button("OK") {
                    scannerError = nil
                }
            } message: {
                Text(scannerError ?? "")
            }
        }
        .overlay {
            if scenePhase != .active || isSceneCaptured {
                SensitiveContentShield(isCaptured: isSceneCaptured)
            }
        }
        .onChange(of: isSceneCaptured) { _, captured in
            if captured {
                rawURL = ""
                showScanner = false
            }
        }
    }
}
