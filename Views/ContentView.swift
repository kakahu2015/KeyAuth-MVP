import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var store: OTPStore
    @EnvironmentObject private var appLock: AppLockManager
    @Environment(\.scenePhase) private var scenePhase

    @State private var showAdd = false
    @State private var showRecovery = false
    @State private var accountToEdit: OTPStore.DecryptedAccount?
    @State private var accountToDelete: OTPStore.DecryptedAccount?

    var body: some View {
        Group {
            if appLock.isLocked {
                LockView()
            } else {
                authenticatedContent
            }
        }
        .onChange(of: scenePhase) { _, newPhase in
            if newPhase == .background {
                appLock.lock()
                store.lock()
            }
        }
        .onChange(of: appLock.isLocked) { _, isLocked in
            guard !isLocked, let keyring = appLock.consumeKeyring() else {
                return
            }
            Task {
                let unlocked = await store.unlock(
                    keys: keyring.keys,
                    currentVersion: keyring.currentVersion,
                    recoveryKey: keyring.recoveryKey
                )
                if !unlocked {
                    appLock.lock()
                    store.lock()
                }
            }
        }
        .alert(
            "Error",
            isPresented: Binding(
                get: { store.lastError != nil },
                set: { if !$0 { store.clearError() } }
            )
        ) {
            Button("OK") {
                store.clearError()
            }
        } message: {
            Text(store.lastError ?? "")
        }
    }

    @ViewBuilder
    private var authenticatedContent: some View {
        NavigationStack {
            Group {
                if store.isLoading {
                    ProgressView("Loading…")
                } else if store.accounts.isEmpty {
                    VStack(spacing: 12) {
                        ContentUnavailableView(
                            "No codes",
                            systemImage: "key.fill",
                            description: Text("Import an otpauth:// URL or scan a QR code to begin.")
                        )
                        if !store.isReady {
                            Button {
                                Task {
                                    await store.bootstrap()
                                }
                            } label: {
                                Label("重试加载", systemImage: "arrow.clockwise")
                            }
                            .buttonStyle(.bordered)
                            .disabled(store.isLoading)
                        }
                        if let message = store.syncMessage {
                            Button(message) { store.startPendingUploads() }
                                .font(.footnote)
                        }
                        StorageModeLabel(isCloudSyncEnabled: store.isCloudSyncEnabled)
                    }
                } else {
                    List {
                        if let message = store.syncMessage {
                            Button(message) { store.startPendingUploads() }
                                .font(.footnote)
                        }
                        StorageModeLabel(isCloudSyncEnabled: store.isCloudSyncEnabled)
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            ForEach(store.accounts) { account in
                                OTPRow(
                                    account: account,
                                    code: store.code(
                                        for: account,
                                        date: context.date
                                    ),
                                    remaining: TOTPManager.secondsRemaining(
                                        period: account.payload.period,
                                        date: context.date
                                    )
                                )
                                .swipeActions(
                                    edge: .trailing,
                                    allowsFullSwipe: false
                                ) {
                                    Button {
                                        accountToEdit = account
                                    } label: {
                                        Label("Edit", systemImage: "pencil")
                                    }
                                    .tint(.blue)

                                    Button(role: .destructive) {
                                        accountToDelete = account
                                    } label: {
                                        Label("Delete", systemImage: "trash")
                                    }
                                }
                            }
                        }
                    }
                    .refreshable {
                        do {
                            try await store.refresh()
                        } catch {
                            store.lastError = error.localizedDescription
                        }
                    }
                }
            }
            .navigationTitle("KeyAuth")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        showRecovery = true
                    } label: {
                        Image(systemName: "key.horizontal.fill")
                    }
                    .disabled(!store.isReady || store.isLoading)
                }

                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showAdd = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .disabled(!store.isReady || store.isLoading)
                }
            }
            .sheet(isPresented: $showAdd) {
                AddAccountView()
            }
            .sheet(isPresented: $showRecovery) {
                RecoverySetupView()
            }
            .sheet(item: $accountToEdit) { account in
                EditAccountView(account: account)
            }
            .confirmationDialog(
                "Delete this account?",
                isPresented: Binding(
                    get: { accountToDelete != nil },
                    set: { if !$0 { accountToDelete = nil } }
                ),
                titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) {
                    guard let id = accountToDelete?.id else { return }
                    accountToDelete = nil
                    Task {
                        await store.delete(id: id)
                    }
                }
                Button("Cancel", role: .cancel) {
                    accountToDelete = nil
                }
            } message: {
                Text("删除会立即移除本机账号，并在 iCloud 恢复连接后删除云端记录。同步完成后无法通过恢复找回。")
            }
        }
    }
}

private struct StorageModeLabel: View {
    let isCloudSyncEnabled: Bool

    var body: some View {
        Label(
            isCloudSyncEnabled ? "本机加密库 · iCloud 后台同步" : "本机加密库",
            systemImage: isCloudSyncEnabled ? "icloud.fill" : "externaldrive.fill"
        )
        .font(.footnote)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
        .padding(.horizontal)
    }
}

private struct LockView: View {
    @EnvironmentObject private var appLock: AppLockManager
    @State private var recoveryCode = ""

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 48))
                .foregroundStyle(.tint)

            Text("KeyAuth is locked")
                .font(.title2.weight(.semibold))

            Text("Unlock the protected master key with Face ID or your device passcode.")
                .foregroundStyle(.secondary)

            if appLock.needsRecovery {
                SecureField("KA1-恢复密钥", text: $recoveryCode)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)

                Button {
                    appLock.recover(recoveryCode: recoveryCode)
                } label: {
                    Label(
                        "从 iCloud 恢复",
                        systemImage: "icloud.and.arrow.down"
                    )
                }
                .buttonStyle(.borderedProminent)
                .disabled(
                    recoveryCode.isEmpty || appLock.isAuthenticating
                )
            } else {
                Button {
                    appLock.authenticate()
                } label: {
                    Label(
                        appLock.isAuthenticating ? "Unlocking…" : "Unlock",
                        systemImage: "faceid"
                    )
                }
                .buttonStyle(.borderedProminent)
                .disabled(appLock.isAuthenticating)
            }

            if let error = appLock.lastError {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
        }
        .padding()
    }
}

private struct OTPRow: View {
    let account: OTPStore.DecryptedAccount
    let code: String
    let remaining: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                VStack(alignment: .leading) {
                    Text(account.payload.displayTitle)
                        .font(.headline)

                    if let subtitle = account.payload.displaySubtitle {
                        Text(subtitle)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Spacer()

                Text(code)
                    .font(.system(.title2, design: .monospaced))
                    .fontWeight(.semibold)
            }

            ProgressView(
                value: Double(remaining),
                total: Double(account.payload.period)
            )
        }
        .privacySensitive()
        .padding(.vertical, 4)
    }
}
