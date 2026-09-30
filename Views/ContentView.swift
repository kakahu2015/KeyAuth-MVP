import SwiftUI
import UIKit

struct ContentView: View {
    @EnvironmentObject private var store: OTPStore
    @EnvironmentObject private var appLock: AppLockManager
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.isSceneCaptured) private var isSceneCaptured

    @State private var searchText = ""
    @State private var selectedGroup: String?
    @State private var showTransfer = false
    @State private var showAdd = false
    @State private var showRecovery = false
    @State private var accountToEdit: OTPStore.DecryptedAccount?
    @State private var accountToDelete: OTPStore.DecryptedAccount?

    private var filteredAccounts: [OTPStore.DecryptedAccount] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        return store.accounts.filter { account in
            let payload = account.payload
            let matchesGroup = selectedGroup == nil || (payload.groupName ?? "") == selectedGroup
            let matchesSearch = query.isEmpty ||
                payload.displayTitle.localizedCaseInsensitiveContains(query) ||
                payload.issuer.localizedCaseInsensitiveContains(query) ||
                payload.accountName.localizedCaseInsensitiveContains(query) ||
                (payload.groupName ?? "").localizedCaseInsensitiveContains(query)
            return matchesGroup && matchesSearch
        }
    }

    private var groups: [String] {
        Array(Set(store.accounts.compactMap { $0.payload.groupName }.filter { !$0.isEmpty }))
            .sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
    }

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
        .onChange(of: isSceneCaptured) { _, captured in
            if captured {
                appLock.lock()
                store.lock()
            }
        }
        .overlay {
            if scenePhase != .active || isSceneCaptured {
                SensitiveContentShield(isCaptured: isSceneCaptured)
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
            store.conflictingAccountID == nil ? String(localized: "Error") : String(localized: "Sync conflict"),
            isPresented: Binding(
                get: { !appLock.isLocked && !store.isResolvingConflict && (store.conflictingAccountID != nil || store.lastError != nil) },
                set: { if !$0 && store.conflictingAccountID == nil { store.clearError() } }
            )
        ) {
            if store.conflictingAccountID != nil {
                Button("Keep this device's version") {
                    Task { await store.resolveConflict(keepLocal: true) }
                }
                Button("Use iCloud's version") {
                    Task { await store.resolveConflict(keepLocal: false) }
                }
            } else {
                Button("OK") { store.clearError() }
            }
        } message: {
            if let id = store.conflictingAccountID {
                if let account = store.accounts.first(where: { $0.id == id }) {
                    Text(account.payload.displayTitle)
                }
                if store.conflictRemoteMissing {
                    Text("This older account is missing from iCloud. Keep this device's version to upload it again, or use iCloud's version to remove it from this device.")
                } else {
                    Text("This account changed on another device. Your local change is saved until you choose which version to keep.")
                }
                if let error = store.lastError { Text(error) }
            } else {
                Text(store.lastError ?? "")
            }
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
                                Label("Retry loading", systemImage: "arrow.clockwise")
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
                        if filteredAccounts.isEmpty {
                            ContentUnavailableView.search(text: searchText)
                        }
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            ForEach(filteredAccounts) { account in
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
            .onChange(of: groups) { _, updated in
                if let selectedGroup, !selectedGroup.isEmpty, !updated.contains(selectedGroup) {
                    self.selectedGroup = nil
                }
            }
            .searchable(text: $searchText, prompt: "Search accounts")
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

                ToolbarItem(placement: .topBarLeading) {
                    Menu {
                        Picker("Group", selection: $selectedGroup) {
                            Text("All accounts").tag(nil as String?)
                            Text("Ungrouped").tag(Optional(""))
                            ForEach(groups, id: \.self) { group in
                                Text(group).tag(Optional(group))
                            }
                        }
                        Button("Encrypted backup and import") { showTransfer = true }
                    } label: {
                        Image(systemName: "line.3.horizontal.decrease")
                    }
                    .disabled(!store.isReady || store.isLoading)
                    .accessibilityLabel("Groups and backup")
                }

                ToolbarItem(placement: .topBarTrailing) {
                    Link(
                        destination: URL(
                            string: "https://apps.apple.com/us/app/keyauth-otp/id6814867894?l=zh-Hans-CN"
                        )!
                    ) {
                        Image(systemName: "bag")
                    }
                    .accessibilityLabel("View KeyAuth on the App Store")
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
            .sheet(isPresented: $showTransfer) {
                VaultTransferView()
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
                Text(
                    "Deleting removes the account from this device immediately and deletes the cloud record after iCloud reconnects. An older exported backup may still contain it."
                )
            }
        }
    }
}

private struct StorageModeLabel: View {
    let isCloudSyncEnabled: Bool

    var body: some View {
        Group {
            if isCloudSyncEnabled {
                Label(
                    "Local encrypted vault · iCloud background sync",
                    systemImage: "icloud.fill"
                )
            } else {
                Label(
                    "Local encrypted vault",
                    systemImage: "externaldrive.fill"
                )
            }
        }
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
                SecureField("KA1-Recovery key", text: $recoveryCode)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)

                Button {
                    appLock.recover(recoveryCode: recoveryCode)
                } label: {
                    Label(
                        "Recover from iCloud",
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
                    if appLock.isAuthenticating {
                        Label("Unlocking…", systemImage: "faceid")
                    } else {
                        Label("Unlock", systemImage: "faceid")
                    }
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
    @State private var copied = false

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

                Button {
                    guard code != "------" else { return }
                    UIPasteboard.general.setItems(
                        [[UIPasteboard.typeAutomatic: code]],
                        options: [
                            .localOnly: true,
                            .expirationDate: Date().addingTimeInterval(TimeInterval(remaining))
                        ]
                    )
                    copied = true
                } label: {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(code)
                            .font(.system(.title2, design: .monospaced))
                            .fontWeight(.semibold)
                        if copied {
                            Text("Copied")
                                .font(.caption)
                        }
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Copy verification code")
                .onChange(of: code) { _, _ in copied = false }
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
