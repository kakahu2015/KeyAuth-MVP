import SwiftUI

struct EditAccountView: View {
    @EnvironmentObject private var store: OTPStore
    @Environment(\.dismiss) private var dismiss

    let account: OTPStore.DecryptedAccount

    @State private var displayName: String
    @State private var isSaving = false
    @State private var groupName: String

    init(account: OTPStore.DecryptedAccount) {
        self.account = account
        _groupName = State(initialValue: account.payload.groupName ?? "")
        _displayName = State(
            initialValue: account.payload.displayName
                ?? account.payload.displayTitle
        )
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Display name") {
                    TextField("Name", text: $displayName)
                        .textInputAutocapitalization(.words)
                        .autocorrectionDisabled()

                    Text("Clear the field to use the name from the QR code.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section("Group") {
                    TextField("Group name", text: $groupName)
                        .textInputAutocapitalization(.words)
                        .autocorrectionDisabled()
                }

                Section("Account") {
                    LabeledContent("Issuer", value: account.payload.issuer)
                    LabeledContent("Account", value: account.payload.accountName)
                }
            }
            .navigationTitle("Edit Account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                    .disabled(isSaving)
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        isSaving = true
                        Task {
                            if await store.updateDisplayName(
                                for: account.id,
                                to: displayName,
                                groupName: groupName
                            ) {
                                dismiss()
                            } else {
                                isSaving = false
                            }
                        }
                    }
                    .disabled(isSaving)
                }
            }
        }
    }
}
