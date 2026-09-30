import SwiftUI
import UniformTypeIdentifiers

struct EncryptedVaultDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    var data: Data

    init(data: Data) { self.data = data }

    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents,
              data.count <= VaultTransferManager.maximumFileSize else {
            throw VaultTransferError.tooLarge
        }
        self.data = data
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

struct VaultTransferView: View {
    @EnvironmentObject private var store: OTPStore
    @Environment(\.dismiss) private var dismiss
    @State private var export: VaultTransferManager.Export?
    @State private var savedKey = false
    @State private var showExporter = false
    @State private var showImporter = false
    @State private var backupKey = ""
    @State private var resultMessage: String?
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Export encrypted backup") {
                    Text("The backup contains all accounts and groups. Save its backup key separately; the recovery key cannot open this file.")
                    if let export {
                        Text(export.key)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                            .privacySensitive()
                        Toggle("I saved the backup key separately", isOn: $savedKey)
                        Button("Save encrypted file") { showExporter = true }
                            .disabled(!savedKey)
                    } else {
                        Button("Create encrypted backup") {
                            do { export = try store.exportVault() }
                            catch { errorMessage = error.localizedDescription }
                        }
                        .disabled(!store.isReady || store.accounts.isEmpty)
                    }
                }
                Section("Import encrypted backup") {
                    Text("Existing accounts are kept. Duplicate credentials are skipped.")
                    SecureField("KAB1-Backup key", text: $backupKey)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("Choose encrypted file") { showImporter = true }
                        .disabled(backupKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !store.isReady)
                }
                if let resultMessage { Text(resultMessage) }
            }
            .navigationTitle("Backup and import")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .fileExporter(
                isPresented: $showExporter,
                document: export.map { EncryptedVaultDocument(data: $0.data) },
                contentType: .json,
                defaultFilename: "KeyAuth-encrypted-backup"
            ) { result in
                switch result {
                case .success:
                    resultMessage = String(localized: "Encrypted backup saved.")
                case .failure(let error):
                    errorMessage = error.localizedDescription
                }
            }
            .fileImporter(isPresented: $showImporter, allowedContentTypes: [.json]) { result in
                do {
                    let url = try result.get()
                    let scoped = url.startAccessingSecurityScopedResource()
                    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                    let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                    guard size <= VaultTransferManager.maximumFileSize else { throw VaultTransferError.tooLarge }
                    let data = try Data(contentsOf: url)
                    let count = try store.importVault(data: data, backupKey: backupKey)
                    resultMessage = String(localized: "Imported accounts:") + " \(count)"
                    backupKey = ""
                } catch {
                    errorMessage = error.localizedDescription
                }
            }
            .alert("Error", isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } }
            )) {
                Button("OK") { errorMessage = nil }
            } message: {
                Text(errorMessage ?? "")
            }
        }
    }
}
