import Foundation

actor LocalEncryptedStore {
    static let shared = LocalEncryptedStore()

    private let storageKey = "KeyAuth.LocalEncryptedAccounts.v1"

    func fetchAll() throws -> [EncryptedOTPAccount] {
        guard let data = UserDefaults.standard.data(forKey: storageKey) else {
            return []
        }
        return try JSONDecoder().decode([EncryptedOTPAccount].self, from: data)
    }

    func save(_ item: EncryptedOTPAccount) throws {
        var items = try fetchAll()
        if let index = items.firstIndex(where: { $0.id == item.id }) {
            items[index] = item
        } else {
            items.append(item)
        }
        try persist(items)
    }

    func delete(id: UUID) throws {
        let items = try fetchAll().filter { $0.id != id }
        try persist(items)
    }

    func replaceAll(_ items: [EncryptedOTPAccount]) throws {
        try persist(items)
    }

    private func persist(_ items: [EncryptedOTPAccount]) throws {
        let data = try JSONEncoder().encode(items)
        UserDefaults.standard.set(data, forKey: storageKey)
    }
}

// Durable encrypted changes are scoped to the current iCloud user once known;
// a local queue is used until the account identity is available.
actor PendingCloudUploads {
    static let shared = PendingCloudUploads()
    static let unassignedOwner = "__local_pending__"

    private func file(for owner: String) throws -> URL {
        let directory = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ).appendingPathComponent("PendingCloudUploads", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let name = Data(owner.utf8).map { String(format: "%02x", $0) }.joined()
        return directory.appendingPathComponent(name + ".json")
    }

    func fetch(owner: String) throws -> [EncryptedOTPAccount] {
        let url = try file(for: owner)
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        return try JSONDecoder().decode([EncryptedOTPAccount].self, from: Data(contentsOf: url))
    }

    func save(_ item: EncryptedOTPAccount, owner: String) throws {
        var items = try fetch(owner: owner).filter { $0.id != item.id }
        items.append(item)
        try write(items, owner: owner)
    }

    func remove(id: UUID, owner: String) throws {
        try write(fetch(owner: owner).filter { $0.id != id }, owner: owner)
    }

    func move(from sourceOwner: String, to destinationOwner: String) throws {
        guard sourceOwner != destinationOwner else { return }

        let sourceItems = try fetch(owner: sourceOwner)
        guard !sourceItems.isEmpty else { return }

        var destinationItems = try fetch(owner: destinationOwner)
        let destinationIDs = Set(destinationItems.map(\.id))
        destinationItems.append(contentsOf: sourceItems.filter {
            !destinationIDs.contains($0.id)
        })
        try write(destinationItems, owner: destinationOwner)
        try write([], owner: sourceOwner)
    }

    private func write(_ items: [EncryptedOTPAccount], owner: String) throws {
        try JSONEncoder().encode(items).write(
            to: file(for: owner), options: [.atomic, .completeFileProtection]
        )
    }
}

actor PendingCloudDeletes {
    static let shared = PendingCloudDeletes()

    private func file(for owner: String) throws -> URL {
        let directory = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        ).appendingPathComponent("PendingCloudDeletes", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let name = Data(owner.utf8).map { String(format: "%02x", $0) }.joined()
        return directory.appendingPathComponent(name + ".json")
    }

    func fetch(owner: String) throws -> [UUID] {
        let url = try file(for: owner)
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        return try JSONDecoder().decode([UUID].self, from: Data(contentsOf: url))
    }

    func add(id: UUID, owner: String) throws {
        var ids = try fetch(owner: owner)
        if !ids.contains(id) {
            ids.append(id)
            try persist(ids, owner: owner)
        }
    }

    func remove(id: UUID, owner: String) throws {
        try persist(fetch(owner: owner).filter { $0 != id }, owner: owner)
    }

    func move(from sourceOwner: String, to destinationOwner: String) throws {
        guard sourceOwner != destinationOwner else { return }

        let sourceIDs = try fetch(owner: sourceOwner)
        guard !sourceIDs.isEmpty else { return }

        var destinationIDs = try fetch(owner: destinationOwner)
        for id in sourceIDs where !destinationIDs.contains(id) {
            destinationIDs.append(id)
        }
        try persist(destinationIDs, owner: destinationOwner)
        try persist([], owner: sourceOwner)
    }

    private func persist(_ ids: [UUID], owner: String) throws {
        try JSONEncoder().encode(ids).write(
            to: file(for: owner), options: [.atomic, .completeFileProtection]
        )
    }
}
