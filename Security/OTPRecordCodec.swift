import Foundation
import CryptoKit

enum OTPRecordCodecError: Error {
    case invalidRecord
}

struct OTPRecordCodec {
    static func decrypt(_ item: EncryptedOTPAccount, using key: SymmetricKey) throws -> EncryptedOTPRecordPayload {
        do {
            switch item.version {
            case 4:
                return try CryptoManager.decrypt(
                    EncryptedOTPRecordPayload.self,
                    from: item.encryptedBlob,
                    using: key,
                    associatedData: CryptoManager.associatedData(
                        for: item.id,
                        version: item.version,
                        keyVersion: item.keyVersion
                    )
                )
            case 3:
                let payload = try CryptoManager.decrypt(
                    OTPAccountPayload.self,
                    from: item.encryptedBlob,
                    using: key,
                    associatedData: CryptoManager.associatedData(
                        for: item.id,
                        version: item.version,
                        keyVersion: item.keyVersion
                    )
                )
                return EncryptedOTPRecordPayload(
                    otp: payload,
                    createdAt: item.createdAt,
                    updatedAt: item.updatedAt
                )
            case 2:
                let payload = try CryptoManager.decrypt(
                    OTPAccountPayload.self,
                    from: item.encryptedBlob,
                    using: key,
                    associatedData: CryptoManager.legacyAssociatedData(
                        for: item.id,
                        version: item.version
                    )
                )
                return EncryptedOTPRecordPayload(
                    otp: payload,
                    createdAt: item.createdAt,
                    updatedAt: item.updatedAt
                )
            case 1:
                let payload: OTPAccountPayload
                do {
                    payload = try CryptoManager.decrypt(
                        OTPAccountPayload.self,
                        from: item.encryptedBlob,
                        using: key,
                        associatedData: CryptoManager.legacyAssociatedData(
                            for: item.id,
                            version: item.version
                        )
                    )
                } catch {
                    payload = try CryptoManager.decryptLegacy(
                        OTPAccountPayload.self,
                        from: item.encryptedBlob,
                        using: key
                    )
                }
                return EncryptedOTPRecordPayload(
                    otp: payload,
                    createdAt: item.createdAt,
                    updatedAt: item.updatedAt
                )
            default:
                throw OTPRecordCodecError.invalidRecord
            }
        } catch let error as OTPRecordCodecError {
            throw error
        } catch {
            throw OTPRecordCodecError.invalidRecord
        }
    }

    static func encrypt(
        _ record: EncryptedOTPRecordPayload,
        for id: UUID,
        using key: SymmetricKey,
        keyVersion: Int,
        cloudChangeTag: String? = nil,
        canCreateCloudRecord: Bool = false
    ) throws -> EncryptedOTPAccount {
        let version = EncryptedOTPAccount.currentVersion
        let encryptedBlob = try CryptoManager.encrypt(
            record,
            using: key,
            associatedData: CryptoManager.associatedData(
                for: id,
                version: version,
                keyVersion: keyVersion
            )
        )
        return EncryptedOTPAccount(
            id: id,
            encryptedBlob: encryptedBlob,
            version: version,
            keyVersion: keyVersion,
            cloudChangeTag: cloudChangeTag,
            needsUpload: true,
            canCreateCloudRecord: canCreateCloudRecord,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt
        )
    }

}
