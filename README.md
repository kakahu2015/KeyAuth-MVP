# KeyAuth MVP

A SwiftUI TOTP authenticator prototype using an application-level E2EE design:

- The encrypted local vault is the primary data source; TOTP generation works offline
- TOTP secrets and account metadata are encrypted **on-device**
- Encryption: AES-256-GCM via CryptoKit
- Master key: 32 random bytes
- Master key storage: device-bound Keychain item protected by `userPresence`
- Optional backup/sync: CloudKit private database
- CloudKit receives only an encrypted blob plus minimal sync metadata
- No application server

## Threat model

CloudKit contains:

- record UUID
- AES-GCM ciphertext
- schema version
- created/updated timestamps

CloudKit does **not** contain plaintext:

- issuer
- account name
- TOTP secret
- hash algorithm
- digits
- period

The AES master key is never stored in CloudKit.

## Xcode setup

The repository now contains `KeyAuth.xcodeproj`, generated from `project.yml`.
Open it directly, or regenerate it after changing the project definition:

```sh
xcodegen generate --spec project.yml
open KeyAuth.xcodeproj
```

The target uses Swift 6 and iOS 26 or later. `Info.plist` contains the camera
and Face ID usage descriptions required by the QR scanner and app lock.

Simulator builds intentionally use the encrypted local development store;
CloudKit is exercised only by a signed device build with the configured
entitlements.

## Required capability

In Xcode:

`TARGETS -> KeyAuth -> Signing & Capabilities -> + Capability -> iCloud`

Enable:

- CloudKit
- choose/create an iCloud container for this app

The source configuration in `project.yml` must match the Apple Developer team
used for signing:

- `PRODUCT_BUNDLE_IDENTIFIER`
- `KEYAUTH_CLOUD_CONTAINER`

This checkout is configured for:

- Bundle Identifier: `org.kakahu.KeyAuth`
- iCloud container: `iCloud.org.kakahu.KeyAuth`

If you use a different Apple Developer team, change both values together and
associate the container with the App ID in Certificates, Identifiers &
Profiles. Do not ship the `com.example.KeyAuth` /
`iCloud.com.example.KeyAuth` placeholders.

## CloudKit schema

Run the Debug app once in development. If the `EncryptedOTP` record type does
not exist yet, the app treats the Development database as empty; saving the
first account creates the Development schema. Before shipping, deploy that
schema from Development to Production in CloudKit Console.

The app creates record type:

`EncryptedOTP`

Fields:

- `blob` : Bytes
- `version` : Int(64)
- `createdAt` : Date/Time
- `updatedAt` : Date/Time

The app reads records by the `updatedAt` field rather than using a
`TRUEPREDICATE` all-record query. This avoids requiring a `recordName`
queryable index for normal app startup. When deploying the schema to
Production, add a `QUERYABLE` index for `updatedAt` in CloudKit Dashboard.

CloudKit is a backup/sync layer, not the runtime vault. On a device that has
already been provisioned, KeyAuth loads its encrypted local vault first and
continues to display and generate codes when iCloud or the network is
unavailable. Cloud changes are pulled and pushed in the background.

Before App Store release, inspect the Development schema in CloudKit Console and deploy it to Production.

## First test

Use a disposable TOTP account.

Paste an `otpauth://totp/...` URI in Add Account.

The app:

1. parses the URI
2. validates the Base32 secret
3. encrypts the entire account payload using AES-GCM
4. saves the encrypted blob to the local vault first
5. immediately displays the account and current TOTP code
6. queues the encrypted change for iCloud in the background

Failed uploads remain on disk and retry on launch, foreground activation, or
when the user taps the sync status. Until upload completes, the account is
saved only on this device and is not yet available for recovery on another.
Editing and deleting also update the local vault first and queue their cloud
changes, so a network outage does not block normal use.

The first launch requires device authentication. The app locks again when it
enters the background, and account/code rows are marked privacy-sensitive.

New records use AES-GCM associated data binding the record UUID and schema
version. Version 1 MVP records remain readable through a legacy read-only
fallback so an upgrade does not silently discard existing accounts.

Account names can be edited after import. The custom display name is encrypted
inside the same payload; clearing it restores the name from the QR code. Swipe
an account to edit or delete it. Deleting removes it from the local vault
immediately and queues the encrypted CloudKit deletion.

## Moving to another device

P0 deliberately binds the master key to the current device with
`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and a `userPresence` access
control. CloudKit stores only encrypted account records, so those records
cannot be decrypted on a new device by themselves.

When upgrading an existing installation, the first authenticated unlock
migrates the previous synchronizable v1 key into the new device-bound v2
Keychain item. A future recovery implementation must add an independent
Recovery Key wrapper for the vault key; the raw master key must not be synced
directly again.

After a device has been provisioned, it has a local primary vault and can
generate codes offline. Deleting an account removes it locally immediately and
queues the CloudKit deletion; after it syncs, it cannot be restored by
reinstalling the app. Uninstalling the app does not delete CloudKit records.

This is encrypted iCloud backup/sync, not a plaintext export. The current debug
build uses the Development CloudKit environment; a release build must deploy
the schema to Production and use the Production environment.

## Security notes before production

This is a functional MVP, not yet a production security audit.

Still required before release:

- Apple Team signing and a real iCloud container
- development CloudKit schema creation and production deployment
- real-device testing of the protected Keychain item and authentication flow
- Recovery Key wrapping and multi-device bootstrap policy
- key rotation
- CloudKit change subscriptions and conflict handling
- secure clipboard behavior for any future copy action
- migration and backup tests
- HOTP decision (currently rejected)
- RFC test vectors/unit tests
- independent cryptographic/security review

## Important recovery property

Because the P0 master key is device-bound, deleting the trusted device may make
the CloudKit ciphertext unrecoverable until the independent Recovery Key
mechanism is implemented.

That is intentional for a zero-knowledge design, but the production app must explain this clearly and provide a carefully designed recovery mechanism.
