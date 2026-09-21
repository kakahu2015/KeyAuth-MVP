import SwiftUI

@main
struct KeyAuthApp: App {
    @StateObject private var store = OTPStore()
    @StateObject private var appLock = AppLockManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(store)
                .environmentObject(appLock)
                .task {
                    await store.bootstrap()
                }
        }
    }
}
