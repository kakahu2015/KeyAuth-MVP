import SwiftUI

struct SensitiveContentShield: View {
    let isCaptured: Bool

    var body: some View {
        ZStack {
            Color(uiColor: .systemBackground)
                .ignoresSafeArea()

            VStack(spacing: 12) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 42))

                Text(isCaptured ? "Sensitive content hidden" : "KeyAuth")
                    .font(.headline)
            }
        }
        .allowsHitTesting(true)
        .privacySensitive()
    }
}
