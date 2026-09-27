import SwiftUI
import Shared

struct ContentView: View {
    @State private var deviceId = ""

    var body: some View {
        VStack(spacing: 16) {
            Text(AppKt.fluxAppName())
                .font(.largeTitle)
                .bold()

            if deviceId.isEmpty {
                Button("Generate identity") {
                    deviceId = AppKt.deviceIdentity(deviceId: "0123456789abcdef0123456789abcdef")
                }
                .buttonStyle(.borderedProminent)
            } else {
                Text("Device ID")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(deviceId)
                    .font(.system(.body, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
        }
        .padding()
    }
}
