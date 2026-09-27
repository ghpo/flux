import SwiftUI
import Shared
import UIKit

final class FluxModel: ObservableObject {
    @Published var devices: [DeviceUi] = []
    @Published var message: String = ""
    private let flux: Flux

    init() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!.path
        let dir = docs + "/flux"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let name = UIDevice.current.name
        flux = Flux(dir: dir, deviceName: name)
        flux.onUpdate = { [weak self] in
            DispatchQueue.main.async { self?.refresh() }
        }
        flux.onEvent = { [weak self] msg in
            DispatchQueue.main.async { self?.message = msg }
        }
        flux.start()
        refresh()
    }

    deinit {
        flux.stop()
    }

    func refresh() {
        devices = flux.snapshot()
    }

    func pair(_ id: String) {
        flux.pair(id: id, timestamp: Int64(Date().timeIntervalSince1970))
    }

    func accept(_ id: String) { flux.acceptPair(id: id) }
    func reject(_ id: String) { flux.cancelPair(id: id) }
    func unpair(_ id: String) { flux.unpair(id: id) }
}

struct ContentView: View {
    @StateObject private var model = FluxModel()

    var body: some View {
        NavigationView {
            Group {
                if model.devices.isEmpty {
                    Text("Looking for computers...")
                        .foregroundColor(.secondary)
                } else {
                    List(model.devices, id: \.id) { device in
                        DeviceRow(device: device, model: model)
                    }
                }
            }
            .navigationTitle("Flux")
            .toolbar {
                ToolbarItem(placement: .bottomBar) {
                    Text(model.message.isEmpty ? " " : model.message)
                        .font(.footnote)
                        .foregroundColor(.secondary)
                }
            }
        }
    }
}

struct DeviceRow: View {
    let device: DeviceUi
    let model: FluxModel

    var body: some View {
        HStack {
            VStack(alignment: .leading) {
                Text(device.name).font(.headline)
                Text(device.online ? "Online" : "Offline")
                    .font(.caption)
                    .foregroundColor(device.online ? .green : .secondary)
            }
            Spacer()
            if device.paired {
                Button("Unpair") { model.unpair(device.id) }.buttonStyle(.bordered)
            } else if !device.pairKey.isEmpty {
                VStack(alignment: .trailing, spacing: 4) {
                    Text(device.pairKey)
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(.secondary)
                    if device.pairOutgoing {
                        Button("Cancel") { model.reject(device.id) }
                    } else {
                        HStack {
                            Button("Reject") { model.reject(device.id) }
                            Button("Accept") { model.accept(device.id) }.buttonStyle(.borderedProminent)
                        }
                    }
                }
            } else if device.online {
                Button("Pair") { model.pair(device.id) }.buttonStyle(.borderedProminent)
            }
        }
        .padding(.vertical, 2)
    }
}
