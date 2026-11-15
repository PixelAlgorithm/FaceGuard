import SwiftUI

/// DepthProbe: a deliberately dumb client. It captures 1-3 front TrueDepth depth frames when the kiosk
/// edge service asks (long-poll), and uploads them; all liveness math runs in Python on the edge
/// (depth/checks.py). Nothing is stored on the phone. It connects by itself whenever it is on screen;
/// `depthprobe://config?url=...&token=...` (QR from depth/ios/pair.sh) sets the edge URL + token.
@main
struct DepthProbeApp: App {
    @StateObject private var model = ProbeModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .onOpenURL { url in model.applyConfigLink(url) }
        }
        .onChange(of: scenePhase, initial: true) { _, phase in
            switch phase {
            case .active: model.sceneBecameActive()
            case .background: model.sceneEnteredBackground()
            default: break
            }
        }
    }
}
