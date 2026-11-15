import AVFoundation
import SwiftUI
import UIKit

struct ContentView: View {
    @EnvironmentObject var model: ProbeModel
    @State private var showToken = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    StatusRow(title: "Edge", health: model.edgeHealth, line: model.edgeLine,
                              hint: model.edgeHint, raw: model.edgeRaw)
                    StatusRow(title: "Camera", health: model.cameraHealth, line: model.cameraLine,
                              hint: model.cameraHint, raw: nil)
                    if let ok = model.lastOKPoll {
                        HStack {
                            Text("Last good poll")
                            Spacer()
                            (Text(ok, style: .relative) + Text(" ago")).foregroundStyle(.secondary)
                        }
                    }
                    if model.running {
                        Button("Stop", role: .destructive) { model.stop() }
                    } else {
                        Button("Start (connect to edge)") { model.start() }.bold()
                    }
                } header: {
                    Text("DepthProbe \(ProbeModel.appVersion)")
                }
                Section {
                    CameraPreview(session: model.camera.session)
                        .frame(height: 220)
                        .listRowInsets(EdgeInsets())
                } footer: {
                    Text("Front TrueDepth camera. Face 25-50 cm away, indoors, phone on power, DepthProbe on screen.")
                }
                Section {
                    HStack {
                        TextField("http://<mac-ip>:8001", text: $model.edgeURL)
                            .keyboardType(.URL)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        Button(model.discovering ? "Searching..." : "Find Mac") { model.findMac() }
                            .buttonStyle(.borderless)
                            .disabled(model.discovering)
                    }
                    HStack {
                        if showToken {
                            TextField("X-Depth-Token (DEPTH_DEVICE_TOKEN)", text: $model.token)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        } else {
                            SecureField("X-Depth-Token (DEPTH_DEVICE_TOKEN)", text: $model.token)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        }
                        Button(showToken ? "Hide" : "Show") { showToken.toggle() }
                            .buttonStyle(.borderless)
                    }
                    HStack {
                        Text(model.tokenSummary).font(.footnote).foregroundStyle(.secondary)
                        Spacer()
                        PasteButton(payloadType: String.self) { items in
                            guard let text = items.first else { return }
                            Task { @MainActor in model.applyPasted(text) }
                        }
                    }
                    Button(model.testing ? "Testing..." : "Test connection") { model.testConnection() }
                        .disabled(model.testing)
                    Toggle("Send 1 RGB JPEG per attempt", isOn: $model.sendRGB)
                    Picker("Depth width", selection: $model.depthWidth) {
                        Text("320").tag(320)
                        Text("640").tag(640)
                    }
                    .pickerStyle(.segmented)
                } header: {
                    Text("Edge service (Mac)")
                } footer: {
                    Text("URL = http://<Mac IP>:8001 (EDGE_LAN_PORT, not 8000). Token = DEPTH_DEVICE_TOKEN from the "
                        + "Mac's .env. Easiest: run depth/ios/pair.sh on the Mac and scan its QR with the iPhone "
                        + "Camera app (or tap Paste after the script copies the link).")
                }
                Section {
                    Button("Test capture (local only)") { model.testCapture() }
                    Button("Restart camera") { model.restartCamera() }
                }
                Section("Details") {
                    row("State", model.status)
                    row("Last attempt", model.lastAttempt)
                    row("Phase", model.lastPhase)
                    row("Last upload", model.lastUpload)
                    row("Capture ms", model.lastCaptureMs.map(String.init) ?? "-")
                    row("Upload ms", model.lastUploadMs.map(String.init) ?? "-")
                    row("Valid ratio", model.lastValidRatio.map { String(format: "%.2f", $0) } ?? "-")
                    row("Distance", model.lastDistanceCm.map { String(format: "%.0f cm", $0) } ?? "-")
                    row("Polls OK / sent", "\(model.pollsOK) / \(model.attemptsSent)")
                    row("Thermal", model.thermal)
                    row("Format", model.cameraFormat)
                    Text(model.lastDepthInfo).font(.caption).foregroundStyle(.secondary)
                    Text(model.lastFaceInfo).font(.caption).foregroundStyle(.secondary)
                    Text("Edge: \(model.lastEdgeReply)").font(.caption).foregroundStyle(.secondary)
                    if let err = model.lastError {
                        Text(err).font(.caption).foregroundStyle(.red).textSelection(.enabled)
                    }
                }
            }
            .navigationTitle("DepthProbe")
            .navigationBarTitleDisplayMode(.inline)
            .alert("Apply pairing link?", isPresented: Binding(
                get: { model.pendingConfigLink != nil },
                set: { if !$0 { model.cancelPendingLink() } }
            )) {
                Button("Apply") { model.confirmPendingLink() }
                Button("Cancel", role: .cancel) { model.cancelPendingLink() }
            } message: {
                Text(model.pendingLinkSummary())
            }
        }
    }

    private func row(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
        }
    }
}

/// One traffic-light line: what is wrong, how to fix it, and the exact system error.
struct StatusRow: View {
    let title: String
    let health: Health
    let line: String
    let hint: String?
    let raw: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Circle().fill(color).frame(width: 12, height: 12)
                Text(title).font(.headline)
                Text(line)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(health == .error ? Color.red : Color.primary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let hint, !hint.isEmpty {
                Text(hint)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            if let raw, !raw.isEmpty {
                Text(raw)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
        .padding(.vertical, 2)
    }

    private var color: Color {
        switch health {
        case .idle: return .gray
        case .working: return .yellow
        case .ok: return .green
        case .warn: return .orange
        case .error: return .red
        }
    }
}

/// Live preview so the user can centre the face (mirrored like a selfie camera).
struct CameraPreview: UIViewRepresentable {
    let session: AVCaptureSession

    func makeUIView(context: Context) -> PreviewView {
        let view = PreviewView()
        view.previewLayer.session = session
        view.previewLayer.videoGravity = .resizeAspect
        view.backgroundColor = .black
        return view
    }

    func updateUIView(_ uiView: PreviewView, context: Context) {}

    final class PreviewView: UIView {
        override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
        var previewLayer: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
    }
}
