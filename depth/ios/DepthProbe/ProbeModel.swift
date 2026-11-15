import AVFoundation
import Foundation
import QuartzCore
import UIKit

/// Traffic-light state of the edge link and of the camera, shown at the top of the screen.
enum Health { case idle, working, ok, warn, error }

/// App state + the long-poll loop: wait for an attempt, capture 1-3 depth frames, upload, repeat.
/// The loop runs whenever the app is on screen (unless the operator pressed Stop) and does not depend on
/// the camera, so a camera problem never hides a connection problem and vice versa. Every failure is shown
/// with its cause and the fix (EdgeDiagnosis / CameraDiagnosis).
@MainActor
final class ProbeModel: ObservableObject {
    private enum Keys {
        static let edgeURL = "edgeURL", token = "depthToken", sendRGB = "sendRGB", depthWidth = "depthWidth"
        static let wantRunning = "wantRunning"
    }
    static let appVersion = (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "?"
    // CHALLENGE timing when the edge sends neither delay_ms nor interval_ms: spread the 1-3 frames over
    // the challenge (both 1.5 s steps) so at least one frame catches the mouth/cheek movement; the edge
    // measures every frame (per-frame Vision results below) and keeps the most deformed one.
    static let challengeDefaultDelayMs = 400.0
    static let challengeDefaultIntervalMs = 700.0
    static let longPollS = 20
    static let connectTimeoutS: TimeInterval = 5

    @Published var edgeURL: String = UserDefaults.standard.string(forKey: Keys.edgeURL) ?? EdgeDefaults.edgeURL {
        didSet { UserDefaults.standard.set(edgeURL, forKey: Keys.edgeURL); settingsChanged() }
    }
    @Published var token: String = UserDefaults.standard.string(forKey: Keys.token) ?? "" {
        didSet { UserDefaults.standard.set(token, forKey: Keys.token); settingsChanged() }
    }
    // Off by default (data minimisation): the edge needs the RGB photo only when Vision found no face.
    @Published var sendRGB: Bool = (UserDefaults.standard.object(forKey: Keys.sendRGB) as? Bool) ?? false {
        didSet { UserDefaults.standard.set(sendRGB, forKey: Keys.sendRGB) }
    }
    @Published var depthWidth: Int = (UserDefaults.standard.object(forKey: Keys.depthWidth) as? Int) ?? 320 {
        didSet {
            UserDefaults.standard.set(depthWidth, forKey: Keys.depthWidth)
            if isActive { Task { await startCamera() } }
        }
    }
    /// Operator intent: keep polling whenever the app is on screen. Survives backgrounding and relaunch.
    @Published private(set) var wantRunning: Bool = (UserDefaults.standard.object(forKey: Keys.wantRunning) as? Bool) ?? true {
        didSet { UserDefaults.standard.set(wantRunning, forKey: Keys.wantRunning) }
    }

    @Published private(set) var running = false
    @Published private(set) var status = "Stopped"
    @Published private(set) var lastAttempt = "-"
    @Published private(set) var lastPhase = "-"
    @Published private(set) var lastUploadMs: Int?
    @Published private(set) var lastCaptureMs: Int?
    @Published private(set) var lastValidRatio: Double?
    @Published private(set) var lastDistanceCm: Double?
    @Published private(set) var lastDepthInfo = "-"
    @Published private(set) var lastFaceInfo = "-"
    @Published private(set) var lastEdgeReply = "-"
    @Published private(set) var lastUpload = "-"
    @Published private(set) var lastError: String?
    @Published private(set) var attemptsSent = 0
    @Published private(set) var thermal = "-"
    @Published private(set) var cameraFormat = "-"

    // Top-of-screen status
    @Published private(set) var edgeHealth: Health = .idle
    @Published private(set) var edgeLine = "Not started"
    @Published private(set) var edgeHint: String?
    @Published private(set) var edgeRaw: String?
    @Published private(set) var lastOKPoll: Date?
    @Published private(set) var pollsOK = 0
    @Published private(set) var cameraHealth: Health = .idle
    @Published private(set) var cameraLine = "Not started"
    @Published private(set) var cameraHint: String?
    @Published private(set) var discovering = false
    @Published private(set) var testing = false

    let camera = DepthCamera()
    private let client = EdgeClient()
    private var loopTask: Task<Void, Never>?
    private var settingsDebounce: Task<Void, Never>?
    private var observers: [NSObjectProtocol] = []
    private var isActive = false
    private var internalChange = false
    private var cameraIsInterrupted = false

    /// `-pairingLink depthprobe://config?...` launch argument (devicectl / simctl launch): same as scanning
    /// the pairing QR, without the "Open in DepthProbe?" tap.
    private var launchLink: URL?

    init() {
        observeCamera()
        if let s = UserDefaults.standard.string(forKey: "pairingLink"), let u = URL(string: s) { launchLink = u }
    }

    var tokenSummary: String {
        let t = EdgeClient.normalizedToken(token)
        if t.isEmpty { return "Token: not set" }
        return t == token ? "Token: set (\(t.count) characters)" : "Token: set (\(t.count) characters after trimming)"
    }

    // MARK: control

    func start() {
        wantRunning = true
        startLoop()
    }

    func stop() {
        wantRunning = false
        stopLoop()
        status = "Stopped"
        setEdgeState(.idle, "Stopped - tap Start", nil)
    }

    private func startLoop() {
        guard loopTask == nil else { return }
        running = true
        loopTask = Task { [weak self] in await self?.runLoop() }
    }

    private func stopLoop() {
        loopTask?.cancel()
        loopTask = nil
        running = false
    }

    private func restartLoop() {
        stopLoop()
        if wantRunning && isActive { startLoop() }
    }

    /// Edge URL / token edited: reconnect shortly after the operator stops typing.
    private func settingsChanged() {
        guard !internalChange else { return }
        settingsDebounce?.cancel()
        settingsDebounce = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 1_200_000_000)
            guard let self, !Task.isCancelled, self.running else { return }
            self.restartLoop()
        }
    }

    // MARK: scene

    func sceneBecameActive() {
        isActive = true
        UIApplication.shared.isIdleTimerDisabled = true  // the screen must stay on: iOS stops the camera when locked
        Task { await startCamera() }
        if let link = launchLink {
            launchLink = nil
            if applyConfigLink(link) { return }
        }
        if wantRunning { startLoop() }
    }

    func sceneEnteredBackground() {
        isActive = false
        UIApplication.shared.isIdleTimerDisabled = false
        stopLoop()
        camera.stop()
        status = "Paused (app in background)"
        setEdgeState(.idle, "Paused - DepthProbe is not on screen", "Reopen DepthProbe; it reconnects by itself.")
    }

    // MARK: pairing (QR / paste)

    /// depthprobe://config?url=<edge URL>&token=<DEPTH_DEVICE_TOKEN>  (QR / clipboard from depth/ios/pair.sh)
    @discardableResult
    func applyConfigLink(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == EdgeDefaults.configScheme,
              let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return false }
        let items = comps.queryItems ?? []
        let newURL = items.first { $0.name == "url" }?.value
        let newToken = items.first { $0.name == "token" }?.value
        guard newURL != nil || newToken != nil else { return false }
        internalChange = true
        if let u = newURL, !u.isEmpty {
            let before = (try? EdgeClient.baseURL(edgeURL)).map(EdgeClient.hostPort)
            let after = (try? EdgeClient.baseURL(u)).map(EdgeClient.hostPort)
            edgeURL = u
            // A link that points somewhere new without its own token must not receive the old one.
            if newToken == nil && after != before { token = "" }
        }
        if let t = newToken { token = EdgeClient.normalizedToken(t) }
        internalChange = false
        settingsDebounce?.cancel()
        status = "Pairing link applied"
        setEdgeState(.working, "Pairing link applied - connecting...", nil)
        wantRunning = true
        restartLoop()
        return true
    }

    /// Paste button: a depthprobe:// link sets URL + token, an http(s) URL sets the edge URL, anything else
    /// is taken as the token.
    func applyPasted(_ text: String) {
        let s = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return }
        if let u = URL(string: s), applyConfigLink(u) { return }
        if s.lowercased().hasPrefix("http://") || s.lowercased().hasPrefix("https://") {
            edgeURL = s
        } else {
            token = EdgeClient.normalizedToken(s)
        }
    }

    // MARK: connection tools

    /// One short poll (wait_s=0): proves URL + token without waiting for an attempt.
    func testConnection() {
        guard !testing else { return }
        testing = true
        Task {
            defer { testing = false }
            let tok = EdgeClient.normalizedToken(token)
            var base: URL?
            do {
                let b = try EdgeClient.baseURL(edgeURL)
                base = b
                setEdgeState(.working, "Testing \(EdgeClient.hostPort(b))...", nil)
                let job = try await client.pollPending(base: b, token: tok, waitS: 0, timeout: Self.connectTimeoutS)
                markConnected(EdgeClient.hostPort(b))
                if let job { try await handle(job, base: b, token: tok) }  // never drop a claimed attempt
            } catch {
                await reportEdge(error, base: base, token: tok)
            }
        }
    }

    func findMac() {
        guard !discovering else { return }
        Task {
            // Operator-initiated: all local subnets (the status line shows the address that was found).
            if await discover(ports: candidatePorts(), auto: false, hotspotOnly: false) != nil {
                if running { restartLoop() } else { start() }
            }
        }
    }

    /// The configured port first, then the edge's default LAN port (a mistyped port is common).
    private func candidatePorts() -> [Int] {
        let configured = (try? EdgeClient.baseURL(edgeURL))?.port ?? EdgeDefaults.lanPort
        return configured == EdgeDefaults.lanPort ? [configured] : [configured, EdgeDefaults.lanPort]
    }

    /// Scans the local subnets; on success switches edgeURL (without the settings debounce) and returns
    /// "host:port".
    private func discover(ports: [Int], auto: Bool, hotspotOnly: Bool) async -> String? {
        guard !discovering else { return nil }
        discovering = true
        defer { discovering = false }
        let before = (edgeHealth, edgeLine, edgeHint)
        let portList = ports.map(String.init).joined(separator: " / ")
        setEdgeState(.working, "Searching this network for the edge (port \(portList))...", auto ? before.2 : nil)
        if let hit = await EdgeDiscovery.find(client: client, ports: ports, hotspotOnly: hotspotOnly) {
            internalChange = true
            edgeURL = "http://\(hit.host):\(hit.port)"
            internalChange = false
            setEdgeState(.working, "Found the edge at \(hit.host):\(hit.port) - connecting...", nil)
            return "\(hit.host):\(hit.port)"
        }
        if auto {
            setEdgeState(before.0, before.1, before.2)  // keep the original error visible
        } else {
            setEdgeState(.error, "No edge found on this network",
                         "Mac and iPhone must share a network (iPhone hotspot, or the same Wi-Fi without client "
                             + "isolation), the edge must run with EDGE_LAN_PORT=8001, and Local Network must be "
                             + "allowed for DepthProbe.")
        }
        return nil
    }

    // MARK: camera

    /// Capture locally (no edge) to check that depth works and the face is found.
    func testCapture() {
        Task {
            do {
                try await ensureCamera()
                status = "Test capture..."
                let res = try await camera.capture(frames: 1, intervalMs: 0, wantRGB: false, timeout: 3)
                show(res)
                setCameraOK()
                status = "Test capture OK (not sent)"
            } catch {
                setCamera(error)
                status = "Test capture failed: \(cameraLine)"
            }
        }
    }

    func restartCamera() {
        camera.stop()
        Task {
            try? await Task.sleep(nanoseconds: 300_000_000)
            await startCamera()
        }
    }

    func startCamera() async {
        do {
            try await ensureCamera()
        } catch {
            setCamera(error)
        }
    }

    private func ensureCamera() async throws {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            break
        case .notDetermined:
            setCameraState(.working, "Waiting for camera permission...", nil)
            if !(await AVCaptureDevice.requestAccess(for: .video)) { throw CaptureError.notAuthorized }
        default:
            throw CaptureError.notAuthorized
        }
        if !camera.isRunning { setCameraState(.working, "Starting TrueDepth camera...", nil) }
        try await camera.start(preferredDepthWidth: depthWidth)
        cameraFormat = camera.formatInfo
        cameraIsInterrupted = camera.session.isInterrupted
        if camera.isRunning && !cameraIsInterrupted { setCameraOK() }
    }

    private func observeCamera() {
        let nc = NotificationCenter.default
        let s = camera.session
        observers.append(nc.addObserver(forName: AVCaptureSession.wasInterruptedNotification, object: s, queue: .main) { [weak self] note in
            let raw = (note.userInfo?[AVCaptureSessionInterruptionReasonKey] as? NSNumber)?.intValue
            Task { @MainActor in self?.cameraInterrupted(raw) }
        })
        observers.append(nc.addObserver(forName: AVCaptureSession.interruptionEndedNotification, object: s, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.cameraInterruptionEnded() }
        })
        observers.append(nc.addObserver(forName: AVCaptureSession.runtimeErrorNotification, object: s, queue: .main) { [weak self] note in
            let text = (note.userInfo?[AVCaptureSessionErrorKey] as? NSError)?.localizedDescription ?? "unknown"
            Task { @MainActor in self?.cameraRuntimeError(text) }
        })
        observers.append(nc.addObserver(forName: AVCaptureSession.didStartRunningNotification, object: s, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.cameraDidStart() }
        })
        observers.append(nc.addObserver(forName: AVCaptureSession.didStopRunningNotification, object: s, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.cameraDidStop() }
        })
    }

    private func cameraInterrupted(_ raw: Int?) {
        cameraIsInterrupted = true
        let (line, hint) = CameraDiagnosis.interruption(raw)
        setCameraState(.warn, line, hint)
    }

    private func cameraInterruptionEnded() {
        cameraIsInterrupted = false
        if camera.isRunning { setCameraOK() }
    }

    private func cameraRuntimeError(_ text: String) {
        setCameraState(.error, "Camera error: \(text)", "Restarting the camera...")
        guard isActive else { return }
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            await self?.startCamera()
        }
    }

    private func cameraDidStart() {
        cameraFormat = camera.formatInfo
        if !cameraIsInterrupted { setCameraOK() }
    }

    private func cameraDidStop() {
        if !isActive {
            setCameraState(.idle, "Off (app not on screen)", nil)
        } else if cameraHealth == .ok {
            setCameraState(.warn, "Camera stopped", "Tap Restart camera.")
        }
    }

    private func setCameraState(_ h: Health, _ line: String, _ hint: String?) {
        cameraHealth = h
        cameraLine = line
        cameraHint = hint
    }

    private func setCameraOK() {
        setCameraState(.ok, "Running (\(camera.formatInfo))", nil)
    }

    private func setCamera(_ error: Error) {
        let (line, hint) = CameraDiagnosis.make(error)
        setCameraState(.error, line, hint)
    }

    // MARK: loop

    private func runLoop() async {
        var connected = false
        var networkFailures = 0
        var lastDiscovery = Date.distantPast
        while !Task.isCancelled {
            updateThermal()
            if ProcessInfo.processInfo.thermalState == .critical {
                status = "Phone too hot - paused"
                camera.stop()
                try? await Task.sleep(nanoseconds: 10_000_000_000)
                await startCamera()
                continue
            }
            let base: URL
            do {
                base = try EdgeClient.baseURL(edgeURL)
            } catch {
                await reportEdge(error, base: nil, token: "")
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                continue
            }
            let tok = EdgeClient.normalizedToken(token)
            let target = EdgeClient.hostPort(base)
            do {
                if connected {
                    status = "Waiting for attempt (long-poll \(target))"
                } else {
                    status = "Connecting to \(target)"
                    if edgeHealth != .error { setEdgeState(.working, "Connecting to \(target)...", nil) }
                }
                // Short first request so a wrong IP / port / token shows within seconds; then long-poll
                // (the edge holds the request until an attempt needs depth).
                let longPoll = connected
                let started = Date()
                let job = try await client.pollPending(base: base, token: tok, waitS: longPoll ? Self.longPollS : 0,
                                                       timeout: longPoll ? nil : Self.connectTimeoutS)
                connected = true
                networkFailures = 0
                markConnected(target)
                if let job {
                    try await handle(job, base: base, token: tok)
                } else if longPoll, Date().timeIntervalSince(started) < 1.0 {
                    // A server that answers a long-poll at once (ignoring wait_s) must not make us spin.
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                }
            } catch {
                if Task.isCancelled { break }
                connected = false
                await reportEdge(error, base: base, token: tok)
                if error is URLError {
                    networkFailures += 1
                    if networkFailures >= 2, Date().timeIntervalSince(lastDiscovery) > 30 {
                        lastDiscovery = Date()
                        // Automatic: only this iPhone's own hotspot subnet (devices the operator connected), so
                        // an impostor on venue Wi-Fi answering like the edge can never receive the token.
                        if let found = await discover(ports: candidatePorts(), auto: true, hotspotOnly: true),
                           found != target {
                            continue  // edge found at another address/port: retry there at once
                        }
                    }
                }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private func handle(_ job: PendingJob, base: URL, token: String) async throws {
        lastAttempt = job.attempt_id
        lastPhase = job.phase
        let received = Date().timeIntervalSince1970 * 1000.0
        // Skip only clearly stale jobs: phone and Mac clocks may differ; the edge enforces validity.
        if let d = job.deadline_ms, d > 1e12, received > d + 5000 {
            status = "Skipped expired attempt \(job.attempt_id)"
            return
        }
        let challenge = job.phase.uppercased() == "CHALLENGE"
        let edgeTimed = job.delay_ms != nil || job.interval_ms != nil
        let delay = job.delay_ms ?? (challenge && !edgeTimed ? ProbeModel.challengeDefaultDelayMs : 0)
        let interval = job.interval_ms ?? (challenge && !edgeTimed ? ProbeModel.challengeDefaultIntervalMs : 0)
        if !camera.isRunning || cameraIsInterrupted { await startCamera() }
        guard camera.isRunning, !cameraIsInterrupted else {
            // The edge times out (latency_budget_ms.depth_max_wait) and uses depth NOT_AVAILABLE.
            status = "Skipped \(job.attempt_id): camera unavailable"
            lastUpload = "Skipped: \(cameraLine)"
            return
        }
        if delay > 0 {
            try await Task.sleep(nanoseconds: UInt64(min(delay, 3000) * 1_000_000))
        }
        let frames = max(1, min(job.frames ?? 1, 3))
        status = "Capturing \(job.phase) x\(frames)"
        let timeout = max(2.5, interval * Double(frames - 1) / 1000.0 + 1.5)
        let res: CaptureResult
        do {
            res = try await camera.capture(frames: frames, intervalMs: interval, wantRGB: sendRGB,
                                           perFrameFaces: challenge, timeout: timeout)
        } catch {
            setCamera(error)
            status = "Skipped \(job.attempt_id): capture failed"
            lastUpload = "Skipped: \(cameraLine)"
            return
        }
        setCameraOK()
        show(res)
        let meta = buildMeta(job: job, res: res, receivedMs: received)
        status = "Uploading \(job.attempt_id)"
        let t0 = CACurrentMediaTime()
        do {
            let (code, reply) = try await client.uploadFrames(base: base, token: token, meta: meta,
                                                              depthFrames: res.depthFrames, rgbJPEG: res.rgbJPEG)
            lastUploadMs = Int((CACurrentMediaTime() - t0) * 1000.0)
            attemptsSent += 1
            lastEdgeReply = EdgeReply.summary(code: code, json: reply)
            lastUpload = "OK: \(lastEdgeReply)"
            status = "Sent \(job.attempt_id) (\(job.phase))"
        } catch let e as EdgeError {
            // The edge answered but refused this upload (nonce, closed attempt, validation): keep polling.
            lastUploadMs = Int((CACurrentMediaTime() - t0) * 1000.0)
            let d = await EdgeDiagnosis.make(e, base: base, tokenEmpty: token.isEmpty)
            lastEdgeReply = d.raw
            lastUpload = "Rejected: \(d.headline)"
            status = "Upload rejected: \(d.headline)"
            lastError = "\(d.headline). \(d.hint)"
        }
        // URLError (network) propagates: the loop reports it as a connection problem.
    }

    private func buildMeta(job: PendingJob, res: CaptureResult, receivedMs: Double) -> [String: Any] {
        var meta: [String: Any] = [
            "attempt_id": job.attempt_id,
            "phase": job.phase,
            "depth_type": res.depthType,
            "dtype": res.dtype,
            "width": res.width,
            "height": res.height,
            "intrinsics": res.intrinsics,
            "timestamps_ms": res.timestampsMs.map { $0.rounded() },
            "device": DeviceInfo.modelIdentifier,
            "depth_nonce": job.depth_nonce ?? NSNull(),
            "accuracy": res.accuracy,  // edge DepthFramesMeta.accuracy (absolute | relative)
            // extra (optional) fields, ignored by consumers that do not know them
            "depth_accuracy": res.accuracy,
            "depth_filtered": res.filtered,
            "depth_quality": res.quality,
            "intrinsics_source": res.intrinsicsSource,
            "video_width": res.videoWidth,
            "video_height": res.videoHeight,
            "capture_ms": Int(res.captureMs.rounded()),
            "received_ms": receivedMs.rounded(),
            "valid_ratio_device": (res.validRatio * 1000).rounded() / 1000,
            "app_version": ProbeModel.appVersion,
            "os": "iOS \(UIDevice.current.systemVersion)",
        ]
        if job.phase.uppercased() == "CHALLENGE" {
            meta["face_box_norm_frames"] = res.faces.map { ($0?.boxNorm as Any?) ?? NSNull() }
            meta["landmarks_norm_frames"] = res.faces.map { ($0?.landmarks as Any?) ?? NSNull() }
        }
        if let face = res.face {
            meta["face_box_norm"] = face.boxNorm
            meta["landmarks_norm"] = face.landmarks ?? NSNull()
            meta["vision_orientation"] = Int(face.orientation.rawValue)
        } else {
            meta["face_box_norm"] = NSNull()
            meta["landmarks_norm"] = NSNull()
        }
        return meta
    }

    // MARK: status

    private func setEdgeState(_ h: Health, _ line: String, _ hint: String?) {
        edgeHealth = h
        edgeLine = line
        edgeHint = hint
        if h != .error { edgeRaw = nil }
    }

    private func markConnected(_ target: String) {
        lastOKPoll = Date()
        pollsOK += 1
        setEdgeState(.ok, "Connected to \(target) - token OK", nil)
        lastError = nil
    }

    private func reportEdge(_ error: Error, base: URL?, token: String) async {
        let d = await EdgeDiagnosis.make(error, base: base, tokenEmpty: token.isEmpty)
        setEdgeState(.error, d.headline, d.hint)
        edgeRaw = d.raw
        status = "Error: \(d.headline)"
        lastError = "\(d.headline). \(d.hint)"
    }

    private func show(_ res: CaptureResult) {
        lastCaptureMs = Int(res.captureMs.rounded())
        lastValidRatio = res.validRatio
        lastDistanceCm = res.medianDistanceM.map { $0 * 100 }
        lastDepthInfo = "\(res.depthType) \(res.dtype) \(res.width)x\(res.height) \(res.accuracy) "
            + "filtered=\(res.filtered) K=\(res.intrinsicsSource) frames=\(res.depthFrames.count)"
        if let face = res.face {
            let lm = face.landmarks.map { "\($0.count) landmarks" } ?? "no landmarks"
            lastFaceInfo = String(format: "face %.2f, %@, orient %d", face.confidence, lm, face.orientation.rawValue)
        } else {
            lastFaceInfo = "no face found"
        }
    }

    private func updateThermal() {
        switch ProcessInfo.processInfo.thermalState {
        case .nominal: thermal = "nominal"
        case .fair: thermal = "fair"
        case .serious: thermal = "serious"
        case .critical: thermal = "critical"
        @unknown default: thermal = "?"
        }
    }
}

enum EdgeReply {
    static func summary(code: Int, json: [String: Any]?) -> String {
        guard let json = json else { return "HTTP \(code)" }
        let signal = (json["checks"] as? [String: Any]) ?? (json["signal"] as? [String: Any]) ?? json
        var parts = ["HTTP \(code)"]
        for key in ["d0_valid_ratio", "d1_plane_rms_mm", "d2_quad_rms_mm", "d3_nose_relief_mm"] {
            if let v = signal[key] as? Double { parts.append("\(key.split(separator: "_").first ?? "")=\(String(format: "%.2f", v))") }
        }
        if let overall = json["overall"] as? String { parts.append(overall) }
        return parts.joined(separator: " ")
    }
}

enum DeviceInfo {
    static let modelIdentifier: String = {
        var info = utsname()
        uname(&info)
        let mirror = Mirror(reflecting: info.machine)
        let chars = mirror.children.compactMap { $0.value as? Int8 }.filter { $0 != 0 }
        return String(decoding: chars.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }()
}
