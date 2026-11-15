import AVFoundation
import Darwin
import Foundation
import Network

/// Cause + fix for anything that stops the phone talking to the edge. Shown at the top of the screen so
/// the operator can read it out; `raw` is the exact system error (domain, code, text).
struct EdgeDiagnosis {
    let headline: String
    let hint: String
    let raw: String

    static func make(_ error: Error, base: URL?, tokenEmpty: Bool) async -> EdgeDiagnosis {
        let target = base.map(EdgeClient.hostPort) ?? "the edge"
        let raw = rawText(error)
        if let e = error as? EdgeError {
            switch e {
            case .badURL(let s):
                return EdgeDiagnosis(headline: "Edge URL is not valid",
                                     hint: "Enter http://<Mac IP>:\(EdgeDefaults.lanPort), e.g. \(EdgeDefaults.edgeURL) (got \"\(s)\").",
                                     raw: raw)
            case .http(let code, let body):
                return http(code, message: EdgeError.message(from: body), tokenEmpty: tokenEmpty, raw: raw)
            }
        }
        guard let u = error as? URLError else {
            return EdgeDiagnosis(headline: "Error", hint: error.localizedDescription, raw: raw)
        }
        if pathSaysLocalNetworkDenied(u) { return localNetworkDenied(raw) }
        let maybeLocalNetwork: [URLError.Code] = [.notConnectedToInternet, .timedOut, .dataNotAllowed]
        if maybeLocalNetwork.contains(u.code), let base, let host = base.host,
           await LocalNetworkCheck.isDenied(host: host, port: base.port ?? EdgeDefaults.lanPort) {
            return localNetworkDenied(raw)
        }
        switch u.code {
        case .timedOut:
            return EdgeDiagnosis(
                headline: "No reply from \(target) (timed out)",
                hint: "Wrong Mac IP, or phone and Mac are on different networks. On the iPhone hotspot the Mac is 172.20.10.x; "
                    + "on Wi-Fi run 'ipconfig getifaddr en0' on the Mac. Venue Wi-Fi often blocks device-to-device "
                    + "traffic: use the iPhone hotspot. Or tap Find Mac.",
                raw: raw)
        case .cannotConnectToHost:
            return EdgeDiagnosis(
                headline: "\(target) refused the connection",
                hint: "That address answers but nothing listens on the port. Use port \(EdgeDefaults.lanPort) (EDGE_LAN_PORT), "
                    + "not 8000 (localhost only). Is the edge running? /v1/health must show lan_listener "
                    + "'listening 0.0.0.0:8001'.",
                raw: raw)
        case .cannotFindHost, .dnsLookupFailed:
            return EdgeDiagnosis(headline: "Cannot resolve \(target)",
                                 hint: "Use the Mac's numeric IP address, e.g. \(EdgeDefaults.edgeURL).", raw: raw)
        case .notConnectedToInternet, .dataNotAllowed, .internationalRoamingOff:
            return EdgeDiagnosis(
                headline: "No network path to \(target)",
                hint: "Join the same Wi-Fi as the Mac, or keep Personal Hotspot on with the Mac connected. Also check "
                    + "Settings > Privacy & Security > Local Network > DepthProbe.",
                raw: raw)
        case .networkConnectionLost:
            return EdgeDiagnosis(headline: "Connection to \(target) dropped",
                                 hint: "Edge restarting or Mac asleep; retrying automatically.", raw: raw)
        case .appTransportSecurityRequiresSecureConnection:
            return EdgeDiagnosis(
                headline: "Blocked by App Transport Security (http)",
                hint: "Use http://<numeric Mac IP>:\(EdgeDefaults.lanPort). This build allows local http "
                    + "(NSAllowsLocalNetworking); if this persists, reinstall the latest DepthProbe.",
                raw: raw)
        case .secureConnectionFailed, .serverCertificateUntrusted, .serverCertificateHasBadDate,
             .serverCertificateNotYetValid, .serverCertificateHasUnknownRoot, .clientCertificateRejected:
            return EdgeDiagnosis(headline: "TLS failed to \(target)",
                                 hint: "Use http:// - the edge LAN listener is plain HTTP.", raw: raw)
        default:
            return EdgeDiagnosis(headline: "Network error \(u.code.rawValue)", hint: u.localizedDescription, raw: raw)
        }
    }

    static func http(_ code: Int, message: String, tokenEmpty: Bool, raw: String) -> EdgeDiagnosis {
        switch code {
        case 401 where tokenEmpty:
            return EdgeDiagnosis(
                headline: "Token missing (HTTP 401)",
                hint: "Enter DEPTH_DEVICE_TOKEN from the Mac's .env. Easiest: on the Mac run depth/ios/pair.sh and scan "
                    + "the QR with the iPhone Camera app.",
                raw: raw)
        case 401:
            return EdgeDiagnosis(
                headline: "Token rejected (HTTP 401)",
                hint: "The token differs from DEPTH_DEVICE_TOKEN in the Mac's .env (no quotes, no spaces): re-scan the "
                    + "pair.sh QR. The edge reads .env at start, so restart it after editing .env; with no token in "
                    + ".env it rejects every phone.",
                raw: raw)
        case 403:
            return EdgeDiagnosis(headline: "Edge refused (HTTP 403)", hint: message, raw: raw)
        case 404:
            return EdgeDiagnosis(
                headline: "Not the depth listener (HTTP 404)",
                hint: "Use http://<Mac IP>:\(EdgeDefaults.lanPort) with no path; that port serves only /v1/depth/*.",
                raw: raw)
        case 409:
            return EdgeDiagnosis(headline: "Edge refused (HTTP 409)", hint: message, raw: raw)
        case 422:
            return EdgeDiagnosis(headline: "Edge rejected the request (HTTP 422)", hint: message, raw: raw)
        case 500...599:
            return EdgeDiagnosis(headline: "Edge internal error (HTTP \(code))",
                                 hint: "See the edge console on the Mac. \(message)", raw: raw)
        default:
            return EdgeDiagnosis(headline: "Unexpected reply (HTTP \(code))", hint: message, raw: raw)
        }
    }

    static func localNetworkDenied(_ raw: String) -> EdgeDiagnosis {
        EdgeDiagnosis(
            headline: "Local Network access is OFF for DepthProbe",
            hint: "iPhone Settings > Privacy & Security > Local Network > DepthProbe ON, then come back to the app "
                + "(it retries by itself).",
            raw: raw)
    }

    static func rawText(_ error: Error) -> String {
        let ns = error as NSError
        return "\(ns.domain) \(ns.code): \(ns.localizedDescription)"
    }

    /// URLSession puts the failing network path in userInfo; iOS names Local Network denial there.
    static func pathSaysLocalNetworkDenied(_ error: URLError) -> Bool {
        let ns = error as NSError
        var texts = ns.userInfo.values.map { String(describing: $0) }
        if let under = ns.userInfo[NSUnderlyingErrorKey] as? NSError {
            texts += under.userInfo.values.map { String(describing: $0) }
        }
        return texts.contains {
            $0.localizedCaseInsensitiveContains("local network prohibited")
                || $0.localizedCaseInsensitiveContains("localNetworkDenied")
        }
    }
}

enum CameraDiagnosis {
    static func make(_ error: Error) -> (String, String) {
        guard let c = error as? CaptureError else { return ("Camera error", error.localizedDescription) }
        switch c {
        case .notAuthorized:
            return ("Camera permission denied",
                    "iPhone Settings > Apps > DepthProbe > Camera ON (iOS restarts the app).")
        case .noTrueDepth:
            return ("No front TrueDepth camera",
                    "Run DepthProbe on the iPhone 16 Pro Max (the Simulator has no TrueDepth camera).")
        case .configuration(let m):
            return ("Camera setup failed: \(m)", "Close other camera apps, then tap Restart camera.")
        case .notRunning:
            return ("Camera not running", "Tap Restart camera and keep DepthProbe on screen.")
        case .busy:
            return ("Camera busy with another capture", "Wait a second; the next attempt retries.")
        case .timeout:
            return ("No depth frames arrived",
                    "The camera is interrupted or held by another app: close Camera/FaceTime, and do not use this "
                        + "iPhone as the Mac's webcam (Continuity Camera) while DepthProbe runs.")
        }
    }

    static func interruption(_ raw: Int?) -> (String, String) {
        guard let raw, let reason = AVCaptureSession.InterruptionReason(rawValue: raw) else {
            return ("Camera interrupted", "Close other camera apps and return to DepthProbe.")
        }
        switch reason {
        case .videoDeviceNotAvailableInBackground:
            return ("Camera paused: app not on screen", "Keep DepthProbe open in the foreground.")
        case .videoDeviceInUseByAnotherClient:
            return ("Camera in use by another app",
                    "Close Camera/FaceTime, and stop using this iPhone as the Mac's webcam (Continuity Camera): "
                        + "the two cannot run at the same time.")
        case .videoDeviceNotAvailableWithMultipleForegroundApps:
            return ("Camera blocked by multitasking", "Use DepthProbe full screen (no Picture in Picture).")
        case .videoDeviceNotAvailableDueToSystemPressure:
            return ("Camera stopped: phone too hot", "Let the phone cool down; keep it out of the sun, on power.")
        case .audioDeviceInUseByAnotherClient:
            return ("Camera interrupted (audio in use)", "Close the other app and return to DepthProbe.")
        case .sensitiveContentMitigationActivated:
            return ("Camera paused by iOS (sensitive content)", "Return to DepthProbe; it resumes by itself.")
        @unknown default:
            return ("Camera interrupted (reason \(raw))", "Close other camera apps and return to DepthProbe.")
        }
    }
}

/// Asks the Network framework whether iOS blocks the path to host:port because Local Network access is
/// denied for this app (opens a TCP connection and cancels it at once).
enum LocalNetworkCheck {
    static func isDenied(host: String, port: Int, timeout: TimeInterval = 1.5) async -> Bool {
        guard let p = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return false }
        return await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            let queue = DispatchQueue(label: "depthprobe.localnet")
            let conn = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
            let once = OneShot(conn, cont)
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready: once.finish(false)
                case .waiting, .failed: once.finish(once.deniedNow)
                default: break
                }
            }
            conn.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) { once.finish(once.deniedNow) }
        }
    }

    /// Resumes the continuation exactly once; only ever used on one serial queue.
    private final class OneShot: @unchecked Sendable {
        private var done = false
        private let conn: NWConnection
        private let cont: CheckedContinuation<Bool, Never>

        init(_ conn: NWConnection, _ cont: CheckedContinuation<Bool, Never>) {
            self.conn = conn
            self.cont = cont
        }

        var deniedNow: Bool { conn.currentPath?.unsatisfiedReason == .localNetworkDenied }

        func finish(_ denied: Bool) {
            guard !done else { return }
            done = true
            conn.cancel()
            cont.resume(returning: denied)
        }
    }
}

/// "Find Mac": probes every host on the phone's own private IPv4 subnets (iPhone hotspot first, at most
/// a /24 each) for the edge's depth listener. Probes carry no token (the edge answers 401).
enum EdgeDiscovery {
    struct Subnet {
        let name: String
        let address: UInt32
        let mask: UInt32
    }

    /// Subnet-major (hotspot subnet first), then each candidate port, 64 probes in flight.
    static func find(client: EdgeClient, ports: [Int], hotspotOnly: Bool = false) async -> (host: String, port: Int)? {
        var seen = Set<String>()
        for s in localSubnets() where !hotspotOnly || isHotspot(s.address) {
            let hosts = self.hosts(in: s).filter { seen.insert($0).inserted }
            for port in ports {
                var index = 0
                while index < hosts.count {
                    if Task.isCancelled { return nil }
                    let batch = Array(hosts[index..<min(index + 64, hosts.count)])
                    index += batch.count
                    let hit: String? = await withTaskGroup(of: String?.self) { group in
                        for h in batch {
                            group.addTask {
                                guard let url = URL(string: "http://\(h):\(port)") else { return nil }
                                return await client.looksLikeEdge(url) ? h : nil
                            }
                        }
                        for await r in group where r != nil {
                            group.cancelAll()
                            return r
                        }
                        return nil
                    }
                    if let hit { return (hit, port) }
                }
            }
        }
        return nil
    }

    static func localSubnets() -> [Subnet] {
        var out: [Subnet] = []
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cursor {
            cursor = ifa.pointee.ifa_next
            let flags = Int32(bitPattern: ifa.pointee.ifa_flags)
            guard let sa = ifa.pointee.ifa_addr, let nm = ifa.pointee.ifa_netmask,
                  sa.pointee.sa_family == sa_family_t(AF_INET),
                  flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0 else { continue }
            let name = String(cString: ifa.pointee.ifa_name)
            if ["pdp_ip", "utun", "ipsec", "awdl", "llw"].contains(where: { name.hasPrefix($0) }) { continue }
            let addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            let mask = nm.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            guard isPrivate(addr) else { continue }
            out.append(Subnet(name: name, address: addr, mask: mask))
        }
        return out.sorted { isHotspot($0.address) && !isHotspot($1.address) }
    }

    /// At most the /24 around the phone's address. The phone's own address is kept: it only matters in the
    /// Simulator, where the "phone" is the Mac itself.
    static func hosts(in s: Subnet) -> [String] {
        let mask = max(s.mask, 0xFFFF_FF00)
        let net = s.address & mask
        let last = net | ~mask
        guard last > net + 1 else { return [] }
        return (net + 1 ..< last).map(ipString)
    }

    static func isPrivate(_ a: UInt32) -> Bool {
        (a & 0xFF00_0000) == 0x0A00_0000 || (a & 0xFFF0_0000) == 0xAC10_0000 || (a & 0xFFFF_0000) == 0xC0A8_0000
    }

    static func isHotspot(_ a: UInt32) -> Bool { (a & 0xFFFF_FFF0) == 0xAC14_0A00 }  // 172.20.10.0/28

    static func ipString(_ a: UInt32) -> String {
        "\(a >> 24 & 0xFF).\(a >> 16 & 0xFF).\(a >> 8 & 0xFF).\(a & 0xFF)"
    }
}
