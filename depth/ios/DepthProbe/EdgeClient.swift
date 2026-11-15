import Foundation

/// GET /v1/depth/pending response (200). Unknown extra fields are ignored.
struct PendingJob: Decodable {
    let attempt_id: String
    let phase: String            // "PASSIVE" | "CHALLENGE"
    let frames: Int?             // 1-3
    let deadline_ms: Double?     // epoch ms deadline (values < 1e12 are treated as a relative window)
    let delay_ms: Double?        // optional: wait before capturing (e.g. challenge peak)
    let interval_ms: Double?     // optional: spacing between frames
    let depth_nonce: String?     // per-attempt nonce; echoed in the upload meta (edge answers 403 if missing)
}

enum EdgeDefaults {
    /// Port of the edge's LAN listener (EDGE_LAN_PORT in the Mac's .env). The kiosk API on :8000 binds
    /// 127.0.0.1 only, so the phone can never reach it.
    static let lanPort = 8001
    /// The Mac on the iPhone Personal Hotspot (USB) on 14 Nov. "Find Mac" or the pairing QR
    /// (depth/ios/pair.sh) fix it when the address changes.
    static let edgeURL = "http://172.20.10.3:8001"
    /// Pairing link: depthprobe://config?url=<edge URL>&token=<DEPTH_DEVICE_TOKEN>
    static let configScheme = "depthprobe"
}

enum EdgeError: LocalizedError {
    case badURL(String)
    case http(Int, String)

    var errorDescription: String? {
        switch self {
        case .badURL(let s): return "Invalid edge URL: \(s)"
        case .http(let code, let body): return "Edge HTTP \(code): \(EdgeError.message(from: body))"
        }
    }

    /// "CODE: message" from the edge's JSON error body ({"error": {"code", "message"}}), else the raw body.
    static func message(from body: String) -> String {
        if let obj = (try? JSONSerialization.jsonObject(with: Data(body.utf8))) as? [String: Any],
           let err = obj["error"] as? [String: Any], let msg = err["message"] as? String {
            if let code = err["code"] as? String { return "\(code): \(msg)" }
            return msg
        }
        let trimmed = body.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "(empty body)" : String(trimmed.prefix(160))
    }
}

/// Talks to the edge service: long-poll for a pending attempt, upload depth frames (multipart).
/// Never streams video: at most 3 depth frames + 1 JPEG per attempt.
final class EdgeClient: @unchecked Sendable {  // immutable after init
    private let session: URLSession
    private let probeSession: URLSession

    init() {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 40
        config.waitsForConnectivity = false
        config.httpMaximumConnectionsPerHost = 2
        session = URLSession(configuration: config)
        let probe = URLSessionConfiguration.ephemeral
        probe.timeoutIntervalForRequest = 1.5
        probe.timeoutIntervalForResource = 2.5
        probe.waitsForConnectivity = false
        probeSession = URLSession(configuration: probe)
    }

    /// Normalise what the operator typed: adds http://, the LAN port 8001 if none, drops any path.
    static func baseURL(_ text: String) throws -> URL {
        var s = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { throw EdgeError.badURL("(empty)") }
        if !s.lowercased().hasPrefix("http://") && !s.lowercased().hasPrefix("https://") { s = "http://" + s }
        guard var comps = URLComponents(string: s), let host = comps.host, !host.isEmpty else {
            throw EdgeError.badURL(text)
        }
        if comps.port == nil { comps.port = EdgeDefaults.lanPort }
        comps.path = ""
        comps.query = nil
        comps.fragment = nil
        guard let url = comps.url else { throw EdgeError.badURL(text) }
        return url
    }

    static func hostPort(_ base: URL) -> String {
        "\(base.host ?? "?"):\(base.port ?? EdgeDefaults.lanPort)"
    }

    /// The token exactly as the edge holds it. The edge parses .env like this (edge/config.py): surrounding
    /// quotes are dropped, an unquoted value loses a " # comment" tail, whitespace is trimmed. Pasting
    /// `DEPTH_DEVICE_TOKEN="abc"` or `abc ` (trailing newline) therefore still matches.
    static func normalizedToken(_ raw: String) -> String {
        var t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.hasPrefix("DEPTH_DEVICE_TOKEN=") { t = String(t.dropFirst("DEPTH_DEVICE_TOKEN=".count)) }
        t = t.trimmingCharacters(in: .whitespaces)
        if let q = t.first, q == "\"" || q == "'" {
            let rest = t.dropFirst()
            return String(rest[..<(rest.firstIndex(of: q) ?? rest.endIndex)])
        }
        if t.hasPrefix("#") { return "" }
        if let r = t.range(of: #"\s+#.*$"#, options: .regularExpression) { t.removeSubrange(r) }
        return t.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// GET /v1/depth/pending. nil = 204 (nothing to capture). `timeout` defaults to wait_s + 10 s.
    func pollPending(base: URL, token: String, waitS: Int, timeout: TimeInterval? = nil) async throws -> PendingJob? {
        let req = try pendingRequest(base: base, token: token, waitS: waitS,
                                     timeout: timeout ?? TimeInterval(waitS + 10))
        let (data, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
        switch code {
        case 204: return nil
        case 200: return try JSONDecoder().decode(PendingJob.self, from: data)
        default: throw EdgeError.http(code, String(decoding: data, as: UTF8.self))
        }
    }

    /// Discovery probe WITHOUT the token: the edge's depth listener answers 401 "depth device token
    /// required", so no attempt is claimed and nothing changes on the edge.
    func looksLikeEdge(_ base: URL) async -> Bool {
        guard let req = try? pendingRequest(base: base, token: "", waitS: 0, timeout: 1.5),
              let result = try? await probeSession.data(for: req),
              let code = (result.1 as? HTTPURLResponse)?.statusCode else { return false }
        return code == 401 && String(decoding: result.0, as: UTF8.self).contains("depth device token")
    }

    private func pendingRequest(base: URL, token: String, waitS: Int, timeout: TimeInterval) throws -> URLRequest {
        guard var comps = URLComponents(url: base.appendingPathComponent("v1/depth/pending"),
                                        resolvingAgainstBaseURL: false) else { throw EdgeError.badURL(base.absoluteString) }
        comps.queryItems = [URLQueryItem(name: "wait_s", value: String(waitS))]
        guard let url = comps.url else { throw EdgeError.badURL(base.absoluteString) }
        var req = URLRequest(url: url)
        req.timeoutInterval = timeout
        if !token.isEmpty { req.setValue(token, forHTTPHeaderField: "X-Depth-Token") }
        return req
    }

    /// POST /v1/depth/frames. Parts: `meta` (JSON text field), `depth_0..depth_2` (octet-stream
    /// files), optional `rgb_0` (image/jpeg file). Returns (HTTP status, parsed JSON reply or nil).
    func uploadFrames(base: URL, token: String, meta: [String: Any], depthFrames: [Data],
                      rgbJPEG: Data?) async throws -> (Int, [String: Any]?) {
        let boundary = "DepthProbe-\(UUID().uuidString)"
        var body = Data()
        func add(_ s: String) { body.append(Data(s.utf8)) }
        add("--\(boundary)\r\nContent-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n")
        body.append(try JSONSerialization.data(withJSONObject: meta, options: [.sortedKeys]))
        add("\r\n")
        for (i, frame) in depthFrames.enumerated() {
            add("--\(boundary)\r\nContent-Disposition: form-data; name=\"depth_\(i)\"; filename=\"depth_\(i).bin\"\r\n")
            add("Content-Type: application/octet-stream\r\n\r\n")
            body.append(frame)
            add("\r\n")
        }
        if let jpeg = rgbJPEG {
            add("--\(boundary)\r\nContent-Disposition: form-data; name=\"rgb_0\"; filename=\"rgb_0.jpg\"\r\n")
            add("Content-Type: image/jpeg\r\n\r\n")
            body.append(jpeg)
            add("\r\n")
        }
        add("--\(boundary)--\r\n")

        var req = URLRequest(url: base.appendingPathComponent("v1/depth/frames"))
        req.httpMethod = "POST"
        req.timeoutInterval = 10
        req.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        if !token.isEmpty { req.setValue(token, forHTTPHeaderField: "X-Depth-Token") }
        let (data, resp) = try await session.upload(for: req, from: body)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        if !(200..<300).contains(code) { throw EdgeError.http(code, String(decoding: data, as: UTF8.self)) }
        return (code, json)
    }
}
