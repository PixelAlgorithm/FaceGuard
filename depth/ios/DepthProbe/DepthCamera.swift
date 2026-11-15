import AVFoundation
import CoreImage
import QuartzCore
import UIKit

/// One attempt's worth of synchronised TrueDepth frames, ready to upload.
struct CaptureResult {
    var depthFrames: [Data] = []          // raw little-endian row-major float16/float32
    var timestampsMs: [Double] = []       // epoch ms per frame (phone clock)
    var width = 0
    var height = 0
    var depthType = "depth"               // "depth" (metres) | "disparity" (1/m)
    var dtype = "float16"                 // "float16" | "float32"
    var accuracy = "relative"             // AVDepthData.depthDataAccuracy
    var filtered = false
    var quality = "low"
    var intrinsics: [String: Double] = [:]
    var intrinsicsSource = "calibration"  // "calibration" | "fov"
    var face: FaceResult?                 // frame 0
    var faces: [FaceResult?] = []         // per frame (CHALLENGE: Vision runs on every frame)
    var rgbJPEG: Data?
    var videoWidth = 0
    var videoHeight = 0
    var validRatio = 0.0                  // on-device D0-like stat (face box if found, else full frame)
    var medianDistanceM: Double?
    var captureMs = 0.0
}

enum CaptureError: LocalizedError {
    case notAuthorized, noTrueDepth, configuration(String), notRunning, busy, timeout

    var errorDescription: String? {
        switch self {
        case .notAuthorized: return "Camera access denied (Settings > DepthProbe > Camera)"
        case .noTrueDepth: return "No front TrueDepth camera on this device"
        case .configuration(let m): return "Camera configuration failed: \(m)"
        case .notRunning: return "Camera session is not running"
        case .busy: return "A capture is already in progress"
        case .timeout: return "Timed out waiting for synchronised depth frames"
        }
    }
}

/// Front TrueDepth capture: video (BGRA) + depth (unfiltered) through AVCaptureDataOutputSynchronizer.
/// Frames are only copied while a capture request is pending; otherwise the delegate returns at once.
/// Based on Apple's "Streaming depth data from the TrueDepth camera" sample (no code copied).
final class DepthCamera: NSObject, AVCaptureDataOutputSynchronizerDelegate, @unchecked Sendable {
    let session = AVCaptureSession()
    private let sessionQueue = DispatchQueue(label: "depthprobe.session")
    private let dataQueue = DispatchQueue(label: "depthprobe.data", qos: .userInitiated)
    private let videoOutput = AVCaptureVideoDataOutput()
    private let depthOutput = AVCaptureDepthDataOutput()
    private var synchronizer: AVCaptureDataOutputSynchronizer?
    private var device: AVCaptureDevice?
    private var configuredWidth = 0
    private let faceLocator = FaceLocator()
    private let ciContext = CIContext()
    private(set) var formatInfo = "-"

    private struct Request {
        let token: UUID
        let frames: Int
        let intervalMs: Double
        let wantRGB: Bool
        let perFrameFaces: Bool
        let started: CFTimeInterval
        var result: CaptureResult?
        var lastPTS: Double = -1
        let completion: (Result<CaptureResult, Error>) -> Void
    }
    private var request: Request?  // only touched on dataQueue

    // MARK: session lifecycle

    func start(preferredDepthWidth: Int) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            sessionQueue.async {
                do {
                    if self.configuredWidth != preferredDepthWidth {
                        if self.session.isRunning { self.session.stopRunning() }
                        try self.configure(preferredDepthWidth: preferredDepthWidth)
                        self.configuredWidth = preferredDepthWidth
                    }
                    if !self.session.isRunning { self.session.startRunning() }
                    cont.resume()
                } catch {
                    cont.resume(throwing: error)
                }
            }
        }
    }

    func stop() {
        sessionQueue.async {
            if self.session.isRunning { self.session.stopRunning() }
        }
    }

    var isRunning: Bool { session.isRunning }

    private func configure(preferredDepthWidth: Int) throws {
        guard let dev = AVCaptureDevice.default(.builtInTrueDepthCamera, for: .video, position: .front) else {
            throw CaptureError.noTrueDepth
        }
        device = dev
        session.beginConfiguration()
        defer { session.commitConfiguration() }
        session.inputs.forEach { session.removeInput($0) }
        session.outputs.forEach { session.removeOutput($0) }
        session.sessionPreset = .vga640x480

        let input = try AVCaptureDeviceInput(device: dev)
        guard session.canAddInput(input) else { throw CaptureError.configuration("cannot add TrueDepth input") }
        session.addInput(input)

        guard session.canAddOutput(videoOutput) else { throw CaptureError.configuration("cannot add video output") }
        session.addOutput(videoOutput)
        videoOutput.videoSettings = [kCVPixelBufferPixelFormatTypeKey as String: Int(kCVPixelFormatType_32BGRA)]
        videoOutput.alwaysDiscardsLateVideoFrames = true

        guard session.canAddOutput(depthOutput) else { throw CaptureError.configuration("cannot add depth output") }
        session.addOutput(depthOutput)
        depthOutput.isFilteringEnabled = false          // raw depth: holes stay holes (NaN)
        depthOutput.alwaysDiscardsLateDepthData = true
        depthOutput.connection(with: .depthData)?.isEnabled = true

        // Keep both streams in the native sensor orientation, unmirrored, so face coordinates
        // computed on the video buffer index the depth map directly.
        for conn in [videoOutput.connection(with: .video), depthOutput.connection(with: .depthData)] {
            if let conn = conn, conn.isVideoMirroringSupported {
                conn.automaticallyAdjustsVideoMirroring = false
                conn.isVideoMirrored = false
            }
        }

        func subtype(_ f: AVCaptureDevice.Format) -> FourCharCode { CMFormatDescriptionGetMediaSubType(f.formatDescription) }
        func width(_ f: AVCaptureDevice.Format) -> Int { Int(CMVideoFormatDescriptionGetDimensions(f.formatDescription).width) }
        var formats = dev.activeFormat.supportedDepthDataFormats
        if formats.isEmpty,  // preset format without depth: pick the depth-capable video format closest to VGA
           let alt = dev.formats.filter({ !$0.supportedDepthDataFormats.isEmpty })
               .min(by: { abs(width($0) - 640) < abs(width($1) - 640) }) {
            session.sessionPreset = .inputPriority
            try dev.lockForConfiguration()
            dev.activeFormat = alt
            dev.unlockForConfiguration()
            formats = alt.supportedDepthDataFormats
        }
        let preference: [FourCharCode] = [kCVPixelFormatType_DepthFloat16, kCVPixelFormatType_DisparityFloat16,
                                         kCVPixelFormatType_DepthFloat32, kCVPixelFormatType_DisparityFloat32]
        var chosen: AVCaptureDevice.Format?
        for type in preference {
            let candidates = formats.filter { subtype($0) == type }
            if let best = candidates.min(by: { abs(width($0) - preferredDepthWidth) < abs(width($1) - preferredDepthWidth) }) {
                chosen = best
                break
            }
        }
        guard let format = chosen else { throw CaptureError.configuration("active video format has no depth formats") }
        try dev.lockForConfiguration()
        dev.activeDepthDataFormat = format
        dev.unlockForConfiguration()
        let dims = CMVideoFormatDescriptionGetDimensions(format.formatDescription)
        formatInfo = "\(DepthCamera.fourCC(subtype(format))) \(dims.width)x\(dims.height)"

        let sync = AVCaptureDataOutputSynchronizer(dataOutputs: [videoOutput, depthOutput])
        sync.setDelegate(self, queue: dataQueue)
        synchronizer = sync
    }

    // MARK: capture

    func capture(frames: Int, intervalMs: Double, wantRGB: Bool, perFrameFaces: Bool = false,
                 timeout: TimeInterval) async throws -> CaptureResult {
        guard session.isRunning else { throw CaptureError.notRunning }
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<CaptureResult, Error>) in
            dataQueue.async {
                if self.request != nil {
                    cont.resume(throwing: CaptureError.busy)
                    return
                }
                let token = UUID()
                self.request = Request(token: token, frames: max(1, min(frames, 3)), intervalMs: max(0, intervalMs),
                                       wantRGB: wantRGB, perFrameFaces: perFrameFaces, started: CACurrentMediaTime(),
                                       completion: { cont.resume(with: $0) })
                self.dataQueue.asyncAfter(deadline: .now() + timeout) {
                    if let pending = self.request, pending.token == token {
                        self.request = nil
                        pending.completion(.failure(CaptureError.timeout))
                    }
                }
            }
        }
    }

    func dataOutputSynchronizer(_ synchronizer: AVCaptureDataOutputSynchronizer,
                                didOutput collection: AVCaptureSynchronizedDataCollection) {
        guard var req = request else { return }
        guard let syncedDepth = collection.synchronizedData(for: depthOutput) as? AVCaptureSynchronizedDepthData,
              let syncedVideo = collection.synchronizedData(for: videoOutput) as? AVCaptureSynchronizedSampleBufferData,
              !syncedDepth.depthDataWasDropped, !syncedVideo.sampleBufferWasDropped else { return }
        let pts = CMTimeGetSeconds(syncedDepth.timestamp)
        if req.intervalMs > 0, req.lastPTS >= 0, (pts - req.lastPTS) * 1000.0 < req.intervalMs { return }

        var depthData = syncedDepth.depthData
        if depthData.depthDataType == kCVPixelFormatType_DepthFloat32 {
            depthData = depthData.converting(toDepthDataType: kCVPixelFormatType_DepthFloat16)
        } else if depthData.depthDataType == kCVPixelFormatType_DisparityFloat32 {
            depthData = depthData.converting(toDepthDataType: kCVPixelFormatType_DisparityFloat16)
        }
        var (bytes, w, h, bpp) = DepthCamera.copyPixels(depthData.depthDataMap)
        // The 16 Pro Max offers only 640x480 depth on the VGA format: 3 frames = 1.8 MB, too slow for the
        // edge's latency_budget_ms.depth_max_wait. Halve it on the phone (NaN-aware 2x2 mean) when wider than
        // the requested width; intrinsics keep their reference dims (the edge rescales by width/ref_width).
        if configuredWidth > 0, w >= 2 * configuredWidth, bpp == 2 {
            (bytes, w, h) = DepthCamera.downsample2x(bytes, width: w, height: h)
        }

        if req.result == nil {
            guard let pixelBuffer = CMSampleBufferGetImageBuffer(syncedVideo.sampleBuffer) else { return }
            var res = CaptureResult()
            res.width = w
            res.height = h
            res.dtype = bpp == 4 ? "float32" : "float16"
            switch depthData.depthDataType {
            case kCVPixelFormatType_DisparityFloat16, kCVPixelFormatType_DisparityFloat32: res.depthType = "disparity"
            default: res.depthType = "depth"
            }
            res.accuracy = depthData.depthDataAccuracy == .absolute ? "absolute" : "relative"
            res.filtered = depthData.isDepthDataFiltered
            res.quality = depthData.depthDataQuality == .high ? "high" : "low"
            if let cal = depthData.cameraCalibrationData {
                let m = cal.intrinsicMatrix
                let ref = cal.intrinsicMatrixReferenceDimensions
                res.intrinsics = ["fx": Double(m.columns.0.x), "fy": Double(m.columns.1.y),
                                  "cx": Double(m.columns.2.x), "cy": Double(m.columns.2.y),
                                  "ref_width": Double(ref.width), "ref_height": Double(ref.height)]
                res.intrinsicsSource = "calibration"
            } else {
                let fov = Double(device?.activeFormat.videoFieldOfView ?? 70.0)
                let fx = Double(w) / 2.0 / tan(fov * Double.pi / 360.0)
                res.intrinsics = ["fx": fx, "fy": fx, "cx": Double(w - 1) / 2.0, "cy": Double(h - 1) / 2.0,
                                  "ref_width": Double(w), "ref_height": Double(h)]
                res.intrinsicsSource = "fov"
            }
            res.videoWidth = CVPixelBufferGetWidth(pixelBuffer)
            res.videoHeight = CVPixelBufferGetHeight(pixelBuffer)
            res.face = faceLocator.locate(pixelBuffer)
            res.faces = [res.face]
            if req.wantRGB {
                let image = CIImage(cvPixelBuffer: pixelBuffer)
                let quality = kCGImageDestinationLossyCompressionQuality as CIImageRepresentationOption
                res.rgbJPEG = ciContext.jpegRepresentation(of: image, colorSpace: CGColorSpace(name: CGColorSpace.sRGB)!,
                                                           options: [quality: 0.6])
            }
            let stats = DepthCamera.validStats(bytes, width: w, height: h, bpp: bpp, box: res.face?.boxNorm)
            res.validRatio = stats.ratio
            if let med = stats.median, med > 0 {
                res.medianDistanceM = res.depthType == "disparity" ? 1.0 / med : med
            }
            req.result = res
        }
        if req.perFrameFaces, !req.result!.depthFrames.isEmpty,
           let pixelBuffer = CMSampleBufferGetImageBuffer(syncedVideo.sampleBuffer) {
            req.result!.faces.append(faceLocator.locate(pixelBuffer))
        } else if !req.result!.depthFrames.isEmpty {
            req.result!.faces.append(nil)
        }
        req.result!.depthFrames.append(bytes)
        req.result!.timestampsMs.append(DepthCamera.epochMs(hostSeconds: pts))
        req.lastPTS = pts
        if req.result!.depthFrames.count >= req.frames {
            var done = req.result!
            done.captureMs = (CACurrentMediaTime() - req.started) * 1000.0
            request = nil
            req.completion(.success(done))
        } else {
            request = req
        }
    }

    // MARK: helpers

    static func copyPixels(_ pb: CVPixelBuffer) -> (Data, Int, Int, Int) {
        CVPixelBufferLockBaseAddress(pb, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(pb, .readOnly) }
        let w = CVPixelBufferGetWidth(pb)
        let h = CVPixelBufferGetHeight(pb)
        let rowBytes = CVPixelBufferGetBytesPerRow(pb)
        let fmt = CVPixelBufferGetPixelFormatType(pb)
        let bpp = (fmt == kCVPixelFormatType_DepthFloat32 || fmt == kCVPixelFormatType_DisparityFloat32) ? 4 : 2
        var out = Data(count: w * h * bpp)
        guard let base = CVPixelBufferGetBaseAddress(pb) else { return (out, w, h, bpp) }
        out.withUnsafeMutableBytes { (dst: UnsafeMutableRawBufferPointer) in
            guard let d = dst.baseAddress else { return }
            for row in 0..<h {  // drop row padding: contiguous row-major output
                memcpy(d + row * w * bpp, base + row * rowBytes, w * bpp)
            }
        }
        return (out, w, h, bpp)
    }

    /// 2x2 mean of the finite, positive float16 values (holes stay NaN when all four are invalid).
    static func downsample2x(_ data: Data, width: Int, height: Int) -> (Data, Int, Int) {
        let ow = width / 2, oh = height / 2
        guard ow > 0, oh > 0 else { return (data, width, height) }
        var out = Data(count: ow * oh * 2)
        data.withUnsafeBytes { (src: UnsafeRawBufferPointer) in
            out.withUnsafeMutableBytes { (dst: UnsafeMutableRawBufferPointer) in
                let s = src.bindMemory(to: Float16.self)
                let d = dst.bindMemory(to: Float16.self)
                for y in 0..<oh {
                    let r0 = 2 * y * width, r1 = r0 + width
                    for x in 0..<ow {
                        let c = 2 * x
                        var sum: Float = 0
                        var n: Float = 0
                        let a = Float(s[r0 + c]), b = Float(s[r0 + c + 1])
                        let e = Float(s[r1 + c]), f = Float(s[r1 + c + 1])
                        if a.isFinite && a > 0 { sum += a; n += 1 }
                        if b.isFinite && b > 0 { sum += b; n += 1 }
                        if e.isFinite && e > 0 { sum += e; n += 1 }
                        if f.isFinite && f > 0 { sum += f; n += 1 }
                        d[y * ow + x] = n > 0 ? Float16(sum / n) : Float16.nan
                    }
                }
            }
        }
        return (out, ow, oh)
    }

    /// Valid (finite, > 0) ratio and median raw value inside the face box (or the whole frame).
    static func validStats(_ data: Data, width: Int, height: Int, bpp: Int, box: [Double]?) -> (ratio: Double, median: Double?) {
        var x0 = 0, y0 = 0, x1 = width, y1 = height
        if let b = box, b.count == 4 {
            x0 = max(0, Int(b[0] * Double(width)))
            y0 = max(0, Int(b[1] * Double(height)))
            x1 = min(width, Int((b[0] + b[2]) * Double(width)))
            y1 = min(height, Int((b[1] + b[3]) * Double(height)))
        }
        guard x1 > x0, y1 > y0 else { return (0, nil) }
        var total = 0
        var valid: [Float] = []
        valid.reserveCapacity((x1 - x0) * (y1 - y0))
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            if bpp == 2 {
                let p = raw.bindMemory(to: Float16.self)
                for y in y0..<y1 { for x in x0..<x1 {
                    let v = Float(p[y * width + x]); total += 1
                    if v.isFinite && v > 0 { valid.append(v) }
                } }
            } else {
                let p = raw.bindMemory(to: Float.self)
                for y in y0..<y1 { for x in x0..<x1 {
                    let v = p[y * width + x]; total += 1
                    if v.isFinite && v > 0 { valid.append(v) }
                } }
            }
        }
        guard total > 0 else { return (0, nil) }
        let ratio = Double(valid.count) / Double(total)
        guard !valid.isEmpty else { return (ratio, nil) }
        valid.sort()
        return (ratio, Double(valid[valid.count / 2]))
    }

    static func epochMs(hostSeconds: Double) -> Double {
        Date().timeIntervalSince1970 * 1000.0 - (CACurrentMediaTime() - hostSeconds) * 1000.0
    }

    static func fourCC(_ code: FourCharCode) -> String {
        let bytes = [24, 16, 8, 0].map { UInt8((code >> $0) & 0xFF) }
        return String(bytes: bytes, encoding: .ascii) ?? "\(code)"
    }
}
