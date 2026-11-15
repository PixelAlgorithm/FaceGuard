import CoreGraphics
import CoreVideo
import ImageIO
import Vision

/// Face box + landmarks in the *buffer* coordinates of the video frame (normalised, top-left origin).
/// The depth map is delivered in the same native sensor orientation, so these coordinates index the
/// depth map directly. Vision needs an upright face, so we try EXIF orientations (the last one that
/// worked first) and map Vision's oriented, lower-left-origin results back into buffer coordinates.
struct FaceResult {
    var boxNorm: [Double]                 // [x, y, w, h]
    var landmarks: [String: [Double]]?    // left_eye, right_eye, nose (+ mouth, mouth_left, mouth_right, chin)
    var orientation: CGImagePropertyOrientation
    var confidence: Double
}

final class FaceLocator {
    private var preferred: CGImagePropertyOrientation = .leftMirrored  // front camera, portrait
    private static let all: [CGImagePropertyOrientation] = [
        .leftMirrored, .right, .rightMirrored, .left, .up, .upMirrored, .down, .downMirrored,
    ]

    func locate(_ pixelBuffer: CVPixelBuffer) -> FaceResult? {
        var order = [preferred]
        order.append(contentsOf: FaceLocator.all.filter { $0 != preferred })
        for orientation in order {
            if let result = detect(pixelBuffer, orientation: orientation) {
                preferred = orientation
                return result
            }
        }
        return nil
    }

    private func detect(_ pixelBuffer: CVPixelBuffer, orientation: CGImagePropertyOrientation) -> FaceResult? {
        let request = VNDetectFaceLandmarksRequest()
        let handler = VNImageRequestHandler(cvPixelBuffer: pixelBuffer, orientation: orientation, options: [:])
        do {
            try handler.perform([request])
        } catch {
            return nil
        }
        guard let faces = request.results, !faces.isEmpty else { return nil }
        let face = faces.max { a, b in
            a.boundingBox.width * a.boundingBox.height < b.boundingBox.width * b.boundingBox.height
        }!
        let bb = face.boundingBox
        let corners = [
            CGPoint(x: bb.minX, y: bb.minY), CGPoint(x: bb.maxX, y: bb.minY),
            CGPoint(x: bb.minX, y: bb.maxY), CGPoint(x: bb.maxX, y: bb.maxY),
        ].map { FaceLocator.toBuffer($0, orientation) }
        let xs = corners.map { Double($0.x) }
        let ys = corners.map { Double($0.y) }
        let box = [xs.min()!, ys.min()!, xs.max()! - xs.min()!, ys.max()! - ys.min()!]

        var landmarks: [String: [Double]]?
        if let lm = face.landmarks {
            // Vision landmark points are normalised to the face box (oriented space, lower-left origin).
            func points(_ region: VNFaceLandmarkRegion2D?) -> [CGPoint] {
                guard let region = region, region.pointCount > 0 else { return [] }
                return region.normalizedPoints.map {
                    CGPoint(x: bb.minX + $0.x * bb.width, y: bb.minY + $0.y * bb.height)
                }
            }
            func centroid(_ pts: [CGPoint]) -> CGPoint? {
                guard !pts.isEmpty else { return nil }
                let n = CGFloat(pts.count)
                return CGPoint(x: pts.map { $0.x }.reduce(0, +) / n, y: pts.map { $0.y }.reduce(0, +) / n)
            }
            func out(_ p: CGPoint?) -> [Double]? {
                guard let p = p else { return nil }
                let b = FaceLocator.toBuffer(p, orientation)
                return [Double(b.x), Double(b.y)]
            }
            let leftEye = out(centroid(points(lm.leftPupil)) ?? centroid(points(lm.leftEye)))
            let rightEye = out(centroid(points(lm.rightPupil)) ?? centroid(points(lm.rightEye)))
            let nose = out(centroid(points(lm.nose)) ?? points(lm.noseCrest).last)
            if let leftEye = leftEye, let rightEye = rightEye, let nose = nose {
                var dict: [String: [Double]] = ["left_eye": leftEye, "right_eye": rightEye, "nose": nose]
                let lips = points(lm.outerLips)
                dict["mouth"] = out(centroid(lips))
                dict["mouth_left"] = out(lips.min { $0.x < $1.x })
                dict["mouth_right"] = out(lips.max { $0.x < $1.x })
                dict["chin"] = out(points(lm.faceContour).min { $0.y < $1.y })  // lowest contour point
                landmarks = dict
            }
        }
        return FaceResult(boxNorm: box, landmarks: landmarks, orientation: orientation,
                          confidence: Double(face.confidence))
    }

    /// Vision point (oriented image, normalised, lower-left origin) -> buffer point (normalised,
    /// top-left origin). Derived from the EXIF "0th row / 0th column" definitions in CGImageProperties.h.
    static func toBuffer(_ p: CGPoint, _ orientation: CGImagePropertyOrientation) -> CGPoint {
        let ud = p.x
        let vd = 1 - p.y
        switch orientation {
        case .up: return CGPoint(x: ud, y: vd)
        case .upMirrored: return CGPoint(x: 1 - ud, y: vd)
        case .down: return CGPoint(x: 1 - ud, y: 1 - vd)
        case .downMirrored: return CGPoint(x: ud, y: 1 - vd)
        case .leftMirrored: return CGPoint(x: vd, y: ud)
        case .right: return CGPoint(x: vd, y: 1 - ud)
        case .rightMirrored: return CGPoint(x: 1 - vd, y: 1 - ud)
        case .left: return CGPoint(x: 1 - vd, y: ud)
        @unknown default: return CGPoint(x: ud, y: vd)
        }
    }
}
