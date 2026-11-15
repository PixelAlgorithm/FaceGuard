// Renders stdin as a QR code PNG for depth/ios/pair.sh:  xcrun swift qr.swift <out.png> < payload
// The payload (a depthprobe:// pairing link with the token) is read from stdin and never printed.
import CoreImage
import Foundation
import ImageIO
import UniformTypeIdentifiers

let args = CommandLine.arguments
guard args.count == 2 else {
    FileHandle.standardError.write(Data("usage: xcrun swift qr.swift <out.png> < payload\n".utf8))
    exit(2)
}
let payload = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self)
    .trimmingCharacters(in: .whitespacesAndNewlines)
guard !payload.isEmpty, let filter = CIFilter(name: "CIQRCodeGenerator") else { exit(3) }
filter.setValue(Data(payload.utf8), forKey: "inputMessage")
filter.setValue("M", forKey: "inputCorrectionLevel")
let scale: CGFloat = 14
guard let qr = filter.outputImage?.samplingNearest().transformed(by: CGAffineTransform(scaleX: scale, y: scale)) else {
    exit(4)
}
let canvas = qr.extent.insetBy(dx: -4 * scale, dy: -4 * scale)  // 4-module quiet zone
let image = qr.composited(over: CIImage(color: CIColor(red: 1, green: 1, blue: 1)).cropped(to: canvas))
guard let cg = CIContext().createCGImage(image, from: canvas),
      let dest = CGImageDestinationCreateWithURL(URL(fileURLWithPath: args[1]) as CFURL,
                                                 UTType.png.identifier as CFString, 1, nil) else { exit(5) }
CGImageDestinationAddImage(dest, cg, nil)
exit(CGImageDestinationFinalize(dest) ? 0 : 6)
