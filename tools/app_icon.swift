// App icon (design "Mark", variant А): dark tile, red capsule with two eye holes.
// usage: swift tools/app_icon.swift ios/App/Assets.xcassets/AppIcon.appiconset/icon-1024.png
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let out = CommandLine.arguments[1]
let n = 1024
let cs = CGColorSpace(name: CGColorSpace.sRGB)!
let ctx = CGContext(data: nil, width: n, height: n, bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                    bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)!
func rgb(_ h: UInt32) -> CGColor {
    CGColor(colorSpace: cs, components: [CGFloat(h >> 16 & 255) / 255, CGFloat(h >> 8 & 255) / 255, CGFloat(h & 255) / 255, 1])!
}
ctx.setFillColor(rgb(0x0E0E0E))
ctx.fill(CGRect(x: 0, y: 0, width: n, height: n))
// Tile 112, capsule 76 x 38 (viewBox 96 x 48, holes r 14 at x 24 / 72).
let w = CGFloat(n) * 76 / 112, h = w / 2, s = w / 96
let x0 = (CGFloat(n) - w) / 2, y0 = (CGFloat(n) - h) / 2
ctx.setFillColor(rgb(0xFF4A1C))
ctx.addPath(CGPath(roundedRect: CGRect(x: x0, y: y0, width: w, height: h), cornerWidth: h / 2, cornerHeight: h / 2, transform: nil))
ctx.fillPath()
ctx.setFillColor(rgb(0x0E0E0E))
for cx in [24.0, 72.0] {
    ctx.fillEllipse(in: CGRect(x: x0 + (cx - 14) * s, y: y0 + (24 - 14) * s, width: 28 * s, height: 28 * s))
}
let img = ctx.makeImage()!
let dst = CGImageDestinationCreateWithURL(URL(fileURLWithPath: out) as CFURL, UTType.png.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(dst, img, nil)
CGImageDestinationFinalize(dst)
