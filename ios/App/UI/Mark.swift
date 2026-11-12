// The mark (Mark.dc.html): a toggle capsule that is also a mask with two eye holes.
// Off: outline, one solid dot, one dashed socket. On: filled red capsule with two real holes.

import SwiftUI

struct MarkView: View {
    var on: Bool
    var body: some View {
        Canvas { ctx, size in
            let s = size.width / 96
            func r(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat) -> CGRect { CGRect(x: x * s, y: y * s, width: w * s, height: h * s) }
            if on {
                var p = Path(roundedRect: r(0, 0, 96, 48), cornerRadius: 24 * s)
                p.addEllipse(in: r(24 - 13, 24 - 13, 26, 26))
                p.addEllipse(in: r(72 - 13, 24 - 13, 26, 26))
                ctx.fill(p, with: .color(.accent), style: FillStyle(eoFill: true))
            } else {
                let ink = GraphicsContext.Shading.color(.ink)
                ctx.stroke(Path(roundedRect: r(2, 2, 92, 44), cornerRadius: 22 * s), with: ink, lineWidth: 4 * s)
                ctx.fill(Path(ellipseIn: r(24 - 12, 24 - 12, 24, 24)), with: ink)
                ctx.stroke(Path(ellipseIn: r(72 - 11, 24 - 11, 22, 22)), with: ink,
                           style: StrokeStyle(lineWidth: 3 * s, dash: [5 * s, 5 * s]))
            }
        }
        .frame(width: 40, height: 20)
        .accessibilityHidden(true)
    }
}

/// The settings glyph of the round header button (two sliders).
struct SlidersIcon: View {
    var body: some View {
        Canvas { ctx, size in
            let s = size.width / 24
            var p = Path()
            for (a, b, y) in [(4.0, 14.0, 7.0), (18, 20, 7), (4, 6, 17), (10, 20, 17)] {
                p.move(to: CGPoint(x: a * s, y: y * s)); p.addLine(to: CGPoint(x: b * s, y: y * s))
            }
            p.addEllipse(in: CGRect(x: 14 * s, y: 5 * s, width: 4 * s, height: 4 * s))
            p.addEllipse(in: CGRect(x: 6 * s, y: 15 * s, width: 4 * s, height: 4 * s))
            ctx.stroke(p, with: .foreground, style: StrokeStyle(lineWidth: 1.8 * s, lineCap: .round))
        }
        .frame(width: 22, height: 22)
    }
}
