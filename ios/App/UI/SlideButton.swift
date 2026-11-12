// Floating slide-to-toggle (Liquid Glass): off = clear glass, red knob on the left with →,
// «Надеть маску»; on = red glass, white knob on the right with ←, «Снять маску». The knob is
// dragged across (snap + haptic); a tap or the accessibility action toggles too. While the system
// connects / disconnects the knob sits at its new end with a spinner.

import SwiftUI
import UIKit

struct SlideButton: View {
    enum Phase { case off, on, turningOn, turningOff }
    var phase: Phase
    var toggle: (Bool) -> Void

    @State private var drag: CGFloat = 0
    @State private var crossed = false

    private let h: CGFloat = 76, knob: CGFloat = 64, pad: CGFloat = 5

    private var atOn: Bool { phase == .on || phase == .turningOn }
    private var busy: Bool { phase == .turningOn || phase == .turningOff }
    private var label: String {
        switch phase {
        case .off: return "Надеть маску"
        case .on: return "Снять маску"
        case .turningOn: return "Надеваю…"
        case .turningOff: return "Снимаю…"
        }
    }

    var body: some View {
        GeometryReader { g in
            let travel = max(g.size.width - 2 * pad - knob, 1)
            let x = min(max((atOn ? travel : 0) + drag, 0), travel)
            let p = x / travel
            let redness = busy ? 0.55 * p : p
            ZStack(alignment: .leading) {
                // The empty socket at the far end.
                Circle()
                    .fill(atOn ? Color.white.opacity(0.35) : Color.dyn(0x3C3C43, 0xFFFFFF).opacity(0.14))
                    .frame(width: knob, height: knob)
                    .offset(x: atOn ? 0 : travel)
                    .opacity(1 - abs(p - (atOn ? 1 : 0)))
                Text(label)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(p > 0.5 ? Color(hex: 0x1C1C1E) : Color.ink)
                    .frame(maxWidth: .infinity)
                    .opacity(1 - min(abs(drag) / (travel * 0.5), 0.8))
                knobView(on: p > 0.5)
                    .offset(x: x)
            }
            .padding(pad)
            .frame(width: g.size.width, height: h)
            .glassEffect(.regular.tint(Color.accent.opacity(redness)).interactive(), in: .capsule)
            .shadow(color: p > 0.5 ? Color(hex: 0xC8320A).opacity(0.30) : .black.opacity(0.16), radius: 17, y: 10)
            .contentShape(Capsule())
            .gesture(
                DragGesture(minimumDistance: 4)
                    .onChanged { v in
                        drag = v.translation.width
                        let now = atOn ? (x / travel) < 0.45 : (x / travel) > 0.55
                        if now != crossed {
                            crossed = now
                            UIImpactFeedbackGenerator(style: .light).impactOccurred()
                        }
                    }
                    .onEnded { v in
                        let base: CGFloat = atOn ? travel : 0
                        let cur = min(max(base + v.translation.width, 0), travel) / travel
                        let end = min(max(base + v.predictedEndTranslation.width, 0), travel) / travel
                        let flip = atOn ? (cur < 0.45 || end < 0.3) : (cur > 0.55 || end > 0.7)
                        crossed = false
                        if flip { fire(!atOn) } else { withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) { drag = 0 } }
                    }
            )
            .onTapGesture { fire(!atOn) }
        }
        .frame(height: h)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityAddTraits(.isButton)
        .accessibilityIdentifier("slide")
        .accessibilityAction { fire(!atOn) }
    }

    private func fire(_ on: Bool) {
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        withAnimation(.spring(response: 0.4, dampingFraction: 0.82)) {
            toggle(on)
            drag = 0
        }
    }

    @ViewBuilder private func knobView(on: Bool) -> some View {
        ZStack {
            Circle()
                .fill(on ? Color.white.opacity(0.97) : Color.accent)
                .shadow(color: on ? .black.opacity(0.20) : Color(hex: 0xC8320A).opacity(0.30), radius: 5, y: 3)
            if busy {
                ProgressView().tint(Color(hex: 0x1C1C1E))
            } else {
                Image(systemName: on ? "arrow.left" : "arrow.right")
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundStyle(Color(hex: 0x1C1C1E))
            }
        }
        .frame(width: knob, height: knob)
    }
}
