// Colours, type and the grouped-list building blocks of the design (G-*.dc.html): grey page
// #F2F2F7, white cards radius 26, rows 52 pt, hairlines #C6C6C8, one accent #FF4A1C.

import SwiftUI
import UIKit

extension Color {
    init(hex: UInt32, alpha: Double = 1) {
        self.init(.sRGB, red: Double(hex >> 16 & 255) / 255, green: Double(hex >> 8 & 255) / 255, blue: Double(hex & 255) / 255, opacity: alpha)
    }

    /// Light value from the design, dark value for dark appearance.
    static func dyn(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(UIColor { t in
            let h = t.userInterfaceStyle == .dark ? dark : light
            return UIColor(red: CGFloat(h >> 16 & 255) / 255, green: CGFloat(h >> 8 & 255) / 255, blue: CGFloat(h & 255) / 255, alpha: 1)
        })
    }

    static let accent = Color(hex: 0xFF4A1C)
    static let link = dyn(0xB8300A, 0xFF7A52)
    static let page = dyn(0xF2F2F7, 0x000000)
    static let card = dyn(0xFFFFFF, 0x1C1C1E)
    static let ink = dyn(0x1C1C1E, 0xFFFFFF)
    static let ink2 = dyn(0x6C6C70, 0x98989F)
    static let hair = dyn(0xC6C6C8, 0x38383A)
    static let grid = dyn(0xE5E5EA, 0x2C2C2E)
    static let chevron = dyn(0xAEAEB2, 0x5A5A5F)
    static let chip = dyn(0xF2F2F7, 0x2C2C2E)
    static let greyLine = dyn(0xAEAEB2, 0x636366)
    static let rule = dyn(0x8E8E93, 0x8E8E93)
}

/// White card, radius 26, 16 pt side padding.
struct Card<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(spacing: 0) { content }
            .padding(.horizontal, 16)
            .background(Color.card, in: RoundedRectangle(cornerRadius: 26, style: .continuous))
    }
}

/// 0.5 pt separator between rows (the design's border-top).
struct Hairline: View {
    var body: some View { Rectangle().fill(Color.hair).frame(height: 0.5) }
}

struct Chevron: View {
    var body: some View {
        Path { p in p.move(to: CGPoint(x: 1, y: 1)); p.addLine(to: CGPoint(x: 7, y: 7)); p.addLine(to: CGPoint(x: 1, y: 13)) }
            .stroke(Color.chevron, style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
            .frame(width: 8, height: 14)
    }
}

/// Row: title, optional value, optional chevron; 52 pt.
struct Row: View {
    var title: String
    var value: String? = nil
    var chevron = true
    var height: CGFloat = 52
    var body: some View {
        HStack(spacing: 12) {
            Text(title).foregroundStyle(Color.ink).lineLimit(1)
            Spacer(minLength: 0)
            if let value { Text(value).foregroundStyle(Color.ink2).lineLimit(1) }
            if chevron { Chevron() }
        }
        .font(.system(size: 17))
        .frame(height: height)
        .contentShape(Rectangle())
    }
}

struct ToggleRow: View {
    var title: String
    @Binding var isOn: Bool
    var body: some View {
        Toggle(isOn: $isOn) { Text(title).font(.system(size: 17)).foregroundStyle(Color.ink) }
            .tint(Color.accent)
            .frame(height: 52)
    }
}

/// Grey upper-case section title above a card.
struct SectionTitle: View {
    var text: String
    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 13))
            .foregroundStyle(Color.ink2)
            .padding(.horizontal, 16)
            .padding(.top, 20)
            .padding(.bottom, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// "‹ back" in the link colour, 44 pt high.
struct BackHeader: View {
    var title: String
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        HStack {
            Button { dismiss() } label: {
                HStack(spacing: 6) {
                    Path { p in p.move(to: CGPoint(x: 8, y: 2)); p.addLine(to: CGPoint(x: 2, y: 9)); p.addLine(to: CGPoint(x: 8, y: 16)) }
                        .stroke(style: StrokeStyle(lineWidth: 2.4, lineCap: .round, lineJoin: .round))
                        .frame(width: 10, height: 18)
                    Text(title).font(.system(size: 17))
                }
                .foregroundStyle(Color.link)
                .padding(.horizontal, 4)
                .frame(height: 44)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(title)
            Spacer()
        }
    }
}

/// 34 pt bold page title.
struct PageTitle: View {
    var text: String
    var body: some View {
        Text(text)
            .font(.system(size: 34, weight: .bold))
            .tracking(-0.68)
            .foregroundStyle(Color.ink)
            .padding(.horizontal, 4)
            .padding(.top, 4)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// A pushed screen: back header, title, scrolling content on the grey page.
struct Screen<Content: View>: View {
    var back: String
    var title: String
    @ViewBuilder var content: Content
    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                BackHeader(title: back)
                PageTitle(text: title)
                content
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 30)
        }
        .scrollIndicators(.hidden)
        .background(Color.page.ignoresSafeArea())
        .background(SwipeBack().frame(width: 0, height: 0))
        .toolbar(.hidden, for: .navigationBar)
    }
}

/// The navigation bar is hidden on every screen, which turns off the system swipe back; this puts it
/// back (edge swipe and, on iOS 26, the content swipe) for the screen it sits in.
struct SwipeBack: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> VC { VC() }
    func updateUIViewController(_ vc: VC, context: Context) {}

    final class VC: UIViewController, UIGestureRecognizerDelegate {
        override func viewDidAppear(_ animated: Bool) {
            super.viewDidAppear(animated)
            guard let nav = navigationController else { return }
            for g in [nav.interactivePopGestureRecognizer, nav.interactiveContentPopGestureRecognizer] {
                g?.isEnabled = true
                g?.delegate = self
            }
        }

        func gestureRecognizerShouldBegin(_ g: UIGestureRecognizer) -> Bool {
            (navigationController?.viewControllers.count ?? 0) > 1
        }
    }
}

// MARK: - Russian numbers

enum RU {
    /// 1 адрес, 2 адреса, 5 адресов.
    static func plural(_ n: Int, _ one: String, _ few: String, _ many: String) -> String {
        let m10 = n % 10, m100 = n % 100
        if m10 == 1 && m100 != 11 { return one }
        if (2...4).contains(m10) && !(12...14).contains(m100) { return few }
        return many
    }

    static func decimal(_ x: Double, digits: Int = 1) -> String {
        let f = NumberFormatter()
        f.locale = Locale(identifier: "ru_RU")
        f.minimumFractionDigits = 0
        f.maximumFractionDigits = digits
        return f.string(from: NSNumber(value: x)) ?? "\(x)"
    }

    static func bytes(_ b: UInt64) -> String {
        let mb = Double(b) / 1_000_000
        if mb >= 1000 { return decimal(mb / 1000) + " ГБ" }
        if mb >= 10 { return "\(Int(mb.rounded())) МБ" }
        if mb >= 1 { return decimal(mb) + " МБ" }
        return "\(Int((Double(b) / 1000).rounded())) КБ"
    }

    static func duration(_ ms: UInt64) -> String {
        let s = Int(ms / 1000)
        if s < 60 { return "\(s) с" }
        let m = s / 60
        if m < 60 { return "\(m) мин" }
        return m % 60 == 0 ? "\(m / 60) ч" : "\(m / 60) ч \(m % 60) мин"
    }

    /// Pause / gap: "0,7 с", "12 с", "2 мин".
    static func seconds(_ ms: Double) -> String {
        let s = ms / 1000
        if s < 10 { return decimal(s) + " с" }
        if s < 120 { return "\(Int(s.rounded())) с" }
        return "\(Int(s / 60)) мин"
    }

    static func age(_ ms: UInt64) -> String {
        let m = Int(ms / 60_000)
        if m < 60 { return "\(max(m, 1)) мин" }
        let h = m / 60
        if h < 24 { return "\(h) ч" }
        let d = h / 24
        return "\(d) " + plural(d, "день", "дня", "дней")
    }
}
