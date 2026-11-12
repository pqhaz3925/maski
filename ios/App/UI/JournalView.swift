// Journal (G-log): events by day from events.jsonl, the tunnel log's size and age, «Писать
// подробно», and «Поделиться логом» (one text file: journal + both log files, via the share sheet).

import Combine
import SwiftUI
import UIKit

struct JournalView: View {
    @EnvironmentObject var ctl: Controller
    @State private var events: [JEvent] = []
    @State private var logInfo = ""
    @State private var shareURL: URL?
    private let tick = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    private static let hm: DateFormatter = {
        let f = DateFormatter(); f.locale = Locale(identifier: "ru_RU"); f.dateFormat = "HH:mm"; return f
    }()
    private static let day: DateFormatter = {
        let f = DateFormatter(); f.locale = Locale(identifier: "ru_RU"); f.dateFormat = "d MMMM"; return f
    }()

    var body: some View {
        Screen(back: "Настройки", title: "Журнал") {
            ForEach(days(), id: \.0) { title, evs in
                SectionTitle(text: title)
                Card {
                    ForEach(Array(evs.enumerated()), id: \.offset) { i, e in
                        if i > 0 { Hairline() }
                        let (what, detail) = Self.text(e)
                        HStack(spacing: 12) {
                            Text(Self.hm.string(from: Date(timeIntervalSince1970: Double(e.t) / 1000)))
                                .foregroundStyle(Color.ink2).monospacedDigit().frame(width: 48, alignment: .leading)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(what).foregroundStyle(Color.ink).lineLimit(1)
                                if let r = e.r { Text(r).font(.system(size: 13)).foregroundStyle(Color.ink2).lineLimit(1) }
                            }
                            Spacer(minLength: 0)
                            Text(detail).foregroundStyle(Color.ink2).lineLimit(1)
                        }
                        .font(.system(size: 17))
                        .frame(minHeight: 48)
                        .padding(.vertical, e.r == nil ? 0 : 6)
                        .accessibilityElement(children: .combine)
                    }
                }
            }
            SectionTitle(text: "Логи")
            Card {
                Row(title: "Лог туннеля", value: logInfo, chevron: false)
                Hairline()
                ToggleRow(title: "Писать подробно", isOn: $ctl.verbose)
            }
            Color.clear.frame(height: 90)
        }
        .overlay(alignment: .bottom) {
            Button(action: share) {
                HStack(spacing: 10) {
                    Image(systemName: "square.and.arrow.up").font(.system(size: 18, weight: .semibold))
                    Text("Поделиться логом").font(.system(size: 17, weight: .semibold))
                }
                .foregroundStyle(Color.dyn(0xFFFFFF, 0x1C1C1E))
                .frame(maxWidth: .infinity, minHeight: 56)
                .background(Color.ink, in: Capsule())
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 16)
            .padding(.bottom, 8)
        }
        .sheet(item: $shareURL) { u in ShareSheet(items: [u]).presentationDetents([.medium, .large]) }
        .onAppear(perform: reload)
        .onReceive(tick) { _ in reload() }
    }

    private func reload() {
        let e = Journal.read()
        if e != events { events = e }
        logInfo = Self.logSummary()
    }

    private func days() -> [(String, [JEvent])] {
        let cal = Calendar.current
        var out: [(String, [JEvent])] = []
        for e in events.reversed() {
            let d = Date(timeIntervalSince1970: Double(e.t) / 1000)
            let title = cal.isDateInToday(d) ? "Сегодня" : cal.isDateInYesterday(d) ? "Вчера" : Self.day.string(from: d)
            if out.last?.0 == title { out[out.count - 1].1.append(e) } else { out.append((title, [e])) }
        }
        return out
    }

    static func text(_ e: JEvent) -> (String, String) {
        switch e.k {
        case .on: return ("Надета", e.v.map { "\(Int($0.rounded())) мс" } ?? "")
        case .off: return ("Снята", e.a ?? "")
        case .net: return ("\(e.a ?? "?") → \(e.b ?? "?")", e.v.map { RU.seconds($0) } ?? "без паузы")
        case .rec: return ("Переподключение", e.v.map { RU.seconds($0) } ?? "")
        case .drop: return ("Обрыв", e.v.map { RU.seconds($0) } ?? "")
        case .restart: return ("Перезапуск системой", e.a == "log" ? "лог цел" : "лога нет")
        case .fail: return ("Не надета", e.a ?? "")
        }
    }

    static func logFiles() -> [URL] {
        let u = Shared.url(Shared.log)
        return [u.appendingPathExtension("1"), u].filter { FileManager.default.fileExists(atPath: $0.path) }
    }

    static func logSummary() -> String {
        var size: UInt64 = 0
        var first: UInt64?
        for u in logFiles() {
            size += (try? FileManager.default.attributesOfItem(atPath: u.path)[.size] as? UInt64) ?? 0
            if first == nil, let h = try? FileHandle(forReadingFrom: u), let d = try? h.read(upToCount: 32) {
                first = String(decoding: d, as: UTF8.self).split(separator: " ").first.flatMap { UInt64($0) }
                try? h.close()
            }
        }
        if size == 0 { return "пусто" }
        let age = first.map { nowMs() > $0 ? nowMs() - $0 : 0 } ?? 0
        return RU.bytes(size) + " · " + RU.age(age)
    }

    private func share() {
        let f = DateFormatter(); f.dateFormat = "yyyyMMdd-HHmm"
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("maski-log-\(f.string(from: Date())).txt")
        FileManager.default.createFile(atPath: url.path, contents: nil)
        guard let h = try? FileHandle(forWritingTo: url) else { return }
        let full = DateFormatter(); full.dateFormat = "yyyy-MM-dd HH:mm:ss"
        var head = "maski \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") ?? "") \(UIDevice.current.systemVersion)\n\n# journal\n"
        for e in Journal.read(limit: 5000) {
            let (a, b) = Self.text(e)
            head += "\(full.string(from: Date(timeIntervalSince1970: Double(e.t) / 1000)))  \(a)  \(b)\(e.r.map { "  (\($0))" } ?? "")\n"
        }
        head += "\n# tunnel log (ms since 1970, message)\n"
        h.write(Data(head.utf8))
        for u in Self.logFiles() { if let d = try? Data(contentsOf: u) { h.write(d) } }
        try? h.close()
        appendLine("results.jsonl", jsonLine(["cmd": "export", "t": nowMs(), "file": url.lastPathComponent,
                                             "bytes": (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? UInt64) ?? 0]))
        shareURL = url
    }
}

extension URL: @retroactive Identifiable { public var id: String { absoluteString } }

struct ShareSheet: UIViewControllerRepresentable {
    var items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController { UIActivityViewController(activityItems: items, applicationActivities: nil) }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}
