// Journal events (written by the extension, read by the app) and the per-session record that Home
// draws (latency points, network changes, counters). Both live in the App Group container.

import Foundation

/// One journal line in events.jsonl.
struct JEvent: Codable, Equatable {
    enum Kind: String, Codable {
        case on        // connected; v = handshake ms
        case off       // stopped; a = reason
        case net       // network type change; a = from, b = to, v = pause ms (nil = none), r = why the tunnel moved by itself
        case rec       // reconnect / path recovery; v = pause ms
        case drop      // outage without a reconnect; v = ms
        case restart   // the previous extension instance ended without a clean stop; a = "log" if its log is there
        case fail      // could not connect; a = error
    }
    var t: UInt64
    var k: Kind
    var a: String?
    var b: String?
    var v: Double?
    /// Reason of a change the tunnel made itself (fallback to cellular / return), e.g. «нет ответа по Wi-Fi».
    var r: String?
}

enum Journal {
    /// 256 KB + one rotated file: thousands of events.
    static let cap: UInt64 = 256 << 10

    static func read(limit: Int = 500) -> [JEvent] {
        let base = Shared.url(Shared.journal)
        var out: [JEvent] = []
        for u in [base.appendingPathExtension("1"), base] {
            guard let s = try? String(contentsOf: u, encoding: .utf8) else { continue }
            for line in s.split(separator: "\n") {
                if let e = try? JSONDecoder().decode(JEvent.self, from: Data(line.utf8)) { out.append(e) }
            }
        }
        return Array(out.suffix(limit))
    }
}

/// Latency point: wall-clock ms and RTT ms.
struct LPoint: Codable, Equatable {
    var t: UInt64
    var r: Float
}

/// Network segment start: when, and the type label ("Wi-Fi", "LTE", "5G", ...).
struct NetMark: Codable, Equatable {
    var t: UInt64
    var n: String
}

struct Session: Codable, Equatable {
    var id: String
    var start: UInt64
    var last: UInt64
    var end: UInt64?
    /// Set when the next start found this session without a clean stop.
    var unclean: Bool?
    var profile: String
    var pts: [LPoint] = []
    var nets: [NetMark] = []
    var changes: Int = 0
    var drops: Int = 0
    var bytes: UInt64 = 0
    var connectMs: Double?

    static let maxPoints = 1200

    var endOrLast: UInt64 { end ?? last }
    var durationMs: UInt64 { endOrLast > start ? endOrLast - start : 0 }

    /// Append a point; past `maxPoints` average neighbouring pairs (keeps the whole session's shape).
    mutating func add(_ p: LPoint) {
        pts.append(p)
        if pts.count > Self.maxPoints {
            var out: [LPoint] = []
            out.reserveCapacity(pts.count / 2 + 1)
            var i = 0
            while i + 1 < pts.count {
                out.append(LPoint(t: pts[i + 1].t, r: (pts[i].r + pts[i + 1].r) / 2))
                i += 2
            }
            if i < pts.count { out.append(pts[i]) }
            pts = out
        }
    }

    static func load(_ name: String) -> Session? {
        guard let d = try? Data(contentsOf: Shared.url(name)) else { return nil }
        return try? JSONDecoder().decode(Session.self, from: d)
    }

    func save(_ name: String) {
        if let d = try? JSONEncoder().encode(self) { try? d.write(to: Shared.url(name), options: .atomic) }
    }
}
