// Test drivers, triggered by URL (maski://test/<cmd>?k=v&..., the old maski://<cmd>?... still works)
// or launch arguments (-cmd "<cmd>?k=v"). Commands run one after another; every result is one JSON
// line in Documents/results.jsonl.
//
//   install?route=split|full&tun=auto|fd|callback&pin=1&nc=1&sample=1000[&ka=500&dead=1500&recover=migrate&cc=fixed:N]
//   connect | disconnect | mark | clear | rate?ms=200
//   routes?ru=0|1&local=0|1[&ping=secs&tag=]  set the route switches; while connected the extension
//                                    applies them at once and the result has its timing and footprint
//                                    (ping: 5 Hz echo meanwhile, ping-<tag>.txt)
//   ondemand?on=0|1                  «Держать надетой» (On Demand) on/off
//   debug?ru=0|1                     show / hide the «Российские сайты напрямую» switch
//   session                          the live session record (summary)
//   fetch?url=&tag=                  HTTP GET (ephemeral URLSession): status, ms, first 200 bytes
//                                    (e.g. "what is my IP" services: which way a route goes)
//   down?bytes=&rate=&secs=&tag=[&host=]  TCP download from 10.90.0.1:5201 (rate bit/s, 0 = unpaced)
//   up?bytes=&rate=&secs=&tag=       TCP upload
//   ping?secs=&hz=5&tag=             UDP echo to 10.90.0.1:7, gaps >= 500 ms
//   nc?secs=&rate=&tag=              ping + one long paced download together (network-change runs)
//   cycles?n=&tag=                   n fresh connect/disconnect cycles
//   cping?secs=8&hz=20&tag=[&dns=1]  connect with an echo running from before the start (time to
//                                    traffic, stalls after it; ping-<tag>.txt, ../tools/ios_cping.py)
//   dns=1 on routes / ping / cping: echo = DNS query to <test host>:53 (the server's own resolver,
//                                    so no test endpoint is needed), answered or not, it is an echo
//   blackhole?iface=en0&mode=1|2|0   TEST HOOK: the library drops (1) / fails (2) all traffic of that
//                                    interface's sockets, present and future; 0 = off
//   fbt?secs=&rate=&at=&for=&iface=en0&mode=1&tag=   fallback run: ping + paced download (as nc),
//                                    black hole on `iface` from `at` s for `for` s; result has the
//                                    marks, the extension log is drained into extlog.txt

import Foundation
import NetworkExtension
import UIKit

/// Test endpoint (tools/testsrv.py on the server's tunnel address); `install?thost=` changes it, e.g.
/// 10.91.0.1 for the `maski-dev` instance on 8446.
nonisolated(unsafe) var testHost = UserDefaults.standard.string(forKey: "test_host") ?? "10.90.0.1"

@MainActor
final class Driver {
    static let shared = Driver()
    private var chain: Task<Void, Never>?
    private var bg: UIBackgroundTaskIdentifier = .invalid
    private var running = 0
    private let ctl = Controller.shared
    /// Set by the first test command: from then on the app drains the extension while connected.
    private(set) var testMode = false
    var isRunning: Bool { running > 0 || testMode }

    static let commands: Set<String> = ["install", "connect", "disconnect", "mark", "rate", "clear", "down", "up", "ping", "nc",
                                        "cycles", "routes", "ondemand", "debug", "session", "fetch",
                                        "blackhole", "fbt", "cping"]

    /// maski://test/<cmd>?... or the old maski://<cmd>?...; false if the URL is not a test command.
    @discardableResult
    func handle(_ url: URL) -> Bool {
        var cmd = url.host ?? ""
        if cmd == "test" { cmd = url.pathComponents.dropFirst().first ?? "" }
        guard Self.commands.contains(cmd) else { return false }
        var q: [String: String] = [:]
        for i in URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? [] { q[i.name] = i.value ?? "" }
        enqueue(cmd, q)
        return true
    }

    func enqueue(_ cmd: String, _ q: [String: String]) {
        if !["debug", "session"].contains(cmd) { testMode = true }
        let prev = chain
        running += 1
        beginBg()
        chain = Task { @MainActor in
            await prev?.value
            while !ctl.loaded { try? await Task.sleep(nanoseconds: 50_000_000) }
            ctl.busy = "\(cmd) \(q)"
            await run(cmd, q)
            ctl.busy = ""
            running -= 1
            if running == 0 { endBg() }
        }
    }

    /// Back in the foreground during a run: start a fresh background allowance (~30 s) for the
    /// next excursion (e.g. to Settings to toggle Wi-Fi) and drop the old one.
    func renewBg() {
        guard running > 0 else { return }
        let old = bg
        bg = .invalid
        beginBg()
        if old != .invalid { UIApplication.shared.endBackgroundTask(old) }
    }

    private func beginBg() {
        guard bg == .invalid else { return }
        bg = UIApplication.shared.beginBackgroundTask(withName: "maski-test") { [weak self] in
            Task { @MainActor in
                appendLine("results.jsonl", jsonLine(["cmd": "bg-expired", "t": nowMs()]))
                self?.endBg()
            }
        }
    }

    private func endBg() {
        if bg != .invalid { UIApplication.shared.endBackgroundTask(bg); bg = .invalid }
    }

    private func record(_ d: [String: Any]) {
        let line = jsonLine(d)
        appendLine("results.jsonl", line)
        ctl.last = String(line.prefix(400))
    }

    private func int(_ q: [String: String], _ k: String, _ d: Int) -> Int { q[k].flatMap { Int($0) } ?? d }
    private func dbl(_ q: [String: String], _ k: String, _ d: Double) -> Double { q[k].flatMap { Double($0) } ?? d }

    private func waitStatus(_ want: Set<NEVPNStatus>, timeout: Double) async -> Bool {
        let t0 = Date()
        while Date().timeIntervalSince(t0) < timeout {
            if want.contains(ctl.manager?.connection.status ?? .invalid) { return true }
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        return false
    }

    /// Extension status around a measurement: CPU %, footprint window max, available minimum.
    private func extDelta(_ a: [String: Any]?, _ b: [String: Any]?) -> [String: Any] {
        guard let a = a?["now"] as? [String: Any], let bb = b, let b = bb["now"] as? [String: Any] else { return ["ext": "none"] }
        let u = { (d: [String: Any], k: String) -> Double in (d[k] as? NSNumber)?.doubleValue ?? 0 }
        let dt = u(b, "t") - u(a, "t")
        let cpu = dt > 0 ? (u(b, "cpu_us") - u(a, "cpu_us")) / (dt * 1000) * 100 : 0
        let sa = a["st"] as? [String: Any] ?? [:], sb = b["st"] as? [String: Any] ?? [:]
        let us = { (d: [String: Any], k: String) -> Double in (d[k] as? NSNumber)?.doubleValue ?? 0 }
        return [
            "cpu_pct": (cpu * 10).rounded() / 10, "fp_start": u(a, "fp"), "fp_end": u(b, "fp"),
            "fp_win_max": (bb["win_max_fp"] as? NSNumber)?.doubleValue ?? 0, "fp_peak_life": u(b, "fp_peak"),
            "avail_win_min": (bb["win_min_avail"] as? NSNumber)?.doubleValue ?? 0,
            "udp_tx": us(sb, "utx") - us(sa, "utx"), "udp_rx": us(sb, "urx") - us(sa, "urx"),
            "mig": us(sb, "mig") - us(sa, "mig"), "rec": us(sb, "rec") - us(sa, "rec"), "lost": us(sb, "lost") - us(sa, "lost"),
            "wk_int": u(b, "wk_int") - u(a, "wk_int"), "wk_idle": u(b, "wk_idle") - u(a, "wk_idle"),
            // Outer transport counters (MaskiStats): QUIC packets sent, socket ENOBUFS / other errors /
            // EWOULDBLOCK, send-queue gate drops; rate estimate and window at the end.
            "sent": us(sb, "sent") - us(sa, "sent"), "nobufs": us(sb, "nobufs") - us(sa, "nobufs"),
            "serr": us(sb, "serr") - us(sa, "serr"), "sblk": us(sb, "sblk") - us(sa, "sblk"),
            "qdrop": us(sb, "qdrop") - us(sa, "qdrop"), "bw_end": us(sb, "bw"), "cwnd_end": us(sb, "cwnd"),
            "rtt_end_us": us(sb, "rtt_us"),
            "mode": bb["mode"] ?? "", "iface": bb["iface"] ?? "", "ext_dt_ms": dt,
        ]
    }

    private func run(_ cmd: String, _ q: [String: String]) async {
        let t0 = nowMs()
        var res: [String: Any] = ["cmd": cmd, "args": q, "t0": t0]
        switch cmd {
        case "install":
            var cfg: [String: Any] = [:]
            if let v = q["ka"].flatMap(Int.init) { cfg["keepalive_ms"] = v }
            if let v = q["dead"].flatMap(Int.init) { cfg["dead_ms"] = v }
            if let v = q["recover"] { cfg["recover"] = v }
            if let v = q["idle"].flatMap(Int.init) { cfg["idle_timeout_ms"] = v }
            if let v = q["cc"] { cfg["cc"] = v }
            if let v = q["qms"].flatMap(Int.init) { cfg["queue_ms"] = v }
            // server=IP:port overrides the profile's server (e.g. maski-dev on 8446), thost= the test endpoint.
            testHost = q["thost"] ?? (q["server"]?.hasSuffix(":8446") == true ? "10.91.0.1" : "10.90.0.1")
            UserDefaults.standard.set(testHost, forKey: "test_host")
            res["thost"] = testHost
            var opts: [String: Any] = [
                "route": q["route"] ?? "split", "tun": q["tun"] ?? "auto", "pin_iface": (q["pin"] ?? "1") == "1",
                "netchange": (q["nc"] ?? "1") == "1", "sample_ms": int(q, "sample", 1000), "cfg": cfg,
            ]
            if let v = q["server"] { opts["server_override"] = v }
            if let v = q["fb"] { opts["fallback"] = v == "1" }
            // stage=1: Russian routes in a second settings call after the tunnel is up (old way).
            if let v = q["stage"] { opts["ru_stage"] = v == "1" }
            do { try await ctl.install(opts); res["ok"] = true } catch { res["error"] = "\(error)" }
        case "connect":
            do {
                try ctl.connect()
                res["ok"] = await waitStatus([.connected], timeout: 40)
                res["ms"] = nowMs() - t0
                ctl.resetDrain()
                res["ext"] = await ctl.send(["cmd": "snap"]).map { s in ["mode": s["mode"] ?? "", "utun": s["utun"] ?? "", "iface": s["iface"] ?? "", "connect": s["connect"] ?? [:]] as [String: Any] }
            } catch { res["error"] = "\(error)" }
        case "disconnect":
            await ctl.drain()
            ctl.disconnect()
            res["ok"] = await waitStatus([.disconnected, .invalid], timeout: 15)
        case "mark":
            res["ext"] = await ctl.send(["cmd": "mark"]) ?? [:]
        case "routes":
            ctl.lastApply = [:]
            let before = await ctl.send(["cmd": "snap"])
            ctl.setRoutesForTest(ru: q["ru"].map { $0 == "1" }, local: q["local"].map { $0 == "1" })
            if ctl.status == .connected {
                await ctl.saveForTest()
                // ping=<secs>: 5 Hz echo through the tunnel while the settings are applied (does
                // traffic flow during setTunnelNetworkSettings?).
                let ps = dbl(q, "ping", 0), tag = q["tag"] ?? "routes"
                let hz = dbl(q, "hz", 5)
                let dns = q["dns"] == "1"
                let pingTask: Task<[String: Any], Never>? = ps > 0 ? Task.detached { Self.ping(secs: ps, hz: hz, tag: tag, dns: dns) } : nil
                if ps > 0 { try? await Task.sleep(nanoseconds: 1_000_000_000) }
                // run=<n>: only the n largest Russian prefixes, for this apply only (blackout vs count).
                var ro = ctl.routeOptions()
                if let n = q["run"].flatMap(Int.init) { ro["ru_n"] = n }
                res["apply_t"] = nowMs()
                res["apply"] = await ctl.send(["cmd": "apply", "routes": ro]) ?? ["error": "no reply"]
                res["apply_t1"] = nowMs()
                if let p = await pingTask?.value { res["ping"] = p }
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                let after = await ctl.send(["cmd": "snap"])
                res["fp_before"] = (before?["now"] as? [String: Any])?["fp"] ?? 0
                res["fp_after_3s"] = (after?["now"] as? [String: Any])?["fp"] ?? 0
                res["fp_peak"] = (after?["now"] as? [String: Any])?["fp_peak"] ?? 0
            }
            res["opts"] = ctl.routeOptions().mapValues { v -> Any in (v as? [String]).map { $0.count } ?? v }
        case "fetch":
            guard let u = q["url"].flatMap(URL.init(string:)) else { res["error"] = "url"; break }
            var req = URLRequest(url: u, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 15)
            req.setValue("curl/8", forHTTPHeaderField: "User-Agent")
            let rx = { (r: [String: Any]?) -> Double in (((r?["now"] as? [String: Any])?["st"] as? [String: Any])?["rxb"] as? NSNumber)?.doubleValue ?? 0 }
            let before = await ctl.send(["cmd": "snap"])
            let t = nowMs()
            do {
                let (d, r) = try await URLSession(configuration: .ephemeral).data(for: req)
                res["status"] = (r as? HTTPURLResponse)?.statusCode ?? 0
                res["bytes"] = d.count
                let body = String(decoding: d, as: UTF8.self)
                res["body"] = String(body.prefix(120))
                // IPv4 addresses in the answer (the "your address" of an IP-echo page).
                let re = try! NSRegularExpression(pattern: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")
                var ips: [String] = []
                for m in re.matches(in: body, range: NSRange(body.startIndex..., in: body)) {
                    let ip = String(body[Range(m.range, in: body)!])
                    if !ips.contains(ip) { ips.append(ip) }
                }
                res["ips"] = Array(ips.prefix(4))
            } catch { res["error"] = "\(error)" }
            res["ms"] = nowMs() - t
            // Inner bytes the tunnel received meanwhile: ~ the answer's size if it went through the tunnel.
            res["tunnel_rx_delta"] = rx(await ctl.send(["cmd": "snap"])) - rx(before)
        case "ondemand":
            do { try await ctl.setOnDemand(q["on"] == "1"); res["ok"] = true } catch { res["error"] = "\(error)" }
            res["enabled"] = ctl.manager?.isOnDemandEnabled ?? false
        case "debug":
            if let v = q["ru"] { ctl.showRU = v == "1" }
            res["show_ru"] = ctl.showRU
        case "session":
            await ctl.refresh()
            if let s = ctl.live ?? ctl.lastSession {
                res["session"] = ["start": s.start, "last": s.last, "end": s.end ?? 0, "unclean": s.unclean ?? false, "pts": s.pts.count,
                                  "nets": s.nets.map { "\($0.t) \($0.n)" }, "changes": s.changes, "drops": s.drops, "bytes": s.bytes] as [String: Any]
            }
            res["live"] = ctl.live != nil
            res["rtt_ms"] = ctl.rttMs ?? 0
        case "rate":
            res["ext"] = await ctl.send(["cmd": "rate", "ms": int(q, "ms", 1000)]).map { _ in "ok" } ?? "none"
        case "clear":
            for f in ["results.jsonl", "ext.jsonl", "extlog.txt", "status.txt"] { try? FileManager.default.removeItem(at: docURL(f)) }
            if let all = try? FileManager.default.contentsOfDirectory(atPath: docURL("").path) {
                for f in all where f.hasPrefix("ping-") || f.hasPrefix("tl-") { try? FileManager.default.removeItem(at: docURL(f)) }
            }
            ctl.resetDrain()
        case "down", "up":
            let bytes = int(q, "bytes", 10_000_000), rate = int(q, "rate", 0), secs = dbl(q, "secs", 10), tag = q["tag"] ?? cmd
            // host= another address (e.g. the server's public one) for a baseline outside the tunnel.
            let host = q["host"] ?? testHost
            let a = await ctl.send(["cmd": "rate", "ms": 200])
            _ = a
            let before = await ctl.send(["cmd": "mark"])
            // ping=<hz>: UDP echo through the tunnel during the transfer (latency under load).
            let hz = dbl(q, "ping", 0)
            let pingTask: Task<[String: Any], Never>? = hz > 0 ? Task.detached { Self.ping(secs: secs + 0.5, hz: hz, tag: tag) } : nil
            let t: Transfer = await Task.detached {
                if cmd == "up" { return tcpUp(host: host, bytes: bytes, rate: rate, maxSecs: secs, tag: tag) }
                // Timeline tl-<tag>.txt: bytes per 100 ms (startup vs steady rate).
                let tl = "tl-\(tag).txt"
                var bucket: UInt64 = 0, acc = 0, lines: [String] = []
                let t = tcpDown(host: host, bytes: bytes, rate: rate, maxSecs: secs, tag: tag) { t, k in
                    let b = t / 100
                    if b != bucket { if acc > 0 { lines.append("\(bucket * 100) \(acc)") }; bucket = b; acc = 0 }
                    acc += k
                }
                if acc > 0 { lines.append("\(bucket * 100) \(acc)") }
                try? (lines.joined(separator: "\n") + "\n").write(to: docURL(tl), atomically: true, encoding: .utf8)
                return t
            }.value
            if let p = await pingTask?.value { res["ping"] = p }
            let after = await ctl.send(["cmd": "mark"])
            _ = await ctl.send(["cmd": "rate", "ms": 1000])
            res["transfer"] = t.json()
            res["ext"] = extDelta(before, after)
        case "ping":
            let secs = dbl(q, "secs", 30), hz = dbl(q, "hz", 5), tag = q["tag"] ?? "ping", dns = q["dns"] == "1"
            let before = await ctl.send(["cmd": "mark"])
            let r: [String: Any] = await Task.detached { Self.ping(secs: secs, hz: hz, tag: tag, dns: dns) }.value
            let after = await ctl.send(["cmd": "mark"])
            res["ping"] = r
            res["ext"] = extDelta(before, after)
        case "nc":
            let secs = dbl(q, "secs", 300), rate = int(q, "rate", 2_000_000), tag = q["tag"] ?? "nc"
            let before = await ctl.send(["cmd": "mark"])
            let drainer = Task { @MainActor in
                while !Task.isCancelled { await self.ctl.drain(); try? await Task.sleep(nanoseconds: 2_000_000_000) }
            }
            async let p: [String: Any] = Task.detached { Self.ping(secs: secs, hz: 5, tag: tag) }.value
            async let d: Transfer = Task.detached {
                let tl = "tl-\(tag).txt"
                var bucket: UInt64 = 0, acc = 0
                return tcpDown(host: testHost, bytes: Int(Double(rate) / 8 * (secs + 30)), rate: rate, maxSecs: secs, tag: tag) { t, k in
                    let b = t / 100
                    if b != bucket { if acc > 0 { appendLine(tl, "\(bucket * 100) \(acc)") }; bucket = b; acc = 0 }
                    acc += k
                }
            }.value
            let (pr, dr) = await (p, d)
            drainer.cancel()
            await ctl.drain()
            let after = await ctl.send(["cmd": "mark"])
            res["ping"] = pr
            res["transfer"] = dr.json()
            res["ext"] = extDelta(before, after)
        case "blackhole":
            var m: [String: Any] = ["cmd": "blackhole", "mode": int(q, "mode", 1)]
            if let i = q["iface"] { m["iface"] = i }
            res["ext"] = await ctl.send(m).map { s in ["iface": s["iface"] ?? "", "alts": s["alts"] ?? ""] as [String: Any] } ?? "none"
        case "fbt":
            let secs = dbl(q, "secs", 60), rate = int(q, "rate", 1_000_000), tag = q["tag"] ?? "fbt"
            let at = dbl(q, "at", 10), dur = dbl(q, "for", 20), iface = q["iface"] ?? "en0", mode = int(q, "mode", 1)
            _ = await ctl.send(["cmd": "rate", "ms": 200])
            let before = await ctl.send(["cmd": "mark"])
            let drainer = Task { @MainActor in
                while !Task.isCancelled { await self.ctl.drain(); try? await Task.sleep(nanoseconds: 1_000_000_000) }
            }
            let t0 = nowMs()
            let holes = Task { @MainActor () -> [String: UInt64] in
                var marks: [String: UInt64] = [:]
                try? await Task.sleep(nanoseconds: UInt64(at * 1e9))
                marks["hole_on"] = nowMs()
                _ = await self.ctl.send(["cmd": "blackhole", "iface": iface, "mode": mode])
                if dur > 0 {
                    try? await Task.sleep(nanoseconds: UInt64(dur * 1e9))
                    marks["hole_off"] = nowMs()
                    _ = await self.ctl.send(["cmd": "blackhole", "iface": iface, "mode": 0])
                }
                return marks
            }
            async let p: [String: Any] = Task.detached { Self.ping(secs: secs, hz: 5, tag: tag) }.value
            async let d: Transfer = Task.detached {
                let tl = "tl-\(tag).txt"
                var bucket: UInt64 = 0, acc = 0
                return tcpDown(host: testHost, bytes: Int(Double(rate) / 8 * (secs + 30)), rate: rate, maxSecs: secs, tag: tag) { t, k in
                    let b = t / 100
                    if b != bucket { if acc > 0 { appendLine(tl, "\(bucket * 100) \(acc)") }; bucket = b; acc = 0 }
                    acc += k
                }
            }.value
            let (pr, dr) = await (p, d)
            let marks = await holes.value
            drainer.cancel()
            await ctl.drain()
            let after = await ctl.send(["cmd": "mark"])
            _ = await ctl.send(["cmd": "rate", "ms": 1000])
            res["t_start"] = t0
            res["marks"] = marks
            res["ping"] = pr
            res["transfer"] = dr.json()
            res["ext"] = extDelta(before, after)
        case "cping":
            // Connect while an echo runs (unconnected socket: the source address follows the routes
            // as they change). The echo starts 0.5 s before the start, `connect_t` / `connected_t`
            // mark the start and «connected»; ../tools/ios_cping.py: first echo, stalls after it.
            let secs = dbl(q, "secs", 8), hz = dbl(q, "hz", 20), tag = q["tag"] ?? "cping", dns = q["dns"] == "1"
            if ctl.status != .disconnected && ctl.status != .invalid {
                ctl.disconnect()
                _ = await waitStatus([.disconnected, .invalid], timeout: 15)
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
            let pingTask = Task.detached { Self.ping(secs: secs, hz: hz, tag: tag, dns: dns, unconnected: true) }
            try? await Task.sleep(nanoseconds: 500_000_000)
            res["connect_t"] = nowMs()
            do {
                try ctl.connect()
                res["ok"] = await waitStatus([.connected], timeout: 40)
                res["connected_t"] = nowMs()
            } catch { res["error"] = "\(error)" }
            res["ping"] = await pingTask.value
            ctl.resetDrain()
            if let s = await ctl.send(["cmd": "snap"]) {
                res["connect"] = s["connect"] ?? [:]
                res["apply"] = s["apply"] ?? [:]  // the last settings call (excluded, apply_ms, t)
                res["fp"] = (s["now"] as? [String: Any])?["fp"] ?? 0
                res["fp_peak"] = (s["now"] as? [String: Any])?["fp_peak"] ?? 0
            }
        case "cycles":
            let n = int(q, "n", 20), tag = q["tag"] ?? "cycles"
            var ok = 0
            for i in 1...max(n, 1) {
                let c0 = nowMs()
                var one: [String: Any] = ["cmd": "cycle", "tag": tag, "i": i, "t0": c0]
                do {
                    try ctl.connect()
                    let up = await waitStatus([.connected], timeout: 40)
                    one["ok"] = up
                    one["ms"] = nowMs() - c0
                    if up {
                        // A packet through the tunnel proves it carries data, not just that it connected.
                        let echo: Bool = await Task.detached { Self.echoOnce() }.value
                        one["echo"] = echo
                        if echo { ok += 1 }
                        if let s = await ctl.send(["cmd": "snap"]) { one["connect"] = s["connect"] ?? [:]; one["iface"] = s["iface"] ?? "" }
                    }
                } catch { one["error"] = "\(error)" }
                await ctl.drain()
                ctl.disconnect()
                _ = await waitStatus([.disconnected, .invalid], timeout: 15)
                ctl.resetDrain()
                record(one)
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
            res["ok_count"] = ok
            res["n"] = n
        default:
            res["error"] = "unknown command"
        }
        res["t1"] = nowMs()
        record(res)
        await ctl.drain()
    }

    nonisolated static func echoOnce() -> Bool {
        guard let p = Pinger(host: testHost) else { return false }
        p.run(secs: 1.0, hz: 5)
        return !p.snapshot().isEmpty
    }

    nonisolated static func ping(secs: Double, hz: Double, tag: String, dns: Bool = false, unconnected: Bool = false) -> [String: Any] {
        if dns || unconnected {
            guard let p = UPinger(host: testHost, dns: dns) else { return ["error": "socket"] }
            p.run(secs: secs, hz: hz)
            let r = p.snapshot()
            let lines = r.map { "\($0.0) \($0.1) \($0.2)" }.joined(separator: "\n")
            try? (lines + "\n").write(to: docURL("ping-\(tag).txt"), atomically: true, encoding: .utf8)
            let rtts = r.map { Double($0.2 - $0.1) }.sorted()
            return ["sent": p.sent, "recv": r.count, "dns": dns, "first_send": p.firstSend,
                    "rtt_med_ms": rtts.isEmpty ? 0 : rtts[rtts.count / 2], "rtt_max_ms": rtts.last ?? 0]
        }
        guard let p = Pinger(host: testHost) else { return ["error": "socket"] }
        p.run(secs: secs, hz: hz)
        let r = p.snapshot()
        let lines = r.map { "\($0.0) \($0.1) \($0.2)" }.joined(separator: "\n")
        try? (lines + "\n").write(to: docURL("ping-\(tag).txt"), atomically: true, encoding: .utf8)
        let rtts = r.map { Double($0.2 - $0.1) }.sorted()
        let med = rtts.isEmpty ? 0 : rtts[rtts.count / 2]
        let p95 = rtts.isEmpty ? 0 : rtts[min(rtts.count - 1, Int(Double(rtts.count) * 0.95))]
        return ["sent": p.sent, "recv": r.count, "rtt_med_ms": med, "rtt_p95_ms": p95, "rtt_max_ms": rtts.last ?? 0, "gaps": p.gaps()]
    }
}

/// UDP echo on an unconnected socket (sendto: the source address is chosen per packet, so it
/// follows the tunnel coming up), to `host`:7, or with `dns` a DNS query for a plain name to
/// `host`:53 that the resolver answers itself (`domain-needed`); the query id is the sequence number.
/// Replies: (seq, send ms, receive ms).
final class UPinger: @unchecked Sendable {
    private let fd: Int32
    private var addr = sockaddr_in()
    private let dns: Bool
    private(set) var sent = 0
    private(set) var firstSend: UInt64 = 0
    private var sendT: [UInt32: UInt64] = [:]
    private var replies: [(UInt32, UInt64, UInt64)] = []
    private let lock = NSLock()
    private var running = true

    init?(host: String, dns: Bool) {
        self.dns = dns
        fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = (dns ? UInt16(53) : UInt16(7)).bigEndian
        inet_pton(AF_INET, host, &addr.sin_addr)
        var tv = timeval(tv_sec: 0, tv_usec: 200_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    private func packet(_ seq: UInt32, _ ts: UInt64) -> [UInt8] {
        if !dns {
            var b = [UInt8](repeating: 0, count: 32)
            b.withUnsafeMutableBytes { $0.storeBytes(of: seq, toByteOffset: 0, as: UInt32.self); $0.storeBytes(of: ts, toByteOffset: 4, as: UInt64.self) }
            return b
        }
        let id = UInt16(truncatingIfNeeded: seq)
        var b: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        let name = Array("maskiping".utf8)
        b.append(UInt8(name.count)); b += name; b.append(0)
        b += [0, 1, 0, 1]  // A, IN
        return b
    }

    func run(secs: Double, hz: Double) {
        let rx = Thread { [self] in
            var b = [UInt8](repeating: 0, count: 512)
            while running {
                let k = recv(fd, &b, 512, 0)
                let now = nowMs()
                if dns, k >= 2 {
                    let id = UInt32(b[0]) << 8 | UInt32(b[1])
                    lock.lock()
                    // The id wraps at 65536: take the latest sequence number with this id.
                    if let seq = sendT.keys.filter({ $0 & 0xFFFF == id }).max(), let ts = sendT[seq], !replies.contains(where: { $0.0 == seq }) {
                        replies.append((seq, ts, now))
                    }
                    lock.unlock()
                } else if !dns, k >= 12 {
                    let (seq, ts) = b.withUnsafeBytes { ($0.loadUnaligned(fromByteOffset: 0, as: UInt32.self), $0.loadUnaligned(fromByteOffset: 4, as: UInt64.self)) }
                    lock.lock(); replies.append((seq, ts, now)); lock.unlock()
                }
            }
        }
        rx.start()
        let t0 = nowMs()
        firstSend = t0
        var seq: UInt32 = 0
        while Double(nowMs() - t0) < secs * 1000 {
            seq += 1
            let ts = nowMs()
            let b = packet(seq, ts)
            lock.lock(); sendT[seq] = ts; lock.unlock()
            _ = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(fd, b, b.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            sent += 1
            let d = Double(t0) + Double(seq) * 1000 / hz - Double(nowMs())
            if d > 0 { usleep(useconds_t(d * 1000)) }
        }
        usleep(1_000_000)
        running = false
        usleep(300_000)
        close(fd)
    }

    func snapshot() -> [(UInt32, UInt64, UInt64)] { lock.lock(); defer { lock.unlock() }; return replies.sorted { $0.0 < $1.0 } }
}
