// NEPacketTunnelProvider around libmaski (include/maski.h).
//
// Rust owns the outer UDP sockets and the QUIC/HTTP-3 state on its own thread. This provider:
//  * reads the profile (server, credentials, pin) from the shared Keychain;
//  * finds the utun descriptor behind packetFlow (tun "fd" mode: Rust reads/writes it directly),
//    or falls back to packetFlow.readPackets -> maski_send_packets / packets_cb -> writePackets;
//  * pins the outer sockets to the physical interface NWPathMonitor reports (en0 / pdp_ip0) and
//    calls maski_network_changed on every change of that interface;
//  * tells the library which other interface it may fall back to when that one is dead
//    (maski_set_alternates: cellular / Wi-Fi from their own monitors, satisfied and not
//    constrained, «Сотовая при сбое Wi-Fi» on) and journals the library's own switches;
//  * applies the tunnel network settings (routes, exclusions) when MASKI_EVENT_CONNECTED arrives,
//    and again on an "apply" message from the app; the 10k Russian exclusions go into that first
//    call (`ru_stage` = the old two-step way: tunnel up first, Russian routes in a second call);
//  * keeps the journal, the tunnel log and the session record in the App Group container
//    (Tracker.swift), so they survive the extension's death;
//  * samples its own memory / CPU / wakeups and the library counters into a bounded ring the
//    app drains through handleAppMessage (measurements, see ../README.md).

import Foundation
import Network
import NetworkExtension
import os

private let osLog = Logger(subsystem: "org.example.maski.tunnel", category: "tunnel")

/// The tunnel log: tunnel.log in the App Group container (2 MB + one rotated file), plus a
/// bounded in-memory ring the test drivers drain.
final class LogStore {
    private let lock = NSLock()
    private var ring = Ring<(UInt64, UInt64, String)>(capacity: 600)
    private var seq: UInt64 = 0
    let file = RotatingFile(Shared.url(Shared.log), cap: 2 << 20)
    var verbose = false
    func add(_ s: String) {
        lock.lock(); seq += 1; let t = nowMs(); ring.push((seq, t, s)); lock.unlock()
        file.write("\(t) \(s)\n")
        osLog.notice("\(s, privacy: .public)")
    }
    func since(_ n: UInt64) -> [[Any]] {
        lock.lock(); defer { lock.unlock() }
        return ring.items.filter { $0.0 > n }.map { [$0.0, $0.1, $0.2] }
    }
}

let logStore = LogStore()
let journalFile = RotatingFile(Shared.url(Shared.journal), cap: Journal.cap)
private var sampleFile: RotatingFile?
func tlog(_ s: String) { logStore.add(s) }
/// Only with «Писать подробно».
func vlog(_ s: @autoclosure () -> String) { if logStore.verbose { logStore.add(s()) } }

func journal(_ e: JEvent) {
    if let d = try? JSONEncoder().encode(e) { journalFile.write(String(decoding: d, as: UTF8.self) + "\n") }
    tlog("JOURNAL \(e.k.rawValue) a=\(e.a ?? "-") b=\(e.b ?? "-") v=\(e.v.map { String(Int($0)) } ?? "-")")
}

private let rustLog: MaskiLogFn = { _, line in
    if let line { logStore.add(String(cString: line)) }
}

private let packetsCb: MaskiPacketsFn = { ctx, pkts, lens, count in
    guard let ctx, let pkts, let lens else { return }
    let me = Unmanaged<PacketTunnelProvider>.fromOpaque(ctx).takeUnretainedValue()
    // This runs on the library's own thread, which has no autorelease pool: without one, every
    // bridged NSData/NSNumber handed to writePackets is autoreleased into nothing and never freed
    // (measured: footprint 3.6 -> 36 MB over a 25 MB download).
    autoreleasepool {
        var out: [Data] = []
        out.reserveCapacity(count)
        var protos: [NSNumber] = []
        protos.reserveCapacity(count)
        for i in 0..<count {
            guard let p = pkts[i] else { continue }
            out.append(Data(bytes: p, count: lens[i]))
            protos.append(NSNumber(value: (p[0] >> 4) == 6 ? AF_INET6 : AF_INET))
        }
        me.packetFlow.writePackets(out, withProtocols: protos)
    }
}

private let eventsCb: MaskiEventFn = { ctx, kind, json in
    guard let ctx else { return }
    let me = Unmanaged<PacketTunnelProvider>.fromOpaque(ctx).takeUnretainedValue()
    let s = json.map { String(cString: $0) } ?? "{}"
    me.onEvent(kind, s)
}

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let queue = DispatchQueue(label: "maski.provider")
    private var handle: OpaquePointer?
    private var pending: ((Error?) -> Void)?
    private var stopping = false
    private var settings: [String: Any] = [:]

    private var tunMode = "none"
    private var utunName = ""
    private var pinIface = true
    private var autoNetChange = true
    private var route = "full"
    private var routeOpts: [String: Any] = [:]
    /// «Российские сайты напрямую» at connect: false = in the first settings call (the default),
    /// true = tunnel up first, the Russian routes in a second call (`ru_stage` in the configuration).
    private var ruStaged = false
    private var address = "10.90.0.2"
    private var serverIP = ""
    private let monitor = NWPathMonitor()
    /// Per-type monitors: the candidates for a fallback (status and Low Data Mode of each).
    private let cellMon = NWPathMonitor(requiredInterfaceType: .cellular)
    private let wifiMon = NWPathMonitor(requiredInterfaceType: .wifi)
    private var cellPath: Network.NWPath?
    private var wifiPath: Network.NWPath?
    private var fallbackOn = true
    private var lastAlts: String?
    private var ifaceTypes: [String: NWInterface.InterfaceType] = [:]
    private var curIface: String?
    private var pathEvents = 0
    private var connectInfo: [String: Any] = [:]
    private var startMs: UInt64 = 0
    private var connected = false
    private var lastApply: [String: Any] = [:]
    private var tracker: Tracker?

    // Sampler.
    private var timer: DispatchSourceTimer?
    private var sampleMs = 2000
    private var samples = Ring<Sample>(capacity: 2400)
    private var sampleSeq: UInt64 = 0
    private var winMaxFp: UInt64 = 0
    private var winMinAvail: UInt64 = .max
    private var winStart: UInt64 = 0
    private var sleeps = 0
    private var wakes = 0

    // MARK: - lifecycle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        startMs = nowMs()
        let pc = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        settings = pc
        logStore.verbose = Shared.defaults.bool(forKey: Pref.verbose) || (pc["verbose"] as? Bool ?? false)
        if logStore.verbose && sampleFile == nil { sampleFile = RotatingFile(Shared.url("samples.jsonl"), cap: 4 << 20) }
        tlog("startTunnel pid=\(getpid()) on_demand=\(options?["is-on-demand"] != nil) verbose=\(logStore.verbose)")

        // Credentials: the profile in the shared Keychain, or (old test configurations) inline.
        var server = "", pin = "", user = "", pass = "", sni = "", name = "?"
        if let id = pc["profile"] as? String, let p = ProfileStore.get(id) {
            server = p.server; pin = p.pin; user = p.user; pass = p.pass; sni = p.sni; name = p.name
        } else if let s = pc["server"] as? String, let pi = pc["pin"] as? String, let u = pc["user"] as? String, let pw = pc["pass"] as? String {
            server = s; pin = pi; user = u; pass = pw; name = pc["profile_name"] as? String ?? "?"
        }
        // Test runs: another server for the same profile (e.g. the maski-dev instance on 8446).
        if let o = pc["server_override"] as? String, !o.isEmpty { server = o; tlog("server override \(o)") }
        tracker = Tracker(profile: name, logIntact: { logStore.file.url })
        guard !server.isEmpty else {
            tlog("start: no profile (keychain item \(pc["profile"] as? String ?? "-") missing)")
            journal(JEvent(t: nowMs(), k: .fail, a: "нет профиля"))
            completionHandler(NEVPNError(.configurationInvalid))
            return
        }
        route = pc["route"] as? String ?? "full"
        routeOpts = ["ex_local": pc["ex_local"] ?? false, "ex_ru": pc["ex_ru"] ?? false, "bypass": pc["bypass"] ?? []]
        ruStaged = pc["ru_stage"] as? Bool ?? false
        pinIface = pc["pin_iface"] as? Bool ?? true
        autoNetChange = pc["netchange"] as? Bool ?? true
        sampleMs = pc["sample_ms"] as? Int ?? 2000
        fallbackOn = (pc["fallback"] as? Bool) ?? (Shared.defaults.object(forKey: Pref.cellFallback) as? Bool ?? true)
        let wantMode = pc["tun"] as? String ?? "auto"
        maski_set_log(rustLog, Int32(pc["log_level"] as? Int ?? (logStore.verbose ? 4 : 3)))

        queue.async {
            self.pending = completionHandler
            self.stopping = false
            self.connected = false
            self.startSampler()
            // First path update gives the interface to pin to.
            let first = DispatchSemaphore(value: 0)
            var gotFirst = false
            self.monitor.pathUpdateHandler = { [weak self] path in
                guard let self else { return }
                if !gotFirst {
                    gotFirst = true
                    self.curIface = Self.physical(path)
                    self.tracker?.firstPath(path, iface: self.curIface)
                    tlog("path initial status=\(path.status) iface=\(self.curIface ?? "-") net=\(self.tracker?.netLabel ?? "-") all=\(path.availableInterfaces.map { "\($0.name)/\($0.type)" })")
                    first.signal()
                    return
                }
                self.pathChanged(path)
            }
            self.monitor.start(queue: self.queue)
            self.cellMon.pathUpdateHandler = { [weak self] p in self?.cellPath = p; self?.noteTypes(p); self?.pushAlternates() }
            self.wifiMon.pathUpdateHandler = { [weak self] p in self?.wifiPath = p; self?.noteTypes(p); self?.pushAlternates() }
            self.cellMon.start(queue: self.queue)
            self.wifiMon.start(queue: self.queue)
            // pathUpdateHandler runs on `queue`: wait for it off-queue.
            DispatchQueue.global().async {
                _ = first.wait(timeout: .now() + 2)
                // A host name is resolved here, outside the tunnel (the library wants an address).
                let resolved = Self.resolve(server)
                self.queue.async {
                    guard let resolved else {
                        tlog("start: cannot resolve \(server)")
                        journal(JEvent(t: nowMs(), k: .fail, a: "адрес сервера"))
                        self.finishStart(NEVPNError(.configurationInvalid))
                        return
                    }
                    self.serverIP = resolved.0
                    self.launch(server: resolved.1, pin: pin, user: user, pass: pass, sni: sni, wantMode: wantMode)
                }
            }
        }
    }

    /// "host:port" -> (ip, "ip:port"); IP literals pass through.
    static func resolve(_ server: String) -> (String, String)? {
        guard let (host, port) = Profile.parseServer(server) else { return nil }
        if isIPLiteral(host) { return (host, server) }
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_DGRAM, ai_protocol: 0, ai_addrlen: 0,
                             ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &res) == 0, let r = res, let sa = r.pointee.ai_addr else { return nil }
        defer { freeaddrinfo(res) }
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in
            var a = p.pointee.sin_addr
            _ = inet_ntop(AF_INET, &a, &buf, socklen_t(buf.count))
        }
        let ip = String(cString: buf)
        return (ip, "\(ip):\(port)")
    }

    private func launch(server: String, pin: String, user: String, pass: String, sni: String, wantMode: String) {
        var fd: Int32 = -1
        if wantMode != "callback" {
            var name = [CChar](repeating: 0, count: 32)
            fd = maski_find_utun_fd(&name, Int32(name.count))
            utunName = String(cString: name)
            tlog("utun fd scan: fd=\(fd) ifname=\(utunName)")
        }
        if fd >= 0 {
            tunMode = "fd"
        } else if wantMode == "fd" {
            tlog("tun mode fd requested but no utun fd found")
            finishStart(NEVPNError(.configurationInvalid))
            return
        } else {
            tunMode = "callback"
        }
        var cfg: [String: Any] = (settings["cfg"] as? [String: Any]) ?? [:]
        cfg["server"] = server
        cfg["pin"] = pin
        cfg["user"] = user
        cfg["pass"] = pass
        if !sni.isEmpty { cfg["sni"] = sni }
        if pinIface, let i = curIface { cfg["interface"] = i }
        guard let data = try? JSONSerialization.data(withJSONObject: cfg), let json = String(data: data, encoding: .utf8) else {
            finishStart(NEVPNError(.configurationInvalid)); return
        }
        tlog("maski_start mode=\(tunMode) iface=\(pinIface ? (curIface ?? "-") : "unpinned") route=\(route) netchange=\(autoNetChange)")
        let ctx = Unmanaged.passUnretained(self).toOpaque()
        handle = json.withCString { maski_start($0, fd, tunMode == "callback" ? packetsCb : nil, eventsCb, ctx) }
        if handle == nil {
            finishStart(NEVPNError(.configurationInvalid))
        }
    }

    /// Called on the library's thread.
    func onEvent(_ kind: Int32, _ json: String) {
        let obj = (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any] ?? [:]
        queue.async {
            switch kind {
            case MASKI_EVENT_CONNECTED:
                tlog("EVENT connected \(json) after \(nowMs() - self.startMs) ms")
                self.connectInfo = obj
                self.connectInfo["since_start_ms"] = nowMs() - self.startMs
                self.address = obj["address"] as? String ?? "10.90.0.2"
                self.connected = true
                self.tracker?.connected(handshakeMs: (obj["connect_ms"] as? NSNumber)?.doubleValue)
                self.lastAlts = nil
                self.pushAlternates()
                // With the Russian exclusions on, the settings call blocks all traffic while it runs
                // (~1 s for the 10k list). Default: one call with them, before «connected». Staged
                // (`ru_stage`, the old way): tunnel up without them, a second call adds them; that
                // second call stalls traffic that has already started (docs/ru-list-10k.md).
                let staged = self.ruStaged && self.route == "full" && (self.routeOpts["ex_ru"] as? Bool ?? false)
                self.applySettings(withRU: !staged) { r in
                    guard staged, r["ok"] as? Bool ?? false else { return }
                    self.applySettings(withRU: true) { r2 in
                        tlog("RU exclusions applied after the start: \(Int(r2["apply_ms"] as? Double ?? 0)) ms ok=\(r2["ok"] ?? "?")")
                    }
                }
            case MASKI_EVENT_PATH:
                // The library moved the tunnel by itself (fallback to another interface / return).
                let to = obj["to"] as? String ?? "?"
                let why = obj["why"] as? String ?? "?"
                let silent = (obj["silent_ms"] as? NSNumber)?.uint64Value ?? 0
                let label = self.tracker?.label(type: self.ifaceTypes[to] ?? (to.hasPrefix("pdp_ip") ? .cellular : .wifi)) ?? to
                tlog("EVENT path \(json) -> \(label)")
                self.tracker?.libSwitch(to: to, label: label, why: why, silentMs: silent, stats: self.currentStats())
            case MASKI_EVENT_FAILED:
                tlog("EVENT failed \(json)")
                journal(JEvent(t: nowMs(), k: .fail, a: String((obj["error"] as? String ?? "ошибка").prefix(60))))
                self.finishStart(NEVPNError(.connectionFailed))
            case MASKI_EVENT_STOPPED:
                tlog("EVENT stopped")
                if !self.stopping {
                    self.finishStart(NEVPNError(.connectionFailed))
                    self.cancelTunnelWithError(NEVPNError(.connectionFailed))
                }
            default:
                tlog("EVENT \(kind) \(json)")
            }
        }
    }

    // MARK: - network settings

    private static var ruCache: [NEIPv4Route]?

    /// Bundled Russian IPv4 routes (ru4.txt: geoip:ru of xray's geoip.dat merged into 10k supernets,
    /// tools/ru_list.py; `#` lines are skipped).
    private static func ruRoutes() -> [NEIPv4Route] {
        if let c = ruCache { return c }
        var out: [NEIPv4Route] = []
        if let u = Bundle.main.url(forResource: "ru4", withExtension: "txt"), let s = try? String(contentsOf: u, encoding: .utf8) {
            out.reserveCapacity(10_500)
            for line in s.split(separator: "\n") {
                guard let c = CIDR.parse(String(line)), !c.v6 else { continue }
                out.append(NEIPv4Route(destinationAddress: c.addr, subnetMask: CIDR.mask4(c.prefix)))
            }
        }
        ruCache = out
        return out
    }

    private func buildSettings(withRU: Bool) -> (NEPacketTunnelNetworkSettings, Int) {
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: serverIP.isEmpty ? (settings["server_ip"] as? String ?? "192.0.2.1") : serverIP)
        let v4 = NEIPv4Settings(addresses: [address], subnetMasks: ["255.255.255.0"])
        let parts = address.split(separator: ".")
        let subnet = parts.count == 4 ? "\(parts[0]).\(parts[1]).\(parts[2]).0" : "10.90.0.0"
        let tunnelNet = NEIPv4Route(destinationAddress: subnet, subnetMask: "255.255.255.0")
        var excluded = 0
        if route == "full" {
            // The tunnel's own /24 is listed so that it wins over an excluded 10.0.0.0/8.
            v4.includedRoutes = [NEIPv4Route.default(), tunnelNet]
            let v6 = NEIPv6Settings(addresses: ["fd90::2"], networkPrefixLengths: [64])
            v6.includedRoutes = [NEIPv6Route.default()]
            var ex4: [NEIPv4Route] = [], ex6: [NEIPv6Route] = []
            if routeOpts["ex_local"] as? Bool ?? false {
                for (a, m) in [("10.0.0.0", 8), ("172.16.0.0", 12), ("192.168.0.0", 16), ("169.254.0.0", 16), ("224.0.0.0", 4), ("255.255.255.255", 32)] {
                    ex4.append(NEIPv4Route(destinationAddress: a, subnetMask: CIDR.mask4(m)))
                }
                for (a, p) in [("fe80::", 10), ("fc00::", 7), ("ff00::", 8)] {
                    ex6.append(NEIPv6Route(destinationAddress: a, networkPrefixLength: NSNumber(value: p)))
                }
            }
            for raw in routeOpts["bypass"] as? [String] ?? [] {
                guard let c = CIDR.parse(raw) else { continue }
                if c.v6 {
                    ex6.append(NEIPv6Route(destinationAddress: c.addr, networkPrefixLength: NSNumber(value: c.prefix)))
                } else {
                    ex4.append(NEIPv4Route(destinationAddress: c.addr, subnetMask: CIDR.mask4(c.prefix)))
                }
            }
            if withRU && routeOpts["ex_ru"] as? Bool ?? false {
                // Test only (driver `routes?run=`): the n largest prefixes.
                if let n = routeOpts["ru_n"] as? Int {
                    let bits = { (r: NEIPv4Route) in r.destinationSubnetMask.split(separator: ".").reduce(0) { $0 + (UInt8($1) ?? 0).nonzeroBitCount } }
                    ex4 += Self.ruRoutes().map { (bits($0), $0) }.sorted { $0.0 < $1.0 }.prefix(n).map { $0.1 }
                } else {
                    ex4 += Self.ruRoutes()
                }
            }
            v4.excludedRoutes = ex4
            v6.excludedRoutes = ex6
            excluded = ex4.count + ex6.count
            s.ipv6Settings = v6
            // The server's resolver on its tunnel address (the pool's .1, inside the always-included
            // tunnel /24): its answers drive the work-domain routing on the server (see
            // docs/workdomains-handoff.md). Test configurations can name other servers with "dns".
            let gw = parts.count == 4 ? "\(parts[0]).\(parts[1]).\(parts[2]).1" : "10.90.0.1"
            let servers = (settings["dns"] as? [String]).flatMap { $0.isEmpty ? nil : $0 } ?? [gw]
            let dns = NEDNSSettings(servers: servers)
            dns.matchDomains = [""]
            s.dnsSettings = dns
        } else {
            v4.includedRoutes = [tunnelNet]
        }
        s.ipv4Settings = v4
        s.mtu = NSNumber(value: settings["tun_mtu"] as? Int ?? 1360)
        return (s, excluded)
    }

    private var applying = false
    private var applyQueue: [(Bool, ([String: Any]) -> Void)] = []

    /// Build and apply the network settings; `done` gets the measurement (on `queue`). Calls run
    /// one at a time (a later one waits for the one in flight), on `queue`.
    private func applySettings(withRU: Bool = true, _ done: @escaping ([String: Any]) -> Void) {
        if applying { applyQueue.append((withRU, done)); return }
        applying = true
        applyNow(withRU: withRU) { r in
            done(r)
            self.applying = false
            if !self.applyQueue.isEmpty {
                let (w, d) = self.applyQueue.removeFirst()
                self.applySettings(withRU: w, d)
            }
        }
    }

    private func applyNow(withRU: Bool, _ done: @escaping ([String: Any]) -> Void) {
        let t0 = DispatchTime.now().uptimeNanoseconds
        let fp0 = ProcMetrics.read().footprint
        let (s, excluded) = buildSettings(withRU: withRU)
        let tBuilt = DispatchTime.now().uptimeNanoseconds
        let fpBuilt = ProcMetrics.read().footprint
        setTunnelNetworkSettings(s) { err in
            self.queue.async {
                let t1 = DispatchTime.now().uptimeNanoseconds
                let fp1 = ProcMetrics.read().footprint
                var r: [String: Any] = [
                    "excluded": excluded, "build_ms": Double(tBuilt - t0) / 1e6, "apply_ms": Double(t1 - tBuilt) / 1e6,
                    "fp_before": fp0, "fp_built": fpBuilt, "fp_after": fp1, "fp_peak": ProcMetrics.read().footprintPeak,
                    "ok": err == nil, "opts": self.routeOpts, "t": nowMs(),
                ]
                if let err { r["error"] = "\(err)" }
                self.lastApply = r
                tlog("settings \(err == nil ? "applied" : "FAILED \(err!)") addr=\(self.address) route=\(self.route) mode=\(self.tunMode) excluded=\(excluded) build=\(Int(r["build_ms"] as! Double)) ms apply=\(Int(r["apply_ms"] as! Double)) ms fp \(fp0 >> 10)->\(fpBuilt >> 10)->\(fp1 >> 10) KB")
                if let err {
                    self.finishStart(err)
                } else {
                    if self.tunMode == "callback" && self.pending != nil { self.readLoop() }
                    self.finishStart(nil)
                }
                done(r)
            }
        }
    }

    private func finishStart(_ err: Error?) {
        if let p = pending {
            pending = nil
            p(err)
        }
    }

    private func readLoop() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, let h = self.handle, !self.stopping else { return }
            for p in packets {
                p.withUnsafeBytes { raw in
                    guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                    var ptr: UnsafePointer<UInt8>? = base
                    var len = raw.count
                    _ = withUnsafePointer(to: &ptr) { pp in
                        withUnsafePointer(to: &len) { lp in maski_send_packets(h, pp, lp, 1) }
                    }
                }
            }
            self.readLoop()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        tlog("stopTunnel reason=\(reason.rawValue)")
        queue.async {
            self.stopping = true
            self.monitor.cancel()
            self.cellMon.cancel()
            self.wifiMon.cancel()
            self.timer?.cancel()
            self.tracker?.stopped(reason: reason)
            let h = self.handle
            self.handle = nil
            // maski_stop joins the library thread; its STOPPED event only queues work.
            DispatchQueue.global().async {
                if let h { maski_stop(h) }
                completionHandler()
            }
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        queue.async { self.sleeps += 1; vlog("sleep #\(self.sleeps)"); completionHandler() }
    }

    override func wake() {
        queue.async { self.wakes += 1; vlog("wake #\(self.wakes)") }
    }

    // MARK: - network path

    /// The physical interface the path would use (the tunnel's own utun is type `.other`).
    static func physical(_ path: Network.NWPath) -> String? {
        guard path.status == .satisfied else { return nil }
        let kinds: [NWInterface.InterfaceType] = [.wifi, .cellular, .wiredEthernet]
        return path.availableInterfaces.first { kinds.contains($0.type) }?.name
    }

    private func noteTypes(_ p: Network.NWPath) {
        for i in p.availableInterfaces where [.wifi, .cellular, .wiredEthernet].contains(i.type) { ifaceTypes[i.name] = i.type }
    }

    /// Interfaces the library may fall back to: the cellular / Wi-Fi paths that are satisfied and
    /// not constrained (Low Data Mode), other than the OS's current one; none with the setting off.
    private func pushAlternates() {
        var alts: [String] = []
        var why: [String] = []
        if fallbackOn {
            for p in [cellPath, wifiPath] {
                guard let p else { continue }
                let name = p.availableInterfaces.first { [.cellular, .wifi].contains($0.type) }?.name
                if p.status != .satisfied || name == nil { continue }
                if p.isConstrained { why.append("\(name!) constrained"); continue }
                if name == curIface { continue }
                alts.append(name!)
            }
        }
        let csv = alts.joined(separator: ",")
        guard let h = handle, connected, csv != lastAlts else { return }
        lastAlts = csv
        tlog("ALTERNATES [\(csv)] fallback=\(fallbackOn) \(why.joined(separator: " "))")
        csv.withCString { maski_set_alternates(h, $0) }
    }

    private func pathChanged(_ path: Network.NWPath) {
        noteTypes(path)
        defer { pushAlternates() }
        let iface = Self.physical(path)
        pathEvents += 1
        tlog("PATH #\(pathEvents) status=\(path.status) iface=\(iface ?? "-") (was \(curIface ?? "-")) all=\(path.availableInterfaces.map { "\($0.name)/\($0.type)" })")
        tracker?.path(path, iface: iface, stats: currentStats())
        guard let iface, iface != curIface else {
            if iface == nil { curIface = nil }
            return
        }
        curIface = iface
        guard autoNetChange, let h = handle else { return }
        tlog("NETCHANGE -> \(iface) (pin=\(pinIface))")
        if pinIface {
            iface.withCString { maski_network_changed(h, $0) }
        } else {
            maski_network_changed(h, nil)
        }
    }

    func currentStats() -> MaskiStats? {
        var st = MaskiStats()
        guard let h = handle, maski_stats(h, &st) else { return nil }
        return st
    }

    // MARK: - sampler + app messages

    private func startSampler() {
        timer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now(), repeating: .milliseconds(sampleMs), leeway: .milliseconds(sampleMs / 10))
        t.setEventHandler { [weak self] in self?.sample() }
        t.resume()
        timer = t
        tracker?.statsFn = { [weak self] in self?.currentStats() }
        tracker?.queue = queue
    }

    @discardableResult
    private func sample() -> Sample {
        var st = MaskiStats()
        let has = handle.map { maski_stats($0, &st) } ?? false
        sampleSeq += 1
        let s = Sample(seq: sampleSeq, tMs: nowMs(), m: ProcMetrics.read(), s: st, hasStats: has)
        samples.push(s)
        if let f = sampleFile, logStore.verbose, let d = try? JSONSerialization.data(withJSONObject: s.json(), options: [.sortedKeys]) {
            f.write(String(decoding: d, as: UTF8.self) + "\n")
        }
        winMaxFp = max(winMaxFp, s.m.footprint)
        winMinAvail = min(winMinAvail, s.m.available)
        if has && connected { tracker?.tick(st, now: s.tMs) }
        return s
    }

    private func status(_ cur: Sample) -> [String: Any] {
        [
            "now": cur.json(), "mode": tunMode, "utun": utunName, "iface": curIface ?? "-", "pin_iface": pinIface,
            "netchange": autoNetChange, "route": route, "connect": connectInfo, "win_max_fp": winMaxFp,
            "win_min_avail": winMinAvail == .max ? 0 : winMinAvail, "win_start": winStart, "sample_ms": sampleMs,
            "sleeps": sleeps, "wakes": wakes, "path_events": pathEvents, "net": tracker?.netLabel ?? "-",
            "apply": lastApply, "verbose": logStore.verbose, "alts": lastAlts ?? "", "fallback": fallbackOn,
        ]
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let req = (try? JSONSerialization.jsonObject(with: messageData)) as? [String: Any] ?? [:]
        queue.async {
            var resp: [String: Any] = [:]
            switch req["cmd"] as? String ?? "snap" {
            case "mark":
                let cur = self.sample()
                resp = self.status(cur)
                self.winMaxFp = cur.m.footprint
                self.winMinAvail = cur.m.available
                self.winStart = cur.tMs
            case "drain":
                let since = (req["since"] as? NSNumber)?.uint64Value ?? 0
                let lsince = (req["log_since"] as? NSNumber)?.uint64Value ?? 0
                resp = self.status(self.sample())
                resp["samples"] = self.samples.items.filter { $0.seq > since }.map { $0.json() }
                resp["logs"] = logStore.since(lsince)
            case "rate":
                self.sampleMs = max(100, req["ms"] as? Int ?? 1000)
                self.startSampler()
                resp = self.status(self.sample())
            case "netchange":
                if let h = self.handle {
                    let i = req["iface"] as? String
                    tlog("NETCHANGE (app) -> \(i ?? "keep")")
                    if let i { i.withCString { maski_network_changed(h, $0) } } else { maski_network_changed(h, nil) }
                }
                resp = self.status(self.sample())
            case "session":
                // Home: the live session record plus the current latency and network type.
                let st = self.currentStats()
                if let t = self.tracker, let d = try? JSONEncoder().encode(t.session) { resp["session"] = String(decoding: d, as: UTF8.self) }
                resp["rtt_ms"] = st.map { Double($0.rtt_us) / 1000 } ?? 0
                resp["net"] = self.tracker?.netLabel ?? "-"
                resp["fp"] = ProcMetrics.read().footprint
            case "fallback":
                // «Сотовая при сбое Wi-Fi» switched in the app.
                self.fallbackOn = req["on"] as? Bool ?? true
                tlog("fallback=\(self.fallbackOn)")
                self.pushAlternates()
                resp = ["ok": true, "alts": self.lastAlts ?? ""]
            case "blackhole":
                // TEST HOOK (test drivers only): black-hole an interface's sockets inside the library.
                if let h = self.handle {
                    let mode = Int32(req["mode"] as? Int ?? 1)
                    if let i = req["iface"] as? String { i.withCString { maski_test_blackhole(h, $0, mode) } } else { maski_test_blackhole(h, nil, mode) }
                    tlog("TEST blackhole \(req["iface"] as? String ?? "current") mode=\(mode)")
                }
                resp = self.status(self.sample())
            case "verbose":
                logStore.verbose = req["on"] as? Bool ?? false
                if logStore.verbose && sampleFile == nil { sampleFile = RotatingFile(Shared.url("samples.jsonl"), cap: 4 << 20) }
                tlog("verbose=\(logStore.verbose) (library level applies from the next start)")
                resp = ["ok": true]
            case "apply":
                // New route options from the app: apply them now, reply with the measurement.
                if let o = req["routes"] as? [String: Any] { self.routeOpts = o }
                guard self.connected else { resp = ["ok": false, "error": "not connected"]; break }
                self.applySettings { r in completionHandler?(try? JSONSerialization.data(withJSONObject: r)) }
                return
            default:
                resp = self.status(self.sample())
            }
            completionHandler?(try? JSONSerialization.data(withJSONObject: resp))
        }
    }
}
