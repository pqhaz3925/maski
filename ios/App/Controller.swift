// The app's state: the maski NETunnelProviderManager (configuration, On Demand, connect /
// disconnect), profiles, settings, the live session from the extension and the journal; plus the
// message / drain API the test drivers use.

import Foundation
@preconcurrency import NetworkExtension
import UIKit

let tunnelBundle = "org.example.maski.tunnel"

func docURL(_ name: String) -> URL {
    FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent(name)
}

/// Append one line to a file in Documents.
func appendLine(_ name: String, _ line: String) {
    let url = docURL(name)
    let data = Data((line + "\n").utf8)
    if let h = try? FileHandle(forWritingTo: url) {
        h.seekToEndOfFile(); h.write(data); try? h.close()
    } else {
        try? data.write(to: url)
    }
}

func jsonLine(_ obj: Any) -> String {
    (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
}

/// «Российские сайты напрямую»: shown (default off); `maski://test/debug?ru=0` hides it (README: measurements).
let ruSwitchVisibleByDefault = true

@MainActor
final class Controller: ObservableObject {
    static let shared = Controller()

    // Tunnel.
    @Published var status: NEVPNStatus = .invalid
    @Published var connectedDate: Date?
    /// Set the moment the user slides, until the system status catches up.
    @Published var intent: Bool?
    @Published var errorText: String?

    // Data for Home.
    @Published var live: Session?
    @Published var lastSession: Session?
    @Published var rttMs: Double?
    @Published var netLabel = ""

    // Profiles and settings.
    @Published var profiles: [Profile] = []
    @Published var currentID: String = Shared.defaults.string(forKey: Pref.profile) ?? ""
    @Published var routeRU = Shared.defaults.bool(forKey: Pref.routeRU) { didSet { prefChanged(Pref.routeRU, routeRU, routes: true) } }
    @Published var routeLocal = Shared.defaults.bool(forKey: Pref.routeLocal) { didSet { prefChanged(Pref.routeLocal, routeLocal, routes: true) } }
    @Published var bypass: [String] = Shared.defaults.stringArray(forKey: Pref.bypass) ?? [] { didSet { prefChanged(Pref.bypass, bypass, routes: true) } }
    @Published var keepOn = Shared.defaults.bool(forKey: Pref.keepOn) { didSet { prefChanged(Pref.keepOn, keepOn, routes: false) } }
    @Published var offSSIDs: [String] = Shared.defaults.stringArray(forKey: Pref.offSSIDs) ?? [] { didSet { prefChanged(Pref.offSSIDs, offSSIDs, routes: false) } }
    @Published var verbose = Shared.defaults.bool(forKey: Pref.verbose) {
        didSet {
            Shared.defaults.set(verbose, forKey: Pref.verbose)
            Task { _ = await send(["cmd": "verbose", "on": verbose]) }
        }
    }
    /// «Сотовая при сбое Wi-Fi» (default on): read by the extension at start and sent to it live.
    @Published var cellFallback = Shared.defaults.object(forKey: Pref.cellFallback) as? Bool ?? true {
        didSet {
            Shared.defaults.set(cellFallback, forKey: Pref.cellFallback)
            Task { _ = await send(["cmd": "fallback", "on": cellFallback]) }
        }
    }
    @Published var showRU = Shared.defaults.object(forKey: Pref.showRU) as? Bool ?? ruSwitchVisibleByDefault {
        didSet { Shared.defaults.set(showRU, forKey: Pref.showRU) }
    }

    /// A profile from a link or QR waiting for confirmation.
    @Published var pendingImport: Profile?

    // Test drivers.
    @Published var info = ""
    @Published var last = ""
    @Published var busy = ""
    /// Last route application measured by the extension ("apply" message).
    var lastApply: [String: Any] = [:]

    private(set) var manager: NETunnelProviderManager?
    private var observers: [Any] = []
    private var drainSeq: UInt64 = 0
    private var logSeq: UInt64 = 0
    private var draining = false
    private var loading = false
    /// `load()` has run: test commands wait for it (a URL can launch the app and arrive first).
    private(set) var loaded = false

    var current: Profile? { profiles.first { $0.id == currentID } ?? profiles.first }

    // MARK: - load

    func load() async {
        seedProfiles()
        let all = ((try? await NETunnelProviderManager.loadAllFromPreferences()) ?? [])
            .filter { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == tunnelBundle }
        // One configuration only: a second one appeared when a test command saved before this load
        // had finished. Keep the selected (enabled) one.
        manager = all.first { $0.isEnabled } ?? all.first
        for m in all where m !== manager { try? await m.removeFromPreferences() }
        loaded = true
        watch()
        status = manager?.connection.status ?? .invalid
        connectedDate = manager?.connection.connectedDate
        // On Demand armed: bring its rules in line with the settings.
        if let m = manager, m.isOnDemandEnabled { try? await saveConfig(onDemand: keepOn) }
        await refresh()
    }

    /// The first profile, «Мой сервер», from the bundled (git-ignored) Config/server.json.
    private func seedProfiles() {
        profiles = ProfileStore.all()
        if profiles.isEmpty, let c = Self.serverConfig(), let srv = c["server"] as? String, let (h, p) = Profile.parseServer(srv),
           let user = c["user"] as? String, let pass = c["pass"] as? String, let pin = c["pin"] as? String {
            let pr = Profile(name: "Мой сервер", host: h, port: p, user: user, pass: pass, pin: pin, sni: c["sni"] as? String ?? "")
            if ProfileStore.save(pr) { profiles = [pr] }
        }
        if !profiles.contains(where: { $0.id == currentID }), let f = profiles.first { select(f.id) }
    }

    static func serverConfig() -> [String: Any]? {
        guard let url = Bundle.main.url(forResource: "server", withExtension: "json"),
              let d = try? Data(contentsOf: url) else { return nil }
        return (try? JSONSerialization.jsonObject(with: d)) as? [String: Any]
    }

    private func watch() {
        for o in observers { NotificationCenter.default.removeObserver(o) }
        observers = []
        guard let m = manager else { return }
        observers.append(NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: m.connection, queue: .main) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                let s = m.connection.status
                self.status = s
                self.connectedDate = m.connection.connectedDate
                if s == .connected || s == .disconnected || s == .invalid { self.intent = nil }
                appendLine("status.txt", "\(nowMs()) \(s.name)")
                await self.refresh()
            }
        })
        observers.append(NotificationCenter.default.addObserver(forName: .NEVPNConfigurationChange, object: m, queue: .main) { [weak self] _ in
            Task { @MainActor in try? await self?.manager?.loadFromPreferences() }
        })
    }

    // MARK: - home data

    var isUp: Bool { status == .connected || status == .reasserting }

    /// Live session from the extension while up; the last session from the App Group otherwise.
    func refresh() async {
        if status == .connected || status == .reasserting || status == .connecting {
            if status != .connecting, let r = await send(["cmd": "session"]), let s = r["session"] as? String,
               let sess = try? JSONDecoder().decode(Session.self, from: Data(s.utf8)) {
                live = sess
                rttMs = (r["rtt_ms"] as? NSNumber)?.doubleValue
                netLabel = r["net"] as? String ?? ""
                return
            }
            live = Session.load(Shared.session)
        } else {
            live = nil
            rttMs = nil
        }
        lastSession = Session.load(Shared.session) ?? Session.load(Shared.prevSession)
    }

    // MARK: - configuration

    private func onDemandRules() -> [NEOnDemandRule] {
        var rules: [NEOnDemandRule] = []
        let ssids = offSSIDs.filter { !$0.isEmpty }
        if !ssids.isEmpty {
            let r = NEOnDemandRuleDisconnect()
            r.interfaceTypeMatch = .wiFi
            r.ssidMatch = ssids
            rules.append(r)
        }
        let c = NEOnDemandRuleConnect()
        c.interfaceTypeMatch = .any
        rules.append(c)
        return rules
    }

    func routeOptions() -> [String: Any] {
        ["ex_local": routeLocal, "ex_ru": routeRU && showRU, "bypass": bypass]
    }

    /// Write the configuration. `overrides` (test drivers) replace keys of providerConfiguration.
    private func saveConfig(onDemand: Bool, overrides: [String: Any] = [:]) async throws {
        guard let p = current else { throw NSError(domain: "maski", code: 1, userInfo: [NSLocalizedDescriptionKey: "нет профиля"]) }
        var pc: [String: Any] = ["profile": p.id, "profile_name": p.name, "route": "full", "server_ip": p.host, "verbose": verbose]
        for (k, v) in routeOptions() { pc[k] = v }
        for (k, v) in overrides { pc[k] = v }
        let m = manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = tunnelBundle
        proto.serverAddress = p.name
        proto.providerConfiguration = pc
        m.protocolConfiguration = proto
        m.localizedDescription = "maski"
        m.isEnabled = true
        m.onDemandRules = onDemandRules()
        m.isOnDemandEnabled = onDemand
        try await m.saveToPreferences()
        try await m.loadFromPreferences()
        if manager !== m { manager = m; watch() }
        status = m.connection.status
    }

    /// Slide to on.
    func turnOn() async {
        intent = true
        errorText = nil
        do {
            try await saveConfig(onDemand: keepOn)
            try manager?.connection.startVPNTunnel()
        } catch {
            intent = nil
            errorText = error.localizedDescription
        }
    }

    /// Slide to off: On Demand would bring it straight back, so it goes off first.
    func turnOff() async {
        intent = false
        if let m = manager, m.isOnDemandEnabled {
            m.isOnDemandEnabled = false
            try? await m.saveToPreferences()
        }
        manager?.connection.stopVPNTunnel()
    }

    private func prefChanged(_ key: String, _ value: Any, routes: Bool) {
        Shared.defaults.set(value, forKey: key)
        // Saved when the tunnel is up or On Demand is armed (otherwise at the next «Надеть»: saving
        // would make maski the selected VPN configuration and take the slot from another VPN app).
        let up = status == .connected || status == .reasserting || status == .connecting
        guard !loading, let m = manager, up || m.isOnDemandEnabled else { return }
        Task {
            // Saved for the next start; routes are also applied to the running tunnel now.
            try? await saveConfig(onDemand: keepOn)
            if routes, up, let r = await send(["cmd": "apply", "routes": routeOptions()]) { lastApply = r }
        }
    }

    // MARK: - profiles

    func select(_ id: String) {
        let was = current?.id
        currentID = id
        Shared.defaults.set(id, forKey: Pref.profile)
        if was != id, isUp {
            Task {
                await turnOff()
                for _ in 0..<50 where status != .disconnected { try? await Task.sleep(nanoseconds: 100_000_000) }
                await turnOn()
            }
        }
    }

    func add(_ p: Profile) {
        var p = p
        // The same server and user again: update that profile.
        if let old = profiles.first(where: { $0.host == p.host && $0.port == p.port && $0.user == p.user }) {
            p.id = old.id
            p.created = old.created
        }
        ProfileStore.save(p)
        profiles = ProfileStore.all()
        if profiles.count == 1 || current == nil { select(p.id) }
    }

    func remove(_ id: String) {
        ProfileStore.delete(id)
        profiles = ProfileStore.all()
        if currentID == id, let f = profiles.first { select(f.id) }
    }

    func handleLink(_ url: URL) -> Bool {
        guard url.host == "add" else { return false }
        pendingImport = Profile.from(link: url.absoluteString)
        return true
    }

    // MARK: - test drivers

    /// Create or update the VPN configuration for a test run. `opts`: route split|full, tun
    /// auto|fd|callback, pin_iface, netchange, sample_ms, cfg (extra library settings).
    func install(_ opts: [String: Any]) async throws {
        try await saveConfig(onDemand: false, overrides: opts)
        appendLine("results.jsonl", jsonLine(["cmd": "install", "t": nowMs(), "opts": opts]))
    }

    func connect() throws {
        guard let m = manager else { throw NSError(domain: "maski", code: 2, userInfo: [NSLocalizedDescriptionKey: "not installed"]) }
        try m.connection.startVPNTunnel()
    }

    func disconnect() { manager?.connection.stopVPNTunnel() }

    func setRoutesForTest(ru: Bool?, local: Bool?) {
        loading = true
        if let ru { if ru { showRU = true }; routeRU = ru }
        if let local { routeLocal = local }
        loading = false
    }

    /// Save the route switches into the current configuration, keeping its other (test) keys.
    func saveForTest() async {
        guard let m = manager, let proto = m.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var pc = proto.providerConfiguration ?? [:]
        for (k, v) in routeOptions() { pc[k] = v }
        proto.providerConfiguration = pc
        m.protocolConfiguration = proto
        try? await m.saveToPreferences()
    }

    func setOnDemand(_ on: Bool) async throws {
        keepOn = on
        guard let m = manager else { return }
        m.onDemandRules = onDemandRules()
        m.isOnDemandEnabled = on
        try await m.saveToPreferences()
    }

    func send(_ msg: [String: Any]) async -> [String: Any]? {
        guard let s = manager?.connection as? NETunnelProviderSession, status == .connected || status == .connecting || status == .reasserting,
              let data = try? JSONSerialization.data(withJSONObject: msg) else { return nil }
        return await withCheckedContinuation { cont in
            do {
                try s.sendProviderMessage(data) { resp in
                    cont.resume(returning: resp.flatMap { (try? JSONSerialization.jsonObject(with: $0)) as? [String: Any] })
                }
            } catch {
                cont.resume(returning: nil)
            }
        }
    }

    /// Copy new extension samples and log lines into Documents (ext.jsonl, extlog.txt).
    func drain() async {
        guard !draining else { return }
        draining = true
        defer { draining = false }
        guard let r = await send(["cmd": "drain", "since": drainSeq, "log_since": logSeq]) else { return }
        if let ss = r["samples"] as? [[String: Any]] {
            // A restarted extension starts its sequence at 1 again.
            if let first = ss.first?["seq"] as? UInt64, first < drainSeq { drainSeq = 0 }
            for s in ss { appendLine("ext.jsonl", jsonLine(s)); drainSeq = max(drainSeq, (s["seq"] as? NSNumber)?.uint64Value ?? 0) }
        }
        if let ls = r["logs"] as? [[Any]] {
            for l in ls {
                let seq = (l[0] as? NSNumber)?.uint64Value ?? 0
                appendLine("extlog.txt", "\(l[1]) \(l[2])")
                logSeq = max(logSeq, seq)
            }
        }
        if let now = r["now"] as? [String: Any] {
            let fp = Double((now["fp"] as? NSNumber)?.uint64Value ?? 0) / 1_048_576
            let s = now["st"] as? [String: Any] ?? [:]
            info = String(format: "mode %@ iface %@ fp %.1f MB, rtt %@ us, mig %@, rec %@, rx %@ B",
                          r["mode"] as? String ?? "?", r["iface"] as? String ?? "?", fp,
                          "\(s["rtt_us"] ?? "-")", "\(s["mig"] ?? "-")", "\(s["rec"] ?? "-")", "\(s["rxb"] ?? "-")")
        }
    }

    func resetDrain() { drainSeq = 0; logSeq = 0 }
}

extension NEVPNStatus {
    var name: String {
        switch self {
        case .invalid: return "invalid"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default: return "unknown"
        }
    }
}
