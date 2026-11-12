// Session record and journal events of the extension (runs on the provider queue).
//
//  * Session: latency points (QUIC smoothed RTT) every sampler tick, network-type marks, counters;
//    saved to session.json in the App Group every 10 s and on every event, so a killed
//    extension loses at most 10 s of points. At start the previous session.json moves
//    to session-prev.json; one without an end means the last instance died -> "restart" event.
//  * Pauses: after a network change (or when the server has been silent > 1.5 s) a 100 ms poll
//    of `silent_ms` (time since anything arrived from the server) records the longest silence until
//    traffic flows again. That is the pause of the switch, or of a reconnect / an outage.

import CoreTelephony
import Foundation
import Network
import NetworkExtension

final class Tracker {
    private(set) var session: Session
    private(set) var netLabel = "—"
    var statsFn: (() -> MaskiStats?)?
    var queue: DispatchQueue?

    private var lastSave: UInt64 = 0
    private var lastRec: UInt64 = 0
    private var rttMs: Double = 0
    private let tel = CTTelephonyNetworkInfo()

    /// A running pause measurement.
    private struct Watch {
        var net: Bool
        var t0: UInt64
        var from: String
        var to: String
        var maxSilent: UInt64
        var rec0: UInt64
        var thr: UInt64
        /// Why the tunnel moved by itself (fallback / return), nil for the OS's own path changes.
        var reason: String? = nil
    }
    private var watch: Watch?
    private var fast: DispatchSourceTimer?
    /// When the path last went away (no physical interface), for the pause start.
    private var lostAt: UInt64?

    init(profile: String, logIntact: () -> URL) {
        let now = nowMs()
        if var old = Session.load(Shared.session) {
            if old.end == nil {
                old.unclean = true
                old.end = old.last
                let size = (try? FileManager.default.attributesOfItem(atPath: logIntact().path)[.size] as? UInt64) ?? 0
                journal(JEvent(t: now, k: .restart, a: size > 0 ? "log" : nil))
            }
            old.save(Shared.prevSession)
            try? FileManager.default.removeItem(at: Shared.url(Shared.session))
        }
        session = Session(id: UUID().uuidString, start: now, last: now, profile: profile)
        session.save(Shared.session)
    }

    // MARK: network type

    private func cellLabel() -> String {
        var tech: String?
        if let id = tel.dataServiceIdentifier { tech = tel.serviceCurrentRadioAccessTechnology?[id] }
        if tech == nil { tech = tel.serviceCurrentRadioAccessTechnology?.values.first }
        switch tech {
        case CTRadioAccessTechnologyNR, CTRadioAccessTechnologyNRNSA: return "5G"
        case CTRadioAccessTechnologyLTE: return "LTE"
        case CTRadioAccessTechnologyWCDMA, CTRadioAccessTechnologyHSDPA, CTRadioAccessTechnologyHSUPA,
             CTRadioAccessTechnologyCDMAEVDORev0, CTRadioAccessTechnologyCDMAEVDORevA, CTRadioAccessTechnologyCDMAEVDORevB,
             CTRadioAccessTechnologyeHRPD: return "3G"
        case CTRadioAccessTechnologyGPRS, CTRadioAccessTechnologyEdge, CTRadioAccessTechnologyCDMA1x: return "2G"
        default: return "LTE"
        }
    }

    /// Type label of an interface by its NWInterface type.
    func label(type: NWInterface.InterfaceType?) -> String {
        switch type {
        case .wifi: return "Wi-Fi"
        case .cellular: return cellLabel()
        case .wiredEthernet: return "Ethernet"
        default: return "—"
        }
    }

    private func label(_ path: Network.NWPath) -> String? {
        guard path.status == .satisfied else { return nil }
        let kinds: [NWInterface.InterfaceType] = [.wifi, .cellular, .wiredEthernet]
        guard let i = path.availableInterfaces.first(where: { kinds.contains($0.type) }) else { return nil }
        switch i.type {
        case .wifi: return "Wi-Fi"
        case .cellular: return cellLabel()
        default: return "Ethernet"
        }
    }

    /// The physical interface of the OS's path, and the one the tunnel actually uses (they differ
    /// while the library is on a fallback interface).
    private var pathIface: String?
    private var tunIface: String?

    func firstPath(_ path: Network.NWPath, iface: String?) {
        pathIface = iface
        tunIface = iface
        netLabel = label(path) ?? "—"
        session.nets = [NetMark(t: session.start, n: netLabel)]
    }

    /// A path update after the first one.
    func path(_ path: Network.NWPath, iface: String?, stats: MaskiStats?) {
        let now = nowMs()
        guard let new = label(path), iface != nil else {
            if lostAt == nil { lostAt = now }
            return
        }
        let t = lostAt ?? now
        lostAt = nil
        // Same interface (e.g. LTE <-> 5G on pdp_ip0): not a network change for the tunnel.
        guard iface != pathIface else { return }
        pathIface = iface
        // The tunnel is already there (it fell back to this interface before the OS moved).
        guard iface != tunIface else { return }
        tunIface = iface
        startChange(to: new, t: t, now: now, stats: stats, reason: nil)
    }

    /// The library moved the tunnel to another interface by itself (MASKI_EVENT_PATH).
    /// `label`: the type label of `to` ("Wi-Fi", "LTE", ...); `why` from the library.
    func libSwitch(to: String, label: String, why: String, silentMs: UInt64, stats: MaskiStats?) {
        let now = nowMs()
        guard to != tunIface else { return }
        tunIface = to
        let from = netLabel
        let reason: String
        switch why {
        case "unreachable": reason = "\(from) недоступен"
        case "silent": reason = "нет ответа по \(from)"
        case "failed_return": reason = "снова нет ответа по \(from)"
        case "probe": reason = "\(label) снова отвечает"
        case "alt_gone": reason = "\(from) пропал"
        default: reason = why
        }
        // The pause starts when traffic stopped, not when the library gave up on the interface.
        let t = why == "probe" || why == "alt_gone" ? now : now - min(silentMs, now)
        startChange(to: label, t: t, now: now, stats: stats, reason: reason)
    }

    private func startChange(to new: String, t: UInt64, now: UInt64, stats: MaskiStats?, reason: String?) {
        if let w = watch, w.net { finish(w, now: now) }
        let from = netLabel
        netLabel = new
        session.nets.append(NetMark(t: t, n: new))
        let silent = stats?.silent_ms ?? 0
        let rec = stats?.reconnects ?? 0
        // Keepalives every 500 ms: silence up to keepalive + 2 RTT (+ poll slack) is "no pause".
        let thr = UInt64(650 + min(2 * rttMs, 900))
        if var w = watch {
            // An outage was already being measured: it becomes this switch's pause.
            w.net = true; w.from = from; w.to = new; w.t0 = min(w.t0, t); w.reason = reason
            watch = w
        } else {
            watch = Watch(net: true, t0: t, from: from, to: new, maxSilent: silent, rec0: rec, thr: thr, reason: reason)
        }
        startFast()
        save()
    }

    // MARK: events

    func connected(handshakeMs: Double?) {
        session.connectMs = handshakeMs
        journal(JEvent(t: nowMs(), k: .on, v: handshakeMs))
        save()
    }

    func stopped(reason: NEProviderStopReason) {
        if let w = watch { finish(w, now: nowMs()) }
        fast?.cancel(); fast = nil
        journal(JEvent(t: nowMs(), k: .off, a: Self.reason(reason)))
        session.last = nowMs()
        session.end = session.last
        save()
    }

    static func reason(_ r: NEProviderStopReason) -> String {
        switch r {
        case .userInitiated: return "вручную"
        case .providerFailed, .connectionFailed, .internalError: return "ошибка"
        case .noNetworkAvailable: return "нет сети"
        case .unrecoverableNetworkChange: return "смена сети"
        case .providerDisabled, .configurationDisabled, .superceded: return "другой VPN"
        case .configurationFailed: return "настройки"
        case .configurationRemoved: return "профиль удалён"
        case .idleTimeout: return "простой"
        case .sleep: return "сон"
        case .appUpdate: return "обновление"
        case .userLogout, .userSwitch: return "выход"
        case .authenticationCanceled: return "отмена"
        case .none: return "по правилу"
        default: return "система"
        }
    }

    /// Sampler tick (connected, with stats).
    func tick(_ st: MaskiStats, now: UInt64) {
        session.last = now
        session.bytes = st.tx_bytes + st.rx_bytes
        if st.connected && st.rtt_us > 0 && st.silent_ms < 1500 {
            rttMs = Double(st.rtt_us) / 1000
            session.add(LPoint(t: now, r: Float(rttMs)))
        }
        if watch == nil && st.silent_ms > 1500 {
            watch = Watch(net: false, t0: now - min(st.silent_ms, now), from: netLabel, to: netLabel, maxSilent: st.silent_ms,
                          rec0: lastRec, thr: 0)
            startFast()
        }
        if watch == nil && st.reconnects > lastRec {
            // A reconnect the silence check did not catch (shorter than its threshold).
            journal(JEvent(t: now, k: .rec, v: nil))
            session.drops += 1
            save()
        }
        if watch == nil { lastRec = st.reconnects }
        // save() stamps lastSave with the clock at that moment, which can be past this tick's `now`
        // (the journal write above takes a while): an unchecked `now - lastSave` trapped there.
        if now >= lastSave + 10_000 { save() }
    }

    private func startFast() {
        guard fast == nil, let q = queue else { return }
        let t = DispatchSource.makeTimerSource(queue: q)
        t.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100), leeway: .milliseconds(10))
        t.setEventHandler { [weak self] in self?.fastTick() }
        t.resume()
        fast = t
    }

    private func fastTick() {
        guard var w = watch else { fast?.cancel(); fast = nil; return }
        let now = nowMs()
        guard let st = statsFn?() else {
            if now > w.t0 + 60_000 { finish(w, now: now) }
            return
        }
        w.maxSilent = max(w.maxSilent, st.silent_ms)
        watch = w
        let el = now > w.t0 ? now - w.t0 : 0
        let flowing = st.silent_ms < 400
        if (w.net && el >= 2500 && flowing) || (!w.net && flowing) || el > 60_000 {
            finish(w, now: now)
        }
    }

    private func finish(_ w: Watch, now: UInt64) {
        watch = nil
        fast?.cancel(); fast = nil
        let st = statsFn?()
        let recs = (st?.reconnects ?? w.rec0) - min(w.rec0, st?.reconnects ?? w.rec0)
        lastRec = st?.reconnects ?? lastRec
        tlog("PAUSE \(w.net ? "net \(w.from)->\(w.to)" : "outage") max_silent=\(w.maxSilent) ms thr=\(w.thr) reconnects=+\(recs) reason=\(w.reason ?? "-")")
        if w.net {
            session.changes += 1
            journal(JEvent(t: w.t0, k: .net, a: w.from, b: w.to, v: w.maxSilent > w.thr ? Double(w.maxSilent) : nil, r: w.reason))
        } else if recs > 0 {
            session.drops += 1
            journal(JEvent(t: w.t0, k: .rec, v: Double(w.maxSilent)))
        } else if w.maxSilent >= 3000 {
            session.drops += 1
            journal(JEvent(t: w.t0, k: .drop, v: Double(w.maxSilent)))
        }
        save()
    }

    func save() {
        lastSave = nowMs()
        session.save(Shared.session)
    }
}
