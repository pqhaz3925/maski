// Self-measurement of the extension process: memory (phys_footprint, the number jetsam judges),
// memory left before the limit, CPU time and wakeups. Read by the sampler in
// PacketTunnelProvider and handed to the app through handleAppMessage.

import Darwin
import Foundation

struct ProcMetrics {
    var footprint: UInt64 = 0
    /// Lifetime peak of phys_footprint (kernel ledger).
    var footprintPeak: UInt64 = 0
    var available: UInt64 = 0
    /// User + system CPU time of the whole process, microseconds.
    var cpuUs: UInt64 = 0
    var interruptWakeups: UInt64 = 0
    var idleWakeups: UInt64 = 0
    var timerWakeups: UInt64 = 0

    static func read() -> ProcMetrics {
        var m = ProcMetrics()
        var vm = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &vm) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        if kr == KERN_SUCCESS {
            m.footprint = vm.phys_footprint
            m.footprintPeak = UInt64(max(vm.ledger_phys_footprint_peak, 0))
        }
        m.available = UInt64(os_proc_available_memory())
        var ru = rusage()
        if getrusage(RUSAGE_SELF, &ru) == 0 {
            m.cpuUs = UInt64(ru.ru_utime.tv_sec) * 1_000_000 + UInt64(ru.ru_utime.tv_usec)
                + UInt64(ru.ru_stime.tv_sec) * 1_000_000 + UInt64(ru.ru_stime.tv_usec)
        }
        var pw = task_power_info_data_t()
        var pc = mach_msg_type_number_t(MemoryLayout<task_power_info_data_t>.size / MemoryLayout<natural_t>.size)
        let kr2 = withUnsafeMutablePointer(to: &pw) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(pc)) {
                task_info(mach_task_self_, task_flavor_t(TASK_POWER_INFO), $0, &pc)
            }
        }
        if kr2 == KERN_SUCCESS {
            m.interruptWakeups = pw.task_interrupt_wakeups
            m.idleWakeups = pw.task_platform_idle_wakeups
            m.timerWakeups = pw.task_timer_wakeups_bin_1 + pw.task_timer_wakeups_bin_2
        }
        return m
    }
}

/// One sampler tick: process metrics plus the library's counters.
struct Sample {
    var seq: UInt64
    var tMs: UInt64 // wall clock, ms since 1970
    var m: ProcMetrics
    var s: MaskiStats
    var hasStats: Bool

    func json() -> [String: Any] {
        var d: [String: Any] = [
            "seq": seq, "t": tMs, "fp": m.footprint, "fp_peak": m.footprintPeak, "avail": m.available,
            "cpu_us": m.cpuUs, "wk_int": m.interruptWakeups, "wk_idle": m.idleWakeups, "wk_timer": m.timerWakeups,
        ]
        if hasStats {
            d["st"] = [
                "conn": s.connected, "gen": s.generation, "txp": s.tx_packets, "txb": s.tx_bytes, "rxp": s.rx_packets,
                "rxb": s.rx_bytes, "mig": s.migrations, "rec": s.reconnects, "drop": s.dropped, "big": s.too_large,
                "rtt_us": s.rtt_us, "mtu": s.path_mtu, "lost": s.lost_packets, "utx": s.udp_tx_bytes,
                "urx": s.udp_rx_bytes, "silent": s.silent_ms,
                // Transport counters (MaskiStats fields added with the rate controller).
                "sent": s.sent_packets, "nobufs": s.sock_nobufs, "serr": s.sock_errors, "sblk": s.sock_blocked,
                "qdrop": s.queue_drops, "bw": s.bw_bps, "cwnd": s.cwnd,
                // Interface fallback (maski_set_alternates).
                "fb": s.fallbacks, "fbret": s.fb_returns, "probes": s.fb_probes, "pfail": s.fb_probe_fails, "onalt": s.on_alternate,
            ] as [String: Any]
        }
        return d
    }
}

/// Fixed-capacity ring (bounded memory whatever the run length).
struct Ring<T> {
    private var buf: [T?]
    private var head = 0
    private(set) var count = 0
    init(capacity: Int) { buf = Array(repeating: nil, count: capacity) }
    mutating func push(_ x: T) {
        buf[(head + count) % buf.count] = x
        if count < buf.count { count += 1 } else { head = (head + 1) % buf.count }
    }
    var items: [T] { (0..<count).compactMap { buf[(head + $0) % buf.count] } }
}
