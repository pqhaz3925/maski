// Blocking BSD-socket test clients for the server's test endpoints (tools/testsrv.py on the
// server's tunnel address): TCP download/upload and a UDP echo "ping". Run on background threads.

import Darwin
import Foundation

enum NetErr: Error { case sys(String) }

private func sysErr(_ what: String) -> NetErr { .sys("\(what): \(String(cString: strerror(errno)))") }

private func sockaddrIn(_ host: String, _ port: UInt16) -> sockaddr_in {
    var a = sockaddr_in()
    a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    a.sin_family = sa_family_t(AF_INET)
    a.sin_port = port.bigEndian
    inet_pton(AF_INET, host, &a.sin_addr)
    return a
}

private func setTimeout(_ fd: Int32, _ opt: Int32, ms: Int) {
    var tv = timeval(tv_sec: ms / 1000, tv_usec: Int32((ms % 1000) * 1000))
    setsockopt(fd, SOL_SOCKET, opt, &tv, socklen_t(MemoryLayout<timeval>.size))
}

func tcpConnect(_ host: String, _ port: UInt16) throws -> Int32 {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else { throw sysErr("socket") }
    var one: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, 4)
    setTimeout(fd, SO_SNDTIMEO, ms: 5000)
    var a = sockaddrIn(host, port)
    let r = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    if r != 0 { let e = sysErr("connect"); close(fd); throw e }
    return fd
}

private func sendAll(_ fd: Int32, _ p: UnsafeRawPointer, _ n: Int) -> Bool {
    var off = 0
    while off < n {
        let k = send(fd, p + off, n - off, 0)
        if k < 0 { if errno == EINTR || errno == EAGAIN { continue }; return false }
        off += k
    }
    return true
}

/// Result of a TCP transfer measured on this side.
struct Transfer {
    var bytes = 0
    var ms = 0
    var mbps = 0.0
    var maxStallMs = 0
    /// Stalls >= 300 ms: [wall start ms, length ms].
    var stalls: [[UInt64]] = []
    var error: String?
    var serverBytes = 0
    var serverMs = 0
    func json() -> [String: Any] {
        var d: [String: Any] = ["bytes": bytes, "ms": ms, "mbps": (mbps * 100).rounded() / 100, "max_stall_ms": maxStallMs, "stalls": stalls]
        if let error { d["error"] = error }
        if serverMs > 0 { d["server_bytes"] = serverBytes; d["server_ms"] = serverMs }
        return d
    }
}

/// Download `bytes` paced at `rate` bit/s (0 = unpaced), at most `maxSecs`, or until `stop()`.
func tcpDown(host: String, bytes: Int, rate: Int, maxSecs: Double, tag: String, stop: @escaping () -> Bool = { false },
             timeline: ((UInt64, Int) -> Void)? = nil) -> Transfer {
    var t = Transfer()
    let fd: Int32
    do { fd = try tcpConnect(host, 5201) } catch { t.error = "\(error)"; return t }
    defer { close(fd) }
    var rcv: Int32 = 4 << 20
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, 4)
    setTimeout(fd, SO_RCVTIMEO, ms: 100)
    let line = "D \(bytes) \(rate) \(tag)\n"
    _ = line.withCString { sendAll(fd, $0, strlen($0)) }
    let buf = UnsafeMutableRawPointer.allocate(byteCount: 256 * 1024, alignment: 16)
    defer { buf.deallocate() }
    let t0 = nowMs()
    var first: UInt64 = 0, last: UInt64 = 0
    while t.bytes < bytes {
        let now = nowMs()
        if Double(now - t0) > maxSecs * 1000 || stop() { break }
        let k = recv(fd, buf, 256 * 1024, 0)
        let now2 = nowMs()
        if k > 0 {
            if first == 0 { first = now2; last = now2 }
            let gap = Int(now2 - last)
            if gap >= 300 { t.stalls.append([last, UInt64(gap)]) }
            t.maxStallMs = max(t.maxStallMs, gap)
            last = now2
            t.bytes += k
            timeline?(now2, k)
        } else if k == 0 {
            break
        } else if errno != EAGAIN && errno != EINTR {
            t.error = "recv: \(String(cString: strerror(errno)))"
            break
        }
    }
    if first > 0 {
        let tail = Int(nowMs() - last)
        if t.bytes < bytes && tail >= 300 { t.stalls.append([last, UInt64(tail)]); t.maxStallMs = max(t.maxStallMs, tail) }
    }
    t.ms = Int(last - first)
    t.mbps = t.ms > 0 ? Double(t.bytes) * 8 / Double(t.ms) / 1000 : 0
    return t
}

/// Upload `bytes` paced at `rate` bit/s (0 = unpaced), at most `maxSecs`; the server reports what it got.
func tcpUp(host: String, bytes: Int, rate: Int, maxSecs: Double, tag: String) -> Transfer {
    var t = Transfer()
    let fd: Int32
    do { fd = try tcpConnect(host, 5201) } catch { t.error = "\(error)"; return t }
    defer { close(fd) }
    var snd: Int32 = 4 << 20
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, 4)
    let line = "U \(bytes) \(tag)\n"
    _ = line.withCString { sendAll(fd, $0, strlen($0)) }
    let chunk = 32 * 1024
    let buf = UnsafeMutableRawPointer.allocate(byteCount: chunk, alignment: 16)
    defer { buf.deallocate() }
    memset(buf, 0x5a, chunk)
    let t0 = nowMs()
    while t.bytes < bytes {
        let now = nowMs()
        if Double(now - t0) > maxSecs * 1000 { break }
        let n = min(chunk, bytes - t.bytes)
        if !sendAll(fd, buf, n) { t.error = "send: \(String(cString: strerror(errno)))"; break }
        t.bytes += n
        if rate > 0 {
            let due = Double(t0) + Double(t.bytes) * 8 / Double(rate) * 1000
            let d = due - Double(nowMs())
            if d > 0 { usleep(useconds_t(d * 1000)) }
        }
    }
    shutdown(fd, SHUT_WR)
    setTimeout(fd, SO_RCVTIMEO, ms: 15000)
    var resp = [UInt8](repeating: 0, count: 128)
    let k = recv(fd, &resp, 127, 0)
    t.ms = Int(nowMs() - t0)
    if k > 0 {
        let parts = String(decoding: resp[0..<k], as: UTF8.self).split(separator: " ")
        if parts.count >= 3, parts[0] == "OK" {
            t.serverBytes = Int(parts[1]) ?? 0
            t.serverMs = Int(parts[2].trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        }
    }
    let ms = t.serverMs > 0 ? t.serverMs : t.ms
    t.mbps = ms > 0 ? Double(t.serverBytes > 0 ? t.serverBytes : t.bytes) * 8 / Double(ms) / 1000 : 0
    return t
}

/// 5 Hz (by default) UDP echo through the tunnel. Each reply: (seq, sent ms, received ms).
final class Pinger {
    private let fd: Int32
    private(set) var sent = 0
    private(set) var replies: [(UInt32, UInt64, UInt64)] = []
    private let lock = NSLock()
    private var running = true

    init?(host: String, port: UInt16 = 7) {
        fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        var a = sockaddrIn(host, port)
        let r = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        if r != 0 { close(fd); return nil }
        setTimeout(fd, SO_RCVTIMEO, ms: 200)
    }

    /// Runs until `secs` elapse or `stop()`; blocking.
    func run(secs: Double, hz: Double = 5, stop: @escaping () -> Bool = { false }) {
        let rx = Thread { [self] in
            var b = [UInt8](repeating: 0, count: 64)
            while running {
                let k = recv(fd, &b, 64, 0)
                if k >= 12 {
                    let now = nowMs()
                    let (seq, ts) = b.withUnsafeBytes { ($0.loadUnaligned(fromByteOffset: 0, as: UInt32.self),
                                                         $0.loadUnaligned(fromByteOffset: 4, as: UInt64.self)) }
                    lock.lock(); replies.append((seq, ts, now)); lock.unlock()
                }
            }
        }
        rx.start()
        let t0 = nowMs()
        var seq: UInt32 = 0
        while Double(nowMs() - t0) < secs * 1000 && !stop() {
            seq += 1
            var b = [UInt8](repeating: 0, count: 32)
            let ts = nowMs()
            b.withUnsafeMutableBytes { $0.storeBytes(of: seq, toByteOffset: 0, as: UInt32.self); $0.storeBytes(of: ts, toByteOffset: 4, as: UInt64.self) }
            _ = send(fd, b, 32, 0)
            sent += 1
            let next = Double(t0) + Double(seq) * 1000 / hz
            let d = next - Double(nowMs())
            if d > 0 { usleep(useconds_t(d * 1000)) }
        }
        usleep(1_000_000)
        running = false
        usleep(300_000)
        close(fd)
    }

    func snapshot() -> [(UInt32, UInt64, UInt64)] { lock.lock(); defer { lock.unlock() }; return replies }

    /// Gaps between consecutive replies (by arrival) longer than `minMs`: [start ms, length ms].
    func gaps(minMs: UInt64 = 500) -> [[UInt64]] {
        let r = snapshot().sorted { $0.2 < $1.2 }
        var out: [[UInt64]] = []
        for i in 1..<max(r.count, 1) where r[i].2 - r[i - 1].2 >= minMs { out.append([r[i - 1].2, r[i].2 - r[i - 1].2]) }
        return out
    }
}
