#!/usr/bin/env python3
"""Test endpoints on the server's tunnel address (phone measurements, ios/README.md).

TCP :5201, one request line per connection:
  D <bytes> <rate_bps> <tag>   server sends <bytes> (paced at rate_bps, 0 = as fast as possible)
  U <bytes> <tag>              server reads <bytes> (or until EOF), then answers "OK <n> <ms>"
Every connection is sampled every 100 ms (TCP_INFO bytes_acked / bytes_received) and one JSON
summary line goes to <logdir>/tcp.jsonl: bytes, duration, Mbit/s, and every stall >= 300 ms (wall
clock start, length) - the server-side view of an inner TCP flow across network changes.
UDP :7 echoes every datagram (not with a third argument "tcp-only").
"""
import json, os, socket, struct, sys, threading, time

ADDR = sys.argv[1] if len(sys.argv) > 1 else "10.90.0.1"
LOGDIR = sys.argv[2] if len(sys.argv) > 2 else "/var/tmp/maski"
# "tcp-only": no UDP echo (for a baseline instance on a public address).
UDP = not (len(sys.argv) > 3 and sys.argv[3] == "tcp-only")
PORT = int(os.environ.get("TSRV_PORT", "5201"))
LOG = open(os.path.join(LOGDIR, "tcp.jsonl"), "a", buffering=1)
CHUNK = b"\x5a" * 16384


def tcp_counters(s):
    b = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 232)
    acked, received = struct.unpack_from("<QQ", b, 120)
    retrans = struct.unpack_from("<I", b, 100)[0]
    return acked, received, retrans


def sampler(s, key, stop, out):
    last_v, last_t, t0 = -1, time.time(), time.time()
    while not stop.is_set():
        try:
            a, r, rt = tcp_counters(s)
        except OSError:
            break
        v = a if key == "D" else r
        now = time.time()
        if v != last_v:
            if last_v >= 0 and now - last_t >= 0.3:
                out["stalls"].append([round(last_t, 2), int((now - last_t) * 1000)])
            last_v, last_t = v, now
        out["retrans"] = rt
        time.sleep(0.1)
    out["bytes_progress"] = last_v
    # A trailing stall (the connection died while nothing moved) counts too.
    if time.time() - last_t >= 0.3 and out.get("end_reason") not in ("done",):
        out["tail_stall_ms"] = int((time.time() - last_t) * 1000)


def handle(c, peer):
    c.settimeout(600)
    f = c.makefile("rb")
    line = f.readline().decode(errors="replace").split()
    if not line:
        c.close(); return
    out = {"peer": peer[0], "cmd": line[0], "t0": round(time.time(), 3), "stalls": []}
    stop = threading.Event()
    th = threading.Thread(target=sampler, args=(c, line[0], stop, out), daemon=True)
    th.start()
    n = 0
    t0 = time.time()
    try:
        if line[0] == "D":
            total, rate = int(line[1]), int(line[2])
            out.update(tag=line[3] if len(line) > 3 else "", want=total, rate=rate)
            c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            while n < total:
                k = min(len(CHUNK), total - n)
                c.sendall(CHUNK[:k])
                n += k
                if rate > 0:
                    due = t0 + n * 8 / rate
                    d = due - time.time()
                    if d > 0:
                        time.sleep(d)
            # wait until everything is acked (bounded)
            for _ in range(100):
                if tcp_counters(c)[0] >= n:
                    break
                time.sleep(0.05)
            out["end_reason"] = "done"
        elif line[0] == "U":
            total = int(line[1])
            out.update(tag=line[2] if len(line) > 2 else "", want=total)
            buf = bytearray(65536)
            while total == 0 or n < total:
                k = f.readinto1(buf)  # the reader may already hold data sent right after the line
                if k == 0:
                    break
                n += k
            ms = int((time.time() - t0) * 1000)
            c.sendall(f"OK {n} {ms}\n".encode())
            out["end_reason"] = "done"
    except Exception as e:  # reset / timeout: logged as the end reason
        out["end_reason"] = type(e).__name__
    dur = time.time() - t0
    stop.set(); th.join(1)
    out.update(bytes=n, dur_s=round(dur, 3), mbps=round(n * 8 / dur / 1e6, 2) if dur > 0 else 0)
    LOG.write(json.dumps(out) + "\n")
    try:
        c.close()
    except OSError:
        pass


def tcp_server():
    while True:
        try:
            ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind((ADDR, PORT))
            break
        except OSError:
            time.sleep(1)
    ls.listen(64)
    while True:
        c, peer = ls.accept()
        threading.Thread(target=handle, args=(c, peer), daemon=True).start()


def udp_echo():
    while True:
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.bind((ADDR, 7))
            break
        except OSError:
            time.sleep(1)
    while True:
        d, a = u.recvfrom(2048)
        u.sendto(d, a)


if UDP:
    threading.Thread(target=udp_echo, daemon=True).start()
tcp_server()
