# maski

**maski** is an L3 VPN over standard MASQUE: CONNECT-IP ([RFC 9484](https://www.rfc-editor.org/rfc/rfc9484)) over HTTP/3, with IP packets from a TUN device carried in QUIC DATAGRAMs. The core is written in Rust (quinn). There is a Linux server, a command-line client (Linux, macOS) and an iOS app.

[Русская версия](README.ru.md)

It was built for personal use and for friends, so that the same tunnel works on a home line and on a phone in a mobile network where connectivity keeps dropping and changing. UDP/QUIC only, no TCP on the outside.

> Status: a working personal project that is a few days old. It has had no security audit, and the configuration format and flags still change.

## What is different

- **Real L3.** The tunnel carries IP packets, not proxy streams. There is no userspace TCP stack inside; loss and congestion are handled by the applications' own TCP.
- **Survives network changes.** The client notices a silent path within 0.7–1.5 s and moves to a new socket without a new handshake; the server holds traffic back while the client is silent. If Wi-Fi is up but not answering, the client moves to cellular and returns once Wi-Fi passes a check again.
- **Fast reconnect.** When the connection does die, a new handshake starts every second on a fresh socket, and the first one to finish wins.
- **Its own congestion control.** The window comes from the measured delivery rate and the minimum delay and does not react to random loss. The datagram queue is trimmed by waiting time (target 30 ms), so a weak uplink does not turn into seconds of latency.
- **Gets past the first-packet filter.** On three mobile operators out of three, a new UDP flow is cut if its first packet looks "too random" and falls into a certain size (details below). maski picks an initial connection ID with few one-bits and sends a short dummy datagram first on every new socket.
- **Small.** The tunnel extension on an iPhone takes 3.4–5.1 MB against an iOS limit of about 50 MB.

## What is included

**Server** (Linux): several users, each with an optional fixed tunnel address; a self-signed certificate checked on the client by its SHA-256 fingerprint.

**CLI client** (Linux, macOS): binding to an interface and a fallback interface.

**iOS app** (iOS 26+, SwiftUI, Packet Tunnel). The interface is in Russian:
- keep-connected (On Demand) and "cellular when Wi-Fi fails";
- "Russian sites direct": 10,000 routes that bypass the tunnel, with the list built by a script from `geoip.dat`;
- local network direct, custom subnets that bypass the tunnel, and auto-disconnect on chosen Wi-Fi networks;
- a latency chart with network changes marked, and a journal and logs that survive the app being killed;
- a profile is added by a `maski://add?…` link or a QR code.

A macOS app is in progress and is not in this repository yet. There is no IPv6 inside the tunnel.

## Measurements

Everything below is our own measurement from November 2026: the client is in Russia, the server is a VPS in Frankfurt. Operators are anonymized. Most rows have few runs (the count is given), so treat the numbers as an order of magnitude, not a benchmark.

### Throughput

One TCP stream inside the tunnel against the same stream without it, Mbit/s:

| Line | Down, tunnel / bare | Up, tunnel / bare | Runs |
|---|---|---|---|
| Home wired line, Mac | 216–244 / 270–301 | 229–308 / — | 3 × 8 s |
| LTE, operator A, modem | 53.5 / 58.8 | 16.5 / 13.3 | 1 |
| LTE, operator B (roaming SIM, traffic exits through the operator's home network), modem | 37.6 / 47.5 | 10.9 / 13.3 | 1 |
| LTE, operator C, modem | 52.9 / 53.3 | 15.0 / 15.0 | median of 3 pairs |
| LTE, operator A, iPhone, upload only | — | ratio 1.16 | median of 5 pairs |

- On iPhone Wi-Fi, download reaches about 200–250 Mbit/s. Upload through the tunnel tops out at 76–144 Mbit/s against 165–169 without it; the cause is not found yet.
- One connection on operator C moved 1.92 GB in 9 minutes with no cut and no slowdown by volume.

### Network changes and outages

| What | Result | Runs |
|---|---|---|
| Modem: 25 switches LTE ↔ 3G and between bands, a new address every time | the tunnel came back together with the radio; an extra pause happened once, 1.1 s; a long TCP connection inside survived everything | 5 passes |
| iPhone: Wi-Fi stopped answering, move to cellular | ping gap 1.5–1.9 s; iOS on its own took 6–8 s | 5 |
| iPhone: cellular → Wi-Fi | no gap | 1 pass |
| iPhone: 35 s without network, connection dead | back 0.78–0.84 s after the network returned | 2 |
| Modem: radio off for 4 s | back 2.6–3.4 s after the radio returned | 6 |
| Forced reconnect, three operators | 0.23–0.29 s | 3 each |
| iPhone: connect | 0.42–0.54 s; with the Russian route list, first traffic after 1.4–1.5 s | 3–6 |
| iPhone: screen locked for 5 minutes, cellular | the connection survived, about 15 KiB per minute each way | 2 |

### The first-packet filter

On all three operators a new UDP flow is cut after 2–3 packets if its first datagram has many one-bits in the first 16 bytes and, at the same time, its size falls into one of two ranges. In QUIC the first bytes are the header and a random connection ID, and quinn's first packet is 1400 bytes, so without a workaround part of the connections never come up.

| First QUIC packet | Connections established |
|---|---|
| random connection ID, as in stock quinn | 8 of 12 (two operators) |
| connection ID with many one-bits | 0 of 18 |
| the same, with a short dummy datagram before it | 15 of 18 |
| connection ID with few one-bits (maski's default) | 36 of 36 |

The rest is the same on the three operators: the address is behind CGNAT, an idle NAT binding is alive at 120 s and gone by 240 s, and a long flow is not cut.

## Comparison with xray MASQUE

Xray-core 26.11.9, `masque` inbound and outbound, the same server and the same lines, 10 November 2026. The comparison is not rigorous: xray is a proxy, not an L3 tunnel; the runs were at different hours and mostly single; maski here is an early build from the same day.

| | xray MASQUE | maski |
|---|---|---|
| Home line, one TCP stream | 26–31 Mbit/s | 216–244 Mbit/s |
| The same through the server's second address (behind GRE) | 4–52 Mbit/s | 267–290 Mbit/s |
| Home line, four streams in total | 120 Mbit/s | not measured |
| LTE, operator A, one stream | 16.1 Mbit/s | 26.2 Mbit/s |
| Network change on the modem: extra pause after the radio is back | 30.7–33.9 s in 5 of 7 cases | 0 s in 24 of 25, once 1.1 s |
| The same with `quicParams` (`maxIdleTimeout` 4, `keepAlivePeriod` 2) | 0–1.4 s in 8 of 8 | — |
| New connections under the first-packet filter, operator A | 20 of 20 | 36 of 36 on three operators |

- In xray, per-stream speed is limited by the window of its userspace TCP stack and grows with the number of streams; in maski, TCP stays with the application.
- By default an xray connection does not survive an address change and waits for its idle timeout; two client parameters fix that, as the table shows.
- quic-go's first packet is 1350 bytes and falls outside the filter's size ranges, so xray gets through with no special measures.
- **Interoperability:** the maski client connected to xray's `masque` inbound, and xray's `masque` outbound connected to the maski server. This was checked on an early build and not re-checked on the current one.

## Build and run

You need Rust. The server and the client are one binary:

```bash
cargo build --release
```

**Server** (Linux, as root):

```bash
cat > users <<'EOF'
# name   password   [fixed address]
admin    s3cret     10.90.0.2
friend   other-secret
EOF

maski server --listen 0.0.0.0:8445 --tun maski0 --addr 10.90.0.1/24 --mtu 1400 \
  --users users --cert-dir cert
```

On start the server creates a certificate in `cert/` and logs a line `certificate sha256 …`; that is the fingerprint for the client. Internet access is set up separately: `net.ipv4.ip_forward=1` and masquerade for the tunnel subnet.

Next to the certificate the server also keeps `cert/quic-keys` (the QUIC stateless-reset and connection-ID keys, mode 600). Keep it with the certificate: a restarted server then tells clients at once that their connection is gone, and they reconnect in about half a second instead of waiting for their 30 s idle timeout.

**Client** (as root, it creates the TUN device):

```bash
MASKI_PASS=s3cret maski client --server 203.0.113.10:8445 --pin <sha256> --user admin \
  --sni your.domain.example --interface en0
```

The client brings up the TUN device and one route into it (`--route`, the tunnel subnet by default). The rest of the traffic is sent into that interface with ordinary system routes; the iOS app does this itself.

To test new connections without a TUN device and without root, see `maski probe --help`. All flags are in `maski server --help` and `maski client --help`.

**SNI.** The TLS server name is visible on the wire. The defaults in the code are placeholders; set your own `--sni` and `--cert-name`, otherwise every installation looks the same.

**iOS.** You need Xcode, [xcodegen](https://github.com/yonaskolb/XcodeGen) and your own Apple developer team: replace `YOURTEAMID` and the `org.example` prefix in `ios/project.yml`. Then run `tools/build-apple.sh` and `ios/build.sh <udid>`; details are in [`ios/README.md`](ios/README.md).

## Layout

| File | What is there |
|---|---|
| `src/proto.rs` | CONNECT-IP capsules and wire format |
| `src/net.rs` | sockets, QUIC settings, the rate controller, the datagram queue |
| `src/client.rs` | client: path watching, moves to a new socket, fallback interface, reconnect |
| `src/server.rs`, `src/users.rs` | server, users and addresses |
| `src/tls.rs` | certificate and fingerprint check |
| `src/ffi.rs`, `include/maski.h` | C API for the tunnel extension |
| `ios/` | the app and the Packet Tunnel extension |
| `tools/ru_list.py` | builds and checks the Russian route list |
| `vendor/h3` | [h3](https://github.com/hyperium/h3) with one change: the `:protocol` value `connect-ip` |

## Known and not fixed

- The Wi-Fi upload ceiling through the tunnel on iPhone.
- After an outage, the first packet on a new socket is large and falls under the filter; only the dummy datagram protects it, and it misses about once in ten. The client then moves again.
- On a slow line (delay of 400 ms and more), reconnecting takes 2–3 s.
- iOS cannot exclude individual apps from the tunnel, only addresses and subnets.
- The measurement scripts and the lab setup are not in this repository.

## License

GNU AGPL version 3, see [LICENSE](LICENSE). `vendor/h3` is MIT, by the h3 authors (see `vendor/h3/LICENSE`).
