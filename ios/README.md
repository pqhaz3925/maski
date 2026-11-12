# maski iOS (app + Packet Tunnel extension)

SwiftUI app (iOS 26, Liquid Glass) and `NEPacketTunnelProvider` around `libmaski.a` (C API
`../include/maski.h`). Personal app: no onboarding, Russian UI. The screens follow the approved
design (`G-on`, `G-off`, `G-settings`, `G-log`, `Mark`).

## Build and install

```bash
../tools/build-apple.sh            # target/aarch64-apple-ios/apple/libmaski.a
./build.sh <device-udid>           # xcodegen + xcodebuild (automatic signing, team YOURTEAMID) + devicectl install
```

Automatic signing registers the App Group `group.org.example.maski` and the keychain group
`<team>.org.example.maski.shared` for both targets. `Config/server.json` (git-ignored, optional)
seeds the first profile «Мой сервер» into the Keychain on first launch:
`{"server":"IP:8445","pin":"<sha256 of the server cert>","user":"...","pass":"..."[,"sni":"..."]}`.

Reinstalling while «Держать надетой» (On Demand) is on can show «Не удаётся проверить приложение» on
the first launch: the install kills the extension, On Demand holds the traffic for the tunnel, and
the developer-certificate check needs the network. Cancel and open the app again (it recovered within
a minute in testing), or take the mask off before installing.

App icon: `swift ../tools/app_icon.swift App/Assets.xcassets/AppIcon.appiconset/icon-1024.png`.

## Profiles and the link format

Profiles (name, server, user, password, certificate pin, SNI) live in the Keychain (generic
passwords, service `org.example.maski.profile`, accessible after first unlock, this device only),
shared with the extension. The VPN configuration only carries the profile id. A profile is added from
a link, opened from anywhere or scanned as a QR code (Settings › «Добавить по ссылке или QR»):

```
maski://add?name=<name>&server=<host>:<port>&user=<user>&pass=<password>&pin=<sha256 hex>[&sni=<sni>]
```

Query values are percent-encoded UTF-8 (`name=My-server`); `server` is `IP:port`,
`[IPv6]:port` or `host:port` (a host name is resolved by the extension, outside the tunnel, at each
start); `pin` is the 64 hex digits of the server certificate's SHA-256; no `sni` = the library
default. A link for the same server, port and user replaces that profile. A profile's page has
«Поделиться ссылкой» (the same link, secrets included).

## Files in the App Group (`Library/maski/`)

| file | written by | what |
|---|---|---|
| `events.jsonl` | extension | journal: `on` (handshake ms), `off` (reason), `net` (from, to, pause ms), `rec`, `drop`, `restart`, `fail`; 256 KB + one rotated file |
| `tunnel.log` | extension | provider + library log, `<ms since 1970> <text>`; 2 MB + one rotated file (`tunnel.log.1`); every line is one write, so it survives a kill |
| `session.json` | extension | current session: RTT points (one per sampler tick, pairs averaged past 1200), network-type marks, changes, outages, inner bytes; saved every 10 s and on every event |
| `session-prev.json` | extension | the previous session (moved at the next start; one without a clean end is marked `unclean` and logs a `restart` event) |
| `samples.jsonl` | extension | only with «Писать подробно»: one sampler line per tick |

Copy them with `xcrun devicectl device copy from --domain-type appGroupDataContainer
--domain-identifier group.org.example.maski --source Library/maski --destination <dir>` (devicectl
only reaches `Library`, `Documents` and `tmp` of a group container).

«Писать подробно» switches the provider's extra lines and `samples.jsonl` at once; the library's
own level (debug instead of info) applies from the next start of the extension.

## Extension (`Tunnel/`)

- TUN mode `auto`: scan the process's descriptors for the utun control socket behind `packetFlow`
  (`tunfd.c`, as WireGuard does) and hand it to `maski_start` (Rust reads/writes utun itself); if none is
  found, callback mode (`readPackets` -> `maski_send_packets`, `packets_cb` -> `writePackets`).
  `tun=fd|callback` forces one.
- Outer sockets are pinned (`IP_BOUND_IF`, inside the library) to the physical interface
  `NWPathMonitor` reports (`en0` Wi-Fi, `pdp_ip0` cellular); every change of that interface calls
  `maski_network_changed(iface)`. `pin=0` leaves them unpinned, `nc=0` disables the call (dead-path
  detection alone).
- Fallback («Сотовая при сбое Wi-Fi», Автоматика, default on): two more `NWPathMonitor`s
  (`requiredInterfaceType` cellular / Wi-Fi) give the other usable interface (satisfied, not
  constrained = not in Low Data Mode, not the OS's current one); it goes to the library with
  `maski_set_alternates`. When the pinned interface is dead (sends fail as unreachable: at once;
  silence: one same-interface re-hop first, see `Client::detector` in `../src/client.rs`) the
  library moves the connection to that interface, probes the preferred one with a QUIC handshake
  (2, 4, 8, 15 s ...) and moves back on the first success; returns that die within 10 s raise a
  level that doubles the wait (up to 60 s). The OS's own path change always wins. Every such move
  arrives as `MASKI_EVENT_PATH` and is journalled as a network change with its pause and a
  reason line («нет ответа по Wi-Fi», «Wi-Fi недоступен», «Wi-Fi снова отвечает»); with the switch
  off the extension passes no alternates (the behaviour before).
- Network settings are applied when `MASKI_EVENT_CONNECTED` arrives: `route=full` (the app's
  default: default route, IPv6 default route into the tunnel and dropped there, DNS = the server's
  tunnel address, the pool's .1, which serves the work-domain routing, `dns` in the provider
  configuration overrides it) or
  `route=split` (10.90.0.0/24 only, test runs). Exclusions in full mode: «Локальная сеть напрямую»
  (10/8, 172.16/12, 192.168/16, 169.254/16, 224/4, broadcast, fe80::/10, fc00::/7, ff00::/8 - the
  tunnel's own /24 is included explicitly so it still wins over 10/8), «Мимо маски» (addresses /
  CIDRs) and «Российские сайты напрямую» (below). The app sends changed routes with an `apply`
  message and the extension re-applies them at once (the reply has the timing and footprint).
- Latency is the QUIC smoothed RTT (`MaskiStats.rtt_us`). Pauses: after a change of the physical
  interface, or when nothing has come from the server for 1.5 s, the extension polls `silent_ms`
  every 100 ms and records the longest silence until traffic flows again. Up to keepalive + 2 RTT
  counts as «без паузы». Network type: Wi-Fi, Ethernet, or the radio technology of the data SIM
  (LTE / 5G / 3G / 2G, CoreTelephony). Never the Wi-Fi name.
- Self-measurement every `sample` ms (default 2000) into a bounded ring: `phys_footprint` and its ledger peak
  (`TASK_VM_INFO`), `os_proc_available_memory()`, process CPU time (`getrusage`), wakeups
  (`TASK_POWER_INFO`), `maski_stats`. The app reads it with `handleAppMessage` (`snap`, `mark`,
  `drain`, `rate`, `netchange`, `session`, `apply`, `verbose`).

## «Российские сайты напрямую»

`Tunnel/ru4.txt` is `geoip:ru` from xray's `geoip.dat` (the copy used here: modified 2026-11-10, sha256
`283119b5c7679d3cc9a750e1b6da693ecfd42e5d5036b57f0c2d0505f76e36f4`), merged from 20 018 prefixes
into **10 000 supernets** by `../tools/ru_list.py`: every Russian address stays direct, plus 2.24 M
non-RU addresses that are in no other list of that geoip.dat (blocked, Telegram, Google, ...), not
special-purpose space and not announced by an AS of `../tools/ru_list_asn.txt` (curtained foreign
hosters, clouds). Why and what it costs: `../docs/ru-list-10k.md`. Regenerate and check:

```bash
cp /path/to/xray/geoip.dat /tmp/geoip.dat
curl -sO https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz
../tools/ru_list.py build /tmp/geoip.dat riswhoisdump.IPv4.gz > Tunnel/ru4.txt     # ~35 s
../tools/geoip_ru.py /tmp/geoip.dat RU > /tmp/ru4-20018.txt                       # the plain 20k list
../tools/ru_list.py check /tmp/geoip.dat riswhoisdump.IPv4.gz Tunnel/ru4.txt --old /tmp/ru4-20018.txt
```

`check` exits 1 unless every geoip:ru prefix (and every `--old` prefix) is covered, no forbidden
address is covered and there are at most 10 000 routes. The list goes into the first settings call
at connect (`ru_stage` = the old two-step apply, test only). With 10 000 routes, home Wi-Fi: the
settings call 1.3–1.8 s, live re-apply blackout 0.95–1.0 s, at connect steady traffic after
1.4–1.5 s with no stall, extension footprint ~5.1 MB after the apply, peak 6.2 MB (numbers in
`../docs/ru-list-10k.md`).

The plain list (before 2026-11-11 evening): 20018 IPv4 prefixes, 45.9 M addresses, all in
`excludedRoutes`. Measured on the iPhone 16 Pro (iOS 27.2), home Wi-Fi:

- applied live: `setTunnelNetworkSettings` 4.2-4.5 s (building the 20k routes 22-52 ms); at
  connect the tunnel is up after 4.9 s instead of ~0.5 s (handshake 145 ms + 4.5 s settings);
- extension footprint 3.7-3.9 MB -> 6.2-6.5 MB with the routes, lifetime peak 9.0-9.2 MB (limit
  ~50 MB); 6.4 MB during a 5 MB download at 70 Mbit/s;
- it works: with the switch on, ip.mail.ru (89.221.238.11, in the list) saw the home address and
  the tunnel received ~0 bytes for it; api.ipify.org still saw the server's address; the
  tunnel-side endpoint 10.90.0.1 still went through the tunnel.

The switch is shown (default off); `maski://test/debug?ru=0` hides it.

## Test drivers (`App/Driver.swift`)

`maski://test/<cmd>?k=v` (the old `maski://<cmd>?k=v` still works; launch argument
`-cmd "<cmd>?k=v"`); commands queue and each writes a JSON line to `Documents/results.jsonl`;
extension samples go to `ext.jsonl`, its log to `extlog.txt` (drained while a test is running),
pings to `ping-<tag>.txt`, long-download timelines to `tl-<tag>.txt`. Pull the container
(`devicectl` / Xcode / device-mcp `download_app_container`) and run `../tools/ios_an.py <Documents>`;
`../tools/ios_nc.py` takes the extension log (`Library/maski/tunnel.log` from the App Group, or
`extlog.txt`). Launch argument `-appearance light|dark` forces the appearance (screenshots).

| command | what |
|---|---|
| `install?route=&tun=&pin=&nc=&sample=&ka=&dead=&recover=&cc=&qms=&server=&thost=&fb=` | write the VPN configuration for a test run (current profile; default `route=split`, On Demand off). `server=IP:port` replaces the profile's server (e.g. `maski-dev` on 8446, test endpoint then 10.91.0.1 unless `thost=`), `cc` / `qms` the library's `cc` / `queue_ms`, `fb=0` no fallback |
| `connect`, `disconnect`, `mark`, `clear`, `rate?ms=` | |
| `down?bytes=&rate=&secs=&tag=[&host=][&ping=5]` / `up?...` | TCP to the test endpoint `:5201` (`rate` bit/s, 0 = unpaced); `ping=<hz>` echoes during the transfer (p50 / p95 / max); `host=` e.g. the server's public address for a bare baseline (outside a split tunnel); downloads write `tl-<tag>.txt` (bytes per 100 ms) |
| `ping?secs=&hz=5&tag=` | UDP echo to `10.90.0.1:7`, gaps >= 500 ms |
| `nc?secs=&rate=&tag=` | ping + one long paced download (network-change runs) |
| `cycles?n=&tag=` | n fresh connect / echo / disconnect cycles |
| `cping?secs=8&hz=20&tag=[&dns=1]` | connect with an echo already running (unconnected socket); `../tools/ios_cping.py` gives «connected», first echo, stalls after it, steady |
| `dns=1` (on `ping`, `routes`, `cping`) | the echo is a DNS query for a plain name to the test host's :53 (production's resolver answers it itself), so no `testsrv.py` is needed |
| `install?...&stage=1` | Russian routes in a second settings call after the tunnel is up (the old way; default 0) |
| `routes?ru=0\|1&local=0\|1[&ping=<s>&hz=<hz>][&run=<n>]` | set the route switches; connected: applied at once, result has timing + footprint; `ping` echoes during the apply (`../tools/ios_ru.py` finds the blackout); `run` applies only the n largest Russian prefixes, this apply only (test) |
| `ondemand?on=0\|1` | «Держать надетой» |
| `debug?ru=0\|1` | show / hide «Российские сайты напрямую» |
| `fetch?url=&tag=` | HTTP GET: status, IPv4s in the answer, inner bytes the tunnel received meanwhile |
| `session` | summary of the live (or last) session |
| `blackhole?iface=en0&mode=1` | **test hook**: the library drops (1) or fails as unreachable (2) all traffic of the sockets on that interface, present and future (probes too); 0 = off |
| `fbt?secs=&rate=&at=&for=&iface=en0&mode=1&tag=` | fallback run: ping + paced download (as `nc`) with the black hole on `iface` from `at` for `for` seconds; the result has the marks, `extlog.txt` the library's FALLBACK / PROBE / RETURN lines |

Server side: `maski server ... --addr 10.90.0.1/24` plus `../tools/testsrv.py 10.90.0.1 <logdir>`
(TCP sink/source with per-connection stall log `tcp.jsonl` including the peer address, UDP echo).
Bound to `0.0.0.0` it also answers on the server's public address: with that address in «Мимо маски»
the peer is the phone's own public address, without it `10.90.0.x`.
