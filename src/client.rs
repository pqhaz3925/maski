//! CONNECT-IP client engine: QUIC on an interface-pinned UDP socket, extended CONNECT for an IP
//! tunnel, HTTP datagrams both ways. Packet I/O is pluggable: a TUN device (CLI, or the utun fd an
//! Apple Network Extension hands over) or a callback (the extension's `packetFlow`).
//!
//! Path recovery (when nothing has arrived for `dead_ms`):
//! - `migrate`: QUIC connection migration to a fresh UDP socket (short-header packets only).
//! - `reconnect`: a fresh socket, a fresh QUIC connection (a real Initial) and a new CONNECT-IP
//!   request carrying an ADDRESS_REQUEST for the address we already have; the TUN device and
//!   every inner flow stay as they are, the server re-points that address at the new connection.
//! - `hybrid`: migrate first, reconnect if still silent after another `dead_ms`.
//!
//! `start` returns a [`Handle`] once the first connection is up; everything after that (recovery,
//! network changes, stats, stop) goes through the handle.
//!
//! Fallback to another interface (`Handle::set_alternates`): when the pinned (preferred) interface
//! is dead and another usable one is known, the connection migrates to a socket on that one; it
//! returns once a probe handshake on the preferred interface succeeds (see `Client::detector`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use h3::ext::Protocol;
use http::{Method, Request, StatusCode};

use crate::net::{self, KillableSocket, QuicTuning};
use crate::proto;

pub struct ClientOpts {
    pub server: SocketAddr,
    pub sni: String,
    /// Pin every outer socket to this interface; `Handle::network_changed` can replace it.
    pub interface: Option<String>,
    pub pin: String,
    pub user: String,
    pub pass: String,
    pub path: String,
    pub tuning: QuicTuning,
    /// Path-silence threshold for automatic recovery (0 = off).
    pub dead_ms: u64,
    pub stats_secs: u64,
    /// Block on the datagram send buffer instead of dropping the oldest datagram (TUN mode only).
    pub send_wait: bool,
    pub recover: String,
    pub attempt_ms: u64,
    pub remigrate_ms: u64,
    /// Give up on the first connection after this many attempts (each on a fresh socket).
    pub first_attempts: u32,
    /// Open every migration socket with a short throw-away datagram (see `net::send_primer`).
    pub primer: bool,
    /// Interfaces to fall back to when the pinned one is dead (`Handle::set_alternates`).
    pub alternates: Vec<String>,
    /// `migrate` mode: after this long with nothing received and moves done, also race fresh
    /// connections while the old one keeps its chance (`Client::race`; 0 = off).
    pub race_ms: u64,
}

/// Where packets from the server go.
#[derive(Clone)]
pub enum PacketOut {
    Tun(Arc<tun::AsyncDevice>),
    /// Called with a batch of IP packets (one call per burst that was ready at once).
    Callback(Arc<dyn Fn(&[&[u8]]) + Send + Sync>),
}

/// Bytes of headroom `Handle::send_buf` expects in front of the IP packet (datagram header).
pub const HEADROOM: usize = 8;
const BATCH: usize = 64;

/// One live QUIC connection carrying the CONNECT-IP session.
struct Active {
    ep: quinn::Endpoint,
    sock: Mutex<Arc<KillableSocket>>,
    conn: quinn::Connection,
    hdr: Vec<u8>,
    gen: u64,
    gate: net::TxGate,
}

#[derive(Default)]
struct Counters {
    tx_pkts: AtomicU64,
    tx_bytes: AtomicU64,
    rx_pkts: AtomicU64,
    rx_bytes: AtomicU64,
    migrations: AtomicU64,
    reconnects: AtomicU64,
    too_large: AtomicU64,
    dropped: AtomicU64,
    /// Refused by the send-queue gate (`net::TxGate`).
    queue_drops: AtomicU64,
    /// Moves to an alternate interface, returns to the preferred one, probes of the preferred one
    /// while on an alternate, and the failed ones among those probes.
    fallbacks: AtomicU64,
    returns: AtomicU64,
    probes: AtomicU64,
    probe_fails: AtomicU64,
    /// Reconnect races started while the old connection was kept (`Client::race`), and those
    /// abandoned because it came back.
    races: AtomicU64,
    race_aborts: AtomicU64,
}

/// First wait before probing the preferred interface after a fallback; doubles after every failed
/// probe up to `PROBE_CAP_MS`, and the first wait doubles with every level (a return that died
/// again soon) up to `PROBE_MAX_MS`. Failed probes cost nothing on the alternate; it is the
/// levels that stop a bouncing Wi-Fi from pulling the connection back every few seconds.
const PROBE_FIRST_MS: u64 = 2000;
/// Was 15 s: a Wi-Fi that answered again waited up to that long for the next probe (measured on
/// the phone: returns 6-15 s after the black hole ended). A failed probe of a dead interface
/// costs one handshake attempt there, nothing on the alternate.
const PROBE_CAP_MS: u64 = 8000;
/// An OS path update (`set_alternates`) while on an alternate probes the preferred interface at
/// once, at most this often.
const PROBE_EARLY_MIN_MS: u64 = 2000;
const PROBE_MAX_MS: u64 = 60_000;
/// A probe is a QUIC handshake on a fresh socket on the preferred interface; it fails after this,
/// and when its RTT is above max(2 x the alternate's RTT + 150 ms, `PROBE_SLOW_MS`).
const PROBE_TIMEOUT_MS: u64 = 1500;
const PROBE_SLOW_MS: u64 = 400;
/// Silence within this long of a return to the preferred interface means it did not really work:
/// back to the alternate at once, one level up.
const RETURN_VERIFY_MS: u64 = 10_000;
/// The level drops back to 0 once the preferred interface has held this long after a return.
const LEVEL_RESET_MS: u64 = 60_000;

/// Fallback state (all times ms since the client's epoch).
#[derive(Default)]
struct Fb {
    /// On an alternate interface since; `None` = on the preferred one.
    since: Option<u64>,
    /// Bumped on every fallback / return / external change; a probe of an older episode is void.
    episode: u64,
    next_probe: u64,
    probe_gap: u64,
    probe_cap: u64,
    probing: bool,
    level: u32,
    returned_at: Option<u64>,
    /// When the last probe started.
    last_probe_at: u64,
}

struct Client {
    o: ClientOpts,
    cc: quinn::ClientConfig,
    auth: String,
    epoch: Instant,
    last_rx: Arc<AtomicU64>,
    last_action: AtomicU64,
    bind: SocketAddr,
    interface: Mutex<Option<String>>,
    cur: Mutex<Option<Arc<Active>>>,
    out: Mutex<Option<PacketOut>>,
    addr: Mutex<Option<Ipv4Addr>>,
    recovering: AtomicBool,
    /// The running reconnect is a race next to a still-open connection: the detector keeps
    /// moving that one meanwhile.
    racing: AtomicBool,
    gen: AtomicU64,
    c: Counters,
    stopped: AtomicBool,
    /// Detector state reset request (network change): the next tick starts from scratch.
    reset: AtomicBool,
    /// Attempts and wall time the first connection took (`Handle::first_connect`).
    first: Mutex<(u32, u64)>,
    sock: Arc<net::SockStats>,
    /// The interface the OS reports as the path (`network_changed`); `interface` differs from it
    /// only while on an alternate.
    preferred: Mutex<Option<String>>,
    /// Other usable interfaces (from the OS; empty = no fallback).
    alternates: Mutex<Vec<String>>,
    fb: Mutex<Fb>,
    /// Test black holes per interface (mode, see `KillableSocket::hole`) and the sockets they
    /// apply to.
    holes: Mutex<Vec<(String, u8)>>,
    socks: Mutex<Vec<(String, Weak<KillableSocket>)>>,
    /// Time of the first datagram sent after the last receive (ms; <= last_rx = none waiting).
    tx_wait: AtomicU64,
    /// When the detector is due to wake next (ms), so `send` only wakes it when that is too late.
    wake_at: AtomicU64,
    /// Interface switches made by the client itself, as JSON (`Handle::set_event_sink`).
    on_event: Mutex<Option<Arc<dyn Fn(String) + Send + Sync>>>,
}

fn sock_str(s: &Arc<KillableSocket>) -> String {
    use quinn::AsyncUdpSocket;
    s.local_addr().map(|a| a.to_string()).unwrap_or_default()
}

/// Poll a future exactly once; `None` if it is not ready.
fn poll_once<F: std::future::Future>(f: F) -> Option<F::Output> {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match f.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => Some(v),
        std::task::Poll::Pending => None,
    }
}

impl Client {
    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    fn new_socket(&self, primer: bool) -> Result<Arc<KillableSocket>> {
        let iface = self.interface.lock().unwrap().clone();
        self.socket_on(iface.as_deref(), primer, self.last_rx.clone(), self.o.tuning.sockbuf)
    }

    /// A socket pinned to `iface`, receive times into `rx`; a test black hole of `iface` applies
    /// to it (the primer, too, is then not sent).
    fn socket_on(&self, iface: Option<&str>, primer: bool, rx: Arc<AtomicU64>, sockbuf: usize) -> Result<Arc<KillableSocket>> {
        let hole = iface.and_then(|i| self.holes.lock().unwrap().iter().find(|h| h.0 == i).map(|h| h.1)).unwrap_or(0);
        let s = net::udp_socket(self.bind, iface, sockbuf)?;
        if primer && hole == 0 {
            net::send_primer(&s, self.o.server);
        }
        let k = KillableSocket::new(s, rx, self.epoch, self.sock.clone())?;
        if let Some(i) = iface {
            k.hole.store(hole, Ordering::Relaxed);
            let mut v = self.socks.lock().unwrap();
            v.retain(|x| x.1.strong_count() > 0);
            v.push((i.to_string(), Arc::downgrade(&k)));
        }
        Ok(k)
    }

    fn emit(&self, json: String) {
        let f = self.on_event.lock().unwrap().clone();
        if let Some(f) = f {
            f(json);
        }
    }

    fn reset_rate(&self) {
        if let Some(r) = self.active().and_then(|a| net::rate_shared(&a.conn)) {
            r.reset.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// An alternate interface to fall back to now: only while on the preferred interface.
    fn alternate(&self) -> Option<String> {
        if self.fb.lock().unwrap().since.is_some() {
            return None;
        }
        let pref = self.preferred.lock().unwrap().clone()?;
        if self.interface.lock().unwrap().as_deref() != Some(pref.as_str()) {
            return None;
        }
        self.alternates.lock().unwrap().iter().find(|a| **a != pref).cloned()
    }

    /// Move to `alt` (the preferred interface is dead). `why`: silent | unreachable | failed_return.
    fn fallback(self: &Arc<Self>, alt: String, why: &str, silent: u64) {
        let now = self.now_ms();
        let from = self.interface.lock().unwrap().clone().unwrap_or_default();
        let (level, gap) = {
            let mut fb = self.fb.lock().unwrap();
            // A preferred interface that died again within LEVEL_RESET_MS of a return is bouncing
            // (the edge of Wi-Fi coverage: phone log 2026-11-11 15:08-15:12, four returns that each
            // held 10-100 s and cost a 1.3-2 s gap): one level up, so the next probe waits longer.
            let soon = fb.returned_at.is_some_and(|t| now.saturating_sub(t) <= LEVEL_RESET_MS);
            if fb.returned_at.is_some() && !soon {
                fb.level = 0;
            }
            if why == "failed_return" || soon {
                fb.level += 1;
            }
            fb.since = Some(now);
            fb.episode += 1;
            fb.probing = false;
            fb.probe_gap = (PROBE_FIRST_MS << fb.level.min(5)).min(PROBE_MAX_MS);
            fb.probe_cap = fb.probe_gap.max(PROBE_CAP_MS);
            fb.next_probe = now + fb.probe_gap;
            (fb.level, fb.probe_gap)
        };
        *self.interface.lock().unwrap() = Some(alt.clone());
        self.reset_rate();
        let n = self.c.fallbacks.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::info!("FALLBACK #{n} {from} -> {alt} ({why}, silent {silent} ms, level {level}, first probe in {gap} ms)");
        let r = if self.o.recover == "reconnect" {
            self.spawn_reconnect(format!("fallback to {alt}"));
            Ok(())
        } else {
            self.migrate(&format!("fallback to {alt}"))
        };
        if let Err(e) = r {
            tracing::warn!("fallback migrate failed: {e:#}");
        }
        self.emit(format!("{{\"from\":\"{from}\",\"to\":\"{alt}\",\"why\":\"{why}\",\"silent_ms\":{silent}}}"));
    }

    /// Back to the preferred interface (a probe there succeeded, or the alternate went away).
    fn return_to_preferred(self: &Arc<Self>, why: &str) {
        let Some(pref) = self.preferred.lock().unwrap().clone() else { return };
        let now = self.now_ms();
        let from = self.interface.lock().unwrap().clone().unwrap_or_default();
        let since = {
            let mut fb = self.fb.lock().unwrap();
            let s = fb.since.take();
            fb.episode += 1;
            fb.probing = false;
            fb.returned_at = Some(now);
            s
        };
        *self.interface.lock().unwrap() = Some(pref.clone());
        self.reset_rate();
        self.reset.store(true, Ordering::Release);
        let n = self.c.returns.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::info!("RETURN #{n} {from} -> {pref} ({why}) after {} ms on {from}", since.map_or(0, |s| now.saturating_sub(s)));
        if let Err(e) = self.migrate(&format!("return to {pref}")) {
            tracing::warn!("return migrate failed: {e:#}");
        }
        let silent = now.saturating_sub(self.last_rx.load(Ordering::Relaxed));
        self.emit(format!("{{\"from\":\"{from}\",\"to\":\"{pref}\",\"why\":\"{why}\",\"silent_ms\":{silent}}}"));
    }

    /// While on an alternate: start a probe of the preferred interface when it is due.
    fn fb_tick(self: &Arc<Self>, now: u64) -> Option<u64> {
        let pref = self.preferred.lock().unwrap().clone()?;
        let mut fb = self.fb.lock().unwrap();
        fb.since?;
        if fb.probing {
            return None;
        }
        if now < fb.next_probe {
            return Some(fb.next_probe);
        }
        fb.probing = true;
        fb.last_probe_at = now;
        let ep = fb.episode;
        drop(fb);
        let me = self.clone();
        tokio::spawn(async move { me.probe(pref, ep).await });
        None
    }

    /// A QUIC handshake on a fresh socket on `iface` (own receive clock, so it does not look like
    /// traffic of the tunnel). Success = the interface reaches the server both ways.
    async fn probe(self: Arc<Self>, iface: String, episode: u64) {
        let t0 = Instant::now();
        let n = self.c.probes.fetch_add(1, Ordering::Relaxed) + 1;
        let r: Result<Duration> = async {
            let sock = self.socket_on(Some(&iface), false, Arc::new(AtomicU64::new(0)), 256 * 1024)?;
            let ep = quinn::Endpoint::new_with_abstract_socket(net::endpoint_config(), None, sock, Arc::new(quinn::TokioRuntime))?;
            let conn = tokio::time::timeout(Duration::from_millis(PROBE_TIMEOUT_MS), ep.connect_with(self.cc.clone(), self.o.server, &self.o.sni)?)
                .await
                .map_err(|_| anyhow::anyhow!("timeout"))??;
            let rtt = conn.rtt();
            conn.close(0u32.into(), b"probe");
            // Let the CONNECTION_CLOSE go out, so the server does not keep it until its idle timeout.
            let _ = tokio::time::timeout(Duration::from_millis(100), ep.wait_idle()).await;
            // A handshake that completes is not enough: a much slower path than the alternate is
            // not worth returning to (measured through the modem: a 3G path with a 1.2 s handshake
            // RTT was accepted and died within a second).
            let alt = self.active().map_or(Duration::ZERO, |a| a.conn.rtt());
            let limit = (alt * 2 + Duration::from_millis(150)).max(Duration::from_millis(PROBE_SLOW_MS));
            if rtt > limit {
                bail!("too slow: rtt {rtt:?} > {limit:?} (alternate {alt:?})");
            }
            Ok(rtt)
        }
        .await;
        let now = self.now_ms();
        {
            let mut fb = self.fb.lock().unwrap();
            if fb.episode != episode || fb.since.is_none() {
                return;
            }
            fb.probing = false;
            if let Err(e) = &r {
                self.c.probe_fails.fetch_add(1, Ordering::Relaxed);
                fb.probe_gap = (fb.probe_gap * 2).min(fb.probe_cap);
                fb.next_probe = now + fb.probe_gap;
                tracing::info!("PROBE #{n} {iface}: failed after {:?} ({e:#}), next in {} ms", t0.elapsed(), fb.probe_gap);
                return;
            }
        }
        tracing::info!("PROBE #{n} {iface}: ok in {:?}, rtt {:?}", t0.elapsed(), r.as_ref().ok());
        self.return_to_preferred("probe");
    }

    fn active(&self) -> Option<Arc<Active>> {
        self.cur.lock().unwrap().clone()
    }

    /// Fresh socket + endpoint + QUIC handshake (one attempt of `establish`).
    async fn handshake(self: Arc<Self>) -> Result<Hs> {
        let t0 = Instant::now();
        // The first datagram here is the Initial, kept under the DPI line by the DCID choice.
        let sock = self.new_socket(false)?;
        let ep = quinn::Endpoint::new_with_abstract_socket(crate::net::endpoint_config(), None, sock.clone(),
            Arc::new(quinn::TokioRuntime))?;
        let conn = ep.connect_with(self.cc.clone(), self.o.server, &self.o.sni)?.await.context("QUIC handshake")?;
        Ok(Hs { ep, sock, conn, t0, t_quic: t0.elapsed() })
    }

    /// Connect: QUIC handshakes on fresh sockets, a new one every `attempt_ms`, each allowed to run
    /// `ATTEMPT_LIFE` x `attempt_ms` (at least 4 s); the first handshake that completes, and only that one, goes on
    /// to the CONNECT-IP request (`open_session`, its own time limit). The server re-assigns a user's
    /// address to the newest request and closes the older connection ("address taken over"), so two
    /// requests must never be in flight at once: while one is, handshakes that complete wait; if it
    /// fails, the next completed handshake (or the next to complete) gets its turn. What is left
    /// when one succeeds is dropped, and quinn closes those connections. `max_attempts`: give up
    /// after starting this many handshakes and seeing them all fail.
    ///
    /// Why both: with one attempt at a time a fixed 1 s allowance never got through a handshake
    /// plus request that needs more (RTT 500-700 ms in the lab; a weak cellular link on the phone,
    /// log 2026-11-11 14:58), and a growing allowance (`b16ba69`) left the attempt in flight when an
    /// outage ended waiting for quinn's Initial retransmission instead of starting fresh (~0.8 s
    /// slower in the lab at 60 ms RTT).
    async fn establish(self: &Arc<Self>, want: Option<Ipv4Addr>, max_attempts: Option<u32>, what: &str,
        guard: Option<&Guard>) -> Result<(Arc<Active>, Ipv4Addr, u32)> {
        let t0 = Instant::now();
        let mut check = tokio::time::interval(Duration::from_millis(100));
        let every = Duration::from_millis(self.o.attempt_ms.max(100));
        let life = (every * ATTEMPT_LIFE).max(Duration::from_millis(ATTEMPT_LIFE_MIN_MS));
        let mut set: tokio::task::JoinSet<(u32, Result<Hs>)> = tokio::task::JoinSet::new();
        let mut started: u32 = 0;
        let mut next_start = tokio::time::Instant::now();
        let mut ready: std::collections::VecDeque<(u32, Hs)> = Default::default();
        loop {
            if self.stopped.load(Ordering::Relaxed) {
                bail!("stopped");
            }
            if guard.is_some_and(|g| g.revived()) {
                return Err(self.race_lost(what, &mut ready, &mut set));
            }
            // One request at a time: the oldest completed handshake first.
            if let Some((n, hs)) = ready.pop_front() {
                let rtt = hs.conn.rtt();
                // A race next to an open connection: a fresh handshake got through, so the path
                // works now; give the old connection one more move and a round trip or two to
                // answer before its address is taken over (the server re-points the address to
                // the newest request and closes the older connection).
                if let Some(g) = guard.filter(|g| g.old.conn.close_reason().is_none()) {
                    if let Err(e) = self.migrate("race: a fresh handshake got through, last chance for the old connection") {
                        tracing::warn!("migrate failed: {e:#}");
                    }
                    let wait = (rtt * 2 + Duration::from_millis(100)).clamp(Duration::from_millis(300), Duration::from_millis(1500));
                    let until = tokio::time::Instant::now() + wait;
                    while tokio::time::Instant::now() < until && !g.revived() && g.old.conn.close_reason().is_none() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    if g.revived() {
                        ready.push_front((n, hs));
                        return Err(self.race_lost(what, &mut ready, &mut set));
                    }
                }
                let limit = (rtt * 4 + Duration::from_millis(500)).clamp(every, every * 3);
                let t_quic = hs.t_quic;
                let conn = hs.conn.clone();
                let mut sess = std::pin::pin!(tokio::time::timeout(limit, self.open_session(hs, want)));
                // Keep starting and collecting handshakes while the request runs.
                let r = loop {
                    let can_start = max_attempts.is_none_or(|m| started < m);
                    tokio::select! {
                        r = &mut sess => break r,
                        _ = check.tick(), if guard.is_some() => {}
                        _ = tokio::time::sleep_until(next_start), if can_start => {
                            started += 1;
                            next_start = tokio::time::Instant::now() + every;
                            self.start_attempt(&mut set, started, life);
                        }
                        Some(j) = set.join_next() => match j {
                            Ok((k, Ok(h))) => ready.push_back((k, h)),
                            Ok((k, Err(e))) => tracing::info!("{what} attempt {k} failed after {:?}: {e:#}", t0.elapsed()),
                            Err(_) => {}
                        },
                    }
                };
                match r {
                    Ok(Ok((act, ip))) => {
                        tracing::info!("{what}: attempt {n} of {started} won (quic {t_quic:?}, rtt {rtt:?}), {} more completed, {} in flight",
                            ready.len(), set.len());
                        // Dropping `ready` and `set` closes the rest (no request was sent on them).
                        for (_, h) in ready.drain(..) {
                            h.conn.close(0u32.into(), b"lost the race");
                        }
                        set.abort_all();
                        return Ok((act, ip, started));
                    }
                    Ok(Err(e)) => tracing::info!("{what} attempt {n}: request failed after {:?}: {e:#}", t0.elapsed()),
                    Err(_) => tracing::info!("{what} attempt {n}: request timed out ({limit:?})"),
                }
                conn.close(0u32.into(), b"request failed");
                continue;
            }
            let can_start = max_attempts.is_none_or(|m| started < m);
            if !can_start && set.is_empty() {
                bail!("no connection after {started} attempts");
            }
            tokio::select! {
                _ = tokio::time::sleep_until(next_start), if can_start => {
                    started += 1;
                    next_start = tokio::time::Instant::now() + every;
                    self.start_attempt(&mut set, started, life);
                }
                Some(j) = set.join_next() => match j {
                    Ok((k, Ok(h))) => ready.push_back((k, h)),
                    Ok((k, Err(e))) => tracing::info!("{what} attempt {k} failed after {:?}: {e:#}", t0.elapsed()),
                    Err(_) => {}
                },
                _ = check.tick(), if guard.is_some() => {}
            }
        }
    }

    /// The old connection answered during a race: drop the fresh handshakes (no request was sent
    /// on them, so the server's address assignment is untouched).
    fn race_lost(&self, what: &str, ready: &mut std::collections::VecDeque<(u32, Hs)>,
        set: &mut tokio::task::JoinSet<(u32, Result<Hs>)>) -> anyhow::Error {
        for (_, h) in ready.drain(..) {
            h.conn.close(0u32.into(), b"old connection came back");
        }
        set.abort_all();
        self.c.race_aborts.fetch_add(1, Ordering::Relaxed);
        tracing::info!("{what}: the old connection answered again, race abandoned");
        anyhow::anyhow!("old connection came back")
    }

    fn start_attempt(self: &Arc<Self>, set: &mut tokio::task::JoinSet<(u32, Result<Hs>)>, n: u32, life: Duration) {
        let me = self.clone();
        set.spawn(async move {
            let r = match tokio::time::timeout(life, me.handshake()).await {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!("handshake timed out ({life:?})")),
            };
            (n, r)
        });
    }

    /// CONNECT-IP on a connection whose handshake is done. `want` = the address to ask for.
    async fn open_session(self: &Arc<Self>, hs: Hs, want: Option<Ipv4Addr>) -> Result<(Arc<Active>, Ipv4Addr)> {
        let Hs { ep, sock, conn, t0, t_quic } = hs;
        let (mut driver, mut send_req) = h3::client::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
            .await?;
        tokio::spawn(async move {
            let e = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            tracing::debug!("h3 connection closed: {e}");
        });
        let uri = http::Uri::builder().scheme("https").authority(self.o.sni.as_str()).path_and_query(self.o.path.as_str()).build()?;
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("capsule-protocol", "?1")
            .header("authorization", &self.auth)
            .extension(Protocol::CONNECT_IP)
            .body(())?;
        let mut stream = send_req.send_request(req).await?;
        let ask = proto::Assigned { request_id: 1, ip: IpAddr::V4(want.unwrap_or(Ipv4Addr::UNSPECIFIED)), prefix: 32 };
        stream.send_data(Bytes::from(proto::address_request(&[ask]))).await?;
        let resp = stream.recv_response().await?;
        if resp.status() != StatusCode::OK {
            bail!("CONNECT-IP refused: {}", resp.status());
        }
        let sid = stream.id().into_inner();
        let mut cr = proto::CapsuleReader::default();
        let mut addr: Option<Ipv4Addr> = None;
        while addr.is_none() {
            let Some(mut d) = stream.recv_data().await? else { bail!("stream ended before ADDRESS_ASSIGN") };
            cr.push(&d.copy_to_bytes(d.remaining()));
            while let Some((t, p)) = cr.next() {
                log_capsule(t, &p);
                if t == proto::CAP_ADDRESS_ASSIGN {
                    for a in proto::parse_assign(&p).unwrap_or_default() {
                        if let IpAddr::V4(ip) = a.ip {
                            addr.get_or_insert(ip);
                        }
                    }
                }
            }
        }
        let addr = addr.unwrap();
        let gen = self.gen.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::info!("CONNECTED gen={gen} via {} local {} quic {:?} total {:?} rtt {:?} maxdg {:?} addr {addr}",
            conn.remote_address(), sock_str(&sock), t_quic, t0.elapsed(), conn.rtt(), conn.max_datagram_size());
        // Keep the h3 request handle and stream alive for the life of the connection.
        {
            let c2 = conn.clone();
            tokio::spawn(async move {
                let _keep = send_req;
                loop {
                    tokio::select! {
                        r = stream.recv_data() => match r {
                            Ok(Some(mut d)) => {
                                cr.push(&d.copy_to_bytes(d.remaining()));
                                while let Some((t, p)) = cr.next() { log_capsule(t, &p); }
                            }
                            _ => break,
                        },
                        _ = c2.closed() => break,
                    }
                }
                c2.closed().await;
            });
        }
        // Server -> packet output for this connection, in batches of what is ready at once.
        {
            let (conn, me) = (conn.clone(), self.clone());
            let q = sid / 4;
            // The reverse direction's load for the rate controller's min RTT expiry.
            let rs = net::rate_shared(&conn);
            tokio::spawn(async move {
                let mut batch: Vec<Bytes> = Vec::with_capacity(BATCH);
                while let Ok(d) = conn.read_datagram().await {
                    batch.push(d);
                    while batch.len() < BATCH {
                        match poll_once(conn.read_datagram()) {
                            Some(Ok(d)) => batch.push(d),
                            _ => break,
                        }
                    }
                    if let Some(r) = &rs {
                        r.rx_bytes.fetch_add(batch.iter().map(|d| d.len() as u64).sum(), Ordering::Relaxed);
                    }
                    me.deliver(q, &batch).await;
                    batch.clear();
                }
            });
        }
        let gate = net::TxGate::new(self.o.tuning.dgram_sndbuf, self.o.tuning.queue_ms);
        let act = Arc::new(Active { ep, sock: Mutex::new(sock), conn, hdr: proto::datagram_header(sid), gen, gate });
        Ok((act, addr))
    }

    async fn deliver(&self, q: u64, batch: &[Bytes]) {
        let out = self.out.lock().unwrap().clone();
        let mut pkts: Vec<&[u8]> = Vec::with_capacity(batch.len());
        for d in batch {
            match proto::parse_datagram(d) {
                Some((dq, 0, off)) if dq == q => pkts.push(&d[off..]),
                _ => tracing::debug!("foreign datagram"),
            }
        }
        self.c.rx_pkts.fetch_add(pkts.len() as u64, Ordering::Relaxed);
        self.c.rx_bytes.fetch_add(pkts.iter().map(|p| p.len() as u64).sum(), Ordering::Relaxed);
        match out {
            Some(PacketOut::Tun(tun)) => {
                for p in pkts {
                    let _ = tun.send(p).await;
                }
            }
            Some(PacketOut::Callback(f)) => f(&pkts),
            None => {
                self.c.dropped.fetch_add(pkts.len() as u64, Ordering::Relaxed);
            }
        }
    }

    fn migrate(&self, why: &str) -> Result<()> {
        let t0 = Instant::now();
        let a = self.active().context("not connected")?;
        let new = self.new_socket(self.o.primer)?;
        let old = std::mem::replace(&mut *a.sock.lock().unwrap(), new.clone());
        // quinn queues a PING on rebind, but it is congestion-controlled: after an outage the
        // stale in-flight bytes block it until a backed-off PTO (see net::MOVE_ALLOW_PKTS).
        if let Some(r) = net::rate_shared(&a.conn) {
            r.moved();
        }
        a.ep.rebind_abstract(new.clone())?;
        // What is still queued waited for a dead path, not behind a standing queue.
        a.gate.restart();
        // The old socket stays readable (quinn keeps polling it until the new one receives):
        // the server may still be answering on it, e.g. flushing held packets to the address it
        // learned just before this migration.
        self.last_action.store(self.now_ms(), Ordering::Relaxed);
        let n = self.c.migrations.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::info!("MIGRATE #{n} ({why}) gen={} {} -> {} in {:?}", a.gen, sock_str(&old), sock_str(&new), t0.elapsed());
        Ok(())
    }

    /// Start a reconnect unless one is already running.
    fn spawn_reconnect(self: &Arc<Self>, why: String) {
        if self.recovering.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move { me.reconnect(why, None).await });
    }

    /// A reconnect race next to the current connection, which stays in use (and keeps being
    /// moved by the detector) until a new session is up; abandoned if it answers again first.
    ///
    /// Why: when the server restarts it has no state for the connection. Without the server's old
    /// keys (`tls::load_or_create_endpoint_keys`: an older server binary, a lost key file) it
    /// drops our packets without a word, which looks exactly like a dead radio path, so `migrate`
    /// re-hopped until the 30 s idle timeout (measured: traffic back 25.3 s after a 5 s restart).
    /// A plain outage must still end in a migration that keeps the server's session, held
    /// packets and all: so the request on a fresh connection is only sent while the old one has
    /// heard nothing since the race began, and only after one more move of it has gone
    /// unanswered (see `establish`).
    fn race(self: &Arc<Self>, why: String) {
        let Some(old) = self.active() else { return };
        if self.recovering.swap(true, Ordering::AcqRel) {
            return;
        }
        self.racing.store(true, Ordering::Release);
        let n = self.c.races.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::info!("RACE #{n} start ({why})");
        let g = Guard { base: auth_rx(&old.conn), old };
        let me = self.clone();
        tokio::spawn(async move { me.reconnect(why, Some(g)).await });
    }

    /// Replace the connection (`establish`: racing handshakes, one request at a time).
    async fn reconnect(self: &Arc<Self>, why: String, guard: Option<Guard>) {
        let t0 = Instant::now();
        let want = *self.addr.lock().unwrap();
        tracing::info!("RECONNECT start ({why})");
        match self.establish(want, None, "RECONNECT", guard.as_ref()).await {
            Ok((act, ip, attempts)) => {
                if Some(ip) != want {
                    tracing::warn!("server assigned {ip} instead of {want:?}: inner flows will break");
                }
                if let Some(old) = std::mem::replace(&mut *self.cur.lock().unwrap(), Some(act.clone())) {
                    old.sock.lock().unwrap().dead.store(true, Ordering::Relaxed);
                    old.conn.close(0u32.into(), b"replaced");
                }
                let n = self.c.reconnects.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::info!("RECONNECT #{n} done gen={} after {attempts} attempt(s) in {:?}", act.gen, t0.elapsed());
            }
            Err(e) => tracing::info!("RECONNECT ended: {e:#}"),
        }
        self.last_action.store(self.now_ms(), Ordering::Relaxed);
        self.racing.store(false, Ordering::Release);
        self.recovering.store(false, Ordering::Release);
    }

    fn send(&self, mut b: BytesMut, n: usize) {
        let Some(a) = self.active() else {
            self.c.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let hl = a.hdr.len();
        b[HEADROOM - hl..HEADROOM].copy_from_slice(&a.hdr);
        b.truncate(HEADROOM + n);
        let _ = b.split_to(HEADROOM - hl);
        // The first datagram after the last receive starts the "sent, nothing back" clock of the
        // detector's fast check; wake the detector if it would otherwise sleep past that check.
        if self.tx_wait.load(Ordering::Relaxed) <= self.last_rx.load(Ordering::Relaxed) {
            let now = self.now_ms();
            self.tx_wait.store(now, Ordering::Relaxed);
            if now + FAST_MIN_MS < self.wake_at.load(Ordering::Relaxed) {
                self.sock.wake.notify_one();
            }
        }
        match a.gate.send(&a.conn, b.freeze()) {
            net::GateResult::Sent => {
                self.c.tx_pkts.fetch_add(1, Ordering::Relaxed);
                self.c.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
            }
            net::GateResult::Dropped => { self.c.queue_drops.fetch_add(1, Ordering::Relaxed); }
            net::GateResult::Err(quinn::SendDatagramError::TooLarge) => { self.c.too_large.fetch_add(1, Ordering::Relaxed); }
            net::GateResult::Err(e) => {
                self.c.dropped.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("send_datagram: {e}");
            }
        }
    }

    /// The path-silence detector: migrate / reconnect when nothing has arrived for dead_ms, and
    /// fall back to another interface when the pinned one is dead.
    ///
    /// While the path is healthy it sleeps until the silence deadline (at most 1 s, at least
    /// 20 ms) instead of polling every 20 ms (it still polls during a recovery): a 20 ms tick is 50
    /// wakeups a second on an idle phone (measured on iOS: ~72 interrupt wakeups/s with the screen
    /// locked). Waking early is harmless: the deadline only moves later as datagrams arrive. A
    /// socket reporting an unreachable interface, and the first datagram sent after a receive when
    /// the detector sleeps past the fast check, wake it early (`SockStats::wake`).
    ///
    /// Dead path, in this order:
    /// 1. Sends fail with an "unreachable" errno on the current socket (the interface lost its
    ///    address or route; seen as EADDRNOTAVAIL, then ENETUNREACH, when walking out of Wi-Fi
    ///    range) and an alternate is known: fall back at once; a new socket on the same interface
    ///    fails the same way.
    /// 2. Silence: nothing received for `dead_ms`, or (fast check, traffic flowing, and the socket
    ///    in use for at least `FAST_SETTLE_MS`) datagrams sent and nothing received for
    ///    `fast` = clamp(3 x srtt + 300 ms, 700 ms, dead_ms). First a
    ///    re-hop to a fresh socket on the same interface (that is what revives a flow the mobile
    ///    operator's NAT/DPI killed, and a socket stuck after the phone slept); if that brings
    ///    nothing within clamp(2 x srtt + 200 ms, 400 ms, 1 s), fall back. Within
    ///    `RETURN_VERIFY_MS` of a return the re-hop is skipped (the alternate worked just now).
    /// 3. On the alternate, the usual re-hops (each also probes the preferred interface at once:
    ///    the alternate itself is silent then); the preferred interface is probed with a QUIC
    ///    handshake on a fresh socket 2 s after the fallback, then at doubling gaps up to 15 s.
    ///    Each return that went silent within 10 s raises the level, which doubles the first
    ///    wait (and the cap) up to 60 s; the level drops to 0 after 60 s on the preferred
    ///    interface. The first probe that succeeds moves the connection back. A network change
    ///    from the OS ends it all.
    async fn detector(self: Arc<Self>) {
        const MIN_SLEEP: u64 = 20;
        const MAX_SLEEP: u64 = 1000;
        let mut next = MIN_SLEEP;
        // Consecutive recovery actions without anything received in between; the spacing
        // between them backs off dead_ms, 2*dead_ms, ... up to max(dead_ms, 1 s) so a long
        // radio outage does not churn a socket every dead_ms.
        let mut k: u32 = 0;
        // After an outage the path that comes back first is often killed again by the
        // operator's NAT within a second; hop once more to a socket born after the radio
        // returned, `remigrate_ms` after traffic resumes (0 = off).
        let mut remigrate_at: Option<u64> = None;
        // No post-outage re-hop after a fallback: the alternate's radio was not out.
        let mut skip_rehop = false;
        while !self.stopped.load(Ordering::Relaxed) {
            self.wake_at.store(self.now_ms() + next, Ordering::Relaxed);
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(next)) => {}
                _ = self.sock.wake.notified() => {}
            }
            next = MIN_SLEEP;
            if self.reset.swap(false, Ordering::AcqRel) {
                k = 0;
                remigrate_at = None;
                skip_rehop = false;
            }
            // A race (`Client::race`) keeps the old connection: keep moving it meanwhile.
            if self.recovering.load(Ordering::Acquire) && !self.racing.load(Ordering::Acquire) {
                continue;
            }
            // A connection that is already closed (idle timeout after a long outage or a device
            // sleep, or closed by the server) cannot be migrated: replace it in every mode.
            let Some(a) = self.active() else { continue };
            if let Some(r) = a.conn.close_reason() {
                self.spawn_reconnect(format!("connection closed: {r}"));
                continue;
            }
            let now = self.now_ms();
            let last_rx = self.last_rx.load(Ordering::Relaxed);
            let last_act = self.last_action.load(Ordering::Relaxed);
            if last_rx > last_act {
                if k > 0 && !skip_rehop && self.o.remigrate_ms > 0 && self.o.recover != "reconnect" {
                    remigrate_at = Some(now + self.o.remigrate_ms);
                }
                k = 0;
                skip_rehop = false;
            }
            if let Some(at) = remigrate_at {
                if now >= at {
                    remigrate_at = None;
                    if let Err(e) = self.migrate("post-outage re-hop") { tracing::warn!("migrate failed: {e:#}"); }
                    self.last_rx.store(now, Ordering::Relaxed);
                    continue;
                }
            }
            let probe_due = self.fb_tick(now);
            let silent = now.saturating_sub(last_rx);
            let srtt = a.conn.rtt().as_millis() as u64;
            let fast = (3 * srtt + 300).clamp(FAST_MIN_MS, self.o.dead_ms.max(FAST_MIN_MS));
            let tx_wait = self.tx_wait.load(Ordering::Relaxed);
            let waiting = if tx_wait > last_rx { now.saturating_sub(tx_wait) } else { 0 };
            let unreach = a.sock.lock().unwrap().unreach_at.load(Ordering::Relaxed) > last_rx;
            let alt = self.alternate();
            // 1. The interface cannot reach anything: straight to the alternate.
            if unreach {
                if let Some(alt) = alt {
                    self.fallback(alt, "unreachable", silent);
                    k = k.max(1) + 1;
                    skip_rehop = true;
                    continue;
                }
            }
            let gap = (self.o.dead_ms << k.min(6)).min(self.o.dead_ms.max(1000));
            let since_act = now.saturating_sub(last_act);
            // Moves have not helped for race_ms: maybe the server lost the connection (restart).
            if k >= 1 && self.o.race_ms > 0 && self.o.recover == "migrate" && silent >= self.o.race_ms
                && !self.recovering.load(Ordering::Acquire) {
                self.race(format!("path silent {silent} ms after {k} action(s)"));
            }
            // 2. The first action: silence past dead_ms, or past `fast` while sending.
            if k == 0 {
                // The fast check only on a settled socket: right after a move the RTT estimate is the
                // old path's and a new cellular flow can take a second to pass its first packets
                // (measured through the modem: a 700 ms fast check then re-hopped every 1.5 s).
                let settled = since_act >= FAST_SETTLE_MS;
                let dead = (silent > self.o.dead_ms && since_act > gap) || (settled && waiting >= fast);
                if !dead {
                    let mut due = (last_rx + self.o.dead_ms + 1).max(last_act + gap + 1);
                    if tx_wait > last_rx {
                        due = due.min((tx_wait + fast).max(last_act + FAST_SETTLE_MS));
                    }
                    if let Some(p) = probe_due {
                        due = due.min(p);
                    }
                    if remigrate_at.is_none() {
                        next = due.saturating_sub(now).clamp(MIN_SLEEP, MAX_SLEEP);
                    }
                    continue;
                }
                let returned = self.fb.lock().unwrap().returned_at.is_some_and(|t| now.saturating_sub(t) < RETURN_VERIFY_MS);
                if let (true, Some(alt)) = (returned, alt.clone()) {
                    self.fallback(alt, "failed_return", silent);
                    k = 2;
                    skip_rehop = true;
                    continue;
                }
                let why = if silent > self.o.dead_ms { format!("path silent {silent} ms, action 1") }
                    else { format!("sent {waiting} ms ago, nothing back (fast {fast} ms), action 1") };
                self.act(&why);
                k = 1;
                continue;
            }
            // Still silent after a same-interface re-hop: fall back if there is somewhere to go.
            if k == 1 {
                if let Some(alt) = alt {
                    let wait = (2 * srtt + 200).clamp(400, 1000);
                    if since_act >= wait {
                        self.fallback(alt, "silent", silent);
                        k = 2;
                        skip_rehop = true;
                    }
                    continue;
                }
            }
            if silent <= self.o.dead_ms || since_act <= gap {
                continue;
            }
            // Silent on the alternate as well: try the preferred interface now rather than at
            // the next backoff step (a probe of a dead interface costs nothing).
            {
                let mut fb = self.fb.lock().unwrap();
                if fb.since.is_some() && !fb.probing && fb.next_probe > now {
                    fb.next_probe = now;
                }
            }
            self.act(&format!("path silent {silent} ms, action {}", k + 1));
            k += 1;
        }
    }

    /// One recovery action on the current interface, by `recover` mode (hybrid: migrate first).
    fn act(self: &Arc<Self>, why: &str) {
        let mode = self.o.recover.as_str();
        let first = !why.contains("action ") || why.ends_with("action 1");
        if mode == "migrate" || (mode == "hybrid" && first) {
            if let Err(e) = self.migrate(why) { tracing::warn!("migrate failed: {e:#}"); }
        } else {
            self.spawn_reconnect(why.to_string());
        }
    }
}

/// Lower bound of the fast dead-path check (datagrams sent, nothing received), ms.
const FAST_MIN_MS: u64 = 700;
/// The fast check applies only this long after the last recovery action / move.
const FAST_SETTLE_MS: u64 = 5000;

/// Counters and path state of a running client.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub connected: bool,
    pub gen: u64,
    pub tx_pkts: u64,
    pub tx_bytes: u64,
    pub rx_pkts: u64,
    pub rx_bytes: u64,
    pub migrations: u64,
    pub reconnects: u64,
    pub too_large: u64,
    pub dropped: u64,
    pub rtt_us: u64,
    pub path_mtu: u16,
    pub lost_pkts: u64,
    pub udp_tx_bytes: u64,
    pub udp_rx_bytes: u64,
    /// Milliseconds since anything arrived from the server.
    pub silent_ms: u64,
    /// QUIC packets sent on the current connection (denominator for `lost_pkts`).
    pub sent_pkts: u64,
    /// Outer UDP sends that failed with ENOBUFS (interface queue full; the packet is gone).
    pub sock_nobufs: u64,
    /// Other failed outer UDP sends (also gone).
    pub sock_errors: u64,
    /// Outer UDP sends that found the socket not writable (quinn keeps the packet and waits).
    pub sock_blocked: u64,
    /// Packets refused because the send queue was older than its target (`net::TxGate`).
    pub queue_drops: u64,
    /// Rate controller: delivery-rate estimate (bit/s) and window (bytes); 0 with other controllers.
    pub bw_bps: u64,
    pub cwnd: u64,
    /// Fallbacks to an alternate interface, returns to the preferred one, probes (failed ones).
    pub fallbacks: u64,
    pub returns: u64,
    pub probes: u64,
    pub probe_fails: u64,
    /// Currently on an alternate interface.
    pub on_alternate: bool,
}

/// Control surface of a running client. Cheap to clone; all methods are thread-safe. Methods that
/// spawn work (`network_changed`, `reconnect`) must be called from inside the client's runtime or
/// through `Handle::spawn_on`.
#[derive(Clone)]
pub struct Handle {
    c: Arc<Client>,
    rt: tokio::runtime::Handle,
}

impl Handle {
    /// The inner (tunnel) address the server assigned.
    pub fn addr(&self) -> Ipv4Addr {
        self.c.addr.lock().unwrap().expect("connected")
    }

    /// Largest IP packet that currently fits in one datagram.
    pub fn max_packet(&self) -> Option<usize> {
        let a = self.c.active()?;
        Some(a.conn.max_datagram_size()?.saturating_sub(a.hdr.len()))
    }

    /// How many attempts (each on a fresh socket) the first connection needed, and its time in ms.
    pub fn first_connect(&self) -> (u32, u64) {
        *self.c.first.lock().unwrap()
    }

    pub fn set_output(&self, out: Option<PacketOut>) {
        *self.c.out.lock().unwrap() = out;
    }

    /// Send one IP packet to the server (copies it once into a datagram buffer).
    pub fn send_packet(&self, pkt: &[u8]) {
        let mut b = BytesMut::with_capacity(HEADROOM + pkt.len());
        b.resize(HEADROOM, 0);
        b.extend_from_slice(pkt);
        self.c.send(b, pkt.len());
    }

    /// Send an IP packet of `n` bytes that sits at `b[HEADROOM..HEADROOM + n]` (no copy).
    pub fn send_buf(&self, b: BytesMut, n: usize) {
        self.c.send(b, n);
    }

    /// Wait for room in the datagram send buffer, then send (TUN mode, `--send-wait`).
    pub async fn send_buf_wait(&self, mut b: BytesMut, n: usize) {
        let Some(a) = self.c.active() else { return };
        let hl = a.hdr.len();
        b[HEADROOM - hl..HEADROOM].copy_from_slice(&a.hdr);
        b.truncate(HEADROOM + n);
        let _ = b.split_to(HEADROOM - hl);
        if a.conn.send_datagram_wait(b.freeze()).await.is_ok() {
            self.c.c.tx_pkts.fetch_add(1, Ordering::Relaxed);
            self.c.c.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    pub fn send_wait(&self) -> bool {
        self.c.o.send_wait
    }

    /// Move the connection to a fresh socket now (optionally pinned to a new interface) and
    /// restart the path detector, as after any other recovery action. `interface`: `Some("")`
    /// unpins, `None` keeps the current pin.
    pub fn network_changed(&self, interface: Option<&str>) {
        // The OS's choice wins over a fallback of ours. If it moved to where we already are
        // (e.g. cellular after we fell back to it), stay on the working socket.
        let ended = {
            let mut fb = self.c.fb.lock().unwrap();
            let on_alt = fb.since.take().is_some();
            if on_alt {
                fb.episode += 1;
                fb.probing = false;
            }
            on_alt
        };
        if let Some(i) = interface {
            let new = if i.is_empty() { None } else { Some(i.to_string()) };
            *self.c.preferred.lock().unwrap() = new.clone();
            if ended && new.is_some() && *self.c.interface.lock().unwrap() == new {
                tracing::info!("network changed to {i}: already there (fallback), staying on the current socket");
                self.c.reset.store(true, Ordering::Release);
                return;
            }
            *self.c.interface.lock().unwrap() = new;
        } else if ended {
            let p = self.c.preferred.lock().unwrap().clone();
            *self.c.interface.lock().unwrap() = p;
        }
        self.c.reset.store(true, Ordering::Release);
        // A different network: the old min RTT and rate say nothing about the new path.
        self.c.reset_rate();
        let c = self.c.clone();
        let _g = self.rt.enter();
        if let Err(e) = c.migrate("network changed") {
            tracing::warn!("migrate failed: {e:#}");
        }
    }

    /// Other usable interfaces (the OS's view; empty = no fallback). While on an alternate that is
    /// no longer listed, go back to the preferred interface.
    pub fn set_alternates(&self, list: &[String]) {
        let list: Vec<String> = list.iter().filter(|s| !s.is_empty()).cloned().collect();
        tracing::info!("alternates {list:?}");
        *self.c.alternates.lock().unwrap() = list.clone();
        let gone = {
            let mut fb = self.c.fb.lock().unwrap();
            let gone = fb.since.is_some() && !self.c.interface.lock().unwrap().as_ref().is_some_and(|i| list.contains(i));
            // The OS saw some path change while we are on an alternate: the preferred interface may
            // work again, probe it now rather than at the next step of the schedule.
            let now = self.c.now_ms();
            if !gone && fb.since.is_some() && !fb.probing && fb.next_probe > now
                && now.saturating_sub(fb.last_probe_at) >= PROBE_EARLY_MIN_MS {
                fb.next_probe = now;
                self.c.sock.wake.notify_one();
                tracing::info!("path update while on an alternate: probing the preferred interface now");
            }
            gone
        };
        if gone {
            let _g = self.rt.enter();
            self.c.return_to_preferred("alt_gone");
        }
    }

    /// Interface switches the client makes itself (fallback / return) as one JSON object each:
    /// {"from","to","why","silent_ms"}; `why` = unreachable | silent | failed_return | probe | alt_gone.
    pub fn set_event_sink(&self, f: Option<Arc<dyn Fn(String) + Send + Sync>>) {
        *self.c.on_event.lock().unwrap() = f;
    }

    /// TEST HOOK: black-hole `interface` (None = the current pin) for every socket on it, present
    /// and future (probes included), to simulate "Wi-Fi associated but dead". mode 0 off, 1 drop
    /// everything silently, 2 sends fail as unreachable.
    pub fn test_blackhole(&self, interface: Option<&str>, mode: u8) {
        let Some(i) = interface.map(str::to_string).or_else(|| self.c.interface.lock().unwrap().clone()) else { return };
        {
            let mut h = self.c.holes.lock().unwrap();
            h.retain(|x| x.0 != i);
            if mode != 0 {
                h.push((i.clone(), mode));
            }
        }
        let mut n = 0;
        for (si, w) in self.c.socks.lock().unwrap().iter() {
            if *si == i {
                if let Some(k) = w.upgrade() {
                    k.hole.store(mode, Ordering::Relaxed);
                    n += 1;
                }
            }
        }
        tracing::info!("TEST blackhole {i} mode {mode} ({n} live sockets)");
    }

    pub fn migrate(&self, why: &str) {
        let _g = self.rt.enter();
        if let Err(e) = self.c.migrate(why) {
            tracing::warn!("migrate failed: {e:#}");
        }
    }

    /// Black-hole the current socket (simulated path death, for tests).
    pub fn kill_current(&self) {
        if let Some(a) = self.c.active() {
            let s = a.sock.lock().unwrap().clone();
            s.dead.store(true, Ordering::Relaxed);
            tracing::info!("KILL path on socket {} (all its traffic is now dropped)", sock_str(&s));
        }
    }

    pub fn reconnect(&self, why: &str) {
        let _g = self.rt.enter();
        self.c.spawn_reconnect(why.to_string());
    }

    pub fn stats(&self) -> Stats {
        let c = &self.c.c;
        let mut s = Stats {
            tx_pkts: c.tx_pkts.load(Ordering::Relaxed),
            tx_bytes: c.tx_bytes.load(Ordering::Relaxed),
            rx_pkts: c.rx_pkts.load(Ordering::Relaxed),
            rx_bytes: c.rx_bytes.load(Ordering::Relaxed),
            migrations: c.migrations.load(Ordering::Relaxed),
            reconnects: c.reconnects.load(Ordering::Relaxed),
            too_large: c.too_large.load(Ordering::Relaxed),
            dropped: c.dropped.load(Ordering::Relaxed),
            silent_ms: self.c.now_ms().saturating_sub(self.c.last_rx.load(Ordering::Relaxed)),
            ..Default::default()
        };
        if let Some(a) = self.c.active() {
            let q = a.conn.stats();
            s.connected = a.conn.close_reason().is_none();
            s.gen = a.gen;
            s.rtt_us = q.path.rtt.as_micros() as u64;
            s.path_mtu = q.path.current_mtu;
            s.lost_pkts = q.path.lost_packets;
            s.udp_tx_bytes = q.udp_tx.bytes;
            s.udp_rx_bytes = q.udp_rx.bytes;
            s.sent_pkts = q.path.sent_packets;
            s.cwnd = q.path.cwnd;
            if let Some(r) = net::rate_shared(&a.conn) {
                s.bw_bps = r.bw.load(Ordering::Relaxed) * 8;
            }
        }
        s.queue_drops = c.queue_drops.load(Ordering::Relaxed);
        s.sock_nobufs = self.c.sock.nobufs.load(Ordering::Relaxed);
        s.sock_errors = self.c.sock.other_err.load(Ordering::Relaxed);
        s.sock_blocked = self.c.sock.blocked.load(Ordering::Relaxed);
        s.fallbacks = c.fallbacks.load(Ordering::Relaxed);
        s.returns = c.returns.load(Ordering::Relaxed);
        s.probes = c.probes.load(Ordering::Relaxed);
        s.probe_fails = c.probe_fails.load(Ordering::Relaxed);
        s.on_alternate = self.c.fb.lock().unwrap().since.is_some();
        s
    }

    pub fn stats_line(&self) -> String {
        match self.c.active() {
            Some(a) => format!("STATS gen={} {} accepted={} queue_drops={} migrations={} reconnects={} races={} race_aborts={} too_large_drops={} {}", a.gen,
                net::stats_line(&a.conn), self.c.c.tx_pkts.load(Ordering::Relaxed), self.c.c.queue_drops.load(Ordering::Relaxed),
                self.c.c.migrations.load(Ordering::Relaxed), self.c.c.reconnects.load(Ordering::Relaxed),
                self.c.c.races.load(Ordering::Relaxed), self.c.c.race_aborts.load(Ordering::Relaxed),
                self.c.c.too_large.load(Ordering::Relaxed), self.c.sock.line()),
            None => "STATS not connected".into(),
        }
    }

    /// Close the connection and stop the background tasks (they exit within one detector tick).
    pub fn stop(&self) {
        self.c.stopped.store(true, Ordering::Relaxed);
        *self.c.out.lock().unwrap() = None;
        if let Some(a) = self.c.cur.lock().unwrap().take() {
            a.conn.close(0u32.into(), b"stop");
        }
    }
}

pub fn client_config(t: &QuicTuning, pin: &str) -> Result<quinn::ClientConfig> {
    let provider = crate::tls::provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(crate::tls::PinVerifier::new(pin, provider)?)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut cc = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?));
    cc.transport_config(Arc::new(net::transport(t)?));
    if let Some(f) = net::dcid_provider(t.dcid) {
        cc.initial_dst_cid_provider(f);
    }
    Ok(cc)
}

/// Connect (retrying on fresh sockets) and start the background tasks. Must run inside a tokio
/// runtime; the tasks live on that runtime.
pub async fn start(o: ClientOpts) -> Result<Handle> {
    let cc = client_config(&o.tuning, &o.pin)?;
    let auth = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", o.user, o.pass)));
    let bind: SocketAddr = if o.server.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    if !matches!(o.recover.as_str(), "migrate" | "reconnect" | "hybrid") {
        bail!("recover must be migrate|reconnect|hybrid");
    }
    let me = Arc::new(Client {
        cc, auth, epoch: Instant::now(), last_rx: Arc::new(AtomicU64::new(0)), last_action: AtomicU64::new(0), bind,
        interface: Mutex::new(o.interface.clone()), cur: Mutex::new(None), out: Mutex::new(None), addr: Mutex::new(None),
        recovering: AtomicBool::new(false), racing: AtomicBool::new(false), gen: AtomicU64::new(0), c: Counters::default(), stopped: AtomicBool::new(false),
        reset: AtomicBool::new(false), first: Mutex::new((0, 0)), sock: Default::default(),
        preferred: Mutex::new(o.interface.clone()), alternates: Mutex::new(o.alternates.clone()), fb: Default::default(),
        holes: Default::default(), socks: Default::default(), tx_wait: AtomicU64::new(0), wake_at: AtomicU64::new(0),
        on_event: Mutex::new(None), o,
    });
    let t0 = Instant::now();
    // The first connection, like every reconnect, retries on a fresh socket. (The mobile
    // operator's "3 packets, then nothing" kill of fresh flows is avoided by the DCID choice, see
    // net::DcidMode; this retry is for ordinary loss.)
    let (act, addr, attempt) = me.establish(None, Some(me.o.first_attempts.max(1)), "CONNECT", None).await?;
    *me.cur.lock().unwrap() = Some(act);
    *me.addr.lock().unwrap() = Some(addr);
    *me.first.lock().unwrap() = (attempt, t0.elapsed().as_millis() as u64);
    if me.o.dead_ms > 0 {
        tokio::spawn(me.clone().detector());
    }
    let h = Handle { c: me, rt: tokio::runtime::Handle::current() };
    if h.c.o.stats_secs > 0 {
        let h = h.clone();
        tokio::spawn(async move {
            while !h.c.stopped.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(h.c.o.stats_secs)).await;
                tracing::info!("{}", h.stats_line());
            }
        });
    }
    Ok(h)
}

/// TUN -> server loop (one packet per read; the buffer keeps HEADROOM in front for the header).
pub async fn pump_tun(h: Handle, tun: Arc<tun::AsyncDevice>) {
    let wait = h.send_wait();
    loop {
        let mut b = BytesMut::with_capacity(2048);
        b.resize(2048, 0);
        let n = match tun.recv(&mut b[HEADROOM..]).await {
            Ok(n) => n,
            Err(e) => {
                tracing::error!("tun read: {e}");
                return;
            }
        };
        if wait { h.send_buf_wait(b, n).await } else { h.send_buf(b, n) }
    }
}

fn log_capsule(t: u64, p: &[u8]) {
    match t {
        proto::CAP_ADDRESS_ASSIGN => tracing::info!("ADDRESS_ASSIGN {:?}", proto::parse_assign(p)),
        proto::CAP_ROUTE_ADVERTISEMENT => tracing::info!("ROUTE_ADVERTISEMENT {:?}", proto::parse_routes(p)),
        _ => tracing::info!("capsule type {t:#x} len {}", p.len()),
    }
}

/// How long one handshake of `establish` may run: this many times `attempt_ms` (a new one starts
/// every `attempt_ms`), at least `ATTEMPT_LIFE_MIN_MS`.
const ATTEMPT_LIFE: u32 = 4;
const ATTEMPT_LIFE_MIN_MS: u64 = 4000;

/// The connection a race runs next to, and its authenticated receive count when the race began.
struct Guard {
    old: Arc<Active>,
    base: u64,
}

impl Guard {
    /// The old connection received something it could decrypt since the race began.
    fn revived(&self) -> bool {
        self.old.conn.close_reason().is_none() && auth_rx(&self.old.conn) > self.base
    }
}

/// Frames received on `c` (only packets that decrypted count; a stray datagram does not).
fn auth_rx(c: &quinn::Connection) -> u64 {
    let f = c.stats().frame_rx;
    f.acks + f.datagram + f.ping + f.stream + f.path_challenge + f.path_response + f.new_connection_id + f.max_data + f.max_stream_data
}

/// A completed QUIC handshake, before the CONNECT-IP request.
struct Hs {
    ep: quinn::Endpoint,
    sock: Arc<KillableSocket>,
    conn: quinn::Connection,
    t0: Instant,
    t_quic: Duration,
}
