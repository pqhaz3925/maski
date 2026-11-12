//! Outer UDP sockets (interface pinning, buffers), the killable socket wrapper used to simulate a
//! dead path, and the QUIC transport/congestion configuration shared by both ends.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use quinn::congestion::{BbrConfig, Controller, ControllerFactory, CubicConfig, NewRenoConfig};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

/// Default outer socket buffer (each direction; kernel memory, not process memory).
pub const SOCKBUF: usize = 8 * 1024 * 1024;

/// Pin a socket to one interface (macOS `IP_BOUND_IF`, Linux `SO_BINDTODEVICE`).
pub fn bind_interface(fd: i32, interface: &str) -> io::Result<()> {
    let name = std::ffi::CString::new(interface).map_err(|_| io::Error::other("NUL in name"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("no interface {interface}")));
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let r = unsafe {
        libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_BOUND_IF, (&index as *const u32).cast(), 4)
    };
    #[cfg(target_os = "linux")]
    let r = unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, name.as_ptr().cast(),
            name.as_bytes_with_nul().len() as libc::socklen_t)
    };
    if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// A non-blocking IPv4/IPv6 UDP socket with large buffers, optionally pinned to an interface.
pub fn udp_socket(bind: SocketAddr, interface: Option<&str>, sockbuf: usize) -> Result<std::net::UdpSocket> {
    use std::os::fd::AsRawFd;
    let s = socket2::Socket::new(socket2::Domain::for_address(bind), socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP))?;
    let _ = s.set_recv_buffer_size(sockbuf);
    let _ = s.set_send_buffer_size(sockbuf);
    if let Some(i) = interface {
        bind_interface(s.as_raw_fd(), i)?;
    }
    s.bind(&bind.into())?;
    s.set_nonblocking(true)?;
    tracing::info!("udp socket {} rcvbuf={:?} sndbuf={:?} if={:?}", s.local_addr()?.as_socket().unwrap(),
        s.recv_buffer_size(), s.send_buffer_size(), interface);
    Ok(s.into())
}

/// Send-side events of the outer sockets that quinn would otherwise only log (once a minute) or
/// not report at all. Shared by every socket of one client / one server.
#[derive(Debug, Default)]
pub struct SockStats {
    /// sendmsg failed with ENOBUFS (an interface queue was full; the datagram is gone).
    pub nobufs: AtomicU64,
    /// Any other send error except EMSGSIZE (also lost).
    pub other_err: AtomicU64,
    /// The socket was not writable (EWOULDBLOCK): quinn keeps the packet and waits.
    pub blocked: AtomicU64,
    /// Woken when a socket reports that its interface cannot reach the server (the client's path
    /// detector waits on it, see `KillableSocket::unreach_at`).
    pub wake: tokio::sync::Notify,
}

/// Send errors meaning "this interface cannot reach anything" (no address, no route, link down),
/// as opposed to a full queue (ENOBUFS) or a refused packet.
pub fn is_unreachable(errno: i32) -> bool {
    matches!(errno, libc::EADDRNOTAVAIL | libc::ENETUNREACH | libc::EHOSTUNREACH | libc::ENETDOWN)
}

impl SockStats {
    pub fn line(&self) -> String {
        format!("sock_nobufs={} sock_err={} sock_blocked={}", self.nobufs.load(Ordering::Relaxed),
            self.other_err.load(Ordering::Relaxed), self.blocked.load(Ordering::Relaxed))
    }
}

/// quinn's tokio UDP socket, except that send errors are counted (`SockStats`) before being
/// dropped the way quinn drops them.
#[derive(Debug)]
pub struct UdpSock {
    io: tokio::net::UdpSocket,
    state: quinn::udp::UdpSocketState,
    stats: Arc<SockStats>,
    last_log: AtomicU64,
}

impl UdpSock {
    pub fn new(sock: std::net::UdpSocket, stats: Arc<SockStats>) -> io::Result<Arc<Self>> {
        let state = quinn::udp::UdpSocketState::new((&sock).into())?;
        Ok(Arc::new(Self { io: tokio::net::UdpSocket::from_std(sock)?, state, stats, last_log: AtomicU64::new(0) }))
    }
}

impl UdpSock {
    /// Send and count. Returns what quinn sees (Ok for a dropped datagram, as quinn drops it) and
    /// the errno of a dropped datagram.
    fn send_counted(&self, t: &Transmit) -> (io::Result<()>, Option<i32>) {
        match self.io.try_io(tokio::io::Interest::WRITABLE, || self.state.try_send((&self.io).into(), t)) {
            Ok(()) => (Ok(()), None),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                (Err(e), None)
            }
            // Expected for MTU probes above the interface MTU (quinn ignores it the same way).
            Err(e) if e.raw_os_error() == Some(libc::EMSGSIZE) => (Ok(()), None),
            Err(e) => {
                if e.raw_os_error() == Some(libc::ENOBUFS) {
                    self.stats.nobufs.fetch_add(1, Ordering::Relaxed);
                } else {
                    let n = self.stats.other_err.fetch_add(1, Ordering::Relaxed);
                    let now = crate::net::secs_now();
                    if self.last_log.swap(now, Ordering::Relaxed) != now || n == 0 {
                        tracing::warn!("udp send to {}: {e}", t.destination);
                    }
                }
                (Ok(()), e.raw_os_error())
            }
        }
    }
}

#[derive(Debug)]
struct SockPoller(Arc<UdpSock>);
impl UdpPoller for SockPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.io.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for UdpSock {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SockPoller(self))
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        self.send_counted(t).0
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        loop {
            std::task::ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(n) = self.io.try_io(tokio::io::Interest::READABLE, || self.state.recv((&self.io).into(), bufs, meta)) {
                return Poll::Ready(Ok(n));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }
    fn max_transmit_segments(&self) -> usize {
        self.state.max_gso_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
    }
}

fn secs_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Wraps quinn's socket so the client can (1) black-hole it — every send and receive is
/// dropped, which is how a dying path is simulated — and (2) timestamp the last datagram that
/// arrived on it, which the path-silence detector watches.
pub struct KillableSocket {
    inner: Arc<UdpSock>,
    pub dead: AtomicBool,
    /// Test black hole of the socket's interface (`client::Handle::test_blackhole`): 0 off, 1 every
    /// datagram silently dropped both ways (Wi-Fi associated but dead), 2 sends fail as if the
    /// interface had no route. Separate from `dead`, which only ever goes on.
    pub hole: std::sync::atomic::AtomicU8,
    /// When (ms since `epoch`, 0 = never) a send last failed with an "unreachable" errno
    /// (`is_unreachable`): the interface itself cannot reach the server.
    pub unreach_at: AtomicU64,
    last_rx: Arc<AtomicU64>,
    epoch: Instant,
    stats: Arc<SockStats>,
}

impl fmt::Debug for KillableSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KillableSocket({:?}, dead={})", AsyncUdpSocket::local_addr(&*self.inner), self.dead.load(Ordering::Relaxed))
    }
}

impl KillableSocket {
    pub fn new(sock: std::net::UdpSocket, last_rx: Arc<AtomicU64>, epoch: Instant, stats: Arc<SockStats>) -> io::Result<Arc<Self>> {
        Ok(Arc::new(Self { inner: UdpSock::new(sock, stats.clone())?, dead: AtomicBool::new(false), hole: Default::default(),
            unreach_at: AtomicU64::new(0), last_rx, epoch, stats }))
    }

    fn mark_unreachable(&self) {
        self.unreach_at.store((self.epoch.elapsed().as_millis() as u64).max(1), Ordering::Relaxed);
        self.stats.wake.notify_one();
    }

    fn holed(&self) -> bool {
        self.dead.load(Ordering::Relaxed) || self.hole.load(Ordering::Relaxed) != 0
    }
}

impl AsyncUdpSocket for KillableSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if self.dead.load(Ordering::Relaxed) {
            return Ok(());
        }
        match self.hole.load(Ordering::Relaxed) {
            0 => {}
            2 => {
                self.stats.other_err.fetch_add(1, Ordering::Relaxed);
                self.mark_unreachable();
                return Ok(());
            }
            _ => return Ok(()),
        }
        let (r, errno) = self.inner.send_counted(transmit);
        if errno.is_some_and(is_unreachable) {
            self.mark_unreachable();
        }
        r
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        loop {
            match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(_)) if self.holed() => continue,
                Poll::Ready(Ok(n)) => {
                    self.last_rx.store(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
                    return Poll::Ready(Ok(n));
                }
                other => return other,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// "No congestion control": a constant window. The inner TCP flows do their own congestion
/// control; this measures what the outer controller costs.
#[derive(Debug, Clone)]
struct Fixed(u64);

impl Controller for Fixed {
    fn on_congestion_event(&mut self, _: Instant, _: Instant, _: bool, _: u64) {}
    fn on_mtu_update(&mut self, _: u16) {}
    fn window(&self) -> u64 {
        self.0
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }
    fn initial_window(&self) -> u64 {
        self.0
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

struct FixedFactory(u64);
impl ControllerFactory for FixedFactory {
    fn build(self: Arc<Self>, _: Instant, _: u16) -> Box<dyn Controller> {
        Box::new(Fixed(self.0))
    }
}

/// What the rate controller publishes for stats and for the client to reset it.
#[derive(Debug, Default)]
pub struct RateShared {
    /// Delivery-rate estimate, bytes/s.
    pub bw: AtomicU64,
    pub min_rtt_us: AtomicU64,
    pub window: AtomicU64,
    /// Bumped by the owner after a network change: the controller forgets min RTT and rate.
    pub reset: AtomicU64,
    /// Bumped by the client on every move to a new socket (see `Rate::window`).
    pub moved: AtomicU64,
    /// In-flight bytes + 1 when the window was first asked for after the latest move; 0 = not yet.
    pub move_base: AtomicU64,
    /// Bytes of datagrams received from the peer (fed by the owner): the reverse direction's
    /// load, which decides whether an RTT sample can carry the peer's standing queue (`Rate`).
    pub rx_bytes: AtomicU64,
    /// Min RTT re-measurements (drains) done, and how many of them raised the min RTT.
    pub drains: AtomicU64,
    pub raises: AtomicU64,
}

impl RateShared {
    /// A move to a new socket: until the next ACK the window is opened by `MOVE_ALLOW_PKTS`
    /// packets above what is in flight right now.
    pub fn moved(&self) {
        self.move_base.store(0, Ordering::Relaxed);
        self.moved.fetch_add(1, Ordering::Release);
    }
}

/// Outer congestion control that ignores loss: in-flight is capped at `gain` x delivery rate x
/// min RTT, which keeps the path's queue at about (gain - 1) x BDP whatever the path's buffer is.
///
/// Why: the inner TCP flows already react to loss (random loss on the home line must not slow the
/// outer connection: quinn's Cubic gave 30-48 Mbit/s there, quinn's BBR ~190 because it enters
/// packet-conservation recovery on every loss). But with no outer limit at all (a fixed window)
/// the whole window sits in the cellular operator's buffer (seconds of queue measured on a weak
/// LTE uplink) and overflows into quinn's drop-oldest datagram queue. With the window bounded, the
/// excess waits in quinn's datagram queue instead, where `TxGate` bounds it by time.
///
/// Rate: acked bytes over the last max(min RTT, 10 ms), max-filtered over clamp(10 x min RTT,
/// 0.5 s, 2 s); samples taken while app-limited only raise it, and the filter does not age while
/// app-limited. With `gain` 2 the window doubles every round trip until the path is full (no
/// separate startup). Min RTT: per-packet ack time minus send time, the minimum since it was last
/// confirmed (see below), the connection started or the last network change.
///
/// Min RTT expiry. The window is gain x rate x min RTT, so a min RTT that is too small for the path
/// (its RTT grew after the connect: a route change, LTE -> 3G behind a modem's NAT, a silent re-hop
/// to a slower path) shrinks the window below the path's BDP; the delivery rate then falls with it,
/// round after round, down to the 16-packet floor (lab: 20 -> 80 ms after connect gave 2 Mbit/s on
/// a 30 Mbit/s line). Under load every sample carries the standing queue (about one BDP), so a
/// plain sliding minimum would take that queue for path RTT and grow the window with every window
/// (on a deep-buffered weak uplink: unbounded queue). Instead (per ACK frame, `frame_end`):
/// - a frame whose smallest sample is within `near(min)` (25 % + 2 ms, at least 27 ms; a frame for
///   a single packet, which the peer acknowledged on its ACK timer, 15 ms more) confirms the min;
/// - min RTT raises come only from samples without a queue of ours: packets sent with no more
///   than `quiet_cap` (a quarter of the BDP by the average rate, at least 4 packets) in flight.
///   Dense frames of such packets (light traffic) that all stay above `near(min)` for 2 s set the
///   min to their smallest sample; sparse ones (idle keepalives) to their smallest less 10 ms;
/// - a drain makes such samples under load: the window drops to `quiet_cap` until in flight is
///   below it, and the dense frames of packets sent after that give the path's RTT. It runs after
///   `expire` (10 s) without a confirming sample, or early: when dense frames have stayed above
///   `gain x 1.25 x min + 10 ms` (more than our own standing queue explains) for 2 RTTs, or when
///   startup ended on a round that far above. Early drains that find nothing back off 1, 2, 4 s;
///   one costs about a round at a quarter of the rate;
/// - nothing raises the min RTT while the peer sends more than an eighth of what we deliver
///   (`RateShared::rx_bytes`): its standing queue sits on our ACK path and would be taken for
///   path RTT, and two ends taking each other's queue into their min RTT ratchet both queues up
///   (lab: upload and download at once, 70 -> 360 ms within 20 s before this rule);
/// - a raise restarts the startup gain (a new path), a sample below the min lowers it at once,
///   and a move to a new socket makes a confirmation due within 2 s.
#[derive(Debug, Clone)]
pub struct Rate {
    gain: f64,
    startup_gain: f64,
    mtu: u64,
    init: u64,
    window: u64,
    acked: u64,
    /// Bytes acked in the current ACK frame (between `on_end_acks` calls).
    batch: u64,
    hist: std::collections::VecDeque<(Instant, u64)>,
    maxf: std::collections::VecDeque<(Instant, u64)>,
    min_rtt: Option<Duration>,
    reset_seen: u64,
    /// Startup (window gain `STARTUP_GAIN`) until the delivery rate has not grown by 25 % for
    /// three window-limited rounds; again after every reset.
    startup: bool,
    full_bw: u64,
    full_cnt: u32,
    round_end: Option<Instant>,
    /// RTT of the newest acked packet.
    last_rtt: Duration,
    /// Smallest RTT sample of the current queue-check round (one min RTT long) and its end.
    round_min_rtt: Duration,
    round_samples: u32,
    /// Acked packets since the last plateau-check round ended.
    plat_samples: u32,
    qround_end: Option<Instant>,
    /// 1 (default): startup ends on a busy round whose every RTT sample shows a queue; plateau
    /// rounds count when busy. 0: as in `6863145` (one late sample ends startup), for A/B runs.
    mode: u8,
    /// Trace (`RUST_LOG=maski::rate_trace=debug`): ACK frames and window-limited ones since the
    /// last line, the largest RTT sample, when the last line was written.
    tr_acks: u32,
    tr_limited: u32,
    tr_max_rtt: Duration,
    tr_at: Option<Instant>,
    /// In flight per quinn at the last ACK frame, plus bytes sent since (for `window` after a move).
    infl: u64,
    sent_since: u64,
    /// The `shared.moved` count that an ACK has been seen for.
    moved_seen: u64,
    /// Min RTT expiry (zero = never, the behaviour before expiry existed).
    expire: Duration,
    /// When a sample last confirmed the min RTT (within `near(min)`), and the peer's received
    /// bytes at that moment.
    min_at: Option<Instant>,
    rx_at_min: u64,
    acked_at_min: u64,
    /// (time, acked) about every 100 ms over the last second (`avg_rate`), and that rate as of
    /// the last ACK frame.
    slow: std::collections::VecDeque<(Instant, u64)>,
    qrate: u64,
    /// The previous ACK frame (the expiry clock stops while none arrive).
    last_frame: Option<Instant>,
    /// Quiet samples (see `Rate`) since `min_at`: their minimum and count.
    quiet_min: Duration,
    quiet_n: u32,
    /// The same for sparse quiet samples (one packet per ACK frame: keepalives on an idle
    /// connection, acknowledged on the peer's ACK timer).
    sparse_min: Duration,
    sparse_n: u32,
    /// Send time and in-flight bytes (before it) of each packet in flight, oldest first.
    sent_q: std::collections::VecDeque<(Instant, u64)>,
    drain: Option<Drain>,
    /// The ACK frame being processed (`on_ack` calls up to `on_end_acks`): packets, smallest
    /// sample, all of them quiet; packets and smallest sample that count for a drain.
    fr_n: u32,
    fr_min: Duration,
    fr_quiet: bool,
    fr_dn: u32,
    fr_dmin: Duration,
    /// The last frame was dense (two packets or more).
    fr_dense: bool,
    /// Since when every dense frame's smallest sample was above `gain x 1.25 x min + 10 ms` (no
    /// queue of ours explains that: the min RTT is likely too small), and their packets.
    hi_since: Option<Instant>,
    hi_n: u32,
    /// Early drains (on `hi_since`) back off while they find nothing: gap and next allowed time.
    early_gap: Duration,
    next_early: Option<Instant>,
    pub shared: Arc<RateShared>,
}

/// A min RTT re-measurement (see `Rate`).
#[derive(Debug, Clone)]
struct Drain {
    start: Instant,
    /// Window during the drain.
    cap: u64,
    /// When in-flight first fell to `cap`; only packets sent after it count.
    reached: Option<Instant>,
    best: Duration,
    n: u32,
    rx0: u64,
    acked0: u64,
}

/// Min RTT expiry when nothing confirms it (BBR uses the same 10 s).
const MIN_RTT_EXPIRE: Duration = Duration::from_secs(10);
/// Quiet samples above `near(min)` for this long (at least `4 x min`) and at least
/// `QUIET_MIN_SAMPLES` of them set the min RTT.
const QUIET_EXPIRE: Duration = Duration::from_secs(2);
const QUIET_MIN_SAMPLES: u32 = 4;
/// A move to a new socket may be a move to a different path: the min RTT must be confirmed
/// within this long after it, or a drain re-measures it.
const MOVE_RECHECK: Duration = Duration::from_secs(2);
/// The peer's ACK delay that a sample of a dense ACK frame may still carry (quinn's default
/// max_ack_delay; a frame for several packets is mostly sent before its timer).
const ACK_SLACK: Duration = Duration::from_millis(25);
/// A sparse sample (an ACK frame for one packet: a keepalive, acknowledged when the peer's ACK
/// timer fires) confirms the min RTT up to this much more: measured 29-36 ms of delay on idle
/// keepalives in the lab. Sparse samples never raise the min RTT.
const SPARSE_EXTRA: Duration = Duration::from_millis(15);
/// Taken off the smallest sparse sample when it re-measures the path (see `expiry`). Subtracting
/// the whole ACK_SLACK made it 15 ms short on a 20 -> 80 ms step (one sample had 10 ms of delay),
/// and the startup gain over 65 ms then grew the window only as fast as the inner slow start.
const SPARSE_DEDUCT: Duration = Duration::from_millis(10);
/// Dense frames above the queue line for this long (at least 2 x the latest RTT) and this many
/// packets start a drain before `expire`.
const EARLY_AFTER: Duration = Duration::from_millis(150);
const EARLY_MIN_PKTS: u32 = 8;
const EARLY_GAP_MIN: Duration = Duration::from_secs(1);
/// Early drains that find the min RTT right back off 1, 2, 4 s. They do fire on a stable path
/// when the rate estimate runs high (ACK compression: our own queue then passes the line); a
/// longer gap would delay the reaction to a real step by as much.
const EARLY_GAP_MAX: Duration = Duration::from_secs(4);
/// The peer's data rate (bytes/s) below which the reverse path is taken to hold no queue of
/// the peer's: at most this, or an eighth of our own rate.
const RX_QUIET_FLOOR: u64 = 25_000;
/// A drain without a usable sample ends after this (at least 4 x the latest RTT).
const DRAIN_MAX: Duration = Duration::from_secs(2);

/// Samples up to this confirm `min`; above it they say the path got slower (25 % + 2 ms, but at
/// least `ACK_SLACK` + 2 ms above `min`).
fn near(min: Duration) -> Duration {
    (min * 5 / 4 + Duration::from_millis(2)).max(min + ACK_SLACK + Duration::from_millis(2))
}

const RATE_FLOOR_PKTS: u64 = 16;
const RATE_INIT_PKTS: u64 = 32;
/// Acked packets a queue-check round needs before its smallest RTT can end startup.
const RATE_ROUND_MIN_SAMPLES: u32 = 8;
/// Window gain while starting up. With the steady gain (2) the window only equals the next round
/// of an inner slow start (the rate measured over the last round x 2), so any ACK jitter queued
/// the inner flow in quinn's datagram queue and the gate dropped from it: the first 4 MB download
/// on a 40 Mbit/s / 120 ms lab path took 2.3 s instead of 1.6 s with the fixed window.
const STARTUP_GAIN: f64 = 2.5;
/// Packets allowed above the in-flight bytes after a move, until the first ACK on the new path.
///
/// After an outage quinn's in-flight is full of packets that will never be acked and are not yet
/// declared lost (that needs an ACK of something newer). The PING quinn queues on every rebind is
/// congestion-controlled, so it waited for the next PTO, which had backed off during the outage:
/// lab trace 2026-11-12, in flight 25 178 > window 22 912, "blocked by congestion control" until
/// "PTO fired ... count=4" 0.58 s after the move; on an LTE modem 6.9 s to recover after a
/// 4 s radio outage. The first ACK on the new path makes quinn declare the stale packets lost.
const MOVE_ALLOW_PKTS: u64 = 4;

impl Rate {
    fn new(gain: f64, startup_gain: f64, mode: u8, expire: Duration, mtu: u16) -> Self {
        let mtu = mtu as u64;
        let init = RATE_INIT_PKTS * mtu;
        let s = Self { gain, startup_gain, mtu, init, window: init, acked: 0, batch: 0, hist: Default::default(), maxf: Default::default(),
            min_rtt: None, reset_seen: 0, startup: true, full_bw: 0, full_cnt: 0, round_end: None, last_rtt: Duration::ZERO,
            round_min_rtt: Duration::MAX, round_samples: 0, plat_samples: 0, qround_end: None, mode,
            tr_acks: 0, tr_limited: 0, tr_max_rtt: Duration::ZERO, tr_at: None, infl: 0, sent_since: 0, moved_seen: 0,
            expire, min_at: None, rx_at_min: 0, acked_at_min: 0, slow: Default::default(), qrate: 0, last_frame: None, quiet_min: Duration::MAX, quiet_n: 0, sparse_min: Duration::MAX, sparse_n: 0, sent_q: Default::default(), drain: None,
            fr_n: 0, fr_min: Duration::MAX, fr_quiet: true, fr_dn: 0, fr_dmin: Duration::MAX, fr_dense: false, hi_since: None, hi_n: 0,
            early_gap: EARLY_GAP_MIN, next_early: None,
            shared: Default::default() };
        s.shared.window.store(init, Ordering::Relaxed);
        s
    }

    fn check_reset(&mut self) {
        let r = self.shared.reset.load(Ordering::Relaxed);
        if r != self.reset_seen {
            self.reset_seen = r;
            self.min_rtt = None;
            self.hist.clear();
            self.maxf.clear();
            self.window = self.init;
            self.startup = true;
            self.full_bw = 0;
            self.full_cnt = 0;
            self.round_end = None;
            self.round_min_rtt = Duration::MAX;
            self.round_samples = 0;
            self.qround_end = None;
            self.min_at = None;
            self.quiet_min = Duration::MAX;
            self.quiet_n = 0;
            self.drain = None;
            self.hi_since = None;
            self.hi_n = 0;
            self.early_gap = EARLY_GAP_MIN;
            self.next_early = None;
        }
    }

    pub fn bw(&self) -> u64 {
        self.maxf.front().map_or(0, |x| x.1)
    }

    /// Acked bytes per second over the last second or so (not max-filtered: ACK compression
    /// inflates `bw`, measured 5x on an 8 Mbit/s downlink with the uplink loaded too). Falls back
    /// to `bw` before there is a span of 200 ms.
    fn avg_rate(&self, now: Instant) -> u64 {
        match self.slow.front() {
            // Not across a silence (an outage, a pause): that average says nothing about the path.
            Some(&(t, a)) if now.saturating_duration_since(t) >= Duration::from_millis(200)
                && now.saturating_duration_since(t) <= Duration::from_millis(1500) =>
                ((self.acked - a) as f64 / now.saturating_duration_since(t).as_secs_f64()) as u64,
            _ => self.bw(),
        }
    }

    /// In-flight bytes that cannot build a queue of ours worth mentioning: a quarter of the
    /// estimated BDP (by the smaller of the max-filtered and the average rate), at least 4 packets.
    fn quiet_cap(&self, min: Duration) -> u64 {
        ((self.bw().min(self.qrate) as f64 * min.as_secs_f64() / 4.0) as u64).max(4 * self.mtu)
    }

    /// The min RTT was confirmed (or re-measured) now.
    fn confirm(&mut self, now: Instant) {
        self.min_at = Some(now);
        self.acked_at_min = self.acked;
        self.rx_at_min = self.shared.rx_bytes.load(Ordering::Relaxed);
        self.quiet_min = Duration::MAX;
        self.quiet_n = 0;
        self.sparse_min = Duration::MAX;
        self.sparse_n = 0;
    }

    /// Did the peer send little enough between `rx0` and now (`span`), compared with what we
    /// delivered (`acked0` on), that the reverse path holds no queue of its own? Its standing
    /// queue would be in every RTT sample. A one-way transfer's reverse traffic is the inner
    /// ACKs, a few % of it.
    fn rx_quiet(&self, rx0: u64, acked0: u64, span: Duration) -> bool {
        let secs = span.as_secs_f64().max(1e-3);
        let rx = self.shared.rx_bytes.load(Ordering::Relaxed).saturating_sub(rx0) as f64 / secs;
        let own = self.acked.saturating_sub(acked0) as f64 / secs;
        let q = rx <= (own / 8.0).max(RX_QUIET_FLOOR as f64);
        tracing::debug!(target: "maski::rate", "reverse {rx:.0} B/s, own {own:.0} B/s over {span:?}: quiet {q}");
        q
    }

    /// A re-measured path RTT `cand` (from quiet samples or a drain): raise the min RTT to it when
    /// it is clearly above, and the reverse path was quiet; confirm the old one otherwise.
    fn remeasured(&mut self, now: Instant, cand: Duration, quiet: bool, how: &str) {
        let Some(min) = self.min_rtt else { return };
        if cand > near(min) && quiet {
            self.min_rtt = Some(cand);
            self.shared.raises.fetch_add(1, Ordering::Relaxed);
            // A different path: ramp up as on a fresh connection (startup gain), not with the
            // steady gain behind the inner flows' slow start (that made the gate drop from it).
            self.startup = true;
            self.full_bw = 0;
            self.full_cnt = 0;
            self.round_end = None;
            self.qround_end = None;
            self.round_min_rtt = Duration::MAX;
            self.round_samples = 0;
            tracing::info!(target: "maski::rate", "min rtt {:.1} -> {:.1} ms ({how})", min.as_secs_f64() * 1e3, cand.as_secs_f64() * 1e3);
            self.early_gap = EARLY_GAP_MIN;
        } else {
            tracing::debug!(target: "maski::rate", "min rtt {:.1} ms kept ({how}: {:.1} ms, reverse quiet {quiet})",
                min.as_secs_f64() * 1e3, cand.as_secs_f64() * 1e3);
            self.early_gap = (self.early_gap * 2).min(EARLY_GAP_MAX);
        }
        self.next_early = Some(now + self.early_gap);
        self.hi_since = None;
        self.hi_n = 0;
        self.confirm(now);
    }

    /// End of an ACK frame: its smallest sample confirms the min RTT, or counts as quiet, as above
    /// the queue line, or for a drain. Only dense frames (two packets or more: sent on the peer's
    /// ACK threshold, not its timer) count for anything that can raise the min RTT.
    fn frame_end(&mut self, now: Instant) {
        let (n, smin, quiet, dn, dmin) = (self.fr_n, self.fr_min, self.fr_quiet, self.fr_dn, self.fr_dmin);
        self.fr_n = 0;
        self.fr_min = Duration::MAX;
        self.fr_quiet = true;
        self.fr_dn = 0;
        self.fr_dmin = Duration::MAX;
        let Some(min) = self.min_rtt else { return };
        if n == 0 || self.expire.is_zero() {
            return;
        }
        let dense = n >= 2;
        self.fr_dense = dense;
        if smin <= near(min) + if dense { Duration::ZERO } else { SPARSE_EXTRA } {
            self.confirm(now);
        } else if dense && quiet {
            self.quiet_min = self.quiet_min.min(smin);
            self.quiet_n += 1;
        } else if quiet {
            self.sparse_min = self.sparse_min.min(smin);
            self.sparse_n += 1;
        }
        if dense {
            let hi = min.mul_f64(self.gain * 1.25) + Duration::from_millis(10);
            if smin > hi {
                self.hi_since.get_or_insert(now);
                self.hi_n += n;
            } else {
                self.hi_since = None;
                self.hi_n = 0;
            }
            if let Some(d) = &mut self.drain {
                if dn > 0 {
                    d.best = d.best.min(dmin);
                    d.n += dn;
                }
            }
        }
    }

    /// Min RTT expiry, once per ACK frame (see `Rate`).
    fn expiry(&mut self, now: Instant, in_flight: u64) {
        let Some(min) = self.min_rtt else { return };
        if self.expire.is_zero() {
            return;
        }
        if self.min_at.is_none() || (self.startup && self.fr_dense) {
            // Startup fills the path's queue on purpose: its samples under load say nothing about
            // the path. (Idle in startup, which a connection stays in until it first carries
            // load, the quiet rules below still apply.)
            self.confirm(now);
            self.hi_since = None;
            self.hi_n = 0;
            return;
        }
        if let Some(d) = &mut self.drain {
            if d.reached.is_none() && in_flight <= d.cap {
                d.reached = Some(now);
            }
            let to = DRAIN_MAX.max(self.last_rtt * 4);
            let done = match d.reached {
                Some(r) => d.n >= 1 && now >= r + d.best + (d.best / 4).max(Duration::from_millis(10)),
                None => false,
            };
            if done || now.saturating_duration_since(d.start) >= to {
                let d = self.drain.take().unwrap();
                if d.n == 0 {
                    tracing::debug!(target: "maski::rate", "drain: no sample in {:?}", now - d.start);
                    self.confirm(now);
                } else {
                    let quiet = self.rx_quiet(d.rx0, d.acked0, now - d.start);
                    self.remeasured(now, d.best, quiet, "drain");
                }
            }
            return;
        }
        let since = now.saturating_duration_since(self.min_at.unwrap());
        let early = self.hi_since.is_some_and(|t| now.saturating_duration_since(t) >= EARLY_AFTER.max(self.last_rtt * 2))
            && self.hi_n >= EARLY_MIN_PKTS && self.next_early.is_none_or(|t| now >= t);
        let quiet_due = since >= QUIET_EXPIRE.max(min * 4);
        if quiet_due && self.quiet_n >= QUIET_MIN_SAMPLES {
            let quiet = self.rx_quiet(self.rx_at_min, self.acked_at_min, since);
            let cand = self.quiet_min;
            self.remeasured(now, cand, quiet, "quiet samples");
        } else if quiet_due && self.sparse_n >= QUIET_MIN_SAMPLES {
            // Idle: every keepalive came back late. Their smallest sample less SPARSE_DEDUCT as the
            // path RTT: a keepalive's ACK waits 0-36 ms (0 when it rides on a packet of the
            // peer's), so this errs either way by tens of ms at most; a dense sample under load
            // lowers it, and a 25 % error does not shrink the window below the path's BDP.
            let quiet = self.rx_quiet(self.rx_at_min, self.acked_at_min, since);
            let cand = self.sparse_min.saturating_sub(SPARSE_DEDUCT);
            self.remeasured(now, cand, quiet, "sparse samples");
        } else if self.startup {
        } else if since >= self.expire || early {
            // While the peer sends a lot no drain can raise the min RTT (see `rx_quiet`): skip it.
            // Upload and download at once on a weak link otherwise drained every few seconds on
            // both ends, cost ~20 % of the download and doubled the gate drops (lab).
            if !self.rx_quiet(self.rx_at_min, self.acked_at_min, since) {
                self.confirm(now);
                self.hi_since = None;
                self.hi_n = 0;
                self.next_early = Some(now + EARLY_GAP_MAX);
                return;
            }
            self.start_drain(now, min, in_flight, if early { "early" } else { "expiry" });
        }
    }

    fn start_drain(&mut self, now: Instant, min: Duration, in_flight: u64, why: &str) {
        tracing::debug!(target: "maski::rate", "drain ({why}): min {:.1} ms unconfirmed for {:?}", min.as_secs_f64() * 1e3,
            self.min_at.map(|t| now.saturating_duration_since(t)));
        self.shared.drains.fetch_add(1, Ordering::Relaxed);
        let cap = self.quiet_cap(min);
        self.drain = Some(Drain { start: now, cap, reached: (in_flight <= cap).then_some(now), best: Duration::MAX, n: 0,
            rx0: self.shared.rx_bytes.load(Ordering::Relaxed), acked0: self.acked });
    }
}

impl Controller for Rate {
    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64, _app_limited: bool, _rtt: &quinn_proto::RttEstimator) {
        self.check_reset();
        self.acked += bytes;
        self.batch += bytes;
        let s = now.saturating_duration_since(sent);
        self.last_rtt = s;
        self.round_min_rtt = self.round_min_rtt.min(s);
        self.round_samples += 1;
        self.plat_samples += 1;
        // In flight when this packet was sent (packets of one datagram share the send time).
        while self.sent_q.front().is_some_and(|x| x.0 < sent) {
            self.sent_q.pop_front();
        }
        let infl_at = self.sent_q.front().filter(|x| x.0 == sent).map(|x| x.1);
        if s.is_zero() {
            return;
        }
        let Some(m) = self.min_rtt else {
            self.min_rtt = Some(s);
            return;
        };
        // Per ACK frame (see `frame_end`).
        self.fr_n += 1;
        self.fr_min = self.fr_min.min(s);
        self.fr_quiet &= infl_at.is_some_and(|x| x <= self.quiet_cap(m));
        if self.drain.as_ref().is_some_and(|d| d.reached.is_some_and(|r| sent >= r)) {
            self.fr_dn += 1;
            self.fr_dmin = self.fr_dmin.min(s);
        }
        if s < m {
            self.min_rtt = Some(s);
        }
    }

    fn on_sent(&mut self, now: Instant, bytes: u64, _pn: u64) {
        if self.sent_q.len() >= 1 << 16 {
            self.sent_q.pop_front();
        }
        self.sent_q.push_back((now, self.infl + self.sent_since));
        self.sent_since += bytes;
    }

    fn on_end_acks(&mut self, now: Instant, in_flight: u64, _quinn_app_limited: bool, _largest: Option<u64>) {
        self.check_reset();
        self.infl = in_flight;
        self.sent_since = 0;
        let m = self.shared.moved.load(Ordering::Acquire);
        if m != self.moved_seen {
            // An ACK after the move: quinn now declares the old path's packets lost by itself.
            self.moved_seen = m;
            self.shared.move_base.store(0, Ordering::Relaxed);
            // The new socket may take a different path: re-measure soon unless confirmed.
            if let Some(t) = self.min_at {
                if !self.expire.is_zero() {
                    self.min_at = Some(t.min(now.checked_sub(self.expire.saturating_sub(MOVE_RECHECK)).unwrap_or(t)));
                }
            }
        }
        // App-limited = the window was not full when this ACK arrived (in flight before it < window
        // minus two packets). quinn's own flag is useless here: it is false whenever its last poll
        // sent a packet, i.e. almost always while datagrams trickle in, so an idle pause or an inner
        // flow in recovery used to age the estimate down (measured: 27 -> 1.2 Mbit/s between two
        // downloads, window 814 -> 62 KB, the next download then ramped behind the inner slow start).
        let pre = in_flight + std::mem::take(&mut self.batch);
        // A drain limits the window on purpose: its ACKs only raise the rate, as app-limited ones.
        let app_limited = pre + 2 * self.mtu < self.window || self.drain.is_some();
        if self.slow.back().is_none_or(|x| now.saturating_duration_since(x.0) >= Duration::from_millis(100)) {
            self.slow.push_back((now, self.acked));
            while self.slow.len() > 2 && now.saturating_duration_since(self.slow[1].0) >= Duration::from_secs(1) {
                self.slow.pop_front();
            }
        }
        self.qrate = self.avg_rate(now);
        // Nothing came back for a while (an outage, the peer gone quiet): no sample could confirm
        // the min RTT meanwhile, so that time does not count towards its expiry. Without this a
        // 10 s outage made the server drain (window 4 packets) right when it flushed the held
        // packets: at 400 ms RTT one inner download then stalled 55 s instead of ~10 (lab).
        if let (Some(t), Some(m)) = (self.last_frame, self.min_at) {
            let gap = now.saturating_duration_since(t);
            if gap > Duration::from_secs(1) {
                self.min_at = Some(m + gap);
                self.hi_since = None;
                self.hi_n = 0;
            }
        }
        self.last_frame = Some(now);
        self.frame_end(now);
        self.expiry(now, in_flight);
        let Some(min_rtt) = self.min_rtt else { return };
        self.hist.push_back((now, self.acked));
        let span = min_rtt.max(Duration::from_millis(10));
        while self.hist.len() > 2 && now.saturating_duration_since(self.hist[1].0) >= span {
            self.hist.pop_front();
        }
        let (t0, a0) = self.hist[0];
        let dt = now.saturating_duration_since(t0);
        if dt >= span / 2 && dt > Duration::ZERO {
            let sample = ((self.acked - a0) as f64 / dt.as_secs_f64()) as u64;
            if !app_limited || sample > self.bw() {
                while self.maxf.back().is_some_and(|x| x.1 <= sample) {
                    self.maxf.pop_back();
                }
                self.maxf.push_back((now, sample));
            }
            if !app_limited {
                let age = (min_rtt * 10).clamp(Duration::from_millis(500), Duration::from_secs(2));
                while self.maxf.len() > 1 && now.saturating_duration_since(self.maxf[0].0) > age {
                    self.maxf.pop_front();
                }
            }
        }
        let bw = self.bw();
        // Pipe full: an ACK whose packet waited in a queue as long as the path's min RTT, window-
        // limited or not (an inner flow that fills a deep buffer by itself never fills our window;
        // without this the startup gain stayed for good: on a 3 Mbit/s uplink with a 300 KB buffer
        // the ping p95 under upload went from ~175 to ~210 ms),
        // or a window-limited round (one min RTT) that did not raise the rate by 25 %, three
        // times in a row.
        //
        // Mode 1 takes the smallest RTT sample of a round (one min RTT, at least
        // RATE_ROUND_MIN_SAMPLES acked packets) instead of the newest sample. On cellular one late
        // ACK (radio scheduling, ACKs released in bursts) is ordinary: on the phone's LTE it ended
        // startup at 8 Mbit/s, after which the window (2 x rate x min RTT while the real RTT was
        // 1.2-1.5 x the min) held the inner flow's ramp back (window-limited on most ACKs for the
        // first 1.5 s of a 20 MB download). A standing queue raises every sample of a round, so
        // a lower threshold (1.5 x min + 10 ms) still ends startup as early as mode 0 on a deep
        // 3 Mbit/s buffer (lab: same ping p95 and gate drops). An idle connection's few samples
        // (keepalives, the request, a delayed ACK) never make a round: they ended startup before
        // the first download in an earlier version.
        let queue_thr = min_rtt * 2 + Duration::from_millis(10);
        if self.mode == 0 {
            if self.startup && self.last_rtt > queue_thr {
                self.startup = false;
                tracing::debug!(target: "maski::rate", "startup done at {} B/s: rtt {:?} min {min_rtt:?}", self.bw(), self.last_rtt);
            }
        } else if self.qround_end.is_none_or(|t| now >= t) {
            let round_thr = min_rtt * 3 / 2 + Duration::from_millis(10);
            if self.startup && self.qround_end.is_some() && self.round_samples >= RATE_ROUND_MIN_SAMPLES && self.round_min_rtt > round_thr {
                self.startup = false;
                tracing::debug!(target: "maski::rate", "startup done at {} B/s: round min rtt {:?} min {min_rtt:?}", self.bw(), self.round_min_rtt);
                // A startup overshoot raises a round's RTT to 1.5-2 x min; far above the queue
                // line the path itself got slower (the step-up case, idle before): re-measure now.
                if !self.expire.is_zero() && self.round_min_rtt > min_rtt.mul_f64(self.gain * 1.25) + Duration::from_millis(10) {
                    self.start_drain(now, min_rtt, in_flight, "startup ended far above the min");
                }
            }
            self.round_min_rtt = Duration::MAX;
            self.round_samples = 0;
            self.qround_end = Some(now + min_rtt.max(Duration::from_millis(20)));
        }
        // Plateau rounds (one min RTT): mode 0 counts only window-limited ones; mode 1 also those
        // with at least RATE_ROUND_MIN_SAMPLES acked packets (an inner flow that has stopped
        // growing below the window is done starting up too).
        let due = self.round_end.is_none_or(|t| now >= t);
        let robust = self.mode == 1;
        let busy = !app_limited || (robust && self.plat_samples >= RATE_ROUND_MIN_SAMPLES);
        if self.startup && busy && due {
            if bw * 4 >= self.full_bw * 5 {
                self.full_bw = bw;
                self.full_cnt = 0;
            } else {
                self.full_cnt += 1;
                if self.full_cnt >= 3 {
                    self.startup = false;
                    tracing::debug!(target: "maski::rate", "startup done at {bw} B/s");
                }
            }
        }
        if due && (busy || robust) {
            self.round_end = Some(now + min_rtt);
            self.plat_samples = 0;
        }
        let old = self.shared.bw.load(Ordering::Relaxed);
        if bw * 10 < old * 7 || bw * 10 > old * 13 {
            tracing::debug!(target: "maski::rate", "bw {old} -> {bw} B/s app_limited={app_limited} in_flight={in_flight} win={} maxf={} hist={}",
                self.window, self.maxf.len(), self.hist.len());
        }
        if let Some(d) = &self.drain {
            self.window = d.cap;
        } else if bw > 0 {
            let gain = if self.startup { self.gain.max(self.startup_gain) } else { self.gain };
            let w = (gain * bw as f64 * min_rtt.as_secs_f64()) as u64;
            self.window = w.max(RATE_FLOOR_PKTS * self.mtu);
        }
        if tracing::enabled!(target: "maski::rate_trace", tracing::Level::DEBUG) {
            self.tr_acks += 1;
            self.tr_limited += u32::from(!app_limited);
            self.tr_max_rtt = self.tr_max_rtt.max(self.last_rtt);
            if self.tr_at.is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_millis(100)) {
                tracing::debug!(target: "maski::rate_trace", "kbps={} win={} infl={} min_rtt={:.1} rtt={:.1} max_rtt={:.1} acks={} limited={} startup={} drain={}",
                    bw * 8 / 1000, self.window, in_flight, min_rtt.as_secs_f64() * 1e3, self.last_rtt.as_secs_f64() * 1e3,
                    self.tr_max_rtt.as_secs_f64() * 1e3, self.tr_acks, self.tr_limited, self.startup as u8, self.drain.is_some() as u8);
                self.tr_at = Some(now);
                self.tr_acks = 0;
                self.tr_limited = 0;
                self.tr_max_rtt = Duration::ZERO;
            }
        }
        self.shared.bw.store(bw, Ordering::Relaxed);
        self.shared.min_rtt_us.store(min_rtt.as_micros() as u64, Ordering::Relaxed);
        self.shared.window.store(self.window, Ordering::Relaxed);
    }

    fn on_congestion_event(&mut self, _: Instant, _: Instant, _: bool, _: u64) {}

    fn on_mtu_update(&mut self, mtu: u16) {
        self.mtu = mtu as u64;
        self.window = self.window.max(RATE_FLOOR_PKTS * self.mtu);
    }
    fn window(&self) -> u64 {
        if self.shared.moved.load(Ordering::Acquire) != self.moved_seen {
            let mut b = self.shared.move_base.load(Ordering::Relaxed);
            if b == 0 {
                b = self.infl + self.sent_since + 1;
                let _ = self.shared.move_base.compare_exchange(0, b, Ordering::Relaxed, Ordering::Relaxed);
            }
            return self.window.max(b - 1 + MOVE_ALLOW_PKTS * self.mtu);
        }
        self.window
    }
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }
    fn initial_window(&self) -> u64 {
        self.init
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

struct RateFactory(f64, f64, u8, Duration);
impl ControllerFactory for RateFactory {
    fn build(self: Arc<Self>, _: Instant, mtu: u16) -> Box<dyn Controller> {
        Box::new(Rate::new(self.0, self.1, self.2, self.3, mtu))
    }
}

/// The rate controller's shared state of a connection, if it uses one.
pub fn rate_shared(c: &quinn::Connection) -> Option<Arc<RateShared>> {
    c.congestion_state().into_any().downcast::<Rate>().ok().map(|r| r.shared.clone())
}

/// Bytes quinn charges per queued datagram on top of its payload (`size_of::<Datagram>()`).
const DGRAM_OVERHEAD: usize = 32;

/// Admission to quinn's datagram send queue by time (CoDel, RFC 8289, applied on arrival).
///
/// With the outer window bounded (`Rate`), whatever the inner flows send beyond the path's rate
/// waits in quinn's datagram queue. The gate knows the exact age of the oldest datagram still
/// queued (quinn reports the bytes still queued; the gate remembers when each accepted byte
/// entered, and the queue is FIFO). Datagrams over 200 bytes are refused CoDel-style: once the
/// age has stayed above `target` for `INTERVAL`, one is dropped, then more often (interval /
/// sqrt(count)) until the age falls below `target`. The inner TCP so sees an early, single loss
/// instead of a long queue, and a short burst (slow start) passes. Above `HARD_LIMIT` every big
/// datagram is refused, so a UDP flood cannot build more delay than that; it is well above
/// `target + INTERVAL` because a cellular radio pauses for a few hundred ms now and then, and a
/// queue that only waits out such a pause must not lose a whole burst. Datagrams of <= 200 bytes (pings,
/// TCP ACKs, DNS) are only refused when the queue is older than `SMALL_LIMIT`.
#[derive(Debug)]
pub struct TxGate {
    st: std::sync::Mutex<GateState>,
    cap: usize,
    target: Duration,
    pub drops: AtomicU64,
}

#[derive(Debug, Default)]
struct GateState {
    total: u64,
    ring: std::collections::VecDeque<(Instant, u64)>,
    first_above: Option<Instant>,
    dropping: bool,
    count: u32,
    drop_next: Option<Instant>,
}

const INTERVAL: Duration = Duration::from_millis(100);
const SMALL_LIMIT: Duration = Duration::from_millis(1000);
const HARD_LIMIT: Duration = Duration::from_millis(300);

pub enum GateResult {
    Sent,
    /// Refused by the gate.
    Dropped,
    Err(quinn::SendDatagramError),
}

impl TxGate {
    pub fn new(cap: usize, target_ms: u64) -> Self {
        Self { st: Default::default(), cap, target: Duration::from_millis(target_ms), drops: AtomicU64::new(0) }
    }

    /// The path came back after an outage: whatever still waits in quinn's queue waited for the
    /// path, not behind a standing queue, so its age must not count. Without this every datagram
    /// over 200 bytes was refused for as long as those stale ones were still queued (their age was
    /// > 300 ms), including the server's flush of held packets on the client's return: measured
    /// on the phone, the inner sender's held retransmission of the first lost segment was refused,
    /// and the download stalled until the sender's next (backed-off) RTO, 5.6 s after the hole.
    pub fn restart(&self) {
        let mut st = self.st.lock().unwrap();
        let total = st.total;
        st.ring.clear();
        st.ring.push_back((Instant::now(), total));
        st.first_above = None;
        st.dropping = false;
    }

    pub fn send(&self, conn: &quinn::Connection, d: bytes::Bytes) -> GateResult {
        if self.target.is_zero() {
            return match conn.send_datagram(d) { Ok(()) => GateResult::Sent, Err(e) => GateResult::Err(e) };
        }
        let now = Instant::now();
        let len = d.len();
        let mut st = self.st.lock().unwrap();
        let used = self.cap.saturating_sub(conn.datagram_send_buffer_space() + DGRAM_OVERHEAD) as u64;
        let head = st.total.saturating_sub(used);
        while st.ring.front().is_some_and(|x| x.1 <= head) {
            st.ring.pop_front();
        }
        let age = if used == 0 { Duration::ZERO } else { st.ring.front().map_or(Duration::ZERO, |x| now - x.0) };
        if self.refuse(&mut st, now, age, len) {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return GateResult::Dropped;
        }
        match conn.send_datagram(d) {
            Ok(()) => {
                st.total += (len + DGRAM_OVERHEAD) as u64;
                let total = st.total;
                st.ring.push_back((now, total));
                GateResult::Sent
            }
            Err(e) => GateResult::Err(e),
        }
    }

    fn refuse(&self, st: &mut GateState, now: Instant, age: Duration, len: usize) -> bool {
        if len <= 200 {
            return age > SMALL_LIMIT;
        }
        if age > HARD_LIMIT.max(self.target + INTERVAL) {
            return true;
        }
        // CoDel state machine.
        let ok_to_drop = if age < self.target {
            st.first_above = None;
            false
        } else {
            match st.first_above {
                None => { st.first_above = Some(now + INTERVAL); false }
                Some(t) => now >= t,
            }
        };
        let law = |t: Instant, count: u32| t + INTERVAL.div_f64((count.max(1) as f64).sqrt());
        if st.dropping {
            if !ok_to_drop {
                st.dropping = false;
                return false;
            }
            if st.drop_next.is_some_and(|t| now >= t) {
                st.count += 1;
                st.drop_next = Some(law(st.drop_next.unwrap(), st.count));
                return true;
            }
            false
        } else if ok_to_drop {
            st.dropping = true;
            // Resume near the previous drop rate if the last dropping state ended recently.
            st.count = match st.drop_next {
                Some(t) if st.count > 2 && now.saturating_duration_since(t) < INTERVAL * 16 => st.count - 2,
                _ => 1,
            };
            st.drop_next = Some(law(now, st.count));
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Debug)]
pub struct QuicTuning {
    pub cc: String,
    pub initial_mtu: u16,
    pub min_mtu: u16,
    pub mtu_upper: u16,
    pub dgram_sndbuf: usize,
    /// quinn datagram receive buffer: datagrams received but not yet read by the app.
    pub dgram_rcvbuf: usize,
    /// SO_RCVBUF / SO_SNDBUF of the outer UDP sockets.
    pub sockbuf: usize,
    pub keepalive_ms: u64,
    pub idle_timeout_ms: u64,
    pub gso: bool,
    pub ack_threshold: Option<u32>,
    pub initial_rtt_ms: u64,
    pub dcid: DcidMode,
    /// `TxGate` target in ms (0 = no gate: quinn's drop-oldest queue only).
    pub queue_ms: u64,
}

pub fn transport(t: &QuicTuning) -> Result<quinn::TransportConfig> {
    let mut tc = quinn::TransportConfig::default();
    match t.cc.as_str() {
        "cubic" => { tc.congestion_controller_factory(Arc::new(CubicConfig::default())); }
        "bbr" => { tc.congestion_controller_factory(Arc::new(BbrConfig::default())); }
        "newreno" => { tc.congestion_controller_factory(Arc::new(NewRenoConfig::default())); }
        "rate" => { tc.congestion_controller_factory(Arc::new(RateFactory(2.0, STARTUP_GAIN, 1, MIN_RTT_EXPIRE))); }
        // rate:<gain>[:<startup gain>[:<mode>[:<min RTT expiry, s>]]] (mode 0 = startup as in
        // 6863145; expiry 0 = the min RTT never expires, as before it existed; for A/B)
        s if s.starts_with("rate:") => {
            let mut it = s[5..].split(':');
            let g: f64 = it.next().unwrap_or("2").parse()?;
            let sg: f64 = it.next().map_or(Ok(STARTUP_GAIN), str::parse)?;
            let mode: u8 = it.next().map_or(Ok(1), str::parse)?;
            let exp: f64 = it.next().map_or(Ok(MIN_RTT_EXPIRE.as_secs_f64()), str::parse)?;
            if !(1.0..=8.0).contains(&g) || !(1.0..=8.0).contains(&sg) || mode > 1 || !(0.0..=600.0).contains(&exp) {
                bail!("rate gains must be 1..8, mode 0 or 1, expiry 0..600 s");
            }
            tc.congestion_controller_factory(Arc::new(RateFactory(g, sg, mode, Duration::from_secs_f64(exp))));
        }
        s if s.starts_with("fixed:") => {
            let w: u64 = s[6..].parse()?;
            tc.congestion_controller_factory(Arc::new(FixedFactory(w)));
        }
        s => bail!("unknown --cc {s}"),
    }
    tc.initial_mtu(t.initial_mtu);
    tc.min_mtu(t.min_mtu);
    let mut mtud = quinn::MtuDiscoveryConfig::default();
    mtud.upper_bound(t.mtu_upper);
    tc.mtu_discovery_config(Some(mtud));
    tc.datagram_receive_buffer_size(Some(t.dgram_rcvbuf));
    tc.datagram_send_buffer_size(t.dgram_sndbuf);
    if t.keepalive_ms > 0 {
        tc.keep_alive_interval(Some(Duration::from_millis(t.keepalive_ms)));
    }
    tc.max_idle_timeout(Some(Duration::from_millis(t.idle_timeout_ms).try_into()?));
    tc.enable_segmentation_offload(t.gso);
    tc.initial_rtt(Duration::from_millis(t.initial_rtt_ms));
    if let Some(n) = t.ack_threshold {
        let mut af = quinn::AckFrequencyConfig::default();
        af.ack_eliciting_threshold(n.into());
        tc.ack_frequency_config(Some(af));
    }
    // Streams carry only the CONNECT-IP request and capsules (a few hundred bytes), so their
    // flow-control windows bound nothing that matters; keep them small (quinn: 1.25 MB per
    // stream, unlimited per connection, 10 MB send).
    tc.max_concurrent_uni_streams(16u32.into());
    tc.max_concurrent_bidi_streams(16u32.into());
    tc.stream_receive_window(quinn::VarInt::from_u32(256 * 1024));
    tc.receive_window(quinn::VarInt::from_u32(1024 * 1024));
    tc.send_window(1024 * 1024);
    Ok(tc)
}

/// Endpoint config shared by both ends. QUIC-bit greasing (RFC 9287) is OFF: quinn otherwise
/// clears the fixed bit on ~half of its short-header packets once the peer allows it. It was
/// switched off while chasing the mobile operator's kills of fresh flows (25-40% with greasing,
/// 10-25% without); the actual cause turned out to be the first datagram (see `DcidMode`), so the
/// greasing effect was never isolated. Off is what every mobile measurement since used.
pub fn endpoint_config() -> quinn::EndpointConfig {
    let mut c = quinn::EndpointConfig::default();
    c.grease_quic_bit(false);
    c
}

/// What the client puts in the Destination Connection ID of its first Initial.
///
/// The mobile operator's DPI kills a fresh UDP flow after 3 client packets when the first 16 bytes
/// of its first datagram have 50 or more bits set (measured: 89 recorded quinn connections split
/// perfectly at popcount 49/50; replaying a recording byte for byte reproduces its fate every
/// time, and splicing only the first 8 DCID bytes of a killed recording into a passing one kills
/// it). Those 16 bytes are the long-header first byte (0xc0 + 4 protected bits), the version
/// (0x00000001), the DCID length (0x14) and the first 10 DCID bytes, so with quinn's random
/// 20-byte DCID roughly a quarter of connections cross the line.
/// `Low` draws random 20-byte DCIDs until their first 10 bytes have at most 32 bits set: the
/// header then has at most 5 + 4 + 32 = 41 bits in that window. `High` (for the causal test)
/// forces at least 45, i.e. >= 50 in the window. `Random` is quinn's default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum DcidMode {
    Random,
    Low,
    High,
}

impl std::str::FromStr for DcidMode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "random" => Self::Random,
            "low" => Self::Low,
            "high" => Self::High,
            _ => bail!("initial_dcid must be random|low|high"),
        })
    }
}

/// Send a short throw-away datagram as the very first packet of a fresh client socket.
///
/// The same DPI rule as for the Initial (see `DcidMode`) applies to the first datagram of every
/// new UDP flow, including the flow a QUIC migration creates: a first datagram of 81..1319 or
/// 1376..1427 bytes whose first 16 bytes have >= 50 bits set gets the flow cut after 3 packets.
/// Short-header packets nearly always have >= 50 bits there, so a migration whose first packet
/// is, say, a 101-byte tunnelled TCP ACK dies (measured: 4/41 moves under light traffic, all with
/// a first datagram of 101-102 bytes; every move that began with a 30-38-byte packet survived).
/// Datagrams of <= 80 bytes are never cut (measured 20..80 bytes, random content). This sends
/// 32 random bytes with the QUIC fixed bit clear, which the server's quinn drops as a malformed
/// header without answering (no stateless reset), before quinn sends anything on the socket.
pub fn send_primer(sock: &std::net::UdpSocket, to: SocketAddr) {
    let mut b = [0u8; 32];
    if rustls::crypto::ring::default_provider().secure_random.fill(&mut b).is_ok() {
        b[0] &= 0x3f;
        if let Err(e) = sock.send_to(&b, to) {
            tracing::debug!("primer: {e}");
        }
    }
}

/// Popcount of the first 10 DCID bytes.
pub fn dcid_ones(cid: &[u8]) -> u32 {
    cid.iter().take(10).map(|b| b.count_ones()).sum()
}

pub fn dcid_provider(mode: DcidMode) -> Option<Arc<dyn Fn() -> quinn::ConnectionId + Send + Sync>> {
    let ok: fn(u32) -> bool = match mode {
        DcidMode::Random => return None,
        DcidMode::Low => |n| n <= 32,
        DcidMode::High => |n| n >= 45,
    };
    let rng = rustls::crypto::ring::default_provider().secure_random;
    Some(Arc::new(move || {
        let mut b = [0u8; 20];
        loop {
            rng.fill(&mut b).expect("random");
            if ok(dcid_ones(&b)) {
                return quinn::ConnectionId::new(&b);
            }
        }
    }))
}

/// Periodic one-line connection stats.
pub fn stats_line(c: &quinn::Connection) -> String {
    let s = c.stats();
    format!(
        "rtt={:?} cwnd={} mtu={} sent_pkts={} lost_pkts={} lost_bytes={} cong_events={} udp_tx={}/{}B udp_rx={}/{}B dgram_tx={} dgram_rx={} maxdg={:?}",
        s.path.rtt, s.path.cwnd, s.path.current_mtu, s.path.sent_packets, s.path.lost_packets, s.path.lost_bytes,
        s.path.congestion_events, s.udp_tx.datagrams, s.udp_tx.bytes, s.udp_rx.datagrams, s.udp_rx.bytes,
        s.frame_tx.datagram, s.frame_rx.datagram, c.max_datagram_size()
    ) + &rate_shared(c).map_or(String::new(), |r| format!(" bw={} win={} minrtt_us={} drains={} raises={}",
        r.bw.load(Ordering::Relaxed) * 8, r.window.load(Ordering::Relaxed), r.min_rtt_us.load(Ordering::Relaxed),
        r.drains.load(Ordering::Relaxed), r.raises.load(Ordering::Relaxed)))
}
