//! CONNECT-IP server: QUIC endpoint on a wildcard socket (quinn answers from the arrival address
//! via IP_PKTINFO), one TUN device, an address pool, HTTP datagrams straight between them.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use h3::ext::Protocol;
use http::{Method, Response, StatusCode};

use crate::net::{self, QuicTuning};
use crate::proto;
use crate::tunio;

pub struct ServerOpts {
    pub listen: SocketAddr,
    pub tun: String,
    /// Server's own tunnel address with the pool prefix, e.g. 10.90.0.1/24.
    pub addr: String,
    pub mtu: u16,
    pub cert_dir: PathBuf,
    pub cert_name: String,
    /// Who may connect; fixed addresses are checked against the pool at start.
    pub users: Vec<crate::users::User>,
    pub tuning: QuicTuning,
    pub stats_secs: u64,
    /// When nothing has arrived from a client for this long, hold its downlink packets instead of
    /// sending them into a dead path, and flush them the moment it is heard again (0 = off).
    pub hold_ms: u64,
}

/// Downlink packets held while a client's path is silent. The inner TCP's own retransmissions
/// land here during an outage; delivering the newest of them as soon as the client is back lets
/// the sender leave its RTO backoff at once instead of after its next (exponentially later) timer.
#[derive(Default)]
struct Hold {
    dead: std::sync::atomic::AtomicBool,
    q: Mutex<std::collections::VecDeque<Bytes>>,
}
const HOLD_MAX: usize = 256;

struct Session {
    conn: quinn::Connection,
    /// Index into State::users.
    user: usize,
    hdr: Vec<u8>,
    hold: Arc<Hold>,
    gate: Arc<net::TxGate>,
}

#[derive(Default)]
struct Counters {
    tun_rx: AtomicU64,
    tun_tx: AtomicU64,
    no_route: AtomicU64,
    too_large: AtomicU64,
    bad_dgram: AtomicU64,
    dgram_ok: AtomicU64,
    queue_drops: AtomicU64,
}

struct State {
    sessions: Mutex<HashMap<Ipv4Addr, Session>>,
    net: Ipv4Addr,
    prefix: u8,
    me: Ipv4Addr,
    users: crate::users::Users,
    c: Counters,
    hold_ms: u64,
    dgram_sndbuf: usize,
    queue_ms: u64,
}

pub async fn run(o: ServerOpts) -> Result<()> {
    let (me, prefix) = tunio::parse_cidr(&o.addr)?;
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let netaddr = Ipv4Addr::from(u32::from(me) & mask);
    let tun = Arc::new(tunio::create(&tunio::TunCfg { name: Some(o.tun.clone()), addr: me, prefix,
        dest: None, mtu: o.mtu })?);
    tracing::info!("tun {} {}/{} mtu {}", o.tun, me, prefix, o.mtu);

    let provider = crate::tls::provider();
    let (cert, key) = crate::tls::load_or_create(&o.cert_dir, &o.cert_name)?;
    tracing::info!("certificate sha256 {}", crate::tls::fingerprint(&cert));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = u32::MAX;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(tls)?));
    sc.transport_config(Arc::new(net::transport(&o.tuning)?));
    sc.migration(true);
    let sock = net::udp_socket(o.listen, None, o.tuning.sockbuf)?;
    let sock_stats = Arc::new(net::SockStats::default());
    let ep = quinn::Endpoint::new_with_abstract_socket(crate::net::endpoint_config(), Some(sc),
        net::UdpSock::new(sock, sock_stats.clone())?, Arc::new(quinn::TokioRuntime))?;
    tracing::info!("listening on udp {}", o.listen);

    let users = crate::users::Users::new(o.users, netaddr, prefix, me)?;
    tracing::info!("{} user(s)", users.len());
    let st = Arc::new(State { sessions: Mutex::new(HashMap::new()), net: netaddr, prefix, me, users, c: Counters::default(), hold_ms: o.hold_ms,
        dgram_sndbuf: o.tuning.dgram_sndbuf, queue_ms: o.tuning.queue_ms });

    // TUN -> clients.
    {
        let (st, tun) = (st.clone(), tun.clone());
        tokio::spawn(async move {
            loop {
                let mut b = BytesMut::with_capacity(2048);
                b.resize(8 + 2048 - 8, 0);
                let n = match tun.recv(&mut b[8..]).await {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::error!("tun read: {e}");
                        return;
                    }
                };
                st.c.tun_rx.fetch_add(1, Ordering::Relaxed);
                if n < 20 || b[8] >> 4 != 4 {
                    continue;
                }
                let dst = Ipv4Addr::new(b[8 + 16], b[8 + 17], b[8 + 18], b[8 + 19]);
                let (conn, hl, hold, gate) = {
                    let s = st.sessions.lock().unwrap();
                    match s.get(&dst) {
                        Some(sess) => {
                            let hl = sess.hdr.len();
                            b[8 - hl..8].copy_from_slice(&sess.hdr);
                            (sess.conn.clone(), hl, sess.hold.clone(), sess.gate.clone())
                        }
                        None => {
                            st.c.no_route.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                };
                b.truncate(8 + n);
                let _ = b.split_to(8 - hl);
                if hold.dead.load(Ordering::Relaxed) {
                    let mut q = hold.q.lock().unwrap();
                    if q.len() >= HOLD_MAX { q.pop_front(); }
                    q.push_back(b.freeze());
                    continue;
                }
                match gate.send(&conn, b.freeze()) {
                    net::GateResult::Sent => { st.c.dgram_ok.fetch_add(1, Ordering::Relaxed); }
                    net::GateResult::Dropped => { st.c.queue_drops.fetch_add(1, Ordering::Relaxed); }
                    net::GateResult::Err(quinn::SendDatagramError::TooLarge) => { st.c.too_large.fetch_add(1, Ordering::Relaxed); }
                    net::GateResult::Err(e) => tracing::debug!("send_datagram: {e}"),
                }
            }
        });
    }

    if o.stats_secs > 0 {
        let st = st.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(o.stats_secs)).await;
                let c = &st.c;
                tracing::info!("tun_rx={} tun_tx={} no_route={} too_large={} bad_dgram={} accepted={} queue_drops={} {}",
                    c.tun_rx.load(Ordering::Relaxed), c.tun_tx.load(Ordering::Relaxed), c.no_route.load(Ordering::Relaxed),
                    c.too_large.load(Ordering::Relaxed), c.bad_dgram.load(Ordering::Relaxed), c.dgram_ok.load(Ordering::Relaxed),
                    c.queue_drops.load(Ordering::Relaxed), sock_stats.line());
                for (ip, s) in st.sessions.lock().unwrap().iter() {
                    tracing::info!("{ip} {} {}", s.conn.remote_address(), net::stats_line(&s.conn));
                }
            }
        });
    }

    while let Some(inc) = ep.accept().await {
        let (st, tun) = (st.clone(), tun.clone());
        tokio::spawn(async move {
            let remote = inc.remote_address();
            if let Err(e) = handle(inc, st, tun).await {
                tracing::warn!("{remote}: {e:#}");
            }
        });
    }
    Ok(())
}

/// Assign an address. A user with a fixed address always gets it (whatever the client asked
/// for), taking it over from the user's older connection. Otherwise the address the client asked
/// for, if it is in the pool, fixed to nobody, and free or held by the same user (that is how a
/// client that reconnected keeps its inner address and flows); else the first free one. One user
/// never takes over another user's address.
fn allocate(st: &State, conn: &quinn::Connection, user: usize, hdr: Vec<u8>, want: Option<Ipv4Addr>, hold: Arc<Hold>, gate: Arc<net::TxGate>) -> Option<Ipv4Addr> {
    let mut s = st.sessions.lock().unwrap();
    let base = u32::from(st.net);
    let size = 1u32 << (32 - st.prefix);
    let fixed = st.users.get(user).addr;
    let pick = fixed.or_else(|| want.filter(|&w| {
        let off = u32::from(w).wrapping_sub(base);
        off >= 1 && off < size - 1 && w != st.me && !st.users.is_reserved(w) && s.get(&w).is_none_or(|x| x.user == user)
    }));
    if let Some(w) = pick {
        if let Some(old) = s.insert(w, Session { conn: conn.clone(), user, hdr, hold, gate }) {
            tracing::info!("{w} taken over from connection {} ({})", old.conn.stable_id(), old.conn.remote_address());
            old.conn.close(0u32.into(), b"address taken over");
        }
        return Some(w);
    }
    for i in 1..size - 1 {
        let ip = Ipv4Addr::from(base + i);
        if ip == st.me || s.contains_key(&ip) || st.users.is_reserved(ip) {
            continue;
        }
        s.insert(ip, Session { conn: conn.clone(), user, hdr, hold, gate });
        return Some(ip);
    }
    None
}

async fn handle(inc: quinn::Incoming, st: Arc<State>, tun: Arc<tun::AsyncDevice>) -> Result<()> {
    let conn = inc.await?;
    tracing::info!("connection from {} (local ip {:?})", conn.remote_address(), conn.local_ip());
    let mut h3c: h3::server::Connection<h3_quinn::Connection, Bytes> = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build(h3_quinn::Connection::new(conn.clone()))
        .await?;

    // Datagrams -> TUN. Every datagram on this connection with context id 0 belongs to its one
    // CONNECT-IP stream; the session's own address is enforced as inner source.
    let assigned: Arc<Mutex<Option<(u64, Ipv4Addr)>>> = Arc::new(Mutex::new(None));
    {
        let (conn, st, tun, assigned) = (conn.clone(), st.clone(), tun.clone(), assigned.clone());
        tokio::spawn(async move {
            while let Ok(d) = conn.read_datagram().await {
                let Some((q, ctx, off)) = proto::parse_datagram(&d) else { continue };
                let p = &d[off..];
                let ok = ctx == 0 && p.len() >= 20 && match *assigned.lock().unwrap() {
                    Some((sq, ip)) => sq == q && p[12..16] == ip.octets(),
                    None => false,
                };
                if !ok {
                    st.c.bad_dgram.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if tun.send(p).await.is_ok() {
                    st.c.tun_tx.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    let mut my_ip: Option<Ipv4Addr> = None;
    let res: Result<()> = async {
        loop {
            let Some(resolver) = h3c.accept().await? else { return Ok(()) };
            let (req, mut stream) = resolver.resolve_request().await?;
            let proto = req.extensions().get::<Protocol>().copied();
            let authz = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
            tracing::info!("request {} {} protocol={:?} capsule-protocol={:?}", req.method(), req.uri(), proto,
                req.headers().get("capsule-protocol"));
            if req.method() != Method::CONNECT || proto != Some(Protocol::CONNECT_IP) {
                stream.send_response(Response::builder().status(StatusCode::NOT_FOUND).body(())?).await?;
                stream.finish().await?;
                continue;
            }
            let Some(user) = st.users.check(authz) else {
                stream.send_response(Response::builder().status(StatusCode::PROXY_AUTHENTICATION_REQUIRED).body(())?).await?;
                stream.finish().await?;
                continue;
            };
            if my_ip.is_some() {
                bail!("second CONNECT-IP on one connection is not supported");
            }
            let sid = stream.id().into_inner();
            // An ADDRESS_REQUEST normally rides in the same flight as the request headers.
            let mut cr = proto::CapsuleReader::default();
            let (mut want, mut req_id) = (None, 0u64);
            let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
            'wait: while let Ok(Ok(Some(mut d))) = tokio::time::timeout_at(deadline, stream.recv_data()).await {
                cr.push(&d.copy_to_bytes(d.remaining()));
                while let Some((t, p)) = cr.next() {
                    tracing::info!("client capsule type {t:#x} {:?}", proto::parse_assign(&p));
                    if t == proto::CAP_ADDRESS_REQUEST {
                        for a in proto::parse_assign(&p).unwrap_or_default() {
                            if let IpAddr::V4(ip) = a.ip {
                                req_id = a.request_id;
                                if !ip.is_unspecified() { want = Some(ip); }
                            }
                        }
                        break 'wait;
                    }
                }
            }
            let hold = Arc::new(Hold::default());
            let gate = Arc::new(net::TxGate::new(st.dgram_sndbuf, st.queue_ms));
            let ip = allocate(&st, &conn, user, proto::datagram_header(sid), want, hold.clone(), gate.clone())
                .ok_or_else(|| anyhow!("pool exhausted"))?;
            if st.hold_ms > 0 {
                let (conn, hold_ms, gate) = (conn.clone(), st.hold_ms, gate.clone());
                tokio::spawn(async move {
                    let mut iv = tokio::time::interval(Duration::from_millis(25));
                    let (mut last_rx, mut last_change) = (0u64, std::time::Instant::now());
                    // The first path after a radio switch often dies again within a second (the
                    // operator's NAT): keep what was flushed and send it again if the client
                    // shows up from yet another address shortly after.
                    let mut flushed: Option<(std::time::Instant, SocketAddr, Vec<Bytes>)> = None;
                    let mut prev_remote: Option<SocketAddr> = None;
                    loop {
                        tokio::select! { _ = iv.tick() => {}, _ = conn.closed() => return }
                        let rx = conn.stats().udp_rx.datagrams;
                        if rx != last_rx {
                            last_rx = rx;
                            let remote = conn.remote_address();
                            // Back after a silence too short for a hold, or from a new address: the
                            // queue's age is the path's outage, not a standing queue.
                            if !hold.dead.load(Ordering::Relaxed)
                                && (last_change.elapsed() > Duration::from_millis(400) || prev_remote.is_some_and(|p| p != remote)) {
                                gate.restart();
                            }
                            prev_remote = Some(remote);
                            if hold.dead.swap(false, Ordering::AcqRel) {
                                let q: Vec<Bytes> = hold.q.lock().unwrap().drain(..).collect();
                                // What waited in quinn's queue waited for the path (see TxGate::restart).
                                gate.restart();
                                let sent = q.iter().filter(|d| matches!(gate.send(&conn, (*d).clone()), net::GateResult::Sent)).count();
                                tracing::info!("{ip}: HOLD end after {:?}, flushing {} packets to {remote} ({sent} accepted)", last_change.elapsed(), q.len());
                                if !q.is_empty() { flushed = Some((std::time::Instant::now(), remote, q)); }
                            } else if let Some((t, addr, q)) = &flushed {
                                if t.elapsed() > Duration::from_secs(4) {
                                    flushed = None;
                                } else if *addr != remote {
                                    tracing::info!("{ip}: client moved {addr} -> {remote} {:?} after a flush, re-sending {} packets",
                                        t.elapsed(), q.len());
                                    gate.restart();
                                    for d in q { let _ = gate.send(&conn, d.clone()); }
                                    flushed = None;
                                }
                            }
                            last_change = std::time::Instant::now();
                        } else if !hold.dead.load(Ordering::Relaxed) && last_change.elapsed() > Duration::from_millis(hold_ms) {
                            hold.dead.store(true, Ordering::Release);
                            tracing::info!("{ip}: HOLD start (client silent {:?})", last_change.elapsed());
                        }
                    }
                });
            }
            my_ip = Some(ip);
            *assigned.lock().unwrap() = Some((sid / 4, ip));
            stream.send_response(Response::builder().status(StatusCode::OK).header("capsule-protocol", "?1").body(())?).await?;
            let mut caps = proto::address_assign(&[proto::Assigned { request_id: req_id, ip: IpAddr::V4(ip), prefix: 32 }]);
            let bcast = Ipv4Addr::from(u32::from(st.net) | !(u32::MAX << (32 - st.prefix)));
            caps.extend(proto::route_advertisement(&[proto::Range { start: IpAddr::V4(st.net), end: IpAddr::V4(bcast), proto: 0 }]));
            stream.send_data(Bytes::from(caps)).await?;
            tracing::info!("assigned {ip} to {} {} (stream {sid}, max datagram {:?})", st.users.get(user).name, conn.remote_address(), conn.max_datagram_size());

            // Capsules from the client: logged (ADDRESS_REQUEST is answered by the assign above).
            tokio::spawn(async move {
                loop {
                    match stream.recv_data().await {
                        Ok(Some(mut d)) => {
                            let b = d.copy_to_bytes(d.remaining());
                            cr.push(&b);
                            while let Some((t, p)) = cr.next() {
                                tracing::info!("client capsule type {t:#x} len {}", p.len());
                            }
                        }
                        Ok(None) => { tracing::info!("request stream closed"); return; }
                        Err(e) => { tracing::info!("request stream: {e}"); return; }
                    }
                }
            });
        }
    }
    .await;
    if let Some(ip) = my_ip {
        let mut s = st.sessions.lock().unwrap();
        if s.get(&ip).is_some_and(|x| x.conn.stable_id() == conn.stable_id()) {
            s.remove(&ip);
            tracing::info!("released {ip}");
        }
    }
    res.context("h3")
}
