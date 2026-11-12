//! `maski probe`: N fresh connections one after another (new socket each), each doing the QUIC
//! handshake, CONNECT-IP, then ~50 ICMP echoes to the server's tunnel address over 3 s as HTTP
//! datagrams. One CSV line per attempt: did it pass, where it stopped, and the ClientHello
//! extension-order seed rustls used. With SSLKEYLOGFILE set the TLS secrets are logged for tshark.
//! The echoes go to the first address of the assigned /24 (the server's tunnel address), or to
//! `$MASKI_PROBE_DST`. With `primer` every fresh socket first sends the 32-byte throw-away datagram
//! the client sends on migration sockets (`net::send_primer`), for a DPI A/B on fresh flows.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use base64::Engine;
use bytes::{Buf, Bytes};
use h3::ext::Protocol;
use http::{Method, Request, StatusCode};

use crate::net::{self, KillableSocket, QuicTuning};
use crate::proto;

pub struct ProbeOpts {
    pub server: SocketAddr,
    pub sni: String,
    pub interface: Option<String>,
    pub pin: String,
    pub user: String,
    pub pass: String,
    pub path: String,
    pub count: u32,
    pub gap_ms: u64,
    /// None = rustls default (random per connection); Some(seed) = fixed extension order.
    pub ext_seed: Option<u16>,
    /// Seeds to cycle through (overrides ext_seed), for a causal A/B in one run.
    pub seeds: Vec<u16>,
    /// DCID modes to cycle through per attempt (overrides --initial-dcid), for an interleaved A/B.
    pub dcid_cycle: Vec<net::DcidMode>,
    /// Comma list of primer settings to cycle through per attempt (after the DCID cycle).
    pub primer_cycle: Vec<bool>,
    pub out: String,
    pub tuning: QuicTuning,
}

fn csum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in b.chunks(2) {
        s += u32::from(c[0]) << 8 | u32::from(*c.get(1).unwrap_or(&0));
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
    let mut icmp = vec![8u8, 0, 0, 0];
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(&[0x55; 32]);
    let c = csum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0];
    let tl = (20 + icmp.len()) as u16;
    ip[2..4].copy_from_slice(&tl.to_be_bytes());
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let c = csum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

#[derive(Default, Debug)]
struct Attempt {
    port: u16,
    seed: u32,
    handshake_ms: Option<u128>,
    connectip_ms: Option<u128>,
    sent: u32,
    replies: u32,
    last_reply_ms: Option<u128>,
    err: String,
}

async fn one(o: &ProbeOpts, seed: Option<u16>, dcid: net::DcidMode, primer: bool, idx: u32) -> Attempt {
    let mut a = Attempt::default();
    let r: Result<()> = async {
        let (provider, rnd) = crate::tls::client_provider(seed);
        let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(crate::tls::PinVerifier::new(&o.pin, provider)?)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.key_log = Arc::new(rustls::KeyLogFile::new());
        let mut cc = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?));
        cc.transport_config(Arc::new(net::transport(&o.tuning)?));
        if let Some(f) = net::dcid_provider(dcid) {
            cc.initial_dst_cid_provider(f);
        }
        let bind: SocketAddr = "0.0.0.0:0".parse()?;
        let epoch = Instant::now();
        let raw = net::udp_socket(bind, o.interface.as_deref(), o.tuning.sockbuf)?;
        if primer {
            net::send_primer(&raw, o.server);
        }
        let sock = KillableSocket::new(raw, Arc::new(AtomicU64::new(0)), epoch, Default::default())?;
        {
            use quinn::AsyncUdpSocket;
            a.port = sock.local_addr()?.port();
        }
        let ep = quinn::Endpoint::new_with_abstract_socket(net::endpoint_config(), None, sock, Arc::new(quinn::TokioRuntime))?;
        let t0 = Instant::now();
        let conn = tokio::time::timeout(Duration::from_secs(3), ep.connect_with(cc, o.server, &o.sni)?).await;
        a.seed = rnd.last.load(Ordering::Relaxed);
        let conn = match conn {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => bail!("handshake: {e}"),
            Err(_) => bail!("handshake timeout"),
        };
        a.handshake_ms = Some(t0.elapsed().as_millis());
        let (mut driver, mut send_req) = h3::client::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
            .await?;
        let drv = tokio::spawn(async move { let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await; });
        let auth = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", o.user, o.pass)));
        let uri = http::Uri::builder().scheme("https").authority(o.sni.as_str()).path_and_query(o.path.as_str()).build()?;
        let req = Request::builder().method(Method::CONNECT).uri(uri).header("capsule-protocol", "?1")
            .header("authorization", auth).extension(Protocol::CONNECT_IP).body(())?;
        let res = tokio::time::timeout(Duration::from_secs(3), async {
            let mut stream = send_req.send_request(req).await?;
            // $MASKI_PROBE_ASK: ask for this address (tests of the server's address policy).
            let want = std::env::var("MASKI_PROBE_ASK").ok().and_then(|a| a.parse().ok()).unwrap_or(Ipv4Addr::UNSPECIFIED);
            let ask = proto::Assigned { request_id: 1, ip: IpAddr::V4(want), prefix: 32 };
            stream.send_data(Bytes::from(proto::address_request(&[ask]))).await?;
            let resp = stream.recv_response().await?;
            if resp.status() != StatusCode::OK { bail!("status {}", resp.status()); }
            let mut cr = proto::CapsuleReader::default();
            loop {
                let Some(mut d) = stream.recv_data().await? else { bail!("stream ended") };
                cr.push(&d.copy_to_bytes(d.remaining()));
                while let Some((t, p)) = cr.next() {
                    if t == proto::CAP_ADDRESS_ASSIGN {
                        for x in proto::parse_assign(&p).unwrap_or_default() {
                            if let IpAddr::V4(ip) = x.ip { return Ok((stream, ip)); }
                        }
                    }
                }
            }
        }).await;
        let (_stream, me) = match res {
            Ok(Ok(x)) => x,
            Ok(Err(e)) => bail!("connect-ip: {e:#}"),
            Err(_) => bail!("connect-ip timeout"),
        };
        a.connectip_ms = Some(t0.elapsed().as_millis());
        let hdr = proto::datagram_header(0);
        let dst: Ipv4Addr = match std::env::var("MASKI_PROBE_DST") {
            Ok(d) => d.parse()?,
            Err(_) => Ipv4Addr::from(u32::from(me) & 0xffff_ff00 | 1),
        };
        let t1 = Instant::now();
        let rx = {
            let conn = conn.clone();
            tokio::spawn(async move {
                let (mut n, mut last) = (0u32, None);
                while let Ok(Ok(_d)) = tokio::time::timeout(Duration::from_millis(3500).saturating_sub(t1.elapsed()), conn.read_datagram()).await {
                    n += 1;
                    last = Some(t1.elapsed().as_millis());
                }
                (n, last)
            })
        };
        for seq in 0..50u16 {
            let mut d = hdr.clone();
            d.extend(icmp_echo(me, dst, 0x6d71 ^ idx as u16, seq));
            let _ = conn.send_datagram(Bytes::from(d));
            a.sent += 1;
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        let (n, last) = rx.await?;
        a.replies = n;
        a.last_reply_ms = last;
        conn.close(0u32.into(), b"probe done");
        drv.abort();
        ep.wait_idle().await;
        Ok(())
    }
    .await;
    if let Err(e) = r {
        a.err = format!("{e:#}").replace(',', ";");
    }
    a
}

pub async fn run(o: ProbeOpts) -> Result<()> {
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&o.out)?;
    writeln!(f, "idx,unix_ms,port,dcid,primer,seed,forced,handshake_ms,connectip_ms,sent,replies,last_reply_ms,pass,err")?;
    let mut pass = 0;
    for i in 0..o.count {
        let seed = if !o.seeds.is_empty() { Some(o.seeds[i as usize % o.seeds.len()]) } else { o.ext_seed };
        let dcid = if o.dcid_cycle.is_empty() { o.tuning.dcid } else { o.dcid_cycle[i as usize % o.dcid_cycle.len()] };
        // The primer cycle advances once per full DCID cycle, so every (dcid, primer) pair comes up.
        let primer = if o.primer_cycle.is_empty() { false } else {
            o.primer_cycle[(i as usize / o.dcid_cycle.len().max(1)) % o.primer_cycle.len()]
        };
        let a = one(&o, seed, dcid, primer, i).await;
        let ok = a.replies >= 40;
        pass += ok as u32;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis();
        let line = format!("{i},{now},{},{dcid:?},{},{},{},{},{},{},{},{},{},{}", a.port, primer as u8, a.seed, seed.map(|s| s.to_string()).unwrap_or_default(),
            a.handshake_ms.map(|x| x.to_string()).unwrap_or_default(), a.connectip_ms.map(|x| x.to_string()).unwrap_or_default(),
            a.sent, a.replies, a.last_reply_ms.map(|x| x.to_string()).unwrap_or_default(), ok as u8, a.err);
        writeln!(f, "{line}")?;
        println!("{line}");
        tokio::time::sleep(Duration::from_millis(o.gap_ms)).await;
    }
    println!("PASS {pass}/{}", o.count);
    Ok(())
}
