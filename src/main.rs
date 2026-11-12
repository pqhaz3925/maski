//! maski — spike of an L3 VPN over standard MASQUE CONNECT-IP (RFC 9484), HTTP/3 datagrams
//! (RFC 9297) on QUIC (quinn).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use maski::{client, net, probe, server, tunio, users};

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Tuning {
    /// rate[:gain[:startup gain[:startup mode 0|1]]] | cubic | bbr | newreno | fixed:<bytes>. `rate` (default): in-flight capped at
    /// gain (2) x delivery rate x min RTT, loss ignored (see net::Rate). Loss-based controllers
    /// collapse on the home line's random loss (cubic 30-45 Mbit/s, bbr ~190); `fixed` has no
    /// limit and fills a cellular operator's buffer.
    #[arg(long, default_value = "rate")]
    cc: String,
    /// Refuse datagrams while the oldest one in the send queue has waited longer than this
    /// (4x for packets <= 200 bytes); 0 = off (quinn then drops the oldest when the queue is full).
    #[arg(long, default_value_t = 30)]
    queue_ms: u64,
    /// UDP payload size assumed before MTU discovery.
    #[arg(long, default_value_t = 1440)]
    initial_mtu: u16,
    /// UDP payload size quinn never falls below (its black-hole detection otherwise drops to
    /// 1200 after a loss burst, and every 1400-byte inner packet becomes too large).
    #[arg(long, default_value_t = 1440)]
    min_mtu: u16,
    /// MTU discovery upper bound (UDP payload).
    #[arg(long, default_value_t = 1472)]
    mtu_upper: u16,
    /// quinn datagram send buffer (bytes); when full the oldest datagram is dropped.
    #[arg(long, default_value_t = 2 * 1024 * 1024)]
    dgram_sndbuf: usize,
    /// quinn datagram receive buffer (bytes): received datagrams not yet handed to the TUN.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    dgram_rcvbuf: usize,
    /// SO_RCVBUF/SO_SNDBUF of the outer UDP sockets (bytes).
    #[arg(long, default_value_t = net::SOCKBUF)]
    sockbuf: usize,
    #[arg(long, default_value_t = 100)]
    keepalive_ms: u64,
    #[arg(long, default_value_t = 30000)]
    idle_timeout_ms: u64,
    /// Disable UDP GSO batching (Linux).
    #[arg(long)]
    no_gso: bool,
    /// Ask the peer (ACK frequency extension) to ACK only every N+1 ack-eliciting packets.
    #[arg(long)]
    ack_threshold: Option<u32>,
    /// RTT assumed before the first sample (drives Initial retransmits on a reconnect).
    #[arg(long, default_value_t = 333)]
    initial_rtt_ms: u64,
    /// Client: how to pick the first Initial's DCID (see net::DcidMode). `low` keeps the first
    /// 16 bytes of the first datagram under the mobile operator's popcount line.
    #[arg(long, value_enum, default_value = "low")]
    initial_dcid: net::DcidMode,
}

impl Tuning {
    fn q(&self) -> net::QuicTuning {
        net::QuicTuning {
            cc: self.cc.clone(),
            initial_mtu: self.initial_mtu,
            min_mtu: self.min_mtu,
            mtu_upper: self.mtu_upper,
            dgram_sndbuf: self.dgram_sndbuf,
            dgram_rcvbuf: self.dgram_rcvbuf,
            sockbuf: self.sockbuf,
            keepalive_ms: self.keepalive_ms,
            idle_timeout_ms: self.idle_timeout_ms,
            gso: !self.no_gso,
            ack_threshold: self.ack_threshold,
            initial_rtt_ms: self.initial_rtt_ms,
            dcid: self.initial_dcid,
            queue_ms: self.queue_ms,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the CONNECT-IP server.
    Server {
        #[arg(long, default_value = "0.0.0.0:8445")]
        listen: SocketAddr,
        #[arg(long, default_value = "maski0")]
        tun: String,
        #[arg(long, default_value = "10.90.0.1/24")]
        addr: String,
        #[arg(long, default_value_t = 1400)]
        mtu: u16,
        #[arg(long, default_value = "./cert")]
        cert_dir: PathBuf,
        #[arg(long, default_value = "maski.local")]
        cert_name: String,
        /// Single user (no fixed address); may be combined with --users.
        #[arg(long, requires = "pass")]
        user: Option<String>,
        #[arg(long, env = "MASKI_PASS")]
        pass: Option<String>,
        /// Users file: `name password [fixed tunnel address]` per line (see users.rs).
        #[arg(long, required_unless_present = "user")]
        users: Option<PathBuf>,
        #[arg(long, default_value_t = 0)]
        stats_secs: u64,
        /// Hold a client's downlink while it is silent this long, flush when it is back (0 = off).
        #[arg(long, default_value_t = 0)]
        hold_ms: u64,
        #[command(flatten)]
        tuning: Tuning,
    },
    /// Open N fresh connections one after another and test each (no TUN, no root needed).
    Probe {
        #[arg(long)]
        server: SocketAddr,
        #[arg(long, default_value = "www.example.com")]
        sni: String,
        #[arg(long)]
        interface: Option<String>,
        #[arg(long)]
        pin: String,
        #[arg(long)]
        user: String,
        #[arg(long, env = "MASKI_PASS")]
        pass: String,
        #[arg(long, default_value = "/.well-known/masque/ip/*/*/")]
        path: String,
        #[arg(long, default_value_t = 60)]
        count: u32,
        #[arg(long, default_value_t = 1000)]
        gap_ms: u64,
        /// Pin rustls's ClientHello extension-order seed (default: random per connection).
        #[arg(long)]
        ext_seed: Option<u16>,
        /// Comma list of seeds to cycle through.
        #[arg(long, value_delimiter = ',')]
        seeds: Vec<u16>,
        /// Comma list of DCID modes to cycle through per attempt (random,low,high).
        #[arg(long, value_delimiter = ',', value_enum)]
        dcid_cycle: Vec<net::DcidMode>,
        /// Comma list of primer settings (true,false) to cycle through, one step per full DCID
        /// cycle: each fresh socket first sends the 32-byte throw-away datagram (net::send_primer).
        #[arg(long, value_delimiter = ',')]
        primer_cycle: Vec<bool>,
        #[arg(long, default_value = "probe.csv")]
        out: String,
        #[command(flatten)]
        tuning: Tuning,
    },
    /// Run the client (needs root for the TUN device).
    Client {
        #[arg(long)]
        server: SocketAddr,
        #[arg(long, default_value = "maski.local")]
        sni: String,
        /// Pin every outer UDP socket to this interface (IP_BOUND_IF / SO_BINDTODEVICE).
        #[arg(long)]
        interface: Option<String>,
        /// SHA-256 of the server certificate (hex), or "any".
        #[arg(long)]
        pin: String,
        #[arg(long)]
        user: String,
        #[arg(long, env = "MASKI_PASS")]
        pass: String,
        #[arg(long, default_value = "/.well-known/masque/ip/*/*/")]
        path: String,
        #[arg(long, default_value_t = 1400)]
        tun_mtu: u16,
        #[arg(long, default_value = "10.90.0.0/24")]
        route: String,
        #[arg(long)]
        tun_peer: Option<Ipv4Addr>,
        /// Migrate to a new socket when nothing arrived for this long (0 = off).
        #[arg(long, default_value_t = 400)]
        dead_ms: u64,
        #[arg(long, default_value_t = 0)]
        stats_secs: u64,
        #[arg(long)]
        send_wait: bool,
        /// What to do when the path goes silent: migrate (same QUIC connection, new socket),
        /// reconnect (new socket + new QUIC connection + new CONNECT-IP asking for the same inner
        /// address), or hybrid (migrate first, reconnect if still silent after another dead-ms).
        #[arg(long, default_value = "migrate")]
        recover: String,
        /// Reconnect: a fresh QUIC handshake (own socket) every this many ms, each allowed 4x as long;
        /// the first to complete sends the CONNECT-IP request.
        #[arg(long, default_value_t = 1000)]
        attempt_ms: u64,
        /// After an outage, migrate once more this long after traffic resumes (0 = off).
        #[arg(long, default_value_t = 0)]
        remigrate_ms: u64,
        /// recover=migrate: after this long with nothing received (and moves done), also race
        /// fresh connections; the old one is kept and wins if it answers first (0 = off). For a
        /// server that restarted without its old keys.
        #[arg(long, default_value_t = 5000)]
        race_ms: u64,
        /// Do not open migration sockets with a short throw-away datagram (see net::send_primer).
        #[arg(long)]
        no_primer: bool,
        /// Interfaces to fall back to when the pinned one is dead (comma list; needs --interface).
        #[arg(long, value_delimiter = ',')]
        alt_interface: Vec<String>,
        /// Exit after this many seconds (0 = run until Ctrl-C); for test runs under sudo.
        #[arg(long, default_value_t = 0)]
        exit_after_secs: u64,
        /// tokio worker threads (0 = a single-threaded runtime, as in the Apple extension).
        #[arg(long, default_value_t = 4)]
        threads: usize,
        #[command(flatten)]
        tuning: Tuning,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    let threads = match &cli.cmd { Cmd::Client { threads, .. } => *threads, _ => 4 };
    let rt = if threads == 0 {
        tokio::runtime::Builder::new_current_thread().enable_all().build()?
    } else {
        tokio::runtime::Builder::new_multi_thread().worker_threads(threads).enable_all().build()?
    };
    rt.block_on(async move {
        match cli.cmd {
            Cmd::Server { listen, tun, addr, mtu, cert_dir, cert_name, user, pass, users: users_file, stats_secs, hold_ms, tuning } => {
                let mut list = match &users_file { Some(f) => users::load(f)?, None => vec![] };
                if let (Some(name), Some(pass)) = (user, pass) {
                    list.push(users::User { name, pass, addr: None });
                }
                server::run(server::ServerOpts { listen, tun, addr, mtu, cert_dir, cert_name, users: list,
                    tuning: tuning.q(), stats_secs, hold_ms }).await
            }
            Cmd::Probe { server, sni, interface, pin, user, pass, path, count, gap_ms, ext_seed, seeds, dcid_cycle, primer_cycle, out, tuning } => {
                probe::run(probe::ProbeOpts { server, sni, interface, pin, user, pass, path, count, gap_ms, ext_seed, seeds, dcid_cycle, primer_cycle, out,
                    tuning: tuning.q() }).await
            }
            Cmd::Client { server, sni, interface, pin, user, pass, path, tun_mtu, route, tun_peer, dead_ms, stats_secs,
                send_wait, recover, attempt_ms, remigrate_ms, race_ms, no_primer, alt_interface, exit_after_secs, threads: _, tuning } => {
                let h = client::start(client::ClientOpts { server, sni, interface, pin, user, pass, path,
                    tuning: tuning.q(), dead_ms, stats_secs, send_wait, recover: recover.clone(), attempt_ms, remigrate_ms, first_attempts: 30,
                    primer: !no_primer, alternates: alt_interface, race_ms }).await?;
                let addr = h.addr();
                let (rnet, rprefix) = tunio::parse_cidr(&route)?;
                let peer = tun_peer.unwrap_or_else(|| Ipv4Addr::from(u32::from(rnet) + 1));
                let tun = Arc::new(tunio::create(&tunio::TunCfg { name: None, addr, prefix: rprefix, dest: Some(peer), mtu: tun_mtu })?);
                h.set_output(Some(client::PacketOut::Tun(tun.clone())));
                tracing::info!("tunnel address {addr}, route {route} via tun, mtu {tun_mtu}, recover={recover} dead_ms={dead_ms} keepalive_ms={}",
                    tuning.keepalive_ms);
                tokio::spawn(client::pump_tun(h.clone(), tun));
                // SIGUSR1 = migrate now, SIGUSR2 = black-hole the current socket (simulated path
                // death), SIGHUP = reconnect now.
                use tokio::signal::unix::{signal, SignalKind};
                let mut u1 = signal(SignalKind::user_defined1())?;
                let mut u2 = signal(SignalKind::user_defined2())?;
                let mut hup = signal(SignalKind::hangup())?;
                // $MASKI_HOLE_FILE is also polled (every 200 ms, applied when it changes), so a
                // test can drive the black hole of a root client without signalling it.
                let hole_file = std::env::var("MASKI_HOLE_FILE").ok();
                let mut hole_seen = String::new();
                let mut tick = tokio::time::interval(std::time::Duration::from_millis(200));
                let deadline = (exit_after_secs > 0).then(|| tokio::time::Instant::now() + std::time::Duration::from_secs(exit_after_secs));
                loop {
                    tokio::select! {
                        _ = tick.tick() => {
                            if deadline.is_some_and(|d| tokio::time::Instant::now() >= d) { break; }
                            if let Some(l) = hole_file.as_ref().and_then(|f| std::fs::read_to_string(f).ok()) {
                                if !l.trim().is_empty() && l != hole_seen {
                                    let mut w = l.split_whitespace();
                                    let i = w.next().filter(|i| *i != "-");
                                    let m = w.next().and_then(|m| m.parse().ok()).unwrap_or(1);
                                    h.test_blackhole(i, m);
                                    hole_seen = l;
                                }
                            }
                        }
                        // With $MASKI_IFACE_FILE set, SIGUSR1 is a network change to the interface
                        // named in that file (as the Apple extension's maski_network_changed).
                        _ = u1.recv() => match std::env::var("MASKI_IFACE_FILE").ok().and_then(|f| std::fs::read_to_string(f).ok()) {
                            Some(i) => h.network_changed(Some(i.trim())),
                            None => h.migrate("command"),
                        },
                        // With $MASKI_HOLE_FILE set, SIGUSR2 applies "<interface|-> <mode>" from that
                        // file (test black hole, see Handle::test_blackhole).
                        _ = u2.recv() => match std::env::var("MASKI_HOLE_FILE").ok().and_then(|f| std::fs::read_to_string(f).ok()) {
                            Some(l) => {
                                let mut w = l.split_whitespace();
                                let i = w.next().filter(|i| *i != "-");
                                let m = w.next().and_then(|m| m.parse().ok()).unwrap_or(1);
                                h.test_blackhole(i, m);
                            }
                            None => h.kill_current(),
                        },
                        _ = hup.recv() => h.reconnect("command"),
                        _ = tokio::signal::ctrl_c() => break,
                    }
                }
                h.stop();
                Ok(())
            }
        }
    })
}
