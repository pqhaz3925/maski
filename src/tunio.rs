//! TUN device setup (Linux `maski0`, macOS `utunN`).

use std::net::Ipv4Addr;

use anyhow::{anyhow, bail, Context, Result};

pub struct TunCfg {
    pub name: Option<String>,
    pub addr: Ipv4Addr,
    pub prefix: u8,
    /// Point-to-point peer (macOS utun); the route for addr/prefix goes via it.
    pub dest: Option<Ipv4Addr>,
    pub mtu: u16,
}

pub fn parse_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip, p) = s.split_once('/').ok_or_else(|| anyhow!("CIDR expected, got {s}"))?;
    let p: u8 = p.parse()?;
    if p > 32 {
        bail!("bad prefix /{p}");
    }
    Ok((ip.parse()?, p))
}

pub fn mask(prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) })
}

#[cfg(feature = "cli")]
pub fn create(cfg: &TunCfg) -> Result<tun::AsyncDevice> {
    use tun::AbstractDevice;
    let mut c = tun::Configuration::default();
    if let Some(n) = &cfg.name {
        c.tun_name(n);
    }
    c.address(cfg.addr).netmask(mask(cfg.prefix)).mtu(cfg.mtu).up();
    if let Some(d) = cfg.dest {
        c.destination(d);
    }
    let dev = tun::create_as_async(&c).context("creating tun")?;
    let name = dev.tun_name().unwrap_or_default();
    tracing::info!("tun device {name}");
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip").args(["link", "set", "dev", &name, "txqueuelen", "10000"]).status();
    }
    Ok(dev)
}

/// Wrap an already-open utun/tun file descriptor (e.g. the one behind an Apple
/// `NEPacketTunnelFlow`). The descriptor is not closed when the device is dropped.
pub fn from_fd(fd: i32, mtu: u16) -> Result<tun::AsyncDevice> {
    let mut c = tun::Configuration::default();
    c.raw_fd(fd).close_fd_on_drop(false).mtu(mtu);
    tun::create_as_async(&c).context("wrapping tun fd")
}
