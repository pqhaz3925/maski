//! Wire bits of RFC 9000 varints, RFC 9297 capsules / HTTP datagrams and RFC 9484 CONNECT-IP
//! capsules (ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const CAP_DATAGRAM: u64 = 0x00;
pub const CAP_ADDRESS_ASSIGN: u64 = 0x01;
pub const CAP_ADDRESS_REQUEST: u64 = 0x02;
pub const CAP_ROUTE_ADVERTISEMENT: u64 = 0x03;

pub fn varint_len(v: u64) -> usize {
    match v {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1_073_741_823 => 4,
        _ => 8,
    }
}

pub fn put_varint(buf: &mut Vec<u8>, v: u64) {
    match varint_len(v) {
        1 => buf.push(v as u8),
        2 => buf.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        4 => buf.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => buf.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// Decode a varint at the start of `b`: (value, bytes consumed).
pub fn get_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for &x in &b[1..len] {
        v = (v << 8) | x as u64;
    }
    Some((v, len))
}

/// Prefix of every HTTP datagram we send on a request stream: quarter stream id + context id 0.
pub fn datagram_header(stream_id: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(4);
    put_varint(&mut h, stream_id / 4);
    put_varint(&mut h, 0);
    h
}

/// Parse an HTTP datagram: (quarter stream id, context id, payload offset).
pub fn parse_datagram(b: &[u8]) -> Option<(u64, u64, usize)> {
    let (q, n1) = get_varint(b)?;
    let (c, n2) = get_varint(&b[n1..])?;
    Some((q, c, n1 + n2))
}

fn put_ip(buf: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(a) => {
            buf.push(4);
            buf.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            buf.push(6);
            buf.extend_from_slice(&a.octets());
        }
    }
}

fn capsule(t: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    put_varint(&mut out, t);
    put_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Assigned {
    pub request_id: u64,
    pub ip: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Range {
    pub start: IpAddr,
    pub end: IpAddr,
    pub proto: u8,
}

pub fn address_assign(list: &[Assigned]) -> Vec<u8> {
    let mut p = Vec::new();
    for a in list {
        put_varint(&mut p, a.request_id);
        put_ip(&mut p, a.ip);
        p.push(a.prefix);
    }
    capsule(CAP_ADDRESS_ASSIGN, &p)
}

pub fn address_request(list: &[Assigned]) -> Vec<u8> {
    let mut p = Vec::new();
    for a in list {
        put_varint(&mut p, a.request_id);
        put_ip(&mut p, a.ip);
        p.push(a.prefix);
    }
    capsule(CAP_ADDRESS_REQUEST, &p)
}

pub fn route_advertisement(list: &[Range]) -> Vec<u8> {
    let mut p = Vec::new();
    for r in list {
        put_ip(&mut p, r.start);
        match r.end {
            IpAddr::V4(a) => p.extend_from_slice(&a.octets()),
            IpAddr::V6(a) => p.extend_from_slice(&a.octets()),
        }
        p.push(r.proto);
    }
    capsule(CAP_ROUTE_ADVERTISEMENT, &p)
}

fn get_ip(b: &[u8]) -> Option<(IpAddr, usize)> {
    match *b.first()? {
        4 if b.len() >= 5 => Some((IpAddr::V4(Ipv4Addr::new(b[1], b[2], b[3], b[4])), 5)),
        6 if b.len() >= 17 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[1..17]);
            Some((IpAddr::V6(Ipv6Addr::from(o)), 17))
        }
        _ => None,
    }
}

/// ADDRESS_ASSIGN / ADDRESS_REQUEST payload.
pub fn parse_assign(mut b: &[u8]) -> Option<Vec<Assigned>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (request_id, n) = get_varint(b)?;
        b = &b[n..];
        let (ip, n) = get_ip(b)?;
        b = &b[n..];
        let prefix = *b.first()?;
        b = &b[1..];
        out.push(Assigned { request_id, ip, prefix });
    }
    Some(out)
}

pub fn parse_routes(mut b: &[u8]) -> Option<Vec<Range>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (start, n) = get_ip(b)?;
        b = &b[n..];
        let alen = if start.is_ipv4() { 4 } else { 16 };
        if b.len() < alen + 1 {
            return None;
        }
        let end = if alen == 4 {
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        } else {
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[..16]);
            IpAddr::V6(Ipv6Addr::from(o))
        };
        let proto = b[alen];
        b = &b[alen + 1..];
        out.push(Range { start, end, proto });
    }
    Some(out)
}

/// Incremental capsule parser over the request-stream DATA bytes.
#[derive(Default)]
pub struct CapsuleReader {
    buf: Vec<u8>,
}

impl CapsuleReader {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn next(&mut self) -> Option<(u64, Vec<u8>)> {
        let (t, n1) = get_varint(&self.buf)?;
        let (len, n2) = get_varint(&self.buf[n1..])?;
        let start = n1 + n2;
        let end = start + len as usize;
        if self.buf.len() < end {
            return None;
        }
        let payload = self.buf[start..end].to_vec();
        self.buf.drain(..end);
        Some((t, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        for v in [0u64, 63, 64, 16383, 16384, 1 << 29, 1 << 40] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(get_varint(&b), Some((v, b.len())));
        }
    }

    #[test]
    fn capsules_roundtrip() {
        let a = Assigned { request_id: 0, ip: "10.90.0.2".parse().unwrap(), prefix: 32 };
        let r = Range { start: "10.90.0.0".parse().unwrap(), end: "10.90.0.255".parse().unwrap(), proto: 0 };
        let mut cr = CapsuleReader::default();
        let mut all = address_assign(&[a]);
        all.extend(route_advertisement(&[r]));
        cr.push(&all[..3]);
        assert!(cr.next().is_none());
        cr.push(&all[3..]);
        let (t, p) = cr.next().unwrap();
        assert_eq!(t, CAP_ADDRESS_ASSIGN);
        assert_eq!(parse_assign(&p).unwrap(), vec![a]);
        let (t, p) = cr.next().unwrap();
        assert_eq!(t, CAP_ROUTE_ADVERTISEMENT);
        assert_eq!(parse_routes(&p).unwrap(), vec![r]);
    }
}
