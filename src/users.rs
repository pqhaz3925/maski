//! Server users: who may connect and which tunnel address each one gets.
//!
//! A user either has a fixed address (always assigned to that user, never to anyone else, so
//! policy on the server can match it as an inner source address) or takes one from the pool.
//! The users file has one user per line, `#` starts a comment:
//!
//! ```text
//! # name      password            [fixed address]
//! admin       s3cret              10.90.0.2
//! friend      other-secret
//! ```
//!
//! Names and passwords cannot contain whitespace or `:` (name only); the address must lie inside the
//! server's pool and be neither the server's own address nor the network/broadcast address.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine;

#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub pass: String,
    pub addr: Option<Ipv4Addr>,
}

/// Users indexed by their `Authorization` header value.
pub struct Users {
    list: Vec<User>,
    by_auth: HashMap<String, usize>,
    reserved: HashSet<Ipv4Addr>,
}

impl Users {
    /// Check the list against the pool (`net`/`prefix`, server address `me`) and index it.
    pub fn new(list: Vec<User>, net: Ipv4Addr, prefix: u8, me: Ipv4Addr) -> Result<Self> {
        if list.is_empty() {
            bail!("no users");
        }
        let base = u32::from(net);
        let size = 1u64 << (32 - prefix as u32);
        let (mut by_auth, mut reserved, mut names) = (HashMap::new(), HashSet::new(), HashSet::new());
        for (i, u) in list.iter().enumerate() {
            if u.name.is_empty() || u.name.contains(':') || u.name.contains(char::is_whitespace) {
                bail!("bad user name {:?}", u.name);
            }
            if u.pass.is_empty() {
                bail!("user {}: empty password", u.name);
            }
            if !names.insert(u.name.clone()) {
                bail!("user {} listed twice", u.name);
            }
            if let Some(a) = u.addr {
                let off = u32::from(a).wrapping_sub(base) as u64;
                if off == 0 || off >= size - 1 || a == me {
                    bail!("user {}: address {a} is not a client address of {net}/{prefix}", u.name);
                }
                if !reserved.insert(a) {
                    bail!("user {}: address {a} given to two users", u.name);
                }
            }
            by_auth.insert(auth_header(&u.name, &u.pass), i);
        }
        Ok(Users { list, by_auth, reserved })
    }

    /// The user whose credentials are in this `Authorization` header value.
    pub fn check(&self, authz: &str) -> Option<usize> {
        self.by_auth.get(authz).copied()
    }

    pub fn get(&self, i: usize) -> &User {
        &self.list[i]
    }

    /// Fixed to some user (so never handed out from the pool or on request).
    pub fn is_reserved(&self, a: Ipv4Addr) -> bool {
        self.reserved.contains(&a)
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }
}

pub fn auth_header(user: &str, pass: &str) -> String {
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}")))
}

pub fn parse(text: &str) -> Result<Vec<User>> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let addr = match f.len() {
            2 => None,
            3 => Some(f[2].parse::<Ipv4Addr>().with_context(|| format!("line {}: bad address {:?}", n + 1, f[2]))?),
            _ => bail!("line {}: expected `name password [address]`", n + 1),
        };
        out.push(User { name: f[0].to_string(), pass: f[1].to_string(), addr });
    }
    Ok(out)
}

pub fn load(path: &Path) -> Result<Vec<User>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse(&text).with_context(|| format!("{}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> (Ipv4Addr, u8, Ipv4Addr) {
        ("10.90.0.0".parse().unwrap(), 24, "10.90.0.1".parse().unwrap())
    }

    #[test]
    fn parse_and_index() {
        let l = parse("# c\nadmin pw1 10.90.0.2  # me\n\nfriend pw2\n").unwrap();
        assert_eq!(l.len(), 2);
        let (n, p, me) = pool();
        let u = Users::new(l, n, p, me).unwrap();
        assert_eq!(u.check(&auth_header("admin", "pw1")), Some(0));
        assert_eq!(u.check(&auth_header("friend", "pw2")), Some(1));
        assert_eq!(u.check(&auth_header("friend", "pw1")), None);
        assert!(u.is_reserved("10.90.0.2".parse().unwrap()));
        assert!(!u.is_reserved("10.90.0.3".parse().unwrap()));
    }

    #[test]
    fn rejects_bad_lists() {
        let (n, p, me) = pool();
        for t in ["a pw 10.90.0.1", "a pw 10.90.0.255", "a pw 10.90.0.0", "a pw 10.91.0.2",
                  "a pw 10.90.0.2\nb pw 10.90.0.2", "a pw\na pw2", "a:b pw"] {
            let r = parse(t).and_then(|l| Users::new(l, n, p, me));
            assert!(r.is_err(), "{t:?} accepted");
        }
        assert!(parse("a").is_err());
        assert!(parse("a pw x").is_err());
    }
}
