//! Self-signed server certificate and SHA-256 pinning on the client.

use std::sync::Arc;

use anyhow::Result;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// rustls (0.23.x) shuffles the ClientHello extensions with a 16-bit seed it draws from the
/// provider's `secure_random` (`random_u16`, a 2-byte fill). This wrapper records that seed and can
/// pin it: `forced = Some(seed)` makes every ClientHello use the same extension order. All other
/// randomness (client random, keys, nonces) is untouched.
#[derive(Debug)]
pub struct SeedRandom {
    inner: &'static dyn rustls::crypto::SecureRandom,
    forced: Option<u16>,
    pub last: std::sync::atomic::AtomicU32,
}

impl rustls::crypto::SecureRandom for SeedRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        if buf.len() == 2 {
            match self.forced {
                Some(v) => buf.copy_from_slice(&v.to_be_bytes()),
                None => self.inner.fill(buf)?,
            }
            self.last.store(u16::from_be_bytes([buf[0], buf[1]]) as u32, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
        self.inner.fill(buf)
    }
    fn fips(&self) -> bool {
        false
    }
}

/// Client provider with a controllable ClientHello extension-order seed.
pub fn client_provider(ext_seed: Option<u16>) -> (Arc<CryptoProvider>, &'static SeedRandom) {
    let base = rustls::crypto::ring::default_provider();
    let rnd: &'static SeedRandom = Box::leak(Box::new(SeedRandom {
        inner: base.secure_random, forced: ext_seed, last: std::sync::atomic::AtomicU32::new(u32::MAX) }));
    (Arc::new(CryptoProvider { secure_random: rnd, ..base }), rnd)
}

/// Load `cert.der`/`key.der` from `dir`, generating them on first use.
#[cfg(feature = "cli")]
pub fn load_or_create(dir: &std::path::Path, name: &str)
    -> Result<(CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>)> {
    use anyhow::Context;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let (cp, kp) = (dir.join("cert.der"), dir.join("key.der"));
    if !cp.exists() {
        std::fs::create_dir_all(dir)?;
        let ck = rcgen::generate_simple_self_signed(vec![name.to_string()])?;
        std::fs::write(&cp, ck.cert.der())?;
        std::fs::write(&kp, ck.key_pair.serialize_der())?;
    }
    let cert = CertificateDer::from(std::fs::read(&cp).context("cert.der")?);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::fs::read(&kp).context("key.der")?));
    Ok((cert, key))
}

pub fn fingerprint(cert: &[u8]) -> String {
    hex::encode(Sha256::digest(cert))
}

#[derive(Debug)]
pub struct PinVerifier {
    /// `None` = accept any certificate (interop testing only).
    pin: Option<Vec<u8>>,
    provider: Arc<CryptoProvider>,
}

impl PinVerifier {
    pub fn new(pin: &str, provider: Arc<CryptoProvider>) -> Result<Arc<Self>> {
        let pin = if pin == "any" { None } else { Some(hex::decode(pin.replace(':', ""))?) };
        Ok(Arc::new(Self { pin, provider }))
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>,
        _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        match &self.pin {
            None => Ok(ServerCertVerified::assertion()),
            Some(p) if p.as_slice() == Sha256::digest(end_entity.as_ref()).as_slice() => Ok(ServerCertVerified::assertion()),
            Some(_) => Err(rustls::Error::General(format!("certificate pin mismatch: {}", fingerprint(end_entity)))),
        }
    }

    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct)
        -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
