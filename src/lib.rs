//! maski — L3 VPN over standard MASQUE CONNECT-IP (RFC 9484), HTTP/3 datagrams (RFC 9297) on
//! QUIC (quinn).
//!
//! Library surface for an app: [`client::start`] connects and returns a [`client::Handle`]
//! (send packets, `network_changed`, stats, stop); packets from the server go to a
//! [`client::PacketOut`] (a TUN device or a callback). [`ffi`] wraps that in a C API with its own
//! runtime thread for an Apple Network Extension.

pub mod client;
pub mod net;
pub mod proto;
pub mod tls;
pub mod tunio;

#[cfg(feature = "cli")]
pub mod probe;
#[cfg(feature = "cli")]
pub mod server;
#[cfg(feature = "cli")]
pub mod users;

#[cfg(feature = "ffi")]
pub mod ffi;
