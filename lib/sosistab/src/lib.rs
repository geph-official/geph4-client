//! # What is Sosistab?
//!
//! Sosistab is an unreliable, obfuscated datagram transport over UDP and TCP, designed to achieve high performance even in extremely bad networks. It is originally designed for [Geph](https://geph.io), a resliient anti-censorship VPN, but it can be used for reliable communication over radios, game networking, etc. It also comes with a QUIC-like multiplex protocol that implements multiple TCP-like reliable streams over the base sosistab layer. This multiplex protocol is ideal for applications requiring a mix of reliable and unreliable traffic. For example, VPNs might do signaling and authentication over reliable streams, while passing packets through unreliable datagrams.
//!
//! **NOTE**: Sosistab is still in *heavy* development. Expect significant breaking API changes before version 1.0 is released.
//!
//! # Features
//!
//! - State-of-the-art reliable streaming protocol with selective ACKs and BIC-based congestion control. Notably, it has better fairness *and* performance in modern networks than protocols like KCP that ape 1980s TCP specifications.
//! - Strong, state-of-the-art (obfs4-like) obfuscation. Sosistab servers cannot be detected by active probing, and Sosistab traffic is reasonably indistinguishable from random. We also make a best-effort attempt at hiding side-channels through random padding.
//! - Strong yet lightweight authenticated encryption with chacha20-poly1305
//! - Deniable public-key encryption with triple-x25519, with servers having long-term public keys that must be provided out-of-band. Similar to decent encrypted transports like TLS and DTLS --- but not to the whole Shadowsocks/Vmess family of protocols --- different clients have different session keys and cannot spy on each other.
//! - Reed-Solomon error correction that targets a certain application packet loss level. Intelligent autotuning and dynamic batch sizes make performance much better than other FEC-based tools like udpspeeder. This lets Sosistab turns high-bandwidth, high-loss links to medium-bandwidth, low-loss links, which is generally much more useful.
//! - Avoids last-mile congestive collapse but works around lossy links. Shamelessly unfair in permanently congested WANs --- but that's really their problem, not yours. In any case, permanently congested WANs are observationally identical to lossy links, and any solution for the latter will cause unfairness in the former.
//!
//! # Use of async
//!
//! Sosistab uses the "futures" traits and the [smolscale] executor. In practice, this means that Sosistab is compatible with any executor, but unless your program uses [smolscale], Sosistab will run on a separate thread pool from the rest of your program. This comes with less overhead than you imagine, and generally it's fine to use Sosistab with e.g. async-std or Tokio.
//!
//! In the future, we will consider adding hyper-like traits to enable integration of Sosistab with other executors.

mod client;
mod crypt;
mod fec;
mod listener;
pub use client::*;
pub use listener::*;
use std::time::Duration;
mod protocol;
pub mod runtime;
mod session;
pub use session::*;
mod backhaul;
mod mux;
pub use mux::*;
mod tcp;
use backhaul::*;
mod batchan;
mod recfilter;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
