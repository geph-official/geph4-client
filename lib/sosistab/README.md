# Sosistab - an obfuscated datagram transport for horrible networks

Sosistab is an unreliable, obfuscated datagram transport over UDP, and in the future TCP, designed to achieve high performance even in extremely bad networks. Sosistab can be used for applications like anti-censorship VPNs, reliable communication over radios, game networking, etc. It also comes with a QUIC-like multiplex protocol that implements multiple TCP-like reliable streams over the base sosistab layer. This multiplex protocol is ideal for applications requiring reliable signaling traffic.

Features:

- Strong (obfs4-like) obfuscation. Sosistab servers cannot be detected by active probing, and Sosistab traffic is reasonably indistinguishable from random.
- Strong yet lightweight authenticated encryption with ChaCha12 and 64-bit truncated blake3.
- Deniable public-key encryption with triple-x25519. Different clients have different session keys, ensuring DTLS-level security.
- Autotuning Reed-Solomon error correction that targets a certain application packet loss level
- Avoids last-mile congestive collapse but works around lossy links. Shamelessly unfair in permanently congested WANs --- but that's really their problem, not yours. In any case, permanently congested WANs are observationally identical to lossy links, and any solution for the latter will cause unfairness in the former.
