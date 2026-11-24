# browntls

A modern TLS library written in Rust with intended kernel-level integration.

browntls is in initial development. The workspace contains:

- `crates/browntls-crypto`: cryptographic primitives with portable,
  SIMD and hardware-accelerated backends for x86-64 (x86-64-v3 baseline),
  aarch64 (NEON and the Cryptographic Extension) and riscv64 (RVV 1.0 and the
  vector cryptography extensions).
- `crates/browntls-pki`: PKI types, PEM decoding and X.509 path validation.
- `crates/browntls`: the crate applications depend on. It re-exports
  `browntls-core` and, with the `tokio` and `ktls` features, `browntls-tokio`
  (`browntls::tokio`) and `browntls-ktls` (`browntls::ktls`)
  ([README](crates/browntls/README.md)).
- `crates/browntls-core`: the TLS 1.2 / TLS 1.3 protocol, DTLS 1.3 and an
  explicit [DTLS 1.2 certificate handshake layer](docs/DTLS12.md) through a
  low-level datagram API and a blocking UDP API (`UdpClient`, `UdpServer`),
  the crypto provider mount point, and the built-in providers.
- `crates/browntls-tokio`: asynchronous TLS streams for Tokio
  ([README](crates/browntls-tokio/README.md)).
- `crates/browntls-ktls`: Linux kernel TLS offload of browntls connections
  ([README](crates/browntls-ktls/README.md)).
- `crates/browntls-e2e` and `crates/browntls-entropy`: unpublished test tools
  (the [Docker end-to-end](tests/e2e/README.md) peer and the
  [entropy checks](crates/browntls-entropy/README.md)).

See [Architecture](docs/Architecture.md) for the design and
[Roadmap](docs/Roadmap.md) for implementation status and gaps. The code has not
been independently reviewed or audited. There are no published releases or
production-readiness claims. Kernel integration starts with Linux kernel TLS
offload; other kernel mechanisms remain to be designed.

Rust 1.100.0 is required (pinned in `rust-toolchain.toml`).

## Contributing

- [Contributor workflow and checks](CONTRIBUTING.md)
- [Agent guidance](AGENTS.md)
- [Maintenance and release prerequisites](docs/Maintenance.md)
- [Security policy and private reporting](SECURITY.md)

The contributor workflow takes inspiration from
[OxiBelt](https://github.com/OxiBelt/OxiBelt), adapted to this library's current
stage. Proxy, WAF, browser, and container-release machinery are not part of
this initialization; Kubernetes is used only for the
[revocation test](tests/kubernetes/README.md).

## License

[Apache-2.0](LICENSE).
