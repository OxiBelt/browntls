# browntls

A modern TLS library written in Rust with intended kernel-level integration.

browntls is in initial development. The workspace contains:

- `crates/browntls-crypto`: cryptographic primitives with portable,
  SIMD and hardware-accelerated backends for x86-64 (x86-64-v3 baseline),
  aarch64 (NEON and the Cryptographic Extension) and riscv64 (RVV 1.0 and the
  vector cryptography extensions).
- `crates/browntls-pki`: PKI types, PEM decoding and X.509 path validation.
- `crates/browntls`: the TLS 1.2 / TLS 1.3 protocol, the crypto provider
  mount point, and the built-in providers.

See [Architecture](docs/Architecture.md) for the design and
[Roadmap](docs/Roadmap.md) for implementation status and gaps. The code has not
been independently reviewed or audited. There are no published releases or
production-readiness claims; kernel integration remains to be designed.

Rust 1.99.1 is required (pinned in `rust-toolchain.toml`).

## Contributing

- [Contributor workflow and checks](CONTRIBUTING.md)
- [Agent guidance](AGENTS.md)
- [Maintenance and release prerequisites](docs/Maintenance.md)
- [Security policy and private reporting](SECURITY.md)

The contributor workflow takes inspiration from
[OxiBelt](https://github.com/OxiBelt/OxiBelt), adapted to this library's current
stage. Proxy, WAF, browser, container-release, and Kubernetes machinery are not
part of this initialization.

## License

[Apache-2.0](LICENSE).
