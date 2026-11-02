# browntls

A modern TLS library written in Rust with intended kernel-level integration.

browntls is in initial development. This repository currently contains project
policies and maintenance checks, not a TLS implementation. Protocol architecture,
cryptographic providers, public APIs, supported platforms, and kernel mechanisms
remain to be designed. There are no published releases or production-readiness
claims.

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
