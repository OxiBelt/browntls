//! Test fixture of the Kubernetes revocation smoke test
//! (`tests/kubernetes/README.md`): a Tokio TLS server that staples and
//! refreshes its certificate status response, and a Tokio TLS client that
//! checks revocation through a live OCSP lookup or through the staple.
//!
//! This is not an example of application code: the peers speak a
//! line-based test protocol and the client asserts the outcome the
//! scenario named on its command line must have.
//!
//! ```text
//! cargo run -p browntls-tokio --features ocsp --example revocation_kubernetes -- help
//! ```

#[cfg(all(feature = "ocsp", feature = "native"))]
mod client;
#[cfg(all(feature = "ocsp", feature = "native"))]
mod http;
#[cfg(all(feature = "ocsp", feature = "native"))]
mod server;
#[cfg(all(feature = "ocsp", feature = "native"))]
mod support;

#[cfg(all(feature = "ocsp", feature = "native"))]
fn main() -> std::process::ExitCode {
    support::run()
}

#[cfg(not(all(feature = "ocsp", feature = "native")))]
fn main() -> std::process::ExitCode {
    eprintln!("revocation_kubernetes needs the `ocsp` and `native` features of browntls-tokio");
    std::process::ExitCode::from(2)
}
