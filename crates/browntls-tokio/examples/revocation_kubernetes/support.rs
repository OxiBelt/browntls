//! Command line, credentials and the pieces both peers share.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use browntls::RootCertStore;
use browntls::crypto::CryptoProvider;
use browntls::pki_types::pem::PemObject;
use browntls::pki_types::{Cert, CertificateDer};
use browntls::revocation::{RevocationDigests, RevocationQuery};
use browntls_tokio::browntls;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Errors of the fixture: a message for the pod's log.
pub(crate) type Failure = Box<dyn std::error::Error + Send + Sync>;

/// Longest line of the test protocol.
const MAX_LINE: usize = 512;

/// Bound on each network step of the test protocol.
pub(crate) const STEP_TIMEOUT: Duration = Duration::from_secs(10);

const USAGE: &str = "\
usage: revocation_kubernetes server --cert CHAIN.pem --key KEY.pem --ca CA.pem
           --responder URL --plain-listen ADDR --staple-listen ADDR
       revocation_kubernetes client --scenario live|denied|staple --ca CA.pem
           --responder URL --name SERVER_NAME --plain HOST:PORT --staple HOST:PORT";

pub(crate) fn run() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let options = match Options::parse(args) {
        Ok(options) => options,
        Err(err) => {
            eprintln!("{err}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("cannot start the runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    let outcome = match command.as_str() {
        "server" => runtime.block_on(crate::server::run(&options)),
        "client" => runtime.block_on(crate::client::run(&options)),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            println!("RESULT failed: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The `--name value` pairs of the command line.
pub(crate) struct Options(HashMap<String, String>);

impl Options {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, Failure> {
        let mut options = HashMap::new();
        while let Some(name) = args.next() {
            let key = name
                .strip_prefix("--")
                .ok_or_else(|| format!("unexpected argument {name}"))?;
            let value = args.next().ok_or_else(|| format!("{name} needs a value"))?;
            options.insert(key.to_owned(), value);
        }
        Ok(Self(options))
    }

    pub(crate) fn get(&self, name: &str) -> Result<&str, Failure> {
        self.0
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("missing --{name}").into())
    }
}

pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(browntls::crypto::native::default_provider())
}

/// The certificates of a PEM file.
pub(crate) fn certificates(path: &str) -> Result<Vec<CertificateDer<'static>>, Failure> {
    let pem = std::fs::read(path).map_err(|err| format!("cannot read {path}: {err}"))?;
    let certificates = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("{path}: {err:?}"))?;
    if certificates.is_empty() {
        return Err(format!("{path} holds no certificate").into());
    }
    Ok(certificates)
}

/// The fixture's certification authority: the only trust anchor of both
/// peers and the only issuer whose responder they may ask.
pub(crate) struct Authority {
    pub(crate) roots: Arc<RootCertStore>,
    /// SHA-256 of the authority's `SubjectPublicKeyInfo`.
    key_hash: [u8; 32],
    /// The one responder URL the test authorizes for this issuer.
    responder: String,
}

impl Authority {
    pub(crate) fn load(options: &Options) -> Result<Self, Failure> {
        let path = options.get("ca")?;
        let mut roots = RootCertStore::empty();
        let mut key_hash = None;
        for certificate in certificates(path)? {
            let parsed = Cert::try_from(&certificate).map_err(|err| format!("{path}: {err}"))?;
            let spki = parsed.subject_public_key_info();
            key_hash = Some((RevocationDigests::native().sha256)(&spki));
            roots
                .add(certificate.clone())
                .map_err(|err| format!("{path}: {err}"))?;
        }
        Ok(Self {
            roots: Arc::new(roots),
            key_hash: key_hash.ok_or("no trust anchor")?,
            responder: options.get("responder")?.to_owned(),
        })
    }

    /// The responder to ask for `query`: the configured one, and only for
    /// a certificate this authority issued that names exactly that URL.
    /// The URLs of a query come from a certificate and are not followed.
    pub(crate) fn authorized_responder(&self, query: &RevocationQuery) -> io::Result<String> {
        let authorized = *query.issuer_key_hash() == self.key_hash
            && query.responder_urls().contains(&self.responder);
        if authorized {
            Ok(self.responder.clone())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "no authorized responder for this certificate",
            ))
        }
    }

    pub(crate) fn responder(&self) -> &str {
        &self.responder
    }
}

/// Lower-case hexadecimal SHA-256 of `bytes`, to name a stapled response
/// in logs and in the test protocol.
pub(crate) fn fingerprint(bytes: &[u8]) -> String {
    let digest = (RevocationDigests::native().sha256)(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Reads one line of the test protocol, without its line feed.
pub(crate) async fn read_line(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<String> {
    let mut line = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == b'\n' {
            break;
        }
        if line.len() == MAX_LINE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        line.push(byte);
    }
    String::from_utf8(line).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

/// Writes one line of the test protocol.
pub(crate) async fn write_line(
    stream: &mut (impl AsyncWrite + Unpin),
    line: &str,
) -> io::Result<()> {
    stream.write_all(line.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await
}

/// Runs `step` under [`STEP_TIMEOUT`].
pub(crate) async fn bounded<T>(
    what: &str,
    step: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match tokio::time::timeout(STEP_TIMEOUT, step).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{what} timed out"),
        )),
    }
}
