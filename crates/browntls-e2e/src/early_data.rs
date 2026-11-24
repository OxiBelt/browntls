//! A bounded PSK-only test peer for the Phase 1 TCP Service scenarios.

use std::io::Read as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use browntls::crypto::hash::HashAlgorithm;
use browntls::crypto::native;
use browntls::pki_types::{ServerName, UnixTime};
use browntls::psk::{
    ExternalPsk, ExternalPskReplayDecision, ExternalPskReplayKey, ExternalPskReplayPolicy,
};
use browntls::tokio::{self as tls, EarlyDataOutcome};
use browntls::{CipherSuite, ClientConfig, RootCertStore, ServerConfig, version};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::Result;
use crate::async_io::bounded;
use crate::output::{Value, emit};

const IDENTITY: &[u8] = b"browntls-phase1-test";
const ALPN: &[u8] = b"browntls-test";
const EARLY: &[u8] = b"early request";
const ORDINARY: &[u8] = b"ordinary request";
const REPLY: &[u8] = b"ordinary reply";

#[derive(Debug, Default)]
struct SingleMark(Mutex<Option<Vec<u8>>>);

impl ExternalPskReplayPolicy for SingleMark {
    fn check_and_mark(
        &self,
        key: &ExternalPskReplayKey,
        expires_at: UnixTime,
    ) -> ExternalPskReplayDecision {
        use ExternalPskReplayDecision::*;
        let Ok(mut mark) = self.0.lock() else {
            return Unavailable;
        };
        if UnixTime::now() >= expires_at {
            return Unavailable;
        }
        match &*mark {
            Some(prior) if prior == key.as_ref() => Duplicate,
            Some(_) => Unavailable,
            None => {
                *mark = Some(key.as_ref().to_vec());
                FirstUse
            }
        }
    }
}

#[derive(Debug)]
struct UnavailablePolicy;

impl ExternalPskReplayPolicy for UnavailablePolicy {
    fn check_and_mark(
        &self,
        _key: &ExternalPskReplayKey,
        _expires_at: UnixTime,
    ) -> ExternalPskReplayDecision {
        ExternalPskReplayDecision::Unavailable
    }
}

pub(super) fn run(command: &str, args: &[String]) -> Result<()> {
    let [address, key_file, style, decision] = args else {
        return Err(format!(
            "usage: {command} ADDR KEY_FILE buffered|unbuffered accept|decline"
        ));
    };
    let buffered = match style.as_str() {
        "buffered" => true,
        "unbuffered" => false,
        _ => return Err("expected buffered or unbuffered".into()),
    };
    let accepted = match decision.as_str() {
        "accept" => true,
        "decline" => false,
        _ => return Err("expected accept or decline".into()),
    };
    let key = std::fs::read(key_file).map_err(|error| error.to_string())?;
    let psk = ExternalPsk::new(IDENTITY.to_vec(), key, HashAlgorithm::SHA256)
        .map_err(|error| error.to_string())?
        .with_cipher_suite(CipherSuite::TLS13_AES_128_GCM_SHA256)
        .with_alpn_protocol(ALPN.to_vec())
        .with_early_data(2048);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| error.to_string())?;
    if command == "early-data-server" {
        runtime.block_on(server(address, psk, buffered, accepted))
    } else {
        runtime.block_on(client(address, psk, buffered, accepted))
    }
}

async fn server(address: &str, psk: ExternalPsk, buffered: bool, accepted: bool) -> Result<()> {
    let cutoff = UnixTime::since_unix_epoch(Duration::from_secs(UnixTime::now().as_secs() + 300));
    let mut config = ServerConfig::builder_with_provider(Arc::new(native::default_provider()))
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|error| error.to_string())?
        .with_no_client_auth()
        .with_external_psks_only(Arc::new(vec![Arc::new(psk.with_early_data_expiry(cutoff))]));
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.send_tls13_tickets = 0;
    config.external_psk_replay_policy = Some(if accepted {
        Arc::new(SingleMark::default())
    } else {
        Arc::new(UnavailablePolicy)
    });
    let config = Arc::new(config);
    let listener = bounded("listen", TcpListener::bind(address)).await?;
    emit(&[("event", "listening".into())]);
    let (socket, _) = bounded("accept", listener.accept()).await?;
    if buffered {
        let mut stream =
            bounded("handshake", tls::TlsAcceptor::from(config).accept(socket)).await?;
        verify_identity(stream.get_ref().1)?;
        let mut early = Vec::new();
        if let Some(mut reader) = stream.get_mut().1.early_data() {
            reader
                .read_to_end(&mut early)
                .map_err(|error| error.to_string())?;
        }
        verify_early(&early, accepted)?;
        ordinary_server(&mut stream).await?;
    } else {
        let mut stream = bounded(
            "handshake",
            tls::unbuffered::TlsAcceptor::from(config).accept(socket),
        )
        .await?;
        verify_identity(stream.get_ref().1)?;
        verify_early(stream.early_data(), accepted)?;
        ordinary_server(&mut stream).await?;
    }
    report("server", buffered, accepted)
}

async fn client(address: &str, psk: ExternalPsk, buffered: bool, accepted: bool) -> Result<()> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(native::default_provider()))
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|error| error.to_string())?
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.enable_early_data = true;
    config.require_external_psk = true;
    config.external_psks.push(Arc::new(psk));
    let config = Arc::new(config);
    let socket = bounded("connect TCP", TcpStream::connect(address)).await?;
    let name = ServerName::try_from("browntls-phase1.test").map_err(|error| error.to_string())?;
    if buffered {
        let connector = tls::TlsConnector::from(config).early_data(true);
        let mut stream = bounded("connect TLS", connector.connect(name, socket)).await?;
        bounded("early write", stream.write_all(EARLY)).await?;
        let outcome = bounded("settle early data", stream.finish_early_data()).await?;
        verify_outcome(outcome, accepted)?;
        verify_identity(stream.get_ref().1)?;
        verify_ack(stream.acknowledge_rejected_early_data(), accepted)?;
        ordinary_client(&mut stream).await?;
    } else {
        let connector = tls::unbuffered::TlsConnector::from(config).early_data(true);
        let mut stream = bounded("connect TLS", connector.connect(name, socket)).await?;
        bounded("early write", stream.write_all(EARLY)).await?;
        let outcome = bounded("settle early data", stream.finish_early_data()).await?;
        verify_outcome(outcome, accepted)?;
        verify_identity(stream.get_ref().1)?;
        verify_ack(stream.acknowledge_rejected_early_data(), accepted)?;
        ordinary_client(&mut stream).await?;
    }
    report("client", buffered, accepted)
}

fn verify_identity(state: &browntls::CommonState) -> Result<()> {
    if state.is_handshaking()
        || state.external_psk_identity() != Some(IDENTITY)
        || state.alpn_protocol() != Some(ALPN)
    {
        return Err("expected a completed external PSK handshake and the selected ALPN".into());
    }
    Ok(())
}

fn verify_early(early: &[u8], accepted: bool) -> Result<()> {
    let expected = if accepted { EARLY } else { &[] };
    if early == expected {
        Ok(())
    } else {
        Err("server received unexpected early data".into())
    }
}

fn verify_outcome(outcome: EarlyDataOutcome, accepted: bool) -> Result<()> {
    let expected = if accepted {
        EarlyDataOutcome::Accepted {
            early_bytes: EARLY.len(),
        }
    } else {
        EarlyDataOutcome::Rejected {
            early_bytes: EARLY.len(),
            resent_bytes: 0,
            unresent_bytes: EARLY.len(),
        }
    };
    if outcome == expected {
        Ok(())
    } else {
        Err(format!("unexpected client early-data outcome: {outcome:?}"))
    }
}

fn verify_ack(acknowledged: Option<usize>, accepted: bool) -> Result<()> {
    if acknowledged == (!accepted).then_some(EARLY.len()) {
        Ok(())
    } else {
        Err("unexpected client acknowledgement count".into())
    }
}

async fn ordinary_server(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Result<()> {
    let mut request = [0; ORDINARY.len()];
    bounded("ordinary read", stream.read_exact(&mut request)).await?;
    if request != ORDINARY {
        return Err("server received a different ordinary request".into());
    }
    bounded("reply", stream.write_all(REPLY)).await?;
    bounded("flush reply", stream.flush()).await?;
    bounded("shutdown", stream.shutdown()).await
}

async fn ordinary_client(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Result<()> {
    bounded("ordinary write", stream.write_all(ORDINARY)).await?;
    bounded("flush request", stream.flush()).await?;
    let mut reply = [0; REPLY.len()];
    bounded("read reply", stream.read_exact(&mut reply)).await?;
    if reply != REPLY {
        return Err("client received a different ordinary reply".into());
    }
    bounded("shutdown", stream.shutdown()).await
}

fn report(role: &str, buffered: bool, accepted: bool) -> Result<()> {
    emit(&[
        ("event", "early-data".into()),
        ("role", role.into()),
        (
            "style",
            if buffered { "buffered" } else { "unbuffered" }.into(),
        ),
        ("accepted", Value::Bool(accepted)),
        (
            "early_bytes",
            Value::Num(if role == "client" || accepted {
                EARLY.len()
            } else {
                0
            }),
        ),
        (
            "unresent_bytes",
            Value::Num(if role == "client" && !accepted {
                EARLY.len()
            } else {
                0
            }),
        ),
        ("ordinary_exchange", Value::Bool(true)),
    ]);
    Ok(())
}
