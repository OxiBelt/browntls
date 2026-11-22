//! Public Tokio early-data controls over bounded, in-process transports.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use browntls_core::crypto::hash::HashAlgorithm;
use browntls_core::psk::ExternalPsk;
use browntls_core::{CipherSuite, ClientConfig, RootCertStore, ServerConfig, version};
use browntls_tokio::{
    EarlyDataOutcome, RejectedEarlyDataPolicy, TlsAcceptor, TlsConnector, unbuffered,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use crate::tls_conn::setup::server_name;

#[test]
fn early_data_reporting_for_both_tokio_adapters() {
    crate::init();
    let psk = Arc::new(
        ExternalPsk::new(b"seed".to_vec(), vec![0x87; 32], HashAlgorithm::SHA256)
            .expect("PSK")
            .with_cipher_suite(CipherSuite::TLS13_AES_128_GCM_SHA256)
            .with_early_data(1024),
    );
    let mut client = ClientConfig::builder_with_protocol_versions(&[&version::TLS13])
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    client.enable_early_data = true;
    client.require_external_psk = true;
    client.external_psks.push(psk.clone());
    let mut server = ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
        .with_no_client_auth()
        .with_external_psks_only(Arc::new(vec![psk]));
    server.send_tls13_tickets = 0;
    let client = Arc::new(client);
    let server = Arc::new(server);
    let policy = RejectedEarlyDataPolicy::ResendIfSameAlpn {
        max_bytes: NonZeroUsize::new(32).expect("nonzero"),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            macro_rules! sockets {
                () => {{
                    let (local, remote) = duplex(512);
                    let server = server.clone();
                    let peer = tokio::spawn(async move {
                        let mut stream = TlsAcceptor::from(server)
                            .accept(remote)
                            .await
                            .expect("accept");
                        assert!(stream.get_mut().1.early_data().is_none());
                        assert_eq!(stream.read_u8().await.expect("ordinary data"), b'x');
                    });
                    (local, peer)
                }};
            }
            macro_rules! exercise {
                ($connector:expr) => {{
                    let connector = $connector
                        .early_data(true)
                        .rejected_early_data_policy(policy);
                    let (local, peer) = sockets!();
                    let mut stream = connector
                        .connect(server_name(), local)
                        .await
                        .expect("client");
                    stream.write_all(b"early").await.expect("early write");
                    assert_eq!(stream.early_data_outcome(), EarlyDataOutcome::Pending);
                    let rejected = EarlyDataOutcome::Rejected {
                        early_bytes: 5,
                        resent_bytes: 0,
                        unresent_bytes: 5,
                    };
                    assert_eq!(stream.finish_early_data().await.expect("finish"), rejected);
                    assert_eq!(stream.acknowledge_rejected_early_data(), Some(5));
                    stream.write_all(b"x").await.expect("ordinary write");
                    stream.flush().await.expect("flush");
                    peer.await.expect("peer");

                    let (local, peer) = sockets!();
                    let mut stream = connector
                        .connect(server_name(), local)
                        .await
                        .expect("client");
                    stream.write_all(b"early").await.expect("early write");
                    let (mut read, mut write) = stream.into_split();
                    assert_eq!(write.finish_early_data().await.expect("finish"), rejected);
                    assert_eq!(read.early_data_outcome().await.expect("outcome"), rejected);
                    assert_eq!(write.early_data_outcome().await.expect("outcome"), rejected);
                    assert_eq!(
                        write
                            .acknowledge_rejected_early_data()
                            .await
                            .expect("acknowledge"),
                        Some(5),
                    );
                    write.write_all(b"x").await.expect("ordinary write");
                    write.flush().await.expect("flush");
                    peer.await.expect("peer");
                }};
            }
            exercise!(TlsConnector::from(client.clone()));
            exercise!(unbuffered::TlsConnector::from(client));
        })
        .await
        .expect("early-data checks made progress");
    });
}
