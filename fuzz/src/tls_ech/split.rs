//! Split-mode handshakes of the `tls_ech` target (RFC 9849 §3.1): a
//! client-facing server fed in fuzz-chosen pieces, forwarding to a back-end
//! server or handing over to a local one.

use std::io::{Read, Write};
use std::sync::Arc;

use browntls_core::crypto::native::hpke::ALL_SUPPORTED_SUITES;
use browntls_core::ech::split::{ClientFacing, ClientFacingDecision};
use browntls_core::ech::{
    EchConfig, EchGreaseConfig, EchMode, EchServerConfig, EchServerKey, EchStatus,
};
use browntls_core::{ClientConnection, Error, ServerConfig, ServerConnection};

use super::handshake::{connect, default_key, server_config};
use super::{ECH_VERSION, Fields, KEMS, PUBLIC, SECRET, State, config_list, fixture};
use crate::input::Input;

// -------------------------------------------------------------- split mode

/// The parties of a split-mode connection and their first errors.
struct SplitRun {
    client: ClientConnection,
    front: Option<ClientFacing>,
    backend: Option<ServerConnection>,
    local: Option<ServerConnection>,
    backend_config: Arc<ServerConfig>,
    local_config: Arc<ServerConfig>,
    /// The largest piece the client-facing server reads at once.
    chunk: usize,
    /// Whether the local server reads `into_received` rather than being
    /// made by `into_server_connection`.
    by_hand: bool,
    client_err: Option<Error>,
    front_err: Option<Error>,
    server_err: Option<Error>,
}

fn drain<S: browntls_core::SideData>(conn: &mut browntls_core::ConnectionCommon<S>) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        if conn.write_tls(&mut out).is_err() {
            break;
        }
    }
    out
}

fn feed<S: browntls_core::SideData>(
    conn: &mut browntls_core::ConnectionCommon<S>,
    mut data: &[u8],
) {
    while !data.is_empty() {
        match conn.read_tls(&mut data) {
            Ok(n) if n > 0 => {}
            _ => {
                if conn.process_new_packets().is_err() {
                    break;
                }
            }
        }
    }
}

impl SplitRun {
    /// Feeds `data` to the client-facing server in pieces; a fatal error
    /// must come with a plaintext alert for the client.
    fn front_reads(&mut self, data: &[u8], from_client: bool) {
        let Some(front) = &mut self.front else {
            return;
        };
        for piece in data.chunks(self.chunk) {
            let res = if from_client {
                front.read_client(piece)
            } else {
                front.read_backend(piece)
            };
            if let Err(e) = res {
                if self.front_err.is_none() && from_client {
                    let alert = front.take_for_client();
                    assert!(
                        alert.len() == 7 && alert[..6] == [21, 3, 3, 0, 2, 2],
                        "{alert:?}"
                    );
                    feed(&mut self.client, &alert);
                }
                self.front_err.get_or_insert(e);
                return;
            }
        }
    }

    fn pump(&mut self, mut edit: Option<(usize, u8)>) {
        for _ in 0..32 {
            let mut moved = false;
            let mut out = drain(&mut self.client);
            if let Some((at, x)) = edit.take()
                && !out.is_empty()
            {
                let at = at % out.len();
                out[at] ^= x;
            }
            moved |= !out.is_empty();
            match &mut self.local {
                Some(local) => feed(local, &out),
                None => self.front_reads(&out, true),
            }

            match self.front.as_ref().and_then(ClientFacing::decision) {
                Some(ClientFacingDecision::Local) if self.local.is_none() => {
                    let front = self.front.take().expect("front");
                    let local = if self.by_hand {
                        let received = front.into_received();
                        let mut local =
                            ServerConnection::new(self.local_config.clone()).expect("local");
                        feed(&mut local, &received);
                        local
                    } else {
                        front
                            .into_server_connection(self.local_config.clone())
                            .expect("local")
                    };
                    self.local = Some(local);
                    moved = true;
                }
                Some(ClientFacingDecision::Forward) if self.backend.is_none() => {
                    self.backend =
                        Some(ServerConnection::new(self.backend_config.clone()).expect("backend"));
                    moved = true;
                }
                _ => {}
            }
            if let Some(local) = &mut self.local
                && self.server_err.is_none()
                && let Err(e) = local.process_new_packets()
            {
                self.server_err = Some(e);
            }

            if let (Some(front), Some(backend)) = (&mut self.front, &mut self.backend) {
                let forwarded = front.take_for_backend();
                moved |= !forwarded.is_empty();
                feed(backend, &forwarded);
                if self.server_err.is_none()
                    && let Err(e) = backend.process_new_packets()
                {
                    self.server_err = Some(e);
                }
                let answer = drain(backend);
                moved |= !answer.is_empty();
                self.front_reads(&answer, false);
            }

            let to_client = match (&mut self.front, &mut self.local) {
                (_, Some(local)) => drain(local),
                (Some(front), None) => front.take_for_client(),
                (None, None) => Vec::new(),
            };
            moved |= !to_client.is_empty();
            feed(&mut self.client, &to_client);
            if self.client_err.is_none()
                && let Err(e) = self.client.process_new_packets()
            {
                self.client_err = Some(e);
            }
            if !moved {
                break;
            }
        }
    }

    fn no_errors(&self) -> bool {
        self.client_err.is_none() && self.front_err.is_none() && self.server_err.is_none()
    }
}

/// Split mode (scenarios 4 and 5): variant (accepted, stale, GREASE) and
/// piece size. Scenario 5 sends a random configuration identifier to a
/// client-facing server with trial decryption and the public name check.
#[allow(clippy::too_many_arguments)]
pub(super) fn split(
    input: &mut Input,
    state: &State,
    key: &EchServerKey,
    current: &Arc<EchServerConfig>,
    sound: bool,
    hrr: bool,
    random_ids: bool,
    edit: Option<(usize, u8)>,
) {
    let variant = if random_ids { 0 } else { input.choose(3) };
    let chunk = 1 + usize::from(input.byte());
    let edited = edit.is_some();
    let ech = if random_ids {
        // The fixture's X25519 key pair under another configuration first:
        // trial decryption must move on to the next key.
        let ech = EchServerConfig::new(vec![default_key(9, 0), key.clone()])
            .expect("keys")
            .with_trial_decryption()
            .with_public_name_check();
        assert!(ech.trial_decryption() && ech.public_name_check());
        Arc::new(ech)
    } else {
        current.clone()
    };
    let mode = match variant {
        0 => {
            let Ok(config) = EchConfig::new(current.ech_config_list(), ALL_SUPPORTED_SUITES) else {
                return;
            };
            let config = if random_ids {
                config.with_random_config_id()
            } else {
                config
            };
            assert_eq!(config.random_config_id(), random_ids);
            EchMode::Enable(config)
        }
        1 => {
            let fixture = fixture();
            let stale = Fields {
                version: ECH_VERSION,
                config_id: 1,
                kem: KEMS[0].0,
                public_key: fixture.stale.0.clone(),
                suites: vec![(1, 1)],
                maximum_name_length: 0,
                public_name: PUBLIC.as_bytes().to_vec(),
                extensions: Vec::new(),
            };
            let list = config_list([&stale.encode()[..]]);
            EchMode::Enable(EchConfig::new(&list, ALL_SUPPORTED_SUITES).expect("stale config"))
        }
        _ => match &state.grease {
            Some((g, true)) => EchMode::Grease(g.clone()),
            _ => {
                EchMode::Grease(EchGreaseConfig::generate(ALL_SUPPORTED_SUITES[0]).expect("GREASE"))
            }
        },
    };
    let mut backend = (*server_config(None, hrr)).clone();
    backend.ech_backend = true;
    let local_config = server_config(Some(ech.clone()), hrr);
    let Some((client, _)) = connect(mode, &local_config, sound) else {
        return;
    };
    let mut run = SplitRun {
        client,
        front: Some(ClientFacing::new(ech.clone())),
        backend: None,
        local: None,
        backend_config: Arc::new(backend),
        local_config,
        chunk,
        by_hand: chunk % 2 == 1,
        client_err: None,
        front_err: None,
        server_err: None,
    };
    let _ = format!("{:?}", run.front);
    run.pump(edit);
    if edited || !sound {
        return;
    }
    match variant {
        0 => {
            assert!(
                run.no_errors(),
                "{:?} {:?} {:?}",
                run.client_err,
                run.front_err,
                run.server_err
            );
            let front = run.front.as_mut().expect("forwarding");
            assert_eq!(front.decision(), Some(ClientFacingDecision::Forward));
            assert_eq!(front.ech_status(), EchStatus::Accepted);
            assert_eq!(front.server_name(), Some(SECRET));
            assert!(front.is_relaying());
            assert_eq!(run.client.ech_status(), EchStatus::Accepted);
            let backend = run.backend.as_mut().expect("backend");
            assert_eq!(backend.ech_status(), EchStatus::Accepted);
            assert_eq!(backend.server_name(), Some(SECRET));
            // Application data passes the relay unmodified.
            run.client.writer().write_all(b"hidden").expect("write");
            let out = drain(&mut run.client);
            front.read_client(&out).expect("relay");
            assert_eq!(front.take_for_backend(), out);
            feed(backend, &out);
            backend.process_new_packets().expect("backend reads");
            let mut got = [0u8; 6];
            backend.reader().read_exact(&mut got).expect("data");
            assert_eq!(&got, b"hidden");
        }
        1 => {
            assert!(run.backend.is_none());
            let local = run.local.as_ref().expect("local");
            assert_eq!(local.ech_status(), EchStatus::Rejected);
            let Some(Error::RejectedEch(rejected)) = &run.client_err else {
                panic!("expected a rejection: {:?}", run.client_err);
            };
            assert_eq!(rejected.retry_configs(), Some(ech.ech_config_list()));
        }
        _ => {
            assert!(
                run.no_errors(),
                "{:?} {:?} {:?}",
                run.client_err,
                run.front_err,
                run.server_err
            );
            assert!(run.backend.is_none());
            assert_eq!(run.client.ech_status(), EchStatus::Grease);
            assert_eq!(
                run.local.as_ref().expect("local").ech_status(),
                EchStatus::Rejected
            );
        }
    }
}
