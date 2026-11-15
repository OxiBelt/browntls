//! The TLS 1.3 key schedule (RFC 8446 §7.1).
//!
//! The schedule progresses through typed stages so that each secret is only
//! derivable at the point in the handshake where it is defined:
//!
//! ```text
//! KeyScheduleEarly ─┐
//!                   ├─> KeySchedulePreHandshake ─> KeyScheduleHandshake
//! (no PSK) ─────────┘       ─> KeyScheduleTrafficWithClientFinishedPending
//!                            ─> KeyScheduleTraffic ─> KeyScheduleResumption
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::common_state::{CommonState, Side};
use crate::crypto::cipher::{AeadKey, Iv, MessageDecrypter};
use crate::crypto::tls13::{HkdfExpander, OkmBlock};
use crate::crypto::{SharedSecret, hmac};
use crate::error::Error;
use crate::key_log::KeyLog;
use crate::suites::PartiallyExtractedSecrets;
use crate::tls13::Tls13CipherSuite;

/// The labels of RFC 8446 §7.1 and §7.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretKind {
    ResumptionPskBinderKey,
    ClientEarlyTrafficSecret,
    EarlyExporterMasterSecret,
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientApplicationTrafficSecret,
    ServerApplicationTrafficSecret,
    ExporterMasterSecret,
    ResumptionMasterSecret,
    DerivedSecret,
}

impl SecretKind {
    fn to_bytes(self) -> &'static [u8] {
        match self {
            Self::ResumptionPskBinderKey => b"res binder",
            Self::ClientEarlyTrafficSecret => b"c e traffic",
            Self::EarlyExporterMasterSecret => b"e exp master",
            Self::ClientHandshakeTrafficSecret => b"c hs traffic",
            Self::ServerHandshakeTrafficSecret => b"s hs traffic",
            Self::ClientApplicationTrafficSecret => b"c ap traffic",
            Self::ServerApplicationTrafficSecret => b"s ap traffic",
            Self::ExporterMasterSecret => b"exp master",
            Self::ResumptionMasterSecret => b"res master",
            Self::DerivedSecret => b"derived",
        }
    }

    fn log_label(self) -> Option<&'static str> {
        Some(match self {
            Self::ClientEarlyTrafficSecret => "CLIENT_EARLY_TRAFFIC_SECRET",
            Self::EarlyExporterMasterSecret => "EARLY_EXPORTER_SECRET",
            Self::ClientHandshakeTrafficSecret => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            Self::ServerHandshakeTrafficSecret => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            Self::ClientApplicationTrafficSecret => "CLIENT_TRAFFIC_SECRET_0",
            Self::ServerApplicationTrafficSecret => "SERVER_TRAFFIC_SECRET_0",
            Self::ExporterMasterSecret => "EXPORTER_SECRET",
            _ => return None,
        })
    }
}

/// The running `HKDF-Extract` chain plus the suite it belongs to.
struct KeySchedule {
    current: Box<dyn HkdfExpander>,
    suite: &'static Tls13CipherSuite,
}

impl KeySchedule {
    fn new(suite: &'static Tls13CipherSuite, secret: &[u8]) -> Self {
        Self {
            current: suite.hkdf_provider.extract_from_secret(None, secret),
            suite,
        }
    }

    fn new_with_empty_secret(suite: &'static Tls13CipherSuite) -> Self {
        Self {
            current: suite.hkdf_provider.extract_from_zero_ikm(None),
            suite,
        }
    }

    fn hash_len(&self) -> usize {
        self.current.hash_len()
    }

    /// `Derive-Secret(current, kind, hs_hash)`.
    fn derive(&self, kind: SecretKind, hs_hash: &[u8]) -> OkmBlock {
        hkdf_expand_label_block(&*self.current, kind.to_bytes(), hs_hash)
    }

    /// `Derive-Secret(current, "derived", Transcript-Hash(""))`.
    fn derive_for_empty_hash(&self) -> OkmBlock {
        let empty_hash = self.suite.common.hash_provider.hash(&[]);
        self.derive(SecretKind::DerivedSecret, empty_hash.as_ref())
    }

    fn derive_logged_secret(
        &self,
        kind: SecretKind,
        hs_hash: &[u8],
        key_log: &dyn KeyLog,
        client_random: &[u8; 32],
    ) -> OkmBlock {
        let output = self.derive(kind, hs_hash);
        if let Some(label) = kind.log_label()
            && key_log.will_log(label)
        {
            key_log.log(label, client_random, output.as_ref());
        }
        output
    }

    /// Feeds the next input secret (`HKDF-Extract(Derive-Secret(current, "derived", ""), secret)`).
    fn input_secret(&mut self, secret: &[u8]) {
        let salt = self.derive_for_empty_hash();
        self.current = self
            .suite
            .hkdf_provider
            .extract_from_secret(Some(salt.as_ref()), secret);
    }

    fn input_empty(&mut self) {
        let salt = self.derive_for_empty_hash();
        self.current = self
            .suite
            .hkdf_provider
            .extract_from_zero_ikm(Some(salt.as_ref()));
    }

    fn input_shared_secret(&mut self, secret: &SharedSecret) {
        self.input_secret(secret.secret_bytes());
    }

    /// `HMAC(HKDF-Expand-Label(base_key, "finished", "", Hash.length), hs_hash)`.
    fn sign_finish(&self, base_key: &OkmBlock, hs_hash: &[u8]) -> hmac::Tag {
        let expander = self.suite.hkdf_provider.expander_for_okm(base_key);
        let finished_key = hkdf_expand_label_block(&*expander, b"finished", &[]);
        self.suite.hkdf_provider.hmac_sign(&finished_key, hs_hash)
    }

    fn set_encrypter(&self, secret: &OkmBlock, common: &mut CommonState) {
        let expander = self.suite.hkdf_provider.expander_for_okm(secret);
        let (key, iv) = derive_traffic_key_iv(&*expander, self.suite.aead_alg.key_len());
        common.record_layer.set_message_encrypter(
            self.suite.aead_alg.encrypter(key, iv),
            self.suite.common.confidentiality_limit,
        );
    }

    fn set_decrypter(&self, secret: &OkmBlock, common: &mut CommonState) {
        common
            .record_layer
            .set_message_decrypter(self.derive_decrypter(secret));
    }

    fn derive_decrypter(&self, secret: &OkmBlock) -> Box<dyn MessageDecrypter> {
        let expander = self.suite.hkdf_provider.expander_for_okm(secret);
        let (key, iv) = derive_traffic_key_iv(&*expander, self.suite.aead_alg.key_len());
        self.suite.aead_alg.decrypter(key, iv)
    }

    /// `HKDF-Expand-Label(secret, "traffic upd", "", Hash.length)` (RFC 8446 §7.2).
    fn next_traffic_secret(&self, secret: &OkmBlock) -> OkmBlock {
        let expander = self.suite.hkdf_provider.expander_for_okm(secret);
        hkdf_expand_label_block(&*expander, b"traffic upd", &[])
    }
}

/// `HKDF-Expand-Label(secret, label, context, L)` into `output`.
///
/// The `HkdfLabel` structure is `u16 length; opaque label<7..255> = "tls13 " + label;
/// opaque context<0..255>`.
pub(crate) fn hkdf_expand_label(
    expander: &dyn HkdfExpander,
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
) {
    const LABEL_PREFIX: &[u8] = b"tls13 ";
    // Output lengths are bounded by callers; labels and contexts are at most 255 bytes.
    let output_len = (output.len() as u16).to_be_bytes();
    let label_len = [(LABEL_PREFIX.len() + label.len()) as u8];
    let context_len = [context.len() as u8];
    let info: [&[u8]; 6] = [
        &output_len,
        &label_len,
        LABEL_PREFIX,
        label,
        &context_len,
        context,
    ];
    // The only way this fails is an over-long output, which no caller requests.
    let _ = expander.expand_slice(&info, output);
}

/// `HKDF-Expand-Label` producing one hash-length block.
pub(crate) fn hkdf_expand_label_block(
    expander: &dyn HkdfExpander,
    label: &[u8],
    context: &[u8],
) -> OkmBlock {
    const LABEL_PREFIX: &[u8] = b"tls13 ";
    let output_len = (expander.hash_len() as u16).to_be_bytes();
    let label_len = [(LABEL_PREFIX.len() + label.len()) as u8];
    let context_len = [context.len() as u8];
    let info: [&[u8]; 6] = [
        &output_len,
        &label_len,
        LABEL_PREFIX,
        label,
        &context_len,
        context,
    ];
    expander.expand_block(&info)
}

/// Derives the traffic key and IV from a traffic secret's expander.
pub(crate) fn derive_traffic_key_iv(
    expander: &dyn HkdfExpander,
    aead_key_len: usize,
) -> (AeadKey, Iv) {
    let mut key = [0u8; AeadKey::MAX_LEN];
    hkdf_expand_label(expander, b"key", &[], &mut key[..aead_key_len]);
    let aead_key = AeadKey::new(&key[..aead_key_len]);
    crate::crypto::zeroize_slice(&mut key);
    let mut iv = [0u8; 12];
    hkdf_expand_label(expander, b"iv", &[], &mut iv);
    (aead_key, Iv::new(iv))
}

/// The schedule before any secret is mixed in but with a PSK available (or
/// `new_with_empty_secret` for no PSK).
pub(crate) struct KeyScheduleEarly {
    ks: KeySchedule,
}

impl KeyScheduleEarly {
    pub(crate) fn new(suite: &'static Tls13CipherSuite, secret: &[u8]) -> Self {
        Self {
            ks: KeySchedule::new(suite, secret),
        }
    }

    /// Derives and installs the `client_early_traffic_secret` for 0-RTT.
    pub(crate) fn client_early_traffic_secret(
        &self,
        hs_hash: &[u8],
        key_log: &dyn KeyLog,
        client_random: &[u8; 32],
        common: &mut CommonState,
    ) {
        let secret = self.ks.derive_logged_secret(
            SecretKind::ClientEarlyTrafficSecret,
            hs_hash,
            key_log,
            client_random,
        );
        match common.side {
            Side::Client => self.ks.set_encrypter(&secret, common),
            Side::Server => common
                .record_layer
                .set_early_data_decrypter(self.ks.derive_decrypter(&secret)),
        }
    }

    /// Derives `early_exporter_master_secret` (RFC 9846 §7.1) from the
    /// transcript hash of the ClientHello, for the early exporter (§7.5).
    pub(crate) fn early_exporter(
        &self,
        hs_hash: &[u8],
        key_log: &dyn KeyLog,
        client_random: &[u8; 32],
    ) -> EarlyExporter {
        EarlyExporter {
            suite: self.ks.suite,
            secret: self.ks.derive_logged_secret(
                SecretKind::EarlyExporterMasterSecret,
                hs_hash,
                key_log,
                client_random,
            ),
        }
    }

    /// `HMAC(binder_key, hs_hash)` for the `pre_shared_key` binder.
    pub(crate) fn resumption_psk_binder_key_and_sign_verify_data(
        &self,
        hs_hash: &[u8],
    ) -> hmac::Tag {
        let empty_hash = self.ks.suite.common.hash_provider.hash(&[]);
        let binder_key = self
            .ks
            .derive(SecretKind::ResumptionPskBinderKey, empty_hash.as_ref());
        self.ks.sign_finish(&binder_key, hs_hash)
    }

    pub(crate) fn into_pre_handshake(self) -> KeySchedulePreHandshake {
        KeySchedulePreHandshake { ks: self.ks }
    }
}

/// The schedule between the early secret and the handshake secret.
pub(crate) struct KeySchedulePreHandshake {
    ks: KeySchedule,
}

impl KeySchedulePreHandshake {
    pub(crate) fn new(suite: &'static Tls13CipherSuite) -> Self {
        Self {
            ks: KeySchedule::new_with_empty_secret(suite),
        }
    }

    /// Mixes in an already-computed shared secret.
    pub(crate) fn into_handshake_with_shared_secret(
        mut self,
        secret: &SharedSecret,
    ) -> KeyScheduleHandshakeStart {
        self.ks.input_shared_secret(secret);
        KeyScheduleHandshakeStart { ks: self.ks }
    }
}

impl From<KeyScheduleEarly> for KeySchedulePreHandshake {
    fn from(early: KeyScheduleEarly) -> Self {
        early.into_pre_handshake()
    }
}

/// The handshake secret is established; traffic secrets not yet derived.
pub(crate) struct KeyScheduleHandshakeStart {
    ks: KeySchedule,
}

impl KeyScheduleHandshakeStart {
    /// Derives both handshake traffic secrets and installs the server's
    /// encrypter (server side) or decrypter (client side); the other
    /// direction is installed by `install_client_key` once the client has
    /// consumed (or sent) any plaintext still due.
    pub(crate) fn derive_client_handshake_secrets(
        self,
        early_data_enabled: bool,
        hs_hash: &[u8],
        key_log: &dyn KeyLog,
        client_random: &[u8; 32],
        common: &mut CommonState,
    ) -> KeyScheduleHandshake {
        let (client_secret, server_secret) = self.derive(hs_hash, key_log, client_random);
        // The server starts encrypting immediately; the client starts
        // decrypting with the server's secret.
        match common.side {
            Side::Client => self.ks.set_decrypter(&server_secret, common),
            Side::Server => self.ks.set_encrypter(&server_secret, common),
        }
        if !early_data_enabled {
            match common.side {
                Side::Client => self.ks.set_encrypter(&client_secret, common),
                Side::Server => self.ks.set_decrypter(&client_secret, common),
            }
        }
        KeyScheduleHandshake {
            ks: self.ks,
            client_handshake_traffic_secret: client_secret,
            server_handshake_traffic_secret: server_secret,
        }
    }

    fn derive(
        &self,
        hs_hash: &[u8],
        key_log: &dyn KeyLog,
        client_random: &[u8; 32],
    ) -> (OkmBlock, OkmBlock) {
        let client = self.ks.derive_logged_secret(
            SecretKind::ClientHandshakeTrafficSecret,
            hs_hash,
            key_log,
            client_random,
        );
        let server = self.ks.derive_logged_secret(
            SecretKind::ServerHandshakeTrafficSecret,
            hs_hash,
            key_log,
            client_random,
        );
        (client, server)
    }
}

/// Both handshake traffic secrets are known.
pub(crate) struct KeyScheduleHandshake {
    ks: KeySchedule,
    client_handshake_traffic_secret: OkmBlock,
    server_handshake_traffic_secret: OkmBlock,
}

impl KeyScheduleHandshake {
    /// Installs the client handshake key in the pending direction (used after
    /// early data finishes).
    pub(crate) fn set_handshake_encrypter(&self, common: &mut CommonState) {
        self.ks
            .set_encrypter(&self.client_handshake_traffic_secret, common);
    }

    pub(crate) fn set_handshake_decrypter(
        &self,
        skip_requested: Option<usize>,
        common: &mut CommonState,
    ) {
        let decrypter = self
            .ks
            .derive_decrypter(&self.client_handshake_traffic_secret);
        match skip_requested {
            Some(max_early_data) => common
                .record_layer
                .set_message_decrypter_with_trial_decryption(decrypter, max_early_data),
            None => common.record_layer.set_message_decrypter(decrypter),
        }
    }

    pub(crate) fn sign_server_finish(&self, hs_hash: &[u8]) -> hmac::Tag {
        self.ks
            .sign_finish(&self.server_handshake_traffic_secret, hs_hash)
    }

    /// Mixes in the empty master-secret input and derives the application
    /// traffic secrets. The server installs its application encrypter at once;
    /// the client's application keys wait for the client Finished.
    pub(crate) fn into_traffic_with_client_finished_pending(
        mut self,
        hs_hash: &[u8],
        key_log: &dyn KeyLog,
        client_random: &[u8; 32],
        common: &mut CommonState,
    ) -> KeyScheduleTrafficWithClientFinishedPending {
        self.ks.input_empty();
        let traffic = KeyScheduleTraffic::new(self.ks, hs_hash, key_log, client_random);
        if common.side == Side::Server {
            traffic
                .ks
                .set_encrypter(&traffic.current_server_traffic_secret, common);
        }
        KeyScheduleTrafficWithClientFinishedPending {
            handshake_client_traffic_secret: self.client_handshake_traffic_secret,
            traffic,
        }
    }
}

/// The application secrets exist but the client's Finished is outstanding.
pub(crate) struct KeyScheduleTrafficWithClientFinishedPending {
    handshake_client_traffic_secret: OkmBlock,
    traffic: KeyScheduleTraffic,
}

impl KeyScheduleTrafficWithClientFinishedPending {
    /// Verifies the client's Finished tag; on success switches the client
    /// direction to application keys.
    pub(crate) fn sign_client_finish(&self, hs_hash: &[u8]) -> hmac::Tag {
        self.traffic
            .ks
            .sign_finish(&self.handshake_client_traffic_secret, hs_hash)
    }

    pub(crate) fn into_traffic(self, common: &mut CommonState) -> KeyScheduleTraffic {
        match common.side {
            Side::Client => self
                .traffic
                .ks
                .set_encrypter(&self.traffic.current_client_traffic_secret, common),
            Side::Server => self
                .traffic
                .ks
                .set_decrypter(&self.traffic.current_client_traffic_secret, common),
        }
        self.traffic
    }

    /// Switches the server's decrypter from the early traffic key to the
    /// client handshake key, once EndOfEarlyData arrives.
    pub(crate) fn update_decrypter(&self, common: &mut CommonState) {
        self.traffic
            .ks
            .set_decrypter(&self.handshake_client_traffic_secret, common);
    }

    /// Installs the server application decrypter on the client, which may
    /// happen before the client sends its Finished.
    pub(crate) fn set_server_application_decrypter(&self, common: &mut CommonState) {
        self.traffic
            .ks
            .set_decrypter(&self.traffic.current_server_traffic_secret, common);
    }
}

/// `TLS-Exporter(label, context, length)` of RFC 9846 §7.5 under `secret`
/// (the exporter or the early exporter master secret).
fn export_from_secret(
    suite: &'static Tls13CipherSuite,
    secret: &OkmBlock,
    out: &mut [u8],
    label: &[u8],
    context: Option<&[u8]>,
) -> Result<(), Error> {
    let hash = suite.common.hash_provider;
    if out.len() > 255 * hash.output_len() {
        return Err(Error::general("exporter output too long"));
    }
    // HkdfLabel.label is `"tls13 " + label`, at most 255 bytes.
    if label.len() > 255 - 6 {
        return Err(Error::general("exporter label too long"));
    }
    let empty_hash = hash.hash(&[]);
    let expander = suite.hkdf_provider.expander_for_okm(secret);
    let derived = hkdf_expand_label_block(&*expander, label, empty_hash.as_ref());
    let context_hash = hash.hash(context.unwrap_or(&[]));
    let expander = suite.hkdf_provider.expander_for_okm(&derived);
    hkdf_expand_label(&*expander, b"exporter", context_hash.as_ref(), out);
    Ok(())
}

/// The early exporter (RFC 9846 §7.5): keying material bound to the
/// ClientHello and the PSK, usable with 0-RTT data. Like 0-RTT data it is
/// not forward secret and is replayable with the ClientHello.
#[derive(Clone)]
pub(crate) struct EarlyExporter {
    suite: &'static Tls13CipherSuite,
    secret: OkmBlock,
}

impl EarlyExporter {
    pub(crate) fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        export_from_secret(self.suite, &self.secret, out, label, context)
    }
}

impl core::fmt::Debug for EarlyExporter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EarlyExporter").finish_non_exhaustive()
    }
}

/// The steady-state schedule: application traffic, exporter and resumption secrets.
pub(crate) struct KeyScheduleTraffic {
    ks: KeySchedule,
    current_client_traffic_secret: OkmBlock,
    current_server_traffic_secret: OkmBlock,
    current_exporter_secret: OkmBlock,
}

impl KeyScheduleTraffic {
    fn new(
        ks: KeySchedule,
        hs_hash: &[u8],
        key_log: &dyn KeyLog,
        client_random: &[u8; 32],
    ) -> Self {
        let current_client_traffic_secret = ks.derive_logged_secret(
            SecretKind::ClientApplicationTrafficSecret,
            hs_hash,
            key_log,
            client_random,
        );
        let current_server_traffic_secret = ks.derive_logged_secret(
            SecretKind::ServerApplicationTrafficSecret,
            hs_hash,
            key_log,
            client_random,
        );
        let current_exporter_secret = ks.derive_logged_secret(
            SecretKind::ExporterMasterSecret,
            hs_hash,
            key_log,
            client_random,
        );
        Self {
            ks,
            current_client_traffic_secret,
            current_server_traffic_secret,
            current_exporter_secret,
        }
    }

    /// Rotates our sending key (RFC 8446 §7.2) and installs the new encrypter.
    pub(crate) fn update_encrypter_and_notify(&mut self, common: &mut CommonState) {
        let secret = self.next_application_traffic_secret(common.side);
        self.ks.set_encrypter(&secret, common);
    }

    /// Rotates the peer's sending key and installs the new decrypter.
    pub(crate) fn update_decrypter(&mut self, common: &mut CommonState) {
        let secret = self.next_application_traffic_secret(common.side.peer());
        self.ks.set_decrypter(&secret, common);
    }

    fn next_application_traffic_secret(&mut self, side: Side) -> OkmBlock {
        let current = match side {
            Side::Client => &mut self.current_client_traffic_secret,
            Side::Server => &mut self.current_server_traffic_secret,
        };
        let next = self.ks.next_traffic_secret(current);
        *current = next.clone();
        next
    }

    /// `HKDF-Expand-Label(Derive-Secret(resumption_master_secret, "res master",
    /// hs_hash), "resumption", nonce, Hash.length)`.
    pub(crate) fn resumption_master_secret_and_derive_ticket_psk(
        &self,
        hs_hash: &[u8],
        nonce: &[u8],
    ) -> Vec<u8> {
        let rms = self.ks.derive(SecretKind::ResumptionMasterSecret, hs_hash);
        let expander = self.ks.suite.hkdf_provider.expander_for_okm(&rms);
        let mut out = alloc::vec![0u8; self.ks.hash_len()];
        hkdf_expand_label(&*expander, b"resumption", nonce, &mut out);
        out
    }

    /// RFC 9846 §7.5 and RFC 5705 exporter.
    pub(crate) fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        export_from_secret(
            self.ks.suite,
            &self.current_exporter_secret,
            out,
            label,
            context,
        )
    }

    /// The Finished MAC of a post-handshake client authentication over
    /// `hs_hash`, keyed by the current `client_application_traffic_secret_N`
    /// (RFC 9846 §4.5, "Authentication Inputs").
    pub(crate) fn sign_post_handshake_client_finish(&self, hs_hash: &[u8]) -> hmac::Tag {
        self.ks
            .sign_finish(&self.current_client_traffic_secret, hs_hash)
    }

    /// Extracts the current traffic secrets for kernel offload.
    pub(crate) fn extract_secrets(&self, side: Side) -> Result<PartiallyExtractedSecrets, Error> {
        let extract = |secret: &OkmBlock| {
            let expander = self.ks.suite.hkdf_provider.expander_for_okm(secret);
            let (key, iv) = derive_traffic_key_iv(&*expander, self.ks.suite.aead_alg.key_len());
            self.ks.suite.aead_alg.extract_keys(key, iv)
        };
        let client = extract(&self.current_client_traffic_secret)?;
        let server = extract(&self.current_server_traffic_secret)?;
        Ok(match side {
            Side::Client => PartiallyExtractedSecrets {
                tx: client,
                rx: server,
            },
            Side::Server => PartiallyExtractedSecrets {
                tx: server,
                rx: client,
            },
        })
    }
}

#[cfg(all(test, feature = "native", feature = "std"))]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::*;

    #[derive(Debug, Default)]
    struct Recorder(std::sync::Mutex<Vec<(String, Vec<u8>)>>);

    impl KeyLog for Recorder {
        fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
            if let Ok(mut entries) = self.0.lock() {
                entries.push((label.into(), secret.to_vec()));
            }
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s
            .bytes()
            .filter(u8::is_ascii_hexdigit)
            .map(|c| match c {
                b'0'..=b'9' => c - b'0',
                _ => (c | 0x20) - b'a' + 10,
            })
            .collect();
        digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
    }

    /// RFC 8448 §4 (resumed 0-RTT handshake): `early_exporter_master_secret`
    /// from the resumption PSK and the ClientHello hash.
    #[test]
    fn early_exporter_master_secret_matches_rfc8448() {
        let suite = crate::crypto::native::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap();
        let psk = unhex(
            "4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c a4 c5
             85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3",
        );
        let client_hello_hash = unhex(
            "08 ad 0f a0 5d 7c 72 33 b1 77 5b a2 ff 9f 4c 5b
             8b 59 27 6b 7f 22 7f 13 a9 76 24 5f 5d 96 09 13",
        );
        let expected = unhex(
            "b2 02 68 66 61 09 37 d7 42 3e 5b e9 08 62
             cc f2 4c 0e 60 91 18 6d 34 f8 12 08 9f f5 be 2e f7 df",
        );
        let recorder = Recorder::default();
        let exporter = KeyScheduleEarly::new(suite, &psk).early_exporter(
            &client_hello_hash,
            &recorder,
            &[0; 32],
        );
        assert_eq!(exporter.secret.as_ref(), expected.as_slice());
        let logged = recorder.0.lock().unwrap().clone();
        assert_eq!(logged, [(String::from("EARLY_EXPORTER_SECRET"), expected)]);

        // HkdfLabel cannot hold a label longer than 249 bytes.
        assert!(
            exporter
                .export_keying_material(&mut [0u8; 8], &[b'x'; 250], None)
                .is_err()
        );
    }
}
