//! A userspace stand-in for Linux kernel TLS, adapted from the integration
//! tests (`crates/browntls/tests/cases/kernel/sim.rs`), that also checks
//! what the [`KernelConnection`] asks of it.
//!
//! It protects records with the extracted secrets as the kernel does
//! (TLS 1.2 AES-GCM explicit nonces counting up from the IV it is given,
//! everything else XORing the sequence number into the IV), passes
//! application data through, hands every other record to the connection,
//! and executes the connection's outputs in order. Like Linux it stops
//! reading after a TLS 1.3 KeyUpdate until new receive keys are installed.

use std::fmt::Write as _;

use browntls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, MessageDecrypter, MessageEncrypter, OutboundChunks,
    OutboundPlainMessage, Tls12RecordProtection,
};
use browntls::kernel::{KernelConnection, KernelOutput};
use browntls::{
    ConnectionTrafficSecrets, ContentType, Error, ExtractedSecrets, ProtocolVersion, SideData,
    SupportedCipherSuite,
};

/// The most plaintext Linux puts into one record by default.
pub(super) const MAX_PAYLOAD: usize = 16384;

/// The handshake type of KeyUpdate.
const KEY_UPDATE: u8 = 24;

fn key_iv(secrets: &ConnectionTrafficSecrets) -> (&[u8], [u8; 12]) {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
        | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
        | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
        | ConnectionTrafficSecrets::Aes128Ccm { key, iv } => {
            (key.as_ref(), iv.as_ref().try_into().expect("12-byte IV"))
        }
        other => panic!("secrets with no kernel form handed out: {other:?}"),
    }
}

/// Record protection keyed like the kernel: `secrets` at sequence number
/// `seq`.
fn keys(
    suite: SupportedCipherSuite,
    secrets: &ConnectionTrafficSecrets,
    seq: u64,
) -> (Box<dyn MessageEncrypter>, Box<dyn MessageDecrypter>) {
    let (key, iv) = key_iv(secrets);
    match suite {
        SupportedCipherSuite::Tls13(s) => (
            s.aead_alg.encrypter(AeadKey::new(key), iv.into()),
            s.aead_alg.decrypter(AeadKey::new(key), iv.into()),
        ),
        SupportedCipherSuite::Tls12(s) => {
            let Tls12RecordProtection::Aead(alg) = s.record else {
                panic!("a suite with no kernel form was handed over");
            };
            if alg.key_block_shape().explicit_nonce_len == 8 {
                // The kernel sends `iv[4..] + k` with record `seq + k`; the
                // library's encrypter sends `extra + seq`.
                let next = u64::from_be_bytes(iv[4..].try_into().expect("8 bytes"));
                let extra = next.wrapping_sub(seq).to_be_bytes();
                (
                    alg.encrypter(AeadKey::new(key), &iv[..4], &extra),
                    alg.decrypter(AeadKey::new(key), &iv[..4]),
                )
            } else {
                (
                    alg.encrypter(AeadKey::new(key), &iv, &[]),
                    alg.decrypter(AeadKey::new(key), &iv),
                )
            }
        }
    }
}

/// Whether `payload` is exactly one KeyUpdate message.
pub(super) fn is_key_update(payload: &[u8]) -> bool {
    matches!(payload, [KEY_UPDATE, 0, 0, 1, 0 | 1])
}

/// One direction's record protection and next sequence number.
struct Direction<C: ?Sized> {
    cipher: Box<C>,
    seq: u64,
}

/// The simulated socket: the connection plus the kernel's state.
pub(super) struct Offloaded<D> {
    pub(super) conn: KernelConnection<D>,
    suite: SupportedCipherSuite,
    tx: Direction<dyn MessageEncrypter>,
    rx: Direction<dyn MessageDecrypter>,
    /// A KeyUpdate was received and no new receive key installed yet.
    rx_paused: bool,
    /// Reception ended (the connection failed, or a record did not
    /// decrypt after fuzzed records were handled).
    rx_stopped: bool,
    /// Ciphertext for the peer.
    pub(super) wire_out: Vec<u8>,
    /// Ciphertext from the peer not yet a whole record.
    wire_in: Vec<u8>,
    /// Application data received, from before the handover on.
    pub(super) app_in: Vec<u8>,
    /// The key bytes of every secret handed out, as they would appear in
    /// lower-case hex and in a `Debug` byte list.
    secret_forms: Vec<String>,
    /// Handshake bytes handed to the connection that do not yet form a
    /// whole message: a model of its joiner, valid while `joiner_known`.
    joiner: Vec<u8>,
    joiner_known: bool,
    /// `handle_record` failed: the connection is over.
    pub(super) failed: bool,
    /// We output `close_notify`.
    pub(super) closed: bool,
    /// Records were handled that the peer did not send.
    pub(super) desynced: bool,
}

impl<D: SideData> Offloaded<D> {
    /// `joiner_known`: no part of a handshake message can be buffered in
    /// the connection at the handover.
    pub(super) fn new(
        conn: KernelConnection<D>,
        secrets: &ExtractedSecrets,
        app_in: Vec<u8>,
        joiner_known: bool,
    ) -> Self {
        let suite = conn.negotiated_cipher_suite();
        let (tx, _) = keys(suite, &secrets.tx.1, secrets.tx.0);
        let (_, rx) = keys(suite, &secrets.rx.1, secrets.rx.0);
        let mut off = Self {
            conn,
            suite,
            tx: Direction {
                cipher: tx,
                seq: secrets.tx.0,
            },
            rx: Direction {
                cipher: rx,
                seq: secrets.rx.0,
            },
            rx_paused: false,
            rx_stopped: false,
            wire_out: Vec::new(),
            wire_in: Vec::new(),
            app_in,
            secret_forms: Vec::new(),
            joiner: Vec::new(),
            joiner_known,
            failed: false,
            closed: false,
            desynced: false,
        };
        off.note_secret(&secrets.tx.1);
        off.note_secret(&secrets.rx.1);
        off.check_debug(&format!("{:?}", off.conn));
        off
    }

    pub(super) fn tls13(&self) -> bool {
        self.conn.protocol_version() == ProtocolVersion::TLSv1_3
    }

    fn note_secret(&mut self, secrets: &ConnectionTrafficSecrets) {
        let (key, _) = key_iv(secrets);
        let mut hex = String::new();
        for b in key {
            let _ = write!(hex, "{b:02x}");
        }
        let list = key[..8]
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        self.secret_forms.push(hex);
        self.secret_forms.push(list);
    }

    /// `text`, a `Debug` rendering, shows no key handed out.
    pub(super) fn check_debug(&self, text: &str) {
        for form in &self.secret_forms {
            assert!(!text.contains(form.as_str()), "Debug output shows a key");
        }
    }

    pub(super) fn max_payload(&self) -> usize {
        self.conn
            .max_tx_payload_len()
            .map_or(MAX_PAYLOAD, usize::from)
    }

    fn seal(&mut self, typ: ContentType, payload: &[u8]) {
        assert!(payload.len() <= self.max_payload(), "record over the limit");
        let msg = OutboundPlainMessage {
            typ,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let sealed = self
            .tx
            .cipher
            .encrypt(msg, self.tx.seq)
            .expect("kernel encryption");
        self.tx.seq += 1;
        self.wire_out.extend_from_slice(&sealed.encode());
    }

    /// Takes every output the connection queued, checks the sequence, and
    /// executes it. `rx_expected`: how many RxKeys the call may produce
    /// (`None`: not known). `fatal`: the call failed the connection.
    /// Returns how many RxKeys there were.
    pub(super) fn drain(
        &mut self,
        rx_expected: Option<usize>,
        fatal: bool,
        before_failed: bool,
    ) -> usize {
        let mut outs = Vec::new();
        while self.conn.has_output() {
            outs.push(self.conn.pop_output().expect("has_output"));
        }
        assert!(self.conn.pop_output().is_none(), "output after has_output");
        for out in &outs {
            if let KernelOutput::TxKeys(s) | KernelOutput::RxKeys(s) = out {
                self.note_secret(s);
            }
        }
        for out in &outs {
            self.check_debug(&format!("{out:?}"));
        }
        let rx = self.check_outputs(&outs, rx_expected, fatal, before_failed);
        for out in outs {
            self.execute(out);
        }
        rx
    }

    fn check_outputs(
        &mut self,
        outs: &[KernelOutput],
        rx_expected: Option<usize>,
        fatal: bool,
        before_failed: bool,
    ) -> usize {
        let key_update_record = |out: Option<&KernelOutput>| {
            matches!(out, Some(KernelOutput::Record { typ: ContentType::Handshake, payload })
                if payload.len() == 5 && payload[..4] == [KEY_UPDATE, 0, 0, 1])
        };
        let mut rx = 0;
        let mut fatal_alert = false;
        for (i, out) in outs.iter().enumerate() {
            assert!(!fatal_alert, "output after the fatal alert");
            // After a failure only the alert; after our close_notify only
            // alerts and the keys to keep receiving.
            let alert = matches!(
                out,
                KernelOutput::Record {
                    typ: ContentType::Alert,
                    ..
                }
            );
            if before_failed {
                assert!(alert, "{out:?} after the connection failed");
            }
            if self.closed {
                assert!(
                    alert || matches!(out, KernelOutput::RxKeys(_)),
                    "{out:?} after close_notify"
                );
            }
            match out {
                KernelOutput::Record { typ, payload } => {
                    assert_ne!(
                        *typ,
                        ContentType::ApplicationData,
                        "application data queued"
                    );
                    if key_update_record(Some(out)) {
                        assert!(
                            matches!(outs.get(i + 1), Some(KernelOutput::TxKeys(_))),
                            "a KeyUpdate not followed by TxKeys: {outs:?}"
                        );
                    }
                    if *typ == ContentType::Alert {
                        match payload[..] {
                            [1, 0] => self.closed = true,
                            [2, _] => fatal_alert = fatal,
                            _ => {}
                        }
                    }
                }
                KernelOutput::TxKeys(_) => {
                    assert!(self.tls13(), "TLS 1.2 has no rekey");
                    assert!(
                        i > 0 && key_update_record(outs.get(i - 1)),
                        "TxKeys without a KeyUpdate before: {outs:?}"
                    );
                }
                KernelOutput::RxKeys(_) => {
                    assert!(self.tls13(), "TLS 1.2 has no rekey");
                    rx += 1;
                    // What follows is the answer owed, if any: our KeyUpdate
                    // then the new transmit keys.
                    let rest = &outs[i + 1..];
                    assert!(
                        rest.is_empty()
                            || (rest.len() == 2
                                && key_update_record(rest.first())
                                && matches!(rest[1], KernelOutput::TxKeys(_))),
                        "RxKeys followed by {rest:?}"
                    );
                }
                _ => {}
            }
        }
        assert!(rx <= 1, "several RxKeys for one call: {outs:?}");
        if let Some(expected) = rx_expected {
            assert_eq!(rx, expected, "RxKeys for {expected} KeyUpdates: {outs:?}");
        }
        rx
    }

    fn execute(&mut self, out: KernelOutput) {
        match out {
            KernelOutput::Record { typ, payload } => self.seal(typ, &payload),
            KernelOutput::TxKeys(secrets) => {
                self.tx = Direction {
                    cipher: keys(self.suite, &secrets, 0).0,
                    seq: 0,
                };
            }
            KernelOutput::RxKeys(secrets) => {
                self.rx = Direction {
                    cipher: keys(self.suite, &secrets, 0).1,
                    seq: 0,
                };
                self.rx_paused = false;
            }
            other => panic!("unknown output {other:?}"),
        }
    }

    /// `handle_record`, with the properties every call must have.
    pub(super) fn handle(&mut self, typ: ContentType, payload: &[u8]) -> Result<(), Error> {
        let before_failed = self.failed;
        let peer_closed = self.conn.peer_has_closed();
        let may_send = self.conn.may_send_application_data();
        // The KeyUpdates this record completes, per the joiner model.
        let mut key_updates = 0;
        let modelled =
            self.joiner_known && typ == ContentType::Handshake && !before_failed && !peer_closed;
        if modelled {
            self.joiner.extend_from_slice(payload);
            while self.joiner.len() >= 4 {
                let len = usize::from(self.joiner[1]) << 16
                    | usize::from(self.joiner[2]) << 8
                    | usize::from(self.joiner[3]);
                if self.joiner.len() < 4 + len {
                    break;
                }
                if self.joiner[0] == KEY_UPDATE {
                    key_updates += 1;
                }
                self.joiner.drain(..4 + len);
            }
        }
        let result = self.conn.handle_record(typ, payload);
        if let Err(err) = &result {
            let _ = format!("{err} {err:?}");
        }

        if typ == ContentType::ApplicationData {
            // Refused, and nothing else changes.
            assert!(result.is_err(), "application data handled");
            assert!(!self.conn.has_output());
            assert_eq!(may_send, self.conn.may_send_application_data());
            return result;
        }
        if before_failed {
            assert!(result.is_err(), "a failed connection handled a record");
            self.drain(Some(0), false, true);
            return result;
        }
        if peer_closed {
            // Ignored after the peer's close_notify.
            assert!(
                !self.conn.has_output(),
                "output for a record after close_notify"
            );
            self.failed |= result.is_err();
            return result;
        }
        match &result {
            Ok(()) => {
                // What the deframer refuses in userspace, and the records
                // that would stall Linux (it pauses after any handshake
                // record starting with the KeyUpdate type).
                let starts_key_update =
                    typ == ContentType::Handshake && payload.first() == Some(&KEY_UPDATE);
                if starts_key_update {
                    assert!(
                        self.tls13() && is_key_update(payload),
                        "a record starting with the KeyUpdate type accepted"
                    );
                }
                if typ == ContentType::Handshake {
                    assert!(!payload.is_empty(), "an empty handshake record accepted");
                } else if self.joiner_known {
                    assert!(
                        self.joiner.is_empty(),
                        "a record interleaved with a handshake message accepted"
                    );
                }
                if modelled {
                    assert!(
                        key_updates <= 1,
                        "several KeyUpdates in one record accepted"
                    );
                    if key_updates == 1 {
                        assert!(
                            self.joiner.is_empty(),
                            "a KeyUpdate that did not end its record"
                        );
                    }
                    assert_eq!(
                        key_updates,
                        usize::from(starts_key_update),
                        "a KeyUpdate accepted in a record Linux does not pause on"
                    );
                }
                // New receive keys exactly for the records Linux pauses on.
                let rx_expected = Some(usize::from(self.tls13() && starts_key_update));
                // A KeyUpdate ends its record: the joiner is empty now.
                if self.drain(rx_expected, false, false) == 1 && !self.joiner_known {
                    self.joiner.clear();
                    self.joiner_known = true;
                }
            }
            Err(_) => {
                self.failed = true;
                self.drain(None, true, false);
            }
        }
        result
    }

    /// Reads ciphertext from the peer: application data is kept, every
    /// other record goes to the connection.
    pub(super) fn receive(&mut self, wire: &[u8]) {
        if self.rx_stopped || self.failed {
            return;
        }
        self.wire_in.extend_from_slice(wire);
        while self.wire_in.len() >= 5 && !self.rx_stopped && !self.failed {
            let len = usize::from(u16::from_be_bytes([self.wire_in[3], self.wire_in[4]]));
            if self.wire_in.len() < 5 + len {
                break;
            }
            let mut record: Vec<u8> = self.wire_in.drain(..5 + len).collect();
            if self.rx_paused {
                // Fuzzed handshake bytes may have joined the KeyUpdate to
                // something else; otherwise new keys must have come.
                assert!(self.desynced, "read after a KeyUpdate without new keys");
                self.rx_stopped = true;
                return;
            }
            let typ = ContentType::from(record[0]);
            let plain = match self.rx.cipher.decrypt(
                InboundOpaqueMessage::new(typ, ProtocolVersion::TLSv1_2, &mut record[5..]),
                self.rx.seq,
            ) {
                Ok(plain) => plain,
                Err(err) => {
                    assert!(self.desynced, "kernel decryption failed: {err:?}");
                    self.rx_stopped = true;
                    return;
                }
            };
            self.rx.seq += 1;
            let (typ, payload) = (plain.typ, plain.payload.to_vec());
            if typ == ContentType::ApplicationData {
                if !payload.is_empty() {
                    self.conn.application_data_received();
                }
                self.app_in.extend_from_slice(&payload);
                continue;
            }
            // Linux pauses reception after a TLS 1.3 KeyUpdate.
            if self.tls13() && typ == ContentType::Handshake && payload.first() == Some(&KEY_UPDATE)
            {
                self.rx_paused = true;
            }
            if self.handle(typ, &payload).is_err() {
                self.rx_stopped = true;
            }
        }
    }

    /// Sends application data as the kernel does: records of at most the
    /// maximum payload, counted for the connection's limits. Returns
    /// whether it was sent.
    pub(super) fn send(&mut self, data: &[u8]) -> bool {
        if !self.conn.may_send_application_data() {
            return false;
        }
        let max = self.max_payload();
        let mut records = 0;
        for chunk in data.chunks(max) {
            self.seal(ContentType::ApplicationData, chunk);
            records += 1;
        }
        let before_failed = self.failed;
        let _ = self.conn.records_sent(records);
        self.drain(Some(0), false, before_failed);
        true
    }
}
