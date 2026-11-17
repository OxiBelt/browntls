//! A userspace stand-in for Linux kernel TLS, driven by a
//! [`KernelConnection`] the way a real offload driver would be.
//!
//! It protects records with the extracted secrets as the kernel does
//! (TLS 1.2 AES-GCM explicit nonces counting up from the IV it is given,
//! everything else XORing the sequence number into the IV), passes
//! application data through, hands every other record to the connection,
//! and executes the connection's outputs in order. Like Linux it stops
//! reading after a TLS 1.3 KeyUpdate until new receive keys are installed.

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
pub(crate) const MAX_PAYLOAD: usize = 16384;

fn key_iv(secrets: &ConnectionTrafficSecrets) -> (AeadKey, [u8; 12]) {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
        | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
        | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
        | ConnectionTrafficSecrets::Aes128Ccm { key, iv } => {
            (AeadKey::new(key.as_ref()), iv.as_ref().try_into().unwrap())
        }
        other => panic!("unknown secrets {other:?}"),
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
            s.aead_alg.encrypter(AeadKey::new(key.as_ref()), iv.into()),
            s.aead_alg.decrypter(key, iv.into()),
        ),
        SupportedCipherSuite::Tls12(s) => {
            let Tls12RecordProtection::Aead(alg) = s.record else {
                panic!("no kernel form");
            };
            let shape = alg.key_block_shape();
            if shape.explicit_nonce_len == 8 {
                // The kernel sends `iv[4..] + k` with record `seq + k`; the
                // library's encrypter sends `extra + seq`.
                let next = u64::from_be_bytes(iv[4..].try_into().unwrap());
                let extra = next.wrapping_sub(seq).to_be_bytes();
                (
                    alg.encrypter(AeadKey::new(key.as_ref()), &iv[..4], &extra),
                    alg.decrypter(key, &iv[..4]),
                )
            } else {
                (
                    alg.encrypter(AeadKey::new(key.as_ref()), &iv, &[]),
                    alg.decrypter(key, &iv),
                )
            }
        }
    }
}

/// One direction's record protection and next sequence number.
struct Direction<C: ?Sized> {
    cipher: Box<C>,
    seq: u64,
}

/// The simulated socket: the connection plus the kernel's state.
pub(crate) struct Offloaded<Data> {
    pub(crate) conn: KernelConnection<Data>,
    suite: SupportedCipherSuite,
    tx: Direction<dyn MessageEncrypter>,
    rx: Direction<dyn MessageDecrypter>,
    /// A KeyUpdate was received and no new receive key installed yet.
    rx_paused: bool,
    /// Ciphertext for the peer.
    pub(crate) wire_out: Vec<u8>,
    /// Ciphertext from the peer not yet a whole record.
    wire_in: Vec<u8>,
    /// Application data received.
    pub(crate) app_in: Vec<u8>,
    /// Records the connection asked the kernel to send, by type.
    pub(crate) control_sent: Vec<(ContentType, Vec<u8>)>,
    /// How many TxKeys and RxKeys were installed.
    pub(crate) tx_rekeys: usize,
    pub(crate) rx_rekeys: usize,
}

impl<Data: SideData> Offloaded<Data> {
    pub(crate) fn new(conn: KernelConnection<Data>, secrets: ExtractedSecrets) -> Self {
        let suite = conn.negotiated_cipher_suite();
        let (tx, _) = keys(suite, &secrets.tx.1, secrets.tx.0);
        let (_, rx) = keys(suite, &secrets.rx.1, secrets.rx.0);
        Self {
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
            wire_out: Vec::new(),
            wire_in: Vec::new(),
            app_in: Vec::new(),
            control_sent: Vec::new(),
            tx_rekeys: 0,
            rx_rekeys: 0,
        }
    }

    fn tls13(&self) -> bool {
        self.conn.protocol_version() == ProtocolVersion::TLSv1_3
    }

    fn seal(&mut self, typ: ContentType, payload: &[u8]) {
        let max = self
            .conn
            .max_tx_payload_len()
            .map_or(MAX_PAYLOAD, usize::from);
        assert!(payload.len() <= max, "record over the limit");
        let msg = OutboundPlainMessage {
            typ,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let sealed = self.tx.cipher.encrypt(msg, self.tx.seq).unwrap();
        self.tx.seq += 1;
        self.wire_out.extend_from_slice(&sealed.encode());
    }

    /// Executes the connection's outputs, in order.
    pub(crate) fn flush(&mut self) {
        while let Some(output) = self.conn.pop_output() {
            match output {
                KernelOutput::Record { typ, payload } => {
                    self.seal(typ, &payload);
                    self.control_sent.push((typ, payload));
                }
                KernelOutput::TxKeys(secrets) => {
                    assert!(self.tls13(), "TLS 1.2 has no rekey");
                    self.tx = Direction {
                        cipher: keys(self.suite, &secrets, 0).0,
                        seq: 0,
                    };
                    self.tx_rekeys += 1;
                }
                KernelOutput::RxKeys(secrets) => {
                    assert!(self.tls13(), "TLS 1.2 has no rekey");
                    self.rx = Direction {
                        cipher: keys(self.suite, &secrets, 0).1,
                        seq: 0,
                    };
                    self.rx_paused = false;
                    self.rx_rekeys += 1;
                }
                other => panic!("unknown output {other:?}"),
            }
        }
    }

    /// Sends application data as the kernel does: records of at most the
    /// maximum payload, counted for the connection's limits.
    pub(crate) fn send(&mut self, data: &[u8]) {
        self.flush();
        assert!(self.conn.may_send_application_data());
        let max = self
            .conn
            .max_tx_payload_len()
            .map_or(MAX_PAYLOAD, usize::from);
        let mut records = 0;
        for chunk in data.chunks(max) {
            self.seal(ContentType::ApplicationData, chunk);
            records += 1;
        }
        self.conn.records_sent(records).unwrap();
        self.flush();
    }

    /// Reads ciphertext from the peer: application data is kept, every
    /// other record goes to the connection.
    pub(crate) fn receive(&mut self, wire: &[u8]) -> Result<(), Error> {
        self.wire_in.extend_from_slice(wire);
        while self.wire_in.len() >= 5 {
            let len = usize::from(u16::from_be_bytes([self.wire_in[3], self.wire_in[4]]));
            if self.wire_in.len() < 5 + len {
                break;
            }
            let mut record: Vec<u8> = self.wire_in.drain(..5 + len).collect();
            assert!(!self.rx_paused, "read after a KeyUpdate without new keys");
            let typ = ContentType::from(record[0]);
            let plain = self
                .rx
                .cipher
                .decrypt(
                    InboundOpaqueMessage::new(typ, ProtocolVersion::TLSv1_2, &mut record[5..]),
                    self.rx.seq,
                )
                .expect("kernel decryption");
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
            if self.tls13() && typ == ContentType::Handshake && payload.first() == Some(&24) {
                self.rx_paused = true;
            }
            let result = self.conn.handle_record(typ, &payload);
            self.flush();
            result?;
        }
        Ok(())
    }

    /// Takes the ciphertext for the peer.
    pub(crate) fn take_wire(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.wire_out)
    }
}
