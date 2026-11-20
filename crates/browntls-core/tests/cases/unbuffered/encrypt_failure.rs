// Data records are encrypted in place in the caller's buffer
// (`MessageEncrypter::encrypt_into`). A provider whose
// `encrypted_payload_len` understates a data record makes the record not
// fit after the size check passed, and a provider's `encrypt_into` may fail
// after it wrote the plaintext, or report a length that is not the record it
// wrote, or write a record of another content type: each time the write
// fails with `Failed`, the buffer is wiped from where the record began (the
// records before it stay), and the connection is finished.

/// What the encrypter of [`Faulty`] does with a 3-byte plaintext.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// States the record one byte shorter than it is and keeps the provided
    /// `encrypt_into` (encrypt, then copy).
    UnderstatedProvided,
    /// The same, with the wrapped built-in encrypter's `encrypt_into`.
    UnderstatedInPlace,
    /// Reports this many bytes and writes nothing.
    Reports(usize),
    /// Reports more bytes than the buffer has.
    ReportsPastTheBuffer,
    /// Writes the record and reports one byte less than it wrote.
    ReportsShort,
    /// Writes the record with a header that states one byte more.
    WrongHeader,
    /// Writes the record, well framed, as a handshake record.
    WrongType,
    /// Copies the plaintext into the buffer and fails.
    PlaintextThenError,
}

const FAULTS: [Fault; 10] = [
    Fault::UnderstatedProvided,
    Fault::UnderstatedInPlace,
    Fault::Reports(0),
    Fault::Reports(4),
    Fault::Reports(5),
    Fault::ReportsPastTheBuffer,
    Fault::ReportsShort,
    Fault::WrongHeader,
    Fault::WrongType,
    Fault::PlaintextThenError,
];

/// A TLS 1.3 AEAD whose encrypter has a fault for 3-byte plaintexts.
struct Faulty {
    aead: &'static dyn browntls_core::crypto::cipher::Tls13AeadAlgorithm,
    fault: Fault,
}

struct FaultyEncrypter {
    inner: Box<dyn browntls_core::crypto::cipher::MessageEncrypter>,
    fault: Fault,
}

impl browntls_core::crypto::cipher::MessageEncrypter for FaultyEncrypter {
    fn encrypt(
        &mut self,
        msg: browntls_core::crypto::cipher::OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<browntls_core::crypto::cipher::OutboundOpaqueMessage, Error> {
        self.inner.encrypt(msg, seq)
    }

    fn encrypt_into(
        &mut self,
        msg: browntls_core::crypto::cipher::OutboundPlainMessage<'_>,
        seq: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if msg.payload.len() != 3 {
            return self.inner.encrypt_into(msg, seq, out);
        }
        match self.fault {
            Fault::UnderstatedProvided => {
                // What the provided method does.
                let record = self.inner.encrypt(msg, seq)?.encode();
                out.get_mut(..record.len())
                    .ok_or(Error::EncryptError)?
                    .copy_from_slice(&record);
                Ok(record.len())
            }
            Fault::UnderstatedInPlace => self.inner.encrypt_into(msg, seq, out),
            Fault::Reports(len) => Ok(len),
            Fault::ReportsPastTheBuffer => Ok(out.len() + 1),
            Fault::ReportsShort => Ok(self.inner.encrypt_into(msg, seq, out)? - 1),
            Fault::WrongHeader => {
                let len = self.inner.encrypt_into(msg, seq, out)?;
                out[4] += 1;
                Ok(len)
            }
            Fault::WrongType => {
                let len = self.inner.encrypt_into(msg, seq, out)?;
                out[0] = 22;
                Ok(len)
            }
            Fault::PlaintextThenError => {
                let plain = msg.payload.to_vec();
                out[5..5 + plain.len()].copy_from_slice(&plain);
                Err(Error::EncryptError)
            }
        }
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        let real = self.inner.encrypted_payload_len(payload_len);
        let understated = matches!(
            self.fault,
            Fault::UnderstatedProvided | Fault::UnderstatedInPlace
        );
        if understated && payload_len == 3 {
            real - 1
        } else {
            real
        }
    }
}

impl browntls_core::crypto::cipher::Tls13AeadAlgorithm for Faulty {
    fn encrypter(
        &self,
        key: browntls_core::crypto::cipher::AeadKey,
        iv: browntls_core::crypto::cipher::Iv,
    ) -> Box<dyn browntls_core::crypto::cipher::MessageEncrypter> {
        Box::new(FaultyEncrypter {
            inner: self.aead.encrypter(key, iv),
            fault: self.fault,
        })
    }

    fn decrypter(
        &self,
        key: browntls_core::crypto::cipher::AeadKey,
        iv: browntls_core::crypto::cipher::Iv,
    ) -> Box<dyn browntls_core::crypto::cipher::MessageDecrypter> {
        self.aead.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.aead.key_len()
    }

    fn extract_keys(
        &self,
        key: browntls_core::crypto::cipher::AeadKey,
        iv: browntls_core::crypto::cipher::Iv,
    ) -> Result<
        browntls_core::ConnectionTrafficSecrets,
        browntls_core::crypto::cipher::UnsupportedOperationError,
    > {
        self.aead.extract_keys(key, iv)
    }
}

/// The largest plaintext of one record under [`SMALL_RECORDS`].
const FRAGMENT: usize = 59;
/// A `max_fragment_size` (it counts the record header).
const SMALL_RECORDS: usize = FRAGMENT + 5;

#[test]
fn a_faulty_data_encrypter_fails_the_write_and_leaves_no_plaintext() {
    init_logging();
    // The faulty record is the write's only one, or follows a whole one.
    for (fault, before) in FAULTS
        .into_iter()
        .flat_map(|fault| [(fault, 0), (fault, FRAGMENT)])
    {
        let case = format!("{fault:?} after {before} bytes");
        let orig = prov::cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .unwrap();
        let suite: &'static browntls_core::Tls13CipherSuite =
            Box::leak(Box::new(browntls_core::Tls13CipherSuite {
                common: browntls_core::CipherSuiteCommon {
                    suite: orig.common.suite,
                    hash_provider: orig.common.hash_provider,
                    confidentiality_limit: orig.common.confidentiality_limit,
                },
                hkdf_provider: orig.hkdf_provider,
                aead_alg: Box::leak(Box::new(Faulty {
                    aead: orig.aead_alg,
                    fault,
                })),
                quic: None,
            }));
        let chain = server_chain(KeyType::Ed25519);
        let mut p = prov::default_provider();
        p.cipher_suites = vec![browntls_core::SupportedCipherSuite::Tls13(suite)];
        let mut cc = ClientConfig::builder_with_provider(Arc::new(p))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(PinnedServerVerifier::new(&chain))
            .with_no_client_auth();
        cc.max_fragment_size = Some(SMALL_RECORDS);
        let cc = Arc::new(cc);
        let sc = Arc::new(versioned_server(&chain, ProtocolVersion::TLSv1_3));
        let mut c = ub_client(&cc, Feed::Whole);
        let mut s = b_server(&sc);
        handshake(&mut c, &mut s);
        // Other lengths are stated correctly.
        exchange(&mut c, &mut s, b"four");

        let Ok(ConnectionState::WriteTraffic(mut w)) = c.conn.process_tls_records(&mut []).state
        else {
            panic!("expected WriteTraffic");
        };
        let needs = |w: &mut browntls_core::unbuffered::WriteTraffic<'_, _>, data: &[u8]| match w
            .encrypt(data, &mut [])
        {
            Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => {
                required_size
            }
            other => panic!("{other:?}"),
        };
        let mut secret = vec![0x3c; before];
        secret.extend([0x5e, 0xc2, 0xe7]);
        let kept = if before == 0 {
            0
        } else {
            needs(&mut w, &secret[..before])
        };
        let required = needs(&mut w, &secret);
        // An understated record fails only where it does not fit. The
        // others get more room than the record needs: all of it is wiped.
        let spare = match fault {
            Fault::UnderstatedProvided | Fault::UnderstatedInPlace => 0,
            _ => 9,
        };
        let mut buf = vec![0xa5u8; required + spare];
        assert_eq!(
            w.encrypt(&secret, &mut buf),
            Err(EncryptError::Failed),
            "{case}"
        );
        // The record before the faulty one is whole (the peer reads it);
        // nothing follows it.
        let (whole, wiped) = buf.split_at(kept);
        assert!(wiped.iter().all(|b| *b == 0), "{case}: {wiped:02x?}");
        let whole = whole.to_vec();
        // The sequence number is spent: nothing more goes out.
        assert_eq!(
            w.encrypt(b"four", &mut [0u8; 64]),
            Err(EncryptError::Failed),
            "{case}"
        );
        assert_eq!(
            c.conn.process_tls_records(&mut []).state.err(),
            Some(Error::EncryptError),
            "{case}"
        );
        s.give_input(&whole);
        assert_eq!(s.error, None, "{case}");
        assert_eq!(s.take_received(), secret[..before], "{case}");
    }
}
