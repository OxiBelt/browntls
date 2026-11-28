//! The provider operations of the `crypto_hpke` target: the TLS-side HPKE
//! API (`browntls_core::crypto::hpke`) of the native provider's suites, in
//! base mode and in every mode (`HpkeModes`), against the crate API
//! underneath.

use browntls_core::Error as TlsError;
use browntls_core::crypto::cipher::UnsupportedOperationError;
use browntls_core::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeAead, HpkeModes, HpkeOpenMode, HpkeOpener, HpkePrivateKey,
    HpkePsk, HpkePublicKey, HpkeSealMode, HpkeSealer,
};
use browntls_core::crypto::native;
use browntls_crypto::hpke::{Aead, Kdf, Kem, PrivateKey, Psk, PublicKey, Suite};
use browntls_crypto::rand::{FixedRng, OsRng};

use super::keys::private_bytes;
use super::session::{setup_recipient, setup_sender};
use super::{MAX_STEPS, exact, mutate};
use crate::input::Input;

/// The TLS-side provider API on one of the native suites.
pub(super) fn provider(input: &mut Input<'_>) {
    let all = browntls_core::crypto::native::hpke::ALL_SUPPORTED_SUITES;
    let hpke: &dyn Hpke = *input.pick(all);
    let tls = hpke.suite();
    let suite = Suite::from_ids(tls.kem.0, tls.sym.kdf_id.0, tls.sym.aead_id.0)
        .expect("native suites are crate suites");
    assert_ne!(suite.aead, Aead::ExportOnly);
    assert!(!hpke.fips());
    let kem = suite.kem;
    let tag_len = tls.sym.aead_id.tag_len().expect("sealing AEAD");

    let (pk, sk) = if input.bool() {
        hpke.generate_key_pair().expect("OS randomness")
    } else {
        let ikm = exact(input, kem.private_key_len());
        let sk = kem.derive_key_pair(&ikm).expect("Nsk bytes");
        (
            HpkePublicKey(sk.public_key().as_bytes().to_vec()),
            HpkePrivateKey::from(private_bytes(&sk)),
        )
    };
    assert_eq!(sk.secret_bytes().len(), kem.private_key_len());
    let crate_sk = PrivateKey::from_bytes(kem, sk.secret_bytes()).expect("own key");
    assert_eq!(crate_sk.public_key().as_bytes(), pk.0.as_slice());
    assert!(format!("{sk:?}").contains(".."));
    let info = input.short_field().to_vec();

    // A fuzzed public key is usable exactly when the crate accepts it.
    if input.choose(4) == 0 {
        let mut bytes = pk.0.clone();
        mutate(input, &mut bytes);
        // Low-order X25519/X448 points parse but fail the agreement.
        let valid = PublicKey::from_bytes(kem, &bytes)
            .and_then(|pk| suite.setup_sender(&pk, &info, &OsRng))
            .is_ok();
        let result = hpke.setup_sealer(&info, &HpkePublicKey(bytes));
        assert_eq!(result.is_ok(), valid, "{tls:?}");
        return;
    }
    // Likewise a fuzzed private key.
    if input.choose(4) == 0 {
        let mut bytes = sk.secret_bytes().to_vec();
        mutate(input, &mut bytes);
        let fuzzed_sk = HpkePrivateKey::from(bytes.clone());
        let enc = exact(input, kem.enc_len());
        let expected = PrivateKey::from_bytes(kem, &bytes)
            .and_then(|k| suite.setup_recipient(&enc, &k, &info))
            .is_ok();
        let result = hpke.setup_opener(&EncapsulatedSecret(enc), &info, &fuzzed_sk);
        assert_eq!(result.is_ok(), expected, "{tls:?}");
        return;
    }

    let (enc, mut sealer) = hpke.setup_sealer(&info, &pk).expect("valid key");
    assert_eq!(enc.0.len(), kem.enc_len());
    let mut opener = hpke.setup_opener(&enc, &info, &sk).expect("genuine enc");
    let mut crate_opener = suite
        .setup_recipient(&enc.0, &crate_sk, &info)
        .expect("genuine enc");

    // A fuzzed enc: the opener exists exactly when the crate accepts it.
    if input.bool() {
        let mut bytes = enc.0.clone();
        mutate(input, &mut bytes);
        let expected = suite.setup_recipient(&bytes, &crate_sk, &info).is_ok();
        let result = hpke.setup_opener(&EncapsulatedSecret(bytes), &info, &sk);
        assert_eq!(result.is_ok(), expected, "{tls:?}");
    }

    for _ in 0..MAX_STEPS {
        if input.is_empty() {
            break;
        }
        let aad = input.short_field();
        let pt = input.field();
        let pt = &pt[..pt.len().min(1024)];
        let ct = sealer.seal(aad, pt).expect("seal");
        assert_eq!(ct.len(), pt.len() + tag_len);
        let tamper = input.choose(3);
        if tamper != 0 {
            let mut bad = ct.clone();
            if tamper == 1 {
                let pos = usize::from(input.u16()) % bad.len();
                bad[pos] ^= 1 << (input.byte() % 8);
            } else {
                bad.truncate(input.choose(bad.len()));
            }
            assert!(
                opener.open(aad, &bad).is_err(),
                "{tls:?}: tampered accepted"
            );
        }
        assert_eq!(opener.open(aad, &ct).expect("genuine"), pt, "{tls:?}");
        assert_eq!(crate_opener.open(aad, &ct).expect("genuine"), pt, "{tls:?}");
    }
}

/// A sealer and an opener without their own `export`, for the provided
/// one.
#[derive(Debug)]
struct NoExport;

impl HpkeSealer for NoExport {
    fn seal(&mut self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, TlsError> {
        Err(TlsError::EncryptError)
    }
}

impl HpkeOpener for NoExport {
    fn open(&mut self, _: &[u8], _: &[u8]) -> Result<Vec<u8>, TlsError> {
        Err(TlsError::DecryptError)
    }
}

/// `HpkePsk::new`, which must refuse what `Psk::new` refuses (a key shorter
/// than `MIN_KEY_LEN`, an empty identifier) and keep what it accepts.
fn checked_hpke_psk(key: &[u8], id: &[u8]) -> Option<HpkePsk> {
    let crate_ok = Psk::new(key, id).is_ok();
    match HpkePsk::new(key.to_vec(), id.to_vec()) {
        Ok(psk) => {
            assert!(crate_ok, "HpkePsk accepts what Psk refuses");
            assert_eq!(psk.secret_bytes(), key);
            assert_eq!(psk.id(), id);
            assert_eq!(format!("{psk:?}"), "HpkePsk(..)");
            let copy = psk.clone();
            assert_eq!((copy.secret_bytes(), copy.id()), (key, id));
            Some(psk)
        }
        Err(e) => {
            assert!(!crate_ok, "HpkePsk refuses what Psk accepts");
            assert!(matches!(e, TlsError::General(_)), "{e:?}");
            None
        }
    }
}

/// The crate's view of a provider PSK.
fn crate_psk(psk: Option<&HpkePsk>) -> Option<Psk<'_>> {
    psk.map(|p| Psk::new(p.secret_bytes(), p.id()).expect("checked"))
}

/// The sender's mode for a PSK and a sender private key.
fn seal_mode<'a>(psk: Option<&'a HpkePsk>, sk_s: Option<&'a HpkePrivateKey>) -> HpkeSealMode<'a> {
    match (psk, sk_s) {
        (None, None) => HpkeSealMode::Base,
        (Some(psk), None) => HpkeSealMode::Psk(psk),
        (None, Some(sk)) => HpkeSealMode::Auth(sk),
        (Some(psk), Some(sk)) => HpkeSealMode::AuthPsk(psk, sk),
    }
}

/// The recipient's mode for a PSK and a sender public key.
fn open_mode<'a>(psk: Option<&'a HpkePsk>, pk_s: Option<&'a HpkePublicKey>) -> HpkeOpenMode<'a> {
    match (psk, pk_s) {
        (None, None) => HpkeOpenMode::Base,
        (Some(psk), None) => HpkeOpenMode::Psk(psk),
        (None, Some(pk)) => HpkeOpenMode::Auth(pk),
        (Some(psk), Some(pk)) => HpkeOpenMode::AuthPsk(psk, pk),
    }
}

/// `ALL_SUPPORTED_SUITES_WITH_MODES` lists `ALL_SUPPORTED_SUITES` in the
/// same order, then the export-only suites of every KEM and KDF.
fn check_mode_list() {
    let base = native::hpke::ALL_SUPPORTED_SUITES;
    let all = native::hpke::ALL_SUPPORTED_SUITES_WITH_MODES;
    assert_eq!(all.len(), base.len() + Kem::ALL.len() * Kdf::ALL.len());
    for (with_modes, hpke) in all.iter().zip(base) {
        assert_eq!(with_modes.suite(), hpke.suite());
    }
    // In the order of `ALL_SUPPORTED_SUITES`: X25519 first.
    let kems = [
        Kem::DhX25519HkdfSha256,
        Kem::DhP256HkdfSha256,
        Kem::DhP384HkdfSha384,
        Kem::DhP521HkdfSha512,
        Kem::DhX448HkdfSha512,
    ];
    let kem_kdf = kems
        .into_iter()
        .flat_map(|kem| Kdf::ALL.into_iter().map(move |kdf| (kem, kdf)));
    for (hpke, (kem, kdf)) in all[base.len()..].iter().zip(kem_kdf) {
        let tls = hpke.suite();
        assert_eq!(tls.kem.0, kem.id());
        assert_eq!(tls.sym.kdf_id.0, kdf.id());
        assert_eq!(tls.sym.aead_id, HpkeAead::EXPORT_ONLY);
    }
}

/// A fixed PSK for a recipient of a sender without one.
fn fixed_psk() -> HpkePsk {
    HpkePsk::new(vec![0x42; 32], b"other".to_vec()).expect("valid")
}

/// Fills a buffer of `len` bytes with `f`, or `None` if it fails.
fn export(len: usize, f: impl FnOnce(&mut [u8]) -> bool) -> Option<Vec<u8>> {
    let mut out = vec![0u8; len];
    f(&mut out).then_some(out)
}

/// The provider's modes (`HpkeModes`) on one of
/// `ALL_SUPPORTED_SUITES_WITH_MODES`: a provider sealer against a crate
/// recipient, and a crate sender (deterministic) against a provider opener
/// whose mode, PSK or sender key may differ from the sender's, which must
/// then fail to open and export other secrets, exactly as a crate recipient
/// set up the same way. Seals, opens and exports of fuzzed lengths must
/// agree with the crate; export-only suites seal and open nothing.
pub(super) fn provider_modes(input: &mut Input<'_>) {
    check_mode_list();
    let hpke: &dyn HpkeModes = *input.pick(native::hpke::ALL_SUPPORTED_SUITES_WITH_MODES);
    let tls = hpke.suite();
    let suite = Suite::from_ids(tls.kem.0, tls.sym.kdf_id.0, tls.sym.aead_id.0)
        .expect("native suites are crate suites");
    let kem = suite.kem;
    let nsk = kem.private_key_len();
    let crate_sk = kem.derive_key_pair(&exact(input, nsk)).expect("Nsk bytes");
    let pk = HpkePublicKey(crate_sk.public_key().as_bytes().to_vec());
    let sk = HpkePrivateKey::from(private_bytes(&crate_sk));
    let info = input.short_field().to_vec();

    // The sender: a PSK (bit 0), a sender key (bit 1), fuzzed sender
    // private key bytes (bit 2).
    let flags = input.byte();
    let psk = if flags & 1 == 0 {
        None
    } else {
        let (key, id) = (input.short_field(), input.short_field());
        checked_hpke_psk(key, id)
    };
    let crate_sk_s =
        (flags & 2 != 0).then(|| kem.derive_key_pair(&exact(input, nsk)).expect("Nsk bytes"));
    let sk_s = crate_sk_s
        .as_ref()
        .map(|k| HpkePrivateKey::from(private_bytes(k)));
    let pk_s = crate_sk_s
        .as_ref()
        .map(|k| HpkePublicKey(k.public_key().as_bytes().to_vec()));
    let crate_psk_s = crate_psk(psk.as_ref());
    let mode = seal_mode(psk.as_ref(), sk_s.as_ref());
    if psk.is_some() {
        assert!(format!("{mode:?}").contains("HpkePsk(..)"));
    }
    if let Some(sk_s) = &sk_s
        && flags & 4 != 0
    {
        // Sender key bytes are usable exactly when the crate accepts them.
        let mut bytes = sk_s.secret_bytes().to_vec();
        mutate(input, &mut bytes);
        let fuzzed = HpkePrivateKey::from(bytes.clone());
        let pk_r = crate_sk.public_key();
        let expected = PrivateKey::from_bytes(kem, &bytes)
            .and_then(|k| setup_sender(suite, pk_r, &info, crate_psk_s.as_ref(), Some(&k), &OsRng))
            .is_ok();
        let mode = seal_mode(psk.as_ref(), Some(&fuzzed));
        let result = hpke.setup_sealer_with_mode(mode, &info, &pk);
        assert_eq!(result.is_ok(), expected, "{tls:?}");
        return;
    }
    let ikm_e = exact(input, nsk);

    // Provider sealer, crate recipient.
    let (enc, mut sealer) = hpke
        .setup_sealer_with_mode(mode, &info, &pk)
        .expect("valid keys");
    assert_eq!(enc.0.len(), kem.enc_len());
    let crate_pk_s = crate_sk_s.as_ref().map(PrivateKey::public_key);
    let mut crate_r = setup_recipient(
        suite,
        &enc.0,
        &crate_sk,
        &info,
        crate_psk_s.as_ref(),
        crate_pk_s,
    )
    .expect("genuine enc");

    // Crate sender, provider opener with this mode or another.
    let (crate_enc, mut crate_s) = setup_sender(
        suite,
        crate_sk.public_key(),
        &info,
        crate_psk_s.as_ref(),
        crate_sk_s.as_ref(),
        &FixedRng::new(&ikm_e),
    )
    .expect("valid keys");
    let mut other_psk = psk.clone();
    let mut other_pk = pk_s.clone();
    match input.choose(4) {
        0 => {}
        1 => {
            // Another mode, with the sender's PSK and key where it has
            // them, and otherwise a fixed PSK and the recipient's own key.
            let other = input.byte();
            other_psk = (other & 1 != 0).then(|| psk.clone().unwrap_or_else(fixed_psk));
            other_pk = (other & 2 != 0).then(|| pk_s.clone().unwrap_or_else(|| pk.clone()));
        }
        2 => {
            // A mutated sender public key (the recipient's own if the
            // sender has none).
            let mut bytes = pk_s.as_ref().unwrap_or(&pk).0.clone();
            mutate(input, &mut bytes);
            other_pk = Some(HpkePublicKey(bytes));
        }
        _ => {
            // A mutated PSK key with the sender's identifier.
            let base = psk.clone().unwrap_or_else(fixed_psk);
            let mut key = base.secret_bytes().to_vec();
            mutate(input, &mut key);
            let Some(psk) = checked_hpke_psk(&key, base.id()) else {
                return;
            };
            other_psk = Some(psk);
        }
    }
    let psk_bytes = |p: &HpkePsk| (p.secret_bytes().to_vec(), p.id().to_vec());
    let genuine =
        other_psk.as_ref().map(psk_bytes) == psk.as_ref().map(psk_bytes) && other_pk == pk_s;
    let crate_enc = EncapsulatedSecret(crate_enc.as_bytes().to_vec());
    let opener = hpke.setup_opener_with_mode(
        open_mode(other_psk.as_ref(), other_pk.as_ref()),
        &crate_enc,
        &info,
        &sk,
    );
    let other_crate_psk = crate_psk(other_psk.as_ref());
    let crate_opener = other_pk
        .as_ref()
        .map(|pk| PublicKey::from_bytes(kem, &pk.0))
        .transpose()
        .and_then(|pk_s| {
            let psk = other_crate_psk.as_ref();
            setup_recipient(suite, &crate_enc.0, &crate_sk, &info, psk, pk_s.as_ref())
        });
    assert_eq!(
        opener.is_ok(),
        crate_opener.is_ok(),
        "{tls:?}: opener setups differ"
    );
    assert!(
        opener.is_ok() || !genuine,
        "{tls:?}: genuine opener refused"
    );
    let mut opener = opener.ok().zip(crate_opener.ok());

    // The provided `export` fails.
    let mut out = [0u8; 8];
    let unsupported = Err(UnsupportedOperationError.into());
    assert_eq!(HpkeSealer::export(&NoExport, b"", &mut out), unsupported);
    assert_eq!(HpkeOpener::export(&NoExport, b"", &mut out), unsupported);

    let sealing = suite.aead != Aead::ExportOnly;
    for _ in 0..MAX_STEPS {
        if input.is_empty() {
            break;
        }
        if input.bool() {
            let ctx = input.short_field();
            let limit = 255 * suite.kdf.output_len();
            let len = match input.choose(3) {
                0 => input.choose(256),
                1 => limit - 4 + input.choose(9),
                _ => usize::from(input.u16()) % (limit + 8),
            };
            let ours = export(len, |o| sealer.export(ctx, o).is_ok());
            let theirs = export(len, |o| crate_r.export(ctx, o).is_ok());
            assert_eq!(ours.is_some(), len <= limit, "{tls:?}");
            assert_eq!(ours, theirs, "{tls:?}: sealer export differs");
            let sent = export(len, |o| crate_s.export(ctx, o).is_ok());
            if let Some((opener, crate_opener)) = &opener {
                let ours = export(len, |o| opener.export(ctx, o).is_ok());
                let theirs = export(len, |o| crate_opener.export(ctx, o).is_ok());
                assert_eq!(ours, theirs, "{tls:?}: opener export differs");
                if (1..=limit).contains(&len) {
                    assert_eq!(ours == sent, genuine, "{tls:?}: exports");
                }
            }
            continue;
        }
        let aad = input.short_field();
        let pt = input.field();
        let pt = &pt[..pt.len().min(1024)];
        let ct = sealer.seal(aad, pt);
        assert_eq!(ct.is_ok(), sealing, "{tls:?}");
        if let Ok(ct) = ct {
            assert_eq!(crate_r.open(aad, &ct), Ok(pt.to_vec()), "{tls:?}");
        }
        let Ok(ct) = crate_s.seal(aad, pt) else {
            assert!(!sealing);
            continue;
        };
        if let Some((opener, crate_opener)) = &mut opener {
            let ours = opener.open(aad, &ct);
            assert_eq!(ours.is_ok(), crate_opener.open(aad, &ct).is_ok());
            assert_eq!(ours.ok(), genuine.then(|| pt.to_vec()), "{tls:?}: open");
        }
    }
}
