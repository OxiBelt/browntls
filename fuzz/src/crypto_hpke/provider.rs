//! The provider operation of the `crypto_hpke` target: the TLS-side HPKE
//! API (`browntls_core::crypto::hpke`) of the native provider's suites against
//! the crate API underneath.

use browntls_core::crypto::hpke::{EncapsulatedSecret, Hpke, HpkePrivateKey, HpkePublicKey};
use browntls_crypto::hpke::{Aead, PrivateKey, PublicKey, Suite};
use browntls_crypto::rand::OsRng;

use super::keys::private_bytes;
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
