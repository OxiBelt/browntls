//! Decoding and evaluating the inputs to certificate revocation decisions.

use std::sync::OnceLock;

use browntls::crypto::native;
use browntls::revocation::RevocationDigests;
use browntls_pki::crlite::{CrliteFilter, CrliteKey, CrliteLimits, CrliteSct};
use browntls_pki::ocsp::{CertIdHashers, OcspIssuer, OcspPolicy, verify_response};
use browntls_pki::sct::{CtLog, CtPolicy, SctOptions, SctVerifier};
use browntls_pki::{Cert, UnixTime};

use crate::connection::Identity;

mod handshake;

const CLUBCARD_V3: &[u8] =
    include_bytes!("../../crates/browntls-pki/tests/data/crlite/full-v3.clubcard");
const CLUBCARD_V4: &[u8] =
    include_bytes!("../../crates/browntls-pki/tests/data/crlite/full-v4.clubcard");

pub fn run(data: &[u8]) {
    let Some((&kind, bytes)) = data.split_first() else {
        return;
    };
    if kind % 4 == 0 {
        let limits = CrliteLimits {
            max_layer_len: 64 * 1024,
            ..CrliteLimits::DEFAULT
        };
        if let Ok(filter) = CrliteFilter::decode(bytes, &limits) {
            let issuer = bytes
                .get(..32)
                .and_then(|v| v.try_into().ok())
                .unwrap_or([0; 32]);
            let serial = bytes.get(32..40).unwrap_or(&[0]);
            let digest =
                (RevocationDigests::native().sha256)(&[issuer.as_slice(), serial].concat());
            let key = CrliteKey::new(issuer, serial, digest);
            let time = bytes
                .get(40..48)
                .and_then(|v| v.try_into().ok())
                .map(u64::from_be_bytes)
                .unwrap_or(0);
            let _ = filter.status(&key, &[CrliteSct::from_verified(issuer, time)]);
        }
        return;
    }
    static IDENTITY: OnceLock<Identity> = OnceLock::new();
    let identity = IDENTITY.get_or_init(|| {
        Identity::generate("localhost", rcgen::ExtendedKeyUsagePurpose::ServerAuth)
    });
    let issuer = Cert::try_from(&identity.ca).unwrap();
    let leaf = Cert::try_from(&identity.chain[0]).unwrap();
    let digests = RevocationDigests::native();
    let provider = native::default_provider();
    let algorithms = provider.signature_verification_algorithms.all;
    let now = UnixTime::now();
    if kind % 4 == 1 {
        let hashers = CertIdHashers {
            sha1: digests.sha1,
            sha256: Some(digests.sha256),
        };
        let policy = OcspPolicy::stapled(algorithms, hashers, now);
        let _ = verify_response(bytes, &leaf, &OcspIssuer::from_cert(&issuer), &policy);
    } else if kind % 4 == 2 {
        let spki = issuer.subject_public_key_info();
        let logs = [CtLog::new(spki.as_ref(), digests.sha256).unwrap()];
        let policy = CtPolicy {
            logs: &logs,
            supported_sig_algs: algorithms,
            sha256: digests.sha256,
            options: SctOptions::default(),
        };
        let mut verifier = SctVerifier::new(&policy, &leaf, Some(spki.as_ref()), now).unwrap();
        let _ = verifier.verify_embedded();
        let _ = verifier.verify_tls_extension(bytes);
        let _ = verifier.verify_ocsp_extension(bytes);
    } else {
        handshake::run(identity, bytes);
    }
}

pub fn seeds() -> Vec<Vec<u8>> {
    vec![
        [&[0], CLUBCARD_V3].concat(),
        [&[0], CLUBCARD_V4].concat(),
        vec![1, 0x30, 3, 0x0a, 1, 3],
        vec![2, 0, 3, 0, 1, 0],
        vec![3, 1, 2, 3, 4],
        vec![3, 0, 4],
    ]
}
