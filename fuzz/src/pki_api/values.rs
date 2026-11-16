//! Values: `UnixTime`, `AlgorithmIdentifier` and the `id-RSASSA-PSS`
//! canonical forms, the DER and key containers, and their PEM decoding.

use core::time::Duration;

use browntls_pki::alg_id::{self, canonical_public_key_alg_id, canonical_signature_alg_id};
use browntls_pki::pem::{self, PemObject, SectionKind};
use browntls_pki::{
    AlgorithmIdentifier, CertificateDer, CertificateRevocationListDer,
    CertificateSigningRequestDer, Der, EchConfigListBytes, PrivateKeyDer, PrivatePkcs1KeyDer,
    PrivatePkcs8KeyDer, PrivateSec1KeyDer, SubjectPublicKeyInfoDer, UnixTime,
};

use super::der;
use crate::input::Input;

/// A time in seconds: fixed edge values or fuzzed, with fuzzed
/// nanoseconds.
fn time(input: &mut Input<'_>) -> (u64, Duration) {
    let secs = match input.choose(8) {
        0 => 0,
        1 => 1,
        2 => crate::tls_config::NOW.as_secs(),
        3 => u64::MAX,
        4 => u64::MAX - 1,
        _ => input.u64(),
    };
    let nanos = input.u32() % 1_000_000_000;
    (secs, Duration::new(secs, nanos))
}

/// `UnixTime` keeps the whole seconds and orders like them; `now` is the
/// system clock's.
pub(super) fn time_op(input: &mut Input<'_>) {
    let (a_secs, a) = time(input);
    let (b_secs, b) = time(input);
    let a = UnixTime::since_unix_epoch(a);
    let b = UnixTime::since_unix_epoch(b);
    assert_eq!(a.as_secs(), a_secs);
    assert_eq!(a.cmp(&b), a_secs.cmp(&b_secs));
    assert_eq!(a == b, a_secs == b_secs);

    let secs = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after 1970")
            .as_secs()
    };
    let before = secs();
    let now = UnixTime::now().as_secs();
    assert!(before <= now && now <= secs());
}

/// Every `AlgorithmIdentifier` constant.
pub(super) const ALG_IDS: &[AlgorithmIdentifier] = &[
    alg_id::ECDSA_P256,
    alg_id::ECDSA_P384,
    alg_id::ECDSA_P521,
    alg_id::ECDSA_SHA256,
    alg_id::ECDSA_SHA384,
    alg_id::ECDSA_SHA512,
    alg_id::RSA_ENCRYPTION,
    alg_id::RSA_PKCS1_SHA256,
    alg_id::RSA_PKCS1_SHA384,
    alg_id::RSA_PKCS1_SHA512,
    alg_id::RSA_PSS_SHA256,
    alg_id::RSA_PSS_SHA384,
    alg_id::RSA_PSS_SHA512,
    alg_id::RSASSA_PSS,
    alg_id::RSASSA_PSS_SHA256_KEY,
    alg_id::RSASSA_PSS_SHA384_KEY,
    alg_id::RSASSA_PSS_SHA512_KEY,
    alg_id::ED25519,
    alg_id::ED448,
    alg_id::ML_DSA_44,
    alg_id::ML_DSA_65,
    alg_id::ML_DSA_87,
];

/// The canonical public key and signature forms of a constant.
fn constant_forms(
    a: AlgorithmIdentifier,
) -> (Option<AlgorithmIdentifier>, Option<AlgorithmIdentifier>) {
    if a == alg_id::RSASSA_PSS {
        (Some(a), None)
    } else if [
        alg_id::RSA_PSS_SHA256,
        alg_id::RSA_PSS_SHA384,
        alg_id::RSA_PSS_SHA512,
    ]
    .contains(&a)
    {
        (Some(a), Some(a))
    } else {
        (None, None)
    }
}

/// Properties of the canonical forms of any input, and of matching against
/// every constant.
fn canonical_invariants(bytes: &[u8]) {
    let key = canonical_public_key_alg_id(bytes);
    let sig = canonical_signature_alg_id(bytes);
    if let Some(key) = key {
        assert!(bytes.starts_with(alg_id::RSASSA_PSS.as_bytes()));
        assert!(
            [
                alg_id::RSASSA_PSS,
                alg_id::RSASSA_PSS_SHA256_KEY,
                alg_id::RSASSA_PSS_SHA384_KEY,
                alg_id::RSASSA_PSS_SHA512_KEY
            ]
            .contains(&key)
        );
        assert_eq!(canonical_public_key_alg_id(key.as_bytes()), Some(key));
    }
    if let Some(sig) = sig {
        assert!(
            [
                alg_id::RSA_PSS_SHA256,
                alg_id::RSA_PSS_SHA384,
                alg_id::RSA_PSS_SHA512
            ]
            .contains(&sig)
        );
        assert_eq!(canonical_signature_alg_id(sig.as_bytes()), Some(sig));
        // Parameters fit for a signature restrict a key to the same hash,
        // whose canonical encoding is the signature's.
        assert_eq!(key, Some(sig));
    }
    for c in ALG_IDS {
        assert_eq!(
            c.matches_public_key(bytes),
            c.as_bytes() == bytes || key == Some(*c)
        );
        assert_eq!(
            c.matches_signature(bytes),
            c.as_bytes() == bytes || sig == Some(*c)
        );
    }
}

/// Two constants against each other, and fuzzed identifiers.
pub(super) fn alg_id_op(input: &mut Input<'_>) {
    let a = *input.pick(ALG_IDS);
    let b = *input.pick(ALG_IDS);
    let copy = AlgorithmIdentifier::from_slice(a.as_bytes());
    assert_eq!(copy, a);
    assert_eq!(&*copy, a.as_bytes());
    assert_eq!(copy.as_ref(), a.as_bytes());
    assert!(format!("{a:?}").starts_with("AlgorithmIdentifier("));

    let (key, sig) = constant_forms(b);
    assert_eq!(canonical_public_key_alg_id(b.as_bytes()), key);
    assert_eq!(canonical_signature_alg_id(b.as_bytes()), sig);
    assert_eq!(a.matches_public_key(b.as_bytes()), a == b || key == Some(a));
    assert_eq!(a.matches_signature(b.as_bytes()), a == b || sig == Some(a));
    canonical_invariants(b.as_bytes());

    let extra = input.short_field();
    if input.bool() {
        canonical_invariants(&[alg_id::RSASSA_PSS.as_bytes(), extra].concat());
    } else {
        canonical_invariants(extra);
    }
}

/// Hash choices in `RSASSA-PSS-params`: absent, SHA-1, SHA-224, SHA-256,
/// SHA-384, SHA-512, and an unrelated OID.
const HASH_OIDS: [&[u8]; 6] = [
    &[0x2b, 0x0e, 0x03, 0x02, 0x1a],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
    &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
    &[0x2a, 0x03],
];

/// `id-mgf1`.
const MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];

/// A hash `AlgorithmIdentifier` for choice `h` (1..=6), with or without
/// NULL parameters.
fn hash_alg(h: usize, null: bool) -> Vec<u8> {
    let mut v = der(0x06, HASH_OIDS[h - 1]);
    if null {
        v.extend([0x05, 0x00]);
    }
    der(0x30, &v)
}

/// A minimal DER `INTEGER` for a non-negative value.
fn integer(value: u16) -> Vec<u8> {
    let mut bytes: Vec<u8> = value
        .to_be_bytes()
        .into_iter()
        .skip_while(|&b| b == 0)
        .collect();
    if bytes.first().is_none_or(|b| b & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    der(0x02, &bytes)
}

/// `id-RSASSA-PSS` identifiers built field by field against a model of
/// their canonical forms, then corrupted.
pub(super) fn pss_op(input: &mut Input<'_>) {
    let present = input.bool();
    let hash = input.choose(7);
    let hash_null = input.bool();
    let mgf = input.choose(3);
    let mgf_hash = input.choose(7);
    let mgf_null = input.bool();
    let salt = input.bool().then(|| input.u16() % 300);
    let trailer = input.bool().then(|| u16::from(input.byte()));

    let mut params = Vec::new();
    if hash != 0 {
        params.extend(der(0xa0, &hash_alg(hash, hash_null)));
    }
    match mgf {
        0 => {}
        1 => {
            let mut v = der(0x06, MGF1);
            if mgf_hash != 0 {
                v.extend(hash_alg(mgf_hash, mgf_null));
            }
            params.extend(der(0xa1, &der(0x30, &v)));
        }
        _ => {
            let v = [der(0x06, &[0x2a, 0x03, 0x04]), vec![0x05, 0x00]].concat();
            params.extend(der(0xa1, &der(0x30, &v)));
        }
    }
    if let Some(salt) = salt {
        params.extend(der(0xa2, &integer(salt)));
    }
    if let Some(trailer) = trailer {
        params.extend(der(0xa3, &integer(trailer)));
    }
    let mut encoded = alg_id::RSASSA_PSS.as_bytes().to_vec();
    if present {
        encoded.extend(der(0x30, &params));
    }

    // The model: SHA-256/384/512 with MGF1 over the same hash, a trailer
    // field absent or 1, a salt absent (20) or explicit but not 20; a key
    // takes salts up to the digest length, a signature exactly that.
    let digest = match hash {
        3 => Some((32u16, alg_id::RSA_PSS_SHA256)),
        4 => Some((48, alg_id::RSA_PSS_SHA384)),
        5 => Some((64, alg_id::RSA_PSS_SHA512)),
        _ => None,
    };
    let (key, sig) = if !present {
        (Some(alg_id::RSASSA_PSS), None)
    } else {
        let supported = digest.filter(|_| {
            mgf == 1 && mgf_hash == hash && trailer.is_none_or(|t| t == 1) && salt != Some(20)
        });
        let salt = salt.unwrap_or(20);
        match supported {
            Some((len, id)) if salt <= 255 => {
                ((salt <= len).then_some(id), (salt == len).then_some(id))
            }
            _ => (None, None),
        }
    };
    assert_eq!(canonical_public_key_alg_id(&encoded), key, "{encoded:02x?}");
    assert_eq!(canonical_signature_alg_id(&encoded), sig, "{encoded:02x?}");
    canonical_invariants(&encoded);

    if input.bool() {
        let at = input.choose(encoded.len());
        encoded[at] ^= input.byte() | 1;
        canonical_invariants(&encoded);
    }
}

macro_rules! check_der_types {
    ($bytes:expr, $($ty:ident),*) => {$({
        let bytes: &[u8] = $bytes;
        let value = $ty::from_slice(bytes);
        assert_eq!(value.as_ref(), bytes);
        assert_eq!(&*value, bytes);
        let owned: $ty<'static> = value.clone().into_owned();
        assert_eq!(owned, value);
        assert_eq!($ty::from(bytes.to_vec()), value);
        assert_eq!($ty::from(bytes), value);
        assert_eq!($ty::from(Der::from_slice(bytes)), value);
        assert_eq!(
            format!("{value:?}"),
            format!("{}({:?})", stringify!($ty), Der::from_slice(bytes))
        );
    })*};
}

macro_rules! check_key_types {
    ($bytes:expr, $($ty:ident => $variant:ident),*) => {$({
        let bytes: &[u8] = $bytes;
        let key = $ty::from(bytes);
        assert_eq!(key.secret_der(), bytes);
        let copy = key.clone_key();
        assert_eq!(copy.secret_der(), bytes);
        assert_eq!(copy, key);
        assert_eq!($ty::from(bytes.to_vec()), key);
        assert_eq!(format!("{key:?}"), concat!(stringify!($ty), "(<redacted>)"));
        let any = PrivateKeyDer::from(key);
        assert_eq!(any.secret_der(), bytes);
        let copy = any.clone_key();
        assert_eq!(copy, any);
        assert!(matches!(copy, PrivateKeyDer::$variant(_)));
    })*};
}

/// Every container keeps its bytes through every conversion.
pub(super) fn types_op(input: &mut Input<'_>) {
    let bytes = input.field();
    let generic = Der::from_slice(bytes);
    assert_eq!(&*generic, bytes);
    assert_eq!(generic.clone().into_owned(), generic);
    assert_eq!(Der::from(bytes.to_vec()), generic);
    assert_eq!(Der::from(bytes).as_ref(), bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(format!("{generic:?}"), format!("0x{hex}"));

    check_der_types!(
        bytes,
        CertificateDer,
        SubjectPublicKeyInfoDer,
        CertificateRevocationListDer,
        CertificateSigningRequestDer,
        EchConfigListBytes
    );
    check_key_types!(
        bytes,
        PrivatePkcs1KeyDer => Pkcs1,
        PrivateSec1KeyDer => Sec1,
        PrivatePkcs8KeyDer => Pkcs8
    );
}

/// PEM labels and their kinds.
const LABELS: [(&str, SectionKind); 8] = [
    ("CERTIFICATE", SectionKind::Certificate),
    ("PUBLIC KEY", SectionKind::PublicKey),
    ("RSA PRIVATE KEY", SectionKind::RsaPrivateKey),
    ("PRIVATE KEY", SectionKind::PrivateKey),
    ("EC PRIVATE KEY", SectionKind::EcPrivateKey),
    ("X509 CRL", SectionKind::Crl),
    ("CERTIFICATE REQUEST", SectionKind::Csr),
    ("ECHCONFIG", SectionKind::EchConfigList),
];

/// Standard padded Base64 (RFC 4648 §4), independent of the library's.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.len();
        let v = chunk
            .iter()
            .chain(core::iter::repeat(&0))
            .take(3)
            .fold(0u32, |acc, &b| acc << 8 | u32::from(b));
        for i in 0..4 {
            if i <= n {
                out.push(char::from(ALPHABET[(v >> (18 - 6 * i) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `T::from_pem_slice` and `T::pem_slice_iter` for a PEM document holding
/// one section of `kind` with `bytes`, or failing with `error`.
fn check_pem_type<T: PemObject>(
    pem: &[u8],
    accepts: bool,
    error: Option<&pem::Error>,
    bytes: impl Fn(&T) -> Vec<u8>,
) -> Option<Vec<u8>> {
    let first = T::from_pem_slice(pem);
    let all: Vec<_> = T::pem_slice_iter(pem).collect();
    match (error, accepts) {
        (Some(e), _) => {
            assert_eq!(first.err().as_ref(), Some(e));
            assert!(all.iter().all(Result::is_err));
            None
        }
        (None, false) => {
            assert_eq!(first.err(), Some(pem::Error::NoItemsFound));
            assert!(all.is_empty());
            None
        }
        (None, true) => {
            let value = first.expect("the section");
            assert_eq!(all.len(), 1);
            Some(bytes(&value))
        }
    }
}

/// PEM written with an independent encoder decodes to the bytes, by kind;
/// broken labels, a missing end and bad Base64 fail.
pub(super) fn pem_op(input: &mut Input<'_>) {
    let (label, kind) = *input.pick(&LABELS);
    let wrap = *input.pick(&[64usize, 76, usize::MAX]);
    let damage = input.choose(5);
    let bytes = input.field();

    let body = base64(bytes);
    assert_eq!(pem::base64_decode(body.as_bytes()).as_deref(), Ok(bytes));
    let mut text = String::new();
    if damage == 1 {
        text.push_str("junk\n-----BEGIN UNKNOWN-----\nAA==\n-----END UNKNOWN-----\n");
    }
    text.push_str(&format!("-----BEGIN {label}-----\n"));
    let mut rest = body.as_str();
    while !rest.is_empty() {
        let (line, tail) = rest.split_at(wrap.min(rest.len()));
        text.push_str(line);
        text.push_str(if damage == 1 { "\r\n" } else { "\n" });
        rest = tail;
    }
    let error = match damage {
        2 => {
            let other = LABELS.iter().find(|(l, _)| *l != label).expect("labels").0;
            text.push_str(&format!("-----END {other}-----\n"));
            Some(pem::Error::LabelMismatch)
        }
        3 => Some(pem::Error::MissingEnd),
        4 => {
            text.push_str(&format!("!\n-----END {label}-----\n"));
            Some(pem::Error::Base64)
        }
        _ => {
            text.push_str(&format!("-----END {label}-----\ntrailing text\n"));
            None
        }
    };
    let pem = text.as_bytes();

    let sections: Vec<_> = pem::sections(pem).collect();
    match &error {
        None => assert_eq!(sections, [Ok((kind, bytes.to_vec()))]),
        Some(e) => assert_eq!(sections, [Err(e.clone())]),
    }

    let e = error.as_ref();
    let mut decoded = [
        check_pem_type::<CertificateDer<'static>>(pem, kind == SectionKind::Certificate, e, |v| {
            v.to_vec()
        }),
        check_pem_type::<SubjectPublicKeyInfoDer<'static>>(
            pem,
            kind == SectionKind::PublicKey,
            e,
            |v| v.to_vec(),
        ),
        check_pem_type::<CertificateRevocationListDer<'static>>(
            pem,
            kind == SectionKind::Crl,
            e,
            |v| v.to_vec(),
        ),
        check_pem_type::<CertificateSigningRequestDer<'static>>(
            pem,
            kind == SectionKind::Csr,
            e,
            |v| v.to_vec(),
        ),
        check_pem_type::<EchConfigListBytes<'static>>(
            pem,
            kind == SectionKind::EchConfigList,
            e,
            |v| v.to_vec(),
        ),
        check_pem_type::<PrivatePkcs1KeyDer<'static>>(
            pem,
            kind == SectionKind::RsaPrivateKey,
            e,
            |v| v.secret_der().to_vec(),
        ),
        check_pem_type::<PrivatePkcs8KeyDer<'static>>(
            pem,
            kind == SectionKind::PrivateKey,
            e,
            |v| v.secret_der().to_vec(),
        ),
        check_pem_type::<PrivateSec1KeyDer<'static>>(
            pem,
            kind == SectionKind::EcPrivateKey,
            e,
            |v| v.secret_der().to_vec(),
        ),
    ]
    .into_iter()
    .flatten();
    if error.is_none() {
        assert_eq!(decoded.next().as_deref(), Some(bytes));
    }
    assert!(decoded.next().is_none());

    let is_key = matches!(
        kind,
        SectionKind::RsaPrivateKey | SectionKind::PrivateKey | SectionKind::EcPrivateKey
    );
    let key = check_pem_type::<PrivateKeyDer<'static>>(pem, is_key, e, |v| v.secret_der().to_vec());
    if is_key && error.is_none() {
        assert_eq!(key.as_deref(), Some(bytes));
    }
}
