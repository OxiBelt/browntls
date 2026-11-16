//! Provider internals: cipher suites, hashes, HMAC, HKDF, the TLS 1.2 PRF,
//! key exchange and record protection, for both providers.

use browntls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, Iv, KeyBlockShape, NONCE_LEN, Nonce, OutboundChunks,
    OutboundPlainMessage, Tls12MacOrder, Tls12RecordProtection, make_tls12_aad, make_tls13_aad,
};
use browntls::crypto::hash::{self, HashAlgorithm};
use browntls::crypto::{
    CryptoProvider, SharedSecret, SupportedKxGroup, hmac, native, rustcrypto, tls13,
};
use browntls::{
    CipherSuite, ConnectionTrafficSecrets, ContentType, NamedGroup, ProtocolVersion,
    SignatureAlgorithm, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite, Tls13CipherSuite,
    version,
};
use browntls_crypto::accel::{self, Acceleration, Policy};
use hmac_oracle::{KeyInit as _, Mac as _};
use sha2::Digest as _;

use super::{KNOWN_SCHEMES, provider_name};
use crate::input::Input;

// The oracle crates under names that do not clash with `browntls::crypto::hmac`.
mod hmac_oracle {
    pub(super) use ::hmac::{Hmac, KeyInit, Mac};
}

/// Every cipher suite of provider `p` (0 native, 1 rustcrypto).
pub(super) fn suites(p: usize) -> &'static [SupportedCipherSuite] {
    if p == 0 {
        native::ALL_CIPHER_SUITES
    } else {
        rustcrypto::ALL_CIPHER_SUITES
    }
}

/// Every key exchange group of provider `p`.
pub(super) fn kx_groups(p: usize) -> &'static [&'static dyn SupportedKxGroup] {
    if p == 0 {
        native::ALL_KX_GROUPS
    } else {
        rustcrypto::ALL_KX_GROUPS
    }
}

fn tls13_suites(p: usize) -> Vec<&'static Tls13CipherSuite> {
    suites(p).iter().filter_map(|s| s.tls13()).collect()
}

fn tls12_suites(p: usize) -> Vec<&'static Tls12CipherSuite> {
    suites(p)
        .iter()
        .filter_map(|s| match s {
            SupportedCipherSuite::Tls12(t) => Some(*t),
            SupportedCipherSuite::Tls13(_) => None,
        })
        .collect()
}

/// The suite with the same identifier in the other provider.
fn counterpart(p: usize, suite: CipherSuite) -> Option<SupportedCipherSuite> {
    suites(1 - p).iter().copied().find(|s| s.suite() == suite)
}

/// SHA-2 through the RustCrypto oracle.
fn oracle_hash(alg: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlgorithm::SHA256 => sha2::Sha256::digest(data).to_vec(),
        HashAlgorithm::SHA384 => sha2::Sha384::digest(data).to_vec(),
        HashAlgorithm::SHA512 => sha2::Sha512::digest(data).to_vec(),
        other => panic!("unexpected suite hash {other:?}"),
    }
}

/// HMAC through the RustCrypto oracle.
pub(super) fn oracle_hmac(alg: HashAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
    macro_rules! mac {
        ($h:ty) => {{
            let mut m = hmac_oracle::Hmac::<$h>::new_from_slice(key).expect("any key length");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }};
    }
    match alg {
        HashAlgorithm::SHA256 => mac!(sha2::Sha256),
        HashAlgorithm::SHA384 => mac!(sha2::Sha384),
        HashAlgorithm::SHA512 => mac!(sha2::Sha512),
        other => panic!("unexpected HMAC hash {other:?}"),
    }
}

/// HKDF-Extract then HKDF-Expand through the RustCrypto oracle; `None` when
/// `len` is too long.
fn oracle_hkdf(
    alg: HashAlgorithm,
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    len: usize,
) -> Option<Vec<u8>> {
    let mut out = vec![0u8; len];
    let ok = match alg {
        HashAlgorithm::SHA256 => hkdf::Hkdf::<sha2::Sha256>::new(salt, ikm)
            .expand(info, &mut out)
            .is_ok(),
        HashAlgorithm::SHA384 => hkdf::Hkdf::<sha2::Sha384>::new(salt, ikm)
            .expand(info, &mut out)
            .is_ok(),
        other => panic!("unexpected HKDF hash {other:?}"),
    };
    ok.then_some(out)
}

/// HKDF-Expand from a pseudorandom key through the oracle.
fn oracle_expand(alg: HashAlgorithm, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    match alg {
        HashAlgorithm::SHA256 => hkdf::Hkdf::<sha2::Sha256>::from_prk(prk)
            .expect("PRK length")
            .expand(info, &mut out)
            .expect("expand length"),
        HashAlgorithm::SHA384 => hkdf::Hkdf::<sha2::Sha384>::from_prk(prk)
            .expect("PRK length")
            .expand(info, &mut out)
            .expect("expand length"),
        other => panic!("unexpected HKDF hash {other:?}"),
    }
    out
}

/// P_hash of RFC 5246 §5 with the oracle HMAC.
fn oracle_prf(alg: HashAlgorithm, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let label_seed = [label, seed].concat();
    let mut a = oracle_hmac(alg, secret, &label_seed);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        out.extend_from_slice(&oracle_hmac(alg, secret, &[&a[..], &label_seed].concat()));
        a = oracle_hmac(alg, secret, &a);
    }
    out.truncate(len);
    out
}

/// Up to three short fields, as HKDF `info` / HMAC message pieces.
fn pieces<'a>(input: &mut Input<'a>) -> Vec<&'a [u8]> {
    let n = input.choose(4);
    (0..n).map(|_| input.short_field()).collect()
}

/// A list of offered signature schemes: known ones and raw code points.
pub(super) fn offered_schemes(input: &mut Input<'_>) -> Vec<SignatureScheme> {
    let n = input.choose(8);
    (0..n)
        .map(|_| {
            let b = input.byte();
            if b & 0x80 == 0 {
                KNOWN_SCHEMES[usize::from(b) % KNOWN_SCHEMES.len()]
            } else {
                SignatureScheme::from(input.u16())
            }
        })
        .collect()
}

// ------------------------------------------------------------------ suites

/// Cipher suite metadata and the relations between its accessors.
pub(super) fn suite_props(input: &mut Input<'_>) {
    let p = input.choose(2);
    let suite = *input.pick(suites(p));
    let id = suite.suite();
    assert_eq!(CipherSuite::from(u16::from(id)), id);
    let sig_alg = SignatureAlgorithm::from(input.byte());
    match suite {
        SupportedCipherSuite::Tls13(t) => {
            assert!(core::ptr::eq(suite.tls13().expect("TLS 1.3 suite"), t));
            assert_eq!(suite.version().version, ProtocolVersion::TLSv1_3);
            assert!(suite.usable_for_signature_algorithm(sig_alg));
            assert!(!suite.is_tls12_block_cipher());
            if suite.fips() {
                assert!(t.fips() && t.common.fips());
            }
            assert_eq!(suite.fips(), t.fips());
            // Resumption needs the same hash, whichever provider.
            let candidates = tls13_suites(input.choose(2));
            let prev = *input.pick(&candidates);
            let same_hash =
                t.common.hash_provider.algorithm() == prev.common.hash_provider.algorithm();
            match t.can_resume_from(prev) {
                Some(r) => {
                    assert!(same_hash);
                    assert!(core::ptr::eq(r, prev));
                }
                None => assert!(!same_hash),
            }
        }
        SupportedCipherSuite::Tls12(t) => {
            assert!(suite.tls13().is_none());
            assert_eq!(suite.version().version, ProtocolVersion::TLSv1_2);
            let offered = offered_schemes(input);
            let resolved = t.resolve_sig_schemes(&offered);
            let expected: Vec<SignatureScheme> = t
                .sign
                .iter()
                .copied()
                .filter(|s| offered.contains(s))
                .collect();
            assert_eq!(resolved, expected);
            assert_eq!(
                suite.usable_for_signature_algorithm(sig_alg),
                t.sign.iter().any(|s| scheme_algorithm(*s) == Some(sig_alg))
            );
            assert_eq!(suite.is_tls12_block_cipher(), t.record.is_block_cipher());
            if suite.is_tls12_block_cipher() {
                // CBC suites are ordered after every AEAD suite.
                assert!(id.is_non_preferred());
            }
            let shape = t.record.key_block_shape();
            assert_eq!(shape.total_len(), shape_len(&shape));
            let parts = [t.common.fips(), t.prf_provider.fips(), t.record.fips()];
            assert_eq!(t.fips(), parts.iter().all(|f| *f));
            assert_eq!(suite.fips(), t.fips());
        }
    }
}

/// The signature algorithm of a scheme (`SignatureScheme::algorithm` is
/// crate-private).
pub(super) fn scheme_algorithm(scheme: SignatureScheme) -> Option<SignatureAlgorithm> {
    use SignatureScheme as S;
    match scheme {
        S::RSA_PKCS1_SHA1
        | S::RSA_PKCS1_SHA256
        | S::RSA_PKCS1_SHA384
        | S::RSA_PKCS1_SHA512
        | S::RSA_PSS_SHA256
        | S::RSA_PSS_SHA384
        | S::RSA_PSS_SHA512
        | S::RSA_PSS_PSS_SHA256
        | S::RSA_PSS_PSS_SHA384
        | S::RSA_PSS_PSS_SHA512 => Some(SignatureAlgorithm::RSA),
        S::ECDSA_SHA1_Legacy
        | S::ECDSA_NISTP256_SHA256
        | S::ECDSA_NISTP384_SHA384
        | S::ECDSA_NISTP521_SHA512 => Some(SignatureAlgorithm::ECDSA),
        S::ED25519 => Some(SignatureAlgorithm::ED25519),
        S::ED448 => Some(SignatureAlgorithm::ED448),
        _ => None,
    }
}

fn shape_len(shape: &KeyBlockShape) -> usize {
    2 * (shape.mac_key_len + shape.enc_key_len + shape.fixed_iv_len + shape.explicit_nonce_len)
}

// ----------------------------------------------------- hashes, HMAC, HKDF

fn suite_hash(suite: SupportedCipherSuite) -> &'static dyn hash::Hash {
    match suite {
        SupportedCipherSuite::Tls12(t) => t.common.hash_provider,
        SupportedCipherSuite::Tls13(t) => t.common.hash_provider,
    }
}

/// A suite's hash: one-shot against incremental with fuzzed chunking,
/// forks, and the oracle.
pub(super) fn hash_op(input: &mut Input<'_>) {
    let p = input.choose(2);
    let suite = *input.pick(suites(p));
    let h = suite_hash(suite);
    let data = input.field();
    let data = &data[..data.len().min(4096)];
    let one_shot = h.hash(data);
    assert_eq!(one_shot.as_ref().len(), h.output_len());
    assert_eq!(one_shot.as_ref(), oracle_hash(h.algorithm(), data));
    let _ = h.fips();

    let mut ctx = h.start();
    let mut fed = 0;
    while fed < data.len() {
        let step = (usize::from(input.byte()) + 1).min(data.len() - fed);
        ctx.update(&data[fed..fed + step]);
        fed += step;
        if input.bool() {
            // A fork sees the prefix so far and is independent afterwards.
            assert_eq!(
                ctx.fork_finish().as_ref(),
                oracle_hash(h.algorithm(), &data[..fed])
            );
            let mut fork = ctx.fork();
            fork.update(b"diverge");
            let _ = fork.finish();
        }
    }
    assert_eq!(ctx.finish().as_ref(), one_shot.as_ref());

    let raw = input.short_field();
    let out = hash::Output::new(raw);
    assert_eq!(out.as_ref(), &raw[..raw.len().min(hash::Output::MAX_LEN)]);
}

/// The native HMACs against the oracle, through `sign` and `sign_concat`.
pub(super) fn hmac_op(input: &mut Input<'_>) {
    let (h, alg) = *input.pick(&[
        (native::hmac::HMAC_SHA256, HashAlgorithm::SHA256),
        (native::hmac::HMAC_SHA384, HashAlgorithm::SHA384),
        (native::hmac::HMAC_SHA512, HashAlgorithm::SHA512),
    ]);
    let key_bytes = input.field();
    let key_bytes = &key_bytes[..key_bytes.len().min(300)];
    let parts = pieces(input);
    let key = h.with_key(key_bytes);
    assert_eq!(key.tag_len(), h.hash_output_len());
    let _ = h.fips();
    let expected = oracle_hmac(alg, key_bytes, &parts.concat());
    assert_eq!(key.sign(&parts).as_ref(), expected);
    let (first, rest) = parts
        .split_first()
        .map_or((&[][..], &[][..]), |(f, r)| (*f, r));
    let (last, middle) = rest
        .split_last()
        .map_or((&[][..], &[][..]), |(l, m)| (*l, m));
    assert_eq!(key.sign_concat(first, middle, last).as_ref(), expected);

    let tag = hmac::Tag::new(input.short_field());
    assert!(tag.as_ref().len() <= hmac::Tag::MAX_LEN);
}

/// A TLS 1.3 suite's HKDF against the oracle.
pub(super) fn hkdf_op(input: &mut Input<'_>) {
    let p = input.choose(2);
    let candidates = tls13_suites(p);
    let suite = *input.pick(&candidates);
    let hk = suite.hkdf_provider;
    let alg = suite.common.hash_provider.algorithm();
    let hash_len = suite.common.hash_provider.output_len();
    let salt = if input.bool() {
        Some(input.short_field())
    } else {
        None
    };
    let ikm = input.short_field();
    let info = pieces(input);
    let info_cat = info.concat();
    let len = usize::from(input.u16()) % (255 * hash_len + 32);

    let expander = hk.extract_from_secret(salt, ikm);
    assert_eq!(expander.hash_len(), hash_len);
    let mut out = vec![0u8; len];
    let result = expander.expand_slice(&info, &mut out);
    match oracle_hkdf(alg, salt, ikm, &info_cat, len) {
        Some(expected) => {
            assert!(result.is_ok());
            assert_eq!(out, expected);
        }
        None => assert!(result.is_err()),
    }
    let block = expander.expand_block(&info);
    let first = oracle_hkdf(alg, salt, ikm, &info_cat, hash_len).expect("one block");
    assert_eq!(block.as_ref(), first);
    let iv: Iv = tls13::expand::<Iv, NONCE_LEN>(&*expander, &info);
    assert_eq!(iv.as_ref(), &first[..NONCE_LEN.min(hash_len)]);
    let key: AeadKey = tls13::expand::<AeadKey, 32>(&*expander, &info);
    assert_eq!(key.as_ref(), &first[..32]);

    // A zero IKM of hash length.
    let zeros = vec![0u8; hash_len];
    let a = hk.extract_from_zero_ikm(salt).expand_block(&info);
    let b = hk.extract_from_secret(salt, &zeros).expand_block(&info);
    assert_eq!(a.as_ref(), b.as_ref());

    // Expansion from an existing PRK, and HMAC with an OKM block as key.
    let prk = oracle_hmac(alg, salt.unwrap_or(&zeros), ikm);
    let okm = tls13::OkmBlock::new(&prk);
    assert_eq!(okm.as_ref(), prk);
    let from_prk = hk.expander_for_okm(&okm).expand_block(&info);
    assert_eq!(
        from_prk.as_ref(),
        oracle_expand(alg, &prk, &info_cat, hash_len)
    );
    assert_eq!(
        hk.hmac_sign(&okm, &info_cat).as_ref(),
        oracle_hmac(alg, &prk, &info_cat)
    );
    let _ = hk.fips();
}

/// A TLS 1.2 suite's PRF against the oracle, from a secret and from a key
/// exchange.
pub(super) fn prf_op(input: &mut Input<'_>) {
    let p = input.choose(2);
    let candidates = tls12_suites(p);
    let suite = *input.pick(&candidates);
    let alg = suite.common.hash_provider.algorithm();
    let prf = suite.prf_provider;
    let secret = input.short_field();
    let label = input.short_field();
    let seed = input.short_field();
    let len = usize::from(input.byte()) * 2;
    let mut out = vec![0u8; len];
    prf.for_secret(&mut out, secret, label, seed);
    assert_eq!(out, oracle_prf(alg, secret, label, seed, len));
    let _ = prf.fips();

    // From a key exchange: the PRF keyed with the shared secret.
    let groups: Vec<_> = kx_groups(p)
        .iter()
        .filter(|g| matches!(g.name(), NamedGroup::X25519 | NamedGroup::secp256r1))
        .collect();
    let group = *input.pick(&groups);
    let Ok(ours) = group.start() else { return };
    let Ok(theirs) = group.start_and_complete(ours.pub_key()) else {
        panic!("{:?} rejected its own share", group.name());
    };
    let mut master = [0u8; 48];
    prf.for_key_exchange(&mut master, ours, &theirs.pub_key, label, seed)
        .expect("valid peer share");
    assert_eq!(
        master[..],
        oracle_prf(alg, theirs.secret.secret_bytes(), label, seed, 48)[..]
    );
}

// ------------------------------------------------------------- key exchange

/// Groups cheap enough for one input (FFDHE above 3072 bits is not).
fn cheap(g: &&&'static dyn SupportedKxGroup) -> bool {
    !matches!(
        g.name(),
        NamedGroup::FFDHE4096 | NamedGroup::FFDHE6144 | NamedGroup::FFDHE8192
    )
}

fn find_group(p: usize, name: NamedGroup) -> Option<&'static dyn SupportedKxGroup> {
    kx_groups(p).iter().copied().find(|g| g.name() == name)
}

/// One side of a group in one provider against the other side in either
/// provider: both must derive the same secret; hybrids also through their
/// classical component.
pub(super) fn kx_op(input: &mut Input<'_>) {
    let p = input.choose(2);
    let groups: Vec<_> = kx_groups(p).iter().filter(cheap).collect();
    let group = **input.pick(&groups);
    let name = group.name();
    let q = input.choose(2);
    let peer = find_group(q, name).unwrap_or(group);
    let _ = (
        group.fips(),
        group.usable_for_version(ProtocolVersion::TLSv1_2),
    );

    let Ok(ours) = group.start() else { return };
    assert_eq!(ours.group(), name);
    let theirs = peer
        .start_and_complete(ours.pub_key())
        .unwrap_or_else(|e| panic!("{name:?}: peer rejected a genuine share: {e:?}"));
    assert_eq!(theirs.group, name);
    let tls12 = input.bool() && group.usable_for_version(ProtocolVersion::TLSv1_2);
    let expected = theirs.secret.secret_bytes();
    let secret = if tls12 {
        ours.complete_for_tls_version(&theirs.pub_key, &version::TLS12)
    } else {
        ours.complete_for_tls_version(&theirs.pub_key, &version::TLS13)
    }
    .unwrap_or_else(|e| panic!("{name:?}: genuine share rejected: {e:?}"));
    let dhe = name.key_exchange_algorithm() == browntls::crypto::KeyExchangeAlgorithm::DHE;
    if tls12 && dhe {
        // TLS 1.2 strips the leading zeros of a finite-field secret.
        let zeros = expected.iter().take_while(|b| **b == 0).count();
        assert_eq!(secret.secret_bytes(), &expected[zeros..]);
    } else {
        assert_eq!(secret.secret_bytes(), expected);
    }

    // A hybrid's classical component on its own.
    let Ok(second) = group.start() else { return };
    match second.hybrid_component() {
        Some((component, share)) => {
            let classical = find_group(p, component).expect("component group");
            let peer = classical
                .start_and_complete(share)
                .expect("component share accepted");
            let s = second
                .complete_hybrid_component(&peer.pub_key)
                .expect("component completes");
            assert_eq!(s.secret_bytes(), peer.secret.secret_bytes());
        }
        None => assert!(second.complete_hybrid_component(&theirs.pub_key).is_err()),
    }

    // A fuzzed peer share must be an error or some secret, never a panic.
    let Ok(third) = group.start() else { return };
    let fuzzed = input.field();
    let _ = third.complete(fuzzed);
    let _ = peer.start_and_complete(fuzzed);

    let raw = input.short_field();
    assert_eq!(SharedSecret::from(raw).secret_bytes(), raw);
    assert_eq!(SharedSecret::from(raw.to_vec()).secret_bytes(), raw);
}

// -------------------------------------------------------- record protection

const INNER_TYPES: [ContentType; 4] = [
    ContentType::Handshake,
    ContentType::Alert,
    ContentType::ApplicationData,
    ContentType::ChangeCipherSpec,
];

/// Runs `f` with every native algorithm restricted to portable code, then
/// restores the default policy.
fn portable<T>(f: impl FnOnce() -> T) -> T {
    let _ = accel::set_policy_all(Policy::NONE);
    let out = f();
    let _ = accel::set_policy_all(Policy::PREFERRED);
    out
}

fn traffic_key(secrets: &ConnectionTrafficSecrets) -> (&[u8], &[u8]) {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
        | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
        | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }
        | ConnectionTrafficSecrets::Aes128Ccm { key, iv } => (key.as_ref(), iv.as_ref()),
        _ => (&[], &[]),
    }
}

fn tls13_seal(
    suite: &Tls13CipherSuite,
    key: &[u8],
    iv: [u8; NONCE_LEN],
    typ: ContentType,
    chunks: &[&[u8]],
    seq: u64,
) -> Vec<u8> {
    let mut enc = suite.aead_alg.encrypter(AeadKey::new(key), Iv::new(iv));
    let len = chunks.iter().map(|c| c.len()).sum();
    let msg = OutboundPlainMessage {
        typ,
        version: ProtocolVersion::TLSv1_2,
        payload: OutboundChunks::new(chunks),
    };
    let out = enc.encrypt(msg, seq).expect("TLS 1.3 encryption");
    assert_eq!(out.typ, ContentType::ApplicationData);
    assert_eq!(out.payload.len(), enc.encrypted_payload_len(len));
    out.payload.as_ref().to_vec()
}

/// TLS 1.3 record protection: round trip, tampering, the other provider
/// and the portable backend.
pub(super) fn aead13_op(input: &mut Input<'_>) {
    let p = input.choose(2);
    let candidates = tls13_suites(p);
    let suite = *input.pick(&candidates);
    let key_len = suite.aead_alg.key_len();
    let key_bytes: [u8; 32] = input.array();
    let key = &key_bytes[..key_len];
    let iv: [u8; NONCE_LEN] = input.array();
    let typ = *input.pick(&INNER_TYPES);
    let seq = input.u64();
    let plain = input.field();
    let plain = &plain[..plain.len().min(2048)];
    let split = usize::from(input.u16()) % (plain.len() + 1);
    let (a, b) = plain.split_at(split);
    let chunks = [a, b];

    let sealed = tls13_seal(suite, key, iv, typ, &chunks, seq);
    assert_eq!(sealed, tls13_seal(suite, key, iv, typ, &[plain], seq));
    if p == 0 {
        assert_eq!(
            sealed,
            portable(|| tls13_seal(suite, key, iv, typ, &chunks, seq)),
            "{:?} portable backend",
            suite.common.suite
        );
    }
    if let Some(SupportedCipherSuite::Tls13(other)) = counterpart(p, suite.common.suite) {
        assert_eq!(
            sealed,
            tls13_seal(other, key, iv, typ, &chunks, seq),
            "{:?} between providers",
            suite.common.suite
        );
    }

    let open = |bytes: &mut [u8], seq: u64| {
        let mut dec = suite.aead_alg.decrypter(AeadKey::new(key), Iv::new(iv));
        let _ = dec.integrity_limit_reached();
        dec.decrypt(
            InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                bytes,
            ),
            seq,
        )
        .map(|m| (m.typ, m.payload.to_vec()))
    };
    // An empty record must carry application data (RFC 8446 §5.4).
    let legal = !plain.is_empty() || typ == ContentType::ApplicationData;
    let mut buf = sealed.clone();
    match open(&mut buf, seq) {
        Ok((got_typ, got)) => {
            assert!(legal, "empty {typ:?} record accepted");
            assert_eq!(got_typ, typ);
            assert_eq!(got, plain);
        }
        Err(e) => assert!(!legal, "genuine record: {e:?}"),
    }

    // Any flipped bit, another sequence number, a truncation: rejected.
    let mut buf = sealed.clone();
    let at = usize::from(input.u16()) % buf.len();
    buf[at] ^= 1 << input.choose(8);
    assert!(open(&mut buf, seq).is_err());
    let mut buf = sealed.clone();
    assert!(open(&mut buf, seq ^ (1 << input.choose(64))).is_err());
    let mut buf = sealed[..at].to_vec();
    assert!(open(&mut buf, seq).is_err());

    if let Ok(secrets) = suite.aead_alg.extract_keys(AeadKey::new(key), Iv::new(iv)) {
        let (k, v) = traffic_key(&secrets);
        assert_eq!((k, v), (key, &iv[..]));
    }
    let _ = suite.aead_alg.fips();
}

fn tls12_seal(
    suite: &Tls12CipherSuite,
    keys: (&[u8], &[u8], &[u8]),
    order: Tls12MacOrder,
    typ: ContentType,
    plain: &[u8],
    seq: u64,
) -> Vec<u8> {
    let (key, iv, extra) = keys;
    let mut enc = match suite.record {
        Tls12RecordProtection::Aead(alg) => alg.encrypter(AeadKey::new(key), iv, extra),
        Tls12RecordProtection::BlockCipher(alg) => alg.encrypter(extra, AeadKey::new(key), order),
    };
    let msg = OutboundPlainMessage {
        typ,
        version: ProtocolVersion::TLSv1_2,
        payload: OutboundChunks::Single(plain),
    };
    let out = enc.encrypt(msg, seq).expect("TLS 1.2 encryption");
    assert_eq!(out.typ, typ);
    // CBC pads to the block size, so the prediction is an upper bound there.
    if suite.record.is_block_cipher() {
        assert!(out.payload.len() <= enc.encrypted_payload_len(plain.len()));
    } else {
        assert_eq!(out.payload.len(), enc.encrypted_payload_len(plain.len()));
    }
    out.payload.as_ref().to_vec()
}

/// TLS 1.2 record protection (AEAD and CBC): round trip, tampering, the
/// other provider's AEAD.
pub(super) fn aead12_op(input: &mut Input<'_>) {
    let p = input.choose(2);
    let candidates = tls12_suites(p);
    let suite = *input.pick(&candidates);
    let shape = suite.record.key_block_shape();
    let block: [u8; 128] = input.array();
    let key = &block[..shape.enc_key_len];
    let iv = &block[32..32 + shape.fixed_iv_len];
    // For AEAD the explicit nonce seed, for CBC the MAC key.
    let extra_len = if suite.record.is_block_cipher() {
        shape.mac_key_len
    } else {
        shape.explicit_nonce_len
    };
    let extra = &block[64..64 + extra_len];
    let order = if input.bool() {
        Tls12MacOrder::EncryptThenMac
    } else {
        Tls12MacOrder::MacThenEncrypt
    };
    let typ = *input.pick(&INNER_TYPES);
    let seq = input.u64();
    let plain = input.field();
    let plain = &plain[..plain.len().min(2048)];

    let sealed = tls12_seal(suite, (key, iv, extra), order, typ, plain, seq);
    if !suite.record.is_block_cipher()
        && let Some(SupportedCipherSuite::Tls12(other)) = counterpart(p, suite.common.suite)
    {
        assert_eq!(
            sealed,
            tls12_seal(other, (key, iv, extra), order, typ, plain, seq),
            "{:?} between providers",
            suite.common.suite
        );
    }
    let open = |bytes: &mut [u8], seq: u64| {
        let mut dec = match suite.record {
            Tls12RecordProtection::Aead(alg) => alg.decrypter(AeadKey::new(key), iv),
            Tls12RecordProtection::BlockCipher(alg) => {
                alg.decrypter(extra, AeadKey::new(key), order)
            }
        };
        dec.decrypt(
            InboundOpaqueMessage::new(typ, ProtocolVersion::TLSv1_2, bytes),
            seq,
        )
        .map(|m| m.payload.to_vec())
    };
    let mut buf = sealed.clone();
    assert_eq!(open(&mut buf, seq).expect("genuine record"), plain);
    let mut buf = sealed.clone();
    let at = usize::from(input.u16()) % buf.len();
    buf[at] ^= 1 << input.choose(8);
    assert!(
        open(&mut buf, seq).is_err(),
        "{:?} tampered",
        suite.common.suite
    );
    let mut buf = sealed.clone();
    assert!(open(&mut buf, seq ^ (1 << input.choose(64))).is_err());

    if let Tls12RecordProtection::Aead(alg) = suite.record
        && let Ok(secrets) = alg.extract_keys(AeadKey::new(key), iv, extra)
    {
        let (k, v) = traffic_key(&secrets);
        assert_eq!(k, key);
        assert_eq!(&v[..iv.len()], iv);
    }
}

// ------------------------------------------------------------ small helpers

/// The value types of `crypto::cipher` and friends.
pub(super) fn helpers(input: &mut Input<'_>) {
    let len = usize::from(input.u16());
    let aad = make_tls13_aad(len);
    assert_eq!(aad[..3], [0x17, 3, 3]);
    assert_eq!(aad[3..], (len as u16).to_be_bytes());

    let seq = input.u64();
    let typ = ContentType::from(input.byte());
    let vers = ProtocolVersion::from(input.u16());
    let aad = make_tls12_aad(seq, typ, vers, len);
    assert_eq!(aad[..8], seq.to_be_bytes());
    assert_eq!(aad[8], u8::from(typ));
    assert_eq!(aad[9..11], u16::from(vers).to_be_bytes());
    assert_eq!(aad[11..], (len as u16).to_be_bytes());

    let raw = input.short_field();
    let iv = Iv::copy(raw);
    let n = raw.len().min(NONCE_LEN);
    assert_eq!(&iv.as_ref()[..n], &raw[..n]);
    assert!(iv.as_ref()[n..].iter().all(|b| *b == 0));
    let nonce = Nonce::new(&iv, seq);
    for i in 0..NONCE_LEN {
        let s = if i < 4 { 0 } else { seq.to_be_bytes()[i - 4] };
        assert_eq!(nonce.0[i], iv.as_ref()[i] ^ s);
    }
    let iv2 = Iv::from(nonce.0);
    assert_eq!(Nonce::new(&iv2, 0).0, nonce.0);

    let key = AeadKey::new(raw);
    let used = raw.len().min(AeadKey::MAX_LEN);
    assert_eq!(key.as_ref(), &raw[..used]);
    let cut = input.choose(40);
    let key = key.with_length(cut);
    assert_eq!(key.as_ref(), &raw[..used.min(cut)]);
    let full: [u8; 32] = input.array();
    assert_eq!(AeadKey::from(full).as_ref(), full);

    let shape = KeyBlockShape {
        mac_key_len: input.choose(64),
        enc_key_len: input.choose(64),
        fixed_iv_len: input.choose(64),
        explicit_nonce_len: input.choose(64),
    };
    assert_eq!(shape.total_len(), shape_len(&shape));
    let okm = tls13::OkmBlock::new(raw);
    assert_eq!(
        okm.as_ref(),
        &raw[..raw.len().min(tls13::OkmBlock::MAX_LEN)]
    );
}

/// Providers: construction, acceleration policies, the process default,
/// FIPS reporting, randomness.
pub(super) fn provider_op(input: &mut Input<'_>) {
    let level = |b: u8| match b % 3 {
        0 => Acceleration::Required,
        1 => Acceleration::Preferred,
        _ => Acceleration::None,
    };
    let provider = match input.choose(3) {
        0 => native::default_provider(),
        1 => rustcrypto::default_provider(),
        _ => {
            let policy = Policy::new(level(input.byte()), level(input.byte()));
            let made = native::default_provider_with_acceleration(policy);
            let _ = accel::set_policy_all(Policy::PREFERRED);
            match made {
                Ok(p) => p,
                // A required level this machine cannot satisfy.
                Err(_) => return,
            }
        }
    };
    let name = provider_name(&provider);
    let algs = &provider.signature_verification_algorithms;
    let algs_fips = algs.fips();
    assert_eq!(
        algs_fips,
        algs.all.iter().all(|a| a.fips())
            && algs.mapping.iter().all(|(_, m)| m.iter().all(|a| a.fips()))
    );
    assert_eq!(
        provider.fips(),
        provider.cipher_suites.iter().all(|s| s.fips())
            && provider.kx_groups.iter().all(|g| g.fips())
            && algs_fips
            && provider.secure_random.fips()
            && provider.key_provider.fips(),
        "{name}"
    );
    let n = 16 + input.choose(48);
    let mut a = vec![0u8; n];
    let mut b = vec![0u8; n];
    provider.secure_random.fill(&mut a).expect("randomness");
    provider.secure_random.fill(&mut b).expect("randomness");
    // Two 128-bit or longer draws never coincide.
    assert_ne!(a, b, "{name}: repeated random output");

    // `crate::init` installed the native provider; a second install fails
    // and hands the provider back.
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    match provider.install_default() {
        Err(back) => assert_eq!(
            back.signature_verification_algorithms.supported_schemes(),
            schemes
        ),
        Ok(()) => panic!("a second default provider was installed"),
    }
    let default: &CryptoProvider = CryptoProvider::get_default().expect("installed");
    assert!(!default.cipher_suites.is_empty());
}
