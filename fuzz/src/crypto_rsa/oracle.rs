//! An independent RSA reference for the `crypto_rsa` target: raw RSA with
//! `num-bigint`, EMSA-PKCS1-v1_5 and EMSA-PSS (RFC 8017 §9) written from the
//! specification, and the RustCrypto hashes.

use browntls_crypto::hash::HashAlgorithm;
use num_bigint::BigUint;

/// Every hash `browntls_crypto` signs with.
pub const HASHES: [HashAlgorithm; 7] = [
    HashAlgorithm::Sha224,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha3_256,
    HashAlgorithm::Sha3_384,
    HashAlgorithm::Sha3_512,
];

/// The digest of the concatenation of `parts`, computed by RustCrypto.
pub fn digest(hash: HashAlgorithm, parts: &[&[u8]]) -> Vec<u8> {
    fn run<D: sha2::Digest>(parts: &[&[u8]]) -> Vec<u8> {
        let mut h = D::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().to_vec()
    }
    match hash {
        HashAlgorithm::Sha224 => run::<sha2::Sha224>(parts),
        HashAlgorithm::Sha256 => run::<sha2::Sha256>(parts),
        HashAlgorithm::Sha384 => run::<sha2::Sha384>(parts),
        HashAlgorithm::Sha512 => run::<sha2::Sha512>(parts),
        HashAlgorithm::Sha3_256 => run::<sha3::Sha3_256>(parts),
        HashAlgorithm::Sha3_384 => run::<sha3::Sha3_384>(parts),
        HashAlgorithm::Sha3_512 => run::<sha3::Sha3_512>(parts),
        other => panic!("no reference for {other:?}"),
    }
}

/// The last arc of the hash's OBJECT IDENTIFIER under
/// `2.16.840.1.101.3.4.2` (NIST hashAlgs).
fn hash_arc(hash: HashAlgorithm) -> u8 {
    match hash {
        HashAlgorithm::Sha256 => 1,
        HashAlgorithm::Sha384 => 2,
        HashAlgorithm::Sha512 => 3,
        HashAlgorithm::Sha224 => 4,
        HashAlgorithm::Sha3_256 => 8,
        HashAlgorithm::Sha3_384 => 9,
        HashAlgorithm::Sha3_512 => 10,
        other => panic!("no OID for {other:?}"),
    }
}

/// `DigestInfo` for `hash` and `digest`; with `null_params` false the
/// AlgorithmIdentifier omits its NULL (a variant lenient verifiers accept).
pub fn digest_info(hash: HashAlgorithm, digest: &[u8], null_params: bool) -> Vec<u8> {
    let oid = [
        0x60,
        0x86,
        0x48,
        0x01,
        0x65,
        0x03,
        0x04,
        0x02,
        hash_arc(hash),
    ];
    let mut alg = vec![0x06, 9];
    alg.extend_from_slice(&oid);
    if null_params {
        alg.extend_from_slice(&[0x05, 0x00]);
    }
    let mut body = vec![0x30, alg.len() as u8];
    body.extend_from_slice(&alg);
    body.extend_from_slice(&[0x04, digest.len() as u8]);
    body.extend_from_slice(digest);
    let mut out = vec![0x30, body.len() as u8];
    out.extend_from_slice(&body);
    out
}

/// EMSA-PKCS1-v1_5 of `t` (a DigestInfo) into `k` bytes, or `None` when
/// `k < tLen + 11`.
pub fn pkcs1_em(t: &[u8], k: usize) -> Option<Vec<u8>> {
    if k < t.len() + 11 {
        return None;
    }
    let mut em = vec![0x00, 0x01];
    em.resize(k - t.len() - 1, 0xff);
    em.push(0x00);
    em.extend_from_slice(t);
    Some(em)
}

/// MGF1 with `hash` (RFC 8017 B.2.1).
fn mgf1(hash: HashAlgorithm, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut counter = 0u32;
    while out.len() < len {
        out.extend_from_slice(&digest(hash, &[seed, &counter.to_be_bytes()]));
        counter += 1;
    }
    out.truncate(len);
    out
}

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with an arbitrary salt, or `None` when
/// the encoded message is too short for it.
pub fn pss_encode(hash: HashAlgorithm, msg: &[u8], salt: &[u8], em_bits: usize) -> Option<Vec<u8>> {
    let h_len = hash.output_len();
    let em_len = em_bits.div_ceil(8);
    if em_len < h_len + salt.len() + 2 {
        return None;
    }
    let m_hash = digest(hash, &[msg]);
    let h = digest(hash, &[&[0u8; 8], &m_hash, salt]);
    let db_len = em_len - h_len - 1;
    let mut db = vec![0u8; db_len - salt.len() - 1];
    db.push(0x01);
    db.extend_from_slice(salt);
    for (d, m) in db.iter_mut().zip(mgf1(hash, &h, db_len)) {
        *d ^= m;
    }
    db[0] &= 0xff >> (8 * em_len - em_bits);
    db.extend_from_slice(&h);
    db.push(0xbc);
    Some(db)
}

/// EMSA-PSS-VERIFY (RFC 8017 §9.1.2) with `sLen = hLen`; returns the salt.
pub fn pss_verify(hash: HashAlgorithm, msg: &[u8], em: &[u8], em_bits: usize) -> Option<Vec<u8>> {
    let h_len = hash.output_len();
    let s_len = h_len;
    let em_len = em.len();
    if em_len != em_bits.div_ceil(8) || em_len < h_len + s_len + 2 || em[em_len - 1] != 0xbc {
        return None;
    }
    let unused = 8 * em_len - em_bits;
    let (masked_db, rest) = em.split_at(em_len - h_len - 1);
    let h = &rest[..h_len];
    if masked_db[0] & !(0xffu8 >> unused) != 0 {
        return None;
    }
    let mut db: Vec<u8> = masked_db
        .iter()
        .zip(mgf1(hash, h, masked_db.len()))
        .map(|(a, b)| a ^ b)
        .collect();
    db[0] &= 0xff >> unused;
    let ps_len = em_len - h_len - s_len - 2;
    if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
        return None;
    }
    let salt = db[ps_len + 1..].to_vec();
    let m_hash = digest(hash, &[msg]);
    (digest(hash, &[&[0u8; 8], &m_hash, &salt]) == h).then_some(salt)
}

/// `x` as exactly `k` big-endian bytes (`x < 256^k`).
pub fn to_fixed(x: &BigUint, k: usize) -> Vec<u8> {
    let bytes = x.to_bytes_be();
    let mut out = vec![0u8; k.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes);
    out
}

/// An RSA public key for the reference.
#[derive(Clone, Debug)]
pub struct Public {
    pub n: BigUint,
    pub e: BigUint,
    /// Modulus length in bytes.
    pub k: usize,
    /// Modulus length in bits.
    pub bits: usize,
}

impl Public {
    pub fn new(n_be: &[u8], e_be: &[u8]) -> Self {
        let n = BigUint::from_bytes_be(n_be);
        let bits = usize::try_from(n.bits()).expect("bits");
        Self {
            k: bits.div_ceil(8),
            bits,
            n,
            e: BigUint::from_bytes_be(e_be),
        }
    }

    /// RSAVP1 with the RFC 8017 length and range checks.
    pub fn open(&self, sig: &[u8]) -> Option<Vec<u8>> {
        if sig.len() != self.k {
            return None;
        }
        let s = BigUint::from_bytes_be(sig);
        (s < self.n).then(|| to_fixed(&s.modpow(&self.e, &self.n), self.k))
    }

    /// RSASSA-PKCS1-v1_5-VERIFY.
    pub fn verify_pkcs1v15(&self, hash: HashAlgorithm, msg: &[u8], sig: &[u8]) -> bool {
        self.open(sig)
            .is_some_and(|em| self.pkcs1v15_matches(hash, msg, &em))
    }

    /// The EMSA-PKCS1-v1_5 comparison on an opened signature `em`.
    pub fn pkcs1v15_matches(&self, hash: HashAlgorithm, msg: &[u8], em: &[u8]) -> bool {
        let t = digest_info(hash, &digest(hash, &[msg]), true);
        pkcs1_em(&t, self.k).is_some_and(|expected| em == expected)
    }

    /// RSASSA-PSS-VERIFY with `sLen = hLen`; returns the salt.
    pub fn verify_pss(&self, hash: HashAlgorithm, msg: &[u8], sig: &[u8]) -> Option<Vec<u8>> {
        self.pss_salt(hash, msg, &self.open(sig)?)
    }

    /// EMSA-PSS-VERIFY on an opened signature `em` (of `k` bytes).
    pub fn pss_salt(&self, hash: HashAlgorithm, msg: &[u8], em: &[u8]) -> Option<Vec<u8>> {
        let em_bits = self.bits - 1;
        let skip = self.k - em_bits.div_ceil(8);
        if em[..skip].iter().any(|&b| b != 0) {
            return None;
        }
        pss_verify(hash, msg, &em[skip..], em_bits)
    }
}

/// An RSA private key for the reference (CRT form).
#[derive(Clone, Debug)]
pub struct Private {
    pub public: Public,
    pub p: BigUint,
    pub q: BigUint,
    pub dp: BigUint,
    pub dq: BigUint,
    pub qinv: BigUint,
}

impl Private {
    /// RSASP1 of the `k`-byte `em` (which must be below `n`).
    pub fn sign_raw(&self, em: &[u8]) -> Option<Vec<u8>> {
        let m = BigUint::from_bytes_be(em);
        if m >= self.public.n {
            return None;
        }
        let m1 = m.modpow(&self.dp, &self.p);
        let m2 = m.modpow(&self.dq, &self.q);
        let h = (&self.qinv * ((&m1 + &self.p) - (&m2 % &self.p))) % &self.p;
        Some(to_fixed(&(m2 + h * &self.q), self.public.k))
    }
}
