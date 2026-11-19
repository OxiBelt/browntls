//! The TLS 1.2 CBC record transform (`tls_cbc`) of the `crypto_cipher`
//! target, checked against records built independently with the RustCrypto
//! `cbc` and `hmac` crates.

use ::aes::cipher::KeyInit as _;
use browntls_crypto::Error;
use browntls_crypto::aes;
use browntls_crypto::cbc::AesCbcKey;
use browntls_crypto::tls_cbc::{
    IV_LEN, MAX_FRAGMENT_LEN, MAX_PLAINTEXT_LEN, MacAlgorithm, MacOrder, RecordKey,
};
use hmac::Mac as _;

use super::aes_block::cbc_ref;
use super::{aes_key, flip};
use crate::input::Input;

// ----------------------------------------------------------- TLS 1.2 CBC

const MACS: [MacAlgorithm; 3] = [
    MacAlgorithm::HmacSha1,
    MacAlgorithm::HmacSha256,
    MacAlgorithm::HmacSha384,
];

/// The record MAC with the RustCrypto `hmac` crate.
fn tls_mac_ref(alg: MacAlgorithm, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    macro_rules! go {
        ($h:ty) => {{
            let mut m = hmac::Hmac::<$h>::new_from_slice(key).expect("any key length");
            for p in parts {
                m.update(p);
            }
            m.finalize().into_bytes().to_vec()
        }};
    }
    match alg {
        MacAlgorithm::HmacSha1 => go!(sha1::Sha1),
        MacAlgorithm::HmacSha256 => go!(sha2::Sha256),
        MacAlgorithm::HmacSha384 => go!(sha2::Sha384),
    }
}

/// The parameters of one TLS 1.2 CBC record.
struct Record<'a> {
    alg: MacAlgorithm,
    order: MacOrder,
    aes_key: &'a [u8],
    mac_key: &'a [u8],
    seq: u64,
    content_type: u8,
    version: [u8; 2],
    iv: [u8; 16],
}

impl Record<'_> {
    fn header(&self, len: usize) -> Vec<u8> {
        let mut h = self.seq.to_be_bytes().to_vec();
        h.push(self.content_type);
        h.extend_from_slice(&self.version);
        h.extend_from_slice(&u16::try_from(len).expect("record length").to_be_bytes());
        h
    }

    /// The protected fragment built independently (RFC 5246 section
    /// 6.2.3.2, RFC 7366 section 3) with `pad` bytes of padding including
    /// the length byte. `corrupt` changes padding byte `corrupt % (pad - 1)`
    /// (the length byte stays intact) when `pad > 1`.
    fn seal(&self, pt: &[u8], pad: usize, corrupt: Option<usize>) -> Vec<u8> {
        let value = u8::try_from(pad - 1).expect("at most 256 bytes of padding");
        let mut padding = vec![value; pad];
        if let Some(i) = corrupt
            && pad > 1
        {
            padding[i % (pad - 1)] ^= 0x40;
        }
        let mut out = self.iv.to_vec();
        match self.order {
            MacOrder::MacThenEncrypt => {
                let mac = tls_mac_ref(self.alg, self.mac_key, &[&self.header(pt.len()), pt]);
                let mut body = [pt, &mac[..], &padding[..]].concat();
                cbc_ref(self.aes_key, &self.iv, &mut body, true);
                out.extend_from_slice(&body);
            }
            MacOrder::EncryptThenMac => {
                let mut body = [pt, &padding[..]].concat();
                cbc_ref(self.aes_key, &self.iv, &mut body, true);
                out.extend_from_slice(&body);
                let mac = tls_mac_ref(self.alg, self.mac_key, &[&self.header(out.len()), &out]);
                out.extend_from_slice(&mac);
            }
        }
        out
    }
}

/// Opens `frag` and asserts the documented failure: `DecryptFailed` and a
/// wiped buffer.
fn assert_record_rejected<C: browntls_crypto::tls_cbc::CbcBlockCipher>(
    key: &RecordKey<C>,
    r: &Record<'_>,
    seq: u64,
    mut frag: Vec<u8>,
    what: &str,
) {
    let res = key.open(seq, r.content_type, r.version, &mut frag);
    assert_eq!(res, Err(Error::DecryptFailed), "{what}");
    assert!(frag.iter().all(|&b| b == 0), "{what}: buffer not wiped");
}

pub(super) fn op_tls_cbc(input: &mut Input<'_>) {
    let alg = *input.pick(&MACS);
    let order = if input.bool() {
        MacOrder::EncryptThenMac
    } else {
        MacOrder::MacThenEncrypt
    };
    let wide = input.bool();
    let backend_sel = input.byte();
    let aes_key_bytes: [u8; 32] = input.array();
    let own_mac_key = input.bool();
    let mac_key_field = input.short_field();
    let seq = input.u64();
    let content_type = input.byte();
    let version: [u8; 2] = input.array();
    let iv: [u8; 16] = input.array();
    // Plaintexts up to a little beyond the 2^14-byte limit.
    let mut pt = input.field().to_vec();
    let ext = usize::from(input.byte()) * 67;
    pt.extend((0..ext).map(|i| (i % 249) as u8));
    let slack = input.byte();
    let extra = input.byte();
    let tamper = input.u16();
    let fuzzed = input.field();

    let h = alg.mac_len();
    let mac_key_pattern: Vec<u8> = (0..h).map(|i| (i as u8) ^ 0x3c).collect();
    let mac_key = if own_mac_key {
        mac_key_field
    } else {
        &mac_key_pattern
    };
    let aes_key = aes_key(&aes_key_bytes, wide);
    let available: Vec<aes::Backend> = aes::Backend::ALL
        .into_iter()
        .filter(|b| b.is_available())
        .collect();
    let backend = available[usize::from(backend_sel) % available.len()];
    let cipher = AesCbcKey::with_backend(aes_key, backend).expect("available backend");
    let key = match RecordKey::new(cipher, alg, mac_key, order) {
        Ok(key) => {
            assert_eq!(mac_key.len(), h);
            key
        }
        Err(e) => {
            assert_ne!(mac_key.len(), h);
            assert_eq!(e, Error::InvalidKey);
            return;
        }
    };
    assert_eq!(key.mac_algorithm(), alg);
    assert_eq!(key.mac_order(), order);
    assert_eq!(key.mac_len(), h);
    assert_eq!(h, tls_mac_ref(alg, b"", &[]).len());
    let r = Record {
        alg,
        order,
        aes_key,
        mac_key,
        seq,
        content_type,
        version,
        iv,
    };

    // Arbitrary fragments: never a panic; a failure wipes the buffer.
    let mut frag = fuzzed.to_vec();
    match key.open(seq, content_type, version, &mut frag) {
        Ok(range) => {
            assert!(range.start >= IV_LEN && range.end <= frag.len());
            assert!(range.len() <= MAX_PLAINTEXT_LEN);
        }
        Err(e) => {
            assert_eq!(e, Error::DecryptFailed);
            assert!(frag.iter().all(|&b| b == 0), "fuzzed fragment not wiped");
        }
    }

    pt.truncate(MAX_PLAINTEXT_LEN + 64);
    let n = pt.len();
    let round_up = |x: usize| x.div_ceil(16) * 16;
    let sealed_len = match order {
        MacOrder::MacThenEncrypt => IV_LEN + round_up(n + h + 1),
        MacOrder::EncryptThenMac => IV_LEN + round_up(n + 1) + h,
    };
    assert_eq!(key.sealed_len(n), sealed_len);
    let buf_len = if slack & 0x80 != 0 {
        sealed_len - (usize::from(slack & 0x0f) + 1)
    } else {
        sealed_len + usize::from(slack & 0x3f)
    };
    let mut buf = vec![0u8; buf_len.max(IV_LEN + n)];
    buf[IV_LEN..IV_LEN + n].copy_from_slice(&pt);
    let res = key.seal(seq, content_type, version, &iv, &mut buf, n);
    if n > MAX_PLAINTEXT_LEN || buf_len < sealed_len {
        assert_eq!(res, Err(Error::InvalidLength));
        return;
    }
    assert_eq!(res, Ok(sealed_len));
    let minimal = sealed_len - IV_LEN - n - h;
    let want = r.seal(&pt, minimal, None);
    assert_eq!(&buf[..sealed_len], &want[..], "sealed record");

    let mut rec = want.clone();
    let range = key.open(seq, content_type, version, &mut rec);
    assert_eq!(range, Ok(IV_LEN..IV_LEN + n), "open");
    assert_eq!(&rec[IV_LEN..IV_LEN + n], &pt[..]);

    // Extra padding blocks (up to 256 bytes of padding in all).
    let pad = minimal + 16 * (usize::from(extra) % ((256 - minimal) / 16 + 1));
    let padded = r.seal(&pt, pad, None);
    if padded.len() <= MAX_FRAGMENT_LEN {
        let mut rec = padded.clone();
        let range = key.open(seq, content_type, version, &mut rec);
        assert_eq!(
            range,
            Ok(IV_LEN..IV_LEN + n),
            "open with {pad} bytes of padding"
        );
        assert_eq!(&rec[IV_LEN..IV_LEN + n], &pt[..]);
        if pad > 1 {
            let bad = r.seal(&pt, pad, Some(usize::from(tamper)));
            assert_record_rejected(&key, &r, seq, bad, "bad padding");
        }
    }

    // A flipped bit anywhere, or another sequence number, is rejected.
    let mut bad = want.clone();
    flip(&mut [&mut bad], tamper);
    assert_record_rejected(&key, &r, seq, bad, "tampered record");
    assert_record_rejected(
        &key,
        &r,
        seq ^ (1 << (tamper % 64)),
        want.clone(),
        "wrong sequence number",
    );
    // A record whose MAC was computed under another key is rejected.
    let mut other_key = mac_key.to_vec();
    other_key[usize::from(tamper) % h] ^= 1;
    let other = Record {
        mac_key: &other_key,
        ..r
    };
    let forged = other.seal(&pt, minimal, None);
    assert_record_rejected(&key, &other, seq, forged, "MAC under another key");
}
