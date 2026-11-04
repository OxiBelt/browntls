//! The TLS 1.2 pseudorandom function (RFC 5246, section 5): `P_hash`.

use crate::hash::HashFunction;
use crate::hmac::Hmac;

/// Computes `PRF(secret, label, seed)` with `P_<H>` and writes `out.len()`
/// bytes. `seed` is given as concatenated fragments.
pub fn prf<H: HashFunction>(out: &mut [u8], secret: &[u8], label: &[u8], seed: &[&[u8]]) {
    let key = Hmac::<H>::new(secret);
    // A(1) = HMAC(secret, label || seed)
    let mut a = {
        let mut m = key.clone();
        m.update(label);
        for s in seed {
            m.update(s);
        }
        m.finalize()
    };
    for chunk in out.chunks_mut(H::OUTPUT_LEN) {
        let mut m = key.clone();
        m.update(a.as_ref());
        m.update(label);
        for s in seed {
            m.update(s);
        }
        let p = m.finalize();
        chunk.copy_from_slice(&p.as_ref()[..chunk.len()]);
        let mut m = key.clone();
        m.update(a.as_ref());
        a = m.finalize();
    }
    crate::zeroize::zeroize_bytes(a.as_mut());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha256, Sha384};

    // Widely used TLS 1.2 PRF vectors (P_SHA256 / P_SHA384) published with the
    // IETF TLS WG mailing-list test vectors.
    #[test]
    fn sha256_vector() {
        let secret = hex::decode("9bbe436ba940f017b17652849a71db35").unwrap();
        let seed = hex::decode("a0ba9f936cda311827a6f796ffd5198c").unwrap();
        let mut out = [0u8; 100];
        prf::<Sha256>(&mut out, &secret, b"test label", &[&seed]);
        assert_eq!(
            hex::encode(out),
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a\
             6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab\
             4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701\
             87347b66"
        );
    }

    #[test]
    fn sha384_vector() {
        let secret = hex::decode("b80b733d6ceefcdc71566ea48e5567df").unwrap();
        let seed = hex::decode("cd665cf6a8447dd6ff8b27555edb7465").unwrap();
        let mut out = [0u8; 148];
        prf::<Sha384>(&mut out, &secret, b"test label", &[&seed]);
        assert_eq!(
            hex::encode(&out[..32]),
            "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd"
        );
    }
}
