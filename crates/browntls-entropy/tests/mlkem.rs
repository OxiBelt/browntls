//! ML-KEM key generation and encapsulation (`browntls-crypto`, FIPS 203).
//!
//! The 64-byte seed `d || z` is the key's entropy. `rho`, the last 32 bytes
//! of the encapsulation key, is the first half of `G(d || k)` and must be
//! uniform as well. The rest of the encapsulation key encodes coefficients
//! modulo 3329, which are not uniform bytes, so it is not examined.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use browntls_crypto::mlkem::{DecapsulationKey, MlKem512, MlKem768, MlKem1024};
use browntls_crypto::rand::OsRng;
use browntls_entropy::{Stream, check, err, sample_count};

macro_rules! mlkem_test {
    ($test:ident, $title:literal, $params:ty) => {
        #[test]
        fn $test() {
            check(
                concat!($title, " key generation and encapsulation"),
                sample_count(1, 1 << 12),
                &[
                    Stream::new(concat!($title, " seed d || z"), 64),
                    Stream::new(concat!($title, " encapsulation key rho"), 32),
                    Stream::new(concat!($title, " encapsulated shared secret"), 32),
                ],
                |out| {
                    let (dk, ek) = DecapsulationKey::<$params>::generate(&OsRng).map_err(err)?;
                    out[0].copy_from_slice(dk.seed().ok_or("generated key has no seed")?);
                    let ek_bytes = ek.as_bytes();
                    out[1].copy_from_slice(&ek_bytes[ek_bytes.len() - 32..]);
                    let (ct, ss) = ek.encapsulate(&OsRng).map_err(err)?;
                    if dk.decapsulate(ct.as_ref()).map_err(err)? != ss {
                        return Err("decapsulation disagrees with encapsulation".into());
                    }
                    out[2].copy_from_slice(&ss);
                    Ok(())
                },
            );
        }
    };
}

mlkem_test!(mlkem512, "ML-KEM-512", MlKem512);
mlkem_test!(mlkem768, "ML-KEM-768", MlKem768);
mlkem_test!(mlkem1024, "ML-KEM-1024", MlKem1024);
