//! The RustCrypto `ml-dsa` crate as the independent implementation.

use browntls_crypto::mldsa::{MlDsa44, MlDsa65, MlDsa87};

/// The oracle's operations for one parameter set, on byte strings.
pub(crate) trait Oracle {
    /// `ML-DSA.KeyGen_internal(seed)`: the encoded public key and the
    /// expanded private key.
    fn oracle_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>);

    /// `ML-DSA.Sign_internal` of the key derived from `seed` on
    /// `M' = 0 || |ctx| || ctx || msg` with `rnd` (`ctx` at most 255 bytes).
    fn oracle_sign(seed: &[u8; 32], msg: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Vec<u8>;

    /// As [`Self::oracle_sign`] with an expanded private key (which the oracle
    /// loads without checking it).
    fn oracle_sign_expanded(sk: &[u8], msg: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Vec<u8>;

    /// The public key the oracle derives from an expanded private key.
    fn oracle_expanded_public_key(sk: &[u8]) -> Vec<u8>;

    /// `ML-DSA.Verify`; `None` if `pk` has the wrong length. A signature of
    /// the wrong length or with a malformed encoding is `Some(false)`.
    fn oracle_verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Option<bool>;
}

macro_rules! oracle {
    ($ours:ty, $theirs:ty) => {
        impl Oracle for $ours {
            fn oracle_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
                let key = ml_dsa::SigningKey::<$theirs>::from_seed(&(*seed).into());
                let expanded = key.expanded_key();
                #[allow(deprecated)]
                let sk = expanded.to_expanded().to_vec();
                (expanded.verifying_key().encode().to_vec(), sk)
            }

            fn oracle_sign(seed: &[u8; 32], msg: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Vec<u8> {
                let key = ml_dsa::SigningKey::<$theirs>::from_seed(&(*seed).into());
                let len = [u8::try_from(ctx.len()).expect("a context of at most 255 bytes")];
                key.expanded_key()
                    .sign_internal(&[&[0], &len, ctx, msg], &(*rnd).into())
                    .encode()
                    .to_vec()
            }

            fn oracle_sign_expanded(sk: &[u8], msg: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Vec<u8> {
                let bytes = ml_dsa::ExpandedSigningKeyBytes::<$theirs>::try_from(sk)
                    .expect("an expanded key of the right length");
                #[allow(deprecated)]
                let key = ml_dsa::ExpandedSigningKey::<$theirs>::from_expanded(&bytes);
                let len = [u8::try_from(ctx.len()).expect("a context of at most 255 bytes")];
                key.sign_internal(&[&[0], &len, ctx, msg], &(*rnd).into())
                    .encode()
                    .to_vec()
            }

            fn oracle_expanded_public_key(sk: &[u8]) -> Vec<u8> {
                let bytes = ml_dsa::ExpandedSigningKeyBytes::<$theirs>::try_from(sk)
                    .expect("an expanded key of the right length");
                #[allow(deprecated)]
                let key = ml_dsa::ExpandedSigningKey::<$theirs>::from_expanded(&bytes);
                key.verifying_key().encode().to_vec()
            }

            fn oracle_verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Option<bool> {
                let pk = ml_dsa::EncodedVerifyingKey::<$theirs>::try_from(pk).ok()?;
                let vk = ml_dsa::VerifyingKey::<$theirs>::decode(&pk);
                Some(
                    ml_dsa::Signature::<$theirs>::try_from(sig)
                        .is_ok_and(|sig| vk.verify_with_context(msg, ctx, &sig)),
                )
            }
        }
    };
}

oracle!(MlDsa44, ml_dsa::MlDsa44);
oracle!(MlDsa65, ml_dsa::MlDsa65);
oracle!(MlDsa87, ml_dsa::MlDsa87);
