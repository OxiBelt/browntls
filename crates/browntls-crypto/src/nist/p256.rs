//! NIST P-256 (secp256r1 / prime256v1): ECDH, ECDSA, and field, scalar and point arithmetic.
//!
//! Backends: portable 64-bit Montgomery arithmetic everywhere; on x86-64 with
//! BMI2 and ADX the field multiplication uses a `mulx`/`adcx`/`adox` kernel.

use super::params::P256;

#[cfg(target_arch = "x86_64")]
type Fast = super::p256_x86::P256Adx;
#[cfg(not(target_arch = "x86_64"))]
type Fast = P256;

super::api::curve_module! {
    name = "P-256",
    soft = P256,
    fast = Fast,
    backend = P256Backend,
    load = P256_LOAD,
    limbs = 4,
    field_len = 32,
    tls_hash = Sha256
}

super::arith::arith_module! {
    name = "P-256",
    soft = P256,
    fast = Fast,
    backend = P256Backend,
    limbs = 4,
    field_len = 32
}
