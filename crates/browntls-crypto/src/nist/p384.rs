//! NIST P-384 (secp384r1): ECDH, ECDSA, and field and scalar arithmetic.
//!
//! Backends: the full-width product followed by a Montgomery reduction
//! specialised to the shape of `p` everywhere; on x86-64 with BMI2 and ADX
//! the product comes from a `mulx`/`adcx`/`adox` kernel, and the reduction,
//! addition and subtraction are assembly as well.

use super::params::P384;

#[cfg(target_arch = "x86_64")]
type Fast = super::p384_x86::P384Adx;
#[cfg(not(target_arch = "x86_64"))]
type Fast = P384;

super::api::curve_module! {
    name = "P-384",
    soft = P384,
    fast = Fast,
    backend = P384Backend,
    load = P384_LOAD,
    limbs = 6,
    field_len = 48,
    tls_hash = Sha384
}

super::arith::arith_module! {
    name = "P-384",
    soft = P384,
    fast = Fast,
    backend = P384Backend,
    limbs = 6,
    field_len = 48
}
