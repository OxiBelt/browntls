//! NIST P-521 (secp521r1): ECDH and ECDSA.
//!
//! Backends: the full-width product followed by a fold and rotation for the
//! Mersenne prime `p = 2^521 - 1` everywhere; on x86-64 with BMI2 and ADX the
//! product comes from a `mulx`/`adcx`/`adox` kernel, and the reduction,
//! addition and subtraction are assembly as well.

use super::params::P521;

#[cfg(target_arch = "x86_64")]
type Fast = super::p521_x86::P521Adx;
#[cfg(not(target_arch = "x86_64"))]
type Fast = P521;

super::api::curve_module! {
    name = "P-521",
    soft = P521,
    fast = Fast,
    backend = P521Backend,
    load = P521_LOAD,
    limbs = 9,
    field_len = 66,
    tls_hash = Sha512
}
