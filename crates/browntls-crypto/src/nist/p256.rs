//! NIST P-256 (secp256r1 / prime256v1): ECDH and ECDSA.
//!
//! Backends: portable 64-bit Montgomery arithmetic everywhere; on x86-64 with
//! BMI2 and ADX the field multiplication uses a `mulx`/`adcx`/`adox` kernel.

use super::params::P256;

#[cfg(target_arch = "x86_64")]
type Fast = super::p256_x86::P256Adx;
#[cfg(not(target_arch = "x86_64"))]
type Fast = P256;

#[inline]
fn accelerated() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        crate::accel::allowed(crate::accel::Algorithm::P256) && super::p256_x86::available()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

super::api::curve_module! {
    name = "P-256",
    soft = P256,
    fast = Fast,
    accel = accelerated(),
    limbs = 4,
    field_len = 32,
    tls_hash = Sha256
}
