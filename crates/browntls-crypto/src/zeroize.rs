//! Best-effort zeroisation of secret material.
#![allow(unsafe_code)]

use core::sync::atomic::{Ordering, compiler_fence};

/// Types whose secret contents can be overwritten with zeros.
pub trait Zeroize {
    /// Overwrites the value with zeros in a way the optimiser will not elide.
    fn zeroize(&mut self);
}

/// Overwrites `buf` with zeros using volatile writes.
#[inline(never)]
pub fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference to a `u8`.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Overwrites `buf` with zeros using volatile writes.
#[inline(never)]
pub fn zeroize_u32(buf: &mut [u32]) {
    for w in buf.iter_mut() {
        // SAFETY: `w` is a valid, aligned, exclusive reference to a `u32`.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Overwrites `buf` with zeros using volatile writes.
#[inline(never)]
pub fn zeroize_u64(buf: &mut [u64]) {
    for w in buf.iter_mut() {
        // SAFETY: `w` is a valid, aligned, exclusive reference to a `u64`.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        zeroize_bytes(self);
    }
}

impl Zeroize for [u32] {
    fn zeroize(&mut self) {
        zeroize_u32(self);
    }
}

impl Zeroize for [u64] {
    fn zeroize(&mut self) {
        zeroize_u64(self);
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        zeroize_bytes(self);
    }
}

impl<const N: usize> Zeroize for [u32; N] {
    fn zeroize(&mut self) {
        zeroize_u32(self);
    }
}

impl<const N: usize> Zeroize for [u64; N] {
    fn zeroize(&mut self) {
        zeroize_u64(self);
    }
}

#[cfg(feature = "alloc")]
impl Zeroize for alloc::vec::Vec<u8> {
    fn zeroize(&mut self) {
        zeroize_bytes(self.as_mut_slice());
        self.clear();
    }
}

/// Owns a value and zeroises it on drop.
#[derive(Clone, Default)]
pub struct Zeroizing<T: Zeroize>(pub T);

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> core::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> core::fmt::Debug for Zeroizing<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Zeroizing(..)")
    }
}
