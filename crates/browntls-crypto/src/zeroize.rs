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

/// Overwrites `buf` with zeros using volatile writes.
#[inline(never)]
pub fn zeroize_i16(buf: &mut [i16]) {
    for w in buf.iter_mut() {
        // SAFETY: `w` is a valid, aligned, exclusive reference to an `i16`.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Overwrites `buf` with zeros using volatile writes.
#[inline(never)]
pub fn zeroize_i32(buf: &mut [i32]) {
    for w in buf.iter_mut() {
        // SAFETY: `w` is a valid, aligned, exclusive reference to an `i32`.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Drops the values of a boxed slice, overwrites the whole of their storage
/// with zeros and frees it.
///
/// A value's own `Drop` can only wipe what the value owns. Its storage can
/// hold more: padding, and for an enum whose variants differ in size the
/// bytes past the variant in use, all of which a move copies from wherever
/// the value was built. Those bytes may be stale secrets of that place.
#[cfg(feature = "std")]
pub(crate) fn wipe_boxed<T>(values: alloc::boxed::Box<[T]>) {
    let raw = alloc::boxed::Box::into_raw(values);
    // SAFETY: `raw` comes from `Box::into_raw`, so it points to a live,
    // exclusively owned slice that nothing else drops.
    unsafe { drop_and_zero(raw) };
    // SAFETY: `MaybeUninit<T>` has the size and alignment of `T`, so this is
    // the allocation `raw` came from, with the layout it was made with. A
    // `MaybeUninit` may hold any bytes and drops nothing, so the box only
    // frees the memory.
    drop(unsafe { alloc::boxed::Box::from_raw(raw as *mut [core::mem::MaybeUninit<T>]) });
}

/// Drops the values `raw` points to and overwrites their storage with zeros.
///
/// # Safety
///
/// `raw` must point to a live slice that the caller owns exclusively. The
/// values are dropped: afterwards the memory must not be used as `T`s, nor
/// dropped again.
#[cfg(feature = "std")]
#[inline(never)]
unsafe fn drop_and_zero<T>(raw: *mut [T]) {
    // SAFETY: the caller guarantees a live, exclusively owned slice, which
    // is not used as values again.
    unsafe { core::ptr::drop_in_place(raw) };
    let bytes = raw.cast::<u8>();
    for i in 0..raw.len() * size_of::<T>() {
        // SAFETY: the slice spans `len * size_of::<T>()` bytes that the
        // caller owns exclusively, and its values are already dropped.
        unsafe { core::ptr::write_volatile(bytes.wrapping_add(i), 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

impl Zeroize for [i16] {
    fn zeroize(&mut self) {
        zeroize_i16(self);
    }
}

impl<const N: usize> Zeroize for [i16; N] {
    fn zeroize(&mut self) {
        zeroize_i16(self);
    }
}

impl Zeroize for [i32] {
    fn zeroize(&mut self) {
        zeroize_i32(self);
    }
}

impl<const N: usize> Zeroize for [i32; N] {
    fn zeroize(&mut self) {
        zeroize_i32(self);
    }
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

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    /// A value that owns a few bytes of storage sized for a larger variant.
    #[allow(clippy::large_enum_variant)]
    enum Sized {
        Small(u8),
        Large([u8; 256]),
    }

    impl Drop for Sized {
        fn drop(&mut self) {
            if let Self::Small(b) = self {
                *b = 0;
            }
        }
    }

    #[test]
    fn storage_is_wiped_beyond_what_the_values_own() {
        let mut values: alloc::vec::Vec<Sized> = alloc::vec::Vec::new();
        for _ in 0..3 {
            // The large variant fills its storage with a recognisable
            // pattern; the small one that replaces it owns one byte of it.
            values.push(Sized::Large([0xa5; 256]));
        }
        for value in &mut values {
            let Sized::Large(pattern) = value else {
                continue;
            };
            assert_eq!(pattern[255], 0xa5);
            *value = Sized::Small(0xa5);
        }
        let raw = alloc::boxed::Box::into_raw(values.into_boxed_slice());
        let len = raw.len() * size_of::<Sized>();
        assert!(len >= 3 * 257);
        // SAFETY: `raw` comes from `Box::into_raw` and is not used as values
        // again.
        unsafe { drop_and_zero(raw) };
        for i in 0..len {
            // SAFETY: within the allocation, which `drop_and_zero` filled
            // with initialised (zero) bytes.
            let byte = unsafe { raw.cast::<u8>().wrapping_add(i).read() };
            assert_eq!(byte, 0, "byte {i}");
        }
        // SAFETY: the allocation `raw` came from, with the same layout; a
        // `MaybeUninit` drops nothing.
        drop(unsafe { alloc::boxed::Box::from_raw(raw as *mut [MaybeUninit<Sized>]) });

        // The whole operation, on values and on nothing.
        wipe_boxed(alloc::vec![Sized::Small(1), Sized::Large([2; 256])].into_boxed_slice());
        wipe_boxed::<Sized>(alloc::boxed::Box::default());
    }
}
