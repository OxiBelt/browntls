//! Generation and validation of the committed base-point tables.
//!
//! The tables in `tables/` are generated source: computing them at compile
//! time costs about a minute of constant evaluation per build, so they are
//! committed instead and this module keeps them honest. `tables_match_generator`
//! recomputes every entry from the base point with the run-time group law and
//! fails on any difference; `regenerate_tables` (ignored, run manually) rewrites
//! the files:
//!
//! ```text
//! cargo test -p browntls-crypto --lib nist::table::tests::regenerate_tables -- --ignored
//! ```
//!
//! The differential tests against independent implementations additionally
//! check scalars that hit individual table entries.

/// Number of 4-bit Booth digits of a `BITS`-bit scalar.
pub(crate) const fn comb_digits(bits: usize) -> usize {
    bits / 4 + 1
}

/// Digits that share one table position (`T_j = 2^(4 * INTERLEAVE * j) G`).
pub(crate) const INTERLEAVE: usize = 4;

/// Number of positions in the fixed-base table.
pub(crate) const fn comb_positions(bits: usize) -> usize {
    comb_digits(bits).div_ceil(INTERLEAVE)
}

#[cfg(test)]
pub(crate) mod generate {
    use std::vec::Vec;

    use super::super::curve::{Affine, Curve, Projective, add, double, to_affine};
    use super::{INTERLEAVE, comb_positions};

    /// Recomputes the fixed-base comb table: `[j][m - 1] = m * 2^(16 j) * G`.
    pub(crate) fn base_table<C: Curve<N>, const N: usize>() -> Vec<[Affine<N>; 8]> {
        let mut out = Vec::new();
        let mut base = Projective::from_affine::<C>(&C::G);
        for _ in 0..comb_positions(C::BITS) {
            let mut row = [Affine::<N>::ZERO; 8];
            let mut acc = base;
            for entry in &mut row {
                *entry = to_affine::<C, N>(&acc).expect("multiple of G is not the identity");
                acc = add::<C, N>(&acc, &base);
            }
            out.push(row);
            for _ in 0..4 * INTERLEAVE {
                base = double::<C, N>(&base);
            }
        }
        out
    }

    /// Recomputes the odd multiples `(2i + 1) * G`, `i` in `0..16`.
    pub(crate) fn odd_table<C: Curve<N>, const N: usize>() -> [Affine<N>; 16] {
        let g = Projective::from_affine::<C>(&C::G);
        let g2 = double::<C, N>(&g);
        let mut out = [Affine::<N>::ZERO; 16];
        let mut acc = g;
        for entry in &mut out {
            *entry = to_affine::<C, N>(&acc).expect("odd multiple of G is not the identity");
            acc = add::<C, N>(&acc, &g2);
        }
        out
    }

    fn fmt_point<const N: usize>(p: &Affine<N>, out: &mut std::string::String) {
        use std::fmt::Write;
        out.push_str("    Affine { x: [");
        for (i, l) in p.x.iter().enumerate() {
            let _ = write!(out, "{}{l:#018x}", if i == 0 { "" } else { ", " });
        }
        out.push_str("], y: [");
        for (i, l) in p.y.iter().enumerate() {
            let _ = write!(out, "{}{l:#018x}", if i == 0 { "" } else { ", " });
        }
        out.push_str("] },\n");
    }

    /// Renders the generated source file for one curve.
    pub(crate) fn render<C: Curve<N>, const N: usize>(curve_name: &str) -> std::string::String {
        use std::fmt::Write;
        let base = base_table::<C, N>();
        let odd = odd_table::<C, N>();
        let mut s = std::string::String::new();
        let _ = writeln!(
            s,
            "//! Precomputed base-point multiples for {curve_name} (generated; do not edit).\n\
             //!\n\
             //! Regenerate with the ignored test `nist::table::tests::regenerate_tables`;\n\
             //! `nist::table::tests::tables_match_generator` verifies every entry.\n\
             #![allow(clippy::unreadable_literal)]\n\n\
             use super::super::curve::Affine;\n\n\
             /// `[j][m - 1] = m * 2^(16 j) * G`.\n\
             #[rustfmt::skip]\n\
             pub(in super::super) static BASE: [[Affine<{N}>; 8]; {}] = [",
            base.len()
        );
        for row in &base {
            s.push_str("  [\n");
            for p in row {
                fmt_point(p, &mut s);
            }
            s.push_str("  ],\n");
        }
        s.push_str("];\n\n/// `[i] = (2 i + 1) * G`.\n#[rustfmt::skip]\n");
        let _ = writeln!(s, "pub(in super::super) static ODD: [Affine<{N}>; 16] = [");
        for p in &odd {
            fmt_point(p, &mut s);
        }
        s.push_str("];\n");
        s
    }
}

#[cfg(test)]
mod tests {
    use super::super::curve::{Curve, is_on_curve};
    use super::super::params::{P256, P384, P521};
    use super::*;

    fn check<C: Curve<N>, const N: usize>() {
        let base = generate::base_table::<C, N>();
        assert_eq!(C::BASE_TABLE.len(), comb_positions(C::BITS));
        assert_eq!(C::BASE_TABLE.len(), base.len());
        for (j, (got, want)) in C::BASE_TABLE.iter().zip(&base).enumerate() {
            for (m, (g, w)) in got.iter().zip(want).enumerate() {
                assert!(is_on_curve::<C, N>(g));
                assert_eq!(g, w, "base table position {j} multiple {}", m + 1);
            }
        }
        let odd = generate::odd_table::<C, N>();
        for (i, (g, w)) in C::G_ODD.iter().zip(&odd).enumerate() {
            assert!(is_on_curve::<C, N>(g));
            assert_eq!(g, w, "odd table entry {i}");
        }
    }

    #[test]
    fn tables_match_generator() {
        check::<P256, 4>();
        check::<P384, 6>();
        check::<P521, 9>();
    }

    /// Rewrites `src/nist/tables/*.rs`. Run manually after changing the table
    /// layout; `tables_match_generator` must pass afterwards.
    #[test]
    #[ignore = "rewrites generated source files"]
    fn regenerate_tables() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/nist/tables");
        std::fs::write(dir.join("p256.rs"), generate::render::<P256, 4>("P-256")).unwrap();
        std::fs::write(dir.join("p384.rs"), generate::render::<P384, 6>("P-384")).unwrap();
        std::fs::write(dir.join("p521.rs"), generate::render::<P521, 9>("P-521")).unwrap();
    }
}
