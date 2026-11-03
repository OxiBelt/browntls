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

/// Number of Booth digits of width `w` of a `BITS`-bit scalar (one more bit
/// than the scalar, so the top digit is never negative).
pub(crate) const fn comb_digits(bits: usize, w: usize) -> usize {
    bits / w + 1
}

/// Number of positions (table rows) of a comb with Booth width `w` and
/// interleave `s`: digits `s j .. s j + s - 1` share `T_j = 2^(w s j) G`.
pub(crate) const fn comb_positions(bits: usize, w: usize, s: usize) -> usize {
    comb_digits(bits, w).div_ceil(s)
}

#[cfg(test)]
pub(crate) mod generate {
    use std::vec::Vec;

    use super::super::curve::{Affine, Curve, Projective, add, double, to_affine};
    use super::comb_positions;

    /// Recomputes a fixed-base comb table of Booth width `w` and interleave
    /// `s`, flattened: row `j` holds `m * 2^(w s j) * G` for `m` in
    /// `1..=2^(w-1)`.
    pub(crate) fn base_table<C: Curve<N>, const N: usize>(w: usize, s: usize) -> Vec<Affine<N>> {
        let mut out = Vec::new();
        let mut base = Projective::from_affine::<C>(&C::G);
        for _ in 0..comb_positions(C::BITS, w, s) {
            let mut acc = base;
            for _ in 0..1 << (w - 1) {
                out.push(to_affine::<C, N>(&acc).expect("multiple of G is not the identity"));
                acc = add::<C, N>(&acc, &base);
            }
            for _ in 0..w * s {
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
        let (w, s_) = (C::COMB_WIDTH, C::COMB_INTERLEAVE);
        let row_len = 1usize << (w - 1);
        let base = base_table::<C, N>(w, s_);
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
             /// `[j][m - 1] = m * 2^({} j) * G`.\n\
             #[rustfmt::skip]\n\
             pub(in super::super) static BASE: [[Affine<{N}>; {row_len}]; {}] = [",
            w * s_,
            base.len() / row_len
        );
        for row in base.chunks(row_len) {
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
        let (w, s) = (C::COMB_WIDTH, C::COMB_INTERLEAVE);
        let base = generate::base_table::<C, N>(w, s);
        let row = 1usize << (w - 1);
        assert_eq!(C::BASE_TABLE.len(), row * comb_positions(C::BITS, w, s));
        assert_eq!(C::BASE_TABLE.len(), base.len());
        for (i, (g, want)) in C::BASE_TABLE.iter().zip(&base).enumerate() {
            assert!(is_on_curve::<C, N>(g));
            assert_eq!(
                g,
                want,
                "base table position {} multiple {}",
                i / row,
                i % row + 1
            );
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
