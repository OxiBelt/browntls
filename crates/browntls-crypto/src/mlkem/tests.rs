//! Unit tests: every available backend against the portable one, and the
//! portable arithmetic against schoolbook multiplication.

use super::backend::{Backend, Engine};
use super::poly::{self, N, Poly, Q};

/// xorshift64* (test data only).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform in `[-bound, bound]`.
    fn coeff(&mut self, bound: i16) -> i16 {
        let span = 2 * i64::from(bound) + 1;
        ((self.next() % span as u64) as i64 - i64::from(bound)) as i16
    }

    fn poly(&mut self, bound: i16) -> Poly {
        let mut p = Poly::ZERO;
        for c in p.0.iter_mut() {
            *c = self.coeff(bound);
        }
        p
    }
}

fn engines() -> impl Iterator<Item = Engine> {
    Backend::available().map(|b| Engine::new(b).unwrap())
}

/// Edge-case inputs with `|x| <= bound`.
fn edge_polys(bound: i16) -> [Poly; 5] {
    let mut alt = Poly::ZERO;
    for (i, c) in alt.0.iter_mut().enumerate() {
        *c = if i % 2 == 0 { bound } else { -bound };
    }
    [
        Poly::ZERO,
        Poly([bound; N]),
        Poly([-bound; N]),
        alt,
        Poly([1; N]),
    ]
}

fn inputs(seed: u64, bound: i16) -> impl Iterator<Item = Poly> {
    let mut rng = Rng(seed);
    edge_polys(bound)
        .into_iter()
        .chain((0..200).map(move |_| rng.poly(bound)))
}

#[test]
fn backends_detected() {
    let all: std::vec::Vec<_> = Backend::available().collect();
    std::println!(
        "ML-KEM backends: {all:?} (selected {:?})",
        Backend::detect()
    );
    assert!(all.contains(&Backend::Portable));
    assert_eq!(all[0], Backend::detect());
    for b in Backend::ALL {
        assert_eq!(Engine::new(b).is_ok(), b.is_available());
    }
}

#[test]
fn ntt_matches_portable() {
    for e in engines() {
        for x in inputs(1, Q - 1) {
            let (mut a, mut b) = (x, x);
            poly::ntt(&mut a);
            e.ntt(&mut b);
            assert_eq!(a, b, "{:?}", e.backend());
        }
    }
}

#[test]
fn invntt_matches_portable() {
    for e in engines() {
        for x in inputs(2, Q - 1) {
            let (mut a, mut b) = (x, x);
            poly::invntt(&mut a);
            e.invntt(&mut b);
            assert_eq!(a, b, "{:?}", e.backend());
            assert!(a.0.iter().all(|c| c.abs() < Q));
        }
    }
}

#[test]
fn basemul_matches_portable() {
    let mut rng = Rng(3);
    for e in engines() {
        for k in 1..=4 {
            for round in 0..50 {
                let bound = if round == 0 { Q - 1 } else { Q / 2 + 1 };
                let a: [Poly; 4] = core::array::from_fn(|_| rng.poly(bound));
                let b: [Poly; 4] = core::array::from_fn(|_| rng.poly(bound));
                let (mut r1, mut r2) = (Poly::ZERO, Poly([7; N]));
                poly::basemul_acc(&mut r1, &a[..k], &b[..k]);
                e.basemul_acc(&mut r2, &a[..k], &b[..k]);
                assert_eq!(r1, r2, "{:?} k={k}", e.backend());
            }
        }
        let worst = [Poly([Q - 1; N]); 4];
        let neg = [Poly([-(Q - 1); N]); 4];
        let (mut r1, mut r2) = (Poly::ZERO, Poly::ZERO);
        poly::basemul_acc(&mut r1, &worst, &neg);
        e.basemul_acc(&mut r2, &worst, &neg);
        assert_eq!(r1, r2);
    }
}

#[test]
fn reduce_and_tomont_match_portable() {
    for e in engines() {
        for x in inputs(4, i16::MAX).chain(edge_polys(i16::MIN + 1)) {
            let (mut a, mut b) = (x, x);
            poly::reduce(&mut a);
            e.reduce(&mut b);
            assert_eq!(a, b, "{:?}", e.backend());
            let (mut a, mut b) = (x, x);
            poly::tomont(&mut a);
            e.tomont(&mut b);
            assert_eq!(a, b, "{:?}", e.backend());
        }
        let mut p = Poly([i16::MIN; N]);
        let mut p2 = p;
        poly::reduce(&mut p);
        e.reduce(&mut p2);
        assert_eq!(p, p2);
    }
}

#[test]
fn rej_uniform_matches_portable() {
    let mut rng = Rng(5);
    for e in engines() {
        for len in [0usize, 3, 48, 57, 168, 504, 600] {
            for start in [0usize, 1, 100, 224, 225, 250, 255, 256] {
                let mut buf = std::vec![0u8; len];
                for (i, b) in buf.iter_mut().enumerate() {
                    // Mix of accepted and rejected values, including runs of 0xff.
                    *b = if i % 7 == 0 { 0xff } else { rng.next() as u8 };
                }
                let mut a = [0i16; N];
                let mut b = [0i16; N];
                let n1 = poly::rej_uniform(&mut a, start, &buf);
                let n2 = e.rej_uniform(&mut b, start, &buf);
                assert_eq!(n1, n2, "{:?}", e.backend());
                assert_eq!(a[start.min(N)..n1], b[start.min(N)..n2]);
            }
        }
    }
}

/// Schoolbook multiplication in `Z_q[X]/(X^256 + 1)`.
fn schoolbook(a: &Poly, b: &Poly) -> [i64; N] {
    let mut r = [0i64; N];
    for i in 0..N {
        for j in 0..N {
            let p = i64::from(a.0[i]) * i64::from(b.0[j]);
            if i + j < N {
                r[i + j] += p;
            } else {
                r[i + j - N] -= p;
            }
        }
    }
    r.map(|x| x.rem_euclid(i64::from(Q)))
}

#[test]
fn ntt_multiplication_is_negacyclic_convolution() {
    let mut rng = Rng(6);
    for e in engines() {
        for _ in 0..10 {
            let a = rng.poly(Q - 1);
            let b = rng.poly(3);
            let expected = schoolbook(&a, &b);
            let (mut ah, mut bh) = (a, b);
            e.ntt(&mut ah);
            e.ntt(&mut bh);
            let mut r = Poly::ZERO;
            e.basemul_acc(&mut r, &[ah], &[bh]);
            e.invntt(&mut r);
            let got = r.0.map(|c| i64::from(poly::canonical(c)));
            assert_eq!(got, expected, "{:?}", e.backend());
            // tomont after a single basemul undoes the Montgomery factor.
            let mut t = Poly::ZERO;
            e.basemul_acc(&mut t, &[ah], &[bh]);
            e.tomont(&mut t);
            e.invntt(&mut t);
            let mut r2 = r;
            e.tomont(&mut r2);
            let lhs = t.0.map(poly::canonical);
            let rhs = r2.0.map(poly::canonical);
            assert_eq!(lhs, rhs);
        }
    }
}

#[test]
fn encode_decode_roundtrip() {
    let mut rng = Rng(7);
    for _ in 0..20 {
        let p = rng.poly(Q - 1);
        let mut bytes = [0u8; 384];
        poly::encode12(&p, &mut bytes);
        assert!(poly::check12(&bytes));
        let mut back = Poly::ZERO;
        poly::decode12(&bytes, &mut back);
        assert_eq!(back.0.map(poly::canonical), p.0.map(poly::canonical));
        for d in [1u32, 4, 5, 10, 11] {
            let mut c = [0u8; 352];
            poly::compress_encode(&p, d, &mut c[..32 * d as usize]);
            let mut q = Poly::ZERO;
            poly::decode_decompress(&c[..32 * d as usize], d, &mut q);
            // |x - Decompress(Compress(x))| <= round(q / 2^(d+1)).
            let bound = (i32::from(Q) + (1 << (d + 1)) - 1) >> (d + 1);
            for (x, y) in p.0.iter().zip(q.0.iter()) {
                let diff = (i32::from(poly::canonical(*x)) - i32::from(*y)).rem_euclid(3329);
                assert!(diff.min(3329 - diff) <= bound, "d={d} {x} {y}");
            }
            let mut c2 = [0u8; 352];
            poly::compress_encode(&q, d, &mut c2[..32 * d as usize]);
            assert_eq!(c[..32 * d as usize], c2[..32 * d as usize]);
        }
    }
    let mut bad = [0u8; 384];
    bad[0] = 0x01;
    bad[1] = 0x0d; // 0xd01 = 3329
    assert!(!poly::check12(&bad));
    let mut p = Poly::ZERO;
    poly::decode12(&bad, &mut p);
    assert_eq!(p.0[0], 0);
}

/// Arithmetic-only throughput per backend
/// (`cargo test --release -p browntls-crypto --lib mlkem::tests::arith_throughput -- --ignored --nocapture`).
#[test]
#[ignore = "throughput measurement"]
fn arith_throughput() {
    use std::time::{Duration, Instant};
    fn rate(mut f: impl FnMut()) -> f64 {
        let start = Instant::now();
        let mut n = 0u64;
        while start.elapsed() < Duration::from_millis(200) {
            for _ in 0..64 {
                f();
            }
            n += 64;
        }
        n as f64 / start.elapsed().as_secs_f64()
    }
    let mut rng = Rng(8);
    let a: [Poly; 3] = core::array::from_fn(|_| rng.poly(Q / 2));
    let b: [Poly; 3] = core::array::from_fn(|_| rng.poly(Q / 2));
    for e in engines() {
        let mut p = a[0];
        let ntt = rate(|| {
            p = a[0];
            e.ntt(core::hint::black_box(&mut p));
        });
        let inv = rate(|| {
            p = a[0];
            e.invntt(core::hint::black_box(&mut p));
        });
        let mut r = Poly::ZERO;
        let bm = rate(|| e.basemul_acc(core::hint::black_box(&mut r), &a, &b));
        std::println!(
            "{:<9} ntt {:>9.0}/s  invntt {:>9.0}/s  basemul_acc(k=3) {:>9.0}/s",
            std::format!("{:?}", e.backend()),
            ntt,
            inv,
            bm
        );
    }
}
