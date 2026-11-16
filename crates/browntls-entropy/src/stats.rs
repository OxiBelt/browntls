//! Tail probabilities and critical values used by the checks.
//!
//! Every check compares a statistic with a critical value computed from a
//! false-alarm probability, so the thresholds hold for any sample count.

use core::f64::consts::{LN_2, SQRT_2};

/// `erfc(x)` with a fractional error below 1.2e-7 everywhere (Numerical
/// Recipes §6.2, Chebyshev fit), which is ample for picking thresholds.
#[must_use]
pub fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let poly = -z * z - 1.265_512_23
        + t * (1.000_023_68
            + t * (0.374_091_96
                + t * (0.096_784_18
                    + t * (-0.186_288_06
                        + t * (0.278_868_07
                            + t * (-1.135_203_98
                                + t * (1.488_515_87 + t * (-0.822_152_23 + t * 0.170_872_77))))))));
    let r = t * poly.exp();
    if x >= 0.0 { r } else { 2.0 - r }
}

/// `P(Z > z)` for a standard normal `Z`.
#[must_use]
pub fn normal_sf(z: f64) -> f64 {
    0.5 * erfc(z / SQRT_2)
}

/// The `z` with `P(Z > z) = p`, for `0 < p < 0.5`.
#[must_use]
pub fn normal_isf(p: f64) -> f64 {
    let (mut lo, mut hi) = (0.0_f64, 40.0_f64);
    for _ in 0..200 {
        let mid = 0.5 * (lo + hi);
        if normal_sf(mid) > p {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    0.5 * (lo + hi)
}

/// Two-sided critical `|z|` for `tests` simultaneous tests whose combined
/// false-alarm probability is at most `alpha` (Bonferroni).
#[must_use]
pub fn z_two_sided(alpha: f64, tests: usize) -> f64 {
    normal_isf(alpha / (2.0 * tests.max(1) as f64))
}

/// One-sided critical `z` for `tests` simultaneous tests (Bonferroni).
#[must_use]
pub fn z_one_sided(alpha: f64, tests: usize) -> f64 {
    normal_isf(alpha / tests.max(1) as f64)
}

/// The Wilson–Hilferty normal deviate of a chi-square statistic with `df`
/// degrees of freedom.
#[must_use]
pub fn chi2_to_z(chi2: f64, df: f64) -> f64 {
    let v = 2.0 / (9.0 * df);
    ((chi2 / df).cbrt() - (1.0 - v)) / v.sqrt()
}

/// The chi-square value whose Wilson–Hilferty deviate is `z`.
#[must_use]
pub fn chi2_from_z(z: f64, df: f64) -> f64 {
    let v = 2.0 / (9.0 * df);
    df * (1.0 - v + z * v.sqrt()).powi(3)
}

/// `ln(k!)`: exact below 32, Stirling's series above.
fn ln_factorial(k: u64) -> f64 {
    if k < 32 {
        return (2..=k).map(|i| (i as f64).ln()).sum();
    }
    let x = k as f64;
    x * x.ln() - x + 0.5 * (2.0 * core::f64::consts::PI * x).ln() + 1.0 / (12.0 * x)
        - 1.0 / (360.0 * x * x * x)
}

/// `ln P(X = k)` for `X ~ Poisson(lambda)`.
fn poisson_ln_pmf(k: u64, lambda: f64) -> f64 {
    if lambda == 0.0 {
        return if k == 0 { 0.0 } else { f64::NEG_INFINITY };
    }
    k as f64 * lambda.ln() - lambda - ln_factorial(k)
}

/// `P(X >= k)` for `X ~ Poisson(lambda)`.
#[must_use]
pub fn poisson_sf(k: u64, lambda: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    if (k as f64) <= lambda {
        return 1.0 - poisson_cdf(k - 1, lambda);
    }
    // Upper tail: the terms decrease from k on.
    let mut term = poisson_ln_pmf(k, lambda).exp();
    let mut sum = 0.0;
    let mut j = k;
    while term > sum * 1e-17 && term > 0.0 {
        sum += term;
        j += 1;
        term *= lambda / j as f64;
    }
    sum.min(1.0)
}

/// `P(X <= k)` for `X ~ Poisson(lambda)`.
#[must_use]
pub fn poisson_cdf(k: u64, lambda: f64) -> f64 {
    if (k as f64) >= lambda {
        return 1.0 - poisson_sf(k + 1, lambda);
    }
    // Lower tail: the terms decrease from k down to 0.
    let mut term = poisson_ln_pmf(k, lambda).exp();
    let mut sum = 0.0;
    let mut j = k;
    loop {
        sum += term;
        if j == 0 || term <= sum * 1e-17 {
            break;
        }
        term *= j as f64 / lambda;
        j -= 1;
    }
    sum.min(1.0)
}

/// Shannon entropy in bits of a histogram with `total` observations.
#[must_use]
pub fn shannon_bits(hist: &[u64], total: u64) -> f64 {
    let n = total as f64;
    -hist
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

/// The approximate Shannon entropy of a near-uniform `bins`-bin histogram
/// whose chi-square statistic against uniformity is `chi2`
/// (`H ≈ log2(bins) - chi2 / (2 N ln 2)`).
#[must_use]
pub fn shannon_from_chi2(chi2: f64, bins: f64, n: f64) -> f64 {
    bins.log2() - chi2 / (2.0 * n * LN_2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, rel: f64) -> bool {
        (a - b).abs() <= rel * b.abs()
    }

    #[test]
    fn normal_tails() {
        assert!(close(normal_sf(0.0), 0.5, 1e-6));
        assert!(close(normal_sf(1.959_963_985), 0.025, 1e-5));
        assert!(close(normal_sf(6.0), 9.865_876e-10, 1e-5));
        assert!(close(normal_isf(1e-9), 5.997_807, 1e-5));
        assert!(close(z_two_sided(1e-9, 1), 6.109_410, 1e-5));
    }

    #[test]
    fn wilson_hilferty_round_trip() {
        let chi2 = chi2_from_z(6.0, 255.0);
        assert!(close(chi2_to_z(chi2, 255.0), 6.0, 1e-9));
        // The exact 1e-9 upper quantile of chi2(255) is 414.55.
        let exact = chi2_from_z(normal_isf(1e-9), 255.0);
        assert!(close(exact, 414.545, 2e-3), "{exact}");
    }

    #[test]
    fn poisson_tails() {
        // P(X >= 1) for lambda = 0.5 is 1 - e^-0.5.
        assert!(close(poisson_sf(1, 0.5), 1.0 - (-0.5f64).exp(), 1e-9));
        // P(X <= 0) for lambda = 3 is e^-3.
        assert!(close(poisson_cdf(0, 3.0), (-3.0f64).exp(), 1e-9));
        // Median region and complements.
        let lambda = 512.0;
        assert!(close(
            poisson_sf(513, lambda) + poisson_cdf(512, lambda),
            1.0,
            1e-9
        ));
        // Far tails: P(X >= 700) and P(X <= 350) for lambda = 512 are tiny.
        assert!(poisson_sf(700, lambda) < 1e-12);
        assert!(poisson_cdf(350, lambda) < 1e-12);
        assert!(poisson_sf(560, lambda) > 1e-3);
    }

    #[test]
    fn entropy_of_histograms() {
        assert!(close(shannon_bits(&[1, 1, 1, 1], 4), 2.0, 1e-12));
        assert!(shannon_bits(&[4, 0, 0, 0], 4).abs() < 1e-12);
    }
}
