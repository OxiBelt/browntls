//! CPU feature detection (`cpu`), acceleration policies (`accel`), the
//! load-aware routing controls (`accel::load`) and `Error` of the
//! `crypto_util` target.

use browntls_crypto::Error;
use browntls_crypto::accel::load::{self, Phase};
use browntls_crypto::accel::{self, Acceleration, Algorithm, Kind, Policy, Uses};
use browntls_crypto::cpu::{self, Features};
use browntls_crypto::curve25519::x25519;

use crate::input::Input;

const LEVELS: [Acceleration; 3] = [
    Acceleration::Required,
    Acceleration::Preferred,
    Acceleration::None,
];

/// The `accel` call that runs one `accel::load` call (see [`load_op`]).
pub(super) const ACCEL_LOAD: u8 = 6;
/// Calls of `accel` operations.
const ACCEL_CALLS: usize = 7;

pub(super) const LOAD_ENABLE: u8 = 0;
pub(super) const LOAD_DISABLE: u8 = 1;
pub(super) const LOAD_SET_FIXED: u8 = 2;
pub(super) const LOAD_CLEAR_FIXED: u8 = 3;
pub(super) const LOAD_KEY_EXCHANGE: u8 = 4;
const LOAD_CALLS: usize = 5;

/// Lanes and alternates a fuzzed index selects from: more than any family
/// has, so that missing ones are asked for as well.
const LOAD_INDEXES: u8 = 4;

// ---------------------------------------------------------------------------
// cpu, accel, error
// ---------------------------------------------------------------------------

/// Every accessor of `f`, with its name and architecture.
fn accessors(f: Features) -> Vec<(&'static str, &'static str, bool)> {
    vec![
        ("x86_64", "x86_v3", f.x86_v3()),
        ("x86_64", "x86_ssse3", f.x86_ssse3()),
        ("x86_64", "x86_sse41", f.x86_sse41()),
        ("x86_64", "x86_avx", f.x86_avx()),
        ("x86_64", "x86_avx2", f.x86_avx2()),
        ("x86_64", "x86_bmi2", f.x86_bmi2()),
        ("x86_64", "x86_aes", f.x86_aes()),
        ("x86_64", "x86_pclmulqdq", f.x86_pclmulqdq()),
        ("x86_64", "x86_sha", f.x86_sha()),
        ("x86_64", "x86_sha512", f.x86_sha512()),
        ("x86_64", "x86_vaes", f.x86_vaes()),
        ("x86_64", "x86_vpclmulqdq", f.x86_vpclmulqdq()),
        ("x86_64", "x86_avx512", f.x86_avx512()),
        ("x86_64", "x86_avx512_ifma", f.x86_avx512_ifma()),
        ("x86_64", "x86_avx512_vbmi", f.x86_avx512_vbmi()),
        ("x86_64", "x86_adx", f.x86_adx()),
        ("x86_64", "x86_gfni", f.x86_gfni()),
        ("aarch64", "arm_neon", f.arm_neon()),
        ("aarch64", "arm_aes", f.arm_aes()),
        ("aarch64", "arm_sha2", f.arm_sha2()),
        ("aarch64", "arm_sha3", f.arm_sha3()),
        ("riscv64", "rv_v", f.rv_v()),
        ("riscv64", "rv_zvkned", f.rv_zvkned()),
        ("riscv64", "rv_zvknha", f.rv_zvknha()),
        ("riscv64", "rv_zvknhb", f.rv_zvknhb()),
        ("riscv64", "rv_zvkg", f.rv_zvkg()),
        ("riscv64", "rv_zvbc", f.rv_zvbc()),
        ("riscv64", "rv_zvbb", f.rv_zvbb()),
        ("riscv64", "rv_zvkb", f.rv_zvkb()),
        ("riscv64", "rv_zbb", f.rv_zbb()),
        ("riscv64", "rv_zbc", f.rv_zbc()),
        ("riscv64", "rv_zbkb", f.rv_zbkb()),
        ("riscv64", "rv_zbkc", f.rv_zbkc()),
        ("riscv64", "rv_zknh", f.rv_zknh()),
        ("riscv64", "rv_zkne", f.rv_zkne()),
        ("riscv64", "rv_zknd", f.rv_zknd()),
    ]
}

pub(super) fn cpu_op(input: &mut Input<'_>) {
    let f = cpu::features();
    assert_eq!(cpu::features(), f, "detection is not stable");
    assert_eq!(f.bits() >> 63, 0);
    assert_eq!(Features::NONE.bits(), 0);
    assert_eq!(f.without(Features::NONE), f);
    assert_eq!(f.without(f), Features::NONE);
    assert_eq!(Features::NONE.without(f), Features::NONE);

    // Masks reachable through the API: none, all, or what remains after
    // removing either.
    let mask = match input.choose(3) {
        0 => Features::NONE,
        1 => f,
        _ => f.without(f),
    };
    let g = f.without(mask);
    assert_eq!(g.bits(), f.bits() & !mask.bits());
    let debug = format!("{g:?}");
    for ((arch, name, fv), ((_, _, mv), (_, _, gv))) in accessors(f)
        .into_iter()
        .zip(accessors(mask).into_iter().zip(accessors(g)))
    {
        assert_eq!(gv, fv && !mv, "{name}");
        if arch != std::env::consts::ARCH {
            assert!(!fv, "{name} on {}", std::env::consts::ARCH);
        }
        assert_eq!(
            debug.contains(&format!("\"{name}\"")),
            gv,
            "{name} in {debug}"
        );
    }
    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(f.x86_aes(), std::is_x86_feature_detected!("aes"));
        assert_eq!(
            f.x86_pclmulqdq(),
            std::is_x86_feature_detected!("pclmulqdq")
        );
        assert_eq!(f.x86_sha(), std::is_x86_feature_detected!("sha"));
        assert_eq!(f.x86_adx(), std::is_x86_feature_detected!("adx"));
        assert_eq!(f.x86_bmi2(), std::is_x86_feature_detected!("bmi2"));
        assert_eq!(f.x86_avx2(), std::is_x86_feature_detected!("avx2"));
        assert_eq!(f.x86_avx(), std::is_x86_feature_detected!("avx"));
        assert_eq!(f.x86_ssse3(), std::is_x86_feature_detected!("ssse3"));
        assert_eq!(f.x86_sse41(), std::is_x86_feature_detected!("sse4.1"));
    }
    let vlenb = cpu::riscv_vlenb();
    if cfg!(target_arch = "riscv64") && f.rv_v() {
        assert!(vlenb >= 16 && vlenb.is_power_of_two());
    } else {
        assert_eq!(vlenb, 0);
    }
}

fn uses(simd: bool, dedicated: bool) -> Uses {
    Uses { simd, dedicated }
}

/// The kinds a policy requires, as a `Uses`.
fn required(p: Policy) -> Uses {
    uses(
        p.simd == Acceleration::Required,
        p.dedicated == Acceleration::Required,
    )
}

/// Whether `want` is a subset of `have`.
fn subset(want: Uses, have: Uses) -> bool {
    (!want.simd || have.simd) && (!want.dedicated || have.dedicated)
}

/// Checks the outcome of setting `next` over `before` for one algorithm.
fn check_set(alg: Algorithm, before: Policy, next: Policy, result: Result<(), Error>) {
    let status = accel::status(alg);
    assert_eq!(status.algorithm, alg);
    match result {
        Ok(()) => {
            assert_eq!(accel::policy(alg), next, "{alg}");
            assert_eq!(status.policy, next);
            assert!(next.permits(status.uses), "{status}");
            assert!(subset(required(next), status.uses), "{status}");
        }
        Err(e) => {
            assert_eq!(e, Error::Unsupported);
            assert_eq!(accel::policy(alg), before, "failed set changed the policy");
            assert!(
                required(next).any(),
                "{alg}: {next} without Required failed"
            );
        }
    }
    if !subset(required(next), status.available) {
        assert!(result.is_err(), "{alg}: {next} accepted without hardware");
    }
    if !required(next).any() {
        assert!(result.is_ok(), "{alg}: {next} rejected");
    }
}

/// Every status report agrees with the others.
fn check_status() {
    let all = accel::status_all();
    for (alg, s) in Algorithm::ALL.into_iter().zip(all) {
        assert_eq!(s, accel::status(alg));
        assert_eq!(s.algorithm, alg);
        assert_eq!(s.policy, accel::policy(alg));
        assert_eq!(s.accelerated(), s.uses.any());
        assert_eq!(s.accelerated(), s.backend != "portable", "{s}");
        assert!(subset(s.uses, s.available), "{s}");
        assert!(s.policy.permits(s.uses), "{s}");
        assert!(!s.to_string().is_empty());
    }
    let accelerated: Vec<_> = accel::accelerated().map(|s| s.algorithm).collect();
    let expected: Vec<_> = all
        .iter()
        .filter(|s| s.uses.any())
        .map(|s| s.algorithm)
        .collect();
    assert_eq!(accelerated, expected);
    for kind in Kind::ALL {
        let by: Vec<_> = accel::accelerated_by(kind).map(|s| s.algorithm).collect();
        let expected: Vec<_> = all
            .iter()
            .filter(|s| s.uses.get(kind))
            .map(|s| s.algorithm)
            .collect();
        assert_eq!(by, expected, "{kind}");
    }
}

pub(super) fn accel_op(input: &mut Input<'_>) {
    let alg = *input.pick(&Algorithm::ALL);
    let kind = *input.pick(&Kind::ALL);
    let level = *input.pick(&LEVELS);
    let policy = Policy::new(*input.pick(&LEVELS), *input.pick(&LEVELS));
    match input.choose(ACCEL_CALLS) {
        0 => {
            let before = accel::policy(alg);
            let result = accel::set_policy(alg, policy);
            check_set(alg, before, policy, result);
        }
        1 => {
            let before = accel::policy(alg);
            let result = accel::set_kind(alg, kind, level);
            check_set(alg, before, before.with(kind, level), result);
        }
        2 => {
            let before = Algorithm::ALL.map(accel::policy);
            let result = accel::set_policy_all(policy);
            let after = Algorithm::ALL.map(accel::policy);
            match result {
                Ok(()) => assert!(after.iter().all(|p| *p == policy)),
                Err(e) => {
                    assert_eq!(e, Error::Unsupported);
                    assert_eq!(after, before, "failed set_policy_all changed policies");
                    // Some algorithm cannot satisfy it alone either.
                    let unsatisfiable = Algorithm::ALL.into_iter().any(|a| {
                        let old = accel::policy(a);
                        let ok = accel::set_policy(a, policy).is_ok();
                        accel::set_policy(a, old).expect("was set before");
                        !ok
                    });
                    assert!(unsatisfiable);
                }
            }
        }
        3 => {
            let before = Algorithm::ALL.map(accel::policy);
            let result = accel::set_kind_all(kind, level);
            let after = Algorithm::ALL.map(accel::policy);
            match result {
                Ok(()) => {
                    for (b, a) in before.iter().zip(after) {
                        assert_eq!(a, b.with(kind, level));
                    }
                }
                Err(e) => {
                    assert_eq!(e, Error::Unsupported);
                    assert_eq!(after, before, "failed set_kind_all changed policies");
                    assert!(
                        before.iter().any(|p| required(p.with(kind, level)).any()),
                        "set_kind_all failed without a Required kind"
                    );
                }
            }
        }
        4 => {
            // Pure policy algebra against a truth table.
            let u = uses(input.bool(), input.bool());
            let allowed = |l: Acceleration, used: bool| match l {
                Acceleration::Required => used,
                Acceleration::Preferred => true,
                Acceleration::None => !used,
            };
            assert_eq!(
                policy.permits(u),
                allowed(policy.simd, u.simd) && allowed(policy.dedicated, u.dedicated)
            );
            let with = policy.with(kind, level);
            assert_eq!(with.get(kind), level);
            for other in Kind::ALL {
                if other != kind {
                    assert_eq!(with.get(other), policy.get(other));
                }
            }
            assert_eq!(policy.get(Kind::Simd), policy.simd);
            assert_eq!(policy.get(Kind::Dedicated), policy.dedicated);
            assert_eq!(u.get(Kind::Simd), u.simd);
            assert_eq!(u.get(Kind::Dedicated), u.dedicated);
            assert_eq!(u.any(), u.simd || u.dedicated);
            assert_eq!(u.bits(), u8::from(u.simd) | u8::from(u.dedicated) << 1);
            assert!(Policy::PREFERRED.permits(u));
            assert_eq!(Policy::NONE.permits(u), !u.any());
            assert_eq!(Policy::default(), Policy::PREFERRED);
            assert!(!format!("{policy} {u}").is_empty());
        }
        5 => {
            // Names and parsing.
            for phase in [Phase::Steady, Phase::Probing, Phase::Shifting, Phase::Fixed] {
                assert_eq!(phase.name(), phase.to_string());
            }
            assert_eq!(kind.name(), kind.to_string());
            assert_eq!(level.name(), level.to_string());
            assert_eq!(alg.name(), alg.to_string());
            assert_eq!(level.name().parse::<Acceleration>(), Ok(level));
            assert_eq!(
                level.name().to_ascii_uppercase().parse::<Acceleration>(),
                Ok(level)
            );
            let text = String::from_utf8_lossy(input.short_field()).into_owned();
            let expected = if text.eq_ignore_ascii_case("required") {
                Ok(Acceleration::Required)
            } else if text.eq_ignore_ascii_case("preferred")
                || text.eq_ignore_ascii_case("prefered")
            {
                Ok(Acceleration::Preferred)
            } else if text.eq_ignore_ascii_case("none") {
                Ok(Acceleration::None)
            } else {
                Err(Error::Unsupported)
            };
            assert_eq!(text.parse::<Acceleration>(), expected, "{text:?}");
        }
        _ => load_op(input, alg),
    }
    check_status();
    check_load();
}

/// Turns load-aware routing off and checks that nothing of it is left: no
/// configuration, and every stream steady without statistics.
pub(super) fn disable_load() {
    load::disable();
    assert_eq!(load::config(), None);
    for s in load::status_all() {
        assert_eq!(
            (s.phase, s.alternate, s.shifted_percent),
            (Phase::Steady, None, 0),
            "{s}"
        );
        assert_eq!(
            (s.primary_cost, s.baseline_cost, s.alternate_cost),
            (None, None, None),
            "{s}"
        );
    }
}

/// Every `accel::load` report agrees with the others, with the acceleration
/// status and with the configuration.
fn check_load() {
    let config = load::config();
    let mut all = Vec::new();
    for alg in Algorithm::ALL {
        let lanes = load::lanes(alg);
        let selected = accel::status(alg);
        for lane in 0..lanes {
            let s = load::status(alg, lane).expect("a lane below `lanes`");
            assert_eq!((s.algorithm, s.lane), (alg, lane));
            assert_eq!(s.primary, selected.backend, "{s}");
            assert!(!s.name.is_empty(), "{s}");
            assert!(matches!(s.unit, "byte" | "op"), "{s}");
            assert!(s.to_string().contains(s.phase.name()), "{s}");
            assert!(s.shifted_percent <= 100, "{s}");
            if s.phase == Phase::Steady {
                assert_eq!(
                    (s.alternate, s.shifted_percent, s.alternate_cost),
                    (None, 0, None),
                    "{s}"
                );
            } else {
                assert!(config.is_some(), "{s} while routing is disabled");
                assert!(s.alternates > 0, "{s}");
                assert!(s.alternate.is_some_and(|a| a != s.primary), "{s}");
            }
            // The portable backend is every family's last choice, so nothing
            // is left to take its work; and when it may not take shifted
            // work, every alternate is an accelerated backend.
            if !selected.accelerated() {
                assert_eq!(s.alternates, 0, "{s}");
            }
            if config.is_some_and(|c| !c.portable) && s.alternates > 0 {
                assert!(selected.available.any(), "{s}");
            }
            all.push(s);
        }
        assert_eq!(load::status(alg, lanes), None, "{alg}");
    }
    assert_eq!(load::status_all().collect::<Vec<_>>(), all);
}

/// One fuzzed `accel::load` call on a stream of `alg`, with its outcome
/// checked against the documented conditions.
fn load_op(input: &mut Input<'_>, alg: Algorithm) {
    let lane = usize::from(input.byte() % LOAD_INDEXES);
    let alternate = usize::from(input.byte() % LOAD_INDEXES);
    let percent = input.byte();
    let before = load::status(alg, lane);
    assert_eq!(
        before.is_some(),
        lane < load::lanes(alg),
        "{alg} lane {lane}"
    );
    match u8::try_from(input.choose(LOAD_CALLS)).unwrap_or(0) {
        LOAD_ENABLE => {
            let config = load::Config {
                threshold_percent: input.byte(),
                max_shift_percent: input.byte(),
                portable: input.bool(),
            };
            // The fuzz project builds `browntls-crypto` with `std`, which
            // provides the clock.
            assert_eq!(load::enable(config), Ok(()));
            assert_eq!(
                load::config(),
                Some(load::Config {
                    threshold_percent: config.threshold_percent.clamp(20, 200),
                    max_shift_percent: config.max_shift_percent.clamp(1, 93),
                    portable: config.portable,
                })
            );
            assert_eq!(load::Config::default(), load::Config::DEFAULT);
            // Statistics gathered so far are kept.
            let costs =
                |s: Option<load::StreamStatus>| s.map(|s| (s.primary_cost, s.baseline_cost));
            assert_eq!(costs(load::status(alg, lane)), costs(before));
        }
        LOAD_DISABLE => disable_load(),
        LOAD_SET_FIXED => {
            let possible = load::config().is_some()
                && percent <= 100
                && before.is_some_and(|s| alternate < s.alternates);
            let result = load::set_fixed(alg, lane, alternate, percent);
            let after = load::status(alg, lane);
            let call = format!("{alg}: set_fixed({lane}, {alternate}, {percent})");
            match result {
                Ok(()) => {
                    assert!(possible, "{call} succeeded");
                    let s = after.expect("a share was fixed on this stream");
                    assert_eq!(s.phase, Phase::Fixed, "{s}");
                    assert_eq!(s.shifted_percent, percent, "{s}");
                    assert!(s.alternate.is_some_and(|a| a != s.primary), "{s}");
                }
                Err(e) => {
                    assert_eq!(e, Error::Unsupported);
                    assert!(!possible, "{call} failed");
                    assert_eq!(after, before, "{call} failed and changed the stream");
                }
            }
        }
        LOAD_CLEAR_FIXED => {
            load::clear_fixed(alg, lane);
            let after = load::status(alg, lane);
            if before.is_some_and(|s| s.phase == Phase::Fixed) {
                let s = after.expect("the stream had a fixed share");
                assert_eq!(
                    (s.phase, s.alternate, s.shifted_percent),
                    (Phase::Steady, None, 0),
                    "{s}"
                );
            } else {
                // Only a fixed share ends; one hidden by a later policy or
                // configuration was reported as steady already.
                assert_eq!(after, before, "{alg}: clear_fixed({lane})");
            }
        }
        _ => {
            // Every key exchange is timed while routing is enabled, on the
            // primary or on the alternate holding a fixed share, and nothing
            // is timed while it is disabled.
            let _ = x25519::x25519(&[0x42; 32], &x25519::BASEPOINT);
            let s = load::status(Algorithm::X25519, 0).expect("X25519 has a stream");
            assert_eq!(
                s.primary_cost.is_some() || s.alternate_cost.is_some(),
                load::config().is_some(),
                "{s}"
            );
        }
    }
}

pub(super) fn error_op() {
    let all = [
        Error::InvalidKey,
        Error::InvalidLength,
        Error::InvalidEncoding,
        Error::InvalidSignature,
        Error::DecryptFailed,
        Error::KeyAgreementFailed,
        Error::RandomFailure,
        Error::Unsupported,
    ];
    let texts: Vec<String> = all.iter().map(ToString::to_string).collect();
    for (i, t) in texts.iter().enumerate() {
        assert!(!t.is_empty());
        assert!(!texts[..i].contains(t), "duplicate message {t}");
        let e: &dyn std::error::Error = &all[i];
        assert!(e.source().is_none());
    }
}
