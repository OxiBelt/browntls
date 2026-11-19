//! Tests of the shift controller with synthetic costs.

use super::*;

const PARAMS: Params = Params {
    threshold: 25,
    max_share: MAX_AUTO_SHARE,
};
/// Slot 0 is the primary; slots 1 and 3 are alternates.
const MASK: u8 = 0b1010;

/// A deterministic stand-in for the callers' unpredictable call words.
struct Calls(u64);

impl Calls {
    fn next(&mut self) -> u64 {
        self.0 += 1;
        mix(self.0 ^ 0x5eed_5eed_5eed_5eed)
    }
}

fn feed(s: &Stream, slot: usize, nanos: u64, times: usize) {
    for _ in 0..times {
        s.observe(slot, 1, nanos, 0, MASK, PARAMS);
    }
}

fn ctl(s: &Stream) -> Ctl {
    s.snapshot().ctl
}

/// The primary's baseline in nanoseconds per unit, rounded.
fn baseline(s: &Stream) -> u64 {
    (picos(s.snapshot().channels[0].1).unwrap() + 500) / 1000
}

/// Whether the primary's baseline is within 1% of `nanos`. (The first
/// slow samples of a run move it by a thousandth each.)
fn baseline_is(s: &Stream, nanos: u64) -> bool {
    baseline(s).abs_diff(nanos) <= nanos / 100
}

/// Runs `n` calls through the stream with the given cost per slot,
/// returning how many went to each slot.
fn drive(s: &Stream, calls: &mut Calls, n: u64, cost: [u64; SLOTS]) -> [u64; SLOTS] {
    let mut used = [0; SLOTS];
    for _ in 0..n {
        let (slot, sample) = s.decide(calls.next(), 1, 0, MASK);
        used[slot] += 1;
        if sample {
            s.observe(slot, 1, cost[slot], 0, MASK, PARAMS);
        }
    }
    used
}

#[test]
fn control_word_round_trips() {
    for phase in [Phase::Steady, Phase::Probing, Phase::Shifting, Phase::Fixed] {
        let c = Ctl {
            share: 256,
            alt: 7,
            primary: 5,
            phase,
            patience: 200,
            backoff: MAX_BACKOFF,
            cooldown: BASE_COOLDOWN << MAX_BACKOFF,
            quiet: QUIET,
        };
        assert_eq!(Ctl::unpack(c.pack()), c);
        assert_eq!(Phase::from_bits(phase.bits()), phase);
    }
    assert_eq!(Ctl::unpack(0), Ctl::steady(0));
    // No stored word decodes outside the ranges the controller assumes.
    for word in [u64::MAX, 0x1ff, 0xf << 25] {
        let c = Ctl::unpack(word);
        assert!(c.share <= FULL_SHARE && c.backoff <= MAX_BACKOFF, "{c:?}");
        assert!(c.alt < SLOTS && c.primary < SLOTS);
        assert!(BASE_COOLDOWN.checked_shl(c.backoff).is_some());
    }
}

#[test]
fn steady_while_the_cost_is_stable() {
    let s = Stream::op("test");
    let mut calls = Calls(0);
    feed(&s, 0, 1000, 500);
    // Noise below the threshold changes nothing.
    for i in 0..2000u64 {
        s.observe(0, 1, 1000 + (i % 7) * 30, 0, MASK, PARAMS);
    }
    assert_eq!(ctl(&s), Ctl::steady(0));
    assert_eq!(drive(&s, &mut calls, 1000, [1000; SLOTS])[0], 1000);
}

#[test]
fn congestion_shifts_work_to_a_faster_alternate_and_back() {
    let s = Stream::op("test");
    let mut calls = Calls(0);
    let mut cost = [1000; SLOTS];
    cost[1] = 1300;
    assert_eq!(drive(&s, &mut calls, 500, cost)[0], 500);

    // The primary becomes twice as slow; the first alternate is now
    // cheaper, so the share grows to the maximum.
    cost[0] = 2000;
    let used = drive(&s, &mut calls, 2000, cost);
    let c = ctl(&s);
    assert_eq!(
        (c.phase, c.alt, c.share),
        (Phase::Shifting, 1, MAX_AUTO_SHARE)
    );
    assert!(used[1] > used[0], "{used:?}");
    assert_eq!(used[3], 0, "the second alternate is not needed");
    // The baseline did not follow the congestion.
    assert!(baseline_is(&s, 1000), "{}", baseline(&s));
    // The share is the fraction of calls, on average.
    let window = drive(&s, &mut calls, 25_600, cost);
    let expected = 100 * u64::from(MAX_AUTO_SHARE);
    assert!(window[1].abs_diff(expected) < 300, "{window:?}");

    // The primary recovers: everything returns to it.
    cost[0] = 1000;
    drive(&s, &mut calls, 2000, cost);
    assert_eq!(ctl(&s), Ctl::steady(0));
    assert_eq!(drive(&s, &mut calls, 500, cost)[0], 500);
}

#[test]
fn nothing_is_shifted_to_a_slower_alternate() {
    let s = Stream::op("test");
    let mut calls = Calls(0);
    let mut cost = [1000; SLOTS];
    cost[1] = 5000;
    cost[3] = 9000;
    drive(&s, &mut calls, 500, cost);
    cost[0] = 2000;
    let used = drive(&s, &mut calls, 4000, cost);
    // Each alternate got its probes and nothing else.
    for alt in [1, 3] {
        assert!((u64::from(PROBES)..=3 * u64::from(PROBES)).contains(&used[alt]));
    }
    let c = ctl(&s);
    assert_eq!((c.phase, c.share, c.backoff), (Phase::Steady, 0, 1));
    // The slow level is the new baseline, so it is not probed again.
    assert!(baseline_is(&s, 2000), "{}", baseline(&s));
    let used = drive(&s, &mut calls, 4000, cost);
    assert_eq!(used[0], 4000);
    // When the slow level ends the baseline follows it down again, long
    // before it would follow a rise.
    cost[0] = 1000;
    drive(&s, &mut calls, 2000, cost);
    assert!(baseline(&s) < 1010, "{}", baseline(&s));
}

#[test]
fn a_slow_level_is_accepted_in_bounded_steps() {
    let s = Stream::op("test");
    let mut calls = Calls(0);
    let mut cost = [1000; SLOTS];
    cost[1] = 1_000_000;
    cost[3] = 1_000_000;
    drive(&s, &mut calls, 500, cost);
    // Fifteen times slower: each fruitless episode doubles the baseline
    // at most, and the pause before the next doubles as well.
    cost[0] = 15_000;
    let mut probes = 0;
    for (episode, expected) in [(1, 2000), (2, 4000), (3, 8000), (4, 15_000)] {
        let mut left = 2 * (u64::from(BASE_COOLDOWN) << episode);
        while ctl(&s).backoff < episode {
            let used = drive(&s, &mut calls, 1, cost);
            probes += used[1] + used[3];
            left -= 1;
            assert!(left > 0, "episode {episode} did not end");
        }
        assert_eq!(ctl(&s).backoff, episode);
        assert!(baseline_is(&s, expected), "{}", baseline(&s));
    }
    assert!(probes <= 4 * 2 * 3 * u64::from(PROBES), "{probes}");
    // Accepted: nothing more happens, and the pauses are forgotten one
    // doubling per quiet stretch.
    let n = 5 * u64::from(QUIET) + (u64::from(BASE_COOLDOWN) << 4);
    assert_eq!(drive(&s, &mut calls, n, cost)[0], n);
    assert_eq!(ctl(&s), Ctl::steady(0));
}

#[test]
fn a_slowdown_during_a_pause_is_not_absorbed() {
    let s = Stream::op("test");
    let mut calls = Calls(0);
    let mut cost = [1000; SLOTS];
    cost[1] = 1300;
    cost[3] = 9000;
    drive(&s, &mut calls, 500, cost);
    // The stream is in its longest pause when the primary becomes
    // congested for good.
    let paused = Ctl {
        backoff: MAX_BACKOFF,
        ..Ctl::steady(0)
    }
    .paused(BASE_COOLDOWN);
    s.ctl.store(paused.pack(), Relaxed);
    cost[0] = 1600;
    // (The pause is counted in steps, so its last few calls may already
    // be past it.)
    let n = u64::from(paused.cooldown - 2 * BATCH);
    assert_eq!(drive(&s, &mut calls, n, cost)[0], n);
    assert!(baseline_is(&s, 1000), "{}", baseline(&s));
    // Once the pause is over the congestion is still seen and acted on.
    drive(&s, &mut calls, 2000, cost);
    let c = ctl(&s);
    assert_eq!((c.phase, c.alt), (Phase::Shifting, 1));
}

#[test]
fn congestion_without_an_alternate_is_accepted() {
    let s = Stream::op("test");
    for _ in 0..200 {
        s.observe(0, 1, 1000, 0, 0, PARAMS);
    }
    for _ in 0..40 {
        s.observe(0, 1, 1500, 0, 0, PARAMS);
    }
    let c = ctl(&s);
    assert_eq!((c.phase, c.backoff), (Phase::Steady, 1));
    assert!((1300..=1500).contains(&baseline(&s)), "{}", baseline(&s));
}

#[test]
fn the_second_alternate_is_used_when_the_first_does_not_help() {
    let s = Stream::op("test");
    let mut calls = Calls(0);
    let mut cost = [1000; SLOTS];
    cost[1] = 3000;
    cost[3] = 1200;
    drive(&s, &mut calls, 500, cost);
    cost[0] = 2000;
    let used = drive(&s, &mut calls, 2000, cost);
    let c = ctl(&s);
    assert_eq!((c.phase, c.alt), (Phase::Shifting, 3));
    assert!(used[3] > used[0], "{used:?}");
}

/// The premise of the balancer: a channel has a fixed capacity, so its
/// cost falls as work leaves it. The primary costs 2000 with all of the
/// work and 1000 with none; the alternate always costs `alt`. Every
/// timed call is off by up to `jitter` percent. Returns the mean cost of
/// a call over the second half of the run.
fn capacity_model(stream: &Stream, units: usize, alt: u64, jitter: u64) -> u64 {
    let mut calls = Calls(0);
    let mut noise = Calls(1 << 40);
    let rounds = 400_000u64;
    let mut total = 0u64;
    for i in 0..rounds {
        let share = u64::from(ctl(stream).share);
        let primary = if i < 4000 {
            1000
        } else {
            1000 + 1000 * (256 - share) / 256
        };
        let (slot, sample) = stream.decide(calls.next(), units, 0, MASK);
        let cost = if slot == 0 { primary } else { alt };
        if sample {
            let off = cost * jitter / 100;
            let nanos = cost - off + (noise.next() >> 32) % (2 * off + 1);
            stream.observe(slot, units, nanos * units as u64, 0, MASK, PARAMS);
        }
        if i >= rounds / 2 {
            total += cost;
        }
    }
    total / (rounds / 2)
}

#[test]
fn the_share_settles_where_the_costs_meet() {
    // Without routing every call costs 2000. The best fixed split makes
    // both backends cost the same: the alternate's cost.
    for (alt, jitter, bound) in [
        (1200, 0, 1230),
        (1400, 0, 1440),
        (1400, 10, 1440),
        (1600, 0, 1650),
        (1600, 10, 1660),
        (1600, 20, 1700),
    ] {
        let op = capacity_model(&Stream::op("test"), 1, alt, jitter);
        let bulk = capacity_model(&Stream::bulk("test"), 16384, alt, jitter);
        assert!(
            (alt..=bound).contains(&op) && (alt..=bound).contains(&bulk),
            "alternate {alt}, jitter {jitter}%: {op} (op), {bulk} (bulk)"
        );
    }
    // An alternate that barely helps is given up in bad conditions;
    // routing then costs what no routing costs, not more.
    let cost = capacity_model(&Stream::op("test"), 1, 1900, 20);
    assert!((1900..=2010).contains(&cost), "{cost}");
}

#[test]
fn a_helpful_shift_is_not_accepted_as_the_baseline() {
    let s = Stream::op("test");
    capacity_model(&s, 1, 1600, 10);
    let c = ctl(&s);
    assert_eq!(c.phase, Phase::Shifting);
    // With jitter the baseline sits a little below the mean cost.
    assert!((930..=1010).contains(&baseline(&s)), "{}", baseline(&s));
}

#[test]
fn slow_calls_that_alternate_with_normal_ones_are_congestion() {
    let s = Stream::op("test");
    feed(&s, 0, 1000, 200);
    // Three slow calls, one normal one, again and again: no run of slow
    // calls is ever long, but most calls are slow.
    for _ in 0..8 {
        feed(&s, 0, 2000, 3);
        feed(&s, 0, 1000, 1);
    }
    assert_eq!(ctl(&s).phase, Phase::Probing);
    assert!(baseline(&s) < 1010, "{}", baseline(&s));
}

#[test]
fn a_stalled_probe_is_abandoned() {
    let s = Stream::op("test");
    feed(&s, 0, 1000, 200);
    // Only the primary reports: its callers cannot use the alternates.
    feed(&s, 0, 2000, 40);
    assert_eq!(ctl(&s).phase, Phase::Probing);
    feed(&s, 0, 2000, 4 * PROBE_PATIENCE as usize);
    let c = ctl(&s);
    assert_eq!((c.phase, c.backoff), (Phase::Steady, 1));
}

#[test]
fn a_load_that_comes_and_goes_does_not_keep_probing() {
    let s = Stream::op("test");
    let mut calls = Calls(0);
    let mut cost = [1000; SLOTS];
    cost[1] = 6000;
    cost[3] = 6000;
    drive(&s, &mut calls, 500, cost);
    // Ten times slower for 18 calls, normal for 14, again and again:
    // every burst looks like congestion and every gap like recovery.
    let mut used = [0u64; SLOTS];
    for _ in 0..3000 {
        for (len, nanos) in [(18, 10_000), (14, 1000)] {
            cost[0] = nanos;
            for (total, n) in used.iter_mut().zip(drive(&s, &mut calls, len, cost)) {
                *total += n;
            }
        }
    }
    let probes = used[1] + used[3];
    assert!(probes * 200 < used[0], "{used:?}");
}

#[test]
fn a_blip_ends_the_probe() {
    let s = Stream::op("test");
    feed(&s, 0, 1000, 200);
    feed(&s, 0, 2000, 40);
    assert_eq!(ctl(&s).phase, Phase::Probing);
    feed(&s, 0, 1000, 40);
    let c = ctl(&s);
    assert_eq!((c.phase, c.backoff), (Phase::Steady, 1));
    assert!(c.cooldown > 0 && c.cooldown < BASE_COOLDOWN);
    assert!(baseline_is(&s, 1000), "{}", baseline(&s));
}

#[test]
fn outliers_are_clamped() {
    let s = Stream::op("test");
    feed(&s, 0, 1000, 200);
    // One call descheduled for 10 ms counts as four times the baseline,
    // moves the baseline by a thousandth at most, and is not congestion.
    for _ in 0..50 {
        s.observe(0, 1, 10_000_000, 0, MASK, PARAMS);
        let (fast, _, _) = s.snapshot().channels[0];
        assert!(picos(fast).unwrap() < 1_500_000, "{fast}");
        assert!(baseline(&s) < 1020, "{}", baseline(&s));
        feed(&s, 0, 1000, 15);
        assert_eq!(ctl(&s).phase, Phase::Steady);
    }
    // A run of them is.
    feed(&s, 0, 10_000_000, RUN as usize);
    assert_eq!(ctl(&s).phase, Phase::Probing);
}

#[test]
fn an_early_outlier_does_not_set_the_baseline() {
    // The very first call is interrupted, or runs cold.
    let s = Stream::op("test");
    s.observe(0, 1, 100_000, 0, MASK, PARAMS);
    feed(&s, 0, 1000, 39);
    assert!(baseline_is(&s, 1000), "{}", baseline(&s));
    // So is one of the next few: it is clamped.
    let s = Stream::op("test");
    feed(&s, 0, 1000, 3);
    s.observe(0, 1, 100_000, 0, MASK, PARAMS);
    feed(&s, 0, 1000, 36);
    assert!(baseline(&s) < 1100, "{}", baseline(&s));
    // A real congestion is then still found.
    feed(&s, 0, 2000, 40);
    assert_eq!(ctl(&s).phase, Phase::Probing);
    // Only a first sample is ever discarded: a workload that keeps
    // alternating between two levels still gets a baseline.
    let s = Stream::op("test");
    for _ in 0..100 {
        feed(&s, 0, 1000, 1);
        feed(&s, 0, 10_000, 2);
    }
    assert_eq!(s.snapshot().channels[0].2, 300);
}

#[test]
fn a_policy_change_starts_over() {
    let s = Stream::op("test");
    let mut calls = Calls(0);
    let mut cost = [1000; SLOTS];
    cost[1] = 1200;
    drive(&s, &mut calls, 500, cost);
    cost[0] = 2000;
    drive(&s, &mut calls, 2000, cost);
    assert_eq!(ctl(&s).phase, Phase::Shifting);
    // The alternate is no longer a candidate: calls stay on the primary
    // at once, and the next sample resets the controller.
    for word in [0, u64::MAX, calls.next()] {
        assert_eq!(s.decide(word, 1, 0, 0b1000), (0, true));
    }
    s.observe(0, 1, 2000, 0, 0b1000, PARAMS);
    assert_eq!(ctl(&s), Ctl::steady(0));
    // Another primary: the same.
    drive(&s, &mut calls, 3000, cost);
    assert_ne!(ctl(&s).phase, Phase::Steady);
    for word in [0, u64::MAX, calls.next()] {
        assert_eq!(s.decide(word, 1, 3, 0b0011).0, 3);
    }
    s.observe(3, 1, 2000, 3, 0b0011, PARAMS);
    assert_eq!(ctl(&s), Ctl::steady(3));
}

#[test]
fn fixed_shares_ignore_measurements() {
    let s = Stream::op("test");
    let mut calls = Calls(0);
    let mut cost = [1000; SLOTS];
    cost[3] = 1_000_000;
    for share in [0u32, 1, 64, 128, 255, 256] {
        s.fix(0, 3, share);
        let n = 256 * 400;
        let used = drive(&s, &mut calls, n, cost);
        let expected = u64::from(share) * 400;
        // Exact at the ends, and the fraction of calls in between.
        let tolerance = if share == 0 || share == 256 { 0 } else { 900 };
        assert!(
            used[3].abs_diff(expected) <= tolerance,
            "share {share}: {used:?}"
        );
        assert_eq!(used[0] + used[3], n);
        assert_eq!(ctl(&s).phase, Phase::Fixed);
    }
    // A fixed alternate outside the candidates is not used.
    assert_eq!(s.decide(0, 1, 0, 0b0010).0, 0);
    s.release();
    assert_eq!(ctl(&s), Ctl::steady(0));
    // `release` leaves a measured shift alone.
    let mut cost = [1000; SLOTS];
    cost[1] = 1200;
    s.reset();
    drive(&s, &mut calls, 500, cost);
    cost[0] = 2000;
    drive(&s, &mut calls, 2000, cost);
    s.release();
    assert_eq!(ctl(&s).phase, Phase::Shifting);
    s.reset();
    assert_eq!(s.snapshot().channels, [(0, 0, 0); SLOTS]);
}

#[test]
fn bulk_streams_time_one_long_call_in_sixteen() {
    let s = Stream::bulk("test");
    let mut calls = Calls(0);
    let mut sampled = |len| {
        (0..16_000)
            .filter(|_| s.decide(calls.next(), len, 0, MASK).1)
            .count()
    };
    assert_eq!(sampled(4095), 0);
    assert!(sampled(4096).abs_diff(1000) < 150);
    // Cost is per byte: the same throughput at two sizes is one cost.
    s.observe(0, 4096, 4096, 0, MASK, PARAMS);
    s.observe(0, 16384, 16384, 0, MASK, PARAMS);
    let (fast, slow, n) = s.snapshot().channels[0];
    assert_eq!((picos(fast), picos(slow), n), (Some(1000), Some(1000), 2));
    assert_eq!((s.name(), s.unit()), ("test", "byte"));
    // Degenerate observations are ignored or clamped.
    s.observe(0, 0, 5, 0, MASK, PARAMS);
    s.observe(SLOTS, 1, 5, 0, MASK, PARAMS);
    s.observe(0, usize::MAX, u64::MAX, 0, MASK, PARAMS);
    s.observe(0, 1, u64::MAX, 0, MASK, PARAMS);
    assert_eq!(s.snapshot().channels[0].2, 4);
}

#[test]
fn short_calls_are_not_shifted() {
    let s = Stream::bulk("test");
    let mut calls = Calls(0);
    let mut run = |s: &Stream, n: u64, len: usize, primary_ps: u64| {
        let mut used = [0u64; SLOTS];
        for _ in 0..n {
            let (slot, sample) = s.decide(calls.next(), len, 0, MASK);
            used[slot] += 1;
            if sample {
                let ps = if slot == 0 { primary_ps } else { 120 };
                s.observe(slot, len, ps * len as u64 / 1000, 0, MASK, PARAMS);
            }
        }
        used
    };
    run(&s, 2000, 16384, 100);
    let used = run(&s, 12_000, 16384, 200);
    assert_eq!(ctl(&s).phase, Phase::Shifting);
    assert!(used[1] > used[0], "{used:?}");
    // Short records are never timed, so they stay on the primary while
    // the long ones are shifted, and nothing changes the state.
    let before = ctl(&s);
    assert_eq!(run(&s, 1000, 4095, 200)[0], 1000);
    assert_eq!(ctl(&s), before);
    assert!(s.passes(4095) && !s.passes(4096));
    // Unless the share was fixed by hand.
    s.fix(0, 1, FULL_SHARE);
    assert!(!s.passes(1));
    assert_eq!(run(&s, 100, 1, 200)[1], 100);
}

#[test]
fn the_choices_of_a_call_are_independent() {
    // Shifted and timed calls are picked by separate bits of the call's
    // word, so timing does not favour one backend.
    let s = Stream::bulk("test");
    let mut calls = Calls(0);
    s.fix(0, 1, 128);
    let (mut shifted, mut timed, mut both) = (0u64, 0u64, 0u64);
    let n = 64_000;
    for _ in 0..n {
        let (slot, sample) = s.decide(calls.next(), 16384, 0, MASK);
        shifted += u64::from(slot == 1);
        timed += u64::from(sample);
        both += u64::from(slot == 1 && sample);
    }
    assert!(shifted.abs_diff(n / 2) < 1000, "{shifted}");
    assert!(timed.abs_diff(n / 16) < 400, "{timed}");
    assert!(both.abs_diff(n / 32) < 300, "{both}");
}

#[test]
fn placed_work_follows_the_share_and_is_timed_where_it_is() {
    // Slot 0 is the primary and slot 1 its only alternate, as for work
    // that is placed as a whole (`super::super::kernel`).
    const ONE: u8 = 0b10;
    const LEN: usize = 16384;
    let s = Stream::bulk("test");
    let mut calls = Calls(0);
    let mut placed = |s: &Stream, n: u64| {
        (0..n)
            .filter(|_| s.place(calls.next(), 0, ONE) == 1)
            .count()
    };
    let mut calls = Calls(1 << 40);
    let mut timed = |s: &Stream, len, slot| {
        (0..16_000)
            .filter(|_| s.timed(calls.next(), len, slot))
            .count()
    };
    let observe = |slot, ps: u64| s.observe(slot, LEN, ps * LEN as u64 / 1000, 0, ONE, PARAMS);

    // Steady: everything is placed on the primary; on either slot one
    // long call in sixteen is timed and no short one.
    assert_eq!(placed(&s, 1000), 0);
    for slot in [0, 1] {
        assert!(timed(&s, LEN, slot).abs_diff(1000) < 150);
        assert_eq!(timed(&s, 4095, slot), 0);
    }
    assert!(s.measurable(4096) && !s.measurable(4095));

    // A fixed share is the fraction of the placements.
    for (share, tolerance) in [(0, 0), (64, 300), (FULL_SHARE, 0)] {
        s.fix(0, 1, share);
        let expected = 100 * share as usize;
        assert!(placed(&s, 25_600).abs_diff(expected) <= tolerance);
        assert!(timed(&s, LEN, 1).abs_diff(1000) < 150);
    }
    s.release();

    // Probing: the first placements all go to the alternate until it has
    // its samples, then one in eight. Until then its long calls are all
    // timed, as nothing else would measure it, and the primary is timed
    // more often than when steady.
    for _ in 0..500 {
        observe(0, 100);
    }
    while ctl(&s).phase == Phase::Steady {
        observe(0, 200);
    }
    assert_eq!((ctl(&s).phase, ctl(&s).alt), (Phase::Probing, 1));
    assert_eq!(placed(&s, u64::from(PLACED_PROBES)), PLACED_PROBES as usize);
    assert!(placed(&s, 800).abs_diff(100) < 40);
    assert_eq!(timed(&s, LEN, 1), 16_000);
    assert_eq!(timed(&s, 4095, 1), 0);
    assert!(timed(&s, LEN, 0).abs_diff(4000) < 300);
    for _ in 0..PROBES {
        observe(1, 120);
    }
    assert_eq!(ctl(&s).phase, Phase::Probing);
    assert!(timed(&s, LEN, 1).abs_diff(4000) < 300);
    assert!(placed(&s, 1600).abs_diff(200) < 60);

    // The alternate measured cheaper: the share of the placements grows
    // to the limit and comes back when the primary has recovered.
    for _ in 0..400 {
        observe(0, 200);
    }
    let c = ctl(&s);
    assert_eq!((c.phase, c.share), (Phase::Shifting, MAX_AUTO_SHARE));
    let expected = 100 * MAX_AUTO_SHARE as usize;
    assert!(placed(&s, 25_600).abs_diff(expected) < 300);
    assert!(timed(&s, LEN, 1).abs_diff(4000) < 300);
    for _ in 0..400 {
        observe(0, 100);
    }
    assert_eq!(ctl(&s).phase, Phase::Steady);
    assert_eq!(placed(&s, 1000), 0);
}

#[test]
fn concurrent_observers_keep_the_state_in_range() {
    let s = Stream::op("test");
    std::thread::scope(|scope| {
        for t in 0..4u64 {
            let s = &s;
            scope.spawn(move || {
                let mut calls = Calls(t << 32);
                for i in 0..200_000u64 {
                    // The policy and the load change under the threads.
                    let (primary, mask) = if (i >> 14) % 3 == 2 {
                        (1, 0b1000)
                    } else {
                        (0, MASK)
                    };
                    let (slot, sample) = s.decide(calls.next(), 1, primary, mask);
                    assert!(slot == primary || mask & (1 << slot) != 0);
                    if sample {
                        let nanos = if (i >> 11) % 2 == 0 { 1000 } else { 3000 + t };
                        s.observe(slot, 1, nanos, primary, mask, PARAMS);
                    }
                    if i % 50_000 == 49_999 {
                        s.fix(primary, 3, 77);
                        s.release();
                    }
                    let c = ctl(s);
                    assert!(c.share <= FULL_SHARE && c.backoff <= MAX_BACKOFF);
                    assert!(c.cooldown <= BASE_COOLDOWN << MAX_BACKOFF);
                }
            });
        }
    });
}

#[test]
fn a_probe_of_placed_work_ends_without_samples() {
    const ONE: u8 = 0b10;
    const LEN: usize = 16384;
    for alternate_timed in [false, true] {
        let s = Stream::bulk("test");
        let mut calls = Calls(0);
        let observe = |slot, ps: u64| s.observe(slot, LEN, ps * LEN as u64 / 1000, 0, ONE, PARAMS);
        for _ in 0..500 {
            observe(0, 100);
        }
        while ctl(&s).phase == Phase::Steady {
            observe(0, 200);
        }
        if alternate_timed {
            for _ in 0..PROBES {
                observe(1, 50);
            }
        }
        let accepted = s.snapshot().channels[0].1;

        // The work the primary had is done, and what is placed from now
        // on makes no call long enough to time: no sample ends the probe.
        // The alternate gets its first placements and then one in eight.
        let kept = (0..PLACE_PATIENCE)
            .filter(|_| s.place(calls.next(), 0, ONE) == 1)
            .count();
        assert_eq!(ctl(&s).phase, Phase::Probing);
        let forced = if alternate_timed { 0 } else { PLACED_PROBES };
        let expected = (forced + (PLACE_PATIENCE - forced) / 8) as usize;
        assert!(kept.abs_diff(expected) < 100, "{kept}, not {expected}");

        // The placements end it: the primary's level is accepted and the
        // stream pauses, everything on the primary.
        assert_eq!(s.place(calls.next(), 0, ONE), 0);
        let c = ctl(&s);
        assert_eq!((c.phase, c.share), (Phase::Steady, 0));
        assert!(s.snapshot().channels[0].1 > accepted);
        assert!((0..1000).all(|_| s.place(calls.next(), 0, ONE) == 0));
    }
}
