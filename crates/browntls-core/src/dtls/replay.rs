//! The anti-replay window of one epoch (RFC 9147 §4.5.1).
//!
//! This is the sliding window of RFC 4303 §3.4.3: its right edge is the
//! highest sequence number received in the epoch, and a bitmap records which
//! of the [`WINDOW`] numbers ending there were received. Anything left of the
//! window is taken as a replay.

/// How many sequence numbers, ending at the highest received, the window
/// remembers: the bits of a `u128`. RFC 9147 §4.5.1 asks for enough to cover
/// any plausible reordering; 128 records is twice the 64 that RFC 4303
/// recommends.
pub(crate) const WINDOW: u64 = u128::BITS as u64;

/// The anti-replay window of one epoch (RFC 9147 §4.5.1).
#[derive(Debug, Clone)]
pub(crate) struct ReplayWindow {
    /// The highest sequence number marked, if any.
    highest: Option<u64>,
    /// Bit `i` is set when `highest - i` was marked.
    bits: u128,
}

impl ReplayWindow {
    pub(crate) fn new() -> Self {
        Self {
            highest: None,
            bits: 0,
        }
    }

    /// The highest sequence number marked, if any.
    pub(crate) fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Whether `seq` was neither marked nor falls below the window (too
    /// old).
    pub(crate) fn is_new(&self, seq: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        match highest.checked_sub(seq) {
            // Right of the window.
            None => true,
            Some(behind) if behind < WINDOW => self.bits & (1 << behind) == 0,
            // Left of the window.
            Some(_) => false,
        }
    }

    /// Marks `seq` received. Call it only once the record authenticated
    /// (RFC 9147 §4.5.1). Marking a number left of the window does nothing.
    pub(crate) fn mark(&mut self, seq: u64) {
        let Some(highest) = self.highest else {
            self.highest = Some(seq);
            self.bits = 1;
            return;
        };
        match highest.checked_sub(seq) {
            None => {
                // `seq > highest`: slide the window right.
                let kept = match u32::try_from(seq - highest) {
                    Ok(shift) if shift < u128::BITS => self.bits << shift,
                    _ => 0,
                };
                self.bits = kept | 1;
                self.highest = Some(seq);
            }
            Some(behind) if behind < WINDOW => self.bits |= 1 << behind,
            Some(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_record() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.highest(), None);
        assert!(window.is_new(0));
        assert!(window.is_new(u64::MAX));
        window.mark(5);
        assert_eq!(window.highest(), Some(5));
        assert!(!window.is_new(5));
        // Below the first record but within the window: still new.
        for seq in 0..5 {
            assert!(window.is_new(seq), "{seq}");
        }
        assert!(window.is_new(6));
    }

    #[test]
    fn reordering_and_duplicates() {
        let mut window = ReplayWindow::new();
        for seq in [3, 1, 7, 2, 0, 7, 3] {
            window.mark(seq);
        }
        assert_eq!(window.highest(), Some(7));
        for seq in 0..=10 {
            let marked = matches!(seq, 0..=3 | 7);
            assert_eq!(window.is_new(seq), !marked, "{seq}");
        }
        // Marking the same number again changes nothing.
        let before = window.clone();
        window.mark(2);
        assert_eq!(window.bits, before.bits);
        assert_eq!(window.highest(), before.highest());
    }

    #[test]
    fn exactly_at_the_window_edge() {
        let mut window = ReplayWindow::new();
        window.mark(1000);
        // The oldest number still in the window, and the first out of it.
        let oldest = 1000 - (WINDOW - 1);
        assert!(window.is_new(oldest));
        assert!(!window.is_new(oldest - 1));
        window.mark(oldest);
        assert!(!window.is_new(oldest));
        // Marking left of the window is ignored.
        window.mark(oldest - 1);
        assert!(!window.is_new(oldest - 1));
        assert_eq!(window.highest(), Some(1000));
        // One step right pushes `oldest` out; its neighbour stays new.
        window.mark(1001);
        assert!(!window.is_new(oldest));
        assert!(window.is_new(oldest + 1));
        // A shift by exactly the window width keeps only the new number.
        window.mark(1001 + WINDOW);
        assert!(!window.is_new(1001));
        assert!(window.is_new(1002));
        assert!(!window.is_new(1001 + WINDOW));
    }

    #[test]
    fn shift_keeps_marks_in_place() {
        let mut window = ReplayWindow::new();
        window.mark(10);
        window.mark(8);
        window.mark(50);
        assert!(!window.is_new(10));
        assert!(!window.is_new(8));
        assert!(window.is_new(9));
        assert!(!window.is_new(50));
        assert!(window.is_new(49));
    }

    #[test]
    fn big_jumps_and_u64_max() {
        let mut window = ReplayWindow::new();
        window.mark(0);
        window.mark(u64::MAX - 1);
        assert_eq!(window.highest(), Some(u64::MAX - 1));
        assert!(!window.is_new(0));
        assert!(!window.is_new(u64::MAX - 1));
        assert!(window.is_new(u64::MAX - 2));
        assert!(window.is_new(u64::MAX));
        window.mark(u64::MAX);
        assert!(!window.is_new(u64::MAX));
        assert!(!window.is_new(u64::MAX - 1));
        assert!(!window.is_new(u64::MAX - WINDOW));
        assert!(window.is_new(u64::MAX - (WINDOW - 1)));
        // Nothing is right of the window any more.
        window.mark(u64::MAX);
        assert_eq!(window.highest(), Some(u64::MAX));

        let mut window = ReplayWindow::new();
        window.mark(u64::MAX);
        assert!(window.is_new(u64::MAX - 1));
        assert!(!window.is_new(0));
        window.mark(0);
        assert!(!window.is_new(0));
        assert_eq!(window.highest(), Some(u64::MAX));

        // Jumps just past a `u32` shift.
        let mut window = ReplayWindow::new();
        window.mark(1);
        window.mark(1 + (1 << 32));
        assert!(!window.is_new(1));
        assert!(window.is_new(1 << 32));
    }
}
