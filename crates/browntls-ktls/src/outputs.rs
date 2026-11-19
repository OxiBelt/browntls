//! The connection's outputs that wait for room on the socket, with what
//! they cost in memory, so that reading can stop before a peer that asks
//! for answers without reading them makes the queue grow without bound.

use std::collections::VecDeque;
use std::mem::size_of;

use browntls::kernel::KernelOutput;

/// The most the waiting outputs may cost before reading stops: the
/// userspace connection's cap on unwritten control records
/// (`DEFAULT_BUFFER_LIMIT`, 64 KiB).
pub(crate) const BUDGET: usize = 64 * 1024;

/// Outputs (control records, transmit keys) waiting behind a record the
/// socket had no room for, in order. New receive keys never wait: the
/// engine installs them at once.
#[derive(Default)]
pub(crate) struct Waiting {
    queue: VecDeque<KernelOutput>,
    /// The sum of [`cost`] over `queue`.
    cost: usize,
}

impl Waiting {
    pub(crate) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub(crate) fn front(&self) -> Option<&KernelOutput> {
        self.queue.front()
    }

    pub(crate) fn pop_front(&mut self) -> Option<KernelOutput> {
        let output = self.queue.pop_front()?;
        self.cost = self.cost.saturating_sub(cost(&output));
        Some(output)
    }

    pub(crate) fn push_back(&mut self, output: KernelOutput) {
        debug_assert!(
            !matches!(output, KernelOutput::RxKeys(_)),
            "receive keys are installed at once"
        );
        self.cost = self.cost.saturating_add(cost(&output));
        self.queue.push_back(output);
    }

    pub(crate) fn clear(&mut self) {
        self.queue.clear();
        self.cost = 0;
    }

    /// Whether the waiting outputs cost more than [`BUDGET`].
    pub(crate) fn over_budget(&self) -> bool {
        self.cost > BUDGET
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }
}

/// What a waiting output holds in memory: the output itself and a record's
/// payload.
fn cost(output: &KernelOutput) -> usize {
    let payload = match output {
        KernelOutput::Record { payload, .. } => payload.len(),
        _ => 0,
    };
    size_of::<KernelOutput>().saturating_add(payload)
}

#[cfg(test)]
mod tests {
    use browntls::crypto::cipher::{AeadKey, Iv};
    use browntls::kernel::KernelOutput;
    use browntls::{ConnectionTrafficSecrets, ContentType};

    use super::{BUDGET, Waiting, cost};

    fn key_update() -> KernelOutput {
        KernelOutput::Record {
            typ: ContentType::Handshake,
            payload: vec![24, 0, 0, 1, 0],
        }
    }

    fn tx_keys() -> KernelOutput {
        KernelOutput::TxKeys(ConnectionTrafficSecrets::Aes128Gcm {
            key: AeadKey::new(&[0; 16]),
            iv: Iv::new([0; 12]),
        })
    }

    #[test]
    fn records_cost_their_payload_and_keys_their_size() {
        let mut waiting = Waiting::default();
        waiting.push_back(key_update());
        waiting.push_back(tx_keys());
        assert_eq!(
            waiting.cost,
            2 * size_of::<KernelOutput>() + 5,
            "a KeyUpdate answer and its keys"
        );
        assert_eq!(cost(&tx_keys()), size_of::<KernelOutput>());
    }

    #[test]
    fn key_update_answers_pass_the_budget_after_a_bounded_number() {
        let per_answer = cost(&key_update()) + cost(&tx_keys());
        let mut waiting = Waiting::default();
        let mut answers = 0;
        while !waiting.over_budget() {
            waiting.push_back(key_update());
            waiting.push_back(tx_keys());
            answers += 1;
        }
        assert_eq!(answers, BUDGET / per_answer + 1);
        assert!(answers < 600, "{answers} answers fit");
        assert_eq!(waiting.len(), 2 * answers);
    }

    #[test]
    fn taking_and_clearing_return_the_cost() {
        let mut waiting = Waiting::default();
        let big = KernelOutput::Record {
            typ: ContentType::Handshake,
            payload: vec![0; BUDGET],
        };
        waiting.push_back(big);
        assert!(waiting.over_budget());
        waiting.push_back(tx_keys());
        assert!(waiting.pop_front().is_some());
        assert!(!waiting.over_budget());
        assert_eq!(waiting.cost, size_of::<KernelOutput>());
        waiting.clear();
        assert!(waiting.is_empty());
        assert_eq!(waiting.cost, 0);
    }
}
