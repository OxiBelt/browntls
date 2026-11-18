//! Taking part in Tokio's cooperative scheduling.
//!
//! Tokio gives every task a budget of operations for each time it is
//! polled. Tokio's own resources (sockets, channels, timers) take one unit
//! of it for every operation they complete and, once it is spent, return
//! `Pending` after rescheduling the task, so that a task whose operations
//! are always ready still lets the others run.
//!
//! A TLS stream completes operations its transport knows nothing about (a
//! read served from buffered plaintext, a write the connection buffered),
//! reads records that carry no plaintext for as long as the peer sends
//! them, and may run over a transport that takes no part in the budget at
//! all. So the streams and handshake futures take part themselves:
//!
//! - an operation does nothing and returns `Pending` when the budget is
//!   spent ([`poll_budget`]), and takes one unit when it completes
//!   ([`spend_if_ready`]);
//! - within one poll, every read from the transport after the first takes
//!   one unit ([`poll_proceed`]), which bounds the input one poll works
//!   through.
//!
//! Without the `coop` feature nothing here touches the budget: the checks
//! always pass. Outside a Tokio runtime the budget is unlimited, with the
//! same effect.

use std::task::{Context, Poll};

#[cfg(feature = "coop")]
use tokio::task::coop;

/// One unit of the task's budget, taken by [`poll_proceed`]. Dropping it
/// gives the unit back, unless [`spent`](Self::spent) was called.
#[must_use = "a unit that is not spent returns to the budget"]
pub(crate) struct Unit(#[cfg(feature = "coop")] coop::RestoreOnPending);

impl Unit {
    /// Keeps the unit out of the budget: the step it was taken for moved
    /// on. Anything the step itself took from the budget stays taken too.
    pub(crate) fn spent(self) {
        #[cfg(feature = "coop")]
        self.0.made_progress();
    }
}

/// Takes one unit of the task's budget for a step that may not move on.
/// `Pending`, with the task rescheduled, when the budget is spent.
pub(crate) fn poll_proceed(cx: &mut Context<'_>) -> Poll<Unit> {
    #[cfg(feature = "coop")]
    {
        coop::poll_proceed(cx).map(Unit)
    }
    #[cfg(not(feature = "coop"))]
    {
        let _ = cx;
        Poll::Ready(Unit())
    }
}

/// Whether the task may go on: `Pending`, with the task rescheduled, when
/// its budget is spent. Takes nothing from the budget.
pub(crate) fn poll_budget(cx: &mut Context<'_>) -> Poll<()> {
    #[cfg(feature = "coop")]
    if !coop::has_budget_remaining() {
        // Nothing is left to take, so this reschedules the task and returns
        // `Pending`. Should a unit come back after all, dropping it returns
        // it.
        return coop::poll_proceed(cx).map(drop);
    }
    let _ = cx;
    Poll::Ready(())
}

/// Passes `poll` on, taking one unit of the task's budget when it is
/// `Ready`: the operation completed.
///
/// The unit is taken here rather than held across the operation, as
/// [`poll_proceed`] would have it: a unit that is given back restores the
/// budget as it was when the unit was taken, which would also give back
/// what the transport took meanwhile whenever the operation ends `Pending`.
/// An operation that used up the budget on the way completes for free.
pub(crate) fn spend_if_ready<T>(cx: &mut Context<'_>, poll: Poll<T>) -> Poll<T> {
    #[cfg(feature = "coop")]
    if poll.is_ready()
        && coop::has_budget_remaining()
        && let Poll::Ready(unit) = coop::poll_proceed(cx)
    {
        unit.made_progress();
    }
    let _ = cx;
    poll
}

/// Runs one operation under the task's budget: not at all when the budget
/// is spent, and for one unit when it completes.
pub(crate) fn budgeted<T>(
    cx: &mut Context<'_>,
    operation: impl FnOnce(&mut Context<'_>) -> Poll<T>,
) -> Poll<T> {
    ready!(poll_budget(cx));
    let poll = operation(cx);
    spend_if_ready(cx, poll)
}
