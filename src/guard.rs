//! # The guard: persist BEFORE signing
//!
//! `hbs-state` is **the index guard for stateful hash-based
//! signatures**, extracted from `zk-ssl-guardian` (§296 of Arqueo): a
//! monotonic counter persisted with `fsync`, which refuses to operate where
//! `fsync` does not persist (tmpfs) and which reconciles its state after a
//! restart in four cases, of which only one is fatal.
//!
//! ⚠️ **It is not a tree-state manager**, and it is worth saying so because
//! the initial hypothesis described it that way. What it brings to an MTC
//! CA is the **invariant**, which applies twice here:
//!
//! 1. **The checkpoint number.** The CA persists the number of the checkpoint
//!    it is about to sign BEFORE signing it. If the process dies in between,
//!    the number is left orphaned (normal case, `CounterAhead`); if at
//!    start-up the log's journal is ahead of the counter (`KeyAhead`),
//!    someone signed without going through the guard and **we do not start**.
//!
//!    ⚠️ **What it protects, stated precisely:** the number does NOT go into
//!    the signed message (the draft's `CosignedMessage` has no room for
//!    it), so the guard **does not prevent** the CA from signing two
//!    different views of the log: witnesses detect that with consistency
//!    proofs, and that is their role. What the guard gives is a **durable
//!    record, prior to each signature**, with which at start-up one knows
//!    how many checkpoint signatures may have gone out and how many the
//!    journal recorded, in order to rebuild the log up to a state that covers
//!    them and not publish an inconsistent view by carelessness. It is the
//!    same invariant as in XMSS and the same reconciliation; what changes is
//!    the consequence of breaking it: there a key leaks, here trust is lost.
//! 2. **The signature index**, if the CA's cosigner is XMSS/LMS: there it
//!    is used as is, as in `FirmanteCabeza`.
//!
//! [`SequenceGuard`] is the minimal interface the CA needs;
//! `hbs_state::IndexGuard` implements it without an adapter, and [`MemoryGuard`]
//! exists **only for tests**: it persists nothing and says so.

pub use hbs_state::{is_fatal, reconcile_values, GuardError, IndexGuard, Reconciliation};

/// A monotonic counter whose reserved value survives the process.
pub trait SequenceGuard {
    /// Persists `current + 1` and returns it; **only then** is anything signed.
    fn reserve(&mut self) -> Result<u64, GuardError>;
    /// The last persisted value. Never goes backwards.
    fn current(&self) -> u64;
    /// Compares the counter with what the log's journal claims to have
    /// published. Only `KeyAhead` is fatal ([`is_fatal`]).
    fn reconcile(&self, observed: u64) -> Reconciliation {
        reconcile_values(self.current(), observed)
    }
}

impl SequenceGuard for IndexGuard {
    fn reserve(&mut self) -> Result<u64, GuardError> {
        IndexGuard::reserve(self)
    }
    fn current(&self) -> u64 {
        IndexGuard::current(self)
    }
}

/// ⚠️ **Does not persist.** For tests and for measuring without disk. A CA
/// that starts with this will reuse checkpoint numbers after every crash.
#[derive(Debug, Default)]
pub struct MemoryGuard {
    current: u64,
}

impl SequenceGuard for MemoryGuard {
    fn reserve(&mut self) -> Result<u64, GuardError> {
        self.current = self
            .current
            .checked_add(1)
            .ok_or_else(|| GuardError::Io("the counter overflowed".into()))?;
        Ok(self.current)
    }
    fn current(&self) -> u64 {
        self.current
    }
}

/// What a CA decides at start-up after comparing the guard with the log's
/// journal: the last checkpoint number the journal recorded as published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupDecision {
    /// Start. `orphans` is how many reserved numbers never reached the
    /// journal: the normal case after a crash between reserving and signing.
    Start { orphans: u64 },
    /// Do not start, and say why.
    Refuse(StartupRefusal),
}

/// The two states in which the pair (counter, journal) forbids starting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupRefusal {
    /// The journal recorded a checkpoint the counter never reserved: the
    /// counter file was deleted (`IndexGuard::open` recreates a missing
    /// file at zero, silently) or restored from an older copy. Starting
    /// would reuse checkpoint numbers behind published signatures.
    CounterBehindJournal { counter: u64, journal: u64 },
    /// The counter reserved checkpoints but the journal has none: the log
    /// was lost or restored from before its first checkpoint. Starting
    /// would publish a tree inconsistent with signatures already out.
    JournalMissing { counter: u64 },
}

impl core::fmt::Display for StartupRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StartupRefusal::CounterBehindJournal { counter, journal } => write!(
                f,
                "the journal recorded checkpoint {journal} but the counter only reserved {counter}: \
                 counter deleted or restored; do not start"
            ),
            StartupRefusal::JournalMissing { counter } => write!(
                f,
                "the counter reserved {counter} checkpoints but the journal has none: log lost or \
                 restored; do not start"
            ),
        }
    }
}

/// **The start-up policy, applied to the pair ALWAYS.**
///
/// `journal_last` is the highest checkpoint number the log's journal
/// recorded as published, or `None` if it recorded none. The four states
/// of `hbs-state` map to two decisions, and the journal is consulted in
/// every one of them, not only when the counter reads zero. That is the
/// lesson of a defect found by reading Arqueo's node (its start-up policy
/// consulted the journal only in one branch, so a deleted counter file
/// reopened at zero and would have re-signed used XMSS leaves): the datum
/// outside the pair has to be looked at whatever the pair says.
pub fn startup_check(guard: &impl SequenceGuard, journal_last: Option<u64>) -> StartupDecision {
    let counter = guard.current();
    match journal_last {
        None if counter == 0 => StartupDecision::Start { orphans: 0 },
        None => StartupDecision::Refuse(StartupRefusal::JournalMissing { counter }),
        Some(journal) => match reconcile_values(counter, journal) {
            Reconciliation::InSync { .. } => StartupDecision::Start { orphans: 0 },
            Reconciliation::CounterAhead { orphans, .. } => StartupDecision::Start { orphans },
            // `journal == 0` with a counter ahead is a journal that recorded
            // nothing yet: same as `None`.
            Reconciliation::KeyAtZero { .. } => {
                StartupDecision::Refuse(StartupRefusal::JournalMissing { counter })
            }
            Reconciliation::KeyAhead { .. } => {
                StartupDecision::Refuse(StartupRefusal::CounterBehindJournal { counter, journal })
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_journal_is_consulted_in_every_state() {
        let mut g = MemoryGuard::default();
        assert_eq!(
            startup_check(&g, None),
            StartupDecision::Start { orphans: 0 }
        );
        g.reserve().unwrap();
        g.reserve().unwrap();
        assert_eq!(
            startup_check(&g, Some(2)),
            StartupDecision::Start { orphans: 0 }
        );
        assert_eq!(
            startup_check(&g, Some(1)),
            StartupDecision::Start { orphans: 1 }
        );
        assert_eq!(
            startup_check(&g, Some(3)),
            StartupDecision::Refuse(StartupRefusal::CounterBehindJournal {
                counter: 2,
                journal: 3
            })
        );
        assert_eq!(
            startup_check(&g, None),
            StartupDecision::Refuse(StartupRefusal::JournalMissing { counter: 2 })
        );
        assert_eq!(
            startup_check(&g, Some(0)),
            StartupDecision::Refuse(StartupRefusal::JournalMissing { counter: 2 })
        );
        // A counter at zero with a journal ahead: the deleted-file case.
        let fresh = MemoryGuard::default();
        assert_eq!(
            startup_check(&fresh, Some(5)),
            StartupDecision::Refuse(StartupRefusal::CounterBehindJournal {
                counter: 0,
                journal: 5
            })
        );
    }

    #[test]
    fn only_key_ahead_is_fatal_for_the_checkpoint_counter() {
        let mut g = MemoryGuard::default();
        assert_eq!(g.reserve().unwrap(), 1);
        assert_eq!(g.reserve().unwrap(), 2);
        // The journal published 2: in sync.
        assert!(!is_fatal(&g.reconcile(2)));
        // The journal stopped at 1: orphan, the normal case after a crash.
        assert!(matches!(
            g.reconcile(1),
            Reconciliation::CounterAhead { orphans: 1, .. }
        ));
        // The journal says 3 and the counter 2: someone signed without reserving.
        assert!(is_fatal(&g.reconcile(3)));
    }
}
