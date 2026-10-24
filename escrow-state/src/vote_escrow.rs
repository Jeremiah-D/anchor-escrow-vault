//! Vote-escrow lock (AV-207): time-weighted governance voting power.
//!
//! A governance participant locks an amount for a fixed duration and
//! receives voting power that decays linearly as the lock runs out:
//!
//! ```text
//! voting_power(now) = amount * remaining(now) / duration
//! remaining(now)   = duration - min(now - start, duration)
//! ```
//!
//! All power math is `u128`, so a `u64::MAX` lock can never overflow
//! the multiply — the product is exact, and the division floors, so a
//! lock never reports more power than it holds.
//!
//! Lifecycle:
//! - [`VoteEscrowLock::lock`] — opens a lock (`amount > 0`,
//!   `duration > 0`, both [`EscrowError::InvalidVoteLock`] otherwise).
//! - [`VoteEscrowLock::voting_power_at`] — read-only decay curve; an
//!   exited lock reports `0`, and power is `0` once the lock matures.
//! - [`VoteEscrowLock::extend_to`] — lengthens the lock to a later
//!   end. Extension only: a new end at or before the current end (or
//!   at or before `now`) is refused, so a lock can never be shortened
//!   into more power or out of its commitment early.
//! - [`VoteEscrowLock::early_exit`] — closes the lock before maturity
//!   and splits the amount into a refund and a penalty proportional
//!   to the remaining time (`penalty = amount * remaining / duration`,
//!   floored). A mature lock exits penalty-free. The penalty is
//!   returned to the caller — the AV-106 insurance pool is the sink —
//!   this module moves no lamports itself, it only prices the exit.
//!
//! Orthogonal to [`StakeDelegation`](super::StakeDelegation) (AV-170,
//! yield on escrowed funds — this lock earns nothing, it votes) and
//! to [`TokenWeightSnapshot`](super::TokenWeightSnapshot) (AV-183, a
//! frozen balance snapshot read at release time — this lock *generates*
//! a decaying weight over time). Pure logic, zero dependencies: the
//! lock is a sidecar, not a vault field, so no layout change.

use super::EscrowError;

/// A single vote-escrow lock: `amount` locked from `start` for
/// `duration_secs`, decaying to zero voting power at `end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteEscrowLock {
    amount: u64,
    start: u64,
    duration_secs: u64,
    exited: bool,
}

impl VoteEscrowLock {
    /// Open a lock of `amount` at `start` for `duration_secs`.
    /// `amount == 0` or `duration_secs == 0` is
    /// [`EscrowError::InvalidVoteLock`] — a voteless or instant lock
    /// is always a misconfiguration, never a degenerate lock.
    pub fn lock(amount: u64, start: u64, duration_secs: u64) -> Result<Self, EscrowError> {
        if amount == 0 || duration_secs == 0 {
            return Err(EscrowError::InvalidVoteLock);
        }
        Ok(Self {
            amount,
            start,
            duration_secs,
            exited: false,
        })
    }

    /// The locked amount.
    pub fn amount(self) -> u64 {
        self.amount
    }

    /// The lock's start timestamp.
    pub fn start(self) -> u64 {
        self.start
    }

    /// The lock's duration in seconds.
    pub fn duration_secs(self) -> u64 {
        self.duration_secs
    }

    /// The lock's end timestamp (`start + duration`, saturating — a
    /// lock opened at the edge of the `u64` clock simply ends at the
    /// clock's end rather than wrapping).
    pub fn end(self) -> u64 {
        self.start.saturating_add(self.duration_secs)
    }

    /// True once [`VoteEscrowLock::early_exit`] has closed the lock.
    pub fn exited(self) -> bool {
        self.exited
    }

    /// Seconds of lock remaining at `now`: the full duration before
    /// `start`, `0` once the lock matures or after an exit.
    pub fn remaining_at(self, now: u64) -> u64 {
        if self.exited {
            return 0;
        }
        let elapsed = now.saturating_sub(self.start);
        self.duration_secs.saturating_sub(elapsed)
    }

    /// Voting power at `now`: `amount * remaining / duration` in
    /// `u128`, floored. Full power at `start`, `0` at maturity and
    /// after an exit; `now < start` reads as full power (the lock
    /// has not started decaying yet).
    pub fn voting_power_at(self, now: u64) -> u128 {
        if self.exited {
            return 0;
        }
        let remaining = self.remaining_at(now) as u128;
        self.amount as u128 * remaining / self.duration_secs as u128
    }

    /// Lengthen the lock so it ends at `new_end`. Only extension:
    /// `new_end` must be later than the current end *and* later than
    /// `now` — extending a mature lock into the past, or shortening
    /// a live one, is [`EscrowError::InvalidVoteLock`], as is
    /// extending an exited lock. The start never moves, so the power
    /// curve re-bases over the longer duration from the same origin.
    pub fn extend_to(&mut self, new_end: u64, now: u64) -> Result<(), EscrowError> {
        if self.exited || new_end <= self.end() || new_end <= now {
            return Err(EscrowError::InvalidVoteLock);
        }
        self.duration_secs = new_end - self.start;
        Ok(())
    }

    /// Close the lock early. Returns `(refund, penalty)`: the penalty
    /// is `floor(amount * remaining / duration)` — proportional to
    /// the unserved time — and the refund is the rest. A mature lock
    /// exits with penalty `0` and a full refund. The penalty is the
    /// caller's to route to the AV-106 insurance pool; this method
    /// only prices it. A second exit is
    /// [`EscrowError::InvalidVoteLock`] — an exited lock holds
    /// nothing to exit again.
    pub fn early_exit(&mut self, now: u64) -> Result<(u64, u64), EscrowError> {
        if self.exited {
            return Err(EscrowError::InvalidVoteLock);
        }
        let remaining = self.remaining_at(now) as u128;
        let penalty =
            (self.amount as u128 * remaining / self.duration_secs as u128) as u64;
        let refund = self.amount - penalty;
        self.exited = true;
        Ok((refund, penalty))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_rejects_zero_amount_and_zero_duration() {
        assert_eq!(
            VoteEscrowLock::lock(0, 1_000, 100),
            Err(EscrowError::InvalidVoteLock)
        );
        assert_eq!(
            VoteEscrowLock::lock(1_000, 1_000, 0),
            Err(EscrowError::InvalidVoteLock)
        );
    }

    #[test]
    fn voting_power_decays_linearly_to_zero() {
        let lock = VoteEscrowLock::lock(1_000, 1_000, 100).unwrap();
        assert_eq!(lock.voting_power_at(1_000), 1_000);
        assert_eq!(lock.voting_power_at(1_025), 750);
        assert_eq!(lock.voting_power_at(1_050), 500);
        assert_eq!(lock.voting_power_at(1_099), 10);
        assert_eq!(lock.voting_power_at(1_100), 0);
        assert_eq!(lock.voting_power_at(1_500), 0);
        // Before the start the lock has not decayed yet.
        assert_eq!(lock.voting_power_at(900), 1_000);
    }

    #[test]
    fn voting_power_floors_and_never_overflows() {
        // 1000 * 1 / 3 floors to 333, never rounds up.
        let lock = VoteEscrowLock::lock(1_000, 0, 3).unwrap();
        assert_eq!(lock.voting_power_at(2), 333);
        // u64::MAX amount: the u128 product stays exact.
        let lock = VoteEscrowLock::lock(u64::MAX, 0, 2).unwrap();
        assert_eq!(lock.voting_power_at(1), (u64::MAX as u128) / 2);
        assert_eq!(lock.voting_power_at(0), u64::MAX as u128);
    }

    #[test]
    fn extend_lengthens_only_and_rebases_power() {
        let mut lock = VoteEscrowLock::lock(100, 0, 100).unwrap();
        assert_eq!(lock.voting_power_at(50), 50);
        // Shorten, same end, and extension into the past all refuse.
        assert_eq!(
            lock.extend_to(100, 50),
            Err(EscrowError::InvalidVoteLock)
        );
        assert_eq!(
            lock.extend_to(90, 50),
            Err(EscrowError::InvalidVoteLock)
        );
        assert_eq!(
            lock.extend_to(60, 50),
            Err(EscrowError::InvalidVoteLock)
        );
        lock.extend_to(200, 50).unwrap();
        assert_eq!(lock.end(), 200);
        // Same start, longer duration: 100 * 150 / 200 = 75.
        assert_eq!(lock.voting_power_at(50), 75);
        assert_eq!(lock.remaining_at(50), 150);
    }

    #[test]
    fn early_exit_penalty_is_proportional_to_remaining() {
        let mut lock = VoteEscrowLock::lock(1_000, 1_000, 100).unwrap();
        // 75 of 100 seconds remain: penalty 750, refund 250.
        assert_eq!(lock.early_exit(1_025), Ok((250, 750)));
        assert!(lock.exited());
        assert_eq!(lock.voting_power_at(1_025), 0);
        // A second exit has nothing left to exit.
        assert_eq!(
            lock.early_exit(1_025),
            Err(EscrowError::InvalidVoteLock)
        );
    }

    #[test]
    fn mature_exit_is_penalty_free() {
        let mut lock = VoteEscrowLock::lock(1_000, 1_000, 100).unwrap();
        assert_eq!(lock.early_exit(1_100), Ok((1_000, 0)));
        // Extending an exited lock is refused, not silently revived.
        assert_eq!(
            lock.extend_to(1_300, 1_100),
            Err(EscrowError::InvalidVoteLock)
        );
    }
}
