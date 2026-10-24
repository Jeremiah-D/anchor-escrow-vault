//! Milestone due dates and late-release penalties (AV-206).
//!
//! A milestone plan (AV-15) splits the lockup into tranches but gives
//! them no calendar: a tranche released a year late settles exactly
//! like one released on time, so the initializer has no priced lever
//! against a taker who drags a milestone. This module adds that lever
//! as two opt-in, `Uninitialized`-only configurations on the escrow:
//!
//! - [`validate_milestone_due_dates`]: the per-tranche deadline
//!   table, one `due_at` unix timestamp per tranche, strictly
//!   increasing (a deadline table that goes backwards would let a
//!   later tranche expire before an earlier one, which no in-order
//!   settlement sequence can honour). The table's length must equal
//!   the plan's tranche count — a shorter table would leave the last
//!   tranches deadline-free by accident, and a longer one would
//!   invent deadlines for tranches that do not exist.
//! - [`validate_late_penalty_bps`] / [`late_penalty_for`]: the
//!   penalty rate, 0–10_000 bps, and the penalty itself:
//!   `floor(tranche * bps / 10_000)` when `now > due_at`, else zero.
//!   "After" is strict: releasing exactly at `due_at` is on time,
//!   not late — a deadline that penalises the compliant release is
//!   not a deadline.
//!
//! Accounting (the part that must not be improvised): the penalty
//! slice is *not* a taker payout and *not* a protocol fee. On a late
//! `release_milestone` the tranche settles as
//!
//! ```text
//! released      += tranche - penalty   (net taker principal)
//! penalty_paid  += penalty             (late-penalty sink)
//! taker_payout   = (tranche - penalty) - fee + interest
//! ```
//!
//! so `released + penalty_paid + skipped + remaining == amount`
//! still holds with the conservation formula untouched, and the
//! escrow closes when `released + penalty_paid == amount` (the
//! pre-AV-206 close test `released == amount` is that same test with
//! `penalty_paid == 0`). The penalty is charged on the gross tranche
//! and the protocol fee then slices the *net* remainder — the fee
//! is a cut of value the taker actually receives, never a fee on a
//! slice the taker forfeited. This reuses the AV-82 `penalty_paid`
//! sink, which is safe here precisely because `slash` refuses
//! milestone-scheduled escrows: on a milestone escrow `penalty_paid`
//! can only ever hold late penalties, so the audit trail never
//! confuses a late tranche with a slash.
//!
//! Orthogonal to:
//!
//! - AV-82 `slash` (whole-escrow default enforcement, refused on
//!   milestone schedules — this is per-tranche lateness, not
//!   default);
//! - AV-24 `penalty_bps` (the taker-initiated `cancel_expired`
//!   anti-griefing rate — a different trigger, a different sink
//!   path, and a different name on purpose: `late_penalty_bps` here
//!   never touches the cancel path);
//! - AV-70 / AV-155 milestone amount rewrites (they change tranche
//!   *amounts*, never the tranche *count*, so a deadline table
//!   attached before a rewrite stays valid — and a rewrite that
//!   changed the count would need a new table, which is why the
//!   table is fixed before funding alongside the plan).
//!
//! Pure logic, zero dependencies, `Copy`-friendly: the escrow owns
//! the storage (a `[u64; MAX_MILESTONES]` deadline table plus one
//! `u16` rate, appended to the vault layout like every other
//! opt-in field); this module owns only validation and pricing.

use crate::{EscrowError, MAX_MILESTONES};

/// Maximum late-penalty rate: 100% of the tranche. Anything above
/// would take more than the tranche holds, which is not a penalty
/// but a confiscation the tranche accounting cannot express.
pub const MAX_LATE_PENALTY_BPS: u16 = 10_000;

/// Validate a late-penalty rate (AV-206): 0–10_000 bps, else
/// [`EscrowError::InvalidPenalty`] — the same error `with_penalty_bps`
/// uses for the AV-24 rate, because the failure is the same shape
/// (a rate that cannot be a rate).
pub fn validate_late_penalty_bps(bps: u16) -> Result<(), EscrowError> {
    if bps > MAX_LATE_PENALTY_BPS {
        return Err(EscrowError::InvalidPenalty);
    }
    Ok(())
}

/// Validate a milestone deadline table (AV-206): its length must
/// equal the plan's tranche count, and the timestamps must be
/// strictly increasing. A table attached to no plan, or to a plan
/// of a different length, is [`EscrowError::InvalidMilestones`] —
/// the plan-shape error, because the failure is a plan/table shape
/// mismatch, not a rate problem. Zero is rejected as a deadline:
/// storage uses `0` for "no deadline attached for this tranche"
/// (see [`Escrow::milestone_due_at`]), so a builder that accepted
/// `0` would make "attached, due at the epoch" indistinguishable
/// from "never attached" — and every later release would read as
/// late. A caller that wants no deadlines simply does not attach
/// a table; partial tables are not a thing (length must equal the
/// tranche count).
pub fn validate_milestone_due_dates(
    due_at: &[u64],
    tranche_count: usize,
) -> Result<(), EscrowError> {
    if tranche_count == 0 || tranche_count > MAX_MILESTONES {
        return Err(EscrowError::InvalidMilestones);
    }
    if due_at.len() != tranche_count {
        return Err(EscrowError::InvalidMilestones);
    }
    if due_at[0] == 0 {
        return Err(EscrowError::InvalidMilestones);
    }
    for window in due_at.windows(2) {
        if window[1] <= window[0] {
            return Err(EscrowError::InvalidMilestones);
        }
    }
    Ok(())
}

/// Price the late penalty for one tranche (AV-206): zero when the
/// release is on time (`now <= due_at`) or no rate is configured,
/// otherwise `floor(tranche * penalty_bps / 10_000)` in `u128`
/// (`u64::MAX * 10_000 < u128::MAX`, so the product cannot wrap,
/// and the floored quotient is `<= tranche` since
/// `penalty_bps <= 10_000`, so the downcast is exact).
pub fn late_penalty_for(
    tranche: u64,
    due_at: u64,
    now: u64,
    penalty_bps: u16,
) -> u64 {
    if penalty_bps == 0 || now <= due_at {
        return 0;
    }
    ((tranche as u128 * penalty_bps as u128) / 10_000u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_date_table_must_match_tranche_count_and_rise_strictly() {
        assert!(validate_milestone_due_dates(&[100, 200], 2).is_ok());
        assert_eq!(
            validate_milestone_due_dates(&[100], 2).unwrap_err(),
            EscrowError::InvalidMilestones
        );
        assert_eq!(
            validate_milestone_due_dates(&[100, 200, 300], 2).unwrap_err(),
            EscrowError::InvalidMilestones
        );
        // Equal neighbours are not strictly increasing.
        assert_eq!(
            validate_milestone_due_dates(&[100, 100], 2).unwrap_err(),
            EscrowError::InvalidMilestones
        );
        assert_eq!(
            validate_milestone_due_dates(&[200, 100], 2).unwrap_err(),
            EscrowError::InvalidMilestones
        );
        assert_eq!(
            validate_milestone_due_dates(&[], 0).unwrap_err(),
            EscrowError::InvalidMilestones
        );
        // Zero is not a deadline (it means "never attached").
        assert_eq!(
            validate_milestone_due_dates(&[0, 200], 2).unwrap_err(),
            EscrowError::InvalidMilestones
        );
    }

    #[test]
    fn penalty_rate_capped_at_full_tranche() {
        assert!(validate_late_penalty_bps(0).is_ok());
        assert!(validate_late_penalty_bps(10_000).is_ok());
        assert_eq!(
            validate_late_penalty_bps(10_001).unwrap_err(),
            EscrowError::InvalidPenalty
        );
    }

    #[test]
    fn penalty_is_zero_on_time_and_floored_when_late() {
        assert_eq!(late_penalty_for(1_000_000, 500, 500, 1_000), 0);
        assert_eq!(late_penalty_for(1_000_000, 500, 499, 1_000), 0);
        assert_eq!(late_penalty_for(1_000_000, 500, 501, 0), 0);
        // 10% of 1,000,000, floored.
        assert_eq!(late_penalty_for(1_000_000, 500, 501, 1_000), 100_000);
        // Dust floors to zero, never rounds up into the penalty.
        assert_eq!(late_penalty_for(99, 500, 501, 1_000), 9);
        assert_eq!(late_penalty_for(1_000_000, 500, 501, 10_000), 1_000_000);
    }
}
