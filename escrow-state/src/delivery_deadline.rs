//! Delivery-confirmation deadline and late-delivery penalty (AV-216).
//!
//! AV-203 lets the taker confirm receipt, but gives the confirmation
//! no calendar: a taker who confirms a year late settles exactly like
//! one who confirms on time, so the initializer has no priced lever
//! against a delivery confirmation dragged past the agreed date.
//! This module adds that lever as two opt-in, `Uninitialized`-only
//! configurations on the escrow, plus the late flag the timed
//! confirmation records:
//!
//! - [`validate_delivery_deadline`]: a single unix timestamp. Zero
//!   is rejected: storage uses `0` for "no deadline attached" (the
//!   AV-206 sentinel convention), so a builder that accepted `0`
//!   would make "attached, due at the epoch" indistinguishable from
//!   "never attached" — and every later confirmation would read as
//!   late. A caller that wants no deadline simply does not attach
//!   one.
//! - [`validate_late_delivery_penalty_bps`] /
//!   [`late_delivery_penalty_for`]: the penalty rate, 0–10_000 bps,
//!   and the penalty itself: `floor(amount * bps / 10_000)` when a
//!   late confirmation was recorded, else zero. "Late" is strict:
//!   confirming exactly at `deadline_at` is on time, not late —
//!   the AV-206 rule, applied to the confirmation instead of the
//!   release.
//!
//! Accounting (the part that must not be improvised): lateness is
//! recorded once, at confirmation time, not recomputed at release
//! time — the release path cannot know when the taker confirmed
//! unless the confirmation stored it, and re-deriving it from the
//! release clock would penalise a taker who confirmed on time but
//! settled late (the initializer's own delay). On a late-confirmed
//! `release` / `release_milestone` the payout settles as:
//!
//! ```text
//! released      += gross - penalty   (net taker principal)
//! penalty_paid  += penalty           (late-delivery sink)
//! taker_payout   = (gross - penalty) - fee + interest
//! ```
//!
//! so `released + penalty_paid + remaining == lockup` still holds
//! with the conservation formula untouched, and the escrow closes
//! exactly when nothing remains locked. The protocol fee (and the
//! AV-191 referral share, and the AV-100 streaming fee) slice the
//! *net* remainder — the fee is a cut of value the taker actually
//! receives, never a fee on a slice the taker forfeited. The AV-205
//! per-call cap and the AV-208 operator spend cap still bind the
//! *gross* call amount, and the lockup cap still checks the gross:
//! checking the net against the pre-penalty cap would let a
//! release settle gross value past the lockup (net fits, gross
//! does not), so the gross check stays even though `released`
//! stores the net.
//!
//! The penalty reuses the AV-82 `penalty_paid` sink, like AV-206.
//! On a milestone escrow that sink can only ever hold late
//! penalties (`slash` refuses milestone schedules); on a plain
//! escrow it can additionally hold a slash — the two sinks are the
//! same counter, so an audit reads the counter's composition from
//! the escrow's configuration, not from the counter alone.
//!
//! Orthogonal to:
//!
//! - AV-206 (per-tranche milestone due dates: a tranche released
//!   late — this is the whole-deal delivery confirmation late,
//!   and the two penalties stack, AV-206 first, then this one on
//!   the post-AV-206 net);
//! - AV-211 (the post-confirmation inspection window: the window
//!   runs from the confirmation, this deadline bounds the
//!   confirmation itself);
//! - AV-190 (rental use-right overdue rent: a different deal
//!   shape, a different clock);
//! - AV-203 (the confirmation gate itself: without a recorded
//!   late confirmation this prices nothing — a rate without a
//!   deadline, or a deadline without a rate, settles at zero
//!   penalty, and the timeless `confirm_delivery` records no
//!   lateness, so only the timed `confirm_delivery_at` — and the
//!   indexed wrapper, whose `at` is the confirmation time — can
//!   ever arm the penalty).
//!
//! Pure logic, zero dependencies: the escrow owns the storage (one
//! u64 deadline, one u16 rate, one bool late flag, appended to the
//! vault layout like every other opt-in field); this module owns
//! only validation and pricing.

use crate::EscrowError;

/// Validate a delivery-confirmation deadline (AV-216): a non-zero
/// unix timestamp, else [`EscrowError::AmountMismatch`] — the same
/// shape as the AV-205 zero-cap refusal, because the failure is the
/// same shape (a "configured" value that the `0` sentinel already
/// means "never configured").
pub fn validate_delivery_deadline(deadline_at: u64) -> Result<(), EscrowError> {
    if deadline_at == 0 {
        return Err(EscrowError::AmountMismatch);
    }
    Ok(())
}

/// Validate a late-delivery penalty rate (AV-216): 0–10_000 bps, else
/// [`EscrowError::InvalidPenalty`] — the AV-206 validator, reused
/// verbatim, because the failure is the same shape (a rate that
/// cannot be a rate) and the two rates share the bps ceiling.
pub fn validate_late_delivery_penalty_bps(bps: u16) -> Result<(), EscrowError> {
    crate::validate_late_penalty_bps(bps)
}

/// Price the late-delivery penalty for one payout (AV-216): zero
/// when no late confirmation was recorded (`late == false`) or no
/// rate is configured, otherwise `floor(amount * bps / 10_000)` in
/// `u128` (`u64::MAX * 10_000 < u128::MAX`, so the product cannot
/// wrap, and the floored quotient is `<= amount` since the stored
/// rate was validated to `<= 10_000`, so the downcast is exact).
/// Callers pass the already-recorded `late` flag — never a clock —
/// so an on-time confirmation followed by a late settlement prices
/// zero, by construction.
pub fn late_delivery_penalty_for(amount: u64, bps: u16, late: bool) -> u64 {
    if !late || bps == 0 {
        return 0;
    }
    ((amount as u128 * bps as u128) / 10_000u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_deadline_is_not_a_deadline() {
        assert_eq!(
            validate_delivery_deadline(0),
            Err(EscrowError::AmountMismatch)
        );
        assert!(validate_delivery_deadline(1).is_ok());
    }

    #[test]
    fn penalty_is_zero_without_lateness_or_rate() {
        assert_eq!(late_delivery_penalty_for(10_000, 1_000, false), 0);
        assert_eq!(late_delivery_penalty_for(10_000, 0, true), 0);
    }

    #[test]
    fn penalty_floors_on_the_gross_amount() {
        // floor(10_001 * 1000 / 10_000) = 1000, not 1001.
        assert_eq!(late_delivery_penalty_for(10_001, 1_000, true), 1_000);
        assert_eq!(late_delivery_penalty_for(10_000, 10_000, true), 10_000);
    }

    #[test]
    fn rate_above_10000_is_not_a_rate() {
        assert_eq!(
            validate_late_delivery_penalty_bps(10_001),
            Err(EscrowError::InvalidPenalty)
        );
        assert!(validate_late_delivery_penalty_bps(10_000).is_ok());
    }
}
