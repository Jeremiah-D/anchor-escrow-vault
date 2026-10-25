//! AV-220: partial funding — installment deposits toward the escrow's
//! declared amount (Solana / payment fintech: staged funding).
//!
//! The deposit-path counterpart to AV-11 (staged *release*) and the
//! single-asset counterpart to AV-95 (the multi-asset basket):
//!
//! - AV-11's funding plan moves the escrow to `Funded` on the *first*
//!   tranche and gates payouts on `is_funding_complete`.
//! - AV-220 keeps the escrow `Uninitialized` until the *last*
//!   installment lands: the vault is not fundable-then-spendable
//!   halfway through. Only when `funded_total == amount` does the
//!   state flip to `Funded` (and the AV-64 / AV-107 clocks anchor).
//! - AV-95's basket funds several assets at once; this item funds one
//!   asset in several calls. The two never combine: a basket escrow
//!   keeps its own deposit path.
//!
//! The escrow owns the storage (one `partial_funding` opt-in bool,
//! appended to the vault layout — see `VAULT_FIELDS`); this module
//! owns only the pure accumulation math and the progress view, so the
//! arithmetic can be tested without building an escrow. The locked
//! amount itself never moves: installments accumulate toward the
//! declared `amount`, never redefine it, so milestones, vesting, and
//! fees keep pricing off `amount` exactly as before.
//!
//! Accumulation runs in `u128`: `funded + deposit` can never wrap
//! (both operands are `u64`), so an over-funding deposit is a clean
//! `AmountMismatch` refusal, never a wraparound. A zero deposit is
//! `AmountMismatch` too — a no-op installment is not a deposit.
//!
//! Mid-funding exits: `release` refuses (the state is still
//! `Uninitialized`, so every payout path's state gate already says
//! no), while `cancel_expired` — once the AV-21 expiry gate passes —
//! refunds exactly what was deposited (`funded_total` via the
//! AV-220 `lockup_total` rule), never the declared amount: funds
//! that never arrived cannot be refunded.

use crate::EscrowError;

/// One installment deposit, in `u128` so the sum can never wrap.
///
/// `funded` is the cumulative deposited amount so far, `deposit` the
/// new installment, `target` the escrow's declared (locked) amount.
/// Returns the new cumulative total. Refuses a zero deposit and any
/// deposit that would push the total past the target, both with
/// [`EscrowError::AmountMismatch`] — the fund-tranche precedent
/// (AV-111's `fund_tranche` refuses over-plan deposits the same way).
pub fn partial_fund(funded: u64, deposit: u64, target: u64) -> Result<u64, EscrowError> {
    if deposit == 0 {
        return Err(EscrowError::AmountMismatch);
    }
    let new_total = funded as u128 + deposit as u128;
    if new_total > target as u128 {
        return Err(EscrowError::AmountMismatch);
    }
    Ok(new_total as u64)
}

/// Read-only funding progress for a partially-funded escrow: how much
/// has arrived, how much the deal needs, and what is still missing.
/// Keeper / indexer reporting surface — no state, no mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartialFundingProgress {
    /// Cumulative deposited amount (`funded_total`).
    pub funded: u64,
    /// The escrow's declared (locked) amount.
    pub target: u64,
}

impl PartialFundingProgress {
    /// `funded` past `target` is not a progress state — it is an
    /// over-funded escrow, which `partial_fund` can never produce.
    pub fn new(funded: u64, target: u64) -> Result<Self, EscrowError> {
        if funded > target {
            return Err(EscrowError::AmountMismatch);
        }
        Ok(Self { funded, target })
    }

    /// True once the installments sum to the declared amount — the
    /// moment the escrow flips to `Funded`.
    pub fn is_complete(&self) -> bool {
        self.funded == self.target
    }

    /// What is still missing. Saturating by construction (`funded <=
    /// target` is the constructor invariant), so this can never
    /// underflow; `0` exactly at completion.
    pub fn remaining(&self) -> u64 {
        self.target.saturating_sub(self.funded)
    }
}

#[cfg(test)]
mod partial_funding_tests {
    use super::*;

    #[test]
    fn first_installment_accumulates() {
        assert_eq!(partial_fund(0, 400_000, 1_000_000).unwrap(), 400_000);
        assert_eq!(partial_fund(400_000, 600_000, 1_000_000).unwrap(), 1_000_000);
    }

    #[test]
    fn zero_deposit_is_not_a_deposit() {
        assert_eq!(
            partial_fund(400_000, 0, 1_000_000).unwrap_err(),
            EscrowError::AmountMismatch
        );
    }

    #[test]
    fn over_funding_is_refused_not_wrapped() {
        // One unit past the target refuses, even at the u64 edge:
        // the u128 sum (u64::MAX + 1) never wraps, so the refusal is
        // a clean comparison, not an overflow artifact.
        assert_eq!(
            partial_fund(999_999, 2, 1_000_000).unwrap_err(),
            EscrowError::AmountMismatch
        );
        assert_eq!(
            partial_fund(u64::MAX - 1, 2, u64::MAX).unwrap_err(),
            EscrowError::AmountMismatch
        );
        assert_eq!(
            partial_fund(u64::MAX, 1, u64::MAX).unwrap_err(),
            EscrowError::AmountMismatch
        );
    }

    #[test]
    fn progress_view_reports_remaining_and_completion() {
        let p = PartialFundingProgress::new(400_000, 1_000_000).unwrap();
        assert!(!p.is_complete());
        assert_eq!(p.remaining(), 600_000);
        let done = PartialFundingProgress::new(1_000_000, 1_000_000).unwrap();
        assert!(done.is_complete());
        assert_eq!(done.remaining(), 0);
        assert_eq!(
            PartialFundingProgress::new(1_000_001, 1_000_000).unwrap_err(),
            EscrowError::AmountMismatch
        );
    }
}
