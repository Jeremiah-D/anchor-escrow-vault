//! AV-164: tx fee-payer sponsorship — per-escrow sponsor policy, the
//! keeper's fee budget, and the structured sponsorship audit.
//!
//! The Solana meta-transaction pattern separates *authorization* from
//! *payment*: a release intent (AV-123) is signed by the initializer,
//! but the fee payer is whoever submits the transaction. This module
//! is the *policy layer* on top of that pattern — it decides which fee
//! payers an escrow trusts, how much fee spend each trusted sponsor may
//! incur, and how the operator's own fee budget is spent. It is
//! deliberately orthogonal to the intent's relayer semantics: the intent
//! authorizes *what* happens (a release of a fixed amount to a fixed
//! destination); this module authorizes *who may pay the fee* for
//! submitting it, and *how much* they may spend.
//!
//! # Components
//!
//! - [`SponsorPolicy`]: per-escrow allowlist of sponsor keys plus the
//!   spend policy — a per-tx lamport cap, a per-sponsor cumulative cap,
//!   and an effective window. [`SponsorPolicy::authorize`] is the gate
//!   the keeper calls before submitting a sponsored transaction.
//! - [`SponsorBudget`]: the keeper's own fee budget. `fund` tops it up,
//!   [`SponsorBudget::deduct`] spends it; a deduct that would go below
//!   zero fails with [`EscrowError::SponsorBudgetExhausted`]. Every
//!   successful deduct appends a [`SponsorAuditEntry`] to a bounded
//!   ring — the sponsorship audit trail (sponsor key + lamports +
//!   escrow identity, per the audit shape this item specifies).
//!
//! # What is real here
//!
//! - **The policy is a pre-submit gate.** `authorize` checks, in order:
//!   sponsor-allowlisted → window active → per-tx cap → cumulative cap
//!   (authority first, then config, then amounts — the crate's check
//!   order convention). On success it books the amount against the
//!   sponsor's cumulative usage, so the cumulative cap is enforced
//!   across calls.
//! - **The budget never goes negative.** `deduct` is checked-before-
//!   subtracted with saturating-safe math; a failed deduct changes
//!   nothing.
//! - **The audit is append-only and bounded.** The 64-entry ring keeps
//!   the newest history; [`SponsorBudget::audit`] returns entries
//!   oldest-first, like the AV-163 circuit-breaker audit ring.
//!
//! # What is deliberately NOT here (honesty labels)
//!
//! - **Policy enforcement is off-chain.** The fee payer is a
//!   transaction-level property the program cannot compel; this module
//!   is the keeper-side policy the operator's bot enforces before
//!   submitting. The on-chain analogue (an Anchor skeleton gate) is a
//!   deployment change for a later item.
//! - **The budget holds no lamports.** It is an accounting abstraction
//!   over the keeper's fee wallet, not a vault: `fund`/`deduct` move
//!   no on-chain funds. The audit records the *intent* to spend, so the
//!   operator can reconcile against actual wallet balances.
//! - **Cumulative usage is per-policy-instance.** The policy is
//!   per-escrow by construction; a keeper running many escrows keeps
//!   one policy per escrow. Usage does not persist across process
//!   restarts (the keeper re-derives it from the sponsorship audit or
//!   re-books from zero — documented, not hidden).
//! - **Sentinel values:** `per_tx_cap == 0` / `cumulative_cap == 0`
//!   mean *unlimited* (the corresponding check is skipped);
//!   `window_start == window_end == 0` means *always active*. Any other
//!   window with `window_end == 0` is open-ended from `window_start`.

use std::collections::VecDeque;

use super::EscrowError;

/// Maximum sponsor keys per policy. Fixed bound so usage accounting
/// stays O(n) scan, never a map the crate would need to allocate.
pub const MAX_SPONSORS: usize = 16;

/// How many sponsorship audit entries the budget remembers: a bounded
/// ring, mirroring the AV-163 circuit-breaker convention (fixed-size
/// tail, oldest evicts first).
pub const MAX_SPONSOR_AUDIT_ENTRIES: usize = 64;

/// One structured sponsorship audit entry: who paid, how much, for
/// which escrow, and when. Appended by
/// [`SponsorBudget::deduct`] — the "sponsor key + amount + escrow"
/// audit shape this item specifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SponsorAuditEntry {
    /// The sponsor key that paid the fee.
    pub sponsor: [u8; 32],
    /// Lamports of fee sponsored by this deduct.
    pub amount_lamports: u64,
    /// The escrow (vault PDA) whose transaction was sponsored.
    pub escrow: [u8; 32],
    /// Unix timestamp of the deduct (clock sysvar on-chain).
    pub at: u64,
}

/// Per-escrow fee-payer sponsorship policy: the allowlist of sponsor
/// keys plus the spend policy (per-tx cap, per-sponsor cumulative cap,
/// effective window).
///
/// `per_tx_cap == 0` / `cumulative_cap == 0` are *unlimited* sentinels
/// (the corresponding check is skipped); `window_start == window_end ==
/// 0` means the policy is always active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SponsorPolicy {
    /// Allowlisted sponsor keys (no zero key, no duplicates).
    allowed: Vec<[u8; 32]>,
    /// Per-transaction lamport cap; `0` = unlimited.
    per_tx_cap: u64,
    /// Per-sponsor cumulative lamport cap; `0` = unlimited.
    cumulative_cap: u64,
    /// Window start (unix seconds); `0` = no start bound.
    window_start: u64,
    /// Window end (unix seconds, inclusive); `0` = no end bound.
    window_end: u64,
    /// Booked cumulative spend per allowlisted sponsor, parallel to
    /// `allowed`.
    used: Vec<u64>,
}

impl SponsorPolicy {
    /// Build a policy. Rejects (with
    /// [`EscrowError::InvalidSponsorPolicy`]): an empty or over-long
    /// allowlist, a zero sponsor key, a duplicate sponsor key (usage
    /// accounting would be ambiguous), or a window with
    /// `window_start > window_end` (when an end bound is set).
    pub fn new(
        allowed: &[[u8; 32]],
        per_tx_cap: u64,
        cumulative_cap: u64,
        window_start: u64,
        window_end: u64,
    ) -> Result<Self, EscrowError> {
        if allowed.is_empty() || allowed.len() > MAX_SPONSORS {
            return Err(EscrowError::InvalidSponsorPolicy);
        }
        for (i, key) in allowed.iter().enumerate() {
            if *key == [0u8; 32] {
                return Err(EscrowError::InvalidSponsorPolicy);
            }
            for other in &allowed[..i] {
                if other == key {
                    return Err(EscrowError::InvalidSponsorPolicy);
                }
            }
        }
        if window_end != 0 && window_start > window_end {
            return Err(EscrowError::InvalidSponsorPolicy);
        }
        Ok(SponsorPolicy {
            allowed: allowed.to_vec(),
            per_tx_cap,
            cumulative_cap,
            window_start,
            window_end,
            used: vec![0u64; allowed.len()],
        })
    }

    /// Whether `sponsor` is allowlisted.
    pub fn is_allowed(&self, sponsor: &[u8; 32]) -> bool {
        self.allowed.iter().any(|k| k == sponsor)
    }

    /// Whether the policy is active at `now` (unix seconds).
    pub fn window_active(&self, now: u64) -> bool {
        (self.window_start == 0 || now >= self.window_start)
            && (self.window_end == 0 || now <= self.window_end)
    }

    /// Cumulative lamports already booked for `sponsor`
    /// (`None` when the sponsor is not allowlisted).
    pub fn used_by(&self, sponsor: &[u8; 32]) -> Option<u64> {
        self.allowed
            .iter()
            .position(|k| k == sponsor)
            .map(|i| self.used[i])
    }

    /// The pre-submit gate: authorize `sponsor` to pay
    /// `amount_lamports` of fee at `now`. Check order —
    /// sponsor-allowlisted ([`EscrowError::SponsorNotAllowed`]), then
    /// window ([`EscrowError::SponsorWindowInactive`]), then per-tx cap
    /// ([`EscrowError::SponsorAmountExceedsPerTxCap`]), then cumulative
    /// cap ([`EscrowError::SponsorCumulativeCapExceeded`]). On success
    /// the amount is booked against the sponsor's cumulative usage.
    /// Failed calls book nothing (checked-before-mutated).
    pub fn authorize(
        &mut self,
        sponsor: &[u8; 32],
        amount_lamports: u64,
        now: u64,
    ) -> Result<(), EscrowError> {
        let idx = self
            .allowed
            .iter()
            .position(|k| k == sponsor)
            .ok_or(EscrowError::SponsorNotAllowed)?;
        if !self.window_active(now) {
            return Err(EscrowError::SponsorWindowInactive);
        }
        if self.per_tx_cap != 0 && amount_lamports > self.per_tx_cap {
            return Err(EscrowError::SponsorAmountExceedsPerTxCap);
        }
        // Usage is always booked (even when the cumulative cap is
        // unlimited, so `used_by` stays an honest spend meter); the cap
        // itself is only enforced when nonzero. The booking saturates
        // on overflow — usage is a meter, not money.
        let next = self.used[idx].saturating_add(amount_lamports);
        let overflowed = amount_lamports > u64::MAX - self.used[idx];
        if self.cumulative_cap != 0 && (overflowed || next > self.cumulative_cap) {
            return Err(EscrowError::SponsorCumulativeCapExceeded);
        }
        self.used[idx] = next;
        Ok(())
    }
}

/// The keeper's fee budget: an accounting abstraction over the
/// keeper's fee wallet. `fund` tops it up; `deduct` spends it and
/// appends a [`SponsorAuditEntry`] to the bounded audit ring. The
/// budget never goes negative — a short deduct fails with
/// [`EscrowError::SponsorBudgetExhausted`] and changes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SponsorBudget {
    balance: u64,
    total_funded: u64,
    total_spent: u64,
    audit: VecDeque<SponsorAuditEntry>,
}

impl SponsorBudget {
    /// Create an empty budget.
    pub fn new() -> Self {
        SponsorBudget {
            balance: 0,
            total_funded: 0,
            total_spent: 0,
            audit: VecDeque::with_capacity(MAX_SPONSOR_AUDIT_ENTRIES),
        }
    }

    /// Current spendable balance (lamports).
    pub fn balance(&self) -> u64 {
        self.balance
    }

    /// Lifetime lamports funded into the budget.
    pub fn total_funded(&self) -> u64 {
        self.total_funded
    }

    /// Lifetime lamports deducted from the budget.
    pub fn total_spent(&self) -> u64 {
        self.total_spent
    }

    /// Top up the budget. `amount == 0` is a no-op (still `Ok`).
    /// Saturates on overflow — a funded budget can never wrap.
    pub fn fund(&mut self, amount: u64) {
        if amount == 0 {
            return;
        }
        self.balance = self.balance.saturating_add(amount);
        self.total_funded = self.total_funded.saturating_add(amount);
    }

    /// Spend `amount_lamports` of fee on behalf of `sponsor` for the
    /// transaction on `escrow` at `at`. Fails with
    /// [`EscrowError::SponsorBudgetExhausted`] when the balance is
    /// short (nothing is booked, nothing is audited). On success the
    /// balance drops and a [`SponsorAuditEntry`] is appended to the
    /// bounded ring (oldest evicts first past
    /// [`MAX_SPONSOR_AUDIT_ENTRIES`]).
    pub fn deduct(
        &mut self,
        amount_lamports: u64,
        sponsor: [u8; 32],
        escrow: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let next = self
            .balance
            .checked_sub(amount_lamports)
            .ok_or(EscrowError::SponsorBudgetExhausted)?;
        self.balance = next;
        self.total_spent = self.total_spent.saturating_add(amount_lamports);
        if self.audit.len() == MAX_SPONSOR_AUDIT_ENTRIES {
            self.audit.pop_front();
        }
        self.audit.push_back(SponsorAuditEntry {
            sponsor,
            amount_lamports,
            escrow,
            at,
        });
        Ok(())
    }

    /// The sponsorship audit trail, oldest-first.
    pub fn audit(&self) -> Vec<SponsorAuditEntry> {
        self.audit.iter().copied().collect()
    }
}

impl Default for SponsorBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod sponsor_tests {
    use super::*;

    const SPONSOR_A: [u8; 32] = [0xA1; 32];
    const SPONSOR_B: [u8; 32] = [0xB2; 32];
    const ESCROW_X: [u8; 32] = [0xE1; 32];

    fn policy() -> SponsorPolicy {
        SponsorPolicy::new(&[SPONSOR_A, SPONSOR_B], 10_000, 25_000, 1_000, 2_000).unwrap()
    }

    #[test]
    fn new_rejects_empty_allowlist() {
        assert_eq!(
            SponsorPolicy::new(&[], 0, 0, 0, 0),
            Err(EscrowError::InvalidSponsorPolicy)
        );
    }

    #[test]
    fn new_rejects_overlong_allowlist() {
        let keys = vec![[0x11; 32]; MAX_SPONSORS + 1];
        assert_eq!(
            SponsorPolicy::new(&keys, 0, 0, 0, 0),
            Err(EscrowError::InvalidSponsorPolicy)
        );
    }

    #[test]
    fn new_rejects_zero_key() {
        assert_eq!(
            SponsorPolicy::new(&[[0u8; 32]], 0, 0, 0, 0),
            Err(EscrowError::InvalidSponsorPolicy)
        );
    }

    #[test]
    fn new_rejects_duplicate_key() {
        assert_eq!(
            SponsorPolicy::new(&[SPONSOR_A, SPONSOR_A], 0, 0, 0, 0),
            Err(EscrowError::InvalidSponsorPolicy)
        );
    }

    #[test]
    fn new_rejects_inverted_window() {
        assert_eq!(
            SponsorPolicy::new(&[SPONSOR_A], 0, 0, 2_000, 1_000),
            Err(EscrowError::InvalidSponsorPolicy)
        );
    }

    #[test]
    fn new_accepts_open_ended_and_always_on_windows() {
        assert!(SponsorPolicy::new(&[SPONSOR_A], 0, 0, 0, 0).is_ok());
        assert!(SponsorPolicy::new(&[SPONSOR_A], 0, 0, 1_000, 0).is_ok());
    }

    #[test]
    fn unknown_sponsor_is_not_allowed() {
        let mut p = policy();
        assert_eq!(
            p.authorize(&[0xCC; 32], 100, 1_500),
            Err(EscrowError::SponsorNotAllowed)
        );
    }

    #[test]
    fn window_gate_inclusive_bounds() {
        let mut p = policy();
        // Before the window and after the window both fail; the
        // boundary timestamps are active.
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 999),
            Err(EscrowError::SponsorWindowInactive)
        );
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 2_001),
            Err(EscrowError::SponsorWindowInactive)
        );
        assert!(p.authorize(&SPONSOR_A, 100, 1_000).is_ok());
        assert!(p.authorize(&SPONSOR_A, 100, 2_000).is_ok());
        // Failed authorizations book nothing.
        assert_eq!(p.used_by(&SPONSOR_A), Some(200));
    }

    #[test]
    fn per_tx_cap_gate() {
        let mut p = policy();
        assert_eq!(
            p.authorize(&SPONSOR_A, 10_001, 1_500),
            Err(EscrowError::SponsorAmountExceedsPerTxCap)
        );
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
    }

    #[test]
    fn per_tx_cap_zero_means_unlimited() {
        let mut p = SponsorPolicy::new(&[SPONSOR_A], 0, 25_000, 0, 0).unwrap();
        assert!(p.authorize(&SPONSOR_A, u64::MAX, 0).is_err()); // hits cumulative
        assert_eq!(
            p.authorize(&SPONSOR_A, u64::MAX, 0),
            Err(EscrowError::SponsorCumulativeCapExceeded)
        );
    }

    #[test]
    fn cumulative_cap_accumulates_across_calls() {
        let mut p = policy();
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert_eq!(p.used_by(&SPONSOR_A), Some(20_000));
        // 10_000 more would exceed the 25_000 cumulative cap.
        assert_eq!(
            p.authorize(&SPONSOR_A, 10_000, 1_500),
            Err(EscrowError::SponsorCumulativeCapExceeded)
        );
        // Usage is per-sponsor: B is untouched.
        assert_eq!(p.used_by(&SPONSOR_B), Some(0));
        assert!(p.authorize(&SPONSOR_B, 10_000, 1_500).is_ok());
    }

    #[test]
    fn cumulative_cap_zero_means_unlimited() {
        let mut p = SponsorPolicy::new(&[SPONSOR_A], 10_000, 0, 0, 0).unwrap();
        for _ in 0..5 {
            assert!(p.authorize(&SPONSOR_A, 10_000, 0).is_ok());
        }
        assert_eq!(p.used_by(&SPONSOR_A), Some(50_000));
    }

    #[test]
    fn budget_deduct_needs_funds() {
        let mut b = SponsorBudget::new();
        assert_eq!(
            b.deduct(1, SPONSOR_A, ESCROW_X, 100),
            Err(EscrowError::SponsorBudgetExhausted)
        );
        // A failed deduct audits nothing and spends nothing.
        assert!(b.audit().is_empty());
        assert_eq!(b.total_spent(), 0);
    }

    #[test]
    fn budget_fund_and_deduct() {
        let mut b = SponsorBudget::new();
        b.fund(5_000);
        assert_eq!(b.balance(), 5_000);
        b.deduct(2_000, SPONSOR_A, ESCROW_X, 123).unwrap();
        assert_eq!(b.balance(), 3_000);
        assert_eq!(b.total_funded(), 5_000);
        assert_eq!(b.total_spent(), 2_000);
        let audit = b.audit();
        assert_eq!(audit.len(), 1);
        assert_eq!(
            audit[0],
            SponsorAuditEntry {
                sponsor: SPONSOR_A,
                amount_lamports: 2_000,
                escrow: ESCROW_X,
                at: 123,
            }
        );
    }

    #[test]
    fn budget_audit_ring_evicts_oldest() {
        let mut b = SponsorBudget::new();
        b.fund(u64::MAX);
        for i in 0..(MAX_SPONSOR_AUDIT_ENTRIES + 5) {
            b.deduct(1, SPONSOR_A, ESCROW_X, i as u64).unwrap();
        }
        let audit = b.audit();
        assert_eq!(audit.len(), MAX_SPONSOR_AUDIT_ENTRIES);
        // Oldest-first: the first five entries evicted.
        assert_eq!(audit[0].at, 5);
        assert_eq!(audit[audit.len() - 1].at, (MAX_SPONSOR_AUDIT_ENTRIES + 4) as u64);
    }

    #[test]
    fn policy_authorize_then_budget_deduct_compose() {
        let mut p = SponsorPolicy::new(&[SPONSOR_A], 10_000, 0, 0, 0).unwrap();
        let mut b = SponsorBudget::new();
        b.fund(100_000);
        // The keeper's submit path: policy gate first, budget second.
        p.authorize(&SPONSOR_A, 5_000, 0).unwrap();
        b.deduct(5_000, SPONSOR_A, ESCROW_X, 0).unwrap();
        assert_eq!(b.balance(), 95_000);
        assert_eq!(p.used_by(&SPONSOR_A), Some(5_000));
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(EscrowError::InvalidSponsorPolicy.code(), 225);
        assert_eq!(EscrowError::SponsorNotAllowed.code(), 226);
        assert_eq!(EscrowError::SponsorWindowInactive.code(), 227);
        assert_eq!(EscrowError::SponsorAmountExceedsPerTxCap.code(), 228);
        assert_eq!(EscrowError::SponsorCumulativeCapExceeded.code(), 229);
        assert_eq!(EscrowError::SponsorBudgetExhausted.code(), 230);
    }
}
