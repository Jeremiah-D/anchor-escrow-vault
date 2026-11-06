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

    /// Revise the spend caps live (AV-352), without rebuilding the
    /// policy. Any `u64` pair is legal — `0` is the unlimited
    /// sentinel for either cap — so this returns `bool`, not
    /// `Result`, following the AV-349 `amend_retry_policy` precedent:
    /// there is no failable input and no never-triggered error to
    /// invent. Amending to the pair already in force is a no-op
    /// returning `false`; any other pair atomically swaps BOTH caps
    /// (a single-field change still returns `true`, the other field
    /// untouched) and returns `true`.
    ///
    /// `used` is NEVER touched: no reset, no pro-rata rescaling.
    /// Rebuilding via [`new`](Self::new) zeroes `used` — a sponsor
    /// who spent 24,000/25,000 would silently get a fresh 25,000 —
    /// which is exactly the forgiveness this revision path exists
    /// to avoid. Already-booked authorizations stay booked.
    /// Tightening the cumulative cap below already-booked `used`
    /// does NOT error and does NOT clear the books: the next
    /// [`authorize`](Self::authorize) for that sponsor returns
    /// [`EscrowError::SponsorCumulativeCapExceeded`] — a fail-closed
    /// "revoke the remaining allowance". It stays locked because
    /// `used` only grows (there is no un-book entry), so a later
    /// loosening is the only way back in. Tightening the per-tx cap
    /// never permanently locks a sponsor — each transaction is
    /// judged alone. Loosening either cap takes effect from the next
    /// `authorize`, which always reads the live values.
    ///
    /// No state gate: `SponsorPolicy` is an off-chain keeper-side
    /// policy object, so revision is an operator-side act, not a
    /// Vault state transition. No audit event fires — this module
    /// has no amend audit surface (the only audit surface is
    /// [`SponsorBudget`]'s 64-entry ring, which this revision does
    /// not touch) — so the revision behaviour is pinned by tests,
    /// as in AV-349/AV-350/AV-351.
    pub fn amend_spend_caps(&mut self, new_per_tx_cap: u64, new_cumulative_cap: u64) -> bool {
        if self.per_tx_cap == new_per_tx_cap && self.cumulative_cap == new_cumulative_cap {
            return false;
        }
        self.per_tx_cap = new_per_tx_cap;
        self.cumulative_cap = new_cumulative_cap;
        true
    }

    /// Revise the effective window live (AV-354), without rebuilding
    /// the policy. The window was fixed at construction: an operator
    /// who wanted to extend an expired sponsorship window (a
    /// campaign running long) or close one early (a sponsor gone dark
    /// or suspected of abuse) had only `new()` — and a rebuild zeroes
    /// `used`, silently forgiving already-booked spend, exactly the
    /// forgiveness [`amend_spend_caps`](Self::amend_spend_caps)
    /// exists to avoid. This revision swaps the window pair in
    /// place; `used` is NEVER touched.
    ///
    /// Validation reuses [`new`](Self::new)'s gate: an inverted
    /// window (`window_end != 0 && window_start > window_end`) fails
    /// with [`EscrowError::InvalidSponsorPolicy`] and the live window
    /// is untouched. Amending to the pair already in force is an
    /// `Ok(false)` no-op; any other pair atomically swaps BOTH
    /// bounds and returns `Ok(true)`. The new window governs the
    /// next [`authorize`](Self::authorize), which always reads the
    /// live values — tightening can shut sponsorship off at once
    /// (fail-closed: the next `authorize` returns
    /// [`EscrowError::SponsorWindowInactive`], `used` untouched) and
    /// loosening reopens it. Sentinel semantics are unchanged:
    /// `(0, 0)` means always active, `window_end == 0` means
    /// open-ended from `window_start`.
    ///
    /// No audit event fires — this module has no amend audit surface
    /// (the only audit surface is [`SponsorBudget`]'s 64-entry ring,
    /// which this revision does not touch) — so the revision
    /// behaviour is pinned by tests, as in AV-352.
    pub fn amend_sponsor_window(
        &mut self,
        new_window_start: u64,
        new_window_end: u64,
    ) -> Result<bool, EscrowError> {
        if new_window_end != 0 && new_window_start > new_window_end {
            return Err(EscrowError::InvalidSponsorPolicy);
        }
        if self.window_start == new_window_start && self.window_end == new_window_end {
            return Ok(false);
        }
        self.window_start = new_window_start;
        self.window_end = new_window_end;
        Ok(true)
    }

    /// Add a sponsor to the allowlist live (AV-357), without
    /// rebuilding the policy. The allowlist was fixed at
    /// construction: an operator who wanted to onboard a new keeper
    /// fee payer (expansion) or cut off a sponsor gone dark or
    /// suspected of abuse had only `new()` — and a rebuild zeroes
    /// `used`, silently forgiving already-booked spend, exactly the
    /// forgiveness [`amend_spend_caps`](Self::amend_spend_caps)
    /// exists to avoid. This revision adds one member in place;
    /// every other member's `used` is NEVER touched.
    ///
    /// Check order follows the AV-354 convention (validate → same
    /// value → replace): a zero key fails with
    /// [`EscrowError::InvalidSponsorPolicy`] and the live allowlist
    /// is untouched; a key already allowlisted is an `Ok(false)`
    /// no-op; a full allowlist (`MAX_SPONSORS` members) fails with
    /// [`EscrowError::InvalidSponsorPolicy`] and the live allowlist
    /// is untouched; otherwise the key is pushed with a fresh
    /// `used` entry of `0` (the new member starts booked from zero)
    /// and `Ok(true)` is returned. The new member is usable from
    /// the next [`authorize`](Self::authorize), which always reads
    /// the live allowlist. The caps and the window are untouched.
    ///
    /// No audit event fires — this module has no amend audit surface
    /// (the only audit surface is [`SponsorBudget`]'s 64-entry ring,
    /// which this revision does not touch) — so the revision
    /// behaviour is pinned by tests, as in AV-352/AV-354.
    pub fn add_sponsor(&mut self, sponsor: [u8; 32]) -> Result<bool, EscrowError> {
        if sponsor == [0u8; 32] {
            return Err(EscrowError::InvalidSponsorPolicy);
        }
        if self.allowed.iter().any(|k| *k == sponsor) {
            return Ok(false);
        }
        if self.allowed.len() >= MAX_SPONSORS {
            return Err(EscrowError::InvalidSponsorPolicy);
        }
        self.allowed.push(sponsor);
        self.used.push(0);
        Ok(true)
    }

    /// Remove a sponsor from the allowlist live (AV-357), without
    /// rebuilding the policy. The counterpart of
    /// [`add_sponsor`](Self::add_sponsor): cutting off a sponsor
    /// gone dark or suspected of abuse must take effect at once
    /// (fail-closed — the next [`authorize`](Self::authorize) for
    /// that sponsor returns
    /// [`EscrowError::SponsorNotAllowed`]), and must not forgive
    /// the other sponsors' already-booked spend the way a `new()`
    /// rebuild would.
    ///
    /// Check order follows the AV-354 convention (validate → same
    /// value → replace): a key not allowlisted is an `Ok(false)`
    /// no-op; removing the last member fails with
    /// [`EscrowError::InvalidSponsorPolicy`] — guarding `new()`'s
    /// non-empty invariant — and the live allowlist is untouched;
    /// otherwise the member and its parallel `used` entry are
    /// removed together (the removed member's booked spend leaves
    /// with its entry; its audit trail still lives in
    /// [`SponsorBudget`]'s ring, a separate object, untouched) and
    /// `Ok(true)` is returned. Every other member's `used` is
    /// NEVER touched. The caps and the window are untouched.
    ///
    /// No audit event fires — this module has no amend audit surface
    /// — so the revision behaviour is pinned by tests, as in
    /// AV-352/AV-354.
    pub fn remove_sponsor(&mut self, sponsor: &[u8; 32]) -> Result<bool, EscrowError> {
        let idx = match self.allowed.iter().position(|k| k == sponsor) {
            Some(i) => i,
            None => return Ok(false),
        };
        if self.allowed.len() == 1 {
            return Err(EscrowError::InvalidSponsorPolicy);
        }
        self.allowed.remove(idx);
        self.used.remove(idx);
        Ok(true)
    }

    /// The allowlisted sponsor keys currently in force, in
    /// insertion order. Follows the live allowlist — members added
    /// by [`add_sponsor`](Self::add_sponsor) appear, members
    /// removed by [`remove_sponsor`](Self::remove_sponsor) do not.
    pub fn allowed_sponsors(&self) -> &[[u8; 32]] {
        &self.allowed
    }

    /// The per-transaction lamport cap currently in force (`0` =
    /// unlimited).
    pub fn per_tx_cap(&self) -> u64 {
        self.per_tx_cap
    }

    /// The per-sponsor cumulative lamport cap currently in force
    /// (`0` = unlimited).
    pub fn cumulative_cap(&self) -> u64 {
        self.cumulative_cap
    }

    /// The effective window start currently in force (unix seconds;
    /// `0` = no start bound).
    pub fn window_start(&self) -> u64 {
        self.window_start
    }

    /// The effective window end currently in force (unix seconds,
    /// inclusive; `0` = no end bound).
    pub fn window_end(&self) -> u64 {
        self.window_end
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
    fn cap_getters_read_construction_values() {
        let p = policy();
        assert_eq!(p.per_tx_cap(), 10_000);
        assert_eq!(p.cumulative_cap(), 25_000);
    }

    #[test]
    fn amend_spend_caps_revises_both_caps() {
        let mut p = policy();
        assert!(p.amend_spend_caps(5_000, 50_000));
        assert_eq!(p.per_tx_cap(), 5_000);
        assert_eq!(p.cumulative_cap(), 50_000);
    }

    #[test]
    fn amend_spend_caps_same_pair_is_noop() {
        let mut p = policy();
        assert!(!p.amend_spend_caps(10_000, 25_000));
        assert_eq!(p.per_tx_cap(), 10_000);
        assert_eq!(p.cumulative_cap(), 25_000);
    }

    #[test]
    fn amend_spend_caps_single_field_change() {
        let mut p = policy();
        // Only the cumulative cap moves; per-tx stays put — still true.
        assert!(p.amend_spend_caps(10_000, 40_000));
        assert_eq!(p.per_tx_cap(), 10_000);
        assert_eq!(p.cumulative_cap(), 40_000);
        // Only the per-tx cap moves this time.
        assert!(p.amend_spend_caps(7_000, 40_000));
        assert_eq!(p.per_tx_cap(), 7_000);
        assert_eq!(p.cumulative_cap(), 40_000);
    }

    #[test]
    fn amend_spend_caps_zero_means_unlimited() {
        let mut p = policy();
        assert!(p.amend_spend_caps(0, 0));
        // Amounts over both old caps now pass.
        assert!(p.authorize(&SPONSOR_A, 20_000, 1_500).is_ok());
        assert!(p.authorize(&SPONSOR_A, 30_000, 1_500).is_ok());
        assert_eq!(p.used_by(&SPONSOR_A), Some(50_000));
    }

    #[test]
    fn tighten_cumulative_below_used_locks_remaining_allowance() {
        let mut p = policy();
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert_eq!(p.used_by(&SPONSOR_A), Some(20_000));
        // Tighten below the booked 20_000: no error, books untouched.
        assert!(p.amend_spend_caps(10_000, 15_000));
        assert_eq!(p.used_by(&SPONSOR_A), Some(20_000));
        // Fail-closed: the next authorize is refused, and books
        // nothing — the sponsor stays locked until loosened.
        assert_eq!(
            p.authorize(&SPONSOR_A, 1, 1_500),
            Err(EscrowError::SponsorCumulativeCapExceeded)
        );
        assert_eq!(p.used_by(&SPONSOR_A), Some(20_000));
    }

    #[test]
    fn loosen_cumulative_reopens_authorize() {
        let mut p = policy();
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert!(p.amend_spend_caps(10_000, 15_000));
        assert_eq!(
            p.authorize(&SPONSOR_A, 1, 1_500),
            Err(EscrowError::SponsorCumulativeCapExceeded)
        );
        // Loosening is the only way back in.
        assert!(p.amend_spend_caps(10_000, 30_000));
        assert!(p.authorize(&SPONSOR_A, 5_000, 1_500).is_ok());
        assert_eq!(p.used_by(&SPONSOR_A), Some(25_000));
    }

    #[test]
    fn tighten_per_tx_gate_reads_live_value() {
        let mut p = policy();
        assert!(p.amend_spend_caps(5_000, 25_000));
        assert_eq!(
            p.authorize(&SPONSOR_A, 10_000, 1_500),
            Err(EscrowError::SponsorAmountExceedsPerTxCap)
        );
        // A failed authorize books nothing.
        assert_eq!(p.used_by(&SPONSOR_A), Some(0));
        // In-limit authorizes book normally under the new cap.
        assert!(p.authorize(&SPONSOR_A, 5_000, 1_500).is_ok());
        assert_eq!(p.used_by(&SPONSOR_A), Some(5_000));
    }

    #[test]
    fn amend_spend_caps_does_not_reset_used() {
        let mut p = policy();
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        // Unlike a `new()` rebuild, revision keeps the books.
        assert!(p.amend_spend_caps(5_000, 50_000));
        assert_eq!(p.used_by(&SPONSOR_A), Some(20_000));
    }

    #[test]
    fn amend_spend_caps_does_not_touch_allowlist_or_window() {
        let mut p = policy();
        assert!(p.amend_spend_caps(5_000, 50_000));
        // Non-allowlisted sponsors are still refused first.
        assert_eq!(
            p.authorize(&[0xCC; 32], 100, 1_500),
            Err(EscrowError::SponsorNotAllowed)
        );
        // The window is untouched: out-of-window is still refused.
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 999),
            Err(EscrowError::SponsorWindowInactive)
        );
    }

    #[test]
    fn window_getters_read_construction_values() {
        let p = policy();
        assert_eq!(p.window_start(), 1_000);
        assert_eq!(p.window_end(), 2_000);
    }

    #[test]
    fn amend_sponsor_window_revises_both_bounds() {
        let mut p = policy();
        assert_eq!(p.amend_sponsor_window(3_000, 4_000), Ok(true));
        assert_eq!(p.window_start(), 3_000);
        assert_eq!(p.window_end(), 4_000);
        // The new window governs the next authorize.
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 1_500),
            Err(EscrowError::SponsorWindowInactive)
        );
        assert!(p.authorize(&SPONSOR_A, 100, 3_000).is_ok());
        assert!(p.authorize(&SPONSOR_A, 100, 4_000).is_ok());
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 4_001),
            Err(EscrowError::SponsorWindowInactive)
        );
    }

    #[test]
    fn amend_sponsor_window_same_pair_is_noop() {
        let mut p = policy();
        assert_eq!(p.amend_sponsor_window(1_000, 2_000), Ok(false));
        assert_eq!(p.window_start(), 1_000);
        assert_eq!(p.window_end(), 2_000);
        assert!(p.authorize(&SPONSOR_A, 100, 1_500).is_ok());
    }

    #[test]
    fn amend_sponsor_window_single_bound_change() {
        let mut p = policy();
        // Only the end moves; the start stays put — still true.
        assert_eq!(p.amend_sponsor_window(1_000, 3_000), Ok(true));
        assert_eq!(p.window_start(), 1_000);
        assert_eq!(p.window_end(), 3_000);
        assert!(p.authorize(&SPONSOR_A, 100, 2_500).is_ok());
        // Only the start moves this time.
        assert_eq!(p.amend_sponsor_window(2_000, 3_000), Ok(true));
        assert_eq!(p.window_start(), 2_000);
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 1_500),
            Err(EscrowError::SponsorWindowInactive)
        );
    }

    #[test]
    fn amend_sponsor_window_rejects_inverted_window_and_keeps_live() {
        let mut p = policy();
        assert_eq!(
            p.amend_sponsor_window(2_000, 1_000),
            Err(EscrowError::InvalidSponsorPolicy)
        );
        // The live window is untouched: the old bounds still govern.
        assert_eq!(p.window_start(), 1_000);
        assert_eq!(p.window_end(), 2_000);
        assert!(p.authorize(&SPONSOR_A, 100, 1_500).is_ok());
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 999),
            Err(EscrowError::SponsorWindowInactive)
        );
    }

    #[test]
    fn amend_sponsor_window_sentinels_still_hold() {
        let mut p = policy();
        // (0, 0) = always active.
        assert_eq!(p.amend_sponsor_window(0, 0), Ok(true));
        assert!(p.authorize(&SPONSOR_A, 100, 0).is_ok());
        assert!(p.authorize(&SPONSOR_A, 100, u64::MAX).is_ok());
        // Open-ended: active from the start, no end bound.
        assert_eq!(p.amend_sponsor_window(5_000, 0), Ok(true));
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 4_999),
            Err(EscrowError::SponsorWindowInactive)
        );
        assert!(p.authorize(&SPONSOR_A, 100, u64::MAX).is_ok());
    }

    #[test]
    fn tighten_window_closes_authorize_immediately_and_keeps_used() {
        let mut p = policy();
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert_eq!(p.used_by(&SPONSOR_A), Some(10_000));
        // Close the window at once: the next authorize is refused
        // fail-closed, and the books are untouched.
        assert_eq!(p.amend_sponsor_window(3_000, 4_000), Ok(true));
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 1_500),
            Err(EscrowError::SponsorWindowInactive)
        );
        assert_eq!(p.used_by(&SPONSOR_A), Some(10_000));
    }

    #[test]
    fn loosen_window_reopens_authorize() {
        let mut p = policy();
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert_eq!(p.amend_sponsor_window(3_000, 4_000), Ok(true));
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 1_500),
            Err(EscrowError::SponsorWindowInactive)
        );
        // Loosening is the only way back in.
        assert_eq!(p.amend_sponsor_window(1_000, 2_000), Ok(true));
        assert!(p.authorize(&SPONSOR_A, 5_000, 1_500).is_ok());
        assert_eq!(p.used_by(&SPONSOR_A), Some(15_000));
    }

    #[test]
    fn amend_sponsor_window_does_not_touch_caps_allowlist_or_used() {
        let mut p = policy();
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert_eq!(p.amend_sponsor_window(3_000, 4_000), Ok(true));
        // Unlike a `new()` rebuild, revision keeps the books.
        assert_eq!(p.used_by(&SPONSOR_A), Some(10_000));
        // The caps are untouched.
        assert_eq!(p.per_tx_cap(), 10_000);
        assert_eq!(p.cumulative_cap(), 25_000);
        // Non-allowlisted sponsors are still refused first.
        assert_eq!(
            p.authorize(&[0xCC; 32], 100, 3_500),
            Err(EscrowError::SponsorNotAllowed)
        );
    }

    #[test]
    fn amend_sponsor_window_does_not_touch_budget() {
        let mut p = policy();
        let mut b = SponsorBudget::new();
        b.fund(5_000);
        b.deduct(2_000, SPONSOR_A, ESCROW_X, 123).unwrap();
        assert_eq!(p.amend_sponsor_window(3_000, 4_000), Ok(true));
        assert_eq!(b.balance(), 3_000);
        assert_eq!(b.total_funded(), 5_000);
        assert_eq!(b.total_spent(), 2_000);
        assert_eq!(b.audit().len(), 1);
    }

    #[test]
    fn repeated_window_revisions_each_take_effect() {
        let mut p = policy();
        assert_eq!(p.amend_sponsor_window(1_500, 2_500), Ok(true));
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 1_000),
            Err(EscrowError::SponsorWindowInactive)
        );
        assert!(p.authorize(&SPONSOR_A, 100, 2_000).is_ok());
        assert_eq!(p.amend_sponsor_window(0, 0), Ok(true));
        assert!(p.authorize(&SPONSOR_A, 100, 1_000).is_ok());
        assert_eq!(p.used_by(&SPONSOR_A), Some(200));
    }

    #[test]
    fn amend_spend_caps_does_not_touch_budget() {
        let mut p = policy();
        let mut b = SponsorBudget::new();
        b.fund(5_000);
        b.deduct(2_000, SPONSOR_A, ESCROW_X, 123).unwrap();
        assert!(p.amend_spend_caps(5_000, 50_000));
        assert_eq!(b.balance(), 3_000);
        assert_eq!(b.total_funded(), 5_000);
        assert_eq!(b.total_spent(), 2_000);
        assert_eq!(b.audit().len(), 1);
    }

    #[test]
    fn repeated_revisions_each_take_effect() {
        let mut p = policy();
        assert!(p.amend_spend_caps(8_000, 20_000));
        assert_eq!(
            p.authorize(&SPONSOR_A, 9_000, 1_500),
            Err(EscrowError::SponsorAmountExceedsPerTxCap)
        );
        assert!(p.amend_spend_caps(12_000, 20_000));
        assert!(p.authorize(&SPONSOR_A, 9_000, 1_500).is_ok());
        assert!(p.amend_spend_caps(12_000, 9_000));
        // 9_000 booked already meets the tightened cumulative cap.
        assert_eq!(
            p.authorize(&SPONSOR_A, 1, 1_500),
            Err(EscrowError::SponsorCumulativeCapExceeded)
        );
        assert_eq!(p.used_by(&SPONSOR_A), Some(9_000));
    }

    const SPONSOR_C: [u8; 32] = [0xC3; 32];

    #[test]
    fn add_sponsor_adds_new_member_usable_from_next_authorize() {
        let mut p = policy();
        assert_eq!(p.add_sponsor(SPONSOR_C), Ok(true));
        assert_eq!(p.allowed_sponsors(), &[SPONSOR_A, SPONSOR_B, SPONSOR_C]);
        // The new member starts booked from zero.
        assert_eq!(p.used_by(&SPONSOR_C), Some(0));
        assert!(p.authorize(&SPONSOR_C, 100, 1_500).is_ok());
        assert_eq!(p.used_by(&SPONSOR_C), Some(100));
    }

    #[test]
    fn add_sponsor_duplicate_is_noop() {
        let mut p = policy();
        assert_eq!(p.add_sponsor(SPONSOR_A), Ok(false));
        assert_eq!(p.allowed_sponsors(), &[SPONSOR_A, SPONSOR_B]);
        assert!(p.authorize(&SPONSOR_A, 100, 1_500).is_ok());
    }

    #[test]
    fn add_sponsor_rejects_zero_key_and_keeps_live() {
        let mut p = policy();
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert_eq!(
            p.add_sponsor([0u8; 32]),
            Err(EscrowError::InvalidSponsorPolicy)
        );
        // The live allowlist is untouched.
        assert_eq!(p.allowed_sponsors(), &[SPONSOR_A, SPONSOR_B]);
        assert_eq!(p.used_by(&SPONSOR_A), Some(10_000));
        assert_eq!(p.used_by(&SPONSOR_B), Some(0));
    }

    #[test]
    fn add_sponsor_rejects_full_allowlist_and_keeps_live() {
        let mut keys = vec![SPONSOR_A];
        for i in 1..MAX_SPONSORS {
            keys.push([i as u8; 32]);
        }
        let mut p = SponsorPolicy::new(&keys, 10_000, 25_000, 0, 0).unwrap();
        assert_eq!(p.allowed_sponsors().len(), MAX_SPONSORS);
        assert_eq!(
            p.add_sponsor(SPONSOR_C),
            Err(EscrowError::InvalidSponsorPolicy)
        );
        assert_eq!(p.allowed_sponsors().len(), MAX_SPONSORS);
        assert!(!p.is_allowed(&SPONSOR_C));
    }

    #[test]
    fn add_sponsor_does_not_touch_used_caps_or_window() {
        let mut p = policy();
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert_eq!(p.add_sponsor(SPONSOR_C), Ok(true));
        // Unlike a `new()` rebuild, revision keeps the books.
        assert_eq!(p.used_by(&SPONSOR_A), Some(10_000));
        assert_eq!(p.used_by(&SPONSOR_B), Some(0));
        // The caps and the window are untouched.
        assert_eq!(p.per_tx_cap(), 10_000);
        assert_eq!(p.cumulative_cap(), 25_000);
        assert_eq!(p.window_start(), 1_000);
        assert_eq!(p.window_end(), 2_000);
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 999),
            Err(EscrowError::SponsorWindowInactive)
        );
    }

    #[test]
    fn remove_sponsor_removes_member_and_its_used_entry() {
        let mut p = policy();
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert!(p.authorize(&SPONSOR_B, 5_000, 1_500).is_ok());
        assert_eq!(p.remove_sponsor(&SPONSOR_A), Ok(true));
        assert_eq!(p.allowed_sponsors(), &[SPONSOR_B]);
        // The removed member's booked spend leaves with its entry;
        // the survivor's books are untouched.
        assert_eq!(p.used_by(&SPONSOR_A), None);
        assert_eq!(p.used_by(&SPONSOR_B), Some(5_000));
        // Fail-closed: the next authorize refuses the removed member.
        assert_eq!(
            p.authorize(&SPONSOR_A, 100, 1_500),
            Err(EscrowError::SponsorNotAllowed)
        );
        assert_eq!(p.used_by(&SPONSOR_A), None);
        // The survivor still authorizes and books normally.
        assert!(p.authorize(&SPONSOR_B, 100, 1_500).is_ok());
        assert_eq!(p.used_by(&SPONSOR_B), Some(5_100));
    }

    #[test]
    fn remove_sponsor_unknown_is_noop() {
        let mut p = policy();
        assert_eq!(p.remove_sponsor(&[0xCC; 32]), Ok(false));
        assert_eq!(p.allowed_sponsors(), &[SPONSOR_A, SPONSOR_B]);
        assert!(p.authorize(&SPONSOR_A, 100, 1_500).is_ok());
    }

    #[test]
    fn remove_sponsor_rejects_emptying_allowlist_and_keeps_live() {
        let mut p = SponsorPolicy::new(&[SPONSOR_A], 10_000, 25_000, 1_000, 2_000).unwrap();
        assert_eq!(
            p.remove_sponsor(&SPONSOR_A),
            Err(EscrowError::InvalidSponsorPolicy)
        );
        // The live allowlist is untouched.
        assert_eq!(p.allowed_sponsors(), &[SPONSOR_A]);
        assert!(p.authorize(&SPONSOR_A, 100, 1_500).is_ok());
    }

    #[test]
    fn remove_sponsor_does_not_touch_caps_window_or_budget() {
        let mut p = policy();
        let mut b = SponsorBudget::new();
        b.fund(5_000);
        b.deduct(2_000, SPONSOR_A, ESCROW_X, 123).unwrap();
        assert!(p.authorize(&SPONSOR_A, 10_000, 1_500).is_ok());
        assert_eq!(p.remove_sponsor(&SPONSOR_B), Ok(true));
        assert_eq!(p.used_by(&SPONSOR_A), Some(10_000));
        assert_eq!(p.per_tx_cap(), 10_000);
        assert_eq!(p.cumulative_cap(), 25_000);
        assert_eq!(p.window_start(), 1_000);
        assert_eq!(p.window_end(), 2_000);
        assert_eq!(b.balance(), 3_000);
        assert_eq!(b.total_spent(), 2_000);
        assert_eq!(b.audit().len(), 1);
    }

    #[test]
    fn repeated_add_remove_each_take_effect() {
        let mut p = policy();
        assert_eq!(p.add_sponsor(SPONSOR_C), Ok(true));
        assert!(p.authorize(&SPONSOR_C, 100, 1_500).is_ok());
        assert_eq!(p.remove_sponsor(&SPONSOR_C), Ok(true));
        assert_eq!(
            p.authorize(&SPONSOR_C, 100, 1_500),
            Err(EscrowError::SponsorNotAllowed)
        );
        // Re-adding starts the member booked from zero again.
        assert_eq!(p.add_sponsor(SPONSOR_C), Ok(true));
        assert_eq!(p.used_by(&SPONSOR_C), Some(0));
        assert!(p.authorize(&SPONSOR_C, 100, 1_500).is_ok());
        assert_eq!(p.used_by(&SPONSOR_C), Some(100));
    }

    #[test]
    fn allowed_sponsors_getter_follows_live_value() {
        let p = policy();
        assert_eq!(p.allowed_sponsors(), &[SPONSOR_A, SPONSOR_B]);
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
