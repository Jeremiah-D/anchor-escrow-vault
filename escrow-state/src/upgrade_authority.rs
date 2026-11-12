//! AV-179: program upgrade-authority handover — two-step propose/accept
//! with an opt-in handover delay (Solana governance / backend
//! engineering).
//!
//! On Solana, `set_upgrade_authority` on the BPF loader is a single
//! instruction: whoever holds the upgrade authority can reassign it in
//! one transaction, irreversibly and silently. A fat-fingered key or a
//! compromised authority can brick the program's upgradability in one
//! shot, and no on-chain record explains who moved the authority or
//! why.
//!
//! [`UpgradeAuthority`] is the executable spec of the safe handover:
//!
//! - **Two-step**: the current authority *proposes* a successor via
//!   [`propose_handover`](UpgradeAuthority::propose_handover); the
//!   *proposed* key must *accept* via
//!   [`confirm_handover`](UpgradeAuthority::confirm_handover). The
//!   current authority can never silently hand the program to a key
//!   nobody controls — the recipient opts in (the Ownable2Step shape,
//!   adapted to program governance).
//! - **Delay**: `handover_delay_secs` forces a cooling period between
//!   proposal and acceptance; a rushed or coerced handover cannot
//!   complete inside the window. The clock is injected (`now: u64`),
//!   so the policy is fully testable off-chain.
//! - **Structured audit**: propose / confirm / cancel append a
//!   [`UpgradeAuditEntry`] to a bounded 32-entry ring (the AV-163
//!   circuit-breaker convention — fixed-size tail, oldest evicts
//!   first).
//! - **Renounce (AV-415)**: the current authority may give the
//!   authority back to nobody via
//!   [`renounce_upgrade_authority`](UpgradeAuthority::renounce_upgrade_authority),
//!   the loader's `set_upgrade_authority`-to-`None` terminal step.
//!   One-way and audited (`UpgradeAuthorityRenounced`, successor slot
//!   zero); a live proposal blocks it — cancel first. After renounce
//!   there is no authority to compare against, so propose / amend are
//!   `Unauthorized` and confirm / cancel are
//!   `NoUpgradeHandoverPending`; renouncing again is a silent no-op.
//! - **Keeper drift scan**:
//!   [`scan_upgrade_authority_drift`] diffs the live authority against
//!   the operator-approved template and raises a drift alert — the
//!   AV-175 config-drift vocabulary applied to program governance. A
//!   drifted authority is either a completed handover the operator
//!   did not approve or a tampered program account.
//!
//! # What is deliberately NOT here (honesty labels)
//!
//! - **This does not call the BPF loader.** The on-chain program still
//!   issues `set_upgrade_authority` through the loader after the
//!   custody check; this module is the off-chain executable spec both
//!   the program and the keeper tooling pin against (the same honesty
//!   contract as AV-163's circuit breaker).
//! - **The delay is a live-revisable deployment policy, not a
//!   consensus.** `handover_delay_secs` is bound at construction and
//!   may be revised in place by the current authority via
//!   [`amend_handover_delay_secs`](UpgradeAuthority::amend_handover_delay_secs)
//!   (AV-356) — no rebuild, so the audit ring and any in-flight
//!   proposal survive; the new delay governs the next
//!   [`confirm_handover`](UpgradeAuthority::confirm_handover).
//! - **Acceptance cannot be forced.** If the proposed key never
//!   accepts, the current authority cancels the proposal via
//!   [`cancel_handover`](UpgradeAuthority::cancel_handover); there is
//!   no expiry auto-cancel in this round (a later item may add one).
//! - **No multisig quorum.** The handover is a single-authority action
//!   by design (it mirrors the loader's single-authority model); a
//!   multisig-gated handover would be a governance layer above this.
//! - **No un-renounce.** Renouncing the authority (AV-415) is one-way
//!   by design — the loader has no instruction that restores an
//!   authority once it is set to `None`; the program becomes immutable.

use super::EscrowError;

/// How many handover events the authority remembers: a bounded ring,
/// mirroring the AV-163 circuit-breaker convention (fixed-size tail,
/// oldest evicts first).
pub const MAX_UPGRADE_AUDIT_ENTRIES: usize = 32;

/// The handover lifecycle events carried by [`UpgradeAuditEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeAuthorityEventKind {
    /// A successor was proposed by the current authority.
    HandoverProposed,
    /// The proposed successor accepted; the authority moved.
    HandoverConfirmed,
    /// The live proposal was cancelled by the current authority.
    HandoverCancelled,
    /// The handover delay was revised by the current authority.
    HandoverDelayAmended,
    /// The current authority renounced the upgrade authority (AV-415):
    /// the program is now immutable, with no authority left to move.
    UpgradeAuthorityRenounced,
}

/// One structured audit entry: what happened, when, who acted, and
/// which successor key the event concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeAuditEntry {
    /// Propose, confirm, cancel, or delay amendment.
    pub kind: UpgradeAuthorityEventKind,
    /// Unix timestamp of the event (clock sysvar on-chain).
    pub at: u64,
    /// The key that acted (proposer / confirmer / canceller).
    pub actor: [u8; 32],
    /// The proposed successor on propose, the confirmed successor on
    /// confirm, the withdrawn proposal on cancel.
    pub successor: [u8; 32],
}

/// A live handover proposal: the successor, who proposed it, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingHandover {
    proposed: [u8; 32],
    proposed_by: [u8; 32],
    proposed_at: u64,
}

/// The program's upgrade-authority custody with the two-step handover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeAuthority {
    /// The live upgrade authority; `None` once renounced (AV-415) —
    /// the program is then immutable and no key may act as authority.
    current: Option<[u8; 32]>,
    /// The in-flight proposal, if any (at most one — a second proposal
    /// must wait for cancel or confirm).
    pending: Option<PendingHandover>,
    /// Cooling period between proposal and acceptance, in seconds.
    handover_delay_secs: u64,
    /// Bounded audit ring of handover events.
    audit: [Option<UpgradeAuditEntry>; MAX_UPGRADE_AUDIT_ENTRIES],
    /// Number of valid entries in `audit`.
    audit_len: usize,
    /// Ring index of the oldest entry.
    audit_start: usize,
}

impl UpgradeAuthority {
    /// Bind the initial authority and the handover delay. The zero key
    /// is rejected — an unbound authority would be ungovernable, and a
    /// zero-key handover target is the classic fat-finger this module
    /// exists to prevent.
    pub fn new(current: [u8; 32], handover_delay_secs: u64) -> Result<Self, EscrowError> {
        if current == [0u8; 32] {
            return Err(EscrowError::InvalidUpgradeAuthority);
        }
        Ok(UpgradeAuthority {
            current: Some(current),
            pending: None,
            handover_delay_secs,
            audit: [None; MAX_UPGRADE_AUDIT_ENTRIES],
            audit_len: 0,
            audit_start: 0,
        })
    }

    /// The live upgrade authority; `None` once renounced (AV-415).
    pub fn current(&self) -> Option<[u8; 32]> {
        self.current
    }

    /// The live handover delay, in seconds (AV-356 revisable).
    pub fn handover_delay_secs(&self) -> u64 {
        self.handover_delay_secs
    }

    /// Revise the handover delay in place (AV-356). Only the current
    /// authority; any `u64` is accepted (`new()` never validated the
    /// delay, and `0` — no cooling — is the operator's explicit
    /// choice). Re-affirming the current delay is an `Ok(false)`
    /// no-op that writes no audit entry. Any other value replaces the
    /// delay atomically, returns `Ok(true)`, and appends a
    /// `HandoverDelayAmended` entry (actor: the caller; the delay
    /// revision has no successor key, so the successor slot records
    /// the acting authority itself, by documented convention). The
    /// new delay governs the next `confirm_handover` — which reads
    /// the live value — so an in-flight proposal is re-measured
    /// against it: raising the delay can hold a proposed handover,
    /// lowering it can release one. `current` / `pending` are
    /// untouched, and `scan_upgrade_authority_drift` compares only
    /// the authority, so a delay revision never reads as drift.
    /// Check order: authority, then same-value.
    pub fn amend_handover_delay_secs(
        &mut self,
        caller: [u8; 32],
        new_delay_secs: u64,
        now: u64,
    ) -> Result<bool, EscrowError> {
        if Some(caller) != self.current {
            return Err(EscrowError::Unauthorized);
        }
        if new_delay_secs == self.handover_delay_secs {
            return Ok(false);
        }
        self.handover_delay_secs = new_delay_secs;
        self.push_audit(UpgradeAuditEntry {
            kind: UpgradeAuthorityEventKind::HandoverDelayAmended,
            at: now,
            actor: caller,
            successor: caller,
        });
        Ok(true)
    }

    /// The live proposal as `(proposed successor, proposed_at)`, if any.
    pub fn pending_proposal(&self) -> Option<([u8; 32], u64)> {
        self.pending
            .map(|p| (p.proposed, p.proposed_at))
    }

    /// Step 1 — propose a successor. Only the current authority; the
    /// successor must be a live, distinct key (the zero key and the
    /// current key are both rejected); at most one proposal may be
    /// live (cancel it first). Check order mirrors AV-163: authority
    /// first, then validity, then state.
    pub fn propose_handover(
        &mut self,
        caller: [u8; 32],
        new_authority: [u8; 32],
        now: u64,
    ) -> Result<(), EscrowError> {
        if Some(caller) != self.current {
            return Err(EscrowError::Unauthorized);
        }
        if new_authority == [0u8; 32] || Some(new_authority) == self.current {
            return Err(EscrowError::InvalidUpgradeAuthority);
        }
        if self.pending.is_some() {
            return Err(EscrowError::UpgradeHandoverPending);
        }
        self.pending = Some(PendingHandover {
            proposed: new_authority,
            proposed_by: caller,
            proposed_at: now,
        });
        self.push_audit(UpgradeAuditEntry {
            kind: UpgradeAuthorityEventKind::HandoverProposed,
            at: now,
            actor: caller,
            successor: new_authority,
        });
        Ok(())
    }

    /// Step 2 — accept the handover. Only the *proposed* successor may
    /// accept: the current authority cannot silently move the program
    /// to a key nobody controls. Acceptance is refused before
    /// `proposed_at + handover_delay_secs`. Check order: pending
    /// exists, then authority, then delay.
    pub fn confirm_handover(&mut self, caller: [u8; 32], now: u64) -> Result<(), EscrowError> {
        let p = self.pending.ok_or(EscrowError::NoUpgradeHandoverPending)?;
        if caller != p.proposed {
            return Err(EscrowError::Unauthorized);
        }
        if now < p.proposed_at.saturating_add(self.handover_delay_secs) {
            return Err(EscrowError::UpgradeHandoverDelayNotElapsed);
        }
        self.current = Some(p.proposed);
        self.pending = None;
        self.push_audit(UpgradeAuditEntry {
            kind: UpgradeAuthorityEventKind::HandoverConfirmed,
            at: now,
            actor: caller,
            successor: p.proposed,
        });
        Ok(())
    }

    /// Withdraw a live proposal. Only the current authority; with no
    /// live proposal this is a loud refuse, never a silent no-op.
    pub fn cancel_handover(&mut self, caller: [u8; 32], now: u64) -> Result<(), EscrowError> {
        let p = self.pending.ok_or(EscrowError::NoUpgradeHandoverPending)?;
        if Some(caller) != self.current {
            return Err(EscrowError::Unauthorized);
        }
        self.pending = None;
        self.push_audit(UpgradeAuditEntry {
            kind: UpgradeAuthorityEventKind::HandoverCancelled,
            at: now,
            actor: caller,
            successor: p.proposed,
        });
        Ok(())
    }

    /// Renounce the upgrade authority (AV-415): give the authority
    /// back to nobody, the loader's `set_upgrade_authority`-to-`None`
    /// terminal step — the program becomes immutable. One-way: there
    /// is no un-renounce. Only the current authority; a live proposal
    /// blocks the renounce (cancel it first), otherwise the proposed
    /// successor could still confirm into a program whose authority
    /// was already given away. Already renounced is a silent no-op
    /// `Ok(())` regardless of caller (the AV-413 re-revoke
    /// convention), checked before the authority check. A successful
    /// renounce appends an `UpgradeAuthorityRenounced` entry (actor:
    /// the caller; the successor slot records the zero key — the
    /// authority in effect after renounce is "none", distinguished
    /// from a handover by the kind). Check order: renounced, then
    /// authority, then pending.
    pub fn renounce_upgrade_authority(
        &mut self,
        caller: [u8; 32],
        now: u64,
    ) -> Result<(), EscrowError> {
        if self.current.is_none() {
            return Ok(());
        }
        if Some(caller) != self.current {
            return Err(EscrowError::Unauthorized);
        }
        if self.pending.is_some() {
            return Err(EscrowError::UpgradeHandoverPending);
        }
        self.current = None;
        self.push_audit(UpgradeAuditEntry {
            kind: UpgradeAuthorityEventKind::UpgradeAuthorityRenounced,
            at: now,
            actor: caller,
            successor: [0u8; 32],
        });
        Ok(())
    }

    /// The structured audit log, oldest first.
    pub fn audit_log(&self) -> Vec<UpgradeAuditEntry> {
        let mut out = Vec::with_capacity(self.audit_len);
        for i in 0..self.audit_len {
            let idx = (self.audit_start + i) % MAX_UPGRADE_AUDIT_ENTRIES;
            if let Some(e) = self.audit[idx] {
                out.push(e);
            }
        }
        out
    }

    fn push_audit(&mut self, entry: UpgradeAuditEntry) {
        if self.audit_len < MAX_UPGRADE_AUDIT_ENTRIES {
            let idx = (self.audit_start + self.audit_len) % MAX_UPGRADE_AUDIT_ENTRIES;
            self.audit[idx] = Some(entry);
            self.audit_len += 1;
        } else {
            // Ring full: overwrite the oldest.
            self.audit[self.audit_start] = Some(entry);
            self.audit_start = (self.audit_start + 1) % MAX_UPGRADE_AUDIT_ENTRIES;
        }
    }
}

/// The keeper's drift alert: the live upgrade authority no longer
/// matches the operator-approved template (AV-175 vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeAuthorityDrift {
    /// The operator-approved authority.
    pub expected: [u8; 32],
    /// The live on-chain authority.
    pub actual: [u8; 32],
    /// A handover proposal is live while the authority already
    /// drifted — the keeper sees both the drift and where the next
    /// move is heading.
    pub pending_proposal: Option<[u8; 32]>,
}

/// Keeper entry point: diff the live authority against the
/// operator-approved template. `None` when they match; `Some` drift
/// alert otherwise. Pure and read-only (the AV-175 scan convention).
/// A renounced authority (AV-415) compares as the zero key — the
/// loader's encoding of "no authority" — so a template expecting a
/// live key reports drift, and a template expecting the zero key
/// (an intentionally immutable program) matches.
pub fn scan_upgrade_authority_drift(
    authority: &UpgradeAuthority,
    expected_authority: [u8; 32],
) -> Option<UpgradeAuthorityDrift> {
    let actual = authority.current().unwrap_or([0u8; 32]);
    if actual == expected_authority {
        return None;
    }
    Some(UpgradeAuthorityDrift {
        expected: expected_authority,
        actual,
        pending_proposal: authority.pending_proposal().map(|(p, _)| p),
    })
}

#[cfg(test)]
mod upgrade_authority_tests {
    use super::*;

    const CURRENT: [u8; 32] = [0xA1; 32];
    const SUCCESSOR: [u8; 32] = [0xB2; 32];
    const STRANGER: [u8; 32] = [0xCC; 32];
    const DELAY: u64 = 3_600;

    fn authority() -> UpgradeAuthority {
        UpgradeAuthority::new(CURRENT, DELAY).unwrap()
    }

    #[test]
    fn new_rejects_the_zero_authority_key() {
        assert_eq!(
            UpgradeAuthority::new([0u8; 32], DELAY),
            Err(EscrowError::InvalidUpgradeAuthority)
        );
        let a = authority();
        assert_eq!(a.current(), Some(CURRENT));
        assert_eq!(a.handover_delay_secs(), DELAY);
        assert_eq!(a.pending_proposal(), None);
        assert!(a.audit_log().is_empty());
    }

    #[test]
    fn propose_records_the_pending_handover_and_audits() {
        let mut a = authority();
        a.propose_handover(CURRENT, SUCCESSOR, 1_000).unwrap();
        assert_eq!(a.pending_proposal(), Some((SUCCESSOR, 1_000)));
        // The proposal changes nothing live yet.
        assert_eq!(a.current(), Some(CURRENT));
        let log = a.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].kind, UpgradeAuthorityEventKind::HandoverProposed);
        assert_eq!(log[0].at, 1_000);
        assert_eq!(log[0].actor, CURRENT);
        assert_eq!(log[0].successor, SUCCESSOR);
    }

    #[test]
    fn propose_rejects_a_stranger_and_changes_nothing() {
        let mut a = authority();
        assert_eq!(
            a.propose_handover(STRANGER, SUCCESSOR, 1_000),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(a.pending_proposal(), None);
        assert!(a.audit_log().is_empty());
    }

    #[test]
    fn propose_rejects_zero_and_self_successors() {
        let mut a = authority();
        assert_eq!(
            a.propose_handover(CURRENT, [0u8; 32], 1_000),
            Err(EscrowError::InvalidUpgradeAuthority)
        );
        assert_eq!(
            a.propose_handover(CURRENT, CURRENT, 1_000),
            Err(EscrowError::InvalidUpgradeAuthority)
        );
        assert_eq!(a.pending_proposal(), None);
    }

    #[test]
    fn propose_while_pending_is_upgrade_handover_pending() {
        let mut a = authority();
        a.propose_handover(CURRENT, SUCCESSOR, 1_000).unwrap();
        assert_eq!(
            a.propose_handover(CURRENT, STRANGER, 2_000),
            Err(EscrowError::UpgradeHandoverPending)
        );
        // The first proposal survives untouched.
        assert_eq!(a.pending_proposal(), Some((SUCCESSOR, 1_000)));
    }

    #[test]
    fn confirm_by_the_proposed_key_moves_the_authority() {
        let mut a = authority();
        a.propose_handover(CURRENT, SUCCESSOR, 1_000).unwrap();
        // Inside the delay: refused.
        assert_eq!(
            a.confirm_handover(SUCCESSOR, 1_000 + DELAY - 1),
            Err(EscrowError::UpgradeHandoverDelayNotElapsed)
        );
        assert_eq!(a.current(), Some(CURRENT));
        // At exactly the deadline: accepted.
        a.confirm_handover(SUCCESSOR, 1_000 + DELAY).unwrap();
        assert_eq!(a.current(), Some(SUCCESSOR));
        assert_eq!(a.pending_proposal(), None);
        let log = a.audit_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].kind, UpgradeAuthorityEventKind::HandoverConfirmed);
        assert_eq!(log[1].actor, SUCCESSOR);
        assert_eq!(log[1].successor, SUCCESSOR);
    }

    #[test]
    fn confirm_rejects_the_current_authority_and_strangers() {
        // The current authority cannot accept its own proposal — only
        // the proposed successor opts in (the anti-usurpation rule).
        let mut a = authority();
        a.propose_handover(CURRENT, SUCCESSOR, 1_000).unwrap();
        assert_eq!(
            a.confirm_handover(CURRENT, 1_000 + DELAY),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            a.confirm_handover(STRANGER, 1_000 + DELAY),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(a.current(), Some(CURRENT));
    }

    #[test]
    fn confirm_with_no_pending_is_no_upgrade_handover_pending() {
        let mut a = authority();
        assert_eq!(
            a.confirm_handover(SUCCESSOR, 5_000),
            Err(EscrowError::NoUpgradeHandoverPending)
        );
        assert!(a.audit_log().is_empty());
    }

    #[test]
    fn cancel_withdraws_the_proposal_and_audits() {
        let mut a = authority();
        a.propose_handover(CURRENT, SUCCESSOR, 1_000).unwrap();
        a.cancel_handover(CURRENT, 2_000).unwrap();
        assert_eq!(a.pending_proposal(), None);
        assert_eq!(a.current(), Some(CURRENT));
        let log = a.audit_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[1].kind, UpgradeAuthorityEventKind::HandoverCancelled);
        assert_eq!(log[1].actor, CURRENT);
        assert_eq!(log[1].successor, SUCCESSOR);
        // A new proposal may follow the cancel.
        a.propose_handover(CURRENT, STRANGER, 3_000).unwrap();
        assert_eq!(a.pending_proposal(), Some((STRANGER, 3_000)));
    }

    #[test]
    fn cancel_rejects_strangers_and_empty_state() {
        let mut a = authority();
        assert_eq!(
            a.cancel_handover(CURRENT, 1_000),
            Err(EscrowError::NoUpgradeHandoverPending)
        );
        a.propose_handover(CURRENT, SUCCESSOR, 1_000).unwrap();
        assert_eq!(
            a.cancel_handover(STRANGER, 2_000),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(a.pending_proposal(), Some((SUCCESSOR, 1_000)));
    }

    #[test]
    fn failed_transitions_audit_nothing() {
        let mut a = authority();
        let _ = a.propose_handover(STRANGER, SUCCESSOR, 1);
        let _ = a.propose_handover(CURRENT, [0u8; 32], 2);
        let _ = a.confirm_handover(SUCCESSOR, 3);
        let _ = a.cancel_handover(CURRENT, 4);
        assert!(a.audit_log().is_empty());
        a.propose_handover(CURRENT, SUCCESSOR, 5).unwrap();
        let _ = a.confirm_handover(CURRENT, 5 + DELAY);
        let _ = a.confirm_handover(SUCCESSOR, 5);
        assert_eq!(a.audit_log().len(), 1);
    }

    #[test]
    fn audit_ring_is_bounded_and_chronological() {
        let mut a = UpgradeAuthority::new(CURRENT, 0).unwrap();
        // 40 propose/cancel pairs > 32 slots: oldest 8 evict.
        for i in 0..40u64 {
            a.propose_handover(CURRENT, SUCCESSOR, 2 * i).unwrap();
            a.cancel_handover(CURRENT, 2 * i + 1).unwrap();
        }
        let log = a.audit_log();
        assert_eq!(log.len(), MAX_UPGRADE_AUDIT_ENTRIES);
        for w in log.windows(2) {
            assert!(w[0].at < w[1].at);
        }
        // The surviving 32 are pairs 24..40.
        assert_eq!(log[0].at, 48);
        assert_eq!(log[31].at, 79);
    }

    #[test]
    fn drift_scan_is_quiet_when_the_authority_matches() {
        let a = authority();
        assert_eq!(scan_upgrade_authority_drift(&a, CURRENT), None);
    }

    #[test]
    fn drift_scan_alerts_on_mismatch_with_pending_direction() {
        let mut a = authority();
        a.propose_handover(CURRENT, SUCCESSOR, 1_000).unwrap();
        a.confirm_handover(SUCCESSOR, 1_000 + DELAY).unwrap();
        let drift = scan_upgrade_authority_drift(&a, CURRENT).unwrap();
        assert_eq!(drift.expected, CURRENT);
        assert_eq!(drift.actual, SUCCESSOR);
        assert_eq!(drift.pending_proposal, None);
        // A drifted authority with a live proposal shows the heading.
        let mut b = authority();
        b.propose_handover(CURRENT, SUCCESSOR, 1_000).unwrap();
        let drift = scan_upgrade_authority_drift(&b, STRANGER).unwrap();
        assert_eq!(drift.actual, CURRENT);
        assert_eq!(drift.pending_proposal, Some(SUCCESSOR));
    }

    #[test]
    fn amend_handover_delay_revises_and_audits() {
        let mut a = authority();
        assert_eq!(
            a.amend_handover_delay_secs(CURRENT, 7_200, 1_000),
            Ok(true)
        );
        assert_eq!(a.handover_delay_secs(), 7_200);
        // Nothing else moves: the authority and the (absent) proposal
        // are untouched, and the drift scan stays quiet.
        assert_eq!(a.current(), Some(CURRENT));
        assert_eq!(a.pending_proposal(), None);
        assert_eq!(scan_upgrade_authority_drift(&a, CURRENT), None);
        let log = a.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(
            log[0].kind,
            UpgradeAuthorityEventKind::HandoverDelayAmended
        );
        assert_eq!(log[0].at, 1_000);
        assert_eq!(log[0].actor, CURRENT);
        // A delay revision has no successor key: the successor slot
        // records the acting authority itself, by convention.
        assert_eq!(log[0].successor, CURRENT);
    }

    #[test]
    fn amend_handover_delay_rejects_a_stranger_and_changes_nothing() {
        let mut a = authority();
        assert_eq!(
            a.amend_handover_delay_secs(STRANGER, 7_200, 1_000),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(a.handover_delay_secs(), DELAY);
        assert!(a.audit_log().is_empty());
    }

    #[test]
    fn amend_handover_delay_same_value_is_a_noop() {
        let mut a = authority();
        assert_eq!(
            a.amend_handover_delay_secs(CURRENT, DELAY, 1_000),
            Ok(false)
        );
        assert_eq!(a.handover_delay_secs(), DELAY);
        assert!(a.audit_log().is_empty());
    }

    #[test]
    fn amend_handover_delay_to_zero_removes_the_cooling() {
        let mut a = authority();
        assert_eq!(a.amend_handover_delay_secs(CURRENT, 0, 1_000), Ok(true));
        assert_eq!(a.handover_delay_secs(), 0);
        // A proposal may now be accepted in the same instant.
        a.propose_handover(CURRENT, SUCCESSOR, 2_000).unwrap();
        a.confirm_handover(SUCCESSOR, 2_000).unwrap();
        assert_eq!(a.current(), Some(SUCCESSOR));
    }

    #[test]
    fn amend_handover_delay_remeasures_an_in_flight_proposal() {
        let mut a = authority();
        a.propose_handover(CURRENT, SUCCESSOR, 1_000).unwrap();
        // Raising the delay holds the proposed handover: the original
        // deadline no longer suffices.
        assert_eq!(
            a.amend_handover_delay_secs(CURRENT, 7_200, 1_500),
            Ok(true)
        );
        assert_eq!(
            a.confirm_handover(SUCCESSOR, 1_000 + DELAY),
            Err(EscrowError::UpgradeHandoverDelayNotElapsed)
        );
        assert_eq!(a.current(), Some(CURRENT));
        assert_eq!(a.pending_proposal(), Some((SUCCESSOR, 1_000)));
        // Lowering it releases the same proposal early.
        assert_eq!(
            a.amend_handover_delay_secs(CURRENT, 100, 1_600),
            Ok(true)
        );
        a.confirm_handover(SUCCESSOR, 1_000 + 100).unwrap();
        assert_eq!(a.current(), Some(SUCCESSOR));
        // The amendment entries sit in the audit trail in order.
        let kinds: Vec<_> = a
            .audit_log()
            .iter()
            .map(|e| e.kind)
            .collect();
        assert_eq!(
            kinds,
            [
                UpgradeAuthorityEventKind::HandoverProposed,
                UpgradeAuthorityEventKind::HandoverDelayAmended,
                UpgradeAuthorityEventKind::HandoverDelayAmended,
                UpgradeAuthorityEventKind::HandoverConfirmed,
            ]
        );
    }

    #[test]
    fn amend_handover_delay_follows_the_live_authority() {
        let mut a = authority();
        a.propose_handover(CURRENT, SUCCESSOR, 1_000).unwrap();
        a.confirm_handover(SUCCESSOR, 1_000 + DELAY).unwrap();
        // The old authority lost the right the moment the handover
        // completed; the new authority holds it.
        assert_eq!(
            a.amend_handover_delay_secs(CURRENT, 7_200, 5_000),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            a.amend_handover_delay_secs(SUCCESSOR, 7_200, 5_000),
            Ok(true)
        );
        assert_eq!(a.handover_delay_secs(), 7_200);
    }

    #[test]
    fn renounce_by_the_current_authority_clears_the_authority_and_audits() {
        let mut a = authority();
        a.renounce_upgrade_authority(CURRENT, 1_000).unwrap();
        assert_eq!(a.current(), None);
        // The delay is untouched: renounce moves the authority, not
        // the policy (a pending proposal would have blocked it anyway).
        assert_eq!(a.handover_delay_secs(), DELAY);
        assert_eq!(a.pending_proposal(), None);
        let log = a.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(
            log[0].kind,
            UpgradeAuthorityEventKind::UpgradeAuthorityRenounced
        );
        assert_eq!(log[0].at, 1_000);
        assert_eq!(log[0].actor, CURRENT);
        // The authority in effect after renounce is "none": the
        // successor slot records the zero key, distinguished from a
        // handover by the kind.
        assert_eq!(log[0].successor, [0u8; 32]);
    }

    #[test]
    fn renounce_rejects_a_stranger_and_changes_nothing() {
        let mut a = authority();
        assert_eq!(
            a.renounce_upgrade_authority(STRANGER, 1_000),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(a.current(), Some(CURRENT));
        assert!(a.audit_log().is_empty());
    }

    #[test]
    fn renounce_refused_while_a_proposal_is_live_then_allowed_after_cancel() {
        let mut a = authority();
        a.propose_handover(CURRENT, SUCCESSOR, 1_000).unwrap();
        assert_eq!(
            a.renounce_upgrade_authority(CURRENT, 2_000),
            Err(EscrowError::UpgradeHandoverPending)
        );
        // The proposal survives the refused renounce.
        assert_eq!(a.pending_proposal(), Some((SUCCESSOR, 1_000)));
        assert_eq!(a.current(), Some(CURRENT));
        // Cancel first, then the renounce goes through.
        a.cancel_handover(CURRENT, 3_000).unwrap();
        a.renounce_upgrade_authority(CURRENT, 4_000).unwrap();
        assert_eq!(a.current(), None);
    }

    #[test]
    fn after_renounce_propose_and_amend_are_unauthorized() {
        let mut a = authority();
        a.renounce_upgrade_authority(CURRENT, 1_000).unwrap();
        // No authority is left to compare against — every caller,
        // including the former authority, is a stranger now.
        assert_eq!(
            a.propose_handover(CURRENT, SUCCESSOR, 2_000),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            a.propose_handover(STRANGER, SUCCESSOR, 2_000),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            a.amend_handover_delay_secs(CURRENT, 7_200, 2_000),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(a.current(), None);
        // Only the renounce itself audited.
        assert_eq!(a.audit_log().len(), 1);
    }

    #[test]
    fn after_renounce_confirm_and_cancel_are_no_upgrade_handover_pending() {
        let mut a = authority();
        a.renounce_upgrade_authority(CURRENT, 1_000).unwrap();
        // A renounced authority can never have a pending proposal.
        assert_eq!(
            a.confirm_handover(SUCCESSOR, 2_000),
            Err(EscrowError::NoUpgradeHandoverPending)
        );
        assert_eq!(
            a.cancel_handover(CURRENT, 2_000),
            Err(EscrowError::NoUpgradeHandoverPending)
        );
        assert_eq!(a.audit_log().len(), 1);
    }

    #[test]
    fn renounce_twice_is_a_silent_noop() {
        let mut a = authority();
        a.renounce_upgrade_authority(CURRENT, 1_000).unwrap();
        // Renouncing again is Ok(()) regardless of caller — even a
        // stranger — and writes no second audit entry.
        a.renounce_upgrade_authority(CURRENT, 2_000).unwrap();
        a.renounce_upgrade_authority(STRANGER, 3_000).unwrap();
        assert_eq!(a.current(), None);
        assert_eq!(a.audit_log().len(), 1);
    }

    #[test]
    fn renounce_keeps_older_audit_entries_and_new_still_rejects_zero() {
        let mut a = authority();
        a.propose_handover(CURRENT, SUCCESSOR, 1_000).unwrap();
        a.cancel_handover(CURRENT, 2_000).unwrap();
        a.renounce_upgrade_authority(CURRENT, 3_000).unwrap();
        let kinds: Vec<_> = a.audit_log().iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [
                UpgradeAuthorityEventKind::HandoverProposed,
                UpgradeAuthorityEventKind::HandoverCancelled,
                UpgradeAuthorityEventKind::UpgradeAuthorityRenounced,
            ]
        );
        // Renounce is a lifecycle transition, not a construction state:
        // building an authority on the zero key is still refused.
        assert_eq!(
            UpgradeAuthority::new([0u8; 32], DELAY),
            Err(EscrowError::InvalidUpgradeAuthority)
        );
    }

    #[test]
    fn after_renounce_propose_successor_gates_are_unreachable() {
        let mut a = authority();
        a.renounce_upgrade_authority(CURRENT, 1_000).unwrap();
        // The zero-key and self-successor gates sit behind the
        // authority check, which now refuses every caller first.
        assert_eq!(
            a.propose_handover(CURRENT, [0u8; 32], 2_000),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            a.propose_handover(CURRENT, CURRENT, 2_000),
            Err(EscrowError::Unauthorized)
        );
    }

    #[test]
    fn drift_scan_after_renounce_compares_as_the_zero_key() {
        let mut a = authority();
        a.renounce_upgrade_authority(CURRENT, 1_000).unwrap();
        // A template expecting a live key reports drift: the live
        // authority is now "none".
        let drift = scan_upgrade_authority_drift(&a, CURRENT).unwrap();
        assert_eq!(drift.expected, CURRENT);
        assert_eq!(drift.actual, [0u8; 32]);
        assert_eq!(drift.pending_proposal, None);
        // A template expecting the zero key — an intentionally
        // immutable program — matches.
        assert_eq!(scan_upgrade_authority_drift(&a, [0u8; 32]), None);
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(EscrowError::InvalidUpgradeAuthority.code(), 242);
        assert_eq!(EscrowError::UpgradeHandoverPending.code(), 243);
        assert_eq!(EscrowError::NoUpgradeHandoverPending.code(), 244);
        assert_eq!(EscrowError::UpgradeHandoverDelayNotElapsed.code(), 245);
    }
}
