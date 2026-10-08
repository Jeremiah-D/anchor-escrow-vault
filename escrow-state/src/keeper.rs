//! Off-chain keeper report (AV-20): scan a batch of escrows and emit the
//! executable `cancel_expired` / `claim` call list as JSON.
//!
//! A keeper bot watches many vaults and needs to know, at a given `now`,
//! which ones have an *immediately executable* keeper action:
//!
//! - `cancel_expired`: the escrow is `Funded`, the expiry gate passes at
//!   `now` (`now >= expires_at + grace_period` — see
//!   [`Escrow::is_expiry_eligible`]), and a refundable remainder exists.
//!   Either party may call it; the report names the initializer as the
//!   canonical caller (the taker may also call — the on-chain instruction
//!   accepts either). The grace period (AV-21) is honored here exactly as
//!   on-chain: the keeper never lists a `cancel_expired` call the chain
//!   would reject as `NotExpired`, which is the whole point of the grace
//!   period (keeper/cluster clock drift).
//! - `claim`: the escrow is `Funded`, a vesting schedule is attached, no
//!   milestone plan is attached (the plan owns the release schedule, so
//!   `claim` is disabled there), the vested-minus-released amount is
//!   positive, and any configured quorum is satisfied — otherwise the
//!   call would fail with `QuorumNotReached` and would not be executable.
//!
//! Every listed action carries the exact arguments the keeper needs to
//! build the instruction: `caller` (the signing key), `mint` (the bound
//! SPL mint, or `null` on the native-SOL path), and `amount` (the refund
//! the `cancel_expired` call would return to the initializer, or the
//! gross vested-but-unreleased amount a `claim` would move — the protocol
//! fee slices it, `payout + fee == amount`).
//!
//! # Dry-run by construction
//!
//! The scan only reads `&Escrow` snapshots: it cannot mutate anything,
//! emits no events, and touches no clock. Amounts are as of the scan — a
//! keeper executes the list, then re-scans.
//!
//! # Output
//!
//! [`KeeperReport::to_json`] hand-serializes the report (the crate is
//! dependency-free): deterministic field order, keys as 64-char lowercase
//! hex, `mint` as a hex string or `null`. Actions keep the input order so
//! a keeper feeding a stable watch list gets a stable call list.

use crate::{Escrow, EscrowState};

/// Render 32 bytes as 64 lowercase hex characters.
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// One watched escrow: a caller-supplied identity plus a read-only state
/// snapshot. The scan never mutates the snapshot (dry-run).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchedEscrow {
    /// Caller-supplied 32-byte escrow identity. The Anchor layer uses the
    /// vault PDA's public key — the same convention as
    /// [`crate::IndexedEscrow`]'s `escrow_id`.
    pub escrow_id: [u8; 32],
    /// Read-only snapshot of the escrow's state.
    pub escrow: Escrow,
}

/// The keeper-callable action for one escrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeeperActionKind {
    /// `cancel_expired(authority, now, mint)`.
    CancelExpired,
    /// `claim(taker, now, mint)`.
    Claim,
}

impl KeeperActionKind {
    fn as_str(&self) -> &'static str {
        match self {
            KeeperActionKind::CancelExpired => "cancel_expired",
            KeeperActionKind::Claim => "claim",
        }
    }
}

/// One executable keeper call: everything needed to build the
/// instruction, nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeeperAction {
    /// Which escrow this call targets.
    pub escrow_id: [u8; 32],
    /// Which transition to invoke.
    pub kind: KeeperActionKind,
    /// The key that must sign the call.
    pub caller: [u8; 32],
    /// Which role `caller` plays: `"initializer"` or `"taker"`.
    pub caller_role: &'static str,
    /// The `mint` argument to pass: the escrow's bound mint, or `None`
    /// on the native-SOL path.
    pub mint: Option<[u8; 32]>,
    /// `cancel_expired`: the refundable remainder the call would return
    /// to the initializer. `claim`: the gross vested-but-unreleased
    /// amount (the protocol fee slices it; `payout + fee == amount`).
    /// Always `> 0` — zero-value actions are never listed.
    pub amount: u64,
    /// Machine-readable reason: `"expired"` or `"vesting_unlocked"`.
    pub reason: &'static str,
}

/// The scan result: every executable keeper call at [`KeeperReport::at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeeperReport {
    /// The `now` (Unix seconds) the scan ran at.
    pub at: u64,
    /// How many escrows were scanned.
    pub scanned: usize,
    /// Executable actions, in the input's order.
    pub actions: Vec<KeeperAction>,
}

impl KeeperReport {
    /// True when the scan found nothing executable.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Hand-serialized JSON (the crate is dependency-free). Deterministic
    /// field order; keys are 64-char lowercase hex; `mint` is a hex
    /// string or `null`.
    ///
    /// ```json
    /// {"at":1000000,"scanned":1,"actions":[
    ///   {"escrow_id":"...","action":"cancel_expired","caller":"...",
    ///    "caller_role":"initializer","mint":null,"amount":1000000,
    ///    "reason":"expired"}
    /// ]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(128 + self.actions.len() * 360);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"actions\":[");
        for (i, a) in self.actions.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&a.escrow_id));
            s.push_str("\",\"action\":\"");
            s.push_str(a.kind.as_str());
            s.push_str("\",\"caller\":\"");
            s.push_str(&hex32(&a.caller));
            s.push_str("\",\"caller_role\":\"");
            s.push_str(a.caller_role);
            s.push_str("\",\"mint\":");
            match a.mint {
                Some(m) => {
                    s.push('"');
                    s.push_str(&hex32(&m));
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            s.push_str(",\"amount\":");
            s.push_str(&a.amount.to_string());
            s.push_str(",\"reason\":\"");
            s.push_str(a.reason);
            s.push_str("\"}");
        }
        s.push_str("]}");
        s
    }
}

/// Scan `watched` at `now` and return every immediately executable keeper
/// call. Pure read over the snapshots: zero side effects, deterministic
/// output in input order.
///
/// An escrow contributes at most one action per kind. An expired escrow
/// with claimable vesting lists *both*: both calls are executable at the
/// scan time (amounts are as of the scan; the keeper re-scans after
/// executing).
pub fn scan_keeper_actions(watched: &[WatchedEscrow], now: u64) -> KeeperReport {
    let mut actions = Vec::new();
    for w in watched {
        let e = &w.escrow;
        // Only a live, funded escrow has keeper-executable exits:
        // Uninitialized / Activated escrows are not funded yet, and the
        // terminal states (Released, Cancelled, Settled) — plus Disputed,
        // whose unilateral exits are locked — have none.
        if e.state() != EscrowState::Funded {
            continue;
        }
        // The expiry gate is the state machine's own predicate
        // (`Escrow::is_expiry_eligible`): the keeper honors the grace
        // period exactly as `cancel_expired` enforces it on-chain, so a
        // listed call is always executable — never a `NotExpired`
        // rejection caused by keeper/cluster clock drift.
        if e.is_expiry_eligible(now) && e.remaining_amount() > 0 {
            // Either party may cancel an expired escrow; the initializer
            // is the canonical keeper caller. The refund is the remainder
            // — never fee'd, so no fee accounting is needed here.
            actions.push(KeeperAction {
                escrow_id: w.escrow_id,
                kind: KeeperActionKind::CancelExpired,
                caller: e.initializer(),
                caller_role: "initializer",
                mint: e.mint(),
                amount: e.remaining_amount(),
                reason: "expired",
            });
        }
        // The taker's pull path: vesting attached, no milestone plan (the
        // plan owns the release schedule and disables `claim`), something
        // vested-but-unreleased, and any configured quorum satisfied —
        // otherwise the call would fail and is not executable.
        if e.vesting_schedule().is_some()
            && e.milestone_plan().is_none()
            && e.claimable_amount(now) > 0
            && e.quorum().map(|q| q.is_satisfied()).unwrap_or(true)
        {
            actions.push(KeeperAction {
                escrow_id: w.escrow_id,
                kind: KeeperActionKind::Claim,
                caller: e.taker(),
                caller_role: "taker",
                mint: e.mint(),
                amount: e.claimable_amount(now),
                reason: "vesting_unlocked",
            });
        }
    }
    KeeperReport {
        at: now,
        scanned: watched.len(),
        actions,
    }
}

#[cfg(test)]
mod keeper_tests {
    use super::*;
    use crate::{MilestonePlan, QuorumPolicy, VestingSchedule};

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const A1: [u8; 32] = [0xA1; 32]; // attestors
    const A2: [u8; 32] = [0xA2; 32];
    const A3: [u8; 32] = [0xA3; 32];
    const MINT: [u8; 32] = [0xD0; 32];
    const ID1: [u8; 32] = [0x01; 32];
    const ID2: [u8; 32] = [0x02; 32];
    const ID3: [u8; 32] = [0x03; 32];
    const AMOUNT: u64 = 1_000_000;
    const VEST_START: u64 = 1_700_000_000;
    const VEST_END: u64 = 1_800_000_000;
    const MID: u64 = 1_750_000_000; // half-vested
    const NEVER: u64 = u64::MAX; // no timeout

    fn watch(id: [u8; 32], escrow: Escrow) -> WatchedEscrow {
        WatchedEscrow {
            escrow_id: id,
            escrow,
        }
    }

    fn funded(amount: u64, expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, amount, expires_at).unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    fn funded_vesting(expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, expires_at)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    fn hex_of(byte: u8) -> String {
        let h: String = format!("{:02x}", byte);
        h.repeat(32)
    }

    #[test]
    fn empty_input_scans_to_empty_report() {
        let report = scan_keeper_actions(&[], MID);
        assert!(report.is_empty());
        assert_eq!(report.scanned, 0);
        assert_eq!(report.to_json(), r#"{"at":1750000000,"scanned":0,"actions":[]}"#);
    }

    #[test]
    fn unfunded_and_terminal_escrows_yield_no_actions() {
        let uninit = Escrow::initialize(ALICE, BOB, AMOUNT, 0).unwrap();
        let mut released = funded(AMOUNT, NEVER);
        released.release(ALICE, AMOUNT, None).unwrap();
        let mut cancelled = funded(AMOUNT, NEVER);
        cancelled.cancel(ALICE, None).unwrap();
        let watched = [watch(ID1, uninit), watch(ID2, released), watch(ID3, cancelled)];
        let report = scan_keeper_actions(&watched, MID);
        assert!(report.is_empty());
        assert_eq!(report.scanned, 3);
    }

    #[test]
    fn funded_unexpired_plain_escrow_has_no_keeper_action() {
        let watched = [watch(ID1, funded(AMOUNT, NEVER))];
        let report = scan_keeper_actions(&watched, MID);
        assert!(report.is_empty());
    }

    #[test]
    fn expired_escrow_lists_cancel_expired_for_initializer() {
        let watched = [watch(ID1, funded(AMOUNT, 0))];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::CancelExpired);
        assert_eq!(a.escrow_id, ID1);
        assert_eq!(a.caller, ALICE);
        assert_eq!(a.caller_role, "initializer");
        assert_eq!(a.mint, None);
        assert_eq!(a.amount, AMOUNT);
        assert_eq!(a.reason, "expired");
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        // `now == expires_at` is expiry-eligible (`now >= expires_at`).
        let watched = [watch(ID1, funded(AMOUNT, MID))];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].kind, KeeperActionKind::CancelExpired);
        // One second earlier: not eligible.
        let report = scan_keeper_actions(&watched, MID - 1);
        assert!(report.is_empty());
    }

    #[test]
    fn grace_period_defers_cancel_expired_listing() {
        // AV-21: the keeper honors the grace period exactly as the chain
        // enforces it — a listed `cancel_expired` is always executable,
        // never a `NotExpired` rejection from clock drift.
        const GRACE: u64 = 300;
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, MID)
            .unwrap()
            .with_grace_period(GRACE)
            .unwrap();
        e.fund(ALICE).unwrap();
        let watched = [watch(ID1, e)];
        // At expires_at: the chain would reject — the keeper lists nothing.
        let report = scan_keeper_actions(&watched, MID);
        assert!(report.is_empty(), "keeper must not list a premature cancel");
        // Inside the grace window: still nothing.
        let report = scan_keeper_actions(&watched, MID + GRACE - 1);
        assert!(report.is_empty());
        // At expires_at + grace: executable, listed.
        let report = scan_keeper_actions(&watched, MID + GRACE);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].kind, KeeperActionKind::CancelExpired);
        assert_eq!(report.actions[0].reason, "expired");
        // Cross-check against the real transition at every boundary: the
        // keeper's predicate and the chain's gate never disagree.
        for now in [MID - 1, MID, MID + 1, MID + GRACE - 1, MID + GRACE, MID + GRACE + 1] {
            let listed = !scan_keeper_actions(&watched, now).is_empty();
            let mut probe = e;
            let executable = probe.cancel_expired(ALICE, now, None).is_ok();
            assert_eq!(listed, executable, "keeper/chain disagree at now={now}");
        }
    }

    #[test]
    fn never_expires_escrow_is_never_listed_for_cancel() {
        let watched = [watch(ID1, funded(AMOUNT, NEVER))];
        let report = scan_keeper_actions(&watched, u64::MAX - 1);
        assert!(report.is_empty());
    }

    #[test]
    fn cancel_expired_refunds_the_remainder_after_partial_release() {
        let mut e = funded(AMOUNT, 0);
        e.release(ALICE, 400_000, None).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].amount, 600_000);
    }

    #[test]
    fn mint_bound_escrow_carries_the_mint_argument() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, 0)
            .unwrap()
            .with_mint(MINT)
            .unwrap();
        e.fund(ALICE).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].mint, Some(MINT));
        let json = report.to_json();
        assert!(
            json.contains(&format!("\"mint\":\"{}\"", hex_of(0xD0))),
            "mint must serialize as hex, got: {json}"
        );
    }

    #[test]
    fn vesting_mid_schedule_lists_claim_for_taker() {
        let watched = [watch(ID1, funded_vesting(NEVER))];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::Claim);
        assert_eq!(a.escrow_id, ID1);
        assert_eq!(a.caller, BOB);
        assert_eq!(a.caller_role, "taker");
        // Half the linear curve vested: floor(1_000_000 / 2) = 500_000.
        assert_eq!(a.amount, 500_000);
        assert_eq!(a.reason, "vesting_unlocked");
    }

    #[test]
    fn vesting_before_start_lists_nothing() {
        let watched = [watch(ID1, funded_vesting(NEVER))];
        let report = scan_keeper_actions(&watched, VEST_START - 1);
        assert!(report.is_empty());
    }

    #[test]
    fn claim_amount_is_vested_minus_released() {
        // The initializer released ahead of the curve: the claimable
        // remainder is what is vested but not yet released.
        let mut e = funded_vesting(NEVER);
        e.release(ALICE, 200_000, None).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].amount, 300_000); // 500_000 - 200_000
    }

    #[test]
    fn claim_requires_satisfied_quorum_to_be_executable() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_quorum(QuorumPolicy::new(&[A1, A2, A3], 2).unwrap())
            .unwrap();
        e.fund(ALICE).unwrap();
        e.attest(A1).unwrap(); // 1 of 2: the claim call would fail
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert!(
            report.is_empty(),
            "an unsatisfiable claim is not an executable call"
        );
        // Satisfy the quorum: the claim becomes executable.
        let mut e2 = e;
        e2.attest(A2).unwrap();
        let watched = [watch(ID1, e2)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].kind, KeeperActionKind::Claim);
    }

    #[test]
    fn milestone_plan_disables_claim_but_not_cancel_expired() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, 0)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap();
        e.fund(ALICE).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        // The plan owns the release schedule (`claim` would fail with
        // InvalidMilestones), but the expiry exit still refunds.
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].kind, KeeperActionKind::CancelExpired);
    }

    #[test]
    fn disputed_escrow_has_no_keeper_action() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter([0xA8; 32])
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(ALICE, MID).unwrap();
        assert_eq!(e.state(), EscrowState::Disputed);
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert!(
            report.is_empty(),
            "unilateral exits are locked while disputed"
        );
    }

    #[test]
    fn scan_is_dry_run_and_preserves_input_order() {
        let e1 = funded(AMOUNT, 0); // -> cancel_expired
        let e2 = funded_vesting(NEVER); // -> claim
        let e3 = funded(AMOUNT, NEVER); // -> nothing
        let before = [watch(ID1, e1), watch(ID2, e2), watch(ID3, e3)];
        let report = scan_keeper_actions(&before, MID);
        // Zero side effects: the snapshots are bit-identical afterwards
        // (WatchedEscrow is Copy + PartialEq, so this is exact).
        assert_eq!(before, [watch(ID1, e1), watch(ID2, e2), watch(ID3, e3)]);
        assert_eq!(report.scanned, 3);
        assert_eq!(report.actions.len(), 2);
        // Input order preserved: ID1's cancel first, ID2's claim second.
        assert_eq!(
            report.actions[0],
            KeeperAction {
                escrow_id: ID1,
                kind: KeeperActionKind::CancelExpired,
                caller: ALICE,
                caller_role: "initializer",
                mint: None,
                amount: AMOUNT,
                reason: "expired",
            }
        );
        assert_eq!(report.actions[1].escrow_id, ID2);
        assert_eq!(report.actions[1].kind, KeeperActionKind::Claim);
    }

    #[test]
    fn json_shape_is_pinned() {
        let watched = [watch(ID1, funded(AMOUNT, 0))];
        let report = scan_keeper_actions(&watched, 1_000_000);
        let expected = format!(
            "{{\"at\":1000000,\"scanned\":1,\"actions\":[{{\"escrow_id\":\"{}\",\"action\":\"cancel_expired\",\"caller\":\"{}\",\"caller_role\":\"initializer\",\"mint\":null,\"amount\":1000000,\"reason\":\"expired\"}}]}}",
            hex_of(0x01),
            hex_of(0xAA),
        );
        assert_eq!(report.to_json(), expected);
    }

    #[test]
    fn json_shape_with_claim_and_mint_is_pinned() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_mint(MINT)
            .unwrap();
        e.fund(ALICE).unwrap();
        let watched = [watch(ID2, e)];
        let report = scan_keeper_actions(&watched, MID);
        let expected = format!(
            "{{\"at\":1750000000,\"scanned\":1,\"actions\":[{{\"escrow_id\":\"{}\",\"action\":\"claim\",\"caller\":\"{}\",\"caller_role\":\"taker\",\"mint\":\"{}\",\"amount\":500000,\"reason\":\"vesting_unlocked\"}}]}}",
            hex_of(0x02),
            hex_of(0xBB),
            hex_of(0xD0),
        );
        assert_eq!(report.to_json(), expected);
    }

    #[test]
    fn expired_vesting_escrow_lists_both_calls() {
        // Both calls are executable at the scan time; the keeper executes
        // one and re-scans. Amounts are as of the scan.
        let watched = [watch(ID1, funded_vesting(0))];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 2);
        assert_eq!(report.actions[0].kind, KeeperActionKind::CancelExpired);
        assert_eq!(report.actions[0].amount, AMOUNT);
        assert_eq!(report.actions[1].kind, KeeperActionKind::Claim);
        assert_eq!(report.actions[1].amount, 500_000);
    }
}
