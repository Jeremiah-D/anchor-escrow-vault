//! Off-chain keeper report (AV-20): scan a batch of escrows and emit the
//! executable `cancel_expired` / `claim` / `resolve` call list as JSON.
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
//!   positive, any configured quorum is satisfied, and the timelock
//!   (AV-27) is unlocked — otherwise the call would fail with
//!   `QuorumNotReached` / `TimelockNotReached` and would not be
//!   executable.
//! - `resolve` (AV-38): the escrow is `Disputed` with a configured
//!   arbiter and a positive remaining balance. Only the arbiter may
//!   call it; the report names the arbiter as the caller so an
//!   arbiter-operated keeper bot learns which disputes await its ruling.
//!   The taker/initializer split is the arbiter's judgment and the
//!   rationale-document commitment (AV-38) comes from the arbiter's
//!   off-chain deliberation, so neither is on the action — the keeper
//!   flags the escrow as awaiting resolution with the splittable pool
//!   (`amount`) and the bound mint; the arbiter supplies the split and
//!   the rationale hash at call time.
//!
//! Every listed action carries the exact arguments the keeper needs to
//! build the instruction: `caller` (the signing key), `mint` (the bound
//! SPL mint, or `null` on the native-SOL path), `refund_to` (the refund
//! destination for `cancel_expired` — the escrow's whitelisted address
//! when configured, else the initializer; `null` for `claim` and
//! `resolve`), and `amount` (the refund the `cancel_expired` call would
//! return to the initializer, the gross vested-but-unreleased amount a
//! `claim` would move — the protocol fee slices it, `payout + fee ==
//! amount` — or the remaining locked amount a `resolve` would split).
//!
//! `Disputed` escrows list exactly the `resolve` action above — their
//! unilateral exits stay locked — and the scan never drops their state:
//! the dispute evidence hash attached at `escalate` (AV-22) stays
//! readable on the watched snapshot ([`Escrow::evidence_hash`]) so
//! operator tooling can fetch the off-chain evidence for the arbiter.
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
//!
//! # Rent-reclaim sweep (AV-40)
//!
//! A terminal-state vault (`Cancelled` / `Released` / `Settled`) has
//! served its purpose, but its rent-exempt deposit stays locked until
//! the account is closed — leaving it there would strand the deposit
//! forever. [`scan_closeable`] is the second scan: it walks the same
//! watch list and emits the executable `close_vault` call list for
//! terminal-state vaults, grouped per initializer signer into
//! [`CloseBatch`]es with a per-batch reclaimed-lamports total, and
//! serializable via [`CloseReport::to_json`] (same hand-rolled
//! deterministic style as the keeper report).
//!
//! Only *executable* calls are listed, exactly like the AV-20 scan: the
//! chain rejects `close_vault` from `Disputed` (AV-34: the arbitration
//! is still live and the vault account is the audit surface the arbiter
//! works from) and from `Closed` (the rent is already reclaimed), so
//! those two states are skipped — never listed — as are the
//! pre-terminal states (`Uninitialized` / `Funded` / `Activated`),
//! whose vault accounts have not served their purpose yet. The
//! canonical caller is the initializer: AV-34 restricts `close_vault`
//! to the initializer, checked before state validity, so it is the
//! only key the chain will accept.

use crate::{format_amount, vault_close_rent_reclaimed, Escrow, EscrowState};

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
    /// `resolve(arbiter, taker_amount, mint, rationale_hash)` (AV-38):
    /// the arbiter's settlement of a `Disputed` escrow. Listed so an
    /// arbiter-operated keeper bot learns which disputes await its
    /// ruling; the taker/initializer split and the rationale-document
    /// commitment are the arbiter's call-time judgment, not keeper
    /// inputs.
    Resolve,
}

impl KeeperActionKind {
    /// `pub(crate)` so the execution-plan builder (AV-33) can stamp the
    /// instruction name on planned instructions.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            KeeperActionKind::CancelExpired => "cancel_expired",
            KeeperActionKind::Claim => "claim",
            KeeperActionKind::Resolve => "resolve",
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
    /// Which role `caller` plays: `"initializer"`, `"taker"`, or
    /// `"arbiter"` (AV-38, `resolve` actions).
    pub caller_role: &'static str,
    /// The `mint` argument to pass: the escrow's bound mint, or `None`
    /// on the native-SOL path.
    pub mint: Option<[u8; 32]>,
    /// `cancel_expired`: the refund destination to pass — the escrow's
    /// whitelisted refund address when one is configured via
    /// [`Escrow::with_refund_address`], otherwise the initializer
    /// (AV-23: the state machine rejects any other destination with
    /// `RefundAddressMismatch`, so the keeper must build the
    /// instruction with exactly this address). `None` for `claim`
    /// actions, which pay the taker rather than refunding — and `None`
    /// for `resolve` actions, which split the remainder between the
    /// taker and the initializer rather than refunding to one address.
    pub refund_to: Option<[u8; 32]>,
    /// `cancel_expired`: the refundable remainder the call would return
    /// to the initializer. `claim`: the gross vested-but-unreleased
    /// amount (the protocol fee slices it; `payout + fee == amount`).
    /// `resolve` (AV-38): the remaining locked amount the arbiter's
    /// split divides between the taker and the initializer — the split
    /// itself is the arbiter's judgment at call time.
    /// Always `> 0` — zero-value actions are never listed.
    pub amount: u64,
    /// The escrow's token decimal metadata (AV-28): the SPL mint's
    /// decimal places, `0` when none is declared. Feeds the report's
    /// `display_amount` rendering only — the instruction itself always
    /// moves the raw `amount`.
    pub decimals: u8,
    /// Machine-readable reason: `"expired"`, `"vesting_unlocked"`, or
    /// `"disputed"` (AV-38, `resolve` actions).
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
    ///    "caller_role":"initializer","mint":null,
    ///    "refund_to":"...","amount":1000000,"decimals":6,
    ///    "display_amount":"1.000000",
    ///    "reason":"expired"}
    /// ]}
    /// ```
    ///
    /// AV-28: every action also carries `decimals` (the escrow's token
    /// decimal metadata, `0` when none is declared) and `display_amount`
    /// — the same `amount` rendered in human units via
    /// [`crate::format_amount`]. The instruction itself always moves the
    /// raw `amount`; the display field is for operators and logs only.
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
            // AV-23: the refund destination the cancel_expired
            // instruction must name (`null` for claim actions).
            s.push_str(",\"refund_to\":");
            match a.refund_to {
                Some(r) => {
                    s.push('"');
                    s.push_str(&hex32(&r));
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            s.push_str(",\"amount\":");
            s.push_str(&a.amount.to_string());
            // AV-28: human-readable amount alongside the raw value (the
            // instruction moves `amount`; `display_amount` is for
            // operators and logs only).
            s.push_str(",\"decimals\":");
            s.push_str(&a.decimals.to_string());
            s.push_str(",\"display_amount\":\"");
            s.push_str(&format_amount(a.amount, a.decimals));
            s.push_str("\",\"reason\":\"");
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
        // AV-38: a disputed escrow has exactly one keeper-executable
        // call — the arbiter's `resolve`. The unilateral exits stay
        // locked, so nothing else is listed; the taker/initializer split
        // and the rationale-document commitment are the arbiter's
        // judgment at call time, so the action carries the splittable
        // pool rather than a decided split. An arbiter-less dispute
        // (unreachable through the state machine, which requires an
        // arbiter to escalate) lists nothing — no key could sign the
        // call.
        if e.state() == EscrowState::Disputed {
            if let Some(arbiter) = e.arbiter() {
                let remaining = e.remaining_amount();
                if remaining > 0 {
                    actions.push(KeeperAction {
                        escrow_id: w.escrow_id,
                        kind: KeeperActionKind::Resolve,
                        caller: arbiter,
                        caller_role: "arbiter",
                        mint: e.mint(),
                        // `resolve` splits the remainder between the
                        // taker and the initializer — no single refund
                        // destination applies.
                        refund_to: None,
                        amount: remaining,
                        // AV-28: the report renders the amount in human
                        // units alongside the raw value.
                        decimals: e.decimals(),
                        reason: "disputed",
                    });
                }
            }
            continue;
        }
        // Only a live, funded escrow has keeper-executable exits:
        // Uninitialized / Activated escrows are not funded yet, and the
        // terminal states (Released, Cancelled, Settled, Closed) have
        // none.
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
                // AV-23: the instruction must name the refund
                // destination explicitly, and the state machine pins it
                // to the escrow's refund policy — the report carries the
                // effective recipient so the keeper builds a valid call.
                refund_to: Some(e.refund_recipient()),
                amount: e.remaining_amount(),
                // AV-28: the report renders the amount in human units
                // alongside the raw value.
                decimals: e.decimals(),
                reason: "expired",
            });
        }
        // The taker's pull path: vesting attached, no milestone plan (the
        // plan owns the release schedule and disables `claim`), something
        // vested-but-unreleased, any configured quorum satisfied, and the
        // timelock (AV-27) already unlocked — otherwise the call would
        // fail and is not executable.
        if e.vesting_schedule().is_some()
            && e.milestone_plan().is_none()
            && e.claimable_amount(now) > 0
            && e.quorum().map(|q| q.is_satisfied()).unwrap_or(true)
            && e.is_unlock_eligible(now)
        {
            actions.push(KeeperAction {
                escrow_id: w.escrow_id,
                kind: KeeperActionKind::Claim,
                caller: e.taker(),
                caller_role: "taker",
                mint: e.mint(),
                // Claims pay the taker, not a refund: no refund
                // destination applies.
                refund_to: None,
                amount: e.claimable_amount(now),
                // AV-28: the report renders the amount in human units
                // alongside the raw value.
                decimals: e.decimals(),
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

/// One executable `close_vault` call: everything needed to build the
/// instruction, nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseAction {
    /// Which escrow's vault this call closes: the caller-supplied
    /// identity (the Anchor layer keys the vault PDA off it — the
    /// same convention as [`WatchedEscrow::escrow_id`]).
    pub escrow_id: [u8; 32],
    /// The key that must sign the `close_vault` call — always the
    /// escrow's initializer. AV-34 restricts `close_vault` to the
    /// initializer and checks the authority *before* state validity,
    /// so this is the canonical caller and the only key the chain
    /// will accept. It doubles as the instruction's `authority`
    /// argument: `close_vault(authority)` takes no other arguments —
    /// the vault account is the target, the initializer is the signer.
    pub caller: [u8; 32],
    /// Always `"initializer"` — the canonical (and only accepted)
    /// close caller.
    pub caller_role: &'static str,
    /// Estimated rent-exempt lamports the call returns to the
    /// initializer. Computed from [`crate::vault_close_rent_reclaimed`]
    /// — the mainnet rent-exempt minimum for the *current*
    /// [`crate::VAULT_SPACE`] — never a hardcoded figure: the account
    /// layout has grown since earlier constants, and the estimate
    /// tracks the layout automatically.
    pub rent_reclaimed: u64,
    /// Machine-readable reason: the terminal state the vault sits in —
    /// `"cancelled"`, `"released"`, or `"settled"`.
    pub reason: &'static str,
}

/// One per-caller close batch: every close action that a single
/// initializer signer must issue. Batching per caller matters for the
/// operator: one signer, one sweep, one rent-reclaim total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseBatch {
    /// The initializer all of this batch's actions sign for.
    pub caller: [u8; 32],
    /// This caller's close actions, in input order.
    pub actions: Vec<CloseAction>,
    /// Sum of `rent_reclaimed` across the batch's actions.
    pub total_reclaimed: u64,
}

/// The close-sweep result: terminal-state vaults grouped into
/// per-caller close batches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseReport {
    /// How many escrows were scanned.
    pub scanned: usize,
    /// Per-caller batches, in first-seen caller order, so a keeper
    /// feeding a stable watch list gets a stable sweep list.
    pub batches: Vec<CloseBatch>,
}

impl CloseReport {
    /// True when no closeable vault was found.
    pub fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }

    /// Hand-serialized JSON (the crate is dependency-free). Deterministic
    /// field order; keys are 64-char lowercase hex. Batches keep their
    /// first-seen caller order, actions keep the input order.
    ///
    /// ```json
    /// {"scanned":2,"batches":[
    ///   {"caller":"...","total_reclaimed":5470560,"actions":[
    ///     {"escrow_id":"...","action":"close_vault","caller":"...",
    ///      "caller_role":"initializer","rent_reclaimed":5470560,
    ///      "reason":"released"}
    ///   ]}
    /// ]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(64 + self.batches.len() * 360);
        s.push_str("{\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"batches\":[");
        for (bi, b) in self.batches.iter().enumerate() {
            if bi > 0 {
                s.push(',');
            }
            s.push_str("{\"caller\":\"");
            s.push_str(&hex32(&b.caller));
            s.push_str("\",\"total_reclaimed\":");
            s.push_str(&b.total_reclaimed.to_string());
            s.push_str(",\"actions\":[");
            for (i, a) in b.actions.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str("{\"escrow_id\":\"");
                s.push_str(&hex32(&a.escrow_id));
                s.push_str("\",\"action\":\"close_vault\",\"caller\":\"");
                s.push_str(&hex32(&a.caller));
                s.push_str("\",\"caller_role\":\"");
                s.push_str(a.caller_role);
                s.push_str("\",\"rent_reclaimed\":");
                s.push_str(&a.rent_reclaimed.to_string());
                s.push_str(",\"reason\":\"");
                s.push_str(a.reason);
                s.push_str("\"}");
            }
            s.push_str("]}");
        }
        s.push_str("]}");
        s
    }
}

/// Scan `watched` and return every immediately executable `close_vault`
/// call, grouped into per-caller batches. Pure read over the
/// snapshots: zero side effects, deterministic output in input order.
///
/// The scan lists exactly the vaults AV-34's `close_vault` accepts —
/// `Cancelled`, `Released`, `Settled` — and nothing else:
///
/// - `Disputed` is skipped: the chain rejects the close (the
///   arbitration is still live, and the vault account is the audit
///   surface the arbiter works from), so listing it would not be an
///   *executable* call.
/// - `Closed` is skipped: the rent deposit is already reclaimed and a
///   second `close_vault` fails with `InvalidStateTransition`.
/// - `Uninitialized` / `Funded` / `Activated` are skipped: their vault
///   accounts have not served their purpose yet, and the close would
///   fail the terminal-state gate.
///
/// The scan carries no `now`: closing has no time gate, so the list is
/// valid until the vaults are closed and re-scanned.
pub fn scan_closeable(watched: &[WatchedEscrow]) -> CloseReport {
    // AV-40: `rent_reclaimed` is computed from the current
    // `VAULT_SPACE` formula (via `vault_close_rent_reclaimed`), never
    // hardcoded — the same figure `close_vault` returns on success.
    let rent = vault_close_rent_reclaimed();
    let mut batches: Vec<CloseBatch> = Vec::new();
    for w in watched {
        let e = &w.escrow;
        // Mirror AV-34's terminal-state gate exactly: only the three
        // states `close_vault` accepts contribute an action.
        let reason = match e.state() {
            EscrowState::Cancelled => "cancelled",
            EscrowState::Released => "released",
            EscrowState::Settled => "settled",
            _ => continue,
        };
        let caller = e.initializer();
        let action = CloseAction {
            escrow_id: w.escrow_id,
            // AV-34 restricts `close_vault` to the initializer —
            // authority is checked before state validity — so the
            // initializer is the canonical caller *and* the only key
            // the chain accepts.
            caller,
            caller_role: "initializer",
            rent_reclaimed: rent,
            reason,
        };
        // Group per caller, batches in first-seen caller order.
        match batches.iter_mut().find(|b| b.caller == caller) {
            Some(batch) => {
                batch.actions.push(action);
                batch.total_reclaimed += rent;
            }
            None => batches.push(CloseBatch {
                caller,
                actions: vec![action],
                total_reclaimed: rent,
            }),
        }
    }
    CloseReport {
        scanned: watched.len(),
        batches,
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
        released.release(ALICE, 1_750_000_000, AMOUNT, None).unwrap();
        let mut cancelled = funded(AMOUNT, NEVER);
        cancelled.cancel(ALICE, None, ALICE).unwrap();
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
            let executable = probe.cancel_expired(ALICE, now, None, ALICE).is_ok();
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
        e.release(ALICE, 1_750_000_000, 400_000, None).unwrap();
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
        e.release(ALICE, 1_750_000_000, 200_000, None).unwrap();
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
    fn disputed_escrow_lists_resolve_for_arbiter() {
        // AV-38: a disputed escrow lists exactly one keeper action —
        // the arbiter's `resolve` — so an arbiter-operated keeper bot
        // learns which disputes await its ruling. The unilateral exits
        // stay locked, so nothing else is listed.
        const ARBITER: [u8; 32] = [0xA8; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(ALICE, MID, None).unwrap();
        assert_eq!(e.state(), EscrowState::Disputed);
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::Resolve);
        assert_eq!(a.escrow_id, ID1);
        assert_eq!(a.caller, ARBITER);
        assert_eq!(a.caller_role, "arbiter");
        assert_eq!(a.mint, None);
        assert_eq!(a.refund_to, None, "resolve splits, it does not refund");
        assert_eq!(a.amount, AMOUNT, "the splittable pool");
        assert_eq!(a.reason, "disputed");
        // JSON shape: the action name renders as "resolve".
        let json = report.to_json();
        assert!(json.contains("\"action\":\"resolve\""));
        assert!(json.contains("\"caller_role\":\"arbiter\""));
        assert!(json.contains("\"reason\":\"disputed\""));
    }

    #[test]
    fn disputed_evidence_hash_survives_keeper_scan() {
        // AV-22 passthrough: the keeper lists only the arbiter's
        // `resolve` for a disputed escrow (AV-38), but the scan pipeline
        // must not drop the dispute evidence hash — operator tooling
        // reads it from the watched snapshot to fetch the off-chain
        // evidence for the arbiter.
        const EVIDENCE: [u8; 32] = [0xE1; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter([0xA8; 32])
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(BOB, MID, Some(EVIDENCE)).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].kind, KeeperActionKind::Resolve);
        assert_eq!(
            watched[0].escrow.evidence_hash(),
            Some(EVIDENCE),
            "keeper scan dropped the dispute evidence hash"
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
                // No whitelist configured: the refund goes to the
                // initializer (AV-23 default policy).
                refund_to: Some(ALICE),
                amount: AMOUNT,
                // No decimal metadata declared: bare-integer rendering.
                decimals: 0,
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
            "{{\"at\":1000000,\"scanned\":1,\"actions\":[{{\"escrow_id\":\"{}\",\"action\":\"cancel_expired\",\"caller\":\"{}\",\"caller_role\":\"initializer\",\"mint\":null,\"refund_to\":\"{}\",\"amount\":1000000,\"decimals\":0,\"display_amount\":\"1000000\",\"reason\":\"expired\"}}]}}",
            hex_of(0x01),
            hex_of(0xAA),
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
            "{{\"at\":1750000000,\"scanned\":1,\"actions\":[{{\"escrow_id\":\"{}\",\"action\":\"claim\",\"caller\":\"{}\",\"caller_role\":\"taker\",\"mint\":\"{}\",\"refund_to\":null,\"amount\":500000,\"decimals\":0,\"display_amount\":\"500000\",\"reason\":\"vesting_unlocked\"}}]}}",
            hex_of(0x02),
            hex_of(0xBB),
            hex_of(0xD0),
        );
        assert_eq!(report.to_json(), expected);
    }

    #[test]
    fn cancel_expired_action_carries_whitelisted_refund_to() {
        // AV-23: the keeper builds the cancel_expired instruction, so
        // the action must name the refund destination the state machine
        // will pin — the whitelisted address, not the caller.
        const WHITELIST: [u8; 32] = [0xC4; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, 0)
            .unwrap()
            .with_refund_address(WHITELIST)
            .unwrap();
        e.fund(ALICE).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, 1_000_000);
        assert_eq!(report.actions.len(), 1);
        let action = &report.actions[0];
        assert_eq!(action.kind, KeeperActionKind::CancelExpired);
        assert_eq!(action.caller, ALICE, "initializer is the canonical caller");
        assert_eq!(
            action.refund_to,
            Some(WHITELIST),
            "the instruction must name the whitelisted destination"
        );
        assert!(
            report.to_json().contains(&format!(
                "\"refund_to\":\"{}\"",
                hex_of(0xC4)
            )),
            "refund_to must be serialized for the operator"
        );
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

    #[test]
    fn actions_render_human_amounts_with_decimals() {
        // AV-28: a 6-decimal escrow's report carries the raw amount for
        // the instruction and the human amount for the operator.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, 0)
            .unwrap()
            .with_decimals(6)
            .unwrap();
        e.fund(ALICE).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, 1_000_000);
        assert_eq!(report.actions.len(), 1);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::CancelExpired);
        assert_eq!(a.amount, AMOUNT, "the instruction moves raw units");
        assert_eq!(a.decimals, 6);
        let json = report.to_json();
        assert!(
            json.contains("\"amount\":1000000,\"decimals\":6,\"display_amount\":\"1.000000\""),
            "human amount must serialize alongside the raw amount, got: {json}"
        );
    }

    #[test]
    fn claim_action_renders_human_amount_with_decimals() {
        // AV-28: same for the claim path — half of 1_000_000 raw units
        // at 6 decimals is 0.500000 whole tokens.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_decimals(6)
            .unwrap();
        e.fund(ALICE).unwrap();
        let watched = [watch(ID2, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::Claim);
        assert_eq!(a.amount, 500_000);
        assert_eq!(a.decimals, 6);
        let json = report.to_json();
        assert!(
            json.contains("\"amount\":500000,\"decimals\":6,\"display_amount\":\"0.500000\""),
            "claim display amount must serialize, got: {json}"
        );
    }
}

#[cfg(test)]
mod close_keeper_tests {
    use super::*;
    use crate::{
        rent_exempt_minimum_lamports, MAINNET_EXEMPTION_THRESHOLD_YEARS,
        MAINNET_LAMPORTS_PER_BYTE_YEAR, VAULT_SPACE,
    };

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const CAROL: [u8; 32] = [0xCC; 32]; // second initializer (batch grouping)
    const ARBITER: [u8; 32] = [0xA8; 32];
    const ID1: [u8; 32] = [0x01; 32];
    const ID2: [u8; 32] = [0x02; 32];
    const ID3: [u8; 32] = [0x03; 32];
    const ID4: [u8; 32] = [0x04; 32];
    const AMOUNT: u64 = 1_000_000;
    const MID: u64 = 1_750_000_000;
    const NEVER: u64 = u64::MAX; // no timeout

    fn watch(id: [u8; 32], escrow: Escrow) -> WatchedEscrow {
        WatchedEscrow {
            escrow_id: id,
            escrow,
        }
    }

    fn funded(initializer: [u8; 32]) -> Escrow {
        let mut e = Escrow::initialize(initializer, BOB, AMOUNT, NEVER).unwrap();
        e.fund(initializer).unwrap();
        e
    }

    fn cancelled() -> Escrow {
        let mut e = funded(ALICE);
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        e
    }

    fn released() -> Escrow {
        let mut e = funded(ALICE);
        e.release(ALICE, MID, AMOUNT, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        e
    }

    fn settled() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(ALICE, MID, None).unwrap();
        e.resolve(ARBITER, 400_000, None, None).unwrap();
        assert_eq!(e.state(), EscrowState::Settled);
        e
    }

    fn closed() -> Escrow {
        let mut e = released();
        e.close_vault(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Closed);
        e
    }

    fn disputed() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(ALICE, MID, None).unwrap();
        assert_eq!(e.state(), EscrowState::Disputed);
        e
    }

    fn hex_of(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn terminal_states_cancelled_released_settled_are_all_listed() {
        // AV-34's terminal states are exactly the ones `close_vault`
        // accepts — each contributes one closeable action.
        let watched = [
            watch(ID1, cancelled()),
            watch(ID2, released()),
            watch(ID3, settled()),
        ];
        let report = scan_closeable(&watched);
        assert_eq!(report.scanned, 3);
        assert_eq!(report.batches.len(), 1, "one caller: one batch");
        let batch = &report.batches[0];
        assert_eq!(batch.actions.len(), 3);
        // Input order preserved.
        assert_eq!(batch.actions[0].escrow_id, ID1);
        assert_eq!(batch.actions[0].reason, "cancelled");
        assert_eq!(batch.actions[1].escrow_id, ID2);
        assert_eq!(batch.actions[1].reason, "released");
        assert_eq!(batch.actions[2].escrow_id, ID3);
        assert_eq!(batch.actions[2].reason, "settled");
    }

    #[test]
    fn disputed_and_closed_are_skipped() {
        // `Disputed`: the arbitration is still live and the vault
        // account is the arbiter's audit surface — the chain rejects
        // the close, so the keeper never lists it. `Closed`: the rent
        // is already reclaimed and a second close would fail — the
        // scan never lists a call the chain would reject.
        let watched = [watch(ID1, disputed()), watch(ID2, closed())];
        let report = scan_closeable(&watched);
        assert!(report.is_empty(), "neither state is closeable");
        assert_eq!(report.scanned, 2);
        assert_eq!(report.to_json(), r#"{"scanned":2,"batches":[]}"#);
    }

    #[test]
    fn non_terminal_states_are_skipped() {
        // Uninitialized / Funded / Activated: the vault account has
        // not served its purpose yet, and `close_vault` would fail the
        // terminal-state gate — not executable, not listed.
        let uninit = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER).unwrap();
        // AV-12: a dual-signature escrow reaches `Activated` once both
        // parties record their activation signatures.
        let mut activated = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_dual_sig()
            .unwrap();
        activated.activate(ALICE).unwrap();
        activated.activate(BOB).unwrap();
        assert_eq!(activated.state(), EscrowState::Activated);
        let watched = [
            watch(ID1, uninit),
            watch(ID2, funded(ALICE)),
            watch(ID3, activated),
        ];
        let report = scan_closeable(&watched);
        assert!(report.is_empty());
        assert_eq!(report.scanned, 3);
    }

    #[test]
    fn initializer_is_the_canonical_caller() {
        // AV-34 restricts `close_vault` to the initializer, checked
        // before state validity — the report names the one key the
        // chain will accept. Each escrow's own initializer signs for
        // its vault.
        let mut e = funded(CAROL);
        e.cancel(CAROL, None, CAROL).unwrap();
        let carol_escrow = e;
        let watched = [watch(ID1, cancelled()), watch(ID2, carol_escrow)];
        let report = scan_closeable(&watched);
        assert_eq!(report.batches.len(), 2);
        for batch in &report.batches {
            for a in &batch.actions {
                assert_eq!(a.caller, batch.caller);
                assert_eq!(a.caller_role, "initializer");
            }
        }
        assert_eq!(report.batches[0].caller, ALICE);
        assert_eq!(report.batches[0].actions[0].caller, ALICE);
        assert_eq!(report.batches[1].caller, CAROL);
        assert_eq!(report.batches[1].actions[0].caller, CAROL);
    }

    #[test]
    fn rent_reclaimed_matches_current_vault_space_formula() {
        // AV-40: the estimate is computed from the CURRENT
        // `VAULT_SPACE` formula — never a hardcoded figure. The layout
        // has grown since earlier constants, so the test recomputes
        // the rent-exempt minimum from the live `VAULT_SPACE` instead
        // of pinning a stale number.
        let expected = rent_exempt_minimum_lamports(
            VAULT_SPACE,
            MAINNET_LAMPORTS_PER_BYTE_YEAR,
            MAINNET_EXEMPTION_THRESHOLD_YEARS,
        );
        assert_eq!(
            vault_close_rent_reclaimed(),
            expected,
            "rent reclaimed must track the current VAULT_SPACE"
        );
        let watched = [watch(ID1, cancelled()), watch(ID2, settled())];
        let report = scan_closeable(&watched);
        for batch in &report.batches {
            for a in &batch.actions {
                assert_eq!(
                    a.rent_reclaimed, expected,
                    "listed reclaim must equal the VAULT_SPACE formula"
                );
            }
            assert_eq!(
                batch.total_reclaimed,
                expected * batch.actions.len() as u64,
                "batch total must equal the per-action sum"
            );
        }
    }

    #[test]
    fn listed_rent_matches_close_vault_return() {
        // Keeper/chain agreement: the scan's estimate equals what a
        // real `close_vault` returns — the keeper never quotes a
        // figure the chain would not actually transfer.
        let escrows = [cancelled(), released(), settled()];
        let watched = [
            watch(ID1, escrows[0]),
            watch(ID2, escrows[1]),
            watch(ID3, escrows[2]),
        ];
        let report = scan_closeable(&watched);
        let actions: Vec<&CloseAction> =
            report.batches.iter().flat_map(|b| b.actions.iter()).collect();
        assert_eq!(actions.len(), 3);
        for (i, w) in watched.iter().enumerate() {
            let mut probe = w.escrow;
            let rent = probe.close_vault(w.escrow.initializer()).unwrap();
            assert_eq!(
                actions[i].rent_reclaimed, rent,
                "keeper estimate disagrees with close_vault at index {i}"
            );
            assert_eq!(actions[i].caller, w.escrow.initializer());
        }
    }

    #[test]
    fn actions_grouped_per_caller_with_totals() {
        // Two initializers share the watch list: the sweep groups per
        // caller with a per-batch reclaimed total.
        let rent = vault_close_rent_reclaimed();
        let mut carol_cancelled = funded(CAROL);
        carol_cancelled.cancel(CAROL, None, CAROL).unwrap();
        let watched = [
            watch(ID1, cancelled()),      // ALICE
            watch(ID2, carol_cancelled),  // CAROL
            watch(ID3, released()),       // ALICE
            watch(ID4, funded(ALICE)),    // ALICE, but live: skipped
        ];
        let report = scan_closeable(&watched);
        assert_eq!(report.scanned, 4);
        assert_eq!(report.batches.len(), 2);
        let (alice_batch, carol_batch) = (&report.batches[0], &report.batches[1]);
        // Batches in first-seen caller order.
        assert_eq!(alice_batch.caller, ALICE);
        assert_eq!(carol_batch.caller, CAROL);
        // Actions in input order within each batch.
        assert_eq!(alice_batch.actions.len(), 2);
        assert_eq!(alice_batch.actions[0].escrow_id, ID1);
        assert_eq!(alice_batch.actions[1].escrow_id, ID3);
        assert_eq!(carol_batch.actions.len(), 1);
        assert_eq!(carol_batch.actions[0].escrow_id, ID2);
        // Per-batch totals.
        assert_eq!(alice_batch.total_reclaimed, 2 * rent);
        assert_eq!(carol_batch.total_reclaimed, rent);
        // Total invariant: the batch total is the sum of its actions.
        for batch in &report.batches {
            let sum: u64 = batch.actions.iter().map(|a| a.rent_reclaimed).sum();
            assert_eq!(batch.total_reclaimed, sum);
        }
    }

    #[test]
    fn batch_order_follows_first_seen_caller() {
        // Deterministic output: batch order is the callers' first
        // appearance in the input, so a stable watch list gives a
        // stable sweep list.
        let mut carol_cancelled = funded(CAROL);
        carol_cancelled.cancel(CAROL, None, CAROL).unwrap();
        let watched = [watch(ID1, carol_cancelled), watch(ID2, cancelled())];
        let report = scan_closeable(&watched);
        assert_eq!(report.batches.len(), 2);
        assert_eq!(report.batches[0].caller, CAROL);
        assert_eq!(report.batches[1].caller, ALICE);
    }

    #[test]
    fn scan_is_dry_run() {
        // Zero side effects: the snapshots are bit-identical after
        // the scan (WatchedEscrow is Copy + PartialEq, so exact).
        let before = [
            watch(ID1, cancelled()),
            watch(ID2, disputed()),
            watch(ID3, released()),
            watch(ID4, settled()),
        ];
        let _report = scan_closeable(&before);
        assert_eq!(
            before,
            [
                watch(ID1, cancelled()),
                watch(ID2, disputed()),
                watch(ID3, released()),
                watch(ID4, settled())
            ]
        );
    }

    #[test]
    fn json_shape_is_pinned() {
        // Deterministic serialization: fixed field order, 64-hex
        // lowercase keys, batches in first-seen caller order, actions
        // in input order.
        let rent = vault_close_rent_reclaimed();
        let watched = [watch(ID1, cancelled()), watch(ID2, released())];
        let report = scan_closeable(&watched);
        let expected = format!(
            "{{\"scanned\":2,\"batches\":[{{\"caller\":\"{}\",\"total_reclaimed\":{},\"actions\":[{{\"escrow_id\":\"{}\",\"action\":\"close_vault\",\"caller\":\"{}\",\"caller_role\":\"initializer\",\"rent_reclaimed\":{},\"reason\":\"cancelled\"}},{{\"escrow_id\":\"{}\",\"action\":\"close_vault\",\"caller\":\"{}\",\"caller_role\":\"initializer\",\"rent_reclaimed\":{},\"reason\":\"released\"}}]}}]}}",
            hex_of(0xAA),
            2 * rent,
            hex_of(0x01),
            hex_of(0xAA),
            rent,
            hex_of(0x02),
            hex_of(0xAA),
            rent,
        );
        assert_eq!(report.to_json(), expected);
    }

    #[test]
    fn empty_input_scans_to_empty_report() {
        let report = scan_closeable(&[]);
        assert!(report.is_empty());
        assert_eq!(report.scanned, 0);
        assert_eq!(report.to_json(), r#"{"scanned":0,"batches":[]}"#);
    }
}

// ============================================================================
// Milestone tranche keeper scan (AV-42)
// ============================================================================
//
// `scan_keeper_actions` (AV-20) answers "which vault needs a keeper call
// *right now*". Milestone-plan escrows (AV-15) need a finer answer: each
// tranche moves through confirm -> release, or the dual-signed skip path,
// strictly in order, so the keeper must know *which party's signature is
// missing* and *which tranche is sequence-blocked*.
//
// [`scan_milestones`] is the third keeper scan. It walks the same watch
// list and, per escrow, emits:
//
// - `actions`: the immediately executable milestone calls — each party's
//   missing `confirm_milestone` approval, each party's missing
//   `skip_milestone` approval, and the initializer's `release_milestone`
//   once every gate passes. Every action carries the exact arguments the
//   keeper needs: `escrow_id`, `index`, `caller` (+ `caller_role`),
//   `mint`, and the tranche amount split (`tranche`, `fee`,
//   `taker_payout` — the AV-17 protocol-fee preview, `0` on
//   confirm/skip actions which move no funds).
// - `blocked`: per-tranche `release_milestone` items that are *not*
//   executable yet, each with the machine-readable reason:
//   `"unconfirmed"` (confirmations missing), `"quorum_not_satisfied"`,
//   `"timelock_not_reached"`, or `"prerequisite"` (an earlier tranche is
//   still unsettled — settlement is strictly in-order).
//
// Skipping is dual-signed on-chain: each party records their skip
// approval with a *separate* `skip_milestone` call, and the skip executes
// only once both approvals are present. The scan therefore lists each
// missing party's approval as its own executable call — exactly like
// confirmations — rather than inventing a combined call the chain has no
// instruction for.
//
// Like the other scans this is a dry-run over `&Escrow` snapshots: no
// mutation, no events, no clock. Escrows without a milestone plan, not in
// `Funded` state, or whose plan is fully settled contribute nothing —
// there is no executable milestone call on them.
//
// Output is the same hand-rolled deterministic JSON as the other scans
// (AV-33 conventions): fixed field order, 64-char lowercase hex keys,
// `mint` as hex or `null`, actions and blocked entries in scan order.

/// The milestone-tranche keeper action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MilestoneActionKind {
    /// `confirm_milestone(authority, index)`: one party's acceptance of
    /// the deliverable. Per-party and idempotent — the scan lists the
    /// missing party's call.
    ConfirmMilestone,
    /// `skip_milestone(authority, index)`: one party's skip approval.
    /// Dual-signed on-chain (both parties approve separately); the scan
    /// lists each missing party's approval call.
    SkipMilestone,
    /// `release_milestone(initializer, now, index, mint)`: the
    /// initializer's push of a dual-confirmed tranche to the taker.
    ReleaseMilestone,
}

impl MilestoneActionKind {
    fn as_str(&self) -> &'static str {
        match self {
            MilestoneActionKind::ConfirmMilestone => "confirm_milestone",
            MilestoneActionKind::SkipMilestone => "skip_milestone",
            MilestoneActionKind::ReleaseMilestone => "release_milestone",
        }
    }
}

/// One executable milestone call: everything needed to build the
/// instruction, nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MilestoneAction {
    /// Which escrow this call targets.
    pub escrow_id: [u8; 32],
    /// Which transition to invoke.
    pub kind: MilestoneActionKind,
    /// The 0-based tranche index.
    pub index: u8,
    /// The key that must sign the call.
    pub caller: [u8; 32],
    /// Which role `caller` plays: `"initializer"` or `"taker"`.
    pub caller_role: &'static str,
    /// The `mint` argument to pass: the escrow's bound mint, or `None`
    /// on the native-SOL path.
    pub mint: Option<[u8; 32]>,
    /// The tranche's gross amount.
    pub tranche: u64,
    /// Protocol-fee preview for `release_milestone`
    /// ([`Escrow::protocol_fee_for`]); `0` on confirm/skip actions,
    /// which move no funds.
    pub fee: u64,
    /// `tranche - fee` for `release_milestone`: the taker's net payout;
    /// `0` on confirm/skip actions.
    pub taker_payout: u64,
    /// The escrow's token decimal metadata (AV-28): the SPL mint's
    /// decimal places, `0` when none is declared. Feeds the report's
    /// `display_amount` rendering only.
    pub decimals: u8,
    /// Machine-readable reason: `"confirmation_pending"`,
    /// `"skip_approval_pending"`, or `"confirmed"`.
    pub reason: &'static str,
}

/// One not-yet-executable `release_milestone`: the tranche, and why the
/// keeper must wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MilestoneBlocked {
    /// Which escrow this item belongs to.
    pub escrow_id: [u8; 32],
    /// The 0-based tranche index.
    pub index: u8,
    /// Always `"release_milestone"` today: confirmations and skip
    /// approvals are the executable path *toward* this call.
    pub action: &'static str,
    /// `"unconfirmed"`, `"quorum_not_satisfied"`,
    /// `"timelock_not_reached"`, or `"prerequisite"`.
    pub reason: &'static str,
}

/// The milestone scan result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MilestoneReport {
    /// The `now` (Unix seconds) the scan ran at.
    pub at: u64,
    /// How many escrows were scanned.
    pub scanned: usize,
    /// Executable actions, in the input's order.
    pub actions: Vec<MilestoneAction>,
    /// Blocked `release_milestone` items, in the input's order.
    pub blocked: Vec<MilestoneBlocked>,
}

impl MilestoneReport {
    /// True when the scan found neither an executable action nor a
    /// blocked tranche.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.blocked.is_empty()
    }

    /// Hand-serialized JSON (the crate is dependency-free). Deterministic
    /// field order; keys are 64-char lowercase hex; `mint` is a hex
    /// string or `null`.
    ///
    /// ```json
    /// {"at":1000000,"scanned":1,"actions":[
    ///   {"escrow_id":"...","action":"confirm_milestone","index":0,
    ///    "caller":"...","caller_role":"taker","mint":null,
    ///    "tranche":300000,"fee":0,"taker_payout":0,"decimals":6,
    ///    "display_amount":"0.300000","reason":"confirmation_pending"}
    /// ],"blocked":[
    ///   {"escrow_id":"...","index":1,"action":"release_milestone",
    ///    "reason":"prerequisite"}
    /// ]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(128 + self.actions.len() * 380);
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
            s.push_str("\",\"index\":");
            s.push_str(&a.index.to_string());
            s.push_str(",\"caller\":\"");
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
            s.push_str(",\"tranche\":");
            s.push_str(&a.tranche.to_string());
            s.push_str(",\"fee\":");
            s.push_str(&a.fee.to_string());
            s.push_str(",\"taker_payout\":");
            s.push_str(&a.taker_payout.to_string());
            s.push_str(",\"decimals\":");
            s.push_str(&a.decimals.to_string());
            s.push_str(",\"display_amount\":\"");
            s.push_str(&format_amount(a.tranche, a.decimals));
            s.push_str("\",\"reason\":\"");
            s.push_str(a.reason);
            s.push_str("\"}");
        }
        s.push_str("],\"blocked\":[");
        for (i, b) in self.blocked.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&b.escrow_id));
            s.push_str("\",\"index\":");
            s.push_str(&b.index.to_string());
            s.push_str(",\"action\":\"");
            s.push_str(b.action);
            s.push_str("\",\"reason\":\"");
            s.push_str(b.reason);
            s.push_str("\"}");
        }
        s.push_str("]}");
        s
    }
}

/// Build one [`MilestoneAction`] with the escrow-derived fields filled in.
/// `fee`/`taker_payout` are the release amount split; callers pass `0`
/// for confirm/skip actions, which move no funds.
fn milestone_action(
    escrow_id: [u8; 32],
    kind: MilestoneActionKind,
    index: u8,
    caller: [u8; 32],
    caller_role: &'static str,
    e: &Escrow,
    tranche: u64,
    fee: u64,
    taker_payout: u64,
    reason: &'static str,
) -> MilestoneAction {
    MilestoneAction {
        escrow_id,
        kind,
        index,
        caller,
        caller_role,
        mint: e.mint(),
        tranche,
        fee,
        taker_payout,
        decimals: e.decimals(),
        reason,
    }
}

/// Scan `watched` at `now` and return every executable milestone call
/// plus every sequence/gate-blocked tranche. Pure read over the
/// snapshots: zero side effects, deterministic output in input order.
///
/// Only the first unsettled tranche of a `Funded` escrow with a plan can
/// carry executable calls — confirmations and skip approvals are
/// strictly in-order on-chain, and `release_milestone` additionally
/// requires every earlier tranche settled. Later unsettled tranches are
/// reported as blocked with reason `"prerequisite"`.
pub fn scan_milestones(watched: &[WatchedEscrow], now: u64) -> MilestoneReport {
    let mut actions = Vec::new();
    let mut blocked = Vec::new();
    for w in watched {
        let e = &w.escrow;
        if e.state() != EscrowState::Funded {
            continue;
        }
        let plan = match e.milestone_plan() {
            Some(p) => p,
            None => continue,
        };
        let count = plan.count() as usize;
        let next = match e.next_milestone() {
            Some(i) => i,
            None => continue,
        };
        let tranche = plan
            .amount_at(next)
            .expect("next_milestone is always in plan range");
        let index = next as u8;
        let init = e.initializer();
        let taker = e.taker();

        // Confirmations: each missing party's approval is an executable
        // call (idempotent per party on-chain).
        if !e.milestone_confirmed_by_initializer(next) {
            actions.push(milestone_action(
                w.escrow_id,
                MilestoneActionKind::ConfirmMilestone,
                index,
                init,
                "initializer",
                e,
                tranche,
                0,
                0,
                "confirmation_pending",
            ));
        }
        if !e.milestone_confirmed_by_taker(next) {
            actions.push(milestone_action(
                w.escrow_id,
                MilestoneActionKind::ConfirmMilestone,
                index,
                taker,
                "taker",
                e,
                tranche,
                0,
                0,
                "confirmation_pending",
            ));
        }
        // Skip approvals: dual-signed on-chain, one executable call per
        // missing party — the same shape as confirmations.
        if !e.milestone_skip_approved_by_initializer(next) {
            actions.push(milestone_action(
                w.escrow_id,
                MilestoneActionKind::SkipMilestone,
                index,
                init,
                "initializer",
                e,
                tranche,
                0,
                0,
                "skip_approval_pending",
            ));
        }
        if !e.milestone_skip_approved_by_taker(next) {
            actions.push(milestone_action(
                w.escrow_id,
                MilestoneActionKind::SkipMilestone,
                index,
                taker,
                "taker",
                e,
                tranche,
                0,
                0,
                "skip_approval_pending",
            ));
        }

        // Release: the full on-chain gate set, read-only. Mirrors
        // `release_milestone`'s check order (quorum, timelock, then
        // confirmation); the sequence gate holds by construction since
        // only the first unsettled tranche is considered.
        let quorum_ok = e.quorum().map(|q| q.is_satisfied()).unwrap_or(true);
        let timelock_ok = e.is_unlock_eligible(now);
        let confirmed = e.milestone_confirmed(next);
        if quorum_ok && timelock_ok && confirmed {
            let fee = e.protocol_fee_for(tranche);
            actions.push(milestone_action(
                w.escrow_id,
                MilestoneActionKind::ReleaseMilestone,
                index,
                init,
                "initializer",
                e,
                tranche,
                fee,
                tranche - fee,
                "confirmed",
            ));
        } else {
            let reason = if !quorum_ok {
                "quorum_not_satisfied"
            } else if !timelock_ok {
                "timelock_not_reached"
            } else {
                "unconfirmed"
            };
            blocked.push(MilestoneBlocked {
                escrow_id: w.escrow_id,
                index,
                action: "release_milestone",
                reason,
            });
        }

        // Later unsettled tranches: sequence-blocked until every earlier
        // tranche settles.
        for i in (next + 1)..count {
            if !e.milestone_settled(i) {
                blocked.push(MilestoneBlocked {
                    escrow_id: w.escrow_id,
                    index: i as u8,
                    action: "release_milestone",
                    reason: "prerequisite",
                });
            }
        }
    }
    MilestoneReport {
        at: now,
        scanned: watched.len(),
        actions,
        blocked,
    }
}

#[cfg(test)]
mod keeper_milestone_tests {
    use super::*;
    use crate::{EscrowError, MilestonePlan, QuorumPolicy};

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const A1: [u8; 32] = [0xA1; 32]; // attestors
    const A2: [u8; 32] = [0xA2; 32];
    const A3: [u8; 32] = [0xA3; 32];
    const ID1: [u8; 32] = [0x01; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;
    const NOW: u64 = 1_750_000_000;

    fn watch(id: [u8; 32], escrow: Escrow) -> WatchedEscrow {
        WatchedEscrow {
            escrow_id: id,
            escrow,
        }
    }

    /// Funded escrow with a milestone plan splitting `amounts`. The
    /// `build` closure configures pre-funding options (fee, quorum,
    /// timelock) on the `Uninitialized` escrow before it is funded.
    fn milestone_escrow(amounts: &[u64]) -> Escrow {
        milestone_escrow_with(amounts, Ok)
    }

    fn milestone_escrow_with(
        amounts: &[u64],
        build: impl FnOnce(Escrow) -> Result<Escrow, EscrowError>,
    ) -> Escrow {
        let total: u64 = amounts.iter().sum();
        let e = Escrow::initialize(ALICE, BOB, total, EXPIRES_AT)
            .unwrap()
            .with_milestones(MilestonePlan::new(amounts).unwrap())
            .unwrap();
        let mut e = build(e).unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    fn hex_of(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn confirm_lists_only_the_missing_party() {
        let mut e = milestone_escrow(&[300_000, 700_000]);
        e.confirm_milestone(ALICE, 0).unwrap();
        let report = scan_milestones(&[watch(ID1, e)], NOW);
        // The initializer's confirmation is done: only the taker's
        // confirm remains, plus both skip approvals, and the release is
        // blocked as unconfirmed.
        let confirms: Vec<_> = report
            .actions
            .iter()
            .filter(|a| a.kind == MilestoneActionKind::ConfirmMilestone)
            .collect();
        assert_eq!(confirms.len(), 1, "actions: {:?}", report.actions);
        assert_eq!(confirms[0].caller, BOB);
        assert_eq!(confirms[0].caller_role, "taker");
        assert_eq!(confirms[0].index, 0);
        assert_eq!(confirms[0].tranche, 300_000);
        assert_eq!(report.blocked.len(), 2);
        assert_eq!(report.blocked[0].reason, "unconfirmed");
        assert_eq!(report.blocked[0].index, 0);
        assert_eq!(report.blocked[1].reason, "prerequisite");
        assert_eq!(report.blocked[1].index, 1);
    }

    #[test]
    fn skip_lists_only_the_missing_approval() {
        let mut e = milestone_escrow(&[300_000, 700_000]);
        e.skip_milestone(BOB, 0).unwrap();
        let report = scan_milestones(&[watch(ID1, e)], NOW);
        let skips: Vec<_> = report
            .actions
            .iter()
            .filter(|a| a.kind == MilestoneActionKind::SkipMilestone)
            .collect();
        assert_eq!(skips.len(), 1, "actions: {:?}", report.actions);
        assert_eq!(skips[0].caller, ALICE);
        assert_eq!(skips[0].caller_role, "initializer");
        assert_eq!(skips[0].reason, "skip_approval_pending");
    }

    #[test]
    fn release_lists_with_fee_split_when_fully_gated() {
        let mut e = milestone_escrow_with(&[300_000, 700_000], |e| {
            e.with_protocol_fee(100)
        });
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        let report = scan_milestones(&[watch(ID1, e)], NOW);
        let releases: Vec<_> = report
            .actions
            .iter()
            .filter(|a| a.kind == MilestoneActionKind::ReleaseMilestone)
            .collect();
        assert_eq!(releases.len(), 1, "actions: {:?}", report.actions);
        let r = releases[0];
        assert_eq!(r.caller, ALICE);
        assert_eq!(r.caller_role, "initializer");
        assert_eq!(r.tranche, 300_000);
        assert_eq!(r.fee, 3_000); // floor(300_000 * 100 / 10_000)
        assert_eq!(r.taker_payout, 297_000);
        assert_eq!(r.reason, "confirmed");
        // The next tranche is still sequence-blocked.
        assert_eq!(report.blocked.len(), 1);
        assert_eq!(report.blocked[0].reason, "prerequisite");
    }

    #[test]
    fn release_blocked_by_quorum_reports_reason() {
        let mut e = milestone_escrow_with(&[300_000, 700_000], |e| {
            e.with_quorum(QuorumPolicy::new(&[A1, A2, A3], 2).unwrap())
        });
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        // No attestations: quorum not satisfied, even though both
        // parties confirmed.
        let report = scan_milestones(&[watch(ID1, e)], NOW);
        assert!(
            report
                .actions
                .iter()
                .all(|a| a.kind != MilestoneActionKind::ReleaseMilestone),
            "release must not be listed: {:?}",
            report.actions
        );
        assert_eq!(report.blocked[0].reason, "quorum_not_satisfied");
        // Confirm/skip approvals are not quorum-gated: nothing blocks
        // them, and both parties already confirmed so none are listed.
        assert!(
            report
                .actions
                .iter()
                .all(|a| a.kind == MilestoneActionKind::SkipMilestone),
            "only skip approvals remain: {:?}",
            report.actions
        );
    }

    #[test]
    fn release_blocked_by_timelock_reports_reason() {
        let mut e = milestone_escrow_with(&[300_000, 700_000], |e| {
            e.with_timelock(NOW + 1_000)
        });
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        let report = scan_milestones(&[watch(ID1, e)], NOW);
        assert!(
            report
                .actions
                .iter()
                .all(|a| a.kind != MilestoneActionKind::ReleaseMilestone),
            "release must not be listed before unlock_at"
        );
        assert_eq!(report.blocked[0].reason, "timelock_not_reached");
        // After the timelock passes the same state releases.
        let later = scan_milestones(&[watch(ID1, e)], NOW + 1_000);
        assert!(
            later
                .actions
                .iter()
                .any(|a| a.kind == MilestoneActionKind::ReleaseMilestone),
            "release must unlock at unlock_at: {:?}",
            later.actions
        );
    }

    #[test]
    fn json_is_deterministic_and_pinned() {
        let mut e = milestone_escrow(&[300_000, 700_000]);
        e.confirm_milestone(ALICE, 0).unwrap();
        let watched = [watch(ID1, e)];
        let a = scan_milestones(&watched, NOW).to_json();
        let b = scan_milestones(&watched, NOW).to_json();
        assert_eq!(a, b, "equal input must serialize byte-identically");
        // Pinned shape: the taker's missing confirmation plus the
        // unconfirmed/prerequisite blocked entries.
        let expected = format!(
            "{{\"at\":1750000000,\"scanned\":1,\"actions\":[\
             {{\"escrow_id\":\"{id}\",\"action\":\"confirm_milestone\",\"index\":0,\
             \"caller\":\"{bob}\",\"caller_role\":\"taker\",\"mint\":null,\
             \"tranche\":300000,\"fee\":0,\"taker_payout\":0,\"decimals\":0,\
             \"display_amount\":\"300000\",\"reason\":\"confirmation_pending\"}},\
             {{\"escrow_id\":\"{id}\",\"action\":\"skip_milestone\",\"index\":0,\
             \"caller\":\"{alice}\",\"caller_role\":\"initializer\",\"mint\":null,\
             \"tranche\":300000,\"fee\":0,\"taker_payout\":0,\"decimals\":0,\
             \"display_amount\":\"300000\",\"reason\":\"skip_approval_pending\"}},\
             {{\"escrow_id\":\"{id}\",\"action\":\"skip_milestone\",\"index\":0,\
             \"caller\":\"{bob}\",\"caller_role\":\"taker\",\"mint\":null,\
             \"tranche\":300000,\"fee\":0,\"taker_payout\":0,\"decimals\":0,\
             \"display_amount\":\"300000\",\"reason\":\"skip_approval_pending\"}}\
             ],\"blocked\":[\
             {{\"escrow_id\":\"{id}\",\"index\":0,\"action\":\"release_milestone\",\"reason\":\"unconfirmed\"}},\
             {{\"escrow_id\":\"{id}\",\"index\":1,\"action\":\"release_milestone\",\"reason\":\"prerequisite\"}}\
             ]}}",
            id = hex_of(0x01),
            alice = hex_of(0xAA),
            bob = hex_of(0xBB),
        );
        assert_eq!(a, expected, "pinned JSON shape");
    }

    #[test]
    fn skips_escrows_without_plan_or_not_funded() {
        // Funded but no milestone plan: nothing milestone-related.
        let mut plain = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        plain.fund(ALICE).unwrap();
        // Plan attached but never funded: not executable.
        let unplanned = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[1_000_000]).unwrap())
            .unwrap();
        let report = scan_milestones(&[watch(ID1, plain), watch([0x02; 32], unplanned)], NOW);
        assert!(report.is_empty(), "nothing actionable: {report:?}");
        assert_eq!(report.scanned, 2);
    }

    #[test]
    fn scan_is_dry_run() {
        let mut e = milestone_escrow(&[300_000, 700_000]);
        e.confirm_milestone(ALICE, 0).unwrap();
        let before = e;
        let _ = scan_milestones(&[watch(ID1, e)], NOW);
        assert_eq!(e, before, "scan must not mutate the escrow");
    }

    #[test]
    fn per_party_accessors_match_bits() {
        let mut e = milestone_escrow(&[300_000, 700_000]);
        assert!(!e.milestone_confirmed_by_initializer(0));
        assert!(!e.milestone_confirmed_by_taker(0));
        e.confirm_milestone(ALICE, 0).unwrap();
        assert!(e.milestone_confirmed_by_initializer(0));
        assert!(!e.milestone_confirmed_by_taker(0));
        assert!(!e.milestone_confirmed(0));
        e.skip_milestone(BOB, 0).unwrap();
        assert!(e.milestone_skip_approved_by_taker(0));
        assert!(!e.milestone_skip_approved_by_initializer(0));
        // Out of range: false, never panics.
        assert!(!e.milestone_confirmed_by_initializer(63));
        assert!(!e.milestone_skip_approved_by_taker(63));
    }

    #[test]
    fn stranger_cannot_confirm_or_skip() {
        // Sanity: the accessors report what the state machine did, and
        // the state machine rejects strangers.
        let mut e = milestone_escrow(&[300_000, 700_000]);
        assert_eq!(
            e.confirm_milestone([0xCC; 32], 0),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            e.skip_milestone([0xCC; 32], 0),
            Err(EscrowError::Unauthorized)
        );
    }
}

// ============================================================================
// Vault rent-health keeper scan (AV-43)
// ============================================================================
//
// `scan_keeper_actions` (AV-20) answers "which vault needs a keeper call
// *right now*", `scan_closeable` (AV-40) sweeps terminal vaults, and
// `scan_milestones` (AV-42) walks tranche gates. None of them watches the
// vault *account's* lamports balance — but a vault account must carry the
// rent-exempt minimum for [`VAULT_SPACE`](crate::VAULT_SPACE) for as long
// as the escrow lives. A vault whose balance has eroded below that minimum
// is rent-bleeding: on-chain the runtime eats lamports each epoch, and at
// close the account only transfers what it actually holds — the
// initializer's expected `vault_close_rent_reclaimed()` reclaim (see
// [`Escrow::close_vault`]) silently shrinks. An underfunded vault can
// therefore make `close_vault` *economically* fail: the close succeeds on
// the state machine but returns less rent than the operator funded.
//
// [`scan_rent_health`] is the fourth keeper scan: it walks watched vaults
// together with their measured on-chain lamports balances
// ([`WatchedEscrowWithBalance`]) and lists every vault whose balance has
// fallen into the critical threshold — a configurable percentage of the
// canonical rent-exempt minimum — with the exact top-up lamports needed
// to restore full rent exemption (`required - balance`). The operator
// transfers exactly that amount into the vault account; the next scan
// shows the vault healthy again.
//
// The canonical figure is the main formula: [`vault_close_rent_reclaimed`]
// (`rent_exempt_minimum_lamports(VAULT_SPACE, MAINNET...)`) — the same
// number `initialize` funds, `check_vault_rent_exempt` enforces, and
// `close_vault` promises. Never a hardcoded figure: the account layout
// has grown since earlier constants, and the scan tracks the layout
// automatically.
//
// Like the other scans this is a dry-run over `&` snapshots: no mutation,
// no events. `Closed` vaults are skipped — the account no longer exists,
// so there is no balance to measure. Every other state is scanned: a
// live `Funded` vault bleeds rent while it waits, a terminal vault bleeds
// while it waits to be closed, and an `Uninitialized` entry with a zero
// balance simply reports the full `required` — exactly what `initialize`
// will demand. Actions keep the input order so a keeper feeding a stable
// watch list gets a stable top-up list.
//
// Output is the same hand-rolled deterministic JSON as the other scans:
// fixed field order, 64-char lowercase hex keys, lamports as plain
// integers (the exact unit the top-up transfer moves).

/// One watched vault with its measured on-chain lamports balance: the
/// caller-supplied identity, the read-only state snapshot, and the vault
/// account's *actual* lamports as observed off-chain (e.g. via
/// `getAccountInfo`). The scan never mutates the snapshot (dry-run).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchedEscrowWithBalance {
    /// Caller-supplied 32-byte escrow identity — the same convention as
    /// [`WatchedEscrow::escrow_id`].
    pub escrow_id: [u8; 32],
    /// Read-only snapshot of the escrow's state.
    pub escrow: Escrow,
    /// The vault account's measured lamports balance.
    pub vault_lamports: u64,
}

/// One executable `top_up` action: everything needed to fund the vault
/// back to rent exemption, nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopUpAction {
    /// Which escrow's vault this action tops up.
    pub escrow_id: [u8; 32],
    /// The escrow's state at scan time, for operator context:
    /// `"funded"`, `"cancelled"`, `"released"`, `"settled"`,
    /// `"disputed"`, `"activated"`, or `"uninitialized"`.
    pub state: &'static str,
    /// The vault's measured lamports balance at scan time.
    pub vault_lamports: u64,
    /// The canonical rent-exempt minimum from
    /// [`vault_close_rent_reclaimed`] — the figure the scan compared
    /// against.
    pub required_lamports: u64,
    /// The exact lamports to transfer into the vault account to restore
    /// rent exemption: `required_lamports - vault_lamports`. Always
    /// `> 0` — only under-threshold vaults are listed.
    pub top_up_lamports: u64,
    /// The key that should fund the top-up — the escrow's initializer,
    /// the canonical funder of the vault account (it funded the rent
    /// deposit at `initialize` time).
    pub caller: [u8; 32],
    /// Always `"initializer"` — the canonical vault funder.
    pub caller_role: &'static str,
    /// Machine-readable reason: always `"underfunded"` today — the
    /// vault's balance has fallen below the critical threshold of the
    /// rent-exempt minimum.
    pub reason: &'static str,
}

/// The rent-health scan result: every vault needing a top-up at
/// [`RentHealthReport::at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RentHealthReport {
    /// The `now` (Unix seconds) the scan ran at. The scan has no time
    /// gate — rent health is a balance fact, not a deadline — but the
    /// timestamp pins when the balances were measured.
    pub at: u64,
    /// How many vaults were scanned.
    pub scanned: usize,
    /// The canonical rent-exempt minimum the scan used, from
    /// [`vault_close_rent_reclaimed`].
    pub required_lamports: u64,
    /// The effective critical-threshold percentage (the caller's value,
    /// clamped to `0..=100`).
    pub critical_threshold_pct: u8,
    /// Top-up actions, in the input's order.
    pub top_ups: Vec<TopUpAction>,
}

impl RentHealthReport {
    /// True when every scanned vault is above its critical threshold.
    pub fn is_empty(&self) -> bool {
        self.top_ups.is_empty()
    }

    /// Hand-serialized JSON (the crate is dependency-free). Deterministic
    /// field order; keys are 64-char lowercase hex; lamports are plain
    /// integers — the exact unit the top-up transfer moves.
    ///
    /// ```json
    /// {"at":1000000,"scanned":1,"required_lamports":5477520,
    ///  "critical_threshold_pct":90,"top_ups":[
    ///   {"escrow_id":"...","state":"funded","vault_lamports":4000000,
    ///    "required_lamports":5477520,"top_up_lamports":1477520,
    ///    "caller":"...","caller_role":"initializer",
    ///    "reason":"underfunded"}
    /// ]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(128 + self.top_ups.len() * 380);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"required_lamports\":");
        s.push_str(&self.required_lamports.to_string());
        s.push_str(",\"critical_threshold_pct\":");
        s.push_str(&self.critical_threshold_pct.to_string());
        s.push_str(",\"top_ups\":[");
        for (i, t) in self.top_ups.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&t.escrow_id));
            s.push_str("\",\"state\":\"");
            s.push_str(t.state);
            s.push_str("\",\"vault_lamports\":");
            s.push_str(&t.vault_lamports.to_string());
            s.push_str(",\"required_lamports\":");
            s.push_str(&t.required_lamports.to_string());
            s.push_str(",\"top_up_lamports\":");
            s.push_str(&t.top_up_lamports.to_string());
            s.push_str(",\"caller\":\"");
            s.push_str(&hex32(&t.caller));
            s.push_str("\",\"caller_role\":\"");
            s.push_str(t.caller_role);
            s.push_str("\",\"reason\":\"");
            s.push_str(t.reason);
            s.push_str("\"}");
        }
        s.push_str("]}");
        s
    }
}

/// Lowercase state name for the rent-health report's operator context.
fn rent_health_state_name(state: EscrowState) -> &'static str {
    match state {
        EscrowState::Uninitialized => "uninitialized",
        EscrowState::Funded => "funded",
        EscrowState::Released => "released",
        EscrowState::Cancelled => "cancelled",
        EscrowState::Activated => "activated",
        EscrowState::Disputed => "disputed",
        EscrowState::Settled => "settled",
        EscrowState::Closed => "closed",
    }
}

/// Scan `watched` at `now` and return every vault whose measured balance
/// has fallen into the critical threshold of the canonical rent-exempt
/// minimum, with the exact top-up lamports to restore it. Pure read over
/// the snapshots: zero side effects, deterministic output in input order.
///
/// A vault is listed when `vault_lamports < floor(required *
/// critical_threshold_pct / 100)` — the boundary is exclusive: a vault
/// sitting *exactly* on the threshold is not critical. The threshold
/// percentage is clamped to `0..=100` (`0` lists nothing; `100` lists
/// every strictly-underfunded vault).
///
/// The listed `top_up_lamports` is `required - vault_lamports`: funding
/// exactly that amount restores the full rent-exempt minimum, so the
/// next scan shows the vault healthy. Only the initializer is named as
/// the funder — it funded the rent deposit at `initialize` time.
///
/// `Closed` vaults are skipped: the account no longer exists, so there is
/// no balance to measure and no top-up to perform.
pub fn scan_rent_health(
    watched: &[WatchedEscrowWithBalance],
    now: u64,
    critical_threshold_pct: u8,
) -> RentHealthReport {
    // AV-43: the canonical figure is the main formula — the same number
    // `initialize` funds and `close_vault` promises. Computed in u128:
    // `required * pct` cannot wrap (u128 is far larger than u64 * 100).
    let required = vault_close_rent_reclaimed();
    let pct = critical_threshold_pct.min(100);
    let critical_min = ((required as u128 * pct as u128) / 100) as u64;
    let mut top_ups = Vec::new();
    for w in watched {
        let e = &w.escrow;
        // A closed vault's account no longer exists — nothing to
        // measure, nothing to top up.
        if e.state() == EscrowState::Closed {
            continue;
        }
        // Exclusive boundary: exactly-at-threshold is not critical.
        // `critical_min <= required`, so a listed vault is always
        // strictly underfunded and `required - balance` never wraps.
        if w.vault_lamports < critical_min {
            top_ups.push(TopUpAction {
                escrow_id: w.escrow_id,
                state: rent_health_state_name(e.state()),
                vault_lamports: w.vault_lamports,
                required_lamports: required,
                top_up_lamports: required - w.vault_lamports,
                // The initializer is the canonical vault funder.
                caller: e.initializer(),
                caller_role: "initializer",
                reason: "underfunded",
            });
        }
    }
    RentHealthReport {
        at: now,
        scanned: watched.len(),
        required_lamports: required,
        critical_threshold_pct: pct,
        top_ups,
    }
}

#[cfg(test)]
mod rent_health_tests {
    use super::*;
    use crate::{
        check_vault_rent_exempt, vault_close_rent_reclaimed, RentShortfall,
        MAINNET_EXEMPTION_THRESHOLD_YEARS, MAINNET_LAMPORTS_PER_BYTE_YEAR,
    };

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const ID1: [u8; 32] = [0x01; 32];
    const ID2: [u8; 32] = [0x02; 32];
    const ID3: [u8; 32] = [0x03; 32];
    const AMOUNT: u64 = 1_000_000;
    const NOW: u64 = 1_750_000_000;
    const NEVER: u64 = u64::MAX; // no timeout
    const PCT: u8 = 90;

    fn watch(id: [u8; 32], escrow: Escrow, vault_lamports: u64) -> WatchedEscrowWithBalance {
        WatchedEscrowWithBalance {
            escrow_id: id,
            escrow,
            vault_lamports,
        }
    }

    fn funded() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER).unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    fn released() -> Escrow {
        let mut e = funded();
        e.release(ALICE, NOW, AMOUNT, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        e
    }

    fn closed() -> Escrow {
        let mut e = released();
        e.close_vault(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Closed);
        e
    }

    fn required() -> u64 {
        vault_close_rent_reclaimed()
    }

    fn critical_min(pct: u8) -> u64 {
        ((required() as u128 * pct as u128) / 100) as u64
    }

    fn hex_of(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn empty_input_scans_to_empty_report() {
        let report = scan_rent_health(&[], NOW, PCT);
        assert!(report.is_empty());
        assert_eq!(report.scanned, 0);
        assert_eq!(report.required_lamports, required());
        assert_eq!(report.critical_threshold_pct, PCT);
        let expected = format!(
            "{{\"at\":1750000000,\"scanned\":0,\"required_lamports\":{},\"critical_threshold_pct\":90,\"top_ups\":[]}}",
            required()
        );
        assert_eq!(report.to_json(), expected);
    }

    #[test]
    fn healthy_vault_at_or_above_required_is_not_listed() {
        // A vault carrying the full rent-exempt minimum (or more) is
        // healthy — the keeper lists nothing.
        let watched = [
            watch(ID1, funded(), required()),
            watch(ID2, funded(), required() + 1),
            watch(ID3, released(), u64::MAX),
        ];
        let report = scan_rent_health(&watched, NOW, PCT);
        assert!(report.is_empty(), "no top-up needed: {report:?}");
        assert_eq!(report.scanned, 3);
    }

    #[test]
    fn exact_at_threshold_vault_is_not_listed() {
        // The critical boundary is exclusive: a vault sitting exactly on
        // `floor(required * pct / 100)` is not critical.
        let balance = critical_min(PCT);
        assert!(balance < required(), "sanity: 90% < 100%");
        let watched = [watch(ID1, funded(), balance)];
        let report = scan_rent_health(&watched, NOW, PCT);
        assert!(
            report.is_empty(),
            "exact-at-threshold is not critical: {report:?}"
        );
    }

    #[test]
    fn just_below_threshold_lists_exact_top_up() {
        // One lamport below the threshold: listed, with the exact amount
        // to restore the full rent-exempt minimum.
        let balance = critical_min(PCT) - 1;
        let watched = [watch(ID1, funded(), balance)];
        let report = scan_rent_health(&watched, NOW, PCT);
        assert_eq!(report.top_ups.len(), 1);
        let t = report.top_ups[0];
        assert_eq!(t.escrow_id, ID1);
        assert_eq!(t.state, "funded");
        assert_eq!(t.vault_lamports, balance);
        assert_eq!(t.required_lamports, required());
        assert_eq!(
            t.top_up_lamports,
            required() - balance,
            "exact lamports to restore rent exemption"
        );
        assert_eq!(t.caller, ALICE);
        assert_eq!(t.caller_role, "initializer");
        assert_eq!(t.reason, "underfunded");
        // Funding the exact top-up restores health: the next scan is
        // clean at every threshold percentage.
        let restored = [watch(ID1, funded(), balance + t.top_up_lamports)];
        assert_eq!(restored[0].vault_lamports, required());
        for pct in [0u8, 50, 90, 100] {
            assert!(
                scan_rent_health(&restored, NOW, pct).is_empty(),
                "restored vault must be healthy at pct={pct}"
            );
        }
    }

    #[test]
    fn underfunded_vault_makes_close_economically_fail() {
        // The close boundary: `close_vault` promises `required` lamports
        // back to the initializer, but an eroded vault account only holds
        // `balance` — on-chain the `close` constraint transfers what the
        // account actually holds, so the close *economically* fails to
        // return the full rent. The keeper's top-up is exactly the
        // reclaim shortfall. At 100% threshold every strictly-underfunded
        // vault is listed — below `required` is critical by definition.
        let shortfall: u64 = 100_000;
        let balance = required() - shortfall;
        // Probe a copy for the close promise; the watched escrow stays
        // `Released` — the scan skips `Closed` vaults (their account no
        // longer exists).
        let mut probe = released();
        let promised = probe.close_vault(ALICE).unwrap();
        assert_eq!(promised, required(), "close_vault promises full rent");
        // The same balance fails the rent-exemption check `initialize`
        // runs — the scan measures against the main formula, exactly.
        assert_eq!(
            check_vault_rent_exempt(
                balance,
                MAINNET_LAMPORTS_PER_BYTE_YEAR,
                MAINNET_EXEMPTION_THRESHOLD_YEARS
            ),
            Err(RentShortfall {
                required: required(),
                provided: balance,
            })
        );
        let watched = [watch(ID1, released(), balance)];
        let report = scan_rent_health(&watched, NOW, 100);
        assert_eq!(report.top_ups.len(), 1);
        let t = report.top_ups[0];
        assert_eq!(t.state, "released");
        assert_eq!(
            t.top_up_lamports, shortfall,
            "top-up must equal the reclaim shortfall the initializer would suffer on close"
        );
        assert_eq!(t.vault_lamports + t.top_up_lamports, promised);
    }

    #[test]
    fn terminal_states_all_scanned_for_rent_health() {
        // A terminal vault still holds the rent deposit until it is
        // closed — rent erosion there matters just as much as on a live
        // vault.
        let mut cancelled = funded();
        cancelled.cancel(ALICE, None, ALICE).unwrap();
        let watched = [
            watch(ID1, cancelled, 0),
            watch(ID2, released(), 0),
        ];
        let report = scan_rent_health(&watched, NOW, PCT);
        assert_eq!(report.top_ups.len(), 2);
        assert_eq!(report.top_ups[0].state, "cancelled");
        assert_eq!(report.top_ups[1].state, "released");
        // A never-created vault account (balance 0) reports the full
        // `required` — exactly what `initialize` will demand.
        for t in &report.top_ups {
            assert_eq!(t.top_up_lamports, required());
        }
    }

    #[test]
    fn closed_vaults_are_skipped() {
        // The account no longer exists after close: no balance to
        // measure, no top-up to perform — even at zero lamports.
        let watched = [watch(ID1, closed(), 0)];
        let report = scan_rent_health(&watched, NOW, PCT);
        assert!(report.is_empty(), "closed vaults have no account: {report:?}");
        assert_eq!(report.scanned, 1);
    }

    #[test]
    fn threshold_pct_is_clamped_to_100() {
        // A percentage above 100 is meaningless: it behaves as 100 —
        // every strictly-underfunded vault is listed, nothing more.
        let watched = [
            watch(ID1, funded(), required() - 1),
            watch(ID2, funded(), required()),
        ];
        let report = scan_rent_health(&watched, NOW, 250);
        assert_eq!(report.critical_threshold_pct, 100);
        assert_eq!(report.top_ups.len(), 1);
        assert_eq!(report.top_ups[0].escrow_id, ID1);
        assert_eq!(report.top_ups[0].top_up_lamports, 1);
    }

    #[test]
    fn pct_zero_lists_nothing() {
        // A 0% threshold disables the scan: no balance can fall below 0.
        let watched = [watch(ID1, funded(), 0)];
        let report = scan_rent_health(&watched, NOW, 0);
        assert!(report.is_empty());
    }

    #[test]
    fn json_is_deterministic_and_pinned() {
        let balance = critical_min(PCT) - 7;
        let top_up = required() - balance;
        let watched = [watch(ID1, funded(), balance), watch(ID2, funded(), required())];
        let a = scan_rent_health(&watched, NOW, PCT).to_json();
        let b = scan_rent_health(&watched, NOW, PCT).to_json();
        assert_eq!(a, b, "equal input must serialize byte-identically");
        // Input order preserved: only ID1 is listed.
        let expected = format!(
            "{{\"at\":1750000000,\"scanned\":2,\"required_lamports\":{req},\"critical_threshold_pct\":90,\"top_ups\":[{{\"escrow_id\":\"{id}\",\"state\":\"funded\",\"vault_lamports\":{bal},\"required_lamports\":{req},\"top_up_lamports\":{top},\"caller\":\"{alice}\",\"caller_role\":\"initializer\",\"reason\":\"underfunded\"}}]}}",
            req = required(),
            id = hex_of(0x01),
            bal = balance,
            top = top_up,
            alice = hex_of(0xAA),
        );
        assert_eq!(a, expected, "pinned JSON shape");
    }

    #[test]
    fn scan_is_dry_run_and_preserves_input_order() {
        let before = [
            watch(ID1, funded(), critical_min(PCT) - 1),
            watch(ID2, funded(), required()),
            watch(ID3, released(), 0),
        ];
        let report = scan_rent_health(&before, NOW, PCT);
        // Zero side effects: the snapshots are bit-identical afterwards
        // (WatchedEscrowWithBalance is Copy + PartialEq, so this is
        // exact).
        assert_eq!(
            before,
            [
                watch(ID1, funded(), critical_min(PCT) - 1),
                watch(ID2, funded(), required()),
                watch(ID3, released(), 0),
            ]
        );
        assert_eq!(report.scanned, 3);
        // Input order preserved: ID1's top-up first, ID3's second.
        assert_eq!(report.top_ups.len(), 2);
        assert_eq!(report.top_ups[0].escrow_id, ID1);
        assert_eq!(report.top_ups[1].escrow_id, ID3);
    }

    #[test]
    fn listed_balance_always_fails_the_main_rent_formula() {
        // Cross-check: every listed vault fails `check_vault_rent_exempt`
        // with the mainnet parameters — the scan's notion of
        // "underfunded" is exactly the chain's notion of "not
        // rent-exempt".
        let balances = [
            0,
            1,
            critical_min(PCT) - 1,
            required() - 1,
        ];
        for (i, balance) in balances.iter().enumerate() {
            let watched = [watch([i as u8; 32], funded(), *balance)];
            let report = scan_rent_health(&watched, NOW, 100);
            assert_eq!(report.top_ups.len(), 1, "balance={balance}");
            assert_eq!(
                check_vault_rent_exempt(
                    *balance,
                    MAINNET_LAMPORTS_PER_BYTE_YEAR,
                    MAINNET_EXEMPTION_THRESHOLD_YEARS
                ),
                Err(RentShortfall {
                    required: required(),
                    provided: *balance,
                }),
                "listed balance must fail the main rent formula: {balance}"
            );
        }
    }
}
