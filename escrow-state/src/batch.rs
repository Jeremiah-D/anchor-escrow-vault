//! AV-37: batch lifecycle scan — one report emitting the executable
//! `initialize -> fund -> release` call list for many escrows, with
//! Address Lookup Table (ALT) support and per-item failure isolation.
//!
//! The keeper report (AV-20) covers the *reactive* exits
//! (`cancel_expired` / `claim`). A fleet operator also needs the
//! *proactive* lifecycle: bring up N new escrows (`initialize`), fund
//! the ones that are ready (`fund`), and sweep the funded ones
//! (`release`) — in one scan, as one executable call list.
//!
//! [`scan_batch_lifecycle`] takes a watch list where each item is
//! either a not-yet-created vault (with its initialize parameters) or
//! a live escrow snapshot, and returns, per item, exactly one of:
//!
//! - an executable [`BatchLifecycleAction`] (`initialize`, `fund`, or
//!   a full `release` of the remainder), with the exact arguments and
//!   the logical accounts the instruction needs;
//! - `Blocked { reason }` — the item is not executable *right now*
//!   (unsatisfied quorum, locked timelock, milestone plan attached,
//!   dual-signature activation pending, disputed, …). The reason is
//!   machine-readable; the operator fixes the item and re-scans;
//! - `Done` — a terminal state (`Released`, `Cancelled`, `Settled`,
//!   `Closed`): nothing to do, not a failure.
//!
//! # Partial-failure isolation
//!
//! The scan is pure reads over the snapshots: one item's outcome can
//! never affect another's. A blocked item is reported inline with its
//! reason while every executable item still gets its action — the
//! operator runs the executable calls and retries the blocked ones
//! later. There is no abort, no shared mutable state, no ordering
//! hazard.
//!
//! # Address Lookup Tables
//!
//! Every action lists its logical accounts (`vault`, `initializer`,
//! `taker`, `mint`) with `signer` / `writable` flags mirroring the
//! Anchor constraints. The report additionally builds `alt_table`: the
//! deduped set of every *non-signer* account referenced by any action,
//! in first-seen order, capped at 256 entries (the on-chain ALT
//! limit). Signers can never live in a lookup table, so they are
//! excluded by construction. Each account carries `alt_index` — its
//! index into `alt_table`, or `None` when the account is a signer or
//! the table was full. The operator creates (or extends) the ALT from
//! `alt_table` once, then references accounts by index in every
//! transaction — the standard fleet pattern for batch `initialize`
//! runs where dozens of vault PDAs would otherwise bloat every
//! transaction's account list.
//!
//! Like the keeper report, the scan is dry-run by construction: it
//! only reads the snapshots, emits no events, and touches no clock.
//! Amounts are as of the scan; the operator executes the list, then
//! re-scans.

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

/// Initialize parameters for a not-yet-created vault. Read only when
/// [`BatchWatchItem::escrow`] is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchInitializeParams {
    /// The key that will sign `initialize` (and later `fund`).
    pub initializer: [u8; 32],
    /// The counterparty.
    pub taker: [u8; 32],
    /// Locked amount in base units. Must be `> 0`.
    pub amount: u64,
    /// Unix-seconds expiry (`u64::MAX` = no timeout).
    pub expires_at: u64,
}

/// One watched item: either a vault to create or a live escrow to
/// advance. The scan never mutates the snapshot (dry-run).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchWatchItem {
    /// Caller-supplied 32-byte escrow identity (the vault PDA on-chain).
    pub escrow_id: [u8; 32],
    /// `None` = the vault does not exist yet: the scan lists an
    /// `initialize` call built from [`BatchWatchItem::initialize`].
    /// `Some` = the live escrow snapshot to advance.
    pub escrow: Option<Escrow>,
    /// Initialize parameters, used only when `escrow` is `None`.
    pub initialize: BatchInitializeParams,
}

/// Which lifecycle call a [`BatchLifecycleAction`] invokes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchActionKind {
    /// `initialize(initializer, taker, amount, expires_at)`.
    Initialize,
    /// `fund(initializer)`.
    Fund,
    /// `release(initializer, now, remaining, mint)` — always the full
    /// remainder; partial releases are an operator decision, not a
    /// batch default.
    Release,
}

impl BatchActionKind {
    fn as_str(&self) -> &'static str {
        match self {
            BatchActionKind::Initialize => "initialize",
            BatchActionKind::Fund => "fund",
            BatchActionKind::Release => "release",
        }
    }
}

/// One logical account of a batch action: the pubkey plus the role it
/// plays. `signer` / `writable` mirror the Anchor `#[derive(Accounts)]`
/// constraints the program enforces, so a submitter can translate them
/// directly into `AccountMeta`s (or ALT indexes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchAccount {
    /// The account's pubkey.
    pub pubkey: [u8; 32],
    /// Logical role: `"vault"`, `"initializer"`, `"taker"`, or `"mint"`.
    pub role: &'static str,
    /// Whether the account must sign. Signers are never ALT-eligible.
    pub signer: bool,
    /// Whether the instruction writes the account.
    pub writable: bool,
    /// Index into [`BatchReport::alt_table`] when this account is
    /// ALT-eligible (non-signer, table had room); `None` otherwise.
    pub alt_index: Option<u8>,
}

/// One executable lifecycle call: everything needed to build the
/// instruction, nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchLifecycleAction {
    /// Which escrow this call targets (the vault PDA).
    pub escrow_id: [u8; 32],
    /// Which lifecycle call to invoke.
    pub kind: BatchActionKind,
    /// The key that must sign the call (always the initializer for
    /// the `initialize -> fund -> release` lifecycle).
    pub caller: [u8; 32],
    /// Which role `caller` plays: always `"initializer"` here.
    pub caller_role: &'static str,
    /// The `mint` argument to pass: the escrow's bound mint, or `None`
    /// on the native-SOL path (`initialize` actions carry `None` — the
    /// mint is bound afterwards via `initialize_mint`).
    pub mint: Option<[u8; 32]>,
    /// `initialize`: the taker to pass; `None` for `fund` / `release`.
    pub taker: Option<[u8; 32]>,
    /// `initialize`: the `expires_at` to pass; `0` for `fund` /
    /// `release` (not applicable).
    pub expires_at: u64,
    /// `initialize` / `fund`: the locked amount. `release`: the gross
    /// remainder the call moves (`payout + fee == amount`).
    pub amount: u64,
    /// `release`: the taker's net payout (`amount - fee`); `0` for
    /// `initialize` / `fund`.
    pub payout: u64,
    /// `release`: the protocol fee sliced from the payout
    /// ([`Escrow::protocol_fee_for`]); `0` for `initialize` / `fund`.
    pub fee: u64,
    /// Logical accounts, in program-declared order.
    pub accounts: Vec<BatchAccount>,
    /// Machine-readable reason this call is listed: `"not_created"`,
    /// `"unfunded"`, or `"releasable"`.
    pub reason: &'static str,
}

/// The per-item outcome of the scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchItemOutcome {
    /// An executable call (see [`BatchLifecycleAction`]).
    Action(BatchLifecycleAction),
    /// Not executable right now. `reason` is machine-readable:
    /// `"invalid_amount"`, `"awaiting_activation"`,
    /// `"quorum_not_satisfied"`, `"timelock_not_reached"`,
    /// `"milestone_plan_attached"`, `"nothing_to_release"`, or
    /// `"disputed"`. Reported inline — it never affects other items.
    Blocked { reason: &'static str },
    /// Terminal state (`Released`, `Cancelled`, `Settled`, `Closed`):
    /// nothing to do, not a failure.
    Done,
}

/// One scanned item and its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchItem {
    /// Which escrow this outcome is for.
    pub escrow_id: [u8; 32],
    /// The scan's verdict for this item.
    pub outcome: BatchItemOutcome,
}

/// Maximum addresses in one on-chain Address Lookup Table. Accounts
/// past this cap get `alt_index: None` (listed directly).
const ALT_TABLE_CAP: usize = 256;

/// The scan result: the executable call list plus the ALT candidate
/// set, at [`BatchReport::at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchReport {
    /// The `now` (Unix seconds) the scan ran at.
    pub at: u64,
    /// How many items were scanned.
    pub scanned: usize,
    /// Per-item outcomes, in the input's order.
    pub items: Vec<BatchItem>,
    /// Deduped ALT candidate set: every non-signer account referenced
    /// by any action, in first-seen order, capped at
    /// [`ALT_TABLE_CAP`]. The operator creates (or extends) the ALT
    /// from this list once; each action's [`BatchAccount::alt_index`]
    /// points into it.
    pub alt_table: Vec<[u8; 32]>,
}

impl BatchReport {
    /// Number of executable actions in the report.
    pub fn action_count(&self) -> usize {
        self.items
            .iter()
            .filter(|i| matches!(i.outcome, BatchItemOutcome::Action(_)))
            .count()
    }

    /// Hand-serialized JSON (the crate is dependency-free).
    /// Deterministic field order; keys are 64-char lowercase hex.
    pub fn to_json(&self) -> String {
        fn hex_or_null(buf: &mut String, v: Option<[u8; 32]>) {
            match v {
                Some(b) => {
                    buf.push('"');
                    buf.push_str(&hex32(&b));
                    buf.push('"');
                }
                None => buf.push_str("null"),
            }
        }
        let mut s = String::with_capacity(256 + self.items.len() * 420);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"items\":[");
        for (i, item) in self.items.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&item.escrow_id));
            match &item.outcome {
                BatchItemOutcome::Action(a) => {
                    s.push_str("\",\"outcome\":\"action\",\"action\":\"");
                    s.push_str(a.kind.as_str());
                    s.push_str("\",\"caller\":\"");
                    s.push_str(&hex32(&a.caller));
                    s.push_str("\",\"caller_role\":\"");
                    s.push_str(a.caller_role);
                    s.push_str("\",\"mint\":");
                    hex_or_null(&mut s, a.mint);
                    s.push_str(",\"taker\":");
                    hex_or_null(&mut s, a.taker);
                    s.push_str(",\"expires_at\":");
                    s.push_str(&a.expires_at.to_string());
                    s.push_str(",\"amount\":");
                    s.push_str(&a.amount.to_string());
                    s.push_str(",\"payout\":");
                    s.push_str(&a.payout.to_string());
                    s.push_str(",\"fee\":");
                    s.push_str(&a.fee.to_string());
                    s.push_str(",\"accounts\":[");
                    for (j, acc) in a.accounts.iter().enumerate() {
                        if j > 0 {
                            s.push(',');
                        }
                        s.push_str("{\"pubkey\":\"");
                        s.push_str(&hex32(&acc.pubkey));
                        s.push_str("\",\"role\":\"");
                        s.push_str(acc.role);
                        s.push_str("\",\"signer\":");
                        s.push_str(if acc.signer { "true" } else { "false" });
                        s.push_str(",\"writable\":");
                        s.push_str(if acc.writable { "true" } else { "false" });
                        s.push_str(",\"alt_index\":");
                        match acc.alt_index {
                            Some(idx) => s.push_str(&idx.to_string()),
                            None => s.push_str("null"),
                        }
                        s.push('}');
                    }
                    s.push_str("],\"reason\":\"");
                    s.push_str(a.reason);
                    s.push_str("\"}");
                }
                BatchItemOutcome::Blocked { reason } => {
                    s.push_str("\",\"outcome\":\"blocked\",\"reason\":\"");
                    s.push_str(reason);
                    s.push_str("\"}");
                }
                BatchItemOutcome::Done => {
                    s.push_str("\",\"outcome\":\"done\"}");
                }
            }
        }
        s.push_str("],\"alt_table\":[");
        for (i, key) in self.alt_table.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('"');
            s.push_str(&hex32(key));
            s.push('"');
        }
        s.push_str("]}");
        s
    }
}

/// Scan `items` at `now` and return the executable `initialize ->
/// fund -> release` call list. Pure reads over the snapshots: zero
/// side effects, deterministic output in input order, per-item
/// failure isolation (see the module docs).
pub fn scan_batch_lifecycle(items: &[BatchWatchItem], now: u64) -> BatchReport {
    // First pass: per-item outcomes with accounts *before* ALT
    // indexes (the table is built from all actions first, so indexes
    // are stable regardless of item order).
    let mut outcomes: Vec<BatchItemOutcome> = Vec::with_capacity(items.len());
    for item in items {
        outcomes.push(scan_one(item, now));
    }
    // Second pass: build the ALT table (non-signer accounts, deduped,
    // first-seen order, capped) and stamp `alt_index` onto every
    // account of every action.
    let mut alt_table: Vec<[u8; 32]> = Vec::new();
    for outcome in &outcomes {
        if let BatchItemOutcome::Action(a) = outcome {
            for acc in &a.accounts {
                if acc.signer {
                    continue; // Signers can never live in a lookup table.
                }
                if !alt_table.contains(&acc.pubkey) && alt_table.len() < ALT_TABLE_CAP {
                    alt_table.push(acc.pubkey);
                }
            }
        }
    }
    let mut report_items = Vec::with_capacity(items.len());
    for (item, outcome) in items.iter().zip(outcomes.into_iter()) {
        let outcome = match outcome {
            BatchItemOutcome::Action(mut a) => {
                for acc in a.accounts.iter_mut() {
                    acc.alt_index = if acc.signer {
                        None
                    } else {
                        alt_table
                            .iter()
                            .position(|k| *k == acc.pubkey)
                            .map(|i| i as u8)
                    };
                }
                BatchItemOutcome::Action(a)
            }
            other => other,
        };
        report_items.push(BatchItem {
            escrow_id: item.escrow_id,
            outcome,
        });
    }
    BatchReport {
        at: now,
        scanned: items.len(),
        items: report_items,
        alt_table,
    }
}

/// The per-item verdict. `now` is only used for the `release`
/// executability gates (quorum / timelock are time-dependent).
fn scan_one(item: &BatchWatchItem, now: u64) -> BatchItemOutcome {
    let p = &item.initialize;
    let Some(e) = item.escrow else {
        // The vault does not exist yet: list the `initialize` call.
        if p.amount == 0 {
            return BatchItemOutcome::Blocked {
                reason: "invalid_amount",
            };
        }
        return BatchItemOutcome::Action(BatchLifecycleAction {
            escrow_id: item.escrow_id,
            kind: BatchActionKind::Initialize,
            caller: p.initializer,
            caller_role: "initializer",
            // The mint is bound afterwards via `initialize_mint`
            // (AV-16): `initialize` itself takes no mint argument.
            mint: None,
            taker: Some(p.taker),
            expires_at: p.expires_at,
            amount: p.amount,
            payout: 0,
            fee: 0,
            accounts: vec![
                BatchAccount {
                    pubkey: item.escrow_id,
                    role: "vault",
                    signer: false,
                    writable: true,
                    alt_index: None, // stamped in the second pass
                },
                BatchAccount {
                    pubkey: p.initializer,
                    role: "initializer",
                    signer: true,
                    writable: true,
                    alt_index: None,
                },
            ],
            reason: "not_created",
        });
    };
    match e.state() {
        EscrowState::Uninitialized => {
            // Dual-signature escrows fund only from `Activated`: one
            // party activating alone leaves the escrow `Uninitialized`,
            // and `fund` from there is `InvalidStateTransition` — the
            // operator must collect the second signature first.
            if e.dual_sig_required() && !(e.initializer_activated() && e.taker_activated()) {
                return BatchItemOutcome::Blocked {
                    reason: "awaiting_activation",
                };
            }
            BatchItemOutcome::Action(BatchLifecycleAction {
                escrow_id: item.escrow_id,
                kind: BatchActionKind::Fund,
                caller: e.initializer(),
                caller_role: "initializer",
                mint: None,
                taker: None,
                expires_at: 0,
                amount: e.amount(),
                payout: 0,
                fee: 0,
                accounts: vec![
                    BatchAccount {
                        pubkey: item.escrow_id,
                        role: "vault",
                        signer: false,
                        writable: true,
                        alt_index: None,
                    },
                    BatchAccount {
                        pubkey: e.initializer(),
                        role: "initializer",
                        signer: true,
                        writable: true,
                        alt_index: None,
                    },
                ],
                reason: "unfunded",
            })
        }
        // AV-12: dual-signature escrows reach `Activated` once both
        // parties recorded their signatures — `fund` is legal from
        // here (initializer-only, like the plain path).
        EscrowState::Activated => BatchItemOutcome::Action(BatchLifecycleAction {
            escrow_id: item.escrow_id,
            kind: BatchActionKind::Fund,
            caller: e.initializer(),
            caller_role: "initializer",
            mint: None,
            taker: None,
            expires_at: 0,
            amount: e.amount(),
            payout: 0,
            fee: 0,
            accounts: vec![
                BatchAccount {
                    pubkey: item.escrow_id,
                    role: "vault",
                    signer: false,
                    writable: true,
                    alt_index: None,
                },
                BatchAccount {
                    pubkey: e.initializer(),
                    role: "initializer",
                    signer: true,
                    writable: true,
                    alt_index: None,
                },
            ],
            reason: "unfunded",
        }),
        EscrowState::Funded => {
            let remaining = e.remaining_amount();
            // Defensive: a `Funded` escrow with nothing left cannot
            // happen (`release` flips to `Released` at full payout),
            // but the scan must never list a zero-amount release.
            if remaining == 0 {
                return BatchItemOutcome::Blocked {
                    reason: "nothing_to_release",
                };
            }
            // AV-15: a milestone plan owns the release schedule — plain
            // `release` would fail with `InvalidMilestones`.
            if e.milestone_plan().is_some() {
                return BatchItemOutcome::Blocked {
                    reason: "milestone_plan_attached",
                };
            }
            // The quorum gates `release`: an unsatisfied threshold
            // would fail with `QuorumNotReached`.
            if !e.quorum().map(|q| q.is_satisfied()).unwrap_or(true) {
                return BatchItemOutcome::Blocked {
                    reason: "quorum_not_satisfied",
                };
            }
            // AV-27: the timelock gates every taker payout path.
            if !e.is_unlock_eligible(now) {
                return BatchItemOutcome::Blocked {
                    reason: "timelock_not_reached",
                };
            }
            let fee = e.protocol_fee_for(remaining);
            let mut accounts = vec![
                BatchAccount {
                    pubkey: item.escrow_id,
                    role: "vault",
                    signer: false,
                    writable: true,
                    alt_index: None,
                },
                BatchAccount {
                    pubkey: e.initializer(),
                    role: "initializer",
                    signer: true,
                    writable: true,
                    alt_index: None,
                },
            ];
            if let Some(m) = e.mint() {
                accounts.push(BatchAccount {
                    pubkey: m,
                    role: "mint",
                    signer: false,
                    writable: false,
                    alt_index: None,
                });
            }
            BatchItemOutcome::Action(BatchLifecycleAction {
                escrow_id: item.escrow_id,
                kind: BatchActionKind::Release,
                caller: e.initializer(),
                caller_role: "initializer",
                mint: e.mint(),
                taker: None,
                expires_at: 0,
                amount: remaining,
                // `payout + fee == amount` by construction
                // (`protocol_fee_for` is `floor(amount * fee_bps /
                // 10_000) <= amount`).
                payout: remaining - fee,
                fee,
                accounts,
                reason: "releasable",
            })
        }
        // AV-14: unilateral exits are locked while disputed — and a
        // disputed escrow is not terminal either, so it is `Blocked`
        // (the arbiter's `resolve` is out of scope for the
        // `initialize -> fund -> release` lifecycle), not `Done`.
        EscrowState::Disputed => BatchItemOutcome::Blocked {
            reason: "disputed",
        },
        // Terminal states: nothing to do.
        EscrowState::Released
        | EscrowState::Cancelled
        | EscrowState::Settled
        | EscrowState::Closed => BatchItemOutcome::Done,
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use crate::{MilestonePlan, QuorumPolicy};

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const A1: [u8; 32] = [0xA1; 32];
    const A2: [u8; 32] = [0xA2; 32];
    const MINT: [u8; 32] = [0xD0; 32];
    const ID1: [u8; 32] = [0x01; 32];
    const ID2: [u8; 32] = [0x02; 32];
    const ID3: [u8; 32] = [0x03; 32];
    const AMOUNT: u64 = 1_000_000;
    const EXPIRES: u64 = 1_800_000_000;
    const NOW: u64 = 1_750_000_000;

    fn params() -> BatchInitializeParams {
        BatchInitializeParams {
            initializer: ALICE,
            taker: BOB,
            amount: AMOUNT,
            expires_at: EXPIRES,
        }
    }

    fn watch(id: [u8; 32], escrow: Option<Escrow>) -> BatchWatchItem {
        BatchWatchItem {
            escrow_id: id,
            escrow,
            initialize: params(),
        }
    }

    fn funded(amount: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, amount, EXPIRES).unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    fn hex_of(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    fn action_of(report: &BatchReport, id: [u8; 32]) -> &BatchLifecycleAction {
        let item = report
            .items
            .iter()
            .find(|i| i.escrow_id == id)
            .expect("item missing from report");
        match &item.outcome {
            BatchItemOutcome::Action(a) => a,
            other => panic!("expected an action for {id:?}, got {other:?}"),
        }
    }

    fn blocked_reason(report: &BatchReport, id: [u8; 32]) -> &'static str {
        let item = report
            .items
            .iter()
            .find(|i| i.escrow_id == id)
            .expect("item missing from report");
        match &item.outcome {
            BatchItemOutcome::Blocked { reason } => reason,
            other => panic!("expected blocked for {id:?}, got {other:?}"),
        }
    }

    #[test]
    fn missing_vault_lists_initialize_with_exact_args() {
        let report = scan_batch_lifecycle(&[watch(ID1, None)], NOW);
        assert_eq!(report.scanned, 1);
        assert_eq!(report.action_count(), 1);
        let a = action_of(&report, ID1);
        assert_eq!(a.kind, BatchActionKind::Initialize);
        assert_eq!(a.caller, ALICE);
        assert_eq!(a.caller_role, "initializer");
        assert_eq!(a.mint, None);
        assert_eq!(a.taker, Some(BOB));
        assert_eq!(a.expires_at, EXPIRES);
        assert_eq!(a.amount, AMOUNT);
        assert_eq!(a.payout, 0);
        assert_eq!(a.fee, 0);
        assert_eq!(a.reason, "not_created");
        assert_eq!(a.accounts.len(), 2);
        assert_eq!(a.accounts[0].role, "vault");
        assert_eq!(a.accounts[0].pubkey, ID1);
        assert!(!a.accounts[0].signer && a.accounts[0].writable);
        assert_eq!(a.accounts[1].role, "initializer");
        assert!(a.accounts[1].signer);
    }

    #[test]
    fn zero_amount_initialize_is_blocked_not_listed() {
        let mut item = watch(ID1, None);
        item.initialize.amount = 0;
        let report = scan_batch_lifecycle(&[item], NOW);
        assert_eq!(report.action_count(), 0);
        assert_eq!(blocked_reason(&report, ID1), "invalid_amount");
        // The ALT table stays empty: a blocked item contributes no accounts.
        assert!(report.alt_table.is_empty());
    }

    #[test]
    fn uninitialized_escrow_lists_fund() {
        let e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES).unwrap();
        let report = scan_batch_lifecycle(&[watch(ID1, Some(e))], NOW);
        let a = action_of(&report, ID1);
        assert_eq!(a.kind, BatchActionKind::Fund);
        assert_eq!(a.caller, ALICE);
        assert_eq!(a.amount, AMOUNT);
        assert_eq!(a.reason, "unfunded");
    }

    #[test]
    fn dual_sig_pending_activation_is_blocked_but_activated_funds() {
        // Only the initializer activated: `fund` would fail with
        // `InvalidStateTransition` — the scan reports it instead of
        // listing a doomed call.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES)
            .unwrap()
            .with_dual_sig()
            .unwrap();
        e.activate(ALICE).unwrap();
        let report = scan_batch_lifecycle(&[watch(ID1, Some(e))], NOW);
        assert_eq!(blocked_reason(&report, ID1), "awaiting_activation");
        // Both parties activated: `fund` is executable.
        let mut e2 = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES)
            .unwrap()
            .with_dual_sig()
            .unwrap();
        e2.activate(ALICE).unwrap();
        e2.activate(BOB).unwrap();
        assert_eq!(e2.state(), EscrowState::Activated);
        let report = scan_batch_lifecycle(&[watch(ID2, Some(e2))], NOW);
        assert_eq!(action_of(&report, ID2).kind, BatchActionKind::Fund);
    }

    #[test]
    fn funded_escrow_lists_full_release_with_fee_split() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES)
            .unwrap()
            .with_protocol_fee(100)
            .unwrap()
            .with_mint(MINT)
            .unwrap();
        e.fund(ALICE).unwrap();
        // Partial plain release first: the batch releases the remainder.
        e.release(ALICE, NOW, 400_000, Some(MINT), BOB).unwrap();
        let report = scan_batch_lifecycle(&[watch(ID1, Some(e))], NOW);
        let a = action_of(&report, ID1);
        assert_eq!(a.kind, BatchActionKind::Release);
        assert_eq!(a.caller, ALICE);
        assert_eq!(a.mint, Some(MINT));
        assert_eq!(a.amount, 600_000);
        // 1% of 600_000 = 6_000 fee; payout + fee == amount.
        assert_eq!(a.fee, 6_000);
        assert_eq!(a.payout, 594_000);
        assert_eq!(a.payout + a.fee, a.amount);
        assert_eq!(a.reason, "releasable");
        // The mint account is listed (readonly) for the SPL path.
        assert_eq!(a.accounts.len(), 3);
        assert_eq!(a.accounts[2].role, "mint");
        assert_eq!(a.accounts[2].pubkey, MINT);
        assert!(!a.accounts[2].signer && !a.accounts[2].writable);
    }

    #[test]
    fn funded_escrow_with_blockers_reports_each_reason() {
        // Unsatisfied quorum.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES)
            .unwrap()
            .with_quorum(QuorumPolicy::new(&[A1, A2], &[1, 1], 2).unwrap())
            .unwrap();
        e.fund(ALICE).unwrap();
        e.attest(A1).unwrap(); // 1 of 2
        // Locked timelock.
        let mut e2 = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES)
            .unwrap()
            .with_timelock(NOW + 1_000)
            .unwrap();
        e2.fund(ALICE).unwrap();
        // Milestone plan attached (plain `release` disabled).
        let mut e3 = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap();
        e3.fund(ALICE).unwrap();
        let report = scan_batch_lifecycle(
            &[watch(ID1, Some(e)), watch(ID2, Some(e2)), watch(ID3, Some(e3))],
            NOW,
        );
        assert_eq!(report.action_count(), 0);
        assert_eq!(blocked_reason(&report, ID1), "quorum_not_satisfied");
        assert_eq!(blocked_reason(&report, ID2), "timelock_not_reached");
        assert_eq!(blocked_reason(&report, ID3), "milestone_plan_attached");
    }

    #[test]
    fn disputed_is_blocked_and_terminal_is_done() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES)
            .unwrap()
            .with_arbiter([0xA8; 32])
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(ALICE, NOW, None).unwrap();
        let mut e2 = funded(AMOUNT);
        e2.release(ALICE, NOW, AMOUNT, None, BOB).unwrap();
        assert_eq!(e2.state(), EscrowState::Released);
        let mut e3 = funded(AMOUNT);
        e3.cancel(ALICE, None, ALICE).unwrap();
        let report = scan_batch_lifecycle(
            &[watch(ID1, Some(e)), watch(ID2, Some(e2)), watch(ID3, Some(e3))],
            NOW,
        );
        assert_eq!(blocked_reason(&report, ID1), "disputed");
        for id in [ID2, ID3] {
            let item = report.items.iter().find(|i| i.escrow_id == id).unwrap();
            assert_eq!(item.outcome, BatchItemOutcome::Done);
        }
        assert_eq!(report.action_count(), 0);
    }

    #[test]
    fn partial_failure_isolation_other_items_still_listed() {
        // One blocked item (unsatisfied quorum) must not affect the
        // executable items around it — input order preserved.
        let mut blocked = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES)
            .unwrap()
            .with_quorum(QuorumPolicy::new(&[A1, A2], &[1, 1], 2).unwrap())
            .unwrap();
        blocked.fund(ALICE).unwrap();
        let items = [
            watch(ID1, None),            // -> initialize
            watch(ID2, Some(blocked)),   // -> blocked
            watch(ID3, Some(funded(AMOUNT))), // -> release
        ];
        let report = scan_batch_lifecycle(&items, NOW);
        assert_eq!(report.scanned, 3);
        assert_eq!(report.action_count(), 2);
        assert_eq!(action_of(&report, ID1).kind, BatchActionKind::Initialize);
        assert_eq!(blocked_reason(&report, ID2), "quorum_not_satisfied");
        assert_eq!(action_of(&report, ID3).kind, BatchActionKind::Release);
        // Input order preserved in the report.
        assert_eq!(report.items[0].escrow_id, ID1);
        assert_eq!(report.items[1].escrow_id, ID2);
        assert_eq!(report.items[2].escrow_id, ID3);
    }

    #[test]
    fn alt_table_dedups_non_signers_and_excludes_signers() {
        // Two releases sharing the same mint: the mint appears once in
        // the table; both actions index it. The shared initializer is
        // a signer — never in the table.
        let mut e1 = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES)
            .unwrap()
            .with_mint(MINT)
            .unwrap();
        e1.fund(ALICE).unwrap();
        let mut e2 = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES)
            .unwrap()
            .with_mint(MINT)
            .unwrap();
        e2.fund(ALICE).unwrap();
        let report = scan_batch_lifecycle(&[watch(ID1, Some(e1)), watch(ID2, Some(e2))], NOW);
        // First-seen order: ID1 (vault), MINT, ID2 (vault).
        assert_eq!(report.alt_table, vec![ID1, MINT, ID2]);
        for id in [ID1, ID2] {
            let a = action_of(&report, id);
            // vault -> its own index, initializer -> None (signer),
            // mint -> shared index 1.
            assert_eq!(a.accounts[0].alt_index, report.alt_table.iter().position(|k| *k == id).map(|i| i as u8));
            assert_eq!(a.accounts[1].alt_index, None, "signers are never ALT-eligible");
            assert_eq!(a.accounts[2].alt_index, Some(1));
        }
    }

    #[test]
    fn scan_is_dry_run() {
        let e = funded(AMOUNT);
        let items = [watch(ID1, Some(e)), watch(ID2, None)];
        let before = items;
        let report = scan_batch_lifecycle(&items, NOW);
        assert_eq!(items, before, "scan mutated its input");
        assert_eq!(report.at, NOW);
        assert_eq!(report.scanned, 2);
    }

    #[test]
    fn json_shape_is_pinned() {
        let report = scan_batch_lifecycle(&[watch(ID1, None)], NOW);
        let json = report.to_json();
        let expected = format!(
            "{{\"at\":1750000000,\"scanned\":1,\"items\":[{{\"escrow_id\":\"{}\",\"outcome\":\"action\",\"action\":\"initialize\",\"caller\":\"{}\",\"caller_role\":\"initializer\",\"mint\":null,\"taker\":\"{}\",\"expires_at\":1800000000,\"amount\":1000000,\"payout\":0,\"fee\":0,\"accounts\":[{{\"pubkey\":\"{}\",\"role\":\"vault\",\"signer\":false,\"writable\":true,\"alt_index\":0}},{{\"pubkey\":\"{}\",\"role\":\"initializer\",\"signer\":true,\"writable\":true,\"alt_index\":null}}],\"reason\":\"not_created\"}}],\"alt_table\":[\"{}\"]}}",
            hex_of(0x01),
            hex_of(0xAA),
            hex_of(0xBB),
            hex_of(0x01),
            hex_of(0xAA),
            hex_of(0x01),
        );
        assert_eq!(json, expected);
    }

    #[test]
    fn json_blocked_and_done_shapes() {
        let mut e = funded(AMOUNT);
        e.release(ALICE, NOW, AMOUNT, None, BOB).unwrap();
        let report = scan_batch_lifecycle(
            &[watch(ID1, Some(e))],
            NOW,
        );
        let json = report.to_json();
        assert!(
            json.contains(&format!(
                "{{\"escrow_id\":\"{}\",\"outcome\":\"done\"}}",
                hex_of(0x01)
            )),
            "done shape wrong: {json}"
        );
        assert!(json.ends_with("\"alt_table\":[]}"), "no accounts, no table: {json}");
    }
}
