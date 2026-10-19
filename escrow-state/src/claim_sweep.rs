//! Batch claim sweep (AV-146): one keeper pass sweeping the `claim`
//! calls for many ready vaults (`claim_many` semantics).
//!
//! [`scan_keeper_actions`](crate::scan_keeper_actions) (AV-20) lists
//! every executable keeper call; a keeper bot servicing a large
//! vesting fleet then faces a packing problem — which claims fit in
//! one signing run, and which lookup-table entries the batch needs.
//! [`plan_claim_sweep`] answers it: it walks the same watch list,
//! keeps exactly the vaults the keeper scan would list for `claim`
//! (the
//! [`claim_action_for`](crate::keeper::claim_action_for)
//! single truth source — the sweep never lists a claim the scan would
//! not), and packs them into sweeps:
//!
//! 1. **Deterministic vault order.** Vaults sort by `escrow_id`, so a
//!    stable watch list yields a stable sweep plan.
//! 2. **CU budgeting (AV-88, AV-145).** Each vault's claim carries its
//!    AV-88 compute-unit estimate; vaults accumulate into a sweep
//!    until the next would push it past
//!    [`CU_MAX_PER_TRANSACTION`](crate::cu_estimate::CU_MAX_PER_TRANSACTION)
//!    (1.4M) — then a new sweep starts (the automatic split, the AV-145
//!    merge convention). A vault alone over budget keeps its own
//!    sweep, flagged `over_budget`, never dropped.
//! 3. **Cross-vault ALT dedup (batch.rs AV-37 convention).** Each
//!    sweep builds one deduped lookup set — non-signer accounts only,
//!    first-seen order, capped at 256 — with per-account `alt_index`
//!    remapping, so the operator extends a single on-chain ALT per
//!    sweep. An account outside the cap renders `alt_index: None` and
//!    travels as a static account meta — never a dangling index.
//! 4. **Per-vault outcomes.** Every watched vault appears in the
//!    report's `results`: `swept` (with the `sweep_id`), `skipped`
//!    (with the machine-readable reason — the keeper predicate's
//!    conjuncts, in check order), or `failed` (a missing CU-table row
//!    — the AV-88 table covers every keeper instruction kind, so this
//!    is defensive, never silent).
//!
//! # Dry-run by construction
//!
//! Like the scan: [`plan_claim_sweep`] only reads `&Escrow`
//! snapshots, emits no events, touches no clock, and mutates nothing.
//! Amounts are as of the scan's `now` — the operator submits the
//! sweeps, then re-scans.
//!
//! # Output
//!
//! [`ClaimSweepReport::to_json`] hand-serializes the report (the crate
//! is dependency-free): deterministic field order, keys as 64-char
//! lowercase hex, `mint` as a hex string or `null`. Sweeps keep the
//! deterministic vault order, ALT tables keep first-seen order, and
//! results sort by `escrow_id`.

use crate::keeper::{claim_action_for, KeeperAction, WatchedEscrow};
use crate::{format_amount, Escrow};
use crate::cu_estimate::CU_MAX_PER_TRANSACTION;

/// ALT table cap — the batch.rs AV-37 convention (`alt_table`:
/// deduped non-signer accounts, first-seen order, capped at 256).
const ALT_TABLE_CAP: usize = 256;

/// Why a vault did not make it into a sweep, as a
/// machine-readable string on [`VaultClaimResult::reason`].
///
/// Skip reasons mirror [`claim_eligible`](crate::keeper::claim_eligible)'s
/// conjuncts in check order, so the first failing conjunct names the
/// outcome — a skipped vault is exactly a vault the keeper scan would
/// not list for `claim`.
pub mod skip_reason {
    /// No vesting schedule and no Dutch auction attached — there is
    /// no `claim` pricing curve on this vault.
    pub const NO_VESTING_SCHEDULE: &str = "no_vesting_schedule";
    /// A milestone plan is attached — the plan owns the release
    /// schedule and disables `claim`.
    pub const MILESTONE_PLAN_ATTACHED: &str = "milestone_plan_attached";
    /// Nothing is priced-but-unreleased at the scan time
    /// (`claimable_amount(now) == 0`).
    pub const NOTHING_CLAIMABLE: &str = "nothing_claimable";
    /// A quorum is configured and not yet satisfied.
    pub const QUORUM_NOT_SATISFIED: &str = "quorum_not_satisfied";
    /// The timelock (AV-27) has not unlocked yet.
    pub const TIMELOCK_LOCKED: &str = "timelock_locked";
}

/// Why a vault's sweep item failed to plan, as a machine-readable
/// string on [`VaultClaimResult::reason`].
pub mod fail_reason {
    /// The AV-88 CU table has no row for the claim instruction, so the
    /// vault cannot be budgeted. Defensive: the cu_estimate tests pin
    /// coverage of every keeper instruction kind, so this is
    /// unreachable on real plans — the per-vault `failed` outcome
    /// exists so a missing row is loud, never silently estimated as
    /// zero (the AV-88 convention).
    pub const CU_ESTIMATE_UNAVAILABLE: &str = "cu_estimate_unavailable";
}

/// The per-vault outcome inside a [`ClaimSweepReport`]'s `results`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultClaimOutcome {
    /// The vault's `claim` was packed into a sweep.
    Swept,
    /// The vault is not claim-eligible — see
    /// [`VaultClaimResult::reason`].
    Skipped,
    /// The vault's sweep item could not be planned — see
    /// [`VaultClaimResult::reason`].
    Failed,
}

impl VaultClaimOutcome {
    fn as_str(&self) -> &'static str {
        match self {
            VaultClaimOutcome::Swept => "swept",
            VaultClaimOutcome::Skipped => "skipped",
            VaultClaimOutcome::Failed => "failed",
        }
    }
}

/// One account on a sweep item's `claim` instruction: `vault` (the
/// vault PDA, non-signer writable), `caller` (the taker, signer), and
/// `mint` (the bound SPL mint, non-signer readonly, only when the
/// escrow binds one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimSweepAccount {
    /// The account's pubkey.
    pub pubkey: [u8; 32],
    /// `"vault"`, `"caller"`, or `"mint"`.
    pub role: &'static str,
    /// Signers are never ALT-eligible (batch.rs convention).
    pub signer: bool,
    /// Whether the instruction writes the account.
    pub writable: bool,
    /// Index into the sweep's [`ClaimSweep::alt_table`] when the
    /// account is ALT-eligible; `None` for signers and for accounts
    /// outside the 256-entry cap.
    pub alt_index: Option<u8>,
}

/// One vault's packed `claim`: the exact keeper action the scan
/// would list, its AV-88 CU estimate, and its instruction accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimSweepItem {
    /// Which vault this item claims from.
    pub escrow_id: [u8; 32],
    /// The keeper `claim` action (identical to the scan's listing).
    pub action: KeeperAction,
    /// The AV-88 compute-unit estimate for this claim.
    pub estimated_cu: u64,
    /// The claim instruction's accounts (roles + ALT indexes).
    pub accounts: Vec<ClaimSweepAccount>,
}

/// One sweep: the claims to execute in a single signing run, their
/// merged ALT table, and the CU budget line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimSweep {
    /// Stable within one plan: `"sweep-0"`, `"sweep-1"`, … in
    /// deterministic vault order.
    pub sweep_id: String,
    /// The sweep's claims, in deterministic vault order.
    pub items: Vec<ClaimSweepItem>,
    /// The cross-vault deduped ALT table (batch.rs convention).
    pub alt_table: Vec<[u8; 32]>,
    /// Σ estimated compute units across the sweep's claims.
    pub total_cu: u64,
    /// True when the sweep alone exceeds
    /// [`CU_MAX_PER_TRANSACTION`](crate::cu_estimate::CU_MAX_PER_TRANSACTION)
    /// — a single claim larger than one transaction; the operator must
    /// split it by hand (the sweep never silently drops a claim to
    /// fit).
    pub over_budget: bool,
}

impl ClaimSweep {
    /// Number of claims in the sweep.
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Deterministic JSON for one sweep.
    fn to_json(&self) -> String {
        let mut s = String::with_capacity(128 + self.items.len() * 560);
        s.push_str("{\"sweep_id\":\"");
        s.push_str(&self.sweep_id);
        s.push_str("\",\"total_cu\":");
        s.push_str(&self.total_cu.to_string());
        s.push_str(",\"over_budget\":");
        s.push_str(if self.over_budget { "true" } else { "false" });
        s.push_str(",\"items\":[");
        for (i, item) in self.items.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let a = &item.action;
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&item.escrow_id));
            s.push_str("\",\"action\":\"claim\",\"caller\":\"");
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
            // AV-28: the human-unit rendering rides the item, like the
            // keeper report's `display_amount`.
            s.push_str(",\"decimals\":");
            s.push_str(&a.decimals.to_string());
            s.push_str(",\"display_amount\":\"");
            s.push_str(&format_amount(a.amount, a.decimals));
            s.push_str("\",\"reason\":\"");
            s.push_str(a.reason);
            s.push_str("\",\"estimated_cu\":");
            s.push_str(&item.estimated_cu.to_string());
            s.push_str(",\"accounts\":[");
            for (j, acc) in item.accounts.iter().enumerate() {
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
            s.push_str("]}");
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

/// One watched vault's outcome in the sweep plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultClaimResult {
    /// Which vault this result is for.
    pub escrow_id: [u8; 32],
    /// Whether the vault was swept, skipped, or failed to plan.
    pub outcome: VaultClaimOutcome,
    /// `Some` on `swept` — the sweep that packed this vault's claim.
    /// `None` on `skipped` / `failed`.
    pub sweep_id: Option<String>,
    /// `Some` on `skipped` / `failed` — the machine-readable reason
    /// (see [`skip_reason`] / [`fail_reason`]). `None` on `swept`.
    pub reason: Option<&'static str>,
}

impl VaultClaimResult {
    /// Deterministic JSON for one result.
    fn to_json(&self) -> String {
        let mut s = String::with_capacity(160);
        s.push_str("{\"escrow_id\":\"");
        s.push_str(&hex32(&self.escrow_id));
        s.push_str("\",\"outcome\":\"");
        s.push_str(self.outcome.as_str());
        s.push('"');
        match &self.sweep_id {
            Some(id) => {
                s.push_str(",\"sweep_id\":\"");
                s.push_str(id);
                s.push('"');
            }
            None => s.push_str(",\"sweep_id\":null"),
        }
        match self.reason {
            Some(r) => {
                s.push_str(",\"reason\":\"");
                s.push_str(r);
                s.push('"');
            }
            None => s.push_str(",\"reason\":null"),
        }
        s.push('}');
        s
    }
}

/// The sweep plan: every watched vault's outcome plus the packed
/// sweeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimSweepReport {
    /// The `now` (Unix seconds) the plan ran at.
    pub at: u64,
    /// How many escrows were scanned.
    pub scanned: usize,
    /// The packed sweeps, in deterministic vault order.
    pub sweeps: Vec<ClaimSweep>,
    /// One result per watched vault, sorted by `escrow_id`.
    pub results: Vec<VaultClaimResult>,
    /// Σ estimated compute units across the sweeps' claims.
    pub total_cu: u64,
}

impl ClaimSweepReport {
    /// True when no vault was claim-eligible.
    pub fn is_empty(&self) -> bool {
        self.sweeps.is_empty()
    }

    /// Hand-serialized JSON (the crate is dependency-free).
    /// Deterministic field order; keys are 64-char lowercase hex;
    /// `mint` is a hex string or `null`. Sweeps keep the
    /// deterministic vault order, ALT tables keep first-seen order,
    /// and results sort by `escrow_id` — two plans over the same
    /// watch list at the same `now` are byte-identical.
    ///
    /// ```json
    /// {"at":1750000000,"scanned":3,"total_cu":27628,"sweeps":[
    ///   {"sweep_id":"sweep-0","total_cu":27628,"over_budget":false,
    ///    "items":[
    ///     {"escrow_id":"...","action":"claim","caller":"...",
    ///      "caller_role":"taker","mint":null,"amount":500000,
    ///      "decimals":6,"display_amount":"0.500000",
    ///      "reason":"vesting_unlocked","estimated_cu":13814,
    ///      "accounts":[
    ///       {"pubkey":"...","role":"vault","signer":false,
    ///        "writable":true,"alt_index":0},
    ///       {"pubkey":"...","role":"caller","signer":true,
    ///        "writable":true,"alt_index":null}]},
    ///    ...],
    ///    "alt_table":["..."]}],
    ///  "results":[
    ///   {"escrow_id":"...","outcome":"swept","sweep_id":"sweep-0",
    ///    "reason":null},
    ///   {"escrow_id":"...","outcome":"skipped","sweep_id":null,
    ///    "reason":"nothing_claimable"}]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(128 + self.sweeps.len() * 700);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"total_cu\":");
        s.push_str(&self.total_cu.to_string());
        s.push_str(",\"sweeps\":[");
        for (i, sweep) in self.sweeps.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&sweep.to_json());
        }
        s.push_str("],\"results\":[");
        for (i, r) in self.results.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&r.to_json());
        }
        s.push_str("]}");
        s
    }
}

/// Render 32 bytes as 64 lowercase hex characters (the crate
/// convention, local copy).
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// The machine-readable skip reason for a vault the keeper's `claim`
/// predicate rejects — the predicate's conjuncts in check order, so
/// the first failing conjunct names the outcome. Only called when
/// [`claim_action_for`] returned `None`, so exactly one conjunct
/// fails and the trailing branch is the timelock by elimination.
fn claim_skip_reason(e: &Escrow, now: u64) -> &'static str {
    if e.vesting_schedule().is_none() && e.auction().is_none() {
        skip_reason::NO_VESTING_SCHEDULE
    } else if e.milestone_plan().is_some() {
        skip_reason::MILESTONE_PLAN_ATTACHED
    } else if e.claimable_amount(now) == 0 {
        skip_reason::NOTHING_CLAIMABLE
    } else if !e.quorum().map(|q| q.is_satisfied()).unwrap_or(true) {
        skip_reason::QUORUM_NOT_SATISFIED
    } else {
        skip_reason::TIMELOCK_LOCKED
    }
}

/// The `claim` instruction's accounts for one sweep item: the vault
/// PDA (the precomputed AV-92 address when recorded, else the
/// watch entry's identity — the Anchor layer keys the vault off it),
/// the taker signer, and the bound mint when set.
fn claim_accounts(action: &KeeperAction) -> Vec<ClaimSweepAccount> {
    let vault = action.vault_address.unwrap_or(action.escrow_id);
    let mut accounts = vec![
        ClaimSweepAccount {
            pubkey: vault,
            role: "vault",
            signer: false,
            writable: true,
            alt_index: None,
        },
        ClaimSweepAccount {
            pubkey: action.caller,
            role: "caller",
            signer: true,
            writable: true,
            alt_index: None,
        },
    ];
    if let Some(mint) = action.mint {
        accounts.push(ClaimSweepAccount {
            pubkey: mint,
            role: "mint",
            signer: false,
            writable: false,
            alt_index: None,
        });
    }
    accounts
}

/// Plan the batch claim sweep over `watched` at `now`.
///
/// Vaults sort by `escrow_id` (deterministic); each claim-eligible
/// vault's action accumulates into the open sweep until the next
/// claim would push it past
/// [`CU_MAX_PER_TRANSACTION`](crate::cu_estimate::CU_MAX_PER_TRANSACTION),
/// at which point a new sweep starts (the AV-145 automatic split). A
/// vault alone over budget keeps its own sweep, flagged
/// `over_budget`, never dropped.
///
/// Pure read — the input is borrowed, nothing mutates, no events, no
/// clock access beyond the caller-supplied `now`.
pub fn plan_claim_sweep(watched: &[WatchedEscrow], now: u64) -> ClaimSweepReport {
    // Deterministic vault order: escrow_id ascending.
    let mut order: Vec<&WatchedEscrow> = watched.iter().collect();
    order.sort_by_key(|w| w.escrow_id);

    let mut sweeps: Vec<ClaimSweep> = Vec::new();
    let mut results: Vec<VaultClaimResult> = Vec::new();
    let mut open: Option<ClaimSweep> = None;

    let mut new_sweep = |id: usize| ClaimSweep {
        sweep_id: format!("sweep-{id}"),
        items: Vec::new(),
        alt_table: Vec::new(),
        total_cu: 0,
        over_budget: false,
    };

    for w in order {
        let escrow_id = w.escrow_id;
        match claim_action_for(w, now) {
            None => results.push(VaultClaimResult {
                escrow_id,
                outcome: VaultClaimOutcome::Skipped,
                sweep_id: None,
                reason: Some(claim_skip_reason(&w.escrow, now)),
            }),
            Some(action) => match action.estimated_compute_units_opt() {
                None => results.push(VaultClaimResult {
                    escrow_id,
                    outcome: VaultClaimOutcome::Failed,
                    sweep_id: None,
                    reason: Some(fail_reason::CU_ESTIMATE_UNAVAILABLE),
                }),
                Some(cu) => {
                    let need_new = match &open {
                        // A sweep always takes at least one claim — a
                        // claim alone over budget still gets its own
                        // sweep (flagged `over_budget`), never
                        // dropped (the AV-145 merge convention).
                        Some(s) => {
                            !s.items.is_empty()
                                && s.total_cu.saturating_add(cu) > CU_MAX_PER_TRANSACTION
                        }
                        None => true,
                    };
                    if need_new {
                        if let Some(s) = open.take() {
                            sweeps.push(finalize_sweep(s));
                        }
                        open = Some(new_sweep(sweeps.len()));
                    }
                    let s = open.as_mut().unwrap();
                    let sweep_id = s.sweep_id.clone();
                    s.total_cu = s.total_cu.saturating_add(cu);
                    s.items.push(ClaimSweepItem {
                        escrow_id,
                        action,
                        estimated_cu: cu,
                        accounts: claim_accounts(&action),
                    });
                    results.push(VaultClaimResult {
                        escrow_id,
                        outcome: VaultClaimOutcome::Swept,
                        sweep_id: Some(sweep_id),
                        reason: None,
                    });
                }
            },
        }
    }
    if let Some(s) = open.take() {
        sweeps.push(finalize_sweep(s));
    }
    // Results sort by escrow_id — the same order the sweeps packed,
    // so the report is input-order independent.
    results.sort_by_key(|r| r.escrow_id);
    let total_cu = sweeps
        .iter()
        .map(|s| s.total_cu)
        .fold(0u64, |a, b| a.saturating_add(b));
    ClaimSweepReport {
        at: now,
        scanned: watched.len(),
        sweeps,
        results,
        total_cu,
    }
}

/// Finish a sweep: build the cross-vault deduped ALT table, remap
/// `alt_index`, and flag over-budget sweeps.
fn finalize_sweep(mut sweep: ClaimSweep) -> ClaimSweep {
    // Cross-vault dedup (batch.rs AV-37 convention): non-signer
    // accounts only, first-seen order, capped at 256.
    let mut alt_table: Vec<[u8; 32]> = Vec::new();
    for item in &sweep.items {
        for acc in &item.accounts {
            if acc.signer {
                continue;
            }
            if !alt_table.contains(&acc.pubkey) && alt_table.len() < ALT_TABLE_CAP {
                alt_table.push(acc.pubkey);
            }
        }
    }
    // Remap every item's `alt_index` into the merged table. An
    // account outside the cap (table full) renders `None` and
    // travels as a static account meta — never a dangling index.
    for item in &mut sweep.items {
        for acc in &mut item.accounts {
            if acc.signer {
                acc.alt_index = None;
            } else {
                acc.alt_index = alt_table
                    .iter()
                    .position(|k| *k == acc.pubkey)
                    .and_then(|i| u8::try_from(i).ok());
            }
        }
    }
    sweep.alt_table = alt_table;
    sweep.over_budget = sweep.total_cu > CU_MAX_PER_TRANSACTION;
    sweep
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod claim_sweep_tests {
    use super::*;
    use crate::{MilestonePlan, QuorumPolicy, VestingSchedule};

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const A1: [u8; 32] = [0xA1; 32]; // attestors
    const A2: [u8; 32] = [0xA2; 32];
    const A3: [u8; 32] = [0xA3; 32];
    const MINT: [u8; 32] = [0xD0; 32];
    const AMOUNT: u64 = 1_000_000;
    const VEST_START: u64 = 1_700_000_000;
    const VEST_END: u64 = 1_800_000_000;
    const MID: u64 = 1_750_000_000; // half-vested
    const NEVER: u64 = u64::MAX; // no timeout

    fn id(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn watch(escrow_id: [u8; 32], escrow: Escrow) -> WatchedEscrow {
        let reference = escrow.reference();
        WatchedEscrow {
            escrow_id,
            escrow,
            reference,
            vault_derivation: None,
            pending_intent: None,
        }
    }

    fn funded_vesting(expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, expires_at)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e
    }

    #[test]
    fn empty_watch_list_plans_nothing() {
        let report = plan_claim_sweep(&[], MID);
        assert!(report.is_empty());
        assert_eq!(report.scanned, 0);
        assert_eq!(report.total_cu, 0);
        assert!(report.results.is_empty());
        let json = report.to_json();
        assert!(json.starts_with("{\"at\":1750000000,\"scanned\":0,\"total_cu\":0,"));
        assert!(json.ends_with(",\"sweeps\":[],\"results\":[]}"));
    }

    #[test]
    fn single_claimable_vault_packs_one_sweep() {
        let watched = [watch(id(0x01), funded_vesting(NEVER))];
        let report = plan_claim_sweep(&watched, MID);
        assert_eq!(report.scanned, 1);
        assert_eq!(report.sweeps.len(), 1);
        let sweep = &report.sweeps[0];
        assert_eq!(sweep.sweep_id, "sweep-0");
        assert_eq!(sweep.item_count(), 1);
        assert!(!sweep.over_budget);
        let item = &sweep.items[0];
        assert_eq!(item.escrow_id, id(0x01));
        // The sweep's action is the keeper scan's action: same kind,
        // same caller, same amount (half the linear curve vested).
        assert_eq!(item.action.kind, crate::KeeperActionKind::Claim);
        assert_eq!(item.action.caller, BOB);
        assert_eq!(item.action.amount, 500_000);
        assert_eq!(item.action.reason, "vesting_unlocked");
        // The AV-88 estimate is the action's own estimate.
        assert_eq!(item.estimated_cu, item.action.estimated_compute_units());
        assert_eq!(sweep.total_cu, item.estimated_cu);
        assert_eq!(report.total_cu, item.estimated_cu);
        // ALT table: vault + no mint (native SOL) — the taker signer
        // is never ALT-eligible.
        assert_eq!(sweep.alt_table, vec![id(0x01)]);
        assert_eq!(item.accounts[0].alt_index, Some(0));
        assert_eq!(item.accounts[0].role, "vault");
        assert_eq!(item.accounts[1].alt_index, None);
        assert_eq!(item.accounts[1].role, "caller");
        // The per-vault result.
        assert_eq!(report.results.len(), 1);
        let r = &report.results[0];
        assert_eq!(r.escrow_id, id(0x01));
        assert_eq!(r.outcome, VaultClaimOutcome::Swept);
        assert_eq!(r.sweep_id.as_deref(), Some("sweep-0"));
        assert_eq!(r.reason, None);
    }

    #[test]
    fn skip_reasons_mirror_the_keeper_predicate_conjuncts() {
        // No vesting schedule and no auction: nothing to price.
        let plain = {
            let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER).unwrap();
            e.fund(ALICE, MID).unwrap();
            e
        };
        // Milestone plan attached: the plan owns the schedule.
        let with_plan = {
            let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
                .unwrap()
                .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
                .unwrap()
                .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
                .unwrap();
            e.fund(ALICE, MID).unwrap();
            e
        };
        // Vesting attached but the scan runs before the curve
        // starts: nothing priced-but-unreleased.
        let early = funded_vesting(NEVER);
        // Quorum configured and unsatisfied.
        let quorum_locked = {
            let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
                .unwrap()
                .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
                .unwrap()
                .with_quorum(QuorumPolicy::new(&[A1, A2, A3], &[1, 1, 1], 2).unwrap())
                .unwrap();
            e.fund(ALICE, MID).unwrap();
            e
        };
        // Timelock not yet unlocked.
        let timelocked = {
            let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
                .unwrap()
                .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
                .unwrap()
                .with_timelock(MID + 1_000)
                .unwrap();
            e.fund(ALICE, MID).unwrap();
            e
        };
        let watched = [
            watch(id(0x01), plain),
            watch(id(0x02), with_plan),
            watch(id(0x03), early),
            watch(id(0x04), quorum_locked),
            watch(id(0x05), timelocked),
        ];
        // The pre-curve vault scans before VEST_START; the rest at MID.
        let early_report = plan_claim_sweep(&watched[2..3], VEST_START - 1);
        assert_eq!(
            early_report.results[0].reason,
            Some(skip_reason::NOTHING_CLAIMABLE)
        );
        let report = plan_claim_sweep(&[watched[0], watched[1], watched[3], watched[4]], MID);
        assert!(report.is_empty(), "no vault is claim-eligible");
        assert_eq!(report.results.len(), 4);
        let reasons: Vec<Option<&'static str>> =
            report.results.iter().map(|r| r.reason).collect();
        assert_eq!(
            reasons,
            vec![
                Some(skip_reason::NO_VESTING_SCHEDULE),
                Some(skip_reason::MILESTONE_PLAN_ATTACHED),
                Some(skip_reason::QUORUM_NOT_SATISFIED),
                Some(skip_reason::TIMELOCK_LOCKED),
            ]
        );
        for r in &report.results {
            assert_eq!(r.outcome, VaultClaimOutcome::Skipped);
            assert_eq!(r.sweep_id, None);
        }
        // Every skip agrees with the keeper scan: nothing listed.
        let scan = crate::scan_keeper_actions(
            &[watched[0], watched[1], watched[3], watched[4]],
            MID,
        );
        assert!(scan.actions.iter().all(|a| a.kind != crate::KeeperActionKind::Claim));
    }

    #[test]
    fn sweep_agrees_with_the_keeper_scan_on_eligible_vaults() {
        // The sweep lists exactly the claims the scan lists —
        // eligibility is one truth source.
        let watched = [
            watch(id(0x01), funded_vesting(NEVER)),
            watch(id(0x02), funded_vesting(NEVER)),
        ];
        let report = plan_claim_sweep(&watched, MID);
        let scan = crate::scan_keeper_actions(&watched, MID);
        let scan_claims: Vec<_> = scan
            .actions
            .iter()
            .filter(|a| a.kind == crate::KeeperActionKind::Claim)
            .collect();
        assert_eq!(scan_claims.len(), 2);
        assert_eq!(report.sweeps.len(), 1);
        for (item, scan_action) in report.sweeps[0].items.iter().zip(scan_claims.iter()) {
            assert_eq!(item.action, **scan_action);
        }
    }

    #[test]
    fn plan_is_deterministic_regardless_of_input_order() {
        let a = watch(id(0x03), funded_vesting(NEVER));
        let b = watch(id(0x01), funded_vesting(NEVER));
        let c = watch(id(0x02), funded_vesting(NEVER));
        let forward = plan_claim_sweep(&[a, b, c], MID);
        let backward = plan_claim_sweep(&[c, b, a], MID);
        assert_eq!(forward.to_json(), backward.to_json());
        // Sweeps pack in escrow_id order.
        let ids: Vec<[u8; 32]> = forward.sweeps[0].items.iter().map(|i| i.escrow_id).collect();
        assert_eq!(ids, vec![id(0x01), id(0x02), id(0x03)]);
    }

    #[test]
    fn auto_splits_past_1_4m_cu() {
        // One claim's CU is small (~13k), so a fleet large enough to
        // cross 1.4M forces the AV-145 automatic split.
        let one_cu = claim_action_for(&watch(id(0x00), funded_vesting(NEVER)), MID)
            .unwrap()
            .estimated_compute_units();
        let n = (CU_MAX_PER_TRANSACTION / one_cu) as usize + 3;
        let watched: Vec<WatchedEscrow> = (0..n)
            .map(|i| watch([(i % 251) as u8 + 1, (i / 251) as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], funded_vesting(NEVER)))
            .collect();
        let report = plan_claim_sweep(&watched, MID);
        assert!(report.sweeps.len() > 1, "expected a split, got {}", report.sweeps.len());
        // No claim lost across the split.
        let packed: usize = report.sweeps.iter().map(|s| s.item_count()).sum();
        assert_eq!(packed, n);
        assert_eq!(
            report.results.iter().filter(|r| r.outcome == VaultClaimOutcome::Swept).count(),
            n
        );
        // Every non-final sweep is full but within budget.
        for s in &report.sweeps {
            assert!(!s.over_budget, "a claim is far below 1.4M");
            assert!(s.total_cu <= CU_MAX_PER_TRANSACTION);
        }
        // Sweep ids are stable and sequential.
        for (i, s) in report.sweeps.iter().enumerate() {
            assert_eq!(s.sweep_id, format!("sweep-{i}"));
        }
    }

    #[test]
    fn alt_table_dedups_mint_across_vaults() {
        // Two vaults binding the same SPL mint: the mint appears once
        // in the sweep's ALT table, after the two vault PDAs.
        let minted = |id: [u8; 32]| {
            let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
                .unwrap()
                .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
                .unwrap()
                .with_mint(MINT)
                .unwrap();
            e.fund(ALICE, MID).unwrap();
            watch(id, e)
        };
        let watched = [minted(id(0x01)), minted(id(0x02))];
        let report = plan_claim_sweep(&watched, MID);
        assert_eq!(report.sweeps.len(), 1);
        let sweep = &report.sweeps[0];
        // First-seen order across items: vault-1, then the shared
        // mint (seen on item 0), then vault-2.
        assert_eq!(sweep.alt_table.len(), 3);
        assert_eq!(sweep.alt_table[0], id(0x01));
        assert_eq!(sweep.alt_table[1], MINT);
        assert_eq!(sweep.alt_table[2], id(0x02));
        // Per-item indexes remap into the merged table.
        let item0 = &sweep.items[0];
        assert_eq!(item0.accounts[0].alt_index, Some(0)); // vault
        assert_eq!(item0.accounts[1].alt_index, None); // caller signer
        assert_eq!(item0.accounts[2].alt_index, Some(1)); // mint
        let item1 = &sweep.items[1];
        assert_eq!(item1.accounts[0].alt_index, Some(2)); // vault
        assert_eq!(item1.accounts[2].alt_index, Some(1)); // same mint, same index
    }

    #[test]
    fn json_carries_the_per_vault_results_list() {
        let watched = [
            watch(id(0x01), funded_vesting(NEVER)),
            watch(id(0x02), {
                let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER).unwrap();
                e.fund(ALICE, MID).unwrap();
                e
            }),
        ];
        let report = plan_claim_sweep(&watched, MID);
        let json = report.to_json();
        // Swept result names the sweep; the skipped result names the
        // reason.
        assert!(json.contains("\"outcome\":\"swept\",\"sweep_id\":\"sweep-0\",\"reason\":null"));
        assert!(json.contains(&format!(
            "\"outcome\":\"skipped\",\"sweep_id\":null,\"reason\":\"{}\"",
            skip_reason::NO_VESTING_SCHEDULE
        )));
        // Results sort by escrow_id regardless of sweep packing —
        // search within the results section only.
        let results_start = json.find("\"results\":[").unwrap();
        let results_json = &json[results_start..];
        let r0 = results_json.find(&hex_of_id(0x01)).unwrap();
        let r1 = results_json.find(&hex_of_id(0x02)).unwrap();
        assert!(r0 < r1, "results sorted by escrow_id");
    }

    fn hex_of_id(b: u8) -> String {
        let h: String = format!("{:02x}", b);
        h.repeat(32)
    }
}
