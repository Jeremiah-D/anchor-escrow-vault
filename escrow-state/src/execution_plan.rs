//! AV-33: batch settlement execution plan over the keeper report.
//!
//! The keeper report (AV-20) lists every immediately executable
//! `cancel_expired` / `claim` call. A keeper bot — or a human operator
//! driving a multisig / CLI — still has to turn that flat call list into
//! *executable work*: which calls can go out together, who signs what,
//! and what happens when one of them fails.
//!
//! [`plan_execution`] answers that by grouping the report's actions into
//! **atomicity batches** keyed by `(mint, caller)`:
//!
//! - *Same caller*: one signing key authorizes the whole batch, so the
//!   batch fits a single signing session (one multisig proposal, one CLI
//!   run with one keypair).
//! - *Same mint*: the token path is uniform inside a batch — either every
//!   instruction is native-SOL or every instruction moves the same SPL
//!   mint, so the account set the submitter must assemble (token program,
//!   associated token accounts) is the same shape throughout.
//! - *Across batches*: vault account sets are disjoint by construction
//!   (one escrow contributes its actions to exactly one batch per caller),
//!   so a failing batch never invalidates another — the operator retries
//!   the failed batch alone and re-scans.
//!
//! Each planned instruction carries the real Anchor instruction
//! discriminator (`sha256("global:<name>")[..8]`, the same constructor
//! the AV-29 IDL pipeline pins) and the logical accounts it needs as
//! `(pubkey, role, signer, writable)` triples. The roles are *logical*:
//! `vault` is the escrow's vault PDA, `authority` the signing caller,
//! `refund_to` the pinned refund destination, `mint` the bound SPL mint.
//! A multisig/CLI maps them to concrete accounts — adding the system
//! program, the token program, and the derived token accounts — which is
//! deliberately left to the submitter: this crate never invents account
//! addresses it cannot derive.
//!
//! Like the report, the plan is dry-run by construction: it only reads
//! the report, emits no events, and touches no clock. Amounts are as of
//! the scan; the keeper executes the plan, then re-scans.

use super::cu_estimate::{
    check_compute_budget, estimate_instruction_cu, ComputeBudgetWarning, CU_MAX_PER_TRANSACTION,
};
use super::discriminator::instruction_discriminator;
use super::keeper::{KeeperAction, KeeperActionKind, KeeperReport};
use std::collections::BTreeMap;

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

/// Render 8 bytes as 16 lowercase hex characters.
fn hex8(bytes: &[u8; 8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(16);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// One logical account of a planned instruction: the pubkey plus the
/// role it plays. `signer` / `writable` mirror the Anchor `#[derive(Accounts)]`
/// constraints the program enforces, so a submitter can translate them
/// directly into `AccountMeta`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedAccount {
    /// The account's pubkey.
    pub pubkey: [u8; 32],
    /// Logical role: `"vault"`, `"authority"`, `"refund_to"`, or `"mint"`.
    pub role: &'static str,
    /// Whether the account must sign.
    pub signer: bool,
    /// Whether the instruction writes the account.
    pub writable: bool,
}

/// One executable instruction inside a batch: everything a multisig or
/// CLI needs to build the transaction instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedInstruction {
    /// Which escrow this instruction targets (the vault PDA).
    pub escrow_id: [u8; 32],
    /// Which program instruction to invoke.
    pub kind: KeeperActionKind,
    /// Which role the caller plays: `"initializer"` or `"taker"`.
    pub caller_role: &'static str,
    /// The real Anchor instruction discriminator
    /// (`sha256("global:<name>")[..8]`).
    pub discriminator: [u8; 8],
    /// Logical accounts, in program-declared order.
    pub accounts: Vec<PlannedAccount>,
    /// Raw amount the instruction moves (lamports / base units).
    pub amount: u64,
    /// Machine-readable reason (`"expired"` / `"vesting_unlocked"`).
    pub reason: &'static str,
}

/// One atomicity batch: instructions sharing `(mint, caller)`, safe to
/// submit as one signing session. Batches are mutually independent — a
/// failed batch is retried alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionBatch {
    /// Stable within one plan: `"batch-0"`, `"batch-1"`, … in the plan's
    /// deterministic batch order.
    pub batch_id: String,
    /// The SPL mint every instruction in the batch moves, or `None` on
    /// the native-SOL path.
    pub mint: Option<[u8; 32]>,
    /// The key that signs every instruction in the batch.
    pub caller: [u8; 32],
    /// Instructions in keeper-report (scan) order.
    pub instructions: Vec<PlannedInstruction>,
}

impl ExecutionBatch {
    /// Sum of the batch's instruction amounts (informational only —
    /// per-instruction amounts are the exact values). Saturates at
    /// `u64::MAX` rather than wrapping.
    pub fn total_amount(&self) -> u64 {
        self.instructions
            .iter()
            .map(|i| i.amount)
            .fold(0u64, |a, b| a.saturating_add(b))
    }

    /// AV-88: bundle-level CU aggregation — the sum of the batch's
    /// per-instruction estimates. Saturates instead of wrapping. The
    /// operator compares this against the per-transaction compute
    /// budget before signing: a batch is one signing session, but it
    /// may need several transactions.
    pub fn estimated_compute_units(&self) -> u64 {
        self.instructions
            .iter()
            .map(|i| i.estimated_compute_units())
            .fold(0u64, |a, b| a.saturating_add(b))
    }

    /// AV-88: over-limit warning — `Some` when the batch's estimate
    /// exceeds one transaction's compute budget, i.e. the batch cannot
    /// execute as a single transaction and must be split.
    pub fn compute_budget_warning(&self) -> Option<ComputeBudgetWarning> {
        check_compute_budget(self.estimated_compute_units())
    }
}

impl PlannedInstruction {
    /// AV-88: heuristic compute-unit estimate for this instruction —
    /// the kind's base cost plus per-signature, per-account, and
    /// per-data-byte charges from the [`cu_estimate`](super::cu_estimate)
    /// cost model. A planning number, not a measured cost: calibrate
    /// against `simulateTransaction` for production sizing.
    pub fn estimated_compute_units(&self) -> u64 {
        let signers = self.accounts.iter().filter(|a| a.signer).count();
        estimate_instruction_cu(self.kind.as_str(), self.accounts.len(), signers)
            // The cost table covers every keeper instruction kind — the
            // cu_estimate tests pin that — so this is unreachable on
            // real plans; the expect guards a hand-built kind the way
            // the AV-33 planner guards `refund_to`.
            .expect("AV-88: CU table covers every keeper instruction kind")
    }
}

/// The full execution plan derived from one keeper report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlan {
    /// The report's scan time: amounts are as of this timestamp.
    pub generated_at: u64,
    /// How many escrows the underlying scan covered.
    pub scanned: usize,
    /// How many actions the underlying report listed.
    pub actions: usize,
    /// Atomicity batches in deterministic order: native-SOL (`mint:
    /// None`) first, then by mint, then by caller.
    pub batches: Vec<ExecutionBatch>,
}

/// Build one planned instruction from a keeper action.
fn plan_instruction(a: &KeeperAction) -> PlannedInstruction {
    let mut accounts = vec![
        PlannedAccount {
            pubkey: a.escrow_id,
            role: "vault",
            signer: false,
            writable: true,
        },
        PlannedAccount {
            pubkey: a.caller,
            role: "authority",
            signer: true,
            writable: false,
        },
    ];
    if a.kind == KeeperActionKind::CancelExpired || a.kind == KeeperActionKind::CrankExpired {
        // The scan always sets `refund_to` for `cancel_expired` /
        // `crank_expired` — the refund recipient the state machine pins
        // (AV-23 anti-phishing; the AV-48 crank refunds to the same
        // pinned destination, the cranker receives nothing).
        // Guarded anyway: a plan must never name a wrong destination,
        // and must never panic on a hand-built report either.
        if let Some(r) = a.refund_to {
            accounts.push(PlannedAccount {
                pubkey: r,
                role: "refund_to",
                signer: false,
                writable: true,
            });
        }
    }
    if let Some(m) = a.mint {
        accounts.push(PlannedAccount {
            pubkey: m,
            role: "mint",
            signer: false,
            writable: false,
        });
    }
    PlannedInstruction {
        escrow_id: a.escrow_id,
        kind: a.kind,
        caller_role: a.caller_role,
        discriminator: instruction_discriminator(a.kind.as_str()),
        accounts,
        amount: a.amount,
        reason: a.reason,
    }
}

/// Group `report`'s actions into atomicity batches (same mint + same
/// caller) and return the multisig/CLI-ready execution plan.
///
/// Deterministic: batches are ordered by `(mint, caller)` with
/// native-SOL first; instructions keep the report's scan order; batch
/// ids are positional (`"batch-0"`, …). The same report always yields
/// the same plan and the same [`ExecutionPlan::to_json`] bytes.
pub fn plan_execution(report: &KeeperReport) -> ExecutionPlan {
    let mut groups: BTreeMap<(Option<[u8; 32]>, [u8; 32]), Vec<PlannedInstruction>> =
        BTreeMap::new();
    for a in &report.actions {
        groups
            .entry((a.mint, a.caller))
            .or_default()
            .push(plan_instruction(a));
    }
    let batches = groups
        .into_iter()
        .enumerate()
        .map(|(i, ((mint, caller), instructions))| ExecutionBatch {
            batch_id: format!("batch-{i}"),
            mint,
            caller,
            instructions,
        })
        .collect();
    ExecutionPlan {
        generated_at: report.at,
        scanned: report.scanned,
        actions: report.actions.len(),
        batches,
    }
}

impl ExecutionPlan {
    /// Hand-serialized JSON (the crate is dependency-free). Deterministic
    /// field order; keys are 64-char lowercase hex; `mint` is a hex
    /// string or `null`; discriminators are 16-char hex.
    ///
    /// ```json
    /// {"generated_at":1750000000,"scanned":2,"actions":2,"batches":[
    ///   {"batch_id":"batch-0","mint":null,"caller":"aa…",
    ///    "total_amount":2000000,"instructions":[
    ///     {"escrow_id":"01…","instruction":"cancel_expired",
    ///      "caller_role":"initializer","discriminator":"1a2b3c4d5e6f7080",
    ///      "accounts":[{"pubkey":"01…","role":"vault",
    ///                   "signer":false,"writable":true},…],
    ///      "amount":1000000,"reason":"expired"}]}]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(256 + self.actions * 560);
        s.push_str("{\"generated_at\":");
        s.push_str(&self.generated_at.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"actions\":");
        s.push_str(&self.actions.to_string());
        s.push_str(",\"batches\":[");
        for (bi, b) in self.batches.iter().enumerate() {
            if bi > 0 {
                s.push(',');
            }
            s.push_str("{\"batch_id\":\"");
            s.push_str(&b.batch_id);
            s.push_str("\",\"mint\":");
            match b.mint {
                Some(m) => {
                    s.push('"');
                    s.push_str(&hex32(&m));
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            s.push_str(",\"caller\":\"");
            s.push_str(&hex32(&b.caller));
            s.push_str("\",\"total_amount\":");
            s.push_str(&b.total_amount().to_string());
            s.push_str(",\"instructions\":[");
            for (ii, ix) in b.instructions.iter().enumerate() {
                if ii > 0 {
                    s.push(',');
                }
                s.push_str("{\"escrow_id\":\"");
                s.push_str(&hex32(&ix.escrow_id));
                s.push_str("\",\"instruction\":\"");
                s.push_str(ix.kind.as_str());
                s.push_str("\",\"caller_role\":\"");
                s.push_str(ix.caller_role);
                s.push_str("\",\"discriminator\":\"");
                s.push_str(&hex8(&ix.discriminator));
                s.push_str("\",\"accounts\":[");
                for (ai, a) in ix.accounts.iter().enumerate() {
                    if ai > 0 {
                        s.push(',');
                    }
                    s.push_str("{\"pubkey\":\"");
                    s.push_str(&hex32(&a.pubkey));
                    s.push_str("\",\"role\":\"");
                    s.push_str(a.role);
                    s.push_str("\",\"signer\":");
                    s.push_str(if a.signer { "true" } else { "false" });
                    s.push_str(",\"writable\":");
                    s.push_str(if a.writable { "true" } else { "false" });
                    s.push('}');
                }
                s.push_str("],\"amount\":");
                s.push_str(&ix.amount.to_string());
                s.push_str(",\"reason\":\"");
                s.push_str(ix.reason);
                s.push_str("\"}");
            }
            s.push_str("]}");
        }
        s.push_str("]}");
        s
    }
}

impl ExecutionPlan {
    /// AV-88: plan-level CU aggregation — the sum of every batch's
    /// estimate. Saturates instead of wrapping.
    pub fn total_estimated_compute_units(&self) -> u64 {
        self.batches
            .iter()
            .map(|b| b.estimated_compute_units())
            .fold(0u64, |a, b| a.saturating_add(b))
    }

    /// AV-88: the batches whose estimate exceeds one transaction's
    /// compute budget — each needs splitting before submission. Empty
    /// when every batch fits.
    pub fn batches_over_budget(&self) -> Vec<&ExecutionBatch> {
        self.batches
            .iter()
            .filter(|b| b.compute_budget_warning().is_some())
            .collect()
    }
}

#[cfg(test)]
mod execution_plan_tests {
    use super::*;

    const FUND_AT: u64 = 1_700_000_000;
    use crate::{scan_keeper_actions, Escrow, WatchedEscrow};

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const CAROL: [u8; 32] = [0xCC; 32]; // another initializer
    const MINT_A: [u8; 32] = [0xD0; 32];
    const MINT_B: [u8; 32] = [0xD1; 32];
    const ID1: [u8; 32] = [0x01; 32];
    const ID2: [u8; 32] = [0x02; 32];
    const ID3: [u8; 32] = [0x03; 32];
    const ID4: [u8; 32] = [0x04; 32];
    const MID: u64 = 1_750_000_000;

    fn action(
        id: [u8; 32],
        kind: KeeperActionKind,
        caller: [u8; 32],
        role: &'static str,
        mint: Option<[u8; 32]>,
        amount: u64,
    ) -> KeeperAction {
        KeeperAction {
            escrow_id: id,
            kind,
            caller,
            caller_role: role,
            mint,
            refund_to: if kind == KeeperActionKind::CancelExpired {
                Some(caller)
            } else {
                None
            },
            amount,
            decimals: 0,
            // AV-53: test actions carry no reference memo.
            reference: None,
            // AV-59: test actions carry no extension history.
            extension_count: 0,
            // AV-84: test actions carry no multisig binding.
            multisig_authority: None,
            // AV-91: test actions carry no evidence disclosure.
            evidence_disclosure: None,
            reason: "test",
        }
    }

    fn report(actions: Vec<KeeperAction>) -> KeeperReport {
        KeeperReport {
            at: MID,
            scanned: actions.len(),
            actions,
        }
    }

    fn roles(ix: &PlannedInstruction) -> Vec<&'static str> {
        ix.accounts.iter().map(|a| a.role).collect()
    }

    #[test]
    fn empty_report_plans_to_no_batches() {
        let plan = plan_execution(&report(vec![]));
        assert!(plan.batches.is_empty());
        assert_eq!(plan.generated_at, MID);
        assert_eq!(plan.scanned, 0);
        assert_eq!(plan.actions, 0);
        assert_eq!(
            plan.to_json(),
            r#"{"generated_at":1750000000,"scanned":0,"actions":0,"batches":[]}"#
        );
    }

    #[test]
    fn groups_by_mint_and_caller() {
        let actions = vec![
            action(ID1, KeeperActionKind::CancelExpired, ALICE, "initializer", None, 100),
            action(ID2, KeeperActionKind::CancelExpired, ALICE, "initializer", None, 200),
            action(ID3, KeeperActionKind::CancelExpired, ALICE, "initializer", Some(MINT_A), 300),
            action(ID4, KeeperActionKind::CancelExpired, CAROL, "initializer", None, 400),
        ];
        let plan = plan_execution(&report(actions));
        // (None, ALICE) / (None, CAROL) / (Some(MINT_A), ALICE): 3 batches.
        assert_eq!(plan.batches.len(), 3);
        assert_eq!(plan.batches[0].batch_id, "batch-0");
        // Deterministic order: native-SOL first, then by mint, then caller.
        assert_eq!(plan.batches[0].mint, None);
        assert_eq!(plan.batches[0].caller, ALICE);
        assert_eq!(plan.batches[0].instructions.len(), 2);
        assert_eq!(plan.batches[0].total_amount(), 300);
        assert_eq!(plan.batches[1].caller, CAROL);
        assert_eq!(plan.batches[1].mint, None);
        assert_eq!(plan.batches[2].mint, Some(MINT_A));
        // Scan order preserved inside a batch.
        assert_eq!(plan.batches[0].instructions[0].escrow_id, ID1);
        assert_eq!(plan.batches[0].instructions[1].escrow_id, ID2);
    }

    #[test]
    fn same_caller_different_mints_split_batches() {
        let actions = vec![
            action(ID1, KeeperActionKind::CancelExpired, ALICE, "initializer", Some(MINT_A), 100),
            action(ID2, KeeperActionKind::CancelExpired, ALICE, "initializer", Some(MINT_B), 200),
        ];
        let plan = plan_execution(&report(actions));
        assert_eq!(plan.batches.len(), 2);
        assert_eq!(plan.batches[0].mint, Some(MINT_A)); // MINT_A < MINT_B
        assert_eq!(plan.batches[1].mint, Some(MINT_B));
    }

    #[test]
    fn instruction_accounts_match_kind() {
        let cancel = action(ID1, KeeperActionKind::CancelExpired, ALICE, "initializer", None, 100);
        let claim = action(ID2, KeeperActionKind::Claim, BOB, "taker", Some(MINT_A), 50);
        let plan = plan_execution(&report(vec![cancel, claim]));
        assert_eq!(plan.batches.len(), 2);
        let cancel_ix = &plan.batches[0].instructions[0];
        assert_eq!(roles(cancel_ix), vec!["vault", "authority", "refund_to"]);
        assert!(!cancel_ix.accounts[0].signer && cancel_ix.accounts[0].writable); // vault
        assert!(cancel_ix.accounts[1].signer && !cancel_ix.accounts[1].writable); // authority
        let claim_ix = &plan.batches[1].instructions[0];
        assert_eq!(roles(claim_ix), vec!["vault", "authority", "mint"]);
        assert_eq!(claim_ix.caller_role, "taker");
    }

    #[test]
    fn discriminators_follow_the_anchor_rule() {
        // Independent recomputation via the crate sha256: the plan must
        // stamp sha256("global:<name>")[..8], the same bytes the IDL
        // pipeline pins.
        let digest = crate::sha256(b"global:cancel_expired");
        let mut expected = [0u8; 8];
        expected.copy_from_slice(&digest[..8]);
        let plan = plan_execution(&report(vec![action(
            ID1,
            KeeperActionKind::CancelExpired,
            ALICE,
            "initializer",
            None,
            100,
        )]));
        let ix = &plan.batches[0].instructions[0];
        assert_eq!(ix.discriminator, expected);
        assert_eq!(ix.discriminator.len(), 8);
        // …and the JSON renders it as 16 lowercase hex chars.
        let json = plan.to_json();
        let want = format!(
            "\"discriminator\":\"{}\"",
            expected.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        assert!(json.contains(&want), "json missing {want}");
    }

    #[test]
    fn batches_are_vault_disjoint_for_failure_isolation() {
        // The documented isolation property: no vault appears in two
        // batches, so a failed batch never invalidates another.
        let actions = vec![
            action(ID1, KeeperActionKind::CancelExpired, ALICE, "initializer", None, 100),
            action(ID2, KeeperActionKind::CancelExpired, CAROL, "initializer", None, 200),
            action(ID3, KeeperActionKind::Claim, BOB, "taker", Some(MINT_A), 300),
        ];
        let plan = plan_execution(&report(actions));
        let mut seen = std::collections::HashSet::new();
        for b in &plan.batches {
            for ix in &b.instructions {
                assert!(
                    seen.insert(ix.escrow_id),
                    "vault appears in two batches — isolation broken"
                );
            }
        }
    }

    #[test]
    fn plan_is_deterministic() {
        let actions = vec![
            action(ID3, KeeperActionKind::Claim, BOB, "taker", Some(MINT_A), 300),
            action(ID1, KeeperActionKind::CancelExpired, ALICE, "initializer", None, 100),
            action(ID2, KeeperActionKind::CancelExpired, ALICE, "initializer", None, 200),
        ];
        let r = report(actions);
        let a = plan_execution(&r);
        let b = plan_execution(&r);
        assert_eq!(a, b);
        assert_eq!(a.to_json(), b.to_json());
    }

    #[test]
    fn scan_then_plan_end_to_end() {
        // Real scan output feeds the planner: an expired escrow becomes
        // two batches — the permissionless crank (zero-key caller sorts
        // first) and the party-signed cancel_expired — each carrying the
        // pinned refund_to account.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, 0).unwrap();
        e.fund(ALICE, FUND_AT).unwrap();
        let watched = [WatchedEscrow {
            escrow_id: ID1,
            escrow: e,
            // AV-53: no reference memo on this escrow.
            reference: None,
        }];
        let plan = plan_execution(&scan_keeper_actions(&watched, MID));
        assert_eq!(plan.scanned, 1);
        assert_eq!(plan.actions, 2);
        assert_eq!(plan.batches.len(), 2);
        let crank = &plan.batches[0].instructions[0];
        assert_eq!(crank.kind, KeeperActionKind::CrankExpired);
        assert_eq!(crank.caller_role, "anyone");
        assert_eq!(crank.amount, 1_000_000);
        let ix = &plan.batches[1].instructions[0];
        assert_eq!(ix.kind, KeeperActionKind::CancelExpired);
        assert_eq!(ix.caller_role, "initializer");
        assert_eq!(ix.amount, 1_000_000);
        // The batch JSON carries everything a CLI needs: discriminator,
        // accounts with signer/writable flags, amount.
        let json = plan.to_json();
        assert!(json.contains("\"instruction\":\"cancel_expired\""));
        assert!(json.contains("\"instruction\":\"crank_expired\""));
        assert!(json.contains("\"role\":\"refund_to\""));
        assert!(json.contains("\"signer\":true"));
    }

    #[test]
    fn planned_instruction_estimated_cu_matches_cost_model() {
        // AV-88: cancel_expired plans 3 accounts
        // (vault/authority/refund_to), 1 signer → 13_814.
        let r = report(vec![action(
            ID1,
            KeeperActionKind::CancelExpired,
            ALICE,
            "initializer",
            None,
            100,
        )]);
        let plan = plan_execution(&r);
        let ix = &plan.batches[0].instructions[0];
        assert_eq!(ix.accounts.len(), 3);
        assert_eq!(ix.estimated_compute_units(), 13_814);
        // The keeper report's passthrough agrees with the plan's number
        // — one cost model, two views.
        assert_eq!(r.actions[0].estimated_compute_units(), 13_814);
    }

    #[test]
    fn batch_estimated_cu_aggregates_and_warns() {
        let plan = plan_execution(&report(vec![
            action(
                ID1,
                KeeperActionKind::CancelExpired,
                ALICE,
                "initializer",
                None,
                100
            ),
            action(ID2, KeeperActionKind::Claim, BOB, "taker", Some(MINT_A), 50),
        ]));
        // batch-0 (native, ALICE): cancel_expired → 13_814.
        // batch-1 (MINT_A, BOB): claim with mint → vault + authority +
        // mint = 3 accounts → 14_000 + 3_000 + 3×250 + 8×8 = 17_814.
        assert_eq!(plan.batches[0].estimated_compute_units(), 13_814);
        assert_eq!(plan.batches[1].estimated_compute_units(), 17_814);
        assert_eq!(plan.total_estimated_compute_units(), 13_814 + 17_814);
        assert!(plan.batches[0].compute_budget_warning().is_none());
        assert!(plan.batches[1].compute_budget_warning().is_none());
        assert!(plan.batches_over_budget().is_empty());

        // A giant batch trips the over-limit warning: 200 × 13_814 =
        // 2,762,800 > 1,400,000 — it cannot fit one transaction.
        let many: Vec<KeeperAction> = (0..200)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = (i & 0xff) as u8;
                id[1] = ((i >> 8) & 0xff) as u8;
                action(
                    id,
                    KeeperActionKind::CancelExpired,
                    ALICE,
                    "initializer",
                    None,
                    100,
                )
            })
            .collect();
        let big = plan_execution(&report(many));
        assert_eq!(big.batches.len(), 1);
        let est = big.batches[0].estimated_compute_units();
        assert_eq!(est, 200 * 13_814);
        let w = big.batches[0].compute_budget_warning().unwrap();
        assert_eq!(w.limit_cu, CU_MAX_PER_TRANSACTION);
        assert_eq!(w.estimated_cu, est);
        assert_eq!(w.over_by_cu, est - CU_MAX_PER_TRANSACTION);
        assert_eq!(big.batches_over_budget().len(), 1);
        assert_eq!(big.batches_over_budget()[0].batch_id, "batch-0");
    }
}
