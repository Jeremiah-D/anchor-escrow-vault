//! AV-61: keeper execution bundles over the batch lifecycle scan.
//!
//! [`scan_batch_lifecycle`] (AV-37) emits the executable `initialize ->
//! fund -> release` calls as a flat per-item call list. A keeper — or a
//! human operator driving a multisig / CLI — needs one more step before
//! anything can be submitted: pack the flat list into per-signing-session
//! execution bundles.
//!
//! [`bundle_execution`] groups the report's actions into atomicity
//! bundles keyed by `(mint, caller)`, the AV-33 convention:
//!
//! - *Same caller*: one signing key authorizes the whole bundle, so the
//!   bundle fits a single signing session (one multisig proposal, one
//!   CLI run with one keypair).
//! - *Same mint*: the token path is uniform inside a bundle — either
//!   every instruction is native-SOL or every instruction moves the same
//!   SPL mint — so the account set the submitter must assemble (token
//!   program, associated token accounts) has the same shape throughout.
//! - *Across bundles*: vault account sets are disjoint by construction
//!   (one escrow contributes its action to exactly one bundle — every
//!   item lists at most one action, and every action has a single
//!   caller), so a failing bundle never invalidates another. The
//!   operator retries the failed bundle alone and re-scans. This is the
//!   failure-isolation semantic the AV-33 execution plan documents,
//!   carried over to the lifecycle line.
//!
//! # Discriminators
//!
//! Each bundled action carries the real Anchor instruction discriminator
//! (`sha256("global:<name>")[..8]`), computed by the same
//! [`instruction_discriminator`] constructor the AV-29 IDL pipeline pins.
//! The name mapping is checked against the program side: the IDL
//! `INSTRUCTIONS` spec names are authoritative, so
//! [`program_instruction_name`] maps `Initialize -> "initialize"`,
//! `Fund -> "fund"`, `Release -> "release"`. At AV-61 implementation time
//! the batch kind names and the IDL instruction names agree — no drift —
//! but if the program side ever renames an instruction, the IDL side
//! wins: [`program_instruction_name`] is the single mapping point, and
//! the pin tests fail on drift.
//!
//! # Arguments
//!
//! `args` carries what the multisig/CLI needs to build the instruction,
//! in fixed key order per kind:
//!
//! - `initialize`: `taker` (hex), `amount`, `expires_at`. Note: the
//!   program reads `taker` from the instruction *accounts*
//!   (`input_mapping` in the IDL spec) — it is rendered inside `args`
//!   here because the scan carries it on the action and the submitter
//!   needs the key to assemble the account list.
//! - `fund`: `amount` — informational only; the program's `fund` takes
//!   no instruction arguments (IDL spec `params: []`).
//! - `release`: `amount` (the real instruction argument — the full
//!   remainder the scan computed), `payout` and `fee` (the expected
//!   taker-net / protocol-fee split — the transition's *return* values,
//!   informational, so the operator can reconcile what landed on chain).
//!
//! # ALT tables
//!
//! Every bundle embeds the report's full `alt_table` (deduped, first-seen
//! order, capped at 256 — the AV-37 build) alongside each action's
//! `alt_index`, which the scan already stamped to point into that table.
//! The bundle is therefore self-contained: the operator creates (or
//! extends) one ALT from `alt_table` once, then references accounts by
//! index in every transaction. Signers are excluded from the table by
//! construction (AV-37) and render with `alt_index: null`.
//!
//! # Determinism
//!
//! Bundles are ordered by `(mint, caller)` — native-SOL (`mint: None`)
//! first, then by mint, then by caller — and actions keep the report's
//! scan order inside each bundle. [`ExecutionBundle::to_json`] is
//! hand-serialized with fixed field order, so the same report always
//! renders the same bytes.
//!
//! # Dry-run
//!
//! Like the scan itself: [`bundle_execution`] only reads the report. It
//! emits no events, touches no clock, and mutates nothing — the input
//! `&BatchReport` is never written to, and no program-side state (in
//! particular [`VAULT_FIELDS`](crate::VAULT_FIELDS)) is touched. Amounts
//! are as of the report's `at`; the operator executes the bundles, then
//! re-scans.

use super::batch::{BatchAccount, BatchActionKind, BatchItemOutcome, BatchReport};
use super::discriminator::instruction_discriminator;
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

/// Map a batch action kind to the program-side instruction name.
///
/// The IDL `INSTRUCTIONS` spec (AV-29) is authoritative here: these
/// strings are the names the program's `#[program]` module declares,
/// which is what the Anchor discriminator rule hashes. If the program
/// side renames an instruction, update this mapping (not the batch
/// kinds) — the pin tests catch any drift.
///
/// Checked at AV-61: `Initialize -> "initialize"`, `Fund -> "fund"`,
/// `Release -> "release"` — the batch kind names and the IDL
/// instruction names agree, no drift.
fn program_instruction_name(kind: BatchActionKind) -> &'static str {
    match kind {
        BatchActionKind::Initialize => "initialize",
        BatchActionKind::Fund => "fund",
        BatchActionKind::Release => "release",
    }
}

/// One logical account of a bundled instruction: the pubkey plus the
/// role it plays, with its ALT index already resolved. `signer` /
/// `writable` mirror the Anchor `#[derive(Accounts)]` constraints, so
/// a submitter can translate them directly into `AccountMeta`s (or ALT
/// indexes). The `alt_index` values are the ones the scan stamped —
/// they point into the bundle's [`ExecutionBundle::alt_table`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundledAccount {
    /// The account's pubkey.
    pub pubkey: [u8; 32],
    /// Logical role: `"vault"`, `"initializer"`, or `"mint"`.
    pub role: &'static str,
    /// Whether the account must sign. Signers are never ALT-eligible.
    pub signer: bool,
    /// Whether the instruction writes the account.
    pub writable: bool,
    /// Index into the bundle's `alt_table` when this account is
    /// ALT-eligible (non-signer, table had room); `None` otherwise.
    pub alt_index: Option<u8>,
}

impl From<BatchAccount> for BundledAccount {
    fn from(a: BatchAccount) -> Self {
        BundledAccount {
            pubkey: a.pubkey,
            role: a.role,
            signer: a.signer,
            writable: a.writable,
            alt_index: a.alt_index,
        }
    }
}

/// One executable instruction inside a bundle: everything a multisig or
/// CLI needs to build and submit the instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundledAction {
    /// Which escrow this instruction targets (the vault PDA).
    pub escrow_id: [u8; 32],
    /// Which lifecycle call this is (`Initialize` / `Fund` / `Release`).
    pub kind: BatchActionKind,
    /// The program-side instruction name (see
    /// [`program_instruction_name`]).
    pub instruction: &'static str,
    /// The real Anchor instruction discriminator
    /// (`sha256("global:<name>")[..8]`).
    pub discriminator: [u8; 8],
    /// Which role the caller plays: always `"initializer"` on this
    /// lifecycle line.
    pub caller_role: &'static str,
    /// The taker to pass (hex): `initialize` only; `None` for `fund` /
    /// `release`.
    pub taker: Option<[u8; 32]>,
    /// `initialize`: the `expires_at` to pass; `0` for `fund` /
    /// `release` (not applicable).
    pub expires_at: u64,
    /// `initialize` / `fund`: the locked amount. `release`: the gross
    /// remainder the call moves (`payout + fee == amount`).
    pub amount: u64,
    /// `release`: the expected taker net payout (`amount - fee`);
    /// informational (a transition return value, not an instruction
    /// arg); `0` for `initialize` / `fund`.
    pub payout: u64,
    /// `release`: the expected protocol fee sliced from the payout;
    /// informational; `0` for `initialize` / `fund`.
    pub fee: u64,
    /// Logical accounts, in program-declared order.
    pub accounts: Vec<BundledAccount>,
    /// Machine-readable reason the scan listed the call: `"not_created"`,
    /// `"unfunded"`, or `"releasable"`.
    pub reason: &'static str,
}

impl BundledAction {
    /// Render the instruction arguments as a deterministic JSON object
    /// with fixed key order per kind (see the module docs for the
    /// per-kind semantics).
    fn args_json(&self) -> String {
        let mut s = String::from("{");
        match self.kind {
            BatchActionKind::Initialize => {
                s.push_str("\"taker\":\"");
                // The scan always sets `taker` for `initialize`; the
                // `expect` guards a hand-built report the way the AV-33
                // planner guards `refund_to`.
                s.push_str(&hex32(
                    &self.taker.expect("initialize action missing taker"),
                ));
                s.push_str("\",\"amount\":");
                s.push_str(&self.amount.to_string());
                s.push_str(",\"expires_at\":");
                s.push_str(&self.expires_at.to_string());
            }
            BatchActionKind::Fund => {
                s.push_str("\"amount\":");
                s.push_str(&self.amount.to_string());
            }
            BatchActionKind::Release => {
                s.push_str("\"amount\":");
                s.push_str(&self.amount.to_string());
                s.push_str(",\"payout\":");
                s.push_str(&self.payout.to_string());
                s.push_str(",\"fee\":");
                s.push_str(&self.fee.to_string());
            }
        }
        s.push('}');
        s
    }
}

/// One atomicity bundle: actions sharing `(mint, caller)`, safe to
/// submit as one signing session. Bundles are mutually independent —
/// vault sets are disjoint by construction, so a failed bundle is
/// retried alone while the others stand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionBundle {
    /// Stable within one bundling: `"bundle-0"`, `"bundle-1"`, … in the
    /// deterministic `(mint, caller)` order (native-SOL first).
    pub bundle_id: String,
    /// The SPL mint every instruction in the bundle moves, or `None` on
    /// the native-SOL path.
    pub mint: Option<[u8; 32]>,
    /// The key that signs every instruction in the bundle.
    pub caller: [u8; 32],
    /// Which role `caller` plays: always `"initializer"` on this
    /// lifecycle line (carried from the scan).
    pub caller_role: &'static str,
    /// Instructions in batch-report (scan) order.
    pub actions: Vec<BundledAction>,
    /// The report's `alt_table`, verbatim: the deduped non-signer
    /// account set in first-seen order, capped at 256 (AV-37). Every
    /// action's `alt_index` points into this list.
    pub alt_table: Vec<[u8; 32]>,
    /// The report's scan time: amounts are as of this timestamp.
    pub at: u64,
    /// How many items the underlying scan covered.
    pub scanned: usize,
}

impl ExecutionBundle {
    /// Number of executable instructions in the bundle.
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    /// Hand-serialized JSON (the crate is dependency-free). Deterministic
    /// field order; pubkeys are 64-char lowercase hex; `mint` is a hex
    /// string or `null`; discriminators are 16-char hex. The bundle is
    /// self-contained: `alt_table` plus per-account `alt_index` values
    /// are everything a multisig/CLI needs to assemble the transactions.
    ///
    /// ```json
    /// {"bundle_id":"bundle-0","mint":null,"caller":"aa…",
    ///  "caller_role":"initializer","actions":[
    ///   {"escrow_id":"01…","instruction":"initialize",
    ///    "discriminator":"1a2b3c4d5e6f7080","caller_role":"initializer",
    ///    "args":{"taker":"bb…","amount":1000000,"expires_at":1800000000},
    ///    "accounts":[{"pubkey":"01…","role":"vault",
    ///                 "signer":false,"writable":true,"alt_index":0}],
    ///    "reason":"not_created"}],
    ///  "action_count":1,"alt_table":["01…"],
    ///  "at":1750000000,"scanned":2}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(256 + self.actions.len() * 640);
        s.push_str("{\"bundle_id\":\"");
        s.push_str(&self.bundle_id);
        s.push_str("\",\"mint\":");
        match self.mint {
            Some(m) => {
                s.push('"');
                s.push_str(&hex32(&m));
                s.push('"');
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"caller\":\"");
        s.push_str(&hex32(&self.caller));
        s.push_str("\",\"caller_role\":\"");
        s.push_str(self.caller_role);
        s.push_str("\",\"actions\":[");
        for (ai, a) in self.actions.iter().enumerate() {
            if ai > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&a.escrow_id));
            s.push_str("\",\"instruction\":\"");
            s.push_str(a.instruction);
            s.push_str("\",\"discriminator\":\"");
            s.push_str(&hex8(&a.discriminator));
            s.push_str("\",\"caller_role\":\"");
            s.push_str(a.caller_role);
            s.push_str("\",\"args\":");
            s.push_str(&a.args_json());
            s.push_str(",\"accounts\":[");
            for (ci, acc) in a.accounts.iter().enumerate() {
                if ci > 0 {
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
        s.push_str("],\"action_count\":");
        s.push_str(&self.action_count().to_string());
        s.push_str(",\"alt_table\":[");
        for (i, key) in self.alt_table.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('"');
            s.push_str(&hex32(key));
            s.push('"');
        }
        s.push_str("],\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push('}');
        s
    }
}

/// Group the report's executable actions into `(mint, caller)` atomicity
/// bundles (see the module docs). `Blocked` and `Done` items contribute
/// nothing — only [`BatchItemOutcome::Action`] enters a bundle.
///
/// Deterministic: bundles are ordered by `(mint, caller)` with
/// native-SOL first; actions keep the report's scan order inside each
/// bundle; bundle ids are positional (`"bundle-0"`, …). The same report
/// always yields the same bundles and the same
/// [`ExecutionBundle::to_json`] bytes.
///
/// Dry-run by construction: this only reads `report` — no events, no
/// clock, no mutation. Amounts are as of the report's `at`; execute the
/// bundles, then re-scan.
pub fn bundle_execution(report: &BatchReport) -> Vec<ExecutionBundle> {
    fn bundle_action(
        escrow_id: [u8; 32],
        a: &super::batch::BatchLifecycleAction,
    ) -> BundledAction {
        let instruction = program_instruction_name(a.kind);
        BundledAction {
            escrow_id,
            kind: a.kind,
            instruction,
            discriminator: instruction_discriminator(instruction),
            caller_role: a.caller_role,
            taker: a.taker,
            expires_at: a.expires_at,
            amount: a.amount,
            payout: a.payout,
            fee: a.fee,
            accounts: a.accounts.iter().map(|acc| BundledAccount::from(*acc)).collect(),
            reason: a.reason,
        }
    }

    let mut groups: BTreeMap<(Option<[u8; 32]>, [u8; 32]), Vec<BundledAction>> = BTreeMap::new();
    for item in &report.items {
        if let BatchItemOutcome::Action(a) = &item.outcome {
            groups
                .entry((a.mint, a.caller))
                .or_default()
                .push(bundle_action(item.escrow_id, a));
        }
    }
    groups
        .into_iter()
        .enumerate()
        .map(|(i, ((mint, caller), actions))| ExecutionBundle {
            bundle_id: format!("bundle-{i}"),
            mint,
            caller,
            // Every action on the `initialize -> fund -> release` line
            // is caller-signed as the initializer (the scan pins this).
            caller_role: "initializer",
            actions,
            alt_table: report.alt_table.clone(),
            at: report.at,
            scanned: report.scanned,
        })
        .collect()
}

#[cfg(test)]
mod execution_bundle_tests {
    use super::*;
    use crate::{scan_batch_lifecycle, BatchInitializeParams, BatchWatchItem, Escrow};

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const CAROL: [u8; 32] = [0xCC; 32]; // another initializer
    const MINT_A: [u8; 32] = [0xD0; 32];
    const MINT_B: [u8; 32] = [0xD1; 32];
    const ID1: [u8; 32] = [0x01; 32];
    const ID2: [u8; 32] = [0x02; 32];
    const ID3: [u8; 32] = [0x03; 32];
    const ID4: [u8; 32] = [0x04; 32];
    const AMOUNT: u64 = 1_000_000;
    const EXPIRES: u64 = 1_800_000_000;
    const NOW: u64 = 1_750_000_000;

    fn params(initializer: [u8; 32]) -> BatchInitializeParams {
        BatchInitializeParams {
            initializer,
            taker: BOB,
            amount: AMOUNT,
            expires_at: EXPIRES,
        }
    }

    fn watch(id: [u8; 32], escrow: Option<Escrow>, initializer: [u8; 32]) -> BatchWatchItem {
        BatchWatchItem {
            escrow_id: id,
            escrow,
            initialize: params(initializer),
        }
    }

    fn funded(initializer: [u8; 32], mint: Option<[u8; 32]>) -> Escrow {
        let mut e = Escrow::initialize(initializer, BOB, AMOUNT, EXPIRES).unwrap();
        if let Some(m) = mint {
            e = e.with_mint(m).unwrap();
        }
        e.fund(initializer).unwrap();
        e
    }

    fn hex_of(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn groups_by_mint_and_caller_with_deterministic_order() {
        let items = [
            watch(ID1, None, ALICE),                          // initialize (None, ALICE)
            watch(ID2, None, CAROL),                          // initialize (None, CAROL)
            watch(ID3, Some(funded(ALICE, Some(MINT_A))), ALICE), // release (MINT_A, ALICE)
            watch(ID4, Some(funded(ALICE, Some(MINT_B))), ALICE), // release (MINT_B, ALICE)
        ];
        let bundles = bundle_execution(&scan_batch_lifecycle(&items, NOW));
        assert_eq!(bundles.len(), 4);
        // Deterministic order: native-SOL first, then by mint, then caller.
        assert_eq!(bundles[0].bundle_id, "bundle-0");
        assert_eq!(bundles[0].mint, None);
        assert_eq!(bundles[0].caller, ALICE);
        assert_eq!(bundles[1].mint, None);
        assert_eq!(bundles[1].caller, CAROL);
        assert_eq!(bundles[2].mint, Some(MINT_A));
        assert_eq!(bundles[2].caller, ALICE);
        assert_eq!(bundles[3].mint, Some(MINT_B));
        assert_eq!(bundles[3].caller, ALICE);
        // Bundle ids are positional.
        for (i, b) in bundles.iter().enumerate() {
            assert_eq!(b.bundle_id, format!("bundle-{i}"));
            assert_eq!(b.at, NOW);
            assert_eq!(b.scanned, 4);
        }
    }

    #[test]
    fn same_caller_different_mints_split_bundles() {
        let items = [
            watch(ID1, Some(funded(ALICE, Some(MINT_A))), ALICE),
            watch(ID2, Some(funded(ALICE, Some(MINT_B))), ALICE),
        ];
        let bundles = bundle_execution(&scan_batch_lifecycle(&items, NOW));
        assert_eq!(bundles.len(), 2);
        assert_eq!(bundles[0].mint, Some(MINT_A)); // MINT_A < MINT_B
        assert_eq!(bundles[1].mint, Some(MINT_B));
        // Every action's mint agrees with its bundle's key.
        for b in &bundles {
            for a in &b.actions {
                assert_eq!(Some(b.mint), Some(a_kind_mint(a)), "mint key drift");
            }
        }
    }

    /// The mint an action was grouped under, re-derived for the key
    /// agreement check (the scan stamps it on the action).
    fn a_kind_mint(a: &BundledAction) -> Option<[u8; 32]> {
        match a.kind {
            BatchActionKind::Release => {
                // The release action's mint account is the third account
                // when the SPL path is bound.
                a.accounts
                    .iter()
                    .find(|acc| acc.role == "mint")
                    .map(|acc| acc.pubkey)
            }
            _ => None,
        }
    }

    #[test]
    fn scan_order_preserved_inside_bundle() {
        // Deliberately out of escrow-id order in the input: the bundle
        // must keep the report's scan order, not sort by id.
        let items = [
            watch(ID3, None, ALICE),
            watch(ID1, None, ALICE),
            watch(ID2, None, ALICE),
        ];
        let bundles = bundle_execution(&scan_batch_lifecycle(&items, NOW));
        assert_eq!(bundles.len(), 1);
        let ids: Vec<[u8; 32]> = bundles[0].actions.iter().map(|a| a.escrow_id).collect();
        assert_eq!(ids, vec![ID3, ID1, ID2]);
    }

    #[test]
    fn discriminators_match_the_anchor_constructor() {
        // Independent recomputation via the crate sha256: each bundled
        // action must stamp sha256("global:<program-name>")[..8], the
        // same bytes the IDL pipeline pins for the program side.
        for (kind, name) in [
            (BatchActionKind::Initialize, "initialize"),
            (BatchActionKind::Fund, "fund"),
            (BatchActionKind::Release, "release"),
        ] {
            let digest = crate::sha256(format!("global:{name}").as_bytes());
            let mut expected = [0u8; 8];
            expected.copy_from_slice(&digest[..8]);
            assert_eq!(
                instruction_discriminator(name),
                expected,
                "discriminator constructor drift for {name}"
            );
            assert_eq!(
                program_instruction_name(kind),
                name,
                "kind -> program-name mapping drift for {name:?}"
            );
        }
        // End to end: a report with all three kinds stamps each action
        // with the discriminator of its program-side name.
        let e_uninit = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES).unwrap();
        let items = [
            watch(ID1, None, ALICE),                     // initialize
            watch(ID2, Some(e_uninit), ALICE),           // fund
            watch(ID3, Some(funded(ALICE, None)), ALICE), // release
        ];
        let bundles = bundle_execution(&scan_batch_lifecycle(&items, NOW));
        assert_eq!(bundles.len(), 1); // all (None, ALICE)
        let find =
            |kind: BatchActionKind| bundles[0].actions.iter().find(|a| a.kind == kind).unwrap();
        for (kind, name) in [
            (BatchActionKind::Initialize, "initialize"),
            (BatchActionKind::Fund, "fund"),
            (BatchActionKind::Release, "release"),
        ] {
            let a = find(kind);
            assert_eq!(a.instruction, name);
            assert_eq!(a.discriminator, instruction_discriminator(name));
            // …and the JSON renders it as 16 lowercase hex chars.
            let json = bundles[0].to_json();
            let want = format!(
                "\"instruction\":\"{name}\",\"discriminator\":\"{}\"",
                a.discriminator.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            assert!(json.contains(&want), "json missing {want}");
        }
    }

    #[test]
    fn alt_index_points_into_bundle_alt_table() {
        // Two releases sharing a mint: the bundle's alt_table is the
        // scan's table verbatim, and every action's alt_index resolves
        // into it. The shared initializer is a signer — never indexed.
        let items = [
            watch(ID1, Some(funded(ALICE, Some(MINT_A))), ALICE),
            watch(ID2, Some(funded(ALICE, Some(MINT_A))), ALICE),
        ];
        let report = scan_batch_lifecycle(&items, NOW);
        let bundles = bundle_execution(&report);
        assert_eq!(bundles.len(), 1);
        let b = &bundles[0];
        assert_eq!(b.alt_table, report.alt_table);
        // First-seen order: ID1 (vault), MINT_A, ID2 (vault).
        assert_eq!(b.alt_table, vec![ID1, MINT_A, ID2]);
        for a in &b.actions {
            for acc in &a.accounts {
                match acc.alt_index {
                    Some(idx) => {
                        assert!(
                            !acc.signer,
                            "signer account must never carry an alt_index"
                        );
                        assert_eq!(
                            b.alt_table[idx as usize], acc.pubkey,
                            "alt_index does not resolve into alt_table"
                        );
                    }
                    None => assert!(acc.signer, "non-signer missing alt_index"),
                }
            }
            // The mint account indexes the shared slot 1.
            let mint_acc = a.accounts.iter().find(|acc| acc.role == "mint").unwrap();
            assert_eq!(mint_acc.alt_index, Some(1));
        }
    }

    #[test]
    fn bundling_is_deterministic() {
        let items = [
            watch(ID4, Some(funded(ALICE, Some(MINT_B))), ALICE),
            watch(ID1, None, ALICE),
            watch(ID3, Some(funded(ALICE, Some(MINT_A))), ALICE),
            watch(ID2, None, CAROL),
        ];
        let report = scan_batch_lifecycle(&items, NOW);
        let a = bundle_execution(&report);
        let b = bundle_execution(&report);
        assert_eq!(a, b);
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.to_json(), y.to_json(), "JSON bytes differ");
        }
    }

    #[test]
    fn bundling_is_dry_run() {
        let items = [
            watch(ID1, None, ALICE),
            watch(ID2, Some(funded(ALICE, Some(MINT_A))), ALICE),
        ];
        let report = scan_batch_lifecycle(&items, NOW);
        let before = report.clone();
        let bundles = bundle_execution(&report);
        assert_eq!(report, before, "bundling mutated the report");
        assert_eq!(bundles.len(), 2);
    }

    #[test]
    fn empty_report_bundles_to_nothing() {
        let report = BatchReport {
            at: NOW,
            scanned: 0,
            items: vec![],
            alt_table: vec![],
        };
        let bundles = bundle_execution(&report);
        assert!(bundles.is_empty());
    }

    #[test]
    fn blocked_and_done_items_never_enter_a_bundle() {
        // ID1: blocked (zero-amount initialize) — no action.
        let mut blocked = watch(ID1, None, ALICE);
        blocked.initialize.amount = 0;
        // ID2: terminal (released) — Done, no action.
        let mut released = funded(ALICE, None);
        released.release(ALICE, NOW, AMOUNT, None, BOB).unwrap();
        // ID3: executable release — the only action.
        let items = [
            blocked,
            watch(ID2, Some(released), ALICE),
            watch(ID3, Some(funded(ALICE, None)), ALICE),
        ];
        let report = scan_batch_lifecycle(&items, NOW);
        assert_eq!(report.action_count(), 1);
        let bundles = bundle_execution(&report);
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].action_count(), 1);
        assert_eq!(bundles[0].actions[0].escrow_id, ID3);
        assert_eq!(bundles[0].actions[0].kind, BatchActionKind::Release);
    }

    #[test]
    fn args_shape_matches_kind() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES)
            .unwrap()
            .with_protocol_fee(100)
            .unwrap();
        e.fund(ALICE).unwrap();
        let items = [
            watch(ID1, None, ALICE),          // initialize
            watch(ID2, Some(e), ALICE),       // release (1% fee)
        ];
        let bundles = bundle_execution(&scan_batch_lifecycle(&items, NOW));
        assert_eq!(bundles.len(), 1);
        let json = bundles[0].to_json();
        // initialize args: taker + amount + expires_at.
        assert!(
            json.contains(&format!(
                "\"instruction\":\"initialize\",\"discriminator\":\"{}\",\"caller_role\":\"initializer\",\"args\":{{\"taker\":\"{}\",\"amount\":1000000,\"expires_at\":1800000000}}",
                instruction_discriminator("initialize").iter().map(|b| format!("{b:02x}")).collect::<String>(),
                hex_of(0xBB),
            )),
            "initialize args shape wrong: {json}"
        );
        // release args: amount + expected payout/fee split
        // (1% of 1_000_000 = 10_000 fee; payout + fee == amount).
        assert!(
            json.contains("\"instruction\":\"release\"")
                && json.contains("\"args\":{\"amount\":1000000,\"payout\":990000,\"fee\":10000}"),
            "release args shape wrong: {json}"
        );
    }

    #[test]
    fn fund_action_carries_no_instruction_args() {
        // The program's `fund` takes no instruction arguments (IDL
        // spec `params: []`); the bundle lists only the informational
        // locked amount.
        let e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES).unwrap();
        let bundles = bundle_execution(&scan_batch_lifecycle(&[watch(ID1, Some(e), ALICE)], NOW));
        assert_eq!(bundles.len(), 1);
        let a = &bundles[0].actions[0];
        assert_eq!(a.kind, BatchActionKind::Fund);
        assert_eq!(a.args_json(), "{\"amount\":1000000}");
    }

    #[test]
    fn bundles_are_vault_disjoint_for_failure_isolation() {
        // The documented isolation property: no vault appears in two
        // bundles, so a failed bundle never invalidates another.
        let items = [
            watch(ID1, None, ALICE),
            watch(ID2, None, CAROL),
            watch(ID3, Some(funded(ALICE, Some(MINT_A))), ALICE),
            watch(ID4, Some(funded(CAROL, Some(MINT_A))), CAROL),
        ];
        let bundles = bundle_execution(&scan_batch_lifecycle(&items, NOW));
        assert!(bundles.len() >= 3);
        let mut seen = std::collections::HashSet::new();
        for b in &bundles {
            for a in &b.actions {
                assert!(
                    seen.insert(a.escrow_id),
                    "vault appears in two bundles — isolation broken"
                );
            }
        }
    }

    #[test]
    fn json_shape_is_pinned() {
        let bundles = bundle_execution(&scan_batch_lifecycle(&[watch(ID1, None, ALICE)], NOW));
        assert_eq!(bundles.len(), 1);
        let json = bundles[0].to_json();
        let disc: String = instruction_discriminator("initialize")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let expected = format!(
            "{{\"bundle_id\":\"bundle-0\",\"mint\":null,\"caller\":\"{}\",\"caller_role\":\"initializer\",\"actions\":[{{\"escrow_id\":\"{}\",\"instruction\":\"initialize\",\"discriminator\":\"{}\",\"caller_role\":\"initializer\",\"args\":{{\"taker\":\"{}\",\"amount\":1000000,\"expires_at\":1800000000}},\"accounts\":[{{\"pubkey\":\"{}\",\"role\":\"vault\",\"signer\":false,\"writable\":true,\"alt_index\":0}},{{\"pubkey\":\"{}\",\"role\":\"initializer\",\"signer\":true,\"writable\":true,\"alt_index\":null}}],\"reason\":\"not_created\"}}],\"action_count\":1,\"alt_table\":[\"{}\"],\"at\":1750000000,\"scanned\":1}}",
            hex_of(0xAA),
            hex_of(0x01),
            disc,
            hex_of(0xBB),
            hex_of(0x01),
            hex_of(0xAA),
            hex_of(0x01),
        );
        assert_eq!(json, expected);
    }
}
