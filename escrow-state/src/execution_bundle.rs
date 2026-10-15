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
use super::cpi::{system_transfer, TransferInstruction};
use super::discriminator::instruction_discriminator;
use super::events::IndexedEscrow;
use super::priority_fee::PriorityFeeRecommendation;
use crate::{EscrowError, EscrowState};
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

/// Render arbitrary bytes as lowercase hex.
fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// AV-98: validation errors for the opt-in Jito tip attached to a
/// keeper execution bundle. The backlog calls this "RangeError
/// validation" — in Rust that is a `Result`: every constructor that
/// takes a tip amount or recipient rejects degenerate input instead of
/// building a worthless or dangerous instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipConfigError {
    /// The tip would move zero lamports — a no-op instruction that
    /// still costs the submitter a signature.
    ZeroTipAmount,
    /// The tip recipient is the zero address — the lamports would be
    /// burned.
    ZeroRecipient,
    /// The bundle's signing caller is the zero address — there is no
    /// payer to debit (only reachable on a hand-built bundle; the scan
    /// always stamps a real caller).
    ZeroPayer,
    /// The tip recipient is the bundle's own caller — a self-transfer
    /// the system program would reject, and a sign the operator pasted
    /// the wrong address.
    TipRecipientIsPayer,
}

/// AV-98: the operator's Jito tip configuration — how much to pay and
/// who receives it — before it is bound to a specific bundle payer.
/// [`KeeperReport`](super::keeper::KeeperReport) carries this form:
/// the report annotates the intended tip (`jito_tip`) without building
/// the instruction, because the report's actions may name different
/// callers while the payer is the operator's own key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JitoTipConfig {
    /// Tip in lamports. Always > 0 (see [`TipConfigError`]).
    pub lamports: u64,
    /// The Jito tip recipient — a Jito validator tip address the
    /// operator pastes in. Never the zero address.
    pub recipient: [u8; 32],
}

impl JitoTipConfig {
    /// Validated constructor: rejects a zero amount and a zero
    /// recipient.
    pub fn new(lamports: u64, recipient: [u8; 32]) -> Result<Self, TipConfigError> {
        if lamports == 0 {
            return Err(TipConfigError::ZeroTipAmount);
        }
        if recipient == [0u8; 32] {
            return Err(TipConfigError::ZeroRecipient);
        }
        Ok(JitoTipConfig { lamports, recipient })
    }
}

/// AV-98: a Jito tip bound to one execution bundle — the validated
/// config plus the fully assembled system-transfer instruction, built
/// with [`system_transfer`](super::cpi::system_transfer) (the AV-31
/// byte constructor: `u32` index `2` LE followed by the `u64` lamport
/// amount LE, 12 bytes). The instruction moves `lamports` from the
/// bundle's caller to the tip recipient.
///
/// Jito convention: the tip instruction goes **last** in the
/// transaction — after every escrow instruction — so a partially
/// executed transaction never pays the tip without doing the work.
/// The bundle JSON renders it after the `actions` array for exactly
/// that reason; the submitter appends it after the escrow instructions
/// when assembling the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitoTip {
    /// The validated amount + recipient.
    pub config: JitoTipConfig,
    /// `system_transfer(caller, recipient, lamports)`: program id is
    /// the system program, accounts are `[payer (signer, writable),
    /// recipient (writable)]`, data is the 12-byte transfer encoding.
    pub instruction: TransferInstruction,
}

impl JitoTip {
    /// Validated constructor: the config checks plus payer checks
    /// (nonzero, distinct from the recipient). `payer` is the bundle's
    /// `caller` — the key that signs the whole bundle.
    pub fn new(
        payer: [u8; 32],
        lamports: u64,
        recipient: [u8; 32],
    ) -> Result<Self, TipConfigError> {
        let config = JitoTipConfig::new(lamports, recipient)?;
        if payer == [0u8; 32] {
            return Err(TipConfigError::ZeroPayer);
        }
        if recipient == payer {
            return Err(TipConfigError::TipRecipientIsPayer);
        }
        // Every `system_transfer` precondition holds by construction
        // (nonzero amount, nonzero distinct addresses), so this cannot
        // fail — the expect documents the invariant, the way the
        // bundle's other constructors guard hand-built inputs.
        let instruction = system_transfer(payer, recipient, lamports)
            .expect("jito tip: system_transfer preconditions validated above");
        Ok(JitoTip { config, instruction })
    }

    /// The tip amount in lamports.
    pub fn lamports(&self) -> u64 {
        self.config.lamports
    }

    /// The tip recipient.
    pub fn recipient(&self) -> [u8; 32] {
        self.config.recipient
    }
}

/// Render a [`TransferInstruction`] as deterministic JSON: program id
/// as 64-char hex, accounts in order with signer/writable flags, data
/// as lowercase hex.
fn transfer_instruction_json(ix: &TransferInstruction) -> String {
    let mut s = String::from("{\"program_id\":\"");
    s.push_str(&hex32(&ix.program_id));
    s.push_str("\",\"accounts\":[");
    for (i, acc) in ix.accounts.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"pubkey\":\"");
        s.push_str(&hex32(&acc.pubkey));
        s.push_str("\",\"signer\":");
        s.push_str(if acc.is_signer { "true" } else { "false" });
        s.push_str(",\"writable\":");
        s.push_str(if acc.is_writable { "true" } else { "false" });
        s.push('}');
    }
    s.push_str("],\"data\":\"");
    s.push_str(&hex_bytes(&ix.data));
    s.push_str("\"}");
    s
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
    /// AV-89: the priority-fee recommendation the caller stamped onto
    /// the bundle (the keeper's
    /// [`PriorityFeeOracle`](super::priority_fee::PriorityFeeOracle)
    /// output) — the dry-run report's fee line, paired with the AV-88
    /// CU passthrough (`action_count` and the per-action CU estimates
    /// the submitter derives). `None` when the caller stamped nothing;
    /// the JSON renders it as `null` (the same `Option` convention as
    /// `mint`).
    pub estimated_priority_fee: Option<PriorityFeeRecommendation>,
    /// AV-98: the opt-in Jito tip bound to this bundle ([`JitoTip`])
    /// — `None` unless the keeper stamped one via
    /// [`with_jito_tip`](ExecutionBundle::with_jito_tip). The tip
    /// instruction is the bundle's last instruction at submit time;
    /// it is bundle overhead, not an escrow action, so
    /// [`action_count`](ExecutionBundle::action_count) excludes it.
    pub jito_tip: Option<JitoTip>,
}

impl ExecutionBundle {
    /// Number of executable instructions in the bundle.
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    /// Stamp the priority-fee recommendation onto the bundle (builder
    /// style — [`bundle_execution`] leaves it `None`; the keeper calls
    /// this with its oracle's [`recommend`](super::priority_fee::PriorityFeeOracle::recommend)
    /// output before handing the bundle JSON to the signer).
    pub fn with_priority_fee(mut self, fee: PriorityFeeRecommendation) -> Self {
        self.estimated_priority_fee = Some(fee);
        self
    }

    /// AV-98: stamp the opt-in Jito tip onto the bundle (builder
    /// style — [`bundle_execution`] leaves it `None`). `payer` is the
    /// bundle's `caller`: the system-transfer instruction debits the
    /// signing key, so the tip comes out of the keeper operator's own
    /// pocket, never out of escrowed funds.
    ///
    /// Validation (the backlog's "RangeError" checks): a zero amount,
    /// a zero recipient, a zero payer, or a recipient equal to the
    /// payer all return [`TipConfigError`] and leave the bundle
    /// untouched — `with_jito_tip` takes `self` by value and only
    /// assigns on success, so a failed stamp cannot half-apply.
    pub fn with_jito_tip(
        mut self,
        lamports: u64,
        recipient: [u8; 32],
    ) -> Result<Self, TipConfigError> {
        let tip = JitoTip::new(self.caller, lamports, recipient)?;
        self.jito_tip = Some(tip);
        Ok(self)
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
    ///  "jito_tip":{"lamports":10000,"recipient":"ee…",
    ///   "instruction":{"program_id":"00…","accounts":[
    ///    {"pubkey":"aa…","signer":true,"writable":true},
    ///    {"pubkey":"ee…","signer":false,"writable":true}],
    ///   "data":"02000000…"}} — or `null` when unstamped (AV-98: the
    ///  tip instruction goes last at submit time),
    ///  "action_count":1,"alt_table":["01…"],
    ///  "at":1750000000,"scanned":2,"estimated_priority_fee":
    ///  {"micro_lamports_per_cu":1200,"confidence":"high","fallback":false}}
    /// ```
    ///
    /// `estimated_priority_fee` renders as `null` when the caller
    /// stamped no recommendation (see
    /// [`ExecutionBundle::with_priority_fee`]).
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
        // AV-98: the Jito tip, rendered after the escrow actions — at
        // submit time the tip instruction is appended LAST, after every
        // escrow instruction, so a partially executed transaction never
        // pays the tip without doing the work. `null` when the keeper
        // stamped nothing (same Option convention as `mint`).
        s.push_str("],\"jito_tip\":");
        match &self.jito_tip {
            Some(tip) => {
                s.push_str("{\"lamports\":");
                s.push_str(&tip.config.lamports.to_string());
                s.push_str(",\"recipient\":\"");
                s.push_str(&hex32(&tip.config.recipient));
                s.push_str("\",\"instruction\":");
                s.push_str(&transfer_instruction_json(&tip.instruction));
                s.push('}');
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"action_count\":");
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
        // AV-89: the dry-run report's fee line — the caller's stamped
        // priority-fee recommendation, or null when none was stamped.
        s.push_str(",\"estimated_priority_fee\":");
        match &self.estimated_priority_fee {
            Some(fee) => s.push_str(&fee.to_json()),
            None => s.push_str("null"),
        }
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
            // AV-89: the keeper stamps its oracle recommendation via
            // `with_priority_fee` — the bundler itself stays fee-free.
            estimated_priority_fee: None,
            // AV-98: the keeper stamps its Jito tip via `with_jito_tip`
            // — the bundler itself stays tip-free.
            jito_tip: None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// AV-102: bundle simulation — the keeper dry-run.
// ---------------------------------------------------------------------------

/// Why a simulated action was not executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulatedSkipReason {
    /// An earlier action in the bundle failed: the bundle is atomic, so
    /// a real submission would abort the whole transaction here.
    BundleAborted,
    /// No snapshot was supplied for a non-`initialize` action — the
    /// keeper must pass the current [`IndexedEscrow`] for every vault
    /// the bundle touches (fresh vaults are created by `initialize`
    /// and need no snapshot).
    MissingSnapshot,
}

/// What a simulated bundle action produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulatedOutcome {
    /// The action would execute; the predicted post-state and amounts
    /// on the [`SimulatedAction`] apply.
    Executed,
    /// The action would fail: the gate rejects it with this exact
    /// [`EscrowError`] — see [`EscrowError::code`] for the stable
    /// numeric code. Simulation stops here (atomicity).
    Failed(EscrowError),
    /// Not attempted (see [`SimulatedSkipReason`]).
    Skipped(SimulatedSkipReason),
}

/// One event the simulated action would emit, in `seq` order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatedEvent {
    /// The event kind name (e.g. `"Initialized"`, `"Funded"`,
    /// `"Released"`).
    pub kind: String,
    pub from: EscrowState,
    pub to: EscrowState,
    /// Taker payout carried by the event (`Released` only).
    pub payout: u64,
    /// Protocol fee carried by the event (`Released` only).
    pub fee: u64,
}

/// The predicted outcome of one bundle action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatedAction {
    /// Which escrow this instruction targets (the vault PDA).
    pub escrow_id: [u8; 32],
    /// The program-side instruction name (`"initialize"`, `"fund"`,
    /// `"release"`).
    pub instruction: &'static str,
    pub outcome: SimulatedOutcome,
    /// Post-action state when executed; pre-action state otherwise
    /// (a failed action changes nothing — the AV-76 no-mutation
    /// guarantee — so pre == post on failure).
    pub state: EscrowState,
    /// Cumulative released amount after the action.
    pub released: u64,
    /// Cumulative refunded amount after the action (`0` on this
    /// lifecycle line — `initialize -> fund -> release` never refunds;
    /// the field exists so the dry-run shape matches the keeper's
    /// other reports).
    pub refunded: u64,
    /// This action's taker payout (`release` only).
    pub payout: u64,
    /// This action's protocol fee (`release` only).
    pub fee: u64,
    /// Events the action would emit, in `seq` order (captured on the
    /// simulation clone — zero leakage into the caller's escrows).
    pub events: Vec<SimulatedEvent>,
}

impl SimulatedAction {
    fn failed(
        action: &BundledAction,
        error: EscrowError,
        state: EscrowState,
        released: u64,
    ) -> Self {
        Self {
            escrow_id: action.escrow_id,
            instruction: action.instruction,
            outcome: SimulatedOutcome::Failed(error),
            state,
            released,
            refunded: 0,
            payout: 0,
            fee: 0,
            events: Vec::new(),
        }
    }

    fn skipped(action: &BundledAction, reason: SimulatedSkipReason) -> Self {
        Self {
            escrow_id: action.escrow_id,
            instruction: action.instruction,
            outcome: SimulatedOutcome::Skipped(reason),
            // Unknown without a snapshot; `Uninitialized` is the honest
            // "no information" marker here, documented as such.
            state: EscrowState::Uninitialized,
            released: 0,
            refunded: 0,
            payout: 0,
            fee: 0,
            events: Vec::new(),
        }
    }
}

/// The dry-run prediction for a whole [`ExecutionBundle`]: one
/// [`SimulatedAction`] per bundle action, in bundle order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSimulation {
    /// The simulated bundle's id.
    pub bundle_id: String,
    /// The `at` the simulation ran against (the state machine's
    /// `now` for gate checks).
    pub at: u64,
    pub actions: Vec<SimulatedAction>,
}

impl BundleSimulation {
    /// `true` iff every action would execute — the keeper's green
    /// light to submit.
    pub fn all_ok(&self) -> bool {
        self.actions
            .iter()
            .all(|a| a.outcome == SimulatedOutcome::Executed)
    }

    /// The first action that would fail, if any.
    pub fn failed_action(&self) -> Option<&SimulatedAction> {
        self.actions.iter().find(|a| {
            matches!(a.outcome, SimulatedOutcome::Failed(_))
        })
    }

    fn hex32(b: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for byte in b {
            s.push(HEX[(byte >> 4) as usize] as char);
            s.push(HEX[(byte & 0x0f) as usize] as char);
        }
        s
    }

    /// Hand-serialized JSON (the crate is dependency-free).
    /// Deterministic field order; a failed action carries
    /// `"error":{"name":"…","code":N}` and every later action
    /// `"outcome":"skipped"`.
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push_str("{\"bundle_id\":\"");
        s.push_str(&self.bundle_id);
        s.push_str("\",\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"all_ok\":");
        s.push_str(if self.all_ok() { "true" } else { "false" });
        s.push_str(",\"actions\":[");
        for (i, a) in self.actions.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&Self::hex32(&a.escrow_id));
            s.push_str("\",\"instruction\":\"");
            s.push_str(a.instruction);
            s.push_str("\",\"outcome\":\"");
            match &a.outcome {
                SimulatedOutcome::Executed => s.push_str("executed"),
                SimulatedOutcome::Failed(_) => s.push_str("failed"),
                SimulatedOutcome::Skipped(_) => s.push_str("skipped"),
            }
            s.push('"');
            match &a.outcome {
                SimulatedOutcome::Failed(e) => {
                    s.push_str(",\"error\":{\"name\":\"");
                    s.push_str(&format!("{:?}", e));
                    s.push_str("\",\"code\":");
                    s.push_str(&e.code().to_string());
                    s.push('}');
                }
                SimulatedOutcome::Skipped(reason) => {
                    s.push_str(",\"skip_reason\":\"");
                    s.push_str(match reason {
                        SimulatedSkipReason::BundleAborted => "bundle_aborted",
                        SimulatedSkipReason::MissingSnapshot => "missing_snapshot",
                    });
                    s.push('"');
                }
                SimulatedOutcome::Executed => {}
            }
            s.push_str(",\"state\":\"");
            s.push_str(&format!("{:?}", a.state));
            s.push_str("\",\"released\":");
            s.push_str(&a.released.to_string());
            s.push_str(",\"refunded\":");
            s.push_str(&a.refunded.to_string());
            s.push_str(",\"payout\":");
            s.push_str(&a.payout.to_string());
            s.push_str(",\"fee\":");
            s.push_str(&a.fee.to_string());
            s.push_str(",\"events\":[");
            for (j, e) in a.events.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                s.push_str("{\"kind\":\"");
                s.push_str(&e.kind);
                s.push_str("\",\"from\":\"");
                s.push_str(&format!("{:?}", e.from));
                s.push_str("\",\"to\":\"");
                s.push_str(&format!("{:?}", e.to));
                s.push_str("\",\"payout\":");
                s.push_str(&e.payout.to_string());
                s.push_str(",\"fee\":");
                s.push_str(&e.fee.to_string());
                s.push('}');
            }
            s.push_str("]}");
        }
        s.push_str("]}");
        s
    }
}

/// Dry-run an [`ExecutionBundle`] without touching anything real.
///
/// Each action executes in bundle order on a per-escrow
/// [`IndexedEscrow`] clone seeded from `watched` (`initialize`
/// actions create a fresh vault — they need no snapshot). The
/// caller's `watched` snapshots are never mutated and no events leak
/// anywhere: every transition — including its event log — happens on
/// the clone, following the AV-76 all-or-nothing convention.
///
/// The first action whose gate rejects it ends the simulation with
/// [`SimulatedOutcome::Failed`] carrying the exact [`EscrowError`]
/// (and its stable [`code`](EscrowError::code)); every later action
/// is [`SimulatedOutcome::Skipped`] (`bundle_aborted`) because a real
/// submission would abort the whole transaction there. A
/// non-`initialize` action with no snapshot in `watched` is skipped
/// (`missing_snapshot`) — the keeper must pass the current snapshot
/// for every vault the bundle touches.
///
/// `at` is the state machine's `now` for gate checks (timelock,
/// expiry). It defaults to the bundle's own `at` when the caller
/// passes `bundle.at`; pass a newer timestamp to dry-run "what if I
/// submit this bundle later".
pub fn simulate_bundle(
    bundle: &ExecutionBundle,
    watched: &[IndexedEscrow],
    at: u64,
) -> BundleSimulation {
    let mut sim = BundleSimulation {
        bundle_id: bundle.bundle_id.clone(),
        at,
        actions: Vec::with_capacity(bundle.actions.len()),
    };
    // Per-escrow working clones, in first-seen order. Only these are
    // ever mutated.
    let mut working: Vec<IndexedEscrow> = Vec::new();
    let mut aborted = false;
    for action in &bundle.actions {
        if aborted {
            sim.actions.push(SimulatedAction::skipped(
                action,
                SimulatedSkipReason::BundleAborted,
            ));
            continue;
        }
        let simulated = simulate_one(bundle, action, watched, &mut working, at);
        if matches!(simulated.outcome, SimulatedOutcome::Failed(_)) {
            aborted = true;
        }
        sim.actions.push(simulated);
    }
    sim
}

/// Simulate one bundle action against the per-escrow working clones.
fn simulate_one(
    bundle: &ExecutionBundle,
    action: &BundledAction,
    watched: &[IndexedEscrow],
    working: &mut Vec<IndexedEscrow>,
    at: u64,
) -> SimulatedAction {
    // Resolve the working clone for this escrow, creating it on first
    // touch. Returns the index into `working`, or a complete
    // `SimulatedAction` when the action is fully resolved during
    // setup (fresh `initialize`, missing snapshot, contradictory
    // input).
    let work_idx: usize = match working.iter().position(|w| w.escrow_id() == action.escrow_id) {
        Some(i) => i,
        None => {
            if action.kind == BatchActionKind::Initialize {
                // A fresh vault: the scan lists `initialize` only for
                // not-created items, so an existing snapshot here
                // means the bundle contradicts the watch list — the
                // chain would reject the duplicate create.
                if watched.iter().any(|w| w.escrow_id() == action.escrow_id) {
                    return SimulatedAction::failed(
                        action,
                        EscrowError::InvalidStateTransition,
                        EscrowState::Uninitialized,
                        0,
                    );
                }
                let fresh = IndexedEscrow::initialize(
                    bundle.caller,
                    action.taker.unwrap_or([0u8; 32]),
                    action.amount,
                    action.expires_at,
                    action.escrow_id,
                    at,
                );
                match fresh {
                    Ok(w) => {
                        let events: Vec<SimulatedEvent> = w
                            .events()
                            .iter()
                            .map(|e| SimulatedEvent {
                                kind: format!("{:?}", e.kind),
                                from: e.from,
                                to: e.to,
                                payout: e.amounts.payout,
                                fee: e.amounts.fee,
                            })
                            .collect();
                        let simulated = SimulatedAction {
                            escrow_id: action.escrow_id,
                            instruction: action.instruction,
                            outcome: SimulatedOutcome::Executed,
                            state: w.inner().state(),
                            released: w.inner().released_amount(),
                            refunded: 0,
                            payout: 0,
                            fee: 0,
                            events,
                        };
                        working.push(w);
                        return simulated;
                    }
                    Err(e) => {
                        return SimulatedAction::failed(
                            action,
                            e,
                            EscrowState::Uninitialized,
                            0,
                        )
                    }
                }
            } else {
                match watched.iter().find(|w| w.escrow_id() == action.escrow_id) {
                    Some(snap) => {
                        working.push(snap.clone());
                        working.len() - 1
                    }
                    None => {
                        return SimulatedAction::skipped(
                            action,
                            SimulatedSkipReason::MissingSnapshot,
                        )
                    }
                }
            }
        }
    };
    let work = &mut working[work_idx];
    let events_before = work.events().len();
    let pre_state = work.inner().state();
    let pre_released = work.inner().released_amount();

    // Apply the action to the clone. On failure the state machine
    // leaves the escrow untouched (AV-76), so pre-state == post-state.
    let result: Result<(u64, u64), EscrowError> = match action.kind {
        BatchActionKind::Initialize => {
            // Already created above on first touch; a second
            // `initialize` for the same escrow in one bundle is a
            // caller bug — the chain would reject the duplicate.
            Err(EscrowError::InvalidStateTransition)
        }
        BatchActionKind::Fund => work.fund(bundle.caller, at).map(|()| (0, 0)),
        BatchActionKind::Release => {
            let payout_to = work.inner().taker();
            work.release(bundle.caller, action.amount, bundle.mint, payout_to, at)
        }
    };

    let (payout, fee) = match result {
        Ok((p, f)) => (p, f),
        Err(e) => return SimulatedAction::failed(action, e, pre_state, pre_released),
    };

    let events: Vec<SimulatedEvent> = work.events()[events_before..]
        .iter()
        .map(|e| SimulatedEvent {
            kind: format!("{:?}", e.kind),
            from: e.from,
            to: e.to,
            payout: e.amounts.payout,
            fee: e.amounts.fee,
        })
        .collect();
    SimulatedAction {
        escrow_id: action.escrow_id,
        instruction: action.instruction,
        outcome: SimulatedOutcome::Executed,
        state: work.inner().state(),
        released: work.inner().released_amount(),
        refunded: 0,
        payout,
        fee,
        events,
    }
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
            vault_derivation: None,
        }
    }

    fn funded(initializer: [u8; 32], mint: Option<[u8; 32]>) -> Escrow {
        let mut e = Escrow::initialize(initializer, BOB, AMOUNT, EXPIRES).unwrap();
        if let Some(m) = mint {
            e = e.with_mint(m).unwrap();
        }
        e.fund(initializer, NOW).unwrap();
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
        e.fund(ALICE, NOW).unwrap();
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
            "{{\"bundle_id\":\"bundle-0\",\"mint\":null,\"caller\":\"{}\",\"caller_role\":\"initializer\",\"actions\":[{{\"escrow_id\":\"{}\",\"instruction\":\"initialize\",\"discriminator\":\"{}\",\"caller_role\":\"initializer\",\"args\":{{\"taker\":\"{}\",\"amount\":1000000,\"expires_at\":1800000000}},\"accounts\":[{{\"pubkey\":\"{}\",\"role\":\"vault\",\"signer\":false,\"writable\":true,\"alt_index\":0}},{{\"pubkey\":\"{}\",\"role\":\"initializer\",\"signer\":true,\"writable\":true,\"alt_index\":null}}],\"reason\":\"not_created\"}}],\"jito_tip\":null,\"action_count\":1,\"alt_table\":[\"{}\"],\"at\":1750000000,\"scanned\":1,\"estimated_priority_fee\":null}}",
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

    /// AV-89: the bundle dry-run report passes through the caller's
    /// stamped priority-fee recommendation — the fee line the signer
    /// pairs with the AV-88 CU passthrough. Unstamped bundles render
    /// `null` (pinned above); stamping never disturbs the rest of the
    /// JSON, and stamping is deterministic.
    #[test]
    fn priority_fee_passthrough_renders_in_json() {
        use crate::priority_fee::{Confidence, PriorityFeeConfig, PriorityFeeOracle};

        let mut oracle = PriorityFeeOracle::new(PriorityFeeConfig::default());
        for s in [900u64, 1_100, 1_000, 1_050] {
            oracle.observe(s);
        }
        // Thin sample count: the flagged fallback, not a silent EWMA.
        let rec = oracle.recommend();
        assert_eq!(rec.confidence, Confidence::Low);
        assert!(rec.fallback);

        let bundles = bundle_execution(&scan_batch_lifecycle(&[watch(ID1, None, ALICE)], NOW));
        assert_eq!(bundles.len(), 1);
        let stamped = bundles[0].clone().with_priority_fee(rec);
        let json = stamped.to_json();
        let want = format!(
            "\"estimated_priority_fee\":{{\"micro_lamports_per_cu\":{},\"confidence\":\"low\",\"fallback\":true}}",
            rec.recommended_micro_lamports_per_cu
        );
        assert!(json.contains(&want), "fee line missing: {json}");
        // Deterministic: same stamp, same bytes.
        assert_eq!(json, bundles[0].clone().with_priority_fee(rec).to_json());
        // The stamp touches only the fee line.
        let unstamped = bundles[0].to_json();
        assert_eq!(
            json.replace(&want, "\"estimated_priority_fee\":null"),
            unstamped
        );
    }

    /// AV-98: the opt-in Jito tip on an execution bundle — the tip
    /// instruction is built from the AV-31 system-transfer constructor,
    /// renders after the escrow actions (it goes LAST at submit time),
    /// and the keeper report annotates the tip amount + recipient.
    #[test]
    fn jito_tip_renders_after_actions_and_goes_last() {
        let bundles = bundle_execution(&scan_batch_lifecycle(&[watch(ID1, None, ALICE)], NOW));
        assert_eq!(bundles.len(), 1);
        const TIP: u64 = 10_000;
        const RECIPIENT: [u8; 32] = [0xE0; 32];
        let stamped = bundles[0].clone().with_jito_tip(TIP, RECIPIENT).unwrap();
        let tip = stamped.jito_tip.as_ref().unwrap();
        // The assembled instruction: system program, payer -> recipient,
        // 12-byte transfer encoding carrying the tip amount.
        assert_eq!(tip.lamports(), TIP);
        assert_eq!(tip.recipient(), RECIPIENT);
        assert_eq!(tip.instruction.program_id, crate::cpi::system_program_id());
        assert_eq!(tip.instruction.amount(), Some(TIP));
        assert_eq!(tip.instruction.accounts.len(), 2);
        assert_eq!(tip.instruction.accounts[0].pubkey, ALICE);
        assert!(tip.instruction.accounts[0].is_signer);
        assert_eq!(tip.instruction.accounts[1].pubkey, RECIPIENT);
        assert!(!tip.instruction.accounts[1].is_signer);
        // The tip is bundle overhead, not an escrow action.
        assert_eq!(stamped.action_count(), 1);

        let json = stamped.to_json();
        // Rendered after the actions array (submit-time: last
        // instruction), before action_count.
        let tip_pos = json.find("\"jito_tip\"").unwrap();
        let actions_end = json.find("\"action_count\"").unwrap();
        let last_reason = json.rfind("\"reason\"").unwrap();
        assert!(tip_pos > last_reason, "tip must render after every action: {json}");
        assert!(tip_pos < actions_end, "tip must render before action_count: {json}");
        let want = format!(
            "\"jito_tip\":{{\"lamports\":10000,\"recipient\":\"{}\",\"instruction\":{{\"program_id\":\"{}\",\"accounts\":[{{\"pubkey\":\"{}\",\"signer\":true,\"writable\":true}},{{\"pubkey\":\"{}\",\"signer\":false,\"writable\":true}}],\"data\":\"02000000{}\"}}}},",
            hex_of(0xE0),
            hex_of(0x00),
            hex_of(0xAA),
            hex_of(0xE0),
            // 10_000u64 LE, 8 bytes, after the 4-byte index prefix.
            "1027000000000000",
        );
        assert!(json.contains(&want), "tip instruction JSON wrong: {json}");
        // Deterministic: same stamp, same bytes; the stamp touches only
        // the tip line.
        assert_eq!(json, bundles[0].clone().with_jito_tip(TIP, RECIPIENT).unwrap().to_json());
        let unstamped = bundles[0].to_json();
        assert_eq!(json.replace(&want[..want.len() - 1], "\"jito_tip\":null"), unstamped);
        // Unstamped bundles render null.
        assert!(unstamped.contains("\"jito_tip\":null"), "missing null tip: {unstamped}");
    }

    #[test]
    fn jito_tip_config_validation_rejects_degenerate_input() {
        let bundles = bundle_execution(&scan_batch_lifecycle(&[watch(ID1, None, ALICE)], NOW));
        let b = &bundles[0];
        const RECIPIENT: [u8; 32] = [0xE0; 32];
        // Zero amount: a no-op instruction that still costs a signature.
        assert_eq!(
            b.clone().with_jito_tip(0, RECIPIENT).unwrap_err(),
            TipConfigError::ZeroTipAmount
        );
        // Zero recipient: the lamports would be burned.
        assert_eq!(
            b.clone().with_jito_tip(1_000, [0u8; 32]).unwrap_err(),
            TipConfigError::ZeroRecipient
        );
        // Recipient == caller (the bundle's payer): a self-transfer the
        // system program rejects.
        assert_eq!(
            b.clone().with_jito_tip(1_000, ALICE).unwrap_err(),
            TipConfigError::TipRecipientIsPayer
        );
        // A failed stamp leaves the bundle untouched.
        assert!(b.jito_tip.is_none());
        // The report-level config carries the same validation.
        assert_eq!(
            JitoTipConfig::new(0, RECIPIENT).unwrap_err(),
            TipConfigError::ZeroTipAmount
        );
        assert_eq!(
            JitoTipConfig::new(1_000, [0u8; 32]).unwrap_err(),
            TipConfigError::ZeroRecipient
        );
        let cfg = JitoTipConfig::new(1_000, RECIPIENT).unwrap();
        assert_eq!(cfg.lamports, 1_000);
        assert_eq!(cfg.recipient, RECIPIENT);
        // Zero payer on a hand-built bundle (the scan always stamps a
        // real caller).
        let mut zero_caller = b.clone();
        zero_caller.caller = [0u8; 32];
        assert_eq!(
            zero_caller.with_jito_tip(1_000, RECIPIENT).unwrap_err(),
            TipConfigError::ZeroPayer
        );
    }

    // ---------------------------------------------------------------
    // AV-102: bundle simulation tests.
    // ---------------------------------------------------------------

    /// Build `IndexedEscrow` snapshots from plain escrows (the
    /// keeper's watch-list conversion via `IndexedEscrow::wrap`).
    fn indexed_watch(items: &[([u8; 32], Escrow)]) -> Vec<IndexedEscrow> {
        items
            .iter()
            .map(|(id, e)| IndexedEscrow::wrap(*id, e.clone()))
            .collect()
    }

    #[test]
    fn simulate_initialize_then_fund_predicts_state_and_events() {
        // One not-created vault: the bundle holds `initialize`.
        let items = vec![watch(ID1, None, ALICE)];
        let report = scan_batch_lifecycle(&items, NOW);
        let bundles = bundle_execution(&report);
        assert_eq!(bundles.len(), 1);
        let sim = simulate_bundle(&bundles[0], &[], NOW);
        assert!(sim.all_ok());
        assert_eq!(sim.actions.len(), 1);
        let a = &sim.actions[0];
        assert_eq!(a.instruction, "initialize");
        assert_eq!(a.outcome, SimulatedOutcome::Executed);
        // A fresh initialize leaves the escrow `Uninitialized`
        // (funding is a separate step) with no funds moved.
        assert_eq!(a.state, EscrowState::Uninitialized);
        assert_eq!(a.released, 0);
        assert_eq!(a.payout, 0);
        assert_eq!(a.fee, 0);
        assert_eq!(a.events.len(), 1);
        assert_eq!(a.events[0].kind, "Initialized");
        // The dry-run JSON carries the prediction.
        let json = sim.to_json();
        assert!(json.contains("\"all_ok\":true"));
        assert!(json.contains("\"instruction\":\"initialize\""));
        assert!(json.contains("\"outcome\":\"executed\""));
    }

    #[test]
    fn simulate_fund_and_release_end_to_end() {
        // Funded escrow past its timelock: the bundle holds `release`.
        let e = funded(ALICE, None);
        let items = vec![watch(ID1, Some(e.clone()), ALICE)];
        let report = scan_batch_lifecycle(&items, NOW);
        let bundles = bundle_execution(&report);
        assert_eq!(bundles.len(), 1);
        // Sanity: the scan listed a release for the funded escrow.
        assert!(bundles[0].actions.iter().any(|a| a.instruction == "release"));

        let watched = indexed_watch(&[(ID1, e)]);
        let sim = simulate_bundle(&bundles[0], &watched, NOW);
        assert!(sim.all_ok());
        let a = sim.actions.iter().find(|a| a.instruction == "release").unwrap();
        assert_eq!(a.outcome, SimulatedOutcome::Executed);
        assert_eq!(a.state, EscrowState::Released);
        assert_eq!(a.released, AMOUNT);
        assert_eq!(a.payout + a.fee, AMOUNT);
        assert_eq!(a.refunded, 0);
        assert_eq!(a.events.len(), 1);
        assert_eq!(a.events[0].kind, "Released");
        assert_eq!(a.events[0].payout, a.payout);
    }

    #[test]
    fn simulate_stops_at_first_failure_with_precise_error() {
        // Hand-build a bundle whose fund must fail: the escrow is
        // already `Funded`, so a second `fund` hits the state gate.
        // The scan would never list this — the test pins the
        // failure-prediction path directly.
        let e = funded(ALICE, None);
        let bundle = ExecutionBundle {
            bundle_id: "bundle-0".to_string(),
            mint: None,
            caller: ALICE,
            caller_role: "initializer",
            actions: vec![
                BundledAction {
                    escrow_id: ID1,
                    kind: BatchActionKind::Fund,
                    instruction: "fund",
                    discriminator: [0u8; 8],
                    caller_role: "initializer",
                    taker: None,
                    expires_at: 0,
                    amount: AMOUNT,
                    payout: 0,
                    fee: 0,
                    accounts: vec![],
                    reason: "unfunded",
                },
                BundledAction {
                    escrow_id: ID1,
                    kind: BatchActionKind::Release,
                    instruction: "release",
                    discriminator: [0u8; 8],
                    caller_role: "initializer",
                    taker: None,
                    expires_at: 0,
                    amount: AMOUNT,
                    payout: 0,
                    fee: 0,
                    accounts: vec![],
                    reason: "releasable",
                },
            ],
            alt_table: vec![],
            at: NOW,
            scanned: 1,
            estimated_priority_fee: None,
            jito_tip: None,
        };
        let watched = indexed_watch(&[(ID1, e)]);
        let sim = simulate_bundle(&bundle, &watched, NOW);
        assert!(!sim.all_ok());
        // The fund action failed with the state gate's exact error.
        let failed = sim.failed_action().expect("one failure");
        assert_eq!(failed.instruction, "fund");
        match failed.outcome {
            SimulatedOutcome::Failed(err) => {
                assert_eq!(err, EscrowError::InvalidStateTransition);
                assert_eq!(err.code(), EscrowError::InvalidStateTransition.code());
            }
            _ => panic!("expected Failed"),
        }
        // The release was never attempted (atomicity).
        assert_eq!(
            sim.actions[1].outcome,
            SimulatedOutcome::Skipped(SimulatedSkipReason::BundleAborted)
        );
        let json = sim.to_json();
        assert!(json.contains("\"all_ok\":false"));
        assert!(json.contains("\"outcome\":\"failed\""));
        assert!(json.contains("\"name\":\"InvalidStateTransition\""));
        assert!(json.contains("\"outcome\":\"skipped\""));
        assert!(json.contains("\"skip_reason\":\"bundle_aborted\""));
    }

    #[test]
    fn simulate_never_mutates_watched_or_leaks_events() {
        let e = funded(ALICE, None);
        let items = vec![watch(ID1, Some(e.clone()), ALICE)];
        let report = scan_batch_lifecycle(&items, NOW);
        let bundles = bundle_execution(&report);
        let mut watched = indexed_watch(&[(ID1, e)]);
        let events_before = watched[0].events().len();
        let state_before = watched[0].inner().state();
        let _ = simulate_bundle(&bundles[0], &watched, NOW);
        // The caller's snapshots are bit-identical afterwards.
        assert_eq!(watched[0].inner().state(), state_before);
        assert_eq!(watched[0].events().len(), events_before);
        assert_eq!(watched.len(), 1);
        // And a second simulation sees the same starting point
        // (idempotent dry-run).
        let sim2 = simulate_bundle(&bundles[0], &watched, NOW);
        assert!(sim2.all_ok());
    }

    #[test]
    fn simulate_missing_snapshot_skips_with_reason() {
        let items = vec![watch(ID1, Some(funded(ALICE, None)), ALICE)];
        let report = scan_batch_lifecycle(&items, NOW);
        let bundles = bundle_execution(&report);
        // No snapshots at all: non-initialize actions cannot run.
        let sim = simulate_bundle(&bundles[0], &[], NOW);
        assert!(!sim.all_ok());
        assert!(sim.actions.iter().all(|a| matches!(
            a.outcome,
            SimulatedOutcome::Skipped(SimulatedSkipReason::MissingSnapshot)
        )));
        assert!(sim.to_json().contains("\"skip_reason\":\"missing_snapshot\""));
    }

    #[test]
    fn wrap_starts_with_empty_event_log() {
        let e = funded(ALICE, None);
        let w = IndexedEscrow::wrap(ID1, e);
        assert_eq!(w.escrow_id(), ID1);
        assert!(w.events().is_empty());
        assert_eq!(w.inner().state(), EscrowState::Funded);
    }
}
