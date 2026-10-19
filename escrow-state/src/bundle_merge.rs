//! Keeper multi-bundle merge submission (AV-145).
//!
//! [`merge_bundles`] packs several AV-61 [`ExecutionBundle`]s (one per
//! `(mint, caller)`) into [`MergeSession`]s — one multisig proposal /
//! CLI signing session each. Pure logic, zero dependencies; the merge
//! is a dry-run (reads the bundles, mutates nothing).
//!
//! # What the merge does
//!
//! 1. **Deterministic order.** Bundles sort by `(mint, caller)`
//!    (native-SOL first) — the same order [`bundle_execution`]
//!    emits — and actions keep their bundle order inside the merge.
//! 2. **CU budgeting.** Every action gets a compute-unit estimate via
//!    [`estimate_instruction_cu`] (AV-88); actions accumulate into a
//!    session until the next action would exceed
//!    [`CU_MAX_PER_TRANSACTION`] (1.4M), at which point a new session
//!    starts — the automatic split. An action whose instruction has no
//!    CU table row is a [`MergeError::UnknownInstruction`] (never
//!    silently zero, the AV-88 convention).
//! 3. **Cross-bundle ALT dedup.** Each session builds one merged
//!    `alt_table` from its actions using the batch.rs AV-37
//!    convention — non-signer accounts only, first-seen order, capped
//!    at 256 — and every action's `alt_index` is remapped into it (an
//!    account that falls outside the cap renders `alt_index: None`
//!    and travels as a static account meta).
//! 4. **Submission output.** [`MergeSession::signable_messages`]
//!    compiles every action into a signable v0 message (base64, AV-71)
//!    against the session's merged table; [`MergeSession::to_json`]
//!    renders the deterministic session JSON carrying the merged
//!    bundle references.
//!
//! # Dry-run
//!
//! Like the scan and the bundler: [`merge_bundles`] only reads its
//! input. It emits no events, touches no clock, and mutates nothing —
//! the input `&[ExecutionBundle]` is never written to. Amounts are as
//! of the bundles' `at`; the operator submits the sessions, then
//! re-scans.
//!
//! [`ExecutionBundle`]: crate::execution_bundle::ExecutionBundle
//! [`bundle_execution`]: crate::execution_bundle::bundle_execution
//! [`estimate_instruction_cu`]: crate::cu_estimate::estimate_instruction_cu
//! [`CU_MAX_PER_TRANSACTION`]: crate::cu_estimate::CU_MAX_PER_TRANSACTION

use crate::cu_estimate::{estimate_instruction_cu, CU_MAX_PER_TRANSACTION};
use crate::execution_bundle::{BundledAction, ExecutionBundle};
use crate::tx_message::{signable_message_v0_base64, TxMessageError};
use std::collections::BTreeMap;

/// ALT table cap — the batch.rs AV-37 convention (`alt_table`:
/// deduped non-signer accounts, first-seen order, capped at 256).
const ALT_TABLE_CAP: usize = 256;

/// Why a bundle merge failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeError {
    /// An action's instruction has no CU-table row, so the session
    /// cannot be budgeted — a build-time coverage failure, never
    /// silently estimated as zero (the AV-88 convention).
    UnknownInstruction(&'static str),
}

/// A reference to one source bundle merged into a session.
///
/// The deterministic JSON carries these so the operator can trace
/// every session action back to the AV-61 bundle (and the batch
/// report) it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleRef {
    /// The source bundle's id (`"bundle-0"`, …).
    pub bundle_id: String,
    /// The source bundle's mint (`None` = native SOL).
    pub mint: Option<[u8; 32]>,
    /// The source bundle's caller (the signing key).
    pub caller: [u8; 32],
    /// How many of this bundle's actions landed in this session (a
    /// bundle split across the 1.4M boundary appears in several
    /// sessions).
    pub action_count: usize,
}

/// One action inside a merged session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedAction {
    /// The source bundle's id.
    pub bundle_id: String,
    /// The action, with `alt_index` remapped into the session's
    /// merged `alt_table`.
    pub action: BundledAction,
    /// The AV-88 compute-unit estimate for this action.
    pub estimated_cu: u64,
}

/// Runtime parameters for signable-message compilation (AV-71).
///
/// These are only known at submit time — the merge itself is a
/// dry-run — so message compilation is a separate step from merging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageParams {
    /// The escrow program id the instructions target.
    pub program_id: [u8; 32],
    /// A recent blockhash for the message header.
    pub recent_blockhash: [u8; 32],
    /// The on-chain address lookup table key the session's
    /// `alt_table` was (or will be) extended into.
    pub address_table_key: [u8; 32],
}

/// One compiled signable message from a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMessage {
    /// The source bundle's id.
    pub bundle_id: String,
    /// The escrow (vault) the instruction targets.
    pub escrow_id: [u8; 32],
    /// The program instruction name.
    pub instruction: &'static str,
    /// The signable v0 message, base64 (AV-71).
    pub message_base64: String,
}

impl SessionMessage {
    /// Deterministic JSON for one message.
    fn to_json(&self) -> String {
        let mut s = String::with_capacity(128 + self.message_base64.len());
        s.push_str("{\"bundle_id\":\"");
        s.push_str(&self.bundle_id);
        s.push_str("\",\"escrow_id\":\"");
        s.push_str(&hex32(&self.escrow_id));
        s.push_str("\",\"instruction\":\"");
        s.push_str(self.instruction);
        s.push_str("\",\"message_base64\":\"");
        s.push_str(&self.message_base64);
        s.push_str("\"}");
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

/// A multisig/CLI submission session: the actions to sign in one
/// signing run, their merged ALT table, and the CU budget line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeSession {
    /// Stable within one merge: `"session-0"`, `"session-1"`, … in
    /// deterministic bundle order.
    pub session_id: String,
    /// The source bundles contributing actions, in first-seen order.
    pub bundles: Vec<BundleRef>,
    /// The session's actions in deterministic order.
    pub actions: Vec<MergedAction>,
    /// The cross-bundle deduped ALT table (batch.rs convention).
    pub alt_table: Vec<[u8; 32]>,
    /// Σ estimated compute units across the session's actions.
    pub total_cu: u64,
    /// True when the session alone exceeds [`CU_MAX_PER_TRANSACTION`]
    /// — a single action (or bundle) larger than one transaction; the
    /// operator must split it by hand (the merge never silently drops
    /// an action to fit).
    pub over_budget: bool,
    /// The bundles' scan time (max across merged bundles): amounts
    /// are as of this timestamp.
    pub at: u64,
}

impl MergeSession {
    /// Number of actions in the session.
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    /// Compile every action into a signable v0 message (base64),
    /// resolving ALT-eligible accounts against the session's merged
    /// `alt_table` (AV-71). Pure read — the session is borrowed.
    pub fn signable_messages(
        &self,
        params: &MessageParams,
    ) -> Result<Vec<SessionMessage>, TxMessageError> {
        let mut out = Vec::with_capacity(self.actions.len());
        for merged in &self.actions {
            let message_base64 = signable_message_v0_base64(
                params.program_id,
                &merged.action,
                params.recent_blockhash,
                params.address_table_key,
                &self.alt_table,
            )?;
            out.push(SessionMessage {
                bundle_id: merged.bundle_id.clone(),
                escrow_id: merged.action.escrow_id,
                instruction: merged.action.instruction,
                message_base64,
            });
        }
        Ok(out)
    }

    /// Deterministic JSON for the session: id, CU line, bundle
    /// references, actions (with remapped `alt_index`), and the
    /// merged `alt_table`. Hand-written, fixed field order.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(256 + self.actions.len() * 256);
        s.push_str("{\"session_id\":\"");
        s.push_str(&self.session_id);
        s.push_str("\",\"total_cu\":");
        s.push_str(&self.total_cu.to_string());
        s.push_str(",\"over_budget\":");
        s.push_str(if self.over_budget { "true" } else { "false" });
        s.push_str(",\"action_count\":");
        s.push_str(&self.actions.len().to_string());
        s.push_str(",\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"bundles\":[");
        for (i, b) in self.bundles.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"bundle_id\":\"");
            s.push_str(&b.bundle_id);
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
            s.push_str("\",\"action_count\":");
            s.push_str(&b.action_count.to_string());
            s.push('}');
        }
        s.push_str("],\"actions\":[");
        for (i, m) in self.actions.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"bundle_id\":\"");
            s.push_str(&m.bundle_id);
            s.push_str("\",\"escrow_id\":\"");
            s.push_str(&hex32(&m.action.escrow_id));
            s.push_str("\",\"instruction\":\"");
            s.push_str(m.action.instruction);
            s.push_str("\",\"estimated_cu\":");
            s.push_str(&m.estimated_cu.to_string());
            s.push_str(",\"alt_indexes\":[");
            for (j, acc) in m.action.accounts.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                match acc.alt_index {
                    Some(idx) => s.push_str(&idx.to_string()),
                    None => s.push_str("null"),
                }
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

    /// Deterministic JSON for the session *plus* the batch of
    /// signable v0 messages (AV-71) — the multisig/CLI submission
    /// packet. `params` carries the submit-time values (program id,
    /// blockhash, ALT key).
    pub fn to_json_with_messages(
        &self,
        params: &MessageParams,
    ) -> Result<String, TxMessageError> {
        let messages = self.signable_messages(params)?;
        let mut s = self.to_json();
        // Splice the messages array in before the closing brace.
        s.pop(); // '}'
        s.push_str(",\"messages\":[");
        for (i, m) in messages.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&m.to_json());
        }
        s.push_str("]}");
        Ok(s)
    }
}

/// Estimate one action's compute units (AV-88).
fn action_cu(action: &BundledAction) -> Result<u64, MergeError> {
    let signers = action.accounts.iter().filter(|a| a.signer).count();
    estimate_instruction_cu(action.instruction, action.accounts.len(), signers)
        .ok_or(MergeError::UnknownInstruction(action.instruction))
}

/// Merge several AV-61 execution bundles into multisig/CLI
/// submission sessions.
///
/// Bundles sort by `(mint, caller)`; actions accumulate into a
/// session until the next action would push the session past
/// [`CU_MAX_PER_TRANSACTION`], at which point a new session starts
/// (the automatic 1.4M split). Each session gets one cross-bundle
/// deduped ALT table (batch.rs convention) with remapped
/// `alt_index` values.
///
/// Pure read — the input bundles are borrowed, nothing mutates.
pub fn merge_bundles(bundles: &[ExecutionBundle]) -> Result<Vec<MergeSession>, MergeError> {
    // Deterministic bundle order: (mint, caller), native-SOL first.
    let mut order: Vec<usize> = (0..bundles.len()).collect();
    order.sort_by_key(|&i| (bundles[i].mint, bundles[i].caller));

    // Per-action CU estimates up front — a missing table row fails
    // the whole merge before any session is built.
    let mut cu_by_action: BTreeMap<(usize, usize), u64> = BTreeMap::new();
    for &bi in &order {
        for (ai, action) in bundles[bi].actions.iter().enumerate() {
            cu_by_action.insert((bi, ai), action_cu(action)?);
        }
    }

    let mut sessions: Vec<MergeSession> = Vec::new();
    // (session index, per-bundle action counts) for the open session.
    let mut open: Option<(MergeSession, BTreeMap<usize, usize>)> = None;

    let mut new_session = |id: usize| MergeSession {
        session_id: format!("session-{id}"),
        bundles: Vec::new(),
        actions: Vec::new(),
        alt_table: Vec::new(),
        total_cu: 0,
        over_budget: false,
        at: 0,
    };

    for &bi in &order {
        let bundle = &bundles[bi];
        for (ai, action) in bundle.actions.iter().enumerate() {
            let cu = cu_by_action[&(bi, ai)];
            let need_new = match &open {
                // A session always takes at least one action — an
                // action alone over budget still gets its own session
                // (flagged `over_budget`), never dropped.
                Some((s, _)) => !s.actions.is_empty() && s.total_cu + cu > CU_MAX_PER_TRANSACTION,
                None => true,
            };
            if need_new {
                if let Some((s, counts)) = open.take() {
                    sessions.push(finalize_session(s, bundles, &counts));
                }
                open = Some((new_session(sessions.len()), BTreeMap::new()));
            }
            let (s, counts) = open.as_mut().unwrap();
            *counts.entry(bi).or_insert(0) += 1;
            s.total_cu = s.total_cu.saturating_add(cu);
            s.at = s.at.max(bundle.at);
            s.actions.push(MergedAction {
                bundle_id: bundle.bundle_id.clone(),
                action: action.clone(),
                estimated_cu: cu,
            });
        }
    }
    if let Some((s, counts)) = open.take() {
        sessions.push(finalize_session(s, bundles, &counts));
    }
    Ok(sessions)
}

/// Finish a session: build the merged ALT table, remap `alt_index`,
/// attach bundle references, and flag over-budget sessions.
fn finalize_session(
    mut session: MergeSession,
    bundles: &[ExecutionBundle],
    counts: &BTreeMap<usize, usize>,
) -> MergeSession {
    // Cross-bundle dedup (batch.rs AV-37 convention): non-signer
    // accounts only, first-seen order, capped at 256.
    let mut alt_table: Vec<[u8; 32]> = Vec::new();
    for merged in &session.actions {
        for acc in &merged.action.accounts {
            if acc.signer {
                continue;
            }
            if !alt_table.contains(&acc.pubkey) && alt_table.len() < ALT_TABLE_CAP {
                alt_table.push(acc.pubkey);
            }
        }
    }
    // Remap every action's `alt_index` into the merged table. An
    // account outside the cap (table full) renders `None` and travels
    // as a static account meta — never a dangling index.
    for merged in &mut session.actions {
        for acc in &mut merged.action.accounts {
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
    session.alt_table = alt_table;
    // Bundle references in first-seen order.
    for (&bi, &count) in counts {
        let b = &bundles[bi];
        session.bundles.push(BundleRef {
            bundle_id: b.bundle_id.clone(),
            mint: b.mint,
            caller: b.caller,
            action_count: count,
        });
    }
    session.over_budget = session.total_cu > CU_MAX_PER_TRANSACTION;
    session
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod bundle_merge_tests {
    use super::*;
    use crate::batch::{
        BatchAccount, BatchActionKind, BatchItem, BatchItemOutcome, BatchLifecycleAction, BatchReport,
    };
    use crate::execution_bundle::bundle_execution;

    const PROGRAM_ID: [u8; 32] = [0x11; 32];
    const BLOCKHASH: [u8; 32] = [0x22; 32];
    const ALT_KEY: [u8; 32] = [0x33; 32];

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn acct(pubkey: [u8; 32], role: &'static str, signer: bool, writable: bool) -> BatchAccount {
        BatchAccount {
            pubkey,
            role,
            signer,
            writable,
            alt_index: None,
        }
    }

    /// Build a minimal batch report with `n` release actions for one
    /// (mint, caller), then bundle it via AV-61.
    fn report_with_releases(n: usize, mint: Option<[u8; 32]>, caller: [u8; 32]) -> BatchReport {
        let mut report = BatchReport {
            at: 1_750_000_000,
            scanned: n,
            items: Vec::new(),
            alt_table: Vec::new(),
        };
        for i in 0..n {
            let escrow_id = [(i as u8).wrapping_add(1), 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                             0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                             0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
            let vault = key(0x10 + i as u8);
            let action = BatchLifecycleAction {
                escrow_id,
                vault_address: None,
                kind: BatchActionKind::Release,
                mint,
                caller,
                caller_role: "initializer",
                taker: None,
                expires_at: 0,
                amount: 1_000_000,
                payout: 990_000,
                fee: 10_000,
                payout_legs: None,
                accounts: vec![
                    acct(vault, "vault", false, true),
                    acct(caller, "initializer", true, true),
                    acct(key(0xF0), "fee_recipient", false, true),
                ],
                reason: "releasable",
            };
            // The scan stamps alt_index values; mirror the AV-37 build
            // (dedup non-signers, first-seen, cap 256).
            for acc in [&vault, &key(0xF0)] {
                if !report.alt_table.contains(acc) && report.alt_table.len() < 256 {
                    report.alt_table.push(*acc);
                }
            }
            let mut action = action;
            for a in &mut action.accounts {
                if !a.signer {
                    a.alt_index = report.alt_table.iter().position(|k| *k == a.pubkey).map(|i| i as u8);
                }
            }
            report.items.push(BatchItem {
                escrow_id,
                outcome: BatchItemOutcome::Action(action),
            });
        }
        report
    }

    fn message_params() -> MessageParams {
        MessageParams {
            program_id: PROGRAM_ID,
            recent_blockhash: BLOCKHASH,
            address_table_key: ALT_KEY,
        }
    }

    #[test]
    fn merges_bundles_into_one_session() {
        let bundles = [
            bundle_execution(&report_with_releases(2, None, key(0x01))),
            bundle_execution(&report_with_releases(3, None, key(0x02))),
        ];
        let bundles: Vec<ExecutionBundle> =
            bundles.into_iter().flatten().collect();
        assert_eq!(bundles.len(), 2);

        let sessions = merge_bundles(&bundles).unwrap();
        // 5 small releases fit one session.
        assert_eq!(sessions.len(), 1);
        let s = &sessions[0];
        assert_eq!(s.session_id, "session-0");
        assert_eq!(s.action_count(), 5);
        assert!(!s.over_budget);
        assert_eq!(s.bundles.len(), 2);
        // Bundle refs carry the source identity.
        assert_eq!(s.bundles[0].action_count + s.bundles[1].action_count, 5);
        // CU is the Σ action estimates.
        let want_cu: u64 = s.actions.iter().map(|a| a.estimated_cu).sum();
        assert_eq!(s.total_cu, want_cu);
        assert!(s.total_cu > 0);
        // Cross-bundle dedup: the shared fee_recipient appears once.
        assert_eq!(s.alt_table.iter().filter(|k| **k == key(0xF0)).count(), 1);
    }

    #[test]
    fn auto_splits_past_1_4m_cu() {
        // One release ≈ 16k base + accounts; 100 of them exceed 1.4M.
        let bundles: Vec<ExecutionBundle> =
            bundle_execution(&report_with_releases(100, None, key(0x01)))
                .into_iter()
                .collect();
        let sessions = merge_bundles(&bundles).unwrap();
        assert!(sessions.len() > 1, "expected a split, got {}", sessions.len());
        for s in &sessions {
            assert!(!s.over_budget, "session {} over budget", s.session_id);
            assert!(s.total_cu <= CU_MAX_PER_TRANSACTION);
        }
        // No action lost across the split.
        let total: usize = sessions.iter().map(|s| s.action_count()).sum();
        assert_eq!(total, 100);
        // Session ids are stable and ordered.
        assert_eq!(sessions[0].session_id, "session-0");
        assert_eq!(sessions[1].session_id, "session-1");
    }

    #[test]
    fn alt_index_remaps_into_merged_table() {
        let bundles: Vec<ExecutionBundle> =
            bundle_execution(&report_with_releases(2, None, key(0x01)))
                .into_iter()
                .collect();
        let sessions = merge_bundles(&bundles).unwrap();
        let s = &sessions[0];
        // Every non-signer account's alt_index resolves into the
        // session table at the account's own pubkey.
        for m in &s.actions {
            for acc in &m.action.accounts {
                match (acc.signer, acc.alt_index) {
                    (true, None) => {}
                    (false, Some(idx)) => {
                        assert_eq!(s.alt_table[idx as usize], acc.pubkey);
                    }
                    (false, None) => panic!("non-signer lost its ALT index"),
                    (true, Some(_)) => panic!("signer carries an ALT index"),
                }
            }
        }
    }

    #[test]
    fn signable_messages_compile_against_merged_table() {
        let bundles: Vec<ExecutionBundle> =
            bundle_execution(&report_with_releases(2, None, key(0x01)))
                .into_iter()
                .collect();
        let sessions = merge_bundles(&bundles).unwrap();
        let messages = sessions[0].signable_messages(&message_params()).unwrap();
        assert_eq!(messages.len(), 2);
        for m in &messages {
            assert!(!m.message_base64.is_empty());
            assert_eq!(m.instruction, "release");
        }
        // The JSON submission packet carries bundle refs + messages.
        let json = sessions[0].to_json_with_messages(&message_params()).unwrap();
        assert!(json.contains("\"bundle_id\":\"bundle-0\""));
        assert!(json.contains("\"messages\":["));
        assert!(json.contains("\"message_base64\":\""));
        // Deterministic: same input renders byte-identical JSON.
        let again = sessions[0].to_json_with_messages(&message_params()).unwrap();
        assert_eq!(json, again);
    }

    #[test]
    fn empty_merge_yields_no_sessions() {
        let sessions = merge_bundles(&[]).unwrap();
        assert!(sessions.is_empty());
    }

    #[test]
    fn merge_is_dry_run() {
        let bundles: Vec<ExecutionBundle> =
            bundle_execution(&report_with_releases(3, None, key(0x01)))
                .into_iter()
                .collect();
        let before = bundles.clone();
        let _ = merge_bundles(&bundles).unwrap();
        assert_eq!(bundles, before, "merge must not mutate its input");
    }

    #[test]
    fn session_json_shape() {
        let bundles: Vec<ExecutionBundle> =
            bundle_execution(&report_with_releases(1, None, key(0x01)))
                .into_iter()
                .collect();
        let sessions = merge_bundles(&bundles).unwrap();
        let json = sessions[0].to_json();
        assert!(json.starts_with("{\"session_id\":\"session-0\""));
        assert!(json.contains("\"total_cu\":"));
        assert!(json.contains("\"over_budget\":false"));
        assert!(json.contains("\"bundles\":[{\"bundle_id\":\"bundle-0\""));
        assert!(json.contains("\"alt_table\":["));
        assert!(json.ends_with("]}"));
    }
}
