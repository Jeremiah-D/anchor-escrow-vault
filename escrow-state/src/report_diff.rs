//! Incremental keeper-report diffs (AV-120).
//!
//! A full [`KeeperReport`](crate::KeeperReport) re-lists every executable
//! keeper action on every scan — fine for a handful of vaults, wasteful
//! for a fleet. This module lets the keeper operator ship *diffs*
//! instead: [`compute_diff`] compares a fresh scan's actions against a
//! persisted [`ReportWatermark`] (the last reported sequence number plus
//! a per-vault fingerprint of the previously reported action set) and
//! returns a [`ReportDiff`] that lists only the vaults that were added,
//! removed, or changed since the last report.
//!
//! The watermark is plain data the operator persists (disk, KV store)
//! between scans: [`ReportWatermark::to_json`] /
//! [`ReportWatermark::from_json`] hand-serialize it deterministically
//! (the crate stays dependency-free). [`compute_diff`] is a pure
//! function — one call yields both the diff and the advanced watermark —
//! and replay-safe: feeding the same `report_seq` twice yields an empty
//! diff and an unchanged watermark, so a retried / duplicated scan can
//! never double-report.
//!
//! Sequence numbers start at 1; [`ReportWatermark::initial`] reports
//! `last_report_seq == 0` (the never-reported sentinel), so the first
//! real report must stamp `report_seq >= 1`.
//!
//! # Fingerprints
//!
//! Each vault's fingerprint is FNV-1a (64-bit) over its reported action
//! set — kind, caller role, reason, amount, caller key, the optional
//! addresses, the counters and the estimates — in scan order, with
//! every string length-prefixed so concatenations cannot collide. Two
//! scans list the same vault with byte-identical key fields iff the
//! fingerprints match; any listed-field change flips the vault to
//! [`VaultChangeKind::Changed`].
//!
//! # Incremental CSV
//!
//! [`report_diff_to_csv`] / [`csv_to_report_diff`] render a diff as
//! RFC 4180 CSV in the AV-74 conventions (header row, fixed column
//! order, LF line endings, a hand-written escaper, precise
//! [`DiffCsvError`]s, CRLF tolerated on import) — the incremental
//! complement to the full-event CSV export, for audit ingestion and
//! operator dashboards.
//!
//! The CSV is a *projection*, exactly like the AV-74 event export: it
//! carries `report_seq`, `at`, `escrow_id`, the change kind, the action
//! kind, `amount`, and `reason`. A [`KeeperAction`](crate::KeeperAction)
//! rebuilt from CSV carries documented zero-values everywhere else
//! (zero caller key, empty caller role, `None` for every optional
//! field, `0` for every counter) — the real action lives in the typed
//! diff. `reason` round-trips only through the scan's canonical reason
//! strings (see [`canonical_reason`]); anything else is a
//! [`DiffCsvError::UnknownReason`].

use crate::keeper::{KeeperAction, KeeperActionKind, KeeperReport};
use std::collections::{BTreeMap, HashSet};

/// How one vault moved between two keeper reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultChangeKind {
    /// The vault was absent from the previous watermark and lists
    /// actions now.
    Added,
    /// The vault was in the previous watermark and lists no actions
    /// now — its [`VaultChange::actions`] is empty.
    Removed,
    /// The vault lists actions in both reports but the action set's
    /// fingerprint changed.
    Changed,
}

impl VaultChangeKind {
    /// Canonical snake_case name — the CSV `change` column value.
    pub fn as_str(&self) -> &'static str {
        match self {
            VaultChangeKind::Added => "added",
            VaultChangeKind::Removed => "removed",
            VaultChangeKind::Changed => "changed",
        }
    }

    /// Parse [`as_str`](VaultChangeKind::as_str) back. `None` on an
    /// unknown name.
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "added" => VaultChangeKind::Added,
            "removed" => VaultChangeKind::Removed,
            "changed" => VaultChangeKind::Changed,
            _ => return None,
        })
    }
}

/// One vault's entry in a [`ReportDiff`]: what changed and the vault's
/// current action set (empty for [`VaultChangeKind::Removed`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultChange {
    /// Which vault moved.
    pub escrow_id: [u8; 32],
    /// How it moved.
    pub change: VaultChangeKind,
    /// The vault's current actions, in scan order. Empty for
    /// `Removed`.
    pub actions: Vec<KeeperAction>,
}

/// The incremental keeper report: only the vaults that moved since the
/// previous report sequence number. Changes are sorted by `escrow_id`
/// — the same input always yields the same order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportDiff {
    /// The report sequence number this diff was computed for.
    pub report_seq: u64,
    /// The `now` (Unix seconds) the underlying scan ran at.
    pub at: u64,
    /// The vaults that moved, sorted by `escrow_id`.
    pub changes: Vec<VaultChange>,
}

impl ReportDiff {
    /// True when nothing moved — the steady-state scan result the
    /// operator can skip persisting / shipping.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

/// The persisted scan cursor: the last reported sequence number plus,
/// per vault (keyed by 64-char lowercase escrow-id hex), the
/// fingerprint of the action set that sequence number reported.
///
/// [`compute_diff`] advances this deterministically; the operator
/// persists it with [`to_json`](ReportWatermark::to_json) and restores
/// it with [`from_json`](ReportWatermark::from_json).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportWatermark {
    /// The highest report sequence number already reported.
    pub last_report_seq: u64,
    /// Per-vault action-set fingerprints, keyed by escrow-id hex.
    pub vault_fingerprints: BTreeMap<String, u64>,
}

impl ReportWatermark {
    /// The never-reported watermark: sequence 0, no vaults. The first
    /// real report must stamp `report_seq >= 1`.
    pub fn initial() -> Self {
        Self {
            last_report_seq: 0,
            vault_fingerprints: BTreeMap::new(),
        }
    }

    /// Pure, deterministic advance: returns the watermark reporting
    /// `report_seq` with the `next` per-vault fingerprints. When
    /// `report_seq <= prev.last_report_seq` (a replayed or
    /// out-of-order report) the watermark is returned *unchanged* —
    /// calling this twice with the same inputs always yields the same
    /// result.
    pub fn advance(
        prev: &Self,
        report_seq: u64,
        next: BTreeMap<String, u64>,
    ) -> Self {
        if report_seq <= prev.last_report_seq {
            prev.clone()
        } else {
            Self {
                last_report_seq: report_seq,
                vault_fingerprints: next,
            }
        }
    }

    /// Hand-serialized JSON (the crate is dependency-free).
    /// Deterministic: fixed field order, vault entries sorted by key.
    ///
    /// ```json
    /// {"last_report_seq":42,"vaults":[["aa…aa",123],["bb…bb",456]]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(48 + self.vault_fingerprints.len() * 80);
        s.push_str("{\"last_report_seq\":");
        s.push_str(&self.last_report_seq.to_string());
        s.push_str(",\"vaults\":[");
        for (i, (key, fp)) in self.vault_fingerprints.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("[\"");
            s.push_str(key);
            s.push_str("\",");
            s.push_str(&fp.to_string());
            s.push(']');
        }
        s.push_str("]}");
        s
    }

    /// Parse exactly what [`to_json`](ReportWatermark::to_json)
    /// emits — no whitespace, no reordered fields, no trailing bytes.
    /// Every malformed input maps to a precise [`WatermarkError`];
    /// this never panics.
    pub fn from_json(json: &str) -> Result<Self, WatermarkError> {
        if json.is_empty() {
            return Err(WatermarkError::Empty);
        }
        let mut p = JParser {
            b: json.as_bytes(),
            i: 0,
        };
        p.expect_lit("{")?;
        p.expect_lit("\"last_report_seq\"")?;
        p.expect_lit(":")?;
        let seq_text = p
            .digits()
            .ok_or(WatermarkError::Malformed {
                position: p.i,
                expected: "decimal digits",
            })?;
        let last_report_seq = seq_text.parse::<u64>().map_err(|_| WatermarkError::InvalidLastReportSeq {
            value: seq_text.to_string(),
        })?;
        p.expect_lit(",")?;
        p.expect_lit("\"vaults\"")?;
        p.expect_lit(":")?;
        p.expect_lit("[")?;
        let mut vaults: BTreeMap<String, u64> = BTreeMap::new();
        if p.try_lit("]") {
            // No vaults recorded.
        } else {
            loop {
                p.expect_lit("[")?;
                let key = p.quoted().ok_or(WatermarkError::Malformed {
                    position: p.i,
                    expected: "\"",
                })?;
                if !is_hex64(key) {
                    return Err(WatermarkError::InvalidEscrowId {
                        value: key.to_string(),
                    });
                }
                p.expect_lit(",")?;
                let fp_text = p.digits().ok_or(WatermarkError::Malformed {
                    position: p.i,
                    expected: "decimal digits",
                })?;
                let fp = fp_text.parse::<u64>().map_err(|_| WatermarkError::InvalidFingerprint {
                    vault: key.to_string(),
                    value: fp_text.to_string(),
                })?;
                p.expect_lit("]")?;
                if vaults.insert(key.to_string(), fp).is_some() {
                    return Err(WatermarkError::DuplicateVault {
                        value: key.to_string(),
                    });
                }
                if p.try_lit(",") {
                    continue;
                }
                p.expect_lit("]")?;
                break;
            }
        }
        p.expect_lit("}")?;
        if !p.eof() {
            return Err(WatermarkError::Malformed {
                position: p.i,
                expected: "end of input",
            });
        }
        Ok(Self {
            last_report_seq,
            vault_fingerprints: vaults,
        })
    }
}

/// Errors [`ReportWatermark::from_json`] can return. Positions are
/// byte offsets. The parser never panics — every malformed input maps
/// to one of these variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatermarkError {
    /// The input is the empty string.
    Empty,
    /// A fixed token was expected at `position` but something else
    /// (or the end of input) was found.
    Malformed {
        /// Byte offset of the failure.
        position: usize,
        /// What the parser expected there.
        expected: &'static str,
    },
    /// `last_report_seq` is not a decimal `u64`.
    InvalidLastReportSeq {
        /// The offending digit run, verbatim.
        value: String,
    },
    /// A vault key is not 64 hex characters.
    InvalidEscrowId {
        /// The offending key, verbatim.
        value: String,
    },
    /// A fingerprint is not a decimal `u64`.
    InvalidFingerprint {
        /// The vault key the fingerprint belongs to.
        vault: String,
        /// The offending digit run, verbatim.
        value: String,
    },
    /// The same vault key appears twice.
    DuplicateVault {
        /// The offending key, verbatim.
        value: String,
    },
}

// ---------------------------------------------------------------------------
// Diff computation
// ---------------------------------------------------------------------------

/// Diff a fresh scan's `actions` against `prev`, returning the
/// incremental [`ReportDiff`] and the advanced [`ReportWatermark`] in
/// one call.
///
/// A vault lists actions now but not in `prev` → [`VaultChangeKind::Added`];
/// in `prev` but not now → [`VaultChangeKind::Removed`] (empty
/// actions); in both but with a different action-set fingerprint →
/// [`VaultChangeKind::Changed`]. Vaults whose fingerprint is unchanged
/// are omitted — that is the bandwidth the operator saves.
///
/// Replay-safe: when `report_seq <= prev.last_report_seq` the diff is
/// empty and the watermark is returned unchanged (see
/// [`ReportWatermark::advance`]).
///
/// Pure function: no I/O, no clock reads, deterministic output.
pub fn compute_diff(
    prev: &ReportWatermark,
    report_seq: u64,
    at: u64,
    actions: &[KeeperAction],
) -> (ReportDiff, ReportWatermark) {
    // Replay or out-of-order report: the diff is empty and the
    // watermark does not move, so a retried scan never
    // double-reports. (Sequence numbers start at 1;
    // `ReportWatermark::initial` reports 0.)
    if report_seq <= prev.last_report_seq {
        return (
            ReportDiff {
                report_seq,
                at,
                changes: Vec::new(),
            },
            prev.clone(),
        );
    }
    // Group the scan's actions per vault, preserving scan order
    // inside each vault's action list.
    let mut by_vault: BTreeMap<[u8; 32], Vec<KeeperAction>> = BTreeMap::new();
    for a in actions {
        by_vault.entry(a.escrow_id).or_default().push(*a);
    }
    // The next watermark's per-vault fingerprints.
    let mut next: BTreeMap<String, u64> = BTreeMap::new();
    let mut changes: Vec<VaultChange> = Vec::new();
    for (id, acts) in &by_vault {
        let key = hex32(id);
        let fp = fingerprint_actions(acts);
        next.insert(key.clone(), fp);
        match prev.vault_fingerprints.get(&key) {
            None => changes.push(VaultChange {
                escrow_id: *id,
                change: VaultChangeKind::Added,
                actions: acts.clone(),
            }),
            Some(&old) if old != fp => changes.push(VaultChange {
                escrow_id: *id,
                change: VaultChangeKind::Changed,
                actions: acts.clone(),
            }),
            // Fingerprint unchanged: the vault did not move.
            _ => {}
        }
    }
    // Removed: present in the previous watermark, absent now.
    for key in prev.vault_fingerprints.keys() {
        if next.contains_key(key) {
            continue;
        }
        // Watermark keys are canonical hex64 as written by
        // `to_json`; a foreign key can only arrive via direct struct
        // construction, so it is ignored rather than reported.
        if let Some(id) = dehex32(key) {
            changes.push(VaultChange {
                escrow_id: id,
                change: VaultChangeKind::Removed,
                actions: Vec::new(),
            });
        }
    }
    // Deterministic order regardless of the scan's input order.
    changes.sort_by(|a, b| a.escrow_id.cmp(&b.escrow_id));
    let watermark = ReportWatermark::advance(prev, report_seq, next);
    (
        ReportDiff {
            report_seq,
            at,
            changes,
        },
        watermark,
    )
}

/// Convenience over [`compute_diff`]: diff a stamped
/// [`KeeperReport`](crate::KeeperReport) against `prev`. The report's
/// [`report_seq`](crate::KeeperReport::report_seq) drives the
/// sequence check; a legacy report with `report_seq == None` is
/// treated as the next sequence after `prev` — adopting incremental
/// reports mid-stream yields one full-`Added` diff, then steady-state
/// empties.
pub fn diff_report(prev: &ReportWatermark, report: &KeeperReport) -> (ReportDiff, ReportWatermark) {
    let seq = report
        .report_seq
        .unwrap_or_else(|| prev.last_report_seq.saturating_add(1));
    compute_diff(prev, seq, report.at, &report.actions)
}

// ---------------------------------------------------------------------------
// Fingerprints
// ---------------------------------------------------------------------------

/// FNV-1a (64-bit): the deterministic, dependency-free hash behind
/// the per-vault fingerprints. Not cryptographic — it only needs to
/// flip when a listed field changes.
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

struct Hasher {
    state: u64,
}

impl Hasher {
    fn new() -> Self {
        Self {
            state: FNV_OFFSET_BASIS,
        }
    }

    fn bytes(&mut self, b: &[u8]) {
        for &x in b {
            self.state ^= x as u64;
            self.state = self.state.wrapping_mul(FNV_PRIME);
        }
    }

    /// Length-prefixed so "ab"+"c" and "a"+"bc" hash differently.
    fn str_field(&mut self, s: &str) {
        self.u64_field(s.len() as u64);
        self.bytes(s.as_bytes());
    }

    fn u64_field(&mut self, n: u64) {
        self.bytes(&n.to_le_bytes());
    }

    fn opt32(&mut self, v: &Option<[u8; 32]>) {
        match v {
            Some(b) => {
                self.u64_field(1);
                self.bytes(b);
            }
            None => self.u64_field(0),
        }
    }
}

/// Fingerprint one vault's action set: every listed field of every
/// action, in order. Two scans produce the same fingerprint for a
/// vault iff they list the same actions with the same key fields.
fn fingerprint_actions(actions: &[KeeperAction]) -> u64 {
    let mut h = Hasher::new();
    h.u64_field(actions.len() as u64);
    for a in actions {
        h.str_field(a.kind.as_str());
        h.str_field(a.caller_role);
        h.str_field(a.reason);
        h.u64_field(a.amount);
        h.bytes(&a.caller);
        h.u64_field(a.decimals as u64);
        h.u64_field(a.extension_count);
        h.u64_field(a.penalty_estimate);
        h.opt32(&a.vault_address);
        h.opt32(&a.mint);
        h.opt32(&a.refund_to);
        h.opt32(&a.reference);
        h.opt32(&a.merge_source);
        match a.slot_unlock_at {
            Some(s) => {
                h.u64_field(1);
                h.u64_field(s);
            }
            None => h.u64_field(0),
        }
        match a.evidence_disclosure {
            Some((disclosed, total)) => {
                h.u64_field(1);
                h.u64_field(disclosed);
                h.u64_field(total as u64);
            }
            None => h.u64_field(0),
        }
        match a.funding_progress {
            Some(p) => {
                h.u64_field(1);
                h.u64_field(p.funded_total);
                h.u64_field(p.total_amount);
                h.u64_field(p.tranches_used as u64);
                h.u64_field(p.max_tranches as u64);
            }
            None => h.u64_field(0),
        }
        match a.multisig_authority {
            Some(m) => {
                h.u64_field(1);
                h.bytes(&m.program_id);
                h.bytes(&m.authority);
                h.u64_field(m.threshold as u64);
            }
            None => h.u64_field(0),
        }
    }
    h.state
}

// ---------------------------------------------------------------------------
// Watermark JSON parser internals
// ---------------------------------------------------------------------------

/// Minimal cursor over the watermark JSON: the format is fixed, so a
/// full JSON parser would be overkill.
struct JParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> JParser<'a> {
    fn eof(&self) -> bool {
        self.i >= self.b.len()
    }

    /// Consume `lit` or fail with the byte position and the expected
    /// literal.
    fn expect_lit(&mut self, lit: &str) -> Result<(), WatermarkError> {
        if self.try_lit(lit) {
            Ok(())
        } else {
            Err(WatermarkError::Malformed {
                position: self.i,
                expected: lit_to_expected(lit),
            })
        }
    }

    /// Consume `lit` when it is next; `false` leaves the cursor put.
    fn try_lit(&mut self, lit: &str) -> bool {
        let bytes = lit.as_bytes();
        if self.b.len() - self.i >= bytes.len() && &self.b[self.i..self.i + bytes.len()] == bytes {
            self.i += bytes.len();
            true
        } else {
            false
        }
    }

    /// Consume a maximal run of ASCII digits. `None` when the next
    /// byte is not a digit.
    fn digits(&mut self) -> Option<&'a str> {
        let start = self.i;
        while self.i < self.b.len() && self.b[self.i].is_ascii_digit() {
            self.i += 1;
        }
        if self.i == start {
            None
        } else {
            // Only ASCII digits were consumed: valid UTF-8 by
            // construction.
            std::str::from_utf8(&self.b[start..self.i]).ok()
        }
    }

    /// Consume a `"…"` string without escapes (the exporter never
    /// writes any). `None` when the next byte is not `"`.
    fn quoted(&mut self) -> Option<&'a str> {
        if self.i >= self.b.len() || self.b[self.i] != b'"' {
            return None;
        }
        let start = self.i + 1;
        let mut j = start;
        while j < self.b.len() && self.b[j] != b'"' {
            j += 1;
        }
        if j >= self.b.len() {
            return None;
        }
        self.i = j + 1;
        // Vault keys are ASCII hex: valid UTF-8 by construction.
        std::str::from_utf8(&self.b[start..j]).ok()
    }
}

/// Map a literal to the `expected` label for
/// [`WatermarkError::Malformed`].
fn lit_to_expected(lit: &str) -> &'static str {
    match lit {
        "{" => "\"{\"",
        "}" => "\"}\"",
        "[" => "\"[\"",
        "]" => "\"]\"",
        ":" => "\":\"",
        "," => "\",\"",
        "\"last_report_seq\"" => "\"last_report_seq\"",
        "\"vaults\"" => "\"vaults\"",
        _ => "token",
    }
}

/// 64 ASCII hex characters — the canonical escrow-id key form.
fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Incremental CSV (AV-74 conventions)
// ---------------------------------------------------------------------------

/// The exact header row [`report_diff_to_csv`] writes and
/// [`csv_to_report_diff`] requires.
const DIFF_HEADER: &str = "report_seq,at,escrow_id,change,action,amount,reason";

/// Expected column count per record row.
const DIFF_COLUMN_COUNT: usize = 7;

/// Errors [`csv_to_report_diff`] can return. Line numbers are 1-based;
/// the header is line 1, the first record line 2. The parser never
/// panics — every malformed input maps to one of these variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffCsvError {
    /// The input has no lines at all (empty string).
    MissingHeader,
    /// Line 1 is not the exact [`DIFF_HEADER`] row.
    UnexpectedHeader {
        /// The offending first line, verbatim.
        got: String,
    },
    /// A record row does not carry exactly [`DIFF_COLUMN_COUNT`]
    /// fields.
    BadFieldCount {
        line: usize,
        expected: usize,
        got: usize,
    },
    /// The `change` column is not `added` / `removed` / `changed`.
    UnknownChange { line: usize, value: String },
    /// The `action` column is not a known keeper action name.
    UnknownAction { line: usize, value: String },
    /// The `reason` column is not one of the scan's canonical reason
    /// strings (see [`canonical_reason`]).
    UnknownReason { line: usize, value: String },
    /// A `report_seq` / `at` / `amount` column is not a decimal `u64`.
    InvalidInt {
        line: usize,
        column: &'static str,
        value: String,
    },
    /// The `escrow_id` column is not 64 hex characters.
    InvalidEscrowIdHex { line: usize, value: String },
    /// Not every row carries the first row's `report_seq`.
    MixedReportSeq {
        line: usize,
        expected: u64,
        got: u64,
    },
    /// Not every row carries the first row's `at`.
    MixedAt {
        line: usize,
        expected: u64,
        got: u64,
    },
    /// A `removed` row carries a non-empty `action` column — removed
    /// vaults have no actions, so the column must stay empty.
    RemovedRowHasAction { line: usize, value: String },
    /// A `removed` row carries a non-zero `amount` column.
    RemovedRowHasAmount { line: usize, value: String },
    /// A `removed` row carries a non-empty `reason` column.
    RemovedRowHasReason { line: usize, value: String },
    /// The same escrow reappears non-consecutively (rows for one
    /// vault must be contiguous).
    DuplicateEscrow { line: usize, value: String },
    /// Rows for one escrow carry different `change` values.
    EscrowChangeMismatch { line: usize, value: String },
    /// A quoted field never closes on its line.
    UnterminatedQuote { line: usize },
    /// Characters other than `,` follow a quoted field's closing
    /// quote.
    TrailingCharsAfterQuote { line: usize },
}

/// Render a [`ReportDiff`] as deterministic CSV: the [`DIFF_HEADER`]
/// row, then one record row per action in diff order, LF-terminated
/// lines. A [`VaultChangeKind::Removed`] vault (no actions) emits one
/// sentinel row with empty `action` / zero `amount` / empty `reason`
/// so the removal survives the round-trip.
pub fn report_diff_to_csv(diff: &ReportDiff) -> String {
    let mut out = String::new();
    out.push_str(DIFF_HEADER);
    out.push('\n');
    for change in &diff.changes {
        if change.actions.is_empty() {
            push_diff_row(
                &mut out,
                diff.report_seq,
                diff.at,
                &change.escrow_id,
                change.change,
                "",
                0,
                "",
            );
        } else {
            for a in &change.actions {
                push_diff_row(
                    &mut out,
                    diff.report_seq,
                    diff.at,
                    &a.escrow_id,
                    change.change,
                    a.kind.as_str(),
                    a.amount,
                    a.reason,
                );
            }
        }
    }
    out
}

/// Parse CSV previously written by [`report_diff_to_csv`] back into a
/// diff.
///
/// The carried fields (`report_seq`, `at`, `escrow_id`, `change`,
/// action kind, `amount`, `reason`) round-trip exactly; the rebuilt
/// [`KeeperAction`](crate::KeeperAction)s take the documented
/// zero-value projection elsewhere (see the module docs).
/// `report_diff_to_csv(csv_to_report_diff(csv))` is byte-identical to
/// `csv` for any `csv` this module emitted.
#[allow(clippy::too_many_lines)]
pub fn csv_to_report_diff(csv: &str) -> Result<ReportDiff, DiffCsvError> {
    // Split into lines, dropping the single empty piece a trailing
    // newline leaves behind; every other line must be a real record.
    let raw: Vec<&str> = csv.split('\n').collect();
    let mut end = raw.len();
    if end > 0 && raw[end - 1].is_empty() {
        end -= 1;
    }
    let lines = &raw[..end];
    if lines.is_empty() {
        return Err(DiffCsvError::MissingHeader);
    }
    let header = strip_cr(lines[0]);
    if header != DIFF_HEADER {
        return Err(DiffCsvError::UnexpectedHeader {
            got: header.to_string(),
        });
    }
    let mut report_seq: Option<u64> = None;
    let mut at: Option<u64> = None;
    let mut changes: Vec<VaultChange> = Vec::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    // The open row group: consecutive rows for one vault.
    let mut cur_id: Option<[u8; 32]> = None;
    let mut cur_change: Option<VaultChangeKind> = None;
    let mut cur_actions: Vec<KeeperAction> = Vec::new();

    for (i, raw_line) in lines.iter().enumerate().skip(1) {
        // 1-based line number; the header is line 1.
        let line_no = i + 1;
        let fields = parse_csv_line(strip_cr(raw_line), line_no)?;
        if fields.len() != DIFF_COLUMN_COUNT {
            return Err(DiffCsvError::BadFieldCount {
                line: line_no,
                expected: DIFF_COLUMN_COUNT,
                got: fields.len(),
            });
        }
        let seq = parse_diff_u64(&fields[0], line_no, "report_seq")?;
        let row_at = parse_diff_u64(&fields[1], line_no, "at")?;
        match report_seq {
            None => report_seq = Some(seq),
            Some(first) if first != seq => {
                return Err(DiffCsvError::MixedReportSeq {
                    line: line_no,
                    expected: first,
                    got: seq,
                })
            }
            _ => {}
        }
        match at {
            None => at = Some(row_at),
            Some(first) if first != row_at => {
                return Err(DiffCsvError::MixedAt {
                    line: line_no,
                    expected: first,
                    got: row_at,
                })
            }
            _ => {}
        }
        let escrow_id = dehex32(&fields[2]).ok_or_else(|| DiffCsvError::InvalidEscrowIdHex {
            line: line_no,
            value: fields[2].clone(),
        })?;
        let change = VaultChangeKind::from_str(&fields[3]).ok_or_else(|| DiffCsvError::UnknownChange {
            line: line_no,
            value: fields[3].clone(),
        })?;
        // Same vault as the open group?
        if cur_id == Some(escrow_id) {
            if cur_change != Some(change) {
                return Err(DiffCsvError::EscrowChangeMismatch {
                    line: line_no,
                    value: fields[2].clone(),
                });
            }
        } else {
            // Close the open group, if any.
            if let (Some(id), Some(ch)) = (cur_id.take(), cur_change.take()) {
                changes.push(VaultChange {
                    escrow_id: id,
                    change: ch,
                    actions: std::mem::take(&mut cur_actions),
                });
            }
            if !seen.insert(escrow_id) {
                return Err(DiffCsvError::DuplicateEscrow {
                    line: line_no,
                    value: fields[2].clone(),
                });
            }
            cur_id = Some(escrow_id);
            cur_change = Some(change);
        }
        match change {
            VaultChangeKind::Removed => {
                // The sentinel row: no action, zero amount, no reason.
                if !fields[4].is_empty() {
                    return Err(DiffCsvError::RemovedRowHasAction {
                        line: line_no,
                        value: fields[4].clone(),
                    });
                }
                let amount = parse_diff_u64(&fields[5], line_no, "amount")?;
                if amount != 0 {
                    return Err(DiffCsvError::RemovedRowHasAmount {
                        line: line_no,
                        value: fields[5].clone(),
                    });
                }
                if !fields[6].is_empty() {
                    return Err(DiffCsvError::RemovedRowHasReason {
                        line: line_no,
                        value: fields[6].clone(),
                    });
                }
            }
            VaultChangeKind::Added | VaultChangeKind::Changed => {
                let kind = action_kind_from_name(&fields[4]).ok_or_else(|| DiffCsvError::UnknownAction {
                    line: line_no,
                    value: fields[4].clone(),
                })?;
                let amount = parse_diff_u64(&fields[5], line_no, "amount")?;
                let reason = canonical_reason(&fields[6]).ok_or_else(|| DiffCsvError::UnknownReason {
                    line: line_no,
                    value: fields[6].clone(),
                })?;
                // The CSV is a projection: only the carried fields
                // round-trip. Everything else takes the documented
                // zero-values.
                cur_actions.push(KeeperAction {
                    escrow_id,
                    vault_address: None,
                    kind,
                    caller: [0u8; 32],
                    caller_role: "",
                    mint: None,
                    refund_to: None,
                    amount,
                    decimals: 0,
                    reference: None,
                    extension_count: 0,
                    multisig_authority: None,
                    evidence_disclosure: None,
                    funding_progress: None,
                    reason,
                    merge_source: None,
                    penalty_estimate: 0,
                    slot_unlock_at: None,
                });
            }
        }
    }
    // Close the final group.
    if let (Some(id), Some(ch)) = (cur_id, cur_change) {
        changes.push(VaultChange {
            escrow_id: id,
            change: ch,
            actions: cur_actions,
        });
    }
    Ok(ReportDiff {
        report_seq: report_seq.unwrap_or(0),
        at: at.unwrap_or(0),
        changes,
    })
}

/// Map a keeper action's canonical snake_case name back to its kind.
/// Mirrors [`KeeperActionKind::as_str`] — when the keeper gains a new
/// action kind, this table must gain its name too.
fn action_kind_from_name(name: &str) -> Option<KeeperActionKind> {
    Some(match name {
        "cancel_expired" => KeeperActionKind::CancelExpired,
        "crank_expired" => KeeperActionKind::CrankExpired,
        "claim" => KeeperActionKind::Claim,
        "resolve" => KeeperActionKind::Resolve,
        "submit_panel_judgment" => KeeperActionKind::PanelJudgment,
        "release_period" => KeeperActionKind::ReleasePeriod,
        "slash" => KeeperActionKind::Slash,
        "file_appeal" => KeeperActionKind::FileAppeal,
        "review_appeal" => KeeperActionKind::ReviewAppeal,
        "expire_appeal" => KeeperActionKind::ExpireAppeal,
        "pool_payout" => KeeperActionKind::PoolPayout,
        "claim_deadman" => KeeperActionKind::ClaimDeadman,
        "fund_tranche" => KeeperActionKind::FundTranche,
        "merge_escrows" => KeeperActionKind::MergeEscrows,
        _ => return None,
    })
}

/// Map a scan reason string to the canonical `&'static str` the scan
/// itself uses, so the rebuilt [`KeeperAction`](crate::KeeperAction)
/// keeps the static-str invariant. Mirrors the `reason:` literals in
/// [`scan_keeper_actions`](crate::scan_keeper_actions) — when the scan
/// gains a new reason, this table must gain it too.
pub fn canonical_reason(reason: &str) -> Option<&'static str> {
    Some(match reason {
        "appeal_filed" => "appeal_filed",
        "appeal_window_lapsed" => "appeal_window_lapsed",
        "appeal_window_open" => "appeal_window_open",
        "deadman_inactivity_elapsed" => "deadman_inactivity_elapsed",
        "disputed" => "disputed",
        "expired" => "expired",
        "funding_incomplete" => "funding_incomplete",
        "mergeable_pair" => "mergeable_pair",
        "pool_payout_available" => "pool_payout_available",
        "slash_deadline_passed" => "slash_deadline_passed",
        "subscription_period_due" => "subscription_period_due",
        "vesting_unlocked" => "vesting_unlocked",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// CSV + hex plumbing (AV-74 conventions, module-local like the rest of
// the crate)
// ---------------------------------------------------------------------------

fn push_diff_row(
    out: &mut String,
    report_seq: u64,
    at: u64,
    escrow_id: &[u8; 32],
    change: VaultChangeKind,
    action: &str,
    amount: u64,
    reason: &str,
) {
    push_u64(out, report_seq);
    out.push(',');
    push_u64(out, at);
    out.push(',');
    push_field(out, &hex32(escrow_id));
    out.push(',');
    push_field(out, change.as_str());
    out.push(',');
    push_field(out, action);
    out.push(',');
    push_u64(out, amount);
    out.push(',');
    push_field(out, reason);
    out.push('\n');
}

/// Strip the one trailing `\r` a CRLF line ending leaves behind.
/// Export always writes LF; import tolerates CRLF.
fn strip_cr(line: &str) -> &str {
    line.strip_suffix('\r').unwrap_or(line)
}

/// Append one CSV field with RFC 4180 §2.7 escaping: a field
/// containing `,`, `"`, `\n` or `\r` is wrapped in quotes and every
/// inner quote is doubled.
fn push_field(out: &mut String, field: &str) {
    let needs_quote = field.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r'));
    if !needs_quote {
        out.push_str(field);
        return;
    }
    out.push('"');
    for c in field.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
}

/// Append a `u64` as canonical decimal (no padding, no separators).
fn push_u64(out: &mut String, n: u64) {
    out.push_str(&n.to_string());
}

/// Render 32 bytes as 64 lowercase hex characters — the same
/// convention as the keeper report serializer.
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode 64 hex characters (either case) into 32 bytes. `None` on a
/// wrong length or a non-hex character.
fn dehex32(s: &str) -> Option<[u8; 32]> {
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = nibble(bytes[2 * i])? << 4 | nibble(bytes[2 * i + 1])?;
    }
    Some(out)
}

/// Parse one decimal `u64` column, tagging parse failures with the
/// line and the column name.
fn parse_diff_u64(s: &str, line: usize, column: &'static str) -> Result<u64, DiffCsvError> {
    s.parse::<u64>().map_err(|_| DiffCsvError::InvalidInt {
        line,
        column,
        value: s.to_string(),
    })
}

/// Split one record line into fields, honoring RFC 4180 quoted
/// fields (doubled quotes unescape to one). Line-oriented: never
/// crosses a `\n`, never panics.
fn parse_csv_line(line: &str, line_no: usize) -> Result<Vec<String>, DiffCsvError> {
    #[derive(PartialEq)]
    enum State {
        FieldStart,
        InBare,
        InQuoted,
        AfterQuoted,
    }

    let mut fields = Vec::new();
    let mut field = String::new();
    let mut state = State::FieldStart;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match state {
            State::FieldStart => match c {
                '"' => state = State::InQuoted,
                ',' => fields.push(std::mem::take(&mut field)),
                _ => {
                    field.push(c);
                    state = State::InBare;
                }
            },
            State::InBare => match c {
                ',' => {
                    fields.push(std::mem::take(&mut field));
                    state = State::FieldStart;
                }
                '"' => return Err(DiffCsvError::TrailingCharsAfterQuote { line: line_no }),
                _ => field.push(c),
            },
            State::InQuoted => {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        field.push('"');
                        chars.next();
                    } else {
                        state = State::AfterQuoted;
                    }
                } else {
                    field.push(c);
                }
            }
            State::AfterQuoted => match c {
                ',' => {
                    fields.push(std::mem::take(&mut field));
                    state = State::FieldStart;
                }
                _ => return Err(DiffCsvError::TrailingCharsAfterQuote { line: line_no }),
            },
        }
    }

    match state {
        State::InQuoted => Err(DiffCsvError::UnterminatedQuote { line: line_no }),
        _ => {
            fields.push(field);
            Ok(fields)
        }
    }
}

#[cfg(test)]
mod report_diff_tests {
    use super::*;
    use crate::{Escrow, WatchedEscrow};

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MID: u64 = 1_750_000_000;
    const AT: u64 = 1_800_000_000;

    fn vid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn action(id: [u8; 32], kind: KeeperActionKind, amount: u64, reason: &'static str) -> KeeperAction {
        KeeperAction {
            escrow_id: id,
            vault_address: None,
            kind,
            caller: ALICE,
            caller_role: "initializer",
            mint: None,
            refund_to: None,
            amount,
            decimals: 0,
            reference: None,
            extension_count: 0,
            multisig_authority: None,
            evidence_disclosure: None,
            funding_progress: None,
            reason,
            merge_source: None,
            penalty_estimate: 0,
            slot_unlock_at: None,
        }
    }

    fn expired_watch(id: [u8; 32]) -> WatchedEscrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, 0).unwrap();
        e.fund(ALICE, MID).unwrap();
        let reference = e.reference();
        WatchedEscrow {
            escrow_id: id,
            escrow: e,
            reference,
            vault_derivation: None,
        }
    }

    #[test]
    fn first_scan_with_empty_watermark_marks_everything_added() {
        let actions = vec![
            action(vid(0x01), KeeperActionKind::CancelExpired, 1_000_000, "expired"),
            action(vid(0x01), KeeperActionKind::CrankExpired, 1_000_000, "expired"),
            action(vid(0x02), KeeperActionKind::Claim, 500_000, "vesting_unlocked"),
        ];
        let (diff, next) = compute_diff(&ReportWatermark::initial(), 1, AT, &actions);
        assert_eq!(diff.report_seq, 1);
        assert_eq!(diff.at, AT);
        assert_eq!(diff.changes.len(), 2);
        assert_eq!(diff.changes[0].change, VaultChangeKind::Added);
        assert_eq!(diff.changes[0].escrow_id, vid(0x01));
        assert_eq!(diff.changes[0].actions.len(), 2);
        assert_eq!(diff.changes[1].change, VaultChangeKind::Added);
        assert_eq!(diff.changes[1].escrow_id, vid(0x02));
        assert_eq!(diff.changes[1].actions.len(), 1);
        // The watermark advanced deterministically.
        assert_eq!(next.last_report_seq, 1);
        assert_eq!(next.vault_fingerprints.len(), 2);
        assert!(next.vault_fingerprints.contains_key(&hex32(&vid(0x01))));
    }

    #[test]
    fn no_change_yields_empty_diff_and_advances_seq() {
        let actions = vec![action(vid(0x01), KeeperActionKind::Claim, 500_000, "vesting_unlocked")];
        let (_, w1) = compute_diff(&ReportWatermark::initial(), 1, AT, &actions);
        let (diff, w2) = compute_diff(&w1, 2, AT + 60, &actions);
        assert!(diff.is_empty());
        assert!(diff.changes.is_empty());
        assert_eq!(diff.report_seq, 2);
        assert_eq!(diff.at, AT + 60);
        // The sequence still advances on an empty diff — the cursor
        // must move even when nothing moved.
        assert_eq!(w2.last_report_seq, 2);
        assert_eq!(w2.vault_fingerprints, w1.vault_fingerprints);
    }

    #[test]
    fn added_vault_detected() {
        let a1 = vec![action(vid(0x01), KeeperActionKind::Claim, 500_000, "vesting_unlocked")];
        let (_, w1) = compute_diff(&ReportWatermark::initial(), 1, AT, &a1);
        let a2 = vec![
            action(vid(0x01), KeeperActionKind::Claim, 500_000, "vesting_unlocked"),
            action(vid(0x02), KeeperActionKind::Slash, 100_000, "slash_deadline_passed"),
        ];
        let (diff, w2) = compute_diff(&w1, 2, AT, &a2);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change, VaultChangeKind::Added);
        assert_eq!(diff.changes[0].escrow_id, vid(0x02));
        assert_eq!(diff.changes[0].actions[0].kind, KeeperActionKind::Slash);
        assert_eq!(w2.last_report_seq, 2);
        assert_eq!(w2.vault_fingerprints.len(), 2);
    }

    #[test]
    fn removed_vault_detected_with_empty_actions() {
        let both = vec![
            action(vid(0x01), KeeperActionKind::Claim, 500_000, "vesting_unlocked"),
            action(vid(0x02), KeeperActionKind::Claim, 700_000, "vesting_unlocked"),
        ];
        let (_, w1) = compute_diff(&ReportWatermark::initial(), 1, AT, &both);
        let one = vec![action(vid(0x01), KeeperActionKind::Claim, 500_000, "vesting_unlocked")];
        let (diff, w2) = compute_diff(&w1, 2, AT, &one);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change, VaultChangeKind::Removed);
        assert_eq!(diff.changes[0].escrow_id, vid(0x02));
        assert!(diff.changes[0].actions.is_empty());
        // The watermark drops the removed vault.
        assert_eq!(w2.vault_fingerprints.len(), 1);
        assert!(!w2.vault_fingerprints.contains_key(&hex32(&vid(0x02))));
    }

    #[test]
    fn changed_amount_is_detected() {
        let v1 = vec![action(vid(0x01), KeeperActionKind::Claim, 500_000, "vesting_unlocked")];
        let (_, w1) = compute_diff(&ReportWatermark::initial(), 1, AT, &v1);
        let v2 = vec![action(vid(0x01), KeeperActionKind::Claim, 400_000, "vesting_unlocked")];
        let (diff, _) = compute_diff(&w1, 2, AT, &v2);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change, VaultChangeKind::Changed);
        assert_eq!(diff.changes[0].actions[0].amount, 400_000);
    }

    #[test]
    fn changed_kind_and_action_count_are_detected() {
        let v1 = vec![action(vid(0x01), KeeperActionKind::Claim, 500_000, "vesting_unlocked")];
        let (_, w1) = compute_diff(&ReportWatermark::initial(), 1, AT, &v1);
        // Same vault, different kind and one more action.
        let v2 = vec![
            action(vid(0x01), KeeperActionKind::CancelExpired, 1_000_000, "expired"),
            action(vid(0x01), KeeperActionKind::CrankExpired, 1_000_000, "expired"),
        ];
        let (diff, _) = compute_diff(&w1, 2, AT, &v2);
        assert_eq!(diff.changes.len(), 1);
        assert_eq!(diff.changes[0].change, VaultChangeKind::Changed);
        assert_eq!(diff.changes[0].actions.len(), 2);
    }

    #[test]
    fn changes_come_out_sorted_by_escrow_id() {
        // Feed the vaults in reverse order; the diff must still sort.
        let actions = vec![
            action(vid(0x03), KeeperActionKind::Claim, 1, "vesting_unlocked"),
            action(vid(0x01), KeeperActionKind::Claim, 1, "vesting_unlocked"),
            action(vid(0x02), KeeperActionKind::Claim, 1, "vesting_unlocked"),
        ];
        let (diff, _) = compute_diff(&ReportWatermark::initial(), 1, AT, &actions);
        let ids: Vec<[u8; 32]> = diff.changes.iter().map(|c| c.escrow_id).collect();
        assert_eq!(ids, vec![vid(0x01), vid(0x02), vid(0x03)]);
        // Same for a mixed added/removed/changed diff (0x02 is
        // unchanged and must be omitted).
        let (_, w1) = compute_diff(&ReportWatermark::initial(), 1, AT, &actions);
        let next_actions = vec![
            action(vid(0x03), KeeperActionKind::Claim, 2, "vesting_unlocked"), // changed
            action(vid(0x04), KeeperActionKind::Claim, 1, "vesting_unlocked"), // added
            action(vid(0x02), KeeperActionKind::Claim, 1, "vesting_unlocked"), // unchanged
            // 0x01 removed
        ];
        let (diff2, _) = compute_diff(&w1, 2, AT, &next_actions);
        let ids2: Vec<[u8; 32]> = diff2.changes.iter().map(|c| c.escrow_id).collect();
        assert_eq!(ids2, vec![vid(0x01), vid(0x03), vid(0x04)]);
        assert_eq!(diff2.changes[0].change, VaultChangeKind::Removed);
        assert_eq!(diff2.changes[1].change, VaultChangeKind::Changed);
        assert_eq!(diff2.changes[2].change, VaultChangeKind::Added);
    }

    #[test]
    fn replay_same_report_seq_is_idempotent() {
        let actions = vec![
            action(vid(0x01), KeeperActionKind::Claim, 500_000, "vesting_unlocked"),
            action(vid(0x05), KeeperActionKind::Slash, 10_000, "slash_deadline_passed"),
        ];
        let (_, w1) = compute_diff(&ReportWatermark::initial(), 1, AT, &actions);
        // Replaying seq 1: empty diff, watermark untouched.
        let (diff_replay, w_replay) = compute_diff(&w1, 1, AT + 999, &actions);
        assert!(diff_replay.is_empty());
        assert_eq!(w_replay, w1);
        // A stale (older) seq is also a no-op.
        let (diff_stale, w_stale) = compute_diff(&w1, 0, AT, &actions);
        assert!(diff_stale.is_empty());
        assert_eq!(w_stale, w1);
        // And replaying twice yields the same result both times.
        let (d2, w2) = compute_diff(&w1, 1, AT, &actions);
        assert_eq!(d2.changes, diff_replay.changes);
        assert_eq!(w2, w_replay);
    }

    #[test]
    fn advance_is_pure_and_deterministic() {
        let prev = ReportWatermark::initial();
        let mut next = BTreeMap::new();
        next.insert(hex32(&vid(0x01)), 12345);
        let a = ReportWatermark::advance(&prev, 1, next.clone());
        let b = ReportWatermark::advance(&prev, 1, next.clone());
        assert_eq!(a, b, "same inputs must give the same watermark");
        assert_eq!(a.last_report_seq, 1);
        // A replayed or out-of-order sequence never moves the cursor.
        assert_eq!(ReportWatermark::advance(&a, 1, BTreeMap::new()), a);
        assert_eq!(ReportWatermark::advance(&a, 0, BTreeMap::new()), a);
    }

    #[test]
    fn watermark_json_is_byte_pinned_and_round_trips() {
        let mut vaults = BTreeMap::new();
        vaults.insert("aa".repeat(32), 123);
        vaults.insert("bb".repeat(32), 456);
        let w = ReportWatermark {
            last_report_seq: 42,
            vault_fingerprints: vaults,
        };
        let json = w.to_json();
        assert_eq!(
            json,
            format!(
                "{{\"last_report_seq\":42,\"vaults\":[[\"{}\",123],[\"{}\",456]]}}",
                "aa".repeat(32),
                "bb".repeat(32)
            )
        );
        assert_eq!(ReportWatermark::from_json(&json).unwrap(), w);
        // The empty watermark pins too.
        assert_eq!(
            ReportWatermark::initial().to_json(),
            "{\"last_report_seq\":0,\"vaults\":[]}"
        );
        assert_eq!(
            ReportWatermark::from_json("{\"last_report_seq\":0,\"vaults\":[]}").unwrap(),
            ReportWatermark::initial()
        );
    }

    #[test]
    fn watermark_json_rejects_garbage() {
        assert_eq!(ReportWatermark::from_json(""), Err(WatermarkError::Empty));
        assert!(matches!(
            ReportWatermark::from_json("{"),
            Err(WatermarkError::Malformed { .. })
        ));
        // Truncated mid-vaults (valid key, then the input ends).
        assert!(matches!(
            ReportWatermark::from_json(&format!(
                "{{\"last_report_seq\":1,\"vaults\":[[\"{}\"]",
                "aa".repeat(32)
            )),
            Err(WatermarkError::Malformed { .. })
        ));
        // Non-numeric sequence.
        assert!(matches!(
            ReportWatermark::from_json("{\"last_report_seq\":x,\"vaults\":[]}"),
            Err(WatermarkError::Malformed { .. })
        ));
        // Overflowing sequence.
        assert_eq!(
            ReportWatermark::from_json("{\"last_report_seq\":18446744073709551616,\"vaults\":[]}"),
            Err(WatermarkError::InvalidLastReportSeq {
                value: "18446744073709551616".to_string()
            })
        );
        // Non-hex vault key.
        assert_eq!(
            ReportWatermark::from_json("{\"last_report_seq\":1,\"vaults\":[[\"zz\",5]]}"),
            Err(WatermarkError::InvalidEscrowId {
                value: "zz".to_string()
            })
        );
        // Overflowing fingerprint.
        let bad_fp = format!(
            "{{\"last_report_seq\":1,\"vaults\":[[\"{}\",18446744073709551616]]}}",
            "aa".repeat(32)
        );
        assert_eq!(
            ReportWatermark::from_json(&bad_fp),
            Err(WatermarkError::InvalidFingerprint {
                vault: "aa".repeat(32),
                value: "18446744073709551616".to_string()
            })
        );
        // Duplicate vault key.
        let dup = format!(
            "{{\"last_report_seq\":1,\"vaults\":[[\"{}\",1],[\"{}\",2]]}}",
            "aa".repeat(32),
            "aa".repeat(32)
        );
        assert_eq!(
            ReportWatermark::from_json(&dup),
            Err(WatermarkError::DuplicateVault {
                value: "aa".repeat(32)
            })
        );
        // Trailing bytes after the object.
        assert!(matches!(
            ReportWatermark::from_json("{\"last_report_seq\":1,\"vaults\":[]} "),
            Err(WatermarkError::Malformed { .. })
        ));
        // Reordered fields are rejected (the format is fixed).
        assert!(matches!(
            ReportWatermark::from_json("{\"vaults\":[],\"last_report_seq\":1}"),
            Err(WatermarkError::Malformed { .. })
        ));
    }

    #[test]
    fn fingerprint_distinguishes_key_fields() {
        let base = action(vid(0x01), KeeperActionKind::Claim, 500_000, "vesting_unlocked");
        let fp = |a: KeeperAction| fingerprint_actions(std::slice::from_ref(&a));
        assert_eq!(fp(base), fp(base), "identical actions hash identically");
        let mut changed = base;
        changed.amount = 500_001;
        assert_ne!(fp(base), fp(changed), "amount change must flip the fingerprint");
        let mut changed = base;
        changed.kind = KeeperActionKind::Slash;
        changed.reason = "slash_deadline_passed";
        assert_ne!(fp(base), fp(changed), "kind change must flip the fingerprint");
        let mut changed = base;
        changed.caller = BOB;
        assert_ne!(fp(base), fp(changed), "caller change must flip the fingerprint");
        let mut changed = base;
        changed.penalty_estimate = 1;
        assert_ne!(fp(base), fp(changed), "estimate change must flip the fingerprint");
        // Order matters: the same actions in a different order hash
        // differently (the scan order is part of the fingerprint).
        let a2 = action(vid(0x01), KeeperActionKind::CancelExpired, 1_000_000, "expired");
        assert_ne!(
            fingerprint_actions(&[base, a2]),
            fingerprint_actions(&[a2, base])
        );
    }

    #[test]
    fn real_scan_feeds_compute_diff() {
        // End-to-end: a real keeper scan diffed against a fresh
        // watermark, then re-diffed after "executing" nothing.
        let watched = vec![expired_watch(vid(0x01)), expired_watch(vid(0x02))];
        let report = crate::scan_keeper_actions(&watched, 1_000_000);
        assert_eq!(report.actions.len(), 4); // cancel + crank per escrow
        let (diff, w1) = compute_diff(&ReportWatermark::initial(), 1, report.at, &report.actions);
        assert_eq!(diff.changes.len(), 2);
        assert!(diff.changes.iter().all(|c| c.change == VaultChangeKind::Added));
        // Nothing executed: the next scan diffs to empty.
        let report2 = crate::scan_keeper_actions(&watched, 1_000_000);
        let (diff2, _) = compute_diff(&w1, 2, report2.at, &report2.actions);
        assert!(diff2.is_empty());
    }

    #[test]
    fn diff_report_honors_stamped_seq_and_legacy_none() {
        let actions = vec![action(vid(0x01), KeeperActionKind::Claim, 500_000, "vesting_unlocked")];
        let base = KeeperReport {
            at: AT,
            scanned: 1,
            actions,
            jito_tip: None,
            pool_balance: 0,
            pool_inflow: 0,
            pool_outflow: 0,
            report_seq: Some(7),
        };
        let (diff, next) = diff_report(&ReportWatermark::initial(), &base);
        assert_eq!(diff.report_seq, 7);
        assert_eq!(next.last_report_seq, 7);
        assert_eq!(diff.changes.len(), 1);
        // A legacy report without a stamp is treated as the next
        // sequence — adopting incremental reports yields one full
        // Added diff, then steady-state empties.
        let mut legacy = base.clone();
        legacy.report_seq = None;
        let (diff2, next2) = diff_report(&ReportWatermark::initial(), &legacy);
        assert_eq!(diff2.report_seq, 1);
        assert_eq!(next2.last_report_seq, 1);
        assert_eq!(diff2.changes.len(), 1);
        assert_eq!(diff2.changes[0].change, VaultChangeKind::Added);
        let (diff3, _) = diff_report(&next2, &legacy);
        assert!(diff3.is_empty(), "replaying the legacy report is a no-op");
    }

    // -- CSV ---------------------------------------------------------

    fn sample_diff() -> ReportDiff {
        ReportDiff {
            report_seq: 9,
            at: AT,
            changes: vec![
                VaultChange {
                    escrow_id: vid(0x01),
                    change: VaultChangeKind::Added,
                    actions: vec![
                        action(vid(0x01), KeeperActionKind::Claim, 500_000, "vesting_unlocked"),
                        action(vid(0x01), KeeperActionKind::Slash, 10_000, "slash_deadline_passed"),
                    ],
                },
                VaultChange {
                    escrow_id: vid(0x02),
                    change: VaultChangeKind::Changed,
                    actions: vec![action(vid(0x02), KeeperActionKind::Resolve, 900_000, "disputed")],
                },
                VaultChange {
                    escrow_id: vid(0x03),
                    change: VaultChangeKind::Removed,
                    actions: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn csv_export_is_byte_pinned() {
        let csv = report_diff_to_csv(&sample_diff());
        let id1 = "01".repeat(32);
        let id2 = "02".repeat(32);
        let id3 = "03".repeat(32);
        let expected = format!(
            "report_seq,at,escrow_id,change,action,amount,reason\n\
             9,{AT},{id1},added,claim,500000,vesting_unlocked\n\
             9,{AT},{id1},added,slash,10000,slash_deadline_passed\n\
             9,{AT},{id2},changed,resolve,900000,disputed\n\
             9,{AT},{id3},removed,,0,\n"
        );
        assert_eq!(csv, expected);
    }

    #[test]
    fn csv_round_trip_preserves_carried_fields() {
        let diff = sample_diff();
        let csv = report_diff_to_csv(&diff);
        let back = csv_to_report_diff(&csv).unwrap();
        assert_eq!(back.report_seq, diff.report_seq);
        assert_eq!(back.at, diff.at);
        assert_eq!(back.changes.len(), 3);
        for (orig, rt) in diff.changes.iter().zip(back.changes.iter()) {
            assert_eq!(rt.escrow_id, orig.escrow_id);
            assert_eq!(rt.change, orig.change);
            assert_eq!(rt.actions.len(), orig.actions.len());
            for (oa, ra) in orig.actions.iter().zip(rt.actions.iter()) {
                assert_eq!(ra.kind, oa.kind);
                assert_eq!(ra.amount, oa.amount);
                assert_eq!(ra.reason, oa.reason);
                assert_eq!(ra.escrow_id, oa.escrow_id);
            }
        }
        // The removed vault survives as an action-less change.
        assert!(back.changes[2].actions.is_empty());
        // The projection zeroes the non-carried fields (AV-74 style).
        let rebuilt = &back.changes[0].actions[0];
        assert_eq!(rebuilt.caller, [0u8; 32]);
        assert_eq!(rebuilt.caller_role, "");
        assert!(rebuilt.mint.is_none());
        // Re-emission is byte-identical: the parse is canonical.
        assert_eq!(report_diff_to_csv(&back), csv);
    }

    #[test]
    fn csv_empty_diff_exports_header_only() {
        let diff = ReportDiff {
            report_seq: 3,
            at: AT,
            changes: Vec::new(),
        };
        let csv = report_diff_to_csv(&diff);
        assert_eq!(csv, "report_seq,at,escrow_id,change,action,amount,reason\n");
        let back = csv_to_report_diff(&csv).unwrap();
        // No rows: the sequence falls back to the documented zero.
        assert_eq!(back.report_seq, 0);
        assert!(back.changes.is_empty());
    }

    #[test]
    fn csv_rejects_bad_inputs() {
        assert_eq!(csv_to_report_diff(""), Err(DiffCsvError::MissingHeader));
        let bad_header = csv_to_report_diff("report_seq,at\n1,2\n");
        assert_eq!(
            bad_header,
            Err(DiffCsvError::UnexpectedHeader {
                got: "report_seq,at".to_string()
            })
        );
        let id = "01".repeat(32);
        // Unknown change kind.
        let csv = format!("{DIFF_HEADER}\n9,{AT},{id},launched,claim,1,expired\n");
        assert_eq!(
            csv_to_report_diff(&csv),
            Err(DiffCsvError::UnknownChange {
                line: 2,
                value: "launched".to_string()
            })
        );
        // Unknown action kind.
        let csv = format!("{DIFF_HEADER}\n9,{AT},{id},added,launch,1,expired\n");
        assert_eq!(
            csv_to_report_diff(&csv),
            Err(DiffCsvError::UnknownAction {
                line: 2,
                value: "launch".to_string()
            })
        );
        // Unknown reason.
        let csv = format!("{DIFF_HEADER}\n9,{AT},{id},added,claim,1,bogus\n");
        assert_eq!(
            csv_to_report_diff(&csv),
            Err(DiffCsvError::UnknownReason {
                line: 2,
                value: "bogus".to_string()
            })
        );
        // Bad field count.
        let csv = format!("{DIFF_HEADER}\n9,{AT},{id},added\n");
        assert_eq!(
            csv_to_report_diff(&csv),
            Err(DiffCsvError::BadFieldCount {
                line: 2,
                expected: 7,
                got: 4
            })
        );
        // Invalid escrow hex.
        let csv = format!("{DIFF_HEADER}\n9,{AT},01,added,claim,1,expired\n");
        assert_eq!(
            csv_to_report_diff(&csv),
            Err(DiffCsvError::InvalidEscrowIdHex {
                line: 2,
                value: "01".to_string()
            })
        );
        // Mixed report_seq across rows.
        let csv = format!(
            "{DIFF_HEADER}\n9,{AT},{id},added,claim,1,expired\n8,{AT},{id},added,claim,2,expired\n"
        );
        assert_eq!(
            csv_to_report_diff(&csv),
            Err(DiffCsvError::MixedReportSeq {
                line: 3,
                expected: 9,
                got: 8
            })
        );
        // Mixed at across rows.
        let csv = format!(
            "{DIFF_HEADER}\n9,{AT},{id},added,claim,1,expired\n9,1,{id},added,claim,2,expired\n"
        );
        assert_eq!(
            csv_to_report_diff(&csv),
            Err(DiffCsvError::MixedAt {
                line: 3,
                expected: AT,
                got: 1
            })
        );
        // A removed row must not carry an action.
        let csv = format!("{DIFF_HEADER}\n9,{AT},{id},removed,claim,0,\n");
        assert_eq!(
            csv_to_report_diff(&csv),
            Err(DiffCsvError::RemovedRowHasAction {
                line: 2,
                value: "claim".to_string()
            })
        );
        // …nor a non-zero amount…
        let csv = format!("{DIFF_HEADER}\n9,{AT},{id},removed,,5,\n");
        assert_eq!(
            csv_to_report_diff(&csv),
            Err(DiffCsvError::RemovedRowHasAmount {
                line: 2,
                value: "5".to_string()
            })
        );
        // …nor a reason.
        let csv = format!("{DIFF_HEADER}\n9,{AT},{id},removed,,0,expired\n");
        assert_eq!(
            csv_to_report_diff(&csv),
            Err(DiffCsvError::RemovedRowHasReason {
                line: 2,
                value: "expired".to_string()
            })
        );
        // The same escrow twice, non-consecutively.
        let id2 = "02".repeat(32);
        let csv = format!(
            "{DIFF_HEADER}\n9,{AT},{id},added,claim,1,expired\n9,{AT},{id2},added,claim,1,expired\n9,{AT},{id},added,claim,1,expired\n"
        );
        assert_eq!(
            csv_to_report_diff(&csv),
            Err(DiffCsvError::DuplicateEscrow {
                line: 4,
                value: id.clone()
            })
        );
        // Same escrow, conflicting change kinds.
        let csv = format!(
            "{DIFF_HEADER}\n9,{AT},{id},added,claim,1,expired\n9,{AT},{id},changed,claim,1,expired\n"
        );
        assert_eq!(
            csv_to_report_diff(&csv),
            Err(DiffCsvError::EscrowChangeMismatch {
                line: 3,
                value: id
            })
        );
    }

    #[test]
    fn csv_tolerates_crlf() {
        let csv = report_diff_to_csv(&sample_diff()).replace('\n', "\r\n");
        let back = csv_to_report_diff(&csv).unwrap();
        assert_eq!(back.changes.len(), 3);
        assert_eq!(back.report_seq, 9);
    }

    #[test]
    fn thousand_vault_diff_runs_well_under_a_second() {
        let mut actions = Vec::with_capacity(2000);
        for i in 0..1000u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_le_bytes());
            actions.push(action(id, KeeperActionKind::Claim, 500_000, "vesting_unlocked"));
            actions.push(action(id, KeeperActionKind::Slash, 10_000, "slash_deadline_passed"));
        }
        let start = std::time::Instant::now();
        let (diff, next) = compute_diff(&ReportWatermark::initial(), 1, AT, &actions);
        let elapsed = start.elapsed();
        assert_eq!(diff.changes.len(), 1000);
        assert_eq!(next.vault_fingerprints.len(), 1000);
        // Loose on purpose: a smoke bound, not a benchmark.
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "1000-vault diff took {elapsed:?}"
        );
    }
}

