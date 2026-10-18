//! Expiry-warning keeper scan (AV-136 — Solana operations): read-only,
//! edge-triggered warnings for escrows whose deadline falls inside a
//! caller-chosen warning window.
//!
//! [`scan_keeper_actions`](crate::scan_keeper_actions) (AV-20) lists
//! *already-expired* escrows with an immediately executable
//! `cancel_expired`; this scan is its complement — it fires *before*
//! the deadline, while the operator can still act. Each warning
//! carries an executable checklist trimmed by the escrow's state and
//! configuration (reusing the AV-59 [`Escrow::extend_expiry`]
//! semantics), so a keeper bot or an operator dashboard knows exactly
//! which calls are available and under what conditions.
//!
//! # Dry-run by construction
//!
//! [`scan_expiry_warnings`] is a pure function: it only reads `&Escrow`
//! snapshots, emits no events, touches no clock, and keeps no state.
//! Edge-triggering ("warn once per escrow per deadline") lives in the
//! caller-held [`ExpiryWarningLedger`]: the scan stays side-effect
//! free while the ledger suppresses repeats. A deadline moved by
//! [`Escrow::extend_expiry`] produces a new `warning_key`, so the
//! warning re-arms automatically after a renewal — no explicit reset
//! needed.
//!
//! # Determinism
//!
//! Warnings are emitted sorted by `(expires_at, escrow_id)` and
//! [`ExpiryWarningReport::to_json`] hand-serializes with fixed field
//! order (the crate is dependency-free), so two scans of the same
//! watch list at the same `now` produce byte-identical JSON.

use crate::{Escrow, EscrowState, WatchedEscrow};
use std::collections::HashSet;

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// One executable operator action attached to an [`ExpiryWarning`].
///
/// The checklist is advisory: `executable_now` is evaluated against
/// the scan's `now`, and `detail` states the exact call conditions so
/// an operator (or a keeper bot) can decide without re-reading the
/// state machine docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchAction {
    /// The instruction name, e.g. `"extend_expiry"`.
    pub action: &'static str,
    /// Who may sign it: `"initializer"`, `"initializer_or_taker"`,
    /// or `"taker"`.
    pub caller: &'static str,
    /// Whether the call would succeed if submitted at the scan's
    /// `now` (best-effort read of the on-chain predicates).
    pub executable_now: bool,
    /// Concrete arguments / conditions, e.g. the AV-59 per-call
    /// increment bound or the grace-period eligibility instant.
    pub detail: String,
}

/// One escrow whose deadline falls inside the warning window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryWarning {
    /// Caller-supplied escrow identity (the
    /// [`WatchedEscrow`](crate::WatchedEscrow) convention).
    pub escrow_id: [u8; 32],
    /// `"Funded"` or `"Activated"` — the only states warned about.
    pub state: &'static str,
    /// The deadline that is approaching.
    pub expires_at: u64,
    /// `expires_at - now` at scan time.
    pub expires_in_secs: u64,
    /// Locked funds still in the vault.
    pub remaining_amount: u64,
    /// How many times AV-59 `extend_expiry` already moved the
    /// deadline (saturating).
    pub extension_count: u64,
    /// The AV-59 per-call extension bound; `0` means extension was
    /// never enabled.
    pub max_extension_secs: u64,
    /// Deterministic edge-trigger key: `hex(escrow_id):expires_at`.
    /// A renewed deadline (via `extend_expiry`) yields a new key, so
    /// the warning re-arms automatically.
    pub warning_key: String,
    /// The executable checklist, trimmed by state and configuration.
    pub checklist: Vec<WatchAction>,
}

/// The read-only result of [`scan_expiry_warnings`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryWarningReport {
    /// The `now` the scan ran at.
    pub at: u64,
    /// The warning window in seconds the scan used.
    pub warn_window_secs: u64,
    /// How many watched escrows were scanned.
    pub scanned: usize,
    /// Warnings, sorted by `(expires_at, escrow_id)`.
    pub warnings: Vec<ExpiryWarning>,
}

impl ExpiryWarningReport {
    /// Hand-serialized JSON (the crate is dependency-free).
    /// Deterministic field order; keys are 64-char lowercase hex.
    ///
    /// ```json
    /// {"at":999000,"warn_window_secs":86400,"scanned":2,"warnings":[
    ///  {"escrow_id":"...","state":"Funded","expires_at":1000000,
    ///   "expires_in_secs":1000,"remaining_amount":1000000,
    ///   "extension_count":1,"max_extension_secs":86400,
    ///   "warning_key":"...:1000000",
    ///   "checklist":[{"action":"extend_expiry","caller":"initializer",
    ///    "executable_now":true,"detail":"..."}]}]}
    /// ```
    pub fn to_json(&self) -> String {
        fn esc(s: &mut String, v: &str) {
            for c in v.chars() {
                match c {
                    '"' => s.push_str("\\\""),
                    '\\' => s.push_str("\\\\"),
                    '\n' => s.push_str("\\n"),
                    _ => s.push(c),
                }
            }
        }
        let mut s = String::with_capacity(160 + self.warnings.len() * 400);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"warn_window_secs\":");
        s.push_str(&self.warn_window_secs.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"warnings\":[");
        for (i, w) in self.warnings.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&w.escrow_id));
            s.push_str("\",\"state\":\"");
            s.push_str(w.state);
            s.push_str("\",\"expires_at\":");
            s.push_str(&w.expires_at.to_string());
            s.push_str(",\"expires_in_secs\":");
            s.push_str(&w.expires_in_secs.to_string());
            s.push_str(",\"remaining_amount\":");
            s.push_str(&w.remaining_amount.to_string());
            s.push_str(",\"extension_count\":");
            s.push_str(&w.extension_count.to_string());
            s.push_str(",\"max_extension_secs\":");
            s.push_str(&w.max_extension_secs.to_string());
            s.push_str(",\"warning_key\":\"");
            esc(&mut s, &w.warning_key);
            s.push_str("\",\"checklist\":[");
            for (j, a) in w.checklist.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                s.push_str("{\"action\":\"");
                s.push_str(a.action);
                s.push_str("\",\"caller\":\"");
                s.push_str(a.caller);
                s.push_str("\",\"executable_now\":");
                s.push_str(if a.executable_now { "true" } else { "false" });
                s.push_str(",\"detail\":\"");
                esc(&mut s, &a.detail);
                s.push_str("\"}");
            }
            s.push_str("]}");
        }
        s.push_str("]}");
        s
    }
}

/// Scan `watched` for escrows whose deadline falls inside
/// `[now, now + warn_window_secs]` and emit one [`ExpiryWarning`] per
/// hit, sorted by `(expires_at, escrow_id)`.
///
/// Only `Funded` and `Activated` escrows are warned about:
/// `Disputed` escrows are owned by the arbitration path (a panel vote
/// or `resolve` moves them, not the deadline), terminal states need
/// no warning, and already-expired escrows belong to AV-20's
/// `cancel_expired` scan — warning about them here would double-list.
/// An escrow expiring exactly at `now + warn_window_secs` is included
/// (inclusive window edge).
///
/// Pure: reads `&Escrow` snapshots only — no mutation, no events, no
/// clock. The caller dedups repeats with [`ExpiryWarningLedger`].
pub fn scan_expiry_warnings(
    watched: &[WatchedEscrow],
    now: u64,
    warn_window_secs: u64,
) -> ExpiryWarningReport {
    let mut warnings = Vec::new();
    for w in watched {
        let e = &w.escrow;
        let state = match e.state() {
            EscrowState::Funded => "Funded",
            EscrowState::Activated => "Activated",
            _ => continue,
        };
        let expires_at = e.expires_at();
        // Already expired (or expiring exactly now): AV-20's
        // `cancel_expired` scan owns these — never double-list.
        if expires_at <= now {
            continue;
        }
        if expires_at - now > warn_window_secs {
            continue;
        }
        warnings.push(build_warning(w.escrow_id, e, state, now));
    }
    warnings.sort_by(|a, b| {
        (a.expires_at, a.escrow_id).cmp(&(b.expires_at, b.escrow_id))
    });
    ExpiryWarningReport {
        at: now,
        warn_window_secs,
        scanned: watched.len(),
        warnings,
    }
}

fn build_warning(
    escrow_id: [u8; 32],
    e: &Escrow,
    state: &'static str,
    now: u64,
) -> ExpiryWarning {
    let expires_at = e.expires_at();
    let max_extension_secs = e.max_extension_secs();
    let mut checklist = Vec::with_capacity(3);

    // 1. extend_expiry (AV-59 semantics): initializer-only, Funded or
    // Uninitialized state, per-call increment capped at
    // max_extension_secs, and never on an already-eligible (expired)
    // escrow. The watch only sees Funded/Activated, so the state gate
    // trims the Activated case explicitly instead of listing a call
    // the chain would reject.
    if state == "Funded" {
        let enabled = max_extension_secs > 0;
        let executable_now = enabled && !e.is_expiry_eligible(now);
        let detail = if !enabled {
            "extension never enabled on this escrow (with_max_extension_secs was not called); \
             the deadline cannot be moved in place"
                .to_string()
        } else if e.is_expiry_eligible(now) {
            format!(
                "extension disabled by expiry: now >= expires_at + grace_period ({}s); \
                 cancel_expired owns the expired escrow",
                e.grace_period()
            )
        } else {
            format!(
                "initializer only; one call may push expires_at forward by at most {}s \
                 (new_expires_at <= expires_at + {}s and > expires_at); \
                 already extended {} time(s)",
                max_extension_secs, max_extension_secs, e.extension_count()
            )
        };
        checklist.push(WatchAction {
            action: "extend_expiry",
            caller: "initializer",
            executable_now,
            detail,
        });
    } else {
        // Activated: extend_expiry's state gate (Uninitialized |
        // Funded only) rejects — list it as not-executable with the
        // reason instead of pretending the operator can renew.
        checklist.push(WatchAction {
            action: "extend_expiry",
            caller: "initializer",
            executable_now: false,
            detail: "not applicable while Activated: extend_expiry requires \
                     Funded state (AV-59) — activate then fund first; the \
                     deadline keeps ticking meanwhile"
                .to_string(),
        });
    }

    // 2. cancel_expired: either party, once the AV-21 grace gate
    // passes. Inside the warning window it is never executable yet —
    // the warning exists precisely so the operator can act first —
    // but the checklist names the exact eligibility instant.
    let eligible_at = expires_at.saturating_add(e.grace_period());
    checklist.push(WatchAction {
        action: "cancel_expired",
        caller: "initializer_or_taker",
        executable_now: e.is_expiry_eligible(now),
        detail: format!(
            "either party may cancel once now >= expires_at + grace_period ({}s), \
             i.e. at t={}; refunds the remaining {} lamports to the initializer",
            e.grace_period(),
            eligible_at,
            e.remaining_amount()
        ),
    });

    // 3. claim: only meaningful with a vesting schedule attached; the
    // taker claims the vested-but-unreleased portion. Unlock
    // evaluation is call-time (schedule math), so the scan does not
    // claim executability here.
    if e.vesting_schedule().is_some() {
        checklist.push(WatchAction {
            action: "claim",
            caller: "taker",
            executable_now: false,
            detail: "vesting schedule attached: the taker claims the \
                     vested-but-unreleased portion via claim; evaluate the \
                     schedule unlock at call time"
                .to_string(),
        });
    }

    ExpiryWarning {
        escrow_id,
        state,
        expires_at,
        expires_in_secs: expires_at - now,
        remaining_amount: e.remaining_amount(),
        extension_count: e.extension_count(),
        max_extension_secs,
        warning_key: format!("{}:{}", hex32(&escrow_id), expires_at),
        checklist,
    }
}

/// Caller-held edge-trigger state for [`scan_expiry_warnings`].
///
/// The scan itself is pure (dry-run); this ledger is the explicit
/// mutation the operator opts into. [`filter_new`](Self::filter_new)
/// passes through only warnings whose `(escrow_id, expires_at)` was
/// never returned before — the same escrow warns exactly once per
/// deadline. A renewed deadline ([`Escrow::extend_expiry`]) changes
/// `expires_at`, producing a fresh key, so the warning re-arms
/// automatically with no reset call.
#[derive(Debug, Default)]
pub struct ExpiryWarningLedger {
    seen: HashSet<([u8; 32], u64)>,
}

impl ExpiryWarningLedger {
    /// Empty ledger: every warning is new.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the warnings of `report` not seen before, recording
    /// their keys. Repeat scans of an unchanged watch list return an
    /// empty vec — the edge-triggered contract.
    pub fn filter_new<'a>(
        &mut self,
        report: &'a ExpiryWarningReport,
    ) -> Vec<&'a ExpiryWarning> {
        let mut out = Vec::new();
        for w in &report.warnings {
            if self.seen.insert((w.escrow_id, w.expires_at)) {
                out.push(w);
            }
        }
        out
    }

    /// How many distinct `(escrow_id, expires_at)` keys are armed.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether no warning was ever recorded.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Escrow, EscrowError};

    const ALICE: [u8; 32] = [1u8; 32];
    const BOB: [u8; 32] = [2u8; 32];
    const ID_A: [u8; 32] = [0xAA; 32];
    const ID_B: [u8; 32] = [0xBB; 32];

    fn funded(expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, expires_at).unwrap();
        e.fund(ALICE, expires_at).unwrap();
        e
    }

    fn watched(id: [u8; 32], escrow: Escrow) -> WatchedEscrow {
        WatchedEscrow {
            escrow_id: id,
            escrow,
            reference: None,
            vault_derivation: None,
            pending_intent: None,
        }
    }

    #[test]
    fn warns_for_funded_escrow_inside_window() {
        let now = 1_000_000;
        let report = scan_expiry_warnings(
            &[watched(ID_A, funded(now + 3_600))],
            now,
            86_400,
        );
        assert_eq!(report.scanned, 1);
        assert_eq!(report.warnings.len(), 1);
        let w = &report.warnings[0];
        assert_eq!(w.state, "Funded");
        assert_eq!(w.expires_in_secs, 3_600);
        assert_eq!(w.remaining_amount, 1_000_000);
        assert_eq!(
            w.warning_key,
            format!("{}:{}", hex32(&ID_A), now + 3_600)
        );
        // Checklist: extend_expiry (not enabled -> not executable),
        // cancel_expired (not yet eligible), no claim (no vesting).
        assert_eq!(w.checklist.len(), 2);
        assert_eq!(w.checklist[0].action, "extend_expiry");
        assert_eq!(w.checklist[0].caller, "initializer");
        assert!(!w.checklist[0].executable_now);
        assert_eq!(w.checklist[1].action, "cancel_expired");
        assert_eq!(w.checklist[1].caller, "initializer_or_taker");
        assert!(!w.checklist[1].executable_now);
    }

    #[test]
    fn extend_expiry_checklist_executable_when_enabled() {
        let now = 1_000_000;
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, now + 3_600).unwrap();
        e = e.with_max_extension_secs(86_400).unwrap();
        e.fund(ALICE, now + 3_600).unwrap();
        let report = scan_expiry_warnings(&[watched(ID_A, e)], now, 86_400);
        let w = &report.warnings[0];
        assert_eq!(w.max_extension_secs, 86_400);
        assert!(w.checklist[0].executable_now);
        assert!(w.checklist[0].detail.contains("86400"));
    }

    #[test]
    fn skips_outside_window_and_expired_and_disputed() {
        let now = 1_000_000;
        // Outside the window.
        let far = watched(ID_A, funded(now + 200_000));
        // Already expired: AV-20's cancel_expired scan owns it.
        let old = watched(ID_B, funded(now - 10));
        // Disputed: arbitration owns it.
        let mut d = Escrow::initialize(ALICE, BOB, 1_000_000, now + 3_600).unwrap();
        d = d.with_arbiter([0xDD; 32]).unwrap();
        d.fund(ALICE, now + 3_600).unwrap();
        d.escalate(ALICE, now, 500_000, None, None, 0).unwrap();
        let disputed = watched([0xCC; 32], d);
        let report = scan_expiry_warnings(&[far, old, disputed], now, 86_400);
        assert_eq!(report.scanned, 3);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn warns_activated_with_extend_expiry_not_executable() {
        let now = 1_000_000;
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, now + 3_600)
            .unwrap()
            .with_dual_sig()
            .unwrap();
        // Activated via both parties (initializer == taker not
        // required; activate records one signature each).
        let mut e = e;
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        assert_eq!(e.state(), EscrowState::Activated);
        let report = scan_expiry_warnings(&[watched(ID_A, e)], now, 86_400);
        assert_eq!(report.warnings.len(), 1);
        let w = &report.warnings[0];
        assert_eq!(w.state, "Activated");
        assert_eq!(w.checklist[0].action, "extend_expiry");
        assert!(!w.checklist[0].executable_now);
        assert!(w.checklist[0].detail.contains("Activated"));
    }

    #[test]
    fn ledger_edge_triggers_and_rearms_on_renewal() {
        let now = 1_000_000;
        let mut ledger = ExpiryWarningLedger::new();
        assert!(ledger.is_empty());

        let list = vec![watched(ID_A, funded(now + 3_600))];
        let r1 = scan_expiry_warnings(&list, now, 86_400);
        assert_eq!(ledger.filter_new(&r1).len(), 1);
        assert_eq!(ledger.len(), 1);
        // Repeat scan: suppressed.
        let r2 = scan_expiry_warnings(&list, now + 100, 86_400);
        assert!(ledger.filter_new(&r2).is_empty());
        // extend_expiry moves the deadline -> new key -> re-arms.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, now + 3_600).unwrap();
        e = e.with_max_extension_secs(86_400).unwrap();
        e.fund(ALICE, now + 3_600).unwrap();
        e.extend_expiry(ALICE, now + 10_000, now).unwrap();
        let r3 = scan_expiry_warnings(&[watched(ID_A, e)], now + 100, 86_400);
        let fresh = ledger.filter_new(&r3);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].expires_at, now + 10_000);
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn scan_is_pure_and_deterministic() {
        let now = 1_000_000;
        let list = vec![
            watched(ID_B, funded(now + 7_200)),
            watched(ID_A, funded(now + 3_600)),
        ];
        let r1 = scan_expiry_warnings(&list, now, 86_400);
        let r2 = scan_expiry_warnings(&list, now, 86_400);
        assert_eq!(r1.to_json(), r2.to_json());
        // Sorted by expires_at regardless of input order.
        assert_eq!(r1.warnings[0].escrow_id, ID_A);
        assert_eq!(r1.warnings[1].escrow_id, ID_B);
        let json = r1.to_json();
        assert!(json.contains("\"warn_window_secs\":86400"));
        assert!(json.contains("\"state\":\"Funded\""));
        assert!(json.contains("\"action\":\"extend_expiry\""));
    }

    #[test]
    fn window_edge_is_inclusive() {
        let now = 1_000_000;
        let report =
            scan_expiry_warnings(&[watched(ID_A, funded(now + 86_400))], now, 86_400);
        assert_eq!(report.warnings.len(), 1);
    }

    #[test]
    fn zero_window_warns_nothing() {
        let now = 1_000_000;
        let report =
            scan_expiry_warnings(&[watched(ID_A, funded(now + 3_600))], now, 0);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn extend_expiry_rejects_wrong_caller() {
        // Sanity: the checklist's "initializer only" claim matches
        // the state machine — a stranger cannot extend.
        let now = 1_000_000;
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, now + 3_600).unwrap();
        e = e.with_max_extension_secs(86_400).unwrap();
        e.fund(ALICE, now + 3_600).unwrap();
        assert_eq!(
            e.extend_expiry([9u8; 32], now + 10_000, now),
            Err(EscrowError::Unauthorized)
        );
    }
}
