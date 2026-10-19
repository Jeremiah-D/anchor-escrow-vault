//! Keeper watchtower (AV-147): the standing off-chain monitor that
//! scans the fleet's [`IndexedEscrow`] vaults and emits alert events
//! for the three conditions an operator pages on:
//!
//! - `expiry_soon`: a `Funded` vault whose deadline is inside the
//!   warning window — the operator can still extend, release, or
//!   claim before the taker's cancel window opens.
//! - `arbitration_pending`: a `Disputed` vault whose arbitration has
//!   been open longer than the pending threshold — the arbiter or
//!   panel has not ruled.
//! - `rent_unclaimed`: a terminal vault (`Cancelled` / `Released` /
//!   `Settled` / `Split` / `Declined` — the AV-34 `close_vault` gate)
//!   whose rent-exempt deposit has sat unclaimed longer than the
//!   threshold.
//!
//! # How this differs from the neighboring scans
//!
//! [`scan_expiry_warnings`](crate::scan_expiry_warnings) (AV-136) is
//! the per-vault edge-triggered operator warning with a re-arm ledger
//! and an executable checklist; the watchtower's `expiry_soon` is
//! the standing threshold monitor with a severity tier —
//! dashboards consume the alert, the expiry scan drives the
//! per-vault response. [`scan_closeable`](crate::scan_closeable)
//! (AV-40) and [`scan_unclaimed_rent`](crate::scan_unclaimed_rent)
//! (AV-139) plan *executable* close/sweep calls; the watchtower's
//! `rent_unclaimed` only raises the alert and names the advisory
//! remedy — the operator picks the executable path. One module, one
//! pass, three fleet-health alerts: the monitor, not the executor.
//!
//! # Dry-run by construction
//!
//! [`scan_watchtower`] only reads the indexed snapshots, emits no
//! events, touches no clock beyond the caller-supplied `now`, and
//! mutates nothing. Alert thresholds are caller-configurable with
//! conservative defaults ([`WatchtowerConfig::default`]).
//!
//! # Output
//!
//! [`WatchtowerReport::to_json`] hand-serializes the report (the crate
//! is dependency-free): deterministic field order, keys as 64-char
//! lowercase hex. Alerts sort by (kind, `escrow_id`), so two scans of
//! the same watch list at the same `now` produce byte-identical JSON.

use crate::{Escrow, EscrowState, IndexedEscrow};

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

/// Alert thresholds for [`scan_watchtower`]. All fields are seconds.
/// Use [`WatchtowerConfig::default`] for the conservative built-ins,
/// or tune per fleet; [`WatchtowerConfig::validate`] fail-fasts on
/// nonsense (the scan validates before emitting anything).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchtowerConfig {
    /// A `Funded` vault whose deadline is within this many seconds
    /// raises `expiry_soon` at `"warning"` severity. Must be `> 0`.
    pub expiry_warning_secs: u64,
    /// Inside this many seconds the `expiry_soon` alert escalates to
    /// `"critical"`. Must be `> 0` and strictly below
    /// `expiry_warning_secs`.
    pub expiry_critical_secs: u64,
    /// A `Disputed` vault open longer than this many seconds raises
    /// `arbitration_pending`. Must be `> 0`.
    pub arbitration_pending_secs: u64,
    /// A terminal vault unclosed longer than this many seconds raises
    /// `rent_unclaimed`. Must be `> 0`.
    pub rent_unclaimed_secs: u64,
}

impl Default for WatchtowerConfig {
    /// Conservative built-ins: alert only when the condition is
    /// clearly actionable — a deadline inside 3 days (critical inside
    /// 12 hours), a dispute open over 7 days, rent unclaimed over 14
    /// days.
    fn default() -> Self {
        Self {
            expiry_warning_secs: 3 * 24 * 3600,
            expiry_critical_secs: 12 * 3600,
            arbitration_pending_secs: 7 * 24 * 3600,
            rent_unclaimed_secs: 14 * 24 * 3600,
        }
    }
}

/// Why a [`WatchtowerConfig`] is unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchtowerConfigError {
    /// `expiry_warning_secs` is zero — a zero window never alerts.
    ZeroExpiryWarning,
    /// `expiry_critical_secs` is zero.
    ZeroExpiryCritical,
    /// `expiry_critical_secs >= expiry_warning_secs` — the critical
    /// tier must sit strictly inside the warning tier.
    CriticalNotInsideWarning,
    /// `arbitration_pending_secs` is zero.
    ZeroArbitrationPending,
    /// `rent_unclaimed_secs` is zero.
    ZeroRentUnclaimed,
}

impl WatchtowerConfig {
    /// Fail-fast on nonsense thresholds. Checked first by
    /// [`scan_watchtower`].
    pub fn validate(&self) -> Result<(), WatchtowerConfigError> {
        if self.expiry_warning_secs == 0 {
            return Err(WatchtowerConfigError::ZeroExpiryWarning);
        }
        if self.expiry_critical_secs == 0 {
            return Err(WatchtowerConfigError::ZeroExpiryCritical);
        }
        if self.expiry_critical_secs >= self.expiry_warning_secs {
            return Err(WatchtowerConfigError::CriticalNotInsideWarning);
        }
        if self.arbitration_pending_secs == 0 {
            return Err(WatchtowerConfigError::ZeroArbitrationPending);
        }
        if self.rent_unclaimed_secs == 0 {
            return Err(WatchtowerConfigError::ZeroRentUnclaimed);
        }
        Ok(())
    }
}

/// Which fleet-health condition a [`WatchtowerAlert`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchtowerAlertKind {
    /// A `Funded` vault's deadline is inside the warning window.
    ExpirySoon,
    /// A `Disputed` vault's arbitration has been open too long.
    ArbitrationPending,
    /// A terminal vault's rent has sat unclaimed too long.
    RentUnclaimed,
}

impl WatchtowerAlertKind {
    fn as_str(&self) -> &'static str {
        match self {
            WatchtowerAlertKind::ExpirySoon => "expiry_soon",
            WatchtowerAlertKind::ArbitrationPending => "arbitration_pending",
            WatchtowerAlertKind::RentUnclaimed => "rent_unclaimed",
        }
    }

    /// Deterministic alert order in the report: expiries first
    /// (action is time-critical), then stalled arbitrations, then
    /// idle rent.
    fn rank(&self) -> u8 {
        match self {
            WatchtowerAlertKind::ExpirySoon => 0,
            WatchtowerAlertKind::ArbitrationPending => 1,
            WatchtowerAlertKind::RentUnclaimed => 2,
        }
    }

    /// The advisory remedy the alert names — an operator hint, not an
    /// executable plan (the AV-20/AV-40/AV-139 scans produce the
    /// executable call lists).
    fn remedy(&self) -> &'static str {
        match self {
            // The operator can still move the deadline or settle
            // before the cancel window opens.
            WatchtowerAlertKind::ExpirySoon => "extend_expiry",
            // The ruling is the arbiter's (or panel's) call-time
            // judgment; the monitor only flags the stall.
            WatchtowerAlertKind::ArbitrationPending => "resolve",
            // The initializer's AV-34 close reclaims the rent (the
            // AV-139 permissionless sweep is the fleet's other path
            // once its grace elapses).
            WatchtowerAlertKind::RentUnclaimed => "close_vault",
        }
    }
}

/// One fleet-health alert: what the watchtower saw, how urgent it is,
/// and the advisory remedy. Timing fields are `Some` only for the
/// alert kind they belong to — `None` everywhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchtowerAlert {
    /// Which vault the alert is for.
    pub escrow_id: [u8; 32],
    /// Which condition fired.
    pub kind: WatchtowerAlertKind,
    /// `"warning"` or `"critical"` (only `expiry_soon` escalates to
    /// critical; the other kinds are always `"warning"`).
    pub severity: &'static str,
    /// `expiry_soon`: the vault's deadline.
    pub expires_at: Option<u64>,
    /// `expiry_soon`: seconds until the deadline at scan time.
    pub seconds_left: Option<u64>,
    /// `arbitration_pending`: when the dispute was filed.
    pub disputed_at: Option<u64>,
    /// `arbitration_pending`: seconds the dispute has been open at
    /// scan time.
    pub seconds_pending: Option<u64>,
    /// `rent_unclaimed`: when the vault entered its terminal state.
    pub terminal_at: Option<u64>,
    /// `rent_unclaimed`: seconds since the terminal transition at
    /// scan time.
    pub seconds_since_terminal: Option<u64>,
    /// `rent_unclaimed`: the rent-exempt lamports sitting idle —
    /// [`crate::vault_close_rent_reclaimed`], the same figure the
    /// AV-40 close scan reports.
    pub rent_lamports: Option<u64>,
    /// The advisory remedy (see
    /// [`WatchtowerAlertKind::remedy`](WatchtowerAlertKind)).
    pub remedy: &'static str,
}

impl WatchtowerAlert {
    /// Deterministic JSON for one alert. Timing fields render `null`
    /// when they do not belong to the alert's kind.
    fn to_json(&self) -> String {
        let mut s = String::with_capacity(320);
        s.push_str("{\"escrow_id\":\"");
        s.push_str(&hex32(&self.escrow_id));
        s.push_str("\",\"kind\":\"");
        s.push_str(self.kind.as_str());
        s.push_str("\",\"severity\":\"");
        s.push_str(self.severity);
        s.push_str("\",\"expires_at\":");
        opt_u64(&mut s, self.expires_at);
        s.push_str(",\"seconds_left\":");
        opt_u64(&mut s, self.seconds_left);
        s.push_str(",\"disputed_at\":");
        opt_u64(&mut s, self.disputed_at);
        s.push_str(",\"seconds_pending\":");
        opt_u64(&mut s, self.seconds_pending);
        s.push_str(",\"terminal_at\":");
        opt_u64(&mut s, self.terminal_at);
        s.push_str(",\"seconds_since_terminal\":");
        opt_u64(&mut s, self.seconds_since_terminal);
        s.push_str(",\"rent_lamports\":");
        opt_u64(&mut s, self.rent_lamports);
        s.push_str(",\"remedy\":\"");
        s.push_str(self.remedy);
        s.push_str("\"}");
        s
    }
}

fn opt_u64(s: &mut String, v: Option<u64>) {
    match v {
        Some(n) => s.push_str(&n.to_string()),
        None => s.push_str("null"),
    }
}

/// The watchtower's scan result: every fleet-health alert at
/// [`WatchtowerReport::at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchtowerReport {
    /// The `now` (Unix seconds) the scan ran at.
    pub at: u64,
    /// How many vaults were scanned.
    pub scanned: usize,
    /// The alerts, sorted by (kind rank, `escrow_id`) — deterministic
    /// regardless of input order.
    pub alerts: Vec<WatchtowerAlert>,
}

impl WatchtowerReport {
    /// True when the fleet is healthy (no alerts).
    pub fn is_empty(&self) -> bool {
        self.alerts.is_empty()
    }

    /// Hand-serialized JSON (the crate is dependency-free).
    /// Deterministic field order; keys are 64-char lowercase hex.
    ///
    /// ```json
    /// {"at":1750000000,"scanned":2,"alerts":[
    ///   {"escrow_id":"...","kind":"expiry_soon","severity":"warning",
    ///    "expires_at":1750086400,"seconds_left":86400,
    ///    "disputed_at":null,"seconds_pending":null,
    ///    "terminal_at":null,"seconds_since_terminal":null,
    ///    "rent_lamports":null,"remedy":"extend_expiry"},
    ///   {"escrow_id":"...","kind":"rent_unclaimed","severity":"warning",
    ///    "expires_at":null,"seconds_left":null,
    ///    "disputed_at":null,"seconds_pending":null,
    ///    "terminal_at":1748000000,"seconds_since_terminal":2000000,
    ///    "rent_lamports":42442080,"remedy":"close_vault"}]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(96 + self.alerts.len() * 360);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"alerts\":[");
        for (i, a) in self.alerts.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&a.to_json());
        }
        s.push_str("]}");
        s
    }
}

/// Scan `indexed` at `now` and emit the watchtower's fleet-health
/// alerts. Pure read over the snapshots: zero side effects, no
/// events, no clock access beyond the caller-supplied `now`.
///
/// - `expiry_soon`: `Funded` vaults whose deadline is inside
///   `config.expiry_warning_secs` (`"critical"` inside
///   `config.expiry_critical_secs`). No-timeout vaults
///   (`expires_at == u64::MAX`) and already-expired vaults never
///   alert — the former have no deadline, the latter are the AV-20
///   keeper scan's `cancel_expired` territory.
/// - `arbitration_pending`: `Disputed` vaults open longer than
///   `config.arbitration_pending_secs` (`now - disputed_at`).
/// - `rent_unclaimed`: terminal vaults (the AV-34 `close_vault` gate:
///   `Cancelled` / `Released` / `Settled` / `Split` / `Declined`)
///   unclosed longer than `config.rent_unclaimed_secs`
///   (`now - terminal_at`). `Closed` vaults never alert — the rent is
///   already reclaimed — and `Disputed` vaults never alert — the
///   arbitration is still live and the vault is the arbiter's audit
///   surface.
///
/// Returns [`WatchtowerConfigError`] when the config fails
/// validation — before any alert is evaluated.
pub fn scan_watchtower(
    indexed: &[IndexedEscrow],
    now: u64,
    config: &WatchtowerConfig,
) -> Result<WatchtowerReport, WatchtowerConfigError> {
    config.validate()?;
    let mut alerts: Vec<WatchtowerAlert> = Vec::new();
    for ix in indexed {
        let e = ix.inner();
        let escrow_id = ix.escrow_id();
        // expiry_soon: Funded, real deadline, still in the future,
        // inside the warning window.
        if e.state() == EscrowState::Funded
            && e.expires_at() != u64::MAX
            && e.expires_at() > now
            && e.expires_at() - now <= config.expiry_warning_secs
        {
            let kind = WatchtowerAlertKind::ExpirySoon;
            alerts.push(WatchtowerAlert {
                escrow_id,
                kind,
                severity: if e.expires_at() - now <= config.expiry_critical_secs {
                    "critical"
                } else {
                    "warning"
                },
                expires_at: Some(e.expires_at()),
                seconds_left: Some(e.expires_at() - now),
                disputed_at: None,
                seconds_pending: None,
                terminal_at: None,
                seconds_since_terminal: None,
                rent_lamports: None,
                remedy: kind.remedy(),
            });
        }
        // arbitration_pending: Disputed, open too long.
        if e.state() == EscrowState::Disputed
            && now.saturating_sub(e.disputed_at()) >= config.arbitration_pending_secs
        {
            let kind = WatchtowerAlertKind::ArbitrationPending;
            alerts.push(WatchtowerAlert {
                escrow_id,
                kind,
                severity: "warning",
                expires_at: None,
                seconds_left: None,
                disputed_at: Some(e.disputed_at()),
                seconds_pending: Some(now.saturating_sub(e.disputed_at())),
                terminal_at: None,
                seconds_since_terminal: None,
                rent_lamports: None,
                remedy: kind.remedy(),
            });
        }
        // rent_unclaimed: terminal (closeable), rent sitting idle too
        // long. Closed never alerts (reclaimed); Disputed never
        // alerts (the audit surface is still live).
        if matches!(
            e.state(),
            EscrowState::Cancelled
                | EscrowState::Released
                | EscrowState::Settled
                | EscrowState::Split
                | EscrowState::Declined
        ) && now.saturating_sub(e.terminal_at()) >= config.rent_unclaimed_secs
        {
            let kind = WatchtowerAlertKind::RentUnclaimed;
            alerts.push(WatchtowerAlert {
                escrow_id,
                kind,
                severity: "warning",
                expires_at: None,
                seconds_left: None,
                disputed_at: None,
                seconds_pending: None,
                terminal_at: Some(e.terminal_at()),
                seconds_since_terminal: Some(now.saturating_sub(e.terminal_at())),
                rent_lamports: Some(crate::vault_close_rent_reclaimed()),
                remedy: kind.remedy(),
            });
        }
    }
    // Deterministic regardless of input order.
    alerts.sort_by_key(|a| (a.kind.rank(), a.escrow_id));
    Ok(WatchtowerReport {
        at: now,
        scanned: indexed.len(),
        alerts,
    })
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod watchtower_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const ARBITER: [u8; 32] = [0xA0; 32]; // arbiter
    const AMOUNT: u64 = 1_000_000;
    const NOW: u64 = 1_750_000_000;
    const DAY: u64 = 24 * 3600;

    fn id(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn funded(expires_at: u64, fund_at: u64) -> IndexedEscrow {
        let mut ix = IndexedEscrow::initialize(ALICE, BOB, AMOUNT, expires_at, id(0x01), fund_at)
            .unwrap();
        ix.fund(ALICE, fund_at).unwrap();
        ix
    }

    /// A `Disputed` vault whose dispute was filed at `disputed_at` —
    /// built through the `Escrow` builders (arbiter required for
    /// `escalate`) and wrapped, so no event history is invented.
    fn disputed(escrow_id: [u8; 32], disputed_at: u64) -> IndexedEscrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NOW + 30 * DAY)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE, NOW - 10 * DAY).unwrap();
        e.escalate(ALICE, disputed_at, e.remaining_amount(), None, None, 0)
            .unwrap();
        IndexedEscrow::wrap(escrow_id, e)
    }

    fn with_id(ix: IndexedEscrow, escrow_id: [u8; 32]) -> IndexedEscrow {
        // Re-key the wrapper for multi-vault tests — the inner state
        // is untouched; only the caller-supplied identity changes.
        // (IndexedEscrow has no re-key API; wrap() carries the state
        // over without inventing event history.)
        let inner = *ix.inner();
        IndexedEscrow::wrap(escrow_id, inner)
    }

    fn config() -> WatchtowerConfig {
        WatchtowerConfig::default()
    }

    #[test]
    fn empty_fleet_is_healthy() {
        let report = scan_watchtower(&[], NOW, &config()).unwrap();
        assert!(report.is_empty());
        assert_eq!(report.scanned, 0);
        assert_eq!(report.to_json(), "{\"at\":1750000000,\"scanned\":0,\"alerts\":[]}");
    }

    #[test]
    fn expiry_soon_tiers_warning_and_critical() {
        // Default: warning inside 3 days, critical inside 12 hours.
        let warn_vault = with_id(funded(NOW + 2 * DAY, NOW - DAY), id(0x01));
        let crit_vault = with_id(funded(NOW + 3600, NOW - DAY), id(0x02));
        let far_vault = with_id(funded(NOW + 10 * DAY, NOW - DAY), id(0x03));
        let report = scan_watchtower(&[warn_vault, crit_vault, far_vault], NOW, &config()).unwrap();
        assert_eq!(report.alerts.len(), 2);
        // Sorted by (kind rank, escrow_id): both expiry_soon, id order.
        assert_eq!(report.alerts[0].escrow_id, id(0x01));
        assert_eq!(report.alerts[0].kind, WatchtowerAlertKind::ExpirySoon);
        assert_eq!(report.alerts[0].severity, "warning");
        assert_eq!(report.alerts[0].expires_at, Some(NOW + 2 * DAY));
        assert_eq!(report.alerts[0].seconds_left, Some(2 * DAY));
        assert_eq!(report.alerts[0].remedy, "extend_expiry");
        assert_eq!(report.alerts[1].escrow_id, id(0x02));
        assert_eq!(report.alerts[1].severity, "critical");
        assert_eq!(report.alerts[1].seconds_left, Some(3600));
        // Non-expiry timing fields stay null.
        assert_eq!(report.alerts[0].disputed_at, None);
        assert_eq!(report.alerts[0].rent_lamports, None);
    }

    #[test]
    fn expiry_soon_skips_no_timeout_and_already_expired() {
        // No-timeout vaults have no deadline to warn about.
        let no_timeout = with_id(funded(u64::MAX, NOW - DAY), id(0x01));
        // Already-expired vaults are the AV-20 keeper scan's
        // cancel_expired territory, not the watchtower's.
        let expired = with_id(funded(NOW - 1, NOW - 2 * DAY), id(0x02));
        let report = scan_watchtower(&[no_timeout, expired], NOW, &config()).unwrap();
        assert!(report.is_empty(), "got alerts: {:?}", report.alerts);
    }

    #[test]
    fn arbitration_pending_fires_after_the_threshold() {
        // Dispute filed 8 days ago — past the 7-day default.
        let ix = disputed(id(0x01), NOW - 8 * DAY);
        let report = scan_watchtower(&[ix], NOW, &config()).unwrap();
        assert_eq!(report.alerts.len(), 1);
        let a = &report.alerts[0];
        assert_eq!(a.kind, WatchtowerAlertKind::ArbitrationPending);
        assert_eq!(a.severity, "warning");
        assert_eq!(a.disputed_at, Some(NOW - 8 * DAY));
        assert_eq!(a.seconds_pending, Some(8 * DAY));
        assert_eq!(a.remedy, "resolve");
    }

    #[test]
    fn arbitration_pending_silent_inside_the_threshold() {
        // Dispute filed 2 days ago — inside the 7-day default.
        let ix = disputed(id(0x01), NOW - 2 * DAY);
        let report = scan_watchtower(&[ix], NOW, &config()).unwrap();
        assert!(report.is_empty());
    }

    #[test]
    fn rent_unclaimed_fires_on_idle_terminal_vaults() {
        // Released 20 days ago — past the 14-day default.
        let mut ix = IndexedEscrow::initialize(ALICE, BOB, AMOUNT, NOW + 30 * DAY, id(0x01), NOW - 30 * DAY)
            .unwrap();
        ix.fund(ALICE, NOW - 30 * DAY).unwrap();
        ix.release(ALICE, AMOUNT, None, BOB, NOW - 20 * DAY).unwrap();
        assert_eq!(ix.inner().state(), EscrowState::Released);
        let report = scan_watchtower(&[ix], NOW, &config()).unwrap();
        assert_eq!(report.alerts.len(), 1);
        let a = &report.alerts[0];
        assert_eq!(a.kind, WatchtowerAlertKind::RentUnclaimed);
        assert_eq!(a.severity, "warning");
        assert_eq!(a.terminal_at, Some(NOW - 20 * DAY));
        assert_eq!(a.seconds_since_terminal, Some(20 * DAY));
        assert_eq!(a.rent_lamports, Some(crate::vault_close_rent_reclaimed()));
        assert_eq!(a.remedy, "close_vault");
    }

    #[test]
    fn rent_unclaimed_skips_fresh_and_closed_vaults() {
        // Released 2 days ago — the operator may still be coming.
        let mut fresh = IndexedEscrow::initialize(ALICE, BOB, AMOUNT, NOW + 30 * DAY, id(0x01), NOW - 30 * DAY)
            .unwrap();
        fresh.fund(ALICE, NOW - 30 * DAY).unwrap();
        fresh.release(ALICE, AMOUNT, None, BOB, NOW - 2 * DAY).unwrap();
        // Closed 20 days ago — the rent is already reclaimed.
        let mut closed = IndexedEscrow::initialize(ALICE, BOB, AMOUNT, NOW + 30 * DAY, id(0x02), NOW - 40 * DAY)
            .unwrap();
        closed.fund(ALICE, NOW - 40 * DAY).unwrap();
        closed.release(ALICE, AMOUNT, None, BOB, NOW - 30 * DAY).unwrap();
        closed.close_vault(ALICE, NOW - 20 * DAY).unwrap();
        assert_eq!(closed.inner().state(), EscrowState::Closed);
        let report = scan_watchtower(&[fresh, closed], NOW, &config()).unwrap();
        assert!(report.is_empty(), "got alerts: {:?}", report.alerts);
    }

    #[test]
    fn config_validation_fail_fasts() {
        let mut bad = config();
        bad.expiry_warning_secs = 0;
        assert_eq!(
            scan_watchtower(&[], NOW, &bad).unwrap_err(),
            WatchtowerConfigError::ZeroExpiryWarning
        );
        let mut bad = config();
        bad.expiry_critical_secs = 0;
        assert_eq!(
            scan_watchtower(&[], NOW, &bad).unwrap_err(),
            WatchtowerConfigError::ZeroExpiryCritical
        );
        let mut bad = config();
        bad.expiry_critical_secs = bad.expiry_warning_secs;
        assert_eq!(
            scan_watchtower(&[], NOW, &bad).unwrap_err(),
            WatchtowerConfigError::CriticalNotInsideWarning
        );
        let mut bad = config();
        bad.arbitration_pending_secs = 0;
        assert_eq!(
            scan_watchtower(&[], NOW, &bad).unwrap_err(),
            WatchtowerConfigError::ZeroArbitrationPending
        );
        let mut bad = config();
        bad.rent_unclaimed_secs = 0;
        assert_eq!(
            scan_watchtower(&[], NOW, &bad).unwrap_err(),
            WatchtowerConfigError::ZeroRentUnclaimed
        );
        // The default config is valid.
        assert!(config().validate().is_ok());
    }

    #[test]
    fn scan_is_deterministic_regardless_of_input_order() {
        let expiry = with_id(funded(NOW + DAY, NOW - DAY), id(0x03));
        let disputed_vault = disputed(id(0x02), NOW - 8 * DAY);
        let mut terminal = IndexedEscrow::initialize(ALICE, BOB, AMOUNT, NOW + 30 * DAY, id(0x01), NOW - 30 * DAY)
            .unwrap();
        terminal.fund(ALICE, NOW - 30 * DAY).unwrap();
        terminal.release(ALICE, AMOUNT, None, BOB, NOW - 20 * DAY).unwrap();
        let forward = scan_watchtower(&[expiry.clone(), disputed_vault.clone(), terminal.clone()], NOW, &config()).unwrap();
        let backward = scan_watchtower(&[terminal, disputed_vault, expiry], NOW, &config()).unwrap();
        assert_eq!(forward.to_json(), backward.to_json());
        // Kind rank order: expiry_soon, arbitration_pending,
        // rent_unclaimed.
        let kinds: Vec<WatchtowerAlertKind> =
            forward.alerts.iter().map(|a| a.kind).collect();
        assert_eq!(
            kinds,
            vec![
                WatchtowerAlertKind::ExpirySoon,
                WatchtowerAlertKind::ArbitrationPending,
                WatchtowerAlertKind::RentUnclaimed,
            ]
        );
        assert_eq!(forward.alerts.len(), 3);
    }

    #[test]
    fn json_renders_nulls_for_foreign_timing_fields() {
        let vault = with_id(funded(NOW + 2 * DAY, NOW - DAY), id(0x01));
        let report = scan_watchtower(&[vault], NOW, &config()).unwrap();
        let json = report.to_json();
        assert!(json.contains("\"kind\":\"expiry_soon\",\"severity\":\"warning\""));
        assert!(json.contains("\"disputed_at\":null,\"seconds_pending\":null"));
        assert!(json.contains("\"terminal_at\":null,\"seconds_since_terminal\":null"));
        assert!(json.contains("\"rent_lamports\":null"));
        assert!(json.contains("\"remedy\":\"extend_expiry\""));
    }
}
