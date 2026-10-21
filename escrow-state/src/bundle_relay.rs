//! Private bundle-relay submission adapter (AV-169).
//!
//! Keeper execution bundles (AV-61) carry an optional Jito tip
//! (AV-98) so validators include them promptly. Submitting such a
//! bundle to the *public mempool* broadcasts the settlement intent to
//! everyone watching — including MEV searchers. This module submits
//! the bundle to a *private block-engine relay* (e.g. Jito) instead:
//! the [`BundleRelay`] trait models the relay as an injectable
//! dependency, and [`BundleRelaySubmitter`] orchestrates submission
//! with bundle replay protection plus landing-rate /
//! confirmation-latency observations surfaced as audit events.
//!
//! # The no-fallback rule
//!
//! When the relay is unavailable the submission fails with
//! [`RelayError::Unavailable`] — the adapter NEVER silently falls
//! back to the public mempool. A silent fallback would broadcast the
//! exact intent the private relay was chosen to protect. There is no
//! mempool path in this module at all: [`BundleRelaySubmitter`] has
//! no mempool handle, no mempool flag, and no code path that touches
//! one. Callers that want an explicit, operator-approved fallback do
//! it themselves, outside this adapter, where the decision is
//! visible.
//!
//! # Replay protection
//!
//! [`BundleRelaySubmitter::submit_bundle`] keys every submission on
//! the [`BundleId`] (SHA-256 of the bundle bytes): resubmitting a
//! pending bundle returns the cached receipt (idempotent, no
//! duplicate submission), while resubmitting an already-landed bundle
//! fails with [`RelayError::AlreadyLanded`]. A bundle the relay
//! reports as failed is dropped from tracking so the operator can
//! retry it deliberately.

use std::collections::HashMap;

use crate::JitoTipConfig;

// ---------------------------------------------------------------------------
// Bundle identity and receipts.
// ---------------------------------------------------------------------------

/// Identity of a bundle: SHA-256 of its signable bytes (the same
/// hand-written hash the CPI accounts-hash audit commitment uses).
/// Two submissions with identical bytes are the same bundle — that
/// is what the replay protection keys on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BundleId([u8; 32]);

impl BundleId {
    /// Hash the bundle's signable bytes into its identity.
    pub fn of(bundle_bytes: &[u8]) -> Self {
        BundleId(crate::sha256(bundle_bytes))
    }

    /// The raw 32-byte hash.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Lowercase hex encoding (for logs and audit events).
    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in &self.0 {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0x0F) as u32, 16).unwrap());
        }
        s
    }
}

/// What the relay returns on an accepted submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleReceipt {
    /// The submitted bundle's identity.
    pub bundle_id: BundleId,
    /// The tip the relay will bid with (from the AV-98
    /// [`JitoTipConfig`]).
    pub tip_lamports: u64,
}

/// The relay's answer when asked about a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleStatus {
    /// Accepted, not yet landed.
    Pending,
    /// Included in a block at `landed_slot`.
    Landed {
        /// The slot whose block included the bundle.
        landed_slot: u64,
    },
    /// The relay dropped the bundle.
    Failed {
        /// The relay's reported reason (opaque string).
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// The relay trait and its errors.
// ---------------------------------------------------------------------------

/// Failures from bundle-relay submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// The relay is unreachable / down. The submission did not
    /// happen; the caller decides what to do — this adapter never
    /// falls back to the public mempool on its own.
    Unavailable(String),
    /// The relay actively refused the bundle (malformed, tip too
    /// low, rate-limited, ...). The reason is the relay's own string.
    Rejected(String),
    /// A transport-level failure talking to the relay (not a
    /// rejection of the bundle itself).
    Transport(String),
    /// The bundle already landed — resubmitting it would risk a
    /// duplicate on-chain execution, so the submission is refused.
    AlreadyLanded(BundleId),
}

/// A private block-engine relay (e.g. Jito's block engine) as an
/// injectable dependency. Implementors talk the relay's API;
/// [`BundleRelaySubmitter`] adds replay protection, stats, and audit
/// observations on top.
pub trait BundleRelay {
    /// Human-readable relay name (for logs and audit events).
    fn name(&self) -> &str;

    /// Submit the bundle's signable bytes with the AV-98 tip config
    /// for auction ordering. The tip instruction itself is already
    /// the bundle's last instruction (AV-98); the config here tells
    /// the relay what the bundle bids.
    fn submit(
        &self,
        bundle_bytes: &[u8],
        tip: &JitoTipConfig,
    ) -> Result<BundleReceipt, RelayError>;

    /// Poll the relay for a bundle's status.
    fn status(&self, bundle_id: &BundleId) -> Result<BundleStatus, RelayError>;
}

// ---------------------------------------------------------------------------
// Observations and audit events.
// ---------------------------------------------------------------------------

/// What one status poll learned about a bundle: landed or failed,
/// with the confirmation latency in slots when it landed. This is
/// the unit the keeper feeds its audit sink — see [`to_json`](Self::to_json).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayObservation {
    /// The observed bundle.
    pub bundle_id: BundleId,
    /// Whether the bundle landed (`false` = the relay dropped it).
    pub landed: bool,
    /// The landing slot, when landed.
    pub landed_slot: Option<u64>,
    /// `landed_slot − submitted_slot`, when landed.
    pub confirmation_latency_slots: Option<u64>,
}

impl RelayObservation {
    /// The audit-event JSON: `{"bundle_id":<hex>,"landed":bool,
    /// "landed_slot":n|null,"confirmation_latency_slots":n|null}`.
    /// Hand-written, zero dependencies — the keeper's audit pipeline
    /// ingests these next to the AV-18 indexer events.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(160);
        s.push_str("{\"bundle_id\":\"");
        s.push_str(&self.bundle_id.hex());
        s.push_str("\",\"landed\":");
        s.push_str(&self.landed.to_string());
        s.push_str(",\"landed_slot\":");
        match self.landed_slot {
            Some(slot) => s.push_str(&slot.to_string()),
            None => s.push_str("null"),
        }
        s.push_str(",\"confirmation_latency_slots\":");
        match self.confirmation_latency_slots {
            Some(lat) => s.push_str(&lat.to_string()),
            None => s.push_str("null"),
        }
        s.push('}');
        s
    }
}

/// Lifecycle audit events for bundle-relay submission, as JSON for
/// the keeper's audit sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleRelayEvent {
    /// A bundle was accepted by the relay.
    Submitted {
        bundle_id: BundleId,
        relay: String,
        submitted_slot: u64,
        tip_lamports: u64,
    },
    /// A bundle landed, with its confirmation latency.
    Landed {
        bundle_id: BundleId,
        relay: String,
        landed_slot: u64,
        confirmation_latency_slots: u64,
    },
    /// The relay dropped a bundle.
    Failed {
        bundle_id: BundleId,
        relay: String,
        reason: String,
    },
    /// The relay was unavailable — the submission did not happen and
    /// no mempool fallback was taken.
    RelayUnavailable {
        relay: String,
        reason: String,
    },
}

impl BundleRelayEvent {
    /// The audit-event JSON. Hand-written; string fields are JSON-
    /// escaped.
    pub fn to_json(&self) -> String {
        fn esc(into: &mut String, s: &str) {
            for c in s.chars() {
                match c {
                    '"' => into.push_str("\\\""),
                    '\\' => into.push_str("\\\\"),
                    '\n' => into.push_str("\\n"),
                    '\r' => into.push_str("\\r"),
                    '\t' => into.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        into.push_str(&format!("\\u{:04x}", c as u32));
                    }
                    c => into.push(c),
                }
            }
        }
        let mut s = String::with_capacity(200);
        match self {
            BundleRelayEvent::Submitted { bundle_id, relay, submitted_slot, tip_lamports } => {
                s.push_str("{\"event\":\"bundle_relay_submitted\",\"bundle_id\":\"");
                s.push_str(&bundle_id.hex());
                s.push_str("\",\"relay\":\"");
                esc(&mut s, relay);
                s.push_str("\",\"submitted_slot\":");
                s.push_str(&submitted_slot.to_string());
                s.push_str(",\"tip_lamports\":");
                s.push_str(&tip_lamports.to_string());
                s.push('}');
            }
            BundleRelayEvent::Landed { bundle_id, relay, landed_slot, confirmation_latency_slots } => {
                s.push_str("{\"event\":\"bundle_relay_landed\",\"bundle_id\":\"");
                s.push_str(&bundle_id.hex());
                s.push_str("\",\"relay\":\"");
                esc(&mut s, relay);
                s.push_str("\",\"landed_slot\":");
                s.push_str(&landed_slot.to_string());
                s.push_str(",\"confirmation_latency_slots\":");
                s.push_str(&confirmation_latency_slots.to_string());
                s.push('}');
            }
            BundleRelayEvent::Failed { bundle_id, relay, reason } => {
                s.push_str("{\"event\":\"bundle_relay_failed\",\"bundle_id\":\"");
                s.push_str(&bundle_id.hex());
                s.push_str("\",\"relay\":\"");
                esc(&mut s, relay);
                s.push_str("\",\"reason\":\"");
                esc(&mut s, reason);
                s.push_str("\"}");
            }
            BundleRelayEvent::RelayUnavailable { relay, reason } => {
                s.push_str("{\"event\":\"bundle_relay_unavailable\",\"relay\":\"");
                esc(&mut s, relay);
                s.push_str("\",\"reason\":\"");
                esc(&mut s, reason);
                s.push_str("\"}");
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Landing-rate / latency statistics.
// ---------------------------------------------------------------------------

/// Running submission statistics for one relay: landing rate and
/// confirmation latency, the two numbers the operator watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayStats {
    /// Bundles accepted by the relay.
    pub submitted: u64,
    /// Bundles observed landed.
    pub landed: u64,
    /// Bundles the relay dropped.
    pub failed: u64,
    /// Submissions refused because the relay was unavailable.
    pub unavailable: u64,
    /// Sum of confirmation latencies (slots) over landed bundles.
    pub total_confirmation_latency_slots: u64,
}

impl RelayStats {
    /// Landing rate in basis points (`landed * 10_000 / submitted`);
    /// `0` when nothing was submitted yet. Integer math — no floats
    /// in this crate.
    pub fn landing_rate_bps(&self) -> u64 {
        if self.submitted == 0 {
            return 0;
        }
        self.landed.saturating_mul(10_000) / self.submitted
    }

    /// Mean confirmation latency in slots over landed bundles;
    /// `None` when nothing landed yet.
    pub fn mean_confirmation_latency_slots(&self) -> Option<u64> {
        if self.landed == 0 {
            return None;
        }
        Some(self.total_confirmation_latency_slots / self.landed)
    }
}

// ---------------------------------------------------------------------------
// The submission orchestrator.
// ---------------------------------------------------------------------------

/// One tracked submission inside [`BundleRelaySubmitter`].
#[derive(Debug, Clone)]
struct TrackedSubmission {
    receipt: BundleReceipt,
    submitted_slot: u64,
    landed_slot: Option<u64>,
}

/// Submits keeper execution bundles to a private block-engine relay,
/// with replay protection and landing observations.
///
/// The submitter owns the relay handle and the tracking map; it has
/// no mempool access by construction, so the no-fallback rule is
/// structural, not just a code comment.
#[derive(Debug)]
pub struct BundleRelaySubmitter<R: BundleRelay> {
    relay: R,
    tracked: HashMap<BundleId, TrackedSubmission>,
    stats: RelayStats,
}

impl<R: BundleRelay> BundleRelaySubmitter<R> {
    /// Wrap a relay handle.
    pub fn new(relay: R) -> Self {
        BundleRelaySubmitter {
            relay,
            tracked: HashMap::new(),
            stats: RelayStats::default(),
        }
    }

    /// The relay's name (for logs and audit events).
    pub fn relay_name(&self) -> &str {
        self.relay.name()
    }

    /// Running statistics.
    pub fn stats(&self) -> RelayStats {
        self.stats
    }

    /// Submit a bundle's signable bytes with the AV-98 tip config.
    ///
    /// Replay protection: a bundle already tracked as *landed* is
    /// refused with [`RelayError::AlreadyLanded`]; a bundle tracked
    /// as *pending* returns the cached receipt without touching the
    /// relay again. A bundle the relay reports failed is dropped
    /// from tracking, so the operator can retry it deliberately.
    ///
    /// [`RelayError::Unavailable`] propagates to the caller — the
    /// submission did not happen, and this adapter takes no mempool
    /// fallback.
    pub fn submit_bundle(
        &mut self,
        bundle_bytes: &[u8],
        tip: &JitoTipConfig,
        current_slot: u64,
    ) -> Result<BundleReceipt, RelayError> {
        let bundle_id = BundleId::of(bundle_bytes);
        if let Some(tracked) = self.tracked.get(&bundle_id) {
            if tracked.landed_slot.is_some() {
                return Err(RelayError::AlreadyLanded(bundle_id));
            }
            return Ok(tracked.receipt.clone());
        }
        let receipt = match self.relay.submit(bundle_bytes, tip) {
            Ok(receipt) => receipt,
            Err(RelayError::Unavailable(reason)) => {
                self.stats.unavailable += 1;
                return Err(RelayError::Unavailable(reason));
            }
            Err(other) => return Err(other),
        };
        // The relay echoes the bundle id it accepted — a mismatched
        // echo is a relay bug: tracking it would key the wrong
        // bundle, so the submission fails loud instead.
        if receipt.bundle_id != bundle_id {
            return Err(RelayError::Transport(
                "relay echoed a mismatched bundle id".to_string(),
            ));
        }
        self.stats.submitted += 1;
        self.tracked.insert(
            bundle_id,
            TrackedSubmission {
                receipt: receipt.clone(),
                submitted_slot: current_slot,
                landed_slot: None,
            },
        );
        Ok(receipt)
    }

    /// Poll the relay for one bundle and record what happened.
    ///
    /// Returns `None` while the bundle is still pending (nothing to
    /// report yet). On landed: marks the bundle landed, records the
    /// confirmation latency into the stats, and returns the
    /// observation. On failed: drops the bundle from tracking
    /// (retryable by the operator), counts the failure, and returns
    /// the observation. Unknown bundle ids return `None` — polling
    /// something never submitted is a caller bug, but a silent
    /// no-op, not a fabricated observation.
    pub fn observe(&mut self, bundle_id: &BundleId) -> Result<Option<RelayObservation>, RelayError> {
        let tracked = match self.tracked.get(bundle_id) {
            Some(t) => t.clone(),
            None => return Ok(None),
        };
        if tracked.landed_slot.is_some() {
            return Ok(None);
        }
        match self.relay.status(bundle_id)? {
            BundleStatus::Pending => Ok(None),
            BundleStatus::Landed { landed_slot } => {
                let latency = landed_slot.saturating_sub(tracked.submitted_slot);
                self.stats.landed += 1;
                self.stats.total_confirmation_latency_slots =
                    self.stats.total_confirmation_latency_slots.saturating_add(latency);
                if let Some(t) = self.tracked.get_mut(bundle_id) {
                    t.landed_slot = Some(landed_slot);
                }
                Ok(Some(RelayObservation {
                    bundle_id: *bundle_id,
                    landed: true,
                    landed_slot: Some(landed_slot),
                    confirmation_latency_slots: Some(latency),
                }))
            }
            BundleStatus::Failed { reason: _ } => {
                self.stats.failed += 1;
                self.tracked.remove(bundle_id);
                Ok(Some(RelayObservation {
                    bundle_id: *bundle_id,
                    landed: false,
                    landed_slot: None,
                    confirmation_latency_slots: None,
                }))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod bundle_relay_tests {
    use super::*;
    use std::cell::RefCell;

    struct MockRelay {
        name: String,
        unavailable: bool,
        reject: Option<String>,
        statuses: RefCell<HashMap<BundleId, BundleStatus>>,
        submit_calls: RefCell<u32>,
        seen_tips: RefCell<Vec<u64>>,
    }

    impl MockRelay {
        fn new(name: &str) -> Self {
            MockRelay {
                name: name.to_string(),
                unavailable: false,
                reject: None,
                statuses: RefCell::new(HashMap::new()),
                submit_calls: RefCell::new(0),
                seen_tips: RefCell::new(Vec::new()),
            }
        }

        fn down(name: &str) -> Self {
            let mut r = Self::new(name);
            r.unavailable = true;
            r
        }

        fn land(&self, id: &BundleId, slot: u64) {
            self.statuses
                .borrow_mut()
                .insert(*id, BundleStatus::Landed { landed_slot: slot });
        }

        fn fail(&self, id: &BundleId, reason: &str) {
            self.statuses.borrow_mut().insert(
                *id,
                BundleStatus::Failed { reason: reason.to_string() },
            );
        }
    }

    impl BundleRelay for MockRelay {
        fn name(&self) -> &str {
            &self.name
        }

        fn submit(
            &self,
            bundle_bytes: &[u8],
            tip: &JitoTipConfig,
        ) -> Result<BundleReceipt, RelayError> {
            *self.submit_calls.borrow_mut() += 1;
            self.seen_tips.borrow_mut().push(tip.lamports);
            if self.unavailable {
                return Err(RelayError::Unavailable("mock relay down".to_string()));
            }
            if let Some(reason) = &self.reject {
                return Err(RelayError::Rejected(reason.clone()));
            }
            let bundle_id = BundleId::of(bundle_bytes);
            self.statuses
                .borrow_mut()
                .insert(bundle_id, BundleStatus::Pending);
            Ok(BundleReceipt { bundle_id, tip_lamports: tip.lamports })
        }

        fn status(&self, bundle_id: &BundleId) -> Result<BundleStatus, RelayError> {
            if self.unavailable {
                return Err(RelayError::Unavailable("mock relay down".to_string()));
            }
            Ok(self
                .statuses
                .borrow()
                .get(bundle_id)
                .cloned()
                .unwrap_or(BundleStatus::Pending))
        }
    }

    fn tip(lamports: u64) -> JitoTipConfig {
        JitoTipConfig::new(lamports, [0x55; 32]).expect("valid test tip")
    }

    fn submitter() -> BundleRelaySubmitter<MockRelay> {
        BundleRelaySubmitter::new(MockRelay::new("mock-jito"))
    }

    #[test]
    fn bundle_id_is_deterministic_sha256() {
        let a = BundleId::of(b"bundle-bytes");
        let b = BundleId::of(b"bundle-bytes");
        let c = BundleId::of(b"other-bytes");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_bytes(), crate::sha256(b"bundle-bytes"));
        assert_eq!(a.hex().len(), 64);
    }

    #[test]
    fn submit_records_tip_and_receipt() {
        let mut s = submitter();
        let receipt = s.submit_bundle(b"bundle-1", &tip(5_000), 100).unwrap();
        assert_eq!(receipt.bundle_id, BundleId::of(b"bundle-1"));
        assert_eq!(receipt.tip_lamports, 5_000, "the AV-98 tip config rides the submission");
        assert_eq!(s.stats().submitted, 1);
        assert_eq!(s.relay_name(), "mock-jito");
    }

    #[test]
    fn resubmit_pending_bundle_is_idempotent() {
        let relay = MockRelay::new("mock-jito");
        let mut s = BundleRelaySubmitter::new(relay);
        let first = s.submit_bundle(b"bundle-1", &tip(5_000), 100).unwrap();
        let second = s.submit_bundle(b"bundle-1", &tip(5_000), 101).unwrap();
        assert_eq!(first, second, "pending resubmission returns the cached receipt");
        // The relay saw exactly one submission — no duplicate.
        assert_eq!(s.stats().submitted, 1);
    }

    #[test]
    fn resubmit_landed_bundle_is_rejected() {
        let relay = MockRelay::new("mock-jito");
        let mut s = BundleRelaySubmitter::new(relay);
        let receipt = s.submit_bundle(b"bundle-1", &tip(5_000), 100).unwrap();
        s.land_for_test(&receipt.bundle_id, 105);
        let obs = s.observe(&receipt.bundle_id).unwrap().expect("landed observation");
        assert!(obs.landed);
        assert_eq!(
            s.submit_bundle(b"bundle-1", &tip(5_000), 106),
            Err(RelayError::AlreadyLanded(receipt.bundle_id)),
            "a landed bundle is never resubmitted"
        );
    }

    #[test]
    fn relay_unavailable_fails_loud_with_no_mempool_fallback() {
        let mut s = BundleRelaySubmitter::new(MockRelay::down("mock-jito"));
        let err = s.submit_bundle(b"bundle-1", &tip(5_000), 100).unwrap_err();
        assert_eq!(
            err,
            RelayError::Unavailable("mock relay down".to_string()),
            "unavailability surfaces as an explicit error"
        );
        // The failed submission is counted and tracked nowhere — and
        // there is no mempool path to have taken: the adapter has no
        // mempool handle, flag, or fallback branch at all.
        assert_eq!(s.stats().unavailable, 1);
        assert_eq!(s.stats().submitted, 0);
        assert_eq!(s.observe(&BundleId::of(b"bundle-1")).unwrap(), None);
    }

    #[test]
    fn relay_rejection_propagates() {
        let mut relay = MockRelay::new("mock-jito");
        relay.reject = Some("tip too low".to_string());
        let mut s = BundleRelaySubmitter::new(relay);
        assert_eq!(
            s.submit_bundle(b"bundle-1", &tip(5_000), 100).unwrap_err(),
            RelayError::Rejected("tip too low".to_string())
        );
        assert_eq!(s.stats().submitted, 0);
    }

    #[test]
    fn observe_landed_records_confirmation_latency() {
        let relay = MockRelay::new("mock-jito");
        let mut s = BundleRelaySubmitter::new(relay);
        let receipt = s.submit_bundle(b"bundle-1", &tip(5_000), 100).unwrap();
        // Still pending: no observation.
        assert_eq!(s.observe(&receipt.bundle_id).unwrap(), None);
        s.land_for_test(&receipt.bundle_id, 105);
        let obs = s.observe(&receipt.bundle_id).unwrap().expect("observation");
        assert_eq!(
            obs,
            RelayObservation {
                bundle_id: receipt.bundle_id,
                landed: true,
                landed_slot: Some(105),
                confirmation_latency_slots: Some(5),
            }
        );
        assert_eq!(s.stats().landed, 1);
        assert_eq!(s.stats().landing_rate_bps(), 10_000);
        assert_eq!(s.stats().mean_confirmation_latency_slots(), Some(5));
    }

    #[test]
    fn observe_failed_drops_bundle_and_allows_retry() {
        let relay = MockRelay::new("mock-jito");
        let mut s = BundleRelaySubmitter::new(relay);
        let receipt = s.submit_bundle(b"bundle-1", &tip(5_000), 100).unwrap();
        s.fail_for_test(&receipt.bundle_id, "bundle expired");
        let obs = s.observe(&receipt.bundle_id).unwrap().expect("observation");
        assert!(!obs.landed);
        assert_eq!(obs.confirmation_latency_slots, None);
        assert_eq!(s.stats().failed, 1);
        // The failed bundle is gone from tracking: the operator may
        // retry it deliberately, and the retry submits fresh.
        let receipt2 = s.submit_bundle(b"bundle-1", &tip(6_000), 110).unwrap();
        assert_eq!(receipt2.bundle_id, receipt.bundle_id);
        assert_eq!(receipt2.tip_lamports, 6_000);
        assert_eq!(s.stats().submitted, 2);
    }

    #[test]
    fn stats_track_landing_rate_across_bundles() {
        let relay = MockRelay::new("mock-jito");
        let mut s = BundleRelaySubmitter::new(relay);
        let r1 = s.submit_bundle(b"bundle-1", &tip(5_000), 100).unwrap();
        let r2 = s.submit_bundle(b"bundle-2", &tip(5_000), 100).unwrap();
        s.land_for_test(&r1.bundle_id, 108);
        s.fail_for_test(&r2.bundle_id, "stale");
        s.observe(&r1.bundle_id).unwrap();
        s.observe(&r2.bundle_id).unwrap();
        let stats = s.stats();
        assert_eq!(stats.submitted, 2);
        assert_eq!(stats.landed, 1);
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.landing_rate_bps(), 5_000, "1 of 2 landed");
        assert_eq!(stats.mean_confirmation_latency_slots(), Some(8));
        // Empty stats: rate 0, mean None — never a divide-by-zero.
        let empty = RelayStats::default();
        assert_eq!(empty.landing_rate_bps(), 0);
        assert_eq!(empty.mean_confirmation_latency_slots(), None);
    }

    #[test]
    fn observe_unknown_bundle_is_a_quiet_noop() {
        let mut s = submitter();
        assert_eq!(s.observe(&BundleId::of(b"never-submitted")).unwrap(), None);
    }

    #[test]
    fn observation_audit_json_shape() {
        let id = BundleId::of(b"bundle-1");
        let obs = RelayObservation {
            bundle_id: id,
            landed: true,
            landed_slot: Some(105),
            confirmation_latency_slots: Some(5),
        };
        assert_eq!(
            obs.to_json(),
            format!(
                "{{\"bundle_id\":\"{}\",\"landed\":true,\"landed_slot\":105,\
                 \"confirmation_latency_slots\":5}}",
                id.hex()
            )
        );
        let failed = RelayObservation {
            bundle_id: id,
            landed: false,
            landed_slot: None,
            confirmation_latency_slots: None,
        };
        assert!(failed.to_json().contains("\"landed\":false"));
        assert!(failed.to_json().contains("\"landed_slot\":null"));
    }

    #[test]
    fn lifecycle_event_audit_json_shapes() {
        let id = BundleId::of(b"bundle-1");
        let submitted = BundleRelayEvent::Submitted {
            bundle_id: id,
            relay: "mock-jito".to_string(),
            submitted_slot: 100,
            tip_lamports: 5_000,
        };
        let json = submitted.to_json();
        assert!(json.contains("\"event\":\"bundle_relay_submitted\""));
        assert!(json.contains(&id.hex()));
        assert!(json.contains("\"tip_lamports\":5000"));

        let landed = BundleRelayEvent::Landed {
            bundle_id: id,
            relay: "mock-jito".to_string(),
            landed_slot: 105,
            confirmation_latency_slots: 5,
        };
        assert!(landed.to_json().contains("\"event\":\"bundle_relay_landed\""));

        let failed = BundleRelayEvent::Failed {
            bundle_id: id,
            relay: "mock-jito".to_string(),
            reason: "bundle \"expired\"\n".to_string(),
        };
        // String fields are JSON-escaped.
        assert!(failed.to_json().contains("\\\"expired\\\"\\n"));

        let down = BundleRelayEvent::RelayUnavailable {
            relay: "mock-jito".to_string(),
            reason: "connection refused".to_string(),
        };
        assert!(down.to_json().contains("\"event\":\"bundle_relay_unavailable\""));
    }

    // Test-only helpers to drive the mock's scripted statuses through
    // the submitter (the mock itself is owned by the submitter).
    impl BundleRelaySubmitter<MockRelay> {
        fn land_for_test(&self, id: &BundleId, slot: u64) {
            self.relay.land(id, slot);
        }
        fn fail_for_test(&self, id: &BundleId, reason: &str) {
            self.relay.fail(id, reason);
        }
    }
}
