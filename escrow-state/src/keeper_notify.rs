//! AV-118: keeper action push notifications.
//!
//! The keeper scans ([`scan_keeper_actions`](super::keeper::scan_keeper_actions),
//! [`scan_rent_health`](super::keeper::scan_rent_health)) are dry-run by
//! construction — they return reports, they never act. An operator running a
//! keeper bot still wants to *hear* about executable actions the moment a scan
//! finds them: an expired escrow awaiting `cancel_expired`, claimable vesting,
//! a vault slipping under its rent-exempt minimum, an appeal window opening.
//!
//! This module is the push side, and it is deliberately split from the scan
//! path:
//!
//! - [`KeeperNotifier`] is the opt-in pluggable transport trait. The core
//!   defines the trait plus a deterministic in-memory [`RecordingNotifier`]
//!   for tests; the *caller* implements the actual HTTP delivery (POST the
//!   payload, set [`KEEPER_SIGNATURE_HEADER`]). Zero dependencies on the
//!   core side — the same seam as the EB-51 bridge transport and the LG-74
//!   provider: inject `&mut dyn KeeperNotifier`, the state machine never
//!   touches the network. Object-safe by construction (one method, no
//!   generics), like [`PriceFeed`](super::PriceFeed).
//! - [`KeeperNotificationEvent`] is the notification-worthy *subset* of
//!   keeper actions: `cancel_expired`, `claim`, rent top-up (AV-43
//!   rent-health scan), and the appeal windows (`file_appeal` /
//!   `review_appeal` / `expire_appeal`). [`from_action`](KeeperNotificationEvent::from_action)
//!   maps a [`KeeperAction`](super::keeper::KeeperAction) onto the subset
//!   (`None` for uncovered kinds — resolve, slash, panel judgments, …);
//!   [`from_top_up`](KeeperNotificationEvent::from_top_up) maps an
//!   AV-43 [`TopUpAction`](super::keeper::TopUpAction).
//! - Every delivery is authenticated: [`hmac_sha256`] (RFC 2104, hand-rolled
//!   over the crate's SHA-256 — the crate stays dependency-free) signs the
//!   canonical payload bytes, and the signature travels in the
//!   [`KEEPER_SIGNATURE_HEADER`] (`x-keeper-signature`) header, with an
//!   optional key-id annotation for secret rotation. [`verify_delivery`]
//!   is the receiver-side check — forge a byte and it fails.
//! - [`NotifyDispatcher`] owns the queue. The caller scans, hands the
//!   already-built reports to [`push_report`](NotifyDispatcher::push_report)
//!   (a no-op unless the config opted in), then pumps on its own schedule
//!   via [`pump`](NotifyDispatcher::pump). Delivery failure is *bounded*:
//!   each payload is attempted at most [`RetryPolicy::max_attempts`] times
//!   with capped exponential backoff, then dropped and counted. `pump`
//!   never returns `Err` and never panics on notifier failure — a dead
//!   webhook can neither stall nor break the keeper scan loop. The scan
//!   functions themselves are untouched: the notification path can never
//!   block the scan path, because it is a separate call the operator makes
//!   when they choose to.
//! - AV-101/AV-71 combination: [`push_report`](NotifyDispatcher::push_report)
//!   accepts the report's signable bundle (the caller passes e.g.
//!   `report.to_signed_json(&key)`); every payload carries the bundle's
//!   SHA-256 digest as `bundle_ref`, and the delivery carries the full
//!   bundle so the receiver can verify its Ed25519 signature independently.
//!
//! Opt-in by construction: [`NotifyConfig::default`] is disabled, and a
//! disabled dispatcher enqueues nothing — scans behave byte-identically to
//! before AV-118.

use std::collections::VecDeque;

use super::keeper::{KeeperAction, KeeperActionKind, KeeperReport, RentHealthReport, TopUpAction};
use super::sha256;

// ---------------------------------------------------------------------------
// HMAC-SHA256 (RFC 2104), hand-rolled over the crate's SHA-256.
// ---------------------------------------------------------------------------

/// The HTTP header carrying the delivery signature.
pub const KEEPER_SIGNATURE_HEADER: &str = "x-keeper-signature";

/// HMAC-SHA256 (RFC 2104) of `message` under `key`, hand-rolled over the
/// crate's [`sha256`] so the crate stays dependency-free. Keys longer than
/// the 64-byte block are hashed first (RFC 2104 §2); shorter keys are
/// zero-padded.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(BLOCK + message.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// Sign canonical delivery payload bytes → the 32-byte HMAC tag.
pub fn sign_delivery(canonical_payload: &str, key: &[u8]) -> [u8; 32] {
    hmac_sha256(key, canonical_payload.as_bytes())
}

/// Verify a delivery tag against canonical payload bytes. Recomputes the
/// tag and compares in constant time — `false` on any mismatch, including
/// a tampered payload, a flipped tag byte, or a wrong key. Never panics.
pub fn verify_delivery(canonical_payload: &str, signature: &[u8; 32], key: &[u8]) -> bool {
    let expected = sign_delivery(canonical_payload, key);
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= expected[i] ^ signature[i];
    }
    diff == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Minimal JSON string escaping for caller-supplied tokens (the key id).
/// The event/report fields the dispatcher serializes are all hex or
/// numbers and need no escaping.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Render the [`KEEPER_SIGNATURE_HEADER`] value for a delivery:
/// `hmac-sha256=<hex>`, prefixed with `key-id=<id>,` when a key id is
/// configured (so the receiver can pick the right secret during rotation).
pub fn signature_header_value(signature: &[u8; 32], key_id: Option<&str>) -> String {
    match key_id {
        Some(id) => format!("key-id={id},hmac-sha256={}", hex_encode(signature)),
        None => format!("hmac-sha256={}", hex_encode(signature)),
    }
}

/// Parse a [`KEEPER_SIGNATURE_HEADER`] value back into
/// `(signature, key_id)`. Strict: the tag must be `hmac-sha256=` followed
/// by exactly 64 hex chars, and an optional `key-id=<id>,` prefix must be
/// non-empty. Anything else is `None` — never panics.
pub fn parse_signature_header(value: &str) -> Option<([u8; 32], Option<String>)> {
    const TAG_PREFIX: &str = "hmac-sha256=";
    const ID_PREFIX: &str = "key-id=";
    let (id_part, tag_part) = match value.split_once(',') {
        Some((id, tag)) => (Some(id), tag),
        None => (None, value),
    };
    let key_id = match id_part {
        Some(id) => {
            let id = id.strip_prefix(ID_PREFIX)?;
            if id.is_empty() {
                return None;
            }
            Some(id.to_string())
        }
        None => None,
    };
    let hex = tag_part.strip_prefix(TAG_PREFIX)?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut sig = [0u8; 32];
    for i in 0..32 {
        sig[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some((sig, key_id))
}

// ---------------------------------------------------------------------------
// Notification events: the AV-118 subset of keeper actions.
// ---------------------------------------------------------------------------

/// The notification-worthy subset of keeper actions. Everything else a
/// scan can list (resolve, panel judgments, slash, pool payouts, …) is
/// deliberately *not* pushed — those are judgment calls for an operator
/// dashboard, not real-time alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyEventKind {
    /// `cancel_expired` executable — the escrow timed out (AV-20).
    CancelExpired,
    /// `claim` executable — vesting unlocked (AV-20).
    Claim,
    /// Vault balance under the rent-exempt minimum — top-up needed
    /// (AV-43 rent-health scan).
    RentTopUp,
    /// `file_appeal` window open — the taker may appeal the slash (AV-86).
    FileAppeal,
    /// `review_appeal` vote pending — a panel member's ballot awaits (AV-86).
    ReviewAppeal,
    /// `expire_appeal` sweep due — the appeal window lapsed unresolved
    /// (AV-103).
    ExpireAppeal,
}

impl NotifyEventKind {
    /// The wire name: the keeper instruction the event is about
    /// (`rent_top_up` names the AV-43 action, the rest mirror the
    /// instruction names).
    pub fn as_str(&self) -> &'static str {
        match self {
            NotifyEventKind::CancelExpired => "cancel_expired",
            NotifyEventKind::Claim => "claim",
            NotifyEventKind::RentTopUp => "rent_top_up",
            NotifyEventKind::FileAppeal => "file_appeal",
            NotifyEventKind::ReviewAppeal => "review_appeal",
            NotifyEventKind::ExpireAppeal => "expire_appeal",
        }
    }
}

/// One push notification event — the wire shape a keeper operator's
/// webhook consumes. Built from a scan's actions; never built by hand in
/// production (the constructors are the mapping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeeperNotificationEvent {
    /// Which notification-worthy action fired.
    pub kind: NotifyEventKind,
    /// Which escrow the action targets.
    pub escrow_id: [u8; 32],
    /// The key that must sign the keeper call (copied from the action).
    pub caller: [u8; 32],
    /// Which role `caller` plays (`"initializer"`, `"taker"`, …).
    pub caller_role: &'static str,
    /// The action's amount (refundable remainder / claimable gross /
    /// top-up lamports — see the action docs).
    pub amount: u64,
    /// Machine-readable reason (copied from the action).
    pub reason: &'static str,
    /// The escrow's opt-in off-chain reference memo, when the watch
    /// entry carried one.
    pub reference: Option<[u8; 32]>,
}

impl KeeperNotificationEvent {
    /// Map a keeper-report action onto the AV-118 notification subset.
    /// Returns `None` for action kinds AV-118 does not push (resolve,
    /// panel judgments, slash, pool payouts, …) — the scan still lists
    /// them, they just don't trigger a push.
    pub fn from_action(action: &KeeperAction) -> Option<Self> {
        let kind = match action.kind {
            KeeperActionKind::CancelExpired => NotifyEventKind::CancelExpired,
            KeeperActionKind::Claim => NotifyEventKind::Claim,
            KeeperActionKind::FileAppeal => NotifyEventKind::FileAppeal,
            KeeperActionKind::ReviewAppeal => NotifyEventKind::ReviewAppeal,
            KeeperActionKind::ExpireAppeal => NotifyEventKind::ExpireAppeal,
            _ => return None,
        };
        Some(Self {
            kind,
            escrow_id: action.escrow_id,
            caller: action.caller,
            caller_role: action.caller_role,
            amount: action.amount,
            reason: action.reason,
            reference: action.reference,
        })
    }

    /// Map an AV-43 rent-health top-up onto the notification subset.
    /// `amount` is the exact lamports needed to restore rent exemption.
    pub fn from_top_up(top_up: &TopUpAction) -> Self {
        Self {
            kind: NotifyEventKind::RentTopUp,
            escrow_id: top_up.escrow_id,
            caller: top_up.caller,
            caller_role: top_up.caller_role,
            amount: top_up.top_up_lamports,
            reason: top_up.reason,
            reference: None,
        }
    }

    /// Canonical JSON (deterministic field order, hex ids) — the event
    /// half of the delivery payload the HMAC covers.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(240);
        s.push_str("{\"kind\":\"");
        s.push_str(self.kind.as_str());
        s.push_str("\",\"escrow_id\":\"");
        s.push_str(&hex_encode(&self.escrow_id));
        s.push_str("\",\"caller\":\"");
        s.push_str(&hex_encode(&self.caller));
        s.push_str("\",\"caller_role\":\"");
        s.push_str(self.caller_role);
        s.push_str("\",\"amount\":");
        s.push_str(&self.amount.to_string());
        s.push_str(",\"reason\":\"");
        s.push_str(self.reason);
        s.push_str("\",\"reference\":");
        match self.reference {
            Some(r) => {
                s.push('"');
                s.push_str(&hex_encode(&r));
                s.push('"');
            }
            None => s.push_str("null"),
        }
        s.push('}');
        s
    }
}

/// Canonical delivery payload JSON:
/// `{"event":<event_json>,"at":<unix>,"bundle_ref":"<hex>"|null,"key_id":"<id>"|null}`.
/// The HMAC covers exactly these bytes.
fn delivery_payload_json(
    event: &KeeperNotificationEvent,
    at: u64,
    bundle_ref: Option<&str>,
    key_id: Option<&str>,
) -> String {
    let mut s = String::with_capacity(320);
    s.push_str("{\"event\":");
    s.push_str(&event.to_json());
    s.push_str(",\"at\":");
    s.push_str(&at.to_string());
    s.push_str(",\"bundle_ref\":");
    match bundle_ref {
        Some(r) => {
            s.push('"');
            s.push_str(r);
            s.push('"');
        }
        None => s.push_str("null"),
    }
    s.push_str(",\"key_id\":");
    match key_id {
        Some(id) => {
            s.push('"');
            s.push_str(&json_escape(id));
            s.push('"');
        }
        None => s.push_str("null"),
    }
    s.push('}');
    s
}

// ---------------------------------------------------------------------------
// The pluggable transport trait.
// ---------------------------------------------------------------------------

/// Delivery failure. The dispatcher treats [`NotifyError::Transport`] as
/// retryable and [`NotifyError::Rejected`] as drop-immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyError {
    /// Retryable transport failure: connection refused, timeout, 5xx,
    /// DNS — anything where trying again might work.
    Transport,
    /// The receiver refused the payload (auth failure, malformed
    /// payload, 4xx): retrying is pointless, so the dispatcher drops it
    /// immediately and counts it as dropped.
    Rejected,
}

/// Pluggable push transport (AV-118). The dispatcher owns signing, retry,
/// and stats; the caller implements the actual delivery — typically an
/// HTTP POST of [`KeeperDelivery::payload_json`] with
/// [`KEEPER_SIGNATURE_HEADER`] set to
/// [`KeeperDelivery::signature_header`]. Object-safe (`&mut dyn`
/// friendly) like [`PriceFeed`](super::PriceFeed): the core never touches
/// the network, so the crate stays dependency-free.
pub trait KeeperNotifier {
    /// Deliver one signed payload. `Ok` on acceptance (HTTP 2xx or
    /// equivalent); `Err` on failure — the dispatcher retries per
    /// [`RetryPolicy`]. Must not panic.
    fn deliver(&mut self, delivery: &KeeperDelivery) -> Result<(), NotifyError>;
}

/// Deterministic in-memory [`KeeperNotifier`] for tests — records
/// accepted deliveries in order, with a scripted failure count to
/// exercise the dispatcher's retry path. Zero clock or network access.
#[derive(Debug, Default)]
pub struct RecordingNotifier {
    /// Accepted deliveries, in delivery order.
    pub delivered: Vec<KeeperDelivery>,
    /// Total `deliver` calls so far, including failures.
    pub attempts: u64,
    /// Scripted transport failures remaining: each is consumed by one
    /// failed `deliver` call before successes begin.
    pub failures_before_success: u64,
}

impl RecordingNotifier {
    /// A notifier that accepts every delivery.
    pub fn new() -> Self {
        Self::default()
    }

    /// A notifier whose first `n` deliveries fail with
    /// [`NotifyError::Transport`] before successes begin.
    pub fn failing(n: u64) -> Self {
        Self {
            delivered: Vec::new(),
            attempts: 0,
            failures_before_success: n,
        }
    }
}

impl KeeperNotifier for RecordingNotifier {
    fn deliver(&mut self, delivery: &KeeperDelivery) -> Result<(), NotifyError> {
        self.attempts += 1;
        if self.failures_before_success > 0 {
            self.failures_before_success -= 1;
            return Err(NotifyError::Transport);
        }
        self.delivered.push(delivery.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Retry policy, config, stats, dispatcher.
// ---------------------------------------------------------------------------

/// Bounded retry policy for delivery attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts per delivery *including* the first (`1` = no
    /// retry). Clamped to `[1, MAX_ATTEMPTS]`.
    pub max_attempts: u8,
    /// Base backoff in milliseconds; the delay after the n-th failed
    /// attempt (0-based) is `min(base_backoff_ms * 2^n, max_backoff_ms)`.
    pub base_backoff_ms: u64,
    /// Cap for the exponential backoff — the delay never exceeds this.
    pub max_backoff_ms: u64,
}

impl RetryPolicy {
    /// Hard cap on attempts — a delivery never retries forever, so a
    /// dead webhook cannot grow the queue or the wait without bound.
    pub const MAX_ATTEMPTS: u8 = 16;

    /// Build a policy; `max_attempts` is clamped to `[1, MAX_ATTEMPTS]`
    /// and `max_backoff_ms` is raised to `base_backoff_ms` when lower.
    pub fn new(max_attempts: u8, base_backoff_ms: u64, max_backoff_ms: u64) -> Self {
        Self {
            max_attempts: max_attempts.clamp(1, Self::MAX_ATTEMPTS),
            base_backoff_ms,
            max_backoff_ms: max_backoff_ms.max(base_backoff_ms),
        }
    }

    /// Delay in milliseconds before retry `retry_index` (0 = after the
    /// first failure). Saturating exponential, capped at
    /// `max_backoff_ms`.
    pub fn delay_ms(&self, retry_index: u8) -> u64 {
        let mut delay = self.base_backoff_ms;
        for _ in 0..retry_index {
            delay = delay.saturating_mul(2);
            if delay >= self.max_backoff_ms {
                return self.max_backoff_ms;
            }
        }
        delay.min(self.max_backoff_ms)
    }
}

impl Default for RetryPolicy {
    /// 4 attempts total, 500ms base backoff, 8s cap.
    fn default() -> Self {
        Self::new(4, 500, 8_000)
    }
}

/// Dispatcher configuration. Opt-in: [`NotifyConfig::default`] is
/// disabled, and a disabled dispatcher enqueues nothing — scans behave
/// exactly as before AV-118.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyConfig {
    /// Master switch. `false` (default) = no-op: `push_report` enqueues
    /// nothing, `pump` delivers nothing.
    pub enabled: bool,
    /// HMAC secret. Required when enabled — [`NotifyConfig::new`]
    /// rejects an empty secret; an unsigned push would be a forgery
    /// vector.
    pub secret: Vec<u8>,
    /// Optional key-id annotation: rendered into the signature header
    /// (`key-id=<id>,hmac-sha256=…`) and the payload JSON so the
    /// receiver can pick the right secret during rotation.
    pub key_id: Option<String>,
    /// Retry behavior for failed deliveries.
    pub retry: RetryPolicy,
}

/// [`NotifyConfig::new`] rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyConfigError {
    /// Enabled config with an empty HMAC secret — refused, because an
    /// unsigned push is a forgery vector.
    EmptySecret,
}

impl NotifyConfig {
    /// Enabled config signing with `secret`. An empty secret is
    /// [`NotifyConfigError::EmptySecret`].
    pub fn new(secret: Vec<u8>) -> Result<Self, NotifyConfigError> {
        if secret.is_empty() {
            return Err(NotifyConfigError::EmptySecret);
        }
        Ok(Self {
            enabled: true,
            secret,
            key_id: None,
            retry: RetryPolicy::default(),
        })
    }

    /// Builder: annotate the key id (see [`signature_header_value`]).
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Builder: override the retry policy.
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }
}

impl Default for NotifyConfig {
    /// Disabled: the dispatcher is a no-op until the operator opts in
    /// via [`NotifyConfig::new`].
    fn default() -> Self {
        Self {
            enabled: false,
            secret: Vec::new(),
            key_id: None,
            retry: RetryPolicy::default(),
        }
    }
}

/// Delivery counters — the only observable effect of a failed push.
/// Failures never raise and never block the scan path; they land here.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct KeeperNotifyStats {
    /// Payloads built and queued.
    pub enqueued: u64,
    /// Payloads the notifier accepted.
    pub delivered: u64,
    /// Retry attempts beyond each first attempt.
    pub retries: u64,
    /// Payloads dropped: attempts exhausted, or the receiver rejected
    /// the payload ([`NotifyError::Rejected`]).
    pub dropped: u64,
}

/// One signed delivery unit handed to the [`KeeperNotifier`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeeperDelivery {
    /// Canonical payload JSON (see [`delivery_payload_json`]) — the
    /// HMAC covers exactly these bytes. The HTTP layer POSTs this body.
    pub payload_json: String,
    /// HMAC-SHA256 over the payload bytes.
    pub signature: [u8; 32],
    /// The [`KEEPER_SIGNATURE_HEADER`] value for this delivery,
    /// pre-rendered so the HTTP layer sets it verbatim.
    pub signature_header: String,
    /// The optional AV-101/AV-71 signable bundle this payload
    /// references (the caller passes e.g. the report's
    /// `to_signed_json` envelope) — the receiver verifies its Ed25519
    /// signature independently; `bundle_ref` inside the payload binds
    /// it to this delivery.
    pub bundle: Option<String>,
}

/// Builds signed deliveries from keeper reports and pumps them through a
/// [`KeeperNotifier`] with bounded retries.
///
/// The scan path never touches the dispatcher: the caller scans
/// (`scan_keeper_actions` / `scan_rent_health`), hands the already-built
/// reports to [`push_report`](Self::push_report), then pumps on its own
/// schedule ([`pump`](Self::pump)). A failed push is counted in
/// [`stats`](Self::stats) and dropped — `pump` never returns `Err` and
/// never panics on notifier failure, so notification delivery can
/// neither stall nor break the keeper scan loop.
#[derive(Debug)]
pub struct NotifyDispatcher {
    config: NotifyConfig,
    queue: VecDeque<KeeperDelivery>,
    stats: KeeperNotifyStats,
}

impl NotifyDispatcher {
    /// Build a dispatcher from `config`.
    pub fn new(config: NotifyConfig) -> Self {
        Self {
            config,
            queue: VecDeque::new(),
            stats: KeeperNotifyStats::default(),
        }
    }

    /// Build one signed delivery per notification-worthy event in
    /// `report` (the AV-118 subset) plus one per `rent` top-up, and
    /// enqueue them in scan order. No-op when the config is disabled.
    ///
    /// `bundle` is the optional AV-101/AV-71 signable bundle the
    /// payloads reference — the caller passes e.g.
    /// `report.to_signed_json(&signing_key)`; each payload carries the
    /// bundle's SHA-256 digest as `bundle_ref`, and the delivery
    /// carries the full bundle for independent Ed25519 verification.
    /// `None` pushes plain event payloads (`bundle_ref: null`).
    pub fn push_report(
        &mut self,
        report: &KeeperReport,
        rent: Option<&RentHealthReport>,
        bundle: Option<&str>,
    ) {
        if !self.config.enabled {
            return;
        }
        let bundle_ref = bundle.map(|b| hex_encode(&sha256(b.as_bytes())));
        for action in &report.actions {
            if let Some(event) = KeeperNotificationEvent::from_action(action) {
                self.enqueue_event(&event, report.at, bundle, bundle_ref.as_deref());
            }
        }
        if let Some(rent) = rent {
            for top_up in &rent.top_ups {
                let event = KeeperNotificationEvent::from_top_up(top_up);
                self.enqueue_event(&event, rent.at, bundle, bundle_ref.as_deref());
            }
        }
    }

    fn enqueue_event(
        &mut self,
        event: &KeeperNotificationEvent,
        at: u64,
        bundle: Option<&str>,
        bundle_ref: Option<&str>,
    ) {
        let key_id = self.config.key_id.as_deref();
        let payload_json = delivery_payload_json(event, at, bundle_ref, key_id);
        let signature = sign_delivery(&payload_json, &self.config.secret);
        let signature_header = signature_header_value(&signature, key_id);
        self.stats.enqueued += 1;
        self.queue.push_back(KeeperDelivery {
            payload_json,
            signature,
            signature_header,
            bundle: bundle.map(|b| b.to_string()),
        });
    }

    /// Deliver everything queued, honoring the retry policy. Each
    /// delivery is attempted up to `max_attempts` times with capped
    /// exponential backoff between attempts; the caller-supplied
    /// `sleep` performs the wait — the dispatcher never sleeps on its
    /// own, so tests inject a recorder and production passes a closure
    /// over `std::thread::sleep`. A delivery that exhausts its attempts
    /// (or is rejected) is dropped and counted in the stats.
    ///
    /// Never returns `Err`, never panics on notifier failure: failure
    /// is statistics, not control flow — the scan path stays unblocked
    /// by construction, because the scan never calls this.
    ///
    /// No-op while disabled ([`amend_enabled`](Self::amend_enabled)):
    /// the queue is left exactly as it was, so a re-enable drains the
    /// already-signed payloads — disabling never drops or re-signs
    /// anything.
    pub fn pump(&mut self, notifier: &mut dyn KeeperNotifier, sleep: &mut dyn FnMut(u64)) {
        if !self.config.enabled {
            return;
        }
        while let Some(delivery) = self.queue.pop_front() {
            let mut attempt: u8 = 0;
            loop {
                match notifier.deliver(&delivery) {
                    Ok(()) => {
                        self.stats.delivered += 1;
                        break;
                    }
                    Err(NotifyError::Rejected) => {
                        // The receiver refused the payload — retrying
                        // is pointless.
                        self.stats.dropped += 1;
                        break;
                    }
                    Err(NotifyError::Transport) => {
                        attempt += 1;
                        if attempt >= self.config.retry.max_attempts {
                            self.stats.dropped += 1;
                            break;
                        }
                        self.stats.retries += 1;
                        sleep(self.config.retry.delay_ms(attempt - 1));
                    }
                }
            }
        }
    }

    /// Delivery counters (see [`KeeperNotifyStats`]).
    pub fn stats(&self) -> KeeperNotifyStats {
        self.stats
    }

    /// Deliveries waiting for the next [`pump`](Self::pump).
    pub fn pending(&self) -> usize {
        self.queue.len()
    }

    /// Revise the retry policy live (AV-349). The input is normalized
    /// first, with the same rules as [`RetryPolicy::new`]:
    /// `max_attempts` clamps to `[1, 16]`, and `max_backoff_ms` is
    /// raised to `base_backoff_ms` when lower. Amending to the policy
    /// already in force (after normalization) is a no-op returning
    /// `false`: nothing moves and no audit event fires — this module
    /// has no audit ring, so the revision is pinned by tests, as in
    /// AV-316 ([`HeartbeatRegistry::amend_config`](super::keeper_heartbeat::HeartbeatRegistry::amend_config)).
    /// Any other policy replaces `config.retry` wholesale and returns
    /// `true`.
    ///
    /// Only the three retry fields move: `enabled`, `secret`, and
    /// `key_id` are untouched, the queue keeps its already-signed
    /// payloads as-is, and the stats keep accumulating. The new
    /// policy governs the next [`pump`](Self::pump) — every attempt
    /// reads the live config — but there is no revision entry
    /// mid-pump: `pump` takes `&mut self` and runs single-threaded,
    /// so no outside caller can amend while a pump is in flight; a
    /// delivery already popped continues with its popped attempt
    /// count, it is never reset.
    pub fn amend_retry_policy(&mut self, new_retry: RetryPolicy) -> bool {
        let normalized = RetryPolicy::new(
            new_retry.max_attempts,
            new_retry.base_backoff_ms,
            new_retry.max_backoff_ms,
        );
        if self.config.retry == normalized {
            return false;
        }
        self.config.retry = normalized;
        true
    }

    /// The retry policy currently in force.
    pub fn retry_policy(&self) -> RetryPolicy {
        self.config.retry
    }

    /// Revise the master enable switch live (AV-350). Check order
    /// value → secret → same → replace, following
    /// [`HeartbeatRegistry::amend_config`](super::keeper_heartbeat::HeartbeatRegistry::amend_config)
    /// and the AV-349 shape: disabling never fails — shutting off
    /// pushes needs no secret; enabling with an empty secret fails
    /// with [`NotifyConfigError::EmptySecret`] (the same guard as
    /// [`NotifyConfig::new`]: an unsigned push would be a forgery
    /// vector) and leaves the live state exactly as it was;
    /// amending to the value already in force is a no-op returning
    /// `Ok(false)` — nothing moves and no audit event fires; any
    /// other value replaces `config.enabled` only and returns
    /// `Ok(true)`.
    ///
    /// Disabling gates both [`push_report`](Self::push_report)
    /// (which already reads the live switch) and [`pump`](Self::pump)
    /// (which returns immediately while disabled): the signed pending
    /// queue is preserved as-is and keeps delivering after a
    /// re-enable — nothing is dropped, nothing is re-signed. Only
    /// `enabled` moves: `secret`, `key_id`, the retry policy, the
    /// queue, and the stats are untouched, and no audit event fires —
    /// this module has no audit ring, so the revision is pinned by
    /// tests, as in AV-316 and AV-349. The new switch governs the
    /// next `push_report` / `pump` — every call reads the live
    /// config — but there is no revision entry mid-pump: `pump`
    /// takes `&mut self` and runs single-threaded, so no outside
    /// caller can amend while a pump is in flight.
    pub fn amend_enabled(&mut self, enabled: bool) -> Result<bool, NotifyConfigError> {
        if enabled && self.config.secret.is_empty() {
            return Err(NotifyConfigError::EmptySecret);
        }
        if self.config.enabled == enabled {
            return Ok(false);
        }
        self.config.enabled = enabled;
        Ok(true)
    }

    /// Whether pushes are currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

#[cfg(test)]
mod keeper_notify_tests {
    use super::super::ed25519::SigningKey;
    use super::super::report_signing::SignableReport;
    use super::*;

    // -- test fixtures ----------------------------------------------------

    fn action(
        kind: KeeperActionKind,
        id: u8,
        caller_role: &'static str,
        reason: &'static str,
    ) -> KeeperAction {
        KeeperAction {
            escrow_id: [id; 32],
            vault_address: None,
            kind,
            caller: [0x11; 32],
            caller_role,
            mint: None,
            refund_to: Some([0x11; 32]),
            amount: 1_000_000,
            decimals: 6,
            reference: Some([0x22; 32]),
            extension_count: 0,
            multisig_authority: None,
            evidence_disclosure: None,
            funding_progress: None,
            reason,
            merge_source: None,
            penalty_estimate: 0,
            slot_unlock_at: None,
            bounty_lamports: 0,
            bounty_unprofitable: false,
            // AV-135: no arbiter fee on synthetic/test actions.
            arbiter_fee: None,
        }
    }

    fn report_with(actions: Vec<KeeperAction>) -> KeeperReport {
        KeeperReport {
            at: 1_700_000_000,
            scanned: 3,
            actions,
            jito_tip: None,
            pool_balance: 0,
            // AV-123: no intent annotations in tests.
            intent_releases: Vec::new(),
            pool_inflow: 0,
            pool_outflow: 0,
            // AV-120: keeper-notify tests never stamp a sequence.
            report_seq: None,
            pending_auto_unpause: Vec::new(),
            funding_bounds: Vec::new(),
        }
    }

    fn top_up(id: u8) -> TopUpAction {
        TopUpAction {
            escrow_id: [id; 32],
            state: "funded",
            vault_lamports: 100,
            required_lamports: 1_000,
            top_up_lamports: 900,
            caller: [0x33; 32],
            caller_role: "initializer",
            reason: "underfunded",
        }
    }

    fn rent_report_with(top_ups: Vec<TopUpAction>) -> RentHealthReport {
        RentHealthReport {
            at: 1_700_000_001,
            scanned: 2,
            required_lamports: 1_000,
            critical_threshold_pct: 100,
            top_ups,
        }
    }

    fn enabled_config() -> NotifyConfig {
        NotifyConfig::new(b"test-secret-32-bytes-long-key!!".to_vec())
            .unwrap()
            .with_key_id("keeper-01")
    }

    // -- HMAC-SHA256 -------------------------------------------------------

    #[test]
    fn hmac_sha256_matches_rfc4231_vectors() {
        // RFC 4231 test case 1.
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex_encode(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // RFC 4231 test case 2.
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex_encode(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // RFC 4231 test case 6: key longer than the 64-byte block is
        // hashed first.
        let mac = hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex_encode(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn delivery_sign_verify_roundtrip() {
        let key = b"another-secret";
        let payload = "{\"event\":{\"kind\":\"claim\"}}";
        let sig = sign_delivery(payload, key);
        assert!(verify_delivery(payload, &sig, key));
        // Tampered payload fails.
        assert!(!verify_delivery("{\"event\":{\"kind\":\"claim!\"}}", &sig, key));
        // Wrong key fails.
        assert!(!verify_delivery(payload, &sig, b"wrong-secret"));
        // Flipped tag byte fails.
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!verify_delivery(payload, &bad, key));
    }

    // -- signature header ---------------------------------------------------

    #[test]
    fn signature_header_roundtrips_with_and_without_key_id() {
        let sig = sign_delivery("payload", b"k");
        let v = signature_header_value(&sig, Some("keeper-01"));
        assert!(v.starts_with("key-id=keeper-01,hmac-sha256="));
        let (parsed_sig, parsed_id) = parse_signature_header(&v).expect("parses");
        assert_eq!(parsed_sig, sig);
        assert_eq!(parsed_id.as_deref(), Some("keeper-01"));

        let v2 = signature_header_value(&sig, None);
        assert!(v2.starts_with("hmac-sha256="));
        let (parsed_sig2, parsed_id2) = parse_signature_header(&v2).expect("parses");
        assert_eq!(parsed_sig2, sig);
        assert_eq!(parsed_id2, None);
    }

    #[test]
    fn malformed_signature_headers_are_rejected() {
        let sig = sign_delivery("payload", b"k");
        let good = signature_header_value(&sig, None);
        assert!(parse_signature_header("").is_none());
        assert!(parse_signature_header("hmac-sha256=").is_none());
        // Truncated tag.
        assert!(parse_signature_header(&good[..good.len() - 2]).is_none());
        // Non-hex tag.
        assert!(parse_signature_header("hmac-sha256=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
            .is_none());
        // Wrong scheme.
        assert!(parse_signature_header(&good.replacen("hmac-sha256=", "sha256=", 1)).is_none());
        // Empty key id.
        assert!(parse_signature_header(&format!("key-id=,{good}")).is_none());
        // Uppercase hex digits still parse (the hex-digit check is
        // case-insensitive; the scheme prefix stays lowercase).
        let upper_hex = good.replacen("hmac-sha256=", "hmac-sha256=", 1);
        let pos = upper_hex.find("hmac-sha256=").unwrap() + "hmac-sha256=".len();
        let mut upper = upper_hex.clone();
        upper.replace_range(pos.., &upper_hex[pos..].to_uppercase());
        assert!(parse_signature_header(&upper).is_some());
    }

    // -- event mapping ------------------------------------------------------

    #[test]
    fn from_action_maps_the_covered_subset() {
        let cases = [
            (KeeperActionKind::CancelExpired, "cancel_expired", "initializer", "expired"),
            (KeeperActionKind::Claim, "claim", "taker", "vesting_unlocked"),
            (KeeperActionKind::FileAppeal, "file_appeal", "taker", "appeal_window_open"),
            (KeeperActionKind::ReviewAppeal, "review_appeal", "panel_member", "appeal_under_review"),
            (KeeperActionKind::ExpireAppeal, "expire_appeal", "anyone", "appeal_expired"),
        ];
        for (kind, wire, role, reason) in cases {
            let a = action(kind, 0x01, role, reason);
            let e = KeeperNotificationEvent::from_action(&a).expect("covered");
            assert_eq!(e.kind.as_str(), wire);
            assert_eq!(e.escrow_id, [0x01; 32]);
            assert_eq!(e.caller, [0x11; 32]);
            assert_eq!(e.caller_role, role);
            assert_eq!(e.amount, 1_000_000);
            assert_eq!(e.reason, reason);
            assert_eq!(e.reference, Some([0x22; 32]));
        }
    }

    #[test]
    fn from_action_returns_none_for_uncovered_kinds() {
        for kind in [
            KeeperActionKind::CrankExpired,
            KeeperActionKind::Resolve,
            KeeperActionKind::PanelJudgment,
            KeeperActionKind::ReleasePeriod,
            // AV-160: the permissionless subscription crank — a
            // liveness suggestion, not a push-worthy event.
            KeeperActionKind::CrankReleasePeriod,
            KeeperActionKind::Slash,
            KeeperActionKind::PoolPayout,
            KeeperActionKind::ClaimDeadman,
            KeeperActionKind::FundTranche,
            KeeperActionKind::MergeEscrows,
        ] {
            let a = action(kind, 0x02, "initializer", "expired");
            assert!(
                KeeperNotificationEvent::from_action(&a).is_none(),
                "kind {kind:?} must not trigger a push"
            );
        }
    }

    #[test]
    fn from_top_up_maps_rent_event() {
        let e = KeeperNotificationEvent::from_top_up(&top_up(0x05));
        assert_eq!(e.kind, NotifyEventKind::RentTopUp);
        assert_eq!(e.kind.as_str(), "rent_top_up");
        assert_eq!(e.escrow_id, [0x05; 32]);
        assert_eq!(e.caller, [0x33; 32]);
        assert_eq!(e.caller_role, "initializer");
        assert_eq!(e.amount, 900);
        assert_eq!(e.reason, "underfunded");
        assert_eq!(e.reference, None);
    }

    #[test]
    fn event_json_is_canonical() {
        let e = KeeperNotificationEvent::from_action(&action(
            KeeperActionKind::CancelExpired,
            0x01,
            "initializer",
            "expired",
        ))
        .unwrap();
        let mut id = String::new();
        let mut caller = String::new();
        let mut reference = String::new();
        for _ in 0..32 {
            id.push_str("01");
            caller.push_str("11");
            reference.push_str("22");
        }
        assert_eq!(
            e.to_json(),
            format!(
                "{{\"kind\":\"cancel_expired\",\"escrow_id\":\"{id}\",\"caller\":\"{caller}\",\
                 \"caller_role\":\"initializer\",\"amount\":1000000,\"reason\":\"expired\",\
                 \"reference\":\"{reference}\"}}"
            )
        );
    }

    // -- opt-in behavior -----------------------------------------------------

    #[test]
    fn disabled_config_is_a_noop() {
        let mut dispatcher = NotifyDispatcher::new(NotifyConfig::default());
        let report = report_with(vec![action(
            KeeperActionKind::CancelExpired,
            0x01,
            "initializer",
            "expired",
        )]);
        let rent = rent_report_with(vec![top_up(0x02)]);
        dispatcher.push_report(&report, Some(&rent), None);
        assert_eq!(dispatcher.pending(), 0);
        assert_eq!(dispatcher.stats(), KeeperNotifyStats::default());

        let mut notifier = RecordingNotifier::new();
        let mut sleeps = Vec::new();
        dispatcher.pump(&mut notifier, &mut |ms| sleeps.push(ms));
        assert_eq!(notifier.attempts, 0);
        assert!(sleeps.is_empty());
        assert_eq!(dispatcher.stats(), KeeperNotifyStats::default());
    }

    #[test]
    fn config_rejects_empty_secret() {
        assert_eq!(
            NotifyConfig::new(Vec::new()),
            Err(NotifyConfigError::EmptySecret)
        );
        let cfg = NotifyConfig::new(b"s".to_vec()).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.key_id, None);
    }

    // -- dispatcher: signing + queueing -------------------------------------

    #[test]
    fn push_report_enqueues_covered_events_only() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let report = report_with(vec![
            action(KeeperActionKind::CancelExpired, 0x01, "initializer", "expired"),
            action(KeeperActionKind::Resolve, 0x02, "arbiter", "disputed"), // uncovered
            action(KeeperActionKind::Claim, 0x03, "taker", "vesting_unlocked"),
        ]);
        let rent = rent_report_with(vec![top_up(0x04)]);
        let signing_key = SigningKey::from_seed([0x42; 32]);
        let bundle = report.to_signed_json(&signing_key);
        dispatcher.push_report(&report, Some(&rent), Some(&bundle));

        // 2 covered keeper actions + 1 rent top-up; the resolve action
        // stays in the report but triggers no push.
        assert_eq!(dispatcher.pending(), 3);
        let stats = dispatcher.stats();
        assert_eq!(stats.enqueued, 3);
        assert_eq!(stats.delivered, 0);

        let mut notifier = RecordingNotifier::new();
        let mut sleeps = Vec::new();
        dispatcher.pump(&mut notifier, &mut |ms| sleeps.push(ms));
        assert_eq!(notifier.delivered.len(), 3);
        assert!(sleeps.is_empty()); // no failures → no backoff
        assert_eq!(dispatcher.pending(), 0);

        let secret = b"test-secret-32-bytes-long-key!!";
        let expected_bundle_ref = hex_encode(&sha256(bundle.as_bytes()));
        for (i, d) in notifier.delivered.iter().enumerate() {
            // Every payload verifies under the configured secret.
            assert!(verify_delivery(&d.payload_json, &d.signature, secret));
            // The header the HTTP layer sets is the same signature.
            let (hdr_sig, hdr_id) = parse_signature_header(&d.signature_header).expect("parses");
            assert_eq!(hdr_sig, d.signature);
            assert_eq!(hdr_id.as_deref(), Some("keeper-01"));
            // The bundle reference binds the AV-101 envelope; the full
            // bundle rides the delivery for independent verification.
            assert!(d.payload_json.contains(&format!("\"bundle_ref\":\"{expected_bundle_ref}\"")));
            assert!(d.payload_json.contains("\"key_id\":\"keeper-01\""));
            let carried = d.bundle.as_deref().expect("bundle carried");
            assert_eq!(carried, bundle);
            assert!(super::super::report_signing::verify_signed_report_json(carried));
            // Scan order is preserved: cancel_expired, claim, rent_top_up.
            let want_kind = ["cancel_expired", "claim", "rent_top_up"][i];
            assert!(d.payload_json.contains(&format!("\"kind\":\"{want_kind}\"")));
        }
        let stats = dispatcher.stats();
        assert_eq!(stats.delivered, 3);
        assert_eq!(stats.retries, 0);
        assert_eq!(stats.dropped, 0);
    }

    // -- dispatcher: bounded retry ------------------------------------------

    #[test]
    fn retry_is_bounded_and_backs_off_exponentially() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        dispatcher.push_report(&report, None, None);
        assert_eq!(dispatcher.pending(), 1);

        // Two transport failures, then success.
        let mut notifier = RecordingNotifier::failing(2);
        let mut sleeps: Vec<u64> = Vec::new();
        dispatcher.pump(&mut notifier, &mut |ms| sleeps.push(ms));

        assert_eq!(notifier.attempts, 3); // 1 initial + 2 retries
        assert_eq!(notifier.delivered.len(), 1);
        // Default policy: 500ms base → 500, 1000.
        assert_eq!(sleeps, vec![500, 1000]);
        let stats = dispatcher.stats();
        assert_eq!(stats.delivered, 1);
        assert_eq!(stats.retries, 2);
        assert_eq!(stats.dropped, 0);
        assert_eq!(dispatcher.pending(), 0);
    }

    #[test]
    fn exhausted_delivery_is_dropped_and_pump_continues() {
        let config = NotifyConfig::new(b"secret".to_vec())
            .unwrap()
            .with_retry(RetryPolicy::new(3, 100, 1_000));
        let mut dispatcher = NotifyDispatcher::new(config);
        let report = report_with(vec![
            action(KeeperActionKind::CancelExpired, 0x01, "initializer", "expired"),
            action(KeeperActionKind::Claim, 0x02, "taker", "vesting_unlocked"),
        ]);
        dispatcher.push_report(&report, None, None);

        // The transport never recovers.
        let mut notifier = RecordingNotifier::failing(100);
        let mut sleeps: Vec<u64> = Vec::new();
        // pump must not panic, must not return Err (there is no Err to
        // return) — failure is statistics.
        dispatcher.pump(&mut notifier, &mut |ms| sleeps.push(ms));

        // Each delivery attempted exactly max_attempts times, then
        // dropped; the second delivery still got its full attempt
        // budget (failure isolation between queued payloads).
        assert_eq!(notifier.attempts, 6);
        assert!(notifier.delivered.is_empty());
        assert_eq!(sleeps, vec![100, 200, 100, 200]);
        let stats = dispatcher.stats();
        assert_eq!(stats.enqueued, 2);
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.retries, 4);
        assert_eq!(stats.dropped, 2);
        assert_eq!(dispatcher.pending(), 0);
    }

    #[test]
    fn rejected_payload_is_dropped_without_retry() {
        struct RejectAll;
        impl KeeperNotifier for RejectAll {
            fn deliver(&mut self, _d: &KeeperDelivery) -> Result<(), NotifyError> {
                Err(NotifyError::Rejected)
            }
        }
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let report = report_with(vec![action(
            KeeperActionKind::FileAppeal,
            0x01,
            "taker",
            "appeal_window_open",
        )]);
        dispatcher.push_report(&report, None, None);

        let mut notifier = RejectAll;
        let mut sleeps: Vec<u64> = Vec::new();
        dispatcher.pump(&mut notifier, &mut |ms| sleeps.push(ms));

        assert!(sleeps.is_empty()); // no retry on rejection
        let stats = dispatcher.stats();
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.retries, 0);
        assert_eq!(stats.delivered, 0);
    }

    #[test]
    fn backoff_delay_sequence_is_capped() {
        let p = RetryPolicy::new(16, 100, 250);
        assert_eq!(p.delay_ms(0), 100);
        assert_eq!(p.delay_ms(1), 200);
        assert_eq!(p.delay_ms(2), 250); // 400 capped
        assert_eq!(p.delay_ms(10), 250);
        // Attempts clamp to [1, MAX_ATTEMPTS].
        assert_eq!(RetryPolicy::new(0, 100, 1_000).max_attempts, 1);
        assert_eq!(
            RetryPolicy::new(99, 100, 1_000).max_attempts,
            RetryPolicy::MAX_ATTEMPTS
        );
        // max_backoff below base is raised to base.
        assert_eq!(RetryPolicy::new(4, 500, 100).max_backoff_ms, 500);
    }

    // -- scan path independence ----------------------------------------------

    #[test]
    fn scan_path_is_untouched_by_the_dispatcher() {
        // The dispatcher never sees the scan inputs — it only consumes
        // already-built reports. A report built before any dispatcher
        // exists serializes identically after pushes and pumps.
        let watched: Vec<super::super::keeper::WatchedEscrow> = Vec::new();
        let report = super::super::keeper::scan_keeper_actions(&watched, 1_000);
        let before = report.to_json();
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        dispatcher.push_report(&report, None, None);
        let mut notifier = RecordingNotifier::new();
        dispatcher.pump(&mut notifier, &mut |_| {});
        assert_eq!(report.to_json(), before);
        assert_eq!(dispatcher.stats().enqueued, 0); // empty report → no events
    }

    // -- live retry-policy revision (AV-349) --------------------------------

    #[test]
    fn amend_retry_policy_normalizes_input() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        // Default policy is 4 attempts / 500ms / 8s.
        assert_eq!(dispatcher.retry_policy(), RetryPolicy::default());

        // max_attempts 0 clamps to 1.
        assert!(dispatcher.amend_retry_policy(RetryPolicy::new(0, 500, 8_000)));
        assert_eq!(dispatcher.retry_policy().max_attempts, 1);
        // max_attempts 99 clamps to MAX_ATTEMPTS.
        assert!(dispatcher.amend_retry_policy(RetryPolicy::new(99, 100, 1_000)));
        assert_eq!(dispatcher.retry_policy().max_attempts, RetryPolicy::MAX_ATTEMPTS);
        // max_backoff_ms below base is raised to base.
        assert!(dispatcher.amend_retry_policy(RetryPolicy::new(4, 500, 100)));
        assert_eq!(dispatcher.retry_policy().max_backoff_ms, 500);
        assert_eq!(dispatcher.retry_policy().base_backoff_ms, 500);
    }

    #[test]
    fn amend_retry_policy_same_value_is_a_noop() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        // Amending to the policy already in force is a no-op.
        assert!(!dispatcher.amend_retry_policy(RetryPolicy::default()));
        assert_eq!(dispatcher.retry_policy(), RetryPolicy::default());
        // Normalization counts: 0 attempts normalizes to 1, which is
        // the live value once the dispatcher was set to 1 — so the
        // normalized-equal amend is a no-op too.
        assert!(dispatcher.amend_retry_policy(RetryPolicy::new(1, 500, 8_000)));
        assert!(!dispatcher.amend_retry_policy(RetryPolicy::new(0, 500, 8_000)));
        assert_eq!(dispatcher.retry_policy().max_attempts, 1);
    }

    #[test]
    fn amend_retry_policy_replaces_policy_and_getter_reads_it() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let widened = RetryPolicy::new(8, 250, 4_000);
        assert!(dispatcher.amend_retry_policy(widened));
        assert_eq!(dispatcher.retry_policy(), widened);
        // enabled/secret/key_id are untouched by the revision — a
        // fresh push still signs under the same key id.
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        dispatcher.push_report(&report, None, None);
        let mut notifier = RecordingNotifier::new();
        dispatcher.pump(&mut notifier, &mut |_| {});
        assert_eq!(notifier.delivered.len(), 1);
        assert!(notifier.delivered[0]
            .signature_header
            .starts_with("key-id=keeper-01,"));
    }

    #[test]
    fn amend_retry_policy_keeps_queue_and_signatures() {
        // Two dispatchers, same config, same report: the amended one
        // must deliver byte-identical payloads to the untouched one.
        let report = report_with(vec![
            action(KeeperActionKind::CancelExpired, 0x01, "initializer", "expired"),
            action(KeeperActionKind::Claim, 0x02, "taker", "vesting_unlocked"),
        ]);
        let mut amended = NotifyDispatcher::new(enabled_config());
        let mut control = NotifyDispatcher::new(enabled_config());
        amended.push_report(&report, None, None);
        control.push_report(&report, None, None);
        assert_eq!(amended.pending(), 2);

        assert!(amended.amend_retry_policy(RetryPolicy::new(8, 250, 4_000)));
        assert_eq!(amended.pending(), 2); // queue untouched

        let mut amended_notifier = RecordingNotifier::new();
        let mut control_notifier = RecordingNotifier::new();
        amended.pump(&mut amended_notifier, &mut |_| {});
        control.pump(&mut control_notifier, &mut |_| {});
        assert_eq!(amended_notifier.delivered, control_notifier.delivered);
    }

    #[test]
    fn amend_retry_policy_keeps_stats() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        dispatcher.push_report(&report, None, None);
        let mut notifier = RecordingNotifier::failing(1);
        dispatcher.pump(&mut notifier, &mut |_| {});
        let before = dispatcher.stats();
        assert_eq!(before.enqueued, 1);
        assert_eq!(before.delivered, 1);
        assert_eq!(before.retries, 1);
        assert_eq!(before.dropped, 0);

        assert!(dispatcher.amend_retry_policy(RetryPolicy::new(8, 250, 4_000)));
        assert_eq!(dispatcher.stats(), before); // stats untouched

        // Counters keep accumulating across the revision.
        dispatcher.push_report(&report, None, None);
        let mut notifier = RecordingNotifier::new();
        dispatcher.pump(&mut notifier, &mut |_| {});
        let after = dispatcher.stats();
        assert_eq!(after.enqueued, 2);
        assert_eq!(after.delivered, 2);
        assert_eq!(after.retries, 1);
        assert_eq!(after.dropped, 0);
    }

    #[test]
    fn pump_drops_earlier_under_tightened_max_attempts() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        dispatcher.push_report(&report, None, None);
        // Tighten from the default 4 attempts to 2.
        assert!(dispatcher.amend_retry_policy(RetryPolicy::new(2, 500, 8_000)));

        let mut notifier = RecordingNotifier::failing(100);
        let mut sleeps: Vec<u64> = Vec::new();
        dispatcher.pump(&mut notifier, &mut |ms| sleeps.push(ms));

        assert_eq!(notifier.attempts, 2); // 1 initial + 1 retry
        assert!(notifier.delivered.is_empty());
        assert_eq!(sleeps, vec![500]);
        let stats = dispatcher.stats();
        assert_eq!(stats.retries, 1);
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn pump_drops_later_under_widened_max_attempts() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        dispatcher.push_report(&report, None, None);
        // Widen from the default 4 attempts to 8.
        assert!(dispatcher.amend_retry_policy(RetryPolicy::new(8, 500, 8_000)));

        // Five transport failures, then success: under the old policy
        // this delivery would have been dropped after 4 attempts.
        let mut notifier = RecordingNotifier::failing(5);
        let mut sleeps: Vec<u64> = Vec::new();
        dispatcher.pump(&mut notifier, &mut |ms| sleeps.push(ms));

        assert_eq!(notifier.attempts, 6);
        assert_eq!(notifier.delivered.len(), 1);
        assert_eq!(sleeps, vec![500, 1_000, 2_000, 4_000, 8_000]);
        let stats = dispatcher.stats();
        assert_eq!(stats.delivered, 1);
        assert_eq!(stats.retries, 5);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn pump_sleeps_per_new_delay_sequence() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        dispatcher.push_report(&report, None, None);
        // New base/cap: 100ms base, 250ms cap — 100, 200, 250, 250.
        assert!(dispatcher.amend_retry_policy(RetryPolicy::new(16, 100, 250)));

        let mut notifier = RecordingNotifier::failing(4);
        let mut sleeps: Vec<u64> = Vec::new();
        dispatcher.pump(&mut notifier, &mut |ms| sleeps.push(ms));

        assert_eq!(notifier.attempts, 5);
        assert_eq!(notifier.delivered.len(), 1);
        assert_eq!(sleeps, vec![100, 200, 250, 250]);
    }

    #[test]
    fn amend_retry_policy_on_disabled_dispatcher() {
        let mut dispatcher = NotifyDispatcher::new(NotifyConfig::default());
        // The revision still writes and is getter-visible on a
        // disabled dispatcher…
        assert!(dispatcher.amend_retry_policy(RetryPolicy::new(8, 250, 4_000)));
        assert_eq!(dispatcher.retry_policy(), RetryPolicy::new(8, 250, 4_000));
        // …but the push/pump gating is unchanged: disabled still
        // enqueues nothing.
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        dispatcher.push_report(&report, None, None);
        assert_eq!(dispatcher.pending(), 0);
        assert_eq!(dispatcher.stats(), KeeperNotifyStats::default());
        let mut notifier = RecordingNotifier::new();
        dispatcher.pump(&mut notifier, &mut |_| {});
        assert_eq!(notifier.attempts, 0);
    }

    #[test]
    fn repeated_revisions_back_and_forth_take_effect() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let wide = RetryPolicy::new(8, 250, 4_000);
        let tight = RetryPolicy::new(2, 100, 200);
        assert!(dispatcher.amend_retry_policy(wide));
        assert_eq!(dispatcher.retry_policy(), wide);
        assert!(dispatcher.amend_retry_policy(tight));
        assert_eq!(dispatcher.retry_policy(), tight);
        assert!(dispatcher.amend_retry_policy(wide));
        assert_eq!(dispatcher.retry_policy(), wide);
        // And back to the default is a real revision too.
        assert!(dispatcher.amend_retry_policy(RetryPolicy::default()));
        assert_eq!(dispatcher.retry_policy(), RetryPolicy::default());
        // Repeating the live value is a no-op.
        assert!(!dispatcher.amend_retry_policy(RetryPolicy::default()));
    }

    // -- live enable/disable revision (AV-350) ----------------------------

    #[test]
    fn amend_enabled_disable_stops_push_report() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        dispatcher.push_report(&report, None, None);
        assert_eq!(dispatcher.pending(), 1);
        assert_eq!(dispatcher.stats().enqueued, 1);

        assert_eq!(dispatcher.amend_enabled(false), Ok(true));
        assert!(!dispatcher.is_enabled());
        dispatcher.push_report(&report, None, None);
        assert_eq!(dispatcher.pending(), 1); // nothing new enqueued
        assert_eq!(dispatcher.stats().enqueued, 1);
    }

    #[test]
    fn amend_enabled_disable_when_already_disabled_is_a_noop() {
        let mut dispatcher = NotifyDispatcher::new(NotifyConfig::default());
        assert!(!dispatcher.is_enabled());
        // Disabling needs no secret: even the empty-secret default
        // config disables without failing.
        assert_eq!(dispatcher.amend_enabled(false), Ok(false));
        assert!(!dispatcher.is_enabled());
    }

    #[test]
    fn amend_enabled_re_enable_with_secret_resumes_push() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        assert!(dispatcher.is_enabled());
        assert_eq!(dispatcher.amend_enabled(false), Ok(true));
        assert!(!dispatcher.is_enabled());

        assert_eq!(dispatcher.amend_enabled(true), Ok(true));
        assert!(dispatcher.is_enabled());
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        dispatcher.push_report(&report, None, None);
        assert_eq!(dispatcher.pending(), 1);
        assert_eq!(dispatcher.stats().enqueued, 1);
    }

    #[test]
    fn amend_enabled_enable_when_already_enabled_is_a_noop() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        assert_eq!(dispatcher.amend_enabled(true), Ok(false));
        assert!(dispatcher.is_enabled());
        // Still live: pushes keep flowing.
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        dispatcher.push_report(&report, None, None);
        assert_eq!(dispatcher.pending(), 1);
    }

    #[test]
    fn amend_enabled_on_default_dispatcher_rejects_empty_secret() {
        let mut dispatcher = NotifyDispatcher::new(NotifyConfig::default());
        assert_eq!(
            dispatcher.amend_enabled(true),
            Err(NotifyConfigError::EmptySecret)
        );
        // Live state untouched: still disabled, still no queue.
        assert!(!dispatcher.is_enabled());
        assert_eq!(dispatcher.pending(), 0);
        assert_eq!(dispatcher.stats(), KeeperNotifyStats::default());
        // And the failed enable leaves nothing half-written: a later
        // disable is still the no-op it was before.
        assert_eq!(dispatcher.amend_enabled(false), Ok(false));
    }

    #[test]
    fn disabled_pump_preserves_queue_and_drains_after_re_enable() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let report = report_with(vec![
            action(KeeperActionKind::CancelExpired, 0x01, "initializer", "expired"),
            action(KeeperActionKind::Claim, 0x02, "taker", "vesting_unlocked"),
        ]);
        dispatcher.push_report(&report, None, None);
        assert_eq!(dispatcher.pending(), 2);

        assert_eq!(dispatcher.amend_enabled(false), Ok(true));
        let mut notifier = RecordingNotifier::new();
        let mut sleeps = Vec::new();
        dispatcher.pump(&mut notifier, &mut |ms| sleeps.push(ms));
        assert_eq!(notifier.attempts, 0);
        assert!(notifier.delivered.is_empty());
        assert!(sleeps.is_empty());
        assert_eq!(dispatcher.pending(), 2); // queue preserved as-is
        assert_eq!(dispatcher.stats().delivered, 0);

        assert_eq!(dispatcher.amend_enabled(true), Ok(true));
        dispatcher.pump(&mut notifier, &mut |_| {});
        assert_eq!(dispatcher.pending(), 0);
        assert_eq!(notifier.delivered.len(), 2);
        assert_eq!(dispatcher.stats().delivered, 2);
    }

    #[test]
    fn amend_enabled_keeps_stats() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        dispatcher.push_report(&report, None, None);
        let mut notifier = RecordingNotifier::failing(1);
        dispatcher.pump(&mut notifier, &mut |_| {});
        let before = dispatcher.stats();
        assert_eq!(before.enqueued, 1);
        assert_eq!(before.delivered, 1);
        assert_eq!(before.retries, 1);
        assert_eq!(before.dropped, 0);

        assert_eq!(dispatcher.amend_enabled(false), Ok(true));
        assert_eq!(dispatcher.stats(), before); // stats untouched
        assert_eq!(dispatcher.amend_enabled(true), Ok(true));
        assert_eq!(dispatcher.stats(), before);

        // Counters keep accumulating across the toggle.
        dispatcher.push_report(&report, None, None);
        let mut notifier = RecordingNotifier::new();
        dispatcher.pump(&mut notifier, &mut |_| {});
        let after = dispatcher.stats();
        assert_eq!(after.enqueued, 2);
        assert_eq!(after.delivered, 2);
        assert_eq!(after.retries, 1);
        assert_eq!(after.dropped, 0);
    }

    #[test]
    fn amend_enabled_keeps_retry_policy_and_signatures() {
        // Two dispatchers, same config, same report: the toggled one
        // must deliver byte-identical payloads to the untouched one —
        // disabling neither re-signs nor drops queued deliveries.
        let report = report_with(vec![
            action(KeeperActionKind::CancelExpired, 0x01, "initializer", "expired"),
            action(KeeperActionKind::Claim, 0x02, "taker", "vesting_unlocked"),
        ]);
        let mut toggled = NotifyDispatcher::new(enabled_config());
        let mut control = NotifyDispatcher::new(enabled_config());
        toggled.push_report(&report, None, None);
        control.push_report(&report, None, None);
        assert_eq!(toggled.pending(), 2);

        assert_eq!(toggled.amend_enabled(false), Ok(true));
        assert_eq!(toggled.pending(), 2); // queue untouched
        assert_eq!(toggled.retry_policy(), control.retry_policy());
        assert_eq!(toggled.amend_enabled(true), Ok(true));
        assert_eq!(toggled.retry_policy(), RetryPolicy::default());

        let mut toggled_notifier = RecordingNotifier::new();
        let mut control_notifier = RecordingNotifier::new();
        toggled.pump(&mut toggled_notifier, &mut |_| {});
        control.pump(&mut control_notifier, &mut |_| {});
        assert_eq!(toggled_notifier.delivered, control_notifier.delivered);
        // The signature headers match the pre-toggle signing exactly.
        assert!(toggled_notifier.delivered[0]
            .signature_header
            .starts_with("key-id=keeper-01,hmac-sha256="));
    }

    #[test]
    fn repeated_enable_disable_toggles_take_effect() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        assert_eq!(dispatcher.amend_enabled(false), Ok(true));
        assert!(!dispatcher.is_enabled());
        dispatcher.push_report(&report, None, None);
        assert_eq!(dispatcher.pending(), 0);
        assert_eq!(dispatcher.amend_enabled(true), Ok(true));
        assert!(dispatcher.is_enabled());
        dispatcher.push_report(&report, None, None);
        assert_eq!(dispatcher.pending(), 1);
        assert_eq!(dispatcher.amend_enabled(false), Ok(true));
        assert!(!dispatcher.is_enabled());
        dispatcher.push_report(&report, None, None);
        assert_eq!(dispatcher.pending(), 1);
        assert_eq!(dispatcher.amend_enabled(true), Ok(true));
        assert!(dispatcher.is_enabled());
        // Repeating the live value is a no-op either way.
        assert_eq!(dispatcher.amend_enabled(true), Ok(false));
        assert_eq!(dispatcher.amend_enabled(false), Ok(true));
        assert_eq!(dispatcher.amend_enabled(false), Ok(false));
    }

    #[test]
    fn pump_while_disabled_never_sleeps_or_retries() {
        let mut dispatcher = NotifyDispatcher::new(enabled_config());
        let report = report_with(vec![action(
            KeeperActionKind::Claim,
            0x01,
            "taker",
            "vesting_unlocked",
        )]);
        dispatcher.push_report(&report, None, None);
        assert_eq!(dispatcher.amend_enabled(false), Ok(true));

        // Even a notifier that would fail on every attempt is never
        // called while disabled — no attempts, no backoff sleeps.
        let mut notifier = RecordingNotifier::failing(100);
        let mut sleeps = Vec::new();
        dispatcher.pump(&mut notifier, &mut |ms| sleeps.push(ms));
        assert_eq!(notifier.attempts, 0);
        assert!(sleeps.is_empty());
        assert_eq!(dispatcher.pending(), 1);
        assert_eq!(dispatcher.stats().delivered, 0);
        assert_eq!(dispatcher.stats().retries, 0);
        assert_eq!(dispatcher.stats().dropped, 0);
    }
}
