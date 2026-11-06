//! AV-211: delivery inspection period — the taker's post-confirmation
//! inspection window, with automatic release on quiet expiry.
//!
//! AV-203 (`Escrow::confirm_delivery`) lets the taker confirm receipt,
//! and once confirmed the payout paths open immediately: a taker who
//! confirms, then discovers the delivery is defective, has no
//! on-escrow way to hold the release — the only recourse is a dispute
//! escalated under AV-14, which is anchored to the escrow's *expiry*,
//! not to the delivery, and either party may trigger it. This sidecar
//! closes that gap with a pure inspection-window decision machine
//! anchored to the delivery confirmation itself:
//!
//! - The window opens at the confirmation moment (`confirmed_at`,
//!   seconds) and runs `inspection_secs` seconds. A zero window could
//!   never be inspected, so it is refused at construction.
//! - Inside the window the taker — and only the taker — may
//!   [`InspectionPeriod::dispute`] to freeze the release. A stranger's
//!   dispute is refused before any window check, so a prober learns
//!   nothing about the window from a refused call.
//! - At or after the deadline, [`InspectionPeriod::settle`] releases
//!   automatically: no second `release` call is needed, and no party
//!   can stall a quiet deal by simply never calling again. Settling
//!   early is refused ([`EscrowError::InspectionNotDue`]) — the
//!   window is the taker's, and it runs its full course.
//! - A disputed window never auto-releases: `settle` on a disputed
//!   window fails closed, and the freeze stands until an arbiter
//!   resolves it (AV-14's `resolve` — this module never invents an
//!   un-dispute path, because a taker who disputed and then went
//!   quiet must not silently unfreeze the funds by inaction).
//! - A dispute at or after the deadline is refused
//!   ([`EscrowError::InspectionWindowExpired`]): the window is over,
//!   so the caller must `settle` instead of disputing a closed
//!   window. A second `settle` after release is likewise refused —
//!   the release decision is made exactly once, never double-counted.
//!
//! The boundary convention is the AV-206 deadline rule: the deadline
//! second itself belongs to the *next* phase, so a dispute exactly at
//! `expires_at` is already late, and a settle exactly at `expires_at`
//! already releases.
//!
//! Orthogonal to AV-112 (the release-intent cooling period: an
//! announced intent, either party may veto, plain `release` only, and
//! never an automatic release — this window is anchored to the
//! delivery confirmation, taker-only, and *does* auto-release on quiet
//! expiry), to AV-14 (the dispute window anchored to escrow expiry,
//! escalatable by either party — this window is anchored to delivery
//! confirmation and disputable by the taker only), and to AV-210
//! (a third-party verifier's attestation gating a milestone release —
//! this window gates on the taker's own silence, no signature needed).
//!
//! Funds never move here. `settle` returns the release *decision*; the
//! actual payout stays the Anchor program's job, exactly like
//! AV-209's winner-payment window deciding who may pay without moving
//! any deposit itself. Pure logic: no Vault layout change, no
//! `VAULT_SPACE` bump.

use crate::EscrowError;

fn hex64(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes.iter() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Lifecycle of a delivery inspection period.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InspectionState {
    /// The taker is inside the inspection window; the release is held.
    #[default]
    Inspecting,
    /// The taker disputed inside the window; the release is frozen
    /// until an arbiter resolves it (AV-14) — never auto-released.
    Disputed,
    /// The window expired quietly; the release decision is made.
    AutoReleased,
}

/// Receipt for a quiet-expiry automatic release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectionRelease {
    /// The second the automatic release decision was made.
    pub released_at: u64,
}

/// The delivery inspection window for one escrow's taker.
///
/// Constructed from the delivery-confirmation moment (the
/// `confirmed_at` the Anchor program records when
/// `Escrow::confirm_delivery` runs), not from the escrow's expiry:
/// the window measures inspection time, not escrow lifetime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectionPeriod {
    taker: [u8; 32],
    confirmed_at: u64,
    inspection_secs: u64,
    expires_at: u64,
    state: InspectionState,
    disputed_at: Option<u64>,
    released_at: Option<u64>,
}

impl InspectionPeriod {
    /// Open an inspection window for `taker`, confirmed at
    /// `confirmed_at` seconds, lasting `inspection_secs` seconds.
    /// A zero taker key, a zero window, or an overflowing deadline
    /// (`confirmed_at + inspection_secs` past `u64::MAX`) is refused
    /// — a window that could never be inspected, or whose deadline
    /// cannot be represented, must not be constructed.
    pub fn new(
        taker: [u8; 32],
        confirmed_at: u64,
        inspection_secs: u64,
    ) -> Result<Self, EscrowError> {
        if taker == [0u8; 32] {
            return Err(EscrowError::InspectionInvalidWindow);
        }
        if inspection_secs == 0 {
            return Err(EscrowError::InspectionInvalidWindow);
        }
        let expires_at = confirmed_at
            .checked_add(inspection_secs)
            .ok_or(EscrowError::InspectionInvalidWindow)?;
        Ok(Self {
            taker,
            confirmed_at,
            inspection_secs,
            expires_at,
            state: InspectionState::Inspecting,
            disputed_at: None,
            released_at: None,
        })
    }

    /// The taker under inspection.
    pub fn taker(&self) -> [u8; 32] {
        self.taker
    }

    /// The delivery-confirmation second the window opened at.
    pub fn confirmed_at(&self) -> u64 {
        self.confirmed_at
    }

    /// The configured inspection length, in seconds.
    pub fn inspection_secs(&self) -> u64 {
        self.inspection_secs
    }

    /// The second the window closes; a dispute at or after this
    /// second is late, a settle at or after it releases.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// The window's lifecycle state.
    pub fn state(&self) -> InspectionState {
        self.state
    }

    /// The second the taker disputed, if the window is disputed.
    pub fn disputed_at(&self) -> Option<u64> {
        self.disputed_at
    }

    /// The second the window auto-released, if it did.
    pub fn released_at(&self) -> Option<u64> {
        self.released_at
    }

    /// Whether the window is inspecting and `now` is at or past the
    /// deadline — the pure query a keeper polls to decide whether to
    /// call `settle`. It never mutates: a disputed or already
    /// released window is never "releasable" through this window.
    pub fn is_releasable(&self, now: u64) -> bool {
        self.state == InspectionState::Inspecting && now >= self.expires_at
    }

    /// The taker disputes inside the window, freezing the release.
    ///
    /// Check order: state → identity → window. A dispute on a
    /// terminal window (disputed or auto-released) is refused before
    /// identity is considered; a stranger is refused before the
    /// window is considered; a dispute at or after the deadline is
    /// refused because the window is already over — the caller must
    /// `settle` instead. A successful dispute is terminal for this
    /// window: there is no un-dispute, so a disputed window can
    /// never drift back into `Inspecting`.
    pub fn dispute(&mut self, caller: [u8; 32], now: u64) -> Result<(), EscrowError> {
        if self.state != InspectionState::Inspecting {
            return Err(EscrowError::InvalidStateTransition);
        }
        if caller != self.taker {
            return Err(EscrowError::InspectionNotTaker);
        }
        if now >= self.expires_at {
            return Err(EscrowError::InspectionWindowExpired);
        }
        self.state = InspectionState::Disputed;
        self.disputed_at = Some(now);
        Ok(())
    }

    /// Settle the window: at or after the deadline, with no dispute
    /// recorded, the release decision is made automatically — no
    /// second `release` call is needed, and no party can stall a
    /// quiet deal by never calling again.
    ///
    /// Settling early is refused ([`EscrowError::InspectionNotDue`]);
    /// settling a disputed window is refused (the freeze stands until
    /// an arbiter resolves it); settling an already released window
    /// is refused (the decision is made exactly once).
    pub fn settle(&mut self, now: u64) -> Result<InspectionRelease, EscrowError> {
        if self.state != InspectionState::Inspecting {
            return Err(EscrowError::InvalidStateTransition);
        }
        if now < self.expires_at {
            return Err(EscrowError::InspectionNotDue);
        }
        self.state = InspectionState::AutoReleased;
        self.released_at = Some(now);
        Ok(InspectionRelease { released_at: now })
    }

    /// Revise the inspection window's length live (AV-359): the
    /// window is no longer frozen at its construction-time
    /// `inspection_secs`.
    ///
    /// Check order: state → value → deadline → same. A terminal
    /// window (disputed or auto-released) is refused — a finished
    /// window must not be revived by amending it, and the only
    /// other path to a new window is discarding and rebuilding
    /// with [`InspectionPeriod::new`], which loses the terminal
    /// state. A zero window, or one whose deadline
    /// (`confirmed_at + new_inspection_secs`) overflows, is refused
    /// ([`EscrowError::InspectionInvalidWindow`]), reusing the
    /// same gates as `new`. The new deadline must be strictly
    /// later than `now`, otherwise the amendment would silently
    /// extinguish the taker's dispute right
    /// ([`EscrowError::InspectionWindowExpired`]) — the deadline
    /// second belongs to the next phase (AV-206), so a new
    /// deadline equal to `now` is already expired, and the call
    /// fails closed. Amending to the current value is a silent
    /// no-op (`Ok(false)`).
    ///
    /// Otherwise only `inspection_secs` and `expires_at` move
    /// (`expires_at = confirmed_at + new_inspection_secs`);
    /// `taker`, `confirmed_at`, `state`, `disputed_at` and
    /// `released_at` are untouched. The new window governs from
    /// the next evaluation: [`InspectionPeriod::is_releasable`],
    /// [`InspectionPeriod::dispute`] and
    /// [`InspectionPeriod::settle`] all read `expires_at` live,
    /// so an extension revives a nearly-expired window's dispute
    /// right and a shortening lets the window settle earlier.
    pub fn amend_inspection_secs(
        &mut self,
        new_inspection_secs: u64,
        now: u64,
    ) -> Result<bool, EscrowError> {
        if self.state != InspectionState::Inspecting {
            return Err(EscrowError::InvalidStateTransition);
        }
        if new_inspection_secs == 0 {
            return Err(EscrowError::InspectionInvalidWindow);
        }
        let new_expires_at = self
            .confirmed_at
            .checked_add(new_inspection_secs)
            .ok_or(EscrowError::InspectionInvalidWindow)?;
        if new_expires_at <= now {
            return Err(EscrowError::InspectionWindowExpired);
        }
        if new_inspection_secs == self.inspection_secs {
            return Ok(false);
        }
        self.inspection_secs = new_inspection_secs;
        self.expires_at = new_expires_at;
        Ok(true)
    }

    /// Audit-event JSON for a live window revision (hand-written):
    /// `{"event":"inspection_window_amended","taker":"<64hex>",
    /// "previous_inspection_secs":<u64>,"inspection_secs":<u64>,
    /// "previous_expires_at":<u64>,"expires_at":<u64>}`.
    /// `previous_inspection_secs` is the window length this call
    /// replaced; the new values are read off `self`, and
    /// `previous_expires_at` is `confirmed_at` plus the previous
    /// length — the anchor the revision preserves, so the event
    /// pins both the new window and where it started counting
    /// from. Only call on a real revision: a no-op amendment
    /// emits no event.
    pub fn inspection_window_audit_json(&self, previous_inspection_secs: u64) -> String {
        let mut s = String::from("{\"event\":\"inspection_window_amended\",\"taker\":\"");
        s.push_str(&hex64(&self.taker));
        s.push_str("\",\"previous_inspection_secs\":");
        s.push_str(&previous_inspection_secs.to_string());
        s.push_str(",\"inspection_secs\":");
        s.push_str(&self.inspection_secs.to_string());
        s.push_str(",\"previous_expires_at\":");
        s.push_str(
            &self
                .confirmed_at
                .saturating_add(previous_inspection_secs)
                .to_string(),
        );
        s.push_str(",\"expires_at\":");
        s.push_str(&self.expires_at.to_string());
        s.push('}');
        s
    }

    /// Audit-event JSON for a taker dispute (hand-written):
    /// `{"event":"inspection_disputed","taker":"<64hex>","at":<u64>}`.
    pub fn disputed_audit_json(&self) -> String {
        let mut s = String::from("{\"event\":\"inspection_disputed\",\"taker\":\"");
        s.push_str(&hex64(&self.taker));
        s.push_str("\",\"at\":");
        match self.disputed_at {
            Some(at) => s.push_str(&at.to_string()),
            None => s.push_str("null"),
        }
        s.push('}');
        s
    }

    /// Audit-event JSON for a quiet-expiry automatic release
    /// (hand-written):
    /// `{"event":"inspection_auto_released","taker":"<64hex>","at":<u64>}`.
    pub fn released_audit_json(&self) -> String {
        let mut s = String::from("{\"event\":\"inspection_auto_released\",\"taker\":\"");
        s.push_str(&hex64(&self.taker));
        s.push_str("\",\"at\":");
        match self.released_at {
            Some(at) => s.push_str(&at.to_string()),
            None => s.push_str("null"),
        }
        s.push('}');
        s
    }
}

#[cfg(test)]
mod inspection_tests {
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = b;
        k
    }

    fn window() -> InspectionPeriod {
        InspectionPeriod::new(key(7), 1000, 3600).unwrap()
    }

    #[test]
    fn constructor_validation() {
        assert_eq!(
            InspectionPeriod::new([0u8; 32], 1000, 3600).unwrap_err(),
            EscrowError::InspectionInvalidWindow
        );
        assert_eq!(
            InspectionPeriod::new(key(7), 1000, 0).unwrap_err(),
            EscrowError::InspectionInvalidWindow
        );
        assert_eq!(
            InspectionPeriod::new(key(7), u64::MAX, 1).unwrap_err(),
            EscrowError::InspectionInvalidWindow
        );
        let w = window();
        assert_eq!(w.taker(), key(7));
        assert_eq!(w.confirmed_at(), 1000);
        assert_eq!(w.inspection_secs(), 3600);
        assert_eq!(w.expires_at(), 4600);
        assert_eq!(w.state(), InspectionState::Inspecting);
        assert_eq!(w.disputed_at(), None);
        assert_eq!(w.released_at(), None);
        assert!(!w.is_releasable(4599));
        assert!(w.is_releasable(4600));
    }

    #[test]
    fn taker_dispute_freezes_release() {
        let mut w = window();
        // A stranger learns nothing about the window.
        assert_eq!(
            w.dispute(key(8), 2000).unwrap_err(),
            EscrowError::InspectionNotTaker
        );
        assert_eq!(w.state(), InspectionState::Inspecting);
        w.dispute(key(7), 2000).unwrap();
        assert_eq!(w.state(), InspectionState::Disputed);
        assert_eq!(w.disputed_at(), Some(2000));
        assert!(!w.is_releasable(9999));
        // The freeze stands: settle never auto-releases a dispute.
        assert_eq!(
            w.settle(9999).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        // And a second dispute is a terminal-state refusal, not a
        // second freeze.
        assert_eq!(
            w.dispute(key(7), 2001).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        assert_eq!(
            w.disputed_audit_json(),
            format!(
                "{{\"event\":\"inspection_disputed\",\"taker\":\"{}\",\"at\":2000}}",
                hex64(&key(7))
            )
        );
    }

    #[test]
    fn dispute_at_deadline_is_late() {
        let mut w = window();
        // The deadline second belongs to the next phase (AV-206).
        assert_eq!(
            w.dispute(key(7), 4600).unwrap_err(),
            EscrowError::InspectionWindowExpired
        );
        assert_eq!(w.state(), InspectionState::Inspecting);
        // The caller settles instead of disputing a closed window.
        let receipt = w.settle(4600).unwrap();
        assert_eq!(receipt.released_at, 4600);
    }

    #[test]
    fn quiet_expiry_auto_releases_without_second_call() {
        let mut w = window();
        assert_eq!(
            w.settle(4599).unwrap_err(),
            EscrowError::InspectionNotDue
        );
        assert_eq!(w.state(), InspectionState::Inspecting);
        let receipt = w.settle(5000).unwrap();
        assert_eq!(receipt.released_at, 5000);
        assert_eq!(w.state(), InspectionState::AutoReleased);
        assert_eq!(w.released_at(), Some(5000));
        assert!(!w.is_releasable(6000));
        // The decision is made exactly once.
        assert_eq!(
            w.settle(6000).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        assert_eq!(
            w.dispute(key(7), 6000).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        assert_eq!(
            w.released_audit_json(),
            format!(
                "{{\"event\":\"inspection_auto_released\",\"taker\":\"{}\",\"at\":5000}}",
                hex64(&key(7))
            )
        );
    }

    #[test]
    fn dispute_before_deadline_then_expiry_stays_frozen() {
        let mut w = window();
        w.dispute(key(7), 4599).unwrap();
        // Even long past the deadline, a disputed window never
        // auto-releases by inaction.
        assert_eq!(
            w.settle(99999).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        assert_eq!(w.state(), InspectionState::Disputed);
    }

    #[test]
    fn amend_terminal_windows_are_refused() {
        // Disputed: the freeze stands, no revival by amendment.
        let mut disputed = window();
        disputed.dispute(key(7), 2000).unwrap();
        assert_eq!(
            disputed.amend_inspection_secs(7200, 2000).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        assert_eq!(disputed.inspection_secs(), 3600);
        assert_eq!(disputed.expires_at(), 4600);
        assert_eq!(disputed.state(), InspectionState::Disputed);
        // Auto-released: the decision is made exactly once.
        let mut released = window();
        released.settle(4600).unwrap();
        assert_eq!(
            released.amend_inspection_secs(7200, 4600).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        assert_eq!(released.inspection_secs(), 3600);
        assert_eq!(released.expires_at(), 4600);
        assert_eq!(released.state(), InspectionState::AutoReleased);
    }

    #[test]
    fn amend_zero_or_overflowing_window_is_refused() {
        let mut w = window();
        assert_eq!(
            w.amend_inspection_secs(0, 2000).unwrap_err(),
            EscrowError::InspectionInvalidWindow
        );
        assert_eq!(w.inspection_secs(), 3600);
        assert_eq!(w.expires_at(), 4600);
        // A deadline past u64::MAX cannot be represented.
        let mut edge = InspectionPeriod::new(key(7), u64::MAX - 10, 10).unwrap();
        assert_eq!(edge.expires_at(), u64::MAX);
        assert_eq!(
            edge.amend_inspection_secs(u64::MAX, 0).unwrap_err(),
            EscrowError::InspectionInvalidWindow
        );
        assert_eq!(edge.inspection_secs(), 10);
        assert_eq!(edge.expires_at(), u64::MAX);
    }

    #[test]
    fn amend_new_deadline_at_or_before_now_is_refused() {
        let mut w = window();
        // A new deadline of 1010 is not strictly later than now.
        assert_eq!(
            w.amend_inspection_secs(10, 1010).unwrap_err(),
            EscrowError::InspectionWindowExpired
        );
        assert_eq!(
            w.amend_inspection_secs(10, 1011).unwrap_err(),
            EscrowError::InspectionWindowExpired
        );
        // A failed revision changed nothing.
        assert_eq!(w.inspection_secs(), 3600);
        assert_eq!(w.expires_at(), 4600);
        assert_eq!(w.state(), InspectionState::Inspecting);
    }

    #[test]
    fn amend_same_value_is_a_silent_noop() {
        let mut w = window();
        assert_eq!(w.amend_inspection_secs(3600, 2000), Ok(false));
        assert_eq!(w.inspection_secs(), 3600);
        assert_eq!(w.expires_at(), 4600);
        assert_eq!(w.state(), InspectionState::Inspecting);
        assert_eq!(w.taker(), key(7));
        assert_eq!(w.confirmed_at(), 1000);
    }

    #[test]
    fn amend_same_value_past_deadline_still_fails_closed() {
        // Check order pins this: the deadline gate runs before the
        // same-value no-op, so a same-value call at or past the
        // deadline is an expiry refusal, not a silent no-op.
        let mut w = window();
        assert_eq!(
            w.amend_inspection_secs(3600, 4600).unwrap_err(),
            EscrowError::InspectionWindowExpired
        );
        assert_eq!(w.inspection_secs(), 3600);
        assert_eq!(w.expires_at(), 4600);
    }

    #[test]
    fn amend_extend_revives_a_nearly_expired_window() {
        let mut w = window();
        assert_eq!(w.amend_inspection_secs(7200, 4500), Ok(true));
        assert_eq!(w.inspection_secs(), 7200);
        assert_eq!(w.expires_at(), 8200);
        // Past the old deadline, the taker can still dispute.
        assert!(!w.is_releasable(5000));
        w.dispute(key(7), 5000).unwrap();
        assert_eq!(w.state(), InspectionState::Disputed);
        assert_eq!(w.disputed_at(), Some(5000));
    }

    #[test]
    fn amend_shorten_makes_the_window_settleable_earlier() {
        let mut w = window();
        assert_eq!(w.amend_inspection_secs(600, 1100), Ok(true));
        assert_eq!(w.inspection_secs(), 600);
        assert_eq!(w.expires_at(), 1600);
        assert!(!w.is_releasable(1599));
        assert!(w.is_releasable(1600));
        let receipt = w.settle(1600).unwrap();
        assert_eq!(receipt.released_at, 1600);
        assert_eq!(w.state(), InspectionState::AutoReleased);
    }

    #[test]
    fn amend_moves_only_the_window_fields() {
        let mut w = window();
        assert!(w.amend_inspection_secs(7200, 2000).unwrap());
        assert_eq!(w.taker(), key(7));
        assert_eq!(w.confirmed_at(), 1000);
        assert_eq!(w.state(), InspectionState::Inspecting);
        assert_eq!(w.disputed_at(), None);
        assert_eq!(w.released_at(), None);
        assert_eq!(w.inspection_secs(), 7200);
        assert_eq!(w.expires_at(), 8200);
    }

    #[test]
    fn inspection_window_amended_audit_json_exact() {
        let mut w = window();
        assert!(w.amend_inspection_secs(7200, 2000).unwrap());
        assert_eq!(
            w.inspection_window_audit_json(3600),
            format!(
                "{{\"event\":\"inspection_window_amended\",\"taker\":\"{}\",\
                 \"previous_inspection_secs\":3600,\"inspection_secs\":7200,\
                 \"previous_expires_at\":4600,\"expires_at\":8200}}",
                hex64(&key(7))
            )
        );
    }
}
