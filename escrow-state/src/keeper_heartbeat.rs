//! AV-165: keeper fleet liveness — signed heartbeats, missed-beat
//! detection, and standby takeover of unhealthy keepers' escrow sets.
//!
//! The keeper scans ([`scan_keeper_actions`](super::keeper::scan_keeper_actions),
//! [`scan_rent_health`](super::keeper::scan_rent_health)) are dry-run by
//! construction, so a fleet of keeper bots can share the work — but a
//! dead keeper silently drops its escrow set. This module is the
//! liveness layer: keepers prove they are alive with Ed25519-signed
//! heartbeats, a missed-beat detector marks keepers that go quiet, and
//! a standby keeper can claim an unhealthy keeper's escrow set.
//! It is deliberately orthogonal to the AV-118 push notifications: that
//! module *announces* actions, this module *detects dead operators and
//! reassigns their work*.
//!
//! # Components
//!
//! - [`Heartbeat`]: the signed liveness envelope — keeper key, slot,
//!   unix timestamp, and the keeper's last executed action
//!   ([`KeeperLastAction`]). Signed over canonical bytes prefixed with
//!   [`KEEPER_HEARTBEAT_DOMAIN`] (the cross-protocol replay defense,
//!   same convention as AV-123).
//! - [`HeartbeatRegistry`]: the fleet roster. `register` enrolls a
//!   keeper; [`HeartbeatRegistry::heartbeat`] verifies and folds a
//!   signed heartbeat; [`HeartbeatRegistry::scan`] is the missed-beat
//!   detector (marks keepers unhealthy); [`HeartbeatRegistry::claim`]
//!   lets a standby claim an unhealthy keeper's escrow set.
//! - [`HeartbeatAuditEntry`]: the structured audit — `HeartbeatMissed`
//!   on the unhealthy transition (edge-triggered), `TakeoverClaimed`
//!   on a successful claim, `ClaimConflict` when two standbys race for
//!   the same set (first-come-first-served, the loser is audited), and
//!   `ClaimRevoked` when the original keeper recovers. Bounded 64-entry
//!   ring, oldest evicts first (the AV-163 convention).
//!
//! # What is real here
//!
//! - **Signatures are verified, not trusted.** Every heartbeat's
//!   Ed25519 signature is checked against the registered keeper key
//!   before any state moves; a forged or tampered heartbeat is
//!   [`EscrowError::HeartbeatSignatureInvalid`].
//! - **Unhealthy is computed from slots, not wall clocks.**
//!   `missed = (current_slot - last_slot) / expected_interval_slots`;
//!   a keeper is unhealthy when `missed >= max_missed_beats` *or*
//!   `current_slot - last_slot > stale_slot_threshold`. Both rules are
//!   deterministic given the slot numbers — the same inputs always give
//!   the same verdict.
//! - **Stale heartbeats are idempotent no-ops.** A heartbeat with
//!   `slot <= last_slot` (a delayed duplicate or a replay) changes
//!   nothing — it can neither rewind the record nor revive an unhealthy
//!   keeper. Only a *fresh* slot updates the record and clears the
//!   unhealthy latch.
//! - **Takeover is first-come-first-served with conflict audit.**
//!   The first standby to claim an unhealthy keeper's set wins; a
//!   second claimant gets [`EscrowError::ClaimConflict`] *and* a
//!   `ClaimConflict` audit entry (the AV-36 convention: the failed
//!   security-relevant call is still audited).
//! - **Recovery revokes the claim.** A fresh heartbeat from a claimed
//!   keeper clears the claim (`ClaimRevoked` audit) — the original
//!   keeper is back, so the standby stands down. No split-brain.
//!
//! # What is deliberately NOT here (honesty labels)
//!
//! - **The registry is off-chain state.** It is the operator's fleet
//!   roster, not an on-chain account: no slot sysvar, no account
//!   layout, no Anchor instruction in this round. The caller feeds
//!   `current_slot` / `now` — the crate has no clock.
//! - **The standby must be a registered keeper.** Claims from unknown
//!   keys are rejected ([`EscrowError::KeeperNotRegistered`]) — the
//!   roster is the trust boundary.
//! - **The detector only marks; it never acts.** `scan` returns the
//!   newly-unhealthy keepers and audits the transition; the operator
//!   decides which standby claims which set (or automates it — the
//!   claim call is the automation hook).
//! - **The escrow set is caller-supplied.** `claim` takes the escrow ids
//!   being claimed and records them on the target's record (capped at
//!   [`MAX_CLAIMED_ESCROWS`]); the registry does not scan escrows
//!   itself — that is the keeper scan's job.

use std::collections::VecDeque;

use super::ed25519::{verify as ed25519_verify, SigningKey};
use super::EscrowError;

/// Domain-separation prefix for the signed heartbeat payload.
/// Prepended to the canonical field encoding before signing, so a
/// signature minted for any other envelope (release intent, keeper
/// report, multisig ballot, …) can never verify as a heartbeat.
pub const KEEPER_HEARTBEAT_DOMAIN: &[u8] = b"KEEPER-HEARTBEAT-v1";

/// Canonical byte length of the signed payload: domain (19) + keeper
/// (32) + slot (8) + at (8) + last_action (1).
pub const HEARTBEAT_MSG_LEN: usize = 19 + 32 + 8 + 8 + 1;

/// How many heartbeat audit entries the registry remembers: a bounded
/// ring, mirroring the AV-163 circuit-breaker convention (fixed-size
/// tail, oldest evicts first).
pub const MAX_KEEPER_AUDIT_ENTRIES: usize = 64;

/// Maximum escrow ids recorded per takeover claim. The set is
/// caller-supplied; the cap keeps one claim from ballooning the
/// registry.
pub const MAX_CLAIMED_ESCROWS: usize = 256;

/// The last action a keeper reports in its heartbeat — a compact
/// status code, not a full action log (the keeper scans own the
/// details).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeeperLastAction {
    /// No action executed since the last heartbeat (idle).
    Idle = 0,
    /// Executed a `cancel_expired` (or crank) call.
    CancelExpired = 1,
    /// Executed a vesting `claim`.
    Claim = 2,
    /// Executed a rent top-up.
    RentTopUp = 3,
    /// Anything else.
    Other = 255,
}

impl KeeperLastAction {
    /// Decode the wire byte; unknown values map to `Other` (never a
    /// parse failure — a heartbeat must not die on a new action code).
    pub fn from_u8(b: u8) -> Self {
        match b {
            0 => KeeperLastAction::Idle,
            1 => KeeperLastAction::CancelExpired,
            2 => KeeperLastAction::Claim,
            3 => KeeperLastAction::RentTopUp,
            _ => KeeperLastAction::Other,
        }
    }

    /// The wire byte.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The signed liveness envelope a keeper submits. `keeper` is the
/// keeper's Ed25519 public key (the registry's roster key); `slot` is
/// the keeper's latest observed slot; `at` is the unix timestamp the
/// heartbeat was minted at; `last_action` is what the keeper last did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    /// The keeper's public key.
    pub keeper: [u8; 32],
    /// The keeper's latest observed slot.
    pub slot: u64,
    /// Unix timestamp the heartbeat was minted at.
    pub at: u64,
    /// The last action the keeper executed.
    pub last_action: KeeperLastAction,
}

impl Heartbeat {
    /// Canonical byte encoding: domain + keeper + slot (LE) + at (LE)
    /// + last_action. Fixed-field-order, no length prefixes — exactly
    /// one byte string per heartbeat (canonical by construction; the
    /// `heartbeat_canonical_bytes_are_pinned` test pins it
    /// byte-for-byte).
    pub fn canonical_bytes(&self) -> [u8; HEARTBEAT_MSG_LEN] {
        let mut out = [0u8; HEARTBEAT_MSG_LEN];
        out[..19].copy_from_slice(KEEPER_HEARTBEAT_DOMAIN);
        out[19..51].copy_from_slice(&self.keeper);
        out[51..59].copy_from_slice(&self.slot.to_le_bytes());
        out[59..67].copy_from_slice(&self.at.to_le_bytes());
        out[67] = self.last_action.as_u8();
        out
    }

    /// Sign this heartbeat with a [`SigningKey`] (test/operator-side
    /// helper — the registry only ever verifies).
    pub fn sign(&self, key: &SigningKey) -> [u8; 64] {
        key.sign(&self.canonical_bytes())
    }

    /// Verify a detached signature against `public_key`. `false` on
    /// any mismatch — tampered bytes, wrong key, or a signature minted
    /// for a different domain. Never panics.
    pub fn verify(&self, public_key: &[u8; 32], signature: &[u8; 64]) -> bool {
        ed25519_verify(public_key, &self.canonical_bytes(), signature)
    }
}

/// Missed-beat detector configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatConfig {
    /// Expected slots between heartbeats; the missed-beat counter is
    /// `(current_slot - last_slot) / expected_interval_slots`.
    pub expected_interval_slots: u64,
    /// Consecutive missed beats that mark a keeper unhealthy.
    pub max_missed_beats: u32,
    /// Absolute slot staleness that marks a keeper unhealthy even when
    /// the beat counter has not tripped (covers a keeper whose
    /// configured interval is long).
    pub stale_slot_threshold: u64,
}

impl HeartbeatConfig {
    /// Validate: zero `expected_interval_slots` or zero
    /// `max_missed_beats` would make the detector vacuous.
    pub fn validate(&self) -> Result<(), EscrowError> {
        if self.expected_interval_slots == 0 || self.max_missed_beats == 0 {
            return Err(EscrowError::InvalidHeartbeatConfig);
        }
        Ok(())
    }
}

/// The heartbeat audit events the registry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatAuditKind {
    /// The missed-beat detector marked a keeper unhealthy
    /// (edge-triggered: once per unhealthy transition).
    HeartbeatMissed,
    /// A standby claimed an unhealthy keeper's escrow set.
    TakeoverClaimed,
    /// A second standby raced for an already-claimed set and lost
    /// (first-come-first-served; the failed claim is audited anyway).
    ClaimConflict,
    /// The original keeper recovered (fresh heartbeat) and the
    /// standby's claim was revoked.
    ClaimRevoked,
}

/// One structured heartbeat audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatAuditEntry {
    /// What happened.
    pub kind: HeartbeatAuditKind,
    /// Unix timestamp of the event (caller-supplied).
    pub at: u64,
    /// The subject keeper (the unhealthy keeper, or the recovering
    /// keeper for `ClaimRevoked`).
    pub keeper: [u8; 32],
    /// The actor: the claiming standby for `TakeoverClaimed`, the
    /// losing standby for `ClaimConflict`, the recovering keeper for
    /// `ClaimRevoked`, and `[0; 32]` for `HeartbeatMissed` (the
    /// detector has no human actor).
    pub actor: [u8; 32],
    /// Escrow ids carried by the claim (`TakeoverClaimed` /
    /// `ClaimConflict` / `ClaimRevoked`); `0` for `HeartbeatMissed`.
    pub escrow_count: u32,
}

/// One enrolled keeper's liveness record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeeperRecord {
    key: [u8; 32],
    last_slot: u64,
    last_at: u64,
    last_action: KeeperLastAction,
    unhealthy: bool,
    claimed_by: Option<[u8; 32]>,
    claimed_at: u64,
    claimed_escrows: Vec<[u8; 32]>,
}

/// The keeper fleet roster: liveness records, the missed-beat
/// detector, standby takeover, and the bounded audit ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatRegistry {
    config: HeartbeatConfig,
    keepers: Vec<KeeperRecord>,
    audit: VecDeque<HeartbeatAuditEntry>,
}

impl HeartbeatRegistry {
    /// Create a registry with a validated config.
    pub fn new(config: HeartbeatConfig) -> Result<Self, EscrowError> {
        config.validate()?;
        Ok(HeartbeatRegistry {
            config,
            keepers: Vec::new(),
            audit: VecDeque::with_capacity(MAX_KEEPER_AUDIT_ENTRIES),
        })
    }

    /// Enroll a keeper. Re-enrolling the same key is an idempotent
    /// no-op. The zero key is rejected
    /// ([`EscrowError::InvalidHeartbeatConfig`]) — an unkeyed roster
    /// entry could never verify a heartbeat.
    pub fn register(&mut self, keeper: [u8; 32]) -> Result<(), EscrowError> {
        if keeper == [0u8; 32] {
            return Err(EscrowError::InvalidHeartbeatConfig);
        }
        if self.keepers.iter().any(|r| r.key == keeper) {
            return Ok(());
        }
        self.keepers.push(KeeperRecord {
            key: keeper,
            last_slot: 0,
            last_at: 0,
            last_action: KeeperLastAction::Idle,
            unhealthy: false,
            claimed_by: None,
            claimed_at: 0,
            claimed_escrows: Vec::new(),
        });
        Ok(())
    }

    fn find(&self, keeper: &[u8; 32]) -> Option<usize> {
        self.keepers.iter().position(|r| &r.key == keeper)
    }

    fn push_audit(&mut self, entry: HeartbeatAuditEntry) {
        if self.audit.len() == MAX_KEEPER_AUDIT_ENTRIES {
            self.audit.pop_front();
        }
        self.audit.push_back(entry);
    }

    /// The unhealthy predicate: `missed >= max_missed_beats`, or the
    /// slot staleness past `stale_slot_threshold`. Deterministic given
    /// the slot numbers. A `current_slot` at or behind `last_slot`
    /// (clock regression) never marks unhealthy.
    fn unhealthy_at(&self, rec: &KeeperRecord, current_slot: u64) -> bool {
        if current_slot <= rec.last_slot {
            return false;
        }
        let elapsed = current_slot - rec.last_slot;
        let missed = elapsed / self.config.expected_interval_slots;
        missed >= self.config.max_missed_beats as u64
            || elapsed > self.config.stale_slot_threshold
    }

    /// Verify and fold a signed heartbeat. Check order: roster
    /// membership ([`EscrowError::KeeperNotRegistered`]), then
    /// signature ([`EscrowError::HeartbeatSignatureInvalid`]).
    ///
    /// A heartbeat with `slot <= last_slot` is a stale duplicate: it
    /// is accepted as an idempotent no-op (the record is untouched —
    /// a replay can neither rewind the record nor revive an unhealthy
    /// keeper). A *fresh* slot updates the record, clears the
    /// unhealthy latch, and — if a standby had claimed this keeper —
    /// revokes the claim (`ClaimRevoked` audit): the original keeper
    /// is back, so the standby stands down.
    pub fn heartbeat(
        &mut self,
        hb: &Heartbeat,
        signature: &[u8; 64],
    ) -> Result<(), EscrowError> {
        let idx = self
            .find(&hb.keeper)
            .ok_or(EscrowError::KeeperNotRegistered)?;
        if !hb.verify(&self.keepers[idx].key, signature) {
            return Err(EscrowError::HeartbeatSignatureInvalid);
        }
        let rec_key = self.keepers[idx].key;
        let was_claimed: bool;
        let claimed_count: u32;
        {
            let rec = &mut self.keepers[idx];
            if hb.slot <= rec.last_slot {
                return Ok(());
            }
            was_claimed = rec.claimed_by.is_some();
            claimed_count = rec.claimed_escrows.len() as u32;
            rec.last_slot = hb.slot;
            rec.last_at = hb.at;
            rec.last_action = hb.last_action;
            rec.unhealthy = false;
            if was_claimed {
                rec.claimed_by = None;
                rec.claimed_at = 0;
                rec.claimed_escrows.clear();
            }
        }
        if was_claimed {
            self.push_audit(HeartbeatAuditEntry {
                kind: HeartbeatAuditKind::ClaimRevoked,
                at: hb.at,
                keeper: rec_key,
                actor: rec_key,
                escrow_count: claimed_count,
            });
        }
        Ok(())
    }

    /// The missed-beat detector: evaluate every enrolled keeper
    /// against `current_slot` and latch newly-unhealthy keepers.
    /// Returns the keepers that transitioned to unhealthy on this
    /// call (edge-triggered — a keeper already latched unhealthy is
    /// not reported again). Each transition appends a
    /// `HeartbeatMissed` audit entry.
    pub fn scan(&mut self, current_slot: u64, now: u64) -> Vec<[u8; 32]> {
        let mut newly = Vec::new();
        for i in 0..self.keepers.len() {
            if !self.keepers[i].unhealthy && self.unhealthy_at(&self.keepers[i], current_slot) {
                self.keepers[i].unhealthy = true;
                let key = self.keepers[i].key;
                newly.push(key);
                self.push_audit(HeartbeatAuditEntry {
                    kind: HeartbeatAuditKind::HeartbeatMissed,
                    at: now,
                    keeper: key,
                    actor: [0u8; 32],
                    escrow_count: 0,
                });
            }
        }
        newly
    }

    /// Whether `keeper` is latched unhealthy (set by
    /// [`HeartbeatRegistry::scan`]; `false` for unknown keepers).
    pub fn is_unhealthy(&self, keeper: &[u8; 32]) -> bool {
        self.find(keeper).map(|i| self.keepers[i].unhealthy).unwrap_or(false)
    }

    /// The standby that claimed `keeper`'s escrow set, if any.
    pub fn claimed_by(&self, keeper: &[u8; 32]) -> Option<[u8; 32]> {
        self.find(keeper).and_then(|i| self.keepers[i].claimed_by)
    }

    /// The escrow ids a standby claimed for `keeper` (`None` for
    /// unknown keepers; empty when unclaimed).
    pub fn claimed_escrows(&self, keeper: &[u8; 32]) -> Option<&[[u8; 32]]> {
        self.find(keeper).map(|i| self.keepers[i].claimed_escrows.as_slice())
    }

    /// Standby takeover: `standby` claims the escrow set of the
    /// unhealthy keeper `target`, recording `escrow_ids` on the
    /// target's record. Check order: claim shape
    /// ([`EscrowError::InvalidClaim`] — zero standby, self-claim, or
    /// an over-long escrow set), roster membership (standby and target
    /// must both be registered:
    /// [`EscrowError::KeeperNotRegistered`]), target health
    /// ([`EscrowError::KeeperHealthy`] — only unhealthy keepers are
    /// claimable), then the first-come-first-served gate
    /// ([`EscrowError::ClaimConflict`]).
    ///
    /// The health check is computed from `current_slot` on the spot
    /// (same predicate as [`HeartbeatRegistry::scan`]), so a claim
    /// works even if no scan ran recently. A lost race appends a
    /// `ClaimConflict` audit entry before returning the error; a win
    /// appends `TakeoverClaimed`.
    pub fn claim(
        &mut self,
        standby: [u8; 32],
        target: [u8; 32],
        escrow_ids: &[[u8; 32]],
        now: u64,
        current_slot: u64,
    ) -> Result<(), EscrowError> {
        if standby == [0u8; 32] || standby == target {
            return Err(EscrowError::InvalidClaim);
        }
        if escrow_ids.len() > MAX_CLAIMED_ESCROWS {
            return Err(EscrowError::InvalidClaim);
        }
        let s_idx = self
            .find(&standby)
            .ok_or(EscrowError::KeeperNotRegistered)?;
        let t_idx = self
            .find(&target)
            .ok_or(EscrowError::KeeperNotRegistered)?;
        let _ = s_idx;
        if !self.unhealthy_at(&self.keepers[t_idx], current_slot) {
            return Err(EscrowError::KeeperHealthy);
        }
        if self.keepers[t_idx].claimed_by.is_some() {
            self.push_audit(HeartbeatAuditEntry {
                kind: HeartbeatAuditKind::ClaimConflict,
                at: now,
                keeper: target,
                actor: standby,
                escrow_count: escrow_ids.len() as u32,
            });
            return Err(EscrowError::ClaimConflict);
        }
        let rec = &mut self.keepers[t_idx];
        rec.claimed_by = Some(standby);
        rec.claimed_at = now;
        rec.claimed_escrows = escrow_ids.to_vec();
        self.push_audit(HeartbeatAuditEntry {
            kind: HeartbeatAuditKind::TakeoverClaimed,
            at: now,
            keeper: target,
            actor: standby,
            escrow_count: escrow_ids.len() as u32,
        });
        Ok(())
    }

    /// The heartbeat audit trail, oldest-first.
    pub fn audit(&self) -> Vec<HeartbeatAuditEntry> {
        self.audit.iter().copied().collect()
    }
}

#[cfg(test)]
mod keeper_heartbeat_tests {
    use super::*;

    const KEEPER_A_SEED: [u8; 32] = [0xA1; 32];
    const KEEPER_B_SEED: [u8; 32] = [0xB2; 32];
    const KEEPER_C_SEED: [u8; 32] = [0xC3; 32];

    fn config() -> HeartbeatConfig {
        HeartbeatConfig {
            expected_interval_slots: 10,
            max_missed_beats: 3,
            stale_slot_threshold: 100,
        }
    }

    fn registry() -> (HeartbeatRegistry, [u8; 32], [u8; 32], [u8; 32]) {
        let ka = SigningKey::from_seed(KEEPER_A_SEED);
        let kb = SigningKey::from_seed(KEEPER_B_SEED);
        let kc = SigningKey::from_seed(KEEPER_C_SEED);
        let (pa, pb, pc) = (ka.public_key(), kb.public_key(), kc.public_key());
        let mut r = HeartbeatRegistry::new(config()).unwrap();
        r.register(pa).unwrap();
        r.register(pb).unwrap();
        r.register(pc).unwrap();
        (r, pa, pb, pc)
    }

    fn heartbeat_for(key: &SigningKey, slot: u64, action: KeeperLastAction) -> (Heartbeat, [u8; 64]) {
        let hb = Heartbeat {
            keeper: key.public_key(),
            slot,
            at: 1_700_000_000 + slot,
            last_action: action,
        };
        let sig = hb.sign(key);
        (hb, sig)
    }

    #[test]
    fn heartbeat_canonical_bytes_are_pinned() {
        let hb = Heartbeat {
            keeper: [0x11; 32],
            slot: 0x0102030405060708,
            at: 0x1112131415161718,
            last_action: KeeperLastAction::Claim,
        };
        let bytes = hb.canonical_bytes();
        assert_eq!(bytes.len(), HEARTBEAT_MSG_LEN);
        assert_eq!(&bytes[..19], b"KEEPER-HEARTBEAT-v1");
        assert_eq!(&bytes[19..51], &[0x11; 32]);
        assert_eq!(&bytes[51..59], &0x0102030405060708u64.to_le_bytes());
        assert_eq!(&bytes[59..67], &0x1112131415161718u64.to_le_bytes());
        assert_eq!(bytes[67], 2); // Claim
    }

    #[test]
    fn new_rejects_vacuous_config() {
        assert_eq!(
            HeartbeatRegistry::new(HeartbeatConfig {
                expected_interval_slots: 0,
                max_missed_beats: 3,
                stale_slot_threshold: 100,
            }),
            Err(EscrowError::InvalidHeartbeatConfig)
        );
        assert_eq!(
            HeartbeatRegistry::new(HeartbeatConfig {
                expected_interval_slots: 10,
                max_missed_beats: 0,
                stale_slot_threshold: 100,
            }),
            Err(EscrowError::InvalidHeartbeatConfig)
        );
    }

    #[test]
    fn register_rejects_zero_key_and_is_idempotent() {
        let mut r = HeartbeatRegistry::new(config()).unwrap();
        assert_eq!(
            r.register([0u8; 32]),
            Err(EscrowError::InvalidHeartbeatConfig)
        );
        let ka = SigningKey::from_seed(KEEPER_A_SEED).public_key();
        assert!(r.register(ka).is_ok());
        assert!(r.register(ka).is_ok()); // idempotent
    }

    #[test]
    fn heartbeat_for_unknown_keeper_is_rejected() {
        let (mut r, _, _, _) = registry();
        let outsider = SigningKey::from_seed([0xFF; 32]);
        let (hb, sig) = heartbeat_for(&outsider, 10, KeeperLastAction::Idle);
        assert_eq!(
            r.heartbeat(&hb, &sig),
            Err(EscrowError::KeeperNotRegistered)
        );
    }

    #[test]
    fn tampered_heartbeat_fails_signature() {
        let (mut r, pa, _, _) = registry();
        let ka = SigningKey::from_seed(KEEPER_A_SEED);
        let (hb, sig) = heartbeat_for(&ka, 10, KeeperLastAction::Idle);
        assert!(r.heartbeat(&hb, &sig).is_ok());
        // Tamper the slot after signing: the signature no longer covers
        // the bytes.
        let mut tampered = hb;
        tampered.slot = 11;
        assert_eq!(
            r.heartbeat(&tampered, &sig),
            Err(EscrowError::HeartbeatSignatureInvalid)
        );
        // Wrong-key signature also fails.
        let kb = SigningKey::from_seed(KEEPER_B_SEED);
        let wrong_sig = hb.sign(&kb);
        let (hb2, _) = heartbeat_for(&ka, 20, KeeperLastAction::Idle);
        assert_eq!(
            r.heartbeat(&hb2, &wrong_sig),
            Err(EscrowError::HeartbeatSignatureInvalid)
        );
        let _ = pa;
    }

    #[test]
    fn stale_heartbeat_is_idempotent_noop() {
        let (mut r, _, _, _) = registry();
        let ka = SigningKey::from_seed(KEEPER_A_SEED);
        let (hb, sig) = heartbeat_for(&ka, 50, KeeperLastAction::Claim);
        r.heartbeat(&hb, &sig).unwrap();
        // A delayed duplicate with an older slot changes nothing and
        // cannot revive or rewind.
        let (old, old_sig) = heartbeat_for(&ka, 40, KeeperLastAction::Idle);
        assert!(r.heartbeat(&old, &old_sig).is_ok());
        let idx = r.find(&ka.public_key()).unwrap();
        assert_eq!(r.keepers[idx].last_slot, 50);
        assert_eq!(r.keepers[idx].last_action, KeeperLastAction::Claim);
        // Same slot is also a no-op.
        let (same, same_sig) = heartbeat_for(&ka, 50, KeeperLastAction::Idle);
        assert!(r.heartbeat(&same, &same_sig).is_ok());
        assert_eq!(r.keepers[idx].last_action, KeeperLastAction::Claim);
    }

    #[test]
    fn scan_marks_unhealthy_on_missed_beats() {
        let (mut r, pa, pb, pc) = registry();
        let ka = SigningKey::from_seed(KEEPER_A_SEED);
        let kb = SigningKey::from_seed(KEEPER_B_SEED);
        let kc = SigningKey::from_seed(KEEPER_C_SEED);
        // All three heartbeat at slot 100; at slot 131 each missed
        // 3 beats (31 / 10) — the trip threshold.
        let (hb, sig) = heartbeat_for(&ka, 100, KeeperLastAction::Idle);
        r.heartbeat(&hb, &sig).unwrap();
        let (hbb, sigb) = heartbeat_for(&kb, 100, KeeperLastAction::Idle);
        r.heartbeat(&hbb, &sigb).unwrap();
        let (hbc, sigc) = heartbeat_for(&kc, 100, KeeperLastAction::Idle);
        r.heartbeat(&hbc, &sigc).unwrap();
        let newly = r.scan(131, 9_999);
        assert_eq!(newly, vec![pa, pb, pc]);
        assert!(r.is_unhealthy(&pa));
        assert!(r.is_unhealthy(&pb));
        assert!(r.is_unhealthy(&pc));
        // Edge-triggered: the second scan reports nothing new.
        assert!(r.scan(200, 10_000).is_empty());
        // The audit carries one HeartbeatMissed per keeper.
        let missed: Vec<_> = r
            .audit()
            .into_iter()
            .filter(|e| e.kind == HeartbeatAuditKind::HeartbeatMissed)
            .collect();
        assert_eq!(missed.len(), 3);
        assert_eq!(missed[0].keeper, pa);
        assert_eq!(missed[0].actor, [0u8; 32]); // the detector, no human actor
    }

    #[test]
    fn scan_stale_threshold_triggers_before_beat_counter() {
        let cfg = HeartbeatConfig {
            expected_interval_slots: 1_000,
            max_missed_beats: 100,
            stale_slot_threshold: 50,
        };
        let ka = SigningKey::from_seed(KEEPER_A_SEED);
        let mut r = HeartbeatRegistry::new(cfg).unwrap();
        r.register(ka.public_key()).unwrap();
        let (hb, sig) = heartbeat_for(&ka, 1_000, KeeperLastAction::Idle);
        r.heartbeat(&hb, &sig).unwrap();
        // Elapsed 51: missed = 0 beats, but staleness 51 > 50.
        assert_eq!(r.scan(1_051, 1), vec![ka.public_key()]);
    }

    #[test]
    fn scan_ignores_clock_regression() {
        let (mut r, pa, _, _) = registry();
        let ka = SigningKey::from_seed(KEEPER_A_SEED);
        let (hb, sig) = heartbeat_for(&ka, 1_000, KeeperLastAction::Idle);
        r.heartbeat(&hb, &sig).unwrap();
        // A current_slot behind A's last heartbeat is a clock
        // regression: A must not be marked. (B and C never heartbeated,
        // so they are legitimately flagged — the assertion is only
        // about A.)
        let newly = r.scan(500, 1);
        assert!(!newly.contains(&pa));
        assert!(!r.is_unhealthy(&pa));
    }

    #[test]
    fn claim_rejects_bad_shape_and_unknown_parties() {
        let (mut r, pa, pb, _) = registry();
        let kb = SigningKey::from_seed(KEEPER_B_SEED);
        // Make B unhealthy without a scan: last_slot 0, current 1000.
        assert_eq!(
            r.claim([0u8; 32], pb, &[], 1, 1_000),
            Err(EscrowError::InvalidClaim)
        );
        assert_eq!(
            r.claim(pa, pa, &[], 1, 1_000),
            Err(EscrowError::InvalidClaim)
        );
        let big = vec![[0xE1; 32]; MAX_CLAIMED_ESCROWS + 1];
        assert_eq!(
            r.claim(pa, pb, &big, 1, 1_000),
            Err(EscrowError::InvalidClaim)
        );
        assert_eq!(
            r.claim([0xDD; 32], pb, &[], 1, 1_000),
            Err(EscrowError::KeeperNotRegistered)
        );
        assert_eq!(
            r.claim(pa, [0xDD; 32], &[], 1, 1_000),
            Err(EscrowError::KeeperNotRegistered)
        );
        let _ = kb;
    }

    #[test]
    fn claim_on_healthy_keeper_is_rejected() {
        let (mut r, pa, pb, _) = registry();
        let ka = SigningKey::from_seed(KEEPER_A_SEED);
        let (hb, sig) = heartbeat_for(&ka, 1_000, KeeperLastAction::Idle);
        r.heartbeat(&hb, &sig).unwrap();
        // A is fresh at slot 1005: healthy, not claimable.
        assert_eq!(
            r.claim(pb, pa, &[], 2, 1_005),
            Err(EscrowError::KeeperHealthy)
        );
    }

    #[test]
    fn claim_records_takeover_and_first_come_first_served() {
        let (mut r, pa, pb, pc) = registry();
        let ka = SigningKey::from_seed(KEEPER_A_SEED);
        // A heartbeats fresh: healthy, not claimable.
        let (hb, sig) = heartbeat_for(&ka, 1_000, KeeperLastAction::Idle);
        r.heartbeat(&hb, &sig).unwrap();
        let escrows = [[0xE1; 32], [0xE2; 32]];
        // Healthy keeper: not claimable.
        assert_eq!(
            r.claim(pb, pa, &escrows, 1, 1_005),
            Err(EscrowError::KeeperHealthy)
        );
        // Self-claim is rejected even on an unhealthy keeper.
        assert_eq!(
            r.claim(pb, pb, &escrows, 1, 1_005),
            Err(EscrowError::InvalidClaim)
        );
        // C never heartbeated (last_slot 0, elapsed 1005 → missed 100
        // beats): unhealthy — B claims C's set.
        r.claim(pb, pc, &escrows, 42, 1_005).unwrap();
        assert_eq!(r.claimed_by(&pc), Some(pb));
        assert_eq!(r.claimed_escrows(&pc).unwrap(), &escrows);
        let audit = r.audit();
        let took: Vec<_> = audit
            .iter()
            .filter(|e| e.kind == HeartbeatAuditKind::TakeoverClaimed)
            .collect();
        assert_eq!(took.len(), 1);
        assert_eq!(took[0].keeper, pc);
        assert_eq!(took[0].actor, pb);
        assert_eq!(took[0].escrow_count, 2);
        // A second standby races and loses: conflict error + conflict
        // audit, and the first claim stands.
        assert_eq!(
            r.claim(pa, pc, &escrows, 43, 1_005),
            Err(EscrowError::ClaimConflict)
        );
        assert_eq!(r.claimed_by(&pc), Some(pb));
        let audit = r.audit();
        let conflicts: Vec<_> = audit
            .iter()
            .filter(|e| e.kind == HeartbeatAuditKind::ClaimConflict)
            .collect();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].actor, pa);
        assert_eq!(conflicts[0].escrow_count, 2);
    }

    #[test]
    fn recovery_revokes_the_claim() {
        let (mut r, _, pb, pc) = registry();
        let kc = SigningKey::from_seed(KEEPER_C_SEED);
        let escrows = [[0xE1; 32]];
        r.claim(pb, pc, &escrows, 42, 1_000).unwrap();
        assert_eq!(r.claimed_by(&pc), Some(pb));
        // C recovers with a fresh heartbeat: the claim is revoked.
        let (hb, sig) = heartbeat_for(&kc, 1_001, KeeperLastAction::Idle);
        r.heartbeat(&hb, &sig).unwrap();
        assert_eq!(r.claimed_by(&pc), None);
        assert!(r.claimed_escrows(&pc).unwrap().is_empty());
        assert!(!r.is_unhealthy(&pc));
        let audit = r.audit();
        let revoked: Vec<_> = audit
            .iter()
            .filter(|e| e.kind == HeartbeatAuditKind::ClaimRevoked)
            .collect();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].keeper, pc);
        assert_eq!(revoked[0].actor, pc);
        assert_eq!(revoked[0].escrow_count, 1);
        // Healthy again: not claimable.
        assert_eq!(
            r.claim(pb, pc, &escrows, 43, 1_001),
            Err(EscrowError::KeeperHealthy)
        );
    }

    #[test]
    fn audit_ring_evicts_oldest() {
        let (mut r, _, pb, pc) = registry();
        let kd = SigningKey::from_seed([0xD4; 32]);
        let ke = SigningKey::from_seed([0xE5; 32]);
        r.register(kd.public_key()).unwrap();
        r.register(ke.public_key()).unwrap();
        let escrows = [[0xE1; 32]];
        // C never heartbeated → unhealthy at slot 1000: B claims.
        r.claim(pb, pc, &escrows, 1, 1_000).unwrap();
        // D and E race past the ring capacity; every lost race appends
        // a ClaimConflict audit entry.
        for i in 0..(MAX_KEEPER_AUDIT_ENTRIES + 5) {
            let standby = if i % 2 == 0 {
                kd.public_key()
            } else {
                ke.public_key()
            };
            assert_eq!(
                r.claim(standby, pc, &escrows, i as u64 + 2, 1_000),
                Err(EscrowError::ClaimConflict)
            );
        }
        let audit = r.audit();
        assert_eq!(audit.len(), MAX_KEEPER_AUDIT_ENTRIES);
        // 1 takeover + 69 conflicts = 70 entries; the first 6 evicted
        // (the takeover at=1 and conflicts at=2..=6), so the oldest
        // surviving entry is the conflict at=7.
        assert_eq!(audit[0].at, 7);
        assert_eq!(audit[0].kind, HeartbeatAuditKind::ClaimConflict);
    }

    #[test]
    fn last_action_from_u8_maps_unknown_to_other() {
        assert_eq!(KeeperLastAction::from_u8(0), KeeperLastAction::Idle);
        assert_eq!(KeeperLastAction::from_u8(1), KeeperLastAction::CancelExpired);
        assert_eq!(KeeperLastAction::from_u8(2), KeeperLastAction::Claim);
        assert_eq!(KeeperLastAction::from_u8(3), KeeperLastAction::RentTopUp);
        assert_eq!(KeeperLastAction::from_u8(9), KeeperLastAction::Other);
        assert_eq!(KeeperLastAction::from_u8(255), KeeperLastAction::Other);
        assert_eq!(KeeperLastAction::Idle.as_u8(), 0);
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(EscrowError::InvalidHeartbeatConfig.code(), 231);
        assert_eq!(EscrowError::KeeperNotRegistered.code(), 232);
        assert_eq!(EscrowError::HeartbeatSignatureInvalid.code(), 233);
        assert_eq!(EscrowError::KeeperHealthy.code(), 234);
        assert_eq!(EscrowError::ClaimConflict.code(), 235);
        assert_eq!(EscrowError::InvalidClaim.code(), 236);
    }
}
