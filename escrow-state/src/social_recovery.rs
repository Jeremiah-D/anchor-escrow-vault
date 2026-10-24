//! AV-195: Social recovery — M-of-N guardian key rotation.
//!
//! The key-loss escape hatch for the initializer. At setup
//! (`Uninitialized` only) the initializer names up to
//! [`MAX_RECOVERY_GUARDIANS`] guardians, an approval threshold `M`, and
//! a timelock. If the initializer key is lost (or compromised and the
//! holder wants to move first), the recovery flow rotates the escrow's
//! initializer to a fresh authority without the old key:
//!
//! 1. **Request** — any guardian opens a recovery request naming the
//!    replacement authority (counts as their approval).
//! 2. **Approve** — guardians approve until `M` distinct approvals are
//!    recorded (approvals are never withdrawn).
//! 3. **Timelock** — once the threshold is reached, a timelock elapses.
//!    This is the original key's last chance: if the key is *not*
//!    lost, the holder vetoes. The veto is also the collusion defense —
//!    guardians cannot silently rotate a live key.
//! 4. **Execute** — anyone cranks execution once the threshold and the
//!    timelock are both satisfied; the initializer rotates with the
//!    same side effects as [`Escrow::rotate_initializer`] (the
//!    activation signature bit is cleared, the operator delegation is
//!    revoked).
//!
//! Design notes:
//!
//! - The policy lives on the `Escrow` (`recovery:
//!   Option<SocialRecovery>`, persisted like the AV-14 arbiter — see
//!   `VAULT_FIELDS`); the transitions live on `Escrow` in `lib.rs`
//!   because they mutate the initializer. This module owns config
//!   validation and the request-state machine.
//! - `Disputed` escrows cannot start or execute a recovery —
//!   arbitration is in flight and the initializer's identity is part
//!   of what the arbiter adjudicates (same exclusion as
//!   `rotate_initializer`).
//! - A vetoed or executed request is gone; a fresh request starts
//!   over. There is no request replacement while one is live —
//!   `request_recovery` on a live request is
//!   [`EscrowError::RecoveryRequestPending`], so a guardian cannot
//!   front-run another guardian's request with a different authority.
//!
//! [`Escrow::rotate_initializer`]: super::Escrow::rotate_initializer

use crate::EscrowError;

/// Maximum guardians per escrow — 8 fit one approval-bitmask byte, and
/// the whole policy stays a fixed-size `Copy` struct.
pub const MAX_RECOVERY_GUARDIANS: usize = 8;

/// Serialized length of [`RecoveryRequest`]: the 32-byte replacement
/// authority, the 1-byte approval bitmask, and the 8-byte request
/// timestamp.
pub const RECOVERY_REQUEST_LEN: usize = 32 + 1 + 8;

/// Serialized length of [`SocialRecovery`]: 8 guardian slots (32 bytes
/// each), the guardian count, the threshold, the timelock, the pending
/// discriminant, and the pending request region (zeroed when idle).
pub const SOCIAL_RECOVERY_LEN: usize =
    MAX_RECOVERY_GUARDIANS * 32 + 1 + 1 + 8 + 1 + RECOVERY_REQUEST_LEN;

/// Serialized tail length of the AV-195 recovery region in the vault
/// layout: the 1-byte `Option` discriminant + [`SOCIAL_RECOVERY_LEN`]
/// (zeroed when no policy is configured).
pub const SOCIAL_RECOVERY_TAIL_LEN: usize = 1 + SOCIAL_RECOVERY_LEN;

/// A live recovery request: the replacement authority the guardians are
/// converging on, who approved (bitmask over the guardian slots), and
/// when the request opened (the timelock origin).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryRequest {
    /// The replacement initializer the request would install.
    pub new_authority: [u8; 32],
    /// Bit `i` set once guardian slot `i` approved. Approvals are
    /// never withdrawn — a guardian who changes their mind asks the
    /// initializer to veto instead.
    pub approvals: u8,
    /// Unix seconds when the request opened (timelock origin).
    pub requested_at: u64,
}

/// The social-recovery policy bound at setup (`Uninitialized` only via
/// [`Escrow::with_social_recovery`](super::Escrow::with_social_recovery)).
/// `Copy`, heap-free, `no_std`-friendly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocialRecovery {
    guardians: [[u8; 32]; MAX_RECOVERY_GUARDIANS],
    guardian_count: u8,
    threshold: u8,
    timelock_secs: u64,
    pending: Option<RecoveryRequest>,
}

impl SocialRecovery {
    /// Build the policy, validating the guardian set fail-closed:
    /// non-empty, at most [`MAX_RECOVERY_GUARDIANS`], threshold in
    /// `1..=count`, no zero keys, no duplicates. A zero timelock is
    /// allowed (the veto window is then only the approval latency —
    /// the initializer opted out of the delay deliberately).
    pub fn new(
        guardians: &[[u8; 32]],
        threshold: u8,
        timelock_secs: u64,
    ) -> Result<Self, EscrowError> {
        if guardians.is_empty() || guardians.len() > MAX_RECOVERY_GUARDIANS {
            return Err(EscrowError::InvalidSocialRecovery);
        }
        if threshold == 0 || threshold as usize > guardians.len() {
            return Err(EscrowError::InvalidSocialRecovery);
        }
        let mut slots = [[0u8; 32]; MAX_RECOVERY_GUARDIANS];
        for (i, g) in guardians.iter().enumerate() {
            if *g == [0u8; 32] {
                return Err(EscrowError::InvalidSocialRecovery);
            }
            // Duplicate scan over the slots filled so far.
            for taken in slots.iter().take(i) {
                if taken == g {
                    return Err(EscrowError::InvalidSocialRecovery);
                }
            }
            slots[i] = *g;
        }
        Ok(Self {
            guardians: slots,
            guardian_count: guardians.len() as u8,
            threshold,
            timelock_secs,
            pending: None,
        })
    }

    /// Reconstruct from decoded parts (the vault-account decoder in
    /// `discriminator.rs`). Validates exactly like [`SocialRecovery::new`];
    /// the pending request is restored verbatim (it was recorded by
    /// `open_request`), with its own structural checks: a non-zero
    /// replacement authority and no approval bit outside the guardian
    /// slots.
    pub(crate) fn from_parts(
        guardians: &[[u8; 32]],
        threshold: u8,
        timelock_secs: u64,
        pending: Option<RecoveryRequest>,
    ) -> Result<Self, EscrowError> {
        let mut policy = Self::new(guardians, threshold, timelock_secs)?;
        if let Some(req) = &pending {
            if req.new_authority == [0u8; 32] {
                return Err(EscrowError::InvalidSocialRecovery);
            }
            // No approval bit outside the guardian slots (the count is
            // validated by `new` above, so the shift cannot overflow).
            let live_mask: u8 = if policy.guardian_count >= MAX_RECOVERY_GUARDIANS as u8 {
                0xFF
            } else {
                (1u8 << policy.guardian_count) - 1
            };
            if req.approvals & !live_mask != 0 {
                return Err(EscrowError::InvalidSocialRecovery);
            }
        }
        policy.pending = pending;
        Ok(policy)
    }

    /// The registered guardians, in slot order.
    pub fn guardians(&self) -> &[[u8; 32]] {
        &self.guardians[..self.guardian_count as usize]
    }

    /// How many guardians are registered.
    pub fn guardian_count(&self) -> u8 {
        self.guardian_count
    }

    /// Approvals required to arm the timelock.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Seconds between threshold-reached and execution.
    pub fn timelock_secs(&self) -> u64 {
        self.timelock_secs
    }

    /// The live request, if any.
    pub fn pending(&self) -> Option<RecoveryRequest> {
        self.pending
    }

    /// Slot index of a guardian, or `None`.
    pub fn guardian_index(&self, key: [u8; 32]) -> Option<usize> {
        self.guardians()
            .iter()
            .position(|g| *g == key)
    }

    /// True for a registered guardian.
    pub fn is_guardian(&self, key: [u8; 32]) -> bool {
        self.guardian_index(key).is_some()
    }

    /// Distinct approvals recorded on the live request (0 when idle).
    pub fn approval_count(&self) -> u32 {
        self.pending.map(|r| r.approvals.count_ones()).unwrap_or(0)
    }

    /// Open a recovery request. The requesting guardian's approval is
    /// recorded immediately. Fails when the caller is not a guardian,
    /// a request is already live, or the replacement authority is the
    /// zero address.
    pub fn open_request(
        &mut self,
        guardian: [u8; 32],
        new_authority: [u8; 32],
        now: u64,
    ) -> Result<(), EscrowError> {
        let idx = self
            .guardian_index(guardian)
            .ok_or(EscrowError::RecoveryNotGuardian)?;
        if self.pending.is_some() {
            return Err(EscrowError::RecoveryRequestPending);
        }
        if new_authority == [0u8; 32] {
            return Err(EscrowError::InvalidSocialRecovery);
        }
        self.pending = Some(RecoveryRequest {
            new_authority,
            approvals: 1u8 << idx,
            requested_at: now,
        });
        Ok(())
    }

    /// Record a guardian's approval on the live request. Returns `true`
    /// when this approval is new, `false` on an idempotent re-approve
    /// (the bit is already set — approving twice is a no-op, not an
    /// error).
    pub fn approve(&mut self, guardian: [u8; 32]) -> Result<bool, EscrowError> {
        let idx = self
            .guardian_index(guardian)
            .ok_or(EscrowError::RecoveryNotGuardian)?;
        let req = self.pending.as_mut().ok_or(EscrowError::RecoveryNoPendingRequest)?;
        let bit = 1u8 << idx;
        if req.approvals & bit != 0 {
            return Ok(false);
        }
        req.approvals |= bit;
        Ok(true)
    }

    /// Whether the live request may execute at `now`: the approval
    /// threshold is met and the timelock has elapsed. The timelock
    /// origin is the request opening (not the threshold moment), so
    /// the original key gets the full delay from first signal.
    pub fn executable(&self, now: u64) -> Result<(), EscrowError> {
        let req = self.pending.ok_or(EscrowError::RecoveryNoPendingRequest)?;
        if req.approvals.count_ones() < self.threshold as u32 {
            return Err(EscrowError::RecoveryThresholdNotReached);
        }
        if now < req.requested_at.saturating_add(self.timelock_secs) {
            return Err(EscrowError::RecoveryTimelockNotElapsed);
        }
        Ok(())
    }

    /// Take the live request for execution (clears the slot).
    pub fn take_request(&mut self) -> Option<RecoveryRequest> {
        self.pending.take()
    }

    /// Cancel the live request (the initializer's veto).
    pub fn cancel_request(&mut self) -> Result<(), EscrowError> {
        if self.pending.is_none() {
            return Err(EscrowError::RecoveryNoPendingRequest);
        }
        self.pending = None;
        Ok(())
    }
}

#[cfg(test)]
mod social_recovery_tests {
    use super::*;

    const G1: [u8; 32] = [0x11; 32];
    const G2: [u8; 32] = [0x22; 32];
    const G3: [u8; 32] = [0x33; 32];
    const NEW_KEY: [u8; 32] = [0x99; 32];
    const STRANGER: [u8; 32] = [0xCC; 32];

    fn policy() -> SocialRecovery {
        SocialRecovery::new(&[G1, G2, G3], 2, 3600).unwrap()
    }

    #[test]
    fn config_validation_is_fail_closed() {
        // Empty guardian set.
        assert_eq!(
            SocialRecovery::new(&[], 1, 0),
            Err(EscrowError::InvalidSocialRecovery)
        );
        // Over the slot ceiling.
        let many = [[0x44; 32]; MAX_RECOVERY_GUARDIANS + 1];
        assert_eq!(
            SocialRecovery::new(&many, 1, 0),
            Err(EscrowError::InvalidSocialRecovery)
        );
        // Zero threshold.
        assert_eq!(
            SocialRecovery::new(&[G1], 0, 0),
            Err(EscrowError::InvalidSocialRecovery)
        );
        // Threshold above the guardian count.
        assert_eq!(
            SocialRecovery::new(&[G1, G2], 3, 0),
            Err(EscrowError::InvalidSocialRecovery)
        );
        // Zero guardian key.
        assert_eq!(
            SocialRecovery::new(&[G1, [0u8; 32]], 1, 0),
            Err(EscrowError::InvalidSocialRecovery)
        );
        // Duplicate guardian.
        assert_eq!(
            SocialRecovery::new(&[G1, G2, G1], 2, 0),
            Err(EscrowError::InvalidSocialRecovery)
        );
        // Boundary-valid: 1-of-1 and 8-of-8.
        let eight = [[0x44; 32], [0x45; 32], [0x46; 32], [0x47; 32], [0x48; 32], [0x49; 32], [0x4A; 32], [0x4B; 32]];
        assert!(SocialRecovery::new(&[G1], 1, 0).is_ok());
        assert!(SocialRecovery::new(&eight, 8, 0).is_ok());
    }

    #[test]
    fn serialized_length_is_pinned() {
        // 8 guardian slots + count + threshold + timelock + pending
        // discriminant + the pending request region.
        assert_eq!(RECOVERY_REQUEST_LEN, 41);
        assert_eq!(SOCIAL_RECOVERY_LEN, 256 + 1 + 1 + 8 + 1 + 41);
        assert_eq!(SOCIAL_RECOVERY_LEN, 308);
    }

    #[test]
    fn open_request_records_first_approval() {
        let mut p = policy();
        p.open_request(G1, NEW_KEY, 1_000).unwrap();
        let req = p.pending().unwrap();
        assert_eq!(req.new_authority, NEW_KEY);
        assert_eq!(req.approvals.count_ones(), 1);
        assert_eq!(req.requested_at, 1_000);
        assert_eq!(p.approval_count(), 1);
    }

    #[test]
    fn open_request_rejects_stranger_and_zero_authority() {
        let mut p = policy();
        assert_eq!(
            p.open_request(STRANGER, NEW_KEY, 1_000),
            Err(EscrowError::RecoveryNotGuardian)
        );
        assert!(p.pending().is_none());
        assert_eq!(
            p.open_request(G1, [0u8; 32], 1_000),
            Err(EscrowError::InvalidSocialRecovery)
        );
        assert!(p.pending().is_none());
    }

    #[test]
    fn second_request_while_live_is_rejected() {
        let mut p = policy();
        p.open_request(G1, NEW_KEY, 1_000).unwrap();
        // Another guardian cannot front-run with a different authority.
        assert_eq!(
            p.open_request(G2, STRANGER, 1_001),
            Err(EscrowError::RecoveryRequestPending)
        );
        // The live request is untouched.
        assert_eq!(p.pending().unwrap().new_authority, NEW_KEY);
    }

    #[test]
    fn approve_is_idempotent_for_repeats() {
        let mut p = policy();
        assert_eq!(
            p.approve(G1),
            Err(EscrowError::RecoveryNoPendingRequest)
        );
        p.open_request(G1, NEW_KEY, 1_000).unwrap();
        // G1 already approved via open_request: re-approve is a no-op.
        assert_eq!(p.approve(G1), Ok(false));
        assert_eq!(p.approval_count(), 1);
        // A stranger cannot approve.
        assert_eq!(
            p.approve(STRANGER),
            Err(EscrowError::RecoveryNotGuardian)
        );
        // G2's approval is new and counts.
        assert_eq!(p.approve(G2), Ok(true));
        assert_eq!(p.approval_count(), 2);
    }

    #[test]
    fn executable_gates_threshold_then_timelock() {
        let mut p = policy();
        p.open_request(G1, NEW_KEY, 1_000).unwrap();
        // 1 of 2 approvals: threshold not reached, even past the timelock.
        assert_eq!(
            p.executable(1_000 + 3_600 + 1),
            Err(EscrowError::RecoveryThresholdNotReached)
        );
        p.approve(G2).unwrap();
        // Threshold met, timelock not elapsed (exactly at the edge).
        assert_eq!(
            p.executable(1_000 + 3_600 - 1),
            Err(EscrowError::RecoveryTimelockNotElapsed)
        );
        // Timelock inclusive at the boundary.
        assert!(p.executable(1_000 + 3_600).is_ok());
        // Nothing pending: not executable.
        let q = policy();
        assert_eq!(
            q.executable(u64::MAX),
            Err(EscrowError::RecoveryNoPendingRequest)
        );
    }

    #[test]
    fn veto_cancels_and_frees_a_fresh_request() {
        let mut p = policy();
        p.open_request(G1, NEW_KEY, 1_000).unwrap();
        p.cancel_request().unwrap();
        assert!(p.pending().is_none());
        assert_eq!(p.approval_count(), 0);
        // A fresh request starts clean — no stale approvals.
        p.open_request(G2, STRANGER, 2_000).unwrap();
        assert_eq!(p.approval_count(), 1);
        assert_eq!(p.pending().unwrap().new_authority, STRANGER);
        // Veto with nothing pending.
        p.cancel_request().unwrap();
        assert_eq!(
            p.cancel_request(),
            Err(EscrowError::RecoveryNoPendingRequest)
        );
    }

    #[test]
    fn take_request_consumes_for_execution() {
        let mut p = policy();
        p.open_request(G1, NEW_KEY, 1_000).unwrap();
        p.approve(G2).unwrap();
        let req = p.take_request().unwrap();
        assert_eq!(req.new_authority, NEW_KEY);
        assert!(p.pending().is_none());
        assert!(p.take_request().is_none());
    }

    #[test]
    fn error_codes_pinned() {
        // Never renumber: the Anchor layer assigns one program error
        // per variant and off-chain clients match on these numbers.
        assert_eq!(EscrowError::InvalidSocialRecovery.code(), 286);
        assert_eq!(EscrowError::RecoveryNotConfigured.code(), 287);
        assert_eq!(EscrowError::RecoveryNotGuardian.code(), 288);
        assert_eq!(EscrowError::RecoveryRequestPending.code(), 289);
        assert_eq!(EscrowError::RecoveryNoPendingRequest.code(), 290);
        assert_eq!(EscrowError::RecoveryThresholdNotReached.code(), 291);
        assert_eq!(EscrowError::RecoveryTimelockNotElapsed.code(), 292);
        for e in [
            EscrowError::InvalidSocialRecovery,
            EscrowError::RecoveryNotConfigured,
            EscrowError::RecoveryNotGuardian,
            EscrowError::RecoveryRequestPending,
            EscrowError::RecoveryNoPendingRequest,
            EscrowError::RecoveryThresholdNotReached,
            EscrowError::RecoveryTimelockNotElapsed,
        ] {
            assert!(EscrowError::all().contains(&e));
        }
        // AV-195 appends 7 social-recovery errors after AV-194's
        // BidDepositBookFull (285); AV-196 appends 6 jury-sortition
        // errors after those.
        assert_eq!(EscrowError::all().len(), 220); // AV-195: +7 social-recovery errors, AV-196: +6 jury-sortition errors, AV-197: +5 payment-channel errors; AV-209: +4
    }
}
