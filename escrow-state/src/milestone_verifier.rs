//! Milestone release verifier attestation (AV-210).
//!
//! `release_milestone` currently trusts only internal confirmation:
//! both parties confirmed the milestone, so the initializer may
//! release it. That is fine for a bilateral deal, but a milestone
//! that represents third-party acceptance — a build delivered, an
//! audit passed, a shipment inspected — needs an outside voice that
//! neither party can forge. This module adds that voice as an
//! opt-in gate, orthogonal to the two existing milestone controls:
//!
//! - AV-101 keeper reporting signs *reports* about the escrow but
//!   never gates a release — a signed report is evidence, not
//!   permission;
//! - AV-203 taker delivery confirmation is the *taker's own*
//!   receipt — the counterparty to the release, not an independent
//!   verifier.
//!
//! The gate has two halves. The escrow half is one stored pubkey,
//! [`Escrow::milestone_verifier`], bound `Uninitialized`-only via
//! [`Escrow::with_milestone_verifier`] (the zero key is the unbound
//! sentinel, so binding it is rejected — a gate bound to nobody
//! would be a gate that never opens). Once bound, the plain
//! [`Escrow::release_milestone`] path refuses with
//! [`EscrowError::MilestoneVerifierRequired`]: the dual-control
//! precedent (a direct `release` on a dual-control escrow is
//! `DualControlRequired`) — the gated path cannot be bypassed by
//! simply not mentioning the verifier. The release then goes
//! through [`Escrow::release_milestone_verified`], which checks one
//! attestation and delegates to the same settlement code, so the
//! fee, cap, timelock, quorum and late-penalty gates all still run.
//!
//! The attestation half is one Ed25519 signature (RFC 8032, the
//! crate's hand-rolled verifier — no new dependency) over a
//! domain-separated message that binds exactly the four things the
//! backlog item names:
//!
//! ```text
//! message = "escrow-milestone-verifier/v1" || vault || index || tranche_hash || expires_at
//! ```
//!
//! - `vault`: the vault account key, supplied by the caller — on
//!   chain this is the account's own key, never a field the escrow
//!   could be tricked into misreporting, so an attestation minted
//!   for one vault cannot settle another vault's milestone even
//!   when the tranches match;
//! - `index`: the milestone ordinal (u64 little-endian), so an
//!   attestation for milestone 0 cannot release milestone 1;
//! - `tranche_hash`: [`milestone_tranche_hash`], the SHA-256 of the
//!   deal terms for that tranche (`vault || index || amount`), so
//!   the verifier signs terms, not just an ordinal — the gate
//!   recomputes the hash from the live plan amount, so an
//!   attestation minted for a rewritten tranche fails the hash
//!   check even with a valid signature;
//! - `expires_at`: the attestation's own deadline. A release at
//!   `now > expires_at` is [`EscrowError::MilestoneAttestationExpired`];
//!   a release exactly at `expires_at` is still valid, the AV-206
//!   deadline convention (a deadline that punishes the compliant
//!   release is not a deadline).
//!
//! Check order inside [`verify_milestone_attestation`] is
//! deliberate: expiry first (a stale attestation is stale whatever
//! it says), then the three bindings (vault, index, tranche hash —
//! all cheap comparisons, and each reported as the same
//! [`EscrowError::MilestoneAttestationInvalid`] so a prober learns
//! nothing about which binding failed), then the signature. The
//! signature is the last check, not the first, because a signature
//! that verifies over the wrong terms proves nothing.
//!
//! Replay: an attestation authorizes exactly one release. Releases
//! are strictly in-order and each tranche settles at most once
//! (the released bit), so a replayed attestation for an already
//! settled milestone can never settle a second tranche — and
//! [`Escrow::release_milestone_verified`] makes that explicit by
//! checking the released bit first and reporting
//! [`EscrowError::MilestoneAttestationReplay`] instead of letting
//! the replay fall through to the generic out-of-order error. The
//! attestation itself carries no nonce: with the vault, index and
//! tranche hash all bound, there is no second release the same
//! attestation could ever authorize, so a nonce would be a field
//! with no failure mode to prevent.
//!
//! What this module deliberately does *not* do: the Anchor
//! instruction that accepts the attestation on chain (the program
//! side passes the vault account key and the attestation bytes
//! through to `release_milestone_verified`) is follow-up work,
//! like the AV-206/AV-208 program-side notes — the pure-logic gate
//! here is complete and tested, and the README states the boundary
//! rather than claiming an instruction that does not exist yet.

use crate::ed25519::{verify as ed25519_verify, SigningKey};
use crate::{sha256, EscrowError};

/// Domain separator for the verifier attestation message. Versioned
/// so a future message format cannot be mistaken for this one.
pub const MILESTONE_VERIFIER_DOMAIN: &[u8] = b"escrow-milestone-verifier/v1";

/// Domain separator for the tranche hash: the hash binds deal
/// terms, so it gets its own domain rather than reusing the
/// attestation message domain.
pub const MILESTONE_TRANCHE_HASH_DOMAIN: &[u8] = b"escrow-milestone-tranche/v1";

/// The zero key: the `milestone_verifier` field's unbound sentinel.
/// A verifier-bound escrow never stores this value (the builder
/// rejects it), so "stored key is zero" reads unambiguously as
/// "no verifier gate configured".
pub const UNBOUND_MILESTONE_VERIFIER: [u8; 32] = [0u8; 32];

/// One third-party attestation for one milestone release.
///
/// `vault`, `milestone_index` and `tranche_hash` are the bindings
/// the gate rechecks against live state; `expires_at` is the
/// attestation's own deadline; `signature` is the verifier's
/// Ed25519 signature over [`attestation_message`] of these fields.
/// The struct carries no nonce, by design — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MilestoneAttestation {
    /// The vault account key this attestation was minted for.
    pub vault: [u8; 32],
    /// The milestone ordinal this attestation authorizes.
    pub milestone_index: u64,
    /// [`milestone_tranche_hash`] of the tranche's deal terms.
    pub tranche_hash: [u8; 32],
    /// Unix timestamp: valid through this instant, expired after.
    pub expires_at: u64,
    /// The verifier's Ed25519 signature over the message.
    pub signature: [u8; 64],
}

/// The tranche hash (AV-210): `SHA-256(domain || vault || index ||
/// amount)`. The verifier computes this off chain from the deal
/// terms and signs it; the gate recomputes it from the live plan
/// amount, so the signature covers the terms, not just an ordinal.
/// A tranche rewritten after attestation (AV-70 / AV-155 amount
/// rewrites) invalidates outstanding attestations — the verifier
/// must re-attest the new terms, which is the point: a signature
/// over stale terms must never settle new terms.
pub fn milestone_tranche_hash(vault: [u8; 32], index: u64, amount: u64) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(
        MILESTONE_TRANCHE_HASH_DOMAIN.len() + 32 + 8 + 8,
    );
    bytes.extend_from_slice(MILESTONE_TRANCHE_HASH_DOMAIN);
    bytes.extend_from_slice(&vault);
    bytes.extend_from_slice(&index.to_le_bytes());
    bytes.extend_from_slice(&amount.to_le_bytes());
    sha256(&bytes)
}

/// The canonical attestation message: `domain || vault || index ||
/// tranche_hash || expires_at`, all integers little-endian. The
/// verifier signs exactly these bytes; anything else the verifier
/// signed is not an attestation for this gate.
pub fn attestation_message(attestation: &MilestoneAttestation) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        MILESTONE_VERIFIER_DOMAIN.len() + 32 + 8 + 32 + 8,
    );
    bytes.extend_from_slice(MILESTONE_VERIFIER_DOMAIN);
    bytes.extend_from_slice(&attestation.vault);
    bytes.extend_from_slice(&attestation.milestone_index.to_le_bytes());
    bytes.extend_from_slice(&attestation.tranche_hash);
    bytes.extend_from_slice(&attestation.expires_at.to_le_bytes());
    bytes
}

/// Verify one attestation (AV-210) against the expected bindings.
/// `verifier` is the pubkey stored on the escrow, `vault` the vault
/// account key, `milestone_index` the milestone being released,
/// `expected_tranche_hash` the gate-recomputed deal-terms hash, and
/// `now` the release time. Expiry first, bindings second, signature
/// last — see the module docs for why that order. Returns `Ok`
/// only when every check passes; every failure is one of the
/// `MilestoneAttestation*` errors, never a panic.
pub fn verify_milestone_attestation(
    verifier: [u8; 32],
    vault: [u8; 32],
    milestone_index: u64,
    expected_tranche_hash: [u8; 32],
    attestation: &MilestoneAttestation,
    now: u64,
) -> Result<(), EscrowError> {
    // Expiry first: a stale attestation is stale whatever it says.
    if now > attestation.expires_at {
        return Err(EscrowError::MilestoneAttestationExpired);
    }
    // Bindings second: vault, index, tranche hash — each mismatch
    // is the same error, so a prober learns nothing about which
    // binding failed.
    if attestation.vault != vault
        || attestation.milestone_index != milestone_index
        || attestation.tranche_hash != expected_tranche_hash
    {
        return Err(EscrowError::MilestoneAttestationInvalid);
    }
    // Signature last: a signature over the wrong terms proves
    // nothing, so it is only meaningful once the bindings match.
    if !ed25519_verify(&verifier, &attestation_message(attestation), &attestation.signature)
    {
        return Err(EscrowError::MilestoneAttestationInvalid);
    }
    Ok(())
}

/// Sign one attestation with the verifier's key (AV-210). This is
/// the off-chain / test-side constructor: the verifier builds the
/// attestation struct, signs its canonical message, and hands the
/// signed struct to the release caller. The on-chain gate never
/// calls this — it only verifies.
pub fn sign_milestone_attestation(
    signing_key: &SigningKey,
    vault: [u8; 32],
    milestone_index: u64,
    tranche_hash: [u8; 32],
    expires_at: u64,
) -> MilestoneAttestation {
    let mut attestation = MilestoneAttestation {
        vault,
        milestone_index,
        tranche_hash,
        expires_at,
        signature: [0u8; 64],
    };
    attestation.signature = signing_key.sign(&attestation_message(&attestation));
    attestation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Escrow, EscrowState, MilestonePlan};

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const VAULT: [u8; 32] = [0x11; 32];
    const NOW: u64 = 1_750_000_000;
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn verifier_key() -> SigningKey {
        SigningKey::from_seed([0x77; 32])
    }

    fn valid_attestation() -> (SigningKey, MilestoneAttestation) {
        let key = verifier_key();
        let hash = milestone_tranche_hash(VAULT, 0, 400_000);
        let attestation =
            sign_milestone_attestation(&key, VAULT, 0, hash, EXPIRES_AT);
        (key, attestation)
    }

    fn verified_escrow() -> Escrow {
        let plan = MilestonePlan::new(&[400_000, 600_000]).unwrap();
        let key = verifier_key();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan)
            .unwrap()
            .with_milestone_verifier(key.public_key())
            .unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        e
    }

    #[test]
    fn tranche_hash_binds_vault_index_and_amount() {
        let base = milestone_tranche_hash(VAULT, 0, 400_000);
        assert_ne!(base, milestone_tranche_hash([0x12; 32], 0, 400_000));
        assert_ne!(base, milestone_tranche_hash(VAULT, 1, 400_000));
        assert_ne!(base, milestone_tranche_hash(VAULT, 0, 400_001));
        assert_eq!(base, milestone_tranche_hash(VAULT, 0, 400_000));
    }

    #[test]
    fn attestation_verifies_and_rejects_each_failure_shape() {
        let (key, attestation) = valid_attestation();
        let verifier = key.public_key();
        let hash = milestone_tranche_hash(VAULT, 0, 400_000);
        assert_eq!(
            verify_milestone_attestation(
                verifier,
                VAULT,
                0,
                hash,
                &attestation,
                NOW
            ),
            Ok(())
        );
        // Valid exactly at the deadline, expired one second past it.
        assert_eq!(
            verify_milestone_attestation(
                verifier,
                VAULT,
                0,
                hash,
                &attestation,
                EXPIRES_AT
            ),
            Ok(())
        );
        assert_eq!(
            verify_milestone_attestation(
                verifier,
                VAULT,
                0,
                hash,
                &attestation,
                EXPIRES_AT + 1
            ),
            Err(EscrowError::MilestoneAttestationExpired)
        );
        // Each binding mismatch is the same error.
        let mut wrong_vault = attestation;
        wrong_vault.vault = [0x12; 32];
        assert_eq!(
            verify_milestone_attestation(
                verifier,
                VAULT,
                0,
                hash,
                &wrong_vault,
                NOW
            ),
            Err(EscrowError::MilestoneAttestationInvalid)
        );
        let mut wrong_index = attestation;
        wrong_index.milestone_index = 1;
        assert_eq!(
            verify_milestone_attestation(
                verifier,
                VAULT,
                0,
                hash,
                &wrong_index,
                NOW
            ),
            Err(EscrowError::MilestoneAttestationInvalid)
        );
        assert_eq!(
            verify_milestone_attestation(
                verifier,
                VAULT,
                0,
                milestone_tranche_hash(VAULT, 0, 400_001),
                &attestation,
                NOW
            ),
            Err(EscrowError::MilestoneAttestationInvalid)
        );
        // A valid signature from a different verifier proves nothing.
        let stranger = SigningKey::from_seed([0x99; 32]);
        let stranger_attestation = sign_milestone_attestation(
            &stranger,
            VAULT,
            0,
            hash,
            EXPIRES_AT,
        );
        assert_eq!(
            verify_milestone_attestation(
                verifier,
                VAULT,
                0,
                hash,
                &stranger_attestation,
                NOW
            ),
            Err(EscrowError::MilestoneAttestationInvalid)
        );
        // A tampered signature fails even with matching bindings.
        let mut tampered = attestation;
        tampered.signature[0] ^= 0x01;
        assert_eq!(
            verify_milestone_attestation(
                verifier,
                VAULT,
                0,
                hash,
                &tampered,
                NOW
            ),
            Err(EscrowError::MilestoneAttestationInvalid)
        );
    }

    #[test]
    fn plain_release_refuses_verifier_bound_escrow() {
        let mut e = verified_escrow();
        assert_eq!(
            e.release_milestone(ALICE, NOW, 0, None, BOB),
            Err(EscrowError::MilestoneVerifierRequired)
        );
        assert_eq!(e.released_amount(), 0, "a refused release moves nothing");
    }

    #[test]
    fn verified_release_settles_and_replay_is_explicit() {
        let key = verifier_key();
        let mut e = verified_escrow();
        let hash = milestone_tranche_hash(VAULT, 0, 400_000);
        let attestation =
            sign_milestone_attestation(&key, VAULT, 0, hash, EXPIRES_AT);
        let (payout, fee) = e
            .release_milestone_verified(ALICE, NOW, 0, None, BOB, VAULT, &attestation)
            .unwrap();
        assert_eq!((payout, fee), (400_000, 0));
        assert_eq!(e.released_amount(), 400_000);
        // Same attestation again: the tranche is settled, so the
        // replay is explicit, not a generic out-of-order error.
        assert_eq!(
            e.release_milestone_verified(ALICE, NOW, 0, None, BOB, VAULT, &attestation),
            Err(EscrowError::MilestoneAttestationReplay)
        );
        assert_eq!(e.released_amount(), 400_000, "a replay settles nothing twice");
    }

    #[test]
    fn verified_release_rejects_bad_attestation_without_settling() {
        let key = verifier_key();
        let mut e = verified_escrow();
        // Expired attestation.
        let hash = milestone_tranche_hash(VAULT, 0, 400_000);
        let stale = sign_milestone_attestation(&key, VAULT, 0, hash, NOW - 1);
        assert_eq!(
            e.release_milestone_verified(ALICE, NOW, 0, None, BOB, VAULT, &stale),
            Err(EscrowError::MilestoneAttestationExpired)
        );
        // Attestation minted for a different vault.
        let foreign =
            sign_milestone_attestation(&key, [0x12; 32], 0, hash, EXPIRES_AT);
        assert_eq!(
            e.release_milestone_verified(ALICE, NOW, 0, None, BOB, VAULT, &foreign),
            Err(EscrowError::MilestoneAttestationInvalid)
        );
        // Attestation minted for rewritten terms.
        let stale_terms = sign_milestone_attestation(
            &key,
            VAULT,
            0,
            milestone_tranche_hash(VAULT, 0, 400_001),
            EXPIRES_AT,
        );
        assert_eq!(
            e.release_milestone_verified(ALICE, NOW, 0, None, BOB, VAULT, &stale_terms),
            Err(EscrowError::MilestoneAttestationInvalid)
        );
        assert_eq!(e.released_amount(), 0, "no failed attestation settles");
    }

    #[test]
    fn verified_path_on_unbound_escrow_and_bad_binding() {
        let plan = MilestonePlan::new(&[400_000, 600_000]).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan)
            .unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        let (_, attestation) = valid_attestation();
        assert_eq!(
            e.release_milestone_verified(ALICE, NOW, 0, None, BOB, VAULT, &attestation),
            Err(EscrowError::MilestoneVerifierNotBound)
        );
        // Binding the zero key is rejected: zero is the unbound
        // sentinel, so binding it would be a gate that never opens.
        let e2 = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap());
        assert_eq!(
            e2.and_then(|esc| esc.with_milestone_verifier([0u8; 32])),
            Err(EscrowError::InvalidMilestoneVerifier)
        );
        // Binding after funding is a state transition error, like
        // every other Uninitialized-only builder.
        assert_eq!(
            e.with_milestone_verifier(verifier_key().public_key()),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn unbound_escrow_release_is_unchanged() {
        let plan = MilestonePlan::new(&[400_000, 600_000]).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan)
            .unwrap();
        assert_eq!(e.milestone_verifier(), [0u8; 32]);
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        let (payout, _) = e.release_milestone(ALICE, NOW, 0, None, BOB).unwrap();
        assert_eq!(payout, 400_000);
    }
}
