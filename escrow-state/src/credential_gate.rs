//! Credential-gated release (AV-212).
//!
//! `release` currently trusts only internal authority: the
//! initializer (or their RELEASE-scoped operator) may release, and
//! the payout destination is pinned by the allowlist. That is fine
//! for a bilateral deal, but a release that must only reach a
//! compliance-cleared taker — a KYC'd counterparty, a licensed
//! custodian, a sanctions-screened recipient — needs an outside
//! voice that neither party can forge: the issuer's credential.
//! This module adds that voice as an opt-in gate, orthogonal to
//! the three existing release gates it is most often confused
//! with:
//!
//! - AV-210 milestone verifier attestation is a third party
//!   attesting a *delivery fact* (a milestone's terms were met) —
//!   the credential here attests the *taker's identity and
//!   compliance qualification*, a different subject, minted by a
//!   different issuer, for a full release rather than one tranche;
//! - AV-113/AV-128 price gates look at an oracle *price* — this
//!   gate looks at an issuer *identity credential*, never a price;
//! - AV-104 delegation is an *operation-right* grant (who may call
//!   release) — this gate is a *release-qualification* check (who
//!   may receive it), and it runs after authority, so a delegated
//!   operator still cannot release to an uncredentialed taker.
//!
//! The gate has two halves. The escrow half is one stored pubkey,
//! [`Escrow::credential_issuer`], bound `Uninitialized`-only via
//! [`Escrow::with_credential_gate`] (the zero key is the unbound
//! sentinel, so binding it is rejected — a gate bound to nobody
//! would be a gate that never opens). Once bound, the plain
//! [`Escrow::release`] path refuses with
//! [`EscrowError::CredentialGateRequired`]: the dual-control
//! precedent (a direct `release` on a dual-control escrow is
//! `DualControlRequired`) — the gated path cannot be bypassed by
//! simply not mentioning the credential. The release then goes
//! through [`Escrow::release_with_credential`], which checks one
//! credential and delegates to the same settlement code, so the
//! fee, cap, timelock, quorum and payout-allowlist gates all still
//! run.
//!
//! The credential half is one Ed25519 signature (RFC 8032, the
//! crate's hand-rolled verifier — no new dependency) over a
//! domain-separated message that binds exactly the two things the
//! backlog item names, plus the issuer's revocation verdict:
//!
//! ```text
//! message = "escrow-credential-gate/v1" || taker || expires_at
//! ```
//!
//! - `taker`: the taker this credential qualifies. The gate
//!   rechecks it against the escrow's own taker, so a credential
//!   minted for another taker cannot settle this escrow's release
//!   even when the caller is the initializer;
//! - `expires_at`: the credential's own deadline. A release at
//!   `now > expires_at` is [`EscrowError::CredentialExpired`];
//!   a release exactly at `expires_at` is still valid, the AV-206
//!   deadline convention (a deadline that punishes the compliant
//!   release is not a deadline);
//! - revocation: the issuer's revocation state is not a field on
//!   the credential — a credential that carried its own "not
//!   revoked" flag would be a claim the holder asserts about
//!   themselves. Instead [`verify_release_credential`] takes a
//!   revocation query, `&dyn Fn(&ReleaseCredential) -> bool`, the
//!   pure-logic stand-in for the issuer's revocation registry
//!   lookup (on chain, the program passes its registry check here).
//!   A revoked credential is [`EscrowError::CredentialRevoked`]
//!   whatever its signature says.
//!
//! Check order inside [`verify_release_credential`] is
//! deliberate: expiry first (a stale credential is stale whatever
//! it says), revocation second (a revoked credential is revoked
//! whatever it says), then the taker binding and the signature —
//! both reported as the same [`EscrowError::CredentialInvalid`]
//! so a prober learns nothing about which of the two failed. The
//! signature is the last check, not the first, because a signature
//! that verifies over the wrong taker proves nothing.
//!
//! Replay: a credential authorizes a release, and a full release
//! is terminal — the escrow settles at most once — so a replayed
//! credential for an already-settled escrow can never settle a
//! second release; the second call fails the state check, not a
//! dedicated replay error. The credential itself carries no nonce:
//! with the taker bound and the release terminal, there is no
//! second release the same credential could ever authorize, so a
//! nonce would be a field with no failure mode to prevent.
//!
//! What this module deliberately does *not* do: the Anchor
//! instruction that accepts the credential on chain (the program
//! side passes the revocation-registry verdict through to
//! `release_with_credential`) is follow-up work, like the AV-206 /
//! AV-208 / AV-210 program-side notes — the pure-logic gate here
//! is complete and tested, and the README states the boundary
//! rather than claiming an instruction that does not exist yet.

use crate::ed25519::{verify as ed25519_verify, SigningKey};
use crate::EscrowError;

/// Domain separator for the credential message. Versioned so a
/// future message format cannot be mistaken for this one.
pub const CREDENTIAL_GATE_DOMAIN: &[u8] = b"escrow-credential-gate/v1";

/// The zero key: the `credential_issuer` field's unbound sentinel.
/// A credential-gated escrow never stores this value (the builder
/// rejects it), so "stored key is zero" reads unambiguously as
/// "no credential gate configured".
pub const UNBOUND_CREDENTIAL_ISSUER: [u8; 32] = [0u8; 32];

/// One issuer credential qualifying one taker for release.
///
/// `taker` is the taker this credential qualifies;
/// `expires_at` is the credential's own deadline;
/// `signature` is the issuer's Ed25519 signature over
/// [`credential_message`] of these fields. The struct carries no
/// revocation flag, by design — revocation is the issuer's
/// verdict, queried through the callback in
/// [`verify_release_credential`], never asserted by the holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseCredential {
    /// The taker this credential qualifies for release.
    pub taker: [u8; 32],
    /// Unix timestamp: valid through this instant, expired after.
    pub expires_at: u64,
    /// The issuer's Ed25519 signature over the message.
    pub signature: [u8; 64],
}

/// The canonical credential message: `domain || taker ||
/// expires_at`, the expiry little-endian. The issuer signs exactly
/// these bytes; anything else the issuer signed is not a
/// credential for this gate.
pub fn credential_message(credential: &ReleaseCredential) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CREDENTIAL_GATE_DOMAIN.len() + 32 + 8);
    bytes.extend_from_slice(CREDENTIAL_GATE_DOMAIN);
    bytes.extend_from_slice(&credential.taker);
    bytes.extend_from_slice(&credential.expires_at.to_le_bytes());
    bytes
}

/// Verify one credential (AV-212) against the expected taker.
/// `issuer` is the pubkey stored on the escrow, `expected_taker`
/// the escrow's own taker, `now` the release time, and
/// `is_revoked` the issuer's revocation query — `true` when the
/// issuer reports this credential revoked. Expiry first,
/// revocation second, binding and signature last — see the module
/// docs for why that order. Returns `Ok` only when every check
/// passes; every failure is one of the `Credential*` errors,
/// never a panic.
pub fn verify_release_credential(
    issuer: [u8; 32],
    expected_taker: [u8; 32],
    credential: &ReleaseCredential,
    now: u64,
    is_revoked: &dyn Fn(&ReleaseCredential) -> bool,
) -> Result<(), EscrowError> {
    // Expiry first: a stale credential is stale whatever it says.
    if now > credential.expires_at {
        return Err(EscrowError::CredentialExpired);
    }
    // Revocation second: a revoked credential is revoked whatever
    // its signature says — and the verdict comes from the issuer's
    // registry, never from a flag the holder could set.
    if is_revoked(credential) {
        return Err(EscrowError::CredentialRevoked);
    }
    // Binding third: the credential must name this escrow's taker.
    if credential.taker != expected_taker {
        return Err(EscrowError::CredentialInvalid);
    }
    // Signature last: a signature over the wrong taker proves
    // nothing, so it is only meaningful once the binding matches.
    if !ed25519_verify(&issuer, &credential_message(credential), &credential.signature)
    {
        return Err(EscrowError::CredentialInvalid);
    }
    Ok(())
}

/// Sign one credential with the issuer's key (AV-212). This is
/// the off-chain / test-side constructor: the issuer builds the
/// credential struct, signs its canonical message, and hands the
/// signed struct to the release caller. The on-chain gate never
/// calls this — it only verifies.
pub fn sign_release_credential(
    signing_key: &SigningKey,
    taker: [u8; 32],
    expires_at: u64,
) -> ReleaseCredential {
    let mut credential = ReleaseCredential {
        taker,
        expires_at,
        signature: [0u8; 64],
    };
    credential.signature = signing_key.sign(&credential_message(&credential));
    credential
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Escrow, EscrowState};

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const NOW: u64 = 1_750_000_000;
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn issuer_key() -> SigningKey {
        SigningKey::from_seed([0x77; 32])
    }

    fn not_revoked(_: &ReleaseCredential) -> bool {
        false
    }

    fn valid_credential() -> (SigningKey, ReleaseCredential) {
        let key = issuer_key();
        let credential = sign_release_credential(&key, BOB, EXPIRES_AT);
        (key, credential)
    }

    fn gated_escrow() -> Escrow {
        let key = issuer_key();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_credential_gate(key.public_key())
            .unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        e
    }

    #[test]
    fn credential_message_binds_taker_and_expiry() {
        let key = issuer_key();
        let base = sign_release_credential(&key, BOB, EXPIRES_AT);
        let base_msg = credential_message(&base);
        let other_taker = sign_release_credential(&key, [0xBC; 32], EXPIRES_AT);
        assert_ne!(base_msg, credential_message(&other_taker));
        let other_expiry = sign_release_credential(&key, BOB, EXPIRES_AT + 1);
        assert_ne!(base_msg, credential_message(&other_expiry));
        assert_eq!(base_msg, credential_message(&base));
    }

    #[test]
    fn credential_verifies_and_rejects_each_failure_shape() {
        let (key, credential) = valid_credential();
        let issuer = key.public_key();
        assert_eq!(
            verify_release_credential(issuer, BOB, &credential, NOW, &not_revoked),
            Ok(())
        );
        // Valid exactly at the deadline, expired one second past it.
        assert_eq!(
            verify_release_credential(issuer, BOB, &credential, EXPIRES_AT, &not_revoked),
            Ok(())
        );
        assert_eq!(
            verify_release_credential(issuer, BOB, &credential, EXPIRES_AT + 1, &not_revoked),
            Err(EscrowError::CredentialExpired)
        );
        // Revocation beats a valid signature.
        assert_eq!(
            verify_release_credential(issuer, BOB, &credential, NOW, &|_| true),
            Err(EscrowError::CredentialRevoked)
        );
        // A credential minted for a different taker proves nothing.
        let foreign = sign_release_credential(&key, [0xBC; 32], EXPIRES_AT);
        assert_eq!(
            verify_release_credential(issuer, BOB, &foreign, NOW, &not_revoked),
            Err(EscrowError::CredentialInvalid)
        );
        // A valid signature from a different issuer proves nothing.
        let stranger = SigningKey::from_seed([0x99; 32]);
        let stranger_credential = sign_release_credential(&stranger, BOB, EXPIRES_AT);
        assert_eq!(
            verify_release_credential(issuer, BOB, &stranger_credential, NOW, &not_revoked),
            Err(EscrowError::CredentialInvalid)
        );
        // A tampered signature fails even with a matching taker.
        let mut tampered = credential;
        tampered.signature[0] ^= 0x01;
        assert_eq!(
            verify_release_credential(issuer, BOB, &tampered, NOW, &not_revoked),
            Err(EscrowError::CredentialInvalid)
        );
    }

    #[test]
    fn plain_release_refuses_credential_gated_escrow() {
        let mut e = gated_escrow();
        assert_eq!(
            e.release(ALICE, NOW, 1_000_000, None, BOB),
            Err(EscrowError::CredentialGateRequired)
        );
        assert_eq!(e.released_amount(), 0, "a refused release moves nothing");
    }

    #[test]
    fn credentialed_release_settles_and_second_release_fails_state() {
        let key = issuer_key();
        let mut e = gated_escrow();
        let credential = sign_release_credential(&key, BOB, EXPIRES_AT);
        let (payout, fee) = e
            .release_with_credential(ALICE, NOW, 1_000_000, None, BOB, &credential, &not_revoked)
            .unwrap();
        assert_eq!((payout, fee), (1_000_000, 0));
        assert_eq!(e.released_amount(), 1_000_000);
        // The release is terminal: a replayed credential can never
        // settle a second release — the state check refuses it.
        assert_eq!(
            e.release_with_credential(ALICE, NOW, 1_000_000, None, BOB, &credential, &not_revoked),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.released_amount(), 1_000_000, "a replay settles nothing twice");
    }

    #[test]
    fn credentialed_release_rejects_bad_credential_without_settling() {
        let key = issuer_key();
        let mut e = gated_escrow();
        // Expired credential.
        let stale = sign_release_credential(&key, BOB, NOW - 1);
        assert_eq!(
            e.release_with_credential(ALICE, NOW, 1_000_000, None, BOB, &stale, &not_revoked),
            Err(EscrowError::CredentialExpired)
        );
        // Revoked credential.
        let (_, credential) = valid_credential();
        assert_eq!(
            e.release_with_credential(ALICE, NOW, 1_000_000, None, BOB, &credential, &|_| true),
            Err(EscrowError::CredentialRevoked)
        );
        // Credential minted for a different taker.
        let foreign = sign_release_credential(&key, [0xBC; 32], EXPIRES_AT);
        assert_eq!(
            e.release_with_credential(ALICE, NOW, 1_000_000, None, BOB, &foreign, &not_revoked),
            Err(EscrowError::CredentialInvalid)
        );
        assert_eq!(e.released_amount(), 0, "no failed credential settles");
    }

    #[test]
    fn credentialed_path_on_unbound_escrow_and_bad_binding() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        let (_, credential) = valid_credential();
        assert_eq!(
            e.release_with_credential(ALICE, NOW, 1_000_000, None, BOB, &credential, &not_revoked),
            Err(EscrowError::CredentialGateNotBound)
        );
        // Binding the zero key is rejected: zero is the unbound
        // sentinel, so binding it would be a gate that never opens.
        let e2 = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .and_then(|esc| esc.with_credential_gate([0u8; 32]));
        assert_eq!(e2, Err(EscrowError::InvalidCredentialIssuer));
        // Binding after funding is a state transition error, like
        // every other Uninitialized-only builder.
        assert_eq!(
            e.with_credential_gate(issuer_key().public_key()),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn unbound_escrow_release_is_unchanged() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(e.credential_issuer(), [0u8; 32]);
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        let (payout, _) = e.release(ALICE, NOW, 1_000_000, None, BOB).unwrap();
        assert_eq!(payout, 1_000_000);
    }
}
