//! AV-125: off-chain state attestation for keeper verification —
//! Solana observability / backend engineering.
//!
//! The initializer signs a [`StateSummary`] *off-chain* with their
//! Ed25519 key; keepers and indexers verify the detached signature
//! against the initializer's public key without trusting any keeper.
//! A keeper that forges vault state (e.g. claims a vault is `Funded`
//! when the chain says `Cancelled`) cannot produce a signature that
//! verifies — the state summary is bound to the initializer's key,
//! exactly like the AV-123 release-intent channel.
//!
//! Design notes:
//!
//! - **Purely off-chain.** Unlike [`crate::ReleaseIntent`], an
//!   attestation never executes on-chain: there is no Anchor
//!   instruction, no IDL entry, no account-layout change, no rent
//!   change — `VAULT_FIELDS` is untouched. `attest_state` is a pure
//!   read on `&self`: it emits no events and mutates nothing.
//! - The signature covers the summary's *canonical byte encoding*,
//!   prefixed with [`STATE_ATTESTATION_DOMAIN`]. The domain prefix is
//!   the cross-protocol replay defense: a signature minted for a
//!   release intent, a keeper report, a multisig ballot, or any other
//!   signed envelope in this crate (all of which sign different
//!   canonical bytes) cannot verify as a state attestation, and a
//!   state attestation cannot be replayed into those protocols.
//! - The encoding is fixed-field-order, little-endian integers, no
//!   length prefixes — every field has a statically known size, so
//!   there is exactly one byte string per summary (canonical by
//!   construction; the `*_canonical` tests pin it byte-for-byte).
//! - The `slot` parameter must come from the chain clock slot (the
//!   AV-27 rule: measured on-chain, never an instruction param). The
//!   signer reads `Clock::get().slot` (or the slot the keeper's RPC
//!   node reported for the account) and the verifier compares the
//!   attested slot against the slot its own view came from — a stale
//!   attestation is detectable by construction.
//! - The signer is always the initializer: their key is the one
//!   `release` already trusts. A taker- or operator-signed attestation
//!   verifies only against *their* key, which no keeper should trust
//!   for a vault — same authority rule as the release-intent channel.
//!
//! The envelope is [`StateAttestation`]: the vault identity
//! (`escrow_id`, the 32-byte vault PDA — the same convention as
//! [`crate::ReleaseIntent`]'s `escrow`, caller-supplied), the signed
//! [`StateSummary`], and the 64-byte Ed25519 signature. The signature
//! binds the *summary content*; the envelope's `escrow_id` names the
//! vault the signer claims the summary describes, and the verifier
//! pairs the attestation with the initializer pubkey it resolved for
//! that vault (from the vault account itself).
//!
//! [`EscrowSnapshot`](crate::EscrowSnapshot) exports
//! [`attestation_summary`](crate::EscrowSnapshot::attestation_summary)
//! so a keeper holding only snapshots can recompute the exact bytes a
//! signature covers and verify an attestation offline — no chain node
//! required.

use super::ed25519::{verify as ed25519_verify, SigningKey};
use super::{Escrow, EscrowState};

/// Domain-separation prefix for the signed state-summary payload.
/// Prepended to the canonical field encoding before signing, so a
/// signature minted for any other envelope (release intent, keeper
/// report, multisig ballot, …) can never verify as a state
/// attestation.
pub const STATE_ATTESTATION_DOMAIN: &[u8] = b"ESCROW-STATE-ATTEST-v1";

/// Canonical byte length of the signed payload: domain (22) + state
/// (1) + amount (8) + released (8) + refunded (8) + penalty_paid (8)
/// + schema_version (1) + slot (8).
pub const STATE_SUMMARY_MSG_LEN: usize = 22 + 1 + 8 + 8 + 8 + 8 + 1 + 8;

/// The canonical, signature-bound digest of an escrow's fund state —
/// what the initializer actually attests to. `state` is the
/// Borsh-stable [`EscrowState`] discriminant (`0`–`10`, pinned by the
/// `escrow_state_discriminants` tests in the crate root); `slot` is
/// the chain slot the summary anchors to (AV-27: measured on-chain).
/// Every field has a fixed size, so the canonical encoding is
/// byte-unique per summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateSummary {
    /// The [`EscrowState`] discriminant at attestation time.
    pub state: u8,
    /// Total amount ever locked (the escrow's declared `amount`).
    pub amount: u64,
    /// Cumulative gross amount released to the taker.
    pub released: u64,
    /// Cumulative initializer receipts — derived, not persisted (see
    /// [`Escrow::state_summary`]).
    pub refunded: u64,
    /// Cumulative amount slashed to the penalty account.
    pub penalty_paid: u64,
    /// The vault layout schema version (AV-75).
    pub schema_version: u8,
    /// The chain slot the summary is anchored to.
    pub slot: u64,
}

impl StateSummary {
    /// The canonical signed payload:
    /// `STATE_ATTESTATION_DOMAIN || state || amount.to_le_bytes() ||
    /// released.to_le_bytes() || refunded.to_le_bytes() ||
    /// penalty_paid.to_le_bytes() || schema_version ||
    /// slot.to_le_bytes()`.
    /// Fixed field order, fixed sizes — exactly one byte string per
    /// summary. The domain prefix is what makes a cross-protocol
    /// signature fail to verify here.
    pub fn canonical_bytes(&self) -> [u8; STATE_SUMMARY_MSG_LEN] {
        let mut out = [0u8; STATE_SUMMARY_MSG_LEN];
        let mut p = 0usize;
        out[p..p + STATE_ATTESTATION_DOMAIN.len()]
            .copy_from_slice(STATE_ATTESTATION_DOMAIN);
        p += STATE_ATTESTATION_DOMAIN.len();
        out[p] = self.state;
        p += 1;
        out[p..p + 8].copy_from_slice(&self.amount.to_le_bytes());
        p += 8;
        out[p..p + 8].copy_from_slice(&self.released.to_le_bytes());
        p += 8;
        out[p..p + 8].copy_from_slice(&self.refunded.to_le_bytes());
        p += 8;
        out[p..p + 8].copy_from_slice(&self.penalty_paid.to_le_bytes());
        p += 8;
        out[p] = self.schema_version;
        p += 1;
        out[p..p + 8].copy_from_slice(&self.slot.to_le_bytes());
        debug_assert_eq!(p + 8, STATE_SUMMARY_MSG_LEN);
        out
    }
}

/// A signed state attestation: the vault identity, the attested
/// [`StateSummary`], and the initializer's detached Ed25519 signature
/// over the summary's canonical bytes. The keeper stores or relays
/// this envelope; verification needs only the initializer's 32-byte
/// public key — no chain access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateAttestation {
    /// The escrow (vault PDA) this attestation describes —
    /// caller-supplied, same convention as
    /// [`crate::ReleaseIntent`]'s `escrow`.
    pub escrow_id: [u8; 32],
    /// The attested state summary.
    pub summary: StateSummary,
    /// The 64-byte Ed25519 signature over
    /// [`StateSummary::canonical_bytes`].
    pub signature: [u8; 64],
}

impl StateAttestation {
    /// Build the envelope. No validation — verification is the
    /// keeper's job ([`verify_state_attestation`]); construction stays
    /// total so offline signers can build the envelope freely.
    pub fn new(escrow_id: [u8; 32], summary: StateSummary, signature: [u8; 64]) -> Self {
        StateAttestation {
            escrow_id,
            summary,
            signature,
        }
    }

    /// Verify the envelope's signature against `public_key` (the
    /// escrow initializer's key). `false` on any mismatch.
    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        verify_state_attestation(public_key, self)
    }
}

/// Sign a state summary's canonical bytes with the initializer's
/// Ed25519 key (deterministic RFC 8032, via [`SigningKey::sign`]).
/// The returned 64-byte signature is what keepers verify with
/// [`verify_state_attestation`].
pub fn sign_state_attestation(key: &SigningKey, summary: &StateSummary) -> [u8; 64] {
    key.sign(&summary.canonical_bytes())
}

/// Verify a detached signature over the attestation's summary
/// canonical bytes against the initializer's 32-byte Ed25519 public
/// key. `false` (never panics) on any mismatch — including a
/// signature minted for a different domain, a different state, or a
/// tampered summary field.
pub fn verify_state_attestation(public_key: &[u8; 32], attestation: &StateAttestation) -> bool {
    ed25519_verify(
        public_key,
        &attestation.summary.canonical_bytes(),
        &attestation.signature,
    )
}

impl Escrow {
    /// Build the canonical state summary this escrow attests to at
    /// chain slot `slot` — the exact bytes
    /// [`Escrow::attest_state`] signs, so a keeper holding only the
    /// summary can recompute the signed payload. Pure read: the
    /// escrow is borrowed, no state changes, no events.
    ///
    /// `slot` must come from the chain clock (AV-27 rule: measured
    /// on-chain, never an instruction param) — the slot the keeper's
    /// view of this vault came from.
    ///
    /// The `refunded` leg is *derived*, not persisted: the summary
    /// reports the terminal transition's refund (the event-sourced
    /// [`crate::FundsTriple`] rebuilds the full history from the log
    /// — never fabricated, per the AV-26 snapshot rule). The
    /// persisted cumulative partial-refund counter
    /// ([`Escrow::refunded_amount`], AV-127) is available separately
    /// for keepers that need the on-chain audit trail. After `cancel`,
    /// `cancel_expired`, or `resolve` the escrow is terminal and the
    /// audit-preserved [`Escrow::remaining_amount`] *is* the
    /// initializer's refund (the taker's share of `resolve` rides in
    /// `released`), so those states — and `Closed` reached from
    /// them — report it; every other state reports `0`, including
    /// `Split` (funds were re-homed to children, not refunded) and
    /// `Declined` (funds are still parked). Caveat: a `Closed` vault
    /// retired from `Split` still preserves its remainder, which the
    /// summary counts as refunded — read split parents against the
    /// child folds.
    pub fn state_summary(&self, slot: u64) -> StateSummary {
        let refunded = match self.state {
            EscrowState::Cancelled | EscrowState::Settled | EscrowState::Closed => {
                self.remaining_amount()
            }
            _ => 0,
        };
        StateSummary {
            state: self.state as u8,
            amount: self.amount(),
            released: self.released_amount(),
            refunded,
            penalty_paid: self.penalty_paid(),
            schema_version: self.schema_version(),
            slot,
        }
    }

    /// Sign this escrow's state summary with the initializer's Ed25519
    /// key and return the [`StateAttestation`] envelope — the off-chain
    /// proof a keeper relays to prove "the initializer says the vault
    /// looks like this at `slot`".
    ///
    /// Pure read on `&self` (emits no events, mutates nothing) and —
    /// unlike [`Escrow::release_via_intent`](crate::Escrow::release_via_intent) —
    /// this never executes on-chain: there is no instruction, no IDL
    /// entry, no layout or rent change. `escrow_id` is the vault PDA
    /// (caller-supplied); `slot` is the chain clock slot the
    /// attestation anchors to; `signing_key` is the initializer's key
    /// (the same authority the release channel trusts).
    pub fn attest_state(
        &self,
        escrow_id: [u8; 32],
        slot: u64,
        signing_key: &SigningKey,
    ) -> StateAttestation {
        let summary = self.state_summary(slot);
        let signature = sign_state_attestation(signing_key, &summary);
        StateAttestation::new(escrow_id, summary, signature)
    }
}

#[cfg(test)]
mod state_attestation_tests {
    use super::*;

    const ESCROW_ID: [u8; 32] = [0x1D; 32];
    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;
    const SLOT: u64 = 312_456_789;

    fn signing_key() -> SigningKey {
        SigningKey::from_seed([0x11; 32])
    }

    fn summary() -> StateSummary {
        StateSummary {
            state: EscrowState::Funded as u8,
            amount: 1_000_000,
            released: 250_000,
            refunded: 0,
            penalty_paid: 10_000,
            schema_version: 3,
            slot: SLOT,
        }
    }

    fn attestation() -> StateAttestation {
        let key = signing_key();
        let s = summary();
        StateAttestation::new(ESCROW_ID, s, sign_state_attestation(&key, &s))
    }

    #[test]
    fn canonical_encoding_is_byte_pinned() {
        // The domain is 22 bytes; the field order is
        // domain || state || amount(le) || released(le) || refunded(le)
        // || penalty_paid(le) || schema_version || slot(le).
        // Pinned byte-for-byte so a signer in any language reproduces
        // the same bytes.
        let b = summary().canonical_bytes();
        assert_eq!(b.len(), STATE_SUMMARY_MSG_LEN);
        assert_eq!(&b[..22], b"ESCROW-STATE-ATTEST-v1");
        assert_eq!(b[22], EscrowState::Funded as u8);
        assert_eq!(u64::from_le_bytes(b[23..31].try_into().unwrap()), 1_000_000);
        assert_eq!(
            u64::from_le_bytes(b[31..39].try_into().unwrap()),
            250_000
        );
        assert_eq!(u64::from_le_bytes(b[39..47].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(b[47..55].try_into().unwrap()),
            10_000
        );
        assert_eq!(b[55], 3);
        assert_eq!(u64::from_le_bytes(b[56..64].try_into().unwrap()), SLOT);
    }

    #[test]
    fn canonical_encoding_is_field_order_sensitive() {
        // Swapping two fields' bytes must change the encoding — no
        // two distinct summaries share a payload.
        let a = summary();
        let mut b = a;
        b.released = a.refunded;
        b.refunded = a.released;
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = signing_key();
        let a = attestation();
        assert!(verify_state_attestation(&key.public_key(), &a));
        assert!(a.verify(&key.public_key()));
    }

    #[test]
    fn verify_rejects_tampered_summary_fields() {
        let key = signing_key();
        let a = attestation();
        // Every summary field is signature-bound: flipping any one
        // breaks verification — a keeper cannot inflate the released
        // amount, backdate the slot, or forge the state.
        for mutate in [
            |x: &mut StateSummary| x.state = EscrowState::Cancelled as u8,
            |x: &mut StateSummary| x.amount += 1,
            |x: &mut StateSummary| x.released += 1,
            |x: &mut StateSummary| x.refunded += 1,
            |x: &mut StateSummary| x.penalty_paid += 1,
            |x: &mut StateSummary| x.schema_version ^= 0xFF,
            |x: &mut StateSummary| x.slot -= 1,
        ] {
            let mut tampered = a;
            mutate(&mut tampered.summary);
            assert!(
                !verify_state_attestation(&key.public_key(), &tampered),
                "tampered summary verified"
            );
        }
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let other = SigningKey::from_seed([0x22; 32]);
        let a = attestation();
        assert!(!verify_state_attestation(&other.public_key(), &a));
    }

    #[test]
    fn verify_rejects_cross_domain_signature() {
        // The cross-protocol replay defense: a signature minted over
        // the same summary bytes with a different domain prefix must
        // not verify as a state attestation.
        let key = signing_key();
        let s = summary();
        let mut other_domain_msg = b"ESCROW-RELEASE-v1___".to_vec();
        other_domain_msg.extend_from_slice(&s.canonical_bytes()[22..]);
        let a = StateAttestation::new(ESCROW_ID, s, key.sign(&other_domain_msg));
        assert!(!verify_state_attestation(&key.public_key(), &a));
    }

    #[test]
    fn verify_rejects_malformed_signature() {
        let key = signing_key();
        let mut a = attestation();
        a.signature = [0u8; 64];
        assert!(!verify_state_attestation(&key.public_key(), &a));
        a.signature = [0xFF; 64];
        assert!(!verify_state_attestation(&key.public_key(), &a));
    }

    #[test]
    fn signature_is_deterministic() {
        // Same vault state + same slot must mint identical bytes —
        // a keeper re-signing the same view cannot produce a
        // different signature, and equality is a cheap freshness
        // check.
        let key = signing_key();
        let s = summary();
        let a = sign_state_attestation(&key, &s);
        let b = sign_state_attestation(&key, &s);
        assert_eq!(a, b);
    }

    #[test]
    fn state_summary_tracks_live_escrow() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        let s = e.state_summary(SLOT);
        assert_eq!(s.state, EscrowState::Funded as u8);
        assert_eq!(s.amount, 1_000_000);
        assert_eq!(s.released, 0);
        assert_eq!(s.refunded, 0);
        assert_eq!(s.penalty_paid, 0);
        assert_eq!(s.schema_version, e.schema_version());
        assert_eq!(s.slot, SLOT);
    }

    #[test]
    fn state_summary_refunded_is_derived_on_cancelled() {
        // The initializer's refund on cancel is the audit-preserved
        // remainder — the summary reports it as `refunded`.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        e.release(ALICE, EXPIRES_AT - 100, 250_000, None, BOB).unwrap();
        e.cancel(ALICE, None, ALICE).unwrap();
        let s = e.state_summary(SLOT);
        assert_eq!(s.state, EscrowState::Cancelled as u8);
        assert_eq!(s.released, 250_000);
        assert_eq!(s.refunded, 750_000);
        assert_eq!(s.amount, s.released + s.refunded + s.penalty_paid);
    }

    #[test]
    fn state_summary_refunded_is_zero_on_released() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        e.release(ALICE, EXPIRES_AT - 100, 1_000_000, None, BOB).unwrap();
        let s = e.state_summary(SLOT);
        assert_eq!(s.state, EscrowState::Released as u8);
        assert_eq!(s.released, 1_000_000);
        assert_eq!(s.refunded, 0);
    }

    #[test]
    fn attest_state_is_pure_read_and_verifies() {
        // attest_state emits nothing and mutates nothing: the escrow
        // is identical before and after, and the envelope verifies
        // against the initializer's key.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        let key = signing_key();
        let before = e.state_summary(SLOT);
        let a = e.attest_state(ESCROW_ID, SLOT, &key);
        assert_eq!(a.escrow_id, ESCROW_ID);
        assert_eq!(a.summary, before);
        assert_eq!(e.state_summary(SLOT), before);
        assert!(a.verify(&key.public_key()));
    }
}
