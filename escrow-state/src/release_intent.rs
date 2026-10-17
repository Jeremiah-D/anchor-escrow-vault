//! AV-123: gasless release via a signed Ed25519 intent — the Solana
//! meta-transaction pattern.
//!
//! The initializer signs a [`ReleaseIntent`] *off-chain* with their
//! Ed25519 key; any relayer (any fee payer) then submits
//! [`Escrow::release_via_intent`](crate::Escrow::release_via_intent)
//! with the intent and its detached signature. The state machine
//! verifies the signature against the escrow's initializer key and,
//! on success, runs the exact [`Escrow::release`](crate::Escrow::release)
//! guard chain — a gasless release is a release, never a bypass.
//!
//! Design notes:
//!
//! - The signature covers the intent's *canonical byte encoding*,
//!   prefixed with [`RELEASE_INTENT_DOMAIN`]. The domain prefix is
//!   the cross-protocol replay defense: a signature minted for a
//!   keeper report, a multisig ballot, or any other signed envelope
//!   in this crate (all of which sign different canonical bytes)
//!   cannot verify as a release intent, and a release intent cannot
//!   be replayed into those protocols.
//! - The encoding is fixed-field-order, little-endian integers,
//!   no length prefixes — every field has a statically known size,
//!   so there is exactly one byte string per intent (canonical by
//!   construction; the `*_canonical` tests pin it byte-for-byte).
//! - Replay protection is the vault's persisted `last_intent_nonce`
//!   (see `VAULT_FIELDS`): an intent is accepted only when
//!   `intent.nonce > last_intent_nonce` — strictly increasing, so a
//!   captured intent can never be submitted twice — and only while
//!   `now_slot < intent.expiry_slot` (the slot comes from the clock
//!   sysvar on-chain, never an instruction param, same rule as the
//!   AV-27 timelock).
//! - The signer is always the initializer: their key is the one
//!   `release` already trusts. A taker- or operator-signed intent is
//!   `InvalidReleaseIntent` — the intent channel cannot smuggle in a
//!   second authority.
//!
//! This module only defines the envelope and the signature primitive;
//! the nonce/expiry bookkeeping and the `release` delegation live on
//! [`Escrow`](crate::Escrow) (the persisted field is part of the
//! account layout), and the keeper-scan annotation lives in
//! [`crate::keeper`] ([`crate::WatchedEscrow::with_pending_intent`]).

use super::ed25519::{verify as ed25519_verify, SigningKey};

/// Domain-separation prefix for the signed intent payload. Prepended
/// to the canonical field encoding before signing, so a signature
/// minted for any other envelope (keeper report, multisig ballot,
/// …) can never verify as a release intent.
pub const RELEASE_INTENT_DOMAIN: &[u8] = b"ESCROW-RELEASE-v1";

/// Canonical byte length of the signed payload: domain (17) +
/// escrow id (32) + amount (8) + payout_to (32) + nonce (8) +
/// expiry_slot (8).
pub const RELEASE_INTENT_MSG_LEN: usize = 17 + 32 + 8 + 32 + 8 + 8;

/// The off-chain authorization the initializer signs for a gasless
/// release. `escrow` is the 32-byte escrow identity (the vault PDA —
/// the same convention as [`crate::IndexedEscrow`]'s `escrow_id`);
/// `amount` / `payout_to` are the exact `release` arguments the
/// intent authorizes (a relayer cannot change them — the signature
/// binds them); `nonce` is the strictly-increasing replay counter;
/// `expiry_slot` is the last slot the intent may be executed at
/// (`now_slot < expiry_slot` is required).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseIntent {
    /// The escrow (vault PDA) this intent authorizes a release from.
    pub escrow: [u8; 32],
    /// The gross release amount the intent authorizes.
    pub amount: u64,
    /// The taker payout destination the intent authorizes.
    pub payout_to: [u8; 32],
    /// Strictly increasing replay counter (see `last_intent_nonce`).
    pub nonce: u64,
    /// Last executable slot; the intent is dead at
    /// `now_slot >= expiry_slot`.
    pub expiry_slot: u64,
}

impl ReleaseIntent {
    /// Build an intent. No validation — the state machine validates
    /// (`InvalidReleaseIntent`, `IntentNonceReused`, `IntentExpired`);
    /// construction stays total so offline signers can build the
    /// envelope freely.
    pub fn new(
        escrow: [u8; 32],
        amount: u64,
        payout_to: [u8; 32],
        nonce: u64,
        expiry_slot: u64,
    ) -> Self {
        ReleaseIntent {
            escrow,
            amount,
            payout_to,
            nonce,
            expiry_slot,
        }
    }

    /// The canonical signed payload:
    /// `RELEASE_INTENT_DOMAIN || escrow || amount.to_le_bytes() ||
    /// payout_to || nonce.to_le_bytes() || expiry_slot.to_le_bytes()`.
    /// Fixed field order, fixed sizes — exactly one byte string per
    /// intent. The domain prefix is what makes a cross-protocol
    /// signature fail to verify here.
    pub fn canonical_bytes(&self) -> [u8; RELEASE_INTENT_MSG_LEN] {
        let mut out = [0u8; RELEASE_INTENT_MSG_LEN];
        let mut p = 0usize;
        out[p..p + RELEASE_INTENT_DOMAIN.len()].copy_from_slice(RELEASE_INTENT_DOMAIN);
        p += RELEASE_INTENT_DOMAIN.len();
        out[p..p + 32].copy_from_slice(&self.escrow);
        p += 32;
        out[p..p + 8].copy_from_slice(&self.amount.to_le_bytes());
        p += 8;
        out[p..p + 32].copy_from_slice(&self.payout_to);
        p += 32;
        out[p..p + 8].copy_from_slice(&self.nonce.to_le_bytes());
        p += 8;
        out[p..p + 8].copy_from_slice(&self.expiry_slot.to_le_bytes());
        debug_assert_eq!(p + 8, RELEASE_INTENT_MSG_LEN);
        out
    }
}

/// Sign the intent's canonical bytes with the initializer's Ed25519
/// key (deterministic RFC 8032, via [`SigningKey::sign`]). The
/// returned 64-byte signature is what
/// [`Escrow::release_via_intent`](crate::Escrow::release_via_intent)
/// verifies — the relayer submits it alongside the intent.
pub fn sign_release_intent(key: &SigningKey, intent: &ReleaseIntent) -> [u8; 64] {
    key.sign(&intent.canonical_bytes())
}

/// Verify a detached signature over the intent's canonical bytes
/// against the initializer's 32-byte Ed25519 public key. `false`
/// (never panics) on any mismatch — including a signature minted
/// for a different domain, a different escrow, or a tampered field.
pub fn verify_release_intent(
    public_key: &[u8; 32],
    intent: &ReleaseIntent,
    signature: &[u8; 64],
) -> bool {
    ed25519_verify(public_key, &intent.canonical_bytes(), signature)
}

/// A signed release intent: the intent plus its detached Ed25519
/// signature — exactly what the relayer submits to
/// [`Escrow::release_via_intent`](crate::Escrow::release_via_intent)
/// (and what the Anchor `release_via_intent` instruction carries).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedReleaseIntent {
    /// The intent the initializer authorized.
    pub intent: ReleaseIntent,
    /// The 64-byte Ed25519 signature over
    /// [`ReleaseIntent::canonical_bytes`].
    pub signature: [u8; 64],
}

impl SignedReleaseIntent {
    /// Build the envelope. No validation — verification is the
    /// state machine's job (`InvalidReleaseIntent`); construction
    /// stays total so offline signers and keepers can build the
    /// envelope freely.
    pub fn new(intent: ReleaseIntent, signature: [u8; 64]) -> Self {
        SignedReleaseIntent { intent, signature }
    }

    /// Verify the envelope's signature against `public_key` (the
    /// escrow initializer's key). `false` on any mismatch.
    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        verify_release_intent(public_key, &self.intent, &self.signature)
    }
}

#[cfg(test)]
mod release_intent_tests {
    use super::*;

    const ESCROW_ID: [u8; 32] = [0x1D; 32];
    const PAYOUT: [u8; 32] = [0xBB; 32];

    fn intent() -> ReleaseIntent {
        ReleaseIntent::new(ESCROW_ID, 1_000_000, PAYOUT, 1, 9_999_999)
    }

    #[test]
    fn canonical_encoding_is_byte_pinned() {
        // The domain is 17 bytes; the field order is
        // domain || escrow || amount(le) || payout_to || nonce(le) ||
        // expiry_slot(le). Pinned byte-for-byte so a signer in any
        // language reproduces the same bytes.
        let b = intent().canonical_bytes();
        assert_eq!(b.len(), RELEASE_INTENT_MSG_LEN);
        assert_eq!(&b[..17], b"ESCROW-RELEASE-v1");
        assert_eq!(&b[17..49], &ESCROW_ID);
        assert_eq!(
            u64::from_le_bytes(b[49..57].try_into().unwrap()),
            1_000_000
        );
        assert_eq!(&b[57..89], &PAYOUT);
        assert_eq!(u64::from_le_bytes(b[89..97].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_le_bytes(b[97..105].try_into().unwrap()),
            9_999_999
        );
    }

    #[test]
    fn canonical_encoding_is_field_order_sensitive() {
        // Swapping two fields' bytes must change the encoding — no
        // two distinct intents share a payload.
        let a = intent();
        let mut b = a;
        b.amount = a.nonce;
        b.nonce = a.amount;
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = SigningKey::from_seed([0x11; 32]);
        let i = intent();
        let sig = sign_release_intent(&key, &i);
        assert!(verify_release_intent(&key.public_key(), &i, &sig));
    }

    #[test]
    fn verify_rejects_tampered_fields() {
        let key = SigningKey::from_seed([0x11; 32]);
        let i = intent();
        let sig = sign_release_intent(&key, &i);
        // Every field is signature-bound: flipping any one breaks
        // verification (a relayer cannot redirect the payout or
        // inflate the amount).
        for mutate in [
            |x: &mut ReleaseIntent| x.amount += 1,
            |x: &mut ReleaseIntent| x.payout_to[0] ^= 0xFF,
            |x: &mut ReleaseIntent| x.escrow[31] ^= 0xFF,
            |x: &mut ReleaseIntent| x.nonce += 1,
            |x: &mut ReleaseIntent| x.expiry_slot -= 1,
        ] {
            let mut tampered = i;
            mutate(&mut tampered);
            assert!(
                !verify_release_intent(&key.public_key(), &tampered, &sig),
                "tampered intent verified"
            );
        }
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key = SigningKey::from_seed([0x11; 32]);
        let other = SigningKey::from_seed([0x22; 32]);
        let i = intent();
        let sig = sign_release_intent(&key, &i);
        assert!(!verify_release_intent(&other.public_key(), &i, &sig));
    }

    #[test]
    fn verify_rejects_cross_domain_signature() {
        // The cross-protocol replay defense: a signature minted over
        // the same fields with a different domain prefix must not
        // verify as a release intent.
        let key = SigningKey::from_seed([0x11; 32]);
        let i = intent();
        let mut other_domain_msg = b"KEEPER-REPORT-v1__".to_vec();
        other_domain_msg.extend_from_slice(&i.canonical_bytes()[17..]);
        let sig = key.sign(&other_domain_msg);
        assert!(!verify_release_intent(&key.public_key(), &i, &sig));
    }

    #[test]
    fn verify_rejects_malformed_signature() {
        let key = SigningKey::from_seed([0x11; 32]);
        let i = intent();
        assert!(!verify_release_intent(&key.public_key(), &i, &[0u8; 64]));
        assert!(!verify_release_intent(&key.public_key(), &i, &[0xFF; 64]));
    }
}
