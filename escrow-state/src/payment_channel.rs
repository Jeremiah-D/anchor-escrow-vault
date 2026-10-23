//! AV-197: Bidirectional payment channel — Lightning-style off-chain
//! balance updates over escrow-locked funds.
//!
//! An escrow's locked funds open a two-party payment channel
//! ([`PaymentChannel::open`] + [`PaymentChannel::fund`]); the two
//! parties then update their balance split *off-chain* by co-signing
//! [`ChannelUpdate`]s (each carrying a strictly increasing `nonce` —
//! the replay protection). Settlement is either cooperative (both
//! parties sign the final state — instant, no waiting) or unilateral
//! (one party submits the latest co-signed state on-chain and a
//! challenge window opens; the counterparty can refute with a newer
//! co-signed state).
//!
//! ```text
//! Unfunded --fund--> Open --update--> Open (nonce+1, both sigs)
//!    |                  |
//!    |                  +--close_cooperative--> Closed (instant settlement)
//!    |                  |
//!    |                  +--close_unilateral--> UnilateralClosePending
//!    |                                            |--dispute (newer state)--> window restarts
//!    |                                            |--finalize (now >= challenge_until)--> Closed
//! ```
//!
//! Design notes:
//! - The channel state machine is *independent* of the main [`Escrow`]
//!   state machine: it never touches the vault, so no `VAULT_FIELDS`
//!   growth and no rent math changes. The program keeps a channel in
//!   its own PDA; this crate is the executable off-chain spec.
//! - Every signed payload binds the channel identity
//!   (`party_a || party_b || total`) via the canonical bytes, so a
//!   signature minted for one channel can never be replayed on another
//!   channel — even between the same two parties.
//! - A state is valid only when *both* parties signed it
//!   ([`SignedChannelUpdate::verify`]). The unilateral path is
//!   unilateral only in *submission*: the submitter posts a
//!   mutually-signed state, and the challenge window exists so the
//!   counterparty can surface a *newer* mutually-signed state. A
//!   submitter can therefore never settle on a state the counterparty
//!   did not co-sign — the classic Lightning safety property.
//! - Conservation is checked in `u128`: `balance_a + balance_b` must
//!   equal `total` exactly, so no update can mint or burn lamports.
//! - Check order mirrors the crate convention (config → state →
//!   signatures → nonce → conservation): strangers learn nothing about
//!   the channel's state from a failed signature check.
//!
//! Pure logic, `Copy`-friendly fixed arrays, heap-free,
//! `no_std`-friendly. Deterministic: the same calls always produce the
//! same channel bytes.

use super::ed25519::{verify as ed25519_verify, SigningKey};
use crate::EscrowError;

/// Domain separator for the signed channel-update payload. The domain
/// is what makes a cross-protocol signature fail to verify here.
pub const CHANNEL_UPDATE_DOMAIN: &[u8] = b"PAYMENT-CHANNEL-v1";

/// Serialized length of a [`ChannelUpdate`]'s canonical bytes:
/// domain (18) + party_a (32) + party_b (32) + total (8) + nonce (8) +
/// balance_a (8) + balance_b (8).
pub const CHANNEL_UPDATE_MSG_LEN: usize = 18 + 32 + 32 + 8 + 8 + 8 + 8;

/// A payment channel's lifecycle state. Discriminants are stable —
/// they are persisted by the program, so never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChannelState {
    /// Created via [`PaymentChannel::open`], no funds committed yet.
    Unfunded = 0,
    /// Funded via [`PaymentChannel::fund`]; off-chain updates accepted.
    Open = 1,
    /// Unilateral close submitted; the counterparty may dispute with a
    /// newer co-signed state until `challenge_until`.
    UnilateralClosePending = 2,
    /// Settled — terminal. [`PaymentChannel::settlement`] reads the
    /// final split.
    Closed = 3,
}

/// One off-chain balance update both parties co-sign. The update binds
/// the channel identity (`party_a`, `party_b`, `total`), the replay
/// guard (`nonce`) and the new split (`balance_a`, `balance_b`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelUpdate {
    /// Strictly increasing per channel: `apply_update` requires
    /// `nonce == channel.nonce() + 1`; close/dispute paths require
    /// `nonce > channel.nonce()`.
    pub nonce: u64,
    /// Party A's new balance (lamports).
    pub balance_a: u64,
    /// Party B's new balance (lamports).
    pub balance_b: u64,
}

impl ChannelUpdate {
    /// The canonical signed payload:
    /// `CHANNEL_UPDATE_DOMAIN || party_a || party_b || total.to_le_bytes()
    /// || nonce.to_le_bytes() || balance_a.to_le_bytes() ||
    /// balance_b.to_le_bytes()`.
    /// Fixed field order, fixed sizes — exactly one byte string per
    /// update. The channel identity in the payload is what stops a
    /// signature from being replayed on a different channel.
    pub fn canonical_bytes(
        &self,
        party_a: &[u8; 32],
        party_b: &[u8; 32],
        total: u64,
    ) -> [u8; CHANNEL_UPDATE_MSG_LEN] {
        let mut out = [0u8; CHANNEL_UPDATE_MSG_LEN];
        let mut p = 0usize;
        out[p..p + CHANNEL_UPDATE_DOMAIN.len()].copy_from_slice(CHANNEL_UPDATE_DOMAIN);
        p += CHANNEL_UPDATE_DOMAIN.len();
        out[p..p + 32].copy_from_slice(party_a);
        p += 32;
        out[p..p + 32].copy_from_slice(party_b);
        p += 32;
        out[p..p + 8].copy_from_slice(&total.to_le_bytes());
        p += 8;
        out[p..p + 8].copy_from_slice(&self.nonce.to_le_bytes());
        p += 8;
        out[p..p + 8].copy_from_slice(&self.balance_a.to_le_bytes());
        p += 8;
        out[p..p + 8].copy_from_slice(&self.balance_b.to_le_bytes());
        debug_assert_eq!(p + 8, CHANNEL_UPDATE_MSG_LEN);
        out
    }
}

/// A channel update plus both parties' detached Ed25519 signatures —
/// exactly what the off-chain transport carries and what the program's
/// close instructions receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedChannelUpdate {
    /// The update both parties authorized.
    pub update: ChannelUpdate,
    /// Party A's 64-byte Ed25519 signature over
    /// [`ChannelUpdate::canonical_bytes`].
    pub sig_a: [u8; 64],
    /// Party B's 64-byte Ed25519 signature over the same bytes.
    pub sig_b: [u8; 64],
}

impl SignedChannelUpdate {
    /// Build the envelope. No validation — verification is the channel's
    /// job; construction stays total so offline signers can build the
    /// envelope freely.
    pub fn new(update: ChannelUpdate, sig_a: [u8; 64], sig_b: [u8; 64]) -> Self {
        SignedChannelUpdate {
            update,
            sig_a,
            sig_b,
        }
    }

    /// Verify both signatures against the channel's parties and total.
    /// `false` (never panics) on any mismatch — including a signature
    /// minted for a different channel, a swapped signer, or a tampered
    /// balance.
    pub fn verify(&self, channel: &PaymentChannel) -> bool {
        let msg = self
            .update
            .canonical_bytes(&channel.party_a, &channel.party_b, channel.total);
        ed25519_verify(&channel.party_a, &msg, &self.sig_a)
            && ed25519_verify(&channel.party_b, &msg, &self.sig_b)
    }
}

/// Sign a channel update with one party's Ed25519 key (deterministic
/// RFC 8032, via [`SigningKey::sign`]). Each party signs the same
/// canonical bytes; the pair becomes a [`SignedChannelUpdate`].
pub fn sign_channel_update(
    key: &SigningKey,
    update: &ChannelUpdate,
    party_a: &[u8; 32],
    party_b: &[u8; 32],
    total: u64,
) -> [u8; 64] {
    key.sign(&update.canonical_bytes(party_a, party_b, total))
}

/// A bidirectional payment channel over escrow-locked funds.
///
/// Created [`PaymentChannel::open`], funded [`PaymentChannel::fund`],
/// updated off-chain via [`PaymentChannel::apply_update`], and settled
/// cooperatively ([`PaymentChannel::close_cooperative`]) or
/// unilaterally with a challenge window
/// ([`PaymentChannel::close_unilateral`] /
/// [`PaymentChannel::dispute`] / [`PaymentChannel::finalize`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentChannel {
    party_a: [u8; 32],
    party_b: [u8; 32],
    total: u64,
    balance_a: u64,
    balance_b: u64,
    nonce: u64,
    state: ChannelState,
    /// Challenge window length (same clock units as the `now` the
    /// program passes in) for the unilateral close path.
    challenge_period: u64,
    /// Set by `close_unilateral` / refreshed by `dispute`; meaningful
    /// only in [`ChannelState::UnilateralClosePending`].
    challenge_until: u64,
}

impl PaymentChannel {
    /// Create an unfunded channel between two distinct non-zero parties.
    /// `total` is the locked capacity (must be > 0); `challenge_period`
    /// is the unilateral-close dispute window (0 = instant unilateral
    /// finalization — allowed but documented as defeating the window's
    /// purpose).
    pub fn open(
        party_a: [u8; 32],
        party_b: [u8; 32],
        total: u64,
        challenge_period: u64,
    ) -> Result<Self, EscrowError> {
        if party_a == [0u8; 32] || party_b == [0u8; 32] || party_a == party_b {
            return Err(EscrowError::InvalidChannelConfig);
        }
        if total == 0 {
            return Err(EscrowError::InvalidChannelConfig);
        }
        Ok(PaymentChannel {
            party_a,
            party_b,
            total,
            balance_a: 0,
            balance_b: 0,
            nonce: 0,
            state: ChannelState::Unfunded,
            challenge_period,
            challenge_until: 0,
        })
    }

    /// Commit the funding split and open the channel for off-chain
    /// updates: `split_a` goes to party A, `total - split_a` to party B.
    /// `Unfunded`-only; the split must conserve `total` exactly.
    pub fn fund(&mut self, split_a: u64) -> Result<(), EscrowError> {
        if self.state != ChannelState::Unfunded {
            return Err(EscrowError::InvalidChannelState);
        }
        let split_b = self
            .total
            .checked_sub(split_a)
            .ok_or(EscrowError::ChannelBalanceMismatch)?;
        self.balance_a = split_a;
        self.balance_b = split_b;
        self.state = ChannelState::Open;
        Ok(())
    }

    /// Apply one co-signed off-chain update: both signatures must
    /// verify, `nonce` must be exactly `self.nonce + 1` (strictly
    /// monotonic — a replayed update is [`EscrowError::StaleChannelNonce`]),
    /// and the split must conserve `total`. `Open`-only.
    pub fn apply_update(&mut self, signed: &SignedChannelUpdate) -> Result<(), EscrowError> {
        if self.state != ChannelState::Open {
            return Err(EscrowError::InvalidChannelState);
        }
        if !signed.verify(self) {
            return Err(EscrowError::InvalidChannelSignature);
        }
        let update = &signed.update;
        if update.nonce != self.nonce.wrapping_add(1) {
            return Err(EscrowError::StaleChannelNonce);
        }
        self.check_conservation(update.balance_a, update.balance_b)?;
        self.balance_a = update.balance_a;
        self.balance_b = update.balance_b;
        self.nonce = update.nonce;
        Ok(())
    }

    /// Cooperative close: both parties signed the final state, so
    /// settlement is instant — no challenge window. Requires a state
    /// *newer* than the channel's current nonce (the final state must
    /// move the channel forward, never replay it). Returns the
    /// `(party_a, party_b)` settlement split. `Open`-only.
    pub fn close_cooperative(
        &mut self,
        signed: &SignedChannelUpdate,
    ) -> Result<(u64, u64), EscrowError> {
        if self.state != ChannelState::Open {
            return Err(EscrowError::InvalidChannelState);
        }
        if !signed.verify(self) {
            return Err(EscrowError::InvalidChannelSignature);
        }
        let update = &signed.update;
        if update.nonce <= self.nonce {
            return Err(EscrowError::StaleChannelNonce);
        }
        self.check_conservation(update.balance_a, update.balance_b)?;
        self.balance_a = update.balance_a;
        self.balance_b = update.balance_b;
        self.nonce = update.nonce;
        self.state = ChannelState::Closed;
        Ok((self.balance_a, self.balance_b))
    }

    /// Unilateral close: `submitter` (one of the parties) posts the
    /// latest co-signed state on-chain. The state must be co-signed by
    /// *both* parties and newer than the channel's current nonce; the
    /// challenge window opens at `now + challenge_period` so the
    /// counterparty can [`PaymentChannel::dispute`] with a newer state.
    /// `Open`-only.
    pub fn close_unilateral(
        &mut self,
        submitter: &[u8; 32],
        signed: &SignedChannelUpdate,
        now: u64,
    ) -> Result<(), EscrowError> {
        self.check_party(submitter)?;
        if self.state != ChannelState::Open {
            return Err(EscrowError::InvalidChannelState);
        }
        if !signed.verify(self) {
            return Err(EscrowError::InvalidChannelSignature);
        }
        let update = &signed.update;
        if update.nonce <= self.nonce {
            return Err(EscrowError::StaleChannelNonce);
        }
        self.check_conservation(update.balance_a, update.balance_b)?;
        let challenge_until = now
            .checked_add(self.challenge_period)
            .ok_or(EscrowError::InvalidChannelConfig)?;
        self.balance_a = update.balance_a;
        self.balance_b = update.balance_b;
        self.nonce = update.nonce;
        self.state = ChannelState::UnilateralClosePending;
        self.challenge_until = challenge_until;
        Ok(())
    }

    /// Refute a unilateral close with a *newer* co-signed state. Any
    /// party may submit it (in practice the counterparty, but the
    /// signatures are what authorize the state, not the submitter).
    /// A valid dispute replaces the pending state and *restarts* the
    /// challenge window at `now + challenge_period` — the other side
    /// always gets a full window to respond, so last-second disputes
    /// cannot grief. `UnilateralClosePending`-only and only while the
    /// window is live (`now < challenge_until`).
    pub fn dispute(
        &mut self,
        submitter: &[u8; 32],
        signed: &SignedChannelUpdate,
        now: u64,
    ) -> Result<(), EscrowError> {
        self.check_party(submitter)?;
        if self.state != ChannelState::UnilateralClosePending {
            return Err(EscrowError::InvalidChannelState);
        }
        if now >= self.challenge_until {
            return Err(EscrowError::InvalidChannelState);
        }
        if !signed.verify(self) {
            return Err(EscrowError::InvalidChannelSignature);
        }
        let update = &signed.update;
        if update.nonce <= self.nonce {
            return Err(EscrowError::StaleChannelNonce);
        }
        self.check_conservation(update.balance_a, update.balance_b)?;
        let challenge_until = now
            .checked_add(self.challenge_period)
            .ok_or(EscrowError::InvalidChannelConfig)?;
        self.balance_a = update.balance_a;
        self.balance_b = update.balance_b;
        self.nonce = update.nonce;
        self.challenge_until = challenge_until;
        Ok(())
    }

    /// Finalize a unilateral close once the challenge window elapsed
    /// (`now >= challenge_until`). Returns the `(party_a, party_b)`
    /// settlement split. `UnilateralClosePending`-only.
    pub fn finalize(&mut self, now: u64) -> Result<(u64, u64), EscrowError> {
        if self.state != ChannelState::UnilateralClosePending {
            return Err(EscrowError::InvalidChannelState);
        }
        if now < self.challenge_until {
            return Err(EscrowError::InvalidChannelState);
        }
        self.state = ChannelState::Closed;
        Ok((self.balance_a, self.balance_b))
    }

    /// The final `(party_a, party_b)` split — `Some` only once
    /// [`ChannelState::Closed`].
    pub fn settlement(&self) -> Option<(u64, u64)> {
        if self.state == ChannelState::Closed {
            Some((self.balance_a, self.balance_b))
        } else {
            None
        }
    }

    /// The channel's lifecycle state.
    pub fn state(&self) -> ChannelState {
        self.state
    }

    /// The locked capacity both parties' balances always sum to.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// The current `(party_a, party_b)` split.
    pub fn balances(&self) -> (u64, u64) {
        (self.balance_a, self.balance_b)
    }

    /// The nonce of the latest applied state (0 = nothing applied yet).
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Party A's key.
    pub fn party_a(&self) -> &[u8; 32] {
        &self.party_a
    }

    /// Party B's key.
    pub fn party_b(&self) -> &[u8; 32] {
        &self.party_b
    }

    /// The unilateral-close dispute window, in the program's clock units.
    pub fn challenge_period(&self) -> u64 {
        self.challenge_period
    }

    /// When the live challenge window ends — meaningful only in
    /// [`ChannelState::UnilateralClosePending`].
    pub fn challenge_until(&self) -> u64 {
        self.challenge_until
    }

    /// The submitter must be one of the two channel parties. Checked
    /// before state validity, so strangers learn nothing about the
    /// channel's state — the crate's authority-first convention.
    fn check_party(&self, submitter: &[u8; 32]) -> Result<(), EscrowError> {
        if *submitter != self.party_a && *submitter != self.party_b {
            return Err(EscrowError::Unauthorized);
        }
        Ok(())
    }

    /// The conservation invariant: the split must sum to `total`
    /// exactly (summed in `u128`, so the sum can never wrap). No update
    /// may mint or burn lamports.
    fn check_conservation(&self, balance_a: u64, balance_b: u64) -> Result<(), EscrowError> {
        let sum = balance_a as u128 + balance_b as u128;
        if sum != self.total as u128 {
            return Err(EscrowError::ChannelBalanceMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod payment_channel_tests {
    use super::*;

    const ALICE_SEED: [u8; 32] = [0xA1; 32];
    const BOB_SEED: [u8; 32] = [0xB2; 32];
    const MALLORY_SEED: [u8; 32] = [0xCC; 32];
    const TOTAL: u64 = 1_000_000;
    const CHALLENGE_PERIOD: u64 = 3_600;

    fn alice() -> SigningKey {
        SigningKey::from_seed(ALICE_SEED)
    }
    fn bob() -> SigningKey {
        SigningKey::from_seed(BOB_SEED)
    }
    fn mallory() -> SigningKey {
        SigningKey::from_seed(MALLORY_SEED)
    }

    fn channel() -> PaymentChannel {
        PaymentChannel::open(
            alice().public_key(),
            bob().public_key(),
            TOTAL,
            CHALLENGE_PERIOD,
        )
        .unwrap()
    }

    fn open_channel() -> PaymentChannel {
        let mut ch = channel();
        ch.fund(600_000).unwrap();
        ch
    }

    /// Both parties co-sign `update` for `ch`.
    fn cosign(ch: &PaymentChannel, update: &ChannelUpdate) -> SignedChannelUpdate {
        let sig_a = sign_channel_update(&alice(), update, ch.party_a(), ch.party_b(), ch.total());
        let sig_b = sign_channel_update(&bob(), update, ch.party_a(), ch.party_b(), ch.total());
        SignedChannelUpdate::new(*update, sig_a, sig_b)
    }

    fn update(nonce: u64, balance_a: u64, balance_b: u64) -> ChannelUpdate {
        ChannelUpdate {
            nonce,
            balance_a,
            balance_b,
        }
    }

    #[test]
    fn canonical_encoding_is_byte_pinned() {
        let ch = open_channel();
        let u = update(3, 700_000, 300_000);
        let b = u.canonical_bytes(ch.party_a(), ch.party_b(), ch.total());
        assert_eq!(b.len(), CHANNEL_UPDATE_MSG_LEN);
        assert_eq!(&b[..18], b"PAYMENT-CHANNEL-v1");
        assert_eq!(&b[18..50], ch.party_a());
        assert_eq!(&b[50..82], ch.party_b());
        assert_eq!(u64::from_le_bytes(b[82..90].try_into().unwrap()), TOTAL);
        assert_eq!(u64::from_le_bytes(b[90..98].try_into().unwrap()), 3);
        assert_eq!(
            u64::from_le_bytes(b[98..106].try_into().unwrap()),
            700_000
        );
        assert_eq!(
            u64::from_le_bytes(b[106..114].try_into().unwrap()),
            300_000
        );
    }

    #[test]
    fn open_and_fund_happy_path() {
        let mut ch = channel();
        assert_eq!(ch.state(), ChannelState::Unfunded);
        assert_eq!(ch.nonce(), 0);
        ch.fund(600_000).unwrap();
        assert_eq!(ch.state(), ChannelState::Open);
        assert_eq!(ch.balances(), (600_000, 400_000));
        assert_eq!(ch.settlement(), None);
    }

    #[test]
    fn open_rejects_bad_config() {
        let a = alice().public_key();
        let b = bob().public_key();
        // Zero keys.
        assert_eq!(
            PaymentChannel::open([0u8; 32], b, TOTAL, CHALLENGE_PERIOD),
            Err(EscrowError::InvalidChannelConfig)
        );
        assert_eq!(
            PaymentChannel::open(a, [0u8; 32], TOTAL, CHALLENGE_PERIOD),
            Err(EscrowError::InvalidChannelConfig)
        );
        // Same party twice.
        assert_eq!(
            PaymentChannel::open(a, a, TOTAL, CHALLENGE_PERIOD),
            Err(EscrowError::InvalidChannelConfig)
        );
        // Zero capacity.
        assert_eq!(
            PaymentChannel::open(a, b, 0, CHALLENGE_PERIOD),
            Err(EscrowError::InvalidChannelConfig)
        );
    }

    #[test]
    fn fund_rejects_bad_split_and_double_fund() {
        let mut ch = channel();
        // Over-funding mints lamports — refused.
        assert_eq!(
            ch.fund(TOTAL + 1),
            Err(EscrowError::ChannelBalanceMismatch)
        );
        ch.fund(TOTAL).unwrap();
        assert_eq!(ch.balances(), (TOTAL, 0));
        // Double fund.
        assert_eq!(ch.fund(0), Err(EscrowError::InvalidChannelState));
    }

    #[test]
    fn apply_update_happy_path() {
        let mut ch = open_channel();
        let signed = cosign(&ch, &update(1, 500_000, 500_000));
        ch.apply_update(&signed).unwrap();
        assert_eq!(ch.nonce(), 1);
        assert_eq!(ch.balances(), (500_000, 500_000));
        let signed = cosign(&ch, &update(2, 100_000, 900_000));
        ch.apply_update(&signed).unwrap();
        assert_eq!(ch.nonce(), 2);
        assert_eq!(ch.balances(), (100_000, 900_000));
    }

    #[test]
    fn apply_update_rejects_stale_nonce() {
        let mut ch = open_channel();
        let signed = cosign(&ch, &update(1, 500_000, 500_000));
        ch.apply_update(&signed).unwrap();
        // Exact replay.
        assert_eq!(
            ch.apply_update(&signed),
            Err(EscrowError::StaleChannelNonce)
        );
        // Skipped nonce is also a replay-shaped gap for the strict
        // +1 rule — the bus must never accept an out-of-order update.
        let skipped = cosign(&ch, &update(3, 500_000, 500_000));
        assert_eq!(
            ch.apply_update(&skipped),
            Err(EscrowError::StaleChannelNonce)
        );
        assert_eq!(ch.nonce(), 1);
    }

    #[test]
    fn apply_update_rejects_broken_conservation() {
        let mut ch = open_channel();
        // Minting: sums to total + 1.
        let mint = cosign(&ch, &update(1, 500_001, 500_000));
        assert_eq!(
            ch.apply_update(&mint),
            Err(EscrowError::ChannelBalanceMismatch)
        );
        // Burning: sums to total - 1.
        let burn = cosign(&ch, &update(1, 499_999, 500_000));
        assert_eq!(
            ch.apply_update(&burn),
            Err(EscrowError::ChannelBalanceMismatch)
        );
        assert_eq!(ch.nonce(), 0);
    }

    #[test]
    fn apply_update_rejects_bad_signature() {
        let mut ch = open_channel();
        let u = update(1, 500_000, 500_000);
        // Mallory's signature in place of Bob's.
        let sig_a = sign_channel_update(&alice(), &u, ch.party_a(), ch.party_b(), ch.total());
        let sig_m = sign_channel_update(&mallory(), &u, ch.party_a(), ch.party_b(), ch.total());
        let forged = SignedChannelUpdate::new(u, sig_a, sig_m);
        assert_eq!(
            ch.apply_update(&forged),
            Err(EscrowError::InvalidChannelSignature)
        );
        // Tampered balances after signing.
        let mut tampered = cosign(&ch, &u);
        tampered.update.balance_a = 1;
        assert_eq!(
            ch.apply_update(&tampered),
            Err(EscrowError::InvalidChannelSignature)
        );
        // Signature minted for a different channel (different total).
        let other_total = cosign(&ch, &u);
        let mut ch2 = PaymentChannel::open(
            alice().public_key(),
            bob().public_key(),
            TOTAL + 1,
            CHALLENGE_PERIOD,
        )
        .unwrap();
        ch2.fund(TOTAL + 1).unwrap();
        assert_eq!(
            ch2.apply_update(&other_total),
            Err(EscrowError::InvalidChannelSignature)
        );
        assert_eq!(ch.nonce(), 0);
    }

    #[test]
    fn apply_update_rejects_wrong_state() {
        let ch = channel();
        let signed = cosign(&ch, &update(1, 500_000, 500_000));
        let mut unfunded = ch;
        assert_eq!(
            unfunded.apply_update(&signed),
            Err(EscrowError::InvalidChannelState)
        );
    }

    #[test]
    fn close_cooperative_settles_instantly() {
        let mut ch = open_channel();
        let signed = cosign(&ch, &update(1, 300_000, 700_000));
        let settlement = ch.close_cooperative(&signed).unwrap();
        assert_eq!(settlement, (300_000, 700_000));
        assert_eq!(ch.state(), ChannelState::Closed);
        assert_eq!(ch.settlement(), Some((300_000, 700_000)));
        // Terminal: no second close.
        let later = cosign(&ch, &update(2, 0, TOTAL));
        assert_eq!(
            ch.close_cooperative(&later),
            Err(EscrowError::InvalidChannelState)
        );
    }

    #[test]
    fn close_cooperative_rejects_stale_final_state() {
        let mut ch = open_channel();
        let signed = cosign(&ch, &update(1, 500_000, 500_000));
        ch.apply_update(&signed).unwrap();
        // Final state must move the channel forward, never replay it.
        let replay = cosign(&ch, &update(1, 900_000, 100_000));
        assert_eq!(
            ch.close_cooperative(&replay),
            Err(EscrowError::StaleChannelNonce)
        );
        assert_eq!(ch.state(), ChannelState::Open);
    }

    #[test]
    fn unilateral_close_opens_challenge_window() {
        let mut ch = open_channel();
        let signed = cosign(&ch, &update(1, 250_000, 750_000));
        let alice_key = alice().public_key();
        ch.close_unilateral(&alice_key, &signed, 1_000_000).unwrap();
        assert_eq!(ch.state(), ChannelState::UnilateralClosePending);
        assert_eq!(ch.challenge_until(), 1_000_000 + CHALLENGE_PERIOD);
        assert_eq!(ch.balances(), (250_000, 750_000));
        // Finalize before the window elapses is refused.
        assert_eq!(
            ch.finalize(1_000_000 + CHALLENGE_PERIOD - 1),
            Err(EscrowError::InvalidChannelState)
        );
        // At the boundary the window is over.
        let settlement = ch.finalize(1_000_000 + CHALLENGE_PERIOD).unwrap();
        assert_eq!(settlement, (250_000, 750_000));
        assert_eq!(ch.state(), ChannelState::Closed);
    }

    #[test]
    fn unilateral_close_rejects_stranger_submitter() {
        let mut ch = open_channel();
        let signed = cosign(&ch, &update(1, 250_000, 750_000));
        let mallory_key = mallory().public_key();
        assert_eq!(
            ch.close_unilateral(&mallory_key, &signed, 1_000_000),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(ch.state(), ChannelState::Open);
    }

    #[test]
    fn unilateral_close_rejects_unsigned_state() {
        let mut ch = open_channel();
        // Only Alice signed — a unilateral submitter cannot smuggle in
        // a state the counterparty never co-signed.
        let u = update(1, 0, TOTAL);
        let sig_a = sign_channel_update(&alice(), &u, ch.party_a(), ch.party_b(), ch.total());
        let half = SignedChannelUpdate::new(u, sig_a, [0u8; 64]);
        let alice_key = alice().public_key();
        assert_eq!(
            ch.close_unilateral(&alice_key, &half, 1_000_000),
            Err(EscrowError::InvalidChannelSignature)
        );
        assert_eq!(ch.state(), ChannelState::Open);
    }

    #[test]
    fn dispute_with_newer_state_replaces_and_restarts_window() {
        let mut ch = open_channel();
        let v1 = cosign(&ch, &update(1, 250_000, 750_000));
        let alice_key = alice().public_key();
        ch.close_unilateral(&alice_key, &v1, 1_000_000).unwrap();
        // Bob surfaces the newer co-signed state (nonce 2).
        let v2 = cosign(&ch, &update(2, 800_000, 200_000));
        let bob_key = bob().public_key();
        ch.dispute(&bob_key, &v2, 1_000_500).unwrap();
        assert_eq!(ch.balances(), (800_000, 200_000));
        assert_eq!(ch.nonce(), 2);
        // Window restarted at the dispute time.
        assert_eq!(ch.challenge_until(), 1_000_500 + CHALLENGE_PERIOD);
        // Old window expiry no longer finalizes.
        assert_eq!(
            ch.finalize(1_000_000 + CHALLENGE_PERIOD),
            Err(EscrowError::InvalidChannelState)
        );
        let settlement = ch.finalize(1_000_500 + CHALLENGE_PERIOD).unwrap();
        assert_eq!(settlement, (800_000, 200_000));
    }

    #[test]
    fn dispute_rejects_stale_and_late_states() {
        let mut ch = open_channel();
        let v1 = cosign(&ch, &update(1, 250_000, 750_000));
        let alice_key = alice().public_key();
        ch.close_unilateral(&alice_key, &v1, 1_000_000).unwrap();
        // Stale nonce is not a refutation.
        let stale = cosign(&ch, &update(1, 900_000, 100_000));
        let bob_key = bob().public_key();
        assert_eq!(
            ch.dispute(&bob_key, &stale, 1_000_500),
            Err(EscrowError::StaleChannelNonce)
        );
        // After the window, dispute is the wrong call — finalize.
        let v2 = cosign(&ch, &update(2, 800_000, 200_000));
        assert_eq!(
            ch.dispute(&bob_key, &v2, 1_000_000 + CHALLENGE_PERIOD),
            Err(EscrowError::InvalidChannelState)
        );
    }

    #[test]
    fn dispute_rejects_stranger_submitter() {
        let mut ch = open_channel();
        let v1 = cosign(&ch, &update(1, 250_000, 750_000));
        let alice_key = alice().public_key();
        ch.close_unilateral(&alice_key, &v1, 1_000_000).unwrap();
        let v2 = cosign(&ch, &update(2, 800_000, 200_000));
        let mallory_key = mallory().public_key();
        assert_eq!(
            ch.dispute(&mallory_key, &v2, 1_000_500),
            Err(EscrowError::Unauthorized)
        );
    }

    #[test]
    fn update_refused_once_closing() {
        let mut ch = open_channel();
        let v1 = cosign(&ch, &update(1, 250_000, 750_000));
        let alice_key = alice().public_key();
        ch.close_unilateral(&alice_key, &v1, 1_000_000).unwrap();
        let v2 = cosign(&ch, &update(2, 800_000, 200_000));
        // Off-chain updates are over once the on-chain close started —
        // the newer state must go through `dispute`.
        assert_eq!(
            ch.apply_update(&v2),
            Err(EscrowError::InvalidChannelState)
        );
        assert_eq!(
            ch.close_cooperative(&v2),
            Err(EscrowError::InvalidChannelState)
        );
    }

    #[test]
    fn challenge_period_overflow_is_config_error() {
        let mut ch = PaymentChannel::open(
            alice().public_key(),
            bob().public_key(),
            TOTAL,
            u64::MAX,
        )
        .unwrap();
        ch.fund(TOTAL).unwrap();
        let v1 = cosign(&ch, &update(1, TOTAL, 0));
        let alice_key = alice().public_key();
        // now + u64::MAX cannot be represented — the channel refuses
        // to open a window it cannot bound.
        assert_eq!(
            ch.close_unilateral(&alice_key, &v1, 1),
            Err(EscrowError::InvalidChannelConfig)
        );
        assert_eq!(ch.state(), ChannelState::Open);
    }
}
