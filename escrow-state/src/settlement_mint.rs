//! Settlement-mint conversion (AV-217).
//!
//! An escrow locks one mint (AV-16), but the parties may want to
//! settle in another: the taker is paid in a settlement mint at an
//! agreed rate instead of the funded mint. This module adds that
//! conversion as an opt-in, `Uninitialized`-only settlement mint
//! on the escrow plus a dual-signed rate attestation verified on
//! every settled release:
//!
//! - [`SettlementRateAttestation`]: the rate quote — the
//!   settlement mint, a rational rate (`numerator` /
//!   `denominator`, settle units per funded unit), an expiry,
//!   and one Ed25519 signature from each party over the
//!   canonical message. The rate may be sourced from an AV-193
//!   oracle feed quote off chain; the gate verifies the
//!   parties' signatures over that quote, so an oracle quote the
//!   parties never signed settles nothing.
//! - [`verify_settlement_rate`]: the gate. Expiry first (a stale
//!   quote is stale whatever it says), the settlement-mint
//!   binding second, a zero denominator third, the two
//!   signatures last — the AV-210 check order, because a
//!   signature over the wrong terms proves nothing.
//! - [`SettlementRate::convert`]: the conversion itself —
//!   `floor(funded * numerator / denominator)` in `u128`
//!   (`u64::MAX * u64::MAX < u128::MAX`, so the product cannot
//!   wrap, and the floored quotient fits `u64` whenever the rate
//!   is sane; a rate that would overflow the settle leg is a
//!   caller error the gate does not bless — see below).
//!
//! Rounding rule (fixed, never improvised): floor, per leg.
//! The settled release converts each leg independently — the
//! taker payout, the protocol fee, and the late-delivery penalty
//! — and each conversion floors. The dust (under one settle
//! unit per leg) stays with the vault: the funded-unit
//! conservation identity (`released + penalty_paid +
//! remaining == lockup`) remains the audited identity, and the
//! settle-unit legs are transfer sizings, not a second ledger.
//! A rate is only as good as its attestation: the settled
//! release re-verifies the attestation on every call, and
//! attestations are reusable within their validity window — a
//! rate quote, not a one-time voucher (unlike the AV-210
//! milestone attestation, which authorizes exactly one tranche).
//! Expiry bounds the reuse window; a quote presented after its
//! own `expires_at` is refused outright.
//!
//! Fail-closed, in order: no settlement mint bound, no
//! attestation (the settled path is the only path that reads
//! one — plain `release` never looks at it), an expired quote,
//! a quote for the wrong settlement mint, a zero denominator,
//! or either signature failing all refuse before any gate runs
//! and before any fee is charged — a refused settled release
//! moves nothing. The funded-mint binding (AV-16) still gates
//! the funded leg: the caller passes the funded mint exactly
//! like a plain `release`, and the settlement mint binds only
//! the payout denomination.
//!
//! Orthogonal to:
//!
//! - AV-113 / AV-193 (the oracle price gate decides whether a
//!   payout may happen at all — this item decides what currency
//!   and amount it settles in; a price-gated escrow still needs
//!   its gate to pass, and the settled path runs the same
//!   `release` guard chain underneath);
//! - AV-16 (the escrow binds a single funded mint — this item
//!   does not rebind it, it redenominates the payout);
//! - AV-206 / AV-216 (milestone and delivery lateness price in
//!   funded units first; the settled path converts the priced
//!   legs, it never reprices them);
//! - AV-191 (the referral share is part of the returned fee
//!   leg, converted like the rest of the fee — the settled
//!   release does not split referral from protocol fee).
//!
//! Pure logic, zero dependencies: the escrow owns the storage
//! (one settlement-mint pubkey, appended to the vault layout);
//! this module owns only the attestation shape, the gate, and
//! the conversion math.

use crate::{ed25519::verify as ed25519_verify, EscrowError};

/// Domain separator for the settlement-rate message.
pub const SETTLEMENT_RATE_DOMAIN: &[u8] = b"escrow-settlement-rate/v1";

/// One dual-signed settlement-rate quote (AV-217).
///
/// `settle_mint` is the payout denomination this quote prices;
/// `numerator` / `denominator` is the rate in settle units per
/// funded unit (so `numerator = 3, denominator = 2` means one
/// funded unit settles as 1.5 settle units); `expires_at` is
/// the quote's own deadline (valid through this instant, expired
/// after — the AV-206 strict-after convention); the two
/// signatures are the initializer's and the taker's Ed25519
/// signatures over [`settlement_rate_message`] of these fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementRateAttestation {
    /// The settlement mint this quote prices.
    pub settle_mint: [u8; 32],
    /// Rate numerator (settle units per `denominator` funded units).
    pub numerator: u64,
    /// Rate denominator (funded units per `numerator` settle units).
    pub denominator: u64,
    /// Unix timestamp: valid through this instant, expired after.
    pub expires_at: u64,
    /// The initializer's Ed25519 signature over the message.
    pub initializer_signature: [u8; 64],
    /// The taker's Ed25519 signature over the message.
    pub taker_signature: [u8; 64],
}

/// The canonical attestation message: `domain || settle_mint ||
/// numerator || denominator || expires_at`, all integers
/// little-endian. Both parties sign exactly these bytes; anything
/// else either party signed is not a quote for this gate.
pub fn settlement_rate_message(attestation: &SettlementRateAttestation) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        SETTLEMENT_RATE_DOMAIN.len() + 32 + 8 + 8 + 8,
    );
    bytes.extend_from_slice(SETTLEMENT_RATE_DOMAIN);
    bytes.extend_from_slice(&attestation.settle_mint);
    bytes.extend_from_slice(&attestation.numerator.to_le_bytes());
    bytes.extend_from_slice(&attestation.denominator.to_le_bytes());
    bytes.extend_from_slice(&attestation.expires_at.to_le_bytes());
    bytes
}

/// A verified settlement rate (AV-217): the rational conversion
/// factor, stripped of the attestation that carried it. Only
/// [`verify_settlement_rate`] constructs one from an
/// attestation, so a `SettlementRate` in hand always passed the
/// expiry, mint-binding, denominator, and dual-signature checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementRate {
    /// Rate numerator (settle units per `denominator` funded units).
    pub numerator: u64,
    /// Rate denominator (funded units per `numerator` settle units).
    pub denominator: u64,
}

impl SettlementRate {
    /// Convert one funded-unit amount to settle units (AV-217):
    /// `floor(funded * numerator / denominator)` in `u128`.
    /// The product cannot wrap (`u64::MAX * u64::MAX` is below
    /// `u128::MAX`), and the quotient is downcast exactly — a
    /// rate whose converted leg would exceed `u64::MAX` is a
    /// caller error the gate does not bless, and this cast
    /// saturates rather than wraps on such a pathological rate.
    pub fn convert(&self, funded: u64) -> u64 {
        let converted = (funded as u128 * self.numerator as u128) / self.denominator as u128;
        u64::try_from(converted).unwrap_or(u64::MAX)
    }
}

/// The settled release's sizing (AV-217): every leg in
/// settlement-mint units, converted from the funded-unit
/// settlement the `release` guard chain produced. `payout` is
/// what the taker receives, `fee` the protocol fee leg (the
/// AV-191 referral share rides inside it, converted like the
/// rest), `penalty` the late-delivery penalty leg (AV-216, or
/// zero when no late confirmation was recorded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettledRelease {
    /// The taker's payout, in settlement-mint units.
    pub payout: u64,
    /// The protocol fee leg, in settlement-mint units.
    pub fee: u64,
    /// The late-delivery penalty leg, in settlement-mint units.
    pub penalty: u64,
    /// The settlement mint these legs are denominated in.
    pub settle_mint: [u8; 32],
}

/// Verify one settlement-rate attestation (AV-217) against the
/// escrow's live bindings. `settlement_mint` is the mint the
/// escrow bound via `with_settlement_mint`, `initializer` /
/// `taker` the escrow's parties, `now` the release time.
/// Expiry first, mint binding second, denominator third,
/// signatures last — the AV-210 order, for the same reason: a
/// signature over the wrong terms proves nothing, so it is
/// only meaningful once the bindings match. Returns the
/// verified [`SettlementRate`] on success; every failure is
/// one of the `SettlementRate*` errors, never a panic.
pub fn verify_settlement_rate(
    settlement_mint: [u8; 32],
    initializer: [u8; 32],
    taker: [u8; 32],
    attestation: &SettlementRateAttestation,
    now: u64,
) -> Result<SettlementRate, EscrowError> {
    // Expiry first: a stale quote is stale whatever it says.
    if now > attestation.expires_at {
        return Err(EscrowError::SettlementRateExpired);
    }
    // Binding second: the quote must price the escrow's own
    // settlement mint — a quote for another mint is not a quote
    // for this escrow, however well signed.
    if attestation.settle_mint != settlement_mint {
        return Err(EscrowError::SettlementRateInvalid);
    }
    // A zero denominator is not a rate (division by zero has no
    // conversion, and a quote that divides by zero prices
    // nothing).
    if attestation.denominator == 0 {
        return Err(EscrowError::SettlementRateInvalid);
    }
    // Signatures last: both parties must have signed these
    // exact terms. Either failure is the same error, so a
    // prober learns nothing about which party's signature
    // failed.
    let message = settlement_rate_message(attestation);
    if !ed25519_verify(&initializer, &message, &attestation.initializer_signature)
        || !ed25519_verify(&taker, &message, &attestation.taker_signature)
    {
        return Err(EscrowError::SettlementRateInvalid);
    }
    Ok(SettlementRate {
        numerator: attestation.numerator,
        denominator: attestation.denominator,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_floors_in_u128() {
        let rate = SettlementRate {
            numerator: 1,
            denominator: 3,
        };
        // floor(1000 / 3) = 333, not 334.
        assert_eq!(rate.convert(1_000), 333);
        assert_eq!(rate.convert(0), 0);
        let rate = SettlementRate {
            numerator: 3,
            denominator: 2,
        };
        assert_eq!(rate.convert(1_000), 1_500);
        // u64::MAX-scale products never wrap the u128 math.
        let rate = SettlementRate {
            numerator: u64::MAX,
            denominator: u64::MAX,
        };
        assert_eq!(rate.convert(u64::MAX), u64::MAX);
    }
}
