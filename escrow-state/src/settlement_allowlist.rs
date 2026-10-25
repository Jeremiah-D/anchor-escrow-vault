//! Settlement-mint allowlist (AV-218).
//!
//! AV-217 lets an escrow settle in a mint other than the funded one
//! at a dual-signed rate — but it accepts *any* attested settlement
//! mint. A quote both parties signed is not, by itself, proof the
//! mint is one the initializer ever meant to pay out in: a
//! counterfeit or illiquid mint both parties were talked into
//! signing, or a quote replayed against a different deal's mint,
//! settles fine under AV-217. This module adds the initializer's
//! own gate on top: an opt-in, `Uninitialized`-only list of at most
//! 8 settlement mints the escrow will ever settle in.
//!
//! - [`SettlementMintAllowlist::new`]: the list itself — a fixed
//!   array of mint addresses plus a length, the AV-157
//!   `MintAllowlist` shape with a settlement-mint name. Empty,
//!   over-long, zero-address, and duplicate inputs are all
//!   fail-closed ([`EscrowError::InvalidSettlementMintAllowlist`]).
//!   An empty slice never reaches `new` through the builder: like
//!   [`Escrow::with_mint_allowlist`], an empty builder input means
//!   "allowlist off" (`None`), not "allowlist that allows nothing"
//!   — an empty allowlist that refused every settlement would be a
//!   footgun the initializer could not distinguish from a bug.
//! - [`require_settlement_mint_allowlisted`]: the gate, called by
//!   [`Escrow::release_with_settlement_rate`] *before*
//!   [`verify_settlement_rate`] — check order matters here. A
//!   quote for a non-allowlisted mint is refused with
//!   [`EscrowError::SettlementMintNotAllowlisted`] without ever
//!   entering rate verification or conversion pricing: the
//!   allowlist is a policy decision about the mint, not a
//!   statement about the quote, so a bad mint fails before any
//!   signature is checked and before any leg is priced. An
//!   escrow with no allowlist configured (`None`) skips the gate
//!   entirely — backward compatible, AV-217 semantics unchanged.
//!
//! What the gate does *not* do, stated plainly: it checks the
//! attestation's `settle_mint`, not the bound settlement mint.
//! That is sufficient, not sloppy — `verify_settlement_rate`
//! already requires the attestation's mint to equal the bound
//! mint, so a quote that passes the allowlist check and then
//! passes verification is necessarily a quote for an allowlisted
//! mint *and* the bound mint. Checking the bound mint separately
//! would add a second failure mode for the same refusal and
//! teach probers which check fired.
//!
//! Orthogonal to:
//!
//! - AV-217 (the conversion itself: this item gates which mints
//!   the conversion may settle in, it never reprices a leg);
//! - AV-16 (the funded-mint binding: this item constrains the
//!   payout denomination, never the funded mint — and the AV-16
//!   allowlist deliberately still does not apply here, it governs
//!   the funded mint);
//! - AV-49 (the payout-address allowlist: that gates *where* the
//!   payout goes, this gates *what asset* it is paid in —
//!   destination and denomination are independent axes, and a
//!   settled release must pass both when both are configured).
//!
//! Pure logic, zero dependencies: the escrow owns the storage
//! (one allowlist, appended to the vault layout after the AV-217
//! settlement mint); this module owns only the list shape, its
//! validation, and the gate.

use crate::EscrowError;

/// Maximum settlement mints on one allowlist (AV-218) — the AV-157
/// cap, because a settlement policy longer than a funded-mint
/// policy would be a second, looser governance surface for no
/// reason.
pub const MAX_SETTLEMENT_MINT_ALLOWLIST: usize = 8;

/// Serialized length of the mint array plus the entry count, before
/// the `Option` discriminant: 8 slots of 32 bytes + 1 count byte.
pub const SETTLEMENT_MINT_ALLOWLIST_LEN: usize = MAX_SETTLEMENT_MINT_ALLOWLIST * 32 + 1;

/// The opt-in settlement-mint allowlist (AV-218).
///
/// Only `mints[..len as usize]` are meaningful; the tail is zeroed,
/// the AV-157 convention — so a decoded allowlist and a built one
/// compare equal, and a stale tail slot can never smuggle a mint
/// back onto the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettlementMintAllowlist {
    /// The allowlisted mints; only the first `len` entries count.
    pub mints: [[u8; 32]; MAX_SETTLEMENT_MINT_ALLOWLIST],
    /// How many mints are allowlisted.
    pub len: u8,
}

impl SettlementMintAllowlist {
    /// Build from a slice, validating length, zero addresses, and
    /// duplicates. An empty slice, more than
    /// [`MAX_SETTLEMENT_MINT_ALLOWLIST`] entries, a zero address,
    /// or a repeated address are all
    /// [`EscrowError::InvalidSettlementMintAllowlist`]: a policy
    /// that cannot be stated exactly is refused at configuration
    /// time, never interpreted loosely at settlement time.
    pub fn new(mints: &[[u8; 32]]) -> Result<Self, EscrowError> {
        if mints.is_empty() || mints.len() > MAX_SETTLEMENT_MINT_ALLOWLIST {
            return Err(EscrowError::InvalidSettlementMintAllowlist);
        }
        if mints.iter().any(|m| *m == [0u8; 32]) {
            return Err(EscrowError::InvalidSettlementMintAllowlist);
        }
        for (i, m) in mints.iter().enumerate() {
            if mints[..i].contains(m) {
                return Err(EscrowError::InvalidSettlementMintAllowlist);
            }
        }
        let mut out = [[0u8; 32]; MAX_SETTLEMENT_MINT_ALLOWLIST];
        out[..mints.len()].copy_from_slice(mints);
        Ok(Self {
            mints: out,
            len: mints.len() as u8,
        })
    }

    /// The allowlisted mints as a slice.
    pub fn as_slice(&self) -> &[[u8; 32]] {
        &self.mints[..self.len as usize]
    }

    /// True when `mint` is allowlisted.
    pub fn contains(&self, mint: &[u8; 32]) -> bool {
        self.as_slice().contains(mint)
    }
}

/// The AV-218 gate: when an allowlist is configured, the
/// attestation's settlement mint must be on it, or the settled
/// release is refused with
/// [`EscrowError::SettlementMintNotAllowlisted`] before any rate
/// verification or conversion pricing runs. `None` (no allowlist
/// configured) passes silently — the gate is opt-in.
pub fn require_settlement_mint_allowlisted(
    allowlist: Option<&SettlementMintAllowlist>,
    settle_mint: &[u8; 32],
) -> Result<(), EscrowError> {
    if let Some(list) = allowlist {
        if !list.contains(settle_mint) {
            return Err(EscrowError::SettlementMintNotAllowlisted);
        }
    }
    Ok(())
}
