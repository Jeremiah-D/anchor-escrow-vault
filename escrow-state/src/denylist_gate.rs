//! Denylist-gated release (AV-213).
//!
//! The escrow already knows one denylist: AV-96's persisted payout
//! denylist, bound at initialize time (or changed later by the
//! initializer alone) and checked inside
//! [`Escrow::require_payout_recipient`](crate::Escrow::require_payout_recipient).
//! That list answers "which *recipients* may never be paid", and it
//! is fixed by governance. What it cannot answer is the release-time
//! question: a compliance list that arrived *after* initialization —
//! a sanctions list refreshed yesterday, an intermediary mint flagged
//! this morning — that must block today's release whether or not
//! anyone re-governed the escrow. This module is that gate, as a
//! pure-logic sidecar the release caller consults *before* any other
//! release gate runs.
//!
//! Two legs, one verdict:
//!
//! - *Recipient leg.* The caller-supplied denied recipients. This
//!   overlaps AV-96 in effect but differs in source and timing: the
//!   AV-96 list is the escrow's own persisted veto, this list is the
//!   caller's release-time list, and either one denies. The two
//!   compose — see [`Escrow::check_denylist_gate`](crate::Escrow::check_denylist_gate),
//!   which checks the stored list first, then this gate — never a
//!   choice between them.
//! - *Mint leg.* The denied settlement / intermediate mints. This leg
//!   is entirely new: no mint denylist exists anywhere in the crate
//!   (AV-157's mint allowlist is the mirror image — only listed
//!   mints may settle — and AV-96's denylist names recipients, never
//!   mints). A basket or swap release whose intermediate mint is
//!   denied is denied as a whole, not leg by leg: a denied mint in
//!   one leg must not be laundered through the other legs.
//!
//! Check order is deliberate and total: recipient first, then mint,
//! then nothing else — this gate is the *first* gate, before
//! authority, cap, timelock, quorum and the AV-49 allowlist, so a
//! denied release fails fast, settles nothing and charges no fee.
//! A caller that needs to know *which* leg denied (for an operator
//! report, not for a second chance — a denial is final for this
//! release) uses [`DenylistGate::denied_target`] before
//! [`DenylistGate::check_release`]; the two agree by construction.
//!
//! No new error code. Both legs deny with the code AV-96 already
//! assigned to a denylist denial, [`EscrowError::PayoutDenied`]:
//! the verdict *is* "this release's payout is denied", and the leg
//! is carried by [`DeniedTarget`], not by minting a code that would
//! force an IDL regeneration and a layout pin change for a
//! distinction the caller can already read. A denied mint is not
//! reported as `MintNotAllowlisted` — that code means "mint not on
//! the AV-157 allowlist", a different gate with a different
//! remedy, and conflating the two would mislead a client matching
//! on codes.
//!
//! What this module deliberately does *not* do: it stores nothing
//! on the Vault, so there is no layout change, no `VAULT_SPACE`
//! bump and no IDL regeneration — the gate is supplied per release,
//! like AV-211's inspection sidecar. The Anchor instruction that
//! passes the program's release-time compliance list through this
//! gate before calling `release` is follow-up work, exactly like
//! the AV-206 / AV-208 / AV-210 program-side notes; the pure-logic
//! gate here is complete and tested, and the README states the
//! boundary rather than claiming an instruction that does not
//! exist yet.
//!
//! Orthogonal to AV-49 (allowlist: only listed recipients may be
//! paid — deny takes precedence over allow, so a recipient on both
//! lists is still denied), to AV-212 (the taker's identity
//! credential — this gate looks at the *destination and the asset*,
//! never at who the taker claims to be), and to AV-157 (mint
//! allowlist: a mint can be allowlisted and still denied here —
//! deny wins, by the same precedence AV-96 established).

use crate::EscrowError;

/// Maximum denied recipients in one gate, mirroring
/// [`MAX_PAYOUT_DENYLIST`](crate::MAX_PAYOUT_DENYLIST) (AV-96):
/// a gate wider than the persisted denylist would be a second,
/// looser vocabulary for the same concept.
pub const MAX_DENYLIST_GATE_RECIPIENTS: usize = 4;

/// Maximum denied mints in one gate, mirroring
/// [`MAX_MINT_ALLOWLIST`](crate::MAX_MINT_ALLOWLIST) (AV-157):
/// the mint list is a compliance list, not an inventory, so the
/// allowlist's width is the right ceiling.
pub const MAX_DENYLIST_GATE_MINTS: usize = 8;

/// Which leg of a [`DenylistGate`] denied a release, as reported
/// by [`DenylistGate::denied_target`]. The error itself is always
/// [`EscrowError::PayoutDenied`]; this enum is the diagnostic that
/// says which list fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeniedTarget {
    /// The payout recipient is on the gate's denied-recipient list
    /// (checked first).
    Recipient,
    /// The settlement / intermediate mint is on the gate's
    /// denied-mint list (checked second).
    Mint,
}

/// A release-time denylist: caller-supplied denied recipients and
/// denied mints, checked before every other release gate.
///
/// Fixed-size so the crate stays heap-free and `Copy`, like the
/// AV-96 / AV-157 lists it mirrors. A gate that denies nothing is
/// refused at construction — a gate that can never fire is a
/// configuration mistake wearing a gate's name, and a release
/// caller that meant to deny something must not silently hold an
/// empty list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenylistGate {
    recipients: [[u8; 32]; MAX_DENYLIST_GATE_RECIPIENTS],
    recipient_len: usize,
    mints: [[u8; 32]; MAX_DENYLIST_GATE_MINTS],
    mint_len: usize,
}

impl DenylistGate {
    /// Build a gate from its two lists. Either list may be empty,
    /// but not both; a zero address in either list is refused (the
    /// zero key is no recipient and no mint, so it could never be
    /// a real denial — binding it would be a silent no-op entry);
    /// duplicates are refused (a list that says the same denial
    /// twice is a list nobody audited); over-long lists are
    /// refused with the code of the list they overflow.
    pub fn new(
        recipients: &[[u8; 32]],
        mints: &[[u8; 32]],
    ) -> Result<Self, EscrowError> {
        if recipients.is_empty() && mints.is_empty() {
            return Err(EscrowError::InvalidPayoutDenylist);
        }
        if recipients.len() > MAX_DENYLIST_GATE_RECIPIENTS {
            return Err(EscrowError::InvalidPayoutDenylist);
        }
        if mints.len() > MAX_DENYLIST_GATE_MINTS {
            return Err(EscrowError::InvalidMint);
        }
        let mut gate = DenylistGate {
            recipients: [[0u8; 32]; MAX_DENYLIST_GATE_RECIPIENTS],
            recipient_len: 0,
            mints: [[0u8; 32]; MAX_DENYLIST_GATE_MINTS],
            mint_len: 0,
        };
        for (i, addr) in recipients.iter().enumerate() {
            if *addr == [0u8; 32] {
                return Err(EscrowError::InvalidPayoutDenylist);
            }
            if gate.recipients[..i].contains(addr) {
                return Err(EscrowError::InvalidPayoutDenylist);
            }
            gate.recipients[i] = *addr;
            gate.recipient_len += 1;
        }
        for (i, mint) in mints.iter().enumerate() {
            if *mint == [0u8; 32] {
                return Err(EscrowError::InvalidMint);
            }
            if gate.mints[..i].contains(mint) {
                return Err(EscrowError::InvalidMint);
            }
            gate.mints[i] = *mint;
            gate.mint_len += 1;
        }
        Ok(gate)
    }

    /// The denied recipients, in construction order.
    pub fn recipients(&self) -> &[[u8; 32]] {
        &self.recipients[..self.recipient_len]
    }

    /// The denied mints, in construction order.
    pub fn mints(&self) -> &[[u8; 32]] {
        &self.mints[..self.mint_len]
    }

    /// Whether `recipient` is on the denied-recipient list.
    pub fn contains_recipient(&self, recipient: &[u8; 32]) -> bool {
        self.recipients().contains(recipient)
    }

    /// Whether `mint` is on the denied-mint list.
    pub fn contains_mint(&self, mint: &[u8; 32]) -> bool {
        self.mints().contains(mint)
    }

    /// Which leg denies this release, if any: the recipient first,
    /// then the mint. `mint` is `None` for a native (no-mint)
    /// release, where only the recipient leg can fire. This is a
    /// pure query — it never denies by itself; use
    /// [`check_release`](Self::check_release) for the verdict.
    pub fn denied_target(
        &self,
        recipient: &[u8; 32],
        mint: Option<&[u8; 32]>,
    ) -> Option<DeniedTarget> {
        if self.contains_recipient(recipient) {
            return Some(DeniedTarget::Recipient);
        }
        if let Some(mint) = mint {
            if self.contains_mint(mint) {
                return Some(DeniedTarget::Mint);
            }
        }
        None
    }

    /// The release verdict: `PayoutDenied` when either leg fires,
    /// in recipient-then-mint order. Call this before every other
    /// release gate — a denial here must not be preceded by a fee,
    /// a cap or a timelock decision that could leak whether the
    /// release would otherwise have succeeded.
    pub fn check_release(
        &self,
        recipient: &[u8; 32],
        mint: Option<&[u8; 32]>,
    ) -> Result<(), EscrowError> {
        match self.denied_target(recipient, mint) {
            Some(_) => Err(EscrowError::PayoutDenied),
            None => Ok(()),
        }
    }

    /// The multi-leg verdict for basket / swap releases: every leg
    /// mint is checked, and one denied mint denies the whole
    /// release — a denied asset must not be laundered through the
    /// clean legs. An empty leg list passes: there is no asset to
    /// deny. (Recipient checks stay per release, not per leg: the
    /// legs share one payout destination policy.)
    pub fn check_mints(&self, mints: &[[u8; 32]]) -> Result<(), EscrowError> {
        for mint in mints {
            if self.contains_mint(mint) {
                return Err(EscrowError::PayoutDenied);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Escrow;

    const ALICE: [u8; 32] = [0x11; 32];
    const BOB: [u8; 32] = [0x22; 32];
    const MALLORY: [u8; 32] = [0x33; 32];
    const MINT_A: [u8; 32] = [0xaa; 32];
    const MINT_B: [u8; 32] = [0xbb; 32];

    #[test]
    fn construction_validates_both_lists() {
        // Empty gate: a gate that denies nothing is refused.
        assert_eq!(
            DenylistGate::new(&[], &[]),
            Err(EscrowError::InvalidPayoutDenylist)
        );
        // Zero addresses are refused, per list, with that list's code.
        assert_eq!(
            DenylistGate::new(&[[0u8; 32]], &[]),
            Err(EscrowError::InvalidPayoutDenylist)
        );
        assert_eq!(
            DenylistGate::new(&[], &[[0u8; 32]]),
            Err(EscrowError::InvalidMint)
        );
        // Duplicates are refused, per list.
        assert_eq!(
            DenylistGate::new(&[ALICE, ALICE], &[]),
            Err(EscrowError::InvalidPayoutDenylist)
        );
        assert_eq!(
            DenylistGate::new(&[], &[MINT_A, MINT_A]),
            Err(EscrowError::InvalidMint)
        );
        // Over-long lists are refused, per list.
        assert_eq!(
            DenylistGate::new(&[[0x01; 32]; MAX_DENYLIST_GATE_RECIPIENTS + 1], &[]),
            Err(EscrowError::InvalidPayoutDenylist)
        );
        assert_eq!(
            DenylistGate::new(&[], &[[0x01; 32]; MAX_DENYLIST_GATE_MINTS + 1]),
            Err(EscrowError::InvalidMint)
        );
        // Either list alone is a valid gate.
        assert!(DenylistGate::new(&[ALICE], &[]).is_ok());
        assert!(DenylistGate::new(&[], &[MINT_A]).is_ok());
    }

    #[test]
    fn recipient_checked_before_mint() {
        let gate = DenylistGate::new(&[ALICE], &[MINT_A]).unwrap();
        // Both legs fire: the recipient wins, deterministically.
        assert_eq!(
            gate.denied_target(&ALICE, Some(&MINT_A)),
            Some(DeniedTarget::Recipient)
        );
        assert_eq!(
            gate.check_release(&ALICE, Some(&MINT_A)),
            Err(EscrowError::PayoutDenied)
        );
        // Mint alone fires only when the recipient is clean.
        assert_eq!(
            gate.denied_target(&BOB, Some(&MINT_A)),
            Some(DeniedTarget::Mint)
        );
        // Native release (no mint): only the recipient leg can fire.
        assert_eq!(gate.denied_target(&BOB, None), None);
        assert!(gate.check_release(&BOB, None).is_ok());
        // Clean recipient, clean mint: the release passes the gate.
        assert!(gate.check_release(&BOB, Some(&MINT_B)).is_ok());
    }

    #[test]
    fn one_denied_leg_mint_denies_the_whole_release() {
        let gate = DenylistGate::new(&[], &[MINT_B]).unwrap();
        assert!(gate.check_mints(&[MINT_A]).is_ok());
        assert_eq!(
            gate.check_mints(&[MINT_A, MINT_B]),
            Err(EscrowError::PayoutDenied)
        );
        assert!(gate.check_mints(&[]).is_ok());
    }

    #[test]
    fn stored_and_supplied_denylists_compose_on_the_escrow() {
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, 10_000)
            .and_then(|esc| esc.with_denylist(&[MALLORY]))
            .unwrap();
        let gate = DenylistGate::new(&[BOB], &[MINT_A]).unwrap();
        // The stored AV-96 veto fires even when the supplied gate
        // would pass this recipient.
        assert_eq!(
            e.check_denylist_gate(&gate, MALLORY, Some(MINT_B)),
            Err(EscrowError::PayoutDenied)
        );
        // The supplied gate's recipient leg fires.
        assert_eq!(
            e.check_denylist_gate(&gate, BOB, Some(MINT_B)),
            Err(EscrowError::PayoutDenied)
        );
        // The supplied gate's mint leg fires.
        assert_eq!(
            e.check_denylist_gate(&gate, ALICE, Some(MINT_A)),
            Err(EscrowError::PayoutDenied)
        );
        // Clean on every list: the pre-screen passes.
        assert!(e.check_denylist_gate(&gate, ALICE, Some(MINT_B)).is_ok());
        assert!(e.check_denylist_gate(&gate, ALICE, None).is_ok());
    }
}
