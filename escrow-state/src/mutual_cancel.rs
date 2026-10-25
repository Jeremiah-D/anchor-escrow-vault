//! Mutual cancel by dual-party agreement (AV-219).
//!
//! The unilateral exits already cover one party acting alone:
//! [`Escrow::cancel`] is the initializer's own unwind, and
//! [`Escrow::cancel_expired`] / [`Escrow::crank_expired`] are the
//! time-triggered exits. What none of them covers is the clean
//! case: both parties agree the deal is off *before* expiry, and
//! neither wants to wait for the clock or to force the other's
//! hand. A taker who wants out today has no honest path — the
//! initializer's unilateral cancel is not theirs to call, and
//! the expiry cancel is not yet eligible — so the pair is stuck
//! negotiating off-chain while funds sit locked. This module
//! adds the agreed exit.
//!
//! - [`MutualCancelAgreement`]: the two signatures the transition
//!   requires — the initializer's and the taker's, each an
//!   `Option` so the Anchor layer can pass "this party did not
//!   sign" through as `None` instead of inventing a key. The
//!   shape is deliberately not two bare keys: a bare-key
//!   signature cannot express absence, and absence is exactly
//!   the case this item refuses.
//! - [`require_mutual_cancel_agreement`]: the gate, called by
//!   [`Escrow::mutual_cancel`] before any state check — check
//!   order matters here. A missing party (`None`) or a stranger
//!   (`Some` key that is not the bound party) is
//!   [`EscrowError::Unauthorized`], and the gate runs before
//!   the state gate, so a stranger never learns whether an
//!   escrow is `Funded` from the error alone — the
//!   `cancel_expired` convention, applied to the agreement
//!   instead of the caller.
//!
//! What agreement does *not* mean, stated plainly:
//!
//! - An AV-104 CANCEL-scoped operator does not satisfy either
//!   side. The unilateral cancel delegates; the mutual cancel
//!   does not — termination by agreement is a personal act of
//!   both parties, and an operator key is a stranger to this
//!   gate even when it could call `cancel` alone. A delegated
//!   initializer who wants out unilaterally still has `cancel`;
//!   the mutual path is for the two parties themselves.
//! - One party's agreement is not enough. A call carrying only
//!   the initializer's signature is the unilateral cancel
//!   wearing a mutual-cancel name, and it is refused with
//!   `Unauthorized` — the taker's absence is a refusal, not a
//!   default-to-yes. Symmetrically, the taker alone cannot
//!   force the initializer out either.
//!
//! Settlement follows the unilateral cancel, not a new split:
//! the escrow moves `Funded -> Cancelled`, the outstanding
//! yield claim is voided (AV-107, like `cancel`), and the
//! remainder unwinds bilaterally (AV-148) — the initializer's
//! leg to the AV-23 refund policy destination
//! ([`Escrow::refund_recipient`]: the whitelisted address when
//! configured, otherwise the initializer), the taker's leg
//! back to the taker. No AV-24 anti-griefing penalty: the
//! penalty prices a *taker-initiated unilateral* expiry exit,
//! and a cancel both parties signed is not griefing. On a
//! plain single-funded escrow the taker's leg is zero, so the
//! entire remainder returns to the initializer through the
//! AV-23 destination — the backlog's "funds return to the
//! initializer" is the common case of the bilateral rule, not
//! a confiscation of a taker's collateral on a bilateral
//! escrow.
//!
//! Orthogonal to:
//!
//! - `cancel` (the initializer's unilateral unwind: one
//!   signature, one party's decision — this item needs two);
//! - `cancel_expired` / `crank_expired` (time-triggered: the
//!   clock decides, not the parties — this item needs no
//!   expiry, and refuses nothing for being early);
//! - AV-130 (maker-checker on the *release* intent: a second
//!   pair of eyes on paying out — this item terminates the
//!   escrow, it never pays the taker);
//! - AV-52 (taker rotation: the counterparty identity changes
//!   while the deal lives — this item ends the deal, and the
//!   rotated taker is simply the taker whose agreement counts).
//!
//! Pure logic, zero dependencies: the escrow owns no new
//! storage (no agreement field is persisted — the agreement
//! is a call-time fact, like the AV-130 checker's approval,
//! not vault state); this module owns only the agreement
//! shape and its gate, and [`Escrow::mutual_cancel`] owns the
//! transition. No new error code: `Unauthorized` for a
//! missing or stranger party, `InvalidStateTransition`
//! outside `Funded` — so no error-count pin, IDL range, or
//! IDL JSON changes, and nothing is renumbered.

use crate::EscrowError;

/// The dual-party agreement a mutual cancel requires (AV-219).
///
/// Each side is an `Option` so absence is expressible: `None`
/// means "this party did not sign", never a zero key standing
/// in for a missing signature. The Anchor layer passes the
/// transaction's signer keys through (or `None` when a party
/// is not a signer on the call); the pure-logic gate below
/// compares them against the bound parties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutualCancelAgreement {
    /// The initializer's signer key, or `None` if absent.
    pub initializer_signer: Option<[u8; 32]>,
    /// The taker's signer key, or `None` if absent.
    pub taker_signer: Option<[u8; 32]>,
}

impl MutualCancelAgreement {
    /// Build from the two optional signer keys.
    pub fn new(
        initializer_signer: Option<[u8; 32]>,
        taker_signer: Option<[u8; 32]>,
    ) -> Self {
        Self {
            initializer_signer,
            taker_signer,
        }
    }

    /// The both-signed case: each party present with their own key.
    pub fn both(initializer: [u8; 32], taker: [u8; 32]) -> Self {
        Self {
            initializer_signer: Some(initializer),
            taker_signer: Some(taker),
        }
    }

    /// The initializer-only case: the unilateral attempt this item
    /// refuses — the taker is absent, not defaulted to yes.
    pub fn initializer_only(initializer: [u8; 32]) -> Self {
        Self {
            initializer_signer: Some(initializer),
            taker_signer: None,
        }
    }

    /// The taker-only case: the mirror unilateral attempt.
    pub fn taker_only(taker: [u8; 32]) -> Self {
        Self {
            initializer_signer: None,
            taker_signer: Some(taker),
        }
    }
}

/// The AV-219 gate: both bound parties must be present, and each
/// present key must be that party's own key. A missing party
/// (`None` on either side) or a stranger key on either side is
/// [`EscrowError::Unauthorized`] — independent `==` checks, not
/// `||`, so a call that is wrong on both sides still reports
/// the same single refusal and leaks nothing about which side
/// failed. An AV-104 operator key is a stranger here by
/// construction: it equals neither bound party, so delegation
/// never satisfies the agreement.
pub fn require_mutual_cancel_agreement(
    agreement: &MutualCancelAgreement,
    initializer: &[u8; 32],
    taker: &[u8; 32],
) -> Result<(), EscrowError> {
    if agreement.initializer_signer != Some(*initializer) {
        return Err(EscrowError::Unauthorized);
    }
    if agreement.taker_signer != Some(*taker) {
        return Err(EscrowError::Unauthorized);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Escrow, EscrowState};

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const REFUND_TO: [u8; 32] = [0xDD; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn funded_escrow() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        e
    }

    #[test]
    fn both_parties_agree_cancels_and_refunds_to_initializer() {
        let mut e = funded_escrow();
        let (initializer_refund, taker_refund) = e
            .mutual_cancel(MutualCancelAgreement::both(ALICE, BOB), None, 0)
            .unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        // Plain single-funded escrow: the taker's leg is zero, so
        // the entire remainder returns to the initializer through
        // the AV-23 destination (here the initializer himself, no
        // whitelist configured).
        assert_eq!(initializer_refund, 1_000_000);
        assert_eq!(taker_refund, 0);
        assert_eq!(e.refund_recipient(), ALICE);
        assert_eq!(e.amount(), 1_000_000);
        assert_eq!(e.remaining_amount(), 1_000_000);
    }

    #[test]
    fn whitelisted_refund_destination_is_the_av23_recipient() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_refund_address(REFUND_TO)
            .unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        let (initializer_refund, taker_refund) = e
            .mutual_cancel(MutualCancelAgreement::both(ALICE, BOB), None, 0)
            .unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        assert_eq!(initializer_refund, 1_000_000);
        assert_eq!(taker_refund, 0);
        // The initializer's leg is addressed to the AV-23 whitelist
        // destination, not to the initializer personally.
        assert_eq!(e.refund_recipient(), REFUND_TO);
    }

    #[test]
    fn bilateral_escrow_returns_each_leg_home() {
        let mut e = funded_escrow();
        e.fund_taker(BOB, 200_000, EXPIRES_AT - 3_600).unwrap();
        let (initializer_refund, taker_refund) = e
            .mutual_cancel(MutualCancelAgreement::both(ALICE, BOB), None, 0)
            .unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        // AV-148 bilateral unwind, same as `cancel`: the taker's
        // collateral is not confiscated by the agreement — each
        // party's leg returns along its own route.
        assert_eq!(initializer_refund, 1_000_000);
        assert_eq!(taker_refund, 200_000);
    }

    #[test]
    fn missing_taker_is_unauthorized_and_moves_nothing() {
        let mut e = funded_escrow();
        assert_eq!(
            e.mutual_cancel(MutualCancelAgreement::initializer_only(ALICE), None, 0),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn missing_initializer_is_unauthorized() {
        let mut e = funded_escrow();
        assert_eq!(
            e.mutual_cancel(MutualCancelAgreement::taker_only(BOB), None, 0),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn stranger_on_either_side_is_unauthorized() {
        let mut e = funded_escrow();
        assert_eq!(
            e.mutual_cancel(MutualCancelAgreement::both(MALLORY, BOB), None, 0),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            e.mutual_cancel(MutualCancelAgreement::both(ALICE, MALLORY), None, 0),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            e.mutual_cancel(MutualCancelAgreement::both(MALLORY, MALLORY), None, 0),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn unilateral_only_agreement_is_rejected() {
        // The initializer signing alone is the unilateral cancel
        // wearing a mutual-cancel name: refused, not upgraded.
        let mut e = funded_escrow();
        assert_eq!(
            e.mutual_cancel(
                MutualCancelAgreement::new(Some(ALICE), None),
                None,
                0
            ),
            Err(EscrowError::Unauthorized)
        );
        // And the taker alone cannot force the initializer out.
        assert_eq!(
            e.mutual_cancel(
                MutualCancelAgreement::new(None, Some(BOB)),
                None,
                0
            ),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn non_funded_state_is_rejected_even_with_both_signatures() {
        // Uninitialized: agreement is real, but there is nothing
        // funded to unwind.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(
            e.mutual_cancel(MutualCancelAgreement::both(ALICE, BOB), None, 0),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Uninitialized);
        // Already Cancelled (via the unilateral path): terminal,
        // no second exit — and the error is the state error, not
        // an authority error, because the agreement itself passed.
        let mut e = funded_escrow();
        e.cancel(ALICE, None, ALICE, 0).unwrap();
        assert_eq!(
            e.mutual_cancel(MutualCancelAgreement::both(ALICE, BOB), None, 0),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn agreement_gate_refuses_before_the_state_gate() {
        // A stranger on an Uninitialized escrow learns nothing
        // about the state: the agreement refusal fires first.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(
            e.mutual_cancel(MutualCancelAgreement::both(MALLORY, BOB), None, 0),
            Err(EscrowError::Unauthorized)
        );
    }

    #[test]
    fn agreement_gate_alone_accepts_only_exact_party_keys() {
        assert!(require_mutual_cancel_agreement(
            &MutualCancelAgreement::both(ALICE, BOB),
            &ALICE,
            &BOB
        )
        .is_ok());
        assert_eq!(
            require_mutual_cancel_agreement(
                &MutualCancelAgreement::new(None, None),
                &ALICE,
                &BOB
            ),
            Err(EscrowError::Unauthorized)
        );
        // Swapped keys are strangers: each key must be its own
        // party's, not merely a bound party's.
        assert_eq!(
            require_mutual_cancel_agreement(
                &MutualCancelAgreement::both(BOB, ALICE),
                &ALICE,
                &BOB
            ),
            Err(EscrowError::Unauthorized)
        );
    }
}
