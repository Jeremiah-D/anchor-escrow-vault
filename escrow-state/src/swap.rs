//! Atomic swap pairs (AV-105): two escrows linked as one settlement.
//!
//! Two escrows — A: initializer X → taker Y of `amount_a`, B:
//! initializer Y → taker X of `amount_b` — link into a swap pair via
//! [`link_swap`]: each side's [`Escrow::swap_link`] field records the
//! counterparty's escrow id, so the two vaults settle as one atomic
//! unit. Pure logic, zero dependencies.
//!
//! Design:
//! - The link is established only while *both* sides are
//!   `Uninitialized` (linking is a pre-fund setup step, like the AV-13
//!   vesting builder): the parties must be mirrored
//!   (`a.initializer == b.taker && a.taker == b.initializer`) and the
//!   caller-supplied amounts must match each escrow's locked amount —
//!   the caller asserts the swap terms up front instead of trusting
//!   the vaults to be the right pair.
//! - Escrow has no id field, so partner identity is a caller-supplied
//!   parameter (`escrow_id_a` / `escrow_id_b`): the on-chain layer
//!   passes the vault PDAs, off-chain callers pass their indexer ids.
//! - Pair settlement is two-phase: a dry run of each side's
//!   single-side transition on *copies* with the links stripped (the
//!   copies are cheap — [`Escrow`] is `Copy`), then the real run with
//!   the link taken and restored around the public single-side calls.
//!   Any failure in the dry run returns the error with the originals
//!   untouched — and since nothing mutates between the dry run and
//!   the real run, the real run cannot fail after a passing dry run.
//!   The link persists through terminal states as the audit trail;
//!   enforcement ([`Escrow::require_no_live_swap_link`]) applies only
//!   to non-terminal states, so the pair ops strip the link only to
//!   satisfy the single-side refusal, never to erase it.
//! - Pair ops are party-only: an AV-104 operator can never trigger a
//!   pair op — the authority gate checks the caller against the two
//!   parties and never consults the delegation slot. The on-chain
//!   instruction requires *both* parties as signers (the pure-logic
//!   layer models this dual-party authorization; each side's inner
//!   call runs under that side's own initializer authority, like a
//!   dual-signed governance transition).
//! - [`cancel_swap_expired`] refuses atomically: *both* sides must
//!   satisfy [`Escrow::is_expiry_eligible`] or the whole call fails
//!   with [`EscrowError::NotExpired`] — no partial expiry.
//!
//! Check order on every pair op is pause (both vaults) → party
//! authority → link → state/config — mirroring the single-side
//! convention (pause first, then reentrancy, then authority → state →
//! config) with the pair-level gates first, since the single-side
//! calls repeat their own guards on the real run.

use super::{Escrow, EscrowError, EscrowState};

/// Serialized length of the swap-link region in `VAULT_FIELDS`:
/// `Option<[u8; 32]>` = 1-byte Borsh discriminant + the 32-byte
/// counterparty escrow id. The region is always reserved (zeroed when
/// `None`) so `link_swap` writes in place — same treatment as
/// `arbiter` / `mint` / `refund_to`.
pub const SWAP_LINK_REGION_LEN: usize = 1 + 32;

/// True when `caller` is one of the two parties of the escrow — the
/// pair-op authority gate. AV-104 operators are deliberately *not*
/// consulted: pair ops are party-only.
fn is_party(escrow: &Escrow, caller: [u8; 32]) -> bool {
    let (initializer, taker) = (escrow.initializer(), escrow.taker());
    caller == initializer || caller == taker
}

/// The pair-link cross-check shared by the three settlement pair ops:
/// both sides must carry the counterparty's id. A missing link is
/// [`EscrowError::SwapLinkActive`] (a single-side refusal or an
/// unlinked pair), a mismatched one is
/// [`EscrowError::InvalidSwapParties`] (the pair is not what the
/// caller claims).
fn require_cross_link(
    a: &Escrow,
    b: &Escrow,
    escrow_id_a: [u8; 32],
    escrow_id_b: [u8; 32],
) -> Result<(), EscrowError> {
    match (a.swap_link(), b.swap_link()) {
        (Some(link_a), Some(link_b)) if link_a == escrow_id_b && link_b == escrow_id_a => Ok(()),
        (Some(_), Some(_)) => Err(EscrowError::InvalidSwapParties),
        _ => Err(EscrowError::SwapLinkActive),
    }
}

/// Link two escrows as an atomic swap pair (AV-105).
///
/// A is the X→Y leg (`amount_a`), B the Y→X leg (`amount_b`); on
/// success `a.swap_link == Some(escrow_id_b)` and
/// `b.swap_link == Some(escrow_id_a)`. Gate order: pause on both
/// vaults, then party authority, then state, then link/ids/parties/
/// amounts.
///
/// Rejections: [`EscrowError::Paused`] (either vault paused),
/// [`EscrowError::Unauthorized`] (caller is neither party — AV-104
/// operators included), [`EscrowError::InvalidStateTransition`]
/// (either side not `Uninitialized`), [`EscrowError::SwapLinkActive`]
/// (either side already linked), [`EscrowError::InvalidSwapParties`]
/// (zero/duplicate ids, or the parties are not mirrored), and
/// [`EscrowError::InvalidSwapAmounts`] (a caller-supplied amount
/// disagrees with the escrow's locked amount).
pub fn link_swap(
    a: &mut Escrow,
    b: &mut Escrow,
    caller: [u8; 32],
    escrow_id_a: [u8; 32],
    escrow_id_b: [u8; 32],
    amount_a: u64,
    amount_b: u64,
) -> Result<(), EscrowError> {
    // AV-46: pause guard first on both vaults — a paused escrow fails
    // fast, before the authority check.
    a.require_not_paused()?;
    b.require_not_paused()?;
    // Party-only: the caller must be one of the two parties (the
    // parties are the same mirrored pair on both sides, so checking
    // `a` covers `b`); an AV-104 operator is Unauthorized here.
    if !is_party(a, caller) {
        return Err(EscrowError::Unauthorized);
    }
    // Linking is a pre-fund setup step, like the `with_*` builders.
    if a.state() != EscrowState::Uninitialized || b.state() != EscrowState::Uninitialized {
        return Err(EscrowError::InvalidStateTransition);
    }
    // No double link: one pair per escrow, and there is no unlink —
    // the link persists as the audit trail once the pair settles.
    if a.swap_link().is_some() || b.swap_link().is_some() {
        return Err(EscrowError::SwapLinkActive);
    }
    // Partner ids are caller-supplied (the escrow has no id field): a
    // zero id is a link to nowhere, a duplicate id is a self-link.
    if escrow_id_a == [0u8; 32] || escrow_id_b == [0u8; 32] || escrow_id_a == escrow_id_b {
        return Err(EscrowError::InvalidSwapParties);
    }
    // The mirrored-parties rule: A's initializer is B's taker and
    // vice versa — X's leg pays Y, Y's leg pays X.
    if a.initializer() != b.taker() || a.taker() != b.initializer() {
        return Err(EscrowError::InvalidSwapParties);
    }
    // The caller asserts the swap terms: the linked amounts must be
    // the escrows' actual locked amounts, so a mislabeled pair of
    // vaults cannot be linked by accident.
    if amount_a != a.amount() || amount_b != b.amount() {
        return Err(EscrowError::InvalidSwapAmounts);
    }
    a.swap_link = Some(escrow_id_b);
    b.swap_link = Some(escrow_id_a);
    Ok(())
}

/// Release both sides of a linked pair atomically (AV-105).
///
/// Returns `(payout_a, fee_a, payout_b, fee_b)` — the per-side
/// [`Escrow::release`] splits (taker net, AV-17 protocol fee).
/// Per-side authority is that side's own initializer (the on-chain
/// instruction requires both parties as signers, so each leg runs
/// under its leg's initializer — party-only, AV-104 operators
/// rejected at the pair gate).
///
/// Two-phase atomicity: the dry run executes `release` on copies
/// with the links stripped; any failure returns the error with the
/// originals untouched and zero observable change. The real run then
/// takes and restores the link around each public `release` call (the
/// single-side refusal would otherwise trip on the live link); the
/// link persists on both vaults as the audit trail.
#[allow(clippy::too_many_arguments)]
pub fn release_swap(
    a: &mut Escrow,
    b: &mut Escrow,
    caller: [u8; 32],
    escrow_id_a: [u8; 32],
    escrow_id_b: [u8; 32],
    now: u64,
    amount_a: u64,
    mint_a: Option<[u8; 32]>,
    payout_to_a: [u8; 32],
    amount_b: u64,
    mint_b: Option<[u8; 32]>,
    payout_to_b: [u8; 32],
) -> Result<(u64, u64, u64, u64), EscrowError> {
    a.require_not_paused()?;
    b.require_not_paused()?;
    // Party-only: an AV-104 operator is Unauthorized — the delegation
    // slot is never consulted on pair ops.
    if !is_party(a, caller) {
        return Err(EscrowError::Unauthorized);
    }
    require_cross_link(a, b, escrow_id_a, escrow_id_b)?;
    let auth_a = a.initializer();
    let auth_b = b.initializer();
    // Phase 1 — dry run on copies with the links stripped (the
    // single-side refusal trips on a live link, so the copies run
    // link-free). `Escrow` is `Copy`, so the originals are untouched
    // whatever the dry run decides.
    let mut dry_a = *a;
    let mut dry_b = *b;
    dry_a.swap_link = None;
    dry_b.swap_link = None;
    dry_a.release(auth_a, now, amount_a, mint_a, payout_to_a)?;
    dry_b.release(auth_b, now, amount_b, mint_b, payout_to_b)?;
    // Phase 2 — the real run: the dry run passed on identical
    // inputs and identical state, so these calls cannot fail; the
    // link is taken and restored around each one (it persists as the
    // audit trail — enforcement applies only to non-terminal states).
    let link_a = a.swap_link.take();
    let real_a = a.release(auth_a, now, amount_a, mint_a, payout_to_a);
    a.swap_link = link_a;
    let (payout_a, fee_a) = real_a?;
    let link_b = b.swap_link.take();
    let real_b = b.release(auth_b, now, amount_b, mint_b, payout_to_b);
    b.swap_link = link_b;
    let (payout_b, fee_b) = real_b?;
    Ok((payout_a, fee_a, payout_b, fee_b))
}

/// Cancel both sides of a linked pair atomically (AV-105): one
/// party's cancel triggers the pair-wide cancel.
///
/// The caller must be the initializer of at least one side
/// (party-only — a stranger or an AV-104 operator is Unauthorized);
/// per-side authority is that side's own initializer, so the leg
/// whose initializer is not the caller still settles under its own
/// party (the on-chain instruction requires both parties as signers).
/// Two-phase atomicity mirrors [`release_swap`].
#[allow(clippy::too_many_arguments)]
pub fn cancel_swap(
    a: &mut Escrow,
    b: &mut Escrow,
    caller: [u8; 32],
    escrow_id_a: [u8; 32],
    escrow_id_b: [u8; 32],
    mint_a: Option<[u8; 32]>,
    refund_to_a: [u8; 32],
    mint_b: Option<[u8; 32]>,
    refund_to_b: [u8; 32],
) -> Result<(), EscrowError> {
    a.require_not_paused()?;
    b.require_not_paused()?;
    // Party-only, and the cancelling party must be an initializer —
    // the taker cannot unilaterally cancel (the single-side `cancel`
    // is initializer-only too).
    if caller != a.initializer() && caller != b.initializer() {
        return Err(EscrowError::Unauthorized);
    }
    require_cross_link(a, b, escrow_id_a, escrow_id_b)?;
    let auth_a = a.initializer();
    let auth_b = b.initializer();
    // Phase 1 — dry run on link-stripped copies.
    let mut dry_a = *a;
    let mut dry_b = *b;
    dry_a.swap_link = None;
    dry_b.swap_link = None;
    dry_a.cancel(auth_a, mint_a, refund_to_a)?;
    dry_b.cancel(auth_b, mint_b, refund_to_b)?;
    // Phase 2 — real run with link take/restore (the link persists as
    // the audit trail).
    let link_a = a.swap_link.take();
    let real_a = a.cancel(auth_a, mint_a, refund_to_a);
    a.swap_link = link_a;
    real_a?;
    let link_b = b.swap_link.take();
    let real_b = b.cancel(auth_b, mint_b, refund_to_b);
    b.swap_link = link_b;
    real_b?;
    Ok(())
}

/// Cancel both sides of a linked pair on expiry (AV-105).
///
/// Returns `(refund_a, penalty_a, refund_b, penalty_b)` — the
/// per-side [`Escrow::cancel_expired`] splits. The caller must be one
/// of the two parties (the single-side path allows either party, so
/// the pair path does too); per-side authority is the caller, so the
/// AV-24 anti-griefing penalty keys per side exactly as the
/// single-side path charges it (a taker-caller pays the penalty on
/// the leg where they are the taker).
///
/// Atomic refusal: *both* sides must satisfy
/// [`Escrow::is_expiry_eligible`] before either side moves — one
/// ineligible side fails the whole call with
/// [`EscrowError::NotExpired`], so there is no partial expiry. Then
/// the two-phase run mirrors [`release_swap`].
#[allow(clippy::too_many_arguments)]
pub fn cancel_swap_expired(
    a: &mut Escrow,
    b: &mut Escrow,
    caller: [u8; 32],
    escrow_id_a: [u8; 32],
    escrow_id_b: [u8; 32],
    now: u64,
    mint_a: Option<[u8; 32]>,
    refund_to_a: [u8; 32],
    mint_b: Option<[u8; 32]>,
    refund_to_b: [u8; 32],
) -> Result<(u64, u64, u64, u64), EscrowError> {
    a.require_not_paused()?;
    b.require_not_paused()?;
    // Party-only: an AV-104 operator is Unauthorized.
    if !is_party(a, caller) {
        return Err(EscrowError::Unauthorized);
    }
    require_cross_link(a, b, escrow_id_a, escrow_id_b)?;
    // Atomic refusal — checked before either side moves, so a
    // one-sided expiry can never strand the pair half-cancelled.
    if !a.is_expiry_eligible(now) || !b.is_expiry_eligible(now) {
        return Err(EscrowError::NotExpired);
    }
    // Phase 1 — dry run on link-stripped copies.
    let mut dry_a = *a;
    let mut dry_b = *b;
    dry_a.swap_link = None;
    dry_b.swap_link = None;
    dry_a.cancel_expired(caller, now, mint_a, refund_to_a)?;
    dry_b.cancel_expired(caller, now, mint_b, refund_to_b)?;
    // Phase 2 — real run with link take/restore (the link persists as
    // the audit trail).
    let link_a = a.swap_link.take();
    let real_a = a.cancel_expired(caller, now, mint_a, refund_to_a);
    a.swap_link = link_a;
    let (refund_a, penalty_a) = real_a?;
    let link_b = b.swap_link.take();
    let real_b = b.cancel_expired(caller, now, mint_b, refund_to_b);
    b.swap_link = link_b;
    let (refund_b, penalty_b) = real_b?;
    Ok((refund_a, penalty_a, refund_b, penalty_b))
}

#[cfg(test)]
mod swap_tests {
    use super::super::events::IndexedEscrow;
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const OPERATOR: [u8; 32] = [0xDD; 32];
    const ID_A: [u8; 32] = [0xA1; 32];
    const ID_B: [u8; 32] = [0xB2; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;
    const T0: u64 = 1_700_000_000;

    /// A is ALICE→BOB of 1_000, B is BOB→ALICE of 500 — the mirrored
    /// pair `link_swap` accepts.
    fn pair() -> (Escrow, Escrow) {
        let a = Escrow::initialize(ALICE, BOB, 1_000, EXPIRES_AT).unwrap();
        let b = Escrow::initialize(BOB, ALICE, 500, EXPIRES_AT).unwrap();
        (a, b)
    }

    fn funded_pair() -> (Escrow, Escrow) {
        let (mut a, mut b) = pair();
        link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500).unwrap();
        a.fund(ALICE, T0).unwrap();
        b.fund(BOB, T0).unwrap();
        (a, b)
    }

    #[test]
    fn link_swap_links_both_sides() {
        let (mut a, mut b) = pair();
        link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500).unwrap();
        assert_eq!(a.swap_link(), Some(ID_B));
        assert_eq!(b.swap_link(), Some(ID_A));
        // The taker may link too — either party.
        let (mut c, mut d) = pair();
        link_swap(&mut c, &mut d, BOB, ID_A, ID_B, 1_000, 500).unwrap();
        assert_eq!(c.swap_link(), Some(ID_B));
    }

    #[test]
    fn link_swap_rejects_stranger_and_operator() {
        use super::super::{
            DELEGATION_SCOPE_CANCEL, DELEGATION_SCOPE_FUND, DELEGATION_SCOPE_RELEASE,
        };
        let (mut a, mut b) = pair();
        assert_eq!(
            link_swap(&mut a, &mut b, MALLORY, ID_A, ID_B, 1_000, 500),
            Err(EscrowError::Unauthorized)
        );
        // An AV-104 operator with every scope is still not a party.
        a.delegate_authority(
            ALICE,
            OPERATOR,
            DELEGATION_SCOPE_FUND | DELEGATION_SCOPE_RELEASE | DELEGATION_SCOPE_CANCEL,
        )
        .unwrap();
        assert_eq!(
            link_swap(&mut a, &mut b, OPERATOR, ID_A, ID_B, 1_000, 500),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(a.swap_link(), None);
        assert_eq!(b.swap_link(), None);
    }

    #[test]
    fn link_swap_rejects_non_uninitialized() {
        let (mut a, mut b) = pair();
        a.fund(ALICE, T0).unwrap();
        assert_eq!(
            link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn link_swap_rejects_double_link() {
        let (mut a, mut b) = pair();
        link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500).unwrap();
        assert_eq!(
            link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500),
            Err(EscrowError::SwapLinkActive)
        );
        // The original link is untouched by the failed re-link.
        assert_eq!(a.swap_link(), Some(ID_B));
    }

    #[test]
    fn link_swap_rejects_bad_ids() {
        let (mut a, mut b) = pair();
        // Zero partner id.
        assert_eq!(
            link_swap(&mut a, &mut b, ALICE, [0u8; 32], ID_B, 1_000, 500),
            Err(EscrowError::InvalidSwapParties)
        );
        assert_eq!(
            link_swap(&mut a, &mut b, ALICE, ID_A, [0u8; 32], 1_000, 500),
            Err(EscrowError::InvalidSwapParties)
        );
        // Self-link.
        assert_eq!(
            link_swap(&mut a, &mut b, ALICE, ID_A, ID_A, 1_000, 500),
            Err(EscrowError::InvalidSwapParties)
        );
    }

    #[test]
    fn link_swap_rejects_non_mirrored_parties() {
        let mut a = Escrow::initialize(ALICE, BOB, 1_000, EXPIRES_AT).unwrap();
        // Same direction, not mirrored.
        let mut b = Escrow::initialize(ALICE, BOB, 500, EXPIRES_AT).unwrap();
        assert_eq!(
            link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500),
            Err(EscrowError::InvalidSwapParties)
        );
        // Third party entirely.
        let mut c = Escrow::initialize(BOB, MALLORY, 500, EXPIRES_AT).unwrap();
        assert_eq!(
            link_swap(&mut a, &mut c, ALICE, ID_A, ID_B, 1_000, 500),
            Err(EscrowError::InvalidSwapParties)
        );
    }

    #[test]
    fn link_swap_rejects_amount_mismatch() {
        let (mut a, mut b) = pair();
        assert_eq!(
            link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 999, 500),
            Err(EscrowError::InvalidSwapAmounts)
        );
        assert_eq!(
            link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 501),
            Err(EscrowError::InvalidSwapAmounts)
        );
        assert_eq!(a.swap_link(), None);
    }

    #[test]
    fn link_swap_rejects_when_paused() {
        let (mut a, mut b) = pair();
        a = a.with_pause_authority(ALICE).unwrap();
        a.pause(ALICE).unwrap();
        assert_eq!(
            link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500),
            Err(EscrowError::Paused)
        );
    }

    #[test]
    fn release_swap_releases_both_sides_atomically() {
        let (mut a, mut b) = funded_pair();
        let (payout_a, fee_a, payout_b, fee_b) = release_swap(
            &mut a,
            &mut b,
            ALICE,
            ID_A,
            ID_B,
            T0,
            1_000,
            None,
            BOB,
            500,
            None,
            ALICE,
        )
        .unwrap();
        // No fee configured: each taker takes their leg whole.
        assert_eq!((payout_a, fee_a), (1_000, 0));
        assert_eq!((payout_b, fee_b), (500, 0));
        assert_eq!(a.state(), EscrowState::Released);
        assert_eq!(b.state(), EscrowState::Released);
        // The link persists through the terminal state as the audit
        // trail.
        assert_eq!(a.swap_link(), Some(ID_B));
        assert_eq!(b.swap_link(), Some(ID_A));
    }

    #[test]
    fn release_swap_charges_per_side_protocol_fees() {
        let (mut a, mut b) = pair();
        a = a.with_protocol_fee(1_000).unwrap(); // 10% on leg A.
        b = b.with_protocol_fee(2_000).unwrap(); // 20% on leg B.
        link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500).unwrap();
        a.fund(ALICE, T0).unwrap();
        b.fund(BOB, T0).unwrap();
        let (payout_a, fee_a, payout_b, fee_b) = release_swap(
            &mut a,
            &mut b,
            BOB,
            ID_A,
            ID_B,
            T0,
            1_000,
            None,
            BOB,
            500,
            None,
            ALICE,
        )
        .unwrap();
        assert_eq!((payout_a, fee_a), (900, 100));
        assert_eq!((payout_b, fee_b), (400, 100));
        assert_eq!(a.fees_paid(), 100);
        assert_eq!(b.fees_paid(), 100);
    }

    #[test]
    fn release_swap_is_atomic_on_side_b_failure() {
        let (mut a, mut b) = pair();
        // Leg B carries a timelock the dry run cannot pass.
        b = b.with_timelock(T0 + 10_000).unwrap();
        link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500).unwrap();
        a.fund(ALICE, T0).unwrap();
        b.fund(BOB, T0).unwrap();
        assert_eq!(
            release_swap(
                &mut a,
                &mut b,
                ALICE,
                ID_A,
                ID_B,
                T0,
                1_000,
                None,
                BOB,
                500,
                None,
                ALICE,
            ),
            Err(EscrowError::TimelockNotReached)
        );
        // Side A is untouched: still Funded, nothing released, link
        // intact.
        assert_eq!(a.state(), EscrowState::Funded);
        assert_eq!(a.released_amount(), 0);
        assert_eq!(a.swap_link(), Some(ID_B));
        assert_eq!(b.state(), EscrowState::Funded);
    }

    #[test]
    fn release_swap_rejects_operator_and_stranger() {
        let (mut a, mut b) = funded_pair();
        assert_eq!(
            release_swap(
                &mut a, &mut b, MALLORY, ID_A, ID_B, T0, 1_000, None, BOB, 500, None,
                ALICE,
            ),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            release_swap(
                &mut a, &mut b, OPERATOR, ID_A, ID_B, T0, 1_000, None, BOB, 500, None,
                ALICE,
            ),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(a.state(), EscrowState::Funded);
    }

    #[test]
    fn release_swap_rejects_wrong_pair() {
        let (mut a, mut b) = funded_pair();
        // Swapped ids: the cross-link does not match the claim.
        assert_eq!(
            release_swap(
                &mut a, &mut b, ALICE, ID_B, ID_A, T0, 1_000, None, BOB, 500, None,
                ALICE,
            ),
            Err(EscrowError::InvalidSwapParties)
        );
        // Unlinked pair.
        let (mut c, mut d) = pair();
        c.fund(ALICE, T0).unwrap();
        d.fund(BOB, T0).unwrap();
        assert_eq!(
            release_swap(
                &mut c, &mut d, ALICE, ID_A, ID_B, T0, 1_000, None, BOB, 500, None,
                ALICE,
            ),
            Err(EscrowError::SwapLinkActive)
        );
    }

    #[test]
    fn single_side_settlement_refused_on_live_link() {
        let (mut a, mut b) = funded_pair();
        // Every fund-moving single-side transition refuses while the
        // link is live and the state is non-terminal.
        assert_eq!(
            a.release(ALICE, T0, 1_000, None, BOB),
            Err(EscrowError::SwapLinkActive)
        );
        assert_eq!(
            a.release_via_cpi(ALICE, T0, 1_000, None, BOB, &cpi_invocation(), |_| Ok(())),
            Err(EscrowError::SwapLinkActive)
        );
        assert_eq!(a.cancel(ALICE, None, ALICE), Err(EscrowError::SwapLinkActive));
        assert_eq!(
            a.cancel_partial(ALICE, 100, None, ALICE),
            Err(EscrowError::SwapLinkActive)
        );
        assert_eq!(
            a.cancel_expired(ALICE, EXPIRES_AT + 1, None, ALICE),
            Err(EscrowError::SwapLinkActive)
        );
        // `claim` needs a vesting schedule to reach the state gate;
        // build a linked pair with one.
        let (mut va, mut vb) = pair();
        let schedule =
            super::super::VestingSchedule::new(T0, T0 + 10_000).unwrap();
        va = va.with_vesting(schedule).unwrap();
        link_swap(&mut va, &mut vb, ALICE, ID_A, ID_B, 1_000, 500).unwrap();
        va.fund(ALICE, T0).unwrap();
        vb.fund(BOB, T0).unwrap();
        assert_eq!(
            va.claim(BOB, T0 + 5_000, None, BOB),
            Err(EscrowError::SwapLinkActive)
        );
        let _ = b;
    }

    #[test]
    fn single_side_resolve_and_slash_refused_on_live_link() {
        // `resolve` (Disputed) and `slash` (Funded) are fund-moving
        // too — both refuse on a live link.
        let (mut a, mut b) = pair();
        a = a.with_arbiter(MALLORY).unwrap();
        link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500).unwrap();
        a.fund(ALICE, T0).unwrap();
        b.fund(BOB, T0).unwrap();
        a.escalate(ALICE, T0 + 1, None, None, 0).unwrap();
        assert_eq!(
            a.resolve(MALLORY, 600, T0 + 1, None, None, BOB),
            Err(EscrowError::SwapLinkActive)
        );
        let (mut c, _) = funded_pair();
        assert_eq!(
            c.slash(ALICE, 100, None, T0),
            Err(EscrowError::SwapLinkActive)
        );
    }

    #[test]
    fn cancel_swap_cancels_both_sides() {
        let (mut a, mut b) = funded_pair();
        cancel_swap(&mut a, &mut b, ALICE, ID_A, ID_B, None, ALICE, None, BOB).unwrap();
        assert_eq!(a.state(), EscrowState::Cancelled);
        assert_eq!(b.state(), EscrowState::Cancelled);
        // The link persists as the audit trail.
        assert_eq!(a.swap_link(), Some(ID_B));
        assert_eq!(b.swap_link(), Some(ID_A));
        // The other initializer may trigger it too.
        let (mut c, mut d) = funded_pair();
        cancel_swap(&mut c, &mut d, BOB, ID_A, ID_B, None, ALICE, None, BOB).unwrap();
        assert_eq!(c.state(), EscrowState::Cancelled);
        assert_eq!(d.state(), EscrowState::Cancelled);
    }

    #[test]
    fn cancel_swap_rejects_stranger_and_operator() {
        let (mut a, mut b) = funded_pair();
        // A stranger is Unauthorized.
        assert_eq!(
            cancel_swap(&mut a, &mut b, MALLORY, ID_A, ID_B, None, ALICE, None, BOB),
            Err(EscrowError::Unauthorized)
        );
        // An AV-104 operator is Unauthorized — pair ops are party-only.
        assert_eq!(
            cancel_swap(&mut a, &mut b, OPERATOR, ID_A, ID_B, None, ALICE, None, BOB),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(a.state(), EscrowState::Funded);
        assert_eq!(b.state(), EscrowState::Funded);
    }

    #[test]
    fn cancel_swap_expired_needs_both_sides_eligible() {
        // Both eligible: both cancel.
        let (mut a, mut b) = pair();
        a = a.with_grace_period(0).unwrap();
        link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500).unwrap();
        a.fund(ALICE, T0).unwrap();
        b.fund(BOB, T0).unwrap();
        let (refund_a, penalty_a, refund_b, penalty_b) = cancel_swap_expired(
            &mut a,
            &mut b,
            ALICE,
            ID_A,
            ID_B,
            EXPIRES_AT + 1,
            None,
            ALICE,
            None,
            BOB,
        )
        .unwrap();
        assert_eq!((refund_a, penalty_a), (1_000, 0));
        assert_eq!((refund_b, penalty_b), (500, 0));
        assert_eq!(a.state(), EscrowState::Cancelled);
        assert_eq!(b.state(), EscrowState::Cancelled);
        // One side ineligible: atomic refusal, both unchanged.
        let (mut c, mut d) = pair();
        c = c.with_grace_period(100_000).unwrap();
        link_swap(&mut c, &mut d, ALICE, ID_A, ID_B, 1_000, 500).unwrap();
        c.fund(ALICE, T0).unwrap();
        d.fund(BOB, T0).unwrap();
        assert_eq!(
            cancel_swap_expired(
                &mut c, &mut d, ALICE, ID_A, ID_B, EXPIRES_AT + 1, None, ALICE, None,
                BOB,
            ),
            Err(EscrowError::NotExpired)
        );
        assert_eq!(c.state(), EscrowState::Funded);
        assert_eq!(d.state(), EscrowState::Funded);
    }

    #[test]
    fn swap_error_codes_pinned() {
        assert_eq!(EscrowError::InvalidSwapParties.code(), 161);
        assert_eq!(EscrowError::InvalidSwapAmounts.code(), 162);
        assert_eq!(EscrowError::SwapLinkActive.code(), 163);
        assert!(EscrowError::all().contains(&EscrowError::InvalidSwapParties));
        assert!(EscrowError::all().contains(&EscrowError::InvalidSwapAmounts));
        assert!(EscrowError::all().contains(&EscrowError::SwapLinkActive));
    }

    #[test]
    fn indexed_pair_emits_swap_linked_in_a_then_b_order() {
        use super::super::events::EscrowEventKind;
        let ia = IndexedEscrow::initialize(ALICE, BOB, 1_000, EXPIRES_AT, ID_A, T0).unwrap();
        let ib = IndexedEscrow::initialize(BOB, ALICE, 500, EXPIRES_AT, ID_B, T0).unwrap();
        let mut a = ia;
        let mut b = ib;
        IndexedEscrow::link_swap_pair(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500, T0 + 1)
            .unwrap();
        let ev_a = a.drain_events();
        let ev_b = b.drain_events();
        // Each escrow's log: Initialized (seq 0), then SwapLinked (seq
        // 1) — the deterministic A→B emission order.
        assert_eq!(ev_a.len(), 2);
        assert_eq!(ev_a[1].kind, EscrowEventKind::SwapLinked);
        assert_eq!(ev_a[1].seq, 1);
        assert_eq!(ev_b.len(), 2);
        assert_eq!(ev_b[1].kind, EscrowEventKind::SwapLinked);
        assert_eq!(ev_b[1].seq, 1);
        assert_eq!(ev_a[1].kind.discriminant(), 55);
        // Failure emits nothing.
        let mut c =
            IndexedEscrow::initialize(ALICE, BOB, 1_000, EXPIRES_AT, ID_A, T0).unwrap();
        let mut d =
            IndexedEscrow::initialize(BOB, ALICE, 500, EXPIRES_AT, ID_B, T0).unwrap();
        c.drain_events();
        d.drain_events();
        assert_eq!(
            IndexedEscrow::link_swap_pair(&mut c, &mut d, MALLORY, ID_A, ID_B, 1_000, 500, T0 + 1),
            Err(EscrowError::Unauthorized)
        );
        assert!(c.drain_events().is_empty());
        assert!(d.drain_events().is_empty());
    }

    #[test]
    fn indexed_release_swap_pair_emits_released_a_then_b() {
        use super::super::events::EscrowEventKind;
        let mut a =
            IndexedEscrow::initialize(ALICE, BOB, 1_000, EXPIRES_AT, ID_A, T0).unwrap();
        let mut b =
            IndexedEscrow::initialize(BOB, ALICE, 500, EXPIRES_AT, ID_B, T0).unwrap();
        IndexedEscrow::link_swap_pair(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500, T0 + 1)
            .unwrap();
        a.fund(ALICE, T0 + 2).unwrap();
        b.fund(BOB, T0 + 2).unwrap();
        a.drain_events();
        b.drain_events();
        let (payout_a, fee_a, payout_b, fee_b) = IndexedEscrow::release_swap_pair(
            &mut a,
            &mut b,
            ALICE,
            ID_A,
            ID_B,
            T0 + 3,
            1_000,
            None,
            BOB,
            500,
            None,
            ALICE,
        )
        .unwrap();
        assert_eq!((payout_a, fee_a, payout_b, fee_b), (1_000, 0, 500, 0));
        let ev_a = a.drain_events();
        let ev_b = b.drain_events();
        assert_eq!(ev_a.len(), 1);
        assert_eq!(ev_a[0].kind, EscrowEventKind::Released);
        assert_eq!(ev_a[0].from, EscrowState::Funded);
        assert_eq!(ev_a[0].to, EscrowState::Released);
        assert_eq!(ev_b.len(), 1);
        assert_eq!(ev_b[0].kind, EscrowEventKind::Released);
        // Atomicity at the event layer: a B-side failure emits
        // nothing on either side.
        let mut c =
            IndexedEscrow::initialize(ALICE, BOB, 1_000, EXPIRES_AT, ID_A, T0).unwrap();
        let mut d =
            IndexedEscrow::initialize(BOB, ALICE, 500, EXPIRES_AT, ID_B, T0).unwrap();
        IndexedEscrow::link_swap_pair(&mut c, &mut d, ALICE, ID_A, ID_B, 1_000, 500, T0 + 1)
            .unwrap();
        c.fund(ALICE, T0 + 2).unwrap();
        d.fund(BOB, T0 + 2).unwrap();
        c.drain_events();
        d.drain_events();
        assert_eq!(
            IndexedEscrow::release_swap_pair(
                &mut c,
                &mut d,
                MALLORY,
                ID_A,
                ID_B,
                T0 + 3,
                1_000,
                None,
                BOB,
                500,
                None,
                ALICE,
            ),
            Err(EscrowError::Unauthorized)
        );
        assert!(c.drain_events().is_empty());
        assert!(d.drain_events().is_empty());
    }

    #[test]
    fn indexed_cancel_swap_pair_emits_cancelled_a_then_b() {
        use super::super::events::EscrowEventKind;
        let mut a =
            IndexedEscrow::initialize(ALICE, BOB, 1_000, EXPIRES_AT, ID_A, T0).unwrap();
        let mut b =
            IndexedEscrow::initialize(BOB, ALICE, 500, EXPIRES_AT, ID_B, T0).unwrap();
        IndexedEscrow::link_swap_pair(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500, T0 + 1)
            .unwrap();
        a.fund(ALICE, T0 + 2).unwrap();
        b.fund(BOB, T0 + 2).unwrap();
        a.drain_events();
        b.drain_events();
        IndexedEscrow::cancel_swap_pair(
            &mut a,
            &mut b,
            ALICE,
            ID_A,
            ID_B,
            None,
            ALICE,
            None,
            BOB,
            T0 + 3,
        )
        .unwrap();
        let ev_a = a.drain_events();
        let ev_b = b.drain_events();
        assert_eq!(ev_a.len(), 1);
        assert_eq!(ev_a[0].kind, EscrowEventKind::Cancelled);
        assert_eq!(ev_a[0].from, EscrowState::Funded);
        assert_eq!(ev_a[0].to, EscrowState::Cancelled);
        assert_eq!(ev_b.len(), 1);
        assert_eq!(ev_b[0].kind, EscrowEventKind::Cancelled);
    }

    #[test]
    fn indexed_cancel_swap_expired_pair_emits_expired_cancelled() {
        use super::super::events::EscrowEventKind;
        let mut a =
            IndexedEscrow::initialize(ALICE, BOB, 1_000, EXPIRES_AT, ID_A, T0).unwrap();
        let mut b =
            IndexedEscrow::initialize(BOB, ALICE, 500, EXPIRES_AT, ID_B, T0).unwrap();
        IndexedEscrow::link_swap_pair(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 500, T0 + 1)
            .unwrap();
        a.fund(ALICE, T0 + 2).unwrap();
        b.fund(BOB, T0 + 2).unwrap();
        a.drain_events();
        b.drain_events();
        let (refund_a, penalty_a, refund_b, penalty_b) =
            IndexedEscrow::cancel_swap_expired_pair(
                &mut a,
                &mut b,
                ALICE,
                ID_A,
                ID_B,
                EXPIRES_AT + 1,
                None,
                ALICE,
                None,
                BOB,
            )
            .unwrap();
        assert_eq!((refund_a, penalty_a, refund_b, penalty_b), (1_000, 0, 500, 0));
        let ev_a = a.drain_events();
        let ev_b = b.drain_events();
        assert_eq!(ev_a.len(), 1);
        assert_eq!(ev_a[0].kind, EscrowEventKind::ExpiredCancelled);
        assert_eq!(ev_b.len(), 1);
        assert_eq!(ev_b[0].kind, EscrowEventKind::ExpiredCancelled);
    }

    fn cpi_invocation() -> super::super::CpiInvocation {
        use super::super::AccountMeta;
        super::super::CpiInvocation {
            program_id: [0xE0; 32],
            accounts: vec![AccountMeta {
                pubkey: [0xE1; 32],
                is_signer: false,
                is_writable: true,
            }],
            data: vec![0x01, 0x02],
        }
    }
}
