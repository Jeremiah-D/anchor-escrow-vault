//! AV-296: delegation scope revision — test matrix.
//!
//! Either party may revise the live grant's scope bitmap in place
//! (`amend_delegation_scopes`): narrow or widen — but only to a
//! bitmap `validate_delegation_scopes` accepts (non-empty, within
//! `DELEGATION_SCOPE_MASK`). The operator paths read the live bitmap
//! on every call, so a narrowed scope revokes a power at once and a
//! widened scope grants it at once, with no settled call ever
//! re-judged. Only the scopes move: the operator, the spend cap, the
//! settled `spent` counter and the expiry window are untouched.
//! Check order mirrors `amend_delegation_spend_cap`: pause →
//! authority → state, then `InvalidDelegation` for no grant or a bad
//! bitmap. No new event: like renewal and the cap revision, the
//! amendment emits nothing.

use escrow_state::{
    Escrow, EscrowError, EscrowState, DELEGATION_SCOPE_CANCEL, DELEGATION_SCOPE_FUND,
    DELEGATION_SCOPE_RELEASE,
};

const INITIALIZER: [u8; 32] = [7u8; 32];
const TAKER: [u8; 32] = [9u8; 32];
const OPERATOR: [u8; 32] = [5u8; 32];
const STRANGER: [u8; 32] = [3u8; 32];
const AMOUNT: u64 = 1_000_000;
const ESCROW_EXPIRY: u64 = 1_900_000_000;
const T0: u64 = 1_700_000_000;
const WINDOW: u64 = 1_750_000_000;
const CAP: u64 = 500_000;

const ALL_SCOPES: u32 = DELEGATION_SCOPE_FUND | DELEGATION_SCOPE_RELEASE | DELEGATION_SCOPE_CANCEL;

fn funded_with_scopes(scopes: u32) -> Escrow {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    e.delegate_authority(INITIALIZER, OPERATOR, scopes).unwrap();
    e.fund(INITIALIZER, T0).unwrap();
    e
}

fn grant_fields(e: &Escrow) -> ([u8; 32], u32, u64, u64) {
    let grant = e.delegation().unwrap();
    (
        grant.delegate(),
        grant.scopes(),
        grant.spend_cap(),
        grant.spent(),
    )
}

#[test]
fn either_party_may_amend_the_scopes() {
    let mut e = funded_with_scopes(DELEGATION_SCOPE_RELEASE);
    // The initializer narrows to cancel-only; only the scopes move.
    e.amend_delegation_scopes(INITIALIZER, DELEGATION_SCOPE_CANCEL)
        .unwrap();
    assert_eq!(
        grant_fields(&e),
        (OPERATOR, DELEGATION_SCOPE_CANCEL, 0, 0)
    );
    // The taker widens back to the full bitmap; the grant identity
    // is untouched.
    e.amend_delegation_scopes(TAKER, ALL_SCOPES).unwrap();
    assert_eq!(grant_fields(&e), (OPERATOR, ALL_SCOPES, 0, 0));
    // Amendment works on an Uninitialized escrow too (the
    // renew_delegation state rule).
    let mut fresh = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    fresh
        .delegate_authority(INITIALIZER, OPERATOR, DELEGATION_SCOPE_FUND)
        .unwrap();
    fresh
        .amend_delegation_scopes(TAKER, DELEGATION_SCOPE_FUND | DELEGATION_SCOPE_RELEASE)
        .unwrap();
    assert_eq!(
        fresh.delegation().unwrap().scopes(),
        DELEGATION_SCOPE_FUND | DELEGATION_SCOPE_RELEASE
    );
}

#[test]
fn amendment_keeps_cap_spent_and_expiry_intact() {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    // A time-bounded, uncapped grant: window attached, cap 0.
    e.delegate_authority_with_expiry(INITIALIZER, OPERATOR, ALL_SCOPES, WINDOW)
        .unwrap();
    e.fund(INITIALIZER, T0).unwrap();
    e.release(OPERATOR, T0, 100_000, None, TAKER).unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 100_000);
    // Narrowing the scopes keeps the settled volume and the window.
    e.amend_delegation_scopes(TAKER, DELEGATION_SCOPE_RELEASE)
        .unwrap();
    let grant = e.delegation().unwrap();
    assert_eq!(grant.delegate(), OPERATOR);
    assert_eq!(grant.scopes(), DELEGATION_SCOPE_RELEASE);
    assert_eq!(grant.spend_cap(), 0);
    assert_eq!(grant.spent(), 100_000);
    assert_eq!(e.delegation_expires_at(), Some(WINDOW));

    // Capped variant: the cap survives a scope change too.
    let mut e2 = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    e2.delegate_authority_with_spend_cap(
        INITIALIZER,
        OPERATOR,
        DELEGATION_SCOPE_RELEASE,
        CAP,
    )
    .unwrap();
    e2.fund(INITIALIZER, T0).unwrap();
    e2.release(OPERATOR, T0, 100_000, None, TAKER).unwrap();
    e2.amend_delegation_scopes(
        INITIALIZER,
        DELEGATION_SCOPE_RELEASE | DELEGATION_SCOPE_CANCEL,
    )
    .unwrap();
    assert_eq!(
        grant_fields(&e2),
        (
            OPERATOR,
            DELEGATION_SCOPE_RELEASE | DELEGATION_SCOPE_CANCEL,
            CAP,
            100_000
        )
    );
}

#[test]
fn paused_escrow_refuses_the_amendment() {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY)
        .unwrap()
        .with_pause_authority(INITIALIZER)
        .unwrap();
    e.delegate_authority(INITIALIZER, OPERATOR, DELEGATION_SCOPE_RELEASE)
        .unwrap();
    e.fund(INITIALIZER, T0).unwrap();
    e.pause(INITIALIZER, None).unwrap();
    // The pause gate fires first — before any authority question.
    assert_eq!(
        e.amend_delegation_scopes(INITIALIZER, DELEGATION_SCOPE_CANCEL),
        Err(EscrowError::Paused)
    );
    assert_eq!(
        e.delegation().unwrap().scopes(),
        DELEGATION_SCOPE_RELEASE
    );
}

#[test]
fn non_party_caller_is_refused() {
    let mut e = funded_with_scopes(DELEGATION_SCOPE_RELEASE);
    // A stranger, and the operator themselves, are Unauthorized:
    // the scopes are a party power, never an operator power.
    assert_eq!(
        e.amend_delegation_scopes(STRANGER, DELEGATION_SCOPE_CANCEL),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(
        e.amend_delegation_scopes(OPERATOR, DELEGATION_SCOPE_CANCEL),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(
        e.delegation().unwrap().scopes(),
        DELEGATION_SCOPE_RELEASE
    );
}

#[test]
fn amendment_refused_once_the_escrow_settles() {
    let mut e = funded_with_scopes(DELEGATION_SCOPE_RELEASE);
    // The initializer settles the whole lockup: Funded -> Released.
    e.release(INITIALIZER, T0, AMOUNT, None, TAKER).unwrap();
    assert_eq!(e.state(), EscrowState::Released);
    assert_eq!(
        e.amend_delegation_scopes(INITIALIZER, DELEGATION_SCOPE_CANCEL),
        Err(EscrowError::InvalidStateTransition)
    );
    assert_eq!(
        e.delegation().unwrap().scopes(),
        DELEGATION_SCOPE_RELEASE
    );
}

#[test]
fn amendment_without_a_grant_is_invalid() {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    e.fund(INITIALIZER, T0).unwrap();
    assert_eq!(
        e.amend_delegation_scopes(INITIALIZER, DELEGATION_SCOPE_CANCEL),
        Err(EscrowError::InvalidDelegation)
    );
    assert_eq!(e.delegation(), None);
}

#[test]
fn bad_bitmaps_fail_closed_and_scopes_unchanged() {
    let mut e = funded_with_scopes(DELEGATION_SCOPE_RELEASE);
    // Empty bitmap: a grant of nothing.
    assert_eq!(
        e.amend_delegation_scopes(INITIALIZER, 0),
        Err(EscrowError::InvalidDelegation)
    );
    // Unknown bits: a future scope smuggled into an old bitmap.
    assert_eq!(
        e.amend_delegation_scopes(INITIALIZER, ALL_SCOPES | (1 << 7)),
        Err(EscrowError::InvalidDelegation)
    );
    // Both refusals leave the original bitmap untouched.
    assert_eq!(
        e.delegation().unwrap().scopes(),
        DELEGATION_SCOPE_RELEASE
    );
    // The bitmap check runs after the grant check: without a grant
    // even a bad bitmap is the no-grant error (same code, same
    // fail-closed outcome — asserted via the grant state).
    let mut bare = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    bare.fund(INITIALIZER, T0).unwrap();
    assert_eq!(
        bare.amend_delegation_scopes(INITIALIZER, 0),
        Err(EscrowError::InvalidDelegation)
    );
    assert_eq!(bare.delegation(), None);
}

#[test]
fn same_scopes_is_a_no_op() {
    let mut e = funded_with_scopes(DELEGATION_SCOPE_RELEASE);
    e.release(OPERATOR, T0, 300_000, None, TAKER).unwrap();
    // Re-affirming the live bitmap succeeds and writes nothing.
    e.amend_delegation_scopes(TAKER, DELEGATION_SCOPE_RELEASE)
        .unwrap();
    assert_eq!(
        grant_fields(&e),
        (OPERATOR, DELEGATION_SCOPE_RELEASE, 0, 300_000)
    );
    // The no-op still needs a party: a stranger is refused even
    // for the identical bitmap.
    assert_eq!(
        e.amend_delegation_scopes(STRANGER, DELEGATION_SCOPE_RELEASE),
        Err(EscrowError::Unauthorized)
    );
}

#[test]
fn narrowing_revokes_operator_power_at_once() {
    let mut e = funded_with_scopes(DELEGATION_SCOPE_RELEASE);
    // In-scope: the operator release settles.
    e.release(OPERATOR, T0, 400_000, None, TAKER).unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 400_000);
    // Narrow to cancel-only: the release power is gone at once —
    // the next operator release is refused, and nothing moves.
    e.amend_delegation_scopes(INITIALIZER, DELEGATION_SCOPE_CANCEL)
        .unwrap();
    assert_eq!(
        e.release(OPERATOR, T0, 100_000, None, TAKER),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(e.delegation().unwrap().spent(), 400_000);
    assert_eq!(e.released_amount(), 400_000);
    // The remaining power still works: the operator may cancel.
    e.cancel(OPERATOR, None, INITIALIZER, 0).unwrap();
    assert_eq!(e.state(), EscrowState::Cancelled);
}

#[test]
fn widening_grants_operator_power_at_once() {
    // A cancel-only grant: the operator cannot fund or release.
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    e.delegate_authority(INITIALIZER, OPERATOR, DELEGATION_SCOPE_CANCEL)
        .unwrap();
    assert_eq!(e.fund(OPERATOR, T0), Err(EscrowError::Unauthorized));
    // Widen to fund + release: the operator funds at once, and the
    // release power lands with the same amendment.
    e.amend_delegation_scopes(
        TAKER,
        DELEGATION_SCOPE_FUND | DELEGATION_SCOPE_RELEASE,
    )
    .unwrap();
    e.fund(OPERATOR, T0).unwrap();
    assert_eq!(e.state(), EscrowState::Funded);
    e.release(OPERATOR, T0, 250_000, None, TAKER).unwrap();
    assert_eq!(e.released_amount(), 250_000);
    assert_eq!(e.delegation().unwrap().spent(), 250_000);
}
