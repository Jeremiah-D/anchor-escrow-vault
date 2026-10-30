//! AV-301: delegation operator rotation — test matrix.
//!
//! Either party may rotate the live grant's delegate key in place
//! (`rotate_delegation_delegate`): a compromised hot wallet is cut
//! off by one rotation, with no re-grant and no new grant to
//! configure. Only the delegate moves: the scopes, the spend cap,
//! the settled `spent` counter and the expiry window are untouched.
//! The rotation is an identity change, not a re-authorization —
//! reusing the `delegate_authority` re-grant path would reset
//! `spent` to `0`, laundering the settled volume out of the cap, so
//! the delegate field is rewritten in place and `spent` is never
//! cleared. The operator paths read the live delegate on every call,
//! so the new operator is effective from the next operator call and
//! the old operator loses power at once. Check order mirrors
//! `amend_delegation_scopes`: pause → authority → state, then
//! `InvalidDelegation` for no grant or a zero new delegate. No new
//! event: like renewal and the cap and scope revisions, the rotation
//! emits nothing.

use escrow_state::{
    Escrow, EscrowError, EscrowState, DELEGATION_SCOPE_CANCEL, DELEGATION_SCOPE_FUND,
    DELEGATION_SCOPE_RELEASE,
};

const INITIALIZER: [u8; 32] = [7u8; 32];
const TAKER: [u8; 32] = [9u8; 32];
const OPERATOR: [u8; 32] = [5u8; 32];
const NEW_OPERATOR: [u8; 32] = [6u8; 32];
const STRANGER: [u8; 32] = [3u8; 32];
const AMOUNT: u64 = 1_000_000;
const ESCROW_EXPIRY: u64 = 1_900_000_000;
const T0: u64 = 1_700_000_000;
const WINDOW: u64 = 1_750_000_000;
const CAP: u64 = 500_000;

const ALL_SCOPES: u32 = DELEGATION_SCOPE_FUND | DELEGATION_SCOPE_RELEASE | DELEGATION_SCOPE_CANCEL;

fn funded_with_operator() -> Escrow {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    e.delegate_authority(INITIALIZER, OPERATOR, ALL_SCOPES)
        .unwrap();
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
fn either_party_may_rotate_the_delegate() {
    let mut e = funded_with_operator();
    // The initializer rotates to the new operator; only the
    // delegate moves.
    e.rotate_delegation_delegate(INITIALIZER, NEW_OPERATOR)
        .unwrap();
    assert_eq!(grant_fields(&e), (NEW_OPERATOR, ALL_SCOPES, 0, 0));
    // The taker rotates back; the grant identity is untouched
    // apart from the delegate.
    e.rotate_delegation_delegate(TAKER, OPERATOR).unwrap();
    assert_eq!(grant_fields(&e), (OPERATOR, ALL_SCOPES, 0, 0));
    // Rotation works on an Uninitialized escrow too (the
    // renew_delegation state rule).
    let mut fresh = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    fresh
        .delegate_authority(INITIALIZER, OPERATOR, DELEGATION_SCOPE_FUND)
        .unwrap();
    fresh
        .rotate_delegation_delegate(TAKER, NEW_OPERATOR)
        .unwrap();
    assert_eq!(fresh.delegation().unwrap().delegate(), NEW_OPERATOR);
}

#[test]
fn rotation_keeps_scopes_cap_spent_and_expiry_intact() {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    // A time-bounded, uncapped grant: window attached, cap 0.
    // Settle volume under the operator first.
    e.delegate_authority_with_expiry(INITIALIZER, OPERATOR, ALL_SCOPES, WINDOW)
        .unwrap();
    e.fund(INITIALIZER, T0).unwrap();
    e.release(OPERATOR, T0, 100_000, None, TAKER).unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 100_000);
    // Rotating the delegate keeps the settled volume and the window.
    e.rotate_delegation_delegate(TAKER, NEW_OPERATOR).unwrap();
    let grant = e.delegation().unwrap();
    assert_eq!(grant.delegate(), NEW_OPERATOR);
    assert_eq!(grant.scopes(), ALL_SCOPES);
    assert_eq!(grant.spend_cap(), 0);
    assert_eq!(grant.spent(), 100_000);
    assert_eq!(e.delegation_expires_at(), Some(WINDOW));

    // Capped variant: the cap survives a rotation too, and the
    // settled volume is not laundered — a re-grant would have
    // reset `spent` to 0, a rotation must not.
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
    e2.rotate_delegation_delegate(INITIALIZER, NEW_OPERATOR)
        .unwrap();
    assert_eq!(
        grant_fields(&e2),
        (NEW_OPERATOR, DELEGATION_SCOPE_RELEASE, CAP, 100_000)
    );
    // The cap still binds the grant's cumulative volume under the
    // new operator: 100_000 already spent, a further 450_000 would
    // breach the 500_000 cap.
    assert_eq!(
        e2.release(NEW_OPERATOR, T0, 450_000, None, TAKER),
        Err(EscrowError::SpendCapExceeded)
    );
    assert_eq!(e2.delegation().unwrap().spent(), 100_000);
}

#[test]
fn paused_escrow_refuses_the_rotation() {
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
        e.rotate_delegation_delegate(INITIALIZER, NEW_OPERATOR),
        Err(EscrowError::Paused)
    );
    assert_eq!(e.delegation().unwrap().delegate(), OPERATOR);
}

#[test]
fn non_party_caller_is_refused() {
    let mut e = funded_with_operator();
    // A stranger, and the operator themselves, are Unauthorized:
    // the delegate is a party power, never an operator power.
    assert_eq!(
        e.rotate_delegation_delegate(STRANGER, NEW_OPERATOR),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(
        e.rotate_delegation_delegate(OPERATOR, NEW_OPERATOR),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(e.delegation().unwrap().delegate(), OPERATOR);
}

#[test]
fn rotation_refused_once_the_escrow_settles() {
    let mut e = funded_with_operator();
    // The initializer settles the whole lockup: Funded -> Released.
    e.release(INITIALIZER, T0, AMOUNT, None, TAKER).unwrap();
    assert_eq!(e.state(), EscrowState::Released);
    assert_eq!(
        e.rotate_delegation_delegate(INITIALIZER, NEW_OPERATOR),
        Err(EscrowError::InvalidStateTransition)
    );
    assert_eq!(e.delegation().unwrap().delegate(), OPERATOR);
}

#[test]
fn rotation_without_a_grant_is_invalid() {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    e.fund(INITIALIZER, T0).unwrap();
    assert_eq!(
        e.rotate_delegation_delegate(INITIALIZER, NEW_OPERATOR),
        Err(EscrowError::InvalidDelegation)
    );
    assert_eq!(e.delegation(), None);
}

#[test]
fn zero_key_new_delegate_fails_closed_and_delegate_unchanged() {
    let mut e = funded_with_operator();
    e.release(OPERATOR, T0, 200_000, None, TAKER).unwrap();
    // A grant to nowhere: refused, the original delegate stays.
    assert_eq!(
        e.rotate_delegation_delegate(INITIALIZER, [0u8; 32]),
        Err(EscrowError::InvalidDelegation)
    );
    assert_eq!(
        grant_fields(&e),
        (OPERATOR, ALL_SCOPES, 0, 200_000)
    );
    // The zero-key check runs after the grant check: without a
    // grant even a zero key is the no-grant error (same code, same
    // fail-closed outcome — asserted via the grant state).
    let mut bare = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    bare.fund(INITIALIZER, T0).unwrap();
    assert_eq!(
        bare.rotate_delegation_delegate(INITIALIZER, [0u8; 32]),
        Err(EscrowError::InvalidDelegation)
    );
    assert_eq!(bare.delegation(), None);
}

#[test]
fn same_delegate_is_a_no_op_and_spent_kept() {
    let mut e = funded_with_operator();
    e.release(OPERATOR, T0, 300_000, None, TAKER).unwrap();
    // Re-affirming the live delegate succeeds and writes nothing.
    e.rotate_delegation_delegate(TAKER, OPERATOR).unwrap();
    assert_eq!(grant_fields(&e), (OPERATOR, ALL_SCOPES, 0, 300_000));
    // The no-op still needs a party: a stranger is refused even
    // for the identical delegate.
    assert_eq!(
        e.rotate_delegation_delegate(STRANGER, OPERATOR),
        Err(EscrowError::Unauthorized)
    );
}

#[test]
fn old_operator_loses_power_at_once_and_new_operator_takes_over() {
    let mut e = funded_with_operator();
    // In-scope: the operator release settles.
    e.release(OPERATOR, T0, 400_000, None, TAKER).unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 400_000);
    // Rotate: the old operator is cut off at once — the next
    // operator release is refused, and nothing moves.
    e.rotate_delegation_delegate(INITIALIZER, NEW_OPERATOR)
        .unwrap();
    assert_eq!(
        e.release(OPERATOR, T0, 100_000, None, TAKER),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(e.delegation().unwrap().spent(), 400_000);
    assert_eq!(e.released_amount(), 400_000);
    // The new operator holds the same scopes: the release settles
    // and charges against the same cumulative `spent`.
    e.release(NEW_OPERATOR, T0, 100_000, None, TAKER).unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 500_000);
    assert_eq!(e.released_amount(), 500_000);
}
