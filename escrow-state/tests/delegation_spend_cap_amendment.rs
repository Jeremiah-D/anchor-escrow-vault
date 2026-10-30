//! AV-295: delegation spend-cap revision — test matrix.
//!
//! Either party may revise the live grant's spend cap in place
//! (`amend_delegation_spend_cap`): up, down, or to `0` (uncapped) —
//! but never below the volume already settled under the live grant,
//! so a settled release is never retroactively over-cap. Only the
//! cap moves: the operator, the scopes, the settled `spent` counter
//! and the expiry window are untouched, and the operator spend path
//! reads the live cap on every release, so the new bound governs
//! from the next operator release onward. Check order mirrors
//! `renew_delegation`: pause → authority → state, then
//! `InvalidDelegation` for no grant or a cap below live `spent`.
//! No new event: like renewal, the amendment emits nothing.

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

fn funded_with_cap() -> Escrow {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    e.delegate_authority_with_spend_cap(
        INITIALIZER,
        OPERATOR,
        DELEGATION_SCOPE_RELEASE,
        CAP,
    )
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
fn either_party_may_amend_the_cap() {
    let mut e = funded_with_cap();
    // The initializer raises the cap; only the cap moves.
    e.amend_delegation_spend_cap(INITIALIZER, 800_000).unwrap();
    assert_eq!(
        grant_fields(&e),
        (OPERATOR, DELEGATION_SCOPE_RELEASE, 800_000, 0)
    );
    // The taker lowers it back; the grant identity is untouched.
    e.amend_delegation_spend_cap(TAKER, 400_000).unwrap();
    assert_eq!(
        grant_fields(&e),
        (OPERATOR, DELEGATION_SCOPE_RELEASE, 400_000, 0)
    );
    // Amendment works on an Uninitialized escrow too (the
    // renew_delegation state rule).
    let mut fresh = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    fresh
        .delegate_authority_with_spend_cap(INITIALIZER, OPERATOR, DELEGATION_SCOPE_RELEASE, CAP)
        .unwrap();
    fresh.amend_delegation_spend_cap(TAKER, 600_000).unwrap();
    assert_eq!(fresh.delegation().unwrap().spend_cap(), 600_000);
}

#[test]
fn amendment_keeps_spent_and_expiry_intact() {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    // An uncapped, time-bounded grant: cap 0, window attached.
    e.delegate_authority_with_expiry(INITIALIZER, OPERATOR, ALL_SCOPES, WINDOW)
        .unwrap();
    e.fund(INITIALIZER, T0).unwrap();
    e.release(OPERATOR, T0, 100_000, None, TAKER).unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 100_000);
    // Capping the grant keeps the settled volume and the window.
    e.amend_delegation_spend_cap(TAKER, 250_000).unwrap();
    let grant = e.delegation().unwrap();
    assert_eq!(grant.delegate(), OPERATOR);
    assert_eq!(grant.scopes(), ALL_SCOPES);
    assert_eq!(grant.spend_cap(), 250_000);
    assert_eq!(grant.spent(), 100_000);
    assert_eq!(e.delegation_expires_at(), Some(WINDOW));
}

#[test]
fn paused_escrow_refuses_the_amendment() {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY)
        .unwrap()
        .with_pause_authority(INITIALIZER)
        .unwrap();
    e.delegate_authority_with_spend_cap(
        INITIALIZER,
        OPERATOR,
        DELEGATION_SCOPE_RELEASE,
        CAP,
    )
    .unwrap();
    e.fund(INITIALIZER, T0).unwrap();
    e.pause(INITIALIZER, None).unwrap();
    // The pause gate fires first — before any authority question.
    assert_eq!(
        e.amend_delegation_spend_cap(INITIALIZER, 600_000),
        Err(EscrowError::Paused)
    );
    assert_eq!(e.delegation().unwrap().spend_cap(), CAP);
}

#[test]
fn non_party_caller_is_refused() {
    let mut e = funded_with_cap();
    // A stranger, and the operator themselves, are Unauthorized:
    // the cap is a party power, never an operator power.
    assert_eq!(
        e.amend_delegation_spend_cap(STRANGER, 600_000),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(
        e.amend_delegation_spend_cap(OPERATOR, 600_000),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(e.delegation().unwrap().spend_cap(), CAP);
}

#[test]
fn amendment_refused_once_the_escrow_settles() {
    let mut e = funded_with_cap();
    // The initializer settles the whole lockup: Funded -> Released.
    e.release(INITIALIZER, T0, AMOUNT, None, TAKER).unwrap();
    assert_eq!(e.state(), EscrowState::Released);
    assert_eq!(
        e.amend_delegation_spend_cap(INITIALIZER, 600_000),
        Err(EscrowError::InvalidStateTransition)
    );
    assert_eq!(e.delegation().unwrap().spend_cap(), CAP);
}

#[test]
fn amendment_without_a_grant_is_invalid() {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    e.fund(INITIALIZER, T0).unwrap();
    assert_eq!(
        e.amend_delegation_spend_cap(INITIALIZER, 600_000),
        Err(EscrowError::InvalidDelegation)
    );
    assert_eq!(e.delegation(), None);
}

#[test]
fn cap_below_live_spent_is_refused_and_cap_unchanged() {
    let mut e = funded_with_cap();
    e.release(OPERATOR, T0, 300_000, None, TAKER).unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 300_000);
    // 200_000 is below the 300_000 already settled: fail-closed,
    // the original cap stays.
    assert_eq!(
        e.amend_delegation_spend_cap(INITIALIZER, 200_000),
        Err(EscrowError::InvalidDelegation)
    );
    assert_eq!(e.delegation().unwrap().spend_cap(), CAP);
    assert_eq!(e.delegation().unwrap().spent(), 300_000);
    // Exactly at the settled volume is allowed: the cap is a bound
    // on future volume, and nothing settled is over it.
    e.amend_delegation_spend_cap(TAKER, 300_000).unwrap();
    assert_eq!(e.delegation().unwrap().spend_cap(), 300_000);
    // At the cap, one more unit of operator volume is refused.
    assert_eq!(
        e.release(OPERATOR, T0, 1, None, TAKER),
        Err(EscrowError::SpendCapExceeded)
    );
    assert_eq!(e.delegation().unwrap().spent(), 300_000);
}

#[test]
fn zero_cap_means_uncapped() {
    let mut e = funded_with_cap();
    e.release(OPERATOR, T0, 300_000, None, TAKER).unwrap();
    // Dropping the cap to 0 lifts the bound entirely: the operator
    // may settle the rest of the lockup, and `spent` keeps
    // accumulating as the audit counter.
    e.amend_delegation_spend_cap(INITIALIZER, 0).unwrap();
    assert_eq!(e.delegation().unwrap().spend_cap(), 0);
    e.release(OPERATOR, T0, 700_000, None, TAKER).unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 1_000_000);
    assert_eq!(e.state(), EscrowState::Released);
}

#[test]
fn same_cap_is_a_no_op() {
    let mut e = funded_with_cap();
    e.release(OPERATOR, T0, 300_000, None, TAKER).unwrap();
    // Re-affirming the live cap succeeds and writes nothing.
    e.amend_delegation_spend_cap(TAKER, CAP).unwrap();
    assert_eq!(
        grant_fields(&e),
        (OPERATOR, DELEGATION_SCOPE_RELEASE, CAP, 300_000)
    );
    // The no-op still needs a party: a stranger is refused even
    // for the identical cap.
    assert_eq!(
        e.amend_delegation_spend_cap(STRANGER, CAP),
        Err(EscrowError::Unauthorized)
    );
}

#[test]
fn operator_enforcement_honors_the_amended_cap() {
    let mut e = funded_with_cap();
    e.release(OPERATOR, T0, 300_000, None, TAKER).unwrap();
    // Tighten the cap to 400_000: the next 200_000 would push
    // spent to 500_000, past the new bound, and is refused.
    e.amend_delegation_spend_cap(INITIALIZER, 400_000).unwrap();
    assert_eq!(
        e.release(OPERATOR, T0, 200_000, None, TAKER),
        Err(EscrowError::SpendCapExceeded)
    );
    assert_eq!(e.delegation().unwrap().spent(), 300_000);
    // Exactly up to the new cap still settles.
    e.release(OPERATOR, T0, 100_000, None, TAKER).unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 400_000);
    // Loosening the cap re-opens the operator path at once.
    e.amend_delegation_spend_cap(TAKER, 1_000_000).unwrap();
    e.release(OPERATOR, T0, 500_000, None, TAKER).unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 900_000);
}
