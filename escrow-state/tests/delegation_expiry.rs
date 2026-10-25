//! AV-215: time-bounded delegation — test matrix.
//!
//! A grant may carry an opt-in `expires_at`, set at grant time
//! (`delegate_authority_with_expiry`). While `now < expires_at`
//! the grant behaves exactly like an AV-104 grant; once
//! `now >= expires_at` the operator's every operation is refused
//! with `DelegationExpired` — fund, release and cancel alike —
//! while the parties keep full authority. Expiry deactivates, it
//! never clears: the grant and its `spent` counter survive the
//! lapse, the owner may renew the window (reactivating the same
//! grant with its history intact) or revoke it, and every grant
//! replacement, revocation or party rotation clears the window
//! with the grant, so a stale expiry can never attach itself to
//! a grant it was not set for.
//!
//! Check order on the gated paths is unchanged (party first,
//! then delegation): the expiry refusal sits inside the operator
//! branch of the authority check, before scope and before state.

use escrow_state::{
    Escrow, EscrowError, DELEGATION_SCOPE_CANCEL, DELEGATION_SCOPE_FUND,
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

const ALL_SCOPES: u32 = DELEGATION_SCOPE_FUND | DELEGATION_SCOPE_RELEASE | DELEGATION_SCOPE_CANCEL;

fn escrow_with_window() -> Escrow {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    e.delegate_authority_with_expiry(INITIALIZER, OPERATOR, ALL_SCOPES, WINDOW)
        .unwrap();
    e
}

#[test]
fn grant_with_expiry_validates_config() {
    let mut e = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    // Zero operator key, bad scopes, zero expiry: all config errors.
    assert_eq!(
        e.delegate_authority_with_expiry(INITIALIZER, [0u8; 32], ALL_SCOPES, WINDOW),
        Err(EscrowError::InvalidDelegation)
    );
    assert_eq!(
        e.delegate_authority_with_expiry(INITIALIZER, OPERATOR, 0, WINDOW),
        Err(EscrowError::InvalidDelegation)
    );
    assert_eq!(
        e.delegate_authority_with_expiry(INITIALIZER, OPERATOR, ALL_SCOPES, 0),
        Err(EscrowError::InvalidDelegation)
    );
    // A stranger cannot grant at all — the grant is a party power.
    assert_eq!(
        e.delegate_authority_with_expiry(STRANGER, OPERATOR, ALL_SCOPES, WINDOW),
        Err(EscrowError::Unauthorized)
    );
    // The grant lands with its window attached.
    e.delegate_authority_with_expiry(INITIALIZER, OPERATOR, ALL_SCOPES, WINDOW)
        .unwrap();
    assert_eq!(e.delegation_expires_at(), Some(WINDOW));
    assert!(!e.is_delegation_expired(WINDOW - 1));
    assert!(e.is_delegation_expired(WINDOW));
}

#[test]
fn operator_works_inside_the_window_and_is_refused_after_it() {
    let mut e = escrow_with_window();
    // Inside the window the operator funds and releases exactly
    // like an AV-104 operator.
    e.fund(OPERATOR, T0).unwrap();
    e.release(OPERATOR, T0, 100_000, None, TAKER).unwrap();
    // The uncapped grant still accumulates `spent` as an audit
    // counter (the AV-208 rule).
    assert_eq!(e.delegation().unwrap().spent(), 100_000);
    // At the expiry instant itself the window is already closed:
    // every operator path refuses with DelegationExpired, before
    // any scope or state question is asked.
    assert_eq!(
        e.release(OPERATOR, WINDOW, 100_000, None, TAKER),
        Err(EscrowError::DelegationExpired)
    );
    assert_eq!(
        e.cancel(OPERATOR, None, INITIALIZER, WINDOW),
        Err(EscrowError::DelegationExpired)
    );
    assert_eq!(
        e.fund(OPERATOR, WINDOW),
        Err(EscrowError::DelegationExpired)
    );
    // The role report agrees with the gate.
    assert_eq!(e.effective_role_at(OPERATOR, WINDOW), None);
    // The parties are never expiry-gated: the initializer settles
    // past the operator's window without a hiccup.
    assert!(e.effective_role_at(INITIALIZER, WINDOW).is_some());
    e.release(INITIALIZER, WINDOW, 100_000, None, TAKER).unwrap();
}

#[test]
fn renewal_reactivates_with_spent_intact() {
    let mut e = escrow_with_window();
    e.fund(OPERATOR, T0).unwrap();
    e.release(OPERATOR, T0, 100_000, None, TAKER).unwrap();
    assert_eq!(
        e.release(OPERATOR, WINDOW, 100_000, None, TAKER),
        Err(EscrowError::DelegationExpired)
    );
    // Renewal reactivates the lapsed grant — it is a pause, not a
    // death — and the settled volume survives the lapse.
    let later = WINDOW + 100_000;
    e.renew_delegation(INITIALIZER, later).unwrap();
    assert_eq!(e.delegation_expires_at(), Some(later));
    assert_eq!(e.delegation().unwrap().spent(), 100_000);
    e.release(OPERATOR, WINDOW + 1, 100_000, None, TAKER).unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 200_000);
    // Renewing to the identical expiry is a no-op success.
    e.renew_delegation(TAKER, later).unwrap();
    // Renewal needs a live grant and a real timestamp.
    let mut fresh = Escrow::initialize(INITIALIZER, TAKER, AMOUNT, ESCROW_EXPIRY).unwrap();
    assert_eq!(
        fresh.renew_delegation(INITIALIZER, later),
        Err(EscrowError::InvalidDelegation)
    );
    assert_eq!(
        e.renew_delegation(INITIALIZER, 0),
        Err(EscrowError::InvalidDelegation)
    );
    assert_eq!(
        e.renew_delegation(STRANGER, later + 1),
        Err(EscrowError::Unauthorized)
    );
}

#[test]
fn regrant_without_expiry_clears_the_window() {
    let mut e = escrow_with_window();
    e.fund(OPERATOR, T0).unwrap();
    // A plain re-grant of the identical operator and scopes is a
    // change, not a no-op, when a window is attached: the fresh
    // grant is unbounded, and no stale expiry may survive it.
    e.delegate_authority(INITIALIZER, OPERATOR, ALL_SCOPES).unwrap();
    assert_eq!(e.delegation_expires_at(), None);
    assert!(!e.is_delegation_expired(WINDOW));
    e.release(OPERATOR, WINDOW + 1, 100_000, None, TAKER).unwrap();
}

#[test]
fn expiry_change_on_the_same_grant_keeps_spent() {
    let mut e = escrow_with_window();
    e.fund(OPERATOR, T0).unwrap();
    e.release(OPERATOR, T0, 100_000, None, TAKER).unwrap();
    // Re-granting the identical grant with a new window keeps the
    // settled volume: a re-bound grant is the same grant with a
    // new window, not a new grant.
    let later = WINDOW + 100_000;
    e.delegate_authority_with_expiry(INITIALIZER, OPERATOR, ALL_SCOPES, later)
        .unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 100_000);
    assert_eq!(e.delegation_expires_at(), Some(later));
    // Re-granting the identical bound grant is a no-op success.
    e.delegate_authority_with_expiry(INITIALIZER, OPERATOR, ALL_SCOPES, later)
        .unwrap();
    assert_eq!(e.delegation().unwrap().spent(), 100_000);
}

#[test]
fn revocation_clears_grant_and_window_together() {
    let mut e = escrow_with_window();
    e.revoke_delegation(TAKER).unwrap();
    assert_eq!(e.delegation(), None);
    assert_eq!(e.delegation_expires_at(), None);
    // A future grant starts unbounded: no stale window attaches.
    e.delegate_authority(INITIALIZER, OPERATOR, ALL_SCOPES).unwrap();
    assert_eq!(e.delegation_expires_at(), None);
    assert!(!e.is_delegation_expired(WINDOW));
}
