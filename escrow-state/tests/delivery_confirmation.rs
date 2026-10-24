//! AV-203: delivery-confirmation gate — test matrix.
//!
//! When an escrow opts in via `with_delivery_confirmation`
//! (Uninitialized-only), the three taker payout paths — `release`,
//! `claim` and `release_milestone` — refuse to settle until the
//! taker confirms receipt with `confirm_delivery`
//! (`DeliveryNotConfirmed`, code 315). The gate is the last check
//! before settlement, so a refused payout charges no fee and moves
//! no funds. The unilateral exits (`cancel`, `cancel_expired`)
//! and the arbiter's `resolve` are deliberately *not* gated, so a
//! taker who refuses to confirm can never trap funds forever.
//! Orthogonal to AV-130 (maker-checker on the authority side —
//! this is the taker-side receipt confirmation).
//!
//! Check order on the payout paths: authority → state → … →
//! delivery-confirmation.

use escrow_state::{
    Escrow, EscrowError, EscrowEventKind, EscrowState, IndexedEscrow, MilestonePlan,
    VestingSchedule,
};

fn initializer() -> [u8; 32] {
    [7u8; 32]
}

fn taker() -> [u8; 32] {
    [9u8; 32]
}

fn stranger() -> [u8; 32] {
    [11u8; 32]
}

fn arbiter() -> [u8; 32] {
    [13u8; 32]
}

fn gated() -> Escrow {
    Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_delivery_confirmation()
        .unwrap()
}

fn funded_gated() -> Escrow {
    let mut e = gated();
    e.fund(initializer(), 100).unwrap();
    e
}

#[test]
fn builder_is_uninitialized_only() {
    let e = funded_gated();
    assert_eq!(
        e.with_delivery_confirmation(),
        Err(EscrowError::InvalidStateTransition)
    );
    // A plain escrow funded first, then configured, refuses too.
    let mut plain = Escrow::initialize(initializer(), taker(), 1_000, 10_000).unwrap();
    plain.fund(initializer(), 100).unwrap();
    assert_eq!(
        plain.with_delivery_confirmation(),
        Err(EscrowError::InvalidStateTransition)
    );
    assert!(!plain.delivery_confirmation());
    assert!(e.delivery_confirmation());
    assert!(!e.delivery_confirmed());
}

#[test]
fn release_blocked_until_taker_confirms() {
    let mut e = funded_gated();
    // Before confirmation the payout refuses, moves nothing, and
    // charges no fee.
    assert_eq!(
        e.release(initializer(), 200, 1_000, None, taker()),
        Err(EscrowError::DeliveryNotConfirmed)
    );
    assert_eq!(e.released_amount(), 0);
    assert_eq!(e.fees_paid(), 0);
    assert_eq!(e.state(), EscrowState::Funded);
    // The initializer cannot confirm their own delivery.
    assert_eq!(
        e.confirm_delivery(initializer()),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(
        e.confirm_delivery(stranger()),
        Err(EscrowError::Unauthorized)
    );
    // The taker confirms; the payout settles in full.
    e.confirm_delivery(taker()).unwrap();
    assert!(e.delivery_confirmed());
    // Idempotent: a second confirmation is a no-op, not an error.
    e.confirm_delivery(taker()).unwrap();
    assert_eq!(e.release(initializer(), 200, 1_000, None, taker()).unwrap(), (1_000, 0));
    assert_eq!(e.state(), EscrowState::Released);
}

#[test]
fn claim_blocked_until_taker_confirms() {
    let schedule = VestingSchedule::new(0, 100).unwrap();
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_delivery_confirmation()
        .unwrap()
        .with_vesting(schedule)
        .unwrap();
    e.fund(initializer(), 0).unwrap();
    // Fully vested at t=100, but the gate still refuses the pull.
    assert_eq!(
        e.claim(taker(), 100, None, taker()),
        Err(EscrowError::DeliveryNotConfirmed)
    );
    e.confirm_delivery(taker()).unwrap();
    assert_eq!(e.claim(taker(), 100, None, taker()).unwrap(), (1_000, 0));
}

#[test]
fn milestone_release_blocked_until_taker_confirms() {
    let plan = MilestonePlan::new(&[400, 600]).unwrap();
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_delivery_confirmation()
        .unwrap()
        .with_milestones(plan)
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    e.confirm_milestone(initializer(), 0).unwrap();
    e.confirm_milestone(taker(), 0).unwrap();
    assert_eq!(
        e.release_milestone(initializer(), 200, 0, None, taker()),
        Err(EscrowError::DeliveryNotConfirmed)
    );
    e.confirm_delivery(taker()).unwrap();
    assert_eq!(
        e.release_milestone(initializer(), 200, 0, None, taker())
            .unwrap(),
        (400, 0)
    );
}

#[test]
fn cancel_paths_and_resolve_are_not_gated() {
    // Unilateral cancel needs no confirmation.
    let mut e = funded_gated();
    e.cancel(initializer(), None, initializer(), 200).unwrap();
    assert_eq!(e.state(), EscrowState::Cancelled);

    // Expiry cancel needs no confirmation either.
    let mut e2 = funded_gated();
    e2.cancel_expired(initializer(), 10_001, None, initializer())
        .unwrap();
    assert_eq!(e2.state(), EscrowState::Cancelled);

    // Arbiter settlement needs no confirmation.
    let mut e3 = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_delivery_confirmation()
        .unwrap()
        .with_arbiter(arbiter())
        .unwrap();
    e3.fund(initializer(), 100).unwrap();
    e3.escalate(initializer(), 200, 1_000, None, None, 0).unwrap();
    let (taker_payout, _, _) = e3
        .resolve(arbiter(), 600, 300, None, None, taker())
        .unwrap();
    assert_eq!(taker_payout, 600);
    assert_eq!(e3.state(), EscrowState::Settled);
}

#[test]
fn plain_escrow_pays_without_any_confirmation() {
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000).unwrap();
    assert!(!e.delivery_confirmation());
    e.fund(initializer(), 100).unwrap();
    assert_eq!(e.release(initializer(), 200, 1_000, None, taker()).unwrap(), (1_000, 0));
}

#[test]
fn indexed_wrapper_emits_delivery_confirmed_once() {
    let mut indexed = IndexedEscrow::initialize(initializer(), taker(), 1_000, 10_000, [3u8; 32], 0)
        .unwrap()
        .with_delivery_confirmation()
        .unwrap();
    indexed.fund(initializer(), 100).unwrap();
    let before = indexed.events().len();
    indexed.confirm_delivery(taker(), 200).unwrap();
    let events = indexed.events();
    assert_eq!(events.len(), before + 1);
    let last = events.last().unwrap();
    assert_eq!(last.kind, EscrowEventKind::DeliveryConfirmed);
    assert_eq!(last.kind.name(), "delivery_confirmed");
    // Repeat confirmation emits nothing.
    indexed.confirm_delivery(taker(), 201).unwrap();
    assert_eq!(indexed.events().len(), before + 1);
    // And the payout path is now open through the wrapper too.
    assert_eq!(
        indexed.release(initializer(), 1_000, None, taker(), 202).unwrap(),
        (1_000, 0)
    );
}

#[test]
fn error_code_is_315_and_stable() {
    assert_eq!(EscrowError::DeliveryNotConfirmed.code(), 315);
}
