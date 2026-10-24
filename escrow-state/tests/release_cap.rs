//! AV-205: per-call release cap — test matrix.
//!
//! When an escrow opts in via `with_max_release_per_call`
//! (Uninitialized-only, positive only), every taker payout call
//! whose gross amount exceeds the cap refuses with
//! `ReleaseExceedsCap` (code 316) and moves nothing: `release`,
//! `release_milestone`, `claim`, `release_split` (the gross split
//! total, so splitting across recipients never evades the cap),
//! `release_payout_split` (the full-lockup table path), and the
//! dual-control declaration `initiate_release` (with
//! `confirm_release` re-checking the live cap at settlement).
//! The cap is per call, not cumulative: several capped calls may
//! settle a deal larger than the cap. The cap itself changes only
//! by initializer+taker dual signature (`update_release_cap`);
//! it can be raised or lowered, never removed (0 is rejected on
//! both paths, so 0 in storage always means "never opted in").

use escrow_state::{Escrow, EscrowError, EscrowState, MilestonePlan, VestingSchedule};

fn initializer() -> [u8; 32] {
    [7u8; 32]
}

fn taker() -> [u8; 32] {
    [9u8; 32]
}

fn stranger() -> [u8; 32] {
    [11u8; 32]
}

fn checker() -> [u8; 32] {
    [13u8; 32]
}

fn other() -> [u8; 32] {
    [15u8; 32]
}

fn capped() -> Escrow {
    Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_max_release_per_call(600)
        .unwrap()
}

fn funded_capped() -> Escrow {
    let mut e = capped();
    e.fund(initializer(), 100).unwrap();
    e
}

#[test]
fn builder_is_uninitialized_only_and_rejects_zero() {
    assert_eq!(capped().max_release_per_call(), 600);
    // A plain escrow has no cap: 0 means "never opted in".
    let plain = Escrow::initialize(initializer(), taker(), 1_000, 10_000).unwrap();
    assert_eq!(plain.max_release_per_call(), 0);
    // Zero is not a cap: the opt-in must be positive.
    assert_eq!(
        Escrow::initialize(initializer(), taker(), 1_000, 10_000)
            .unwrap()
            .with_max_release_per_call(0),
        Err(EscrowError::AmountMismatch)
    );
    // Funded first, then configured, refuses too.
    let funded = funded_capped();
    assert_eq!(
        funded.with_max_release_per_call(100),
        Err(EscrowError::InvalidStateTransition)
    );
    let mut plain_funded = Escrow::initialize(initializer(), taker(), 1_000, 10_000).unwrap();
    plain_funded.fund(initializer(), 100).unwrap();
    assert_eq!(
        plain_funded.with_max_release_per_call(100),
        Err(EscrowError::InvalidStateTransition)
    );
}

#[test]
fn error_code_is_316_and_stable() {
    assert_eq!(EscrowError::ReleaseExceedsCap.code(), 316);
}

#[test]
fn release_bound_per_call_not_cumulative() {
    let mut e = funded_capped();
    // The full deal exceeds the cap: refused, moves nothing,
    // charges no fee.
    assert_eq!(
        e.release(initializer(), 200, 1_000, None, taker()),
        Err(EscrowError::ReleaseExceedsCap)
    );
    assert_eq!(e.released_amount(), 0);
    assert_eq!(e.fees_paid(), 0);
    assert_eq!(e.state(), EscrowState::Funded);
    // Exactly at the cap settles.
    assert_eq!(
        e.release(initializer(), 200, 600, None, taker()).unwrap(),
        (600, 0)
    );
    // A second capped call settles the remainder: the cap binds
    // each call, not the deal total (600 + 400 > 600).
    assert_eq!(
        e.release(initializer(), 200, 400, None, taker()).unwrap(),
        (400, 0)
    );
    assert_eq!(e.state(), EscrowState::Released);
}

#[test]
fn milestone_tranche_bound_and_dual_signed_raise() {
    let plan = MilestonePlan::new(&[400, 600]).unwrap();
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_max_release_per_call(500)
        .unwrap()
        .with_milestones(plan)
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    e.confirm_milestone(initializer(), 0).unwrap();
    e.confirm_milestone(taker(), 0).unwrap();
    assert_eq!(
        e.release_milestone(initializer(), 200, 0, None, taker())
            .unwrap(),
        (400, 0)
    );
    e.confirm_milestone(initializer(), 1).unwrap();
    e.confirm_milestone(taker(), 1).unwrap();
    // The 600 tranche exceeds the 500 cap.
    assert_eq!(
        e.release_milestone(initializer(), 200, 1, None, taker()),
        Err(EscrowError::ReleaseExceedsCap)
    );
    assert_eq!(e.released_amount(), 400);
    // Both parties raise the cap; the tranche settles.
    e.update_release_cap(initializer(), taker(), 600).unwrap();
    assert_eq!(e.max_release_per_call(), 600);
    assert_eq!(
        e.release_milestone(initializer(), 200, 1, None, taker())
            .unwrap(),
        (600, 0)
    );
    assert_eq!(e.state(), EscrowState::Released);
}

#[test]
fn claim_bound_by_cap_and_refuses_slice_semantics() {
    let schedule = VestingSchedule::new(0, 100).unwrap();
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_max_release_per_call(600)
        .unwrap()
        .with_vesting(schedule)
        .unwrap();
    e.fund(initializer(), 0).unwrap();
    // Fully vested at t=100, but the 1_000 pull exceeds the cap:
    // the claim refuses outright rather than paying a 600 slice.
    assert_eq!(
        e.claim(taker(), 100, None, taker()),
        Err(EscrowError::ReleaseExceedsCap)
    );
    assert_eq!(e.released_amount(), 0);
    e.update_release_cap(initializer(), taker(), 1_000).unwrap();
    assert_eq!(e.claim(taker(), 100, None, taker()).unwrap(), (1_000, 0));
}

#[test]
fn split_total_bound_not_per_leg() {
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_max_release_per_call(600)
        .unwrap()
        .with_payout_allowlist(&[taker(), other()])
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    // Every leg is under the cap, but the 1_000 total is over it.
    assert_eq!(
        e.release_split(initializer(), 200, 1_000, None, &[(taker(), 5000), (other(), 5000)]),
        Err(EscrowError::ReleaseExceedsCap)
    );
    assert_eq!(e.released_amount(), 0);
    let (legs, fee) = e
        .release_split(initializer(), 200, 600, None, &[(taker(), 5000), (other(), 5000)])
        .unwrap();
    assert_eq!(fee, 0);
    assert_eq!(legs, vec![(taker(), 300), (other(), 300)]);
}

#[test]
fn payout_split_table_bound() {
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_max_release_per_call(600)
        .unwrap()
        .with_payout_split(&[(taker(), 700), (other(), 300)])
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    // The table path settles the full lockup in one call, so the
    // 1_000 total refuses under a 600 cap — otherwise the cap
    // would be trivially bypassable through the declared table.
    assert_eq!(
        e.release_payout_split(initializer(), 200, None),
        Err(EscrowError::ReleaseExceedsCap)
    );
    e.update_release_cap(initializer(), taker(), 1_000).unwrap();
    let legs = e.release_payout_split(initializer(), 200, None).unwrap();
    assert_eq!(legs, vec![(taker(), 700), (other(), 300)]);
    assert_eq!(e.state(), EscrowState::Released);
}

#[test]
fn dual_control_intent_bound_at_declaration_and_confirm() {
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_max_release_per_call(600)
        .unwrap()
        .with_dual_control(checker())
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    // A too-large declaration never becomes a live intent.
    assert_eq!(
        e.initiate_release(initializer(), 200, 1_000, None, taker(), 10_000),
        Err(EscrowError::ReleaseExceedsCap)
    );
    assert_eq!(
        e.confirm_release(checker(), 300),
        Err(EscrowError::DualControlNotInitiated)
    );
    // A capped declaration goes live.
    e.initiate_release(initializer(), 200, 600, None, taker(), 10_000)
        .unwrap();
    // Lowering the cap after declaration still refuses the
    // confirm — and the intent stays live for a retry.
    e.update_release_cap(initializer(), taker(), 500).unwrap();
    assert_eq!(
        e.confirm_release(checker(), 300),
        Err(EscrowError::ReleaseExceedsCap)
    );
    e.update_release_cap(initializer(), taker(), 600).unwrap();
    assert_eq!(
        e.confirm_release(checker(), 300).unwrap(),
        (600, 0)
    );
}

#[test]
fn update_release_cap_auth_shape_and_state() {
    // Uninitialized: the builder is the path, not the update.
    let mut fresh = capped();
    assert_eq!(
        fresh.update_release_cap(initializer(), taker(), 700),
        Err(EscrowError::InvalidStateTransition)
    );
    let mut e = funded_capped();
    // Either party alone, or a stranger, cannot move the cap.
    assert_eq!(
        e.update_release_cap(initializer(), stranger(), 700),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(
        e.update_release_cap(stranger(), taker(), 700),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(
        e.update_release_cap(stranger(), stranger(), 700),
        Err(EscrowError::Unauthorized)
    );
    // Zero never removes the cap.
    assert_eq!(
        e.update_release_cap(initializer(), taker(), 0),
        Err(EscrowError::AmountMismatch)
    );
    assert_eq!(e.max_release_per_call(), 600);
    // Both parties together: raise and lower both work.
    e.update_release_cap(initializer(), taker(), 700).unwrap();
    assert_eq!(e.max_release_per_call(), 700);
    e.update_release_cap(initializer(), taker(), 500).unwrap();
    assert_eq!(e.max_release_per_call(), 500);
    // Lowering the cap binds the next call immediately.
    assert_eq!(
        e.release(initializer(), 200, 600, None, taker()),
        Err(EscrowError::ReleaseExceedsCap)
    );
}

#[test]
fn plain_escrow_has_no_cap() {
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000).unwrap();
    e.fund(initializer(), 100).unwrap();
    assert_eq!(
        e.release(initializer(), 200, 1_000, None, taker()).unwrap(),
        (1_000, 0)
    );
}
