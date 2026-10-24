//! AV-206: milestone due dates and late-release penalties — test matrix.
//!
//! When an escrow opts in via `with_milestone_due_dates` (after
//! `with_milestones`, `Uninitialized`-only, one strictly increasing
//! deadline per tranche) and `with_late_penalty_bps` (0–10_000 bps),
//! a `release_milestone` after a tranche's deadline settles as:
//!
//! ```text
//! released      += tranche - penalty   (net taker principal)
//! penalty_paid  += penalty             (late-penalty sink)
//! taker_payout   = (tranche - penalty) - fee + interest
//! ```
//!
//! so `released + penalty_paid + skipped + remaining == amount`
//! with the conservation formula untouched, and the escrow closes
//! exactly when `released + penalty_paid == amount` (the pre-AV-206
//! close test `released == amount` is that test with
//! `penalty_paid == 0`). Releasing exactly at `due_at` is on time,
//! not late. The protocol fee slices the *net* tranche, never the
//! forfeited slice; the AV-205 per-call cap still binds the *gross*
//! tranche. A rate without deadlines prices nothing (no tranche has
//! a deadline to miss), and deadlines without a rate price nothing
//! either — the two builders compose, neither implies the other.
//! This reuses the AV-82 `penalty_paid` sink safely because `slash`
//! refuses milestone-scheduled escrows: on a milestone escrow that
//! counter can only ever hold late penalties.

use escrow_state::{Escrow, EscrowError, EscrowState, MilestonePlan};

fn initializer() -> [u8; 32] {
    [7u8; 32]
}

fn taker() -> [u8; 32] {
    [9u8; 32]
}

fn plan() -> MilestonePlan {
    MilestonePlan::new(&[400, 600]).unwrap()
}

/// Milestone escrow with deadlines [1000, 2000] and a 10% late rate.
fn dated() -> Escrow {
    Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_milestones(plan())
        .unwrap()
        .with_milestone_due_dates(&[1_000, 2_000])
        .unwrap()
        .with_late_penalty_bps(1_000)
        .unwrap()
}

fn funded_dated() -> Escrow {
    let mut e = dated();
    e.fund(initializer(), 100).unwrap();
    e
}

fn confirm_both(e: &mut Escrow, index: u8) {
    e.confirm_milestone(initializer(), index).unwrap();
    e.confirm_milestone(taker(), index).unwrap();
}

#[test]
fn builders_are_uninitialized_only_and_validate_shape() {
    assert_eq!(dated().milestone_due_at(0), Some(1_000));
    assert_eq!(dated().milestone_due_at(1), Some(2_000));
    assert_eq!(dated().milestone_due_at(2), None);
    assert_eq!(dated().milestone_late_penalty_bps(), 1_000);

    // No plan attached yet: the table has no tranche count to match.
    let no_plan = Escrow::initialize(initializer(), taker(), 1_000, 10_000).unwrap();
    assert_eq!(
        no_plan.with_milestone_due_dates(&[1_000, 2_000]),
        Err(EscrowError::InvalidMilestones)
    );
    // Length mismatch, non-increasing, and zero deadlines all fail.
    let base = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_milestones(plan())
        .unwrap();
    assert_eq!(
        base.with_milestone_due_dates(&[1_000]),
        Err(EscrowError::InvalidMilestones)
    );
    assert_eq!(
        base.with_milestone_due_dates(&[1_000, 1_000]),
        Err(EscrowError::InvalidMilestones)
    );
    assert_eq!(
        base.with_milestone_due_dates(&[2_000, 1_000]),
        Err(EscrowError::InvalidMilestones)
    );
    assert_eq!(
        base.with_milestone_due_dates(&[0, 2_000]),
        Err(EscrowError::InvalidMilestones)
    );
    // A rate above 100% is not a rate.
    assert_eq!(
        base.with_late_penalty_bps(10_001),
        Err(EscrowError::InvalidPenalty)
    );
    // Both builders refuse a funded escrow.
    let funded = funded_dated();
    assert_eq!(
        funded.with_milestone_due_dates(&[1_000, 2_000]),
        Err(EscrowError::InvalidStateTransition)
    );
    assert_eq!(
        funded.with_late_penalty_bps(500),
        Err(EscrowError::InvalidStateTransition)
    );
}

#[test]
fn release_exactly_at_due_at_is_on_time() {
    let mut e = funded_dated();
    confirm_both(&mut e, 0);
    let (payout, fee) = e.release_milestone(initializer(), 1_000, 0, None, taker()).unwrap();
    assert_eq!((payout, fee), (400, 0));
    assert_eq!(e.released_amount(), 400);
    assert_eq!(e.penalty_paid(), 0);
    assert_eq!(e.state(), EscrowState::Funded);
}

#[test]
fn late_release_deducts_penalty_and_closes_on_gross_total() {
    let mut e = funded_dated();
    confirm_both(&mut e, 0);
    e.release_milestone(initializer(), 1_000, 0, None, taker()).unwrap();
    confirm_both(&mut e, 1);
    // One second past the deadline: 10% of 600 = 60.
    let (payout, fee) = e.release_milestone(initializer(), 2_001, 1, None, taker()).unwrap();
    assert_eq!((payout, fee), (540, 0));
    assert_eq!(e.released_amount(), 940);
    assert_eq!(e.penalty_paid(), 60);
    assert_eq!(e.remaining_amount(), 0);
    // Conservation: net released + penalty == the locked amount.
    assert_eq!(e.released_amount() + e.penalty_paid(), 1_000);
    assert_eq!(e.state(), EscrowState::Released);
}

#[test]
fn rate_without_deadlines_and_deadlines_without_rate_price_nothing() {
    // Rate alone: no deadline to miss, so a late-looking release
    // (now far past any calendar) still pays in full.
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_milestones(plan())
        .unwrap()
        .with_late_penalty_bps(1_000)
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    confirm_both(&mut e, 0);
    let (payout, _) = e.release_milestone(initializer(), 99_999, 0, None, taker()).unwrap();
    assert_eq!(payout, 400);
    assert_eq!(e.penalty_paid(), 0);
    // Deadlines alone: no rate, so a release past the deadline
    // still pays in full.
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_milestones(plan())
        .unwrap()
        .with_milestone_due_dates(&[1_000, 2_000])
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    confirm_both(&mut e, 0);
    let (payout, _) = e.release_milestone(initializer(), 99_999, 0, None, taker()).unwrap();
    assert_eq!(payout, 400);
    assert_eq!(e.penalty_paid(), 0);
}

#[test]
fn protocol_fee_slices_the_net_tranche_not_the_penalty() {
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_milestones(MilestonePlan::new(&[1_000]).unwrap())
        .unwrap()
        .with_milestone_due_dates(&[1_000])
        .unwrap()
        .with_late_penalty_bps(1_000)
        .unwrap()
        .with_protocol_fee(1_000)
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    confirm_both(&mut e, 0);
    // Penalty 100 (10% of 1000), net 900, fee 90 (10% of 900).
    let (payout, fee) = e.release_milestone(initializer(), 1_001, 0, None, taker()).unwrap();
    assert_eq!((payout, fee), (810, 90));
    assert_eq!(e.released_amount(), 900);
    assert_eq!(e.penalty_paid(), 100);
    assert_eq!(e.state(), EscrowState::Released);
}

#[test]
fn per_call_cap_binds_the_gross_tranche() {
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_milestones(plan())
        .unwrap()
        .with_milestone_due_dates(&[1_000, 2_000])
        .unwrap()
        .with_late_penalty_bps(1_000)
        .unwrap()
        .with_max_release_per_call(500)
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    confirm_both(&mut e, 0);
    e.release_milestone(initializer(), 1_000, 0, None, taker()).unwrap();
    confirm_both(&mut e, 1);
    // Gross 600 exceeds the 500 cap even though the net (540)
    // would not: the cap binds the call's gross amount.
    assert_eq!(
        e.release_milestone(initializer(), 2_001, 1, None, taker()),
        Err(EscrowError::ReleaseExceedsCap)
    );
    assert_eq!(e.released_amount(), 400);
    assert_eq!(e.penalty_paid(), 0);
    assert_eq!(e.state(), EscrowState::Funded);
}

#[test]
fn skipped_tranche_keeps_the_escrow_open_after_a_late_release() {
    let mut e = funded_dated();
    // Skip tranche 0 by mutual agreement (refund path, not penalty).
    e.skip_milestone(initializer(), 0).unwrap();
    e.skip_milestone(taker(), 0).unwrap();
    confirm_both(&mut e, 1);
    let (payout, _) = e.release_milestone(initializer(), 2_001, 1, None, taker()).unwrap();
    assert_eq!(payout, 540);
    assert_eq!(e.released_amount(), 540);
    assert_eq!(e.penalty_paid(), 60);
    // released + penalty (600) != amount (1000): the skipped 400
    // is still the initializer's refund, so the escrow stays Funded
    // and the remainder is exactly the skipped amount.
    assert_eq!(e.state(), EscrowState::Funded);
    assert_eq!(e.remaining_amount(), 400);
}
