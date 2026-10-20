//! AV-160: the permissionless subscription-period crank
//! (`Escrow::crank_release_period`) — test matrix.
//!
//! The crank is the subscription analogue of the AV-48
//! `crank_expired` convention: anyone may release the next *due*
//! subscription period, the payout is pinned to the taker, and the
//! caller receives zero (anti-MEV). Every other gate mirrors
//! `release_period` exactly — the matrix below pins the happy path,
//! each rejection mode, the zero-reward property, and gate
//! consistency between the two entry points.

use escrow_state::{
    Escrow, EscrowError, EscrowEventKind, EscrowState, IndexedEscrow, QuorumPolicy,
};

const ALICE: [u8; 32] = [0xAA; 32]; // initializer
const BOB: [u8; 32] = [0xBB; 32]; // taker
const MALLORY: [u8; 32] = [0xCC; 32]; // stranger / cranker
const ATTESTOR: [u8; 32] = [0xA1; 32];
const MINT: [u8; 32] = [0xA5; 32];
const OTHER_MINT: [u8; 32] = [0xB5; 32];

const AMOUNT: u64 = 1_000_000;
const PERIODS: u8 = 4;
const PER_PERIOD: u64 = 250_000;
const PERIOD_SECS: u64 = 86_400;
const EXPIRES_AT: u64 = 1_800_000_000;
const ESCROW_ID: [u8; 32] = [0xE5; 32];
const T0: u64 = 1_700_000_000;

/// A funded subscription escrow: 4 daily periods, last one pinned to
/// `EXPIRES_AT` (back-scheduled).
fn subscription_escrow() -> Escrow {
    let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
        .unwrap()
        .with_subscription(PERIOD_SECS, PERIODS, PER_PERIOD)
        .unwrap();
    e.fund(ALICE, EXPIRES_AT - 4 * PERIOD_SECS).unwrap();
    e
}

fn due_at(index: u8) -> u64 {
    EXPIRES_AT - (PERIODS as u64 - 1 - index as u64) * PERIOD_SECS
}

#[test]
fn crank_due_period_by_stranger_pays_taker() {
    // Permissionless: a stranger (neither party) releases the due
    // period; the tranche lands in the taker's accounting.
    let mut e = subscription_escrow();
    let (payout, fee) = e.crank_release_period(MALLORY, due_at(0), None).unwrap();
    assert_eq!(payout + fee, PER_PERIOD, "payout + fee == per_period");
    assert_eq!(e.subscription_next_period(), 1);
    assert_eq!(e.released_amount(), PER_PERIOD);
    assert_eq!(e.state(), EscrowState::Funded);
}

#[test]
fn crank_before_due_is_rejected() {
    let mut e = subscription_escrow();
    assert_eq!(
        e.crank_release_period(MALLORY, due_at(0) - 1, None),
        Err(EscrowError::PeriodNotDue)
    );
    assert_eq!(e.subscription_next_period(), 0, "no state moved");
}

#[test]
fn crank_replay_and_skip_ahead_are_rejected() {
    let mut e = subscription_escrow();
    e.crank_release_period(MALLORY, due_at(0), None).unwrap();
    // The crank always targets the next period in order — there is no
    // way to re-crank period 0 or jump to period 2 early.
    assert_eq!(
        e.crank_release_period(MALLORY, due_at(0), None),
        Err(EscrowError::PeriodNotDue)
    );
    // Period 1 is not due yet one second before its due date — the
    // crank can never skip ahead or release early.
    assert_eq!(
        e.crank_release_period(MALLORY, due_at(1) - 1, None),
        Err(EscrowError::PeriodNotDue)
    );
    assert_eq!(e.subscription_next_period(), 1);
}

#[test]
fn crank_after_final_period_is_rejected() {
    let mut e = subscription_escrow();
    for i in 0..PERIODS {
        e.crank_release_period(MALLORY, due_at(i), None).unwrap();
    }
    assert_eq!(e.state(), EscrowState::Released);
    assert_eq!(
        e.crank_release_period(MALLORY, due_at(PERIODS - 1) + 1, None),
        Err(EscrowError::InvalidStateTransition)
    );
}

#[test]
fn crank_while_paused_is_rejected() {
    let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
        .unwrap()
        .with_subscription(PERIOD_SECS, PERIODS, PER_PERIOD)
        .unwrap()
        .with_pause_authority(ALICE)
        .unwrap();
    e.fund(ALICE, EXPIRES_AT - 4 * PERIOD_SECS).unwrap();
    e.pause(ALICE, None).unwrap();
    assert_eq!(
        e.crank_release_period(MALLORY, due_at(0), None),
        Err(EscrowError::Paused)
    );
    assert_eq!(e.released_amount(), 0, "a rejected crank moves nothing");
}

#[test]
fn crank_without_schedule_is_rejected() {
    let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT).unwrap();
    e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
    assert_eq!(
        e.crank_release_period(MALLORY, EXPIRES_AT - 1, None),
        Err(EscrowError::InvalidSubscription)
    );
}

#[test]
fn crank_caller_receives_zero_reward() {
    // Anti-MEV: the crank's return carries only the taker's payout
    // and the protocol fee — there is no bounty leg, no caller leg.
    // Cranking as the taker themselves changes nothing: the funds
    // still go to the taker's accounting, the caller keeps zero.
    let mut by_stranger = subscription_escrow();
    let mut by_taker = subscription_escrow();
    let (payout_s, fee_s) = by_stranger.crank_release_period(MALLORY, due_at(0), None).unwrap();
    let (payout_t, fee_t) = by_taker.crank_release_period(BOB, due_at(0), None).unwrap();
    assert_eq!((payout_s, fee_s), (payout_t, fee_t));
    assert_eq!(payout_s + fee_s, PER_PERIOD);
    assert_eq!(by_stranger.released_amount(), PER_PERIOD);
    assert_eq!(by_taker.released_amount(), PER_PERIOD);
}

#[test]
fn crank_gate_consistency_with_release_period() {
    // Every gate except the authority check is identical: wherever
    // `release_period` fails, the crank fails with the same error,
    // and wherever the party path succeeds the crank succeeds too.
    let quorum = || {
        QuorumPolicy::new(&[ATTESTOR], &[1], 1).unwrap()
    };

    // Quorum configured but unsatisfied.
    let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
        .unwrap()
        .with_subscription(PERIOD_SECS, PERIODS, PER_PERIOD)
        .unwrap()
        .with_quorum(quorum())
        .unwrap();
    e.fund(ALICE, EXPIRES_AT - 4 * PERIOD_SECS).unwrap();
    assert_eq!(
        e.release_period(ALICE, due_at(0), 0, None, BOB),
        Err(EscrowError::QuorumNotReached)
    );
    assert_eq!(
        e.crank_release_period(MALLORY, due_at(0), None),
        Err(EscrowError::QuorumNotReached)
    );

    // Timelock not reached (timelock is an Uninitialized-only
    // builder, so the escrow is assembled by hand here).
    let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
        .unwrap()
        .with_subscription(PERIOD_SECS, PERIODS, PER_PERIOD)
        .unwrap()
        .with_timelock(due_at(0) + 1)
        .unwrap();
    e.fund(ALICE, EXPIRES_AT - 4 * PERIOD_SECS).unwrap();
    assert_eq!(
        e.release_period(ALICE, due_at(0), 0, None, BOB),
        Err(EscrowError::TimelockNotReached)
    );
    assert_eq!(
        e.crank_release_period(MALLORY, due_at(0), None),
        Err(EscrowError::TimelockNotReached)
    );

    // Mint mismatch.
    let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
        .unwrap()
        .with_subscription(PERIOD_SECS, PERIODS, PER_PERIOD)
        .unwrap()
        .with_mint(MINT)
        .unwrap();
    e.fund(ALICE, EXPIRES_AT - 4 * PERIOD_SECS).unwrap();
    assert_eq!(
        e.release_period(ALICE, due_at(0), 0, Some(OTHER_MINT), BOB),
        Err(EscrowError::MintMismatch)
    );
    assert_eq!(
        e.crank_release_period(MALLORY, due_at(0), Some(OTHER_MINT)),
        Err(EscrowError::MintMismatch)
    );

    // Happy path: both succeed and agree on the amounts.
    let mut e = subscription_escrow();
    let via_party = e.release_period(ALICE, due_at(0), 0, None, BOB).unwrap();
    let mut e2 = subscription_escrow();
    let via_crank = e2.crank_release_period(MALLORY, due_at(0), None).unwrap();
    assert_eq!(via_party, via_crank, "identical payout and fee");
}

#[test]
fn crank_emits_subscription_period_released_with_cranker_as_caller() {
    // The event marks the caller as the crank, so the indexer
    // distinguishes crank-driven releases from the initializer's
    // push path.
    let mut e = IndexedEscrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT, ESCROW_ID, T0)
        .unwrap()
        .with_subscription(PERIOD_SECS, PERIODS, PER_PERIOD)
        .unwrap();
    e.fund(ALICE, EXPIRES_AT - 4 * PERIOD_SECS).unwrap();
    let (payout, fee) = e.crank_release_period(MALLORY, due_at(0), None).unwrap();
    assert_eq!(payout + fee, PER_PERIOD);
    let last = e.events().last().expect("crank emits an event");
    assert_eq!(last.kind, EscrowEventKind::SubscriptionPeriodReleased);
    assert_eq!(last.caller, Some(MALLORY), "the event marks the crank caller");
    assert_eq!(last.from, EscrowState::Funded);
    assert_eq!(last.to, EscrowState::Funded);
}
