//! AV-216: delivery-confirmation deadline and late-delivery penalty
//! — test matrix.
//!
//! When an escrow opts in via `with_delivery_deadline` (a single
//! unix timestamp, `Uninitialized`-only) and
//! `with_late_delivery_penalty_bps` (0–10_000 bps,
//! `Uninitialized`-only), a taker confirmation after the deadline
//! — recorded only by the timed `confirm_delivery_at`, never by
//! the timeless `confirm_delivery` — prices on the payout paths:
//!
//! ```text
//! released      += gross - penalty   (net taker principal)
//! penalty_paid  += penalty           (late-delivery sink)
//! taker_payout   = (gross - penalty) - fee + interest
//! ```
//!
//! so `released + penalty_paid + remaining == amount` with the
//! conservation formula untouched. Confirming exactly at the
//! deadline is on time (strict-after, the AV-206 rule). The
//! penalty stacks on the post-AV-206 net tranche on
//! `release_milestone`, and never touches the unilateral exits
//! (`cancel` / `cancel_expired`) or the arbiter's `resolve` —
//! the AV-203 non-gating rule, extended to the price: a late
//! confirmation prices payouts, never traps funds.

use escrow_state::{
    Escrow, EscrowError, EscrowState, IndexedEscrow, MilestonePlan,
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

/// Deadline 500, 10% late rate, delivery-confirmation gate on.
fn dated() -> Escrow {
    Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_delivery_confirmation()
        .unwrap()
        .with_delivery_deadline(500)
        .unwrap()
        .with_late_delivery_penalty_bps(1_000)
        .unwrap()
}

fn funded_dated() -> Escrow {
    let mut e = dated();
    e.fund(initializer(), 100).unwrap();
    e
}

#[test]
fn builders_are_uninitialized_only_and_validate() {
    let e = dated();
    assert_eq!(e.delivery_deadline_at(), Some(500));
    assert_eq!(e.late_delivery_penalty_bps(), 1_000);
    assert!(!e.delivery_late());
    assert!(!e.delivery_confirmed());

    // A zero deadline is not a deadline (0 = "never attached").
    let base = Escrow::initialize(initializer(), taker(), 1_000, 10_000).unwrap();
    assert_eq!(
        base.with_delivery_deadline(0),
        Err(EscrowError::AmountMismatch)
    );
    // A rate above 10_000 bps is not a rate.
    let base = Escrow::initialize(initializer(), taker(), 1_000, 10_000).unwrap();
    assert_eq!(
        base.with_late_delivery_penalty_bps(10_001),
        Err(EscrowError::InvalidPenalty)
    );
    // Defaults: no deadline, no rate, not late.
    let plain = Escrow::initialize(initializer(), taker(), 1_000, 10_000).unwrap();
    assert_eq!(plain.delivery_deadline_at(), None);
    assert_eq!(plain.late_delivery_penalty_bps(), 0);
    assert!(!plain.delivery_late());

    // Funded escrows refuse both builders.
    let funded = funded_dated();
    assert_eq!(
        funded.with_delivery_deadline(600),
        Err(EscrowError::InvalidStateTransition)
    );
    assert_eq!(
        funded.with_late_delivery_penalty_bps(500),
        Err(EscrowError::InvalidStateTransition)
    );
}

#[test]
fn timed_confirmation_gates_and_records_lateness() {
    let mut e = funded_dated();
    // Only the taker may confirm, timed or not.
    assert_eq!(
        e.confirm_delivery_at(initializer(), 600),
        Err(EscrowError::Unauthorized)
    );
    assert_eq!(
        e.confirm_delivery_at(stranger(), 600),
        Err(EscrowError::Unauthorized)
    );
    assert!(!e.delivery_confirmed());
    assert!(!e.delivery_late());

    // An un-funded escrow cannot confirm at all.
    let mut fresh = dated();
    assert_eq!(
        fresh.confirm_delivery_at(taker(), 600),
        Err(EscrowError::InvalidStateTransition)
    );
}

#[test]
fn confirmation_exactly_at_the_deadline_is_on_time() {
    let mut e = funded_dated();
    e.confirm_delivery_at(taker(), 500).unwrap();
    assert!(e.delivery_confirmed());
    assert!(!e.delivery_late());
    // Full payout, zero penalty, clean close.
    assert_eq!(
        e.release(initializer(), 600, 1_000, None, taker()).unwrap(),
        (1_000, 0)
    );
    assert_eq!(e.released_amount(), 1_000);
    assert_eq!(e.penalty_paid(), 0);
    assert_eq!(e.remaining_amount(), 0);
    assert_eq!(e.state(), EscrowState::Released);
}

#[test]
fn late_confirmation_slices_the_payout_and_keeps_conservation() {
    let mut e = funded_dated();
    e.confirm_delivery_at(taker(), 501).unwrap();
    assert!(e.delivery_confirmed());
    assert!(e.delivery_late());
    // 10% of 1_000 = 100 penalty: taker nets 900, released
    // stores the net, penalty_paid the slice, nothing remains.
    assert_eq!(
        e.release(initializer(), 600, 1_000, None, taker()).unwrap(),
        (900, 0)
    );
    assert_eq!(e.released_amount(), 900);
    assert_eq!(e.penalty_paid(), 100);
    assert_eq!(e.remaining_amount(), 0);
    assert_eq!(e.state(), EscrowState::Released);
}

#[test]
fn partial_late_releases_accumulate_penalty_per_call() {
    let mut e = funded_dated();
    e.confirm_delivery_at(taker(), 501).unwrap();
    // First call: gross 400, penalty 40, taker nets 360.
    assert_eq!(
        e.release(initializer(), 600, 400, None, taker()).unwrap(),
        (360, 0)
    );
    assert_eq!(e.released_amount(), 360);
    assert_eq!(e.penalty_paid(), 40);
    assert_eq!(e.remaining_amount(), 600);
    assert_eq!(e.state(), EscrowState::Funded);
    // Second call: gross 600, penalty 60, taker nets 540 — the
    // escrow closes exactly when released + penalty == amount.
    assert_eq!(
        e.release(initializer(), 600, 600, None, taker()).unwrap(),
        (540, 0)
    );
    assert_eq!(e.released_amount(), 900);
    assert_eq!(e.penalty_paid(), 100);
    assert_eq!(e.remaining_amount(), 0);
    assert_eq!(e.state(), EscrowState::Released);
}

#[test]
fn first_confirmation_wins_in_both_directions() {
    // On time first: a later timed confirmation cannot rewrite
    // the escrow late.
    let mut e = funded_dated();
    e.confirm_delivery_at(taker(), 500).unwrap();
    e.confirm_delivery_at(taker(), 999).unwrap();
    assert!(!e.delivery_late());
    assert_eq!(
        e.release(initializer(), 1_000, 1_000, None, taker()).unwrap(),
        (1_000, 0)
    );

    // Late first: a re-confirmation cannot wash the flag clean.
    let mut e = funded_dated();
    e.confirm_delivery_at(taker(), 501).unwrap();
    e.confirm_delivery_at(taker(), 100).unwrap();
    assert!(e.delivery_late());
    assert_eq!(
        e.release(initializer(), 1_000, 1_000, None, taker()).unwrap(),
        (900, 0)
    );
}

#[test]
fn timeless_confirmation_records_no_lateness() {
    // The AV-203 path has no timestamp to compare against the
    // deadline, so it leaves the flag exactly as it found it —
    // a deadline-configured escrow confirmed timelessly settles
    // in full, even after the deadline passed.
    let mut e = funded_dated();
    e.confirm_delivery(taker()).unwrap();
    assert!(e.delivery_confirmed());
    assert!(!e.delivery_late());
    assert_eq!(
        e.release(initializer(), 999, 1_000, None, taker()).unwrap(),
        (1_000, 0)
    );
    assert_eq!(e.penalty_paid(), 0);
}

#[test]
fn rate_without_deadline_and_deadline_without_rate_price_nothing() {
    // Rate only: no deadline to miss.
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_delivery_confirmation()
        .unwrap()
        .with_late_delivery_penalty_bps(1_000)
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    e.confirm_delivery_at(taker(), 999_999).unwrap();
    assert!(!e.delivery_late());
    assert_eq!(
        e.release(initializer(), 1_000, 1_000, None, taker()).unwrap(),
        (1_000, 0)
    );

    // Deadline only: no rate to price with.
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_delivery_confirmation()
        .unwrap()
        .with_delivery_deadline(500)
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    e.confirm_delivery_at(taker(), 501).unwrap();
    assert!(e.delivery_late());
    assert_eq!(
        e.release(initializer(), 1_000, 1_000, None, taker()).unwrap(),
        (1_000, 0)
    );
    assert_eq!(e.penalty_paid(), 0);
}

#[test]
fn milestone_release_stacks_av206_and_av216_penalties() {
    // Plan [400, 600], AV-206 deadlines [1000, 2000] at 10%,
    // plus AV-216 deadline 500 at 10% on the delivery side.
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_milestones(MilestonePlan::new(&[400, 600]).unwrap())
        .unwrap()
        .with_milestone_due_dates(&[1_000, 2_000])
        .unwrap()
        .with_late_penalty_bps(1_000)
        .unwrap()
        .with_delivery_confirmation()
        .unwrap()
        .with_delivery_deadline(500)
        .unwrap()
        .with_late_delivery_penalty_bps(1_000)
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    // Late delivery confirmation (600 > 500).
    e.confirm_delivery_at(taker(), 600).unwrap();
    e.confirm_milestone(initializer(), 0).unwrap();
    e.confirm_milestone(taker(), 0).unwrap();
    // Tranche 400, released at 1500 (past its AV-206 due 1000):
    // AV-206 takes 40 (10% of 400) -> 360; AV-216 takes 36
    // (10% of 360) -> 324 net. Penalty sink holds 40 + 36.
    assert_eq!(
        e.release_milestone(initializer(), 1_500, 0, None, taker())
            .unwrap(),
        (324, 0)
    );
    assert_eq!(e.released_amount(), 324);
    assert_eq!(e.penalty_paid(), 76);
}

#[test]
fn cancel_paths_ignore_the_late_penalty() {
    // A late confirmation prices payouts, never the exits: a
    // late-confirmed escrow still cancels clean, with no penalty
    // charged on the unwind.
    let mut e = funded_dated();
    e.confirm_delivery_at(taker(), 501).unwrap();
    assert!(e.delivery_late());
    e.cancel(initializer(), None, initializer(), 600).unwrap();
    assert_eq!(e.state(), EscrowState::Cancelled);
    assert_eq!(e.penalty_paid(), 0);

    let mut e2 = funded_dated();
    e2.confirm_delivery_at(taker(), 501).unwrap();
    e2.cancel_expired(initializer(), 10_001, None, initializer())
        .unwrap();
    assert_eq!(e2.state(), EscrowState::Cancelled);
    assert_eq!(e2.penalty_paid(), 0);
}

#[test]
fn indexed_wrapper_records_lateness_from_its_event_time() {
    // The indexed wrapper's `at` doubles as the AV-216
    // confirmation time: a post-deadline indexed confirmation
    // arms the penalty exactly like a direct timed one.
    let mut indexed = IndexedEscrow::initialize(initializer(), taker(), 1_000, 10_000, [3u8; 32], 0)
        .unwrap()
        .with_delivery_confirmation()
        .unwrap()
        .with_delivery_deadline(500)
        .unwrap()
        .with_late_delivery_penalty_bps(1_000)
        .unwrap();
    indexed.fund(initializer(), 100).unwrap();
    indexed.confirm_delivery(taker(), 501).unwrap();
    assert!(indexed.inner().delivery_late());
    assert_eq!(
        indexed.release(initializer(), 1_000, None, taker(), 600).unwrap(),
        (900, 0)
    );
    assert_eq!(indexed.inner().penalty_paid(), 100);
}
