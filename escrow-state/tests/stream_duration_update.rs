//! AV-298: `PaymentStream::amend_stream_duration_secs` — test matrix.
//!
//! The stream length may be renegotiated mid-flight, but only when
//! *both* parties sign (initializer + recipient); either party absent,
//! or a stranger in either slot, is `StreamUnauthorized`. Only the
//! accrual window's end moves (`end_ts = start_ts + duration_secs`):
//! lengthening lets accrual run longer, shortening caps it earlier.
//! The amount already earned is checkpointed at change time and never
//! repriced or reduced, so `earned(now)` is identical immediately
//! before and after the change; shortening below the seconds already
//! accrued freezes the earned amount (never a fall-back, never a
//! clawback of what was already withdrawn). The new duration reuses
//! the `create_stream` gate (non-zero, and at least the live cliff,
//! else `InvalidStream`). `total_funded` never moves: lengthening
//! creates no new funding obligation, shortening refunds nothing.
//!
//! Check order: authority → state → config.

use escrow_state::{EscrowError, PaymentStream, StreamState};

fn initializer() -> [u8; 32] {
    [7u8; 32]
}

fn recipient() -> [u8; 32] {
    [9u8; 32]
}

fn stranger() -> [u8; 32] {
    [11u8; 32]
}

/// rate 10/s, start 0, duration 100s — total funded 1000.
fn stream() -> PaymentStream {
    PaymentStream::create_stream(initializer(), recipient(), 10, 0, 100, 0).unwrap()
}

#[test]
fn dual_signature_required_both_slots() {
    let mut s = stream();
    // Initializer present, recipient absent (stranger in that slot).
    assert_eq!(
        s.amend_stream_duration_secs(initializer(), stranger(), 200, 25),
        Err(EscrowError::StreamUnauthorized)
    );
    // Recipient present, initializer absent.
    assert_eq!(
        s.amend_stream_duration_secs(stranger(), recipient(), 200, 25),
        Err(EscrowError::StreamUnauthorized)
    );
    // Neither party.
    assert_eq!(
        s.amend_stream_duration_secs(stranger(), stranger(), 200, 25),
        Err(EscrowError::StreamUnauthorized)
    );
    // A failed attempt changes nothing.
    assert_eq!(s.duration_secs(), 100);
    assert_eq!(s.end_ts(), 100);
    assert_eq!(s.earned(25), 250);
    // Both parties present: accepted.
    s.amend_stream_duration_secs(initializer(), recipient(), 200, 25)
        .unwrap();
    assert_eq!(s.duration_secs(), 200);
    assert_eq!(s.end_ts(), 200);
}

#[test]
fn zero_duration_and_cliff_beyond_new_duration_fail_closed() {
    let mut s = stream();
    // Zero length is refused, original duration kept.
    assert_eq!(
        s.amend_stream_duration_secs(initializer(), recipient(), 0, 25),
        Err(EscrowError::InvalidStream)
    );
    assert_eq!(s.duration_secs(), 100);
    assert_eq!(s.earned(25), 250);
    // A cliffed stream cannot be shortened below its live cliff.
    let mut s = PaymentStream::create_stream(initializer(), recipient(), 10, 0, 100, 50)
        .unwrap();
    assert_eq!(
        s.amend_stream_duration_secs(initializer(), recipient(), 40, 25),
        Err(EscrowError::InvalidStream)
    );
    assert_eq!(s.duration_secs(), 100);
    assert_eq!(s.cliff_secs(), 50);
    // Exactly the cliff is the create_stream boundary: allowed.
    s.amend_stream_duration_secs(initializer(), recipient(), 50, 25)
        .unwrap();
    assert_eq!(s.duration_secs(), 50);
    assert_eq!(s.end_ts(), 50);
}

#[test]
fn lengthening_moves_the_window_but_not_the_funding_cap() {
    let mut s = stream();
    // At t=90 the stream has earned 900 of its 1000 funded.
    assert_eq!(s.earned(90), 900);
    // Lengthen to 200s at t=90: the checkpoint freezes 900, and
    // accrual continues at 10/s — but the 1000 total cap does not
    // move, so the stream still tops out at 1000.
    s.amend_stream_duration_secs(initializer(), recipient(), 200, 90)
        .unwrap();
    assert_eq!(s.duration_secs(), 200);
    assert_eq!(s.end_ts(), 200);
    assert_eq!(s.total_funded(), 1000);
    assert_eq!(s.earned(100), 1000);
    assert_eq!(s.earned(150), 1000);
    // Withdrawing at 150 drains the whole funded amount: lengthening
    // created no new funding obligation.
    assert_eq!(s.stream_withdraw(recipient(), 150).unwrap(), 1000);
    assert_eq!(s.state(), StreamState::Exhausted);
}

#[test]
fn lengthening_lets_accrual_run_past_the_old_end() {
    // Rate 20/s, duration 50s, total funded 1000. Drop the rate to
    // 5/s at t=25 (checkpoint freezes 500), then lengthen to 200s:
    // accrual keeps running past the old 50s end at the new rate.
    // (With an unchanged rate the funding cap always binds at the
    // old end, so a rate decrease is what makes the longer window
    // observable.)
    let mut s =
        PaymentStream::create_stream(initializer(), recipient(), 20, 0, 50, 0).unwrap();
    s.update_stream_rate(initializer(), recipient(), 5, 25)
        .unwrap();
    // Under the old window, earned would stop at 500 + 5 x 25 = 625.
    assert_eq!(s.earned(50), 625);
    s.amend_stream_duration_secs(initializer(), recipient(), 200, 25)
        .unwrap();
    assert_eq!(s.end_ts(), 200);
    assert_eq!(s.total_funded(), 1000);
    // Past the old end: 500 + 5 x 75 = 875 at t=100.
    assert_eq!(s.earned(100), 875);
    assert_eq!(s.stream_withdraw(recipient(), 100).unwrap(), 875);
}

#[test]
fn shortening_freezes_earned_never_decreases() {
    let mut s = stream();
    // At t=60 the stream has earned 600.
    assert_eq!(s.earned(60), 600);
    // Shorten the window to 40s — below the 60s already accrued.
    // The checkpoint freezes 600: earned never falls back, even
    // though the new end_ts (40) is behind `now`.
    s.amend_stream_duration_secs(initializer(), recipient(), 40, 60)
        .unwrap();
    assert_eq!(s.duration_secs(), 40);
    assert_eq!(s.end_ts(), 40);
    assert_eq!(s.total_funded(), 1000);
    assert_eq!(s.earned(80), 600);
    assert_eq!(s.earned(100), 600);
    // Withdrawing pays the frozen 600 — no more accrues.
    assert_eq!(s.stream_withdraw(recipient(), 80).unwrap(), 600);
    assert_eq!(s.withdrawn(), 600);
    assert_eq!(s.state(), StreamState::Active);
}

#[test]
fn shortening_below_withdrawn_never_claws_back() {
    let mut s = stream();
    assert_eq!(s.stream_withdraw(recipient(), 25).unwrap(), 250);
    // Shorten to 40s at t=30: the checkpoint freezes 300, then
    // accrual runs 30 -> 40 at 10/s, so earned(40) is 400.
    s.amend_stream_duration_secs(initializer(), recipient(), 40, 30)
        .unwrap();
    assert_eq!(s.earned(40), 400);
    // Only the 150 not yet withdrawn is payable — the 250 already
    // withdrawn stays withdrawn, never a clawback.
    assert_eq!(s.stream_withdraw(recipient(), 40).unwrap(), 150);
    assert_eq!(s.withdrawn(), 400);
    assert_eq!(s.earned(100), 400);
}

#[test]
fn duration_change_keeps_rate_start_cliff_total_and_checkpoint() {
    // A cliffed stream with a prior rate change: the duration change
    // must chain from the existing checkpoint, not reprice it.
    let mut s =
        PaymentStream::create_stream(initializer(), recipient(), 10, 0, 100, 50).unwrap();
    s.update_stream_rate(initializer(), recipient(), 20, 25)
        .unwrap();
    // 250 earned pre-change (ungated checkpoint) at 25 — but the
    // 50s cliff still gates payout, so earned reports 0 until t=50.
    assert_eq!(s.earned(35), 0);
    // Shorten to 60s at t=35: checkpoint freezes the ungated 450.
    s.amend_stream_duration_secs(initializer(), recipient(), 60, 35)
        .unwrap();
    assert_eq!(s.duration_secs(), 60);
    assert_eq!(s.rate_per_sec(), 10 * 2);
    assert_eq!(s.start_ts(), 0);
    assert_eq!(s.cliff_secs(), 50);
    assert_eq!(s.total_funded(), 1000);
    assert_eq!(s.withdrawn(), 0);
    // Still gated at t=45; past the cliff, post-change accrual runs
    // at 20/s from the frozen 450: 450 + 20 x 15 = 750 at t=50.
    assert_eq!(s.earned(45), 0);
    assert_eq!(s.earned(50), 750);
    assert_eq!(s.stream_withdraw(recipient(), 50).unwrap(), 750);
}

#[test]
fn earned_is_continuous_across_the_change() {
    let mut s = stream();
    // earned(now) must be identical immediately before and after
    // the change, for both directions.
    let before = s.earned(25);
    s.amend_stream_duration_secs(initializer(), recipient(), 200, 25)
        .unwrap();
    assert_eq!(s.earned(25), before);
    let before = s.earned(40);
    s.amend_stream_duration_secs(initializer(), recipient(), 50, 40)
        .unwrap();
    assert_eq!(s.earned(40), before);
}

#[test]
fn terminal_streams_refuse_duration_changes() {
    // Cancelled.
    let mut s = stream();
    s.stream_cancel(initializer(), 25).unwrap();
    assert_eq!(s.state(), StreamState::Cancelled);
    assert_eq!(
        s.amend_stream_duration_secs(initializer(), recipient(), 200, 25),
        Err(EscrowError::StreamNotActive)
    );
    // Exhausted (fully withdrawn).
    let mut s = stream();
    assert_eq!(s.stream_withdraw(recipient(), 100).unwrap(), 1000);
    assert_eq!(s.state(), StreamState::Exhausted);
    assert_eq!(
        s.amend_stream_duration_secs(initializer(), recipient(), 200, 100),
        Err(EscrowError::StreamNotActive)
    );
}

#[test]
fn duration_change_while_paused_applies_from_resume() {
    let mut s = stream();
    s.pause(initializer(), 20).unwrap();
    // Accrual frozen at 200; changing the duration while paused is legal.
    s.amend_stream_duration_secs(initializer(), recipient(), 200, 30)
        .unwrap();
    assert_eq!(s.earned(30), 200);
    assert_eq!(s.duration_secs(), 200);
    s.resume(initializer(), 40).unwrap();
    // 20s pre-pause at 10 + 10s post-resume at 10 = 300.
    assert_eq!(s.earned(50), 300);
    // And the lengthened window is live: accrual runs past 100s.
    assert_eq!(s.earned(150), 1000);
}

#[test]
fn same_duration_change_is_an_idempotent_noop() {
    let mut s = stream();
    s.amend_stream_duration_secs(initializer(), recipient(), 100, 25)
        .unwrap();
    assert_eq!(s.duration_secs(), 100);
    assert_eq!(s.earned(60), 600);
    // No checkpoint churn: a later rate change still chains from
    // the original (0, 0) checkpoint.
    s.update_stream_rate(initializer(), recipient(), 20, 60)
        .unwrap();
    assert_eq!(s.earned(70), 800);
}

#[test]
fn duration_update_audit_json_shape() {
    assert_eq!(
        PaymentStream::duration_update_audit_json(100, 200, 25),
        "{\"event\":\"stream_duration_updated\",\"old_duration_secs\":100,\"new_duration_secs\":200,\"at\":25}"
    );
}
