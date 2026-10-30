//! AV-300: `PaymentStream::amend_stream_start_ts` — test matrix.
//!
//! The stream start may be renegotiated mid-flight, but only when
//! *both* parties sign (initializer + recipient); either party absent,
//! or a stranger in either slot, is `StreamUnauthorized`. Only a
//! stream that has not started yet may move its start: `now` must be
//! before the live `start_ts` and the new start must be after `now`,
//! so a revision only moves a future start moment and never backdates
//! the stream open. Only the window's start moves (`end_ts = start_ts
//! + duration_secs` shifts with it): the window slides, it does not
//! stretch — `duration_secs` and `total_funded` never move. A stream
//! with any accrual or withdrawal history — a non-`(0, 0)` checkpoint
//! pair or a non-zero `withdrawn` — is refused outright, fail-closed:
//! changing the start after accrual began would rewrite accrued
//! history, and the gate blocks bypassing the `now < start_ts` check
//! by pre-setting a checkpoint with a future `now`. No checkpoint is
//! needed for the change itself: with no history the checkpoint is
//! `(0, 0)` and `earned` reads the live `start_ts` on every call.
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

/// rate 10/s, start 100, duration 100s, no cliff — total funded 1000,
/// window [100, 200).
fn stream() -> PaymentStream {
    PaymentStream::create_stream(initializer(), recipient(), 10, 100, 100, 0).unwrap()
}

#[test]
fn dual_signature_required_both_slots() {
    let mut s = stream();
    // Initializer present, recipient absent (stranger in that slot).
    assert_eq!(
        s.amend_stream_start_ts(initializer(), stranger(), 200, 50),
        Err(EscrowError::StreamUnauthorized)
    );
    // Recipient present, initializer absent.
    assert_eq!(
        s.amend_stream_start_ts(stranger(), recipient(), 200, 50),
        Err(EscrowError::StreamUnauthorized)
    );
    // Neither party.
    assert_eq!(
        s.amend_stream_start_ts(stranger(), stranger(), 200, 50),
        Err(EscrowError::StreamUnauthorized)
    );
    // A failed attempt changes nothing.
    assert_eq!(s.start_ts(), 100);
    assert_eq!(s.end_ts(), 200);
    assert_eq!(s.earned(150), 500);
    // Both parties present: accepted.
    s.amend_stream_start_ts(initializer(), recipient(), 200, 50)
        .unwrap();
    assert_eq!(s.start_ts(), 200);
    assert_eq!(s.end_ts(), 300);
}

#[test]
fn terminal_streams_refuse_start_changes() {
    // Cancelled.
    let mut s = stream();
    s.stream_cancel(initializer(), 50).unwrap();
    assert_eq!(s.state(), StreamState::Cancelled);
    assert_eq!(
        s.amend_stream_start_ts(initializer(), recipient(), 200, 50),
        Err(EscrowError::StreamNotActive)
    );
    // Exhausted (fully withdrawn).
    let mut s = stream();
    assert_eq!(s.stream_withdraw(recipient(), 200).unwrap(), 1000);
    assert_eq!(s.state(), StreamState::Exhausted);
    assert_eq!(
        s.amend_stream_start_ts(initializer(), recipient(), 200, 50),
        Err(EscrowError::StreamNotActive)
    );
}

#[test]
fn started_stream_refuses_start_change() {
    let mut s = stream();
    // `now` exactly at the live start: the stream has started.
    assert_eq!(
        s.amend_stream_start_ts(initializer(), recipient(), 200, 100),
        Err(EscrowError::InvalidStream)
    );
    // `now` past the live start: same refusal, original start kept.
    assert_eq!(
        s.amend_stream_start_ts(initializer(), recipient(), 200, 150),
        Err(EscrowError::InvalidStream)
    );
    assert_eq!(s.start_ts(), 100);
    assert_eq!(s.end_ts(), 200);
    assert_eq!(s.earned(150), 500);
}

#[test]
fn new_start_not_after_now_is_refused() {
    let mut s = stream();
    // New start in the past.
    assert_eq!(
        s.amend_stream_start_ts(initializer(), recipient(), 40, 50),
        Err(EscrowError::InvalidStream)
    );
    // New start exactly at `now`: not after `now`, so it would open
    // the stream immediately — refused.
    assert_eq!(
        s.amend_stream_start_ts(initializer(), recipient(), 50, 50),
        Err(EscrowError::InvalidStream)
    );
    assert_eq!(s.start_ts(), 100);
    assert_eq!(s.end_ts(), 200);
    assert_eq!(s.earned(150), 500);
}

#[test]
fn checkpoint_history_blocks_the_change() {
    // A rate change at t=150 (after the start) checkpoints the 500
    // earned so far. Amending with an earlier `now` (50, before the
    // start) would pass the time gate — the history gate must catch
    // it: the checkpoint was pre-set with a future `now`.
    let mut s = stream();
    s.update_stream_rate(initializer(), recipient(), 20, 150)
        .unwrap();
    assert_eq!(
        s.amend_stream_start_ts(initializer(), recipient(), 200, 50),
        Err(EscrowError::InvalidStream)
    );
    assert_eq!(s.start_ts(), 100);
    assert_eq!(s.end_ts(), 200);
    // The checkpoint is untouched by the refused change: earned at
    // t=150 is still the frozen 500.
    assert_eq!(s.earned(150), 500);
}

#[test]
fn withdrawn_history_blocks_the_change() {
    // Withdrawing at t=150 leaves `withdrawn` at 500. Amending with
    // an earlier `now` (50, before the start) would pass the time
    // gate — the history gate must catch it.
    let mut s = stream();
    assert_eq!(s.stream_withdraw(recipient(), 150).unwrap(), 500);
    assert_eq!(
        s.amend_stream_start_ts(initializer(), recipient(), 200, 50),
        Err(EscrowError::InvalidStream)
    );
    assert_eq!(s.start_ts(), 100);
    assert_eq!(s.end_ts(), 200);
    assert_eq!(s.withdrawn(), 500);
    assert_eq!(s.earned(150), 500);
}

#[test]
fn successful_amendment_shifts_end_and_keeps_everything_else() {
    // A cliffed stream: the amendment must leave the cliff alone.
    let mut s =
        PaymentStream::create_stream(initializer(), recipient(), 10, 100, 100, 10).unwrap();
    // Move the start 100 -> 200 at t=50: the window slides by +100.
    s.amend_stream_start_ts(initializer(), recipient(), 200, 50)
        .unwrap();
    assert_eq!(s.start_ts(), 200);
    assert_eq!(s.end_ts(), 300);
    assert_eq!(s.duration_secs(), 100);
    assert_eq!(s.rate_per_sec(), 10);
    assert_eq!(s.cliff_secs(), 10);
    assert_eq!(s.total_funded(), 1000);
    assert_eq!(s.withdrawn(), 0);
    // No checkpoint churn: a later rate change still chains from the
    // original (0, 0) checkpoint — 100 earned by t=210 at 10/s, then
    // 20/s onward: 100 + 20 x 10 = 300 at t=220.
    s.update_stream_rate(initializer(), recipient(), 20, 210)
        .unwrap();
    assert_eq!(s.earned(220), 300);
}

#[test]
fn earned_is_computed_from_the_new_start() {
    let mut s = stream();
    // Before the change, t=150 is 50s into the stream: 500 earned.
    assert_eq!(s.earned(150), 500);
    // Move the start 100 -> 200 at t=50.
    s.amend_stream_start_ts(initializer(), recipient(), 200, 50)
        .unwrap();
    // The same instant now earns nothing — accrual restarts at 200.
    assert_eq!(s.earned(150), 0);
    // And the new start takes effect from the next evaluation:
    // 50s in at t=250 is 500 again, capped at 1000 by t=300.
    assert_eq!(s.earned(250), 500);
    assert_eq!(s.earned(300), 1000);
    assert_eq!(s.stream_withdraw(recipient(), 250).unwrap(), 500);
}

#[test]
fn moving_start_earlier_while_still_future_is_allowed() {
    let mut s = stream();
    // Move the start 100 -> 80 at t=50: earlier, but still after
    // `now` — a legitimate revision, not a backdate.
    s.amend_stream_start_ts(initializer(), recipient(), 80, 50)
        .unwrap();
    assert_eq!(s.start_ts(), 80);
    assert_eq!(s.end_ts(), 180);
    assert_eq!(s.total_funded(), 1000);
    assert_eq!(s.earned(90), 100);
    assert_eq!(s.earned(180), 1000);
}

#[test]
fn start_change_while_paused_applies_from_resume() {
    let mut s = stream();
    s.pause(initializer(), 20).unwrap();
    // Accrual has not begun; changing the start while paused is legal.
    s.amend_stream_start_ts(initializer(), recipient(), 200, 30)
        .unwrap();
    assert_eq!(s.earned(30), 0);
    assert_eq!(s.start_ts(), 200);
    s.resume(initializer(), 40).unwrap();
    // The 20s pause interval (20 -> 40) precedes the new start, but
    // the pre-existing pause accounting still excludes it from
    // accrual: 50s in at t=250 less 20s paused = 300 earned.
    assert_eq!(s.earned(250), 300);
}

#[test]
fn same_start_change_is_an_idempotent_noop() {
    let mut s = stream();
    s.amend_stream_start_ts(initializer(), recipient(), 100, 50)
        .unwrap();
    assert_eq!(s.start_ts(), 100);
    assert_eq!(s.end_ts(), 200);
    assert_eq!(s.earned(150), 500);
    // No checkpoint churn: a later rate change still chains from
    // the original (0, 0) checkpoint — 200 earned by t=120 at 10/s,
    // then 20/s onward: 200 + 20 x 10 = 400 at t=130.
    s.update_stream_rate(initializer(), recipient(), 20, 120)
        .unwrap();
    assert_eq!(s.earned(130), 400);
}

#[test]
fn start_update_audit_json_shape() {
    assert_eq!(
        PaymentStream::start_update_audit_json(100, 200, 50),
        "{\"event\":\"stream_start_updated\",\"old_start_ts\":100,\"new_start_ts\":200,\"at\":50}"
    );
}
