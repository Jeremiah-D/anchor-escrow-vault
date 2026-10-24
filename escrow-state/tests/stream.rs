//! AV-198: `PaymentStream` (Sablier-style per-second salary stream) —
//! test matrix.
//!
//! The stream is pure arithmetic: earned = `rate × elapsed` (all in
//! `u128`, so it cannot overflow), capped at the funded total; the
//! recipient withdraws what it has earned, the initializer can
//! cancel/pause/resume. Every behavior below gets a pinned case,
//! including the terminal states and the paused-interval math.

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

/// A stream that ended long ago (start 0, duration 100, rate 10).
fn stream_fully_earned() -> PaymentStream {
    stream()
}

#[test]
fn create_stream_happy_path_pins_accessors() {
    let s = stream();
    assert_eq!(s.initializer(), initializer());
    assert_eq!(s.recipient(), recipient());
    assert_eq!(s.rate_per_sec(), 10);
    assert_eq!(s.start_ts(), 0);
    assert_eq!(s.duration_secs(), 100);
    assert_eq!(s.cliff_secs(), 0);
    assert_eq!(s.total_funded(), 1000);
    assert_eq!(s.withdrawn(), 0);
    assert_eq!(s.end_ts(), 100);
    assert_eq!(s.state(), StreamState::Active);
    assert!(!s.is_paused());
    // Total = rate x duration computed exactly.
    assert_eq!(s.total_funded(), 10 * 100);
}

#[test]
fn earned_grows_per_second_and_caps_at_total() {
    let s = stream_fully_earned();
    assert_eq!(s.earned(0), 0);
    assert_eq!(s.earned(1), 10);
    assert_eq!(s.earned(50), 500);
    assert_eq!(s.earned(100), 1000);
    // Capped: no accrual past the end.
    assert_eq!(s.earned(101), 1000);
    assert_eq!(s.earned(u64::MAX), 1000);
}

#[test]
fn full_lifecycle_earn_withdraw_exhausted() {
    let mut s = stream();
    // First withdraw halfway through.
    assert_eq!(s.stream_withdraw(recipient(), 50).unwrap(), 500);
    assert_eq!(s.withdrawn(), 500);
    assert_eq!(s.state(), StreamState::Active);
    // Second withdraw at the end drains the stream -> Exhausted.
    assert_eq!(s.stream_withdraw(recipient(), 100).unwrap(), 500);
    assert_eq!(s.withdrawn(), 1000);
    assert_eq!(s.state(), StreamState::Exhausted);
}

#[test]
fn partial_withdraw_twice_accumulates() {
    let mut s = stream();
    assert_eq!(s.stream_withdraw(recipient(), 25).unwrap(), 250);
    // Only the newly-earned delta comes out the second time.
    assert_eq!(s.stream_withdraw(recipient(), 50).unwrap(), 250);
    assert_eq!(s.withdrawn(), 500);
    assert_eq!(s.state(), StreamState::Active);
}

#[test]
fn zero_earn_withdraw_is_idempotent_noop() {
    let mut s = stream();
    // Before the start nothing is earned, but withdraw is not an error.
    assert_eq!(s.stream_withdraw(recipient(), 0).unwrap(), 0);
    // Same instant twice: nothing new earned.
    assert_eq!(s.stream_withdraw(recipient(), 10).unwrap(), 100);
    assert_eq!(s.stream_withdraw(recipient(), 10).unwrap(), 0);
    assert_eq!(s.state(), StreamState::Active);
}

#[test]
fn cliff_gates_payout_without_eating_the_stream() {
    // cliff 30s: no payout before start+30, accrual still runs from start.
    let mut s = PaymentStream::create_stream(initializer(), recipient(), 10, 1000, 100, 30)
        .unwrap();
    assert_eq!(s.earned(1005), 0);
    assert_eq!(s.stream_withdraw(recipient(), 1005).unwrap(), 0);
    // At the cliff instant: 30 accrued seconds pay out at once.
    assert_eq!(s.earned(1030), 300);
    assert_eq!(s.stream_withdraw(recipient(), 1030).unwrap(), 300);
}

#[test]
fn cancel_splits_earned_to_recipient_unearned_to_initializer() {
    let mut s = stream();
    assert_eq!(s.stream_withdraw(recipient(), 25).unwrap(), 250);
    // Cancel at t=40: earned 400 total, 250 already withdrawn.
    let (to_recipient, to_initializer) = s.stream_cancel(initializer(), 40).unwrap();
    assert_eq!(to_recipient, 150);
    assert_eq!(to_initializer, 600);
    assert_eq!(s.state(), StreamState::Cancelled);
}

#[test]
fn cancel_before_start_returns_everything() {
    let mut s =
        PaymentStream::create_stream(initializer(), recipient(), 10, 1000, 100, 0).unwrap();
    let (to_recipient, to_initializer) = s.stream_cancel(initializer(), 500).unwrap();
    assert_eq!(to_recipient, 0);
    assert_eq!(to_initializer, 1000);
    assert_eq!(s.state(), StreamState::Cancelled);
}

#[test]
fn pause_freezes_accrual_and_resume_restarts_it() {
    let mut s = stream();
    s.pause(initializer(), 20).unwrap();
    assert!(s.is_paused());
    // While paused the earned amount is frozen...
    assert_eq!(s.earned(30), 200);
    // ...even if the pause runs past the end.
    assert_eq!(s.earned(200), 200);
    s.resume(initializer(), 50).unwrap();
    assert!(!s.is_paused());
    assert_eq!(s.paused_total(), 30);
    // The paused interval is permanently excluded from accrual.
    assert_eq!(s.earned(100), 700);
}

#[test]
fn multiple_pause_intervals_accumulate() {
    let mut s = stream();
    s.pause(initializer(), 10).unwrap();
    s.resume(initializer(), 20).unwrap();
    s.pause(initializer(), 30).unwrap();
    s.resume(initializer(), 60).unwrap();
    assert_eq!(s.paused_total(), 40);
    // 100 - 40 paused = 60 accruing seconds.
    assert_eq!(s.earned(100), 600);
}

#[test]
fn cancel_while_paused_excludes_open_pause_interval() {
    let mut s = stream();
    s.pause(initializer(), 10).unwrap();
    // At t=40 the open interval [10,40) never accrued: earned = 10*10.
    let (to_recipient, to_initializer) = s.stream_cancel(initializer(), 40).unwrap();
    assert_eq!(to_recipient, 100);
    assert_eq!(to_initializer, 900);
    assert_eq!(s.state(), StreamState::Cancelled);
}

#[test]
fn unauthorized_callers_are_rejected_before_state() {
    let mut s = stream();
    // Non-recipient withdraw.
    assert_eq!(
        s.stream_withdraw(initializer(), 50).unwrap_err(),
        EscrowError::StreamUnauthorized
    );
    assert_eq!(
        s.stream_withdraw(stranger(), 50).unwrap_err(),
        EscrowError::StreamUnauthorized
    );
    // Non-initializer cancel / pause / resume.
    assert_eq!(
        s.stream_cancel(recipient(), 50).unwrap_err(),
        EscrowError::StreamUnauthorized
    );
    assert_eq!(
        s.pause(recipient(), 50).unwrap_err(),
        EscrowError::StreamUnauthorized
    );
    assert_eq!(
        s.resume(recipient(), 50).unwrap_err(),
        EscrowError::StreamUnauthorized
    );
    // Rejection happened before any state changed.
    assert_eq!(s.state(), StreamState::Active);
    assert!(!s.is_paused());
}

#[test]
fn pause_twice_and_resume_unpaused() {
    let mut s = stream();
    s.pause(initializer(), 10).unwrap();
    assert_eq!(
        s.pause(initializer(), 20).unwrap_err(),
        EscrowError::StreamAlreadyPaused
    );
    s.resume(initializer(), 30).unwrap();
    assert_eq!(
        s.resume(initializer(), 40).unwrap_err(),
        EscrowError::StreamNotPaused
    );
}

#[test]
fn ops_on_cancelled_stream_are_rejected() {
    let mut s = stream();
    s.stream_cancel(initializer(), 50).unwrap();
    assert_eq!(
        s.stream_withdraw(recipient(), 60).unwrap_err(),
        EscrowError::StreamNotActive
    );
    assert_eq!(
        s.stream_cancel(initializer(), 60).unwrap_err(),
        EscrowError::StreamNotActive
    );
    assert_eq!(
        s.pause(initializer(), 60).unwrap_err(),
        EscrowError::StreamNotActive
    );
    assert_eq!(
        s.resume(initializer(), 60).unwrap_err(),
        EscrowError::StreamNotActive
    );
}

#[test]
fn ops_on_exhausted_stream_are_rejected() {
    let mut s = stream();
    s.stream_withdraw(recipient(), 100).unwrap();
    assert_eq!(s.state(), StreamState::Exhausted);
    assert_eq!(
        s.stream_withdraw(recipient(), 100).unwrap_err(),
        EscrowError::StreamNotActive
    );
    assert_eq!(
        s.stream_cancel(initializer(), 100).unwrap_err(),
        EscrowError::StreamNotActive
    );
    assert_eq!(
        s.pause(initializer(), 100).unwrap_err(),
        EscrowError::StreamNotActive
    );
}

#[test]
fn config_errors_are_invalid_stream() {
    // Zero rate.
    assert_eq!(
        PaymentStream::create_stream(initializer(), recipient(), 0, 0, 100, 0).unwrap_err(),
        EscrowError::InvalidStream
    );
    // Zero duration.
    assert_eq!(
        PaymentStream::create_stream(initializer(), recipient(), 10, 0, 0, 0).unwrap_err(),
        EscrowError::InvalidStream
    );
    // Cliff longer than the stream.
    assert_eq!(
        PaymentStream::create_stream(initializer(), recipient(), 10, 0, 100, 101).unwrap_err(),
        EscrowError::InvalidStream
    );
    // Zero keys.
    assert_eq!(
        PaymentStream::create_stream([0u8; 32], recipient(), 10, 0, 100, 0).unwrap_err(),
        EscrowError::InvalidStream
    );
    assert_eq!(
        PaymentStream::create_stream(initializer(), [0u8; 32], 10, 0, 100, 0).unwrap_err(),
        EscrowError::InvalidStream
    );
    // rate x duration that does not fit u64 is refused, not wrapped.
    assert_eq!(
        PaymentStream::create_stream(initializer(), recipient(), u64::MAX, 0, 2, 0).unwrap_err(),
        EscrowError::InvalidStream
    );
}

#[test]
fn max_scale_rate_times_duration_cannot_overflow() {
    // rate = u64::MAX, duration = 1: total fits exactly (u64::MAX).
    let mut s = PaymentStream::create_stream(initializer(), recipient(), u64::MAX, 0, 1, 0)
        .unwrap();
    assert_eq!(s.total_funded(), u64::MAX);
    assert_eq!(s.earned(1), u64::MAX);
    // The whole u64::MAX pays out exactly; the multiply ran in u128.
    assert_eq!(s.stream_withdraw(recipient(), 1).unwrap(), u64::MAX);
    assert_eq!(s.state(), StreamState::Exhausted);
}

#[test]
fn new_error_codes_are_pinned() {
    assert_eq!(EscrowError::InvalidStream.code(), 304);
    assert_eq!(EscrowError::StreamUnauthorized.code(), 305);
    assert_eq!(EscrowError::StreamNotActive.code(), 306);
    assert_eq!(EscrowError::StreamAlreadyPaused.code(), 307);
    assert_eq!(EscrowError::StreamNotPaused.code(), 308);
}
