//! AV-204: `PaymentStream::update_stream_rate` — test matrix.
//!
//! The rate may be renegotiated mid-flight, but only when *both*
//! parties sign (initializer + recipient); either party absent, or a
//! stranger in either slot, is `StreamUnauthorized`. Only future
//! accrual changes: the amount earned under the old rate is
//! checkpointed at change time and never repriced, and the funded
//! total still caps everything.
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
        s.update_stream_rate(initializer(), stranger(), 20, 10),
        Err(EscrowError::StreamUnauthorized)
    );
    // Recipient present, initializer absent.
    assert_eq!(
        s.update_stream_rate(stranger(), recipient(), 20, 10),
        Err(EscrowError::StreamUnauthorized)
    );
    // Neither party.
    assert_eq!(
        s.update_stream_rate(stranger(), stranger(), 20, 10),
        Err(EscrowError::StreamUnauthorized)
    );
    // A failed attempt changes nothing.
    assert_eq!(s.rate_per_sec(), 10);
    assert_eq!(s.earned(10), 100);
    // Both parties present: accepted.
    s.update_stream_rate(initializer(), recipient(), 20, 10).unwrap();
    assert_eq!(s.rate_per_sec(), 20);
}

#[test]
fn only_future_accrual_changes() {
    let mut s = stream();
    assert_eq!(s.earned(25), 250);
    s.update_stream_rate(initializer(), recipient(), 20, 25).unwrap();
    // Identical immediately after the change — no repricing.
    assert_eq!(s.earned(25), 250);
    // Then the new rate applies: 250 + 5s × 20.
    assert_eq!(s.earned(30), 350);
    assert_eq!(s.earned(50), 750);
    // Withdrawals follow the new schedule.
    assert_eq!(s.stream_withdraw(recipient(), 50).unwrap(), 750);
    // A second change checkpoints again.
    s.update_stream_rate(initializer(), recipient(), 5, 50).unwrap();
    assert_eq!(s.earned(50), 750);
    assert_eq!(s.earned(60), 800);
}

#[test]
fn zero_and_overflowing_rates_fail_closed() {
    let mut s = stream();
    assert_eq!(
        s.update_stream_rate(initializer(), recipient(), 0, 10),
        Err(EscrowError::InvalidStream)
    );
    // u64::MAX × 100s does not fit u64.
    assert_eq!(
        s.update_stream_rate(initializer(), recipient(), u64::MAX, 10),
        Err(EscrowError::InvalidStream)
    );
    // Failed attempts change nothing.
    assert_eq!(s.rate_per_sec(), 10);
    assert_eq!(s.earned(10), 100);
}

#[test]
fn terminal_streams_refuse_rate_changes() {
    // Cancelled.
    let mut s = stream();
    s.stream_cancel(initializer(), 25).unwrap();
    assert_eq!(s.state(), StreamState::Cancelled);
    assert_eq!(
        s.update_stream_rate(initializer(), recipient(), 20, 30),
        Err(EscrowError::StreamNotActive)
    );
    // Exhausted (fully withdrawn).
    let mut s = stream();
    assert_eq!(s.stream_withdraw(recipient(), 100).unwrap(), 1000);
    assert_eq!(s.state(), StreamState::Exhausted);
    assert_eq!(
        s.update_stream_rate(initializer(), recipient(), 20, 100),
        Err(EscrowError::StreamNotActive)
    );
}

#[test]
fn rate_change_while_paused_applies_from_resume() {
    let mut s = stream();
    s.pause(initializer(), 20).unwrap();
    // Accrual frozen at 200; changing the rate while paused is legal.
    s.update_stream_rate(initializer(), recipient(), 20, 30).unwrap();
    assert_eq!(s.earned(30), 200);
    s.resume(initializer(), 40).unwrap();
    // 20s pre-pause at 10 + 10s post-resume at 20.
    assert_eq!(s.earned(50), 400);
}

#[test]
fn funded_total_still_caps_a_rate_increase() {
    let mut s = stream();
    s.update_stream_rate(initializer(), recipient(), 100, 25).unwrap();
    // 250 + 25s × 100 = 2750, capped at the funded 1000.
    assert_eq!(s.earned(50), 1000);
    assert_eq!(s.stream_withdraw(recipient(), 50).unwrap(), 1000);
    assert_eq!(s.state(), StreamState::Exhausted);
}

#[test]
fn pre_cliff_change_does_not_erase_pre_change_accrual() {
    // cliff 50s: payout gated, accrual still runs from start_ts.
    let mut s =
        PaymentStream::create_stream(initializer(), recipient(), 10, 0, 100, 50).unwrap();
    assert_eq!(s.earned(25), 0);
    s.update_stream_rate(initializer(), recipient(), 20, 25).unwrap();
    assert_eq!(s.earned(25), 0);
    // After the cliff: 250 earned pre-change (ungated checkpoint)
    // + 35s × 20 post-change — not 35s × 20 alone.
    assert_eq!(s.earned(60), 950);
}

#[test]
fn same_rate_change_is_an_idempotent_noop() {
    let mut s = stream();
    s.update_stream_rate(initializer(), recipient(), 10, 25).unwrap();
    assert_eq!(s.rate_per_sec(), 10);
    assert_eq!(s.earned(40), 400);
}

#[test]
fn rate_update_audit_json_shape() {
    assert_eq!(
        PaymentStream::rate_update_audit_json(10, 20, 25),
        "{\"event\":\"stream_rate_updated\",\"old_rate\":10,\"new_rate\":20,\"at\":25}"
    );
}
