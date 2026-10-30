//! AV-297: `PaymentStream::amend_stream_cliff_secs` — test matrix.
//!
//! The payout cliff may be renegotiated mid-flight, but only when
//! *both* parties sign (initializer + recipient); either party absent,
//! or a stranger in either slot, is `StreamUnauthorized`. Only future
//! payouts change: the cliff gates payout, not accrual, so moving it
//! never reprices anything — raising it re-gates the stream (a
//! withdraw then returns `0`, never a clawback of what was already
//! withdrawn), lowering it releases the gated accrual at once. The new
//! cliff reuses the `create_stream` gate (`cliff_secs <=
//! duration_secs`, else `InvalidStream`).
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
        s.amend_stream_cliff_secs(initializer(), stranger(), 50),
        Err(EscrowError::StreamUnauthorized)
    );
    // Recipient present, initializer absent.
    assert_eq!(
        s.amend_stream_cliff_secs(stranger(), recipient(), 50),
        Err(EscrowError::StreamUnauthorized)
    );
    // Neither party.
    assert_eq!(
        s.amend_stream_cliff_secs(stranger(), stranger(), 50),
        Err(EscrowError::StreamUnauthorized)
    );
    // A failed attempt changes nothing.
    assert_eq!(s.cliff_secs(), 0);
    assert_eq!(s.earned(10), 100);
    // Both parties present: accepted.
    s.amend_stream_cliff_secs(initializer(), recipient(), 50)
        .unwrap();
    assert_eq!(s.cliff_secs(), 50);
}

#[test]
fn cliff_beyond_duration_fails_closed() {
    let mut s = stream();
    // 101s is past the 100s duration: refused, original cliff kept.
    assert_eq!(
        s.amend_stream_cliff_secs(initializer(), recipient(), 101),
        Err(EscrowError::InvalidStream)
    );
    assert_eq!(s.cliff_secs(), 0);
    assert_eq!(s.earned(10), 100);
    // Exactly the duration is the create_stream boundary: allowed.
    s.amend_stream_cliff_secs(initializer(), recipient(), 100)
        .unwrap();
    assert_eq!(s.cliff_secs(), 100);
    // Payout is gated until the stream end; nothing is earned before.
    assert_eq!(s.earned(99), 0);
    assert_eq!(s.earned(100), 1000);
}

#[test]
fn raising_the_cliff_re_gates_but_never_claws_back() {
    let mut s = stream();
    assert_eq!(s.earned(25), 250);
    assert_eq!(s.stream_withdraw(recipient(), 25).unwrap(), 250);
    // Raise the cliff past now: the stream re-gates, but the 250
    // already withdrawn stays withdrawn — no clawback.
    s.amend_stream_cliff_secs(initializer(), recipient(), 50)
        .unwrap();
    assert_eq!(s.earned(30), 0);
    assert_eq!(s.stream_withdraw(recipient(), 30).unwrap(), 0);
    assert_eq!(s.withdrawn(), 250);
    assert_eq!(s.state(), StreamState::Active);
    // After the new cliff: ungated accrual 600, minus 250 withdrawn.
    assert_eq!(s.earned(60), 600);
    assert_eq!(s.stream_withdraw(recipient(), 60).unwrap(), 350);
    assert_eq!(s.withdrawn(), 600);
    // Rate, start, duration and checkpoint are untouched by the
    // amendment: accrual after the cliff still runs at 10/s.
    assert_eq!(s.earned(80), 800);
}

#[test]
fn lowering_the_cliff_releases_gated_accrual_at_once() {
    // cliff 50s: payout gated, accrual still runs from start_ts.
    let mut s =
        PaymentStream::create_stream(initializer(), recipient(), 10, 0, 100, 50).unwrap();
    assert_eq!(s.earned(25), 0);
    assert_eq!(s.stream_withdraw(recipient(), 25).unwrap(), 0);
    // Lower the cliff to 10s: the 250 accrued so far is payable now.
    s.amend_stream_cliff_secs(initializer(), recipient(), 10)
        .unwrap();
    assert_eq!(s.earned(25), 250);
    assert_eq!(s.stream_withdraw(recipient(), 25).unwrap(), 250);
    // Clearing the cliff entirely (0) is legal: no gate at all.
    s.amend_stream_cliff_secs(initializer(), recipient(), 0)
        .unwrap();
    assert_eq!(s.earned(30), 300);
    assert_eq!(s.stream_withdraw(recipient(), 30).unwrap(), 50);
}

#[test]
fn cliff_change_does_not_reprice_accrual() {
    // A rate change before the cliff checkpoints the *ungated*
    // accrual; a cliff change afterwards must not erase it.
    let mut s =
        PaymentStream::create_stream(initializer(), recipient(), 10, 0, 100, 50).unwrap();
    s.update_stream_rate(initializer(), recipient(), 20, 25)
        .unwrap();
    // Move the cliff earlier: 250 earned pre-change (ungated
    // checkpoint) + 10s x 20 post-change — not 10s x 20 alone.
    s.amend_stream_cliff_secs(initializer(), recipient(), 30)
        .unwrap();
    assert_eq!(s.earned(35), 450);
    assert_eq!(s.stream_withdraw(recipient(), 35).unwrap(), 450);
}

#[test]
fn terminal_streams_refuse_cliff_changes() {
    // Cancelled.
    let mut s = stream();
    s.stream_cancel(initializer(), 25).unwrap();
    assert_eq!(s.state(), StreamState::Cancelled);
    assert_eq!(
        s.amend_stream_cliff_secs(initializer(), recipient(), 50),
        Err(EscrowError::StreamNotActive)
    );
    // Exhausted (fully withdrawn).
    let mut s = stream();
    assert_eq!(s.stream_withdraw(recipient(), 100).unwrap(), 1000);
    assert_eq!(s.state(), StreamState::Exhausted);
    assert_eq!(
        s.amend_stream_cliff_secs(initializer(), recipient(), 50),
        Err(EscrowError::StreamNotActive)
    );
}

#[test]
fn cliff_change_while_paused_applies_from_resume() {
    let mut s = stream();
    s.pause(initializer(), 20).unwrap();
    // Accrual frozen at 200; changing the cliff while paused is legal.
    s.amend_stream_cliff_secs(initializer(), recipient(), 50)
        .unwrap();
    assert_eq!(s.earned(30), 0);
    s.resume(initializer(), 40).unwrap();
    // 20s pre-pause at 10 + 10s post-resume at 10, past the new cliff.
    assert_eq!(s.earned(50), 300);
}

#[test]
fn same_cliff_change_is_an_idempotent_noop() {
    let mut s =
        PaymentStream::create_stream(initializer(), recipient(), 10, 0, 100, 50).unwrap();
    s.amend_stream_cliff_secs(initializer(), recipient(), 50)
        .unwrap();
    assert_eq!(s.cliff_secs(), 50);
    assert_eq!(s.earned(60), 600);
}

#[test]
fn cliff_update_audit_json_shape() {
    assert_eq!(
        PaymentStream::cliff_update_audit_json(0, 50, 25),
        "{\"event\":\"stream_cliff_updated\",\"old_cliff_secs\":0,\"new_cliff_secs\":50,\"at\":25}"
    );
}
