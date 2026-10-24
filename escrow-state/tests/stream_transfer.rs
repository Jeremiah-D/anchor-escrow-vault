//! AV-202: `PaymentStream::transfer_recipient` — test matrix.
//!
//! The current recipient may transfer the whole stream to a new
//! recipient: the stream survives (rate, schedule, initializer,
//! paused intervals, state are untouched), the new recipient inherits
//! the earned-but-unwithdrawn balance, and the transfer is recorded
//! with the `stream_recipient_transferred` audit event. Orthogonal to
//! `stream_cancel` (terminal — this is a *continuing* transfer).
//!
//! Check order: authority → state → config.

use escrow_state::{EscrowError, PaymentStream, StreamState};

fn initializer() -> [u8; 32] {
    [7u8; 32]
}

fn recipient() -> [u8; 32] {
    [9u8; 32]
}

fn new_recipient() -> [u8; 32] {
    [13u8; 32]
}

fn stranger() -> [u8; 32] {
    [11u8; 32]
}

/// rate 10/s, start 0, duration 100s — total funded 1000.
fn stream() -> PaymentStream {
    PaymentStream::create_stream(initializer(), recipient(), 10, 0, 100, 0).unwrap()
}

#[test]
fn transfer_happy_path_moves_payee_and_preserves_schedule() {
    let mut s = stream();
    // Old recipient withdraws 250 first (t=25), then transfers the rest.
    assert_eq!(s.stream_withdraw(recipient(), 25).unwrap(), 250);
    let before = s.recipient();
    s.transfer_recipient(recipient(), new_recipient()).unwrap();
    assert_eq!(before, recipient());
    assert_eq!(s.recipient(), new_recipient());
    // Everything else is untouched.
    assert_eq!(s.initializer(), initializer());
    assert_eq!(s.rate_per_sec(), 10);
    assert_eq!(s.start_ts(), 0);
    assert_eq!(s.duration_secs(), 100);
    assert_eq!(s.cliff_secs(), 0);
    assert_eq!(s.total_funded(), 1000);
    assert_eq!(s.withdrawn(), 250);
    assert_eq!(s.state(), StreamState::Active);
    assert!(!s.is_paused());
}

#[test]
fn new_recipient_inherits_earned_but_unwithdrawn() {
    let mut s = stream();
    assert_eq!(s.stream_withdraw(recipient(), 25).unwrap(), 250);
    s.transfer_recipient(recipient(), new_recipient()).unwrap();
    // At t=60 earned is 600; 250 already withdrawn → 350 due to the
    // *new* recipient.
    assert_eq!(s.stream_withdraw(new_recipient(), 60).unwrap(), 350);
    assert_eq!(s.withdrawn(), 600);
}

#[test]
fn old_recipient_loses_withdraw_rights_after_transfer() {
    let mut s = stream();
    s.transfer_recipient(recipient(), new_recipient()).unwrap();
    // The old key is now a stranger: authority is checked first.
    assert_eq!(
        s.stream_withdraw(recipient(), 10),
        Err(EscrowError::StreamUnauthorized)
    );
    assert_eq!(
        s.transfer_recipient(recipient(), stranger()),
        Err(EscrowError::StreamUnauthorized)
    );
}

#[test]
fn stranger_and_initializer_cannot_transfer() {
    let mut s = stream();
    // Stranger first: authority before state.
    assert_eq!(
        s.transfer_recipient(stranger(), new_recipient()),
        Err(EscrowError::StreamUnauthorized)
    );
    // The initializer may cancel but may NOT reassign the stream.
    assert_eq!(
        s.transfer_recipient(initializer(), new_recipient()),
        Err(EscrowError::StreamUnauthorized)
    );
    assert_eq!(s.recipient(), recipient());
}

#[test]
fn transfer_on_terminal_stream_is_stream_not_active() {
    // After cancel: terminal.
    let mut s = stream();
    s.stream_cancel(initializer(), 50).unwrap();
    assert_eq!(s.state(), StreamState::Cancelled);
    assert_eq!(
        s.transfer_recipient(recipient(), new_recipient()),
        Err(EscrowError::StreamNotActive)
    );
    // After exhaustion: terminal too.
    let mut s2 = stream();
    assert_eq!(s2.stream_withdraw(recipient(), 100).unwrap(), 1000);
    assert_eq!(s2.state(), StreamState::Exhausted);
    assert_eq!(
        s2.transfer_recipient(recipient(), new_recipient()),
        Err(EscrowError::StreamNotActive)
    );
}

#[test]
fn zero_new_recipient_is_invalid_stream() {
    let mut s = stream();
    assert_eq!(
        s.transfer_recipient(recipient(), [0u8; 32]),
        Err(EscrowError::InvalidStream)
    );
    assert_eq!(s.recipient(), recipient());
}

#[test]
fn self_transfer_is_an_idempotent_noop() {
    let mut s = stream();
    s.transfer_recipient(recipient(), recipient()).unwrap();
    assert_eq!(s.recipient(), recipient());
    assert_eq!(s.state(), StreamState::Active);
    assert_eq!(s.stream_withdraw(recipient(), 10).unwrap(), 100);
}

#[test]
fn transfer_while_paused_keeps_pause_accounting() {
    let mut s = stream();
    s.pause(initializer(), 10).unwrap();
    s.transfer_recipient(recipient(), new_recipient()).unwrap();
    s.resume(initializer(), 20).unwrap();
    // 10 paused seconds excluded: at t=30 earned = 10 * (30 - 10) = 200.
    assert_eq!(s.earned(30), 200);
    assert_eq!(s.stream_withdraw(new_recipient(), 30).unwrap(), 200);
    assert_eq!(s.paused_total(), 10);
}

#[test]
fn transfer_audit_json_carries_the_event() {
    let j = PaymentStream::transfer_audit_json(recipient(), new_recipient());
    assert!(j.starts_with("{\"event\":\"stream_recipient_transferred\","));
    assert!(j.contains("\"old_recipient\":\"0909090909090909090909090909090909090909090909090909090909090909\""));
    assert!(j.contains("\"new_recipient\":\"0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d\""));
    assert!(j.ends_with('}'));
}

#[test]
fn transfer_does_not_renumber_error_codes() {
    assert_eq!(EscrowError::InvalidStream.code(), 304);
    assert_eq!(EscrowError::StreamUnauthorized.code(), 305);
    assert_eq!(EscrowError::StreamNotActive.code(), 306);
}
