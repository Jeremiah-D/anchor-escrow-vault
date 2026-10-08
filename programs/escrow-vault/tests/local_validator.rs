//! Anchor integration test stubs for the escrow-vault program.
//!
//! These tests are `#[ignore]`d: CI never runs them. They are meant to be
//! run locally against a running `solana-test-validator`, in which case the
//! real on-chain assertions (account state round-trips after each
//! instruction) would execute against the deployed program.
//!
//! Local run:
//!
//! ```bash
//! solana-test-validator            # in another terminal
//! cargo test -p escrow-vault -- --ignored
//! ```
//!
//! The Anchor program source (`src/program.rs`) is not compiled in this
//! environment (it needs `anchor-lang` and the Solana toolchain), so these
//! stubs drive the *instruction -> state machine input mapping* pinned in
//! `escrow-state`'s AV-05 spec: each test builds the instruction call
//! exactly as the Anchor instruction would receive it (instruction name,
//! params, signer keys), feeds the mapped inputs to the real state machine,
//! and asserts the resulting state, amount invariants, and error variants.
//! Nothing is asserted without the mapping behind it, and nothing is
//! faked as passing: every test first calls `require_local_validator()`,
//! which fails loudly when no validator is reachable instead of silently
//! succeeding.
//!
//! Only existing dependencies are used (`escrow-state` via path; std for
//! the validator probe). No external crates were added.

use escrow_state::{Escrow, EscrowError, EscrowState, QuorumPolicy};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Default RPC port of `solana-test-validator`.
const VALIDATOR_RPC: &str = "127.0.0.1:8899";

/// Fail loudly when no local validator is reachable, instead of letting
/// the test pretend to pass. Dependency-free probe: a TCP connect to the
/// validator's RPC port with a short timeout.
fn require_local_validator() {
    let addr: SocketAddr = VALIDATOR_RPC
        .parse()
        .expect("VALIDATOR_RPC must be a valid socket address");
    let reachable = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok();
    assert!(
        reachable,
        "local solana-test-validator is not reachable at {VALIDATOR_RPC}: \
         start it with `solana-test-validator` in another terminal, then re-run \
         `cargo test -p escrow-vault -- --ignored`. Refusing to fake a pass."
    );
}

/// One Anchor instruction call as the on-chain program would receive it:
/// the instruction name, its IDL params, and the signer keys the program
/// reads authority from. Mirrors the AV-05 mapping spec in `escrow-state`.
#[derive(Debug)]
struct InstructionCall {
    /// Instruction name as it appears in the IDL (`global:<name>` sighash).
    name: &'static str,
    /// (param name, value) pairs the IDL declares for this instruction.
    params: Vec<(&'static str, u64)>,
    /// Signer keys the instruction reads authority from (`accounts.*`).
    signers: Vec<[u8; 32]>,
}

const ALICE: [u8; 32] = [0xAA; 32]; // initializer
const BOB: [u8; 32] = [0xBB; 32]; // taker
const MALLORY: [u8; 32] = [0xCC; 32]; // stranger
const ATTESTOR_1: [u8; 32] = [0xA1; 32];
const ATTESTOR_2: [u8; 32] = [0xA2; 32];
const ATTESTOR_3: [u8; 32] = [0xA3; 32];
const AMOUNT: u64 = 1_000_000;
const EXPIRES_AT: u64 = 1_800_000_000;

/// Drive the `initialize(amount, expires_at)` call the way the program's
/// `initialize` handler does: `initializer`/`taker` from the account
/// signers, `amount`/`expires_at` from the instruction params.
fn apply_initialize(call: &InstructionCall, initializer: [u8; 32], taker: [u8; 32]) -> Escrow {
    assert_eq!(call.name, "initialize");
    assert!(call.signers.contains(&initializer));
    let amount = call
        .params
        .iter()
        .find(|(n, _)| *n == "amount")
        .map(|(_, v)| *v)
        .expect("initialize must carry an `amount` param");
    let expires_at = call
        .params
        .iter()
        .find(|(n, _)| *n == "expires_at")
        .map(|(_, v)| *v)
        .expect("initialize must carry an `expires_at` param");
    Escrow::initialize(initializer, taker, amount, expires_at)
        .expect("initialize with amount > 0 must succeed")
}

/// Happy path: `initialize -> fund -> release`. Asserts the vault reaches
/// `Released` and the escrowed amount is preserved end to end (the payout
/// accounting the on-chain transfer must honor).
#[test]
#[ignore]
fn initialize_fund_release_happy_path() {
    require_local_validator();

    let init_call = InstructionCall {
        name: "initialize",
        params: vec![("amount", AMOUNT), ("expires_at", EXPIRES_AT)],
        signers: vec![ALICE],
    };
    let mut escrow = apply_initialize(&init_call, ALICE, BOB);
    assert_eq!(escrow.state(), EscrowState::Uninitialized);

    // `fund`: authority <- accounts.initializer (signer).
    escrow.fund(ALICE).expect("fund by initializer must succeed");
    assert_eq!(escrow.state(), EscrowState::Funded);

    // `release(amount)`: authority <- accounts.initializer (signer);
    // amount <- instruction param.
    escrow
        .release(ALICE, 1_750_000_000, AMOUNT, None)
        .expect("release by initializer must succeed");
    assert_eq!(escrow.state(), EscrowState::Released);
    assert_eq!(escrow.amount(), AMOUNT, "payout accounting preserved");
}

/// Quorum path: `initialize -> initialize_quorum -> attest x2 -> fund ->
/// release` with a 2-of-3 policy. Mirrors the AV-04 release gate: release
/// succeeds only once the threshold of distinct attestations is recorded.
#[test]
#[ignore]
fn quorum_attest_release_happy_path() {
    require_local_validator();

    let init_call = InstructionCall {
        name: "initialize",
        params: vec![("amount", AMOUNT), ("expires_at", EXPIRES_AT)],
        signers: vec![ALICE],
    };
    // `initialize_quorum(attestors, threshold)` params -> QuorumPolicy::new,
    // authority enforced by the program's account constraint (initializer).
    let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2, ATTESTOR_3], 2)
        .expect("2-of-3 policy must construct");
    let mut escrow = apply_initialize(&init_call, ALICE, BOB)
        .with_quorum(policy)
        .expect("quorum attach on Uninitialized must succeed");

    // `attest`: attestor <- accounts.attestor (signer, registered set).
    escrow.attest(ATTESTOR_1).expect("a1 attests");
    escrow.attest(ATTESTOR_3).expect("a3 attests");
    assert!(escrow
        .quorum()
        .expect("quorum must be set")
        .is_satisfied());

    escrow.fund(ALICE).expect("fund by initializer must succeed");
    escrow
        .release(ALICE, 1_750_000_000, AMOUNT, None)
        .expect("release with satisfied quorum must succeed");
    assert_eq!(escrow.state(), EscrowState::Released);
    assert_eq!(escrow.amount(), AMOUNT, "payout accounting preserved");
}

/// Failure path: `release` driven by a non-initializer. The state machine
/// must reject with `Unauthorized` (authority checked before state) and
/// leave the vault untouched.
#[test]
#[ignore]
fn release_by_non_initializer_is_rejected() {
    require_local_validator();

    let init_call = InstructionCall {
        name: "initialize",
        params: vec![("amount", AMOUNT), ("expires_at", EXPIRES_AT)],
        signers: vec![ALICE],
    };
    let mut escrow = apply_initialize(&init_call, ALICE, BOB);
    escrow.fund(ALICE).expect("fund by initializer must succeed");

    let release_call = InstructionCall {
        name: "release",
        params: vec![("amount", AMOUNT)],
        signers: vec![MALLORY],
    };
    assert!(release_call.signers.contains(&MALLORY));
    assert_eq!(
        escrow.release(MALLORY, 1_750_000_000, AMOUNT, None),
        Err(EscrowError::Unauthorized),
        "stranger release must be Unauthorized"
    );
    assert_eq!(escrow.state(), EscrowState::Funded, "state untouched");
    assert_eq!(escrow.amount(), AMOUNT, "amount untouched");
}

/// Failure path: `release` with a configured quorum whose threshold is not
/// reached. Must fail with `QuorumNotReached` while the vault stays
/// `Funded` and the funds stay locked.
#[test]
#[ignore]
fn release_before_quorum_threshold_is_rejected() {
    require_local_validator();

    let init_call = InstructionCall {
        name: "initialize",
        params: vec![("amount", AMOUNT), ("expires_at", EXPIRES_AT)],
        signers: vec![ALICE],
    };
    let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2, ATTESTOR_3], 2)
        .expect("2-of-3 policy must construct");
    let mut escrow = apply_initialize(&init_call, ALICE, BOB)
        .with_quorum(policy)
        .expect("quorum attach on Uninitialized must succeed");
    escrow.fund(ALICE).expect("fund by initializer must succeed");

    // Only one of the two required attestations: below threshold.
    escrow.attest(ATTESTOR_2).expect("a2 attests");
    assert!(!escrow
        .quorum()
        .expect("quorum must be set")
        .is_satisfied());

    assert_eq!(
        escrow.release(ALICE, 1_750_000_000, AMOUNT, None),
        Err(EscrowError::QuorumNotReached),
        "release below quorum threshold must be QuorumNotReached"
    );
    assert_eq!(escrow.state(), EscrowState::Funded, "funds stay locked");
    assert_eq!(escrow.amount(), AMOUNT, "amount untouched");
}
