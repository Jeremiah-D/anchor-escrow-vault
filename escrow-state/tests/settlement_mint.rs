//! AV-217: settlement-mint conversion — test matrix.
//!
//! When an escrow opts in via `with_settlement_mint`
//! (`Uninitialized`-only, non-zero key), `release` keeps
//! settling in funded units, and
//! `release_with_settlement_rate` settles the same guard chain
//! with the returned legs redenominated at a dual-signed rate:
//!
//! ```text
//! payout_settled  = floor(payout_funded  * num / den)
//! fee_settled     = floor(fee_funded     * num / den)
//! penalty_settled = floor(penalty_funded * num / den)
//! ```
//!
//! each leg floored independently (the dust stays with the
//! vault; funded-unit conservation remains the audited
//! identity). The attestation fails closed: no bound mint, an
//! expired quote, a quote for the wrong mint, a zero
//! denominator, or either party's signature failing all refuse
//! before any settlement runs. A quote presented exactly at
//! its `expires_at` is still valid (the AV-206 strict-after
//! convention).

use escrow_state::{
    settlement_rate_message, Escrow, EscrowError, EscrowState, SettlementRateAttestation,
    SigningKey,
};

fn init_key() -> SigningKey {
    SigningKey::from_seed([0x11; 32])
}

fn taker_key() -> SigningKey {
    SigningKey::from_seed([0x22; 32])
}

fn stranger_key() -> SigningKey {
    SigningKey::from_seed([0x33; 32])
}

fn initializer() -> [u8; 32] {
    init_key().public_key()
}

fn taker() -> [u8; 32] {
    taker_key().public_key()
}

fn settle_mint() -> [u8; 32] {
    [0x44; 32]
}

/// A dual-signed quote over the given terms.
fn quote(
    settle: [u8; 32],
    numerator: u64,
    denominator: u64,
    expires_at: u64,
) -> SettlementRateAttestation {
    let mut attestation = SettlementRateAttestation {
        settle_mint: settle,
        numerator,
        denominator,
        expires_at,
        initializer_signature: [0u8; 64],
        taker_signature: [0u8; 64],
    };
    let message = settlement_rate_message(&attestation);
    attestation.initializer_signature = init_key().sign(&message);
    attestation.taker_signature = taker_key().sign(&message);
    attestation
}

fn settled() -> Escrow {
    Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_settlement_mint(settle_mint())
        .unwrap()
}

fn funded_settled() -> Escrow {
    let mut e = settled();
    e.fund(initializer(), 100).unwrap();
    e
}

#[test]
fn builder_is_uninitialized_only_and_rejects_the_zero_key() {
    let e = settled();
    assert_eq!(e.settlement_mint(), Some(settle_mint()));
    let plain = Escrow::initialize(initializer(), taker(), 1_000, 10_000).unwrap();
    assert_eq!(plain.settlement_mint(), None);
    assert_eq!(
        plain.with_settlement_mint([0u8; 32]),
        Err(EscrowError::InvalidMint)
    );
    let funded = funded_settled();
    assert_eq!(
        funded.with_settlement_mint([0x55; 32]),
        Err(EscrowError::InvalidStateTransition)
    );
}

#[test]
fn settled_release_converts_payout_fee_and_penalty_legs() {
    // 1% protocol fee, 10% late-delivery penalty, 3:2 rate.
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_protocol_fee(100)
        .unwrap()
        .with_delivery_confirmation()
        .unwrap()
        .with_delivery_deadline(500)
        .unwrap()
        .with_late_delivery_penalty_bps(1_000)
        .unwrap()
        .with_settlement_mint(settle_mint())
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    e.confirm_delivery_at(taker(), 501).unwrap();
    let attestation = quote(settle_mint(), 3, 2, 2_000);
    let settled = e
        .release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &attestation)
        .unwrap();
    // Funded units: penalty 100, net 900, fee 9, payout 891.
    // Settled at 3:2, floored per leg: payout 1336, fee 13,
    // penalty 150.
    assert_eq!(settled.payout, 1_336);
    assert_eq!(settled.fee, 13);
    assert_eq!(settled.penalty, 150);
    assert_eq!(settled.settle_mint, settle_mint());
    // Funded counters still move in funded units.
    assert_eq!(e.released_amount(), 900);
    assert_eq!(e.penalty_paid(), 100);
    assert_eq!(e.fees_paid(), 9);
    assert_eq!(e.remaining_amount(), 0);
    assert_eq!(e.state(), EscrowState::Released);
}

#[test]
fn conversion_floors_each_leg() {
    let mut e = funded_settled();
    let attestation = quote(settle_mint(), 1, 3, 2_000);
    let settled = e
        .release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &attestation)
        .unwrap();
    // floor(1000 / 3) = 333, not 334.
    assert_eq!(settled.payout, 333);
    assert_eq!(settled.fee, 0);
    assert_eq!(settled.penalty, 0);
}

#[test]
fn attestation_failures_are_fail_closed() {
    // Expired quote: now past expires_at.
    let mut e = funded_settled();
    let stale = quote(settle_mint(), 2, 1, 599);
    assert_eq!(
        e.release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &stale),
        Err(EscrowError::SettlementRateExpired)
    );
    assert_eq!(e.state(), EscrowState::Funded);
    assert_eq!(e.released_amount(), 0);
    assert_eq!(e.fees_paid(), 0);

    // Wrong settlement mint in the quote.
    let mut e = funded_settled();
    let wrong_mint = quote([0x55; 32], 2, 1, 2_000);
    assert_eq!(
        e.release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &wrong_mint),
        Err(EscrowError::SettlementRateInvalid)
    );

    // Zero denominator is not a rate.
    let mut e = funded_settled();
    let zero_den = quote(settle_mint(), 2, 0, 2_000);
    assert_eq!(
        e.release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &zero_den),
        Err(EscrowError::SettlementRateInvalid)
    );

    // Stranger's signature in place of the taker's.
    let mut e = funded_settled();
    let mut forged = quote(settle_mint(), 2, 1, 2_000);
    forged.taker_signature = stranger_key().sign(&settlement_rate_message(&forged));
    assert_eq!(
        e.release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &forged),
        Err(EscrowError::SettlementRateInvalid)
    );

    // Tampered terms after signing: the signatures no longer
    // cover the quote.
    let mut e = funded_settled();
    let mut tampered = quote(settle_mint(), 2, 1, 2_000);
    tampered.numerator = 3;
    assert_eq!(
        e.release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &tampered),
        Err(EscrowError::SettlementRateInvalid)
    );

    // No settlement mint bound at all: the settled path has no
    // denomination, whatever the quote says.
    let mut plain = Escrow::initialize(initializer(), taker(), 1_000, 10_000).unwrap();
    plain.fund(initializer(), 100).unwrap();
    let attestation = quote(settle_mint(), 2, 1, 2_000);
    assert_eq!(
        plain.release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &attestation),
        Err(EscrowError::SettlementMintNotBound)
    );

    // A stranger cannot drive the settled release either — the
    // settled path runs the plain release authority gate.
    let mut e = funded_settled();
    let attestation = quote(settle_mint(), 2, 1, 2_000);
    assert_eq!(
        e.release_with_settlement_rate(stranger_key().public_key(), 600, 1_000, None, taker(), &attestation),
        Err(EscrowError::Unauthorized)
    );
}

#[test]
fn quote_exactly_at_expiry_is_still_valid() {
    let mut e = funded_settled();
    let attestation = quote(settle_mint(), 2, 1, 600);
    let settled = e
        .release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &attestation)
        .unwrap();
    assert_eq!(settled.payout, 2_000);
    assert_eq!(settled.fee, 0);
    assert_eq!(settled.penalty, 0);
}

#[test]
fn plain_release_still_settles_funded_units() {
    // Binding a settlement mint changes nothing for the plain
    // path: it keeps settling in funded units, unconverted.
    let mut e = funded_settled();
    assert_eq!(
        e.release(initializer(), 600, 1_000, None, taker()).unwrap(),
        (1_000, 0)
    );
    assert_eq!(e.released_amount(), 1_000);
}

#[test]
fn error_codes_are_pinned() {
    assert_eq!(EscrowError::SettlementMintNotBound.code(), 346);
    assert_eq!(EscrowError::SettlementRateInvalid.code(), 347);
    assert_eq!(EscrowError::SettlementRateExpired.code(), 348);
}
