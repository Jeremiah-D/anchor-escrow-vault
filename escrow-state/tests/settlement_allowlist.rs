//! AV-218: settlement-mint allowlist — test matrix.
//!
//! AV-217 settles in any attested mint. This item adds the
//! initializer's own gate: an opt-in, `Uninitialized`-only list
//! of at most 8 settlement mints. `release_with_settlement_rate`
//! checks the attestation's mint against the list *before* rate
//! verification or conversion pricing, so a non-allowlisted mint
//! is refused with `SettlementMintNotAllowlisted` even when the
//! quote is perfectly signed — and even when it is not signed
//! at all (the allowlist check precedes signature verification).
//! No allowlist configured means AV-217 semantics unchanged,
//! and plain `release` never consults the list.

use escrow_state::{
    settlement_rate_message, Escrow, EscrowError, EscrowState, SettlementMintAllowlist,
    SettlementRateAttestation, SigningKey,
};

fn init_key() -> SigningKey {
    SigningKey::from_seed([0x11; 32])
}

fn taker_key() -> SigningKey {
    SigningKey::from_seed([0x22; 32])
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

fn other_mint() -> [u8; 32] {
    [0x55; 32]
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

fn allowlisted() -> Escrow {
    Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_settlement_mint(settle_mint())
        .unwrap()
        .with_settlement_mint_allowlist(&[settle_mint(), other_mint()])
        .unwrap()
}

fn funded_allowlisted() -> Escrow {
    let mut e = allowlisted();
    e.fund(initializer(), 100).unwrap();
    e
}

#[test]
fn builder_is_uninitialized_only_and_validates_entries() {
    let e = allowlisted();
    let list = e.settlement_mint_allowlist().unwrap();
    assert_eq!(list.as_slice(), &[settle_mint(), other_mint()]);
    assert!(list.contains(&settle_mint()));
    assert!(!list.contains(&[0x66; 32]));

    // No allowlist by default.
    let plain = Escrow::initialize(initializer(), taker(), 1_000, 10_000).unwrap();
    assert_eq!(plain.settlement_mint_allowlist(), None);

    // An empty slice means "allowlist off", the AV-157 convention.
    let off = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_settlement_mint_allowlist(&[])
        .unwrap();
    assert_eq!(off.settlement_mint_allowlist(), None);

    // A zero address is fail-closed.
    assert_eq!(
        plain
            .clone()
            .with_settlement_mint_allowlist(&[[0u8; 32]]),
        Err(EscrowError::InvalidSettlementMintAllowlist)
    );
    // A duplicate is fail-closed.
    assert_eq!(
        plain
            .clone()
            .with_settlement_mint_allowlist(&[settle_mint(), settle_mint()]),
        Err(EscrowError::InvalidSettlementMintAllowlist)
    );
    // More than 8 entries is fail-closed (distinct entries, so
    // the length check is what fires, not the duplicate check).
    let mut distinct = [[0u8; 32]; 9];
    for (i, m) in distinct.iter_mut().enumerate() {
        m[0] = (i + 1) as u8;
    }
    assert_eq!(
        plain
            .clone()
            .with_settlement_mint_allowlist(&distinct),
        Err(EscrowError::InvalidSettlementMintAllowlist)
    );

    // The direct constructor validates the same way.
    assert_eq!(
        SettlementMintAllowlist::new(&[]),
        Err(EscrowError::InvalidSettlementMintAllowlist)
    );
    assert_eq!(
        SettlementMintAllowlist::new(&[settle_mint(), settle_mint()]),
        Err(EscrowError::InvalidSettlementMintAllowlist)
    );

    // A funded escrow cannot gain an allowlist mid-deal.
    let funded = funded_allowlisted();
    assert_eq!(
        funded.with_settlement_mint_allowlist(&[settle_mint()]),
        Err(EscrowError::InvalidStateTransition)
    );
}

#[test]
fn allowlisted_quote_settles_and_plain_release_ignores_the_list() {
    let mut e = funded_allowlisted();
    let attestation = quote(settle_mint(), 2, 1, 2_000);
    let settled = e
        .release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &attestation)
        .unwrap();
    assert_eq!(settled.payout, 2_000);
    assert_eq!(settled.settle_mint, settle_mint());
    assert_eq!(e.state(), EscrowState::Released);

    // Plain release never consults the allowlist: an escrow with
    // a list that excludes nothing still settles in funded units.
    let mut e = funded_allowlisted();
    assert_eq!(
        e.release(initializer(), 600, 1_000, None, taker()).unwrap(),
        (1_000, 0)
    );
    assert_eq!(e.released_amount(), 1_000);
}

#[test]
fn non_allowlisted_quote_is_refused_before_verification() {
    // A perfectly signed quote for a mint outside the list.
    let mut e = funded_allowlisted();
    let signed = quote([0x66; 32], 2, 1, 2_000);
    assert_eq!(
        e.release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &signed),
        Err(EscrowError::SettlementMintNotAllowlisted)
    );
    // Nothing moved, and the escrow still settles afterwards.
    assert_eq!(e.state(), EscrowState::Funded);
    assert_eq!(e.released_amount(), 0);
    let good = quote(settle_mint(), 2, 1, 2_000);
    assert!(e
        .release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &good)
        .is_ok());

    // An *unsigned* quote for a non-allowlisted mint fails with
    // the allowlist error, not a signature error: the allowlist
    // check runs before verification.
    let mut e = funded_allowlisted();
    let mut unsigned = quote([0x66; 32], 2, 1, 2_000);
    unsigned.initializer_signature = [0u8; 64];
    unsigned.taker_signature = [0u8; 64];
    assert_eq!(
        e.release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &unsigned),
        Err(EscrowError::SettlementMintNotAllowlisted)
    );

    // An expired quote for a non-allowlisted mint likewise fails
    // at the allowlist, not at expiry: policy before quote.
    let mut e = funded_allowlisted();
    let stale = quote([0x66; 32], 2, 1, 599);
    assert_eq!(
        e.release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &stale),
        Err(EscrowError::SettlementMintNotAllowlisted)
    );
}

#[test]
fn allowlist_excluding_the_bound_mint_blocks_every_settled_release() {
    // The builder deliberately does not check the bound mint
    // against the list (the release-time gate is the single
    // enforcement point); a list that excludes the bound mint
    // simply means no settled release can pass.
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_settlement_mint(settle_mint())
        .unwrap()
        .with_settlement_mint_allowlist(&[other_mint()])
        .unwrap();
    e.fund(initializer(), 100).unwrap();
    let attestation = quote(settle_mint(), 2, 1, 2_000);
    assert_eq!(
        e.release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &attestation),
        Err(EscrowError::SettlementMintNotAllowlisted)
    );
    assert_eq!(e.state(), EscrowState::Funded);
}

#[test]
fn no_allowlist_keeps_av217_semantics() {
    let mut e = Escrow::initialize(initializer(), taker(), 1_000, 10_000)
        .unwrap()
        .with_settlement_mint(settle_mint())
        .unwrap();
    assert_eq!(e.settlement_mint_allowlist(), None);
    e.fund(initializer(), 100).unwrap();
    let attestation = quote(settle_mint(), 2, 1, 2_000);
    let settled = e
        .release_with_settlement_rate(initializer(), 600, 1_000, None, taker(), &attestation)
        .unwrap();
    assert_eq!(settled.payout, 2_000);
}

#[test]
fn error_codes_are_pinned() {
    assert_eq!(EscrowError::InvalidSettlementMintAllowlist.code(), 349);
    assert_eq!(EscrowError::SettlementMintNotAllowlisted.code(), 350);
}
