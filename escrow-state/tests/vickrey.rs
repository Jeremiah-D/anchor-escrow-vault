//! AV-200: Vickrey (second-price) sealed-bid settlement — test matrix.
//!
//! `SealedBidAuction::with_vickrey` opts a sealed-bid auction into
//! second-price settlement: the highest *validly revealed* bid still
//! wins (ties to the earliest reveal, exactly like first-price), but
//! the winner pays the second-highest revealed bid — the classic
//! truthful-bidding incentive. The pricing rule is locked before the
//! first commitment lands (`SealedBidPricingLocked`, code 313);
//! changing it afterwards would rewrite the game the bidders entered.
//!
//! The matrix below pins: the default stays first-price, the
//! second-price happy path, the single-revealer degenerate case, tie
//! handling, the minimum-bid floor clamp on the price, the
//! `ReserveNotMet` / `NoBids` reuse, unrevealed commitments staying out
//! of the price, the pricing-lock rejections, the audit JSON, and the
//! new error code pin.

use escrow_state::{
    sealed_bid_commitment, EscrowError, SealedBidAuction, SealedBidPricing,
    SealedBidSettlement,
};

fn key(b: u8) -> [u8; 32] {
    [b; 32]
}
fn nonce(b: u8) -> [u8; 32] {
    [b.wrapping_add(0x80); 32]
}

/// Commit window [100, 200), reveal window [200, 300).
fn vickrey_auction(min_bid: u64) -> SealedBidAuction {
    SealedBidAuction::new(key(0xAA), 100, 200, 300, min_bid)
        .unwrap()
        .with_vickrey()
        .unwrap()
}

fn commit(a: &mut SealedBidAuction, bidder: [u8; 32], bid: u64, n: [u8; 32], slot: u64) {
    let c = sealed_bid_commitment(&bidder, bid, &n);
    a.commit_bid(bidder, c, slot).unwrap();
}

#[test]
fn default_pricing_is_first_price_and_builder_opts_into_vickrey() {
    let a = SealedBidAuction::new(key(0xAA), 100, 200, 300, 0).unwrap();
    assert_eq!(a.pricing(), SealedBidPricing::FirstPrice);
    let a = a.with_vickrey().unwrap();
    assert_eq!(a.pricing(), SealedBidPricing::Vickrey);
    // Idempotent: opting in twice is a harmless no-op.
    let a = a.with_vickrey().unwrap();
    assert_eq!(a.pricing(), SealedBidPricing::Vickrey);
}

#[test]
fn vickrey_winner_pays_second_highest() {
    let mut a = vickrey_auction(0);
    commit(&mut a, key(1), 50, nonce(1), 100);
    commit(&mut a, key(2), 90, nonce(2), 120);
    commit(&mut a, key(3), 70, nonce(3), 150);
    a.reveal_bid(key(1), 50, nonce(1), 200).unwrap();
    a.reveal_bid(key(2), 90, nonce(2), 210).unwrap();
    a.reveal_bid(key(3), 70, nonce(3), 220).unwrap();
    // Bidder 2 wins (highest reveal) but pays bidder 3's 70.
    assert_eq!(
        a.settle(300).unwrap(),
        SealedBidSettlement::Sold {
            winner: key(2),
            winning_bid: 70
        }
    );
}

#[test]
fn vickrey_lone_revealer_pays_own_bid() {
    let mut a = vickrey_auction(0);
    commit(&mut a, key(1), 90, nonce(1), 100);
    commit(&mut a, key(2), 50, nonce(2), 120);
    // Bidder 2 never reveals — the commitment drops out of contention
    // (AV-194 governs the deposit side) and cannot set the price.
    a.reveal_bid(key(1), 90, nonce(1), 200).unwrap();
    assert_eq!(
        a.settle(300).unwrap(),
        SealedBidSettlement::Sold {
            winner: key(1),
            winning_bid: 90
        }
    );
}

#[test]
fn vickrey_tie_pays_the_tied_price_to_earliest_reveal() {
    let mut a = vickrey_auction(0);
    commit(&mut a, key(1), 90, nonce(1), 100);
    commit(&mut a, key(2), 90, nonce(2), 110);
    // Bidder 2 reveals first, but the tie breaks to bidder 1's earlier
    // reveal slot — and the second-highest bid is also 90.
    a.reveal_bid(key(2), 90, nonce(2), 210).unwrap();
    a.reveal_bid(key(1), 90, nonce(1), 200).unwrap();
    assert_eq!(
        a.settle(300).unwrap(),
        SealedBidSettlement::Sold {
            winner: key(1),
            winning_bid: 90
        }
    );
}

#[test]
fn vickrey_price_is_clamped_up_to_the_minimum_bid() {
    // min_bid = 100. The winner's own bid clears the floor; the
    // second-highest (60) does not — the seller still gets the floor.
    let mut a = vickrey_auction(100);
    commit(&mut a, key(1), 150, nonce(1), 100);
    commit(&mut a, key(2), 60, nonce(2), 120);
    a.reveal_bid(key(1), 150, nonce(1), 200).unwrap();
    a.reveal_bid(key(2), 60, nonce(2), 210).unwrap();
    assert_eq!(
        a.settle(300).unwrap(),
        SealedBidSettlement::Sold {
            winner: key(1),
            winning_bid: 100
        }
    );
}

#[test]
fn vickrey_second_price_above_floor_is_untouched() {
    let mut a = vickrey_auction(10);
    commit(&mut a, key(1), 150, nonce(1), 100);
    commit(&mut a, key(2), 120, nonce(2), 120);
    a.reveal_bid(key(1), 150, nonce(1), 200).unwrap();
    a.reveal_bid(key(2), 120, nonce(2), 210).unwrap();
    assert_eq!(
        a.settle(300).unwrap(),
        SealedBidSettlement::Sold {
            winner: key(1),
            winning_bid: 120
        }
    );
}

#[test]
fn vickrey_reuses_reserve_not_met_and_no_bids() {
    // Best valid bid under the floor: reserve not met — same rule as
    // first-price.
    let mut a = vickrey_auction(100);
    commit(&mut a, key(1), 80, nonce(1), 100);
    commit(&mut a, key(2), 60, nonce(2), 120);
    a.reveal_bid(key(1), 80, nonce(1), 200).unwrap();
    a.reveal_bid(key(2), 60, nonce(2), 210).unwrap();
    assert_eq!(
        a.settle(300).unwrap(),
        SealedBidSettlement::ReserveNotMet {
            highest_bidder: key(1),
            highest_bid: 80
        }
    );
    // Nobody reveals: no sale.
    let mut b = vickrey_auction(0);
    commit(&mut b, key(1), 80, nonce(1), 100);
    assert_eq!(b.settle(300).unwrap(), SealedBidSettlement::NoBids);
}

#[test]
fn pricing_lock_rejects_mode_change_after_first_commit() {
    let mut a = SealedBidAuction::new(key(0xAA), 100, 200, 300, 0).unwrap();
    commit(&mut a, key(1), 50, nonce(1), 100);
    let err = a.with_vickrey().unwrap_err();
    assert_eq!(err, EscrowError::SealedBidPricingLocked);
    assert_eq!(err.code(), 313);
    // The pricing rule did not move.
    assert_eq!(a.pricing(), SealedBidPricing::FirstPrice);
}

#[test]
fn pricing_lock_rejects_mode_change_on_terminal_auction() {
    let mut a = vickrey_auction(0);
    commit(&mut a, key(1), 50, nonce(1), 100);
    a.reveal_bid(key(1), 50, nonce(1), 200).unwrap();
    a.settle(300).unwrap();
    let err = a.with_vickrey().unwrap_err();
    assert_eq!(err, EscrowError::SealedBidPricingLocked);
    // A cancelled auction is terminal too.
    let mut b = SealedBidAuction::new(key(0xAA), 100, 200, 300, 0).unwrap();
    b.cancel(key(0xAA), 100).unwrap();
    assert_eq!(
        b.with_vickrey().unwrap_err(),
        EscrowError::SealedBidPricingLocked
    );
}

#[test]
fn vickrey_reveal_phase_gates_are_unchanged() {
    let mut a = vickrey_auction(0);
    let c = sealed_bid_commitment(&key(1), 50, &nonce(1));
    // Commit during the reveal phase is still refused.
    assert_eq!(
        a.commit_bid(key(1), c, 200).unwrap_err(),
        EscrowError::SealedBidNotLive
    );
    // Wrong preimage is still a mismatch.
    commit(&mut a, key(1), 50, nonce(1), 100);
    assert_eq!(
        a.reveal_bid(key(1), 51, nonce(1), 200).unwrap_err(),
        EscrowError::SealedBidRevealMismatch
    );
    // Settling before the reveal window closes is still too early.
    a.reveal_bid(key(1), 50, nonce(1), 200).unwrap();
    assert_eq!(
        a.settle(299).unwrap_err(),
        EscrowError::SealedBidSettleTooEarly
    );
}

#[test]
fn settle_audit_json_records_pricing_and_second_price() {
    let mut a = vickrey_auction(0);
    commit(&mut a, key(1), 150, nonce(1), 100);
    commit(&mut a, key(2), 120, nonce(2), 120);
    a.reveal_bid(key(1), 150, nonce(1), 200).unwrap();
    a.reveal_bid(key(2), 120, nonce(2), 210).unwrap();
    let s = a.settle(300).unwrap();
    let j = a.settle_audit_json(s);
    assert!(j.contains("\"event\":\"sealed_bid_settled\""));
    assert!(j.contains("\"outcome\":\"sold\""));
    assert!(j.contains("\"winning_bid\":120"));
    assert!(j.contains("\"pricing\":\"vickrey\""));
    // First-price audit JSON keeps the old shape plus the pricing tag.
    let mut b = SealedBidAuction::new(key(0xAA), 100, 200, 300, 0).unwrap();
    commit(&mut b, key(1), 50, nonce(1), 100);
    b.reveal_bid(key(1), 50, nonce(1), 200).unwrap();
    let s = b.settle(300).unwrap();
    let j = b.settle_audit_json(s);
    assert!(j.contains("\"winning_bid\":50"));
    assert!(j.contains("\"pricing\":\"first_price\""));
}

#[test]
fn new_error_code_is_pinned() {
    assert_eq!(EscrowError::SealedBidPricingLocked.code(), 313);
    assert!(EscrowError::all().contains(&EscrowError::SealedBidPricingLocked));
}
