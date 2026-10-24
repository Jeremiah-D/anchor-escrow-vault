//! AV-201: English-auction buy-it-now — test matrix.
//!
//! `EnglishAuction::with_buyout` sets an opt-in buyout price: any
//! *legal* bid at or above it settles the auction immediately — the
//! winner pays exactly the buyout price (the bid is capped), the
//! remaining bidding window and any anti-sniping extension are
//! skipped, and the outbid leader is named in the receipt for the
//! exact full refund (the AV-194 deposit path reuses these fields
//! unchanged). The buyout price is locked before the first bid
//! (`EnglishAuctionBuyoutLocked`, code 314).
//!
//! The matrix below pins: the opt-in builder (defaults, no-op zero,
//! config fail-closes), the pricing lock, the immediate-settlement
//! happy path (price cap, refund fields, no extension, recorded
//! sale), the exact-price boundary, the below-buyout normal path,
//! post-buyout terminality, the anti-sniping skip, the
//! `ReserveNotMet` reuse when the window closes without a buyout, the
//! audit JSON, and the new error code pin.

use escrow_state::{
    AuctionSettlement, AuctionState, EnglishAuction, EscrowError, MAX_SNIPE_EXTENSIONS,
};

fn key(b: u8) -> [u8; 32] {
    [b; 32]
}

/// Bidding window [100, 200), min raise 10, no reserve, no anti-sniping.
fn open_auction() -> EnglishAuction {
    EnglishAuction::new(key(0xAA), 100, 200, 10, 0, 0, 0, 0).unwrap()
}

#[test]
fn buyout_is_opt_in_and_zero_is_a_noop() {
    let a = open_auction();
    assert_eq!(a.buyout_price(), 0);
    assert_eq!(a.buyout_sale(), None);
    // Zero is the disabled sentinel — a harmless no-op.
    let a = a.with_buyout(0).unwrap();
    assert_eq!(a.buyout_price(), 0);
    // Opt in.
    let a = a.with_buyout(500).unwrap();
    assert_eq!(a.buyout_price(), 500);
    // Replacing the price before any bid is allowed.
    let a = a.with_buyout(600).unwrap();
    assert_eq!(a.buyout_price(), 600);
}

#[test]
fn buyout_config_is_fail_closed() {
    // Below the minimum increment: could never trigger (the
    // minimum-raise gate would reject the bid first).
    assert_eq!(
        open_auction().with_buyout(9).unwrap_err(),
        EscrowError::InvalidEnglishAuction
    );
    // Below the reserve: would sell under the seller's floor.
    let a = EnglishAuction::new(key(0xAA), 100, 200, 10, 400, 0, 0, 0).unwrap();
    assert_eq!(
        a.with_buyout(399).unwrap_err(),
        EscrowError::InvalidEnglishAuction
    );
    // At the reserve: fine.
    let a = a.with_buyout(400).unwrap();
    assert_eq!(a.buyout_price(), 400);
    assert_eq!(EscrowError::InvalidEnglishAuction.code(), 263);
}

#[test]
fn buyout_price_locks_once_bidding_starts() {
    let mut a = open_auction().with_buyout(500).unwrap();
    a.place_bid(key(1), 100, 150).unwrap();
    let err = a.with_buyout(600).unwrap_err();
    assert_eq!(err, EscrowError::EnglishAuctionBuyoutLocked);
    assert_eq!(err.code(), 314);
    assert_eq!(a.buyout_price(), 500);
    // Terminal auctions lock too.
    let mut b = open_auction();
    b.cancel(key(0xAA), 150).unwrap();
    assert_eq!(
        b.with_buyout(500).unwrap_err(),
        EscrowError::EnglishAuctionBuyoutLocked
    );
}

#[test]
fn buyout_bid_settles_immediately_at_the_buyout_price() {
    let mut a = open_auction().with_buyout(500).unwrap();
    a.place_bid(key(1), 100, 150).unwrap();
    // 700 >= 500: buyout — the winner pays 500, not 700.
    let r = a.place_bid(key(2), 700, 160).unwrap();
    assert!(r.buyout);
    assert!(!r.extended);
    assert_eq!(r.new_bid, 500);
    assert_eq!(r.previous_bidder, key(1));
    assert_eq!(r.previous_bid, 100);
    assert_eq!(r.end_slot, 200);
    assert_eq!(a.state(), AuctionState::Settled);
    assert_eq!(a.highest_bidder(), key(2));
    assert_eq!(a.highest_bid(), 500);
    assert_eq!(a.buyout_sale(), Some((key(2), 500)));
}

#[test]
fn exact_buyout_price_triggers() {
    let mut a = open_auction().with_buyout(500).unwrap();
    let r = a.place_bid(key(1), 500, 150).unwrap();
    assert!(r.buyout);
    assert_eq!(r.new_bid, 500);
    assert_eq!(r.previous_bid, 0);
    assert_eq!(r.previous_bidder, [0u8; 32]);
    assert_eq!(a.buyout_sale(), Some((key(1), 500)));
}

#[test]
fn bids_below_buyout_take_the_normal_path() {
    let mut a = open_auction().with_buyout(500).unwrap();
    let r = a.place_bid(key(1), 100, 150).unwrap();
    assert!(!r.buyout);
    assert_eq!(r.new_bid, 100);
    assert_eq!(a.state(), AuctionState::Bidding);
    assert_eq!(a.buyout_sale(), None);
}

#[test]
fn buyout_skips_the_anti_sniping_extension() {
    // Tail window 10, extension 25, budget 2 — a normal tail bid would
    // push the close out.
    let mut a = EnglishAuction::new(key(0xAA), 100, 200, 10, 0, 10, 25, 2)
        .unwrap()
        .with_buyout(500)
        .unwrap();
    let r = a.place_bid(key(1), 500, 195).unwrap();
    assert!(r.buyout);
    assert!(!r.extended);
    assert_eq!(r.end_slot, 200);
    assert_eq!(a.end_slot(), 200);
    assert_eq!(a.extension_count(), 0);
    assert_eq!(a.state(), AuctionState::Settled);
}

#[test]
fn auction_is_terminal_after_buyout() {
    let mut a = open_auction().with_buyout(500).unwrap();
    a.place_bid(key(1), 500, 150).unwrap();
    // No more bids.
    assert_eq!(
        a.place_bid(key(2), 600, 160).unwrap_err(),
        EscrowError::EnglishAuctionNotLive
    );
    // settle() after the buyout is a double-settle — refused, same as
    // any terminal auction.
    assert_eq!(
        a.settle(200).unwrap_err(),
        EscrowError::EnglishAuctionNotLive
    );
    // No cancel either.
    assert_eq!(
        a.cancel(key(0xAA), 160).unwrap_err(),
        EscrowError::EnglishAuctionNotCancellable
    );
}

#[test]
fn reserve_not_met_path_is_reused_without_buyout() {
    // Reserve 150, buyout 500 — the window closes with the highest bid
    // under the reserve and no buyout: the normal ReserveNotMet path.
    let mut a = EnglishAuction::new(key(0xAA), 100, 200, 10, 150, 0, 0, 0)
        .unwrap()
        .with_buyout(500)
        .unwrap();
    a.place_bid(key(1), 100, 150).unwrap();
    a.place_bid(key(2), 120, 160).unwrap();
    assert_eq!(
        a.settle(200).unwrap(),
        AuctionSettlement::ReserveNotMet {
            highest_bidder: key(2),
            highest_bid: 120
        }
    );
    assert_eq!(a.state(), AuctionState::NoSale);
}

#[test]
fn buyout_bid_must_still_clear_the_minimum_raise() {
    // highest = 495, min_increment = 10, buyout = 500: a 502 offer is
    // above the buyout price but not a legal bid (ladder needs 505) —
    // the ladder is not bypassed.
    let mut a = open_auction().with_buyout(500).unwrap();
    a.place_bid(key(1), 495, 150).unwrap();
    assert_eq!(
        a.place_bid(key(2), 502, 160).unwrap_err(),
        EscrowError::EnglishAuctionBidTooLow
    );
    assert_eq!(a.state(), AuctionState::Bidding);
    // The next legal bid (505) reaches the buyout and settles.
    let r = a.place_bid(key(2), 505, 160).unwrap();
    assert!(r.buyout);
    assert_eq!(r.new_bid, 500);
}

#[test]
fn buyout_audit_json_carries_winner_price_and_refund() {
    let mut a = open_auction().with_buyout(500).unwrap();
    let r = a.place_bid(key(1), 100, 150).unwrap();
    let r2 = a.place_bid(key(2), 700, 160).unwrap();
    let j = a.buyout_audit_json(key(2), r2.previous_bidder, r2.previous_bid);
    assert!(j.contains("\"event\":\"english_auction_buyout\""));
    assert!(j.contains("\"price\":500"));
    assert!(j.contains("\"previous_bid\":100"));
    assert!(j.contains(
        "0101010101010101010101010101010101010101010101010101010101010101"
    ));
    assert!(j.contains(
        "0202020202020202020202020202020202020202020202020202020202020202"
    ));
    // Sanity: the receipt fields the audit JSON consumed.
    assert_eq!(r.previous_bid, 0);
}

#[test]
fn new_error_code_is_pinned() {
    assert_eq!(EscrowError::EnglishAuctionBuyoutLocked.code(), 314);
    assert!(EscrowError::all().contains(&EscrowError::EnglishAuctionBuyoutLocked));
    // The cap constant is untouched.
    assert_eq!(MAX_SNIPE_EXTENSIONS, 64);
}
