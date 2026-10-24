//! AV-189: English auction — ascending-bid escrow.
//!
//! A seller lists an asset and bidders compete upward: every bid must
//! beat the current highest by at least the minimum increment. Two
//! classic English-auction rules are built in:
//!
//! - **Anti-sniping**: a bid landing inside the tail window pushes the
//!   settlement slot out by the configured extension (bounded by a
//!   maximum number of extensions, so a bidding war cannot postpone
//!   settlement forever).
//! - **Reserve price**: the seller's hidden floor. If the highest bid
//!   never reaches it, the sale fails and every bidder is refunded in
//!   full — the seller never parts with the asset below the floor.
//! - **Buy-it-now** (AV-201, opt-in): the seller may set a buyout
//!   price; a live bid at or above it settles the auction immediately
//!   at exactly that price, skipping the remaining window and any
//!   anti-sniping extension.
//!
//! Orthogonal to AV-97 (Dutch auction, *descending* price — the price
//! falls until someone takes it): here the price *rises* until nobody
//! outbids. Orthogonal to AV-13 vesting (a time-release schedule,
//! not price discovery). This crate is pure logic: bid custody (who
//! holds the lamports/tokens while bidding is live) is the Anchor
//! program's job; this module is the deterministic state machine the
//! program drives. `Copy`, heap-free, `no_std`-friendly.

use crate::EscrowError;

/// Maximum anti-sniping extensions per auction — the settle slot can
/// drift at most `max_extensions * anti_snipe_extension` past the
/// original end. Callers that want strictly bounded windows set
/// `max_extensions` accordingly (or `0` with `anti_snipe_window == 0`
/// to disable anti-sniping entirely).
pub const MAX_SNIPE_EXTENSIONS: u16 = 64;

/// Auction lifecycle: `Bidding` → `Settled` | `NoSale` | `Cancelled`.
/// All three exits are terminal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuctionState {
    /// Bidding is live (within `[start_slot, end_slot)`).
    #[default]
    Bidding,
    /// Settled to the winner — the reserve was met.
    Settled,
    /// No sale: either nobody bid or the reserve was not met — every
    /// bidder is refunded in full.
    NoSale,
    /// The seller cancelled before the first bid (terminal).
    Cancelled,
}

/// What [`EnglishAuction::settle`] decided once the bidding window
/// closed. The Anchor program maps `Sold` to "transfer the asset to
/// the winner, refund the outbid bidders" and `NoBids` /
/// `ReserveNotMet` to "refund everybody, return the asset to the
/// seller".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuctionSettlement {
    /// A winner exists: `(winner, winning_bid)`. The reserve (if any)
    /// was met.
    Sold {
        winner: [u8; 32],
        winning_bid: u64,
    },
    /// Nobody bid — nothing moves except the seller's asset coming
    /// home.
    NoBids,
    /// Bidding happened but the highest bid is under the reserve
    /// price: `(highest_bidder, highest_bid)`. Full refunds.
    ReserveNotMet {
        highest_bidder: [u8; 32],
        highest_bid: u64,
    },
}

/// The caller's receipt for a successful
/// [`EnglishAuction::place_bid`]: everything the Anchor program needs
/// to move funds — refund the previous leader their full bid, escrow
/// the new bid, and record the (possibly extended) end slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BidReceipt {
    /// The outbid leader's key, or the zero key when this is the
    /// opening bid (nothing to refund).
    pub previous_bidder: [u8; 32],
    /// The outbid leader's amount (`0` on the opening bid).
    pub previous_bid: u64,
    /// The new bid's amount (what the program escrows).
    pub new_bid: u64,
    /// The auction's end slot after this bid (anti-sniping may have
    /// pushed it out).
    pub end_slot: u64,
    /// `true` when this bid triggered an anti-sniping extension.
    pub extended: bool,
    /// `true` when this bid hit the buy-it-now price and settled the
    /// auction immediately — `new_bid` is the buyout price (the winner
    /// pays exactly that), and no anti-sniping extension fired.
    pub buyout: bool,
}

/// An English auction: ascending bids, a minimum raise, anti-sniping
/// tail protection, and a seller's reserve price.
///
/// Construct with [`EnglishAuction::new`]. The reserve price is set
/// once and is never revealed to bidders by this module — the Anchor
/// program keeps it in the vault account's private fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnglishAuction {
    seller: [u8; 32],
    reserve_price: u64,
    min_increment: u64,
    start_slot: u64,
    end_slot: u64,
    anti_snipe_window: u64,
    anti_snipe_extension: u64,
    max_extensions: u16,
    /// The buy-it-now price (`0` = disabled). A live bid at or above
    /// this price settles the auction immediately at exactly this
    /// price (see [`EnglishAuction::with_buyout`]).
    buyout_price: u64,
    highest_bid: u64,
    highest_bidder: [u8; 32],
    bid_count: u32,
    extension_count: u16,
    /// The recorded buy-it-now sale `(winner, price)` — `Some` only
    /// when the auction settled via [`EnglishAuction::place_bid`]'s
    /// buyout path.
    buyout_sale: Option<([u8; 32], u64)>,
    state: AuctionState,
}

impl EnglishAuction {
    /// Open an auction.
    ///
    /// Refused (fail-closed, [`EscrowError::InvalidEnglishAuction`],
    /// code 263) when the seller key is zero, `start_slot >=
    /// end_slot` (an empty bidding window), `min_increment == 0` (no
    /// minimum raise — the auction could never converge), or the
    /// anti-sniping config is degenerate: a nonzero tail window with
    /// a zero extension or a zero extension budget never triggers, so
    /// that combination is rejected. Both zero (or a nonzero budget
    /// with a zero window) disables anti-sniping cleanly.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        seller: [u8; 32],
        start_slot: u64,
        end_slot: u64,
        min_increment: u64,
        reserve_price: u64,
        anti_snipe_window: u64,
        anti_snipe_extension: u64,
        max_extensions: u16,
    ) -> Result<Self, EscrowError> {
        if seller == [0u8; 32] || start_slot >= end_slot || min_increment == 0 {
            return Err(EscrowError::InvalidEnglishAuction);
        }
        if max_extensions > MAX_SNIPE_EXTENSIONS {
            return Err(EscrowError::InvalidEnglishAuction);
        }
        if anti_snipe_window > 0 && (anti_snipe_extension == 0 || max_extensions == 0) {
            return Err(EscrowError::InvalidEnglishAuction);
        }
        Ok(EnglishAuction {
            seller,
            reserve_price,
            min_increment,
            start_slot,
            end_slot,
            anti_snipe_window,
            anti_snipe_extension,
            max_extensions,
            buyout_price: 0,
            highest_bid: 0,
            highest_bidder: [0u8; 32],
            bid_count: 0,
            extension_count: 0,
            buyout_sale: None,
            state: AuctionState::Bidding,
        })
    }

    /// Set a buy-it-now price: a live bid at or above `buyout_price`
    /// settles the auction immediately — the winner pays exactly
    /// `buyout_price`, the remaining bidding window and any
    /// anti-sniping extension are skipped.
    ///
    /// The price is fixed before the game starts: refused with
    /// [`EscrowError::EnglishAuctionBuyoutLocked`] (code 314) once the
    /// first bid has landed or the auction is terminal. Fail-closed
    /// config checks ([`EscrowError::InvalidEnglishAuction`], code
    /// 263): a price below `min_increment` could never trigger (the
    /// minimum-raise gate would reject the bid first), and a price
    /// below a nonzero `reserve_price` would sell under the seller's
    /// floor. `buyout_price == 0` is a no-op (buy-it-now stays
    /// disabled); calling twice replaces the price while no bid has
    /// landed.
    pub fn with_buyout(mut self, buyout_price: u64) -> Result<Self, EscrowError> {
        if buyout_price == 0 {
            return Ok(self);
        }
        if self.state != AuctionState::Bidding || self.bid_count > 0 {
            return Err(EscrowError::EnglishAuctionBuyoutLocked);
        }
        if buyout_price < self.min_increment
            || (self.reserve_price > 0 && buyout_price < self.reserve_price)
        {
            return Err(EscrowError::InvalidEnglishAuction);
        }
        self.buyout_price = buyout_price;
        Ok(self)
    }

    /// The buy-it-now price (`0` = disabled).
    pub fn buyout_price(&self) -> u64 {
        self.buyout_price
    }

    /// The recorded buy-it-now sale `(winner, price)` — `Some` only
    /// when the auction settled through the buyout path of
    /// [`EnglishAuction::place_bid`].
    pub fn buyout_sale(&self) -> Option<([u8; 32], u64)> {
        self.buyout_sale
    }

    /// The seller key.
    pub fn seller(&self) -> [u8; 32] {
        self.seller
    }

    /// The seller's reserve price (`0` = no reserve).
    pub fn reserve_price(&self) -> u64 {
        self.reserve_price
    }

    /// The minimum raise over the current highest bid — and the
    /// minimum *opening* bid (the first bid must clear
    /// `min_increment`).
    pub fn min_increment(&self) -> u64 {
        self.min_increment
    }

    /// The slot bidding opens.
    pub fn start_slot(&self) -> u64 {
        self.start_slot
    }

    /// The slot bidding closes — pushed out by anti-sniping bids (see
    /// [`EnglishAuction::place_bid`]).
    pub fn end_slot(&self) -> u64 {
        self.end_slot
    }

    /// Current lifecycle state.
    pub fn state(&self) -> AuctionState {
        self.state
    }

    /// The current highest bid (`0` before the first bid).
    pub fn highest_bid(&self) -> u64 {
        self.highest_bid
    }

    /// The current leader's key (zero key before the first bid).
    pub fn highest_bidder(&self) -> [u8; 32] {
        self.highest_bidder
    }

    /// How many bids have landed.
    pub fn bid_count(&self) -> u32 {
        self.bid_count
    }

    /// How many anti-sniping extensions have fired.
    pub fn extension_count(&self) -> u16 {
        self.extension_count
    }

    /// `true` while bids are accepted: state is `Bidding` and
    /// `start_slot <= current_slot < end_slot` (the end is strict — a
    /// bid *at* the closing slot is too late).
    pub fn is_live(&self, current_slot: u64) -> bool {
        self.state == AuctionState::Bidding
            && current_slot >= self.start_slot
            && current_slot < self.end_slot
    }

    /// Place a bid.
    ///
    /// Check order: liveness → bidder key → minimum raise →
    /// buy-it-now → anti-sniping. The minimum legal bid is
    /// `highest_bid + min_increment` — for the opening bid that is just
    /// `min_increment`, so the increment doubles as the minimum
    /// opening bid.
    ///
    /// Buy-it-now: when a buyout price is set and a legal bid reaches
    /// it, the auction settles immediately at exactly the buyout price
    /// (the bid is capped — a bidder offering more still pays the
    /// buyout price). The remaining bidding window and any
    /// anti-sniping extension are skipped; the receipt carries
    /// `buyout: true` and the outbid leader for the exact full refund
    /// (the AV-194 deposit path reuses these fields unchanged). The
    /// reserve price needs no separate check here — `with_buyout`
    /// already refused a buyout below it, so a buyout sale always
    /// satisfies the reserve.
    ///
    /// Anti-sniping: when a bid lands within `anti_snipe_window`
    /// slots of `end_slot` and the extension budget is not exhausted,
    /// `end_slot` is pushed out by `anti_snipe_extension` and the
    /// extension is counted.
    ///
    /// Returns a [`BidReceipt`] — the previous leader (for an exact
    /// full refund) and the possibly-extended end slot. The previous
    /// leader's funds are marked *before* the new leader is recorded,
    /// so a re-entrant caller cannot double-spend the lead.
    pub fn place_bid(
        &mut self,
        bidder: [u8; 32],
        amount: u64,
        current_slot: u64,
    ) -> Result<BidReceipt, EscrowError> {
        if !self.is_live(current_slot) {
            return Err(EscrowError::EnglishAuctionNotLive);
        }
        if bidder == [0u8; 32] {
            return Err(EscrowError::InvalidEnglishAuction);
        }
        let minimum = self.highest_bid.saturating_add(self.min_increment);
        if amount < minimum {
            return Err(EscrowError::EnglishAuctionBidTooLow);
        }
        let previous_bidder = self.highest_bidder;
        let previous_bid = self.highest_bid;
        if self.buyout_price > 0 && amount >= self.buyout_price {
            self.highest_bid = self.buyout_price;
            self.highest_bidder = bidder;
            self.bid_count = self.bid_count.saturating_add(1);
            self.state = AuctionState::Settled;
            self.buyout_sale = Some((bidder, self.buyout_price));
            return Ok(BidReceipt {
                previous_bidder,
                previous_bid,
                new_bid: self.buyout_price,
                end_slot: self.end_slot,
                extended: false,
                buyout: true,
            });
        }
        let receipt = BidReceipt {
            previous_bidder: self.highest_bidder,
            previous_bid: self.highest_bid,
            new_bid: amount,
            end_slot: self.end_slot,
            extended: false,
            buyout: false,
        };
        self.highest_bid = amount;
        self.highest_bidder = bidder;
        self.bid_count = self.bid_count.saturating_add(1);
        // Anti-sniping: a bid in the tail pushes the close out.
        let mut receipt = receipt;
        if self.anti_snipe_window > 0
            && self.extension_count < self.max_extensions
            && current_slot.saturating_add(self.anti_snipe_window) >= self.end_slot
        {
            self.end_slot = self.end_slot.saturating_add(self.anti_snipe_extension);
            self.extension_count = self.extension_count.saturating_add(1);
            receipt.extended = true;
            receipt.end_slot = self.end_slot;
        }
        Ok(receipt)
    }

    /// Settle the auction once the bidding window has closed.
    /// Permissionless — anyone may finalize after `end_slot`.
    ///
    /// Refused ([`EscrowError::EnglishAuctionSettleTooEarly`], code
    /// 266) at `current_slot < end_slot`, and
    /// ([`EscrowError::EnglishAuctionNotLive`], code 265) when the
    /// auction is already in a terminal state. The reserve test is
    /// `highest_bid >= reserve_price` — a zero reserve always
    /// succeeds, and a reserve of exactly the winning bid is met
    /// (the seller's floor is inclusive).
    pub fn settle(&mut self, current_slot: u64) -> Result<AuctionSettlement, EscrowError> {
        if self.state != AuctionState::Bidding {
            return Err(EscrowError::EnglishAuctionNotLive);
        }
        if current_slot < self.end_slot {
            return Err(EscrowError::EnglishAuctionSettleTooEarly);
        }
        if self.bid_count == 0 {
            self.state = AuctionState::NoSale;
            return Ok(AuctionSettlement::NoBids);
        }
        if self.highest_bid < self.reserve_price {
            self.state = AuctionState::NoSale;
            return Ok(AuctionSettlement::ReserveNotMet {
                highest_bidder: self.highest_bidder,
                highest_bid: self.highest_bid,
            });
        }
        self.state = AuctionState::Settled;
        Ok(AuctionSettlement::Sold {
            winner: self.highest_bidder,
            winning_bid: self.highest_bid,
        })
    }

    /// The seller cancels the auction — only before the first bid and
    /// only while the window has not lapsed.
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// non-seller caller, and
    /// ([`EscrowError::EnglishAuctionNotCancellable`], code 267) once
    /// any bid has landed, once the auction is already terminal, or
    /// once `end_slot` has passed (settle it instead — cancelling a
    /// lapsed auction would strand the bidders' funds).
    pub fn cancel(&mut self, seller: [u8; 32], current_slot: u64) -> Result<(), EscrowError> {
        if seller != self.seller {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != AuctionState::Bidding
            || self.bid_count > 0
            || current_slot >= self.end_slot
        {
            return Err(EscrowError::EnglishAuctionNotCancellable);
        }
        self.state = AuctionState::Cancelled;
        Ok(())
    }

    /// Audit-event JSON for a bid (hand-written):
    /// `{"event":"english_auction_bid","bidder":"<64hex>","bid":<u64>,
    /// "end_slot":<u64>,"extended":<bool>}`.
    pub fn bid_audit_json(&self, bidder: [u8; 32], bid: u64, extended: bool) -> String {
        let mut s = String::from("{\"event\":\"english_auction_bid\",\"bidder\":\"");
        s.push_str(&hex64(&bidder));
        s.push_str("\",\"bid\":");
        s.push_str(&bid.to_string());
        s.push_str(",\"end_slot\":");
        s.push_str(&self.end_slot.to_string());
        s.push_str(",\"extended\":");
        s.push_str(&extended.to_string());
        s.push('}');
        s
    }

    /// Audit-event JSON for a buy-it-now settlement (hand-written):
    /// `{"event":"english_auction_buyout","bidder":"<64hex>",
    /// "price":<u64>,"previous_bidder":"<64hex>","previous_bid":<u64>}`.
    /// `price` is the buyout price the winner paid (the bid is capped —
    /// offering more does not raise the price); `previous_bidder` /
    /// `previous_bid` name the outbid leader for the exact full refund
    /// (taken from the buyout [`BidReceipt`], since `place_bid`
    /// already recorded the winner on the auction).
    pub fn buyout_audit_json(
        &self,
        bidder: [u8; 32],
        previous_bidder: [u8; 32],
        previous_bid: u64,
    ) -> String {
        let mut s = String::from("{\"event\":\"english_auction_buyout\",\"bidder\":\"");
        s.push_str(&hex64(&bidder));
        s.push_str("\",\"price\":");
        s.push_str(&self.buyout_price.to_string());
        s.push_str(",\"previous_bidder\":\"");
        s.push_str(&hex64(&previous_bidder));
        s.push_str("\",\"previous_bid\":");
        s.push_str(&previous_bid.to_string());
        s.push('}');
        s
    }

    /// Audit-event JSON for a settlement (hand-written):
    /// `{"event":"english_auction_settled","outcome":"sold|no_bids|
    /// reserve_not_met","winner":"<64hex>","winning_bid":<u64>}`.
    pub fn settle_audit_json(&self, settlement: AuctionSettlement) -> String {
        let mut s = String::from("{\"event\":\"english_auction_settled\",\"outcome\":\"");
        let (winner, bid) = match settlement {
            AuctionSettlement::Sold { winner, winning_bid } => {
                s.push_str("sold");
                (winner, winning_bid)
            }
            AuctionSettlement::NoBids => {
                s.push_str("no_bids");
                ([0u8; 32], 0)
            }
            AuctionSettlement::ReserveNotMet { highest_bidder, highest_bid } => {
                s.push_str("reserve_not_met");
                (highest_bidder, highest_bid)
            }
        };
        s.push_str("\",\"winner\":\"");
        s.push_str(&hex64(&winner));
        s.push_str("\",\"winning_bid\":");
        s.push_str(&bid.to_string());
        s.push('}');
        s
    }
}

fn hex64(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes.iter() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod english_auction_tests {
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn open_auction() -> EnglishAuction {
        // No anti-sniping here: seller, [100, 200), min raise 10,
        // reserve 150.
        EnglishAuction::new(key(0xAA), 100, 200, 10, 150, 0, 0, 0).unwrap()
    }

    #[test]
    fn new_rejects_degenerate_auctions() {
        // Zero seller.
        assert_eq!(
            EnglishAuction::new([0u8; 32], 100, 200, 10, 150, 0, 0, 0).unwrap_err(),
            EscrowError::InvalidEnglishAuction
        );
        // Empty bidding window.
        assert_eq!(
            EnglishAuction::new(key(0xAA), 200, 200, 10, 150, 0, 0, 0).unwrap_err(),
            EscrowError::InvalidEnglishAuction
        );
        // Zero minimum increment — the auction could never converge.
        assert_eq!(
            EnglishAuction::new(key(0xAA), 100, 200, 0, 150, 0, 0, 0).unwrap_err(),
            EscrowError::InvalidEnglishAuction
        );
        // Degenerate anti-sniping: a tail window with no extension.
        assert_eq!(
            EnglishAuction::new(key(0xAA), 100, 200, 10, 150, 10, 0, 3).unwrap_err(),
            EscrowError::InvalidEnglishAuction
        );
        // Degenerate anti-sniping: a tail window with no extension budget.
        assert_eq!(
            EnglishAuction::new(key(0xAA), 100, 200, 10, 150, 10, 5, 0).unwrap_err(),
            EscrowError::InvalidEnglishAuction
        );
        // Extension budget above the hard cap.
        assert_eq!(
            EnglishAuction::new(key(0xAA), 100, 200, 10, 150, 10, 5, MAX_SNIPE_EXTENSIONS + 1)
                .unwrap_err(),
            EscrowError::InvalidEnglishAuction
        );
        let err = EscrowError::InvalidEnglishAuction;
        assert_eq!(err.code(), 263);
        assert!(EscrowError::all().contains(&err));
    }

    #[test]
    fn opening_bid_must_clear_min_increment() {
        let mut a = open_auction();
        // Below the minimum opening bid.
        let err = a.place_bid(key(1), 9, 150).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionBidTooLow);
        assert_eq!(err.code(), 264);
        // Exactly the minimum opening bid is accepted.
        let r = a.place_bid(key(1), 10, 150).unwrap();
        assert_eq!(r.previous_bid, 0);
        assert_eq!(r.previous_bidder, [0u8; 32]);
        assert_eq!(r.new_bid, 10);
        assert!(!r.extended);
        assert_eq!(a.highest_bid(), 10);
        assert_eq!(a.highest_bidder(), key(1));
        assert_eq!(a.bid_count(), 1);
    }

    #[test]
    fn each_bid_must_beat_highest_plus_increment() {
        let mut a = open_auction();
        a.place_bid(key(1), 100, 150).unwrap();
        // One under the minimum raise is rejected.
        let err = a.place_bid(key(2), 109, 151).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionBidTooLow);
        // Re-bidding the current highest is rejected too.
        let err = a.place_bid(key(2), 100, 151).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionBidTooLow);
        // Exactly highest + increment clears (boundary).
        let r = a.place_bid(key(2), 110, 151).unwrap();
        assert_eq!(r.previous_bidder, key(1));
        assert_eq!(r.previous_bid, 100);
        assert_eq!(r.new_bid, 110);
        assert_eq!(a.highest_bidder(), key(2));
    }

    #[test]
    fn zero_bidder_is_rejected() {
        let mut a = open_auction();
        let err = a.place_bid([0u8; 32], 50, 150).unwrap_err();
        assert_eq!(err, EscrowError::InvalidEnglishAuction);
        assert_eq!(a.bid_count(), 0);
    }

    #[test]
    fn bids_outside_the_window_are_rejected() {
        let mut a = open_auction();
        // Before the window opens.
        let err = a.place_bid(key(1), 50, 99).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionNotLive);
        assert_eq!(err.code(), 265);
        // At the closing slot (strict end) — too late.
        let err = a.place_bid(key(1), 50, 200).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionNotLive);
        // Past the close.
        let err = a.place_bid(key(1), 50, 201).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionNotLive);
        assert_eq!(a.bid_count(), 0);
    }

    #[test]
    fn anti_sniping_extends_the_close() {
        // Tail window 10 slots, extension 25 slots, budget 2.
        let mut a =
            EnglishAuction::new(key(0xAA), 100, 200, 10, 0, 10, 25, 2).unwrap();
        // Bid far from the tail: no extension.
        let r = a.place_bid(key(1), 100, 150).unwrap();
        assert!(!r.extended);
        assert_eq!(r.end_slot, 200);
        assert_eq!(a.end_slot(), 200);
        // Bid inside the tail window: the close moves out.
        let r = a.place_bid(key(2), 120, 195).unwrap();
        assert!(r.extended);
        assert_eq!(r.end_slot, 225);
        assert_eq!(a.end_slot(), 225);
        assert_eq!(a.extension_count(), 1);
        // Second tail bid burns the last extension.
        let r = a.place_bid(key(3), 140, 220).unwrap();
        assert!(r.extended);
        assert_eq!(a.end_slot(), 250);
        assert_eq!(a.extension_count(), 2);
        // Budget exhausted: the bid still lands, but the close holds.
        let r = a.place_bid(key(4), 160, 245).unwrap();
        assert!(!r.extended);
        assert_eq!(a.end_slot(), 250);
        assert_eq!(a.highest_bidder(), key(4));
    }

    #[test]
    fn settle_rejects_early_close_and_double_settle() {
        let mut a = open_auction();
        a.place_bid(key(1), 200, 150).unwrap();
        // One slot before the close.
        let err = a.settle(199).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionSettleTooEarly);
        assert_eq!(err.code(), 266);
        // At the close: settles to the winner (reserve 150 met).
        let s = a.settle(200).unwrap();
        assert_eq!(
            s,
            AuctionSettlement::Sold {
                winner: key(1),
                winning_bid: 200
            }
        );
        assert_eq!(a.state(), AuctionState::Settled);
        // Settling twice is refused — the auction is terminal.
        let err = a.settle(200).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionNotLive);
        // No more bids after settlement either.
        let err = a.place_bid(key(2), 300, 200).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionNotLive);
    }

    #[test]
    fn settle_with_no_bids_is_no_sale() {
        let mut a = open_auction();
        let s = a.settle(200).unwrap();
        assert_eq!(s, AuctionSettlement::NoBids);
        assert_eq!(a.state(), AuctionState::NoSale);
    }

    #[test]
    fn reserve_not_met_refunds_everyone() {
        let mut a = open_auction(); // reserve 150.
        a.place_bid(key(1), 100, 150).unwrap();
        a.place_bid(key(2), 120, 160).unwrap();
        let s = a.settle(200).unwrap();
        assert_eq!(
            s,
            AuctionSettlement::ReserveNotMet {
                highest_bidder: key(2),
                highest_bid: 120
            }
        );
        assert_eq!(a.state(), AuctionState::NoSale);
        // The audit trail records the no-sale outcome.
        let j = a.settle_audit_json(s);
        assert!(j.contains("\"outcome\":\"reserve_not_met\""));
        assert!(j.contains("\"winning_bid\":120"));
    }

    #[test]
    fn reserve_floor_is_inclusive_and_zero_means_no_reserve() {
        // Winning bid exactly at the reserve: sold.
        let mut a = open_auction(); // reserve 150.
        a.place_bid(key(1), 150, 150).unwrap();
        let s = a.settle(200).unwrap();
        assert!(matches!(s, AuctionSettlement::Sold { .. }));
        // Zero reserve: any winning bid sells.
        let mut b = EnglishAuction::new(key(0xAA), 100, 200, 10, 0, 0, 0, 0).unwrap();
        b.place_bid(key(3), 10, 150).unwrap();
        let s = b.settle(250).unwrap();
        assert_eq!(
            s,
            AuctionSettlement::Sold {
                winner: key(3),
                winning_bid: 10
            }
        );
        let j = b.settle_audit_json(s);
        assert!(j.contains("\"outcome\":\"sold\""));
        assert!(j.contains("\"winning_bid\":10"));
    }

    #[test]
    fn seller_cancels_before_first_bid_only() {
        let mut a = open_auction();
        a.cancel(key(0xAA), 150).unwrap();
        assert_eq!(a.state(), AuctionState::Cancelled);
        // Terminal: nothing more can happen.
        let err = a.place_bid(key(1), 50, 150).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionNotLive);
        let err = a.cancel(key(0xAA), 150).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionNotCancellable);
        assert_eq!(err.code(), 267);
    }

    #[test]
    fn cancel_is_seller_only_and_never_after_bids() {
        let mut a = open_auction();
        // A stranger cannot cancel.
        let err = a.cancel(key(9), 150).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        // After the first bid, even the seller cannot cancel.
        a.place_bid(key(1), 50, 150).unwrap();
        let err = a.cancel(key(0xAA), 150).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionNotCancellable);
        // Cancelling a lapsed auction is refused — settle it instead.
        let mut b = open_auction();
        let err = b.cancel(key(0xAA), 200).unwrap_err();
        assert_eq!(err, EscrowError::EnglishAuctionNotCancellable);
        assert_eq!(b.state(), AuctionState::Bidding);
    }

    #[test]
    fn bid_audit_json_carries_the_receipt() {
        let mut a = open_auction();
        let r = a.place_bid(key(7), 60, 150).unwrap();
        let j = a.bid_audit_json(key(7), 60, r.extended);
        assert!(j.contains("\"event\":\"english_auction_bid\""));
        assert!(j.contains("\"bid\":60"));
        assert!(j.contains("\"end_slot\":200"));
        assert!(j.contains("\"extended\":false"));
        // The bidder key is hex-encoded, never raw bytes.
        assert!(j.contains("0707070707070707070707070707070707070707070707070707070707070707"));
    }

    #[test]
    fn error_codes_pinned() {
        // Never renumber: the Anchor layer assigns one program error
        // per variant and off-chain clients match on these numbers.
        assert_eq!(EscrowError::InvalidEnglishAuction.code(), 263);
        assert_eq!(EscrowError::EnglishAuctionBidTooLow.code(), 264);
        assert_eq!(EscrowError::EnglishAuctionNotLive.code(), 265);
        assert_eq!(EscrowError::EnglishAuctionSettleTooEarly.code(), 266);
        assert_eq!(EscrowError::EnglishAuctionNotCancellable.code(), 267);
        assert_eq!(EscrowError::EnglishAuctionBuyoutLocked.code(), 314);
        for e in [
            EscrowError::InvalidEnglishAuction,
            EscrowError::EnglishAuctionBidTooLow,
            EscrowError::EnglishAuctionNotLive,
            EscrowError::EnglishAuctionSettleTooEarly,
            EscrowError::EnglishAuctionNotCancellable,
            EscrowError::EnglishAuctionBuyoutLocked,
        ] {
            assert!(EscrowError::all().contains(&e));
        }
        // AV-190 appends 3 rental-escrow errors after these.
        assert_eq!(EscrowError::all().len(), 214); // AV-195: +7 social-recovery errors, AV-196: +6 jury-sortition errors, AV-197: +5 payment-channel errors, AV-200: +1, AV-201: +1, AV-203: +1 AV-205: +1; AV-209: +4
    }
}
