//! AV-199: Multi-unit uniform-price sealed-bid auction.
//!
//! The seller auctions `units` homogeneous shares (fungible — one share
//! is as good as another) and every bidder bids a *per-unit* price for
//! exactly one share. Commitments reuse the AV-192 format
//! `SHA-256(bid || nonce || bidder)` (see
//! [`crate::sealed_bid_commitment`]), so the commit/reveal machinery —
//! phases, binding commitments, idempotent reveals — behaves exactly
//! like [`crate::SealedBidAuction`]. What changes is the pricing rule:
//!
//! - **Uniform price**: every winner pays the same clearing price — the
//!   marginal price. Sort the valid revealed bids descending; the
//!   clearing price is the `units`-th bid when demand covers supply, or
//!   the lowest winning bid when the auction is undersubscribed.
//! - **Pro-rata at the margin**: bidders tied *at* the clearing price
//!   split the remaining shares proportionally — each marginal bidder
//!   receives `remaining / tied` shares (a rational
//!   `units_num / units_den`; shares are fungible so fractions are
//!   fine). Bidders above the clearing price take a full share each;
//!   bidders below it get nothing (their deposits are refunded —
//!   commitments carry no funds here, custody stays the Anchor
//!   program's job, AV-194 governs deposits).
//! - **Undersubscribed**: every valid bidder takes one full share at
//!   the clearing price and the unsold shares return to the seller.
//!
//! Orthogonal to AV-192 (single-item, first-price — one winner takes
//! all) and to AV-189 English / AV-97 Dutch (open outcry price
//! discovery): here the price is discovered privately and *shared* by
//! all winners. `Copy`, heap-free, `no_std`-friendly.

use crate::{sealed_bid_commitment, EscrowError};

/// Maximum bidders per multi-unit auction — the book is a fixed array
/// so the crate stays heap-free. A 65th committer finds the auction
/// not live for new commitments ([`EscrowError::MultiUnitNotLive`],
/// code 310).
pub const MAX_MULTI_UNIT_BIDS: usize = 64;

/// Auction lifecycle. `Active` covers both the commit and the reveal
/// phase (see [`MultiUnitPhase`]); the other three are terminal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MultiUnitState {
    /// Not yet settled, cancelled, or failed — commits/reveals may
    /// still land inside their phases.
    #[default]
    Active,
    /// Cleared to the winners at `end_slot`.
    Settled,
    /// No sale: nobody revealed, or no reveal met the minimum bid.
    NoSale,
    /// The seller cancelled before the first commitment (terminal).
    Cancelled,
}

/// The slot-derived phase of an active auction. Commitments land only
/// in [`MultiUnitPhase::Commit`], reveals only in
/// [`MultiUnitPhase::Reveal`]; [`MultiUnitPhase::Closed`] means the
/// reveal window has passed and the auction is ready to settle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiUnitPhase {
    /// `commit_start_slot <= slot < reveal_start_slot`.
    Commit,
    /// `reveal_start_slot <= slot < end_slot`.
    Reveal,
    /// `slot < commit_start_slot` or `slot >= end_slot`.
    Closed,
}

/// One bidder's commitment slot. `Copy` so the book stays a plain
/// fixed-size array.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct MultiUnitSlot {
    bidder: [u8; 32],
    commitment: [u8; 32],
    /// The revealed per-unit bid (`0` until revealed).
    bid: u64,
    /// Slot the reveal landed at (`0` until revealed) — the
    /// deterministic tie-breaker for the sort order.
    reveal_slot: u64,
    revealed: bool,
    occupied: bool,
}

/// The caller's receipt for a successful
/// [`MultiUnitAuction::commit_bid`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MultiUnitCommitReceipt {
    /// The committer's key.
    pub bidder: [u8; 32],
    /// The locked commitment.
    pub commitment: [u8; 32],
}

/// The caller's receipt for a successful
/// [`MultiUnitAuction::reveal_bid`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MultiUnitRevealReceipt {
    /// The revealer's key.
    pub bidder: [u8; 32],
    /// The revealed per-unit bid.
    pub bid: u64,
}

/// One winner's share of the clearing: `units_num / units_den` shares
/// at the uniform clearing price. Bidders above the clearing price
/// always see `1 / 1`; marginal bidders tied at the clearing price see
/// `remaining / tied` (pro-rata); undersubscribed winners see `1 / 1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MultiUnitAllocation {
    /// The winner's key.
    pub bidder: [u8; 32],
    /// Shares allocated, as the rational `units_num / units_den`.
    pub units_num: u64,
    /// Shares allocated, as the rational `units_num / units_den`
    /// (always `>= 1`; never `0`).
    pub units_den: u64,
}

/// What [`MultiUnitAuction::settle`] decided once the reveal window
/// closed. The Anchor program maps `Cleared` to "transfer each
/// winner's shares at `clearing_price` per share, refund the
/// unfilled, return `unsold_units` to the seller" and `NoSale` to
/// "return every share to the seller" (commitments carry no funds —
/// AV-194 deposits aside).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiUnitSettlement {
    /// The auction cleared: every winner pays `clearing_price` per
    /// share. `allocations[..allocation_count]` holds the winners;
    /// `unsold_units` is `0` unless the auction was undersubscribed.
    Cleared {
        clearing_price: u64,
        allocations: [MultiUnitAllocation; MAX_MULTI_UNIT_BIDS],
        allocation_count: u32,
        unsold_units: u64,
    },
    /// Nobody revealed a bid, or no reveal met the minimum bid —
    /// nothing moves except the seller's shares coming home.
    NoSale,
}

/// A multi-unit uniform-price sealed-bid auction: commit-reveal
/// phases over `SHA-256(bid || nonce || bidder)` commitments (the
/// AV-192 format), uniform-price clearing with pro-rata allocation at
/// the margin, a public minimum per-unit bid, and seller-only
/// pre-commit cancellation.
///
/// Construct with [`MultiUnitAuction::new`]. Every bidder bids a
/// per-unit price for exactly one share; the bids stay hidden until
/// the reveal phase — this module only ever stores commitments during
/// the commit phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MultiUnitAuction {
    seller: [u8; 32],
    units: u64,
    min_bid: u64,
    commit_start_slot: u64,
    reveal_start_slot: u64,
    end_slot: u64,
    slots: [MultiUnitSlot; MAX_MULTI_UNIT_BIDS],
    commit_count: u32,
    reveal_count: u32,
    state: MultiUnitState,
}

impl MultiUnitAuction {
    /// Open a multi-unit auction for `units` homogeneous shares.
    ///
    /// Refused (fail-closed, [`EscrowError::InvalidMultiUnit`], code
    /// 309) when the seller key is zero, `units == 0`,
    /// `commit_start_slot >= reveal_start_slot` (an empty commit
    /// window), or `reveal_start_slot >= end_slot` (an empty reveal
    /// window). `min_bid == 0` disables the floor.
    pub fn new(
        seller: [u8; 32],
        units: u64,
        commit_start_slot: u64,
        reveal_start_slot: u64,
        end_slot: u64,
        min_bid: u64,
    ) -> Result<Self, EscrowError> {
        if seller == [0u8; 32]
            || units == 0
            || commit_start_slot >= reveal_start_slot
            || reveal_start_slot >= end_slot
        {
            return Err(EscrowError::InvalidMultiUnit);
        }
        Ok(MultiUnitAuction {
            seller,
            units,
            min_bid,
            commit_start_slot,
            reveal_start_slot,
            end_slot,
            slots: [MultiUnitSlot::default(); MAX_MULTI_UNIT_BIDS],
            commit_count: 0,
            reveal_count: 0,
            state: MultiUnitState::Active,
        })
    }

    /// The slot-derived phase: commitments land only in `Commit`,
    /// reveals only in `Reveal`.
    pub fn phase(&self, current_slot: u64) -> MultiUnitPhase {
        if current_slot < self.commit_start_slot || current_slot >= self.end_slot {
            MultiUnitPhase::Closed
        } else if current_slot < self.reveal_start_slot {
            MultiUnitPhase::Commit
        } else {
            MultiUnitPhase::Reveal
        }
    }

    /// Lock a bid commitment during the commit phase.
    ///
    /// The commitment is `SHA-256(bid || nonce || bidder)` — the exact
    /// AV-192 format ([`crate::sealed_bid_commitment`]); `bid` is the
    /// per-unit price for one share.
    ///
    /// Refused with [`EscrowError::MultiUnitNotLive`] (code 310)
    /// outside the commit phase, on a terminal auction, or when the
    /// book is full (the auction is not live for new commitments),
    /// [`EscrowError::InvalidMultiUnit`] (code 309) for a zero bidder
    /// key or zero commitment, and
    /// [`EscrowError::MultiUnitDuplicateCommit`] (code 311) when this
    /// bidder already committed (one commitment per bidder).
    pub fn commit_bid(
        &mut self,
        bidder: [u8; 32],
        commitment: [u8; 32],
        current_slot: u64,
    ) -> Result<MultiUnitCommitReceipt, EscrowError> {
        if self.state != MultiUnitState::Active || self.phase(current_slot) != MultiUnitPhase::Commit
        {
            return Err(EscrowError::MultiUnitNotLive);
        }
        if bidder == [0u8; 32] || commitment == [0u8; 32] {
            return Err(EscrowError::InvalidMultiUnit);
        }
        if self.find_slot(&bidder).is_some() {
            return Err(EscrowError::MultiUnitDuplicateCommit);
        }
        let free = self.slots.iter().position(|s| !s.occupied);
        match free {
            Some(i) => {
                self.slots[i] = MultiUnitSlot {
                    bidder,
                    commitment,
                    bid: 0,
                    reveal_slot: 0,
                    revealed: false,
                    occupied: true,
                };
                self.commit_count += 1;
                Ok(MultiUnitCommitReceipt { bidder, commitment })
            }
            None => Err(EscrowError::MultiUnitNotLive),
        }
    }

    /// Reveal `(bid, nonce)` during the reveal phase.
    ///
    /// The preimage `SHA-256(bid || nonce || bidder)` must equal the
    /// stored commitment, otherwise the reveal is rejected with
    /// [`EscrowError::MultiUnitRevealMismatch`] (code 312) — a bidder
    /// with no commitment on record lands here too (there is nothing
    /// valid to reveal). Reveals are idempotent for the same
    /// `(bid, nonce)`; a *different* bid after a reveal is rejected as
    /// a mismatch (the commitment already binds exactly one bid).
    /// Phase/terminal violations return
    /// [`EscrowError::MultiUnitNotLive`] (code 310).
    pub fn reveal_bid(
        &mut self,
        bidder: [u8; 32],
        bid: u64,
        nonce: [u8; 32],
        current_slot: u64,
    ) -> Result<MultiUnitRevealReceipt, EscrowError> {
        if self.state != MultiUnitState::Active || self.phase(current_slot) != MultiUnitPhase::Reveal
        {
            return Err(EscrowError::MultiUnitNotLive);
        }
        let idx = match self.find_slot(&bidder) {
            Some(i) => i,
            None => return Err(EscrowError::MultiUnitRevealMismatch),
        };
        let expected = self.slots[idx].commitment;
        if sealed_bid_commitment(&bidder, bid, &nonce) != expected {
            return Err(EscrowError::MultiUnitRevealMismatch);
        }
        if !self.slots[idx].revealed {
            self.slots[idx].bid = bid;
            self.slots[idx].reveal_slot = current_slot;
            self.slots[idx].revealed = true;
            self.reveal_count += 1;
        }
        Ok(MultiUnitRevealReceipt { bidder, bid })
    }

    /// Clear the auction once the reveal window has closed
    /// (`current_slot >= end_slot`).
    ///
    /// Valid revealed bids (at or above `min_bid`) sort descending by
    /// bid, ties to the earliest reveal slot (deterministic, no
    /// randomness needed on-chain). The clearing price is the marginal
    /// price: the `units`-th bid when demand covers supply, the lowest
    /// winning bid when undersubscribed. Bidders above the clearing
    /// price take one full share each; every bidder tied *at* the
    /// clearing price shares the remaining shares pro-rata
    /// (`remaining / tied`); bidders below it get nothing. When fewer
    /// bidders revealed than there are shares, every winner takes one
    /// full share and the rest return to the seller (`unsold_units`).
    /// Reveals below `min_bid` are recorded but cannot win; with no
    /// valid bid the outcome is `NoSale`.
    ///
    /// Refused with [`EscrowError::MultiUnitNotLive`] (code 310)
    /// before `end_slot` and on a terminal auction.
    pub fn settle(&mut self, current_slot: u64) -> Result<MultiUnitSettlement, EscrowError> {
        if self.state != MultiUnitState::Active {
            return Err(EscrowError::MultiUnitNotLive);
        }
        if current_slot < self.end_slot {
            return Err(EscrowError::MultiUnitNotLive);
        }
        // Insertion sort over slot indices: bid descending, then
        // earliest reveal slot. Fixed-size, heap-free.
        let mut order = [0usize; MAX_MULTI_UNIT_BIDS];
        let mut valid = 0usize;
        for (i, s) in self.slots.iter().enumerate() {
            if !(s.occupied && s.revealed) {
                continue;
            }
            if self.min_bid > 0 && s.bid < self.min_bid {
                continue;
            }
            let mut j = valid;
            while j > 0 {
                let o = order[j - 1];
                let os = &self.slots[o];
                let before = s.bid > os.bid
                    || (s.bid == os.bid && s.reveal_slot < os.reveal_slot);
                if !before {
                    break;
                }
                order[j] = o;
                j -= 1;
            }
            order[j] = i;
            valid += 1;
        }
        if valid == 0 {
            self.state = MultiUnitState::NoSale;
            return Ok(MultiUnitSettlement::NoSale);
        }
        let take = (self.units as usize).min(valid);
        let clearing_price = self.slots[order[take - 1]].bid;
        let mut allocations = [MultiUnitAllocation::default(); MAX_MULTI_UNIT_BIDS];
        let allocation_count: u32;
        if valid < self.units as usize {
            // Undersubscribed: every valid bidder takes one full
            // share; the rest go home to the seller.
            for k in 0..valid {
                let s = &self.slots[order[k]];
                allocations[k] = MultiUnitAllocation {
                    bidder: s.bidder,
                    units_num: 1,
                    units_den: 1,
                };
            }
            allocation_count = valid as u32;
            self.state = MultiUnitState::Settled;
            return Ok(MultiUnitSettlement::Cleared {
                clearing_price,
                allocations,
                allocation_count,
                unsold_units: self.units - valid as u64,
            });
        }
        // Demand covers supply: bidders above the clearing price take a
        // full share each; every bidder tied at the clearing price
        // splits the remaining shares pro-rata.
        let mut full = 0u32;
        let mut tied = 0u32;
        for k in 0..valid {
            let b = self.slots[order[k]].bid;
            if b > clearing_price {
                full += 1;
            } else if b == clearing_price {
                tied += 1;
            }
        }
        let remaining = self.units - full as u64;
        let mut n = 0usize;
        for k in 0..valid {
            let s = &self.slots[order[k]];
            if s.bid > clearing_price {
                allocations[n] = MultiUnitAllocation {
                    bidder: s.bidder,
                    units_num: 1,
                    units_den: 1,
                };
                n += 1;
            } else if s.bid == clearing_price {
                allocations[n] = MultiUnitAllocation {
                    bidder: s.bidder,
                    units_num: remaining,
                    units_den: tied as u64,
                };
                n += 1;
            }
        }
        allocation_count = n as u32;
        self.state = MultiUnitState::Settled;
        Ok(MultiUnitSettlement::Cleared {
            clearing_price,
            allocations,
            allocation_count,
            unsold_units: 0,
        })
    }

    /// Cancel the auction. Seller-only
    /// ([`EscrowError::Unauthorized`], code 100, for anyone else) and
    /// only before the first commitment lands and while the commit
    /// phase is still open ([`EscrowError::MultiUnitNotLive`], code
    /// 310 otherwise — a lapsed or committed auction is settled, not
    /// cancelled, so no bidder's position is stranded).
    pub fn cancel(&mut self, caller: [u8; 32], current_slot: u64) -> Result<(), EscrowError> {
        if caller != self.seller {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != MultiUnitState::Active
            || self.commit_count > 0
            || current_slot >= self.reveal_start_slot
        {
            return Err(EscrowError::MultiUnitNotLive);
        }
        self.state = MultiUnitState::Cancelled;
        Ok(())
    }

    /// Audit-event JSON for a commitment (hand-written):
    /// `{"event":"multi_unit_commit","bidder":"<64hex>","commitment":
    /// "<64hex>","units":<u64>,"reveal_start_slot":<u64>}`.
    pub fn commit_audit_json(&self, bidder: [u8; 32], commitment: [u8; 32]) -> String {
        let mut s = String::from("{\"event\":\"multi_unit_commit\",\"bidder\":\"");
        s.push_str(&hex64(&bidder));
        s.push_str("\",\"commitment\":\"");
        s.push_str(&hex64(&commitment));
        s.push_str("\",\"units\":");
        s.push_str(&self.units.to_string());
        s.push_str(",\"reveal_start_slot\":");
        s.push_str(&self.reveal_start_slot.to_string());
        s.push('}');
        s
    }

    /// Audit-event JSON for a reveal (hand-written):
    /// `{"event":"multi_unit_reveal","bidder":"<64hex>","bid":<u64>}`.
    /// The nonce is never logged — it stays secret until the program
    /// needs it (and after reveal it is public on-chain anyway).
    pub fn reveal_audit_json(&self, bidder: [u8; 32], bid: u64) -> String {
        let mut s = String::from("{\"event\":\"multi_unit_reveal\",\"bidder\":\"");
        s.push_str(&hex64(&bidder));
        s.push_str("\",\"bid\":");
        s.push_str(&bid.to_string());
        s.push('}');
        s
    }

    /// Audit-event JSON for a settlement (hand-written):
    /// `{"event":"multi_unit_cleared","outcome":"cleared|no_sale",
    /// "clearing_price":<u64>,"winners":<u32>,"unsold_units":<u64>}`.
    pub fn settle_audit_json(&self, settlement: &MultiUnitSettlement) -> String {
        let mut s = String::from("{\"event\":\"multi_unit_cleared\",\"outcome\":\"");
        let (price, winners, unsold) = match settlement {
            MultiUnitSettlement::Cleared {
                clearing_price,
                allocation_count,
                unsold_units,
                ..
            } => {
                s.push_str("cleared");
                (*clearing_price, *allocation_count, *unsold_units)
            }
            MultiUnitSettlement::NoSale => {
                s.push_str("no_sale");
                (0, 0, self.units)
            }
        };
        s.push_str("\",\"clearing_price\":");
        s.push_str(&price.to_string());
        s.push_str(",\"winners\":");
        s.push_str(&winners.to_string());
        s.push_str(",\"unsold_units\":");
        s.push_str(&unsold.to_string());
        s.push('}');
        s
    }

    fn find_slot(&self, bidder: &[u8; 32]) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.occupied && &s.bidder == bidder)
    }

    /// The seller's key.
    pub fn seller(&self) -> [u8; 32] {
        self.seller
    }

    /// Homogeneous shares on offer.
    pub fn units(&self) -> u64 {
        self.units
    }

    /// The public minimum per-unit bid (`0` = no floor).
    pub fn min_bid(&self) -> u64 {
        self.min_bid
    }

    /// Lifecycle state.
    pub fn state(&self) -> MultiUnitState {
        self.state
    }

    /// Commitments locked so far.
    pub fn commit_count(&self) -> u32 {
        self.commit_count
    }

    /// Valid reveals so far.
    pub fn reveal_count(&self) -> u32 {
        self.reveal_count
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
mod multi_unit_tests {
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn nonce(b: u8) -> [u8; 32] {
        [b.wrapping_add(0x80); 32]
    }

    /// 4 shares, commit window [100, 200), reveal window [200, 300).
    fn open_auction() -> MultiUnitAuction {
        MultiUnitAuction::new(key(0xAA), 4, 100, 200, 300, 10).unwrap()
    }

    fn commit(
        a: &mut MultiUnitAuction,
        bidder: [u8; 32],
        bid: u64,
        nonce: [u8; 32],
        slot: u64,
    ) -> MultiUnitCommitReceipt {
        let c = sealed_bid_commitment(&bidder, bid, &nonce);
        a.commit_bid(bidder, c, slot).unwrap()
    }

    fn reveal(a: &mut MultiUnitAuction, bidder: [u8; 32], bid: u64, nonce: [u8; 32], slot: u64) {
        a.reveal_bid(bidder, bid, nonce, slot).unwrap();
    }

    fn cleared(a: &mut MultiUnitAuction) -> (u64, Vec<([u8; 32], u64, u64)>, u64) {
        match a.settle(300).unwrap() {
            MultiUnitSettlement::Cleared {
                clearing_price,
                allocations,
                allocation_count,
                unsold_units,
            } => {
                let allocs = allocations[..allocation_count as usize]
                    .iter()
                    .map(|x| (x.bidder, x.units_num, x.units_den))
                    .collect();
                (clearing_price, allocs, unsold_units)
            }
            MultiUnitSettlement::NoSale => panic!("expected Cleared"),
        }
    }

    #[test]
    fn new_rejects_bad_config() {
        // Zero seller.
        assert_eq!(
            MultiUnitAuction::new([0u8; 32], 4, 100, 200, 300, 0).unwrap_err(),
            EscrowError::InvalidMultiUnit
        );
        // Zero units.
        assert_eq!(
            MultiUnitAuction::new(key(0xAA), 0, 100, 200, 300, 0).unwrap_err(),
            EscrowError::InvalidMultiUnit
        );
        // Empty commit window.
        assert_eq!(
            MultiUnitAuction::new(key(0xAA), 4, 200, 200, 300, 0).unwrap_err(),
            EscrowError::InvalidMultiUnit
        );
        // Empty reveal window.
        assert_eq!(
            MultiUnitAuction::new(key(0xAA), 4, 100, 300, 300, 0).unwrap_err(),
            EscrowError::InvalidMultiUnit
        );
        assert_eq!(EscrowError::InvalidMultiUnit.code(), 309);
    }

    #[test]
    fn uniform_price_top_bidders_win_at_marginal_price() {
        let mut a = open_auction(); // 4 shares, floor 10
        commit(&mut a, key(1), 100, nonce(1), 100);
        commit(&mut a, key(2), 90, nonce(2), 110);
        commit(&mut a, key(3), 80, nonce(3), 120);
        commit(&mut a, key(4), 70, nonce(4), 130);
        commit(&mut a, key(5), 60, nonce(5), 140);
        for (i, b) in [1u8, 2, 3, 4, 5].iter().enumerate() {
            reveal(&mut a, key(*b), [100, 90, 80, 70, 60][i], nonce(*b), 200 + i as u64);
        }
        let (price, allocs, unsold) = cleared(&mut a);
        // Clearing price = 4th bid = 70; top 4 each take one full share
        // at 70 — uniform price, nobody pays their own bid.
        assert_eq!(price, 70);
        assert_eq!(unsold, 0);
        assert_eq!(allocs.len(), 4);
        for (bidder, num, den) in allocs {
            assert!([key(1), key(2), key(3), key(4)].contains(&bidder));
            assert_eq!((num, den), (1, 1));
        }
        assert_eq!(a.state(), MultiUnitState::Settled);
    }

    #[test]
    fn marginal_tie_splits_pro_rata() {
        let mut a = open_auction(); // 4 shares
        commit(&mut a, key(1), 100, nonce(1), 100);
        commit(&mut a, key(2), 80, nonce(2), 110);
        commit(&mut a, key(3), 80, nonce(3), 120);
        commit(&mut a, key(4), 80, nonce(4), 130);
        commit(&mut a, key(5), 70, nonce(5), 140);
        reveal(&mut a, key(1), 100, nonce(1), 200);
        reveal(&mut a, key(2), 80, nonce(2), 201);
        reveal(&mut a, key(3), 80, nonce(3), 202);
        reveal(&mut a, key(4), 80, nonce(4), 203);
        reveal(&mut a, key(5), 70, nonce(5), 204);
        let (price, allocs, unsold) = cleared(&mut a);
        // Clearing price 80. Bidder 1 takes 1 full share; the three
        // 80-bidders split the remaining 3 shares pro-rata: 3/3 each.
        // (Bidder 5 at 70 is below the clearing price: nothing.)
        assert_eq!(price, 80);
        assert_eq!(unsold, 0);
        assert_eq!(allocs.len(), 4);
        assert!(allocs.contains(&(key(1), 1, 1)));
        assert!(allocs.contains(&(key(2), 3, 3)));
        assert!(allocs.contains(&(key(3), 3, 3)));
        assert!(allocs.contains(&(key(4), 3, 3)));
    }

    #[test]
    fn pro_rata_fractions_sum_to_remaining_shares() {
        let mut a = MultiUnitAuction::new(key(0xAA), 3, 100, 200, 300, 0).unwrap();
        commit(&mut a, key(1), 100, nonce(1), 100);
        commit(&mut a, key(2), 80, nonce(2), 110);
        commit(&mut a, key(3), 80, nonce(3), 120);
        commit(&mut a, key(4), 80, nonce(4), 130);
        reveal(&mut a, key(1), 100, nonce(1), 200);
        reveal(&mut a, key(2), 80, nonce(2), 201);
        reveal(&mut a, key(3), 80, nonce(3), 202);
        reveal(&mut a, key(4), 80, nonce(4), 203);
        let (price, allocs, _) = cleared(&mut a);
        // 3 shares: bidder 1 takes 1; three 80-bidders split the
        // remaining 2 → 2/3 each. Sum: 1 + 3*(2/3) = 3 exactly.
        assert_eq!(price, 80);
        assert!(allocs.contains(&(key(1), 1, 1)));
        for b in [key(2), key(3), key(4)] {
            assert!(allocs.contains(&(b, 2, 3)), "missing {:?}", &b[..2]);
        }
        let full: u64 = allocs.iter().filter(|(_, n, d)| *n == *d).map(|(_, n, _)| n).sum();
        assert_eq!(full, 1);
    }

    #[test]
    fn undersubscribed_everyone_takes_one_share() {
        let mut a = MultiUnitAuction::new(key(0xAA), 5, 100, 200, 300, 0).unwrap();
        commit(&mut a, key(1), 100, nonce(1), 100);
        commit(&mut a, key(2), 60, nonce(2), 110);
        reveal(&mut a, key(1), 100, nonce(1), 200);
        reveal(&mut a, key(2), 60, nonce(2), 201);
        let (price, allocs, unsold) = cleared(&mut a);
        // Clearing price = lowest winning bid = 60; both take a full
        // share; 3 shares return to the seller.
        assert_eq!(price, 60);
        assert_eq!(allocs.len(), 2);
        assert!(allocs.contains(&(key(1), 1, 1)));
        assert!(allocs.contains(&(key(2), 1, 1)));
        assert_eq!(unsold, 3);
    }

    #[test]
    fn min_bid_floor_excludes_cheap_reveals() {
        let mut a = open_auction(); // floor 10
        commit(&mut a, key(1), 5, nonce(1), 100);
        commit(&mut a, key(2), 50, nonce(2), 110);
        reveal(&mut a, key(1), 5, nonce(1), 200);
        reveal(&mut a, key(2), 50, nonce(2), 201);
        let (price, allocs, unsold) = cleared(&mut a);
        // Bidder 1's reveal is recorded but below the floor: only
        // bidder 2 wins, one full share at 50, 3 unsold.
        assert_eq!(price, 50);
        assert_eq!(allocs, vec![(key(2), 1, 1)]);
        assert_eq!(unsold, 3);
    }

    #[test]
    fn no_valid_reveals_is_no_sale() {
        let mut a = open_auction();
        commit(&mut a, key(1), 5, nonce(1), 100); // below the floor
        reveal(&mut a, key(1), 5, nonce(1), 200);
        assert_eq!(a.settle(300).unwrap(), MultiUnitSettlement::NoSale);
        assert_eq!(a.state(), MultiUnitState::NoSale);
        // And with no reveals at all.
        let mut b = open_auction();
        commit(&mut b, key(1), 50, nonce(1), 100);
        assert_eq!(b.settle(300).unwrap(), MultiUnitSettlement::NoSale);
    }

    #[test]
    fn commitment_format_is_shared_with_av192() {
        // The multi-unit commitment is byte-identical to the AV-192
        // sealed-bid commitment for the same inputs: one format, one
        // audit trail, no second preimage discipline to review.
        let via_sealed = sealed_bid_commitment(&key(1), 42, &nonce(1));
        let mut preimage = [0u8; 72];
        preimage[..8].copy_from_slice(&42u64.to_le_bytes());
        preimage[8..40].copy_from_slice(&nonce(1));
        preimage[40..72].copy_from_slice(&key(1));
        assert_eq!(via_sealed, crate::sha256(&preimage));
        // A reveal through the multi-unit path verifies against it.
        let mut a = open_auction();
        a.commit_bid(key(1), via_sealed, 100).unwrap();
        a.reveal_bid(key(1), 42, nonce(1), 200).unwrap();
        assert_eq!(a.reveal_count(), 1);
    }

    #[test]
    fn wrong_preimage_fails_reveal() {
        let mut a = open_auction();
        commit(&mut a, key(1), 50, nonce(1), 100);
        let err = a.reveal_bid(key(1), 50, nonce(9), 200).unwrap_err();
        assert_eq!(err, EscrowError::MultiUnitRevealMismatch);
        let err = a.reveal_bid(key(1), 51, nonce(1), 200).unwrap_err();
        assert_eq!(err, EscrowError::MultiUnitRevealMismatch);
        assert_eq!(err.code(), 312);
        // No commitment on record either.
        let err = a.reveal_bid(key(7), 50, nonce(7), 200).unwrap_err();
        assert_eq!(err, EscrowError::MultiUnitRevealMismatch);
        assert_eq!(a.reveal_count(), 0);
    }

    #[test]
    fn duplicate_commit_rejected() {
        let mut a = open_auction();
        commit(&mut a, key(1), 50, nonce(1), 100);
        let c = sealed_bid_commitment(&key(1), 60, &nonce(2));
        let err = a.commit_bid(key(1), c, 110).unwrap_err();
        assert_eq!(err, EscrowError::MultiUnitDuplicateCommit);
        assert_eq!(err.code(), 311);
        assert_eq!(a.commit_count(), 1);
    }

    #[test]
    fn phase_violations_are_not_live() {
        let mut a = open_auction();
        let c = sealed_bid_commitment(&key(1), 50, &nonce(1));
        let err = a.commit_bid(key(1), c, 99).unwrap_err();
        assert_eq!(err, EscrowError::MultiUnitNotLive);
        let err = a.commit_bid(key(1), c, 200).unwrap_err();
        assert_eq!(err, EscrowError::MultiUnitNotLive);
        commit(&mut a, key(1), 50, nonce(1), 100);
        let err = a.reveal_bid(key(1), 50, nonce(1), 150).unwrap_err();
        assert_eq!(err, EscrowError::MultiUnitNotLive);
        assert_eq!(err.code(), 310);
        // Settle before the reveal window closes.
        let err = a.settle(299).unwrap_err();
        assert_eq!(err, EscrowError::MultiUnitNotLive);
    }

    #[test]
    fn terminal_auction_rejects_everything() {
        let mut a = open_auction();
        commit(&mut a, key(1), 50, nonce(1), 100);
        reveal(&mut a, key(1), 50, nonce(1), 200);
        a.settle(300).unwrap();
        let c = sealed_bid_commitment(&key(2), 60, &nonce(2));
        assert_eq!(
            a.commit_bid(key(2), c, 100).unwrap_err(),
            EscrowError::MultiUnitNotLive
        );
        assert_eq!(
            a.reveal_bid(key(2), 60, nonce(2), 200).unwrap_err(),
            EscrowError::MultiUnitNotLive
        );
        assert_eq!(a.settle(400).unwrap_err(), EscrowError::MultiUnitNotLive);
    }

    #[test]
    fn book_full_is_not_live_for_new_commits() {
        let mut a = open_auction();
        for i in 0..MAX_MULTI_UNIT_BIDS {
            let mut bidder = [i as u8; 32];
            if bidder == [0u8; 32] {
                bidder = [0xFF; 32];
            }
            let c = sealed_bid_commitment(&bidder, 50 + i as u64, &nonce(i as u8));
            a.commit_bid(bidder, c, 100).unwrap();
        }
        assert_eq!(a.commit_count(), MAX_MULTI_UNIT_BIDS as u32);
        let c = sealed_bid_commitment(&key(0x42), 99, &nonce(0x42));
        let err = a.commit_bid(key(0x42), c, 100).unwrap_err();
        assert_eq!(err, EscrowError::MultiUnitNotLive);
    }

    #[test]
    fn cancel_is_seller_only_and_never_after_commit() {
        let mut a = open_auction();
        let err = a.cancel(key(9), 100).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        commit(&mut a, key(1), 50, nonce(1), 100);
        let err = a.cancel(key(0xAA), 150).unwrap_err();
        assert_eq!(err, EscrowError::MultiUnitNotLive);
        let mut b = open_auction();
        let err = b.cancel(key(0xAA), 200).unwrap_err();
        assert_eq!(err, EscrowError::MultiUnitNotLive);
        assert_eq!(b.state(), MultiUnitState::Active);
        let mut c = open_auction();
        c.cancel(key(0xAA), 100).unwrap();
        assert_eq!(c.state(), MultiUnitState::Cancelled);
    }

    #[test]
    fn audit_json_carries_commit_reveal_settle() {
        let mut a = open_auction();
        let c = commit(&mut a, key(7), 60, nonce(7), 100).commitment;
        let j = a.commit_audit_json(key(7), c);
        assert!(j.contains("\"event\":\"multi_unit_commit\""));
        assert!(j.contains("\"units\":4"));
        assert!(j.contains("\"reveal_start_slot\":200"));
        let j = a.reveal_audit_json(key(7), 60);
        assert!(j.contains("\"event\":\"multi_unit_reveal\""));
        assert!(j.contains("\"bid\":60"));
        assert!(!j.contains("8787878787878787878787878787878787878787878787878787878787878787"));
        reveal(&mut a, key(7), 60, nonce(7), 200);
        let s = a.settle(300).unwrap();
        let j = a.settle_audit_json(&s);
        assert!(j.contains("\"event\":\"multi_unit_cleared\""));
        assert!(j.contains("\"outcome\":\"cleared\""));
        assert!(j.contains("\"clearing_price\":60"));
        assert!(j.contains("\"winners\":1"));
        assert!(j.contains("\"unsold_units\":3"));
    }

    #[test]
    fn error_codes_pinned() {
        // Never renumber: the Anchor layer assigns one program error
        // per variant and off-chain clients match on these numbers.
        // AV-199 appends 4 multi-unit errors after AV-198's
        // StreamNotPaused (308).
        assert_eq!(EscrowError::InvalidMultiUnit.code(), 309);
        assert_eq!(EscrowError::MultiUnitNotLive.code(), 310);
        assert_eq!(EscrowError::MultiUnitDuplicateCommit.code(), 311);
        assert_eq!(EscrowError::MultiUnitRevealMismatch.code(), 312);
    }
}
