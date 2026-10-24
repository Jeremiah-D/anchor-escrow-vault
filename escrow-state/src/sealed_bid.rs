//! AV-192: Sealed-bid auction — commit-reveal dark auction.
//!
//! The seller lists an asset and bidders submit *hidden* bids: during the
//! commit phase each bidder locks a `SHA-256(bid || nonce || bidder)`
//! commitment (see [`sealed_bid_commitment`]); during the reveal phase
//! they disclose `(bid, nonce)` and the commitment is verified. The
//! highest *validly revealed* bid wins first-price — nobody learns a
//! rival's bid until the reveal phase, so there is no bid shading or
//! last-second sniping on price. AV-200 adds an opt-in Vickrey
//! (second-price) mode: the winner still pays the second-highest
//! revealed bid, for the classic truthful-bidding incentive.
//!
//! Two classic sealed-bid rules are built in:
//!
//! - **Binding commitments**: the bidder key is part of the preimage, so
//!   a commitment cannot be copied and revealed by a different bidder.
//!   A reveal whose preimage does not verify is rejected, and an
//!   unrevealed commitment simply drops out of contention (it never
//!   blocks settlement).
//! - **Minimum bid**: the seller's public floor. Valid reveals below it
//!   are recorded but cannot win; if the highest valid bid never reaches
//!   it the sale fails and every bidder walks away (reserve-not-met).
//!
//! Orthogonal to AV-189 English (ascending, *open* bids — the price
//! rises in public) and AV-97 Dutch (descending price — the price falls
//! until someone takes it): here the price is discovered *privately* and
//! paid first-price. Orthogonal to AV-137 (commit-reveal for *arbitration
//! votes* — the preimage there binds a judgment amount and rationale,
//! here it binds an auction bid and bidder). Orthogonal to AV-194
//! (opt-in bid *deposits* with confiscation on no-reveal): this module
//! tracks commitments, not funds — custody and deposits stay the Anchor
//! program's job. `Copy`, heap-free, `no_std`-friendly.

use crate::EscrowError;

/// Maximum commitments per auction — the book is a fixed array so the
/// crate stays heap-free. A 65th committer is refused fail-closed
/// ([`EscrowError::SealedBidBookFull`], code 278).
pub const MAX_SEALED_BIDS: usize = 64;

/// Auction lifecycle. `Active` covers both the commit and the reveal
/// phase (see [`SealedBidPhase`]); the other three are terminal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SealedBidState {
    /// Not yet settled, cancelled, or failed — commits/reveals may
    /// still land inside their phases.
    #[default]
    Active,
    /// Settled to the winner at `end_slot`.
    Settled,
    /// No sale: nobody revealed, or the minimum bid was not met.
    NoSale,
    /// The seller cancelled before the first commitment (terminal).
    Cancelled,
}

/// The slot-derived phase of an active auction. Commitments land only
/// in [`SealedBidPhase::Commit`], reveals only in
/// [`SealedBidPhase::Reveal`]; [`SealedBidPhase::Closed`] means the
/// reveal window has passed and the auction is ready to settle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedBidPhase {
    /// `commit_start_slot <= slot < reveal_start_slot`.
    Commit,
    /// `reveal_start_slot <= slot < end_slot`.
    Reveal,
    /// `slot < commit_start_slot` or `slot >= end_slot`.
    Closed,
}

/// The pricing rule [`SealedBidAuction::settle`] applies once the
/// reveal window closes.
///
/// [`SealedBidPricing::FirstPrice`] (the default) is the classic
/// sealed-bid rule: the highest validly revealed bid wins and pays its
/// own bid. [`SealedBidPricing::Vickrey`] is the second-price rule: the
/// highest validly revealed bid still wins, but the winner pays the
/// *second-highest* revealed bid — the classic truthful-bidding
/// incentive (a bidder's best strategy is to reveal their true value,
/// since the price they pay is set by someone else's bid).
///
/// The mode is fixed before the first commitment lands (see
/// [`SealedBidAuction::with_vickrey`]) — changing the pricing rule
/// after bidders have committed would rewrite the game they entered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SealedBidPricing {
    /// Winner pays their own bid.
    #[default]
    FirstPrice,
    /// Winner pays the second-highest revealed bid (their own bid when
    /// alone), clamped up to the minimum bid.
    Vickrey,
}

/// What [`SealedBidAuction::settle`] decided once the reveal window
/// closed. The Anchor program maps `Sold` to "transfer the asset to the
/// winner" and `NoBids` / `ReserveNotMet` to "return the asset to the
/// seller" (commitments carry no funds — AV-194 deposits aside).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedBidSettlement {
    /// A winner exists: `(winner, winning_bid)` — first-price, highest
    /// validly revealed bid; ties break to the earliest reveal.
    /// Under [`SealedBidPricing::Vickrey`] `winning_bid` is the price
    /// *paid*: the second-highest revealed bid (the winner's own bid
    /// when they are the only revealer), clamped up to the minimum
    /// bid — never below the seller's public floor.
    Sold {
        winner: [u8; 32],
        winning_bid: u64,
    },
    /// Nobody revealed a bid — nothing moves except the seller's asset
    /// coming home.
    NoBids,
    /// Reveals happened but the highest valid bid is under the minimum
    /// bid: `(highest_bidder, highest_bid)`.
    ReserveNotMet {
        highest_bidder: [u8; 32],
        highest_bid: u64,
    },
}

/// One bidder's commitment slot. `Copy` so the book stays a plain
/// fixed-size array.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SealedBidSlot {
    bidder: [u8; 32],
    commitment: [u8; 32],
    /// The revealed bid (`0` until revealed).
    bid: u64,
    /// Slot the reveal landed at (`0` until revealed) — the
    /// deterministic tie-breaker.
    reveal_slot: u64,
    revealed: bool,
    occupied: bool,
}

/// The caller's receipt for a successful
/// [`SealedBidAuction::commit_bid`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedBidCommitReceipt {
    /// The committer's key.
    pub bidder: [u8; 32],
    /// The locked commitment.
    pub commitment: [u8; 32],
}

/// The caller's receipt for a successful
/// [`SealedBidAuction::reveal_bid`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedBidRevealReceipt {
    /// The revealer's key.
    pub bidder: [u8; 32],
    /// The revealed bid.
    pub bid: u64,
}

/// The sealed-bid commitment: `SHA-256(bid || nonce || bidder)` with
/// fixed-width little-endian encoding (`bid` as 8 bytes LE, `nonce` as
/// 32 bytes, `bidder` as 32 bytes — 72 bytes total, the same 72-byte
/// layout discipline as AV-137's [`crate::blind_commitment`]).
///
/// Binding the bidder key into the preimage stops commitment copying: a
/// rival who front-runs someone else's commitment bytes cannot reveal
/// them, because the reveal is verified against *their own* key.
pub fn sealed_bid_commitment(bidder: &[u8; 32], bid: u64, nonce: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 72];
    preimage[..8].copy_from_slice(&bid.to_le_bytes());
    preimage[8..40].copy_from_slice(nonce);
    preimage[40..72].copy_from_slice(bidder);
    crate::sha256(&preimage)
}

/// A sealed-bid auction: commit-reveal phases, first-price settlement,
/// a public minimum bid, and seller-only pre-commit cancellation.
///
/// Construct with [`SealedBidAuction::new`]. The bids themselves stay
/// hidden until the reveal phase — this module only ever stores
/// commitments during the commit phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedBidAuction {
    seller: [u8; 32],
    min_bid: u64,
    commit_start_slot: u64,
    reveal_start_slot: u64,
    end_slot: u64,
    /// The pricing rule `settle` applies — fixed before the first
    /// commitment (see [`SealedBidAuction::with_vickrey`]).
    pricing: SealedBidPricing,
    slots: [SealedBidSlot; MAX_SEALED_BIDS],
    commit_count: u32,
    reveal_count: u32,
    state: SealedBidState,
}

impl SealedBidAuction {
    /// Open a sealed-bid auction.
    ///
    /// Refused (fail-closed, [`EscrowError::InvalidSealedBid`], code
    /// 272) when the seller key is zero, `commit_start_slot >=
    /// reveal_start_slot` (an empty commit window), or
    /// `reveal_start_slot >= end_slot` (an empty reveal window).
    /// `min_bid == 0` disables the floor.
    pub fn new(
        seller: [u8; 32],
        commit_start_slot: u64,
        reveal_start_slot: u64,
        end_slot: u64,
        min_bid: u64,
    ) -> Result<Self, EscrowError> {
        if seller == [0u8; 32]
            || commit_start_slot >= reveal_start_slot
            || reveal_start_slot >= end_slot
        {
            return Err(EscrowError::InvalidSealedBid);
        }
        Ok(SealedBidAuction {
            seller,
            min_bid,
            commit_start_slot,
            reveal_start_slot,
            end_slot,
            pricing: SealedBidPricing::FirstPrice,
            slots: [SealedBidSlot::default(); MAX_SEALED_BIDS],
            commit_count: 0,
            reveal_count: 0,
            state: SealedBidState::Active,
        })
    }

    /// Opt in to Vickrey (second-price) settlement — the highest
    /// validly revealed bid still wins, but the winner pays the
    /// second-highest revealed bid.
    ///
    /// The mode is fixed before the game starts: refused with
    /// [`EscrowError::SealedBidPricingLocked`] (code 313) once the
    /// first commitment has landed or the auction is terminal —
    /// bidders committed under first-price rules and the rule may not
    /// be rewritten underneath them. Calling it twice is a harmless
    /// no-op (the mode is already Vickrey).
    pub fn with_vickrey(mut self) -> Result<Self, EscrowError> {
        if self.state != SealedBidState::Active || self.commit_count > 0 {
            return Err(EscrowError::SealedBidPricingLocked);
        }
        self.pricing = SealedBidPricing::Vickrey;
        Ok(self)
    }

    /// The slot-derived phase: commitments land only in `Commit`,
    /// reveals only in `Reveal`.
    pub fn phase(&self, current_slot: u64) -> SealedBidPhase {
        if current_slot < self.commit_start_slot || current_slot >= self.end_slot {
            SealedBidPhase::Closed
        } else if current_slot < self.reveal_start_slot {
            SealedBidPhase::Commit
        } else {
            SealedBidPhase::Reveal
        }
    }

    /// Lock a bid commitment during the commit phase.
    ///
    /// Refused with [`EscrowError::SealedBidNotLive`] (code 273) outside
    /// the commit phase or on a terminal auction,
    /// [`EscrowError::InvalidSealedBid`] (code 272) for a zero bidder
    /// key or zero commitment,
    /// [`EscrowError::SealedBidDuplicateCommit`] (code 274) when this
    /// bidder already committed (one commitment per bidder — replacing
    /// a commitment would let a bidder narrow the field after seeing
    /// the commitment count), and
    /// [`EscrowError::SealedBidBookFull`] (code 278) past
    /// [`MAX_SEALED_BIDS`] commitments.
    pub fn commit_bid(
        &mut self,
        bidder: [u8; 32],
        commitment: [u8; 32],
        current_slot: u64,
    ) -> Result<SealedBidCommitReceipt, EscrowError> {
        if self.state != SealedBidState::Active || self.phase(current_slot) != SealedBidPhase::Commit
        {
            return Err(EscrowError::SealedBidNotLive);
        }
        if bidder == [0u8; 32] || commitment == [0u8; 32] {
            return Err(EscrowError::InvalidSealedBid);
        }
        if self.find_slot(&bidder).is_some() {
            return Err(EscrowError::SealedBidDuplicateCommit);
        }
        let free = self.slots.iter().position(|s| !s.occupied);
        match free {
            Some(i) => {
                self.slots[i] = SealedBidSlot {
                    bidder,
                    commitment,
                    bid: 0,
                    reveal_slot: 0,
                    revealed: false,
                    occupied: true,
                };
                self.commit_count += 1;
                Ok(SealedBidCommitReceipt { bidder, commitment })
            }
            None => Err(EscrowError::SealedBidBookFull),
        }
    }

    /// Reveal `(bid, nonce)` during the reveal phase.
    ///
    /// The preimage `SHA-256(bid || nonce || bidder)` must equal the
    /// stored commitment, otherwise the reveal is rejected with
    /// [`EscrowError::SealedBidRevealMismatch`] (code 275) — a bidder
    /// with no commitment on record lands here too (there is nothing
    /// valid to reveal). Reveals are idempotent for the same
    /// `(bid, nonce)`; a *different* bid after a reveal is rejected as
    /// a mismatch (the commitment already binds exactly one bid).
    /// Phase/terminal violations return
    /// [`EscrowError::SealedBidNotLive`] (code 273).
    pub fn reveal_bid(
        &mut self,
        bidder: [u8; 32],
        bid: u64,
        nonce: [u8; 32],
        current_slot: u64,
    ) -> Result<SealedBidRevealReceipt, EscrowError> {
        if self.state != SealedBidState::Active || self.phase(current_slot) != SealedBidPhase::Reveal
        {
            return Err(EscrowError::SealedBidNotLive);
        }
        let idx = match self.find_slot(&bidder) {
            Some(i) => i,
            None => return Err(EscrowError::SealedBidRevealMismatch),
        };
        let expected = self.slots[idx].commitment;
        if sealed_bid_commitment(&bidder, bid, &nonce) != expected {
            return Err(EscrowError::SealedBidRevealMismatch);
        }
        if !self.slots[idx].revealed {
            self.slots[idx].bid = bid;
            self.slots[idx].reveal_slot = current_slot;
            self.slots[idx].revealed = true;
            self.reveal_count += 1;
        }
        Ok(SealedBidRevealReceipt { bidder, bid })
    }

    /// Settle the auction once the reveal window has closed
    /// (`current_slot >= end_slot`).
    ///
    /// First-price (the default): the highest validly revealed bid
    /// wins and pays its own bid; ties break to the earliest reveal
    /// slot (deterministic, no randomness needed on-chain). Vickrey
    /// (see [`SealedBidAuction::with_vickrey`]): the highest validly
    /// revealed bid still wins (same tie-break), but the winner pays
    /// the *second-highest* revealed bid — with a single revealer the
    /// winner pays their own bid, and the price is clamped up to
    /// `min_bid` so the seller never receives less than the public
    /// floor. Reveals below `min_bid` cannot win — when the best valid
    /// bid is under the floor the outcome is `ReserveNotMet`.
    /// Unrevealed commitments are simply dropped from contention
    /// (AV-194 governs deposit confiscation for no-reveal).
    ///
    /// Refused with [`EscrowError::SealedBidSettleTooEarly`] (code 276)
    /// before `end_slot` and [`EscrowError::SealedBidNotLive`] (code
    /// 273) on a terminal auction.
    pub fn settle(&mut self, current_slot: u64) -> Result<SealedBidSettlement, EscrowError> {
        if self.state != SealedBidState::Active {
            return Err(EscrowError::SealedBidNotLive);
        }
        if current_slot < self.end_slot {
            return Err(EscrowError::SealedBidSettleTooEarly);
        }
        // Rank reveals by (bid desc, reveal_slot asc): `first` is the
        // winner candidate, `second` the Vickrey price source.
        let mut first: Option<(u64, u64, [u8; 32])> = None;
        let mut second: Option<u64> = None;
        for s in self.slots.iter().filter(|s| s.occupied && s.revealed) {
            let rank = (s.bid, s.reveal_slot);
            let better_first = match first {
                None => true,
                Some((b, rs, _)) => rank_greater(rank, (b, rs)),
            };
            if better_first {
                second = first.map(|(b, _, _)| b);
                first = Some((s.bid, s.reveal_slot, s.bidder));
            } else {
                let better_second = match second {
                    None => true,
                    Some(b) => rank_greater(rank, (b, u64::MAX)),
                };
                if better_second {
                    second = Some(s.bid);
                }
            }
        }
        let settlement = match first {
            None => {
                self.state = SealedBidState::NoSale;
                SealedBidSettlement::NoBids
            }
            Some((bid, _, bidder)) if self.min_bid > 0 && bid < self.min_bid => {
                self.state = SealedBidState::NoSale;
                SealedBidSettlement::ReserveNotMet {
                    highest_bidder: bidder,
                    highest_bid: bid,
                }
            }
            Some((bid, _, bidder)) => {
                self.state = SealedBidState::Settled;
                let price = match self.pricing {
                    SealedBidPricing::FirstPrice => bid,
                    SealedBidPricing::Vickrey => {
                        let p = second.unwrap_or(bid);
                        if self.min_bid > 0 {
                            p.max(self.min_bid)
                        } else {
                            p
                        }
                    }
                };
                SealedBidSettlement::Sold {
                    winner: bidder,
                    winning_bid: price,
                }
            }
        };
        Ok(settlement)
    }

    /// The pricing rule this auction settles under.
    pub fn pricing(&self) -> SealedBidPricing {
        self.pricing
    }

    /// Cancel the auction. Seller-only
    /// ([`EscrowError::Unauthorized`], code 100, for anyone else) and
    /// only before the first commitment lands and while the commit
    /// phase is still open ([`EscrowError::SealedBidNotCancellable`],
    /// code 277 otherwise — a lapsed or committed auction is settled,
    /// not cancelled, so no bidder's position is stranded).
    pub fn cancel(&mut self, caller: [u8; 32], current_slot: u64) -> Result<(), EscrowError> {
        if caller != self.seller {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != SealedBidState::Active
            || self.commit_count > 0
            || current_slot >= self.reveal_start_slot
        {
            return Err(EscrowError::SealedBidNotCancellable);
        }
        self.state = SealedBidState::Cancelled;
        Ok(())
    }

    /// Audit-event JSON for a commitment (hand-written):
    /// `{"event":"sealed_bid_commit","bidder":"<64hex>","commitment":
    /// "<64hex>","reveal_start_slot":<u64>}`.
    pub fn commit_audit_json(&self, bidder: [u8; 32], commitment: [u8; 32]) -> String {
        let mut s = String::from("{\"event\":\"sealed_bid_commit\",\"bidder\":\"");
        s.push_str(&hex64(&bidder));
        s.push_str("\",\"commitment\":\"");
        s.push_str(&hex64(&commitment));
        s.push_str("\",\"reveal_start_slot\":");
        s.push_str(&self.reveal_start_slot.to_string());
        s.push('}');
        s
    }

    /// Audit-event JSON for a reveal (hand-written):
    /// `{"event":"sealed_bid_reveal","bidder":"<64hex>","bid":<u64>}`.
    /// The nonce is never logged — it stays secret until the program
    /// needs it (and after reveal it is public on-chain anyway).
    pub fn reveal_audit_json(&self, bidder: [u8; 32], bid: u64) -> String {
        let mut s = String::from("{\"event\":\"sealed_bid_reveal\",\"bidder\":\"");
        s.push_str(&hex64(&bidder));
        s.push_str("\",\"bid\":");
        s.push_str(&bid.to_string());
        s.push('}');
        s
    }

    /// Audit-event JSON for a settlement (hand-written):
    /// `{"event":"sealed_bid_settled","outcome":"sold|no_bids|
    /// reserve_not_met","winner":"<64hex>","winning_bid":<u64>,
    /// "pricing":"first_price|vickrey"}`. `winning_bid` is the price
    /// *paid* — the winner's own bid under first-price, the
    /// second-highest revealed bid under Vickrey.
    pub fn settle_audit_json(&self, settlement: SealedBidSettlement) -> String {
        let mut s = String::from("{\"event\":\"sealed_bid_settled\",\"outcome\":\"");
        let (winner, bid) = match settlement {
            SealedBidSettlement::Sold { winner, winning_bid } => {
                s.push_str("sold");
                (winner, winning_bid)
            }
            SealedBidSettlement::NoBids => {
                s.push_str("no_bids");
                ([0u8; 32], 0)
            }
            SealedBidSettlement::ReserveNotMet {
                highest_bidder,
                highest_bid,
            } => {
                s.push_str("reserve_not_met");
                (highest_bidder, highest_bid)
            }
        };
        s.push_str("\",\"winner\":\"");
        s.push_str(&hex64(&winner));
        s.push_str("\",\"winning_bid\":");
        s.push_str(&bid.to_string());
        s.push_str(",\"pricing\":\"");
        s.push_str(match self.pricing {
            SealedBidPricing::FirstPrice => "first_price",
            SealedBidPricing::Vickrey => "vickrey",
        });
        s.push_str("\"}");
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

    /// The public minimum bid (`0` = no floor).
    pub fn min_bid(&self) -> u64 {
        self.min_bid
    }

    /// Lifecycle state.
    pub fn state(&self) -> SealedBidState {
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

/// Ranking order for reveals: higher bid first, ties to the earlier
/// reveal slot. `rank_greater(a, b)` is `true` when `a` outranks `b`.
fn rank_greater(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 > b.0 || (a.0 == b.0 && a.1 < b.1)
}

fn hex64(bytes: &[u8; 32]) -> String {    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes.iter() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod sealed_bid_tests {
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn nonce(b: u8) -> [u8; 32] {
        [b.wrapping_add(0x80); 32]
    }

    /// commit window [100, 200), reveal window [200, 300).
    fn open_auction() -> SealedBidAuction {
        SealedBidAuction::new(key(0xAA), 100, 200, 300, 10).unwrap()
    }

    fn commit(
        a: &mut SealedBidAuction,
        bidder: [u8; 32],
        bid: u64,
        nonce: [u8; 32],
        slot: u64,
    ) -> SealedBidCommitReceipt {
        let c = sealed_bid_commitment(&bidder, bid, &nonce);
        a.commit_bid(bidder, c, slot).unwrap()
    }

    #[test]
    fn new_rejects_bad_windows() {
        assert_eq!(
            SealedBidAuction::new([0u8; 32], 100, 200, 300, 0).unwrap_err(),
            EscrowError::InvalidSealedBid
        );
        // Empty commit window.
        assert_eq!(
            SealedBidAuction::new(key(0xAA), 200, 200, 300, 0).unwrap_err(),
            EscrowError::InvalidSealedBid
        );
        // Empty reveal window.
        assert_eq!(
            SealedBidAuction::new(key(0xAA), 100, 300, 300, 0).unwrap_err(),
            EscrowError::InvalidSealedBid
        );
        assert_eq!(EscrowError::InvalidSealedBid.code(), 272);
    }

    #[test]
    fn full_cycle_highest_revealed_bid_wins_first_price() {
        let mut a = open_auction();
        commit(&mut a, key(1), 50, nonce(1), 100);
        commit(&mut a, key(2), 90, nonce(2), 120);
        commit(&mut a, key(3), 70, nonce(3), 150);
        assert_eq!(a.commit_count(), 3);
        assert_eq!(a.reveal_count(), 0);
        // Only two reveal; the third commitment drops out of contention.
        a.reveal_bid(key(1), 50, nonce(1), 200).unwrap();
        a.reveal_bid(key(2), 90, nonce(2), 210).unwrap();
        assert_eq!(a.reveal_count(), 2);
        let s = a.settle(300).unwrap();
        assert_eq!(
            s,
            SealedBidSettlement::Sold {
                winner: key(2),
                winning_bid: 90
            }
        );
        assert_eq!(a.state(), SealedBidState::Settled);
    }

    #[test]
    fn commitment_hides_the_bid() {
        let c1 = sealed_bid_commitment(&key(1), 50, &nonce(1));
        let c2 = sealed_bid_commitment(&key(1), 51, &nonce(1));
        let c3 = sealed_bid_commitment(&key(1), 50, &nonce(2));
        let c4 = sealed_bid_commitment(&key(2), 50, &nonce(1));
        // Any change to bid, nonce, or bidder changes the commitment.
        assert_ne!(c1, c2);
        assert_ne!(c1, c3);
        assert_ne!(c1, c4);
        // Deterministic: same inputs, same commitment.
        assert_eq!(c1, sealed_bid_commitment(&key(1), 50, &nonce(1)));
    }

    #[test]
    fn wrong_preimage_fails_reveal() {
        let mut a = open_auction();
        commit(&mut a, key(1), 50, nonce(1), 100);
        // Wrong nonce.
        let err = a.reveal_bid(key(1), 50, nonce(9), 200).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidRevealMismatch);
        // Wrong bid.
        let err = a.reveal_bid(key(1), 51, nonce(1), 200).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidRevealMismatch);
        assert_eq!(err.code(), 275);
        // A bidder with no commitment on record cannot reveal.
        let err = a.reveal_bid(key(7), 50, nonce(7), 200).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidRevealMismatch);
        // Nothing was recorded.
        assert_eq!(a.reveal_count(), 0);
    }

    #[test]
    fn copied_commitment_cannot_be_revealed_by_another_bidder() {
        let mut a = open_auction();
        // Attacker copies bidder 1's commitment bytes verbatim.
        let c = sealed_bid_commitment(&key(1), 50, &nonce(1));
        a.commit_bid(key(9), c, 100).unwrap();
        // The attacker cannot produce a preimage that verifies against
        // their own key — the bidder key is bound into the commitment.
        let err = a.reveal_bid(key(9), 50, nonce(1), 200).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidRevealMismatch);
    }

    #[test]
    fn duplicate_commit_rejected() {
        let mut a = open_auction();
        commit(&mut a, key(1), 50, nonce(1), 100);
        let c = sealed_bid_commitment(&key(1), 60, &nonce(2));
        let err = a.commit_bid(key(1), c, 110).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidDuplicateCommit);
        assert_eq!(err.code(), 274);
        assert_eq!(a.commit_count(), 1);
    }

    #[test]
    fn reveal_is_idempotent_for_the_same_bid() {
        let mut a = open_auction();
        commit(&mut a, key(1), 50, nonce(1), 100);
        let r1 = a.reveal_bid(key(1), 50, nonce(1), 200).unwrap();
        let r2 = a.reveal_bid(key(1), 50, nonce(1), 210).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(a.reveal_count(), 1);
        // A *different* bid after a reveal is a mismatch — the
        // commitment already binds exactly one bid.
        let err = a.reveal_bid(key(1), 60, nonce(1), 210).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidRevealMismatch);
    }

    #[test]
    fn phase_violations_are_not_live() {
        let mut a = open_auction();
        let c = sealed_bid_commitment(&key(1), 50, &nonce(1));
        // Commit before the commit window.
        let err = a.commit_bid(key(1), c, 99).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidNotLive);
        // Commit during the reveal phase.
        let err = a.commit_bid(key(1), c, 200).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidNotLive);
        // Reveal during the commit phase.
        commit(&mut a, key(1), 50, nonce(1), 100);
        let err = a.reveal_bid(key(1), 50, nonce(1), 150).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidNotLive);
        assert_eq!(err.code(), 273);
        // Settle before the reveal window closes.
        let err = a.settle(299).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidSettleTooEarly);
        assert_eq!(err.code(), 276);
    }

    #[test]
    fn terminal_auction_rejects_everything() {
        let mut a = open_auction();
        commit(&mut a, key(1), 50, nonce(1), 100);
        a.reveal_bid(key(1), 50, nonce(1), 200).unwrap();
        a.settle(300).unwrap();
        let c = sealed_bid_commitment(&key(2), 60, &nonce(2));
        assert_eq!(
            a.commit_bid(key(2), c, 100).unwrap_err(),
            EscrowError::SealedBidNotLive
        );
        assert_eq!(
            a.reveal_bid(key(2), 60, nonce(2), 200).unwrap_err(),
            EscrowError::SealedBidNotLive
        );
        assert_eq!(
            a.settle(400).unwrap_err(),
            EscrowError::SealedBidNotLive
        );
    }

    #[test]
    fn min_bid_floor_blocks_cheap_wins() {
        let mut a = open_auction(); // min_bid = 10
        commit(&mut a, key(1), 5, nonce(1), 100);
        a.reveal_bid(key(1), 5, nonce(1), 200).unwrap();
        let s = a.settle(300).unwrap();
        assert_eq!(
            s,
            SealedBidSettlement::ReserveNotMet {
                highest_bidder: key(1),
                highest_bid: 5
            }
        );
        assert_eq!(a.state(), SealedBidState::NoSale);
        // No floor: the same bid wins.
        let mut b = SealedBidAuction::new(key(0xAA), 100, 200, 300, 0).unwrap();
        commit(&mut b, key(1), 5, nonce(1), 100);
        b.reveal_bid(key(1), 5, nonce(1), 200).unwrap();
        assert_eq!(
            b.settle(300).unwrap(),
            SealedBidSettlement::Sold {
                winner: key(1),
                winning_bid: 5
            }
        );
    }

    #[test]
    fn no_reveals_is_no_sale() {
        let mut a = open_auction();
        commit(&mut a, key(1), 50, nonce(1), 100);
        // Nobody reveals — the commitment drops out of contention.
        let s = a.settle(300).unwrap();
        assert_eq!(s, SealedBidSettlement::NoBids);
        assert_eq!(a.state(), SealedBidState::NoSale);
    }

    #[test]
    fn tie_breaks_to_earliest_reveal() {
        let mut a = open_auction();
        commit(&mut a, key(1), 50, nonce(1), 100);
        commit(&mut a, key(2), 50, nonce(2), 110);
        // Bidder 2 reveals first, but bidder 1 revealed the same bid
        // at an earlier slot — earliest reveal wins the tie.
        a.reveal_bid(key(2), 50, nonce(2), 210).unwrap();
        a.reveal_bid(key(1), 50, nonce(1), 200).unwrap();
        assert_eq!(
            a.settle(300).unwrap(),
            SealedBidSettlement::Sold {
                winner: key(1),
                winning_bid: 50
            }
        );
    }

    #[test]
    fn book_full_is_fail_closed() {
        let mut a = open_auction();
        for i in 0..MAX_SEALED_BIDS {
            let bidder = [i as u8; 32];
            // Avoid the zero bidder key on i == 0.
            let bidder = if bidder == [0u8; 32] { [0xFF; 32] } else { bidder };
            let c = sealed_bid_commitment(&bidder, 50 + i as u64, &nonce(i as u8));
            a.commit_bid(bidder, c, 100).unwrap();
        }
        assert_eq!(a.commit_count(), MAX_SEALED_BIDS as u32);
        let c = sealed_bid_commitment(&key(0x42), 99, &nonce(0x42));
        let err = a.commit_bid(key(0x42), c, 100).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidBookFull);
        assert_eq!(err.code(), 278);
    }

    #[test]
    fn cancel_is_seller_only_and_never_after_commit() {
        let mut a = open_auction();
        // A stranger cannot cancel.
        let err = a.cancel(key(9), 100).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        // After the first commitment, even the seller cannot cancel.
        commit(&mut a, key(1), 50, nonce(1), 100);
        let err = a.cancel(key(0xAA), 150).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidNotCancellable);
        // A lapsed commit phase is settled, not cancelled.
        let mut b = open_auction();
        let err = b.cancel(key(0xAA), 200).unwrap_err();
        assert_eq!(err, EscrowError::SealedBidNotCancellable);
        assert_eq!(err.code(), 277);
        assert_eq!(b.state(), SealedBidState::Active);
        // Clean cancel before any commitment.
        let mut c = open_auction();
        c.cancel(key(0xAA), 100).unwrap();
        assert_eq!(c.state(), SealedBidState::Cancelled);
    }

    #[test]
    fn audit_json_carries_commit_reveal_settle() {
        let mut a = open_auction();
        let c = commit(&mut a, key(7), 60, nonce(7), 100).commitment;
        let j = a.commit_audit_json(key(7), c);
        assert!(j.contains("\"event\":\"sealed_bid_commit\""));
        assert!(j.contains("\"reveal_start_slot\":200"));
        assert!(j.contains("0707070707070707070707070707070707070707070707070707070707070707"));
        let j = a.reveal_audit_json(key(7), 60);
        assert!(j.contains("\"event\":\"sealed_bid_reveal\""));
        assert!(j.contains("\"bid\":60"));
        // The nonce never appears in the audit log.
        assert!(!j.contains("8787878787878787878787878787878787878787878787878787878787878787"));
        a.reveal_bid(key(7), 60, nonce(7), 200).unwrap();
        let s = a.settle(300).unwrap();
        let j = a.settle_audit_json(s);
        assert!(j.contains("\"event\":\"sealed_bid_settled\""));
        assert!(j.contains("\"outcome\":\"sold\""));
        assert!(j.contains("\"winning_bid\":60"));
    }

    #[test]
    fn error_codes_pinned() {
        // Never renumber: the Anchor layer assigns one program error
        // per variant and off-chain clients match on these numbers.
        assert_eq!(EscrowError::InvalidSealedBid.code(), 272);
        assert_eq!(EscrowError::SealedBidNotLive.code(), 273);
        assert_eq!(EscrowError::SealedBidDuplicateCommit.code(), 274);
        assert_eq!(EscrowError::SealedBidRevealMismatch.code(), 275);
        assert_eq!(EscrowError::SealedBidSettleTooEarly.code(), 276);
        assert_eq!(EscrowError::SealedBidNotCancellable.code(), 277);
        assert_eq!(EscrowError::SealedBidBookFull.code(), 278);
        assert_eq!(EscrowError::SealedBidPricingLocked.code(), 313);
        for e in [
            EscrowError::InvalidSealedBid,
            EscrowError::SealedBidNotLive,
            EscrowError::SealedBidDuplicateCommit,
            EscrowError::SealedBidRevealMismatch,
            EscrowError::SealedBidSettleTooEarly,
            EscrowError::SealedBidNotCancellable,
            EscrowError::SealedBidBookFull,
            EscrowError::SealedBidPricingLocked,
        ] {
            assert!(EscrowError::all().contains(&e));
        }
        // AV-192 appends 7 sealed-bid errors after AV-191's
        // InvalidReferral (271); AV-193 appends 3 oracle-adapter
        // errors after those.
        assert_eq!(EscrowError::all().len(), 220); // AV-195: +7, AV-196: +6, AV-197: +5, AV-200: +1, AV-203: +1 AV-205: +1; AV-209: +4
    }
}
