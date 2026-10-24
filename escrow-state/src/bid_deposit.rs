//! AV-194: opt-in bid deposits for auctions.
//!
//! A seller attaches a flat bid deposit to an auction — English
//! (AV-189), Dutch (AV-97) or sealed-bid (AV-192). Every bidder locks
//! the deposit when they bid; at settlement the winner's deposit is
//! *applied* toward the purchase price, every honest loser's deposit
//! is *refunded* in full, and misbehaving bidders are *forfeited*:
//!
//! - sealed-bid bidders that never reveal lose the deposit
//!   (no-reveal confiscation — the AV-192 auction module tracks
//!   commitments, not funds, so this module is where the confiscation
//!   lands);
//! - the seller may slash a locked deposit before settlement for
//!   misbehavior outside the auction rules (e.g. a winner that ghosts
//!   a malicious no-sale).
//!
//! Orthogonal to AV-103 (the taker's appeal bond on a *slashed*
//! escrow — a dispute collateral, not an auction bid bond) and to the
//! auction modules themselves (AV-189/AV-97/AV-192 price the asset and
//! pick the winner; this module only moves the deposits once the
//! program tells it the outcome). Pure logic: bid custody is the
//! Anchor program's job; this module is the deterministic state
//! machine the program drives. `Copy`, heap-free, `no_std`-friendly.

use crate::EscrowError;

/// Maximum registered bid deposits per auction — the book is a
/// fixed-size array, so the 65th bidder is refused fail-closed rather
/// than silently dropped (same bound as `MAX_SEALED_BIDS`, so a
/// deposit-backed sealed-bid auction can cover every committer).
pub const MAX_BID_DEPOSITS: usize = 64;

/// The auction the deposit book is attached to. Stored for
/// observability and audit only — settlement behavior is chosen by
/// which settle entrypoint the program calls (`settle` for
/// open-bid auctions, `settle_sealed` for sealed-bid), and calling
/// the wrong one for the kind is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuctionKind {
    /// Ascending open-bid auction (AV-189).
    English,
    /// Descending-price auction (AV-97).
    Dutch,
    /// Commit-reveal dark auction (AV-192).
    SealedBid,
}

/// Lifecycle of one bidder's deposit: `Locked` → `Applied` |
/// `Refunded` | `Forfeited`. All three exits are terminal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DepositState {
    /// The deposit is held — the bidder may still be refunded,
    /// applied, or forfeited.
    #[default]
    Locked,
    /// The winner's deposit, applied toward the purchase price.
    Applied,
    /// Returned to the bidder in full (losers, and every deposit on
    /// an open-bid no-sale).
    Refunded,
    /// Confiscated: sealed-bid no-reveal, or a seller slash for
    /// misbehavior.
    Forfeited,
}

/// One registered deposit: the bidder's key, the deposit's lifecycle
/// state, and (sealed-bid only) whether the bidder revealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DepositEntry {
    bidder: [u8; 32],
    state: DepositState,
    revealed: bool,
}

/// The program's receipt for a successful
/// [`BidDepositAuction::register`]: everything needed to move funds —
/// who locked how much, and which auction book they joined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositReceipt {
    /// The bidder that just locked the deposit.
    pub bidder: [u8; 32],
    /// The flat deposit amount locked (see
    /// [`BidDepositAuction::deposit_amount`]).
    pub amount: u64,
    /// The auction book's identifier.
    pub auction: [u8; 32],
}

/// What [`BidDepositAuction::settle`] / `settle_sealed` decided: the
/// per-outcome counts the Anchor program uses to move funds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BidDepositSettlement {
    /// The winner, or `None` for a no-sale. The winner's deposit is
    /// applied toward the purchase price.
    pub winner: Option<[u8; 32]>,
    /// Deposit amount applied toward the purchase (`0` on no-sale).
    pub applied: u64,
    /// How many deposits were refunded in full.
    pub refunded: u8,
    /// How many deposits were forfeited.
    pub forfeited: u8,
}

/// A flat bid-deposit book for one auction.
///
/// Construct with [`BidDepositAuction::new`]. Bidders
/// [`register`](Self::register) during the bidding phase; the seller
/// may [`forfeit`](Self::forfeit) a misbehaving bidder's deposit
/// before settlement; the program finalizes with
/// [`settle`](Self::settle) (English/Dutch) or
/// [`settle_sealed`](Self::settle_sealed) (sealed-bid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BidDepositAuction {
    auction: [u8; 32],
    kind: AuctionKind,
    seller: [u8; 32],
    deposit_amount: u64,
    entries: [Option<DepositEntry>; MAX_BID_DEPOSITS],
    count: u8,
    settled: bool,
}

impl BidDepositAuction {
    /// Open a deposit book for `auction`.
    ///
    /// Refused (fail-closed, [`EscrowError::InvalidBidDeposit`], code
    /// 282) on a zero auction id, a zero seller key (nobody could
    /// authorize a forfeit), or a zero deposit amount (a zero-deposit
    /// book is a no-op — the program should skip deposits instead).
    pub fn new(
        auction: [u8; 32],
        kind: AuctionKind,
        seller: [u8; 32],
        deposit_amount: u64,
    ) -> Result<Self, EscrowError> {
        if auction == [0u8; 32] || seller == [0u8; 32] || deposit_amount == 0 {
            return Err(EscrowError::InvalidBidDeposit);
        }
        Ok(BidDepositAuction {
            auction,
            kind,
            seller,
            deposit_amount,
            entries: [None; MAX_BID_DEPOSITS],
            count: 0,
            settled: false,
        })
    }

    /// The auction book's identifier.
    pub fn auction(&self) -> [u8; 32] {
        self.auction
    }

    /// The auction kind this book backs.
    pub fn kind(&self) -> AuctionKind {
        self.kind
    }

    /// The seller — the only authority that may forfeit a deposit.
    pub fn seller(&self) -> [u8; 32] {
        self.seller
    }

    /// The flat per-bidder deposit amount.
    pub fn deposit_amount(&self) -> u64 {
        self.deposit_amount
    }

    /// How many deposits are registered.
    pub fn deposit_count(&self) -> u8 {
        self.count
    }

    /// `true` once the book has been settled (terminal).
    pub fn is_settled(&self) -> bool {
        self.settled
    }

    fn find(&self, bidder: [u8; 32]) -> Option<usize> {
        self.entries
            .iter()
            .take(self.count as usize)
            .position(|e| e.map(|entry| entry.bidder == bidder).unwrap_or(false))
    }

    /// Register a bidder's deposit — the deposit locks now, at bid
    /// time.
    ///
    /// Check order: settled → bidder key → duplicate → book capacity.
    /// A second registration from the same bidder is refused — one
    /// deposit per bidder, so a bidder cannot dilute the confiscation
    /// by splitting across identities' accounting (the program maps
    /// identities to keys).
    ///
    /// Returns a [`DepositReceipt`] — the Anchor program escrows
    /// `deposit_amount` on this receipt.
    pub fn register(&mut self, bidder: [u8; 32]) -> Result<DepositReceipt, EscrowError> {
        if self.settled {
            return Err(EscrowError::BidDepositAlreadySettled);
        }
        if bidder == [0u8; 32] {
            return Err(EscrowError::InvalidBidDeposit);
        }
        if self.find(bidder).is_some() {
            return Err(EscrowError::InvalidBidDeposit);
        }
        let slot = self.count as usize;
        if slot >= MAX_BID_DEPOSITS {
            return Err(EscrowError::BidDepositBookFull);
        }
        self.entries[slot] = Some(DepositEntry {
            bidder,
            state: DepositState::Locked,
            revealed: false,
        });
        self.count = self.count.saturating_add(1);
        Ok(DepositReceipt {
            bidder,
            amount: self.deposit_amount,
            auction: self.auction,
        })
    }

    /// Mark a bidder revealed — the sealed-bid program calls this as
    /// reveals land (see [`SealedBidAuction`](crate::SealedBidAuction)).
    /// Harmless on English/Dutch books; `settle_sealed` is where the
    /// flag is read.
    ///
    /// Refused ([`EscrowError::BidDepositNotRegistered`], code 283)
    /// for an unknown bidder, and
    /// ([`EscrowError::BidDepositAlreadySettled`], code 284) after
    /// settlement. Idempotent: revealing twice is a no-op.
    pub fn mark_revealed(&mut self, bidder: [u8; 32]) -> Result<(), EscrowError> {
        if self.settled {
            return Err(EscrowError::BidDepositAlreadySettled);
        }
        match self.find(bidder) {
            Some(i) => {
                if let Some(entry) = self.entries[i].as_mut() {
                    entry.revealed = true;
                }
                Ok(())
            }
            None => Err(EscrowError::BidDepositNotRegistered),
        }
    }

    /// The seller slashes a locked deposit for misbehavior outside the
    /// auction rules (e.g. a winner that ghosts a malicious no-sale).
    ///
    /// Check order: authority → settled → registration → locked state.
    /// A stranger learns nothing about the book (seller-only, code 100
    /// like the other seller gates in this crate).
    pub fn forfeit(&mut self, bidder: [u8; 32], authority: [u8; 32]) -> Result<(), EscrowError> {
        if authority != self.seller {
            return Err(EscrowError::Unauthorized);
        }
        if self.settled {
            return Err(EscrowError::BidDepositAlreadySettled);
        }
        match self.find(bidder) {
            Some(i) => {
                let entry = self.entries[i].as_mut().expect("find hit implies Some");
                if entry.state != DepositState::Locked {
                    return Err(EscrowError::InvalidBidDeposit);
                }
                entry.state = DepositState::Forfeited;
                Ok(())
            }
            None => Err(EscrowError::BidDepositNotRegistered),
        }
    }

    /// The current state of one bidder's deposit.
    ///
    /// Refused ([`EscrowError::BidDepositNotRegistered`], code 283)
    /// for a bidder that never registered.
    pub fn state_of(&self, bidder: [u8; 32]) -> Result<DepositState, EscrowError> {
        match self.find(bidder) {
            Some(i) => Ok(self.entries[i].expect("find hit implies Some").state),
            None => Err(EscrowError::BidDepositNotRegistered),
        }
    }

    /// Custody accounting: `(locked, applied, refunded, forfeited)` in
    /// lamports/tokens. The conservation invariant the program and
    /// the tests check: the four buckets always sum to
    /// `deposit_count * deposit_amount` — funds are never created or
    /// destroyed by this state machine, only reclassified.
    pub fn total_custody(&self) -> (u64, u64, u64, u64) {
        let mut locked = 0u64;
        let mut applied = 0u64;
        let mut refunded = 0u64;
        let mut forfeited = 0u64;
        for e in self.entries.iter().take(self.count as usize).flatten() {
            match e.state {
                DepositState::Locked => locked = locked.saturating_add(self.deposit_amount),
                DepositState::Applied => applied = applied.saturating_add(self.deposit_amount),
                DepositState::Refunded => refunded = refunded.saturating_add(self.deposit_amount),
                DepositState::Forfeited => forfeited = forfeited.saturating_add(self.deposit_amount),
            }
        }
        (locked, applied, refunded, forfeited)
    }

    fn apply_settle_common(&mut self, winner: Option<[u8; 32]>) -> Result<(), EscrowError> {
        if self.settled {
            return Err(EscrowError::BidDepositAlreadySettled);
        }
        if let Some(w) = winner {
            match self.find(w) {
                Some(i) => {
                    let st = self.entries[i].expect("find hit implies Some").state;
                    if st != DepositState::Locked {
                        // A forfeited winner cannot have its deposit
                        // applied — the confiscation stands.
                        return Err(EscrowError::InvalidBidDeposit);
                    }
                }
                None => return Err(EscrowError::BidDepositNotRegistered),
            }
        }
        Ok(())
    }

    fn finalize_settle(&mut self, winner: Option<[u8; 32]>, forfeit_unrevealed: bool) -> BidDepositSettlement {
        let mut refunded = 0u8;
        for e in self.entries.iter_mut().take(self.count as usize).flatten() {
            if e.state != DepositState::Locked {
                // Pre-settlement seller forfeits stand — settlement
                // never reclassifies a terminal deposit.
                continue;
            }
            if Some(e.bidder) == winner {
                e.state = DepositState::Applied;
            } else if forfeit_unrevealed && !e.revealed {
                e.state = DepositState::Forfeited;
            } else {
                e.state = DepositState::Refunded;
                refunded = refunded.saturating_add(1);
            }
        }
        // Count pre-settlement forfeits too, so the report accounts
        // for every deposit exactly once — recompute from state so
        // there is no double counting.
        let total_forfeited = self
            .entries
            .iter()
            .take(self.count as usize)
            .flatten()
            .filter(|e| e.state == DepositState::Forfeited)
            .count() as u8;
        self.settled = true;
        BidDepositSettlement {
            winner,
            applied: if winner.is_some() { self.deposit_amount } else { 0 },
            refunded,
            forfeited: total_forfeited,
        }
    }

    /// Settle an English/Dutch deposit book once the auction closed.
    /// Permissionless — anyone may finalize; the outcome is fully
    /// determined by `winner`.
    ///
    /// The winner's deposit is applied toward the purchase price;
    /// every other locked deposit is refunded in full; pre-settlement
    /// seller forfeits stand. `None` is a no-sale: every locked
    /// deposit is refunded.
    ///
    /// Refused on a sealed-bid book (call `settle_sealed`), on a
    /// double settle ([`EscrowError::BidDepositAlreadySettled`], code
    /// 284), on an unknown winner
    /// ([`EscrowError::BidDepositNotRegistered`], code 283), and when
    /// the winner's deposit is no longer locked
    /// ([`EscrowError::InvalidBidDeposit`], code 282).
    pub fn settle(&mut self, winner: Option<[u8; 32]>) -> Result<BidDepositSettlement, EscrowError> {
        if self.kind == AuctionKind::SealedBid {
            return Err(EscrowError::InvalidBidDeposit);
        }
        self.apply_settle_common(winner)?;
        Ok(self.finalize_settle(winner, false))
    }

    /// Settle a sealed-bid deposit book once the reveal window closed.
    /// Same as [`settle`](Self::settle), except every *unrevealed*
    /// bidder's deposit is forfeited instead of refunded — the
    /// no-reveal confiscation. A sealed-bid auction with no reveals
    /// at all is a no-sale *and* a full forfeit: committers that
    /// ghosted lose their deposits.
    ///
    /// The winner must have revealed — an unrevealed winner is a
    /// caller bug ([`EscrowError::InvalidBidDeposit`], code 282).
    /// Refused on a non-sealed-bid book (call `settle`).
    pub fn settle_sealed(&mut self, winner: Option<[u8; 32]>) -> Result<BidDepositSettlement, EscrowError> {
        if self.kind != AuctionKind::SealedBid {
            return Err(EscrowError::InvalidBidDeposit);
        }
        if let Some(w) = winner {
            match self.find(w) {
                Some(i) => {
                    let e = self.entries[i].expect("find hit implies Some");
                    if !e.revealed || e.state != DepositState::Locked {
                        return Err(EscrowError::InvalidBidDeposit);
                    }
                }
                None => return Err(EscrowError::BidDepositNotRegistered),
            }
        }
        if self.settled {
            return Err(EscrowError::BidDepositAlreadySettled);
        }
        Ok(self.finalize_settle(winner, true))
    }

    /// Audit-event JSON for a registration (hand-written):
    /// `{"event":"bid_deposit_registered","auction":"<64hex>",
    /// "bidder":"<64hex>","amount":<u64>}`.
    pub fn register_audit_json(&self, bidder: [u8; 32]) -> String {
        let mut s = String::from("{\"event\":\"bid_deposit_registered\",\"auction\":\"");
        s.push_str(&hex64(&self.auction));
        s.push_str("\",\"bidder\":\"");
        s.push_str(&hex64(&bidder));
        s.push_str("\",\"amount\":");
        s.push_str(&self.deposit_amount.to_string());
        s.push('}');
        s
    }

    /// Audit-event JSON for a settlement (hand-written):
    /// `{"event":"bid_deposit_settled","auction":"<64hex>",
    /// "winner":"<64hex>","applied":<u64>,"refunded":<u8>,
    /// "forfeited":<u8>}` — the zero key marks a no-sale.
    pub fn settle_audit_json(&self, report: BidDepositSettlement) -> String {
        let mut s = String::from("{\"event\":\"bid_deposit_settled\",\"auction\":\"");
        s.push_str(&hex64(&self.auction));
        s.push_str("\",\"winner\":\"");
        s.push_str(&hex64(&report.winner.unwrap_or([0u8; 32])));
        s.push_str("\",\"applied\":");
        s.push_str(&report.applied.to_string());
        s.push_str(",\"refunded\":");
        s.push_str(&report.refunded.to_string());
        s.push_str(",\"forfeited\":");
        s.push_str(&report.forfeited.to_string());
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
mod bid_deposit_tests {
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn open_book() -> BidDepositAuction {
        // English auction book, seller 0xAA, 1000-lamport deposits.
        BidDepositAuction::new(key(0xA0), AuctionKind::English, key(0xAA), 1000).unwrap()
    }

    fn open_sealed_book() -> BidDepositAuction {
        BidDepositAuction::new(key(0xB0), AuctionKind::SealedBid, key(0xAA), 500).unwrap()
    }

    fn assert_conservation(book: &BidDepositAuction) {
        let (locked, applied, refunded, forfeited) = book.total_custody();
        assert_eq!(
            locked + applied + refunded + forfeited,
            book.deposit_count() as u64 * book.deposit_amount(),
            "custody conservation violated"
        );
    }

    #[test]
    fn new_rejects_degenerate_books() {
        // Zero auction id.
        assert_eq!(
            BidDepositAuction::new([0u8; 32], AuctionKind::English, key(0xAA), 1000).unwrap_err(),
            EscrowError::InvalidBidDeposit
        );
        // Zero seller — nobody could authorize a forfeit.
        assert_eq!(
            BidDepositAuction::new(key(0xA0), AuctionKind::English, [0u8; 32], 1000).unwrap_err(),
            EscrowError::InvalidBidDeposit
        );
        // Zero deposit — a no-op book.
        assert_eq!(
            BidDepositAuction::new(key(0xA0), AuctionKind::Dutch, key(0xAA), 0).unwrap_err(),
            EscrowError::InvalidBidDeposit
        );
        let err = EscrowError::InvalidBidDeposit;
        assert_eq!(err.code(), 282);
        assert!(EscrowError::all().contains(&err));
    }

    #[test]
    fn register_locks_one_deposit_per_bidder() {
        let mut b = open_book();
        let r = b.register(key(1)).unwrap();
        assert_eq!(r.bidder, key(1));
        assert_eq!(r.amount, 1000);
        assert_eq!(r.auction, key(0xA0));
        assert_eq!(b.deposit_count(), 1);
        assert_eq!(b.state_of(key(1)).unwrap(), DepositState::Locked);
        assert_conservation(&b);
        // A second registration from the same bidder is refused.
        let err = b.register(key(1)).unwrap_err();
        assert_eq!(err, EscrowError::InvalidBidDeposit);
        // Zero bidder is refused.
        let err = b.register([0u8; 32]).unwrap_err();
        assert_eq!(err, EscrowError::InvalidBidDeposit);
        assert_eq!(b.deposit_count(), 1);
    }

    #[test]
    fn book_full_is_fail_closed() {
        let mut b = open_book();
        for i in 0..MAX_BID_DEPOSITS {
            b.register([(i % 251 + 1) as u8; 32]).unwrap();
        }
        assert_eq!(b.deposit_count(), MAX_BID_DEPOSITS as u8);
        let err = b.register(key(0xFE)).unwrap_err();
        assert_eq!(err, EscrowError::BidDepositBookFull);
        assert_eq!(err.code(), 285);
        assert_conservation(&b);
    }

    #[test]
    fn settle_sold_applies_winner_refunds_losers() {
        let mut b = open_book();
        b.register(key(1)).unwrap();
        b.register(key(2)).unwrap();
        b.register(key(3)).unwrap();
        let s = b.settle(Some(key(2))).unwrap();
        assert_eq!(s.winner, Some(key(2)));
        assert_eq!(s.applied, 1000);
        assert_eq!(s.refunded, 2);
        assert_eq!(s.forfeited, 0);
        assert_eq!(b.state_of(key(2)).unwrap(), DepositState::Applied);
        assert_eq!(b.state_of(key(1)).unwrap(), DepositState::Refunded);
        assert_eq!(b.state_of(key(3)).unwrap(), DepositState::Refunded);
        assert!(b.is_settled());
        assert_conservation(&b);
        // Double settle is refused.
        let err = b.settle(Some(key(2))).unwrap_err();
        assert_eq!(err, EscrowError::BidDepositAlreadySettled);
        assert_eq!(err.code(), 284);
        // Registration after settlement is refused.
        let err = b.register(key(9)).unwrap_err();
        assert_eq!(err, EscrowError::BidDepositAlreadySettled);
    }

    #[test]
    fn settle_no_sale_refunds_everyone() {
        let mut b = open_book();
        b.register(key(1)).unwrap();
        b.register(key(2)).unwrap();
        let s = b.settle(None).unwrap();
        assert_eq!(s.winner, None);
        assert_eq!(s.applied, 0);
        assert_eq!(s.refunded, 2);
        assert_eq!(s.forfeited, 0);
        assert_eq!(b.state_of(key(1)).unwrap(), DepositState::Refunded);
        assert_conservation(&b);
    }

    #[test]
    fn settle_rejects_unknown_or_forfeited_winner() {
        let mut b = open_book();
        b.register(key(1)).unwrap();
        // Unknown winner.
        let err = b.settle(Some(key(9))).unwrap_err();
        assert_eq!(err, EscrowError::BidDepositNotRegistered);
        assert_eq!(err.code(), 283);
        assert!(!b.is_settled());
        // Forfeited winner: the seller slashed key(1) pre-settlement.
        b.forfeit(key(1), key(0xAA)).unwrap();
        let err = b.settle(Some(key(1))).unwrap_err();
        assert_eq!(err, EscrowError::InvalidBidDeposit);
        assert!(!b.is_settled());
        assert_conservation(&b);
    }

    #[test]
    fn forfeit_is_seller_only_and_pre_settlement() {
        let mut b = open_book();
        b.register(key(1)).unwrap();
        // A stranger cannot slash.
        let err = b.forfeit(key(1), key(9)).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        // Unknown bidder.
        let err = b.forfeit(key(9), key(0xAA)).unwrap_err();
        assert_eq!(err, EscrowError::BidDepositNotRegistered);
        // The seller slashes the locked deposit.
        b.forfeit(key(1), key(0xAA)).unwrap();
        assert_eq!(b.state_of(key(1)).unwrap(), DepositState::Forfeited);
        // Slashing a terminal deposit is refused.
        let err = b.forfeit(key(1), key(0xAA)).unwrap_err();
        assert_eq!(err, EscrowError::InvalidBidDeposit);
        // Settlement keeps the forfeit and refunds the rest.
        b.register(key(2)).unwrap();
        let s = b.settle(Some(key(2))).unwrap();
        assert_eq!(s.forfeited, 1);
        assert_eq!(s.refunded, 0);
        assert_eq!(b.state_of(key(1)).unwrap(), DepositState::Forfeited);
        assert_conservation(&b);
        // No forfeit after settlement.
        let err = b.forfeit(key(2), key(0xAA)).unwrap_err();
        assert_eq!(err, EscrowError::BidDepositAlreadySettled);
    }

    #[test]
    fn settle_entrypoint_must_match_auction_kind() {
        let mut sealed = open_sealed_book();
        sealed.register(key(1)).unwrap();
        sealed.mark_revealed(key(1)).unwrap();
        // Open-bid settle on a sealed-bid book is refused.
        let err = sealed.settle(Some(key(1))).unwrap_err();
        assert_eq!(err, EscrowError::InvalidBidDeposit);
        let mut open = open_book();
        open.register(key(1)).unwrap();
        // Sealed settle on an open-bid book is refused.
        let err = open.settle_sealed(Some(key(1))).unwrap_err();
        assert_eq!(err, EscrowError::InvalidBidDeposit);
        assert!(!sealed.is_settled());
        assert!(!open.is_settled());
    }

    #[test]
    fn settle_sealed_forfeits_unrevealed_refunds_revealed_losers() {
        let mut b = open_sealed_book();
        b.register(key(1)).unwrap(); // winner, reveals
        b.register(key(2)).unwrap(); // loser, reveals
        b.register(key(3)).unwrap(); // ghosts — never reveals
        b.mark_revealed(key(1)).unwrap();
        b.mark_revealed(key(2)).unwrap();
        // mark_revealed is idempotent.
        b.mark_revealed(key(1)).unwrap();
        let s = b.settle_sealed(Some(key(1))).unwrap();
        assert_eq!(s.winner, Some(key(1)));
        assert_eq!(s.applied, 500);
        assert_eq!(s.refunded, 1);
        assert_eq!(s.forfeited, 1);
        assert_eq!(b.state_of(key(1)).unwrap(), DepositState::Applied);
        assert_eq!(b.state_of(key(2)).unwrap(), DepositState::Refunded);
        assert_eq!(b.state_of(key(3)).unwrap(), DepositState::Forfeited);
        assert_conservation(&b);
    }

    #[test]
    fn settle_sealed_no_reveals_is_full_forfeit() {
        let mut b = open_sealed_book();
        b.register(key(1)).unwrap();
        b.register(key(2)).unwrap();
        // Nobody revealed: no sale, and every deposit is confiscated.
        let s = b.settle_sealed(None).unwrap();
        assert_eq!(s.applied, 0);
        assert_eq!(s.refunded, 0);
        assert_eq!(s.forfeited, 2);
        assert_eq!(b.state_of(key(1)).unwrap(), DepositState::Forfeited);
        assert_conservation(&b);
    }

    #[test]
    fn settle_sealed_rejects_unrevealed_winner() {
        let mut b = open_sealed_book();
        b.register(key(1)).unwrap();
        b.register(key(2)).unwrap();
        b.mark_revealed(key(2)).unwrap();
        // key(1) never revealed — it cannot be the winner.
        let err = b.settle_sealed(Some(key(1))).unwrap_err();
        assert_eq!(err, EscrowError::InvalidBidDeposit);
        assert!(!b.is_settled());
        // Unknown winner.
        let err = b.settle_sealed(Some(key(9))).unwrap_err();
        assert_eq!(err, EscrowError::BidDepositNotRegistered);
    }

    #[test]
    fn mark_revealed_guards() {
        let mut b = open_sealed_book();
        // Unknown bidder.
        let err = b.mark_revealed(key(1)).unwrap_err();
        assert_eq!(err, EscrowError::BidDepositNotRegistered);
        b.register(key(1)).unwrap();
        b.settle_sealed(None).unwrap();
        // After settlement.
        let err = b.mark_revealed(key(1)).unwrap_err();
        assert_eq!(err, EscrowError::BidDepositAlreadySettled);
    }

    #[test]
    fn state_of_unknown_bidder() {
        let b = open_book();
        let err = b.state_of(key(1)).unwrap_err();
        assert_eq!(err, EscrowError::BidDepositNotRegistered);
    }

    #[test]
    fn conservation_holds_across_a_mixed_lifecycle() {
        let mut b = open_sealed_book();
        for i in 1u8..=6 {
            b.register(key(i)).unwrap();
        }
        assert_conservation(&b);
        // Seller slashes one misbehaving bidder pre-settlement.
        b.forfeit(key(6), key(0xAA)).unwrap();
        assert_conservation(&b);
        for i in [1u8, 2, 3, 4] {
            b.mark_revealed(key(i)).unwrap();
        }
        assert_conservation(&b);
        let s = b.settle_sealed(Some(key(2))).unwrap();
        assert_eq!((s.applied, s.refunded, s.forfeited), (500, 3, 2));
        assert_conservation(&b);
        let (locked, applied, refunded, forfeited) = b.total_custody();
        assert_eq!(locked, 0);
        assert_eq!(applied, 500);
        assert_eq!(refunded, 1500);
        assert_eq!(forfeited, 1000);
    }

    #[test]
    fn audit_json_carries_the_custody_facts() {
        let mut b = open_book();
        b.register(key(7)).unwrap();
        let j = b.register_audit_json(key(7));
        assert!(j.contains("\"event\":\"bid_deposit_registered\""));
        assert!(j.contains("\"amount\":1000"));
        assert!(j.contains("0707070707070707070707070707070707070707070707070707070707070707"));
        b.register(key(8)).unwrap();
        let s = b.settle(Some(key(7))).unwrap();
        let j = b.settle_audit_json(s);
        assert!(j.contains("\"event\":\"bid_deposit_settled\""));
        assert!(j.contains("\"applied\":1000"));
        assert!(j.contains("\"refunded\":1"));
        assert!(j.contains("\"forfeited\":0"));
    }

    #[test]
    fn error_codes_pinned() {
        // Never renumber: the Anchor layer assigns one program error
        // per variant and off-chain clients match on these numbers.
        assert_eq!(EscrowError::InvalidBidDeposit.code(), 282);
        assert_eq!(EscrowError::BidDepositNotRegistered.code(), 283);
        assert_eq!(EscrowError::BidDepositAlreadySettled.code(), 284);
        assert_eq!(EscrowError::BidDepositBookFull.code(), 285);
        for e in [
            EscrowError::InvalidBidDeposit,
            EscrowError::BidDepositNotRegistered,
            EscrowError::BidDepositAlreadySettled,
            EscrowError::BidDepositBookFull,
        ] {
            assert!(EscrowError::all().contains(&e));
        }
        assert_eq!(EscrowError::all().len(), 205); // AV-195: +7 social-recovery errors, AV-196: +6 jury-sortition errors, AV-197: +5 payment-channel errors
    }
}
