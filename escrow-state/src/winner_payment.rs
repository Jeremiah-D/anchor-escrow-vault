//! AV-209: winner payment window with ranked fallback — the auction
//! settlement follow-through.
//!
//! `SealedBidAuction::settle` (AV-192) only ranks: it names a winner
//! and never asks whether that winner actually pays. A winner who
//! ghosts after winning would strand the sale — the seller cannot
//! re-offer to the runner-up without an off-chain decision, and the
//! runner-up's bid is left to rot. This sidecar closes that gap with a
//! pure ranking/window decision machine:
//!
//! - The current winner has `window_slots` slots from the window start
//!   to pay. Paying in-window (`mark_paid`) locks the sale.
//! - Missing the window (`expire`) forfeits that winner and promotes
//!   the next validly revealed bidder in settle order, with a fresh
//!   window. Promotion walks the whole ranking; when every ranked
//!   bidder has defaulted the window is `Exhausted` — a no-sale the
//!   seller can act on, not a silent hang.
//! - The ranking input is the settle ordering itself: bid descending,
//!   ties to the earliest reveal slot (the same comparator
//!   `SealedBidAuction::settle` uses, see [`rank_revealed_bidders`]).
//!   The sidecar takes reveals, not a pre-sorted list, so the ordering
//!   rule lives in exactly one documented place and cannot drift from
//!   settle by a caller sorting differently.
//!
//! Funds never move here. The forfeited winner's deposit is confiscated
//! through AV-194's own semantics: [`WinnerPaymentWindow::forfeit_deposits`]
//! maps each recorded default onto `BidDepositAuction::forfeit` (the
//! seller-authorized slash), after validating every entry up front so a
//! bad book fails closed with zero partial confiscation. The actual
//! purchase payment and the deposit custody stay the Anchor program's
//! job — this module only decides *who* may still pay and *whose*
//! deposit is forfeit.
//!
//! Orthogonal to AV-194 itself (which confiscates for *unrevealed* or
//! *no-sale* bidders at settle time — a defaulting winner has revealed
//! and won, so AV-194's settle path would refund, not forfeit, them)
//! and to AV-189 English (open ascending bids: the winner is public
//! and the next bid is known without a ranking walk). Pure logic: no
//! Vault layout change, no VAULT_SPACE bump.

use crate::{BidDepositAuction, DepositState, EscrowError};

fn hex64(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes.iter() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// One validly revealed bid, as settle sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevealedBid {
    /// The bidder's key.
    pub bidder: [u8; 32],
    /// The revealed bid amount.
    pub bid: u64,
    /// The slot the reveal landed in (settle's tie-break).
    pub reveal_slot: u64,
}

/// Rank revealed bids in settle order: bid descending, ties to the
/// earliest reveal slot. A stable sort, so two reveals with an identical
/// (bid, reveal_slot) keep input order — matching settle's first-seen
/// tie-break, where a strictly-greater comparison never displaces the
/// incumbent.
pub fn rank_revealed_bidders(reveals: &[RevealedBid]) -> Vec<[u8; 32]> {
    let mut sorted: Vec<RevealedBid> = reveals.to_vec();
    sorted.sort_by(|a, b| {
        b.bid
            .cmp(&a.bid)
            .then_with(|| a.reveal_slot.cmp(&b.reveal_slot))
    });
    sorted.iter().map(|r| r.bidder).collect()
}

/// Lifecycle of a winner payment window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WinnerPaymentState {
    /// A winner is on the clock; the sale is not yet locked.
    #[default]
    AwaitingPayment,
    /// The current winner paid in-window; the sale is locked.
    Paid,
    /// Every ranked bidder defaulted; no winner remains (no-sale).
    Exhausted,
}

/// Receipt for an in-window payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WinnerPaymentReceipt {
    /// The winner who paid.
    pub winner: [u8; 32],
    /// The slot the payment was recorded at.
    pub paid_at_slot: u64,
}

/// Outcome of expiring one winner's window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WinnerPaymentExpiry {
    /// The winner whose window lapsed (deposit forfeiture candidate).
    pub forfeited_winner: [u8; 32],
    /// The promoted successor, if any ranked bidder remains.
    pub next_winner: Option<[u8; 32]>,
    /// The successor's fresh deadline, if any ranked bidder remains.
    pub next_deadline_slot: Option<u64>,
}

/// The winner payment window over a settle ranking.
///
/// Constructed from the reveal set (ranked internally) or from an
/// already-ranked bidder list via [`WinnerPaymentWindow::from_ranking`]
/// when the caller already holds settle's order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WinnerPaymentWindow {
    ranked: Vec<[u8; 32]>,
    current: usize,
    window_slots: u64,
    deadline_slot: u64,
    state: WinnerPaymentState,
    forfeited: Vec<[u8; 32]>,
    paid_winner: Option<[u8; 32]>,
}

impl WinnerPaymentWindow {
    /// Build a window from revealed bids, ranked in settle order.
    /// `window_slots` must be > 0 (a zero window could never be paid);
    /// a duplicate bidder is rejected — settle's book holds one slot
    /// per bidder, so a duplicate ranking is a caller bug, not a tie.
    /// An empty reveal set is a legitimate no-sale: the window starts
    /// `Exhausted` with no winner and no deadline.
    pub fn new(
        reveals: &[RevealedBid],
        window_slots: u64,
        start_slot: u64,
    ) -> Result<Self, EscrowError> {
        let ranked = rank_revealed_bidders(reveals);
        Self::from_ranking(ranked, window_slots, start_slot)
    }

    /// Build a window from an already-ranked bidder list (settle
    /// order: bid desc, reveal slot asc). Same validation as `new`.
    pub fn from_ranking(
        ranked: Vec<[u8; 32]>,
        window_slots: u64,
        start_slot: u64,
    ) -> Result<Self, EscrowError> {
        if window_slots == 0 {
            return Err(EscrowError::WinnerPaymentInvalidWindow);
        }
        for (i, bidder) in ranked.iter().enumerate() {
            if *bidder == [0u8; 32] {
                return Err(EscrowError::WinnerPaymentInvalidWindow);
            }
            if ranked[..i].contains(bidder) {
                return Err(EscrowError::WinnerPaymentInvalidWindow);
            }
        }
        let state = if ranked.is_empty() {
            WinnerPaymentState::Exhausted
        } else {
            WinnerPaymentState::AwaitingPayment
        };
        Ok(Self {
            ranked,
            current: 0,
            window_slots,
            deadline_slot: start_slot.saturating_add(window_slots),
            state,
            forfeited: Vec::new(),
            paid_winner: None,
        })
    }

    /// The bidder currently on the clock, if any.
    pub fn current_winner(&self) -> Option<[u8; 32]> {
        if self.state != WinnerPaymentState::AwaitingPayment {
            return None;
        }
        self.ranked.get(self.current).copied()
    }

    /// The current winner's payment deadline (slot).
    pub fn deadline_slot(&self) -> u64 {
        self.deadline_slot
    }

    /// The window's lifecycle state.
    pub fn state(&self) -> WinnerPaymentState {
        self.state
    }

    /// Winners whose windows lapsed, in default order.
    pub fn forfeited_winners(&self) -> &[[u8; 32]] {
        &self.forfeited
    }

    /// The winner who paid in-window, if the sale locked.
    pub fn paid_winner(&self) -> Option<[u8; 32]> {
        self.paid_winner
    }

    /// Ranked bidders still in line behind the current winner.
    pub fn remaining_ranking(&self) -> &[[u8; 32]] {
        if self.state != WinnerPaymentState::AwaitingPayment {
            return &[];
        }
        &self.ranked[self.current + 1..]
    }

    /// Record the current winner's payment.
    ///
    /// Check order: state → identity → window. A stranger learns
    /// nothing about the window (non-winner callers are refused before
    /// any window check), and a payment at or after the deadline is
    /// refused — the caller must `expire` first so the successor, not
    /// a late payer, owns the sale.
    pub fn mark_paid(
        &mut self,
        caller: [u8; 32],
        current_slot: u64,
    ) -> Result<WinnerPaymentReceipt, EscrowError> {
        if self.state != WinnerPaymentState::AwaitingPayment {
            return Err(EscrowError::InvalidStateTransition);
        }
        let winner = self
            .current_winner()
            .ok_or(EscrowError::InvalidStateTransition)?;
        if caller != winner {
            return Err(EscrowError::WinnerPaymentNotCurrentWinner);
        }
        if current_slot >= self.deadline_slot {
            return Err(EscrowError::WinnerPaymentWindowExpired);
        }
        self.state = WinnerPaymentState::Paid;
        self.paid_winner = Some(winner);
        Ok(WinnerPaymentReceipt {
            winner,
            paid_at_slot: current_slot,
        })
    }

    /// Expire the current winner's window and promote the successor.
    ///
    /// Refused before the deadline ([`EscrowError::WinnerPaymentNotDue`])
    /// and on a terminal window (paid or exhausted). A promotion opens
    /// a fresh window for the successor (`current_slot + window_slots`);
    /// when no ranked bidder remains the window is `Exhausted` and the
    /// outcome carries no successor.
    pub fn expire(&mut self, current_slot: u64) -> Result<WinnerPaymentExpiry, EscrowError> {
        if self.state != WinnerPaymentState::AwaitingPayment {
            return Err(EscrowError::InvalidStateTransition);
        }
        if current_slot < self.deadline_slot {
            return Err(EscrowError::WinnerPaymentNotDue);
        }
        let forfeited_winner = self
            .current_winner()
            .ok_or(EscrowError::InvalidStateTransition)?;
        self.forfeited.push(forfeited_winner);
        self.current += 1;
        if self.current >= self.ranked.len() {
            self.state = WinnerPaymentState::Exhausted;
            return Ok(WinnerPaymentExpiry {
                forfeited_winner,
                next_winner: None,
                next_deadline_slot: None,
            });
        }
        self.deadline_slot = current_slot.saturating_add(self.window_slots);
        Ok(WinnerPaymentExpiry {
            forfeited_winner,
            next_winner: self.ranked.get(self.current).copied(),
            next_deadline_slot: Some(self.deadline_slot),
        })
    }

    /// Confiscate every recorded defaulter's deposit through AV-194.
    ///
    /// Validation first, mutation second: the deposit book must be
    /// unsettled, every forfeited winner must hold a `Locked` deposit,
    /// and the caller must be the book's seller — otherwise nothing
    /// moves and the error names the problem. Returns the number of
    /// deposits forfeited. A no-op (0) when no winner has defaulted.
    /// Idempotency note: a second call fails closed — the first call
    /// already moved the deposits out of `Locked`, so re-running
    /// reports `InvalidBidDeposit` instead of double-counting.
    pub fn forfeit_deposits(
        &self,
        auction: &mut BidDepositAuction,
        seller: [u8; 32],
    ) -> Result<u8, EscrowError> {
        if auction.is_settled() {
            return Err(EscrowError::BidDepositAlreadySettled);
        }
        for winner in self.forfeited.iter() {
            match auction.state_of(*winner)? {
                DepositState::Locked => {}
                _ => return Err(EscrowError::InvalidBidDeposit),
            }
        }
        let mut count: u8 = 0;
        for winner in self.forfeited.iter() {
            auction.forfeit(*winner, seller)?;
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    /// Audit-event JSON for an in-window payment (hand-written):
    /// `{"event":"winner_payment_paid","winner":"<64hex>","slot":<u64>}`.
    pub fn paid_audit_json(&self, receipt: &WinnerPaymentReceipt) -> String {
        let mut s = String::from("{\"event\":\"winner_payment_paid\",\"winner\":\"");
        s.push_str(&hex64(&receipt.winner));
        s.push_str("\",\"slot\":");
        s.push_str(&receipt.paid_at_slot.to_string());
        s.push('}');
        s
    }

    /// Audit-event JSON for a window expiry (hand-written):
    /// `{"event":"winner_payment_expired","forfeited":"<64hex>",
    /// "next_winner":"<64hex|null>","next_deadline":<u64|null>,
    /// "forfeited_count":<u8>}`.
    pub fn expiry_audit_json(&self, expiry: &WinnerPaymentExpiry) -> String {
        let mut s = String::from("{\"event\":\"winner_payment_expired\",\"forfeited\":\"");
        s.push_str(&hex64(&expiry.forfeited_winner));
        s.push_str("\",\"next_winner\":");
        match expiry.next_winner {
            Some(w) => {
                s.push('"');
                s.push_str(&hex64(&w));
                s.push('"');
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"next_deadline\":");
        match expiry.next_deadline_slot {
            Some(d) => s.push_str(&d.to_string()),
            None => s.push_str("null"),
        }
        s.push_str(",\"forfeited_count\":");
        s.push_str(&self.forfeited.len().to_string());
        s.push('}');
        s
    }
}

#[cfg(test)]
mod winner_payment_tests {
    use super::*;
    use crate::{AuctionKind, BidDepositAuction};

    fn key(b: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = b;
        k
    }

    fn reveals() -> Vec<RevealedBid> {
        vec![
            RevealedBid { bidder: key(1), bid: 100, reveal_slot: 10 },
            RevealedBid { bidder: key(2), bid: 300, reveal_slot: 12 },
            RevealedBid { bidder: key(3), bid: 300, reveal_slot: 11 },
            RevealedBid { bidder: key(4), bid: 50, reveal_slot: 9 },
        ]
    }

    #[test]
    fn ranking_matches_settle_order() {
        // 300@11 beats 300@12 (earliest reveal wins the tie); 100 and
        // 50 follow in bid order.
        assert_eq!(
            rank_revealed_bidders(&reveals()),
            vec![key(3), key(2), key(1), key(4)]
        );
        assert_eq!(rank_revealed_bidders(&[]), Vec::<[u8; 32]>::new());
    }

    #[test]
    fn constructor_validation() {
        assert_eq!(
            WinnerPaymentWindow::new(&reveals(), 0, 100).unwrap_err(),
            EscrowError::WinnerPaymentInvalidWindow
        );
        let dup = vec![
            RevealedBid { bidder: key(1), bid: 10, reveal_slot: 1 },
            RevealedBid { bidder: key(1), bid: 20, reveal_slot: 2 },
        ];
        assert_eq!(
            WinnerPaymentWindow::new(&dup, 10, 100).unwrap_err(),
            EscrowError::WinnerPaymentInvalidWindow
        );
        let zero = vec![RevealedBid { bidder: [0u8; 32], bid: 10, reveal_slot: 1 }];
        assert_eq!(
            WinnerPaymentWindow::new(&zero, 10, 100).unwrap_err(),
            EscrowError::WinnerPaymentInvalidWindow
        );
        let mut empty = WinnerPaymentWindow::new(&[], 10, 100).unwrap();
        assert_eq!(empty.state(), WinnerPaymentState::Exhausted);
        assert_eq!(empty.current_winner(), None);
        assert_eq!(empty.mark_paid(key(1), 100).unwrap_err(), EscrowError::InvalidStateTransition);
        assert_eq!(empty.expire(200).unwrap_err(), EscrowError::InvalidStateTransition);
    }

    #[test]
    fn in_window_payment_locks_sale() {
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        assert_eq!(w.current_winner(), Some(key(3)));
        assert_eq!(w.deadline_slot(), 110);
        // A non-winner learns nothing about the window.
        assert_eq!(
            w.mark_paid(key(2), 105).unwrap_err(),
            EscrowError::WinnerPaymentNotCurrentWinner
        );
        // The deadline slot itself is already late.
        assert_eq!(
            w.mark_paid(key(3), 110).unwrap_err(),
            EscrowError::WinnerPaymentWindowExpired
        );
        let receipt = w.mark_paid(key(3), 109).unwrap();
        assert_eq!(receipt.winner, key(3));
        assert_eq!(w.state(), WinnerPaymentState::Paid);
        assert_eq!(w.paid_winner(), Some(key(3)));
        assert_eq!(w.current_winner(), None);
        assert_eq!(w.mark_paid(key(3), 109).unwrap_err(), EscrowError::InvalidStateTransition);
        assert_eq!(
            w.paid_audit_json(&receipt),
            format!(
                "{{\"event\":\"winner_payment_paid\",\"winner\":\"{}\",\"slot\":109}}",
                hex64(&key(3))
            )
        );
    }

    #[test]
    fn expiry_promotes_in_rank_order_then_exhausts() {
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        assert_eq!(w.expire(109).unwrap_err(), EscrowError::WinnerPaymentNotDue);
        let e1 = w.expire(110).unwrap();
        assert_eq!(e1.forfeited_winner, key(3));
        assert_eq!(e1.next_winner, Some(key(2)));
        assert_eq!(e1.next_deadline_slot, Some(120));
        assert_eq!(w.current_winner(), Some(key(2)));
        assert_eq!(w.forfeited_winners(), &[key(3)]);
        assert_eq!(w.remaining_ranking(), &[key(1), key(4)]);
        // The successor's fresh window, not the original deadline.
        assert_eq!(w.expire(119).unwrap_err(), EscrowError::WinnerPaymentNotDue);
        let e2 = w.expire(120).unwrap();
        assert_eq!(e2.next_winner, Some(key(1)));
        let e3 = w.expire(130).unwrap();
        assert_eq!(e3.next_winner, Some(key(4)));
        let e4 = w.expire(140).unwrap();
        assert_eq!(e4.forfeited_winner, key(4));
        assert_eq!(e4.next_winner, None);
        assert_eq!(e4.next_deadline_slot, None);
        assert_eq!(w.state(), WinnerPaymentState::Exhausted);
        assert_eq!(w.forfeited_winners(), &[key(3), key(2), key(1), key(4)]);
        assert_eq!(w.remaining_ranking(), &[] as &[[u8; 32]]);
        assert_eq!(w.expire(150).unwrap_err(), EscrowError::InvalidStateTransition);
        assert!(w
            .expiry_audit_json(&e4)
            .contains("\"next_winner\":null"));
    }

    #[test]
    fn successor_pays_after_promotion() {
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        w.expire(110).unwrap();
        let receipt = w.mark_paid(key(2), 115).unwrap();
        assert_eq!(receipt.winner, key(2));
        assert_eq!(w.state(), WinnerPaymentState::Paid);
        // The defaulted winner can never pay late.
        assert_eq!(w.mark_paid(key(3), 115).unwrap_err(), EscrowError::InvalidStateTransition);
    }

    #[test]
    fn forfeit_deposits_maps_defaults_onto_av194() {
        let seller = key(9);
        let mut book = BidDepositAuction::new(key(8), AuctionKind::SealedBid, seller, 100).unwrap();
        for b in [1u8, 2, 3, 4] {
            book.register(key(b)).unwrap();
        }
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        assert_eq!(w.forfeit_deposits(&mut book, seller).unwrap(), 0);
        w.expire(110).unwrap();
        w.expire(120).unwrap();
        assert_eq!(w.forfeited_winners(), &[key(3), key(2)]);
        assert_eq!(w.forfeit_deposits(&mut book, seller).unwrap(), 2);
        assert_eq!(book.state_of(key(3)).unwrap(), DepositState::Forfeited);
        assert_eq!(book.state_of(key(2)).unwrap(), DepositState::Forfeited);
        assert_eq!(book.state_of(key(1)).unwrap(), DepositState::Locked);
        // Custody conservation: 2 forfeited, 2 still locked.
        assert_eq!(book.total_custody(), (200, 0, 0, 200));
        // Re-running fails closed instead of double-counting.
        assert_eq!(
            w.forfeit_deposits(&mut book, seller).unwrap_err(),
            EscrowError::InvalidBidDeposit
        );
    }

    #[test]
    fn forfeit_deposits_fails_closed_on_bad_book() {
        let seller = key(9);
        let mut book = BidDepositAuction::new(key(8), AuctionKind::SealedBid, seller, 100).unwrap();
        book.register(key(3)).unwrap();
        // key(2) never registered: validation fails before any mutation.
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        w.expire(110).unwrap();
        w.expire(120).unwrap();
        assert_eq!(
            w.forfeit_deposits(&mut book, seller).unwrap_err(),
            EscrowError::BidDepositNotRegistered
        );
        assert_eq!(book.state_of(key(3)).unwrap(), DepositState::Locked);
        // Wrong seller: zero mutation, Unauthorized from AV-194 itself.
        let mut book2 = BidDepositAuction::new(key(8), AuctionKind::SealedBid, seller, 100).unwrap();
        for b in [1u8, 2, 3, 4] {
            book2.register(key(b)).unwrap();
        }
        assert_eq!(
            w.forfeit_deposits(&mut book2, key(7)).unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(book2.state_of(key(3)).unwrap(), DepositState::Locked);
    }
}
