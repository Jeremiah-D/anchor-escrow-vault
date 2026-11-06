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

    /// The live payment-window length, in slots.
    ///
    /// Follows [`WinnerPaymentWindow::amend_window_slots`]: the
    /// construction-time value until the window is revised, the
    /// revised value after.
    pub fn window_slots(&self) -> u64 {
        self.window_slots
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

    /// Revise the live payment-window length, in slots (AV-358).
    ///
    /// A winner dragging their feet can have the window tightened so
    /// the sale falls through to the runner-up sooner; a winner held
    /// up by chain congestion can have it widened so the sale is not
    /// lost. Before this method the only remedy was rebuilding the
    /// window — which discarded the `current` successor, the
    /// `forfeited` list, and any `paid_winner`, and required
    /// re-ranking every revealed bid. This revises the window in
    /// place: the ranking, the current winner, the forfeited list,
    /// and the paid state are untouched.
    ///
    /// The window's start is preserved and the elapsed time is kept:
    /// `window_start = deadline_slot - old window_slots` and the new
    /// deadline is `window_start + new_window_slots`. The new window
    /// governs from the next evaluation on: [`WinnerPaymentWindow::mark_paid`]
    /// judges against the new deadline, and
    /// [`WinnerPaymentWindow::expire`] opens the successor's fresh
    /// window from the new length.
    ///
    /// Check order: state → value → deadline → same, mirroring
    /// AV-345's [`MerkleDistributor::amend_merkle_expiry_slot`] and
    /// AV-339's `amend_htlc_expiry_slot`:
    ///
    /// 1. terminal window (`Paid` / `Exhausted`) → [`EscrowError::InvalidStateTransition`]
    ///    — a terminal window has no live clock left to move, so
    ///    revising it is meaningless;
    /// 2. `new_window_slots == 0` → [`EscrowError::WinnerPaymentInvalidWindow`],
    ///    reusing [`WinnerPaymentWindow::new`]'s zero-window gate, live
    ///    values untouched;
    /// 3. the recomputed deadline is at or before `current_slot` →
    ///    [`EscrowError::WinnerPaymentInvalidWindow`], live values
    ///    untouched — a revision only narrows or widens the window,
    ///    never kills it early; ending a window is [`WinnerPaymentWindow::expire`]'s
    ///    job;
    /// 4. re-affirming the current length → `Ok(false)`, a silent
    ///    no-op: nothing is written and no audit event is emitted.
    ///
    /// Otherwise `window_slots` and `deadline_slot` are replaced as a
    /// pair and the method returns `Ok(true)`. A window that has
    /// lapsed but not yet been expired can be revived by widening it
    /// (`new_deadline > current_slot`): the current winner may still
    /// pay until `expire` is called, the same revival AV-345 allows.
    ///
    /// There is no authority gate: the struct holds no authority key,
    /// so gating belongs to the Anchor instruction that will call this
    /// method, not to the pure-logic sidecar (same as `SponsorPolicy`
    /// and `PriorityFeeOracle`).
    pub fn amend_window_slots(
        &mut self,
        new_window_slots: u64,
        current_slot: u64,
    ) -> Result<bool, EscrowError> {
        if self.state != WinnerPaymentState::AwaitingPayment {
            return Err(EscrowError::InvalidStateTransition);
        }
        if new_window_slots == 0 {
            return Err(EscrowError::WinnerPaymentInvalidWindow);
        }
        let window_start = self.deadline_slot.saturating_sub(self.window_slots);
        let new_deadline = window_start.saturating_add(new_window_slots);
        if new_deadline <= current_slot {
            return Err(EscrowError::WinnerPaymentInvalidWindow);
        }
        if new_window_slots == self.window_slots {
            return Ok(false);
        }
        self.window_slots = new_window_slots;
        self.deadline_slot = new_deadline;
        Ok(true)
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

    /// Audit-event JSON for a window-length revision (call only on an
    /// actual change — a same-length no-op emits nothing):
    /// `{"event":"winner_payment_window_amended",
    /// "previous_window_slots":<u64>,"window_slots":<u64>,
    /// "previous_deadline":<u64>,"deadline":<u64>,"slot":<u64>}`.
    /// `previous_window_slots` / `previous_deadline` are the values
    /// this call replaced; the new values are read off `self`.
    /// `"slot"` is the window's start slot
    /// (`deadline_slot - window_slots`) — the anchor the revision
    /// preserves, so the event pins both the new window and where it
    /// started counting from.
    pub fn window_slots_amended_audit_json(
        &self,
        previous_window_slots: u64,
        previous_deadline_slot: u64,
    ) -> String {
        let mut s =
            String::from("{\"event\":\"winner_payment_window_amended\",\"previous_window_slots\":");
        s.push_str(&previous_window_slots.to_string());
        s.push_str(",\"window_slots\":");
        s.push_str(&self.window_slots.to_string());
        s.push_str(",\"previous_deadline\":");
        s.push_str(&previous_deadline_slot.to_string());
        s.push_str(",\"deadline\":");
        s.push_str(&self.deadline_slot.to_string());
        s.push_str(",\"slot\":");
        s.push_str(
            &self
                .deadline_slot
                .saturating_sub(self.window_slots)
                .to_string(),
        );
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

    #[test]
    fn window_slots_getter_follows_live_value() {
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        assert_eq!(w.window_slots(), 10);
        assert!(w.amend_window_slots(25, 102).unwrap());
        assert_eq!(w.window_slots(), 25);
    }

    #[test]
    fn amend_window_slots_tightens_and_governs_next_evaluation() {
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        // Window start 100 is preserved: new deadline 100 + 4.
        assert!(w.amend_window_slots(4, 102).unwrap());
        assert_eq!(w.window_slots(), 4);
        assert_eq!(w.deadline_slot(), 104);
        // mark_paid judges against the new deadline.
        assert_eq!(
            w.mark_paid(key(3), 104).unwrap_err(),
            EscrowError::WinnerPaymentWindowExpired
        );
        let receipt = w.mark_paid(key(3), 103).unwrap();
        assert_eq!(receipt.winner, key(3));
        assert_eq!(w.state(), WinnerPaymentState::Paid);
    }

    #[test]
    fn amend_window_slots_successor_window_uses_new_length() {
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        assert!(w.amend_window_slots(4, 102).unwrap());
        let e = w.expire(104).unwrap();
        assert_eq!(e.forfeited_winner, key(3));
        assert_eq!(e.next_winner, Some(key(2)));
        // Successor window: expire slot + NEW length, not the old 10.
        assert_eq!(e.next_deadline_slot, Some(108));
        assert_eq!(w.deadline_slot(), 108);
        assert_eq!(w.window_slots(), 4);
    }

    #[test]
    fn amend_window_slots_widens_and_revives_lapsed_window() {
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        // Deadline 110 has passed at slot 115, but expire has not run.
        assert_eq!(
            w.mark_paid(key(3), 115).unwrap_err(),
            EscrowError::WinnerPaymentWindowExpired
        );
        assert!(w.amend_window_slots(20, 115).unwrap());
        assert_eq!(w.deadline_slot(), 120);
        // Revived: the winner may still pay until expire is called.
        let receipt = w.mark_paid(key(3), 115).unwrap();
        assert_eq!(receipt.winner, key(3));
        assert_eq!(w.state(), WinnerPaymentState::Paid);
    }

    #[test]
    fn amend_window_slots_rejects_zero_and_killing_deadline() {
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        assert_eq!(
            w.amend_window_slots(0, 102).unwrap_err(),
            EscrowError::WinnerPaymentInvalidWindow
        );
        assert_eq!(w.window_slots(), 10);
        assert_eq!(w.deadline_slot(), 110);
        // Shrink to 5 at slot 105: new deadline 100 + 5 = 105, at the
        // current slot — the revision would kill the window now.
        assert_eq!(
            w.amend_window_slots(5, 105).unwrap_err(),
            EscrowError::WinnerPaymentInvalidWindow
        );
        assert_eq!(w.window_slots(), 10);
        assert_eq!(w.deadline_slot(), 110);
        // Same shrink one slot earlier is fine: deadline 105 > 104.
        assert!(w.amend_window_slots(5, 104).unwrap());
        assert_eq!(w.deadline_slot(), 105);
    }

    #[test]
    fn amend_window_slots_same_length_is_silent_noop() {
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        assert!(!w.amend_window_slots(10, 105).unwrap());
        assert_eq!(w.window_slots(), 10);
        assert_eq!(w.deadline_slot(), 110);
        // The deadline gate runs before the no-op check: re-affirming
        // the length of an already-lapsed window still fails.
        assert_eq!(
            w.amend_window_slots(10, 115).unwrap_err(),
            EscrowError::WinnerPaymentInvalidWindow
        );
        assert_eq!(w.window_slots(), 10);
        assert_eq!(w.deadline_slot(), 110);
    }

    #[test]
    fn amend_window_slots_refused_on_terminal_windows() {
        let mut paid = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        paid.mark_paid(key(3), 105).unwrap();
        assert_eq!(
            paid.amend_window_slots(20, 106).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        // State gate runs before the value gate: zero on a Paid window
        // reports the terminal state, not the zero window.
        assert_eq!(
            paid.amend_window_slots(0, 106).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        let mut exhausted = WinnerPaymentWindow::new(&[], 10, 100).unwrap();
        assert_eq!(exhausted.state(), WinnerPaymentState::Exhausted);
        assert_eq!(
            exhausted.amend_window_slots(20, 101).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
    }

    #[test]
    fn amend_window_slots_preserves_ranking_and_forfeits() {
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        w.expire(110).unwrap();
        assert_eq!(w.forfeited_winners(), &[key(3)]);
        assert_eq!(w.current_winner(), Some(key(2)));
        // Successor window started at 110 (deadline 120, length 10).
        assert!(w.amend_window_slots(5, 112).unwrap());
        assert_eq!(w.window_slots(), 5);
        assert_eq!(w.deadline_slot(), 115);
        assert_eq!(w.current_winner(), Some(key(2)));
        assert_eq!(w.forfeited_winners(), &[key(3)]);
        assert_eq!(w.remaining_ranking(), &[key(1), key(4)]);
        assert_eq!(w.paid_winner(), None);
        // The next successor's window opens from the new length too.
        let e = w.expire(115).unwrap();
        assert_eq!(e.next_winner, Some(key(1)));
        assert_eq!(e.next_deadline_slot, Some(120));
    }

    #[test]
    fn window_slots_amended_audit_json_exact() {
        let mut w = WinnerPaymentWindow::new(&reveals(), 10, 100).unwrap();
        assert!(w.amend_window_slots(20, 105).unwrap());
        assert_eq!(
            w.window_slots_amended_audit_json(10, 110),
            "{\"event\":\"winner_payment_window_amended\",\"previous_window_slots\":10,\
             \"window_slots\":20,\"previous_deadline\":110,\"deadline\":120,\"slot\":100}"
        );
    }
}
