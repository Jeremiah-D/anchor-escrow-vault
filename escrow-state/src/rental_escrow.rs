//! AV-190: rental escrow — time-boxed custody of an asset.
//!
//! The renter pays rent and receives *temporary custody* of the
//! asset for the lease term: the asset is held by the escrow program
//! (the renter gets use, not ownership), and custody returns to the
//! owner automatically when the term expires. An opt-in late-fee
//! schedule (basis points per day, capped) prices overdue returns.
//!
//! Orthogonal to AV-187 NFT escrow (an *ownership* transfer — the
//! asset changes hands permanently) and to AV-13 vesting (a linear
//! *release* schedule of funds): this module is a *use-right* time
//! box — the asset comes home at the end. `Copy`, heap-free,
//! `no_std`-friendly. This crate is pure logic: the Anchor program
//! performs the custody transfers; the module is the deterministic
//! state machine it drives.

use crate::EscrowError;

/// Maximum late-fee rate in basis points per day: 10_000 bps = 100%.
/// A rate above this is not a valid percentage and is rejected.
pub const MAX_LATE_FEE_BPS: u16 = 10_000;

/// Opt-in late-fee schedule for overdue returns: `bps_per_day`
/// charged per overdue day (any partial day counts as a full day),
/// with the total fee capped at `cap_bps` of the rent amount. `None`
/// (no schedule) means overdue returns are free — the renter is
/// still recorded as late.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LateFeeTerms {
    /// Late fee per overdue day, in basis points of the rent amount.
    pub bps_per_day: u16,
    /// Cap on the total late fee, in basis points of the rent
    /// amount.
    pub cap_bps: u16,
}

/// Rental lifecycle: `Active` → `Returned` | `ReturnedLate` |
/// `Cancelled`. All three exits are terminal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RentalState {
    /// Custody is with the renter (or the term has not started yet —
    /// see [`RentalEscrow::is_in_term`]).
    #[default]
    Active,
    /// The asset returned to the owner on time (or with no late-fee
    /// schedule) — terminal.
    Returned,
    /// The asset returned after the term with a late-fee schedule —
    /// terminal.
    ReturnedLate,
    /// The owner cancelled before the term started — terminal.
    Cancelled,
}

/// The caller's receipt for [`RentalEscrow::return_asset`]: what the
/// Anchor program settles — the late fee (if any) the renter owes,
/// and the overdue bookkeeping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RentalReturn {
    /// Late fee due from the renter (`0` when on time or when no
    /// late-fee schedule was configured).
    pub late_fee_due: u64,
    /// Slots past `term_end_slot` (`0` when on time).
    pub overdue_slots: u64,
    /// Overdue days charged (ceiling of `overdue_slots /
    /// slots_per_day`; `0` when on time).
    pub overdue_days: u64,
    /// `true` when the return is past the term end.
    pub was_overdue: bool,
}

/// A time-boxed rental: the renter pays `rent_amount` for custody of
/// `asset_id` over `[term_start_slot, term_end_slot]`, after which
/// custody returns to the owner.
///
/// `asset_id` is the caller's placeholder for whatever the Anchor
/// program holds in custody (an NFT mint, a token account, …) — the
/// module models the *terms*, not the custody mechanism, exactly
/// like AV-187's [`MintDescriptor`](crate::NftMintDescriptor)
/// observer pattern. Construct with [`RentalEscrow::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RentalEscrow {
    owner: [u8; 32],
    renter: [u8; 32],
    asset_id: [u8; 32],
    rent_amount: u64,
    term_start_slot: u64,
    term_end_slot: u64,
    slots_per_day: u64,
    late_fee: Option<LateFeeTerms>,
    state: RentalState,
}

impl RentalEscrow {
    /// Open a rental.
    ///
    /// Refused (fail-closed, [`EscrowError::InvalidRentalTerms`],
    /// code 268) when the owner or renter key is zero, owner and
    /// renter are the same key (a self-lease is degenerate),
    /// `rent_amount == 0`, `term_end_slot <= term_start_slot` (an
    /// empty term), `slots_per_day == 0` (the overdue computation
    /// would divide by zero), or a late-fee rate/cap above 10_000
    /// bps (not a valid percentage).
    pub fn new(
        owner: [u8; 32],
        renter: [u8; 32],
        asset_id: [u8; 32],
        rent_amount: u64,
        term_start_slot: u64,
        term_end_slot: u64,
        slots_per_day: u64,
        late_fee: Option<LateFeeTerms>,
    ) -> Result<Self, EscrowError> {
        if owner == [0u8; 32]
            || renter == [0u8; 32]
            || owner == renter
            || rent_amount == 0
            || term_end_slot <= term_start_slot
            || slots_per_day == 0
        {
            return Err(EscrowError::InvalidRentalTerms);
        }
        if let Some(terms) = late_fee {
            if terms.bps_per_day > MAX_LATE_FEE_BPS || terms.cap_bps > MAX_LATE_FEE_BPS {
                return Err(EscrowError::InvalidRentalTerms);
            }
        }
        Ok(RentalEscrow {
            owner,
            renter,
            asset_id,
            rent_amount,
            term_start_slot,
            term_end_slot,
            slots_per_day,
            late_fee,
            state: RentalState::Active,
        })
    }

    /// The owner key.
    pub fn owner(&self) -> [u8; 32] {
        self.owner
    }

    /// The renter key.
    pub fn renter(&self) -> [u8; 32] {
        self.renter
    }

    /// The asset under custody.
    pub fn asset_id(&self) -> [u8; 32] {
        self.asset_id
    }

    /// The total rent for the term.
    pub fn rent_amount(&self) -> u64 {
        self.rent_amount
    }

    /// The slot the term starts.
    pub fn term_start_slot(&self) -> u64 {
        self.term_start_slot
    }

    /// The slot the term ends — the asset comes home after this.
    pub fn term_end_slot(&self) -> u64 {
        self.term_end_slot
    }

    /// Current lifecycle state.
    pub fn state(&self) -> RentalState {
        self.state
    }

    /// The configured late-fee schedule (`None` = opt-out).
    pub fn late_fee(&self) -> Option<LateFeeTerms> {
        self.late_fee
    }

    /// `true` while the term is live: `term_start_slot <=
    /// current_slot <= term_end_slot` (the end is inclusive — the
    /// renter has use through the closing slot).
    pub fn is_in_term(&self, current_slot: u64) -> bool {
        current_slot >= self.term_start_slot && current_slot <= self.term_end_slot
    }

    /// `true` past the term: `current_slot > term_end_slot`.
    pub fn is_overdue(&self, current_slot: u64) -> bool {
        current_slot > self.term_end_slot
    }

    /// The late fee due at `current_slot`, without changing state.
    /// Pure: `0` when on time or when no late-fee schedule is
    /// configured; otherwise `min(rent * bps_per_day / 10_000 *
    /// overdue_days, rent * cap_bps / 10_000)` where `overdue_days`
    /// is the ceiling of `overdue_slots / slots_per_day` (any partial
    /// day counts as a full day). Computed in `u128` — no overflow.
    pub fn late_fee_due(&self, current_slot: u64) -> u64 {
        let terms = match self.late_fee {
            Some(t) => t,
            None => return 0,
        };
        if !self.is_overdue(current_slot) {
            return 0;
        }
        let overdue_slots = current_slot - self.term_end_slot;
        let overdue_days =
            (overdue_slots as u128 + self.slots_per_day as u128 - 1) / self.slots_per_day as u128;
        let rent = self.rent_amount as u128;
        let per_day = rent * terms.bps_per_day as u128 / 10_000;
        let fee = per_day.saturating_mul(overdue_days);
        let cap = rent * terms.cap_bps as u128 / 10_000;
        fee.min(cap).min(u64::MAX as u128) as u64
    }

    /// Return the asset to the owner. Callable any time while the
    /// rental is `Active` — an early return is clean (the renter gave
    /// the asset back ahead of schedule); a return past the term is
    /// overdue and priced by the late-fee schedule.
    ///
    /// Refused ([`EscrowError::RentalNotActive`], code 269) once the
    /// rental is already in a terminal state. Returns a
    /// [`RentalReturn`] — the late fee the renter owes and the overdue
    /// bookkeeping — and moves the state to `Returned` (on time or no
    /// schedule) or `ReturnedLate` (overdue with a schedule).
    pub fn return_asset(&mut self, current_slot: u64) -> Result<RentalReturn, EscrowError> {
        if self.state != RentalState::Active {
            return Err(EscrowError::RentalNotActive);
        }
        let was_overdue = self.is_overdue(current_slot);
        let overdue_slots = if was_overdue {
            current_slot - self.term_end_slot
        } else {
            0
        };
        let overdue_days = if was_overdue {
            ((overdue_slots as u128 + self.slots_per_day as u128 - 1) / self.slots_per_day as u128)
                as u64
        } else {
            0
        };
        let receipt = RentalReturn {
            late_fee_due: self.late_fee_due(current_slot),
            overdue_slots,
            overdue_days,
            was_overdue,
        };
        self.state = if was_overdue && self.late_fee.is_some() {
            RentalState::ReturnedLate
        } else {
            RentalState::Returned
        };
        Ok(receipt)
    }

    /// The owner cancels the rental — only before the term starts
    /// (the renter has not taken custody yet).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// non-owner caller, and
    /// ([`EscrowError::RentalCancelNotAllowed`], code 270) once
    /// `term_start_slot` has passed (the renter has custody — the
    /// asset must be returned, not cancelled) or when the rental is
    /// already in a terminal state.
    pub fn cancel(&mut self, owner: [u8; 32], current_slot: u64) -> Result<(), EscrowError> {
        if owner != self.owner {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != RentalState::Active || current_slot >= self.term_start_slot {
            return Err(EscrowError::RentalCancelNotAllowed);
        }
        self.state = RentalState::Cancelled;
        Ok(())
    }

    /// Audit-event JSON for a return (hand-written):
    /// `{"event":"rental_returned","asset":"<64hex>","late_fee":<u64>,
    /// "overdue_days":<u64>,"late":<bool>}`.
    pub fn return_audit_json(&self, receipt: RentalReturn) -> String {
        let mut s = String::from("{\"event\":\"rental_returned\",\"asset\":\"");
        s.push_str(&hex64(&self.asset_id));
        s.push_str("\",\"late_fee\":");
        s.push_str(&receipt.late_fee_due.to_string());
        s.push_str(",\"overdue_days\":");
        s.push_str(&receipt.overdue_days.to_string());
        s.push_str(",\"late\":");
        s.push_str(&receipt.was_overdue.to_string());
        s.push('}');
        s
    }

    /// Audit-event JSON for a cancellation (hand-written):
    /// `{"event":"rental_cancelled","asset":"<64hex>"}`.
    pub fn cancel_audit_json(&self) -> String {
        let mut s = String::from("{\"event\":\"rental_cancelled\",\"asset\":\"");
        s.push_str(&hex64(&self.asset_id));
        s.push_str("\"}");
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
mod rental_escrow_tests {
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn terms() -> Option<LateFeeTerms> {
        // 100 bps/day = 1%/day, capped at 20% of rent.
        Some(LateFeeTerms {
            bps_per_day: 100,
            cap_bps: 2000,
        })
    }

    fn open_rental() -> RentalEscrow {
        // Rent 1_000_000 for slots [100, 200), 100 slots/day, with the
        // late-fee schedule above.
        RentalEscrow::new(key(0xAA), key(0xBB), key(0xCC), 1_000_000, 100, 200, 100, terms())
            .unwrap()
    }

    #[test]
    fn new_rejects_degenerate_terms() {
        let t = terms();
        // Zero owner.
        assert_eq!(
            RentalEscrow::new([0u8; 32], key(0xBB), key(0xCC), 1_000_000, 100, 200, 100, t)
                .unwrap_err(),
            EscrowError::InvalidRentalTerms
        );
        // Zero renter.
        assert_eq!(
            RentalEscrow::new(key(0xAA), [0u8; 32], key(0xCC), 1_000_000, 100, 200, 100, t)
                .unwrap_err(),
            EscrowError::InvalidRentalTerms
        );
        // Self-lease: owner == renter.
        assert_eq!(
            RentalEscrow::new(key(0xAA), key(0xAA), key(0xCC), 1_000_000, 100, 200, 100, t)
                .unwrap_err(),
            EscrowError::InvalidRentalTerms
        );
        // Zero rent.
        assert_eq!(
            RentalEscrow::new(key(0xAA), key(0xBB), key(0xCC), 0, 100, 200, 100, t).unwrap_err(),
            EscrowError::InvalidRentalTerms
        );
        // Empty term.
        assert_eq!(
            RentalEscrow::new(key(0xAA), key(0xBB), key(0xCC), 1_000_000, 200, 200, 100, t)
                .unwrap_err(),
            EscrowError::InvalidRentalTerms
        );
        // Zero slots_per_day — the overdue computation would divide
        // by zero.
        assert_eq!(
            RentalEscrow::new(key(0xAA), key(0xBB), key(0xCC), 1_000_000, 100, 200, 0, t)
                .unwrap_err(),
            EscrowError::InvalidRentalTerms
        );
        // Rate above 100%.
        let bad = Some(LateFeeTerms {
            bps_per_day: 10_001,
            cap_bps: 2000,
        });
        assert_eq!(
            RentalEscrow::new(key(0xAA), key(0xBB), key(0xCC), 1_000_000, 100, 200, 100, bad)
                .unwrap_err(),
            EscrowError::InvalidRentalTerms
        );
        // Cap above 100%.
        let bad = Some(LateFeeTerms {
            bps_per_day: 100,
            cap_bps: 10_001,
        });
        assert_eq!(
            RentalEscrow::new(key(0xAA), key(0xBB), key(0xCC), 1_000_000, 100, 200, 100, bad)
                .unwrap_err(),
            EscrowError::InvalidRentalTerms
        );
        let err = EscrowError::InvalidRentalTerms;
        assert_eq!(err.code(), 268);
        assert!(EscrowError::all().contains(&err));
    }

    #[test]
    fn clean_return_mid_term_and_at_term_end() {
        let mut r = open_rental();
        assert!(r.is_in_term(150));
        assert!(!r.is_overdue(150));
        let receipt = r.return_asset(150).unwrap();
        assert_eq!(receipt.late_fee_due, 0);
        assert_eq!(receipt.overdue_slots, 0);
        assert!(!receipt.was_overdue);
        assert_eq!(r.state(), RentalState::Returned);
        // The term end is inclusive: returning exactly at term_end is
        // still on time.
        let mut r2 = open_rental();
        let receipt = r2.return_asset(200).unwrap();
        assert_eq!(receipt.late_fee_due, 0);
        assert!(!receipt.was_overdue);
        assert_eq!(r2.state(), RentalState::Returned);
    }

    #[test]
    fn early_return_is_clean() {
        // Returning before the term even starts: the renter gave the
        // asset back ahead of schedule — no fee, clean state.
        let mut r = open_rental();
        assert!(!r.is_in_term(50));
        let receipt = r.return_asset(50).unwrap();
        assert_eq!(receipt.late_fee_due, 0);
        assert_eq!(r.state(), RentalState::Returned);
    }

    #[test]
    fn one_overdue_day_charges_one_day() {
        let mut r = open_rental();
        // 100 slots past the end with 100 slots/day = exactly 1 day:
        // 1_000_000 * 100 / 10_000 = 10_000.
        let receipt = r.return_asset(300).unwrap();
        assert!(receipt.was_overdue);
        assert_eq!(receipt.overdue_slots, 100);
        assert_eq!(receipt.overdue_days, 1);
        assert_eq!(receipt.late_fee_due, 10_000);
        assert_eq!(r.state(), RentalState::ReturnedLate);
        let j = r.return_audit_json(receipt);
        assert!(j.contains("\"event\":\"rental_returned\""));
        assert!(j.contains("\"late_fee\":10000"));
        assert!(j.contains("\"overdue_days\":1"));
        assert!(j.contains("\"late\":true"));
    }

    #[test]
    fn partial_day_rounds_up_to_a_full_day() {
        let mut r = open_rental();
        // 101 overdue slots with 100 slots/day = 2 charged days.
        let receipt = r.return_asset(301).unwrap();
        assert_eq!(receipt.overdue_days, 2);
        assert_eq!(receipt.late_fee_due, 20_000);
        assert_eq!(r.state(), RentalState::ReturnedLate);
    }

    #[test]
    fn late_fee_is_capped() {
        let mut r = open_rental();
        // 3000 overdue slots = 30 days uncapped: 30 * 10_000 =
        // 300_000 — but the cap is 20% of 1_000_000 = 200_000.
        let receipt = r.return_asset(3200).unwrap();
        assert_eq!(receipt.overdue_days, 30);
        assert_eq!(receipt.late_fee_due, 200_000);
        assert_eq!(r.state(), RentalState::ReturnedLate);
    }

    #[test]
    fn opt_out_schedule_never_charges_but_still_marks_returned() {
        let mut r =
            RentalEscrow::new(key(0xAA), key(0xBB), key(0xCC), 1_000_000, 100, 200, 100, None)
                .unwrap();
        assert_eq!(r.late_fee_due(9999), 0);
        let receipt = r.return_asset(9999).unwrap();
        assert!(receipt.was_overdue);
        assert_eq!(receipt.late_fee_due, 0);
        // No schedule: the return is recorded clean even though late.
        assert_eq!(r.state(), RentalState::Returned);
    }

    #[test]
    fn return_on_terminal_state_is_rejected() {
        let mut r = open_rental();
        r.return_asset(150).unwrap();
        let err = r.return_asset(150).unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(err.code(), 269);
        // ...and a cancelled rental cannot be returned either.
        let mut r2 = open_rental();
        r2.cancel(key(0xAA), 50).unwrap();
        let err = r2.return_asset(50).unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
    }

    #[test]
    fn cancel_before_term_start_only() {
        let mut r = open_rental();
        r.cancel(key(0xAA), 99).unwrap();
        assert_eq!(r.state(), RentalState::Cancelled);
        let j = r.cancel_audit_json();
        assert!(j.contains("\"event\":\"rental_cancelled\""));
        // Terminal: a second cancel is refused.
        let err = r.cancel(key(0xAA), 99).unwrap_err();
        assert_eq!(err, EscrowError::RentalCancelNotAllowed);
        assert_eq!(err.code(), 270);
    }

    #[test]
    fn cancel_is_owner_only_and_never_after_term_start() {
        let mut r = open_rental();
        // A stranger cannot cancel.
        let err = r.cancel(key(9), 50).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        // Once the term starts the renter has custody — return, don't
        // cancel.
        let err = r.cancel(key(0xAA), 100).unwrap_err();
        assert_eq!(err, EscrowError::RentalCancelNotAllowed);
        assert_eq!(r.state(), RentalState::Active);
        // ...and after an on-time return the rental is terminal.
        r.return_asset(150).unwrap();
        let err = r.cancel(key(0xAA), 150).unwrap_err();
        assert_eq!(err, EscrowError::RentalCancelNotAllowed);
    }

    #[test]
    fn late_fee_due_is_pure_and_gated() {
        let r = open_rental();
        // Pure: calling it twice changes nothing.
        assert_eq!(r.late_fee_due(300), 10_000);
        assert_eq!(r.late_fee_due(300), 10_000);
        assert_eq!(r.state(), RentalState::Active);
        // No fee before or at the term end.
        assert_eq!(r.late_fee_due(99), 0);
        assert_eq!(r.late_fee_due(200), 0);
        // One slot past the end: 1 overdue slot = 1 charged day.
        assert_eq!(r.late_fee_due(201), 10_000);
    }

    #[test]
    fn error_codes_pinned() {
        // Never renumber: the Anchor layer assigns one program error
        // per variant and off-chain clients match on these numbers.
        assert_eq!(EscrowError::InvalidRentalTerms.code(), 268);
        assert_eq!(EscrowError::RentalNotActive.code(), 269);
        assert_eq!(EscrowError::RentalCancelNotAllowed.code(), 270);
        for e in [
            EscrowError::InvalidRentalTerms,
            EscrowError::RentalNotActive,
            EscrowError::RentalCancelNotAllowed,
        ] {
            assert!(EscrowError::all().contains(&e));
        }
        assert_eq!(EscrowError::all().len(), 247); // AV-195: +7 social-recovery errors, AV-196: +6 jury-sortition errors, AV-197: +5 payment-channel errors; AV-209: +4; AV-214: +6; AV-215: +1; AV-217: +3; AV-218: +2; AV-220: +1; AV-225: +1
    }
}
