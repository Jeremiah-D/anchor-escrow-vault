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

    /// Slots per day — the pace the overdue-day computation divides
    /// by ([`RentalEscrow::late_fee_due`], [`RentalEscrow::return_asset`]).
    pub fn slots_per_day(&self) -> u64 {
        self.slots_per_day
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

    /// Revise the late-fee schedule on an `Active` rental (AV-291 —
    /// Solana rental governance): both parties authorize the change
    /// (the late fee is a bilateral economic term — a unilateral
    /// rewrite would let one side reprice the other's overdue cost
    /// alone). Check order is authority → state, mirroring AV-284's
    /// `NftEscrow` precedent, so a stranger learns nothing about
    /// the rental's state from the error alone.
    ///
    /// Why: the schedule is fixed at construction
    /// ([`RentalEscrow::new`]), but the parties may renegotiate the
    /// overdue price mid-term — a schedule that cannot be revised
    /// would either strand the renter under a stale rate or force a
    /// fresh rental (and a fresh custody transfer) for a legitimate
    /// new rate. Only an `Active` rental may revise: a returned or
    /// cancelled rental is terminal, so revising it could never
    /// govern a future return, and a fee already settled by
    /// `return_asset` is never restated.
    ///
    /// The new schedule reuses the [`RentalEscrow::new`] gate
    /// exactly: a rate or cap above 10_000 bps fails closed with
    /// [`EscrowError::InvalidRentalTerms`] (code 268), leaving the
    /// current schedule untouched, because the new terms are
    /// validated before any write. An explicit `None` clears the
    /// schedule back to opt-out (the `new` `None` = opt-out
    /// precedent) — after clearing, overdue returns are free but
    /// still recorded as late. Re-affirming the current schedule is
    /// a no-op that writes nothing. Only `late_fee` changes — the
    /// owner, renter, asset, rent amount, term slots,
    /// `slots_per_day`, and state are untouched — and
    /// [`RentalEscrow::late_fee_due`] / [`RentalEscrow::return_asset`]
    /// read the live schedule, so the new terms govern from the
    /// next billing; a return already executed is unaffected. There
    /// is no event layer on `RentalEscrow`, so no event is emitted
    /// for the revision or its no-op. Orthogonal to
    /// [`RentalEscrow::new`] (that installs the schedule at build
    /// time, this revises it while `Active`) and to AV-190 (that is
    /// the rental mechanism itself, this is its terms revision).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller pair that is not exactly owner + renter, and
    /// ([`EscrowError::RentalNotActive`], code 269) once the rental
    /// is in a terminal state.
    pub fn amend_late_fee(
        &mut self,
        owner: [u8; 32],
        renter: [u8; 32],
        late_fee: Option<LateFeeTerms>,
    ) -> Result<(), EscrowError> {
        if owner != self.owner || renter != self.renter {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != RentalState::Active {
            return Err(EscrowError::RentalNotActive);
        }
        if let Some(terms) = late_fee {
            if terms.bps_per_day > MAX_LATE_FEE_BPS || terms.cap_bps > MAX_LATE_FEE_BPS {
                return Err(EscrowError::InvalidRentalTerms);
            }
        }
        self.late_fee = late_fee;
        Ok(())
    }

    /// Extend the term end on an `Active` rental (AV-292 — Solana
    /// rental governance): both parties authorize the change (the
    /// term is a bilateral use-right window — a unilateral extension
    /// would let one side stretch the other's custody or use
    /// alone). Check order is authority → state → window, mirroring
    /// AV-284's `NftEscrow` precedent, so a stranger learns nothing
    /// about the rental's state from the error alone.
    ///
    /// Why: the window is fixed at construction
    /// ([`RentalEscrow::new`]), but the parties may agree to keep
    /// the asset out longer — a window that cannot be extended
    /// would force a fresh rental (and a fresh custody transfer)
    /// for a legitimate longer stay. Only an `Active` rental may
    /// extend, and only while it is not yet overdue: an overdue
    /// rental's fee has already been accruing against the old
    /// window, so extending that window would retroactively erase
    /// accrued overdue days. Extension only, never shrinkage: the
    /// new end must lie strictly past the current end, so an
    /// equal-value call is not a re-affirmation but an invalid
    /// extension. Only `term_end_slot` changes — the rent amount
    /// is not repriced (the same total rent covers the longer
    /// window, confirmed by both signatures), and the term start,
    /// `slots_per_day`, late fee, and state are untouched — and
    /// [`RentalEscrow::is_in_term`], [`RentalEscrow::is_overdue`],
    /// [`RentalEscrow::late_fee_due`], and
    /// [`RentalEscrow::return_asset`] read the live window, so the
    /// new window governs from the revision (a term already counted
    /// as overdue is re-judged against the new end; a return
    /// already executed is unaffected). There is no event layer on
    /// `RentalEscrow`, so no event is emitted for the extension.
    /// Orthogonal to [`RentalEscrow::new`] (that installs the window
    /// at build time, this extends it while `Active`), to AV-190
    /// (that is the rental mechanism itself, this is its window
    /// revision), and to AV-291 (that revises the late-fee terms,
    /// this revises the term window).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller pair that is not exactly owner + renter,
    /// ([`EscrowError::RentalNotActive`], code 269) once the rental
    /// is in a terminal state, and
    /// ([`EscrowError::InvalidRentalTerms`], code 268) when the
    /// rental is already overdue at `current_slot` or when
    /// `new_end_slot` does not lie strictly past the current term
    /// end — either way the current window is untouched.
    pub fn extend_term_end(
        &mut self,
        owner: [u8; 32],
        renter: [u8; 32],
        new_end_slot: u64,
        current_slot: u64,
    ) -> Result<(), EscrowError> {
        if owner != self.owner || renter != self.renter {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != RentalState::Active {
            return Err(EscrowError::RentalNotActive);
        }
        if current_slot > self.term_end_slot {
            return Err(EscrowError::InvalidRentalTerms);
        }
        if new_end_slot <= self.term_end_slot {
            return Err(EscrowError::InvalidRentalTerms);
        }
        self.term_end_slot = new_end_slot;
        Ok(())
    }

    /// Revise the rent amount on an `Active` rental (AV-314 —
    /// Solana rental governance): both parties authorize the change
    /// (the rent is a bilateral economic term — a unilateral
    /// rewrite would let one side reprice the other's custody cost
    /// alone). Check order is authority → state → window → value,
    /// mirroring AV-292's `extend_term_end`, so a stranger learns
    /// nothing about the rental's state from the error alone.
    ///
    /// Why: the rent is fixed at construction
    /// ([`RentalEscrow::new`]), but the parties may renegotiate the
    /// price before the term starts — a rent that cannot be revised
    /// would force a fresh rental (and a fresh custody transfer)
    /// for a legitimate new price. Only an `Active` rental may
    /// revise, and only before the term starts: once the term has
    /// begun the rent corresponds to use already consumed (and
    /// possibly already prepaid), and repricing it would only
    /// rebase the late-fee computation on consumed use. Before the
    /// start there is no consumed use and no accrued fee, so a
    /// renegotiated rent is a clean re-price.
    ///
    /// The new rent reuses the [`RentalEscrow::new`] gate exactly:
    /// a zero rent fails closed with
    /// [`EscrowError::InvalidRentalTerms`] (code 268), leaving the
    /// current rent untouched, because the new value is validated
    /// before any write. Re-affirming the current rent is a no-op
    /// that writes nothing. Only `rent_amount` changes — the owner,
    /// renter, asset, term slots, `slots_per_day`, late fee, and
    /// state are untouched — and [`RentalEscrow::late_fee_due`] /
    /// [`RentalEscrow::return_asset`] read the live rent, so the new
    /// rent governs from the next billing (both the per-day fee and
    /// the cap scale with it); a return already executed is
    /// unaffected. There is no event layer on `RentalEscrow`, so no
    /// event is emitted for the revision or its no-op. No new error
    /// code: the refusals reuse `Unauthorized` (100),
    /// `RentalNotActive` (269), and `InvalidRentalTerms` (268).
    /// Orthogonal to [`RentalEscrow::new`] (that installs the rent
    /// at build time, this revises it while `Active` and
    /// pre-term), to AV-190 (that is the rental mechanism itself,
    /// this is its rent revision), to AV-291 (that revises the
    /// late-fee terms, this revises the rent), and to AV-292 (that
    /// extends the term window, this revises the rent).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller pair that is not exactly owner + renter,
    /// ([`EscrowError::RentalNotActive`], code 269) once the rental
    /// is in a terminal state, and
    /// ([`EscrowError::InvalidRentalTerms`], code 268) once
    /// `term_start_slot` has arrived or when the new rent is zero —
    /// either way the current rent is untouched.
    pub fn amend_rent_amount(
        &mut self,
        owner: [u8; 32],
        renter: [u8; 32],
        new_rent_amount: u64,
        current_slot: u64,
    ) -> Result<(), EscrowError> {
        if owner != self.owner || renter != self.renter {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != RentalState::Active {
            return Err(EscrowError::RentalNotActive);
        }
        if current_slot >= self.term_start_slot {
            return Err(EscrowError::InvalidRentalTerms);
        }
        if new_rent_amount == 0 {
            return Err(EscrowError::InvalidRentalTerms);
        }
        self.rent_amount = new_rent_amount;
        Ok(())
    }

    /// Revise the overdue-day pace on an `Active` rental (AV-329 —
    /// Solana rental governance): both parties authorize the change
    /// (the pace is a bilateral economic term — a unilateral rewrite
    /// would let one side reprice the other's overdue cost alone).
    /// Check order is authority → state → window → value, mirroring
    /// AV-314's `amend_rent_amount`, so a stranger learns nothing
    /// about the rental's state from the error alone.
    ///
    /// Why: the pace is fixed at construction
    /// ([`RentalEscrow::new`]), but the parties may renegotiate how
    /// fast overdue days accrue before the term starts — a pace that
    /// cannot be revised would force a fresh rental (and a fresh
    /// custody transfer) for a legitimate new day length. Only an
    /// `Active` rental may revise, and only before the term starts:
    /// once the term has begun fees have been accruing against the
    /// old pace, and repricing it would rebase the overdue-day
    /// count on consumed use. Before the start there is no consumed
    /// use and no accrued fee, so a renegotiated pace is a clean
    /// re-price.
    ///
    /// The new pace reuses the [`RentalEscrow::new`] gate exactly:
    /// a zero pace fails closed with
    /// [`EscrowError::InvalidRentalTerms`] (code 268), leaving the
    /// current pace untouched, because the new value is validated
    /// before any write. Re-affirming the current pace is a no-op
    /// that writes nothing. Only `slots_per_day` changes — the
    /// owner, renter, asset, rent amount, term slots, late fee, and
    /// state are untouched — and [`RentalEscrow::late_fee_due`] /
    /// [`RentalEscrow::return_asset`] read the live pace, so the new
    /// pace governs from the next billing (the ceiling division
    /// `overdue_slots / slots_per_day` reprices both the day count
    /// and the fee); a return already executed is unaffected. There
    /// is no event layer on `RentalEscrow`, so no event is emitted
    /// for the revision or its no-op. No new error code: the
    /// refusals reuse `Unauthorized` (100), `RentalNotActive`
    /// (269), and `InvalidRentalTerms` (268). Orthogonal to
    /// [`RentalEscrow::new`] (that installs the pace at build time,
    /// this revises it while `Active` and pre-term), to AV-190
    /// (that is the rental mechanism itself, this is its pace
    /// revision), to AV-291 (that revises the late-fee terms, this
    /// revises the pace those terms divide by), to AV-292 (that
    /// extends the term window, this revises the pace), and to
    /// AV-314 (that revises the rent, this revises the pace).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller pair that is not exactly owner + renter,
    /// ([`EscrowError::RentalNotActive`], code 269) once the rental
    /// is in a terminal state, and
    /// ([`EscrowError::InvalidRentalTerms`], code 268) once
    /// `term_start_slot` has arrived or when the new pace is zero —
    /// either way the current pace is untouched.
    pub fn amend_slots_per_day(
        &mut self,
        owner: [u8; 32],
        renter: [u8; 32],
        new_slots_per_day: u64,
        current_slot: u64,
    ) -> Result<(), EscrowError> {
        if owner != self.owner || renter != self.renter {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != RentalState::Active {
            return Err(EscrowError::RentalNotActive);
        }
        if current_slot >= self.term_start_slot {
            return Err(EscrowError::InvalidRentalTerms);
        }
        if new_slots_per_day == 0 {
            return Err(EscrowError::InvalidRentalTerms);
        }
        self.slots_per_day = new_slots_per_day;
        Ok(())
    }

    /// Revise the term start slot on an `Active` rental (AV-330 —
    /// Solana rental governance): both parties authorize the change
    /// (the term window is a bilateral use-right window — a
    /// unilateral shift would let one side move the other's custody
    /// or use alone). Check order is authority → state → window →
    /// value, mirroring AV-314's `amend_rent_amount`, so a stranger
    /// learns nothing about the rental's state from the error alone.
    ///
    /// Why: the start is fixed at construction
    /// ([`RentalEscrow::new`]), but the parties may agree to move
    /// the term — a start that cannot be revised would force a fresh
    /// rental (and a fresh custody transfer) for a legitimate
    /// reschedule. Only an `Active` rental may revise, and only
    /// before the term starts: once the term has begun the renter
    /// has taken custody, and moving the start would retroactively
    /// rewrite use already consumed. Before the start there is no
    /// consumed use and no accrued fee, so a rescheduled start is a
    /// clean move.
    ///
    /// The new start must lie strictly in the future and strictly
    /// before the term end: `current_slot < new_term_start_slot <
    /// term_end_slot`. A start at or behind the current slot fails
    /// closed with [`EscrowError::InvalidRentalTerms`] (code 268) —
    /// a revised term must still be in the future, otherwise the
    /// revision would backdate the opening and instantly kill the
    /// cancellation window (the AV-304 future-slot gate) — and a
    /// start at or past the term end reuses the [`RentalEscrow::new`]
    /// empty-term gate (code 268), leaving the current start
    /// untouched, because the new value is validated before any
    /// write. Re-affirming the current start is a no-op that writes
    /// nothing — but the no-op check sits after the window gate, so
    /// a same-value call at or after the term start is still refused
    /// (code 268), following AV-314's gate order. Only
    /// `term_start_slot` changes — the owner, renter, asset, rent
    /// amount, term end, `slots_per_day`, late fee, and state are
    /// untouched — and [`RentalEscrow::is_in_term`],
    /// [`RentalEscrow::cancel`], [`RentalEscrow::amend_rent_amount`],
    /// and [`RentalEscrow::amend_slots_per_day`] all read the live
    /// start, so the new start governs from the next evaluation:
    /// delaying it pushes the term (and widens the cancellation and
    /// pre-start revision windows), advancing it pulls the term
    /// forward (and narrows them); [`RentalEscrow::late_fee_due`] /
    /// [`RentalEscrow::return_asset`] are unaffected — they only read
    /// `term_end_slot`. A return already executed is unaffected.
    /// There is no event layer on `RentalEscrow`, so no event is
    /// emitted for the revision or its no-op. No new error code: the
    /// refusals reuse `Unauthorized` (100), `RentalNotActive`
    /// (269), and `InvalidRentalTerms` (268). Orthogonal to
    /// [`RentalEscrow::new`] (that installs the start at build time,
    /// this revises it while `Active` and pre-term), to AV-190 (that
    /// is the rental mechanism itself, this is its window revision),
    /// to AV-291 (that revises the late-fee terms, this revises the
    /// window), to AV-292 (that only extends `term_end_slot` and
    /// leaves the start untouched, this only moves the start), to
    /// AV-314 (that revises the rent, this revises the start the
    /// rent's pre-start gate reads), and to AV-329 (that revises
    /// the pace, this revises the start the pace's pre-start gate
    /// reads).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller pair that is not exactly owner + renter,
    /// ([`EscrowError::RentalNotActive`], code 269) once the rental
    /// is in a terminal state, and
    /// ([`EscrowError::InvalidRentalTerms`], code 268) once
    /// `term_start_slot` has arrived, when the new start is at or
    /// behind `current_slot`, or when the new start is at or past
    /// `term_end_slot` — either way the current start is untouched.
    pub fn amend_term_start_slot(
        &mut self,
        owner: [u8; 32],
        renter: [u8; 32],
        new_term_start_slot: u64,
        current_slot: u64,
    ) -> Result<(), EscrowError> {
        if owner != self.owner || renter != self.renter {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != RentalState::Active {
            return Err(EscrowError::RentalNotActive);
        }
        if current_slot >= self.term_start_slot {
            return Err(EscrowError::InvalidRentalTerms);
        }
        if new_term_start_slot <= current_slot {
            return Err(EscrowError::InvalidRentalTerms);
        }
        if new_term_start_slot >= self.term_end_slot {
            return Err(EscrowError::InvalidRentalTerms);
        }
        self.term_start_slot = new_term_start_slot;
        Ok(())
    }

    /// Shorten the term end on an `Active` rental (AV-331 —
    /// Solana rental governance): both parties authorize the change
    /// (the term is a bilateral use-right window — a unilateral
    /// cut would let one side pull the other's custody or use
    /// alone). Check order is authority → state → window → value,
    /// mirroring AV-292's `extend_term_end`, so a stranger learns
    /// nothing about the rental's state from the error alone.
    ///
    /// Why: the end is fixed at construction
    /// ([`RentalEscrow::new`]) and [`RentalEscrow::extend_term_end`]
    /// only ever moves it later, so a term that needs to end early
    /// — the renter hands the asset back ahead of schedule, the
    /// owner reclaims it, or the parties renegotiate a shorter
    /// lease — would force a fresh rental (and a fresh custody
    /// transfer) for a legitimate early close. Only an `Active`
    /// rental may shorten, and the new end must still lie in the
    /// future-or-now and strictly inside the current window:
    /// `term_start_slot < new_end_slot < term_end_slot` with
    /// `current_slot <= new_end_slot`.
    ///
    /// The window gate is the mirror of AV-292's "already overdue,
    /// no extension": shortening must not retroactively manufacture
    /// overdue time. A new end behind `current_slot` would turn use
    /// already consumed under the old window into overdue days at a
    /// stroke — the fee has already been accruing against the old
    /// window, so the cut would conjure overdue days out of use
    /// that was in term when it happened — hence
    /// `current_slot > new_end_slot` fails closed with
    /// [`EscrowError::InvalidRentalTerms`] (code 268). The boundary
    /// is inclusive, matching [`RentalEscrow::is_in_term`]: a new
    /// end exactly at `current_slot` is still in term, so the
    /// rental stays live and the cut is allowed. Growing the window
    /// is [`RentalEscrow::extend_term_end`]'s job, so a new end at
    /// or past the current end fails closed with code 268 too — an
    /// equal-value call is not a re-affirmation but an invalid
    /// shortening — and a new end at or before the term start
    /// reuses the [`RentalEscrow::new`] empty-term gate (code 268),
    /// leaving the current end untouched, because the new value is
    /// validated before any write.
    ///
    /// Only `term_end_slot` changes — the rent amount is not
    /// repriced (the same total rent covers the shorter window,
    /// confirmed by both signatures), and the owner, renter, asset,
    /// term start, `slots_per_day`, late fee, and state are
    /// untouched — and [`RentalEscrow::is_in_term`],
    /// [`RentalEscrow::is_overdue`], [`RentalEscrow::late_fee_due`],
    /// and [`RentalEscrow::return_asset`] read the live window, so
    /// the new window governs from the revision: a return past the
    /// new end is overdue and priced against the live late-fee
    /// terms, while a rental still at or before the new end stays
    /// in term and does not turn overdue on the spot; a return
    /// already executed is unaffected. There is no event layer on
    /// `RentalEscrow`, so no event is emitted for the shortening.
    /// No new error code: the refusals reuse `Unauthorized` (100),
    /// `RentalNotActive` (269), and `InvalidRentalTerms` (268).
    /// Orthogonal to [`RentalEscrow::new`] (that installs the window
    /// at build time, this shortens it while `Active`), to AV-190
    /// (that is the rental mechanism itself, this is its window
    /// revision), to AV-291 (that revises the late-fee terms, this
    /// revises the term window), to AV-292 (that only extends
    /// `term_end_slot`, this only shortens it — the opposite
    /// direction on the same field, each an independent method and
    /// mutually exclusive per call), to AV-314 (that revises the
    /// rent, this revises the window), to AV-329 (that revises the
    /// pace, this revises the window), and to AV-330 (that moves
    /// the term start, this moves the term end).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller pair that is not exactly owner + renter,
    /// ([`EscrowError::RentalNotActive`], code 269) once the rental
    /// is in a terminal state, and
    /// ([`EscrowError::InvalidRentalTerms`], code 268) when
    /// `current_slot` is already past the new end, when the new end
    /// is at or past the current term end, or when the new end is
    /// at or before the term start — either way the current window
    /// is untouched.
    pub fn shorten_term_end(
        &mut self,
        owner: [u8; 32],
        renter: [u8; 32],
        new_end_slot: u64,
        current_slot: u64,
    ) -> Result<(), EscrowError> {
        if owner != self.owner || renter != self.renter {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != RentalState::Active {
            return Err(EscrowError::RentalNotActive);
        }
        if current_slot > new_end_slot {
            return Err(EscrowError::InvalidRentalTerms);
        }
        if new_end_slot >= self.term_end_slot {
            return Err(EscrowError::InvalidRentalTerms);
        }
        if new_end_slot <= self.term_start_slot {
            return Err(EscrowError::InvalidRentalTerms);
        }
        self.term_end_slot = new_end_slot;
        Ok(())
    }

    /// Revise the asset identifier on an `Active` rental before the
    /// term starts (AV-332 — Solana rental governance): both parties
    /// authorize the change (the asset is a bilaterally escrowed
    /// subject — a unilateral rewrite would let one side swap the
    /// escrowed item for another alone). Check order is authority →
    /// state → window → value, mirroring AV-330's
    /// `amend_term_start_slot`, so a stranger learns nothing about
    /// the rental's state from the error alone.
    ///
    /// Why: the asset id is fixed at construction
    /// ([`RentalEscrow::new`]) and there is no other revision entry
    /// point, so a rental opened against the wrong asset — a mistyped
    /// NFT mint, the wrong token account, or the parties renegotiating
    /// to lease a different item — would force the owner to cancel
    /// the rental (pre-term only) and open a fresh one with a fresh
    /// custody transfer, or else return settlement and the audit trail
    /// would attribute the return to the wrong asset. Only an
    /// `Active` rental may revise the asset, and only before the term
    /// starts: once the term has begun the renter physically holds
    /// the original asset, so swapping the id would point return
    /// settlement and audit at an asset that was never escrowed;
    /// before the start nobody holds it and no fee has accrued, so
    /// the swap is a clean redirect.
    ///
    /// The value gate is new in this item and deliberately asymmetric
    /// with [`RentalEscrow::new`], which does not validate `asset_id`
    /// (a placeholder id, even the zero id, may open a rental):
    /// revision refuses a zero `new_asset_id` with
    /// [`EscrowError::InvalidRentalTerms`] (code 268), failing closed
    /// rather than letting the parties blank the escrowed identifier
    /// into "no asset" while rent and late-fee terms keep accruing.
    /// Restating the current asset is a no-op — but the no-op check
    /// sits after the window gate, following AV-330's gate order, so
    /// a same-value restatement after the term has started is still
    /// refused with code 268.
    ///
    /// Only `asset_id` changes — the owner, renter, rent amount,
    /// term start, term end, `slots_per_day`, late fee, and state are
    /// untouched — and [`RentalEscrow::return_audit_json`] and
    /// [`RentalEscrow::cancel_audit_json`] read the live asset id, so
    /// the new asset governs from the next audit: a return or cancel
    /// after the revision carries the new asset hex, while a return
    /// already executed is unaffected (its JSON string is already on
    /// disk); [`RentalEscrow::late_fee_due`] and
    /// [`RentalEscrow::return_asset`] never read `asset_id`, so fee
    /// math is unaffected by the change. There is no event layer on
    /// `RentalEscrow`, so no event is emitted for the revision.
    /// No new error code: the refusals reuse `Unauthorized` (100),
    /// `RentalNotActive` (269), and `InvalidRentalTerms` (268).
    /// Orthogonal to [`RentalEscrow::new`] (that installs the asset
    /// at build time, this revises it while `Active` and pre-term),
    /// to AV-190 (that is the rental mechanism itself, this is its
    /// asset revision), to AV-187 (that transfers NFT ownership,
    /// this revises the use-right escrow's asset placeholder and
    /// never touches ownership), to AV-291 (that revises the late-fee
    /// terms, this revises the asset), to AV-292 (that extends the
    /// term end, this revises the asset), to AV-314 (that revises the
    /// rent, this revises the asset), to AV-329 (that revises the
    /// pace, this revises the asset), to AV-330 (that moves the term
    /// start, this revises the asset), and to AV-331 (that shortens
    /// the term end, this revises the asset).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller pair that is not exactly owner + renter,
    /// ([`EscrowError::RentalNotActive`], code 269) once the rental
    /// is in a terminal state, and
    /// ([`EscrowError::InvalidRentalTerms`], code 268) once
    /// `term_start_slot` has arrived, or when the new asset id is
    /// the zero key — either way the current asset is untouched.
    pub fn amend_asset_id(
        &mut self,
        owner: [u8; 32],
        renter: [u8; 32],
        new_asset_id: [u8; 32],
        current_slot: u64,
    ) -> Result<(), EscrowError> {
        if owner != self.owner || renter != self.renter {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != RentalState::Active {
            return Err(EscrowError::RentalNotActive);
        }
        if current_slot >= self.term_start_slot {
            return Err(EscrowError::InvalidRentalTerms);
        }
        if new_asset_id == [0u8; 32] {
            return Err(EscrowError::InvalidRentalTerms);
        }
        if new_asset_id == self.asset_id {
            return Ok(());
        }
        self.asset_id = new_asset_id;
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
    fn amend_late_fee_revises_the_live_schedule() {
        // AV-291: dual-signed revision reprices future billings only.
        let mut r = open_rental();
        assert_eq!(r.late_fee_due(300), 10_000);
        r.amend_late_fee(
            key(0xAA),
            key(0xBB),
            Some(LateFeeTerms {
                bps_per_day: 200,
                cap_bps: 5000,
            }),
        )
        .unwrap();
        assert_eq!(
            r.late_fee(),
            Some(LateFeeTerms {
                bps_per_day: 200,
                cap_bps: 5000,
            })
        );
        // The live schedule prices the same overdue slot: 2%/day now.
        assert_eq!(r.late_fee_due(300), 20_000);
        // Nothing else moved.
        assert_eq!(r.owner(), key(0xAA));
        assert_eq!(r.renter(), key(0xBB));
        assert_eq!(r.asset_id(), key(0xCC));
        assert_eq!(r.rent_amount(), 1_000_000);
        assert_eq!(r.term_start_slot(), 100);
        assert_eq!(r.term_end_slot(), 200);
        assert_eq!(r.state(), RentalState::Active);
        // The amended schedule governs the return settlement.
        let receipt = r.return_asset(300).unwrap();
        assert_eq!(receipt.late_fee_due, 20_000);
        assert_eq!(r.state(), RentalState::ReturnedLate);
    }

    #[test]
    fn amend_late_fee_clear_to_none_opts_out() {
        // AV-291: an explicit None clears back to no late fee.
        let mut r = open_rental();
        r.amend_late_fee(key(0xAA), key(0xBB), None).unwrap();
        assert_eq!(r.late_fee(), None);
        assert_eq!(r.late_fee_due(9999), 0);
        let receipt = r.return_asset(9999).unwrap();
        assert!(receipt.was_overdue);
        assert_eq!(receipt.late_fee_due, 0);
        // No schedule: recorded clean even though late.
        assert_eq!(r.state(), RentalState::Returned);
    }

    #[test]
    fn amend_late_fee_is_dual_signed() {
        // AV-291: a stranger, or either party alone, is refused and
        // the schedule is untouched.
        let mut r = open_rental();
        let err = r
            .amend_late_fee(key(9), key(0xBB), None)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = r
            .amend_late_fee(
                key(0xAA),
                key(9),
                Some(LateFeeTerms {
                    bps_per_day: 200,
                    cap_bps: 5000,
                }),
            )
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = r
            .amend_late_fee(
                key(9),
                key(9),
                Some(LateFeeTerms {
                    bps_per_day: 200,
                    cap_bps: 5000,
                }),
            )
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        assert_eq!(r.late_fee(), terms());
        // Authority is checked before state: a stranger on a
        // terminal rental still gets Unauthorized, not RentalNotActive.
        let mut r2 = open_rental();
        r2.return_asset(150).unwrap();
        let err = r2.amend_late_fee(key(9), key(0xBB), None).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
    }

    #[test]
    fn amend_late_fee_rejects_terminal_rentals() {
        // AV-291: Returned / ReturnedLate / Cancelled are terminal.
        let mut r = open_rental();
        r.return_asset(150).unwrap();
        let err = r.amend_late_fee(key(0xAA), key(0xBB), None).unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(err.code(), 269);
        assert_eq!(r.late_fee(), terms());

        let mut r2 = open_rental();
        r2.return_asset(300).unwrap();
        assert_eq!(r2.state(), RentalState::ReturnedLate);
        let err = r2.amend_late_fee(key(0xAA), key(0xBB), None).unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);

        let mut r3 = open_rental();
        r3.cancel(key(0xAA), 50).unwrap();
        let err = r3.amend_late_fee(key(0xAA), key(0xBB), None).unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
    }

    #[test]
    fn amend_late_fee_reuses_the_construction_gate() {
        // AV-291: a rate or cap above 10_000 bps fails closed with
        // the original schedule untouched.
        let mut r = open_rental();
        let bad_rate = Some(LateFeeTerms {
            bps_per_day: 10_001,
            cap_bps: 2000,
        });
        let err = r
            .amend_late_fee(key(0xAA), key(0xBB), bad_rate)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(err.code(), 268);
        assert_eq!(r.late_fee(), terms());
        let bad_cap = Some(LateFeeTerms {
            bps_per_day: 100,
            cap_bps: 10_001,
        });
        let err = r
            .amend_late_fee(key(0xAA), key(0xBB), bad_cap)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.late_fee(), terms());
        // The boundary itself is legal: exactly 10_000 bps passes.
        r.amend_late_fee(
            key(0xAA),
            key(0xBB),
            Some(LateFeeTerms {
                bps_per_day: 10_000,
                cap_bps: 10_000,
            }),
        )
        .unwrap();
        assert_eq!(
            r.late_fee(),
            Some(LateFeeTerms {
                bps_per_day: 10_000,
                cap_bps: 10_000,
            })
        );
    }

    #[test]
    fn amend_late_fee_identical_terms_is_a_noop() {
        // AV-291: re-affirming the current schedule writes nothing.
        let mut r = open_rental();
        r.amend_late_fee(key(0xAA), key(0xBB), terms()).unwrap();
        assert_eq!(r.late_fee(), terms());
        assert_eq!(r.state(), RentalState::Active);
        assert_eq!(r.late_fee_due(300), 10_000);
        // Clearing an already-cleared schedule is likewise a no-op.
        let mut r2 =
            RentalEscrow::new(key(0xAA), key(0xBB), key(0xCC), 1_000_000, 100, 200, 100, None)
                .unwrap();
        r2.amend_late_fee(key(0xAA), key(0xBB), None).unwrap();
        assert_eq!(r2.late_fee(), None);
    }

    #[test]
    fn extend_term_end_moves_the_live_window() {
        // AV-292: dual-signed extension re-judges term and overdue
        // against the new end, and reprices nothing else.
        let mut r = open_rental();
        // Under the old window slot 250 is 50 slots overdue: 1 day.
        assert!(r.is_overdue(250));
        assert_eq!(r.late_fee_due(250), 10_000);
        r.extend_term_end(key(0xAA), key(0xBB), 300, 150).unwrap();
        assert_eq!(r.term_end_slot(), 300);
        assert!(r.is_in_term(250));
        assert!(!r.is_overdue(250));
        assert_eq!(r.late_fee_due(250), 0);
        // Nothing else moved.
        assert_eq!(r.owner(), key(0xAA));
        assert_eq!(r.renter(), key(0xBB));
        assert_eq!(r.asset_id(), key(0xCC));
        assert_eq!(r.rent_amount(), 1_000_000);
        assert_eq!(r.term_start_slot(), 100);
        assert_eq!(r.state(), RentalState::Active);
        assert_eq!(r.late_fee(), terms());
        // The extended window governs the return settlement.
        let receipt = r.return_asset(250).unwrap();
        assert_eq!(receipt.late_fee_due, 0);
        assert!(!receipt.was_overdue);
        assert_eq!(r.state(), RentalState::Returned);
    }

    #[test]
    fn extend_term_end_governs_later_overdue_returns() {
        // AV-292: past the new end, overdue is priced against the
        // new window, not the old one.
        let mut r = open_rental();
        r.extend_term_end(key(0xAA), key(0xBB), 300, 150).unwrap();
        let receipt = r.return_asset(350).unwrap();
        assert!(receipt.was_overdue);
        assert_eq!(receipt.overdue_slots, 50);
        assert_eq!(receipt.overdue_days, 1);
        assert_eq!(receipt.late_fee_due, 10_000);
        assert_eq!(r.state(), RentalState::ReturnedLate);
    }

    #[test]
    fn extend_term_end_rejects_shrink_and_equal() {
        // AV-292: extension only — a shorter or equal window is an
        // invalid extension, not a re-affirmation, and the current
        // window is untouched.
        let mut r = open_rental();
        let err = r.extend_term_end(key(0xAA), key(0xBB), 150, 150).unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(err.code(), 268);
        assert_eq!(r.term_end_slot(), 200);
        let err = r.extend_term_end(key(0xAA), key(0xBB), 200, 150).unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.term_end_slot(), 200);
        // The boundary the other way is legal: one slot past the end.
        r.extend_term_end(key(0xAA), key(0xBB), 201, 150).unwrap();
        assert_eq!(r.term_end_slot(), 201);
    }

    #[test]
    fn extend_term_end_rejects_already_overdue_rentals() {
        // AV-292: once overdue, the old window's fee has already
        // accrued — extending it would retroactively erase overdue
        // days, so the window is frozen.
        let mut r = open_rental();
        let err = r.extend_term_end(key(0xAA), key(0xBB), 300, 201).unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.term_end_slot(), 200);
        // The end itself is inclusive: extending exactly at the term
        // end is still in term, not overdue.
        let mut r2 = open_rental();
        r2.extend_term_end(key(0xAA), key(0xBB), 300, 200).unwrap();
        assert_eq!(r2.term_end_slot(), 300);
        // Extending before the term even starts is allowed — the
        // only window gate is "not yet overdue".
        let mut r3 = open_rental();
        r3.extend_term_end(key(0xAA), key(0xBB), 300, 50).unwrap();
        assert_eq!(r3.term_end_slot(), 300);
    }

    #[test]
    fn extend_term_end_is_dual_signed_and_active_only() {
        // AV-292: a stranger, or either party alone, is refused and
        // the window is untouched.
        let mut r = open_rental();
        let err = r.extend_term_end(key(9), key(0xBB), 300, 150).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = r.extend_term_end(key(0xAA), key(9), 300, 150).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        assert_eq!(r.term_end_slot(), 200);
        // Authority is checked before state: a stranger on a
        // terminal rental still gets Unauthorized.
        let mut r2 = open_rental();
        r2.return_asset(150).unwrap();
        let err = r2.extend_term_end(key(9), key(0xBB), 300, 150).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        // The parties on a terminal rental get RentalNotActive.
        let err = r2.extend_term_end(key(0xAA), key(0xBB), 300, 150).unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(err.code(), 269);
        let mut r3 = open_rental();
        r3.cancel(key(0xAA), 50).unwrap();
        let err = r3.extend_term_end(key(0xAA), key(0xBB), 300, 50).unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(r3.term_end_slot(), 200);
    }

    #[test]
    fn amend_rent_amount_revises_the_live_rent() {
        // AV-314: dual-signed re-price before the term starts
        // reprices future billings only.
        let mut r = open_rental();
        assert_eq!(r.late_fee_due(300), 10_000);
        r.amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 50)
            .unwrap();
        assert_eq!(r.rent_amount(), 2_000_000);
        // The live rent prices the same overdue slot: 1%/day of the
        // new rent now.
        assert_eq!(r.late_fee_due(300), 20_000);
        // Nothing else moved.
        assert_eq!(r.owner(), key(0xAA));
        assert_eq!(r.renter(), key(0xBB));
        assert_eq!(r.asset_id(), key(0xCC));
        assert_eq!(r.term_start_slot(), 100);
        assert_eq!(r.term_end_slot(), 200);
        assert_eq!(r.state(), RentalState::Active);
        assert_eq!(r.late_fee(), terms());
        // The amended rent governs the return settlement.
        let receipt = r.return_asset(300).unwrap();
        assert_eq!(receipt.late_fee_due, 20_000);
        assert_eq!(r.state(), RentalState::ReturnedLate);
    }

    #[test]
    fn amend_rent_amount_governs_later_overdue_returns_and_cap() {
        // AV-314: both the per-day fee and the cap scale with the
        // new rent — the cap is 20% of the *revised* rent.
        let mut r = open_rental();
        // Under the old rent the 30-day fee would cap at 200_000.
        assert_eq!(r.late_fee_due(3200), 200_000);
        r.amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 50)
            .unwrap();
        // 30 days uncapped at 20_000/day = 600_000, capped at 20%
        // of 2_000_000 = 400_000.
        assert_eq!(r.late_fee_due(3200), 400_000);
        let receipt = r.return_asset(3200).unwrap();
        assert_eq!(receipt.overdue_days, 30);
        assert_eq!(receipt.late_fee_due, 400_000);
        assert_eq!(r.state(), RentalState::ReturnedLate);
    }

    #[test]
    fn amend_rent_amount_is_dual_signed() {
        // AV-314: a stranger, or either party alone, is refused and
        // the rent is untouched.
        let mut r = open_rental();
        let err = r
            .amend_rent_amount(key(9), key(0xBB), 2_000_000, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = r
            .amend_rent_amount(key(0xAA), key(9), 2_000_000, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = r
            .amend_rent_amount(key(9), key(9), 2_000_000, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        assert_eq!(r.rent_amount(), 1_000_000);
        // Authority is checked before state: a stranger on a
        // terminal rental still gets Unauthorized, not
        // RentalNotActive.
        let mut r2 = open_rental();
        r2.return_asset(150).unwrap();
        let err = r2
            .amend_rent_amount(key(9), key(0xBB), 2_000_000, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
    }

    #[test]
    fn amend_rent_amount_rejects_terminal_rentals() {
        // AV-314: Returned / ReturnedLate / Cancelled are terminal.
        let mut r = open_rental();
        r.return_asset(150).unwrap();
        let err = r
            .amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(err.code(), 269);
        assert_eq!(r.rent_amount(), 1_000_000);

        let mut r2 = open_rental();
        r2.return_asset(300).unwrap();
        assert_eq!(r2.state(), RentalState::ReturnedLate);
        let err = r2
            .amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);

        let mut r3 = open_rental();
        r3.cancel(key(0xAA), 50).unwrap();
        let err = r3
            .amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(r3.rent_amount(), 1_000_000);
    }

    #[test]
    fn amend_rent_amount_only_before_term_start() {
        // AV-314: once the term starts the rent is frozen — the
        // rent corresponds to use already consumed.
        let mut r = open_rental();
        // Exactly at the term start: too late.
        let err = r
            .amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 100)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(err.code(), 268);
        assert_eq!(r.rent_amount(), 1_000_000);
        // Mid-term: too late.
        let err = r
            .amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 150)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.rent_amount(), 1_000_000);
        // One slot before the term starts: still renegotiable.
        r.amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 99)
            .unwrap();
        assert_eq!(r.rent_amount(), 2_000_000);
    }

    #[test]
    fn amend_rent_amount_reuses_the_construction_gate() {
        // AV-314: a zero rent fails closed with the original rent
        // untouched.
        let mut r = open_rental();
        let err = r
            .amend_rent_amount(key(0xAA), key(0xBB), 0, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(err.code(), 268);
        assert_eq!(r.rent_amount(), 1_000_000);
        // The boundary itself is legal: a rent of 1 passes.
        r.amend_rent_amount(key(0xAA), key(0xBB), 1, 50).unwrap();
        assert_eq!(r.rent_amount(), 1);
    }

    #[test]
    fn amend_rent_amount_identical_value_is_a_noop() {
        // AV-314: re-affirming the current rent writes nothing.
        let mut r = open_rental();
        r.amend_rent_amount(key(0xAA), key(0xBB), 1_000_000, 50)
            .unwrap();
        assert_eq!(r.rent_amount(), 1_000_000);
        assert_eq!(r.state(), RentalState::Active);
        assert_eq!(r.late_fee_due(300), 10_000);
    }

    #[test]
    fn amend_slots_per_day_revises_the_live_pace() {
        // AV-329: dual-signed re-pacing before the term starts
        // reprices future billings only.
        let mut r = open_rental();
        assert_eq!(r.slots_per_day(), 100);
        assert_eq!(r.late_fee_due(300), 10_000);
        r.amend_slots_per_day(key(0xAA), key(0xBB), 50, 50).unwrap();
        assert_eq!(r.slots_per_day(), 50);
        // The live pace prices the same overdue slot: 100 overdue
        // slots are 2 days at 50 slots/day now.
        assert_eq!(r.late_fee_due(300), 20_000);
        // Nothing else moved.
        assert_eq!(r.owner(), key(0xAA));
        assert_eq!(r.renter(), key(0xBB));
        assert_eq!(r.asset_id(), key(0xCC));
        assert_eq!(r.rent_amount(), 1_000_000);
        assert_eq!(r.term_start_slot(), 100);
        assert_eq!(r.term_end_slot(), 200);
        assert_eq!(r.state(), RentalState::Active);
        assert_eq!(r.late_fee(), terms());
    }

    #[test]
    fn amend_slots_per_day_governs_return_settlement() {
        // AV-329: the amended pace governs the return settlement —
        // the receipt's day count and fee both reprice.
        let mut r = open_rental();
        r.amend_slots_per_day(key(0xAA), key(0xBB), 50, 50).unwrap();
        let receipt = r.return_asset(300).unwrap();
        assert!(receipt.was_overdue);
        assert_eq!(receipt.overdue_slots, 100);
        assert_eq!(receipt.overdue_days, 2);
        assert_eq!(receipt.late_fee_due, 20_000);
        assert_eq!(r.state(), RentalState::ReturnedLate);
    }

    #[test]
    fn amend_slots_per_day_slower_pace_charges_fewer_days() {
        // AV-329: slowing the pace cuts the charged days — the
        // ceiling division reprices in both directions.
        let mut r = open_rental();
        // 250 overdue slots = 3 charged days at 100 slots/day.
        assert_eq!(r.late_fee_due(450), 30_000);
        r.amend_slots_per_day(key(0xAA), key(0xBB), 200, 50).unwrap();
        // 250 overdue slots = 2 charged days at 200 slots/day.
        assert_eq!(r.late_fee_due(450), 20_000);
        let receipt = r.return_asset(450).unwrap();
        assert_eq!(receipt.overdue_days, 2);
        assert_eq!(receipt.late_fee_due, 20_000);
        assert_eq!(r.state(), RentalState::ReturnedLate);
    }

    #[test]
    fn amend_slots_per_day_is_dual_signed() {
        // AV-329: a stranger, or either party alone, is refused and
        // the pace is untouched.
        let mut r = open_rental();
        let err = r
            .amend_slots_per_day(key(9), key(0xBB), 50, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = r
            .amend_slots_per_day(key(0xAA), key(9), 50, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = r
            .amend_slots_per_day(key(9), key(9), 50, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        assert_eq!(r.slots_per_day(), 100);
        // Authority is checked before state: a stranger on a
        // terminal rental still gets Unauthorized, not
        // RentalNotActive.
        let mut r2 = open_rental();
        r2.return_asset(150).unwrap();
        let err = r2
            .amend_slots_per_day(key(9), key(0xBB), 50, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
    }

    #[test]
    fn amend_slots_per_day_rejects_terminal_rentals() {
        // AV-329: Returned / ReturnedLate / Cancelled are terminal.
        let mut r = open_rental();
        r.return_asset(150).unwrap();
        let err = r
            .amend_slots_per_day(key(0xAA), key(0xBB), 50, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(err.code(), 269);
        assert_eq!(r.slots_per_day(), 100);

        let mut r2 = open_rental();
        r2.return_asset(300).unwrap();
        assert_eq!(r2.state(), RentalState::ReturnedLate);
        let err = r2
            .amend_slots_per_day(key(0xAA), key(0xBB), 50, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);

        let mut r3 = open_rental();
        r3.cancel(key(0xAA), 50).unwrap();
        let err = r3
            .amend_slots_per_day(key(0xAA), key(0xBB), 50, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(r3.slots_per_day(), 100);
    }

    #[test]
    fn amend_slots_per_day_only_before_term_start() {
        // AV-329: once the term starts the pace is frozen — fees
        // have been accruing against the old pace.
        let mut r = open_rental();
        // Exactly at the term start: too late.
        let err = r
            .amend_slots_per_day(key(0xAA), key(0xBB), 50, 100)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(err.code(), 268);
        assert_eq!(r.slots_per_day(), 100);
        // Mid-term: too late.
        let err = r
            .amend_slots_per_day(key(0xAA), key(0xBB), 50, 150)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.slots_per_day(), 100);
        // One slot before the term starts: still renegotiable.
        r.amend_slots_per_day(key(0xAA), key(0xBB), 50, 99)
            .unwrap();
        assert_eq!(r.slots_per_day(), 50);
    }

    #[test]
    fn amend_slots_per_day_reuses_the_construction_gate() {
        // AV-329: a zero pace fails closed with the original pace
        // untouched (the overdue computation would divide by zero).
        let mut r = open_rental();
        let err = r
            .amend_slots_per_day(key(0xAA), key(0xBB), 0, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(err.code(), 268);
        assert_eq!(r.slots_per_day(), 100);
        // The boundary itself is legal: a pace of 1 passes.
        r.amend_slots_per_day(key(0xAA), key(0xBB), 1, 50).unwrap();
        assert_eq!(r.slots_per_day(), 1);
        // At 1 slot/day every overdue slot is a charged day: 100
        // days uncapped would be 1_000_000, capped at 20% of rent.
        assert_eq!(r.late_fee_due(300), 200_000);
    }

    #[test]
    fn amend_slots_per_day_identical_value_is_a_noop() {
        // AV-329: re-affirming the current pace writes nothing.
        let mut r = open_rental();
        r.amend_slots_per_day(key(0xAA), key(0xBB), 100, 50)
            .unwrap();
        assert_eq!(r.slots_per_day(), 100);
        assert_eq!(r.state(), RentalState::Active);
        assert_eq!(r.late_fee_due(300), 10_000);
    }

    #[test]
    fn amend_term_start_slot_moves_the_live_start() {
        // AV-330: dual-signed reschedule delays the term; the live
        // start governs term membership and the cancel window, and
        // the late fee (which only reads the end) is untouched.
        let mut r = open_rental();
        assert!(r.is_in_term(120));
        r.amend_term_start_slot(key(0xAA), key(0xBB), 150, 50)
            .unwrap();
        assert_eq!(r.term_start_slot(), 150);
        assert!(!r.is_in_term(120)); // no longer in term
        assert!(r.is_in_term(160));
        assert_eq!(r.late_fee_due(300), 10_000);
        // Nothing else moved.
        assert_eq!(r.owner(), key(0xAA));
        assert_eq!(r.renter(), key(0xBB));
        assert_eq!(r.asset_id(), key(0xCC));
        assert_eq!(r.rent_amount(), 1_000_000);
        assert_eq!(r.term_end_slot(), 200);
        assert_eq!(r.slots_per_day(), 100);
        assert_eq!(r.late_fee(), terms());
        assert_eq!(r.state(), RentalState::Active);
        // Delaying widens the cancel window: slot 120 was past the
        // old start (uncancellable), now it is before the new one.
        r.cancel(key(0xAA), 120).unwrap();
        assert_eq!(r.state(), RentalState::Cancelled);
    }

    #[test]
    fn amend_term_start_slot_advance_pulls_the_term_forward() {
        // AV-330: advancing the start pulls the term forward — a
        // slot that was pre-term is in term now, and the cancel
        // window narrows with it.
        let mut r = open_rental();
        assert!(!r.is_in_term(75));
        r.amend_term_start_slot(key(0xAA), key(0xBB), 50, 10)
            .unwrap();
        assert_eq!(r.term_start_slot(), 50);
        assert!(r.is_in_term(75));
        // Slot 75 is now past the (new) start: no longer cancellable.
        let err = r.cancel(key(0xAA), 75).unwrap_err();
        assert_eq!(err, EscrowError::RentalCancelNotAllowed);
        assert_eq!(err.code(), 270);
        assert_eq!(r.state(), RentalState::Active);
        // The moved start governs the return settlement window.
        let receipt = r.return_asset(75).unwrap();
        assert_eq!(receipt.late_fee_due, 0);
        assert!(!receipt.was_overdue);
        assert_eq!(r.state(), RentalState::Returned);
    }

    #[test]
    fn amend_term_start_slot_is_dual_signed() {
        // AV-330: a stranger, or either party alone, is refused and
        // the start is untouched.
        let mut r = open_rental();
        let err = r
            .amend_term_start_slot(key(9), key(0xBB), 150, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = r
            .amend_term_start_slot(key(0xAA), key(9), 150, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = r
            .amend_term_start_slot(key(9), key(9), 150, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        assert_eq!(r.term_start_slot(), 100);
        // Authority is checked before state: a stranger on a
        // terminal rental still gets Unauthorized, not
        // RentalNotActive.
        let mut r2 = open_rental();
        r2.return_asset(150).unwrap();
        let err = r2
            .amend_term_start_slot(key(9), key(0xBB), 150, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
    }

    #[test]
    fn amend_term_start_slot_rejects_terminal_rentals() {
        // AV-330: Returned / ReturnedLate / Cancelled are terminal.
        let mut r = open_rental();
        r.return_asset(150).unwrap();
        let err = r
            .amend_term_start_slot(key(0xAA), key(0xBB), 150, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(err.code(), 269);
        assert_eq!(r.term_start_slot(), 100);

        let mut r2 = open_rental();
        r2.return_asset(300).unwrap();
        assert_eq!(r2.state(), RentalState::ReturnedLate);
        let err = r2
            .amend_term_start_slot(key(0xAA), key(0xBB), 150, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);

        let mut r3 = open_rental();
        r3.cancel(key(0xAA), 50).unwrap();
        let err = r3
            .amend_term_start_slot(key(0xAA), key(0xBB), 150, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(r3.term_start_slot(), 100);
    }

    #[test]
    fn amend_term_start_slot_only_before_term_start() {
        // AV-330: once the term starts the start is frozen — the
        // renter has custody, and moving the start would rewrite
        // use already consumed.
        let mut r = open_rental();
        // Exactly at the term start: too late.
        let err = r
            .amend_term_start_slot(key(0xAA), key(0xBB), 150, 100)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(err.code(), 268);
        assert_eq!(r.term_start_slot(), 100);
        // Mid-term: too late.
        let err = r
            .amend_term_start_slot(key(0xAA), key(0xBB), 150, 150)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.term_start_slot(), 100);
        // A same-value re-affirmation at the start is still refused
        // — the no-op sits after the window gate.
        let err = r
            .amend_term_start_slot(key(0xAA), key(0xBB), 100, 100)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.term_start_slot(), 100);
        // One slot before the term starts: still reschedulable.
        r.amend_term_start_slot(key(0xAA), key(0xBB), 150, 99)
            .unwrap();
        assert_eq!(r.term_start_slot(), 150);
    }

    #[test]
    fn amend_term_start_slot_new_start_must_be_in_the_future() {
        // AV-330: the revised term must still be in the future —
        // backdating the opening would instantly kill the cancel
        // window, so a start at or behind the current slot is
        // refused with the current start untouched.
        let mut r = open_rental();
        // Exactly at the current slot: not in the future.
        let err = r
            .amend_term_start_slot(key(0xAA), key(0xBB), 50, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(err.code(), 268);
        assert_eq!(r.term_start_slot(), 100);
        // Behind the current slot: also refused.
        let err = r
            .amend_term_start_slot(key(0xAA), key(0xBB), 40, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.term_start_slot(), 100);
        // The boundary the other way is legal: one slot past now.
        r.amend_term_start_slot(key(0xAA), key(0xBB), 51, 50)
            .unwrap();
        assert_eq!(r.term_start_slot(), 51);
    }

    #[test]
    fn amend_term_start_slot_new_start_must_precede_the_end() {
        // AV-330: the new() empty-term gate, reused — a start at or
        // past the term end is an empty term, not a reschedule.
        let mut r = open_rental();
        let err = r
            .amend_term_start_slot(key(0xAA), key(0xBB), 200, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(err.code(), 268);
        assert_eq!(r.term_start_slot(), 100);
        let err = r
            .amend_term_start_slot(key(0xAA), key(0xBB), 250, 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.term_start_slot(), 100);
        // The boundary the other way is legal: one slot before the end.
        r.amend_term_start_slot(key(0xAA), key(0xBB), 199, 50)
            .unwrap();
        assert_eq!(r.term_start_slot(), 199);
    }

    #[test]
    fn amend_term_start_slot_identical_value_is_a_noop() {
        // AV-330: re-affirming the current start writes nothing.
        let mut r = open_rental();
        r.amend_term_start_slot(key(0xAA), key(0xBB), 100, 50)
            .unwrap();
        assert_eq!(r.term_start_slot(), 100);
        assert_eq!(r.state(), RentalState::Active);
        assert!(r.is_in_term(150));
        assert_eq!(r.late_fee_due(300), 10_000);
    }

    #[test]
    fn amend_term_start_slot_moves_the_pre_start_revision_window() {
        // AV-330 cross-effect: AV-314's rent revision (and AV-329's
        // pace revision) gate on the *live* start, so moving the
        // start moves their windows with it.
        // Delaying 100 -> 150 reopens slot 120 for rent revision:
        // it was past the old start (refused), now it is before the
        // new one.
        let mut r = open_rental();
        let err = r
            .amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 120)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        r.amend_term_start_slot(key(0xAA), key(0xBB), 150, 50)
            .unwrap();
        r.amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 120)
            .unwrap();
        assert_eq!(r.rent_amount(), 2_000_000);
        // Advancing 100 -> 50 closes slot 75 for rent revision: it
        // was before the old start (allowed), now it is past the new
        // one.
        let mut r2 = open_rental();
        r2.amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 75)
            .unwrap();
        assert_eq!(r2.rent_amount(), 2_000_000);
        let mut r3 = open_rental();
        r3.amend_term_start_slot(key(0xAA), key(0xBB), 50, 10)
            .unwrap();
        let err = r3
            .amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 75)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r3.rent_amount(), 1_000_000);
    }

    #[test]
    fn shorten_term_end_moves_the_live_window() {
        // AV-331: dual-signed shortening re-judges term and overdue
        // against the new end, and reprices nothing else.
        let mut r = open_rental();
        // Under the old window slot 160 is in term; past the new
        // end it is 10 slots overdue — a partial day still counts
        // as a full day, so the fee is 10_000.
        assert!(r.is_in_term(160));
        assert!(!r.is_overdue(160));
        r.shorten_term_end(key(0xAA), key(0xBB), 150, 120).unwrap();
        assert_eq!(r.term_end_slot(), 150);
        assert!(r.is_in_term(140));
        assert!(!r.is_in_term(160));
        assert!(r.is_overdue(160));
        assert_eq!(r.late_fee_due(160), 10_000);
        // 100 slots past the new end is exactly 1 day: 10_000.
        assert_eq!(r.late_fee_due(250), 10_000);
        // Nothing else moved.
        assert_eq!(r.owner(), key(0xAA));
        assert_eq!(r.renter(), key(0xBB));
        assert_eq!(r.asset_id(), key(0xCC));
        assert_eq!(r.rent_amount(), 1_000_000);
        assert_eq!(r.term_start_slot(), 100);
        assert_eq!(r.slots_per_day(), 100);
        assert_eq!(r.state(), RentalState::Active);
        assert_eq!(r.late_fee(), terms());
        // The shortened window governs the return settlement: a
        // return inside the new window is still clean.
        let receipt = r.return_asset(140).unwrap();
        assert_eq!(receipt.late_fee_due, 0);
        assert!(!receipt.was_overdue);
        assert_eq!(r.state(), RentalState::Returned);
    }

    #[test]
    fn shorten_term_end_governs_later_overdue_returns() {
        // AV-331: past the new end, overdue is priced against the
        // new window, not the old one.
        let mut r = open_rental();
        r.shorten_term_end(key(0xAA), key(0xBB), 150, 120).unwrap();
        let receipt = r.return_asset(250).unwrap();
        assert!(receipt.was_overdue);
        assert_eq!(receipt.overdue_slots, 100);
        assert_eq!(receipt.overdue_days, 1);
        assert_eq!(receipt.late_fee_due, 10_000);
        assert_eq!(r.state(), RentalState::ReturnedLate);
    }

    #[test]
    fn shorten_term_end_rejects_grow_and_equal() {
        // AV-331: shortening only — a longer or equal window is an
        // invalid shortening, not a re-affirmation, and the current
        // window is untouched.
        let mut r = open_rental();
        let err = r.shorten_term_end(key(0xAA), key(0xBB), 250, 150).unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(err.code(), 268);
        assert_eq!(r.term_end_slot(), 200);
        let err = r.shorten_term_end(key(0xAA), key(0xBB), 200, 150).unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.term_end_slot(), 200);
        // The boundary the other way is legal: one slot short of
        // the end.
        r.shorten_term_end(key(0xAA), key(0xBB), 199, 150).unwrap();
        assert_eq!(r.term_end_slot(), 199);
    }

    #[test]
    fn shorten_term_end_rejects_already_past_new_end() {
        // AV-331: shortening must not retroactively manufacture
        // overdue time — a new end behind the current slot would
        // turn use already consumed in term into overdue days.
        let mut r = open_rental();
        let err = r.shorten_term_end(key(0xAA), key(0xBB), 150, 151).unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.term_end_slot(), 200);
        // The end is inclusive: shortening exactly to the current
        // slot is still in term, not overdue.
        let mut r2 = open_rental();
        r2.shorten_term_end(key(0xAA), key(0xBB), 150, 150).unwrap();
        assert_eq!(r2.term_end_slot(), 150);
        assert!(r2.is_in_term(150));
        assert!(!r2.is_overdue(150));
        assert_eq!(r2.late_fee_due(150), 0);
        // Shortening before the term even starts is allowed — the
        // only window gate is "not yet past the new end".
        let mut r3 = open_rental();
        r3.shorten_term_end(key(0xAA), key(0xBB), 150, 50).unwrap();
        assert_eq!(r3.term_end_slot(), 150);
    }

    #[test]
    fn shorten_term_end_rejects_empty_term() {
        // AV-331: the new end reuses the construction empty-term
        // gate — at or before the term start is not a term at all.
        let mut r = open_rental();
        let err = r.shorten_term_end(key(0xAA), key(0xBB), 100, 50).unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.term_end_slot(), 200);
        let err = r.shorten_term_end(key(0xAA), key(0xBB), 90, 50).unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.term_end_slot(), 200);
    }

    #[test]
    fn shorten_term_end_is_dual_signed_and_active_only() {
        // AV-331: a stranger, or either party alone, is refused and
        // the window is untouched.
        let mut r = open_rental();
        let err = r.shorten_term_end(key(9), key(0xBB), 150, 120).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = r.shorten_term_end(key(0xAA), key(9), 150, 120).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        assert_eq!(r.term_end_slot(), 200);
        // Authority is checked before state: a stranger on a
        // terminal rental still gets Unauthorized.
        let mut r2 = open_rental();
        r2.return_asset(150).unwrap();
        let err = r2.shorten_term_end(key(9), key(0xBB), 150, 120).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        // The parties on a terminal rental get RentalNotActive.
        let err = r2.shorten_term_end(key(0xAA), key(0xBB), 150, 120).unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(err.code(), 269);
        let mut r3 = open_rental();
        r3.cancel(key(0xAA), 50).unwrap();
        let err = r3.shorten_term_end(key(0xAA), key(0xBB), 150, 50).unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(r3.term_end_slot(), 200);
    }

    #[test]
    fn shorten_then_extend_term_end_works_on_the_live_value() {
        // AV-331 cross-effect: AV-292's extend_term_end reads the
        // live end, so a shortened window can be extended again —
        // the two directions are independent methods on the same
        // field, mutually exclusive per call.
        let mut r = open_rental();
        r.shorten_term_end(key(0xAA), key(0xBB), 150, 120).unwrap();
        assert_eq!(r.term_end_slot(), 150);
        // Extending back past the shortened end works.
        r.extend_term_end(key(0xAA), key(0xBB), 300, 120).unwrap();
        assert_eq!(r.term_end_slot(), 300);
        assert!(r.is_in_term(250));
        assert_eq!(r.late_fee_due(250), 0);
        // ...but extending to the shortened end itself is still an
        // invalid extension — the equal-value gate reads the live
        // value, not the original one.
        let mut r2 = open_rental();
        r2.shorten_term_end(key(0xAA), key(0xBB), 150, 120).unwrap();
        let err = r2.extend_term_end(key(0xAA), key(0xBB), 150, 120).unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r2.term_end_slot(), 150);
    }

    #[test]
    fn shorten_term_end_leaves_pre_start_revision_windows_untouched() {
        // AV-331 cross-effect: AV-314's rent revision and AV-329's
        // pace revision gate on the *live start*, which shortening
        // never moves — so their pre-start windows are unaffected
        // by a shortened end.
        let mut r = open_rental();
        r.shorten_term_end(key(0xAA), key(0xBB), 150, 50).unwrap();
        assert_eq!(r.term_end_slot(), 150);
        r.amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 50)
            .unwrap();
        assert_eq!(r.rent_amount(), 2_000_000);
        r.amend_slots_per_day(key(0xAA), key(0xBB), 200, 50)
            .unwrap();
        assert_eq!(r.slots_per_day(), 200);
        assert_eq!(r.term_end_slot(), 150);
    }

    #[test]
    fn amend_asset_id_revises_the_live_asset() {
        // AV-332: a pre-term revision swaps the escrowed identifier
        // and the getter reads the new value.
        let mut r = open_rental();
        assert_eq!(r.asset_id(), key(0xCC));
        r.amend_asset_id(key(0xAA), key(0xBB), key(0xDD), 50)
            .unwrap();
        assert_eq!(r.asset_id(), key(0xDD));
        // Only the asset moves — every other field is untouched.
        assert_eq!(r.owner(), key(0xAA));
        assert_eq!(r.renter(), key(0xBB));
        assert_eq!(r.rent_amount(), 1_000_000);
        assert_eq!(r.term_start_slot(), 100);
        assert_eq!(r.term_end_slot(), 200);
        assert_eq!(r.slots_per_day(), 100);
        assert_eq!(r.late_fee(), terms());
        assert_eq!(r.state(), RentalState::Active);
        // A second revision works on the live value.
        r.amend_asset_id(key(0xAA), key(0xBB), key(0xEE), 60)
            .unwrap();
        assert_eq!(r.asset_id(), key(0xEE));
    }

    #[test]
    fn amend_asset_id_is_dual_signed_and_active_only() {
        // AV-332: a stranger, or either party alone, is refused and
        // the asset is untouched — the asset is a bilaterally
        // escrowed subject, so a unilateral rewrite would swap the
        // escrowed item alone.
        let mut r = open_rental();
        let err = r
            .amend_asset_id(key(9), key(0xBB), key(0xDD), 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = r
            .amend_asset_id(key(0xAA), key(9), key(0xDD), 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = r
            .amend_asset_id(key(9), key(9), key(0xDD), 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        assert_eq!(r.asset_id(), key(0xCC));
        // Authority is checked before state: a stranger on a
        // terminal rental still gets Unauthorized.
        let mut r2 = open_rental();
        r2.return_asset(150).unwrap();
        let err = r2
            .amend_asset_id(key(9), key(0xBB), key(0xDD), 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        // The parties on a terminal rental get RentalNotActive.
        let err = r2
            .amend_asset_id(key(0xAA), key(0xBB), key(0xDD), 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(err.code(), 269);
        assert_eq!(r2.asset_id(), key(0xCC));
        let mut r3 = open_rental();
        r3.cancel(key(0xAA), 50).unwrap();
        let err = r3
            .amend_asset_id(key(0xAA), key(0xBB), key(0xDD), 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::RentalNotActive);
        assert_eq!(r3.asset_id(), key(0xCC));
    }

    #[test]
    fn amend_asset_id_only_before_term_start() {
        // AV-332: once the term has begun the renter physically
        // holds the original asset — swapping the id would point
        // return settlement and audit at an asset never escrowed.
        let mut r = open_rental();
        let err = r
            .amend_asset_id(key(0xAA), key(0xBB), key(0xDD), 100)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(err.code(), 268);
        assert_eq!(r.asset_id(), key(0xCC));
        let err = r
            .amend_asset_id(key(0xAA), key(0xBB), key(0xDD), 150)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.asset_id(), key(0xCC));
    }

    #[test]
    fn amend_asset_id_rejects_zero_asset() {
        // AV-332: the zero-asset gate is new in this item and
        // deliberately asymmetric with new(), which does not validate
        // asset_id — revision fails closed rather than blanking the
        // escrowed identifier into "no asset" while rent and
        // late-fee terms keep accruing.
        let mut r = open_rental();
        let err = r
            .amend_asset_id(key(0xAA), key(0xBB), [0u8; 32], 50)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(err.code(), 268);
        assert_eq!(r.asset_id(), key(0xCC));
    }

    #[test]
    fn amend_asset_id_identical_value_is_a_noop() {
        // AV-332: restating the current asset pre-term is a no-op,
        // but the no-op check sits after the window gate — a
        // same-value restatement after the term has started is still
        // refused, following AV-330's gate order.
        let mut r = open_rental();
        r.amend_asset_id(key(0xAA), key(0xBB), key(0xCC), 50)
            .unwrap();
        assert_eq!(r.asset_id(), key(0xCC));
        assert_eq!(r.state(), RentalState::Active);
        let err = r
            .amend_asset_id(key(0xAA), key(0xBB), key(0xCC), 100)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidRentalTerms);
        assert_eq!(r.asset_id(), key(0xCC));
    }

    #[test]
    fn amend_asset_id_at_the_slot_before_term_start_is_allowed() {
        // AV-332: the boundary is the term start itself — one slot
        // before it, nobody holds the asset yet, so the swap is a
        // clean redirect.
        let mut r = open_rental();
        r.amend_asset_id(key(0xAA), key(0xBB), key(0xDD), 99)
            .unwrap();
        assert_eq!(r.asset_id(), key(0xDD));
    }

    #[test]
    fn amend_asset_id_governs_the_next_audit() {
        // AV-332: the audit JSONs read the live asset id, so a return
        // or cancel after the revision carries the new asset hex.
        let mut r = open_rental();
        r.amend_asset_id(key(0xAA), key(0xBB), key(0xDD), 50)
            .unwrap();
        let receipt = r.return_asset(150).unwrap();
        let j = r.return_audit_json(receipt);
        assert!(j.contains("\"asset\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\""));
        assert!(!j.contains("cccc"));
        // A return already executed keeps the asset it was audited
        // under — its JSON string is already on disk.
        let mut r2 = open_rental();
        let receipt = r2.return_asset(150).unwrap();
        let j = r2.return_audit_json(receipt);
        assert!(j.contains("\"asset\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\""));
        // Same for a cancelled rental.
        let mut r3 = open_rental();
        r3.amend_asset_id(key(0xAA), key(0xBB), key(0xDD), 50)
            .unwrap();
        let j = r3.cancel_audit_json();
        assert!(j.contains("\"asset\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\""));
        assert_eq!(j, "{\"event\":\"rental_cancelled\",\"asset\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"}");
    }

    #[test]
    fn amend_asset_id_leaves_other_revisions_and_fees_untouched() {
        // AV-332 cross-effect: after the revision, the AV-314/329/
        // 330/331 revisions still work on the live values, and the
        // late-fee settlement is unaffected — fee math never reads
        // the asset id.
        let mut r = open_rental();
        r.amend_asset_id(key(0xAA), key(0xBB), key(0xDD), 50)
            .unwrap();
        r.amend_rent_amount(key(0xAA), key(0xBB), 2_000_000, 50)
            .unwrap();
        assert_eq!(r.rent_amount(), 2_000_000);
        r.amend_slots_per_day(key(0xAA), key(0xBB), 200, 50)
            .unwrap();
        assert_eq!(r.slots_per_day(), 200);
        r.amend_term_start_slot(key(0xAA), key(0xBB), 150, 50)
            .unwrap();
        assert_eq!(r.term_start_slot(), 150);
        r.shorten_term_end(key(0xAA), key(0xBB), 180, 50)
            .unwrap();
        assert_eq!(r.term_end_slot(), 180);
        assert_eq!(r.asset_id(), key(0xDD));
        // The fee at 100 slots past the (shortened) end, 200
        // slots/day: 1 overdue day on the revised rent —
        // 2_000_000 * 100 / 10_000 = 20_000 — is priced exactly as
        // it would be without the asset change.
        assert_eq!(r.late_fee_due(280), 20_000);
        let receipt = r.return_asset(280).unwrap();
        assert_eq!(receipt.late_fee_due, 20_000);
        assert_eq!(receipt.overdue_days, 1);
        // And on an unrevised rental the same overdue return prices
        // identically apart from the rent revision itself: the asset
        // change contributes nothing to the fee.
        let mut r2 = open_rental();
        assert_eq!(r2.late_fee_due(300), 10_000);
        r2.amend_asset_id(key(0xAA), key(0xBB), key(0xDD), 50)
            .unwrap();
        assert_eq!(r2.late_fee_due(300), 10_000);
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
        assert_eq!(EscrowError::all().len(), 253); // AV-195: +7 social-recovery errors, AV-196: +6 jury-sortition errors, AV-197: +5 payment-channel errors; AV-209: +4; AV-214: +6; AV-215: +1; AV-217: +3; AV-218: +2; AV-220: +1; AV-225: +1; AV-228: +1; AV-266: +1; AV-284: +1; AV-287: +1 auto-unpause-at error; AV-337: +1 governance-proposal-expired error; AV-342: +1 distribution-claims-started error
    }
}
