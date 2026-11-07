//! Option escrow (AV-214): a fixed-strike, expiry-bound call option
//! over a locked underlying amount, as a pure-logic sidecar.
//!
//! The seller locks an underlying amount and the buyer pays a
//! premium up front for the *right* — not the obligation — to buy
//! that underlying at a fixed strike price before an expiry
//! timestamp. This is the financial-option semantic, not a
//! price-gated release: the holder's active choice is the trigger,
//! and the strike never moves with the market.
//!
//! Settlement, in one place so no caller can misprice a leg:
//!
//! - *Exercise* (buyer only, strictly before expiry, paying exactly
//!   the strike): the underlying goes to the buyer, the strike plus
//!   the premium go to the seller. The premium is non-refundable in
//!   every outcome — it bought the right, and the right was held.
//! - *Expiry* (at or after expiry, unexercised): the premium stays
//!   with the seller and the underlying returns to the seller. An
//!   unexercised option is not a failed escrow — it is the option
//!   expiring worthless, which is a normal terminal outcome, not an
//!   error.
//!
//! The boundary is exact: exercise is allowed while `now < expiry`
//! and expiry settles while `now >= expiry`, so at the expiry
//! instant itself exercise is already closed and expiry is already
//! open — no timestamp is both exercisable and expirable, and no
//! timestamp is neither. The module moves no funds itself: like the
//! HTLC claim, it verifies the terms and returns the settlement
//! legs for transfer sizing, and the premium's custody before
//! construction (paid to the seller up front, outside this module)
//! is the caller's job — a premium the seller never received is a
//! caller bug this module cannot see, exactly like an HTLC amount
//! never locked.
//!
//! Check order on exercise mirrors the HTLC claim (authority →
//! state → timelock → payment): a stranger learns nothing about the
//! option's state from the error they get, and a settled option
//! reports itself settled before any timestamp or payment question
//! is asked. A wrong strike payment is [`EscrowError::OptionStrikeMismatch`],
//! not [`EscrowError::AmountMismatch`] — that code means
//! "initialize with amount == 0", and reusing it for a payment
//! mismatch would mislead a client matching on codes.
//!
//! Orthogonal to AV-113 (a price gate that *permits* a release
//! when a market condition holds — no holder choice, no strike),
//! to AV-97 (a Dutch auction that *discovers* a price — the strike
//! here is fixed at construction, never bid), and to AV-186 (an
//! HTLC: a hashlock plus a timelock where the claim secret, not a
//! payment, unlocks the funds). What this module deliberately does
//! *not* do: it stores nothing on the Vault, so there is no layout
//! change, no `VAULT_SPACE` bump and no IDL regeneration — the
//! Anchor instruction that locks the underlying, collects the
//! premium and settles these legs on chain is follow-up work, and
//! the README states the boundary rather than claiming an
//! instruction that does not exist yet.

use crate::EscrowError;

/// The lifecycle state of an [`OptionEscrow`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptionState {
    /// Live: exercisable while `now < expiry`, expirable once
    /// `now >= expiry`.
    Active,
    /// Exercised: the underlying went to the buyer, strike plus
    /// premium to the seller. Terminal.
    Exercised,
    /// Expired unexercised: the premium stayed with the seller and
    /// the underlying returned to the seller. Terminal.
    Expired,
}

/// The settlement legs of an exercise: what each side receives.
/// The buyer paid the premium up front (outside this module) and
/// pays the strike now; the seller receives both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionExercise {
    /// The locked underlying, to the buyer.
    pub underlying_to_buyer: u64,
    /// The strike payment, to the seller.
    pub strike_to_seller: u64,
    /// The up-front premium, to the seller (non-refundable).
    pub premium_to_seller: u64,
}

/// The settlement legs of an expiry: the option died unexercised.
/// The premium stays with the seller; the underlying returns to
/// the seller. The buyer receives nothing — the premium bought a
/// right that was never used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionExpiry {
    /// The locked underlying, back to the seller.
    pub underlying_to_seller: u64,
    /// The up-front premium, to the seller (non-refundable).
    pub premium_to_seller: u64,
}

/// A fixed-strike call option over a locked underlying amount.
///
/// Fixed-size and `Copy`, like the other pure-logic sidecars: the
/// option's terms are set once at construction — with five
/// governed exceptions, the strike, the expiry, the seller, the
/// buyer, and the premium, which the two parties may revise
/// together while the option is `Active`
/// ([`OptionEscrow::amend_option_strike`], AV-294;
/// [`OptionEscrow::amend_option_expiry`], AV-299;
/// [`OptionEscrow::amend_option_seller`], AV-366;
/// [`OptionEscrow::amend_option_buyer`], AV-367;
/// [`OptionEscrow::amend_option_premium`], AV-371). A unilateral
/// move of any of them would let one side rewrite the deal alone, so
/// all five revisions need seller + buyer together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionEscrow {
    seller: [u8; 32],
    buyer: [u8; 32],
    underlying: u64,
    premium: u64,
    strike: u64,
    expiry: u64,
    state: OptionState,
}

impl OptionEscrow {
    /// Build an option. The seller and the buyer must be distinct
    /// non-zero keys (an option with oneself is a no-op wearing a
    /// contract's name); the underlying, the premium and the
    /// strike must all be positive (a zero underlying is nothing
    /// to buy, a zero premium is a free option, a zero strike is
    /// a gift, and none of them is an option); the expiry must be
    /// a real timestamp (0 is "no expiry", and an option without
    /// an expiry is a perpetual — a different instrument). Every
    /// violation is [`EscrowError::InvalidOptionTerms`].
    pub fn new(
        seller: [u8; 32],
        buyer: [u8; 32],
        underlying: u64,
        premium: u64,
        strike: u64,
        expiry: u64,
    ) -> Result<Self, EscrowError> {
        if seller == [0u8; 32]
            || buyer == [0u8; 32]
            || seller == buyer
            || underlying == 0
            || premium == 0
            || strike == 0
            || expiry == 0
        {
            return Err(EscrowError::InvalidOptionTerms);
        }
        Ok(OptionEscrow {
            seller,
            buyer,
            underlying,
            premium,
            strike,
            expiry,
            state: OptionState::Active,
        })
    }

    /// The seller: the underlying's owner, who receives the
    /// premium in every outcome — fixed at construction,
    /// revisable only by the dual-signed
    /// [`OptionEscrow::amend_option_seller`] while `Active`.
    pub fn seller(&self) -> [u8; 32] {
        self.seller
    }

    /// The buyer: the option holder, the only party who may
    /// exercise — fixed at construction, revisable only by the
    /// dual-signed [`OptionEscrow::amend_option_buyer`] while
    /// `Active`.
    pub fn buyer(&self) -> [u8; 32] {
        self.buyer
    }

    /// The locked underlying amount.
    pub fn underlying(&self) -> u64 {
        self.underlying
    }

    /// The up-front premium (non-refundable in every outcome) —
    /// fixed at construction, revisable only by the dual-signed
    /// [`OptionEscrow::amend_option_premium`] while `Active`.
    pub fn premium(&self) -> u64 {
        self.premium
    }

    /// The current strike price the buyer pays on exercise —
    /// fixed at construction, revisable only by the dual-signed
    /// [`OptionEscrow::amend_option_strike`] while `Active`.
    pub fn strike(&self) -> u64 {
        self.strike
    }

    /// The expiry timestamp: exercise needs `now < expiry`,
    /// expiry settles at `now >= expiry` — fixed at construction,
    /// revisable only by the dual-signed
    /// [`OptionEscrow::amend_option_expiry`] while `Active`.
    pub fn expiry(&self) -> u64 {
        self.expiry
    }

    /// The lifecycle state.
    pub fn state(&self) -> OptionState {
        self.state
    }

    /// Whether the exercise window is open at `now`, independent
    /// of state — a convenience for keeper scans, like the HTLC's
    /// `claim_window_open`.
    pub fn exercise_window_open(&self, now: u64) -> bool {
        now < self.expiry
    }

    /// Exercise the option: the buyer pays exactly the strike
    /// before expiry and receives the underlying; the seller
    /// receives the strike plus the premium.
    ///
    /// Check order is authority → state → timelock → payment:
    /// a non-buyer is [`EscrowError::OptionNotBuyer`] whatever
    /// the state; a settled option is
    /// [`EscrowError::OptionAlreadySettled`] whatever the time;
    /// an exercise at or after expiry is
    /// [`EscrowError::OptionExpired`]; a payment other than the
    /// strike is [`EscrowError::OptionStrikeMismatch`].
    pub fn exercise(
        &mut self,
        caller: [u8; 32],
        now: u64,
        strike_payment: u64,
    ) -> Result<OptionExercise, EscrowError> {
        if caller != self.buyer {
            return Err(EscrowError::OptionNotBuyer);
        }
        if self.state != OptionState::Active {
            return Err(EscrowError::OptionAlreadySettled);
        }
        if now >= self.expiry {
            return Err(EscrowError::OptionExpired);
        }
        if strike_payment != self.strike {
            return Err(EscrowError::OptionStrikeMismatch);
        }
        self.state = OptionState::Exercised;
        Ok(OptionExercise {
            underlying_to_buyer: self.underlying,
            strike_to_seller: self.strike,
            premium_to_seller: self.premium,
        })
    }

    /// Settle an unexercised option at or after expiry: the
    /// premium stays with the seller and the underlying returns
    /// to the seller.
    ///
    /// Check order is state → timelock: a settled option is
    /// [`EscrowError::OptionAlreadySettled`]; an expiry before
    /// the window closes is [`EscrowError::OptionNotExpired`] —
    /// the buyer's window is still open and the seller cannot
    /// race it. Anyone may call expiry: it settles a lapsed
    /// option, it does not move funds to the caller.
    pub fn expire(&mut self, now: u64) -> Result<OptionExpiry, EscrowError> {
        if self.state != OptionState::Active {
            return Err(EscrowError::OptionAlreadySettled);
        }
        if now < self.expiry {
            return Err(EscrowError::OptionNotExpired);
        }
        self.state = OptionState::Expired;
        Ok(OptionExpiry {
            underlying_to_seller: self.underlying,
            premium_to_seller: self.premium,
        })
    }

    /// Revise the strike on an `Active` option (AV-294 — Solana
    /// option governance): both parties authorize the change
    /// (the strike is a bilateral price term — a unilateral
    /// rewrite would let one side reprice the other's bargain
    /// alone). Check order is authority → state → value,
    /// mirroring [`OptionEscrow::exercise`] and AV-292's
    /// `extend_term_end`, so a stranger learns nothing about
    /// the option's state from the error alone.
    ///
    /// Why: the strike is fixed at construction
    /// ([`OptionEscrow::new`]), but the parties may agree the
    /// bargained price no longer reflects the deal — a strike
    /// that cannot move would force a fresh option (and a fresh
    /// premium) for a legitimate repricing. Only an `Active`
    /// option may revise: an exercised option has already
    /// settled ([`EscrowError::OptionAlreadySettled`]), and an
    /// expired option's window has lapsed
    /// ([`EscrowError::OptionExpired`] — the lapsed-window
    /// error `exercise` returns once the window closes, since
    /// expiry settlement is then the only remaining path).
    /// The revision takes no timestamp: like `expire`, the
    /// settlement boundary is the explicit state transition,
    /// not the wall clock, so an `Active` option whose expiry
    /// instant has passed but which has not yet been expired
    /// may still revise — the revision never revives the
    /// exercise window, which still closes at `expiry`. The
    /// new strike reuses the `new` gate (it must be positive,
    /// [`EscrowError::InvalidOptionTerms`] otherwise, and the
    /// current strike is untouched). Only `strike` changes —
    /// seller, buyer, underlying, premium, expiry and state
    /// are untouched — and re-affirming the current strike is
    /// a no-op. [`OptionEscrow::exercise`] reads the live
    /// strike, so the new strike governs the next exercise
    /// (an exercise already settled keeps the strike it
    /// settled under). There is no event layer on
    /// `OptionEscrow`, so no event is emitted for the revision.
    /// Orthogonal to [`OptionEscrow::new`] (that installs the
    /// strike at build time, this revises it while `Active`)
    /// and to `exercise` (that settles at the strike, this
    /// reprices it).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller pair that is not exactly seller + buyer,
    /// ([`EscrowError::OptionAlreadySettled`], code 343) once
    /// the option has been exercised,
    /// ([`EscrowError::OptionExpired`], code 341) once the
    /// option has expired, and
    /// ([`EscrowError::InvalidOptionTerms`], code 339) for a
    /// zero new strike — either way the current strike is
    /// untouched.
    pub fn amend_option_strike(
        &mut self,
        seller: [u8; 32],
        buyer: [u8; 32],
        new_strike: u64,
    ) -> Result<(), EscrowError> {
        if seller != self.seller || buyer != self.buyer {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            OptionState::Active => {}
            OptionState::Exercised => return Err(EscrowError::OptionAlreadySettled),
            OptionState::Expired => return Err(EscrowError::OptionExpired),
        }
        if new_strike == 0 {
            return Err(EscrowError::InvalidOptionTerms);
        }
        if new_strike == self.strike {
            return Ok(());
        }
        self.strike = new_strike;
        Ok(())
    }

    /// Revise the expiry on an `Active` option (AV-299 — Solana
    /// option governance): both parties authorize the change
    /// (the expiry is a bilateral time term — a unilateral
    /// rewrite would let one side re-time the other's exercise
    /// window alone). Check order is authority → state → value,
    /// mirroring [`OptionEscrow::amend_option_strike`] and
    /// [`OptionEscrow::exercise`], so a stranger learns nothing
    /// about the option's state from the error alone.
    ///
    /// Why: the expiry is fixed at construction
    /// ([`OptionEscrow::new`]), but the parties may agree the
    /// bargained window no longer fits the deal — an expiry
    /// that cannot move would force a fresh option (and a fresh
    /// premium) for a legitimate rescheduling. Only an `Active`
    /// option may revise: an exercised option has already
    /// settled ([`EscrowError::OptionAlreadySettled`]), and an
    /// expired option's window has lapsed
    /// ([`EscrowError::OptionExpired`] — the lapsed-window
    /// error `exercise` returns once the window closes, since
    /// expiry settlement is then the only remaining path).
    /// The revision is judged by state, not by the clock, like
    /// `amend_option_strike`: an `Active` option whose expiry
    /// instant has passed but which has not yet been expired
    /// may still revise — and that is the point of the dual
    /// signature, a strike revision never revives the exercise
    /// window but an expiry revision agreed by both parties
    /// and extended to a future point reopens it (shortening
    /// to a point still above `now` likewise moves the
    /// window, never below it). The new expiry reuses the
    /// `new` gate (it must be positive — 0 is "no expiry",
    /// a perpetual, a different instrument — and strictly
    /// later than `now`, [`EscrowError::InvalidOptionTerms`]
    /// otherwise, and the current expiry is untouched either
    /// way): a revision only moves the window, it never
    /// forces expiry through the back door — forcing expiry
    /// is [`OptionEscrow::expire`]'s job. Only `expiry`
    /// changes — seller, buyer, underlying, premium, strike
    /// and state are untouched — and re-affirming the current
    /// expiry is a no-op, provided the current expiry is
    /// still in the future (re-affirming an already-lapsed
    /// expiry fails the `> now` gate). [`OptionEscrow::exercise`]
    /// and [`OptionEscrow::expire`] read the live expiry, so
    /// the new expiry governs the next exercise or expiry
    /// (a settlement already made keeps the expiry it
    /// settled under). There is no event layer on
    /// `OptionEscrow`, so no event is emitted for the revision.
    /// Orthogonal to [`OptionEscrow::new`] (that installs the
    /// expiry at build time, this revises it while `Active`),
    /// to `amend_option_strike` (that reprices, this
    /// reschedules), and to `exercise` / `expire` (those
    /// settle at the expiry, this moves it).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller pair that is not exactly seller + buyer,
    /// ([`EscrowError::OptionAlreadySettled`], code 343) once
    /// the option has been exercised,
    /// ([`EscrowError::OptionExpired`], code 341) once the
    /// option has expired, and
    /// ([`EscrowError::InvalidOptionTerms`], code 339) for a
    /// zero new expiry or one at or before `now` — either way
    /// the current expiry is untouched.
    pub fn amend_option_expiry(
        &mut self,
        seller: [u8; 32],
        buyer: [u8; 32],
        new_expiry: u64,
        now: u64,
    ) -> Result<(), EscrowError> {
        if seller != self.seller || buyer != self.buyer {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            OptionState::Active => {}
            OptionState::Exercised => return Err(EscrowError::OptionAlreadySettled),
            OptionState::Expired => return Err(EscrowError::OptionExpired),
        }
        if new_expiry == 0 {
            return Err(EscrowError::InvalidOptionTerms);
        }
        if new_expiry <= now {
            return Err(EscrowError::InvalidOptionTerms);
        }
        if new_expiry == self.expiry {
            return Ok(());
        }
        self.expiry = new_expiry;
        Ok(())
    }

    /// Rotate the seller on an `Active` option (AV-366 — Solana
    /// option governance): both parties authorize the change
    /// (the seller is the bilateral settlement counterparty — a
    /// unilateral rewrite would let one side redirect both
    /// settlement legs alone). Check order is authority → state
    /// → value, mirroring [`OptionEscrow::amend_option_strike`]
    /// and [`OptionEscrow::exercise`], so a stranger learns
    /// nothing about the option's state from the error alone.
    ///
    /// Why: the seller is fixed at construction
    /// ([`OptionEscrow::new`]), but the seller's key may be
    /// compromised, or the seller may move from a hot wallet to
    /// cold storage — with no rotation path the only exits are
    /// `exercise` (the buyer exercises, and both legs pay the
    /// live seller) and `expire` (anyone may call it, and both
    /// legs still pay the live seller), so a stolen key sits and
    /// collects the underlying plus the premium at expiry. Only
    /// an `Active` option may rotate: an exercised option has
    /// already settled ([`EscrowError::OptionAlreadySettled`]),
    /// and an expired option's window has lapsed
    /// ([`EscrowError::OptionExpired`]). The revision is judged
    /// by state, not by the clock, like `amend_option_strike`:
    /// an `Active` option whose expiry instant has passed but
    /// which has not yet been expired may still rotate — the
    /// rotation never revives the exercise window, which still
    /// closes at `expiry`. The new seller reuses the `new` gate
    /// (it must be non-zero and distinct from the live buyer,
    /// [`EscrowError::InvalidOptionTerms`] otherwise, and the
    /// current seller is untouched). Only `seller` changes —
    /// buyer, underlying, premium, strike, expiry and state are
    /// untouched — and re-affirming the current seller is a
    /// no-op. [`OptionEscrow::exercise`] and
    /// [`OptionEscrow::expire`] read the live seller, so the new
    /// seller governs the next settlement (a settlement already
    /// made keeps the seller it settled under). There is no event
    /// layer on `OptionEscrow`, so no event is emitted for the
    /// rotation. A seller who has lost their key cannot rotate:
    /// the current seller must co-sign, exactly like the pauser
    /// rotation (AV-355) — key loss is not recoverable here.
    /// Orthogonal to [`OptionEscrow::new`] (that installs the
    /// seller at build time, this rotates it while `Active`) and
    /// to `amend_option_strike` / `amend_option_expiry` (those
    /// revise terms, this rotates the counterparty).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller pair that is not exactly seller + buyer,
    /// ([`EscrowError::OptionAlreadySettled`], code 343) once
    /// the option has been exercised,
    /// ([`EscrowError::OptionExpired`], code 341) once the
    /// option has expired, and
    /// ([`EscrowError::InvalidOptionTerms`], code 339) for a
    /// zero new seller or one equal to the live buyer — either
    /// way the current seller is untouched.
    pub fn amend_option_seller(
        &mut self,
        seller: [u8; 32],
        buyer: [u8; 32],
        new_seller: [u8; 32],
    ) -> Result<(), EscrowError> {
        if seller != self.seller || buyer != self.buyer {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            OptionState::Active => {}
            OptionState::Exercised => return Err(EscrowError::OptionAlreadySettled),
            OptionState::Expired => return Err(EscrowError::OptionExpired),
        }
        if new_seller == [0u8; 32] || new_seller == self.buyer {
            return Err(EscrowError::InvalidOptionTerms);
        }
        if new_seller == self.seller {
            return Ok(());
        }
        self.seller = new_seller;
        Ok(())
    }

    /// Rotate the buyer on an `Active` option (AV-367 — Solana
    /// option governance): both parties authorize the change
    /// (the buyer is the sole holder of the exercise right — a
    /// unilateral rewrite would let one side redirect that right
    /// alone, handing the option to a stranger or stranding it).
    /// Check order is authority → state → value, mirroring
    /// [`OptionEscrow::amend_option_seller`] and
    /// [`OptionEscrow::exercise`], so a stranger learns nothing
    /// about the option's state from the error alone.
    ///
    /// Why: the buyer is fixed at construction
    /// ([`OptionEscrow::new`]), but the buyer's key may be
    /// compromised, or the buyer may assign the position to
    /// another wallet (an option assignment: the holder hands
    /// the exercise right to a new wallet or sells the
    /// position) — with no rotation path the only exits are
    /// `exercise` (only the live buyer may call it) and `expire`
    /// (anyone may call it, and the premium stays with the
    /// seller), so a stolen key sits and collects nothing while
    /// the position's value drains to zero at expiry. Only an
    /// `Active` option may rotate: an exercised option has
    /// already settled ([`EscrowError::OptionAlreadySettled`]),
    /// and an expired option's window has lapsed
    /// ([`EscrowError::OptionExpired`]). The revision is judged
    /// by state, not by the clock, like `amend_option_strike`:
    /// an `Active` option whose expiry instant has passed but
    /// which has not yet been expired may still rotate — the
    /// rotation never revives the exercise window, which still
    /// closes at `expiry`. The new buyer reuses the `new` gate
    /// (it must be non-zero and distinct from the live seller,
    /// [`EscrowError::InvalidOptionTerms`] otherwise, and the
    /// current buyer is untouched). Only `buyer` changes —
    /// seller, underlying, premium, strike, expiry and state are
    /// untouched — and re-affirming the current buyer is a
    /// no-op. [`OptionEscrow::exercise`] reads the live buyer,
    /// so the new buyer is the sole exerciser from the next
    /// exercise (the old buyer gets
    /// [`EscrowError::OptionNotBuyer`]), and `expire` is
    /// unaffected (anyone may call it, and the legs still pay
    /// the seller). There is no event layer on `OptionEscrow`,
    /// so no event is emitted for the rotation. A buyer who has
    /// lost their key cannot rotate: the current buyer must
    /// co-sign, exactly like the seller rotation (AV-366) and
    /// the pauser rotation (AV-355) — key loss is not
    /// recoverable here. Orthogonal to
    /// [`OptionEscrow::new`] (that installs the buyer at build
    /// time, this rotates it while `Active`) and to
    /// `amend_option_seller` (that rotates the settlement
    /// counterparty, this rotates the exercise-right holder).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller pair that is not exactly seller + buyer,
    /// ([`EscrowError::OptionAlreadySettled`], code 343) once
    /// the option has been exercised,
    /// ([`EscrowError::OptionExpired`], code 341) once the
    /// option has expired, and
    /// ([`EscrowError::InvalidOptionTerms`], code 339) for a
    /// zero new buyer or one equal to the live seller — either
    /// way the current buyer is untouched.
    pub fn amend_option_buyer(
        &mut self,
        seller: [u8; 32],
        buyer: [u8; 32],
        new_buyer: [u8; 32],
    ) -> Result<(), EscrowError> {
        if seller != self.seller || buyer != self.buyer {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            OptionState::Active => {}
            OptionState::Exercised => return Err(EscrowError::OptionAlreadySettled),
            OptionState::Expired => return Err(EscrowError::OptionExpired),
        }
        if new_buyer == [0u8; 32] || new_buyer == self.seller {
            return Err(EscrowError::InvalidOptionTerms);
        }
        if new_buyer == self.buyer {
            return Ok(());
        }
        self.buyer = new_buyer;
        Ok(())
    }

    /// Revise the premium on an `Active` option (AV-371 — Solana
    /// option governance): both parties authorize the change
    /// (the premium is a bilateral price term — a unilateral
    /// rewrite would let one side reprice the other's bargain
    /// alone). Check order is authority → state → value,
    /// mirroring [`OptionEscrow::amend_option_strike`] and
    /// [`OptionEscrow::exercise`], so a stranger learns nothing
    /// about the option's state from the error alone.
    ///
    /// Why: the premium is fixed at construction
    /// ([`OptionEscrow::new`]), but the parties may agree the
    /// bargained price no longer reflects the deal — volatility
    /// moved, or the strike was revised (AV-294) and the premium
    /// never followed it, so the option is mispriced against its
    /// own strike. A premium that cannot move would force a
    /// fresh option (and a fresh custody) for a legitimate
    /// repricing, discarding the `Active` state. Only an `Active`
    /// option may revise: an exercised option has already
    /// settled ([`EscrowError::OptionAlreadySettled`]), and an
    /// expired option's window has lapsed
    /// ([`EscrowError::OptionExpired`] — the lapsed-window
    /// error `exercise` returns once the window closes, since
    /// expiry settlement is then the only remaining path).
    /// The revision takes no timestamp: like `amend_option_strike`,
    /// the settlement boundary is the explicit state transition,
    /// not the wall clock, so an `Active` option whose expiry
    /// instant has passed but which has not yet been expired
    /// may still revise — the revision never revives the
    /// exercise window, which still closes at `expiry`. The
    /// new premium reuses the `new` gate (it must be positive,
    /// [`EscrowError::InvalidOptionTerms`] otherwise, and the
    /// current premium is untouched). Only `premium` changes —
    /// seller, buyer, underlying, strike, expiry and state are
    /// untouched — and re-affirming the current premium is a
    /// no-op. [`OptionEscrow::exercise`] and
    /// [`OptionEscrow::expire`] read the live premium, so the new
    /// premium governs the next settlement (a settlement already
    /// made keeps the premium it settled under). There is no
    /// event layer on `OptionEscrow`, so no event is emitted for
    /// the revision. Orthogonal to [`OptionEscrow::new`] (that
    /// installs the premium at build time, this revises it while
    /// `Active`) and to `exercise` / `expire` (those settle at
    /// the premium, this reprices it).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller pair that is not exactly seller + buyer,
    /// ([`EscrowError::OptionAlreadySettled`], code 343) once
    /// the option has been exercised,
    /// ([`EscrowError::OptionExpired`], code 341) once the
    /// option has expired, and
    /// ([`EscrowError::InvalidOptionTerms`], code 339) for a
    /// zero new premium — either way the current premium is
    /// untouched.
    pub fn amend_option_premium(
        &mut self,
        seller: [u8; 32],
        buyer: [u8; 32],
        new_premium: u64,
    ) -> Result<(), EscrowError> {
        if seller != self.seller || buyer != self.buyer {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            OptionState::Active => {}
            OptionState::Exercised => return Err(EscrowError::OptionAlreadySettled),
            OptionState::Expired => return Err(EscrowError::OptionExpired),
        }
        if new_premium == 0 {
            return Err(EscrowError::InvalidOptionTerms);
        }
        if new_premium == self.premium {
            return Ok(());
        }
        self.premium = new_premium;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SELLER: [u8; 32] = [0x11; 32];
    const BUYER: [u8; 32] = [0x22; 32];
    const STRANGER: [u8; 32] = [0x33; 32];
    const NEW_SELLER: [u8; 32] = [0x44; 32];
    const NEW_SELLER_2: [u8; 32] = [0x55; 32];
    const NEW_BUYER: [u8; 32] = [0x66; 32];
    const NEW_BUYER_2: [u8; 32] = [0x77; 32];
    const UNDERLYING: u64 = 1_000_000;
    const PREMIUM: u64 = 50_000;
    const STRIKE: u64 = 900_000;
    const EXPIRY: u64 = 1_800_000_000;

    fn option() -> OptionEscrow {
        OptionEscrow::new(SELLER, BUYER, UNDERLYING, PREMIUM, STRIKE, EXPIRY).unwrap()
    }

    #[test]
    fn construction_validates_terms() {
        // Zero parties, same party, zero amounts, zero expiry.
        assert_eq!(
            OptionEscrow::new([0u8; 32], BUYER, UNDERLYING, PREMIUM, STRIKE, EXPIRY),
            Err(EscrowError::InvalidOptionTerms)
        );
        assert_eq!(
            OptionEscrow::new(SELLER, [0u8; 32], UNDERLYING, PREMIUM, STRIKE, EXPIRY),
            Err(EscrowError::InvalidOptionTerms)
        );
        assert_eq!(
            OptionEscrow::new(SELLER, SELLER, UNDERLYING, PREMIUM, STRIKE, EXPIRY),
            Err(EscrowError::InvalidOptionTerms)
        );
        assert_eq!(
            OptionEscrow::new(SELLER, BUYER, 0, PREMIUM, STRIKE, EXPIRY),
            Err(EscrowError::InvalidOptionTerms)
        );
        assert_eq!(
            OptionEscrow::new(SELLER, BUYER, UNDERLYING, 0, STRIKE, EXPIRY),
            Err(EscrowError::InvalidOptionTerms)
        );
        assert_eq!(
            OptionEscrow::new(SELLER, BUYER, UNDERLYING, PREMIUM, 0, EXPIRY),
            Err(EscrowError::InvalidOptionTerms)
        );
        assert_eq!(
            OptionEscrow::new(SELLER, BUYER, UNDERLYING, PREMIUM, STRIKE, 0),
            Err(EscrowError::InvalidOptionTerms)
        );
        let o = option();
        assert_eq!(o.state(), OptionState::Active);
        assert_eq!(o.seller(), SELLER);
        assert_eq!(o.buyer(), BUYER);
        assert!(o.exercise_window_open(EXPIRY - 1));
        assert!(!o.exercise_window_open(EXPIRY));
    }

    #[test]
    fn exercise_settles_every_leg() {
        let mut o = option();
        let legs = o.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
        assert_eq!(legs.underlying_to_buyer, UNDERLYING);
        assert_eq!(legs.strike_to_seller, STRIKE);
        assert_eq!(legs.premium_to_seller, PREMIUM);
        assert_eq!(o.state(), OptionState::Exercised);
        // Conservation: the seller's take is exactly premium +
        // strike, the buyer's take exactly the underlying.
        assert_eq!(legs.strike_to_seller + legs.premium_to_seller, STRIKE + PREMIUM);
    }

    #[test]
    fn exercise_check_order_is_buyer_state_time_payment() {
        let mut o = option();
        // Stranger, whatever the state or time: buyer error first.
        assert_eq!(
            o.exercise(STRANGER, EXPIRY - 1, STRIKE),
            Err(EscrowError::OptionNotBuyer)
        );
        // Wrong payment, right buyer, live window.
        assert_eq!(
            o.exercise(BUYER, EXPIRY - 1, STRIKE - 1),
            Err(EscrowError::OptionStrikeMismatch)
        );
        assert_eq!(
            o.exercise(BUYER, EXPIRY - 1, STRIKE + 1),
            Err(EscrowError::OptionStrikeMismatch)
        );
        // At expiry itself the window is already closed.
        assert_eq!(
            o.exercise(BUYER, EXPIRY, STRIKE),
            Err(EscrowError::OptionExpired)
        );
        // Settle, then every further call reports settled first.
        o.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
        assert_eq!(
            o.exercise(BUYER, EXPIRY - 1, STRIKE),
            Err(EscrowError::OptionAlreadySettled)
        );
        assert_eq!(
            o.exercise(STRANGER, EXPIRY - 1, STRIKE),
            Err(EscrowError::OptionNotBuyer)
        );
        let mut o2 = option();
        o2.expire(EXPIRY).unwrap();
        assert_eq!(
            o2.exercise(BUYER, EXPIRY - 1, STRIKE),
            Err(EscrowError::OptionAlreadySettled)
        );
    }

    #[test]
    fn expiry_returns_premium_and_underlying_to_seller() {
        let mut o = option();
        // Before expiry the buyer's window is still open.
        assert_eq!(o.expire(EXPIRY - 1), Err(EscrowError::OptionNotExpired));
        // At expiry itself the option is already expirable.
        let legs = o.expire(EXPIRY).unwrap();
        assert_eq!(legs.underlying_to_seller, UNDERLYING);
        assert_eq!(legs.premium_to_seller, PREMIUM);
        assert_eq!(o.state(), OptionState::Expired);
        // Terminal: no second settlement either way.
        assert_eq!(o.expire(EXPIRY + 1), Err(EscrowError::OptionAlreadySettled));
    }

    #[test]
    fn amend_option_strike_moves_the_live_strike() {
        // AV-294: the revised strike governs the next exercise,
        // and nothing else moves.
        let mut o = option();
        o.amend_option_strike(SELLER, BUYER, 1_100_000).unwrap();
        assert_eq!(o.strike(), 1_100_000);
        assert_eq!(o.seller(), SELLER);
        assert_eq!(o.buyer(), BUYER);
        assert_eq!(o.underlying(), UNDERLYING);
        assert_eq!(o.premium(), PREMIUM);
        assert_eq!(o.expiry(), EXPIRY);
        assert_eq!(o.state(), OptionState::Active);
        // The old strike no longer buys the underlying.
        assert_eq!(
            o.exercise(BUYER, EXPIRY - 1, STRIKE),
            Err(EscrowError::OptionStrikeMismatch)
        );
        let legs = o.exercise(BUYER, EXPIRY - 1, 1_100_000).unwrap();
        assert_eq!(legs.strike_to_seller, 1_100_000);
        assert_eq!(legs.underlying_to_buyer, UNDERLYING);
        assert_eq!(legs.premium_to_seller, PREMIUM);
    }

    #[test]
    fn amend_option_strike_can_reprice_down_and_again() {
        // AV-294: revisions are not one-shot — each amendment
        // supersedes the last, and exercise always reads live.
        let mut o = option();
        o.amend_option_strike(SELLER, BUYER, 800_000).unwrap();
        o.amend_option_strike(SELLER, BUYER, 950_000).unwrap();
        assert_eq!(o.strike(), 950_000);
        assert_eq!(
            o.exercise(BUYER, EXPIRY - 1, 800_000),
            Err(EscrowError::OptionStrikeMismatch)
        );
        o.exercise(BUYER, EXPIRY - 1, 950_000).unwrap();
    }

    #[test]
    fn amend_option_strike_rejects_zero_and_reaffirmation_is_noop() {
        // AV-294: a zero strike reuses the `new` gate and leaves
        // the current strike untouched; re-affirming the current
        // strike succeeds and changes nothing.
        let mut o = option();
        let err = o
            .amend_option_strike(SELLER, BUYER, 0)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidOptionTerms);
        assert_eq!(err.code(), 339);
        assert_eq!(o.strike(), STRIKE);
        o.amend_option_strike(SELLER, BUYER, STRIKE).unwrap();
        assert_eq!(o.strike(), STRIKE);
        // Still exercisable at the affirmed strike.
        o.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
    }

    #[test]
    fn amend_option_strike_is_dual_signed_and_active_only() {
        // AV-294: a stranger, either party alone, or the parties
        // swapped is refused, and the strike is untouched.
        let mut o = option();
        let err = o
            .amend_option_strike(STRANGER, BUYER, 1_100_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = o
            .amend_option_strike(SELLER, STRANGER, 1_100_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        let err = o
            .amend_option_strike(BUYER, SELLER, 1_100_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(o.strike(), STRIKE);
        // Authority is checked before state: a stranger on a
        // settled option still gets Unauthorized.
        let mut exercised = option();
        exercised.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
        let err = exercised
            .amend_option_strike(STRANGER, BUYER, 1_100_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(exercised.strike(), STRIKE);
        // The parties on an exercised option get AlreadySettled.
        let err = exercised
            .amend_option_strike(SELLER, BUYER, 1_100_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::OptionAlreadySettled);
        assert_eq!(err.code(), 343);
        assert_eq!(exercised.strike(), STRIKE);
        // The parties on an expired option get OptionExpired.
        let mut expired = option();
        expired.expire(EXPIRY).unwrap();
        let err = expired
            .amend_option_strike(SELLER, BUYER, 1_100_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::OptionExpired);
        assert_eq!(err.code(), 341);
        assert_eq!(expired.strike(), STRIKE);
    }

    #[test]
    fn amend_option_expiry_moves_the_live_expiry() {
        // AV-299: the revised expiry governs the next exercise
        // and expiry, and nothing else moves.
        let mut o = option();
        o.amend_option_expiry(SELLER, BUYER, EXPIRY + 1_000, EXPIRY - 1)
            .unwrap();
        assert_eq!(o.expiry(), EXPIRY + 1_000);
        assert_eq!(o.seller(), SELLER);
        assert_eq!(o.buyer(), BUYER);
        assert_eq!(o.underlying(), UNDERLYING);
        assert_eq!(o.premium(), PREMIUM);
        assert_eq!(o.strike(), STRIKE);
        assert_eq!(o.state(), OptionState::Active);
        // The old expiry no longer closes the window: at the old
        // instant the option is neither expirable nor closed.
        assert_eq!(o.expire(EXPIRY), Err(EscrowError::OptionNotExpired));
        let legs = o.exercise(BUYER, EXPIRY, STRIKE).unwrap();
        assert_eq!(legs.underlying_to_buyer, UNDERLYING);
        assert_eq!(legs.strike_to_seller, STRIKE);
        assert_eq!(legs.premium_to_seller, PREMIUM);
    }

    #[test]
    fn amend_option_expiry_can_extend_a_lapsed_window_and_shorten() {
        // AV-299: unlike a strike revision, a dual-signed expiry
        // revision to a future point reopens a lapsed window —
        // that is the point of the dual signature — and shortening
        // to a point still above `now` moves the window too.
        let mut o = option();
        // Lapsed (now past expiry) but not yet expired: exercise
        // is closed, expiry is open — yet the parties may extend.
        assert_eq!(
            o.exercise(BUYER, EXPIRY, STRIKE),
            Err(EscrowError::OptionExpired)
        );
        o.amend_option_expiry(SELLER, BUYER, EXPIRY + 1_000, EXPIRY)
            .unwrap();
        assert_eq!(o.expiry(), EXPIRY + 1_000);
        // The window is open again at the old expiry instant.
        assert!(o.exercise_window_open(EXPIRY));
        let legs = o.exercise(BUYER, EXPIRY, STRIKE).unwrap();
        assert_eq!(legs.underlying_to_buyer, UNDERLYING);

        // Shortening: the new expiry still sits above `now`, so
        // the option lives until then and expires at it.
        let mut o2 = option();
        o2.amend_option_expiry(SELLER, BUYER, EXPIRY - 1_000, EXPIRY - 2_000)
            .unwrap();
        assert_eq!(o2.expiry(), EXPIRY - 1_000);
        assert_eq!(
            o2.exercise(BUYER, EXPIRY - 1_000, STRIKE),
            Err(EscrowError::OptionExpired)
        );
        let legs = o2.expire(EXPIRY - 1_000).unwrap();
        assert_eq!(legs.underlying_to_seller, UNDERLYING);
        assert_eq!(legs.premium_to_seller, PREMIUM);
    }

    #[test]
    fn amend_option_expiry_rejects_zero_past_and_reaffirmation_is_noop() {
        // AV-299: a zero expiry reuses the `new` gate (0 is "no
        // expiry", a perpetual); an expiry at or before `now`
        // would force expiry through the back door, so it fails
        // closed too — either way the current expiry is untouched.
        // Re-affirming the current expiry (still in the future)
        // succeeds and changes nothing.
        let mut o = option();
        let err = o
            .amend_option_expiry(SELLER, BUYER, 0, EXPIRY - 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidOptionTerms);
        assert_eq!(err.code(), 339);
        assert_eq!(o.expiry(), EXPIRY);
        for bad in [EXPIRY - 1, EXPIRY - 2] {
            let err = o
                .amend_option_expiry(SELLER, BUYER, bad, EXPIRY - 1)
                .unwrap_err();
            assert_eq!(err, EscrowError::InvalidOptionTerms);
            assert_eq!(o.expiry(), EXPIRY);
        }
        // At the expiry instant itself the new expiry must still
        // be in the future — `now` itself is not a valid expiry.
        let err = o
            .amend_option_expiry(SELLER, BUYER, EXPIRY, EXPIRY)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidOptionTerms);
        assert_eq!(o.expiry(), EXPIRY);
        // Re-affirming an already-lapsed expiry fails the same
        // gate: the requested expiry is not in the future.
        let err = o
            .amend_option_expiry(SELLER, BUYER, EXPIRY, EXPIRY + 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidOptionTerms);
        assert_eq!(o.expiry(), EXPIRY);
        // Re-affirming the current (future) expiry is a no-op.
        o.amend_option_expiry(SELLER, BUYER, EXPIRY, EXPIRY - 1)
            .unwrap();
        assert_eq!(o.expiry(), EXPIRY);
        // Still exercisable at the affirmed expiry.
        o.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
    }

    #[test]
    fn amend_option_expiry_is_dual_signed_and_active_only() {
        // AV-299: a stranger, either party alone, or the parties
        // swapped is refused, and the expiry is untouched.
        let mut o = option();
        let err = o
            .amend_option_expiry(STRANGER, BUYER, EXPIRY + 1_000, EXPIRY - 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = o
            .amend_option_expiry(SELLER, STRANGER, EXPIRY + 1_000, EXPIRY - 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        let err = o
            .amend_option_expiry(BUYER, SELLER, EXPIRY + 1_000, EXPIRY - 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(o.expiry(), EXPIRY);
        // Authority is checked before state: a stranger on a
        // settled option still gets Unauthorized.
        let mut exercised = option();
        exercised.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
        let err = exercised
            .amend_option_expiry(STRANGER, BUYER, EXPIRY + 1_000, EXPIRY - 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(exercised.expiry(), EXPIRY);
        // The parties on an exercised option get AlreadySettled.
        let err = exercised
            .amend_option_expiry(SELLER, BUYER, EXPIRY + 1_000, EXPIRY - 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::OptionAlreadySettled);
        assert_eq!(err.code(), 343);
        assert_eq!(exercised.expiry(), EXPIRY);
        // The parties on an expired option get OptionExpired.
        let mut expired = option();
        expired.expire(EXPIRY).unwrap();
        let err = expired
            .amend_option_expiry(SELLER, BUYER, EXPIRY + 1_000, EXPIRY - 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::OptionExpired);
        assert_eq!(err.code(), 341);
        assert_eq!(expired.expiry(), EXPIRY);
    }

    #[test]
    fn amend_option_seller_moves_the_live_seller() {
        // AV-366: the revised seller governs the next settlement,
        // and nothing else moves.
        let mut o = option();
        o.amend_option_seller(SELLER, BUYER, NEW_SELLER).unwrap();
        assert_eq!(o.seller(), NEW_SELLER);
        assert_eq!(o.buyer(), BUYER);
        assert_eq!(o.underlying(), UNDERLYING);
        assert_eq!(o.premium(), PREMIUM);
        assert_eq!(o.strike(), STRIKE);
        assert_eq!(o.expiry(), EXPIRY);
        assert_eq!(o.state(), OptionState::Active);
        // The buyer still exercises at the same strike, and the
        // legs are unchanged in amount — they now pay the new
        // seller, whose identity the legs carry by construction
        // (exercise/expire return the amounts for the live seller).
        let legs = o.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
        assert_eq!(legs.underlying_to_buyer, UNDERLYING);
        assert_eq!(legs.strike_to_seller, STRIKE);
        assert_eq!(legs.premium_to_seller, PREMIUM);
    }

    #[test]
    fn amend_option_seller_can_rotate_again() {
        // AV-366: rotations are not one-shot — each rotation
        // supersedes the last, and the new seller is the authority
        // for the next one.
        let mut o = option();
        o.amend_option_seller(SELLER, BUYER, NEW_SELLER).unwrap();
        o.amend_option_seller(NEW_SELLER, BUYER, NEW_SELLER_2)
            .unwrap();
        assert_eq!(o.seller(), NEW_SELLER_2);
        // The first seller can no longer rotate: it is a stranger
        // now.
        let err = o
            .amend_option_seller(SELLER, BUYER, NEW_SELLER)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(o.seller(), NEW_SELLER_2);
    }

    #[test]
    fn amend_option_seller_rejects_zero_buyer_equal_and_reaffirmation_is_noop() {
        // AV-366: a zero seller or one equal to the live buyer
        // reuses the `new` gate and leaves the current seller
        // untouched; re-affirming the current seller succeeds and
        // changes nothing.
        let mut o = option();
        let err = o
            .amend_option_seller(SELLER, BUYER, [0u8; 32])
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidOptionTerms);
        assert_eq!(err.code(), 339);
        assert_eq!(o.seller(), SELLER);
        let err = o
            .amend_option_seller(SELLER, BUYER, BUYER)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidOptionTerms);
        assert_eq!(o.seller(), SELLER);
        o.amend_option_seller(SELLER, BUYER, SELLER).unwrap();
        assert_eq!(o.seller(), SELLER);
        // Still exercisable with the affirmed seller in place.
        o.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
    }

    #[test]
    fn amend_option_seller_is_dual_signed_and_active_only() {
        // AV-366: a stranger, either party alone, or the parties
        // swapped is refused, and the seller is untouched.
        let mut o = option();
        let err = o
            .amend_option_seller(STRANGER, BUYER, NEW_SELLER)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = o
            .amend_option_seller(SELLER, STRANGER, NEW_SELLER)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        let err = o
            .amend_option_seller(BUYER, SELLER, NEW_SELLER)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(o.seller(), SELLER);
        // Authority is checked before state: a stranger on a
        // settled option still gets Unauthorized.
        let mut exercised = option();
        exercised.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
        let err = exercised
            .amend_option_seller(STRANGER, BUYER, NEW_SELLER)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(exercised.seller(), SELLER);
        // The parties on an exercised option get AlreadySettled.
        let err = exercised
            .amend_option_seller(SELLER, BUYER, NEW_SELLER)
            .unwrap_err();
        assert_eq!(err, EscrowError::OptionAlreadySettled);
        assert_eq!(err.code(), 343);
        assert_eq!(exercised.seller(), SELLER);
        // The parties on an expired option get OptionExpired.
        let mut expired = option();
        expired.expire(EXPIRY).unwrap();
        let err = expired
            .amend_option_seller(SELLER, BUYER, NEW_SELLER)
            .unwrap_err();
        assert_eq!(err, EscrowError::OptionExpired);
        assert_eq!(err.code(), 341);
        assert_eq!(expired.seller(), SELLER);
    }

    #[test]
    fn amend_option_seller_old_seller_loses_governance() {
        // AV-366: rotation revokes the old seller's governance —
        // the old seller plus the buyer can no longer revise the
        // strike or the expiry.
        let mut o = option();
        o.amend_option_seller(SELLER, BUYER, NEW_SELLER).unwrap();
        let err = o
            .amend_option_strike(SELLER, BUYER, 1_100_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = o
            .amend_option_expiry(SELLER, BUYER, EXPIRY + 1_000, EXPIRY - 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(o.strike(), STRIKE);
        assert_eq!(o.expiry(), EXPIRY);
    }

    #[test]
    fn amend_option_seller_new_seller_can_govern() {
        // AV-366: the new seller plus the buyer keep governing —
        // a strike revision succeeds, and the next exercise
        // settles at the new strike (its legs pay the new seller).
        let mut o = option();
        o.amend_option_seller(SELLER, BUYER, NEW_SELLER).unwrap();
        o.amend_option_strike(NEW_SELLER, BUYER, 1_100_000)
            .unwrap();
        assert_eq!(o.strike(), 1_100_000);
        let legs = o.exercise(BUYER, EXPIRY - 1, 1_100_000).unwrap();
        assert_eq!(legs.strike_to_seller, 1_100_000);
        assert_eq!(legs.underlying_to_buyer, UNDERLYING);
        assert_eq!(legs.premium_to_seller, PREMIUM);
    }

    #[test]
    fn amend_option_seller_expiry_still_settles_after_rotation() {
        // AV-366: rotation disturbs nothing about expiry — an
        // unexercised option still expires at the same instant
        // with the same legs.
        let mut o = option();
        o.amend_option_seller(SELLER, BUYER, NEW_SELLER).unwrap();
        assert_eq!(
            o.expire(EXPIRY - 1),
            Err(EscrowError::OptionNotExpired)
        );
        let legs = o.expire(EXPIRY).unwrap();
        assert_eq!(legs.underlying_to_seller, UNDERLYING);
        assert_eq!(legs.premium_to_seller, PREMIUM);
        assert_eq!(o.state(), OptionState::Expired);
    }

    #[test]
    fn amend_option_seller_lapsed_window_still_rotates() {
        // AV-366: like the strike revision, rotation is judged by
        // state, not by the clock — an `Active` option whose
        // expiry instant has passed but which has not yet been
        // expired may still rotate, and the rotation never revives
        // the exercise window.
        let mut o = option();
        assert_eq!(
            o.exercise(BUYER, EXPIRY, STRIKE),
            Err(EscrowError::OptionExpired)
        );
        o.amend_option_seller(SELLER, BUYER, NEW_SELLER).unwrap();
        assert_eq!(o.seller(), NEW_SELLER);
        assert!(!o.exercise_window_open(EXPIRY));
        assert_eq!(
            o.exercise(BUYER, EXPIRY, STRIKE),
            Err(EscrowError::OptionExpired)
        );
        let legs = o.expire(EXPIRY).unwrap();
        assert_eq!(legs.underlying_to_seller, UNDERLYING);
        assert_eq!(legs.premium_to_seller, PREMIUM);
    }

    #[test]
    fn amend_option_buyer_moves_the_live_buyer() {
        // AV-367: the revised buyer governs the next exercise,
        // and nothing else moves.
        let mut o = option();
        o.amend_option_buyer(SELLER, BUYER, NEW_BUYER).unwrap();
        assert_eq!(o.buyer(), NEW_BUYER);
        assert_eq!(o.seller(), SELLER);
        assert_eq!(o.underlying(), UNDERLYING);
        assert_eq!(o.premium(), PREMIUM);
        assert_eq!(o.strike(), STRIKE);
        assert_eq!(o.expiry(), EXPIRY);
        assert_eq!(o.state(), OptionState::Active);
        // The old buyer is refused at the exercise gate, the new
        // buyer exercises at the same strike with the same legs.
        assert_eq!(
            o.exercise(BUYER, EXPIRY - 1, STRIKE),
            Err(EscrowError::OptionNotBuyer)
        );
        let legs = o.exercise(NEW_BUYER, EXPIRY - 1, STRIKE).unwrap();
        assert_eq!(legs.underlying_to_buyer, UNDERLYING);
        assert_eq!(legs.strike_to_seller, STRIKE);
        assert_eq!(legs.premium_to_seller, PREMIUM);
    }

    #[test]
    fn amend_option_buyer_can_rotate_again() {
        // AV-367: rotations are not one-shot — each rotation
        // supersedes the last, and the new buyer is the authority
        // for the next one.
        let mut o = option();
        o.amend_option_buyer(SELLER, BUYER, NEW_BUYER).unwrap();
        o.amend_option_buyer(SELLER, NEW_BUYER, NEW_BUYER_2)
            .unwrap();
        assert_eq!(o.buyer(), NEW_BUYER_2);
        // The first buyer can no longer rotate: it is a stranger
        // now.
        let err = o
            .amend_option_buyer(SELLER, BUYER, NEW_BUYER)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(o.buyer(), NEW_BUYER_2);
    }

    #[test]
    fn amend_option_buyer_rejects_zero_seller_equal_and_reaffirmation_is_noop() {
        // AV-367: a zero buyer or one equal to the live seller
        // reuses the `new` gate and leaves the current buyer
        // untouched; re-affirming the current buyer succeeds and
        // changes nothing.
        let mut o = option();
        let err = o
            .amend_option_buyer(SELLER, BUYER, [0u8; 32])
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidOptionTerms);
        assert_eq!(err.code(), 339);
        assert_eq!(o.buyer(), BUYER);
        let err = o
            .amend_option_buyer(SELLER, BUYER, SELLER)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidOptionTerms);
        assert_eq!(o.buyer(), BUYER);
        o.amend_option_buyer(SELLER, BUYER, BUYER).unwrap();
        assert_eq!(o.buyer(), BUYER);
        // Still exercisable with the affirmed buyer in place.
        o.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
    }

    #[test]
    fn amend_option_buyer_is_dual_signed_and_active_only() {
        // AV-367: a stranger, either party alone, or the parties
        // swapped is refused, and the buyer is untouched.
        let mut o = option();
        let err = o
            .amend_option_buyer(STRANGER, BUYER, NEW_BUYER)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = o
            .amend_option_buyer(SELLER, STRANGER, NEW_BUYER)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        let err = o
            .amend_option_buyer(BUYER, SELLER, NEW_BUYER)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(o.buyer(), BUYER);
        // Authority is checked before state: a stranger on a
        // settled option still gets Unauthorized.
        let mut exercised = option();
        exercised.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
        let err = exercised
            .amend_option_buyer(STRANGER, BUYER, NEW_BUYER)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(exercised.buyer(), BUYER);
        // The parties on an exercised option get AlreadySettled.
        let err = exercised
            .amend_option_buyer(SELLER, BUYER, NEW_BUYER)
            .unwrap_err();
        assert_eq!(err, EscrowError::OptionAlreadySettled);
        assert_eq!(err.code(), 343);
        assert_eq!(exercised.buyer(), BUYER);
        // The parties on an expired option get OptionExpired.
        let mut expired = option();
        expired.expire(EXPIRY).unwrap();
        let err = expired
            .amend_option_buyer(SELLER, BUYER, NEW_BUYER)
            .unwrap_err();
        assert_eq!(err, EscrowError::OptionExpired);
        assert_eq!(err.code(), 341);
        assert_eq!(expired.buyer(), BUYER);
    }

    #[test]
    fn amend_option_buyer_old_buyer_loses_exercise() {
        // AV-367: rotation revokes the old buyer's exercise right
        // — the old buyer is refused at the exercise gate, and
        // the old buyer plus the seller can no longer rotate the
        // buyer back.
        let mut o = option();
        o.amend_option_buyer(SELLER, BUYER, NEW_BUYER).unwrap();
        assert_eq!(
            o.exercise(BUYER, EXPIRY - 1, STRIKE),
            Err(EscrowError::OptionNotBuyer)
        );
        let err = o
            .amend_option_buyer(SELLER, BUYER, BUYER)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(o.buyer(), NEW_BUYER);
    }

    #[test]
    fn amend_option_buyer_new_buyer_can_exercise_in_window() {
        // AV-367: the new buyer exercises inside the window at
        // the live strike, and the settlement legs are unchanged
        // — only the recipient of the underlying moved.
        let mut o = option();
        o.amend_option_buyer(SELLER, BUYER, NEW_BUYER).unwrap();
        let legs = o.exercise(NEW_BUYER, EXPIRY - 1, STRIKE).unwrap();
        assert_eq!(legs.underlying_to_buyer, UNDERLYING);
        assert_eq!(legs.strike_to_seller, STRIKE);
        assert_eq!(legs.premium_to_seller, PREMIUM);
        assert_eq!(o.state(), OptionState::Exercised);
    }

    #[test]
    fn amend_option_buyer_lapsed_window_still_rotates() {
        // AV-367: like the seller rotation, buyer rotation is
        // judged by state, not by the clock — an `Active` option
        // whose expiry instant has passed but which has not yet
        // been expired may still rotate, and the rotation never
        // revives the exercise window.
        let mut o = option();
        assert_eq!(
            o.exercise(BUYER, EXPIRY, STRIKE),
            Err(EscrowError::OptionExpired)
        );
        o.amend_option_buyer(SELLER, BUYER, NEW_BUYER).unwrap();
        assert_eq!(o.buyer(), NEW_BUYER);
        assert!(!o.exercise_window_open(EXPIRY));
        assert_eq!(
            o.exercise(NEW_BUYER, EXPIRY, STRIKE),
            Err(EscrowError::OptionExpired)
        );
        let legs = o.expire(EXPIRY).unwrap();
        assert_eq!(legs.underlying_to_seller, UNDERLYING);
        assert_eq!(legs.premium_to_seller, PREMIUM);
    }

    #[test]
    fn amend_option_buyer_old_buyer_loses_governance() {
        // AV-367: rotation revokes the old buyer's governance —
        // the old buyer plus the seller can no longer revise the
        // strike, the expiry, or the seller.
        let mut o = option();
        o.amend_option_buyer(SELLER, BUYER, NEW_BUYER).unwrap();
        let err = o
            .amend_option_strike(SELLER, BUYER, 1_100_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = o
            .amend_option_expiry(SELLER, BUYER, EXPIRY + 1_000, EXPIRY - 1)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = o
            .amend_option_seller(SELLER, BUYER, NEW_SELLER)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(o.strike(), STRIKE);
        assert_eq!(o.expiry(), EXPIRY);
        assert_eq!(o.seller(), SELLER);
    }

    #[test]
    fn amend_option_buyer_expiry_still_settles_after_rotation() {
        // AV-367: rotation disturbs nothing about expiry — an
        // unexercised option still expires at the same instant
        // with the same legs, and the new buyer cannot stop it.
        let mut o = option();
        o.amend_option_buyer(SELLER, BUYER, NEW_BUYER).unwrap();
        assert_eq!(
            o.expire(EXPIRY - 1),
            Err(EscrowError::OptionNotExpired)
        );
        let legs = o.expire(EXPIRY).unwrap();
        assert_eq!(legs.underlying_to_seller, UNDERLYING);
        assert_eq!(legs.premium_to_seller, PREMIUM);
        assert_eq!(o.state(), OptionState::Expired);
    }

    #[test]
    fn amend_option_premium_moves_the_live_premium() {
        // AV-371: the revised premium governs the next exercise,
        // and nothing else moves.
        let mut o = option();
        o.amend_option_premium(SELLER, BUYER, 80_000).unwrap();
        assert_eq!(o.premium(), 80_000);
        assert_eq!(o.seller(), SELLER);
        assert_eq!(o.buyer(), BUYER);
        assert_eq!(o.underlying(), UNDERLYING);
        assert_eq!(o.strike(), STRIKE);
        assert_eq!(o.expiry(), EXPIRY);
        assert_eq!(o.state(), OptionState::Active);
        // Exercise settles at the new premium: the seller's take
        // is the strike plus the revised premium.
        let legs = o.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
        assert_eq!(legs.underlying_to_buyer, UNDERLYING);
        assert_eq!(legs.strike_to_seller, STRIKE);
        assert_eq!(legs.premium_to_seller, 80_000);
    }

    #[test]
    fn amend_option_premium_can_reprice_again() {
        // AV-371: revisions are not one-shot — each amendment
        // supersedes the last, and exercise always reads live.
        let mut o = option();
        o.amend_option_premium(SELLER, BUYER, 30_000).unwrap();
        o.amend_option_premium(SELLER, BUYER, 120_000).unwrap();
        assert_eq!(o.premium(), 120_000);
        let legs = o.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
        assert_eq!(legs.premium_to_seller, 120_000);
        assert_eq!(legs.strike_to_seller, STRIKE);
    }

    #[test]
    fn amend_option_premium_rejects_zero_and_reaffirmation_is_noop() {
        // AV-371: a zero premium reuses the `new` gate and leaves
        // the current premium untouched; re-affirming the current
        // premium succeeds and changes nothing.
        let mut o = option();
        let err = o
            .amend_option_premium(SELLER, BUYER, 0)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidOptionTerms);
        assert_eq!(err.code(), 339);
        assert_eq!(o.premium(), PREMIUM);
        o.amend_option_premium(SELLER, BUYER, PREMIUM).unwrap();
        assert_eq!(o.premium(), PREMIUM);
        // Still exercisable, settling at the affirmed premium.
        let legs = o.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
        assert_eq!(legs.premium_to_seller, PREMIUM);
    }

    #[test]
    fn amend_option_premium_is_dual_signed_and_active_only() {
        // AV-371: a stranger, either party alone, or the parties
        // swapped is refused, and the premium is untouched.
        let mut o = option();
        let err = o
            .amend_option_premium(STRANGER, BUYER, 80_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        let err = o
            .amend_option_premium(SELLER, STRANGER, 80_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        let err = o
            .amend_option_premium(BUYER, SELLER, 80_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(o.premium(), PREMIUM);
        // Authority is checked before state: a stranger on a
        // settled option still gets Unauthorized.
        let mut exercised = option();
        exercised.exercise(BUYER, EXPIRY - 1, STRIKE).unwrap();
        let err = exercised
            .amend_option_premium(STRANGER, BUYER, 80_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(exercised.premium(), PREMIUM);
        // The parties on an exercised option get AlreadySettled.
        let err = exercised
            .amend_option_premium(SELLER, BUYER, 80_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::OptionAlreadySettled);
        assert_eq!(err.code(), 343);
        assert_eq!(exercised.premium(), PREMIUM);
        // The parties on an expired option get OptionExpired.
        let mut expired = option();
        expired.expire(EXPIRY).unwrap();
        let err = expired
            .amend_option_premium(SELLER, BUYER, 80_000)
            .unwrap_err();
        assert_eq!(err, EscrowError::OptionExpired);
        assert_eq!(err.code(), 341);
        assert_eq!(expired.premium(), PREMIUM);
    }

    #[test]
    fn amend_option_premium_expiry_settles_at_new_premium() {
        // AV-371: the expiry leg reads the live premium too — a
        // repriced option that dies unexercised leaves the new
        // premium with the seller, and the old premium is gone.
        let mut o = option();
        o.amend_option_premium(SELLER, BUYER, 80_000).unwrap();
        let legs = o.expire(EXPIRY).unwrap();
        assert_eq!(legs.underlying_to_seller, UNDERLYING);
        assert_eq!(legs.premium_to_seller, 80_000);
        assert_eq!(o.state(), OptionState::Expired);
    }

    #[test]
    fn amend_option_premium_lapsed_window_still_revises() {
        // AV-371: like the strike revision, the premium revision
        // is judged by state, not by the clock — an `Active`
        // option whose expiry instant has passed but which has
        // not yet been expired may still revise, and the revision
        // never revives the exercise window.
        let mut o = option();
        assert_eq!(
            o.exercise(BUYER, EXPIRY, STRIKE),
            Err(EscrowError::OptionExpired)
        );
        o.amend_option_premium(SELLER, BUYER, 80_000).unwrap();
        assert_eq!(o.premium(), 80_000);
        assert!(!o.exercise_window_open(EXPIRY));
        assert_eq!(
            o.exercise(BUYER, EXPIRY, STRIKE),
            Err(EscrowError::OptionExpired)
        );
        let legs = o.expire(EXPIRY).unwrap();
        assert_eq!(legs.premium_to_seller, 80_000);
    }
}
