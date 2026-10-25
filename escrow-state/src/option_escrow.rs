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
/// option's terms are set once at construction and never
/// renegotiated — a strike or expiry that could move after the
/// premium was paid would let one side rewrite the deal.
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
    /// premium in every outcome.
    pub fn seller(&self) -> [u8; 32] {
        self.seller
    }

    /// The buyer: the option holder, the only party who may
    /// exercise.
    pub fn buyer(&self) -> [u8; 32] {
        self.buyer
    }

    /// The locked underlying amount.
    pub fn underlying(&self) -> u64 {
        self.underlying
    }

    /// The up-front premium (non-refundable in every outcome).
    pub fn premium(&self) -> u64 {
        self.premium
    }

    /// The fixed strike price the buyer pays on exercise.
    pub fn strike(&self) -> u64 {
        self.strike
    }

    /// The expiry timestamp: exercise needs `now < expiry`,
    /// expiry settles at `now >= expiry`.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const SELLER: [u8; 32] = [0x11; 32];
    const BUYER: [u8; 32] = [0x22; 32];
    const STRANGER: [u8; 32] = [0x33; 32];
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
}
