//! Pure-Rust escrow vault state machine.
//!
//! This crate is the dependency-free logic core of the escrow vault.
//! It models the full lifecycle of a two-party escrow with initializer
//! authority checks and amount invariants. The Anchor program under
//! `programs/escrow-vault` wraps exactly this logic for the Solana target.

/// Lifecycle states of an escrow vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowState {
    Uninitialized,
    Funded,
    Released,
    Cancelled,
}

/// An escrow vault. Public keys are `[u8; 32]` so this crate stays
/// dependency-free; the Anchor layer converts `Pubkey` to/from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Escrow {
    initializer: [u8; 32],
    taker: [u8; 32],
    amount: u64,
    state: EscrowState,
}

/// Errors the state machine can return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowError {
    Unauthorized,
    InvalidStateTransition,
    AmountMismatch,
    AlreadyInitialized,
}

impl Escrow {
    /// Construct a new escrow in the `Uninitialized` state.
    ///
    /// Returns `AmountMismatch` when `amount == 0`.
    pub fn initialize(
        initializer: [u8; 32],
        taker: [u8; 32],
        amount: u64,
    ) -> Result<Self, EscrowError> {
        if amount == 0 {
            return Err(EscrowError::AmountMismatch);
        }
        Ok(Self {
            initializer,
            taker,
            amount,
            state: EscrowState::Uninitialized,
        })
    }

    fn require_initializer(&self, authority: [u8; 32]) -> Result<(), EscrowError> {
        if authority != self.initializer {
            return Err(EscrowError::Unauthorized);
        }
        Ok(())
    }

    /// Lock funds into the vault. `Uninitialized -> Funded`.
    pub fn fund(&mut self, authority: [u8; 32]) -> Result<(), EscrowError> {
        self.require_initializer(authority)?;
        match self.state {
            EscrowState::Uninitialized => {
                self.state = EscrowState::Funded;
                Ok(())
            }
            _ => Err(EscrowError::InvalidStateTransition),
        }
    }

    /// Release the locked funds to the taker. `Funded -> Released`.
    pub fn release(&mut self, authority: [u8; 32]) -> Result<(), EscrowError> {
        self.require_initializer(authority)?;
        match self.state {
            EscrowState::Funded => {
                self.state = EscrowState::Released;
                Ok(())
            }
            _ => Err(EscrowError::InvalidStateTransition),
        }
    }

    /// Cancel the escrow and return funds. `Funded -> Cancelled`.
    pub fn cancel(&mut self, authority: [u8; 32]) -> Result<(), EscrowError> {
        self.require_initializer(authority)?;
        match self.state {
            EscrowState::Funded => {
                self.state = EscrowState::Cancelled;
                Ok(())
            }
            _ => Err(EscrowError::InvalidStateTransition),
        }
    }

    /// Read-only accessors.
    pub fn initializer(&self) -> [u8; 32] {
        self.initializer
    }
    pub fn taker(&self) -> [u8; 32] {
        self.taker
    }
    pub fn amount(&self) -> u64 {
        self.amount
    }
    pub fn state(&self) -> EscrowState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];

    fn escrow() -> Escrow {
        Escrow::initialize(ALICE, BOB, 1_000_000).unwrap()
    }

    // ---------- initialize ----------

    #[test]
    fn initialize_stores_fields_and_starts_uninitialized() {
        let e = escrow();
        assert_eq!(e.initializer(), ALICE);
        assert_eq!(e.taker(), BOB);
        assert_eq!(e.amount(), 1_000_000);
        assert_eq!(e.state(), EscrowState::Uninitialized);
    }

    #[test]
    fn initialize_rejects_zero_amount() {
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 0),
            Err(EscrowError::AmountMismatch)
        );
    }

    // ---------- legal transitions ----------

    #[test]
    fn fund_moves_uninitialized_to_funded() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.amount(), 1_000_000); // amount invariant
    }

    #[test]
    fn release_moves_funded_to_released_and_preserves_amount() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        let before = e.amount();
        e.release(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.amount(), before); // amount invariant across release
    }

    #[test]
    fn cancel_moves_funded_to_cancelled_and_preserves_amount() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        let before = e.amount();
        e.cancel(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        assert_eq!(e.amount(), before);
    }

    // ---------- illegal transitions ----------

    #[test]
    fn release_from_uninitialized_is_invalid() {
        let mut e = escrow();
        assert_eq!(
            e.release(ALICE),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Uninitialized);
    }

    #[test]
    fn cancel_from_uninitialized_is_invalid() {
        let mut e = escrow();
        assert_eq!(e.cancel(ALICE), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.state(), EscrowState::Uninitialized);
    }

    #[test]
    fn double_fund_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        assert_eq!(e.fund(ALICE), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn release_after_release_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE).unwrap();
        assert_eq!(
            e.release(ALICE),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn cancel_after_release_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE).unwrap();
        assert_eq!(e.cancel(ALICE), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn release_after_cancel_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.cancel(ALICE).unwrap();
        assert_eq!(
            e.release(ALICE),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn fund_after_release_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE).unwrap();
        assert_eq!(e.fund(ALICE), Err(EscrowError::InvalidStateTransition));
    }

    #[test]
    fn fund_after_cancel_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.cancel(ALICE).unwrap();
        assert_eq!(e.fund(ALICE), Err(EscrowError::InvalidStateTransition));
    }

    // ---------- authority checks ----------

    #[test]
    fn non_initializer_cannot_fund() {
        let mut e = escrow();
        assert_eq!(e.fund(MALLORY), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Uninitialized);
    }

    #[test]
    fn non_initializer_cannot_release() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        assert_eq!(e.release(MALLORY), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn non_initializer_cannot_cancel() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        assert_eq!(e.cancel(MALLORY), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn taker_is_not_an_authority() {
        let mut e = escrow();
        // The taker is the beneficiary, not the authority: they cannot drive transitions.
        assert_eq!(e.fund(BOB), Err(EscrowError::Unauthorized));
        e.fund(ALICE).unwrap();
        assert_eq!(e.release(BOB), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Funded);
    }
}
