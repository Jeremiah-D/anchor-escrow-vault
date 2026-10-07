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
///
/// Timestamps are Unix seconds supplied by the caller: this crate has no
/// clock (no `std::time` on-chain target issues, no hidden ambient
/// authority). Pass `u64::MAX` as `expires_at` for an escrow with no
/// timeout; `0` means it is eligible for expiry cancellation as soon as
/// it is funded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Escrow {
    initializer: [u8; 32],
    taker: [u8; 32],
    amount: u64,
    expires_at: u64,
    state: EscrowState,
}

/// Errors the state machine can return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowError {
    Unauthorized,
    InvalidStateTransition,
    AmountMismatch,
    AlreadyInitialized,
    /// `cancel_expired` called before `expires_at`.
    NotExpired,
}

impl Escrow {
    /// Construct a new escrow in the `Uninitialized` state.
    ///
    /// `expires_at` is the Unix timestamp after which either party may
    /// cancel the escrow via [`Escrow::cancel_expired`]. Pass `u64::MAX`
    /// for no timeout.
    ///
    /// Returns `AmountMismatch` when `amount == 0`.
    pub fn initialize(
        initializer: [u8; 32],
        taker: [u8; 32],
        amount: u64,
        expires_at: u64,
    ) -> Result<Self, EscrowError> {
        if amount == 0 {
            return Err(EscrowError::AmountMismatch);
        }
        Ok(Self {
            initializer,
            taker,
            amount,
            expires_at,
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

    /// Cancel an escrow that has timed out and refund the initializer.
    /// `Funded -> Cancelled`.
    ///
    /// Unlike [`Escrow::cancel`], either party — the initializer or the
    /// taker — may call this, so a stalled counterparty cannot lock funds
    /// forever. Requires `now >= expires_at` (the caller supplies the
    /// clock; on-chain this is the Solana clock sysvar).
    ///
    /// Check order is deliberate: authority first, then state, then
    /// expiry. A stranger never learns whether an escrow is expired from
    /// the error alone beyond `Unauthorized`.
    pub fn cancel_expired(&mut self, authority: [u8; 32], now: u64) -> Result<(), EscrowError> {
        if authority != self.initializer && authority != self.taker {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            EscrowState::Funded => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        if now < self.expires_at {
            return Err(EscrowError::NotExpired);
        }
        self.state = EscrowState::Cancelled;
        Ok(())
    }

    /// Read-only accessors.
    pub fn initializer(&self) -> [u8; 32] {
        self.initializer
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
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
    /// Expiry timestamp used by most tests.
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn escrow() -> Escrow {
        Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap()
    }

    fn funded_escrow() -> Escrow {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e
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
            Escrow::initialize(ALICE, BOB, 0, EXPIRES_AT),
            Err(EscrowError::AmountMismatch)
        );
    }

    #[test]
    fn initialize_stores_expires_at() {
        let e = escrow();
        assert_eq!(e.expires_at(), EXPIRES_AT);
        let no_timeout = Escrow::initialize(ALICE, BOB, 1, u64::MAX).unwrap();
        assert_eq!(no_timeout.expires_at(), u64::MAX);
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

    // ---------- cancel_expired ----------

    #[test]
    fn cancel_expired_by_initializer_after_expiry_ok() {
        let mut e = funded_escrow();
        let before = e.amount();
        e.cancel_expired(ALICE, EXPIRES_AT + 1).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        assert_eq!(e.amount(), before); // refund accounting preserved
    }

    #[test]
    fn cancel_expired_by_taker_after_expiry_ok() {
        // Either party may cancel an expired escrow: the taker is not
        // left hostage to an unresponsive initializer.
        let mut e = funded_escrow();
        e.cancel_expired(BOB, EXPIRES_AT + 3_600).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn cancel_expired_at_exact_expiry_boundary_ok() {
        // `now >= expires_at` is the trigger: equality counts as expired.
        let mut e = funded_escrow();
        e.cancel_expired(ALICE, EXPIRES_AT).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn cancel_expired_before_expiry_fails_for_both_parties() {
        for authority in [ALICE, BOB] {
            let mut e = funded_escrow();
            assert_eq!(
                e.cancel_expired(authority, EXPIRES_AT - 1),
                Err(EscrowError::NotExpired)
            );
            assert_eq!(e.state(), EscrowState::Funded);
        }
    }

    #[test]
    fn cancel_expired_by_stranger_after_expiry_is_unauthorized() {
        let mut e = funded_escrow();
        assert_eq!(
            e.cancel_expired(MALLORY, EXPIRES_AT + 1),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn cancel_expired_on_non_funded_states_is_invalid() {
        // Uninitialized: authority passes, state rejects.
        let mut e = escrow();
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT + 1),
            Err(EscrowError::InvalidStateTransition)
        );
        // Released: terminal, cannot be cancelled again.
        let mut e = funded_escrow();
        e.release(ALICE).unwrap();
        assert_eq!(
            e.cancel_expired(BOB, EXPIRES_AT + 1),
            Err(EscrowError::InvalidStateTransition)
        );
        // Cancelled: terminal, double-cancel rejected.
        let mut e = funded_escrow();
        e.cancel(ALICE).unwrap();
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT + 1),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn escrow_without_timeout_cannot_be_cancel_expired() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, u64::MAX).unwrap();
        e.fund(ALICE).unwrap();
        // Any realistic `now` is below u64::MAX.
        assert_eq!(
            e.cancel_expired(ALICE, u64::MAX - 1),
            Err(EscrowError::NotExpired)
        );
        assert_eq!(e.state(), EscrowState::Funded);
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

// ---------- AV-02: permission model, full negative coverage ----------
//
// Permission matrix (ALICE = initializer, BOB = taker, MALLORY = stranger):
//
// | transition     | ALICE (initializer) | BOB (taker)            | MALLORY (stranger) |
// |----------------|---------------------|------------------------|--------------------|
// | fund           | ✓                 | ✗ Unauthorized       | ✗ Unauthorized     |
// | release        | ✓                 | ✗ Unauthorized       | ✗ Unauthorized     |
// | cancel         | ✓                 | ✗ Unauthorized       | ✗ Unauthorized     |
// | cancel_expired | ✓ (expired only)  | ✓ (expired only)     | ✗ Unauthorized     |
//
// Every test below is a negative test: it asserts that a caller without
// the required authority gets `Unauthorized` and the state is unchanged.
// Authority is checked *before* state validity, so even on terminal
// states a stranger gets `Unauthorized` rather than `InvalidStateTransition`
// (check-order property pinned by `authority_precedes_state_check`).
#[cfg(test)]
mod permission_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const ZERO_KEY: [u8; 32] = [0x00; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    const ALL_STATES: [EscrowState; 4] = [
        EscrowState::Uninitialized,
        EscrowState::Funded,
        EscrowState::Released,
        EscrowState::Cancelled,
    ];

    /// Build an escrow in each of the four lifecycle states.
    fn in_state(state: EscrowState) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        match state {
            EscrowState::Uninitialized => {}
            EscrowState::Funded => e.fund(ALICE).unwrap(),
            EscrowState::Released => {
                e.fund(ALICE).unwrap();
                e.release(ALICE).unwrap();
            }
            EscrowState::Cancelled => {
                e.fund(ALICE).unwrap();
                e.cancel(ALICE).unwrap();
            }
        }
        assert_eq!(e.state(), state);
        e
    }

    // ----- fund / release / cancel: stranger and taker denied in every state -----

    #[test]
    fn stranger_cannot_fund_in_any_state() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.fund(MALLORY), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn taker_cannot_fund_in_any_state() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.fund(BOB), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn stranger_cannot_release_in_any_state() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.release(MALLORY), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn taker_cannot_release_in_any_state() {
        // The taker is the beneficiary of a release, but only the
        // initializer may drive the transition.
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.release(BOB), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn stranger_cannot_cancel_in_any_state() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.cancel(MALLORY), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn taker_cannot_cancel_in_any_state() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.cancel(BOB), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    // ----- cancel_expired: stranger denied everywhere, even after expiry -----

    #[test]
    fn stranger_cannot_cancel_expired_in_any_state_even_after_expiry() {
        for state in ALL_STATES {
            for now in [EXPIRES_AT - 1, EXPIRES_AT, EXPIRES_AT + 1] {
                let mut e = in_state(state);
                assert_eq!(
                    e.cancel_expired(MALLORY, now),
                    Err(EscrowError::Unauthorized)
                );
                assert_eq!(e.state(), state, "state must be unchanged");
            }
        }
    }

    // ----- taker on cancel_expired: authorized party, gated by expiry -----

    #[test]
    fn taker_cancel_expired_before_expiry_is_not_expired_not_unauthorized() {
        // The taker IS an authorized caller for cancel_expired; before
        // expiry the failure is timing, not authority.
        let mut e = in_state(EscrowState::Funded);
        assert_eq!(
            e.cancel_expired(BOB, EXPIRES_AT - 1),
            Err(EscrowError::NotExpired)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn taker_cancel_expired_on_terminal_states_is_invalid_transition() {
        // Check order: authority passes for the taker, then the state
        // check rejects terminal states before expiry is even consulted.
        for state in [EscrowState::Released, EscrowState::Cancelled] {
            let mut e = in_state(state);
            assert_eq!(
                e.cancel_expired(BOB, EXPIRES_AT + 1),
                Err(EscrowError::InvalidStateTransition)
            );
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn taker_can_cancel_expired_after_expiry_positive_control() {
        // Boundary of the permission matrix: the taker is denied on
        // fund/release/cancel but allowed here once expired.
        let mut e = in_state(EscrowState::Funded);
        e.cancel_expired(BOB, EXPIRES_AT).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    // ----- check order and degenerate callers -----

    #[test]
    fn authority_precedes_state_check() {
        // On a terminal state, an illegal transition by the initializer
        // would be InvalidStateTransition, but a stranger still gets
        // Unauthorized: authority is checked first. This keeps the error
        // from leaking state information to unauthorized callers.
        let mut e = in_state(EscrowState::Released);
        assert_eq!(e.release(MALLORY), Err(EscrowError::Unauthorized));
        let mut e = in_state(EscrowState::Cancelled);
        assert_eq!(e.cancel(MALLORY), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn zero_key_caller_is_unauthorized_on_all_transitions() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.fund(ZERO_KEY), Err(EscrowError::Unauthorized));
            assert_eq!(e.release(ZERO_KEY), Err(EscrowError::Unauthorized));
            assert_eq!(e.cancel(ZERO_KEY), Err(EscrowError::Unauthorized));
            assert_eq!(
                e.cancel_expired(ZERO_KEY, EXPIRES_AT + 1),
                Err(EscrowError::Unauthorized)
            );
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }
}
