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
    /// Optional N-of-M attestor quorum gating `release`. `None` means a
    /// plain two-party escrow (backward compatible).
    quorum: Option<QuorumPolicy>,
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
    /// Quorum policy misconfiguration (empty attestor list, duplicate
    /// attestor, threshold 0 or larger than the attestor count), or
    /// [`Escrow::attest`] called on an escrow with no quorum configured.
    InvalidQuorum,
    /// `release` attempted while the configured quorum's threshold of
    /// attestations has not been reached yet.
    QuorumNotReached,
}

/// Maximum number of attestors in a [`QuorumPolicy`]. Fixed-size so the
/// crate stays heap-free and `Copy`.
pub const MAX_ATTESTORS: usize = 8;

/// N-of-M release policy: `threshold` distinct attestations from the
/// registered `attestors` must be recorded before [`Escrow::release`]
/// succeeds. Models arbitrated / oracle-gated escrows (e.g. 2-of-3 with
/// an arbiter, or M-of-N oracle attestation of delivery), the same
/// pattern as multi-sig escrow release conditions.
///
/// Attestations are a bitmask over the registered attestors, so the
/// policy is `Copy` and needs no allocation. Deliberately, the quorum
/// gates *release only*: the `cancel` / `cancel_expired` refund paths
/// stay initializer-driven so attestors cannot grief funds into a lockup
/// by withholding approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumPolicy {
    attestors: [[u8; 32]; MAX_ATTESTORS],
    registered: u8,
    threshold: u8,
    approvals: u64,
}

impl QuorumPolicy {
    /// Register `attestors` with an N-of-M `threshold`.
    ///
    /// Rejects with [`EscrowError::InvalidQuorum`] when the list is
    /// empty, longer than [`MAX_ATTESTORS`], contains a duplicate, or the
    /// threshold is 0 / larger than the number of attestors.
    pub fn new(attestors: &[[u8; 32]], threshold: u8) -> Result<Self, EscrowError> {
        if attestors.is_empty() || attestors.len() > MAX_ATTESTORS {
            return Err(EscrowError::InvalidQuorum);
        }
        let mut table = [[0u8; 32]; MAX_ATTESTORS];
        for (i, attestor) in attestors.iter().enumerate() {
            if table[..i].contains(attestor) {
                return Err(EscrowError::InvalidQuorum);
            }
            table[i] = *attestor;
        }
        let registered = attestors.len() as u8;
        if threshold == 0 || threshold > registered {
            return Err(EscrowError::InvalidQuorum);
        }
        Ok(Self {
            attestors: table,
            registered,
            threshold,
            approvals: 0,
        })
    }

    fn index_of(&self, attestor: [u8; 32]) -> Option<usize> {
        self.attestors[..self.registered as usize]
            .iter()
            .position(|a| *a == attestor)
    }

    /// Record an attestation. Idempotent: repeat attestations by the same
    /// attestor count once. Callers outside the registered set get
    /// `Unauthorized`.
    pub fn attest(&mut self, attestor: [u8; 32]) -> Result<(), EscrowError> {
        match self.index_of(attestor) {
            Some(i) => {
                self.approvals |= 1u64 << i;
                Ok(())
            }
            None => Err(EscrowError::Unauthorized),
        }
    }

    /// True once at least `threshold` distinct attestors have attested.
    pub fn is_satisfied(&self) -> bool {
        self.approval_count() >= self.threshold
    }

    /// Number of distinct attestors that have attested so far.
    pub fn approval_count(&self) -> u8 {
        self.approvals.count_ones() as u8
    }

    /// The N in N-of-M.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// The M in N-of-M.
    pub fn registered_count(&self) -> u8 {
        self.registered
    }
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
            quorum: None,
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
    ///
    /// When a quorum is configured, additionally requires the quorum's
    /// threshold of attestations (`QuorumNotReached` otherwise). Check
    /// order is deliberate: authority, then state, then quorum — an
    /// unauthorized caller learns nothing about attestation progress.
    pub fn release(&mut self, authority: [u8; 32]) -> Result<(), EscrowError> {
        self.require_initializer(authority)?;
        match self.state {
            EscrowState::Funded => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        if let Some(policy) = &self.quorum {
            if !policy.is_satisfied() {
                return Err(EscrowError::QuorumNotReached);
            }
        }
        self.state = EscrowState::Released;
        Ok(())
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

    /// Attach an N-of-M attestor quorum to the release path.
    /// Builder-style: only valid on an `Uninitialized` escrow, so the
    /// release condition is fixed before any funds move. Re-configuring
    /// a live escrow is rejected with `InvalidStateTransition`.
    pub fn with_quorum(mut self, policy: QuorumPolicy) -> Result<Self, EscrowError> {
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        self.quorum = Some(policy);
        Ok(self)
    }

    /// Record an attestation from a registered attestor.
    ///
    /// Allowed while the escrow is `Uninitialized` or `Funded` (attestors
    /// usually vote before release is attempted); rejected on terminal
    /// states. Errors `InvalidQuorum` when no quorum is configured, and
    /// `Unauthorized` for callers outside the registered attestor set.
    pub fn attest(&mut self, attestor: [u8; 32]) -> Result<(), EscrowError> {
        match self.state {
            EscrowState::Uninitialized | EscrowState::Funded => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        match self.quorum.as_mut() {
            Some(policy) => policy.attest(attestor),
            None => Err(EscrowError::InvalidQuorum),
        }
    }

    /// Read-only accessors.
    pub fn quorum(&self) -> Option<QuorumPolicy> {
        self.quorum
    }
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

// ---------- AV-03: model-based fuzz of amount conservation ----------
//
// Property test: across long random operation sequences over a small
// fleet of escrows, the money is conserved exactly. A vault ledger model
// tracks the three buckets money can sit in:
//
//   inflow   = sum of amounts successfully funded (money entering vaults)
//   locked   = sum of amounts in `Funded` escrows (recomputed from real states)
//   released = sum of amounts successfully released (paid out to takers)
//   refunded  = sum of amounts successfully cancelled (returned to initializers)
//
// Invariant after every single operation:
//   inflow == locked + released + refunded
// plus field immutability: `amount` / `expires_at` never change through any
// transition, and failed operations leave state untouched.
//
// PRNG is xorshift64* with fixed seeds: deterministic, dependency-free,
// no network, no wall clock. Boundary amounts (0, 1, u64::MAX) and
// boundary expiries (0, u64::MAX) are deliberately biased into the stream.
#[cfg(test)]
mod fuzz_tests {
    use super::*;

    const INIT_KEYS: [[u8; 32]; 4] = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]];
    const EXPIRY: u64 = 1_800_000_000;
    const SEEDS: u64 = 24;
    const ESCROW_COUNT: usize = 6;
    const OPS_PER_SEED: usize = 48;

    struct XorShift64(u64);

    impl XorShift64 {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
            xs[self.below(xs.len() as u64) as usize]
        }
    }

    struct Slot {
        escrow: Escrow,
        amount: u64,
        expires_at: u64,
    }

    fn fuzz_amount(rng: &mut XorShift64) -> u64 {
        match rng.below(8) {
            0 => 0, // init must reject with AmountMismatch
            1 => 1,
            2 => 2,
            3 => rng.below(1_000_000) + 1,
            4 => u64::MAX,
            5 => u64::MAX / 2,
            6 => u64::MAX - 1,
            _ => rng.next(),
        }
    }

    fn fuzz_expiry(rng: &mut XorShift64) -> u64 {
        match rng.below(5) {
            0 => 0, // immediately expirable
            1 => EXPIRY,
            2 => EXPIRY + 1,
            3 => u64::MAX, // never expirable
            _ => rng.next(),
        }
    }

    fn fuzz_now(rng: &mut XorShift64) -> u64 {
        match rng.below(6) {
            0 => 0,
            1 => EXPIRY - 1,
            2 => EXPIRY,
            3 => EXPIRY + 1,
            4 => u64::MAX - 1,
            _ => rng.next(),
        }
    }

    fn run_seed(seed: u64) {
        let mut rng = XorShift64(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1));
        let mut slots: Vec<Option<Slot>> = Vec::with_capacity(ESCROW_COUNT);

        // Initialize a fleet; zero-amount inits fail and leave the slot empty.
        for _ in 0..ESCROW_COUNT {
            let init = rng.pick(&INIT_KEYS);
            let taker = rng.pick(&INIT_KEYS);
            let amount = fuzz_amount(&mut rng);
            let expires_at = fuzz_expiry(&mut rng);
            match Escrow::initialize(init, taker, amount, expires_at) {
                Ok(escrow) => slots.push(Some(Slot {
                    escrow,
                    amount,
                    expires_at,
                })),
                Err(EscrowError::AmountMismatch) => {
                    assert_eq!(amount, 0, "only zero amounts may fail init");
                    slots.push(None);
                }
                Err(e) => panic!("unexpected init error {e:?} on seed {seed}"),
            }
        }

        let mut inflow: u128 = 0;
        let mut released: u128 = 0;
        let mut refunded: u128 = 0;

        for _ in 0..OPS_PER_SEED {
            let i = rng.below(ESCROW_COUNT as u64) as usize;
            let Some(slot) = slots[i].as_mut() else { continue };
            let authority = rng.pick(&INIT_KEYS);
            let state_before = slot.escrow.state();

            let result = match rng.below(4) {
                0 => slot.escrow.fund(authority),
                1 => slot.escrow.release(authority),
                2 => slot.escrow.cancel(authority),
                _ => slot.escrow.cancel_expired(authority, fuzz_now(&mut rng)),
            };

            match result {
                Ok(()) => match state_before {
                    // From Uninitialized only `fund` can succeed.
                    EscrowState::Uninitialized => inflow += slot.amount as u128,
                    EscrowState::Funded => match slot.escrow.state() {
                        EscrowState::Released => released += slot.amount as u128,
                        EscrowState::Cancelled => refunded += slot.amount as u128,
                        s => panic!("unexpected post-op state {s:?} from Funded on seed {seed}"),
                    },
                    s => panic!("op succeeded from terminal state {s:?} on seed {seed}"),
                },
                Err(_) => {
                    // Failed ops must leave everything untouched.
                    assert_eq!(slot.escrow.state(), state_before);
                }
            }

            // Field immutability for this escrow ...
            assert_eq!(slot.escrow.amount(), slot.amount, "amount changed on seed {seed}");
            assert_eq!(
                slot.escrow.expires_at(),
                slot.expires_at,
                "expires_at changed on seed {seed}"
            );

            // ... and global conservation across the fleet.
            let locked: u128 = slots
                .iter()
                .flatten()
                .filter(|s| s.escrow.state() == EscrowState::Funded)
                .map(|s| s.amount as u128)
                .sum();
            assert_eq!(
                inflow,
                locked + released + refunded,
                "conservation violated on seed {seed}"
            );
        }
    }

    #[test]
    fn fuzz_amount_conservation_across_random_op_sequences() {
        for seed in 0..SEEDS {
            run_seed(seed);
        }
    }
}


// ---------- AV-04: attestor quorum, N-of-M release gate ----------
//
// | case                                   | fund | release            | cancel/cancel_expired |
// |----------------------------------------|------|--------------------|-----------------------|
// | no quorum                              | ✓    | initializer only | initializer / either  |
// | quorum, threshold not reached          | ✓    | ✗ QuorumNotReached | ungated (anti-grief)  |
// | quorum, threshold reached              | ✓    | ✓ initializer      | ungated (anti-grief)  |
//
// Design pinned below: quorum gates release only; attestations are
// idempotent and accepted in Uninitialized/Funded; the policy is fixed
// before funding (with_quorum is Uninitialized-only).
#[cfg(test)]
mod quorum_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const ATTESTOR_1: [u8; 32] = [0xA1; 32];
    const ATTESTOR_2: [u8; 32] = [0xA2; 32];
    const ATTESTOR_3: [u8; 32] = [0xA3; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn quorum_2_of_3() -> QuorumPolicy {
        QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2, ATTESTOR_3], 2).unwrap()
    }

    fn escrow_with_quorum() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(quorum_2_of_3())
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    // ---------- policy construction ----------

    #[test]
    fn policy_rejects_empty_attestor_list() {
        assert_eq!(
            QuorumPolicy::new(&[], 1),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn policy_rejects_zero_threshold() {
        assert_eq!(
            QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], 0),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn policy_rejects_threshold_above_attestor_count() {
        assert_eq!(
            QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], 3),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn policy_rejects_duplicate_attestor() {
        assert_eq!(
            QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_1], 1),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn policy_rejects_more_than_max_attestors() {
        let many: Vec<[u8; 32]> = (0..=MAX_ATTESTORS as u8).map(|i| [i; 32]).collect();
        assert_eq!(
            QuorumPolicy::new(&many, 1),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn policy_accepts_boundary_configs() {
        // 1-of-1 and M-of-M are the boundary policies.
        let one = QuorumPolicy::new(&[ATTESTOR_1], 1).unwrap();
        assert_eq!((one.registered_count(), one.threshold()), (1, 1));
        let all = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2, ATTESTOR_3], 3).unwrap();
        assert!(!all.is_satisfied());
    }

    // ---------- attestation recording ----------

    #[test]
    fn attest_by_non_registered_caller_is_unauthorized() {
        let mut policy = quorum_2_of_3();
        assert_eq!(policy.attest(MALLORY), Err(EscrowError::Unauthorized));
        assert_eq!(policy.approval_count(), 0);
    }

    #[test]
    fn duplicate_attestation_counts_once() {
        let mut policy = quorum_2_of_3();
        policy.attest(ATTESTOR_1).unwrap();
        policy.attest(ATTESTOR_1).unwrap();
        assert_eq!(policy.approval_count(), 1);
        assert!(!policy.is_satisfied());
    }

    #[test]
    fn satisfaction_tracks_distinct_attestors() {
        let mut policy = quorum_2_of_3();
        assert!(!policy.is_satisfied());
        policy.attest(ATTESTOR_1).unwrap();
        assert!(!policy.is_satisfied());
        policy.attest(ATTESTOR_2).unwrap();
        assert!(policy.is_satisfied());
        assert_eq!(policy.approval_count(), 2);
    }

    // ---------- release gating ----------

    #[test]
    fn release_before_quorum_reached_fails_and_preserves_state() {
        let mut e = escrow_with_quorum();
        e.attest(ATTESTOR_1).unwrap();
        assert_eq!(e.release(ALICE), Err(EscrowError::QuorumNotReached));
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.amount(), 1_000_000);
    }

    #[test]
    fn release_after_threshold_reached_succeeds() {
        let mut e = escrow_with_quorum();
        e.attest(ATTESTOR_1).unwrap();
        e.attest(ATTESTOR_3).unwrap();
        e.release(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.amount(), 1_000_000); // payout accounting preserved
    }

    #[test]
    fn quorum_does_not_weaken_initializer_authority() {
        // Even with a satisfied quorum, a stranger cannot release.
        let mut e = escrow_with_quorum();
        e.attest(ATTESTOR_1).unwrap();
        e.attest(ATTESTOR_2).unwrap();
        assert_eq!(e.release(MALLORY), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn quorum_does_not_leak_attestation_progress_to_strangers() {
        // Check order: authority before quorum. A stranger gets
        // Unauthorized even with zero attestations recorded.
        let mut e = escrow_with_quorum();
        assert_eq!(e.release(MALLORY), Err(EscrowError::Unauthorized));
        // ... while the initializer sees the quorum gate.
        assert_eq!(e.release(ALICE), Err(EscrowError::QuorumNotReached));
    }

    #[test]
    fn cancel_paths_are_not_gated_by_quorum() {
        // Anti-griefing: attestors withholding approval cannot lock funds;
        // the initializer refund path stays quorum-free.
        let mut e = escrow_with_quorum();
        e.cancel(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);

        let mut e = escrow_with_quorum();
        e.cancel_expired(BOB, EXPIRES_AT + 1).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn escrow_without_quorum_releases_without_attestations() {
        // Backward compatibility: plain two-party escrow unchanged.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(e.quorum(), None);
        e.fund(ALICE).unwrap();
        e.release(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
    }

    // ---------- configuration lifecycle ----------

    #[test]
    fn with_quorum_rejected_after_funding() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.with_quorum(quorum_2_of_3()),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.quorum(), None);
    }

    #[test]
    fn attest_without_quorum_configured_is_invalid_quorum() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(e.attest(ATTESTOR_1), Err(EscrowError::InvalidQuorum));
    }

    #[test]
    fn attest_on_terminal_states_is_invalid_transition() {
        let mut e = escrow_with_quorum();
        e.attest(ATTESTOR_1).unwrap();
        e.attest(ATTESTOR_2).unwrap();
        e.release(ALICE).unwrap();
        assert_eq!(
            e.attest(ATTESTOR_3),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn attestations_accepted_before_funding() {
        // Attestors usually vote during negotiation, before funds move.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(quorum_2_of_3())
            .unwrap();
        e.attest(ATTESTOR_1).unwrap();
        e.attest(ATTESTOR_2).unwrap();
        e.fund(ALICE).unwrap();
        e.release(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn initializer_or_taker_as_attestor_is_allowed() {
        // Parties may double as attestors (e.g. 2-of-3 maker/taker/arbiter).
        let policy = QuorumPolicy::new(&[ALICE, ATTESTOR_1], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.attest(ALICE).unwrap();
        e.attest(ATTESTOR_1).unwrap();
        e.fund(ALICE).unwrap();
        e.release(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
    }
}
