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
    /// AV-12: both parties of a dual-signature escrow have recorded their
    /// activation signatures. Lifecycle position is
    /// `Uninitialized -> Activated -> Funded` (via [`Escrow::activate`],
    /// then [`Escrow::fund`]). The variant is appended last — not in
    /// lifecycle order — so the existing Borsh discriminants (0–3) stay
    /// stable for already-serialized vaults.
    Activated,
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
    /// Cumulative amount released so far via [`Escrow::release`].
    /// Partial releases accumulate here; always `<= amount`. Exposed
    /// through [`Escrow::released_amount`] / [`Escrow::remaining_amount`].
    released: u64,
    expires_at: u64,
    state: EscrowState,
    /// Optional N-of-M attestor quorum gating `release`. `None` means a
    /// plain two-party escrow (backward compatible).
    quorum: Option<QuorumPolicy>,
    /// AV-12: dual-signature activation bitmask (see
    /// [`ACTIVATION_INITIALIZER_BIT`] etc.). Activation progress must
    /// survive serialization, so it is a persisted field, not a transient
    /// flag. `0` for plain escrows — dual-signature activation is opt-in
    /// via [`Escrow::with_dual_sig`].
    activation: u8,
}

/// Bit 0 of [`Escrow::activation`]: the initializer has recorded their
/// activation signature via [`Escrow::activate`].
pub const ACTIVATION_INITIALIZER_BIT: u8 = 0b001;
/// Bit 1 of [`Escrow::activation`]: the taker has recorded their
/// activation signature via [`Escrow::activate`].
pub const ACTIVATION_TAKER_BIT: u8 = 0b010;
/// Bit 2 of [`Escrow::activation`]: dual-signature activation is required
/// before [`Escrow::fund`]. Set once by [`Escrow::with_dual_sig`] on an
/// `Uninitialized` escrow; never cleared afterwards.
pub const ACTIVATION_DUAL_SIG_REQUIRED_BIT: u8 = 0b100;

/// Errors the state machine can return.
///
/// Each variant has a stable numeric code (see [`EscrowError::code`]):
/// codes are part of the crate's public contract, so never renumber a
/// variant or reuse a code from a removed variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowError {
    /// The caller is not the authority for the transition. Checked
    /// before state validity, so strangers learn nothing about state.
    Unauthorized,
    /// The transition is not allowed from the current state (double
    /// fund, release before fund, any transition from a terminal
    /// state, ...).
    InvalidStateTransition,
    /// [`Escrow::initialize`] called with `amount == 0`.
    AmountMismatch,
    /// `cancel_expired` called before `expires_at`.
    NotExpired,
    /// Quorum policy misconfiguration (empty attestor list, duplicate
    /// attestor, threshold 0 or larger than the attestor count), or
    /// [`Escrow::attest`] called on an escrow with no quorum configured.
    InvalidQuorum,
    /// `release` attempted while the configured quorum's threshold of
    /// attestations has not been reached yet.
    QuorumNotReached,
    /// `release` attempted with a cumulative amount that would exceed the
    /// locked [`Escrow::amount`] — or whose cumulative addition would
    /// overflow `u64`. Partial releases must never outrun the lockup.
    ReleaseExceedsLocked,
}

impl EscrowError {
    /// Stable numeric code for this error.
    ///
    /// The mapping is a public contract: off-chain clients and the
    /// Anchor program match on these numbers (the Anchor layer assigns
    /// one program error per variant). Codes are never renumbered and
    /// removed variants' codes are never reused — the AV-06 test module
    /// below pins the full table.
    pub fn code(&self) -> u32 {
        match self {
            EscrowError::Unauthorized => 100,
            EscrowError::InvalidStateTransition => 101,
            EscrowError::AmountMismatch => 102,
            EscrowError::NotExpired => 103,
            EscrowError::InvalidQuorum => 104,
            EscrowError::QuorumNotReached => 105,
            EscrowError::ReleaseExceedsLocked => 106,
        }
    }

    /// Every variant of this enum, for completeness assertions.
    pub fn all() -> &'static [EscrowError] {
        &[
            EscrowError::Unauthorized,
            EscrowError::InvalidStateTransition,
            EscrowError::AmountMismatch,
            EscrowError::NotExpired,
            EscrowError::InvalidQuorum,
            EscrowError::QuorumNotReached,
            EscrowError::ReleaseExceedsLocked,
        ]
    }
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
            released: 0,
            expires_at,
            state: EscrowState::Uninitialized,
            quorum: None,
            activation: 0,
        })
    }

    fn require_initializer(&self, authority: [u8; 32]) -> Result<(), EscrowError> {
        if authority != self.initializer {
            return Err(EscrowError::Unauthorized);
        }
        Ok(())
    }

    /// Lock funds into the vault. `Uninitialized -> Funded` for a plain
    /// escrow, `Activated -> Funded` for a dual-signature escrow
    /// (AV-12): a single signature can create the escrow, but only the
    /// initializer *after both parties activated* may fund it.
    pub fn fund(&mut self, authority: [u8; 32]) -> Result<(), EscrowError> {
        self.require_initializer(authority)?;
        match self.state {
            EscrowState::Uninitialized if !self.dual_sig_required() => {
                self.state = EscrowState::Funded;
                Ok(())
            }
            // Dual-signature escrows fund only from `Activated`: one party
            // activating alone leaves the escrow `Uninitialized`, and
            // `fund` from there is `InvalidStateTransition`.
            EscrowState::Activated => {
                self.state = EscrowState::Funded;
                Ok(())
            }
            _ => Err(EscrowError::InvalidStateTransition),
        }
    }

    /// Opt in to dual-signature activation (AV-12). Builder-style: only
    /// valid on an `Uninitialized` escrow, so the activation requirement
    /// is fixed before any funds move — mirroring [`Escrow::with_quorum`].
    /// After this, `fund` requires the escrow to be `Activated`
    /// (both parties recorded via [`Escrow::activate`]); a lone
    /// initializer signature can create but never fund the escrow.
    /// Models Solana multisig escrow activation, where each party's
    /// approval arrives as a separate signed transaction.
    pub fn with_dual_sig(mut self) -> Result<Self, EscrowError> {
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        self.activation |= ACTIVATION_DUAL_SIG_REQUIRED_BIT;
        Ok(self)
    }

    /// Record one party's activation signature (AV-12). Only the
    /// initializer or the taker may call this (`Unauthorized` otherwise);
    /// only on a dual-signature escrow still `Uninitialized`
    /// (`InvalidStateTransition` otherwise — including re-activation of
    /// an already-`Activated` escrow).
    ///
    /// Idempotent per party: activating twice sets the same bit again and
    /// succeeds. When *both* bits are set the escrow moves
    /// `Uninitialized -> Activated`, unlocking `fund`.
    ///
    /// Check order is deliberate: authority first, then state, then the
    /// dual-sig requirement — a stranger learns nothing about the
    /// escrow's configuration from the error alone.
    pub fn activate(&mut self, authority: [u8; 32]) -> Result<(), EscrowError> {
        if authority != self.initializer && authority != self.taker {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        if !self.dual_sig_required() {
            return Err(EscrowError::InvalidStateTransition);
        }
        // Independent `if`s, not `if/else`: when initializer == taker
        // (degenerate self-escrow) one signature sets both party bits at
        // once. With distinct keys exactly one bit is set per call.
        if authority == self.initializer {
            self.activation |= ACTIVATION_INITIALIZER_BIT;
        }
        if authority == self.taker {
            self.activation |= ACTIVATION_TAKER_BIT;
        }
        // Degenerate case initializer == taker: one signature sets both
        // bits at once and activates immediately. Deterministic and
        // consistent — a self-escrow needs no counterparty.
        if self.activation & (ACTIVATION_INITIALIZER_BIT | ACTIVATION_TAKER_BIT)
            == (ACTIVATION_INITIALIZER_BIT | ACTIVATION_TAKER_BIT)
        {
            self.state = EscrowState::Activated;
        }
        Ok(())
    }

    /// True when dual-signature activation was opted in via
    /// [`Escrow::with_dual_sig`].
    pub fn dual_sig_required(&self) -> bool {
        self.activation & ACTIVATION_DUAL_SIG_REQUIRED_BIT != 0
    }

    /// True when the initializer has recorded their activation signature.
    pub fn initializer_activated(&self) -> bool {
        self.activation & ACTIVATION_INITIALIZER_BIT != 0
    }

    /// True when the taker has recorded their activation signature.
    pub fn taker_activated(&self) -> bool {
        self.activation & ACTIVATION_TAKER_BIT != 0
    }

    /// Release `amount` of the locked funds to the taker. Partial releases
    /// accumulate in [`Escrow::released_amount`] and leave the escrow
    /// `Funded`; when the cumulative released total reaches the locked
    /// [`Escrow::amount`] the escrow moves `Funded -> Released`. Cumulative
    /// releases must never exceed the locked amount (`ReleaseExceedsLocked`),
    /// and `amount == 0` is `AmountMismatch`. Models staged payouts
    /// (e.g. delivery milestones paid out in tranches).
    ///
    /// When a quorum is configured, additionally requires the quorum's
    /// threshold of attestations (`QuorumNotReached` otherwise). Check
    /// order is deliberate: authority, then state, then quorum, then the
    /// amount checks — an unauthorized caller learns nothing about
    /// attestation progress or release history.
    pub fn release(&mut self, authority: [u8; 32], amount: u64) -> Result<(), EscrowError> {
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
        if amount == 0 {
            return Err(EscrowError::AmountMismatch);
        }
        // checked_add: a wrapping add would reset the counter and let an
        // attacker drain past the lockup; overflow is a hard failure.
        let new_released = self
            .released
            .checked_add(amount)
            .ok_or(EscrowError::ReleaseExceedsLocked)?;
        if new_released > self.amount {
            return Err(EscrowError::ReleaseExceedsLocked);
        }
        self.released = new_released;
        if self.released == self.amount {
            self.state = EscrowState::Released;
        }
        Ok(())
    }

    /// Cancel the escrow and return funds. `Funded -> Cancelled`.
    ///
    /// After partial releases the refund is the remainder
    /// ([`Escrow::remaining_amount`]); [`Escrow::released_amount`] is
    /// preserved for audit.
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
    ///
    /// After partial releases the refund is the remainder
    /// ([`Escrow::remaining_amount`]); [`Escrow::released_amount`] is
    /// preserved for audit.
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
    /// Allowed while the escrow is `Uninitialized`, `Activated` (AV-12:
    /// attestors may vote after both parties activated but before
    /// funding), or `Funded` (attestors usually vote before release is
    /// attempted); rejected on terminal states. Errors `InvalidQuorum`
    /// when no quorum is configured, and `Unauthorized` for callers
    /// outside the registered attestor set.
    pub fn attest(&mut self, attestor: [u8; 32]) -> Result<(), EscrowError> {
        match self.state {
            EscrowState::Uninitialized | EscrowState::Activated | EscrowState::Funded => {}
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
    /// Cumulative amount released so far (AV-11): partial releases
    /// accumulate here; always `<= amount()`. Progress query for staged
    /// payouts.
    pub fn released_amount(&self) -> u64 {
        self.released
    }
    /// Amount still locked: `amount() - released_amount()`. This is what
    /// `cancel` / `cancel_expired` refund.
    pub fn remaining_amount(&self) -> u64 {
        self.amount - self.released
    }
    pub fn state(&self) -> EscrowState {
        self.state
    }
}

// ---------- AV-10: Anchor account space accounting ----------
//
// The Anchor program (`programs/escrow-vault`) persists the vault in one
// `Vault` account. Anchor serializes accounts with Borsh and prefixes an
// 8-byte discriminator. This section is the pure-logic, dependency-free
// half of that layout: exact serialized sizes, the rent-exemption check
// the program runs at `initialize` time, and the field table the tests
// cross-check against the IDL parameter mapping in both directions.
//
// Field order below is the Borsh serialization order and must match the
// `Vault` struct field order in the Anchor program.

/// Anchor account discriminator length in bytes: every Anchor `#[account]`
/// starts with an 8-byte discriminator.
pub const ANCHOR_DISCRIMINATOR_LEN: usize = 8;

/// Serialized length of a Solana `Pubkey` under Borsh/Anchor: 32 bytes.
pub const PUBKEY_LEN: usize = 32;

/// Serialized length of `QuorumPolicy` under Borsh/Anchor: 8 registered
/// attestor pubkeys, the registered count, the threshold, and the approval
/// bitmask. Fixed-size by design (`MAX_ATTESTORS`), so account space is
/// known at `initialize` time and never needs a realloc.
pub const QUORUM_POLICY_LEN: usize = 8 * PUBKEY_LEN + 1 + 1 + 8;

/// (field name, Anchor type, serialized length in bytes) for the `Vault`
/// account, in Borsh field order. This table is the single source of truth
/// for account sizing: `ESCROW_BODY_LEN` is derived from it by `const`
/// summation, and the tests assert the program's `space =` expression and
/// the IDL parameter mapping against it in both directions. Add a field
/// here and every derived constant plus the two-way test fail until the
/// program side is updated too — that is the point.
pub const VAULT_FIELDS: &[(&str, &str, usize)] = &[
    ("initializer", "Pubkey", PUBKEY_LEN),
    ("taker", "Pubkey", PUBKEY_LEN),
    ("amount", "u64", 8),
    // Cumulative released amount (AV-11): partial releases accumulate
    // here so release progress survives serialization; always `<= amount`.
    ("released", "u64", 8),
    ("expires_at", "u64", 8),
    // `EscrowState` is a unit-only enum: Borsh writes one discriminant byte.
    ("state", "u8 (enum discriminant)", 1),
    // `Option<QuorumPolicy>`: one discriminant byte, then the policy when
    // `Some`. The space is always reserved (even for plain two-party
    // escrows) so `initialize_quorum` never needs to grow the account.
    ("quorum", "Option<QuorumPolicy>", 1 + QUORUM_POLICY_LEN),
    // AV-12: dual-signature activation bitmask (bit 0 initializer, bit 1
    // taker, bit 2 dual-sig required). One byte; activation progress must
    // survive serialization.
    ("activation", "u8 (bitmask)", 1),
];

/// Sums the serialized lengths of a field table at compile time.
const fn sum_field_lens(fields: &[(&str, &str, usize)]) -> usize {
    let mut total = 0;
    let mut i = 0;
    while i < fields.len() {
        total += fields[i].2;
        i += 1;
    }
    total
}

/// Serialized length of the `Escrow` payload inside the `Vault` account —
/// everything after the Anchor discriminator. Derived from `VAULT_FIELDS`.
pub const ESCROW_BODY_LEN: usize = sum_field_lens(VAULT_FIELDS);

/// Full `Vault` account space: discriminator + serialized escrow payload.
/// The Anchor program passes this (or the no-quorum variant below) as the
/// `space =` argument when creating the account.
pub const VAULT_SPACE: usize = ANCHOR_DISCRIMINATOR_LEN + ESCROW_BODY_LEN;

/// Vault space when the account is created without quorum data
/// (`quorum: None` serializes as a single discriminant byte). The program
/// skeleton's `Initialize` constraint uses this exact expression; quorum
/// data is written in place later without reallocating. The activation
/// bitmask (AV-12) is always present — one byte, zeroed for plain escrows.
pub const VAULT_SPACE_NO_QUORUM: usize =
    ANCHOR_DISCRIMINATOR_LEN + PUBKEY_LEN + PUBKEY_LEN + 8 + 8 + 8 + 1 + 1 + 1;

/// Account storage overhead in bytes added by the Solana runtime when
/// computing rent (mirrors `solana_rent::ACCOUNT_STORAGE_OVERHEAD`).
pub const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;

/// Mainnet value of `Rent::lamports_per_byte_year`: 3_480 lamports.
pub const MAINNET_LAMPORTS_PER_BYTE_YEAR: u64 = 3_480;

/// Mainnet value of `Rent::exemption_threshold`: 2 years of rent prepaid.
pub const MAINNET_EXEMPTION_THRESHOLD_YEARS: f64 = 2.0;

/// Pure-Rust mirror of `Rent::minimum_balance`: the lamports an account
/// holding `space` bytes must carry to be rent-exempt, given the rent
/// parameters. Same arithmetic as the runtime
/// (`((128 + space) * lamports_per_byte_year) * exemption_threshold`,
/// truncated to u64), so the numbers match on-chain exactly. The program
/// layer reads the parameters from the rent sysvar; the mainnet defaults
/// above are provided for off-chain estimation.
pub fn rent_exempt_minimum_lamports(
    space: usize,
    lamports_per_byte_year: u64,
    exemption_threshold_years: f64,
) -> u64 {
    (((ACCOUNT_STORAGE_OVERHEAD + space as u64) * lamports_per_byte_year) as f64
        * exemption_threshold_years) as u64
}

/// Shortfall reported when a vault account is not rent-exempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RentShortfall {
    /// Lamports the account must carry to be rent-exempt.
    pub required: u64,
    /// Lamports the account actually carries.
    pub provided: u64,
}

/// Pure-logic half of the rent-exemption check the Anchor program runs at
/// `initialize` time (on-chain: `Rent::get()?.is_exempt(lamports,
/// VAULT_SPACE)` before writing the account). Checks against the full
/// `VAULT_SPACE` — not the no-quorum variant — so a later
/// `initialize_quorum` never finds the account underfunded for its
/// reserved quorum bytes. Returns `Ok(())` when `vault_lamports` covers
/// the rent-exempt minimum, else the exact shortfall.
pub fn check_vault_rent_exempt(
    vault_lamports: u64,
    lamports_per_byte_year: u64,
    exemption_threshold_years: f64,
) -> Result<(), RentShortfall> {
    let required =
        rent_exempt_minimum_lamports(VAULT_SPACE, lamports_per_byte_year, exemption_threshold_years);
    if vault_lamports >= required {
        Ok(())
    } else {
        Err(RentShortfall {
            required,
            provided: vault_lamports,
        })
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
        e.release(ALICE, 1_000_000).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.amount(), before); // amount invariant across release
        assert_eq!(e.released_amount(), before); // full release tracked
        assert_eq!(e.remaining_amount(), 0);
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
        e.release(ALICE, 1_000_000).unwrap();
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
            e.release(ALICE, 1_000_000),
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
        e.release(ALICE, 1_000_000).unwrap();
        assert_eq!(
            e.release(ALICE, 1_000_000),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn cancel_after_release_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_000_000).unwrap();
        assert_eq!(e.cancel(ALICE), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn release_after_cancel_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.cancel(ALICE).unwrap();
        assert_eq!(
            e.release(ALICE, 1_000_000),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn fund_after_release_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_000_000).unwrap();
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
        assert_eq!(e.release(MALLORY, 1_000_000), Err(EscrowError::Unauthorized));
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
        assert_eq!(e.release(BOB, 1_000_000), Err(EscrowError::Unauthorized));
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

    const ALL_STATES: [EscrowState; 5] = [
        EscrowState::Uninitialized,
        EscrowState::Activated,
        EscrowState::Funded,
        EscrowState::Released,
        EscrowState::Cancelled,
    ];

    /// Build an escrow in each of the five lifecycle states.
    fn in_state(state: EscrowState) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        match state {
            EscrowState::Uninitialized => {}
            EscrowState::Activated => {
                // AV-12: dual-signature escrow, both parties activated,
                // not yet funded.
                e = e.with_dual_sig().unwrap();
                e.activate(ALICE).unwrap();
                e.activate(BOB).unwrap();
            }
            EscrowState::Funded => e.fund(ALICE).unwrap(),
            EscrowState::Released => {
                e.fund(ALICE).unwrap();
                e.release(ALICE, 1_000_000).unwrap();
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
            assert_eq!(e.release(MALLORY, 1_000_000), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn taker_cannot_release_in_any_state() {
        // The taker is the beneficiary of a release, but only the
        // initializer may drive the transition.
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.release(BOB, 1_000_000), Err(EscrowError::Unauthorized));
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
        assert_eq!(e.release(MALLORY, 1_000_000), Err(EscrowError::Unauthorized));
        let mut e = in_state(EscrowState::Cancelled);
        assert_eq!(e.cancel(MALLORY), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn zero_key_caller_is_unauthorized_on_all_transitions() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.fund(ZERO_KEY), Err(EscrowError::Unauthorized));
            assert_eq!(e.release(ZERO_KEY, 1_000_000), Err(EscrowError::Unauthorized));
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
//   locked   = sum of unreleased amounts (`amount - released_amount()`) in
//              `Funded` escrows (recomputed from real states)
//   released = sum of amounts successfully released (paid out to takers,
//              including partial releases)
//   refunded  = sum of remainders successfully cancelled (returned to
//              initializers)
//
// Invariant after every single operation:
//   inflow == locked + released + refunded
// plus field immutability: `amount` / `expires_at` never change through any
// transition, and failed operations leave state — and the released
// counter — untouched.
//
// PRNG is xorshift64* with fixed seeds: deterministic, dependency-free,
// no network, no wall clock. Boundary amounts (0, 1, u64::MAX) and
// boundary expiries (0, u64::MAX) are deliberately biased into the stream.
// Release amounts are boundary-biased too (0, 1, half, full, just over
// the total, u64::MAX), so partial releases, cumulative caps, and
// over-release rejections are all exercised.
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

    /// Boundary-biased release amount generator. `total` is the escrow's
    /// locked amount; the stream covers the zero-amount rejection, a
    /// minimum partial, a half partial, the full amount, just over the
    /// total (exceeds unless `total == u64::MAX`), `u64::MAX` (exceeds
    /// unless `total == u64::MAX`), an rng-based value in `(1, total]`,
    /// and an arbitrary u64 (usually exceeding the remaining).
    fn fuzz_release_amount(rng: &mut XorShift64, total: u64) -> u64 {
        match rng.below(8) {
            0 => 0, // release must reject with AmountMismatch
            1 => 1, // minimum partial (full when total == 1)
            2 => total / 2, // partial (0 -> AmountMismatch when total == 1)
            3 => total, // full (or exceeds remaining when partially released)
            4 => total.saturating_add(1), // exceeds (full when total == u64::MAX)
            5 => u64::MAX, // exceeds unless total == u64::MAX
            6 => {
                if total < 2 {
                    1 // (1, total] is empty when total == 1
                } else {
                    rng.below(total - 1) + 2
                }
            }
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
            let released_before = slot.escrow.released_amount();

            let op = rng.below(4);
            let mut rel_amt = 0u64;
            let result = match op {
                0 => slot.escrow.fund(authority),
                1 => {
                    rel_amt = fuzz_release_amount(&mut rng, slot.amount);
                    slot.escrow.release(authority, rel_amt)
                }
                2 => slot.escrow.cancel(authority),
                _ => slot.escrow.cancel_expired(authority, fuzz_now(&mut rng)),
            };

            match result {
                Ok(()) => match state_before {
                    // From Uninitialized only `fund` can succeed.
                    EscrowState::Uninitialized => inflow += slot.amount as u128,
                    EscrowState::Funded => match slot.escrow.state() {
                        // release: a full release closes the escrow, a
                        // partial release leaves it Funded — either way
                        // rel_amt left the locked bucket.
                        EscrowState::Released | EscrowState::Funded => {
                            assert_eq!(
                                op, 1,
                                "only release can succeed from Funded to Funded/Released on seed {seed}"
                            );
                            released += rel_amt as u128;
                        }
                        // cancel / cancel_expired: the refund is the
                        // unreleased remainder (partial releases are
                        // already counted in `released`).
                        EscrowState::Cancelled => {
                            refunded +=
                                (slot.amount - slot.escrow.released_amount()) as u128;
                        }
                        s => panic!("unexpected post-op state {s:?} from Funded on seed {seed}"),
                    },
                    s => panic!("op succeeded from terminal state {s:?} on seed {seed}"),
                },
                Err(_) => {
                    // Failed ops must leave everything untouched.
                    assert_eq!(slot.escrow.state(), state_before);
                    assert_eq!(
                        slot.escrow.released_amount(),
                        released_before,
                        "failed op moved the released counter on seed {seed}"
                    );
                }
            }

            // Field immutability for this escrow ...
            assert_eq!(slot.escrow.amount(), slot.amount, "amount changed on seed {seed}");
            assert_eq!(
                slot.escrow.expires_at(),
                slot.expires_at,
                "expires_at changed on seed {seed}"
            );

            // ... and global conservation across the fleet. `locked` is the
            // unreleased remainder of every still-Funded escrow: partial
            // releases have already moved money into `released`.
            let locked: u128 = slots
                .iter()
                .flatten()
                .filter(|s| s.escrow.state() == EscrowState::Funded)
                .map(|s| s.amount as u128 - s.escrow.released_amount() as u128)
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
        assert_eq!(e.release(ALICE, 1_000_000), Err(EscrowError::QuorumNotReached));
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.amount(), 1_000_000);
    }

    #[test]
    fn release_after_threshold_reached_succeeds() {
        let mut e = escrow_with_quorum();
        e.attest(ATTESTOR_1).unwrap();
        e.attest(ATTESTOR_3).unwrap();
        e.release(ALICE, 1_000_000).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.amount(), 1_000_000); // payout accounting preserved
    }

    #[test]
    fn quorum_does_not_weaken_initializer_authority() {
        // Even with a satisfied quorum, a stranger cannot release.
        let mut e = escrow_with_quorum();
        e.attest(ATTESTOR_1).unwrap();
        e.attest(ATTESTOR_2).unwrap();
        assert_eq!(e.release(MALLORY, 1_000_000), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn quorum_does_not_leak_attestation_progress_to_strangers() {
        // Check order: authority before quorum. A stranger gets
        // Unauthorized even with zero attestations recorded.
        let mut e = escrow_with_quorum();
        assert_eq!(e.release(MALLORY, 1_000_000), Err(EscrowError::Unauthorized));
        // ... while the initializer sees the quorum gate.
        assert_eq!(e.release(ALICE, 1_000_000), Err(EscrowError::QuorumNotReached));
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
        e.release(ALICE, 1_000_000).unwrap();
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
        e.release(ALICE, 1_000_000).unwrap();
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
        e.release(ALICE, 1_000_000).unwrap();
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
        e.release(ALICE, 1_000_000).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
    }
}

// ---------- AV-05: Anchor IDL <-> state machine input mapping ----------
//
// The Anchor program (`programs/escrow-vault`; skeleton: not compiled by
// CI because it needs the Solana/Anchor toolchain) is a thin adapter:
// every instruction converts on-chain accounts into `escrow_state` types,
// calls exactly one state-machine transition, and writes the result
// back. This module pins that contract as an executable spec so the two
// sides cannot drift:
//
// * `INSTRUCTIONS` lists every IDL instruction the program exposes: its
//   name, its params (name, IDL type, value source), and the
//   state-machine method it must call with which inputs.
// * The tests execute each instruction's documented input tuple against
//   the real state machine and assert the documented outcome — happy path
//   plus the representative failure modes.
// * `instruction_set_is_complete` asserts the instruction set covers
//   every public transition exactly once. Add a transition or an
//   instruction and the test fails until the table is updated — that is
//   the IDL consistency check.
//
// Conventions pinned here (and mirrored in the program's doc comment):
// * Authority inputs always come from transaction signers
//   (`accounts.*`), never from instruction params: a param can be
//   spoofed, a signer cannot.
// * `cancel_expired`'s `now` is ambient input from the Solana clock
//   sysvar, deliberately NOT an instruction param — letting the caller
//   supply the timestamp would let anyone fast-forward expiry.
// * `initialize_quorum`'s authority check lives in the Anchor account
//   constraint (`initializer.key() == vault.initializer` in the real
//   build), not in the state machine: `with_quorum` takes no authority
//   argument because the policy is fixed before funding and
//   re-configuration is rejected by state, while *who* may configure it
//   is the program layer's job. The spec marks this explicitly instead
//   of hiding the seam.
#[cfg(test)]
mod anchor_idl_tests {
    use super::*;
    use std::collections::HashSet;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const ATTESTOR_1: [u8; 32] = [0xA1; 32];
    const ATTESTOR_2: [u8; 32] = [0xA2; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    /// One IDL instruction and how it maps onto the state machine.
    struct InstructionSpec {
        /// Instruction name as it appears in the IDL.
        name: &'static str,
        /// (param name, IDL type, value source). Empty when the
        /// instruction's inputs come entirely from accounts / sysvars.
        params: &'static [(&'static str, &'static str, &'static str)],
        /// State-machine method this instruction must call.
        method: &'static str,
        /// Which account / sysvar feeds which method argument.
        input_mapping: &'static str,
    }

    const INSTRUCTIONS: &[InstructionSpec] = &[
        InstructionSpec {
            name: "initialize",
            params: &[
                ("amount", "u64", "instruction param"),
                (
                    "expires_at",
                    "u64",
                    "instruction param; u64::MAX = no timeout",
                ),
            ],
            method: "Escrow::initialize",
            input_mapping: "initializer <- accounts.initializer (signer); \
                            taker <- accounts.taker; \
                            amount, expires_at <- params; \
                            creates the Vault account (Anchor `init`)",
        },
        InstructionSpec {
            name: "fund",
            params: &[],
            method: "Escrow::fund",
            input_mapping: "authority <- accounts.initializer (signer)",
        },
        InstructionSpec {
            name: "release",
            params: &[("amount", "u64", "instruction param")],
            method: "Escrow::release",
            input_mapping: "authority <- accounts.initializer (signer); \
                            amount <- param; partial releases accumulate in \
                            the `released` field and must not cumulatively \
                            exceed `amount` (ReleaseExceedsLocked); \
                            `amount == 0` is AmountMismatch; when a quorum \
                            is configured the release gate from AV-04 \
                            applies (QuorumNotReached)",
        },
        InstructionSpec {
            name: "cancel",
            params: &[],
            method: "Escrow::cancel",
            input_mapping: "authority <- accounts.initializer (signer)",
        },
        InstructionSpec {
            name: "cancel_expired",
            params: &[],
            method: "Escrow::cancel_expired",
            input_mapping: "authority <- accounts.authority (signer: \
                            initializer OR taker); now <- clock sysvar \
                            (NOT an instruction param — see module docs)",
        },
        InstructionSpec {
            name: "initialize_quorum",
            params: &[
                ("attestors", "Vec<Pubkey>", "instruction param"),
                ("threshold", "u8", "instruction param"),
            ],
            method: "QuorumPolicy::new + Escrow::with_quorum",
            input_mapping: "attestors/threshold <- params (Pubkey -> \
                            [u8; 32] conversion); authority <- \
                            accounts.initializer (signer), enforced by the \
                            Anchor account constraint, not the state machine",
        },
        InstructionSpec {
            // AV-12: dual-signature activation.
            name: "initialize_dual_sig",
            params: &[],
            method: "Escrow::with_dual_sig",
            input_mapping: "no params; authority <- accounts.initializer \
                            (signer), enforced by the Anchor account \
                            constraint, not the state machine; \
                            Uninitialized only, like initialize_quorum",
        },
        InstructionSpec {
            name: "activate",
            params: &[],
            method: "Escrow::activate",
            input_mapping: "authority <- accounts.authority (signer: \
                            initializer OR taker); records one party's \
                            activation bit; both bits set moves the escrow \
                            Uninitialized -> Activated, unlocking fund",
        },
        InstructionSpec {
            name: "attest",
            params: &[],
            method: "Escrow::attest",
            input_mapping: "attestor <- accounts.attestor (signer; must be \
                            in the registered set); allowed in \
                            Uninitialized, Activated (AV-12: between \
                            activation and funding), and Funded",
        },
    ];

    fn funded_escrow() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    fn quorum_funded_escrow() -> Escrow {
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    // ----- the consistency check -----

    #[test]
    fn instruction_set_is_complete() {
        // The public transition API of the state machine. If you add a
        // transition, add its instruction spec to INSTRUCTIONS and extend
        // this list — this test fails until you do.
        const TRANSITIONS: &[&str] = &[
            "Escrow::initialize",
            "Escrow::fund",
            "Escrow::release",
            "Escrow::cancel",
            "Escrow::cancel_expired",
            "QuorumPolicy::new + Escrow::with_quorum",
            "Escrow::with_dual_sig",
            "Escrow::activate",
            "Escrow::attest",
        ];
        assert_eq!(
            INSTRUCTIONS.len(),
            TRANSITIONS.len(),
            "instruction count drifted from transition count"
        );
        for t in TRANSITIONS {
            assert!(
                INSTRUCTIONS.iter().any(|s| s.method == *t),
                "no instruction spec covers transition {t}"
            );
        }
        let mut seen = HashSet::new();
        for s in INSTRUCTIONS {
            assert!(
                seen.insert(s.method),
                "duplicate instruction spec for {}",
                s.method
            );
        }
    }

    #[test]
    fn only_initialize_release_and_initialize_quorum_take_params() {
        // Pins which instructions carry IDL params; any new param must be
        // justified in the spec table above.
        let with_params: Vec<&&str> = INSTRUCTIONS
            .iter()
            .filter(|s| !s.params.is_empty())
            .map(|s| &s.name)
            .collect();
        assert_eq!(
            with_params,
            vec![&"initialize", &"release", &"initialize_quorum"]
        );
    }

    // ----- per-instruction mapping, executed against the real machine -----

    #[test]
    fn initialize_maps_amount_and_expires_at_params() {
        // IDL: initialize(amount: u64, expires_at: u64).
        // initializer <- accounts.initializer, taker <- accounts.taker.
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(e.state(), EscrowState::Uninitialized);
        assert_eq!(e.initializer(), ALICE);
        assert_eq!(e.taker(), BOB);
        assert_eq!((e.amount(), e.expires_at()), (1_000_000, EXPIRES_AT));
        // Documented failure mode: zero amount.
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 0, EXPIRES_AT),
            Err(EscrowError::AmountMismatch)
        );
    }

    #[test]
    fn fund_maps_initializer_signer_to_authority() {
        // IDL: fund() — no params; authority <- accounts.initializer.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        // Documented failure mode: signer is not the initializer.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(e.fund(MALLORY), Err(EscrowError::Unauthorized));
    }

    #[test]
    fn release_maps_initializer_signer_to_authority() {
        // IDL: release(amount: u64) — authority <- accounts.initializer;
        // amount <- instruction param (partial releases accumulate in the
        // `released` field; the cumulative total is capped at `amount`).
        let mut e = funded_escrow();
        e.release(ALICE, 1_000_000).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        // Documented partial path: stays Funded, progress tracked.
        let mut e = funded_escrow();
        e.release(ALICE, 400_000).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!((e.released_amount(), e.remaining_amount()), (400_000, 600_000));
        // Documented failure mode: quorum configured but threshold unmet
        // (release-specific gate from AV-04).
        let mut e = quorum_funded_escrow();
        e.attest(ATTESTOR_1).unwrap();
        assert_eq!(e.release(ALICE, 1_000_000), Err(EscrowError::QuorumNotReached));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn cancel_maps_initializer_signer_to_authority() {
        // IDL: cancel() — no params; authority <- accounts.initializer.
        let mut e = funded_escrow();
        e.cancel(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        // Documented failure mode: signer is not the initializer.
        let mut e = funded_escrow();
        assert_eq!(e.cancel(MALLORY), Err(EscrowError::Unauthorized));
    }

    #[test]
    fn cancel_expired_maps_authority_and_clock_sysvar() {
        // IDL: cancel_expired() — no params. authority <- accounts.authority
        // (signer: initializer OR taker); now <- clock sysvar, deliberately
        // not an instruction param (caller-supplied timestamps would let
        // anyone fast-forward expiry). The program layer must pass
        // Clock::get()?.unix_timestamp here.
        let mut e = funded_escrow();
        e.cancel_expired(BOB, EXPIRES_AT).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        // Documented failure mode: clock before expiry.
        let mut e = funded_escrow();
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT - 1),
            Err(EscrowError::NotExpired)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn initialize_quorum_maps_attestor_list_and_threshold() {
        // IDL: initialize_quorum(attestors: Vec<Pubkey>, threshold: u8).
        // The program converts each Pubkey to [u8; 32], runs
        // QuorumPolicy::new, then Escrow::with_quorum. Authority <-
        // accounts.initializer, enforced by the Anchor account constraint
        // (see module docs), not by the state machine.
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        assert!(e.quorum().is_some());
        e.fund(ALICE).unwrap();
        // The release gate is live immediately: threshold not yet reached.
        assert_eq!(e.release(ALICE, 1_000_000), Err(EscrowError::QuorumNotReached));
        // Documented failure mode: bad policy rejected before touching the escrow.
        assert_eq!(
            QuorumPolicy::new(&[ATTESTOR_1], 0),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn attest_maps_signer_to_registered_attestor() {
        // IDL: attest() — no params; attestor <- accounts.attestor (signer).
        let mut e = quorum_funded_escrow();
        e.attest(ATTESTOR_1).unwrap();
        assert_eq!(e.quorum().unwrap().approval_count(), 1);
        // Documented failure mode: signer outside the registered set.
        assert_eq!(e.attest(MALLORY), Err(EscrowError::Unauthorized));
        assert_eq!(e.quorum().unwrap().approval_count(), 1);
    }

    #[test]
    fn initialize_dual_sig_maps_initializer_signer_to_requirement() {
        // IDL: initialize_dual_sig() — no params; authority <-
        // accounts.initializer (signer), enforced by the Anchor account
        // constraint. Mirrors initialize_quorum: Uninitialized only.
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_dual_sig()
            .unwrap();
        assert!(e.dual_sig_required());
        assert_eq!(e.state(), EscrowState::Uninitialized);
        // Documented failure mode: re-configuring after activation is a
        // builder like with_quorum — only valid pre-funding.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_dual_sig()
            .unwrap();
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        assert_eq!(
            e.with_dual_sig(),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn activate_maps_either_party_signer_to_activation_bit() {
        // IDL: activate() — no params; authority <- accounts.authority
        // (signer: initializer OR taker). One signature alone cannot fund;
        // both signatures move Uninitialized -> Activated.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_dual_sig()
            .unwrap();
        // Single signature (either party) leaves the escrow Uninitialized:
        // fund is still rejected.
        e.activate(ALICE).unwrap();
        assert!(e.initializer_activated());
        assert!(!e.taker_activated());
        assert_eq!(e.state(), EscrowState::Uninitialized);
        assert_eq!(e.fund(ALICE), Err(EscrowError::InvalidStateTransition));
        // The second party's signature activates; fund now succeeds.
        e.activate(BOB).unwrap();
        assert!(e.taker_activated());
        assert_eq!(e.state(), EscrowState::Activated);
        e.fund(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        // Documented failure mode: stranger learns nothing (Unauthorized
        // before any state/config check).
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_dual_sig()
            .unwrap();
        assert_eq!(e.activate(MALLORY), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Uninitialized);
    }

    // ----- AV-10, second half: two-way vault-field <-> IDL consistency -----
    //
    // Direction 1 (IDL -> account): every instruction param must populate
    // exactly one vault field — a param that writes nothing (or writes an
    // undocumented field) is a spec lie the program would compile anyway.
    // Direction 2 (account -> IDL): every vault field must have exactly one
    // documented source — a field no instruction or account constraint ever
    // writes is dead space the `space =` rent pays for.
    //
    // `PARAM_FIELD_MAP` covers params; `FIELD_SOURCES` covers the rest
    // (signer accounts, transitions, derived/zeroed fields). The vault
    // field list itself comes from `VAULT_FIELDS` (expanded: `quorum`
    // unfolds into its four subfields), so adding a field or a param
    // breaks one side until the other is updated.

    /// (instruction name, IDL param name) -> vault field path it populates.
    const PARAM_FIELD_MAP: &[(&str, &str, &str)] = &[
        ("initialize", "amount", "amount"),
        ("initialize", "expires_at", "expires_at"),
        ("release", "amount", "released"),
        ("initialize_quorum", "attestors", "quorum.attestors"),
        ("initialize_quorum", "threshold", "quorum.threshold"),
    ];

    /// Vault field paths not populated by instruction params, with their
    /// documented source.
    const FIELD_SOURCES: &[(&str, &str)] = &[
        (
            "initializer",
            "accounts.initializer signer, stored by initialize",
        ),
        ("taker", "accounts.taker, stored by initialize"),
        (
            "state",
            "transitions: fund/release/cancel/cancel_expired/activate",
        ),
        (
            "activation",
            "zeroed by initialize; required-bit set by initialize_dual_sig, \
             party bits flipped by activate",
        ),
        (
            "quorum.registered",
            "derived from attestors.len() by initialize_quorum",
        ),
        (
            "quorum.approvals",
            "zeroed by initialize_quorum, bits flipped by attest",
        ),
    ];

    /// Every vault field path from `VAULT_FIELDS`, with `quorum` unfolded
    /// into its serialized subfields (order matches Borsh layout).
    fn vault_field_paths() -> Vec<&'static str> {
        let mut paths = Vec::new();
        for (name, _, _) in VAULT_FIELDS {
            if *name == "quorum" {
                paths.extend([
                    "quorum.attestors",
                    "quorum.registered",
                    "quorum.threshold",
                    "quorum.approvals",
                ]);
            } else {
                paths.push(name);
            }
        }
        paths
    }

    #[test]
    fn every_idl_param_maps_to_exactly_one_vault_field() {
        let vault_fields = vault_field_paths();
        for spec in INSTRUCTIONS {
            for (param, _, _) in spec.params {
                let targets: Vec<&&str> = PARAM_FIELD_MAP
                    .iter()
                    .filter(|(ix, p, _)| *ix == spec.name && *p == *param)
                    .map(|(_, _, field)| field)
                    .collect();
                assert_eq!(
                    targets.len(),
                    1,
                    "instruction {} param {param}: expected exactly one vault field mapping, found {}",
                    spec.name,
                    targets.len()
                );
                assert!(
                    vault_fields.contains(targets[0]),
                    "instruction {} param {param} maps to unknown vault field {}",
                    spec.name,
                    targets[0]
                );
            }
        }
    }

    #[test]
    fn every_vault_field_has_exactly_one_documented_source() {
        let from_params: Vec<&str> =
            PARAM_FIELD_MAP.iter().map(|(_, _, field)| *field).collect();
        let from_sources: Vec<&str> =
            FIELD_SOURCES.iter().map(|(field, _)| *field).collect();
        let mut seen = HashSet::new();
        for field in vault_field_paths() {
            let via_param = from_params.iter().filter(|f| **f == field).count();
            let via_source = from_sources.iter().filter(|f| **f == field).count();
            assert_eq!(
                via_param + via_source,
                1,
                "vault field {field}: expected exactly one documented source \
                 (param mapping or field source), found param={via_param} source={via_source}"
            );
            assert!(
                seen.insert(field),
                "vault field {field} documented twice"
            );
        }
        assert_eq!(
            seen.len(),
            from_params.len() + from_sources.len(),
            "a param mapping or field source names a field outside VAULT_FIELDS"
        );
    }
}

// ---------- AV-06: error code catalog ----------
//
// Every EscrowError variant is pinned to its trigger condition AND its
// stable numeric code. `code()` is a public contract (the Anchor program
// maps one program error per variant, off-chain clients match on the
// numbers), so these tests hardcode the numbers: renumbering a code
// without a deliberate migration fails here on purpose.
//
// Note on `AlreadyInitialized`: the variant used to exist here but no
// method could ever return it — `initialize` is a constructor and there
// is no re-initialization path (Anchor's `init` constraint handles
// double-init at the account layer). It was dead code and has been
// removed; per the no-reuse rule its code is gone with it.
#[cfg(test)]
mod error_code_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const ATTESTOR_1: [u8; 32] = [0xA1; 32];
    const ATTESTOR_2: [u8; 32] = [0xA2; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn escrow() -> Escrow {
        Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap()
    }

    /// The full catalog: (variant, code, one-line trigger description).
    /// `error_codes_are_stable` asserts this table against `code()`, so a
    /// silent renumber is impossible.
    const CATALOG: &[(EscrowError, u32, &str)] = &[
        (EscrowError::Unauthorized, 100, "caller is not the transition authority"),
        (
            EscrowError::InvalidStateTransition,
            101,
            "transition illegal from the current state",
        ),
        (EscrowError::AmountMismatch, 102, "initialize with amount == 0"),
        (
            EscrowError::NotExpired,
            103,
            "cancel_expired with now < expires_at",
        ),
        (
            EscrowError::InvalidQuorum,
            104,
            "bad quorum config or attest with no quorum",
        ),
        (
            EscrowError::QuorumNotReached,
            105,
            "release before quorum threshold reached",
        ),
        (
            EscrowError::ReleaseExceedsLocked,
            106,
            "release cumulative amount exceeding the locked amount",
        ),
    ];

    #[test]
    fn catalog_covers_every_variant_exactly_once() {
        let all = EscrowError::all();
        assert_eq!(
            all.len(),
            CATALOG.len(),
            "EscrowError::all() drifted from the catalog"
        );
        for (variant, _, _) in CATALOG {
            assert!(all.contains(variant), "{variant:?} missing from all()");
        }
    }

    #[test]
    fn error_codes_are_stable() {
        // Hardcoded numbers on purpose: the test FAILS if a code moves.
        for (variant, code, trigger) in CATALOG {
            assert_eq!(
                variant.code(),
                *code,
                "code for {variant:?} ({trigger}) changed from {code}"
            );
        }
    }

    #[test]
    fn error_codes_are_unique() {
        let mut codes: Vec<u32> = CATALOG.iter().map(|(_, c, _)| *c).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), CATALOG.len(), "duplicate error code");
    }

    // ----- trigger conditions, one per variant -----

    #[test]
    fn unauthorized_triggered_by_stranger_on_fund() {
        let mut e = escrow();
        let err = e.fund(MALLORY).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
    }

    #[test]
    fn invalid_state_transition_triggered_by_double_fund() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        let err = e.fund(ALICE).unwrap_err();
        assert_eq!(err, EscrowError::InvalidStateTransition);
        assert_eq!(err.code(), 101);
    }

    #[test]
    fn amount_mismatch_triggered_by_zero_amount_init() {
        let err = Escrow::initialize(ALICE, BOB, 0, EXPIRES_AT).unwrap_err();
        assert_eq!(err, EscrowError::AmountMismatch);
        assert_eq!(err.code(), 102);
    }

    #[test]
    fn not_expired_triggered_by_early_cancel_expired() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        // Authorized party (initializer), right state, wrong time.
        let err = e.cancel_expired(ALICE, EXPIRES_AT - 1).unwrap_err();
        assert_eq!(err, EscrowError::NotExpired);
        assert_eq!(err.code(), 103);
    }

    #[test]
    fn invalid_quorum_triggered_by_attest_without_quorum() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        let err = e.attest(ATTESTOR_1).unwrap_err();
        assert_eq!(err, EscrowError::InvalidQuorum);
        assert_eq!(err.code(), 104);
    }

    #[test]
    fn invalid_quorum_triggered_by_zero_threshold_policy() {
        let err = QuorumPolicy::new(&[ATTESTOR_1], 0).unwrap_err();
        assert_eq!(err, EscrowError::InvalidQuorum);
        assert_eq!(err.code(), 104);
    }

    #[test]
    fn quorum_not_reached_triggered_by_premature_release() {
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], 2).unwrap();
        let mut e = escrow().with_quorum(policy).unwrap();
        e.fund(ALICE).unwrap();
        e.attest(ATTESTOR_1).unwrap(); // 1 of 2: not enough
        let err = e.release(ALICE, 1_000_000).unwrap_err();
        assert_eq!(err, EscrowError::QuorumNotReached);
        assert_eq!(err.code(), 105);
    }

    #[test]
    fn release_exceeds_locked_triggered_by_over_release() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 600_000).unwrap(); // partial: 400_000 remains
        let err = e.release(ALICE, 400_001).unwrap_err();
        assert_eq!(err, EscrowError::ReleaseExceedsLocked);
        assert_eq!(err.code(), 106);
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 600_000, "failed release must not move released");
    }

    #[test]
    fn amount_mismatch_triggered_by_zero_amount_release() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        let err = e.release(ALICE, 0).unwrap_err();
        assert_eq!(err, EscrowError::AmountMismatch);
        assert_eq!(err.code(), 102);
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0);
    }

    #[test]
    fn check_order_is_visible_in_codes() {        // Authority is checked before state: a stranger on a terminal
        // state still gets 100 (Unauthorized), not 101.
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_000_000).unwrap(); // now Released
        let err = e.fund(MALLORY).unwrap_err();
        assert_eq!(err.code(), 100);
        // ... while the initializer sees the state error, 101.
        let err = e.fund(ALICE).unwrap_err();
        assert_eq!(err.code(), 101);
    }
}

// ---------- AV-08: property-based tests with a handwritten generator ----------
//
// proptest-style property tests, but the generator is hand-rolled: this
// crate's zero-dependency policy is a hard design constraint (README:
// "dependency-free Rust state machine"), so adding proptest as a
// dev-dependency would trade the crate's defining property for a smaller
// test file. The generator below is ~50 lines of xorshift64* with heavy
// boundary bias, and the backlog item explicitly allows it.
//
// This module complements the AV-03 fleet fuzz rather than repeating it:
// AV-03 pins *fleet-level amount conservation across random operation
// sequences*; this module pins *per-case invariants* in the classic
// `for_all` style:
//
//   P1 amount dichotomy: `initialize` accepts `amount != 0` and rejects
//      `amount == 0` with `AmountMismatch`; accessors round-trip the
//      exact value.
//   P2 lifecycle preservation: for every boundary amount (1, 2,
//      u64::MAX-1, u64::MAX, arbitrary), all four legal lifecycles
//      (fund→release, fund→cancel, fund→cancel_expired by the taker,
//      quorum fund→attest→release) end in the expected terminal state
//      with `amount()` bit-identical — especially at u64::MAX, where
//      any accounting arithmetic would overflow.
//   P3 expiry edge: `cancel_expired` (Funded state, authorized caller
//      fixed) succeeds iff `now >= expires_at`, over boundary
//      (expires_at, now) pairs including (0, 0) and
//      (u64::MAX, u64::MAX).
//   P4 quorum idempotency under random attestation order: random
//      sequences with duplicates; `approval_count` == distinct
//      registered attestors seen; `is_satisfied()` iff distinct >=
//      threshold; outsiders are `Unauthorized` and change nothing.
//
// Every case is deterministic: the PRNG is seeded from a fixed
// domain-separation constant plus the case index, so a failing case is
// reproducible by its index.
#[cfg(test)]
mod property_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const EXPIRY: u64 = 1_800_000_000;
    const CASES: u64 = 512;

    struct PropRng(u64);

    impl PropRng {
        fn for_case(base: u64, case: u64) -> Self {
            // SplitMix-style domain separation: each (property, case)
            // gets its own stream so properties don't share sequences.
            let mut z = base
                .wrapping_add(case.wrapping_mul(0x9E37_79B9_7F4A_7C15))
                .wrapping_add(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            // Never zero: xorshift with a zero state never advances.
            Self(z | 1)
        }

        fn next(&mut self) -> u64 {
            // xorshift64*
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, n: u64) -> u64 {
            debug_assert!(n > 0);
            self.next() % n
        }
    }

    /// Boundary-biased amount generator: 0 (must reject), 1, 2, small,
    /// u64::MAX-1, u64::MAX, half-MAX, and an arbitrary 64-bit value.
    fn gen_amount(rng: &mut PropRng) -> u64 {
        match rng.below(8) {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => rng.below(1_000_000) + 1,
            4 => u64::MAX - 1,
            5 => u64::MAX,
            6 => u64::MAX / 2,
            _ => rng.next(),
        }
    }

    /// Boundary-biased expiry / timestamp generator.
    fn gen_time(rng: &mut PropRng) -> u64 {
        match rng.below(8) {
            0 => 0,
            1 => 1,
            2 => EXPIRY - 1,
            3 => EXPIRY,
            4 => EXPIRY + 1,
            5 => u64::MAX - 1,
            6 => u64::MAX,
            _ => rng.next(),
        }
    }

    fn for_all(base: u64, mut check: impl FnMut(&mut PropRng, u64)) {
        for case in 0..CASES {
            let mut rng = PropRng::for_case(base, case);
            check(&mut rng, case);
        }
    }

    // ----- P1: initialize amount dichotomy -----

    #[test]
    fn property_initialize_amount_dichotomy() {
        // amount == 0 ⟺ Err(AmountMismatch); amount != 0 ⟹ Ok.
        for_all(0xA001, |rng, case| {
            let amount = gen_amount(rng);
            let expiry = gen_time(rng);
            match Escrow::initialize(ALICE, BOB, amount, expiry) {
                Ok(e) => {
                    assert_ne!(amount, 0, "case {case}: zero amount accepted");
                    // Accessor round-trips the exact boundary value.
                    assert_eq!(e.amount(), amount, "case {case}: amount not stored exactly");
                    assert_eq!(e.expires_at(), expiry, "case {case}: expiry not stored exactly");
                    assert_eq!(e.state(), EscrowState::Uninitialized);
                }
                Err(e) => {
                    assert_eq!(
                        amount, 0,
                        "case {case}: non-zero amount {amount} rejected with {e:?}"
                    );
                    assert_eq!(e, EscrowError::AmountMismatch);
                }
            }
        });
    }

    // ----- P2: lifecycle preservation of the amount -----

    #[test]
    fn property_lifecycle_preserves_amount() {
        // For every non-zero boundary amount, all four legal lifecycles
        // terminate in the expected state with the amount bit-identical.
        for_all(0xA002, |rng, case| {
            let amount = gen_amount(rng);
            if amount == 0 {
                return; // covered by P1
            }
            let expiry = gen_time(rng);
            let mk = || Escrow::initialize(ALICE, BOB, amount, expiry).unwrap();

            // fund → release.
            let mut e = mk();
            e.fund(ALICE).unwrap();
            e.release(ALICE, amount).unwrap();
            assert_eq!(e.state(), EscrowState::Released);
            assert_eq!(e.amount(), amount, "case {case}: amount changed on release path");
            assert_eq!(
                e.released_amount(),
                amount,
                "case {case}: full release not tracked in released_amount"
            );
            assert_eq!(
                e.remaining_amount(),
                0,
                "case {case}: remaining not zero after full release"
            );

            // fund → cancel.
            let mut e = mk();
            e.fund(ALICE).unwrap();
            e.cancel(ALICE).unwrap();
            assert_eq!(e.state(), EscrowState::Cancelled);
            assert_eq!(e.amount(), amount, "case {case}: amount changed on cancel path");

            // fund → cancel_expired by the taker at exactly the expiry
            // edge (now == expires_at satisfies now >= expires_at).
            let mut e = mk();
            e.fund(ALICE).unwrap();
            e.cancel_expired(BOB, expiry).unwrap();
            assert_eq!(e.state(), EscrowState::Cancelled);
            assert_eq!(
                e.amount(),
                amount,
                "case {case}: amount changed on cancel_expired path"
            );

            // quorum fund → attest → release.
            let policy = QuorumPolicy::new(&[[0xA1; 32], [0xA2; 32]], 2).unwrap();
            let mut e = mk().with_quorum(policy).unwrap();
            e.fund(ALICE).unwrap();
            e.attest([0xA1; 32]).unwrap();
            e.attest([0xA2; 32]).unwrap();
            e.release(ALICE, amount).unwrap();
            assert_eq!(e.state(), EscrowState::Released);
            assert_eq!(e.amount(), amount, "case {case}: amount changed on quorum path");
            assert_eq!(
                e.released_amount(),
                amount,
                "case {case}: full release not tracked in released_amount"
            );
            assert_eq!(
                e.remaining_amount(),
                0,
                "case {case}: remaining not zero after full release"
            );
        });
    }

    // ----- P3: cancel_expired edge matches now >= expires_at -----

    #[test]
    fn property_cancel_expired_edge_matches_now_ge_expires_at() {
        // Funded state and authorized caller fixed; cancel_expired
        // succeeds iff now >= expires_at. Boundary pairs (0, 0),
        // (u64::MAX, u64::MAX), (expiry, expiry±1) are biased in.
        for_all(0xA003, |rng, case| {
            let expiry = gen_time(rng);
            let now = gen_time(rng);
            let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, expiry).unwrap();
            e.fund(ALICE).unwrap();
            let expected = now >= expiry;
            match e.cancel_expired(ALICE, now) {
                Ok(()) => {
                    assert!(
                        expected,
                        "case {case}: succeeded with now={now} < expires_at={expiry}"
                    );
                    assert_eq!(e.state(), EscrowState::Cancelled);
                }
                Err(EscrowError::NotExpired) => {
                    assert!(
                        !expected,
                        "case {case}: NotExpired with now={now} >= expires_at={expiry}"
                    );
                    assert_eq!(e.state(), EscrowState::Funded);
                }
                Err(other) => panic!(
                    "case {case}: unexpected error {other:?} for now={now}, expiry={expiry}"
                ),
            }
        });
    }

    // ----- P4: quorum idempotency under random attestation order -----

    #[test]
    fn property_quorum_idempotent_under_random_attestation_order() {
        // Random attestation sequences with duplicates and outsider
        // noise: approval_count == distinct registered attestors seen,
        // is_satisfied() iff distinct >= threshold, outsiders are
        // Unauthorized and change nothing.
        for_all(0xA004, |rng, case| {
            let m = (rng.below(MAX_ATTESTORS as u64) + 1) as u8; // 1..=8
            let threshold = (rng.below(m as u64) + 1) as u8; // 1..=m
            let mut attestors = [[0u8; 32]; MAX_ATTESTORS];
            for i in 0..m {
                // Distinct, and never colliding with ALICE/MALLORY
                // (0xAA/0xCC) so the outsider check is sound.
                attestors[i as usize] = [(i + 1) as u8; 32];
            }
            let mut policy = QuorumPolicy::new(&attestors[..m as usize], threshold).unwrap();

            // 2m attestations: duplicates plus outsider noise.
            let mut distinct = [false; MAX_ATTESTORS];
            let mut distinct_count = 0u8;
            for _ in 0..(2 * m as u64) {
                match rng.below(4) {
                    // 3/4: a registered attestor (possibly repeated).
                    0..=2 => {
                        let idx = rng.below(m as u64) as usize;
                        policy.attest(attestors[idx]).unwrap();
                        if !distinct[idx] {
                            distinct[idx] = true;
                            distinct_count += 1;
                        }
                    }
                    // 1/4: outsiders — must be Unauthorized and change nothing.
                    _ => {
                        let before = policy.approval_count();
                        assert_eq!(policy.attest(MALLORY), Err(EscrowError::Unauthorized));
                        assert_eq!(policy.attest(ALICE), Err(EscrowError::Unauthorized));
                        assert_eq!(policy.approval_count(), before);
                    }
                }
                assert_eq!(
                    policy.approval_count(),
                    distinct_count,
                    "case {case}: approval count drifted from distinct attestor count"
                );
            }

            assert_eq!(
                policy.is_satisfied(),
                distinct_count >= threshold,
                "case {case}: satisfaction mismatch \
                 (distinct={distinct_count}, threshold={threshold})"
            );
            assert_eq!((policy.registered_count(), policy.threshold()), (m, threshold));
        });
    }
}

// ---------- AV-10: account space + rent-exemption tests ----------
//
// These tests pin the numbers the Anchor program bakes into its
// `#[account(init, space = ...)]` constraint and its `initialize`-time
// rent check. The sizes are asserted three ways so they cannot drift
// silently:
//
// 1. `space_constants_match_hand_computed_layout` hardcodes the byte
//    math (the same addition the program author does by hand);
// 2. `manual_borsh_encoding_matches_space_constant` serializes a real
//    `Escrow` with a test-only Borsh encoder and asserts the byte
//    length — and the field offsets — equal the constants;
// 3. the two-way test inside `anchor_idl_tests` ties the field table to
//    the IDL parameter mapping in both directions.
//
// Rent numbers use the real mainnet parameters (3_480 lamports per
// byte-year, 2-year exemption threshold) so the asserted lamport values
// are the ones the program will actually demand on-chain.
#[cfg(test)]
mod account_space_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    /// Test-only Borsh encoder for `Escrow`, mirroring the field order of
    /// the Anchor `Vault` account (see `VAULT_FIELDS`). Exists so the
    /// space constants are checked against a real serialization, not just
    /// re-derived from the same table.
    ///
    /// Note: this encodes the *account layout*, not strict Borsh of the
    /// Rust struct. Borsh would write `quorum: None` as a single byte, but
    /// the account always reserves the full quorum region (see
    /// `VAULT_FIELDS`): a `None` quorum is stored as the `0` discriminant
    /// followed by zeroed quorum bytes, so `initialize_quorum` can write
    /// the policy in place without reallocating.
    fn encode_escrow(e: &Escrow) -> Vec<u8> {
        let mut out = Vec::with_capacity(ESCROW_BODY_LEN + 8);
        out.extend_from_slice(&e.initializer);
        out.extend_from_slice(&e.taker);
        out.extend_from_slice(&e.amount.to_le_bytes());
        out.extend_from_slice(&e.released.to_le_bytes());
        out.extend_from_slice(&e.expires_at.to_le_bytes());
        out.push(e.state as u8);
        match e.quorum {
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; QUORUM_POLICY_LEN]);
            }
            Some(q) => {
                out.push(1);
                for attestor in q.attestors {
                    out.extend_from_slice(&attestor);
                }
                out.push(q.registered);
                out.push(q.threshold);
                out.extend_from_slice(&q.approvals.to_le_bytes());
            }
        }
        // AV-12: activation bitmask, always present (zeroed for plain
        // escrows), Borsh field order after `quorum`.
        out.push(e.activation);
        out
    }

    #[test]
    fn space_constants_match_hand_computed_layout() {
        // Hardcoded on purpose: if the layout ever changes, these numbers
        // must be updated deliberately — and the Anchor program's
        // `space =` expression with them.
        assert_eq!(QUORUM_POLICY_LEN, 8 * 32 + 1 + 1 + 8, "quorum policy bytes");
        assert_eq!(QUORUM_POLICY_LEN, 266);
        // 32 + 32 + 8 + 8 + 8 + 1 + (1 + 266) + 1 (AV-12 activation bitmask)
        assert_eq!(ESCROW_BODY_LEN, 357, "escrow payload bytes");
        // 8-byte Anchor discriminator + payload.
        assert_eq!(VAULT_SPACE, 365, "full Vault account space");
        // Discriminator + payload with `quorum: None` (1-byte
        // discriminant) + 1-byte activation bitmask (AV-12, always
        // present even for plain escrows).
        assert_eq!(
            VAULT_SPACE_NO_QUORUM,
            8 + 32 + 32 + 8 + 8 + 8 + 1 + 1 + 1,
            "no-quorum Vault account space"
        );
        assert_eq!(VAULT_SPACE_NO_QUORUM, 99);
    }

    #[test]
    fn field_table_derives_body_len() {
        // `ESCROW_BODY_LEN` is const-summed from `VAULT_FIELDS`; this pins
        // the table itself against the hardcoded total above.
        let summed: usize = VAULT_FIELDS.iter().map(|(_, _, len)| len).sum();
        assert_eq!(summed, ESCROW_BODY_LEN);
        assert_eq!(VAULT_SPACE, ANCHOR_DISCRIMINATOR_LEN + ESCROW_BODY_LEN);
    }

    #[test]
    fn state_discriminants_follow_declaration_order() {
        // Borsh serializes unit enums by declaration order. The manual
        // encoder above relies on that, so pin it explicitly.
        assert_eq!(EscrowState::Uninitialized as u8, 0);
        assert_eq!(EscrowState::Funded as u8, 1);
        assert_eq!(EscrowState::Released as u8, 2);
        assert_eq!(EscrowState::Cancelled as u8, 3);
        // AV-12: appended last so discriminants 0–3 stay stable for
        // already-serialized vaults.
        assert_eq!(EscrowState::Activated as u8, 4);
    }

    #[test]
    fn manual_borsh_encoding_matches_space_constant() {
        // Plain two-party escrow, funded.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE).unwrap();
        let bytes = encode_escrow(&e);
        assert_eq!(bytes.len(), ESCROW_BODY_LEN);

        // Field offsets: 0..32 initializer, 32..64 taker, 64..72 amount,
        // 72..80 released, 80..88 expires_at, 88 state, 89 quorum
        // discriminant (None), 356 activation bitmask (AV-12).
        assert_eq!(&bytes[0..32], &ALICE);
        assert_eq!(&bytes[32..64], &BOB);
        assert_eq!(u64::from_le_bytes(bytes[64..72].try_into().unwrap()), 1_000_000);
        assert_eq!(
            u64::from_le_bytes(bytes[72..80].try_into().unwrap()),
            0,
            "nothing released yet"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[80..88].try_into().unwrap()),
            EXPIRES_AT
        );
        assert_eq!(bytes[88], EscrowState::Funded as u8);
        assert_eq!(bytes[89], 0, "quorum: None discriminant");
        assert_eq!(
            &bytes[90..356],
            &[0u8; QUORUM_POLICY_LEN],
            "None quorum reserves zeroed quorum bytes in the account layout"
        );
        // AV-12: activation bitmask trails the quorum region; zero for a
        // plain escrow.
        assert_eq!(bytes[356], 0, "activation bitmask offset, plain escrow");

        // With quorum: same total length (space is always reserved), Some
        // discriminant, attestor bytes and approval bitmask in place.
        let policy =
            QuorumPolicy::new(&[[0xA1; 32], [0xA2; 32]], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.attest([0xA1; 32]).unwrap();
        let bytes = encode_escrow(&e);
        assert_eq!(bytes.len(), ESCROW_BODY_LEN);
        assert_eq!(bytes[89], 1, "quorum: Some discriminant");
        assert_eq!(
            u64::from_le_bytes(bytes[72..80].try_into().unwrap()),
            0,
            "released field offset, nothing released yet"
        );
        // attestors: 90..346 (8 x 32), registered at 346, threshold at 347,
        // approvals u64 LE at 348..356.
        assert_eq!(&bytes[90..122], &[0xA1; 32]);
        assert_eq!(&bytes[122..154], &[0xA2; 32]);
        assert_eq!(&bytes[154..346], &[0u8; 192], "unused attestor slots are zero");
        assert_eq!(bytes[346], 2, "registered count");
        assert_eq!(bytes[347], 2, "threshold");
        assert_eq!(
            u64::from_le_bytes(bytes[348..356].try_into().unwrap()),
            0b01,
            "approval bitmask after one attestation"
        );
        // AV-12: activation bitmask trails the quorum region; zero here
        // (this escrow did not opt into dual-signature activation).
        assert_eq!(bytes[356], 0, "activation bitmask offset, no dual-sig");
    }

    #[test]
    fn rent_formula_matches_hand_computed_mainnet_numbers() {
        // ((128 + space) * lamports_per_byte_year) * exemption_threshold.
        let full = rent_exempt_minimum_lamports(
            VAULT_SPACE,
            MAINNET_LAMPORTS_PER_BYTE_YEAR,
            MAINNET_EXEMPTION_THRESHOLD_YEARS,
        );
        // (128 + 365) * 3480 * 2 = 493 * 6960 = 3_431_280 lamports.
        assert_eq!(full, 3_431_280);

        let no_quorum = rent_exempt_minimum_lamports(
            VAULT_SPACE_NO_QUORUM,
            MAINNET_LAMPORTS_PER_BYTE_YEAR,
            MAINNET_EXEMPTION_THRESHOLD_YEARS,
        );
        // (128 + 99) * 3480 * 2 = 227 * 6960 = 1_579_920 lamports.
        assert_eq!(no_quorum, 1_579_920);
        assert!(no_quorum < full, "smaller account needs less rent");

        // Zero-byte account: pure storage overhead.
        assert_eq!(
            rent_exempt_minimum_lamports(0, 3_480, 2.0),
            128 * 3_480 * 2,
            "128 * 3480 * 2 = 890_880"
        );
    }

    #[test]
    fn rent_scales_linearly_with_space() {
        // Each extra byte costs exactly lamports_per_byte_year * threshold.
        let one_more = rent_exempt_minimum_lamports(
            VAULT_SPACE + 1,
            MAINNET_LAMPORTS_PER_BYTE_YEAR,
            MAINNET_EXEMPTION_THRESHOLD_YEARS,
        );
        let base = rent_exempt_minimum_lamports(
            VAULT_SPACE,
            MAINNET_LAMPORTS_PER_BYTE_YEAR,
            MAINNET_EXEMPTION_THRESHOLD_YEARS,
        );
        assert_eq!(one_more - base, 3_480 * 2);
    }

    #[test]
    fn rent_formula_accepts_custom_parameters() {
        // Devnet / test-validator rent configs flow through unchanged.
        assert_eq!(
            rent_exempt_minimum_lamports(100, 1_000, 1.0),
            (128 + 100) * 1_000
        );
    }

    #[test]
    fn check_vault_rent_exempt_boundary() {
        let params = (
            MAINNET_LAMPORTS_PER_BYTE_YEAR,
            MAINNET_EXEMPTION_THRESHOLD_YEARS,
        );
        // Exactly the minimum: exempt.
        assert_eq!(check_vault_rent_exempt(3_431_280, params.0, params.1), Ok(()));
        // One lamport short: exact shortfall reported.
        assert_eq!(
            check_vault_rent_exempt(3_431_279, params.0, params.1),
            Err(RentShortfall {
                required: 3_431_280,
                provided: 3_431_279,
            })
        );
        // Generous funding: exempt.
        assert_eq!(
            check_vault_rent_exempt(10_000_000, params.0, params.1),
            Ok(())
        );
        // Zero lamports: the full minimum is the shortfall.
        assert_eq!(
            check_vault_rent_exempt(0, params.0, params.1),
            Err(RentShortfall {
                required: 3_431_280,
                provided: 0,
            })
        );
    }
}

// ---------- AV-11: partial release with cumulative cap ----------
//
// `release` takes an `amount`: partial releases accumulate in the
// `released` field and leave the escrow `Funded` until the cumulative
// released total reaches the locked amount, at which point the escrow
// becomes `Released`. Cumulative releases must never exceed the locked
// amount (`ReleaseExceedsLocked`); a zero-amount release is
// `AmountMismatch`. `released_amount()` / `remaining_amount()` expose the
// release progress for staged payouts (e.g. delivery milestones paid out
// in tranches), and `cancel` / `cancel_expired` after partial releases
// refund only the remainder while preserving `released_amount` for audit.
#[cfg(test)]
mod partial_release_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const ATTESTOR_1: [u8; 32] = [0xA1; 32];
    const ATTESTOR_2: [u8; 32] = [0xA2; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn funded_escrow() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.released_amount(),
            0,
            "a freshly funded escrow has released nothing"
        );
        e
    }

    #[test]
    fn partial_release_stays_funded_with_progress_tracked() {
        let mut e = funded_escrow();
        e.release(ALICE, 400_000).unwrap();
        assert_eq!(
            e.state(),
            EscrowState::Funded,
            "a partial release must not close the escrow"
        );
        assert_eq!(e.released_amount(), 400_000);
        assert_eq!(e.remaining_amount(), 600_000);
        // A second partial accumulates on top of the first.
        e.release(ALICE, 100_000).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 500_000);
        assert_eq!(e.remaining_amount(), 500_000);
    }

    #[test]
    fn final_partial_release_closes_the_escrow() {
        let mut e = funded_escrow();
        e.release(ALICE, 400_000).unwrap();
        e.release(ALICE, 600_000).unwrap(); // reaches the locked amount exactly
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.released_amount(), 1_000_000);
        assert_eq!(e.remaining_amount(), 0);
    }

    #[test]
    fn zero_amount_release_is_amount_mismatch_and_changes_nothing() {
        let mut e = funded_escrow();
        assert_eq!(e.release(ALICE, 0), Err(EscrowError::AmountMismatch));
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0);
        assert_eq!(e.remaining_amount(), 1_000_000);
    }

    #[test]
    fn release_beyond_remaining_is_release_exceeds_locked() {
        let mut e = funded_escrow();
        e.release(ALICE, 600_000).unwrap();
        // 400_000 remains: asking for one lamport more must fail.
        assert_eq!(
            e.release(ALICE, 400_001),
            Err(EscrowError::ReleaseExceedsLocked)
        );
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(
            e.released_amount(),
            600_000,
            "a failed release must not move the counter"
        );
        assert_eq!(e.remaining_amount(), 400_000);
    }

    #[test]
    fn cumulative_addition_overflow_is_release_exceeds_locked() {
        // u64::MAX escrow: release u64::MAX - 10 (stays Funded), then
        // release(11) would overflow the u64 accumulator — a wrapping add
        // would reset the counter to 0 and let the lockup be drained past
        // its amount. The checked_add guard must catch it instead.
        let mut e = Escrow::initialize(ALICE, BOB, u64::MAX, EXPIRES_AT).unwrap();
        e.fund(ALICE).unwrap();
        e.release(ALICE, u64::MAX - 10).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), u64::MAX - 10);
        assert_eq!(
            e.release(ALICE, 11),
            Err(EscrowError::ReleaseExceedsLocked)
        );
        assert_eq!(
            e.released_amount(),
            u64::MAX - 10,
            "the counter is untouched by the overflow attempt"
        );
        // The exact remainder still works and closes the escrow.
        e.release(ALICE, 10).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.remaining_amount(), 0);
    }

    #[test]
    fn quorum_still_gates_partial_release() {
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.fund(ALICE).unwrap();
        // A partial amount changes nothing about the gate: no attestations.
        assert_eq!(
            e.release(ALICE, 400_000),
            Err(EscrowError::QuorumNotReached)
        );
        assert_eq!(e.released_amount(), 0);
    }

    #[test]
    fn attestations_allowed_between_partial_releases() {
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.attest(ATTESTOR_1).unwrap();
        // 1 of 2: still gated.
        assert_eq!(
            e.release(ALICE, 400_000),
            Err(EscrowError::QuorumNotReached)
        );
        e.attest(ATTESTOR_2).unwrap();
        // Gate satisfied: the partial release goes through and stays Funded.
        e.release(ALICE, 400_000).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 400_000);
        // The final partial closes the escrow.
        e.release(ALICE, 600_000).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn cancel_after_partial_release_refunds_remainder_and_preserves_released() {
        let mut e = funded_escrow();
        e.release(ALICE, 400_000).unwrap();
        e.cancel(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        // Released funds stay released; the refund is the remainder.
        assert_eq!(e.released_amount(), 400_000, "released preserved for audit");
        assert_eq!(e.remaining_amount(), 600_000, "refundable remainder");
    }

    #[test]
    fn release_after_full_release_is_invalid_transition() {
        let mut e = funded_escrow();
        e.release(ALICE, 1_000_000).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(
            e.release(ALICE, 1_000_000),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.released_amount(), 1_000_000);
    }
}

// ---------- AV-12: dual-signature activation ----------
//
// A dual-signature escrow requires both the initializer and the taker to
// record an activation signature before funds can move: one signature
// creates the escrow, two signatures unlock funding. This mirrors Solana
// multisig escrow activation, where each party's approval arrives as a
// separate signed transaction. The requirement is opt-in via the
// `with_dual_sig` builder (plain escrows behave exactly as before), and
// activation progress is a persisted bitmask so it survives
// serialization to the Vault account.
#[cfg(test)]
mod dual_sig_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn dual_sig_escrow() -> Escrow {
        Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_dual_sig()
            .unwrap()
    }

    fn activated_escrow() -> Escrow {
        let mut e = dual_sig_escrow();
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        assert_eq!(e.state(), EscrowState::Activated);
        e
    }

    #[test]
    fn plain_escrow_has_no_dual_sig_requirement() {
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert!(!e.dual_sig_required());
        assert!(!e.initializer_activated());
        assert!(!e.taker_activated());
    }

    #[test]
    fn with_dual_sig_sets_only_the_requirement_bit() {
        let e = dual_sig_escrow();
        assert!(e.dual_sig_required());
        assert!(!e.initializer_activated());
        assert!(!e.taker_activated());
        assert_eq!(e.state(), EscrowState::Uninitialized);
    }

    #[test]
    fn with_dual_sig_rejected_after_activation() {
        let e = activated_escrow();
        assert_eq!(
            e.with_dual_sig(),
            Err(EscrowError::InvalidStateTransition),
            "the requirement is fixed before funds move, like with_quorum"
        );
    }

    #[test]
    fn single_activation_keeps_escrow_uninitialized_and_unfundable() {
        // Either party alone: bit recorded, state unchanged, fund refused.
        for party in [ALICE, BOB] {
            let mut e = dual_sig_escrow();
            e.activate(party).unwrap();
            assert_eq!(e.state(), EscrowState::Uninitialized);
            assert_eq!(e.fund(ALICE), Err(EscrowError::InvalidStateTransition));
            assert_eq!(e.fund(BOB), Err(EscrowError::Unauthorized));
        }
    }

    #[test]
    fn both_activations_unlock_fund() {
        let mut e = activated_escrow();
        // Activation order does not matter; taker-first works too.
        e.fund(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn taker_first_activation_order_also_works() {
        let mut e = dual_sig_escrow();
        e.activate(BOB).unwrap();
        assert_eq!(e.state(), EscrowState::Uninitialized);
        e.activate(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Activated);
    }

    #[test]
    fn activate_is_idempotent_per_party() {
        let mut e = dual_sig_escrow();
        e.activate(ALICE).unwrap();
        // Second activation by the same party: same bit, still
        // Uninitialized, still no error.
        e.activate(ALICE).unwrap();
        assert!(e.initializer_activated());
        assert!(!e.taker_activated());
        assert_eq!(e.state(), EscrowState::Uninitialized);
    }

    #[test]
    fn stranger_activate_is_unauthorized_and_changes_nothing() {
        let mut e = dual_sig_escrow();
        assert_eq!(e.activate(MALLORY), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Uninitialized);
        assert!(!e.initializer_activated());
        assert!(!e.taker_activated());
    }

    #[test]
    fn activate_on_plain_escrow_is_invalid_transition() {
        // `activate` is meaningless without the opt-in; it must not
        // silently succeed on a plain escrow.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(e.activate(ALICE), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.state(), EscrowState::Uninitialized);
    }

    #[test]
    fn activate_after_activation_is_invalid_transition() {
        let mut e = activated_escrow();
        assert_eq!(e.activate(ALICE), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.activate(BOB), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.state(), EscrowState::Activated);
    }

    #[test]
    fn activate_after_fund_is_invalid_transition() {
        let mut e = activated_escrow();
        e.fund(ALICE).unwrap();
        assert_eq!(e.activate(ALICE), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.activate(BOB), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn fund_from_activated_still_requires_initializer() {
        let mut e = activated_escrow();
        assert_eq!(e.fund(BOB), Err(EscrowError::Unauthorized));
        assert_eq!(e.fund(MALLORY), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Activated);
    }

    #[test]
    fn dual_sig_full_lifecycle_release_and_cancel() {
        // The rest of the machine is unchanged once funded.
        let mut e = activated_escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 400_000).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!((e.released_amount(), e.remaining_amount()), (400_000, 600_000));
        e.cancel(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn dual_sig_combines_with_quorum() {
        // Independent builders compose: activation gates fund, quorum
        // gates release.
        let policy = QuorumPolicy::new(&[[0xA1; 32], [0xA2; 32]], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_dual_sig()
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(e.release(ALICE, 1_000_000), Err(EscrowError::QuorumNotReached));
        e.attest([0xA1; 32]).unwrap();
        e.attest([0xA2; 32]).unwrap();
        e.release(ALICE, 1_000_000).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn attest_allowed_between_activation_and_funding() {
        let policy = QuorumPolicy::new(&[[0xA1; 32]], 1).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_dual_sig()
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        // Activated but not yet funded: attestors may already vote.
        e.attest([0xA1; 32]).unwrap();
        assert!(e.quorum().unwrap().is_satisfied());
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_000_000).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn activation_bits_are_distinct_and_stable() {
        assert_eq!(ACTIVATION_INITIALIZER_BIT, 0b001);
        assert_eq!(ACTIVATION_TAKER_BIT, 0b010);
        assert_eq!(ACTIVATION_DUAL_SIG_REQUIRED_BIT, 0b100);
        // No overlap: each bit is independent.
        assert_eq!(
            ACTIVATION_INITIALIZER_BIT | ACTIVATION_TAKER_BIT | ACTIVATION_DUAL_SIG_REQUIRED_BIT,
            0b111
        );
    }

    #[test]
    fn self_escrow_activates_with_one_signature() {
        // Degenerate initializer == taker: one signature sets both party
        // bits at once. Deterministic, documented, no special-casing in
        // callers.
        let mut e = Escrow::initialize(ALICE, ALICE, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_dual_sig()
            .unwrap();
        e.activate(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Activated);
        e.fund(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
    }
}
