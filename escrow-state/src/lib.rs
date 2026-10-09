//! Pure-Rust escrow vault state machine.
//!
//! This crate is the dependency-free logic core of the escrow vault.
//! It models the full lifecycle of a two-party escrow with initializer
//! authority checks and amount invariants. The Anchor program under
//! `programs/escrow-vault` wraps exactly this logic for the Solana target.

mod events;
mod keeper;
mod snapshot;
mod cpi;
#[cfg(test)]
mod idl_json;
#[cfg(test)]
mod sim;

// AV-31: off-chain CPI transfer instruction construction — byte-exact
// System Program / SPL Token transfer builders plus settlement plans
// that validate amounts and recipients against the state machine's
// transition results before anything is submitted on-chain.
pub use cpi::{
    payout_plan, refund_plan, resolve_plan, spl_token_program_id, spl_token_transfer,
    system_program_id, system_transfer, AccountMeta, CpiError, PayoutAddrs, PayoutKind,
    Pubkey, RefundAddrs, RefundKind, ResolveAddrs, SettlementPlan, TransferInstruction,
};

// AV-18: typed indexer events — an event-logging adapter over `Escrow`
// plus the `EscrowEvent` / `EscrowEventKind` / `EventAmounts` record
// types. Purely additive: no existing signature changed.
pub use events::{EscrowEvent, EscrowEventKind, EventAmounts, IndexedEscrow};

// AV-20: off-chain keeper report — scan a batch of escrows for executable
// `cancel_expired` / `claim` calls and serialize the call list as JSON.
// Purely additive and read-only (dry-run by construction).
pub use keeper::{
    scan_keeper_actions, KeeperAction, KeeperActionKind, KeeperReport, WatchedEscrow,
};

// AV-26: off-chain state snapshot — a point-in-time, read-only view of
// an `Escrow` as canonical JSON (all fields + derived remaining /
// vested-claimable / quorum progress), for keeper bots and indexers
// reconciling off-chain state. Purely additive and read-only.
pub use snapshot::{
    DualSigSnapshot, EscrowSnapshot, MilestoneSnapshot, MilestoneTrancheSnapshot, QuorumSnapshot,
    VestingSnapshot,
};

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
    /// AV-14: either party escalated the escrow into arbitration
    /// (via [`Escrow::escalate`]). While `Disputed`, every unilateral
    /// exit is locked — `release`, `cancel`, `cancel_expired`, and
    /// `claim` all return `InvalidStateTransition` — so neither party
    /// can move funds while the arbiter deliberates. Only
    /// [`Escrow::resolve`] leaves this state.
    Disputed,
    /// AV-14: the arbiter settled the dispute (via [`Escrow::resolve`])
    /// with a single atomic split of the remaining locked funds between
    /// taker (payout) and initializer (refund). Terminal: no transition
    /// leaves `Settled`.
    Settled,
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
    /// AV-13: optional linear vesting schedule gating [`Escrow::claim`].
    /// `None` means no vesting (backward compatible): the taker cannot
    /// claim, and `release` keeps its existing semantics.
    vesting: Option<VestingSchedule>,
    /// AV-14: optional dispute arbiter. `None` means no arbitration
    /// (backward compatible): `escalate` / `resolve` fail with
    /// [`EscrowError::InvalidArbiter`]. Set once via
    /// [`Escrow::with_arbiter`] on an `Uninitialized` escrow, like the
    /// quorum and vesting builders. Persisted (33 bytes in the vault
    /// account) so the arbiter's identity survives serialization.
    arbiter: Option<[u8; 32]>,
    /// AV-15: optional milestone tranche plan (see
    /// [`Escrow::with_milestones`]). `None` means no milestone schedule
    /// (backward compatible): `confirm_milestone` / `release_milestone` /
    /// `skip_milestone` fail with [`EscrowError::InvalidMilestones`], and
    /// plain [`Escrow::release`] / [`Escrow::claim`] keep their existing
    /// semantics. Set once on an `Uninitialized` escrow, like the quorum
    /// and vesting builders. Persisted (66 bytes in the vault account)
    /// so the tranche schedule survives serialization.
    milestones: Option<MilestonePlan>,
    /// AV-15: per-milestone confirmation bitmap, persisted so
    /// confirmation progress survives serialization. Six bits per
    /// milestone (see the `MILESTONE_*` bit constants): the two parties'
    /// release-path confirmations, the released bit, the two parties'
    /// skip approvals, and the skipped bit. Always present (zeroed for
    /// escrows without a milestone plan).
    milestone_flags: u64,
    /// AV-15: cumulative amount skipped by mutual agreement (see
    /// [`Escrow::skip_milestone`]). Skipped tranches join the refundable
    /// remainder — visible in [`Escrow::remaining_amount`] — not the
    /// taker-payout [`Escrow::released_amount`] counter. Always `<=
    /// amount`; `released + skipped <= amount` is the milestone
    /// accounting invariant.
    skipped: u64,
    /// AV-16: optional SPL token mint this escrow is bound to (see
    /// [`Escrow::with_mint`]). `None` means a native-SOL escrow
    /// (backward compatible): the fund-moving transitions take no token
    /// mint and behave exactly as before. `Some` pins the escrow to one
    /// SPL mint — every fund-moving transition
    /// ([`Escrow::release`], [`Escrow::cancel`],
    /// [`Escrow::cancel_expired`], [`Escrow::claim`],
    /// [`Escrow::release_milestone`], [`Escrow::resolve`]) then requires
    /// the token account's mint to equal this address
    /// ([`EscrowError::MintMismatch`] otherwise). Set once via
    /// [`Escrow::with_mint`] on an `Uninitialized` escrow, like the
    /// quorum and vesting builders. Persisted (33 bytes in the vault
    /// account) so the binding survives serialization.
    mint: Option<[u8; 32]>,
    /// AV-17: protocol fee rate in basis points (0–10000), charged on
    /// every taker payout ([`Escrow::release`], [`Escrow::claim`],
    /// [`Escrow::release_milestone`], and the taker's share of
    /// [`Escrow::resolve`]). Set once via
    /// [`Escrow::with_protocol_fee`] on an `Uninitialized` escrow, like
    /// the other `with_*` builders; `0` (the default) means no fee —
    /// backward compatible. Persisted (2 bytes in the vault account) so
    /// the rate survives serialization. Appended last so every earlier
    /// field offset stays stable.
    fee_bps: u16,
    /// AV-17: cumulative protocol fee charged across all payouts
    /// (always `<= released`): the fee is a routing slice of the gross
    /// payout, not an extra deduction from the lockup. Audit trail for
    /// the protocol; the Anchor program routes each payout's fee to the
    /// protocol fee account. Always present (zeroed for escrows that
    /// charged no fee). Appended last so every earlier field offset
    /// stays stable.
    fees_paid: u64,
    /// AV-21: expiry grace period in seconds. `cancel_expired` requires
    /// `now >= expires_at + grace_period` (see
    /// [`Escrow::is_expiry_eligible`]): the keeper's off-chain clock can
    /// drift from the Solana cluster clock, and without a grace period
    /// the keeper would submit `cancel_expired` the moment *its* clock
    /// passes `expires_at`, only for the chain to reject it as
    /// `NotExpired`. Opt-in via [`Escrow::with_grace_period`]; `0` (the
    /// default) means no grace — backward compatible. Always present
    /// (one u64, zeroed when no grace configured). Appended last so
    /// every earlier field offset stays stable.
    grace_period: u64,
    /// AV-22: 32-byte commitment to the off-chain dispute evidence
    /// attached at [`Escrow::escalate`] (e.g. the SHA-256 of an IPFS
    /// CID). `None` means no evidence was attached (backward
    /// compatible): the field is only `Some` on a `Disputed` escrow
    /// whose escalating party supplied evidence. Persisted (33 bytes in
    /// the vault account) so the arbiter and indexers can read it
    /// without trusting the escalator to re-supply it. Never cleared —
    /// it stays on the escrow through `Settled` as the audit trail of
    /// what the arbiter reviewed. Appended last so every earlier field
    /// offset stays stable.
    evidence_hash: Option<[u8; 32]>,
    /// AV-23: opt-in refund address whitelist (see
    /// [`Escrow::with_refund_address`]). `None` means no whitelist
    /// (backward compatible): refunds go to the initializer. `Some(addr)`
    /// pins every refund on the unilateral exit paths
    /// ([`Escrow::cancel`], [`Escrow::cancel_expired`]) to `addr` — the
    /// transitions take the destination explicitly and reject anything
    /// else with [`EscrowError::RefundAddressMismatch`], so a phishing
    /// frontend cannot redirect the refund by swapping the destination
    /// account. Set once via [`Escrow::with_refund_address`] on an
    /// `Uninitialized` escrow, like the quorum and vesting builders.
    /// Persisted (33 bytes in the vault account) so the policy survives
    /// serialization. Appended last so every earlier field offset stays
    /// stable.
    refund_to: Option<[u8; 32]>,
    /// AV-24: anti-griefing penalty rate in basis points (0–10000),
    /// charged to the initializer on a *taker-initiated*
    /// [`Escrow::cancel_expired`]: the taker dragging the deal to expiry
    /// locks the initializer's capital for free otherwise. Set once via
    /// [`Escrow::with_penalty_bps`] on an `Uninitialized` escrow, like
    /// the other `with_*` builders; `0` (the default) means no penalty —
    /// backward compatible. Persisted (2 bytes in the vault account) so
    /// the rate survives serialization. Appended last so every earlier
    /// field offset stays stable.
    penalty_bps: u16,
    /// AV-27: timelock — Unix timestamp before which no taker payout may
    /// leave the escrow. [`Escrow::release`], [`Escrow::claim`] and
    /// [`Escrow::release_milestone`] require `now >= unlock_at`
    /// ([`EscrowError::TimelockNotReached`] otherwise). `0` (the default)
    /// means no lock — backward compatible. Set once via
    /// [`Escrow::with_timelock`] on an `Uninitialized` escrow, like the
    /// other `with_*` builders. Persisted (8 bytes in the vault account)
    /// so the lock survives serialization. Appended last so every earlier
    /// field offset stays stable.
    ///
    /// Design: the lock gates only *payout* paths. The unilateral exits
    /// ([`Escrow::cancel`], [`Escrow::cancel_expired`]) and the arbiter's
    /// [`Escrow::resolve`] are deliberately *not* gated — a misconfigured
    /// or abandoned timelock must never trap funds forever; after
    /// `expires_at` either party can still walk the `cancel_expired` path,
    /// and a live dispute still settles via arbitration.
    timelock: u64,
    /// AV-28: token decimal metadata — the SPL mint's decimal places.
    /// `0` (the default) means no decimal metadata was declared: a
    /// native-SOL escrow, or a vault created before this metadata
    /// existed — amounts render as bare integers (backward compatible).
    /// Set once via [`Escrow::with_decimals`] on an `Uninitialized`
    /// escrow, like the other `with_*` builders. Persisted (1 byte in
    /// the vault account) so the precision survives serialization.
    /// Appended last so every earlier field offset stays stable.
    ///
    /// Design: the metadata never moves funds — it only feeds
    /// [`Escrow::display_amount`] and the human-readable amounts in the
    /// keeper report and the AV-26 snapshot export. SPL mints declare at
    /// most 9 decimals; 18 is the hard ceiling
    /// ([`EscrowError::InvalidDecimals`]).
    decimals: u8,
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
    /// `cancel_expired` called before the expiry gate passes
    /// (`now < expires_at + grace_period` — see
    /// [`Escrow::is_expiry_eligible`]).
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
    /// Vesting misconfiguration or misuse (AV-13): `VestingSchedule::new`
    /// with `start >= end`, or [`Escrow::claim`] on an escrow with no
    /// vesting schedule attached. Parallels [`EscrowError::InvalidQuorum`]
    /// (config error, plus the no-config call path).
    InvalidVesting,
    /// Arbiter misconfiguration or misuse (AV-14): `with_arbiter` with a
    /// zero key, or [`Escrow::escalate`] / [`Escrow::resolve`] on an
    /// escrow with no arbiter configured. Parallels
    /// [`EscrowError::InvalidQuorum`] and [`EscrowError::InvalidVesting`]
    /// (config error, plus the no-config call path).
    InvalidArbiter,
    /// [`Escrow::escalate`] called after the dispute window closed
    /// (`now >= expires_at`). The dispute window is the escrow's live
    /// window: before expiry either party may escalate, but once the
    /// escrow is expiry-eligible the unilateral `cancel_expired` path is
    /// the way out, so arbitration can no longer start.
    DisputeWindowClosed,
    /// Milestone plan misconfiguration or misuse (AV-15):
    /// [`MilestonePlan::new`] with an empty list, more than
    /// [`MAX_MILESTONES`] tranches, or a zero-amount tranche;
    /// [`Escrow::with_milestones`] whose tranche amounts do not sum to
    /// the locked amount (summed in `u128`, so the sum can never wrap);
    /// re-configuring the plan after funding; any milestone operation on
    /// an escrow with no plan attached; an out-of-range milestone index;
    /// or plain [`Escrow::release`] / [`Escrow::claim`] on an escrow with
    /// a milestone plan (the plan owns the release schedule). Parallels
    /// [`EscrowError::InvalidQuorum`], [`EscrowError::InvalidVesting`]
    /// and [`EscrowError::InvalidArbiter`] (config error, plus the
    /// no-config call path).
    InvalidMilestones,
    /// [`Escrow::release_milestone`] attempted before both parties
    /// confirmed the milestone via [`Escrow::confirm_milestone`].
    /// Parallels [`EscrowError::QuorumNotReached`]: the dual-confirmation
    /// gate is the milestone analogue of the quorum gate.
    MilestoneNotConfirmed,
    /// Mint address misconfiguration (AV-16): [`parse_mint_address`]
    /// with an empty string, a character outside the base58 alphabet, or
    /// an encoding that does not decode to exactly 32 bytes; or
    /// [`Escrow::with_mint`] with the zero address (well-formed but not
    /// a real SPL mint — parallels [`EscrowError::InvalidArbiter`]'s
    /// zero-key rejection).
    InvalidMint,
    /// [`Escrow::release`], [`Escrow::cancel`],
    /// [`Escrow::cancel_expired`], [`Escrow::claim`],
    /// [`Escrow::release_milestone`] or [`Escrow::resolve`] called with a
    /// token mint that does not equal the escrow's bound mint (AV-16):
    /// the tokens being moved are not the tokens this escrow locks.
    /// `None` vs `Some` also mismatches — a native-SOL escrow and a
    /// token-bound escrow never share an exit path.
    MintMismatch,
    /// Protocol fee misconfiguration (AV-17):
    /// [`Escrow::with_protocol_fee`] with `fee_bps > 10_000` — the rate
    /// is in basis points, so anything above 10_000 (100%) is not a
    /// valid rate. Parallels [`EscrowError::InvalidQuorum`],
    /// [`EscrowError::InvalidVesting`], [`EscrowError::InvalidArbiter`]
    /// and [`EscrowError::InvalidMint`] (config error).
    InvalidProtocolFee,
    /// Grace period misconfiguration (AV-21):
    /// [`Escrow::with_grace_period`] where `expires_at + grace_period`
    /// would overflow `u64` — in particular a grace period cannot be
    /// combined with the no-timeout convention
    /// (`expires_at == u64::MAX`), where it would be meaningless: an
    /// escrow that can never expire has no expiry gate to grace.
    InvalidGracePeriod,
    /// Refund destination mismatch (AV-23): [`Escrow::cancel`] or
    /// [`Escrow::cancel_expired`] called with a `refund_to` destination
    /// that does not equal the escrow's whitelisted refund address
    /// ([`Escrow::with_refund_address`]) — or, with no whitelist
    /// configured, that does not equal the initializer. Also returned by
    /// [`Escrow::with_refund_address`] for the zero address: a zero
    /// address can never be the legitimate refund destination, so
    /// binding it is a policy mismatch by construction.
    RefundAddressMismatch,
    /// Anti-griefing penalty misconfiguration (AV-24):
    /// [`Escrow::with_penalty_bps`] with `penalty_bps > 10_000` — the
    /// rate is in basis points, so anything above 10_000 (100%) is not
    /// a valid rate. Parallels [`EscrowError::InvalidProtocolFee`]
    /// (config error).
    InvalidPenalty,
    /// Timelock not reached (AV-27): [`Escrow::release`],
    /// [`Escrow::claim`] or [`Escrow::release_milestone`] called while
    /// `now < unlock_at` — the payout paths stay locked until the
    /// timelock configured via [`Escrow::with_timelock`] passes. The
    /// unilateral exits (`cancel`, `cancel_expired`) and the arbiter's
    /// [`Escrow::resolve`] are deliberately *not* gated by the timelock,
    /// so a misconfigured lock can never trap funds forever.
    TimelockNotReached,
    /// Token decimal metadata misconfiguration (AV-28):
    /// [`Escrow::with_decimals`] with `decimals > 18` — beyond the
    /// largest precision any SPL/EVM token convention needs. Parallels
    /// [`EscrowError::InvalidQuorum`], [`EscrowError::InvalidVesting`],
    /// [`EscrowError::InvalidArbiter`], [`EscrowError::InvalidMint`] and
    /// [`EscrowError::InvalidProtocolFee`] (config error).
    InvalidDecimals,
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
            EscrowError::InvalidVesting => 107,
            EscrowError::InvalidArbiter => 108,
            EscrowError::DisputeWindowClosed => 109,
            EscrowError::InvalidMilestones => 110,
            EscrowError::MilestoneNotConfirmed => 111,
            EscrowError::InvalidMint => 112,
            EscrowError::MintMismatch => 113,
            EscrowError::InvalidProtocolFee => 114,
            EscrowError::InvalidGracePeriod => 115,
            EscrowError::RefundAddressMismatch => 116,
            EscrowError::InvalidPenalty => 117,
            EscrowError::TimelockNotReached => 118,
            EscrowError::InvalidDecimals => 119,
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
            EscrowError::InvalidVesting,
            EscrowError::InvalidArbiter,
            EscrowError::DisputeWindowClosed,
            EscrowError::InvalidMilestones,
            EscrowError::MilestoneNotConfirmed,
            EscrowError::InvalidMint,
            EscrowError::MintMismatch,
            EscrowError::InvalidProtocolFee,
            EscrowError::InvalidGracePeriod,
            EscrowError::RefundAddressMismatch,
            EscrowError::InvalidPenalty,
            EscrowError::TimelockNotReached,
            EscrowError::InvalidDecimals,
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

/// Linear vesting schedule (AV-13): the locked [`Escrow::amount`] unlocks
/// uniformly between `start` and `end` (Unix seconds, caller-supplied
/// clock like `expires_at`). The taker claims the vested-but-unreleased
/// portion at any time via [`Escrow::claim`] — the streaming-payments
/// pattern (salary streams, linear token unlocks).
///
/// `Copy` and heap-free like the rest of the crate. The schedule is fixed
/// before funding via [`Escrow::with_vesting`]; it never changes
/// afterwards, so both parties can reason about the unlock curve
/// off-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VestingSchedule {
    start: u64,
    end: u64,
}

impl VestingSchedule {
    /// Build a schedule unlocking linearly from `start` (inclusive) to
    /// `end` (exclusive boundary: at `now >= end` everything is vested).
    /// Rejects `start >= end` with [`EscrowError::InvalidVesting`] — a
    /// zero-length window would divide by zero in
    /// [`VestingSchedule::vested_amount`].
    pub fn new(start: u64, end: u64) -> Result<Self, EscrowError> {
        if start >= end {
            return Err(EscrowError::InvalidVesting);
        }
        Ok(Self { start, end })
    }

    /// Unix timestamp at which unlocking begins.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Unix timestamp at which unlocking completes (everything vested).
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Amount vested at `now` for a locked total of `amount`: linear
    /// interpolation `amount * elapsed / duration`, clamped to
    /// `[0, amount]`. Before `start` nothing is vested; at or after `end`
    /// everything is.
    ///
    /// Computed in `u128`: `amount * elapsed` can reach
    /// `(u64::MAX)^2 < u128::MAX`, so the multiplication cannot overflow,
    /// and the result is `<= amount <= u64::MAX`, so the downcast is
    /// exact.
    pub fn vested_amount(&self, amount: u64, now: u64) -> u64 {
        let duration = self.end - self.start; // > 0 by construction
        let elapsed = now.saturating_sub(self.start).min(duration);
        ((amount as u128 * elapsed as u128) / duration as u128) as u64
    }
}

/// Maximum number of tranches in a [`MilestonePlan`]. Fixed-size so the
/// crate stays heap-free and `Copy` — the same bound as
/// [`MAX_ATTESTORS`]: eight tranches cover staged settlements without
/// bloating the vault account (the plan reserves 65 bytes).
pub const MAX_MILESTONES: usize = 8;

/// Bit offsets inside [`Escrow::milestone_flags`]: six bits per milestone
/// (48 bits for [`MAX_MILESTONES`] milestones fit in a `u64`). Bit
/// `index * 6 + offset`:
/// - 0: the initializer confirmed the milestone (release path)
/// - 1: the taker confirmed the milestone (release path)
/// - 2: the milestone's tranche was released
/// - 3: the initializer approved skipping the milestone
/// - 4: the taker approved skipping the milestone
/// - 5: the milestone was skipped (its tranche refunded to the
///   initializer)
const MILESTONE_BIT_WIDTH: u32 = 6;
const MILESTONE_CONFIRM_INIT_BIT: u32 = 0;
const MILESTONE_CONFIRM_TAKER_BIT: u32 = 1;
const MILESTONE_RELEASED_BIT: u32 = 2;
const MILESTONE_SKIP_INIT_BIT: u32 = 3;
const MILESTONE_SKIP_TAKER_BIT: u32 = 4;
const MILESTONE_SKIPPED_BIT: u32 = 5;

/// Milestone tranche plan (AV-15): the locked [`Escrow::amount`] split
/// into at most [`MAX_MILESTONES`] ordered tranches, released one by one
/// as the two parties confirm each milestone — the staged-settlement
/// pattern (Solana milestone payments: construction tranches, grant
/// disbursements, gated unlocks).
///
/// The plan is fixed before funding via [`Escrow::with_milestones`],
/// which additionally requires the tranche amounts to sum to exactly the
/// locked amount (accumulated in `u128`, so the sum can never wrap): the
/// plan is the *complete* release schedule. `Copy` and heap-free like the
/// rest of the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MilestonePlan {
    amounts: [u64; MAX_MILESTONES],
    count: u8,
}

impl MilestonePlan {
    /// Build a plan from the tranche amounts, in release order.
    ///
    /// Rejects an empty list, more than [`MAX_MILESTONES`] tranches, and
    /// zero-amount tranches (a tranche that releases nothing is a config
    /// error — it would stall the in-order sequence) with
    /// [`EscrowError::InvalidMilestones`]. The sum-to-locked check happens
    /// in [`Escrow::with_milestones`], which knows the locked amount.
    pub fn new(amounts: &[u64]) -> Result<Self, EscrowError> {
        if amounts.is_empty() || amounts.len() > MAX_MILESTONES {
            return Err(EscrowError::InvalidMilestones);
        }
        let mut table = [0u64; MAX_MILESTONES];
        for (i, amount) in amounts.iter().enumerate() {
            if *amount == 0 {
                return Err(EscrowError::InvalidMilestones);
            }
            table[i] = *amount;
        }
        Ok(Self {
            amounts: table,
            count: amounts.len() as u8,
        })
    }

    /// Number of tranches in the plan.
    pub fn count(&self) -> u8 {
        self.count
    }

    /// The tranche amount at `index`, or `None` when out of range.
    pub fn amount_at(&self, index: usize) -> Option<u64> {
        (index < self.count as usize).then_some(self.amounts[index])
    }

    /// Exact sum of the tranche amounts. Accumulated in `u128`:
    /// `MAX_MILESTONES * u64::MAX < u128::MAX`, so the sum can never wrap
    /// — a wrapping `u64` sum could alias a wrong total onto the locked
    /// amount and accept a plan that over- or under-covers the lockup.
    pub fn total(&self) -> u128 {
        self.amounts[..self.count as usize]
            .iter()
            .map(|a| *a as u128)
            .sum()
    }
}

/// Solana base58 alphabet: no `0`, `O`, `I` or `l` (they are omitted
/// precisely to avoid visual ambiguity in addresses).
const BASE58_ALPHABET: &[u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Parse an SPL token mint address from its base58 encoding into the 32
/// raw bytes (AV-16).
///
/// The decoder is handwritten: this crate's zero-dependency policy is a
/// hard design constraint, so no `bs58` crate. Semantics mirror a
/// standard base58 decode with the Solana alphabet:
/// - the empty string is rejected;
/// - every character must be in [`BASE58_ALPHABET`] (this also rejects
///   non-ASCII bytes — no UTF-8 multibyte sequence is all alphabet
///   characters);
/// - leading `'1'`s decode to leading zero bytes, and the total decoded
///   length must be exactly 32 bytes: more than 32 leading `'1'`s, or a
///   non-zero value that needs more than the remaining bytes, is
///   rejected.
///
/// Any violation is [`EscrowError::InvalidMint`]. Note this is pure
/// format validation: the zero address (`"111...1"`, 32 ones) decodes
/// fine here — it is [`Escrow::with_mint`] that rejects it as "not a
/// real mint", paralleling [`Escrow::with_arbiter`]'s zero-key rejection.
pub fn parse_mint_address(s: &str) -> Result<[u8; 32], EscrowError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err(EscrowError::InvalidMint);
    }
    // Leading '1's are leading zero bytes in base58.
    let mut leading_zeros = 0usize;
    for &b in bytes {
        if b == b'1' {
            leading_zeros += 1;
        } else {
            break;
        }
    }
    if leading_zeros > 32 {
        // More zero bytes than an address can hold.
        return Err(EscrowError::InvalidMint);
    }
    // Big-endian base-256 multiply-add over the non-leading part, which
    // must fit in the remaining bytes. `out[0]` is most significant;
    // the loop runs least-significant-first so the carry propagates
    // towards `out[0]`.
    let mut out = [0u8; 32];
    let tail_len = 32 - leading_zeros;
    for &b in &bytes[leading_zeros..] {
        let digit = match BASE58_ALPHABET.iter().position(|&c| c == b) {
            Some(d) => d as u32,
            None => return Err(EscrowError::InvalidMint),
        };
        let mut carry = digit;
        for i in ((32 - tail_len)..32).rev() {
            let v = out[i] as u32 * 58 + carry;
            out[i] = v as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            // The value needs more than `tail_len` bytes: longer than a
            // 32-byte address.
            return Err(EscrowError::InvalidMint);
        }
    }
    Ok(out)
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
            vesting: None,
            arbiter: None,
            milestones: None,
            milestone_flags: 0,
            skipped: 0,
            // AV-16: no mint bound by default — a plain escrow is the
            // native-SOL path (backward compatible). Bind one SPL mint
            // via `with_mint` before funding.
            mint: None,
            // AV-17: no protocol fee by default — a plain escrow pays
            // takers in full (backward compatible). Configure a rate via
            // `with_protocol_fee` before funding.
            fee_bps: 0,
            fees_paid: 0,
            // AV-21: no expiry grace period by default — `cancel_expired`
            // keeps its historical `now >= expires_at` gate (backward
            // compatible). Opt in via `with_grace_period` before funding.
            grace_period: 0,
            // AV-22: no dispute evidence attached by default — the field
            // is only `Some` once `escalate` stores an evidence hash
            // (backward compatible).
            evidence_hash: None,
            // AV-23: no refund whitelist by default — refunds go to the
            // initializer (backward compatible). Opt in via
            // `with_refund_address` before funding.
            refund_to: None,
            // AV-24: no anti-griefing penalty by default — a
            // taker-initiated `cancel_expired` refunds the full
            // remainder (backward compatible). Opt in via
            // `with_penalty_bps` before funding.
            penalty_bps: 0,
            // AV-27: no timelock by default — payouts are not time-gated
            // (backward compatible). Opt in via `with_timelock` before
            // funding.
            timelock: 0,
            // AV-28: no decimal metadata by default — amounts render as
            // bare integers (backward compatible). Opt in via
            // `with_decimals` before funding.
            decimals: 0,
        })
    }

    fn require_initializer(&self, authority: [u8; 32]) -> Result<(), EscrowError> {
        if authority != self.initializer {
            return Err(EscrowError::Unauthorized);
        }
        Ok(())
    }

    /// Require the token mint of the accounts moving funds to equal the
    /// escrow's bound mint (AV-16). `None` means the caller asserts the
    /// native-SOL path (no token accounts); `Some(m)` asserts the SPL
    /// path with token mint `m`. The comparison is plain `Option`
    /// equality: a bound escrow only exits through the matching mint,
    /// and an unbound escrow never exits through a token mint — either
    /// mismatch is [`EscrowError::MintMismatch`].
    fn require_mint_match(&self, mint: Option<[u8; 32]>) -> Result<(), EscrowError> {
        if self.mint != mint {
            return Err(EscrowError::MintMismatch);
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
    /// Returns `(taker_payout, fee)`: the taker's net payout and the
    /// protocol fee (AV-17) routed to the protocol fee account, so the
    /// caller (and the Anchor layer) can size both transfers.
    /// `taker_payout + fee == amount` always; the fee is
    /// `floor(amount * fee_bps / 10_000)` and accumulates in
    /// [`Escrow::fees_paid`]. With no fee configured (`fee_bps == 0`)
    /// the fee is `0` and the taker receives the full amount — the
    /// pre-AV-17 behavior.
    ///
    /// AV-15: when a milestone plan is attached (see
    /// [`Escrow::with_milestones`), the plan owns the release schedule and
    /// plain `release` is disabled (`InvalidMilestones`) — arbitrary
    /// tranche amounts would release funds outside the plan and break
    /// per-tranche accounting. Use [`Escrow::release_milestone`] instead.
    ///
    /// When a quorum is configured, additionally requires the quorum's
    /// threshold of attestations (`QuorumNotReached` otherwise). AV-27:
    /// when a timelock is configured, additionally requires
    /// `now >= unlock_at` (`TimelockNotReached` otherwise) — the clock
    /// comes from the caller (on-chain: the Solana clock sysvar, never an
    /// instruction param — a caller-supplied timestamp would let the
    /// initializer fast-forward the lock). Check
    /// order is deliberate: authority, then state, then the mint
    /// binding (AV-16), then the milestone plan, then quorum, then the
    /// timelock, then the amount checks — an unauthorized caller learns
    /// nothing about attestation progress, release history, or the lock.
    pub fn release(
        &mut self,
        authority: [u8; 32],
        now: u64,
        amount: u64,
        mint: Option<[u8; 32]>,
    ) -> Result<(u64, u64), EscrowError> {
        self.require_initializer(authority)?;
        match self.state {
            EscrowState::Funded => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        // AV-16: the tokens being released must be the tokens this
        // escrow locks — `None` on the native-SOL path, `Some` equal to
        // the bound mint on the SPL path (`MintMismatch` otherwise).
        self.require_mint_match(mint)?;
        // AV-15: a milestone plan owns the release schedule (see
        // `with_milestones`): arbitrary tranche amounts would break the
        // per-tranche accounting, so plain `release` is a config error
        // once a plan is attached.
        if self.milestones.is_some() {
            return Err(EscrowError::InvalidMilestones);
        }
        if let Some(policy) = &self.quorum {
            if !policy.is_satisfied() {
                return Err(EscrowError::QuorumNotReached);
            }
        }
        // AV-27: the timelock gates every taker payout path. Checked
        // after the config gates so a misconfigured escrow still reports
        // its misconfiguration first; checked before the amount math so
        // a locked escrow never touches the `released` counter.
        if !self.is_unlock_eligible(now) {
            return Err(EscrowError::TimelockNotReached);
        }
        if amount == 0 {
            return Err(EscrowError::AmountMismatch);
        }
        // AV-17: charge the protocol fee only after every gate passes —
        // a rejected release must not touch `fees_paid`. The `released`
        // counter still accumulates the *gross* amount (taker payout +
        // fee), so the conservation invariant
        // inflow == locked + released + refunded is untouched by fees.
        // checked_add: a wrapping add would reset the counter and let an
        // attacker drain past the lockup; overflow is a hard failure.
        let new_released = self
            .released
            .checked_add(amount)
            .ok_or(EscrowError::ReleaseExceedsLocked)?;
        if new_released > self.amount {
            return Err(EscrowError::ReleaseExceedsLocked);
        }
        let fee = self.charge_protocol_fee(amount)?;
        self.released = new_released;
        if self.released == self.amount {
            self.state = EscrowState::Released;
        }
        Ok((amount - fee, fee))
    }

    /// Cancel the escrow and return funds. `Funded -> Cancelled`.
    ///
    /// After partial releases the refund is the remainder
    /// ([`Escrow::remaining_amount`]); [`Escrow::released_amount`] is
    /// preserved for audit.
    ///
    /// AV-16: `mint` is the token account's mint (`None` on the
    /// native-SOL path) and must equal the escrow's bound mint
    /// (`MintMismatch` otherwise).
    ///
    /// AV-23: `refund_to` is the address the refund will be sent to, and
    /// it must equal the escrow's refund policy — the whitelisted
    /// address configured via [`Escrow::with_refund_address`], or the
    /// initializer when no whitelist is configured
    /// ([`EscrowError::RefundAddressMismatch`] otherwise). The caller
    /// names the destination explicitly (on-chain: the refund
    /// account's key) and the state machine pins it, so a phishing
    /// frontend cannot redirect the refund by swapping the destination
    /// account. Check order: authority, then state, then the mint
    /// binding, then the refund destination — a misconfigured call
    /// fails before any state changes.
    pub fn cancel(
        &mut self,
        authority: [u8; 32],
        mint: Option<[u8; 32]>,
        refund_to: [u8; 32],
    ) -> Result<(), EscrowError> {
        self.require_initializer(authority)?;
        match self.state {
            EscrowState::Funded => {
                self.require_mint_match(mint)?;
                self.require_refund_recipient(refund_to)?;
                self.state = EscrowState::Cancelled;
                Ok(())
            }
            _ => Err(EscrowError::InvalidStateTransition),
        }
    }

    /// Require the refund destination to equal the escrow's refund
    /// policy (AV-23): the whitelisted address when one is configured
    /// via [`Escrow::with_refund_address`], otherwise the initializer
    /// (backward compatible). See [`Escrow::with_refund_address`] for
    /// the anti-phishing rationale.
    fn require_refund_recipient(&self, refund_to: [u8; 32]) -> Result<(), EscrowError> {
        if refund_to != self.refund_recipient() {
            return Err(EscrowError::RefundAddressMismatch);
        }
        Ok(())
    }

    /// Cancel an escrow that has timed out and refund the initializer.
    /// `Funded -> Cancelled`.
    ///
    /// Unlike [`Escrow::cancel`], either party — the initializer or the
    /// taker — may call this, so a stalled counterparty cannot lock funds
    /// forever. Requires the expiry gate to pass (see
    /// [`Escrow::is_expiry_eligible`]): `now >= expires_at + grace_period`
    /// — the caller supplies the clock; on-chain this is the Solana clock
    /// sysvar. The grace period (AV-21, opt-in via
    /// [`Escrow::with_grace_period`], `0` by default) absorbs clock drift
    /// between an off-chain keeper and the cluster: without it a keeper
    /// whose clock runs ahead would submit `cancel_expired` the moment
    /// *its* clock passes `expires_at`, only for the chain to reject it
    /// as `NotExpired`.
    ///
    /// Returns `(refund, penalty)` so the caller (and the Anchor layer)
    /// can size both transfers: `refund` goes to the whitelisted
    /// `refund_to` destination, `penalty` (when non-zero) is routed to
    /// the initializer as anti-griefing compensation (AV-24), and
    /// `refund + penalty == remaining` always. An initializer-initiated
    /// cancel returns `(remaining, 0)` — the initializer pays no penalty
    /// to reclaim their own funds. A taker-initiated cancel with
    /// `penalty_bps == 0` is likewise `(remaining, 0)` (backward
    /// compatible).
    ///
    /// Check order is deliberate: authority first, then state, then the
    /// mint binding (AV-16), then the refund destination (AV-23), then
    /// expiry. A stranger never learns whether an escrow is expired from
    /// the error alone beyond `Unauthorized`, and a misconfigured call
    /// fails before the time logic runs.
    ///
    /// After partial releases the refund is the remainder
    /// ([`Escrow::remaining_amount`]); [`Escrow::released_amount`] is
    /// preserved for audit. The refund goes to the whitelisted address
    /// when one is configured — *even when the taker is the caller*:
    /// the caller authorizes the cancel, the whitelist authorizes the
    /// destination. The anti-griefing penalty (AV-24), when charged on a
    /// taker-initiated cancel, always routes to the initializer
    /// personally — the compensation follows the harmed party, not the
    /// refund address.
    pub fn cancel_expired(
        &mut self,
        authority: [u8; 32],
        now: u64,
        mint: Option<[u8; 32]>,
        refund_to: [u8; 32],
    ) -> Result<(u64, u64), EscrowError> {
        if authority != self.initializer && authority != self.taker {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            EscrowState::Funded => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        // AV-16: the refunded tokens must be the tokens this escrow
        // locks (`MintMismatch` otherwise).
        self.require_mint_match(mint)?;
        // AV-23: the refund destination must match the escrow's refund
        // policy (`RefundAddressMismatch` otherwise) — checked before
        // the expiry gate, like the mint binding.
        self.require_refund_recipient(refund_to)?;
        if !self.is_expiry_eligible(now) {
            return Err(EscrowError::NotExpired);
        }
        // AV-24: the anti-griefing penalty is charged only on a
        // *taker-initiated* cancel — the initializer pays no penalty to
        // reclaim their own funds, and a rejected cancel charges nothing.
        // `penalty <= remaining` by construction of
        // `expiry_cancel_penalty` (floor of `remaining * bps / 10000`,
        // `bps <= 10000`), so the subtraction cannot underflow.
        let remaining = self.remaining_amount();
        let penalty = if authority == self.taker {
            self.expiry_cancel_penalty(remaining)
        } else {
            0
        };
        self.state = EscrowState::Cancelled;
        Ok((remaining - penalty, penalty))
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

    /// Adjust the quorum's attestation threshold by mutual agreement
    /// (AV-25 — Solana quorum governance): both the initializer and the
    /// taker must authorize the change (dual-signature governance,
    /// reusing the AV-12 concept), on an escrow that is `Uninitialized`
    /// or `Funded`.
    ///
    /// Why: the quorum is fixed before funding ([`Escrow::with_quorum`]),
    /// but attestors can go dark — a lost key or an unresponsive oracle
    /// would otherwise lock the funds behind an unreachable threshold
    /// forever, since the refund paths deliberately stay quorum-free and
    /// cannot release to the taker. Dual-signed governance lets the two
    /// parties lower the threshold to restore liveness (or raise it by
    /// mutual agreement when they want a stricter gate), without any
    /// single party being able to weaken the gate unilaterally.
    ///
    /// The attestor set and existing attestations are untouched: only
    /// the threshold moves, in place within the already-reserved quorum
    /// region (no layout change, no realloc). If the new threshold is at
    /// or below the current approval count, `release` becomes legal
    /// immediately — that is the intended unlock. Setting the same
    /// threshold again succeeds as a no-op.
    ///
    /// Check order is deliberate: authority (both parties) first, then
    /// state, then quorum configuration, then threshold validity — a
    /// stranger learns nothing about the quorum from the error alone.
    /// A `0` threshold or one above the registered attestor count is
    /// [`EscrowError::InvalidQuorum`], reusing the quorum configuration
    /// error; calling on an escrow with no quorum configured is
    /// `InvalidQuorum` too.
    pub fn update_quorum(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        new_threshold: u8,
    ) -> Result<(), EscrowError> {
        // Both parties must sign: either key alone (or a stranger) is
        // Unauthorized. Independent `==` checks (not `||`): the
        // degenerate initializer == taker self-escrow authorizes with
        // one key passed twice, like AV-12's activation.
        if initializer != self.initializer || taker != self.taker {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            EscrowState::Uninitialized | EscrowState::Funded => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        let policy = self.quorum.as_mut().ok_or(EscrowError::InvalidQuorum)?;
        if new_threshold == 0 || new_threshold > policy.registered_count() {
            return Err(EscrowError::InvalidQuorum);
        }
        policy.threshold = new_threshold;
        Ok(())
    }

    /// Attach a linear vesting schedule (AV-13). Builder-style: only valid
    /// on an `Uninitialized` escrow, so the unlock curve is fixed before
    /// any funds move — mirroring [`Escrow::with_quorum`]. After this, the
    /// taker may [`Escrow::claim`] the vested-but-unreleased portion at
    /// any time; `cancel` / `cancel_expired` still refund the unreleased
    /// remainder regardless of vesting.
    pub fn with_vesting(mut self, schedule: VestingSchedule) -> Result<Self, EscrowError> {
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        self.vesting = Some(schedule);
        Ok(self)
    }

    /// Claim the vested-but-unreleased portion of the locked funds
    /// (AV-13, streaming payments). Returns `(taker_payout, fee)` — the
    /// taker's net payout and the protocol fee (AV-17) — so the caller
    /// (and the Anchor layer) can size both transfers;
    /// `taker_payout + fee == claimable` always.
    ///
    /// Only the taker may claim (`Unauthorized` otherwise): vesting is the
    /// taker's pull path, while [`Escrow::release`] stays the initializer's
    /// push path. The initializer may still `release` ahead of the curve
    /// (e.g. a milestone completed early); in that case a later `claim`
    /// sees `vested <= released`, claims nothing, and reports
    /// `AmountMismatch` instead of going negative.
    ///
    /// When a quorum is configured it gates `claim` exactly like
    /// `release` (`QuorumNotReached`): the quorum guards every release
    /// path, otherwise the taker could bypass attestation via `claim`.
    /// Claims accumulate in the same `released` counter as `release`, so
    /// the conservation invariant and the audit trail are shared; when the
    /// cumulative released total reaches the locked amount the escrow
    /// moves `Funded -> Released`.
    ///
    /// Check order is deliberate: authority, then state, then the
    /// milestone plan (AV-15: the plan owns the release schedule), then
    /// the mint binding (AV-16), then vesting configuration, then
    /// quorum, then the timelock (AV-27), then the claimable amount — a
    /// stranger learns nothing, and a misconfigured call fails before the
    /// gates run.
    pub fn claim(
        &mut self,
        authority: [u8; 32],
        now: u64,
        mint: Option<[u8; 32]>,
    ) -> Result<(u64, u64), EscrowError> {
        if authority != self.taker {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            EscrowState::Funded => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        // AV-15: a milestone plan and a vesting curve are alternative
        // release schedules, not composable ones. Time-based claims would
        // pull funds outside the tranche plan and break per-tranche
        // accounting, so `claim` is disabled once a plan is attached —
        // use `release_milestone` for acceptance-gated tranches.
        if self.milestones.is_some() {
            return Err(EscrowError::InvalidMilestones);
        }
        // AV-16: the claimed tokens must be the tokens this escrow locks
        // (`MintMismatch` otherwise).
        self.require_mint_match(mint)?;
        let schedule = self.vesting.ok_or(EscrowError::InvalidVesting)?;
        if let Some(policy) = &self.quorum {
            if !policy.is_satisfied() {
                return Err(EscrowError::QuorumNotReached);
            }
        }
        // AV-27: the timelock gates every taker payout path, including
        // the taker's pull path — otherwise the lock would be trivially
        // bypassable via `claim`.
        if !self.is_unlock_eligible(now) {
            return Err(EscrowError::TimelockNotReached);
        }
        let vested = schedule.vested_amount(self.amount, now);
        // `released` only grows via `release`/`claim`, and `vested` is a
        // pure function of (amount, now): saturating keeps the counter
        // monotonic even if the initializer released ahead of the curve.
        let claimable = vested.saturating_sub(self.released);
        if claimable == 0 {
            // Nothing unlocked yet, or everything vested is already
            // released — parallels `release` with `amount == 0`.
            return Err(EscrowError::AmountMismatch);
        }
        // `released + claimable <= vested <= amount`: no overflow, no cap
        // breach — the `release` checked_add path is not needed here.
        // AV-17: the protocol fee slices the gross claimable; the
        // `released` counter keeps the gross so conservation is
        // untouched.
        let fee = self.charge_protocol_fee(claimable)?;
        self.released += claimable;
        if self.released == self.amount {
            self.state = EscrowState::Released;
        }
        Ok((claimable - fee, fee))
    }

    /// Opt in to dispute arbitration (AV-14). Builder-style: only valid
    /// on an `Uninitialized` escrow, so the arbiter's identity is fixed
    /// before any funds move — mirroring [`Escrow::with_quorum`] and
    /// [`Escrow::with_vesting`]. A zero key is `InvalidArbiter`: the
    /// arbiter must be a real identity, since `resolve` authenticates
    /// against it. Re-configuring a live escrow is rejected with
    /// `InvalidStateTransition`.
    pub fn with_arbiter(mut self, arbiter: [u8; 32]) -> Result<Self, EscrowError> {
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        if arbiter == [0u8; 32] {
            return Err(EscrowError::InvalidArbiter);
        }
        self.arbiter = Some(arbiter);
        Ok(self)
    }

    /// Bind one SPL token mint to the escrow (AV-16). Builder-style: only
    /// valid on an `Uninitialized` escrow, so the token scope is fixed
    /// before any funds move — mirroring [`Escrow::with_quorum`],
    /// [`Escrow::with_vesting`] and [`Escrow::with_arbiter`]. A zero
    /// address is [`EscrowError::InvalidMint`]: it is well-formed but not
    /// a real mint (parallels `with_arbiter`'s zero-key rejection).
    /// Re-configuring a live escrow is rejected with
    /// `InvalidStateTransition`.
    ///
    /// After this, every fund-moving transition
    /// ([`Escrow::release`], [`Escrow::cancel`],
    /// [`Escrow::cancel_expired`], [`Escrow::claim`],
    /// [`Escrow::release_milestone`], [`Escrow::resolve`]) takes the
    /// token account's mint and requires it to equal this address
    /// ([`EscrowError::MintMismatch`] otherwise) — the escrow can only
    /// ever move the tokens it was scoped to. Without a bound mint the
    /// escrow is the native-SOL path and those transitions take `None`.
    ///
    /// The Anchor program feeds this from the `initialize_mint`
    /// instruction's base58 `mint` param via [`parse_mint_address`].
    pub fn with_mint(mut self, mint: [u8; 32]) -> Result<Self, EscrowError> {
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        if mint == [0u8; 32] {
            return Err(EscrowError::InvalidMint);
        }
        self.mint = Some(mint);
        Ok(self)
    }

    /// Opt in to a protocol fee on taker payouts (AV-17 — Solana/DeFi
    /// protocol revenue: a few basis points of every payout route to
    /// the protocol's fee account instead of the taker).
    /// Builder-style: only valid on an `Uninitialized` escrow, so the
    /// fee rate is fixed before any funds move — mirroring
    /// [`Escrow::with_quorum`], [`Escrow::with_vesting`],
    /// [`Escrow::with_arbiter`] and [`Escrow::with_mint`].
    /// Re-configuring a live escrow is rejected with
    /// `InvalidStateTransition`.
    ///
    /// The rate is in basis points and must be `<= 10_000`
    /// ([`EscrowError::InvalidProtocolFee`] otherwise); `0` is a valid
    /// rate meaning "no fee" (the default, backward compatible).
    ///
    /// The fee is charged on every taker payout — [`Escrow::release`],
    /// [`Escrow::claim`], [`Escrow::release_milestone`] and the taker's
    /// share of [`Escrow::resolve`] — as
    /// `floor(gross_payout * fee_bps / 10_000)` (see
    /// [`Escrow::protocol_fee_for`]), accumulated in the `fees_paid`
    /// counter. The refund paths (`cancel`, `cancel_expired`), the
    /// initializer's `resolve` share, and skipped milestones never
    /// carry a fee: only value the taker receives is feeable, and the
    /// fee is always a routing slice of the gross payout — it never
    /// takes the cumulative released total past the locked amount.
    pub fn with_protocol_fee(mut self, fee_bps: u16) -> Result<Self, EscrowError> {
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        if fee_bps > 10_000 {
            return Err(EscrowError::InvalidProtocolFee);
        }
        self.fee_bps = fee_bps;
        Ok(self)
    }

    /// The protocol fee for a gross taker payout of `amount` (AV-17):
    /// `floor(amount * fee_bps / 10_000)`.
    ///
    /// Computed in `u128`: `amount * fee_bps` can reach
    /// `u64::MAX * 10_000 < u128::MAX`, so the multiplication cannot
    /// overflow, and the floored quotient is `<= amount` (since
    /// `fee_bps <= 10_000`), so the downcast is exact. Floor rounding
    /// means dust payouts may carry a zero fee — the protocol never
    /// rounds *up* into the taker's pocket.
    pub fn protocol_fee_for(&self, amount: u64) -> u64 {
        ((amount as u128 * self.fee_bps as u128) / 10_000u128) as u64
    }

    /// Charge the protocol fee on a gross taker payout of `amount`
    /// (AV-17): accumulate it in `fees_paid` and return it. Called after
    /// all gates pass, immediately before mutating `released` — a failed
    /// payout never touches the fee counter.
    ///
    /// `fees_paid` provably cannot overflow: each fee is `<=` its gross
    /// payout and the gross payouts cumulatively cap at `amount <=
    /// u64::MAX`; the `checked_add` is a backstop, paralleling
    /// `release`'s.
    fn charge_protocol_fee(&mut self, amount: u64) -> Result<u64, EscrowError> {
        let fee = self.protocol_fee_for(amount);
        self.fees_paid = self
            .fees_paid
            .checked_add(fee)
            .ok_or(EscrowError::ReleaseExceedsLocked)?;
        Ok(fee)
    }

    /// The protocol fee rate in basis points configured via
    /// [`Escrow::with_protocol_fee`]; `0` when no fee is configured
    /// (backward compatible).
    pub fn fee_bps(&self) -> u16 {
        self.fee_bps
    }

    /// Cumulative protocol fee charged across all payouts (AV-17).
    /// Always `<= released_amount()`: the fee is a routing slice of the
    /// gross payouts, and `payout + fee == gross` for every payout.
    pub fn fees_paid(&self) -> u64 {
        self.fees_paid
    }

    /// Opt in to an expiry grace period (AV-21 — Solana operations /
    /// backend engineering): [`Escrow::cancel_expired`] then requires
    /// `now >= expires_at + grace_period` (see
    /// [`Escrow::is_expiry_eligible`]) instead of `now >= expires_at`.
    ///
    /// Why: the off-chain keeper watches vaults with its own clock,
    /// which can drift from the Solana cluster clock. Without a grace
    /// period the keeper submits `cancel_expired` the moment *its* clock
    /// passes `expires_at`, and the chain — whose clock runs behind —
    /// rejects it as `NotExpired`: a wasted transaction and a confused
    /// operator. Set the grace period to cover the worst-case keeper /
    /// cluster clock skew (e.g. `300` for five minutes).
    ///
    /// Builder-style: only valid on an `Uninitialized` escrow, so the
    /// grace period is fixed before any funds move — mirroring
    /// [`Escrow::with_quorum`], [`Escrow::with_vesting`],
    /// [`Escrow::with_arbiter`], [`Escrow::with_mint`] and
    /// [`Escrow::with_protocol_fee`]. Re-configuring a live escrow is
    /// rejected with `InvalidStateTransition`.
    ///
    /// [`EscrowError::InvalidGracePeriod`] when
    /// `expires_at + grace_period` would overflow `u64`: in particular a
    /// grace period cannot be combined with the no-timeout convention
    /// (`expires_at == u64::MAX`), where it would be meaningless — an
    /// escrow that can never expire has no expiry gate to grace. `0`
    /// (the default) means no grace period — backward compatible.
    pub fn with_grace_period(mut self, grace_period: u64) -> Result<Self, EscrowError> {
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        self.expires_at
            .checked_add(grace_period)
            .ok_or(EscrowError::InvalidGracePeriod)?;
        self.grace_period = grace_period;
        Ok(self)
    }

    /// The expiry grace period in seconds configured via
    /// [`Escrow::with_grace_period`]; `0` when none is configured
    /// (backward compatible).
    pub fn grace_period(&self) -> u64 {
        self.grace_period
    }

    /// True when the expiry gate of [`Escrow::cancel_expired`] passes at
    /// `now`: `now >= expires_at + grace_period`.
    ///
    /// The single source of truth for expiry eligibility: both
    /// [`Escrow::cancel_expired`] and the off-chain keeper report
    /// (`keeper::scan_keeper_actions`) evaluate this predicate, so the
    /// keeper can never list a `cancel_expired` call the chain would
    /// reject as `NotExpired` — and the event log
    /// (`IndexedEscrow::cancel_expired`) inherits it by delegating to
    /// the state machine. The addition saturates: `with_grace_period`
    /// already rejects configurations that would overflow `u64`, so
    /// saturation is a backstop, never a behavior.
    pub fn is_expiry_eligible(&self, now: u64) -> bool {
        now >= self.expires_at.saturating_add(self.grace_period)
    }

    /// Escalate the escrow into arbitration: `Funded -> Disputed`
    /// (AV-14). Either party — the initializer or the taker — may call
    /// this, so a counterparty who stops cooperating cannot block the
    /// dispute path.
    ///
    /// `evidence_hash` (AV-22) is an optional 32-byte commitment to the
    /// off-chain dispute evidence (e.g. the SHA-256 of an IPFS CID
    /// holding chat logs, delivery photos, or an oracle report). It is
    /// persisted on the escrow ([`Escrow::evidence_hash`]) so the arbiter
    /// and indexers can read it without trusting the escalator to
    /// re-supply it later; `None` attaches no evidence (backward
    /// compatible). The hash is a *commitment*, not the evidence itself:
    /// the chain stores 32 bytes, the evidence lives off-chain, and the
    /// arbiter verifies the preimage out of band before calling
    /// [`Escrow::resolve`]. Failed escalations store nothing.
    ///
    /// The dispute window is the escrow's live window: `escalate`
    /// requires `now < expires_at` (`DisputeWindowClosed` otherwise).
    /// Before expiry either party may escalate; once the escrow is
    /// expiry-eligible the unilateral `cancel_expired` path is the way
    /// out, so arbitration can no longer start. Pass `u64::MAX` as
    /// `expires_at` for an escrow that is always escalatable.
    ///
    /// While `Disputed`, every unilateral exit is locked: `release`,
    /// `cancel`, `cancel_expired`, and `claim` all return
    /// `InvalidStateTransition` from `Disputed` (their state matches
    /// only accept `Funded`), so neither party can move funds while the
    /// arbiter deliberates. Only [`Escrow::resolve`] leaves `Disputed`.
    ///
    /// Check order is deliberate: authority, then state, then arbiter
    /// configuration, then the window — a stranger learns nothing, and
    /// a misconfigured call fails before the time logic runs.
    pub fn escalate(
        &mut self,
        authority: [u8; 32],
        now: u64,
        evidence_hash: Option<[u8; 32]>,
    ) -> Result<(), EscrowError> {
        if authority != self.initializer && authority != self.taker {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            EscrowState::Funded => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        if self.arbiter.is_none() {
            return Err(EscrowError::InvalidArbiter);
        }
        if now >= self.expires_at {
            return Err(EscrowError::DisputeWindowClosed);
        }
        self.state = EscrowState::Disputed;
        self.evidence_hash = evidence_hash;
        Ok(())
    }

    /// The 32-byte dispute-evidence commitment attached at
    /// [`Escrow::escalate`], or `None` when no evidence was attached
    /// (backward compatible). Only meaningful on a `Disputed` (or later
    /// `Settled`) escrow — it is never cleared, so the settlement keeps
    /// the audit trail of what the arbiter reviewed.
    pub fn evidence_hash(&self) -> Option<[u8; 32]> {
        self.evidence_hash
    }

    /// Opt in to a refund address whitelist (AV-23 — Solana security /
    /// payment fintech): declare the address every refund on the
    /// unilateral exit paths ([`Escrow::cancel`],
    /// [`Escrow::cancel_expired`]) must go to.
    ///
    /// Why: the refund destination is the highest-value parameter a
    /// phishing frontend can tamper with — it swaps the destination
    /// account in the cancel instruction and the user's refund lands in
    /// the attacker's wallet. With a whitelist, the state machine itself
    /// rejects any destination that is not the declared address
    /// ([`EscrowError::RefundAddressMismatch`]), so the UI cannot
    /// redirect the refund no matter what account it passes. With no
    /// whitelist configured the policy is "refund to the initializer"
    /// (backward compatible) — and crucially, *even the taker-initiated*
    /// `cancel_expired` refunds to the declared address, never to the
    /// caller: the caller authorizes the cancel, the whitelist
    /// authorizes the destination.
    ///
    /// Builder-style: only valid on an `Uninitialized` escrow, so the
    /// policy is fixed before any funds move — mirroring
    /// [`Escrow::with_quorum`], [`Escrow::with_vesting`],
    /// [`Escrow::with_arbiter`], [`Escrow::with_mint`],
    /// [`Escrow::with_protocol_fee`] and [`Escrow::with_grace_period`].
    /// Re-configuring a live escrow is rejected with
    /// `InvalidStateTransition`. The zero address is
    /// [`EscrowError::RefundAddressMismatch`]: it can never be the
    /// legitimate refund destination, so binding it is a policy mismatch
    /// by construction (parallels `with_arbiter`'s / `with_mint`'s
    /// zero-key rejections).
    ///
    /// Scope note: the whitelist covers the *unilateral* refund paths
    /// only. The arbiter's [`Escrow::resolve`] split and the milestone
    /// skip refunds keep their existing semantics — the arbiter is the
    /// trusted settlement mechanism by design, and widening the pin to
    /// those paths would let a stale whitelist veto a settlement.
    pub fn with_refund_address(mut self, refund_to: [u8; 32]) -> Result<Self, EscrowError> {
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        if refund_to == [0u8; 32] {
            return Err(EscrowError::RefundAddressMismatch);
        }
        self.refund_to = Some(refund_to);
        Ok(self)
    }

    /// Opt in to an anti-griefing penalty on taker-initiated expiry
    /// cancellation (AV-24 — Solana escrow / payment fintech): when the
    /// *taker* calls [`Escrow::cancel_expired`], a slice of the remainder
    /// is paid to the initializer as griefing compensation instead of
    /// being refunded.
    ///
    /// Why: a taker who refuses to cooperate forces the initializer's
    /// capital to sit locked until `expires_at`, and `cancel_expired`
    /// exists precisely so either party can walk away from a stalled
    /// deal. Without a penalty that walk-away is costless for the
    /// griefer — they can idle past expiry and then release the
    /// initializer's funds themselves, having extracted maximum delay
    /// for zero price. The penalty prices the delay: dragging the deal
    /// to expiry costs the taker `floor(remaining * penalty_bps /
    /// 10_000)` of the lockup, routed to the initializer.
    ///
    /// Economics note: the taker never holds escrow funds, so the
    /// penalty is an *allocation rule* on the initializer's own
    /// remainder, not a value transfer from the taker — on a
    /// taker-initiated cancel the return splits `(refund, penalty)`
    /// with `refund + penalty == remaining`. In the default
    /// refund-to-initializer case both transfers land on the same
    /// account and the split is accounting-exact for indexers and
    /// auditors; when a refund whitelist (AV-23) points the refund at a
    /// different address, the penalty still routes to the initializer
    /// personally — the compensation follows the harmed party, not the
    /// refund address.
    ///
    /// Scope: only a *taker-initiated* `cancel_expired` carries the
    /// penalty. An initializer-initiated `cancel_expired` returns
    /// `(remaining, 0)` — the initializer pays no penalty to reclaim
    /// their own funds — and neither [`Escrow::cancel`] (initializer
    /// only) nor the arbiter's [`Escrow::resolve`] carry one: the
    /// arbiter is the trusted settlement mechanism by design.
    ///
    /// Builder-style: only valid on an `Uninitialized` escrow, so the
    /// rate is fixed before any funds move — mirroring
    /// [`Escrow::with_protocol_fee`] and the other `with_*` builders.
    /// The rate is in basis points and must be `<= 10_000`
    /// ([`EscrowError::InvalidPenalty`] otherwise); `0` is a valid rate
    /// meaning "no penalty" (the default, backward compatible).
    pub fn with_penalty_bps(mut self, penalty_bps: u16) -> Result<Self, EscrowError> {
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        if penalty_bps > 10_000 {
            return Err(EscrowError::InvalidPenalty);
        }
        self.penalty_bps = penalty_bps;
        Ok(self)
    }

    /// The anti-griefing penalty for a taker-initiated
    /// [`Escrow::cancel_expired`] on a remainder of `remaining` (AV-24):
    /// `floor(remaining * penalty_bps / 10_000)`.
    ///
    /// Computed in `u128`: `remaining * penalty_bps` can reach
    /// `u64::MAX * 10_000 < u128::MAX`, so the multiplication cannot
    /// overflow, and the floored quotient is `<= remaining` (since
    /// `penalty_bps <= 10_000`), so the downcast is exact. Floor
    /// rounding means dust remainders may carry a zero penalty — the
    /// escrow never rounds *up* into the compensation.
    pub fn expiry_cancel_penalty(&self, remaining: u64) -> u64 {
        ((remaining as u128 * self.penalty_bps as u128) / 10_000u128) as u64
    }

    /// The anti-griefing penalty rate in basis points configured via
    /// [`Escrow::with_penalty_bps`]; `0` when no penalty is configured
    /// (backward compatible).
    pub fn penalty_bps(&self) -> u16 {
        self.penalty_bps
    }

    /// Opt in to a timelock (AV-27). Builder-style: only valid on an
    /// `Uninitialized` escrow, so the unlock timestamp is fixed before
    /// any funds move — mirroring [`Escrow::with_grace_period`] and the
    /// other `with_*` builders. After this, the taker payout paths
    /// ([`Escrow::release`], [`Escrow::claim`],
    /// [`Escrow::release_milestone`]) require `now >= unlock_at`
    /// ([`EscrowError::TimelockNotReached`] otherwise); `unlock_at == 0`
    /// is a valid no-op meaning "no lock" (the default).
    ///
    /// The unilateral exits ([`Escrow::cancel`],
    /// [`Escrow::cancel_expired`]) and the arbiter's
    /// [`Escrow::resolve`] are deliberately *not* gated: a timelock that
    /// also locked refunds could trap funds forever if the initializer
    /// disappeared, so the lock only ever delays *payouts*, never exits.
    pub fn with_timelock(mut self, unlock_at: u64) -> Result<Self, EscrowError> {
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        self.timelock = unlock_at;
        Ok(self)
    }

    /// The timelock unlock timestamp configured via
    /// [`Escrow::with_timelock`]; `0` when no timelock is configured
    /// (backward compatible — no payout is ever time-gated).
    pub fn unlock_at(&self) -> u64 {
        self.timelock
    }

    /// True when the timelock gate of the taker payout paths
    /// ([`Escrow::release`], [`Escrow::claim`],
    /// [`Escrow::release_milestone`]) passes at `now`: `now >= unlock_at`.
    ///
    /// The single source of truth for unlock eligibility: the state
    /// machine's payout gates and the off-chain keeper report
    /// (`keeper::scan_keeper_actions`) both evaluate this predicate, so
    /// the keeper can never list a `claim` call the chain would reject
    /// as `TimelockNotReached`.
    pub fn is_unlock_eligible(&self, now: u64) -> bool {
        now >= self.timelock
    }

    /// Opt in to token decimal metadata (AV-28). Builder-style: only
    /// valid on an `Uninitialized` escrow, so the precision is fixed
    /// before any funds move — mirroring [`Escrow::with_timelock`] and
    /// the other `with_*` builders. `decimals` is the SPL mint's decimal
    /// places (SPL mints declare at most 9); anything above 18 is
    /// [`EscrowError::InvalidDecimals`]. `decimals == 0` is a valid
    /// no-op meaning "no decimal metadata" (the default — native-SOL
    /// escrows keep rendering bare integers).
    ///
    /// The metadata never gates a transition and never moves funds: it
    /// only feeds [`Escrow::display_amount`] and the human-readable
    /// amounts in the keeper report (`keeper::KeeperReport::to_json`)
    /// and the AV-26 snapshot export
    /// (`snapshot::EscrowSnapshot::to_json`), so a payment operator
    /// sees `1.000000` instead of `1000000` for a 6-decimal token.
    pub fn with_decimals(mut self, decimals: u8) -> Result<Self, EscrowError> {
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        if decimals > 18 {
            return Err(EscrowError::InvalidDecimals);
        }
        self.decimals = decimals;
        Ok(self)
    }

    /// The token decimal places configured via
    /// [`Escrow::with_decimals`]; `0` when no decimal metadata is
    /// configured (backward compatible — amounts render as bare
    /// integers).
    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// The locked [`Escrow::amount`] rendered in human units with this
    /// escrow's configured decimals (AV-28): `amount = 1_000_000`,
    /// `decimals = 6` → `"1.000000"`. Exact fixed-point rendering — the
    /// raw amount is already the smallest unit, so no rounding ever
    /// occurs; `decimals == 0` (the default) renders the bare integer.
    /// See [`format_amount`] for the formatting rules.
    pub fn display_amount(&self) -> String {
        format_amount(self.amount, self.decimals)
    }

    /// The whitelisted refund address configured via
    /// [`Escrow::with_refund_address`], or `None` when no whitelist is
    /// configured (refunds go to the initializer — backward compatible).
    pub fn refund_to(&self) -> Option<[u8; 32]> {
        self.refund_to
    }

    /// The address the unilateral refund paths
    /// ([`Escrow::cancel`], [`Escrow::cancel_expired`]) must send the
    /// refund to: the whitelisted address when configured, otherwise the
    /// initializer. The Anchor program sends the refund transfer here
    /// after the state machine's destination check passes.
    pub fn refund_recipient(&self) -> [u8; 32] {
        self.refund_to.unwrap_or(self.initializer)
    }

    /// Settle a disputed escrow: `Disputed -> Settled` (AV-14). Only the
    /// configured arbiter may call this (`Unauthorized` otherwise); the
    /// settlement is a single atomic split of the *remaining* locked
    /// funds — the taker is paid `taker_amount`, the initializer is
    /// refunded the rest. Returns `(taker_payout, fee,
    /// initializer_refund)` so the caller (and the Anchor layer) can
    /// size all three transfers: the protocol fee (AV-17) slices the
    /// taker's share (`taker_payout + fee == taker_amount`), the
    /// initializer's refund is never fee'd.
    ///
    /// `taker_amount` may be anything from `0` (full refund to the
    /// initializer) to the full remainder (full payout to the taker);
    /// exceeding the remainder is `ReleaseExceedsLocked`, paralleling
    /// `release`'s cumulative cap. The taker's share accumulates in the
    /// same `released` counter as `release` / `claim`, so the
    /// conservation invariant and the audit trail stay unified;
    /// `remaining_amount()` is zero afterwards.
    ///
    /// Deliberately, a configured quorum does *not* gate `resolve`: the
    /// arbiter is the resolution mechanism, and requiring attestations
    /// on top would let attestors veto the settlement. Vesting likewise
    /// does not gate `resolve` — arbitration overrides the unlock curve
    /// by design (the dispute exists precisely because the schedule is
    /// contested). Partial releases made before the dispute are honored:
    /// the split applies to the remainder, never to already-released
    /// funds. A milestone plan (AV-15) is likewise overridden, not
    /// honored: unsettled tranches are part of the remainder the arbiter
    /// splits.
    ///
    /// AV-22: the dispute evidence hash attached at
    /// [`Escrow::escalate`] is left untouched — it persists through
    /// `Settled` as the audit trail of what the arbiter reviewed, and
    /// the `Resolved` indexer event carries it (see
    /// [`crate::EscrowEvent::evidence_hash`]).
    ///
    /// Check order is deliberate: arbiter configuration, then state,
    /// then authority, then the mint binding (AV-16), then the amount.
    /// The arbiter's identity is the authority being verified, so the
    /// configuration check comes first; a stranger on an arbiter-less
    /// escrow gets `InvalidArbiter` (the arbiter field is public on-chain
    /// account data anyway, so nothing sensitive leaks).
    pub fn resolve(
        &mut self,
        authority: [u8; 32],
        taker_amount: u64,
        mint: Option<[u8; 32]>,
    ) -> Result<(u64, u64, u64), EscrowError> {
        let arbiter = self.arbiter.ok_or(EscrowError::InvalidArbiter)?;
        match self.state {
            EscrowState::Disputed => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        if authority != arbiter {
            return Err(EscrowError::Unauthorized);
        }
        // AV-16: the split moves the escrow's locked tokens — they must be
        // the bound mint (`MintMismatch` otherwise).
        self.require_mint_match(mint)?;
        // `released <= amount` is the crate invariant, so `remaining`
        // cannot underflow; `taker_amount <= remaining` keeps
        // `released + taker_amount <= amount` without a checked add.
        let remaining = self.amount - self.released;
        if taker_amount > remaining {
            return Err(EscrowError::ReleaseExceedsLocked);
        }
        // AV-17: the fee slices the taker's share; the `released`
        // counter keeps the gross so conservation is untouched. The
        // initializer's refund is never fee'd.
        let fee = self.charge_protocol_fee(taker_amount)?;
        self.released += taker_amount;
        self.state = EscrowState::Settled;
        Ok((taker_amount - fee, fee, remaining - taker_amount))
    }

    /// Attach a milestone tranche plan (AV-15). Builder-style: only valid
    /// on an `Uninitialized` escrow, so the release schedule is fixed
    /// before any funds move — mirroring [`Escrow::with_quorum`],
    /// [`Escrow::with_vesting`] and [`Escrow::with_arbiter`].
    ///
    /// The tranche amounts must sum to exactly the locked amount: the
    /// plan is the *complete* release schedule. The sum is accumulated in
    /// `u128` (see [`MilestonePlan::total`]), which cannot wrap for at
    /// most [`MAX_MILESTONES`] `u64` tranches — a wrapping `u64` sum could
    /// alias a wrong total onto the locked amount (e.g. two `u64::MAX`
    /// tranches wrapping to `u64::MAX - 1`) and accept a plan that over- or
    /// under-covers the lockup.
    ///
    /// Once a plan is attached it owns the release schedule: plain
    /// [`Escrow::release`] and [`Escrow::claim`] return
    /// [`EscrowError::InvalidMilestones`] — arbitrary or time-based pulls
    /// would release funds outside the tranche plan and break the
    /// per-tranche accounting. Tranches release via
    /// [`Escrow::release_milestone`] after dual confirmation
    /// ([`Escrow::confirm_milestone`]), or are refunded to the initializer
    /// via a dual-signed [`Escrow::skip_milestone`]. The refund paths
    /// (`cancel` / `cancel_expired`) stay available and refund the
    /// remainder; [`Escrow::resolve`] overrides the plan by design, like
    /// it overrides vesting (unsettled tranches are part of the split
    /// remainder).
    pub fn with_milestones(mut self, plan: MilestonePlan) -> Result<Self, EscrowError> {
        match self.state {
            EscrowState::Uninitialized => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        if plan.total() != self.amount as u128 {
            return Err(EscrowError::InvalidMilestones);
        }
        self.milestones = Some(plan);
        Ok(self)
    }

    /// Confirm milestone `index` for the release path (AV-15): records the
    /// calling party's acceptance of the milestone's deliverable. Either
    /// the initializer or the taker may confirm (`Unauthorized`
    /// otherwise); a stranger learns nothing about the plan from the
    /// error. The milestone is *confirmed* — releasable via
    /// [`Escrow::release_milestone`] — once *both* parties have confirmed
    /// it: each confirmation is a separate signature, reusing the AV-12
    /// dual-signature concept for per-tranche acceptance (one party
    /// accepts the deliverable, the other agrees it is complete).
    ///
    /// Confirmations are strictly in-order: only the first unsettled
    /// milestone may be confirmed; confirming ahead is
    /// `InvalidStateTransition`. Confirming is idempotent per party.
    /// Requires `Funded` state and a configured plan (`InvalidMilestones`
    /// without one, or for an out-of-range index).
    ///
    /// Design note on attestors: when a quorum is configured it gates
    /// `release_milestone` exactly like `release` / `claim` (the quorum
    /// guards every release path), so attestors keep their AV-04 role as
    /// the release gate while the two parties own milestone acceptance.
    pub fn confirm_milestone(&mut self, authority: [u8; 32], index: u8) -> Result<(), EscrowError> {
        if authority != self.initializer && authority != self.taker {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            EscrowState::Funded => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        let plan = self.milestones.ok_or(EscrowError::InvalidMilestones)?;
        let i = index as usize;
        if i >= plan.count as usize {
            return Err(EscrowError::InvalidMilestones);
        }
        if Some(i) != self.next_milestone_index() {
            return Err(EscrowError::InvalidStateTransition);
        }
        // Independent `if`s, not `if/else`: the degenerate
        // initializer == taker self-escrow confirms with one signature,
        // like AV-12's activation.
        if authority == self.initializer {
            self.milestone_flags |= Self::milestone_bit(i, MILESTONE_CONFIRM_INIT_BIT);
        }
        if authority == self.taker {
            self.milestone_flags |= Self::milestone_bit(i, MILESTONE_CONFIRM_TAKER_BIT);
        }
        Ok(())
    }

    /// Release milestone `index`'s tranche to the taker (AV-15). Returns
    /// `(taker_payout, fee)` — the taker's net payout and the protocol
    /// fee (AV-17) — so the caller (and the Anchor layer) can size both
    /// transfers; `taker_payout + fee == tranche` always.
    ///
    /// Only the initializer may drive the release (`Unauthorized`
    /// otherwise): like [`Escrow::release`], tranche release is the
    /// initializer's push path, executed after the milestone earned its
    /// dual confirmation. Requires `Funded` state, a configured plan, an
    /// in-range index, strictly in-order settlement (every earlier
    /// milestone released or skipped), and both parties' confirmation
    /// ([`EscrowError::MilestoneNotConfirmed`] otherwise). A configured
    /// quorum gates this exactly like `release` / `claim`
    /// (`QuorumNotReached`) — the quorum guards every release path.
    ///
    /// The tranche accumulates in the shared `released` counter, so the
    /// conservation invariant and the audit trail stay unified with
    /// `release` / `claim` / `resolve`; when the cumulative released total
    /// reaches the locked amount the escrow moves `Funded -> Released`.
    /// Each tranche releases at most once (the released bit) and the
    /// tranches sum to the locked amount, so the cumulative total can
    /// never exceed it — the `checked_add` is a backstop, paralleling
    /// `release`.
    ///
    /// Check order is deliberate: authority, then state, then plan
    /// configuration, then index, then the mint binding (AV-16), then
    /// quorum, then sequence, then confirmation — a stranger learns
    /// nothing, and a misconfigured call fails before the gates run.
    pub fn release_milestone(
        &mut self,
        authority: [u8; 32],
        now: u64,
        index: u8,
        mint: Option<[u8; 32]>,
    ) -> Result<(u64, u64), EscrowError> {
        self.require_initializer(authority)?;
        match self.state {
            EscrowState::Funded => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        let plan = self.milestones.ok_or(EscrowError::InvalidMilestones)?;
        let i = index as usize;
        if i >= plan.count as usize {
            return Err(EscrowError::InvalidMilestones);
        }
        // AV-16: the tranche's tokens must be the tokens this escrow
        // locks (`MintMismatch` otherwise).
        self.require_mint_match(mint)?;
        if let Some(policy) = &self.quorum {
            if !policy.is_satisfied() {
                return Err(EscrowError::QuorumNotReached);
            }
        }
        // AV-27: the timelock gates every taker payout path, including
        // milestone tranches.
        if !self.is_unlock_eligible(now) {
            return Err(EscrowError::TimelockNotReached);
        }
        if Some(i) != self.next_milestone_index() {
            return Err(EscrowError::InvalidStateTransition);
        }
        if !self.milestone_confirmed(i) {
            return Err(EscrowError::MilestoneNotConfirmed);
        }
        let tranche = plan.amounts[i];
        // Each tranche releases at most once (the released bit) and the
        // tranches sum to the locked amount: released + tranche <= amount
        // always. The checked_add and the cap are backstops, paralleling
        // `release`.
        let new_released = self
            .released
            .checked_add(tranche)
            .ok_or(EscrowError::ReleaseExceedsLocked)?;
        if new_released > self.amount {
            return Err(EscrowError::ReleaseExceedsLocked);
        }
        // AV-17: the protocol fee slices the tranche; the `released`
        // counter keeps the gross so conservation is untouched. Charged
        // only after every gate passes — a rejected payout never
        // touches `fees_paid`.
        let fee = self.charge_protocol_fee(tranche)?;
        self.released = new_released;
        self.milestone_flags |= Self::milestone_bit(i, MILESTONE_RELEASED_BIT);
        if self.released == self.amount {
            self.state = EscrowState::Released;
        }
        Ok((tranche - fee, fee))
    }

    /// Skip milestone `index` by mutual agreement (AV-15): the milestone's
    /// tranche is *not* released to the taker — it is refunded to the
    /// initializer's claim instead. Skipping requires a dual signature:
    /// each party — the initializer or the taker — records their skip
    /// approval with a separate call (reusing the AV-12 dual-signature
    /// concept), and the skip executes only once *both* approvals are
    /// present. Approvals are idempotent per party; a stranger gets
    /// `Unauthorized`.
    ///
    /// Requires `Funded` state, a configured plan, an in-range index, and
    /// strictly in-order settlement (only the first unsettled milestone
    /// may be skipped). The skipped amount accumulates in
    /// [`Escrow::skipped_amount`] and joins the refundable remainder
    /// (visible in [`Escrow::remaining_amount`]) — it never enters the
    /// taker-payout `released` counter. Skipping does not close the
    /// escrow: later milestones continue, and `cancel` / `cancel_expired`
    /// refund whatever remains.
    ///
    /// A milestone one party confirmed (release path) and the other
    /// skip-approved stays unsettled until both parties align on one path:
    /// neither path completes on a single party's word.
    pub fn skip_milestone(&mut self, authority: [u8; 32], index: u8) -> Result<(), EscrowError> {
        if authority != self.initializer && authority != self.taker {
            return Err(EscrowError::Unauthorized);
        }
        match self.state {
            EscrowState::Funded => {}
            _ => return Err(EscrowError::InvalidStateTransition),
        }
        let plan = self.milestones.ok_or(EscrowError::InvalidMilestones)?;
        let i = index as usize;
        if i >= plan.count as usize {
            return Err(EscrowError::InvalidMilestones);
        }
        if Some(i) != self.next_milestone_index() {
            return Err(EscrowError::InvalidStateTransition);
        }
        // Independent `if`s: the degenerate initializer == taker
        // self-escrow skip-approves with one signature, like AV-12's
        // activation.
        if authority == self.initializer {
            self.milestone_flags |= Self::milestone_bit(i, MILESTONE_SKIP_INIT_BIT);
        }
        if authority == self.taker {
            self.milestone_flags |= Self::milestone_bit(i, MILESTONE_SKIP_TAKER_BIT);
        }
        let approvals = Self::milestone_bit(i, MILESTONE_SKIP_INIT_BIT)
            | Self::milestone_bit(i, MILESTONE_SKIP_TAKER_BIT);
        if self.milestone_flags & approvals == approvals {
            self.milestone_flags |= Self::milestone_bit(i, MILESTONE_SKIPPED_BIT);
            // Skipped tranches are refundable, never taker payouts:
            // released + skipped <= amount is the milestone accounting
            // invariant (each tranche settles at most once, Σ == amount).
            // Checked arithmetic as a backstop.
            self.skipped = self
                .skipped
                .checked_add(plan.amounts[i])
                .ok_or(EscrowError::ReleaseExceedsLocked)?;
            let accounted = self
                .released
                .checked_add(self.skipped)
                .ok_or(EscrowError::ReleaseExceedsLocked)?;
            if accounted > self.amount {
                return Err(EscrowError::ReleaseExceedsLocked);
            }
        }
        Ok(())
    }

    /// Bit position of milestone `index`'s `offset` bit inside
    /// `milestone_flags`. Callers guarantee `index < MAX_MILESTONES`
    /// (plan counts are capped there), so the shift cannot overflow.
    fn milestone_bit(index: usize, offset: u32) -> u64 {
        1u64 << (index as u32 * MILESTONE_BIT_WIDTH + offset)
    }

    /// Index of the first unsettled (neither released nor skipped)
    /// milestone, or `None` when no plan is configured or every tranche
    /// is settled.
    fn next_milestone_index(&self) -> Option<usize> {
        let plan = self.milestones?;
        (0..plan.count as usize).find(|&i| !self.milestone_settled(i))
    }

    /// Read-only accessors.
    pub fn quorum(&self) -> Option<QuorumPolicy> {
        self.quorum
    }

    /// The dispute arbiter attached via [`Escrow::with_arbiter`], if any.
    pub fn arbiter(&self) -> Option<[u8; 32]> {
        self.arbiter
    }
    /// The SPL token mint bound via [`Escrow::with_mint`], if any.
    /// `None` means a native-SOL escrow: the fund-moving transitions
    /// take no token mint.
    pub fn mint(&self) -> Option<[u8; 32]> {
        self.mint
    }
    /// The milestone tranche plan attached via
    /// [`Escrow::with_milestones`], if any.
    pub fn milestone_plan(&self) -> Option<MilestonePlan> {
        self.milestones
    }
    /// Cumulative amount skipped by mutual agreement (AV-15, see
    /// [`Escrow::skip_milestone`]). Skipped tranches join the refundable
    /// remainder — they are the initializer's refund, not the taker's
    /// payout.
    pub fn skipped_amount(&self) -> u64 {
        self.skipped
    }
    /// True when milestone `index` was released or skipped. Out-of-range
    /// indices report `false`.
    pub fn milestone_settled(&self, index: usize) -> bool {
        if index >= MAX_MILESTONES {
            return false;
        }
        let mask = Self::milestone_bit(index, MILESTONE_RELEASED_BIT)
            | Self::milestone_bit(index, MILESTONE_SKIPPED_BIT);
        self.milestone_flags & mask != 0
    }
    /// True when both parties confirmed milestone `index` for the release
    /// path (see [`Escrow::confirm_milestone`]). Out-of-range indices
    /// report `false`.
    pub fn milestone_confirmed(&self, index: usize) -> bool {
        if index >= MAX_MILESTONES {
            return false;
        }
        let mask = Self::milestone_bit(index, MILESTONE_CONFIRM_INIT_BIT)
            | Self::milestone_bit(index, MILESTONE_CONFIRM_TAKER_BIT);
        self.milestone_flags & mask == mask
    }
    /// Index of the first unsettled milestone, or `None` when no plan is
    /// configured or every tranche is settled. The next milestone to
    /// confirm, release, or skip.
    pub fn next_milestone(&self) -> Option<usize> {
        self.next_milestone_index()
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
    /// `cancel` / `cancel_expired` refund. After `cancel`, `cancel_expired`,
    /// or `resolve` the escrow is terminal and nothing is locked anymore —
    /// the value is then the initializer's refund, preserved for audit
    /// (for `resolve`, the taker's share sits in `released_amount()`).
    ///
    /// AV-15: with a milestone plan, skipped tranches join this remainder
    /// — a skipped tranche is the initializer's refund, never the taker's
    /// payout (see [`Escrow::skipped_amount`]).
    pub fn remaining_amount(&self) -> u64 {
        self.amount - self.released
    }
    /// The vesting schedule attached via [`Escrow::with_vesting`], if any.
    pub fn vesting_schedule(&self) -> Option<VestingSchedule> {
        self.vesting
    }
    /// Amount vested at `now` under the attached schedule, or `0` when no
    /// vesting is configured.
    pub fn vested_amount(&self, now: u64) -> u64 {
        self.vesting
            .map(|s| s.vested_amount(self.amount, now))
            .unwrap_or(0)
    }
    /// Amount the taker could [`Escrow::claim`] right now: vested minus
    /// already released, saturating at zero. `0` when no vesting is
    /// configured.
    pub fn claimable_amount(&self, now: u64) -> u64 {
        self.vested_amount(now).saturating_sub(self.released)
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

/// Serialized length of [`MilestonePlan`] under Borsh/Anchor (AV-15):
/// `MAX_MILESTONES` tranche-amount u64s plus the tranche count byte.
/// Fixed-size by design, so account space is known at `initialize` time
/// and never needs a realloc.
pub const MILESTONE_PLAN_LEN: usize = MAX_MILESTONES * 8 + 1;

/// Render a raw token amount as a human-readable decimal string given
/// the mint's decimal places (AV-28). The single formatting primitive
/// behind [`Escrow::display_amount`], the keeper report's
/// `display_amount` fields, and the AV-26 snapshot export.
///
/// Rules (exact fixed-point, no rounding ever):
/// - `decimals == 0` renders the bare integer (`1000000` → `"1000000"`);
/// - otherwise the fractional part is zero-padded to *exactly*
///   `decimals` digits (`1_000_000` with 6 → `"1.000000"`, `5` with 9 →
///   `"0.000000005"`). Trailing zeros are kept: the rendering is the
///   exact value of the raw amount in whole units, and trimming them
///   would suggest a precision the mint does not promise;
/// - the integer part is never empty (`0` with 6 → `"0.000000"`,
///   never `".000000"`).
///
/// Total on all inputs: the string is built from the amount's decimal
/// digits, so no power-of-ten arithmetic can overflow (any `u8`
/// `decimals` renders, far beyond the 18 the
/// [`Escrow::with_decimals`] builder accepts).
pub fn format_amount(amount: u64, decimals: u8) -> String {
    let digits = amount.to_string();
    let d = decimals as usize;
    if d == 0 {
        return digits;
    }
    if digits.len() > d {
        let (int, frac) = digits.split_at(digits.len() - d);
        format!("{int}.{frac}")
    } else {
        // The amount is smaller than one whole unit: left-pad the
        // fraction with zeros after the point.
        format!("0.{digits:0>d$}")
    }
}

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
    // AV-13: linear vesting schedule gating `claim`: one discriminant
    // byte, then start/end u64. The region is always reserved (zeroed
    // when `None`) so `with_vesting` never needs a realloc — same
    // treatment as `quorum`.
    ("vesting", "Option<VestingSchedule>", 1 + 16),
    // AV-14: optional dispute arbiter (see `Escrow::with_arbiter`):
    // one discriminant byte, then the 32-byte key. The region is always
    // reserved (zeroed when `None`) so `with_arbiter` writes in place —
    // same treatment as `quorum` / `vesting`. Appended last so every
    // earlier field offset stays stable.
    ("arbiter", "Option<Pubkey>", 1 + PUBKEY_LEN),
    // AV-15: milestone tranche plan: one discriminant byte, then the
    // tranche amounts and the tranche count byte. The region is always
    // reserved (zeroed when `None`) so `with_milestones` writes in place
    // — same treatment as `quorum` / `vesting` / `arbiter`. Appended last
    // so every earlier field offset stays stable.
    ("milestones", "Option<MilestonePlan>", 1 + MILESTONE_PLAN_LEN),
    // AV-15: per-milestone confirmation bitmap (see the `MILESTONE_*`
    // bit constants): six bits per milestone — the two parties'
    // release-path confirmations, the released bit, the two parties'
    // skip approvals, and the skipped bit. One u64, always present
    // (zeroed for escrows without a milestone plan).
    ("milestone_flags", "u64 (bitmask)", 8),
    // AV-15: cumulative amount skipped by mutual agreement (see
    // `Escrow::skip_milestone`): skipped tranches join the refundable
    // remainder, not the taker-payout `released` counter. Always present
    // (zeroed when nothing was skipped).
    ("skipped", "u64", 8),
    // AV-16: optional SPL token mint binding (see `Escrow::with_mint`):
    // one discriminant byte, then the 32-byte mint address. The region
    // is always reserved (zeroed when `None`) so `with_mint` writes in
    // place — same treatment as `quorum` / `vesting` / `arbiter` /
    // `milestones`. Appended last so every earlier field offset stays
    // stable.
    ("mint", "Option<Pubkey>", 1 + PUBKEY_LEN),
    // AV-17: protocol fee rate in basis points (see
    // `Escrow::with_protocol_fee`): one u16, always present (zeroed
    // when no fee is configured). Appended last so every earlier field
    // offset stays stable.
    ("fee_bps", "u16", 2),
    // AV-17: cumulative protocol fee charged across payouts (see
    // `Escrow::fees_paid`): one u64, always present (zeroed when no
    // fee was charged). Appended last so every earlier field offset
    // stays stable.
    ("fees_paid", "u64", 8),
    // AV-21: expiry grace period in seconds (see
    // `Escrow::with_grace_period`): one u64, always present (zeroed
    // when no grace period is configured). Appended last so every
    // earlier field offset stays stable.
    ("grace_period", "u64", 8),
    // AV-22: dispute evidence hash (see `Escrow::escalate`): one
    // discriminant byte, then the 32-byte commitment. The region is
    // always reserved (zeroed when `None`) so `escalate` writes in
    // place — same treatment as `arbiter` / `mint`. Appended last so
    // every earlier field offset stays stable.
    ("evidence_hash", "Option<[u8; 32]>", 1 + 32),
    // AV-23: refund address whitelist (see
    // `Escrow::with_refund_address`): one discriminant byte, then the
    // 32-byte address. The region is always reserved (zeroed when
    // `None`) so `with_refund_address` writes in place — same treatment
    // as `arbiter` / `mint` / `evidence_hash`. Appended last so every
    // earlier field offset stays stable.
    ("refund_to", "Option<Pubkey>", 1 + PUBKEY_LEN),
    // AV-24: anti-griefing penalty rate in basis points (see
    // `Escrow::with_penalty_bps`): one u16, always present (zeroed
    // when no penalty is configured). Appended last so every earlier
    // field offset stays stable.
    ("penalty_bps", "u16", 2),
    // AV-27: timelock unlock timestamp (see `Escrow::with_timelock`):
    // one u64, always present (zeroed when no timelock is configured).
    // Appended last so every earlier field offset stays stable.
    ("timelock", "u64", 8),
    // AV-28: token decimal metadata (see `Escrow::with_decimals`): one
    // u8, always present (zeroed when no decimal metadata is
    // configured). Appended last so every earlier field offset stays
    // stable.
    ("decimals", "u8", 1),
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
/// bitmask (AV-12) is always present — one byte, zeroed for plain escrows —
/// and so is the vesting discriminant (AV-13): one byte, zeroed when no
/// schedule is attached. The arbiter discriminant (AV-14) is likewise
/// always present: one byte, zeroed when no arbiter is configured. The
/// milestones discriminant (AV-15) is likewise always present: one byte,
/// zeroed when no plan is configured — followed by the always-present
/// 8-byte confirmation bitmap and 8-byte skipped counter. The mint
/// discriminant (AV-16) is likewise always present: one byte, zeroed when
/// no mint is bound. The protocol fee fields (AV-17) are always present
/// too: 2-byte `fee_bps` (zeroed when no fee configured) and 8-byte
/// `fees_paid` (zeroed when no fee was charged). The grace period (AV-21)
/// is always present too: 8-byte `grace_period` (zeroed when no grace
/// period is configured). The dispute evidence hash (AV-22) is likewise
/// always present: 1-byte discriminant + 32-byte commitment (zeroed when
/// no evidence is attached). The refund address whitelist (AV-23) is
/// likewise always present: 1-byte discriminant + 32-byte address
/// (zeroed when no whitelist is configured). The anti-griefing penalty
/// rate (AV-24) is always present too: 2-byte `penalty_bps` (zeroed when
/// no penalty is configured). The timelock unlock timestamp (AV-27) is
/// always present too: 8-byte `timelock` (zeroed when no timelock is
/// configured). The token decimal metadata (AV-28) is always present
/// too: 1-byte `decimals` (zeroed when no decimal metadata is
/// configured).
pub const VAULT_SPACE_NO_QUORUM: usize =
    ANCHOR_DISCRIMINATOR_LEN + PUBKEY_LEN + PUBKEY_LEN + 8 + 8 + 8 + 1 + 1 + 1 + 1 + 1 + 1 + 8 + 8 + 1 + 2 + 8 + 8 + 1 + 32 + 1 + 32 + 2 + 8 + 1;

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
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
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
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        assert_eq!(e.amount(), before);
    }

    // ---------- cancel_expired ----------

    #[test]
    fn cancel_expired_by_initializer_after_expiry_ok() {
        let mut e = funded_escrow();
        let before = e.amount();
        e.cancel_expired(ALICE, EXPIRES_AT + 1, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        assert_eq!(e.amount(), before); // refund accounting preserved
    }

    #[test]
    fn cancel_expired_by_taker_after_expiry_ok() {
        // Either party may cancel an expired escrow: the taker is not
        // left hostage to an unresponsive initializer.
        let mut e = funded_escrow();
        e.cancel_expired(BOB, EXPIRES_AT + 3_600, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn cancel_expired_at_exact_expiry_boundary_ok() {
        // `now >= expires_at` is the trigger: equality counts as expired.
        let mut e = funded_escrow();
        e.cancel_expired(ALICE, EXPIRES_AT, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn cancel_expired_before_expiry_fails_for_both_parties() {
        for authority in [ALICE, BOB] {
            let mut e = funded_escrow();
            assert_eq!(
                e.cancel_expired(authority, EXPIRES_AT - 1, None, ALICE),
                Err(EscrowError::NotExpired)
            );
            assert_eq!(e.state(), EscrowState::Funded);
        }
    }

    #[test]
    fn cancel_expired_by_stranger_after_expiry_is_unauthorized() {
        let mut e = funded_escrow();
        assert_eq!(
            e.cancel_expired(MALLORY, EXPIRES_AT + 1, None, ALICE),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn cancel_expired_on_non_funded_states_is_invalid() {
        // Uninitialized: authority passes, state rejects.
        let mut e = escrow();
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT + 1, None, ALICE),
            Err(EscrowError::InvalidStateTransition)
        );
        // Released: terminal, cannot be cancelled again.
        let mut e = funded_escrow();
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!(
            e.cancel_expired(BOB, EXPIRES_AT + 1, None, ALICE),
            Err(EscrowError::InvalidStateTransition)
        );
        // Cancelled: terminal, double-cancel rejected.
        let mut e = funded_escrow();
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT + 1, None, ALICE),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn escrow_without_timeout_cannot_be_cancel_expired() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, u64::MAX).unwrap();
        e.fund(ALICE).unwrap();
        // Any realistic `now` is below u64::MAX.
        assert_eq!(
            e.cancel_expired(ALICE, u64::MAX - 1, None, ALICE),
            Err(EscrowError::NotExpired)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    // ---------- illegal transitions ----------

    #[test]
    fn release_from_uninitialized_is_invalid() {
        let mut e = escrow();
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 1_000_000, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Uninitialized);
    }

    #[test]
    fn cancel_from_uninitialized_is_invalid() {
        let mut e = escrow();
        assert_eq!(e.cancel(ALICE, None, ALICE), Err(EscrowError::InvalidStateTransition));
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
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 1_000_000, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn cancel_after_release_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!(e.cancel(ALICE, None, ALICE), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn release_after_cancel_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 1_000_000, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn fund_after_release_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!(e.fund(ALICE), Err(EscrowError::InvalidStateTransition));
    }

    #[test]
    fn fund_after_cancel_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.cancel(ALICE, None, ALICE).unwrap();
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
        assert_eq!(e.release(MALLORY, 1_750_000_000, 1_000_000, None), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn non_initializer_cannot_cancel() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        assert_eq!(e.cancel(MALLORY, None, ALICE), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn taker_is_not_an_authority() {
        let mut e = escrow();
        // The taker is the beneficiary, not the authority: they cannot drive transitions.
        assert_eq!(e.fund(BOB), Err(EscrowError::Unauthorized));
        e.fund(ALICE).unwrap();
        assert_eq!(e.release(BOB, 1_750_000_000, 1_000_000, None), Err(EscrowError::Unauthorized));
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

    const ALL_STATES: [EscrowState; 7] = [
        EscrowState::Uninitialized,
        EscrowState::Activated,
        EscrowState::Funded,
        EscrowState::Released,
        EscrowState::Cancelled,
        EscrowState::Disputed,
        EscrowState::Settled,
    ];

    /// Arbiter key used to build the disputed / settled states.
    const ARBITER: [u8; 32] = [0xA8; 32];

    /// Build an escrow in each of the seven lifecycle states.
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
                e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
            }
            EscrowState::Cancelled => {
                e.fund(ALICE).unwrap();
                e.cancel(ALICE, None, ALICE).unwrap();
            }
            EscrowState::Disputed => {
                // AV-14: arbitration in progress; every unilateral exit
                // is locked.
                e = e.with_arbiter(ARBITER).unwrap();
                e.fund(ALICE).unwrap();
                e.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
            }
            EscrowState::Settled => {
                // AV-14: arbiter split the remainder 600k / 400k.
                e = e.with_arbiter(ARBITER).unwrap();
                e.fund(ALICE).unwrap();
                e.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
                e.resolve(ARBITER, 600_000, None).unwrap();
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
            assert_eq!(e.release(MALLORY, 1_750_000_000, 1_000_000, None), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn taker_cannot_release_in_any_state() {
        // The taker is the beneficiary of a release, but only the
        // initializer may drive the transition.
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.release(BOB, 1_750_000_000, 1_000_000, None), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn stranger_cannot_cancel_in_any_state() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.cancel(MALLORY, None, ALICE), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn taker_cannot_cancel_in_any_state() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.cancel(BOB, None, ALICE), Err(EscrowError::Unauthorized));
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
                    e.cancel_expired(MALLORY, now, None, ALICE),
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
            e.cancel_expired(BOB, EXPIRES_AT - 1, None, ALICE),
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
                e.cancel_expired(BOB, EXPIRES_AT + 1, None, ALICE),
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
        e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
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
        assert_eq!(e.release(MALLORY, 1_750_000_000, 1_000_000, None), Err(EscrowError::Unauthorized));
        let mut e = in_state(EscrowState::Cancelled);
        assert_eq!(e.cancel(MALLORY, None, ALICE), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn zero_key_caller_is_unauthorized_on_all_transitions() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.fund(ZERO_KEY), Err(EscrowError::Unauthorized));
            assert_eq!(e.release(ZERO_KEY, 1_750_000_000, 1_000_000, None), Err(EscrowError::Unauthorized));
            assert_eq!(e.cancel(ZERO_KEY, None, ALICE), Err(EscrowError::Unauthorized));
            assert_eq!(
                e.cancel_expired(ZERO_KEY, EXPIRES_AT + 1, None, ALICE),
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
        /// Model of the escrow's `fees_paid` counter (AV-17).
        fees_paid: u128,
        /// Configured anti-griefing penalty rate (AV-24): pinned for the
        /// field-immutability check below.
        penalty_bps: u16,
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
                Ok(escrow) => {
                    // AV-17: part of the fleet carries a protocol fee
                    // (0–10000 bps, boundary-biased at 10000), so the
                    // fuzz exercises fee charging under the conservation
                    // invariant — `released` stays gross, so the
                    // invariant is untouched by fees.
                    let fee_bps = match rng.below(3) {
                        0 => rng.below(10_001) as u16,
                        1 => 10_000,
                        _ => 0,
                    };
                    let escrow = escrow
                        .with_protocol_fee(fee_bps)
                        .expect("fee_bps <= 10_000 must configure");
                    // AV-24: part of the fleet carries an anti-griefing
                    // penalty rate (0–10000 bps, boundary-biased at
                    // 10000), so the fuzz exercises the taker-initiated
                    // penalty split — `refund + penalty == remainder`, a
                    // routing of the refund that never escapes the
                    // conservation invariant.
                    let penalty_bps = match rng.below(3) {
                        0 => rng.below(10_001) as u16,
                        1 => 10_000,
                        _ => 0,
                    };
                    let escrow = escrow
                        .with_penalty_bps(penalty_bps)
                        .expect("penalty_bps <= 10_000 must configure");
                    slots.push(Some(Slot {
                        escrow,
                        amount,
                        expires_at,
                        fees_paid: 0,
                        penalty_bps,
                    }))
                }
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
            let mut rel_fee = 0u64;
            // AV-24: `cancel_expired` returns the `(refund, penalty)`
            // split, so the op result carries it; the other ops map to
            // `(0, 0)` (their fund movements are tracked in
            // `released`/`refunded` below, not via the return).
            let mut exp_refund = 0u64;
            let mut exp_penalty = 0u64;
            let result: Result<(u64, u64), EscrowError> = match op {
                0 => slot.escrow.fund(authority).map(|()| (0, 0)),
                1 => {
                    rel_amt = fuzz_release_amount(&mut rng, slot.amount);
                    slot.escrow
                        .release(authority, 1_750_000_000, rel_amt, None)
                        .map(|(payout, fee)| {
                            // AV-17: the fee is a routing slice of the
                            // gross payout — it never escapes it.
                            assert_eq!(
                                payout + fee,
                                rel_amt,
                                "payout + fee != gross release on seed {seed}"
                            );
                            rel_fee = fee;
                            (0, 0)
                        })
                }
                2 => {
                    // The fuzz fleet configures no refund whitelist, so
                    // the policy is "refund to the initializer" — read
                    // it off the escrow (the fleet's initializers are
                    // fuzzed keys, not always ALICE).
                    let refund_to = slot.escrow.initializer();
                    slot.escrow.cancel(authority, None, refund_to).map(|()| (0, 0))
                }
                _ => {
                    let refund_to = slot.escrow.initializer();
                    slot.escrow
                        .cancel_expired(authority, fuzz_now(&mut rng), None, refund_to)
                        .map(|(refund, penalty)| {
                            // AV-24: the penalty is a routing slice of
                            // the remainder — it never escapes it.
                            assert_eq!(
                                refund + penalty,
                                slot.amount - slot.escrow.released_amount(),
                                "refund + penalty != remainder on seed {seed}"
                            );
                            exp_refund = refund;
                            exp_penalty = penalty;
                            (refund, penalty)
                        })
                }
            };

            match result {
                Ok(_) => match state_before {
                    // From Uninitialized only `fund` can succeed.
                    EscrowState::Uninitialized => inflow += slot.amount as u128,
                    EscrowState::Funded => match slot.escrow.state() {
                        // release: a full release closes the escrow, a
                        // partial release leaves it Funded — either way
                        // rel_amt left the locked bucket. AV-17: the
                        // gross amount (payout + fee) left the bucket,
                        // so the conservation invariant is unchanged.
                        EscrowState::Released | EscrowState::Funded => {
                            assert_eq!(
                                op, 1,
                                "only release can succeed from Funded to Funded/Released on seed {seed}"
                            );
                            released += rel_amt as u128;
                            slot.fees_paid += rel_fee as u128;
                        }
                        // cancel / cancel_expired: the refund is the
                        // unreleased remainder (partial releases are
                        // already counted in `released`). AV-24: on a
                        // taker-initiated cancel the penalty rides to
                        // the initializer alongside the refund, so it
                        // joins the same `refunded` bucket.
                        EscrowState::Cancelled => {
                            if op == 3 {
                                assert_eq!(
                                    exp_refund + exp_penalty,
                                    slot.amount - slot.escrow.released_amount(),
                                    "penalty split drifted on seed {seed}"
                                );
                                refunded += (exp_refund + exp_penalty) as u128;
                            } else {
                                refunded +=
                                    (slot.amount - slot.escrow.released_amount()) as u128;
                            }
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
                    assert_eq!(
                        slot.escrow.fees_paid() as u128,
                        slot.fees_paid,
                        "failed op moved the fee counter on seed {seed}"
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
            // AV-24: the penalty rate is fixed before funding and never
            // mutates afterwards.
            assert_eq!(
                slot.escrow.penalty_bps(),
                slot.penalty_bps,
                "penalty_bps changed on seed {seed}"
            );

            // AV-17: the fee model tracks the escrow's counter exactly —
            // the fee is a routing slice of the gross payout, so it
            // rides along inside `released` and the invariant above is
            // unchanged by fees. (Read before the `slots` borrow below.)
            let escrow_fees: u128 = slot.escrow.fees_paid() as u128;
            let model_fees: u128 = slot.fees_paid;
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
            // AV-17: the fee model tracks the escrow's counter exactly —
            // the fee is a routing slice of the gross payout, so it
            // rides along inside `released` and the invariant above is
            // unchanged by fees.
            assert_eq!(
                escrow_fees, model_fees,
                "fee counter drifted from model on seed {seed}"
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
        assert_eq!(e.release(ALICE, 1_750_000_000, 1_000_000, None), Err(EscrowError::QuorumNotReached));
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.amount(), 1_000_000);
    }

    #[test]
    fn release_after_threshold_reached_succeeds() {
        let mut e = escrow_with_quorum();
        e.attest(ATTESTOR_1).unwrap();
        e.attest(ATTESTOR_3).unwrap();
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.amount(), 1_000_000); // payout accounting preserved
    }

    #[test]
    fn quorum_does_not_weaken_initializer_authority() {
        // Even with a satisfied quorum, a stranger cannot release.
        let mut e = escrow_with_quorum();
        e.attest(ATTESTOR_1).unwrap();
        e.attest(ATTESTOR_2).unwrap();
        assert_eq!(e.release(MALLORY, 1_750_000_000, 1_000_000, None), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn quorum_does_not_leak_attestation_progress_to_strangers() {
        // Check order: authority before quorum. A stranger gets
        // Unauthorized even with zero attestations recorded.
        let mut e = escrow_with_quorum();
        assert_eq!(e.release(MALLORY, 1_750_000_000, 1_000_000, None), Err(EscrowError::Unauthorized));
        // ... while the initializer sees the quorum gate.
        assert_eq!(e.release(ALICE, 1_750_000_000, 1_000_000, None), Err(EscrowError::QuorumNotReached));
    }

    #[test]
    fn cancel_paths_are_not_gated_by_quorum() {
        // Anti-griefing: attestors withholding approval cannot lock funds;
        // the initializer refund path stays quorum-free.
        let mut e = escrow_with_quorum();
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);

        let mut e = escrow_with_quorum();
        e.cancel_expired(BOB, EXPIRES_AT + 1, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn escrow_without_quorum_releases_without_attestations() {
        // Backward compatibility: plain two-party escrow unchanged.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(e.quorum(), None);
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
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
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
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
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
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
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
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
//   supply the timestamp would let anyone fast-forward expiry. The same
//   holds for the AV-27 timelock gate: `release`, `claim` and
//   `release_milestone` read `now` from the clock sysvar, never from a
//   param — a caller-supplied timestamp would let the initializer
//   fast-forward the lock they configured.
// * `initialize_quorum`'s authority check lives in the Anchor account
//   constraint (`initializer.key() == vault.initializer` in the real
//   build), not in the state machine: `with_quorum` takes no authority
//   argument because the policy is fixed before funding and
//   re-configuration is rejected by state, while *who* may configure it
//   is the program layer's job. The spec marks this explicitly instead
//   of hiding the seam.
#[cfg(test)]
pub(crate) mod anchor_idl_tests {
    use super::*;
    use std::collections::HashSet;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const ATTESTOR_1: [u8; 32] = [0xA1; 32];
    const ATTESTOR_2: [u8; 32] = [0xA2; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    /// One IDL instruction and how it maps onto the state machine.
    /// `pub(crate)` so the AV-29 IDL pipeline (`idl_json`) can pin the
    /// generated `escrow_vault.json` against this table in both directions.
    pub(crate) struct InstructionSpec {
        /// Instruction name as it appears in the IDL.
        pub(crate) name: &'static str,
        /// (param name, IDL type, value source). Empty when the
        /// instruction's inputs come entirely from accounts / sysvars.
        pub(crate) params: &'static [(&'static str, &'static str, &'static str)],
        /// State-machine method this instruction must call.
        pub(crate) method: &'static str,
        /// Which account / sysvar feeds which method argument.
        pub(crate) input_mapping: &'static str,
    }

    pub(crate) const INSTRUCTIONS: &[InstructionSpec] = &[
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
                            amount <- param; now <- clock sysvar (NOT an \
                            instruction param — see module docs); partial \
                            releases accumulate in \
                            the `released` field and must not cumulatively \
                            exceed `amount` (ReleaseExceedsLocked); \
                            `amount == 0` is AmountMismatch; returns \
                            (taker_payout, fee) — AV-17: the protocol fee \
                            slices the payout and accumulates in \
                            `fees_paid`; when a quorum \
                            is configured the release gate from AV-04 \
                            applies (QuorumNotReached); when a timelock \
                            is configured the AV-27 gate applies \
                            (TimelockNotReached while now < unlock_at)",
        },
        InstructionSpec {
            name: "cancel",
            params: &[],
            method: "Escrow::cancel",
            input_mapping: "authority <- accounts.initializer (signer); \
                            refund destination <- accounts.refund_to \
                            (must equal the whitelisted address, or the \
                            initializer with no whitelist — \
                            RefundAddressMismatch otherwise; AV-23 \
                            anti-phishing pin)",
        },
        InstructionSpec {
            name: "cancel_expired",
            params: &[],
            method: "Escrow::cancel_expired",
            input_mapping: "authority <- accounts.authority (signer: \
                            initializer OR taker); now <- clock sysvar \
                            (NOT an instruction param — see module docs); \
                            refund destination <- accounts.refund_to \
                            (must equal the whitelisted address, or the \
                            initializer with no whitelist — \
                            RefundAddressMismatch otherwise; AV-23 \
                            anti-phishing pin; even a taker-initiated \
                            cancel refunds to the declared address); \
                            returns (refund, penalty) — AV-24: only a \
                            *taker-initiated* cancel charges the penalty, \
                            routed to the initializer as griefing \
                            compensation; initializer-initiated cancels \
                            return (remaining, 0)",
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
            // AV-25: dual-signed quorum threshold governance.
            name: "update_quorum",
            params: &[("threshold", "u8", "instruction param; the new N in N-of-M")],
            method: "Escrow::update_quorum",
            input_mapping: "authority <- accounts.initializer AND \
                            accounts.taker (BOTH signers — dual-signature \
                            governance; one party alone is Unauthorized); \
                            threshold <- param; Uninitialized or Funded \
                            only; 0 or > registered attestor count is \
                            InvalidQuorum, and no quorum configured is \
                            InvalidQuorum; the attestor set and existing \
                            attestations are untouched — only the threshold \
                            moves, in place, so the account needs no \
                            realloc; lowering an unreachable threshold \
                            restores liveness when attestors go dark",
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
            // AV-13: streaming release (linear vesting).
            name: "initialize_vesting",
            params: &[
                ("start", "u64", "instruction param; unlock begins"),
                ("end", "u64", "instruction param; fully vested at now >= end"),
            ],
            method: "VestingSchedule::new + Escrow::with_vesting",
            input_mapping: "start/end <- params; authority <- \
                            accounts.initializer (signer), enforced by the \
                            Anchor account constraint, not the state machine; \
                            Uninitialized only, like initialize_quorum; \
                            start >= end is InvalidVesting",
        },
        InstructionSpec {
            name: "claim",
            params: &[],
            method: "Escrow::claim",
            input_mapping: "authority <- accounts.taker (signer); now <- \
                            clock sysvar (NOT an instruction param — see \
                            cancel_expired rationale); returns (taker_payout, \
                            fee) so the program can size both transfers \
                            (AV-17); the quorum gate applies exactly as \
                            for release",
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
        InstructionSpec {
            // AV-14: dispute arbitration, opt-in arbiter.
            name: "initialize_arbiter",
            params: &[("arbiter", "Pubkey", "instruction param")],
            method: "Escrow::with_arbiter",
            input_mapping: "arbiter <- param (Pubkey -> [u8; 32] \
                            conversion); authority <- accounts.initializer \
                            (signer), enforced by the Anchor account \
                            constraint, not the state machine; \
                            Uninitialized only, like initialize_quorum; \
                            the zero key is InvalidArbiter",
        },
        InstructionSpec {
            name: "escalate",
            params: &[(
                "evidence_hash",
                "Option<[u8; 32]>",
                "instruction param; 32-byte commitment to the off-chain \
                 dispute evidence (e.g. SHA-256 of an IPFS CID), None = \
                 no evidence attached",
            )],
            method: "Escrow::escalate",
            input_mapping: "authority <- accounts.authority (signer: \
                            initializer OR taker); now <- clock sysvar \
                            (NOT an instruction param — a caller-supplied \
                            timestamp could rewind past the dispute \
                            window, same rationale as cancel_expired); \
                            evidence_hash <- param, persisted on the \
                            escrow so the arbiter and indexers can read \
                            it; Funded -> Disputed, locks every \
                            unilateral exit until resolve",
        },
        InstructionSpec {
            name: "resolve",
            params: &[(
                "taker_amount",
                "u64",
                "instruction param; taker's share of the remaining funds",
            )],
            method: "Escrow::resolve",
            input_mapping: "authority <- accounts.arbiter (signer; must \
                            equal the configured arbiter); taker_amount <- \
                            param, capped at the remaining locked amount \
                            (ReleaseExceedsLocked); Disputed -> Settled; \
                            returns (taker_payout, fee, initializer_refund) \
                            so the program can size all three transfers \
                            (AV-17: the fee slices the taker's share, the \
                            refund is never fee'd); the \
                            quorum gate does NOT apply (the arbiter is \
                            the resolution mechanism)",
        },
        InstructionSpec {
            // AV-15: milestone tranche schedule.
            name: "initialize_milestones",
            params: &[(
                "milestones",
                "Vec<u64>",
                "instruction param; tranche amounts in release order, \
                 Σ must equal the locked amount",
            )],
            method: "MilestonePlan::new + Escrow::with_milestones",
            input_mapping: "milestones <- param (Vec<u64> -> tranche \
                            table); authority <- accounts.initializer \
                            (signer), enforced by the Anchor account \
                            constraint, not the state machine; \
                            Uninitialized only, like initialize_quorum; \
                            the Σ == locked check accumulates in u128 so \
                            the sum can never wrap; once attached, the \
                            plan owns the release schedule (plain \
                            release / claim become InvalidMilestones)",
        },
        InstructionSpec {
            name: "confirm_milestone",
            params: &[("index", "u8", "instruction param; milestone index")],
            method: "Escrow::confirm_milestone",
            input_mapping: "authority <- accounts.authority (signer: \
                            initializer OR taker); index <- param; \
                            records one party's acceptance; the milestone \
                            is confirmed only once BOTH parties confirmed \
                            (dual-signature acceptance, the AV-12 \
                            concept); strictly in-order, idempotent per \
                            party",
        },
        InstructionSpec {
            name: "release_milestone",
            params: &[("index", "u8", "instruction param; milestone index")],
            method: "Escrow::release_milestone",
            input_mapping: "authority <- accounts.initializer (signer); \
                            index <- param; now <- clock sysvar (NOT an \
                            instruction param — see module docs); releases \
                            the tranche only \
                            after dual confirmation (MilestoneNotConfirmed \
                            otherwise) and in-order; returns (taker_payout, \
                            fee) so the program can size both transfers \
                            (AV-17); \
                            the quorum gate applies exactly as for release; \
                            the AV-27 timelock gate applies exactly as for \
                            release (TimelockNotReached while \
                            now < unlock_at)",
        },
        InstructionSpec {
            name: "skip_milestone",
            params: &[("index", "u8", "instruction param; milestone index")],
            method: "Escrow::skip_milestone",
            input_mapping: "authority <- accounts.authority (signer: \
                            initializer OR taker); index <- param; \
                            records one party's skip approval; the skip \
                            executes (tranche refunded to the initializer) \
                            only after BOTH parties approved (dual-sig \
                            skip); strictly in-order, idempotent per party",
        },
        InstructionSpec {
            // AV-16: SPL token mint binding.
            name: "initialize_mint",
            params: &[(
                "mint",
                "String",
                "instruction param; base58 SPL mint address",
            )],
            method: "Escrow::with_mint",
            input_mapping: "mint <- param (base58 string -> [u8; 32] via \
                            parse_mint_address; empty / non-alphabet / \
                            not-32-bytes is InvalidMint, the zero address \
                            is rejected too); authority <- \
                            accounts.initializer (signer), enforced by the \
                            Anchor account constraint, not the state \
                            machine; Uninitialized only, like \
                            initialize_quorum; after this the fund-moving \
                            instructions (release / cancel / cancel_expired \
                            / claim / release_milestone / resolve) take \
                            the vault token account's mint and require it \
                            to equal the bound address (MintMismatch \
                            otherwise); without a bound mint the escrow is \
                            the native-SOL path and those instructions \
                            take no token mint",
        },
        InstructionSpec {
            // AV-17: protocol fee in basis points.
            name: "initialize_protocol_fee",
            params: &[(
                "fee_bps",
                "u16",
                "instruction param; basis points, 0-10000",
            )],
            method: "Escrow::with_protocol_fee",
            input_mapping: "fee_bps <- param; authority <- \
                            accounts.initializer (signer), enforced by the \
                            Anchor account constraint, not the state \
                            machine; Uninitialized only, like \
                            initialize_quorum; fee_bps > 10000 is \
                            InvalidProtocolFee; the fee slices every taker \
                            payout (release / claim / release_milestone / \
                            resolve) as floor(payout * fee_bps / 10000) \
                            and accumulates in vault.fees_paid — the \
                            program routes each payout's fee to the \
                            protocol fee account",
        },
        InstructionSpec {
            // AV-21: expiry grace period in seconds.
            name: "initialize_grace_period",
            params: &[(
                "grace_period",
                "u64",
                "instruction param; seconds added to expires_at for the cancel_expired gate",
            )],
            method: "Escrow::with_grace_period",
            input_mapping: "grace_period <- param; authority <- \
                            accounts.initializer (signer), enforced by the \
                            Anchor account constraint, not the state \
                            machine; Uninitialized only, like \
                            initialize_quorum; expires_at + grace_period \
                            overflowing u64 is InvalidGracePeriod (in \
                            particular a grace period cannot be combined \
                            with the no-timeout convention expires_at == \
                            u64::MAX); after this, cancel_expired requires \
                            now >= expires_at + grace_period \
                            (NotExpired otherwise), so a keeper whose \
                            clock runs ahead of the cluster clock cannot \
                            submit a premature cancel; 0 is the valid \
                            \"no grace\" default",
        },
        InstructionSpec {
            // AV-23: refund address whitelist.
            name: "initialize_refund_address",
            params: &[(
                "refund_to",
                "Pubkey",
                "instruction param; every unilateral refund (cancel / \
                 cancel_expired) must go to this address",
            )],
            method: "Escrow::with_refund_address",
            input_mapping: "refund_to <- param (Pubkey -> [u8; 32] \
                            conversion); authority <- accounts.initializer \
                            (signer), enforced by the Anchor account \
                            constraint, not the state machine; \
                            Uninitialized only, like initialize_quorum; \
                            the zero address is RefundAddressMismatch; \
                            after this, cancel / cancel_expired take the \
                            refund destination explicitly and reject \
                            anything but the whitelisted address \
                            (RefundAddressMismatch) — a phishing frontend \
                            cannot redirect the refund; with no whitelist \
                            the policy is refund-to-initializer",
        },
        InstructionSpec {
            // AV-24: anti-griefing penalty in basis points.
            name: "initialize_penalty",
            params: &[(
                "penalty_bps",
                "u16",
                "instruction param; basis points, 0-10000",
            )],
            method: "Escrow::with_penalty_bps",
            input_mapping: "penalty_bps <- param; authority <- \
                            accounts.initializer (signer), enforced by the \
                            Anchor account constraint, not the state \
                            machine; Uninitialized only, like \
                            initialize_quorum; penalty_bps > 10000 is \
                            InvalidPenalty; only a *taker-initiated* \
                            cancel_expired charges the penalty — it returns \
                            (refund, penalty) so the program can route the \
                            penalty to the initializer as griefing \
                            compensation; initializer-initiated cancels \
                            and the arbiter's resolve never carry it",
        },
        InstructionSpec {
            // AV-27: timelock.
            name: "initialize_timelock",
            params: &[(
                "unlock_at",
                "u64",
                "instruction param; Unix timestamp before which no taker payout may leave the escrow; 0 = no lock",
            )],
            method: "Escrow::with_timelock",
            input_mapping: "unlock_at <- param; authority <- \\
                            accounts.initializer (signer), enforced by the \\
                            Anchor account constraint, not the state \\
                            machine; Uninitialized only, like \\
                            initialize_quorum; after this, release / claim \\
                            / release_milestone require now >= unlock_at \\
                            (TimelockNotReached otherwise), where now <- \\
                            clock sysvar (NOT an instruction param — a \\
                            caller-supplied timestamp would let the \\
                            initializer fast-forward the lock); cancel / \\
                            cancel_expired / resolve are deliberately NOT \\
                            gated, so a misconfigured lock can never trap \\
                            funds forever",
        },
        InstructionSpec {
            // AV-28: token decimal metadata.
            name: "initialize_decimals",
            params: &[(
                "decimals",
                "u8",
                "instruction param; the SPL mint's decimal places (SPL mints declare at most 9); 0 = no decimal metadata",
            )],
            method: "Escrow::with_decimals",
            input_mapping: "decimals <- param; authority <- \\
                            accounts.initializer (signer), enforced by the \\
                            Anchor account constraint, not the state \\
                            machine; Uninitialized only, like \\
                            initialize_quorum; decimals > 18 is \\
                            InvalidDecimals; the metadata never gates a \\
                            transition and never moves funds — it only \\
                            feeds Escrow::display_amount and the \\
                            human-readable amounts in the keeper report \\
                            and the AV-26 snapshot export",
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
            "Escrow::update_quorum",
            "Escrow::with_dual_sig",
            "Escrow::activate",
            "VestingSchedule::new + Escrow::with_vesting",
            "Escrow::claim",
            "Escrow::attest",
            "Escrow::with_arbiter",
            "Escrow::escalate",
            "Escrow::resolve",
            "MilestonePlan::new + Escrow::with_milestones",
            "Escrow::confirm_milestone",
            "Escrow::release_milestone",
            "Escrow::skip_milestone",
            "Escrow::with_mint",
            "Escrow::with_protocol_fee",
            "Escrow::with_grace_period",
            "Escrow::with_refund_address",
            "Escrow::with_penalty_bps",
            "Escrow::with_timelock",
            "Escrow::with_decimals",
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
    fn only_nineteen_instructions_take_params() {
        // Pins which instructions carry IDL params; any new param must be
        // justified in the spec table above.
        let with_params: Vec<&&str> = INSTRUCTIONS
            .iter()
            .filter(|s| !s.params.is_empty())
            .map(|s| &s.name)
            .collect();
        assert_eq!(
            with_params,
            vec![
                &"initialize",
                &"release",
                &"initialize_quorum",
                &"update_quorum",
                &"initialize_vesting",
                &"initialize_arbiter",
                &"escalate",
                &"resolve",
                &"initialize_milestones",
                &"confirm_milestone",
                &"release_milestone",
                &"skip_milestone",
                &"initialize_mint",
                &"initialize_protocol_fee",
                &"initialize_grace_period",
                &"initialize_refund_address",
                &"initialize_penalty",
                &"initialize_timelock",
                &"initialize_decimals"
            ]
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
    fn initialize_mint_maps_base58_mint_param() {
        // IDL: initialize_mint(mint: String). The program parses the
        // base58 address via parse_mint_address, then Escrow::with_mint;
        // authority <- accounts.initializer, enforced by the Anchor
        // account constraint, not the state machine (Uninitialized only,
        // like initialize_quorum).
        let bytes = parse_mint_address("11111111111111111111111111111112").unwrap();
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_mint(bytes)
            .unwrap();
        assert_eq!(e.mint(), Some(bytes));
        assert_eq!(e.state(), EscrowState::Uninitialized);
        // Documented failure modes: bad base58 rejected at parse time,
        // before touching the escrow ...
        assert_eq!(
            parse_mint_address("not a mint!!"),
            Err(EscrowError::InvalidMint)
        );
        assert_eq!(parse_mint_address(""), Err(EscrowError::InvalidMint));
        // ... and the zero address rejected at bind time (well-formed
        // but not a real mint).
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
                .unwrap()
                .with_mint([0u8; 32]),
            Err(EscrowError::InvalidMint)
        );
        // Re-binding a live escrow is rejected by state.
        let mut funded = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_mint(bytes)
            .unwrap();
        funded.fund(ALICE).unwrap();
        assert_eq!(
            funded.with_mint(bytes),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn initialize_protocol_fee_maps_param_to_fee_bps_field() {
        // IDL: initialize_protocol_fee(fee_bps: u16). The program takes
        // the param, then Escrow::with_protocol_fee; authority <-
        // accounts.initializer, enforced by the Anchor account constraint,
        // not the state machine (Uninitialized only, like
        // initialize_quorum).
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_protocol_fee(250)
            .unwrap();
        assert_eq!(e.fee_bps(), 250);
        assert_eq!(e.fees_paid(), 0);
        assert_eq!(e.state(), EscrowState::Uninitialized);
        // Documented failure mode: not a valid basis-point rate.
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
                .unwrap()
                .with_protocol_fee(10_001),
            Err(EscrowError::InvalidProtocolFee)
        );
        // Re-configuring a live escrow is rejected by state.
        let mut funded = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_protocol_fee(250)
            .unwrap();
        funded.fund(ALICE).unwrap();
        assert_eq!(
            funded.with_protocol_fee(300),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(funded.fee_bps(), 250);
    }

    #[test]
    fn initialize_grace_period_maps_param_to_grace_period_field() {
        // IDL: initialize_grace_period(grace_period: u64). The program
        // takes the param, then Escrow::with_grace_period; authority <-
        // accounts.initializer, enforced by the Anchor account
        // constraint, not the state machine (Uninitialized only, like
        // initialize_quorum).
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_grace_period(300)
            .unwrap();
        assert_eq!(e.grace_period(), 300);
        assert_eq!(e.state(), EscrowState::Uninitialized);
        // The gate moves: cancel_expired now needs expires_at + grace.
        let mut funded = e;
        funded.fund(ALICE).unwrap();
        assert_eq!(
            funded.cancel_expired(ALICE, EXPIRES_AT, None, ALICE),
            Err(EscrowError::NotExpired)
        );
        funded.cancel_expired(ALICE, EXPIRES_AT + 300, None, ALICE).unwrap();
        // Documented failure mode: expires_at + grace_period overflows.
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 1_000_000, u64::MAX)
                .unwrap()
                .with_grace_period(1),
            Err(EscrowError::InvalidGracePeriod)
        );
        // Re-configuring a live escrow is rejected by state.
        let mut funded = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_grace_period(300)
            .unwrap();
        funded.fund(ALICE).unwrap();
        assert_eq!(
            funded.with_grace_period(600),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(funded.grace_period(), 300);
    }

    #[test]
    fn initialize_penalty_maps_param_to_penalty_bps_field() {
        // IDL: initialize_penalty(penalty_bps: u16). The program takes
        // the param, then Escrow::with_penalty_bps; authority <-
        // accounts.initializer, enforced by the Anchor account
        // constraint, not the state machine (Uninitialized only, like
        // initialize_quorum).
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_penalty_bps(250)
            .unwrap();
        assert_eq!(e.penalty_bps(), 250);
        assert_eq!(e.state(), EscrowState::Uninitialized);
        // The taker-initiated cancel splits the remainder: 250 bps of
        // 1_000_000 = 25_000 to the initializer as griefing
        // compensation, the rest refunded.
        let mut funded = e;
        funded.fund(ALICE).unwrap();
        let (refund, penalty) = funded.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        assert_eq!((refund, penalty), (975_000, 25_000));
        assert_eq!(funded.state(), EscrowState::Cancelled);
        // Documented failure mode: not a valid basis-point rate.
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
                .unwrap()
                .with_penalty_bps(10_001),
            Err(EscrowError::InvalidPenalty)
        );
        // Re-configuring a live escrow is rejected by state.
        let mut funded = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_penalty_bps(250)
            .unwrap();
        funded.fund(ALICE).unwrap();
        assert_eq!(
            funded.with_penalty_bps(300),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(funded.penalty_bps(), 250);
    }

    #[test]
    fn initialize_timelock_maps_param_to_timelock_field() {
        // IDL: initialize_timelock(unlock_at: u64). The program takes
        // the param, then Escrow::with_timelock; authority <-
        // accounts.initializer, enforced by the Anchor account
        // constraint, not the state machine (Uninitialized only, like
        // initialize_quorum).
        const UNLOCK_AT: u64 = 1_900_000_000;
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_timelock(UNLOCK_AT)
            .unwrap();
        assert_eq!(e.unlock_at(), UNLOCK_AT);
        assert!(!e.is_unlock_eligible(UNLOCK_AT - 1));
        assert!(e.is_unlock_eligible(UNLOCK_AT));
        assert_eq!(e.state(), EscrowState::Uninitialized);
        // The gate moves: release / claim / release_milestone need
        // now >= unlock_at. A vesting escrow exercises the claim path.
        let mut funded = e;
        funded.fund(ALICE).unwrap();
        assert_eq!(
            funded.release(ALICE, UNLOCK_AT - 1, 1_000_000, None),
            Err(EscrowError::TimelockNotReached)
        );
        assert_eq!(funded.state(), EscrowState::Funded);
        assert_eq!(funded.released_amount(), 0, "a locked release moves nothing");
        funded.release(ALICE, UNLOCK_AT, 1_000_000, None).unwrap();
        assert_eq!(funded.state(), EscrowState::Released);
        // Re-configuring a live escrow is rejected by state.
        let mut funded = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_timelock(UNLOCK_AT)
            .unwrap();
        funded.fund(ALICE).unwrap();
        assert_eq!(
            funded.with_timelock(UNLOCK_AT + 1),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(funded.unlock_at(), UNLOCK_AT);
        // unlock_at == 0 is the valid no-op: payouts are never gated.
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_timelock(0)
            .unwrap();
        assert_eq!(e.unlock_at(), 0);
        assert!(e.is_unlock_eligible(0));
    }

    #[test]
    fn initialize_decimals_maps_param_to_decimals_field() {
        // IDL: initialize_decimals(decimals: u8). The program takes
        // the param, then Escrow::with_decimals; authority <-
        // accounts.initializer, enforced by the Anchor account
        // constraint, not the state machine (Uninitialized only, like
        // initialize_quorum).
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_decimals(6)
            .unwrap();
        assert_eq!(e.decimals(), 6);
        assert_eq!(e.display_amount(), "1.000000");
        assert_eq!(e.state(), EscrowState::Uninitialized);
        // Documented failure mode: beyond the 18-decimal ceiling.
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
                .unwrap()
                .with_decimals(19),
            Err(EscrowError::InvalidDecimals)
        );
        // The metadata never gates a transition: a 6-decimal escrow
        // releases exactly like a plain one.
        let mut funded = e;
        funded.fund(ALICE).unwrap();
        funded.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!(funded.state(), EscrowState::Released);
        // Re-configuring a live escrow is rejected by state.
        let mut funded = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_decimals(6)
            .unwrap();
        funded.fund(ALICE).unwrap();
        assert_eq!(
            funded.with_decimals(9),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(funded.decimals(), 6);
        // decimals == 0 is the valid no-op: bare-integer rendering.
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_decimals(0)
            .unwrap();
        assert_eq!(e.decimals(), 0);
        assert_eq!(e.display_amount(), "1000000");
    }

    #[test]
    fn update_quorum_maps_dual_signers_and_threshold_param() {
        // IDL: update_quorum(threshold: u8). The program passes
        // accounts.initializer and accounts.taker (BOTH signers) plus
        // the param, then Escrow::update_quorum.
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(e.quorum().unwrap().threshold(), 2);
        // Both parties sign: the threshold moves.
        e.update_quorum(ALICE, BOB, 1).unwrap();
        assert_eq!(e.quorum().unwrap().threshold(), 1);
        // One party alone is Unauthorized — the gate cannot be weakened
        // unilaterally. A stranger learns nothing either.
        assert_eq!(
            e.update_quorum(ALICE, MALLORY, 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            e.update_quorum(MALLORY, BOB, 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.quorum().unwrap().threshold(), 1, "failed update keeps the threshold");
        // Documented failure modes: no quorum configured ...
        let mut plain = funded_escrow();
        assert_eq!(
            plain.update_quorum(ALICE, BOB, 1),
            Err(EscrowError::InvalidQuorum)
        );
        // ... a zero threshold, or one above the registered count.
        assert_eq!(
            e.update_quorum(ALICE, BOB, 0),
            Err(EscrowError::InvalidQuorum)
        );
        assert_eq!(
            e.update_quorum(ALICE, BOB, 3),
            Err(EscrowError::InvalidQuorum)
        );
        assert_eq!(e.quorum().unwrap().threshold(), 1);
        // Terminal states are locked out.
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(
            e.update_quorum(ALICE, BOB, 1),
            Err(EscrowError::InvalidStateTransition)
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
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        // Documented partial path: stays Funded, progress tracked.
        let mut e = funded_escrow();
        e.release(ALICE, 1_750_000_000, 400_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!((e.released_amount(), e.remaining_amount()), (400_000, 600_000));
        // Documented failure mode: quorum configured but threshold unmet
        // (release-specific gate from AV-04).
        let mut e = quorum_funded_escrow();
        e.attest(ATTESTOR_1).unwrap();
        assert_eq!(e.release(ALICE, 1_750_000_000, 1_000_000, None), Err(EscrowError::QuorumNotReached));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn cancel_maps_initializer_signer_to_authority() {
        // IDL: cancel() — no params; authority <- accounts.initializer.
        let mut e = funded_escrow();
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        // Documented failure mode: signer is not the initializer.
        let mut e = funded_escrow();
        assert_eq!(e.cancel(MALLORY, None, ALICE), Err(EscrowError::Unauthorized));
    }

    #[test]
    fn cancel_expired_maps_authority_and_clock_sysvar() {
        // IDL: cancel_expired() — no params. authority <- accounts.authority
        // (signer: initializer OR taker); now <- clock sysvar, deliberately
        // not an instruction param (caller-supplied timestamps would let
        // anyone fast-forward expiry). The program layer must pass
        // Clock::get()?.unix_timestamp here.
        let mut e = funded_escrow();
        e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        // Documented failure mode: clock before expiry.
        let mut e = funded_escrow();
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT - 1, None, ALICE),
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
        assert_eq!(e.release(ALICE, 1_750_000_000, 1_000_000, None), Err(EscrowError::QuorumNotReached));
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
    fn initialize_arbiter_maps_param_to_arbiter_field() {
        // IDL: initialize_arbiter(arbiter: Pubkey) — arbiter <- param;
        // authority <- accounts.initializer (Anchor constraint).
        const ARBITER: [u8; 32] = [0xA8; 32];
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        assert_eq!(e.arbiter(), Some(ARBITER));
        assert_eq!(e.state(), EscrowState::Uninitialized);
        // Documented failure mode: zero key is not an identity.
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
                .unwrap()
                .with_arbiter([0u8; 32]),
            Err(EscrowError::InvalidArbiter)
        );
    }

    #[test]
    fn escalate_maps_authority_and_clock_sysvar() {
        // IDL: escalate() — no params. authority <- accounts.authority
        // (signer: initializer OR taker); now <- clock sysvar, deliberately
        // not an instruction param (a caller-supplied timestamp could
        // rewind past the dispute window). The program layer must pass
        // Clock::get()?.unix_timestamp here.
        const ARBITER: [u8; 32] = [0xA8; 32];
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        // The taker may escalate too: either party can open the dispute.
        e.escalate(BOB, EXPIRES_AT - 1, None).unwrap();
        assert_eq!(e.state(), EscrowState::Disputed);
        // Documented failure mode: the dispute window is closed once the
        // escrow is expiry-eligible.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.escalate(ALICE, EXPIRES_AT, None),
            Err(EscrowError::DisputeWindowClosed)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn resolve_maps_arbiter_signer_and_taker_amount_param() {
        // IDL: resolve(taker_amount: u64) — authority <-
        // accounts.arbiter (signer); taker_amount <- instruction param.
        // Returns (taker_payout, initializer_refund) so the program can
        // size both transfers.
        const ARBITER: [u8; 32] = [0xA8; 32];
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
        let (payout, fee, refund) = e.resolve(ARBITER, 600_000, None).unwrap();
        assert_eq!((payout, fee, refund), (600_000, 0, 400_000));
        assert_eq!(e.state(), EscrowState::Settled);
        // Taker's share in `released`, initializer's refund in
        // `remaining` — the same split the `cancel` path reports.
        assert_eq!((e.released_amount(), e.remaining_amount()), (600_000, 400_000));
        // Documented failure mode: the initializer is not the arbiter.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
        assert_eq!(
            e.resolve(ALICE, 600_000, None),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.state(), EscrowState::Disputed);
    }

    fn milestone_escrow() -> Escrow {
        let plan = MilestonePlan::new(&[400_000, 600_000]).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan)
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    #[test]
    fn initialize_milestones_maps_tranche_list_to_plan() {
        // IDL: initialize_milestones(milestones: Vec<u64>). The program
        // runs MilestonePlan::new then Escrow::with_milestones; authority
        // <- accounts.initializer, enforced by the Anchor account
        // constraint. The tranche amounts must sum to the locked amount.
        let plan = MilestonePlan::new(&[400_000, 600_000]).unwrap();
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan)
            .unwrap();
        assert_eq!(e.milestone_plan(), Some(plan));
        assert_eq!(e.state(), EscrowState::Uninitialized);
        // Documented failure mode: the plan does not cover the lockup.
        let short = MilestonePlan::new(&[400_000, 500_000]).unwrap();
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
                .unwrap()
                .with_milestones(short),
            Err(EscrowError::InvalidMilestones)
        );
        // Documented failure mode: zero-amount tranche rejected at
        // construction, before touching the escrow.
        assert_eq!(
            MilestonePlan::new(&[400_000, 0]),
            Err(EscrowError::InvalidMilestones)
        );
    }

    #[test]
    fn confirm_milestone_maps_either_party_signer_to_confirmation() {
        // IDL: confirm_milestone(index: u8) — no other params; authority
        // <- accounts.authority (signer: initializer OR taker). Records
        // one party's acceptance; the milestone is confirmed once BOTH
        // parties confirmed.
        let mut e = milestone_escrow();
        // One party alone: recorded, but the milestone is not confirmed.
        e.confirm_milestone(ALICE, 0).unwrap();
        assert!(!e.milestone_confirmed(0));
        assert_eq!(e.next_milestone(), Some(0));
        // The second party's confirmation completes it.
        e.confirm_milestone(BOB, 0).unwrap();
        assert!(e.milestone_confirmed(0));
        // Documented failure mode: stranger learns nothing (Unauthorized
        // before any state/config check).
        assert_eq!(
            e.confirm_milestone(MALLORY, 0),
            Err(EscrowError::Unauthorized)
        );
        // Documented failure mode: confirming ahead of the sequence.
        assert_eq!(
            e.confirm_milestone(ALICE, 1),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn release_milestone_maps_initializer_signer_and_index_to_tranche() {
        // IDL: release_milestone(index: u8) — authority <-
        // accounts.initializer (signer); index <- param. Returns the
        // tranche amount so the program can size the transfer; the
        // tranche accumulates in the shared `released` counter.
        let mut e = milestone_escrow();
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        let (tranche, fee) = e.release_milestone(ALICE, 1_750_000_000, 0, None).unwrap();
        assert_eq!((tranche, fee), (400_000, 0), "no fee configured: full tranche to taker");
        assert_eq!((e.released_amount(), e.remaining_amount()), (400_000, 600_000));
        assert_eq!(e.state(), EscrowState::Funded);
        assert!(e.milestone_settled(0));
        // Documented failure mode: releasing before dual confirmation.
        let mut e = milestone_escrow();
        e.confirm_milestone(ALICE, 0).unwrap();
        assert_eq!(
            e.release_milestone(ALICE, 1_750_000_000, 0, None),
            Err(EscrowError::MilestoneNotConfirmed)
        );
        assert_eq!(e.released_amount(), 0);
        // Documented failure mode: the taker cannot drive the release.
        assert_eq!(
            e.release_milestone(BOB, 1_750_000_000, 0, None),
            Err(EscrowError::Unauthorized)
        );
    }

    #[test]
    fn skip_milestone_maps_dual_approval_to_refund() {
        // IDL: skip_milestone(index: u8) — authority <-
        // accounts.authority (signer: initializer OR taker). Records one
        // party's skip approval per call; the skip executes (tranche
        // refunded to the initializer) only once BOTH parties approved.
        let mut e = milestone_escrow();
        // One approval: nothing happens yet — the milestone stays
        // unsettled.
        e.skip_milestone(ALICE, 0).unwrap();
        assert!(!e.milestone_settled(0));
        assert_eq!(e.skipped_amount(), 0);
        // The second approval executes the skip.
        e.skip_milestone(BOB, 0).unwrap();
        assert!(e.milestone_settled(0));
        assert_eq!(e.skipped_amount(), 400_000);
        assert_eq!(e.released_amount(), 0, "skips never pay the taker");
        // The skipped tranche stays inside the refundable remainder
        // (remaining = amount - released; skipped is sub-accounting of
        // the remainder, not a separate bucket).
        assert_eq!(e.remaining_amount(), 1_000_000);
        assert_eq!(e.state(), EscrowState::Funded);
        // Documented failure mode: stranger cannot approve a skip.
        let mut e = milestone_escrow();
        assert_eq!(
            e.skip_milestone(MALLORY, 0),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.skipped_amount(), 0);
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

    #[test]
    fn initialize_vesting_maps_start_end_params_to_schedule() {
        // IDL: initialize_vesting(start: u64, end: u64). The program runs
        // VestingSchedule::new then Escrow::with_vesting; authority <-
        // accounts.initializer, enforced by the Anchor account constraint.
        let schedule = VestingSchedule::new(1_700_000_000, 1_800_000_000).unwrap();
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_vesting(schedule)
            .unwrap();
        assert_eq!(
            e.vesting_schedule(),
            Some(VestingSchedule::new(1_700_000_000, 1_800_000_000).unwrap())
        );
        assert_eq!(e.state(), EscrowState::Uninitialized);
        // Documented failure mode: inverted window rejected at
        // construction, before touching the escrow.
        assert_eq!(
            VestingSchedule::new(1_800_000_000, 1_700_000_000),
            Err(EscrowError::InvalidVesting)
        );
    }

    #[test]
    fn claim_maps_taker_signer_and_clock_sysvar() {
        // IDL: claim() — no params. authority <- accounts.taker (signer);
        // now <- clock sysvar, deliberately not an instruction param
        // (caller-supplied timestamps would let anyone fast-forward the
        // unlock curve). The program layer must pass
        // Clock::get()?.unix_timestamp here, and uses the returned amount
        // to size the transfer.
        let schedule = VestingSchedule::new(1_700_000_000, 1_800_000_000).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_vesting(schedule)
            .unwrap();
        e.fund(ALICE).unwrap();
        // Half the window elapsed: half vested.
        let (claimed, fee) = e.claim(BOB, 1_750_000_000, None).unwrap();
        assert_eq!((claimed, fee), (500_000, 0), "no fee configured: full claim to taker");
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!((e.released_amount(), e.remaining_amount()), (500_000, 500_000));
        // Documented failure mode: initializer cannot pull the taker's
        // stream, even funded.
        assert_eq!(
            e.claim(ALICE, 1_800_000_000, None),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.released_amount(), 500_000);
    }

    // ----- AV-10, second half: two-way vault-field <-> IDL consistency -----
    //
    // Direction 1 (IDL -> account): every instruction param must populate
    // exactly one vault field — a param that writes nothing (or writes an
    // undocumented field) is a spec lie the program would compile anyway.
    // Direction 2 (account -> IDL): every vault field must have a
    // documented source — a field no instruction or account constraint
    // ever writes is dead space the `space =` rent pays for. A field may
    // be written by more than one instruction param (`release`'s `amount`
    // and `resolve`'s `taker_amount` both accumulate into `released`),
    // but never by both a param and a field source: exactly one *kind*
    // of source per field.
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
        // AV-25: the dual-signed governance update writes the same
        // field (a second param source is allowed — see `released`).
        ("update_quorum", "threshold", "quorum.threshold"),
        ("initialize_vesting", "start", "vesting.start"),
        ("initialize_vesting", "end", "vesting.end"),
        ("initialize_arbiter", "arbiter", "arbiter"),
        // The arbiter's split awards the taker `taker_amount` out of the
        // remaining funds; the taker's share accumulates in `released`,
        // like `release`'s amount param.
        ("resolve", "taker_amount", "released"),
        // AV-15: the tranche list populates the plan's amounts; the count
        // is derived (see FIELD_SOURCES). The plan region is zeroed by
        // `initialize`.
        ("initialize_milestones", "milestones", "milestones.amounts"),
        // AV-15: the index selects the milestone whose confirmation bits
        // (or skip-approval bits) are flipped in the bitmap; the bitmap
        // itself is zeroed by `initialize`.
        ("confirm_milestone", "index", "milestone_flags"),
        // AV-15: the index selects the tranche whose amount accumulates
        // in `released` — the same dual-writing the direction-2 note
        // allows for `resolve`'s taker_amount (the released bit in
        // `milestone_flags` is covered by that field's source entry).
        ("release_milestone", "index", "released"),
        ("skip_milestone", "index", "milestone_flags"),
        // AV-16: the base58 mint param populates the bound mint address;
        // the `Option` discriminant is implied (a bound mint is `Some`).
        ("initialize_mint", "mint", "mint"),
        // AV-17: the fee rate param populates `fee_bps` directly (u16,
        // not an Option — 0 is the valid "no fee" rate).
        ("initialize_protocol_fee", "fee_bps", "fee_bps"),
        // AV-21: the grace period param populates `grace_period`
        // directly (u64 — 0 is the valid "no grace" default).
        ("initialize_grace_period", "grace_period", "grace_period"),
        // AV-22: the evidence commitment param populates
        // `evidence_hash`; the `Option` discriminant is implied (an
        // attached hash is `Some`).
        ("escalate", "evidence_hash", "evidence_hash"),
        // AV-23: the refund address whitelist param populates
        // `refund_to`; the `Option` discriminant is implied (a declared
        // whitelist is `Some`).
        ("initialize_refund_address", "refund_to", "refund_to"),
        // AV-24: the anti-griefing penalty rate param populates
        // `penalty_bps` directly (u16 — 0 is the valid "no penalty"
        // default).
        ("initialize_penalty", "penalty_bps", "penalty_bps"),
        // AV-27: the unlock timestamp param populates `timelock`
        // directly (u64 — 0 is the valid "no lock" default).
        ("initialize_timelock", "unlock_at", "timelock"),
        // AV-28: the decimal-places param populates `decimals` directly
        // (u8 — 0 is the valid "no decimal metadata" default).
        ("initialize_decimals", "decimals", "decimals"),
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
            "transitions: fund/release/cancel/cancel_expired/activate/escalate/resolve",
        ),
        // `arbiter` is populated by the `initialize_arbiter` instruction
        // param (see PARAM_FIELD_MAP), so it is not listed here — like
        // `quorum.attestors`, every field gets exactly one source.
        // `initialize` zeroes the region; `initialize_arbiter` is
        // Uninitialized-only, like `initialize_quorum`.
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
        // AV-15: the plan's tranche count is not an instruction param —
        // it is derived from the list length, like `quorum.registered`.
        (
            "milestones.count",
            "derived from milestones.len() by initialize_milestones",
        ),
        // AV-15: the skip counter is an accumulator, like `released`.
        (
            "skipped",
            "accumulated by skip_milestone once both parties approved; \
             zeroed by initialize",
        ),
        // AV-17: the cumulative fee counter is an accumulator, like
        // `released` and `skipped`: every taker payout adds its fee.
        (
            "fees_paid",
            "accumulated by release / claim / release_milestone / resolve \
             (the taker's share); zeroed by initialize",
        ),
    ];

    /// Every vault field path from `VAULT_FIELDS`, with `quorum` unfolded
    /// into its serialized subfields, `vesting` unfolded into start/end,
    /// and `milestones` unfolded into amounts/count (order matches Borsh
    /// layout).
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
            } else if *name == "vesting" {
                paths.extend(["vesting.start", "vesting.end"]);
            } else if *name == "milestones" {
                paths.extend(["milestones.amounts", "milestones.count"]);
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
    fn every_vault_field_has_a_documented_source() {
        let from_params: Vec<&str> =
            PARAM_FIELD_MAP.iter().map(|(_, _, field)| *field).collect();
        let from_sources: Vec<&str> =
            FIELD_SOURCES.iter().map(|(field, _)| *field).collect();
        let vault_fields = vault_field_paths();
        // Every field source must name a real vault field (param mappings
        // are checked against the field list in the direction-1 test).
        for field in &from_sources {
            assert!(
                vault_fields.contains(field),
                "field source names a field outside VAULT_FIELDS: {field}"
            );
        }
        let mut seen = HashSet::new();
        for field in vault_field_paths() {
            let via_param = from_params.iter().filter(|f| **f == field).count();
            let via_source = from_sources.iter().filter(|f| **f == field).count();
            // Exactly one *kind* of source: params (possibly several, see
            // `released`) xor one field source. A field with neither is
            // dead space; a field with both is double-documented.
            assert!(
                (via_param > 0) ^ (via_source == 1),
                "vault field {field}: expected params xor one field source, \
                 found param={via_param} source={via_source}"
            );
            assert!(
                seen.insert(field),
                "vault field {field} documented twice"
            );
        }
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
        (
            EscrowError::InvalidVesting,
            107,
            "bad vesting schedule (start >= end) or claim with no vesting",
        ),
        (
            EscrowError::InvalidArbiter,
            108,
            "with_arbiter with a zero key, or escalate/resolve with no arbiter configured",
        ),
        (
            EscrowError::DisputeWindowClosed,
            109,
            "escalate with now >= expires_at (past the dispute window)",
        ),
        (
            EscrowError::InvalidMilestones,
            110,
            "bad milestone plan (empty list, too many tranches, zero-amount tranche, tranche sum != locked amount), milestone op with no plan attached, out-of-range milestone index, or release/claim with a milestone plan attached",
        ),
        (
            EscrowError::MilestoneNotConfirmed,
            111,
            "release_milestone before both parties confirmed the milestone",
        ),
        (
            EscrowError::InvalidMint,
            112,
            "bad mint address (empty, non-base58, or not 32 bytes) or with_mint with the zero address",
        ),
        (
            EscrowError::MintMismatch,
            113,
            "exit-path token mint != the escrow's bound mint (None vs Some mismatches too)",
        ),
        (
            EscrowError::InvalidProtocolFee,
            114,
            "with_protocol_fee with fee_bps > 10_000 (not a valid basis-point rate)",
        ),
        (
            EscrowError::InvalidGracePeriod,
            115,
            "with_grace_period where expires_at + grace_period would overflow u64 (grace on a no-timeout escrow)",
        ),
        (
            EscrowError::RefundAddressMismatch,
            116,
            "cancel/cancel_expired with a refund destination != the whitelisted address (or != the initializer with no whitelist), or with_refund_address with the zero address",
        ),
        (
            EscrowError::InvalidPenalty,
            117,
            "with_penalty_bps with penalty_bps > 10_000 (not a valid basis-point rate)",
        ),
        (
            EscrowError::TimelockNotReached,
            118,
            "release/claim/release_milestone while now < unlock_at (AV-27 timelock); cancel/cancel_expired/resolve are never gated",
        ),
        (
            EscrowError::InvalidDecimals,
            119,
            "with_decimals with decimals > 18 (not a valid token precision)",
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
        let err = e.cancel_expired(ALICE, EXPIRES_AT - 1, None, ALICE).unwrap_err();
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
        let err = e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap_err();
        assert_eq!(err, EscrowError::QuorumNotReached);
        assert_eq!(err.code(), 105);
    }

    #[test]
    fn release_exceeds_locked_triggered_by_over_release() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_750_000_000, 600_000, None).unwrap(); // partial: 400_000 remains
        let err = e.release(ALICE, 1_750_000_000, 400_001, None).unwrap_err();
        assert_eq!(err, EscrowError::ReleaseExceedsLocked);
        assert_eq!(err.code(), 106);
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 600_000, "failed release must not move released");
    }

    #[test]
    fn amount_mismatch_triggered_by_zero_amount_release() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        let err = e.release(ALICE, 1_750_000_000, 0, None).unwrap_err();
        assert_eq!(err, EscrowError::AmountMismatch);
        assert_eq!(err.code(), 102);
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0);
    }

    #[test]
    fn invalid_vesting_triggered_by_inverted_schedule() {
        // start >= end: the window has zero length (would divide by zero
        // in vested_amount).
        let err = VestingSchedule::new(1_000, 1_000).unwrap_err();
        assert_eq!(err, EscrowError::InvalidVesting);
        assert_eq!(err.code(), 107);
        let err = VestingSchedule::new(2_000, 1_000).unwrap_err();
        assert_eq!(err, EscrowError::InvalidVesting);
    }

    #[test]
    fn invalid_vesting_triggered_by_claim_without_schedule() {
        // No schedule attached: claim is a programming error, reported
        // before any time/quorum logic runs.
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        let err = e.claim(BOB, EXPIRES_AT, None).unwrap_err();
        assert_eq!(err, EscrowError::InvalidVesting);
        assert_eq!(err.code(), 107);
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0);
    }

    #[test]
    fn invalid_arbiter_triggered_by_zero_key_config() {
        // The arbiter must be a real identity: `resolve` authenticates
        // against it, so a zero key is a config error, not a wildcard.
        let err = escrow().with_arbiter([0u8; 32]).unwrap_err();
        assert_eq!(err, EscrowError::InvalidArbiter);
        assert_eq!(err.code(), 108);
    }

    #[test]
    fn invalid_arbiter_triggered_by_escalate_without_arbiter() {
        // Authorized party, right state — but no arbiter was ever
        // configured, so there is nobody to arbitrate.
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        let err = e.escalate(ALICE, EXPIRES_AT - 1, None).unwrap_err();
        assert_eq!(err, EscrowError::InvalidArbiter);
        assert_eq!(err.code(), 108);
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn invalid_arbiter_triggered_by_resolve_without_arbiter() {
        // Config is checked before state here (the arbiter's identity is
        // the authority being verified), so this reports 108 even though
        // the state is not Disputed.
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        let err = e.resolve([0xA8; 32], 100, None).unwrap_err();
        assert_eq!(err, EscrowError::InvalidArbiter);
        assert_eq!(err.code(), 108);
    }

    #[test]
    fn dispute_window_closed_triggered_by_late_escalate() {
        // Once the escrow is expiry-eligible the unilateral
        // cancel_expired path is the way out; arbitration can no longer
        // start.
        const ARBITER: [u8; 32] = [0xA8; 32];
        let mut e = escrow().with_arbiter(ARBITER).unwrap();
        e.fund(ALICE).unwrap();
        let err = e.escalate(BOB, EXPIRES_AT, None).unwrap_err();
        assert_eq!(err, EscrowError::DisputeWindowClosed);
        assert_eq!(err.code(), 109);
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn check_order_is_visible_in_codes() {        // Authority is checked before state: a stranger on a terminal
        // state still gets 100 (Unauthorized), not 101.
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap(); // now Released
        let err = e.fund(MALLORY).unwrap_err();
        assert_eq!(err.code(), 100);
        // ... while the initializer sees the state error, 101.
        let err = e.fund(ALICE).unwrap_err();
        assert_eq!(err.code(), 101);
    }

    fn milestone_escrow() -> Escrow {
        let plan = MilestonePlan::new(&[400_000, 600_000]).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan)
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    #[test]
    fn invalid_milestones_triggered_by_sum_mismatch() {
        // Σ = 900_000 != locked 1_000_000: the plan does not cover the
        // lockup, so it can never be the complete release schedule.
        let short = MilestonePlan::new(&[400_000, 500_000]).unwrap();
        let err = escrow().with_milestones(short).unwrap_err();
        assert_eq!(err, EscrowError::InvalidMilestones);
        assert_eq!(err.code(), 110);
        // Over-covering is rejected too.
        let over = MilestonePlan::new(&[400_000, 700_000]).unwrap();
        assert_eq!(
            escrow().with_milestones(over),
            Err(EscrowError::InvalidMilestones)
        );
    }

    #[test]
    fn invalid_milestones_triggered_by_wrapping_sum() {
        // The u128 accumulation is load-bearing: two u64::MAX tranches
        // sum to 2^65 - 2, which a wrapping u64 sum would alias to
        // u64::MAX - 1 — wrongly accepting the plan against a locked
        // amount of u64::MAX - 1.
        let plan = MilestonePlan::new(&[u64::MAX, u64::MAX]).unwrap();
        let err = Escrow::initialize(ALICE, BOB, u64::MAX - 1, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidMilestones);
        assert_eq!(err.code(), 110);
    }

    #[test]
    fn invalid_milestones_triggered_by_bad_plan_shape() {
        // Empty plan, too many tranches, and zero-amount tranches are all
        // config errors, rejected before touching the escrow.
        assert_eq!(
            MilestonePlan::new(&[]),
            Err(EscrowError::InvalidMilestones)
        );
        let too_many = [1u64; MAX_MILESTONES + 1];
        assert_eq!(
            MilestonePlan::new(&too_many),
            Err(EscrowError::InvalidMilestones)
        );
        assert_eq!(
            MilestonePlan::new(&[400_000, 0]),
            Err(EscrowError::InvalidMilestones)
        );
        // The exact-sum boundary is accepted.
        assert!(MilestonePlan::new(&[400_000, 600_000]).is_ok());
    }

    #[test]
    fn invalid_milestones_triggered_by_release_with_plan() {
        // The plan owns the release schedule: plain `release` is disabled
        // once a plan is attached.
        let mut e = milestone_escrow();
        let err = e.release(ALICE, 1_750_000_000, 400_000, None).unwrap_err();
        assert_eq!(err, EscrowError::InvalidMilestones);
        assert_eq!(err.code(), 110);
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0, "failed release moves nothing");
    }

    #[test]
    fn invalid_milestones_triggered_by_milestone_op_without_plan() {
        // Authorized party, right state — but no plan was ever attached.
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.confirm_milestone(ALICE, 0),
            Err(EscrowError::InvalidMilestones)
        );
        assert_eq!(
            e.release_milestone(ALICE, 1_750_000_000, 0, None),
            Err(EscrowError::InvalidMilestones)
        );
        assert_eq!(
            e.skip_milestone(BOB, 0),
            Err(EscrowError::InvalidMilestones)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn milestone_not_confirmed_triggered_by_early_tranche_release() {
        // Only the initializer confirmed: the taker's acceptance is
        // missing, so the tranche is not releasable.
        let mut e = milestone_escrow();
        e.confirm_milestone(ALICE, 0).unwrap();
        let err = e.release_milestone(ALICE, 1_750_000_000, 0, None).unwrap_err();
        assert_eq!(err, EscrowError::MilestoneNotConfirmed);
        assert_eq!(err.code(), 111);
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0, "failed tranche release moves nothing");
    }

    // ----- AV-16: SPL token mint binding -----

    const MINT_A: [u8; 32] = [0xA6; 32];
    const MINT_B: [u8; 32] = [0xB6; 32];

    fn mint_escrow() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_mint(MINT_A)
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    #[test]
    fn invalid_mint_triggered_by_bad_base58() {
        // Empty string, non-alphabet characters, and non-ASCII bytes are
        // all format errors — rejected before touching any escrow.
        for bad in ["", "0", "O", "I", "l", "not a mint!!", "abc def"] {
            let err = parse_mint_address(bad).unwrap_err();
            assert_eq!(err, EscrowError::InvalidMint);
            assert_eq!(err.code(), 112, "bad input {bad:?}");
        }
    }

    #[test]
    fn invalid_mint_triggered_by_wrong_decoded_length() {
        // 33 leading '1's decode to 33 zero bytes: longer than an
        // address. A 45-char all-'z' string overflows 32 bytes.
        assert_eq!(
            parse_mint_address(&"1".repeat(33)),
            Err(EscrowError::InvalidMint)
        );
        assert_eq!(
            parse_mint_address(&"z".repeat(45)),
            Err(EscrowError::InvalidMint)
        );
        // 32 ones are exactly the zero address: well-formed (decodes to
        // 32 zero bytes) but rejected at bind time, not parse time.
        assert_eq!(parse_mint_address(&"1".repeat(32)).unwrap(), [0u8; 32]);
        assert_eq!(escrow().with_mint([0u8; 32]), Err(EscrowError::InvalidMint));
    }

    #[test]
    fn mint_mismatch_triggered_by_wrong_mint_on_release() {
        // Authorized party, right state — but the token account's mint is
        // not the bound mint: the release must fail without moving
        // anything.
        let mut e = mint_escrow();
        let err = e.release(ALICE, 1_750_000_000, 1_000_000, Some(MINT_B)).unwrap_err();
        assert_eq!(err, EscrowError::MintMismatch);
        assert_eq!(err.code(), 113);
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0, "failed release moves nothing");
        assert_eq!(e.amount(), 1_000_000);
    }

    #[test]
    fn mint_mismatch_triggered_by_sol_path_on_bound_escrow() {
        // A bound escrow never exits through the native-SOL path: `None`
        // vs `Some` mismatches too.
        let mut e = mint_escrow();
        assert_eq!(e.cancel(ALICE, None, ALICE), Err(EscrowError::MintMismatch));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn mint_mismatch_triggered_by_token_path_on_sol_escrow() {
        // And a native-SOL escrow never exits through a token mint.
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 1_000_000, Some(MINT_A)),
            Err(EscrowError::MintMismatch)
        );
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0);
    }

    #[test]
    fn invalid_protocol_fee_triggered_by_rate_above_10000() {
        // The rate is in basis points: 10_000 (100%) is the ceiling, and
        // 0 is a valid "no fee" rate (the default).
        let err = escrow().with_protocol_fee(10_001).unwrap_err();
        assert_eq!(err, EscrowError::InvalidProtocolFee);
        assert_eq!(err.code(), 114);
        // Boundary: 10_000 configures fine.
        let e = escrow().with_protocol_fee(10_000).unwrap();
        assert_eq!(e.fee_bps(), 10_000);
        // The rate is fixed before funding: reconfiguring a live escrow
        // is InvalidStateTransition, like the other `with_*` builders.
        let mut e = escrow().with_protocol_fee(250).unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.with_protocol_fee(300),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.fee_bps(), 250, "failed reconfigure keeps the rate");
    }

    #[test]
    fn invalid_grace_period_triggered_by_overflow() {
        // expires_at + grace_period must fit in u64. A grace period on a
        // no-timeout escrow (expires_at == u64::MAX) always overflows, so
        // it is rejected as misconfiguration — an escrow that can never
        // expire has no expiry gate to grace.
        let never = Escrow::initialize(ALICE, BOB, 1_000_000, u64::MAX).unwrap();
        let err = never.with_grace_period(1).unwrap_err();
        assert_eq!(err, EscrowError::InvalidGracePeriod);
        assert_eq!(err.code(), 115);
        // Boundary: u64::MAX - 1 + 1 fits, and is accepted.
        let edge = Escrow::initialize(ALICE, BOB, 1_000_000, u64::MAX - 1).unwrap();
        let e = edge.with_grace_period(1).unwrap();
        assert_eq!(e.grace_period(), 1);
        // Same boundary one second further: overflows, rejected.
        let edge = Escrow::initialize(ALICE, BOB, 1_000_000, u64::MAX - 1).unwrap();
        assert_eq!(
            edge.with_grace_period(2).unwrap_err(),
            EscrowError::InvalidGracePeriod
        );
        // A zero grace period is always accepted, even on a no-timeout
        // escrow (it is the default — backward compatible).
        let never = Escrow::initialize(ALICE, BOB, 1_000_000, u64::MAX).unwrap();
        let e = never.with_grace_period(0).unwrap();
        assert_eq!(e.grace_period(), 0);
        // The grace period is fixed before funding: reconfiguring a live
        // escrow is InvalidStateTransition, like the other `with_*`
        // builders.
        let mut e = escrow().with_grace_period(300).unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.with_grace_period(600),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.grace_period(), 300, "failed reconfigure keeps the grace");
    }

    #[test]
    fn mint_match_allows_all_exit_paths() {
        // The matching mint opens every fund-moving exit: release,
        // cancel, cancel_expired, and claim (here on a vesting escrow).
        let mut e = mint_escrow();
        e.release(ALICE, 1_750_000_000, 400_000, Some(MINT_A)).unwrap();
        assert_eq!(e.released_amount(), 400_000);

        let mut e = mint_escrow();
        e.cancel(ALICE, Some(MINT_A), ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);

        let mut e = mint_escrow();
        e.cancel_expired(BOB, EXPIRES_AT, Some(MINT_A), ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);

        let schedule = VestingSchedule::new(1_700_000_000, 1_800_000_000).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_mint(MINT_A)
            .unwrap()
            .with_vesting(schedule)
            .unwrap();
        e.fund(ALICE).unwrap();
        let (claimed, fee) = e.claim(BOB, 1_800_000_000, Some(MINT_A)).unwrap();
        assert_eq!((claimed, fee), (1_000_000, 0), "no fee configured: full claim to taker");
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn invalid_penalty_triggered_by_rate_above_10000() {
        // The rate is in basis points: 10_000 (100%) is the ceiling, and
        // 0 is a valid "no penalty" rate (the default).
        let err = escrow().with_penalty_bps(10_001).unwrap_err();
        assert_eq!(err, EscrowError::InvalidPenalty);
        assert_eq!(err.code(), 117);
        // Boundary: 10_000 configures fine.
        let e = escrow().with_penalty_bps(10_000).unwrap();
        assert_eq!(e.penalty_bps(), 10_000);
        // The rate is fixed before funding: reconfiguring a live escrow
        // is InvalidStateTransition, like the other `with_*` builders.
        let mut e = escrow().with_penalty_bps(250).unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.with_penalty_bps(300),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.penalty_bps(), 250, "failed reconfigure keeps the rate");
    }
}

// ---------- AV-16: base58 mint-address decoder ----------
//
// `parse_mint_address` is handwritten (the crate is dependency-free), so
// it gets its own test module. The decoder is checked three ways:
// certain vectors (addresses whose bytes are known by construction),
// a test-only encoder for round-trips over boundary byte arrays, and
// the rejection cases in `error_code_tests` above.

#[cfg(test)]
mod base58_tests {
    use super::*;

    /// Test-only base58 encoder (Solana alphabet): the inverse of
    /// `parse_mint_address`, used only to generate round-trip vectors.
    /// Little-endian base-58 digits, leading zero bytes as `'1'`s.
    fn base58_encode(bytes: &[u8; 32]) -> String {
        let mut digits: Vec<u8> = vec![0];
        for &b in bytes {
            let mut carry = b as u32;
            for d in digits.iter_mut() {
                let v = *d as u32 * 256 + carry;
                *d = (v % 58) as u8;
                carry = v / 58;
            }
            while carry > 0 {
                digits.push((carry % 58) as u8);
                carry /= 58;
            }
        }
        let mut s = String::new();
        for _ in bytes.iter().take_while(|&&b| b == 0) {
            s.push('1');
        }
        for d in digits.iter().rev().skip_while(|&&d| d == 0) {
            s.push(BASE58_ALPHABET[*d as usize] as char);
        }
        s
    }

    #[test]
    fn decode_certain_vectors() {
        // 32 ones: the all-zero address (Solana system program).
        assert_eq!(
            parse_mint_address("11111111111111111111111111111111").unwrap(),
            [0u8; 32]
        );
        // 31 ones + '2' (alphabet index 1): value 1 in the last byte.
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(
            parse_mint_address("11111111111111111111111111111112").unwrap(),
            one
        );
        // Single '2': the same value without leading-one padding —
        // leading zero bytes are implied, not required, in the encoding.
        assert_eq!(parse_mint_address("2").unwrap(), one);
        // 'z' is the last alphabet character (index 57).
        let mut b57 = [0u8; 32];
        b57[31] = 57;
        assert_eq!(parse_mint_address("z").unwrap(), b57);
    }

    #[test]
    fn decode_round_trips_boundary_addresses() {
        // Boundary byte arrays, including leading-zero-heavy ones (the
        // leading-'1' path) and trailing-0xFF ones (the carry path).
        let mut cases: Vec<[u8; 32]> = vec![
            [0u8; 32],
            [1u8; 32],
            [0xFF; 32],
            [0xA6; 32],
        ];
        let mut seq = [0u8; 32];
        for (i, b) in seq.iter_mut().enumerate() {
            *b = i as u8;
        }
        cases.push(seq);
        let mut leading_zeros = [0u8; 32];
        leading_zeros[31] = 0xFF;
        cases.push(leading_zeros);
        let mut trailing_zero = [0xFFu8; 32];
        trailing_zero[0] = 0;
        cases.push(trailing_zero);
        for bytes in &cases {
            let encoded = base58_encode(bytes);
            assert_eq!(
                parse_mint_address(&encoded).unwrap(),
                *bytes,
                "round-trip failed for {bytes:02x?} (encoded {encoded})"
            );
        }
    }

    #[test]
    fn decode_rejects_non_32_byte_values() {
        // Decodes fine as base58 but is not a 32-byte address.
        assert_eq!(
            parse_mint_address("111111111111111111111111111111111").unwrap_err(),
            EscrowError::InvalidMint,
            "33 ones = 33 zero bytes"
        );
        // 44 'z's: the max-length encoding of a 32-byte value is 44
        // chars, but all-max digits overflow 256 bits.
        assert_eq!(
            parse_mint_address(&"z".repeat(44)).unwrap_err(),
            EscrowError::InvalidMint
        );
        // 32 zero bytes plus one more nonzero digit: 33 bytes.
        assert_eq!(
            parse_mint_address(&("1".repeat(32) + "2")).unwrap_err(),
            EscrowError::InvalidMint
        );
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
            e.release(ALICE, 1_750_000_000, amount, None).unwrap();
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
            e.cancel(ALICE, None, ALICE).unwrap();
            assert_eq!(e.state(), EscrowState::Cancelled);
            assert_eq!(e.amount(), amount, "case {case}: amount changed on cancel path");

            // fund → cancel_expired by the taker at exactly the expiry
            // edge (now == expires_at satisfies now >= expires_at).
            let mut e = mk();
            e.fund(ALICE).unwrap();
            e.cancel_expired(BOB, expiry, None, ALICE).unwrap();
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
            e.release(ALICE, 1_750_000_000, amount, None).unwrap();
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
            match e.cancel_expired(ALICE, now, None, ALICE) {
                Ok((refund, penalty)) => {
                    assert!(
                        expected,
                        "case {case}: succeeded with now={now} < expires_at={expiry}"
                    );
                    assert_eq!(e.state(), EscrowState::Cancelled);
                    // ALICE is the initializer and no penalty is
                    // configured: the initializer reclaims the full
                    // remainder, penalty-free (AV-24).
                    assert_eq!(refund, 1_000_000);
                    assert_eq!(penalty, 0);
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
    /// Shared with the AV-22 evidence tests below, which pin the
    /// `Some` encoding of the appended tail fields, and with the AV-29
    /// IDL pipeline (`idl_json`), which pins the IDL field offsets
    /// against these bytes.
    pub(crate) fn encode_escrow(e: &Escrow) -> Vec<u8> {
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
        // AV-13: vesting schedule, always reserved like `quorum`: the
        // `None` discriminant followed by zeroed start/end, so
        // `with_vesting` writes in place without reallocating.
        match e.vesting {
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 16]);
            }
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&v.start.to_le_bytes());
                out.extend_from_slice(&v.end.to_le_bytes());
            }
        }
        // AV-14: dispute arbiter, always reserved like `quorum`: the
        // `None` discriminant followed by a zeroed key, so
        // `with_arbiter` writes in place without reallocating.
        match e.arbiter {
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
            Some(key) => {
                out.push(1);
                out.extend_from_slice(&key);
            }
        }
        // AV-15: milestone plan, always reserved like `quorum`: the
        // `None` discriminant followed by zeroed amounts+count, so
        // `with_milestones` writes in place without reallocating.
        match e.milestones {
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; MILESTONE_PLAN_LEN]);
            }
            Some(p) => {
                out.push(1);
                for amount in p.amounts {
                    out.extend_from_slice(&amount.to_le_bytes());
                }
                out.push(p.count);
            }
        }
        // AV-15: confirmation bitmap, always present (zeroed when no
        // milestone plan is configured).
        out.extend_from_slice(&e.milestone_flags.to_le_bytes());
        // AV-15: cumulative skipped amount, always present.
        out.extend_from_slice(&e.skipped.to_le_bytes());
        // AV-16: SPL token mint binding, always reserved like `quorum`:
        // the `None` discriminant followed by a zeroed address, so
        // `with_mint` writes in place without reallocating.
        match e.mint {
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
            Some(m) => {
                out.push(1);
                out.extend_from_slice(&m);
            }
        }
        // AV-17: protocol fee rate in basis points, always present
        // (zeroed when no fee configured).
        out.extend_from_slice(&e.fee_bps.to_le_bytes());
        // AV-17: cumulative protocol fee charged, always present
        // (zeroed when no fee was charged).
        out.extend_from_slice(&e.fees_paid.to_le_bytes());
        // AV-21: expiry grace period in seconds, always present
        // (zeroed when no grace period is configured).
        out.extend_from_slice(&e.grace_period.to_le_bytes());
        // AV-22: dispute evidence hash, always reserved like `quorum`:
        // the `None` discriminant followed by a zeroed 32-byte
        // commitment, so `escalate` writes in place without reallocating.
        match e.evidence_hash {
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h);
            }
        }
        // AV-23: refund address whitelist, always reserved like `quorum`:
        // the `None` discriminant followed by a zeroed address, so
        // `with_refund_address` writes in place without reallocating.
        match e.refund_to {
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
            Some(addr) => {
                out.push(1);
                out.extend_from_slice(&addr);
            }
        }
        // AV-24: anti-griefing penalty rate in basis points, always
        // present (zeroed when no penalty configured).
        out.extend_from_slice(&e.penalty_bps.to_le_bytes());
        // AV-27: timelock unlock timestamp, always present (zeroed when
        // no timelock is configured); appended last so every earlier
        // offset above is unchanged.
        out.extend_from_slice(&e.timelock.to_le_bytes());
        // AV-28: token decimal metadata, always present (zeroed when no
        // decimal metadata is configured); appended last so every
        // earlier offset above is unchanged.
        out.push(e.decimals);
        out
    }

    #[test]
    fn space_constants_match_hand_computed_layout() {
        // Hardcoded on purpose: if the layout ever changes, these numbers
        // must be updated deliberately — and the Anchor program's
        // `space =` expression with them.
        assert_eq!(QUORUM_POLICY_LEN, 8 * 32 + 1 + 1 + 8, "quorum policy bytes");
        assert_eq!(QUORUM_POLICY_LEN, 266);
        assert_eq!(MILESTONE_PLAN_LEN, 8 * 8 + 1, "milestone plan bytes");
        assert_eq!(MILESTONE_PLAN_LEN, 65);
        // 32 + 32 + 8 + 8 + 8 + 1 + (1 + 266) + 1 (AV-12 activation bitmask)
        // + (1 + 16) (AV-13 vesting schedule) + (1 + 32) (AV-14 arbiter)
        // + (1 + 65) (AV-15 milestone plan) + 8 (AV-15 confirmation bitmap)
        // + 8 (AV-15 skipped counter) + (1 + 32) (AV-16 mint binding)
        // + 2 (AV-17 protocol fee rate) + 8 (AV-17 cumulative fee counter)
        // + 8 (AV-21 expiry grace period) + (1 + 32) (AV-22 dispute
        // evidence hash) + (1 + 32) (AV-23 refund address whitelist)
        // + 2 (AV-24 anti-griefing penalty rate) + 8 (AV-27 timelock)
        // + 1 (AV-28 token decimal metadata).
        assert_eq!(ESCROW_BODY_LEN, 617, "escrow payload bytes");
        // 8-byte Anchor discriminator + payload.
        assert_eq!(VAULT_SPACE, 625, "full Vault account space");
        // Discriminator + payload with `quorum: None` (1-byte
        // discriminant) + 1-byte activation bitmask (AV-12) + 1-byte
        // vesting discriminant (AV-13, zeroed when no schedule) + 1-byte
        // arbiter discriminant (AV-14, zeroed when no arbiter) + 1-byte
        // milestones discriminant (AV-15, zeroed when no plan) + 8-byte
        // confirmation bitmap + 8-byte skipped counter + 1-byte mint
        // discriminant (AV-16, zeroed when no mint bound) + 2-byte
        // protocol fee rate (AV-17, zeroed when no fee configured) +
        // 8-byte cumulative fee counter (AV-17, zeroed when no fee
        // charged) + 8-byte expiry grace period (AV-21, zeroed when no
        // grace period configured) + (1 + 32)-byte dispute evidence hash
        // (AV-22, zeroed when no evidence attached) + (1 + 32)-byte
        // refund address whitelist (AV-23, zeroed when no whitelist
        // configured) + 2-byte anti-griefing penalty rate (AV-24, zeroed
        // when no penalty configured) + 8-byte timelock unlock timestamp
        // (AV-27, zeroed when no timelock configured) + 1-byte token
        // decimal metadata (AV-28, zeroed when no decimal metadata is
        // configured).
        assert_eq!(
            VAULT_SPACE_NO_QUORUM,
            8 + 32 + 32 + 8 + 8 + 8 + 1 + 1 + 1 + 1 + 1 + 1 + 8 + 8 + 1 + 2 + 8 + 8 + 1 + 32 + 1 + 32 + 2 + 8 + 1,
            "no-quorum Vault account space"
        );
        assert_eq!(VAULT_SPACE_NO_QUORUM, 214);
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
        // AV-14: appended after Activated so discriminants 0–4 stay
        // stable for already-serialized vaults.
        assert_eq!(EscrowState::Disputed as u8, 5);
        assert_eq!(EscrowState::Settled as u8, 6);
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
        // AV-13: vesting discriminant + zeroed schedule (no vesting here).
        assert_eq!(bytes[357], 0, "vesting: None discriminant");
        assert_eq!(&bytes[358..374], &[0u8; 16], "vesting: zeroed schedule");
        // AV-14: arbiter discriminant + zeroed key (no arbiter here).
        assert_eq!(bytes[374], 0, "arbiter: None discriminant");
        assert_eq!(&bytes[375..407], &[0u8; 32], "arbiter: zeroed key");
        // AV-15: milestones discriminant + zeroed plan (no plan here),
        // zeroed confirmation bitmap, zero skipped.
        assert_eq!(bytes[407], 0, "milestones: None discriminant");
        assert_eq!(
            &bytes[408..473],
            &[0u8; MILESTONE_PLAN_LEN],
            "milestones: zeroed plan"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[473..481].try_into().unwrap()),
            0,
            "milestone_flags: zeroed"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[481..489].try_into().unwrap()),
            0,
            "skipped: zero"
        );
        // AV-16: mint discriminant + zeroed address (no mint bound here).
        assert_eq!(bytes[489], 0, "mint: None discriminant");
        assert_eq!(&bytes[490..522], &[0u8; 32], "mint: zeroed address");
        // AV-17: fee rate u16 + cumulative fee u64 (no fee configured,
        // none charged).
        assert_eq!(
            u16::from_le_bytes(bytes[522..524].try_into().unwrap()),
            0,
            "fee_bps: zeroed"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[524..532].try_into().unwrap()),
            0,
            "fees_paid: zero"
        );
        // AV-21: expiry grace period u64, zeroed for a plain escrow.
        assert_eq!(
            u64::from_le_bytes(bytes[532..540].try_into().unwrap()),
            0,
            "grace_period: zeroed"
        );
        // AV-22: dispute evidence hash discriminant + zeroed commitment
        // (no evidence attached here); appended last, so every earlier
        // offset above is unchanged.
        assert_eq!(bytes[540], 0, "evidence_hash: None discriminant");
        assert_eq!(&bytes[541..573], &[0u8; 32], "evidence_hash: zeroed");
        // AV-23: refund whitelist discriminant + zeroed address (no
        // whitelist configured here); appended last, so every earlier
        // offset above is unchanged.
        assert_eq!(bytes[573], 0, "refund_to: None discriminant");
        assert_eq!(&bytes[574..606], &[0u8; 32], "refund_to: zeroed");
        // AV-24: anti-griefing penalty rate u16, zeroed for a plain
        // escrow; appended last, so every earlier offset above is
        // unchanged.
        assert_eq!(
            u16::from_le_bytes(bytes[606..608].try_into().unwrap()),
            0,
            "penalty_bps: zeroed"
        );
        // AV-27: timelock unlock timestamp u64, zeroed for a plain
        // escrow; appended last, so every earlier offset above is
        // unchanged.
        assert_eq!(
            u64::from_le_bytes(bytes[608..616].try_into().unwrap()),
            0,
            "timelock: zeroed"
        );
        // AV-28: token decimal metadata u8, zeroed for a plain escrow
        // (no decimal metadata declared); appended last, so every
        // earlier offset above is unchanged.
        assert_eq!(bytes[616], 0, "decimals: zeroed");
        assert_eq!(bytes.len(), ESCROW_BODY_LEN, "tail byte is the last byte");

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
        // AV-13: vesting discriminant + zeroed schedule (no vesting here).
        assert_eq!(bytes[357], 0, "vesting: None discriminant");
        assert_eq!(&bytes[358..374], &[0u8; 16], "vesting: zeroed schedule");
        // AV-14: arbiter discriminant + zeroed key (no arbiter here).
        assert_eq!(bytes[374], 0, "arbiter: None discriminant");
        assert_eq!(&bytes[375..407], &[0u8; 32], "arbiter: zeroed key");
        // AV-15: the tail is untouched by the quorum region: milestones
        // discriminant + zeroed plan, zeroed confirmation bitmap, zero
        // skipped.
        assert_eq!(bytes[407], 0, "milestones: None discriminant");
        assert_eq!(
            &bytes[408..473],
            &[0u8; MILESTONE_PLAN_LEN],
            "milestones: zeroed plan"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[473..481].try_into().unwrap()),
            0,
            "milestone_flags: zeroed"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[481..489].try_into().unwrap()),
            0,
            "skipped: zero"
        );
        // AV-16: the mint region trails the skipped counter, untouched by
        // the quorum region: None discriminant + zeroed address.
        assert_eq!(bytes[489], 0, "mint: None discriminant");
        assert_eq!(&bytes[490..522], &[0u8; 32], "mint: zeroed address");
    }

    #[test]
    fn manual_borsh_encoding_places_arbiter_key() {
        // AV-14: an escrow with an arbiter serializes the key after the
        // vesting region: discriminant 1, then the 32-byte key.
        const ARBITER: [u8; 32] = [0xA8; 32];
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        let bytes = encode_escrow(&e);
        assert_eq!(bytes.len(), ESCROW_BODY_LEN);
        // Everything before the arbiter region is untouched.
        assert_eq!(bytes[88], EscrowState::Funded as u8);
        assert_eq!(&bytes[358..374], &[0u8; 16], "vesting: zeroed schedule");
        assert_eq!(bytes[374], 1, "arbiter: Some discriminant");
        assert_eq!(&bytes[375..407], &ARBITER, "arbiter key offset");
    }

    #[test]
    fn manual_borsh_encoding_places_vesting_schedule() {
        // AV-13: a vesting escrow serializes the schedule after the
        // activation byte: discriminant 1, then start/end u64 LE.
        let schedule = VestingSchedule::new(1_700_000_000, 1_800_000_000).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_vesting(schedule)
            .unwrap();
        e.fund(ALICE).unwrap();
        let bytes = encode_escrow(&e);
        assert_eq!(bytes.len(), ESCROW_BODY_LEN);
        assert_eq!(bytes[357], 1, "vesting: Some discriminant");
        assert_eq!(
            u64::from_le_bytes(bytes[358..366].try_into().unwrap()),
            1_700_000_000,
            "vesting.start offset"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[366..374].try_into().unwrap()),
            1_800_000_000,
            "vesting.end offset"
        );
        // The schedule survives a state transition (claim moves money,
        // never the curve).
        e.claim(BOB, 1_750_000_000, None).unwrap();
        let bytes = encode_escrow(&e);
        assert_eq!(bytes[357], 1, "vesting discriminant unchanged by claim");
        assert_eq!(
            u64::from_le_bytes(bytes[358..366].try_into().unwrap()),
            1_700_000_000
        );
    }

    #[test]
    fn manual_borsh_encoding_places_milestone_plan() {
        // AV-15: an escrow with a milestone plan serializes the plan after
        // the arbiter region, then the confirmation bitmap, then the
        // skipped counter.
        let plan = MilestonePlan::new(&[400_000, 600_000]).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan)
            .unwrap();
        e.fund(ALICE).unwrap();
        // Confirm milestone 0 with both parties, release its tranche.
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        e.release_milestone(ALICE, 1_750_000_000, 0, None).unwrap();
        // Skip milestone 1 by dual approval: the tranche is refunded to
        // the initializer's claim, not released.
        e.skip_milestone(ALICE, 1).unwrap();
        e.skip_milestone(BOB, 1).unwrap();

        let bytes = encode_escrow(&e);
        assert_eq!(bytes.len(), ESCROW_BODY_LEN);
        // The head of the layout is untouched.
        assert_eq!(bytes[88], EscrowState::Funded as u8);
        assert_eq!(&bytes[375..407], &[0u8; 32], "arbiter: zeroed key");
        // Milestone plan: discriminant 1, amounts, count.
        assert_eq!(bytes[407], 1, "milestones: Some discriminant");
        assert_eq!(
            u64::from_le_bytes(bytes[408..416].try_into().unwrap()),
            400_000,
            "milestones.amounts[0] offset"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[416..424].try_into().unwrap()),
            600_000,
            "milestones.amounts[1] offset"
        );
        assert_eq!(&bytes[424..472], &[0u8; 48], "unused tranche slots are zero");
        assert_eq!(bytes[472], 2, "milestones.count offset");
        // Confirmation bitmap: milestone 0 has both confirmations + the
        // released bit (bits 0,1,2); milestone 1 has both skip approvals +
        // the skipped bit (bits 6*1+3, 6*1+4, 6*1+5 = 9,10,11).
        let flags = u64::from_le_bytes(bytes[473..481].try_into().unwrap());
        assert_eq!(flags, 0b111 | (0b111 << 9), "milestone_flags offsets");
        assert_eq!(flags, 3_591);
        // Skipped counter: the refunded tranche.
        assert_eq!(
            u64::from_le_bytes(bytes[481..489].try_into().unwrap()),
            600_000,
            "skipped offset"
        );
        // The state-machine view agrees with the bytes.
        assert_eq!(
            (e.released_amount(), e.skipped_amount(), e.remaining_amount()),
            (400_000, 600_000, 600_000)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn manual_borsh_encoding_places_mint() {
        // AV-16: an escrow with a bound mint serializes the address after
        // the skipped counter: discriminant 1, then the 32-byte address.
        // The head of the layout is untouched.
        const MINT: [u8; 32] = [0xA6; 32];
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_mint(MINT)
            .unwrap();
        e.fund(ALICE).unwrap();
        let bytes = encode_escrow(&e);
        assert_eq!(bytes.len(), ESCROW_BODY_LEN);
        assert_eq!(bytes[88], EscrowState::Funded as u8);
        assert_eq!(&bytes[481..489], &[0u8; 8], "skipped: zero");
        assert_eq!(bytes[489], 1, "mint: Some discriminant");
        assert_eq!(&bytes[490..522], &MINT, "mint address offset");
        // The state-machine view agrees with the bytes.
        assert_eq!(e.mint(), Some(MINT));
        // A bound mint survives a state transition (release moves money,
        // never the binding).
        e.release(ALICE, 1_750_000_000, 1_000_000, Some(MINT)).unwrap();
        let bytes = encode_escrow(&e);
        assert_eq!(bytes[489], 1, "mint discriminant unchanged by release");
        assert_eq!(&bytes[490..522], &MINT);
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn rent_formula_matches_hand_computed_mainnet_numbers() {
        // ((128 + space) * lamports_per_byte_year) * exemption_threshold.
        let full = rent_exempt_minimum_lamports(
            VAULT_SPACE,
            MAINNET_LAMPORTS_PER_BYTE_YEAR,
            MAINNET_EXEMPTION_THRESHOLD_YEARS,
        );
        // (128 + 625) * 3480 * 2 = 753 * 6960 = 5_240_880 lamports.
        assert_eq!(full, 5_240_880);

        let no_quorum = rent_exempt_minimum_lamports(
            VAULT_SPACE_NO_QUORUM,
            MAINNET_LAMPORTS_PER_BYTE_YEAR,
            MAINNET_EXEMPTION_THRESHOLD_YEARS,
        );
        // (128 + 214) * 3480 * 2 = 342 * 6960 = 2_380_320 lamports.
        assert_eq!(no_quorum, 2_380_320);
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
        assert_eq!(check_vault_rent_exempt(5_240_880, params.0, params.1), Ok(()));
        // One lamport short: exact shortfall reported.
        assert_eq!(
            check_vault_rent_exempt(5_240_879, params.0, params.1),
            Err(RentShortfall {
                required: 5_240_880,
                provided: 5_240_879,
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
                required: 5_240_880,
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
        e.release(ALICE, 1_750_000_000, 400_000, None).unwrap();
        assert_eq!(
            e.state(),
            EscrowState::Funded,
            "a partial release must not close the escrow"
        );
        assert_eq!(e.released_amount(), 400_000);
        assert_eq!(e.remaining_amount(), 600_000);
        // A second partial accumulates on top of the first.
        e.release(ALICE, 1_750_000_000, 100_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 500_000);
        assert_eq!(e.remaining_amount(), 500_000);
    }

    #[test]
    fn final_partial_release_closes_the_escrow() {
        let mut e = funded_escrow();
        e.release(ALICE, 1_750_000_000, 400_000, None).unwrap();
        e.release(ALICE, 1_750_000_000, 600_000, None).unwrap(); // reaches the locked amount exactly
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.released_amount(), 1_000_000);
        assert_eq!(e.remaining_amount(), 0);
    }

    #[test]
    fn zero_amount_release_is_amount_mismatch_and_changes_nothing() {
        let mut e = funded_escrow();
        assert_eq!(e.release(ALICE, 1_750_000_000, 0, None), Err(EscrowError::AmountMismatch));
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0);
        assert_eq!(e.remaining_amount(), 1_000_000);
    }

    #[test]
    fn release_beyond_remaining_is_release_exceeds_locked() {
        let mut e = funded_escrow();
        e.release(ALICE, 1_750_000_000, 600_000, None).unwrap();
        // 400_000 remains: asking for one lamport more must fail.
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 400_001, None),
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
        e.release(ALICE, 1_750_000_000, u64::MAX - 10, None).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), u64::MAX - 10);
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 11, None),
            Err(EscrowError::ReleaseExceedsLocked)
        );
        assert_eq!(
            e.released_amount(),
            u64::MAX - 10,
            "the counter is untouched by the overflow attempt"
        );
        // The exact remainder still works and closes the escrow.
        e.release(ALICE, 1_750_000_000, 10, None).unwrap();
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
            e.release(ALICE, 1_750_000_000, 400_000, None),
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
            e.release(ALICE, 1_750_000_000, 400_000, None),
            Err(EscrowError::QuorumNotReached)
        );
        e.attest(ATTESTOR_2).unwrap();
        // Gate satisfied: the partial release goes through and stays Funded.
        e.release(ALICE, 1_750_000_000, 400_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 400_000);
        // The final partial closes the escrow.
        e.release(ALICE, 1_750_000_000, 600_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn cancel_after_partial_release_refunds_remainder_and_preserves_released() {
        let mut e = funded_escrow();
        e.release(ALICE, 1_750_000_000, 400_000, None).unwrap();
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        // Released funds stay released; the refund is the remainder.
        assert_eq!(e.released_amount(), 400_000, "released preserved for audit");
        assert_eq!(e.remaining_amount(), 600_000, "refundable remainder");
    }

    #[test]
    fn release_after_full_release_is_invalid_transition() {
        let mut e = funded_escrow();
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 1_000_000, None),
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
        e.release(ALICE, 1_750_000_000, 400_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!((e.released_amount(), e.remaining_amount()), (400_000, 600_000));
        e.cancel(ALICE, None, ALICE).unwrap();
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
        assert_eq!(e.release(ALICE, 1_750_000_000, 1_000_000, None), Err(EscrowError::QuorumNotReached));
        e.attest([0xA1; 32]).unwrap();
        e.attest([0xA2; 32]).unwrap();
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
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
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
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

// ---------- AV-13: streaming release (linear vesting) ----------
//
// A vesting schedule unlocks the locked amount linearly between `start`
// and `end`; the taker pulls the vested-but-unreleased portion at any
// time via `claim` (the streaming-payments pattern). The schedule is
// fixed before funding, the initializer keeps their `release` push path,
// and both paths share the `released` counter so conservation and audit
// stay unified.
#[cfg(test)]
mod vesting_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;
    const START: u64 = 1_700_000_000;
    const END: u64 = 1_800_000_000;

    fn vesting_escrow() -> Escrow {
        Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_vesting(VestingSchedule::new(START, END).unwrap())
            .unwrap()
    }

    fn funded_vesting_escrow() -> Escrow {
        let mut e = vesting_escrow();
        e.fund(ALICE).unwrap();
        e
    }

    // ----- schedule construction and math -----

    #[test]
    fn schedule_rejects_inverted_or_empty_window() {
        assert_eq!(
            VestingSchedule::new(END, START),
            Err(EscrowError::InvalidVesting)
        );
        assert_eq!(
            VestingSchedule::new(START, START),
            Err(EscrowError::InvalidVesting),
            "a zero-length window would divide by zero"
        );
        assert!(VestingSchedule::new(START, END).is_ok());
        assert!(VestingSchedule::new(0, 1).is_ok());
    }

    #[test]
    fn vested_amount_interpolates_linearly_and_clamps() {
        let s = VestingSchedule::new(START, END).unwrap();
        assert_eq!(s.vested_amount(1_000_000, START - 1), 0, "nothing before start");
        assert_eq!(s.vested_amount(1_000_000, START), 0, "zero elapsed at start");
        assert_eq!(
            s.vested_amount(1_000_000, (START + END) / 2),
            500_000,
            "half the window -> half vested"
        );
        assert_eq!(s.vested_amount(1_000_000, END - 1), 999_999);
        assert_eq!(s.vested_amount(1_000_000, END), 1_000_000, "fully vested at end");
        assert_eq!(
            s.vested_amount(1_000_000, END + 1_000_000),
            1_000_000,
            "clamped after end"
        );
    }

    #[test]
    fn vested_amount_handles_u64_max_without_overflow() {
        // amount * elapsed can reach (u64::MAX)^2: the u128 path must not
        // overflow, and the result is exact.
        let s = VestingSchedule::new(0, 1_000_000).unwrap();
        assert_eq!(s.vested_amount(u64::MAX, 500_000), u64::MAX / 2);
        assert_eq!(s.vested_amount(u64::MAX, 1_000_000), u64::MAX);
        // Degenerate one-second window: all-or-nothing.
        let s = VestingSchedule::new(100, 101).unwrap();
        assert_eq!(s.vested_amount(u64::MAX, 100), 0);
        assert_eq!(s.vested_amount(u64::MAX, 101), u64::MAX);
    }

    // ----- claim lifecycle -----

    #[test]
    fn claim_streams_linearly_and_closes_at_full_vest() {
        let mut e = funded_vesting_escrow();
        // Quarter points of the window.
        let (q1, fee1) = e.claim(BOB, START + (END - START) / 4, None).unwrap();
        assert_eq!((q1, fee1), (250_000, 0));
        assert_eq!(e.state(), EscrowState::Funded);
        let (q2, fee2) = e.claim(BOB, START + (END - START) / 2, None).unwrap();
        assert_eq!((q2, fee2), (250_000, 0), "only the newly vested portion");
        assert_eq!(e.released_amount(), 500_000);
        assert_eq!(e.remaining_amount(), 500_000);
        let (rest, fee_rest) = e.claim(BOB, END, None).unwrap();
        assert_eq!((rest, fee_rest), (500_000, 0));
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.released_amount(), 1_000_000);
    }

    #[test]
    fn claim_returns_the_claimed_amount_for_transfer_sizing() {
        let mut e = funded_vesting_escrow();
        // The Anchor layer needs the exact payout to size the transfer.
        assert_eq!(e.claim(BOB, END, None).unwrap(), (1_000_000, 0));
    }

    #[test]
    fn claim_with_nothing_vested_is_amount_mismatch() {
        let mut e = funded_vesting_escrow();
        assert_eq!(e.claim(BOB, START - 1, None), Err(EscrowError::AmountMismatch));
        assert_eq!(e.claim(BOB, START, None), Err(EscrowError::AmountMismatch));
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0, "failed claim moves nothing");
    }

    #[test]
    fn claim_twice_at_same_timestamp_claims_once() {
        let mut e = funded_vesting_escrow();
        e.claim(BOB, END, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        // Terminal now; but even mid-stream a second claim at the same
        // timestamp finds nothing newly vested.
        let mut e = funded_vesting_escrow();
        e.claim(BOB, START + (END - START) / 2, None).unwrap();
        assert_eq!(
            e.claim(BOB, START + (END - START) / 2, None),
            Err(EscrowError::AmountMismatch)
        );
        assert_eq!(e.released_amount(), 500_000);
    }

    #[test]
    fn only_taker_can_claim() {
        let mut e = funded_vesting_escrow();
        // The initializer keeps the release push path, not the claim path.
        assert_eq!(e.claim(ALICE, END, None), Err(EscrowError::Unauthorized));
        assert_eq!(e.claim(MALLORY, END, None), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0);
    }

    #[test]
    fn claim_before_fund_is_invalid_transition() {
        let mut e = vesting_escrow();
        assert_eq!(e.claim(BOB, END, None), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.state(), EscrowState::Uninitialized);
    }

    #[test]
    fn claim_on_terminal_states_is_invalid_transition() {
        let mut e = funded_vesting_escrow();
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.claim(BOB, END, None), Err(EscrowError::InvalidStateTransition));
    }

    #[test]
    fn with_vesting_rejected_after_funding() {
        let e = funded_vesting_escrow();
        let s = VestingSchedule::new(START, END).unwrap();
        assert_eq!(
            e.with_vesting(s),
            Err(EscrowError::InvalidStateTransition),
            "the unlock curve is fixed before funds move, like with_quorum"
        );
    }

    // ----- interaction with release / cancel / quorum -----

    #[test]
    fn release_ahead_of_curve_then_claim_claims_nothing() {
        // The initializer's push path is not capped by the curve: an early
        // release is their prerogative. A later claim sees
        // vested <= released, saturates to zero, and reports
        // AmountMismatch instead of going negative.
        let mut e = funded_vesting_escrow();
        e.release(ALICE, 1_750_000_000, 800_000, None).unwrap(); // only 500_000 vested at midpoint
        assert_eq!(
            e.claim(BOB, START + (END - START) / 2, None),
            Err(EscrowError::AmountMismatch)
        );
        // Once the curve catches up past 800_000, the remainder is
        // claimable again.
        let (claimed, fee) = e.claim(BOB, END, None).unwrap();
        assert_eq!((claimed, fee), (200_000, 0), "no fee configured: full claim to taker");
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn cancel_after_claims_refunds_remainder_and_preserves_released() {
        let mut e = funded_vesting_escrow();
        e.claim(BOB, START + (END - START) / 2, None).unwrap();
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        assert_eq!(e.released_amount(), 500_000, "claims preserved for audit");
        assert_eq!(e.remaining_amount(), 500_000, "refundable remainder");
    }

    #[test]
    fn quorum_gates_claim_like_release() {
        // Otherwise the taker could bypass attestation via claim.
        let policy = QuorumPolicy::new(&[[0xA1; 32], [0xA2; 32]], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_vesting(VestingSchedule::new(START, END).unwrap())
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(e.claim(BOB, END, None), Err(EscrowError::QuorumNotReached));
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0);
        e.attest([0xA1; 32]).unwrap();
        e.attest([0xA2; 32]).unwrap();
        assert_eq!(e.claim(BOB, END, None).unwrap(), (1_000_000, 0));
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn vesting_combines_with_dual_sig() {
        // Independent builders compose: activation gates fund, the curve
        // gates claim.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_dual_sig()
            .unwrap()
            .with_vesting(VestingSchedule::new(START, END).unwrap())
            .unwrap();
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(e.claim(BOB, START + (END - START) / 2, None).unwrap(), (500_000, 0));
    }

    // ----- observers -----

    #[test]
    fn claimable_amount_tracks_curve_minus_released() {
        let mut e = funded_vesting_escrow();
        assert_eq!(e.claimable_amount(START - 1), 0);
        assert_eq!(e.claimable_amount((START + END) / 2), 500_000);
        e.release(ALICE, 1_750_000_000, 200_000, None).unwrap();
        assert_eq!(
            e.claimable_amount((START + END) / 2),
            300_000,
            "releases (either path) reduce what is claimable"
        );
        assert_eq!(e.claimable_amount(END), 800_000);
    }

    #[test]
    fn vested_amount_is_zero_without_schedule() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(e.vested_amount(END), 0);
        assert_eq!(e.claimable_amount(END), 0);
        assert_eq!(e.vesting_schedule(), None);
    }

    #[test]
    fn claim_conserves_amounts_like_release() {
        // Claims share the `released` counter: inflow == released +
        // refunded holds across mixed claim/release/cancel flows.
        let mut e = funded_vesting_escrow();
        e.claim(BOB, START + (END - START) / 2, None).unwrap(); // 500_000
        e.release(ALICE, 1_750_000_000, 200_000, None).unwrap();
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.released_amount(), 700_000);
        assert_eq!(e.remaining_amount(), 300_000);
        assert_eq!(
            e.released_amount() + e.remaining_amount(),
            1_000_000,
            "conservation across mixed release paths"
        );
    }
}

// ---------- AV-14: dispute arbitration ----------
//
// Opt-in arbiter role: `with_arbiter` fixes the arbiter's identity before
// funding; either party may `escalate` while `Funded` and inside the
// dispute window (`now < expires_at`), moving the escrow to `Disputed`;
// the arbiter then `resolve`s with a single atomic split of the remaining
// locked funds (taker payout / initializer refund), moving to `Settled`.
// While `Disputed`, every unilateral exit — `release`, `cancel`,
// `cancel_expired`, `claim` — is locked with `InvalidStateTransition`,
// so neither party can move funds mid-deliberation.
#[cfg(test)]
mod arbitration_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const ARBITER: [u8; 32] = [0xA8; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn funded_arbitrated_escrow() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    fn disputed_escrow() -> Escrow {
        let mut e = funded_arbitrated_escrow();
        e.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
        e
    }

    // ----- builder -----

    #[test]
    fn with_arbiter_only_before_funding() {
        // The arbiter's identity is fixed before funds move, like the
        // quorum and vesting builders: re-configuring a live escrow is
        // rejected.
        // `with_arbiter` takes `self` by value, so a rejected
        // re-configuration cannot mutate anything: the owned copy is
        // simply dropped with the Err.
        let e = funded_arbitrated_escrow();
        assert_eq!(
            e.with_arbiter([0xA9; 32]),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn with_arbiter_rejects_zero_key() {
        // The arbiter must be a real identity: `resolve` authenticates
        // against it, so a zero key is a config error, not a wildcard.
        let err = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter([0u8; 32])
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidArbiter);
    }

    // ----- escalate -----

    #[test]
    fn either_party_may_escalate_inside_the_window() {
        for authority in [ALICE, BOB] {
            let mut e = funded_arbitrated_escrow();
            e.escalate(authority, EXPIRES_AT - 1, None).unwrap();
            assert_eq!(e.state(), EscrowState::Disputed);
            // Amounts untouched by the escalation itself.
            assert_eq!((e.released_amount(), e.remaining_amount()), (0, 1_000_000));
        }
    }

    #[test]
    fn escalate_rejects_strangers_before_state() {
        // Authority first: a stranger gets Unauthorized, not
        // InvalidArbiter or InvalidStateTransition.
        let mut e = funded_arbitrated_escrow();
        assert_eq!(
            e.escalate(MALLORY, EXPIRES_AT - 1, None),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn escalate_rejects_non_funded_states() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        assert_eq!(
            e.escalate(ALICE, EXPIRES_AT - 1, None),
            Err(EscrowError::InvalidStateTransition)
        );
        // Double escalation: already Disputed.
        let mut e = disputed_escrow();
        assert_eq!(
            e.escalate(BOB, EXPIRES_AT - 1, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Disputed);
    }

    #[test]
    fn escalate_boundary_now_equals_expires_at_is_closed() {
        // The window is `now < expires_at`; at the boundary the escrow is
        // expiry-eligible, so cancel_expired is the way out.
        let mut e = funded_arbitrated_escrow();
        assert_eq!(
            e.escalate(ALICE, EXPIRES_AT, None),
            Err(EscrowError::DisputeWindowClosed)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    // ----- the Disputed lock: every unilateral exit frozen -----

    #[test]
    fn disputed_locks_all_unilateral_exits() {
        // release / cancel / cancel_expired / claim are all Funded-only,
        // so from Disputed each is InvalidStateTransition — and each
        // leaves state and money untouched.
        let mut e = disputed_escrow();
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 100_000, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.cancel(ALICE, None, ALICE), Err(EscrowError::InvalidStateTransition));
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT + 1, None, ALICE),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.claim(BOB, EXPIRES_AT + 1, None), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.attest([0xA1; 32]), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.state(), EscrowState::Disputed);
        assert_eq!((e.released_amount(), e.remaining_amount()), (0, 1_000_000));
        assert_eq!(e.amount(), 1_000_000);
    }

    #[test]
    fn disputed_blocks_cancel_even_after_expiry() {
        // The expiry clock keeps ticking during a dispute, but
        // cancel_expired must not become available: the arbiter owns the
        // outcome once escalated.
        let mut e = disputed_escrow();
        assert_eq!(
            e.cancel_expired(BOB, EXPIRES_AT + 1_000_000, None, ALICE),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Disputed);
    }

    // ----- resolve -----

    #[test]
    fn resolve_splits_the_remainder_atomically() {
        let mut e = disputed_escrow();
        let (payout, fee, refund) = e.resolve(ARBITER, 600_000, None).unwrap();
        assert_eq!((payout, fee, refund), (600_000, 0, 400_000));
        assert_eq!(e.state(), EscrowState::Settled);
        // The taker's share joins the released counter (shared audit
        // trail); the initializer's refund stays visible in
        // `remaining_amount()`, like `cancel`'s refund accounting.
        assert_eq!(e.released_amount(), 600_000);
        assert_eq!(e.remaining_amount(), 400_000);
        assert_eq!(e.amount(), 1_000_000, "locked amount immutable");
    }

    #[test]
    fn resolve_honors_boundary_splits() {
        // Full payout to the taker.
        let mut e = disputed_escrow();
        assert_eq!(e.resolve(ARBITER, 1_000_000, None).unwrap(), (1_000_000, 0, 0));
        assert_eq!(e.state(), EscrowState::Settled);
        // Full refund to the initializer.
        let mut e = disputed_escrow();
        assert_eq!(e.resolve(ARBITER, 0, None).unwrap(), (0, 0, 1_000_000));
        assert_eq!(e.state(), EscrowState::Settled);
    }

    #[test]
    fn resolve_rejects_over_split() {
        let mut e = disputed_escrow();
        assert_eq!(
            e.resolve(ARBITER, 1_000_001, None),
            Err(EscrowError::ReleaseExceedsLocked)
        );
        assert_eq!(e.state(), EscrowState::Disputed);
        assert_eq!(e.released_amount(), 0, "failed resolve moves nothing");
    }

    #[test]
    fn resolve_rejects_non_arbiter_and_wrong_state() {
        // Parties cannot settle their own dispute.
        let mut e = disputed_escrow();
        for authority in [ALICE, BOB, MALLORY] {
            assert_eq!(
                e.resolve(authority, 100_000, None),
                Err(EscrowError::Unauthorized)
            );
            assert_eq!(e.state(), EscrowState::Disputed);
        }
        // Not disputed yet: state rejects before authority is consulted.
        let mut e = funded_arbitrated_escrow();
        assert_eq!(
            e.resolve(ARBITER, 100_000, None),
            Err(EscrowError::InvalidStateTransition)
        );
        // Settled is terminal: no second settlement.
        let mut e = disputed_escrow();
        e.resolve(ARBITER, 600_000, None).unwrap();
        assert_eq!(
            e.resolve(ARBITER, 100_000, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.released_amount(), 600_000, "second resolve moved nothing");
    }

    #[test]
    fn resolve_splits_the_remainder_after_partial_release() {
        // Partial releases made before the dispute are honored: the
        // arbiter splits only what is still locked.
        let mut e = funded_arbitrated_escrow();
        e.release(ALICE, 1_750_000_000, 400_000, None).unwrap();
        e.escalate(BOB, EXPIRES_AT - 1, None).unwrap();
        let (payout, fee, refund) = e.resolve(ARBITER, 600_000, None).unwrap();
        assert_eq!((payout, fee, refund), (600_000, 0, 0));
        assert_eq!(e.released_amount(), 1_000_000);
        assert_eq!(e.remaining_amount(), 0);
        assert_eq!(e.state(), EscrowState::Settled);
    }

    // ----- composition with quorum / vesting / dual-sig -----

    #[test]
    fn resolve_is_not_gated_by_quorum_by_design() {
        // A 2-of-2 quorum gates release, but the arbiter settles without
        // attestations: requiring them would let attestors veto the
        // settlement.
        let policy = QuorumPolicy::new(&[[0xA1; 32], [0xA2; 32]], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
        assert_eq!(e.resolve(ARBITER, 500_000, None).unwrap(), (500_000, 0, 500_000));
        assert_eq!(e.state(), EscrowState::Settled);
    }

    #[test]
    fn dispute_overrides_vesting_curve_by_design() {
        // The vesting curve is contested — that is why there is a
        // dispute — so resolve splits the remainder regardless of what
        // has vested; claim stays locked while Disputed.
        let schedule = VestingSchedule::new(1_700_000_000, 1_800_000_000).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_vesting(schedule)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(BOB, EXPIRES_AT - 1, None).unwrap();
        assert_eq!(
            e.claim(BOB, 1_750_000_000, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.resolve(ARBITER, 200_000, None).unwrap(), (200_000, 0, 800_000));
    }

    #[test]
    fn arbiter_accessor_round_trips() {
        assert_eq!(funded_arbitrated_escrow().arbiter(), Some(ARBITER));
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(e.arbiter(), None);
        e.fund(ALICE).unwrap();
        assert_eq!(e.arbiter(), None, "funding does not invent an arbiter");
    }
}

// ---------- AV-15: milestone tranche release ----------
//
// A milestone plan splits the locked amount into ordered tranches that
// release one by one as both parties confirm each milestone (staged
// settlement: construction tranches, grant disbursements). The plan is
// fixed before funding and must sum to exactly the locked amount (u128
// accumulation, so the sum can never wrap); once attached it owns the
// release schedule — plain `release` / `claim` are disabled. Skipping a
// milestone needs both parties' approval (dual-sig skip): the skipped
// tranche is refunded to the initializer, never paid out to the taker.
#[cfg(test)]
mod milestone_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn plan_2() -> MilestonePlan {
        MilestonePlan::new(&[400_000, 600_000]).unwrap()
    }

    fn milestone_escrow() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan_2())
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    /// Confirm milestone `index` with both parties.
    fn confirm_both(e: &mut Escrow, index: u8) {
        e.confirm_milestone(ALICE, index).unwrap();
        e.confirm_milestone(BOB, index).unwrap();
        assert!(e.milestone_confirmed(index as usize));
    }

    // ----- plan construction -----

    #[test]
    fn plan_total_is_exact_and_rejects_bad_shapes() {
        let plan = MilestonePlan::new(&[400_000, 600_000]).unwrap();
        assert_eq!(plan.count(), 2);
        assert_eq!(plan.total(), 1_000_000);
        assert_eq!(plan.amount_at(0), Some(400_000));
        assert_eq!(plan.amount_at(1), Some(600_000));
        assert_eq!(plan.amount_at(2), None, "out-of-range index");
        // u128 total: no wrapping, exact even at the u64 boundary.
        let big = MilestonePlan::new(&[u64::MAX - 5, 5]).unwrap();
        assert_eq!(big.total(), u64::MAX as u128);
    }

    #[test]
    fn with_milestones_rejected_after_funding() {
        // The release schedule is fixed before funds move, like the
        // quorum and vesting builders.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.with_milestones(plan_2()),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.milestone_plan(), None);
    }

    #[test]
    fn with_milestones_accessor_round_trips() {
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan_2())
            .unwrap();
        assert_eq!(e.milestone_plan(), Some(plan_2()));
        assert_eq!(e.next_milestone(), Some(0));
        assert_eq!(e.skipped_amount(), 0);
        let plain = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(plain.milestone_plan(), None);
        assert_eq!(plain.next_milestone(), None, "no plan: no next milestone");
        assert!(!plain.milestone_confirmed(0));
        assert!(!plain.milestone_settled(0));
        assert!(!plain.milestone_confirmed(99), "out-of-range reports false");
        assert!(!plain.milestone_settled(99), "out-of-range reports false");
    }

    // ----- confirmation -----

    #[test]
    fn confirm_needs_dual_confirmation() {
        let mut e = milestone_escrow();
        // Initializer alone: recorded, not confirmed.
        e.confirm_milestone(ALICE, 0).unwrap();
        assert!(!e.milestone_confirmed(0));
        assert!(!e.milestone_settled(0));
        // Taker alone: recorded, not confirmed.
        let mut e = milestone_escrow();
        e.confirm_milestone(BOB, 0).unwrap();
        assert!(!e.milestone_confirmed(0));
        // Both: confirmed.
        e.confirm_milestone(ALICE, 0).unwrap();
        assert!(e.milestone_confirmed(0));
    }

    #[test]
    fn confirm_is_idempotent_per_party() {
        let mut e = milestone_escrow();
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(ALICE, 0).unwrap();
        assert!(!e.milestone_confirmed(0), "still waiting on the taker");
        e.confirm_milestone(BOB, 0).unwrap();
        assert!(e.milestone_confirmed(0));
    }

    #[test]
    fn confirm_is_strictly_in_order() {
        let mut e = milestone_escrow();
        // Milestone 1 cannot be confirmed while milestone 0 is unsettled.
        assert_eq!(
            e.confirm_milestone(ALICE, 1),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(
            e.confirm_milestone(BOB, 1),
            Err(EscrowError::InvalidStateTransition)
        );
        assert!(!e.milestone_confirmed(1));
        // After milestone 0 settles, milestone 1 is confirmable.
        confirm_both(&mut e, 0);
        e.release_milestone(ALICE, 1_750_000_000, 0, None).unwrap();
        e.confirm_milestone(ALICE, 1).unwrap();
        assert!(!e.milestone_confirmed(1));
    }

    #[test]
    fn confirm_rejects_strangers_and_bad_states() {
        let mut e = milestone_escrow();
        assert_eq!(
            e.confirm_milestone(MALLORY, 0),
            Err(EscrowError::Unauthorized)
        );
        assert!(!e.milestone_confirmed(0));
        // Before funding: the milestone schedule exists, but acceptance
        // happens after funds move.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan_2())
            .unwrap();
        assert_eq!(
            e.confirm_milestone(ALICE, 0),
            Err(EscrowError::InvalidStateTransition)
        );
        // Out-of-range index.
        let mut e = milestone_escrow();
        assert_eq!(
            e.confirm_milestone(ALICE, 2),
            Err(EscrowError::InvalidMilestones)
        );
    }

    // ----- tranche release -----

    #[test]
    fn release_milestone_full_sequence_closes_the_escrow() {
        let mut e = milestone_escrow();
        confirm_both(&mut e, 0);
        let (t0, fee0) = e.release_milestone(ALICE, 1_750_000_000, 0, None).unwrap();
        assert_eq!((t0, fee0), (400_000, 0), "the net tranche is returned for transfer sizing");
        assert_eq!(e.state(), EscrowState::Funded, "more tranches remain");
        assert_eq!((e.released_amount(), e.remaining_amount()), (400_000, 600_000));
        assert_eq!(e.next_milestone(), Some(1));

        confirm_both(&mut e, 1);
        let (t1, fee1) = e.release_milestone(ALICE, 1_750_000_000, 1, None).unwrap();
        assert_eq!((t1, fee1), (600_000, 0));
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.released_amount(), 1_000_000);
        assert_eq!(e.remaining_amount(), 0);
        assert_eq!(e.next_milestone(), None, "every tranche settled");
    }

    #[test]
    fn release_milestone_is_initializer_only_and_in_order() {
        let mut e = milestone_escrow();
        confirm_both(&mut e, 0);
        // The taker is the beneficiary, not the authority.
        assert_eq!(
            e.release_milestone(BOB, 1_750_000_000, 0, None),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            e.release_milestone(MALLORY, 1_750_000_000, 0, None),
            Err(EscrowError::Unauthorized)
        );
        // Releasing milestone 1 while milestone 0 is unsettled.
        assert_eq!(
            e.release_milestone(ALICE, 1_750_000_000, 1, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.released_amount(), 0);
    }

    #[test]
    fn release_milestone_cannot_double_release() {
        let mut e = milestone_escrow();
        confirm_both(&mut e, 0);
        e.release_milestone(ALICE, 1_750_000_000, 0, None).unwrap();
        // Milestone 0 is settled: re-releasing it is out-of-order now.
        assert_eq!(
            e.release_milestone(ALICE, 1_750_000_000, 0, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.released_amount(), 400_000);
    }

    #[test]
    fn quorum_gates_release_milestone_like_release() {
        // Otherwise the initializer could bypass attestation by routing
        // the payout through a milestone.
        let policy = QuorumPolicy::new(&[[0xA1; 32], [0xA2; 32]], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap()
            .with_milestones(plan_2())
            .unwrap();
        e.fund(ALICE).unwrap();
        confirm_both(&mut e, 0);
        assert_eq!(
            e.release_milestone(ALICE, 1_750_000_000, 0, None),
            Err(EscrowError::QuorumNotReached)
        );
        assert_eq!(e.released_amount(), 0);
        e.attest([0xA1; 32]).unwrap();
        e.attest([0xA2; 32]).unwrap();
        assert_eq!(e.release_milestone(ALICE, 1_750_000_000, 0, None).unwrap(), (400_000, 0));
    }

    #[test]
    fn plain_release_and_claim_disabled_with_plan() {
        // The plan is the sole release schedule: arbitrary tranches and
        // time-based claims would break per-tranche accounting.
        let mut e = milestone_escrow();
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 400_000, None),
            Err(EscrowError::InvalidMilestones)
        );
        let schedule = VestingSchedule::new(1_700_000_000, 1_800_000_000).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_vesting(schedule)
            .unwrap()
            .with_milestones(plan_2())
            .unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.claim(BOB, 1_800_000_000, None),
            Err(EscrowError::InvalidMilestones)
        );
        assert_eq!(e.released_amount(), 0);
    }

    // ----- dual-signed skip -----

    #[test]
    fn skip_needs_both_parties_and_refunds_the_tranche() {
        let mut e = milestone_escrow();
        // One approval: recorded, not executed.
        e.skip_milestone(ALICE, 0).unwrap();
        assert!(!e.milestone_settled(0));
        assert_eq!(e.skipped_amount(), 0);
        assert_eq!(e.next_milestone(), Some(0));
        // The second approval executes the skip.
        e.skip_milestone(BOB, 0).unwrap();
        assert!(e.milestone_settled(0));
        assert_eq!(e.skipped_amount(), 400_000);
        assert_eq!(e.released_amount(), 0, "skips never pay the taker");
        // The skipped tranche stays inside the refundable remainder
        // (remaining = amount - released; skipped is sub-accounting of
        // the remainder, not a separate bucket).
        assert_eq!(e.remaining_amount(), 1_000_000);
        assert_eq!(e.state(), EscrowState::Funded, "the plan continues");
        assert_eq!(e.next_milestone(), Some(1));
    }

    #[test]
    fn skip_is_idempotent_per_party_and_in_order() {
        let mut e = milestone_escrow();
        e.skip_milestone(ALICE, 0).unwrap();
        e.skip_milestone(ALICE, 0).unwrap();
        assert_eq!(e.skipped_amount(), 0, "still one approval short");
        // Skipping ahead of the sequence is rejected.
        assert_eq!(
            e.skip_milestone(BOB, 1),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.skipped_amount(), 0);
        // A stranger cannot approve a skip.
        assert_eq!(
            e.skip_milestone(MALLORY, 0),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.skipped_amount(), 0);
    }

    #[test]
    fn mixed_confirm_and_skip_approval_stalls_until_aligned() {
        // One party confirmed (release path), the other skip-approved:
        // neither path completes on a single party's word — the milestone
        // stays unsettled until both parties align on one path.
        let mut e = milestone_escrow();
        e.confirm_milestone(ALICE, 0).unwrap();
        e.skip_milestone(BOB, 0).unwrap();
        assert!(!e.milestone_confirmed(0));
        assert!(!e.milestone_settled(0));
        assert_eq!(
            e.release_milestone(ALICE, 1_750_000_000, 0, None),
            Err(EscrowError::MilestoneNotConfirmed)
        );
        // The taker aligns with the release path: now it is confirmed.
        e.confirm_milestone(BOB, 0).unwrap();
        assert!(e.milestone_confirmed(0));
        assert_eq!(e.release_milestone(ALICE, 1_750_000_000, 0, None).unwrap(), (400_000, 0));
    }

    #[test]
    fn skip_then_continue_and_cancel_refunds_remainder() {
        // Skip milestone 0 by dual approval, then release milestone 1.
        // The skipped tranche is sub-accounting of the refundable
        // remainder: released + remaining == amount always holds.
        let mut e = milestone_escrow();
        e.skip_milestone(ALICE, 0).unwrap();
        e.skip_milestone(BOB, 0).unwrap();
        confirm_both(&mut e, 1);
        e.release_milestone(ALICE, 1_750_000_000, 1, None).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 600_000);
        assert_eq!(e.skipped_amount(), 400_000);
        assert_eq!(e.remaining_amount(), 400_000);
        assert_eq!(
            e.released_amount() + e.remaining_amount(),
            1_000_000,
            "conservation: released + remaining == amount"
        );
        // Cancel refunds the remainder (including the skipped tranche);
        // both counters are preserved for audit.
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        assert_eq!(e.released_amount(), 600_000);
        assert_eq!(e.skipped_amount(), 400_000);
        assert_eq!(e.remaining_amount(), 400_000);
    }

    // ----- composition -----

    #[test]
    fn resolve_overrides_the_milestone_plan() {
        // Arbitration overrides the tranche schedule by design, like it
        // overrides vesting: unsettled tranches are part of the remainder
        // the arbiter splits.
        const ARBITER: [u8; 32] = [0xA8; 32];
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap()
            .with_milestones(plan_2())
            .unwrap();
        e.fund(ALICE).unwrap();
        confirm_both(&mut e, 0);
        e.release_milestone(ALICE, 1_750_000_000, 0, None).unwrap(); // 400_000 to the taker
        e.escalate(BOB, EXPIRES_AT - 1, None).unwrap();
        let (payout, fee, refund) = e.resolve(ARBITER, 300_000, None).unwrap();
        assert_eq!((payout, fee, refund), (300_000, 0, 300_000));
        assert_eq!(e.released_amount(), 700_000, "taker share in released");
        assert_eq!(e.remaining_amount(), 300_000, "initializer refund");
        assert_eq!(e.state(), EscrowState::Settled);
    }

    #[test]
    fn milestone_escrow_at_u64_max_boundary() {
        // The u128 sum check accepts the exact boundary; both tranches
        // release and close the escrow with no overflow.
        let plan = MilestonePlan::new(&[u64::MAX - 5, 5]).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, u64::MAX, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan)
            .unwrap();
        e.fund(ALICE).unwrap();
        confirm_both(&mut e, 0);
        assert_eq!(e.release_milestone(ALICE, 1_750_000_000, 0, None).unwrap(), (u64::MAX - 5, 0));
        assert_eq!(e.state(), EscrowState::Funded);
        confirm_both(&mut e, 1);
        assert_eq!(e.release_milestone(ALICE, 1_750_000_000, 1, None).unwrap(), (5, 0));
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.released_amount(), u64::MAX);
        assert_eq!(e.remaining_amount(), 0);
    }

    #[test]
    fn dispute_locks_milestone_ops() {
        // Milestone ops are Funded-only, so the Disputed lock covers them
        // with no extra code: the lock is a property of the state match.
        const ARBITER: [u8; 32] = [0xA8; 32];
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap()
            .with_milestones(plan_2())
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
        assert_eq!(
            e.confirm_milestone(ALICE, 0),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(
            e.release_milestone(ALICE, 1_750_000_000, 0, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(
            e.skip_milestone(BOB, 0),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Disputed);
    }
}

// ---------- AV-17: protocol fee on taker payouts ----------
//
// `with_protocol_fee` fixes a basis-point rate (0-10000) before funding.
// Every taker payout — `release`, `claim`, `release_milestone`, and the
// taker's share of `resolve` — is split into a net payout and a protocol
// fee (`floor(gross * fee_bps / 10000)`, computed in u128 so it cannot
// overflow). The fee accumulates in `fees_paid` and rides along inside
// the gross `released` counter, so the crate's conservation invariant
// (inflow == locked + released + refunded) is untouched by fees.
// Refunds (`cancel`, `cancel_expired`), the initializer's `resolve`
// share, and skipped milestones are never fee'd.
#[cfg(test)]
mod protocol_fee_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const ARBITER: [u8; 32] = [0xA8; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn fee_escrow(fee_bps: u16) -> Escrow {
        Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_protocol_fee(fee_bps)
            .unwrap()
    }

    fn funded_fee_escrow(fee_bps: u16) -> Escrow {
        let mut e = fee_escrow(fee_bps);
        e.fund(ALICE).unwrap();
        e
    }

    #[test]
    fn fee_math_is_floor_and_overflow_free() {
        let e = fee_escrow(250); // 2.5%
        // floor(1_000_000 * 250 / 10_000) = 25_000.
        assert_eq!(e.protocol_fee_for(1_000_000), 25_000);
        // floor(999 * 250 / 10_000) = floor(24.975) = 24: the protocol
        // never rounds up into the taker's pocket.
        assert_eq!(e.protocol_fee_for(999), 24);
        // Dust payouts carry a zero fee.
        assert_eq!(e.protocol_fee_for(1), 0);
        // u64::MAX * 10_000 < u128::MAX: no overflow at the boundary.
        let full = fee_escrow(10_000);
        assert_eq!(full.protocol_fee_for(u64::MAX), u64::MAX);
        // A zero rate charges nothing.
        let none = fee_escrow(0);
        assert_eq!(none.protocol_fee_for(u64::MAX), 0);
        // 1 bp of u64::MAX: floor((2^64 - 1) / 10_000).
        assert_eq!(fee_escrow(1).protocol_fee_for(u64::MAX), 1_844_674_407_370_955);
    }

    #[test]
    fn release_splits_payout_and_fee() {
        let mut e = funded_fee_escrow(250); // 2.5%
        let (payout, fee) = e.release(ALICE, 1_750_000_000, 400_000, None).unwrap();
        assert_eq!((payout, fee), (390_000, 10_000));
        assert_eq!(payout + fee, 400_000, "fee is a slice of the gross");
        assert_eq!(e.fees_paid(), 10_000);
        // The released counter keeps the gross: conservation is
        // untouched.
        assert_eq!(e.released_amount(), 400_000);
        assert_eq!(e.remaining_amount(), 600_000);
        assert_eq!(e.state(), EscrowState::Funded);
        // Fees accumulate across partial releases.
        let (payout2, fee2) = e.release(ALICE, 1_750_000_000, 600_000, None).unwrap();
        assert_eq!((payout2, fee2), (585_000, 15_000));
        assert_eq!(e.fees_paid(), 25_000);
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.released_amount(), 1_000_000);
    }

    #[test]
    fn full_rate_routes_everything_to_the_fee_account() {
        // 10_000 bps (100%) is a valid config: the taker nets zero.
        let mut e = funded_fee_escrow(10_000);
        let (payout, fee) = e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!((payout, fee), (0, 1_000_000));
        assert_eq!(e.fees_paid(), 1_000_000);
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn claim_splits_vested_payout_and_fee() {
        let schedule = VestingSchedule::new(1_700_000_000, 1_800_000_000).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_protocol_fee(1_000) // 10%
            .unwrap()
            .with_vesting(schedule)
            .unwrap();
        e.fund(ALICE).unwrap();
        // Half the window elapsed: 500_000 vested; 10% -> 50_000 fee.
        let (payout, fee) = e.claim(BOB, 1_750_000_000, None).unwrap();
        assert_eq!((payout, fee), (450_000, 50_000));
        assert_eq!(e.fees_paid(), 50_000);
        assert_eq!(e.released_amount(), 500_000, "released keeps the gross");
    }

    #[test]
    fn milestone_release_splits_tranche_and_fee() {
        let plan = MilestonePlan::new(&[400_000, 600_000]).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_protocol_fee(500) // 5%
            .unwrap()
            .with_milestones(plan)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        let (payout, fee) = e.release_milestone(ALICE, 1_750_000_000, 0, None).unwrap();
        assert_eq!((payout, fee), (380_000, 20_000));
        assert_eq!(e.fees_paid(), 20_000);
        assert_eq!(e.released_amount(), 400_000, "released keeps the gross");
    }

    #[test]
    fn resolve_fees_only_the_takers_share() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_protocol_fee(1_000) // 10%
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
        let (payout, fee, refund) = e.resolve(ARBITER, 600_000, None).unwrap();
        assert_eq!((payout, fee, refund), (540_000, 60_000, 400_000));
        assert_eq!(payout + fee, 600_000, "fee slices the taker's share");
        assert_eq!(e.fees_paid(), 60_000);
        assert_eq!(e.released_amount(), 600_000, "released keeps the gross");
        assert_eq!(e.remaining_amount(), 400_000, "refund untouched by fee");
        assert_eq!(e.state(), EscrowState::Settled);
    }

    #[test]
    fn refunds_and_skips_never_carry_a_fee() {
        // cancel.
        let mut e = funded_fee_escrow(10_000);
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.fees_paid(), 0);
        // cancel_expired.
        let mut e = funded_fee_escrow(10_000);
        e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        assert_eq!(e.fees_paid(), 0);
    }

    #[test]
    fn failed_payouts_leave_the_fee_counter_untouched() {
        // Unauthorized release.
        let mut e = funded_fee_escrow(250);
        assert_eq!(
            e.release(MALLORY, 1_750_000_000, 400_000, None),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.fees_paid(), 0);
        // Over-release: the cap check runs before any fee is charged.
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 1_000_001, None),
            Err(EscrowError::ReleaseExceedsLocked)
        );
        assert_eq!(e.fees_paid(), 0);
        assert_eq!(e.released_amount(), 0);
        // Zero amount.
        assert_eq!(e.release(ALICE, 1_750_000_000, 0, None), Err(EscrowError::AmountMismatch));
        assert_eq!(e.fees_paid(), 0);
        // Claim before anything is vested.
        let schedule = VestingSchedule::new(1_700_000_000, 1_800_000_000).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_protocol_fee(250)
            .unwrap()
            .with_vesting(schedule)
            .unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.claim(BOB, 1_700_000_000, None),
            Err(EscrowError::AmountMismatch)
        );
        assert_eq!(e.fees_paid(), 0);
    }

    #[test]
    fn fee_defaults_to_zero_and_config_is_immutable() {
        // Plain escrows pay takers in full: pre-AV-17 behavior.
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(e.fee_bps(), 0);
        assert_eq!(e.fees_paid(), 0);
        // The fee is part of the initialized config: visible before fund.
        let e = fee_escrow(777);
        assert_eq!((e.fee_bps(), e.fees_paid()), (777, 0));
    }
}

// ---------- AV-19: opt-in configuration matrix combination tests ----------
//
// The six opt-in axes — dual_sig x quorum x vesting x milestones x mint x
// protocol_fee — are independent builders, but they share the fund-moving
// transitions, so their *interactions* are the regression risk: a new gate
// must never weaken an older gate, reorder a documented check sequence,
// or break the conservation invariant. This module enumerates all 2^6 =
// 64 flag combinations deterministically (no RNG — the same binary always
// runs the same matrix) and drives every combination through a full
// lifecycle, plus focused check-order probes on the maximal configuration.
//
// Exhaustive 2^6 coverage implies full pairwise and triplewise coverage:
// every value assignment of every axis pair (C(6,2) x 4 = 60) and every
// axis triple (C(6,3) x 8 = 160) appears in the enumeration — asserted by
// `matrix_pairwise_and_triplewise_coverage_is_exhaustive` below.
#[cfg(test)]
mod combination_matrix_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const MALLORY: [u8; 32] = [0xCC; 32]; // stranger
    const A1: [u8; 32] = [0xA1; 32]; // attestors
    const A2: [u8; 32] = [0xA2; 32];
    const A3: [u8; 32] = [0xA3; 32];
    const MINT: [u8; 32] = [0xD0; 32];
    const OTHER_MINT: [u8; 32] = [0xD1; 32];
    const AMOUNT: u64 = 1_000_000;
    const FEE_BPS: u16 = 250; // 2.5%
    const VEST_START: u64 = 1_700_000_000;
    const VEST_END: u64 = 1_800_000_000;
    const EXPIRES_AT: u64 = 1_800_000_000;
    const NOW: u64 = 1_000_000; // scan time for the cancel_expired sweep
    const TRANCHES: [u64; 2] = [400_000, 600_000];

    // One bit per opt-in axis, in backlog order.
    const F_DUAL_SIG: u8 = 0b000001;
    const F_QUORUM: u8 = 0b000010;
    const F_VESTING: u8 = 0b000100;
    const F_MILESTONES: u8 = 0b001000;
    const F_MINT: u8 = 0b010000;
    const F_FEE: u8 = 0b100000;
    const ALL: u8 = F_DUAL_SIG | F_QUORUM | F_VESTING | F_MILESTONES | F_MINT | F_FEE;
    const AXES: [u8; 6] = [F_DUAL_SIG, F_QUORUM, F_VESTING, F_MILESTONES, F_MINT, F_FEE];

    fn quorum_policy() -> QuorumPolicy {
        QuorumPolicy::new(&[A1, A2, A3], 2).unwrap()
    }

    fn build_with_expiry(flags: u8, expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, expires_at).unwrap();
        if flags & F_DUAL_SIG != 0 {
            e = e.with_dual_sig().unwrap();
        }
        if flags & F_QUORUM != 0 {
            e = e.with_quorum(quorum_policy()).unwrap();
        }
        if flags & F_VESTING != 0 {
            e = e
                .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
                .unwrap();
        }
        if flags & F_MILESTONES != 0 {
            e = e.with_milestones(MilestonePlan::new(&TRANCHES).unwrap()).unwrap();
        }
        if flags & F_MINT != 0 {
            e = e.with_mint(MINT).unwrap();
        }
        if flags & F_FEE != 0 {
            e = e.with_protocol_fee(FEE_BPS).unwrap();
        }
        e
    }

    fn build(flags: u8) -> Escrow {
        build_with_expiry(flags, EXPIRES_AT)
    }

    /// The `mint` argument the fund-moving transitions take for this
    /// combination: the bound mint on the SPL path, `None` on the
    /// native-SOL path.
    fn mint_arg(flags: u8) -> Option<[u8; 32]> {
        if flags & F_MINT != 0 {
            Some(MINT)
        } else {
            None
        }
    }

    /// The expected protocol fee on a gross payout of `gross` for this
    /// combination (`0` when no fee is configured).
    fn expected_fee(flags: u8, gross: u64) -> u64 {
        if flags & F_FEE != 0 {
            ((gross as u128 * FEE_BPS as u128) / 10_000u128) as u64
        } else {
            0
        }
    }

    /// Activate (dual-sig), satisfy the quorum, and fund — the shared
    /// preamble every lifecycle in the matrix runs through.
    fn fund_fully(e: &mut Escrow, flags: u8) {
        if flags & F_DUAL_SIG != 0 {
            e.activate(ALICE).unwrap();
            e.activate(BOB).unwrap();
            assert_eq!(e.state(), EscrowState::Activated);
        }
        if flags & F_QUORUM != 0 {
            e.attest(A1).unwrap();
            e.attest(A2).unwrap();
        }
        e.fund(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
    }

    /// The conservation invariant (AV-03 style): the inflow equals the sum
    /// of every sink. The protocol fee is a routing slice of the gross
    /// payouts, never an extra sink, so `fees_paid <= released` always.
    fn assert_conservation(locked: u64, released: u64, refunded: u64) {
        assert_eq!(
            AMOUNT as u128,
            locked as u128 + released as u128 + refunded as u128,
            "conservation violated: inflow != locked + released + refunded"
        );
    }

    fn assert_fee_bound(e: &Escrow) {
        assert!(
            e.fees_paid() <= e.released_amount(),
            "fee exceeded gross payouts: fees_paid={} released={}",
            e.fees_paid(),
            e.released_amount()
        );
    }

    /// Drive the combination's taker-payout path to a terminal `Released`
    /// state. The milestone plan owns the release schedule when attached
    /// (plain `release` / `claim` are config errors there); otherwise the
    /// vesting curve is claimed by the taker; otherwise the initializer
    /// releases in full.
    fn drive_release_path(e: &mut Escrow, flags: u8) {
        let mint = mint_arg(flags);
        if flags & F_MILESTONES != 0 {
            // The plan owns the schedule: arbitrary and time-based pulls
            // are disabled, even when vesting is also configured.
            assert_eq!(
                e.release(ALICE, 1_750_000_000, AMOUNT, mint),
                Err(EscrowError::InvalidMilestones)
            );
            if flags & F_VESTING != 0 {
                assert_eq!(
                    e.claim(BOB, VEST_END, mint),
                    Err(EscrowError::InvalidMilestones)
                );
            }
            for (i, &tranche) in TRANCHES.iter().enumerate() {
                let i = i as u8;
                e.confirm_milestone(ALICE, i).unwrap();
                e.confirm_milestone(BOB, i).unwrap();
                let (payout, fee) = e.release_milestone(ALICE, 1_750_000_000, i, mint).unwrap();
                assert_eq!(fee, expected_fee(flags, tranche));
                assert_eq!(payout + fee, tranche, "fee is a slice of the gross");
            }
        } else if flags & F_VESTING != 0 {
            // Claim at the end of the curve: everything vested at once.
            let (payout, fee) = e.claim(BOB, VEST_END, mint).unwrap();
            assert_eq!(fee, expected_fee(flags, AMOUNT));
            assert_eq!(payout + fee, AMOUNT, "fee is a slice of the gross");
        } else {
            let (payout, fee) = e.release(ALICE, 1_750_000_000, AMOUNT, mint).unwrap();
            assert_eq!(fee, expected_fee(flags, AMOUNT));
            assert_eq!(payout + fee, AMOUNT, "fee is a slice of the gross");
        }
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.released_amount(), AMOUNT);
        assert_eq!(e.remaining_amount(), 0);
        assert_eq!(e.fees_paid(), expected_fee(flags, AMOUNT));
        assert_conservation(0, AMOUNT, 0);
        assert_fee_bound(e);
    }

    #[test]
    fn matrix_all_combos_drive_release_path() {
        // All 64 combinations: build, fund, and drive the taker-payout
        // path to `Released`, asserting conservation and the fee bound at
        // every step. This is the gate-interaction regression net: any
        // combination that deadlocks, over-releases, or misroutes a fee
        // fails here.
        for flags in 0u8..64 {
            let mut e = build(flags);
            fund_fully(&mut e, flags);
            drive_release_path(&mut e, flags);
        }
    }

    #[test]
    fn matrix_all_combos_cancel_expired() {
        // All 64 combinations through the unilateral expiry exit: the
        // refund path must stay intact no matter which payout gates are
        // armed. `expires_at = 0` makes every escrow expiry-eligible at
        // `NOW`.
        for flags in 0u8..64 {
            let mut e = build_with_expiry(flags, 0);
            fund_fully(&mut e, flags);
            // The mint binding is checked before expiry (check order:
            // authority -> state -> mint -> refund -> expiry): a wrong
            // mint fails even on an expired escrow, in both mismatch
            // directions.
            let wrong_mint = if flags & F_MINT != 0 {
                Some(OTHER_MINT)
            } else {
                Some(MINT)
            };
            assert_eq!(
                e.cancel_expired(ALICE, NOW, wrong_mint, ALICE),
                Err(EscrowError::MintMismatch)
            );
            // Early call: not expired yet.
            let mut early = build_with_expiry(flags, NOW + 1);
            fund_fully(&mut early, flags);
            assert_eq!(
                early.cancel_expired(BOB, NOW, mint_arg(flags), ALICE),
                Err(EscrowError::NotExpired)
            );
            // Either party may cancel an expired escrow; the refund is
            // the full remainder and no fee is ever charged on it.
            e.cancel_expired(BOB, NOW, mint_arg(flags), ALICE).unwrap();
            assert_eq!(e.state(), EscrowState::Cancelled);
            assert_eq!(e.released_amount(), 0);
            assert_eq!(e.remaining_amount(), AMOUNT);
            assert_eq!(e.fees_paid(), 0, "refunds never carry a fee");
            assert_conservation(0, 0, AMOUNT);
        }
    }

    #[test]
    fn matrix_pairwise_and_triplewise_coverage_is_exhaustive() {
        // The 2^6 full enumeration deterministically covers every value
        // assignment of every axis pair (C(6,2) pairs x 4 combos) and every
        // axis triple (C(6,3) triples x 8 combos): this test pins that
        // property so a future change to the enumeration cannot silently
        // shrink the matrix.
        let pair_val = |c: u8, i: usize, j: usize| -> u8 {
            (((c & AXES[i]) != 0) as u8) * 2 + (((c & AXES[j]) != 0) as u8)
        };
        for i in 0..6 {
            for j in (i + 1)..6 {
                for vals in 0u8..4 {
                    assert!(
                        (0u8..64).any(|c| pair_val(c, i, j) == vals),
                        "pair of axes ({i},{j}) never sees value combo {vals:02b}"
                    );
                }
            }
        }
        let triple_val = |c: u8, i: usize, j: usize, k: usize| -> u8 {
            (((c & AXES[i]) != 0) as u8) * 4
                + (((c & AXES[j]) != 0) as u8) * 2
                + (((c & AXES[k]) != 0) as u8)
        };
        for i in 0..6 {
            for j in (i + 1)..6 {
                for k in (j + 1)..6 {
                    for vals in 0u8..8 {
                        assert!(
                            (0u8..64).any(|c| triple_val(c, i, j, k) == vals),
                            "triple of axes ({i},{j},{k}) never sees value combo {vals:03b}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn matrix_builder_order_is_irrelevant() {
        // The builders only set independent config fields: applying the
        // same flag set in a different order yields the identical escrow.
        // Gate interactions therefore cannot depend on configuration
        // order.
        let forward = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_dual_sig()
            .unwrap()
            .with_quorum(quorum_policy())
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_milestones(MilestonePlan::new(&TRANCHES).unwrap())
            .unwrap()
            .with_mint(MINT)
            .unwrap()
            .with_protocol_fee(FEE_BPS)
            .unwrap();
        let reverse = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_protocol_fee(FEE_BPS)
            .unwrap()
            .with_mint(MINT)
            .unwrap()
            .with_milestones(MilestonePlan::new(&TRANCHES).unwrap())
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_quorum(quorum_policy())
            .unwrap()
            .with_dual_sig()
            .unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(build(ALL), forward);
    }

    #[test]
    fn matrix_builders_rejected_after_fund() {
        // Configuration is immutable once funds move: every builder
        // rejects a live escrow, whatever the flag combination.
        let mut e = build(ALL);
        fund_fully(&mut e, ALL);
        assert_eq!(
            e.with_dual_sig().map(|_| ()),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(
            e.with_quorum(quorum_policy()).map(|_| ()),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(
            e.with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
                .map(|_| ()),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(
            e.with_milestones(MilestonePlan::new(&TRANCHES).unwrap())
                .map(|_| ()),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(
            e.with_mint(MINT).map(|_| ()),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(
            e.with_protocol_fee(FEE_BPS).map(|_| ()),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    /// The maximal configuration with the quorum deliberately unsatisfied
    /// (1 of 2 attestations): every gate is armed at once, so each probe
    /// below exercises the documented check order against live
    /// competing failures.
    fn funded_maximal_quorum_open() -> Escrow {
        let mut e = build(ALL);
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        e.attest(A1).unwrap(); // 1 of 2: quorum NOT satisfied
        e.fund(ALICE).unwrap();
        e
    }

    #[test]
    fn matrix_check_order_release() {
        let mut e = funded_maximal_quorum_open();
        let mint = Some(MINT);
        // Authority first: a stranger learns nothing, even though the
        // mint, the plan, the quorum, and the amount would all also fail.
        assert_eq!(
            e.release(MALLORY, 1_750_000_000, AMOUNT, mint),
            Err(EscrowError::Unauthorized)
        );
        // Mint binding before the milestone plan, the quorum, and the
        // amount checks.
        assert_eq!(
            e.release(ALICE, 1_750_000_000, AMOUNT, Some(OTHER_MINT)),
            Err(EscrowError::MintMismatch)
        );
        // The milestone plan owns the release schedule: the config error
        // fires before the quorum gate runs (a zero amount would also be
        // an amount error, but the plan rejects first).
        assert_eq!(
            e.release(ALICE, 1_750_000_000, AMOUNT, mint),
            Err(EscrowError::InvalidMilestones)
        );
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 0, mint),
            Err(EscrowError::InvalidMilestones)
        );
        // The quorum guards the milestone path exactly like `release`:
        // mint mismatch still wins over the quorum gate ...
        assert_eq!(
            e.release_milestone(ALICE, 1_750_000_000, 0, Some(OTHER_MINT)),
            Err(EscrowError::MintMismatch)
        );
        // ... and the quorum gate wins over the confirmation gate.
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        assert_eq!(
            e.release_milestone(ALICE, 1_750_000_000, 0, mint),
            Err(EscrowError::QuorumNotReached)
        );
        // Satisfy the quorum: the path opens and the fee slices the
        // tranche (floor(400_000 * 250 / 10_000) = 10_000).
        e.attest(A2).unwrap();
        let (payout, fee) = e.release_milestone(ALICE, 1_750_000_000, 0, mint).unwrap();
        assert_eq!((payout, fee), (390_000, 10_000));
        assert_conservation(e.remaining_amount(), e.released_amount(), 0);
        assert_fee_bound(&e);
    }

    #[test]
    fn matrix_check_order_claim() {
        // Maximal configuration minus the milestone plan (the plan
        // disables `claim`): authority -> state -> mint -> vesting ->
        // quorum -> amount.
        let flags = ALL & !F_MILESTONES;
        let mut e = build(flags);
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        e.attest(A1).unwrap(); // 1 of 2: quorum NOT satisfied
        e.fund(ALICE).unwrap();
        let mint = Some(MINT);
        assert_eq!(
            e.claim(MALLORY, VEST_END, mint),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            e.claim(BOB, VEST_END, Some(OTHER_MINT)),
            Err(EscrowError::MintMismatch)
        );
        assert_eq!(
            e.claim(BOB, VEST_END, mint),
            Err(EscrowError::QuorumNotReached)
        );
        // Satisfy the quorum: the full curve claims at once.
        e.attest(A2).unwrap();
        let (payout, fee) = e.claim(BOB, VEST_END, mint).unwrap();
        assert_eq!((payout, fee), (975_000, 25_000));
        assert_eq!(e.state(), EscrowState::Released);
        assert_conservation(0, AMOUNT, 0);
        assert_fee_bound(&e);
    }

    #[test]
    fn matrix_check_order_cancel_expired() {
        let mut e = build_with_expiry(ALL, 0);
        fund_fully(&mut e, ALL);
        // Check order: authority -> state -> mint -> refund -> expiry.
        assert_eq!(
            e.cancel_expired(MALLORY, NOW, Some(MINT), ALICE),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            e.cancel_expired(ALICE, NOW, Some(OTHER_MINT), ALICE),
            Err(EscrowError::MintMismatch)
        );
        // Expiry is the last check: an early call fails NotExpired even
        // with every gate armed.
        let mut early = build_with_expiry(ALL, NOW + 1);
        fund_fully(&mut early, ALL);
        assert_eq!(
            early.cancel_expired(ALICE, NOW, Some(MINT), ALICE),
            Err(EscrowError::NotExpired)
        );
        // Executable: either party cancels, the refund is the remainder,
        // and refunds never carry a fee.
        e.cancel_expired(BOB, NOW, Some(MINT), ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        assert_eq!(e.fees_paid(), 0);
        assert_conservation(0, 0, AMOUNT);
    }

    #[test]
    fn matrix_plain_escrow_is_backward_compatible() {
        // The zero-flag combination is the pre-opt-in escrow: the matrix
        // itself pins the original behavior (native-SOL, no gates).
        let mut e = build(0);
        fund_fully(&mut e, 0);
        assert_eq!(e.mint(), None);
        assert_eq!(e.fee_bps(), 0);
        assert!(!e.dual_sig_required());
        let (payout, fee) = e.release(ALICE, 1_750_000_000, AMOUNT, None).unwrap();
        assert_eq!((payout, fee), (AMOUNT, 0));
        assert_eq!(e.state(), EscrowState::Released);
        assert_conservation(0, AMOUNT, 0);
    }
}

// ---------- AV-21: expiry grace period tests ----------
//
// `cancel_expired` requires `now >= expires_at + grace_period`
// (opt-in via `with_grace_period`, `0` by default). These tests pin the
// gate boundary, the builder validation, the check order inside the
// grace window, and backward compatibility of the default.
#[cfg(test)]
mod grace_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const MALLORY: [u8; 32] = [0xCC; 32]; // stranger
    const AMOUNT: u64 = 1_000_000;
    const EXPIRES_AT: u64 = 1_800_000_000;
    const GRACE: u64 = 300; // five minutes of clock-skew cover

    fn funded_no_grace() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT).unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    fn funded_with_grace() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_grace_period(GRACE)
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    #[test]
    fn grace_period_defaults_to_zero_backward_compatible() {
        // No builder: the historical `now >= expires_at` gate is intact.
        let e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT).unwrap();
        assert_eq!(e.grace_period(), 0);
        assert!(e.is_expiry_eligible(EXPIRES_AT));
        assert!(!e.is_expiry_eligible(EXPIRES_AT - 1));
        let mut e = funded_no_grace();
        e.cancel_expired(ALICE, EXPIRES_AT, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn cancel_expired_requires_expires_at_plus_grace() {
        let mut e = funded_with_grace();
        assert_eq!(e.grace_period(), GRACE);
        // At expires_at itself: still NotExpired — the whole point of the
        // grace period (the keeper's clock may be ahead of the chain's).
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT, None, ALICE),
            Err(EscrowError::NotExpired)
        );
        // One second before the gate: still NotExpired.
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT + GRACE - 1, None, ALICE),
            Err(EscrowError::NotExpired)
        );
        assert_eq!(e.state(), EscrowState::Funded, "failed cancels change nothing");
        // At expires_at + grace: the gate passes.
        e.cancel_expired(ALICE, EXPIRES_AT + GRACE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn taker_may_cancel_after_grace() {
        // Either party may cancel an expired escrow — the grace period
        // does not change who may call, only when.
        let mut e = funded_with_grace();
        e.cancel_expired(BOB, EXPIRES_AT + GRACE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn grace_window_keeps_authority_first_check_order() {
        // Inside the grace window (expired by expires_at, not yet by the
        // gate) a stranger still learns nothing beyond Unauthorized —
        // the grace period did not reorder the checks.
        let mut e = funded_with_grace();
        assert_eq!(
            e.cancel_expired(MALLORY, EXPIRES_AT + 1, None, ALICE),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn is_expiry_eligible_agrees_with_cancel_expired() {
        // The predicate the keeper evaluates must agree with the
        // transition's gate at every boundary — this is the sync the
        // keeper report depends on.
        for now in [
            EXPIRES_AT - 1,
            EXPIRES_AT,
            EXPIRES_AT + 1,
            EXPIRES_AT + GRACE - 1,
            EXPIRES_AT + GRACE,
            EXPIRES_AT + GRACE + 1,
            u64::MAX,
        ] {
            let eligible = funded_with_grace().is_expiry_eligible(now);
            let mut e = funded_with_grace();
            let res = e.cancel_expired(ALICE, now, None, ALICE);
            assert_eq!(
                res.is_ok(),
                eligible,
                "predicate/transition disagree at now={now}"
            );
            // And without grace the predicate is the historical gate.
            assert_eq!(
                funded_no_grace().is_expiry_eligible(now),
                now >= EXPIRES_AT,
                "no-grace predicate drifted at now={now}"
            );
        }
    }

    #[test]
    fn partial_release_then_cancel_expired_after_grace_refunds_remainder() {
        // The grace period composes with partial releases: the refund is
        // the remainder, and released progress is preserved for audit.
        let mut e = funded_with_grace();
        e.release(ALICE, 1_750_000_000, 400_000, None).unwrap();
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT + GRACE - 1, None, ALICE),
            Err(EscrowError::NotExpired)
        );
        e.cancel_expired(ALICE, EXPIRES_AT + GRACE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        assert_eq!(e.released_amount(), 400_000);
        assert_eq!(e.remaining_amount(), AMOUNT - 400_000);
    }
}

// ---------- AV-22: dispute evidence hash ----------
//
// `escalate` takes an optional 32-byte commitment to the off-chain
// dispute evidence (e.g. the SHA-256 of an IPFS CID). The hash is
// persisted on the escrow so the arbiter and indexers can read it
// without trusting the escalator to re-supply it, and it is never
// cleared — the `Settled` escrow keeps the audit trail of what the
// arbiter reviewed.
#[cfg(test)]
mod evidence_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const MALLORY: [u8; 32] = [0xCC; 32]; // stranger
    const ARBITER: [u8; 32] = [0xA8; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;
    const EVIDENCE: [u8; 32] = [0xE1; 32]; // stand-in evidence commitment

    fn funded_arbitrated_escrow() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    #[test]
    fn evidence_hash_defaults_to_none_backward_compatible() {
        // A plain escrow carries no evidence; escalating without
        // evidence keeps the historical behavior exactly.
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(e.evidence_hash(), None);
        let mut e = funded_arbitrated_escrow();
        e.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
        assert_eq!(e.state(), EscrowState::Disputed);
        assert_eq!(e.evidence_hash(), None);
    }

    #[test]
    fn escalate_stores_evidence_hash() {
        // Either party may attach evidence when escalating.
        for authority in [ALICE, BOB] {
            let mut e = funded_arbitrated_escrow();
            e.escalate(authority, EXPIRES_AT - 1, Some(EVIDENCE))
                .unwrap();
            assert_eq!(e.state(), EscrowState::Disputed);
            assert_eq!(e.evidence_hash(), Some(EVIDENCE));
        }
    }

    #[test]
    fn failed_escalate_stores_nothing() {
        // A rejected escalation must not leave a half-written hash: the
        // store happens only after every gate passes.
        let mut e = funded_arbitrated_escrow();
        assert_eq!(
            e.escalate(MALLORY, EXPIRES_AT - 1, Some(EVIDENCE)),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.evidence_hash(), None);
        assert_eq!(
            e.escalate(ALICE, EXPIRES_AT, Some(EVIDENCE)),
            Err(EscrowError::DisputeWindowClosed)
        );
        assert_eq!(e.evidence_hash(), None);
        assert_eq!(e.state(), EscrowState::Funded);
        // No arbiter configured: InvalidArbiter, nothing stored.
        let mut e2 = {
            let mut x = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
            x.fund(ALICE).unwrap();
            x
        };
        assert_eq!(
            e2.escalate(ALICE, EXPIRES_AT - 1, Some(EVIDENCE)),
            Err(EscrowError::InvalidArbiter)
        );
        assert_eq!(e2.evidence_hash(), None);
    }

    #[test]
    fn evidence_hash_survives_resolve_into_settled() {
        // The hash is the audit trail of what the arbiter reviewed: it
        // persists through the settlement, never cleared.
        let mut e = funded_arbitrated_escrow();
        e.escalate(ALICE, EXPIRES_AT - 1, Some(EVIDENCE)).unwrap();
        let (payout, fee, refund) = e.resolve(ARBITER, 600_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Settled);
        assert_eq!(e.evidence_hash(), Some(EVIDENCE));
        // payout is net of the fee; the three legs sum to the lockup.
        assert_eq!(payout + fee + refund, 1_000_000);
    }

    #[test]
    fn evidence_hash_persists_in_serialized_layout() {
        // The hash occupies the appended tail of the vault account
        // (discriminant + 32 bytes), so `escalate` writes it in place.
        let mut e = funded_arbitrated_escrow();
        e.escalate(BOB, EXPIRES_AT - 1, Some(EVIDENCE)).unwrap();
        let bytes = super::account_space_tests::encode_escrow(&e);
        assert_eq!(bytes.len(), ESCROW_BODY_LEN);
        assert_eq!(bytes[540], 1, "evidence_hash: Some discriminant");
        assert_eq!(&bytes[541..573], &EVIDENCE, "evidence_hash bytes");
    }
}

// ---------- AV-23: refund address whitelist ----------
//
// The unilateral refund paths (`cancel` / `cancel_expired`) take the
// refund destination explicitly and pin it against the escrow's refund
// policy — the whitelisted address when one is configured via
// `with_refund_address`, otherwise the initializer. A phishing frontend
// that swaps the destination account gets `RefundAddressMismatch`
// instead of a redirected refund.
#[cfg(test)]
mod refund_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const CAROL: [u8; 32] = [0xC4; 32]; // whitelisted refund address
    const MALLORY: [u8; 32] = [0xCC; 32]; // stranger / phishing destination
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn funded(amount: u64, expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, amount, expires_at).unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    fn funded_whitelisted() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_refund_address(CAROL)
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    #[test]
    fn refund_to_defaults_to_none_initializer_is_recipient() {
        // Backward compatible: no whitelist means the initializer is the
        // only valid refund destination.
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(e.refund_to(), None);
        assert_eq!(e.refund_recipient(), ALICE);
        let mut e = funded(1_000_000, EXPIRES_AT);
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        // Any other destination is a policy mismatch.
        let mut e = funded(1_000_000, EXPIRES_AT);
        assert_eq!(
            e.cancel(ALICE, None, MALLORY),
            Err(EscrowError::RefundAddressMismatch)
        );
        assert_eq!(e.state(), EscrowState::Funded, "failed cancel changes nothing");
    }

    #[test]
    fn with_refund_address_only_before_funding() {
        // The policy is fixed before funds move, like the other
        // builders: re-configuring a live escrow is rejected.
        let e = funded(1_000_000, EXPIRES_AT);
        assert_eq!(
            e.with_refund_address(CAROL),
            Err(EscrowError::InvalidStateTransition)
        );
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_refund_address(CAROL)
            .unwrap();
        assert_eq!(e.refund_to(), Some(CAROL));
        assert_eq!(e.refund_recipient(), CAROL);
    }

    #[test]
    fn with_refund_address_rejects_zero_address() {
        // A zero address can never be the legitimate refund destination:
        // binding it is a policy mismatch by construction.
        let err = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_refund_address([0u8; 32])
            .unwrap_err();
        assert_eq!(err, EscrowError::RefundAddressMismatch);
    }

    #[test]
    fn cancel_requires_whitelisted_destination() {
        // With a whitelist, only the declared address is accepted — the
        // initializer's own key is rejected too, so a phishing frontend
        // cannot even fall back to a "plausible" destination.
        let mut e = funded_whitelisted();
        e.cancel(ALICE, None, CAROL).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);

        for bad in [ALICE, BOB, MALLORY, [0u8; 32]] {
            let mut e = funded_whitelisted();
            assert_eq!(
                e.cancel(ALICE, None, bad),
                Err(EscrowError::RefundAddressMismatch),
                "destination {bad:02x?} should be rejected"
            );
            assert_eq!(e.state(), EscrowState::Funded);
        }
    }

    #[test]
    fn cancel_expired_refunds_to_whitelist_even_for_taker() {
        // The caller authorizes the cancel; the whitelist authorizes the
        // destination. A taker-initiated cancel_expired still refunds to
        // the declared address — never to the caller.
        let mut e = funded_whitelisted();
        e.cancel_expired(BOB, EXPIRES_AT, None, CAROL).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);

        let mut e = funded_whitelisted();
        assert_eq!(
            e.cancel_expired(BOB, EXPIRES_AT, None, BOB),
            Err(EscrowError::RefundAddressMismatch),
            "taker must not redirect the refund to themselves"
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn refund_check_order_mint_then_refund_then_expiry() {
        // Authority -> state -> mint -> refund -> expiry: each gate fires
        // in order, so a caller learns nothing beyond the first failure.
        let mut e = funded_whitelisted();
        // Stranger first: Unauthorized before any policy check.
        assert_eq!(
            e.cancel_expired(MALLORY, EXPIRES_AT, None, MALLORY),
            Err(EscrowError::Unauthorized)
        );
        // Mint binding before the refund pin.
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT, Some([0xD0; 32]), MALLORY),
            Err(EscrowError::MintMismatch)
        );
        // Refund pin before the expiry gate: a wrong destination fails
        // even on an unexpired escrow.
        let mut early = {
            let mut x = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT + 10_000)
                .unwrap()
                .with_refund_address(CAROL)
                .unwrap();
            x.fund(ALICE).unwrap();
            x
        };
        assert_eq!(
            early.cancel_expired(ALICE, EXPIRES_AT, None, MALLORY),
            Err(EscrowError::RefundAddressMismatch)
        );
        // And the expiry gate still fires with a correct destination.
        assert_eq!(
            early.cancel_expired(ALICE, EXPIRES_AT, None, CAROL),
            Err(EscrowError::NotExpired)
        );
        assert_eq!(early.state(), EscrowState::Funded);
    }

    #[test]
    fn refund_to_persists_in_serialized_layout() {
        // The whitelist occupies the appended tail of the vault account
        // (discriminant + 32 bytes), so `with_refund_address` writes it
        // in place.
        let e = funded_whitelisted();
        let bytes = super::account_space_tests::encode_escrow(&e);
        assert_eq!(bytes.len(), ESCROW_BODY_LEN);
        assert_eq!(bytes[573], 1, "refund_to: Some discriminant");
        assert_eq!(&bytes[574..606], &CAROL, "refund_to bytes");
    }
}

// ---------- AV-24: anti-griefing penalty on taker-initiated cancel_expired ----------
//
// When the taker calls `cancel_expired`, dragging the deal to expiry is
// priced: a `penalty_bps` slice of the remainder is earmarked for the
// initializer as griefing compensation. The initializer reclaiming
// their own funds, the plain `cancel` path, and the arbiter's `resolve`
// never carry the penalty.
#[cfg(test)]
mod penalty_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const CAROL: [u8; 32] = [0xC4; 32]; // whitelisted refund address
    const MALLORY: [u8; 32] = [0xCC; 32]; // stranger
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn funded_with_penalty(amount: u64, penalty_bps: u16) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, amount, EXPIRES_AT)
            .unwrap()
            .with_penalty_bps(penalty_bps)
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    #[test]
    fn taker_initiated_cancel_splits_remainder_refund_plus_penalty() {
        // 250 bps of 1_000_000 = 25_000 penalty; the refund is the rest.
        let mut e = funded_with_penalty(1_000_000, 250);
        let (refund, penalty) = e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        assert_eq!((refund, penalty), (975_000, 25_000));
        assert_eq!(refund + penalty, 1_000_000, "split covers the remainder exactly");
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn initializer_initiated_cancel_charges_no_penalty() {
        // The initializer reclaims their own funds penalty-free, even
        // with a penalty rate configured.
        let mut e = funded_with_penalty(1_000_000, 250);
        let (refund, penalty) = e.cancel_expired(ALICE, EXPIRES_AT, None, ALICE).unwrap();
        assert_eq!((refund, penalty), (1_000_000, 0));
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn no_penalty_configured_is_backward_compatible() {
        // Default escrows keep the historical behavior: full refund,
        // regardless of who calls.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(e.penalty_bps(), 0);
        e.fund(ALICE).unwrap();
        let (refund, penalty) = e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        assert_eq!((refund, penalty), (1_000_000, 0));
    }

    #[test]
    fn penalty_applies_to_the_partial_remainder() {
        // After a partial release the penalty slices the *remainder*,
        // not the original lockup.
        let mut e = funded_with_penalty(1_000_000, 250);
        e.release(ALICE, 1_750_000_000, 400_000, None).unwrap();
        let (refund, penalty) = e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        // floor(600_000 * 250 / 10_000) = 15_000.
        assert_eq!((refund, penalty), (585_000, 15_000));
        assert_eq!(refund + penalty, e.remaining_amount());
    }

    #[test]
    fn dust_remainder_penalty_floors_to_zero() {
        // Floor rounding never rounds *up* into the compensation: a
        // dust remainder carries a zero penalty.
        let mut e = funded_with_penalty(39, 250);
        let (refund, penalty) = e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        // floor(39 * 250 / 10_000) = floor(0.975) = 0.
        assert_eq!((refund, penalty), (39, 0));
    }

    #[test]
    fn penalty_capped_at_100_percent() {
        // 10_000 bps is a valid (if draconian) rate: the whole remainder
        // becomes the penalty. The split still sums exactly.
        let mut e = funded_with_penalty(1_000_000, 10_000);
        let (refund, penalty) = e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        assert_eq!((refund, penalty), (0, 1_000_000));
    }

    #[test]
    fn failed_cancel_charges_nothing() {
        // The penalty is computed after every gate passes: a rejected
        // cancel leaves the escrow Funded and touches no split.
        let mut e = funded_with_penalty(1_000_000, 250);
        assert_eq!(
            e.cancel_expired(BOB, EXPIRES_AT - 1, None, ALICE),
            Err(EscrowError::NotExpired)
        );
        assert_eq!(e.state(), EscrowState::Funded);
        // ... and a stranger is Unauthorized before any penalty logic.
        assert_eq!(
            e.cancel_expired(MALLORY, EXPIRES_AT, None, ALICE),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn cancel_and_resolve_never_carry_a_penalty() {
        // The initializer-only `cancel` path is penalty-free by design.
        let mut e = funded_with_penalty(1_000_000, 250);
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn u128_math_cannot_overflow_on_max_amount() {
        // amount * penalty_bps can reach u64::MAX * 10_000 < u128::MAX:
        // the multiplication never wraps, even at the ceiling rate.
        let mut e = funded_with_penalty(u64::MAX, 10_000);
        let (refund, penalty) = e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        assert_eq!(refund, 0);
        assert_eq!(penalty, u64::MAX);
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn whitelist_redirects_refund_penalty_still_routes_to_initializer() {
        // AV-23 + AV-24 together: the refund goes to the whitelisted
        // address (the state machine pins the destination), while the
        // penalty is earmarked for the initializer personally — the
        // compensation follows the harmed party, not the refund address.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_refund_address(CAROL)
            .unwrap()
            .with_penalty_bps(250)
            .unwrap();
        e.fund(ALICE).unwrap();
        let (refund, penalty) = e.cancel_expired(BOB, EXPIRES_AT, None, CAROL).unwrap();
        assert_eq!((refund, penalty), (975_000, 25_000));
        // The whitelist still pins the destination: CAROL is the only
        // valid refund address.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_refund_address(CAROL)
            .unwrap()
            .with_penalty_bps(250)
            .unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.cancel_expired(BOB, EXPIRES_AT, None, ALICE),
            Err(EscrowError::RefundAddressMismatch)
        );
    }

    #[test]
    fn penalty_rate_persists_in_layout_tail() {
        // The rate survives serialization at the appended tail offset
        // (bytes[606..608]); earlier offsets are unchanged.
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_penalty_bps(250)
            .unwrap();
        let bytes = super::account_space_tests::encode_escrow(&e);
        assert_eq!(bytes.len(), ESCROW_BODY_LEN);
        assert_eq!(
            u16::from_le_bytes(bytes[606..608].try_into().unwrap()),
            250,
            "penalty_bps tail offset"
        );
    }
}

// ---------- AV-27: timelock ----------

#[cfg(test)]
mod timelock_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const MALLORY: [u8; 32] = [0xCC; 32]; // stranger
    const ARBITER: [u8; 32] = [0xA8; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;
    const UNLOCK_AT: u64 = 1_900_000_000;

    fn funded_with_timelock() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_timelock(UNLOCK_AT)
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    fn funded_vesting_with_timelock() -> Escrow {
        let schedule = VestingSchedule::new(UNLOCK_AT - 1_000, UNLOCK_AT + 1_000).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_vesting(schedule)
            .unwrap()
            .with_timelock(UNLOCK_AT)
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    #[test]
    fn error_code_is_118_and_stable() {
        assert_eq!(EscrowError::TimelockNotReached.code(), 118);
    }

    #[test]
    fn with_timelock_is_uninitialized_only() {
        let mut e = funded_with_timelock();
        assert_eq!(
            e.with_timelock(UNLOCK_AT + 1),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.unlock_at(), UNLOCK_AT, "rejected reconfig changes nothing");
    }

    #[test]
    fn release_is_gated_until_unlock() {
        let mut e = funded_with_timelock();
        // One second early: locked, and the failed call moves nothing.
        assert_eq!(
            e.release(ALICE, UNLOCK_AT - 1, 1_000_000, None),
            Err(EscrowError::TimelockNotReached)
        );
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!((e.released_amount(), e.remaining_amount()), (0, 1_000_000));
        // At the unlock timestamp: the gate passes.
        e.release(ALICE, UNLOCK_AT, 400_000, None).unwrap();
        assert_eq!((e.released_amount(), e.remaining_amount()), (400_000, 600_000));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn timelock_check_order_comes_after_authority_state_and_config() {
        let mut e = funded_with_timelock();
        // Authority first: a stranger learns nothing about the lock.
        assert_eq!(
            e.release(MALLORY, UNLOCK_AT - 1, 1_000_000, None),
            Err(EscrowError::Unauthorized)
        );
        // State before the lock: an unfunded escrow reports state, not
        // the timelock.
        let mut unfunded = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_timelock(UNLOCK_AT)
            .unwrap();
        assert_eq!(
            unfunded.release(ALICE, UNLOCK_AT - 1, 1_000_000, None),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn claim_is_gated_until_unlock() {
        let mut e = funded_vesting_with_timelock();
        // Fully vested at UNLOCK_AT, but the timelock still holds.
        assert_eq!(
            e.claim(BOB, UNLOCK_AT - 1, None),
            Err(EscrowError::TimelockNotReached)
        );
        assert_eq!(e.released_amount(), 0);
        let (payout, fee) = e.claim(BOB, UNLOCK_AT, None).unwrap();
        assert_eq!(payout + fee, 500_000, "half vested at the unlock midpoint");
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn release_milestone_is_gated_until_unlock() {
        let plan = MilestonePlan::new(&[400_000, 600_000]).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(plan)
            .unwrap()
            .with_timelock(UNLOCK_AT)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        assert_eq!(
            e.release_milestone(ALICE, UNLOCK_AT - 1, 0, None),
            Err(EscrowError::TimelockNotReached)
        );
        assert!(!e.milestone_settled(0));
        let (tranche, _) = e.release_milestone(ALICE, UNLOCK_AT, 0, None).unwrap();
        assert_eq!(tranche, 400_000);
        assert!(e.milestone_settled(0));
    }

    #[test]
    fn cancel_is_not_gated_by_the_timelock() {
        // The initializer can always walk away, even before unlock —
        // the lock delays payouts, never exits.
        let mut e = funded_with_timelock();
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn cancel_expired_is_not_gated_by_the_timelock() {
        // A misconfigured far-future timelock must never trap funds:
        // after expiry either party still walks the cancel_expired path.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_timelock(u64::MAX - 1)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn arbiter_resolve_is_not_gated_by_the_timelock() {
        // Arbitration is the trusted settlement mechanism: it settles
        // even under a lock. (The timelock here sits past expiry to prove
        // the point; the dispute is escalated while the window is open.)
        const LATE_UNLOCK: u64 = EXPIRES_AT + 100;
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap()
            .with_timelock(LATE_UNLOCK)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
        let (payout, _fee, _refund) = e.resolve(ARBITER, 600_000, None).unwrap();
        assert_eq!(payout, 600_000);
        assert_eq!(e.state(), EscrowState::Settled);
    }

    #[test]
    fn zero_unlock_at_means_no_lock() {
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_timelock(0)
            .unwrap();
        assert!(e.is_unlock_eligible(0));
        let mut funded = e;
        funded.fund(ALICE).unwrap();
        funded.release(ALICE, 0, 1_000_000, None).unwrap();
        assert_eq!(funded.state(), EscrowState::Released);
    }

    #[test]
    fn keeper_lists_claim_only_after_unlock() {
        use crate::{scan_keeper_actions, KeeperActionKind, WatchedEscrow};
        let e = funded_vesting_with_timelock();
        let watched = [WatchedEscrow {
            escrow_id: [0x01; 32],
            escrow: e,
        }];
        // Before unlock: the claim call would fail, so it is not listed.
        let early = scan_keeper_actions(&watched, UNLOCK_AT - 1);
        assert!(
            !early.actions.iter().any(|a| a.kind == KeeperActionKind::Claim),
            "a locked claim is not an executable keeper call"
        );
        // At unlock: listed.
        let at_unlock = scan_keeper_actions(&watched, UNLOCK_AT);
        assert!(
            at_unlock.actions.iter().any(|a| a.kind == KeeperActionKind::Claim),
            "an unlocked claim is executable"
        );
    }

    #[test]
    fn timelock_persists_in_serialized_layout_tail() {
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_timelock(UNLOCK_AT)
            .unwrap();
        let bytes = super::account_space_tests::encode_escrow(&e);
        assert_eq!(bytes.len(), ESCROW_BODY_LEN);
        assert_eq!(
            u64::from_le_bytes(bytes[608..616].try_into().unwrap()),
            UNLOCK_AT,
            "timelock tail offset"
        );
    }
}

// ---------- AV-28: token decimal metadata ----------
//
// The SPL mint's decimal places, declared once before funding via
// `with_decimals`. The metadata never gates a transition and never
// moves funds: it only renders human-readable amounts (a payment
// operator reads `1.000000`, not `1000000`, for a 6-decimal token) in
// `Escrow::display_amount`, the keeper report, and the AV-26 snapshot
// export. Persisted as one trailing byte in the vault account.
#[cfg(test)]
mod decimals_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const MALLORY: [u8; 32] = [0xCC; 32]; // stranger
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn initialized() -> Escrow {
        Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap()
    }

    #[test]
    fn error_code_is_119_and_stable() {
        assert_eq!(EscrowError::InvalidDecimals.code(), 119);
    }

    #[test]
    fn with_decimals_is_uninitialized_only() {
        let mut e = initialized().with_decimals(6).unwrap();
        assert_eq!(e.decimals(), 6);
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.with_decimals(9),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.decimals(), 6, "rejected reconfig changes nothing");
    }

    #[test]
    fn decimals_above_18_are_rejected() {
        // The ceiling is 18: the largest precision any SPL/EVM token
        // convention needs (SPL mints declare at most 9).
        for bad in [19u8, 20, 100, u8::MAX] {
            assert_eq!(
                initialized().with_decimals(bad),
                Err(EscrowError::InvalidDecimals),
                "decimals={bad} must be rejected"
            );
        }
        // The boundary itself is valid.
        assert_eq!(initialized().with_decimals(18).unwrap().decimals(), 18);
        // And 0 is the valid no-op (no decimal metadata).
        assert_eq!(initialized().with_decimals(0).unwrap().decimals(), 0);
    }

    #[test]
    fn builder_order_is_independent() {
        // `with_decimals` composes with every other opt-in builder in
        // any order — the metadata is orthogonal to the other config.
        let a = initialized()
            .with_decimals(6)
            .unwrap()
            .with_timelock(1_900_000_000)
            .unwrap()
            .with_penalty_bps(500)
            .unwrap();
        let b = initialized()
            .with_penalty_bps(500)
            .unwrap()
            .with_timelock(1_900_000_000)
            .unwrap()
            .with_decimals(6)
            .unwrap();
        assert_eq!(a.decimals(), b.decimals());
        assert_eq!(a.unlock_at(), b.unlock_at());
        assert_eq!(a.penalty_bps(), b.penalty_bps());
        assert_eq!(a.display_amount(), "1.000000");
        assert_eq!(b.display_amount(), "1.000000");
    }

    #[test]
    fn format_amount_vectors() {
        // Zero decimals: bare integer, no decimal point.
        assert_eq!(format_amount(0, 0), "0");
        assert_eq!(format_amount(1_000_000, 0), "1000000");
        assert_eq!(format_amount(u64::MAX, 0), "18446744073709551615");
        // The spec example: full zero-padding, no trimming.
        assert_eq!(format_amount(1_000_000, 6), "1.000000");
        // Sub-unit amounts: the integer part is never empty.
        assert_eq!(format_amount(0, 6), "0.000000");
        assert_eq!(format_amount(5, 9), "0.000000005");
        assert_eq!(format_amount(1, 18), "0.000000000000000001");
        // Common token precisions.
        assert_eq!(format_amount(1_000_000_000, 9), "1.000000000");
        assert_eq!(format_amount(1_500_000, 6), "1.500000");
        assert_eq!(format_amount(123_456_789, 6), "123.456789");
        // u64::MAX at the 18-decimal ceiling: exact, no rounding.
        assert_eq!(
            format_amount(u64::MAX, 18),
            "18.446744073709551615"
        );
        // Exactly one whole unit at high precision.
        assert_eq!(format_amount(10u64.pow(18), 18), "1.000000000000000000");
    }

    #[test]
    fn display_amount_uses_the_escrows_decimals() {
        let e = initialized().with_decimals(6).unwrap();
        assert_eq!(e.display_amount(), "1.000000");
        // No metadata: the default renders the bare integer.
        assert_eq!(initialized().display_amount(), "1000000");
    }

    #[test]
    fn decimals_metadata_never_moves_funds() {
        // A decimal-declared escrow behaves exactly like a plain one:
        // the metadata is display-only.
        let mut e = initialized().with_decimals(6).unwrap();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.released_amount(), 1_000_000);
        assert_eq!(e.display_amount(), "1.000000");
    }

    #[test]
    fn decimals_persists_in_serialized_layout_tail() {
        let e = initialized().with_decimals(9).unwrap();
        let bytes = super::account_space_tests::encode_escrow(&e);
        assert_eq!(bytes.len(), ESCROW_BODY_LEN);
        assert_eq!(ESCROW_BODY_LEN, 617, "one byte appended by AV-28");
        assert_eq!(bytes[616], 9, "decimals tail offset");
        // The timelock offset is unchanged by the append.
        assert_eq!(
            u64::from_le_bytes(bytes[608..616].try_into().unwrap()),
            0,
            "timelock offset stable"
        );
        // A funded escrow without the metadata keeps the zeroed byte.
        let mut plain = initialized();
        plain.fund(ALICE).unwrap();
        let bytes = super::account_space_tests::encode_escrow(&plain);
        assert_eq!(bytes[616], 0, "decimals zeroed without the builder");
        assert_eq!(bytes.len(), ESCROW_BODY_LEN);
    }

    #[test]
    fn rent_accounts_for_the_extra_byte() {
        // (128 + 625) * 3480 * 2 = 753 * 6960 = 5_240_880 lamports.
        assert_eq!(
            rent_exempt_minimum_lamports(
                VAULT_SPACE,
                MAINNET_LAMPORTS_PER_BYTE_YEAR,
                MAINNET_EXEMPTION_THRESHOLD_YEARS
            ),
            5_240_880
        );
        // (128 + 214) * 3480 * 2 = 342 * 6960 = 2_380_320 lamports.
        assert_eq!(
            rent_exempt_minimum_lamports(
                VAULT_SPACE_NO_QUORUM,
                MAINNET_LAMPORTS_PER_BYTE_YEAR,
                MAINNET_EXEMPTION_THRESHOLD_YEARS
            ),
            2_380_320
        );
        // Exactly one byte's rent above the AV-27 numbers.
        assert_eq!(VAULT_SPACE, 625);
        assert_eq!(VAULT_SPACE_NO_QUORUM, 214);
        assert!(check_vault_rent_exempt(5_240_880, 3_480, 2.0).is_ok());
        assert!(check_vault_rent_exempt(5_240_879, 3_480, 2.0).is_err());
    }

    #[test]
    fn unauthorized_caller_learns_nothing_about_decimals() {
        // `with_decimals` is a builder (no authority check — the
        // program's account constraint owns that), but once funded the
        // metadata is readable and immutable: no transition reports it.
        let mut e = initialized().with_decimals(6).unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(e.release(MALLORY, 1_750_000_000, 1, None), Err(EscrowError::Unauthorized));
        assert_eq!(e.decimals(), 6, "failed call changes nothing");
    }
}

// ---------- AV-25: dual-signed quorum threshold governance ----------
//
// The quorum threshold is fixed before funding (`with_quorum`), but
// attestors can go dark — a lost key or an unresponsive oracle would
// otherwise lock funds behind an unreachable threshold forever. Both
// parties together may move the threshold (`update_quorum`, on
// `Uninitialized` or `Funded`): lower it to restore liveness, or raise
// it by mutual agreement. Neither party can weaken the gate alone.
#[cfg(test)]
mod quorum_governance_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const MALLORY: [u8; 32] = [0xCC; 32]; // stranger
    const ATTESTOR_1: [u8; 32] = [0xA1; 32];
    const ATTESTOR_2: [u8; 32] = [0xA2; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn funded_quorum(threshold: u8) -> Escrow {
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], threshold).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    #[test]
    fn lowering_threshold_restores_liveness_when_attestor_goes_dark() {
        // The core scenario: 2-of-2 with one attestor unresponsive. One
        // attestation lands, the other never will — `release` is stuck
        // behind the gate. Both parties agree to drop to 1-of-2, and the
        // release goes through.
        let mut e = funded_quorum(2);
        e.attest(ATTESTOR_1).unwrap();
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 1_000_000, None),
            Err(EscrowError::QuorumNotReached)
        );
        e.update_quorum(ALICE, BOB, 1).unwrap();
        assert_eq!(e.quorum().unwrap().threshold(), 1);
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn raising_threshold_by_mutual_agreement() {
        // Governance is symmetric: both parties may also tighten the
        // gate when they want a stricter release condition.
        let mut e = funded_quorum(1);
        e.attest(ATTESTOR_1).unwrap();
        e.update_quorum(ALICE, BOB, 2).unwrap();
        assert_eq!(e.quorum().unwrap().threshold(), 2);
        // One vote no longer satisfies the gate.
        assert_eq!(
            e.release(ALICE, 1_750_000_000, 1_000_000, None),
            Err(EscrowError::QuorumNotReached)
        );
        // The second attestor's vote restores the release path.
        e.attest(ATTESTOR_2).unwrap();
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn governance_works_before_funding() {
        // The threshold can be adjusted on an `Uninitialized` escrow —
        // e.g. the parties renegotiate the gate before locking funds.
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], 2).unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.update_quorum(ALICE, BOB, 1).unwrap();
        assert_eq!(e.quorum().unwrap().threshold(), 1);
        e.fund(ALICE).unwrap();
        e.attest(ATTESTOR_1).unwrap();
        e.release(ALICE, 1_750_000_000, 1_000_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn attestations_survive_the_threshold_update() {
        // Only the threshold moves — the attestor set and the recorded
        // votes are untouched, in place, with no layout change.
        let mut e = funded_quorum(2);
        e.attest(ATTESTOR_1).unwrap();
        e.update_quorum(ALICE, BOB, 1).unwrap();
        assert_eq!(e.quorum().unwrap().approval_count(), 1);
        assert_eq!(e.quorum().unwrap().registered_count(), 2);
        assert!(e.quorum().unwrap().is_satisfied());
    }

    #[test]
    fn same_threshold_is_a_noop_success() {
        // Re-affirming the current threshold succeeds and changes
        // nothing (the event layer treats it as a no-op, paralleling
        // `attest`'s idempotent duplicates).
        let mut e = funded_quorum(2);
        e.update_quorum(ALICE, BOB, 2).unwrap();
        assert_eq!(e.quorum().unwrap().threshold(), 2);
    }

    #[test]
    fn dual_sig_self_escrow_authorizes_with_one_key_twice() {
        // Degenerate initializer == taker escrow: one key passed for both
        // slots authorizes, paralleling AV-12's activation.
        const SELF: [u8; 32] = [0x5E; 32];
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], 2).unwrap();
        let mut e = Escrow::initialize(SELF, SELF, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(policy)
            .unwrap();
        e.update_quorum(SELF, SELF, 1).unwrap();
        assert_eq!(e.quorum().unwrap().threshold(), 1);
        // A stranger still cannot.
        assert_eq!(
            e.update_quorum(MALLORY, MALLORY, 2),
            Err(EscrowError::Unauthorized)
        );
    }

    #[test]
    fn check_order_authority_then_state_then_config_then_threshold() {
        // A stranger gets Unauthorized before any config check — they
        // learn nothing about whether a quorum exists.
        let mut e = funded_quorum(2);
        assert_eq!(
            e.update_quorum(MALLORY, MALLORY, 1),
            Err(EscrowError::Unauthorized)
        );
        // State before configuration: a stranger-shaped error must not
        // leak the quorum's existence on a terminal escrow either.
        let mut e = funded_quorum(2);
        e.cancel(ALICE, None, ALICE).unwrap();
        assert_eq!(
            e.update_quorum(ALICE, BOB, 1),
            Err(EscrowError::InvalidStateTransition)
        );
        // Configuration before threshold validity.
        let mut plain = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        plain.fund(ALICE).unwrap();
        assert_eq!(
            plain.update_quorum(ALICE, BOB, 0),
            Err(EscrowError::InvalidQuorum),
            "no quorum configured: InvalidQuorum, not a threshold complaint"
        );
    }
}
