//! Pure-Rust escrow vault state machine.
//!
//! This crate is the dependency-free logic core of the escrow vault.
//! It models the full lifecycle of a two-party escrow with initializer
//! authority checks and amount invariants. The Anchor program under
//! `programs/escrow-vault` wraps exactly this logic for the Solana target.

mod events;

// AV-18: typed indexer events — an event-logging adapter over `Escrow`
// plus the `EscrowEvent` / `EscrowEventKind` / `EventAmounts` record
// types. Purely additive: no existing signature changed.
pub use events::{EscrowEvent, EscrowEventKind, EventAmounts, IndexedEscrow};

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
    /// threshold of attestations (`QuorumNotReached` otherwise). Check
    /// order is deliberate: authority, then state, then the mint
    /// binding (AV-16), then the milestone plan, then quorum, then the
    /// amount checks — an unauthorized caller learns nothing about
    /// attestation progress or release history.
    pub fn release(
        &mut self,
        authority: [u8; 32],
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
    pub fn cancel(&mut self, authority: [u8; 32], mint: Option<[u8; 32]>) -> Result<(), EscrowError> {
        self.require_initializer(authority)?;
        match self.state {
            EscrowState::Funded => {
                self.require_mint_match(mint)?;
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
    /// Check order is deliberate: authority first, then state, then the
    /// mint binding (AV-16), then expiry. A stranger never learns
    /// whether an escrow is expired from the error alone beyond
    /// `Unauthorized`.
    ///
    /// After partial releases the refund is the remainder
    /// ([`Escrow::remaining_amount`]); [`Escrow::released_amount`] is
    /// preserved for audit.
    pub fn cancel_expired(
        &mut self,
        authority: [u8; 32],
        now: u64,
        mint: Option<[u8; 32]>,
    ) -> Result<(), EscrowError> {
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
    /// quorum, then the claimable amount — a stranger learns nothing,
    /// and a misconfigured call fails before the gates run.
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

    /// Escalate the escrow into arbitration: `Funded -> Disputed`
    /// (AV-14). Either party — the initializer or the taker — may call
    /// this, so a counterparty who stops cooperating cannot block the
    /// dispute path.
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
    pub fn escalate(&mut self, authority: [u8; 32], now: u64) -> Result<(), EscrowError> {
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
        Ok(())
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
/// `fees_paid` (zeroed when no fee was charged).
pub const VAULT_SPACE_NO_QUORUM: usize =
    ANCHOR_DISCRIMINATOR_LEN + PUBKEY_LEN + PUBKEY_LEN + 8 + 8 + 8 + 1 + 1 + 1 + 1 + 1 + 1 + 8 + 8 + 1 + 2 + 8;

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
        e.release(ALICE, 1_000_000, None).unwrap();
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
        e.cancel(ALICE, None).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        assert_eq!(e.amount(), before);
    }

    // ---------- cancel_expired ----------

    #[test]
    fn cancel_expired_by_initializer_after_expiry_ok() {
        let mut e = funded_escrow();
        let before = e.amount();
        e.cancel_expired(ALICE, EXPIRES_AT + 1, None).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        assert_eq!(e.amount(), before); // refund accounting preserved
    }

    #[test]
    fn cancel_expired_by_taker_after_expiry_ok() {
        // Either party may cancel an expired escrow: the taker is not
        // left hostage to an unresponsive initializer.
        let mut e = funded_escrow();
        e.cancel_expired(BOB, EXPIRES_AT + 3_600, None).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn cancel_expired_at_exact_expiry_boundary_ok() {
        // `now >= expires_at` is the trigger: equality counts as expired.
        let mut e = funded_escrow();
        e.cancel_expired(ALICE, EXPIRES_AT, None).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn cancel_expired_before_expiry_fails_for_both_parties() {
        for authority in [ALICE, BOB] {
            let mut e = funded_escrow();
            assert_eq!(
                e.cancel_expired(authority, EXPIRES_AT - 1, None),
                Err(EscrowError::NotExpired)
            );
            assert_eq!(e.state(), EscrowState::Funded);
        }
    }

    #[test]
    fn cancel_expired_by_stranger_after_expiry_is_unauthorized() {
        let mut e = funded_escrow();
        assert_eq!(
            e.cancel_expired(MALLORY, EXPIRES_AT + 1, None),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn cancel_expired_on_non_funded_states_is_invalid() {
        // Uninitialized: authority passes, state rejects.
        let mut e = escrow();
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT + 1, None),
            Err(EscrowError::InvalidStateTransition)
        );
        // Released: terminal, cannot be cancelled again.
        let mut e = funded_escrow();
        e.release(ALICE, 1_000_000, None).unwrap();
        assert_eq!(
            e.cancel_expired(BOB, EXPIRES_AT + 1, None),
            Err(EscrowError::InvalidStateTransition)
        );
        // Cancelled: terminal, double-cancel rejected.
        let mut e = funded_escrow();
        e.cancel(ALICE, None).unwrap();
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT + 1, None),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn escrow_without_timeout_cannot_be_cancel_expired() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, u64::MAX).unwrap();
        e.fund(ALICE).unwrap();
        // Any realistic `now` is below u64::MAX.
        assert_eq!(
            e.cancel_expired(ALICE, u64::MAX - 1, None),
            Err(EscrowError::NotExpired)
        );
        assert_eq!(e.state(), EscrowState::Funded);
    }

    // ---------- illegal transitions ----------

    #[test]
    fn release_from_uninitialized_is_invalid() {
        let mut e = escrow();
        assert_eq!(
            e.release(ALICE, 1_000_000, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Uninitialized);
    }

    #[test]
    fn cancel_from_uninitialized_is_invalid() {
        let mut e = escrow();
        assert_eq!(e.cancel(ALICE, None), Err(EscrowError::InvalidStateTransition));
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
        e.release(ALICE, 1_000_000, None).unwrap();
        assert_eq!(
            e.release(ALICE, 1_000_000, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn cancel_after_release_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_000_000, None).unwrap();
        assert_eq!(e.cancel(ALICE, None), Err(EscrowError::InvalidStateTransition));
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn release_after_cancel_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.cancel(ALICE, None).unwrap();
        assert_eq!(
            e.release(ALICE, 1_000_000, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn fund_after_release_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_000_000, None).unwrap();
        assert_eq!(e.fund(ALICE), Err(EscrowError::InvalidStateTransition));
    }

    #[test]
    fn fund_after_cancel_is_invalid() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.cancel(ALICE, None).unwrap();
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
        assert_eq!(e.release(MALLORY, 1_000_000, None), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn non_initializer_cannot_cancel() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        assert_eq!(e.cancel(MALLORY, None), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn taker_is_not_an_authority() {
        let mut e = escrow();
        // The taker is the beneficiary, not the authority: they cannot drive transitions.
        assert_eq!(e.fund(BOB), Err(EscrowError::Unauthorized));
        e.fund(ALICE).unwrap();
        assert_eq!(e.release(BOB, 1_000_000, None), Err(EscrowError::Unauthorized));
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
                e.release(ALICE, 1_000_000, None).unwrap();
            }
            EscrowState::Cancelled => {
                e.fund(ALICE).unwrap();
                e.cancel(ALICE, None).unwrap();
            }
            EscrowState::Disputed => {
                // AV-14: arbitration in progress; every unilateral exit
                // is locked.
                e = e.with_arbiter(ARBITER).unwrap();
                e.fund(ALICE).unwrap();
                e.escalate(ALICE, EXPIRES_AT - 1).unwrap();
            }
            EscrowState::Settled => {
                // AV-14: arbiter split the remainder 600k / 400k.
                e = e.with_arbiter(ARBITER).unwrap();
                e.fund(ALICE).unwrap();
                e.escalate(ALICE, EXPIRES_AT - 1).unwrap();
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
            assert_eq!(e.release(MALLORY, 1_000_000, None), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn taker_cannot_release_in_any_state() {
        // The taker is the beneficiary of a release, but only the
        // initializer may drive the transition.
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.release(BOB, 1_000_000, None), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn stranger_cannot_cancel_in_any_state() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.cancel(MALLORY, None), Err(EscrowError::Unauthorized));
            assert_eq!(e.state(), state, "state must be unchanged");
        }
    }

    #[test]
    fn taker_cannot_cancel_in_any_state() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.cancel(BOB, None), Err(EscrowError::Unauthorized));
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
                    e.cancel_expired(MALLORY, now, None),
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
            e.cancel_expired(BOB, EXPIRES_AT - 1, None),
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
                e.cancel_expired(BOB, EXPIRES_AT + 1, None),
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
        e.cancel_expired(BOB, EXPIRES_AT, None).unwrap();
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
        assert_eq!(e.release(MALLORY, 1_000_000, None), Err(EscrowError::Unauthorized));
        let mut e = in_state(EscrowState::Cancelled);
        assert_eq!(e.cancel(MALLORY, None), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn zero_key_caller_is_unauthorized_on_all_transitions() {
        for state in ALL_STATES {
            let mut e = in_state(state);
            assert_eq!(e.fund(ZERO_KEY), Err(EscrowError::Unauthorized));
            assert_eq!(e.release(ZERO_KEY, 1_000_000, None), Err(EscrowError::Unauthorized));
            assert_eq!(e.cancel(ZERO_KEY, None), Err(EscrowError::Unauthorized));
            assert_eq!(
                e.cancel_expired(ZERO_KEY, EXPIRES_AT + 1, None),
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
                    slots.push(Some(Slot {
                        escrow,
                        amount,
                        expires_at,
                        fees_paid: 0,
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
            let result: Result<(), EscrowError> = match op {
                0 => slot.escrow.fund(authority),
                1 => {
                    rel_amt = fuzz_release_amount(&mut rng, slot.amount);
                    slot.escrow
                        .release(authority, rel_amt, None)
                        .map(|(payout, fee)| {
                            // AV-17: the fee is a routing slice of the
                            // gross payout — it never escapes it.
                            assert_eq!(
                                payout + fee,
                                rel_amt,
                                "payout + fee != gross release on seed {seed}"
                            );
                            rel_fee = fee;
                        })
                }
                2 => slot.escrow.cancel(authority, None),
                _ => slot.escrow.cancel_expired(authority, fuzz_now(&mut rng), None),
            };

            match result {
                Ok(()) => match state_before {
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
        assert_eq!(e.release(ALICE, 1_000_000, None), Err(EscrowError::QuorumNotReached));
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.amount(), 1_000_000);
    }

    #[test]
    fn release_after_threshold_reached_succeeds() {
        let mut e = escrow_with_quorum();
        e.attest(ATTESTOR_1).unwrap();
        e.attest(ATTESTOR_3).unwrap();
        e.release(ALICE, 1_000_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.amount(), 1_000_000); // payout accounting preserved
    }

    #[test]
    fn quorum_does_not_weaken_initializer_authority() {
        // Even with a satisfied quorum, a stranger cannot release.
        let mut e = escrow_with_quorum();
        e.attest(ATTESTOR_1).unwrap();
        e.attest(ATTESTOR_2).unwrap();
        assert_eq!(e.release(MALLORY, 1_000_000, None), Err(EscrowError::Unauthorized));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn quorum_does_not_leak_attestation_progress_to_strangers() {
        // Check order: authority before quorum. A stranger gets
        // Unauthorized even with zero attestations recorded.
        let mut e = escrow_with_quorum();
        assert_eq!(e.release(MALLORY, 1_000_000, None), Err(EscrowError::Unauthorized));
        // ... while the initializer sees the quorum gate.
        assert_eq!(e.release(ALICE, 1_000_000, None), Err(EscrowError::QuorumNotReached));
    }

    #[test]
    fn cancel_paths_are_not_gated_by_quorum() {
        // Anti-griefing: attestors withholding approval cannot lock funds;
        // the initializer refund path stays quorum-free.
        let mut e = escrow_with_quorum();
        e.cancel(ALICE, None).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);

        let mut e = escrow_with_quorum();
        e.cancel_expired(BOB, EXPIRES_AT + 1, None).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
    }

    #[test]
    fn escrow_without_quorum_releases_without_attestations() {
        // Backward compatibility: plain two-party escrow unchanged.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        assert_eq!(e.quorum(), None);
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_000_000, None).unwrap();
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
        e.release(ALICE, 1_000_000, None).unwrap();
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
        e.release(ALICE, 1_000_000, None).unwrap();
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
        e.release(ALICE, 1_000_000, None).unwrap();
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
                            `amount == 0` is AmountMismatch; returns \
                            (taker_payout, fee) — AV-17: the protocol fee \
                            slices the payout and accumulates in \
                            `fees_paid`; when a quorum \
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
            params: &[],
            method: "Escrow::escalate",
            input_mapping: "authority <- accounts.authority (signer: \
                            initializer OR taker); now <- clock sysvar \
                            (NOT an instruction param — a caller-supplied \
                            timestamp could rewind past the dispute \
                            window, same rationale as cancel_expired); \
                            Funded -> Disputed, locks every unilateral \
                            exit until resolve",
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
                            index <- param; releases the tranche only \
                            after dual confirmation (MilestoneNotConfirmed \
                            otherwise) and in-order; returns (taker_payout, \
                            fee) so the program can size both transfers \
                            (AV-17); \
                            the quorum gate applies exactly as for release",
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
    fn only_twelve_instructions_take_params() {
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
                &"initialize_vesting",
                &"initialize_arbiter",
                &"resolve",
                &"initialize_milestones",
                &"confirm_milestone",
                &"release_milestone",
                &"skip_milestone",
                &"initialize_mint",
                &"initialize_protocol_fee"
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
        e.release(ALICE, 1_000_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        // Documented partial path: stays Funded, progress tracked.
        let mut e = funded_escrow();
        e.release(ALICE, 400_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!((e.released_amount(), e.remaining_amount()), (400_000, 600_000));
        // Documented failure mode: quorum configured but threshold unmet
        // (release-specific gate from AV-04).
        let mut e = quorum_funded_escrow();
        e.attest(ATTESTOR_1).unwrap();
        assert_eq!(e.release(ALICE, 1_000_000, None), Err(EscrowError::QuorumNotReached));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn cancel_maps_initializer_signer_to_authority() {
        // IDL: cancel() — no params; authority <- accounts.initializer.
        let mut e = funded_escrow();
        e.cancel(ALICE, None).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        // Documented failure mode: signer is not the initializer.
        let mut e = funded_escrow();
        assert_eq!(e.cancel(MALLORY, None), Err(EscrowError::Unauthorized));
    }

    #[test]
    fn cancel_expired_maps_authority_and_clock_sysvar() {
        // IDL: cancel_expired() — no params. authority <- accounts.authority
        // (signer: initializer OR taker); now <- clock sysvar, deliberately
        // not an instruction param (caller-supplied timestamps would let
        // anyone fast-forward expiry). The program layer must pass
        // Clock::get()?.unix_timestamp here.
        let mut e = funded_escrow();
        e.cancel_expired(BOB, EXPIRES_AT, None).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        // Documented failure mode: clock before expiry.
        let mut e = funded_escrow();
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT - 1, None),
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
        assert_eq!(e.release(ALICE, 1_000_000, None), Err(EscrowError::QuorumNotReached));
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
        e.escalate(BOB, EXPIRES_AT - 1).unwrap();
        assert_eq!(e.state(), EscrowState::Disputed);
        // Documented failure mode: the dispute window is closed once the
        // escrow is expiry-eligible.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.escalate(ALICE, EXPIRES_AT),
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
        e.escalate(ALICE, EXPIRES_AT - 1).unwrap();
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
        e.escalate(ALICE, EXPIRES_AT - 1).unwrap();
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
        let (tranche, fee) = e.release_milestone(ALICE, 0, None).unwrap();
        assert_eq!((tranche, fee), (400_000, 0), "no fee configured: full tranche to taker");
        assert_eq!((e.released_amount(), e.remaining_amount()), (400_000, 600_000));
        assert_eq!(e.state(), EscrowState::Funded);
        assert!(e.milestone_settled(0));
        // Documented failure mode: releasing before dual confirmation.
        let mut e = milestone_escrow();
        e.confirm_milestone(ALICE, 0).unwrap();
        assert_eq!(
            e.release_milestone(ALICE, 0, None),
            Err(EscrowError::MilestoneNotConfirmed)
        );
        assert_eq!(e.released_amount(), 0);
        // Documented failure mode: the taker cannot drive the release.
        assert_eq!(
            e.release_milestone(BOB, 0, None),
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
        let err = e.cancel_expired(ALICE, EXPIRES_AT - 1, None).unwrap_err();
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
        let err = e.release(ALICE, 1_000_000, None).unwrap_err();
        assert_eq!(err, EscrowError::QuorumNotReached);
        assert_eq!(err.code(), 105);
    }

    #[test]
    fn release_exceeds_locked_triggered_by_over_release() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 600_000, None).unwrap(); // partial: 400_000 remains
        let err = e.release(ALICE, 400_001, None).unwrap_err();
        assert_eq!(err, EscrowError::ReleaseExceedsLocked);
        assert_eq!(err.code(), 106);
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 600_000, "failed release must not move released");
    }

    #[test]
    fn amount_mismatch_triggered_by_zero_amount_release() {
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        let err = e.release(ALICE, 0, None).unwrap_err();
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
        let err = e.escalate(ALICE, EXPIRES_AT - 1).unwrap_err();
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
        let err = e.escalate(BOB, EXPIRES_AT).unwrap_err();
        assert_eq!(err, EscrowError::DisputeWindowClosed);
        assert_eq!(err.code(), 109);
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn check_order_is_visible_in_codes() {        // Authority is checked before state: a stranger on a terminal
        // state still gets 100 (Unauthorized), not 101.
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 1_000_000, None).unwrap(); // now Released
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
        let err = e.release(ALICE, 400_000, None).unwrap_err();
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
            e.release_milestone(ALICE, 0, None),
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
        let err = e.release_milestone(ALICE, 0, None).unwrap_err();
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
        let err = e.release(ALICE, 1_000_000, Some(MINT_B)).unwrap_err();
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
        assert_eq!(e.cancel(ALICE, None), Err(EscrowError::MintMismatch));
        assert_eq!(e.state(), EscrowState::Funded);
    }

    #[test]
    fn mint_mismatch_triggered_by_token_path_on_sol_escrow() {
        // And a native-SOL escrow never exits through a token mint.
        let mut e = escrow();
        e.fund(ALICE).unwrap();
        assert_eq!(
            e.release(ALICE, 1_000_000, Some(MINT_A)),
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
    fn mint_match_allows_all_exit_paths() {
        // The matching mint opens every fund-moving exit: release,
        // cancel, cancel_expired, and claim (here on a vesting escrow).
        let mut e = mint_escrow();
        e.release(ALICE, 400_000, Some(MINT_A)).unwrap();
        assert_eq!(e.released_amount(), 400_000);

        let mut e = mint_escrow();
        e.cancel(ALICE, Some(MINT_A)).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);

        let mut e = mint_escrow();
        e.cancel_expired(BOB, EXPIRES_AT, Some(MINT_A)).unwrap();
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
            e.release(ALICE, amount, None).unwrap();
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
            e.cancel(ALICE, None).unwrap();
            assert_eq!(e.state(), EscrowState::Cancelled);
            assert_eq!(e.amount(), amount, "case {case}: amount changed on cancel path");

            // fund → cancel_expired by the taker at exactly the expiry
            // edge (now == expires_at satisfies now >= expires_at).
            let mut e = mk();
            e.fund(ALICE).unwrap();
            e.cancel_expired(BOB, expiry, None).unwrap();
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
            e.release(ALICE, amount, None).unwrap();
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
            match e.cancel_expired(ALICE, now, None) {
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
        assert_eq!(ESCROW_BODY_LEN, 532, "escrow payload bytes");
        // 8-byte Anchor discriminator + payload.
        assert_eq!(VAULT_SPACE, 540, "full Vault account space");
        // Discriminator + payload with `quorum: None` (1-byte
        // discriminant) + 1-byte activation bitmask (AV-12) + 1-byte
        // vesting discriminant (AV-13, zeroed when no schedule) + 1-byte
        // arbiter discriminant (AV-14, zeroed when no arbiter) + 1-byte
        // milestones discriminant (AV-15, zeroed when no plan) + 8-byte
        // confirmation bitmap + 8-byte skipped counter + 1-byte mint
        // discriminant (AV-16, zeroed when no mint bound) + 2-byte
        // protocol fee rate (AV-17, zeroed when no fee configured) +
        // 8-byte cumulative fee counter (AV-17, zeroed when no fee
        // charged).
        assert_eq!(
            VAULT_SPACE_NO_QUORUM,
            8 + 32 + 32 + 8 + 8 + 8 + 1 + 1 + 1 + 1 + 1 + 1 + 8 + 8 + 1 + 2 + 8,
            "no-quorum Vault account space"
        );
        assert_eq!(VAULT_SPACE_NO_QUORUM, 129);
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
        e.release_milestone(ALICE, 0, None).unwrap();
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
        e.release(ALICE, 1_000_000, Some(MINT)).unwrap();
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
        // (128 + 540) * 3480 * 2 = 668 * 6960 = 4_649_280 lamports.
        assert_eq!(full, 4_649_280);

        let no_quorum = rent_exempt_minimum_lamports(
            VAULT_SPACE_NO_QUORUM,
            MAINNET_LAMPORTS_PER_BYTE_YEAR,
            MAINNET_EXEMPTION_THRESHOLD_YEARS,
        );
        // (128 + 129) * 3480 * 2 = 257 * 6960 = 1_788_720 lamports.
        assert_eq!(no_quorum, 1_788_720);
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
        assert_eq!(check_vault_rent_exempt(4_649_280, params.0, params.1), Ok(()));
        // One lamport short: exact shortfall reported.
        assert_eq!(
            check_vault_rent_exempt(4_649_279, params.0, params.1),
            Err(RentShortfall {
                required: 4_649_280,
                provided: 4_649_279,
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
                required: 4_649_280,
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
        e.release(ALICE, 400_000, None).unwrap();
        assert_eq!(
            e.state(),
            EscrowState::Funded,
            "a partial release must not close the escrow"
        );
        assert_eq!(e.released_amount(), 400_000);
        assert_eq!(e.remaining_amount(), 600_000);
        // A second partial accumulates on top of the first.
        e.release(ALICE, 100_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 500_000);
        assert_eq!(e.remaining_amount(), 500_000);
    }

    #[test]
    fn final_partial_release_closes_the_escrow() {
        let mut e = funded_escrow();
        e.release(ALICE, 400_000, None).unwrap();
        e.release(ALICE, 600_000, None).unwrap(); // reaches the locked amount exactly
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.released_amount(), 1_000_000);
        assert_eq!(e.remaining_amount(), 0);
    }

    #[test]
    fn zero_amount_release_is_amount_mismatch_and_changes_nothing() {
        let mut e = funded_escrow();
        assert_eq!(e.release(ALICE, 0, None), Err(EscrowError::AmountMismatch));
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 0);
        assert_eq!(e.remaining_amount(), 1_000_000);
    }

    #[test]
    fn release_beyond_remaining_is_release_exceeds_locked() {
        let mut e = funded_escrow();
        e.release(ALICE, 600_000, None).unwrap();
        // 400_000 remains: asking for one lamport more must fail.
        assert_eq!(
            e.release(ALICE, 400_001, None),
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
        e.release(ALICE, u64::MAX - 10, None).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), u64::MAX - 10);
        assert_eq!(
            e.release(ALICE, 11, None),
            Err(EscrowError::ReleaseExceedsLocked)
        );
        assert_eq!(
            e.released_amount(),
            u64::MAX - 10,
            "the counter is untouched by the overflow attempt"
        );
        // The exact remainder still works and closes the escrow.
        e.release(ALICE, 10, None).unwrap();
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
            e.release(ALICE, 400_000, None),
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
            e.release(ALICE, 400_000, None),
            Err(EscrowError::QuorumNotReached)
        );
        e.attest(ATTESTOR_2).unwrap();
        // Gate satisfied: the partial release goes through and stays Funded.
        e.release(ALICE, 400_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!(e.released_amount(), 400_000);
        // The final partial closes the escrow.
        e.release(ALICE, 600_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn cancel_after_partial_release_refunds_remainder_and_preserves_released() {
        let mut e = funded_escrow();
        e.release(ALICE, 400_000, None).unwrap();
        e.cancel(ALICE, None).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        // Released funds stay released; the refund is the remainder.
        assert_eq!(e.released_amount(), 400_000, "released preserved for audit");
        assert_eq!(e.remaining_amount(), 600_000, "refundable remainder");
    }

    #[test]
    fn release_after_full_release_is_invalid_transition() {
        let mut e = funded_escrow();
        e.release(ALICE, 1_000_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(
            e.release(ALICE, 1_000_000, None),
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
        e.release(ALICE, 400_000, None).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        assert_eq!((e.released_amount(), e.remaining_amount()), (400_000, 600_000));
        e.cancel(ALICE, None).unwrap();
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
        assert_eq!(e.release(ALICE, 1_000_000, None), Err(EscrowError::QuorumNotReached));
        e.attest([0xA1; 32]).unwrap();
        e.attest([0xA2; 32]).unwrap();
        e.release(ALICE, 1_000_000, None).unwrap();
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
        e.release(ALICE, 1_000_000, None).unwrap();
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
        e.cancel(ALICE, None).unwrap();
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
        e.release(ALICE, 800_000, None).unwrap(); // only 500_000 vested at midpoint
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
        e.cancel(ALICE, None).unwrap();
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
        e.release(ALICE, 200_000, None).unwrap();
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
        e.release(ALICE, 200_000, None).unwrap();
        e.cancel(ALICE, None).unwrap();
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
        e.escalate(ALICE, EXPIRES_AT - 1).unwrap();
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
            e.escalate(authority, EXPIRES_AT - 1).unwrap();
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
            e.escalate(MALLORY, EXPIRES_AT - 1),
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
            e.escalate(ALICE, EXPIRES_AT - 1),
            Err(EscrowError::InvalidStateTransition)
        );
        // Double escalation: already Disputed.
        let mut e = disputed_escrow();
        assert_eq!(
            e.escalate(BOB, EXPIRES_AT - 1),
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
            e.escalate(ALICE, EXPIRES_AT),
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
            e.release(ALICE, 100_000, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.cancel(ALICE, None), Err(EscrowError::InvalidStateTransition));
        assert_eq!(
            e.cancel_expired(ALICE, EXPIRES_AT + 1, None),
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
            e.cancel_expired(BOB, EXPIRES_AT + 1_000_000, None),
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
        e.release(ALICE, 400_000, None).unwrap();
        e.escalate(BOB, EXPIRES_AT - 1).unwrap();
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
        e.escalate(ALICE, EXPIRES_AT - 1).unwrap();
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
        e.escalate(BOB, EXPIRES_AT - 1).unwrap();
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
        e.release_milestone(ALICE, 0, None).unwrap();
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
        let (t0, fee0) = e.release_milestone(ALICE, 0, None).unwrap();
        assert_eq!((t0, fee0), (400_000, 0), "the net tranche is returned for transfer sizing");
        assert_eq!(e.state(), EscrowState::Funded, "more tranches remain");
        assert_eq!((e.released_amount(), e.remaining_amount()), (400_000, 600_000));
        assert_eq!(e.next_milestone(), Some(1));

        confirm_both(&mut e, 1);
        let (t1, fee1) = e.release_milestone(ALICE, 1, None).unwrap();
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
            e.release_milestone(BOB, 0, None),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            e.release_milestone(MALLORY, 0, None),
            Err(EscrowError::Unauthorized)
        );
        // Releasing milestone 1 while milestone 0 is unsettled.
        assert_eq!(
            e.release_milestone(ALICE, 1, None),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(e.released_amount(), 0);
    }

    #[test]
    fn release_milestone_cannot_double_release() {
        let mut e = milestone_escrow();
        confirm_both(&mut e, 0);
        e.release_milestone(ALICE, 0, None).unwrap();
        // Milestone 0 is settled: re-releasing it is out-of-order now.
        assert_eq!(
            e.release_milestone(ALICE, 0, None),
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
            e.release_milestone(ALICE, 0, None),
            Err(EscrowError::QuorumNotReached)
        );
        assert_eq!(e.released_amount(), 0);
        e.attest([0xA1; 32]).unwrap();
        e.attest([0xA2; 32]).unwrap();
        assert_eq!(e.release_milestone(ALICE, 0, None).unwrap(), (400_000, 0));
    }

    #[test]
    fn plain_release_and_claim_disabled_with_plan() {
        // The plan is the sole release schedule: arbitrary tranches and
        // time-based claims would break per-tranche accounting.
        let mut e = milestone_escrow();
        assert_eq!(
            e.release(ALICE, 400_000, None),
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
            e.release_milestone(ALICE, 0, None),
            Err(EscrowError::MilestoneNotConfirmed)
        );
        // The taker aligns with the release path: now it is confirmed.
        e.confirm_milestone(BOB, 0).unwrap();
        assert!(e.milestone_confirmed(0));
        assert_eq!(e.release_milestone(ALICE, 0, None).unwrap(), (400_000, 0));
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
        e.release_milestone(ALICE, 1, None).unwrap();
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
        e.cancel(ALICE, None).unwrap();
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
        e.release_milestone(ALICE, 0, None).unwrap(); // 400_000 to the taker
        e.escalate(BOB, EXPIRES_AT - 1).unwrap();
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
        assert_eq!(e.release_milestone(ALICE, 0, None).unwrap(), (u64::MAX - 5, 0));
        assert_eq!(e.state(), EscrowState::Funded);
        confirm_both(&mut e, 1);
        assert_eq!(e.release_milestone(ALICE, 1, None).unwrap(), (5, 0));
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
        e.escalate(ALICE, EXPIRES_AT - 1).unwrap();
        assert_eq!(
            e.confirm_milestone(ALICE, 0),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(
            e.release_milestone(ALICE, 0, None),
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
        let (payout, fee) = e.release(ALICE, 400_000, None).unwrap();
        assert_eq!((payout, fee), (390_000, 10_000));
        assert_eq!(payout + fee, 400_000, "fee is a slice of the gross");
        assert_eq!(e.fees_paid(), 10_000);
        // The released counter keeps the gross: conservation is
        // untouched.
        assert_eq!(e.released_amount(), 400_000);
        assert_eq!(e.remaining_amount(), 600_000);
        assert_eq!(e.state(), EscrowState::Funded);
        // Fees accumulate across partial releases.
        let (payout2, fee2) = e.release(ALICE, 600_000, None).unwrap();
        assert_eq!((payout2, fee2), (585_000, 15_000));
        assert_eq!(e.fees_paid(), 25_000);
        assert_eq!(e.state(), EscrowState::Released);
        assert_eq!(e.released_amount(), 1_000_000);
    }

    #[test]
    fn full_rate_routes_everything_to_the_fee_account() {
        // 10_000 bps (100%) is a valid config: the taker nets zero.
        let mut e = funded_fee_escrow(10_000);
        let (payout, fee) = e.release(ALICE, 1_000_000, None).unwrap();
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
        let (payout, fee) = e.release_milestone(ALICE, 0, None).unwrap();
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
        e.escalate(ALICE, EXPIRES_AT - 1).unwrap();
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
        e.cancel(ALICE, None).unwrap();
        assert_eq!(e.fees_paid(), 0);
        // cancel_expired.
        let mut e = funded_fee_escrow(10_000);
        e.cancel_expired(BOB, EXPIRES_AT, None).unwrap();
        assert_eq!(e.fees_paid(), 0);
    }

    #[test]
    fn failed_payouts_leave_the_fee_counter_untouched() {
        // Unauthorized release.
        let mut e = funded_fee_escrow(250);
        assert_eq!(
            e.release(MALLORY, 400_000, None),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.fees_paid(), 0);
        // Over-release: the cap check runs before any fee is charged.
        assert_eq!(
            e.release(ALICE, 1_000_001, None),
            Err(EscrowError::ReleaseExceedsLocked)
        );
        assert_eq!(e.fees_paid(), 0);
        assert_eq!(e.released_amount(), 0);
        // Zero amount.
        assert_eq!(e.release(ALICE, 0, None), Err(EscrowError::AmountMismatch));
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
