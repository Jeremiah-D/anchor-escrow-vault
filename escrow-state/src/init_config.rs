//! AV-161: chain-off-chain initialize-config assembly validator.
//!
//! [`InitConfig`] is the plain-data bundle a keeper or UI assembles
//! (typically from JSON) before driving the chain's `initialize` +
//! builder sequence (`with_milestones` / `with_vesting` /
//! `with_subscription` / `with_quorum` / `with_protocol_fee` /
//! `with_timelock` / `with_mint_allowlist` / `with_payout_allowlist`).
//! [`validate_initialize_config`] checks every cross-field constraint
//! the individual builders cannot see, so a misassembled config fails
//! fast off-chain instead of burning a transaction on-chain.
//!
//! Pure function: no state reads, no state writes, no events. Each
//! check mirrors the corresponding chain-side builder's validation
//! (error variant included), plus the two config-layer invariants
//! the chain deliberately leaves to the assembler: the three release
//! plans are mutually exclusive here (the chain lets vesting compose
//! with a subscription; the config layer forbids it — one escrow, one
//! release story), and the time fields must be mutually consistent.

use super::{
    EscrowError, MAX_ATTESTORS, MAX_MILESTONES, MAX_MINT_ALLOWLIST, MAX_PAYOUT_ALLOWLIST,
    MAX_SUBSCRIPTION_PERIODS,
};

/// Milestone tranche table for [`InitConfig`]: per-tranche amounts,
/// in release order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitMilestones {
    /// Tranche amounts; must be non-empty, all positive, and sum to
    /// exactly [`InitConfig::amount`].
    pub amounts: Vec<u64>,
}

/// Vesting unlock window for [`InitConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitVesting {
    /// Unix timestamp at which unlocking begins.
    pub start: u64,
    /// Unix timestamp at which everything is vested.
    pub end: u64,
    /// Unix timestamp before which zero unlocks. At or before
    /// `start` means no cliff (the chain normalizes it to `start`).
    pub cliff_at: u64,
}

/// Subscription release schedule for [`InitConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitSubscription {
    /// Seconds between consecutive period due dates.
    pub period_secs: u64,
    /// Number of periods.
    pub periods: u8,
    /// Payout per period; `periods * per_period` must equal
    /// [`InitConfig::amount`].
    pub per_period: u64,
}

/// Quorum policy for [`InitConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitQuorum {
    /// Attestor keys, in slot order.
    pub attestors: Vec<[u8; 32]>,
    /// Per-attestor vote weight, parallel to `attestors`.
    pub weights: Vec<u64>,
    /// Weight-sum threshold: release is legal once the accumulated
    /// weight of distinct attestations reaches this value.
    pub threshold: u64,
}

/// The plain-data initialize-config bundle. Every field maps onto
/// one `initialize` argument or one `with_*` builder call; `None`
/// means the corresponding builder is skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitConfig {
    /// Locked amount (`initialize`; must be positive).
    pub amount: u64,
    /// Expiry timestamp (`initialize`; `u64::MAX` = no timeout).
    pub expires_at: u64,
    /// Milestone plan (`with_milestones`).
    pub milestones: Option<InitMilestones>,
    /// Vesting schedule (`with_vesting`).
    pub vesting: Option<InitVesting>,
    /// Subscription schedule (`with_subscription`).
    pub subscription: Option<InitSubscription>,
    /// Quorum policy (`with_quorum`).
    pub quorum: Option<InitQuorum>,
    /// Protocol fee in basis points (`with_protocol_fee`).
    pub fee_bps: u16,
    /// Absolute timelock (`with_timelock`).
    pub timelock_unlock_at: Option<u64>,
    /// SPL mint allowlist (`with_mint_allowlist`).
    pub mint_allowlist: Option<Vec<[u8; 32]>>,
    /// Payout destination allowlist (`with_payout_allowlist`).
    pub payout_allowlist: Option<Vec<[u8; 32]>>,
}

/// Validate an assembled initialize config: every cross-field
/// constraint the individual builders cannot see, checked in one
/// pass so the keeper/UI fails fast before touching the chain.
///
/// Check order: amount, plan mutual exclusion, the set plan's own
/// shape (amounts cover the lockup exactly), quorum reachability,
/// fee rate, time consistency, allowlist shape. The error variant
/// names the failing builder, mirroring the chain-side validation.
pub fn validate_initialize_config(cfg: &InitConfig) -> Result<(), EscrowError> {
    // The lockup must be positive — mirrors `Escrow::initialize`.
    if cfg.amount == 0 {
        return Err(EscrowError::AmountMismatch);
    }
    // The three release plans are mutually exclusive at the config
    // layer: one escrow, one release story. (The chain lets vesting
    // compose with a subscription; the config layer forbids it, so a
    // UI cannot assemble an ambiguous payout story by accident.)
    let plans = cfg.milestones.is_some() as u8
        + cfg.vesting.is_some() as u8
        + cfg.subscription.is_some() as u8;
    if plans > 1 {
        // The subscription owns the release schedule on-chain — a
        // subscription conflict reports as its error, either builder
        // order; a milestones/vesting clash is the milestone plan's.
        if cfg.subscription.is_some() {
            return Err(EscrowError::InvalidSubscription);
        }
        return Err(EscrowError::InvalidMilestones);
    }
    // The set plan's amounts must cover the lockup exactly.
    if let Some(m) = &cfg.milestones {
        validate_milestone_amounts(&m.amounts, cfg.amount)?;
    }
    if let Some(s) = &cfg.subscription {
        validate_subscription_shape(s, cfg.amount, cfg.expires_at)?;
    }
    if let Some(v) = &cfg.vesting {
        validate_vesting_window(v, cfg.expires_at)?;
    }
    // The quorum threshold must be reachable: 1 <= threshold <= the
    // total attestor weight.
    if let Some(q) = &cfg.quorum {
        validate_quorum_terms(q)?;
    }
    // The fee is a basis-point rate — mirrors `with_protocol_fee`.
    if cfg.fee_bps > 10_000 {
        return Err(EscrowError::InvalidProtocolFee);
    }
    // A timelock that outlives the escrow never lifts before the
    // funds move — the config is almost certainly wrong.
    if let Some(unlock_at) = cfg.timelock_unlock_at {
        if unlock_at > cfg.expires_at {
            return Err(EscrowError::InvalidTimelock);
        }
    }
    // Allowlists are opt-in: configured means non-empty and
    // well-formed — mirrors the chain-side list builders.
    if let Some(mints) = &cfg.mint_allowlist {
        if mints.is_empty()
            || mints.len() > MAX_MINT_ALLOWLIST
            || mints.iter().any(|m| *m == [0u8; 32])
        {
            return Err(EscrowError::InvalidMint);
        }
    }
    if let Some(addrs) = &cfg.payout_allowlist {
        if addrs.is_empty()
            || addrs.len() > MAX_PAYOUT_ALLOWLIST
            || addrs.iter().any(|a| *a == [0u8; 32])
        {
            return Err(EscrowError::InvalidPayoutAllowlist);
        }
    }
    Ok(())
}

/// Milestone tranches cover the lockup exactly: non-empty, within
/// the slot count, every tranche positive, and the `u128` sum equals
/// the amount — mirrors `MilestonePlan::new` plus
/// `with_milestones`' total check.
fn validate_milestone_amounts(amounts: &[u64], amount: u64) -> Result<(), EscrowError> {
    if amounts.is_empty() || amounts.len() > MAX_MILESTONES {
        return Err(EscrowError::InvalidMilestones);
    }
    let mut total: u128 = 0;
    for a in amounts {
        if *a == 0 {
            return Err(EscrowError::InvalidMilestones);
        }
        total = total
            .checked_add(*a as u128)
            .ok_or(EscrowError::InvalidMilestones)?;
    }
    if total != amount as u128 {
        return Err(EscrowError::InvalidMilestones);
    }
    Ok(())
}

/// The subscription schedule is well-formed and fits the escrow's
/// lifetime: non-zero cadence, a sane period count, a positive
/// per-period amount covering the lockup exactly, a real expiry to
/// back-schedule from, and the whole schedule inside the lifetime —
/// mirrors `with_subscription`.
fn validate_subscription_shape(
    s: &InitSubscription,
    amount: u64,
    expires_at: u64,
) -> Result<(), EscrowError> {
    if s.period_secs == 0 {
        return Err(EscrowError::InvalidSubscription);
    }
    if s.periods == 0 || s.periods > MAX_SUBSCRIPTION_PERIODS {
        return Err(EscrowError::InvalidSubscription);
    }
    if s.per_period == 0 {
        return Err(EscrowError::InvalidSubscription);
    }
    if s.periods as u128 * s.per_period as u128 != amount as u128 {
        return Err(EscrowError::InvalidSubscription);
    }
    // Back-scheduling pins the last period to `expires_at`: the
    // no-timeout convention has no expiry to pin to.
    if expires_at == u64::MAX {
        return Err(EscrowError::InvalidSubscription);
    }
    // The whole schedule must fit inside the escrow's lifetime — the
    // first period's due date must not underflow timestamp 0. u128,
    // so it can never wrap.
    if (s.periods as u128 - 1) * s.period_secs as u128 > expires_at as u128 {
        return Err(EscrowError::InvalidSubscription);
    }
    Ok(())
}

/// The vesting window is ordered and completes inside the escrow's
/// lifetime: `start < end`, the cliff inside the window (a cliff at
/// or before `start` is the no-cliff schedule — the chain normalizes
/// it, so the validator allows it), and the unlock completing no
/// later than expiry — mirrors `VestingSchedule::new_with_cliff`
/// plus the lifetime fit.
fn validate_vesting_window(v: &InitVesting, expires_at: u64) -> Result<(), EscrowError> {
    if v.start >= v.end {
        return Err(EscrowError::InvalidVesting);
    }
    if v.cliff_at > v.end {
        return Err(EscrowError::InvalidVesting);
    }
    if v.end > expires_at {
        return Err(EscrowError::InvalidVesting);
    }
    Ok(())
}

/// The quorum terms are well-formed and the threshold is reachable:
/// non-empty, within the attestor slots, weights parallel and
/// positive, no duplicate attestor, the `u128` total inside the u64
/// weight domain, and `1 <= threshold <= total` — mirrors
/// `QuorumPolicy::new`.
fn validate_quorum_terms(q: &InitQuorum) -> Result<(), EscrowError> {
    if q.attestors.is_empty() || q.attestors.len() > MAX_ATTESTORS {
        return Err(EscrowError::InvalidQuorum);
    }
    if q.weights.len() != q.attestors.len() {
        return Err(EscrowError::InvalidQuorum);
    }
    let mut total: u128 = 0;
    for (i, (attestor, weight)) in q.attestors.iter().zip(q.weights.iter()).enumerate() {
        if q.attestors[..i].contains(attestor) {
            return Err(EscrowError::InvalidQuorum);
        }
        if *weight == 0 {
            return Err(EscrowError::InvalidQuorum);
        }
        total = total
            .checked_add(*weight as u128)
            .ok_or(EscrowError::InvalidQuorum)?;
    }
    let total_weight = u64::try_from(total).map_err(|_| EscrowError::InvalidQuorum)?;
    if q.threshold == 0 || q.threshold > total_weight {
        return Err(EscrowError::InvalidQuorum);
    }
    Ok(())
}
