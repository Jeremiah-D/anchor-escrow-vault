//! AV-161: `validate_initialize_config(&InitConfig)` — test matrix.
//!
//! The chain-off-chain config assembly validator is a pure function:
//! every cross-field constraint the individual builders cannot see
//! gets a positive and a negative case here, so the keeper/UI fails
//! fast on a misassembled config instead of burning a transaction.

use escrow_state::{
    validate_initialize_config, EscrowError, InitConfig, InitMilestones, InitQuorum,
    InitSubscription, InitVesting,
};

const AMOUNT: u64 = 1_000_000;
const EXPIRES_AT: u64 = 1_800_000_000;

fn addr(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// A minimal valid config: plain escrow, no plans, no quorum, no fee,
/// no timelock, no allowlists.
fn base_config() -> InitConfig {
    InitConfig {
        amount: AMOUNT,
        expires_at: EXPIRES_AT,
        milestones: None,
        vesting: None,
        subscription: None,
        quorum: None,
        fee_bps: 0,
        timelock_unlock_at: None,
        mint_allowlist: None,
        payout_allowlist: None,
    }
}

fn milestones(amounts: &[u64]) -> Option<InitMilestones> {
    Some(InitMilestones {
        amounts: amounts.to_vec(),
    })
}

fn vesting(start: u64, end: u64, cliff_at: u64) -> Option<InitVesting> {
    Some(InitVesting {
        start,
        end,
        cliff_at,
    })
}

fn subscription(period_secs: u64, periods: u8, per_period: u64) -> Option<InitSubscription> {
    Some(InitSubscription {
        period_secs,
        periods,
        per_period,
    })
}

fn quorum(attestors: &[[u8; 32]], weights: &[u64], threshold: u64) -> Option<InitQuorum> {
    Some(InitQuorum {
        attestors: attestors.to_vec(),
        weights: weights.to_vec(),
        threshold,
    })
}

#[test]
fn minimal_config_is_valid() {
    assert_eq!(validate_initialize_config(&base_config()), Ok(()));
}

#[test]
fn zero_amount_is_rejected() {
    let mut cfg = base_config();
    cfg.amount = 0;
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::AmountMismatch)
    );
}

// ---------- plan mutual exclusion ----------

#[test]
fn plans_are_mutually_exclusive() {
    // subscription + milestones: the subscription owns the release
    // schedule on-chain.
    let mut cfg = base_config();
    cfg.milestones = milestones(&[500_000, 500_000]);
    cfg.subscription = subscription(86_400, 4, 250_000);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidSubscription)
    );
    // subscription + vesting.
    let mut cfg = base_config();
    cfg.vesting = vesting(1_700_000_000, 1_750_000_000, 1_700_000_000);
    cfg.subscription = subscription(86_400, 4, 250_000);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidSubscription)
    );
    // milestones + vesting.
    let mut cfg = base_config();
    cfg.milestones = milestones(&[500_000, 500_000]);
    cfg.vesting = vesting(1_700_000_000, 1_750_000_000, 1_700_000_000);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidMilestones)
    );
    // All three at once.
    let mut cfg = base_config();
    cfg.milestones = milestones(&[500_000, 500_000]);
    cfg.vesting = vesting(1_700_000_000, 1_750_000_000, 1_700_000_000);
    cfg.subscription = subscription(86_400, 4, 250_000);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidSubscription)
    );
}

#[test]
fn each_plan_alone_is_valid() {
    let mut cfg = base_config();
    cfg.milestones = milestones(&[500_000, 500_000]);
    assert_eq!(validate_initialize_config(&cfg), Ok(()));

    let mut cfg = base_config();
    cfg.vesting = vesting(1_700_000_000, 1_750_000_000, 1_700_000_000);
    assert_eq!(validate_initialize_config(&cfg), Ok(()));

    let mut cfg = base_config();
    cfg.subscription = subscription(86_400, 4, 250_000);
    assert_eq!(validate_initialize_config(&cfg), Ok(()));
}

// ---------- milestone amounts ----------

#[test]
fn milestone_amounts_must_cover_the_lockup_exactly() {
    // Under-cover.
    let mut cfg = base_config();
    cfg.milestones = milestones(&[500_000, 400_000]);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidMilestones)
    );
    // Over-cover.
    let mut cfg = base_config();
    cfg.milestones = milestones(&[500_000, 600_000]);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidMilestones)
    );
    // Empty table.
    let mut cfg = base_config();
    cfg.milestones = milestones(&[]);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidMilestones)
    );
    // Zero tranche.
    let mut cfg = base_config();
    cfg.milestones = milestones(&[1_000_000, 0]);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidMilestones)
    );
    // Over the slot count (MAX_MILESTONES = 8).
    let mut cfg = base_config();
    cfg.milestones = milestones(&[125_000; 9]);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidMilestones)
    );
}

// ---------- subscription shape ----------

#[test]
fn subscription_must_cover_the_lockup_and_fit_the_lifetime() {
    // periods * per_period != amount.
    let mut cfg = base_config();
    cfg.subscription = subscription(86_400, 4, 200_000);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidSubscription)
    );
    // Zero cadence.
    let mut cfg = base_config();
    cfg.subscription = subscription(0, 4, 250_000);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidSubscription)
    );
    // Zero periods.
    let mut cfg = base_config();
    cfg.subscription = subscription(86_400, 0, 250_000);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidSubscription)
    );
    // Over the period slots (MAX_SUBSCRIPTION_PERIODS = 64).
    let mut cfg = base_config();
    cfg.amount = 65 * 1_000;
    cfg.subscription = subscription(1, 65, 1_000);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidSubscription)
    );
    // Zero per-period amount.
    let mut cfg = base_config();
    cfg.amount = 1;
    cfg.subscription = subscription(86_400, 1, 0);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidSubscription)
    );
    // No-timeout escrows have no expiry to back-schedule from.
    let mut cfg = base_config();
    cfg.expires_at = u64::MAX;
    cfg.subscription = subscription(86_400, 4, 250_000);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidSubscription)
    );
    // The schedule must fit inside the lifetime.
    let mut cfg = base_config();
    cfg.expires_at = 100;
    cfg.subscription = subscription(86_400, 4, 250_000);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidSubscription)
    );
}

// ---------- vesting window ----------

#[test]
fn vesting_window_must_be_ordered_and_fit_the_lifetime() {
    // start >= end.
    let mut cfg = base_config();
    cfg.vesting = vesting(1_750_000_000, 1_750_000_000, 1_750_000_000);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidVesting)
    );
    // Cliff past the unlock window.
    let mut cfg = base_config();
    cfg.vesting = vesting(1_700_000_000, 1_750_000_000, 1_750_000_001);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidVesting)
    );
    // Unlock completing after expiry.
    let mut cfg = base_config();
    cfg.vesting = vesting(1_700_000_000, EXPIRES_AT + 1, 1_700_000_000);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidVesting)
    );
    // A cliff at or before start is the no-cliff schedule — allowed.
    let mut cfg = base_config();
    cfg.vesting = vesting(1_700_000_000, 1_750_000_000, 1_600_000_000);
    assert_eq!(validate_initialize_config(&cfg), Ok(()));
}

// ---------- quorum reachability ----------

#[test]
fn quorum_threshold_must_be_reachable() {
    let a1 = addr(0xA1);
    let a2 = addr(0xA2);
    // Threshold above the total weight.
    let mut cfg = base_config();
    cfg.quorum = quorum(&[a1, a2], &[1, 1], 3);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidQuorum)
    );
    // Zero threshold.
    let mut cfg = base_config();
    cfg.quorum = quorum(&[a1], &[1], 0);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidQuorum)
    );
    // Empty attestor set.
    let mut cfg = base_config();
    cfg.quorum = quorum(&[], &[], 1);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidQuorum)
    );
    // Over the attestor slots (MAX_ATTESTORS = 8).
    let mut cfg = base_config();
    let many: Vec<[u8; 32]> = (0..9u8).map(addr).collect();
    cfg.quorum = quorum(&many, &[1; 9], 9);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidQuorum)
    );
    // Weight/attestor length mismatch.
    let mut cfg = base_config();
    cfg.quorum = quorum(&[a1, a2], &[1], 1);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidQuorum)
    );
    // Zero weight.
    let mut cfg = base_config();
    cfg.quorum = quorum(&[a1, a2], &[1, 0], 1);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidQuorum)
    );
    // Duplicate attestor.
    let mut cfg = base_config();
    cfg.quorum = quorum(&[a1, a1], &[1, 1], 2);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidQuorum)
    );
    // Threshold == total weight is reachable.
    let mut cfg = base_config();
    cfg.quorum = quorum(&[a1, a2], &[2, 3], 5);
    assert_eq!(validate_initialize_config(&cfg), Ok(()));
}

// ---------- fee bps ----------

#[test]
fn fee_bps_is_capped_at_10000() {
    let mut cfg = base_config();
    cfg.fee_bps = 10_001;
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidProtocolFee)
    );
    let mut cfg = base_config();
    cfg.fee_bps = 10_000;
    assert_eq!(validate_initialize_config(&cfg), Ok(()));
}

// ---------- timelock ----------

#[test]
fn timelock_must_not_outlive_the_escrow() {
    let mut cfg = base_config();
    cfg.timelock_unlock_at = Some(EXPIRES_AT + 1);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidTimelock)
    );
    let mut cfg = base_config();
    cfg.timelock_unlock_at = Some(EXPIRES_AT);
    assert_eq!(validate_initialize_config(&cfg), Ok(()));
}

// ---------- allowlists ----------

#[test]
fn mint_allowlist_must_be_non_empty_and_well_formed() {
    // Empty means "allowlist off" — configure it or leave it None.
    let mut cfg = base_config();
    cfg.mint_allowlist = Some(vec![]);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidMint)
    );
    // Over the slot count (MAX_MINT_ALLOWLIST = 8).
    let mut cfg = base_config();
    cfg.mint_allowlist = Some((0..9u8).map(addr).collect());
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidMint)
    );
    // Zero address.
    let mut cfg = base_config();
    cfg.mint_allowlist = Some(vec![[0u8; 32]]);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidMint)
    );
    // Valid.
    let mut cfg = base_config();
    cfg.mint_allowlist = Some(vec![addr(0xA5), addr(0xB5)]);
    assert_eq!(validate_initialize_config(&cfg), Ok(()));
}

#[test]
fn payout_allowlist_must_be_non_empty_and_well_formed() {
    let mut cfg = base_config();
    cfg.payout_allowlist = Some(vec![]);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidPayoutAllowlist)
    );
    // Over the slot count (MAX_PAYOUT_ALLOWLIST = 4).
    let mut cfg = base_config();
    cfg.payout_allowlist = Some((0..5u8).map(addr).collect());
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidPayoutAllowlist)
    );
    // Zero address.
    let mut cfg = base_config();
    cfg.payout_allowlist = Some(vec![[0u8; 32]]);
    assert_eq!(
        validate_initialize_config(&cfg),
        Err(EscrowError::InvalidPayoutAllowlist)
    );
    // Valid.
    let mut cfg = base_config();
    cfg.payout_allowlist = Some(vec![addr(0xBB)]);
    assert_eq!(validate_initialize_config(&cfg), Ok(()));
}

// ---------- combined ----------

#[test]
fn fully_loaded_valid_config_passes() {
    // Every optional system configured, all constraints satisfied —
    // the keeper's happy path.
    let cfg = InitConfig {
        amount: AMOUNT,
        expires_at: EXPIRES_AT,
        milestones: None,
        vesting: None,
        subscription: subscription(86_400, 4, 250_000),
        quorum: quorum(&[addr(0xA1), addr(0xA2)], &[2, 3], 4),
        fee_bps: 250,
        timelock_unlock_at: Some(1_700_000_000),
        mint_allowlist: Some(vec![addr(0xA5)]),
        payout_allowlist: Some(vec![addr(0xBB), addr(0xBC)]),
    };
    assert_eq!(validate_initialize_config(&cfg), Ok(()));
}

#[test]
fn validator_is_pure_no_state_change() {
    // Calling twice on the same config agrees, and the config is
    // untouched — the validator moves nothing.
    let cfg = InitConfig {
        amount: AMOUNT,
        expires_at: EXPIRES_AT,
        milestones: milestones(&[250_000, 250_000, 250_000, 250_000]),
        vesting: None,
        subscription: None,
        quorum: None,
        fee_bps: 100,
        timelock_unlock_at: None,
        mint_allowlist: None,
        payout_allowlist: None,
    };
    let before = cfg.clone();
    assert_eq!(validate_initialize_config(&cfg), Ok(()));
    assert_eq!(validate_initialize_config(&cfg), Ok(()));
    assert_eq!(cfg, before, "pure function: config untouched");
}
