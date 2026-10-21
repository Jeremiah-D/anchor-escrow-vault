//! Native SOL stake delegation for escrowed funds (AV-170).
//!
//! A funded escrow locks SOL in the vault account where it sits idle.
//! When the initializer opts in at fund time, the keeper delegates the
//! locked SOL to a stake account bound to a chosen vote account, so the
//! escrow earns staking rewards while the funds stay locked. This
//! module models that *stake leg* as a pure-logic sidecar bound to the
//! escrow — the [`Escrow`](crate::Escrow) state machine itself is
//! untouched (no new vault fields, no layout change), because the
//! stake account lives outside the vault.
//!
//! # Lifecycle
//!
//! ```text
//! delegate_at_fund ──► Delegated ──► Active ──► Deactivating ──► Deactivated
//!   (Funded only)      (warmup)      (earning)    (cooldown)      (withdrawable)
//! ```
//!
//! - [`StakeDelegation::delegate_at_fund`] — the initializer's opt-in,
//!   callable only while the escrow is `Funded`. Snapshots the escrow's
//!   full amount as the delegated principal and binds the
//!   `(stake_account, vote_account)` pair. Warmup completes at the next
//!   epoch boundary (`activation_epoch = delegation_epoch + 1` — the
//!   modeled rule; a production keeper reads the real stake account
//!   instead of trusting the model).
//! - [`StakeDelegation::note_activation`] — the keeper's observation
//!   that warmup finished moves `Delegated → Active` (idempotent).
//! - [`StakeDelegation::begin_deactivation`] — `Active →
//!   Deactivating`; the cooldown ends at `deactivation_epoch =
//!   current_epoch + 1` (idempotent).
//! - [`StakeDelegation::note_deactivated`] — the keeper's observation
//!   that the cooldown finished moves `Deactivating → Deactivated`
//!   (idempotent).
//!
//! # Settlement
//!
//! [`StakeDelegation::settle`] computes the entitlement split for one
//! keeper-authorized taker payout — the amount the escrow state machine
//! already approved via `release` / `claim` / `release_milestone`:
//!
//! - principal always settles: a pending deactivation never blocks the
//!   principal leg;
//! - rewards settle only once `Deactivated`; while `Active` /
//!   `Deactivating` they are reported as pending and stay in the stake
//!   account, still earning; a `Delegated` (never activated) stake
//!   never earns, so nothing is pending;
//! - the taker's reward share is `floor(rewards × reward_split_bps /
//!   10_000)`; the initializer takes the dust remainder.
//!
//! The observed stake-account balance is keeper-supplied (read at
//! `finalized` commitment — see the AV-171 `CommitmentLevel`). If the observed
//! balance is *below* the remaining principal, the settlement fails
//! with [`StakeError::BalanceBelowPrincipal`] — the module never
//! fabricates lamports to cover a shortfall.
//!
//! # What this module does NOT do
//!
//! It does not move lamports and does not touch stake-program
//! accounts: the split / deactivate / withdraw instruction assembly is
//! the keeper's (and the Anchor program's) job.
//! [`settle`](StakeDelegation::settle) is the accounting both sides
//! agree on; after the transfers land, the keeper calls
//! [`record_principal_release`](StakeDelegation::record_principal_release)
//! so the sidecar's books stay exact.

use crate::{Escrow, EscrowState};

/// Basis-point denominator for the taker's reward share: 10_000 bps =
/// 100%.
pub const STAKE_BPS_DENOMINATOR: u16 = 10_000;

/// Lifecycle of the stake account holding the escrow's delegated SOL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StakeState {
    /// Delegated at [`StakeDelegation::delegation_epoch`]; warmup not
    /// yet complete — the stake is not earning rewards.
    Delegated,
    /// Warmup complete: the stake is earning rewards.
    Active,
    /// Deactivation requested: cooldown until
    /// [`StakeDelegation::deactivation_epoch`].
    Deactivating,
    /// Cooldown complete: the full balance (principal + rewards) is
    /// withdrawable.
    Deactivated,
}

impl StakeState {
    /// Lowercase name for logs and audit events.
    pub fn as_str(&self) -> &'static str {
        match self {
            StakeState::Delegated => "delegated",
            StakeState::Active => "active",
            StakeState::Deactivating => "deactivating",
            StakeState::Deactivated => "deactivated",
        }
    }
}

/// Explicit failures from the stake-leg state machine and settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StakeError {
    /// `delegate_at_fund` on an escrow that is not `Funded` — the
    /// opt-in happens at fund time, not before or after.
    NotFunded,
    /// The opt-in key is not the escrow's initializer — only the
    /// initializer can delegate the locked funds.
    NotInitializer,
    /// The escrow amount is zero (defensive: `initialize` already
    /// rejects zero amounts).
    ZeroPrincipal,
    /// The stake account address is the zero address.
    InvalidStakeAccount,
    /// The vote account address is the zero address.
    InvalidVoteAccount,
    /// `reward_split_bps > 10_000`.
    InvalidRewardSplit,
    /// A stake-state transition that is not in the lifecycle (e.g.
    /// deactivating a never-activated stake).
    InvalidStateTransition,
    /// `note_activation` before `activation_epoch`.
    NotYetActive,
    /// `note_deactivated` before `deactivation_epoch`.
    NotYetDeactivated,
    /// The keeper-authorized taker payout exceeds the remaining
    /// delegated principal.
    InsufficientPrincipal,
    /// The observed stake-account balance is below the remaining
    /// principal — an explicit failure, never silently covered.
    BalanceBelowPrincipal,
    /// Recording a principal release would push the cumulative total
    /// past the delegated principal.
    OverRelease,
    /// Epoch or counter arithmetic overflowed (defensive: only on
    /// `u64::MAX` epochs).
    ArithmeticOverflow,
}

/// The entitlement split for one keeper-authorized taker payout, as
/// computed by [`StakeDelegation::settle`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakeSettlement {
    /// Principal lamports the taker receives now.
    pub taker_principal: u64,
    /// Reward lamports the taker receives now (zero unless the stake
    /// is `Deactivated`).
    pub taker_rewards: u64,
    /// Reward lamports the initializer receives now (zero unless the
    /// stake is `Deactivated`).
    pub initializer_rewards: u64,
    /// `true` while `Active` / `Deactivating`: rewards exist in the
    /// stake account but are not withdrawable yet — the principal leg
    /// is NOT blocked by this.
    pub rewards_pending: bool,
    /// Delegated principal remaining after this settlement.
    pub principal_remaining_after: u64,
    /// The stake state the settlement was computed under.
    pub stake_state: StakeState,
}

impl StakeSettlement {
    /// Everything the taker receives in this settlement.
    pub fn taker_total(&self) -> u64 {
        self.taker_principal + self.taker_rewards
    }

    /// Everything distributed in this settlement (taker + initializer
    /// rewards; the initializer's principal refund is a separate
    /// cancel-path settlement).
    pub fn total_distributed(&self) -> u64 {
        self.taker_principal + self.taker_rewards + self.initializer_rewards
    }
}

/// The stake leg of an escrow: the vault's locked SOL delegated to a
/// vote account, tracked as a pure-logic sidecar bound to the escrow
/// by [`escrow_id`](Self::escrow_id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeDelegation {
    escrow_id: [u8; 32],
    stake_account: [u8; 32],
    vote_account: [u8; 32],
    initializer: [u8; 32],
    principal_lamports: u64,
    principal_released: u64,
    /// The taker's share of staking rewards, in basis points
    /// (0–10_000).
    reward_split_bps: u16,
    state: StakeState,
    delegation_epoch: u64,
    activation_epoch: u64,
    /// Zero until [`begin_deactivation`](Self::begin_deactivation).
    deactivation_epoch: u64,
}

impl StakeDelegation {
    /// The initializer's opt-in: delegate the escrow's full locked
    /// amount to `stake_account` (bound to `vote_account`) at fund
    /// time.
    ///
    /// Check order: escrow state (`Funded`) → opt-in authority
    /// (initializer) → principal → account addresses → reward split.
    /// `reward_split_bps` is the taker's share of rewards; the
    /// initializer keeps the rest.
    pub fn delegate_at_fund(
        escrow: &Escrow,
        escrow_id: [u8; 32],
        initializer: [u8; 32],
        stake_account: [u8; 32],
        vote_account: [u8; 32],
        reward_split_bps: u16,
        current_epoch: u64,
    ) -> Result<Self, StakeError> {
        if escrow.state() != EscrowState::Funded {
            return Err(StakeError::NotFunded);
        }
        if initializer != escrow.initializer() {
            return Err(StakeError::NotInitializer);
        }
        let principal = escrow.amount();
        if principal == 0 {
            return Err(StakeError::ZeroPrincipal);
        }
        if stake_account == [0u8; 32] {
            return Err(StakeError::InvalidStakeAccount);
        }
        if vote_account == [0u8; 32] {
            return Err(StakeError::InvalidVoteAccount);
        }
        if reward_split_bps > STAKE_BPS_DENOMINATOR {
            return Err(StakeError::InvalidRewardSplit);
        }
        let activation_epoch = current_epoch
            .checked_add(1)
            .ok_or(StakeError::ArithmeticOverflow)?;
        Ok(Self {
            escrow_id,
            stake_account,
            vote_account,
            initializer,
            principal_lamports: principal,
            principal_released: 0,
            reward_split_bps,
            state: StakeState::Delegated,
            delegation_epoch: current_epoch,
            activation_epoch,
            deactivation_epoch: 0,
        })
    }

    /// Record the keeper's observation that stake warmup finished:
    /// `Delegated → Active`. Idempotent — re-observing an active
    /// stake is a no-op.
    pub fn note_activation(&mut self, current_epoch: u64) -> Result<(), StakeError> {
        match self.state {
            StakeState::Active => Ok(()),
            StakeState::Delegated => {
                if current_epoch < self.activation_epoch {
                    return Err(StakeError::NotYetActive);
                }
                self.state = StakeState::Active;
                Ok(())
            }
            StakeState::Deactivating | StakeState::Deactivated => {
                Err(StakeError::InvalidStateTransition)
            }
        }
    }

    /// Start the cooldown: `Active → Deactivating`. Idempotent.
    pub fn begin_deactivation(&mut self, current_epoch: u64) -> Result<(), StakeError> {
        match self.state {
            StakeState::Deactivating => Ok(()),
            StakeState::Active => {
                self.deactivation_epoch = current_epoch
                    .checked_add(1)
                    .ok_or(StakeError::ArithmeticOverflow)?;
                self.state = StakeState::Deactivating;
                Ok(())
            }
            StakeState::Delegated | StakeState::Deactivated => {
                Err(StakeError::InvalidStateTransition)
            }
        }
    }

    /// Record the keeper's observation that the cooldown finished:
    /// `Deactivating → Deactivated`. Idempotent.
    pub fn note_deactivated(&mut self, current_epoch: u64) -> Result<(), StakeError> {
        match self.state {
            StakeState::Deactivated => Ok(()),
            StakeState::Deactivating => {
                if current_epoch < self.deactivation_epoch {
                    return Err(StakeError::NotYetDeactivated);
                }
                self.state = StakeState::Deactivated;
                Ok(())
            }
            StakeState::Delegated | StakeState::Active => Err(StakeError::InvalidStateTransition),
        }
    }

    /// Compute the entitlement split for one keeper-authorized taker
    /// payout (`taker_payout` is the amount the escrow state machine
    /// already approved; `current_stake_balance` is the keeper's
    /// observed stake-account balance).
    ///
    /// Pure: this records nothing. After the transfers land, the
    /// keeper calls [`record_principal_release`](Self::record_principal_release).
    pub fn settle(
        &self,
        taker_payout: u64,
        current_stake_balance: u64,
    ) -> Result<StakeSettlement, StakeError> {
        // Invariant: `principal_released <= principal_lamports` is
        // enforced by `record_principal_release`, so this cannot
        // underflow.
        let principal_remaining = self.principal_lamports - self.principal_released;
        if taker_payout > principal_remaining {
            return Err(StakeError::InsufficientPrincipal);
        }
        if current_stake_balance < principal_remaining {
            return Err(StakeError::BalanceBelowPrincipal);
        }
        let rewards = current_stake_balance - principal_remaining;
        let (taker_rewards, initializer_rewards, rewards_pending) = match self.state {
            StakeState::Deactivated => {
                let taker_rewards = (rewards as u128 * u128::from(self.reward_split_bps)
                    / u128::from(STAKE_BPS_DENOMINATOR))
                    as u64;
                (taker_rewards, rewards - taker_rewards, false)
            }
            // Rewards accrue but are not withdrawable yet — the
            // principal leg settles regardless.
            StakeState::Active | StakeState::Deactivating => (0, 0, true),
            // Warmup never completed: the stake never earned.
            StakeState::Delegated => (0, 0, false),
        };
        Ok(StakeSettlement {
            taker_principal: taker_payout,
            taker_rewards,
            initializer_rewards,
            rewards_pending,
            principal_remaining_after: principal_remaining - taker_payout,
            stake_state: self.state,
        })
    }

    /// Record an executed principal payout to the taker, keeping the
    /// sidecar's books exact. Call once per landed transfer.
    pub fn record_principal_release(
        &mut self,
        taker_principal_paid: u64,
    ) -> Result<(), StakeError> {
        let next = self
            .principal_released
            .checked_add(taker_principal_paid)
            .ok_or(StakeError::ArithmeticOverflow)?;
        if next > self.principal_lamports {
            return Err(StakeError::OverRelease);
        }
        self.principal_released = next;
        Ok(())
    }

    /// The escrow this stake leg is bound to.
    pub fn escrow_id(&self) -> [u8; 32] {
        self.escrow_id
    }
    /// The stake account holding the delegated SOL.
    pub fn stake_account(&self) -> [u8; 32] {
        self.stake_account
    }
    /// The vote account the stake is delegated to.
    pub fn vote_account(&self) -> [u8; 32] {
        self.vote_account
    }
    /// The initializer that opted in.
    pub fn initializer(&self) -> [u8; 32] {
        self.initializer
    }
    /// The principal delegated at fund time (the escrow's amount).
    pub fn principal_lamports(&self) -> u64 {
        self.principal_lamports
    }
    /// Cumulative principal paid out to the taker.
    pub fn principal_released(&self) -> u64 {
        self.principal_released
    }
    /// Delegated principal not yet paid out.
    pub fn principal_remaining(&self) -> u64 {
        self.principal_lamports - self.principal_released
    }
    /// The taker's share of rewards, in basis points.
    pub fn reward_split_bps(&self) -> u16 {
        self.reward_split_bps
    }
    /// The current stake lifecycle state.
    pub fn state(&self) -> StakeState {
        self.state
    }
    /// The epoch the delegation was created.
    pub fn delegation_epoch(&self) -> u64 {
        self.delegation_epoch
    }
    /// The epoch warmup completes (`delegation_epoch + 1`).
    pub fn activation_epoch(&self) -> u64 {
        self.activation_epoch
    }
    /// The epoch the cooldown completes (zero until deactivation
    /// begins).
    pub fn deactivation_epoch(&self) -> u64 {
        self.deactivation_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Escrow;

    const INITIALIZER: [u8; 32] = [1u8; 32];
    const TAKER: [u8; 32] = [2u8; 32];
    const STAKE_ACCT: [u8; 32] = [3u8; 32];
    const VOTE_ACCT: [u8; 32] = [4u8; 32];
    const ESCROW_ID: [u8; 32] = [5u8; 32];
    const STRANGER: [u8; 32] = [9u8; 32];

    fn funded_escrow(amount: u64) -> Escrow {
        let mut e = Escrow::initialize(INITIALIZER, TAKER, amount, 9_999_999).unwrap();
        e.fund(INITIALIZER, 1_000).unwrap();
        e
    }

    fn delegated(amount: u64, epoch: u64) -> StakeDelegation {
        StakeDelegation::delegate_at_fund(
            &funded_escrow(amount),
            ESCROW_ID,
            INITIALIZER,
            STAKE_ACCT,
            VOTE_ACCT,
            5_000,
            epoch,
        )
        .unwrap()
    }

    #[test]
    fn delegate_at_fund_binds_escrow_snapshot() {
        let d = delegated(1_000_000, 10);
        assert_eq!(d.state(), StakeState::Delegated);
        assert_eq!(d.principal_lamports(), 1_000_000);
        assert_eq!(d.principal_remaining(), 1_000_000);
        assert_eq!(d.delegation_epoch(), 10);
        assert_eq!(d.activation_epoch(), 11);
        assert_eq!(d.deactivation_epoch(), 0);
        assert_eq!(d.escrow_id(), ESCROW_ID);
        assert_eq!(d.stake_account(), STAKE_ACCT);
        assert_eq!(d.vote_account(), VOTE_ACCT);
        assert_eq!(d.initializer(), INITIALIZER);
        assert_eq!(d.reward_split_bps(), 5_000);
    }

    #[test]
    fn delegate_requires_funded_escrow() {
        let unfunded = Escrow::initialize(INITIALIZER, TAKER, 1_000_000, 9_999_999).unwrap();
        let err = StakeDelegation::delegate_at_fund(
            &unfunded,
            ESCROW_ID,
            INITIALIZER,
            STAKE_ACCT,
            VOTE_ACCT,
            5_000,
            10,
        )
        .unwrap_err();
        assert_eq!(err, StakeError::NotFunded);
    }

    #[test]
    fn delegate_requires_initializer_opt_in() {
        let err = StakeDelegation::delegate_at_fund(
            &funded_escrow(1_000_000),
            ESCROW_ID,
            STRANGER,
            STAKE_ACCT,
            VOTE_ACCT,
            5_000,
            10,
        )
        .unwrap_err();
        assert_eq!(err, StakeError::NotInitializer);
    }

    #[test]
    fn delegate_rejects_bad_config() {
        let e = funded_escrow(1_000_000);
        // Zero vote account.
        assert_eq!(
            StakeDelegation::delegate_at_fund(
                &e, ESCROW_ID, INITIALIZER, STAKE_ACCT, [0u8; 32], 5_000, 10
            )
            .unwrap_err(),
            StakeError::InvalidVoteAccount
        );
        // Zero stake account.
        assert_eq!(
            StakeDelegation::delegate_at_fund(
                &e, ESCROW_ID, INITIALIZER, [0u8; 32], VOTE_ACCT, 5_000, 10
            )
            .unwrap_err(),
            StakeError::InvalidStakeAccount
        );
        // Reward split over 100%.
        assert_eq!(
            StakeDelegation::delegate_at_fund(
                &e, ESCROW_ID, INITIALIZER, STAKE_ACCT, VOTE_ACCT, 10_001, 10
            )
            .unwrap_err(),
            StakeError::InvalidRewardSplit
        );
        // Exactly 100% is fine.
        assert!(StakeDelegation::delegate_at_fund(
            &e, ESCROW_ID, INITIALIZER, STAKE_ACCT, VOTE_ACCT, 10_000, 10
        )
        .is_ok());
    }

    #[test]
    fn activation_epoch_gate() {
        let mut d = delegated(1_000_000, 10);
        assert_eq!(d.note_activation(10).unwrap_err(), StakeError::NotYetActive);
        assert_eq!(d.state(), StakeState::Delegated);
        d.note_activation(11).unwrap();
        assert_eq!(d.state(), StakeState::Active);
        // Idempotent re-observation.
        d.note_activation(11).unwrap();
        assert_eq!(d.state(), StakeState::Active);
    }

    #[test]
    fn full_stake_lifecycle_epochs() {
        let mut d = delegated(1_000_000, 10);
        // Cannot deactivate a never-activated stake.
        assert_eq!(
            d.begin_deactivation(11).unwrap_err(),
            StakeError::InvalidStateTransition
        );
        d.note_activation(11).unwrap();
        d.begin_deactivation(11).unwrap();
        assert_eq!(d.state(), StakeState::Deactivating);
        assert_eq!(d.deactivation_epoch(), 12);
        assert_eq!(
            d.note_deactivated(11).unwrap_err(),
            StakeError::NotYetDeactivated
        );
        // Idempotent begin.
        d.begin_deactivation(11).unwrap();
        d.note_deactivated(12).unwrap();
        assert_eq!(d.state(), StakeState::Deactivated);
        // No transition leaves Deactivated.
        assert_eq!(
            d.begin_deactivation(13).unwrap_err(),
            StakeError::InvalidStateTransition
        );
        // note_activation on a deactivated stake is a programming error.
        assert_eq!(
            d.note_activation(13).unwrap_err(),
            StakeError::InvalidStateTransition
        );
    }

    #[test]
    fn settle_principal_only_while_active() {
        let mut d = delegated(1_000_000, 10);
        d.note_activation(11).unwrap();
        // No rewards accrued yet: balance == principal.
        let s = d.settle(400_000, 1_000_000).unwrap();
        assert_eq!(s.taker_principal, 400_000);
        assert_eq!(s.taker_rewards, 0);
        assert_eq!(s.initializer_rewards, 0);
        assert!(s.rewards_pending);
        assert_eq!(s.principal_remaining_after, 600_000);
        assert_eq!(s.taker_total(), 400_000);
        d.record_principal_release(400_000).unwrap();
        assert_eq!(d.principal_remaining(), 600_000);
    }

    #[test]
    fn settle_distributes_rewards_after_deactivation() {
        let mut d = delegated(1_000_000, 10);
        d.note_activation(11).unwrap();
        d.begin_deactivation(20).unwrap();
        d.note_deactivated(21).unwrap();
        // 50_000 lamports of rewards on top of the principal.
        let s = d.settle(1_000_000, 1_050_000).unwrap();
        assert_eq!(s.taker_principal, 1_000_000);
        // 50% taker share: floor(50_000 * 5000 / 10_000).
        assert_eq!(s.taker_rewards, 25_000);
        assert_eq!(s.initializer_rewards, 25_000);
        assert!(!s.rewards_pending);
        assert_eq!(s.taker_total(), 1_025_000);
        assert_eq!(s.total_distributed(), 1_050_000);
        assert_eq!(s.principal_remaining_after, 0);
    }

    #[test]
    fn settle_before_deactivation_holds_rewards_pending() {
        let mut d = delegated(1_000_000, 10);
        d.note_activation(11).unwrap();
        // Rewards accrued but the stake is still active: the principal
        // leg must not be blocked, and no rewards move yet.
        let s = d.settle(1_000_000, 1_050_000).unwrap();
        assert_eq!(s.taker_principal, 1_000_000);
        assert_eq!(s.taker_rewards, 0);
        assert_eq!(s.initializer_rewards, 0);
        assert!(s.rewards_pending);
        // The rewards are still in the stake account for the later,
        // post-deactivation settlement.
        d.begin_deactivation(20).unwrap();
        d.note_deactivated(21).unwrap();
        d.record_principal_release(1_000_000).unwrap();
        let s2 = d.settle(0, 50_000).unwrap();
        assert_eq!(s2.taker_rewards, 25_000);
        assert_eq!(s2.initializer_rewards, 25_000);
        assert!(!s2.rewards_pending);
    }

    #[test]
    fn settle_never_activated_has_no_pending_rewards() {
        let d = delegated(1_000_000, 10);
        let s = d.settle(1_000_000, 1_000_000).unwrap();
        assert!(!s.rewards_pending);
        assert_eq!(s.taker_rewards, 0);
    }

    #[test]
    fn settle_rejects_over_payout() {
        let d = delegated(1_000_000, 10);
        assert_eq!(
            d.settle(1_000_001, 1_000_001).unwrap_err(),
            StakeError::InsufficientPrincipal
        );
    }

    #[test]
    fn settle_rejects_balance_below_principal() {
        let mut d = delegated(1_000_000, 10);
        d.note_activation(11).unwrap();
        // The keeper observed less than the remaining principal:
        // explicit failure, never silently covered.
        assert_eq!(
            d.settle(100_000, 999_999).unwrap_err(),
            StakeError::BalanceBelowPrincipal
        );
    }

    #[test]
    fn reward_dust_goes_to_initializer() {
        let mut d = StakeDelegation::delegate_at_fund(
            &funded_escrow(1_000_000),
            ESCROW_ID,
            INITIALIZER,
            STAKE_ACCT,
            VOTE_ACCT,
            5_000,
            10,
        )
        .unwrap();
        d.note_activation(11).unwrap();
        d.begin_deactivation(20).unwrap();
        d.note_deactivated(21).unwrap();
        // 1 lamport of rewards at a 50% split: floor(1/2) = 0 to the
        // taker, the dust to the initializer.
        let s = d.settle(1_000_000, 1_000_001).unwrap();
        assert_eq!(s.taker_rewards, 0);
        assert_eq!(s.initializer_rewards, 1);
    }

    #[test]
    fn record_principal_release_tracks_cumulative() {
        let mut d = delegated(1_000_000, 10);
        d.record_principal_release(400_000).unwrap();
        d.record_principal_release(600_000).unwrap();
        assert_eq!(d.principal_released(), 1_000_000);
        assert_eq!(d.principal_remaining(), 0);
        assert_eq!(
            d.record_principal_release(1).unwrap_err(),
            StakeError::OverRelease
        );
    }

    #[test]
    fn partial_releases_keep_reward_accounting_exact() {
        let mut d = delegated(1_000_000, 10);
        d.note_activation(11).unwrap();
        // First partial release: 400k principal, no rewards yet.
        let s1 = d.settle(400_000, 1_000_000).unwrap();
        d.record_principal_release(s1.taker_principal).unwrap();
        // Second partial release after rewards accrued: the keeper
        // observes the balance AFTER the first payout landed, so the
        // remaining principal is 600k and rewards are balance - 600k.
        d.begin_deactivation(20).unwrap();
        d.note_deactivated(21).unwrap();
        let s2 = d.settle(600_000, 630_000).unwrap();
        assert_eq!(s2.taker_principal, 600_000);
        assert_eq!(s2.taker_rewards, 15_000);
        assert_eq!(s2.initializer_rewards, 15_000);
        assert_eq!(s2.principal_remaining_after, 0);
    }

    #[test]
    fn stake_state_names() {
        assert_eq!(StakeState::Delegated.as_str(), "delegated");
        assert_eq!(StakeState::Active.as_str(), "active");
        assert_eq!(StakeState::Deactivating.as_str(), "deactivating");
        assert_eq!(StakeState::Deactivated.as_str(), "deactivated");
    }
}
