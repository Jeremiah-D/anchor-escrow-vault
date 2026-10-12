//! Escrow configuration templates (AV-72): one-call constructors for the
//! four canonical escrow compositions — auction, milestone-plan,
//! subscription, and arbitrated-dispute — with template-level
//! combination validation.
//!
//! Why: the `with_*` builders compose freely, but freedom is also a
//! footgun — an absolute and a relative timelock together, a timelock
//! that unlocks after expiry (so the initializer can always front-run
//! the taker's payout with `cancel_expired`), or a milestone plan whose
//! tranches do not sum to the lockup are all *legal builder sequences*
//! that only fail deep in a transition, or worse, encode an intent the
//! parties did not have. Templates encode the four compositions the
//! protocol is actually used for, validate the *combination* up front
//! with precise errors, and then delegate to the builders — the state
//! machine stays the single source of truth for transition semantics.
//!
//! Design notes:
//! - [`EscrowTemplate::validate`] is pure and side-effect free: callers
//!   can dry-run a configuration before [`EscrowTemplate::build`]
//!   materializes it. `build` validates first, so a template either
//!   produces a fully-configured escrow or fails with a
//!   [`TemplateError`] — never a half-built one.
//! - Combination legality the template enforces: absolute vs relative
//!   timelock are mutually exclusive (one clock per escrow, AV-64);
//!   `dual_sig` and `quorum` *compose* (dual-signature activation gates
//!   `fund`, the quorum gates `release` — the template applies both and
//!   the test matrix drives the full lifecycle through both gates);
//!   kind-specific shapes (tranche sums, subscription cadence, a real
//!   arbiter key) are checked before any builder runs.
//! - Templates are a client-side composition helper: they produce a
//!   plain [`Escrow`], so nothing here changes the vault account
//!   layout, the IDL, or the Anchor program — the chain only ever sees
//!   the composed escrow.

use super::{Escrow, EscrowError, MilestonePlan, QuorumPolicy};

/// The four canonical escrow compositions a template configures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateKind {
    /// Simple two-party escrow with an optional timelock: the classic
    /// auction-deposit / simple timelocked pattern — fund, wait for the
    /// unlock, release; or walk the `cancel_expired` exit after expiry.
    Auction,
    /// Deliverable-gated release (AV-15): the lockup splits into
    /// milestone tranches released on dual confirmation.
    MilestonePlan,
    /// Clock-driven periodic payouts (AV-56): the lockup pays out in
    /// equal per-period tranches back-scheduled from expiry.
    Subscription,
    /// Dispute-arbitrated escrow (AV-14): a single arbiter (or panel,
    /// via `quorum`) adjudicates escalated disputes, with an optional
    /// evidence-disclosure deadline (AV-68).
    ArbitratedDispute,
}

/// Per-kind parameters. The template validates the shape that the
/// builders cannot see as a combination (sums, cadences, key presence)
/// before delegating to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindParams<'a> {
    /// Auction parameters: the expiry grace period (AV-21), `0` for
    /// none.
    Auction {
        /// Expiry grace period in seconds (AV-21): `cancel_expired`
        /// requires `now >= expires_at + grace_period_secs`.
        grace_period_secs: u64,
    },
    /// Milestone-plan parameters: the tranche amounts in release order.
    MilestonePlan {
        /// Tranche amounts in release order; must be non-empty, every
        /// amount positive, and the exact `u128` sum must equal the
        /// locked amount (the plan is the *complete* release schedule,
        /// like [`Escrow::with_milestones`]).
        tranches: &'a [u64],
    },
    /// Subscription parameters (AV-56): the release cadence.
    Subscription {
        /// Seconds between period due dates.
        period_secs: u64,
        /// Number of periods (`1..=64`).
        periods: u8,
        /// The taker's payout per period; `periods * per_period` must
        /// equal the locked amount.
        per_period: u64,
    },
    /// Arbitrated-dispute parameters: the arbiter plus an optional
    /// evidence-disclosure deadline.
    ArbitratedDispute {
        /// The dispute arbiter's key (zero key rejected — a dispute
        /// with no judge is a misconfiguration, not a plain escrow).
        arbiter: [u8; 32],
        /// Optional evidence-disclosure deadline in seconds (AV-68):
        /// applied after the arbiter is bound.
        evidence_deadline_secs: Option<u64>,
    },
}

/// A parameterized escrow configuration: the composition kind, the two
/// parties, the economics, the cross-cutting options, and the
/// kind-specific parameters. Build with [`EscrowTemplate::build`]
/// after an optional [`EscrowTemplate::validate`] dry-run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowTemplate<'a> {
    /// Which of the four canonical compositions to build.
    pub kind: TemplateKind,
    /// The funding party (also the `fund` / `release` / `cancel`
    /// authority).
    pub initializer: [u8; 32],
    /// The payout counterparty.
    pub taker: [u8; 32],
    /// The locked amount in base units. Must be non-zero.
    pub amount: u64,
    /// Unix timestamp after which `cancel_expired` opens (grace
    /// period aside).
    pub expires_at: u64,
    /// Dual-signature activation (AV-12): both parties must activate
    /// before `fund` is accepted.
    pub dual_sig: bool,
    /// Absolute timelock (AV-27): no taker payout before this Unix
    /// timestamp. Mutually exclusive with `relative_timelock_secs`.
    pub timelock: Option<u64>,
    /// Relative timelock (AV-64): no taker payout before
    /// `fund_at + relative_timelock_secs`. Mutually exclusive with
    /// `timelock`.
    pub relative_timelock_secs: Option<u64>,
    /// Optional weighted attestor quorum gating `release` (AV-04 /
    /// AV-45). Composes with `dual_sig`: activation gates `fund`, the
    /// quorum gates `release`.
    pub quorum: Option<QuorumPolicy>,
    /// Optional SPL token mint binding (AV-16).
    pub mint: Option<[u8; 32]>,
    /// The kind-specific parameters.
    pub kind_params: KindParams<'a>,
}

/// What template validation can reject. Builder-level failures surface
/// as [`TemplateError::InvalidConfiguration`] carrying the underlying
/// [`EscrowError`] — the template never invents semantics the state
/// machine does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateError {
    /// `amount == 0`: there is nothing to escrow.
    ZeroAmount,
    /// Both an absolute and a relative timelock were configured — one
    /// clock per escrow (AV-64).
    ConflictingTimelocks,
    /// The absolute timelock unlocks at or after `expires_at`: the
    /// taker could never release before the initializer's
    /// `cancel_expired` opens — a configuration that silently hands
    /// the initializer a front-running option.
    TimelockPastExpiry,
    /// A milestone plan with no tranches.
    EmptyTranches,
    /// The milestone tranches do not sum to exactly the locked amount.
    TrancheSumMismatch,
    /// The subscription cadence does not describe the locked amount
    /// (`period_secs == 0`, `periods` out of `1..=64`, `per_period ==
    /// 0`, or `periods * per_period != amount`).
    InvalidSubscriptionParams,
    /// An arbitrated-dispute template with a zero arbiter key — a
    /// dispute with no judge.
    MissingArbiter,
    /// A builder rejected the configuration after template validation
    /// passed (e.g. an invalid quorum policy): the state machine's own
    /// verdict, carried through unchanged.
    InvalidConfiguration(EscrowError),
}

impl<'a> EscrowTemplate<'a> {
    /// The composition kind this template builds.
    pub fn kind(&self) -> TemplateKind {
        self.kind
    }

    /// Validate the configuration without building: combination
    /// legality (timelock conflicts, kind-specific shapes) plus the
    /// basic economics. Pure — safe to call as a dry-run.
    pub fn validate(&self) -> Result<(), TemplateError> {
        if self.amount == 0 {
            return Err(TemplateError::ZeroAmount);
        }
        // One clock per escrow (AV-64): the builders enforce this too,
        // but the template reports the *combination* error before any
        // builder runs, so the failure does not depend on builder
        // order.
        if self.timelock.is_some() && self.relative_timelock_secs.is_some() {
            return Err(TemplateError::ConflictingTimelocks);
        }
        // A timelock that unlocks at or after expiry hands the
        // initializer a standing front-run over the taker's payout:
        // `cancel_expired` opens at `expires_at` (+ grace) while
        // `release` stays gated. Reject the footgun at configuration
        // time.
        if let Some(unlock_at) = self.timelock {
            if unlock_at >= self.expires_at {
                return Err(TemplateError::TimelockPastExpiry);
            }
        }
        match &self.kind_params {
            KindParams::Auction { .. } => Ok(()),
            KindParams::MilestonePlan { tranches } => {
                if tranches.is_empty() {
                    return Err(TemplateError::EmptyTranches);
                }
                let mut sum: u128 = 0;
                for &t in tranches.iter() {
                    if t == 0 {
                        // A zero tranche stalls the in-order release
                        // sequence — the same config error
                        // `MilestonePlan::new` rejects.
                        return Err(TemplateError::TrancheSumMismatch);
                    }
                    sum += t as u128;
                }
                if sum != self.amount as u128 {
                    return Err(TemplateError::TrancheSumMismatch);
                }
                Ok(())
            }
            KindParams::Subscription {
                period_secs,
                periods,
                per_period,
            } => {
                if *period_secs == 0
                    || *periods == 0
                    || *per_period == 0
                    || *periods as u128 * *per_period as u128 != self.amount as u128
                {
                    return Err(TemplateError::InvalidSubscriptionParams);
                }
                Ok(())
            }
            KindParams::ArbitratedDispute { arbiter, .. } => {
                if *arbiter == [0u8; 32] {
                    return Err(TemplateError::MissingArbiter);
                }
                Ok(())
            }
        }
    }

    /// Build the configured escrow: validate first, then compose the
    /// `with_*` builders in dependency order (timelock before quorum
    /// is irrelevant — builders are order-independent — but the
    /// arbiter must precede the evidence deadline, which requires a
    /// bound arbitration mechanism). Either a fully-configured escrow
    /// or a [`TemplateError`]: never a half-built one.
    pub fn build(&self) -> Result<Escrow, TemplateError> {
        self.validate()?;
        let map = TemplateError::InvalidConfiguration;
        let mut e =
            Escrow::initialize(self.initializer, self.taker, self.amount, self.expires_at)
                .map_err(map)?;
        if self.dual_sig {
            e = e.with_dual_sig().map_err(map)?;
        }
        // The two timelocks are mutually exclusive — `validate` proved
        // at most one is `Some`.
        if let Some(unlock_at) = self.timelock {
            e = e.with_timelock(unlock_at).map_err(map)?;
        }
        if let Some(secs) = self.relative_timelock_secs {
            e = e.with_relative_timelock(secs).map_err(map)?;
        }
        if let Some(policy) = &self.quorum {
            e = e.with_quorum(*policy).map_err(map)?;
        }
        if let Some(mint) = self.mint {
            e = e.with_mint(mint).map_err(map)?;
        }
        match &self.kind_params {
            KindParams::Auction { grace_period_secs } => {
                if *grace_period_secs > 0 {
                    e = e.with_grace_period(*grace_period_secs).map_err(map)?;
                }
            }
            KindParams::MilestonePlan { tranches } => {
                let plan = MilestonePlan::new(tranches).map_err(map)?;
                e = e.with_milestones(plan).map_err(map)?;
            }
            KindParams::Subscription {
                period_secs,
                periods,
                per_period,
            } => {
                e = e
                    .with_subscription(*period_secs, *periods, *per_period)
                    .map_err(map)?;
            }
            KindParams::ArbitratedDispute {
                arbiter,
                evidence_deadline_secs,
            } => {
                // The deadline requires a bound arbitration mechanism
                // (`with_evidence_deadline` rejects otherwise), so the
                // arbiter binds first.
                e = e.with_arbiter(*arbiter).map_err(map)?;
                if let Some(deadline) = evidence_deadline_secs {
                    e = e.with_evidence_deadline(*deadline).map_err(map)?;
                }
            }
        }
        Ok(e)
    }
}

#[cfg(test)]
mod template_tests {
    use super::*;
    use crate::EscrowState;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const ARBITER: [u8; 32] = [0xAD; 32];
    const ATTESTOR_1: [u8; 32] = [0xA1; 32];
    const ATTESTOR_2: [u8; 32] = [0xA2; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;
    const AMOUNT: u64 = 1_000_000;

    fn base(kind: TemplateKind, kind_params: KindParams) -> EscrowTemplate {
        EscrowTemplate {
            kind,
            initializer: ALICE,
            taker: BOB,
            amount: AMOUNT,
            expires_at: EXPIRES_AT,
            dual_sig: false,
            timelock: None,
            relative_timelock_secs: None,
            quorum: None,
            mint: None,
            kind_params,
        }
    }

    fn quorum_1_of_2() -> QuorumPolicy {
        QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], &[1, 1], 1).unwrap()
    }

    // ---------- validation ----------

    #[test]
    fn zero_amount_rejected() {
        let mut t = base(
            TemplateKind::Auction,
            KindParams::Auction {
                grace_period_secs: 0,
            },
        );
        t.amount = 0;
        assert_eq!(t.validate(), Err(TemplateError::ZeroAmount));
        assert_eq!(t.build(), Err(TemplateError::ZeroAmount));
    }

    #[test]
    fn absolute_and_relative_timelock_conflict() {
        let mut t = base(
            TemplateKind::Auction,
            KindParams::Auction {
                grace_period_secs: 0,
            },
        );
        t.timelock = Some(EXPIRES_AT - 100);
        t.relative_timelock_secs = Some(3_600);
        assert_eq!(t.validate(), Err(TemplateError::ConflictingTimelocks));
        assert_eq!(t.build(), Err(TemplateError::ConflictingTimelocks));
    }

    #[test]
    fn timelock_at_or_past_expiry_rejected() {
        for unlock_at in [EXPIRES_AT, EXPIRES_AT + 3_600] {
            let mut t = base(
                TemplateKind::Auction,
                KindParams::Auction {
                    grace_period_secs: 0,
                },
            );
            t.timelock = Some(unlock_at);
            assert_eq!(
                t.validate(),
                Err(TemplateError::TimelockPastExpiry),
                "unlock_at = {unlock_at}"
            );
        }
        // Just before expiry is fine.
        let mut t = base(
            TemplateKind::Auction,
            KindParams::Auction {
                grace_period_secs: 0,
            },
        );
        t.timelock = Some(EXPIRES_AT - 1);
        assert_eq!(t.validate(), Ok(()));
    }

    #[test]
    fn milestone_tranche_shapes_rejected() {
        // Empty.
        let t = base(TemplateKind::MilestonePlan, KindParams::MilestonePlan { tranches: &[] });
        assert_eq!(t.validate(), Err(TemplateError::EmptyTranches));
        // Sum mismatch.
        let t = base(
            TemplateKind::MilestonePlan,
            KindParams::MilestonePlan {
                tranches: &[600_000, 300_000],
            },
        );
        assert_eq!(t.validate(), Err(TemplateError::TrancheSumMismatch));
        // Zero tranche.
        let t = base(
            TemplateKind::MilestonePlan,
            KindParams::MilestonePlan {
                tranches: &[AMOUNT, 0],
            },
        );
        assert_eq!(t.validate(), Err(TemplateError::TrancheSumMismatch));
    }

    #[test]
    fn subscription_param_shapes_rejected() {
        // Cadence does not describe the amount.
        let t = base(
            TemplateKind::Subscription,
            KindParams::Subscription {
                period_secs: 100,
                periods: 4,
                per_period: AMOUNT / 4 + 1,
            },
        );
        assert_eq!(t.validate(), Err(TemplateError::InvalidSubscriptionParams));
        // Zero cadence.
        let t = base(
            TemplateKind::Subscription,
            KindParams::Subscription {
                period_secs: 0,
                periods: 4,
                per_period: AMOUNT / 4,
            },
        );
        assert_eq!(t.validate(), Err(TemplateError::InvalidSubscriptionParams));
    }

    #[test]
    fn arbitrated_dispute_requires_a_real_arbiter() {
        let t = base(
            TemplateKind::ArbitratedDispute,
            KindParams::ArbitratedDispute {
                arbiter: [0u8; 32],
                evidence_deadline_secs: None,
            },
        );
        assert_eq!(t.validate(), Err(TemplateError::MissingArbiter));
    }

    #[test]
    fn builder_failures_surface_as_invalid_configuration() {
        // A zero evidence deadline passes template-level validation
        // (deadline *presence* is fine) but the builder rejects it —
        // the template must carry the state machine's verdict through
        // unchanged.
        let t = base(
            TemplateKind::ArbitratedDispute,
            KindParams::ArbitratedDispute {
                arbiter: ARBITER,
                evidence_deadline_secs: Some(0),
            },
        );
        assert_eq!(t.validate(), Ok(()));
        assert_eq!(
            t.build(),
            Err(TemplateError::InvalidConfiguration(
                EscrowError::InvalidEvidenceDeadline
            ))
        );
    }

    // ---------- builds produce working escrows ----------

    #[test]
    fn auction_builds_and_runs_the_simple_lifecycle() {
        let mut t = base(
            TemplateKind::Auction,
            KindParams::Auction {
                grace_period_secs: 300,
            },
        );
        t.timelock = Some(EXPIRES_AT - 3_600);
        let mut e = t.build().unwrap();
        assert_eq!(e.amount(), AMOUNT);
        assert_eq!(e.unlock_at(), EXPIRES_AT - 3_600);
        assert_eq!(e.grace_period(), 300);
        // Payout before the unlock is gated; after it, the plain
        // release path works.
        e.fund(ALICE, EXPIRES_AT - 7_200).unwrap();
        assert_eq!(
            e.release(ALICE, EXPIRES_AT - 3_601, AMOUNT, None, BOB),
            Err(EscrowError::TimelockNotReached)
        );
        let (payout, fee) = e.release(ALICE, EXPIRES_AT - 3_600, AMOUNT, None, BOB).unwrap();
        assert_eq!((payout, fee), (AMOUNT, 0));
        assert_eq!(e.state(), EscrowState::Released);
    }

    #[test]
    fn milestone_plan_builds_and_runs_tranche_lifecycle() {
        let t = base(
            TemplateKind::MilestonePlan,
            KindParams::MilestonePlan {
                tranches: &[400_000, 600_000],
            },
        );
        let mut e = t.build().unwrap();
        assert_eq!(e.milestone_plan().unwrap().count(), 2);
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        let (payout, _) = e.release_milestone(ALICE, EXPIRES_AT - 1_000, 0, None, BOB).unwrap();
        assert_eq!(payout, 400_000);
        assert_eq!(e.released_amount(), 400_000);
    }

    #[test]
    fn subscription_builds_and_releases_periods() {
        let t = base(
            TemplateKind::Subscription,
            KindParams::Subscription {
                period_secs: 100,
                periods: 4,
                per_period: AMOUNT / 4,
            },
        );
        let mut e = t.build().unwrap();
        let schedule = e.subscription_schedule().unwrap();
        assert_eq!(schedule.periods, 4);
        e.fund(ALICE, EXPIRES_AT - 1_000).unwrap();
        // Periods are back-scheduled from expiry: period 0 is due at
        // EXPIRES_AT - 300.
        let due_0 = e.subscription_period_due_at(0).unwrap();
        let (payout, _) = e.release_period(ALICE, due_0, 0, None, BOB).unwrap();
        assert_eq!(payout, AMOUNT / 4);
        assert_eq!(e.subscription_next_period(), 1);
    }

    #[test]
    fn arbitrated_dispute_builds_and_runs_escalate_resolve() {
        let t = base(
            TemplateKind::ArbitratedDispute,
            KindParams::ArbitratedDispute {
                arbiter: ARBITER,
                evidence_deadline_secs: Some(7_200),
            },
        );
        let mut e = t.build().unwrap();
        assert_eq!(e.arbiter(), Some(ARBITER));
        assert_eq!(e.evidence_deadline_secs(), 7_200);
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1_000, None).unwrap();
        let (payout, _fee, refund) = e.resolve(ARBITER, 600_000, None, None, BOB).unwrap();
        assert_eq!(payout, 600_000);
        assert_eq!(refund, 400_000);
    }

    #[test]
    fn dual_sig_and_quorum_compose() {
        // The combination the template explicitly supports:
        // dual-signature activation gates `fund`, the quorum gates
        // `release` — both must be satisfied in order.
        let mut t = base(
            TemplateKind::Auction,
            KindParams::Auction {
                grace_period_secs: 0,
            },
        );
        t.dual_sig = true;
        t.quorum = Some(quorum_1_of_2());
        let mut e = t.build().unwrap();
        // Activation still required before funding.
        assert_eq!(
            e.fund(ALICE, EXPIRES_AT - 3_600),
            Err(EscrowError::InvalidStateTransition)
        );
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        // Release still gated on the quorum.
        assert_eq!(
            e.release(ALICE, EXPIRES_AT - 1_000, AMOUNT, None, BOB),
            Err(EscrowError::QuorumNotReached)
        );
        e.attest(ATTESTOR_1).unwrap();
        let (payout, _) = e.release(ALICE, EXPIRES_AT - 1_000, AMOUNT, None, BOB).unwrap();
        assert_eq!(payout, AMOUNT);
    }

    #[test]
    fn validate_is_a_pure_dry_run() {
        let t = base(
            TemplateKind::MilestonePlan,
            KindParams::MilestonePlan {
                tranches: &[AMOUNT],
            },
        );
        // Validating twice is fine and builds the same escrow twice —
        // no shared mutable state.
        assert_eq!(t.validate(), Ok(()));
        let e1 = t.build().unwrap();
        let e2 = t.build().unwrap();
        assert_eq!(e1.amount(), e2.amount());
        assert_eq!(
            e1.milestone_plan().unwrap().count(),
            e2.milestone_plan().unwrap().count()
        );
    }

    #[test]
    fn build_is_all_or_nothing() {
        // Template-level validation fails before any builder runs: the
        // conflicting timelocks surface as the template's own error,
        // not a builder-order-dependent `EscrowError`.
        let mut t = base(
            TemplateKind::Subscription,
            KindParams::Subscription {
                period_secs: 100,
                periods: 4,
                per_period: AMOUNT / 4,
            },
        );
        t.timelock = Some(EXPIRES_AT - 100);
        t.relative_timelock_secs = Some(60);
        assert_eq!(t.build(), Err(TemplateError::ConflictingTimelocks));
    }

    #[test]
    fn stranger_keys_build_but_cannot_act() {
        // The template does not invent party policy: anyone can be
        // named, but only the named parties can move funds.
        let mut t = base(
            TemplateKind::Auction,
            KindParams::Auction {
                grace_period_secs: 0,
            },
        );
        t.initializer = MALLORY;
        let mut e = t.build().unwrap();
        assert_eq!(e.fund(ALICE, EXPIRES_AT - 3_600), Err(EscrowError::Unauthorized));
        e.fund(MALLORY, EXPIRES_AT - 3_600).unwrap();
    }
}
