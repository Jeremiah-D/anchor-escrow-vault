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

use super::{sha256, Escrow, EscrowError, MilestonePlan, QuorumPolicy};

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

// ---------------------------------------------------------------------------
// AV-77: governance presets with declared override surfaces.
// ---------------------------------------------------------------------------
//
// AV-72's `EscrowTemplate` is a free-form parameterized configuration —
// every field is settable by the caller. A governance preset is the
// stricter sibling: the four canonical compositions with *audited
// default parameters* plus a *declared override surface* — the field
// names the preset's review allows [`TemplatePreset::apply_template`]
// to change. Anything else (an unknown name, a field another preset
// declares, a mistyped value, a repeated field) is rejected with
// [`EscrowError::TemplateOverrideRejected`]: the preset's audited shape
// is never silently widened.
//
// After the overrides apply, the effective template runs the *full*
// AV-72 invariant validation (conservation / mutual exclusion /
// thresholds) and then `build`, so builder-level gates (quorum policy,
// evidence deadline, …) still hold. Template-level rejections project
// onto [`EscrowError`] via [`map_template_error`], so `apply_template`
// callers match on one error type.
//
// [`IndexedEscrow::apply_template`](super::IndexedEscrow::apply_template)
// is the event-emitting entry point: it stands up the escrow and records
// [`EscrowEventKind::TemplateApplied`](super::EscrowEventKind::TemplateApplied)
// carrying the SHA-256 of the effective parameters
// ([`EscrowTemplate::params_hash`]) for indexers and auditors.

/// A typed per-field override value for
/// [`TemplatePreset::apply_template`]. Each overridable field declares
/// the variant it accepts:
///
/// | field | variant | preset kinds |
/// |---|---|---|
/// | `amount` | `U64` | all |
/// | `expires_at` | `U64` | all |
/// | `dual_sig` | `Bool` | all |
/// | `timelock` | `OptU64` | all |
/// | `relative_timelock_secs` | `OptU64` | all |
/// | `mint` | `OptKey` | all |
/// | `quorum` | `Quorum` | arbitrated-dispute |
/// | `grace_period_secs` | `U64` | auction |
/// | `tranches` | `Tranches` | milestone-plan |
/// | `period_secs` | `U64` | subscription |
/// | `periods` | `U8` | subscription |
/// | `per_period` | `U64` | subscription |
/// | `arbiter` | `Key` | arbitrated-dispute |
/// | `evidence_deadline_secs` | `OptU64` | arbitrated-dispute |
///
/// `initializer` / `taker` are escrow identity, not preset parameters:
/// they are fixed at preset construction and never overridable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideValue<'a> {
    /// A plain `u64` field (`amount`, `expires_at`,
    /// `grace_period_secs`, `period_secs`, `per_period`).
    U64(u64),
    /// A plain `u8` field (`periods`).
    U8(u8),
    /// A boolean field (`dual_sig`).
    Bool(bool),
    /// A 32-byte key field (`arbiter`).
    Key([u8; 32]),
    /// An optional `u64` field (`timelock`, `relative_timelock_secs`,
    /// `evidence_deadline_secs`).
    OptU64(Option<u64>),
    /// An optional 32-byte key field (`mint`).
    OptKey(Option<[u8; 32]>),
    /// The whole quorum policy, or its removal (`quorum`).
    Quorum(Option<QuorumPolicy>),
    /// The milestone tranche table (`tranches`).
    Tranches(&'a [u64]),
}

/// A governance preset: one of the four canonical AV-72 compositions
/// with audited default parameters ([`TemplatePreset::template`]) and
/// the declared override surface ([`TemplatePreset::overridable`]) —
/// the only field names [`TemplatePreset::apply_template`] accepts.
/// Build with the four constructors; the defaults are the conservative
/// composition each preset's review signed off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplatePreset<'a> {
    /// Which of the four canonical compositions this preset configures.
    pub kind: TemplateKind,
    /// The preset's audited default parameters: what
    /// [`TemplatePreset::apply_template`] builds when the override
    /// list is empty.
    pub template: EscrowTemplate<'a>,
    /// Field names `apply_template` may override. Any other name —
    /// unknown, or declared by a different preset's review — is
    /// rejected with [`EscrowError::TemplateOverrideRejected`].
    pub overridable: &'static [&'static str],
}

/// The result of [`TemplatePreset::apply_template`]: the effective
/// (post-override) template, the escrow built from it, and the SHA-256
/// over the effective parameters' canonical encoding
/// ([`EscrowTemplate::params_hash`]) — the value the
/// `TemplateApplied` event carries for auditors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppliedTemplate<'a> {
    /// The template after overrides — what was actually applied.
    pub template: EscrowTemplate<'a>,
    /// The fully-configured escrow built from the effective template.
    pub escrow: Escrow,
    /// `template.params_hash()`: the effective-parameter commitment.
    pub params_hash: [u8; 32],
}

/// Project a [`TemplateError`] onto the program error surface: the
/// closest [`EscrowError`] for each template-level rejection, so
/// `apply_template` callers match on one error type. The mapping is
/// total — `build` runs after `validate`, so `InvalidConfiguration`
/// here only carries builder verdicts `validate` cannot see.
fn map_template_error(e: TemplateError) -> EscrowError {
    match e {
        TemplateError::ZeroAmount => EscrowError::AmountMismatch,
        TemplateError::ConflictingTimelocks | TemplateError::TimelockPastExpiry => {
            EscrowError::InvalidTimelock
        }
        TemplateError::EmptyTranches | TemplateError::TrancheSumMismatch => {
            EscrowError::InvalidMilestones
        }
        TemplateError::InvalidSubscriptionParams => EscrowError::InvalidSubscription,
        TemplateError::MissingArbiter => EscrowError::InvalidArbiter,
        TemplateError::InvalidConfiguration(inner) => inner,
    }
}

fn push_opt_u64(out: &mut Vec<u8>, v: Option<u64>) {
    match v {
        None => out.push(0),
        Some(x) => {
            out.push(1);
            out.extend_from_slice(&x.to_le_bytes());
        }
    }
}

fn push_opt_key(out: &mut Vec<u8>, v: Option<[u8; 32]>) {
    match v {
        None => out.push(0),
        Some(k) => {
            out.push(1);
            out.extend_from_slice(&k);
        }
    }
}

impl<'a> EscrowTemplate<'a> {
    /// AV-77: SHA-256 over the canonical encoding of the *effective*
    /// template parameters — the commitment the `TemplateApplied`
    /// event carries.
    ///
    /// Canonical form (fixed order, no ambiguity): the domain tag
    /// `b"escrow-template-params/v1"`, the kind byte
    /// (auction = 0, milestone-plan = 1, subscription = 2,
    /// arbitrated-dispute = 3), `initializer`, `taker`, `amount` /
    /// `expires_at` (u64 LE), `dual_sig`, the two timelocks and the
    /// quorum / mint as presence-flagged values, then the
    /// kind-specific parameters. The quorum encodes its threshold, the
    /// member count, and the `(key, weight)` pairs in slot order —
    /// the attestor *set* is part of the commitment, not just the
    /// threshold. Uses the crate's hand-written SHA-256
    /// ([`sha256`]); pure and deterministic.
    pub fn params_hash(&self) -> [u8; 32] {
        let mut out = Vec::new();
        out.extend_from_slice(b"escrow-template-params/v1");
        out.push(match self.kind {
            TemplateKind::Auction => 0,
            TemplateKind::MilestonePlan => 1,
            TemplateKind::Subscription => 2,
            TemplateKind::ArbitratedDispute => 3,
        });
        out.extend_from_slice(&self.initializer);
        out.extend_from_slice(&self.taker);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.push(self.dual_sig as u8);
        push_opt_u64(&mut out, self.timelock);
        push_opt_u64(&mut out, self.relative_timelock_secs);
        match &self.quorum {
            None => out.push(0),
            Some(q) => {
                out.push(1);
                out.extend_from_slice(&q.threshold().to_le_bytes());
                let attestors = q.attestors();
                let weights = q.weights();
                out.extend_from_slice(&(attestors.len() as u64).to_le_bytes());
                for (key, weight) in attestors.iter().zip(weights.iter()) {
                    out.extend_from_slice(key);
                    out.extend_from_slice(&weight.to_le_bytes());
                }
            }
        }
        push_opt_key(&mut out, self.mint);
        match &self.kind_params {
            KindParams::Auction { grace_period_secs } => {
                out.extend_from_slice(&grace_period_secs.to_le_bytes());
            }
            KindParams::MilestonePlan { tranches } => {
                out.extend_from_slice(&(tranches.len() as u64).to_le_bytes());
                for t in tranches.iter() {
                    out.extend_from_slice(&t.to_le_bytes());
                }
            }
            KindParams::Subscription {
                period_secs,
                periods,
                per_period,
            } => {
                out.extend_from_slice(&period_secs.to_le_bytes());
                out.push(*periods);
                out.extend_from_slice(&per_period.to_le_bytes());
            }
            KindParams::ArbitratedDispute {
                arbiter,
                evidence_deadline_secs,
            } => {
                out.extend_from_slice(arbiter);
                push_opt_u64(&mut out, *evidence_deadline_secs);
            }
        }
        sha256(&out)
    }

    /// Apply per-field overrides declared by `preset` to a copy of
    /// this template, then run the full invariant validation. Pure.
    ///
    /// Rejections (all [`EscrowError::TemplateOverrideRejected`]):
    /// an override naming a field outside `preset.overridable`
    /// (unknown names and fields declared by a *different* preset's
    /// review alike), a value whose [`OverrideValue`] variant does not
    /// match the field's declared type, or the same field twice (a
    /// repeated name is ambiguous, not a merge — rejected rather than
    /// guessing an order). Invariant failures project onto
    /// [`EscrowError`] via [`map_template_error`].
    fn apply_overrides(
        &self,
        preset: &TemplatePreset<'a>,
        overrides: &[(&str, OverrideValue<'a>)],
    ) -> Result<EscrowTemplate<'a>, EscrowError> {
        let mut effective = *self;
        for (i, (name, value)) in overrides.iter().enumerate() {
            if overrides[..i].iter().any(|(prev, _)| prev == name) {
                return Err(EscrowError::TemplateOverrideRejected);
            }
            if !preset.overridable.contains(name) {
                return Err(EscrowError::TemplateOverrideRejected);
            }
            match (*name, *value) {
                ("amount", OverrideValue::U64(v)) => effective.amount = v,
                ("expires_at", OverrideValue::U64(v)) => effective.expires_at = v,
                ("dual_sig", OverrideValue::Bool(v)) => effective.dual_sig = v,
                ("timelock", OverrideValue::OptU64(v)) => effective.timelock = v,
                ("relative_timelock_secs", OverrideValue::OptU64(v)) => {
                    effective.relative_timelock_secs = v
                }
                ("mint", OverrideValue::OptKey(v)) => effective.mint = v,
                ("quorum", OverrideValue::Quorum(v)) => effective.quorum = v,
                ("grace_period_secs", OverrideValue::U64(v)) => {
                    match &mut effective.kind_params {
                        KindParams::Auction { grace_period_secs } => *grace_period_secs = v,
                        _ => return Err(EscrowError::TemplateOverrideRejected),
                    }
                }
                ("tranches", OverrideValue::Tranches(v)) => match &mut effective.kind_params {
                    KindParams::MilestonePlan { tranches } => *tranches = v,
                    _ => return Err(EscrowError::TemplateOverrideRejected),
                },
                ("period_secs", OverrideValue::U64(v)) => match &mut effective.kind_params {
                    KindParams::Subscription { period_secs, .. } => *period_secs = v,
                    _ => return Err(EscrowError::TemplateOverrideRejected),
                },
                ("periods", OverrideValue::U8(v)) => match &mut effective.kind_params {
                    KindParams::Subscription { periods, .. } => *periods = v,
                    _ => return Err(EscrowError::TemplateOverrideRejected),
                },
                ("per_period", OverrideValue::U64(v)) => match &mut effective.kind_params {
                    KindParams::Subscription { per_period, .. } => *per_period = v,
                    _ => return Err(EscrowError::TemplateOverrideRejected),
                },
                ("arbiter", OverrideValue::Key(v)) => match &mut effective.kind_params {
                    KindParams::ArbitratedDispute { arbiter, .. } => *arbiter = v,
                    _ => return Err(EscrowError::TemplateOverrideRejected),
                },
                ("evidence_deadline_secs", OverrideValue::OptU64(v)) => {
                    match &mut effective.kind_params {
                        KindParams::ArbitratedDispute {
                            evidence_deadline_secs,
                            ..
                        } => *evidence_deadline_secs = v,
                        _ => return Err(EscrowError::TemplateOverrideRejected),
                    }
                }
                // Known name with the wrong value type, or a name the
                // field table does not know at all (belt-and-braces
                // behind the `overridable` check above).
                _ => return Err(EscrowError::TemplateOverrideRejected),
            }
        }
        effective.validate().map_err(map_template_error)?;
        Ok(effective)
    }
}

impl<'a> TemplatePreset<'a> {
    /// The plain two-party escrow preset: no timelock, no quorum, no
    /// grace period by default. Overridable: the economics
    /// (`amount`, `expires_at`), the cross-cutting options
    /// (`dual_sig`, `timelock`, `relative_timelock_secs`, `mint`), and
    /// the auction grace period. A quorum is *not* overridable here —
    /// adding attestor governance changes the preset's trust shape, so
    /// it needs the dispute preset (which declares it) or a hand-built
    /// [`EscrowTemplate`].
    pub fn auction(
        initializer: [u8; 32],
        taker: [u8; 32],
        amount: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            kind: TemplateKind::Auction,
            template: EscrowTemplate {
                kind: TemplateKind::Auction,
                initializer,
                taker,
                amount,
                expires_at,
                dual_sig: false,
                timelock: None,
                relative_timelock_secs: None,
                quorum: None,
                mint: None,
                kind_params: KindParams::Auction {
                    grace_period_secs: 0,
                },
            },
            overridable: &[
                "amount",
                "expires_at",
                "dual_sig",
                "timelock",
                "relative_timelock_secs",
                "mint",
                "grace_period_secs",
            ],
        }
    }

    /// The milestone-tranche preset: deliverable-gated release over
    /// `tranches` (audited default: the caller's table, validated like
    /// AV-72). Overridable: the economics, the cross-cutting options,
    /// and the tranche table itself — the conservation check
    /// (tranches sum to `amount`) re-runs after every override.
    pub fn milestone_plan(
        initializer: [u8; 32],
        taker: [u8; 32],
        amount: u64,
        expires_at: u64,
        tranches: &'a [u64],
    ) -> Self {
        Self {
            kind: TemplateKind::MilestonePlan,
            template: EscrowTemplate {
                kind: TemplateKind::MilestonePlan,
                initializer,
                taker,
                amount,
                expires_at,
                dual_sig: false,
                timelock: None,
                relative_timelock_secs: None,
                quorum: None,
                mint: None,
                kind_params: KindParams::MilestonePlan { tranches },
            },
            overridable: &[
                "amount",
                "expires_at",
                "dual_sig",
                "timelock",
                "relative_timelock_secs",
                "mint",
                "tranches",
            ],
        }
    }

    /// The subscription preset: clock-driven periodic payouts with the
    /// caller's cadence (audited default, validated like AV-72).
    /// Overridable: the economics, the cross-cutting options, and the
    /// full cadence triple (`period_secs`, `periods`, `per_period`) —
    /// the conservation check (`periods * per_period == amount`)
    /// re-runs after every override.
    pub fn subscription(
        initializer: [u8; 32],
        taker: [u8; 32],
        amount: u64,
        expires_at: u64,
        period_secs: u64,
        periods: u8,
        per_period: u64,
    ) -> Self {
        Self {
            kind: TemplateKind::Subscription,
            template: EscrowTemplate {
                kind: TemplateKind::Subscription,
                initializer,
                taker,
                amount,
                expires_at,
                dual_sig: false,
                timelock: None,
                relative_timelock_secs: None,
                quorum: None,
                mint: None,
                kind_params: KindParams::Subscription {
                    period_secs,
                    periods,
                    per_period,
                },
            },
            overridable: &[
                "amount",
                "expires_at",
                "dual_sig",
                "timelock",
                "relative_timelock_secs",
                "mint",
                "period_secs",
                "periods",
                "per_period",
            ],
        }
    }

    /// The arbitrated-dispute preset: a single arbiter (audited
    /// default) with no evidence deadline. Overridable: the economics,
    /// the cross-cutting options, the arbiter key, the evidence
    /// deadline — and the quorum: the panel composition is this
    /// preset's declared governance shape (AV-72: "a single arbiter
    /// (or panel, via `quorum`)"), so swapping the single arbiter for
    /// a panel (or back) stays inside the review.
    pub fn arbitrated_dispute(
        initializer: [u8; 32],
        taker: [u8; 32],
        amount: u64,
        expires_at: u64,
        arbiter: [u8; 32],
    ) -> Self {
        Self {
            kind: TemplateKind::ArbitratedDispute,
            template: EscrowTemplate {
                kind: TemplateKind::ArbitratedDispute,
                initializer,
                taker,
                amount,
                expires_at,
                dual_sig: false,
                timelock: None,
                relative_timelock_secs: None,
                quorum: None,
                mint: None,
                kind_params: KindParams::ArbitratedDispute {
                    arbiter,
                    evidence_deadline_secs: None,
                },
            },
            overridable: &[
                "amount",
                "expires_at",
                "dual_sig",
                "timelock",
                "relative_timelock_secs",
                "mint",
                "quorum",
                "arbiter",
                "evidence_deadline_secs",
            ],
        }
    }

    /// AV-77 `apply_template`: apply per-field overrides to the
    /// preset's defaults, run the full template invariant validation
    /// on the effective parameters, build the escrow, and hash the
    /// effective parameters.
    ///
    /// Override rules — every violation is
    /// [`EscrowError::TemplateOverrideRejected`]:
    /// - each override names a field in
    ///   [`TemplatePreset::overridable`]; unknown names and fields
    ///   declared by a *different* preset are rejected;
    /// - the [`OverrideValue`] variant matches the field's declared
    ///   type;
    /// - each field appears at most once.
    ///
    /// After the overrides apply, the effective template runs the full
    /// AV-72 validation — conservation (`ZeroAmount`,
    /// `TrancheSumMismatch`, `InvalidSubscriptionParams`), mutual
    /// exclusion (`ConflictingTimelocks`), timelock-vs-expiry
    /// (`TimelockPastExpiry`), arbiter presence (`MissingArbiter`) —
    /// and then `build`, so builder-level thresholds (quorum policy,
    /// evidence deadline, …) still gate. Template rejections project
    /// onto [`EscrowError`] via the documented mapping; either a
    /// fully-configured [`AppliedTemplate`] or an error — never a
    /// half-applied one. Pure: applying twice with the same overrides
    /// yields the same template, escrow, and hash.
    pub fn apply_template(
        &self,
        overrides: &[(&str, OverrideValue<'a>)],
    ) -> Result<AppliedTemplate<'a>, EscrowError> {
        let template = self.template.apply_overrides(self, overrides)?;
        let params_hash = template.params_hash();
        let escrow = template.build().map_err(map_template_error)?;
        Ok(AppliedTemplate {
            template,
            escrow,
            params_hash,
        })
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
        e.escalate(ALICE, EXPIRES_AT - 1_000, None, None, 0).unwrap();
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

    // ---------- AV-77: preset overrides ----------

    const TRANCHES: &[u64] = &[400_000, 600_000];

    fn auction_preset() -> TemplatePreset<'static> {
        TemplatePreset::auction(ALICE, BOB, AMOUNT, EXPIRES_AT)
    }

    fn subscription_preset() -> TemplatePreset<'static> {
        TemplatePreset::subscription(ALICE, BOB, AMOUNT, EXPIRES_AT, 100, 4, AMOUNT / 4)
    }

    fn milestone_preset() -> TemplatePreset<'static> {
        TemplatePreset::milestone_plan(ALICE, BOB, AMOUNT, EXPIRES_AT, TRANCHES)
    }

    fn dispute_preset() -> TemplatePreset<'static> {
        TemplatePreset::arbitrated_dispute(ALICE, BOB, AMOUNT, EXPIRES_AT, ARBITER)
    }

    #[test]
    fn preset_defaults_apply_clean_with_empty_overrides() {
        // A no-op application is still an application: the preset's
        // audited defaults take effect unchanged.
        for preset in [
            auction_preset(),
            subscription_preset(),
            milestone_preset(),
            dispute_preset(),
        ] {
            let applied = preset.apply_template(&[]).unwrap();
            assert_eq!(applied.template, preset.template);
            assert_eq!(applied.params_hash, preset.template.params_hash());
            assert_eq!(applied.escrow.amount(), AMOUNT);
        }
    }

    #[test]
    fn unknown_override_field_rejected() {
        // A field no preset declares.
        let err = auction_preset()
            .apply_template(&[("bogus_field", OverrideValue::U64(1))])
            .unwrap_err();
        assert_eq!(err, EscrowError::TemplateOverrideRejected);
        // A real field declared by a *different* preset's review: the
        // auction preset does not declare `quorum` overridable.
        let err = auction_preset()
            .apply_template(&[("quorum", OverrideValue::Quorum(None))])
            .unwrap_err();
        assert_eq!(err, EscrowError::TemplateOverrideRejected);
        // Kind-specific fields are not cross-kind: `tranches` is not
        // on the auction surface even though it is a real field.
        let err = auction_preset()
            .apply_template(&[("tranches", OverrideValue::Tranches(&[AMOUNT]))])
            .unwrap_err();
        assert_eq!(err, EscrowError::TemplateOverrideRejected);
    }

    #[test]
    fn mistyped_override_value_rejected() {
        // `amount` takes U64, not Bool.
        let err = auction_preset()
            .apply_template(&[("amount", OverrideValue::Bool(true))])
            .unwrap_err();
        assert_eq!(err, EscrowError::TemplateOverrideRejected);
        // `dual_sig` takes Bool, not U64.
        let err = auction_preset()
            .apply_template(&[("dual_sig", OverrideValue::U64(1))])
            .unwrap_err();
        assert_eq!(err, EscrowError::TemplateOverrideRejected);
        // `periods` takes U8, not U64.
        let err = subscription_preset()
            .apply_template(&[("periods", OverrideValue::U64(4))])
            .unwrap_err();
        assert_eq!(err, EscrowError::TemplateOverrideRejected);
    }

    #[test]
    fn duplicate_override_field_rejected() {
        let err = auction_preset()
            .apply_template(&[
                ("amount", OverrideValue::U64(AMOUNT)),
                ("amount", OverrideValue::U64(AMOUNT)),
            ])
            .unwrap_err();
        assert_eq!(err, EscrowError::TemplateOverrideRejected);
    }

    #[test]
    fn template_override_rejected_is_code_141() {
        // The program error code is a public contract (the Anchor
        // program maps one program error per variant): never renumber.
        assert_eq!(EscrowError::TemplateOverrideRejected.code(), 141);
        assert!(EscrowError::all().contains(&EscrowError::TemplateOverrideRejected));
    }

    #[test]
    fn legal_overrides_take_effect() {
        // Auction: override the grace period and the economics.
        let applied = auction_preset()
            .apply_template(&[
                ("grace_period_secs", OverrideValue::U64(600)),
                ("amount", OverrideValue::U64(2_000_000)),
            ])
            .unwrap();
        assert_eq!(applied.template.amount, 2_000_000);
        assert_eq!(applied.escrow.amount(), 2_000_000);
        assert_eq!(applied.escrow.grace_period(), 600);
        // Subscription: override the whole cadence triple consistently.
        let applied = subscription_preset()
            .apply_template(&[
                ("period_secs", OverrideValue::U64(200)),
                ("periods", OverrideValue::U8(5)),
                ("per_period", OverrideValue::U64(AMOUNT / 5)),
            ])
            .unwrap();
        let schedule = applied.escrow.subscription_schedule().unwrap();
        assert_eq!(schedule.periods, 5);
        assert_eq!(applied.escrow.subscription_period_due_at(0).unwrap(), EXPIRES_AT - 4 * 200);
        // Cross-cutting option: dual-sig gates funding after the
        // override.
        let applied = auction_preset()
            .apply_template(&[("dual_sig", OverrideValue::Bool(true))])
            .unwrap();
        let mut e = applied.escrow;
        assert_eq!(
            e.fund(ALICE, EXPIRES_AT - 3_600),
            Err(EscrowError::InvalidStateTransition)
        );
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        // Dispute preset: the quorum *is* on this preset's surface.
        let applied = dispute_preset()
            .apply_template(&[("quorum", OverrideValue::Quorum(Some(quorum_1_of_2())))])
            .unwrap();
        assert!(applied.template.quorum.is_some());
    }

    #[test]
    fn override_breaking_conservation_rejected() {
        // Tranches no longer sum to the lockup.
        let err = milestone_preset()
            .apply_template(&[("tranches", OverrideValue::Tranches(&[600_000, 300_000]))])
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidMilestones);
        // Shrinking the amount under the default tranches breaks the
        // same conservation law from the other side.
        let err = milestone_preset()
            .apply_template(&[("amount", OverrideValue::U64(AMOUNT - 1))])
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidMilestones);
        // Subscription cadence no longer describes the amount.
        let err = subscription_preset()
            .apply_template(&[("per_period", OverrideValue::U64(AMOUNT / 4 + 1))])
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidSubscription);
        // Zeroing the amount empties the escrow.
        let err = auction_preset()
            .apply_template(&[("amount", OverrideValue::U64(0))])
            .unwrap_err();
        assert_eq!(err, EscrowError::AmountMismatch);
    }

    #[test]
    fn override_breaking_timelock_exclusion_rejected() {
        // One clock per escrow (AV-64): the mutual exclusion re-runs
        // after overrides.
        let err = auction_preset()
            .apply_template(&[
                ("timelock", OverrideValue::OptU64(Some(EXPIRES_AT - 100))),
                (
                    "relative_timelock_secs",
                    OverrideValue::OptU64(Some(3_600)),
                ),
            ])
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidTimelock);
        // A timelock at/after expiry still hands the initializer the
        // front-running option.
        let err = auction_preset()
            .apply_template(&[("timelock", OverrideValue::OptU64(Some(EXPIRES_AT)))])
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidTimelock);
    }

    #[test]
    fn override_breaking_threshold_rejected() {
        // A zero evidence deadline passes template-level validation
        // but the builder rejects it — the state machine's verdict
        // carries through the application (AV-72's InvalidConfiguration
        // projection).
        let err = dispute_preset()
            .apply_template(&[(
                "evidence_deadline_secs",
                OverrideValue::OptU64(Some(0)),
            )])
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidEvidenceDeadline);
        // Subscription periods outside 1..=64.
        let err = subscription_preset()
            .apply_template(&[("periods", OverrideValue::U8(0))])
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidSubscription);
    }

    #[test]
    fn params_hash_is_deterministic_and_sensitive() {
        let preset = subscription_preset();
        let overrides: &[(&str, OverrideValue)] = &[
            ("period_secs", OverrideValue::U64(200)),
            ("periods", OverrideValue::U8(5)),
            ("per_period", OverrideValue::U64(AMOUNT / 5)),
        ];
        let h1 = preset.apply_template(overrides).unwrap().params_hash;
        let h2 = preset.apply_template(overrides).unwrap().params_hash;
        assert_eq!(h1, h2, "same inputs must hash identically");
        // Any effective-parameter change moves the hash …
        let h3 = preset
            .apply_template(&[("period_secs", OverrideValue::U64(201))])
            .unwrap()
            .params_hash;
        assert_ne!(h1, h3);
        // … including the parties and the kind: the same numbers on a
        // different preset are a different commitment.
        let other = TemplatePreset::subscription(MALLORY, BOB, AMOUNT, EXPIRES_AT, 200, 5, AMOUNT / 5);
        assert_ne!(h1, other.apply_template(&[]).unwrap().params_hash);
        // The empty-override hash equals the preset default's own hash.
        assert_eq!(
            preset.apply_template(&[]).unwrap().params_hash,
            preset.template.params_hash()
        );
    }

    #[test]
    fn params_hash_canonical_encoding_is_pinned() {
        // The hash is the TemplateApplied event's commitment: pin the
        // canonical encoding with golden values (computed by the
        // crate's own SHA-256, known-vector tested) so any encoding
        // change breaks loudly — indexers verify these bytes.
        fn hex(h: [u8; 32]) -> String {
            h.iter().map(|b| format!("{b:02x}")).collect()
        }
        let preset =
            TemplatePreset::subscription(ALICE, BOB, 1_000_000, 1_800_000_000, 100, 4, 250_000);
        assert_eq!(
            hex(preset.apply_template(&[]).unwrap().params_hash),
            "95e8d8c5c3a4be72b3ec44b211c33246ae91c362af859b95a59b4c09edda2ad2"
        );
        let preset = TemplatePreset::auction(ALICE, BOB, 1_000_000, 1_800_000_000);
        assert_eq!(
            hex(preset
                .apply_template(&[("grace_period_secs", OverrideValue::U64(600))])
                .unwrap()
                .params_hash),
            "87a0708ee79e9615d8c58dffcb2a94521eb3c94fca196ce224424c5a6bcbd7f3"
        );
    }

    #[test]
    fn apply_template_is_idempotent() {
        // Applying twice is the same application: same effective
        // template, same escrow configuration, same hash — no shared
        // mutable state between applications.
        let preset = auction_preset();
        let overrides: &[(&str, OverrideValue)] =
            &[("grace_period_secs", OverrideValue::U64(600))];
        let a = preset.apply_template(overrides).unwrap();
        let b = preset.apply_template(overrides).unwrap();
        assert_eq!(a.template, b.template);
        assert_eq!(a.params_hash, b.params_hash);
        assert_eq!(a.escrow.amount(), b.escrow.amount());
        assert_eq!(a.escrow.grace_period(), b.escrow.grace_period());
    }
}