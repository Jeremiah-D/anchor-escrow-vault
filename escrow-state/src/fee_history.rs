//! Keeper-side protocol-fee revenue history view (AV-144).
//!
//! [`FeeHistoryView`] folds an [`IndexedEscrow`]'s event stream into
//! per-(vault, day) protocol-fee totals, split by fee type
//! ([`FeeType`]: release / claim / resolve / streaming / arbiter).
//! The keeper/indexer consumes it for protocol-revenue reporting —
//! which fee types earned, on which vaults, on which days — and
//! exports the daily rollup as deterministic JSON
//! ([`FeeHistoryView::to_json`], [`FeeHistoryReport::to_json`]).
//! Pure logic, zero dependencies.
//!
//! # Fee model
//!
//! The state machine charges two protocol-fee legs on taker payouts
//! (see [`Escrow::charge_protocol_fee`],
//! [`Escrow::charge_streaming_fee`]):
//!
//! * the AV-17 bps fee (flat `fee_bps` or the AV-66 tiered schedule,
//!   AV-63 capped) — accumulated in the unified
//!   [`Escrow::fees_paid`] counter;
//! * the AV-100 streaming fee (`rate` lamports per funded second,
//!   folded into the same `fee` leg) — accumulated in
//!   [`Escrow::fees_paid`] too, with the
//!   [`Escrow::streaming_fees_accrued`] sub-counter tracking the
//!   streaming slice.
//!
//! The event's `amounts.fee` is the *combined* leg (bps + streaming),
//! so the fold recovers the split per event: `streaming = fee -
//! protocol_fee_for(gross)`, where `protocol_fee_for` is the same pure
//! function the state machine charges with. Fee configuration is
//! initialize-time only (builders), so the recomputation matches the
//! charge bit-for-bit; `saturating_sub` guards the impossible.
//!
//! The AV-135 arbiter adjudication fee is a *separate* leg
//! (`amounts.arbiter_fee` on the resolve-family settlement events),
//! never folded into `fees_paid` — the deduction order is bps fee,
//! streaming fee, arbiter fee, all slicing the taker's share.
//!
//! # Fold semantics
//!
//! Every [`EscrowEventKind`] maps to an optional [`FeeType`] (see
//! [`fee_kind`] — the match is exhaustive, so a future variant fails
//! to compile until its fee semantics are decided, never silently
//! mis-booked; the convention mirrors
//! [`event_sourcing::fund_delta`](crate::event_sourcing)):
//!
//! * Taker payouts (`Released`, `ReleasedSplit`, `ReleaseViaIntent`,
//!   `DualControlConfirmed`, `MilestoneReleased`,
//!   `SubscriptionPeriodReleased`, `BasketReleased`, `EscrowsNetted`)
//!   book the bps slice as [`FeeType::Release`];
//! * `Claimed` books it as [`FeeType::Claim`];
//! * Dispute settlements (`Resolved`, `DefaultJudgment`,
//!   `PanelResolved`) book it as [`FeeType::Resolve`] and the
//!   `arbiter_fee` leg as [`FeeType::Arbiter`];
//! * Everything else books nothing — votes, governance, pauses,
//!   disclosures, refunds, and the two summary events
//!   (`BundlePartiallyExecuted` re-states already-booked tranche
//!   fees; `VaultsBatchClosed` re-states rent, which sits outside the
//!   fee legs).
//!
//! Days are Unix days (`event.at / 86_400`, UTC) — the keeper's
//! revenue-reporting grain. The daily map is a `BTreeMap`, so the JSON
//! export iterates days in ascending order (deterministic).
//!
//! # Snapshot base + incremental apply
//!
//! [`FeeHistoryView::from_snapshot`] seeds a view from a snapshot
//! taken at `snapshot_seq`; [`FeeHistoryView::apply`] then folds the
//! later events. Three honest limitations (never fabricated):
//!
//! * The snapshot carries no per-type bps counters — only the unified
//!   `fees_paid` and the `streaming_fees_accrued` sub-counter — so the
//!   base seeds `streaming` exactly (the snapshot.rs pass-through)
//!   and counts the bps types (`release` / `claim` / `resolve`) from
//!   the snapshot point on (the [`MaterializedView`]`refunded = 0`
//!   precedent).
//! * The snapshot carries no cumulative arbiter-fee counter at all
//!   (the state machine never kept one — the event stream is the only
//!   record), so `arbiter` is counted from the snapshot point on too.
//! * Pre-snapshot fees have no day attribution (the snapshot doesn't
//!   say which days they were charged on), so the daily map starts
//!   empty — `totals` includes the seeded streaming base, the daily
//!   map doesn't.
//!
//! # Reconciliation
//!
//! [`FeeHistoryView::reconcile`] cross-checks the fold against the
//! live state machine's counters: `release + claim + resolve +
//! streaming == escrow.fees_paid()` and `streaming ==
//! escrow.streaming_fees_accrued()`, bit-identical on a genesis replay.
//! (The arbiter leg has no state counter — the event stream is the
//! system of record.)
//!
//! [`EscrowEvent`]: crate::EscrowEvent
//! [`EscrowEventKind`]: crate::EscrowEventKind
//! [`IndexedEscrow`]: crate::events::IndexedEscrow
//! [`MaterializedView`]: crate::event_sourcing::MaterializedView
//! [`Escrow`]: crate::Escrow
//! [`Escrow::charge_protocol_fee`]: crate::Escrow::charge_protocol_fee
//! [`Escrow::charge_streaming_fee`]: crate::Escrow::charge_streaming_fee
//! [`Escrow::fees_paid`]: crate::Escrow::fees_paid
//! [`Escrow::streaming_fees_accrued`]: crate::Escrow::streaming_fees_accrued

use crate::events::{EscrowEvent, EscrowEventKind, IndexedEscrow};
use crate::snapshot::EscrowSnapshot;
use crate::{Escrow, EscrowError, FeeSchedule, FeeTier, MAX_FEE_TIERS};
use std::collections::BTreeMap;

/// Seconds per UTC day — the revenue-reporting grain.
const SECS_PER_DAY: u64 = 86_400;

/// Protocol-fee type categories (AV-144).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeeType {
    /// AV-17 bps fee slice on a taker release (release, milestone,
    /// subscription-period, basket-leg, netting and intent /
    /// dual-control release paths).
    Release,
    /// AV-17 bps fee slice on a vesting claim.
    Claim,
    /// AV-17 bps fee slice on a dispute settlement (resolve, default
    /// judgment, panel settlement).
    Resolve,
    /// AV-100 streaming-fee slice (folded into the payout's `fee`
    /// leg; recovered per event, see [`FeeHistoryView`]).
    Streaming,
    /// AV-135 arbiter adjudication fee (the separate `arbiter_fee`
    /// leg on resolve-family settlements).
    Arbiter,
}

impl FeeType {
    /// Canonical lowercase name, used in JSON-adjacent contexts.
    pub fn name(self) -> &'static str {
        match self {
            FeeType::Release => "release",
            FeeType::Claim => "claim",
            FeeType::Resolve => "resolve",
            FeeType::Streaming => "streaming",
            FeeType::Arbiter => "arbiter",
        }
    }

    /// All fee types, in canonical order.
    pub const ALL: [FeeType; 5] = [
        FeeType::Release,
        FeeType::Claim,
        FeeType::Resolve,
        FeeType::Streaming,
        FeeType::Arbiter,
    ];
}

/// Which fee type (if any) an event kind's `fee` leg belongs to.
///
/// The match is exhaustive on purpose: a future variant fails to
/// compile here until its fee semantics are decided (never silently
/// mis-booked). Pinned by
/// `fee_history_tests::fee_kind_covers_every_kind`.
fn fee_kind(kind: EscrowEventKind) -> Option<FeeType> {
    match kind {
        // Taker payouts — the bps slice of the fee leg is a release fee.
        EscrowEventKind::Released
        | EscrowEventKind::ReleasedSplit
        // AV-123: an intent-driven release fees like Released.
        | EscrowEventKind::ReleaseViaIntent
        // AV-130: a checker-approved release fees like Released.
        | EscrowEventKind::DualControlConfirmed
        | EscrowEventKind::MilestoneReleased
        // AV-229: a partial slice fees like a full tranche
        // release — the slice's fee leg is a release fee.
        | EscrowEventKind::MilestonePartiallyClaimed
        | EscrowEventKind::SubscriptionPeriodReleased
        // AV-95b: the per-leg taker payout fees like Released.
        // AV-140: the netting offset fees like Released (the fee leg
        // is zero on netting settlements, but the kind is a payout
        // kind).
        | EscrowEventKind::BasketReleased
        | EscrowEventKind::EscrowsNetted => Some(FeeType::Release),
        // Vesting claims.
        EscrowEventKind::Claimed => Some(FeeType::Claim),
        // AV-149: one claimant's leg fees like a vesting claim — the
        // AV-17 protocol fee slices the leg's gross.
        EscrowEventKind::ShareClaimed => Some(FeeType::Claim),
        // Dispute settlements — the fee slices the taker's share.
        EscrowEventKind::Resolved
        | EscrowEventKind::DefaultJudgment
        | EscrowEventKind::PanelResolved => Some(FeeType::Resolve),
        // Everything else carries no fee leg: pure state flips,
        // governance, votes, disclosures, refunds, rent movements,
        // and the two summary events (`BundlePartiallyExecuted`
        // re-states already-booked tranche fees; `VaultsBatchClosed`
        // re-states rent, which sits outside the fee legs).
        EscrowEventKind::Initialized
        | EscrowEventKind::Activated
        | EscrowEventKind::Funded
        | EscrowEventKind::Cancelled
        | EscrowEventKind::ExpiredCancelled
        | EscrowEventKind::Attested
        | EscrowEventKind::Escalated
        | EscrowEventKind::MilestoneConfirmed
        | EscrowEventKind::MilestoneSkipped
        // AV-232: restoring a skipped tranche carries no fee leg.
        | EscrowEventKind::MilestoneUnskipped
        // AV-203: a delivery confirmation carries no fee leg.
        | EscrowEventKind::DeliveryConfirmed
        // AV-223: chain link / break carry no fee leg.
        | EscrowEventKind::ChainLinked
        | EscrowEventKind::ChainBroken
        | EscrowEventKind::QuorumUpdated
        | EscrowEventKind::AttestorsUpdated
        // AV-154: a quorum key rotation moves no funds.
        | EscrowEventKind::AttestorReplaced
        // AV-155: a milestone repricing moves no funds.
        | EscrowEventKind::MilestonesAmended
        | EscrowEventKind::MilestonesReallocated
        // AV-225: an expired claim carries no fee leg.
        | EscrowEventKind::MilestoneClaimExpired
        // AV-226: an appended tranche carries no fee leg.
        | EscrowEventKind::MilestoneTrancheAppended
        // AV-227: an amended roster carries no fee leg.
        | EscrowEventKind::ClaimantRosterAmended
        // AV-230: a revised schedule carries no fee leg.
        | EscrowEventKind::VestingScheduleAmended
        // AV-231: a revised deadline table moves no funds — the new
        // dates price late penalties only at the later releases.
        | EscrowEventKind::MilestoneDueDatesAmended
        // AV-233: a revised fee rate carries no fee leg.
        | EscrowEventKind::ProtocolFeeAmended
        // AV-234: a rotated verifier carries no fee leg.
        | EscrowEventKind::MilestoneVerifierRotated
        // AV-235: a revised arbiter fee carries no fee leg itself.
        | EscrowEventKind::ArbiterFeeAmended
        // AV-236: a revised appeal window carries no fee leg itself.
        | EscrowEventKind::AppealWindowAmended
        // AV-237: a revised slash ladder carries no fee leg itself.
        | EscrowEventKind::SlashLadderAmended
        // AV-238: a revised appeal bond carries no fee leg itself.
        | EscrowEventKind::AppealBondAmended
        // AV-240: a revised grace period carries no fee leg itself.
        | EscrowEventKind::GracePeriodAmended
        // AV-241: a revised evidence deadline carries no fee leg itself.
        | EscrowEventKind::EvidenceDeadlineAmended
        // AV-242: a revised arbitration deadline moves no funds —
        // the new deadline gates only the later disputes'
        // default judgments.
        | EscrowEventKind::ArbitrationDeadlineAmended
        // AV-243: a revised claim cooldown moves no funds —
        // the next claim's eligibility is recomputed from the
        // amended cooldown.
        | EscrowEventKind::ClaimCooldownAmended
        // AV-244: a revised delivery deadline moves no funds —
        // confirmations after the amendment are judged against
        // the new deadline; an already-confirmed delivery keeps
        // its first-won stamp.
        | EscrowEventKind::DeliveryDeadlineAmended
        // AV-245: a revised late-delivery penalty rate moves no
        // funds — a late-stamped but unreleased delivery reprices
        // at the new rate; already-released amounts are untouched.
        | EscrowEventKind::LateDeliveryPenaltyAmended
        // AV-246: a revised release cooling window moves no
        // funds — a live announced intent is re-measured against
        // the new window; a vetoed intent stays vetoed.
        | EscrowEventKind::ReleaseCoolingAmended
        // AV-247: a revised milestone claim deadline moves no
        // funds — the claim gate re-reads the deadline live;
        // already-claimed or skipped tranches keep settlements.
        | EscrowEventKind::MilestoneClaimDeadlineAmended
        // AV-248: a revised per-extension cap moves no
        // funds — the next extension is judged against the live
        // cap; already-made extensions keep deadline and count.
        | EscrowEventKind::MaxExtensionAmended
        // AV-249: a revised absolute timelock moves no
        // funds — the payout gates re-read the live lock;
        // already-released amounts are never restated.
        | EscrowEventKind::TimelockAmended
        // AV-250: a revised relative timelock moves no
        // funds — the payout gates re-read the live window
        // against the unchanged funding anchor; already-released
        // amounts are never restated.
        | EscrowEventKind::RelativeTimelockAmended
        // AV-251: a revised slot timelock moves no
        // funds — the slot gates re-read the live window
        // against the unchanged funding slot; already-released
        // amounts are never restated.
        | EscrowEventKind::SlotTimelockAmended
        // AV-252: a revised rent sweep grace moves no
        // funds — the sweep gate re-reads the live grace
        // against the unchanged terminal timestamp; a sweep
        // already performed is never undone.
        | EscrowEventKind::RentSweepGraceAmended
        // AV-253: a revised fee schedule moves no
        // funds — later payouts reprice live from the amended
        // schedule; fees already charged or withdrawn are never
        // restated.
        | EscrowEventKind::FeeScheduleAmended
        // AV-254: a revised streaming fee rate moves no
        // funds — the charge gate re-reads the live rate
        // against the unchanged fund_at anchor; fees
        // already charged are never clawed back.
        | EscrowEventKind::StreamingFeeRateAmended
        // AV-255: a revised rent payer moves no
        // funds — the close reads the recipient live
        // through the amended payer; the close
        // authority is untouched and no rent is
        // recomputed.
        | EscrowEventKind::RentPayerAmended
        // AV-256: a revised referrer moves no
        // funds — the release gate re-reads the live
        // binding at every payout; referral already
        // charged is never clawed back.
        | EscrowEventKind::ReferrerAmended
        // AV-257: a revised escalation schedule moves
        // no funds — the cancel gate re-reads the live
        // schedule at every cancel_expired; a cancel
        // already settled keeps its penalty.
        | EscrowEventKind::PenaltyEscalationAmended
        // AV-258: a revised refund address moves
        // no funds — the cancel paths re-read the live
        // address at every cancel / cancel_expired; a refund
        // already settled keeps its destination.
        | EscrowEventKind::RefundAddressAmended
        // AV-259: a revised base penalty rate moves
        // no funds — the cancel gate re-reads the live base
        // rate at every cancel_expired; a cancel already
        // settled keeps its penalty.
        | EscrowEventKind::BasePenaltyAmended
        // AV-260: a revised interest rate moves no
        // funds — the accrual clock re-reads the live
        // rate at every settlement; a slice already
        // settled keeps its rate and accrued yield is
        // never clawed back.
        | EscrowEventKind::InterestRateAmended
        // AV-261: a revised price gate moves no
        // funds — the gated payout paths re-read the
        // live gate at every release / claim; a payout
        // already settled keeps its gate.
        | EscrowEventKind::PriceGateAmended
        // AV-262: a revised TWAP gate moves no
        // funds — the gated payout paths re-read the
        // live gate at every release / claim (including
        // the full-window history coverage requirement);
        // a payout already settled keeps its gate.
        | EscrowEventKind::TwapGateAmended
        // AV-263: a rotated dual-control checker moves no
        // funds — the two-step protocol authenticates the
        // next confirm against the live checker; a live
        // intent blocks the rotation, so no approval power
        // is ever transferred mid-flight.
        | EscrowEventKind::DualControlCheckerRotated
        // AV-264: a rotated credential-gate issuer moves no
        // funds — the gate verifies the next credentialed
        // release against the live issuer; an old-issuer
        // credential stops verifying at rotation, while a
        // release already settled keeps its issuer.
        | EscrowEventKind::CredentialIssuerRotated
        // AV-265: a revised dead-man's inactivity threshold
        // moves no funds — the eligibility gate judges the
        // unchanged elapsed time against the live threshold
        // at the next claim; a claim already settled keeps
        // the threshold it settled under.
        | EscrowEventKind::DeadmanInactivityAmended
        // AV-266: a revised keeper-bounty per-crank amount moves
        // no funds and never tops the pool up — the next crank
        // pays min(new per_crank, pool) from the live amount,
        // while a crank already settled keeps its amount.
        | EscrowEventKind::KeeperBountyPerCrankAmended
        // AV-267: a revised flat slash deadline moves no funds
        // and never restates a settled penalty — the slash path
        // reads the live deadline at the next eligibility check,
        // while a slash already settled keeps its deadline.
        | EscrowEventKind::SlashDeadlineAmended
        // AV-158: delayed-governance lifecycle events move no funds.
        | EscrowEventKind::GovernanceProposed
        | EscrowEventKind::GovernanceExecuted
        | EscrowEventKind::GovernanceCancelled
        | EscrowEventKind::EmergencyUnlock
        | EscrowEventKind::VaultClosed
        | EscrowEventKind::ReentryRejected
        | EscrowEventKind::Paused
        | EscrowEventKind::Unpaused
        | EscrowEventKind::PauseAuthorityRotated
        | EscrowEventKind::ExpiredCranked
        | EscrowEventKind::PayoutAllowlistUpdated
        | EscrowEventKind::TakerRotated
        | EscrowEventKind::InitializerRotated
        | EscrowEventKind::ExpiryExtended
        | EscrowEventKind::PartiallyCancelled
        | EscrowEventKind::ArbiterRotated
        // A panel vote moves no funds — and `PanelJudgment`'s amounts
        // are the *voted* split, not an executed one (the
        // `event_sourcing` PanelJudgment rule); only the settling
        // `PanelResolved` fees.
        | EscrowEventKind::PanelJudgment
        | EscrowEventKind::FeeRecipientRotated
        | EscrowEventKind::EvidenceSubmitted
        | EscrowEventKind::PanelThresholdChanged
        | EscrowEventKind::MilestonesAdjusted
        | EscrowEventKind::SubscriptionAmountsAdjusted
        | EscrowEventKind::SchemaMigrated
        | EscrowEventKind::BundlePartiallyExecuted
        | EscrowEventKind::TemplateApplied
        | EscrowEventKind::VaultsBatchClosed
        | EscrowEventKind::EscrowSplit
        | EscrowEventKind::Slashed
        | EscrowEventKind::CpiAllowlistUpdated
        | EscrowEventKind::AppealFiled
        | EscrowEventKind::AppealResolved
        | EscrowEventKind::EvidenceFiled
        | EscrowEventKind::BasketCancelled
        | EscrowEventKind::BasketExpiredCancelled
        | EscrowEventKind::DenylistUpdated
        | EscrowEventKind::AppealExpired
        | EscrowEventKind::DelegationGranted
        | EscrowEventKind::DelegationRevoked
        | EscrowEventKind::SwapLinked
        | EscrowEventKind::DeadmanClaimed
        | EscrowEventKind::RentToppedUp
        | EscrowEventKind::TrancheFunded
        | EscrowEventKind::ReleaseIntentAnnounced
        | EscrowEventKind::ReleaseIntentVetoed
        | EscrowEventKind::EscrowsMerged
        | EscrowEventKind::Declined
        | EscrowEventKind::CounterOfferProposed
        | EscrowEventKind::CounterOfferAccepted
        | EscrowEventKind::CounterOfferRejected
        | EscrowEventKind::KeeperBountyPaid
        | EscrowEventKind::PartialRefunded
        | EscrowEventKind::DualControlInitiated
        | EscrowEventKind::DualControlCancelled
        // AV-137: a blind commit moves no funds; a reveal's amounts
        // are the *revealed* split, not an executed one (the
        // PanelJudgment rule) — only the settling `PanelResolved`
        // fees.
        | EscrowEventKind::JudgmentCommitted
        | EscrowEventKind::JudgmentRevealed
        | EscrowEventKind::RentSwept
        // AV-148: the taker's counter-fund is pure deposit
        // bookkeeping — no fee leg.
        // AV-150: freezing / restarting the vesting unlock clock
        // moves no funds — no fee leg.
        // AV-174: a protocol-fee withdrawal carries no *new* fee leg
        // — the fee was already attributed at payout time; the
        // extraction is tracked by `fees_withdrawn`, not re-booked.
        | EscrowEventKind::VestingPaused
        | EscrowEventKind::VestingResumed
        | EscrowEventKind::FeeWithdrawn
        | EscrowEventKind::TakerFunded => None,
    }
}

/// Per-type fee totals: the five AV-144 fee categories.
///
/// Sums are plain `u64` per vault (each leg is `<=` its gross payout,
/// and gross payouts cumulatively cap at `u64::MAX` — the same
/// argument that keeps `Escrow::fees_paid` in `u64`); booking uses
/// saturating adds so the fold never panics on an adversarial log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FeeTypeTotals {
    /// AV-17 bps fee on taker releases.
    pub release: u64,
    /// AV-17 bps fee on vesting claims.
    pub claim: u64,
    /// AV-17 bps fee on dispute settlements.
    pub resolve: u64,
    /// AV-100 streaming-fee slice.
    pub streaming: u64,
    /// AV-135 arbiter adjudication fee.
    pub arbiter: u64,
}

impl FeeTypeTotals {
    /// Book `amount` into one fee type (saturating).
    pub fn add(&mut self, fee_type: FeeType, amount: u64) {
        let slot = match fee_type {
            FeeType::Release => &mut self.release,
            FeeType::Claim => &mut self.claim,
            FeeType::Resolve => &mut self.resolve,
            FeeType::Streaming => &mut self.streaming,
            FeeType::Arbiter => &mut self.arbiter,
        };
        *slot = slot.saturating_add(amount);
    }

    /// Read one fee type's total.
    pub fn get(&self, fee_type: FeeType) -> u64 {
        match fee_type {
            FeeType::Release => self.release,
            FeeType::Claim => self.claim,
            FeeType::Resolve => self.resolve,
            FeeType::Streaming => self.streaming,
            FeeType::Arbiter => self.arbiter,
        }
    }

    /// Fold another totals struct in (saturating) — the fleet rollup.
    pub fn add_totals(&mut self, other: &FeeTypeTotals) {
        for fee_type in FeeType::ALL {
            self.add(fee_type, other.get(fee_type));
        }
    }

    /// The three AV-17 bps legs (release + claim + resolve).
    pub fn bps_total(&self) -> u64 {
        self.release
            .saturating_add(self.claim)
            .saturating_add(self.resolve)
    }

    /// All five legs. `u128`: a fleet rollup can exceed `u64`.
    pub fn grand_total_u128(&self) -> u128 {
        self.release as u128
            + self.claim as u128
            + self.resolve as u128
            + self.streaming as u128
            + self.arbiter as u128
    }

    /// Deterministic JSON object with the five legs in canonical
    /// order: `{"release":…,"claim":…,"resolve":…,"streaming":…,"arbiter":…}`.
    fn to_json(&self) -> String {
        let mut s = String::with_capacity(96);
        s.push_str("{\"release\":");
        s.push_str(&self.release.to_string());
        s.push_str(",\"claim\":");
        s.push_str(&self.claim.to_string());
        s.push_str(",\"resolve\":");
        s.push_str(&self.resolve.to_string());
        s.push_str(",\"streaming\":");
        s.push_str(&self.streaming.to_string());
        s.push_str(",\"arbiter\":");
        s.push_str(&self.arbiter.to_string());
        s.push('}');
        s
    }
}

/// The fee-pricing configuration captured at view construction.
///
/// Mirrors [`Escrow::protocol_fee_for`] — the single fee-computation
/// point — so the fold's per-event streaming split matches the state
/// machine's charge bit-for-bit. Kept in sync by
/// `fee_history_tests::pricer_matches_escrow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FeePricer {
    fee_bps: u16,
    fee_cap: u64,
    schedule: FeeSchedule,
}

impl FeePricer {
    fn from_escrow(escrow: &Escrow) -> Self {
        Self {
            fee_bps: escrow.fee_bps(),
            fee_cap: escrow.fee_cap(),
            schedule: escrow.fee_schedule(),
        }
    }

    fn from_snapshot(snapshot: &EscrowSnapshot) -> Self {
        let mut schedule = FeeSchedule::default();
        if let Some(snap) = &snapshot.fee_schedule {
            let n = (snap.tier_count as usize)
                .min(MAX_FEE_TIERS)
                .min(snap.tiers.len());
            schedule.tier_count = n as u8;
            for (i, tier) in snap.tiers.iter().take(n).enumerate() {
                schedule.tiers[i] = FeeTier {
                    min_amount: tier.min_amount,
                    bps: tier.bps,
                };
            }
        }
        Self {
            fee_bps: snapshot.fee_bps,
            fee_cap: snapshot.fee_cap,
            schedule,
        }
    }

    /// Mirror of [`Escrow::protocol_fee_for`].
    ///
    /// [`Escrow::protocol_fee_for`]: crate::Escrow::protocol_fee_for
    fn protocol_fee_for(&self, amount: u64) -> u64 {
        let rate = if self.schedule.is_configured() {
            self.schedule.bps_for(amount)
        } else {
            self.fee_bps
        };
        let bps_fee = ((amount as u128 * rate as u128) / 10_000u128) as u64;
        if self.fee_cap > 0 {
            bps_fee.min(self.fee_cap)
        } else {
            bps_fee
        }
    }
}

/// Render 32 bytes as 64 lowercase hex characters (the keeper.rs
/// `hex32` convention, local copy).
fn hex64(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Single-vault protocol-fee revenue history: the fold cursor over
/// one escrow's [`EscrowEvent`] stream.
///
/// Build it either from genesis ([`Self::from_indexed`]) or from a
/// snapshot base ([`Self::from_snapshot`]) plus [`Self::apply`] for
/// the later events. `apply` enforces strict `seq` continuity — see
/// the module docs.
///
/// [`EscrowEvent`]: crate::EscrowEvent
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeHistoryView {
    escrow_id: [u8; 32],
    totals: FeeTypeTotals,
    /// Per-day rollup (`day = event.at / 86_400`), ascending — the
    /// keeper's revenue-reporting grain.
    daily: BTreeMap<u64, FeeTypeTotals>,
    pricer: FeePricer,
    /// The `seq` the next applied event must carry. Genesis is 0;
    /// after `from_snapshot(_, _, k)` it is `k + 1`.
    next_seq: u64,
}

impl FeeHistoryView {
    /// Pure genesis replay: fold every event of an indexed escrow
    /// from `seq` 0.
    pub fn from_indexed(escrow: &IndexedEscrow) -> Result<Self, EscrowError> {
        let mut view = Self {
            escrow_id: escrow.escrow_id(),
            totals: FeeTypeTotals::default(),
            daily: BTreeMap::new(),
            pricer: FeePricer::from_escrow(escrow.inner()),
            next_seq: 0,
        };
        view.apply(escrow.events())?;
        Ok(view)
    }

    /// Seed a view from a snapshot taken at `snapshot_seq`, then fold
    /// later events with [`Self::apply`].
    ///
    /// The snapshot's `streaming_fees_accrued` sub-counter passes
    /// through as the `streaming` base (exact); the bps types and
    /// `arbiter` start at zero and are counted from the snapshot
    /// point on — the snapshot carries no per-type bps counters and
    /// no cumulative arbiter counter (see the module docs). The daily
    /// map starts empty: pre-snapshot fees have no day attribution.
    pub fn from_snapshot(
        escrow_id: [u8; 32],
        snapshot: &EscrowSnapshot,
        snapshot_seq: u64,
    ) -> Self {
        let mut totals = FeeTypeTotals::default();
        totals.streaming = snapshot.streaming_fees_accrued;
        Self {
            escrow_id,
            totals,
            daily: BTreeMap::new(),
            pricer: FeePricer::from_snapshot(snapshot),
            next_seq: snapshot_seq.saturating_add(1),
        }
    }

    /// Fold a `seq`-continuous event slice into the view.
    ///
    /// Every event must carry this view's `escrow_id` and the exact
    /// expected `seq` (`next_seq`, `next_seq + 1`, …). On the first
    /// break — a gap, an out-of-order or duplicate `seq`, or a foreign
    /// `escrow_id` — the fold stops and returns
    /// [`EscrowError::GapInEventStream`]; the valid prefix stays
    /// applied and [`Self::next_seq`] advances past it, so the caller
    /// resumes by backfilling from `next_seq`.
    ///
    /// Booking uses saturating arithmetic: the fold never panics on
    /// an adversarial log (a well-formed emitter never overflows —
    /// each fee leg is `<=` its gross payout).
    pub fn apply(&mut self, events: &[EscrowEvent]) -> Result<(), EscrowError> {
        // Local pricer copy: `self.pricer` is `Copy`, and borrowing
        // it across the `self.book` mutable borrows would fight the
        // borrow checker.
        let pricer = self.pricer;
        let mut want = self.next_seq;
        for event in events.iter() {
            if event.escrow_id != self.escrow_id || event.seq != want {
                // Stop at the break: the valid prefix stays applied,
                // and the cursor has already advanced past it, so the
                // caller resumes by backfilling from `next_seq`.
                self.next_seq = want;
                return Err(EscrowError::GapInEventStream);
            }
            self.apply_event(pricer, event);
            want = match want.checked_add(1) {
                Some(w) => w,
                // Unreachable in practice (a stream can never hold
                // 2^64 events), but a wrap must not become a silent
                // accept: pin the cursor at the top and report the
                // break, sealing the view.
                None => {
                    self.next_seq = u64::MAX;
                    return Err(EscrowError::GapInEventStream);
                }
            };
        }
        self.next_seq = want;
        Ok(())
    }

    /// Book one event's fee legs.
    fn apply_event(&mut self, pricer: FeePricer, event: &EscrowEvent) {
        let day = event.at / SECS_PER_DAY;
        if event.amounts.fee > 0 {
            if let Some(fee_type) = fee_kind(event.kind) {
                // The event's fee leg is bps + streaming (both fold
                // into `fee` at charge time); recover the split. The
                // bps leg is `fee - streaming` (not the recomputed
                // bps directly) so `bps + streaming == fee` holds
                // exactly even under hypothetical config drift.
                let bps = pricer.protocol_fee_for(event.amounts.payout);
                let streaming = event.amounts.fee.saturating_sub(bps);
                let bps_only = event.amounts.fee - streaming;
                self.book(day, fee_type, bps_only);
                self.book(day, FeeType::Streaming, streaming);
            }
            // `fee > 0` on a non-fee kind: the emitter never produces
            // this (pinned by `fee_kind_covers_every_kind`); the fold
            // does not invent a bucket for it.
        }
        // The arbiter leg only rides resolve-family settlements (the
        // emitter never sets it elsewhere); book it wherever it
        // appears so no fee is ever dropped.
        if event.amounts.arbiter_fee > 0 {
            self.book(day, FeeType::Arbiter, event.amounts.arbiter_fee);
        }
    }

    /// Book `amount` into one fee type, in the totals and the day
    /// bucket. Zero amounts book nothing (a day with no fees never
    /// appears in the rollup).
    fn book(&mut self, day: u64, fee_type: FeeType, amount: u64) {
        if amount == 0 {
            return;
        }
        self.totals.add(fee_type, amount);
        self.daily.entry(day).or_default().add(fee_type, amount);
    }

    /// The vault this view folds.
    pub fn escrow_id(&self) -> [u8; 32] {
        self.escrow_id
    }

    /// Cumulative per-type fee totals.
    pub fn totals(&self) -> FeeTypeTotals {
        self.totals
    }

    /// The per-day rollup, ascending by day.
    pub fn daily(&self) -> &BTreeMap<u64, FeeTypeTotals> {
        &self.daily
    }

    /// One day's fee totals, if the vault earned fees that day.
    pub fn day(&self, day: u64) -> Option<FeeTypeTotals> {
        self.daily.get(&day).copied()
    }

    /// The `seq` the next [`Self::apply`] expects: one past the last
    /// consumed event (`0` on a fresh genesis replay, `snapshot_seq +
    /// 1` on a fresh snapshot base).
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Cross-check the fold against the live state machine's
    /// counters. On a genesis replay both legs match bit-for-bit; on
    /// a snapshot base only the streaming leg is exact (the bps types
    /// count from the snapshot point on — see the module docs).
    pub fn reconcile(&self, escrow: &Escrow) -> FeeReconciliation {
        let view_fees_paid = self.totals.bps_total().saturating_add(self.totals.streaming);
        let state_fees_paid = escrow.fees_paid();
        FeeReconciliation {
            view_fees_paid,
            state_fees_paid,
            fees_paid_match: view_fees_paid == state_fees_paid,
            view_streaming: self.totals.streaming,
            state_streaming: escrow.streaming_fees_accrued(),
            streaming_match: self.totals.streaming == escrow.streaming_fees_accrued(),
        }
    }

    /// Deterministic JSON: `{"escrow_id":"…","totals":{…},"daily":[{"day":…,"fees":{…}},…],"next_seq":…}`.
    /// Days ascend (`BTreeMap`); object keys are in canonical order.
    /// Hand-written, no allocator surprises beyond the output
    /// string — the keeper.rs convention.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(128 + self.daily.len() * 128);
        s.push_str("{\"escrow_id\":\"");
        s.push_str(&hex64(&self.escrow_id));
        s.push_str("\",\"totals\":");
        s.push_str(&self.totals.to_json());
        s.push_str(",\"daily\":[");
        for (i, (day, totals)) in self.daily.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"day\":");
            s.push_str(&day.to_string());
            s.push_str(",\"fees\":");
            s.push_str(&totals.to_json());
            s.push('}');
        }
        s.push_str("],\"next_seq\":");
        s.push_str(&self.next_seq.to_string());
        s.push('}');
        s
    }
}

/// The outcome of [`FeeHistoryView::reconcile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeReconciliation {
    /// The view's `release + claim + resolve + streaming` total.
    pub view_fees_paid: u64,
    /// The state machine's unified [`Escrow::fees_paid`] counter.
    pub state_fees_paid: u64,
    /// Whether they match bit-for-bit.
    pub fees_paid_match: bool,
    /// The view's streaming total.
    pub view_streaming: u64,
    /// The state machine's [`Escrow::streaming_fees_accrued`]
    /// sub-counter.
    pub state_streaming: u64,
    /// Whether they match bit-for-bit.
    pub streaming_match: bool,
}

impl FeeReconciliation {
    /// True when both legs reconcile — the fold agrees with the
    /// state machine bit-for-bit.
    pub fn ok(&self) -> bool {
        self.fees_paid_match && self.streaming_match
    }
}

/// Fleet-wide protocol-fee revenue report (AV-144): per-vault views
/// plus the fleet rollup, for keeper/indexer revenue reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeHistoryReport {
    /// The `now` (Unix seconds) the scan ran at.
    at: u64,
    /// How many escrows were scanned.
    scanned: usize,
    /// Per-vault views, in scan order. Vaults whose event stream was
    /// gappy are *not* here — see `skipped`.
    views: Vec<FeeHistoryView>,
    /// Vaults skipped because their event stream broke `seq`
    /// continuity — a partial revenue view would mislead, so the
    /// operator sees the gap explicitly instead.
    skipped: Vec<[u8; 32]>,
    /// Fleet-wide per-type totals (over `views` only).
    fleet: FeeTypeTotals,
}

impl FeeHistoryReport {
    /// True when no vault produced a view.
    pub fn is_empty(&self) -> bool {
        self.views.is_empty()
    }

    /// The scan time.
    pub fn at(&self) -> u64 {
        self.at
    }

    /// How many escrows were scanned.
    pub fn scanned(&self) -> usize {
        self.scanned
    }

    /// Per-vault views, in scan order.
    pub fn views(&self) -> &[FeeHistoryView] {
        &self.views
    }

    /// Vaults skipped on gappy event streams.
    pub fn skipped(&self) -> &[[u8; 32]] {
        &self.skipped
    }

    /// Fleet-wide per-type totals.
    pub fn fleet(&self) -> FeeTypeTotals {
        self.fleet
    }

    /// Deterministic JSON: `{"at":…,"scanned":…,"fleet":{…},"vaults":[…],"skipped":[…]}`.
    /// Vaults stay in scan order; skipped ids render as hex.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(128 + self.views.len() * 256);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"fleet\":");
        s.push_str(&self.fleet.to_json());
        s.push_str(",\"vaults\":[");
        for (i, view) in self.views.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&view.to_json());
        }
        s.push_str("],\"skipped\":[");
        for (i, id) in self.skipped.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('"');
            s.push_str(&hex64(id));
            s.push('"');
        }
        s.push_str("]}");
        s
    }
}

/// Scan per-vault fee histories across the keeper's watched set:
/// one [`FeeHistoryView`] per escrow, plus the fleet rollup.
///
/// Pure read — the escrows are borrowed, nothing mutates. Vaults
/// whose event stream breaks `seq` continuity are skipped (recorded
/// in [`FeeHistoryReport::skipped`]) rather than reported with a
/// partial view.
pub fn scan_fee_history(indexed: &[IndexedEscrow], now: u64) -> FeeHistoryReport {
    let mut views = Vec::with_capacity(indexed.len());
    let mut skipped = Vec::new();
    let mut fleet = FeeTypeTotals::default();
    for escrow in indexed {
        match FeeHistoryView::from_indexed(escrow) {
            Ok(view) => {
                fleet.add_totals(&view.totals);
                views.push(view);
            }
            Err(_) => skipped.push(escrow.escrow_id()),
        }
    }
    FeeHistoryReport {
        at: now,
        scanned: indexed.len(),
        views,
        skipped,
        fleet,
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod fee_history_tests {
    use super::*;
    use crate::events::IndexedEscrow;
    use crate::VestingSchedule;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const ARB: [u8; 32] = [0xDD; 32];
    const ID: [u8; 32] = [0x1D; 32];
    const NOW: u64 = 1_750_000_000;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn fee_kind_covers_every_kind() {
        for d in 0..=u8::MAX {
            let Some(kind) = EscrowEventKind::from_discriminant(d) else {
                continue;
            };
            // Exhaustive on purpose: adding a variant forces this
            // test to decide its fee semantics (never silently
            // mis-booked).
            let want: Option<FeeType> = match kind {
                EscrowEventKind::Released
                | EscrowEventKind::ReleasedSplit
                | EscrowEventKind::ReleaseViaIntent
                | EscrowEventKind::DualControlConfirmed
                | EscrowEventKind::MilestoneReleased
                // AV-229: a partial slice fees like a full
                // tranche release.
                | EscrowEventKind::MilestonePartiallyClaimed
                | EscrowEventKind::SubscriptionPeriodReleased
                | EscrowEventKind::BasketReleased
                | EscrowEventKind::EscrowsNetted => Some(FeeType::Release),
                EscrowEventKind::Claimed => Some(FeeType::Claim),
                // AV-149: one claimant's leg fees like a vesting claim.
                EscrowEventKind::ShareClaimed => Some(FeeType::Claim),
                EscrowEventKind::Resolved
                | EscrowEventKind::DefaultJudgment
                | EscrowEventKind::PanelResolved => Some(FeeType::Resolve),
                EscrowEventKind::Initialized
                | EscrowEventKind::Activated
                | EscrowEventKind::Funded
                | EscrowEventKind::Cancelled
                | EscrowEventKind::ExpiredCancelled
                | EscrowEventKind::Attested
                | EscrowEventKind::Escalated
                | EscrowEventKind::MilestoneConfirmed
                | EscrowEventKind::MilestoneSkipped
                // AV-232: restoring a skipped tranche carries no fee leg.
                | EscrowEventKind::MilestoneUnskipped
                | EscrowEventKind::QuorumUpdated
                | EscrowEventKind::AttestorsUpdated
                // AV-154: a quorum key rotation moves no funds.
                | EscrowEventKind::AttestorReplaced
                // AV-155: a milestone repricing moves no funds.
                | EscrowEventKind::MilestonesAmended
                | EscrowEventKind::MilestonesReallocated
                // AV-225: an expired claim carries no fee leg.
                | EscrowEventKind::MilestoneClaimExpired
        // AV-226: an appended tranche carries no fee leg.
        | EscrowEventKind::MilestoneTrancheAppended
        // AV-227: an amended roster carries no fee leg.
        | EscrowEventKind::ClaimantRosterAmended
        // AV-230: a revised schedule carries no fee leg.
        | EscrowEventKind::VestingScheduleAmended
        // AV-231: a revised deadline table moves no funds — the new
        // dates price late penalties only at the later releases.
        | EscrowEventKind::MilestoneDueDatesAmended
        // AV-233: a revised fee rate carries no fee leg.
        | EscrowEventKind::ProtocolFeeAmended
        // AV-234: a rotated verifier carries no fee leg.
        | EscrowEventKind::MilestoneVerifierRotated
        // AV-235: a revised arbiter fee carries no fee leg itself.
        | EscrowEventKind::ArbiterFeeAmended
        // AV-236: a revised appeal window carries no fee leg itself.
        | EscrowEventKind::AppealWindowAmended
        // AV-237: a revised slash ladder carries no fee leg itself.
        | EscrowEventKind::SlashLadderAmended
        // AV-238: a revised appeal bond carries no fee leg itself.
        | EscrowEventKind::AppealBondAmended
        // AV-240: a revised grace period carries no fee leg itself.
        | EscrowEventKind::GracePeriodAmended
        // AV-241: a revised evidence deadline carries no fee leg itself.
        | EscrowEventKind::EvidenceDeadlineAmended
        // AV-242: a revised arbitration deadline moves no funds —
        // the new deadline gates only the later disputes'
        // default judgments.
        | EscrowEventKind::ArbitrationDeadlineAmended
        // AV-243: a revised claim cooldown moves no funds —
        // the next claim's eligibility is recomputed from the
        // amended cooldown.
        | EscrowEventKind::ClaimCooldownAmended
        // AV-244: a revised delivery deadline moves no funds —
        // confirmations after the amendment are judged against
        // the new deadline; an already-confirmed delivery keeps
        // its first-won stamp.
        | EscrowEventKind::DeliveryDeadlineAmended
        // AV-245: a revised late-delivery penalty rate moves no
        // funds — a late-stamped but unreleased delivery reprices
        // at the new rate; already-released amounts are untouched.
        | EscrowEventKind::LateDeliveryPenaltyAmended
        // AV-246: a revised release cooling window moves no
        // funds — a live announced intent is re-measured against
        // the new window; a vetoed intent stays vetoed.
        | EscrowEventKind::ReleaseCoolingAmended
        // AV-247: a revised milestone claim deadline moves no
        // funds — the claim gate re-reads the deadline live;
        // already-claimed or skipped tranches keep settlements.
        | EscrowEventKind::MilestoneClaimDeadlineAmended
        // AV-248: a revised per-extension cap moves no
        // funds — the next extension is judged against the live
        // cap; already-made extensions keep deadline and count.
        | EscrowEventKind::MaxExtensionAmended
        // AV-249: a revised absolute timelock moves no
        // funds — the payout gates re-read the live lock;
        // already-released amounts are never restated.
        | EscrowEventKind::TimelockAmended
        // AV-250: a revised relative timelock moves no
        // funds — the payout gates re-read the live window
        // against the unchanged funding anchor; already-released
        // amounts are never restated.
        | EscrowEventKind::RelativeTimelockAmended
        // AV-251: a revised slot timelock moves no
        // funds — the slot gates re-read the live window
        // against the unchanged funding slot; already-released
        // amounts are never restated.
        | EscrowEventKind::SlotTimelockAmended
        // AV-252: a revised rent sweep grace moves no
        // funds — the sweep gate re-reads the live grace
        // against the unchanged terminal timestamp; a sweep
        // already performed is never undone.
        | EscrowEventKind::RentSweepGraceAmended
        // AV-253: a revised fee schedule moves no
        // funds — later payouts reprice live from the amended
        // schedule; fees already charged or withdrawn are never
        // restated.
        | EscrowEventKind::FeeScheduleAmended
        // AV-254: a revised streaming fee rate moves no
        // funds — the charge gate re-reads the live rate
        // against the unchanged fund_at anchor; fees
        // already charged are never clawed back.
        | EscrowEventKind::StreamingFeeRateAmended
        // AV-255: a revised rent payer moves no
        // funds — the close reads the recipient live
        // through the amended payer; the close
        // authority is untouched and no rent is
        // recomputed.
        | EscrowEventKind::RentPayerAmended
        // AV-256: a revised referrer moves no
        // funds — the release gate re-reads the live
        // binding at every payout; referral already
        // charged is never clawed back.
        | EscrowEventKind::ReferrerAmended
        // AV-257: a revised escalation schedule moves
        // no funds — the cancel gate re-reads the live
        // schedule at every cancel_expired; a cancel
        // already settled keeps its penalty.
        | EscrowEventKind::PenaltyEscalationAmended
        // AV-258: a revised refund address moves
        // no funds — the cancel paths re-read the live
        // address at every cancel / cancel_expired; a refund
        // already settled keeps its destination.
        | EscrowEventKind::RefundAddressAmended
        // AV-259: a revised base penalty rate moves
        // no funds — the cancel gate re-reads the live base
        // rate at every cancel_expired; a cancel already
        // settled keeps its penalty.
        | EscrowEventKind::BasePenaltyAmended
        // AV-260: a revised interest rate moves no
        // funds — the accrual clock re-reads the live
        // rate at every settlement; a slice already
        // settled keeps its rate and accrued yield is
        // never clawed back.
        | EscrowEventKind::InterestRateAmended
        // AV-261: a revised price gate moves no
        // funds — the gated payout paths re-read the
        // live gate at every release / claim; a payout
        // already settled keeps its gate.
        | EscrowEventKind::PriceGateAmended
        // AV-262: a revised TWAP gate moves no
        // funds — the gated payout paths re-read the
        // live gate at every release / claim (including
        // the full-window history coverage requirement);
        // a payout already settled keeps its gate.
        | EscrowEventKind::TwapGateAmended
        // AV-263: a rotated dual-control checker moves no
        // funds — the two-step protocol authenticates the
        // next confirm against the live checker; a live
        // intent blocks the rotation, so no approval power
        // is ever transferred mid-flight.
        | EscrowEventKind::DualControlCheckerRotated
        // AV-264: a rotated credential-gate issuer moves no
        // funds — the gate verifies the next credentialed
        // release against the live issuer; an old-issuer
        // credential stops verifying at rotation, while a
        // release already settled keeps its issuer.
        | EscrowEventKind::CredentialIssuerRotated
        // AV-265: a revised dead-man's inactivity threshold
        // moves no funds — the eligibility gate judges the
        // unchanged elapsed time against the live threshold
        // at the next claim; a claim already settled keeps
        // the threshold it settled under.
        | EscrowEventKind::DeadmanInactivityAmended
        // AV-266: a revised keeper-bounty per-crank amount moves
        // no funds and never tops the pool up — the next crank
        // pays min(new per_crank, pool) from the live amount,
        // while a crank already settled keeps its amount.
        | EscrowEventKind::KeeperBountyPerCrankAmended
        // AV-267: a revised flat slash deadline moves no funds
        // and never restates a settled penalty — the slash path
        // reads the live deadline at the next eligibility check,
        // while a slash already settled keeps its deadline.
        | EscrowEventKind::SlashDeadlineAmended
                // AV-158: delayed-governance lifecycle events move no funds.
                | EscrowEventKind::GovernanceProposed
                | EscrowEventKind::GovernanceExecuted
                | EscrowEventKind::GovernanceCancelled
                | EscrowEventKind::EmergencyUnlock
                | EscrowEventKind::VaultClosed
                | EscrowEventKind::ReentryRejected
                | EscrowEventKind::Paused
                | EscrowEventKind::Unpaused
                | EscrowEventKind::PauseAuthorityRotated
                | EscrowEventKind::ExpiredCranked
                | EscrowEventKind::PayoutAllowlistUpdated
                | EscrowEventKind::TakerRotated
                | EscrowEventKind::InitializerRotated
                | EscrowEventKind::ExpiryExtended
                | EscrowEventKind::PartiallyCancelled
                | EscrowEventKind::ArbiterRotated
                | EscrowEventKind::PanelJudgment
                | EscrowEventKind::FeeRecipientRotated
                | EscrowEventKind::EvidenceSubmitted
                | EscrowEventKind::PanelThresholdChanged
                | EscrowEventKind::MilestonesAdjusted
                | EscrowEventKind::SubscriptionAmountsAdjusted
                | EscrowEventKind::SchemaMigrated
                | EscrowEventKind::BundlePartiallyExecuted
                | EscrowEventKind::TemplateApplied
                | EscrowEventKind::VaultsBatchClosed
                | EscrowEventKind::EscrowSplit
                | EscrowEventKind::Slashed
                | EscrowEventKind::CpiAllowlistUpdated
                | EscrowEventKind::AppealFiled
                | EscrowEventKind::AppealResolved
                | EscrowEventKind::EvidenceFiled
                | EscrowEventKind::BasketCancelled
                | EscrowEventKind::BasketExpiredCancelled
                | EscrowEventKind::DenylistUpdated
                | EscrowEventKind::AppealExpired
                | EscrowEventKind::DelegationGranted
                | EscrowEventKind::DelegationRevoked
                | EscrowEventKind::SwapLinked
                | EscrowEventKind::DeadmanClaimed
                | EscrowEventKind::RentToppedUp
                | EscrowEventKind::TrancheFunded
                // AV-148: the taker's counter-fund carries no fee leg.
                | EscrowEventKind::TakerFunded
                // AV-150: freezing / restarting the vesting unlock
                // clock moves no funds — no fee leg.
                // AV-174: a protocol-fee withdrawal carries no *new*
                // fee leg — the fee was already attributed at payout
                // time.
                | EscrowEventKind::VestingPaused
                | EscrowEventKind::VestingResumed
                | EscrowEventKind::FeeWithdrawn
                | EscrowEventKind::ReleaseIntentAnnounced
                | EscrowEventKind::ReleaseIntentVetoed
                | EscrowEventKind::EscrowsMerged
                | EscrowEventKind::Declined
                | EscrowEventKind::CounterOfferProposed
                | EscrowEventKind::CounterOfferAccepted
                | EscrowEventKind::CounterOfferRejected
                | EscrowEventKind::KeeperBountyPaid
                | EscrowEventKind::PartialRefunded
                | EscrowEventKind::DualControlInitiated
                | EscrowEventKind::DualControlCancelled
                | EscrowEventKind::JudgmentCommitted
                | EscrowEventKind::JudgmentRevealed
                // AV-203: a delivery confirmation carries no fee leg.
                | EscrowEventKind::DeliveryConfirmed
                // AV-223: chain link / break carry no fee leg.
                | EscrowEventKind::ChainLinked
                | EscrowEventKind::ChainBroken
                | EscrowEventKind::RentSwept => None,
            };
            assert_eq!(fee_kind(kind), want, "kind {kind:?}");
        }
    }

    #[test]
    fn pricer_matches_escrow() {
        // The fold's per-event streaming split must use exactly the
        // fee the state machine charges — cross-check the mirror
        // against the real `Escrow::protocol_fee_for`.
        let mut ix = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, u64::MAX, ID, NOW)
            .unwrap()
            .with_protocol_fee(250)
            .unwrap();
        ix.fund(ALICE, NOW).unwrap();
        let pricer = FeePricer::from_escrow(ix.inner());
        for amount in [0, 1, 99, 100, 10_000, 999_999, 1_000_000, u64::MAX] {
            assert_eq!(
                pricer.protocol_fee_for(amount),
                ix.inner().protocol_fee_for(amount),
                "amount {amount}"
            );
        }
        // Fee cap path, against a real Escrow.
        let capped = Escrow::initialize(ALICE, BOB, 1_000_000, u64::MAX)
            .unwrap()
            .with_protocol_fee(10_000)
            .unwrap()
            .with_fee_cap(1_000)
            .unwrap();
        let capped_pricer = FeePricer::from_escrow(&capped);
        for amount in [0, 50, 500_000, u64::MAX] {
            assert_eq!(
                capped_pricer.protocol_fee_for(amount),
                capped.protocol_fee_for(amount),
                "capped amount {amount}"
            );
        }
        assert_eq!(capped_pricer.protocol_fee_for(500_000), 1_000);
    }

    fn fee_escrow(id: [u8; 32], fee_bps: u16) -> IndexedEscrow {
        let mut ix = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, u64::MAX, id, NOW)
            .unwrap()
            .with_protocol_fee(fee_bps)
            .unwrap();
        ix.fund(ALICE, NOW).unwrap();
        ix
    }

    #[test]
    fn release_fee_books_and_reconciles() {
        let mut ix = fee_escrow(ID, 100); // 1%
        // Release half: gross 500_000, fee 5_000.
        let (_payout, fee) = ix.release(ALICE, 500_000, None, BOB, NOW).unwrap();
        assert_eq!(fee, 5_000);

        let view = FeeHistoryView::from_indexed(&ix).unwrap();
        let totals = view.totals();
        assert_eq!(totals.release, 5_000);
        assert_eq!(totals.claim, 0);
        assert_eq!(totals.resolve, 0);
        assert_eq!(totals.streaming, 0);
        assert_eq!(totals.arbiter, 0);

        let rec = view.reconcile(ix.inner());
        assert!(rec.ok(), "{rec:?}");
        assert_eq!(rec.view_fees_paid, 5_000);
        assert_eq!(rec.state_fees_paid, ix.inner().fees_paid());
    }

    #[test]
    fn streaming_fee_splits_from_bps() {
        let mut ix = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, u64::MAX, ID, NOW)
            .unwrap()
            .with_protocol_fee(100) // 1% bps
            .unwrap()
            .with_streaming_fee(10) // 10 lamports/sec
            .unwrap();
        ix.fund(ALICE, NOW).unwrap();
        // 1_000 seconds later: streaming accrues 10_000, bps on
        // 500_000 gross is 5_000 — the event's fee leg is 15_000.
        let at = NOW + 1_000;
        let (_payout, fee) = ix.release(ALICE, 500_000, None, BOB, at).unwrap();
        assert_eq!(fee, 15_000);

        let view = FeeHistoryView::from_indexed(&ix).unwrap();
        let totals = view.totals();
        assert_eq!(totals.release, 5_000, "bps slice");
        assert_eq!(totals.streaming, 10_000, "streaming slice");

        let rec = view.reconcile(ix.inner());
        assert!(rec.ok(), "{rec:?}");
        assert_eq!(rec.view_streaming, ix.inner().streaming_fees_accrued());
        assert_eq!(rec.state_streaming, 10_000);
    }

    #[test]
    fn claim_fee_books_as_claim() {
        let schedule = VestingSchedule::new(NOW, NOW + 10_000).unwrap();
        let mut ix = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, u64::MAX, ID, NOW)
            .unwrap()
            .with_protocol_fee(200) // 2%
            .unwrap()
            .with_vesting(schedule)
            .unwrap();
        ix.fund(ALICE, NOW).unwrap();
        // Half vested at NOW + 5_000: claimable 500_000, fee 10_000.
        let (_claimed, fee) = ix.claim(BOB, NOW + 5_000, None, BOB).unwrap();
        assert_eq!(fee, 10_000);

        let view = FeeHistoryView::from_indexed(&ix).unwrap();
        let totals = view.totals();
        assert_eq!(totals.claim, 10_000);
        assert_eq!(totals.release, 0);

        let rec = view.reconcile(ix.inner());
        assert!(rec.ok(), "{rec:?}");
    }

    #[test]
    fn resolve_fee_and_arbiter_fee() {
        let mut ix = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, u64::MAX, ID, NOW)
            .unwrap()
            .with_protocol_fee(100) // 1%
            .unwrap()
            .with_arbiter(ARB)
            .unwrap()
            .with_arbiter_fee(1_000, 500) // 1_000 flat + 5% on the net share
            .unwrap();
        ix.fund(ALICE, NOW).unwrap();
        ix.escalate(ALICE, NOW + 10, 1_000_000, None, None, 0).unwrap();
        // Arbiter awards the taker 600_000 gross: bps fee 6_000 on the
        // taker share; arbiter fee = 1_000 + 5% of (600_000 - 6_000).
        // `resolve` returns (net taker payout, fee, initializer
        // refund) — the arbiter fee rides the event's `arbiter_fee`
        // leg.
        let (taker_payout, fee, refund) =
            ix.resolve(ARB, 600_000, None, None, BOB, NOW + 20).unwrap();
        let want_arbiter = 1_000 + (600_000 - 6_000) * 500 / 10_000;
        assert_eq!(fee, 6_000);
        assert_eq!(refund, 400_000);
        assert_eq!(taker_payout + fee + want_arbiter, 600_000);
        let event_arbiter = ix.events().last().unwrap().amounts.arbiter_fee;
        assert_eq!(event_arbiter, want_arbiter);

        let view = FeeHistoryView::from_indexed(&ix).unwrap();
        let totals = view.totals();
        assert_eq!(totals.resolve, 6_000, "bps slice on the taker share");
        assert_eq!(totals.arbiter, want_arbiter, "arbiter leg");
        assert_eq!(totals.release, 0);
        assert_eq!(totals.claim, 0);

        // The arbiter leg is outside `fees_paid` — reconcile checks
        // only the bps + streaming legs.
        let rec = view.reconcile(ix.inner());
        assert!(rec.ok(), "{rec:?}");
        assert_eq!(rec.view_fees_paid, 6_000);
    }

    #[test]
    fn daily_rollup_splits_days() {
        let mut ix = fee_escrow(ID, 100); // 1%
        let day0 = NOW / SECS_PER_DAY;
        // Two releases on different UTC days.
        ix.release(ALICE, 100_000, None, BOB, NOW).unwrap(); // fee 1_000
        ix.release(ALICE, 200_000, None, BOB, NOW + SECS_PER_DAY)
            .unwrap(); // fee 2_000

        let view = FeeHistoryView::from_indexed(&ix).unwrap();
        assert_eq!(view.totals().release, 3_000);
        assert_eq!(view.day(day0).unwrap().release, 1_000);
        assert_eq!(view.day(day0 + 1).unwrap().release, 2_000);
        assert_eq!(view.day(day0 + 2), None);

        // Days ascend in the JSON.
        let json = view.to_json();
        let d0 = json.find(&format!("\"day\":{day0},")).unwrap();
        let d1 = json.find(&format!("\"day\":{},", day0 + 1)).unwrap();
        assert!(d0 < d1, "days ascend");
    }

    #[test]
    fn json_shape_is_deterministic() {
        let mut ix = fee_escrow(ID, 100);
        ix.release(ALICE, 100_000, None, BOB, NOW).unwrap();
        let view = FeeHistoryView::from_indexed(&ix).unwrap();
        let json = view.to_json();
        // Canonical key order, hex id, totals before daily.
        assert!(json.starts_with("{\"escrow_id\":\""));
        assert!(json.contains(&format!("\"escrow_id\":\"{}\"", hex64(&ID))));
        assert!(json.contains("\"totals\":{\"release\":1000,\"claim\":0,\"resolve\":0,\"streaming\":0,\"arbiter\":0}"));
        assert!(json.contains("\"daily\":[{\"day\":"));
        assert!(json.ends_with(&format!("\"next_seq\":{}}}", view.next_seq())));
        // Two views over the same stream render byte-identical.
        let view2 = FeeHistoryView::from_indexed(&ix).unwrap();
        assert_eq!(view.to_json(), view2.to_json());
    }

    #[test]
    fn snapshot_base_passes_through_streaming() {
        let mut ix = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, u64::MAX, ID, NOW)
            .unwrap()
            .with_protocol_fee(100)
            .unwrap()
            .with_streaming_fee(10)
            .unwrap();
        ix.fund(ALICE, NOW).unwrap();
        ix.release(ALICE, 500_000, None, BOB, NOW + 1_000).unwrap();
        // streaming 10_000, bps 5_000.
        let snapshot_seq = ix.next_seq() - 1;
        let snap = ix.inner().snapshot(NOW + 1_000);

        let mut view = FeeHistoryView::from_snapshot(ID, &snap, snapshot_seq);
        // The streaming sub-counter passes through exactly; the bps
        // types count from the snapshot point on.
        assert_eq!(view.totals().streaming, 10_000);
        assert_eq!(view.totals().release, 0);
        assert!(view.daily().is_empty(), "no day attribution pre-snapshot");

        // A later release folds on top.
        ix.release(ALICE, 100_000, None, BOB, NOW + 2_000).unwrap();
        let later = &ix.events()[ix.events().len() - 1..];
        view.apply(later).unwrap();
        // Second release: 1_000s more streaming (10_000) + bps 1_000.
        assert_eq!(view.totals().streaming, 20_000);
        assert_eq!(view.totals().release, 1_000);
        assert_eq!(view.daily().len(), 1);
    }

    #[test]
    fn seq_gap_errors_and_keeps_prefix() {
        let mut ix = fee_escrow(ID, 100);
        ix.release(ALICE, 100_000, None, BOB, NOW).unwrap();
        let events = ix.events().to_vec();

        let mut view = FeeHistoryView {
            escrow_id: ID,
            totals: FeeTypeTotals::default(),
            daily: BTreeMap::new(),
            pricer: FeePricer::from_escrow(ix.inner()),
            next_seq: 0,
        };
        // Skip seq 1 (the Funded event): the fold stops at the gap.
        let mut gappy = vec![events[0].clone()];
        gappy.extend_from_slice(&events[2..]);
        let err = view.apply(&gappy).unwrap_err();
        assert_eq!(err, EscrowError::GapInEventStream);
        assert_eq!(view.next_seq(), 1);
        // The valid prefix (seq 0, no fee) stays applied; resuming
        // from `next_seq` completes the fold.
        view.apply(&events[1..]).unwrap();
        assert_eq!(view.totals().release, 1_000);
    }

    #[test]
    fn foreign_escrow_id_errors() {
        let mut ix = fee_escrow(ID, 100);
        ix.release(ALICE, 100_000, None, BOB, NOW).unwrap();
        let events = ix.events().to_vec();

        let mut view = FeeHistoryView {
            escrow_id: key(0xFF),
            totals: FeeTypeTotals::default(),
            daily: BTreeMap::new(),
            pricer: FeePricer::from_escrow(ix.inner()),
            next_seq: 0,
        };
        let err = view.apply(&events).unwrap_err();
        assert_eq!(err, EscrowError::GapInEventStream);
        assert_eq!(view.next_seq(), 0);
    }

    #[test]
    fn keeper_scan_rolls_up_fleet() {
        let mut a = fee_escrow(key(0xA1), 100);
        a.release(ALICE, 100_000, None, BOB, NOW).unwrap(); // 1_000
        let mut b = fee_escrow(key(0xB2), 200);
        b.release(ALICE, 100_000, None, BOB, NOW).unwrap(); // 2_000

        let report = scan_fee_history(&[a, b], NOW);
        assert_eq!(report.scanned(), 2);
        assert!(!report.is_empty());
        assert_eq!(report.fleet().release, 3_000);
        assert_eq!(report.views().len(), 2);
        assert!(report.skipped().is_empty());

        let json = report.to_json();
        assert!(json.contains("\"scanned\":2"));
        assert!(json.contains("\"fleet\":{\"release\":3000,\"claim\":0,\"resolve\":0,\"streaming\":0,\"arbiter\":0}"));
        assert!(json.contains("\"skipped\":[]"));

        // Empty scan.
        let empty = scan_fee_history(&[], NOW);
        assert!(empty.is_empty());
        assert_eq!(empty.fleet(), FeeTypeTotals::default());
    }

    #[test]
    fn fee_type_names_are_canonical() {
        assert_eq!(
            FeeType::ALL.map(FeeType::name),
            ["release", "claim", "resolve", "streaming", "arbiter"]
        );
    }
}

