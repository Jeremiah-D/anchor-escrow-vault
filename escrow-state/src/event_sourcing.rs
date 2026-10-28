//! Event-sourced materialized fund view (AV-94).
//!
//! [`MaterializedView`] folds an [`EscrowEvent`] stream into the
//! per-escrow fund triple ([`FundsTriple`]: `locked` / `released` /
//! `refunded`); [`fold_fleet`] rolls per-escrow views into the fleet
//! aggregate ([`FleetFunds`]) that keeper/indexer tooling consumes.
//! Pure logic, zero dependencies — the read-model complement to the
//! AV-18 event log and the AV-26 snapshot.
//!
//! # Fold semantics
//!
//! Every [`EscrowEventKind`] maps to a `(Δlocked, Δreleased, Δrefunded)`
//! triple (see [`fund_delta`](self::fund_delta) — the match is
//! exhaustive, so a future variant fails to compile until its fund
//! semantics are decided, never silently zero):
//!
//! * Taker payouts (`Released`, `ReleasedSplit`, `Claimed`,
//!   `ShareClaimed` (AV-149), `MilestoneReleased`,
//!   `SubscriptionPeriodReleased`) book the
//!   **gross** amount: the AV-17 protocol fee is an internal routing
//!   slice of the gross (`payout` already includes it), matching the
//!   state machine's `released` counter bit-for-bit.
//! * Initializer refunds (`Cancelled`, `PartiallyCancelled`,
//!   `PartialRefunded`, `ExpiredCancelled`, `ExpiredCranked`) book
//!   `refunded`. The AV-24
//!   anti-griefing penalty on a taker-initiated expiry cancel routes
//!   to the initializer as compensation, so it books as `refunded`
//!   too (`refund + penalty == remaining` by construction).
//! * Dispute settlements (`Resolved`, `DefaultJudgment`,
//!   `PanelResolved`) split the remainder: the taker's gross share
//!   into `released`, the initializer's share into `refunded` (never
//!   fee'd — the fee slices only the taker's share).
//! * `EscrowSplit` moves the Σ child amounts sideways (re-locked into
//!   the children, each folding its own log under its derived id):
//!   out of this escrow's `locked`, but neither a payout nor a refund.
//! * Bilateral netting (`EscrowsNetted`, AV-140): the larger leg's
//!   lockup shrank by the netted amount and booked it as released (a
//!   zero-payout settlement — no transfer) — books exactly like
//!   `Released`. The smaller leg's `Released` carries a zero payout
//!   (the netting signature — no other transition can emit one); the
//!   fold moves its whole remaining lockup sideways into `released`,
//!   mirroring the state machine's `released := amount` bookkeeping
//!   bit-for-bit.
//! * Everything else books `(0, 0, 0)` — votes, governance, pauses,
//!   disclosures, and the two summary events (`BundlePartiallyExecuted`
//!   re-states already-booked tranche payouts; `VaultsBatchClosed`
//!   re-states rent, which sits outside the lockup). Two deliberate
//!   no-ops deserve emphasis:
//!   - `Slashed` (AV-82): the penalty is tracked by the state
//!     machine's dedicated `penalty_paid` counter, never mixed into
//!     `released`. The triple has no penalty leg, so the fold books
//!     nothing and the penalty outflow stays parked inside `locked`.
//!   - `AppealResolved` (AV-86): an overturn reverses a penalty the
//!     fold never booked, so it is the symmetric no-op (and the
//!     fold's `locked` realigns with `remaining_amount()` exactly when
//!     `penalty_paid` returns to 0).
//!   - `AppealExpired` (AV-103): a lapsed appeal forfeits the bond —
//!     taker-supplied funds the fold never booked (the bond is
//!     additional inflow outside the principal) — so it is the
//!     symmetric no-op too.
//!   - `KeeperBountyPaid` (AV-124): the bounty pool is
//!     initializer-supplied funds the fold never booked (the pool is
//!     additional inflow outside the principal, the AV-103
//!     appeal-bond precedent) — so the payout is the symmetric
//!     no-op too.
//!   - `MilestoneSkipped`: the tranche stays in the lockup (it joins
//!     the refundable remainder — `remaining_amount()` still counts
//!     it), so the fold books nothing now; the tranche is counted
//!     exactly once, inside the later cancel/resolve refund.
//!   - `PanelJudgment`: a vote moves no funds, and its `payout` is the
//!     *voted* split, not an executed one — only the settling
//!     `PanelResolved` moves funds.
//!
//! The fold maintains the conservation identity
//! `locked + released + refunded == inflow`, where the fold's `locked`
//! equals `remaining_amount() + penalty_paid()` (the parked-penalty
//! convention above). Against the live state machine:
//!
//! * `triple.released == escrow.released_amount()` — bit-identical.
//! * `triple.locked == escrow.remaining_amount() + escrow.penalty_paid()`.
//! * `triple.refunded` equals the Σ initializer receipts tracked from
//!   the transitions' return values (the state machine keeps no
//!   cumulative refunded counter).
//!
//! # Snapshot base + incremental apply
//!
//! [`MaterializedView::from_snapshot`] seeds a view from a snapshot
//! taken at `snapshot_seq`; [`MaterializedView::apply`] then folds the
//! later events. Two honest limitations (never fabricated):
//!
//! * The snapshot carries no cumulative refunded counter, so the base
//!   seeds `refunded = 0` — refunds are counted *from the snapshot
//!   point on*. A genesis replay
//!   ([`MaterializedView::replay`]) and a snapshot+incremental run
//!   agree bit-for-bit exactly when no refund event sits at or before
//!   the snapshot point.
//! * `Funded` carries no amount (`IndexedEscrow::fund` pushes
//!   `EventAmounts::none()`), so the inflow is an explicit seed: the
//!   genesis replay takes `funded_amount` (the same value
//!   [`EscrowSnapshot::amount`] reports), and the snapshot base takes
//!   `remaining + penalty_paid` (live states) or `penalty_paid`
//!   (terminal states, whose `remaining` is preserved for audit, not
//!   locked anymore).
//!
//! # Sequence continuity
//!
//! `apply` expects `seq` strictly continuous (`next_seq`,
//! `next_seq + 1`, …) for this view's `escrow_id`. The first break —
//! a gap, an out-of-order or duplicate `seq`, or a foreign
//! `escrow_id` — stops the fold with
//! [`EscrowError::GapInEventStream`]; the valid prefix stays applied
//! and [`MaterializedView::next_seq`] advances past it, so the caller
//! backfills from `next_seq` instead of trusting a silently gappy
//! aggregate.
//!
//! [`EscrowEvent`]: crate::EscrowEvent
//! [`EscrowEventKind`]: crate::EscrowEventKind
//! [`EscrowSnapshot::amount`]: crate::EscrowSnapshot::amount

use crate::events::{EscrowEvent, EscrowEventKind, EventAmounts};
use crate::snapshot::EscrowSnapshot;
use crate::EscrowError;

/// `(locked_decrement, released_increment, refunded_increment)` for
/// one event — the full [`EscrowEventKind`] table.
///
/// The match is exhaustive on purpose: a future variant fails to
/// compile here until its fund semantics are decided (never silently
/// zero). The table is pinned by
/// `event_sourcing_tests::fund_delta_covers_every_kind`.
///
/// [`EscrowEventKind`]: crate::EscrowEventKind
fn fund_delta(kind: EscrowEventKind, amounts: &EventAmounts) -> (u64, u64, u64) {
    match kind {
        // Pure state flips, governance, votes, disclosures and audit
        // summaries: no fund movement. `Funded` is deliberately zero
        // here too — the event carries no amount, so the inflow is the
        // explicit fold seed (see the module docs).
        EscrowEventKind::Initialized
        | EscrowEventKind::Activated
        | EscrowEventKind::Funded
        | EscrowEventKind::Attested
        | EscrowEventKind::Escalated
        | EscrowEventKind::MilestoneConfirmed
        // AV-203: a delivery confirmation moves no funds.
        | EscrowEventKind::DeliveryConfirmed
        // AV-223: chain link / break move no funds (the funding
        // itself books on the downstream's Funded / release legs).
        | EscrowEventKind::ChainLinked
        | EscrowEventKind::ChainBroken
        | EscrowEventKind::QuorumUpdated
        | EscrowEventKind::AttestorsUpdated
        // AV-154: a quorum key rotation moves no funds.
        | EscrowEventKind::AttestorReplaced
        // AV-155: a milestone repricing moves no funds.
        | EscrowEventKind::MilestonesAmended
        | EscrowEventKind::MilestonesReallocated
        // AV-225: an expired claim is a reclassification, not a
        // settlement — the tranche stays in the lockup (it joins
        // the refundable remainder, like `MilestoneSkipped`), so the
        // fold books nothing now; the tranche is counted exactly
        // once, inside the later cancel/resolve refund.
        | EscrowEventKind::MilestoneClaimExpired
        // AV-226: appending a tranche moves no funds — the tranche
        // is carved from the skipped remainder, not paid out now;
        // the later tranche release carries the amount with its fee.
        | EscrowEventKind::MilestoneTrancheAppended
        // AV-227: amending the roster moves no funds — the new
        // shares price only at the later claim_share pulls.
        | EscrowEventKind::ClaimantRosterAmended
        // AV-230: revising the schedule moves no funds — the new
        // table prices only at the later claim pulls.
        | EscrowEventKind::VestingScheduleAmended
        // AV-231: a revised deadline table moves no funds — the new
        // dates price late penalties only at the later releases.
        | EscrowEventKind::MilestoneDueDatesAmended
        // AV-233: a revised fee rate moves no funds — the new
        // rate prices only the later taker payouts.
        | EscrowEventKind::ProtocolFeeAmended
        // AV-234: a rotated verifier moves no funds — the new
        // key gates only the later attestation checks.
        | EscrowEventKind::MilestoneVerifierRotated
        // AV-235: a revised arbiter fee moves no funds — the new
        // fee prices only the later dispute settlements.
        | EscrowEventKind::ArbiterFeeAmended
        // AV-236: a revised appeal window moves no funds — the new
        // window stamps only the later slashes' appeal deadlines.
        | EscrowEventKind::AppealWindowAmended
        // AV-237: a revised slash ladder moves no funds — the new
        // rungs price only the later slashes.
        | EscrowEventKind::SlashLadderAmended
        // AV-238: a revised appeal bond moves no funds — the new
        // bond is locked only by the later appeal filings.
        | EscrowEventKind::AppealBondAmended
        // AV-240: a revised grace period moves no funds — the new
        // grace gates only the later expiry determinations.
        | EscrowEventKind::GracePeriodAmended
        // AV-241: a revised evidence deadline moves no funds —
        // the new deadline gates only the later disputes'
        // disclosure windows.
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
        | EscrowEventKind::PayoutAllowlistUpdated
        // AV-96: a config change — no fund movement.
        | EscrowEventKind::DenylistUpdated
        | EscrowEventKind::TakerRotated
        | EscrowEventKind::InitializerRotated
        | EscrowEventKind::ExpiryExtended
        | EscrowEventKind::ArbiterRotated
        | EscrowEventKind::FeeRecipientRotated
        | EscrowEventKind::EvidenceSubmitted
        | EscrowEventKind::PanelThresholdChanged
        | EscrowEventKind::MilestonesAdjusted
        | EscrowEventKind::SubscriptionAmountsAdjusted
        | EscrowEventKind::SchemaMigrated
        | EscrowEventKind::TemplateApplied
        | EscrowEventKind::CpiAllowlistUpdated
        | EscrowEventKind::AppealFiled
        | EscrowEventKind::EvidenceFiled
        // AV-104: a config change — no fund movement.
        | EscrowEventKind::DelegationGranted
        | EscrowEventKind::DelegationRevoked
        // AV-105: a config change — no fund movement.
        | EscrowEventKind::SwapLinked
        // AV-122: negotiation state flips — no fund movement. The
        // `CounterOfferProposed` payout is the *proposed* amount, not
        // an executed transfer, so booking it would invent a payout
        // (the PanelJudgment rule).
        | EscrowEventKind::Declined
        | EscrowEventKind::CounterOfferProposed
        | EscrowEventKind::CounterOfferAccepted
        | EscrowEventKind::CounterOfferRejected
        // A panel vote moves no funds — and `PanelJudgment`'s `payout`
        // is the *voted* split, not an executed one, so booking it
        // would invent a payout; only the settling `PanelResolved`
        // moves funds.
        | EscrowEventKind::PanelJudgment
        // AV-137: a blind commit moves no funds; a reveal's `payout`
        // is the *revealed* split, not an executed one (the
        // PanelJudgment rule) — only the settling `PanelResolved`
        // moves funds.
        | EscrowEventKind::JudgmentCommitted
        | EscrowEventKind::JudgmentRevealed
        // A keeper bundle summary: the per-tranche `MilestoneReleased`
        // events already booked the gross — booking the Σ again would
        // double-count.
        | EscrowEventKind::BundlePartiallyExecuted
        // A batch-close summary: rent sits outside the lockup, and the
        // per-vault `VaultClosed` events (also zero here) already ran.
        | EscrowEventKind::VaultsBatchClosed
        // A skipped milestone tranche stays in the lockup (it joins
        // the refundable remainder — `remaining_amount()` still counts
        // it), so the fold books nothing now; the tranche is counted
        // exactly once, inside the later cancel/resolve refund.
        | EscrowEventKind::MilestoneSkipped
        // AV-232: restoring a skipped tranche moves no funds
        // either — the symmetric no-op of MilestoneSkipped: the
        // tranche returns to the claimable schedule inside the
        // lockup, and is counted exactly once, inside the later
        // release or cancel.
        | EscrowEventKind::MilestoneUnskipped
        // AV-82: the slash moves funds to the penalty account, tracked
        // by the state machine's dedicated `penalty_paid` counter —
        // never mixed into `released`. The triple has no penalty leg,
        // so the fold books nothing: the penalty outflow stays parked
        // inside `locked` (i.e. the fold's `locked` is
        // `remaining_amount() + penalty_paid()`).
        | EscrowEventKind::Slashed
        // AV-86: an overturn reverses a penalty the fold never booked
        // (see `Slashed`), so it is the symmetric no-op — and the
        // fold's `locked` realigns with `remaining_amount()` exactly
        // when `penalty_paid` returns to 0. An upheld appeal moves
        // nothing either.
        // AV-103: an expired appeal forfeits the bond — taker-supplied
        // funds the fold never booked (the bond is additional inflow
        // outside the principal) — so it is the symmetric no-op too.
        // AV-150: freezing / restarting the vesting unlock clock is a
        // Funded → Funded schedule-config flip — no funds move; the
        // schedule's window shift on resume is time math, not a
        // transfer.
        | EscrowEventKind::VestingPaused
        | EscrowEventKind::VestingResumed
        | EscrowEventKind::AppealResolved
        | EscrowEventKind::AppealExpired
        // AV-174: a protocol-fee withdrawal moves no *fold-tracked*
        // funds — the fee already left `locked` at payout time as part
        // of the gross release (the AV-17 routing-slice rule); the
        // extraction is tracked by the state machine's dedicated
        // `fees_withdrawn` counter (the `penalty_paid` precedent).
        | EscrowEventKind::FeeWithdrawn => (0, 0, 0),
        // AV-124: a keeper-bounty payout — the bounty pool is
        // initializer-supplied funds the fold never booked (the pool
        // is additional inflow outside the principal, the AV-103
        // appeal-bond precedent), so the payout is the symmetric
        // no-op: the fold's `locked` stays `remaining_amount() +
        // penalty_paid()` and the conservation identity is untouched.
        // Indexers that need the pool balance read the event's
        // `bounty_pool_remaining`.
        EscrowEventKind::KeeperBountyPaid => (0, 0, 0),
        // Taker payouts, gross (AV-17: the fee is an internal routing
        // slice of the gross — `payout` already includes it, matching
        // `Escrow::released_amount`). `ReleasedSplit` (AV-93) likewise
        // books the gross: the per-recipient net legs split
        // `payout - fee`, they are not additional movement.
        EscrowEventKind::Released
        | EscrowEventKind::ReleasedSplit
        // AV-123: an intent-driven release books exactly like the
        // party-signed `Released` — same lifecycle move, same gross
        // accounting; the event kind distinguishes the authorization
        // path, the fund triple does not.
        | EscrowEventKind::ReleaseViaIntent
        // AV-130: a checker-approved release is a release — same
        // lifecycle move, same gross accounting; the kind
        // distinguishes the two-step authorization path, the fund
        // triple does not.
        | EscrowEventKind::DualControlConfirmed
        | EscrowEventKind::Claimed
        // AV-149: one claimant's leg paid out — the per-leg
        // `Claimed`; the leg's gross books as `released`, like the
        // plain kind.
        | EscrowEventKind::ShareClaimed
        | EscrowEventKind::MilestoneReleased
        // AV-229: a partial slice books like the full tranche
        // release — the slice's gross is released value.
        | EscrowEventKind::MilestonePartiallyClaimed
        | EscrowEventKind::SubscriptionPeriodReleased
        // AV-95b: one basket leg paid out to the taker — the per-leg
        // `Released`; the leg's gross books as `released`, like the
        // plain kind.
        // AV-140: bilateral netting shrank the larger leg's lockup by
        // the netted amount and booked it as released (a zero-payout
        // settlement, no transfer) — the fold books it exactly like a
        // taker payout, matching the state machine's `released +=
        // netted` bit-for-bit.
        | EscrowEventKind::BasketReleased
        | EscrowEventKind::EscrowsNetted => {
            (amounts.payout, amounts.payout, 0)
        }
        // Initializer refunds. `Cancelled` refunds the remainder;
        // `PartiallyCancelled` / `PartialRefunded` refund the tranche
        // (the state machine shrinks `amount`, so `locked` drops by
        // the same).
        // AV-95b: one basket leg refunded — the per-leg `Cancelled`.
        EscrowEventKind::Cancelled
        | EscrowEventKind::PartiallyCancelled
        // AV-127: the audited partial-refund path books like
        // `PartiallyCancelled` — the initializer's receipt.
        | EscrowEventKind::PartialRefunded
        // AV-109: the heir's inactivity reclaim books like a
        // `Cancelled` — the remaining locked amount leaves as the
        // refund sink (to the heir, not the initializer).
        | EscrowEventKind::BasketCancelled
        | EscrowEventKind::DeadmanClaimed => {
            (amounts.refund, 0, amounts.refund)
        }
        // AV-110: a rent top-up moves lamports into the vault
        // *account*, not the escrow lockup — rent sits outside the
        // lockup exactly like a close's `rent_reclaimed`, so the
        // fold books nothing (the topped-up lamports ride the
        // event's `rent_reclaimed` field for indexers, never the
        // fund triple).
        | EscrowEventKind::RentToppedUp => (0, 0, 0),
        // AV-139: a rent sweep moves no escrow funds (rent sits
        // outside the lockup; the swept lamports ride the event's
        // `rent_reclaimed` field for indexers, never the fund triple).
        | EscrowEventKind::RentSwept => (0, 0, 0),
        // AV-111: a funding tranche is the fold seed's inflow leg —
        // the fold seeds the lockup with the deal size at `Funded`
        // (exactly like `Funded` itself), so the tranche carries no
        // amount and the fold books nothing.
        | EscrowEventKind::TrancheFunded => (0, 0, 0),
        // AV-148: the taker's counter-fund is the fold seed's inflow
        // leg — the fold seeds the lockup with the bilateral total at
        // `Funded` (exactly like `Funded` itself), so the counter-fund
        // carries no amount and the fold books nothing.
        | EscrowEventKind::TakerFunded => (0, 0, 0),
        // AV-112: release-intent governance signals move no escrow
        // funds — pure bookkeeping for the indexer, like the AV-104
        // delegation config changes — so the fold books nothing.
        | EscrowEventKind::ReleaseIntentAnnounced
        | EscrowEventKind::ReleaseIntentVetoed
        // AV-130: the maker-checker declaration and its abort are the
        // same class of governance signal — no fund movement, the fold
        // books nothing.
        | EscrowEventKind::DualControlInitiated
        | EscrowEventKind::DualControlCancelled => (0, 0, 0),
        // AV-114: the survivor's lockup grew by the merged-in amount
        // (the event's `payout` leg). The triple's legs only express
        // outflows, so `fund_delta` books nothing here — the locked
        // increment is applied directly in `MaterializedView::apply`
        // (the only inflow the fold expresses as a locked increment).
        | EscrowEventKind::EscrowsMerged => (0, 0, 0),
        // Expiry cancels: `refund` goes to the pinned destination and
        // the AV-24 anti-griefing `penalty` routes to the initializer
        // as compensation — both are initializer receipts, so both
        // book as `refunded`; `refund + penalty == remaining` by
        // construction, so `locked` drops by the full remainder.
        // AV-95b: one basket leg expiry-cancelled — the per-leg
        // `ExpiredCancelled`.
        EscrowEventKind::ExpiredCancelled
        | EscrowEventKind::ExpiredCranked
        | EscrowEventKind::BasketExpiredCancelled => {
            let out = amounts.refund.saturating_add(amounts.penalty);
            (out, 0, out)
        }
        // Dispute settlements: the taker's gross share books as
        // `released`, the initializer's share as `refunded` (never
        // fee'd — the fee slices only the taker's share).
        EscrowEventKind::Resolved
        | EscrowEventKind::DefaultJudgment
        | EscrowEventKind::PanelResolved => {
            let out = amounts.payout.saturating_add(amounts.refund);
            (out, amounts.payout, amounts.refund)
        }
        // AV-81: the Σ child amounts are re-locked sideways into the
        // child escrows (each child folds its own log under its derived
        // id) — out of this escrow's lockup, but neither a taker
        // payout nor an initializer refund.
        EscrowEventKind::EscrowSplit => (amounts.payout, 0, 0),
    }
}

/// Per-escrow fund triple reconstructed from the event log.
///
/// * `locked` — funds neither released nor refunded: the fold's
///   reconstruction of the releasable pool *plus* any slashed penalty
///   (the AV-82 penalty has no leg in the triple, so its outflow stays
///   parked here). Equals
///   `remaining_amount() + penalty_paid()` on the live state machine.
/// * `released` — cumulative gross taker payouts (fee included — the
///   AV-17 gross convention). Bit-identical with
///   `Escrow::released_amount()`.
/// * `refunded` — cumulative initializer receipts (refunds plus the
///   AV-24 anti-griefing penalty routed to the initializer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FundsTriple {
    pub locked: u64,
    pub released: u64,
    pub refunded: u64,
}

/// Fleet-wide fund totals over a set of per-escrow views — the
/// keeper/indexer rollup.
///
/// Sums are `u128`: a fleet total can exceed `u64` (the AV-78
/// `total_locked` precedent), and silent saturation would corrupt an
/// aggregate the operator acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FleetFunds {
    pub locked: u128,
    pub released: u128,
    pub refunded: u128,
    /// How many per-escrow views were folded in.
    pub escrow_count: usize,
}

/// Roll per-escrow views into the fleet aggregate for keeper/indexer
/// consumption: Σ `locked` / Σ `released` / Σ `refunded` plus the
/// escrow count. Pure read — the views are borrowed, nothing mutates.
pub fn fold_fleet(views: &[MaterializedView]) -> FleetFunds {
    let mut fleet = FleetFunds::default();
    for view in views {
        let triple = view.triple();
        fleet.locked += triple.locked as u128;
        fleet.released += triple.released as u128;
        fleet.refunded += triple.refunded as u128;
        fleet.escrow_count += 1;
    }
    fleet
}

/// Single-escrow materialized view: the fold cursor over one escrow's
/// [`EscrowEvent`] stream.
///
/// Build it either from genesis ([`Self::replay`]: explicit funded
/// amount, every event from `seq` 0) or from a snapshot base
/// ([`Self::from_snapshot`]) plus [`Self::apply`] for the later
/// events. `apply` enforces strict `seq` continuity — see the module
/// docs.
///
/// [`EscrowEvent`]: crate::EscrowEvent
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedView {
    escrow_id: [u8; 32],
    triple: FundsTriple,
    /// The `seq` the next applied event must carry. Genesis is 0;
    /// after `from_snapshot(_, _, k)` it is `k + 1`.
    next_seq: u64,
}

impl MaterializedView {
    /// Seed a view from a snapshot taken at `snapshot_seq`, then fold
    /// later events with [`Self::apply`].
    ///
    /// The base triple: `locked` is the snapshot's `remaining` plus
    /// its `penalty_paid` on live states (the fold parks the penalty
    /// outflow inside `locked` — it has no penalty leg — so the base
    /// re-adds it to agree with a genesis replay bit-for-bit), or just
    /// `penalty_paid` on terminal states (`cancelled` / `released` /
    /// `settled` / `closed` / `split`), whose `remaining` is preserved
    /// for audit rather than still locked. `released` is the
    /// snapshot's cumulative gross-payout counter. `refunded` seeds to
    /// 0: the snapshot carries no cumulative refunded counter, so
    /// refunds are counted *from the snapshot point on* — never
    /// fabricated (see the module docs).
    pub fn from_snapshot(
        escrow_id: [u8; 32],
        snapshot: &EscrowSnapshot,
        snapshot_seq: u64,
    ) -> Self {
        // Terminal states hold nothing anymore: `remaining_amount()`
        // is preserved for audit (the initializer's refund on
        // `Cancelled`, the settled split on `Settled`), so seeding
        // `locked` from `remaining` would resurrect exited funds. The
        // only thing the fold still parks in `locked` at a terminal
        // state is the (already-exited) penalty.
        let terminal = matches!(
            snapshot.state,
            "cancelled" | "released" | "settled" | "closed" | "split"
        );
        let locked = if terminal {
            snapshot.penalty_paid
        } else {
            snapshot.remaining.saturating_add(snapshot.penalty_paid)
        };
        Self {
            escrow_id,
            triple: FundsTriple {
                locked,
                released: snapshot.released,
                refunded: 0,
            },
            next_seq: snapshot_seq.saturating_add(1),
        }
    }

    /// Pure genesis replay: seed `locked` with the funded amount and
    /// fold every event from `seq` 0.
    ///
    /// The `Funded` event carries no amount
    /// (`IndexedEscrow::fund` pushes `EventAmounts::none()`), so the
    /// inflow is an explicit seed — the same value
    /// [`EscrowSnapshot::amount`] reports.
    ///
    /// [`EscrowSnapshot::amount`]: crate::EscrowSnapshot::amount
    pub fn replay(
        escrow_id: [u8; 32],
        funded_amount: u64,
        events: &[EscrowEvent],
    ) -> Result<Self, EscrowError> {
        let mut view = Self {
            escrow_id,
            triple: FundsTriple {
                locked: funded_amount,
                released: 0,
                refunded: 0,
            },
            next_seq: 0,
        };
        view.apply(events)?;
        Ok(view)
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
    /// Deltas apply with saturating arithmetic: the fold never panics
    /// on an adversarial log (a well-formed emitter never underflows —
    /// conservation is enforced by the state machine).
    pub fn apply(&mut self, events: &[EscrowEvent]) -> Result<(), EscrowError> {
        // Local cursor: `self.next_seq` only commits past the valid
        // prefix (on success past the whole slice, on a break past the
        // events before it).
        let mut want = self.next_seq;
        for event in events.iter() {
            if event.escrow_id != self.escrow_id || event.seq != want {
                // Stop at the break: the valid prefix stays applied,
                // and the cursor has already advanced past it, so the
                // caller resumes by backfilling from `next_seq`.
                self.next_seq = want;
                return Err(EscrowError::GapInEventStream);
            }
            let (locked_dec, released_inc, refunded_inc) =
                fund_delta(event.kind, &event.amounts);
            // AV-114: `EscrowsMerged` is the fold's only inflow — the
            // survivor absorbed the source's locked funds, so `locked`
            // grows by the merged-in amount (the event's `payout`
            // leg) instead of shrinking.
            if event.kind == EscrowEventKind::EscrowsMerged {
                self.triple.locked = self
                    .triple
                    .locked
                    .saturating_add(event.amounts.payout);
            // AV-140: the smaller leg's netting settlement — a
            // `Released` with a zero payout is the netting signature
            // (no other transition can emit one: `release` refuses
            // amount 0 with `AmountMismatch`). The offset extinguished
            // the leg's whole remaining lockup at zero payout, so the
            // remaining lockup moves sideways into `released` — the
            // fold mirror of the state machine's `released := amount`
            // ("released-into-netting") bookkeeping, keeping
            // `triple.released == escrow.released_amount()`
            // bit-identical.
            } else if event.kind == EscrowEventKind::Released
                && event.amounts.payout == 0
            {
                let rest = self.triple.locked;
                self.triple.locked = 0;
                self.triple.released = self.triple.released.saturating_add(rest);
            } else {
                self.triple.locked = self.triple.locked.saturating_sub(locked_dec);
            }
            self.triple.released = self.triple.released.saturating_add(released_inc);
            self.triple.refunded = self.triple.refunded.saturating_add(refunded_inc);
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

    /// The escrow this view folds.
    pub fn escrow_id(&self) -> [u8; 32] {
        self.escrow_id
    }

    /// The current fund triple.
    pub fn triple(&self) -> FundsTriple {
        self.triple
    }

    /// The `seq` the next [`Self::apply`] expects: one past the last
    /// consumed event (`0` on a fresh genesis replay, `snapshot_seq +
    /// 1` on a fresh snapshot base).
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod event_sourcing_tests {
    use super::*;
    use crate::events::IndexedEscrow;
    use crate::{EscrowState, MilestonePlan, SplitConfig, VestingSchedule};

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const CAROL: [u8; 32] = [0xCC; 32];
    const ARB: [u8; 32] = [0xDD; 32];
    const PEN: [u8; 32] = [0xEE; 32];
    const ID: [u8; 32] = [0x1D; 32];
    const NOW: u64 = 1_750_000_000;

    fn synth(
        kind: EscrowEventKind,
        seq: u64,
        payout: u64,
        fee: u64,
        refund: u64,
        penalty: u64,
    ) -> EscrowEvent {
        EscrowEvent {
            kind,
            escrow_id: ID,
            seq,
            from: EscrowState::Funded,
            to: EscrowState::Funded,
            amounts: EventAmounts {
                payout,
                fee,
                refund,
                penalty,
                rent_reclaimed: 0,
                arbiter_fee: 0,
            },
            at: NOW,
            evidence_hash: None,
            evidence_defaulted: false,
            rationale_hash: None,
            cpi: None,
            caller: None,
            reference: None,
            template_params_hash: None,
            split_children: None,
            release_split: None,
            schema_versions: None,
            appeal_outcome: None,
            evidence_root: None,
            evidence_disclosure: None,
            bounty_pool_remaining: None,
            // AV-126: the consumed slash-ladder rung is a live-emit
            // extra, not part of the synth projection — `None` here,
            // like the other kind-specific extras.
            slash_ladder_index: None,
            auto_unpause: false,
            // AV-182: the memo note is a live-emit extra, not part of
            // the synth projection — `None` here, like the other
            // kind-specific extras.
            memo: None,
            // AV-224: the before/after tranche tables are a
            // live-emit extra, not part of the synth projection —
            // `None` here, like the other kind-specific extras.
            milestone_reallocation: None,
            // AV-225: the expired tranche index is a live-emit
            // extra, not part of the synth projection — `None`
            // here, like the other kind-specific extras.
            milestone_claim_expired: None,
        }
    }

    fn seq_events(seqs: &[u64]) -> Vec<EscrowEvent> {
        seqs.iter()
            .map(|&s| synth(EscrowEventKind::Released, s, 10, 1, 0, 0))
            .collect()
    }

    /// The fold matches the state machine bit-for-bit:
    /// * `released` against `released_amount()` (gross, fee included);
    /// * `refunded` against the Σ initializer receipts tracked from
    ///   the transitions' return values (the machine keeps no
    ///   cumulative refunded counter);
    /// * `locked` against the fund-flow identity
    ///   `funded - released - refunded - rehomed` (conservation the
    ///   fold maintains: `locked + released + refunded + rehomed ==
    ///   inflow`, where `rehomed` is the Σ an `EscrowSplit` re-locked
    ///   sideways into child escrows).
    fn assert_consistent(ie: &IndexedEscrow, funded: u64, refunded: u64, rehomed: u64, ctx: &str) {
        let view = MaterializedView::replay(ie.escrow_id(), funded, ie.events())
            .unwrap_or_else(|e| panic!("{ctx}: replay failed: {e:?}"));
        let t = view.triple();
        let inner = ie.inner();
        assert_eq!(t.released, inner.released_amount(), "{ctx}: released");
        assert_eq!(t.refunded, refunded, "{ctx}: refunded");
        assert_eq!(
            t.locked,
            funded - t.released - t.refunded - rehomed,
            "{ctx}: locked fund-flow identity"
        );
    }

    #[test]
    fn fund_delta_covers_every_kind() {
        // Distinctive amounts so a misrouted field breaks loudly.
        const PAYOUT: u64 = 1_000;
        const FEE: u64 = 100;
        const REFUND: u64 = 700;
        const PENALTY: u64 = 50;
        for d in 0..=88u8 {
            let kind = EscrowEventKind::from_discriminant(d)
                .unwrap_or_else(|| panic!("missing discriminant {d}"));
            let event = synth(kind, 0, PAYOUT, FEE, REFUND, PENALTY);
            let got = fund_delta(event.kind, &event.amounts);
            // Exhaustive on purpose: adding a variant forces this test
            // to decide its fund semantics (never silently zero).
            let want: (u64, u64, u64) = match kind {
                EscrowEventKind::Released
                | EscrowEventKind::ReleasedSplit
                // AV-123: an intent-driven release books like Released.
                | EscrowEventKind::ReleaseViaIntent
                // AV-130: a checker-approved release books like Released.
                | EscrowEventKind::DualControlConfirmed
                | EscrowEventKind::Claimed
                // AV-149: the per-leg taker payout books like Released.
                | EscrowEventKind::ShareClaimed
                | EscrowEventKind::MilestoneReleased
                // AV-229: a partial slice books like the full
                // tranche release.
                | EscrowEventKind::MilestonePartiallyClaimed
                | EscrowEventKind::SubscriptionPeriodReleased
                // AV-95b: the per-leg taker payout books like Released.
                // AV-140: the larger leg's netting offset books like
                // Released (lockup shrank by the netted amount,
                // released grew by it).
                | EscrowEventKind::BasketReleased
                | EscrowEventKind::EscrowsNetted => (PAYOUT, PAYOUT, 0),
                EscrowEventKind::Cancelled
                | EscrowEventKind::PartiallyCancelled
                // AV-95b: the per-leg refund books like Cancelled.
                // AV-109: the deadman reclaim books like Cancelled.
                // AV-127: the audited partial-refund tranche books like
                // PartiallyCancelled.
                | EscrowEventKind::BasketCancelled
                | EscrowEventKind::DeadmanClaimed
                | EscrowEventKind::PartialRefunded => {
                    (REFUND, 0, REFUND)
                }
                EscrowEventKind::ExpiredCancelled
                | EscrowEventKind::ExpiredCranked
                // AV-95b: the per-leg expiry cancel books like
                // ExpiredCancelled.
                | EscrowEventKind::BasketExpiredCancelled => {
                    (REFUND + PENALTY, 0, REFUND + PENALTY)
                }
                EscrowEventKind::Resolved
                | EscrowEventKind::DefaultJudgment
                | EscrowEventKind::PanelResolved => (PAYOUT + REFUND, PAYOUT, REFUND),
                EscrowEventKind::EscrowSplit => (PAYOUT, 0, 0),
                EscrowEventKind::Initialized
                | EscrowEventKind::Activated
                | EscrowEventKind::Funded
                | EscrowEventKind::Attested
                | EscrowEventKind::Escalated
                | EscrowEventKind::MilestoneConfirmed
                | EscrowEventKind::MilestoneSkipped
                // AV-232: restoring a skipped tranche moves no funds.
                | EscrowEventKind::MilestoneUnskipped
                // AV-203: a delivery confirmation moves no funds.
                | EscrowEventKind::DeliveryConfirmed
                // AV-223: chain link / break move no funds.
                | EscrowEventKind::ChainLinked
                | EscrowEventKind::ChainBroken
                | EscrowEventKind::QuorumUpdated
                | EscrowEventKind::AttestorsUpdated
                // AV-154: a quorum key rotation moves no funds.
                | EscrowEventKind::AttestorReplaced
                // AV-155: a milestone repricing moves no funds.
                | EscrowEventKind::MilestonesAmended
                | EscrowEventKind::MilestonesReallocated
                // AV-225: an expired claim moves no funds (same
                // reclassification rule as the production fold).
                | EscrowEventKind::MilestoneClaimExpired
        // AV-226: appending a tranche moves no funds — the tranche
        // is carved from the skipped remainder, not paid out now;
        // the later tranche release carries the amount with its fee.
        | EscrowEventKind::MilestoneTrancheAppended
        // AV-227: amending the roster moves no funds — the new
        // shares price only at the later claim_share pulls.
        | EscrowEventKind::ClaimantRosterAmended
        // AV-230: revising the schedule moves no funds — the new
        // table prices only at the later claim pulls.
        | EscrowEventKind::VestingScheduleAmended
        // AV-231: a revised deadline table moves no funds — the new
        // dates price late penalties only at the later releases.
        | EscrowEventKind::MilestoneDueDatesAmended
        // AV-233: a revised fee rate moves no funds.
        | EscrowEventKind::ProtocolFeeAmended
        // AV-234: a rotated verifier moves no funds.
        | EscrowEventKind::MilestoneVerifierRotated
        // AV-235: a revised arbiter fee moves no funds.
        | EscrowEventKind::ArbiterFeeAmended
        // AV-236: a revised appeal window moves no funds — the new
        // window stamps only the later slashes' appeal deadlines.
        | EscrowEventKind::AppealWindowAmended
        // AV-237: a revised slash ladder moves no funds.
        | EscrowEventKind::SlashLadderAmended
        // AV-238: a revised appeal bond moves no funds.
        | EscrowEventKind::AppealBondAmended
        // AV-240: a revised grace period moves no funds.
        | EscrowEventKind::GracePeriodAmended
        // AV-241: a revised evidence deadline moves no funds.
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
                | EscrowEventKind::PayoutAllowlistUpdated
                // AV-96: a config change — no fund movement.
                | EscrowEventKind::DenylistUpdated
                | EscrowEventKind::TakerRotated
                | EscrowEventKind::InitializerRotated
                | EscrowEventKind::ExpiryExtended
                | EscrowEventKind::ArbiterRotated
                | EscrowEventKind::PanelJudgment
                // AV-137: a blind commit moves no funds; a reveal's
                // payout is the revealed (not executed) split.
                | EscrowEventKind::JudgmentCommitted
                | EscrowEventKind::JudgmentRevealed
                | EscrowEventKind::FeeRecipientRotated
                | EscrowEventKind::EvidenceSubmitted
                | EscrowEventKind::PanelThresholdChanged
                | EscrowEventKind::MilestonesAdjusted
                | EscrowEventKind::SubscriptionAmountsAdjusted
                | EscrowEventKind::SchemaMigrated
                | EscrowEventKind::BundlePartiallyExecuted
                | EscrowEventKind::TemplateApplied
                | EscrowEventKind::VaultsBatchClosed
                | EscrowEventKind::CpiAllowlistUpdated
                // AV-122: negotiation state flips — no fund movement.
                | EscrowEventKind::Declined
                | EscrowEventKind::CounterOfferProposed
                | EscrowEventKind::CounterOfferAccepted
                | EscrowEventKind::CounterOfferRejected
                | EscrowEventKind::AppealFiled
                | EscrowEventKind::AppealResolved
                | EscrowEventKind::AppealExpired
                | EscrowEventKind::EvidenceFiled
                // AV-150: the vesting unlock clock freezes / restarts —
                // a Funded → Funded schedule-config flip, no funds move.
                | EscrowEventKind::VestingPaused
                | EscrowEventKind::VestingResumed
                // AV-174: a protocol-fee withdrawal — the fee already
                // left the fold's `locked` at payout time as part of
                // the gross release (the AV-17 routing-slice rule).
                | EscrowEventKind::FeeWithdrawn
                // AV-104: config changes — no fund movement.
                | EscrowEventKind::DelegationGranted
                | EscrowEventKind::DelegationRevoked
                // AV-105: a config change — no fund movement.
                | EscrowEventKind::SwapLinked
                // AV-110: a rent top-up moves no escrow funds (rent
                // sits outside the lockup).
                | EscrowEventKind::RentToppedUp
                // AV-139: a rent sweep moves no escrow funds.
                | EscrowEventKind::RentSwept
                // AV-111: a funding tranche is the fold seed's inflow
                // leg — the fold seeds the lockup with the deal size
                // at `Funded`, so the tranche books nothing.
                | EscrowEventKind::TrancheFunded
                // AV-148: the taker's counter-fund is the fold seed's
                // inflow leg — the fold seeds the lockup with the
                // bilateral total at `Funded`, so the counter-fund
                // books nothing.
                | EscrowEventKind::TakerFunded
                // AV-112: release-intent governance signals move no
                // escrow funds.
                | EscrowEventKind::ReleaseIntentAnnounced
                | EscrowEventKind::ReleaseIntentVetoed
                // AV-130: the maker-checker declaration and its abort
                // move no escrow funds either.
                | EscrowEventKind::DualControlInitiated
                | EscrowEventKind::DualControlCancelled
                // AV-114: the survivor's locked increment rides the
                // event's payout leg, applied directly in `apply` —
                // `fund_delta` books nothing.
                | EscrowEventKind::EscrowsMerged
                // AV-124: the bounty pool is additional inflow outside
                // the principal (the AV-103 appeal-bond precedent), so
                // the payout books nothing — like Slashed's parked
                // penalty outflow.
                | EscrowEventKind::KeeperBountyPaid
                | EscrowEventKind::Slashed => (0, 0, 0),
            };
            assert_eq!(got, want, "delta for {kind:?} (discriminant {d})");
        }
    }

    #[test]
    fn fold_tracks_merge_inflow_and_source_exit() {
        // AV-114: the survivor's `EscrowsMerged` grows `locked` by the
        // merged-in amount (the fold's only inflow); the source's
        // `Cancelled` drops its `locked` to zero.
        let merged = synth(EscrowEventKind::EscrowsMerged, 0, 400_000, 0, 0, 0);
        let view =
            MaterializedView::replay(ID, 1_000_000, &[merged]).unwrap();
        assert_eq!(
            view.triple(),
            FundsTriple {
                locked: 1_400_000,
                released: 0,
                refunded: 0,
            }
        );
        let cancelled = EscrowEvent {
            kind: EscrowEventKind::Cancelled,
            ..synth(EscrowEventKind::Cancelled, 0, 0, 0, 400_000, 0)
        };
        let view =
            MaterializedView::replay(ID, 400_000, &[cancelled]).unwrap();
        assert_eq!(
            view.triple(),
            FundsTriple {
                locked: 0,
                released: 0,
                refunded: 400_000,
            }
        );
    }

    #[test]
    fn fold_tracks_netting_offset_on_both_legs() {
        // AV-140: the larger leg's `EscrowsNetted` shrinks `locked` by
        // the netted amount and grows `released` by it (zero-payout
        // settlement — no transfer). The smaller leg's `Released`
        // carries a zero payout (the netting signature); the fold
        // moves its whole remaining lockup sideways into `released`,
        // mirroring the state machine's `released := amount`
        // bookkeeping bit-for-bit.
        let netted = synth(EscrowEventKind::EscrowsNetted, 0, 700_000, 0, 0, 0);
        let view =
            MaterializedView::replay(ID, 1_000_000, &[netted]).unwrap();
        assert_eq!(
            view.triple(),
            FundsTriple {
                locked: 300_000,
                released: 700_000,
                refunded: 0,
            }
        );
        let settled = EscrowEvent {
            kind: EscrowEventKind::Released,
            to: EscrowState::Released,
            ..synth(EscrowEventKind::Released, 0, 0, 0, 0, 0)
        };
        let view =
            MaterializedView::replay(ID, 700_000, &[settled]).unwrap();
        assert_eq!(
            view.triple(),
            FundsTriple {
                locked: 0,
                released: 700_000,
                refunded: 0,
            }
        );
    }

    #[test]
    fn fold_books_keeper_bounty_as_noop() {
        // AV-124: the bounty pool is additional inflow outside the
        // principal (the AV-103 appeal-bond precedent) — the fold
        // never booked it, so the payout moves nothing in the triple.
        let bounty = synth(EscrowEventKind::KeeperBountyPaid, 0, 10_000, 0, 0, 0);
        let view = MaterializedView::replay(ID, 1_000_000, &[bounty]).unwrap();
        assert_eq!(
            view.triple(),
            FundsTriple {
                locked: 1_000_000,
                released: 0,
                refunded: 0,
            },
            "bounty payout leaves the fold triple untouched"
        );
    }

    #[test]
    fn apply_enforces_seq_continuity() {
        // Happy path.
        let mut view = MaterializedView::replay(ID, 1_000, &seq_events(&[0, 1, 2])).unwrap();
        assert_eq!(view.next_seq(), 3);
        assert_eq!(
            view.triple(),
            FundsTriple {
                locked: 970,
                released: 30,
                refunded: 0
            }
        );

        // Gap: seq 2 missing — stops, keeps the valid prefix, and the
        // caller resumes from next_seq.
        let mut view = MaterializedView::replay(ID, 1_000, &[]).unwrap();
        let err = view.apply(&seq_events(&[0, 1, 3])).unwrap_err();
        assert_eq!(err, EscrowError::GapInEventStream);
        assert_eq!(err.code(), 151);
        assert_eq!(view.next_seq(), 2);
        assert_eq!(view.triple().released, 20);
        view.apply(&seq_events(&[2, 3])).unwrap();
        assert_eq!(view.next_seq(), 4);
        assert_eq!(view.triple().released, 40);

        // Out-of-order.
        let mut view = MaterializedView::replay(ID, 1_000, &[]).unwrap();
        assert_eq!(
            view.apply(&seq_events(&[0, 2, 1])).unwrap_err(),
            EscrowError::GapInEventStream
        );
        assert_eq!(view.next_seq(), 1);

        // Duplicate seq.
        let mut view = MaterializedView::replay(ID, 1_000, &[]).unwrap();
        assert_eq!(
            view.apply(&seq_events(&[0, 1, 1])).unwrap_err(),
            EscrowError::GapInEventStream
        );
        assert_eq!(view.next_seq(), 2);

        // Foreign escrow_id is a stream-integrity break like any other.
        let mut view = MaterializedView::replay(ID, 1_000, &[]).unwrap();
        let mut foreign = synth(EscrowEventKind::Released, 0, 10, 1, 0, 0);
        foreign.escrow_id = [0xFF; 32];
        assert_eq!(
            view.apply(&[foreign]).unwrap_err(),
            EscrowError::GapInEventStream
        );
        assert_eq!(view.next_seq(), 0);
    }

    #[test]
    fn from_snapshot_seeds_base_and_next_seq() {
        let mut ie =
            IndexedEscrow::initialize(ALICE, BOB, 1_000_000, NOW + 1_000_000, ID, NOW).unwrap();
        ie.fund(ALICE, NOW).unwrap();
        ie.release(ALICE, 100_000, None, BOB, NOW).unwrap();
        // seq: 0 = Initialized, 1 = Funded, 2 = Released.
        let snap = ie.inner().snapshot(NOW);
        let view = MaterializedView::from_snapshot(ID, &snap, 2);
        assert_eq!(view.escrow_id(), ID);
        assert_eq!(view.next_seq(), 3);
        assert_eq!(
            view.triple(),
            FundsTriple {
                locked: 900_000,
                released: 100_000,
                refunded: 0,
            }
        );
    }

    #[test]
    fn from_snapshot_terminal_state_parks_only_penalty_in_locked() {
        // Slash then full cancel: the snapshot's `remaining` is the
        // audit-preserved refund, not locked funds — seeding `locked`
        // from it would resurrect exited funds.
        let mut ie =
            IndexedEscrow::initialize(ALICE, BOB, 1_000_000, NOW + 1_000_000, ID, NOW).unwrap();
        ie = ie.with_slash_terms(PEN, NOW - 1).unwrap();
        ie.fund(ALICE, NOW).unwrap();
        ie.slash(ALICE, 200_000, None, NOW).unwrap();
        ie.cancel(ALICE, None, ALICE, NOW).unwrap();
        let snap = ie.inner().snapshot(NOW);
        assert_eq!(snap.state, "cancelled");
        let last_seq = ie.next_seq() - 1;
        let view = MaterializedView::from_snapshot(ID, &snap, last_seq);
        assert_eq!(view.triple().locked, 200_000);
        assert_eq!(view.triple().released, 0);
        // `refunded` counts from the snapshot point on (the snapshot
        // carries no cumulative refunded counter) — the genesis replay
        // booked the 800_000 cancel refund, so only locked/released
        // agree here by construction.
        let replayed = MaterializedView::replay(ID, 1_000_000, ie.events()).unwrap();
        assert_eq!(replayed.triple().locked, view.triple().locked);
        assert_eq!(replayed.triple().released, view.triple().released);
        assert_eq!(replayed.triple().refunded, 800_000);
    }

    #[test]
    fn replay_equals_snapshot_base_plus_incremental() {
        let mut ie =
            IndexedEscrow::initialize(ALICE, BOB, 1_000_000, NOW + 1_000_000, ID, NOW).unwrap();
        ie = ie.with_protocol_fee(250).unwrap();
        ie.fund(ALICE, NOW).unwrap();
        ie.release(ALICE, 100_000, None, BOB, NOW).unwrap();
        ie.release(ALICE, 50_000, None, BOB, NOW).unwrap();
        // Snapshot right after seq 3
        // (Initialized=0, Funded=1, Released=2, Released=3) — before
        // any refund, so the refunded base (0) is exact.
        let snap_seq = 3;
        let snap = ie.inner().snapshot(NOW);
        ie.cancel_partial(ALICE, 70_000, None, ALICE, NOW).unwrap();
        ie.release(ALICE, 30_000, None, BOB, NOW).unwrap();

        let events = ie.events();
        let pure = MaterializedView::replay(ID, 1_000_000, events).unwrap();
        let mut via_snapshot = MaterializedView::from_snapshot(ID, &snap, snap_seq);
        via_snapshot
            .apply(&events[(snap_seq + 1) as usize..])
            .unwrap();
        assert_eq!(pure.triple(), via_snapshot.triple());
        assert_eq!(pure.next_seq(), via_snapshot.next_seq());
        assert_eq!(
            pure.triple(),
            FundsTriple {
                locked: 750_000,
                released: 180_000,
                refunded: 70_000,
            }
        );
    }

    #[test]
    fn fold_matches_state_machine_release_claim_slash_split_resolve() {
        // Rich lifecycle: fee, vesting (claim), slash terms, payout
        // allowlist (release_split), arbiter (resolve). Every step
        // asserts the fold against the live state machine.
        let mut ie =
            IndexedEscrow::initialize(ALICE, BOB, 1_000_000, NOW + 1_000_000, ID, NOW).unwrap();
        ie = ie.with_protocol_fee(250).unwrap();
        ie = ie
            .with_vesting(VestingSchedule::new(NOW - 500_000, NOW + 500_000).unwrap())
            .unwrap();
        ie = ie.with_slash_terms(PEN, NOW - 1).unwrap();
        ie = ie.with_arbiter(ARB).unwrap();
        ie.update_payout_allowlist(ALICE, BOB, &[BOB, CAROL], NOW)
            .unwrap();
        ie.fund(ALICE, NOW).unwrap();
        assert_consistent(&ie, 1_000_000, 0, 0, "funded");

        // release 100_000 gross (fee 2_500).
        ie.release(ALICE, 100_000, None, BOB, NOW).unwrap();
        assert_consistent(&ie, 1_000_000, 0, 0, "release");
        assert_eq!(ie.inner().released_amount(), 100_000);

        // claim: vested 500_000 - released 100_000 = 400_000 gross.
        ie.claim(BOB, NOW, None, BOB).unwrap();
        assert_consistent(&ie, 1_000_000, 0, 0, "claim");
        assert_eq!(ie.inner().released_amount(), 500_000);

        // partial cancel refunds 50_000; the locked total shrinks.
        ie.cancel_partial(ALICE, 50_000, None, ALICE, NOW).unwrap();
        assert_consistent(&ie, 1_000_000, 50_000, 0, "cancel_partial");

        // slash: the fold books nothing — released excludes the
        // penalty, locked is unchanged (the penalty parks inside it).
        ie.slash(ALICE, 80_000, None, NOW).unwrap();
        assert_consistent(&ie, 1_000_000, 50_000, 0, "slash");
        assert_eq!(ie.inner().penalty_paid(), 80_000);

        // release_split 200_000 gross (fee 5_000): released books the
        // gross, like `release`.
        ie.release_split(ALICE, 200_000, None, &[(BOB, 5_000), (CAROL, 5_000)], NOW)
            .unwrap();
        assert_consistent(&ie, 1_000_000, 50_000, 0, "release_split");
        assert_eq!(ie.inner().released_amount(), 700_000);

        // dispute + resolve: taker 100_000 gross into released,
        // initializer 70_000 into refunded.
        ie.escalate(ALICE, NOW, ie.inner().remaining_amount(), None, None, 0).unwrap();
        assert_consistent(&ie, 1_000_000, 50_000, 0, "escalate");
        ie.resolve(ARB, 100_000, None, None, BOB, NOW).unwrap();
        assert_consistent(&ie, 1_000_000, 120_000, 0, "resolve");
        let t = MaterializedView::replay(ID, 1_000_000, ie.events())
            .unwrap()
            .triple();
        assert_eq!(
            t,
            FundsTriple {
                locked: 80_000,
                released: 800_000,
                refunded: 120_000,
            }
        );
    }

    #[test]
    fn fold_matches_state_machine_milestones_and_split() {
        // Milestone tranches, a skip (zero fold delta — the tranche
        // stays locked until the later refund counts it once), then a
        // split: the parent's Σ re-locks sideways, children fold their
        // own logs, and the fleet aggregate conserves.
        let mut ie =
            IndexedEscrow::initialize(ALICE, BOB, 900_000, NOW + 1_000_000, ID, NOW).unwrap();
        ie = ie
            .with_milestones(MilestonePlan::new(&[300_000, 300_000, 300_000]).unwrap())
            .unwrap();
        ie.fund(ALICE, NOW).unwrap();

        ie.confirm_milestone(ALICE, 0, NOW).unwrap();
        ie.confirm_milestone(BOB, 0, NOW).unwrap();
        ie.release_milestone(ALICE, 0, None, BOB, NOW).unwrap();
        assert_consistent(&ie, 900_000, 0, 0, "milestone release");
        assert_eq!(ie.inner().released_amount(), 300_000);

        // Skip tranche 1: both approvals, then the skip executes. The
        // tranche joins the refundable remainder — still locked — so
        // the fold is unchanged.
        ie.confirm_milestone(ALICE, 1, NOW).unwrap();
        ie.confirm_milestone(BOB, 1, NOW).unwrap();
        ie.skip_milestone(ALICE, 1, NOW).unwrap();
        ie.skip_milestone(BOB, 1, NOW).unwrap();
        assert_consistent(&ie, 900_000, 0, 0, "milestone skip");
        assert_eq!(ie.inner().remaining_amount(), 600_000);

        let children = ie
            .split_escrow(ALICE, BOB, &[300_000, 300_000], SplitConfig::default(), NOW)
            .unwrap();
        assert_eq!(children.len(), 2);
        assert_consistent(&ie, 900_000, 0, 600_000, "split parent");
        let parent_view = MaterializedView::replay(ID, 900_000, ie.events()).unwrap();
        assert_eq!(
            parent_view.triple(),
            FundsTriple {
                locked: 0,
                released: 300_000,
                refunded: 0,
            }
        );

        // Each child folds its own log under its derived id.
        let mut views = vec![parent_view];
        for child in &children {
            let cv = MaterializedView::replay(child.escrow_id(), 300_000, child.events()).unwrap();
            assert_eq!(
                cv.triple(),
                FundsTriple {
                    locked: 300_000,
                    released: 0,
                    refunded: 0,
                }
            );
            views.push(cv);
        }
        let fleet = fold_fleet(&views);
        assert_eq!(
            fleet,
            FleetFunds {
                locked: 600_000,
                released: 300_000,
                refunded: 0,
                escrow_count: 3,
            }
        );
    }

    /// xorshift64*: deterministic, dependency-free (the AV-03 / AV-08
    /// harness convention).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            // Never zero: xorshift with a zero state never advances.
            if x == 0 {
                x = 0x9E3779B97F4A7C15;
            }
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    #[test]
    fn fold_matches_state_machine_on_random_op_sequences() {
        const SEEDS: u64 = 8;
        const OPS: usize = 48;
        for seed in 0..SEEDS {
            let mut rng = Rng(
                0x9E3779B97F4A7C15u64.wrapping_add(seed.wrapping_mul(0xBF58476D1CE4E5B9)),
            );
            let amount = 1 + rng.below(1_000_000_000);
            let fee_bps = [0u16, 100, 500][rng.below(3) as usize];
            let penalty_bps = [0u16, 0, 1_000][rng.below(3) as usize];
            let escrow_id = [seed as u8; 32];
            let expires_at = NOW + 100_000;

            let mut ie =
                IndexedEscrow::initialize(ALICE, BOB, amount, expires_at, escrow_id, NOW).unwrap();
            if fee_bps > 0 {
                ie = ie.with_protocol_fee(fee_bps).unwrap();
            }
            if penalty_bps > 0 {
                ie = ie.with_penalty_bps(penalty_bps).unwrap();
            }
            ie = ie
                .with_vesting(VestingSchedule::new(NOW - 500_000, NOW + 500_000).unwrap())
                .unwrap();
            ie = ie.with_slash_terms(PEN, NOW - 1).unwrap();
            ie = ie.with_arbiter(ARB).unwrap();
            ie.update_payout_allowlist(ALICE, BOB, &[BOB, CAROL], NOW)
                .unwrap();
            ie.fund(ALICE, NOW).unwrap();

            let mut refunded = 0u64;
            let mut slashed = false;
            for _ in 0..OPS {
                let remaining = ie.inner().remaining_amount();
                let op = rng.below(10);
                let applied = match op {
                    0..=2 => {
                        if remaining == 0 {
                            false
                        } else {
                            let amt = 1 + rng.below(remaining);
                            ie.release(ALICE, amt, None, BOB, NOW).is_ok()
                        }
                    }
                    3 => ie.claim(BOB, NOW, None, BOB).is_ok(),
                    4 => {
                        if remaining == 0 {
                            false
                        } else {
                            let amt = 1 + rng.below(remaining);
                            match ie.cancel_partial(ALICE, amt, None, ALICE, NOW) {
                                Ok(got) => {
                                    refunded += got;
                                    true
                                }
                                Err(_) => false,
                            }
                        }
                    }
                    5 => {
                        if slashed || remaining == 0 {
                            false
                        } else {
                            let amt = 1 + rng.below(remaining);
                            if ie.slash(ALICE, amt, None, NOW).is_ok() {
                                slashed = true;
                                true
                            } else {
                                false
                            }
                        }
                    }
                    6 => {
                        if remaining == 0 {
                            false
                        } else {
                            let amt = 1 + rng.below(remaining);
                            ie.release_split(
                                ALICE,
                                amt,
                                None,
                                &[(BOB, 5_000), (CAROL, 5_000)],
                                NOW,
                            )
                            .is_ok()
                        }
                    }
                    7 => {
                        // Dispute terminal path.
                        if ie.escalate(ALICE, NOW, ie.inner().remaining_amount(), None, None, 0).is_ok() {
                            let rem = ie.inner().remaining_amount();
                            let taker_amt = rng.below(rem + 1);
                            match ie.resolve(ARB, taker_amt, None, None, BOB, NOW) {
                                Ok((_, _, r)) => {
                                    refunded += r;
                                    true
                                }
                                Err(_) => false,
                            }
                        } else {
                            false
                        }
                    }
                    8 => match ie.cancel(ALICE, None, ALICE, NOW) {
                        Ok((_init_refund, _taker_refund)) => {
                            refunded += ie.inner().remaining_amount();
                            true
                        }
                        Err(_) => false,
                    },
                    _ => match ie.cancel_expired(BOB, expires_at + 1, None, ALICE) {
                        Ok((r, _, p)) => {
                            // The AV-24 penalty routes to the
                            // initializer as compensation: an
                            // initializer receipt, like the refund.
                            refunded += r + p;
                            true
                        }
                        Err(_) => false,
                    },
                };
                if applied {
                    assert_consistent(&ie, amount, refunded, 0, &format!("seed {seed}"));
                }
                if matches!(
                    ie.inner().state(),
                    EscrowState::Released | EscrowState::Cancelled | EscrowState::Settled
                ) {
                    break;
                }
            }
            assert_consistent(&ie, amount, refunded, 0, &format!("seed {seed} final"));
        }
    }
}

