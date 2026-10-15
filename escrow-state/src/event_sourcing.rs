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
//!   `MilestoneReleased`, `SubscriptionPeriodReleased`) book the
//!   **gross** amount: the AV-17 protocol fee is an internal routing
//!   slice of the gross (`payout` already includes it), matching the
//!   state machine's `released` counter bit-for-bit.
//! * Initializer refunds (`Cancelled`, `PartiallyCancelled`,
//!   `ExpiredCancelled`, `ExpiredCranked`) book `refunded`. The AV-24
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
        | EscrowEventKind::QuorumUpdated
        | EscrowEventKind::AttestorsUpdated
        | EscrowEventKind::EmergencyUnlock
        | EscrowEventKind::VaultClosed
        | EscrowEventKind::ReentryRejected
        | EscrowEventKind::Paused
        | EscrowEventKind::Unpaused
        | EscrowEventKind::PauseAuthorityRotated
        | EscrowEventKind::PayoutAllowlistUpdated
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
        // A panel vote moves no funds — and `PanelJudgment`'s `payout`
        // is the *voted* split, not an executed one, so booking it
        // would invent a payout; only the settling `PanelResolved`
        // moves funds.
        | EscrowEventKind::PanelJudgment
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
        | EscrowEventKind::AppealResolved => (0, 0, 0),
        // Taker payouts, gross (AV-17: the fee is an internal routing
        // slice of the gross — `payout` already includes it, matching
        // `Escrow::released_amount`). `ReleasedSplit` (AV-93) likewise
        // books the gross: the per-recipient net legs split
        // `payout - fee`, they are not additional movement.
        EscrowEventKind::Released
        | EscrowEventKind::ReleasedSplit
        | EscrowEventKind::Claimed
        | EscrowEventKind::MilestoneReleased
        | EscrowEventKind::SubscriptionPeriodReleased
        // AV-95b: one basket leg paid out to the taker — the per-leg
        // `Released`; the leg's gross books as `released`, like the
        // plain kind.
        | EscrowEventKind::BasketReleased => {
            (amounts.payout, amounts.payout, 0)
        }
        // Initializer refunds. `Cancelled` refunds the remainder;
        // `PartiallyCancelled` refunds the tranche (the state machine
        // shrinks `amount`, so `locked` drops by the same).
        // AV-95b: one basket leg refunded — the per-leg `Cancelled`.
        EscrowEventKind::Cancelled
        | EscrowEventKind::PartiallyCancelled
        | EscrowEventKind::BasketCancelled => {
            (amounts.refund, 0, amounts.refund)
        }
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
            self.triple.locked = self.triple.locked.saturating_sub(locked_dec);
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
        for d in 0..=50u8 {
            let kind = EscrowEventKind::from_discriminant(d)
                .unwrap_or_else(|| panic!("missing discriminant {d}"));
            let event = synth(kind, 0, PAYOUT, FEE, REFUND, PENALTY);
            let got = fund_delta(event.kind, &event.amounts);
            // Exhaustive on purpose: adding a variant forces this test
            // to decide its fund semantics (never silently zero).
            let want: (u64, u64, u64) = match kind {
                EscrowEventKind::Released
                | EscrowEventKind::ReleasedSplit
                | EscrowEventKind::Claimed
                | EscrowEventKind::MilestoneReleased
                | EscrowEventKind::SubscriptionPeriodReleased
                // AV-95b: the per-leg taker payout books like Released.
                | EscrowEventKind::BasketReleased => (PAYOUT, PAYOUT, 0),
                EscrowEventKind::Cancelled
                | EscrowEventKind::PartiallyCancelled
                // AV-95b: the per-leg refund books like Cancelled.
                | EscrowEventKind::BasketCancelled => {
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
                | EscrowEventKind::QuorumUpdated
                | EscrowEventKind::AttestorsUpdated
                | EscrowEventKind::EmergencyUnlock
                | EscrowEventKind::VaultClosed
                | EscrowEventKind::ReentryRejected
                | EscrowEventKind::Paused
                | EscrowEventKind::Unpaused
                | EscrowEventKind::PauseAuthorityRotated
                | EscrowEventKind::PayoutAllowlistUpdated
                | EscrowEventKind::TakerRotated
                | EscrowEventKind::InitializerRotated
                | EscrowEventKind::ExpiryExtended
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
                | EscrowEventKind::CpiAllowlistUpdated
                | EscrowEventKind::AppealFiled
                | EscrowEventKind::AppealResolved
                | EscrowEventKind::EvidenceFiled
                | EscrowEventKind::Slashed => (0, 0, 0),
            };
            assert_eq!(got, want, "delta for {kind:?} (discriminant {d})");
        }
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
        ie.escalate(ALICE, NOW, None, None, 0).unwrap();
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
                        if ie.escalate(ALICE, NOW, None, None, 0).is_ok() {
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
                        Ok(()) => {
                            refunded += ie.inner().remaining_amount();
                            true
                        }
                        Err(_) => false,
                    },
                    _ => match ie.cancel_expired(BOB, expires_at + 1, None, ALICE) {
                        Ok((r, p)) => {
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

