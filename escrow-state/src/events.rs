//! Typed indexer events for every state transition (AV-18).
//!
//! [`IndexedEscrow`] is an event-logging adapter over [`Escrow`]: it
//! exposes the same mutating transitions and builders, delegates to the
//! inner state machine, and records exactly one [`EscrowEvent`] per
//! successful transition. A chain indexer subscribes to state changes in
//! per-escrow [`EscrowEvent::seq`] order instead of polling account data.
//!
//! # Emission rule
//!
//! An event fires exactly when a successful call changes
//! externally-observable state: the [`EscrowState`] variant, a fund
//! counter (`released`), the quorum's approval count, or a milestone's
//! confirmed / settled status. Failed calls emit nothing, and neither do
//! successful calls that change nothing observable:
//!
//! - `initialize` always emits [`EscrowEventKind::Initialized`] (`seq` 0).
//!   The constructor has no prior state, so `from == to == Uninitialized`
//!   by convention.
//! - `activate` emits [`EscrowEventKind::Activated`] only when the call
//!   actually flips `Uninitialized -> Activated`. A single party's
//!   signature (or an idempotent re-affirmation) emits nothing — the
//!   indexer learns both signatures landed from the one `Activated`
//!   event.
//! - `attest` emits [`EscrowEventKind::Attested`] when it records a *new*
//!   attestation (the quorum's approval count grows). Duplicate
//!   attestations are idempotent in the state machine and emit nothing.
//!   Quorum progress matters to indexers — an attestor-gated `release`
//!   becomes legal only at the threshold — so each distinct vote is
//!   visible; `from == to ==` the current state.
//! - `confirm_milestone` emits [`EscrowEventKind::MilestoneConfirmed`]
//!   when the milestone becomes fully confirmed (the completing vote).
//!   The first party's confirmation alone emits nothing, paralleling
//!   `activate`; `from == to == Funded`.
//! - `skip_milestone` emits [`EscrowEventKind::MilestoneSkipped`] only
//!   when the skip executes (both approvals present). A lone approval
//!   emits nothing; `from == to == Funded`, and `amounts.refund` carries
//!   the skipped tranche (the initializer's refund).
//! - A keeper milestone bundle
//!   ([`crate::keeper::execute_milestone_bundle`], AV-76) emits one
//!   [`EscrowEventKind::MilestoneReleased`] per executed tranche and,
//!   when the bundle executed a *proper subset* of the configured
//!   tranches, a trailing
//!   [`EscrowEventKind::BundlePartiallyExecuted`] — `from == to ==
//!   Funded` (a proper subset can never settle the vault), the executed
//!   tranches' totals in `amounts` (gross in `payout`, protocol fees in
//!   `fee`, like `MilestoneReleased`), no actor (the bundle is a keeper
//!   composition, not a single authority). A full execution emits no
//!   partial event — only the per-tranche `MilestoneReleased` events.
//! - `update_quorum` emits [`EscrowEventKind::QuorumUpdated`] when the
//!   threshold actually changes (AV-25) — `from == to ==` the current
//!   state, all amounts zero: the event is the ordering signal that the
//!   release gate moved, and the indexer reads the new threshold from
//!   the vault (paralleling `Attested`, which likewise does not carry
//!   the vote itself). A no-op update (same threshold) emits nothing,
//!   paralleling `attest`'s idempotent duplicates.
//! - `update_attestors` emits [`EscrowEventKind::AttestorsUpdated`] when
//!   the attestor set actually changes (AV-39) — `from == to ==` the
//!   current state, all amounts zero: the event is the ordering signal
//!   that the release gate's electorate changed, and the indexer reads
//!   the new set from the vault (approval bits are remapped by pubkey,
//!   so a retained attestor's vote survives; a removed attestor's bit
//!   is cleared). A no-op update (the identical set, same order) emits
//!   nothing, paralleling `update_quorum`'s no-op rule.
//! - `rotate_taker` emits [`EscrowEventKind::TakerRotated`] when the
//!   taker actually changes (AV-52) — `from == to ==` the current
//!   state, all amounts zero: the event is the ordering signal that the
//!   payout counterparty moved, and the indexer reads the new taker
//!   from the vault. A no-op rotation (same taker) emits nothing,
//!   paralleling `update_quorum`'s no-op rule.
//! - `rotate_initializer` emits [`EscrowEventKind::InitializerRotated`]
//!   when the initializer actually changes (AV-58) — the exact mirror
//!   of `rotate_taker`'s emission rule: `from == to ==` the current
//!   state, all amounts zero; a no-op rotation emits nothing.
//! - `rotate_arbiter` emits [`EscrowEventKind::ArbiterRotated`]
//!   when the arbiter actually changes (AV-62) — the exact mirror
//!   of `rotate_initializer`'s emission rule: `from == to ==` the
//!   current state, all amounts zero; a no-op rotation emits nothing.
//!   A rotation with no arbiter configured is rejected, so the event
//!   can never fire on an arbiter-less escrow.
//! - `rotate_fee_recipient` emits [`EscrowEventKind::FeeRecipientRotated`]
//!   when the fee recipient actually changes (AV-67) — the exact
//!   mirror of `rotate_arbiter`'s emission rule: `from == to ==` the
//!   current state, all amounts zero; a no-op rotation emits nothing.
//!   A rotation with no fee recipient configured is rejected, so the
//!   event can never fire on a recipient-less escrow.
//! - `submit_panel_judgment` emits [`EscrowEventKind::PanelJudgment`]
//!   on every successful vote (AV-65) — `from == to == Disputed`, the
//!   member's key in `caller`, the voted split in `amounts.payout`:
//!   the vote is the ordering signal and the indexer reads the live
//!   tally from the vault. Re-votes emit too — an overwritten vote
//!   stays in the log as the audit trail. When the vote is the M-th
//!   match, [`EscrowEventKind::PanelResolved`] follows (`Disputed ->
//!   Settled`, the `Resolved` amounts shape, the winning vote's
//!   rationale) — the vote event first, then the settlement.
//! - `extend_expiry` emits [`EscrowEventKind::ExpiryExtended`] when the
//!   deadline moves (AV-59) — `from == to ==` the current state (a
//!   config change, not a lifecycle move), all amounts zero: the event
//!   is the ordering signal that the deadline moved, and the indexer
//!   reads the new `expires_at` (and the monotonic `extension_count`)
//!   from the vault.
//! - `cancel_partial` (AV-60) emits [`EscrowEventKind::PartiallyCancelled`]
//!   with `from == to == Funded`: the [`EscrowState`] variant does not
//!   change, but funds moved (a tranche of the lockup refunded to the
//!   AV-23-pinned destination) and the refund stream must be complete
//!   for the indexer — the exact mirror of a partial `Released` event.
//!   `amounts.refund` carries the partially-cancelled amount; the
//!   `released` counter is untouched.
//! - `adjust_milestone_amounts` emits
//!   [`EscrowEventKind::MilestonesAdjusted`] when the tranche amounts
//!   actually change (AV-70) — `from == to ==` the current state (a
//!   config change, not a lifecycle move, like `QuorumUpdated`), all
//!   amounts zero; a no-op re-affirmation emits nothing. The event is
//!   the ordering signal that the schedule moved, and the indexer
//!   reads the new tranche amounts from the vault.
//! - Partial `release` / `claim` calls emit [`EscrowEventKind::Released`]
//!   / [`EscrowEventKind::Claimed`] with `from == to == Funded`: the
//!   `EscrowState` variant does not change, but funds moved and the
//!   payout stream must be complete for the indexer. A closing payout
//!   has `to == Released`.
//! - `close_vault` (AV-34) emits [`EscrowEventKind::VaultClosed`] with
//!   `from` the terminal state the escrow was in (`Cancelled`,
//!   `Released` or `Settled`) and `to == Closed`:
//!   `amounts.rent_reclaimed` carries the rent-exempt lamports the
//!   initializer reclaimed, every other amount is zero.
//! - `release_and_close` (AV-50) emits `Released` and then
//!   `VaultClosed` in that fixed order: the payout first
//!   (`from == Funded`, `to == Released`, gross payout + fee), then the
//!   close (`from == Released`, `to == Closed`, `rent_reclaimed`).
//! - `close_indexed_vaults` (AV-79) emits one
//!   [`EscrowEventKind::VaultClosed`] per vault it actually closes
//!   (exactly the AV-34 emission, via `IndexedEscrow::close_vault`),
//!   then a single [`EscrowEventKind::VaultsBatchClosed`] summary on
//!   the first closed vault's log (`from == to == Closed`, a
//!   composition summary — not a lifecycle move — and
//!   `amounts.rent_reclaimed` is the Σ rent-exempt lamports the batch
//!   reclaimed). A batch that closes nothing emits no summary event
//!   (paralleling the no-op rules on `QuorumUpdated` et al).
//! - `split_escrow` (AV-81) emits [`EscrowEventKind::EscrowSplit`]
//!   with `from == Funded`, `to == Split` — the parent's lifecycle move
//!   into the new terminal state. `amounts.payout` carries the Σ child
//!   amounts (the gross re-locked into the children, equal to the
//!   parent's pre-split remaining lockup); every other amount is zero.
//!   The `(child_id, amount)` roster rides the event's `split_children`
//!   field, so the whole split family is re-derivable from the one
//!   event; the actor is `None` (dual-signed governance, like
//!   `TakerRotated`). Each child escrow gets its own log —
//!   `Initialized`, then `Funded` (and `Activated` between them when
//!   the children inherit dual-signature activation) — under its
//!   derived escrow ID, so every child's lifecycle is independently
//!   indexable. A failed split emits nothing: the parent stays
//!   `Funded` and no child exists.
//! - A rejected reentrant entry (AV-36) emits
//!   [`EscrowEventKind::ReentryRejected`] — the deliberate exception to
//!   the "failed calls emit nothing" rule. A blocked reentry is a
//!   security signal (a hostile CPI target attempting to re-enter the
//!   program mid-instruction), and the indexer must see it in `seq`
//!   order: `from == to ==` the current state, all amounts zero.
//! - The `with_*` builders (`with_quorum`, `with_mint`, …) are
//!   configuration, not transitions, and emit nothing.
//!
//! # Identity, sequence, and time
//!
//! - `escrow_id` is a caller-supplied 32-byte escrow identity. Off-chain
//!   callers pick any unique tag; the Anchor layer uses the vault PDA's
//!   public key (see `EscrowVaultEvent.vault` in
//!   `programs/escrow-vault/src/program.rs`).
//! - `seq` is a per-escrow monotonic counter starting at 0 for the
//!   `Initialized` event. It never resets — [`IndexedEscrow::drain_events`]
//!   clears the log but not the counter — so an indexer can resume from
//!   any checkpoint without re-reading history.
//! - `at` is a caller-supplied Unix-seconds timestamp (the crate has no
//!   clock). Transitions whose inner method already takes `now`
//!   (`cancel_expired`, `escalate`, `claim`) reuse `now` as `at` rather
//!   than taking a second timestamp; every other transition takes an
//!   explicit `at` parameter. On-chain, the Anchor program feeds `at`
//!   from the clock sysvar.
//!
//! # Amounts
//!
//! [`EventAmounts`] is one struct — not an enum or `Option`s — so
//! indexers deserialize a single shape for every kind. Fields are zero
//! when the kind moves no such value:
//!
//! | kind | `payout` | `fee` | `refund` | `penalty` |
//! |------|----------|-------|----------|-----------|
//! | Initialized, Activated, Funded, Escalated, Attested, MilestoneConfirmed, QuorumUpdated, AttestorsUpdated, EmergencyUnlock (AV-41), ReentryRejected (AV-36), PauseAuthorityRotated (AV-47), TakerRotated (AV-52), InitializerRotated (AV-58), ExpiryExtended (AV-59), PartiallyCancelled, ArbiterRotated (AV-62), FeeRecipientRotated (AV-67), EvidenceSubmitted (AV-68), PanelThresholdChanged (AV-69), MilestonesAdjusted (AV-70), SubscriptionAmountsAdjusted (AV-73), SchemaMigrated (AV-75), TemplateApplied (AV-77) | 0 | 0 | 0 | 0 |
//! | Released, Claimed, MilestoneReleased, SubscriptionPeriodReleased (AV-56) | gross taker amount (net payout + fee) | protocol fee (AV-17) | 0 | 0 |
//! | BundlePartiallyExecuted (AV-76) | Σ gross of the executed tranches | Σ protocol fee of the executed tranches | 0 | 0 |
//! | Cancelled | 0 | 0 | remainder refunded to the initializer | 0 |
//! | PartiallyCancelled (AV-60) | 0 | 0 | the partially-cancelled tranche, refunded to the whitelisted destination (the escrow stays `Funded`; the `released` counter is untouched) | 0 |
//! | ExpiredCancelled | 0 | 0 | remainder minus penalty, to the whitelisted destination | anti-griefing penalty to the initializer (AV-24; 0 unless taker-initiated with `penalty_bps > 0`) |
//! | ExpiredCranked (AV-48) | 0 | 0 | remainder minus penalty, to the whitelisted destination (the cranker receives nothing) | anti-griefing penalty to the initializer (AV-24; 0 unless the cranker is the taker) |
//! | Resolved | gross taker share (`taker_amount`) | protocol fee on the taker's share | initializer's share of the split | 0 |
//! | DefaultJudgment (AV-55) | gross taker share (`default_taker_amount`) | protocol fee on the taker's share | initializer's share of the split | 0 |
//! | PanelResolved (AV-65) | gross taker share (the winning vote's `taker_amount`) | protocol fee on the taker's share | initializer's share of the split | 0 |
//! | PanelJudgment (AV-65) | the voted split (`taker_amount`) | 0 | 0 | 0 |
//! | MilestoneSkipped | 0 | 0 | skipped tranche (the initializer's refund) | 0 |
//! | VaultClosed (AV-34) | 0 | 0 | 0 | 0 — the rent-exempt deposit reclaimed by the initializer on vault close is carried in `rent_reclaimed`, not in these four fields |
//! | VaultsBatchClosed (AV-79) | 0 | 0 | 0 | 0 — the Σ rent-exempt deposits reclaimed across the batch, carried in `rent_reclaimed` |
//! | EscrowSplit (AV-81) | Σ child amounts (the gross re-locked into the child escrows — the parent's pre-split remaining lockup) | 0 | 0 | 0 — the per-child `(child_id, amount)` roster rides the event's `split_children` field |
//! | Slashed (AV-82) | 0 | 0 | 0 | the slashed amount, routed to the penalty account (the escrow stays `Funded`; from == to == `Funded`) |
//! | AppealFiled (AV-86) | 0 | 0 | 0 | 0 — the taker filed the appeal inside the window; no funds move (from == to == `Funded`) |
//! | AppealResolved (AV-86) | the penalty refunded to the taker on overturn — a restitution, no fee (0 on uphold; from == to == `Funded`) | 0 | 0 | 0 |
//!
//! # Backward compatibility
//!
//! No existing public method signature changed: the wrapper is purely
//! additive, and [`Escrow`] itself is untouched. The crate stays
//! dependency-free.

use crate::{Escrow, EscrowError, EscrowState, MilestonePlan, QuorumPolicy, SplitConfig, VestingSchedule};
use crate::{AppealOutcome, OverrideValue, TemplatePreset};
use crate::cpi::CpiError;
use crate::cpi_call::{CpiInvocation, CpiReceipt};

/// What kind of state change an [`EscrowEvent`] records.
///
/// One variant per transition the [`IndexedEscrow`] wrapper emits for.
/// `Attested` covers quorum votes (see the module docs for why a
/// non-`EscrowState`-changing mutation emits); every other variant maps
/// to the same-named transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowEventKind {
    Initialized,
    Activated,
    Funded,
    Released,
    Cancelled,
    ExpiredCancelled,
    Attested,
    Claimed,
    Escalated,
    Resolved,
    MilestoneConfirmed,
    MilestoneReleased,
    MilestoneSkipped,
    /// AV-25: the quorum's attestation threshold changed by dual-signed
    /// governance ([`Escrow::update_quorum`]). `from == to ==` the
    /// current state; the new threshold is read from the vault, the
    /// event is the ordering signal.
    QuorumUpdated,
    /// AV-39: the quorum's attestor set changed by dual-signed
    /// governance ([`Escrow::update_attestors`]). `from == to ==` the
    /// current state; the new set is read from the vault, the event is
    /// the ordering signal. A no-op same-set update emits nothing
    /// (paralleling [`EscrowEventKind::QuorumUpdated`]'s no-op rule).
    AttestorsUpdated,
    /// AV-41: the AV-27 timelock was cleared early by dual-signed
    /// emergency governance ([`Escrow::emergency_unlock`]). `from == to
    /// ==` the current state (a config change, not a lifecycle move —
    /// like [`EscrowEventKind::QuorumUpdated`]); the cleared timelock is
    /// read from the vault, the event is the ordering signal. Always
    /// emitted on success: the call fails unless an active timelock was
    /// cleared, so there is no no-op case.
    EmergencyUnlock,
    /// AV-34: the vault account was closed by the initializer and its
    /// rent-exempt deposit reclaimed ([`Escrow::close_vault`]).
    /// `from` is the terminal state the escrow was in (`Cancelled`,
    /// `Released` or `Settled`), `to == Closed`, and
    /// [`EventAmounts::rent_reclaimed`] carries the reclaimed lamports
    /// ([`crate::vault_close_rent_reclaimed`]).
    VaultClosed,
    /// AV-36: a fund-moving transition was rejected as a reentrant
    /// call ([`EscrowError::ReentrantCall`]) — a nested entry from
    /// inside [`Escrow::release_via_cpi`]'s injected executor window.
    /// `from == to ==` the current state, all amounts zero: nothing
    /// moved. This is the deliberate exception to the "failed calls
    /// emit nothing" rule — a blocked reentry is a security signal
    /// (a hostile CPI target attempting to re-enter the program
    /// mid-instruction), and the indexer must see it in `seq` order.
    ReentryRejected,
    /// AV-46: the emergency pause was engaged ([`Escrow::pause`]).
    /// `from == to ==` the current state (a config flip, not a
    /// lifecycle move — like [`EscrowEventKind::EmergencyUnlock`]); the
    /// pause flag is read from the vault, the event is the ordering
    /// signal.
    Paused,
    /// AV-46: the emergency pause was released ([`Escrow::unpause`]).
    /// `from == to ==` the current state; mirrors
    /// [`EscrowEventKind::Paused`].
    Unpaused,
    /// AV-47: the emergency-pause authority was rotated by owner
    /// governance ([`Escrow::rotate_pause_authority`]). `from == to ==`
    /// the current state (a config change, not a lifecycle move — like
    /// [`EscrowEventKind::QuorumUpdated`]); the new authority is read
    /// from the vault, the event is the ordering signal. Emitted only on
    /// an actual change: rotating to the already-bound key is an
    /// idempotent no-op that emits nothing (paralleling
    /// [`EscrowEventKind::QuorumUpdated`]'s no-op rule).
    PauseAuthorityRotated,
    /// AV-48: an expired escrow was cancelled through the permissionless
    /// crank ([`Escrow::crank_expired`]) instead of the party-signed
    /// [`EscrowEventKind::ExpiredCancelled`] path. `from == Funded`, `to
    /// == Cancelled`; amounts follow the [`EventAmounts::expired_cancel`]
    /// shape (refund to the pinned destination, penalty only when the
    /// cranker is the taker). The [`EscrowEvent::caller`] field carries
    /// the crank caller's key — the one kind where the caller is neither
    /// party, so the indexer cannot infer it from the escrow's parties.
    ExpiredCranked,
    /// AV-49: the payout destination allowlist was updated by owner
    /// governance ([`Escrow::update_payout_allowlist`]). `from == to ==`
    /// the current state (a config change, not a lifecycle move — like
    /// [`EscrowEventKind::QuorumUpdated`]); the new list is read from
    /// the vault, the event is the ordering signal. Amounts are zero.
    /// (The initialize-time builder [`Escrow::with_payout_allowlist`]
    /// emits no event — pre-fund configuration, like
    /// [`Escrow::with_pause_authority`].)
    PayoutAllowlistUpdated,
    /// AV-52: the taker (payout counterparty) was rotated by dual-signed
    /// governance ([`Escrow::rotate_taker`]). `from == to ==` the current
    /// state (a config change, not a lifecycle move — like
    /// [`EscrowEventKind::QuorumUpdated`]); the new taker is read from
    /// the vault, the event is the ordering signal. Emitted only on an
    /// actual change: rotating to the current taker is an idempotent
    /// no-op that emits nothing (paralleling
    /// [`EscrowEventKind::QuorumUpdated`]'s no-op rule).
    TakerRotated,
    /// AV-55: a deadlocked dispute was settled on the pre-agreed
    /// fallback split ([`Escrow::trigger_default_judgment`]). `from ==
    /// Disputed`, `to == Settled` — the same lifecycle move as
    /// [`EscrowEventKind::Resolved`], but executed by either party
    /// after the arbitration deadline instead of by the arbiter.
    /// Amounts follow the `Resolved` shape (`payout` = gross taker
    /// share, `fee` = protocol fee on the taker's share, `refund` =
    /// initializer's share of the split). The dispute evidence hash
    /// the escrow still holds rides the event (survives on the escrow);
    /// the rationale-document commitment is `None` — there is no
    /// arbiter's ruling to reference.
    DefaultJudgment,
    /// AV-56: a subscription period was paid out to the taker
    /// ([`Escrow::release_period`]) — the initializer's push path for a
    /// periodic subscription schedule. `from == Funded`, `to ==
    /// Funded` — or `to == Released` on the last period. Amounts follow
    /// the `Released` shape (`payout` = the gross per-period amount =
    /// taker_payout + fee, `fee` = the AV-17 protocol fee, `refund` =
    /// 0).
    SubscriptionPeriodReleased,
    /// AV-58: the initializer (funding authority) was rotated by
    /// dual-signed governance ([`Escrow::rotate_initializer`]) — the
    /// mirror of [`EscrowEventKind::TakerRotated`]. `from == to ==`
    /// the current state (a config change, not a lifecycle move —
    /// like [`EscrowEventKind::QuorumUpdated`]); the new initializer
    /// is read from the vault, the event is the ordering signal.
    /// Emitted only on an actual change: rotating to the current
    /// initializer is an idempotent no-op that emits nothing
    /// (paralleling [`EscrowEventKind::TakerRotated`]'s no-op rule).
    InitializerRotated,
    /// AV-59: the expiry deadline was extended by the initializer
    /// ([`Escrow::extend_expiry`]). `from == to ==` the current state
    /// (a config change, not a lifecycle move — like
    /// [`EscrowEventKind::InitializerRotated`]); the new `expires_at`
    /// and the monotonic `extension_count` are read from the vault,
    /// the event is the ordering signal. Always emitted on success:
    /// the call fails unless the deadline strictly moved, so there is
    /// no no-op case.
    ExpiryExtended,
    /// AV-60: the initializer partially cancelled the escrow
    /// ([`Escrow::cancel_partial`]) — a tranche of the lockup refunded
    /// to the AV-23-pinned destination while the escrow stays `Funded`.
    /// `from == to == Funded`: the [`EscrowState`] variant does not
    /// change, but funds moved and the refund stream must be complete
    /// for the indexer (the complement of a partial `Released` event).
    /// `amounts.refund` carries the partially-cancelled amount; the
    /// `released` counter is untouched.
    PartiallyCancelled,
    /// AV-62: the dispute arbiter was rotated by dual-signed governance
    /// ([`Escrow::rotate_arbiter`]) — the mirror of
    /// [`EscrowEventKind::InitializerRotated`] for the arbitration
    /// role. `from == to ==` the current state (a config change, not a
    /// lifecycle move — like [`EscrowEventKind::QuorumUpdated`]); the
    /// new arbiter is read from the vault, the event is the ordering
    /// signal. Emitted only on an actual change: rotating to the
    /// current arbiter is an idempotent no-op that emits nothing
    /// (paralleling [`EscrowEventKind::TakerRotated`]'s no-op rule). A
    /// rotation with no arbiter configured is rejected
    /// (`InvalidArbiter`), so the event can never fire on an
    /// arbiter-less escrow.
    ArbiterRotated,
    /// AV-65: one arbiter-panel member submitted their judgment
    /// ([`Escrow::submit_panel_judgment`]). `from == to == Disputed`
    /// (a vote, not a lifecycle move — like
    /// [`EscrowEventKind::Attested`]); the voted split (`taker_amount`)
    /// rides `amounts.payout` and the vote's rationale-document
    /// commitment rides the rationale slot — the vote itself is the
    /// ordering signal, and the indexer reads the live tally (and the
    /// voting member's key summary, in the on-chain history ring's
    /// actor slot) from the vault. Emitted on every submission,
    /// including re-votes: an overwritten vote stays in the log as the
    /// audit trail of the member's changed mind.
    PanelJudgment,
    /// AV-65: the arbiter panel settled the dispute
    /// ([`Escrow::submit_panel_judgment`]): the M-th matching vote
    /// arrived. `from == Disputed`, `to == Settled` — the same
    /// lifecycle move as [`EscrowEventKind::Resolved`], but executed
    /// by the panel's multisig instead of a single arbiter. Amounts
    /// follow the `Resolved` shape (`payout` = gross taker share, `fee`
    /// = protocol fee on the taker's share, `refund` = initializer's
    /// share of the split); the dispute evidence hash the escrow still
    /// holds rides the event, and the winning vote's rationale-document
    /// commitment rides it as the rationale (AV-38 convention). Always
    /// emitted together with the settling vote's `PanelJudgment` (the
    /// vote first, then the settlement).
    PanelResolved,
    /// AV-67: the protocol-fee recipient was rotated by dual-signed
    /// governance ([`Escrow::rotate_fee_recipient`]) — the mirror of
    /// [`EscrowEventKind::ArbiterRotated`] for the fee-destination
    /// role. `from == to ==` the current state (a config change, not a
    /// lifecycle move — like [`EscrowEventKind::QuorumUpdated`]); the
    /// new recipient is read from the vault, the event is the ordering
    /// signal. Emitted only on an actual change: rotating to the
    /// current recipient is an idempotent no-op that emits nothing
    /// (paralleling [`EscrowEventKind::TakerRotated`]'s no-op rule). A
    /// rotation with no fee recipient configured is rejected
    /// (`InvalidFeeRecipient`), so the event can never fire on a
    /// recipient-less escrow.
    FeeRecipientRotated,
    /// AV-68: the escalating party disclosed (or replaced) the
    /// dispute-evidence commitment ([`Escrow::submit_evidence`]).
    /// `from == to == Disputed` (a disclosure, not a lifecycle move —
    /// like [`EscrowEventKind::Attested`]); the disclosed commitment
    /// rides the event's evidence slot, so the log records exactly
    /// what the arbiter can review. All amounts are zero — disclosure
    /// moves no funds.
    EvidenceSubmitted,
    /// AV-69: the arbiter panel's judgment threshold was retuned by
    /// dual-signed governance ([`Escrow::update_panel_threshold`]).
    /// `from == to == Uninitialized` (a config change, not a lifecycle
    /// move — like [`EscrowEventKind::QuorumUpdated`]); the new
    /// threshold is read from the vault, the event is the ordering
    /// signal. Emitted only on an actual change: retuning to the
    /// current threshold is an idempotent no-op that emits nothing
    /// (paralleling [`EscrowEventKind::FeeRecipientRotated`]'s no-op
    /// rule). Cast votes are untouched by the retune — the panel's
    /// judgment history is append-only.
    PanelThresholdChanged,
    /// AV-70: the milestone tranche amounts were re-split by
    /// dual-signed governance
    /// ([`Escrow::adjust_milestone_amounts`]). `from == to ==` the
    /// current state (a config change, not a lifecycle move — like
    /// [`EscrowEventKind::QuorumUpdated`]); the new amounts are read
    /// from the vault, the event is the ordering signal. Emitted only
    /// on an actual change: re-affirming the current amounts is an
    /// idempotent no-op that emits nothing (paralleling
    /// [`EscrowEventKind::FeeRecipientRotated`]'s no-op rule). All
    /// amounts are zero — re-splitting moves no funds (the later
    /// tranche releases carry the new amounts with their fees).
    MilestonesAdjusted,
    /// AV-73: the subscription per-period amounts were re-split by
    /// dual-signed governance
    /// ([`Escrow::adjust_period_amounts`]). `from == to ==` the
    /// current state (a config change, not a lifecycle move — like
    /// [`EscrowEventKind::MilestonesAdjusted`]); the new amounts are
    /// read from the vault, the event is the ordering signal. Emitted
    /// only on an actual change: re-affirming the current amounts is
    /// an idempotent no-op that emits nothing (paralleling
    /// [`EscrowEventKind::MilestonesAdjusted`]'s no-op rule). All
    /// amounts are zero — re-splitting moves no funds (the later
    /// period releases carry the new amounts with their fees).
    SubscriptionAmountsAdjusted,
    /// AV-75: the vault's persisted schema was migrated one version
    /// forward by initializer governance
    /// ([`Escrow::migrate_schema`]). `from == to ==` the current
    /// state (bookkeeping, not a lifecycle move — like
    /// [`EscrowEventKind::SubscriptionAmountsAdjusted`]). AV-85: the
    /// migration is an N → M step chain, and the wrapper emits one
    /// `SchemaMigrated` per applied step — the event chain records
    /// every `from → to` version pair (see
    /// [`EscrowEvent::schema_versions`]) in `seq` order. Always
    /// emitted on success: a successful migration always steps the
    /// version, so there is no no-op case. All amounts are zero —
    /// migration moves no funds.
    SchemaMigrated,
    /// AV-76: a keeper milestone bundle
    /// ([`crate::keeper::execute_milestone_bundle`]) released a
    /// *proper subset* of the configured tranches. `from == to ==`
    /// the current state (a proper subset can never settle the vault —
    /// zero-amount tranches are rejected by
    /// [`MilestonePlan::new`](crate::MilestonePlan::new), so
    /// `released == amount` needs every tranche released). Fired only
    /// for proper-subset executions: a full execution emits just the
    /// per-tranche [`EscrowEventKind::MilestoneReleased`] events. The
    /// executed tranches' totals ride `amounts` (`payout` = Σ gross,
    /// `fee` = Σ protocol fee, like `MilestoneReleased`); the
    /// executed/remaining index lists live on the executor's return
    /// value ([`crate::keeper::MilestoneBundleExecution`]), and an
    /// indexer rebuilds them from the adjacent `MilestoneReleased`
    /// events. The actor is `None` — the bundle is a keeper
    /// composition, not a single authority (each tranche's own
    /// `MilestoneReleased` already names its signer).
    BundlePartiallyExecuted,
    /// AV-77: a governance preset was applied
    /// ([`IndexedEscrow::apply_template`]): the preset's defaults plus
    /// the caller's per-field overrides produced the escrow's full
    /// configuration. `from == to ==` the current state (a
    /// configuration application, not a lifecycle move — like
    /// [`EscrowEventKind::SchemaMigrated`]); all amounts are zero —
    /// applying a template moves no funds. The SHA-256 of the
    /// effective parameters
    /// ([`EscrowTemplate::params_hash`](crate::EscrowTemplate::params_hash))
    /// rides [`EscrowEvent::template_params_hash`], so indexers and
    /// auditors can verify exactly which parameters took effect.
    /// Always emitted on success: a successful application always
    /// configures the escrow, so there is no no-op case (an empty
    /// override list still applies the preset's defaults and emits).
    TemplateApplied,
    /// AV-79: a batch vault close
    /// ([`crate::close_indexed_vaults`]) closed one or more vaults.
    /// `from == to == Closed` — a composition summary, not a
    /// lifecycle move (like
    /// [`EscrowEventKind::BundlePartiallyExecuted`]): the per-vault
    /// [`EscrowEventKind::VaultClosed`] events already record each
    /// close, and the closed vaults' indexes ride the batch report
    /// ([`crate::CloseVaultsReport`]). [`EventAmounts::rent_reclaimed`]
    /// carries the Σ rent-exempt lamports the batch reclaimed, every
    /// other amount zero. The summary rides the first closed vault's
    /// log (in `seq` order, after its `VaultClosed`); a batch that
    /// closes nothing emits no summary event (paralleling the no-op
    /// rules on [`EscrowEventKind::QuorumUpdated`] et al).
    VaultsBatchClosed,
    /// AV-81: a funded escrow was split into N child escrows by
    /// dual-signed governance ([`Escrow::split_escrow`]). `from ==
    /// Funded`, `to == Split` — the parent's lifecycle move into the
    /// new terminal state. [`EventAmounts::payout`] carries the Σ child
    /// amounts (the gross re-locked into the child escrows — equal to
    /// the parent's pre-split [`Escrow::remaining_amount`], so the
    /// conservation invariant is checkable from the log alone); every
    /// other amount is zero. The `(child_id, amount)` roster rides
    /// [`EscrowEvent::split_children`] — the parent is the event's own
    /// `escrow_id`, and each child's ID is the deterministic
    /// [`crate::derive_split_child_id`] derivation, so the whole
    /// family is re-derivable. The actor is `None` — the split is
    /// dual-signed governance, not a single-actor call (like
    /// [`EscrowEventKind::TakerRotated`]). Always emitted on success:
    /// a successful split always re-homes funds, so there is no no-op
    /// case.
    EscrowSplit,
    /// AV-82: the initializer (or the configured arbiter as the
    /// neutral enforcer) slashed the defaulting taker
    /// ([`Escrow::slash`]). `from == to == Funded` — the escrow stays
    /// live, the taker can still earn the remainder. The slashed sum
    /// rides [`EventAmounts::penalty`] (payout/fee/refund are zero —
    /// the penalty is neither a taker payout nor an initializer
    /// refund), so the conservation invariant stays checkable from the
    /// log alone: `inflow == locked + released + refunded +
    /// penalty_paid`. The actor is the slash caller (the initializer
    /// or the arbiter). Always emitted on success: a successful slash
    /// always moves funds, so there is no no-op case.
    Slashed,
    /// AV-83: the CPI target-program allowlist was changed by
    /// dual-party governance ([`Escrow::update_cpi_allowlist`]).
    /// `from == to ==` the current state (a config change, not a
    /// lifecycle move — like [`EscrowEventKind::PayoutAllowlistUpdated`]);
    /// the new list is read from the vault, the event is the ordering
    /// signal. Amounts are zero. (The initialize-time builder
    /// [`Escrow::with_cpi_allowlist`] emits no event — pre-fund
    /// configuration, like [`Escrow::with_payout_allowlist`].)
    CpiAllowlistUpdated,
    /// AV-86: the taker filed an appeal against the executed slash
    /// ([`Escrow::file_appeal`]). `from == to == Funded` — filing moves
    /// no funds, it only records the challenge and opens the arbiter
    /// panel's review. Amounts are zero; the actor is the taker. Always
    /// emitted on success: a successful filing always opens a review,
    /// so there is no no-op case.
    AppealFiled,
    /// AV-86: the arbiter panel resolved the filed slash appeal
    /// ([`Escrow::review_appeal`]) — the first side (uphold or overturn)
    /// to collect `threshold` matching votes. `from == to == Funded`.
    /// On overturn the refunded penalty rides [`EventAmounts::payout`]
    /// (a taker restitution, no fee — the penalty is neither a fresh
    /// payout nor an initializer refund); on uphold all amounts are
    /// zero. The verdict rides the event's `appeal_outcome` field (see
    /// [`EscrowEvent::appeal_outcome`]), and the actor is the member
    /// whose vote was the M-th match. Always emitted on resolution: a
    /// non-resolving vote emits nothing (the ballot is still open).
    AppealResolved,
}

impl EscrowEventKind {
    /// Discriminant by declaration order (Borsh unit-enum convention):
    /// what the AV-57 event-history ring persists per slot. Pinned by
    /// test — never reorder the variants.
    pub(crate) fn discriminant(self) -> u8 {
        self as u8
    }

    /// Inverse of [`Self::discriminant`]: `None` for an unknown byte.
    /// The panic-free account decoder (AV-32) maps `None` to
    /// [`AccountDecodeError::InvalidEventKindDiscriminant`](crate::AccountDecodeError::InvalidEventKindDiscriminant).
    pub(crate) fn from_discriminant(d: u8) -> Option<Self> {
        Some(match d {
            0 => Self::Initialized,
            1 => Self::Activated,
            2 => Self::Funded,
            3 => Self::Released,
            4 => Self::Cancelled,
            5 => Self::ExpiredCancelled,
            6 => Self::Attested,
            7 => Self::Claimed,
            8 => Self::Escalated,
            9 => Self::Resolved,
            10 => Self::MilestoneConfirmed,
            11 => Self::MilestoneReleased,
            12 => Self::MilestoneSkipped,
            13 => Self::QuorumUpdated,
            14 => Self::AttestorsUpdated,
            15 => Self::EmergencyUnlock,
            16 => Self::VaultClosed,
            17 => Self::ReentryRejected,
            18 => Self::Paused,
            19 => Self::Unpaused,
            20 => Self::PauseAuthorityRotated,
            21 => Self::ExpiredCranked,
            22 => Self::PayoutAllowlistUpdated,
            23 => Self::TakerRotated,
            24 => Self::DefaultJudgment,
            25 => Self::SubscriptionPeriodReleased,
            26 => Self::InitializerRotated,
            27 => Self::ExpiryExtended,
            // AV-60: appended after ExpiryExtended so discriminants 0–27
            // stay stable for already-serialized histories.
            28 => Self::PartiallyCancelled,
            // AV-62: appended after PartiallyCancelled so discriminants
            // 0–28 stay stable for already-serialized histories.
            29 => Self::ArbiterRotated,
            // AV-65: appended after ArbiterRotated so discriminants
            // 0–29 stay stable for already-serialized histories.
            30 => Self::PanelJudgment,
            31 => Self::PanelResolved,
            // AV-67: appended after PanelResolved so discriminants
            // 0–31 stay stable for already-serialized histories.
            32 => Self::FeeRecipientRotated,
            // AV-68: appended after FeeRecipientRotated so
            // discriminants 0–32 stay stable for already-serialized
            // histories.
            33 => Self::EvidenceSubmitted,
            // AV-69: appended after EvidenceSubmitted so discriminants
            // 0–33 stay stable for already-serialized histories.
            34 => Self::PanelThresholdChanged,
            // AV-70: appended after PanelThresholdChanged so
            // discriminants 0–34 stay stable for already-serialized
            // histories.
            35 => Self::MilestonesAdjusted,
            // AV-73: appended after MilestonesAdjusted so
            // discriminants 0–35 stay stable for already-serialized
            // histories.
            36 => Self::SubscriptionAmountsAdjusted,
            // AV-75: appended after SubscriptionAmountsAdjusted so
            // discriminants 0–36 stay stable for already-serialized
            // histories.
            37 => Self::SchemaMigrated,
            // AV-76: appended after SchemaMigrated so discriminants
            // 0–37 stay stable for already-serialized histories.
            38 => Self::BundlePartiallyExecuted,
            // AV-77: appended after BundlePartiallyExecuted so
            // discriminants 0–38 stay stable for already-serialized
            // histories.
            39 => Self::TemplateApplied,
            // AV-79: appended after TemplateApplied so discriminants
            // 0–39 stay stable for already-serialized histories.
            40 => Self::VaultsBatchClosed,
            // AV-81: appended after VaultsBatchClosed so discriminants
            // 0–40 stay stable for already-serialized histories.
            41 => Self::EscrowSplit,
            // AV-82: appended after EscrowSplit so discriminants 0–41
            // stay stable for already-serialized histories.
            42 => Self::Slashed,
            // AV-83: appended after Slashed so discriminants 0–42
            // stay stable for already-serialized histories.
            43 => Self::CpiAllowlistUpdated,
            // AV-86: appended after CpiAllowlistUpdated so
            // discriminants 0–43 stay stable for already-serialized
            // histories.
            44 => Self::AppealFiled,
            // AV-86: appended after AppealFiled so discriminants 0–44
            // stay stable for already-serialized histories.
            45 => Self::AppealResolved,
            _ => return None,
        })
    }

    /// Canonical snake_case name, for the AV-26 snapshot JSON export
    /// and indexer tooling. Mirrors the variant name 1:1.
    pub fn name(self) -> &'static str {
        match self {
            Self::Initialized => "initialized",
            Self::Activated => "activated",
            Self::Funded => "funded",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::ExpiredCancelled => "expired_cancelled",
            Self::Attested => "attested",
            Self::Claimed => "claimed",
            Self::Escalated => "escalated",
            Self::Resolved => "resolved",
            Self::MilestoneConfirmed => "milestone_confirmed",
            Self::MilestoneReleased => "milestone_released",
            Self::MilestoneSkipped => "milestone_skipped",
            Self::QuorumUpdated => "quorum_updated",
            Self::AttestorsUpdated => "attestors_updated",
            Self::EmergencyUnlock => "emergency_unlock",
            Self::VaultClosed => "vault_closed",
            Self::ReentryRejected => "reentry_rejected",
            Self::Paused => "paused",
            Self::Unpaused => "unpaused",
            Self::PauseAuthorityRotated => "pause_authority_rotated",
            Self::ExpiredCranked => "expired_cranked",
            Self::PayoutAllowlistUpdated => "payout_allowlist_updated",
            Self::TakerRotated => "taker_rotated",
            Self::DefaultJudgment => "default_judgment",
            Self::SubscriptionPeriodReleased => "subscription_period_released",
            Self::InitializerRotated => "initializer_rotated",
            Self::ExpiryExtended => "expiry_extended",
            Self::PartiallyCancelled => "partially_cancelled",
            Self::ArbiterRotated => "arbiter_rotated",
            Self::PanelJudgment => "panel_judgment",
            Self::PanelResolved => "panel_resolved",
            Self::FeeRecipientRotated => "fee_recipient_rotated",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::PanelThresholdChanged => "panel_threshold_changed",
            Self::MilestonesAdjusted => "milestones_adjusted",
            Self::SubscriptionAmountsAdjusted => "subscription_amounts_adjusted",
            Self::SchemaMigrated => "schema_migrated",
            Self::BundlePartiallyExecuted => "bundle_partially_executed",
            Self::TemplateApplied => "template_applied",
            Self::VaultsBatchClosed => "vaults_batch_closed",
            Self::EscrowSplit => "escrow_split",
            Self::Slashed => "escrow_slashed",
            Self::CpiAllowlistUpdated => "cpi_allowlist_updated",
            Self::AppealFiled => "appeal_filed",
            Self::AppealResolved => "appeal_resolved",
        }
    }

    /// Inverse of [`Self::name`]: the kind whose canonical name is
    /// `name`, `None` for an unknown name. Used by the AV-74 CSV
    /// importer (`csv_to_events`) so a kind column round-trips without
    /// depending on declaration order.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "initialized" => Self::Initialized,
            "activated" => Self::Activated,
            "funded" => Self::Funded,
            "released" => Self::Released,
            "cancelled" => Self::Cancelled,
            "expired_cancelled" => Self::ExpiredCancelled,
            "attested" => Self::Attested,
            "claimed" => Self::Claimed,
            "escalated" => Self::Escalated,
            "resolved" => Self::Resolved,
            "milestone_confirmed" => Self::MilestoneConfirmed,
            "milestone_released" => Self::MilestoneReleased,
            "milestone_skipped" => Self::MilestoneSkipped,
            "quorum_updated" => Self::QuorumUpdated,
            "attestors_updated" => Self::AttestorsUpdated,
            "emergency_unlock" => Self::EmergencyUnlock,
            "vault_closed" => Self::VaultClosed,
            "reentry_rejected" => Self::ReentryRejected,
            "paused" => Self::Paused,
            "unpaused" => Self::Unpaused,
            "pause_authority_rotated" => Self::PauseAuthorityRotated,
            "expired_cranked" => Self::ExpiredCranked,
            "payout_allowlist_updated" => Self::PayoutAllowlistUpdated,
            "taker_rotated" => Self::TakerRotated,
            "default_judgment" => Self::DefaultJudgment,
            "subscription_period_released" => Self::SubscriptionPeriodReleased,
            "initializer_rotated" => Self::InitializerRotated,
            "expiry_extended" => Self::ExpiryExtended,
            "partially_cancelled" => Self::PartiallyCancelled,
            "arbiter_rotated" => Self::ArbiterRotated,
            "panel_judgment" => Self::PanelJudgment,
            "panel_resolved" => Self::PanelResolved,
            "fee_recipient_rotated" => Self::FeeRecipientRotated,
            "evidence_submitted" => Self::EvidenceSubmitted,
            "panel_threshold_changed" => Self::PanelThresholdChanged,
            "milestones_adjusted" => Self::MilestonesAdjusted,
            "subscription_amounts_adjusted" => Self::SubscriptionAmountsAdjusted,
            "schema_migrated" => Self::SchemaMigrated,
            "bundle_partially_executed" => Self::BundlePartiallyExecuted,
            "template_applied" => Self::TemplateApplied,
            "vaults_batch_closed" => Self::VaultsBatchClosed,
            "escrow_split" => Self::EscrowSplit,
            "escrow_slashed" => Self::Slashed,
            "cpi_allowlist_updated" => Self::CpiAllowlistUpdated,
            "appeal_filed" => Self::AppealFiled,
            "appeal_resolved" => Self::AppealResolved,
            _ => return None,
        })
    }
}

/// Fund movements carried by an [`EscrowEvent`].
///
/// A single shape for every kind (see the module docs for the per-kind
/// table): `payout` is the gross amount moved to the taker *before* the
/// protocol-fee split (`payout - fee` is the taker's net), `fee` is the
/// AV-17 protocol fee sliced from `payout`, `refund` is the amount
/// returned to the initializer, `penalty` is the AV-24 anti-griefing
/// penalty sliced from the remainder on a taker-initiated
/// `cancel_expired` (routed to the initializer as griefing
/// compensation), and `rent_reclaimed` is the AV-34 rent-exempt deposit
/// returned to the initializer when the vault account is closed
/// (non-zero only on `VaultClosed`). All fields are zero when the kind
/// moves no such value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventAmounts {
    pub payout: u64,
    pub fee: u64,
    pub refund: u64,
    pub penalty: u64,
    pub rent_reclaimed: u64,
}

impl EventAmounts {
    /// No fund movement (config transitions, votes, pure state flips).
    fn none() -> Self {
        Self {
            payout: 0,
            fee: 0,
            refund: 0,
            penalty: 0,
            rent_reclaimed: 0,
        }
    }

    /// A taker payout of `gross` with `fee` sliced from it.
    fn payout(gross: u64, fee: u64) -> Self {
        Self {
            payout: gross,
            fee,
            refund: 0,
            penalty: 0,
            rent_reclaimed: 0,
        }
    }

    /// An initializer refund of `refund` (cancels, skips).
    fn refund(refund: u64) -> Self {
        Self {
            payout: 0,
            fee: 0,
            refund,
            penalty: 0,
            rent_reclaimed: 0,
        }
    }

    /// A taker-initiated expiry cancel (AV-24): the remainder splits
    /// into the whitelisted `refund` and the anti-griefing `penalty`
    /// routed to the initializer; `refund + penalty == remaining`.
    fn expired_cancel(refund: u64, penalty: u64) -> Self {
        Self {
            payout: 0,
            fee: 0,
            refund,
            penalty,
            rent_reclaimed: 0,
        }
    }

    /// A vault close (AV-34): the initializer reclaims the rent-exempt
    /// deposit `rent`; every other field is zero — no payout, fee,
    /// refund or penalty moves on close.
    fn close(rent: u64) -> Self {
        Self {
            payout: 0,
            fee: 0,
            refund: 0,
            penalty: 0,
            rent_reclaimed: rent,
        }
    }

    /// A batch vault close (AV-79): the Σ rent-exempt deposits the
    /// batch reclaimed, in `rent_reclaimed` — the same shape as
    /// [`Self::close`], aggregated across the closed vaults. Rides the
    /// [`EscrowEventKind::VaultsBatchClosed`] summary event.
    pub(crate) fn batch_close(total_rent: u64) -> Self {
        Self::close(total_rent)
    }

    /// An escrow split (AV-81): the Σ child amounts re-locked into the
    /// child escrows, in `payout` — the gross the parent's remaining
    /// lockup became. Every other field is zero: no taker payout, no
    /// fee slice, no refund, no penalty, no rent reclaim — the funds
    /// moved sideways into the children, not out of escrow. Rides the
    /// [`EscrowEventKind::EscrowSplit`] event; the per-child amounts
    /// ride the event's `split_children` roster.
    pub(crate) fn split(total: u64) -> Self {
        Self {
            payout: total,
            fee: 0,
            refund: 0,
            penalty: 0,
            rent_reclaimed: 0,
        }
    }

    /// A default-penalty slash (AV-82): the slashed amount rides
    /// `penalty` — it is neither a taker payout nor an initializer
    /// refund. Rides the [`EscrowEventKind::Slashed`] event.
    pub(crate) fn slashed(penalty: u64) -> Self {
        Self {
            payout: 0,
            fee: 0,
            refund: 0,
            penalty,
            rent_reclaimed: 0,
        }
    }

    /// A slash-appeal overturn (AV-86): the refunded penalty rides
    /// `payout` — it is a taker restitution (no fee sliced), neither a
    /// fresh payout for work nor an initializer refund. Rides the
    /// [`EscrowEventKind::AppealResolved`] event; an upheld appeal
    /// resolves with [`EventAmounts::none`].
    pub(crate) fn appeal_overturn(refunded: u64) -> Self {
        Self {
            payout: refunded,
            fee: 0,
            refund: 0,
            penalty: 0,
            rent_reclaimed: 0,
        }
    }
}

/// CPI-routing audit for a [`EscrowEvent`]: which third-party program a
/// CPI-routed release invoked, and the SHA-256 commitment over the exact
/// instruction the release authorized (AV-35).
///
/// An indexer re-derives [`cpi_accounts_hash`](super::cpi_accounts_hash)
/// from the proposed instruction and compares it against
/// `accounts_hash` — a swapped account, flag, or data byte changes the
/// hash, so the audit trail pins the authorized instruction byte-exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpiRouteAudit {
    /// The invoked third-party program (e.g. a DEX or lending program).
    pub target: [u8; 32],
    /// SHA-256 over the canonical encoding of the authorized
    /// [`CpiInvocation`](super::CpiInvocation): program id, accounts
    /// (key + signer/writable flags, in order), and data.
    pub accounts_hash: [u8; 32],
}

/// One typed record of a state change, in per-escrow [`seq`](Self::seq)
/// order.
///
/// `from` / `to` are the [`EscrowState`] before and after the call;
/// progress events that leave the state variant untouched
/// (`Attested`, `MilestoneConfirmed`, partial payouts) carry
/// `from == to`. `at` is the caller-supplied Unix-seconds timestamp —
/// for `cancel_expired` / `escalate` / `claim` it is the `now` the
/// transition itself ran on.
///
/// `evidence_hash` (AV-22) carries the dispute-evidence commitment on
/// the dispute events: `Escalated` carries the hash attached at
/// escalation, `Resolved` carries the hash the escrow still holds (the
/// arbiter's settlement references the evidence it reviewed), and
/// `DefaultJudgment` (AV-55) carries the hash the escrow still holds —
/// the fallback settlement references the same evidence. It is `None`
/// on every other kind — the event log never invents evidence.
///
/// `rationale_hash` (AV-38) carries the arbiter's rationale-document
/// commitment on `Resolved`: the hash the arbiter attached at settlement,
/// so the settlement references the ruling it wrote. It is `None` on
/// every other kind — including `DefaultJudgment` (AV-55), where no
/// arbiter ruled — the event log never invents a rationale.
///
/// `cpi` (AV-35) carries the CPI-routing audit on a `Released` event
/// whose payout flowed through a third-party program
/// ([`IndexedEscrow::release_via_cpi`]). It is `None` on every other
/// kind — plain releases authorize no third-party instruction.
///
/// `caller` (AV-48) carries the crank caller's key on the
/// `ExpiredCranked` event — the one kind where the caller is neither
/// party, so the indexer cannot infer it from the escrow's parties.
/// It is `None` on every other kind — the event log never invents a
/// caller.
///
/// `reference` (AV-53) carries the opt-in 32-byte off-chain reference
/// memo on *every* event kind — read from the escrow at emit time, so
/// the log always agrees with the account. It is `None` when the
/// escrow carries no reference — the event log never invents one.
///
/// `split_children` (AV-81) carries the child-escrow roster on the
/// `EscrowSplit` event: `(child_id, amount)` pairs in split-table
/// order, `len` of them valid. It is `None` on every other kind —
/// the event log never invents children.
///
/// [`IndexedEscrow::release_via_cpi`]: IndexedEscrow::release_via_cpi
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowEvent {
    pub kind: EscrowEventKind,
    /// Caller-supplied 32-byte escrow identity (on-chain: the vault PDA
    /// public key).
    pub escrow_id: [u8; 32],
    /// Per-escrow monotonic sequence; 0 is the `Initialized` event.
    pub seq: u64,
    pub from: EscrowState,
    pub to: EscrowState,
    pub amounts: EventAmounts,
    pub at: u64,
    pub evidence_hash: Option<[u8; 32]>,
    /// AV-68: whether the escalating party's evidence disclosure had
    /// defaulted at judgment time — read from the escrow at emit time
    /// (never a `push_event` parameter), so the log always agrees with
    /// the account. `true` only on the settlement kinds (`Resolved`,
    /// `DefaultJudgment`, `PanelResolved`) when a disclosure deadline
    /// was configured, it had lapsed at the event's `at` timestamp,
    /// and no evidence commitment was on record — the judgment-time
    /// adverse-inference signal: the absent-evidence weight favors the
    /// non-escalating party (see
    /// [`crate::Escrow::evidence_defaulted`]). `false` on every other
    /// kind — the event log never invents a default.
    pub evidence_defaulted: bool,
    /// AV-38: the arbiter's rationale-document commitment, carried by
    /// the `Resolved` event (`None` on every other kind); mirrors
    /// [`Escrow::rationale_hash`], so the settlement references the
    /// ruling the arbiter wrote.
    pub rationale_hash: Option<[u8; 32]>,
    pub cpi: Option<CpiRouteAudit>,
    /// AV-48: the permissionless crank caller's key, carried by the
    /// `ExpiredCranked` event (`None` on every other kind).
    pub caller: Option<[u8; 32]>,
    /// AV-53: the opt-in 32-byte off-chain reference memo
    /// ([`Escrow::reference`]), carried on *every* event kind the
    /// wrapper emits — read from the escrow at emit time, so the event
    /// log always agrees with the account. Unlike `rationale_hash`
    /// (carried only by `Resolved`), the reference is bound before any
    /// funds move, so every event from `Initialized` on can already
    /// join the escrow to the operator's off-chain order/invoice
    /// record. Read-only pass-through: the event never invents a
    /// reference — `None` when the escrow carries none.
    pub reference: Option<[u8; 32]>,
    /// AV-77: SHA-256 over the canonical encoding of the effective
    /// template parameters
    /// ([`EscrowTemplate::params_hash`](crate::EscrowTemplate::params_hash)),
    /// carried by the `TemplateApplied` event (`None` on every other
    /// kind — like `rationale_hash`, which rides only `Resolved`). The
    /// hash is computed by the template layer
    /// ([`TemplatePreset::apply_template`](crate::TemplatePreset::apply_template)),
    /// never invented by the wrapper: the emitter stamps it after the
    /// push (see `push_event`), so the log records exactly the
    /// parameters that took effect.
    pub template_params_hash: Option<[u8; 32]>,
    /// AV-81: the child-escrow roster for the `EscrowSplit` event —
    /// `(child_id, amount)` pairs in split order, `len` of them valid.
    /// Carried only by [`EscrowEventKind::EscrowSplit`] (`None` on every
    /// other kind — like `template_params_hash`, which rides only
    /// `TemplateApplied`). The parent is the event's own `escrow_id`;
    /// each `child_id` is the deterministic
    /// [`crate::derive_split_child_id`] derivation, so an indexer
    /// re-derives the whole split family from this one event. The
    /// emitter stamps it after the push (see `push_event`), mirroring
    /// the `template_params_hash` precedent — never a `push_event`
    /// parameter. Fixed-size ([`MAX_SPLIT_CHILDREN`](crate::MAX_SPLIT_CHILDREN))
    /// so the event stays `Copy`.
    pub split_children: Option<([SplitChild; crate::MAX_SPLIT_CHILDREN], u8)>,
    /// AV-85: the schema versions one migration step moved across,
    /// carried by [`EscrowEventKind::SchemaMigrated`] — one event per
    /// applied step, so the chain records every `from → to` pair in
    /// `seq` order (`None` on every other kind — like
    /// `template_params_hash`, which rides only `TemplateApplied`).
    /// The emitter stamps it after the push (see `push_event`),
    /// mirroring the `template_params_hash` precedent — never a
    /// `push_event` parameter. `(u8, u8)` keeps the event `Copy`.
    pub schema_versions: Option<(u8, u8)>,
    /// AV-86: the panel's verdict on the filed slash appeal, carried by
    /// [`EscrowEventKind::AppealResolved`] (`None` on every other kind —
    /// like `template_params_hash`, which rides only `TemplateApplied`).
    /// The emitter stamps it after the push (see `push_event`),
    /// mirroring the `template_params_hash` precedent — never a
    /// `push_event` parameter — so the log records exactly the verdict
    /// the M-th vote settled, and indexers read the outcome without
    /// replaying the ballot.
    pub appeal_outcome: Option<AppealOutcome>,
}

/// One split child on an [`EscrowEventKind::EscrowSplit`] event's
/// roster (AV-81): the derived child identity and its locked amount,
/// in split-table order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitChild {
    /// The derived child escrow identity:
    /// [`crate::derive_split_child_id`]`(parent_id, index)`.
    pub escrow_id: [u8; 32],
    /// The child's locked amount — the split-table entry.
    pub amount: u64,
}

/// An event-logging adapter over [`Escrow`] (AV-18).
///
/// Exposes the same mutating transitions (`initialize` as the
/// constructor, then `activate`, `fund`, `attest`, `update_quorum`,
/// `release`, `cancel`, `cancel_expired`, `claim`, `escalate`,
/// `resolve`, `confirm_milestone`, `release_milestone`,
/// `skip_milestone`, `close_vault`) plus the `with_*` configuration builders,
/// delegating every call to the inner state machine. Exactly one
/// [`EscrowEvent`] is recorded per successful transition (see the module
/// docs for the emission rule); failed calls record nothing.
///
/// Timestamps are caller-supplied Unix seconds, like the rest of the
/// crate: transitions whose inner method takes no `now` take an
/// explicit `at`; `cancel_expired` / `escalate` / `claim` reuse their
/// `now` argument as the event's `at`.
#[derive(Debug, Clone)]
pub struct IndexedEscrow {
    inner: Escrow,
    escrow_id: [u8; 32],
    events: Vec<EscrowEvent>,
    next_seq: u64,
}

impl IndexedEscrow {
    /// Construct a new escrow in the `Uninitialized` state, recording the
    /// `Initialized` event (`seq` 0). Mirrors [`Escrow::initialize`];
    /// `escrow_id` is the caller-supplied escrow identity and `at` the
    /// creation timestamp.
    pub fn initialize(
        initializer: [u8; 32],
        taker: [u8; 32],
        amount: u64,
        expires_at: u64,
        escrow_id: [u8; 32],
        at: u64,
    ) -> Result<Self, EscrowError> {
        let inner = Escrow::initialize(initializer, taker, amount, expires_at)?;
        let mut indexed = Self {
            inner,
            escrow_id,
            events: Vec::new(),
            next_seq: 0,
        };
        // The constructor has no prior state: from == to == Uninitialized
        // by convention, so the very first event still carries a
        // well-formed state pair.
        indexed.push_event(
            EscrowEventKind::Initialized,
            EscrowState::Uninitialized,
            EscrowState::Uninitialized,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(initializer),
        );
        Ok(indexed)
    }

    /// AV-77: stand up a fully-configured escrow from a governance
    /// preset ([`TemplatePreset`]): the preset's defaults plus the
    /// caller's per-field overrides produce the escrow's full
    /// configuration — or the whole application fails with
    /// [`EscrowError`] (never a half-configured escrow).
    ///
    /// Override rules are the preset's: only fields in
    /// [`TemplatePreset::overridable`](crate::TemplatePreset::overridable)
    /// may be overridden, with the declared [`OverrideValue`] type,
    /// each at most once — anything else is
    /// [`EscrowError::TemplateOverrideRejected`]. The effective
    /// parameters then run the full template invariant validation
    /// (conservation / mutual exclusion / thresholds) before the
    /// escrow builds.
    ///
    /// Emits two events: `Initialized` (seq 0 — the per-escrow
    /// invariant that seq 0 is always `Initialized`) and
    /// [`EscrowEventKind::TemplateApplied`] (seq 1, `from == to ==`
    /// the current state — a configuration application, not a
    /// lifecycle move), carrying the SHA-256 of the effective
    /// parameters so indexers and auditors can verify exactly what
    /// was applied. Failed applications emit nothing.
    pub fn apply_template(
        preset: &TemplatePreset<'_>,
        overrides: &[(&str, OverrideValue<'_>)],
        escrow_id: [u8; 32],
        at: u64,
    ) -> Result<Self, EscrowError> {
        let applied = preset.apply_template(overrides)?;
        let mut indexed = Self {
            inner: applied.escrow,
            escrow_id,
            events: Vec::new(),
            next_seq: 0,
        };
        indexed.push_event(
            EscrowEventKind::Initialized,
            EscrowState::Uninitialized,
            EscrowState::Uninitialized,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(applied.template.initializer),
        );
        indexed.emit_template_applied(applied.params_hash, at);
        Ok(indexed)
    }

    /// Record one event, assigning the next per-escrow sequence number.
    /// `caller` (AV-48) is `Some` only for the permissionless crank
    /// ([`EscrowEventKind::ExpiredCranked`]) — every other kind passes
    /// `None`, since the event log never invents a caller.
    ///
    /// `actor` (AV-57) is the transition's single actor when there is
    /// one — the key the wrapper's method took as its authority — and
    /// feeds the on-chain event-history ring
    /// ([`Escrow::record_history`](crate::Escrow::record_history)):
    /// dual-signed governance transitions and reentrancy rejections
    /// pass `None` (the actor is the signature pair, or unknown).
    ///
    /// `template_params_hash` (AV-77) is never a `push_event`
    /// parameter: the `TemplateApplied` emitter stamps it after the
    /// push (the hash is computed by the template layer, never by the
    /// wrapper — the same "read at emit time" rule as `reference`).
    fn push_event(
        &mut self,
        kind: EscrowEventKind,
        from: EscrowState,
        to: EscrowState,
        amounts: EventAmounts,
        at: u64,
        evidence_hash: Option<[u8; 32]>,
        rationale_hash: Option<[u8; 32]>,
        cpi: Option<CpiRouteAudit>,
        caller: Option<[u8; 32]>,
        actor: Option<[u8; 32]>,
    ) {
        let event = EscrowEvent {
            kind,
            escrow_id: self.escrow_id,
            seq: self.next_seq,
            from,
            to,
            amounts,
            at,
            evidence_hash,
            rationale_hash,
            cpi,
            caller,
            // AV-68: the judgment-time adverse-inference signal rides
            // the settlement kinds — read from the escrow at emit time
            // (never a push_event parameter), so the log always agrees
            // with the account. The event's `at` is the judgment-time
            // clock: a settlement whose deadline lapsed undisclosed
            // records the default for the arbiter, the panel members,
            // and indexers.
            evidence_defaulted: matches!(
                kind,
                EscrowEventKind::Resolved
                    | EscrowEventKind::DefaultJudgment
                    | EscrowEventKind::PanelResolved
            ) && self.inner.evidence_defaulted(at),
            // AV-53: the off-chain reference memo rides every event —
            // read from the escrow at emit time (never a push_event
            // parameter), so the log always agrees with the account.
            reference: self.inner.reference(),
            // AV-77: stamped by the TemplateApplied emitter after the
            // push — never a push_event parameter (see above).
            template_params_hash: None,
            // AV-81: stamped by the EscrowSplit emitter after the push
            // — never a push_event parameter (see above).
            split_children: None,
            // AV-85: stamped by the SchemaMigrated emitter after the
            // push — never a push_event parameter (see above).
            schema_versions: None,
            // AV-86: stamped by the AppealResolved emitter after the
            // push — never a push_event parameter (see above).
            appeal_outcome: None,
        };
        self.next_seq += 1;
        self.events.push(event);
        // AV-57: the on-chain ring records the same transition — one
        // record per successful transition, none for failed ones (the
        // AV-36 `ReentryRejected` exception aside, which records with
        // no actor).
        self.inner.record_history(kind, at, actor);
    }

    /// AV-36: map a fund-moving transition's result, emitting
    /// [`EscrowEventKind::ReentryRejected`] when the inner call was
    /// rejected as a reentrant call ([`EscrowError::ReentrantCall`]).
    /// This is the deliberate exception to the "failed calls emit
    /// nothing" rule: a blocked reentry is a security signal — a
    /// hostile CPI target attempting to re-enter the program
    /// mid-instruction — and the indexer must see it in `seq` order.
    /// Every other outcome passes through untouched; in particular a
    /// rejection changes no state, so `from == to ==` the current
    /// state and all amounts are zero.
    fn map_reentrant<T>(
        &mut self,
        result: Result<T, EscrowError>,
        at: u64,
    ) -> Result<T, EscrowError> {
        match result {
            Err(EscrowError::ReentrantCall) => {
                let state = self.inner.state();
                self.push_event(
            EscrowEventKind::ReentryRejected,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            None,
        );
                Err(EscrowError::ReentrantCall)
            }
            other => other,
        }
    }

    /// The inner state machine (read-only: transitions go through this
    /// wrapper so the event log cannot drift from the state).
    pub fn inner(&self) -> &Escrow {
        &self.inner
    }

    /// The caller-supplied escrow identity.
    pub fn escrow_id(&self) -> [u8; 32] {
        self.escrow_id
    }

    /// All recorded events, in `seq` order.
    pub fn events(&self) -> &[EscrowEvent] {
        &self.events
    }

    /// Number of recorded (not yet drained) events.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// The retained on-chain event history (AV-57), oldest first —
    /// the same ring [`Escrow::event_history`](crate::Escrow::event_history)
    /// reads from the vault account. Every event this wrapper emitted
    /// also landed in the ring (see `push_event`), so the two views
    /// agree by construction.
    pub fn event_history(&self) -> Vec<crate::EventHistoryEntry> {
        self.inner.event_history()
    }

    /// The sequence number the next event will carry.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Take all recorded events, clearing the log. The sequence counter
    /// keeps running — drained events are never re-sequenced, so an
    /// indexer resuming from a checkpoint sees no duplicates.
    pub fn drain_events(&mut self) -> Vec<EscrowEvent> {
        std::mem::take(&mut self.events)
    }

    // ----- builders: configuration, not transitions — no events -----

    /// Attach an N-of-M attestor quorum (mirrors [`Escrow::with_quorum`]).
    /// Configuration: emits no event.
    pub fn with_quorum(mut self, policy: QuorumPolicy) -> Result<Self, EscrowError> {
        // `Escrow` is `Copy`, so this rebinds rather than moving out of
        // `self`.
        self.inner = self.inner.with_quorum(policy)?;
        Ok(self)
    }

    /// Opt in to dual-signature activation (mirrors
    /// [`Escrow::with_dual_sig`]). Configuration: emits no event.
    pub fn with_dual_sig(mut self) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_dual_sig()?;
        Ok(self)
    }

    /// Attach a linear vesting schedule (mirrors [`Escrow::with_vesting`]).
    /// Configuration: emits no event.
    pub fn with_vesting(mut self, schedule: VestingSchedule) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_vesting(schedule)?;
        Ok(self)
    }

    /// Opt in to dispute arbitration (mirrors [`Escrow::with_arbiter`]).
    /// Configuration: emits no event.
    pub fn with_arbiter(mut self, arbiter: [u8; 32]) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_arbiter(arbiter)?;
        Ok(self)
    }

    /// Opt in to the arbiter-panel multisig judgment (mirrors
    /// [`Escrow::with_arbiter_panel`]): replace the single dispute
    /// arbiter with an N-member panel and an M-vote judgment threshold.
    /// Configuration: emits no event.
    pub fn with_arbiter_panel(
        mut self,
        members: &[[u8; 32]],
        threshold: u8,
    ) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_arbiter_panel(members, threshold)?;
        Ok(self)
    }

    /// Opt in to the dispute-evidence disclosure deadline (mirrors
    /// [`Escrow::with_evidence_deadline`], AV-68): declare the window
    /// the escalating party gets to disclose the dispute evidence
    /// before the judgment-time adverse inference kicks in.
    /// Configuration: emits no event.
    pub fn with_evidence_deadline(mut self, deadline_secs: u64) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_evidence_deadline(deadline_secs)?;
        Ok(self)
    }

    /// Opt in to bounded expiry extension (mirrors
    /// [`Escrow::with_max_extension_secs`]). Configuration: emits no
    /// event.
    pub fn with_max_extension_secs(mut self, max_extension_secs: u64) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_max_extension_secs(max_extension_secs)?;
        Ok(self)
    }

    /// Opt in to the arbitration default judgment (mirrors
    /// [`Escrow::with_arbitration_deadline`]): declare the fallback
    /// split applied when a live dispute outlives its arbitration
    /// deadline. Configuration: emits no event (pre-fund setup).
    pub fn with_arbitration_deadline(
        mut self,
        deadline_secs: u64,
        default_taker_amount: u64,
    ) -> Result<Self, EscrowError> {
        self.inner = self
            .inner
            .with_arbitration_deadline(deadline_secs, default_taker_amount)?;
        Ok(self)
    }

    /// The taker countersigns the pre-agreed default judgment (mirrors
    /// [`Escrow::confirm_default_judgment`]). Configuration: emits no
    /// event (pre-dispute setup).
    pub fn confirm_default_judgment(mut self, authority: [u8; 32]) -> Result<Self, EscrowError> {
        self.inner.confirm_default_judgment(authority)?;
        Ok(self)
    }

    /// Bind one SPL token mint (mirrors [`Escrow::with_mint`]).
    /// Configuration: emits no event.
    pub fn with_mint(mut self, mint: [u8; 32]) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_mint(mint)?;
        Ok(self)
    }

    /// Opt in to a protocol fee on taker payouts (mirrors
    /// [`Escrow::with_protocol_fee`]). Configuration: emits no event.
    pub fn with_protocol_fee(mut self, fee_bps: u16) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_protocol_fee(fee_bps)?;
        Ok(self)
    }

    /// Pin the protocol-fee destination (mirrors
    /// [`Escrow::with_fee_recipient`]). Configuration: emits no event.
    pub fn with_fee_recipient(mut self, recipient: [u8; 32]) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_fee_recipient(recipient)?;
        Ok(self)
    }

    /// Opt in to an expiry grace period (mirrors
    /// [`Escrow::with_grace_period`]). Configuration: emits no event.
    pub fn with_grace_period(mut self, grace_period: u64) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_grace_period(grace_period)?;
        Ok(self)
    }

    /// Attach a milestone tranche plan (mirrors
    /// [`Escrow::with_milestones`]). Configuration: emits no event.
    pub fn with_milestones(mut self, plan: MilestonePlan) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_milestones(plan)?;
        Ok(self)
    }

    /// Opt in to the default-penalty (slash) clause (mirrors
    /// [`Escrow::with_slash_terms`], AV-82). Configuration: emits no
    /// event.
    pub fn with_slash_terms(
        mut self,
        penalty_account: [u8; 32],
        slash_deadline: u64,
    ) -> Result<Self, EscrowError> {
        self.inner = self
            .inner
            .with_slash_terms(penalty_account, slash_deadline)?;
        Ok(self)
    }

    /// Attach a periodic subscription schedule (mirrors
    /// [`Escrow::with_subscription`], AV-56). Configuration: emits no
    /// event.
    pub fn with_subscription(
        mut self,
        period_secs: u64,
        periods: u8,
        per_period: u64,
    ) -> Result<Self, EscrowError> {
        self.inner = self
            .inner
            .with_subscription(period_secs, periods, per_period)?;
        Ok(self)
    }

    /// Opt in to an anti-griefing penalty on taker-initiated expiry
    /// cancellation (mirrors [`Escrow::with_penalty_bps`]).
    /// Configuration: emits no event.
    pub fn with_penalty_bps(mut self, penalty_bps: u16) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_penalty_bps(penalty_bps)?;
        Ok(self)
    }

    /// Opt in to a timelock (mirrors [`Escrow::with_timelock`]).
    /// Configuration: emits no event.
    pub fn with_timelock(mut self, unlock_at: u64) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_timelock(unlock_at)?;
        Ok(self)
    }

    /// Opt in to emergency timelock-unlock governance (mirrors
    /// [`Escrow::with_emergency_unlock`]). Configuration: emits no event.
    pub fn with_emergency_unlock(mut self) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_emergency_unlock()?;
        Ok(self)
    }

    /// Bind the emergency-pause authority (mirrors
    /// [`Escrow::with_pause_authority`]). Configuration: emits no event.
    pub fn with_pause_authority(mut self, authority: [u8; 32]) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_pause_authority(authority)?;
        Ok(self)
    }

    /// Bind the opt-in 32-byte off-chain reference memo (AV-53; mirrors
    /// [`Escrow::with_reference`]). `Uninitialized` only, like every
    /// other `with_*` builder; a pure setter — any 32 bytes are
    /// accepted, and the memo rides every event the wrapper emits.
    pub fn with_reference(mut self, reference: [u8; 32]) -> Self {
        self.inner = self.inner.with_reference(reference);
        self
    }

    /// Configure the event-history ring capacity (AV-57; mirrors
    /// [`Escrow::with_event_capacity`]). `Uninitialized` only, like
    /// every other `with_*` builder. Configuration: emits no event —
    /// the ring only starts recording at the `Initialized` event.
    pub fn with_event_capacity(mut self, capacity: u8) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_event_capacity(capacity)?;
        Ok(self)
    }

    // ----- transitions: exactly one event per successful transition -----

    /// Record one party's activation signature (mirrors
    /// [`Escrow::activate`]). Emits `Activated` only when the call flips
    /// `Uninitialized -> Activated`; a single party's signature (or an
    /// idempotent re-affirmation) emits nothing.
    pub fn activate(&mut self, authority: [u8; 32], at: u64) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.activate(authority)?;
        let to = self.inner.state();
        if to != from {
            self.push_event(
            EscrowEventKind::Activated,
            from,
            to,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        }
        Ok(())
    }

    /// Lock funds into the vault (mirrors [`Escrow::fund`]). Emits
    /// `Funded`. `at` is both the event timestamp and the state
    /// machine's `now` (so the AV-64 `fund_at` the relative timelock
    /// measures from sees the same clock the event log records).
    pub fn fund(&mut self, authority: [u8; 32], at: u64) -> Result<(), EscrowError> {
        let from = self.inner.state();
        // AV-36: a rejected reentrant entry emits `ReentryRejected`
        // (the deliberate exception to the no-events-on-failure rule).
        // (The inner result is bound first so its `&mut` borrow ends
        // before `map_reentrant` reborrows `self`.)
        let result = self.inner.fund(authority, at);
        self.map_reentrant(result, at)?;
        self.push_event(
            EscrowEventKind::Funded,
            from,
            self.inner.state(),
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(())
    }

    /// Release `amount` of the locked funds to the taker (mirrors
    /// [`Escrow::release`]). Emits `Released` on every successful call —
    /// partial releases carry `from == to == Funded`, the closing one
    /// `to == Released` — so the payout stream is complete in `seq`
    /// order. Returns `(taker_payout, fee)` like the inner method.
    /// `at` is both the event timestamp and the state machine's `now`
    /// (so the AV-27 timelock gate sees the same clock the event log
    /// records).
    pub fn release(
        &mut self,
        authority: [u8; 32],
        amount: u64,
        mint: Option<[u8; 32]>,
        payout_to: [u8; 32],
        at: u64,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self.inner.release(authority, at, amount, mint, payout_to);
        let (payout, fee) = self.map_reentrant(result, at)?;
        // `amount` is the gross payout by construction
        // (`payout + fee == amount`); it cannot overflow u64 addition.
        self.push_event(
            EscrowEventKind::Released,
            from,
            self.inner.state(),
            EventAmounts::payout(amount, fee),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok((payout, fee))
    }

    /// Release `amount` routed through a third-party program via CPI
    /// (mirrors [`Escrow::release_via_cpi`]). Emits `Released` exactly
    /// like [`IndexedEscrow::release`] — partial releases carry
    /// `from == to == Funded`, the closing one `to == Released` — so
    /// the payout stream stays complete in `seq` order, with the CPI
    /// audit attached (`cpi.target` / `cpi.accounts_hash`): the
    /// indexer's audit trail pins the exact instruction the release
    /// authorized. On executor failure the state machine rolls back
    /// and nothing is emitted, like every other failed transition.
    /// Returns `(taker_payout, fee, receipt)` like the inner method.
    /// `at` is both the event timestamp and the state machine's `now`.
    ///
    /// [`Escrow::release_via_cpi`]: super::Escrow::release_via_cpi
    /// [`IndexedEscrow::release`]: IndexedEscrow::release
    pub fn release_via_cpi<F>(
        &mut self,
        authority: [u8; 32],
        amount: u64,
        mint: Option<[u8; 32]>,
        payout_to: [u8; 32],
        at: u64,
        cpi: &CpiInvocation,
        execute_cpi: F,
    ) -> Result<(u64, u64, CpiReceipt), EscrowError>
    where
        F: FnOnce(&CpiInvocation) -> Result<(), CpiError>,
    {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self
            .inner
            .release_via_cpi(authority, at, amount, mint, payout_to, cpi, execute_cpi);
        let (payout, fee, receipt) = self.map_reentrant(result, at)?;
        // `amount` is the gross payout by construction
        // (`payout + fee == amount`); it cannot overflow u64 addition.
        self.push_event(
            EscrowEventKind::Released,
            from,
            self.inner.state(),
            EventAmounts::payout(amount, fee),
            at,
            None,
            None,
            Some(CpiRouteAudit {
                target: receipt.cpi_target,
                accounts_hash: receipt.accounts_hash,
            }),
            None,
            Some(authority),
        );
        Ok((payout, fee, receipt))
    }

    /// Cancel the escrow and return funds (mirrors [`Escrow::cancel`]).
    /// Emits `Cancelled` with the refunded remainder in
    /// `amounts.refund`. `refund_to` is the refund destination, pinned
    /// against the escrow's refund policy (AV-23).
    pub fn cancel(
        &mut self,
        authority: [u8; 32],
        mint: Option<[u8; 32]>,
        refund_to: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self.inner.cancel(authority, mint, refund_to);
        self.map_reentrant(result, at)?;
        let to = self.inner.state();
        let refund = self.inner.remaining_amount();
        self.push_event(
            EscrowEventKind::Cancelled,
            from,
            to,
            EventAmounts::refund(refund),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(())
    }

    /// Partially cancel the escrow and refund a tranche to the
    /// initializer (mirrors [`Escrow::cancel_partial`], AV-60). Emits
    /// `PartiallyCancelled` with `from == to == Funded` and
    /// `amounts.refund` carrying the partially-cancelled amount;
    /// `refund_to` is the refund destination, pinned against the
    /// escrow's refund policy (AV-23). Returns the refunded amount.
    pub fn cancel_partial(
        &mut self,
        authority: [u8; 32],
        amount: u64,
        mint: Option<[u8; 32]>,
        refund_to: [u8; 32],
        at: u64,
    ) -> Result<u64, EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self.inner.cancel_partial(authority, amount, mint, refund_to);
        let refund = self.map_reentrant(result, at)?;
        let to = self.inner.state();
        self.push_event(
            EscrowEventKind::PartiallyCancelled,
            from,
            to,
            EventAmounts::refund(refund),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(refund)
    }

    /// Cancel an expired escrow (mirrors [`Escrow::cancel_expired`]).
    /// Emits `ExpiredCancelled`; `now` doubles as the event's `at`.
    /// `refund_to` is the refund destination, pinned against the
    /// escrow's refund policy (AV-23). Returns the `(refund, penalty)`
    /// split (AV-24): only a taker-initiated cancel charges the penalty.
    pub fn cancel_expired(
        &mut self,
        authority: [u8; 32],
        now: u64,
        mint: Option<[u8; 32]>,
        refund_to: [u8; 32],
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected` (`now` doubles as the event's `at`).
        let result = self
            .inner
            .cancel_expired(authority, now, mint, refund_to);
        let (refund, penalty) = self.map_reentrant(result, now)?;
        let to = self.inner.state();
        self.push_event(
            EscrowEventKind::ExpiredCancelled,
            from,
            to,
            EventAmounts::expired_cancel(refund, penalty),
            now,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok((refund, penalty))
    }

    /// Permissionless expiry crank (mirrors [`Escrow::crank_expired`],
    /// AV-48). Emits `ExpiredCranked` (carrying the crank `caller` —
    /// the one event kind where the caller is neither party) with the
    /// same [`EventAmounts::expired_cancel`] shape as the party-signed
    /// path; `now` doubles as the event's `at`. Returns the `(refund,
    /// penalty)` split: only a taker cranker pays the AV-24 penalty.
    pub fn crank_expired(
        &mut self,
        caller: [u8; 32],
        now: u64,
        mint: Option<[u8; 32]>,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected` (`now` doubles as the event's `at`).
        let result = self.inner.crank_expired(caller, now, mint);
        let (refund, penalty) = self.map_reentrant(result, now)?;
        let to = self.inner.state();
        self.push_event(
            EscrowEventKind::ExpiredCranked,
            from,
            to,
            EventAmounts::expired_cancel(refund, penalty),
            now,
            None,
            None,
            None,
            Some(caller),
            Some(caller),
        );
        Ok((refund, penalty))
    }

    /// Record an attestation from a registered attestor (mirrors
    /// [`Escrow::attest`]). Emits `Attested` when the attestation is
    /// new (the quorum's approval count grows); an idempotent duplicate
    /// emits nothing. `from == to ==` the current state — the quorum
    /// bitmask, not the lifecycle state, is what changed.
    pub fn attest(&mut self, attestor: [u8; 32], at: u64) -> Result<(), EscrowError> {
        let before = self
            .inner
            .quorum()
            .map(|q| q.approval_count())
            .unwrap_or(0);
        self.inner.attest(attestor)?;
        let after = self
            .inner
            .quorum()
            .map(|q| q.approval_count())
            .unwrap_or(0);
        // A successful `attest` with a configured quorum always moves
        // the count unless the attestor already voted (idempotent);
        // without a quorum the inner call fails, so this is unreachable
        // on the error path.
        if after > before {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::Attested,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(attestor),
        );
        }
        Ok(())
    }

    /// Adjust the quorum's attestation threshold by dual-signed
    /// governance (mirrors [`Escrow::update_quorum`]). Emits
    /// `QuorumUpdated` when the threshold actually changes; a no-op
    /// update (same threshold) emits nothing. `from == to ==` the
    /// current state — the quorum gate, not the lifecycle state, is
    /// what changed. `at` is the caller-supplied timestamp (on-chain:
    /// the clock sysvar).
    pub fn update_quorum(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        new_threshold: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let before = self.inner.quorum().map(|q| q.threshold()).unwrap_or(0);
        self.inner.update_quorum(initializer, taker, new_threshold)?;
        let after = self.inner.quorum().map(|q| q.threshold()).unwrap_or(0);
        // The inner call succeeds with a configured quorum or fails
        // (no quorum / bad threshold / wrong authority / bad state), so
        // a changed threshold here always means real governance.
        if after != before {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::QuorumUpdated,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Replace the quorum's attestor set by dual-signed governance
    /// (mirrors [`Escrow::update_attestors`]). Emits `AttestorsUpdated`
    /// when the set actually changes; a no-op update (the identical
    /// set, same order, same weights) emits nothing — paralleling
    /// `update_quorum`'s no-op rule. `from == to ==` the current state:
    /// the electorate, not the lifecycle state, is what changed. `at`
    /// is the caller-supplied timestamp (on-chain: the clock sysvar).
    pub fn update_attestors(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        new_attestors: &[[u8; 32]],
        new_weights: &[u64],
        at: u64,
    ) -> Result<(), EscrowError> {
        let before: Vec<([u8; 32], u64)> = self
            .inner
            .quorum()
            .map(|q| {
                q.attestors()
                    .iter()
                    .zip(q.weights().iter())
                    .map(|(a, w)| (*a, *w))
                    .collect()
            })
            .unwrap_or_default();
        self.inner
            .update_attestors(initializer, taker, new_attestors, new_weights)?;
        let after: Vec<([u8; 32], u64)> = self
            .inner
            .quorum()
            .map(|q| {
                q.attestors()
                    .iter()
                    .zip(q.weights().iter())
                    .map(|(a, w)| (*a, *w))
                    .collect()
            })
            .unwrap_or_default();
        // The inner call succeeds with a configured quorum or fails (no
        // quorum / bad set / wrong authority / bad state), so a changed
        // set here always means real governance. Order matters to the
        // bitmask (votes remap by pubkey), so a pure reorder of the same
        // keys still counts as a change: the canonical slot order is
        // part of the configuration.
        if after != before {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::AttestorsUpdated,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Clear the AV-27 timelock by dual-signed emergency governance
    /// (mirrors [`Escrow::emergency_unlock`]). Emits `EmergencyUnlock`
    /// with `from == to ==` the current state — a config change, not a
    /// lifecycle move (like `QuorumUpdated`). `at` is the caller-supplied
    /// timestamp (on-chain: the clock sysvar). The inner call fails
    /// unless an active timelock was actually cleared, so a successful
    /// call always emits — there is no no-op case.
    pub fn emergency_unlock(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        self.inner.emergency_unlock(initializer, taker)?;
        let state = self.inner.state();
        self.push_event(
            EscrowEventKind::EmergencyUnlock,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Engage the emergency pause (mirrors [`Escrow::pause`]).
    /// Emits `Paused`; `from == to ==` the current state (a config
    /// flip, not a lifecycle move — like `EmergencyUnlock`). `at` is
    /// the caller-supplied event timestamp.
    pub fn pause(&mut self, authority: [u8; 32], at: u64) -> Result<(), EscrowError> {
        self.inner.pause(authority)?;
        let state = self.inner.state();
        self.push_event(
            EscrowEventKind::Paused,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(())
    }

    /// Release the emergency pause (mirrors [`Escrow::unpause`]).
    /// Emits `Unpaused`; mirrors [`IndexedEscrow::pause`].
    pub fn unpause(&mut self, authority: [u8; 32], at: u64) -> Result<(), EscrowError> {
        self.inner.unpause(authority)?;
        let state = self.inner.state();
        self.push_event(
            EscrowEventKind::Unpaused,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(())
    }

    /// Rotate the emergency-pause authority (mirrors
    /// [`Escrow::rotate_pause_authority`]). Emits `PauseAuthorityRotated`
    /// only when the authority actually changes; `from == to ==` the
    /// current state. `at` is the caller-supplied event timestamp.
    pub fn rotate_pause_authority(
        &mut self,
        authority: [u8; 32],
        new_authority: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let before = self.inner.pause_authority();
        self.inner.rotate_pause_authority(authority, new_authority)?;
        let after = self.inner.pause_authority();
        // The inner call rejects an unconfigured switch, a zero key, a
        // stranger, and Uninitialized, so a changed authority here always
        // means real governance — and a same-key no-op stays silent.
        if after != before {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::PauseAuthorityRotated,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        }
        Ok(())
    }

    /// Update the payout destination allowlist (mirrors
    /// [`Escrow::update_payout_allowlist`]). Emits `PayoutAllowlistUpdated`
    /// only when the list actually changes; `from == to ==` the current
    /// state. `at` is the caller-supplied event timestamp.
    pub fn update_payout_allowlist(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        addrs: &[[u8; 32]],
        at: u64,
    ) -> Result<(), EscrowError> {
        let before = self.inner.payout_allowlist();
        self.inner.update_payout_allowlist(initializer, taker, addrs)?;
        let after = self.inner.payout_allowlist();
        // The inner call rejects bad input, strangers, and wrong states,
        // so a changed list here always means real governance — and a
        // same-list no-op stays silent.
        if after != before {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::PayoutAllowlistUpdated,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Update the CPI target-program allowlist (mirrors
    /// [`Escrow::update_cpi_allowlist`]). Emits `CpiAllowlistUpdated`
    /// only when the list actually changes; `from == to ==` the current
    /// state. `at` is the caller-supplied event timestamp.
    pub fn update_cpi_allowlist(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        program_ids: &[[u8; 32]],
        at: u64,
    ) -> Result<(), EscrowError> {
        let before = self.inner.cpi_allowlist();
        self.inner
            .update_cpi_allowlist(initializer, taker, program_ids)?;
        let after = self.inner.cpi_allowlist();
        // The inner call rejects bad input, strangers, and wrong states,
        // so a changed list here always means real governance — and a
        // same-list no-op stays silent.
        if after != before {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::CpiAllowlistUpdated,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Rotate the taker by dual-signed governance (mirrors
    /// [`Escrow::rotate_taker`]). Emits `TakerRotated` only when the
    /// taker actually changes; `from == to ==` the current state (a
    /// config change, not a lifecycle move — like `QuorumUpdated`).
    /// `at` is the caller-supplied event timestamp.
    pub fn rotate_taker(
        &mut self,
        initializer: [u8; 32],
        old_taker: [u8; 32],
        new_taker: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let before = self.inner.taker();
        self.inner.rotate_taker(initializer, old_taker, new_taker)?;
        let after = self.inner.taker();
        // The inner call rejects a stranger pair, wrong states, and the
        // zero address, so a changed taker here always means real
        // governance — and a same-taker no-op stays silent.
        if after != before {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::TakerRotated,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Rotate the initializer by dual-signed governance (mirrors
    /// [`Escrow::rotate_initializer`]) — the mirror of
    /// [`IndexedEscrow::rotate_taker`]. Emits `InitializerRotated`
    /// only when the initializer actually changes; `from == to ==`
    /// the current state (a config change, not a lifecycle move —
    /// like `QuorumUpdated`). `at` is the caller-supplied event
    /// timestamp.
    pub fn rotate_initializer(
        &mut self,
        old_initializer: [u8; 32],
        taker: [u8; 32],
        new_initializer: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let before = self.inner.initializer();
        self.inner
            .rotate_initializer(old_initializer, taker, new_initializer)?;
        let after = self.inner.initializer();
        // The inner call rejects a stranger pair, wrong states, and the
        // zero address, so a changed initializer here always means real
        // governance — and a same-initializer no-op stays silent.
        if after != before {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::InitializerRotated,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Rotate the dispute arbiter by dual-signed governance (mirrors
    /// [`Escrow::rotate_arbiter`]) — the mirror of
    /// [`IndexedEscrow::rotate_initializer`]. Emits `ArbiterRotated`
    /// only when the arbiter actually changes; `from == to ==`
    /// the current state (a config change, not a lifecycle move —
    /// like `QuorumUpdated`). `at` is the caller-supplied event
    /// timestamp.
    pub fn rotate_arbiter(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        new_arbiter: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let before = self.inner.arbiter();
        self.inner
            .rotate_arbiter(initializer, taker, new_arbiter)?;
        let after = self.inner.arbiter();
        // The inner call rejects a stranger pair, wrong states, the
        // zero address, and the no-arbiter case, so a changed arbiter
        // here always means real governance — and a same-arbiter no-op
        // stays silent.
        if after != before {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::ArbiterRotated,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Rotate the protocol-fee recipient by dual-signed governance
    /// (mirrors [`Escrow::rotate_fee_recipient`]) — the mirror of
    /// [`IndexedEscrow::rotate_arbiter`] for the fee-destination role.
    /// Emits `FeeRecipientRotated` only when the recipient actually
    /// changes; `from == to ==` the current state (a config change, not
    /// a lifecycle move — like `QuorumUpdated`). `at` is the
    /// caller-supplied event timestamp.
    pub fn rotate_fee_recipient(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        new_recipient: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let before = self.inner.fee_recipient();
        self.inner
            .rotate_fee_recipient(initializer, taker, new_recipient)?;
        let after = self.inner.fee_recipient();
        // The inner call rejects a stranger pair, wrong states, the
        // zero address, and the no-recipient case, so a changed
        // recipient here always means real governance — and a
        // same-recipient no-op stays silent.
        if after != before {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::FeeRecipientRotated,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Extend the expiry deadline (mirrors [`Escrow::extend_expiry`]).
    /// Emits `ExpiryExtended`; `from == to ==` the current state (a
    /// config change, not a lifecycle move). `now` doubles as the
    /// event's `at`. The call fails unless the deadline strictly
    /// moved, so the event always fires on success — there is no
    /// no-op case.
    pub fn extend_expiry(
        &mut self,
        initializer: [u8; 32],
        new_expires_at: u64,
        now: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.extend_expiry(initializer, new_expires_at, now)?;
        self.push_event(
            EscrowEventKind::ExpiryExtended,
            from,
            self.inner.state(),
            EventAmounts::none(),
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Claim the vested-but-unreleased portion (mirrors [`Escrow::claim`]).
    /// Emits `Claimed`; `now` doubles as the event's `at`. Partial
    /// claims carry `from == to == Funded`, the closing one
    /// `to == Released`.
    pub fn claim(
        &mut self,
        authority: [u8; 32],
        now: u64,
        mint: Option<[u8; 32]>,
        payout_to: [u8; 32],
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected` (`now` doubles as the event's `at`).
        let result = self.inner.claim(authority, now, mint, payout_to);
        let (payout, fee) = self.map_reentrant(result, now)?;
        // `payout + fee` is the gross claimable (`<= amount`); no
        // overflow possible.
        self.push_event(
            EscrowEventKind::Claimed,
            from,
            self.inner.state(),
            EventAmounts::payout(payout + fee, fee),
            now,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok((payout, fee))
    }

    /// Escalate the escrow into arbitration (mirrors [`Escrow::escalate`]).
    /// Emits `Escalated` (`Funded -> Disputed`) carrying the evidence
    /// hash attached at escalation; `now` doubles as the event's `at`.
    pub fn escalate(
        &mut self,
        authority: [u8; 32],
        now: u64,
        evidence_hash: Option<[u8; 32]>,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.escalate(authority, now, evidence_hash)?;
        self.push_event(
            EscrowEventKind::Escalated,
            from,
            self.inner.state(),
            EventAmounts::none(),
            now,
            evidence_hash,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(())
    }

    /// Disclose (or replace) the dispute-evidence commitment while
    /// `Disputed` (mirrors [`Escrow::submit_evidence`], AV-68). Emits
    /// `EvidenceSubmitted` (`from == to == Disputed`) carrying the
    /// disclosed commitment in the event's evidence slot; `now` doubles
    /// as the event's `at`. Only the escalating party may call (the
    /// inner method enforces it); a post-deadline disclosure is
    /// rejected and emits nothing.
    pub fn submit_evidence(
        &mut self,
        authority: [u8; 32],
        evidence_hash: [u8; 32],
        now: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.submit_evidence(authority, evidence_hash, now)?;
        self.push_event(
            EscrowEventKind::EvidenceSubmitted,
            from,
            self.inner.state(),
            EventAmounts::none(),
            now,
            Some(evidence_hash),
            None,
            None,
            None,
            Some(authority),
        );
        Ok(())
    }

    /// Settle a disputed escrow (mirrors [`Escrow::resolve`]). Emits
    /// `Resolved` (`Disputed -> Settled`) with the gross taker share in
    /// `amounts.payout`, the protocol fee in `amounts.fee`, and the
    /// initializer's share in `amounts.refund` — and the dispute
    /// evidence hash the escrow still holds, so the settlement
    /// references the evidence the arbiter reviewed — and the arbiter's
    /// rationale-document commitment (AV-38), so the settlement
    /// references the ruling the arbiter wrote. Returns
    /// `(taker_payout, fee, initializer_refund)` like the inner method.
    pub fn resolve(
        &mut self,
        authority: [u8; 32],
        taker_amount: u64,
        mint: Option<[u8; 32]>,
        rationale_hash: Option<[u8; 32]>,
        payout_to: [u8; 32],
        at: u64,
    ) -> Result<(u64, u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self.inner.resolve(authority, taker_amount, mint, rationale_hash, payout_to);
        let (payout, fee, refund) = self.map_reentrant(result, at)?;
        // `taker_amount` is the gross taker share by construction
        // (`payout + fee == taker_amount`).
        let amounts = EventAmounts {
            payout: taker_amount,
            fee,
            refund,
            penalty: 0,
            rent_reclaimed: 0,
        };
        // AV-22: the evidence hash survives `resolve` on the escrow, so
        // the settlement event carries the same commitment the
        // `Escalated` event carried.
        let evidence_hash = self.inner.evidence_hash();
        // AV-38: the rationale hash the arbiter attached at settlement
        // rides the `Resolved` event, so the settlement references the
        // ruling it wrote.
        let rationale_hash = self.inner.rationale_hash();
        self.push_event(
            EscrowEventKind::Resolved,
            from,
            self.inner.state(),
            amounts,
            at,
            evidence_hash,
            rationale_hash,
            None,
            None,
            Some(authority),
        );
        Ok((payout, fee, refund))
    }

    /// Trigger the pre-agreed arbitration default judgment (mirrors
    /// [`Escrow::trigger_default_judgment`]). Emits `DefaultJudgment`
    /// (`Disputed -> Settled`) with the gross taker share in
    /// `amounts.payout`, the protocol fee in `amounts.fee`, and the
    /// initializer's share in `amounts.refund` — the same amounts shape
    /// as `Resolved` — and the dispute evidence hash the escrow still
    /// holds, so the fallback settlement references the evidence the
    /// (absent) arbiter never reviewed. The rationale-document
    /// commitment is `None`: there is no arbiter's ruling to reference.
    /// Returns `(taker_payout, fee, initializer_refund)` like the inner
    /// method.
    pub fn trigger_default_judgment(
        &mut self,
        caller: [u8; 32],
        now: u64,
        mint: Option<[u8; 32]>,
        payout_to: [u8; 32],
        at: u64,
    ) -> Result<(u64, u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self
            .inner
            .trigger_default_judgment(caller, now, mint, payout_to);
        let (payout, fee, refund) = self.map_reentrant(result, at)?;
        // `default_taker_amount` is the gross taker share by construction
        // (`payout + fee == default_taker_amount`).
        let amounts = EventAmounts {
            payout: payout + fee,
            fee,
            refund,
            penalty: 0,
            rent_reclaimed: 0,
        };
        // AV-22: the evidence hash survives on the escrow, so the
        // fallback settlement event carries the same commitment the
        // `Escalated` event carried.
        let evidence_hash = self.inner.evidence_hash();
        self.push_event(
            EscrowEventKind::DefaultJudgment,
            from,
            self.inner.state(),
            amounts,
            at,
            evidence_hash,
            None,
            None,
            None,
            Some(caller),
        );
        Ok((payout, fee, refund))
    }

    /// Submit one arbiter-panel member's judgment (mirrors
    /// [`Escrow::submit_panel_judgment`]). Emits `PanelJudgment` on
    /// every successful submission (`from == to == Disputed`): the
    /// member's key rides `caller`, the voted split rides
    /// `amounts.payout`, and the vote's rationale-document commitment
    /// rides the rationale slot — re-votes included, so an overwritten
    /// vote stays in the log as the audit trail. When the submission is
    /// the M-th matching vote, a `PanelResolved` event follows
    /// (`Disputed -> Settled`) with the `Resolved` amounts shape and
    /// the winning vote's rationale — the vote event first, then the
    /// settlement, in `seq` order. Returns what the inner method
    /// returns: `None` when the vote did not settle, `Some((payout,
    /// fee, refund))` when it did.
    pub fn submit_panel_judgment(
        &mut self,
        member: [u8; 32],
        taker_amount: u64,
        mint: Option<[u8; 32]>,
        rationale_hash: Option<[u8; 32]>,
        payout_to: [u8; 32],
        at: u64,
    ) -> Result<Option<(u64, u64, u64)>, EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self
            .inner
            .submit_panel_judgment(member, taker_amount, mint, rationale_hash, payout_to);
        let settled = self.map_reentrant(result, at)?;
        // Every submission is recorded, settled or not: the vote is
        // the audit trail.
        self.push_event(
            EscrowEventKind::PanelJudgment,
            from,
            self.inner.state(),
            EventAmounts {
                payout: taker_amount,
                fee: 0,
                refund: 0,
                penalty: 0,
                rent_reclaimed: 0,
            },
            at,
            None,
            rationale_hash,
            None,
            None,
            Some(member),
        );
        if let Some((_payout, fee, refund)) = settled {
            // The M-th matching vote settled the escrow: emit the
            // settlement after the vote event. `taker_amount` is the
            // gross taker share by construction
            // (`payout + fee == taker_amount`).
            let amounts = EventAmounts {
                payout: taker_amount,
                fee,
                refund,
                penalty: 0,
                rent_reclaimed: 0,
            };
            // AV-22: the evidence hash survives on the escrow, so the
            // panel settlement references the evidence the panel
            // reviewed. AV-38: the winning vote's rationale commitment
            // rides the settlement event.
            let evidence_hash = self.inner.evidence_hash();
            let rationale_hash = self.inner.rationale_hash();
            self.push_event(
                EscrowEventKind::PanelResolved,
                from,
                self.inner.state(),
                amounts,
                at,
                evidence_hash,
                rationale_hash,
                None,
                None,
                Some(member),
            );
        }
        Ok(settled)
    }

    /// Retune the arbiter panel's judgment threshold by dual-signed
    /// governance (mirrors [`Escrow::update_panel_threshold`], AV-69).
    /// Emits `PanelThresholdChanged` (`from == to == Uninitialized`)
    /// only on an actual change — retuning to the current threshold is
    /// an idempotent no-op that emits nothing (paralleling
    /// `rotate_fee_recipient`'s no-op rule); `at` is the caller-supplied
    /// event timestamp. Cast votes are untouched by the retune.
    pub fn update_panel_threshold(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        new_threshold: u8,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        let threshold_before = self.inner.arbiter_panel().map(|p| p.threshold);
        self.inner
            .update_panel_threshold(initializer, taker, new_threshold)?;
        let threshold_after = self.inner.arbiter_panel().map(|p| p.threshold);
        if threshold_before != threshold_after {
            self.push_event(
                EscrowEventKind::PanelThresholdChanged,
                from,
                self.inner.state(),
                EventAmounts::none(),
                at,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Re-split the milestone tranche amounts by dual-signed governance
    /// (mirrors [`Escrow::adjust_milestone_amounts`]). Emits
    /// `MilestonesAdjusted` when the amounts actually change (`from ==
    /// to ==` the current state — the schedule, not the lifecycle
    /// state, is what changed); a no-op re-affirmation emits nothing,
    /// paralleling [`Escrow::update_quorum`]'s no-op rule. `at` is the
    /// caller-supplied timestamp (on-chain: the clock sysvar).
    pub fn adjust_milestone_amounts(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        new_amounts: &[u64],
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        let before: Vec<u64> = self
            .inner
            .milestone_plan()
            .map(|p| (0..p.count()).map(|i| p.amount_at(i as usize).unwrap_or(0)).collect())
            .unwrap_or_default();
        self.inner
            .adjust_milestone_amounts(initializer, taker, new_amounts)?;
        let after: Vec<u64> = self
            .inner
            .milestone_plan()
            .map(|p| (0..p.count()).map(|i| p.amount_at(i as usize).unwrap_or(0)).collect())
            .unwrap_or_default();
        if after != before {
            self.push_event(
                EscrowEventKind::MilestonesAdjusted,
                from,
                self.inner.state(),
                EventAmounts::none(),
                at,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Re-split the subscription per-period amounts by dual-signed
    /// governance (mirrors [`Escrow::adjust_period_amounts`]). Emits
    /// `SubscriptionAmountsAdjusted` when the amounts actually change
    /// (`from == to ==` the current state — the schedule, not the
    /// lifecycle state, is what changed); a no-op re-affirmation
    /// emits nothing, paralleling
    /// [`EscrowEventKind::MilestonesAdjusted`]'s no-op rule. `at` is
    /// the caller-supplied timestamp (on-chain: the clock sysvar).
    pub fn adjust_period_amounts(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        new_amounts: &[u64],
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        let before: Vec<u64> = (0..super::MAX_SUBSCRIPTION_PERIODS)
            .filter_map(|i| self.inner.subscription_period_amount(i))
            .collect();
        self.inner
            .adjust_period_amounts(initializer, taker, new_amounts)?;
        let after: Vec<u64> = (0..super::MAX_SUBSCRIPTION_PERIODS)
            .filter_map(|i| self.inner.subscription_period_amount(i))
            .collect();
        if after != before {
            self.push_event(
                EscrowEventKind::SubscriptionAmountsAdjusted,
                from,
                self.inner.state(),
                EventAmounts::none(),
                at,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Migrate the vault's persisted schema to the current revision
    /// (mirrors [`Escrow::migrate_schema`], AV-85: the N → M step
    /// chain). Emits one `SchemaMigrated` per applied step (`from ==
    /// to ==` the current state — bookkeeping, not a lifecycle move,
    /// like [`EscrowEventKind::SubscriptionAmountsAdjusted`]); each
    /// event carries its step's `from → to` versions on
    /// [`EscrowEvent::schema_versions`], so the chain is recorded in
    /// `seq` order. The initializer is the single signer, so it rides
    /// the event's `actor`. A failed migration emits nothing — the
    /// inner chain rolls back to the pre-chain snapshot, so there is
    /// no partial state to record. `at` is the caller-supplied
    /// timestamp (on-chain: the clock sysvar).
    pub fn migrate_schema(&mut self, authority: [u8; 32], at: u64) -> Result<(), EscrowError> {
        let from = self.inner.state();
        let steps = self.inner.migrate_schema_steps(authority)?;
        let state = self.inner.state();
        debug_assert_eq!(from, state, "migration must not move lifecycle state");
        for step in steps {
            self.push_event(
                EscrowEventKind::SchemaMigrated,
                state,
                state,
                EventAmounts::none(),
                at,
                None,
                None,
                None,
                None,
                Some(authority),
            );
            // Stamp the step's versions after the push (the AV-77
            // `template_params_hash` precedent): the event chain
            // records every from → to pair.
            self.events
                .last_mut()
                .expect("SchemaMigrated event just pushed")
                .schema_versions = Some((step.from, step.to));
        }
        Ok(())
    }

    /// Dry-run the schema migration chain (mirrors
    /// [`Escrow::migrate_dry_run`], AV-85): return the
    /// [`MigrationPlan`](crate::MigrationPlan) the real
    /// [`IndexedEscrow::migrate_schema`] call would apply — every step
    /// in order with the fields each step appends. Pure read: emits no
    /// events and mutates nothing, so operators can preview the chain
    /// before the initializer signs.
    pub fn migrate_schema_dry_run(
        &self,
        authority: [u8; 32],
    ) -> Result<crate::MigrationPlan, EscrowError> {
        self.inner.migrate_dry_run(authority)
    }

    /// Confirm a milestone for the release path (mirrors
    /// [`Escrow::confirm_milestone`]). Emits `MilestoneConfirmed` when
    /// the milestone becomes fully confirmed (the completing vote); the
    /// first party's confirmation alone emits nothing, paralleling
    /// `activate`. `from == to == Funded`.
    pub fn confirm_milestone(
        &mut self,
        authority: [u8; 32],
        index: u8,
        at: u64,
    ) -> Result<(), EscrowError> {
        let i = index as usize;
        let confirmed_before = self.inner.milestone_confirmed(i);
        self.inner.confirm_milestone(authority, index)?;
        if !confirmed_before && self.inner.milestone_confirmed(i) {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::MilestoneConfirmed,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        }
        Ok(())
    }

    /// Release a milestone's tranche to the taker (mirrors
    /// [`Escrow::release_milestone`]). Emits `MilestoneReleased` with the
    /// gross tranche in `amounts.payout`; the final tranche carries
    /// `to == Released`. Returns `(taker_payout, fee)` like the inner
    /// method. `at` is both the event timestamp and the state machine's
    /// `now` (AV-27 timelock gate).
    pub fn release_milestone(
        &mut self,
        authority: [u8; 32],
        index: u8,
        mint: Option<[u8; 32]>,
        payout_to: [u8; 32],
        at: u64,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self
            .inner
            .release_milestone(authority, at, index, mint, payout_to);
        let (payout, fee) = self.map_reentrant(result, at)?;
        // `payout + fee` is the gross tranche (`<= amount`); no overflow
        // possible.
        self.push_event(
            EscrowEventKind::MilestoneReleased,
            from,
            self.inner.state(),
            EventAmounts::payout(payout + fee, fee),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok((payout, fee))
    }

    /// Emit [`EscrowEventKind::BundlePartiallyExecuted`] for a keeper
    /// milestone bundle that released a proper subset of the configured
    /// tranches (AV-76 — see
    /// [`crate::keeper::execute_milestone_bundle`]). `from == to ==` the
    /// current state (a proper subset can never settle the vault);
    /// `amounts` carries the executed tranches' totals — gross in
    /// `payout`, protocol fees in `fee`, like
    /// [`EscrowEventKind::MilestoneReleased`]. The actor is `None`: the
    /// bundle is a keeper composition, not a single authority — each
    /// executed tranche's own `MilestoneReleased` event already names
    /// its signer. `at` is the caller-supplied timestamp (the same `at`
    /// the bundle's tranche releases carried).
    pub(crate) fn emit_bundle_partially_executed(
        &mut self,
        total_gross: u64,
        total_fee: u64,
        at: u64,
    ) {
        let state = self.inner.state();
        self.push_event(
            EscrowEventKind::BundlePartiallyExecuted,
            state,
            state,
            EventAmounts::payout(total_gross, total_fee),
            at,
            None,
            None,
            None,
            None,
            None,
        );
    }

    /// AV-77: emit [`EscrowEventKind::TemplateApplied`] carrying the
    /// effective-parameter hash. `from == to ==` the current state (a
    /// configuration application, not a lifecycle move); all amounts
    /// are zero — applying a template moves no funds. The hash rides
    /// [`EscrowEvent::template_params_hash`], stamped after the push:
    /// it is computed by the template layer
    /// ([`TemplatePreset::apply_template`](crate::TemplatePreset::apply_template)),
    /// never invented by the wrapper — the same "read at emit time,
    /// never a `push_event` parameter" rule as `reference` (AV-53).
    /// The actor is `None`: applying a preset is a governance
    /// composition, not a single authority's transition (paralleling
    /// `emit_bundle_partially_executed`).
    fn emit_template_applied(&mut self, params_hash: [u8; 32], at: u64) {
        let state = self.inner.state();
        self.push_event(
            EscrowEventKind::TemplateApplied,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            None,
        );
        self.events
            .last_mut()
            .expect("TemplateApplied event just pushed")
            .template_params_hash = Some(params_hash);
    }

    /// Release a subscription period to the taker (mirrors
    /// [`Escrow::release_period`], AV-56). Emits
    /// `SubscriptionPeriodReleased` with the gross per-period amount in
    /// `amounts.payout`; `from == Funded`, `to == Funded` — or `to ==
    /// Released` on the last period. Returns `(taker_payout, fee)` like
    /// the inner method. `at` is both the event timestamp and the state
    /// machine's `now` (due-date + AV-27 timelock gates).
    pub fn release_period(
        &mut self,
        authority: [u8; 32],
        index: u8,
        mint: Option<[u8; 32]>,
        payout_to: [u8; 32],
        at: u64,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self
            .inner
            .release_period(authority, at, index, mint, payout_to);
        let (payout, fee) = self.map_reentrant(result, at)?;
        // `payout + fee` is the gross per-period amount
        // (`== per_period` by construction); no overflow possible.
        self.push_event(
            EscrowEventKind::SubscriptionPeriodReleased,
            from,
            self.inner.state(),
            EventAmounts::payout(payout + fee, fee),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok((payout, fee))
    }

    /// Skip a milestone by mutual agreement (mirrors
    /// [`Escrow::skip_milestone`]). Emits `MilestoneSkipped` only when
    /// the skip executes (both approvals present); a lone approval emits
    /// nothing. `from == to == Funded`, and `amounts.refund` carries the
    /// skipped tranche — the initializer's refund, never a taker payout.
    pub fn skip_milestone(
        &mut self,
        authority: [u8; 32],
        index: u8,
        at: u64,
    ) -> Result<(), EscrowError> {
        let i = index as usize;
        let settled_before = self.inner.milestone_settled(i);
        // The tranche amount is fixed by the plan; read it before the
        // call. A successful skip implies a configured plan and an
        // in-range index, so the fallback is unreachable on the event
        // path.
        let tranche = self
            .inner
            .milestone_plan()
            .and_then(|p| p.amount_at(i))
            .unwrap_or(0);
        self.inner.skip_milestone(authority, index)?;
        if !settled_before && self.inner.milestone_settled(i) {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::MilestoneSkipped,
            state,
            state,
            EventAmounts::refund(tranche),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        }
        Ok(())
    }

    /// Close the vault account and reclaim the rent-exempt deposit
    /// (mirrors [`Escrow::close_vault`]). Only the initializer may call
    /// this (`Unauthorized` otherwise, checked before state validity —
    /// a stranger learns nothing about state); only the terminal
    /// states `Cancelled`, `Released` and `Settled` may be closed
    /// (`InvalidStateTransition` otherwise — `Disputed` is not a
    /// terminal state, and `Closed` is the deepest terminal).
    ///
    /// Emits `VaultClosed` with `from` the terminal state the escrow
    /// was in and `to == Closed`; `amounts.rent_reclaimed` carries the
    /// reclaimed rent-exempt lamports
    /// ([`crate::vault_close_rent_reclaimed`]). Returns the reclaimed
    /// amount like the inner method.
    pub fn close_vault(&mut self, authority: [u8; 32], at: u64) -> Result<u64, EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self.inner.close_vault(authority);
        let rent = self.map_reentrant(result, at)?;
        self.push_event(
            EscrowEventKind::VaultClosed,
            from,
            self.inner.state(),
            EventAmounts::close(rent),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(rent)
    }

    /// Split a funded escrow into N child escrows by dual-signed
    /// governance (mirrors [`Escrow::split_escrow`](crate::Escrow::split_escrow),
    /// AV-81). Returns the child escrows as [`IndexedEscrow`]s — each
    /// under its derived escrow ID
    /// ([`crate::derive_split_child_id`]`(parent_id, index)`), each
    /// with its own event log.
    ///
    /// Emits [`EscrowEventKind::EscrowSplit`] on the *parent's* log
    /// (`from == Funded`, `to == Split`; `amounts.payout` is the Σ
    /// child amounts — the gross re-locked into the children — and the
    /// `(child_id, amount)` roster is stamped on the event's
    /// `split_children` field, so the whole split family is
    /// re-derivable from the one event). The actor is `None` — the
    /// split is dual-signed governance, not a single-actor call (like
    /// `TakerRotated`).
    ///
    /// Each child's log opens with `Initialized` (seq 0 — the
    /// per-escrow invariant), then `Activated` when the children
    /// inherit dual-signature activation (the split is dual-signed by
    /// construction, so both parties' activation is implied — actor
    /// `None`, like the parent's split event), then `Funded`: the exact
    /// lifecycle the inner state machine ran, replayed in `seq` order,
    /// so every child's lifecycle is independently indexable under its
    /// derived ID. `at` is both the event timestamp and the state
    /// machine's `now` (so each child's AV-64 `fund_at` sees the same
    /// clock the event log records).
    ///
    /// Atomicity mirrors the inner call: a failed split pushes no event
    /// and returns no children — the parent stays `Funded` (the AV-36
    /// `ReentryRejected` exception aside — see `map_reentrant`).
    pub fn split_escrow(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        amounts: &[u64],
        config: SplitConfig<'_>,
        at: u64,
    ) -> Result<Vec<IndexedEscrow>, EscrowError> {
        let parent_id = self.escrow_id;
        // AV-36: a rejected reentrant entry emits `ReentryRejected`
        // (the deliberate exception to the no-events-on-failure rule).
        // (The inner result is bound first so its `&mut` borrow ends
        // before `map_reentrant` reborrows `self`.) `at` doubles as the
        // inner `now`: each child's fund_at sees the same clock the
        // event log records.
        let result = self
            .inner
            .split_escrow(initializer, taker, amounts, config, at);
        let children = self.map_reentrant(result, at)?;
        // The inner call validated the table and built every child, so
        // the roster below cannot overflow: `amounts.len() <=
        // MAX_SPLIT_CHILDREN` was checked before any child existed, and
        // the Σ child amounts equal the parent's pre-split remaining
        // lockup (a `u64`), so the total cannot wrap either.
        let mut roster =
            [SplitChild { escrow_id: [0u8; 32], amount: 0 }; crate::MAX_SPLIT_CHILDREN];
        let mut indexed_children = Vec::with_capacity(children.len());
        let mut total: u64 = 0;
        for (i, child) in children.into_iter().enumerate() {
            let child_id = crate::derive_split_child_id(&parent_id, i as u64);
            roster[i] = SplitChild {
                escrow_id: child_id,
                amount: child.amount(),
            };
            total += child.amount();
            indexed_children.push(Self::wrap_split_child(child, child_id, at));
        }
        self.push_event(
            EscrowEventKind::EscrowSplit,
            EscrowState::Funded,
            EscrowState::Split,
            EventAmounts::split(total),
            at,
            None,
            None,
            None,
            None,
            None,
        );
        // Stamp the roster after the push (the AV-77
        // `template_params_hash` precedent): the event carries
        // parent/children/amounts — the parent is the event's own
        // `escrow_id`, the children ride here.
        self.events
            .last_mut()
            .expect("EscrowSplit event just pushed")
            .split_children = Some((roster, indexed_children.len() as u8));
        Ok(indexed_children)
    }

    /// Slash the defaulting taker (AV-82; mirrors [`Escrow::slash`]):
    /// `Funded -> Funded` — the escrow stays live. Emits
    /// [`EscrowEventKind::Slashed`] (from == to == `Funded`,
    /// `amounts.penalty` = the slashed amount) with the slash caller
    /// (the initializer or the arbiter) as the actor. On executor
    /// failure the state machine rolls back and nothing is emitted,
    /// like every other failed transition. Returns the slashed amount
    /// so the caller can size the transfer to the penalty account.
    /// `at` is both the event timestamp and the state machine's `now`.
    ///
    /// [`Escrow::slash`]: super::Escrow::slash
    pub fn slash(
        &mut self,
        authority: [u8; 32],
        amount: u64,
        mint: Option<[u8; 32]>,
        at: u64,
    ) -> Result<u64, EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self.inner.slash(authority, amount, mint, at);
        let slashed = self.map_reentrant(result, at)?;
        self.push_event(
            EscrowEventKind::Slashed,
            from,
            self.inner.state(),
            EventAmounts::slashed(slashed),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(slashed)
    }

    /// Opt in to the slash-appeal window (mirrors
    /// [`Escrow::with_appeal_window`], AV-86). Configuration: emits no
    /// event.
    pub fn with_appeal_window(mut self, window_secs: u64) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_appeal_window(window_secs)?;
        Ok(self)
    }

    /// File an appeal against the executed slash (AV-86; mirrors
    /// [`Escrow::file_appeal`]): `Funded -> Funded` — the taker contests
    /// the penalty inside the opt-in window, opening the arbiter
    /// panel's review. Emits [`EscrowEventKind::AppealFiled`] (from ==
    /// to == `Funded`, amounts zero) with the taker as the actor. On
    /// executor failure the state machine rolls back and nothing is
    /// emitted, like every other failed transition. `at` is both the
    /// event timestamp and the state machine's `now`.
    ///
    /// [`Escrow::file_appeal`]: super::Escrow::file_appeal
    pub fn file_appeal(&mut self, taker: [u8; 32], at: u64) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.file_appeal(taker, at)?;
        self.push_event(
            EscrowEventKind::AppealFiled,
            from,
            self.inner.state(),
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(taker),
        );
        Ok(())
    }

    /// Cast a panel member's review vote on the filed slash appeal
    /// (AV-86; mirrors [`Escrow::review_appeal`]). A non-resolving vote
    /// emits nothing — the ballot is still open, so there is no
    /// no-op-case event. The M-th matching vote resolves the appeal and
    /// emits [`EscrowEventKind::AppealResolved`] (from == to ==
    /// `Funded`; on overturn `amounts.payout` is the penalty refunded
    /// to the taker, zero on uphold) with the voting member as the
    /// actor, and the verdict is stamped on the event's `appeal_outcome`
    /// field. Returns `Ok(None)` while the ballot is open, or
    /// `Ok(Some((outcome, refunded)))` on resolution — `refunded` is the
    /// penalty returned to the taker (`0` on uphold) so the caller can
    /// size the transfer. `at` is the event timestamp; the state
    /// machine itself is not time-gated here (the window gates the
    /// filing, not the review).
    ///
    /// [`Escrow::review_appeal`]: super::Escrow::review_appeal
    pub fn review_appeal(
        &mut self,
        member: [u8; 32],
        uphold: bool,
        at: u64,
    ) -> Result<Option<(AppealOutcome, u64)>, EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self.inner.review_appeal(member, uphold);
        let resolved = self.map_reentrant(result, at)?;
        if let Some((outcome, refunded)) = resolved {
            let amounts = if refunded > 0 {
                EventAmounts::appeal_overturn(refunded)
            } else {
                EventAmounts::none()
            };
            self.push_event(
                EscrowEventKind::AppealResolved,
                from,
                self.inner.state(),
                amounts,
                at,
                None,
                None,
                None,
                None,
                Some(member),
            );
            // Stamp the verdict after the push (the AV-77
            // `template_params_hash` precedent): the event carries the
            // outcome the M-th vote settled, never a `push_event`
            // parameter.
            self.events
                .last_mut()
                .expect("AppealResolved event just pushed")
                .appeal_outcome = Some(outcome);
        }
        Ok(resolved)
    }

    /// AV-81: wrap a freshly-split child escrow in its own event log.
    /// Replays the exact lifecycle the inner state machine ran —
    /// `Initialized` (seq 0, the per-escrow invariant), then
    /// `Activated` when the child inherited dual-signature activation,
    /// then `Funded` — in `seq` order, so the child's lifecycle is
    /// independently indexable under its derived escrow ID.
    fn wrap_split_child(inner: Escrow, escrow_id: [u8; 32], at: u64) -> Self {
        let mut wrapped = Self {
            inner,
            escrow_id,
            events: Vec::new(),
            next_seq: 0,
        };
        // The child's `Initialized` names its initializer as the actor
        // — like every other `Initialized` event — while the
        // `Activated` / `Funded` legs carry no single actor: they are
        // effects of the dual-signed parent split, not single-actor
        // calls.
        let initializer = wrapped.inner.initializer();
        wrapped.push_event(
            EscrowEventKind::Initialized,
            EscrowState::Uninitialized,
            EscrowState::Uninitialized,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(initializer),
        );
        let mut from = EscrowState::Uninitialized;
        if wrapped.inner.dual_sig_required() {
            wrapped.push_event(
                EscrowEventKind::Activated,
                from,
                EscrowState::Activated,
                EventAmounts::none(),
                at,
                None,
                None,
                None,
                None,
                None,
            );
            from = EscrowState::Activated;
        }
        wrapped.push_event(
            EscrowEventKind::Funded,
            from,
            EscrowState::Funded,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            None,
        );
        wrapped
    }

    /// AV-79: record the [`EscrowEventKind::VaultsBatchClosed`] summary
    /// event on this escrow's log. Called by
    /// [`crate::close_indexed_vaults`] on the *first* vault the batch
    /// actually closed, after that vault's own `VaultClosed` event —
    /// so the summary sits in `seq` order on a participating vault's
    /// log, with `from == to == Closed` (a composition summary, not a
    /// lifecycle move — like
    /// [`EscrowEventKind::BundlePartiallyExecuted`]). `total_rent` is
    /// the Σ rent-exempt lamports the batch reclaimed (in
    /// `amounts.rent_reclaimed`, every other amount zero); `at` is the
    /// batch's timestamp and `actor` the initializer that ran it.
    /// Callers emit no summary when the batch closed nothing — the
    /// no-op rule lives in [`crate::close_indexed_vaults`], not here.
    pub fn record_vaults_batch_closed(&mut self, total_rent: u64, at: u64, actor: [u8; 32]) {        self.push_event(
            EscrowEventKind::VaultsBatchClosed,
            EscrowState::Closed,
            EscrowState::Closed,
            EventAmounts::batch_close(total_rent),
            at,
            None,
            None,
            None,
            None,
            Some(actor),
        );
    }

    /// Release the full remaining lockup to the taker and close the
    /// vault account in one atomic instruction (mirrors
    /// [`Escrow::release_and_close`], AV-50). Emits `Released`
    /// (`from == Funded`, `to == Released`, gross payout + fee) and
    /// then `VaultClosed` (`from == Released`, `to == Closed`,
    /// `rent_reclaimed`) — the two events land in `seq` order, and the
    /// order is fixed: payout first, close second, mirroring the fund
    /// movements on-chain. Returns `(taker_payout, fee, rent_reclaimed)`
    /// like the inner method. `at` is both the event timestamp and the
    /// state machine's `now` (so the AV-27 timelock gate sees the same
    /// clock the event log records).
    ///
    /// Atomicity is two-layered: the inner state machine restores
    /// `released` / `fees_paid` / `state` when the close leg fails, and
    /// this wrapper pushes no event unless both legs succeeded — a
    /// failed call leaves the event log untouched (the AV-36
    /// `ReentryRejected` exception aside — see `map_reentrant`).
    pub fn release_and_close(
        &mut self,
        authority: [u8; 32],
        mint: Option<[u8; 32]>,
        payout_to: [u8; 32],
        at: u64,
    ) -> Result<(u64, u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self.inner.release_and_close(authority, at, mint, payout_to);
        let (payout, fee, rent) = self.map_reentrant(result, at)?;
        // `payout + fee` is the gross payout by construction (== the
        // released remainder); it cannot overflow u64 addition.
        self.push_event(
            EscrowEventKind::Released,
            from,
            EscrowState::Released,
            EventAmounts::payout(payout + fee, fee),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        self.push_event(
            EscrowEventKind::VaultClosed,
            EscrowState::Released,
            EscrowState::Closed,
            EventAmounts::close(rent),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok((payout, fee, rent))
    }
}

#[cfg(test)]
mod event_tests {
    use super::*;
    use crate::{cpi_accounts_hash, AccountMeta, EscrowState, MilestonePlan, QuorumPolicy, VestingSchedule};

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const ATTESTOR_1: [u8; 32] = [0xA1; 32];
    const ATTESTOR_2: [u8; 32] = [0xA2; 32];
    const ATTESTOR_3: [u8; 32] = [0xA3; 32];
    const ARBITER: [u8; 32] = [0xA8; 32];
    const ESCROW_ID: [u8; 32] = [0x1D; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;
    const T0: u64 = 1_700_000_000;

    fn indexed(amount: u64) -> IndexedEscrow {
        IndexedEscrow::initialize(ALICE, BOB, amount, EXPIRES_AT, ESCROW_ID, T0).unwrap()
    }

    fn funded(amount: u64) -> IndexedEscrow {
        let mut e = indexed(amount);
        e.fund(ALICE, T0 + 1).unwrap();
        e
    }

    fn quorum_1_of_1() -> QuorumPolicy {
        QuorumPolicy::new(&[ATTESTOR_1], &[1], 1).unwrap()
    }

    fn milestone_indexed() -> IndexedEscrow {
        IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap()
    }

    // AV-56: 4 periods of 250_000 == the 1_000_000 lockup. The schedule
    // is back-pinned so the last period is due at EXPIRES_AT: period
    // `i` is due at `EXPIRES_AT - (4 - 1 - i) * 86_400`.
    const SUB_PERIOD_SECS: u64 = 86_400;
    const SUB_PERIODS: u8 = 4;
    const SUB_PER_PERIOD: u64 = 250_000;

    fn sub_due_at(i: u8) -> u64 {
        EXPIRES_AT - (SUB_PERIODS as u64 - 1 - i as u64) * SUB_PERIOD_SECS
    }

    fn subscription_indexed() -> IndexedEscrow {
        IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_subscription(SUB_PERIOD_SECS, SUB_PERIODS, SUB_PER_PERIOD)
            .unwrap()
    }

    fn last(e: &IndexedEscrow) -> EscrowEvent {
        *e.events().last().expect("expected at least one event")
    }

    fn assert_event(
        event: &EscrowEvent,
        kind: EscrowEventKind,
        seq: u64,
        from: EscrowState,
        to: EscrowState,
        payout: u64,
        fee: u64,
        refund: u64,
        at: u64,
    ) {
        assert_eq!(event.kind, kind, "kind");
        assert_eq!(event.escrow_id, ESCROW_ID, "escrow_id");
        assert_eq!(event.seq, seq, "seq");
        assert_eq!(event.from, from, "from");
        assert_eq!(event.to, to, "to");
        assert_eq!(
            event.amounts,
            EventAmounts {
                payout,
                fee,
                refund,
                penalty: 0,
                rent_reclaimed: 0,
            },
            "amounts"
        );
        assert_eq!(event.at, at, "at");
    }

    // ----- core lifecycle: seq order, from/to, kinds -----

    #[test]
    fn initialize_emits_seq_zero_with_conventional_state_pair() {
        let e = indexed(1_000_000);
        assert_eq!(e.event_count(), 1);
        assert_eq!(e.next_seq(), 1);
        assert_event(
            &e.events()[0],
            EscrowEventKind::Initialized,
            0,
            EscrowState::Uninitialized,
            EscrowState::Uninitialized,
            0,
            0,
            0,
            T0,
        );
    }

    #[test]
    fn initialize_fund_release_yields_ordered_seq() {
        let mut e = indexed(1_000_000);
        e.fund(ALICE, T0 + 1).unwrap();
        e.release(ALICE, 1_000_000, None, BOB, T0 + 2).unwrap();
        let events = e.events();
        assert_eq!(events.len(), 3);
        assert_event(
            &events[0],
            EscrowEventKind::Initialized,
            0,
            EscrowState::Uninitialized,
            EscrowState::Uninitialized,
            0,
            0,
            0,
            T0,
        );
        assert_event(
            &events[1],
            EscrowEventKind::Funded,
            1,
            EscrowState::Uninitialized,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 1,
        );
        assert_event(
            &events[2],
            EscrowEventKind::Released,
            2,
            EscrowState::Funded,
            EscrowState::Released,
            1_000_000,
            0,
            0,
            T0 + 2,
        );
        // Seq is dense and monotonic across the whole log.
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.seq, i as u64);
        }
    }

    #[test]
    fn partial_releases_emit_without_state_change() {
        let mut e = funded(1_000_000);
        e.release(ALICE, 400_000, None, BOB, T0 + 2).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::Released,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            400_000,
            0,
            0,
            T0 + 2,
        );
        e.release(ALICE, 600_000, None, BOB, T0 + 3).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::Released,
            3,
            EscrowState::Funded,
            EscrowState::Released,
            600_000,
            0,
            0,
            T0 + 3,
        );
    }

    #[test]
    fn fund_from_activated_records_true_from_state() {
        let mut e = indexed(1_000_000).with_dual_sig().unwrap();
        e.activate(ALICE, T0 + 1).unwrap();
        // Single signature: no transition, no event.
        assert_eq!(e.event_count(), 1);
        e.activate(BOB, T0 + 2).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::Activated,
            1,
            EscrowState::Uninitialized,
            EscrowState::Activated,
            0,
            0,
            0,
            T0 + 2,
        );
        e.fund(ALICE, T0 + 3).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::Funded,
            2,
            EscrowState::Activated,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 3,
        );
    }

    // ----- every kind: correct from/to/amounts -----

    #[test]
    fn cancel_emits_refund_of_remainder() {
        let mut e = funded(1_000_000);
        e.release(ALICE, 300_000, None, BOB, T0 + 2).unwrap();
        e.cancel(ALICE, None, ALICE, T0 + 3).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::Cancelled,
            3,
            EscrowState::Funded,
            EscrowState::Cancelled,
            0,
            0,
            700_000,
            T0 + 3,
        );
    }

    #[test]
    fn cancel_expired_emits_with_now_as_at() {
        let mut e = funded(1_000_000);
        e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::ExpiredCancelled,
            2,
            EscrowState::Funded,
            EscrowState::Cancelled,
            0,
            0,
            1_000_000,
            EXPIRES_AT,
        );
    }

    #[test]
    fn taker_initiated_cancel_emits_penalty_split() {
        // AV-24: a taker-initiated cancel with a penalty rate emits the
        // exact (refund, penalty) split — refund + penalty == remainder —
        // so indexers see the compensation routing.
        let mut e = indexed(1_000_000).with_penalty_bps(250).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        let (refund, penalty) = e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        assert_eq!((refund, penalty), (975_000, 25_000));
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::ExpiredCancelled);
        assert_eq!(event.amounts.refund, 975_000);
        assert_eq!(event.amounts.penalty, 25_000);
        assert_eq!(event.amounts.payout, 0);
        assert_eq!(event.amounts.fee, 0);
    }

    #[test]
    fn initializer_initiated_cancel_emits_zero_penalty() {
        // Same penalty rate, but the initializer calls: no penalty, the
        // event carries the full remainder as refund.
        let mut e = indexed(1_000_000).with_penalty_bps(250).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.cancel_expired(ALICE, EXPIRES_AT, None, ALICE).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::ExpiredCancelled);
        assert_eq!(event.amounts.refund, 1_000_000);
        assert_eq!(event.amounts.penalty, 0);
    }

    #[test]
    fn crank_expired_emits_expired_cranked_with_caller() {
        // AV-48: the permissionless crank emits `ExpiredCranked`
        // (not `ExpiredCancelled`) carrying the crank caller's key —
        // the one event kind where the caller is neither party.
        let mut e = funded(1_000_000);
        let (refund, penalty) = e.crank_expired(MALLORY, EXPIRES_AT, None).unwrap();
        assert_eq!((refund, penalty), (1_000_000, 0));
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::ExpiredCranked);
        assert_eq!(event.from, EscrowState::Funded);
        assert_eq!(event.to, EscrowState::Cancelled);
        assert_eq!(event.amounts.refund, 1_000_000);
        assert_eq!(event.amounts.penalty, 0);
        assert_eq!(event.caller, Some(MALLORY), "the crank caller is recorded");
        assert_eq!(event.at, EXPIRES_AT, "now doubles as at");
    }

    #[test]
    fn party_cancel_emits_no_caller() {
        // The `caller` field is `None` on every other kind — the event
        // log never invents a caller.
        let mut e = funded(1_000_000);
        e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::ExpiredCancelled);
        assert_eq!(event.caller, None);
    }

    #[test]
    fn taker_crank_emits_penalty_split() {
        // AV-48: a taker cranker pays the AV-24 penalty — the event
        // carries the exact (refund, penalty) split.
        let mut e = indexed(1_000_000).with_penalty_bps(250).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        let (refund, penalty) = e.crank_expired(BOB, EXPIRES_AT, None).unwrap();
        assert_eq!((refund, penalty), (975_000, 25_000));
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::ExpiredCranked);
        assert_eq!(event.amounts.refund, 975_000);
        assert_eq!(event.amounts.penalty, 25_000);
        assert_eq!(event.caller, Some(BOB));
    }

    #[test]
    fn failed_crank_emits_nothing() {
        // A premature crank emits nothing — the "failed calls emit
        // nothing" rule holds for the permissionless path too.
        let mut e = funded(1_000_000);
        assert!(e.crank_expired(MALLORY, EXPIRES_AT - 1, None).is_err());
        assert_eq!(e.drain_events().len(), 2, "only Initialized + Funded");
    }

    #[test]
    fn cancel_expired_inside_grace_window_fails_and_emits_nothing() {
        // AV-21: the grace gate is enforced by the state machine, so the
        // event log inherits it — a premature cancel emits no event and
        // the log still ends at the funding event.
        let mut e = indexed(1_000_000).with_grace_period(300).unwrap();
        e.fund(ALICE, T0).unwrap();
        let before = e.drain_events().len();
        assert_eq!(
            e.cancel_expired(BOB, EXPIRES_AT, None, ALICE),
            Err(EscrowError::NotExpired)
        );
        assert!(e.drain_events().is_empty(), "failed cancel emitted an event");
        assert_eq!(before, 2, "Initialized + Funded before the failed call");
        // After the grace period the same call succeeds and emits.
        e.cancel_expired(BOB, EXPIRES_AT + 300, None, ALICE).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::ExpiredCancelled,
            2,
            EscrowState::Funded,
            EscrowState::Cancelled,
            0,
            0,
            1_000_000,
            EXPIRES_AT + 300,
        );
    }

    #[test]
    fn attest_emits_progress_event() {
        let mut e = indexed(1_000_000).with_quorum(quorum_1_of_1()).unwrap();
        e.attest(ATTESTOR_1, T0 + 1).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::Attested,
            1,
            EscrowState::Uninitialized,
            EscrowState::Uninitialized,
            0,
            0,
            0,
            T0 + 1,
        );
    }

    #[test]
    fn claim_emits_gross_payout_and_uses_now_as_at() {
        let schedule = VestingSchedule::new(T0, T0 + 1_000).unwrap();
        let mut e = indexed(1_000_000).with_vesting(schedule).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        // Fully vested at `end`: the claim closes the escrow.
        let (payout, fee) = e.claim(BOB, T0 + 1_000, None, BOB).unwrap();
        assert_eq!((payout, fee), (1_000_000, 0));
        assert_event(
            &last(&e),
            EscrowEventKind::Claimed,
            2,
            EscrowState::Funded,
            EscrowState::Released,
            1_000_000,
            0,
            0,
            T0 + 1_000,
        );
    }

    #[test]
    fn escalate_and_resolve_emit_with_split_amounts() {
        let mut e = indexed(1_000_000).with_arbiter(ARBITER).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(BOB, EXPIRES_AT - 1, None).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::Escalated,
            2,
            EscrowState::Funded,
            EscrowState::Disputed,
            0,
            0,
            0,
            EXPIRES_AT - 1,
        );
        let (payout, fee, refund) = e.resolve(ARBITER, 600_000, None, None, BOB, T0 + 3).unwrap();
        assert_eq!((payout, fee, refund), (600_000, 0, 400_000));
        assert_event(
            &last(&e),
            EscrowEventKind::Resolved,
            3,
            EscrowState::Disputed,
            EscrowState::Settled,
            600_000,
            0,
            400_000,
            T0 + 3,
        );
    }

    #[test]
    fn escalated_event_carries_attached_evidence_hash() {
        // AV-22: the Escalated event carries the commitment attached at
        // escalation, so an indexer learns the evidence reference from
        // the event stream without a second account read.
        const EVIDENCE: [u8; 32] = [0xE1; 32];
        let mut e = indexed(1_000_000).with_arbiter(ARBITER).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(BOB, EXPIRES_AT - 1, Some(EVIDENCE)).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::Escalated);
        assert_eq!(event.evidence_hash, Some(EVIDENCE));
        // Without evidence the event carries None — the log never
        // invents evidence.
        let mut e2 = indexed(1_000_000).with_arbiter(ARBITER).unwrap();
        e2.fund(ALICE, T0 + 1).unwrap();
        e2.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
        assert_eq!(last(&e2).evidence_hash, None);
    }

    #[test]
    fn resolved_event_carries_the_stored_evidence_hash() {
        // AV-22: resolve does not take an evidence hash — the escrow
        // already holds it — and the Resolved event carries the stored
        // commitment, so the settlement references what the arbiter
        // reviewed.
        const EVIDENCE: [u8; 32] = [0xE1; 32];
        let mut e = indexed(1_000_000).with_arbiter(ARBITER).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1, Some(EVIDENCE)).unwrap();
        e.resolve(ARBITER, 600_000, None, None, BOB, T0 + 3).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::Resolved);
        assert_eq!(event.from, EscrowState::Disputed);
        assert_eq!(event.to, EscrowState::Settled);
        assert_eq!(event.evidence_hash, Some(EVIDENCE));
        // Non-dispute events never carry a hash.
        assert!(e
            .events()
            .iter()
            .filter(|ev| !matches!(
                ev.kind,
                EscrowEventKind::Escalated | EscrowEventKind::Resolved
            ))
            .all(|ev| ev.evidence_hash.is_none()));
    }

    // ---------- AV-68: evidence-disclosure deadline events ----------

    const EVIDENCE_DEADLINE: u64 = 3_600;

    fn disputed_with_evidence_deadline(escalator: [u8; 32], at: u64) -> IndexedEscrow {
        let mut e = indexed(1_000_000)
            .with_arbiter(ARBITER)
            .unwrap()
            .with_evidence_deadline(EVIDENCE_DEADLINE)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(escalator, at, None).unwrap();
        e
    }

    #[test]
    fn submit_evidence_emits_evidence_submitted() {
        // The disclosure rides the event's evidence slot; from == to ==
        // Disputed (a disclosure, not a lifecycle move).
        const EVIDENCE: [u8; 32] = [0xE1; 32];
        let mut e = disputed_with_evidence_deadline(BOB, T0 + 10);
        e.submit_evidence(BOB, EVIDENCE, T0 + 11).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::EvidenceSubmitted);
        assert_eq!(event.from, EscrowState::Disputed);
        assert_eq!(event.to, EscrowState::Disputed);
        assert_eq!(event.evidence_hash, Some(EVIDENCE));
        assert_eq!(event.at, T0 + 11);
        assert!(!event.evidence_defaulted, "disclosure is not a settlement");
        // A rejected (late) disclosure emits nothing.
        let n = e.events().len();
        assert!(e
            .submit_evidence(BOB, EVIDENCE, T0 + 10 + EVIDENCE_DEADLINE)
            .is_err());
        assert_eq!(e.events().len(), n, "failed call emits nothing");
    }

    #[test]
    fn resolved_event_flags_evidence_default() {
        // The deadline lapsed with no evidence on record: the
        // settlement records the default — the adverse-inference
        // signal favoring the non-escalating party.
        let mut e = disputed_with_evidence_deadline(BOB, T0 + 10);
        let settled_at = T0 + 10 + EVIDENCE_DEADLINE + 1;
        e.resolve(ARBITER, 600_000, None, None, BOB, settled_at)
            .unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::Resolved);
        assert!(event.evidence_defaulted, "deadline lapsed undisclosed");
        assert_eq!(event.evidence_hash, None);
    }

    #[test]
    fn resolved_event_no_default_when_disclosed_in_time() {
        // Disclosure within the window clears the inference — even
        // when the settlement happens after the deadline.
        const EVIDENCE: [u8; 32] = [0xE1; 32];
        let mut e = disputed_with_evidence_deadline(BOB, T0 + 10);
        e.submit_evidence(BOB, EVIDENCE, T0 + 11).unwrap();
        e.resolve(ARBITER, 600_000, None, None, BOB, T0 + 10 + EVIDENCE_DEADLINE + 1)
            .unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::Resolved);
        assert!(!event.evidence_defaulted);
        assert_eq!(event.evidence_hash, Some(EVIDENCE));
    }

    #[test]
    fn resolved_event_no_default_without_deadline() {
        // Backward compatible: no deadline configured, no default
        // signal — even settling "late".
        let mut e = indexed(1_000_000).with_arbiter(ARBITER).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(BOB, T0 + 10, None).unwrap();
        e.resolve(ARBITER, 600_000, None, None, BOB, u64::MAX - 1)
            .unwrap();
        assert!(!last(&e).evidence_defaulted);
    }

    #[test]
    fn default_judgment_event_flags_evidence_default() {
        // The AV-55 fallback settlement carries the same
        // judgment-time signal.
        let mut e = indexed(1_000_000)
            .with_arbiter(ARBITER)
            .unwrap()
            .with_evidence_deadline(EVIDENCE_DEADLINE)
            .unwrap()
            .with_arbitration_deadline(7_200, 400_000)
            .unwrap()
            .confirm_default_judgment(BOB)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(ALICE, T0 + 10, None).unwrap();
        let trigger_at = T0 + 10 + 7_200;
        e.trigger_default_judgment(BOB, trigger_at, None, BOB, trigger_at)
            .unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::DefaultJudgment);
        assert!(event.evidence_defaulted, "deadline lapsed undisclosed");
    }

    #[test]
    fn panel_resolved_event_flags_evidence_default() {
        // Panel mode: the multisig settlement carries the signal too.
        const M1: [u8; 32] = [0xC1; 32];
        const M2: [u8; 32] = [0xC2; 32];
        let mut e = indexed(1_000_000)
            .with_arbiter_panel(&[M1, M2], 2)
            .unwrap()
            .with_evidence_deadline(EVIDENCE_DEADLINE)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(BOB, T0 + 10, None).unwrap();
        let settled_at = T0 + 10 + EVIDENCE_DEADLINE + 1;
        e.submit_panel_judgment(M1, 600_000, None, None, BOB, settled_at)
            .unwrap();
        e.submit_panel_judgment(M2, 600_000, None, None, BOB, settled_at)
            .unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::PanelResolved);
        assert!(event.evidence_defaulted, "deadline lapsed undisclosed");
        // The vote events themselves never carry the settlement
        // signal.
        assert!(e
            .events()
            .iter()
            .filter(|ev| ev.kind == EscrowEventKind::PanelJudgment)
            .all(|ev| !ev.evidence_defaulted));
    }

    #[test]
    fn non_settlement_events_never_carry_the_default_signal() {
        // The log never invents a default: only the three settlement
        // kinds may carry it.
        let mut e = disputed_with_evidence_deadline(BOB, T0 + 10);
        assert!(e
            .events()
            .iter()
            .all(|ev| !ev.evidence_defaulted));
        e.submit_evidence(BOB, [0xE1; 32], T0 + 11).unwrap();
        assert!(e
            .events()
            .iter()
            .all(|ev| !ev.evidence_defaulted));
    }

    #[test]
    fn resolved_event_carries_the_rationale_hash() {
        // AV-38: the arbiter attaches the rationale-document commitment
        // at settlement, and the Resolved event carries it — alongside
        // the evidence hash — so the settlement references the ruling
        // it wrote. Without a rationale the event carries None: the log
        // never invents one.
        const RATIONALE: [u8; 32] = [0xA1; 32];
        const EVIDENCE: [u8; 32] = [0xE1; 32];
        let mut e = indexed(1_000_000).with_arbiter(ARBITER).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1, Some(EVIDENCE)).unwrap();
        e.resolve(ARBITER, 600_000, None, Some(RATIONALE), BOB, T0 + 3)
            .unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::Resolved);
        assert_eq!(event.rationale_hash, Some(RATIONALE));
        assert_eq!(
            event.evidence_hash,
            Some(EVIDENCE),
            "rationale must not displace the evidence commitment"
        );

        let mut e2 = indexed(1_000_000).with_arbiter(ARBITER).unwrap();
        e2.fund(ALICE, T0 + 1).unwrap();
        e2.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
        e2.resolve(ARBITER, 600_000, None, None, BOB, T0 + 3).unwrap();
        assert_eq!(last(&e2).rationale_hash, None);
        // Non-resolve events never carry a rationale hash.
        assert!(e
            .events()
            .iter()
            .chain(e2.events().iter())
            .filter(|ev| !matches!(ev.kind, EscrowEventKind::Resolved))
            .all(|ev| ev.rationale_hash.is_none()));
    }

    #[test]
    fn milestone_confirm_release_skip_emit() {
        let mut e = milestone_indexed();
        e.fund(ALICE, T0 + 1).unwrap();
        // First confirmation: progress only, no event.
        e.confirm_milestone(ALICE, 0, T0 + 2).unwrap();
        assert_eq!(e.event_count(), 2);
        // Completing confirmation: the event.
        e.confirm_milestone(BOB, 0, T0 + 3).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::MilestoneConfirmed,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 3,
        );
        e.release_milestone(ALICE, 0, None, BOB, T0 + 4).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::MilestoneReleased,
            3,
            EscrowState::Funded,
            EscrowState::Funded,
            400_000,
            0,
            0,
            T0 + 4,
        );
        // Skip needs both approvals; the first emits nothing.
        e.skip_milestone(ALICE, 1, T0 + 5).unwrap();
        assert_eq!(e.event_count(), 4);
        e.skip_milestone(BOB, 1, T0 + 6).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::MilestoneSkipped,
            4,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            600_000,
            T0 + 6,
        );
    }

    #[test]
    fn subscription_period_release_emits() {
        // AV-56: every period pays out to the taker in due-date order.
        // The first three releases are partial (`from == to == Funded`);
        // the last one closes the escrow (`to == Released`).
        let mut e = subscription_indexed();
        e.fund(ALICE, T0 + 1).unwrap();
        for (i, seq) in (0..SUB_PERIODS - 1).zip(2..5u64) {
            let due = sub_due_at(i);
            let (payout, fee) = e.release_period(ALICE, i, None, BOB, due).unwrap();
            assert_eq!((payout, fee), (SUB_PER_PERIOD, 0));
            assert_event(
                &last(&e),
                EscrowEventKind::SubscriptionPeriodReleased,
                seq,
                EscrowState::Funded,
                EscrowState::Funded,
                SUB_PER_PERIOD,
                0,
                0,
                due,
            );
        }
        let due_last = sub_due_at(SUB_PERIODS - 1);
        let (payout, fee) = e
            .release_period(ALICE, SUB_PERIODS - 1, None, BOB, due_last)
            .unwrap();
        assert_eq!((payout, fee), (SUB_PER_PERIOD, 0));
        assert_event(
            &last(&e),
            EscrowEventKind::SubscriptionPeriodReleased,
            5,
            EscrowState::Funded,
            EscrowState::Released,
            SUB_PER_PERIOD,
            0,
            0,
            due_last,
        );
        assert_eq!(e.inner().subscription_released_periods(), 0b1111);
    }

    // ----- failed transitions emit nothing -----

    #[test]
    fn failed_transitions_emit_nothing() {
        let mut e = funded(1_000_000);
        let baseline = e.event_count();
        // Unauthorized fund.
        assert!(e.fund(MALLORY, T0 + 9).is_err());
        // Double fund.
        assert!(e.fund(ALICE, T0 + 9).is_err());
        // Zero-amount release.
        assert!(e.release(ALICE, 0, None, BOB, T0 + 9).is_err());
        // Over-release.
        assert!(e.release(ALICE, 1_000_001, None, BOB, T0 + 9).is_err());
        // Cancel by a stranger.
        assert!(e.cancel(MALLORY, None, ALICE, T0 + 9).is_err());
        // Attest with no quorum configured.
        assert!(e.attest(ATTESTOR_1, T0 + 9).is_err());
        // Escalate with no arbiter configured.
        assert!(e.escalate(ALICE, T0 + 9, None).is_err());
        // Resolve outside a dispute.
        assert!(e.resolve(ARBITER, 1, None, None, BOB, T0 + 9).is_err());
        // Milestone ops with no plan attached.
        assert!(e.confirm_milestone(ALICE, 0, T0 + 9).is_err());
        assert!(e.release_milestone(ALICE, 0, None, BOB, T0 + 9).is_err());
        assert!(e.skip_milestone(ALICE, 0, T0 + 9).is_err());
        // Failed constructor emits nothing either.
        assert!(IndexedEscrow::initialize(ALICE, BOB, 0, EXPIRES_AT, ESCROW_ID, T0).is_err());
        assert_eq!(e.event_count(), baseline);
        assert_eq!(e.next_seq(), baseline as u64);
    }

    #[test]
    fn duplicate_attest_emits_nothing() {
        let mut e = indexed(1_000_000).with_quorum(quorum_1_of_1()).unwrap();
        e.attest(ATTESTOR_1, T0 + 1).unwrap();
        assert_eq!(e.event_count(), 2);
        // Idempotent in the state machine: the approval count does not
        // grow, so no second event.
        e.attest(ATTESTOR_1, T0 + 2).unwrap();
        assert_eq!(e.event_count(), 2);
        assert_eq!(e.next_seq(), 2);
    }

    #[test]
    fn update_quorum_emits_governance_event() {
        // AV-25: a real threshold change emits QuorumUpdated with
        // from == to == the current state and zero amounts — the event
        // is the ordering signal, the new threshold is read from the
        // vault.
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], &[1, 1], 2).unwrap();
        let mut e = indexed(1_000_000).with_quorum(policy).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.update_quorum(ALICE, BOB, 1, T0 + 2).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::QuorumUpdated,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 2,
        );
    }

    #[test]
    fn update_quorum_noop_emits_nothing() {
        // Same threshold: the state machine succeeds but nothing
        // observable changed, so no event — paralleling `attest`'s
        // idempotent duplicates.
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], &[1, 1], 2).unwrap();
        let mut e = indexed(1_000_000).with_quorum(policy).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        assert_eq!(e.event_count(), 2);
        e.update_quorum(ALICE, BOB, 2, T0 + 2).unwrap();
        assert_eq!(e.event_count(), 2);
        assert_eq!(e.next_seq(), 2);
    }

    #[test]
    fn failed_update_quorum_emits_nothing() {
        // One party alone is Unauthorized: the failed governance call
        // emits no event and the threshold is untouched.
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], &[1, 1], 2).unwrap();
        let mut e = indexed(1_000_000).with_quorum(policy).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        assert_eq!(
            e.update_quorum(ALICE, MALLORY, 1, T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert!(e.drain_events().len() == 2, "failed update emitted an event");
    }

    #[test]
    fn update_attestors_emits_governance_event() {
        // AV-39: a real set change emits AttestorsUpdated with
        // from == to == the current state and zero amounts — the event
        // is the ordering signal, the new set is read from the vault.
        // ATTESTOR_1's vote is dropped with ATTESTOR_1; ATTESTOR_2's
        // vote remaps to its new slot.
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], &[1, 1], 1).unwrap();
        let mut e = indexed(1_000_000).with_quorum(policy).unwrap();
        e.attest(ATTESTOR_1, T0 + 1).unwrap();
        e.fund(ALICE, T0 + 2).unwrap();
        e.update_attestors(ALICE, BOB, &[ATTESTOR_2, ATTESTOR_3], &[1, 1], T0 + 3)
            .unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::AttestorsUpdated,
            3,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 3,
        );
        // The removed voter's bit is gone at the wrapper level too:
        // quorum progress recomputed from the retained (voteless)
        // set, so the 1-of-2 is no longer satisfied.
        assert!(!e.inner().quorum().unwrap().is_satisfied());
    }

    #[test]
    fn update_attestors_noop_emits_nothing() {
        // The identical set in the identical order: the state machine
        // succeeds but nothing observable changed, so no event —
        // paralleling `update_quorum`'s no-op rule.
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], &[1, 1], 2).unwrap();
        let mut e = indexed(1_000_000).with_quorum(policy).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        assert_eq!(e.event_count(), 2);
        e.update_attestors(ALICE, BOB, &[ATTESTOR_1, ATTESTOR_2], &[1, 1], T0 + 2)
            .unwrap();
        assert_eq!(e.event_count(), 2);
        assert_eq!(e.next_seq(), 2);
    }

    #[test]
    fn failed_update_attestors_emits_nothing() {
        // One party alone is Unauthorized: the failed governance call
        // emits no event and the set is untouched.
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], &[1, 1], 2).unwrap();
        let mut e = indexed(1_000_000).with_quorum(policy).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        assert_eq!(
            e.update_attestors(ALICE, MALLORY, &[ATTESTOR_1], &[1], T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert!(e.drain_events().len() == 2, "failed update emitted an event");
    }

    #[test]
    fn builders_emit_nothing() {
        let e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_quorum(quorum_1_of_1())
            .unwrap()
            .with_dual_sig()
            .unwrap()
            .with_vesting(VestingSchedule::new(T0, T0 + 1_000).unwrap())
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap()
            .with_mint([0xD0; 32])
            .unwrap()
            .with_protocol_fee(250)
            .unwrap()
            .with_penalty_bps(250)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap();
        // Configuration is not a transition: only the Initialized event.
        assert_eq!(e.event_count(), 1);
        assert_eq!(e.events()[0].kind, EscrowEventKind::Initialized);
    }

    // ----- amounts: fees split honestly -----

    #[test]
    fn fee_escrow_splits_payout_and_fee_in_events() {
        let mut e = indexed(1_000_000).with_protocol_fee(250).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        let (payout, fee) = e.release(ALICE, 1_000_000, None, BOB, T0 + 2).unwrap();
        // 250 bps of 1_000_000 = 25_000.
        assert_eq!((payout, fee), (975_000, 25_000));
        assert_event(
            &last(&e),
            EscrowEventKind::Released,
            2,
            EscrowState::Funded,
            EscrowState::Released,
            1_000_000,
            25_000,
            0,
            T0 + 2,
        );
    }

    #[test]
    fn resolve_event_carries_fee_on_taker_share_only() {
        let mut e = indexed(1_000_000)
            .with_arbiter(ARBITER)
            .unwrap()
            .with_protocol_fee(1_000)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
        let (payout, fee, refund) = e.resolve(ARBITER, 600_000, None, None, BOB, T0 + 3).unwrap();
        // 1000 bps of 600_000 = 60_000; the refund is never fee'd.
        assert_eq!((payout, fee, refund), (540_000, 60_000, 400_000));
        assert_event(
            &last(&e),
            EscrowEventKind::Resolved,
            3,
            EscrowState::Disputed,
            EscrowState::Settled,
            600_000,
            60_000,
            400_000,
            T0 + 3,
        );
    }

    // ----- drain: clears the log, never the sequence -----

    #[test]
    fn drain_events_clears_log_and_seq_continues() {
        let mut e = funded(1_000_000);
        let drained = e.drain_events();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].seq, 0);
        assert_eq!(drained[1].seq, 1);
        assert!(e.events().is_empty());
        assert_eq!(e.event_count(), 0);
        // The sequence counter keeps running across drains.
        e.release(ALICE, 1_000_000, None, BOB, T0 + 2).unwrap();
        assert_eq!(e.events().len(), 1);
        assert_eq!(e.events()[0].seq, 2);
        assert_eq!(e.next_seq(), 3);
    }

    // ----- accessors and identity -----

    #[test]
    fn accessors_expose_inner_state_and_identity() {
        let mut e = indexed(1_000_000);
        assert_eq!(e.escrow_id(), ESCROW_ID);
        assert_eq!(e.inner().state(), EscrowState::Uninitialized);
        assert_eq!(e.inner().amount(), 1_000_000);
        e.fund(ALICE, T0 + 1).unwrap();
        assert_eq!(e.inner().state(), EscrowState::Funded);
        // Every event carries the escrow identity.
        assert!(e.events().iter().all(|ev| ev.escrow_id == ESCROW_ID));
    }

    #[test]
    fn distinct_escrows_carry_distinct_identities() {
        let mut a = indexed(1_000_000);
        let mut b =
            IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, [0xBE; 32], T0).unwrap();
        a.fund(ALICE, T0 + 1).unwrap();
        b.fund(ALICE, T0 + 1).unwrap();
        // Independent per-escrow sequences: both start at 0.
        assert_eq!(a.events()[1].seq, 1);
        assert_eq!(b.events()[1].seq, 1);
        assert_ne!(a.events()[1].escrow_id, b.events()[1].escrow_id);
    }

    #[test]
    fn event_types_are_copy_and_comparable() {
        let mut e = funded(500_000);
        let first = e.events()[0];
        let copied = first;
        assert_eq!(first, copied);
        let drained = e.drain_events();
        assert_eq!(drained[0], first);
        // Kinds are distinct values.
        assert_ne!(
            EscrowEventKind::Cancelled,
            EscrowEventKind::ExpiredCancelled
        );
    }

    // ----- AV-34: terminal-state vault close with rent reclamation -----

    fn terminal_indexed(state: EscrowState) -> IndexedEscrow {
        let mut e = funded(1_000_000);
        match state {
            EscrowState::Cancelled => e.cancel(ALICE, None, ALICE, T0 + 2).unwrap(),
            EscrowState::Released => {
                e.release(ALICE, 1_000_000, None, BOB, T0 + 2).unwrap();
            }
            EscrowState::Settled => {
                let mut d = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
                    .unwrap()
                    .with_arbiter(ARBITER)
                    .unwrap();
                d.fund(ALICE, T0 + 1).unwrap();
                d.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
                d.resolve(ARBITER, 0, None, None, BOB, T0 + 3).unwrap();
                return d;
            }
            _ => panic!("not a terminal state"),
        }
        assert_eq!(e.inner().state(), state);
        e
    }

    #[test]
    fn close_vault_emits_vault_closed_with_reclaimed_rent() {
        for state in [
            EscrowState::Cancelled,
            EscrowState::Released,
            EscrowState::Settled,
        ] {
            let mut e = terminal_indexed(state);
            let seq_before = e.next_seq();
            let rent = e.close_vault(ALICE, T0 + 10).unwrap();
            assert_eq!(
                rent,
                crate::vault_close_rent_reclaimed(),
                "from {state:?}"
            );
            assert_eq!(e.inner().state(), EscrowState::Closed);
            let event = last(&e);
            assert_eq!(event.kind, EscrowEventKind::VaultClosed, "from {state:?}");
            assert_eq!(event.seq, seq_before, "from {state:?}");
            assert_eq!(event.from, state, "from {state:?}");
            assert_eq!(event.to, EscrowState::Closed, "from {state:?}");
            assert_eq!(event.escrow_id, ESCROW_ID, "from {state:?}");
            assert_eq!(event.at, T0 + 10, "from {state:?}");
            assert_eq!(event.evidence_hash, None, "from {state:?}");
            assert_eq!(
                event.amounts,
                EventAmounts {
                    payout: 0,
                    fee: 0,
                    refund: 0,
                    penalty: 0,
                    rent_reclaimed: crate::vault_close_rent_reclaimed(),
                },
                "from {state:?}: only rent_reclaimed carries value"
            );
        }
    }

    #[test]
    fn failed_close_vault_emits_nothing() {
        // Stranger on a terminal vault: Unauthorized, checked before
        // state validity.
        let mut e = terminal_indexed(EscrowState::Cancelled);
        let events_before = e.event_count();
        assert_eq!(e.close_vault(MALLORY, T0 + 10), Err(EscrowError::Unauthorized));
        assert_eq!(e.event_count(), events_before);
        // Live escrow: InvalidStateTransition.
        let mut funded = funded(1_000_000);
        let events_before = funded.event_count();
        assert_eq!(
            funded.close_vault(ALICE, T0 + 10),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(funded.event_count(), events_before);
        // Disputed is not terminal: the arbitration is still live.
        let mut d = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        d.fund(ALICE, T0 + 1).unwrap();
        d.escalate(ALICE, EXPIRES_AT - 1, None).unwrap();
        let events_before = d.event_count();
        assert_eq!(
            d.close_vault(ALICE, T0 + 10),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(d.event_count(), events_before);
    }

    // ----- AV-50: release_and_close dual events -----

    #[test]
    fn release_and_close_emits_released_then_vault_closed_in_fixed_order() {
        let mut e = funded(1_000_000);
        let seq_before = e.next_seq();
        let (payout, fee, rent) = e.release_and_close(ALICE, None, BOB, T0 + 2).unwrap();
        assert_eq!((payout, fee), (1_000_000, 0));
        assert_eq!(rent, crate::vault_close_rent_reclaimed());
        assert_eq!(e.inner().state(), EscrowState::Closed);
        let events = e.events();
        // Exactly two new events, in seq order: payout first, close
        // second — the order is fixed, mirroring the fund movements.
        assert_eq!(events.len() as u64 - seq_before, 2);
        let released = &events[events.len() - 2];
        assert_eq!(released.kind, EscrowEventKind::Released);
        assert_eq!(released.seq, seq_before);
        assert_eq!(released.from, EscrowState::Funded);
        assert_eq!(released.to, EscrowState::Released);
        assert_eq!(released.escrow_id, ESCROW_ID);
        assert_eq!(released.amounts.payout, 1_000_000);
        assert_eq!(released.amounts.fee, 0);
        assert_eq!(released.amounts.rent_reclaimed, 0);
        assert_eq!(released.at, T0 + 2);
        let closed = &events[events.len() - 1];
        assert_eq!(closed.kind, EscrowEventKind::VaultClosed);
        assert_eq!(closed.seq, seq_before + 1);
        assert_eq!(closed.from, EscrowState::Released);
        assert_eq!(closed.to, EscrowState::Closed);
        assert_eq!(closed.escrow_id, ESCROW_ID);
        assert_eq!(
            closed.amounts.rent_reclaimed,
            crate::vault_close_rent_reclaimed()
        );
        assert_eq!(closed.amounts.payout, 0);
        assert_eq!(closed.amounts.fee, 0);
        assert_eq!(closed.at, T0 + 2);
    }

    #[test]
    fn release_and_close_first_event_carries_gross_payout_and_fee() {
        // 250 bps fee: the Released event carries gross payout (payout +
        // fee) and the fee; the VaultClosed event carries only the rent.
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_protocol_fee(250)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        let (payout, fee, _) = e.release_and_close(ALICE, None, BOB, T0 + 2).unwrap();
        assert_eq!((payout, fee), (975_000, 25_000));
        let events = e.events();
        let released = &events[events.len() - 2];
        assert_eq!(released.kind, EscrowEventKind::Released);
        assert_eq!(released.amounts.payout, 1_000_000);
        assert_eq!(released.amounts.fee, 25_000);
        let closed = &events[events.len() - 1];
        assert_eq!(closed.kind, EscrowEventKind::VaultClosed);
        assert_eq!(closed.amounts.payout, 0);
        assert_eq!(closed.amounts.fee, 0);
    }

    #[test]
    fn failed_release_and_close_emits_nothing() {
        // Stranger on a live escrow: Unauthorized, no events.
        let mut e = funded(1_000_000);
        let events_before = e.event_count();
        assert_eq!(
            e.release_and_close(MALLORY, None, BOB, T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.event_count(), events_before);
        // Non-Funded state: InvalidStateTransition, no events.
        let mut fresh = indexed(1_000_000);
        let events_before = fresh.event_count();
        assert_eq!(
            fresh.release_and_close(ALICE, None, BOB, T0 + 2),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(fresh.event_count(), events_before);
        // Already-closed: the deepest terminal rejects too, silently.
        let mut closed = funded(1_000_000);
        closed.release_and_close(ALICE, None, BOB, T0 + 2).unwrap();
        let events_before = closed.event_count();
        assert_eq!(
            closed.release_and_close(ALICE, None, BOB, T0 + 3),
            Err(EscrowError::InvalidStateTransition)
        );
        assert_eq!(closed.event_count(), events_before);
    }

    // ----- AV-35: CPI-routed release events -----

    fn dex_invocation() -> CpiInvocation {
        CpiInvocation {
            program_id: [0xD1; 32],
            accounts: vec![
                AccountMeta { pubkey: [1u8; 32], is_signer: true, is_writable: true },
                AccountMeta { pubkey: [2u8; 32], is_signer: false, is_writable: true },
            ],
            data: vec![7, 7, 7],
        }
    }

    #[test]
    fn cpi_routed_release_emits_released_with_cpi_audit() {
        let mut e = funded(1_000_000);
        let inv = dex_invocation();
        let (payout, fee, receipt) = e
            .release_via_cpi(ALICE, 1_000_000, None, BOB, T0 + 2, &inv, |_| Ok(()))
            .unwrap();
        assert_eq!((payout, fee), (1_000_000, 0));
        let event = last(&e);
        assert_event(
            &event,
            EscrowEventKind::Released,
            2,
            EscrowState::Funded,
            EscrowState::Released,
            1_000_000,
            0,
            0,
            T0 + 2,
        );
        // The audit trail pins the exact authorized instruction.
        let audit = event.cpi.expect("CPI-routed release must carry the CPI audit");
        assert_eq!(audit.target, [0xD1; 32]);
        assert_eq!(audit.accounts_hash, receipt.accounts_hash);
        assert_eq!(audit.accounts_hash, cpi_accounts_hash(&inv));
    }

    #[test]
    fn failed_cpi_release_emits_nothing() {
        let mut e = funded(1_000_000);
        let inv = dex_invocation();
        let events_before = e.event_count();
        assert_eq!(
            e.release_via_cpi(ALICE, 1_000_000, None, BOB, T0 + 2, &inv, |_| {
                Err(CpiError::ZeroAddress)
            }),
            Err(EscrowError::CpiExecutionFailed)
        );
        assert_eq!(e.event_count(), events_before);
        // The next successful release still gets the next seq — the
        // failed one left no gap in the event log.
        e.release_via_cpi(ALICE, 1_000_000, None, BOB, T0 + 3, &inv, |_| Ok(()))
            .unwrap();
        assert_eq!(last(&e).seq, events_before as u64);
    }

    #[test]
    fn plain_release_carries_no_cpi_audit() {
        let mut e = funded(1_000_000);
        e.release(ALICE, 1_000_000, None, BOB, T0 + 2).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::Released);
        assert_eq!(event.cpi, None);
        // And no other event kind ever carries one either.
        assert!(e.events().iter().all(|ev| ev.cpi.is_none() || ev.kind == EscrowEventKind::Released));
    }

    // ----- AV-36: reentrancy rejection events -----

    fn cpi_invocation() -> CpiInvocation {
        CpiInvocation {
            program_id: [0xD1; 32],
            accounts: vec![AccountMeta {
                pubkey: [0x01; 32],
                is_signer: false,
                is_writable: true,
            }],
            data: vec![9],
        }
    }

    #[test]
    fn reentry_rejected_event_fires_on_nested_entry() {
        // A hostile executor "calls back" into the escrow mid-release
        // (raw pointer past the &mut borrow — the pure-logic model of
        // a CPI target re-entering the program). The reentrant call
        // goes through the `IndexedEscrow` wrapper, so the rejection
        // is rejected *and* recorded as a security signal.
        let mut e = funded(1_000_000);
        let events_before = e.event_count();
        let inv = cpi_invocation();
        let raw: *mut IndexedEscrow = std::ptr::addr_of_mut!(e);
        e.release_via_cpi(ALICE, 1_000_000, None, BOB, T0 + 2, &inv, |_| {
            let nested = unsafe { &mut *raw };
            assert_eq!(
                nested.release(ALICE, 100, None, BOB, T0 + 2),
                Err(EscrowError::ReentrantCall)
            );
            Ok(())
        })
        .unwrap();
        // The rejection emitted exactly one event: from == to == the
        // state at executor time (the full release already settled, so
        // `Released`), zero amounts, then the outer release's own
        // event in seq order.
        assert_eq!(e.event_count(), events_before + 2);
        let rejected = e.events()[events_before];
        assert_eq!(rejected.kind, EscrowEventKind::ReentryRejected);
        assert_eq!(rejected.from, EscrowState::Released);
        assert_eq!(rejected.to, EscrowState::Released);
        assert_eq!(
            rejected.amounts,
            EventAmounts {
                payout: 0,
                fee: 0,
                refund: 0,
                penalty: 0,
                rent_reclaimed: 0,
            }
        );
        assert_eq!(rejected.seq + 1, last(&e).seq);
        assert_eq!(last(&e).kind, EscrowEventKind::Released);
        // The nested attempt changed nothing.
        assert_eq!(e.inner().released_amount(), 1_000_000);
    }

    #[test]
    fn non_reentrant_failures_still_emit_nothing() {
        // The ReentryRejected exception is narrow: ordinary failures
        // keep the "failed calls emit nothing" rule.
        let mut e = funded(1_000_000);
        let events_before = e.event_count();
        assert_eq!(
            e.release(MALLORY, 100, None, BOB, T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.event_count(), events_before);
        assert_eq!(
            e.cancel(ALICE, None, MALLORY, T0 + 2),
            Err(EscrowError::RefundAddressMismatch)
        );
        assert_eq!(e.event_count(), events_before);
    }

    // ----- AV-57: the on-chain event-history ring -----

    #[test]
    fn indexed_transitions_append_to_the_ring_with_actor_summaries() {
        // Every successful transition the wrapper emits also lands in
        // the on-chain ring — kind, timestamp, and the actor's 8-byte
        // summary — in the same order as the off-chain event log.
        let mut e = indexed(1_000_000);
        e.fund(ALICE, T0 + 1).unwrap();
        e.release(ALICE, 400_000, None, BOB, T0 + 2).unwrap();
        let h = e.event_history();
        assert_eq!(h.len(), 3);
        assert_eq!(
            h.iter().map(|r| r.kind).collect::<Vec<_>>(),
            vec![
                EscrowEventKind::Initialized,
                EscrowEventKind::Funded,
                EscrowEventKind::Released,
            ]
        );
        assert_eq!(h[0].at, T0);
        assert_eq!(h[1].at, T0 + 1);
        assert_eq!(h[2].at, T0 + 2);
        // Actor summaries are the first 8 bytes of the acting key.
        assert_eq!(h[0].actor, Some([0xAA; 8]));
        assert_eq!(h[1].actor, Some([0xAA; 8]));
        assert_eq!(h[2].actor, Some([0xAA; 8]));
        assert_eq!(e.inner().event_total(), 3);
        assert_eq!(e.inner().event_count(), 3);
        // The ring agrees with the off-chain event log, entry by entry.
        let kinds: Vec<EscrowEventKind> = e.events().iter().map(|ev| ev.kind).collect();
        assert_eq!(kinds, h.iter().map(|r| r.kind).collect::<Vec<_>>());
    }

    #[test]
    fn crank_expired_records_the_crank_caller_as_actor() {
        // AV-48: the permissionless crank is the one transition whose
        // actor is neither party — the ring keeps the caller's
        // summary, like the event's `caller` field keeps the key.
        let mut e = funded(1_000_000);
        e.crank_expired(MALLORY, EXPIRES_AT + 1, None).unwrap();
        let h = e.event_history();
        assert_eq!(h.len(), 3);
        assert_eq!(h[2].kind, EscrowEventKind::ExpiredCranked);
        assert_eq!(h[2].actor, Some([0xCC; 8]));
    }

    #[test]
    fn dual_signed_governance_records_no_single_actor() {
        // Dual-signed governance has no single actor — the ring
        // records `None` rather than misattributing the transition to
        // one of the two signers.
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], &[1, 1], 2).unwrap();
        let mut e = indexed(1_000_000).with_quorum(policy).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.update_quorum(ALICE, BOB, 1, T0 + 2).unwrap();
        let h = e.event_history();
        assert_eq!(h.len(), 3);
        assert_eq!(h[2].kind, EscrowEventKind::QuorumUpdated);
        assert_eq!(h[2].actor, None);
    }

    #[test]
    fn failed_indexed_transitions_append_nothing_to_the_ring() {
        // The "failed calls emit nothing" rule covers the ring too
        // (the AV-36 `ReentryRejected` exception aside).
        let mut e = funded(1_000_000);
        let total_before = e.inner().event_total();
        let count_before = e.inner().event_count();
        assert_eq!(e.fund(MALLORY, T0 + 5), Err(EscrowError::Unauthorized));
        assert_eq!(
            e.release(MALLORY, 100, None, BOB, T0 + 6),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(e.inner().event_total(), total_before);
        assert_eq!(e.inner().event_count(), count_before);
    }

    #[test]
    fn indexed_ring_wraps_at_configured_capacity() {
        // The wrapper-level ring honors `with_event_capacity`: the
        // off-chain log keeps every event, the on-chain ring keeps the
        // most recent N — `total` still counts them all.
        let mut e = indexed(1_000_000).with_event_capacity(3).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.release(ALICE, 400_000, None, BOB, T0 + 2).unwrap();
        e.release(ALICE, 600_000, None, BOB, T0 + 3).unwrap();
        assert_eq!(e.event_count(), 4, "off-chain log keeps everything");
        let h = e.event_history();
        assert_eq!(h.len(), 3, "on-chain ring keeps the last 3");
        assert_eq!(e.inner().event_total(), 4);
        assert_eq!(
            h.iter().map(|r| r.kind).collect::<Vec<_>>(),
            vec![
                EscrowEventKind::Funded,
                EscrowEventKind::Released,
                EscrowEventKind::Released,
            ],
            "the oldest (Initialized) aged out first"
        );
    }

    #[test]
    fn with_event_capacity_builder_is_configuration() {
        // Like every other with_* builder: Uninitialized-only, emits
        // no event, and the ring only starts recording at the
        // Initialized event.
        let e = indexed(1_000_000).with_event_capacity(8).unwrap();
        assert_eq!(e.inner().event_capacity(), 8);
        assert_eq!(e.event_count(), 1, "only the Initialized event");
        assert_eq!(
            indexed(1_000_000).with_event_capacity(0).unwrap_err(),
            EscrowError::InvalidEventCapacity
        );
    }
    // ---------- AV-69: PanelThresholdChanged events ----------
    const PM1: [u8; 32] = [0xC1; 32];
    const PM2: [u8; 32] = [0xC2; 32];
    const PM3: [u8; 32] = [0xC3; 32];

    fn panel_indexed(threshold: u8) -> IndexedEscrow {
        IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_arbiter_panel(&[PM1, PM2, PM3], threshold)
            .unwrap()
    }

    #[test]
    fn panel_threshold_changed_emits_event_on_change() {
        let mut e = panel_indexed(3);
        let before = e.event_count();
        e.update_panel_threshold(ALICE, BOB, 2, T0 + 1).unwrap();
        assert_eq!(e.event_count(), before + 1, "one event on change");
        let ev = e.events().last().unwrap();
        assert_eq!(ev.kind, EscrowEventKind::PanelThresholdChanged);
        assert_eq!(ev.from, EscrowState::Uninitialized);
        assert_eq!(ev.to, EscrowState::Uninitialized);
        assert_eq!(ev.amounts, EventAmounts::none(), "moves no funds");
        // The new threshold is read from the vault: the event is the
        // ordering signal.
        assert_eq!(
            e.inner().arbiter_panel().unwrap().threshold,
            2,
            "vault carries the retuned M"
        );
    }

    #[test]
    fn panel_threshold_changed_no_op_emits_nothing() {
        let mut e = panel_indexed(2);
        let before = e.event_count();
        e.update_panel_threshold(ALICE, BOB, 2, T0 + 1).unwrap();
        assert_eq!(e.event_count(), before, "no-op retune emits nothing");
    }

    #[test]
    fn panel_threshold_changed_unauthorized_emits_nothing() {
        let mut e = panel_indexed(2);
        let before = e.event_count();
        assert_eq!(
            e.update_panel_threshold(ALICE, MALLORY, 1, T0 + 1)
                .unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(e.event_count(), before, "failed call emits nothing");
    }

    #[test]
    fn panel_threshold_changed_kind_round_trips() {
        // discriminant 34: appended last, 0–33 stable for
        // already-serialized histories.
        let kind = EscrowEventKind::PanelThresholdChanged;
        assert_eq!(kind.discriminant(), 34);
        assert_eq!(EscrowEventKind::from_discriminant(34), Some(kind));
        assert_eq!(kind.name(), "panel_threshold_changed");
    }

    #[test]
    fn milestones_adjusted_kind_round_trips() {
        // discriminant 35: appended after PanelThresholdChanged, 0–34
        // stable for already-serialized histories.
        let kind = EscrowEventKind::MilestonesAdjusted;
        assert_eq!(kind.discriminant(), 35);
        assert_eq!(EscrowEventKind::from_discriminant(35), Some(kind));
        assert_eq!(kind.name(), "milestones_adjusted");
    }

    #[test]
    fn schema_migrated_kind_round_trips() {
        // discriminant 37: appended after SubscriptionAmountsAdjusted,
        // 0–36 stable for already-serialized histories.
        let kind = EscrowEventKind::SchemaMigrated;
        assert_eq!(kind.discriminant(), 37);
        assert_eq!(EscrowEventKind::from_discriminant(37), Some(kind));
        assert_eq!(kind.name(), "schema_migrated");
        assert_eq!(EscrowEventKind::from_name("schema_migrated"), Some(kind));
    }

    #[test]
    fn bundle_partially_executed_kind_round_trips() {
        // discriminant 38: appended after SchemaMigrated, 0–37 stable
        // for already-serialized histories.
        let kind = EscrowEventKind::BundlePartiallyExecuted;
        assert_eq!(kind.discriminant(), 38);
        assert_eq!(EscrowEventKind::from_discriminant(38), Some(kind));
        assert_eq!(kind.name(), "bundle_partially_executed");
        assert_eq!(
            EscrowEventKind::from_name("bundle_partially_executed"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(46), None);
    }

    #[test]
    fn template_applied_kind_round_trips() {
        // AV-77: discriminant 39, appended after
        // BundlePartiallyExecuted — 0–38 stay stable for
        // already-serialized histories.
        let kind = EscrowEventKind::TemplateApplied;
        assert_eq!(kind.discriminant(), 39);
        assert_eq!(EscrowEventKind::from_discriminant(39), Some(kind));
        assert_eq!(kind.name(), "template_applied");
        assert_eq!(
            EscrowEventKind::from_name("template_applied"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(46), None);
    }

    #[test]
    fn migrate_schema_emits_event_and_records_history() {
        // Simulate a pre-AV-75 vault: the trailing schema byte reads 0.
        let mut e = indexed(1_000_000);
        e.inner.schema_version = 0;
        let before = e.event_count();
        e.migrate_schema(ALICE, T0 + 1).unwrap();
        // AV-85: one SchemaMigrated per applied step — the event chain
        // records every from → to version pair in seq order.
        assert_eq!(e.event_count(), before + 3, "one event per chain step");
        let events = e.events();
        let first = &events[before];
        let second = &events[before + 1];
        let third = &events[before + 2];
        for ev in [first, second, third] {
            assert_eq!(ev.kind, EscrowEventKind::SchemaMigrated);
            assert_eq!(ev.from, EscrowState::Uninitialized);
            assert_eq!(ev.to, EscrowState::Uninitialized, "from == to == current state");
            assert_eq!(ev.amounts, EventAmounts::none(), "moves no funds");
        }
        assert_eq!(first.schema_versions, Some((0, 1)));
        assert_eq!(second.schema_versions, Some((1, 2)));
        assert_eq!(third.schema_versions, Some((2, 3)));
        assert_eq!(second.seq, first.seq + 1, "chain order in seq");
        assert_eq!(third.seq, second.seq + 1, "chain order in seq");
        // The on-chain history ring records the same transitions — the
        // initializer is the single signer, so it rides the ring's
        // actor slot. (The ring already holds the `Initialized` entry
        // from construction.)
        let history = e.inner().event_history();
        assert_eq!(history.len(), 4, "ring records each chain step");
        let entry = history.last().expect("ring records the migration");
        assert_eq!(entry.kind, EscrowEventKind::SchemaMigrated);
        assert_eq!(entry.at, T0 + 1);
        assert_eq!(entry.actor, Some(ALICE[..8].try_into().unwrap()));
    }

    #[test]
    fn migrate_schema_chain_emits_single_event_for_single_step() {
        // A v2 vault runs just its own step: exactly one event, stamped
        // (2, 3).
        let mut e = indexed(1_000_000);
        e.inner.schema_version = 2;
        let before = e.event_count();
        e.migrate_schema(ALICE, T0 + 1).unwrap();
        assert_eq!(e.event_count(), before + 1);
        let ev = last(&e);
        assert_eq!(ev.kind, EscrowEventKind::SchemaMigrated);
        assert_eq!(ev.schema_versions, Some((2, 3)));
    }

    #[test]
    fn migrate_schema_dry_run_emits_nothing_and_mutates_nothing() {
        let mut e = indexed(1_000_000);
        e.inner.schema_version = 0; // simulate a pre-AV-75 vault
        let before_events = e.event_count();
        let plan = e.migrate_schema_dry_run(ALICE).unwrap();
        assert_eq!(plan.from, 0);
        assert_eq!(plan.to, 3);
        assert_eq!(plan.steps.len(), 3);
        assert_eq!(e.event_count(), before_events, "dry-run emits nothing");
        assert_eq!(e.inner.schema_version(), 0, "dry-run mutates nothing");
        // A refused dry-run also emits nothing.
        let current = indexed(1_000_000);
        let current_before = current.event_count();
        assert_eq!(
            current.migrate_schema_dry_run(ALICE).unwrap_err(),
            EscrowError::InvalidSchemaMigration
        );
        assert_eq!(current.event_count(), current_before);
    }

    #[test]
    fn migrate_schema_rejection_emits_nothing() {
        let mut e = indexed(1_000_000);
        let before = e.event_count();
        let ring_before = e.inner().event_history().len();
        // Already current: the inner gate refuses, so nothing emits.
        assert_eq!(
            e.migrate_schema(ALICE, T0 + 1).unwrap_err(),
            EscrowError::InvalidSchemaMigration
        );
        assert_eq!(e.event_count(), before, "failed call emits nothing");
        assert_eq!(
            e.inner().event_history().len(),
            ring_before,
            "failed call records nothing on-chain"
        );
    }

    // ----- AV-76: keeper milestone bundle execution -----

    use crate::keeper::{execute_milestone_bundle, MilestoneAction, MilestoneActionKind};

    /// Funded escrow with a 3-tranche plan (300k/300k/400k ==
    /// 1_000_000), no confirmations yet.
    fn bundle_indexed() -> IndexedEscrow {
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[300_000, 300_000, 400_000]).unwrap())
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e
    }

    /// Dual-confirm the first unsettled tranche through the real API
    /// (confirmations are strictly in-order).
    fn confirm_next(e: &mut IndexedEscrow) {
        let i = e.inner().next_milestone().expect("a tranche is unsettled") as u8;
        e.confirm_milestone(ALICE, i, T0 + 2).unwrap();
        e.confirm_milestone(BOB, i, T0 + 3).unwrap();
        assert!(e.inner().milestone_confirmed(i as usize));
    }

    /// Dual-confirm every tranche at once. The public API confirms
    /// strictly in-order (only the first unsettled milestone is
    /// confirmable), so a multi-confirmed bundle fixture sets the
    /// confirmation bitmap directly — the bitmap is the source of
    /// truth `release_milestone` reads.
    fn confirm_all(e: &mut IndexedEscrow, count: usize) {
        for i in 0..count {
            e.inner.milestone_flags |=
                crate::Escrow::milestone_bit(i, crate::MILESTONE_CONFIRM_INIT_BIT)
                    | crate::Escrow::milestone_bit(i, crate::MILESTONE_CONFIRM_TAKER_BIT);
        }
        for i in 0..count {
            assert!(e.inner().milestone_confirmed(i));
        }
    }

    fn release_action(index: u8, tranche: u64) -> MilestoneAction {
        MilestoneAction {
            escrow_id: ESCROW_ID,
            kind: MilestoneActionKind::ReleaseMilestone,
            index,
            caller: ALICE,
            caller_role: "initializer",
            mint: None,
            tranche,
            fee: 0,
            taker_payout: tranche,
            decimals: 0,
            reason: "confirmed",
        }
    }

    #[test]
    fn bundle_full_execution_releases_all_and_settles() {
        let mut e = bundle_indexed();
        confirm_all(&mut e, 3);
        let actions = [
            release_action(0, 300_000),
            release_action(1, 300_000),
            release_action(2, 400_000),
        ];
        let before = e.event_count();
        let out =
            execute_milestone_bundle(&mut e, ESCROW_ID, &actions, None, BOB, T0 + 10).unwrap();
        assert_eq!(out.executed, vec![0, 1, 2]);
        assert!(out.remaining.is_empty(), "full execution leaves nothing");
        assert!(out.settled, "executing every tranche settles the vault");
        assert_eq!(e.inner().state(), EscrowState::Released);
        assert_eq!(e.inner().released_amount(), 1_000_000);
        // Three per-tranche MilestoneReleased events, and no partial
        // event on a full execution.
        assert_eq!(e.event_count(), before + 3);
        assert!(e
            .events()
            .iter()
            .all(|ev| ev.kind != EscrowEventKind::BundlePartiallyExecuted));
        assert_event(
            &e.events()[before],
            EscrowEventKind::MilestoneReleased,
            before as u64,
            EscrowState::Funded,
            EscrowState::Funded,
            300_000,
            0,
            0,
            T0 + 10,
        );
        assert_event(
            &e.events()[before + 1],
            EscrowEventKind::MilestoneReleased,
            before as u64 + 1,
            EscrowState::Funded,
            EscrowState::Funded,
            300_000,
            0,
            0,
            T0 + 10,
        );
        assert_event(
            &e.events()[before + 2],
            EscrowEventKind::MilestoneReleased,
            before as u64 + 2,
            EscrowState::Funded,
            EscrowState::Released,
            400_000,
            0,
            0,
            T0 + 10,
        );
    }

    #[test]
    fn bundle_proper_subset_emits_partial_event() {
        let mut e = bundle_indexed();
        confirm_next(&mut e); // tranche 0 dual-confirmed via the real API
        let actions = [release_action(0, 300_000)];
        let before = e.event_count();
        let out =
            execute_milestone_bundle(&mut e, ESCROW_ID, &actions, Some(&[0]), BOB, T0 + 10)
                .unwrap();
        assert_eq!(out.executed, vec![0]);
        assert_eq!(out.remaining, vec![1, 2]);
        assert!(!out.settled, "a proper subset never settles the vault");
        assert_eq!(e.inner().state(), EscrowState::Funded);
        assert!(e.inner().milestone_settled(0));
        assert!(!e.inner().milestone_settled(1), "unselected tranche stays pending");
        assert!(!e.inner().milestone_settled(2), "unselected tranche stays pending");
        // The per-tranche MilestoneReleased precedes the partial event.
        assert_eq!(e.event_count(), before + 2);
        assert_event(
            &e.events()[before],
            EscrowEventKind::MilestoneReleased,
            before as u64,
            EscrowState::Funded,
            EscrowState::Funded,
            300_000,
            0,
            0,
            T0 + 10,
        );
        assert_event(
            &e.events()[before + 1],
            EscrowEventKind::BundlePartiallyExecuted,
            before as u64 + 1,
            EscrowState::Funded,
            EscrowState::Funded,
            300_000,
            0,
            0,
            T0 + 10,
        );
        // The on-chain ring records the partial event with no actor —
        // the bundle is a keeper composition, not a single authority.
        let ring = e.inner().event_history();
        let entry = ring.last().expect("ring records the bundle");
        assert_eq!(entry.kind, EscrowEventKind::BundlePartiallyExecuted);
        assert_eq!(entry.at, T0 + 10);
        assert_eq!(entry.actor, None);
    }

    #[test]
    fn bundle_full_set_subset_matches_full_execution() {
        let mut e = bundle_indexed();
        confirm_all(&mut e, 3);
        let actions = [
            release_action(0, 300_000),
            release_action(1, 300_000),
            release_action(2, 400_000),
        ];
        // Unsorted on purpose: the executor normalizes to ascending
        // index order, and a subset equal to the full configured index
        // set is a full execution — no partial event.
        let out =
            execute_milestone_bundle(&mut e, ESCROW_ID, &actions, Some(&[2, 0, 1]), BOB, T0 + 10)
                .unwrap();
        assert_eq!(out.executed, vec![0, 1, 2]);
        assert!(out.remaining.is_empty());
        assert!(out.settled);
        assert_eq!(e.inner().state(), EscrowState::Released);
        assert!(e
            .events()
            .iter()
            .all(|ev| ev.kind != EscrowEventKind::BundlePartiallyExecuted));
    }

    #[test]
    fn bundle_rejects_bad_input_without_side_effects() {
        let mut e = bundle_indexed();
        confirm_next(&mut e);
        let actions = [release_action(0, 300_000)];
        let before = e.event_count();
        let ring_before = e.inner().event_history().len();

        // Empty bundle.
        assert_eq!(
            execute_milestone_bundle(&mut e, ESCROW_ID, &[], None, BOB, T0 + 10).unwrap_err(),
            EscrowError::InvalidMilestones
        );
        // Action for a different escrow.
        let mut mixed = release_action(0, 300_000);
        mixed.escrow_id = [0x99; 32];
        assert_eq!(
            execute_milestone_bundle(&mut e, ESCROW_ID, &[mixed], None, BOB, T0 + 10).unwrap_err(),
            EscrowError::InvalidMilestones
        );
        // Confirm/skip are governance, not keeper execution.
        let mut not_release = release_action(0, 300_000);
        not_release.kind = MilestoneActionKind::ConfirmMilestone;
        assert_eq!(
            execute_milestone_bundle(&mut e, ESCROW_ID, &[not_release], None, BOB, T0 + 10)
                .unwrap_err(),
            EscrowError::InvalidMilestones
        );
        // Empty subset.
        assert_eq!(
            execute_milestone_bundle(&mut e, ESCROW_ID, &actions, Some(&[]), BOB, T0 + 10)
                .unwrap_err(),
            EscrowError::InvalidMilestones
        );
        // Out-of-range index (the backlog's "非法索引" gate reuses the
        // existing InvalidMilestones variant, code 110).
        assert_eq!(
            execute_milestone_bundle(&mut e, ESCROW_ID, &actions, Some(&[3]), BOB, T0 + 10)
                .unwrap_err(),
            EscrowError::InvalidMilestones
        );
        // Duplicate indices.
        assert_eq!(
            execute_milestone_bundle(&mut e, ESCROW_ID, &actions, Some(&[0, 0]), BOB, T0 + 10)
                .unwrap_err(),
            EscrowError::InvalidMilestones
        );
        // Subset index with no bundle action.
        assert_eq!(
            execute_milestone_bundle(&mut e, ESCROW_ID, &actions, Some(&[1]), BOB, T0 + 10)
                .unwrap_err(),
            EscrowError::InvalidMilestones
        );
        // Escrow without a milestone plan.
        let mut plain = funded(1_000_000);
        assert_eq!(
            execute_milestone_bundle(&mut plain, ESCROW_ID, &actions, None, BOB, T0 + 10)
                .unwrap_err(),
            EscrowError::InvalidMilestones
        );

        // Every rejection leaves state and the event log untouched.
        assert_eq!(e.event_count(), before, "rejected bundle emits nothing");
        assert_eq!(
            e.inner().event_history().len(),
            ring_before,
            "rejected bundle records nothing on-chain"
        );
        assert_eq!(e.inner().state(), EscrowState::Funded);
        assert!(!e.inner().milestone_settled(0));
        assert_eq!(e.inner().released_amount(), 0);
    }

    #[test]
    fn bundle_atomic_rollback_on_tranche_failure() {
        let mut e = bundle_indexed();
        confirm_next(&mut e); // only tranche 0 confirmed; tranche 1 is not
        let actions = [release_action(0, 300_000), release_action(1, 300_000)];
        let before = e.event_count();
        let ring_before = e.inner().event_history().len();
        // Tranche 0 releases, then tranche 1 fails (unconfirmed) — the
        // whole subset rolls back.
        assert_eq!(
            execute_milestone_bundle(&mut e, ESCROW_ID, &actions, Some(&[0, 1]), BOB, T0 + 10)
                .unwrap_err(),
            EscrowError::MilestoneNotConfirmed
        );
        assert_eq!(e.inner().state(), EscrowState::Funded);
        assert!(!e.inner().milestone_settled(0), "tranche 0's release rolled back");
        assert_eq!(e.inner().released_amount(), 0);
        assert_eq!(e.event_count(), before, "failed bundle leaks no events");
        assert_eq!(
            e.inner().event_history().len(),
            ring_before,
            "failed bundle records nothing on-chain"
        );
    }

    #[test]
    fn milestones_adjusted_emits_event_on_change() {
        let mut e = milestone_indexed();
        let before = e.event_count();
        e.adjust_milestone_amounts(ALICE, BOB, &[500_000, 500_000], T0 + 1)
            .unwrap();
        assert_eq!(e.event_count(), before + 1, "one event on change");
        let ev = e.events().last().unwrap();
        assert_eq!(ev.kind, EscrowEventKind::MilestonesAdjusted);
        assert_eq!(ev.from, EscrowState::Uninitialized);
        assert_eq!(ev.to, EscrowState::Uninitialized);
        assert_eq!(ev.amounts, EventAmounts::none(), "moves no funds");
        // The new amounts are read from the vault: the event is the
        // ordering signal.
        let plan = e.inner().milestone_plan().unwrap();
        assert_eq!(plan.amount_at(0), Some(500_000));
        assert_eq!(plan.amount_at(1), Some(500_000));
    }

    #[test]
    fn milestones_adjusted_no_op_emits_nothing() {
        let mut e = milestone_indexed();
        let before = e.event_count();
        e.adjust_milestone_amounts(ALICE, BOB, &[400_000, 600_000], T0 + 1)
            .unwrap();
        assert_eq!(e.event_count(), before, "no-op re-affirmation emits nothing");
    }

    #[test]
    fn milestones_adjusted_unauthorized_emits_nothing() {
        let mut e = milestone_indexed();
        let before = e.event_count();
        assert_eq!(
            e.adjust_milestone_amounts(ALICE, MALLORY, &[500_000, 500_000], T0 + 1)
                .unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(e.event_count(), before, "failed call emits nothing");
    }

    // ---------- AV-77: apply_template ----------

    fn subscription_preset() -> TemplatePreset<'static> {
        TemplatePreset::subscription(ALICE, BOB, 1_000_000, EXPIRES_AT, 100, 4, 250_000)
    }

    #[test]
    fn apply_template_emits_initialized_then_template_applied() {
        let preset = subscription_preset();
        let overrides: &[(&str, OverrideValue)] =
            &[("period_secs", OverrideValue::U64(200))];
        let expected_hash = preset.apply_template(overrides).unwrap().params_hash;

        let e = IndexedEscrow::apply_template(&preset, overrides, ESCROW_ID, T0).unwrap();
        let events = e.events();
        assert_eq!(events.len(), 2);
        // seq 0 stays the Initialized event (the per-escrow invariant).
        assert_eq!(events[0].kind, EscrowEventKind::Initialized);
        assert_eq!(events[0].seq, 0);
        assert_eq!(events[0].template_params_hash, None);
        // seq 1 is the TemplateApplied event with the effective hash.
        let applied = &events[1];
        assert_eq!(applied.kind, EscrowEventKind::TemplateApplied);
        assert_eq!(applied.seq, 1);
        assert_eq!(applied.from, EscrowState::Uninitialized);
        assert_eq!(applied.to, EscrowState::Uninitialized);
        assert_eq!(applied.at, T0);
        assert_eq!(applied.escrow_id, ESCROW_ID);
        assert_eq!(applied.amounts, EventAmounts::none());
        assert_eq!(applied.template_params_hash, Some(expected_hash));
        // The built escrow is live: the overridden cadence took effect.
        assert_eq!(
            e.inner().subscription_period_due_at(0).unwrap(),
            EXPIRES_AT - 3 * 200
        );
    }

    #[test]
    fn apply_template_noop_applies_preset_defaults() {
        // An empty override list still applies (and emits): the hash
        // is the preset defaults' own commitment.
        let preset = subscription_preset();
        let e = IndexedEscrow::apply_template(&preset, &[], ESCROW_ID, T0).unwrap();
        let applied = e.events().last().expect("TemplateApplied emitted");
        assert_eq!(applied.kind, EscrowEventKind::TemplateApplied);
        assert_eq!(
            applied.template_params_hash,
            Some(preset.template.params_hash())
        );
        // The escrow runs the default cadence end to end.
        let mut e = e;
        e.fund(ALICE, EXPIRES_AT - 1_000).unwrap();
        let due_0 = e.inner().subscription_period_due_at(0).unwrap();
        let (payout, _) = e.release_period(ALICE, 0, None, BOB, due_0).unwrap();
        assert_eq!(payout, 250_000);
    }

    #[test]
    fn apply_template_rejection_fails_before_any_event() {
        // The constructor fails: there is no IndexedEscrow and no
        // event — the rejection happens before anything is recorded.
        let preset = subscription_preset();
        let err = IndexedEscrow::apply_template(
            &preset,
            &[("bogus_field", OverrideValue::U64(1))],
            ESCROW_ID,
            T0,
        )
        .unwrap_err();
        assert_eq!(err, EscrowError::TemplateOverrideRejected);
        assert_eq!(err.code(), 141);
        // An override that breaks conservation fails the same way.
        let err = IndexedEscrow::apply_template(
            &preset,
            &[("per_period", OverrideValue::U64(1))],
            ESCROW_ID,
            T0,
        )
        .unwrap_err();
        assert_eq!(err, EscrowError::InvalidSubscription);
    }

    #[test]
    fn template_applied_hash_survives_further_transitions() {
        // Later events carry no hash (None on every other kind); the
        // TemplateApplied record keeps the commitment for the log.
        let preset = subscription_preset();
        let mut e = IndexedEscrow::apply_template(&preset, &[], ESCROW_ID, T0).unwrap();
        let committed = e.events()[1].template_params_hash;
        assert!(committed.is_some());
        e.fund(ALICE, T0 + 1).unwrap();
        let funded = e.events().last().expect("Funded emitted");
        assert_eq!(funded.kind, EscrowEventKind::Funded);
        assert_eq!(funded.template_params_hash, None);
        assert_eq!(e.events()[1].template_params_hash, committed);
    }

    #[test]
    fn escrow_split_kind_round_trips() {
        // AV-81: discriminant 41, appended after VaultsBatchClosed —
        // 0–40 stay stable for already-serialized histories.
        let kind = EscrowEventKind::EscrowSplit;
        assert_eq!(kind.discriminant(), 41);
        assert_eq!(EscrowEventKind::from_discriminant(41), Some(kind));
        assert_eq!(kind.name(), "escrow_split");
        assert_eq!(EscrowEventKind::from_name("escrow_split"), Some(kind));
    }

    #[test]
    fn slashed_kind_round_trips() {
        // AV-82: discriminant 42, appended after EscrowSplit —
        // 0–41 stay stable for already-serialized histories.
        let kind = EscrowEventKind::Slashed;
        assert_eq!(kind.discriminant(), 42);
        assert_eq!(EscrowEventKind::from_discriminant(42), Some(kind));
        assert_eq!(kind.name(), "escrow_slashed");
        assert_eq!(EscrowEventKind::from_name("escrow_slashed"), Some(kind));
        assert_eq!(EscrowEventKind::from_discriminant(46), None);
    }

    #[test]
    fn cpi_allowlist_updated_kind_round_trips() {
        // AV-83: discriminant 43, appended after Slashed —
        // 0–42 stay stable for already-serialized histories.
        let kind = EscrowEventKind::CpiAllowlistUpdated;
        assert_eq!(kind.discriminant(), 43);
        assert_eq!(EscrowEventKind::from_discriminant(43), Some(kind));
        assert_eq!(kind.name(), "cpi_allowlist_updated");
        assert_eq!(
            EscrowEventKind::from_name("cpi_allowlist_updated"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(46), None);
    }

    #[test]
    fn appeal_filed_kind_round_trips() {
        // AV-86: discriminant 44, appended after CpiAllowlistUpdated —
        // 0–43 stay stable for already-serialized histories.
        let kind = EscrowEventKind::AppealFiled;
        assert_eq!(kind.discriminant(), 44);
        assert_eq!(EscrowEventKind::from_discriminant(44), Some(kind));
        assert_eq!(kind.name(), "appeal_filed");
        assert_eq!(EscrowEventKind::from_name("appeal_filed"), Some(kind));
        assert_eq!(EscrowEventKind::from_discriminant(46), None);
    }

    #[test]
    fn appeal_resolved_kind_round_trips() {
        // AV-86: discriminant 45, appended after AppealFiled —
        // 0–44 stay stable for already-serialized histories.
        let kind = EscrowEventKind::AppealResolved;
        assert_eq!(kind.discriminant(), 45);
        assert_eq!(EscrowEventKind::from_discriminant(45), Some(kind));
        assert_eq!(kind.name(), "appeal_resolved");
        assert_eq!(EscrowEventKind::from_name("appeal_resolved"), Some(kind));
        assert_eq!(EscrowEventKind::from_discriminant(46), None);
    }

    #[test]
    fn split_escrow_emits_event_with_roster_and_child_logs() {
        let mut e = funded(1_000_000);
        let before = e.event_count();
        let children = e
            .split_escrow(ALICE, BOB, &[600_000, 400_000], SplitConfig::default(), T0 + 2)
            .unwrap();
        assert_eq!(children.len(), 2);
        // The parent's EscrowSplit event: parent/children/amounts.
        assert_eq!(e.event_count(), before + 1);
        let ev = last(&e);
        assert_eq!(ev.kind, EscrowEventKind::EscrowSplit);
        assert_eq!((ev.from, ev.to), (EscrowState::Funded, EscrowState::Split));
        assert_eq!(ev.escrow_id, ESCROW_ID, "the parent rides escrow_id");
        assert_eq!(ev.amounts.payout, 1_000_000, "Σ children == pre-split remaining");
        assert_eq!(ev.amounts.fee, 0);
        assert_eq!(ev.amounts.refund, 0);
        assert_eq!(ev.amounts.penalty, 0);
        assert_eq!(ev.amounts.rent_reclaimed, 0);
        let (roster, len) = ev.split_children.expect("roster stamped");
        assert_eq!(len, 2);
        for i in 0..2 {
            let expected_id = crate::derive_split_child_id(&ESCROW_ID, i as u64);
            assert_eq!(roster[i as usize].escrow_id, expected_id);
            assert_eq!(children[i as usize].escrow_id(), expected_id);
        }
        assert_eq!(roster[0].amount, 600_000);
        assert_eq!(roster[1].amount, 400_000);
        // Every other event kind carries no roster.
        assert!(e.events()[0].split_children.is_none());
        // Each child's own log: Initialized (seq 0) then Funded, under
        // the derived ID — independently indexable.
        for (i, child) in children.iter().enumerate() {
            let kinds: Vec<EscrowEventKind> =
                child.events().iter().map(|ev| ev.kind).collect();
            assert_eq!(
                kinds,
                vec![EscrowEventKind::Initialized, EscrowEventKind::Funded],
                "child {i}"
            );
            assert_eq!(child.events()[0].seq, 0, "seq 0 is always Initialized");
            assert_eq!(child.next_seq(), 2);
            assert!(child.events().iter().all(|ev| ev.split_children.is_none()));
            assert_eq!(child.inner().state(), EscrowState::Funded);
            assert_eq!(child.inner().amount(), [600_000, 400_000][i]);
        }
        // The parent's on-chain history ring recorded the split too.
        let history = e.event_history();
        assert_eq!(
            history.last().map(|h| h.kind),
            Some(EscrowEventKind::EscrowSplit)
        );
    }

    #[test]
    fn split_escrow_dual_sig_children_log_activation() {
        let mut e = funded(1_000_000);
        let config = SplitConfig {
            dual_sig: true,
            ..SplitConfig::default()
        };
        let children = e
            .split_escrow(ALICE, BOB, &[500_000, 500_000], config, T0 + 2)
            .unwrap();
        assert_eq!(children.len(), 2);
        for child in &children {
            let kinds: Vec<EscrowEventKind> =
                child.events().iter().map(|ev| ev.kind).collect();
            // The implied dual-signed activation is visible in the
            // child's log: Uninitialized -> Activated -> Funded.
            assert_eq!(
                kinds,
                vec![
                    EscrowEventKind::Initialized,
                    EscrowEventKind::Activated,
                    EscrowEventKind::Funded
                ]
            );
            let funded_ev = &child.events()[2];
            assert_eq!(
                (funded_ev.from, funded_ev.to),
                (EscrowState::Activated, EscrowState::Funded)
            );
        }
        // The parent's split event is unchanged in shape.
        let ev = last(&e);
        assert_eq!(ev.kind, EscrowEventKind::EscrowSplit);
        assert_eq!((ev.from, ev.to), (EscrowState::Funded, EscrowState::Split));
    }

    #[test]
    fn split_escrow_failed_call_emits_nothing() {
        let mut e = funded(1_000_000);
        let before = e.event_count();
        let err = e
            .split_escrow(ALICE, BOB, &[600_000], SplitConfig::default(), T0 + 2)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidSplit, "under-covering table");
        assert_eq!(e.event_count(), before, "failed call emits nothing");
        assert_eq!(e.inner().state(), EscrowState::Funded);
        // Unauthorized is also silent.
        let err = e
            .split_escrow(MALLORY, BOB, &[1_000_000], SplitConfig::default(), T0 + 2)
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(e.event_count(), before, "failed call emits nothing");
    }

    #[test]
    fn split_escrow_event_survives_csv_projection_as_none() {
        // The CSV projection does not carry the roster: the round-trip
        // documents the None zero-value, like the other non-carried
        // fields.
        let mut e = funded(1_000_000);
        e.split_escrow(ALICE, BOB, &[1_000_000], SplitConfig::default(), T0 + 2)
            .unwrap();
        let csv = crate::events_to_csv(e.events());
        let back = crate::csv_to_events(&csv).unwrap();
        let split = back
            .iter()
            .find(|ev| ev.kind == EscrowEventKind::EscrowSplit)
            .expect("EscrowSplit round-trips by kind name");
        assert_eq!(split.split_children, None);
        assert_eq!(split.amounts.payout, 1_000_000);
    }
}
