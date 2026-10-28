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
//! - `release_milestone` emits [`EscrowEventKind::MilestoneClaimExpired`]
//!   when a vested tranche is claimed past its claim deadline (AV-225):
//!   the claim is rejected and the tranche returns to the refundable
//!   remainder, so `from == to == Funded`, `amounts.refund` carries the
//!   expired tranche (the initializer's refund) and the event's
//!   `milestone_claim_expired` field carries the tranche index.
//! - `append_milestone_tranche` emits
//!   [`EscrowEventKind::MilestoneTrancheAppended`] (AV-226) when a
//!   tranche is appended to the end of the plan by dual-signed
//!   governance: `from == to == Funded`, all amounts zero —
//!   appending moves no funds, the appended tranche is read from the
//!   vault's plan tail, and the event is the ordering signal.
//! - `amend_claimant_roster` emits
//!   [`EscrowEventKind::ClaimantRosterAmended`] (AV-227) when the
//!   claimant roster is revised by initializer-only governance:
//!   `from == to == Funded`, all amounts zero — amending moves no
//!   funds, the amended roster is read from the vault, and the
//!   event is the ordering signal.
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
//! - `replace_attestor` emits [`EscrowEventKind::AttestorReplaced`] when
//!   the slot's key actually changes (AV-154) — `from == to ==` the
//!   current state, all amounts zero: the event is the ordering signal
//!   that a quorum key was rotated, and the indexer reads the new key
//!   from the vault. Unlike `update_attestors`, the rotated slot's
//!   recorded vote is cleared (the old key may be compromised — its
//!   approval must not transfer to the new key). A no-op rotation
//!   (the same key) emits nothing, paralleling
//!   `update_quorum`'s no-op rule.
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
//! - `rotate_milestone_verifier` emits
//!   [`EscrowEventKind::MilestoneVerifierRotated`] on every successful
//!   rotation (AV-234) — `from == to ==` the current state, all amounts
//!   zero; there is no silent case, because the core call rejects a
//!   same-verifier rotation outright instead of no-op succeeding like
//!   `rotate_arbiter`. A rotation with no verifier configured is
//!   rejected, so the event can never fire on a verifier-less escrow.
//! - `amend_arbiter_fee` emits [`EscrowEventKind::ArbiterFeeAmended`]
//!   on every successful amendment (AV-235) — `from == to ==` the
//!   current state, all amounts zero; the amended fee legs are read
//!   from the vault. A failed amendment emits nothing.
//! - `amend_appeal_window` emits [`EscrowEventKind::AppealWindowAmended`]
//!   on every successful amendment (AV-236) — `from == to ==` the
//!   current state, all amounts zero; the amended window is read
//!   from the vault, and only slashes executed after the amendment
//!   stamp their appeal deadline from it. A failed amendment emits
//!   nothing.
//! - `amend_slash_ladder` emits [`EscrowEventKind::SlashLadderAmended`]
//!   on every successful amendment (AV-237) — `from == to ==` the
//!   current state, all amounts zero; the amended ladder is read
//!   from the vault, and only slashes executed after the amendment
//!   price from its future rungs. A failed amendment emits
//!   nothing.
//! - `amend_appeal_bond` emits [`EscrowEventKind::AppealBondAmended`]
//!   on every successful amendment (AV-238) — `from == to ==` the
//!   current state, all amounts zero; the amended bond is read
//!   from the vault, and only appeals filed after the amendment
//!   lock the new bond. A failed amendment emits nothing.
//! - `amend_grace_period` emits [`EscrowEventKind::GracePeriodAmended`]
//!   on every successful amendment (AV-240) — `from == to ==` the
//!   current state, all amounts zero; the amended grace period is
//!   read from the vault, and only expiry determinations after the
//!   amendment follow the new value. A failed amendment emits
//!   nothing.
//! - `amend_evidence_deadline` emits
//!   [`EscrowEventKind::EvidenceDeadlineAmended`] on every
//!   successful amendment (AV-241) — `from == to ==` the current
//!   state, all amounts zero; the amended deadline is read from
//!   the vault, and only disputes escalated after the amendment
//!   measure their disclosure window from the new value. A
//!   failed amendment emits nothing.
//! - `amend_arbitration_deadline` emits
//!   [`EscrowEventKind::ArbitrationDeadlineAmended`] on every
//!   successful amendment (AV-242) — `from == to ==` the current
//!   state, all amounts zero; the amended deadline is read from
//!   the vault, and only disputes escalated after the amendment
//!   measure their default-judgment window from the new value. A
//!   failed amendment emits nothing.
//! - `amend_claim_cooldown` emits
//!   [`EscrowEventKind::ClaimCooldownAmended`] on every
//!   successful amendment (AV-243) — `from == to ==` the current
//!   state, all amounts zero; the amended cooldown is read from
//!   the vault, and the next claim's eligibility is recomputed
//!   from the new value (`last_claim_slot` is untouched). A
//!   failed amendment emits nothing.
//! - `amend_delivery_deadline` emits
//!   [`EscrowEventKind::DeliveryDeadlineAmended`] on every
//!   successful amendment (AV-244) — `from == to ==` the current
//!   state, all amounts zero; the amended deadline is read from
//!   the vault, and confirmations after the amendment are judged
//!   against the new deadline (`confirm_delivery_at` reads the
//!   live field; a delivery already confirmed keeps its first-won
//!   stamp). A failed amendment emits nothing.
//! - `amend_late_delivery_penalty_bps` emits
//!   [`EscrowEventKind::LateDeliveryPenaltyAmended`] on every
//!   successful amendment (AV-245) — `from == to ==` the current
//!   state, all amounts zero; the amended rate is read from the
//!   vault, and a late-stamped but not-yet-released delivery
//!   reprices at the new rate, while amounts already released and
//!   penalties already banked are never restated. A failed
//!   amendment emits nothing.
//! - `amend_release_cooling` emits
//!   [`EscrowEventKind::ReleaseCoolingAmended`] on every
//!   successful amendment (AV-246) — `from == to ==` the current
//!   state, all amounts zero; the amended window is read from the
//!   vault, and a live announced intent is re-measured against
//!   the new window, while a vetoed intent stays vetoed. A
//!   failed amendment emits nothing.
//! - `amend_milestone_claim_deadline` emits
//!   [`EscrowEventKind::MilestoneClaimDeadlineAmended`] on every
//!   successful amendment (AV-247) — `from == to ==` the current
//!   state, all amounts zero; the amended deadline is read from
//!   the vault, and the claim gate re-reads it live, while a
//!   tranche already claimed or skipped keeps its settlement. A
//!   failed amendment emits nothing.
//! - `amend_max_extension_secs` emits
//!   [`EscrowEventKind::MaxExtensionAmended`] on every
//!   successful amendment (AV-248) — `from == to ==` the current
//!   state, all amounts zero; the amended cap is read from the
//!   vault, and the next extension is judged against the live cap,
//!   while extensions already made keep their deadline and count.
//!   A failed amendment emits nothing.
//! - `amend_timelock` emits
//!   [`EscrowEventKind::TimelockAmended`] on every
//!   successful amendment (AV-249) — `from == to ==` the current
//!   state, all amounts zero; the amended lock is read from the
//!   vault, and the payout gates re-read it live, while amounts
//!   already released are never restated. A failed amendment emits
//!   nothing.
//! - `amend_relative_timelock` emits
//!   [`EscrowEventKind::RelativeTimelockAmended`] on every
//!   successful amendment (AV-250) — `from == to ==` the current
//!   state, all amounts zero; the amended window is read from the
//!   vault, and the payout gates re-read it live against the
//!   unchanged `fund_at` anchor, while amounts already released
//!   are never restated. A failed amendment emits nothing.
//! - `amend_slot_timelock` emits
//!   [`EscrowEventKind::SlotTimelockAmended`] on every
//!   successful amendment (AV-251) — `from == to ==` the current
//!   state, all amounts zero; the amended window is read from the
//!   vault, and the slot gates re-read it live against the
//!   unchanged `fund_slot` anchor, while amounts already released
//!   are never restated. A failed amendment emits nothing.
//! - `amend_rent_sweep_grace` emits
//!   [`EscrowEventKind::RentSweepGraceAmended`] on every
//!   successful amendment (AV-252) — `from == to ==` the current
//!   state, all amounts zero; the amended grace is read from the
//!   vault, and the sweep gate re-reads it live against the
//!   unchanged `terminal_at` stamp, while a sweep already
//!   performed is never undone. A failed amendment emits nothing.
//! - `amend_fee_schedule` emits
//!   [`EscrowEventKind::FeeScheduleAmended`] on every
//!   successful amendment (AV-253) — `from == to ==` the current
//!   state, all amounts zero; the amended schedule is read from
//!   the vault, and later payouts reprice live from it, while
//!   fees already charged or withdrawn are never restated.
//!   A failed amendment emits nothing.
//! - `amend_streaming_fee` emits
//!   [`EscrowEventKind::StreamingFeeRateAmended`] on every
//!   successful amendment (AV-254) — `from == to ==` the current
//!   state, all amounts zero; the amended rate is read from the
//!   vault, and the charge gate re-reads it live against the
//!   unchanged `fund_at` anchor, while fees already charged are
//!   never clawed back. A failed amendment emits nothing.
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
//! - `amend_milestones` emits [`EscrowEventKind::MilestonesAmended`]
//!   when the tranche amounts actually change (AV-155) — `from == to
//!   ==` the current state, all amounts zero; a no-op re-affirmation
//!   emits nothing. Unlike `MilestonesAdjusted` (the pre-settlement
//!   re-split), this is the mid-flight renegotiation: confirmed /
//!   settled tranches stay pinned while the unconfirmed ones move.
//! - `reallocate_milestones` emits
//!   [`EscrowEventKind::MilestonesReallocated`] when the tranche
//!   amounts actually change (AV-224) — `from == to ==` the current
//!   state, all amounts zero; a no-op re-affirmation emits nothing.
//!   Unlike `MilestonesAmended`, an unconfirmed tranche may be
//!   repriced to zero (cleared, not deleted — the plan keeps its
//!   tranche count). The event carries the before/after tranche
//!   tables on its `milestone_reallocation` field, so an indexer
//!   reads the reallocation without replaying the vault.
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
//! - `release_basket` (AV-95b) emits [`EscrowEventKind::BasketReleased`]
//!   on every successful leg release — one leg (one SPL mint) per call.
//!   `from == Funded`, `to == Funded` while legs remain unsettled,
//!   `to == Released` when the settled leg was the last unsettled
//!   one — the same lifecycle shape as `Released`, per leg. Amounts
//!   follow the `Released` shape (`payout` = the leg's gross remainder,
//!   `fee` = the AV-17 protocol fee on the leg); the actor is the
//!   initializer. A failed leg release emits nothing.
//! - `cancel_basket` (AV-95b) emits [`EscrowEventKind::BasketCancelled`]
//!   on every successful leg cancel. `from == Funded`, `to == Funded`
//!   while legs remain unsettled, `to == Cancelled` when the settled
//!   leg was the last unsettled one — the per-leg mirror of
//!   `Cancelled`. `amounts.refund` carries the leg's remainder; the
//!   actor is the initializer. A failed leg cancel emits nothing.
//! - `cancel_expired_basket` (AV-95b) emits
//!   [`EscrowEventKind::BasketExpiredCancelled`] on every successful
//!   leg expiry-cancel. `from == Funded`, `to == Funded` while legs
//!   remain unsettled, `to == Cancelled` when the settled leg was the
//!   last unsettled one — the per-leg mirror of `ExpiredCancelled`.
//!   Amounts follow the `ExpiredCancelled` shape (`refund` = the leg's
//!   net refund, `penalty` = the AV-24 penalty on a taker-initiated
//!   cancel); the actor is the caller. A failed call emits nothing.
//! - `release_basket_all` (AV-95c) emits a single
//!   [`EscrowEventKind::BasketReleased`] for the atomic all-legs
//!   settlement. `from == Funded`, `to == Released`; amounts carry
//!   the Σ (`payout` = Σ leg gross, `fee` = Σ protocol fee) — the
//!   event-sourced fold (AV-94) books it bit-identically to the
//!   per-leg event sequence it replaces. The actor is the
//!   initializer. A failed call emits nothing.
//! - `release_many` (AV-141) emits one [`EscrowEventKind::Released`]
//!   per successfully settled leg, in leg order — `from == Funded`,
//!   `to == Funded` on a partial leg, `to == Released` on the closing
//!   one, amounts following the `Released` shape (`payout` = the
//!   leg's gross amount, `fee` = the leg's AV-17 protocol fee); the
//!   actor is the initializer. Exactly the per-leg event sequence a
//!   series of standalone `release` calls would have produced, so the
//!   event-sourced fold needs no new logic. A failed batch emits
//!   nothing on any leg.
//! - `cancel_basket_all` (AV-95c) emits a single
//!   [`EscrowEventKind::BasketCancelled`] for the atomic all-legs
//!   cancel. `from == Funded`, `to == Cancelled`;
//!   `amounts.refund` carries the Σ remainder; the actor is the
//!   initializer. A failed call emits nothing.
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
//! | Initialized, Activated, Funded, Escalated, Attested, MilestoneConfirmed, QuorumUpdated, AttestorsUpdated, EmergencyUnlock (AV-41), ReentryRejected (AV-36), PauseAuthorityRotated (AV-47), TakerRotated (AV-52), InitializerRotated (AV-58), ExpiryExtended (AV-59), PartiallyCancelled, ArbiterRotated (AV-62), FeeRecipientRotated (AV-67), EvidenceSubmitted (AV-68), PanelThresholdChanged (AV-69), MilestonesAdjusted (AV-73), SchemaMigrated (AV-75), TemplateApplied (AV-77), VestingPaused (AV-150), VestingResumed (AV-150), AttestorReplaced (AV-154), MilestonesAmended (AV-155), MilestonesReallocated (AV-224), MilestoneTrancheAppended (AV-226), ClaimantRosterAmended (AV-227), GovernanceProposed (AV-158), GovernanceExecuted (AV-158), GovernanceCancelled (AV-158), FeeWithdrawn (AV-174) | 0 | 0 | 0 | 0 |
//! | Released, Claimed, ShareClaimed (AV-149), MilestoneReleased, SubscriptionPeriodReleased (AV-56) | gross taker amount (net payout + fee) | protocol fee (AV-17) | 0 | 0 |
//! | ReleasedSplit (AV-93) | gross taker amount (Σ net legs + fee) | protocol fee (AV-17, charged on the gross before the split) | 0 | 0 — the per-recipient `(recipient, net_share)` legs ride the event's `release_split` field |
//! | BasketReleased (AV-95b) | the leg's gross remainder (taker payout + fee) | protocol fee (AV-17, charged on the leg's remainder) | 0 | 0 |
//! | BasketCancelled (AV-95b) | 0 | 0 | the leg's remainder, refunded to the escrow's refund recipient | 0 |
//! | BasketExpiredCancelled (AV-95b) | 0 | 0 | the leg's remainder minus penalty, to the refund recipient | anti-griefing penalty to the initializer (AV-24; 0 unless taker-initiated with `penalty_bps > 0`; AV-115 escalation grows the rate with days past the expiry gate) |
//! | BundlePartiallyExecuted (AV-76) | Σ gross of the executed tranches | Σ protocol fee of the executed tranches | 0 | 0 |
//! | Cancelled | 0 | 0 | remainder refunded to the initializer | 0 |
//! | PartiallyCancelled (AV-60) | 0 | 0 | the partially-cancelled tranche, refunded to the whitelisted destination (the escrow stays `Funded`; the `released` counter is untouched) | 0 |
//! | ExpiredCancelled | 0 | 0 | remainder minus penalty, to the whitelisted destination | anti-griefing penalty to the initializer (AV-24; 0 unless taker-initiated with `penalty_bps > 0`; AV-115 escalation grows the rate with days past the expiry gate) |
//! | DeadmanClaimed (AV-109) | 0 | 0 | remaining locked amount, to the configured heir (the heir is not required to be either party) | 0 |
//! | RentToppedUp (AV-110) | 0 | 0 | 0 | 0 — the topped-up lamports ride `rent_reclaimed` (the rent-balance leg: added here, reclaimed on `VaultClosed`; direction is read from the kind) |
//! | TrancheFunded (AV-111) | 0 | 0 | 0 | 0 — a funding tranche landed; the fold seeds the lockup with the deal size at `Funded`, so the tranche carries no amount (exactly like `Funded` itself) |
//! | TakerFunded (AV-148) | 0 | 0 | 0 | 0 — the taker posted counter-fund; the fold seeds the lockup with the bilateral total at `Funded`, so the counter-fund carries no amount (exactly like `Funded` itself) |
//! | ReleaseIntentAnnounced (AV-112) | 0 | 0 | 0 | 0 — a release intent was announced (governance signal; the cooling window starts) |
//! | ReleaseIntentVetoed (AV-112) | 0 | 0 | 0 | 0 — a live release intent was vetoed (governance signal; the announced release is cancelled) |
//! | EscrowsMerged (AV-114) | the source's locked amount folded into the survivor | 0 | 0 | 0 |
//! | EscrowsNetted (AV-140) | the netted amount (the bilateral offset extinguished this much of the larger leg's lockup — no transfer moved; the fold recomputes the surviving lockup from the vault) | 0 | 0 | 0 |
//! | ExpiredCranked (AV-48) | 0 | 0 | remainder minus penalty, to the whitelisted destination (the cranker receives nothing — unless the vault opted into the AV-124 keeper bounty, paid via `KeeperBountyPaid`) | anti-griefing penalty to the initializer (AV-24; 0 unless the cranker is the taker; AV-115 escalation grows the rate with days past the expiry gate) |
//! | Resolved | gross taker share (`taker_amount`) | protocol fee on the taker's share | initializer's principal share of the split (AV-119: the initializer's dispute-interest share rides the refund transfer — tracked in `dispute_interest`, the event keeps the principal leg) | 0 — the AV-135 arbiter adjudication fee rides `arbiter_fee` (0 when the escrow never opted in) |
//! | DefaultJudgment (AV-55) | gross taker share (`default_taker_amount`) | protocol fee on the taker's share | initializer's principal share of the split (AV-119: same dispute-interest rule as `Resolved`) | 0 — the AV-135 arbiter adjudication fee rides `arbiter_fee` |
//! | PanelResolved (AV-65) | gross taker share (the winning vote's `taker_amount`) | protocol fee on the taker's share | initializer's principal share of the split (AV-119: same dispute-interest rule as `Resolved`) | 0 — the AV-135 arbiter adjudication fee rides `arbiter_fee` |
//! | PanelJudgment (AV-65) | the voted split (`taker_amount`) | 0 | 0 | 0 |
//! | MilestoneSkipped | 0 | 0 | skipped tranche (the initializer's refund) | 0 |
//! | MilestoneClaimExpired (AV-225) | 0 | 0 | expired tranche (the initializer's refund) | 0 — the expired tranche index rides the event's `milestone_claim_expired` field |
//! | MilestoneTrancheAppended (AV-226) | 0 | 0 | 0 | 0 — appending moves no funds; the appended tranche is read from the vault's plan tail |
//! | ClaimantRosterAmended (AV-227) | 0 | 0 | 0 | 0 — amending moves no funds; the amended roster is read from the vault |
//! | MilestonePartiallyClaimed (AV-229) | gross slice (net payout + fee, net of penalties priced on this call) | protocol fee | 0 | 0 |
//! | VestingScheduleAmended (AV-230) | 0 | 0 | 0 | 0 — amending moves no funds; the amended schedule is read from the vault |
//! | MilestoneDueDatesAmended (AV-231) | 0 | 0 | 0 | 0 — amending moves no funds; the amended table is read from the vault |
//! | MilestoneUnskipped (AV-232) | 0 | 0 | 0 | 0 — unskipping moves no funds; the restored tranche is read from the vault |
//! | ProtocolFeeAmended (AV-233) | 0 | 0 | 0 | 0 — amending moves no funds; later payouts reprice from the vault |
//! | MilestoneVerifierRotated (AV-234) | 0 | 0 | 0 | 0 — rotating moves no funds; later attestation checks read the new key from the vault |
//! | ArbiterFeeAmended (AV-235) | 0 | 0 | 0 | 0 — amending moves no funds; later dispute settlements price from the vault |
//! | AppealWindowAmended (AV-236) | 0 | 0 | 0 | 0 — amending moves no funds; later slashes stamp their appeal deadline from the vault |
//! | SlashLadderAmended (AV-237) | 0 | 0 | 0 | 0 — amending moves no funds; later slashes price from the amended future rungs |
//! | AppealBondAmended (AV-238) | 0 | 0 | 0 | 0 — amending moves no funds; later appeals lock the amended bond |
//! | GracePeriodAmended (AV-240) | 0 | 0 | 0 | 0 — amending moves no funds; later expiry determinations follow the amended grace |
//! | EvidenceDeadlineAmended (AV-241) | 0 | 0 | 0 | 0 — amending moves no funds; later disputes measure their disclosure window from the amended deadline |
//! | ArbitrationDeadlineAmended (AV-242) | 0 | 0 | 0 | 0 — amending moves no funds; later disputes measure their default-judgment window from the amended deadline |
//! | ClaimCooldownAmended (AV-243) | 0 | 0 | 0 | 0 — amending moves no funds; the next claim's eligibility is recomputed from the amended cooldown |
//! | DeliveryDeadlineAmended (AV-244) | 0 | 0 | 0 | 0 — amending moves no funds; confirmations after the amendment are judged against the new deadline, while an already-confirmed delivery keeps its first-won stamp |
//! | LateDeliveryPenaltyAmended (AV-245) | 0 | 0 | 0 | 0 — amending moves no funds; a late-stamped but unreleased delivery reprices at the new rate, while already-released amounts and banked penalties are never restated |
//! | ReleaseCoolingAmended (AV-246) | 0 | 0 | 0 | 0 — amending moves no funds; a live announced intent is re-measured against the new window, while a vetoed intent stays vetoed |
//! | MilestoneClaimDeadlineAmended (AV-247) | 0 | 0 | 0 | 0 — amending moves no funds; the claim gate re-reads the deadline live, while already-claimed or skipped tranches keep their settlements |
//! | MaxExtensionAmended (AV-248) | 0 | 0 | 0 | 0 — amending moves no funds; the next extension is judged against the live cap, while already-made extensions keep their deadline and count |
//! | TimelockAmended (AV-249) | 0 | 0 | 0 | 0 — amending moves no funds; the payout gates re-read the live lock, while already-released amounts are never restated |
//! | RelativeTimelockAmended (AV-250) | 0 | 0 | 0 | 0 — amending moves no funds; the payout gates re-read the live window against the unchanged funding anchor, while already-released amounts are never restated |
//! | SlotTimelockAmended (AV-251) | 0 | 0 | 0 | 0 — amending moves no funds; the slot gates re-read the live window against the unchanged funding slot, while already-released amounts are never restated |
//! | RentSweepGraceAmended (AV-252) | 0 | 0 | 0 | 0 — amending moves no funds; the sweep gate re-reads the live grace against the unchanged terminal timestamp, while a sweep already performed is never undone |
//! | FeeScheduleAmended (AV-253) | 0 | 0 | 0 | 0 — amending moves no funds; later payouts reprice live from the amended schedule, while fees already charged or withdrawn are never restated |
//! | StreamingFeeRateAmended (AV-254) | 0 | 0 | 0 | 0 — amending moves no funds; the charge gate re-reads the live rate against the unchanged `fund_at` anchor, while fees already charged are never clawed back |
//! | VaultClosed (AV-34) | 0 | 0 | 0 | 0 — the rent-exempt deposit reclaimed by the initializer on vault close is carried in `rent_reclaimed`, not in these four fields |
//! | VaultsBatchClosed (AV-79) | 0 | 0 | 0 | 0 — the Σ rent-exempt deposits reclaimed across the batch, carried in `rent_reclaimed` |
//! | EscrowSplit (AV-81) | Σ child amounts (the gross re-locked into the child escrows — the parent's pre-split remaining lockup) | 0 | 0 | 0 — the per-child `(child_id, amount)` roster rides the event's `split_children` field |
//! | Slashed (AV-82) | 0 | 0 | 0 | the slashed amount, routed to the penalty account (the escrow stays `Funded`; from == to == `Funded`) — on a ladder escrow (AV-126) the consumed rung rides the event's `slash_ladder_index` |
//! | AppealFiled (AV-86) | 0 | 0 | 0 | 0 — the taker filed the appeal inside the window; no funds move (from == to == `Funded`) — with an AV-103 bond the taker locks the bond into `appeal_bond_paid` at filing (read from the vault, not the event) |
//! | AppealResolved (AV-86) | the penalty refunded to the taker on overturn — a restitution, no fee — plus the refunded appeal bond (AV-103; the taker's full restitution) (0 on uphold; from == to == `Funded`) | 0 | 0 | the appeal bond forfeited to the initializer on uphold (AV-103; 0 when no bond was locked) |
//! | AppealExpired (AV-103) | 0 | 0 | 0 | the appeal bond forfeited to the initializer when the window lapsed unresolved (0 when no bond was locked; from == to == `Funded`) |
//! | DelegationGranted (AV-104) | 0 | 0 | 0 | 0 — the operator key and scope bitmap are read from the vault, the event is the ordering signal (actor = the granting party; from == to == the current state) |
//! | DelegationRevoked (AV-104) | 0 | 0 | 0 | 0 — the grant is gone; the actor is the revoking party (from == to == the current state) |
//! | SwapLinked (AV-105) | 0 | 0 | 0 | 0 — the two legs were linked as an atomic swap pair; the counterparty id is read from the vault, the event is the ordering signal (actor = the linking party; from == to == the current state) |
//!
//! # Backward compatibility
//!
//! AV-103 changed two existing public signatures: `file_appeal` now
//! returns the locked bond (`Result<u64>`), and `review_appeal`
//! returns `(outcome, penalty_refunded, bond_moved)` on resolution —
//! the bond additions the appeal-bond feature needs. [`Escrow`] gained
//! two appended fields (`appeal_bond`, `appeal_bond_paid`), the
//! `with_appeal_bond` builder, and `expire_appeal`; every earlier
//! field offset stays stable. The crate stays dependency-free.

use crate::{Escrow, EscrowError, EscrowState, MilestonePlan, PriceFeed, QuorumPolicy, ReleaseLeg, SplitConfig, VestingSchedule};
use crate::{AppealOutcome, BasketSettlement, OverrideValue, TemplatePreset};
use crate::cpi::CpiError;
use crate::cpi_call::{CpiInvocation, CpiReceipt};
use crate::cpi_return::CpiReturnDataAudit;
use crate::release_intent::ReleaseIntent;
use crate::memo::{transition_memo_note, MemoConfig, MemoNote, MemoTransition};

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
    /// payout nor an initializer refund); AV-103: the refunded appeal
    /// bond rides `payout` too (the taker's full restitution, no fee).
    /// On uphold the forfeited appeal bond rides
    /// [`EventAmounts::penalty`] (a penalty-like sink, 0 when no bond
    /// was locked). The verdict rides the event's `appeal_outcome`
    /// field (see [`EscrowEvent::appeal_outcome`]), and the actor is
    /// the member whose vote was the M-th match. Always emitted on
    /// resolution: a non-resolving vote emits nothing (the ballot is
    /// still open).
    AppealResolved,
    /// AV-91: one dispute-evidence document was disclosed against the
    /// committed Merkle root ([`Escrow::file_evidence`]). `from == to
    /// == Disputed` (a disclosure, not a lifecycle move — like
    /// [`EscrowEventKind::QuorumUpdated`]); the committed root rides
    /// the event's `evidence_root` field and the disclosure progress
    /// is read from the vault, so indexers track per-document
    /// disclosure without replaying the bitmap. Re-filing an
    /// already-disclosed document is an idempotent no-op that emits
    /// nothing.
    EvidenceFiled,
    /// AV-93: the locked funds were released split across several
    /// recipients by basis-point weights
    /// ([`Escrow::release_split`]) — the initializer's multi-party
    /// payout (a revenue share, a creator royalty split, a payroll
    /// run) settled in one transition. `from == Funded`, `to ==
    /// Funded` on a partial split, `to == Released` on the closing
    /// one — the same lifecycle shape as
    /// [`EscrowEventKind::Released`]. Amounts follow the `Released`
    /// shape (`payout` = the gross amount = Σ net legs + fee, `fee` =
    /// the AV-17 protocol fee charged on the gross before the split);
    /// the per-recipient `(recipient, net_share)` legs ride
    /// [`EscrowEvent::release_split`] in table order — the first leg
    /// carries the bps-floor dust, so an indexer re-derives the
    /// Anchor layer's exact transfer sizes. The actor is the
    /// initializer. Always emitted on success: a successful split
    /// release always moves funds, so there is no no-op case.
    ReleasedSplit,
    /// AV-95b: one basket leg was released to the taker
    /// ([`Escrow::release_basket`]) — the per-leg taker payout. `from
    /// == Funded`, `to == Funded` while legs remain unsettled, `to ==
    /// Released` when the settled leg was the last unsettled one —
    /// the same lifecycle shape as [`EscrowEventKind::Released`], one
    /// leg at a time. Amounts follow the `Released` shape (`payout` =
    /// the leg's gross remainder = taker payout + fee, `fee` = the
    /// AV-17 protocol fee charged on the leg). The actor is the
    /// initializer. Always emitted on success: a successful leg
    /// release always moves funds, so there is no no-op case.
    BasketReleased,
    /// AV-95b: one basket leg was refunded to the escrow's refund
    /// recipient ([`Escrow::cancel_basket`]) — the per-leg cancel.
    /// `from == Funded`, `to == Funded` while legs remain unsettled,
    /// `to == Cancelled` when the settled leg was the last unsettled
    /// one — the per-leg mirror of [`EscrowEventKind::Cancelled`].
    /// Amounts follow the `Cancelled` shape (`refund` = the leg's
    /// remainder). The actor is the initializer. Always emitted on
    /// success: a successful leg cancel always moves funds, so there
    /// is no no-op case.
    BasketCancelled,
    /// AV-95b: one basket leg was refunded after expiry
    /// ([`Escrow::cancel_expired_basket`]) — the per-leg expiry
    /// cancel. `from == Funded`, `to == Funded` while legs remain
    /// unsettled, `to == Cancelled` when the settled leg was the last
    /// unsettled one — the per-leg mirror of
    /// [`EscrowEventKind::ExpiredCancelled`]. Amounts follow the
    /// `ExpiredCancelled` shape (`refund` = the leg's net refund,
    /// `penalty` = the AV-24 anti-griefing penalty on a
    /// taker-initiated cancel, 0 otherwise). The actor is the caller
    /// (the initializer or the taker). Always emitted on success: a
    /// successful leg expiry-cancel always moves funds, so there is
    /// no no-op case.
    BasketExpiredCancelled,
    /// AV-96: the payout destination denylist was changed by
    /// initializer governance ([`Escrow::update_payout_denylist`]).
    /// `from == to ==` the current state (a config change, not a
    /// lifecycle move — like
    /// [`EscrowEventKind::PayoutAllowlistUpdated`]); the new list is
    /// read from the vault, the event is the ordering signal. Amounts
    /// are zero. (The initialize-time builder
    /// [`Escrow::with_denylist`] emits no event — pre-fund
    /// configuration, like [`Escrow::with_payout_allowlist`].)
    /// Emitted only on an actual change.
    DenylistUpdated,
    /// AV-103: a filed slash appeal's window lapsed while still
    /// unresolved ([`Escrow::expire_appeal`]) — the permissionless
    /// sweep moved the appeal terminally to `Expired`. `from == to
    /// == Funded` (the sweep is a procedural close, like the appeal
    /// review itself). The slash stands, and the locked appeal bond
    /// — if any — was forfeited to the initializer (the
    /// anti-malicious-appeal-delay rule): the forfeited amount rides
    /// [`EventAmounts::penalty`] (a penalty-like sink, 0 when no bond
    /// was locked). The actor is the permissionless caller that ran
    /// the sweep. Always emitted on success: a successful sweep always
    /// closes the appeal, so there is no no-op case.
    AppealExpired,
    /// AV-104: an operator grant was created or replaced
    /// ([`Escrow::delegate_authority`]). `from == to ==` the current
    /// state (a config change, not a lifecycle move — like
    /// [`EscrowEventKind::QuorumUpdated`]); the operator key and scope
    /// bitmap are read from the vault, the event is the ordering
    /// signal. The actor is the granting party. Emitted only on an
    /// actual change: re-granting the identical (operator, scopes)
    /// pair is an idempotent no-op that emits nothing (paralleling
    /// [`EscrowEventKind::QuorumUpdated`]'s no-op rule).
    DelegationGranted,
    /// AV-104: the operator grant was revoked
    /// ([`Escrow::revoke_delegation`]). `from == to ==` the current
    /// state (a config change, not a lifecycle move — like
    /// [`EscrowEventKind::DelegationGranted`]); the actor is the
    /// revoking party. Always emitted on success: the call fails
    /// unless a grant was live, so there is no no-op case.
    DelegationRevoked,
    /// AV-105: two escrows were linked as an atomic swap pair
    /// ([`link_swap`](crate::link_swap)). `from == to ==` the current
    /// state (a config change, not a lifecycle move — like
    /// [`EscrowEventKind::DelegationGranted`]); the counterparty
    /// escrow id is read from the vault, the event is the ordering
    /// signal. The actor is the linking party. Emitted on each leg
    /// in deterministic A→B order; always emitted on success.
    SwapLinked,
    /// AV-109: the dead-man's switch fired
    /// ([`Escrow::claim_deadman`](crate::Escrow::claim_deadman)) — the
    /// heir claimed the remaining locked amount after the inactivity
    /// threshold elapsed. `from == Funded`, `to == Cancelled`. Amounts
    /// follow the `Cancelled` shape (`refund` = the heir's payout; the
    /// heir is not required to be either party). The actor is the heir.
    /// Always emitted on success: a successful claim always moves
    /// funds, so there is no no-op case.
    DeadmanClaimed,
    /// AV-110: rent was topped up
    /// ([`Escrow::top_up_rent`](crate::Escrow::top_up_rent)) — a
    /// permissionless caller added lamports to the vault's rent
    /// balance. `from == to ==` the current state (pure lamport
    /// bookkeeping, not a lifecycle move — like
    /// [`EscrowEventKind::DelegationGranted`]). The topped-up lamports
    /// ride [`EventAmounts::rent_reclaimed`] (the rent-balance leg;
    /// direction is read from the kind — added here, reclaimed on
    /// `VaultClosed`). The actor is the topping-up caller. Always
    /// emitted on success: a zero-lamport call is rejected, so there
    /// is no no-op case.
    RentToppedUp,
    /// AV-111: one funding tranche landed via
    /// [`Escrow::fund_tranche`](crate::Escrow::fund_tranche). `from ==
    /// to ==` the state after the call (a `Funded` state re-entry, not
    /// a lifecycle move — like
    /// [`EscrowEventKind::DelegationGranted`]). Pure deposit
    /// bookkeeping for the off-chain indexer: the tranche is the
    /// explicit fold seed's inflow leg, so the tranche amount itself
    /// carries [`EventAmounts::none`] (the fold seeds the lockup with
    /// the deal size at `Funded`, exactly like `Funded` itself).
    /// Always emitted on success — a rejected tranche changes
    /// nothing, so a failed call emits nothing.
    TrancheFunded,
    /// AV-112: a release intent was announced
    /// ([`Escrow::announce_release`](crate::Escrow::announce_release))
    /// — either party recorded `release_intent_at`, starting the
    /// cooling window the initializer configured via
    /// [`Escrow::with_release_cooling`](crate::Escrow::with_release_cooling).
    /// `from == to ==` the current state (a governance signal, not a
    /// lifecycle move — like
    /// [`EscrowEventKind::DelegationGranted`]). Pure governance
    /// bookkeeping for the off-chain indexer: no funds move, so the
    /// event carries [`EventAmounts::none`]. The actor is the
    /// announcing party. Emitted only on an actual change: a
    /// same-timestamp re-announce is an idempotent no-op that emits
    /// nothing (paralleling
    /// [`EscrowEventKind::DelegationGranted`]'s no-op rule).
    ReleaseIntentAnnounced,
    /// AV-112: a live release intent was vetoed
    /// ([`Escrow::veto_release`](crate::Escrow::veto_release)) — either
    /// party cleared `release_intent_at`, cancelling the announced
    /// release. `from == to ==` the current state (a governance
    /// signal, not a lifecycle move — like
    /// [`EscrowEventKind::DelegationGranted`]). Pure governance
    /// bookkeeping: no funds move, so the event carries
    /// [`EventAmounts::none`]. The actor is the vetoing party.
    /// Emitted only on an actual change: vetoing with no live intent
    /// is a no-op success that emits nothing.
    ReleaseIntentVetoed,
    /// AV-114: two escrows merged
    /// ([`Escrow::merge_escrows`](crate::Escrow::merge_escrows)) — the
    /// source escrow's locked funds folded into the surviving escrow.
    /// `from == to == Funded` on the survivor (the merge is a
    /// consolidation, not a lifecycle move — like
    /// [`EscrowEventKind::ReleaseIntentAnnounced`]); the source emits
    /// [`EscrowEventKind::Cancelled`] separately. The event carries
    /// the merged-in amount as a payout-shaped amount (the survivor's
    /// lockup grew by exactly that), so the event-sourced fold keeps
    /// the conservation identity. The actor is the initializer.
    EscrowsMerged,
    /// AV-122: the taker declined the escrow
    /// ([`Escrow::decline_escrow`]) before any claim. `from ==
    /// Funded`, `to == Declined`; amounts are zero — the decline is
    /// a refusal, not a settlement, so no funds moved. The actor is
    /// the taker.
    Declined,
    /// AV-122: the taker proposed a counter-offer
    /// ([`Escrow::propose_counter_offer`]). `from == Funded`, `to ==
    /// CounterOffered`; `amounts.payout` carries the proposed amount
    /// (no funds moved — the offer is terms, not a transfer), and the
    /// proposed expiry is read from the vault's `counter_offer`. The
    /// actor is the taker.
    CounterOfferProposed,
    /// AV-122: the initializer accepted the taker's counter-offer
    /// ([`Escrow::accept_counter_offer`]), atomically re-setting the
    /// escrow's amount and expiry. `from == CounterOffered`, `to ==
    /// Funded`; the new terms are read from the vault. The actor is
    /// the initializer.
    CounterOfferAccepted,
    /// AV-122: the initializer rejected the taker's counter-offer
    /// ([`Escrow::reject_counter_offer`]). `from == CounterOffered`,
    /// `to == Funded`; the terms are unchanged. The actor is the
    /// initializer.
    CounterOfferRejected,
    /// AV-123: a gasless release executed through a signed Ed25519
    /// intent ([`Escrow::release_via_intent`]). The same lifecycle
    /// shape as [`EscrowEventKind::Released`] (`from == Funded`, `to
    /// == Funded` on a partial release, `to == Released` when the
    /// intent drained the lockup); amounts follow the `Released`
    /// shape (`payout` = the gross intent amount, `fee` = the
    /// protocol fee). The actor is the initializer — their signature
    /// authorized the payout; the relayer that submitted the
    /// transaction is not a party to the escrow and is deliberately
    /// not recorded.
    ReleaseViaIntent,
    /// AV-124: the keeper bounty paid to a permissionless crank
    /// caller ([`Escrow::crank_expired`]). Emitted alongside
    /// [`EscrowEventKind::ExpiredCranked`] when the crank actually
    /// paid a bounty (`from == to == Cancelled` — the unwind is
    /// already final; the bounty settles it, it does not gate it).
    /// Amounts follow the `Released` shape (`payout` = the bounty
    /// paid, `fee` = 0); the caller is the crank signer (carried by
    /// the event's `caller` field, like `ExpiredCranked`), and
    /// `bounty_pool_remaining` carries the pool balance after the
    /// debit so indexers track pool exhaustion without a second
    /// account read. Emitted only when the bounty is non-zero — a
    /// zero-bounty crank emits `ExpiredCranked` alone.
    KeeperBountyPaid,
    /// AV-127: the escrow was partially refunded
    /// ([`Escrow::partial_refund`]) — the initializer reclaimed a
    /// tranche of their locked funds. `from == to == Funded`; amounts
    /// follow the refund shape (`refund` = the refunded tranche, the
    /// same shape as [`EscrowEventKind::PartiallyCancelled`]). The
    /// actor is the initializer. Unlike
    /// [`EscrowEventKind::PartiallyCancelled`], the refunded tranche
    /// also accumulates in the vault's persisted `refunded` counter
    /// (see `Escrow::refunded_amount`).
    PartialRefunded,
    /// AV-130: a dual-control (maker-checker) release declaration was
    /// frozen ([`Escrow::initiate_release`]) — the initializer (the
    /// *maker*) declared the exact payout for the checker to review.
    /// `from == to == Funded`; the intent is a pending declaration,
    /// not a lifecycle move, so amounts carry [`EventAmounts::none`]
    /// (the declaration moves no funds — like AV-112's
    /// `ReleaseIntentAnnounced`). The actor is the maker.
    DualControlInitiated,
    /// AV-130: the checker approved the live dual-control declaration
    /// and it settled ([`Escrow::confirm_release`]) — the two-step
    /// release's terminal event. Amounts follow the `Released` shape
    /// (`payout` = the gross declared amount, `fee` = the protocol
    /// fee); the event-sourced fold books it like `Released`. The
    /// actor is the checker — their approval authorized the payout;
    /// the maker who declared it is visible in the vault state.
    DualControlConfirmed,
    /// AV-130: the live dual-control declaration was aborted
    /// ([`Escrow::cancel_release`]) — either the maker retracted it or
    /// the checker refused it. `from == to == Funded`; amounts carry
    /// [`EventAmounts::none`] (the abort moves no funds — like AV-112's
    /// `ReleaseIntentVetoed`). The actor is the cancelling party.
    DualControlCancelled,
    /// AV-137: a panel member committed their blind judgment
    /// ([`Escrow::submit_judgment_commit`]) — the commitment hash is
    /// recorded, the judgment itself stays hidden until the reveal.
    /// `from == to == Disputed`; amounts carry [`EventAmounts::none`]
    /// (the commit moves no funds). The actor is the committing
    /// member.
    JudgmentCommitted,
    /// AV-137: a panel member revealed their blind judgment
    /// ([`Escrow::reveal_judgment`]) — the revealed
    /// `(taker_amount, rationale_hash)` enters the panel tally like a
    /// plain vote. `from == to == Disputed` per reveal,
    /// `Disputed -> Settled` on the M-th matching reveal (then
    /// `PanelResolved` follows, like the plain path). Amounts follow
    /// the `PanelJudgment` shape (`payout` = the revealed taker
    /// share). The actor is the revealing member.
    JudgmentRevealed,
    /// AV-139: unclaimed rent swept from a terminal vault via
    /// [`Escrow::sweep_unclaimed_rent`](crate::Escrow::sweep_unclaimed_rent).
    /// `from` is the terminal state, `to` is `Closed`; amounts carry
    /// the swept rent-exempt lamports in `rent_reclaimed`. The actor
    /// is the sweeping caller (permissionless). Always emitted on
    /// success: an ineligible vault is rejected, so there is no
    /// no-op case.
    RentSwept,
    /// AV-140: two opposite-direction escrows netted bilaterally
    /// ([`Escrow::net_escrows`](crate::Escrow::net_escrows)) — the
    /// mutual obligations offset, so the larger leg's lockup shrank
    /// by the netted amount with no transfer. `from == to == Funded`
    /// on the larger leg (the netting is an offset, not a lifecycle
    /// move — like
    /// [`EscrowEventKind::ReleaseIntentAnnounced`]); on an exact
    /// mutual offset `to == Released` (the leg's obligation is fully
    /// extinguished). The event carries the netted amount as a
    /// payout-shaped amount (the lockup was reduced by exactly that),
    /// so the event-sourced fold keeps the conservation identity.
    /// The smaller leg emits [`EscrowEventKind::Released`]
    /// separately — with a zero payout, the honest record that no
    /// transfer occurred. The actor is the netting party.
    EscrowsNetted,
    /// AV-148: the taker posted counter-fund via
    /// [`Escrow::fund_taker`](crate::Escrow::fund_taker). `from == to
    /// ==` the state after the call (a `Funded` re-entry — pure
    /// deposit bookkeeping, not a lifecycle move — like
    /// [`EscrowEventKind::TrancheFunded`]). The event carries
    /// [`EventAmounts::none`]: the counter-fund is the fold seed's
    /// inflow leg (the taker's locked leg), so the fold seeds the
    /// lockup with the bilateral total at `Funded`, exactly like
    /// `Funded` itself. The actor is the funding taker. Always emitted
    /// on success — a rejected call changes nothing, so a failed call
    /// emits nothing.
    TakerFunded,
    /// AV-149: one claimant pulled their share via
    /// [`Escrow::claim_share`](crate::Escrow::claim_share). `from ==
    /// to == Funded` for a non-terminal pull (pure leg bookkeeping,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::Claimed`]); the final pull moves the
    /// escrow to `Released`. The event carries the leg's gross in
    /// [`EventAmounts::payout`] (the AV-17 fee sliced from it rides
    /// `fee`), so the fold books it exactly like `Claimed` — the
    /// state machine's `released += gross` bit-for-bit. The actor is
    /// the pulling claimant. Always emitted on success — a rejected
    /// call changes nothing, so a failed call emits nothing.
    ShareClaimed,
    /// AV-150: the initializer froze the vesting unlock clock via
    /// [`Escrow::pause_vesting`](crate::Escrow::pause_vesting).
    /// `from == to == Funded` — a pure schedule-config move, no
    /// funds move and the state byte does not move either. The
    /// actor is the initializer. The indexer reads the new
    /// `vesting_pause.paused_at` from the vault tail for the exact
    /// freeze moment.
    VestingPaused,
    /// AV-150: the initializer restarted a paused vesting schedule
    /// via [`Escrow::resume_vesting`](crate::Escrow::resume_vesting).
    /// `from == to == Funded` — the schedule's `start`/`end`/`cliff_at`
    /// shift forward by the paused duration (the unlock window slides,
    /// its length is unchanged), no funds move. The actor is the
    /// initializer.
    VestingResumed,
    /// AV-154: one attestor's key was rotated in place by dual-signed
    /// governance
    /// ([`Escrow::replace_attestor`](crate::Escrow::replace_attestor)).
    /// `from == to ==` the current state (a config change, not a
    /// lifecycle move — like
    /// [`EscrowEventKind::AttestorsUpdated`]); the new key is read
    /// from the vault, the event is the ordering signal. Emitted only
    /// on an actual change: rotating to the key already registered at
    /// the slot is an idempotent no-op that emits nothing (paralleling
    /// [`EscrowEventKind::AttestorsUpdated`]'s no-op rule). The
    /// rotated slot's recorded vote was cleared — the event marks the
    /// moment the old key lost its approval.
    AttestorReplaced,
    /// AV-155: the milestone tranche amounts were renegotiated by
    /// dual-signed governance
    /// ([`Escrow::amend_milestones`](crate::Escrow::amend_milestones)).
    /// `from == to ==` the current state (a config change, not a
    /// lifecycle move — like [`EscrowEventKind::QuorumUpdated`]); the
    /// new amounts are read from the vault, the event is the ordering
    /// signal. Emitted only on an actual change: re-affirming the
    /// current amounts is an idempotent no-op that emits nothing
    /// (paralleling [`EscrowEventKind::MilestonesAdjusted`]'s no-op
    /// rule). Unlike `MilestonesAdjusted` (AV-70's pre-settlement
    /// re-split), this fires mid-flight: confirmed/settled tranches
    /// stay pinned while the unconfirmed ones move. All amounts are
    /// zero — repricing moves no funds (the later tranche releases
    /// carry the new amounts with their fees).
    MilestonesAmended,
    /// AV-158: a delayed-governance action was proposed by either
    /// party
    /// ([`Escrow::propose_governance`](crate::Escrow::propose_governance)).
    /// `from == to ==` the current state (a proposal, not a config
    /// change yet — like [`EscrowEventKind::QuorumUpdated`]'s
    /// no-op rule, the proposal itself moves nothing). The staged
    /// action is read from the vault's live proposal, the event is
    /// the ordering signal — indexers watch this to learn the delay
    /// window's start. All amounts are zero.
    GovernanceProposed,
    /// AV-158: a delayed-governance proposal survived its delay
    /// window and was executed by either party
    /// ([`Escrow::execute_governance`](crate::Escrow::execute_governance)).
    /// `from == to ==` the current state (a config change, not a
    /// lifecycle move — like [`EscrowEventKind::QuorumUpdated`]);
    /// the applied action is read from the vault, the event is the
    /// ordering signal. All amounts are zero — executing a
    /// governance action moves no funds (the later payouts carry the
    /// new config).
    GovernanceExecuted,
    /// AV-158: a live delayed-governance proposal was cancelled by
    /// either party
    /// ([`Escrow::cancel_governance`](crate::Escrow::cancel_governance)).
    /// `from == to ==` the current state (the proposal is dropped,
    /// the config is untouched — like
    /// [`EscrowEventKind::QuorumUpdated`]'s no-op rule). All amounts
    /// are zero.
    GovernanceCancelled,
    /// AV-174: accumulated protocol fees were extracted to the
    /// protocol side via
    /// [`Escrow::withdraw_protocol_fees`](crate::Escrow::withdraw_protocol_fees).
    /// `from == to ==` the current state — a treasury operation, not
    /// a lifecycle move (like [`EscrowEventKind::QuorumUpdated`]).
    /// `amounts.fee` carries the withdrawn amount and
    /// `amounts.refund` the remaining withdrawable headroom, so
    /// indexers see the post-withdrawal headroom without re-reading
    /// the vault. The actor is the withdrawing authority (the pinned
    /// fee recipient or the initializer). Always emitted on success —
    /// a rejected call changes nothing, so a failed call emits
    /// nothing.
    FeeWithdrawn,
    /// AV-203: the taker confirmed delivery (see
    /// [`Escrow::confirm_delivery`]). `from == to ==` the current
    /// state — a confirmation, not a lifecycle move (like
    /// [`EscrowEventKind::MilestoneConfirmed`]). Emitted only on
    /// the first confirmation; repeat confirmations are idempotent
    /// no-ops that emit nothing. The actor is the taker.
    DeliveryConfirmed,
    /// AV-223: an upstream escrow was linked to a downstream escrow
    /// as a funding chain ([`link_chain`](super::link_chain)).
    /// `from == to ==` the current state (a config change, not a
    /// lifecycle move — like [`EscrowEventKind::SwapLinked`]); the
    /// downstream escrow id is read from the vault, the event is
    /// the ordering signal. The actor is the linking party.
    /// Always emitted on success.
    ChainLinked,
    /// AV-223: an upstream escrow's funding chain broke — its
    /// terminal cancel / expiry / dispute settlement cleared the
    /// link ([`break_chain`](super::break_chain)), so the
    /// downstream will never be funded by this upstream.
    /// `from == to ==` the terminal state; amounts carry
    /// [`EventAmounts::none`] (the break moves no funds). The actor
    /// is the party whose terminal action broke the chain. Always
    /// emitted when a linked escrow terminates this way.
    ChainBroken,
    /// AV-224: the milestone tranche amounts were reallocated by
    /// dual-signed governance
    /// ([`Escrow::reallocate_milestones`](crate::Escrow::reallocate_milestones)).
    /// `from == to ==` the current state (a config change, not a
    /// lifecycle move — like [`EscrowEventKind::MilestonesAmended`]);
    /// the new amounts are read from the vault, the event is the
    /// ordering signal. Emitted only on an actual change: a no-op
    /// re-affirmation emits nothing (paralleling
    /// [`EscrowEventKind::MilestonesAmended`]'s no-op rule). Unlike
    /// `MilestonesAmended`, an unconfirmed tranche may be repriced
    /// to zero — cleared, not deleted — and the before/after
    /// tranche tables ride the event's `milestone_reallocation`
    /// field, so the reallocation is auditable from the log alone.
    /// All amounts are zero — repricing moves no funds (the later
    /// tranche releases carry the new amounts with their fees).
    MilestonesReallocated,
    /// AV-225: a vested milestone tranche claimed strictly after
    /// its claim deadline ([`Escrow::with_milestone_claim_deadline`](crate::Escrow::with_milestone_claim_deadline)).
    /// `from == to ==` the current state (the expiry is a
    /// reclassification, not a settlement — the tranche joins the
    /// refundable remainder, like [`EscrowEventKind::MilestoneSkipped`]);
    /// `amounts.refund` carries the expired tranche (the
    /// initializer's refund) and the event's
    /// `milestone_claim_expired` field carries the tranche index,
    /// so the expiry is auditable from the log alone. Emitted on
    /// the rejected claim call itself (see
    /// [`IndexedEscrow::release_milestone`]), not on a later cancel:
    /// the caller learns the rejection and the return together.
    MilestoneClaimExpired,
    /// AV-226: a milestone tranche was appended to the end of the
    /// plan by dual-signed governance
    /// ([`Escrow::append_milestone_tranche`](crate::Escrow::append_milestone_tranche)).
    /// `from == to ==` the current state (a config change, not a
    /// lifecycle move — like [`EscrowEventKind::MilestonesAmended`]);
    /// all amounts are zero — appending moves no funds (the later
    /// tranche release carries the new amount with its fee). The
    /// appended tranche is read from the vault — the plan's last
    /// tranche after the append — the event is the ordering signal.
    MilestoneTrancheAppended,
    /// AV-227: the claimant roster was amended by initializer-only
    /// governance
    /// ([`Escrow::amend_claimant_roster`](crate::Escrow::amend_claimant_roster)).
    /// `from == to ==` the current state (a config change, not a
    /// lifecycle move — like [`EscrowEventKind::MilestonesAmended`]);
    /// all amounts are zero — amending moves no funds (the later
    /// `claim_share` pulls carry the new shares). The amended roster
    /// is read from the vault — the event is the ordering signal.
    ClaimantRosterAmended,
    /// AV-229: a slice of a milestone tranche was claimed through
    /// [`Escrow::release_milestone_partial`](crate::Escrow::release_milestone_partial).
    /// `from` is the pre-claim state, `to` the post-claim state
    /// (the final slice carries `to == Released`, like
    /// [`EscrowEventKind::MilestoneReleased`]); `amounts.payout`
    /// carries the slice's gross (net payout + fee, net of the
    /// AV-206 / AV-216 penalties priced on this call) and
    /// `amounts.fee` the protocol fee, like `MilestoneReleased`
    /// — a partial claim moves funds, so it is a payout event,
    /// not a config event. The tranche index is not carried: the
    /// event stream is in-order, and the tranche is always the
    /// first unsettled one at emit time (the same convention as
    /// `MilestoneReleased`).
    MilestonePartiallyClaimed,
    /// AV-230: the linear vesting schedule was revised by
    /// dual-signed governance
    /// ([`Escrow::amend_vesting_schedule`](crate::Escrow::amend_vesting_schedule)).
    /// `from == to ==` the current state (a config change, not a
    /// lifecycle move — like [`EscrowEventKind::ClaimantRosterAmended`]);
    /// all amounts are zero — amending moves no funds (the later
    /// `claim` pulls price against the new schedule). The amended
    /// schedule is read from the vault, so the event needs no
    /// extra field.
    VestingScheduleAmended,
    /// AV-231: the milestone deadline table was revised by
    /// dual-signed governance
    /// ([`Escrow::amend_milestone_due_dates`](crate::Escrow::amend_milestone_due_dates)).
    /// `from == to ==` the current state (a config change, not a
    /// lifecycle move — like [`EscrowEventKind::VestingScheduleAmended`]);
    /// all amounts are zero — amending moves no funds (the later
    /// `release_milestone` calls price late penalties against the
    /// new dates). The amended table is read from the vault, so
    /// the event needs no extra field.
    MilestoneDueDatesAmended,
    /// AV-232: a skipped milestone tranche was restored to the
    /// claimable schedule by dual-signed governance
    /// ([`Escrow::unskip_milestone`](crate::Escrow::unskip_milestone)).
    /// `from == to ==` the current state (a schedule restoration,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::MilestoneDueDatesAmended`]); all amounts
    /// are zero — unskipping moves no funds (the tranche returns to
    /// the claimable schedule; the refund it had joined only
    /// materializes at a later cancel). The restored tranche is read
    /// from the vault, so the event needs no extra field.
    MilestoneUnskipped,
    /// AV-233: the protocol fee rate and ceiling were revised by
    /// dual-signed governance
    /// ([`Escrow::amend_protocol_fee`](crate::Escrow::amend_protocol_fee)).
    /// `from == to ==` the current state (a rate revision, not a
    /// lifecycle move — like
    /// [`EscrowEventKind::MilestoneUnskipped`]); all amounts are
    /// zero — amending moves no funds (only later taker payouts
    /// reprice against the new rate and cap). The amended rate and
    /// cap are read from the vault, so the event needs no extra
    /// field.
    ProtocolFeeAmended,
    /// AV-234: the milestone verifier was rotated by dual-signed
    /// governance
    /// ([`Escrow::rotate_milestone_verifier`](crate::Escrow::rotate_milestone_verifier)).
    /// `from == to ==` the current state (a gatekeeper revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::ProtocolFeeAmended`]); all amounts are
    /// zero — rotating moves no funds (only later attestation
    /// checks read the new key). The new verifier is read from
    /// the vault, so the event needs no extra field.
    MilestoneVerifierRotated,
    /// AV-235: the arbiter adjudication fee was revised by
    /// dual-signed governance
    /// ([`Escrow::amend_arbiter_fee`](crate::Escrow::amend_arbiter_fee)).
    /// `from == to ==` the current state (a fee revision, not a
    /// lifecycle move — like
    /// [`EscrowEventKind::MilestoneVerifierRotated`]); all amounts
    /// are zero — amending moves no funds (only later dispute
    /// settlements price against the new fee). The amended fee
    /// legs are read from the vault, so the event needs no extra
    /// field.
    ArbiterFeeAmended,
    /// AV-236: the slash-appeal window was revised by dual-signed
    /// governance
    /// ([`Escrow::amend_appeal_window`](crate::Escrow::amend_appeal_window)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::ArbiterFeeAmended`]); all amounts are
    /// zero — amending moves no funds (only slashes executed after
    /// the amendment stamp their appeal deadline from the new
    /// window; an already-stamped deadline is untouched). The
    /// amended window is read from the vault, so the event needs
    /// no extra field.
    AppealWindowAmended,
    /// AV-237: the tiered slash ladder was revised by dual-signed
    /// governance
    /// ([`Escrow::amend_slash_ladder`](crate::Escrow::amend_slash_ladder)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::AppealWindowAmended`]); all amounts are
    /// zero — amending moves no funds (only slashes executed after
    /// the amendment price from the amended future rungs; the
    /// consumed prefix, the penalty already paid, and the cursor
    /// are untouched). The amended ladder is read from the vault,
    /// so the event needs no extra field.
    SlashLadderAmended,
    /// AV-238: the slash-appeal bond was revised by dual-signed
    /// governance
    /// ([`Escrow::amend_appeal_bond`](crate::Escrow::amend_appeal_bond)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::SlashLadderAmended`]); all amounts are
    /// zero — amending moves no funds (only appeals filed after
    /// the amendment lock the new bond; an already-locked bond
    /// is untouched). The amended bond is read from the vault,
    /// so the event needs no extra field.
    AppealBondAmended,
    /// AV-240: the expiry grace period was revised by dual-signed
    /// governance
    /// ([`Escrow::amend_grace_period`](crate::Escrow::amend_grace_period)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::AppealBondAmended`]); all amounts are
    /// zero — amending moves no funds (only expiry determinations
    /// after the amendment follow the new grace; an already-executed
    /// determination is history). The amended grace period is read
    /// from the vault, so the event needs no extra field.
    GracePeriodAmended,
    /// AV-241: the dispute-evidence disclosure deadline was
    /// revised by dual-signed governance
    /// ([`Escrow::amend_evidence_deadline`](crate::Escrow::amend_evidence_deadline)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::GracePeriodAmended`]); all amounts are
    /// zero — amending moves no funds (only disputes escalated
    /// after the amendment measure their window from the new
    /// deadline; a live dispute's computed due date is
    /// untouched, since a live dispute is `Disputed`, not
    /// `Funded`). The amended deadline is read from the vault,
    /// so the event needs no extra field.
    EvidenceDeadlineAmended,
    /// AV-242: the pre-agreed arbitration default judgment's deadline
    /// was revised by dual-signed governance
    /// ([`Escrow::amend_arbitration_deadline`](crate::Escrow::amend_arbitration_deadline)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::GracePeriodAmended`]); all amounts are
    /// zero — amending moves no funds (only disputes escalated
    /// after the amendment measure their default-judgment window
    /// from the new deadline; a live dispute's trigger window is
    /// untouched, since a live dispute is `Disputed`, not
    /// `Funded`). The amended deadline is read from the vault,
    /// so the event needs no extra field.
    ArbitrationDeadlineAmended,
    /// AV-243: the per-taker claim cooldown was revised by
    /// dual-signed governance
    /// ([`Escrow::amend_claim_cooldown`](crate::Escrow::amend_claim_cooldown)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::GracePeriodAmended`]); all amounts are
    /// zero — amending moves no funds (the next claim's eligibility
    /// is recomputed live from the new cooldown, since
    /// `last_claim_slot` is untouched and the eligibility predicate
    /// adds the live field). The amended cooldown is read from the
    /// vault, so the event needs no extra field.
    ClaimCooldownAmended,
    /// AV-244: the delivery-confirmation deadline was revised by
    /// dual-signed governance
    /// ([`Escrow::amend_delivery_deadline`](crate::Escrow::amend_delivery_deadline)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::GracePeriodAmended`]); all amounts are
    /// zero — amending moves no funds (confirmations after the
    /// amendment are judged against the new deadline, since
    /// `confirm_delivery_at` reads the live field; a delivery
    /// already confirmed keeps its first-won stamp, so moving the
    /// deadline can neither rewrite nor wash clean a recorded
    /// lateness). The amended deadline is read from the vault,
    /// so the event needs no extra field.
    DeliveryDeadlineAmended,
    /// AV-245: the late-delivery penalty rate was revised by
    /// dual-signed governance
    /// ([`Escrow::amend_late_delivery_penalty_bps`](crate::Escrow::amend_late_delivery_penalty_bps)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::GracePeriodAmended`]); all amounts are
    /// zero — amending moves no funds (a late-stamped but
    /// not-yet-released delivery reprices at the new rate, since
    /// `release` / `release_milestone` price from the live field;
    /// amounts already released and penalties already banked are
    /// never restated). The amended rate is read from the vault,
    /// so the event needs no extra field.
    LateDeliveryPenaltyAmended,
    /// AV-246: the release cooling window was revised by
    /// dual-signed governance
    /// ([`Escrow::amend_release_cooling`](crate::Escrow::amend_release_cooling)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::GracePeriodAmended`]); all amounts are
    /// zero — amending moves no funds (a live announced intent is
    /// re-measured against the new window, since
    /// `is_release_cooling_eligible` reads the live field; a
    /// vetoed intent stays vetoed, because veto clears the intent
    /// and this amendment writes the window only). The amended
    /// window is read from the vault, so the event needs no extra
    /// field.
    ReleaseCoolingAmended,
    /// AV-247: one milestone tranche's claim deadline was revised
    /// by dual-signed governance
    /// ([`Escrow::amend_milestone_claim_deadline`](crate::Escrow::amend_milestone_claim_deadline)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::GracePeriodAmended`]); all amounts are
    /// zero — amending moves no funds (the claim gate re-reads
    /// the deadline live, so an extended tranche may still claim
    /// and a shortened one expires sooner; a tranche already
    /// claimed or skipped keeps its settlement, and clearing the
    /// deadline with `0` removes the gate). The amended deadline
    /// is read from the vault, so the event needs no extra field.
    MilestoneClaimDeadlineAmended,
    /// AV-248: the per-extension expiry-increase cap was revised
    /// by dual-signed governance
    /// ([`Escrow::amend_max_extension_secs`](crate::Escrow::amend_max_extension_secs)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::GracePeriodAmended`]); all amounts are
    /// zero — amending moves no funds (the next extension is
    /// judged against the live cap, so tightening rejects
    /// increments that fit the old bound, loosening admits
    /// increments the old bound refused, and closing with `0`
    /// refuses every increment; extensions already made keep
    /// their deadline moves and their count). The amended cap is
    /// read from the vault, so the event needs no extra field.
    MaxExtensionAmended,
    /// AV-249: the absolute timelock was revised by dual-signed
    /// governance
    /// ([`Escrow::amend_timelock`](crate::Escrow::amend_timelock)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::GracePeriodAmended`]); all amounts are
    /// zero — amending moves no funds (the payout gates re-read
    /// the lock live, so lengthening pushes a payout out,
    /// shortening pulls it in, and clearing with `0` unlocks
    /// immediately; amounts already released are never restated,
    /// and the relative and slot locks are untouched). The amended
    /// lock is read from the vault, so the event needs no extra
    /// field.
    TimelockAmended,
    /// AV-250: the relative timelock was revised by dual-signed
    /// governance
    /// ([`Escrow::amend_relative_timelock`](crate::Escrow::amend_relative_timelock)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::GracePeriodAmended`]); all amounts are
    /// zero — amending moves no funds (the payout gates re-read
    /// the window live against the unchanged `fund_at` anchor, so
    /// lengthening pushes a payout out, shortening pulls it in,
    /// and clearing with `0` unlocks immediately; amounts already
    /// released are never restated, and the absolute and slot
    /// locks are untouched). The amended window is read from the
    /// vault, so the event needs no extra field.
    RelativeTimelockAmended,
    /// AV-251: the slot timelock was revised by dual-signed
    /// governance
    /// ([`Escrow::amend_slot_timelock`](crate::Escrow::amend_slot_timelock)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::GracePeriodAmended`]); all amounts are
    /// zero — amending moves no funds (the slot gates re-read
    /// the window live against the unchanged `fund_slot` anchor,
    /// so lengthening pushes a payout out, shortening pulls it in,
    /// and clearing with `0` unlocks immediately; amounts already
    /// released are never restated, and the absolute and relative
    /// locks are untouched). The amended window is read from the
    /// vault, so the event needs no extra field.
    SlotTimelockAmended,
    /// AV-252: the unclaimed-rent sweep grace period was revised by
    /// dual-signed governance
    /// ([`Escrow::amend_rent_sweep_grace`](crate::Escrow::amend_rent_sweep_grace)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::GracePeriodAmended`]); all amounts are
    /// zero — amending moves no funds (the sweep gate re-reads
    /// the grace live against the unchanged `terminal_at` stamp, so
    /// lengthening pushes a sweep out, shortening pulls it in,
    /// and clearing with `0` restores the 30-day default; a
    /// terminal or closed vault cannot be amended, so a sweep
    /// already performed is never undone). The amended grace is
    /// read from the vault, so the event needs no extra field.
    RentSweepGraceAmended,
    /// AV-253: the tiered protocol-fee schedule was revised by
    /// dual-signed governance
    /// ([`Escrow::amend_fee_schedule`](crate::Escrow::amend_fee_schedule)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::ProtocolFeeAmended`]); all amounts are
    /// zero — amending moves no funds (later taker payouts reprice
    /// live from the amended schedule, the flat rate and the cap
    /// are untouched, and fees already charged or withdrawn are
    /// never restated). The amended schedule is read from the
    /// vault, so the event needs no extra field.
    FeeScheduleAmended,
    /// AV-254: the streaming fee rate was revised by
    /// dual-signed governance
    /// ([`Escrow::amend_streaming_fee`](crate::Escrow::amend_streaming_fee)).
    /// `from == to ==` the current state (a governance revision,
    /// not a lifecycle move — like
    /// [`EscrowEventKind::ProtocolFeeAmended`]); all amounts are
    /// zero — amending moves no funds (the charge gate re-reads
    /// the live rate against the unchanged `fund_at` anchor, so
    /// raising the rate bills the difference on the next
    /// settlement, lowering it bills nothing new, and fees already
    /// charged are never clawed back). The amended rate is read
    /// from the vault, so the event needs no extra field.
    StreamingFeeRateAmended,
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
            // AV-91: appended after AppealResolved so discriminants
            // 0–45 stay stable for already-serialized histories.
            46 => Self::EvidenceFiled,
            // AV-93: appended after EvidenceFiled so discriminants
            // 0–46 stay stable for already-serialized histories.
            47 => Self::ReleasedSplit,
            // AV-95b: appended after ReleasedSplit so discriminants
            // 0–47 stay stable for already-serialized histories.
            48 => Self::BasketReleased,
            // AV-95b: appended after BasketReleased so discriminants
            // 0–48 stay stable for already-serialized histories.
            49 => Self::BasketCancelled,
            // AV-95b: appended after BasketCancelled so discriminants
            // 0–49 stay stable for already-serialized histories.
            50 => Self::BasketExpiredCancelled,
            // AV-96: appended after BasketExpiredCancelled so
            // discriminants 0–50 stay stable for already-serialized
            // histories.
            51 => Self::DenylistUpdated,
            // AV-103: appended after DenylistUpdated so discriminants
            // 0–51 stay stable for already-serialized histories.
            52 => Self::AppealExpired,
            // AV-104: appended after AppealExpired so discriminants
            // 0–52 stay stable for already-serialized histories.
            53 => Self::DelegationGranted,
            54 => Self::DelegationRevoked,
            // AV-105: appended after DelegationRevoked so
            // discriminants 0–54 stay stable for already-serialized
            // histories.
            55 => Self::SwapLinked,
            // AV-109: appended after SwapLinked so discriminants
            // 0–55 stay stable for already-serialized histories.
            56 => Self::DeadmanClaimed,
            // AV-110: appended after DeadmanClaimed so discriminants
            // 0–56 stay stable for already-serialized histories.
            57 => Self::RentToppedUp,
            // AV-111: appended after RentToppedUp so discriminants
            // 0–57 stay stable for already-serialized histories.
            58 => Self::TrancheFunded,
            // AV-112: appended after TrancheFunded so discriminants
            // 0–58 stay stable for already-serialized histories.
            59 => Self::ReleaseIntentAnnounced,
            // AV-112: appended after ReleaseIntentAnnounced so
            // discriminants 0–59 stay stable for
            // already-serialized histories.
            60 => Self::ReleaseIntentVetoed,
            // AV-114: appended after ReleaseIntentVetoed so
            // discriminants 0-60 stay stable for
            // already-serialized histories.
            61 => Self::EscrowsMerged,
            // AV-122: appended after EscrowsMerged so discriminants
            // 0-61 stay stable for already-serialized histories.
            62 => Self::Declined,
            63 => Self::CounterOfferProposed,
            64 => Self::CounterOfferAccepted,
            65 => Self::CounterOfferRejected,
            // AV-123: appended after CounterOfferRejected so
            // discriminants 0-65 stay stable for already-serialized
            // histories.
            66 => Self::ReleaseViaIntent,
            // AV-124: appended after ReleaseViaIntent so discriminants
            // 0-66 stay stable for already-serialized histories.
            67 => Self::KeeperBountyPaid,
            // AV-127: appended after KeeperBountyPaid so discriminants
            // 0-67 stay stable for already-serialized histories.
            68 => Self::PartialRefunded,
            // AV-130: appended after PartialRefunded so discriminants
            // 0-68 stay stable for already-serialized histories.
            69 => Self::DualControlInitiated,
            70 => Self::DualControlConfirmed,
            71 => Self::DualControlCancelled,
            // AV-137: appended after DualControlCancelled so
            // discriminants 0–71 stay stable for already-serialized
            // histories.
            72 => Self::JudgmentCommitted,
            // AV-137: appended after JudgmentCommitted so
            // discriminants 0–72 stay stable for already-serialized
            // histories.
            73 => Self::JudgmentRevealed,
            // AV-139: appended after JudgmentRevealed so
            // discriminants 0–73 stay stable for already-serialized
            // histories.
            74 => Self::RentSwept,
            // AV-140: appended after RentSwept so discriminants 0–74
            // stay stable for already-serialized histories.
            75 => Self::EscrowsNetted,
            // AV-148: appended after EscrowsNetted so discriminants
            // 0–75 stay stable for already-serialized histories.
            76 => Self::TakerFunded,
            // AV-149: appended after TakerFunded so discriminants
            // 0–76 stay stable for already-serialized histories.
            77 => Self::ShareClaimed,
            // AV-150: appended after ShareClaimed so discriminants
            // 0–77 stay stable for already-serialized histories.
            78 => Self::VestingPaused,
            // AV-150: appended after VestingPaused so discriminants
            // 0–78 stay stable for already-serialized histories.
            79 => Self::VestingResumed,
            // AV-154: appended after VestingResumed so discriminants
            // 0–79 stay stable for already-serialized histories.
            80 => Self::AttestorReplaced,
            // AV-155: appended after AttestorReplaced so discriminants
            // 0–80 stay stable for already-serialized histories.
            81 => Self::MilestonesAmended,
            // AV-158: appended after MilestonesAmended so
            // discriminants 0–81 stay stable for already-serialized
            // histories.
            82 => Self::GovernanceProposed,
            83 => Self::GovernanceExecuted,
            84 => Self::GovernanceCancelled,
            // AV-174: appended after GovernanceCancelled so
            // discriminants 0–84 stay stable for already-serialized
            // vaults.
            85 => Self::FeeWithdrawn,
            // AV-203: appended after FeeWithdrawn so discriminants
            // 0–85 stay stable for already-serialized vaults.
            86 => Self::DeliveryConfirmed,
            // AV-223: appended after DeliveryConfirmed so
            // discriminants 0–86 stay stable for already-serialized
            // histories.
            87 => Self::ChainLinked,
            88 => Self::ChainBroken,
            // AV-224: appended after ChainBroken so
            // discriminants 0-88 stay stable for already-serialized
            // histories.
            89 => Self::MilestonesReallocated,
            // AV-225: appended after MilestonesReallocated so
            // discriminants 0–89 stay stable for already-serialized
            // histories.
            90 => Self::MilestoneClaimExpired,
            // AV-226: appended after MilestoneClaimExpired so
            // discriminants 0–90 stay stable for already-serialized
            // histories.
            91 => Self::MilestoneTrancheAppended,
            // AV-227: appended after MilestoneTrancheAppended so
            // discriminants 0–91 stay stable for already-serialized
            // histories.
            92 => Self::ClaimantRosterAmended,
            // AV-229: appended after ClaimantRosterAmended so
            // discriminants 0–92 stay stable for already-serialized
            // histories.
            93 => Self::MilestonePartiallyClaimed,
            // AV-230: appended after MilestonePartiallyClaimed so
            // discriminants 0–93 stay stable for already-serialized
            // histories.
            94 => Self::VestingScheduleAmended,
            // AV-231: appended after VestingScheduleAmended so
            // discriminants 0–94 stay stable for already-serialized
            // histories.
            95 => Self::MilestoneDueDatesAmended,
            // AV-232: appended after MilestoneDueDatesAmended so
            // discriminants 0–95 stay stable for already-serialized
            // histories.
            96 => Self::MilestoneUnskipped,
            // AV-233: appended after MilestoneUnskipped so
            // discriminants 0–96 stay stable for already-serialized
            // histories.
            97 => Self::ProtocolFeeAmended,
            // AV-234: appended after ProtocolFeeAmended so
            // discriminants 0–97 stay stable for already-serialized
            // histories.
            98 => Self::MilestoneVerifierRotated,
            // AV-235: appended after MilestoneVerifierRotated so
            // discriminants 0–98 stay stable for already-serialized
            // histories.
            99 => Self::ArbiterFeeAmended,
            // AV-236: appended after ArbiterFeeAmended so
            // discriminants 0–99 stay stable for already-serialized
            // histories.
            100 => Self::AppealWindowAmended,
            // AV-237: appended after AppealWindowAmended so
            // discriminants 0–100 stay stable for already-serialized
            // histories.
            101 => Self::SlashLadderAmended,
            // AV-238: appended after SlashLadderAmended so
            // discriminants 0–101 stay stable for already-serialized
            // histories.
            102 => Self::AppealBondAmended,
            // AV-240: appended after AppealBondAmended so
            // discriminants 0–102 stay stable for already-serialized
            // histories.
            103 => Self::GracePeriodAmended,
            // AV-241: appended after GracePeriodAmended so
            // discriminants 0–103 stay stable for already-serialized
            // histories.
            104 => Self::EvidenceDeadlineAmended,
            // AV-242: appended after EvidenceDeadlineAmended so
            // discriminants 0–104 stay stable for already-serialized
            // histories.
            105 => Self::ArbitrationDeadlineAmended,
            // AV-243: appended after ArbitrationDeadlineAmended so
            // discriminants 0–105 stay stable for already-serialized
            // histories.
            106 => Self::ClaimCooldownAmended,
            // AV-244: appended after ClaimCooldownAmended so
            // discriminants 0–106 stay stable for already-serialized
            // histories.
            107 => Self::DeliveryDeadlineAmended,
            // AV-245: appended after DeliveryDeadlineAmended so
            // discriminants 0–107 stay stable for already-serialized
            // histories.
            108 => Self::LateDeliveryPenaltyAmended,
            // AV-246: appended after LateDeliveryPenaltyAmended so
            // discriminants 0–108 stay stable for already-serialized
            // histories.
            109 => Self::ReleaseCoolingAmended,
            // AV-247: appended after ReleaseCoolingAmended so
            // discriminants 0–109 stay stable for already-serialized
            // histories.
            110 => Self::MilestoneClaimDeadlineAmended,
            // AV-248: appended after MilestoneClaimDeadlineAmended so
            // discriminants 0–110 stay stable for already-serialized
            // histories.
            111 => Self::MaxExtensionAmended,
            // AV-249: appended after MaxExtensionAmended so
            // discriminants 0–111 stay stable for already-serialized
            // histories.
            112 => Self::TimelockAmended,
            // AV-250: appended after TimelockAmended so
            // discriminants 0–112 stay stable for already-serialized
            // histories.
            113 => Self::RelativeTimelockAmended,
            // AV-251: appended after RelativeTimelockAmended so
            // discriminants 0–113 stay stable for already-serialized
            // histories.
            114 => Self::SlotTimelockAmended,
            // AV-252: appended after SlotTimelockAmended so
            // discriminants 0–114 stay stable for already-serialized
            // histories.
            115 => Self::RentSweepGraceAmended,
            // AV-253: appended after RentSweepGraceAmended so
            // discriminants 0–115 stay stable for already-serialized
            // histories.
            116 => Self::FeeScheduleAmended,
            // AV-254: appended after FeeScheduleAmended so
            // discriminants 0–116 stay stable for already-serialized
            // histories.
            117 => Self::StreamingFeeRateAmended,
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
            Self::EvidenceFiled => "evidence_filed",
            Self::ReleasedSplit => "released_split",
            Self::BasketReleased => "basket_released",
            Self::BasketCancelled => "basket_cancelled",
            Self::BasketExpiredCancelled => "basket_expired_cancelled",
            Self::DenylistUpdated => "payout_denylist_updated",
            Self::AppealExpired => "appeal_expired",
            Self::DelegationGranted => "delegation_granted",
            Self::DelegationRevoked => "delegation_revoked",
            Self::SwapLinked => "swap_linked",
            Self::DeadmanClaimed => "deadman_claimed",
            Self::RentToppedUp => "rent_topped_up",
            Self::TrancheFunded => "tranche_funded",
            Self::ReleaseIntentAnnounced => "release_intent_announced",
            Self::ReleaseIntentVetoed => "release_intent_vetoed",
            Self::EscrowsMerged => "escrows_merged",
            // AV-122: appended after escrows_merged so the name table
            // stays stable.
            Self::Declined => "declined",
            Self::CounterOfferProposed => "counter_offer_proposed",
            Self::CounterOfferAccepted => "counter_offer_accepted",
            Self::CounterOfferRejected => "counter_offer_rejected",
            Self::ReleaseViaIntent => "release_via_intent",
            // AV-124: appended after release_via_intent so the name
            // table stays stable for already-serialized histories.
            Self::KeeperBountyPaid => "keeper_bounty_paid",
            // AV-127: appended after keeper_bounty_paid so the name
            // table stays stable for already-serialized histories.
            Self::PartialRefunded => "partial_refunded",
            // AV-130: appended after partial_refunded so the name
            // table stays stable for already-serialized histories.
            Self::DualControlInitiated => "dual_control_initiated",
            Self::DualControlConfirmed => "dual_control_confirmed",
            Self::DualControlCancelled => "dual_control_cancelled",
            // AV-137: appended after dual_control_cancelled so the
            // name table stays stable for already-serialized
            // histories.
            Self::JudgmentCommitted => "judgment_committed",
            Self::JudgmentRevealed => "judgment_revealed",
            // AV-139: appended after judgment_revealed so the name
            // table stays stable.
            Self::RentSwept => "rent_swept",
            // AV-140: appended after rent_swept so the name table
            // stays stable for already-serialized histories.
            Self::EscrowsNetted => "escrows_netted",
            // AV-148: appended after escrows_netted so the name table
            // stays stable for already-serialized histories.
            Self::TakerFunded => "taker_funded",
            // AV-149: appended after taker_funded so the name table
            // stays stable for already-serialized histories.
            Self::ShareClaimed => "share_claimed",
            // AV-150: appended after share_claimed so the name table
            // stays stable for already-serialized histories.
            Self::VestingPaused => "vesting_paused",
            // AV-150: appended after vesting_paused so the name table
            // stays stable for already-serialized histories.
            Self::VestingResumed => "vesting_resumed",
            // AV-154: appended after vesting_resumed so the name
            // table stays stable for already-serialized histories.
            Self::AttestorReplaced => "attestor_replaced",
            // AV-155: appended after attestor_replaced so the name
            // table stays stable for already-serialized histories.
            Self::MilestonesAmended => "milestones_amended",
            // AV-158: appended after milestones_amended so the name
            // table stays stable for already-serialized histories.
            Self::GovernanceProposed => "governance_proposed",
            Self::GovernanceExecuted => "governance_executed",
            Self::GovernanceCancelled => "governance_cancelled",
            Self::FeeWithdrawn => "fee_withdrawn",
            Self::DeliveryConfirmed => "delivery_confirmed",
            Self::ChainLinked => "chain_linked",
            Self::ChainBroken => "chain_broken",
            // AV-224: appended after chain_broken so the name table
            // stays stable for already-serialized histories.
            Self::MilestonesReallocated => "milestones_reallocated",
            // AV-225: appended after milestones_reallocated so the
            // name table stays stable for already-serialized
            // histories.
            Self::MilestoneClaimExpired => "milestone_claim_expired",
            // AV-226: appended after milestone_claim_expired so the
            // name table stays stable for already-serialized
            // histories.
            Self::MilestoneTrancheAppended => "milestone_tranche_appended",
            // AV-227: appended after milestone_tranche_appended so
            // the name table stays stable for already-serialized
            // histories.
            Self::ClaimantRosterAmended => "claimant_roster_amended",
            // AV-229: appended after claimant_roster_amended so the
            // name table stays stable for already-serialized
            // histories.
            Self::MilestonePartiallyClaimed => "milestone_partially_claimed",
            // AV-230: appended after milestone_partially_claimed so
            // the name table stays stable for already-serialized
            // histories.
            Self::VestingScheduleAmended => "vesting_schedule_amended",
            // AV-231: appended after vesting_schedule_amended so
            // the name table stays stable for already-serialized
            // histories.
            Self::MilestoneDueDatesAmended => "milestone_due_dates_amended",
            // AV-232: appended after milestone_due_dates_amended so
            // the name table stays stable for already-serialized
            // histories.
            Self::MilestoneUnskipped => "milestone_unskipped",
            // AV-233: appended after milestone_unskipped so
            // the name table stays stable for already-serialized
            // histories.
            Self::ProtocolFeeAmended => "protocol_fee_amended",
            // AV-234: appended after protocol_fee_amended so
            // the name table stays stable for already-serialized
            // histories.
            Self::MilestoneVerifierRotated => "milestone_verifier_rotated",
            // AV-235: appended after milestone_verifier_rotated so
            // the name table stays stable for already-serialized
            // histories.
            Self::ArbiterFeeAmended => "arbiter_fee_amended",
            // AV-236: appended after arbiter_fee_amended so
            // the name table stays stable for already-serialized
            // histories.
            Self::AppealWindowAmended => "appeal_window_amended",
            // AV-237: appended after appeal_window_amended so
            // the name table stays stable for already-serialized
            // histories.
            Self::SlashLadderAmended => "slash_ladder_amended",
            Self::AppealBondAmended => "appeal_bond_amended",
            Self::GracePeriodAmended => "grace_period_amended",
            Self::EvidenceDeadlineAmended => "evidence_deadline_amended",
            Self::ArbitrationDeadlineAmended => "arbitration_deadline_amended",
            Self::ClaimCooldownAmended => "claim_cooldown_amended",
            Self::DeliveryDeadlineAmended => "delivery_deadline_amended",
            Self::LateDeliveryPenaltyAmended => "late_delivery_penalty_amended",
            Self::ReleaseCoolingAmended => "release_cooling_amended",
            Self::MilestoneClaimDeadlineAmended => "milestone_claim_deadline_amended",
            Self::MaxExtensionAmended => "max_extension_amended",
            Self::TimelockAmended => "timelock_amended",
            Self::RelativeTimelockAmended => "relative_timelock_amended",
            Self::SlotTimelockAmended => "slot_timelock_amended",
            Self::RentSweepGraceAmended => "rent_sweep_grace_amended",
            Self::FeeScheduleAmended => "fee_schedule_amended",
            Self::StreamingFeeRateAmended => "streaming_fee_rate_amended",
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
            "evidence_filed" => Self::EvidenceFiled,
            "released_split" => Self::ReleasedSplit,
            "basket_released" => Self::BasketReleased,
            "basket_cancelled" => Self::BasketCancelled,
            "basket_expired_cancelled" => Self::BasketExpiredCancelled,
            "payout_denylist_updated" => Self::DenylistUpdated,
            "appeal_expired" => Self::AppealExpired,
            "delegation_granted" => Self::DelegationGranted,
            "delegation_revoked" => Self::DelegationRevoked,
            "swap_linked" => Self::SwapLinked,
            "deadman_claimed" => Self::DeadmanClaimed,
            "rent_topped_up" => Self::RentToppedUp,
            "tranche_funded" => Self::TrancheFunded,
            "release_intent_announced" => Self::ReleaseIntentAnnounced,
            "release_intent_vetoed" => Self::ReleaseIntentVetoed,
            "escrows_merged" => Self::EscrowsMerged,
            // AV-122: appended after escrows_merged so the name table
            // stays stable for already-serialized histories.
            "declined" => Self::Declined,
            "counter_offer_proposed" => Self::CounterOfferProposed,
            "counter_offer_accepted" => Self::CounterOfferAccepted,
            "counter_offer_rejected" => Self::CounterOfferRejected,
            // AV-123: appended after counter_offer_rejected so the
            // name table stays stable for already-serialized
            // histories.
            "release_via_intent" => Self::ReleaseViaIntent,
            // AV-124: appended after release_via_intent so the name
            // table stays stable for already-serialized histories.
            "keeper_bounty_paid" => Self::KeeperBountyPaid,
            // AV-127: appended after keeper_bounty_paid so the name
            // table stays stable for already-serialized histories.
            "partial_refunded" => Self::PartialRefunded,
            // AV-130: appended after partial_refunded so the name
            // table stays stable for already-serialized histories.
            "dual_control_initiated" => Self::DualControlInitiated,
            "dual_control_confirmed" => Self::DualControlConfirmed,
            "dual_control_cancelled" => Self::DualControlCancelled,
            // AV-137: appended after dual_control_cancelled so the
            // name table stays stable for already-serialized
            // histories.
            "judgment_committed" => Self::JudgmentCommitted,
            "judgment_revealed" => Self::JudgmentRevealed,
            // AV-139: appended after judgment_revealed so the name
            // table stays stable.
            "rent_swept" => Self::RentSwept,
            // AV-140: appended after rent_swept so the name table
            // stays stable for already-serialized histories.
            "escrows_netted" => Self::EscrowsNetted,
            // AV-148: appended after escrows_netted so the name table
            // stays stable for already-serialized histories.
            "taker_funded" => Self::TakerFunded,
            // AV-149: appended after taker_funded so the name table
            // stays stable for already-serialized histories.
            "share_claimed" => Self::ShareClaimed,
            // AV-150: appended after share_claimed so the name table
            // stays stable for already-serialized histories.
            "vesting_paused" => Self::VestingPaused,
            // AV-150: appended after vesting_paused so the name table
            // stays stable for already-serialized histories.
            "vesting_resumed" => Self::VestingResumed,
            // AV-154: appended after vesting_resumed so the name
            // table stays stable for already-serialized histories.
            "attestor_replaced" => Self::AttestorReplaced,
            // AV-155: appended after attestor_replaced so the name
            // table stays stable for already-serialized histories.
            "milestones_amended" => Self::MilestonesAmended,
            // AV-158: appended after milestones_amended so the name
            // table stays stable for already-serialized histories.
            "governance_proposed" => Self::GovernanceProposed,
            "governance_executed" => Self::GovernanceExecuted,
            "governance_cancelled" => Self::GovernanceCancelled,
            "fee_withdrawn" => Self::FeeWithdrawn,
            "delivery_confirmed" => Self::DeliveryConfirmed,
            "chain_linked" => Self::ChainLinked,
            "chain_broken" => Self::ChainBroken,
            // AV-224: appended after chain_broken so the name table
            // stays stable for already-serialized histories.
            "milestones_reallocated" => Self::MilestonesReallocated,
            // AV-225: appended after milestones_reallocated so the
            // name table stays stable for already-serialized
            // histories.
            "milestone_claim_expired" => Self::MilestoneClaimExpired,
            // AV-226: appended after milestone_claim_expired so the
            // name table stays stable for already-serialized
            // histories.
            "milestone_tranche_appended" => Self::MilestoneTrancheAppended,
            // AV-227: appended after milestone_tranche_appended so
            // the name table stays stable for already-serialized
            // histories.
            "claimant_roster_amended" => Self::ClaimantRosterAmended,
            // AV-229: appended after claimant_roster_amended so the
            // name table stays stable for already-serialized
            // histories.
            "milestone_partially_claimed" => Self::MilestonePartiallyClaimed,
            // AV-230: appended after milestone_partially_claimed so
            // the name table stays stable for already-serialized
            // histories.
            "vesting_schedule_amended" => Self::VestingScheduleAmended,
            // AV-231: appended after vesting_schedule_amended so
            // the name table stays stable for already-serialized
            // histories.
            "milestone_due_dates_amended" => Self::MilestoneDueDatesAmended,
            // AV-232: appended after milestone_due_dates_amended so
            // the name table stays stable for already-serialized
            // histories.
            "milestone_unskipped" => Self::MilestoneUnskipped,
            // AV-233: appended after milestone_unskipped so
            // the name table stays stable for already-serialized
            // histories.
            "protocol_fee_amended" => Self::ProtocolFeeAmended,
            // AV-234: appended after protocol_fee_amended so
            // the name table stays stable for already-serialized
            // histories.
            "milestone_verifier_rotated" => Self::MilestoneVerifierRotated,
            // AV-235: appended after milestone_verifier_rotated so
            // the name table stays stable for already-serialized
            // histories.
            "arbiter_fee_amended" => Self::ArbiterFeeAmended,
            // AV-236: appended after arbiter_fee_amended so
            // the name table stays stable for already-serialized
            // histories.
            "appeal_window_amended" => Self::AppealWindowAmended,
            // AV-237: appended after appeal_window_amended so
            // the name table stays stable for already-serialized
            // histories.
            "slash_ladder_amended" => Self::SlashLadderAmended,
            "appeal_bond_amended" => Self::AppealBondAmended,
            "grace_period_amended" => Self::GracePeriodAmended,
            "evidence_deadline_amended" => Self::EvidenceDeadlineAmended,
            "arbitration_deadline_amended" => Self::ArbitrationDeadlineAmended,
            "claim_cooldown_amended" => Self::ClaimCooldownAmended,
            "delivery_deadline_amended" => Self::DeliveryDeadlineAmended,
            "late_delivery_penalty_amended" => Self::LateDeliveryPenaltyAmended,
            "release_cooling_amended" => Self::ReleaseCoolingAmended,
            "milestone_claim_deadline_amended" => Self::MilestoneClaimDeadlineAmended,
            "max_extension_amended" => Self::MaxExtensionAmended,
            "timelock_amended" => Self::TimelockAmended,
            "relative_timelock_amended" => Self::RelativeTimelockAmended,
            "slot_timelock_amended" => Self::SlotTimelockAmended,
            "rent_sweep_grace_amended" => Self::RentSweepGraceAmended,
            "fee_schedule_amended" => Self::FeeScheduleAmended,
            "streaming_fee_rate_amended" => Self::StreamingFeeRateAmended,
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
/// compensation), `rent_reclaimed` is the AV-34 rent-exempt deposit
/// returned to the initializer when the vault account is closed
/// (non-zero only on `VaultClosed`), and `arbiter_fee` is the AV-135
/// arbiter adjudication fee sliced from the taker's share on a dispute
/// settlement (non-zero only on `Resolved`, `DefaultJudgment` and
/// `PanelResolved` when the escrow opted into the fee). All fields are
/// zero when the kind moves no such value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventAmounts {
    pub payout: u64,
    pub fee: u64,
    pub refund: u64,
    pub penalty: u64,
    pub rent_reclaimed: u64,
    pub arbiter_fee: u64,
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
            arbiter_fee: 0,
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
            arbiter_fee: 0,
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
            arbiter_fee: 0,
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
            arbiter_fee: 0,
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
            arbiter_fee: 0,
        }
    }

    /// A batch vault close (AV-79): the Σ rent-exempt deposits the
    /// batch reclaimed, in `rent_reclaimed` — the same shape as
    /// [`Self::close`], aggregated across the closed vaults. Rides the
    /// [`EscrowEventKind::VaultsBatchClosed`] summary event.
    pub(crate) fn batch_close(total_rent: u64) -> Self {
        Self::close(total_rent)
    }

    /// A protocol-fee withdrawal (AV-174): `withdrawn` lamports of
    /// accumulated protocol fee extracted to the protocol side, with
    /// `withdrawable` remaining. The `fee` leg carries the withdrawn
    /// amount (it is fee money moving); `refund` carries the remaining
    /// withdrawable headroom so indexers see the post-withdrawal
    /// headroom without re-reading the vault. Rides the
    /// [`EscrowEventKind::FeeWithdrawn`] event. The fold books nothing:
    /// the fee already left the fold's `locked` at payout time as part
    /// of the gross release (the AV-17 routing-slice rule), and
    /// `fees_withdrawn` is the dedicated extraction counter (the
    /// `penalty_paid` precedent).
    fn fee_withdrawn(withdrawn: u64, withdrawable: u64) -> Self {
        Self {
            payout: 0,
            fee: withdrawn,
            refund: withdrawable,
            penalty: 0,
            rent_reclaimed: 0,
            arbiter_fee: 0,
        }
    }

    /// A permissionless rent top-up (AV-110): the topped-up `lamports`
    /// ride `rent_reclaimed` — the rent-balance leg (added to the
    /// vault's balance here; the direction is read from the event
    /// kind, which is `RentToppedUp`, not `VaultClosed`). Rides the
    /// [`EscrowEventKind::RentToppedUp`] event.
    pub(crate) fn rent_top_up(lamports: u64) -> Self {
        Self {
            payout: 0,
            fee: 0,
            refund: 0,
            penalty: 0,
            rent_reclaimed: lamports,
            arbiter_fee: 0,
        }
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
            arbiter_fee: 0,
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
            arbiter_fee: 0,
        }
    }

    /// A keeper-bounty payout (AV-124): the `bounty` paid to the
    /// permissionless crank caller rides `payout` — the caller is
    /// neither party, so it is neither a taker payout nor an
    /// initializer refund, and the direction is read from the event
    /// kind. The pool balance *after* the debit rides the event's
    /// `bounty_pool_remaining`, not the amounts. Rides the
    /// [`EscrowEventKind::KeeperBountyPaid`] event.
    pub(crate) fn keeper_bounty(bounty: u64) -> Self {
        Self {
            payout: bounty,
            fee: 0,
            refund: 0,
            penalty: 0,
            rent_reclaimed: 0,
            arbiter_fee: 0,
        }
    }

    /// A slash-appeal overturn (AV-86): the refunded penalty rides
    /// `payout` — it is a taker restitution (no fee sliced), neither a
    /// fresh payout for work nor an initializer refund. AV-103: the
    /// refunded appeal bond rides `payout` too — the taker's full
    /// restitution, no fee. Rides the
    /// [`EscrowEventKind::AppealResolved`] event.
    pub(crate) fn appeal_overturn(refunded: u64, bond_refunded: u64) -> Self {
        Self {
            payout: refunded.saturating_add(bond_refunded),
            fee: 0,
            refund: 0,
            penalty: 0,
            rent_reclaimed: 0,
            arbiter_fee: 0,
        }
    }

    /// A slash-appeal uphold or window-lapse forfeiture (AV-103): the
    /// forfeited appeal bond rides `penalty` — a penalty-like sink
    /// routed to the initializer, neither a taker payout nor an
    /// initializer refund. Rides the
    /// [`EscrowEventKind::AppealResolved`] event on uphold and the
    /// [`EscrowEventKind::AppealExpired`] event on expiry.
    pub(crate) fn appeal_bond_forfeited(forfeited: u64) -> Self {
        Self {
            payout: 0,
            fee: 0,
            refund: 0,
            penalty: forfeited,
            rent_reclaimed: 0,
            arbiter_fee: 0,
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
    /// AV-172: the post-execution return-data attestation, when the
    /// executor verified the callee's `set_return_data` against the
    /// declared [`ReturnDataExpectation`](super::ReturnDataExpectation).
    /// `None` when the executor did not (or could not) check return
    /// data — e.g. a legacy target under the `Warn` missing-data
    /// policy, or an executor that only checks balance deltas.
    pub return_data: Option<CpiReturnDataAudit>,
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
/// `release_split` (AV-93) carries the per-recipient payout legs on
/// the `ReleasedSplit` event: `(recipient, net_share)` pairs in
/// split-table order, `len` of them valid — the first leg carries the
/// bps-floor dust, so the legs sum to the net payout exactly. It is
/// `None` on every other kind — the event log never invents legs.
///
/// `slash_ladder_index` (AV-126) carries the rung the slash consumed
/// on the `Slashed` event: the pre-slash cursor, stamped by the
/// emitter after the push (the state machine advances the cursor
/// during the slash). It is `None` on every other kind — and on
/// single-level slashes, which have no ladder — the event log never
/// invents a rung.
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
    /// AV-93: the per-recipient payout legs for the `ReleasedSplit`
    /// event — `(recipient, net_share)` pairs in split-table order,
    /// `len` of them valid. Carried only by
    /// [`EscrowEventKind::ReleasedSplit`] (`None` on every other kind —
    /// like `split_children`, which rides only `EscrowSplit`). The
    /// emitter stamps it after the push (see `push_event`), mirroring
    /// the `split_children` precedent — never a `push_event`
    /// parameter. Fixed-size
    /// ([`MAX_RELEASE_SPLIT_RECIPIENTS`](crate::MAX_RELEASE_SPLIT_RECIPIENTS))
    /// so the event stays `Copy`.
    pub release_split: Option<([ReleaseShare; crate::MAX_RELEASE_SPLIT_RECIPIENTS], u8)>,
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
    /// AV-91: the committed dispute-evidence Merkle root
    /// ([`crate::Escrow::evidence_root`]), carried by
    /// [`EscrowEventKind::Escalated`] and
    /// [`EscrowEventKind::EvidenceFiled`] (`None` on every other kind —
    /// like `rationale_hash`, which rides only `Resolved`). Read from
    /// the escrow at emit time (never a `push_event` parameter), so the
    /// log always agrees with the account.
    pub evidence_root: Option<[u8; 32]>,
    /// AV-91: disclosure progress `(disclosed, total)` — the
    /// ([`crate::Escrow::evidence_disclosure`]) count of evidence
    /// documents disclosed with valid Merkle proofs and the committed
    /// leaf count — stamped on the settlement kinds (`Resolved`,
    /// `DefaultJudgment`, `PanelResolved`), read from the escrow at
    /// emit time (never a `push_event` parameter), like
    /// `evidence_defaulted`. The arbiter panel verifies disclosure
    /// completeness before judgment: undisclosed documents are
    /// honestly deducted in the judgment weight, and the settlement
    /// event carries the tamper-proof record. `None` on every other
    /// kind, and on settlements with no committed root.
    pub evidence_disclosure: Option<(u64, u8)>,
    /// AV-124: the keeper-bounty pool balance *after* the crank's
    /// debit ([`crate::Escrow::keeper_bounty_pool`]), carried by
    /// [`EscrowEventKind::KeeperBountyPaid`] (`None` on every other
    /// kind — like `evidence_root`, which rides only the dispute
    /// kinds). Read from the escrow at emit time (never a
    /// `push_event` parameter), so the log always agrees with the
    /// account — indexers track pool exhaustion from the event
    /// stream alone.
    pub bounty_pool_remaining: Option<u64>,
    /// AV-126: the rung the slash consumed
    /// ([`crate::Escrow::slash_ladder_index`] *before* the slash
    /// advanced it), carried by [`EscrowEventKind::Slashed`] (`None`
    /// on every other kind — and on single-level slashes, which have
    /// no ladder — like `bounty_pool_remaining`, which rides only
    /// `KeeperBountyPaid`). Stamped by the `Slashed` emitter after the
    /// push (see `push_event`), mirroring the `appeal_outcome` /
    /// `split_children` precedent — never a `push_event` parameter —
    /// so the log records exactly the tier that priced the penalty.
    pub slash_ladder_index: Option<u8>,
    /// AV-133: whether this `Unpaused` event was emitted by the
    /// scheduled auto-recovery ([`Escrow::try_auto_unpause`]) rather
    /// than a manual [`IndexedEscrow::unpause`] call. `true` only on
    /// the auto-recovered `Unpaused` event — `false` on every other
    /// kind and on manual unpauses (like `evidence_defaulted`, the
    /// event log never invents an auto-recovery). Stamped by the
    /// transition emitter after the push — never a `push_event`
    /// parameter — because the schedule is consumed by the recovery
    /// before the event is pushed.
    pub auto_unpause: bool,
    /// AV-182: the canonical Memo program audit note for a lifecycle
    /// transition (`fund` / `release` / `cancel` / `resolve` /
    /// `claim`) — the exact UTF-8 bytes the keeper attaches as a Memo
    /// program instruction on the transition's transaction, so the
    /// on-chain log and the off-chain event agree by construction
    /// (see [`crate::memo::transition_memo_note`]). Stamped by the
    /// transition emitter after the push — never a `push_event`
    /// parameter — and `None` when memo is disabled: the event log
    /// never invents a note.
    pub memo: Option<MemoNote>,
    /// AV-224: the before/after milestone tranche tables for a
    /// [`EscrowEventKind::MilestonesReallocated`] event — `(before,
    /// after, count)`, each table a full
    /// [`MAX_MILESTONES`](crate::MAX_MILESTONES) array with only
    /// the first `count` entries valid, in plan order. Carried
    /// only by `MilestonesReallocated` (`None` on every other
    /// kind — like `template_params_hash`, which rides only
    /// `TemplateApplied`). Stamped by the reallocation emitter
    /// after the push (see `push_event`), mirroring the
    /// `split_children` precedent — never a `push_event`
    /// parameter — so the log records exactly the tables the
    /// governance decision moved between, and indexers read the
    /// reallocation without replaying the vault.
    pub milestone_reallocation: Option<([u64; crate::MAX_MILESTONES], [u64; crate::MAX_MILESTONES], u8)>,
    /// AV-225: the expired milestone tranche index, carried by
    /// [`EscrowEventKind::MilestoneClaimExpired`] (`None` on every
    /// other kind — like `milestone_reallocation`, which rides
    /// only `MilestonesReallocated`). Stamped by the expiry
    /// emitter after the push (see `push_event`), mirroring the
    /// `milestone_reallocation` precedent — never a `push_event`
    /// parameter — so the log records exactly which tranche
    /// lapsed, and indexers read the expiry without replaying the
    /// vault. The returned amount rides `amounts.refund` (the
    /// initializer's refund, like `MilestoneSkipped`).
    pub milestone_claim_expired: Option<u8>,
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

/// One payout leg on an [`EscrowEventKind::ReleasedSplit`] event's
/// roster (AV-93): the recipient and its net share, in split-table
/// order. The first leg carries the bps-floor dust, so the legs sum to
/// the event's `amounts.payout - amounts.fee` exactly — an indexer
/// re-derives the Anchor layer's transfer sizes from this roster
/// alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseShare {
    /// The leg's payout destination — one of the AV-49-pinned
    /// recipients the instruction named.
    pub recipient: [u8; 32],
    /// The recipient's net share (`floor(net * bps / 10_000)`, plus
    /// the dust on the first leg).
    pub net_share: u64,
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
    /// AV-182: opt-in Memo program audit trail. Unlike the `with_*`
    /// builders below, this is wrapper-level state — the memo note is
    /// an off-chain observability concern, not vault state, so it is
    /// never persisted and never touches `VAULT_FIELDS`. `None`
    /// (the default) disables memo stamping.
    memo_config: Option<MemoConfig>,
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
            memo_config: None,
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

    /// AV-95b: stand up a multi-mint basket escrow (mirrors
    /// [`Escrow::initialize_basket`]). Emits `Initialized` like
    /// [`Self::initialize`] — the constructor has no prior state, so
    /// from == to == Uninitialized by convention; the basket leg table
    /// is visible in the vault state itself.
    pub fn initialize_basket(
        initializer: [u8; 32],
        taker: [u8; 32],
        legs: &[([u8; 32], u64)],
        expires_at: u64,
        escrow_id: [u8; 32],
        at: u64,
    ) -> Result<Self, EscrowError> {
        let inner = Escrow::initialize_basket(initializer, taker, legs, expires_at)?;
        let mut indexed = Self {
            inner,
            escrow_id,
            events: Vec::new(),
            next_seq: 0,
            memo_config: None,
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
            memo_config: None,
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
            // AV-93: stamped by the ReleasedSplit emitter after the
            // push — never a push_event parameter (see above).
            release_split: None,
            // AV-85: stamped by the SchemaMigrated emitter after the
            // push — never a push_event parameter (see above).
            schema_versions: None,
            // AV-86: stamped by the AppealResolved emitter after the
            // push — never a push_event parameter (see above).
            appeal_outcome: None,
            // AV-91: the committed evidence Merkle root rides the
            // Escalated and EvidenceFiled events — read from the
            // escrow at emit time (never a push_event parameter), so
            // the log always agrees with the account.
            evidence_root: if matches!(
                kind,
                EscrowEventKind::Escalated | EscrowEventKind::EvidenceFiled
            ) {
                self.inner.evidence_root()
            } else {
                None
            },
            // AV-91: disclosure progress (disclosed, total) rides the
            // settlement kinds — read from the escrow at emit time
            // (never a push_event parameter), like evidence_defaulted:
            // the arbiter panel verifies disclosure completeness
            // before judgment, and the settlement event carries the
            // tamper-proof record for the judgment-weight audit.
            evidence_disclosure: if matches!(
                kind,
                EscrowEventKind::Resolved
                    | EscrowEventKind::DefaultJudgment
                    | EscrowEventKind::PanelResolved
            ) {
                self.inner.evidence_disclosure()
            } else {
                None
            },
            // AV-124: the post-debit bounty pool rides the
            // KeeperBountyPaid event — read from the escrow at emit
            // time (never a push_event parameter), like
            // evidence_defaulted, so the log always agrees with the
            // account.
            bounty_pool_remaining: if matches!(
                kind,
                EscrowEventKind::KeeperBountyPaid
            ) {
                Some(self.inner.keeper_bounty_pool())
            } else {
                None
            },
            // AV-126: the consumed rung rides the Slashed event —
            // stamped by the `slash` emitter after the push (the
            // pre-slash cursor, which the state machine advances
            // during the slash), so `push_event` leaves it `None`
            // here — never a push_event parameter (see above).
            slash_ladder_index: None,
            // AV-133: the auto-recovery flag rides the auto-recovered
            // Unpaused event — stamped by the transition emitter after
            // the push (the schedule is consumed by the recovery), so
            // `push_event` leaves it `false` here — never a push_event
            // parameter (see above).
            auto_unpause: false,
            // AV-182: the Memo program audit note rides the lifecycle
            // transitions — stamped by the transition emitter after
            // the push (it needs the transition's moved amount), so
            // `push_event` leaves it `None` here — never a push_event
            // parameter (see above).
            memo: None,
            // AV-224: the before/after tranche tables ride the
            // MilestonesReallocated event — stamped by the
            // reallocation emitter after the push, so `push_event`
            // leaves it `None` here — never a push_event parameter
            // (see above).
            // AV-225: the expired tranche index rides the
            // MilestoneClaimExpired event — stamped by the expiry
            // emitter after the push, so `push_event` leaves it
            // `None` here — never a push_event parameter (see
            // above).
            milestone_reallocation: None,
            milestone_claim_expired: None,
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

    /// AV-133: stamp the scheduled-auto-recovery flag on the most
    /// recently pushed event. Called by transition emitters right after
    /// pushing the auto-recovered `Unpaused` event — the schedule is
    /// consumed by the recovery, so the flag cannot be derived at emit
    /// time and is never a `push_event` parameter (mirrors the
    /// `slash_ladder_index` / `appeal_outcome` stamping precedent).
    fn mark_last_event_auto_unpause(&mut self) {
        if let Some(last) = self.events.last_mut() {
            last.auto_unpause = true;
        }
    }

    /// AV-133: run the scheduled auto-recovery check before a
    /// clock-bearing transition. Returns `(was_paused, schedule,
    /// auto_unpaused)`: the pre-call pause snapshot for restore, and
    /// whether the recovery fired. The inner state machine repeats the
    /// check idempotently at its own gate — this call exists so the
    /// wrapper can emit the `Unpaused` event and restore on failure.
    fn begin_auto_unpause(&mut self, at: u64) -> (bool, Option<u64>, bool) {
        let was_paused = self.inner.is_paused();
        let schedule = self.inner.auto_unpause_at();
        let auto_unpaused = self.inner.try_auto_unpause(at);
        (was_paused, schedule, auto_unpaused)
    }

    /// AV-133: restore the pre-call pause state when a transition that
    /// fired the auto-recovery goes on to fail — a failed call changes
    /// nothing observable and (the `ReentryRejected` security signal
    /// aside) emits no events.
    fn restore_auto_unpause_on_failure(
        &mut self,
        was_paused: bool,
        schedule: Option<u64>,
        auto_unpaused: bool,
    ) {
        if auto_unpaused {
            self.inner.restore_auto_unpause(was_paused, schedule);
        }
    }

    /// AV-133: emit the `Unpaused` event for a fired scheduled
    /// auto-recovery, before the transition's own event. `from` is the
    /// pre-call state (the pause flip is a config change, not a
    /// lifecycle move — `from == to`). No event when the recovery did
    /// not fire.
    fn emit_auto_unpause(&mut self, from: EscrowState, at: u64, auto_unpaused: bool) {
        if auto_unpaused {
            self.push_event(
                EscrowEventKind::Unpaused,
                from,
                from,
                EventAmounts::none(),
                at,
                None,
                None,
                None,
                None,
                None,
            );
            self.mark_last_event_auto_unpause();
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

    /// AV-102: wrap a plain [`Escrow`] snapshot as an [`IndexedEscrow`]
    /// so keeper-side tooling (notably
    /// [`simulate_bundle`](super::execution_bundle::simulate_bundle))
    /// can run the event-emitting transitions on a clone. The event
    /// log starts empty (`next_seq` 0) — the wrapper records only
    /// transitions applied *after* the wrap, so a wrapped snapshot
    /// never invents history. Read-only with respect to the caller's
    /// `escrow` (it is moved in, the caller's copy — if any — is
    /// untouched).
    pub fn wrap(escrow_id: [u8; 32], escrow: crate::Escrow) -> Self {
        Self {
            inner: escrow,
            escrow_id,
            events: Vec::new(),
            next_seq: 0,
            memo_config: None,
        }
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

    /// Opt into the permissionless-crank keeper bounty (mirrors
    /// [`Escrow::with_keeper_bounty`], AV-124). Configuration: emits
    /// no event.
    pub fn with_keeper_bounty(
        mut self,
        pool_lamports: u64,
        per_crank_lamports: u64,
    ) -> Result<Self, EscrowError> {
        self.inner = self
            .inner
            .with_keeper_bounty(pool_lamports, per_crank_lamports)?;
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

    /// Opt in to the AV-135 arbiter adjudication fee (mirrors
    /// [`Escrow::with_arbiter_fee`]). Configuration: emits no event.
    pub fn with_arbiter_fee(
        mut self,
        flat_lamports: u64,
        fee_bps: u16,
    ) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_arbiter_fee(flat_lamports, fee_bps)?;
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

    /// Attach a multi-mint basket leg table (mirrors
    /// [`Escrow::with_basket`], AV-95). Configuration: emits no event.
    pub fn with_basket(mut self, legs: &[([u8; 32], u64)]) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_basket(legs)?;
        Ok(self)
    }

    /// Opt in to a payout destination denylist (mirrors
    /// [`Escrow::with_denylist`], AV-96). Configuration: emits no
    /// event.
    pub fn with_denylist(mut self, addrs: &[[u8; 32]]) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_denylist(addrs)?;
        Ok(self)
    }

    /// Opt in to a protocol fee on taker payouts (mirrors
    /// [`Escrow::with_protocol_fee`]). Configuration: emits no event.
    pub fn with_protocol_fee(mut self, fee_bps: u16) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_protocol_fee(fee_bps)?;
        Ok(self)
    }

    /// Opt in to a streaming fee on funded time (mirrors
    /// [`Escrow::with_streaming_fee`], AV-100). Configuration: emits
    /// no event.
    pub fn with_streaming_fee(mut self, rate: u64) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_streaming_fee(rate)?;
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

    /// Bind the milestone verifier gate (mirrors
    /// [`Escrow::with_milestone_verifier`], AV-210).
    /// Configuration: emits no event.
    pub fn with_milestone_verifier(mut self, verifier: [u8; 32]) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_milestone_verifier(verifier)?;
        Ok(self)
    }


    /// Attach per-tranche milestone deadlines (mirrors
    /// [`Escrow::with_milestone_due_dates`], AV-206).
    /// Configuration: emits no event.
    pub fn with_milestone_due_dates(mut self, due_at: &[u64]) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_milestone_due_dates(due_at)?;
        Ok(self)
    }

    /// Opt in to multi-taker share claiming (mirrors
    /// [`Escrow::with_claimants`](crate::Escrow::with_claimants),
    /// AV-149). Configuration: emits no event.
    pub fn with_claimants(
        mut self,
        shares: &[([u8; 32], u16)],
    ) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_claimants(shares)?;
        Ok(self)
    }

    /// Attach a claim deadline to one milestone tranche (mirrors
    /// [`Escrow::with_milestone_claim_deadline`], AV-225).
    /// Configuration: emits no event.
    pub fn with_milestone_claim_deadline(
        mut self,
        tranche: u8,
        deadline_secs: u64,
    ) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_milestone_claim_deadline(tranche, deadline_secs)?;
        Ok(self)
    }

    /// Opt in to tranched funding (mirrors
    /// [`Escrow::with_funding_plan`](crate::Escrow::with_funding_plan),
    /// AV-111). Configuration: emits no event.
    pub fn with_funding_plan(
        mut self,
        total_amount: u64,
        max_tranches: u8,
    ) -> Result<Self, EscrowError> {
        self.inner.with_funding_plan(total_amount, max_tranches)?;
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

    /// Opt in to the tiered default-penalty (slash) ladder (mirrors
    /// [`Escrow::with_slash_ladder`], AV-126). Configuration: emits no
    /// event.
    pub fn with_slash_ladder(
        mut self,
        penalty_account: [u8; 32],
        rungs: &[(u64, u16)],
    ) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_slash_ladder(penalty_account, rungs)?;
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

    /// AV-182: opt in to the on-chain Memo program audit trail. Unlike
    /// the `with_*` builders above, this is wrapper-level state: the
    /// memo note is an off-chain observability concern, not vault
    /// state, so it is never persisted and never touches
    /// `VAULT_FIELDS`. When enabled, the `fund` / `release` /
    /// `cancel` / `resolve` / `claim` emitters stamp the canonical
    /// memo note ([`crate::memo::transition_memo_note`]) on the event,
    /// and the keeper attaches the same note as a Memo program
    /// instruction on the transition's transaction. Disabled by
    /// default — pass [`MemoConfig::disabled`] (or omit the call) for
    /// no memo anywhere.
    pub fn with_memo_config(mut self, config: MemoConfig) -> Self {
        self.memo_config = Some(config);
        self
    }

    /// AV-182: stamp the canonical memo note on the just-pushed event.
    /// No-op when memo is disabled. The note is a pure function of
    /// (transition, escrow_id, amount) — the same bytes the keeper
    /// puts in the Memo instruction — so the event never invents a
    /// note. A failed note build is unreachable for the canonical
    /// format; it leaves the event unstamped rather than failing the
    /// transition.
    fn stamp_memo(&mut self, transition: MemoTransition, amount: u64) {
        let enabled = self.memo_config.map(|c| c.enabled).unwrap_or(false);
        if !enabled {
            return;
        }
        if let Ok(note) = transition_memo_note(transition, &self.escrow_id, amount) {
            if let Some(event) = self.events.last_mut() {
                event.memo = Some(note);
            }
        }
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
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self.inner.fund(authority, at);
        match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
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
        // AV-182: the memo note pins the funded amount.
        self.stamp_memo(MemoTransition::Fund, self.inner.amount());
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
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self.inner.release(authority, at, amount, mint, payout_to);
        let (payout, fee) = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        // `amount` is the gross *principal* payout by construction
        // (`payout + fee == amount`); it cannot overflow u64 addition.
        // AV-107: when interest is configured the taker's `payout`
        // additionally carries the bundled yield claim — the event
        // records the principal legs, and the yield leg is observable
        // via the `interest_paid` counter / snapshot.
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
        // AV-182: the memo note pins the gross moved amount
        // (`payout + fee == amount` by construction).
        self.stamp_memo(MemoTransition::Release, payout + fee);
        Ok((payout, fee))
    }

    /// Release through a signed Ed25519 intent (mirrors
    /// [`Escrow::release_via_intent`], AV-123 — the gasless /
    /// meta-transaction path). Emits
    /// [`EscrowEventKind::ReleaseViaIntent`] (not `Released`) so
    /// indexers can distinguish an intent-driven payout from a
    /// party-signed one — the amounts follow the `Released` shape
    /// (`payout` = the gross intent amount, `fee` = the protocol
    /// fee). The event actor is the initializer: their signature
    /// authorized the payout; the relayer that submitted the
    /// transaction is not a party to the escrow. `at` doubles as the
    /// state machine's `now` and the event timestamp; `slot` is the
    /// current Solana slot (the clock sysvar on-chain, never an
    /// instruction param).
    ///
    /// [`Escrow::release_via_intent`]: crate::Escrow::release_via_intent
    pub fn release_via_intent(
        &mut self,
        intent: &ReleaseIntent,
        signature: &[u8; 64],
        at: u64,
        slot: u64,
        mint: Option<[u8; 32]>,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`. A failed intent check (bad signature,
        // replayed nonce, expired intent) is not a reentrant entry
        // and emits nothing.
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self
            .inner
            .release_via_intent(intent, signature, at, slot, mint);
        let (payout, fee) = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        let initializer = self.inner.initializer();
        self.push_event(
            EscrowEventKind::ReleaseViaIntent,
            from,
            self.inner.state(),
            EventAmounts::payout(intent.amount, fee),
            at,
            None,
            None,
            None,
            None,
            Some(initializer),
        );
        Ok((payout, fee))
    }

    /// Opt into dual-control (maker-checker) release governance
    /// (mirrors [`Escrow::with_dual_control`], AV-130). Configuration:
    /// emits no event.
    pub fn with_dual_control(mut self, checker: [u8; 32]) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_dual_control(checker)?;
        Ok(self)
    }

    /// Opt into the delivery-confirmation gate (mirrors
    /// [`Escrow::with_delivery_confirmation`], AV-203). Configuration:
    /// emits no event.
    pub fn with_delivery_confirmation(mut self) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_delivery_confirmation()?;
        Ok(self)
    }

    /// Opt into the delivery-confirmation deadline (mirrors
    /// [`Escrow::with_delivery_deadline`], AV-216). Configuration:
    /// emits no event.
    pub fn with_delivery_deadline(mut self, deadline_at: u64) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_delivery_deadline(deadline_at)?;
        Ok(self)
    }

    /// Opt into the late-delivery penalty rate (mirrors
    /// [`Escrow::with_late_delivery_penalty_bps`], AV-216).
    /// Configuration: emits no event.
    pub fn with_late_delivery_penalty_bps(mut self, bps: u16) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_late_delivery_penalty_bps(bps)?;
        Ok(self)
    }

    /// Opt into the settlement mint (mirrors
    /// [`Escrow::with_settlement_mint`], AV-217). Configuration:
    /// emits no event.
    pub fn with_settlement_mint(mut self, settle_mint: [u8; 32]) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_settlement_mint(settle_mint)?;
        Ok(self)
    }

    /// Declare a release for checker approval (mirrors
    /// [`Escrow::initiate_release`], AV-130 — the *maker* half of the
    /// maker-checker protocol). Emits
    /// [`EscrowEventKind::DualControlInitiated`] (`from == to ==` the
    /// current state — the declaration is a pending intent, not a
    /// lifecycle move; amounts are [`EventAmounts::none`], the
    /// declaration moves no funds). The actor is the maker (the
    /// initializer or their RELEASE-scoped operator). `at` doubles as
    /// the state machine's `now` and the event timestamp. Failed
    /// declarations emit nothing.
    ///
    /// [`Escrow::initiate_release`]: crate::Escrow::initiate_release
    pub fn initiate_release(
        &mut self,
        authority: [u8; 32],
        amount: u64,
        mint: Option<[u8; 32]>,
        payout_to: [u8; 32],
        intent_ttl_secs: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`; a failed declaration gate emits nothing.
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result =
            self.inner
                .initiate_release(authority, at, amount, mint, payout_to, intent_ttl_secs);
        match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        self.push_event(
            EscrowEventKind::DualControlInitiated,
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

    /// Approve the live dual-control declaration and settle it
    /// (mirrors [`Escrow::confirm_release`], AV-130 — the *checker*
    /// half of the maker-checker protocol). Emits
    /// [`EscrowEventKind::DualControlConfirmed`] (not `Released`) so
    /// indexers can distinguish a two-step settlement from a direct
    /// one — amounts follow the `Released` shape (`payout` = the gross
    /// declared amount, `fee` = the protocol fee; the event-sourced
    /// fold books it like `Released`). The actor is the checker —
    /// their approval authorized the payout. `at` doubles as the state
    /// machine's `now` and the event timestamp. Failed confirmations
    /// emit nothing.
    ///
    /// [`Escrow::confirm_release`]: crate::Escrow::confirm_release
    pub fn confirm_release(
        &mut self,
        checker: [u8; 32],
        at: u64,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`. A failed confirmation gate (wrong
        // checker, expired intent, a release guard that would stop the
        // settlement) is not a reentrant entry and emits nothing.
        let intent_amount = self
            .inner
            .dual_control_intent()
            .map(|intent| intent.amount);
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self.inner.confirm_release(checker, at);
        let (payout, fee) = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        self.push_event(
            EscrowEventKind::DualControlConfirmed,
            from,
            self.inner.state(),
            EventAmounts::payout(intent_amount.unwrap_or(0), fee),
            at,
            None,
            None,
            None,
            None,
            Some(checker),
        );
        Ok((payout, fee))
    }

    /// Abort the live dual-control declaration (mirrors
    /// [`Escrow::cancel_release`], AV-130). Emits
    /// [`EscrowEventKind::DualControlCancelled`] (`from == to ==` the
    /// current state; amounts are [`EventAmounts::none`], the abort
    /// moves no funds — the AV-112 `ReleaseIntentVetoed` shape). The
    /// actor is the cancelling party (the maker or the checker). `at`
    /// doubles as the state machine's `now` and the event timestamp.
    /// Failed cancels emit nothing.
    ///
    /// [`Escrow::cancel_release`]: crate::Escrow::cancel_release
    pub fn cancel_release(&mut self, caller: [u8; 32], at: u64) -> Result<(), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`; a failed cancel gate emits nothing.
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self.inner.cancel_release(caller, at);
        match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        self.push_event(
            EscrowEventKind::DualControlCancelled,
            from,
            self.inner.state(),
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(caller),
        );
        Ok(())
    }
    /// [`Escrow::release_price_gated`]). Emits `Released` exactly like
    /// [`IndexedEscrow::release`] — the gate is a check, not a
    /// lifecycle move (mirroring the AV-27 timelock, which likewise
    /// added no event kind). `at` doubles as the state machine's
    /// `now` and the event timestamp; the oracle quote arrives via
    /// `feed` (on-chain: the oracle account's data, passed through by
    /// the Anchor layer).
    ///
    /// [`Escrow::release_price_gated`]: crate::Escrow::release_price_gated
    /// [`IndexedEscrow::release`]: IndexedEscrow::release
    pub fn release_price_gated(
        &mut self,
        authority: [u8; 32],
        amount: u64,
        mint: Option<[u8; 32]>,
        payout_to: [u8; 32],
        at: u64,
        feed: &dyn PriceFeed,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`. The price gate itself runs before the
        // reentrancy guard (see `Escrow::release_price_gated`); a
        // gate failure is not a reentrant entry and emits nothing.
        let result = self
            .inner
            .release_price_gated(authority, at, amount, mint, payout_to, feed);
        let (payout, fee) = self.map_reentrant(result, at)?;
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

    /// Claim the vested amount through the AV-113 oracle price gate
    /// (mirrors [`Escrow::claim_price_gated`]). Emits `Claimed`
    /// exactly like [`IndexedEscrow::claim`].
    ///
    /// [`Escrow::claim_price_gated`]: crate::Escrow::claim_price_gated
    /// [`IndexedEscrow::claim`]: IndexedEscrow::claim
    pub fn claim_price_gated(
        &mut self,
        authority: [u8; 32],
        now: u64,
        mint: Option<[u8; 32]>,
        payout_to: [u8; 32],
        feed: &dyn PriceFeed,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected` (`now` doubles as the event's `at`).
        let result = self
            .inner
            .claim_price_gated(authority, now, mint, payout_to, feed);
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

    /// The taker declines the escrow (mirrors
    /// [`Escrow::decline_escrow`], AV-122).
    ///
    /// Emits `Declined` (`Funded -> Declined`) with zero amounts —
    /// the decline is a refusal, not a settlement. The actor is the
    /// taker.
    pub fn decline_escrow(&mut self, authority: [u8; 32], at: u64) -> Result<(), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self.inner.decline_escrow(authority, at);
        match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        self.push_event(
            EscrowEventKind::Declined,
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

    /// The taker proposes a counter-offer (mirrors
    /// [`Escrow::propose_counter_offer`], AV-122).
    ///
    /// Emits `CounterOfferProposed` (`Funded -> CounterOffered`);
    /// `amounts.payout` carries the proposed amount (no funds moved
    /// — the offer is terms, not a transfer), and the proposed expiry
    /// is read from the vault's `counter_offer`. The actor is the
    /// taker.
    pub fn propose_counter_offer(
        &mut self,
        authority: [u8; 32],
        amount: u64,
        expiry: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self.inner.propose_counter_offer(authority, amount, expiry, at);
        match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        self.push_event(
            EscrowEventKind::CounterOfferProposed,
            from,
            self.inner.state(),
            EventAmounts::payout(amount, 0),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(())
    }

    /// The initializer accepts the taker's live counter-offer
    /// (mirrors [`Escrow::accept_counter_offer`], AV-122).
    ///
    /// Emits `CounterOfferAccepted` (`CounterOffered -> Funded`);
    /// the re-set amount/expiry are read from the vault. The actor
    /// is the initializer.
    pub fn accept_counter_offer(&mut self, authority: [u8; 32], at: u64) -> Result<(), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self.inner.accept_counter_offer(authority, at);
        match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        self.push_event(
            EscrowEventKind::CounterOfferAccepted,
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

    /// The initializer rejects the taker's live counter-offer
    /// (mirrors [`Escrow::reject_counter_offer`], AV-122).
    ///
    /// Emits `CounterOfferRejected` (`CounterOffered -> Funded`);
    /// the terms are unchanged. The actor is the initializer.
    pub fn reject_counter_offer(&mut self, authority: [u8; 32], at: u64) -> Result<(), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self.inner.reject_counter_offer(authority, at);
        match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        self.push_event(
            EscrowEventKind::CounterOfferRejected,
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

    /// Merge `source` into `self` (mirrors
    /// [`Escrow::merge_escrows`]). Emits `EscrowsMerged` on the
    /// surviving escrow (`from == to == Funded`, the merged-in amount
    /// in `amounts.payout`) and `Cancelled` on the source (`Funded` →
    /// `Cancelled`, the released-into-merge amount in
    /// `amounts.refund`). `at` doubles as the event timestamp; the
    /// pure transition takes no clock input. The actor on both events
    /// is the initializer (the only authority that may merge).
    ///
    /// [`Escrow::merge_escrows`]: crate::Escrow::merge_escrows
    pub fn merge_escrows(
        &mut self,
        source: &mut IndexedEscrow,
        authority: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        let source_from = source.inner.state();
        // Capture before the merge: the source's pre-merge remainder is
        // the merged-in leg (what the survivor's lockup actually grows
        // by — the deal-size `amount` overstates it once the source
        // has partial releases). After the merge the source's
        // remainder is 0 — the funds moved, they did not vanish — so
        // the source's `Cancelled` event refunds this same remainder
        // in the fold.
        let source_remaining = source.inner.remaining_amount();
        self.inner.merge_escrows(&mut source.inner, authority)?;
        self.push_event(
            EscrowEventKind::EscrowsMerged,
            from,
            self.inner.state(),
            EventAmounts::payout(source_remaining, 0),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        source.push_event(
            EscrowEventKind::Cancelled,
            source_from,
            source.inner.state(),
            EventAmounts::refund(source_remaining),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(())
    }

    /// Net `other` against `self` bilaterally (mirrors
    /// [`Escrow::net_escrows`]). Returns the [`NettingSettlement`]
    /// receipt. Emits `EscrowsNetted` on the larger leg (`from == to
    /// == Funded` — the netting is an offset, not a lifecycle move;
    /// on an exact mutual offset `to == Released`, the leg's
    /// obligation fully extinguished — with the netted amount in
    /// `amounts.payout`, payout-shaped like the merged-in leg of
    /// `EscrowsMerged`) and `Released` on the smaller leg (`Funded`
    /// → `Released`, `amounts.payout == 0` — the offset extinguished
    /// the smaller leg's obligation with no transfer, and the zero
    /// payout is the honest record of that: the fold must never read
    /// a netting leg as a payment). `at` doubles as the event
    /// timestamp; the pure transition takes no clock input. The actor
    /// on both events is the netting party.
    ///
    /// [`Escrow::net_escrows`]: crate::Escrow::net_escrows
    /// [`NettingSettlement`]: crate::NettingSettlement
    pub fn net_escrows(
        &mut self,
        other: &mut IndexedEscrow,
        authority: [u8; 32],
        at: u64,
    ) -> Result<crate::NettingSettlement, EscrowError> {
        let self_from = self.inner.state();
        let other_from = other.inner.state();
        // Pin the larger leg before settlement: after `net_escrows`
        // the smaller leg is Released and both remainders have moved,
        // so the roles are no longer recoverable from post-state.
        let self_is_larger =
            self.inner.remaining_amount() >= other.inner.remaining_amount();
        let settlement = self.inner.net_escrows(&mut other.inner, authority)?;
        let (larger, smaller, larger_from, smaller_from) = if self_is_larger {
            (&mut *self, &mut *other, self_from, other_from)
        } else {
            (&mut *other, &mut *self, other_from, self_from)
        };
        larger.push_event(
            EscrowEventKind::EscrowsNetted,
            larger_from,
            larger.inner.state(),
            EventAmounts::payout(settlement.netted, 0),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        // The smaller leg's obligation is fully offset — it settles
        // at zero with no transfer. The event carries payout 0
        // *honestly*: a Released with a zero payout leg is the
        // netting signature in the stream, not a payment the fold may
        // mistake for one.
        smaller.push_event(
            EscrowEventKind::Released,
            smaller_from,
            smaller.inner.state(),
            EventAmounts::payout(0, 0),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(settlement)
    }

    /// Atomically release N escrows in one batch (mirrors
    /// [`Escrow::release_many`], AV-141): the initializer's fleet
    /// settlement — N vaults release in one instruction instead of N
    /// transactions. Emits exactly one
    /// [`EscrowEventKind::Released`] per successful leg, in leg order —
    /// partial legs carry `from == to == Funded`, the closing one
    /// `to == Released` — so the payout stream stays complete in
    /// per-escrow `seq` order, exactly as if each leg had gone through
    /// [`IndexedEscrow::release`] alone. `at` doubles as the state
    /// machine's `now` and the event timestamp (the AV-27 timelock gate
    /// sees the same clock the event log records). Returns the
    /// per-leg `(taker_payout, fee)` detail in leg order, like the
    /// inner call.
    ///
    /// Two-phase like the inner call: phase 1 dry-runs every leg's
    /// full `release` guard chain on a shadow copy of the inner state
    /// machine; phase 2 settles the real wrappers leg by leg through
    /// the per-leg `release` wrapper (the auto-unpause handling and
    /// the `Released` emission, identical to a standalone release). A
    /// phase-2 failure restores every wrapper — inner state, the
    /// event stream, and the seq counters — from the pre-call
    /// snapshot, so a failed batch emits nothing and leaves every
    /// escrow bit-identical: the emission rule's "failed calls record
    /// nothing" holds for the batch too. `legs.len() !=
    /// escrows.len()` is [`EscrowError::LegsCountMismatch`] (code
    /// 208), checked before any leg is touched.
    ///
    /// [`Escrow::release_many`]: crate::Escrow::release_many
    pub fn release_many(
        escrows: &mut [IndexedEscrow],
        authority: [u8; 32],
        legs: &[ReleaseLeg],
        mint: Option<[u8; 32]>,
        at: u64,
    ) -> Result<Vec<(u64, u64)>, EscrowError> {
        // Caller-shape bug — fail closed before any leg is touched.
        if legs.len() != escrows.len() {
            return Err(EscrowError::LegsCountMismatch);
        }
        // Phase 1: dry-run shadow validation on the inner state
        // machines — no wrapper (and no event stream) is touched
        // until every leg's guard chain passes.
        for (w, leg) in escrows.iter().zip(legs.iter()) {
            let mut shadow = w.inner;
            shadow.release(authority, at, leg.amount, mint, leg.payout_to)?;
        }
        // Phase 2: real execution through the per-leg `release`
        // wrapper. `IndexedEscrow` is `Clone`, so the defensive
        // snapshot covers inner state, the event stream and the seq
        // counters — a phase-2 failure restores every wrapper
        // bit-identically and emits nothing.
        let snapshot: Vec<IndexedEscrow> = escrows.to_vec();
        let mut out = Vec::with_capacity(legs.len());
        for i in 0..escrows.len() {
            match escrows[i].release(authority, legs[i].amount, mint, legs[i].payout_to, at) {
                Ok(detail) => out.push(detail),
                Err(e) => {
                    escrows.clone_from_slice(&snapshot);
                    return Err(e);
                }
            }
        }
        Ok(out)
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
        min_payout: u64,
        at: u64,
        cpi: &CpiInvocation,
        execute_cpi: F,
    ) -> Result<(u64, u64, CpiReceipt), EscrowError>
    where
        F: FnOnce(&CpiInvocation) -> Result<u64, CpiError>,
    {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        // AV-132: `min_payout` passes straight through to the state
        // machine — the executor reports the actual post-execution
        // taker-leg amount and an actual below the floor rolls back
        // with `SlippageExceeded` (no event, like every other failed
        // transition).
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self
            .inner
            .release_via_cpi(authority, at, amount, mint, payout_to, min_payout, cpi, execute_cpi);
        let (payout, fee, receipt) = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
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
                // AV-172: no return-data check ran on this path yet —
                // the executor stamps `return_data` when it verifies
                // the callee's attestation post-execution.
                return_data: None,
            }),
            None,
            Some(authority),
        );
        Ok((payout, fee, receipt))
    }

    /// Release `amount` split across several recipients by
    /// basis-point weights (mirrors [`Escrow::release_split`], AV-93).
    /// Emits `ReleasedSplit` on every successful call — partial splits
    /// carry `from == to == Funded`, the closing one `to == Released`
    /// — so the payout stream is complete in `seq` order. Amounts
    /// follow the `Released` shape (`payout` = the gross amount,
    /// `fee` = the AV-17 protocol fee charged on the gross before the
    /// split), and the per-recipient `(recipient, net_share)` legs are
    /// stamped on the event's `release_split` field (mirroring the
    /// `EscrowSplit` roster stamp), so indexers and the AV-94 fold read
    /// the Anchor layer's exact transfer sizes from the log. Returns
    /// `(legs, fee)` like the inner method. `at` is both the event
    /// timestamp and the state machine's `now` (so the AV-27 timelock
    /// gate sees the same clock the event log records).
    ///
    /// [`Escrow::release_split`]: super::Escrow::release_split
    pub fn release_split(
        &mut self,
        authority: [u8; 32],
        amount: u64,
        mint: Option<[u8; 32]>,
        shares: &[([u8; 32], u16)],
        at: u64,
    ) -> Result<(Vec<([u8; 32], u64)>, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        // (The inner result is bound first so its `&mut` borrow ends
        // before `map_reentrant` reborrows `self`.)
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self
            .inner
            .release_split(authority, at, amount, mint, shares);
        let (legs, fee) = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        // `amount` is the gross payout by construction
        // (Σ legs + fee == amount); it cannot overflow u64 addition.
        self.push_event(
            EscrowEventKind::ReleasedSplit,
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
        // Stamp the legs after the push (the AV-81 `split_children`
        // precedent): the roster cannot overflow — the inner call
        // validated `shares.len() <= MAX_RELEASE_SPLIT_RECIPIENTS`
        // before any leg existed, and the legs are in table order.
        let mut roster = [ReleaseShare {
            recipient: [0u8; 32],
            net_share: 0,
        }; crate::MAX_RELEASE_SPLIT_RECIPIENTS];
        for (i, (recipient, net_share)) in legs.iter().enumerate() {
            roster[i] = ReleaseShare {
                recipient: *recipient,
                net_share: *net_share,
            };
        }
        self.events
            .last_mut()
            .expect("ReleasedSplit event just pushed")
            .release_split = Some((roster, legs.len() as u8));
        Ok((legs, fee))
    }

    /// Release the full lockup across the initializer-declared
    /// payout-split table (mirrors [`Escrow::release_payout_split`],
    /// AV-108). Emits `ReleasedSplit` — the existing AV-93 event kind
    /// is reused (no new event kind, no `EventAmounts` change): the
    /// amounts follow the `Released` shape (`payout` = the gross
    /// amount, `fee` = the AV-17 protocol fee charged on the gross
    /// before the split), and the per-recipient `(recipient,
    /// net_share)` legs are stamped on the event's `release_split`
    /// field in table order, so indexers and the AV-94 fold read the
    /// Anchor layer's exact transfer sizes from the log. Returns the
    /// legs like the inner method. `at` is both the event timestamp
    /// and the state machine's `now` (so the AV-27 timelock gate sees
    /// the same clock the event log records).
    ///
    /// [`Escrow::release_payout_split`]: super::Escrow::release_payout_split
    pub fn release_payout_split(
        &mut self,
        authority: [u8; 32],
        mint: Option<[u8; 32]>,
        at: u64,
    ) -> Result<Vec<([u8; 32], u64)>, EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        // (The inner result is bound first so its `&mut` borrow ends
        // before `map_reentrant` reborrows `self`.)
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self.inner.release_payout_split(authority, at, mint);
        let legs = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        // The gross amount is the escrow's locked amount by
        // construction (the split table's Σ == amount); the fee is
        // re-derived from the same `charge_protocol_fee` point the
        // inner call used, so the event's amounts match the transition
        // exactly.
        let amount = self.inner.amount();
        let fee = self.inner.protocol_fee_for(amount);
        self.push_event(
            EscrowEventKind::ReleasedSplit,
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
        // Stamp the legs after the push (the AV-81 `split_children`
        // precedent): the roster cannot overflow — the inner call
        // validated `split_count <= MAX_RELEASE_SPLIT_RECIPIENTS`
        // before any leg existed, and the legs are in table order.
        let mut roster = [ReleaseShare {
            recipient: [0u8; 32],
            net_share: 0,
        }; crate::MAX_RELEASE_SPLIT_RECIPIENTS];
        for (i, (recipient, net_share)) in legs.iter().enumerate() {
            roster[i] = ReleaseShare {
                recipient: *recipient,
                net_share: *net_share,
            };
        }
        self.events
            .last_mut()
            .expect("ReleasedSplit event just pushed")
            .release_split = Some((roster, legs.len() as u8));
        Ok(legs)
    }

    /// Cancel the escrow and return funds (mirrors [`Escrow::cancel`]).
    /// Emits `Cancelled` with the combined unwound remainder in
    /// `amounts.refund`. `refund_to` is the refund destination, pinned
    /// against the escrow's refund policy (AV-23). Returns the
    /// `(initializer_refund, taker_refund)` split (AV-148 bilateral
    /// unwind — the initializer's leg to `refund_to`, the taker's leg
    /// back to the taker).
    pub fn cancel(
        &mut self,
        authority: [u8; 32],
        mint: Option<[u8; 32]>,
        refund_to: [u8; 32],
        at: u64,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self.inner.cancel(authority, mint, refund_to, at);
        let (initializer_refund, taker_refund) = self.map_reentrant(result, at)?;
        let to = self.inner.state();
        self.push_event(
            EscrowEventKind::Cancelled,
            from,
            to,
            EventAmounts::refund(initializer_refund + taker_refund),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        // AV-182: the memo note pins the total refunded amount.
        self.stamp_memo(MemoTransition::Cancel, initializer_refund + taker_refund);
        Ok((initializer_refund, taker_refund))
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

    /// Partially refund the escrow (mirrors [`Escrow::partial_refund`],
    /// AV-127). Emits `PartialRefunded` with `from == to == Funded` and
    /// `amounts.refund` carrying the refunded tranche; `refund_to` is
    /// the refund destination, pinned against the escrow's refund
    /// policy (AV-23). Returns the refunded amount. The refunded
    /// tranche also accumulates in the vault's persisted `refunded`
    /// counter (see `Escrow::refunded_amount`) — unlike
    /// [`IndexedEscrow::cancel_partial`], whose audit trail is the
    /// event log alone.
    pub fn partial_refund(
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
        let result = self.inner.partial_refund(authority, amount, mint, refund_to);
        let refund = self.map_reentrant(result, at)?;
        let to = self.inner.state();
        self.push_event(
            EscrowEventKind::PartialRefunded,
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
    /// escrow's refund policy (AV-23). Returns the
    /// `(initializer_refund, taker_refund, penalty)` split (AV-148
    /// bilateral unwind; AV-24: only a taker-initiated cancel charges
    /// the penalty). The event's `refund` leg carries the combined
    /// unwind (`initializer_refund + taker_refund`) — the total funds
    /// the cancel returned to the parties.
    pub fn cancel_expired(
        &mut self,
        authority: [u8; 32],
        now: u64,
        mint: Option<[u8; 32]>,
        refund_to: [u8; 32],
    ) -> Result<(u64, u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected` (`now` doubles as the event's `at`).
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(now);
        let result = self
            .inner
            .cancel_expired(authority, now, mint, refund_to);
        let (initializer_refund, taker_refund, penalty) = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), now);
            }
        };
        self.emit_auto_unpause(pause_state, now, auto_unpaused);
        let to = self.inner.state();
        self.push_event(
            EscrowEventKind::ExpiredCancelled,
            from,
            to,
            EventAmounts::expired_cancel(initializer_refund + taker_refund, penalty),
            now,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok((initializer_refund, taker_refund, penalty))
    }

    /// Permissionless expiry crank (mirrors [`Escrow::crank_expired`],
    /// AV-48). Emits `ExpiredCranked` (carrying the crank `caller` —
    /// the one event kind where the caller is neither party) with the
    /// same [`EventAmounts::expired_cancel`] shape as the party-signed
    /// path; `now` doubles as the event's `at`. AV-124: when the crank
    /// paid a keeper bounty, a second `KeeperBountyPaid` event follows
    /// (`from == to == Cancelled` — the unwind is already final; the
    /// event carries the bounty in `payout`, the caller, and the
    /// post-debit pool balance). Returns the
    /// `(initializer_refund, taker_refund, penalty, bounty)` tuple:
    /// the AV-148 bilateral unwind, only a taker cranker pays the
    /// AV-24 penalty, and the bounty is `0` when no bounty is
    /// configured or the pool is exhausted.
    pub fn crank_expired(
        &mut self,
        caller: [u8; 32],
        now: u64,
        mint: Option<[u8; 32]>,
    ) -> Result<(u64, u64, u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected` (`now` doubles as the event's `at`).
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(now);
        let result = self.inner.crank_expired(caller, now, mint);
        let (initializer_refund, taker_refund, penalty, bounty) = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), now);
            }
        };
        self.emit_auto_unpause(pause_state, now, auto_unpaused);
        let to = self.inner.state();
        self.push_event(
            EscrowEventKind::ExpiredCranked,
            from,
            to,
            EventAmounts::expired_cancel(initializer_refund + taker_refund, penalty),
            now,
            None,
            None,
            None,
            Some(caller),
            Some(caller),
        );
        // AV-124: the bounty settles the already-finalized unwind —
        // its event rides `from == to ==` the post-crank state, and it
        // is emitted only when a bounty was actually paid (a
        // zero-bounty crank emits `ExpiredCranked` alone, keeping the
        // AV-48 event shape for unbountied escrows).
        if bounty > 0 {
            self.push_event(
                EscrowEventKind::KeeperBountyPaid,
                to,
                to,
                EventAmounts::keeper_bounty(bounty),
                now,
                None,
                None,
                None,
                Some(caller),
                Some(caller),
            );
        }
        Ok((initializer_refund, taker_refund, penalty, bounty))
    }

    /// Settle one basket leg to the taker (mirrors
    /// [`Escrow::release_basket`], AV-95b). Emits `BasketReleased`
    /// (`from == Funded`, `to == Funded` while legs remain, `to ==
    /// Released` on the last leg); `now` doubles as the event's `at`.
    /// Amounts follow the `Released` shape (`payout` = the leg's gross
    /// remainder, `fee` = the AV-17 protocol fee on the leg). Returns
    /// the `(payout, fee)` split so the caller can size the token
    /// transfer. A failed leg release emits nothing.
    ///
    /// [`Escrow::release_basket`]: super::Escrow::release_basket
    pub fn release_basket(
        &mut self,
        authority: [u8; 32],
        now: u64,
        mint: Option<[u8; 32]>,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected` (`now` doubles as the event's `at`).
        let result = self.inner.release_basket(authority, now, mint);
        let (payout, fee) = self.map_reentrant(result, now)?;
        let to = self.inner.state();
        // `payout + fee == gross` by construction; it cannot overflow
        // u64 addition.
        self.push_event(
            EscrowEventKind::BasketReleased,
            from,
            to,
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

    /// Refund one basket leg to the escrow's refund recipient (mirrors
    /// [`Escrow::cancel_basket`], AV-95b). Emits `BasketCancelled`
    /// (`from == Funded`, `to == Funded` while legs remain, `to ==
    /// Cancelled` on the last leg) with `amounts.refund` carrying the
    /// leg's remainder. Returns the refunded remainder so the caller
    /// can size the token transfer. A failed leg cancel emits nothing.
    ///
    /// [`Escrow::cancel_basket`]: super::Escrow::cancel_basket
    pub fn cancel_basket(
        &mut self,
        authority: [u8; 32],
        mint: Option<[u8; 32]>,
        at: u64,
    ) -> Result<u64, EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self.inner.cancel_basket(authority, mint, at);
        let refund = self.map_reentrant(result, at)?;
        let to = self.inner.state();
        self.push_event(
            EscrowEventKind::BasketCancelled,
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

    /// Refund one basket leg after expiry (mirrors
    /// [`Escrow::cancel_expired_basket`], AV-95b). Emits
    /// `BasketExpiredCancelled` (`from == Funded`, `to == Funded`
    /// while legs remain, `to == Cancelled` on the last leg); `now`
    /// doubles as the event's `at`. Amounts follow the
    /// `ExpiredCancelled` shape (`refund` = the leg's net refund,
    /// `penalty` = the AV-24 penalty on a taker-initiated cancel).
    /// Returns the `(refund, penalty)` split. A failed call emits
    /// nothing.
    ///
    /// [`Escrow::cancel_expired_basket`]: super::Escrow::cancel_expired_basket
    pub fn cancel_expired_basket(
        &mut self,
        authority: [u8; 32],
        now: u64,
        mint: Option<[u8; 32]>,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected` (`now` doubles as the event's `at`).
        let result = self.inner.cancel_expired_basket(authority, now, mint);
        let (refund, penalty) = self.map_reentrant(result, now)?;
        let to = self.inner.state();
        self.push_event(
            EscrowEventKind::BasketExpiredCancelled,
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

    /// Release every unsettled basket leg atomically to `payout_to`
    /// (mirrors [`Escrow::release_basket_all`], AV-95c). Emits a
    /// single `BasketReleased` (`from == Funded`, `to == Released`)
    /// with the Σ amounts (`payout` = Σ leg gross, `fee` = Σ protocol
    /// fee) — the event-sourced fold (AV-94) books it bit-identically
    /// to the per-leg event sequence it replaces; `now` doubles as
    /// the event's `at`. Returns the [`BasketSettlement`] so the
    /// caller can size the per-mint transfers. A failed call emits
    /// nothing.
    ///
    /// [`Escrow::release_basket_all`]: super::Escrow::release_basket_all
    pub fn release_basket_all(
        &mut self,
        authority: [u8; 32],
        now: u64,
        payout_to: [u8; 32],
    ) -> Result<BasketSettlement, EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected` (`now` doubles as the event's `at`).
        let result = self.inner.release_basket_all(authority, now, payout_to);
        let settlement = self.map_reentrant(result, now)?;
        let to = self.inner.state();
        self.push_event(
            EscrowEventKind::BasketReleased,
            from,
            to,
            EventAmounts::payout(settlement.total_gross(), settlement.fee),
            now,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(settlement)
    }

    /// Refund every unsettled basket leg to the escrow's refund
    /// recipient (mirrors [`Escrow::cancel_basket_all`], AV-95c).
    /// Emits a single `BasketCancelled` (`from == Funded`, `to ==
    /// Cancelled`) with `amounts.refund` carrying the Σ remainder;
    /// `at` doubles as the event's timestamp. Returns the
    /// [`BasketSettlement`] so the caller can size the per-mint
    /// refund transfers. A failed call emits nothing.
    ///
    /// [`Escrow::cancel_basket_all`]: super::Escrow::cancel_basket_all
    pub fn cancel_basket_all(
        &mut self,
        authority: [u8; 32],
        at: u64,
    ) -> Result<BasketSettlement, EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self.inner.cancel_basket_all(authority, at);
        let settlement = self.map_reentrant(result, at)?;
        let to = self.inner.state();
        self.push_event(
            EscrowEventKind::BasketCancelled,
            from,
            to,
            EventAmounts::refund(settlement.total_net()),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(settlement)
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

    /// Rotate one quorum attestor's key by dual-signed governance
    /// (mirrors [`Escrow::replace_attestor`](crate::Escrow::replace_attestor)).
    /// Emits `AttestorReplaced` when the slot's key actually changes;
    /// a no-op rotation (the same key) emits nothing — paralleling
    /// `update_attestors`' no-op rule. `from == to ==` the current
    /// state: the key, not the lifecycle state, is what changed. `at`
    /// is the caller-supplied timestamp (on-chain: the clock sysvar).
    pub fn replace_attestor(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        slot: u8,
        new_attestor: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let before: Option<[u8; 32]> = self
            .inner
            .quorum()
            .and_then(|q| q.attestors().get(slot as usize).copied());
        self.inner
            .replace_attestor(initializer, taker, slot, new_attestor)?;
        let after: Option<[u8; 32]> = self
            .inner
            .quorum()
            .and_then(|q| q.attestors().get(slot as usize).copied());
        // The inner call succeeds with a configured quorum or fails (no
        // quorum / bad slot / bad key / wrong authority / bad state), so
        // a changed key here always means real governance. A same-key
        // rotation is the documented no-op and emits nothing.
        if after != before {
            let state = self.inner.state();
            self.push_event(
                EscrowEventKind::AttestorReplaced,
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
    /// the caller-supplied event timestamp. AV-133: `auto_unpause_at`
    /// opts into scheduled auto-recovery (`Some(t)` — the escrow
    /// resumes automatically when a clock-bearing transition observes
    /// `now >= t`); `None` keeps the manual-pause semantic.
    pub fn pause(
        &mut self,
        authority: [u8; 32],
        auto_unpause_at: Option<u64>,
        at: u64,
    ) -> Result<(), EscrowError> {
        self.inner.pause(authority, auto_unpause_at)?;
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

    /// Top up the vault's rent balance (mirrors
    /// [`Escrow::top_up_rent`], AV-110). Emits `RentToppedUp` with
    /// `from == to ==` the current state (pure lamport bookkeeping,
    /// not a lifecycle move — like `Paused`); the topped-up lamports
    /// ride the event's `rent_reclaimed` amount field. `at` is the
    /// caller-supplied event timestamp (on-chain: the clock sysvar).
    /// The actor is the permissionless caller. A zero-lamport call is
    /// rejected by the state machine, so a successful call always
    /// emits — there is no no-op case.
    pub fn top_up_rent(
        &mut self,
        caller: [u8; 32],
        lamports: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        self.inner.top_up_rent(caller, lamports)?;
        let state = self.inner.state();
        self.push_event(
            EscrowEventKind::RentToppedUp,
            state,
            state,
            EventAmounts::rent_top_up(lamports),
            at,
            None,
            None,
            None,
            None,
            Some(caller),
        );
        Ok(())
    }

    /// Deposit one funding tranche (mirrors
    /// [`Escrow::fund_tranche`](crate::Escrow::fund_tranche), AV-111).
    /// Emits `TrancheFunded` with `from == to ==` the state after the
    /// call (a `Funded` re-entry on later tranches — pure deposit
    /// bookkeeping, not a lifecycle move). The event carries
    /// [`EventAmounts::none`]: the tranche is the fold seed's inflow
    /// leg, so the fold seeds the lockup with the deal size at
    /// `Funded`, exactly like `Funded` itself. `at` is the
    /// caller-supplied event timestamp (on-chain: the clock sysvar).
    /// The actor is the funding initializer (or their FUND-scoped
    /// operator). A rejected tranche changes nothing, so a failed
    /// call emits nothing.
    pub fn fund_tranche(
        &mut self,
        authority: [u8; 32],
        tranche_amount: u64,
        now: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(now);
        if let Err(e) = self.inner.fund_tranche(authority, tranche_amount, now) {
            self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
            return Err(e);
        }
        self.emit_auto_unpause(pause_state, now, auto_unpaused);
        let state = self.inner.state();
        self.push_event(
            EscrowEventKind::TrancheFunded,
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

    /// Post the taker's counter-fund (mirrors
    /// [`Escrow::fund_taker`](crate::Escrow::fund_taker), AV-148).
    /// Emits `TakerFunded` with `from == to ==` the state after the
    /// call (a `Funded` re-entry — pure deposit bookkeeping, not a
    /// lifecycle move, like [`EscrowEventKind::TrancheFunded`]). The
    /// event carries [`EventAmounts::none`]: the counter-fund is the
    /// fold seed's inflow leg (the taker's locked leg), so the fold
    /// seeds the lockup with the bilateral total at `Funded`, exactly
    /// like `Funded` itself. `at` is the caller-supplied event
    /// timestamp (on-chain: the clock sysvar). The actor is the funding
    /// taker. A rejected call changes nothing, so a failed call emits
    /// nothing.
    pub fn fund_taker(
        &mut self,
        authority: [u8; 32],
        amount: u64,
        now: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(now);
        if let Err(e) = self.inner.fund_taker(authority, amount, now) {
            self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
            return Err(e);
        }
        self.emit_auto_unpause(pause_state, now, auto_unpaused);
        let state = self.inner.state();
        self.push_event(
            EscrowEventKind::TakerFunded,
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

    /// Announce a release intent (mirrors
    /// [`Escrow::announce_release`](crate::Escrow::announce_release),
    /// AV-112). Emits `ReleaseIntentAnnounced` with `from == to ==`
    /// the current state (a governance signal, not a lifecycle move)
    /// only when the recorded intent actually changes — a
    /// same-timestamp re-announce is an idempotent no-op that emits
    /// nothing (paralleling
    /// [`EscrowEventKind::DelegationGranted`]'s no-op rule). `at` is
    /// the caller-supplied event timestamp (on-chain: the clock
    /// sysvar). The actor is the announcing party. A rejected
    /// announce changes nothing, so a failed call emits nothing.
    pub fn announce_release(
        &mut self,
        authority: [u8; 32],
        now: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let before = self.inner.release_intent_at();
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(now);
        if let Err(e) = self.inner.announce_release(authority, now) {
            self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
            return Err(e);
        }
        self.emit_auto_unpause(pause_state, now, auto_unpaused);
        let after = self.inner.release_intent_at();
        // The inner call rejects strangers, wrong states, and paused
        // escrows, so a changed intent here always means real
        // governance — and a same-timestamp re-announce stays silent.
        if after != before {
            let state = self.inner.state();
            self.push_event(
                EscrowEventKind::ReleaseIntentAnnounced,
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

    /// Veto a live release intent (mirrors
    /// [`Escrow::veto_release`](crate::Escrow::veto_release), AV-112).
    /// Emits `ReleaseIntentVetoed` with `from == to ==` the current
    /// state (a governance signal, not a lifecycle move) only when
    /// an intent was actually cleared — vetoing with no live intent
    /// is a no-op success that emits nothing. `at` is the
    /// caller-supplied event timestamp (on-chain: the clock sysvar).
    /// The actor is the vetoing party. A rejected veto changes
    /// nothing, so a failed call emits nothing.
    pub fn veto_release(
        &mut self,
        caller: [u8; 32],
        now: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let had_intent = self.inner.release_intent_at().is_some();
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(now);
        if let Err(e) = self.inner.veto_release(caller, now) {
            self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
            return Err(e);
        }
        self.emit_auto_unpause(pause_state, now, auto_unpaused);
        // The inner call is a no-op success with no live intent, so a
        // cleared intent here always means a real veto — and the
        // no-intent no-op stays silent.
        if had_intent {
            let state = self.inner.state();
            self.push_event(
                EscrowEventKind::ReleaseIntentVetoed,
                state,
                state,
                EventAmounts::none(),
                at,
                None,
                None,
                None,
                None,
                Some(caller),
            );
        }
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

    /// Update the payout destination denylist (mirrors
    /// [`Escrow::update_payout_denylist`], AV-96). Emits
    /// `DenylistUpdated` only when the list actually changes; `from ==
    /// to ==` the current state. `at` is the caller-supplied event
    /// timestamp. The actor is the initializer (the veto is the
    /// initializer's compliance instrument).
    pub fn update_payout_denylist(
        &mut self,
        initializer: [u8; 32],
        addrs: &[[u8; 32]],
        at: u64,
    ) -> Result<(), EscrowError> {
        let before = self.inner.payout_denylist();
        self.inner.update_payout_denylist(initializer, addrs)?;
        let after = self.inner.payout_denylist();
        // The inner call rejects bad input, strangers, and wrong states,
        // so a changed list here always means real governance — and a
        // same-list no-op stays silent.
        if after != before {
            let state = self.inner.state();
            self.push_event(
            EscrowEventKind::DenylistUpdated,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(initializer),
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
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(now);
        if let Err(e) = self.inner.extend_expiry(initializer, new_expires_at, now) {
            self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
            return Err(e);
        }
        self.emit_auto_unpause(pause_state, now, auto_unpaused);
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
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(now);
        let result = self.inner.claim(authority, now, mint, payout_to);
        let (payout, fee) = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), now);
            }
        };
        self.emit_auto_unpause(pause_state, now, auto_unpaused);
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
        // AV-182: the memo note pins the gross claimed amount.
        self.stamp_memo(MemoTransition::Claim, payout + fee);
        Ok((payout, fee))
    }

    /// Escalate the escrow into arbitration (mirrors [`Escrow::escalate`]).
    /// Emits `Escalated` (`Funded -> Disputed`) carrying the evidence
    /// hash and the AV-91 evidence Merkle root attached at escalation;
    /// `now` doubles as the event's `at`. AV-131: `dispute_amount` is
    /// the lockup slice the arbiter adjudicates (passed straight
    /// through to `Escrow::escalate`).
    pub fn escalate(
        &mut self,
        authority: [u8; 32],
        now: u64,
        dispute_amount: u64,
        evidence_hash: Option<[u8; 32]>,
        evidence_root: Option<[u8; 32]>,
        evidence_leaves: u8,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(now);
        if let Err(e) = self.inner
            .escalate(authority, now, dispute_amount, evidence_hash, evidence_root, evidence_leaves) {
            self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
            return Err(e);
        }
        self.emit_auto_unpause(pause_state, now, auto_unpaused);
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

    /// Disclose one dispute-evidence document against the committed
    /// Merkle root (mirrors [`Escrow::file_evidence`]). Emits
    /// `EvidenceFiled` carrying the evidence root and the updated
    /// disclosure progress, so indexers can track per-document
    /// disclosure without replaying the bitmap.
    pub fn file_evidence(
        &mut self,
        authority: [u8; 32],
        doc_hash: [u8; 32],
        leaf_index: u8,
        proof: &[[u8; 32]],
        now: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(now);
        if let Err(e) = self.inner
            .file_evidence(authority, doc_hash, leaf_index, proof, now) {
            self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
            return Err(e);
        }
        self.emit_auto_unpause(pause_state, now, auto_unpaused);
        self.push_event(
            EscrowEventKind::EvidenceFiled,
            from,
            self.inner.state(),
            EventAmounts::none(),
            now,
            None,
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
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(now);
        if let Err(e) = self.inner.submit_evidence(authority, evidence_hash, now) {
            self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
            return Err(e);
        }
        self.emit_auto_unpause(pause_state, now, auto_unpaused);
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
    /// `amounts.payout`, the protocol fee in `amounts.fee`, the
    /// initializer's share in `amounts.refund`, and the AV-135 arbiter
    /// adjudication fee in `amounts.arbiter_fee` (zero when the escrow
    /// never opted in) — and the dispute
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
        // AV-119: the event's `at` doubles as the settlement time —
        // the dispute window `[disputed_at, at]` accrues at the AV-107
        // rate inside `resolve`. Capture the pre-settlement remainder
        // so the event records the principal legs (the AV-107
        // convention: the yield legs ride the transfers and stay
        // observable via the `interest_paid` / `dispute_interest`
        // counters and the snapshot).
        let remaining = self.inner.remaining_amount();
        let result =
            self.inner
                .resolve(authority, taker_amount, at, mint, rationale_hash, payout_to);
        let (payout, fee, refund) = self.map_reentrant(result, at)?;
        // `taker_amount` is the gross taker share by construction
        // (`payout + fee == taker_amount`); the refund leg is the
        // principal refund — the initializer's dispute-interest share
        // rides the transfer (see the returned `refund`) but the event
        // keeps the principal leg, like the taker side. AV-135: the
        // arbiter adjudication fee sliced from the post-fee taker
        // share rides `amounts.arbiter_fee` (zero when the escrow never
        // opted in — the legacy event shape is untouched).
        let amounts = EventAmounts {
            payout: taker_amount,
            fee,
            refund: remaining.saturating_sub(taker_amount),
            penalty: 0,
            rent_reclaimed: 0,
            arbiter_fee: self.inner.arbiter_fee_for(taker_amount - fee),
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
        // AV-182: the memo note pins the total settled amount
        // (taker payout + fee + initializer refund).
        self.stamp_memo(MemoTransition::Resolve, payout + fee + refund);
        Ok((payout, fee, refund))
    }

    /// Trigger the pre-agreed arbitration default judgment (mirrors
    /// [`Escrow::trigger_default_judgment`]). Emits `DefaultJudgment`
    /// (`Disputed -> Settled`) with the gross taker share in
    /// `amounts.payout`, the protocol fee in `amounts.fee`, the
    /// initializer's share in `amounts.refund`, and the AV-135 arbiter
    /// adjudication fee in `amounts.arbiter_fee` — the same amounts shape
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
        // AV-119: the inner settlement already ran the dispute-window
        // yield through the shared helper with `now` as `resolved_at`.
        // Capture the pre-settlement remainder so the event records
        // the principal refund leg (the AV-107 convention — see
        // `resolve` above).
        let remaining = self.inner.remaining_amount();
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(now);
        let result = self
            .inner
            .trigger_default_judgment(caller, now, mint, payout_to);
        let (payout, fee, refund) = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), now);
            }
        };
        self.emit_auto_unpause(pause_state, now, auto_unpaused);
        // `default_taker_amount` is the gross taker share by construction
        // (`payout + fee == default_taker_amount`); the event's refund
        // leg is the principal refund — read the pre-agreed taker
        // amount off the judgment (the returned `payout` already
        // carries the taker's dispute-interest share, which stays on
        // the transfer, not the event). AV-135: the arbiter
        // adjudication fee rides `amounts.arbiter_fee` (zero when the
        // escrow never opted in).
        let taker_amount = self
            .inner
            .default_judgment()
            .map(|j| j.default_taker_amount)
            .unwrap_or(0);
        let amounts = EventAmounts {
            payout: payout + fee,
            fee,
            refund: remaining.saturating_sub(taker_amount),
            penalty: 0,
            rent_reclaimed: 0,
            arbiter_fee: self.inner.arbiter_fee_for(taker_amount - fee),
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
    /// (`Disputed -> Settled`) with the `Resolved` amounts shape
    /// (including the AV-135 arbiter fee in `amounts.arbiter_fee`) and
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
        // AV-119: the vote's `at` doubles as the settling vote's
        // settlement time — the dispute window accrues to it inside
        // `submit_panel_judgment`. Capture the pre-settlement
        // remainder so the `PanelResolved` event records the principal
        // legs (the AV-107 convention — see `resolve` above).
        let remaining = self.inner.remaining_amount();
        let result = self.inner.submit_panel_judgment(
            member,
            taker_amount,
            at,
            mint,
            rationale_hash,
            payout_to,
        );
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
                arbiter_fee: 0,
            },
            at,
            None,
            rationale_hash,
            None,
            None,
            Some(member),
        );
        if let Some((_payout, fee, _refund)) = settled {
            // The M-th matching vote settled the escrow: emit the
            // settlement after the vote event. `taker_amount` is the
            // gross taker share by construction
            // (`payout + fee == taker_amount`); the refund leg is the
            // principal refund (see `resolve` above). AV-135: the
            // arbiter adjudication fee rides `amounts.arbiter_fee`
            // (zero when the escrow never opted in).
            let amounts = EventAmounts {
                payout: taker_amount,
                fee,
                refund: remaining.saturating_sub(taker_amount),
                penalty: 0,
                rent_reclaimed: 0,
                arbiter_fee: self.inner.arbiter_fee_for(taker_amount - fee),
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

    /// Opt in to blind (commit-reveal) panel voting (mirrors
    /// [`Escrow::with_blind_panel`], AV-137): the panel tallies
    /// judgments exactly like [`Escrow::with_arbiter_panel`], except
    /// members vote via commit + reveal. Configuration: emits no
    /// event (pre-fund configuration).
    pub fn with_blind_panel(
        mut self,
        members: &[[u8; 32]],
        threshold: u8,
        reveal_window_secs: u64,
    ) -> Result<Self, EscrowError> {
        self.inner = self
            .inner
            .with_blind_panel(members, threshold, reveal_window_secs)?;
        Ok(self)
    }

    /// Commit one panel member's blind judgment (mirrors
    /// [`Escrow::submit_judgment_commit`], AV-137): records the
    /// `SHA-256(taker_amount || rationale_hash || salt)` commitment
    /// without revealing the judgment. Emits `JudgmentCommitted`
    /// (`from == to == Disputed`); `at` is the caller-supplied event
    /// timestamp (and the commitment's `committed_at`).
    pub fn submit_judgment_commit(
        &mut self,
        member: [u8; 32],
        commitment: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`. (Commit is not fund-moving, but the
        // wrapper keeps the uniform reentrancy mapping.)
        let result = self.inner.submit_judgment_commit(member, commitment, at);
        self.map_reentrant(result, at)?;
        // Every commitment is recorded: the commit is the audit
        // trail of the blind round.
        self.push_event(
            EscrowEventKind::JudgmentCommitted,
            from,
            self.inner.state(),
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(member),
        );
        Ok(())
    }

    /// Reveal one panel member's blind judgment (mirrors
    /// [`Escrow::reveal_judgment`], AV-137): the revealed
    /// `(taker_amount, rationale_hash)` enters the panel tally exactly
    /// like a plain vote. Emits `JudgmentRevealed` per reveal (the
    /// revealed taker share rides `amounts.payout`, like
    /// `PanelJudgment`), and `PanelResolved` on the M-th matching
    /// reveal (the reveal event first, then the settlement —
    /// mirroring `submit_panel_judgment`). `at` doubles as the
    /// reveal's `now` and as the settling reveal's settlement time
    /// (the AV-119 convention).
    pub fn reveal_judgment(
        &mut self,
        member: [u8; 32],
        taker_amount: u64,
        rationale_hash: Option<[u8; 32]>,
        salt: [u8; 32],
        mint: Option<[u8; 32]>,
        payout_to: [u8; 32],
        at: u64,
    ) -> Result<Option<(u64, u64, u64)>, EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`. AV-119: the reveal's `at` doubles as the
        // settling reveal's settlement time. Capture the
        // pre-settlement remainder so the `PanelResolved` event
        // records the principal legs (the AV-107 convention — see
        // `resolve` above).
        let remaining = self.inner.remaining_amount();
        let result = self.inner.reveal_judgment(
            member,
            taker_amount,
            rationale_hash,
            salt,
            at,
            at,
            mint,
            payout_to,
        );
        let settled = self.map_reentrant(result, at)?;
        // Every reveal is recorded, settled or not: the revealed
        // vote is the audit trail.
        self.push_event(
            EscrowEventKind::JudgmentRevealed,
            from,
            self.inner.state(),
            EventAmounts {
                payout: taker_amount,
                fee: 0,
                refund: 0,
                penalty: 0,
                rent_reclaimed: 0,
                arbiter_fee: 0,
            },
            at,
            None,
            rationale_hash,
            None,
            None,
            Some(member),
        );
        if let Some((_payout, fee, _refund)) = settled {
            // The M-th matching reveal settled the escrow: emit the
            // settlement after the reveal event (the same shape as
            // the plain panel path's `PanelResolved`).
            let amounts = EventAmounts {
                payout: taker_amount,
                fee,
                refund: remaining.saturating_sub(taker_amount),
                penalty: 0,
                rent_reclaimed: 0,
                arbiter_fee: self.inner.arbiter_fee_for(taker_amount - fee),
            };
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

    /// Renegotiate the milestone tranche amounts by dual-signed
    /// governance (mirrors [`Escrow::amend_milestones`]). Emits
    /// `MilestonesAmended` when the amounts actually change (`from ==
    /// to ==` the current state — the schedule, not the lifecycle
    /// state, is what changed); a no-op re-affirmation emits nothing,
    /// paralleling [`Escrow::adjust_milestone_amounts`]'s no-op rule.
    /// `at` is the caller-supplied timestamp (on-chain: the clock
    /// sysvar).
    pub fn amend_milestones(
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
            .amend_milestones(initializer, taker, new_amounts)?;
        let after: Vec<u64> = self
            .inner
            .milestone_plan()
            .map(|p| (0..p.count()).map(|i| p.amount_at(i as usize).unwrap_or(0)).collect())
            .unwrap_or_default();
        if after != before {
            self.push_event(
                EscrowEventKind::MilestonesAmended,
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

    /// Reallocate the milestone tranche amounts by dual-signed
    /// governance (mirrors [`Escrow::reallocate_milestones`]). Emits
    /// `MilestonesReallocated` when the amounts actually change
    /// (`from == to ==` the current state — the schedule, not the
    /// lifecycle state, is what changed); a no-op re-affirmation
    /// emits nothing, paralleling
    /// [`Escrow::amend_milestones`]'s no-op rule. The event's
    /// `milestone_reallocation` field carries the before/after
    /// tranche tables (full `MAX_MILESTONES` arrays, only the
    /// plan's count entries valid), so the reallocation is
    /// auditable from the log alone — including a tranche
    /// cleared to zero, which keeps its slot in both tables.
    /// `at` is the caller-supplied timestamp (on-chain: the clock
    /// sysvar).
    pub fn reallocate_milestones(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        new_amounts: &[u64],
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        let before = self.milestone_table();
        let count = self
            .inner
            .milestone_plan()
            .map(|p| p.count())
            .unwrap_or(0);
        self.inner
            .reallocate_milestones(initializer, taker, new_amounts)?;
        let after = self.milestone_table();
        if after != before {
            self.push_event(
                EscrowEventKind::MilestonesReallocated,
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
            if let Some(last) = self.events.last_mut() {
                last.milestone_reallocation = Some((before, after, count));
            }
        }
        Ok(())
    }

    /// Append a milestone tranche to the end of the plan by dual-signed
    /// governance (mirrors [`Escrow::append_milestone_tranche`]).
    /// Emits `MilestoneTrancheAppended` (`from == to ==` the current
    /// state — the schedule, not the lifecycle state, is what
    /// changed; all amounts zero, since appending moves no funds).
    /// The appended tranche is read from the vault — the plan's last
    /// tranche after the append — so the event needs no extra
    /// field, unlike `MilestonesReallocated`'s before/after tables.
    /// A failed append emits nothing: the core call returns before
    /// any event is pushed. `at` is the caller-supplied timestamp
    /// (on-chain: the clock sysvar).
    pub fn append_milestone_tranche(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        amount: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .append_milestone_tranche(initializer, taker, amount)?;
        self.push_event(
            EscrowEventKind::MilestoneTrancheAppended,
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
        Ok(())
    }

    /// Revise the claimant roster after funding (mirrors
    /// [`Escrow::amend_claimant_roster`]). Emits
    /// `ClaimantRosterAmended` (`from == to ==` the current state —
    /// the roster, not the lifecycle state, is what changed; all
    /// amounts zero, since amending moves no funds). The amended
    /// roster is read from the vault, so the event needs no extra
    /// field. A failed amendment emits nothing: the core call
    /// returns before any event is pushed. `at` is the
    /// caller-supplied timestamp (on-chain: the clock sysvar).
    pub fn amend_claimant_roster(
        &mut self,
        initializer: [u8; 32],
        new_legs: &[([u8; 32], u16)],
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.amend_claimant_roster(initializer, new_legs)?;
        self.push_event(
            EscrowEventKind::ClaimantRosterAmended,
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
        Ok(())
    }

    /// Revise the linear vesting schedule after funding (mirrors
    /// [`Escrow::amend_vesting_schedule`]). Emits
    /// `VestingScheduleAmended` (`from == to ==` the current state
    /// — the schedule, not the lifecycle state, is what changed;
    /// all amounts zero, since amending moves no funds). The
    /// amended schedule is read from the vault, so the event
    /// needs no extra field. A failed amendment emits nothing:
    /// the core call returns before any event is pushed. `at` is
    /// the caller-supplied timestamp (on-chain: the clock sysvar)
    /// and the state machine's `now` for the anti-clawback floor.
    pub fn amend_vesting_schedule(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        schedule: VestingSchedule,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.amend_vesting_schedule(initializer, taker, schedule, at)?;
        self.push_event(
            EscrowEventKind::VestingScheduleAmended,
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
        Ok(())
    }


    /// Revise the milestone deadline table after funding (mirrors
    /// [`Escrow::amend_milestone_due_dates`]). Emits
    /// `MilestoneDueDatesAmended` (`from == to ==` the current state
    /// — the table, not the lifecycle state, is what changed;
    /// all amounts zero, since amending moves no funds). The
    /// amended table is read from the vault, so the event needs
    /// no extra field. A failed amendment emits nothing: the core
    /// call returns before any event is pushed. `at` is the
    /// caller-supplied timestamp (on-chain: the clock sysvar)
    /// and the state machine's `now` for the no-past-due rule.
    pub fn amend_milestone_due_dates(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        due_at: &[u64],
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.amend_milestone_due_dates(initializer, taker, due_at, at)?;
        self.push_event(
            EscrowEventKind::MilestoneDueDatesAmended,
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
        Ok(())
    }

    /// Revise the protocol fee rate and ceiling after funding
    /// (mirrors [`Escrow::amend_protocol_fee`]). Emits
    /// `ProtocolFeeAmended` (`from == to ==` the current state —
    /// the rate, not the lifecycle state, is what changed; all
    /// amounts zero, since amending moves no funds — only later
    /// payouts reprice). The amended rate and cap are read from
    /// the vault, so the event needs no extra field. A failed
    /// amendment emits nothing: the core call returns before any
    /// event is pushed.
    pub fn amend_protocol_fee(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        fee_bps: u16,
        fee_cap: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.amend_protocol_fee(initializer, taker, fee_bps, fee_cap)?;
        self.push_event(
            EscrowEventKind::ProtocolFeeAmended,
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
        Ok(())
    }

    /// Rotate the milestone verifier after funding (mirrors
    /// [`Escrow::rotate_milestone_verifier`]). Emits
    /// `MilestoneVerifierRotated` (`from == to ==` the current
    /// state — the gatekeeper, not the lifecycle state, is what
    /// changed; all amounts zero, since rotating moves no funds
    /// — only later attestation checks read the new key). The
    /// new verifier is read from the vault, so the event needs
    /// no extra field. A failed rotation emits nothing: the core
    /// call returns before any event is pushed — and unlike
    /// [`IndexedEscrow::rotate_arbiter`]'s no-op silence, there
    /// is no silent case here: the core call rejects a
    /// same-verifier rotation outright, so every success is a
    /// real change and every success emits.
    pub fn rotate_milestone_verifier(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        new_verifier: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .rotate_milestone_verifier(initializer, taker, new_verifier)?;
        self.push_event(
            EscrowEventKind::MilestoneVerifierRotated,
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
        Ok(())
    }

    /// Revise the arbiter adjudication fee after funding (mirrors
    /// [`Escrow::amend_arbiter_fee`]). Emits `ArbiterFeeAmended`
    /// (`from == to ==` the current state — the fee, not the
    /// lifecycle state, is what changed; all amounts zero, since
    /// amending moves no funds — only later dispute settlements
    /// price against the new fee). The amended fee legs are read
    /// from the vault, so the event needs no extra field. A failed
    /// amendment emits nothing: the core call returns before any
    /// event is pushed.
    pub fn amend_arbiter_fee(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        flat_lamports: u64,
        fee_bps: u16,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_arbiter_fee(initializer, taker, flat_lamports, fee_bps)?;
        self.push_event(
            EscrowEventKind::ArbiterFeeAmended,
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
        Ok(())
    }

    /// Revise the slash-appeal window after funding (mirrors
    /// [`Escrow::amend_appeal_window`]). Emits `AppealWindowAmended`
    /// (`from == to ==` the current state — the window, not the
    /// lifecycle state, is what changed; all amounts zero, since
    /// amending moves no funds — only slashes executed after the
    /// amendment stamp their appeal deadline from the new window).
    /// The amended window is read from the vault, so the event
    /// needs no extra field. A failed amendment emits nothing:
    /// the core call returns before any event is pushed.
    pub fn amend_appeal_window(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        window_secs: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_appeal_window(initializer, taker, window_secs)?;
        self.push_event(
            EscrowEventKind::AppealWindowAmended,
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
        Ok(())
    }

    /// Revise the tiered slash ladder after funding (mirrors
    /// [`Escrow::amend_slash_ladder`]). Emits `SlashLadderAmended`
    /// (`from == to ==` the current state — the ladder, not the
    /// lifecycle state, is what changed; all amounts zero, since
    /// amending moves no funds — only slashes executed after the
    /// amendment price from the amended future rungs). The
    /// amended ladder is read from the vault, so the event needs
    /// no extra field. A failed amendment emits nothing: the
    /// core call returns before any event is pushed. `at` doubles
    /// as the core call's `now` — a future rung backdated before
    /// the amendment time is refused, so the event timestamp and
    /// the validation clock agree.
    pub fn amend_slash_ladder(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        new_rungs: &[(u64, u16)],
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_slash_ladder(initializer, taker, new_rungs, at)?;
        self.push_event(
            EscrowEventKind::SlashLadderAmended,
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
        Ok(())
    }

    /// Revise the slash-appeal bond after funding (mirrors
    /// [`Escrow::amend_appeal_bond`]). Emits `AppealBondAmended`
    /// (`from == to ==` the current state — the bond, not the
    /// lifecycle state, is what changed; all amounts zero, since
    /// amending moves no funds — only appeals filed after the
    /// amendment lock the new bond). The amended bond is read
    /// from the vault, so the event needs no extra field. A
    /// failed amendment emits nothing: the core call returns
    /// before any event is pushed.
    pub fn amend_appeal_bond(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        bond: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.amend_appeal_bond(initializer, taker, bond)?;
        self.push_event(
            EscrowEventKind::AppealBondAmended,
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
        Ok(())
    }

    /// Revise the expiry grace period after funding (mirrors
    /// [`Escrow::amend_grace_period`]). Emits `GracePeriodAmended`
    /// (`from == to ==` the current state — the grace period, not
    /// the lifecycle state, is what changed; all amounts zero,
    /// since amending moves no funds — only expiry determinations
    /// after the amendment follow the new grace). The amended
    /// grace period is read from the vault, so the event needs no
    /// extra field. A failed amendment emits nothing: the core
    /// call returns before any event is pushed.
    pub fn amend_grace_period(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        grace_secs: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_grace_period(initializer, taker, grace_secs)?;
        self.push_event(
            EscrowEventKind::GracePeriodAmended,
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
        Ok(())
    }

    /// Revise the dispute-evidence disclosure deadline after
    /// funding (mirrors [`Escrow::amend_evidence_deadline`]).
    /// Emits `EvidenceDeadlineAmended` (`from == to ==` the
    /// current state — the deadline, not the lifecycle state, is
    /// what changed; all amounts zero, since amending moves no
    /// funds — only disputes escalated after the amendment
    /// measure their window from the new deadline). The amended
    /// deadline is read from the vault, so the event needs no
    /// extra field. A failed amendment emits nothing: the core
    /// call returns before any event is pushed.
    pub fn amend_evidence_deadline(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        deadline_secs: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_evidence_deadline(initializer, taker, deadline_secs)?;
        self.push_event(
            EscrowEventKind::EvidenceDeadlineAmended,
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
        Ok(())
    }


    /// Revise the pre-agreed arbitration default judgment's deadline
    /// after funding (mirrors
    /// [`Escrow::amend_arbitration_deadline`]). Emits
    /// `ArbitrationDeadlineAmended` (`from == to ==` the current
    /// state — the deadline, not the lifecycle state, is what
    /// changed; all amounts zero, since amending moves no funds —
    /// only disputes escalated after the amendment measure their
    /// default-judgment window from the new deadline). The amended
    /// deadline is read from the vault, so the event needs no
    /// extra field. A failed amendment emits nothing: the core
    /// call returns before any event is pushed.
    pub fn amend_arbitration_deadline(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        deadline_secs: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_arbitration_deadline(initializer, taker, deadline_secs)?;
        self.push_event(
            EscrowEventKind::ArbitrationDeadlineAmended,
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
        Ok(())
    }

    /// Revise the per-taker claim cooldown after funding (mirrors
    /// [`Escrow::amend_claim_cooldown`]). Emits
    /// `ClaimCooldownAmended` (`from == to ==` the current state —
    /// the cooldown, not the lifecycle state, is what changed; all
    /// amounts zero, since amending moves no funds — the next
    /// claim's eligibility is recomputed from the new cooldown,
    /// since `last_claim_slot` is untouched). The amended cooldown
    /// is read from the vault, so the event needs no extra field.
    /// A failed amendment emits nothing: the core call returns
    /// before any event is pushed.
    pub fn amend_claim_cooldown(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        slots: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_claim_cooldown(initializer, taker, slots)?;
        self.push_event(
            EscrowEventKind::ClaimCooldownAmended,
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
        Ok(())
    }

    /// Revise the delivery-confirmation deadline after funding (mirrors
    /// [`Escrow::amend_delivery_deadline`]). Emits
    /// `DeliveryDeadlineAmended` (`from == to ==` the current state —
    /// the deadline, not the lifecycle state, is what changed; all
    /// amounts zero, since amending moves no funds — confirmations
    /// after the amendment are judged against the new deadline,
    /// while an already-confirmed delivery keeps its first-won
    /// stamp). The amended deadline is read from the vault, so the
    /// event needs no extra field. A failed amendment emits
    /// nothing: the core call returns before any event is pushed.
    pub fn amend_delivery_deadline(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        deadline_at: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_delivery_deadline(initializer, taker, deadline_at)?;
        self.push_event(
            EscrowEventKind::DeliveryDeadlineAmended,
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
        Ok(())
    }

    /// Revise the late-delivery penalty rate after funding (mirrors
    /// [`Escrow::amend_late_delivery_penalty_bps`]). Emits
    /// `LateDeliveryPenaltyAmended` (`from == to ==` the current
    /// state — the rate, not the lifecycle state, is what changed;
    /// all amounts zero, since amending moves no funds — a
    /// late-stamped but not-yet-released delivery reprices at the
    /// new rate, while amounts already released and penalties
    /// already banked are never restated). The amended rate is read
    /// from the vault, so the event needs no extra field. A failed
    /// amendment emits nothing: the core call returns before any
    /// event is pushed.
    pub fn amend_late_delivery_penalty_bps(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        bps: u16,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_late_delivery_penalty_bps(initializer, taker, bps)?;
        self.push_event(
            EscrowEventKind::LateDeliveryPenaltyAmended,
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
        Ok(())
    }

    /// Revise the release cooling window after funding (mirrors
    /// [`Escrow::amend_release_cooling`]). Emits
    /// `ReleaseCoolingAmended` (`from == to ==` the current
    /// state — the window, not the lifecycle state, is what
    /// changed; all amounts zero, since amending moves no funds —
    /// a live announced intent is re-measured against the new
    /// window, while a vetoed intent stays vetoed). The amended
    /// window is read from the vault, so the event needs no extra
    /// field. A failed amendment emits nothing: the core call
    /// returns before any event is pushed.
    pub fn amend_release_cooling(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        cooling_secs: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_release_cooling(initializer, taker, cooling_secs)?;
        self.push_event(
            EscrowEventKind::ReleaseCoolingAmended,
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
        Ok(())
    }

    /// Revise one milestone tranche's claim deadline after funding
    /// (mirrors [`Escrow::amend_milestone_claim_deadline`]). Emits
    /// `MilestoneClaimDeadlineAmended` (`from == to ==` the current
    /// state — the deadline, not the lifecycle state, is what
    /// changed; all amounts zero, since amending moves no funds —
    /// the claim gate re-reads the deadline live, while a tranche
    /// already claimed or skipped keeps its settlement). The
    /// amended deadline is read from the vault, so the event needs
    /// no extra field. A failed amendment emits nothing: the core
    /// call returns before any event is pushed.
    pub fn amend_milestone_claim_deadline(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        tranche: u8,
        deadline_secs: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_milestone_claim_deadline(initializer, taker, tranche, deadline_secs)?;
        self.push_event(
            EscrowEventKind::MilestoneClaimDeadlineAmended,
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
        Ok(())
    }

    /// Revise the per-extension expiry-increase cap after funding
    /// (mirrors [`Escrow::amend_max_extension_secs`]). Emits
    /// `MaxExtensionAmended` (`from == to ==` the current
    /// state — the cap, not the lifecycle state, is what
    /// changed; all amounts zero, since amending moves no funds —
    /// the next extension is judged against the live cap, while
    /// extensions already made keep their deadline and count).
    /// The amended cap is read from the vault, so the event needs
    /// no extra field. A failed amendment emits nothing: the core
    /// call returns before any event is pushed.
    pub fn amend_max_extension_secs(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        max_extension_secs: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_max_extension_secs(initializer, taker, max_extension_secs)?;
        self.push_event(
            EscrowEventKind::MaxExtensionAmended,
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
        Ok(())
    }

    /// Revise the absolute timelock after funding (mirrors
    /// [`Escrow::amend_timelock`]). Emits `TimelockAmended`
    /// (`from == to ==` the current state — the lock, not the
    /// lifecycle state, is what changed; all amounts zero, since
    /// amending moves no funds — the payout gates re-read the
    /// lock live, while amounts already released are never
    /// restated). The amended lock is read from the vault, so the
    /// event needs no extra field. A failed amendment emits
    /// nothing: the core call returns before any event is pushed.
    pub fn amend_timelock(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        unlock_at: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_timelock(initializer, taker, unlock_at)?;
        self.push_event(
            EscrowEventKind::TimelockAmended,
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
        Ok(())
    }

    /// Revise the relative timelock after funding (mirrors
    /// [`Escrow::amend_relative_timelock`]). Emits
    /// `RelativeTimelockAmended` (`from == to ==` the current state
    /// — the window, not the lifecycle state, is what changed; all
    /// amounts zero, since amending moves no funds — the payout
    /// gates re-read the window live against the unchanged
    /// `fund_at` anchor, while amounts already released are never
    /// restated). The amended window is read from the vault, so the
    /// event needs no extra field. A failed amendment emits
    /// nothing: the core call returns before any event is pushed.
    pub fn amend_relative_timelock(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        secs: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_relative_timelock(initializer, taker, secs)?;
        self.push_event(
            EscrowEventKind::RelativeTimelockAmended,
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
        Ok(())
    }

    /// Revise the slot timelock after funding (mirrors
    /// [`Escrow::amend_slot_timelock`]). Emits
    /// `SlotTimelockAmended` (`from == to ==` the current state
    /// — the window, not the lifecycle state, is what changed; all
    /// amounts zero, since amending moves no funds — the slot
    /// gates re-read the window live against the unchanged
    /// `fund_slot` anchor, while amounts already released are never
    /// restated). The amended window is read from the vault, so the
    /// event needs no extra field. A failed amendment emits
    /// nothing: the core call returns before any event is pushed.
    pub fn amend_slot_timelock(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        slots: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_slot_timelock(initializer, taker, slots)?;
        self.push_event(
            EscrowEventKind::SlotTimelockAmended,
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
        Ok(())
    }

    /// Revise the unclaimed-rent sweep grace period after funding (mirrors
    /// [`Escrow::amend_rent_sweep_grace`]). Emits
    /// `RentSweepGraceAmended` (`from == to ==` the current state
    /// — the grace, not the lifecycle state, is what changed; all
    /// amounts zero, since amending moves no funds — the sweep
    /// gate re-reads the grace live against the unchanged
    /// `terminal_at` stamp, while a sweep already performed is
    /// never undone). The amended grace is read from the vault, so
    /// the event needs no extra field. A failed amendment emits
    /// nothing: the core call returns before any event is pushed.
    pub fn amend_rent_sweep_grace(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        grace_secs: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner
            .amend_rent_sweep_grace(initializer, taker, grace_secs)?;
        self.push_event(
            EscrowEventKind::RentSweepGraceAmended,
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
        Ok(())
    }

    /// Revise the tiered protocol-fee schedule after funding (mirrors
    /// [`Escrow::amend_fee_schedule`]). Emits
    /// `FeeScheduleAmended` (`from == to ==` the current state
    /// — the schedule, not the lifecycle state, is what changed; all
    /// amounts zero, since amending moves no funds — later payouts
    /// reprice live from the amended schedule, while fees already
    /// charged or withdrawn are never restated). The amended
    /// schedule is read from the vault, so the event needs no extra
    /// field. A failed amendment emits nothing: the core call returns
    /// before any event is pushed.
    pub fn amend_fee_schedule(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        tiers: &[(u64, u16)],
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.amend_fee_schedule(initializer, taker, tiers)?;
        self.push_event(
            EscrowEventKind::FeeScheduleAmended,
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
        Ok(())
    }

    /// Revise the streaming fee rate after funding (mirrors
    /// [`Escrow::amend_streaming_fee`]). Emits
    /// `StreamingFeeRateAmended` (`from == to ==` the current state
    /// — the rate, not the lifecycle state, is what changed; all
    /// amounts zero, since amending moves no funds — the charge
    /// gate re-reads the live rate against the unchanged `fund_at`
    /// anchor, while fees already charged are never clawed back).
    /// The amended rate is read from the vault, so the event needs
    /// no extra field. A failed amendment emits nothing: the core
    /// call returns before any event is pushed.
    pub fn amend_streaming_fee(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        rate: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.amend_streaming_fee(initializer, taker, rate)?;
        self.push_event(
            EscrowEventKind::StreamingFeeRateAmended,
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
        Ok(())
    }

    /// The live milestone tranche table as a fixed
    /// `MAX_MILESTONES` array (entries past the plan's count are
    /// zero): the shape the `MilestonesReallocated` event carries
    /// on both sides of a reallocation, so the before/after
    /// comparison is a plain array comparison.
    fn milestone_table(&self) -> [u64; crate::MAX_MILESTONES] {
        let mut table = [0u64; crate::MAX_MILESTONES];
        if let Some(plan) = self.inner.milestone_plan() {
            for i in 0..plan.count() as usize {
                table[i] = plan.amount_at(i).unwrap_or(0);
            }
        }
        table
    }

    /// Stage a delayed-governance action (mirrors
    /// [`Escrow::propose_governance`](crate::Escrow::propose_governance)).
    /// Emits `GovernanceProposed` (`from == to ==` the current state
    /// — the proposal itself moves nothing). `at` is the
    /// caller-supplied timestamp (on-chain: the clock sysvar) and
    /// doubles as the proposal's `now`.
    pub fn propose_governance(
        &mut self,
        proposer: [u8; 32],
        action: crate::GovernanceAction,
        at: u64,
    ) -> Result<(), EscrowError> {
        let state = self.inner.state();
        self.inner.propose_governance(proposer, action, at)?;
        self.push_event(
            EscrowEventKind::GovernanceProposed,
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

    /// Apply the live delayed-governance proposal (mirrors
    /// [`Escrow::execute_governance`](crate::Escrow::execute_governance)).
    /// Emits `GovernanceExecuted` (`from == to ==` the current state
    /// — a config change, not a lifecycle move). `at` is the
    /// caller-supplied timestamp (on-chain: the clock sysvar) and
    /// doubles as the execution's `now`.
    pub fn execute_governance(
        &mut self,
        executor: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let state = self.inner.state();
        self.inner.execute_governance(executor, at)?;
        self.push_event(
            EscrowEventKind::GovernanceExecuted,
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

    /// Drop the live delayed-governance proposal (mirrors
    /// [`Escrow::cancel_governance`](crate::Escrow::cancel_governance)).
    /// Emits `GovernanceCancelled` (`from == to ==` the current state
    /// — the proposal is dropped, the config untouched). `at` is the
    /// caller-supplied timestamp (on-chain: the clock sysvar).
    pub fn cancel_governance(
        &mut self,
        canceller: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let state = self.inner.state();
        self.inner.cancel_governance(canceller)?;
        self.push_event(
            EscrowEventKind::GovernanceCancelled,
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

    /// Re-split the subscription per-period amounts by dual-signed
    /// governance (mirrors [`Escrow::adjust_period_amounts`]). Emits    /// `SubscriptionAmountsAdjusted` when the amounts actually change
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

    /// Confirm delivery (mirrors [`Escrow::confirm_delivery`], AV-203
    /// — the taker confirms receipt). Emits
    /// [`EscrowEventKind::DeliveryConfirmed`] only on the first
    /// confirmation (`from == to ==` the current state, amounts
    /// [`EventAmounts::none`], the actor is the taker); repeat
    /// confirmations are idempotent no-ops that emit nothing
    /// (mirroring `confirm_milestone`'s emission rule). Failed
    /// confirmations emit nothing. `at` is the event timestamp
    /// and, via [`Escrow::confirm_delivery_at`] (AV-216), the
    /// confirmation time the delivery deadline is measured
    /// against — a post-deadline indexed confirmation records the
    /// escrow late exactly like a direct timed confirmation.
    pub fn confirm_delivery(
        &mut self,
        authority: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        let confirmed_before = self.inner.delivery_confirmed();
        self.inner.confirm_delivery_at(authority, at)?;
        if !confirmed_before && self.inner.delivery_confirmed() {
            let state = self.inner.state();
            self.push_event(
                EscrowEventKind::DeliveryConfirmed,
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
    /// `now` (AV-27 timelock gate). AV-225: a vested tranche claimed
    /// past its deadline emits `MilestoneClaimExpired` instead
    /// (`from == to ==` the current state, `amounts.refund` the
    /// expired tranche, the tranche index on the event) and still
    /// returns the inner `MilestoneClaimExpired` error — the
    /// expiry is a real state move audited as an event, not a
    /// silent refusal.
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
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        // The tranche amount is fixed by the plan; read it before
        // the call so the expiry path can audit it. A successful
        // release implies a configured plan and an in-range index,
        // so the fallback is unreachable on the event path.
        let tranche = self
            .inner
            .milestone_plan()
            .and_then(|p| p.amount_at(index as usize))
            .unwrap_or(0);
        let result = self
            .inner
            .release_milestone(authority, at, index, mint, payout_to);
        let (payout, fee) = match result {
            Ok(v) => v,
            Err(EscrowError::MilestoneClaimExpired) => {
                // AV-225: the inner call already returned the
                // tranche to remainder (skipped bit + `skipped`
                // counter), so this is a real state move, not a
                // plain refusal — the auto-recovery stays consumed
                // like on success, and the expiry is audited
                // before the error is reported.
                self.emit_auto_unpause(pause_state, at, auto_unpaused);
                let state = self.inner.state();
                self.push_event(
                    EscrowEventKind::MilestoneClaimExpired,
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
                if let Some(last) = self.events.last_mut() {
                    last.milestone_claim_expired = Some(index);
                }
                return self.map_reentrant(Err(EscrowError::MilestoneClaimExpired), at);
            }
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
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

    /// Release part of a milestone's tranche to the taker (mirrors
    /// [`Escrow::release_milestone_partial`]). Emits
    /// `MilestonePartiallyClaimed` with the slice's gross in
    /// `amounts.payout` (net payout + fee); the final slice carries
    /// `to == Released`, like `MilestoneReleased`. Returns
    /// `(taker_payout, fee)` like the inner method. `at` is both
    /// the event timestamp and the state machine's `now` (AV-27
    /// timelock gate). AV-225: a slice claimed past the tranche's
    /// deadline emits `MilestoneClaimExpired` instead (`from == to
    /// ==` the current state, `amounts.refund` the tranche's
    /// unclaimed remainder — the already-claimed slices stay
    /// paid — the tranche index on the event) and still returns
    /// the inner `MilestoneClaimExpired` error, mirroring
    /// [`IndexedEscrow::release_milestone`].
    pub fn release_milestone_partial(
        &mut self,
        authority: [u8; 32],
        index: u8,
        amount: u64,
        mint: Option<[u8; 32]>,
        payout_to: [u8; 32],
        at: u64,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        // The unclaimed remainder is fixed by the plan and the
        // ledger; read it before the call so the expiry path can
        // audit it. A successful slice implies a configured plan
        // and an in-range index, so the fallback is unreachable
        // on the event path.
        let remaining = self
            .inner
            .milestone_partial_remaining_at(index as usize)
            .unwrap_or(0);
        let result = self
            .inner
            .release_milestone_partial(authority, at, index, amount, mint, payout_to);
        let (payout, fee) = match result {
            Ok(v) => v,
            Err(EscrowError::MilestoneClaimExpired) => {
                // AV-225 / AV-229: the inner call already returned
                // the remainder to refund (skipped bit + `skipped`
                // counter), so this is a real state move, not a
                // plain refusal — the auto-recovery stays consumed
                // like on success, and the expiry is audited
                // before the error is reported.
                self.emit_auto_unpause(pause_state, at, auto_unpaused);
                let state = self.inner.state();
                self.push_event(
                    EscrowEventKind::MilestoneClaimExpired,
                    state,
                    state,
                    EventAmounts::refund(remaining),
                    at,
                    None,
                    None,
                    None,
                    None,
                    Some(authority),
                );
                if let Some(last) = self.events.last_mut() {
                    last.milestone_claim_expired = Some(index);
                }
                return self.map_reentrant(Err(EscrowError::MilestoneClaimExpired), at);
            }
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        // `payout + fee` is the slice's gross (`<= tranche`); no
        // overflow possible.
        self.push_event(
            EscrowEventKind::MilestonePartiallyClaimed,
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
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self
            .inner
            .release_period(authority, at, index, mint, payout_to);
        let (payout, fee) = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
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

    /// Crank a due subscription period permissionlessly (mirrors
    /// [`Escrow::crank_release_period`], AV-160; the subscription
    /// analogue of `IndexedEscrow::crank_expired`). Emits
    /// `SubscriptionPeriodReleased` with the gross per-period amount
    /// in `amounts.payout` — `from == Funded`, `to == Funded` — or
    /// `to == Released` on the last period. The event's `actor` is
    /// the cranker's key (the caller is marked as the crank), so the
    /// indexer distinguishes crank-driven period releases from the
    /// initializer's push path. Returns `(taker_payout, fee)` like the
    /// inner method. `at` is both the event timestamp and the state
    /// machine's `now` (due-date + AV-27 timelock gates).
    pub fn crank_release_period(
        &mut self,
        caller: [u8; 32],
        at: u64,
        mint: Option<[u8; 32]>,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self.inner.crank_release_period(caller, at, mint);
        let (payout, fee) = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
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
            Some(caller),
            Some(caller),
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

    /// Restore a skipped milestone to the claimable schedule
    /// (mirrors [`Escrow::unskip_milestone`]). Emits
    /// `MilestoneUnskipped` (`from == to ==` the current state —
    /// the schedule, not the lifecycle state, is what changed;
    /// all amounts zero, since unskipping moves no funds). A
    /// failed restoration emits nothing: the core call returns
    /// before any event is pushed.
    pub fn unskip_milestone(
        &mut self,
        initializer: [u8; 32],
        taker: [u8; 32],
        index: u8,
        at: u64,
    ) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.unskip_milestone(initializer, taker, index)?;
        self.push_event(
            EscrowEventKind::MilestoneUnskipped,
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

    /// Sweep unclaimed rent from a terminal vault (mirrors
    /// [`Escrow::sweep_unclaimed_rent`](crate::Escrow::sweep_unclaimed_rent),
    /// AV-139). Permissionless — the caller is recorded as the event
    /// actor. Returns the swept rent-exempt lamports.
    pub fn sweep_unclaimed_rent(
        &mut self,
        caller: [u8; 32],
        at: u64,
    ) -> Result<u64, EscrowError> {
        let from = self.inner.state();
        let result = self.inner.sweep_unclaimed_rent(caller, at);
        let rent = self.map_reentrant(result, at)?;
        self.push_event(
            EscrowEventKind::RentSwept,
            from,
            self.inner.state(),
            EventAmounts::close(rent),
            at,
            None,
            None,
            None,
            None,
            Some(caller),
        );
        Ok(rent)
    }

    /// Extract accumulated protocol fees to the protocol side (mirrors
    /// [`Escrow::withdraw_protocol_fees`](crate::Escrow::withdraw_protocol_fees),
    /// AV-174). The caller must be the pinned fee recipient or the
    /// initializer (`Unauthorized` otherwise); terminal states,
    /// a paused escrow, and a reentrant entry are refused by the inner
    /// method's guard chain. Returns the resolved
    /// [`FeeWithdrawal`](crate::FeeWithdrawal) — the destination the
    /// executor routes the fee to (`None` means the program-level fee
    /// account) and the remaining withdrawable headroom.
    ///
    /// Emits `FeeWithdrawn` with `from == to ==` the current state
    /// (a treasury operation, not a lifecycle move);
    /// `amounts.fee` is the withdrawn amount, `amounts.refund` the
    /// remaining withdrawable. The actor is the withdrawing authority.
    pub fn withdraw_protocol_fees(
        &mut self,
        authority: [u8; 32],
        amount: u64,
        at: u64,
    ) -> Result<crate::FeeWithdrawal, EscrowError> {
        let from = self.inner.state();
        let result = self.inner.withdraw_protocol_fees(authority, amount);
        let withdrawal = self.map_reentrant(result, at)?;
        self.push_event(
            EscrowEventKind::FeeWithdrawn,
            from,
            self.inner.state(),
            EventAmounts::fee_withdrawn(withdrawal.amount, withdrawal.withdrawable),
            at,
            None,
            None,
            None,
            None,
            Some(authority),
        );
        Ok(withdrawal)
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
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self
            .inner
            .split_escrow(initializer, taker, amounts, config, at);
        let children = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
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
    /// AV-126: on a ladder escrow the event's `slash_ladder_index`
    /// carries the rung this slash consumed (the pre-slash cursor —
    /// the state machine advances the cursor during the slash, so it
    /// is captured before the call); `None` on a single-level slash.
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
        // AV-126: the rung this slash is about to consume — the
        // pre-slash cursor. Captured before the state machine runs
        // because a successful slash advances it.
        let consumed_rung = self.inner.slash_ladder_index();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self.inner.slash(authority, amount, mint, at);
        let slashed = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
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
        // AV-126: stamp the consumed rung on the Slashed event after
        // the push (the appeal_outcome / split_children precedent) —
        // never a push_event parameter. Only ladder escrows carry a
        // rung; single-level slashes stay `None`.
        if self.inner.slash_ladder().is_some() {
            self.events
                .last_mut()
                .expect("Slashed event just pushed")
                .slash_ladder_index = Some(consumed_rung);
        }
        Ok(slashed)
    }

    /// Opt in to the slash-appeal window (mirrors
    /// [`Escrow::with_appeal_window`], AV-86). Configuration: emits no
    /// event.
    pub fn with_appeal_window(mut self, window_secs: u64) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_appeal_window(window_secs)?;
        Ok(self)
    }

    /// Opt in to the appeal bond (mirrors
    /// [`Escrow::with_appeal_bond`], AV-103). Configuration: emits no
    /// event.
    pub fn with_appeal_bond(mut self, bond: u64) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_appeal_bond(bond)?;
        Ok(self)
    }

    /// File an appeal against the executed slash (AV-86; mirrors
    /// [`Escrow::file_appeal`]): `Funded -> Funded` — the taker contests
    /// the penalty inside the opt-in window, opening the arbiter
    /// panel's review. Emits [`EscrowEventKind::AppealFiled`] (from ==
    /// to == `Funded`, amounts zero — a locked AV-103 bond is read
    /// from the vault's `appeal_bond_paid`, not the event) with the
    /// taker as the actor. On executor failure the state machine rolls
    /// back and nothing is emitted, like every other failed transition.
    /// `at` is both the event timestamp and the state machine's `now`.
    /// Returns the locked bond (`0` when no bond was configured) so the
    /// caller can size the taker's bond transfer into the vault.
    ///
    /// [`Escrow::file_appeal`]: super::Escrow::file_appeal
    pub fn file_appeal(&mut self, taker: [u8; 32], at: u64) -> Result<u64, EscrowError> {
        let from = self.inner.state();
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let locked = match self.inner.file_appeal(taker, at) {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return Err(e);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
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
        Ok(locked)
    }

    /// Cast a panel member's review vote on the filed slash appeal
    /// (AV-86; mirrors [`Escrow::review_appeal`]). A non-resolving vote
    /// emits nothing — the ballot is still open, so there is no
    /// no-op-case event. The M-th matching vote resolves the appeal and
    /// emits [`EscrowEventKind::AppealResolved`] (from == to ==
    /// `Funded`; on overturn `amounts.payout` is the refunded penalty
    /// plus the refunded appeal bond — the taker's full restitution, no
    /// fee; on uphold `amounts.penalty` is the bond forfeited to the
    /// initializer) with the voting member as the actor, and the
    /// verdict is stamped on the event's `appeal_outcome` field.
    /// Returns `Ok(None)` while the ballot is open, or
    /// `Ok(Some((outcome, penalty_refunded, bond_moved)))` on
    /// resolution — `penalty_refunded` is the penalty returned to the
    /// taker (`0` on uphold), `bond_moved` the locked appeal bond (`0`
    /// when none was configured; forfeited to the initializer on
    /// uphold, refunded to the taker on overturn) so the caller can
    /// size both transfers. `at` is the event timestamp; the state
    /// machine itself is not time-gated here (the window gates the
    /// filing, not the review).
    ///
    /// [`Escrow::review_appeal`]: super::Escrow::review_appeal
    pub fn review_appeal(
        &mut self,
        member: [u8; 32],
        uphold: bool,
        at: u64,
    ) -> Result<Option<(AppealOutcome, u64, u64)>, EscrowError> {
        let from = self.inner.state();
        // AV-36: see `fund` — a rejected reentrant entry emits
        // `ReentryRejected`.
        let result = self.inner.review_appeal(member, uphold);
        let resolved = self.map_reentrant(result, at)?;
        if let Some((outcome, penalty_refunded, bond_moved)) = resolved {
            let amounts = match outcome {
                AppealOutcome::Overturned => {
                    EventAmounts::appeal_overturn(penalty_refunded, bond_moved)
                }
                AppealOutcome::Upheld => EventAmounts::appeal_bond_forfeited(bond_moved),
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

    /// Sweep a filed slash appeal whose window lapsed unresolved
    /// (AV-103; mirrors [`Escrow::expire_appeal`]): `Funded -> Funded`
    /// — the appeal moves terminally to `Expired`, the slash stands,
    /// and the locked appeal bond (if any) is forfeited to the
    /// initializer. Permissionless: anyone may crank a lapsed appeal.
    /// Emits [`EscrowEventKind::AppealExpired`] (from == to ==
    /// `Funded`, `amounts.penalty` = the forfeited bond) with the
    /// caller as the actor. On executor failure the state machine
    /// rolls back and nothing is emitted, like every other failed
    /// transition. `at` is both the event timestamp and the state
    /// machine's `now`. Returns the forfeited bond (`0` when no bond
    /// was locked) so the caller can size the transfer to the
    /// initializer.
    ///
    /// [`Escrow::expire_appeal`]: super::Escrow::expire_appeal
    pub fn expire_appeal(&mut self, caller: [u8; 32], at: u64) -> Result<u64, EscrowError> {
        let from = self.inner.state();
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let forfeited = match self.inner.expire_appeal(caller, at) {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return Err(e);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
        self.push_event(
            EscrowEventKind::AppealExpired,
            from,
            self.inner.state(),
            EventAmounts::appeal_bond_forfeited(forfeited),
            at,
            None,
            None,
            None,
            None,
            Some(caller),
        );
        Ok(forfeited)
    }

    /// Grant an operator a bounded slice of the caller's authority
    /// (AV-104; mirrors [`Escrow::delegate_authority`]). Emits
    /// [`EscrowEventKind::DelegationGranted`] (`from == to ==` the
    /// current state, amounts zero, actor = the granting party) on an
    /// actual change; the identical re-grant is an idempotent no-op
    /// that emits nothing (the inner machine's no-op rule). On
    /// failure the state machine rolls back and nothing is emitted,
    /// like every other failed transition. `at` is the caller-supplied
    /// event timestamp.
    ///
    /// [`Escrow::delegate_authority`]: super::Escrow::delegate_authority
    pub fn delegate_authority(
        &mut self,
        caller: [u8; 32],
        delegate: [u8; 32],
        scopes: u32,
        at: u64,
    ) -> Result<(), EscrowError> {
        let before = self.inner.delegation();
        self.inner.delegate_authority(caller, delegate, scopes)?;
        if self.inner.delegation() != before {
            let state = self.inner.state();
            self.push_event(
                EscrowEventKind::DelegationGranted,
                state,
                state,
                EventAmounts::none(),
                at,
                None,
                None,
                None,
                None,
                Some(caller),
            );
        }
        Ok(())
    }

    /// Revoke the live operator grant (AV-104; mirrors
    /// [`Escrow::revoke_delegation`]). Emits
    /// [`EscrowEventKind::DelegationRevoked`] (`from == to ==` the
    /// current state, amounts zero, actor = the revoking party).
    /// Always emitted on success: the inner call fails unless a grant
    /// was live, so there is no no-op case. `at` is the
    /// caller-supplied event timestamp.
    ///
    /// [`Escrow::revoke_delegation`]: super::Escrow::revoke_delegation
    pub fn revoke_delegation(&mut self, caller: [u8; 32], at: u64) -> Result<(), EscrowError> {
        self.inner.revoke_delegation(caller)?;
        let state = self.inner.state();
        self.push_event(
            EscrowEventKind::DelegationRevoked,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(caller),
        );
        Ok(())
    }

    /// Link two indexed escrows as an atomic swap pair (AV-105;
    /// mirrors [`link_swap`](super::link_swap)). On success each leg
    /// emits [`EscrowEventKind::SwapLinked`] (`from == to ==` the
    /// current state — `Uninitialized` — amounts zero, actor = the
    /// linking party) in deterministic A→B order. On failure the
    /// state machine rolls back and nothing is emitted, like every
    /// other failed transition. `at` is the caller-supplied event
    /// timestamp.
    ///
    /// [`link_swap`](super::link_swap): super::link_swap
    #[allow(clippy::too_many_arguments)]
    pub fn link_swap_pair(
        a: &mut IndexedEscrow,
        b: &mut IndexedEscrow,
        caller: [u8; 32],
        escrow_id_a: [u8; 32],
        escrow_id_b: [u8; 32],
        amount_a: u64,
        amount_b: u64,
        at: u64,
    ) -> Result<(), EscrowError> {
        super::link_swap(
            &mut a.inner,
            &mut b.inner,
            caller,
            escrow_id_a,
            escrow_id_b,
            amount_a,
            amount_b,
        )?;
        for escrow in [a, b] {
            let state = escrow.inner.state();
            escrow.push_event(
                EscrowEventKind::SwapLinked,
                state,
                state,
                EventAmounts::none(),
                at,
                None,
                None,
                None,
                None,
                Some(caller),
            );
        }
        Ok(())
    }

    /// Link an upstream escrow to a downstream escrow as a funding
    /// chain (AV-223; mirrors [`link_chain`](super::link_chain)).
    /// On success the upstream leg emits
    /// [`EscrowEventKind::ChainLinked`] (`from == to ==` the current
    /// state — `Uninitialized` — amounts zero, actor = the linking
    /// party). On failure the state machine rolls back and nothing
    /// is emitted, like every other failed transition. `at` is the
    /// caller-supplied event timestamp.
    pub fn link_chain_pair(
        a: &mut IndexedEscrow,
        caller: [u8; 32],
        escrow_id_a: [u8; 32],
        escrow_id_b: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        super::link_chain(&mut a.inner, caller, escrow_id_a, escrow_id_b)?;
        let state = a.inner.state();
        a.push_event(
            EscrowEventKind::ChainLinked,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(caller),
        );
        Ok(())
    }

    /// Record that this escrow's funding chain broke (AV-223): call
    /// after a terminal cancel / expiry / dispute settlement cleared
    /// the link (see [`break_chain`](super::break_chain)). Emits
    /// [`EscrowEventKind::ChainBroken`] (`from == to ==` the terminal
    /// state, amounts zero, actor = the party whose terminal action
    /// broke the chain). The downstream id is read from the vault by
    /// indexers — by the time this runs the link is already cleared,
    /// so the event itself is the break's ordering signal.
    pub fn emit_chain_broken(&mut self, actor: [u8; 32], at: u64) {
        let state = self.inner.state();
        self.push_event(
            EscrowEventKind::ChainBroken,
            state,
            state,
            EventAmounts::none(),
            at,
            None,
            None,
            None,
            None,
            Some(actor),
        );
    }

    /// Release both legs of a linked swap pair atomically (AV-105;
    /// mirrors [`release_swap`](super::release_swap)). On success each
    /// leg emits `Released` exactly like
    /// [`IndexedEscrow::release`] — partial releases carry
    /// `from == to == Funded`, the closing one `to == Released` —
    /// with `amounts` in the `Released` shape (`payout` = the leg's
    /// gross amount, `fee` = the AV-17 protocol fee) and the actor =
    /// that leg's initializer (the per-side authority). Events land
    /// in deterministic A→B order. Returns
    /// `(payout_a, fee_a, payout_b, fee_b)` like the inner function.
    /// On failure nothing is emitted on either leg (the two-phase
    /// run rolls back with zero event leakage). `now` doubles as the
    /// event timestamp and the state machine's clock (so the AV-27
    /// timelock gate sees the same clock the event log records).
    ///
    /// [`release_swap`](super::release_swap): super::release_swap
    /// [`IndexedEscrow::release`]: IndexedEscrow::release
    #[allow(clippy::too_many_arguments)]
    pub fn release_swap_pair(
        a: &mut IndexedEscrow,
        b: &mut IndexedEscrow,
        caller: [u8; 32],
        escrow_id_a: [u8; 32],
        escrow_id_b: [u8; 32],
        now: u64,
        amount_a: u64,
        mint_a: Option<[u8; 32]>,
        payout_to_a: [u8; 32],
        amount_b: u64,
        mint_b: Option<[u8; 32]>,
        payout_to_b: [u8; 32],
    ) -> Result<(u64, u64, u64, u64), EscrowError> {
        let (payout_a, fee_a, payout_b, fee_b) = super::release_swap(
            &mut a.inner,
            &mut b.inner,
            caller,
            escrow_id_a,
            escrow_id_b,
            now,
            amount_a,
            mint_a,
            payout_to_a,
            amount_b,
            mint_b,
            payout_to_b,
        )?;
        // `amount` is the gross payout by construction
        // (`payout + fee == amount`); it cannot overflow u64 addition.
        let from_a = EscrowState::Funded;
        a.push_event(
            EscrowEventKind::Released,
            from_a,
            a.inner.state(),
            EventAmounts::payout(amount_a, fee_a),
            now,
            None,
            None,
            None,
            None,
            Some(a.inner.initializer()),
        );
        let from_b = EscrowState::Funded;
        b.push_event(
            EscrowEventKind::Released,
            from_b,
            b.inner.state(),
            EventAmounts::payout(amount_b, fee_b),
            now,
            None,
            None,
            None,
            None,
            Some(b.inner.initializer()),
        );
        Ok((payout_a, fee_a, payout_b, fee_b))
    }

    /// Cancel both legs of a linked swap pair atomically (AV-105;
    /// mirrors [`cancel_swap`](super::cancel_swap)). On success each
    /// leg emits `Cancelled` exactly like [`IndexedEscrow::cancel`]
    /// (`from == Funded`, `to == Cancelled`,
    /// `amounts.refund` = the leg's remainder, actor = that leg's
    /// initializer) in deterministic A→B order. On failure nothing
    /// is emitted on either leg. `at` is the caller-supplied event
    /// timestamp.
    ///
    /// [`cancel_swap`](super::cancel_swap): super::cancel_swap
    /// [`IndexedEscrow::cancel`]: IndexedEscrow::cancel
    #[allow(clippy::too_many_arguments)]
    pub fn cancel_swap_pair(
        a: &mut IndexedEscrow,
        b: &mut IndexedEscrow,
        caller: [u8; 32],
        escrow_id_a: [u8; 32],
        escrow_id_b: [u8; 32],
        mint_a: Option<[u8; 32]>,
        refund_to_a: [u8; 32],
        mint_b: Option<[u8; 32]>,
        refund_to_b: [u8; 32],
        at: u64,
    ) -> Result<(), EscrowError> {
        super::cancel_swap(
            &mut a.inner,
            &mut b.inner,
            caller,
            escrow_id_a,
            escrow_id_b,
            mint_a,
            refund_to_a,
            mint_b,
            refund_to_b,
        )?;
        for escrow in [a, b] {
            let refund = escrow.inner.remaining_amount();
            escrow.push_event(
                EscrowEventKind::Cancelled,
                EscrowState::Funded,
                escrow.inner.state(),
                EventAmounts::refund(refund),
                at,
                None,
                None,
                None,
                None,
                Some(escrow.inner.initializer()),
            );
        }
        Ok(())
    }

    /// Cancel both legs of a linked swap pair on expiry (AV-105;
    /// mirrors [`cancel_swap_expired`](super::cancel_swap_expired)).
    /// On success each leg emits `ExpiredCancelled` exactly like
    /// [`IndexedEscrow::cancel_expired`] (`amounts` in the
    /// [`EventAmounts::expired_cancel`] shape, actor = the caller) in
    /// deterministic A→B order. Returns
    /// `(refund_a, penalty_a, refund_b, penalty_b)` like the inner
    /// function. On failure — including the atomic `NotExpired`
    /// refusal when either leg is ineligible — nothing is emitted on
    /// either leg. `now` doubles as the event timestamp.
    ///
    /// [`cancel_swap_expired`](super::cancel_swap_expired): super::cancel_swap_expired
    /// [`IndexedEscrow::cancel_expired`]: IndexedEscrow::cancel_expired
    #[allow(clippy::too_many_arguments)]
    pub fn cancel_swap_expired_pair(
        a: &mut IndexedEscrow,
        b: &mut IndexedEscrow,
        caller: [u8; 32],
        escrow_id_a: [u8; 32],
        escrow_id_b: [u8; 32],
        now: u64,
        mint_a: Option<[u8; 32]>,
        refund_to_a: [u8; 32],
        mint_b: Option<[u8; 32]>,
        refund_to_b: [u8; 32],
    ) -> Result<(u64, u64, u64, u64, u64, u64), EscrowError> {
        let (init_a, taker_a, penalty_a, init_b, taker_b, penalty_b) = super::cancel_swap_expired(
            &mut a.inner,
            &mut b.inner,
            caller,
            escrow_id_a,
            escrow_id_b,
            now,
            mint_a,
            refund_to_a,
            mint_b,
            refund_to_b,
        )?;
        let splits = [(init_a, taker_a, penalty_a), (init_b, taker_b, penalty_b)];
        for (escrow, (init_refund, taker_refund, penalty)) in [a, b].into_iter().zip(splits) {
            escrow.push_event(
                EscrowEventKind::ExpiredCancelled,
                EscrowState::Funded,
                escrow.inner.state(),
                EventAmounts::expired_cancel(init_refund + taker_refund, penalty),
                now,
                None,
                None,
                None,
                None,
                Some(caller),
            );
        }
        Ok((init_a, taker_a, penalty_a, init_b, taker_b, penalty_b))
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
            memo_config: None,
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
        // AV-133: scheduled auto-recovery before the transition (the
        // inner method repeats the check idempotently).
        let pause_state = self.inner.state();
        let (pause_was, pause_schedule, auto_unpaused) = self.begin_auto_unpause(at);
        let result = self.inner.release_and_close(authority, at, mint, payout_to);
        let (payout, fee, rent) = match result {
            Ok(v) => v,
            Err(e) => {
                self.restore_auto_unpause_on_failure(pause_was, pause_schedule, auto_unpaused);
                return self.map_reentrant(Err(e), at);
            }
        };
        self.emit_auto_unpause(pause_state, at, auto_unpaused);
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
                arbiter_fee: 0,
            },
            "amounts"
        );
        assert_eq!(event.at, at, "at");
    }

    // ----- AV-182: Memo program audit trail -----

    #[test]
    fn memo_disabled_by_default_stamps_nothing() {
        let mut e = funded(1_000_000);
        assert_eq!(last(&e).memo, None);
        e.release(ALICE, 400_000, None, BOB, T0 + 2).unwrap();
        assert_eq!(last(&e).memo, None);
    }

    #[test]
    fn memo_disabled_config_stamps_nothing() {
        let mut e = indexed(1_000_000)
            .with_memo_config(MemoConfig::disabled())
            .with_vesting(VestingSchedule::new(T0, T0 + 1_000).unwrap())
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        assert_eq!(last(&e).memo, None);
    }

    #[test]
    fn memo_stamped_on_fund_release_cancel() {
        let config = MemoConfig::enabled();
        // fund
        let mut e = indexed(1_000_000).with_memo_config(config);
        e.fund(ALICE, T0 + 1).unwrap();
        let expected = transition_memo_note(MemoTransition::Fund, &ESCROW_ID, 1_000_000).unwrap();
        assert_eq!(last(&e).memo, Some(expected));
        // release (partial): the note pins the gross moved amount.
        let (payout, fee) = e.release(ALICE, 400_000, None, BOB, T0 + 2).unwrap();
        let expected =
            transition_memo_note(MemoTransition::Release, &ESCROW_ID, payout + fee).unwrap();
        assert_eq!(last(&e).memo, Some(expected));
        // cancel: the note pins the total refund.
        let (init_refund, taker_refund) = e.cancel(ALICE, None, ALICE, T0 + 3).unwrap();
        let expected = transition_memo_note(
            MemoTransition::Cancel,
            &ESCROW_ID,
            init_refund + taker_refund,
        )
        .unwrap();
        assert_eq!(last(&e).memo, Some(expected));
    }

    #[test]
    fn memo_stamped_on_resolve_and_claim() {
        let config = MemoConfig::enabled();
        // resolve: the note pins the total settled amount.
        let mut e = indexed(1_000_000)
            .with_memo_config(config)
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1, e.inner().remaining_amount(), None, None, 0)
            .unwrap();
        // escalate is not a memo transition.
        assert_eq!(last(&e).memo, None);
        let (payout, fee, refund) = e.resolve(ARBITER, 600_000, None, None, BOB, T0 + 3).unwrap();
        let expected =
            transition_memo_note(MemoTransition::Resolve, &ESCROW_ID, payout + fee + refund)
                .unwrap();
        assert_eq!(last(&e).memo, Some(expected));

        // claim: the note pins the gross claimed amount.
        let mut e = indexed(1_000_000)
            .with_memo_config(config)
            .with_vesting(VestingSchedule::new(T0, T0 + 1_000).unwrap())
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        let (payout, fee) = e.claim(BOB, T0 + 1_000, None, BOB).unwrap();
        let expected =
            transition_memo_note(MemoTransition::Claim, &ESCROW_ID, payout + fee).unwrap();
        assert_eq!(last(&e).memo, Some(expected));
    }

    #[test]
    fn memo_event_note_matches_keeper_instruction_bytes() {
        // The audit event and the on-chain Memo instruction carry the
        // same bytes by construction: the stamped note equals the
        // instruction data the keeper builds.
        let config = MemoConfig::enabled();
        let mut e = indexed(1_000_000).with_memo_config(config);
        e.fund(ALICE, T0 + 1).unwrap();
        let event_note = last(&e).memo.expect("memo stamped");
        let ix = crate::maybe_memo_instruction(
            MemoTransition::Fund,
            &ESCROW_ID,
            1_000_000,
            &config,
        )
        .unwrap()
        .expect("memo enabled");
        assert_eq!(ix.program_id, crate::MEMO_PROGRAM_ID);
        assert_eq!(ix.data, event_note.as_str().as_bytes());
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
        let (refund, _, penalty) = e.cancel_expired(BOB, EXPIRES_AT, None, ALICE).unwrap();
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
        let (refund, _, penalty, _) = e.crank_expired(MALLORY, EXPIRES_AT, None).unwrap();
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
    fn crank_with_bounty_emits_keeper_bounty_paid() {
        // AV-124: a bounty-paying crank emits `ExpiredCranked`
        // followed by `KeeperBountyPaid` — the bounty settles the
        // already-finalized unwind (`from == to == Cancelled`), the
        // caller and the paid amount ride the event, and
        // `bounty_pool_remaining` carries the post-debit pool so
        // indexers track exhaustion without a second account read.
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_keeper_bounty(50_000, 10_000)
            .unwrap();
        e.fund(ALICE, T0).unwrap();
        let (refund, _, penalty, bounty) = e.crank_expired(MALLORY, EXPIRES_AT, None).unwrap();
        assert_eq!((refund, penalty, bounty), (1_000_000, 0, 10_000));
        let events = e.events();
        assert_eq!(events.len(), 4, "Initialized + Funded + ExpiredCranked + KeeperBountyPaid");
        let paid = &events[3];
        assert_eq!(paid.kind, EscrowEventKind::KeeperBountyPaid);
        assert_eq!(paid.from, EscrowState::Cancelled);
        assert_eq!(paid.to, EscrowState::Cancelled);
        assert_eq!(paid.amounts.payout, 10_000, "the bounty rides payout");
        assert_eq!(paid.caller, Some(MALLORY), "the crank caller is recorded");
        assert_eq!(
            paid.bounty_pool_remaining,
            Some(40_000),
            "post-debit pool balance"
        );
    }

    #[test]
    fn crank_without_bounty_emits_no_bounty_event() {
        // AV-124: a zero-bounty crank emits `ExpiredCranked` alone —
        // the AV-48 event shape is unchanged for unbountied escrows.
        let mut e = funded(1_000_000);
        let (_, _, _, bounty) = e.crank_expired(MALLORY, EXPIRES_AT, None).unwrap();
        assert_eq!(bounty, 0);
        let events = e.events();
        assert_eq!(events.len(), 3, "Initialized + Funded + ExpiredCranked only");
        assert_eq!(events[2].kind, EscrowEventKind::ExpiredCranked);
    }

    #[test]
    fn keeper_bounty_paid_csv_round_trip() {
        // AV-124: the bounty event survives the CSV projection — the
        // kind and the payout amount round-trip; the pool-remaining
        // extra takes its documented `None` on import (like the other
        // kind-specific extras).
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_keeper_bounty(50_000, 10_000)
            .unwrap();
        e.fund(ALICE, T0).unwrap();
        e.crank_expired(MALLORY, EXPIRES_AT, None).unwrap();
        let csv = crate::event_csv::events_to_csv(e.events());
        assert!(csv.contains("keeper_bounty_paid"));
        let back = crate::event_csv::csv_to_events(&csv).unwrap();
        let paid = back.iter().find(|ev| ev.kind == EscrowEventKind::KeeperBountyPaid).unwrap();
        assert_eq!(paid.amounts.payout, 10_000);
        assert_eq!(paid.bounty_pool_remaining, None, "not carried by the CSV projection");
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
        let (refund, _, penalty, _) = e.crank_expired(BOB, EXPIRES_AT, None).unwrap();
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
        e.escalate(BOB, EXPIRES_AT - 1, e.inner().remaining_amount(), None, None, 0).unwrap();
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
        e.escalate(BOB, EXPIRES_AT - 1, e.inner().remaining_amount(), Some(EVIDENCE), None, 0).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::Escalated);
        assert_eq!(event.evidence_hash, Some(EVIDENCE));
        // Without evidence the event carries None — the log never
        // invents evidence.
        let mut e2 = indexed(1_000_000).with_arbiter(ARBITER).unwrap();
        e2.fund(ALICE, T0 + 1).unwrap();
        e2.escalate(ALICE, EXPIRES_AT - 1, e2.inner().remaining_amount(), None, None, 0).unwrap();
        assert_eq!(last(&e2).evidence_hash, None);
    }

    #[test]
    fn resolved_event_carries_the_arbiter_fee() {
        // AV-135: the arbiter adjudication fee sliced from the taker's
        // share rides `amounts.arbiter_fee` on the Resolved event — the
        // anti-free-riding trail for arbitration economics.
        let mut e = indexed(1_000_000)
            .with_arbiter(ARBITER)
            .unwrap()
            .with_arbiter_fee(50_000, 1_000) // flat + 10%
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1, e.inner().remaining_amount(), None, None, 0).unwrap();
        e.resolve(ARBITER, 600_000, None, None, BOB, T0 + 3).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::Resolved);
        // 50_000 + floor(600_000 * 1_000 / 10_000) = 110_000.
        assert_eq!(event.amounts.arbiter_fee, 110_000);
        assert_eq!(event.amounts.payout, 600_000);
        assert_eq!(event.amounts.fee, 0);
    }

    #[test]
    fn resolved_event_arbiter_fee_zero_without_opt_in() {
        // No opt-in: the legacy event shape is untouched.
        let mut e = indexed(1_000_000).with_arbiter(ARBITER).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(ALICE, EXPIRES_AT - 1, e.inner().remaining_amount(), None, None, 0).unwrap();
        e.resolve(ARBITER, 600_000, None, None, BOB, T0 + 3).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::Resolved);
        assert_eq!(event.amounts.arbiter_fee, 0);
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
        e.escalate(ALICE, EXPIRES_AT - 1, e.inner().remaining_amount(), Some(EVIDENCE), None, 0).unwrap();
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
        e.escalate(escalator, at, e.inner().remaining_amount(), None, None, 0).unwrap();
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
        e.escalate(BOB, T0 + 10, e.inner().remaining_amount(), None, None, 0).unwrap();
        e.resolve(ARBITER, 600_000, None, None, BOB, u64::MAX - 1)
            .unwrap();
        assert!(!last(&e).evidence_defaulted);
    }

    #[test]
    fn evidence_filed_event_carries_root_and_settlement_carries_disclosure() {
        // AV-91: the Escalated event carries the committed Merkle
        // root, each EvidenceFiled carries it again, and the Resolved
        // settlement stamps the disclosure progress — the arbiter
        // panel audits completeness from the log.
        let d0 = [0xD0; 32];
        let d1 = [0xD1; 32];
        let root = crate::merkle_node_hash(
            &crate::merkle_leaf_hash(&d0),
            &crate::merkle_leaf_hash(&d1),
        );
        let proof0 = [crate::merkle_leaf_hash(&d1)];
        let proof1 = [crate::merkle_leaf_hash(&d0)];
        let mut e = indexed(1_000_000).with_arbiter(ARBITER).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(BOB, T0 + 10, e.inner().remaining_amount(), None, Some(root), 2).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::Escalated);
        assert_eq!(event.evidence_root, Some(root));
        assert_eq!(event.evidence_disclosure, None, "not a settlement kind");
        e.file_evidence(BOB, d0, 0, &proof0, T0 + 11).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::EvidenceFiled);
        assert_eq!(event.from, EscrowState::Disputed);
        assert_eq!(event.to, EscrowState::Disputed);
        assert_eq!(event.evidence_root, Some(root));
        e.file_evidence(BOB, d1, 1, &proof1, T0 + 12).unwrap();
        assert_eq!(last(&e).kind, EscrowEventKind::EvidenceFiled);
        // Full disclosure before judgment: the settlement stamps
        // (2, 2).
        e.resolve(ARBITER, 600_000, None, None, BOB, T0 + 13).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::Resolved);
        assert_eq!(event.evidence_disclosure, Some((2, 2)));
        assert_eq!(event.evidence_root, None, "root rides Escalated/EvidenceFiled only");
    }

    #[test]
    fn partial_disclosure_is_visible_on_the_settlement_event() {
        // AV-91: when the escalating party withholds a committed
        // document, the settlement event honestly records (1, 2) —
        // the judgment weight must deduct the undisclosed document.
        let d0 = [0xD0; 32];
        let d1 = [0xD1; 32];
        let root = crate::merkle_node_hash(
            &crate::merkle_leaf_hash(&d0),
            &crate::merkle_leaf_hash(&d1),
        );
        let proof0 = [crate::merkle_leaf_hash(&d1)];
        let mut e = indexed(1_000_000).with_arbiter(ARBITER).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(BOB, T0 + 10, e.inner().remaining_amount(), None, Some(root), 2).unwrap();
        e.file_evidence(BOB, d0, 0, &proof0, T0 + 11).unwrap();
        e.resolve(ARBITER, 600_000, None, None, BOB, T0 + 12).unwrap();
        let event = last(&e);
        assert_eq!(event.kind, EscrowEventKind::Resolved);
        assert_eq!(event.evidence_disclosure, Some((1, 2)));
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
        e.escalate(ALICE, T0 + 10, e.inner().remaining_amount(), None, None, 0).unwrap();
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
        e.escalate(BOB, T0 + 10, e.inner().remaining_amount(), None, None, 0).unwrap();
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
        e.escalate(ALICE, EXPIRES_AT - 1, e.inner().remaining_amount(), Some(EVIDENCE), None, 0).unwrap();
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
        e2.escalate(ALICE, EXPIRES_AT - 1, e2.inner().remaining_amount(), None, None, 0).unwrap();
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
        assert!(e.escalate(ALICE, T0 + 9, e.inner().remaining_amount(), None, None, 0).is_err());
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
    fn replace_attestor_emits_governance_event() {
        // AV-154: a real key rotation emits AttestorReplaced with
        // from == to == the current state and zero amounts — the event
        // is the ordering signal, the new key is read from the vault.
        // The rotated slot's vote is cleared at the wrapper level too.
        const NEW_KEY: [u8; 32] = [0xA4; 32];
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], &[1, 1], 2).unwrap();
        let mut e = indexed(1_000_000).with_quorum(policy).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.attest(ATTESTOR_1, T0 + 2).unwrap();
        e.replace_attestor(ALICE, BOB, 0, NEW_KEY, T0 + 3).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::AttestorReplaced,
            3,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 3,
        );
        // The compromised key's vote is gone: the 2-of-2 is no longer
        // satisfied even though ATTESTOR_2 never voted.
        assert!(!e.inner().quorum().unwrap().is_satisfied());
        assert_eq!(e.inner().quorum().unwrap().approved_weight(), 0);
    }

    #[test]
    fn replace_attestor_noop_emits_nothing() {
        // The same key: the state machine succeeds but nothing
        // observable changed, so no event — paralleling
        // `update_attestors`' no-op rule.
        const NEW_KEY: [u8; 32] = [0xA4; 32];
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], &[1, 1], 2).unwrap();
        let mut e = indexed(1_000_000).with_quorum(policy).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        assert_eq!(e.event_count(), 2);
        e.replace_attestor(ALICE, BOB, 0, ATTESTOR_1, T0 + 2).unwrap();
        assert_eq!(e.event_count(), 2);
        assert_eq!(e.next_seq(), 2);
        // Sanity: a real rotation right after still emits.
        e.replace_attestor(ALICE, BOB, 0, NEW_KEY, T0 + 3).unwrap();
        assert_eq!(e.event_count(), 3);
    }

    #[test]
    fn failed_replace_attestor_emits_nothing() {
        // A bad slot is AttestorSlotInvalid: the failed governance call
        // emits no event and the set is untouched.
        const NEW_KEY: [u8; 32] = [0xA4; 32];
        let policy = QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], &[1, 1], 2).unwrap();
        let mut e = indexed(1_000_000).with_quorum(policy).unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        assert_eq!(
            e.replace_attestor(ALICE, BOB, 5, NEW_KEY, T0 + 2),
            Err(EscrowError::AttestorSlotInvalid)
        );
        assert!(e.drain_events().len() == 2, "failed rotation emitted an event");
    }

    #[test]
    fn amend_milestones_emits_governance_event() {
        // AV-155: a mid-flight renegotiation emits MilestonesAmended
        // with from == to == the current state and zero amounts — the
        // event is the ordering signal, the new amounts are read from
        // the vault. Tranche 0 is dual-confirmed (locked); the
        // unconfirmed tranches move.
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[300_000, 300_000, 400_000]).unwrap())
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.confirm_milestone(ALICE, 0, T0 + 2).unwrap();
        e.confirm_milestone(BOB, 0, T0 + 3).unwrap();
        assert!(e.inner().milestone_confirmed(0));
        e.amend_milestones(ALICE, BOB, &[300_000, 400_000, 300_000], T0 + 4)
            .unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::MilestonesAmended,
            3,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 4,
        );
        // The locked tranche kept its amount; the free ones moved, and
        // the plan still covers the lockup exactly.
        let plan = e.inner().milestone_plan().unwrap();
        assert_eq!(plan.amount_at(0), Some(300_000));
        assert_eq!(plan.amount_at(1), Some(400_000));
        assert_eq!(plan.amount_at(2), Some(300_000));
        assert_eq!(plan.total(), 1_000_000);
    }

    #[test]
    fn amend_milestones_noop_emits_nothing() {
        // Re-affirming the current amounts succeeds but changes
        // nothing observable, so no event — paralleling
        // `adjust_milestone_amounts`' no-op rule.
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        assert_eq!(e.event_count(), 2);
        e.amend_milestones(ALICE, BOB, &[400_000, 600_000], T0 + 2)
            .unwrap();
        assert_eq!(e.event_count(), 2);
        assert_eq!(e.next_seq(), 2);
    }

    #[test]
    fn failed_amend_milestones_emits_nothing() {
        // Repricing a confirmed tranche is InvalidMilestoneAmendment:
        // the failed governance call emits no event and the plan is
        // untouched.
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.confirm_milestone(ALICE, 0, T0 + 2).unwrap();
        e.confirm_milestone(BOB, 0, T0 + 3).unwrap();
        assert_eq!(
            e.amend_milestones(ALICE, BOB, &[500_000, 500_000], T0 + 4),
            Err(EscrowError::InvalidMilestoneAmendment)
        );
        assert!(e.drain_events().len() == 3, "failed amendment emitted an event");
        let plan = e.inner().milestone_plan().unwrap();
        assert_eq!(plan.amount_at(0), Some(400_000));
        assert_eq!(plan.amount_at(1), Some(600_000));
    }

    #[test]
    fn reallocate_milestones_emits_event_with_old_and_new_tables() {
        // AV-224: a mid-flight reallocation emits
        // MilestonesReallocated with from == to == the current
        // state and zero amounts — and, unlike MilestonesAmended,
        // the event itself carries the before/after tranche
        // tables. Tranche 0 is dual-confirmed (locked); tranche 1
        // is cleared to zero (kept in the plan, not deleted) and
        // tranche 2 absorbs the value. The refundable remainder
        // (amount - released - skipped) is unchanged by the move.
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[300_000, 300_000, 400_000]).unwrap())
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.confirm_milestone(ALICE, 0, T0 + 2).unwrap();
        e.confirm_milestone(BOB, 0, T0 + 3).unwrap();
        assert_eq!(e.inner().remaining_amount(), 1_000_000);
        e.reallocate_milestones(ALICE, BOB, &[300_000, 0, 700_000], T0 + 4)
            .unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::MilestonesReallocated,
            3,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 4,
        );
        assert_eq!(
            last(&e).milestone_reallocation,
            Some((
                [300_000, 300_000, 400_000, 0, 0, 0, 0, 0],
                [300_000, 0, 700_000, 0, 0, 0, 0, 0],
                3,
            )),
            "event carries the before/after tranche tables"
        );
        // The locked tranche kept its amount, the cleared tranche
        // kept its slot, the plan still covers the lockup exactly,
        // and the remainder did not move.
        let plan = e.inner().milestone_plan().unwrap();
        assert_eq!(plan.count(), 3);
        assert_eq!(plan.amount_at(0), Some(300_000));
        assert_eq!(plan.amount_at(1), Some(0));
        assert_eq!(plan.amount_at(2), Some(700_000));
        assert_eq!(plan.total(), 1_000_000);
        assert_eq!(e.inner().remaining_amount(), 1_000_000);
    }

    #[test]
    fn reallocated_tranche_releases_at_new_amount() {
        // AV-224: later releases price from the live plan — a
        // tranche repriced before any confirmation settles at its
        // new amount, not its construction amount. Nothing was
        // claimed before the reallocation, so no retroactive
        // repricing is involved.
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.reallocate_milestones(ALICE, BOB, &[250_000, 750_000], T0 + 2)
            .unwrap();
        e.confirm_milestone(ALICE, 0, T0 + 3).unwrap();
        e.confirm_milestone(BOB, 0, T0 + 4).unwrap();
        let (payout, fee) = e.release_milestone(ALICE, 0, None, BOB, T0 + 5).unwrap();
        assert_eq!((payout, fee), (250_000, 0));
    }

    #[test]
    fn expired_milestone_claim_emits_event_with_tranche_and_refund() {
        // AV-225: a vested tranche claimed past its deadline is
        // rejected with MilestoneClaimExpired, the tranche returns
        // to remainder, and the rejected call still audits the
        // expiry: from == to == Funded, the refund leg carries the
        // expired tranche, and the event names the tranche index.
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap()
            .with_milestone_claim_deadline(0, T0 + 4)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.confirm_milestone(ALICE, 0, T0 + 2).unwrap();
        e.confirm_milestone(BOB, 0, T0 + 3).unwrap();
        assert_eq!(
            e.release_milestone(ALICE, 0, None, BOB, T0 + 5),
            Err(EscrowError::MilestoneClaimExpired)
        );
        assert_event(
            &last(&e),
            EscrowEventKind::MilestoneClaimExpired,
            3,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            400_000,
            T0 + 5,
        );
        assert_eq!(
            last(&e).milestone_claim_expired,
            Some(0),
            "event carries the expired tranche index"
        );
        assert_eq!(e.inner().released_amount(), 0);
        assert_eq!(e.inner().skipped_amount(), 400_000);
        assert_eq!(e.inner().remaining_amount(), 1_000_000);
        assert_eq!(e.inner().next_milestone(), Some(1));
        let history = e.inner().event_history();
        assert_eq!(history.last().unwrap().kind, EscrowEventKind::MilestoneClaimExpired);
        assert_eq!(history.last().unwrap().at, T0 + 5);
    }

    #[test]
    fn partial_claim_emits_event_per_slice_and_settles_on_final_slice() {
        // AV-229: each slice emits MilestonePartiallyClaimed
        // (discriminant 93, appended last) with the slice's gross
        // in payout; the tranche settles only on the final slice,
        // and the event stream stays in Funded until the whole
        // lockup settles.
        assert_eq!(EscrowEventKind::MilestonePartiallyClaimed.discriminant(), 93);
        assert_eq!(
            EscrowEventKind::from_discriminant(93),
            Some(EscrowEventKind::MilestonePartiallyClaimed)
        );
        assert_eq!(
            EscrowEventKind::MilestonePartiallyClaimed.name(),
            "milestone_partially_claimed"
        );
        assert_eq!(
            EscrowEventKind::from_name("milestone_partially_claimed"),
            Some(EscrowEventKind::MilestonePartiallyClaimed)
        );
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.confirm_milestone(ALICE, 0, T0 + 2).unwrap();
        e.confirm_milestone(BOB, 0, T0 + 3).unwrap();
        let (payout, fee) = e
            .release_milestone_partial(ALICE, 0, 150_000, None, BOB, T0 + 4)
            .unwrap();
        assert_eq!((payout, fee), (150_000, 0));
        assert_event(
            &last(&e),
            EscrowEventKind::MilestonePartiallyClaimed,
            3,
            EscrowState::Funded,
            EscrowState::Funded,
            150_000,
            0,
            0,
            T0 + 4,
        );
        assert_eq!(e.inner().milestone_partial_claimed_at(0), Some(150_000));
        let (payout, _) = e
            .release_milestone_partial(ALICE, 0, 250_000, None, BOB, T0 + 5)
            .unwrap();
        assert_eq!(payout, 250_000);
        assert_event(
            &last(&e),
            EscrowEventKind::MilestonePartiallyClaimed,
            4,
            EscrowState::Funded,
            EscrowState::Funded,
            250_000,
            0,
            0,
            T0 + 5,
        );
        assert!(e.inner().milestone_settled(0));
        assert_eq!(e.inner().next_milestone(), Some(1));
        let history = e.inner().event_history();
        assert_eq!(
            history.last().unwrap().kind,
            EscrowEventKind::MilestonePartiallyClaimed
        );
    }

    #[test]
    fn partial_claim_past_deadline_emits_expiry_with_remainder() {
        // AV-229 / AV-225: a slice past the deadline is rejected
        // and audited like a full expired claim — except the
        // refund leg carries only the unclaimed remainder, since
        // the earlier slice already settled.
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap()
            .with_milestone_claim_deadline(0, T0 + 6)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.confirm_milestone(ALICE, 0, T0 + 2).unwrap();
        e.confirm_milestone(BOB, 0, T0 + 3).unwrap();
        e.release_milestone_partial(ALICE, 0, 100_000, None, BOB, T0 + 4)
            .unwrap();
        assert_eq!(
            e.release_milestone_partial(ALICE, 0, 50_000, None, BOB, T0 + 7),
            Err(EscrowError::MilestoneClaimExpired)
        );
        assert_event(
            &last(&e),
            EscrowEventKind::MilestoneClaimExpired,
            4,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            300_000,
            T0 + 7,
        );
        assert_eq!(last(&e).milestone_claim_expired, Some(0));
        assert_eq!(e.inner().released_amount(), 100_000);
        assert_eq!(e.inner().skipped_amount(), 300_000);
        assert_eq!(e.inner().next_milestone(), Some(1));
    }

    #[test]
    fn amend_vesting_schedule_emits_event_and_failed_amend_emits_nothing() {
        // AV-230: a dual-signed revision emits VestingScheduleAmended
        // (discriminant 94, appended last) with zero amounts — a
        // config change, not a settlement — and the amended schedule
        // is read from the vault. A refused revision emits nothing.
        assert_eq!(EscrowEventKind::VestingScheduleAmended.discriminant(), 94);
        assert_eq!(
            EscrowEventKind::from_discriminant(94),
            Some(EscrowEventKind::VestingScheduleAmended)
        );
        assert_eq!(
            EscrowEventKind::VestingScheduleAmended.name(),
            "vesting_schedule_amended"
        );
        assert_eq!(
            EscrowEventKind::from_name("vesting_schedule_amended"),
            Some(EscrowEventKind::VestingScheduleAmended)
        );
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_vesting(VestingSchedule::new(T0, T0 + 1_000).unwrap())
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        // A one-party revision fails and emits nothing: the last
        // event is still Funded.
        assert_eq!(
            e.amend_vesting_schedule(ALICE, ALICE, VestingSchedule::new(T0, T0 + 2_000).unwrap(), T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        let stretched = VestingSchedule::new(T0, T0 + 2_000).unwrap();
        e.amend_vesting_schedule(ALICE, BOB, stretched, T0 + 2).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::VestingScheduleAmended,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 2,
        );
        assert_eq!(e.inner().vesting_schedule(), Some(stretched));
        let history = e.inner().event_history();
        assert_eq!(
            history.last().unwrap().kind,
            EscrowEventKind::VestingScheduleAmended
        );
    }

    #[test]
    fn amend_milestone_due_dates_emits_event_and_failed_amend_emits_nothing() {
        // AV-231: a dual-signed revision emits MilestoneDueDatesAmended
        // (discriminant 95, appended last) with zero amounts — a
        // config change, not a settlement — and the amended table
        // is read from the vault. A refused revision emits nothing.
        assert_eq!(EscrowEventKind::MilestoneDueDatesAmended.discriminant(), 95);
        assert_eq!(
            EscrowEventKind::from_discriminant(95),
            Some(EscrowEventKind::MilestoneDueDatesAmended)
        );
        assert_eq!(
            EscrowEventKind::MilestoneDueDatesAmended.name(),
            "milestone_due_dates_amended"
        );
        assert_eq!(
            EscrowEventKind::from_name("milestone_due_dates_amended"),
            Some(EscrowEventKind::MilestoneDueDatesAmended)
        );
        let plan = MilestonePlan::new(&[400_000, 600_000]).unwrap();
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(plan)
            .unwrap()
            .with_milestone_due_dates(&[T0 + 1_000, T0 + 2_000])
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        // A one-party revision fails and emits nothing: the last
        // event is still Funded.
        assert_eq!(
            e.amend_milestone_due_dates(ALICE, ALICE, &[T0 + 1_000, T0 + 3_000], T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        e.amend_milestone_due_dates(ALICE, BOB, &[T0 + 1_000, T0 + 3_000], T0 + 2).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::MilestoneDueDatesAmended,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 2,
        );
        assert_eq!(e.inner().milestone_due_at(1), Some(T0 + 3_000));
        let history = e.inner().event_history();
        assert_eq!(
            history.last().unwrap().kind,
            EscrowEventKind::MilestoneDueDatesAmended
        );
    }

    #[test]
    fn unskip_milestone_emits_event_and_failed_unskip_emits_nothing() {
        // AV-232: a dual-signed restoration emits MilestoneUnskipped
        // (discriminant 96, appended last) with zero amounts — a
        // schedule restoration, not a settlement — and the restored
        // tranche is read from the vault. A refused restoration
        // emits nothing.
        assert_eq!(EscrowEventKind::MilestoneUnskipped.discriminant(), 96);
        assert_eq!(
            EscrowEventKind::from_discriminant(96),
            Some(EscrowEventKind::MilestoneUnskipped)
        );
        assert_eq!(
            EscrowEventKind::MilestoneUnskipped.name(),
            "milestone_unskipped"
        );
        assert_eq!(
            EscrowEventKind::from_name("milestone_unskipped"),
            Some(EscrowEventKind::MilestoneUnskipped)
        );
        let plan = MilestonePlan::new(&[400_000, 600_000]).unwrap();
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(plan)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.skip_milestone(ALICE, 0, T0 + 2).unwrap();
        e.skip_milestone(BOB, 0, T0 + 3).unwrap();
        assert_eq!(last(&e).kind, EscrowEventKind::MilestoneSkipped);
        assert_eq!(e.inner().skipped_amount(), 400_000);
        // A one-party restoration fails and emits nothing: the last
        // event is still MilestoneSkipped.
        assert_eq!(
            e.unskip_milestone(ALICE, ALICE, 0, T0 + 4),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::MilestoneSkipped);
        e.unskip_milestone(ALICE, BOB, 0, T0 + 5).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::MilestoneUnskipped,
            3,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 5,
        );
        assert_eq!(e.inner().skipped_amount(), 0);
        assert!(!e.inner().milestone_settled(0));
        let history = e.inner().event_history();
        assert_eq!(
            history.last().unwrap().kind,
            EscrowEventKind::MilestoneUnskipped
        );
    }

    #[test]
    fn amend_protocol_fee_emits_event_and_failed_amend_emits_nothing() {
        // AV-233: a dual-signed revision emits ProtocolFeeAmended
        // (discriminant 97, appended last) with zero amounts — a
        // rate revision, not a settlement — and the amended rate
        // and cap are read from the vault. A refused revision
        // emits nothing.
        assert_eq!(EscrowEventKind::ProtocolFeeAmended.discriminant(), 97);
        assert_eq!(
            EscrowEventKind::from_discriminant(97),
            Some(EscrowEventKind::ProtocolFeeAmended)
        );
        assert_eq!(
            EscrowEventKind::ProtocolFeeAmended.name(),
            "protocol_fee_amended"
        );
        assert_eq!(
            EscrowEventKind::from_name("protocol_fee_amended"),
            Some(EscrowEventKind::ProtocolFeeAmended)
        );
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_protocol_fee(500)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        // A one-party revision fails and emits nothing: the last
        // event is still Funded.
        assert_eq!(
            e.amend_protocol_fee(ALICE, ALICE, 1_000, 0, T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        e.amend_protocol_fee(ALICE, BOB, 1_000, 15_000, T0 + 3).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::ProtocolFeeAmended,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 3,
        );
        assert_eq!(e.inner().fee_bps(), 1_000);
        assert_eq!(e.inner().fee_cap(), 15_000);
        let history = e.inner().event_history();
        assert_eq!(
            history.last().unwrap().kind,
            EscrowEventKind::ProtocolFeeAmended
        );
    }

    #[test]
    fn rotate_milestone_verifier_emits_event_and_failed_rotate_emits_nothing() {
        // AV-234: a dual-signed rotation emits
        // MilestoneVerifierRotated (discriminant 98, appended last)
        // with zero amounts — a gatekeeper revision, not a
        // settlement — and the new verifier is read from the
        // vault. A refused rotation emits nothing. Unlike
        // `rotate_arbiter`, there is no silent same-key case: the
        // core call rejects it, so a same-key attempt fails here
        // too and emits nothing.
        assert_eq!(EscrowEventKind::MilestoneVerifierRotated.discriminant(), 98);
        assert_eq!(
            EscrowEventKind::from_discriminant(98),
            Some(EscrowEventKind::MilestoneVerifierRotated)
        );
        assert_eq!(
            EscrowEventKind::MilestoneVerifierRotated.name(),
            "milestone_verifier_rotated"
        );
        assert_eq!(
            EscrowEventKind::from_name("milestone_verifier_rotated"),
            Some(EscrowEventKind::MilestoneVerifierRotated)
        );
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestone_verifier([0x77; 32])
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        // A one-party rotation fails and emits nothing: the last
        // event is still Funded.
        assert_eq!(
            e.rotate_milestone_verifier(ALICE, ALICE, [0x78; 32], T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        // A same-key rotation fails and emits nothing either.
        assert_eq!(
            e.rotate_milestone_verifier(ALICE, BOB, [0x77; 32], T0 + 2),
            Err(EscrowError::InvalidMilestoneVerifier)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        e.rotate_milestone_verifier(ALICE, BOB, [0x78; 32], T0 + 3).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::MilestoneVerifierRotated,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 3,
        );
        assert_eq!(e.inner().milestone_verifier(), [0x78; 32]);
        let history = e.inner().event_history();
        assert_eq!(
            history.last().unwrap().kind,
            EscrowEventKind::MilestoneVerifierRotated
        );
    }

    #[test]
    fn amend_arbiter_fee_emits_event_and_failed_amend_emits_nothing() {
        // AV-235: a dual-signed revision emits ArbiterFeeAmended
        // (discriminant 99, appended last) with zero amounts — a
        // fee revision, not a settlement — and the amended fee
        // legs are read from the vault. A refused revision emits
        // nothing. Orthogonal to AV-233's ProtocolFeeAmended: a
        // different field, a different rate.
        assert_eq!(EscrowEventKind::ArbiterFeeAmended.discriminant(), 99);
        assert_eq!(
            EscrowEventKind::from_discriminant(99),
            Some(EscrowEventKind::ArbiterFeeAmended)
        );
        assert_eq!(
            EscrowEventKind::ArbiterFeeAmended.name(),
            "arbiter_fee_amended"
        );
        assert_eq!(
            EscrowEventKind::from_name("arbiter_fee_amended"),
            Some(EscrowEventKind::ArbiterFeeAmended)
        );
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_arbiter_fee(5_000, 250)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        // A one-party revision fails and emits nothing: the last
        // event is still Funded.
        assert_eq!(
            e.amend_arbiter_fee(ALICE, ALICE, 1_000, 100, T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        // A past-100% revision fails and emits nothing, with both
        // legs untouched.
        assert_eq!(
            e.amend_arbiter_fee(ALICE, BOB, 9_999, 10_001, T0 + 2),
            Err(EscrowError::InvalidArbiterFee)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        assert_eq!(e.inner().arbiter_fee_flat(), Some(5_000));
        assert_eq!(e.inner().arbiter_fee_bps(), Some(250));
        e.amend_arbiter_fee(ALICE, BOB, 1_000, 100, T0 + 3).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::ArbiterFeeAmended,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 3,
        );
        assert_eq!(e.inner().arbiter_fee_flat(), Some(1_000));
        assert_eq!(e.inner().arbiter_fee_bps(), Some(100));
        let history = e.inner().event_history();
        assert_eq!(
            history.last().unwrap().kind,
            EscrowEventKind::ArbiterFeeAmended
        );
    }

    #[test]
    fn amend_appeal_window_emits_event_and_failed_amend_emits_nothing() {
        // AV-236: a dual-signed revision emits AppealWindowAmended
        // (discriminant 100, appended last) with zero amounts — a
        // window revision, not a settlement — and the amended
        // window is read from the vault. A refused revision emits
        // nothing. Orthogonal to AV-235's ArbiterFeeAmended: a
        // different field, a different governance consequence.
        assert_eq!(EscrowEventKind::AppealWindowAmended.discriminant(), 100);
        assert_eq!(
            EscrowEventKind::from_discriminant(100),
            Some(EscrowEventKind::AppealWindowAmended)
        );
        assert_eq!(
            EscrowEventKind::AppealWindowAmended.name(),
            "appeal_window_amended"
        );
        assert_eq!(
            EscrowEventKind::from_name("appeal_window_amended"),
            Some(EscrowEventKind::AppealWindowAmended)
        );
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_appeal_window(86_400)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        // A one-party revision fails and emits nothing: the last
        // event is still Funded.
        assert_eq!(
            e.amend_appeal_window(ALICE, ALICE, 3600, T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        // A zero-window revision fails and emits nothing, with the
        // window untouched.
        assert_eq!(
            e.amend_appeal_window(ALICE, BOB, 0, T0 + 2),
            Err(EscrowError::InvalidAppealWindow)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        assert_eq!(e.inner().appeal_window_secs(), 86_400);
        e.amend_appeal_window(ALICE, BOB, 3600, T0 + 3).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::AppealWindowAmended,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 3,
        );
        assert_eq!(e.inner().appeal_window_secs(), 3600);
        let history = e.inner().event_history();
        assert_eq!(
            history.last().unwrap().kind,
            EscrowEventKind::AppealWindowAmended
        );
    }

    #[test]
    fn amend_slash_ladder_emits_event_and_failed_amend_emits_nothing() {
        const PENALTY: [u8; 32] = [0xDD; 32];
        const DAY: u64 = 86_400;
        // AV-237: a dual-signed revision emits SlashLadderAmended
        // (discriminant 101, appended last) with zero amounts — a
        // ladder revision, not a settlement — and the amended
        // ladder is read from the vault. A refused revision emits
        // nothing. Orthogonal to AV-236's AppealWindowAmended: a
        // different field, a different governance consequence.
        assert_eq!(EscrowEventKind::SlashLadderAmended.discriminant(), 101);
        assert_eq!(
            EscrowEventKind::from_discriminant(101),
            Some(EscrowEventKind::SlashLadderAmended)
        );
        assert_eq!(
            EscrowEventKind::SlashLadderAmended.name(),
            "slash_ladder_amended"
        );
        assert_eq!(
            EscrowEventKind::from_name("slash_ladder_amended"),
            Some(EscrowEventKind::SlashLadderAmended)
        );
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_slash_ladder(PENALTY, &[(T0, 100), (T0 + DAY, 500)])
            .unwrap();
        e.fund(ALICE, T0 - 1).unwrap();
        // A one-party revision fails and emits nothing: the last
        // event is still Funded.
        assert_eq!(
            e.amend_slash_ladder(ALICE, ALICE, &[(T0, 200), (T0 + DAY, 600)], T0 - 1),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        // A consumed-prefix violation fails and emits nothing, with
        // the ladder untouched.
        let mut e2 = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_slash_ladder(PENALTY, &[(T0, 100), (T0 + DAY, 500)])
            .unwrap();
        e2.fund(ALICE, T0 - 1).unwrap();
        e2.slash(ALICE, 10_000, None, T0).unwrap();
        assert_eq!(
            e2.amend_slash_ladder(ALICE, BOB, &[(T0, 101), (T0 + DAY, 600)], T0 + DAY),
            Err(EscrowError::InvalidSlashLadder)
        );
        assert_eq!(e2.inner().slash_ladder().unwrap().rungs[0].bps, 100);
        e.amend_slash_ladder(ALICE, BOB, &[(T0, 200), (T0 + DAY, 600)], T0 - 1)
            .unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::SlashLadderAmended,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 - 1,
        );
        assert_eq!(e.inner().slash_ladder().unwrap().rungs[0].bps, 200);
        let history = e.inner().event_history();
        assert_eq!(
            history.last().unwrap().kind,
            EscrowEventKind::SlashLadderAmended
        );
    }

    #[test]
    fn amend_appeal_bond_emits_event_and_failed_amend_emits_nothing() {
        // AV-238: a dual-signed revision emits AppealBondAmended
        // (discriminant 102, appended last) with zero amounts — a
        // bond revision, not a settlement — and the amended bond
        // is read from the vault. A refused revision emits
        // nothing. Orthogonal to AV-237's SlashLadderAmended and
        // AV-236's AppealWindowAmended: a different field, a
        // different governance consequence.
        assert_eq!(EscrowEventKind::AppealBondAmended.discriminant(), 102);
        assert_eq!(
            EscrowEventKind::from_discriminant(102),
            Some(EscrowEventKind::AppealBondAmended)
        );
        assert_eq!(
            EscrowEventKind::AppealBondAmended.name(),
            "appeal_bond_amended"
        );
        assert_eq!(
            EscrowEventKind::from_name("appeal_bond_amended"),
            Some(EscrowEventKind::AppealBondAmended)
        );
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_appeal_window(86_400)
            .unwrap()
            .with_appeal_bond(50_000)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        // A one-party revision fails and emits nothing: the last
        // event is still Funded.
        assert_eq!(
            e.amend_appeal_bond(ALICE, ALICE, 80_000, T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        // A zero-bond revision fails and emits nothing, with the
        // bond untouched.
        assert_eq!(
            e.amend_appeal_bond(ALICE, BOB, 0, T0 + 2),
            Err(EscrowError::InvalidAppealBond)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        assert_eq!(e.inner().appeal_bond(), 50_000);
        e.amend_appeal_bond(ALICE, BOB, 80_000, T0 + 3).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::AppealBondAmended,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 3,
        );
        assert_eq!(e.inner().appeal_bond(), 80_000);
        let history = e.inner().event_history();
        assert_eq!(
            history.last().unwrap().kind,
            EscrowEventKind::AppealBondAmended
        );
    }

    #[test]
    fn amend_grace_period_emits_event_and_failed_amend_emits_nothing() {
        // AV-240: a dual-signed revision emits GracePeriodAmended
        // (discriminant 103, appended last) with zero amounts — a
        // grace revision, not a settlement — and the amended grace
        // is read from the vault. A refused revision emits
        // nothing. Orthogonal to AV-238's AppealBondAmended: a
        // different field, a different governance consequence.
        assert_eq!(EscrowEventKind::GracePeriodAmended.discriminant(), 103);
        assert_eq!(
            EscrowEventKind::from_discriminant(103),
            Some(EscrowEventKind::GracePeriodAmended)
        );
        assert_eq!(
            EscrowEventKind::GracePeriodAmended.name(),
            "grace_period_amended"
        );
        assert_eq!(
            EscrowEventKind::from_name("grace_period_amended"),
            Some(EscrowEventKind::GracePeriodAmended)
        );
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_grace_period(300)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        // A one-party revision fails and emits nothing: the last
        // event is still Funded.
        assert_eq!(
            e.amend_grace_period(ALICE, ALICE, 600, T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        // The new expiry gate (EXPIRES_AT + 600) follows the
        // amended grace, not the old 300.
        e.amend_grace_period(ALICE, BOB, 600, T0 + 3).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::GracePeriodAmended,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 3,
        );
        assert_eq!(e.inner().grace_period(), 600);
        assert!(!e.inner().is_expiry_eligible(EXPIRES_AT + 300));
        assert!(e.inner().is_expiry_eligible(EXPIRES_AT + 600));
        let history = e.inner().event_history();
        assert_eq!(
            history.last().unwrap().kind,
            EscrowEventKind::GracePeriodAmended
        );
    }

    #[test]
    fn amend_evidence_deadline_emits_event_and_failed_amend_emits_nothing() {
        // AV-241: a dual-signed revision emits
        // EvidenceDeadlineAmended (discriminant 104, appended
        // last) with zero amounts — a deadline revision, not a
        // settlement — and the amended deadline is read from the
        // vault. A refused revision emits nothing. Orthogonal to
        // AV-240's GracePeriodAmended: a different field, a
        // different governance consequence.
        assert_eq!(
            EscrowEventKind::EvidenceDeadlineAmended.discriminant(),
            104
        );
        assert_eq!(
            EscrowEventKind::from_discriminant(104),
            Some(EscrowEventKind::EvidenceDeadlineAmended)
        );
        assert_eq!(
            EscrowEventKind::EvidenceDeadlineAmended.name(),
            "evidence_deadline_amended"
        );
        assert_eq!(
            EscrowEventKind::from_name("evidence_deadline_amended"),
            Some(EscrowEventKind::EvidenceDeadlineAmended)
        );
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap()
            .with_evidence_deadline(3_600)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        // A one-party revision fails and emits nothing: the last
        // event is still Funded.
        assert_eq!(
            e.amend_evidence_deadline(ALICE, ALICE, 7_200, T0 + 2),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        // A zero-deadline revision fails and emits nothing, with
        // the deadline untouched.
        assert_eq!(
            e.amend_evidence_deadline(ALICE, BOB, 0, T0 + 2),
            Err(EscrowError::InvalidEvidenceDeadline)
        );
        assert_eq!(last(&e).kind, EscrowEventKind::Funded);
        assert_eq!(e.inner().evidence_deadline_secs(), 3_600);
        e.amend_evidence_deadline(ALICE, BOB, 7_200, T0 + 3).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::EvidenceDeadlineAmended,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 3,
        );
        assert_eq!(e.inner().evidence_deadline_secs(), 7_200);
        let history = e.inner().event_history();
        assert_eq!(
            history.last().unwrap().kind,
            EscrowEventKind::EvidenceDeadlineAmended
        );
    }

    #[test]
    fn failed_reallocate_milestones_emits_nothing() {
        // Repricing a confirmed tranche is InvalidMilestoneAmendment
        // (the AV-155 amendment error): the failed governance call
        // emits no event and the plan is untouched. A single-party
        // call is Unauthorized for the same reason.
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.confirm_milestone(ALICE, 0, T0 + 2).unwrap();
        e.confirm_milestone(BOB, 0, T0 + 3).unwrap();
        assert_eq!(
            e.reallocate_milestones(ALICE, BOB, &[500_000, 500_000], T0 + 4),
            Err(EscrowError::InvalidMilestoneAmendment)
        );
        assert_eq!(
            e.reallocate_milestones(ALICE, MALLORY, &[400_000, 600_000], T0 + 4),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            e.reallocate_milestones(ALICE, BOB, &[400_000, 500_000], T0 + 4),
            Err(EscrowError::InvalidMilestoneAmendment)
        );
        assert!(e.drain_events().len() == 3, "failed reallocation emitted an event");
        let plan = e.inner().milestone_plan().unwrap();
        assert_eq!(plan.amount_at(0), Some(400_000));
        assert_eq!(plan.amount_at(1), Some(600_000));
    }

    #[test]
    fn append_milestone_tranche_emits_event_and_keeps_tail_readable() {
        // AV-226: appending emits MilestoneTrancheAppended with
        // from == to == Funded and zero amounts — appending moves no
        // funds — and the appended tranche is read from the vault's
        // plan tail. A failed append emits nothing.
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.skip_milestone(ALICE, 0, T0 + 2).unwrap();
        e.skip_milestone(BOB, 0, T0 + 3).unwrap();
        assert_eq!(
            e.append_milestone_tranche(ALICE, BOB, 500_000, T0 + 4),
            Err(EscrowError::InvalidMilestoneAmendment),
            "over-remainder append must fail before any event"
        );
        e.append_milestone_tranche(ALICE, BOB, 150_000, T0 + 4).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::MilestoneTrancheAppended,
            3,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 4,
        );
        let plan = e.inner().milestone_plan().unwrap();
        assert_eq!(plan.count(), 3);
        assert_eq!(plan.amount_at(2), Some(150_000));
        assert_eq!(e.inner().skipped_amount(), 250_000);
        assert_eq!(e.inner().amount(), 1_000_000);
    }

    #[test]
    fn amend_claimant_roster_emits_event_with_new_shares() {
        // AV-227: amending emits ClaimantRosterAmended with
        // from == to == Funded and zero amounts — amending moves
        // no funds — and the amended roster reads back from the
        // vault. A failed amendment emits nothing.
        const C1: [u8; 32] = [0xC1; 32];
        const C2: [u8; 32] = [0xC2; 32];
        const C3: [u8; 32] = [0xC3; 32];
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_claimants(&[(C1, 5000), (C2, 5000)])
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        assert_eq!(
            e.amend_claimant_roster(ALICE, &[(C1, 0)], T0 + 2),
            Err(EscrowError::InvalidClaimantShares),
            "zero-weight amendment must fail before any event"
        );
        e.amend_claimant_roster(ALICE, &[(C1, 1), (C3, 3)], T0 + 2).unwrap();
        assert_event(
            &last(&e),
            EscrowEventKind::ClaimantRosterAmended,
            2,
            EscrowState::Funded,
            EscrowState::Funded,
            0,
            0,
            0,
            T0 + 2,
        );
        let r = e.inner().claimants().unwrap();
        assert_eq!(r.claimant_count, 2);
        assert_eq!(r.find(C1), Some(0));
        assert_eq!(r.share_bps[0], 2500);
        assert_eq!(r.find(C3), Some(1));
        assert_eq!(r.share_bps[1], 7500);
        assert_eq!(r.find(C2), None, "omitted leg is removed");
        assert_eq!(r.unclaimed_bps(), 10_000);
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
        e.escalate(ALICE, EXPIRES_AT - 1, e.inner().remaining_amount(), None, None, 0).unwrap();
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
            EscrowState::Cancelled => {
                e.cancel(ALICE, None, ALICE, T0 + 2).unwrap();
            }
            EscrowState::Released => {
                e.release(ALICE, 1_000_000, None, BOB, T0 + 2).unwrap();
            }
            EscrowState::Settled => {
                let mut d = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
                    .unwrap()
                    .with_arbiter(ARBITER)
                    .unwrap();
                d.fund(ALICE, T0 + 1).unwrap();
                d.escalate(ALICE, EXPIRES_AT - 1, d.inner().remaining_amount(), None, None, 0).unwrap();
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
                    arbiter_fee: 0,
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
        d.escalate(ALICE, EXPIRES_AT - 1, d.inner().remaining_amount(), None, None, 0).unwrap();
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
            .release_via_cpi(ALICE, 1_000_000, None, BOB, 0, T0 + 2, &inv, |_| Ok(1_000_000))
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
            e.release_via_cpi(ALICE, 1_000_000, None, BOB, 0, T0 + 2, &inv, |_| {
                Err(CpiError::ZeroAddress)
            }),
            Err(EscrowError::CpiExecutionFailed)
        );
        assert_eq!(e.event_count(), events_before);
        // The next successful release still gets the next seq — the
        // failed one left no gap in the event log.
        e.release_via_cpi(ALICE, 1_000_000, None, BOB, 0, T0 + 3, &inv, |_| Ok(1_000_000))
            .unwrap();
        assert_eq!(last(&e).seq, events_before as u64);
    }

    #[test]
    fn slippage_exceeded_emits_nothing() {
        // AV-132: a below-floor execution rolls back with
        // SlippageExceeded and emits no event — same as the executor-
        // failure path. The next successful release still gets the
        // next seq.
        let mut e = funded(1_000_000);
        let inv = dex_invocation();
        let events_before = e.event_count();
        assert_eq!(
            e.release_via_cpi(ALICE, 1_000_000, None, BOB, 990_000, T0 + 2, &inv, |_| {
                Ok(989_999)
            }),
            Err(EscrowError::SlippageExceeded)
        );
        assert_eq!(e.event_count(), events_before);
        e.release_via_cpi(ALICE, 1_000_000, None, BOB, 990_000, T0 + 3, &inv, |_| {
            Ok(995_000)
        })
        .unwrap();
        assert_eq!(last(&e).seq, events_before as u64);
        assert_eq!(last(&e).kind, EscrowEventKind::Released);
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
        e.release_via_cpi(ALICE, 1_000_000, None, BOB, 0, T0 + 2, &inv, |_| {
            let nested = unsafe { &mut *raw };
            assert_eq!(
                nested.release(ALICE, 100, None, BOB, T0 + 2),
                Err(EscrowError::ReentrantCall)
            );
            Ok(1_000_000)
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
                arbiter_fee: 0,
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
        assert_eq!(EscrowEventKind::from_discriminant(59), Some(EscrowEventKind::ReleaseIntentAnnounced));
        assert_eq!(EscrowEventKind::from_discriminant(60), Some(EscrowEventKind::ReleaseIntentVetoed));
        assert_eq!(EscrowEventKind::from_discriminant(61), Some(EscrowEventKind::EscrowsMerged));
        // AV-148: discriminant 76, appended after EscrowsNetted —
        // 0–75 stay stable for already-serialized histories.
        assert_eq!(EscrowEventKind::from_discriminant(76), Some(EscrowEventKind::TakerFunded));
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn release_intent_kinds_round_trip() {
        // AV-112: discriminants 59/60, appended after TrancheFunded —
        // 0–58 stay stable for already-serialized histories.
        let announced = EscrowEventKind::ReleaseIntentAnnounced;
        assert_eq!(announced.discriminant(), 59);
        assert_eq!(EscrowEventKind::from_discriminant(59), Some(announced));
        assert_eq!(announced.name(), "release_intent_announced");
        assert_eq!(
            EscrowEventKind::from_name("release_intent_announced"),
            Some(announced)
        );
        let vetoed = EscrowEventKind::ReleaseIntentVetoed;
        assert_eq!(vetoed.discriminant(), 60);
        assert_eq!(EscrowEventKind::from_discriminant(60), Some(vetoed));
        assert_eq!(vetoed.name(), "release_intent_vetoed");
        assert_eq!(
            EscrowEventKind::from_name("release_intent_vetoed"),
            Some(vetoed)
        );
    }

    #[test]
    fn announce_release_emits_only_on_change() {
        // The IndexedEscrow wrapper emits ReleaseIntentAnnounced only
        // when the recorded intent actually changes — a same-timestamp
        // re-announce is a silent idempotent no-op.
        let mut e = funded(1_000_000);
        e.announce_release(ALICE, T0, T0).unwrap();
        e.announce_release(ALICE, T0, T0).unwrap(); // same timestamp: silent
        e.announce_release(BOB, T0 + 5, T0 + 5).unwrap(); // new timestamp: emits
        let announced: Vec<_> = e
            .events()
            .iter()
            .filter(|ev| ev.kind == EscrowEventKind::ReleaseIntentAnnounced)
            .collect();
        assert_eq!(announced.len(), 2, "two real announces, one silent no-op");
        // from == to == Funded: a governance signal, not a lifecycle move.
        for ev in &announced {
            assert_eq!(ev.from, EscrowState::Funded);
            assert_eq!(ev.to, EscrowState::Funded);
        }
        // The actor rides the event-history ring (first 8 key bytes).
        let history = e.inner().event_history();
        let actors: Vec<_> = history
            .iter()
            .filter(|h| h.kind == EscrowEventKind::ReleaseIntentAnnounced)
            .map(|h| h.actor)
            .collect();
        assert_eq!(
            actors,
            vec![
                Some(ALICE[..8].try_into().unwrap()),
                Some(BOB[..8].try_into().unwrap()),
            ]
        );
    }

    #[test]
    fn veto_release_emits_only_on_actual_veto() {
        // Vetoing with no live intent is a no-op success that emits
        // nothing; vetoing a live intent emits ReleaseIntentVetoed.
        let mut e = funded(1_000_000);
        e.veto_release(ALICE, T0, T0).unwrap(); // no intent: silent
        let kinds: Vec<EscrowEventKind> = e.events().iter().map(|ev| ev.kind).collect();
        assert!(
            !kinds.contains(&EscrowEventKind::ReleaseIntentVetoed),
            "no-intent veto emits nothing"
        );
        e.announce_release(ALICE, T0, T0).unwrap();
        e.veto_release(BOB, T0 + 1, T0 + 1).unwrap();
        let vetoed: Vec<_> = e
            .events()
            .iter()
            .filter(|ev| ev.kind == EscrowEventKind::ReleaseIntentVetoed)
            .collect();
        assert_eq!(vetoed.len(), 1);
        assert_eq!(vetoed[0].from, EscrowState::Funded);
        assert_eq!(vetoed[0].to, EscrowState::Funded);
        let history = e.inner().event_history();
        let entry = history
            .iter()
            .find(|h| h.kind == EscrowEventKind::ReleaseIntentVetoed)
            .expect("veto recorded in the ring");
        assert_eq!(entry.actor, Some(BOB[..8].try_into().unwrap()));
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
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
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
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
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
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
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
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
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
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn appeal_expired_kind_round_trips() {
        // AV-103: discriminant 52, appended after DenylistUpdated —
        // 0–51 stay stable for already-serialized histories.
        let kind = EscrowEventKind::AppealExpired;
        assert_eq!(kind.discriminant(), 52);
        assert_eq!(EscrowEventKind::from_discriminant(52), Some(kind));
        assert_eq!(kind.name(), "appeal_expired");
        assert_eq!(EscrowEventKind::from_name("appeal_expired"), Some(kind));
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn delegation_granted_kind_round_trips() {
        // AV-104: discriminant 53, appended after AppealExpired —
        // 0–52 stay stable for already-serialized histories.
        let kind = EscrowEventKind::DelegationGranted;
        assert_eq!(kind.discriminant(), 53);
        assert_eq!(EscrowEventKind::from_discriminant(53), Some(kind));
        assert_eq!(kind.name(), "delegation_granted");
        assert_eq!(
            EscrowEventKind::from_name("delegation_granted"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn delegation_revoked_kind_round_trips() {
        // AV-104: discriminant 54, appended after DelegationGranted —
        // 0–53 stay stable for already-serialized histories.
        let kind = EscrowEventKind::DelegationRevoked;
        assert_eq!(kind.discriminant(), 54);
        assert_eq!(EscrowEventKind::from_discriminant(54), Some(kind));
        assert_eq!(kind.name(), "delegation_revoked");
        assert_eq!(
            EscrowEventKind::from_name("delegation_revoked"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn swap_linked_kind_round_trips() {
        // AV-105: discriminant 55, appended after DelegationRevoked —
        // 0–54 stay stable for already-serialized histories.
        let kind = EscrowEventKind::SwapLinked;
        assert_eq!(kind.discriminant(), 55);
        assert_eq!(EscrowEventKind::from_discriminant(55), Some(kind));
        assert_eq!(kind.name(), "swap_linked");
        assert_eq!(EscrowEventKind::from_name("swap_linked"), Some(kind));
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn evidence_filed_kind_round_trips() {
        // AV-91: discriminant 46, appended after AppealResolved —
        // 0–45 stay stable for already-serialized histories.
        let kind = EscrowEventKind::EvidenceFiled;
        assert_eq!(kind.discriminant(), 46);
        assert_eq!(EscrowEventKind::from_discriminant(46), Some(kind));
        assert_eq!(kind.name(), "evidence_filed");
        assert_eq!(EscrowEventKind::from_name("evidence_filed"), Some(kind));
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn released_split_kind_round_trips() {
        // AV-93: discriminant 47, appended after EvidenceFiled —
        // 0–46 stay stable for already-serialized histories.
        let kind = EscrowEventKind::ReleasedSplit;
        assert_eq!(kind.discriminant(), 47);
        assert_eq!(EscrowEventKind::from_discriminant(47), Some(kind));
        assert_eq!(kind.name(), "released_split");
        assert_eq!(EscrowEventKind::from_name("released_split"), Some(kind));
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn release_via_intent_kind_round_trips() {
        // AV-123: discriminant 66, appended after CounterOfferRejected —
        // 0–65 stay stable for already-serialized histories.
        let kind = EscrowEventKind::ReleaseViaIntent;
        assert_eq!(kind.discriminant(), 66);
        assert_eq!(EscrowEventKind::from_discriminant(66), Some(kind));
        assert_eq!(kind.name(), "release_via_intent");
        assert_eq!(EscrowEventKind::from_name("release_via_intent"), Some(kind));
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn keeper_bounty_paid_kind_round_trips() {
        // AV-124: discriminant 67, appended after ReleaseViaIntent —
        // 0–66 stay stable for already-serialized histories.
        let kind = EscrowEventKind::KeeperBountyPaid;
        assert_eq!(kind.discriminant(), 67);
        assert_eq!(EscrowEventKind::from_discriminant(67), Some(kind));
        assert_eq!(kind.name(), "keeper_bounty_paid");
        assert_eq!(EscrowEventKind::from_name("keeper_bounty_paid"), Some(kind));
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn partial_refunded_kind_round_trips() {
        // AV-127: discriminant 68, appended after KeeperBountyPaid —
        // 0–67 stay stable for already-serialized histories.
        let kind = EscrowEventKind::PartialRefunded;
        assert_eq!(kind.discriminant(), 68);
        assert_eq!(EscrowEventKind::from_discriminant(68), Some(kind));
        assert_eq!(kind.name(), "partial_refunded");
        assert_eq!(EscrowEventKind::from_name("partial_refunded"), Some(kind));
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn judgment_committed_kind_round_trips() {
        // AV-137: discriminant 72, appended after
        // DualControlCancelled — 0–71 stay stable for
        // already-serialized histories.
        let kind = EscrowEventKind::JudgmentCommitted;
        assert_eq!(kind.discriminant(), 72);
        assert_eq!(EscrowEventKind::from_discriminant(72), Some(kind));
        assert_eq!(kind.name(), "judgment_committed");
        assert_eq!(
            EscrowEventKind::from_name("judgment_committed"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn judgment_revealed_kind_round_trips() {
        // AV-137: discriminant 73, appended after JudgmentCommitted —
        // 0–72 stay stable for already-serialized histories.
        let kind = EscrowEventKind::JudgmentRevealed;
        assert_eq!(kind.discriminant(), 73);
        assert_eq!(EscrowEventKind::from_discriminant(73), Some(kind));
        assert_eq!(kind.name(), "judgment_revealed");
        assert_eq!(
            EscrowEventKind::from_name("judgment_revealed"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn attestor_replaced_kind_round_trips() {
        // AV-154: discriminant 80, appended after VestingResumed —
        // 0–79 stay stable for already-serialized histories.
        let kind = EscrowEventKind::AttestorReplaced;
        assert_eq!(kind.discriminant(), 80);
        assert_eq!(EscrowEventKind::from_discriminant(80), Some(kind));
        assert_eq!(kind.name(), "attestor_replaced");
        assert_eq!(
            EscrowEventKind::from_name("attestor_replaced"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn milestones_amended_kind_round_trips() {
        // AV-155: discriminant 81, appended after AttestorReplaced —
        // 0–80 stay stable for already-serialized histories.
        let kind = EscrowEventKind::MilestonesAmended;
        assert_eq!(kind.discriminant(), 81);
        assert_eq!(EscrowEventKind::from_discriminant(81), Some(kind));
        assert_eq!(kind.name(), "milestones_amended");
        assert_eq!(
            EscrowEventKind::from_name("milestones_amended"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn milestones_reallocated_kind_round_trips() {
        // AV-224: discriminant 89, appended after ChainBroken —
        // 0–88 stay stable for already-serialized histories.
        let kind = EscrowEventKind::MilestonesReallocated;
        assert_eq!(kind.discriminant(), 89);
        assert_eq!(EscrowEventKind::from_discriminant(89), Some(kind));
        assert_eq!(kind.name(), "milestones_reallocated");
        assert_eq!(
            EscrowEventKind::from_name("milestones_reallocated"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn milestone_claim_expired_kind_round_trips() {
        // AV-225: discriminant 90, appended after
        // MilestonesReallocated — 0–89 stay stable for
        // already-serialized histories.
        let kind = EscrowEventKind::MilestoneClaimExpired;
        assert_eq!(kind.discriminant(), 90);
        assert_eq!(EscrowEventKind::from_discriminant(90), Some(kind));
        assert_eq!(kind.name(), "milestone_claim_expired");
        assert_eq!(
            EscrowEventKind::from_name("milestone_claim_expired"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn milestone_tranche_appended_kind_round_trips() {
        // AV-226: discriminant 91, appended after
        // MilestoneClaimExpired — 0–90 stay stable for
        // already-serialized histories.
        let kind = EscrowEventKind::MilestoneTrancheAppended;
        assert_eq!(kind.discriminant(), 91);
        assert_eq!(EscrowEventKind::from_discriminant(91), Some(kind));
        assert_eq!(kind.name(), "milestone_tranche_appended");
        assert_eq!(
            EscrowEventKind::from_name("milestone_tranche_appended"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn claimant_roster_amended_kind_round_trips() {
        // AV-227: discriminant 92, appended after
        // MilestoneTrancheAppended — 0–91 stay stable for
        // already-serialized histories.
        let kind = EscrowEventKind::ClaimantRosterAmended;
        assert_eq!(kind.discriminant(), 92);
        assert_eq!(EscrowEventKind::from_discriminant(92), Some(kind));
        assert_eq!(kind.name(), "claimant_roster_amended");
        assert_eq!(
            EscrowEventKind::from_name("claimant_roster_amended"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn delivery_confirmed_kind_round_trips() {
        // AV-203: discriminant 86, appended after FeeWithdrawn —
        // 0–85 stay stable for already-serialized histories.
        let kind = EscrowEventKind::DeliveryConfirmed;
        assert_eq!(kind.discriminant(), 86);
        assert_eq!(EscrowEventKind::from_discriminant(86), Some(kind));
        assert_eq!(kind.name(), "delivery_confirmed");
        assert_eq!(
            EscrowEventKind::from_name("delivery_confirmed"),
            Some(kind)
        );
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn governance_kinds_round_trip() {
        // AV-158: discriminants 82–84, appended after
        // MilestonesAmended — 0–81 stay stable for
        // already-serialized histories.
        let proposed = EscrowEventKind::GovernanceProposed;
        assert_eq!(proposed.discriminant(), 82);
        assert_eq!(EscrowEventKind::from_discriminant(82), Some(proposed));
        assert_eq!(proposed.name(), "governance_proposed");
        assert_eq!(
            EscrowEventKind::from_name("governance_proposed"),
            Some(proposed)
        );
        let executed = EscrowEventKind::GovernanceExecuted;
        assert_eq!(executed.discriminant(), 83);
        assert_eq!(EscrowEventKind::from_discriminant(83), Some(executed));
        assert_eq!(executed.name(), "governance_executed");
        assert_eq!(
            EscrowEventKind::from_name("governance_executed"),
            Some(executed)
        );
        let cancelled = EscrowEventKind::GovernanceCancelled;
        assert_eq!(cancelled.discriminant(), 84);
        assert_eq!(EscrowEventKind::from_discriminant(84), Some(cancelled));
        assert_eq!(cancelled.name(), "governance_cancelled");
        assert_eq!(
            EscrowEventKind::from_name("governance_cancelled"),
            Some(cancelled)
        );
        assert_eq!(EscrowEventKind::from_discriminant(115), Some(EscrowEventKind::RentSweepGraceAmended)); // AV-252: 115 is RentSweepGraceAmended
        assert_eq!(EscrowEventKind::from_discriminant(116), Some(EscrowEventKind::FeeScheduleAmended)); // AV-253: 116 is FeeScheduleAmended
        assert_eq!(EscrowEventKind::from_discriminant(117), Some(EscrowEventKind::StreamingFeeRateAmended)); // AV-254: 117 is StreamingFeeRateAmended
        assert_eq!(EscrowEventKind::from_discriminant(118), None); // AV-254: 117 is StreamingFeeRateAmended
    }

    #[test]
    fn blind_wrappers_emit_commit_reveal_and_settlement_events() {
        // AV-137: the IndexedEscrow wrappers emit JudgmentCommitted
        // per commit, JudgmentRevealed per reveal, and PanelResolved
        // on the M-th matching reveal.
        const M1: [u8; 32] = [0xC1; 32];
        const M2: [u8; 32] = [0xC2; 32];
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_blind_panel(&[M1, M2], 2, 86_400)
            .unwrap();
        e.fund(ALICE, T0 + 1).unwrap();
        e.escalate(ALICE, T0 + 2, 1_000_000, None, None, 0).unwrap();
        let kinds_before = e.event_count();
        let salt1 = [0x11; 32];
        let salt2 = [0x22; 32];
        let c1 = crate::blind_commitment(600_000, None, salt1);
        e.submit_judgment_commit(M1, c1, T0 + 3).unwrap();
        assert_eq!(
            e.events()[kinds_before].kind,
            EscrowEventKind::JudgmentCommitted
        );
        e.reveal_judgment(M1, 600_000, None, salt1, None, BOB, T0 + 4)
            .unwrap();
        assert_eq!(
            e.events()[kinds_before + 1].kind,
            EscrowEventKind::JudgmentRevealed
        );
        // M2's matching reveal settles: JudgmentRevealed then
        // PanelResolved.
        let c2 = crate::blind_commitment(600_000, None, salt2);
        e.submit_judgment_commit(M2, c2, T0 + 5).unwrap();
        let settled = e
            .reveal_judgment(M2, 600_000, None, salt2, None, BOB, T0 + 6)
            .unwrap();
        assert!(settled.is_some());
        let n = e.event_count();
        assert_eq!(e.events()[n - 2].kind, EscrowEventKind::JudgmentRevealed);
        assert_eq!(e.events()[n - 1].kind, EscrowEventKind::PanelResolved);
        assert_eq!(e.inner().state(), EscrowState::Settled);
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
