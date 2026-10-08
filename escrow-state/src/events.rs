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
//! - Partial `release` / `claim` calls emit [`EscrowEventKind::Released`]
//!   / [`EscrowEventKind::Claimed`] with `from == to == Funded`: the
//!   `EscrowState` variant does not change, but funds moved and the
//!   payout stream must be complete for the indexer. A closing payout
//!   has `to == Released`.
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
//! | Initialized, Activated, Funded, Escalated, Attested, MilestoneConfirmed | 0 | 0 | 0 | 0 |
//! | Released, Claimed, MilestoneReleased | gross taker amount (net payout + fee) | protocol fee (AV-17) | 0 | 0 |
//! | Cancelled | 0 | 0 | remainder refunded to the initializer | 0 |
//! | ExpiredCancelled | 0 | 0 | remainder minus penalty, to the whitelisted destination | anti-griefing penalty to the initializer (AV-24; 0 unless taker-initiated with `penalty_bps > 0`) |
//! | Resolved | gross taker share (`taker_amount`) | protocol fee on the taker's share | initializer's share of the split | 0 |
//! | MilestoneSkipped | 0 | 0 | skipped tranche (the initializer's refund) | 0 |
//!
//! # Backward compatibility
//!
//! No existing public method signature changed: the wrapper is purely
//! additive, and [`Escrow`] itself is untouched. The crate stays
//! dependency-free.

use crate::{Escrow, EscrowError, EscrowState, MilestonePlan, QuorumPolicy, VestingSchedule};

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
}

/// Fund movements carried by an [`EscrowEvent`].
///
/// A single shape for every kind (see the module docs for the per-kind
/// table): `payout` is the gross amount moved to the taker *before* the
/// protocol-fee split (`payout - fee` is the taker's net), `fee` is the
/// AV-17 protocol fee sliced from `payout`, `refund` is the amount
/// returned to the initializer, and `penalty` is the AV-24 anti-griefing
/// penalty sliced from the remainder on a taker-initiated
/// `cancel_expired` (routed to the initializer as griefing compensation).
/// All four are zero when the kind moves no such value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventAmounts {
    pub payout: u64,
    pub fee: u64,
    pub refund: u64,
    pub penalty: u64,
}

impl EventAmounts {
    /// No fund movement (config transitions, votes, pure state flips).
    fn none() -> Self {
        Self {
            payout: 0,
            fee: 0,
            refund: 0,
            penalty: 0,
        }
    }

    /// A taker payout of `gross` with `fee` sliced from it.
    fn payout(gross: u64, fee: u64) -> Self {
        Self {
            payout: gross,
            fee,
            refund: 0,
            penalty: 0,
        }
    }

    /// An initializer refund of `refund` (cancels, skips).
    fn refund(refund: u64) -> Self {
        Self {
            payout: 0,
            fee: 0,
            refund,
            penalty: 0,
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
        }
    }
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
/// the two dispute events: `Escalated` carries the hash attached at
/// escalation, `Resolved` carries the hash the escrow still holds (the
/// arbiter's settlement references the evidence it reviewed). It is
/// `None` on every other kind — the event log never invents evidence.
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
}

/// An event-logging adapter over [`Escrow`] (AV-18).
///
/// Exposes the same mutating transitions (`initialize` as the
/// constructor, then `activate`, `fund`, `attest`, `release`, `cancel`,
/// `cancel_expired`, `claim`, `escalate`, `resolve`,
/// `confirm_milestone`, `release_milestone`, `skip_milestone`) plus the
/// `with_*` configuration builders, delegating every call to the inner
/// state machine. Exactly one [`EscrowEvent`] is recorded per
/// successful transition (see the module docs for the emission rule);
/// failed calls record nothing.
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
        );
        Ok(indexed)
    }

    /// Record one event, assigning the next per-escrow sequence number.
    fn push_event(
        &mut self,
        kind: EscrowEventKind,
        from: EscrowState,
        to: EscrowState,
        amounts: EventAmounts,
        at: u64,
        evidence_hash: Option<[u8; 32]>,
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
        };
        self.next_seq += 1;
        self.events.push(event);
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

    /// Opt in to an anti-griefing penalty on taker-initiated expiry
    /// cancellation (mirrors [`Escrow::with_penalty_bps`]).
    /// Configuration: emits no event.
    pub fn with_penalty_bps(mut self, penalty_bps: u16) -> Result<Self, EscrowError> {
        self.inner = self.inner.with_penalty_bps(penalty_bps)?;
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
            self.push_event(EscrowEventKind::Activated, from, to, EventAmounts::none(), at, None);
        }
        Ok(())
    }

    /// Lock funds into the vault (mirrors [`Escrow::fund`]). Emits
    /// `Funded`.
    pub fn fund(&mut self, authority: [u8; 32], at: u64) -> Result<(), EscrowError> {
        let from = self.inner.state();
        self.inner.fund(authority)?;
        self.push_event(
            EscrowEventKind::Funded,
            from,
            self.inner.state(),
            EventAmounts::none(),
            at,
            None,
        );
        Ok(())
    }

    /// Release `amount` of the locked funds to the taker (mirrors
    /// [`Escrow::release`]). Emits `Released` on every successful call —
    /// partial releases carry `from == to == Funded`, the closing one
    /// `to == Released` — so the payout stream is complete in `seq`
    /// order. Returns `(taker_payout, fee)` like the inner method.
    pub fn release(
        &mut self,
        authority: [u8; 32],
        amount: u64,
        mint: Option<[u8; 32]>,
        at: u64,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        let (payout, fee) = self.inner.release(authority, amount, mint)?;
        // `amount` is the gross payout by construction
        // (`payout + fee == amount`); it cannot overflow u64 addition.
        self.push_event(
            EscrowEventKind::Released,
            from,
            self.inner.state(),
            EventAmounts::payout(amount, fee),
            at,
            None,
        );
        Ok((payout, fee))
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
        self.inner.cancel(authority, mint, refund_to)?;
        let to = self.inner.state();
        let refund = self.inner.remaining_amount();
        self.push_event(
            EscrowEventKind::Cancelled,
            from,
            to,
            EventAmounts::refund(refund),
            at,
            None,
        );
        Ok(())
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
        let (refund, penalty) = self
            .inner
            .cancel_expired(authority, now, mint, refund_to)?;
        let to = self.inner.state();
        self.push_event(
            EscrowEventKind::ExpiredCancelled,
            from,
            to,
            EventAmounts::expired_cancel(refund, penalty),
            now,
            None,
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
            self.push_event(EscrowEventKind::Attested, state, state, EventAmounts::none(), at, None);
        }
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
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        let (payout, fee) = self.inner.claim(authority, now, mint)?;
        // `payout + fee` is the gross claimable (`<= amount`); no
        // overflow possible.
        self.push_event(
            EscrowEventKind::Claimed,
            from,
            self.inner.state(),
            EventAmounts::payout(payout + fee, fee),
            now,
            None,
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
        );
        Ok(())
    }

    /// Settle a disputed escrow (mirrors [`Escrow::resolve`]). Emits
    /// `Resolved` (`Disputed -> Settled`) with the gross taker share in
    /// `amounts.payout`, the protocol fee in `amounts.fee`, and the
    /// initializer's share in `amounts.refund` — and the dispute
    /// evidence hash the escrow still holds, so the settlement
    /// references the evidence the arbiter reviewed. Returns
    /// `(taker_payout, fee, initializer_refund)` like the inner method.
    pub fn resolve(
        &mut self,
        authority: [u8; 32],
        taker_amount: u64,
        mint: Option<[u8; 32]>,
        at: u64,
    ) -> Result<(u64, u64, u64), EscrowError> {
        let from = self.inner.state();
        let (payout, fee, refund) = self.inner.resolve(authority, taker_amount, mint)?;
        // `taker_amount` is the gross taker share by construction
        // (`payout + fee == taker_amount`).
        let amounts = EventAmounts {
            payout: taker_amount,
            fee,
            refund,
            penalty: 0,
        };
        // AV-22: the evidence hash survives `resolve` on the escrow, so
        // the settlement event carries the same commitment the
        // `Escalated` event carried.
        let evidence_hash = self.inner.evidence_hash();
        self.push_event(
            EscrowEventKind::Resolved,
            from,
            self.inner.state(),
            amounts,
            at,
            evidence_hash,
        );
        Ok((payout, fee, refund))
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
            );
        }
        Ok(())
    }

    /// Release a milestone's tranche to the taker (mirrors
    /// [`Escrow::release_milestone`]). Emits `MilestoneReleased` with the
    /// gross tranche in `amounts.payout`; the final tranche carries
    /// `to == Released`. Returns `(taker_payout, fee)` like the inner
    /// method.
    pub fn release_milestone(
        &mut self,
        authority: [u8; 32],
        index: u8,
        mint: Option<[u8; 32]>,
        at: u64,
    ) -> Result<(u64, u64), EscrowError> {
        let from = self.inner.state();
        let (payout, fee) = self.inner.release_milestone(authority, index, mint)?;
        // `payout + fee` is the gross tranche (`<= amount`); no overflow
        // possible.
        self.push_event(
            EscrowEventKind::MilestoneReleased,
            from,
            self.inner.state(),
            EventAmounts::payout(payout + fee, fee),
            at,
            None,
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
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod event_tests {
    use super::*;
    use crate::{EscrowState, MilestonePlan, QuorumPolicy, VestingSchedule};

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const MALLORY: [u8; 32] = [0xCC; 32];
    const ATTESTOR_1: [u8; 32] = [0xA1; 32];
    const ATTESTOR_2: [u8; 32] = [0xA2; 32];
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
        QuorumPolicy::new(&[ATTESTOR_1], 1).unwrap()
    }

    fn milestone_indexed() -> IndexedEscrow {
        IndexedEscrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT, ESCROW_ID, T0)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
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
        e.release(ALICE, 1_000_000, None, T0 + 2).unwrap();
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
        e.release(ALICE, 400_000, None, T0 + 2).unwrap();
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
        e.release(ALICE, 600_000, None, T0 + 3).unwrap();
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
        e.release(ALICE, 300_000, None, T0 + 2).unwrap();
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
        let (payout, fee) = e.claim(BOB, T0 + 1_000, None).unwrap();
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
        let (payout, fee, refund) = e.resolve(ARBITER, 600_000, None, T0 + 3).unwrap();
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
        e.resolve(ARBITER, 600_000, None, T0 + 3).unwrap();
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
        e.release_milestone(ALICE, 0, None, T0 + 4).unwrap();
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
        assert!(e.release(ALICE, 0, None, T0 + 9).is_err());
        // Over-release.
        assert!(e.release(ALICE, 1_000_001, None, T0 + 9).is_err());
        // Cancel by a stranger.
        assert!(e.cancel(MALLORY, None, ALICE, T0 + 9).is_err());
        // Attest with no quorum configured.
        assert!(e.attest(ATTESTOR_1, T0 + 9).is_err());
        // Escalate with no arbiter configured.
        assert!(e.escalate(ALICE, T0 + 9, None).is_err());
        // Resolve outside a dispute.
        assert!(e.resolve(ARBITER, 1, None, T0 + 9).is_err());
        // Milestone ops with no plan attached.
        assert!(e.confirm_milestone(ALICE, 0, T0 + 9).is_err());
        assert!(e.release_milestone(ALICE, 0, None, T0 + 9).is_err());
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
        let (payout, fee) = e.release(ALICE, 1_000_000, None, T0 + 2).unwrap();
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
        let (payout, fee, refund) = e.resolve(ARBITER, 600_000, None, T0 + 3).unwrap();
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
        e.release(ALICE, 1_000_000, None, T0 + 2).unwrap();
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
}
