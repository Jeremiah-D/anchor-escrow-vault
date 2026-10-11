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
//! | Initialized, Activated, Funded, Escalated, Attested, MilestoneConfirmed, QuorumUpdated, AttestorsUpdated, EmergencyUnlock (AV-41), ReentryRejected (AV-36), PauseAuthorityRotated (AV-47), TakerRotated (AV-52) | 0 | 0 | 0 | 0 |
//! | Released, Claimed, MilestoneReleased, SubscriptionPeriodReleased (AV-56) | gross taker amount (net payout + fee) | protocol fee (AV-17) | 0 | 0 |
//! | Cancelled | 0 | 0 | remainder refunded to the initializer | 0 |
//! | ExpiredCancelled | 0 | 0 | remainder minus penalty, to the whitelisted destination | anti-griefing penalty to the initializer (AV-24; 0 unless taker-initiated with `penalty_bps > 0`) |
//! | ExpiredCranked (AV-48) | 0 | 0 | remainder minus penalty, to the whitelisted destination (the cranker receives nothing) | anti-griefing penalty to the initializer (AV-24; 0 unless the cranker is the taker) |
//! | Resolved | gross taker share (`taker_amount`) | protocol fee on the taker's share | initializer's share of the split | 0 |
//! | DefaultJudgment (AV-55) | gross taker share (`default_taker_amount`) | protocol fee on the taker's share | initializer's share of the split | 0 |
//! | MilestoneSkipped | 0 | 0 | skipped tranche (the initializer's refund) | 0 |
//! | VaultClosed (AV-34) | 0 | 0 | 0 | 0 — the rent-exempt deposit reclaimed by the initializer on vault close is carried in `rent_reclaimed`, not in these four fields |
//!
//! # Backward compatibility
//!
//! No existing public method signature changed: the wrapper is purely
//! additive, and [`Escrow`] itself is untouched. The crate stays
//! dependency-free.

use crate::{Escrow, EscrowError, EscrowState, MilestonePlan, QuorumPolicy, VestingSchedule};
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
        }
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
            // AV-53: the off-chain reference memo rides every event —
            // read from the escrow at emit time (never a push_event
            // parameter), so the log always agrees with the account.
            reference: self.inner.reference(),
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
    /// `Funded`.
    pub fn fund(&mut self, authority: [u8; 32], at: u64) -> Result<(), EscrowError> {
        let from = self.inner.state();
        // AV-36: a rejected reentrant entry emits `ReentryRejected`
        // (the deliberate exception to the no-events-on-failure rule).
        // (The inner result is bound first so its `&mut` borrow ends
        // before `map_reentrant` reborrows `self`.)
        let result = self.inner.fund(authority);
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
}
