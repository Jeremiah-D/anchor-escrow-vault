//! Off-chain escrow state snapshot (AV-26): a point-in-time, read-only
//! view of an [`Escrow`] as canonical JSON, for keeper bots and indexers
//! that reconcile off-chain state against the chain.
//!
//! A keeper watching many vaults (see [`crate::scan_keeper_actions`]) or
//! an indexer feeding a database both need the same primitive: "what does
//! this escrow look like right now?" [`Escrow::snapshot`] answers that
//! with every raw field plus the derived quantities an operator actually
//! reasons about:
//!
//! - `remaining`: what `cancel` / `cancel_expired` would refund right now;
//! - `vested` / `claimable`: the streaming-payments position at the
//!   snapshot time (`vested` is the schedule's unlock, `claimable` is
//!   vested-minus-already-released, i.e. what `claim` would move);
//! - quorum progress: `approved_weight` of `threshold` weight (of
//!   `total_weight`, across `registered` attestors), and whether the
//!   quorum is already satisfied for a `release`;
//! - milestone progress: per-tranche amounts with their confirmation and
//!   settlement bits, plus the index of the next unsettled tranche;
//! - `expiry_eligible`: whether the chain's `cancel_expired` gate passes
//!   at the snapshot time (grace period included — the same predicate the
//!   keeper scan uses, so a snapshot never disagrees with the scan);
//! - `unlock_at` / `unlock_eligible`: the timelock (AV-27) and whether the
//!   payout gates pass at the snapshot time — the same predicate the
//!   keeper scan uses for `claim` actions;
//! - `relative_timelock_secs` / `fund_at`: the relative timelock
//!   (AV-64) — the lock duration and the funding timestamp it is
//!   measured from — so indexers compute the same unlock time the
//!   chain's payout gates enforce;
//! - `decimals` / `display_*`: the token decimal metadata (AV-28) and
//!   every shown amount rendered in human units (`amount`, `released`,
//!   `remaining`, `vested`, `claimable`, `fees_paid`, `skipped`, and
//!   per-tranche amounts) — the raw fields stay untouched, so indexers
//!   keep diffing numbers while operators read whole tokens.
//!
//! Like [`crate::KeeperReport::to_json`], [`EscrowSnapshot::to_json`]
//! hand-serializes (the crate is dependency-free): deterministic field
//! order, 32-byte keys as 64-char lowercase hex, `Option` fields as a hex
//! string or `null`. Two snapshots of equal state at equal `now` are
//! byte-identical, so indexers can hash or diff them directly.
//!
//! The snapshot is a pure read: it borrows the escrow, emits no events,
//! and advances no state — a dry run by construction.

use crate::{format_amount, AppealState, Escrow, EscrowState, EventHistoryEntry, MultisigAuthority};

/// Render 32 bytes as 64 lowercase hex characters (same convention as
/// [`crate::keeper`]'s serializer).
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Render 8 bytes as 16 lowercase hex characters — the actor summary
/// in an AV-57 event-history entry.
fn hex8(bytes: &[u8; 8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(16);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Canonical name for a lifecycle state in snapshot JSON.
pub(crate) fn state_name(state: EscrowState) -> &'static str {
    match state {
        EscrowState::Uninitialized => "uninitialized",
        EscrowState::Funded => "funded",
        EscrowState::Released => "released",
        EscrowState::Cancelled => "cancelled",
        EscrowState::Activated => "activated",
        EscrowState::Disputed => "disputed",
        EscrowState::Settled => "settled",
        EscrowState::Closed => "closed",
        EscrowState::Split => "split",
    }
}

/// Dual-signature activation progress (AV-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualSigSnapshot {
    /// Whether both parties must activate before funding.
    pub required: bool,
    /// Whether the initializer recorded its activation signature.
    pub initializer_activated: bool,
    /// Whether the taker recorded its activation signature.
    pub taker_activated: bool,
}

/// Weighted quorum progress (AV-04, AV-45).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumSnapshot {
    /// The M: registered attestors.
    pub registered: u8,
    /// The weight-sum threshold a release must reach.
    pub threshold: u64,
    /// Distinct attestors that have attested so far (headcount).
    pub approvals: u8,
    /// Accumulated weight of the distinct attestations so far.
    pub approved_weight: u64,
    /// Total registered voting weight.
    pub total_weight: u64,
    /// Whether `approved_weight >= threshold` — a `release` would pass
    /// the quorum gate right now.
    pub satisfied: bool,
}

/// Linear vesting schedule (AV-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VestingSnapshot {
    /// Unix seconds: unlock starts.
    pub start: u64,
    /// Unix seconds: fully unlocked.
    pub end: u64,
}

/// One unlock tier of a non-linear vesting curve (AV-90): at Unix
/// timestamp `at` the cumulative unlocked fraction reaches
/// `unlocked_bps / 10_000`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VestingTierSnapshot {
    /// Unix seconds: this tier's unlock timestamp.
    pub at: u64,
    /// Cumulative unlocked basis points at `at`.
    pub unlocked_bps: u16,
}

/// One milestone tranche (AV-15): the tranche amount plus its
/// confirmation and settlement bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MilestoneTrancheSnapshot {
    /// Tranche index, in release order.
    pub index: usize,
    /// Tranche amount.
    pub amount: u64,
    /// Both parties confirmed the release path.
    pub confirmed: bool,
    /// The tranche was released or skipped — terminal for this tranche.
    pub settled: bool,
}

/// Milestone plan progress (AV-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MilestoneSnapshot {
    /// Number of tranches.
    pub count: u8,
    /// Exact sum of the tranche amounts (`u128`: never wraps).
    pub total: u128,
    /// How many tranches are settled (released or skipped).
    pub settled: usize,
    /// How many tranches are confirmed for the release path.
    pub confirmed: usize,
    /// Index of the first unsettled tranche, or `None` when every
    /// tranche is settled.
    pub next: Option<usize>,
    /// Per-tranche detail, in release order.
    pub tranches: Vec<MilestoneTrancheSnapshot>,
}

/// One subscription period (AV-56/AV-73): the period's live payout
/// amount plus its release state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionPeriodSnapshot {
    /// Period index, in release order (0-based).
    pub index: u8,
    /// The period's *live* payout amount: the uniform `per_period` at
    /// setup, or the dual-signed re-split from
    /// [`Escrow::adjust_period_amounts`](crate::Escrow::adjust_period_amounts).
    pub amount: u64,
    /// The period already released (its amount is locked history).
    pub released: bool,
    /// Unix timestamp at which the period becomes due
    /// (back-scheduled from `expires_at`).
    pub due_at: u64,
}

/// Subscription schedule progress (AV-56), with the AV-73 live
/// per-period amounts: what `release_period` will actually pay per
/// period, never the construction-time uniform alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionSnapshot {
    /// Number of periods.
    pub periods: u8,
    /// Seconds between period due dates.
    pub period_secs: u64,
    /// The uniform per-period amount at setup (the schedule's
    /// construction-time parameter — informational; payouts read the
    /// live per-period table).
    pub per_period: u64,
    /// Exact sum of the live per-period amounts (`u128`: never wraps)
    /// — always the locked amount.
    pub total: u128,
    /// Index of the next period to release, or `None` when every
    /// period released.
    pub next: Option<u8>,
    /// Per-period detail, in release order, with live amounts.
    pub periods_detail: Vec<SubscriptionPeriodSnapshot>,
}

/// One panel member's current effective vote, as exported by the
/// AV-65 arbiter-panel snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanelVoteSnapshot {
    /// The voting member's key.
    pub member: [u8; 32],
    /// The taker's share of the remaining locked funds this vote
    /// awards.
    pub taker_amount: u64,
    /// The member's optional rationale-document commitment (AV-38
    /// convention).
    pub rationale_hash: Option<[u8; 32]>,
}

/// Point-in-time, read-only view of the AV-65 arbiter panel: the
/// committee, the judgment threshold, and each member's current
/// effective vote (only members who have voted appear in `votes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArbiterPanelSnapshot {
    /// How many members sit on the panel (`1..=8`).
    pub n: u8,
    /// How many matching votes settle the dispute (`1..= n`).
    pub threshold: u8,
    /// The member keys in slot order.
    pub members: Vec<[u8; 32]>,
    /// The current effective vote per voting member, in slot order.
    pub votes: Vec<PanelVoteSnapshot>,
}

/// Point-in-time, read-only view of one AV-66 fee tier: the payout
/// floor it applies from and the basis-point rate for that bracket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeTierSnapshot {
    /// The smallest gross payout (in lamports) this tier applies to.
    pub min_amount: u64,
    /// The protocol-fee rate for payouts in this tier, in basis points.
    pub bps: u16,
}

/// Point-in-time, read-only view of the AV-66 tiered protocol-fee
/// schedule: the live tiers in slot order, so an off-chain indexer can
/// price any gross payout with the same ladder the chain charges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeScheduleSnapshot {
    /// How many tiers are live (`1..=8` when the schedule is present).
    pub tier_count: u8,
    /// The live tiers in slot order (strictly ascending floors).
    pub tiers: Vec<FeeTierSnapshot>,
}

/// Point-in-time, read-only view of an [`Escrow`]. Built by
/// [`Escrow::snapshot`]; serialized by [`EscrowSnapshot::to_json`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowSnapshot {
    /// The `now` (Unix seconds) the snapshot was taken at. All
    /// time-derived fields (`vested`, `claimable`, `expiry_eligible`)
    /// are evaluated at this clock.
    pub at: u64,
    /// The escrow initializer (refund recipient by default).
    pub initializer: [u8; 32],
    /// The escrow taker (payout recipient).
    pub taker: [u8; 32],
    /// Lifecycle state, as a canonical lowercase name.
    pub state: &'static str,
    /// Total amount ever locked.
    pub amount: u64,
    /// Token decimal metadata (AV-28): the SPL mint's decimal places,
    /// `0` when none is declared. Feeds the `display_*` renderings in
    /// [`EscrowSnapshot::to_json`]; the raw amount fields are untouched.
    pub decimals: u8,
    /// Schema version of the vault's persisted layout (AV-75): the
    /// value [`Escrow::schema_version`] stamps — `0` means the vault
    /// was written before the field existed and has not migrated yet,
    /// so keeper/indexer tooling finds stale vaults from one snapshot.
    pub schema_version: u8,
    /// Whether the vault has a pending schema migration (AV-85):
    /// `schema_version < SCHEMA_VERSION` — the direct operator signal
    /// that the initializer should run `migrate_schema` (see
    /// [`crate::keeper::scan_schema_migrations`] for the dry-run
    /// verdict). `false` on a current vault.
    pub migration_pending: bool,
    /// Cumulative amount released to the taker so far.
    pub released: u64,
    /// Amount still locked: `amount - released - penalty_paid` (AV-82).
    /// This is what `cancel` / `cancel_expired` refund (skipped
    /// milestone tranches join it).
    pub remaining: u64,
    /// Unix seconds after which either party may cancel via
    /// `cancel_expired` (grace period applies separately).
    pub expires_at: u64,
    /// AV-21 grace period in seconds: the chain requires
    /// `now >= expires_at + grace_period`.
    pub grace_period: u64,
    /// Whether the chain's `cancel_expired` expiry gate passes at
    /// [`EscrowSnapshot::at`]. Same predicate the keeper scan uses.
    pub expiry_eligible: bool,
    /// Dual-signature activation progress (AV-12).
    pub dual_sig: DualSigSnapshot,
    /// Quorum progress, or `None` for a plain two-party escrow (AV-04).
    pub quorum: Option<QuorumSnapshot>,
    /// Vesting schedule, or `None` when none is attached (AV-13).
    pub vesting: Option<VestingSnapshot>,
    /// Non-linear unlock curve tiers, or `None` when the schedule
    /// unlocks linearly (AV-90). Live tiers in unlock order.
    pub vesting_curve: Option<Vec<VestingTierSnapshot>>,
    /// Amount unlocked by the schedule at [`EscrowSnapshot::at`], or `0`
    /// when no vesting is configured.
    pub vested: u64,
    /// Amount the taker could `claim` right now: vested minus already
    /// released, saturating at zero. `0` without vesting.
    pub claimable: u64,
    /// Dispute arbiter, or `None` when none is attached (AV-14).
    pub arbiter: Option<[u8; 32]>,
    /// SPL token mint bound to this escrow, or `None` for native SOL
    /// (AV-16).
    pub mint: Option<[u8; 32]>,
    /// Token-2022 transfer-hook program declared for this escrow, or
    /// `None` when no hook is bound (AV-99).
    pub transfer_hook: Option<[u8; 32]>,
    /// Streaming fee rate in lamports per second of funded time
    /// (AV-100); `0` when no streaming fee is configured.
    pub streaming_fee_rate: u64,
    /// Cumulative streaming fee already charged across all payouts
    /// (AV-100).
    pub streaming_fees_accrued: u64,
    /// Protocol fee rate in basis points (AV-17).
    pub fee_bps: u16,
    /// Cumulative protocol fee charged across all payouts (AV-17).
    pub fees_paid: u64,
    /// Pinned protocol-fee recipient, or `None` when fees route to the
    /// program-level fee account (AV-44).
    pub fee_recipient: Option<[u8; 32]>,
    /// Absolute protocol-fee ceiling in lamports, or `0` when no cap
    /// was configured (AV-63): the effective fee per payout is
    /// `min(bps fee, fee_cap)` when nonzero.
    pub fee_cap: u64,
    /// Tiered protocol-fee schedule, or `None` when no schedule is
    /// configured (AV-66): the amount-to-rate ladder the fee uses
    /// instead of the flat `fee_bps` rate, so an off-chain indexer can
    /// price any payout without replaying the setup.
    pub fee_schedule: Option<FeeScheduleSnapshot>,
    /// Milestone plan progress, or `None` when none is attached
    /// (AV-15).
    pub milestones: Option<MilestoneSnapshot>,
    /// Subscription schedule progress with live per-period amounts, or
    /// `None` when none is attached (AV-56/AV-73).
    pub subscription: Option<SubscriptionSnapshot>,
    /// Cumulative amount skipped by mutual agreement (AV-15).
    pub skipped: u64,
    /// Dispute evidence commitment attached at `escalate`, or `None`
    /// when no evidence was supplied (AV-22).
    pub evidence_hash: Option<[u8; 32]>,
    /// Dispute-evidence Merkle root committed at `escalate`, or `None`
    /// when no multi-doc evidence was committed (AV-91 — the
    /// multi-doc alternative/supplement to `evidence_hash`).
    pub evidence_root: Option<[u8; 32]>,
    /// The committed evidence leaf count (`0` when `evidence_root` is
    /// `None`), and the number of documents disclosed via
    /// `file_evidence` — `(disclosed, total)`, or `None` when no root
    /// was committed (AV-91).
    pub evidence_disclosure: Option<(u64, u8)>,
    /// Dispute-evidence disclosure deadline in seconds, or `0` when no
    /// deadline was configured (AV-68 — see
    /// [`Escrow::with_evidence_deadline`]).
    pub evidence_deadline_secs: u64,
    /// Which party escalated into `Disputed` — the party the disclosure
    /// deadline binds — or `None` when the escrow was never disputed
    /// (AV-68).
    pub escalated_by: Option<[u8; 32]>,
    /// The arbiter's rationale-document commitment attached at
    /// `resolve`, or `None` when the arbiter supplied no rationale
    /// (AV-38). Only `Some` on a `Settled` escrow — never cleared, so
    /// the snapshot keeps the audit trail of the arbitration.
    pub rationale_hash: Option<[u8; 32]>,
    /// Whitelisted refund destination, or `None` when no whitelist is
    /// configured (AV-23).
    pub refund_to: Option<[u8; 32]>,
    /// The address refunds actually go to: the whitelist when
    /// configured, else the initializer (AV-23).
    pub refund_recipient: [u8; 32],
    /// Anti-griefing penalty rate in basis points charged on
    /// taker-initiated `cancel_expired` (AV-24).
    pub penalty_bps: u16,
    /// Timelock unlock timestamp, or `0` when no timelock is configured
    /// (AV-27).
    pub unlock_at: u64,
    /// Whether the chain's payout gates (`release` / `claim` /
    /// `release_milestone`) pass the timelock at [`EscrowSnapshot::at`]:
    /// `at >= unlock_at`. Same predicate the keeper scan uses (AV-27).
    pub unlock_eligible: bool,
    /// Relative timelock duration in seconds, or `0` when no relative
    /// timelock is configured (AV-64): payouts unlock at
    /// `fund_at + relative_timelock_secs`.
    pub relative_timelock_secs: u64,
    /// Unix timestamp at which the escrow was funded, or `0` when never
    /// funded (AV-64): the origin the relative timelock is measured from.
    pub fund_at: u64,
    /// Payout destination allowlist, or `None` when no allowlist is
    /// configured (AV-49). When `Some`, every fund-moving transition
    /// requires its `payout_to` to be a member.
    pub payout_allowlist: Option<Vec<[u8; 32]>>,
    /// AV-96: the payout destination denylist (`None` = no veto).
    pub payout_denylist: Option<Vec<[u8; 32]>>,
    /// CPI target-program allowlist, or `None` when no allowlist is
    /// configured (AV-83). When `Some`, a `release_via_cpi` whose
    /// target program is outside the list is rejected.
    pub cpi_allowlist: Option<Vec<[u8; 32]>>,
    /// Bound multisig authority, or `None` when no multisig binding is
    /// configured (AV-84). The multisig program id, the vault PDA that
    /// must sign, and the threshold metadata — read-only pass-through
    /// for keepers and indexers, never a check gate.
    pub multisig_authority: Option<MultisigAuthority>,
    /// Opt-in 32-byte off-chain reference memo (e.g. order id / invoice
    /// hash) bound at setup via [`Escrow::with_reference`], or `None`
    /// when no reference was attached (AV-53). Read-only pass-through
    /// for off-chain reconciliation — never read by a check gate.
    pub reference: Option<[u8; 32]>,
    /// The retained on-chain event history (AV-57), oldest first: the
    /// valid ring window ([`Escrow::event_history`]) — kind, timestamp
    /// and actor summary per entry. Empty for an escrow whose
    /// transitions never went through the event-logging adapter.
    pub event_history: Vec<EventHistoryEntry>,
    /// The ring's configured capacity at snapshot time (AV-57):
    /// 1..=64, 64 by default.
    pub event_capacity: u8,
    /// The monotonic total of events ever recorded at snapshot time
    /// (AV-57): `total - event_history.len()` entries aged out of the
    /// retained window.
    pub event_total: u64,
    /// AV-59: the per-extension expiry-increase bound in seconds
    /// (`0` = extension disabled).
    pub max_extension_secs: u64,
    /// AV-59: how many times the deadline was extended via
    /// `extend_expiry` (saturating).
    pub extension_count: u64,
    /// AV-65: the arbiter panel, or `None` when no panel is configured
    /// (single-arbiter mode or no arbitration). Carries the committee,
    /// the M-vote threshold, and each voting member's current effective
    /// vote — so an off-chain indexer can tally the live multisig
    /// judgment without replaying the vote events.
    pub arbiter_panel: Option<ArbiterPanelSnapshot>,
    /// AV-82: the opt-in default-penalty (slash) terms, or `None` when
    /// no slash clause is configured. Carries the penalty sink and the
    /// slash deadline — so an off-chain indexer can watch for
    /// slash-eligible escrows without replaying the setup events.
    pub slash_terms: Option<SlashTermsSnapshot>,
    /// AV-82: cumulative amount slashed to the penalty account (`0`
    /// when never slashed). Kept separate from `released` — the audit
    /// trail distinguishes a default penalty from a taker payout.
    pub penalty_paid: u64,
    /// AV-82: whether [`Escrow::slash`](crate::Escrow::slash) could
    /// succeed at [`EscrowSnapshot::at`] — the keeper scan lists
    /// exactly these escrows.
    pub slash_eligible: bool,
    /// AV-86: the opt-in slash-appeal window in seconds (`0` = no
    /// window configured — a slash is then final).
    pub appeal_window_secs: u64,
    /// AV-86: the Unix timestamp at which the taker's appeal window
    /// closes (`0` = no slash executed under a configured window).
    pub appeal_deadline: u64,
    /// AV-86: the slash appeal's lifecycle state — `None` until the
    /// taker files, `Filed` while the arbiter panel reviews, terminally
    /// `Upheld`, `Overturned`, or `Expired` (AV-103: the window lapsed
    /// unresolved and the sweep closed it).
    pub appeal_state: AppealState,
    /// AV-86: whether [`Escrow::file_appeal`](crate::Escrow::file_appeal)
    /// could succeed at [`EscrowSnapshot::at`] — the keeper scan lists
    /// exactly these escrows for `file_appeal`.
    pub appeal_eligible: bool,
    /// AV-103: the opt-in appeal bond configured via
    /// [`Escrow::with_appeal_bond`](crate::Escrow::with_appeal_bond)
    /// (`0` = no bond — filing stays free).
    pub appeal_bond: u64,
    /// AV-103: the appeal bond locked by the taker at filing (`0`
    /// when no appeal is in flight, or after the appeal resolved or
    /// expired). Independent counter — never mixed into `released`
    /// or `penalty_paid`.
    pub appeal_bond_paid: u64,
    /// AV-103: whether
    /// [`Escrow::expire_appeal`](crate::Escrow::expire_appeal) could
    /// succeed at [`EscrowSnapshot::at`] — the keeper scan lists
    /// exactly these escrows for `expire_appeal`.
    pub appeal_expiry_eligible: bool,
    /// AV-104: the live operator grant
    /// ([`Escrow::delegate_authority`](crate::Escrow::delegate_authority))
    /// as `(operator key, scope bitmap)` — `None` when no grant is
    /// live, so indexers see who may act for the escrow.
    pub delegation: Option<([u8; 32], u32)>,
    /// AV-105: the atomic-swap counterparty's escrow id
    /// ([`link_swap`](crate::link_swap)) — `None` when the escrow is
    /// not linked into a swap pair, so indexers see which two vaults
    /// settle as one.
    pub swap_link: Option<[u8; 32]>,
    /// AV-106: whether the penalty insurance pool is opted in (see
    /// [`Escrow::with_insurance_pool`](crate::Escrow::with_insurance_pool)).
    pub insurance_pool: bool,
    /// AV-106: the insurance pool balance — slashed penalties and
    /// forfeited appeal bonds held in neutral custody (`0` when the
    /// pool is not opted in or empty).
    pub pool_paid: u64,
    /// AV-106: the principal currently held in the pool (the
    /// slash-to-pool inflow net of overturn reversals).
    pub pool_slashed: u64,
    /// AV-106: cumulative pool inflow — every slash-to-pool and
    /// bond-forfeit-to-pool credit.
    pub pool_inflow: u64,
    /// AV-106: the pool's outflow line — `pool_inflow - pool_paid`
    /// (overturn restitution plus authorized payouts).
    pub pool_outflow: u64,
    /// AV-106: cumulative authorized pool payouts via
    /// [`Escrow::pool_payout`](crate::Escrow::pool_payout).
    pub pool_payout_paid: u64,
    /// AV-106: whether [`Escrow::pool_payout`](crate::Escrow::pool_payout)
    /// could succeed at [`EscrowSnapshot::at`] — the keeper scan lists
    /// exactly these escrows for `pool_payout`.
    pub pool_payout_eligible: bool,
    /// AV-107: the configured annual interest rate in basis points
    /// (`0` when interest is not enabled).
    pub interest_rate_bps: u16,
    /// AV-107: the outstanding accrued interest — the taker's
    /// unsettled yield claim at [`EscrowSnapshot::at`].
    pub interest_accrued: u64,
    /// AV-107: cumulative interest paid out to the taker.
    pub interest_paid: u64,
    /// AV-108: the declared multi-recipient payout-split table —
    /// `None` when no split is configured, else the `(recipient,
    /// gross share)` pairs in payout order, so indexers see the
    /// immutable distribution set without replaying the setup.
    pub payout_split: Option<Vec<([u8; 32], u64)>>,
    /// AV-109: the dead-man's switch inactivity threshold in seconds
    /// (`0` when the switch is not configured).
    pub deadman_inactivity_secs: u64,
    /// AV-109: the dead-man's switch heir — `None` when the switch is
    /// not configured.
    pub deadman_heir: Option<[u8; 32]>,
    /// AV-109: the `now` of the most recent successful clock-bearing
    /// state transition (the inactivity clock).
    pub deadman_last_activity: u64,
    /// AV-109: whether `claim_deadman` could succeed at
    /// [`EscrowSnapshot::at`] — the keeper scan lists exactly these
    /// escrows for `claim_deadman`.
    pub deadman_eligible: bool,
    /// AV-110: cumulative lamports ever topped up into this vault's
    /// rent balance via [`Escrow::top_up_rent`](crate::Escrow::top_up_rent)
    /// — the on-chain half of the AV-43 rent-health story, so an
    /// off-chain indexer can reconcile top-up events against the
    /// vault's counter without replaying the transitions.
    pub rent_topped_up_total: u64,
}

/// AV-82: point-in-time, read-only view of the opt-in slash terms —
/// the penalty sink and the default deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlashTermsSnapshot {
    /// Where slashed funds go.
    pub penalty_account: [u8; 32],
    /// Unix seconds after which `slash` becomes eligible.
    pub slash_deadline: u64,
}

impl Escrow {
    /// Take a point-in-time, read-only snapshot of this escrow at `now`.
    /// Pure read: the escrow is borrowed, no state changes, no events —
    /// a keeper or indexer can call this on every watched escrow on
    /// every scan without side effects.
    pub fn snapshot(&self, now: u64) -> EscrowSnapshot {
        let milestones = self.milestone_plan().map(|plan| {
            let count = plan.count() as usize;
            let mut settled = 0usize;
            let mut confirmed = 0usize;
            let mut tranches = Vec::with_capacity(count);
            for i in 0..count {
                let is_settled = self.milestone_settled(i);
                let is_confirmed = self.milestone_confirmed(i);
                if is_settled {
                    settled += 1;
                }
                if is_confirmed {
                    confirmed += 1;
                }
                tranches.push(MilestoneTrancheSnapshot {
                    index: i,
                    // The plan guarantees `Some` for `i < count`.
                    amount: plan.amount_at(i).unwrap_or(0),
                    confirmed: is_confirmed,
                    settled: is_settled,
                });
            }
            MilestoneSnapshot {
                count: plan.count(),
                total: plan.total(),
                settled,
                confirmed,
                next: self.next_milestone(),
                tranches,
            }
        });
        // AV-56/AV-73: subscription schedule progress. The per-period
        // amounts are the *live* table — what `release_period` will
        // actually pay — never the schedule's construction-time
        // uniform alone.
        let subscription = self.subscription_schedule().map(|schedule| {
            let count = schedule.periods as usize;
            let mut periods_detail = Vec::with_capacity(count);
            let mut total: u128 = 0;
            for i in 0..count {
                // `subscription_period_amount` is `Some` for `i <
                // periods` by construction.
                let amount = self.subscription_period_amount(i as u8).unwrap_or(0);
                total += amount as u128;
                periods_detail.push(SubscriptionPeriodSnapshot {
                    index: i as u8,
                    amount,
                    released: self.subscription_released_periods() & (1u64 << i) != 0,
                    due_at: self.subscription_period_due_at(i as u8).unwrap_or(0),
                });
            }
            let next_idx = self.subscription_next_period();
            SubscriptionSnapshot {
                periods: schedule.periods,
                period_secs: schedule.period_secs,
                per_period: schedule.per_period,
                total,
                next: if next_idx < schedule.periods {
                    Some(next_idx)
                } else {
                    None
                },
                periods_detail,
            }
        });
        EscrowSnapshot {
            at: now,
            initializer: self.initializer(),
            taker: self.taker(),
            state: state_name(self.state()),
            amount: self.amount(),
            decimals: self.decimals(),
            schema_version: self.schema_version(),
            // AV-85: the direct pending-migration signal — the snapshot
            // is how operators find stale vaults.
            migration_pending: self.schema_version() < Self::SCHEMA_VERSION,
            released: self.released_amount(),
            remaining: self.remaining_amount(),
            expires_at: self.expires_at(),
            grace_period: self.grace_period(),
            expiry_eligible: self.is_expiry_eligible(now),
            dual_sig: DualSigSnapshot {
                required: self.dual_sig_required(),
                initializer_activated: self.initializer_activated(),
                taker_activated: self.taker_activated(),
            },
            quorum: self.quorum().map(|q| QuorumSnapshot {
                registered: q.registered_count(),
                threshold: q.threshold(),
                approvals: q.approval_count(),
                approved_weight: q.approved_weight(),
                total_weight: q.total_weight(),
                satisfied: q.is_satisfied(),
            }),
            vesting: self.vesting_schedule().map(|s| VestingSnapshot {
                start: s.start(),
                end: s.end(),
            }),
            // AV-90: the unlock curve rides the export — `None` for the
            // plain linear schedule (backward compatible), else the
            // live tiers in unlock order.
            vesting_curve: self.vesting_curve().map(|c| {
                (0..c.tier_count() as usize)
                    .map(|i| {
                        let (at, unlocked_bps) = c.tier(i).unwrap_or((0, 0));
                        VestingTierSnapshot { at, unlocked_bps }
                    })
                    .collect()
            }),
            vested: self.vested_amount(now),
            claimable: self.claimable_amount(now),
            arbiter: self.arbiter(),
            mint: self.mint(),
            transfer_hook: self.transfer_hook(),
            streaming_fee_rate: self.streaming_fee_rate(),
            streaming_fees_accrued: self.streaming_fees_accrued(),
            fee_bps: self.fee_bps(),
            fees_paid: self.fees_paid(),
            fee_recipient: self.fee_recipient(),
            fee_cap: self.fee_cap(),
            // AV-66: the tiered fee schedule rides the export — `None`
            // when no schedule is configured (the flat `fee_bps` rate
            // applies), else the live tiers in slot order.
            fee_schedule: {
                let schedule = self.fee_schedule();
                if schedule.is_configured() {
                    Some(FeeScheduleSnapshot {
                        tier_count: schedule.tier_count,
                        tiers: schedule.tiers[..schedule.tier_count as usize]
                            .iter()
                            .map(|t| FeeTierSnapshot {
                                min_amount: t.min_amount,
                                bps: t.bps,
                            })
                            .collect(),
                    })
                } else {
                    None
                }
            },
            milestones,
            subscription,
            skipped: self.skipped_amount(),
            evidence_hash: self.evidence_hash(),
            // AV-91: the evidence Merkle commitment and the disclosure
            // progress ride the export, so an off-chain indexer (or
            // the arbiter panel) reads disclosure completeness from
            // one snapshot.
            evidence_root: self.evidence_root(),
            evidence_disclosure: self.evidence_disclosure(),
            // AV-68: the disclosure deadline and the escalating party
            // ride the export, so an off-chain indexer can compute the
            // disclosure status (pending / defaulted) from one
            // snapshot.
            evidence_deadline_secs: self.evidence_deadline_secs(),
            escalated_by: self.escalated_by(),
            rationale_hash: self.rationale_hash(),
            refund_to: self.refund_to(),
            refund_recipient: self.refund_recipient(),
            payout_allowlist: self
                .payout_allowlist()
                .map(|list| list.as_slice().to_vec()),
            // AV-96: the payout destination denylist rides the export
            // for reconciliation — read-only except through
            // `update_payout_denylist` (initializer's compliance veto).
            payout_denylist: self
                .payout_denylist()
                .map(|list| list.as_slice().to_vec()),
            // AV-83: the CPI target allowlist rides the export for
            // reconciliation — read-only, enforced by
            // `release_via_cpi`, never rewritten by a transition
            // except `update_cpi_allowlist`.
            cpi_allowlist: self.cpi_allowlist().map(|list| list.as_slice().to_vec()),
            // AV-84: the multisig authority binding rides the export
            // for reconciliation — read-only, immutable once set
            // (Uninitialized-only builder).
            multisig_authority: self.multisig_authority(),
            // AV-53: the off-chain reference memo rides the export for
            // reconciliation — read-only, never a gate input.
            reference: self.reference(),
            // AV-57: the retained event history rides the export, so
            // an off-chain indexer can read the full event window
            // from one snapshot.
            event_history: self.event_history(),
            event_capacity: self.event_capacity(),
            event_total: self.event_total(),
            // AV-59: the extension policy and history ride the export,
            // so an off-chain indexer can see the bound and how many
            // times the deadline moved.
            max_extension_secs: self.max_extension_secs(),
            extension_count: self.extension_count(),
            // AV-65: the arbiter panel rides the export — the committee,
            // the threshold, and each voting member's current effective
            // vote — so an off-chain indexer can tally the live multisig
            // judgment from one snapshot.
            arbiter_panel: self.arbiter_panel().map(|panel| {
                let n = panel.n as usize;
                let mut votes = Vec::new();
                for i in 0..n {
                    if panel.voted & (1 << i) != 0 {
                        votes.push(PanelVoteSnapshot {
                            member: panel.members[i],
                            taker_amount: panel.votes[i].taker_amount,
                            rationale_hash: panel.votes[i].rationale_hash,
                        });
                    }
                }
                ArbiterPanelSnapshot {
                    n: panel.n,
                    threshold: panel.threshold,
                    members: panel.members[..n].to_vec(),
                    votes,
                }
            }),
            penalty_bps: self.penalty_bps(),
            unlock_at: self.unlock_at(),
            unlock_eligible: self.is_unlock_eligible(now),
            // AV-64: the relative lock and its funding origin ride the
            // export, so an off-chain indexer can compute the same
            // unlock time the chain's payout gates enforce.
            relative_timelock_secs: self.relative_timelock_secs(),
            fund_at: self.fund_at(),
            // AV-82: the slash terms ride the export — `None` when no
            // slash clause is configured — plus the cumulative slashed
            // amount and the at-`now` slash eligibility the keeper
            // scan lists on.
            slash_terms: self.slash_terms().map(|t| SlashTermsSnapshot {
                penalty_account: t.penalty_account,
                slash_deadline: t.slash_deadline,
            }),
            penalty_paid: self.penalty_paid(),
            slash_eligible: self.is_slash_eligible(now),
            // AV-86: the appeal window, its deadline, the lifecycle
            // state and the at-`now` filing eligibility ride the export
            // — so an off-chain indexer can watch for appealable
            // slashes and live ballots without replaying the appeal
            // events.
            appeal_window_secs: self.appeal_window_secs(),
            appeal_deadline: self.appeal_deadline(),
            appeal_state: self.appeal_state(),
            appeal_eligible: self.is_appeal_eligible(now),
            // AV-103: the configured bond, the locked bond counter,
            // and the at-`now` expiry-sweep eligibility ride the
            // export — so an off-chain indexer can watch for bonded
            // appeals and lapsed windows without replaying the appeal
            // events.
            appeal_bond: self.appeal_bond(),
            appeal_bond_paid: self.appeal_bond_paid(),
            appeal_expiry_eligible: self.is_appeal_expired(now),
            // AV-104: the live operator grant, so the export shows who
            // may act for the escrow and with what scope.
            delegation: self.delegation().map(|g| (g.delegate(), g.scopes())),
            // AV-105: the swap counterparty id, so the export shows
            // the pair the escrow settles with.
            swap_link: self.swap_link(),
            // AV-106: the insurance-pool opt-in, the balance, the
            // pooled principal, the inflow/outflow lines and the
            // at-`now` payout eligibility ride the export — so an
            // off-chain indexer can watch the neutral pool without
            // replaying the slash / appeal / payout transitions.
            insurance_pool: self.insurance_pool(),
            pool_paid: self.pool_paid(),
            pool_slashed: self.pool_slashed(),
            pool_inflow: self.pool_inflow(),
            pool_outflow: self.pool_outflow(),
            pool_payout_paid: self.pool_payout_paid(),
            pool_payout_eligible: self.is_pool_payout_eligible(now),
            // AV-107: the interest-bearing tail rides the export — the
            // configured rate, the outstanding yield claim, and the
            // cumulative paid counter — so an off-chain indexer can
            // price the taker's yield without replaying the
            // settlement transitions.
            interest_rate_bps: self.interest_rate_bps(),
            interest_accrued: self.interest_accrued(),
            interest_paid: self.interest_paid(),
            // AV-108: the declared split table rides the export —
            // `None` when unconfigured, so a plain escrow's JSON is
            // unchanged.
            payout_split: {
                let split = self.payout_split();
                if split.is_configured() {
                    Some(split.as_slice())
                } else {
                    None
                }
            },
            // AV-109: the dead-man's switch tail rides the export —
            // the threshold, the heir and the activity clock — so an
            // off-chain indexer can watch the inactivity window
            // without replaying the transitions.
            deadman_inactivity_secs: self.deadman_inactivity_secs(),
            deadman_heir: self.deadman_heir(),
            deadman_last_activity: self.deadman_last_activity(),
            deadman_eligible: self.is_deadman_eligible(now),
            // AV-110: the rent top-up counter rides the export so an
            // off-chain indexer can reconcile `RentToppedUp` events
            // against the vault without replaying the transitions.
            rent_topped_up_total: self.rent_topped_up_total(),
        }
    }
}

/// Write an `Option<[u8; 32]>` as a 64-char lowercase hex string or
/// `null`.
fn write_opt_hex(s: &mut String, value: Option<[u8; 32]>) {
    match value {
        Some(v) => {
            s.push('"');
            s.push_str(&hex32(&v));
            s.push('"');
        }
        None => s.push_str("null"),
    }
}

impl EscrowSnapshot {
    /// Hand-serialized canonical JSON (the crate is dependency-free).
    /// Deterministic field order; 32-byte keys are 64-char lowercase
    /// hex; absent options are `null`. Byte-identical for equal state at
    /// equal `at`, so indexers can hash or diff snapshots directly.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(1024);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"initializer\":\"");
        s.push_str(&hex32(&self.initializer));
        s.push_str("\",\"taker\":\"");
        s.push_str(&hex32(&self.taker));
        s.push_str("\",\"state\":\"");
        s.push_str(self.state);
        // AV-75: the persisted schema version — operators find stale
        // (pre-migration) vaults from this field.
        s.push_str("\",\"schema_version\":");
        s.push_str(&self.schema_version.to_string());
        // AV-85: the direct pending-migration flag, next to the
        // version it derives from.
        s.push_str(",\"migration_pending\":");
        s.push_str(if self.migration_pending { "true" } else { "false" });
        s.push_str(",\"amount\":");
        s.push_str(&self.amount.to_string());
        // AV-28: token decimal metadata and the human-readable amount
        // renderings. The raw fields are untouched — operators and
        // indexers read the `display_*` companions; the chain moves the
        // raw values.
        s.push_str(",\"decimals\":");
        s.push_str(&self.decimals.to_string());
        s.push_str(",\"display_amount\":\"");
        s.push_str(&format_amount(self.amount, self.decimals));
        s.push_str("\",\"released\":");
        s.push_str(&self.released.to_string());
        s.push_str(",\"display_released\":\"");
        s.push_str(&format_amount(self.released, self.decimals));
        s.push_str("\",\"remaining\":");
        s.push_str(&self.remaining.to_string());
        s.push_str(",\"display_remaining\":\"");
        s.push_str(&format_amount(self.remaining, self.decimals));
        s.push_str("\",\"expires_at\":");
        s.push_str(&self.expires_at.to_string());
        s.push_str(",\"grace_period\":");
        s.push_str(&self.grace_period.to_string());
        s.push_str(",\"expiry_eligible\":");
        s.push_str(if self.expiry_eligible { "true" } else { "false" });
        // AV-12: dual-signature activation progress.
        s.push_str(",\"dual_sig\":{\"required\":");
        s.push_str(if self.dual_sig.required { "true" } else { "false" });
        s.push_str(",\"initializer_activated\":");
        s.push_str(if self.dual_sig.initializer_activated {
            "true"
        } else {
            "false"
        });
        s.push_str(",\"taker_activated\":");
        s.push_str(if self.dual_sig.taker_activated {
            "true"
        } else {
            "false"
        });
        s.push('}');
        // AV-04: quorum progress.
        s.push_str(",\"quorum\":");
        match self.quorum {
            Some(q) => {
                s.push_str("{\"registered\":");
                s.push_str(&q.registered.to_string());
                s.push_str(",\"threshold\":");
                s.push_str(&q.threshold.to_string());
                s.push_str(",\"approvals\":");
                s.push_str(&q.approvals.to_string());
                s.push_str(",\"approved_weight\":");
                s.push_str(&q.approved_weight.to_string());
                s.push_str(",\"total_weight\":");
                s.push_str(&q.total_weight.to_string());
                s.push_str(",\"satisfied\":");
                s.push_str(if q.satisfied { "true" } else { "false" });
                s.push('}');
            }
            None => s.push_str("null"),
        }
        // AV-13: vesting schedule and its position at `at`.
        s.push_str(",\"vesting\":");
        match self.vesting {
            Some(v) => {
                s.push_str("{\"start\":");
                s.push_str(&v.start.to_string());
                s.push_str(",\"end\":");
                s.push_str(&v.end.to_string());
                s.push('}');
            }
            None => s.push_str("null"),
        }
        // AV-90: the non-linear unlock curve tiers (`null` for the
        // plain linear schedule) — live tiers in unlock order.
        s.push_str(",\"vesting_curve\":");
        match &self.vesting_curve {
            Some(tiers) => {
                s.push('[');
                for (i, t) in tiers.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str("{\"at\":");
                    s.push_str(&t.at.to_string());
                    s.push_str(",\"unlocked_bps\":");
                    s.push_str(&t.unlocked_bps.to_string());
                    s.push('}');
                }
                s.push(']');
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"vested\":");
        s.push_str(&self.vested.to_string());
        s.push_str(",\"display_vested\":\"");
        s.push_str(&format_amount(self.vested, self.decimals));
        s.push_str("\",\"claimable\":");
        s.push_str(&self.claimable.to_string());
        s.push_str(",\"display_claimable\":\"");
        s.push_str(&format_amount(self.claimable, self.decimals));
        s.push_str("\",\"arbiter\":");
        write_opt_hex(&mut s, self.arbiter);
        s.push_str(",\"mint\":");
        write_opt_hex(&mut s, self.mint);
        // AV-99: the declared Token-2022 transfer-hook program — 64-char
        // lowercase hex or `null` — so indexers see the hook binding.
        s.push_str(",\"transfer_hook\":");
        write_opt_hex(&mut s, self.transfer_hook);
        // AV-100: the streaming-fee rate and accrued counter — plain
        // u64s, so indexers can track the fee schedule and its
        // consumption.
        s.push_str(",\"streaming_fee_rate\":");
        s.push_str(&self.streaming_fee_rate.to_string());
        s.push_str(",\"streaming_fees_accrued\":");
        s.push_str(&self.streaming_fees_accrued.to_string());
        s.push_str(",\"fee_bps\":");
        s.push_str(&self.fee_bps.to_string());
        s.push_str(",\"fees_paid\":");
        s.push_str(&self.fees_paid.to_string());
        s.push_str(",\"display_fees_paid\":\"");
        s.push_str(&format_amount(self.fees_paid, self.decimals));
        // AV-44: the pinned protocol-fee recipient — `null` when fees
        // route to the program-level fee account.
        s.push_str("\",\"fee_recipient\":");
        write_opt_hex(&mut s, self.fee_recipient);
        s.push_str(",\"fee_cap\":");
        s.push_str(&self.fee_cap.to_string());
        // AV-66: the tiered fee schedule — `null` when no schedule is
        // configured, else the live-tier count and the tiers in slot
        // order.
        s.push_str(",\"fee_schedule\":");
        match &self.fee_schedule {
            Some(sched) => {
                s.push_str("{\"tier_count\":");
                s.push_str(&sched.tier_count.to_string());
                s.push_str(",\"tiers\":[");
                for (i, t) in sched.tiers.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str("{\"min_amount\":");
                    s.push_str(&t.min_amount.to_string());
                    s.push_str(",\"bps\":");
                    s.push_str(&t.bps.to_string());
                    s.push('}');
                }
                s.push_str("]}");
            }
            None => s.push_str("null"),
        }
        // AV-15: milestone plan progress. (`fee_recipient` is self-
        // quoted-or-null via `write_opt_hex`, so no dangling quote to
        // close here — unlike the `display_*` fields above.)
        s.push_str(",\"milestones\":");
        match &self.milestones {
            Some(m) => {
                s.push_str("{\"count\":");
                s.push_str(&m.count.to_string());
                s.push_str(",\"total\":");
                s.push_str(&m.total.to_string());
                s.push_str(",\"settled\":");
                s.push_str(&m.settled.to_string());
                s.push_str(",\"confirmed\":");
                s.push_str(&m.confirmed.to_string());
                s.push_str(",\"next\":");
                match m.next {
                    Some(n) => s.push_str(&n.to_string()),
                    None => s.push_str("null"),
                }
                s.push_str(",\"tranches\":[");
                for (i, t) in m.tranches.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str("{\"index\":");
                    s.push_str(&t.index.to_string());
                    s.push_str(",\"amount\":");
                    s.push_str(&t.amount.to_string());
                    // AV-28: the tranche amount in human units.
                    s.push_str(",\"display_amount\":\"");
                    s.push_str(&format_amount(t.amount, self.decimals));
                    s.push_str("\",\"confirmed\":");
                    s.push_str(if t.confirmed { "true" } else { "false" });
                    s.push_str(",\"settled\":");
                    s.push_str(if t.settled { "true" } else { "false" });
                    s.push('}');
                }
                s.push_str("]}");
            }
            None => s.push_str("null"),
        }
        // AV-56/AV-73: subscription schedule progress with live
        // per-period amounts.
        s.push_str(",\"subscription\":");
        match &self.subscription {
            Some(sub) => {
                s.push_str("{\"periods\":");
                s.push_str(&sub.periods.to_string());
                s.push_str(",\"period_secs\":");
                s.push_str(&sub.period_secs.to_string());
                s.push_str(",\"per_period\":");
                s.push_str(&sub.per_period.to_string());
                s.push_str(",\"total\":");
                s.push_str(&sub.total.to_string());
                s.push_str(",\"next\":");
                match sub.next {
                    Some(n) => s.push_str(&n.to_string()),
                    None => s.push_str("null"),
                }
                s.push_str(",\"periods_detail\":[");
                for (i, p) in sub.periods_detail.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str("{\"index\":");
                    s.push_str(&p.index.to_string());
                    s.push_str(",\"amount\":");
                    s.push_str(&p.amount.to_string());
                    // AV-28: the period amount in human units.
                    s.push_str(",\"display_amount\":\"");
                    s.push_str(&format_amount(p.amount, self.decimals));
                    s.push_str("\",\"released\":");
                    s.push_str(if p.released { "true" } else { "false" });
                    s.push_str(",\"due_at\":");
                    s.push_str(&p.due_at.to_string());
                    s.push('}');
                }
                s.push_str("]}");
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"skipped\":");
        s.push_str(&self.skipped.to_string());
        s.push_str(",\"display_skipped\":\"");
        s.push_str(&format_amount(self.skipped, self.decimals));
        s.push_str("\",\"evidence_hash\":");
        write_opt_hex(&mut s, self.evidence_hash);
        // AV-91: the evidence Merkle root (`null` when no multi-doc
        // evidence was committed) and the disclosure progress
        // (`{"disclosed":n,"total":m}` or `null`) — the arbiter panel
        // reads disclosure completeness from the snapshot.
        s.push_str(",\"evidence_root\":");
        write_opt_hex(&mut s, self.evidence_root);
        s.push_str(",\"evidence_disclosure\":");
        match self.evidence_disclosure {
            Some((disclosed, total)) => {
                s.push_str("{\"disclosed\":");
                s.push_str(&disclosed.to_string());
                s.push_str(",\"total\":");
                s.push_str(&total.to_string());
                s.push('}');
            }
            None => s.push_str("null"),
        }
        // AV-68: the disclosure deadline (seconds; 0 = none configured)
        // and the escalating party (`null` when never disputed) — an
        // off-chain indexer derives the disclosure status from these.
        s.push_str(",\"evidence_deadline_secs\":");
        s.push_str(&self.evidence_deadline_secs.to_string());
        s.push_str(",\"escalated_by\":");
        write_opt_hex(&mut s, self.escalated_by);
        // AV-38: the arbiter's rationale-document commitment — `null`
        // until the arbiter attaches one at `resolve`.
        s.push_str(",\"rationale_hash\":");
        write_opt_hex(&mut s, self.rationale_hash);
        s.push_str(",\"refund_to\":");
        write_opt_hex(&mut s, self.refund_to);
        s.push_str(",\"refund_recipient\":\"");
        s.push_str(&hex32(&self.refund_recipient));
        s.push_str("\",\"penalty_bps\":");
        s.push_str(&self.penalty_bps.to_string());
        // AV-27: timelock.
        s.push_str(",\"unlock_at\":");
        s.push_str(&self.unlock_at.to_string());
        s.push_str(",\"unlock_eligible\":");
        s.push_str(if self.unlock_eligible { "true" } else { "false" });
        // AV-64: relative timelock duration and the funding timestamp
        // it is measured from.
        s.push_str(",\"relative_timelock_secs\":");
        s.push_str(&self.relative_timelock_secs.to_string());
        s.push_str(",\"fund_at\":");
        s.push_str(&self.fund_at.to_string());
        // AV-49: payout destination allowlist — `null` when none is
        // configured, else the allowlisted addresses as hex strings.
        s.push_str(",\"payout_allowlist\":");
        match &self.payout_allowlist {
            Some(addrs) => {
                s.push('[');
                for (i, a) in addrs.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push('"');
                    s.push_str(&hex32(a));
                    s.push('"');
                }
                s.push(']');
            }
            None => s.push_str("null"),
        }
        // AV-96: payout destination denylist — `null` when no veto is
        // configured, else the denied addresses as hex strings.
        s.push_str(",\"payout_denylist\":");
        match &self.payout_denylist {
            Some(addrs) => {
                s.push('[');
                for (i, a) in addrs.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push('"');
                    s.push_str(&hex32(a));
                    s.push('"');
                }
                s.push(']');
            }
            None => s.push_str("null"),
        }
        // AV-83: CPI target-program allowlist — `null` when none is
        // configured, else the allowlisted program ids as hex strings.
        s.push_str(",\"cpi_allowlist\":");
        match &self.cpi_allowlist {
            Some(addrs) => {
                s.push('[');
                for (i, a) in addrs.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push('"');
                    s.push_str(&hex32(a));
                    s.push('"');
                }
                s.push(']');
            }
            None => s.push_str("null"),
        }
        // AV-84: the bound multisig authority — `null` when no
        // multisig binding is configured, else the program id, the
        // authority PDA, and the threshold metadata.
        s.push_str(",\"multisig_authority\":");
        match &self.multisig_authority {
            Some(bound) => {
                s.push_str("{\"program_id\":\"");
                s.push_str(&hex32(&bound.program_id));
                s.push_str("\",\"authority\":\"");
                s.push_str(&hex32(&bound.authority));
                s.push_str("\",\"threshold\":");
                s.push_str(&bound.threshold.to_string());
                s.push('}');
            }
            None => s.push_str("null"),
        }
        // AV-53: the off-chain reference memo — 64-char lowercase hex
        // or `null` — for off-chain reconciliation.
        s.push_str(",\"reference\":");
        write_opt_hex(&mut s, self.reference);
        // AV-57: the retained event history — the ring's configured
        // capacity, the monotonic total, the valid-entry count, and
        // the entries oldest-first (kind name, timestamp, actor
        // summary as 16-char hex or `null`).
        s.push_str(",\"event_history\":{\"capacity\":");
        s.push_str(&self.event_capacity.to_string());
        s.push_str(",\"total\":");
        s.push_str(&self.event_total.to_string());
        s.push_str(",\"count\":");
        s.push_str(&self.event_history.len().to_string());
        s.push_str(",\"entries\":[");
        for (i, entry) in self.event_history.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"kind\":\"");
            s.push_str(entry.kind.name());
            s.push_str("\",\"at\":");
            s.push_str(&entry.at.to_string());
            s.push_str(",\"actor\":");
            match entry.actor {
                Some(summary) => {
                    s.push('"');
                    s.push_str(&hex8(&summary));
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            s.push('}');
        }
        s.push_str("]}");
        // AV-59: the expiry-extension bound and the renewal count — so
        // an off-chain indexer can see the policy and how many times
        // the deadline moved.
        s.push_str(",\"max_extension_secs\":");
        s.push_str(&self.max_extension_secs.to_string());
        s.push_str(",\"extension_count\":");
        s.push_str(&self.extension_count.to_string());
        // AV-65: the arbiter panel — `null` when no panel is configured,
        // else the committee (n, threshold, member keys) and each voting
        // member's current effective vote.
        s.push_str(",\"arbiter_panel\":");
        match &self.arbiter_panel {
            Some(p) => {
                s.push_str("{\"n\":");
                s.push_str(&p.n.to_string());
                s.push_str(",\"threshold\":");
                s.push_str(&p.threshold.to_string());
                s.push_str(",\"members\":[");
                for (i, m) in p.members.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push('"');
                    s.push_str(&hex32(m));
                    s.push('"');
                }
                s.push_str("],\"votes\":[");
                for (i, v) in p.votes.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str("{\"member\":\"");
                    s.push_str(&hex32(&v.member));
                    s.push_str("\",\"taker_amount\":");
                    s.push_str(&v.taker_amount.to_string());
                    s.push_str(",\"rationale_hash\":");
                    write_opt_hex(&mut s, v.rationale_hash);
                    s.push('}');
                }
                s.push_str("]}");
            }
            None => s.push_str("null"),
        }
        // AV-82: the slash terms — `null` when no slash clause is
        // configured, else the penalty sink and the slash deadline —
        // plus the cumulative slashed amount and the at-`now` slash
        // eligibility flag.
        s.push_str(",\"slash_terms\":");
        match &self.slash_terms {
            Some(t) => {
                s.push_str("{\"penalty_account\":\"");
                s.push_str(&hex32(&t.penalty_account));
                s.push_str("\",\"slash_deadline\":");
                s.push_str(&t.slash_deadline.to_string());
                s.push('}');
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"penalty_paid\":");
        s.push_str(&self.penalty_paid.to_string());
        s.push_str(",\"slash_eligible\":");
        s.push_str(if self.slash_eligible { "true" } else { "false" });
        // AV-86: the appeal window, deadline, lifecycle state and
        // filing eligibility — `appeal_state` renders as its canonical
        // snake_case name (the `EscrowEventKind::name` precedent).
        s.push_str(",\"appeal_window_secs\":");
        s.push_str(&self.appeal_window_secs.to_string());
        s.push_str(",\"appeal_deadline\":");
        s.push_str(&self.appeal_deadline.to_string());
        s.push_str(",\"appeal_state\":\"");
        s.push_str(match self.appeal_state {
            AppealState::None => "none",
            AppealState::Filed => "filed",
            AppealState::Upheld => "upheld",
            AppealState::Overturned => "overturned",
            AppealState::Expired => "expired",
        });
        s.push_str("\",\"appeal_eligible\":");
        s.push_str(if self.appeal_eligible { "true" } else { "false" });
        // AV-103: the bond config, the locked bond, and the
        // expiry-sweep eligibility.
        s.push_str(",\"appeal_bond\":");
        s.push_str(&self.appeal_bond.to_string());
        s.push_str(",\"appeal_bond_paid\":");
        s.push_str(&self.appeal_bond_paid.to_string());
        s.push_str(",\"appeal_expiry_eligible\":");
        s.push_str(if self.appeal_expiry_eligible {
            "true"
        } else {
            "false"
        });
        // AV-104: the live operator grant — null when no grant is
        // live, otherwise the operator's hex key and the scope bitmap,
        // so indexers see who may act for the escrow.
        s.push_str(",\"delegation\":");
        match self.delegation {
            None => s.push_str("null"),
            Some((operator, scopes)) => {
                s.push_str("{\"operator\":\"");
                s.push_str(&hex32(&operator));
                s.push_str("\",\"scopes\":");
                s.push_str(&scopes.to_string());
                s.push('}');
            }
        }
        // AV-105: the swap counterparty id — null when the escrow is
        // not linked into a swap pair.
        s.push_str(",\"swap_link\":");
        write_opt_hex(&mut s, self.swap_link);
        // AV-106: the insurance-pool opt-in, balance, pooled
        // principal, inflow/outflow lines, cumulative payouts, and
        // payout eligibility.
        s.push_str(",\"insurance_pool\":");
        s.push_str(if self.insurance_pool { "true" } else { "false" });
        s.push_str(",\"pool_paid\":");
        s.push_str(&self.pool_paid.to_string());
        s.push_str(",\"pool_slashed\":");
        s.push_str(&self.pool_slashed.to_string());
        s.push_str(",\"pool_inflow\":");
        s.push_str(&self.pool_inflow.to_string());
        s.push_str(",\"pool_outflow\":");
        s.push_str(&self.pool_outflow.to_string());
        s.push_str(",\"pool_payout_paid\":");
        s.push_str(&self.pool_payout_paid.to_string());
        s.push_str(",\"pool_payout_eligible\":");
        s.push_str(if self.pool_payout_eligible {
            "true"
        } else {
            "false"
        });
        // AV-107: the interest-bearing tail — rate, outstanding claim,
        // cumulative paid.
        s.push_str(",\"interest_rate_bps\":");
        s.push_str(&self.interest_rate_bps.to_string());
        s.push_str(",\"interest_accrued\":");
        s.push_str(&self.interest_accrued.to_string());
        s.push_str(",\"interest_paid\":");
        s.push_str(&self.interest_paid.to_string());
        // AV-108: declared split table — `null` when none is
        // configured, else the (recipient, share) pairs in payout
        // order with recipients as hex strings.
        s.push_str(",\"payout_split\":");
        match &self.payout_split {
            Some(shares) => {
                s.push('[');
                for (i, (recipient, amount)) in shares.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str("{\"recipient\":\"");
                    s.push_str(&hex32(recipient));
                    s.push_str("\",\"amount\":");
                    s.push_str(&amount.to_string());
                    s.push('}');
                }
                s.push(']');
            }
            None => s.push_str("null"),
        }
        // AV-109: the dead-man's switch tail — zeroed/`null`/`false`
        // when the switch is not configured, so a plain escrow's JSON
        // gains only the new keys.
        s.push_str(",\"deadman_inactivity_secs\":");
        s.push_str(&self.deadman_inactivity_secs.to_string());
        s.push_str(",\"deadman_heir\":");
        write_opt_hex(&mut s, self.deadman_heir);
        s.push_str(",\"deadman_last_activity\":");
        s.push_str(&self.deadman_last_activity.to_string());
        s.push_str(",\"deadman_eligible\":");
        s.push_str(&self.deadman_eligible.to_string());
        s.push_str(",\"rent_topped_up_total\":");
        s.push_str(&self.rent_topped_up_total.to_string());
        s.push('}');
        s
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::{MilestonePlan, QuorumPolicy, VestingSchedule};

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const A1: [u8; 32] = [0xA1; 32]; // attestors
    const A2: [u8; 32] = [0xA2; 32];
    const A3: [u8; 32] = [0xA3; 32];
    const MINT: [u8; 32] = [0xD0; 32];
    const ARBITER: [u8; 32] = [0xA8; 32];
    const AMOUNT: u64 = 1_000_000;
    const VEST_START: u64 = 1_700_000_000;
    const VEST_END: u64 = 1_800_000_000;
    const MID: u64 = 1_750_000_000; // half-vested
    const NEVER: u64 = u64::MAX; // no timeout

    fn funded(amount: u64, expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, amount, expires_at).unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        e
    }

    fn hex_of(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn plain_funded_snapshot_json_is_pinned() {
        let snap = funded(AMOUNT, 0).snapshot(MID);
        let expected = format!(
            "{{\
             \"at\":1750000000,\
             \"initializer\":\"{init}\",\"taker\":\"{taker}\",\
             \"state\":\"funded\",\
             \"schema_version\":3,\"migration_pending\":false,\
             \"amount\":1000000,\"decimals\":0,\"display_amount\":\"1000000\",\
             \"released\":0,\"display_released\":\"0\",\
             \"remaining\":1000000,\"display_remaining\":\"1000000\",\
             \"expires_at\":0,\"grace_period\":0,\"expiry_eligible\":true,\
             \"dual_sig\":{{\"required\":false,\"initializer_activated\":false,\"taker_activated\":false}},\
             \"quorum\":null,\
             \"vesting\":null,\"vesting_curve\":null,\"vested\":0,\"display_vested\":\"0\",\"claimable\":0,\"display_claimable\":\"0\",\
             \"arbiter\":null,\"mint\":null,\"transfer_hook\":null,\"streaming_fee_rate\":0,\"streaming_fees_accrued\":0,\
             \"fee_bps\":0,\"fees_paid\":0,\"display_fees_paid\":\"0\",\"fee_recipient\":null,\"fee_cap\":0,\"fee_schedule\":null,\
             \"milestones\":null,\"subscription\":null,\
             \"skipped\":0,\"display_skipped\":\"0\",\
             \"evidence_hash\":null,\"evidence_root\":null,\"evidence_disclosure\":null,\"evidence_deadline_secs\":0,\"escalated_by\":null,\"rationale_hash\":null,\"refund_to\":null,\"refund_recipient\":\"{init}\",\
             \"penalty_bps\":0,\"unlock_at\":0,\"unlock_eligible\":true,\"relative_timelock_secs\":0,\"fund_at\":1700000000,\"payout_allowlist\":null,\"payout_denylist\":null,\"cpi_allowlist\":null,\"multisig_authority\":null,\
             \"reference\":null,\
             \"event_history\":{{\"capacity\":64,\"total\":0,\"count\":0,\"entries\":[]}},\
             \"max_extension_secs\":0,\"extension_count\":0,\"arbiter_panel\":null,\
             \"slash_terms\":null,\"penalty_paid\":0,\"slash_eligible\":false,\
             \"appeal_window_secs\":0,\"appeal_deadline\":0,\"appeal_state\":\"none\",\"appeal_eligible\":false,\
             \"appeal_bond\":0,\"appeal_bond_paid\":0,\"appeal_expiry_eligible\":false,\
             \"delegation\":null,\"swap_link\":null,\
             \"insurance_pool\":false,\"pool_paid\":0,\"pool_slashed\":0,\
             \"pool_inflow\":0,\"pool_outflow\":0,\"pool_payout_paid\":0,\
             \"pool_payout_eligible\":false,\
             \"interest_rate_bps\":0,\"interest_accrued\":0,\"interest_paid\":0,\"payout_split\":null,\
             \"deadman_inactivity_secs\":0,\"deadman_heir\":null,\"deadman_last_activity\":1700000000,\
             \"deadman_eligible\":false,\"rent_topped_up_total\":0\
             }}",
            init = hex_of(0xAA),
            taker = hex_of(0xBB),
        );
        assert_eq!(snap.to_json(), expected);
    }

    #[test]
    fn snapshot_carries_schema_version() {
        // A fresh vault is born current.
        let snap = funded(AMOUNT, NEVER).snapshot(MID);
        assert_eq!(snap.schema_version, 3);
        assert!(!snap.migration_pending);
        assert!(snap.to_json().contains("\"schema_version\":3"));
        assert!(snap.to_json().contains("\"migration_pending\":false"));
        // A migrated vault's snapshot shows the new version.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER).unwrap();
        e.schema_version = 0; // simulate a pre-AV-75 vault
        let snap = e.snapshot(MID);
        assert_eq!(snap.schema_version, 0);
        // AV-85: the snapshot flags the pending migration outright.
        assert!(snap.migration_pending);
        assert!(snap.to_json().contains("\"schema_version\":0"));
        assert!(snap.to_json().contains("\"migration_pending\":true"));
        e.migrate_schema(ALICE).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.schema_version, 3);
        assert!(!snap.migration_pending);
        assert!(snap.to_json().contains("\"schema_version\":3"));
        assert!(snap.to_json().contains("\"migration_pending\":false"));
    }

    #[test]
    fn snapshot_is_dry_run_and_deterministic() {
        let e = funded(AMOUNT, NEVER);
        let before = e;
        let a = e.snapshot(MID).to_json();
        let b = e.snapshot(MID).to_json();
        assert_eq!(a, b, "equal state at equal `at` must serialize byte-identically");
        // The escrow is untouched: bit-identical afterwards (Escrow is
        // Copy + PartialEq, so this is exact).
        assert_eq!(e, before, "snapshot must not mutate the escrow");
    }

    #[test]
    fn vesting_position_is_derived_at_snapshot_time() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        // Before the schedule starts: nothing vested.
        let snap = e.snapshot(VEST_START - 1);
        assert_eq!(snap.vested, 0);
        assert_eq!(snap.claimable, 0);
        assert_eq!(snap.vesting, Some(VestingSnapshot { start: VEST_START, end: VEST_END }));
        // Halfway: half vested, all claimable (nothing released yet).
        let snap = e.snapshot(MID);
        assert_eq!(snap.vested, 500_000);
        assert_eq!(snap.claimable, 500_000);
        // After the schedule ends: fully vested.
        let snap = e.snapshot(VEST_END + 1);
        assert_eq!(snap.vested, AMOUNT);
        assert_eq!(snap.claimable, AMOUNT);
        let json = snap.to_json();
        assert!(
            json.contains("\"vesting\":{\"start\":1700000000,\"end\":1800000000}"),
            "vesting window must serialize, got: {json}"
        );
        assert!(json.contains("\"vested\":1000000,\"display_vested\":\"1000000\",\"claimable\":1000000,\"display_claimable\":\"1000000\""));
    }

    #[test]
    fn claimable_is_vested_minus_released() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        e.release(ALICE, 1_750_000_000, 200_000, None, BOB).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.released, 200_000);
        assert_eq!(snap.remaining, 800_000);
        assert_eq!(snap.claimable, 300_000); // 500_000 vested - 200_000 released
    }

    #[test]
    fn quorum_progress_is_derived() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_quorum(QuorumPolicy::new(&[A1, A2, A3], &[1, 1, 1], 2).unwrap())
            .unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        e.attest(A1).unwrap();
        let snap = e.snapshot(MID);
        let q = snap.quorum.expect("quorum must snapshot");
        assert_eq!(q.registered, 3);
        assert_eq!(q.threshold, 2);
        assert_eq!(q.approvals, 1);
        assert_eq!(q.approved_weight, 1);
        assert_eq!(q.total_weight, 3);
        assert!(!q.satisfied);
        let json = snap.to_json();
        assert!(
            json.contains("\"quorum\":{\"registered\":3,\"threshold\":2,\"approvals\":1,\"approved_weight\":1,\"total_weight\":3,\"satisfied\":false}"),
            "quorum progress must serialize, got: {json}"
        );
        // Satisfy it: the snapshot flips without any state transition.
        let mut e2 = e;
        e2.attest(A2).unwrap();
        let q2 = e2.snapshot(MID).quorum.expect("quorum must snapshot");
        assert!(q2.satisfied);
        assert_eq!(q2.approvals, 2);
    }

    #[test]
    fn milestone_progress_is_derived_per_tranche() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        // Both parties confirm tranche 0 for the release path.
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        let snap = e.snapshot(MID);
        let m = snap.milestones.as_ref().expect("plan must snapshot");
        assert_eq!(m.count, 2);
        assert_eq!(m.total, 1_000_000u128);
        assert_eq!(m.settled, 0);
        assert_eq!(m.confirmed, 1);
        assert_eq!(m.next, Some(0));
        assert_eq!(
            m.tranches[0],
            MilestoneTrancheSnapshot {
                index: 0,
                amount: 400_000,
                confirmed: true,
                settled: false,
            }
        );
        assert!(!m.tranches[1].confirmed);
        // Release tranche 0: it settles, tranche 1 becomes next. The
        // confirmation bits persist — they record that the tranche was
        // duly confirmed, even after settlement.
        e.release_milestone(ALICE, 1_750_000_000, 0, None, BOB).unwrap();
        let snap = e.snapshot(MID);
        let m = snap.milestones.as_ref().expect("plan must snapshot");
        assert_eq!(m.settled, 1);
        assert_eq!(m.confirmed, 1);
        assert_eq!(m.next, Some(1));
        assert_eq!(snap.released, 400_000);
        assert_eq!(snap.remaining, 600_000);
        let json = snap.to_json();
        assert!(
            json.contains("\"milestones\":{\"count\":2,\"total\":1000000,\"settled\":1,\"confirmed\":1,\"next\":1,\"tranches\":[{\"index\":0,\"amount\":400000,\"display_amount\":\"400000\",\"confirmed\":true,\"settled\":true},{\"index\":1,\"amount\":600000,\"display_amount\":\"600000\",\"confirmed\":false,\"settled\":false}]}"),
            "milestone progress must serialize, got: {json}"
        );
    }

    #[test]
    fn expiry_eligible_honors_the_grace_period() {
        const GRACE: u64 = 300;
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, MID)
            .unwrap()
            .with_grace_period(GRACE)
            .unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        assert!(!e.snapshot(MID).expiry_eligible);
        assert!(!e.snapshot(MID + GRACE - 1).expiry_eligible);
        assert!(e.snapshot(MID + GRACE).expiry_eligible);
        assert!(e.snapshot(MID).to_json().contains("\"expiry_eligible\":false"));
    }

    #[test]
    fn disputed_snapshot_carries_arbiter_and_evidence() {
        const EVIDENCE: [u8; 32] = [0xE1; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        e.escalate(BOB, MID, Some(EVIDENCE), None, 0).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.state, "disputed");
        assert_eq!(snap.arbiter, Some(ARBITER));
        assert_eq!(snap.evidence_hash, Some(EVIDENCE));
        let json = snap.to_json();
        assert!(json.contains(&format!("\"arbiter\":\"{}\"", hex_of(0xA8))));
        assert!(json.contains(&format!("\"evidence_hash\":\"{}\"", hex_of(0xE1))));
    }

    #[test]
    fn disputed_snapshot_carries_evidence_deadline_and_escalator() {
        // AV-68: the snapshot exports the disclosure deadline and the
        // escalating party, so an off-chain indexer derives the
        // disclosure status from one snapshot.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap()
            .with_evidence_deadline(3_600)
            .unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        e.escalate(BOB, MID, None, None, 0).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.evidence_deadline_secs, 3_600);
        assert_eq!(snap.escalated_by, Some(BOB));
        let json = snap.to_json();
        assert!(json.contains("\"evidence_deadline_secs\":3600"));
        assert!(json.contains(&format!("\"escalated_by\":\"{}\"", hex_of(0xBB))));
        // No deadline configured: zero + null.
        let mut plain = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        plain.fund(ALICE, VEST_START).unwrap();
        plain.escalate(ALICE, MID, None, None, 0).unwrap();
        let plain_snap = plain.snapshot(MID);
        assert_eq!(plain_snap.evidence_deadline_secs, 0);
        assert_eq!(plain_snap.escalated_by, Some(ALICE));
        let plain_json = plain_snap.to_json();
        assert!(plain_json.contains("\"evidence_deadline_secs\":0"));
        assert!(plain_json.contains(&format!("\"escalated_by\":\"{}\"", hex_of(0xAA))));
    }

    #[test]
    fn settled_snapshot_carries_rationale_hash() {
        // AV-38: once the arbiter attaches the rationale-document
        // commitment at `resolve`, the snapshot export carries it —
        // field and JSON — so keeper/indexer tooling can verify what
        // the ruling referenced without a second account read.
        const RATIONALE: [u8; 32] = [0xA1; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        e.escalate(BOB, MID, None, None, 0).unwrap();
        assert_eq!(e.snapshot(MID).rationale_hash, None);
        e.resolve(ARBITER, 400_000, None, Some(RATIONALE), BOB).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.state, "settled");
        assert_eq!(snap.rationale_hash, Some(RATIONALE));
        let json = snap.to_json();
        assert!(json.contains(&format!("\"rationale_hash\":\"{}\"", hex_of(0xA1))));
    }

    #[test]
    fn full_configuration_snapshot() {
        // Every opt-in feature on one escrow: the snapshot must carry
        // each of them, and the derived fields must agree.
        const WHITELIST: [u8; 32] = [0xC4; 32];
        // A finite expiry (grace periods are rejected on no-timeout
        // escrows), placed after the snapshot time so the escrow is not
        // expiry-eligible at MID.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, VEST_END + 1_000)
            .unwrap()
            .with_dual_sig()
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_mint(MINT)
            .unwrap()
            .with_protocol_fee(100)
            .unwrap()
            .with_grace_period(60)
            .unwrap()
            .with_refund_address(WHITELIST)
            .unwrap()
            .with_penalty_bps(500)
            .unwrap();
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.state, "funded");
        assert!(snap.dual_sig.required);
        assert!(snap.dual_sig.initializer_activated);
        assert!(snap.dual_sig.taker_activated);
        assert_eq!(snap.mint, Some(MINT));
        assert_eq!(snap.fee_bps, 100);
        assert_eq!(snap.fees_paid, 0);
        assert_eq!(snap.grace_period, 60);
        assert_eq!(snap.refund_to, Some(WHITELIST));
        assert_eq!(snap.refund_recipient, WHITELIST);
        assert_eq!(snap.penalty_bps, 500);
        assert_eq!(snap.vested, 500_000);
        assert_eq!(snap.claimable, 500_000);
        assert!(!snap.expiry_eligible); // MID < expires_at + grace
        // A 1% fee'd claim: fees accumulate on the snapshot too.
        e.claim(BOB, MID, Some(MINT), BOB).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.released, 500_000);
        assert_eq!(snap.fees_paid, 5_000); // 1% of 500_000
        assert_eq!(snap.remaining, 500_000);
        assert_eq!(snap.claimable, 0);
        let json = snap.to_json();
        assert!(json.contains(&format!("\"mint\":\"{}\"", hex_of(0xD0))));
        assert!(json.contains(&format!("\"refund_recipient\":\"{}\"", hex_of(0xC4))));
        assert!(json.contains("\"fee_bps\":100,\"fees_paid\":5000"));
        assert!(json.contains("\"penalty_bps\":500"));
    }

    #[test]
    fn terminal_states_snapshot_honestly() {
        let mut e = funded(AMOUNT, NEVER);
        e.release(ALICE, 1_750_000_000, AMOUNT, None, BOB).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.state, "released");
        assert_eq!(snap.released, AMOUNT);
        assert_eq!(snap.remaining, 0);
        assert_eq!(snap.claimable, 0);
    }

    #[test]
    fn split_parent_snapshots_honestly() {
        // AV-81: a split parent snapshots as "split" — the funds were
        // re-homed into the children, so the parent's remaining is its
        // pre-split remainder (preserved for audit, like the other
        // terminals).
        let mut e = funded(AMOUNT, NEVER);
        e.split_escrow(
            ALICE,
            BOB,
            &[600_000, 400_000],
            crate::SplitConfig::default(),
            MID,
        )
        .unwrap();
        assert_eq!(e.state(), EscrowState::Split);
        let snap = e.snapshot(MID);
        assert_eq!(snap.state, "split");
        assert_eq!(snap.remaining, AMOUNT);
        assert!(snap.to_json().contains("\"state\":\"split\""));
    }

    #[test]
    fn uninitialized_snapshot() {
        let e = Escrow::initialize(ALICE, BOB, AMOUNT, MID).unwrap();
        let snap = e.snapshot(0);
        assert_eq!(snap.state, "uninitialized");
        assert_eq!(snap.remaining, AMOUNT);
        assert!(!snap.expiry_eligible);
    }

    #[test]
    fn decimals_metadata_flows_into_the_snapshot() {
        // AV-28: a 6-decimal escrow's snapshot carries the metadata and
        // renders every shown amount in human units; the raw fields are
        // untouched for indexers.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_decimals(6)
            .unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        e.release(ALICE, MID, 250_000, None, BOB).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.decimals, 6);
        assert_eq!(snap.amount, AMOUNT);
        assert_eq!(snap.released, 250_000);
        assert_eq!(snap.remaining, 750_000);
        let json = snap.to_json();
        assert!(
            json.contains("\"decimals\":6,\"display_amount\":\"1.000000\""),
            "locked amount must render in human units, got: {json}"
        );
        assert!(
            json.contains("\"released\":250000,\"display_released\":\"0.250000\""),
            "released must render in human units, got: {json}"
        );
        assert!(
            json.contains("\"remaining\":750000,\"display_remaining\":\"0.750000\""),
            "remaining must render in human units, got: {json}"
        );
    }

    #[test]
    fn vesting_and_fee_amounts_render_with_decimals() {
        // AV-28: derived amounts (vested / claimable / fees_paid) use the
        // same rendering — one primitive, one rule.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_decimals(6)
            .unwrap()
            .with_protocol_fee(100)
            .unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.vested, 500_000);
        assert_eq!(snap.claimable, 500_000);
        let json = snap.to_json();
        assert!(json.contains("\"vested\":500000,\"display_vested\":\"0.500000\""), "got: {json}");
        assert!(
            json.contains("\"claimable\":500000,\"display_claimable\":\"0.500000\""),
            "got: {json}"
        );
        // A 1% fee'd claim: fees_paid renders too.
        e.claim(BOB, MID, None, BOB).unwrap();
        let json = e.snapshot(MID).to_json();
        assert!(
            json.contains("\"fees_paid\":5000,\"display_fees_paid\":\"0.005000\""),
            "fee rendering must follow the metadata, got: {json}"
        );
    }

    #[test]
    fn milestone_tranche_amounts_render_with_decimals() {
        // AV-28: per-tranche amounts in the milestone plan render in
        // human units as well.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap()
            .with_decimals(6)
            .unwrap();
        e.fund(ALICE, VEST_START).unwrap();
        let json = e.snapshot(MID).to_json();
        assert!(
            json.contains("\"amount\":400000,\"display_amount\":\"0.400000\""),
            "tranche 0 must render in human units, got: {json}"
        );
        assert!(
            json.contains("\"amount\":600000,\"display_amount\":\"0.600000\""),
            "tranche 1 must render in human units, got: {json}"
        );
    }

    #[test]
    fn snapshot_without_decimals_renders_bare_integers() {
        // Backward compatible: no metadata declared — every display
        // field is the bare integer, no decimal point.
        let snap = funded(AMOUNT, 0).snapshot(MID);
        assert_eq!(snap.decimals, 0);
        let json = snap.to_json();
        assert!(json.contains("\"display_amount\":\"1000000\""), "got: {json}");
        assert!(!json.contains("\"display_amount\":\"1."), "no decimal point without metadata");
    }

    #[test]
    fn snapshot_exports_the_retained_event_history() {
        // AV-57: the snapshot carries the ring's configured capacity,
        // the monotonic total, and the retained entries oldest-first —
        // one read gives an indexer the whole event window.
        use crate::{EscrowEventKind, IndexedEscrow};
        let mut indexed =
            IndexedEscrow::initialize(ALICE, BOB, AMOUNT, NEVER, [0x1D; 32], MID).unwrap();
        indexed.fund(ALICE, MID + 1).unwrap();
        let e = *indexed.inner();
        let snap = e.snapshot(MID);
        assert_eq!(snap.event_capacity, 64);
        assert_eq!(snap.event_total, 2);
        assert_eq!(snap.event_history.len(), 2);
        assert_eq!(snap.event_history[0].kind, EscrowEventKind::Initialized);
        assert_eq!(snap.event_history[0].at, MID);
        assert_eq!(snap.event_history[0].actor, Some([0xAA; 8]));
        assert_eq!(snap.event_history[1].kind, EscrowEventKind::Funded);
        assert_eq!(snap.event_history[1].at, MID + 1);
        let json = snap.to_json();
        assert!(
            json.contains("\"event_history\":{\"capacity\":64,\"total\":2,\"count\":2,\"entries\":[{\"kind\":\"initialized\",\"at\":1750000000,\"actor\":\"aaaaaaaaaaaaaaaa\"},{\"kind\":\"funded\",\"at\":1750000001,\"actor\":\"aaaaaaaaaaaaaaaa\"}]}"),
            "event history must serialize, got: {json}"
        );
    }

    #[test]
    fn snapshot_exports_empty_event_history_for_raw_escrows() {
        // A raw `Escrow` (transitions outside the IndexedEscrow
        // adapter) retains nothing: the export is honest about the
        // empty ring rather than omitting the field.
        let snap = funded(AMOUNT, NEVER).snapshot(MID);
        assert!(snap.event_history.is_empty());
        assert_eq!(snap.event_capacity, 64);
        assert_eq!(snap.event_total, 0);
        let json = snap.to_json();
        assert!(
            json.contains("\"event_history\":{\"capacity\":64,\"total\":0,\"count\":0,\"entries\":[]}"),
            "empty history must serialize, got: {json}"
        );
    }
    #[test]
    fn snapshot_exports_retuned_panel_threshold() {
        // AV-69 passthrough: the retuned M shows up in the panel
        // snapshot, and the JSON round-trips it.
        const M1: [u8; 32] = [0xC1; 32];
        const M2: [u8; 32] = [0xC2; 32];
        const M3: [u8; 32] = [0xC3; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, VEST_END)
            .unwrap()
            .with_arbiter_panel(&[M1, M2, M3], 3)
            .unwrap();
        e.update_panel_threshold(ALICE, BOB, 2).unwrap();
        let snap = e.snapshot(MID);
        let panel = snap.arbiter_panel.as_ref().expect("panel exported");
        assert_eq!(panel.n, 3);
        assert_eq!(panel.threshold, 2, "retuned M exported");
        assert_eq!(panel.members.len(), 3);
        assert!(panel.votes.is_empty(), "no votes yet");
        let json = snap.to_json();
        assert!(
            json.contains("\"threshold\":2"),
            "JSON carries the retuned M, got: {json}"
        );
    }

}
