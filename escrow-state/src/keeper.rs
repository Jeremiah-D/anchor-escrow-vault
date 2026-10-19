//! Off-chain keeper report (AV-20): scan a batch of escrows and emit the
//! executable `cancel_expired` / `claim` / `resolve` call list as JSON.
//!
//! A keeper bot watches many vaults and needs to know, at a given `now`,
//! which ones have an *immediately executable* keeper action:
//!
//! - `cancel_expired`: the escrow is `Funded`, the expiry gate passes at
//!   `now` (`now >= expires_at + grace_period` — see
//!   [`Escrow::is_expiry_eligible`]), and a refundable remainder exists.
//!   Either party may call it; the report names the initializer as the
//!   canonical caller (the taker may also call — the on-chain instruction
//!   accepts either). The grace period (AV-21) is honored here exactly as
//!   on-chain: the keeper never lists a `cancel_expired` call the chain
//!   would reject as `NotExpired`, which is the whole point of the grace
//!   period (keeper/cluster clock drift).
//! - `claim`: the escrow is `Funded`, a vesting schedule is attached, no
//!   milestone plan is attached (the plan owns the release schedule, so
//!   `claim` is disabled there), the vested-minus-released amount is
//!   positive, any configured quorum is satisfied, and the timelock
//!   (AV-27) is unlocked — otherwise the call would fail with
//!   `QuorumNotReached` / `TimelockNotReached` and would not be
//!   executable.
//! - `resolve` (AV-38): the escrow is `Disputed` with a configured
//!   arbiter and a positive remaining balance. Only the arbiter may
//!   call it; the report names the arbiter as the caller so an
//!   arbiter-operated keeper bot learns which disputes await its ruling.
//!   The taker/initializer split is the arbiter's judgment and the
//!   rationale-document commitment (AV-38) comes from the arbiter's
//!   off-chain deliberation, so neither is on the action — the keeper
//!   flags the escrow as awaiting resolution with the splittable pool
//!   (`amount`) and the bound mint; the arbiter supplies the split and
//!   the rationale hash at call time.
//! - `submit_panel_judgment` (AV-65): the escrow is `Disputed` with a
//!   configured arbiter panel and a positive remaining balance —
//!   panel mode, where the single-arbiter `resolve` is disabled. One
//!   action per panel member names that member as the caller
//!   (`caller_role: "panel_member"`) so a member-operated keeper bot
//!   learns which disputes await its vote; the split and the
//!   rationale-document commitment are the member's call-time
//!   judgment, so the action carries the splittable pool (`amount`)
//!   and the bound mint.
//! - `slash` (AV-82): the escrow is `Funded`, slash terms are
//!   configured, the slash deadline has passed at `now`, and the
//!   escrow was not slashed yet (see
//!   [`Escrow::is_slash_eligible`]). The initializer is the canonical
//!   caller; when an arbiter is configured, the neutral enforcer path
//!   is listed as a second action (`caller_role: "arbiter"`). The
//!   enforcement size is the caller's decision — the action carries
//!   the slashable remainder (`amount`), not a decided slash.
//!   AV-126: on a ladder escrow the deadline is the current rung's and
//!   the one-shot gate is bypassed — the ladder is the repeated-slash
//!   path, so a listed ladder slash stays listed after each rung is
//!   consumed (each rung is a separate enforcement, capped at the top
//!   rung once exhausted).
//! - `file_appeal` (AV-86): the taker appeals the executed slash inside
//!   the opt-in window (see [`Escrow::is_appeal_eligible`]) — the taker
//!   is the caller (`caller_role: "taker"`). Filing opens the panel's
//!   review (and locks the AV-103 appeal bond when one was
//!   configured).
//! - `review_appeal` (AV-86): a filed slash appeal awaits panel review
//!   (see [`Escrow::is_appeal_under_review`]) — one action per panel
//!   member who has not voted yet (`caller_role: "panel_member"`), so
//!   a member-operated keeper bot learns which appeals await its vote;
//!   the uphold/overturn judgment is the member's call-time decision.
//! - `expire_appeal` (AV-103): a filed slash appeal whose window lapsed
//!   unresolved (see [`Escrow::is_appeal_expired`]) — the
//!   permissionless sweep (`caller_role: "anyone"`) that closes the
//!   appeal and forfeits the locked bond to the initializer.
//!
//! AV-128: TWAP-gated escrows (`twap_gate` configured) are *not*
//! listed for `claim` / `release` by this scan — the gate's
//! time-weighted average depends on the oracle account's price
//! history, which the off-chain scan cannot evaluate without the
//! keeper-supplied feed. A keeper bot servicing TWAP-gated escrows
//! must fetch the oracle account's quote history itself (see
//! [`Escrow::require_twap_gate`]) and only submit the instruction
//! when the TWAP satisfies the gate; listing such an escrow here
//! would promise executability the scan cannot verify. The
//! `twap_gate` terms are visible on the snapshot (see
//! [`crate::snapshot::EscrowSnapshot`]) so the keeper can decide
//! whether to service the escrow.
//!
//! Every listed action carries the exact arguments the keeper needs to
//! build the instruction: `caller` (the signing key), `mint` (the bound
//! SPL mint, or `null` on the native-SOL path), `refund_to` (the refund
//! destination for `cancel_expired` — the escrow's whitelisted address
//! when configured, else the initializer; `null` for `claim`,
//! `resolve`, and `slash`), and `amount` (the refund the
//! `cancel_expired` call would return to the initializer, the gross
//! vested-but-unreleased amount a `claim` would move — the protocol
//! fee slices it, `payout + fee == amount` — the remaining locked
//! amount a `resolve` would split, or the slashable remainder a
//! `slash` would draw from).
//!
//! `Disputed` escrows list exactly the `resolve` action above in
//! single-arbiter mode — or one `submit_panel_judgment` action per
//! panel member in panel mode (AV-65) — the keeper has no standing to
//! move the undisputed remainder itself (AV-131: `release`/`claim`
//! stay initializer/taker-signed, so the keeper never lists them) —
//! and the scan never drops their state:
//! the dispute evidence hash attached at `escalate` (AV-22) stays
//! readable on the watched snapshot ([`Escrow::evidence_hash`]) so
//! operator tooling can fetch the off-chain evidence for the arbiter.
//!
//! # Dry-run by construction
//!
//! The scan only reads `&Escrow` snapshots: it cannot mutate anything,
//! emits no events, and touches no clock. Amounts are as of the scan — a
//! keeper executes the list, then re-scans.
//!
//! # Schema upgrades (AV-75, AV-85)
//!
//! Keeper scans are schema-agnostic: a pre-AV-75 v0 account is a
//! byte-prefix of the v1 layout (fields are only ever appended last),
//! so the scan reads both — none of the predicates above depend on the
//! schema version, and a vault awaiting [`Escrow::migrate_schema`]
//! keeps its keeper actions. Operators find stale vaults through the
//! AV-26 snapshot export: [`crate::EscrowSnapshot::schema_version`] is
//! `0` until the initializer migrates, [`Escrow::SCHEMA_VERSION`] after
//! (and [`crate::EscrowSnapshot::migration_pending`] flags the pending
//! migration outright).
//!
//! [`scan_schema_migrations`] is the migration-awareness scan: it
//! walks the watch list, dry-runs the AV-85 N → M migration chain
//! ([`Escrow::migrate_dry_run`]) for every vault below
//! [`Escrow::SCHEMA_VERSION`], and reports each vault's version path,
//! changed-fields list, and readiness — `ready` entries are executable
//! `migrate_schema` calls for the initializer to sign, blocked entries
//! name the reason (`"paused"` / `"corrupt"`). Dry-run by construction,
//! like every other scan here.
//!
//! # Output
//!
//! [`KeeperReport::to_json`] hand-serializes the report (the crate is
//! dependency-free): deterministic field order, keys as 64-char lowercase
//! hex, `mint` as a hex string or `null`. Actions keep the input order so
//! a keeper feeding a stable watch list gets a stable call list.
//!
//! # Rent-reclaim sweep (AV-40)
//!
//! A terminal-state vault (`Cancelled` / `Released` / `Settled`) has
//! served its purpose, but its rent-exempt deposit stays locked until
//! the account is closed — leaving it there would strand the deposit
//! forever. [`scan_closeable`] is the second scan: it walks the same
//! watch list and emits the executable `close_vault` call list for
//! terminal-state vaults, grouped per initializer signer into
//! [`CloseBatch`]es with a per-batch reclaimed-lamports total, and
//! serializable via [`CloseReport::to_json`] (same hand-rolled
//! deterministic style as the keeper report).
//!
//! Only *executable* calls are listed, exactly like the AV-20 scan: the
//! chain rejects `close_vault` from `Disputed` (AV-34: the arbitration
//! is still live and the vault account is the audit surface the arbiter
//! works from) and from `Closed` (the rent is already reclaimed), so
//! those two states are skipped — never listed — as are the
//! pre-terminal states (`Uninitialized` / `Funded` / `Activated`),
//! whose vault accounts have not served their purpose yet. The
//! canonical caller is the initializer: AV-34 restricts `close_vault`
//! to the initializer, checked before state validity, so it is the
//! only key the chain will accept.
//!
//! # Keeper milestone bundle execution (AV-76)
//!
//! [`scan_milestones`] is read-only; [`execute_milestone_bundle`] is the
//! write side — the keeper-side executor that turns a bundle of
//! `ReleaseMilestone` actions into real tranche releases on an
//! [`IndexedEscrow`]. It composes the existing `release_milestone`
//! instruction (already in the `INSTRUCTIONS` spec / IDL): no new
//! on-chain instruction exists, and the crate's IDL output is
//! unchanged.
//!
//! The executor takes an optional milestone-index subset: the keeper
//! may release just the tranches it wants settled now (e.g. the next
//! deliverable) while the rest stay pending and the vault stays
//! `Funded`. A subset equal to the full configured index set — or no
//! subset at all — is a full execution and may settle the vault; any
//! *proper* subset additionally emits
//! [`EscrowEventKind::BundlePartiallyExecuted`](crate::EscrowEventKind::BundlePartiallyExecuted)
//! after the per-tranche `MilestoneReleased` events, so indexers see
//! the partial settlement as one ordered unit.
//!
//! Atomicity is the AV-61 bundle-atomicity shape applied to keeper
//! execution: the subset executes all-or-nothing on a clone, in
//! ascending index order (matching the on-chain in-order settlement
//! gate). Any tranche failure — an unconfirmed milestone, a gate the
//! scan misjudged — returns the error with the caller's escrow
//! untouched: zero events leaked, state identical. Confirm/skip
//! actions are rejected: they are dual-signed governance, not keeper
//! execution.

use crate::{
    aggregate::EscrowAggregateView, format_amount, index::EscrowIndex, vault_close_rent_reclaimed,
    Escrow, EscrowError, EscrowState, IndexedEscrow, MultisigAuthority, SchemaFieldDelta,
    SignedReleaseIntent, VaultDerivation,
};
use super::cpi::{AccountMeta, Pubkey};
use super::discriminator::instruction_discriminator;
use super::execution_bundle::{JitoTipConfig, TipConfigError};
use super::tx_message::{
    compile_message, encode_base64, encode_message, ProgramInstruction, TxMessageError,
};

/// Render 32 bytes as 64 lowercase hex characters.
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// One watched escrow: a caller-supplied identity plus a read-only state
/// snapshot. The scan never mutates the snapshot (dry-run).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchedEscrow {
    /// Caller-supplied 32-byte escrow identity. The Anchor layer uses the
    /// vault PDA's public key — the same convention as
    /// [`crate::IndexedEscrow`]'s `escrow_id`.
    pub escrow_id: [u8; 32],
    /// Read-only snapshot of the escrow's state.
    pub escrow: Escrow,
    /// AV-53: the opt-in 32-byte off-chain reference memo for this
    /// watch entry — the operator copies [`Escrow::reference`] when
    /// building the watch list. The scan carries it onto every emitted
    /// action so the keeper report JSON can join the action back to
    /// the operator's off-chain order/invoice record. `None` when the
    /// escrow carries no reference. Read-only: it never affects which
    /// actions are listed.
    pub reference: Option<[u8; 32]>,
    /// AV-92: opt-in PDA derivation inputs for this vault (see
    /// [`VaultDerivation`]). Recorded via
    /// [`WatchedEscrow::with_vault_seeds`]; the scan derives the
    /// canonical vault address from them and attaches it to every
    /// emitted action as [`KeeperAction::vault_address`]. `None` when
    /// the operator did not record seeds — the scan still lists the
    /// same actions, just without the precomputed address. Real
    /// Solana PDAs never store their seeds on-chain, so this stays
    /// off-chain by design; the [`Escrow`] layout is untouched.
    pub vault_derivation: Option<VaultDerivation>,
    /// AV-123: the signed, unsubmitted gasless-release intent the
    /// keeper holds for this escrow (see
    /// [`WatchedEscrow::with_pending_intent`]). Off-chain by design:
    /// a submitted intent lives only in the transaction, never in
    /// the vault account — the keeper records the intent it is
    /// holding here, and [`scan_keeper_actions`] annotates the
    /// escrow as intent-release-ready on the report. `None` when the
    /// keeper holds no intent for this escrow.
    pub pending_intent: Option<SignedReleaseIntent>,
}

impl WatchedEscrow {
    /// Opt-in builder recording the vault's PDA derivation inputs
    /// (seeds + program id). Validates the seeds against the Solana
    /// `create_program_address` limits
    /// ([`EscrowError::InvalidVaultSeeds`] on violation).
    pub fn with_vault_seeds(
        mut self,
        seeds: &[&[u8]],
        program_id: &[u8; 32],
    ) -> Result<Self, EscrowError> {
        self.vault_derivation = Some(VaultDerivation::new(seeds, program_id)?);
        Ok(self)
    }

    /// The canonical vault PDA derived from the recorded seeds, or
    /// `None` when no seeds were recorded (or no bump qualifies —
    /// practically impossible).
    pub fn vault_address(&self) -> Option<[u8; 32]> {
        self.vault_derivation.and_then(|d| d.address())
    }

    /// AV-123: record the signed, unsubmitted gasless-release intent
    /// the keeper is holding for this escrow (the initializer's
    /// off-chain signature over the intent's canonical bytes — see
    /// [`ReleaseIntent`]). Off-chain metadata, like
    /// [`WatchedEscrow::with_vault_seeds`]: the signature is
    /// re-verified at scan time ([`scan_keeper_actions`] annotates
    /// only intents that verify against the escrow's initializer
    /// key and carry a fresh nonce) and again at submit time by
    /// [`Escrow::release_via_intent`](crate::Escrow::release_via_intent)
    /// — recording here never confers authority.
    pub fn with_pending_intent(mut self, signed: SignedReleaseIntent) -> Self {
        self.pending_intent = Some(signed);
        self
    }
}

/// The keeper-callable action for one escrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeeperActionKind {
    /// `cancel_expired(authority, now, mint)`.
    CancelExpired,
    /// `crank_expired(caller, now, mint)` (AV-48): the permissionless
    /// expiry crank. Listed alongside `CancelExpired` for expired
    /// escrows so a keeper bot that is party to nothing can sweep
    /// timed-out vaults — the caller is `"anyone"` (see
    /// [`KeeperAction::caller`]), never the escrow's parties. The
    /// refund destination is the same pinned address as the party
    /// path's; AV-124: when the initializer opted into the keeper
    /// bounty the cranker additionally receives
    /// [`KeeperAction::bounty_lamports`] — without the bounty the
    /// cranker receives nothing (the AV-48 behavior).
    CrankExpired,
    /// `claim(taker, now, mint)`.
    Claim,
    /// `resolve(arbiter, taker_amount, mint, rationale_hash)` (AV-38):
    /// the arbiter's settlement of a `Disputed` escrow. Listed so an
    /// arbiter-operated keeper bot learns which disputes await its
    /// ruling; the taker/initializer split and the rationale-document
    /// commitment are the arbiter's call-time judgment, not keeper
    /// inputs.
    Resolve,
    /// `submit_panel_judgment(member, taker_amount, mint,
    /// rationale_hash)` (AV-65): one panel member's judgment on a
    /// `Disputed` escrow. Listed once per panel member so a
    /// member-operated keeper bot learns which disputes await its
    /// vote; the split and the rationale-document commitment are the
    /// member's call-time judgment, not keeper inputs. The M-th
    /// matching vote settles the escrow automatically.
    PanelJudgment,
    /// `release_period(initializer, now, period_index, mint, payout_to)`
    /// (AV-56): the initializer's push of the next due subscription
    /// period. Listed for `Funded` escrows with an attached schedule
    /// whose next period is due at the scan time — strictly in order,
    /// one per scan.
    ReleasePeriod,
    /// `slash(authority, amount, mint, now)` (AV-82): the
    /// default-penalty enforcement on a `Funded` escrow whose taker
    /// missed the slash deadline. Listed when
    /// [`Escrow::is_slash_eligible`] holds at scan time — a listed
    /// slash is always executable, never a `Paused` or
    /// `SlashNotEligible` rejection. The initializer is the canonical
    /// keeper caller; when an arbiter is configured, the neutral
    /// enforcer path is listed as a second action. `amount` is the
    /// slashable remainder — the enforcement size is the caller's
    /// decision at call time; the keeper carries the pool.
    Slash,
    /// `file_appeal(taker, now)` (AV-86): the taker's appeal against
    /// the executed slash, inside the opt-in window. Listed when
    /// [`Escrow::is_appeal_eligible`] holds at scan time — a listed
    /// filing is always executable, never a `Paused` or
    /// `InvalidAppealWindow` rejection. The taker is the caller
    /// (`caller_role: "taker"`); filing moves no funds, it opens the
    /// panel's review. `amount` is the slashed penalty under appeal —
    /// informational, so the operator sees the stake, not a decided
    /// outcome.
    FileAppeal,
    /// `review_appeal(member, uphold, now)` (AV-86): one panel member's
    /// review vote on a filed slash appeal. Listed once per panel
    /// member who has not voted yet when
    /// [`Escrow::is_appeal_under_review`] holds at scan time, so a
    /// member-operated keeper bot learns which appeals await its vote;
    /// the uphold/overturn judgment is the member's call-time decision,
    /// not a keeper input. `amount` is the slashed penalty the ballot
    /// decides over.
    ReviewAppeal,
    /// `expire_appeal(caller, now)` (AV-103): the permissionless sweep
    /// of a filed slash appeal whose window lapsed unresolved. Listed
    /// when [`Escrow::is_appeal_expired`] holds at scan time — a listed
    /// sweep is always executable, never a `Paused` or
    /// `AppealExpiryNotDue` rejection. The caller is `"anyone"` (see
    /// [`KeeperAction::caller`]), never the escrow's parties — the
    /// forfeited bond routes to the initializer by rule, never the
    /// caller. `amount` is the locked appeal bond the sweep forfeits
    /// (`0` when no bond was configured — the sweep still closes the
    /// appeal); `refund_to` is `None` (the destination is the
    /// initializer by rule, like `slash`'s penalty account).
    ExpireAppeal,
    /// `pool_payout(authority, beneficiary, amount)` (AV-106): the
    /// arbiter- or multisig-authorized drain of the penalty insurance
    /// pool. Listed when [`Escrow::is_pool_payout_eligible`] holds at
    /// scan time — a listed payout is always executable, never a
    /// `Paused` or `InvalidPoolPayout` rejection. One action per
    /// authorized drainer: the arbiter (`caller_role: "arbiter"`)
    /// and/or the bound multisig authority PDA (`caller_role:
    /// "multisig_authority"` — the keeper proposes the payout to the
    /// multisig via
    /// [`validate_pool_payout_proposal`](crate::validate_pool_payout_proposal),
    /// it does not sign as the PDA). `amount` is the pool balance —
    /// the ceiling, not a decided payout; the beneficiary and the
    /// exact amount are the drainer's call-time judgment, so
    /// `refund_to` is `None`.
    PoolPayout,
    /// `claim_deadman(heir, now)` (AV-109): the configured heir's
    /// inactivity reclaim of a dormant escrow's remaining locked
    /// funds. Listed when [`Escrow::is_deadman_eligible`] holds at
    /// scan time — a listed claim is always executable, never a
    /// `Paused`, `Unauthorized`, `InvalidStateTransition`,
    /// `SwapLinkActive` or `DeadmanNotElapsed` rejection. The heir is
    /// the caller (`caller_role: "heir"`); the heir is deliberately
    /// not required to be either party (orthogonal to
    /// `cancel_expired`, where either party may cancel). `amount` is
    /// the remaining locked amount the call pays the heir;
    /// `refund_to` is the heir (the instruction's destination).
    ClaimDeadman,
    /// `fund_tranche(authority, tranche_amount, now)` (AV-111): the
    /// initializer's next funding tranche on a plan escrow. Listed
    /// when the plan is incomplete and a tranche slot remains — a
    /// listed call is always executable, never a `Paused`,
    /// `InvalidFundingPlan`, or `FundingTranchesExhausted` rejection.
    /// The initializer is the canonical keeper caller
    /// (`caller_role: "initializer"`); `amount` is the remaining
    /// unfunded target (`total_amount - funded_total`) — the ceiling
    /// for the next deposit, not a decided tranche size; and
    /// `funding_progress` passes the plan's live counters through so
    /// the operator's dashboard sees the funding state.
    FundTranche,
    /// `merge_escrows(authority)` (AV-114): the initializer's
    /// consolidation of two merge-compatible `Funded` escrows into
    /// one. Listed once per compatible pair per scan — the lower
    /// `escrow_id` survives as the merge target, the higher is the
    /// source (carried on [`KeeperAction::merge_source`]). A listed
    /// merge is always executable, never a `Paused`, `Unauthorized`,
    /// `InvalidStateTransition`, or `MergeIncompatible` rejection:
    /// the scan only pairs unpaused, unexpired, same-party,
    /// term-identical escrows (expiry-eligible escrows keep their
    /// cancel path instead). The initializer is the caller
    /// (`caller_role: "initializer"`); `amount` is the source's
    /// locked amount — the merged-in leg the surviving escrow
    /// absorbs.
    MergeEscrows,
}

impl KeeperActionKind {
    /// `pub(crate)` so the execution-plan builder (AV-33) can stamp the
    /// instruction name on planned instructions.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            KeeperActionKind::CancelExpired => "cancel_expired",
            KeeperActionKind::CrankExpired => "crank_expired",
            KeeperActionKind::Claim => "claim",
            KeeperActionKind::Resolve => "resolve",
            KeeperActionKind::PanelJudgment => "submit_panel_judgment",
            KeeperActionKind::ReleasePeriod => "release_period",
            KeeperActionKind::Slash => "slash",
            KeeperActionKind::FileAppeal => "file_appeal",
            KeeperActionKind::ReviewAppeal => "review_appeal",
            KeeperActionKind::ExpireAppeal => "expire_appeal",
            KeeperActionKind::PoolPayout => "pool_payout",
            KeeperActionKind::ClaimDeadman => "claim_deadman",
            KeeperActionKind::FundTranche => "fund_tranche",
            KeeperActionKind::MergeEscrows => "merge_escrows",
        }
    }
}

/// AV-135: the escrow's configured arbiter adjudication fee, passed
/// through on `Resolve` / `PanelJudgment` keeper actions. `Copy` like
/// the other small report structs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArbiterFeeTerms {
    /// The fixed lamport slice of the fee.
    pub flat_lamports: u64,
    /// The basis-point rate of the variable leg (`<= 10_000`).
    pub bps: u16,
}

/// One executable keeper call: everything needed to build the
/// instruction, nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeeperAction {
    /// Which escrow this call targets.
    pub escrow_id: [u8; 32],
    /// AV-92: the canonical vault PDA precomputed from the watch
    /// entry's recorded seeds ([`WatchedEscrow::with_vault_seeds`]) —
    /// the address the `initialize` instruction must create (or the
    /// existing vault's address, for live escrows). `None` when the
    /// operator recorded no seeds. Informational: it is never an
    /// instruction input and never affects which actions are listed.
    pub vault_address: Option<[u8; 32]>,
    /// Which transition to invoke.
    pub kind: KeeperActionKind,
    /// The key that must sign the call. AV-48: for `CrankExpired` actions
    /// this is the zero key — the crank is permissionless, so *no*
    /// specific key must sign; the keeper substitutes its own key when
    /// building the instruction. `caller_role` is `"anyone"` then.
    pub caller: [u8; 32],
    /// Which role `caller` plays: `"initializer"`, `"taker"`,
    /// `"arbiter"` (AV-38, `resolve` actions), `"panel_member"` (AV-65,
    /// `submit_panel_judgment` actions), or `"anyone"` (AV-48,
    /// `crank_expired` actions — the permissionless crank).
    pub caller_role: &'static str,
    /// The `mint` argument to pass: the escrow's bound mint, or `None`
    /// on the native-SOL path.
    pub mint: Option<[u8; 32]>,
    /// `cancel_expired`: the refund destination to pass — the escrow's
    /// whitelisted refund address when one is configured via
    /// [`Escrow::with_refund_address`], otherwise the initializer
    /// (AV-23: the state machine rejects any other destination with
    /// `RefundAddressMismatch`, so the keeper must build the
    /// instruction with exactly this address). `None` for `claim`
    /// actions, which pay the taker rather than refunding — and `None`
    /// for `resolve` / `submit_panel_judgment` actions, which split
    /// the remainder between the taker and the initializer rather
    /// than refunding to one address — and `None` for `slash` actions
    /// (AV-82), which pay the escrow's configured penalty account,
    /// not a refund destination.
    pub refund_to: Option<[u8; 32]>,
    /// `cancel_expired`: the refundable remainder the call would return
    /// to the initializer. `claim`: the gross vested-but-unreleased
    /// amount (the protocol fee slices it; `payout + fee == amount`).
    /// `resolve` (AV-38): the remaining locked amount the arbiter's
    /// split divides between the taker and the initializer — the split
    /// itself is the arbiter's judgment at call time.
    /// `submit_panel_judgment` (AV-65): the remaining locked amount the
    /// member's vote divides between the taker and the initializer —
    /// the split itself is the member's judgment at call time.
    /// Always `> 0` — zero-value actions are never listed.
    pub amount: u64,
    /// The escrow's token decimal metadata (AV-28): the SPL mint's
    /// decimal places, `0` when none is declared. Feeds the report's
    /// `display_amount` rendering only — the instruction itself always
    /// moves the raw `amount`.
    pub decimals: u8,
    /// The escrow's opt-in 32-byte off-chain reference memo (AV-53),
    /// copied from the [`WatchedEscrow`] entry at scan time — the
    /// operator's order id / invoice hash for off-chain reconciliation.
    /// Carried for correlation only: it is never an instruction input
    /// and never affects which actions are listed.
    pub reference: Option<[u8; 32]>,
    /// AV-59: how many times the escrow's deadline was extended via
    /// [`Escrow::extend_expiry`] (the monotonic `extension_count`).
    /// Surfaced so operators can see at a glance how many times an
    /// escrow's deadline moved — a heavily-extended escrow deserves a
    /// second look before the keeper sweeps it.
    pub extension_count: u64,
    /// AV-84: the escrow's bound multisig authority (`None` when no
    /// multisig binding is configured). When `Some` and the action's
    /// `caller` equals the bound authority PDA, the keeper must route
    /// the call through the multisig program (a Squads vault
    /// transaction) instead of signing directly — the PDA only signs
    /// once its threshold votes.
    pub multisig_authority: Option<MultisigAuthority>,
    /// AV-91: dispute-evidence disclosure progress `(disclosed,
    /// total)` — set on `resolve` and `submit_panel_judgment` actions
    /// (the `Disputed` branch), `None` on every other kind. The
    /// arbiter (or panel member) verifies disclosure completeness
    /// before judgment: `disclosed < total` means the escalating party
    /// is withholding committed evidence, and the judgment weight
    /// must deduct the undisclosed documents honestly.
    pub evidence_disclosure: Option<(u64, u8)>,
    /// AV-111: tranched-funding progress — set on `fund_tranche`
    /// actions, `None` on every other kind. The live plan counters
    /// (`funded_total`, `total_amount`, `tranches_used`,
    /// `max_tranches`) pass through to the report so the operator's
    /// dashboard sees the funding state; `amount` carries the
    /// remaining unfunded target (`total_amount - funded_total`) as
    /// the next tranche's ceiling.
    pub funding_progress: Option<FundingProgress>,
    /// Machine-readable reason: `"expired"`, `"vesting_unlocked"`,
    /// `"disputed"` (AV-38, `resolve` actions; AV-65,
    /// `submit_panel_judgment` actions),
    /// `"subscription_period_due"` (AV-56, `release_period` actions),
    /// `"funding_incomplete"` (AV-111, `fund_tranche` actions), or
    /// `"mergeable_pair"` (AV-114, `merge_escrows` actions).
    pub reason: &'static str,
    /// AV-114: the merge source escrow's id — set on
    /// [`KeeperActionKind::MergeEscrows`] actions (the higher
    /// `escrow_id` of the pair; the action's own `escrow_id` is the
    /// surviving target), `None` on every other kind. The Anchor
    /// `merge_escrows` instruction takes the source vault as its
    /// second account.
    pub merge_source: Option<[u8; 32]>,
    /// AV-115: the taker-initiated anti-griefing penalty estimate at
    /// scan time, in the escrow's smallest unit. Set on
    /// [`KeeperActionKind::CancelExpired`] /
    /// [`KeeperActionKind::CrankExpired`] actions as
    /// `expiry_cancel_penalty_at(remaining, scan_now)` — the
    /// compensation at stake if the taker (rather than the listed
    /// caller) executes the cancel, so the operator watches the
    /// escalation meter grow. `0` on every other kind, and `0` when
    /// no penalty is configured. Informational: it is never an
    /// instruction input and never affects which actions are listed.
    pub penalty_estimate: u64,
    /// AV-116: the first slot at which the AV-116 slot-based relative
    /// timelock opens (`fund_slot + slot_timelock_slots`), or `None`
    /// when no slot lock is configured. Set on every action from
    /// `slot_unlock_slot()` — `None` for the overwhelmingly common
    /// no-slot-lock escrow. Informational: it is never an instruction
    /// input and never affects which actions are listed — but a
    /// slot-locked escrow's `Claim` action additionally needs the
    /// chain to have reached this slot, so the operator watches the
    /// slot gate here rather than guessing from the wall clock.
    pub slot_unlock_at: Option<u64>,
    /// AV-124: the keeper bounty a successful `crank_expired` would
    /// pay the caller right now, in lamports
    /// ([`Escrow::keeper_bounty_payable`](crate::Escrow::keeper_bounty_payable)
    /// at scan time — `min(per_crank, pool)`). Set only on
    /// [`KeeperActionKind::CrankExpired`] actions; `0` on every other
    /// kind, and `0` on crank actions when no bounty is configured
    /// or the pool is exhausted (the AV-48 unpaid-crank case).
    /// Informational: it is never an instruction input and never
    /// affects which actions are listed — the operator (or their bot)
    /// reads the incentive before deciding to crank.
    pub bounty_lamports: u64,
    /// AV-124: true when the crank's bounty does not cover its
    /// estimated execution cost (`bounty_lamports <
    /// [`KeeperAction::estimated_execution_cost_lamports`]`). Set
    /// only on [`KeeperActionKind::CrankExpired`] actions; `false`
    /// on every other kind. An `unprofitable` crank is still listed
    /// — the scan lists every executable action, and the keeper may
    /// crank at a loss (altruistic sweep, or the bounty is only part
    /// of the incentive) — but the flag tells the operator the bounty
    /// alone does not pay for the transaction. Informational, like
    /// `bounty_lamports`.
    pub bounty_unprofitable: bool,
    /// AV-135: the escrow's configured arbiter adjudication fee
    /// ([`Escrow::with_arbiter_fee`]) — the flat lamport slice and
    /// the bps rate the settlement would deduct from the taker's
    /// adjudicated share and route to the arbiter. Set on
    /// [`KeeperActionKind::Resolve`] /
    /// [`KeeperActionKind::PanelJudgment`] actions; `None` on every
    /// other kind and when no fee is configured. Informational: it is
    /// never an instruction input and never affects which actions are
    /// listed — an arbiter-operated keeper bot reads the
    /// compensation before deciding to rule.
    pub arbiter_fee: Option<ArbiterFeeTerms>,
}

/// AV-111: the live tranched-funding counters passed through on a
/// [`KeeperActionKind::FundTranche`] action. `Copy` like the other
/// small report structs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundingProgress {
    /// Cumulative amount deposited so far.
    pub funded_total: u64,
    /// The plan's funding target (== the escrow's declared amount).
    pub total_amount: u64,
    /// Tranches consumed so far.
    pub tranches_used: u8,
    /// The plan's tranche budget.
    pub max_tranches: u8,
}

impl KeeperAction {
    /// AV-146: the [`Option`]-returning twin of
    /// [`estimated_compute_units`](Self::estimated_compute_units) —
    /// the batch claim sweep needs per-vault failure isolation
    /// (the batch.rs AV-37 precedent), so a missing CU-table row
    /// becomes a per-vault `failed` outcome instead of a panic.
    pub(crate) fn estimated_compute_units_opt(&self) -> Option<u64> {
        let mut accounts = 2; // vault + authority
        if matches!(
            self.kind,
            KeeperActionKind::CancelExpired | KeeperActionKind::CrankExpired
        ) && self.refund_to.is_some()
        {
            accounts += 1;
        }
        if self.mint.is_some() {
            accounts += 1;
        }
        super::cu_estimate::estimate_instruction_cu(self.kind.as_str(), accounts, 1)
    }

    /// AV-88: heuristic compute-unit estimate for this keeper call —
    /// the dry-run report's CU passthrough. The account count is the
    /// canonical planned shape (`vault` + `authority` + `refund_to`
    /// when the kind carries one + `mint` when set) — the same accounts
    /// [`plan_execution`](super::execution_plan::plan_execution) would
    /// stamp — and one signature is charged for the caller key (the
    /// permissionless crank's zero key is substituted by the keeper's
    /// own key at build time). A planning number, not a measured cost.
    pub fn estimated_compute_units(&self) -> u64 {
        self.estimated_compute_units_opt()
            // The cost table covers every keeper instruction kind — the
            // cu_estimate tests pin that — so this is unreachable on
            // real scans; the expect guards a hand-built kind.
            .expect("AV-88: CU table covers every keeper instruction kind")
    }

    /// AV-124: the estimated on-chain cost of executing this action,
    /// in lamports — the AV-88 compute-unit estimate priced at the
    /// planning-assumption priority fee (see
    /// [`KEEPER_ASSUMED_MICRO_LAMPORTS_PER_CU`]) plus the fixed base
    /// signature fee ([`KEEPER_BASE_SIGNATURE_FEE_LAMPORTS`]).
    /// Saturates instead of wrapping. A planning number, not a
    /// measured cost: the real inclusion price depends on the
    /// leader's current fee market, so the profitability annotation
    /// ([`KeeperAction::bounty_unprofitable`]) flags only the
    /// clear-cut case — a bounty below this estimate does not pay
    /// for the transaction under the assumed fee regime.
    pub fn estimated_execution_cost_lamports(&self) -> u64 {
        super::priority_fee::fee_budget_lamports(
            self.estimated_compute_units(),
            KEEPER_ASSUMED_MICRO_LAMPORTS_PER_CU,
        )
        .saturating_add(KEEPER_BASE_SIGNATURE_FEE_LAMPORTS)
    }
}

/// AV-124: the fixed Solana base fee per signature, in lamports —
/// the network's protocol constant (every transaction pays this for
/// its first signature, on top of any priority fee). The crank
/// transaction carries the caller's single signature, so the
/// profitability annotation charges it exactly once. Not a
/// heuristic: unlike the compute-unit price, this number does not
/// move with congestion.
pub const KEEPER_BASE_SIGNATURE_FEE_LAMPORTS: u64 = 5_000;

/// AV-124: the assumed price of compute for the keeper-bounty
/// profitability annotation, in micro-lamports per compute unit.
/// This is the crate's own priority-fee planning fallback
/// ([`super::priority_fee::DEFAULT_FALLBACK_MICRO_LAMPORTS_PER_CU`])
/// — the price the keeper assumes before it has a live recent-fee
/// feed — so the annotation and the
/// [`PriorityFeeOracle`](super::priority_fee::PriorityFeeOracle)
/// price compute identically by construction. A planning
/// assumption, not a measurement: an operator with a live fee feed
/// re-prices the comparison themselves; the scan only needs a
/// documented, reproducible baseline.
pub const KEEPER_ASSUMED_MICRO_LAMPORTS_PER_CU: u64 =
    super::priority_fee::DEFAULT_FALLBACK_MICRO_LAMPORTS_PER_CU;

/// AV-123: one scanned escrow carrying a signed, unsubmitted
/// gasless-release intent — the keeper-scan annotation for the
/// meta-transaction path. The relayer submits
/// [`Escrow::release_via_intent`](crate::Escrow::release_via_intent)
/// with any fee payer instead of waiting for a party-signed
/// `release`: the initializer's signature is already embedded in
/// the intent, not the transaction.
///
/// The scan verifies the intent's signature against the escrow's
/// initializer key and requires a fresh nonce (`nonce >
/// last_intent_nonce`) before annotating — an unverifiable or
/// replayed intent is not annotated. The expiry slot is disclosed,
/// not evaluated (the keeper scan's clock is wall time, not slots —
/// the AV-97 `slot_unlock_opt` precedent): the operator compares it
/// against the chain tip before submitting. The submit-time guards
/// (pause, state, mint, payout policy, quorum, timelock, …) still
/// run inside `release_via_intent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentReleaseAnnotation {
    /// The escrow the intent authorizes a release from.
    pub escrow_id: [u8; 32],
    /// The intent's replay nonce (fresh at scan time).
    pub nonce: u64,
    /// The intent's expiry slot — disclosed, not evaluated.
    pub expiry_slot: u64,
}

/// AV-133: a vault with an armed scheduled auto-recovery — the exact
/// Unix timestamp when `try_auto_unpause` will fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingAutoUnpause {
    /// The escrow id.
    pub escrow_id: [u8; 32],
    /// The exact `auto_unpause_at` timestamp.
    pub auto_unpause_at: u64,
}

/// AV-134: a vault with a configured funding amount window (see
/// [`Escrow::with_amount_bounds`](super::Escrow::with_amount_bounds))
/// — the floor and ceiling every deposit must sit inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundingBounds {
    /// The escrow id.
    pub escrow_id: [u8; 32],
    /// The configured `min_funding_amount` floor.
    pub min_amount: u64,
    /// The configured `max_funding_amount` ceiling.
    pub max_amount: u64,
}

/// The scan result: every executable keeper call at [`KeeperReport::at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeeperReport {
    /// The `now` (Unix seconds) the scan ran at.
    pub at: u64,
    /// How many escrows were scanned.
    pub scanned: usize,
    /// Executable actions, in the input's order.
    pub actions: Vec<KeeperAction>,
    /// AV-98: the operator's intended Jito tip for the bundles built
    /// from this report — amount + recipient, annotated on the report
    /// so the dry-run preview shows the tip line. The report does not
    /// build the tip instruction (the report's actions may name
    /// different callers; the payer is the operator's own key) — the
    /// instruction is assembled when the execution bundle is stamped
    /// ([`ExecutionBundle::with_jito_tip`](super::execution_bundle::ExecutionBundle::with_jito_tip)).
    /// `None` unless stamped via
    /// [`with_jito_tip`](KeeperReport::with_jito_tip).
    pub jito_tip: Option<JitoTipConfig>,
    /// AV-123: escrows carrying a signed, unsubmitted gasless-release
    /// intent (see [`IntentReleaseAnnotation`]) — populated by
    /// [`scan_keeper_actions`] from
    /// [`WatchedEscrow::pending_intent`]. Annotation only: the
    /// relayer still submits `release_via_intent` through the state
    /// machine's full guard chain. Empty when no watched escrow
    /// carries a verifiable intent.
    pub intent_releases: Vec<IntentReleaseAnnotation>,
    /// AV-106: total insurance-pool balance across the scanned
    /// escrows — the neutral penalties held fleet-wide. Saturates
    /// instead of wrapping.
    pub pool_balance: u64,
    /// AV-106: total cumulative pool inflow across the scanned
    /// escrows (slash-to-pool + bond-forfeit-to-pool credits).
    pub pool_inflow: u64,
    /// AV-106: total pool outflow across the scanned escrows
    /// (`pool_inflow - pool_balance`: overturn restitution plus
    /// authorized payouts).
    pub pool_outflow: u64,
    /// AV-120: the operator-stamped report sequence number for
    /// incremental diffing ([`crate::compute_diff`]) — `None` on
    /// legacy full reports, which keeps the old "every scan is a full
    /// report" semantics. Stamped via
    /// [`with_report_seq`](KeeperReport::with_report_seq); the scan
    /// itself leaves it `None`.
    pub report_seq: Option<u64>,
    /// AV-133: vaults with an armed scheduled auto-recovery
    /// (`pause(authority, Some(t))`) — the exact recovery timestamp
    /// per vault. Informational: the recovery fires inside the state
    /// machine's `try_auto_unpause`, not via a keeper action.
    pub pending_auto_unpause: Vec<PendingAutoUnpause>,
    /// AV-134: vaults with a configured funding amount window
    /// (`with_amount_bounds`) — the floor and ceiling per vault.
    /// Informational: the window gates the deposit path inside the
    /// state machine, not via a keeper action.
    pub funding_bounds: Vec<FundingBounds>,
}

impl KeeperReport {
    /// True when the scan found nothing executable.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// AV-88: total estimated compute units across the report's
    /// actions — the dry-run preview's cost line. Saturates instead of
    /// wrapping.
    pub fn total_estimated_compute_units(&self) -> u64 {
        self.actions
            .iter()
            .map(|a| a.estimated_compute_units())
            .fold(0u64, |a, b| a.saturating_add(b))
    }

    /// AV-98: stamp the operator's intended Jito tip onto the report
    /// (builder style — [`scan_keeper_actions`] leaves it `None`; the
    /// keeper calls this before handing the report to the bundle
    /// builder). The report annotates the tip amount + recipient; the
    /// tip instruction itself is built at bundle-submit time, when the
    /// payer key is known.
    ///
    /// Validation mirrors
    /// [`JitoTipConfig::new`](super::execution_bundle::JitoTipConfig::new):
    /// a zero amount or a zero recipient returns [`TipConfigError`]
    /// and leaves the report untouched.
    pub fn with_jito_tip(
        mut self,
        lamports: u64,
        recipient: [u8; 32],
    ) -> Result<Self, TipConfigError> {
        self.jito_tip = Some(JitoTipConfig::new(lamports, recipient)?);
        Ok(self)
    }

    /// AV-120: stamp the report sequence number onto the report
    /// (builder style — [`scan_keeper_actions`] leaves it `None`; the
    /// keeper stamps the next sequence before diffing with
    /// [`crate::compute_diff`]). A `None` report keeps the legacy
    /// full-report semantics.
    pub fn with_report_seq(mut self, seq: u64) -> Self {
        self.report_seq = Some(seq);
        self
    }

    /// Hand-serialized JSON (the crate is dependency-free). Deterministic
    /// field order; keys are 64-char lowercase hex; `mint` is a hex
    /// string or `null`.
    ///
    /// ```json
    /// {"at":1000000,"scanned":1,"total_estimated_cu":13814,
    ///  "jito_tip":{"lamports":10000,"recipient":"ee…"},
    ///  "intent_releases":[{"escrow_id":"...","nonce":3,"expiry_slot":99999}],
    ///  "pool_balance":0,"pool_inflow":0,"pool_outflow":0,
    ///  "actions":[
    ///   {"escrow_id":"...","vault_address":"...","action":"cancel_expired","caller":"...",
    ///    "caller_role":"initializer","mint":null,
    ///    "refund_to":"...","amount":1000000,"decimals":6,
    ///    "display_amount":"1.000000",
    ///    "reason":"expired","reference":null,"extension_count":0,
    ///    "multisig_authority":null,"evidence_disclosure":null,
    ///    "funding_progress":null,"merge_source":null,
    ///    "penalty_estimate":0,"slot_unlock_at":null,
    ///    "bounty_lamports":0,"bounty_unprofitable":false,
    ///    "arbiter_fee":null,
    ///    "estimated_cu":13814}
    ///  ],
    ///  "report_seq":null,"pending_auto_unpause":[],"funding_bounds":[]}
    /// ```
    ///
    /// AV-120: `report_seq` rides last — the operator-stamped sequence
    /// number for incremental diffing ([`crate::compute_diff`]),
    /// `null` on legacy full reports.
    ///
    /// AV-28: every action also carries `decimals` (the escrow's token
    /// decimal metadata, `0` when none is declared) and `display_amount`
    /// — the same `amount` rendered in human units via
    /// [`crate::format_amount`]. The instruction itself always moves the
    /// raw `amount`; the display field is for operators and logs only.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(160 + self.actions.len() * 400);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        // AV-88: the dry-run preview's cost line — the summed CU
        // estimate across the report's actions.
        s.push_str(",\"total_estimated_cu\":");
        s.push_str(&self.total_estimated_compute_units().to_string());
        // AV-98: the operator's intended Jito tip for the bundles built
        // from this report — the tip line of the dry-run preview.
        // `null` when the operator stamped nothing (same Option
        // convention as the bundle's `mint`).
        s.push_str(",\"jito_tip\":");
        match &self.jito_tip {
            Some(tip) => {
                s.push_str("{\"lamports\":");
                s.push_str(&tip.lamports.to_string());
                s.push_str(",\"recipient\":\"");
                s.push_str(&hex32(&tip.recipient));
                s.push_str("\"}");
            }
            None => s.push_str("null"),
        }
        // AV-123: the gasless-release intent annotations — escrows
        // carrying a signed, unsubmitted release intent the relayer
        // can submit as `release_via_intent` with any fee payer.
        s.push_str(",\"intent_releases\":[");
        for (i, r) in self.intent_releases.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&r.escrow_id));
            s.push_str("\",\"nonce\":");
            s.push_str(&r.nonce.to_string());
            s.push_str(",\"expiry_slot\":");
            s.push_str(&r.expiry_slot.to_string());
            s.push('}');
        }
        s.push(']');
        // AV-106: the fleet-wide insurance-pool lines — balance,
        // cumulative inflow, and outflow (`inflow - balance`).
        s.push_str(",\"pool_balance\":");
        s.push_str(&self.pool_balance.to_string());
        s.push_str(",\"pool_inflow\":");
        s.push_str(&self.pool_inflow.to_string());
        s.push_str(",\"pool_outflow\":");
        s.push_str(&self.pool_outflow.to_string());
        s.push_str(",\"actions\":[");
        for (i, a) in self.actions.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&a.escrow_id));
            // AV-92: the precomputed vault PDA (hex) or null — the
            // address the seeds derive to under the recorded program
            // id; informational, never an instruction input.
            s.push_str("\",\"vault_address\":");
            match a.vault_address {
                Some(v) => {
                    s.push('"');
                    s.push_str(&hex32(&v));
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            s.push_str(",\"action\":\"");
            s.push_str(a.kind.as_str());
            s.push_str("\",\"caller\":\"");
            s.push_str(&hex32(&a.caller));
            s.push_str("\",\"caller_role\":\"");
            s.push_str(a.caller_role);
            s.push_str("\",\"mint\":");
            match a.mint {
                Some(m) => {
                    s.push('"');
                    s.push_str(&hex32(&m));
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            // AV-23: the refund destination the cancel_expired
            // instruction must name (`null` for claim actions).
            s.push_str(",\"refund_to\":");
            match a.refund_to {
                Some(r) => {
                    s.push('"');
                    s.push_str(&hex32(&r));
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            s.push_str(",\"amount\":");
            s.push_str(&a.amount.to_string());
            // AV-28: human-readable amount alongside the raw value (the
            // instruction moves `amount`; `display_amount` is for
            // operators and logs only).
            s.push_str(",\"decimals\":");
            s.push_str(&a.decimals.to_string());
            s.push_str(",\"display_amount\":\"");
            s.push_str(&format_amount(a.amount, a.decimals));
            s.push_str("\",\"reason\":\"");
            s.push_str(a.reason);
            // AV-53: the off-chain correlation id as 64-char lowercase
            // hex, or `null` — correlation only, never an instruction
            // input.
            s.push_str("\",\"reference\":");
            match a.reference {
                Some(r) => {
                    s.push('"');
                    s.push_str(&hex32(&r));
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            // AV-59: the renewal count — how many times the deadline
            // was extended via `extend_expiry`.
            s.push_str(",\"extension_count\":");
            s.push_str(&a.extension_count.to_string());
            // AV-84: the bound multisig authority — `null` when no
            // multisig binding is configured, else the program id, the
            // authority PDA, and the threshold metadata, so the keeper
            // knows to route the call through the multisig program.
            s.push_str(",\"multisig_authority\":");
            match &a.multisig_authority {
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
            // AV-91: dispute-evidence disclosure progress — `null`
            // unless the action is a `resolve` / `submit_panel_judgment`
            // on a dispute with a committed evidence root, so the
            // arbiter dashboard reads completeness at a glance.
            s.push_str(",\"evidence_disclosure\":");
            match a.evidence_disclosure {
                Some((disclosed, total)) => {
                    s.push_str("{\"disclosed\":");
                    s.push_str(&disclosed.to_string());
                    s.push_str(",\"total\":");
                    s.push_str(&total.to_string());
                    s.push('}');
                }
                None => s.push_str("null"),
            }
            // AV-111: tranched-funding progress — `null` unless the
            // action is a `fund_tranche`, so the operator dashboard
            // reads the live plan counters at a glance.
            s.push_str(",\"funding_progress\":");
            match a.funding_progress {
                Some(p) => {
                    s.push_str("{\"funded_total\":");
                    s.push_str(&p.funded_total.to_string());
                    s.push_str(",\"total_amount\":");
                    s.push_str(&p.total_amount.to_string());
                    s.push_str(",\"tranches_used\":");
                    s.push_str(&p.tranches_used.to_string());
                    s.push_str(",\"max_tranches\":");
                    s.push_str(&p.max_tranches.to_string());
                    s.push('}');
                }
                None => s.push_str("null"),
            }
            // AV-114: the merge source escrow id — hex, `null` unless
            // the action is a `merge_escrows`.
            s.push_str(",\"merge_source\":");
            match a.merge_source {
                Some(id) => {
                    s.push('"');
                    for b in id {
                        s.push_str(&format!("{b:02x}"));
                    }
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            // AV-115: the taker-initiated anti-griefing penalty estimate
            // at scan time — `0` unless the action is a
            // `cancel_expired` / `crank_expired` on a penalty-configured
            // escrow. The operator watches this number grow as the
            // escalation meter runs.
            s.push_str(",\"penalty_estimate\":");
            s.push_str(&a.penalty_estimate.to_string());
            // AV-116: the slot-unlock slot when a slot-based relative
            // timelock is configured — `null` otherwise. The operator
            // compares it against the chain tip; the scan itself is
            // wall-clock based and never evaluates the slot gate.
            s.push_str(",\"slot_unlock_at\":");
            match a.slot_unlock_at {
                Some(slot) => s.push_str(&slot.to_string()),
                None => s.push_str("null"),
            }
            // AV-124: the keeper bounty a successful crank would pay
            // right now — `0` unless the action is a `crank_expired`
            // on a bounty-configured escrow with a non-empty pool.
            // The operator reads the incentive before deciding to
            // crank.
            s.push_str(",\"bounty_lamports\":");
            s.push_str(&a.bounty_lamports.to_string());
            // AV-124: whether the bounty covers the estimated
            // execution cost — `true` means the bounty alone does not
            // pay for the transaction under the assumed fee regime.
            s.push_str(",\"bounty_unprofitable\":");
            s.push_str(if a.bounty_unprofitable { "true" } else { "false" });
            // AV-135: the escrow's configured arbiter adjudication fee
            // — `null` on every action but Resolve / PanelJudgment
            // (and on dispute actions when no fee is configured).
            s.push_str(",\"arbiter_fee\":");
            match a.arbiter_fee {
                Some(t) => {
                    s.push_str("{\"flat_lamports\":");
                    s.push_str(&t.flat_lamports.to_string());
                    s.push_str(",\"bps\":");
                    s.push_str(&t.bps.to_string());
                    s.push('}');
                }
                None => s.push_str("null"),
            }
            // AV-88: the per-action CU passthrough — the heuristic
            // estimate for this keeper call, same cost model as the
            // execution plan.
            s.push_str(",\"estimated_cu\":");
            s.push_str(&a.estimated_compute_units().to_string());
            s.push_str("}");
        }
        s.push(']');
        // AV-120: the stamped sequence number, last — `null` on legacy
        // full reports.
        s.push_str(",\"report_seq\":");
        match self.report_seq {
            Some(seq) => s.push_str(&seq.to_string()),
            None => s.push_str("null"),
        }
        // AV-133: vaults with an armed scheduled auto-recovery — the
        // exact recovery timestamp per vault.
        s.push_str(",\"pending_auto_unpause\":[");
        for (i, p) in self.pending_auto_unpause.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&p.escrow_id));
            s.push_str("\",\"auto_unpause_at\":");
            s.push_str(&p.auto_unpause_at.to_string());
            s.push('}');
        }
        s.push(']');
        // AV-134: vaults with a configured funding amount window —
        // the floor and ceiling per vault.
        s.push_str(",\"funding_bounds\":[");
        for (i, b) in self.funding_bounds.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&b.escrow_id));
            s.push_str("\",\"min_amount\":");
            s.push_str(&b.min_amount.to_string());
            s.push_str(",\"max_amount\":");
            s.push_str(&b.max_amount.to_string());
            s.push('}');
        }
        s.push(']');
        s.push('}');
        s
    }
}

/// Scan `watched` at `now` and return every immediately executable keeper
/// call. Pure read over the snapshots: zero side effects, deterministic
/// output in input order.
///
/// An escrow contributes at most one action per kind. An expired escrow
/// with claimable vesting lists *both* `cancel_expired` and `claim`:
/// AV-116: the slot-unlock slot for the keeper report — `Some(fund_slot
/// + slot_timelock_slots)` when a slot-based relative timelock is
/// configured, `None` otherwise. The keeper scan takes no slot (its
/// clock is wall time), so the report discloses the gate instead of
/// evaluating it: the operator compares against the chain tip.
fn slot_unlock_opt(e: &Escrow) -> Option<u64> {
    if e.slot_timelock_slots() == 0 {
        None
    } else {
        Some(e.slot_unlock_slot())
    }
}

/// AV-135: read the escrow's configured arbiter adjudication fee
/// ([`Escrow::with_arbiter_fee`]) for the keeper report — the flat
/// slice and the bps rate a dispute settlement would charge. `None`
/// when the escrow never opted in.
fn arbiter_fee_terms(e: &Escrow) -> Option<ArbiterFeeTerms> {
    match (e.arbiter_fee_flat(), e.arbiter_fee_bps()) {
        (None, None) => None,
        (flat, bps) => Some(ArbiterFeeTerms {
            flat_lamports: flat.unwrap_or(0),
            bps: bps.unwrap_or(0),
        }),
    }
}

/// both calls are executable at the scan time (amounts are as of the
/// scan; the keeper re-scans after executing). AV-48: an expired escrow
/// additionally lists a `crank_expired` action (permissionless crank,
/// caller `"anyone"`) alongside the party-signed `cancel_expired` — a
/// third-party keeper sweeps with the crank, the initializer's own
/// keeper with the party path.
/// Per-escrow accumulator for [`scan_keeper_actions`] (AV-138): the six
/// collections the per-escrow pass builds. Extracted so the indexed scan
/// ([`scan_keeper_actions_indexed`]) shares the exact per-escrow logic.
#[derive(Default)]
struct KeeperScanAcc {
    actions: Vec<KeeperAction>,
    intent_releases: Vec<IntentReleaseAnnotation>,
    pending_auto_unpause: Vec<PendingAutoUnpause>,
    funding_bounds: Vec<FundingBounds>,
    pool_balance: u64,
    pool_inflow: u64,
}

/// The per-escrow body of [`scan_keeper_actions`], extracted verbatim
/// (AV-138) so the indexed scan shares the exact logic. Reads one watched
/// snapshot; never mutates it. The two `continue`s of the original loop
/// became early `return`s — one escrow per call, so they are equivalent.
/// AV-146: the keeper's `claim` eligibility predicate — the single
/// truth source shared by the scan ([`scan_one_keeper_escrow`]) and
/// the batch claim sweep
/// ([`plan_claim_sweep`](crate::plan_claim_sweep)), so the sweep
/// lists exactly the claims the scan would list. The taker's pull
/// path: vesting attached (or an AV-97 Dutch auction — the auction
/// prices `claim` on its own descending curve), no milestone plan
/// (the plan owns the release schedule and disables `claim`),
/// something priced-but-unreleased, any configured quorum satisfied,
/// and the timelock (AV-27) already unlocked — otherwise the call
/// would fail and is not executable.
pub(crate) fn claim_eligible(e: &Escrow, now: u64) -> bool {
    (e.vesting_schedule().is_some() || e.auction().is_some())
        && e.milestone_plan().is_none()
        && e.claimable_amount(now) > 0
        && e.quorum().map(|q| q.is_satisfied()).unwrap_or(true)
        && e.is_unlock_eligible(now)
}

/// AV-146: build the keeper `claim` action for one watch entry —
/// `None` when [`claim_eligible`] fails. The scan and the batch
/// claim sweep share this builder, so the sweep's per-vault action
/// is exactly the action the scan lists.
pub(crate) fn claim_action_for(w: &WatchedEscrow, now: u64) -> Option<KeeperAction> {
    let e = &w.escrow;
    if !claim_eligible(e, now) {
        return None;
    }
    Some(KeeperAction {
        escrow_id: w.escrow_id,
        vault_address: w.vault_address(),
        kind: KeeperActionKind::Claim,
        caller: e.taker(),
        caller_role: "taker",
        mint: e.mint(),
        // Claims pay the taker, not a refund: no refund
        // destination applies.
        refund_to: None,
        amount: e.claimable_amount(now),
        // AV-28: the report renders the amount in human units
        // alongside the raw value.
        decimals: e.decimals(),
        // AV-53: the off-chain correlation id rides the action so
        // the report JSON joins it to the operator's records.
        reference: w.reference,
        extension_count: e.extension_count(),
        multisig_authority: e.multisig_authority,
        evidence_disclosure: None,
        funding_progress: None,
        // AV-97: the auction window prices the claim, not a
        // vesting curve — the reason tells the operator which
        // pricing the amount came from.
        reason: if e.auction().is_some() {
            "auction_window_open"
        } else {
            "vesting_unlocked"
        },
        merge_source: None,
        // AV-115: the penalty estimate is zero on non-cancel actions.
        penalty_estimate: 0,
        slot_unlock_at: slot_unlock_opt(e),
        bounty_lamports: 0,
        bounty_unprofitable: false,
        arbiter_fee: None,
    })
}

fn scan_one_keeper_escrow(w: &WatchedEscrow, now: u64, acc: &mut KeeperScanAcc) {
    let KeeperScanAcc {
        actions,
        intent_releases,
        pending_auto_unpause,
        funding_bounds,
        pool_balance,
        pool_inflow,
    } = acc;
    let e = &w.escrow;
    *pool_balance = pool_balance.saturating_add(e.pool_paid());
    *pool_inflow = pool_inflow.saturating_add(e.pool_inflow());
    // AV-133: record vaults with an armed auto-recovery schedule.
    if e.is_paused() {
        if let Some(t) = e.auto_unpause_at() {
            pending_auto_unpause.push(PendingAutoUnpause {
                escrow_id: w.escrow_id,
                auto_unpause_at: t,
            });
        }
    }
    // AV-134: record vaults with a configured funding amount
    // window.
    if let Some((min, max)) = e.amount_bounds() {
        funding_bounds.push(FundingBounds {
            escrow_id: w.escrow_id,
            min_amount: min,
            max_amount: max,
        });
    }
    // AV-123: annotate escrows carrying a signed, unsubmitted
    // gasless-release intent. The intent verifies against the
    // escrow's initializer key and must carry a fresh nonce
    // (`nonce > last_intent_nonce`) — an unverifiable or
    // replayed intent is not annotated. The expiry slot is
    // disclosed, not evaluated: the scan's clock is wall time,
    // not slots (the `slot_unlock_opt` precedent), so the
    // operator compares it against the chain tip before the
    // relayer submits `release_via_intent`.
    if let Some(signed) = w.pending_intent {
        if signed.verify(&e.initializer())
            && signed.intent.nonce > e.last_intent_nonce()
        {
            intent_releases.push(IntentReleaseAnnotation {
                escrow_id: w.escrow_id,
                nonce: signed.intent.nonce,
                expiry_slot: signed.intent.expiry_slot,
            });
        }
    }
    // AV-38: a disputed escrow has exactly one keeper-executable
    // call — the arbiter's `resolve`. The unilateral exits stay
    // locked, so nothing else is listed; the taker/initializer split
    // and the rationale-document commitment are the arbiter's
    // judgment at call time, so the action carries the splittable
    // pool rather than a decided split. An arbiter-less dispute
    // (unreachable through the state machine, which requires an
    // arbiter to escalate) lists nothing — no key could sign the
    // call.
    // AV-65: in panel mode the single-arbiter `resolve` is disabled
    // (`PanelResolveDisabled`) — the panel's multisig judgment is
    // the only settlement path. The scan lists one
    // `submit_panel_judgment` action per panel member instead, so a
    // member-operated keeper bot learns which disputes await its
    // vote; the split and rationale are the member's call-time
    // judgment, so the action carries the splittable pool rather
    // than a decided split.
    if e.state() == EscrowState::Disputed {
        if let Some(panel) = e.arbiter_panel() {
            let remaining = e.remaining_amount();
            if remaining > 0 {
                for member in panel.members[..panel.n as usize].iter() {
                    actions.push(KeeperAction {
                        escrow_id: w.escrow_id,
                        vault_address: w.vault_address(),
                        kind: KeeperActionKind::PanelJudgment,
                        caller: *member,
                        caller_role: "panel_member",
                        mint: e.mint(),
                        // `submit_panel_judgment` splits the
                        // remainder between the taker and the
                        // initializer — no single refund
                        // destination applies.
                        refund_to: None,
                        amount: remaining,
                        decimals: e.decimals(),
                        reference: w.reference,
                        extension_count: e.extension_count(),
                        multisig_authority: e.multisig_authority,
                        evidence_disclosure: e.evidence_disclosure(),
                        funding_progress: None,
                        reason: "disputed",
                        merge_source: None,
                        // AV-115: the penalty estimate is zero on non-cancel actions.
                        penalty_estimate: 0,
                        slot_unlock_at: slot_unlock_opt(e),
                        bounty_lamports: 0,
                        bounty_unprofitable: false,
                        // AV-135: the arbiter adjudication fee rides the dispute actions.
                        arbiter_fee: arbiter_fee_terms(e),
                    });
                }
            }
        } else if let Some(arbiter) = e.arbiter() {
            let remaining = e.remaining_amount();
            if remaining > 0 {
                actions.push(KeeperAction {
                    escrow_id: w.escrow_id,
                    vault_address: w.vault_address(),
                    kind: KeeperActionKind::Resolve,
                    caller: arbiter,
                    caller_role: "arbiter",
                    mint: e.mint(),
                    // `resolve` splits the remainder between the
                    // taker and the initializer — no single refund
                    // destination applies.
                    refund_to: None,
                    amount: remaining,
                    // AV-28: the report renders the amount in human
                    // units alongside the raw value.
                    decimals: e.decimals(),
                    // AV-53: the off-chain correlation id rides the action so
                    // the report JSON joins it to the operator's records.
                    reference: w.reference,
                    extension_count: e.extension_count(),
                    multisig_authority: e.multisig_authority,
                    evidence_disclosure: e.evidence_disclosure(),
                    funding_progress: None,
                    reason: "disputed",
                    merge_source: None,
                    // AV-115: the penalty estimate is zero on non-cancel actions.
                    penalty_estimate: 0,
                    slot_unlock_at: slot_unlock_opt(e),
                    bounty_lamports: 0,
                    bounty_unprofitable: false,
                    // AV-135: the arbiter adjudication fee rides the dispute actions.
                    arbiter_fee: arbiter_fee_terms(e),
                });
            }
        }
        return;
    }
    // AV-111: a tranched-funding escrow with an incomplete plan
    // and a remaining tranche slot lists one `fund_tranche`
    // action per scan — the initializer's keeper bot learns the
    // next deposit is due, and `funding_progress` passes the live
    // plan counters through to the operator's dashboard. The
    // action is listed from `Uninitialized` (non-dual-sig),
    // `Activated`, and `Funded` — exactly the states
    // `fund_tranche` accepts — and withheld while paused, so a
    // listed call is always executable.
    if let Some(plan) = e.funding_plan() {
        let tranche_open = e.state() == EscrowState::Funded
            || e.state() == EscrowState::Activated
            || (e.state() == EscrowState::Uninitialized && !e.dual_sig_required());
        if tranche_open
            && !e.is_paused()
            && !e.is_funding_complete()
            && plan.tranches_used() < plan.max_tranches()
        {
            let remaining = plan.total_amount().saturating_sub(e.funded_total());
            if remaining > 0 {
                actions.push(KeeperAction {
                    escrow_id: w.escrow_id,
                    vault_address: w.vault_address(),
                    kind: KeeperActionKind::FundTranche,
                    caller: e.initializer(),
                    caller_role: "initializer",
                    mint: e.mint(),
                    // A tranche is a deposit, not a refund — no
                    // refund destination applies.
                    refund_to: None,
                    amount: remaining,
                    decimals: e.decimals(),
                    reference: w.reference,
                    extension_count: e.extension_count(),
                    multisig_authority: e.multisig_authority,
                    evidence_disclosure: None,
                    funding_progress: Some(FundingProgress {
                        funded_total: e.funded_total(),
                        total_amount: plan.total_amount(),
                        tranches_used: plan.tranches_used(),
                        max_tranches: plan.max_tranches(),
                    }),
                    reason: "funding_incomplete",
                    merge_source: None,
                    // AV-115: the penalty estimate is zero on non-cancel actions.
                    penalty_estimate: 0,
                    slot_unlock_at: slot_unlock_opt(e),
                    bounty_lamports: 0,
                    bounty_unprofitable: false,
                    arbiter_fee: None,
                });
            }
        }
    }
    // Only a live, funded escrow has keeper-executable exits:
    // Uninitialized / Activated escrows are not funded yet, and the
    // terminal states (Released, Cancelled, Settled, Closed) have
    // none.
    if e.state() != EscrowState::Funded {
        return;
    }
    // The expiry gate is the state machine's own predicate
    // (`Escrow::is_expiry_eligible`): the keeper honors the grace
    // period exactly as `cancel_expired` enforces it on-chain, so a
    // listed call is always executable — never a `NotExpired`
    // rejection caused by keeper/cluster clock drift.
    if e.is_expiry_eligible(now) && e.remaining_amount() > 0 {
        // Either party may cancel an expired escrow; the initializer
        // is the canonical keeper caller. The refund is the remainder
        // — never fee'd, so no fee accounting is needed here.
        actions.push(KeeperAction {
            escrow_id: w.escrow_id,
            vault_address: w.vault_address(),
            kind: KeeperActionKind::CancelExpired,
            caller: e.initializer(),
            caller_role: "initializer",
            mint: e.mint(),
            // AV-23: the instruction must name the refund
            // destination explicitly, and the state machine pins it
            // to the escrow's refund policy — the report carries the
            // effective recipient so the keeper builds a valid call.
            refund_to: Some(e.refund_recipient()),
            amount: e.remaining_amount(),
            // AV-28: the report renders the amount in human units
            // alongside the raw value.
            decimals: e.decimals(),
            // AV-53: the off-chain correlation id rides the action so
            // the report JSON joins it to the operator's records.
            reference: w.reference,
            extension_count: e.extension_count(),
            multisig_authority: e.multisig_authority,
            evidence_disclosure: None,
            funding_progress: None,
            reason: "expired",
            merge_source: None,
            // AV-115: the taker-initiated penalty estimate at scan time.
            penalty_estimate: e.expiry_cancel_penalty_at(e.remaining_amount(), now),
            slot_unlock_at: slot_unlock_opt(e),
            bounty_lamports: 0,
            bounty_unprofitable: false,
            arbiter_fee: None,
        });
        // AV-48: the permissionless crank — the same expiry exit,
        // callable by anyone. A keeper bot that is party to nothing
        // sweeps timed-out vaults with `crank_expired`; the party
        // path above stays for the initializer's own keeper. The
        // crank fails on a paused escrow (`require_not_paused`), so
        // it is only listed when the escrow is not paused — a listed
        // crank is always executable, never a `Paused` rejection.
        // (The pre-existing `CancelExpired` listing above predates
        // the pause feature and does not filter on it; left
        // untouched.)
        if !e.is_paused() {
            // AV-124: the keeper-bounty annotation — the bounty a
            // successful crank would pay right now
            // (`Escrow::keeper_bounty_payable`: `min(per_crank,
            // pool)`, `0` when the bounty is not configured or the
            // pool is exhausted), and whether it covers the
            // estimated execution cost. `bounty < cost` marks the
            // crank `unprofitable`: the bounty alone does not pay
            // for the transaction under the assumed fee regime —
            // the crank is still listed (the scan lists every
            // executable action; the keeper may crank at a loss),
            // but the operator sees the economics before signing.
            // The scan and the state machine read the same
            // `keeper_bounty_payable`, so the preview and the
            // payout can never disagree.
            let mut crank = KeeperAction {
                escrow_id: w.escrow_id,
                vault_address: w.vault_address(),
                kind: KeeperActionKind::CrankExpired,
                // Permissionless: no specific key must sign — the
                // keeper substitutes its own key; see `caller` docs.
                caller: [0u8; 32],
                caller_role: "anyone",
                mint: e.mint(),
                // The crank refunds to the same pinned destination
                // as the party path; AV-124: without the bounty the
                // cranker receives nothing (the AV-48 behavior) —
                // with it, the bounty rides `bounty_lamports`.
                refund_to: Some(e.refund_recipient()),
                amount: e.remaining_amount(),
                decimals: e.decimals(),
                // AV-53: the off-chain correlation id rides the action so
                // the report JSON joins it to the operator's records.
                reference: w.reference,
                extension_count: e.extension_count(),
                multisig_authority: e.multisig_authority,
                evidence_disclosure: None,
                funding_progress: None,
                reason: "expired",
                merge_source: None,
                // AV-115: the taker-initiated penalty estimate at scan time.
                penalty_estimate: e.expiry_cancel_penalty_at(e.remaining_amount(), now),
                slot_unlock_at: slot_unlock_opt(e),
                bounty_lamports: 0,
                bounty_unprofitable: false,
                arbiter_fee: None,
            };
            let bounty = e.keeper_bounty_payable();
            crank.bounty_lamports = bounty;
            crank.bounty_unprofitable =
                bounty < crank.estimated_execution_cost_lamports();
            actions.push(crank);
        }
    }
    // AV-109: the dead-man's switch — a configured, funded escrow
    // whose inactivity threshold elapsed at scan time lists one
    // `claim_deadman` action for the heir. The keeper mirrors the
    // call's own guards so a listed claim is always executable:
    // not paused (`require_not_paused`), no live swap link
    // (`require_no_live_swap_link` — a linked escrow settles only
    // through the pair path), and a non-zero remainder. The heir
    // need not be either party — `caller_role` is `"heir"`.
    if e.is_deadman_eligible(now) && e.remaining_amount() > 0 && !e.is_paused() && e.swap_link().is_none() {
        // `is_deadman_eligible` implies configured, so the heir is
        // `Some` — the expect documents the invariant.
        let heir = e
            .deadman_heir()
            .expect("AV-109: eligible implies a configured heir");
        actions.push(KeeperAction {
            escrow_id: w.escrow_id,
            vault_address: w.vault_address(),
            kind: KeeperActionKind::ClaimDeadman,
            caller: heir,
            caller_role: "heir",
            mint: e.mint(),
            // The claim pays the heir directly — the destination
            // is pinned to the configured heir, like
            // `cancel_expired`'s pinned refund destination.
            refund_to: Some(heir),
            amount: e.remaining_amount(),
            decimals: e.decimals(),
            reference: w.reference,
            extension_count: e.extension_count(),
            multisig_authority: e.multisig_authority,
            evidence_disclosure: None,
            funding_progress: None,
            reason: "deadman_inactivity_elapsed",
            merge_source: None,
            // AV-115: the penalty estimate is zero on non-cancel actions.
            penalty_estimate: 0,
            slot_unlock_at: slot_unlock_opt(e),
            bounty_lamports: 0,
            bounty_unprofitable: false,
            arbiter_fee: None,
        });
    }
    // AV-146: the taker's pull path now goes through
    // `claim_action_for` — the batch claim sweep lists exactly
    // these actions (single truth source).
    if let Some(action) = claim_action_for(w, now) {
        actions.push(action);
    }
    // AV-56: the initializer's push path for the next due
    // subscription period. An escrow may legitimately list both a
    // `Claim` (the taker's pull on the vesting curve) and a
    // `ReleasePeriod` (the initializer's push of the next due
    // period) — at most one per kind.
    if let Some(schedule) = e.subscription_schedule() {
        let next = e.subscription_next_period();
        // `subscription_next` only ever runs in order, so the scan
        // names exactly the period `release_period` accepts. The
        // amount is the period's *live* amount (AV-73): the uniform
        // `per_period` at setup, or the dual-signed re-split — the
        // keeper must list what `release_period` will actually pay,
        // never the construction-time uniform.
        let live_amount = e.subscription_period_amount(next).unwrap_or(0);
        // The `live_amount > 0` guard mirrors the builder's
        // invariant; the schedule gates keep zero-value actions
        // off the list.
        if next < schedule.periods
            && live_amount > 0
            && e.subscription_period_due_at(next)
                .map(|due_at| now >= due_at)
                .unwrap_or(false)
        {
            actions.push(KeeperAction {
                escrow_id: w.escrow_id,
                vault_address: w.vault_address(),
                kind: KeeperActionKind::ReleasePeriod,
                caller: e.initializer(),
                caller_role: "initializer",
                mint: e.mint(),
                // A period release pays the taker, not a refund: no
                // refund destination applies.
                refund_to: None,
                amount: live_amount,
                // AV-28: the report renders the amount in human
                // units alongside the raw value.
                decimals: e.decimals(),
                // AV-53: the off-chain correlation id rides the
                // action so the report JSON joins it to the
                // operator's records.
                reference: w.reference,
                extension_count: e.extension_count(),
                multisig_authority: e.multisig_authority,
                evidence_disclosure: None,
                funding_progress: None,
                reason: "subscription_period_due",
                merge_source: None,
                // AV-115: the penalty estimate is zero on non-cancel actions.
                penalty_estimate: 0,
                slot_unlock_at: slot_unlock_opt(e),
                bounty_lamports: 0,
                bounty_unprofitable: false,
                arbiter_fee: None,
            });
        }
    }
    // AV-82: the default-penalty enforcement path. Listed exactly
    // when `is_slash_eligible` holds at scan time — the predicate
    // mirrors every `slash` gate (Funded, terms configured,
    // deadline passed, not yet slashed, not paused, no
    // milestone/subscription schedule), so a listed slash is always
    // executable, never a `Paused` or `SlashNotEligible` rejection.
    // The initializer is the canonical keeper caller; when an
    // arbiter is configured the neutral enforcer path is listed
    // too. `amount` is the slashable remainder — the enforcement
    // size is the caller's decision at call time.
    if e.is_slash_eligible(now) && e.remaining_amount() > 0 {
        actions.push(KeeperAction {
            escrow_id: w.escrow_id,
            vault_address: w.vault_address(),
            kind: KeeperActionKind::Slash,
            caller: e.initializer(),
            caller_role: "initializer",
            mint: e.mint(),
            // Slash pays the escrow's configured penalty account,
            // not a refund destination.
            refund_to: None,
            amount: e.remaining_amount(),
            decimals: e.decimals(),
            reference: w.reference,
            extension_count: e.extension_count(),
            multisig_authority: e.multisig_authority,
            evidence_disclosure: None,
            funding_progress: None,
            reason: "slash_deadline_passed",
            merge_source: None,
            // AV-115: the penalty estimate is zero on non-cancel actions.
            penalty_estimate: 0,
            slot_unlock_at: slot_unlock_opt(e),
            bounty_lamports: 0,
            bounty_unprofitable: false,
            arbiter_fee: None,
        });
        if let Some(arbiter) = e.arbiter() {
            actions.push(KeeperAction {
                escrow_id: w.escrow_id,
                vault_address: w.vault_address(),
                kind: KeeperActionKind::Slash,
                caller: arbiter,
                caller_role: "arbiter",
                mint: e.mint(),
                refund_to: None,
                amount: e.remaining_amount(),
                decimals: e.decimals(),
                reference: w.reference,
                extension_count: e.extension_count(),
                multisig_authority: e.multisig_authority,
                evidence_disclosure: None,
                funding_progress: None,
                reason: "slash_deadline_passed",
                merge_source: None,
                // AV-115: the penalty estimate is zero on non-cancel actions.
                penalty_estimate: 0,
                slot_unlock_at: slot_unlock_opt(e),
                bounty_lamports: 0,
                bounty_unprofitable: false,
                arbiter_fee: None,
            });
        }
    }
    // AV-86: the slash-appeal paths. A taker whose slash is under a
    // live appeal window is listed for `file_appeal` — the
    // predicate mirrors every `file_appeal` gate (Funded, slashed,
    // window configured and open, no appeal filed or resolved, not
    // paused, panel configured), so a listed filing is always
    // executable. A filed appeal lists one `review_appeal` per panel
    // member who has not voted yet — members who already voted
    // (their vote stands unless they re-vote) are not re-listed.
    if e.is_appeal_eligible(now) {
        actions.push(KeeperAction {
            escrow_id: w.escrow_id,
            vault_address: w.vault_address(),
            kind: KeeperActionKind::FileAppeal,
            caller: e.taker(),
            caller_role: "taker",
            mint: e.mint(),
            // Filing moves no funds — there is no refund
            // destination; `amount` is the slashed penalty under
            // appeal, informational.
            refund_to: None,
            amount: e.penalty_paid(),
            decimals: e.decimals(),
            reference: w.reference,
            extension_count: e.extension_count(),
            multisig_authority: e.multisig_authority,
            evidence_disclosure: None,
            funding_progress: None,
            reason: "appeal_window_open",
            merge_source: None,
            // AV-115: the penalty estimate is zero on non-cancel actions.
            penalty_estimate: 0,
            slot_unlock_at: slot_unlock_opt(e),
            bounty_lamports: 0,
            bounty_unprofitable: false,
            arbiter_fee: None,
        });
    }
    if e.is_appeal_under_review() {
        if let Some(panel) = e.arbiter_panel() {
            let ballot = e.appeal_ballot();
            for (i, member) in panel.members[..panel.n as usize].iter().enumerate() {
                // Skip members whose effective vote is already on
                // record — the ballot is still open (a re-vote is
                // always allowed), but the keeper only nudges
                // members who have not voted yet.
                if ballot.voted & (1 << i) != 0 {
                    continue;
                }
                actions.push(KeeperAction {
                    escrow_id: w.escrow_id,
                    vault_address: w.vault_address(),
                    kind: KeeperActionKind::ReviewAppeal,
                    caller: *member,
                    caller_role: "panel_member",
                    mint: e.mint(),
                    // The review moves the penalty only on overturn
                    // — the judgment is the member's call-time
                    // decision; `amount` is the slashed penalty the
                    // ballot decides over.
                    refund_to: None,
                    amount: e.penalty_paid(),
                    decimals: e.decimals(),
                    reference: w.reference,
                    extension_count: e.extension_count(),
                    multisig_authority: e.multisig_authority,
                    evidence_disclosure: None,
                    funding_progress: None,
                    reason: "appeal_filed",
                    merge_source: None,
                    // AV-115: the penalty estimate is zero on non-cancel actions.
                    penalty_estimate: 0,
                    slot_unlock_at: slot_unlock_opt(e),
                    bounty_lamports: 0,
                    bounty_unprofitable: false,
                    arbiter_fee: None,
                });
            }
        }
    }
    // AV-103: the appeal-expiry sweep. A filed appeal whose window
    // lapsed unresolved is listed for `expire_appeal` — the
    // predicate mirrors every `expire_appeal` gate (Funded, Filed,
    // window lapsed, not paused), so a listed sweep is always
    // executable. Permissionless: the keeper substitutes its own
    // key (the zero key), like `crank_expired`; the forfeited bond
    // routes to the initializer by rule, never the caller.
    if e.is_appeal_expired(now) {
        actions.push(KeeperAction {
            escrow_id: w.escrow_id,
            vault_address: w.vault_address(),
            kind: KeeperActionKind::ExpireAppeal,
            // Permissionless: no specific key must sign — the
            // keeper substitutes its own key; see `caller` docs.
            caller: [0u8; 32],
            caller_role: "anyone",
            mint: e.mint(),
            // The forfeited bond routes to the initializer by rule
            // (like `slash`'s penalty account) — no caller-chosen
            // destination.
            refund_to: None,
            amount: e.appeal_bond_paid(),
            decimals: e.decimals(),
            reference: w.reference,
            extension_count: e.extension_count(),
            multisig_authority: e.multisig_authority,
            evidence_disclosure: None,
            funding_progress: None,
            reason: "appeal_window_lapsed",
            merge_source: None,
            // AV-115: the penalty estimate is zero on non-cancel actions.
            penalty_estimate: 0,
            slot_unlock_at: slot_unlock_opt(e),
            bounty_lamports: 0,
            bounty_unprofitable: false,
            arbiter_fee: None,
        });
    }
    // AV-106: the insurance-pool payout. Listed when
    // `is_pool_payout_eligible` holds at scan time — the predicate
    // mirrors every `pool_payout` gate (pool opted in and funded,
    // Funded, unencumbered, not paused, an authorized drainer
    // exists), so a listed payout is always executable. One action
    // per authorized drainer: the arbiter, and/or the bound
    // multisig authority PDA (the keeper proposes the payout to
    // the multisig — it does not sign as the PDA). `amount` is the
    // pool balance — the ceiling; the beneficiary and the exact
    // payout are the drainer's call-time judgment.
    if e.is_pool_payout_eligible(now) {
        let mut drainers: Vec<([u8; 32], &'static str)> = Vec::new();
        if let Some(arbiter) = e.arbiter() {
            drainers.push((arbiter, "arbiter"));
        }
        if let Some(bound) = e.multisig_authority() {
            drainers.push((bound.authority, "multisig_authority"));
        }
        for (caller, caller_role) in drainers {
            actions.push(KeeperAction {
                escrow_id: w.escrow_id,
                vault_address: w.vault_address(),
                kind: KeeperActionKind::PoolPayout,
                caller,
                caller_role,
                mint: e.mint(),
                // The beneficiary is the drainer's call-time
                // judgment — no destination is pinned by rule.
                refund_to: None,
                amount: e.pool_paid(),
                decimals: e.decimals(),
                reference: w.reference,
                extension_count: e.extension_count(),
                multisig_authority: e.multisig_authority,
                evidence_disclosure: None,
                funding_progress: None,
                reason: "pool_payout_available",
                merge_source: None,
                // AV-115: the penalty estimate is zero on non-cancel actions.
                penalty_estimate: 0,
                slot_unlock_at: slot_unlock_opt(e),
                bounty_lamports: 0,
                bounty_unprofitable: false,
                arbiter_fee: None,
            });
        }
    }
}

/// AV-114 merge-pair pass, extracted (AV-138): greedy pairing of `Funded`
/// escrows in candidate order. Each escrow joins at most one pair per
/// scan; the lower `escrow_id` survives as the merge target, the higher
/// is the source. A listed merge is always executable — both sides
/// unpaused, unexpired and `Funded`, same parties and term-identical
/// via `is_merge_compatible_with` (so `merge_escrows` cannot refuse it
/// with `MergeIncompatible`), and the u128-checked accumulation
/// re-verified at call time.
///
/// Restricting the pass to the `Funded` bucket is sound: the original
/// loop skipped every non-`Funded` entry without marking it paired, so
/// pairing over the bucket in watch order yields the identical pairs.
fn scan_merge_pairs(
    candidates: &[&WatchedEscrow],
    now: u64,
    actions: &mut Vec<KeeperAction>,
) {
    let mut paired = vec![false; candidates.len()];
    for i in 0..candidates.len() {
        if paired[i] {
            continue;
        }
        let a = candidates[i];
        // An expiry-eligible escrow already lists its cancel path —
        // merging it would race the cancel, so the scan leaves it
        // to the expiry exit.
        if a.escrow.state() != EscrowState::Funded
            || a.escrow.is_paused()
            || a.escrow.is_expiry_eligible(now)
        {
            continue;
        }
        for j in (i + 1)..candidates.len() {
            if paired[j] {
                continue;
            }
            let b = candidates[j];
            if b.escrow.state() != EscrowState::Funded
                || b.escrow.is_paused()
                || b.escrow.is_expiry_eligible(now)
            {
                continue;
            }
            if !a.escrow.is_merge_compatible_with(&b.escrow) {
                continue;
            }
            let (target, source) = if a.escrow_id <= b.escrow_id {
                (a, b)
            } else {
                (b, a)
            };
            paired[i] = true;
            paired[j] = true;
            actions.push(KeeperAction {
                escrow_id: target.escrow_id,
                vault_address: target.vault_address(),
                kind: KeeperActionKind::MergeEscrows,
                caller: target.escrow.initializer(),
                caller_role: "initializer",
                mint: target.escrow.mint(),
                // `merge_escrows` consolidates the lockups — no
                // single refund destination applies.
                refund_to: None,
                amount: source.escrow.remaining_amount(),
                decimals: target.escrow.decimals(),
                reference: target.reference,
                extension_count: target.escrow.extension_count(),
                multisig_authority: target.escrow.multisig_authority,
                evidence_disclosure: None,
                funding_progress: None,
                reason: "mergeable_pair",
                merge_source: Some(source.escrow_id),
                // AV-115: the penalty estimate is zero on non-cancel actions.
                penalty_estimate: 0,
                slot_unlock_at: slot_unlock_opt(&target.escrow),
                bounty_lamports: 0,
                bounty_unprofitable: false,
                arbiter_fee: None,
            });
            break;
        }
    }
}

/// Shared report construction for [`scan_keeper_actions`] and
/// [`scan_keeper_actions_indexed`] (AV-138): the scan-time fields are
/// identical — only the candidate source differs.
fn scan_keeper_actions_report(now: u64, scanned: usize, acc: KeeperScanAcc) -> KeeperReport {
    let KeeperScanAcc {
        actions,
        intent_releases,
        pending_auto_unpause,
        funding_bounds,
        pool_balance,
        pool_inflow,
    } = acc;
    KeeperReport {
        at: now,
        scanned,
        actions,
        // AV-98: the operator stamps the intended Jito tip via
        // `with_jito_tip` — the scan itself stays tip-free.
        jito_tip: None,
        // AV-123: the gasless-release intent annotations collected
        // above.
        intent_releases,
        // AV-106: the fleet-wide pool lines.
        pool_balance,
        pool_inflow,
        pool_outflow: pool_inflow.saturating_sub(pool_balance),
        // AV-120: the operator stamps the report sequence number via
        // `with_report_seq` — the scan itself stays sequence-free.
        report_seq: None,
        // AV-133: the armed auto-recovery schedules collected above.
        pending_auto_unpause,
        // AV-134: the funding amount windows collected above.
        funding_bounds,
    }
}

/// Indexed variant of [`scan_keeper_actions`] (AV-138): runs the identical
/// per-escrow logic over a keeper-maintained [`EscrowIndex`], so a bot
/// that re-scans the same watch list across slots pays the index build
/// once and reuses it. The merge-pair pass reads only the `Funded`
/// bucket instead of the whole list. Output is byte-identical to
/// [`scan_keeper_actions`] for the same snapshots (see the
/// `indexed_keeper_scan_matches_slice_scan` test); the indexed scans run
/// `verify_consistency` under `debug_assertions`.
pub fn scan_keeper_actions_indexed(index: &EscrowIndex, now: u64) -> KeeperReport {
    debug_assert!(index.verify_consistency().is_ok());
    let mut acc = KeeperScanAcc::default();
    for w in index.iter() {
        scan_one_keeper_escrow(w, now, &mut acc);
    }
    let funded = index.candidates_for_state(EscrowState::Funded);
    scan_merge_pairs(&funded, now, &mut acc.actions);
    scan_keeper_actions_report(now, index.len(), acc)
}

/// keeper with the party path.
/// AV-138: [`scan_keeper_actions_indexed`] runs the identical logic over a
/// keeper-maintained [`EscrowIndex`] — same output, pruned candidate reads.
pub fn scan_keeper_actions(watched: &[WatchedEscrow], now: u64) -> KeeperReport {
    let mut acc = KeeperScanAcc::default();
    for w in watched {
        scan_one_keeper_escrow(w, now, &mut acc);
    }
    // AV-114: merge-pair scan over the full watch list — see
    // `scan_merge_pairs` for the pairing rules.
    let all: Vec<&WatchedEscrow> = watched.iter().collect();
    scan_merge_pairs(&all, now, &mut acc.actions);
    scan_keeper_actions_report(now, watched.len(), acc)
}

/// One executable `close_vault` call: everything needed to build the
/// instruction, nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseAction {
    /// Which escrow's vault this call closes: the caller-supplied
    /// identity (the Anchor layer keys the vault PDA off it — the
    /// same convention as [`WatchedEscrow::escrow_id`]).
    pub escrow_id: [u8; 32],
    /// The key that must sign the `close_vault` call — always the
    /// escrow's initializer. AV-34 restricts `close_vault` to the
    /// initializer and checks the authority *before* state validity,
    /// so this is the canonical caller and the only key the chain
    /// will accept. It doubles as the instruction's `authority`
    /// argument: `close_vault(authority)` takes no other arguments —
    /// the vault account is the target, the initializer is the signer.
    pub caller: [u8; 32],
    /// Always `"initializer"` — the canonical (and only accepted)
    /// close caller.
    pub caller_role: &'static str,
    /// Estimated rent-exempt lamports the call returns to the
    /// initializer. Computed from [`crate::vault_close_rent_reclaimed`]
    /// — the mainnet rent-exempt minimum for the *current*
    /// [`crate::VAULT_SPACE`] — never a hardcoded figure: the account
    /// layout has grown since earlier constants, and the estimate
    /// tracks the layout automatically.
    pub rent_reclaimed: u64,
    /// Machine-readable reason: the terminal state the vault sits in —
    /// `"cancelled"`, `"released"`, or `"settled"`.
    pub reason: &'static str,
}

/// One per-caller close batch: every close action that a single
/// initializer signer must issue. Batching per caller matters for the
/// operator: one signer, one sweep, one rent-reclaim total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseBatch {
    /// The initializer all of this batch's actions sign for.
    pub caller: [u8; 32],
    /// This caller's close actions, in input order.
    pub actions: Vec<CloseAction>,
    /// Sum of `rent_reclaimed` across the batch's actions.
    pub total_reclaimed: u64,
}

/// The close-sweep result: terminal-state vaults grouped into
/// per-caller close batches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseReport {
    /// How many escrows were scanned.
    pub scanned: usize,
    /// Per-caller batches, in first-seen caller order, so a keeper
    /// feeding a stable watch list gets a stable sweep list.
    pub batches: Vec<CloseBatch>,
}

impl CloseReport {
    /// True when no closeable vault was found.
    pub fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }

    /// Hand-serialized JSON (the crate is dependency-free). Deterministic
    /// field order; keys are 64-char lowercase hex. Batches keep their
    /// first-seen caller order, actions keep the input order.
    ///
    /// ```json
    /// {"scanned":2,"batches":[
    ///   {"caller":"...","total_reclaimed":6201360,"actions":[
    ///     {"escrow_id":"...","action":"close_vault","caller":"...",
    ///      "caller_role":"initializer","rent_reclaimed":6201360,
    ///      "reason":"released"}
    ///   ]}
    /// ]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(64 + self.batches.len() * 360);
        s.push_str("{\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"batches\":[");
        for (bi, b) in self.batches.iter().enumerate() {
            if bi > 0 {
                s.push(',');
            }
            s.push_str("{\"caller\":\"");
            s.push_str(&hex32(&b.caller));
            s.push_str("\",\"total_reclaimed\":");
            s.push_str(&b.total_reclaimed.to_string());
            s.push_str(",\"actions\":[");
            for (i, a) in b.actions.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str("{\"escrow_id\":\"");
                s.push_str(&hex32(&a.escrow_id));
                s.push_str("\",\"action\":\"close_vault\",\"caller\":\"");
                s.push_str(&hex32(&a.caller));
                s.push_str("\",\"caller_role\":\"");
                s.push_str(a.caller_role);
                s.push_str("\",\"rent_reclaimed\":");
                s.push_str(&a.rent_reclaimed.to_string());
                s.push_str(",\"reason\":\"");
                s.push_str(a.reason);
                s.push_str("\"}");
            }
            s.push_str("]}");
        }
        s.push_str("]}");
        s
    }
}

/// Scan `watched` and return every immediately executable `close_vault`
/// call, grouped into per-caller batches. Pure read over the
/// snapshots: zero side effects, deterministic output in input order.
///
/// The scan lists exactly the vaults AV-34's `close_vault` accepts —
/// `Cancelled`, `Released`, `Settled` — and nothing else:
///
/// - `Disputed` is skipped: the chain rejects the close (the
///   arbitration is still live, and the vault account is the audit
///   surface the arbiter works from), so listing it would not be an
///   *executable* call.
/// - `Closed` is skipped: the rent deposit is already reclaimed and a
///   second `close_vault` fails with `InvalidStateTransition`.
/// - `Uninitialized` / `Funded` / `Activated` are skipped: their vault
///   accounts have not served their purpose yet, and the close would
///   fail the terminal-state gate.
///
/// AV-78: keeper aggregate statistics view. A read-only rollup over the
/// watched fleet — per-state counts (all eight lifecycle states),
/// amount histogram, average open escrow duration (`now - fund_at` over
/// `Funded`/`Disputed`), and total locked value — for operator
/// dashboards. Pure reads: no chain writes, no state mutation, no events
/// emitted.
///
/// Completed escrow durations are unavailable on this path: plain watch
/// snapshots carry no event history, so
/// [`EscrowAggregateView::avg_completed_duration_secs`] stays `None`
/// (never fabricated); use
/// [`EscrowAggregateView::from_indexed`] for the full-fidelity view.
pub fn scan_aggregate_view(watched: &[WatchedEscrow], now: u64) -> EscrowAggregateView {
    EscrowAggregateView::from_watched(watched, now)
}

/// The scan carries no `now`: closing has no time gate, so the list is
/// valid until the vaults are closed and re-scanned.
pub fn scan_closeable(watched: &[WatchedEscrow]) -> CloseReport {    // AV-40: `rent_reclaimed` is computed from the current
    // `VAULT_SPACE` formula (via `vault_close_rent_reclaimed`), never
    // hardcoded — the same figure `close_vault` returns on success.
    let rent = vault_close_rent_reclaimed();
    let mut batches: Vec<CloseBatch> = Vec::new();
    for w in watched {
        let e = &w.escrow;
        // Mirror AV-34's terminal-state gate exactly: only the four
        // states `close_vault` accepts contribute an action (Split since
        // AV-81 — a split parent's funds were re-homed, so its vault
        // carries nothing but the rent deposit).
        let reason = match e.state() {
            EscrowState::Cancelled => "cancelled",
            EscrowState::Released => "released",
            EscrowState::Settled => "settled",
            EscrowState::Split => "split",
            _ => continue,
        };
        let caller = e.initializer();
        let action = CloseAction {
            escrow_id: w.escrow_id,
            // AV-34 restricts `close_vault` to the initializer —
            // authority is checked before state validity — so the
            // initializer is the canonical caller *and* the only key
            // the chain accepts.
            caller,
            caller_role: "initializer",
            rent_reclaimed: rent,
            reason,
        };
        // Group per caller, batches in first-seen caller order.
        match batches.iter_mut().find(|b| b.caller == caller) {
            Some(batch) => {
                batch.actions.push(action);
                batch.total_reclaimed += rent;
            }
            None => batches.push(CloseBatch {
                caller,
                actions: vec![action],
                total_reclaimed: rent,
            }),
        }
    }
    CloseReport {
        scanned: watched.len(),
        batches,
    }
}

/// One executable stale-vault close: everything the initializer needs
/// to sign and submit `close_vault`, nothing more. The keeper never
/// signs — this is the *to-be-signed* payload (see
/// [`stale_vault_signable_message`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaleVaultAction {
    /// Which escrow's vault this close targets: the caller-supplied
    /// identity (the Anchor layer keys the vault PDA off it — the same
    /// convention as [`WatchedEscrow::escrow_id`]).
    pub escrow_id: [u8; 32],
    /// The key that must sign the `close_vault` call — always the
    /// escrow's initializer. AV-34 restricts `close_vault` to the
    /// initializer (checked before state validity), so it is the only
    /// key the chain will accept.
    pub caller: [u8; 32],
    /// Always `"initializer"` — the canonical (and only accepted)
    /// close caller.
    pub caller_role: &'static str,
    /// The vault's measured lamports balance at scan time — always
    /// exactly [`crate::vault_close_rent_reclaimed`]: only rent-only
    /// vaults are listed (see [`scan_stale_vaults`]).
    pub vault_lamports: u64,
    /// The rent-exempt lamports the close returns to the initializer —
    /// [`crate::vault_close_rent_reclaimed`], the mainnet rent-exempt
    /// minimum for the *current* [`crate::VAULT_SPACE`], never a
    /// hardcoded figure.
    pub rent_reclaimed: u64,
    /// The escrow's deadline (Unix seconds), for operator context:
    /// most stale vaults became terminal through `cancel_expired`
    /// after this deadline passed and were simply never closed.
    /// `u64::MAX` = no timeout (see [`Escrow::expires_at`]).
    pub expires_at: u64,
    /// Machine-readable reason: the terminal state the vault sits in —
    /// `"cancelled"`, `"released"`, or `"settled"` (the same reasons
    /// [`scan_closeable`] stamps).
    pub reason: &'static str,
}

/// One per-caller stale-vault sweep batch: every close action a single
/// initializer signer must issue. One signer, one sweep, one
/// rent-reclaim total — the dry-run preview the operator (or multisig)
/// approves before any signature is produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleVaultBatch {
    /// The initializer all of this batch's actions sign for.
    pub caller: [u8; 32],
    /// This caller's close actions, in input order.
    pub actions: Vec<StaleVaultAction>,
    /// Σ `rent_reclaimed` across the batch's actions, accumulated with
    /// `checked_add` (the AV-79 convention — a defensive belt against
    /// any future per-close variance).
    pub total_reclaimed: u64,
}

impl StaleVaultBatch {
    /// Render this batch's to-be-signed bundle as deterministic JSON:
    /// one base64 legacy transaction message per action (see
    /// [`stale_vault_signable_message`]), in input order. A multisig or
    /// CLI signs each message with the batch's caller key and submits —
    /// one message, one signature, one instruction (the AV-71 shape).
    ///
    /// ```json
    /// {"caller":"...","messages":[
    ///   {"escrow_id":"...","message":"<base64>"}
    /// ]}
    /// ```
    pub fn to_bundle_json(
        &self,
        program_id: Pubkey,
        recent_blockhash: Pubkey,
    ) -> Result<String, TxMessageError> {
        let mut s = String::with_capacity(64 + self.actions.len() * 320);
        s.push_str("{\"caller\":\"");
        s.push_str(&hex32(&self.caller));
        s.push_str("\",\"messages\":[");
        for (i, a) in self.actions.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&a.escrow_id));
            s.push_str("\",\"message\":\"");
            s.push_str(&stale_vault_signable_message(
                program_id,
                a,
                recent_blockhash,
            )?);
            s.push_str("\"}");
        }
        s.push_str("]}");
        Ok(s)
    }
}

/// The stale-vault sweep result: rent-only terminal vaults grouped
/// into per-caller batches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleVaultReport {
    /// How many vaults were scanned.
    pub scanned: usize,
    /// The canonical rent-exempt minimum the scan compared balances
    /// against ([`crate::vault_close_rent_reclaimed`]).
    pub required_lamports: u64,
    /// Per-caller batches, in first-seen caller order, so a keeper
    /// feeding a stable watch list gets a stable sweep list.
    pub batches: Vec<StaleVaultBatch>,
}

impl StaleVaultReport {
    /// True when no stale rent-only vault was found.
    pub fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }

    /// Hand-serialized JSON (the crate is dependency-free): the
    /// dry-run preview — per-initializer grouped reclaimable-rent
    /// totals. Deterministic field order; keys are 64-char lowercase
    /// hex; lamports are plain integers — the exact unit the close
    /// returns.
    ///
    /// ```json
    /// {"scanned":2,"required_lamports":6201360,"batches":[
    ///   {"caller":"...","total_reclaimed":6201360,"actions":[
    ///     {"escrow_id":"...","action":"close_vault","caller":"...",
    ///      "caller_role":"initializer","vault_lamports":6201360,
    ///      "rent_reclaimed":6201360,"expires_at":1700000000,
    ///      "reason":"cancelled"}
    ///   ]}
    /// ]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(64 + self.batches.len() * 420);
        s.push_str("{\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"required_lamports\":");
        s.push_str(&self.required_lamports.to_string());
        s.push_str(",\"batches\":[");
        for (bi, b) in self.batches.iter().enumerate() {
            if bi > 0 {
                s.push(',');
            }
            s.push_str("{\"caller\":\"");
            s.push_str(&hex32(&b.caller));
            s.push_str("\",\"total_reclaimed\":");
            s.push_str(&b.total_reclaimed.to_string());
            s.push_str(",\"actions\":[");
            for (i, a) in b.actions.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str("{\"escrow_id\":\"");
                s.push_str(&hex32(&a.escrow_id));
                s.push_str("\",\"action\":\"close_vault\",\"caller\":\"");
                s.push_str(&hex32(&a.caller));
                s.push_str("\",\"caller_role\":\"");
                s.push_str(a.caller_role);
                s.push_str("\",\"vault_lamports\":");
                s.push_str(&a.vault_lamports.to_string());
                s.push_str(",\"rent_reclaimed\":");
                s.push_str(&a.rent_reclaimed.to_string());
                s.push_str(",\"expires_at\":");
                s.push_str(&a.expires_at.to_string());
                s.push_str(",\"reason\":\"");
                s.push_str(a.reason);
                s.push_str("\"}");
            }
            s.push_str("]}");
        }
        s.push_str("]}");
        s
    }
}

/// Scan `watched` for stale rent-only vaults and return every
/// immediately executable `close_vault` call, grouped into per-caller
/// batches. Pure read over the snapshots and the measured balances:
/// zero side effects, deterministic output in input order.
///
/// A vault is *stale* when its account has served its purpose but still
/// exists carrying only the rent-exempt deposit:
///
/// - the escrow is in a terminal state AV-34's `close_vault` accepts
///   (`Cancelled` / `Released` / `Settled` — the same gate
///   [`scan_closeable`] mirrors), and
/// - the measured vault balance is *exactly* the canonical rent-exempt
///   minimum ([`crate::vault_close_rent_reclaimed`]).
///
/// Anything else is skipped, never listed:
///
/// - `Disputed`: the arbitration is still live; the chain rejects the
///   close and the vault account is the arbiter's audit surface.
/// - `Closed`: the rent is already reclaimed and the account is gone
///   (like [`scan_rent_health`], there is no balance left to sweep).
/// - `Uninitialized` / `Funded` / `Activated`: their vault accounts
///   have not served their purpose yet. An expired `Funded` vault is
///   the AV-20 / AV-48 cancel path's job first — once cancelled it
///   surfaces here on the next scan.
/// - a paused vault: `close_vault` fails it with `Paused` (AV-46), so
///   the call is not executable.
/// - a terminal vault whose balance is *above* the rent minimum still
///   holds user funds (or fee dust): the sweep must not touch it
///   without the operator's fund review. A balance *below* the minimum
///   is the AV-43 rent-health scan's underfunded case — the sweep's
///   reclaim estimate is the canonical figure, so it never lists a
///   vault it would misprice.
///
/// "Closed/expired" in the AV-80 backlog item maps to this: the escrow
/// is closed for business (terminal) — most stale vaults became
/// terminal through `cancel_expired` after their deadline passed and
/// were simply never closed; [`StaleVaultAction::expires_at`] carries
/// that deadline for operator context.
///
/// The scan carries no `now`: closing has no time gate, so the list is
/// valid until the vaults are closed and re-scanned.
///
/// Unlike [`scan_closeable`] (which *plans* every terminal close), the
/// sweep stops at the signature boundary: `close_vault` needs the
/// *initializer's* signature, and the keeper must not sign for it — so
/// the scan emits the to-be-signed bundle
/// ([`stale_vault_signable_message`] /
/// [`StaleVaultBatch::to_bundle_json`]) and the dry-run preview
/// ([`StaleVaultReport::to_json`]) for an offline signer or multisig.
pub fn scan_stale_vaults(watched: &[WatchedEscrowWithBalance]) -> StaleVaultReport {
    // AV-80: the canonical figure is the main formula — the same number
    // `initialize` funds and `close_vault` promises.
    let rent = vault_close_rent_reclaimed();
    let mut batches: Vec<StaleVaultBatch> = Vec::new();
    for w in watched {
        let e = &w.escrow;
        // Mirror AV-34's terminal-state gate exactly: only the four
        // states `close_vault` accepts contribute an action (Split since
        // AV-81). A paused vault fails `close_vault` with `Paused`
        // (AV-46), so it is not executable and is skipped too.
        if e.is_paused() {
            continue;
        }
        let reason = match e.state() {
            EscrowState::Cancelled => "cancelled",
            EscrowState::Released => "released",
            EscrowState::Settled => "settled",
            EscrowState::Split => "split",
            _ => continue,
        };
        // Rent-only: the balance is exactly the canonical rent-exempt
        // minimum — nothing but the deposit is left to reclaim.
        if w.vault_lamports != rent {
            continue;
        }
        let caller = e.initializer();
        let action = StaleVaultAction {
            escrow_id: w.escrow_id,
            // AV-34 restricts `close_vault` to the initializer —
            // authority is checked before state validity — so the
            // initializer is the canonical caller *and* the only key
            // the chain accepts.
            caller,
            caller_role: "initializer",
            vault_lamports: w.vault_lamports,
            rent_reclaimed: rent,
            expires_at: e.expires_at(),
            reason,
        };
        // Group per caller, batches in first-seen caller order; the Σ
        // accumulates with `checked_add` (the AV-79 convention).
        match batches.iter_mut().find(|b| b.caller == caller) {
            Some(batch) => {
                batch.actions.push(action);
                batch.total_reclaimed = batch
                    .total_reclaimed
                    .checked_add(rent)
                    .expect("AV-80: total rent overflowed u64");
            }
            None => batches.push(StaleVaultBatch {
                caller,
                actions: vec![action],
                total_reclaimed: rent,
            }),
        }
    }
    StaleVaultReport {
        scanned: watched.len(),
        required_lamports: rent,
        batches,
    }
}

/// Build the to-be-signed legacy transaction message for one
/// stale-vault close action: the real `close_vault` instruction bytes —
/// the 8-byte discriminator recomputed from the IDL instruction name
/// via [`instruction_discriminator`] (the same single source of truth
/// the AV-29 IDL pipeline pins; the spec's `params: []` means the data
/// is the discriminator alone) — plus the program-declared account
/// metas, compiled into a genuine Solana legacy transaction message
/// with the AV-71 machinery and returned as base64 for an offline
/// signer or multisig to sign and submit.
///
/// The keeper never signs: this is the *unsigned* bundle the sweep
/// outputs — the message carries exactly what `close_vault` needs (the
/// vault account is the target, the initializer is the sole signer)
/// and nothing the keeper must not decide. Program id and recent
/// blockhash are caller-supplied (the AV-71 honesty labels apply: the
/// keeper fetches a fresh blockhash from the cluster; the skeleton's
/// `declare_id!` string is not valid base58 and is never decoded
/// off-chain).
///
/// Account metas mirror the program's `CloseVault` accounts struct in
/// declared order: `vault` — writable, non-signer (Anchor's
/// `close = initializer` constraint closes it and pays the
/// initializer); `initializer` — writable, signer (it receives the
/// closed lamports). A multisig proposal signs one message per
/// instruction; no address-table lookups are compiled in (legacy
/// message).
pub fn stale_vault_signable_message(
    program_id: Pubkey,
    action: &StaleVaultAction,
    recent_blockhash: Pubkey,
) -> Result<String, TxMessageError> {
    // The discriminator is recomputed from the IDL name on every call —
    // a renamed instruction or a drifted spec changes the bytes, never
    // silently signs the wrong entrypoint.
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&instruction_discriminator("close_vault"));
    let ix = ProgramInstruction {
        program_id,
        accounts: vec![
            AccountMeta {
                pubkey: action.escrow_id,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: action.caller,
                is_signer: true,
                is_writable: true,
            },
        ],
        data,
    };
    let msg = compile_message(&ix, recent_blockhash);
    Ok(encode_base64(&encode_message(&msg)))
}

/// Assemble a third-party CPI invocation for a watched escrow
/// (AV-83): validates the invocation shape *and* the escrow's CPI
/// target allowlist ([`Escrow::cpi_target_allowed`]) before returning
/// the invocation, so a keeper bundle never carries a doomed target.
///
/// Why fail at assembly: the state machine's
/// [`Escrow::release_via_cpi`] would roll the release back anyway with
/// [`EscrowError::InvalidCpiTarget`], but a keeper that assembles
/// first and checks never would list phantom executable actions in
/// its report and burn a signature round-trip on a rejection it could
/// have predicted. The check order mirrors the state machine — shape
/// first, then the allowlist — so assembly and execution agree on
/// every input.
///
/// [`Escrow::release_via_cpi`]: crate::Escrow::release_via_cpi
/// [`EscrowError::InvalidCpiTarget`]: crate::EscrowError::InvalidCpiTarget
pub fn assemble_cpi_invocation(
    watched: &WatchedEscrow,
    program_id: Pubkey,
    accounts: Vec<AccountMeta>,
    data: Vec<u8>,
) -> Result<crate::cpi_call::CpiInvocation, EscrowError> {
    let inv = crate::cpi_call::CpiInvocation {
        program_id,
        accounts,
        data,
    };
    // Same order as `release_via_cpi`: shape, then the allowlist.
    crate::cpi_call::validate_cpi_invocation(&inv)?;
    if !watched.escrow.cpi_target_allowed(&program_id) {
        return Err(EscrowError::InvalidCpiTarget);
    }
    Ok(inv)
}

/// Errors from the keeper's off-chain CPI quote lock (AV-132).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpiQuoteError {
    /// The off-chain quote estimated a zero payout — nothing to lock.
    ZeroQuote,
    /// The slippage tolerance exceeds 10_000 bps (100%).
    InvalidSlippageBps,
    /// Post-execution assertion: the reported actual came back below
    /// the locked `min_payout` floor — the execution deviated from the
    /// quote beyond tolerance, rejected off-chain.
    SlippageExceeded,
    /// Post-execution assertion: the quote was older than the
    /// keeper's maximum quote age at execution time — the market may
    /// have moved since the lock, so the execution is rejected even
    /// when the floor held.
    QuoteStale,
}

/// The keeper's off-chain CPI quote lock (AV-132 — Solana/DeFi).
///
/// Before submitting a `release_via_cpi`, the keeper fetches an
/// off-chain quote for the third-party leg (a DEX aggregator quote,
/// a lending protocol's deposit preview, a streaming splitter's
/// estimate) and *locks* it at bundle-signing time: the quoted payout
/// and the derived `min_payout` floor are committed alongside the
/// signature, so the on-chain instruction carries the floor the quote
/// justified. The state machine enforces that floor after execution
/// ([`Escrow::release_via_cpi`] →
/// [`EscrowError::SlippageExceeded`](crate::EscrowError::SlippageExceeded));
/// the keeper additionally asserts the execution against the locked
/// quote itself ([`CpiQuote::verify_execution`]) — a deviation beyond
/// the floor, or a quote gone stale, is rejected off-chain even when
/// the chain accepted the floor.
///
/// Pure data + checked arithmetic: no I/O, no oracle reads. The
/// keeper operator supplies the quote; this type only locks it and
/// judges the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpiQuote {
    /// The off-chain estimated taker-leg payout (lamports / tokens).
    pub quoted_payout: u64,
    /// The slippage floor derived at lock time — the `min_payout`
    /// the keeper stamps on the `release_via_cpi` instruction.
    pub min_payout: u64,
    /// Unix seconds when the quote was locked (bundle signing time).
    pub locked_at: u64,
    /// The quote provider's identifier / commitment — opaque to the
    /// state machine; the keeper joins it to its own records.
    pub quote_id: [u8; 32],
}

impl CpiQuote {
    /// Lock a quote: validate the estimate and derive the `min_payout`
    /// floor as `quoted_payout * (10_000 - max_slippage_bps) / 10_000`
    /// (floor division, like the protocol-fee math). A zero quote or a
    /// tolerance above 100% is rejected — the keeper never signs a
    /// floor it cannot justify.
    pub fn lock(
        quoted_payout: u64,
        max_slippage_bps: u16,
        locked_at: u64,
        quote_id: [u8; 32],
    ) -> Result<Self, CpiQuoteError> {
        if quoted_payout == 0 {
            return Err(CpiQuoteError::ZeroQuote);
        }
        if max_slippage_bps > 10_000 {
            return Err(CpiQuoteError::InvalidSlippageBps);
        }
        let keep_bps = 10_000u64 - max_slippage_bps as u64;
        let min_payout = quoted_payout
            .checked_mul(keep_bps)
            .map(|v| v / 10_000)
            .ok_or(CpiQuoteError::InvalidSlippageBps)?;
        Ok(Self {
            quoted_payout,
            min_payout,
            locked_at,
            quote_id,
        })
    }

    /// Post-execution assertion: judge the reported `actual_payout`
    /// against the locked quote. Rejects when the actual falls below
    /// the locked floor ([`CpiQuoteError::SlippageExceeded`] — the
    /// execution deviated from the quote beyond tolerance) or when the
    /// quote is older than `max_quote_age_secs` at `executed_at`
    /// ([`CpiQuoteError::QuoteStale`] — the market may have moved since
    /// the lock). An execution exactly at the floor with a fresh quote
    /// passes.
    pub fn verify_execution(
        &self,
        actual_payout: u64,
        executed_at: u64,
        max_quote_age_secs: u64,
    ) -> Result<(), CpiQuoteError> {
        if actual_payout < self.min_payout {
            return Err(CpiQuoteError::SlippageExceeded);
        }
        let age = executed_at.saturating_sub(self.locked_at);
        if age > max_quote_age_secs {
            return Err(CpiQuoteError::QuoteStale);
        }
        Ok(())
    }
}

#[cfg(test)]
mod keeper_tests {
    use super::*;
    use crate::{MilestonePlan, QuorumPolicy, VestingSchedule};

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const CAROL: [u8; 32] = [0xCC; 32]; // other taker
    const A1: [u8; 32] = [0xA1; 32]; // attestors
    const A2: [u8; 32] = [0xA2; 32];
    const A3: [u8; 32] = [0xA3; 32];
    const MINT: [u8; 32] = [0xD0; 32];
    const ID1: [u8; 32] = [0x01; 32];
    const ID2: [u8; 32] = [0x02; 32];
    const ID3: [u8; 32] = [0x03; 32];
    const AMOUNT: u64 = 1_000_000;
    const VEST_START: u64 = 1_700_000_000;
    const VEST_END: u64 = 1_800_000_000;
    const MID: u64 = 1_750_000_000; // half-vested
    const NEVER: u64 = u64::MAX; // no timeout

    fn watch(id: [u8; 32], escrow: Escrow) -> WatchedEscrow {
        // AV-53: the watch entry carries the escrow's reference memo,
        // like a keeper operator copying it when building the watch
        // list.
        let reference = escrow.reference();
        WatchedEscrow {
            escrow_id: id,
            escrow,
            reference,
            vault_derivation: None,
            pending_intent: None,
        }
    }

    fn funded(amount: u64, expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, amount, expires_at).unwrap();
        e.fund(ALICE, MID).unwrap();
        e
    }

    fn funded_vesting(expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, expires_at)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e
    }

    fn hex_of(byte: u8) -> String {
        let h: String = format!("{:02x}", byte);
        h.repeat(32)
    }

    #[test]
    fn empty_input_scans_to_empty_report() {
        let report = scan_keeper_actions(&[], MID);
        assert!(report.is_empty());
        assert_eq!(report.scanned, 0);
        assert_eq!(report.to_json(), r#"{"at":1750000000,"scanned":0,"total_estimated_cu":0,"jito_tip":null,"intent_releases":[],"pool_balance":0,"pool_inflow":0,"pool_outflow":0,"actions":[],"report_seq":null,"pending_auto_unpause":[],"funding_bounds":[]}"#);
    }

    #[test]
    fn report_seq_stamps_onto_json() {
        // AV-120: the scan itself stays sequence-free; the operator
        // stamps the next sequence before diffing.
        let legacy = scan_keeper_actions(&[], MID);
        assert_eq!(legacy.report_seq, None);
        assert!(legacy.to_json().ends_with(",\"report_seq\":null,\"pending_auto_unpause\":[],\"funding_bounds\":[]}"));
        let stamped = scan_keeper_actions(&[], MID).with_report_seq(9);
        assert_eq!(stamped.report_seq, Some(9));
        assert!(stamped.to_json().ends_with(",\"report_seq\":9,\"pending_auto_unpause\":[],\"funding_bounds\":[]}"));
        // The stamp is last and fixed-order: pin the tail bytes.
        assert!(stamped
            .to_json()
            .ends_with("\"actions\":[],\"report_seq\":9,\"pending_auto_unpause\":[],\"funding_bounds\":[]}"));
    }

    #[test]
    fn funding_bounds_are_listed_in_the_report() {
        // AV-134: vaults with a configured funding window are listed
        // with their floor and ceiling; vaults without bounds are not.
        let bounded = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_amount_bounds(100_000, 900_000)
            .unwrap();
        let plain = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER).unwrap();
        let watched = [watch(ID1, bounded), watch(ID2, plain)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.funding_bounds.len(), 1);
        let b = &report.funding_bounds[0];
        assert_eq!(b.escrow_id, ID1);
        assert_eq!((b.min_amount, b.max_amount), (100_000, 900_000));
        let json = report.to_json();
        assert!(json.contains("\"funding_bounds\":[{\"escrow_id\":\""));
        assert!(json.contains("\"min_amount\":100000,\"max_amount\":900000"));
    }

    #[test]
    fn keeper_discloses_escalated_penalty_estimate() {
        // AV-115: the report carries the taker-initiated penalty at
        // scan time — base 250 bps + 100 bps/day × 10 days = 1250 bps
        // of the 1_000_000 remainder = 125_000.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, 0)
            .unwrap()
            .with_penalty_bps(250)
            .unwrap()
            .with_penalty_escalation(100, 10_000)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        let now = 10 * 86_400; // 10 days past the expiry gate (0)
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, now);
        assert_eq!(report.actions.len(), 2);
        for a in &report.actions {
            assert!(
                matches!(
                    a.kind,
                    KeeperActionKind::CancelExpired | KeeperActionKind::CrankExpired
                ),
                "unexpected kind {:?}",
                a.kind
            );
            assert_eq!(a.penalty_estimate, 125_000, "escalated estimate on {:?}", a.kind);
        }
        // The estimate rides the report JSON for operator dashboards.
        let json = report.to_json();
        assert_eq!(json.matches("\"penalty_estimate\":125000").count(), 2);
    }

    #[test]
    fn keeper_penalty_estimate_is_zero_without_penalty() {
        let watched = [watch(ID1, funded(AMOUNT, 0))];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 2);
        for a in &report.actions {
            assert_eq!(a.penalty_estimate, 0);
        }
        assert!(report.to_json().contains("\"penalty_estimate\":0"));
    }

    #[test]
    fn keeper_penalty_estimate_uses_fixed_rate_without_escalation() {
        // AV-24 only: the estimate is the fixed rate no matter how
        // late the scan runs.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, 0)
            .unwrap()
            .with_penalty_bps(250)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, 365 * 86_400);
        assert_eq!(report.actions.len(), 2);
        for a in &report.actions {
            assert_eq!(a.penalty_estimate, 25_000);
        }
    }

    #[test]
    fn unfunded_and_terminal_escrows_yield_no_actions() {
        let uninit = Escrow::initialize(ALICE, BOB, AMOUNT, 0).unwrap();
        let mut released = funded(AMOUNT, NEVER);
        released.release(ALICE, 1_750_000_000, AMOUNT, None, BOB).unwrap();
        let mut cancelled = funded(AMOUNT, NEVER);
        cancelled.cancel(ALICE, None, ALICE, 0).unwrap();
        let watched = [watch(ID1, uninit), watch(ID2, released), watch(ID3, cancelled)];
        let report = scan_keeper_actions(&watched, MID);
        assert!(report.is_empty());
        assert_eq!(report.scanned, 3);
    }

    #[test]
    fn funded_unexpired_plain_escrow_has_no_keeper_action() {
        let watched = [watch(ID1, funded(AMOUNT, NEVER))];
        let report = scan_keeper_actions(&watched, MID);
        assert!(report.is_empty());
    }

    #[test]
    fn expired_escrow_lists_cancel_expired_for_initializer() {
        let watched = [watch(ID1, funded(AMOUNT, 0))];
        let report = scan_keeper_actions(&watched, MID);
        // AV-48: the party-signed path plus the permissionless crank.
        assert_eq!(report.actions.len(), 2);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::CancelExpired);
        assert_eq!(a.escrow_id, ID1);
        assert_eq!(a.caller, ALICE);
        assert_eq!(a.caller_role, "initializer");
        assert_eq!(a.mint, None);
        assert_eq!(a.amount, AMOUNT);
        assert_eq!(a.reason, "expired");
        let c = report.actions[1];
        assert_eq!(c.kind, KeeperActionKind::CrankExpired);
        assert_eq!(c.escrow_id, ID1);
        assert_eq!(c.caller, [0u8; 32], "the crank is permissionless");
        assert_eq!(c.caller_role, "anyone");
        assert_eq!(c.mint, None);
        assert_eq!(c.refund_to, Some(ALICE), "same pinned destination");
        assert_eq!(c.amount, AMOUNT);
        assert_eq!(c.reason, "expired");
    }

    #[test]
    fn paused_escrow_lists_no_crank_action() {
        // AV-48: the crank fails on a paused escrow (`require_not_paused`
        // runs first), so the keeper must not list it — a listed crank
        // is always executable. The pre-existing party-signed
        // `cancel_expired` listing is untouched by AV-48.
        const PAUSE_AUTH: [u8; 32] = [0x9A; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, 0)
            .unwrap()
            .with_pause_authority(PAUSE_AUTH)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e.pause(PAUSE_AUTH, None).unwrap();
        assert!(e.is_paused());
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert!(
            report
                .actions
                .iter()
                .all(|a| a.kind != KeeperActionKind::CrankExpired),
            "a paused escrow must not list the crank: {report:?}"
        );
    }

    #[test]
    fn crank_action_json_names_crank_expired_and_anyone_caller() {
        // AV-48: the crank action serializes with the new action name
        // and the `"anyone"` caller role so operator tooling can
        // distinguish it from the party-signed path.
        let watched = [watch(ID1, funded(AMOUNT, 0))];
        let report = scan_keeper_actions(&watched, MID);
        let json = report.to_json();
        assert!(json.contains("\"action\":\"crank_expired\""));
        assert!(json.contains("\"caller_role\":\"anyone\""));
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        // `now == expires_at` is expiry-eligible (`now >= expires_at`).
        let watched = [watch(ID1, funded(AMOUNT, MID))];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 2);
        assert_eq!(report.actions[0].kind, KeeperActionKind::CancelExpired);
        assert_eq!(report.actions[1].kind, KeeperActionKind::CrankExpired);
        // One second earlier: not eligible.
        let report = scan_keeper_actions(&watched, MID - 1);
        assert!(report.is_empty());
    }

    #[test]
    fn grace_period_defers_cancel_expired_listing() {
        // AV-21: the keeper honors the grace period exactly as the chain
        // enforces it — a listed `cancel_expired` is always executable,
        // never a `NotExpired` rejection from clock drift.
        const GRACE: u64 = 300;
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, MID)
            .unwrap()
            .with_grace_period(GRACE)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        let watched = [watch(ID1, e)];
        // At expires_at: the chain would reject — the keeper lists nothing.
        let report = scan_keeper_actions(&watched, MID);
        assert!(report.is_empty(), "keeper must not list a premature cancel");
        // Inside the grace window: still nothing.
        let report = scan_keeper_actions(&watched, MID + GRACE - 1);
        assert!(report.is_empty());
        // At expires_at + grace: executable, listed.
        let report = scan_keeper_actions(&watched, MID + GRACE);
        assert_eq!(report.actions.len(), 2);
        assert_eq!(report.actions[0].kind, KeeperActionKind::CancelExpired);
        assert_eq!(report.actions[1].kind, KeeperActionKind::CrankExpired);
        assert_eq!(report.actions[0].reason, "expired");
        // Cross-check against the real transition at every boundary: the
        // keeper's predicate and the chain's gate never disagree.
        for now in [MID - 1, MID, MID + 1, MID + GRACE - 1, MID + GRACE, MID + GRACE + 1] {
            let listed = !scan_keeper_actions(&watched, now).is_empty();
            let mut probe = e;
            let executable = probe.cancel_expired(ALICE, now, None, ALICE).is_ok();
            assert_eq!(listed, executable, "keeper/chain disagree at now={now}");
        }
    }

    #[test]
    fn never_expires_escrow_is_never_listed_for_cancel() {
        let watched = [watch(ID1, funded(AMOUNT, NEVER))];
        let report = scan_keeper_actions(&watched, u64::MAX - 1);
        assert!(report.is_empty());
    }

    #[test]
    fn cancel_expired_refunds_the_remainder_after_partial_release() {
        let mut e = funded(AMOUNT, 0);
        e.release(ALICE, 1_750_000_000, 400_000, None, BOB).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 2);
        assert_eq!(report.actions[0].amount, 600_000);
        assert_eq!(report.actions[1].kind, KeeperActionKind::CrankExpired);
        assert_eq!(report.actions[1].amount, 600_000);
    }

    #[test]
    fn mint_bound_escrow_carries_the_mint_argument() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, 0)
            .unwrap()
            .with_mint(MINT)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 2);
        assert_eq!(report.actions[0].mint, Some(MINT));
        assert_eq!(report.actions[1].kind, KeeperActionKind::CrankExpired);
        assert_eq!(report.actions[1].mint, Some(MINT));
        let json = report.to_json();
        assert!(
            json.contains(&format!("\"mint\":\"{}\"", hex_of(0xD0))),
            "mint must serialize as hex, got: {json}"
        );
    }

    #[test]
    fn vesting_mid_schedule_lists_claim_for_taker() {
        let watched = [watch(ID1, funded_vesting(NEVER))];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::Claim);
        assert_eq!(a.escrow_id, ID1);
        assert_eq!(a.caller, BOB);
        assert_eq!(a.caller_role, "taker");
        // Half the linear curve vested: floor(1_000_000 / 2) = 500_000.
        assert_eq!(a.amount, 500_000);
        assert_eq!(a.reason, "vesting_unlocked");
    }

    #[test]
    fn vesting_before_start_lists_nothing() {
        let watched = [watch(ID1, funded_vesting(NEVER))];
        let report = scan_keeper_actions(&watched, VEST_START - 1);
        assert!(report.is_empty());
    }

    #[test]
    fn vesting_curve_prices_the_keeper_claim_listing() {
        // AV-90: the keeper's claim listing goes through
        // `claimable_amount` -> `vested_amount`, so it inherits the
        // non-linear curve — the listed amount is the curve's value,
        // not the linear interpolation.
        use crate::VestingCurve;
        let curve =
            VestingCurve::stepped(&[(MID, 2_500), (VEST_END, 10_000)], VEST_START, VEST_END)
                .unwrap();
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting_curve(
                VestingSchedule::new(VEST_START, VEST_END).unwrap(),
                curve,
            )
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        let watched = [watch(ID1, e)];
        // Linear would list 500_000 at MID; the curve lists 250_000.
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].kind, KeeperActionKind::Claim);
        assert_eq!(report.actions[0].amount, 250_000);
        assert_eq!(report.actions[0].reason, "vesting_unlocked");
        // Before the first tier nothing is listed.
        let report = scan_keeper_actions(&watched, MID - 1);
        assert!(report.is_empty(), "pre-tier: nothing vested, no claim");
    }

    #[test]
    fn vesting_before_cliff_lists_nothing() {
        // AV-51: the keeper's claim listing goes through
        // `claimable_amount` -> `vested_amount`, so it inherits the
        // cliff gate — a pre-cliff escrow is never listed as an
        // executable claim.
        const CLIFF: u64 = 1_750_000_000;
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting_cliff(VEST_START, VEST_END, CLIFF)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, CLIFF - 1);
        assert!(
            report.is_empty(),
            "pre-cliff: nothing vested, no executable claim"
        );
        // At the cliff the claim becomes executable and lists the
        // linear value.
        let report = scan_keeper_actions(&watched, CLIFF);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].kind, KeeperActionKind::Claim);
        assert_eq!(report.actions[0].amount, 500_000);
    }

    #[test]
    fn claim_amount_is_vested_minus_released() {
        // The initializer released ahead of the curve: the claimable
        // remainder is what is vested but not yet released.
        let mut e = funded_vesting(NEVER);
        e.release(ALICE, 1_750_000_000, 200_000, None, BOB).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].amount, 300_000); // 500_000 - 200_000
    }

    #[test]
    fn claim_requires_satisfied_quorum_to_be_executable() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_quorum(QuorumPolicy::new(&[A1, A2, A3], &[1, 1, 1], 2).unwrap())
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e.attest(A1).unwrap(); // 1 of 2: the claim call would fail
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert!(
            report.is_empty(),
            "an unsatisfiable claim is not an executable call"
        );
        // Satisfy the quorum: the claim becomes executable.
        let mut e2 = e;
        e2.attest(A2).unwrap();
        let watched = [watch(ID1, e2)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].kind, KeeperActionKind::Claim);
    }

    #[test]
    fn milestone_plan_disables_claim_but_not_cancel_expired() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, 0)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        // The plan owns the release schedule (`claim` would fail with
        // InvalidMilestones), but the expiry exit still refunds.
        assert_eq!(report.actions.len(), 2);
        assert_eq!(report.actions[0].kind, KeeperActionKind::CancelExpired);
        assert_eq!(report.actions[1].kind, KeeperActionKind::CrankExpired);
    }

    #[test]
    fn disputed_escrow_lists_resolve_for_arbiter() {
        // AV-38: a disputed escrow lists exactly one keeper action —
        // the arbiter's `resolve` — so an arbiter-operated keeper bot
        // learns which disputes await its ruling. The unilateral exits
        // stay locked, so nothing else is listed.
        const ARBITER: [u8; 32] = [0xA8; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e.escalate(ALICE, MID, e.remaining_amount(), None, None, 0).unwrap();
        assert_eq!(e.state(), EscrowState::Disputed);
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::Resolve);
        assert_eq!(a.escrow_id, ID1);
        assert_eq!(a.caller, ARBITER);
        assert_eq!(a.caller_role, "arbiter");
        assert_eq!(a.mint, None);
        assert_eq!(a.refund_to, None, "resolve splits, it does not refund");
        assert_eq!(a.amount, AMOUNT, "the splittable pool");
        assert_eq!(a.reason, "disputed");
        // JSON shape: the action name renders as "resolve".
        let json = report.to_json();
        assert!(json.contains("\"action\":\"resolve\""));
        assert!(json.contains("\"caller_role\":\"arbiter\""));
        assert!(json.contains("\"reason\":\"disputed\""));
    }

    #[test]
    fn resolve_action_carries_the_arbiter_fee_terms() {
        // AV-135: the keeper's resolve action tells the arbiter bot
        // the fee terms the settlement will charge — the anti-free-riding
        // economics are visible before the ruling is submitted.
        const ARBITER: [u8; 32] = [0xA8; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap()
            .with_arbiter_fee(50_000, 1_000)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e.escalate(ALICE, MID, e.remaining_amount(), None, None, 0).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::Resolve);
        let terms = a.arbiter_fee.expect("fee terms ride the resolve action");
        assert_eq!(terms.flat_lamports, 50_000);
        assert_eq!(terms.bps, 1_000);
        let json = report.to_json();
        assert!(json.contains("\"arbiter_fee\":{\"flat_lamports\":50000,\"bps\":1000}"));
    }

    #[test]
    fn resolve_action_arbiter_fee_null_without_opt_in() {
        // No opt-in: the field stays null, the legacy shape untouched.
        const ARBITER: [u8; 32] = [0xA8; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e.escalate(ALICE, MID, e.remaining_amount(), None, None, 0).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].arbiter_fee, None);
        assert!(report.to_json().contains("\"arbiter_fee\":null"));
    }

    #[test]
    fn disputed_evidence_hash_survives_keeper_scan() {
        // AV-22 passthrough: the keeper lists only the arbiter's
        // `resolve` for a disputed escrow (AV-38), but the scan pipeline
        // must not drop the dispute evidence hash — operator tooling
        // reads it from the watched snapshot to fetch the off-chain
        // evidence for the arbiter.
        const EVIDENCE: [u8; 32] = [0xE1; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter([0xA8; 32])
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e.escalate(BOB, MID, e.remaining_amount(), Some(EVIDENCE), None, 0).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].kind, KeeperActionKind::Resolve);
        assert_eq!(
            watched[0].escrow.evidence_hash(),
            Some(EVIDENCE),
            "keeper scan dropped the dispute evidence hash"
        );
    }

    #[test]
    fn disputed_resolve_action_surfaces_evidence_disclosure() {
        // AV-91: the arbiter's `resolve` action carries the disclosure
        // progress — the arbiter dashboard verifies completeness
        // before judgment: (1, 2) means one committed document is
        // still undisclosed and the judgment weight must deduct it.
        let d0 = [0xD0; 32];
        let d1 = [0xD1; 32];
        let root = crate::merkle_node_hash(
            &crate::merkle_leaf_hash(&d0),
            &crate::merkle_leaf_hash(&d1),
        );
        let proof0 = [crate::merkle_leaf_hash(&d1)];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter([0xA8; 32])
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e.escalate(BOB, MID, e.remaining_amount(), None, Some(root), 2).unwrap();
        e.file_evidence(BOB, d0, 0, &proof0, MID).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::Resolve);
        assert_eq!(a.evidence_disclosure, Some((1, 2)));
        // The JSON renders the progress for the arbiter dashboard.
        let json = report.to_json();
        assert!(
            json.contains("\"evidence_disclosure\":{\"disclosed\":1,\"total\":2}"),
            "{json}"
        );
        // No committed root: the field is null, not zeroed.
        let mut e2 = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter([0xA8; 32])
            .unwrap();
        e2.fund(ALICE, MID).unwrap();
        e2.escalate(BOB, MID, e2.remaining_amount(), None, None, 0).unwrap();
        let watched = [watch(ID1, e2)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions[0].evidence_disclosure, None);
        assert!(
            report.to_json().contains("\"evidence_disclosure\":null,\"funding_progress\":null"),
            "null when no root committed"
        );
    }

    #[test]
    fn disputed_evidence_deadline_survives_keeper_scan() {
        // AV-68 passthrough: the watched snapshot keeps the disclosure
        // deadline and the escalating party, so operator tooling can
        // compute the disclosure status (pending / defaulted) without
        // a second account read.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter([0xA8; 32])
            .unwrap()
            .with_evidence_deadline(3_600)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e.escalate(BOB, MID, e.remaining_amount(), None, None, 0).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(report.actions[0].kind, KeeperActionKind::Resolve);
        assert_eq!(watched[0].escrow.evidence_deadline_secs(), 3_600);
        assert_eq!(watched[0].escrow.escalated_by(), Some(BOB));
        assert_eq!(watched[0].escrow.evidence_due_at(), Some(MID + 3_600));
        assert_eq!(
            watched[0].escrow.evidence_status(MID + 3_599),
            crate::EvidenceStatus::Pending
        );
        assert_eq!(
            watched[0].escrow.evidence_status(MID + 3_600),
            crate::EvidenceStatus::Defaulted
        );
    }

    #[test]
    fn scan_is_dry_run_and_preserves_input_order() {
        let e1 = funded(AMOUNT, 0); // -> cancel_expired
        let e2 = funded_vesting(NEVER); // -> claim
        let e3 = funded(AMOUNT, NEVER); // -> nothing
        let before = [watch(ID1, e1), watch(ID2, e2), watch(ID3, e3)];
        let report = scan_keeper_actions(&before, MID);
        // Zero side effects: the snapshots are bit-identical afterwards
        // (WatchedEscrow is Copy + PartialEq, so this is exact).
        assert_eq!(before, [watch(ID1, e1), watch(ID2, e2), watch(ID3, e3)]);
        assert_eq!(report.scanned, 3);
        assert_eq!(report.actions.len(), 3);
        // Input order preserved: ID1's cancel first, ID1's crank second,
        // ID2's claim third.
        assert_eq!(
            report.actions[0],
            KeeperAction {
                escrow_id: ID1,
                vault_address: None,
                kind: KeeperActionKind::CancelExpired,
                caller: ALICE,
                caller_role: "initializer",
                mint: None,
                // No whitelist configured: the refund goes to the
                // initializer (AV-23 default policy).
                refund_to: Some(ALICE),
                amount: AMOUNT,
                // No decimal metadata declared: bare-integer rendering.
                decimals: 0,
                // No reference memo attached to the watched escrow.
                reference: None,
                extension_count: 0,
                // No multisig binding on the watched escrow.
                multisig_authority: None,
                evidence_disclosure: None,
                funding_progress: None,
                reason: "expired",
                merge_source: None,
                // AV-115: the penalty estimate is zero on non-cancel actions.
                penalty_estimate: 0,
                slot_unlock_at: slot_unlock_opt(&e1),
                bounty_lamports: 0,
                bounty_unprofitable: false,
                arbiter_fee: None,
            }
        );
        assert_eq!(
            report.actions[1],
            KeeperAction {
                escrow_id: ID1,
                vault_address: None,
                kind: KeeperActionKind::CrankExpired,
                // Permissionless: the zero key marks "anyone".
                caller: [0u8; 32],
                caller_role: "anyone",
                mint: None,
                refund_to: Some(ALICE),
                amount: AMOUNT,
                decimals: 0,
                reference: None,
                extension_count: 0,
                multisig_authority: None,
                evidence_disclosure: None,
                funding_progress: None,
                reason: "expired",
                merge_source: None,
                // AV-115: the penalty estimate is zero on non-cancel actions.
                penalty_estimate: 0,
                slot_unlock_at: slot_unlock_opt(&e1),
                // AV-124: no bounty configured — `bounty_lamports` is
                // 0 and `0 < estimated cost` marks the crank
                // unprofitable (the classic unpaid AV-48 crank).
                bounty_lamports: 0,
                bounty_unprofitable: true,
                // AV-135: no arbiter fee on the crank action.
                arbiter_fee: None,
            }
        );
        assert_eq!(report.actions[2].escrow_id, ID2);
        assert_eq!(report.actions[2].kind, KeeperActionKind::Claim);
    }

    #[test]
    fn scan_lists_merge_pair_lower_id_survives() {
        // Two merge-compatible Funded escrows: the scan lists one
        // merge_escrows action — the lower escrow_id survives as the
        // target, the higher rides merge_source.
        let watched = [
            watch(ID2, funded(AMOUNT, NEVER)),
            watch(ID1, funded(AMOUNT, NEVER)),
        ];
        let report = scan_keeper_actions(&watched, MID);
        let merges: Vec<_> = report
            .actions
            .iter()
            .filter(|a| a.kind == KeeperActionKind::MergeEscrows)
            .collect();
        assert_eq!(merges.len(), 1);
        let m = merges[0];
        assert_eq!(m.escrow_id, ID1);
        assert_eq!(m.merge_source, Some(ID2));
        assert_eq!(m.caller, ALICE);
        assert_eq!(m.caller_role, "initializer");
        assert_eq!(m.amount, AMOUNT);
        assert_eq!(m.reason, "mergeable_pair");
    }

    #[test]
    fn scan_skips_incompatible_and_expired_pairs() {
        // Different takers: no merge.
        let mut other_taker = Escrow::initialize(ALICE, CAROL, AMOUNT, NEVER).unwrap();
        other_taker.fund(ALICE, MID).unwrap();
        let watched = [watch(ID1, funded(AMOUNT, NEVER)), watch(ID2, other_taker)];
        let report = scan_keeper_actions(&watched, MID);
        assert!(!report
            .actions
            .iter()
            .any(|a| a.kind == KeeperActionKind::MergeEscrows));
        // Expired escrows keep their cancel path, not a merge.
        let watched = [watch(ID1, funded(AMOUNT, 0)), watch(ID2, funded(AMOUNT, 0))];
        let report = scan_keeper_actions(&watched, MID);
        assert!(!report
            .actions
            .iter()
            .any(|a| a.kind == KeeperActionKind::MergeEscrows));
    }

    #[test]
    fn scan_pairs_each_escrow_at_most_once() {
        // Three compatible escrows: exactly one pair, the third stays
        // unpaired.
        let id3 = [0x03; 32];
        let watched = [
            watch(ID1, funded(AMOUNT, NEVER)),
            watch(ID2, funded(AMOUNT, NEVER)),
            watch(id3, funded(AMOUNT, NEVER)),
        ];
        let report = scan_keeper_actions(&watched, MID);
        let merges: Vec<_> = report
            .actions
            .iter()
            .filter(|a| a.kind == KeeperActionKind::MergeEscrows)
            .collect();
        assert_eq!(merges.len(), 1);
        assert_eq!(merges[0].escrow_id, ID1);
        assert_eq!(merges[0].merge_source, Some(ID2));
    }

    #[test]
    fn merge_action_cu_is_pinned() {
        // AV-114: merge_escrows — no params (8 data bytes); the keeper
        // plans vault + authority (2 accounts, no refund_to, no mint)
        // + 1 signer.
        let watched = [
            watch(ID1, funded(AMOUNT, NEVER)),
            watch(ID2, funded(AMOUNT, NEVER)),
        ];
        let report = scan_keeper_actions(&watched, MID);
        let m = report
            .actions
            .iter()
            .find(|a| a.kind == KeeperActionKind::MergeEscrows)
            .unwrap();
        // 14_000 base + 3_000/signer + 250/account + 8/data byte.
        assert_eq!(
            m.estimated_compute_units(),
            14_000 + 3_000 + 2 * 250 + 8 * 8
        );
    }

    #[test]
    fn json_shape_is_pinned() {
        let watched = [watch(ID1, funded(AMOUNT, 0))];
        let report = scan_keeper_actions(&watched, 1_000_000);
        // AV-48: the expired escrow lists both the party-signed
        // `cancel_expired` and the permissionless `crank_expired`.
        // AV-88: cancel_expired / crank_expired with refund_to, no mint:
        // 3 accounts, 8 data bytes, 1 signer →
        // 10_000 + 3_000 + 3×250 + 8×8 = 13_814 each; total 27_628.
        let expected = format!(
            "{{\"at\":1000000,\"scanned\":1,\"total_estimated_cu\":27628,\"jito_tip\":null,\"intent_releases\":[],\"pool_balance\":0,\"pool_inflow\":0,\"pool_outflow\":0,\"actions\":[{{\"escrow_id\":\"{}\",\"vault_address\":null,\"action\":\"cancel_expired\",\"caller\":\"{}\",\"caller_role\":\"initializer\",\"mint\":null,\"refund_to\":\"{}\",\"amount\":1000000,\"decimals\":0,\"display_amount\":\"1000000\",\"reason\":\"expired\",\"reference\":null,\"extension_count\":0,\"multisig_authority\":null,\"evidence_disclosure\":null,\"funding_progress\":null,\"merge_source\":null,\"penalty_estimate\":0,\"slot_unlock_at\":null,\"bounty_lamports\":0,\"bounty_unprofitable\":false,\"arbiter_fee\":null,\"estimated_cu\":13814}},{{\"escrow_id\":\"{}\",\"vault_address\":null,\"action\":\"crank_expired\",\"caller\":\"{}\",\"caller_role\":\"anyone\",\"mint\":null,\"refund_to\":\"{}\",\"amount\":1000000,\"decimals\":0,\"display_amount\":\"1000000\",\"reason\":\"expired\",\"reference\":null,\"extension_count\":0,\"multisig_authority\":null,\"evidence_disclosure\":null,\"funding_progress\":null,\"merge_source\":null,\"penalty_estimate\":0,\"slot_unlock_at\":null,\"bounty_lamports\":0,\"bounty_unprofitable\":true,\"arbiter_fee\":null,\"estimated_cu\":13814}}],\"report_seq\":null,\"pending_auto_unpause\":[],\"funding_bounds\":[]}}",
            hex_of(0x01),
            hex_of(0xAA),
            hex_of(0xAA),
            hex_of(0x01),
            hex_of(0x00),
            hex_of(0xAA),
        );
        assert_eq!(report.to_json(), expected);
    }

    #[test]
    fn json_shape_with_claim_and_mint_is_pinned() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_mint(MINT)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        let watched = [watch(ID2, e)];
        let report = scan_keeper_actions(&watched, MID);
        // AV-88: claim with mint, no refund_to: 3 accounts, 8 data
        // bytes, 1 signer → 14_000 + 3_000 + 3×250 + 8×8 = 17_814.
        let expected = format!(
            "{{\"at\":1750000000,\"scanned\":1,\"total_estimated_cu\":17814,\"jito_tip\":null,\"intent_releases\":[],\"pool_balance\":0,\"pool_inflow\":0,\"pool_outflow\":0,\"actions\":[{{\"escrow_id\":\"{}\",\"vault_address\":null,\"action\":\"claim\",\"caller\":\"{}\",\"caller_role\":\"taker\",\"mint\":\"{}\",\"refund_to\":null,\"amount\":500000,\"decimals\":0,\"display_amount\":\"500000\",\"reason\":\"vesting_unlocked\",\"reference\":null,\"extension_count\":0,\"multisig_authority\":null,\"evidence_disclosure\":null,\"funding_progress\":null,\"merge_source\":null,\"penalty_estimate\":0,\"slot_unlock_at\":null,\"bounty_lamports\":0,\"bounty_unprofitable\":false,\"arbiter_fee\":null,\"estimated_cu\":17814}}],\"report_seq\":null,\"pending_auto_unpause\":[],\"funding_bounds\":[]}}",
            hex_of(0x02),
            hex_of(0xBB),
            hex_of(0xD0),
        );
        assert_eq!(report.to_json(), expected);
    }

    // ---------- keeper bounty annotation (AV-124) ----------

    fn bounty_funded(pool: u64, per_crank: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, 0)
            .unwrap()
            .with_keeper_bounty(pool, per_crank)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e
    }

    fn crank_action(report: &KeeperReport) -> &KeeperAction {
        report
            .actions
            .iter()
            .find(|a| a.kind == KeeperActionKind::CrankExpired)
            .expect("expired escrow lists the permissionless crank")
    }

    #[test]
    fn scan_annotates_bounty_on_crank_actions() {
        // The scan carries the payable bounty onto the crank action —
        // the same `keeper_bounty_payable` the state machine pays, so
        // the preview and the payout agree.
        let watched = [watch(ID1, bounty_funded(50_000, 10_000))];
        let report = scan_keeper_actions(&watched, 1_000_000);
        let crank = crank_action(&report);
        assert_eq!(crank.bounty_lamports, 10_000);
        // A pool smaller than the per-crank amount annotates the
        // saturating payout, not the configured rate.
        let watched = [watch(ID1, bounty_funded(7_000, 10_000))];
        let report = scan_keeper_actions(&watched, 1_000_000);
        assert_eq!(crank_action(&report).bounty_lamports, 7_000);
        // Non-crank actions carry no bounty annotation.
        let cancel = report
            .actions
            .iter()
            .find(|a| a.kind == KeeperActionKind::CancelExpired)
            .unwrap();
        assert_eq!(cancel.bounty_lamports, 0);
        assert!(!cancel.bounty_unprofitable);
    }

    #[test]
    fn scan_marks_bounty_profitability_against_estimated_cost() {
        // The cost model: crank_expired with 3 accounts (vault +
        // authority + refund_to), no mint, 1 signer → 10_000 + 3_000 +
        // 3×250 + 8×8 = 13_814 CU; priced at the 10_000
        // micro-lamports/CU planning assumption → ⌈138.14⌉ = 139
        // lamports priority fee + the 5_000-lamport base signature fee
        // = 5_139 lamports.
        let watched = [watch(ID1, bounty_funded(50_000, 10_000))];
        let report = scan_keeper_actions(&watched, 1_000_000);
        let crank = crank_action(&report);
        assert_eq!(crank.estimated_execution_cost_lamports(), 5_139);
        assert_eq!(crank.bounty_lamports, 10_000);
        assert!(
            !crank.bounty_unprofitable,
            "10_000-lamport bounty covers the 5_139-lamport estimate"
        );
        // A bounty below the estimate is flagged unprofitable.
        let watched = [watch(ID1, bounty_funded(50_000, 1_000))];
        let report = scan_keeper_actions(&watched, 1_000_000);
        let crank = crank_action(&report);
        assert_eq!(crank.bounty_lamports, 1_000);
        assert!(
            crank.bounty_unprofitable,
            "1_000-lamport bounty does not cover the 5_139-lamport estimate"
        );
        // No bounty configured: the annotation is zero and the
        // classic unpaid AV-48 crank reads unprofitable (no bounty
        // covers its cost) — the keeper may still crank at a loss.
        let watched = [watch(ID1, funded(AMOUNT, 0))];
        let report = scan_keeper_actions(&watched, 1_000_000);
        let crank = crank_action(&report);
        assert_eq!(crank.bounty_lamports, 0);
        assert!(crank.bounty_unprofitable);
    }

    #[test]
    fn bounty_annotation_rides_the_report_json() {
        // The JSON carries the bounty economics per crank action so
        // the operator's dashboard reads them without recomputing.
        let watched = [watch(ID1, bounty_funded(50_000, 10_000))];
        let report = scan_keeper_actions(&watched, 1_000_000);
        let json = report.to_json();
        assert!(json.contains("\"bounty_lamports\":10000"));
        assert!(json.contains("\"bounty_unprofitable\":false"));
    }

    /// AV-98: the keeper report annotates the operator's intended Jito
    /// tip — amount + recipient on the dry-run preview — without
    /// building the instruction (the payer is the operator's key, not
    /// any single action's caller).
    #[test]
    fn jito_tip_annotation_marks_tip_amount_on_keeper_report() {
        const RECIPIENT: [u8; 32] = [0xE0; 32];
        let watched = [watch(ID1, funded(AMOUNT, 0))];
        let report = scan_keeper_actions(&watched, MID);
        assert!(report.jito_tip.is_none());
        assert!(report.to_json().contains("\"jito_tip\":null"));

        let stamped = report.with_jito_tip(25_000, RECIPIENT).unwrap();
        let tip = stamped.jito_tip.as_ref().unwrap();
        assert_eq!(tip.lamports, 25_000);
        assert_eq!(tip.recipient, RECIPIENT);
        let json = stamped.to_json();
        assert!(
            json.contains(&format!("\"jito_tip\":{{\"lamports\":25000,\"recipient\":\"{}\"}}", hex_of(0xE0))),
            "tip line missing: {json}"
        );
        // Deterministic: same stamp, same bytes.
        let stamped2 = scan_keeper_actions(&watched, MID).with_jito_tip(25_000, RECIPIENT).unwrap();
        assert_eq!(stamped.to_json(), stamped2.to_json());
        // The same RangeError-style validation as the bundle stamp.
        assert_eq!(
            scan_keeper_actions(&watched, MID).with_jito_tip(0, RECIPIENT).unwrap_err(),
            TipConfigError::ZeroTipAmount
        );
        assert_eq!(
            scan_keeper_actions(&watched, MID).with_jito_tip(1_000, [0u8; 32]).unwrap_err(),
            TipConfigError::ZeroRecipient
        );
    }

    #[test]
    fn scan_annotates_verified_intent_release() {
        // AV-123: a watched escrow carrying a signed, unsubmitted
        // release intent is annotated on the report — the relayer
        // submits `release_via_intent` with any fee payer instead of
        // waiting for a party-signed release.
        use crate::SigningKey;
        use crate::{sign_release_intent, ReleaseIntent};
        let key = SigningKey::from_seed([0x11; 32]);
        let mut e = Escrow::initialize(key.public_key(), BOB, AMOUNT, MID + 3_600).unwrap();
        e.fund(key.public_key(), MID).unwrap();
        let intent = ReleaseIntent::new(ID1, 100_000, BOB, 1, 9_999_999);
        let signed = SignedReleaseIntent::new(intent, sign_release_intent(&key, &intent));
        let watched = [watch(ID1, e).with_pending_intent(signed)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.intent_releases.len(), 1);
        let ann = &report.intent_releases[0];
        assert_eq!(ann.escrow_id, ID1);
        assert_eq!(ann.nonce, 1);
        assert_eq!(ann.expiry_slot, 9_999_999);
        // The annotation renders on the report JSON.
        let json = report.to_json();
        assert!(
            json.contains(&format!(
                "\"intent_releases\":[{{\"escrow_id\":\"{}\",\"nonce\":1,\"expiry_slot\":9999999}}]",
                hex_of(0x01)
            )),
            "intent line missing: {json}"
        );
    }

    #[test]
    fn scan_skips_unverifiable_or_replayed_intent() {
        // AV-123: an intent that does not verify against the
        // escrow's initializer key — or one whose nonce is not
        // fresh — is not annotated.
        use crate::SigningKey;
        use crate::{sign_release_intent, ReleaseIntent};
        let key = SigningKey::from_seed([0x11; 32]);
        let other = SigningKey::from_seed([0x22; 32]);
        let mut e = Escrow::initialize(key.public_key(), BOB, AMOUNT, MID + 3_600).unwrap();
        e.fund(key.public_key(), MID).unwrap();
        // Wrong-key signature: not annotated.
        let intent = ReleaseIntent::new(ID1, 100_000, BOB, 1, 9_999_999);
        let bad = SignedReleaseIntent::new(intent, sign_release_intent(&other, &intent));
        let watched = [watch(ID1, e.clone()).with_pending_intent(bad)];
        assert!(scan_keeper_actions(&watched, MID).intent_releases.is_empty());
        // Consumed nonce: a replayed intent is not annotated.
        e.release_via_intent(&intent, &sign_release_intent(&key, &intent), MID, 100, None)
            .unwrap();
        let replayed = SignedReleaseIntent::new(intent, sign_release_intent(&key, &intent));
        let watched = [watch(ID1, e).with_pending_intent(replayed)];
        assert!(scan_keeper_actions(&watched, MID).intent_releases.is_empty());
        // No pending intent at all: no annotation, empty array.
        let mut plain = Escrow::initialize(key.public_key(), BOB, AMOUNT, MID + 3_600).unwrap();
        plain.fund(key.public_key(), MID).unwrap();
        let watched = [watch(ID1, plain)];
        let report = scan_keeper_actions(&watched, MID);
        assert!(report.intent_releases.is_empty());
        assert!(report.to_json().contains("\"intent_releases\":[]"));
    }

    #[test]
    fn vault_address_attached_when_seeds_recorded() {
        // AV-92: a watch entry with recorded seeds yields actions
        // carrying the precomputed vault PDA; without seeds the
        // field is None and the JSON says null.
        let program_id = [0x07; 32];
        let seeds: &[&[u8]] = &[b"vault", &ALICE];
        // Expired funded escrow: the scan lists `cancel_expired`.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, MID - 3_600).unwrap();
        e.fund(ALICE, MID - 7_200).unwrap();
        let watched = watch(ID1, e)
            .with_vault_seeds(seeds, &program_id)
            .unwrap();
        let expected = crate::find_program_address(seeds, &program_id)
            .map(|(addr, _)| addr)
            .unwrap();
        assert_eq!(watched.vault_address(), Some(expected));

        let report = scan_keeper_actions(&[watched], MID);
        // Expired: both `cancel_expired` and the permissionless
        // `crank_expired` are listed — both carry the address.
        assert_eq!(report.actions.len(), 2);
        for a in &report.actions {
            assert_eq!(a.vault_address, Some(expected));
        }
        let json = report.to_json();
        assert!(
            json.contains(&format!("\"vault_address\":\"{}\"", hex32(&expected))),
            "vault_address hex missing: {json}"
        );

        // No seeds recorded: None + null, same actions otherwise.
        let plain = watch(ID1, e);
        assert_eq!(plain.vault_address(), None);
        let report = scan_keeper_actions(&[plain], MID);
        assert_eq!(report.actions[0].vault_address, None);
        assert!(
            report.to_json().contains("\"vault_address\":null"),
            "expected null vault_address"
        );
    }

    #[test]
    fn with_vault_seeds_rejects_invalid_seeds() {
        // AV-92: the builder validates — a 33-byte seed is
        // InvalidVaultSeeds, and the entry is unchanged (builder
        // takes self by value, so the error leaves no half-state).
        let e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER).unwrap();
        let big = [0xAAu8; 33];
        let err = watch(ID1, e)
            .with_vault_seeds(&[&big[..]], &[0x07; 32])
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidVaultSeeds);
    }

    #[test]
    fn keeper_action_estimated_cu_uses_canonical_accounts() {
        // AV-88: the dry-run report's CU passthrough. cancel_expired
        // with refund_to, no mint: vault + authority + refund_to = 3
        // accounts, 8 data bytes, 1 signer →
        // 10_000 + 3_000 + 3×250 + 8×8 = 13_814.
        let a = KeeperAction {
            escrow_id: ID1,
            vault_address: None,
            kind: KeeperActionKind::CancelExpired,
            caller: ALICE,
            caller_role: "initializer",
            mint: None,
            refund_to: Some(ALICE),
            amount: AMOUNT,
            decimals: 0,
            reference: None,
            extension_count: 0,
            multisig_authority: None,
            evidence_disclosure: None,
            funding_progress: None,
            reason: "expired",
            merge_source: None,
            // AV-115: the penalty estimate is zero on non-cancel actions.
            penalty_estimate: 0,
            slot_unlock_at: None,
            bounty_lamports: 0,
            bounty_unprofitable: false,
            arbiter_fee: None,
        };
        assert_eq!(a.estimated_compute_units(), 13_814);
        // Without refund_to the account drops out of the estimate.
        let no_refund = KeeperAction {
            refund_to: None,
            ..a
        };
        assert_eq!(no_refund.estimated_compute_units(), 13_814 - 250);
        // With a mint it joins the estimate.
        let with_mint = KeeperAction {
            mint: Some(MINT),
            ..a
        };
        assert_eq!(with_mint.estimated_compute_units(), 13_814 + 250);
        // resolve carries the 49-byte instruction data and no refund_to
        // (vault + authority = 2 accounts):
        // 22_000 + 3_000 + 2×250 + 49×8 = 25_892.
        let resolve = KeeperAction {
            kind: KeeperActionKind::Resolve,
            caller_role: "arbiter",
            funding_progress: None,
            reason: "disputed",
            merge_source: None,
            // AV-115: the penalty estimate is zero on non-cancel actions.
            penalty_estimate: 0,
            slot_unlock_at: None,
            bounty_lamports: 0,
            bounty_unprofitable: false,
            arbiter_fee: None,
            refund_to: None,
            ..a
        };
        assert_eq!(resolve.estimated_compute_units(), 25_892);
    }

    #[test]
    fn report_total_estimated_cu_sums_actions() {
        let watched = [watch(ID1, funded(AMOUNT, 0))];
        let report = scan_keeper_actions(&watched, 1_000_000);
        // cancel_expired + crank_expired, 13_814 each.
        let sum: u64 = report
            .actions
            .iter()
            .map(|a| a.estimated_compute_units())
            .sum();
        assert_eq!(sum, 27_628);
        assert_eq!(report.total_estimated_compute_units(), sum);
        assert!(report
            .to_json()
            .contains("\"total_estimated_cu\":27628"));
    }

    #[test]
    fn cancel_expired_action_carries_whitelisted_refund_to() {
        // AV-23: the keeper builds the cancel_expired instruction, so
        // the action must name the refund destination the state machine
        // will pin — the whitelisted address, not the caller.
        const WHITELIST: [u8; 32] = [0xC4; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, 0)
            .unwrap()
            .with_refund_address(WHITELIST)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, 1_000_000);
        assert_eq!(report.actions.len(), 2);
        let action = &report.actions[0];
        assert_eq!(action.kind, KeeperActionKind::CancelExpired);
        assert_eq!(action.caller, ALICE, "initializer is the canonical caller");
        assert_eq!(
            action.refund_to,
            Some(WHITELIST),
            "the instruction must name the whitelisted destination"
        );
        // AV-48: the crank carries the same pinned destination — the
        // cranker receives nothing (the AV-124 keeper bounty is paid as
        // a separate bookkeeping transfer, not via `refund_to`).
        let crank = &report.actions[1];
        assert_eq!(crank.kind, KeeperActionKind::CrankExpired);
        assert_eq!(crank.caller_role, "anyone");
        assert_eq!(
            crank.refund_to,
            Some(WHITELIST),
            "the crank refunds to the pinned destination too"
        );
        assert!(
            report.to_json().contains(&format!(
                "\"refund_to\":\"{}\"",
                hex_of(0xC4)
            )),
            "refund_to must be serialized for the operator"
        );
    }

    #[test]
    fn expired_vesting_escrow_lists_both_calls() {
        // Both calls are executable at the scan time; the keeper executes
        // one and re-scans. Amounts are as of the scan. AV-48: the
        // permissionless crank is listed too.
        let watched = [watch(ID1, funded_vesting(0))];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 3);
        assert_eq!(report.actions[0].kind, KeeperActionKind::CancelExpired);
        assert_eq!(report.actions[0].amount, AMOUNT);
        assert_eq!(report.actions[1].kind, KeeperActionKind::CrankExpired);
        assert_eq!(report.actions[1].amount, AMOUNT);
        assert_eq!(report.actions[2].kind, KeeperActionKind::Claim);
        assert_eq!(report.actions[2].amount, 500_000);
    }

    #[test]
    fn actions_render_human_amounts_with_decimals() {
        // AV-28: a 6-decimal escrow's report carries the raw amount for
        // the instruction and the human amount for the operator.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, 0)
            .unwrap()
            .with_decimals(6)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, 1_000_000);
        assert_eq!(report.actions.len(), 2);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::CancelExpired);
        assert_eq!(a.amount, AMOUNT, "the instruction moves raw units");
        assert_eq!(a.decimals, 6);
        assert_eq!(
            report.actions[1].kind,
            KeeperActionKind::CrankExpired,
            "AV-48: the crank is listed too"
        );
        let json = report.to_json();
        assert!(
            json.contains("\"amount\":1000000,\"decimals\":6,\"display_amount\":\"1.000000\""),
            "human amount must serialize alongside the raw amount, got: {json}"
        );
    }

    #[test]
    fn claim_action_renders_human_amount_with_decimals() {
        // AV-28: same for the claim path — half of 1_000_000 raw units
        // at 6 decimals is 0.500000 whole tokens.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_decimals(6)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        let watched = [watch(ID2, e)];
        let report = scan_keeper_actions(&watched, MID);
        assert_eq!(report.actions.len(), 1);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::Claim);
        assert_eq!(a.amount, 500_000);
        assert_eq!(a.decimals, 6);
        let json = report.to_json();
        assert!(
            json.contains("\"amount\":500000,\"decimals\":6,\"display_amount\":\"0.500000\""),
            "claim display amount must serialize, got: {json}"
        );
    }

    // ----- AV-56: subscription period release -----

    const SUB_PERIOD_SECS: u64 = 86_400;
    const SUB_PERIODS: u8 = 4;
    const SUB_PER_PERIOD: u64 = 250_000;
    const SUB_EXPIRES: u64 = 1_800_000_000;

    // The schedule is back-pinned so the last period is due at
    // SUB_EXPIRES: period `i` is due at
    // `SUB_EXPIRES - (4 - 1 - i) * 86_400`.
    fn sub_due_at(i: u8) -> u64 {
        SUB_EXPIRES - (SUB_PERIODS as u64 - 1 - i as u64) * SUB_PERIOD_SECS
    }

    fn funded_subscription() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, SUB_EXPIRES)
            .unwrap()
            .with_subscription(SUB_PERIOD_SECS, SUB_PERIODS, SUB_PER_PERIOD)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e
    }

    #[test]
    fn subscription_due_period_lists_release_period_for_initializer() {
        // AV-56: at a period's due date the keeper lists the
        // initializer's push path for exactly the next period — and
        // nothing else (the escrow is unexpired and has no vesting).
        let watched = [watch(ID1, funded_subscription())];
        let report = scan_keeper_actions(&watched, sub_due_at(0));
        assert_eq!(report.actions.len(), 1);
        let a = report.actions[0];
        assert_eq!(a.kind, KeeperActionKind::ReleasePeriod);
        assert_eq!(a.escrow_id, ID1);
        assert_eq!(a.caller, ALICE);
        assert_eq!(a.caller_role, "initializer");
        assert_eq!(a.mint, None);
        assert_eq!(
            a.refund_to, None,
            "a period release pays the taker, it does not refund"
        );
        assert_eq!(a.amount, SUB_PER_PERIOD);
        assert_eq!(a.decimals, 0);
        assert_eq!(a.reason, "subscription_period_due");
        // JSON shape: the new action name and reason serialize so
        // operator tooling can route the push call.
        let json = report.to_json();
        assert!(json.contains("\"action\":\"release_period\""), "got: {json}");
        assert!(
            json.contains("\"reason\":\"subscription_period_due\""),
            "got: {json}"
        );
    }

    #[test]
    fn subscription_not_yet_due_lists_no_release_period() {
        // One second before the due date: the on-chain call would fail
        // with PeriodNotDue, so the keeper lists nothing.
        let watched = [watch(ID1, funded_subscription())];
        let report = scan_keeper_actions(&watched, sub_due_at(0) - 1);
        assert!(
            report.is_empty(),
            "a not-yet-due period is not executable: {report:?}"
        );
    }

    #[test]
    fn escrow_without_schedule_lists_no_release_period() {
        // Neither a plain funded escrow nor a vesting one (which lists
        // Claim) ever lists the subscription push path.
        let watched = [
            watch(ID1, funded(AMOUNT, NEVER)),
            watch(ID2, funded_vesting(NEVER)),
        ];
        let report = scan_keeper_actions(&watched, MID);
        assert!(
            report
                .actions
                .iter()
                .all(|a| a.kind != KeeperActionKind::ReleasePeriod),
            "no schedule, no release_period: {report:?}"
        );
    }

    #[test]
    fn subscription_fully_released_lists_no_release_period() {
        // All four periods released at their due dates: the escrow is
        // Released — no keeper action at all.
        let mut e = funded_subscription();
        for i in 0..SUB_PERIODS {
            e.release_period(ALICE, sub_due_at(i), i, None, BOB).unwrap();
        }
        assert_eq!(e.state(), EscrowState::Released);
        let watched = [watch(ID1, e)];
        let report = scan_keeper_actions(&watched, sub_due_at(SUB_PERIODS - 1));
        assert!(report.is_empty());
    }

    #[test]
    fn watched_cooling_intent_is_readable_via_the_same_truth_source() {
        // AV-112: the keeper never lists `release` (the initializer
        // calls it), but the watched escrow's cooling window and live
        // intent are readable off-chain through the state machine's
        // own predicate — the single truth source `release` itself
        // uses — so an operator's dashboard can never disagree with
        // the chain about whether a release would clear the gate.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_release_cooling(3_600)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        let w = watch(ID1, e);
        assert_eq!(w.escrow.release_cooling_secs(), 3_600);
        assert_eq!(w.escrow.release_intent_at(), None);
        assert!(!w.escrow.is_release_cooling_eligible(MID + 3_600));

        let mut e2 = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_release_cooling(3_600)
            .unwrap();
        e2.fund(ALICE, MID).unwrap();
        e2.announce_release(ALICE, MID).unwrap();
        let w2 = watch(ID2, e2);
        assert_eq!(w2.escrow.release_intent_at(), Some(MID));
        assert!(!w2.escrow.is_release_cooling_eligible(MID + 3_599));
        assert!(w2.escrow.is_release_cooling_eligible(MID + 3_600));
    }
}

#[cfg(test)]
mod close_keeper_tests {
    use super::*;
    use crate::{
        rent_exempt_minimum_lamports, MAINNET_EXEMPTION_THRESHOLD_YEARS,
        MAINNET_LAMPORTS_PER_BYTE_YEAR, VAULT_SPACE,
    };

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const CAROL: [u8; 32] = [0xCC; 32]; // second initializer (batch grouping)
    const ARBITER: [u8; 32] = [0xA8; 32];
    const ID1: [u8; 32] = [0x01; 32];
    const ID2: [u8; 32] = [0x02; 32];
    const ID3: [u8; 32] = [0x03; 32];
    const ID4: [u8; 32] = [0x04; 32];
    const AMOUNT: u64 = 1_000_000;
    const MID: u64 = 1_750_000_000;
    const NEVER: u64 = u64::MAX; // no timeout

    fn watch(id: [u8; 32], escrow: Escrow) -> WatchedEscrow {
        // AV-53: the watch entry carries the escrow's reference memo,
        // like a keeper operator copying it when building the watch
        // list.
        let reference = escrow.reference();
        WatchedEscrow {
            escrow_id: id,
            escrow,
            reference,
            vault_derivation: None,
            pending_intent: None,
        }
    }

    fn funded(initializer: [u8; 32]) -> Escrow {
        let mut e = Escrow::initialize(initializer, BOB, AMOUNT, NEVER).unwrap();
        e.fund(initializer, MID).unwrap();
        e
    }

    fn cancelled() -> Escrow {
        let mut e = funded(ALICE);
        e.cancel(ALICE, None, ALICE, 0).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        e
    }

    fn released() -> Escrow {
        let mut e = funded(ALICE);
        e.release(ALICE, MID, AMOUNT, None, BOB).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        e
    }

    fn settled() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e.escalate(ALICE, MID, e.remaining_amount(), None, None, 0).unwrap();
        e.resolve(ARBITER, 400_000, MID, None, None, BOB).unwrap();
        assert_eq!(e.state(), EscrowState::Settled);
        e
    }

    fn closed() -> Escrow {
        let mut e = released();
        e.close_vault(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Closed);
        e
    }

    fn disputed() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE, MID).unwrap();
        e.escalate(ALICE, MID, e.remaining_amount(), None, None, 0).unwrap();
        assert_eq!(e.state(), EscrowState::Disputed);
        e
    }

    fn split() -> Escrow {
        // AV-81: a split parent — the funds were re-homed into the
        // children, so the parent vault is closeable like the other
        // terminals.
        let mut e = funded(ALICE);
        e.split_escrow(
            ALICE,
            BOB,
            &[600_000, 400_000],
            crate::SplitConfig::default(),
            MID,
        )
        .unwrap();
        assert_eq!(e.state(), EscrowState::Split);
        e
    }

    fn hex_of(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn terminal_states_cancelled_released_settled_split_are_all_listed() {
        // AV-34's terminal states are exactly the ones `close_vault`
        // accepts — each contributes one closeable action (Split since
        // AV-81).
        let watched = [
            watch(ID1, cancelled()),
            watch(ID2, released()),
            watch(ID3, settled()),
            watch([0x04; 32], split()),
        ];
        let report = scan_closeable(&watched);
        assert_eq!(report.scanned, 4);
        assert_eq!(report.batches.len(), 1, "one caller: one batch");
        let batch = &report.batches[0];
        assert_eq!(batch.actions.len(), 4);
        // Input order preserved.
        assert_eq!(batch.actions[0].escrow_id, ID1);
        assert_eq!(batch.actions[0].reason, "cancelled");
        assert_eq!(batch.actions[1].escrow_id, ID2);
        assert_eq!(batch.actions[1].reason, "released");
        assert_eq!(batch.actions[2].escrow_id, ID3);
        assert_eq!(batch.actions[2].reason, "settled");
        assert_eq!(batch.actions[3].escrow_id, [0x04; 32]);
        assert_eq!(batch.actions[3].reason, "split");
    }

    #[test]
    fn disputed_and_closed_are_skipped() {
        // `Disputed`: the arbitration is still live and the vault
        // account is the arbiter's audit surface — the chain rejects
        // the close, so the keeper never lists it. `Closed`: the rent
        // is already reclaimed and a second close would fail — the
        // scan never lists a call the chain would reject.
        let watched = [watch(ID1, disputed()), watch(ID2, closed())];
        let report = scan_closeable(&watched);
        assert!(report.is_empty(), "neither state is closeable");
        assert_eq!(report.scanned, 2);
        assert_eq!(report.to_json(), r#"{"scanned":2,"batches":[]}"#);
    }

    #[test]
    fn non_terminal_states_are_skipped() {
        // Uninitialized / Funded / Activated: the vault account has
        // not served its purpose yet, and `close_vault` would fail the
        // terminal-state gate — not executable, not listed.
        let uninit = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER).unwrap();
        // AV-12: a dual-signature escrow reaches `Activated` once both
        // parties record their activation signatures.
        let mut activated = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_dual_sig()
            .unwrap();
        activated.activate(ALICE).unwrap();
        activated.activate(BOB).unwrap();
        assert_eq!(activated.state(), EscrowState::Activated);
        let watched = [
            watch(ID1, uninit),
            watch(ID2, funded(ALICE)),
            watch(ID3, activated),
        ];
        let report = scan_closeable(&watched);
        assert!(report.is_empty());
        assert_eq!(report.scanned, 3);
    }

    #[test]
    fn initializer_is_the_canonical_caller() {
        // AV-34 restricts `close_vault` to the initializer, checked
        // before state validity — the report names the one key the
        // chain will accept. Each escrow's own initializer signs for
        // its vault.
        let mut e = funded(CAROL);
        e.cancel(CAROL, None, CAROL, 0).unwrap();
        let carol_escrow = e;
        let watched = [watch(ID1, cancelled()), watch(ID2, carol_escrow)];
        let report = scan_closeable(&watched);
        assert_eq!(report.batches.len(), 2);
        for batch in &report.batches {
            for a in &batch.actions {
                assert_eq!(a.caller, batch.caller);
                assert_eq!(a.caller_role, "initializer");
            }
        }
        assert_eq!(report.batches[0].caller, ALICE);
        assert_eq!(report.batches[0].actions[0].caller, ALICE);
        assert_eq!(report.batches[1].caller, CAROL);
        assert_eq!(report.batches[1].actions[0].caller, CAROL);
    }

    #[test]
    fn rent_reclaimed_matches_current_vault_space_formula() {
        // AV-40: the estimate is computed from the CURRENT
        // `VAULT_SPACE` formula — never a hardcoded figure. The layout
        // has grown since earlier constants, so the test recomputes
        // the rent-exempt minimum from the live `VAULT_SPACE` instead
        // of pinning a stale number.
        let expected = rent_exempt_minimum_lamports(
            VAULT_SPACE,
            MAINNET_LAMPORTS_PER_BYTE_YEAR,
            MAINNET_EXEMPTION_THRESHOLD_YEARS,
        );
        assert_eq!(
            vault_close_rent_reclaimed(),
            expected,
            "rent reclaimed must track the current VAULT_SPACE"
        );
        let watched = [watch(ID1, cancelled()), watch(ID2, settled())];
        let report = scan_closeable(&watched);
        for batch in &report.batches {
            for a in &batch.actions {
                assert_eq!(
                    a.rent_reclaimed, expected,
                    "listed reclaim must equal the VAULT_SPACE formula"
                );
            }
            assert_eq!(
                batch.total_reclaimed,
                expected * batch.actions.len() as u64,
                "batch total must equal the per-action sum"
            );
        }
    }

    #[test]
    fn listed_rent_matches_close_vault_return() {
        // Keeper/chain agreement: the scan's estimate equals what a
        // real `close_vault` returns — the keeper never quotes a
        // figure the chain would not actually transfer.
        let escrows = [cancelled(), released(), settled()];
        let watched = [
            watch(ID1, escrows[0]),
            watch(ID2, escrows[1]),
            watch(ID3, escrows[2]),
        ];
        let report = scan_closeable(&watched);
        let actions: Vec<&CloseAction> =
            report.batches.iter().flat_map(|b| b.actions.iter()).collect();
        assert_eq!(actions.len(), 3);
        for (i, w) in watched.iter().enumerate() {
            let mut probe = w.escrow;
            let rent = probe.close_vault(w.escrow.initializer()).unwrap();
            assert_eq!(
                actions[i].rent_reclaimed, rent,
                "keeper estimate disagrees with close_vault at index {i}"
            );
            assert_eq!(actions[i].caller, w.escrow.initializer());
        }
    }

    #[test]
    fn actions_grouped_per_caller_with_totals() {
        // Two initializers share the watch list: the sweep groups per
        // caller with a per-batch reclaimed total.
        let rent = vault_close_rent_reclaimed();
        let mut carol_cancelled = funded(CAROL);
        carol_cancelled.cancel(CAROL, None, CAROL, 0).unwrap();
        let watched = [
            watch(ID1, cancelled()),      // ALICE
            watch(ID2, carol_cancelled),  // CAROL
            watch(ID3, released()),       // ALICE
            watch(ID4, funded(ALICE)),    // ALICE, but live: skipped
        ];
        let report = scan_closeable(&watched);
        assert_eq!(report.scanned, 4);
        assert_eq!(report.batches.len(), 2);
        let (alice_batch, carol_batch) = (&report.batches[0], &report.batches[1]);
        // Batches in first-seen caller order.
        assert_eq!(alice_batch.caller, ALICE);
        assert_eq!(carol_batch.caller, CAROL);
        // Actions in input order within each batch.
        assert_eq!(alice_batch.actions.len(), 2);
        assert_eq!(alice_batch.actions[0].escrow_id, ID1);
        assert_eq!(alice_batch.actions[1].escrow_id, ID3);
        assert_eq!(carol_batch.actions.len(), 1);
        assert_eq!(carol_batch.actions[0].escrow_id, ID2);
        // Per-batch totals.
        assert_eq!(alice_batch.total_reclaimed, 2 * rent);
        assert_eq!(carol_batch.total_reclaimed, rent);
        // Total invariant: the batch total is the sum of its actions.
        for batch in &report.batches {
            let sum: u64 = batch.actions.iter().map(|a| a.rent_reclaimed).sum();
            assert_eq!(batch.total_reclaimed, sum);
        }
    }

    #[test]
    fn batch_order_follows_first_seen_caller() {
        // Deterministic output: batch order is the callers' first
        // appearance in the input, so a stable watch list gives a
        // stable sweep list.
        let mut carol_cancelled = funded(CAROL);
        carol_cancelled.cancel(CAROL, None, CAROL, 0).unwrap();
        let watched = [watch(ID1, carol_cancelled), watch(ID2, cancelled())];
        let report = scan_closeable(&watched);
        assert_eq!(report.batches.len(), 2);
        assert_eq!(report.batches[0].caller, CAROL);
        assert_eq!(report.batches[1].caller, ALICE);
    }

    #[test]
    fn scan_is_dry_run() {
        // Zero side effects: the snapshots are bit-identical after
        // the scan (WatchedEscrow is Copy + PartialEq, so exact).
        let before = [
            watch(ID1, cancelled()),
            watch(ID2, disputed()),
            watch(ID3, released()),
            watch(ID4, settled()),
        ];
        let _report = scan_closeable(&before);
        assert_eq!(
            before,
            [
                watch(ID1, cancelled()),
                watch(ID2, disputed()),
                watch(ID3, released()),
                watch(ID4, settled())
            ]
        );
    }

    #[test]
    fn json_shape_is_pinned() {
        // Deterministic serialization: fixed field order, 64-hex
        // lowercase keys, batches in first-seen caller order, actions
        // in input order.
        let rent = vault_close_rent_reclaimed();
        let watched = [watch(ID1, cancelled()), watch(ID2, released())];
        let report = scan_closeable(&watched);
        let expected = format!(
            "{{\"scanned\":2,\"batches\":[{{\"caller\":\"{}\",\"total_reclaimed\":{},\"actions\":[{{\"escrow_id\":\"{}\",\"action\":\"close_vault\",\"caller\":\"{}\",\"caller_role\":\"initializer\",\"rent_reclaimed\":{},\"reason\":\"cancelled\"}},{{\"escrow_id\":\"{}\",\"action\":\"close_vault\",\"caller\":\"{}\",\"caller_role\":\"initializer\",\"rent_reclaimed\":{},\"reason\":\"released\"}}]}}]}}",
            hex_of(0xAA),
            2 * rent,
            hex_of(0x01),
            hex_of(0xAA),
            rent,
            hex_of(0x02),
            hex_of(0xAA),
            rent,
        );
        assert_eq!(report.to_json(), expected);
    }

    #[test]
    fn empty_input_scans_to_empty_report() {
        let report = scan_closeable(&[]);
        assert!(report.is_empty());
        assert_eq!(report.scanned, 0);
        assert_eq!(report.to_json(), r#"{"scanned":0,"batches":[]}"#);
    }
}

// ============================================================================
// Milestone tranche keeper scan (AV-42)
// ============================================================================
//
// `scan_keeper_actions` (AV-20) answers "which vault needs a keeper call
// *right now*". Milestone-plan escrows (AV-15) need a finer answer: each
// tranche moves through confirm -> release, or the dual-signed skip path,
// strictly in order, so the keeper must know *which party's signature is
// missing* and *which tranche is sequence-blocked*.
//
// [`scan_milestones`] is the third keeper scan. It walks the same watch
// list and, per escrow, emits:
//
// - `actions`: the immediately executable milestone calls — each party's
//   missing `confirm_milestone` approval, each party's missing
//   `skip_milestone` approval, and the initializer's `release_milestone`
//   once every gate passes. Every action carries the exact arguments the
//   keeper needs: `escrow_id`, `index`, `caller` (+ `caller_role`),
//   `mint`, and the tranche amount split (`tranche`, `fee`,
//   `taker_payout` — the AV-17 protocol-fee preview, `0` on
//   confirm/skip actions which move no funds).
// - `blocked`: per-tranche `release_milestone` items that are *not*
//   executable yet, each with the machine-readable reason:
//   `"unconfirmed"` (confirmations missing), `"quorum_not_satisfied"`,
//   `"timelock_not_reached"`, or `"prerequisite"` (an earlier tranche is
//   still unsettled — settlement is strictly in-order).
//
// Skipping is dual-signed on-chain: each party records their skip
// approval with a *separate* `skip_milestone` call, and the skip executes
// only once both approvals are present. The scan therefore lists each
// missing party's approval as its own executable call — exactly like
// confirmations — rather than inventing a combined call the chain has no
// instruction for.
//
// Like the other scans this is a dry-run over `&Escrow` snapshots: no
// mutation, no events, no clock. Escrows without a milestone plan, not in
// `Funded` state, or whose plan is fully settled contribute nothing —
// there is no executable milestone call on them.
//
// Output is the same hand-rolled deterministic JSON as the other scans
// (AV-33 conventions): fixed field order, 64-char lowercase hex keys,
// `mint` as hex or `null`, actions and blocked entries in scan order.

/// The milestone-tranche keeper action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MilestoneActionKind {
    /// `confirm_milestone(authority, index)`: one party's acceptance of
    /// the deliverable. Per-party and idempotent — the scan lists the
    /// missing party's call.
    ConfirmMilestone,
    /// `skip_milestone(authority, index)`: one party's skip approval.
    /// Dual-signed on-chain (both parties approve separately); the scan
    /// lists each missing party's approval call.
    SkipMilestone,
    /// `release_milestone(initializer, now, index, mint)`: the
    /// initializer's push of a dual-confirmed tranche to the taker.
    ReleaseMilestone,
}

impl MilestoneActionKind {
    fn as_str(&self) -> &'static str {
        match self {
            MilestoneActionKind::ConfirmMilestone => "confirm_milestone",
            MilestoneActionKind::SkipMilestone => "skip_milestone",
            MilestoneActionKind::ReleaseMilestone => "release_milestone",
        }
    }
}

/// One executable milestone call: everything needed to build the
/// instruction, nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MilestoneAction {
    /// Which escrow this call targets.
    pub escrow_id: [u8; 32],
    /// Which transition to invoke.
    pub kind: MilestoneActionKind,
    /// The 0-based tranche index.
    pub index: u8,
    /// The key that must sign the call.
    pub caller: [u8; 32],
    /// Which role `caller` plays: `"initializer"` or `"taker"`.
    pub caller_role: &'static str,
    /// The `mint` argument to pass: the escrow's bound mint, or `None`
    /// on the native-SOL path.
    pub mint: Option<[u8; 32]>,
    /// The tranche's gross amount.
    pub tranche: u64,
    /// Protocol-fee preview for `release_milestone`
    /// ([`Escrow::protocol_fee_for`]); `0` on confirm/skip actions,
    /// which move no funds.
    pub fee: u64,
    /// `tranche - fee` for `release_milestone`: the taker's net payout;
    /// `0` on confirm/skip actions.
    pub taker_payout: u64,
    /// The escrow's token decimal metadata (AV-28): the SPL mint's
    /// decimal places, `0` when none is declared. Feeds the report's
    /// `display_amount` rendering only.
    pub decimals: u8,
    /// Machine-readable reason: `"confirmation_pending"`,
    /// `"skip_approval_pending"`, or `"confirmed"`.
    pub reason: &'static str,
}

/// One not-yet-executable `release_milestone`: the tranche, and why the
/// keeper must wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MilestoneBlocked {
    /// Which escrow this item belongs to.
    pub escrow_id: [u8; 32],
    /// The 0-based tranche index.
    pub index: u8,
    /// Always `"release_milestone"` today: confirmations and skip
    /// approvals are the executable path *toward* this call.
    pub action: &'static str,
    /// `"unconfirmed"`, `"quorum_not_satisfied"`,
    /// `"timelock_not_reached"`, or `"prerequisite"`.
    pub reason: &'static str,
}

/// The milestone scan result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MilestoneReport {
    /// The `now` (Unix seconds) the scan ran at.
    pub at: u64,
    /// How many escrows were scanned.
    pub scanned: usize,
    /// Executable actions, in the input's order.
    pub actions: Vec<MilestoneAction>,
    /// Blocked `release_milestone` items, in the input's order.
    pub blocked: Vec<MilestoneBlocked>,
}

impl MilestoneReport {
    /// True when the scan found neither an executable action nor a
    /// blocked tranche.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty() && self.blocked.is_empty()
    }

    /// Hand-serialized JSON (the crate is dependency-free). Deterministic
    /// field order; keys are 64-char lowercase hex; `mint` is a hex
    /// string or `null`.
    ///
    /// ```json
    /// {"at":1000000,"scanned":1,"actions":[
    ///   {"escrow_id":"...","action":"confirm_milestone","index":0,
    ///    "caller":"...","caller_role":"taker","mint":null,
    ///    "tranche":300000,"fee":0,"taker_payout":0,"decimals":6,
    ///    "display_amount":"0.300000","reason":"confirmation_pending"}
    /// ],"blocked":[
    ///   {"escrow_id":"...","index":1,"action":"release_milestone",
    ///    "reason":"prerequisite"}
    /// ]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(128 + self.actions.len() * 380);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"actions\":[");
        for (i, a) in self.actions.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&a.escrow_id));
            s.push_str("\",\"action\":\"");
            s.push_str(a.kind.as_str());
            s.push_str("\",\"index\":");
            s.push_str(&a.index.to_string());
            s.push_str(",\"caller\":\"");
            s.push_str(&hex32(&a.caller));
            s.push_str("\",\"caller_role\":\"");
            s.push_str(a.caller_role);
            s.push_str("\",\"mint\":");
            match a.mint {
                Some(m) => {
                    s.push('"');
                    s.push_str(&hex32(&m));
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            s.push_str(",\"tranche\":");
            s.push_str(&a.tranche.to_string());
            s.push_str(",\"fee\":");
            s.push_str(&a.fee.to_string());
            s.push_str(",\"taker_payout\":");
            s.push_str(&a.taker_payout.to_string());
            s.push_str(",\"decimals\":");
            s.push_str(&a.decimals.to_string());
            s.push_str(",\"display_amount\":\"");
            s.push_str(&format_amount(a.tranche, a.decimals));
            s.push_str("\",\"reason\":\"");
            s.push_str(a.reason);
            s.push_str("\"}");
        }
        s.push_str("],\"blocked\":[");
        for (i, b) in self.blocked.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&b.escrow_id));
            s.push_str("\",\"index\":");
            s.push_str(&b.index.to_string());
            s.push_str(",\"action\":\"");
            s.push_str(b.action);
            s.push_str("\",\"reason\":\"");
            s.push_str(b.reason);
            s.push_str("\"}");
        }
        s.push_str("]}");
        s
    }
}

/// Build one [`MilestoneAction`] with the escrow-derived fields filled in.
/// `fee`/`taker_payout` are the release amount split; callers pass `0`
/// for confirm/skip actions, which move no funds.
fn milestone_action(
    escrow_id: [u8; 32],
    kind: MilestoneActionKind,
    index: u8,
    caller: [u8; 32],
    caller_role: &'static str,
    e: &Escrow,
    tranche: u64,
    fee: u64,
    taker_payout: u64,
    reason: &'static str,
) -> MilestoneAction {
    MilestoneAction {
        escrow_id,
        kind,
        index,
        caller,
        caller_role,
        mint: e.mint(),
        tranche,
        fee,
        taker_payout,
        decimals: e.decimals(),
        reason,
    }
}

/// Scan `watched` at `now` and return every executable milestone call
/// plus every sequence/gate-blocked tranche. Pure read over the
/// snapshots: zero side effects, deterministic output in input order.
///
/// Only the first unsettled tranche of a `Funded` escrow with a plan can
/// carry executable calls — confirmations and skip approvals are
/// strictly in-order on-chain, and `release_milestone` additionally
/// requires every earlier tranche settled. Later unsettled tranches are
/// reported as blocked with reason `"prerequisite"`.
pub fn scan_milestones(watched: &[WatchedEscrow], now: u64) -> MilestoneReport {
    let mut actions = Vec::new();
    let mut blocked = Vec::new();
    for w in watched {
        let e = &w.escrow;
        if e.state() != EscrowState::Funded {
            continue;
        }
        let plan = match e.milestone_plan() {
            Some(p) => p,
            None => continue,
        };
        let count = plan.count() as usize;
        let next = match e.next_milestone() {
            Some(i) => i,
            None => continue,
        };
        let tranche = plan
            .amount_at(next)
            .expect("next_milestone is always in plan range");
        let index = next as u8;
        let init = e.initializer();
        let taker = e.taker();

        // Confirmations: each missing party's approval is an executable
        // call (idempotent per party on-chain).
        if !e.milestone_confirmed_by_initializer(next) {
            actions.push(milestone_action(
                w.escrow_id,
                MilestoneActionKind::ConfirmMilestone,
                index,
                init,
                "initializer",
                e,
                tranche,
                0,
                0,
                "confirmation_pending",
            ));
        }
        if !e.milestone_confirmed_by_taker(next) {
            actions.push(milestone_action(
                w.escrow_id,
                MilestoneActionKind::ConfirmMilestone,
                index,
                taker,
                "taker",
                e,
                tranche,
                0,
                0,
                "confirmation_pending",
            ));
        }
        // Skip approvals: dual-signed on-chain, one executable call per
        // missing party — the same shape as confirmations.
        if !e.milestone_skip_approved_by_initializer(next) {
            actions.push(milestone_action(
                w.escrow_id,
                MilestoneActionKind::SkipMilestone,
                index,
                init,
                "initializer",
                e,
                tranche,
                0,
                0,
                "skip_approval_pending",
            ));
        }
        if !e.milestone_skip_approved_by_taker(next) {
            actions.push(milestone_action(
                w.escrow_id,
                MilestoneActionKind::SkipMilestone,
                index,
                taker,
                "taker",
                e,
                tranche,
                0,
                0,
                "skip_approval_pending",
            ));
        }

        // Release: the full on-chain gate set, read-only. Mirrors
        // `release_milestone`'s check order (quorum, timelock, then
        // confirmation); the sequence gate holds by construction since
        // only the first unsettled tranche is considered.
        let quorum_ok = e.quorum().map(|q| q.is_satisfied()).unwrap_or(true);
        let timelock_ok = e.is_unlock_eligible(now);
        let confirmed = e.milestone_confirmed(next);
        if quorum_ok && timelock_ok && confirmed {
            let fee = e.protocol_fee_for(tranche);
            actions.push(milestone_action(
                w.escrow_id,
                MilestoneActionKind::ReleaseMilestone,
                index,
                init,
                "initializer",
                e,
                tranche,
                fee,
                tranche - fee,
                "confirmed",
            ));
        } else {
            let reason = if !quorum_ok {
                "quorum_not_satisfied"
            } else if !timelock_ok {
                "timelock_not_reached"
            } else {
                "unconfirmed"
            };
            blocked.push(MilestoneBlocked {
                escrow_id: w.escrow_id,
                index,
                action: "release_milestone",
                reason,
            });
        }

        // Later unsettled tranches: sequence-blocked until every earlier
        // tranche settles.
        for i in (next + 1)..count {
            if !e.milestone_settled(i) {
                blocked.push(MilestoneBlocked {
                    escrow_id: w.escrow_id,
                    index: i as u8,
                    action: "release_milestone",
                    reason: "prerequisite",
                });
            }
        }
    }
    MilestoneReport {
        at: now,
        scanned: watched.len(),
        actions,
        blocked,
    }
}

/// The outcome of [`execute_milestone_bundle`]: which tranches the
/// bundle released and which configured tranches it left pending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MilestoneBundleExecution {
    /// Tranche indices the bundle released, ascending. Non-empty: an
    /// empty bundle is rejected, not executed.
    pub executed: Vec<u8>,
    /// Configured tranche indices the bundle did not execute,
    /// ascending. Empty on a full execution.
    pub remaining: Vec<u8>,
    /// True iff the vault reached `Released` — only possible when the
    /// bundle executed every configured tranche.
    pub settled: bool,
}

/// Execute a keeper milestone bundle on `indexed`: release the selected
/// tranches' payouts to the taker, in ascending index order (AV-76).
///
/// This is keeper-side execution, not an on-chain transition — it
/// composes the existing `release_milestone` instruction (already in
/// the `INSTRUCTIONS` spec), so no new instruction or IDL entry
/// exists. `at` is both the event timestamp and the state machine's
/// `now` (the AV-27 timelock gate), like
/// [`IndexedEscrow::release_milestone`].
///
/// Validation runs first, in the crate's check-order spirit — every
/// rejection below is [`EscrowError::InvalidMilestones`]:
///
/// 1. `actions` is non-empty, every action targets `escrow_id`, and
///    every action's kind is `ReleaseMilestone` (confirm/skip are
///    dual-signed governance, not keeper execution).
/// 2. The escrow carries a milestone plan (mirroring
///    [`Escrow::release_milestone`]'s own gate).
/// 3. The subset (`Some(indices)`) is non-empty, every index is below
///    the plan's tranche count, no index repeats, and every selected
///    index has a bundle action — a dangling index is a caller bug,
///    not an executable bundle. `None` executes every action's index.
///
/// A subset equal to the full configured index set is a *full*
/// execution (the vault may settle); any *proper* subset leaves the
/// unselected tranches pending, the vault stays `Funded`, and a
/// trailing [`EscrowEventKind::BundlePartiallyExecuted`] is emitted
/// after the per-tranche `MilestoneReleased` events (gross + fee
/// totals in `amounts`, no actor — the bundle is a keeper composition,
/// and each tranche's own event already names its signer).
///
/// Atomicity (orthogonal to AV-61's bundle atomicity, same shape):
/// the subset executes all-or-nothing on a clone of `indexed`. On any
/// tranche failure the error returns with the caller's escrow
/// untouched — zero events leaked, state identical.
pub fn execute_milestone_bundle(
    indexed: &mut IndexedEscrow,
    escrow_id: [u8; 32],
    actions: &[MilestoneAction],
    subset: Option<&[u8]>,
    payout_to: [u8; 32],
    at: u64,
) -> Result<MilestoneBundleExecution, EscrowError> {
    // 1. Bundle input first: non-empty, all for this escrow, releases
    // only.
    if actions.is_empty()
        || actions
            .iter()
            .any(|a| a.escrow_id != escrow_id || a.kind != MilestoneActionKind::ReleaseMilestone)
    {
        return Err(EscrowError::InvalidMilestones);
    }
    // 2. The escrow must carry a milestone plan.
    let count = indexed
        .inner()
        .milestone_plan()
        .ok_or(EscrowError::InvalidMilestones)?
        .count() as usize;
    // 3. Subset validation. `None` executes every action's index;
    // either way the selected indices run in ascending order.
    let selected: Vec<u8> = match subset {
        Some(indices) => {
            if indices.is_empty() {
                return Err(EscrowError::InvalidMilestones);
            }
            let mut sel = indices.to_vec();
            sel.sort_unstable();
            sel.dedup();
            if sel.len() != indices.len() {
                return Err(EscrowError::InvalidMilestones);
            }
            sel
        }
        None => {
            let mut sel: Vec<u8> = actions.iter().map(|a| a.index).collect();
            sel.sort_unstable();
            sel.dedup();
            sel
        }
    };
    if selected.iter().any(|i| *i as usize >= count)
        || selected
            .iter()
            .any(|i| !actions.iter().any(|a| a.index == *i))
    {
        return Err(EscrowError::InvalidMilestones);
    }
    let full: Vec<u8> = (0..count as u8).collect();
    let is_partial = selected != full;
    let remaining: Vec<u8> = full
        .iter()
        .filter(|i| !selected.contains(i))
        .copied()
        .collect();
    // 4. All-or-nothing on a clone: any tranche failure returns the
    // error with `indexed` untouched.
    let mut work = indexed.clone();
    let mut total_gross: u64 = 0;
    let mut total_fee: u64 = 0;
    for index in &selected {
        let action = actions
            .iter()
            .find(|a| a.index == *index)
            .expect("every selected index has a bundle action");
        let (payout, fee) =
            work.release_milestone(action.caller, *index, action.mint, payout_to, at)?;
        // `payout + fee` is the tranche gross; the tranches sum to the
        // locked amount, so the totals cannot wrap — the checked adds
        // are backstops, paralleling `Escrow::release_milestone`.
        total_gross = total_gross
            .checked_add(payout + fee)
            .ok_or(EscrowError::ReleaseExceedsLocked)?;
        total_fee = total_fee
            .checked_add(fee)
            .ok_or(EscrowError::ReleaseExceedsLocked)?;
    }
    let settled = work.inner().state() == EscrowState::Released;
    if is_partial {
        // A proper subset can never settle the vault: zero-amount
        // tranches are rejected by `MilestonePlan::new`, so
        // `released == amount` needs every tranche released.
        debug_assert!(!settled, "a proper subset cannot settle the vault");
        work.emit_bundle_partially_executed(total_gross, total_fee, at);
    }
    *indexed = work;
    Ok(MilestoneBundleExecution {
        executed: selected,
        remaining,
        settled,
    })
}

#[cfg(test)]
mod keeper_milestone_tests {
    use super::*;
    use crate::{EscrowError, MilestonePlan, QuorumPolicy};

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const A1: [u8; 32] = [0xA1; 32]; // attestors
    const A2: [u8; 32] = [0xA2; 32];
    const A3: [u8; 32] = [0xA3; 32];
    const ID1: [u8; 32] = [0x01; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;
    const NOW: u64 = 1_750_000_000;

    fn watch(id: [u8; 32], escrow: Escrow) -> WatchedEscrow {
        // AV-53: the watch entry carries the escrow's reference memo,
        // like a keeper operator copying it when building the watch
        // list.
        let reference = escrow.reference();
        WatchedEscrow {
            escrow_id: id,
            escrow,
            reference,
            vault_derivation: None,
            pending_intent: None,
        }
    }

    /// Funded escrow with a milestone plan splitting `amounts`. The
    /// `build` closure configures pre-funding options (fee, quorum,
    /// timelock) on the `Uninitialized` escrow before it is funded.
    fn milestone_escrow(amounts: &[u64]) -> Escrow {
        milestone_escrow_with(amounts, Ok)
    }

    fn milestone_escrow_with(
        amounts: &[u64],
        build: impl FnOnce(Escrow) -> Result<Escrow, EscrowError>,
    ) -> Escrow {
        let total: u64 = amounts.iter().sum();
        let e = Escrow::initialize(ALICE, BOB, total, EXPIRES_AT)
            .unwrap()
            .with_milestones(MilestonePlan::new(amounts).unwrap())
            .unwrap();
        let mut e = build(e).unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        e
    }

    fn hex_of(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn confirm_lists_only_the_missing_party() {
        let mut e = milestone_escrow(&[300_000, 700_000]);
        e.confirm_milestone(ALICE, 0).unwrap();
        let report = scan_milestones(&[watch(ID1, e)], NOW);
        // The initializer's confirmation is done: only the taker's
        // confirm remains, plus both skip approvals, and the release is
        // blocked as unconfirmed.
        let confirms: Vec<_> = report
            .actions
            .iter()
            .filter(|a| a.kind == MilestoneActionKind::ConfirmMilestone)
            .collect();
        assert_eq!(confirms.len(), 1, "actions: {:?}", report.actions);
        assert_eq!(confirms[0].caller, BOB);
        assert_eq!(confirms[0].caller_role, "taker");
        assert_eq!(confirms[0].index, 0);
        assert_eq!(confirms[0].tranche, 300_000);
        assert_eq!(report.blocked.len(), 2);
        assert_eq!(report.blocked[0].reason, "unconfirmed");
        assert_eq!(report.blocked[0].index, 0);
        assert_eq!(report.blocked[1].reason, "prerequisite");
        assert_eq!(report.blocked[1].index, 1);
    }

    #[test]
    fn skip_lists_only_the_missing_approval() {
        let mut e = milestone_escrow(&[300_000, 700_000]);
        e.skip_milestone(BOB, 0).unwrap();
        let report = scan_milestones(&[watch(ID1, e)], NOW);
        let skips: Vec<_> = report
            .actions
            .iter()
            .filter(|a| a.kind == MilestoneActionKind::SkipMilestone)
            .collect();
        assert_eq!(skips.len(), 1, "actions: {:?}", report.actions);
        assert_eq!(skips[0].caller, ALICE);
        assert_eq!(skips[0].caller_role, "initializer");
        assert_eq!(skips[0].reason, "skip_approval_pending");
    }

    #[test]
    fn release_lists_with_fee_split_when_fully_gated() {
        let mut e = milestone_escrow_with(&[300_000, 700_000], |e| {
            e.with_protocol_fee(100)
        });
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        let report = scan_milestones(&[watch(ID1, e)], NOW);
        let releases: Vec<_> = report
            .actions
            .iter()
            .filter(|a| a.kind == MilestoneActionKind::ReleaseMilestone)
            .collect();
        assert_eq!(releases.len(), 1, "actions: {:?}", report.actions);
        let r = releases[0];
        assert_eq!(r.caller, ALICE);
        assert_eq!(r.caller_role, "initializer");
        assert_eq!(r.tranche, 300_000);
        assert_eq!(r.fee, 3_000); // floor(300_000 * 100 / 10_000)
        assert_eq!(r.taker_payout, 297_000);
        assert_eq!(r.reason, "confirmed");
        // The next tranche is still sequence-blocked.
        assert_eq!(report.blocked.len(), 1);
        assert_eq!(report.blocked[0].reason, "prerequisite");
    }

    #[test]
    fn release_blocked_by_quorum_reports_reason() {
        let mut e = milestone_escrow_with(&[300_000, 700_000], |e| {
            e.with_quorum(QuorumPolicy::new(&[A1, A2, A3], &[1, 1, 1], 2).unwrap())
        });
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        // No attestations: quorum not satisfied, even though both
        // parties confirmed.
        let report = scan_milestones(&[watch(ID1, e)], NOW);
        assert!(
            report
                .actions
                .iter()
                .all(|a| a.kind != MilestoneActionKind::ReleaseMilestone),
            "release must not be listed: {:?}",
            report.actions
        );
        assert_eq!(report.blocked[0].reason, "quorum_not_satisfied");
        // Confirm/skip approvals are not quorum-gated: nothing blocks
        // them, and both parties already confirmed so none are listed.
        assert!(
            report
                .actions
                .iter()
                .all(|a| a.kind == MilestoneActionKind::SkipMilestone),
            "only skip approvals remain: {:?}",
            report.actions
        );
    }

    #[test]
    fn release_blocked_by_timelock_reports_reason() {
        let mut e = milestone_escrow_with(&[300_000, 700_000], |e| {
            e.with_timelock(NOW + 1_000)
        });
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        let report = scan_milestones(&[watch(ID1, e)], NOW);
        assert!(
            report
                .actions
                .iter()
                .all(|a| a.kind != MilestoneActionKind::ReleaseMilestone),
            "release must not be listed before unlock_at"
        );
        assert_eq!(report.blocked[0].reason, "timelock_not_reached");
        // After the timelock passes the same state releases.
        let later = scan_milestones(&[watch(ID1, e)], NOW + 1_000);
        assert!(
            later
                .actions
                .iter()
                .any(|a| a.kind == MilestoneActionKind::ReleaseMilestone),
            "release must unlock at unlock_at: {:?}",
            later.actions
        );
    }

    #[test]
    fn json_is_deterministic_and_pinned() {
        let mut e = milestone_escrow(&[300_000, 700_000]);
        e.confirm_milestone(ALICE, 0).unwrap();
        let watched = [watch(ID1, e)];
        let a = scan_milestones(&watched, NOW).to_json();
        let b = scan_milestones(&watched, NOW).to_json();
        assert_eq!(a, b, "equal input must serialize byte-identically");
        // Pinned shape: the taker's missing confirmation plus the
        // unconfirmed/prerequisite blocked entries.
        let expected = format!(
            "{{\"at\":1750000000,\"scanned\":1,\"actions\":[\
             {{\"escrow_id\":\"{id}\",\"action\":\"confirm_milestone\",\"index\":0,\
             \"caller\":\"{bob}\",\"caller_role\":\"taker\",\"mint\":null,\
             \"tranche\":300000,\"fee\":0,\"taker_payout\":0,\"decimals\":0,\
             \"display_amount\":\"300000\",\"reason\":\"confirmation_pending\"}},\
             {{\"escrow_id\":\"{id}\",\"action\":\"skip_milestone\",\"index\":0,\
             \"caller\":\"{alice}\",\"caller_role\":\"initializer\",\"mint\":null,\
             \"tranche\":300000,\"fee\":0,\"taker_payout\":0,\"decimals\":0,\
             \"display_amount\":\"300000\",\"reason\":\"skip_approval_pending\"}},\
             {{\"escrow_id\":\"{id}\",\"action\":\"skip_milestone\",\"index\":0,\
             \"caller\":\"{bob}\",\"caller_role\":\"taker\",\"mint\":null,\
             \"tranche\":300000,\"fee\":0,\"taker_payout\":0,\"decimals\":0,\
             \"display_amount\":\"300000\",\"reason\":\"skip_approval_pending\"}}\
             ],\"blocked\":[\
             {{\"escrow_id\":\"{id}\",\"index\":0,\"action\":\"release_milestone\",\"reason\":\"unconfirmed\"}},\
             {{\"escrow_id\":\"{id}\",\"index\":1,\"action\":\"release_milestone\",\"reason\":\"prerequisite\"}}\
             ]}}",
            id = hex_of(0x01),
            alice = hex_of(0xAA),
            bob = hex_of(0xBB),
        );
        assert_eq!(a, expected, "pinned JSON shape");
    }

    #[test]
    fn skips_escrows_without_plan_or_not_funded() {
        // Funded but no milestone plan: nothing milestone-related.
        let mut plain = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        plain.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        // Plan attached but never funded: not executable.
        let unplanned = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[1_000_000]).unwrap())
            .unwrap();
        let report = scan_milestones(&[watch(ID1, plain), watch([0x02; 32], unplanned)], NOW);
        assert!(report.is_empty(), "nothing actionable: {report:?}");
        assert_eq!(report.scanned, 2);
    }

    #[test]
    fn scan_is_dry_run() {
        let mut e = milestone_escrow(&[300_000, 700_000]);
        e.confirm_milestone(ALICE, 0).unwrap();
        let before = e;
        let _ = scan_milestones(&[watch(ID1, e)], NOW);
        assert_eq!(e, before, "scan must not mutate the escrow");
    }

    #[test]
    fn per_party_accessors_match_bits() {
        let mut e = milestone_escrow(&[300_000, 700_000]);
        assert!(!e.milestone_confirmed_by_initializer(0));
        assert!(!e.milestone_confirmed_by_taker(0));
        e.confirm_milestone(ALICE, 0).unwrap();
        assert!(e.milestone_confirmed_by_initializer(0));
        assert!(!e.milestone_confirmed_by_taker(0));
        assert!(!e.milestone_confirmed(0));
        e.skip_milestone(BOB, 0).unwrap();
        assert!(e.milestone_skip_approved_by_taker(0));
        assert!(!e.milestone_skip_approved_by_initializer(0));
        // Out of range: false, never panics.
        assert!(!e.milestone_confirmed_by_initializer(63));
        assert!(!e.milestone_skip_approved_by_taker(63));
    }

    #[test]
    fn stranger_cannot_confirm_or_skip() {
        // Sanity: the accessors report what the state machine did, and
        // the state machine rejects strangers.
        let mut e = milestone_escrow(&[300_000, 700_000]);
        assert_eq!(
            e.confirm_milestone([0xCC; 32], 0),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(
            e.skip_milestone([0xCC; 32], 0),
            Err(EscrowError::Unauthorized)
        );
    }
}

// ============================================================================
// Vault rent-health keeper scan (AV-43)
// ============================================================================
//
// `scan_keeper_actions` (AV-20) answers "which vault needs a keeper call
// *right now*", `scan_closeable` (AV-40) sweeps terminal vaults, and
// `scan_milestones` (AV-42) walks tranche gates. None of them watches the
// vault *account's* lamports balance — but a vault account must carry the
// rent-exempt minimum for [`VAULT_SPACE`](crate::VAULT_SPACE) for as long
// as the escrow lives. A vault whose balance has eroded below that minimum
// is rent-bleeding: on-chain the runtime eats lamports each epoch, and at
// close the account only transfers what it actually holds — the
// initializer's expected `vault_close_rent_reclaimed()` reclaim (see
// [`Escrow::close_vault`]) silently shrinks. An underfunded vault can
// therefore make `close_vault` *economically* fail: the close succeeds on
// the state machine but returns less rent than the operator funded.
//
// [`scan_rent_health`] is the fourth keeper scan: it walks watched vaults
// together with their measured on-chain lamports balances
// ([`WatchedEscrowWithBalance`]) and lists every vault whose balance has
// fallen into the critical threshold — a configurable percentage of the
// canonical rent-exempt minimum — with the exact top-up lamports needed
// to restore full rent exemption (`required - balance`). The operator
// transfers exactly that amount into the vault account; the next scan
// shows the vault healthy again.
//
// The canonical figure is the main formula: [`vault_close_rent_reclaimed`]
// (`rent_exempt_minimum_lamports(VAULT_SPACE, MAINNET...)`) — the same
// number `initialize` funds, `check_vault_rent_exempt` enforces, and
// `close_vault` promises. Never a hardcoded figure: the account layout
// has grown since earlier constants, and the scan tracks the layout
// automatically.
//
// Like the other scans this is a dry-run over `&` snapshots: no mutation,
// no events. `Closed` vaults are skipped — the account no longer exists,
// so there is no balance to measure. Every other state is scanned: a
// live `Funded` vault bleeds rent while it waits, a terminal vault bleeds
// while it waits to be closed, and an `Uninitialized` entry with a zero
// balance simply reports the full `required` — exactly what `initialize`
// will demand. Actions keep the input order so a keeper feeding a stable
// watch list gets a stable top-up list.
//
// Output is the same hand-rolled deterministic JSON as the other scans:
// fixed field order, 64-char lowercase hex keys, lamports as plain
// integers (the exact unit the top-up transfer moves).

/// One not-yet-executable taker `claim`: the escrow, and why the
/// keeper must wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimCooldownBlocked {
    /// Which escrow this item belongs to.
    pub escrow_id: [u8; 32],
    /// Always `"claim"` today: the taker's pull path is the only
    /// cooldown-gated call.
    pub action: &'static str,
    /// Always `"claim_cooldown"`: the AV-121 per-taker cooldown has
    /// not elapsed at the scan slot.
    pub reason: &'static str,
    /// The first slot at which the taker's next claim is eligible
    /// ([`Escrow::claim_cooldown_eligible_at`]) — the operator
    /// compares against the chain tip, like
    /// [`KeeperAction::slot_unlock_at`].
    pub eligible_at: u64,
}

/// The claim-cooldown scan result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimCooldownReport {
    /// The `now` (Unix seconds) the scan ran at.
    pub at: u64,
    /// The Solana slot the scan ran at.
    pub slot: u64,
    /// How many escrows were scanned.
    pub scanned: usize,
    /// Cooldown-blocked `claim` items, in the input's order.
    pub blocked: Vec<ClaimCooldownBlocked>,
}

impl ClaimCooldownReport {
    /// True when the scan found no cooldown-blocked claim.
    pub fn is_empty(&self) -> bool {
        self.blocked.is_empty()
    }

    /// Hand-serialized JSON (the crate is dependency-free).
    /// Deterministic field order; keys are 64-char lowercase hex.
    ///
    /// ```json
    /// {"at":1000000,"slot":270000000,"scanned":1,"blocked":[
    ///   {"escrow_id":"...","action":"claim",
    ///    "reason":"claim_cooldown","eligible_at":270000100}
    /// ]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(64 + self.blocked.len() * 160);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"slot\":");
        s.push_str(&self.slot.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"blocked\":[");
        for (i, b) in self.blocked.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&b.escrow_id));
            s.push_str("\",\"action\":\"");
            s.push_str(b.action);
            s.push_str("\",\"reason\":\"");
            s.push_str(b.reason);
            s.push_str("\",\"eligible_at\":");
            s.push_str(&b.eligible_at.to_string());
            s.push('}');
        }
        s.push_str("]}");
        s
    }
}

/// Scan `watched` at (`now`, `slot`) and return every taker `claim`
/// the AV-121 per-taker cooldown blocks. Pure read over the
/// snapshots: zero side effects, deterministic output in input
/// order.
///
/// A blocked item is a claim the chain would reject with
/// [`EscrowError::InvalidClaimCooldown`](crate::EscrowError::InvalidClaimCooldown)
/// and nothing else: `Funded`, the taker's pull path attached
/// (vesting or AV-97 Dutch auction, no milestone plan — the plan
/// owns the release schedule and disables `claim`), a positive
/// claimable amount at `now`, any configured quorum satisfied and
/// the AV-27/AV-64 timelock unlocked (mirroring
/// [`scan_keeper_actions`]' claim listing), a nonzero cooldown
/// configured, a previous claim recorded — and the cooldown gate
/// not yet eligible at `slot`.
///
/// Unlike [`scan_keeper_actions`] this scan takes the chain slot:
/// the cooldown is slot-measured (AV-116 slot semantics), so only
/// a slot-bearing scan can evaluate it. The main scan keeps its
/// wall-clock signature and never lists a claim it cannot prove
/// executable; the cooldown-blocked items land here instead of
/// vanishing silently.
pub fn scan_claim_cooldown(
    watched: &[WatchedEscrow],
    now: u64,
    slot: u64,
) -> ClaimCooldownReport {
    let mut blocked = Vec::new();
    for w in watched {
        let e = &w.escrow;
        if e.state() != EscrowState::Funded {
            continue;
        }
        // The taker's pull path only: vesting or auction prices the
        // claim, and a milestone plan disables it (mirrors the
        // `claim` listing in `scan_keeper_actions`).
        if (e.vesting_schedule().is_none() && e.auction().is_none()) || e.milestone_plan().is_some() {
            continue;
        }
        if e.claimable_amount(now) == 0 {
            continue;
        }
        if !e.quorum().map(|q| q.is_satisfied()).unwrap_or(true) {
            continue;
        }
        if !e.is_unlock_eligible(now) {
            continue;
        }
        // Everything the chain would accept is in place — except the
        // cooldown: configured, previously claimed, and not yet
        // eligible at the scan slot.
        let eligible_at = match e.claim_cooldown_eligible_at() {
            Some(at) => at,
            None => continue,
        };
        if slot >= eligible_at {
            continue;
        }
        blocked.push(ClaimCooldownBlocked {
            escrow_id: w.escrow_id,
            action: "claim",
            reason: "claim_cooldown",
            eligible_at,
        });
    }
    ClaimCooldownReport {
        at: now,
        slot,
        scanned: watched.len(),
        blocked,
    }
}

/// One watched vault with its measured on-chain lamports balance: the
/// caller-supplied identity, the read-only state snapshot, and the vault
/// account's *actual* lamports as observed off-chain (e.g. via
/// `getAccountInfo`). The scan never mutates the snapshot (dry-run).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchedEscrowWithBalance {
    /// Caller-supplied 32-byte escrow identity — the same convention as
    /// [`WatchedEscrow::escrow_id`].
    pub escrow_id: [u8; 32],
    /// Read-only snapshot of the escrow's state.
    pub escrow: Escrow,
    /// The vault account's measured lamports balance.
    pub vault_lamports: u64,
}

/// One executable `top_up` action: everything needed to fund the vault
/// back to rent exemption, nothing more. Executed on-chain via the
/// AV-110 `top_up_rent` instruction (permissionless — the listed
/// `caller` is the canonical funder, but any key may submit it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopUpAction {
    /// Which escrow's vault this action tops up.
    pub escrow_id: [u8; 32],
    /// The escrow's state at scan time, for operator context:
    /// `"funded"`, `"cancelled"`, `"released"`, `"settled"`,
    /// `"disputed"`, `"activated"`, or `"uninitialized"`.
    pub state: &'static str,
    /// The vault's measured lamports balance at scan time.
    pub vault_lamports: u64,
    /// The canonical rent-exempt minimum from
    /// [`vault_close_rent_reclaimed`] — the figure the scan compared
    /// against.
    pub required_lamports: u64,
    /// The exact lamports to transfer into the vault account to restore
    /// rent exemption: `required_lamports - vault_lamports`. Always
    /// `> 0` — only under-threshold vaults are listed.
    pub top_up_lamports: u64,
    /// The key that should fund the top-up — the escrow's initializer,
    /// the canonical funder of the vault account (it funded the rent
    /// deposit at `initialize` time).
    pub caller: [u8; 32],
    /// Always `"initializer"` — the canonical vault funder.
    pub caller_role: &'static str,
    /// Machine-readable reason: always `"underfunded"` today — the
    /// vault's balance has fallen below the critical threshold of the
    /// rent-exempt minimum.
    pub reason: &'static str,
}

/// The rent-health scan result: every vault needing a top-up at
/// [`RentHealthReport::at`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RentHealthReport {
    /// The `now` (Unix seconds) the scan ran at. The scan has no time
    /// gate — rent health is a balance fact, not a deadline — but the
    /// timestamp pins when the balances were measured.
    pub at: u64,
    /// How many vaults were scanned.
    pub scanned: usize,
    /// The canonical rent-exempt minimum the scan used, from
    /// [`vault_close_rent_reclaimed`].
    pub required_lamports: u64,
    /// The effective critical-threshold percentage (the caller's value,
    /// clamped to `0..=100`).
    pub critical_threshold_pct: u8,
    /// Top-up actions, in the input's order.
    pub top_ups: Vec<TopUpAction>,
}

impl RentHealthReport {
    /// True when every scanned vault is above its critical threshold.
    pub fn is_empty(&self) -> bool {
        self.top_ups.is_empty()
    }

    /// Hand-serialized JSON (the crate is dependency-free). Deterministic
    /// field order; keys are 64-char lowercase hex; lamports are plain
    /// integers — the exact unit the top-up transfer moves.
    ///
    /// ```json
    /// {"at":1000000,"scanned":1,"required_lamports":6201360,
    ///  "critical_threshold_pct":90,"top_ups":[
    ///   {"escrow_id":"...","state":"funded","vault_lamports":4000000,
    ///    "required_lamports":6201360,"top_up_lamports":2201360,
    ///    "caller":"...","caller_role":"initializer",
    ///    "reason":"underfunded"}
    /// ]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(128 + self.top_ups.len() * 380);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"required_lamports\":");
        s.push_str(&self.required_lamports.to_string());
        s.push_str(",\"critical_threshold_pct\":");
        s.push_str(&self.critical_threshold_pct.to_string());
        s.push_str(",\"top_ups\":[");
        for (i, t) in self.top_ups.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&t.escrow_id));
            s.push_str("\",\"state\":\"");
            s.push_str(t.state);
            s.push_str("\",\"vault_lamports\":");
            s.push_str(&t.vault_lamports.to_string());
            s.push_str(",\"required_lamports\":");
            s.push_str(&t.required_lamports.to_string());
            s.push_str(",\"top_up_lamports\":");
            s.push_str(&t.top_up_lamports.to_string());
            s.push_str(",\"caller\":\"");
            s.push_str(&hex32(&t.caller));
            s.push_str("\",\"caller_role\":\"");
            s.push_str(t.caller_role);
            s.push_str("\",\"reason\":\"");
            s.push_str(t.reason);
            s.push_str("\"}");
        }
        s.push_str("]}");
        s
    }
}

/// Lowercase state name for the rent-health report's operator context.
fn rent_health_state_name(state: EscrowState) -> &'static str {
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
        EscrowState::Declined => "declined",
        EscrowState::CounterOffered => "counter_offered",
    }
}

/// Scan `watched` at `now` and return every vault whose measured balance
/// has fallen into the critical threshold of the canonical rent-exempt
/// minimum, with the exact top-up lamports to restore it. Pure read over
/// the snapshots: zero side effects, deterministic output in input order.
///
/// A vault is listed when `vault_lamports < floor(required *
/// critical_threshold_pct / 100)` — the boundary is exclusive: a vault
/// sitting *exactly* on the threshold is not critical. The threshold
/// percentage is clamped to `0..=100` (`0` lists nothing; `100` lists
/// every strictly-underfunded vault).
///
/// The listed `top_up_lamports` is `required - vault_lamports`: funding
/// exactly that amount restores the full rent-exempt minimum, so the
/// next scan shows the vault healthy. Only the initializer is named as
/// the funder — it funded the rent deposit at `initialize` time.
///
/// `Closed` vaults are skipped: the account no longer exists, so there is
/// no balance to measure and no top-up to perform.
pub fn scan_rent_health(
    watched: &[WatchedEscrowWithBalance],
    now: u64,
    critical_threshold_pct: u8,
) -> RentHealthReport {
    // AV-43: the canonical figure is the main formula — the same number
    // `initialize` funds and `close_vault` promises. Computed in u128:
    // `required * pct` cannot wrap (u128 is far larger than u64 * 100).
    let required = vault_close_rent_reclaimed();
    let pct = critical_threshold_pct.min(100);
    let critical_min = ((required as u128 * pct as u128) / 100) as u64;
    let mut top_ups = Vec::new();
    for w in watched {
        let e = &w.escrow;
        // A closed vault's account no longer exists — nothing to
        // measure, nothing to top up.
        if e.state() == EscrowState::Closed {
            continue;
        }
        // Exclusive boundary: exactly-at-threshold is not critical.
        // `critical_min <= required`, so a listed vault is always
        // strictly underfunded and `required - balance` never wraps.
        if w.vault_lamports < critical_min {
            top_ups.push(TopUpAction {
                escrow_id: w.escrow_id,
                state: rent_health_state_name(e.state()),
                vault_lamports: w.vault_lamports,
                required_lamports: required,
                top_up_lamports: required - w.vault_lamports,
                // The initializer is the canonical vault funder.
                caller: e.initializer(),
                caller_role: "initializer",
                reason: "underfunded",
            });
        }
    }
    RentHealthReport {
        at: now,
        scanned: watched.len(),
        required_lamports: required,
        critical_threshold_pct: pct,
        top_ups,
    }
}

/// One vault with a pending schema migration (AV-85): the dry-run
/// verdict for `migrate_schema` on this vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaMigrationAction {
    /// Which escrow this migration targets: the caller-supplied
    /// identity (the Anchor layer keys the vault PDA off it — the same
    /// convention as [`WatchedEscrow::escrow_id`]).
    pub escrow_id: [u8; 32],
    /// The key that must sign the `migrate_schema` call — always the
    /// escrow's initializer. The state machine checks the initializer
    /// before state validity, so it is the only key the chain will
    /// accept.
    pub caller: [u8; 32],
    /// Always `"initializer"` — the canonical (and only accepted)
    /// migration caller.
    pub caller_role: &'static str,
    /// The vault's schema version at scan time.
    pub from_version: u8,
    /// The version the chain would land on — always
    /// [`Escrow::SCHEMA_VERSION`].
    pub to_version: u8,
    /// The fields each step would append, in step order (see
    /// [`Escrow::schema_step_fields`]) — the dry-run's changed-fields
    /// list, flattened across the chain's steps. Empty when the
    /// migration is blocked.
    pub new_fields: Vec<SchemaFieldDelta>,
    /// Whether the dry-run passed: the real `migrate_schema` call
    /// would succeed, so this action is an executable
    /// `migrate_schema` call for the initializer to sign.
    pub ready: bool,
    /// Machine-readable reason the migration is blocked: `"paused"`
    /// (a paused escrow fails fast — migration is not the pause
    /// key-loss escape hatch) or `"corrupt"` (a carried-over field
    /// violates the conservation invariants — the vault needs repair,
    /// never a migration signature). `None` when `ready`.
    pub block_reason: Option<&'static str>,
    /// The escrow's opt-in 32-byte off-chain reference memo (AV-53),
    /// copied from the [`WatchedEscrow`] entry at scan time — the
    /// operator's order id / invoice hash for off-chain reconciliation.
    /// Carried for correlation only: it is never an instruction input
    /// and never affects which actions are listed.
    pub reference: Option<[u8; 32]>,
}

/// The schema-migration scan result: every watched vault with a
/// pending migration, in input order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaMigrationReport {
    /// How many vaults were scanned.
    pub scanned: usize,
    /// The pending-migration actions, in input order, so a keeper
    /// feeding a stable watch list gets a stable migration list.
    pub actions: Vec<SchemaMigrationAction>,
}

impl SchemaMigrationReport {
    /// True when no watched vault has a pending migration.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Hand-serialized JSON (the crate is dependency-free): the
    /// dry-run preview — per-vault version path, changed-fields list,
    /// and readiness. Deterministic field order; keys are 64-char
    /// lowercase hex.
    ///
    /// ```json
    /// {"scanned":2,"actions":[
    ///   {"escrow_id":"...","action":"migrate_schema","caller":"...",
    ///    "caller_role":"initializer","from_version":0,"to_version":2,
    ///    "new_fields":[{"name":"schema_version","type":"u8","bytes":1},
    ///                 {"name":"slash_terms","type":"Option<SlashTerms>","bytes":41},
    ///                 {"name":"penalty_paid","type":"u64","bytes":8}],
    ///    "ready":true,"block_reason":null,"reference":null}
    /// ]}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(64 + self.actions.len() * 420);
        s.push_str("{\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"actions\":[");
        for (i, a) in self.actions.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&a.escrow_id));
            s.push_str("\",\"action\":\"migrate_schema\",\"caller\":\"");
            s.push_str(&hex32(&a.caller));
            s.push_str("\",\"caller_role\":\"");
            s.push_str(a.caller_role);
            s.push_str("\",\"from_version\":");
            s.push_str(&a.from_version.to_string());
            s.push_str(",\"to_version\":");
            s.push_str(&a.to_version.to_string());
            s.push_str(",\"new_fields\":[");
            for (j, f) in a.new_fields.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                s.push_str("{\"name\":\"");
                s.push_str(f.name);
                s.push_str("\",\"type\":\"");
                s.push_str(f.ty);
                s.push_str("\",\"bytes\":");
                s.push_str(&f.bytes.to_string());
                s.push('}');
            }
            s.push_str("],\"ready\":");
            s.push_str(if a.ready { "true" } else { "false" });
            s.push_str(",\"block_reason\":");
            match a.block_reason {
                Some(r) => {
                    s.push('"');
                    s.push_str(r);
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            s.push_str(",\"reference\":");
            match a.reference {
                Some(r) => {
                    s.push('"');
                    s.push_str(&hex32(&r));
                    s.push('"');
                }
                None => s.push_str("null"),
            }
            s.push('}');
        }
        s.push_str("]}");
        s
    }
}

/// Map a migration dry-run failure onto the report's machine-readable
/// `block_reason`: `Paused` → `"paused"`, `Unauthorized` →
/// `"unauthorized"` (defensive — the scan always passes the vault's
/// own initializer), anything else → `"corrupt"` (a carried-over field
/// violates the conservation invariants, or the step table has no
/// entry for the vault's version).
fn migration_block_reason(err: EscrowError) -> &'static str {
    match err {
        EscrowError::Paused => "paused",
        EscrowError::Unauthorized => "unauthorized",
        _ => "corrupt",
    }
}

/// Scan `watched` and return every vault with a pending schema
/// migration, each with the dry-run verdict for `migrate_schema`
/// (AV-85).
///
/// Read-only by construction — the scan only runs
/// [`Escrow::migrate_dry_run`] over the snapshots: it cannot mutate
/// anything, emits no events, and touches no clock. A vault is listed
/// when `schema_version < SCHEMA_VERSION`; current vaults are skipped
/// (there is no no-op migration to list).
///
/// Each action carries the dry-run's changed-fields list
/// (`new_fields`, flattened in step order) so the operator sees what
/// the migration would append before the initializer signs. `ready`
/// actions are executable `migrate_schema` calls; blocked actions name
/// the reason (`"paused"` / `"corrupt"`) so the operator knows the
/// vault needs attention rather than a migration signature.
pub fn scan_schema_migrations(watched: &[WatchedEscrow]) -> SchemaMigrationReport {
    let mut actions = Vec::new();
    for w in watched {
        let e = &w.escrow;
        if e.schema_version() >= Escrow::SCHEMA_VERSION {
            continue;
        }
        // The initializer is the only accepted migration signer — the
        // dry-run checks it like the real call would.
        let initializer = e.initializer();
        match e.migrate_dry_run(initializer) {
            Ok(plan) => {
                let new_fields: Vec<SchemaFieldDelta> = plan
                    .steps
                    .iter()
                    .flat_map(|step| step.new_fields.iter().copied())
                    .collect();
                actions.push(SchemaMigrationAction {
                    escrow_id: w.escrow_id,
                    caller: initializer,
                    caller_role: "initializer",
                    from_version: plan.from,
                    to_version: plan.to,
                    new_fields,
                    ready: true,
                    block_reason: None,
                    reference: w.reference,
                });
            }
            Err(err) => actions.push(SchemaMigrationAction {
                escrow_id: w.escrow_id,
                caller: initializer,
                caller_role: "initializer",
                from_version: e.schema_version(),
                to_version: Escrow::SCHEMA_VERSION,
                new_fields: Vec::new(),
                ready: false,
                block_reason: Some(migration_block_reason(err)),
                reference: w.reference,
            }),
        }
    }
    SchemaMigrationReport {
        scanned: watched.len(),
        actions,
    }
}

#[cfg(test)]
mod schema_migration_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const ID1: [u8; 32] = [0x01; 32];
    const ID2: [u8; 32] = [0x02; 32];
    const ID3: [u8; 32] = [0x03; 32];
    const PAUSE_AUTH: [u8; 32] = [0xA9; 32];
    const NEVER: u64 = u64::MAX; // no timeout

    fn watch(id: [u8; 32], escrow: Escrow) -> WatchedEscrow {
        let reference = escrow.reference();
        WatchedEscrow {
            escrow_id: id,
            escrow,
            reference,
            vault_derivation: None,
            pending_intent: None,
        }
    }

    /// A v0-state vault: written before AV-75 existed, so the trailing
    /// schema byte reads `0`.
    fn v0_escrow() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, NEVER).unwrap();
        e.schema_version = 0;
        e
    }

    #[test]
    fn lists_pending_vaults_with_dry_run_verdict() {
        let mut v1 = Escrow::initialize(ALICE, BOB, 1_000_000, NEVER).unwrap();
        v1.schema_version = 1;
        let watched = vec![
            watch(ID1, v0_escrow()),
            watch(ID2, v1),
            // A current vault is skipped: no no-op migration to list.
            watch(ID3, Escrow::initialize(ALICE, BOB, 1_000_000, NEVER).unwrap()),
        ];
        let report = scan_schema_migrations(&watched);
        assert_eq!(report.scanned, 3);
        assert_eq!(report.actions.len(), 2, "only stale vaults are listed");
        // Input order is preserved.
        let first = &report.actions[0];
        assert_eq!(first.escrow_id, ID1);
        assert_eq!(first.caller, ALICE);
        assert_eq!(first.caller_role, "initializer");
        assert_eq!(first.from_version, 0);
        assert_eq!(first.to_version, Escrow::SCHEMA_VERSION);
        assert!(first.ready);
        assert_eq!(first.block_reason, None);
        // The dry-run's changed-fields list, flattened in step order.
        let names: Vec<&str> = first.new_fields.iter().map(|f| f.name).collect();
        assert_eq!(
            names,
            vec![
                "schema_version",
                "slash_terms",
                "penalty_paid",
                "appeal_window_secs",
                "appeal_deadline",
                "appeal_state",
                "appeal_ballot"
            ]
        );
        let second = &report.actions[1];
        assert_eq!(second.escrow_id, ID2);
        assert_eq!(second.from_version, 1);
        assert!(second.ready);
        let names: Vec<&str> = second.new_fields.iter().map(|f| f.name).collect();
        assert_eq!(
            names,
            vec![
                "slash_terms",
                "penalty_paid",
                "appeal_window_secs",
                "appeal_deadline",
                "appeal_state",
                "appeal_ballot"
            ]
        );
    }

    #[test]
    fn blocked_vaults_name_the_reason() {
        // Paused: the dry-run fails fast, like the real migration.
        let mut paused = Escrow::initialize(ALICE, BOB, 1_000_000, NEVER)
            .unwrap()
            .with_pause_authority(PAUSE_AUTH)
            .unwrap();
        paused.schema_version = 0;
        paused.pause(PAUSE_AUTH, None).unwrap();
        // Corrupt: a carried-over field violates the conservation
        // invariants — repair, never migrate.
        let mut corrupt = v0_escrow();
        corrupt.released = 1_000_001;
        let watched = vec![watch(ID1, paused), watch(ID2, corrupt)];
        let report = scan_schema_migrations(&watched);
        assert_eq!(report.actions.len(), 2);
        assert!(!report.actions[0].ready);
        assert_eq!(report.actions[0].block_reason, Some("paused"));
        assert!(report.actions[0].new_fields.is_empty());
        assert!(!report.actions[1].ready);
        assert_eq!(report.actions[1].block_reason, Some("corrupt"));
        assert!(!report.is_empty());
    }

    #[test]
    fn empty_watch_list_reports_empty() {
        let report = scan_schema_migrations(&[]);
        assert!(report.is_empty());
        assert_eq!(report.to_json(), "{\"scanned\":0,\"actions\":[]}");
    }

    #[test]
    fn report_json_is_deterministic() {
        let watched = vec![watch(ID1, v0_escrow())];
        let a = scan_schema_migrations(&watched).to_json();
        let b = scan_schema_migrations(&watched).to_json();
        assert_eq!(a, b);
        assert!(a.contains("\"action\":\"migrate_schema\""));
        assert!(a.contains("\"from_version\":0,\"to_version\":3"));
        assert!(a.contains("\"name\":\"slash_terms\",\"type\":\"Option<SlashTerms>\",\"bytes\":41"));
        assert!(a.contains("\"name\":\"appeal_ballot\",\"type\":\"AppealBallot\",\"bytes\":9"));
        assert!(a.contains("\"ready\":true,\"block_reason\":null"));
    }

    #[test]
    fn scan_is_read_only() {
        let e = v0_escrow();
        let before = e;
        let watched = vec![watch(ID1, e)];
        let report = scan_schema_migrations(&watched);
        assert_eq!(report.actions.len(), 1);
        assert_eq!(watched[0].escrow, before, "the scan must not mutate snapshots");
    }
}

/// A vault whose unclaimed rent is sweepable — the dry-run entry
/// of [`scan_unclaimed_rent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepableVault {
    /// Caller-supplied 32-byte escrow identity (see
    /// [`WatchedEscrow::escrow_id`]).
    pub escrow_id: [u8; 32],
    /// The terminal state the vault sits in (e.g. `Cancelled`).
    pub state: EscrowState,
    /// When the vault entered the terminal state (see
    /// [`Escrow::terminal_at`]).
    pub terminal_at: u64,
    /// Seconds of grace remaining before the sweep becomes callable
    /// (0 when already eligible — included for completeness; the
    /// scan only lists eligible vaults).
    pub grace_remaining_secs: u64,
    /// The rent-exempt lamports a sweep would reclaim (see
    /// [`crate::vault_close_rent_reclaimed`]).
    pub rent_lamports: u64,
}

/// The read-only result of [`scan_unclaimed_rent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnclaimedRentReport {
    /// Every watched vault whose rent is currently sweepable, sorted
    /// by `terminal_at` ascending (oldest terminal entry first — the
    /// keeper sweeps the stalest rent first).
    pub sweepable: Vec<SweepableVault>,
    /// Total rent-exempt lamports across all sweepable vaults.
    pub total_rent_lamports: u64,
}

/// Dry-run scan listing the watched vaults whose unclaimed rent is
/// currently sweepable via
/// [`Escrow::sweep_unclaimed_rent`](crate::Escrow::sweep_unclaimed_rent)
/// (AV-139).
///
/// A vault is listed when [`Escrow::is_rent_sweep_eligible`] holds at
/// `now`: the state is a closeable terminal state, the sweep grace
/// period has elapsed since `terminal_at`, and the vault is not
/// paused or reentrancy-locked (the sweep would fail its guards, so
/// listing it would be noise).
///
/// Pure: reads `&Escrow` snapshots only — no mutation, no events, no
/// clock. The keeper calls `sweep_unclaimed_rent` for each listed
/// vault; the scan itself never sweeps.
pub fn scan_unclaimed_rent(watched: &[WatchedEscrow], now: u64) -> UnclaimedRentReport {
    let mut sweepable = Vec::new();
    let mut total_rent_lamports = 0u64;
    for w in watched {
        let e = &w.escrow;
        if !e.is_rent_sweep_eligible(now) {
            continue;
        }
        // The sweep's own guards would reject a paused or
        // reentrancy-locked vault — skip it here so the report only
        // lists vaults the keeper can actually sweep now.
        if e.is_paused() || e.is_reentrancy_locked() {
            continue;
        }
        let grace = e.effective_rent_sweep_grace_secs();
        let eligible_at = e.terminal_at().saturating_add(grace);
        sweepable.push(SweepableVault {
            escrow_id: w.escrow_id,
            state: e.state(),
            terminal_at: e.terminal_at(),
            grace_remaining_secs: eligible_at.saturating_sub(now),
            rent_lamports: crate::vault_close_rent_reclaimed(),
        });
        total_rent_lamports = total_rent_lamports.saturating_add(crate::vault_close_rent_reclaimed());
    }
    sweepable.sort_by(|a, b| {
        a.terminal_at
            .cmp(&b.terminal_at)
            .then_with(|| a.escrow_id.cmp(&b.escrow_id))
    });
    UnclaimedRentReport {
        sweepable,
        total_rent_lamports,
    }
}

#[cfg(test)]
mod rent_health_tests {
    use super::*;
    use crate::{
        check_vault_rent_exempt, vault_close_rent_reclaimed, RentShortfall,
        MAINNET_EXEMPTION_THRESHOLD_YEARS, MAINNET_LAMPORTS_PER_BYTE_YEAR,
    };

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const ID1: [u8; 32] = [0x01; 32];
    const ID2: [u8; 32] = [0x02; 32];
    const ID3: [u8; 32] = [0x03; 32];
    const AMOUNT: u64 = 1_000_000;
    const NOW: u64 = 1_750_000_000;
    const NEVER: u64 = u64::MAX; // no timeout
    const PCT: u8 = 90;

    fn watch(id: [u8; 32], escrow: Escrow, vault_lamports: u64) -> WatchedEscrowWithBalance {
        WatchedEscrowWithBalance {
            escrow_id: id,
            escrow,
            vault_lamports,
        }
    }

    fn funded() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER).unwrap();
        e.fund(ALICE, NOW).unwrap();
        e
    }

    fn released() -> Escrow {
        let mut e = funded();
        e.release(ALICE, NOW, AMOUNT, None, BOB).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        e
    }

    fn closed() -> Escrow {
        let mut e = released();
        e.close_vault(ALICE).unwrap();
        assert_eq!(e.state(), EscrowState::Closed);
        e
    }

    fn required() -> u64 {
        vault_close_rent_reclaimed()
    }

    fn critical_min(pct: u8) -> u64 {
        ((required() as u128 * pct as u128) / 100) as u64
    }

    fn hex_of(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn empty_input_scans_to_empty_report() {
        let report = scan_rent_health(&[], NOW, PCT);
        assert!(report.is_empty());
        assert_eq!(report.scanned, 0);
        assert_eq!(report.required_lamports, required());
        assert_eq!(report.critical_threshold_pct, PCT);
        let expected = format!(
            "{{\"at\":1750000000,\"scanned\":0,\"required_lamports\":{},\"critical_threshold_pct\":90,\"top_ups\":[]}}",
            required()
        );
        assert_eq!(report.to_json(), expected);
    }

    #[test]
    fn healthy_vault_at_or_above_required_is_not_listed() {
        // A vault carrying the full rent-exempt minimum (or more) is
        // healthy — the keeper lists nothing.
        let watched = [
            watch(ID1, funded(), required()),
            watch(ID2, funded(), required() + 1),
            watch(ID3, released(), u64::MAX),
        ];
        let report = scan_rent_health(&watched, NOW, PCT);
        assert!(report.is_empty(), "no top-up needed: {report:?}");
        assert_eq!(report.scanned, 3);
    }

    #[test]
    fn exact_at_threshold_vault_is_not_listed() {
        // The critical boundary is exclusive: a vault sitting exactly on
        // `floor(required * pct / 100)` is not critical.
        let balance = critical_min(PCT);
        assert!(balance < required(), "sanity: 90% < 100%");
        let watched = [watch(ID1, funded(), balance)];
        let report = scan_rent_health(&watched, NOW, PCT);
        assert!(
            report.is_empty(),
            "exact-at-threshold is not critical: {report:?}"
        );
    }

    #[test]
    fn just_below_threshold_lists_exact_top_up() {
        // One lamport below the threshold: listed, with the exact amount
        // to restore the full rent-exempt minimum.
        let balance = critical_min(PCT) - 1;
        let watched = [watch(ID1, funded(), balance)];
        let report = scan_rent_health(&watched, NOW, PCT);
        assert_eq!(report.top_ups.len(), 1);
        let t = report.top_ups[0];
        assert_eq!(t.escrow_id, ID1);
        assert_eq!(t.state, "funded");
        assert_eq!(t.vault_lamports, balance);
        assert_eq!(t.required_lamports, required());
        assert_eq!(
            t.top_up_lamports,
            required() - balance,
            "exact lamports to restore rent exemption"
        );
        assert_eq!(t.caller, ALICE);
        assert_eq!(t.caller_role, "initializer");
        assert_eq!(t.reason, "underfunded");
        // Funding the exact top-up restores health: the next scan is
        // clean at every threshold percentage.
        let restored = [watch(ID1, funded(), balance + t.top_up_lamports)];
        assert_eq!(restored[0].vault_lamports, required());
        for pct in [0u8, 50, 90, 100] {
            assert!(
                scan_rent_health(&restored, NOW, pct).is_empty(),
                "restored vault must be healthy at pct={pct}"
            );
        }
    }

    #[test]
    fn underfunded_vault_makes_close_economically_fail() {
        // The close boundary: `close_vault` promises `required` lamports
        // back to the initializer, but an eroded vault account only holds
        // `balance` — on-chain the `close` constraint transfers what the
        // account actually holds, so the close *economically* fails to
        // return the full rent. The keeper's top-up is exactly the
        // reclaim shortfall. At 100% threshold every strictly-underfunded
        // vault is listed — below `required` is critical by definition.
        let shortfall: u64 = 100_000;
        let balance = required() - shortfall;
        // Probe a copy for the close promise; the watched escrow stays
        // `Released` — the scan skips `Closed` vaults (their account no
        // longer exists).
        let mut probe = released();
        let promised = probe.close_vault(ALICE).unwrap();
        assert_eq!(promised, required(), "close_vault promises full rent");
        // The same balance fails the rent-exemption check `initialize`
        // runs — the scan measures against the main formula, exactly.
        assert_eq!(
            check_vault_rent_exempt(
                balance,
                MAINNET_LAMPORTS_PER_BYTE_YEAR,
                MAINNET_EXEMPTION_THRESHOLD_YEARS
            ),
            Err(RentShortfall {
                required: required(),
                provided: balance,
            })
        );
        let watched = [watch(ID1, released(), balance)];
        let report = scan_rent_health(&watched, NOW, 100);
        assert_eq!(report.top_ups.len(), 1);
        let t = report.top_ups[0];
        assert_eq!(t.state, "released");
        assert_eq!(
            t.top_up_lamports, shortfall,
            "top-up must equal the reclaim shortfall the initializer would suffer on close"
        );
        assert_eq!(t.vault_lamports + t.top_up_lamports, promised);
    }

    #[test]
    fn terminal_states_all_scanned_for_rent_health() {
        // A terminal vault still holds the rent deposit until it is
        // closed — rent erosion there matters just as much as on a live
        // vault.
        let mut cancelled = funded();
        cancelled.cancel(ALICE, None, ALICE, 0).unwrap();
        let watched = [
            watch(ID1, cancelled, 0),
            watch(ID2, released(), 0),
        ];
        let report = scan_rent_health(&watched, NOW, PCT);
        assert_eq!(report.top_ups.len(), 2);
        assert_eq!(report.top_ups[0].state, "cancelled");
        assert_eq!(report.top_ups[1].state, "released");
        // A never-created vault account (balance 0) reports the full
        // `required` — exactly what `initialize` will demand.
        for t in &report.top_ups {
            assert_eq!(t.top_up_lamports, required());
        }
    }

    #[test]
    fn closed_vaults_are_skipped() {
        // The account no longer exists after close: no balance to
        // measure, no top-up to perform — even at zero lamports.
        let watched = [watch(ID1, closed(), 0)];
        let report = scan_rent_health(&watched, NOW, PCT);
        assert!(report.is_empty(), "closed vaults have no account: {report:?}");
        assert_eq!(report.scanned, 1);
    }

    #[test]
    fn threshold_pct_is_clamped_to_100() {
        // A percentage above 100 is meaningless: it behaves as 100 —
        // every strictly-underfunded vault is listed, nothing more.
        let watched = [
            watch(ID1, funded(), required() - 1),
            watch(ID2, funded(), required()),
        ];
        let report = scan_rent_health(&watched, NOW, 250);
        assert_eq!(report.critical_threshold_pct, 100);
        assert_eq!(report.top_ups.len(), 1);
        assert_eq!(report.top_ups[0].escrow_id, ID1);
        assert_eq!(report.top_ups[0].top_up_lamports, 1);
    }

    #[test]
    fn pct_zero_lists_nothing() {
        // A 0% threshold disables the scan: no balance can fall below 0.
        let watched = [watch(ID1, funded(), 0)];
        let report = scan_rent_health(&watched, NOW, 0);
        assert!(report.is_empty());
    }

    #[test]
    fn json_is_deterministic_and_pinned() {
        let balance = critical_min(PCT) - 7;
        let top_up = required() - balance;
        let watched = [watch(ID1, funded(), balance), watch(ID2, funded(), required())];
        let a = scan_rent_health(&watched, NOW, PCT).to_json();
        let b = scan_rent_health(&watched, NOW, PCT).to_json();
        assert_eq!(a, b, "equal input must serialize byte-identically");
        // Input order preserved: only ID1 is listed.
        let expected = format!(
            "{{\"at\":1750000000,\"scanned\":2,\"required_lamports\":{req},\"critical_threshold_pct\":90,\"top_ups\":[{{\"escrow_id\":\"{id}\",\"state\":\"funded\",\"vault_lamports\":{bal},\"required_lamports\":{req},\"top_up_lamports\":{top},\"caller\":\"{alice}\",\"caller_role\":\"initializer\",\"reason\":\"underfunded\"}}]}}",
            req = required(),
            id = hex_of(0x01),
            bal = balance,
            top = top_up,
            alice = hex_of(0xAA),
        );
        assert_eq!(a, expected, "pinned JSON shape");
    }

    #[test]
    fn scan_is_dry_run_and_preserves_input_order() {
        let before = [
            watch(ID1, funded(), critical_min(PCT) - 1),
            watch(ID2, funded(), required()),
            watch(ID3, released(), 0),
        ];
        let report = scan_rent_health(&before, NOW, PCT);
        // Zero side effects: the snapshots are bit-identical afterwards
        // (WatchedEscrowWithBalance is Copy + PartialEq, so this is
        // exact).
        assert_eq!(
            before,
            [
                watch(ID1, funded(), critical_min(PCT) - 1),
                watch(ID2, funded(), required()),
                watch(ID3, released(), 0),
            ]
        );
        assert_eq!(report.scanned, 3);
        // Input order preserved: ID1's top-up first, ID3's second.
        assert_eq!(report.top_ups.len(), 2);
        assert_eq!(report.top_ups[0].escrow_id, ID1);
        assert_eq!(report.top_ups[1].escrow_id, ID3);
    }

    #[test]
    fn listed_balance_always_fails_the_main_rent_formula() {
        // Cross-check: every listed vault fails `check_vault_rent_exempt`
        // with the mainnet parameters — the scan's notion of
        // "underfunded" is exactly the chain's notion of "not
        // rent-exempt".
        let balances = [
            0,
            1,
            critical_min(PCT) - 1,
            required() - 1,
        ];
        for (i, balance) in balances.iter().enumerate() {
            let watched = [watch([i as u8; 32], funded(), *balance)];
            let report = scan_rent_health(&watched, NOW, 100);
            assert_eq!(report.top_ups.len(), 1, "balance={balance}");
            assert_eq!(
                check_vault_rent_exempt(
                    *balance,
                    MAINNET_LAMPORTS_PER_BYTE_YEAR,
                    MAINNET_EXEMPTION_THRESHOLD_YEARS
                ),
                Err(RentShortfall {
                    required: required(),
                    provided: *balance,
                }),
                "listed balance must fail the main rent formula: {balance}"
            );
        }
    }

}

#[cfg(test)]
mod stale_sweep_tests {
    use super::*;
    use crate::anchor_idl_tests::INSTRUCTIONS;
    use crate::tx_message::{decode_base64, decode_message, encode_message};

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const CAROL: [u8; 32] = [0xCC; 32]; // second initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const ARBITER: [u8; 32] = [0xA8; 32];
    const ID1: [u8; 32] = [0x01; 32];
    const ID2: [u8; 32] = [0x02; 32];
    const ID3: [u8; 32] = [0x03; 32];
    const ID4: [u8; 32] = [0x04; 32];
    const ID5: [u8; 32] = [0x05; 32];
    const ID6: [u8; 32] = [0x06; 32];
    const ID7: [u8; 32] = [0x07; 32];
    const ID8: [u8; 32] = [0x08; 32];
    const PROGRAM_ID: [u8; 32] = [0x07; 32];
    const BLOCKHASH: [u8; 32] = [0xBB; 32];
    const NOW: u64 = 1_750_000_000;
    const EXPIRED: u64 = 1_700_000_000;
    const FUTURE: u64 = 1_800_000_000; // dispute paths need now < expires_at

    fn rent() -> u64 {
        vault_close_rent_reclaimed()
    }

    fn watch(id: [u8; 32], escrow: Escrow, vault_lamports: u64) -> WatchedEscrowWithBalance {
        WatchedEscrowWithBalance {
            escrow_id: id,
            escrow,
            vault_lamports,
        }
    }

    fn cancelled(initializer: [u8; 32], expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(initializer, BOB, 1_000_000, expires_at).unwrap();
        e.fund(initializer, NOW).unwrap();
        e.cancel(initializer, None, initializer, 0).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        e
    }

    fn released(initializer: [u8; 32]) -> Escrow {
        let mut e = Escrow::initialize(initializer, BOB, 1_000_000, EXPIRED).unwrap();
        e.fund(initializer, NOW).unwrap();
        e.release(initializer, NOW, 1_000_000, None, BOB).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        e
    }

    fn settled(initializer: [u8; 32]) -> Escrow {
        let mut e = Escrow::initialize(initializer, BOB, 1_000_000, FUTURE)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(initializer, NOW).unwrap();
        e.escalate(initializer, NOW, e.remaining_amount(), None, None, 0).unwrap();
        e.resolve(ARBITER, 400_000, NOW, None, None, BOB).unwrap();
        assert_eq!(e.state(), EscrowState::Settled);
        e
    }

    fn funded(initializer: [u8; 32]) -> Escrow {
        let mut e = Escrow::initialize(initializer, BOB, 1_000_000, EXPIRED).unwrap();
        e.fund(initializer, NOW).unwrap();
        e
    }

    fn split(initializer: [u8; 32]) -> Escrow {
        // AV-81: a split parent — the funds were re-homed into the
        // children, so the parent vault carries nothing but the rent
        // deposit: stale-sweep eligible like the other terminals.
        let mut e = funded(initializer);
        e.split_escrow(
            initializer,
            BOB,
            &[600_000, 400_000],
            crate::SplitConfig::default(),
            NOW,
        )
        .unwrap();
        assert_eq!(e.state(), EscrowState::Split);
        e
    }

    fn hex_of(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn empty_input_scans_to_empty_report() {
        let report = scan_stale_vaults(&[]);
        assert!(report.is_empty());
        assert_eq!(report.scanned, 0);
        assert_eq!(report.required_lamports, rent());
        let expected = format!(
            "{{\"scanned\":0,\"required_lamports\":{},\"batches\":[]}}",
            rent()
        );
        assert_eq!(report.to_json(), expected);
    }

    #[test]
    fn lists_only_rent_only_terminal_vaults() {
        let r = rent();
        let watched = [
            watch(ID1, cancelled(ALICE, EXPIRED), r), // listed: cancelled, rent-only
            watch(ID2, released(ALICE), r),           // listed: released, rent-only
            watch(ID3, settled(ALICE), r),            // listed: settled, rent-only
            watch(ID4, funded(ALICE), r),             // Funded: not terminal
            watch(ID5, cancelled(ALICE, EXPIRED), r + 1), // user funds left: not rent-only
            watch(ID6, cancelled(ALICE, EXPIRED), r - 1), // underfunded: rent-health's job
            watch(ID7, released(CAROL), r),           // listed: other initializer
            watch(ID8, split(ALICE), r),             // listed: split, rent-only (AV-81)
        ];
        let report = scan_stale_vaults(&watched);
        assert_eq!(report.scanned, 8);
        assert_eq!(report.batches.len(), 2, "two initializers: {report:?}");
        let alice = &report.batches[0];
        assert_eq!(alice.caller, ALICE);
        assert_eq!(alice.actions.len(), 4);
        assert_eq!(alice.total_reclaimed, 4 * r);
        assert_eq!(alice.actions[0].escrow_id, ID1);
        assert_eq!(alice.actions[0].caller, ALICE);
        assert_eq!(alice.actions[0].caller_role, "initializer");
        assert_eq!(alice.actions[0].vault_lamports, r);
        assert_eq!(alice.actions[0].rent_reclaimed, r);
        assert_eq!(alice.actions[0].expires_at, EXPIRED);
        assert_eq!(alice.actions[0].reason, "cancelled");
        assert_eq!(alice.actions[1].reason, "released");
        assert_eq!(alice.actions[2].reason, "settled");
        assert_eq!(alice.actions[3].reason, "split");
        assert_eq!(alice.actions[3].escrow_id, ID8);
        let carol = &report.batches[1];
        assert_eq!(carol.caller, CAROL);
        assert_eq!(carol.actions.len(), 1);
        assert_eq!(carol.total_reclaimed, r);
    }

    #[test]
    fn disputed_closed_and_paused_vaults_are_never_listed() {
        let r = rent();
        // Disputed: arbitration live, the chain rejects the close.
        let mut d = Escrow::initialize(ALICE, BOB, 1_000_000, FUTURE)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        d.fund(ALICE, NOW).unwrap();
        d.escalate(ALICE, NOW, d.remaining_amount(), None, None, 0).unwrap();
        assert_eq!(d.state(), EscrowState::Disputed);
        // Closed: the rent is already reclaimed.
        let mut c = cancelled(ALICE, EXPIRED);
        c.close_vault(ALICE).unwrap();
        assert_eq!(c.state(), EscrowState::Closed);
        // Paused terminal vault: `close_vault` would fail `Paused`.
        let mut p = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRED)
            .unwrap()
            .with_pause_authority(ALICE)
            .unwrap();
        p.fund(ALICE, NOW).unwrap();
        p.cancel(ALICE, None, ALICE, 0).unwrap();
        p.pause(ALICE, None).unwrap();
        assert!(p.is_paused());
        let watched = [
            watch(ID1, d, r),
            watch(ID2, c, 0),
            watch(ID3, p, r),
        ];
        let report = scan_stale_vaults(&watched);
        assert!(report.is_empty(), "nothing listed: {report:?}");
        assert_eq!(report.scanned, 3);
    }

    #[test]
    fn dry_run_leaves_everything_untouched() {
        let r = rent();
        let watched = [
            watch(ID1, cancelled(ALICE, EXPIRED), r),
            watch(ID2, funded(ALICE), r),
            watch(ID3, settled(CAROL), r),
        ];
        let before = watched;
        let report = scan_stale_vaults(&watched);
        assert_eq!(watched, before, "the scan must not mutate its input");
        // Deterministic: the same watch list always renders the same
        // preview.
        assert_eq!(report.to_json(), scan_stale_vaults(&watched).to_json());
        // The listed escrows are unchanged too (Copy snapshots compare).
        for (w, b) in watched.iter().zip(before.iter()) {
            assert_eq!(w.escrow.state(), b.escrow.state());
        }
    }

    #[test]
    fn report_json_shape_is_deterministic() {
        let r = rent();
        let watched = [watch(ID1, cancelled(ALICE, EXPIRED), r)];
        let json = scan_stale_vaults(&watched).to_json();
        let expected = format!(
            "{{\"scanned\":1,\"required_lamports\":{r},\"batches\":[{{\"caller\":\"{}\",\"total_reclaimed\":{r},\"actions\":[{{\"escrow_id\":\"{}\",\"action\":\"close_vault\",\"caller\":\"{}\",\"caller_role\":\"initializer\",\"vault_lamports\":{r},\"rent_reclaimed\":{r},\"expires_at\":{EXPIRED},\"reason\":\"cancelled\"}}]}}]}}",
            hex_of(0xAA),
            hex_of(0x01),
            hex_of(0xAA),
        );
        assert_eq!(json, expected);
    }

    #[test]
    fn signable_message_carries_real_close_vault_bytes() {
        // The byte-exact core: data == the close_vault discriminator
        // (the IDL name rule, the shared constructor, and the bundle's
        // recomputed bytes all agree), pinned against the INSTRUCTIONS
        // spec table — `close_vault` takes no params.
        let spec = INSTRUCTIONS
            .iter()
            .find(|s| s.name == "close_vault")
            .expect("INSTRUCTIONS missing close_vault");
        assert_eq!(spec.params.len(), 0, "close_vault(params: [])");
        assert_eq!(spec.method, "Escrow::close_vault");

        let r = rent();
        let report = scan_stale_vaults(&[watch(ID1, cancelled(ALICE, EXPIRED), r)]);
        let action = report.batches[0].actions[0];
        let b64 = stale_vault_signable_message(PROGRAM_ID, &action, BLOCKHASH).unwrap();
        let bytes = decode_base64(&b64).unwrap();
        let msg = decode_message(&bytes).unwrap();
        assert_eq!(msg.instructions.len(), 1, "one instruction per message");
        let cix = &msg.instructions[0];
        // Discriminator pinned three ways.
        let mut expected_disc = [0u8; 8];
        expected_disc
            .copy_from_slice(&crate::sha256(format!("global:close_vault").as_bytes())[..8]);
        assert_eq!(&cix.data[..8], &expected_disc);
        assert_eq!(&cix.data[..8], &instruction_discriminator("close_vault"));
        assert_eq!(cix.data.len(), 8, "discriminator only — no params");
        // Account metas in program-declared order: vault (writable,
        // non-signer), initializer (writable, signer). Compiled
        // canonical order: writable signers, writable non-signers,
        // then the readonly program id.
        assert_eq!(
            msg.account_keys,
            vec![ALICE, ID1, PROGRAM_ID],
            "initializer, vault, program id"
        );
        assert_eq!(cix.program_id_index, 2);
        assert_eq!(cix.accounts, vec![1, 0], "vault, initializer");
        assert_eq!(msg.recent_blockhash, BLOCKHASH);
        assert_eq!(msg.header.num_required_signatures, 1);
        assert_eq!(msg.header.num_readonly_signed_accounts, 0);
        assert_eq!(msg.header.num_readonly_unsigned_accounts, 1);
        // Re-encoding the decoded message reproduces the exact bytes —
        // the base64 is a faithful serialization (the AV-71 dry-run
        // property: building the bundle never touches the action).
        let before = action;
        assert_eq!(encode_base64(&encode_message(&msg)), b64);
        assert_eq!(action, before);
    }

    #[test]
    fn bundle_json_lists_one_message_per_action() {
        let r = rent();
        let report = scan_stale_vaults(&[
            watch(ID1, cancelled(ALICE, EXPIRED), r),
            watch(ID2, released(ALICE), r),
        ]);
        let batch = &report.batches[0];
        let json = batch.to_bundle_json(PROGRAM_ID, BLOCKHASH).unwrap();
        assert!(
            json.contains(&format!("\"caller\":\"{}\"", hex_of(0xAA))),
            "bundle names the caller: {json}"
        );
        for a in &batch.actions {
            let expected = stale_vault_signable_message(PROGRAM_ID, a, BLOCKHASH).unwrap();
            let escrow_hex = a
                .escrow_id
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert!(
                json.contains(&format!("\"escrow_id\":\"{escrow_hex}\",\"message\":\"{expected}\"")),
                "bundle carries the exact message for {escrow_hex}"
            );
            // Every message decodes back to a well-formed legacy
            // message targeting close_vault.
            let msg = decode_message(&decode_base64(&expected).unwrap()).unwrap();
            assert_eq!(msg.instructions.len(), 1);
            assert_eq!(
                &msg.instructions[0].data[..8],
                &instruction_discriminator("close_vault")
            );
        }
    }

    // ---------- AV-132: CpiQuote lock + post-execution assertion ----------
    //
    // The keeper locks the off-chain quote at bundle-signing time
    // (deriving the min_payout floor it stamps on release_via_cpi)
    // and asserts the execution against the locked quote afterwards:
    // a deviation beyond the floor, or a stale quote, is rejected
    // off-chain.

    const QUOTE_ID: [u8; 32] = [0x71; 32];

    #[test]
    fn cpi_quote_lock_derives_the_floor() {
        // 1_000_000 quoted with 100 bps tolerance → 990_000 floor.
        let q = CpiQuote::lock(1_000_000, 100, 1_700_000_000, QUOTE_ID).unwrap();
        assert_eq!(q.quoted_payout, 1_000_000);
        assert_eq!(q.min_payout, 990_000);
        assert_eq!(q.locked_at, 1_700_000_000);
        assert_eq!(q.quote_id, QUOTE_ID);
        // Zero tolerance: the floor is the quote itself.
        let q = CpiQuote::lock(1_000_000, 0, 1_700_000_000, QUOTE_ID).unwrap();
        assert_eq!(q.min_payout, 1_000_000);
        // Full tolerance: the floor is zero (no protection).
        let q = CpiQuote::lock(1_000_000, 10_000, 1_700_000_000, QUOTE_ID).unwrap();
        assert_eq!(q.min_payout, 0);
    }

    #[test]
    fn cpi_quote_lock_rejects_bad_inputs() {
        assert_eq!(
            CpiQuote::lock(0, 100, 1_700_000_000, QUOTE_ID),
            Err(CpiQuoteError::ZeroQuote)
        );
        assert_eq!(
            CpiQuote::lock(1_000_000, 10_001, 1_700_000_000, QUOTE_ID),
            Err(CpiQuoteError::InvalidSlippageBps)
        );
    }

    #[test]
    fn cpi_quote_verify_execution_matrix() {
        let q = CpiQuote::lock(1_000_000, 100, 1_700_000_000, QUOTE_ID).unwrap();
        // At the floor, fresh quote: passes.
        assert_eq!(q.verify_execution(990_000, 1_700_000_100, 300), Ok(()));
        // Above the floor: passes.
        assert_eq!(q.verify_execution(995_000, 1_700_000_100, 300), Ok(()));
        // Below the floor: rejected — the execution deviated from the
        // quote beyond tolerance.
        assert_eq!(
            q.verify_execution(989_999, 1_700_000_100, 300),
            Err(CpiQuoteError::SlippageExceeded)
        );
        // Fresh floor but stale quote: rejected — the market may have
        // moved since the lock.
        assert_eq!(
            q.verify_execution(995_000, 1_700_000_301, 300),
            Err(CpiQuoteError::QuoteStale)
        );
        // Slippage takes precedence over staleness (the deviation is
        // the sharper signal).
        assert_eq!(
            q.verify_execution(989_999, 1_700_000_301, 300),
            Err(CpiQuoteError::SlippageExceeded)
        );
    }
}
