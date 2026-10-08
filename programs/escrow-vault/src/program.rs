//! Anchor program skeleton for the escrow vault.
//!
//! NOTE: This file is not compiled by CI. Building it requires the
//! Solana/Anchor toolchain (`anchor-lang`), which is intentionally kept out
//! of the workspace. It is excluded from the `escrow-vault` cargo package
//! (that package only ships the ignored integration test stubs in
//! `tests/`); it is kept here as the reference Anchor implementation.
//! It shows how the dependency-free state machine in
//! `escrow-state` maps onto Anchor instructions: each instruction converts
//! the on-chain account into `escrow_state::Escrow`, runs the transition,
//! and writes it back. State and authority rules live in one place —
//! the `escrow-state` crate — so the on-chain program cannot drift from
//! the tested logic. The optional N-of-M attestor quorum (`initialize_quorum`
//! / `attest`) gates `release` exactly as the state machine does; the
//! optional linear vesting schedule (`initialize_vesting` / `claim`) lets
//! the taker pull the vested stream exactly as `Escrow::claim` defines;
//! the optional dispute arbiter (`initialize_arbiter` / `escalate` /
//! `resolve`) settles contested escrows with one atomic split exactly as
//! `Escrow::escalate` / `Escrow::resolve` define; the optional milestone
//! tranche plan (`initialize_milestones` / `confirm_milestone` /
//! `release_milestone` / `skip_milestone`) releases the lockup in
//! dual-confirmed tranches exactly as `Escrow::with_milestones` and
//! friends define; the optional SPL token mint binding (`initialize_mint`)
//! scopes the escrow to one token mint exactly as `Escrow::with_mint`
//! defines, with every fund-moving instruction verifying the vault token
//! account's mint against the bound address (`MintMismatch` otherwise);
//! the optional protocol fee (`initialize_protocol_fee`) routes a
//! basis-point slice of every taker payout to the protocol fee account
//! exactly as `Escrow::with_protocol_fee` / `protocol_fee_for` define;
//! every state transition emits a typed indexer event (`emit!`, AV-18)
//! mirroring `escrow_state::EscrowEvent`, with a per-vault monotonic
//! `seq` so an off-chain indexer can subscribe to state changes in
//! order instead of polling account data.
//!
//! To compile for real: `anchor build` with the Solana toolchain installed.

use anchor_lang::prelude::*;

// Program ID placeholder — replace with the real deployed program address.
declare_id!("EscrowVault1111111111111111111111111111111111");

#[program]
pub mod escrow_vault {
    use super::*;

    /// Create the vault account and record initializer / taker / amount /
    /// expiry. Pass `u64::MAX` as `expires_at` for no timeout.
    pub fn initialize(ctx: Context<Initialize>, amount: u64, expires_at: u64) -> Result<()> {
        let escrow = escrow_state::Escrow::initialize(
            ctx.accounts.initializer.key().to_bytes(),
            ctx.accounts.taker.key().to_bytes(),
            amount,
            expires_at,
        )
        .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: the constructor has no prior state — from == to ==
        // Uninitialized by the same convention as `IndexedEscrow`.
        let state = escrow_state::EscrowState::Uninitialized as u8;
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Initialized,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
        );
        Ok(())
    }

    /// Lock funds into the vault (`Uninitialized -> Funded`).
    pub fn fund(ctx: Context<Fund>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        escrow
            .fund(ctx.accounts.initializer.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: one indexer event per state transition (mirrors
        // `IndexedEscrow::fund`).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Funded,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
        );
        Ok(())
    }

    /// Release `amount` of the locked funds to the taker. Partial releases
    /// accumulate in `vault.released` and leave the escrow `Funded`; when
    /// the cumulative released total reaches the locked amount the escrow
    /// becomes `Released`. Cumulative releases must not exceed the locked
    /// amount (`ReleaseExceedsLocked`); `amount == 0` is `AmountMismatch`.
    /// The AV-04 quorum gate applies exactly as the state machine defines.
    /// Returns `(taker_payout, fee)`: the taker's net payout and the
    /// protocol fee (AV-17), so the real build can transfer each to its
    /// destination (taker account / protocol fee account).
    /// AV-16: the vault token account's mint must equal the bound
    /// `vault.mint` (`MintMismatch` otherwise); `None` on the native-SOL
    /// path (no mint bound).
    pub fn release(ctx: Context<Release>, amount: u64) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let (payout, fee) = escrow
            .release(
                ctx.accounts.initializer.key().to_bytes(),
                amount,
                vault_token_mint(&ctx.accounts.vault_token_account),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Transfer of `payout` lamports/tokens to `ctx.accounts.taker`
        // and `fee` to the protocol fee account goes here once real
        // token accounts are wired up.
        // AV-18: `payout + fee` is the gross amount (== the `amount`
        // param); partial releases carry from == to == Funded, the
        // closing one to == Released.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Released,
            from,
            escrow.state() as u8,
            payout + fee,
            fee,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
        );
        Ok((payout, fee))
    }

    /// Cancel the escrow and return funds (`Funded -> Cancelled`).
    /// AV-16: the vault token account's mint must equal the bound
    /// `vault.mint` (`MintMismatch` otherwise); `None` on the native-SOL
    /// path (no mint bound).
    /// AV-23: the refund goes to `accounts.refund_to`, pinned by the
    /// state machine against the escrow's refund policy (the whitelisted
    /// address, or the initializer with no whitelist;
    /// `RefundAddressMismatch` otherwise) — a phishing frontend cannot
    /// redirect the refund by swapping the destination account.
    pub fn cancel(ctx: Context<Cancel>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        escrow
            .cancel(
                ctx.accounts.initializer.key().to_bytes(),
                vault_token_mint(&ctx.accounts.vault_token_account),
                ctx.accounts.refund_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: the refund is the remainder after any partial releases.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Cancelled,
            from,
            escrow.state() as u8,
            0,
            0,
            escrow.remaining_amount(),
            Clock::get()?.unix_timestamp as u64,
            None,
        );
        Ok(())
    }

    /// Cancel an expired escrow (`Funded -> Cancelled`). Either the
    /// initializer or the taker may call this once the clock (Solana
    /// clock sysvar in the real build) has passed `expires_at` plus the
    /// opt-in grace period (`initialize_grace_period`; `NotExpired`
    /// otherwise) — the grace period absorbs keeper/cluster clock drift
    /// so a keeper cannot submit a premature cancel.
    /// AV-16: the vault token account's mint must equal the bound
    /// `vault.mint` (`MintMismatch` otherwise); `None` on the native-SOL
    /// path (no mint bound).
    /// AV-23: the refund goes to `accounts.refund_to`, pinned by the
    /// state machine against the escrow's refund policy — even when the
    /// taker is the caller, the refund goes to the declared address,
    /// never to the caller (`RefundAddressMismatch` otherwise).
    /// AV-24: on a *taker-initiated* cancel the state machine returns
    /// the `(refund, penalty)` split — the penalty is routed to the
    /// initializer as griefing compensation (a separate transfer in the
    /// real build); initializer-initiated cancels return
    /// `(remaining, 0)`.
    pub fn cancel_expired(ctx: Context<CancelExpired>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        let (refund, _penalty) = escrow
            .cancel_expired(
                ctx.accounts.authority.key().to_bytes(),
                now,
                vault_token_mint(&ctx.accounts.vault_token_account),
                ctx.accounts.refund_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Refund of lamports/tokens to the initializer goes here
        // once real token accounts are wired up. AV-24: `refund` goes to
        // `accounts.refund_to`; `penalty` (non-zero only on a
        // taker-initiated cancel) is a second transfer to the
        // initializer — the griefing compensation.
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::cancel_expired`. The real build's
        // `EscrowVaultEvent` gains a `penalty` amounts field mirroring
        // `escrow_state::EventAmounts::penalty`; the skeleton's
        // `emit_transition` keeps its current shape until the real
        // build wires the event struct.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::ExpiredCancelled,
            from,
            escrow.state() as u8,
            0,
            0,
            refund,
            now,
            None,
        );
        Ok(())
    }

    /// Attach an N-of-M attestor quorum to the release path (`Uninitialized`
    /// only; mirrors `Escrow::with_quorum`). After this, `release`
    /// additionally requires `threshold` distinct attestations; the refund
    /// paths (`cancel` / `cancel_expired`) stay quorum-free by design.
    pub fn initialize_quorum(
        ctx: Context<InitializeQuorum>,
        attestors: Vec<Pubkey>,
        threshold: u8,
    ) -> Result<()> {
        let keys: Vec<[u8; 32]> = attestors.iter().map(|k| k.to_bytes()).collect();
        let policy =
            escrow_state::QuorumPolicy::new(&keys, threshold).map_err(|e| escrow_error(e))?;
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_quorum(policy).map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full quorum region
        // (`escrow_state::QUORUM_POLICY_LEN`), so the policy is written in
        // place — no realloc needed in the real build.
        Ok(())
    }

    /// Record an attestation from a registered attestor (mirrors
    /// `Escrow::attest`). Idempotent; callers outside the registered set
    /// get `Unauthorized`.
    pub fn attest(ctx: Context<Attest>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let approvals_before = escrow
            .quorum()
            .map(|q| q.approval_count())
            .unwrap_or(0);
        escrow
            .attest(ctx.accounts.attestor.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flip the attestor's bit in `vault.quorum.approvals` in the real build.
        // AV-18: emit only for a *new* attestation (mirrors
        // `IndexedEscrow::attest`); idempotent duplicates emit nothing.
        // from == to == the current state — the quorum bitmask, not the
        // lifecycle state, is what changed.
        let approvals_after = escrow.quorum().map(|q| q.approval_count()).unwrap_or(0);
        if approvals_after > approvals_before {
            let state = escrow.state() as u8;
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::Attested,
                state,
                state,
                0,
                0,
                0,
                Clock::get()?.unix_timestamp as u64,
                None,
            );
        }
        Ok(())
    }

    /// Adjust the quorum's attestation threshold by dual-signed
    /// governance (AV-25; mirrors `Escrow::update_quorum`). Both the
    /// initializer and the taker must sign — one party alone cannot
    /// weaken the gate. Allowed on `Uninitialized` or `Funded` escrows;
    /// `0` or above the registered attestor count is `InvalidQuorum`, as
    /// is calling with no quorum configured. The attestor set and
    /// existing attestations are untouched — only the threshold moves,
    /// in place, so the account needs no realloc. Emits `QuorumUpdated`
    /// when the threshold actually changes (a no-op re-affirmation
    /// emits nothing), mirroring `IndexedEscrow::update_quorum`.
    pub fn update_quorum(ctx: Context<UpdateQuorum>, threshold: u8) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let threshold_before = escrow.quorum().map(|q| q.threshold()).unwrap_or(0);
        escrow
            .update_quorum(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
                threshold,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Write the new threshold into `vault.quorum.threshold` in the
        // real build (in place — the quorum region is always reserved).
        let threshold_after = escrow.quorum().map(|q| q.threshold()).unwrap_or(0);
        if threshold_after != threshold_before {
            let state = escrow.state() as u8;
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::QuorumUpdated,
                state,
                state,
                0,
                0,
                0,
                Clock::get()?.unix_timestamp as u64,
                None,
            );
        }
        Ok(())
    }

    /// Opt in to dual-signature activation (AV-12; mirrors
    /// `Escrow::with_dual_sig`). `Uninitialized` only, like
    /// `initialize_quorum`. After this, `fund` requires the escrow to be
    /// `Activated`: a single signature can create the escrow but never
    /// fund it.
    pub fn initialize_dual_sig(ctx: Context<InitializeDualSig>) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_dual_sig().map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Sets the required-bit in `vault.activation` in the real build.
        Ok(())
    }

    /// Record one party's activation signature (AV-12; mirrors
    /// `Escrow::activate`). Either the initializer or the taker signs;
    /// idempotent per party. When both bits are set the escrow moves
    /// `Uninitialized -> Activated`, unlocking `fund`. A stranger's
    /// signature is `Unauthorized`.
    pub fn activate(ctx: Context<Activate>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        escrow
            .activate(ctx.accounts.authority.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flip the party's bit in `vault.activation` in the real build.
        // AV-18: emit only when the call actually transitioned the escrow
        // (mirrors `IndexedEscrow::activate`); a single party's signature
        // emits nothing.
        let to = escrow.state() as u8;
        if to != from {
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::Activated,
                from,
                to,
                0,
                0,
                0,
                Clock::get()?.unix_timestamp as u64,
                None,
            );
        }
        Ok(())
    }

    /// Attach a linear vesting schedule (AV-13; mirrors
    /// `VestingSchedule::new` + `Escrow::with_vesting`). `Uninitialized`
    /// only, like `initialize_quorum`: the unlock curve is fixed before
    /// funds move. `start >= end` is `InvalidVesting`.
    pub fn initialize_vesting(ctx: Context<InitializeVesting>, start: u64, end: u64) -> Result<()> {
        let schedule =
            escrow_state::VestingSchedule::new(start, end).map_err(|e| escrow_error(e))?;
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_vesting(schedule).map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full vesting region
        // (1 + 16 bytes, zeroed when `None`), so the schedule is written
        // in place — no realloc needed in the real build.
        Ok(())
    }

    /// Claim the vested-but-unreleased portion (AV-13; mirrors
    /// `Escrow::claim`). Only the taker may call this; `now` comes from
    /// the Solana clock sysvar (never an instruction param — a
    /// caller-supplied timestamp would let anyone fast-forward the unlock
    /// curve). Returns `(taker_payout, fee)` so the real build can size
    /// the taker's transfer and the protocol fee (AV-17). The AV-04
    /// quorum gate applies exactly as for `release`. AV-16: the vault
    /// token account's mint must equal the bound `vault.mint`
    /// (`MintMismatch` otherwise); `None` on the native-SOL path (no
    /// mint bound).
    pub fn claim(ctx: Context<Claim>) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        let (payout, fee) = escrow
            .claim(
                ctx.accounts.taker.key().to_bytes(),
                now,
                vault_token_mint(&ctx.accounts.vault_token_account),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Transfer of `payout` lamports/tokens to `ctx.accounts.taker`
        // and `fee` to the protocol fee account goes here once real
        // token accounts are wired up.
        // AV-18: `payout + fee` is the gross claimable; `now` doubles as
        // the event's `at`, mirroring `IndexedEscrow::claim`.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Claimed,
            from,
            escrow.state() as u8,
            payout + fee,
            fee,
            0,
            now,
            None,
        );
        Ok((payout, fee))
    }

    /// Opt in to dispute arbitration (AV-14; mirrors
    /// `Escrow::with_arbiter`). `Uninitialized` only, like
    /// `initialize_quorum`: the arbiter's identity is fixed before funds
    /// move. The zero key is `InvalidArbiter` — the arbiter must be a real
    /// identity, since `resolve` authenticates against it.
    pub fn initialize_arbiter(ctx: Context<InitializeArbiter>, arbiter: Pubkey) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_arbiter(arbiter.to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full arbiter region
        // (33 bytes, zeroed when `None`), so the key is written in place
        // — no realloc needed in the real build.
        Ok(())
    }

    /// Escalate the escrow into arbitration (AV-14; mirrors
    /// `Escrow::escalate`): `Funded -> Disputed`. Either the initializer
    /// or the taker signs; `now` comes from the Solana clock sysvar (never
    /// an instruction param — a caller-supplied timestamp could rewind
    /// past the dispute window). While `Disputed`, every unilateral exit
    /// (`release` / `cancel` / `cancel_expired` / `claim`) is locked.
    /// AV-22: `evidence_hash` is the optional 32-byte commitment to the
    /// off-chain dispute evidence (e.g. the SHA-256 of an IPFS CID),
    /// persisted on the vault so the arbiter and indexers can read it.
    pub fn escalate(ctx: Context<Escalate>, evidence_hash: Option<[u8; 32]>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        escrow
            .escalate(
                ctx.accounts.authority.key().to_bytes(),
                now,
                evidence_hash,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::escalate`. AV-22: the Escalated event carries
        // the attached evidence hash.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Escalated,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            evidence_hash,
        );
        Ok(())
    }

    /// Settle a disputed escrow (AV-14; mirrors `Escrow::resolve`):
    /// `Disputed -> Settled`. Only the configured arbiter signs;
    /// `taker_amount` is the taker's share of the remaining locked funds
    /// (the initializer is refunded the rest) in one atomic settlement.
    /// Returns `(taker_payout, fee, initializer_refund)` so the real
    /// build can size all three transfers: the protocol fee (AV-17)
    /// slices the taker's share, the refund is never fee'd. The quorum
    /// gate does not apply: the arbiter is the resolution mechanism.
    /// AV-16: the vault token account's mint must equal the bound
    /// `vault.mint` (`MintMismatch` otherwise); `None` on the
    /// native-SOL path (no mint bound).
    pub fn resolve(ctx: Context<Resolve>, taker_amount: u64) -> Result<(u64, u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let (payout, fee, refund) = escrow
            .resolve(
                ctx.accounts.arbiter.key().to_bytes(),
                taker_amount,
                vault_token_mint(&ctx.accounts.vault_token_account),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Transfer of `payout` to `ctx.accounts.taker`, `fee` to the
        // protocol fee account, and `refund` to
        // `ctx.accounts.initializer` goes here once real token accounts
        // are wired up.
        // AV-18: `taker_amount` is the gross taker share
        // (`payout + fee`); the refund is never fee'd.
        // AV-22: the Resolved event carries the dispute evidence hash
        // the escrow still holds — the settlement references the
        // evidence the arbiter reviewed.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Resolved,
            from,
            escrow.state() as u8,
            taker_amount,
            fee,
            refund,
            Clock::get()?.unix_timestamp as u64,
            escrow.evidence_hash(),
        );
        Ok((payout, fee, refund))
    }

    /// Attach a milestone tranche plan (AV-15; mirrors
    /// `MilestonePlan::new` + `Escrow::with_milestones`). `Uninitialized`
    /// only, like `initialize_quorum`: the tranche schedule is fixed
    /// before funds move. The tranche amounts must sum to exactly the
    /// locked amount (checked in u128, so the sum can never wrap); once
    /// attached, the plan owns the release schedule — plain `release` and
    /// `claim` become `InvalidMilestones`.
    pub fn initialize_milestones(
        ctx: Context<InitializeMilestones>,
        milestones: Vec<u64>,
    ) -> Result<()> {
        let plan =
            escrow_state::MilestonePlan::new(&milestones).map_err(|e| escrow_error(e))?;
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_milestones(plan).map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full milestone region
        // (1 + 65 bytes, zeroed when `None`), so the plan is written in
        // place — no realloc needed in the real build.
        Ok(())
    }

    /// Confirm a milestone for the release path (AV-15; mirrors
    /// `Escrow::confirm_milestone`). Either the initializer or the taker
    /// signs; each confirmation is a separate signature and the milestone
    /// is confirmed only once BOTH parties confirmed (dual-signature
    /// acceptance). Strictly in-order and idempotent per party.
    pub fn confirm_milestone(ctx: Context<ConfirmMilestone>, index: u8) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let confirmed_before = escrow.milestone_confirmed(index as usize);
        escrow
            .confirm_milestone(ctx.accounts.authority.key().to_bytes(), index)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flip the party's confirmation bit in `vault.milestone_flags` in
        // the real build.
        // AV-18: emit only when the milestone became fully confirmed
        // (mirrors `IndexedEscrow::confirm_milestone`); the first party's
        // confirmation alone emits nothing.
        if !confirmed_before && escrow.milestone_confirmed(index as usize) {
            let state = escrow.state() as u8;
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::MilestoneConfirmed,
                state,
                state,
                0,
                0,
                0,
                Clock::get()?.unix_timestamp as u64,
                None,
            );
        }
        Ok(())
    }

    /// Release a milestone's tranche to the taker (AV-15; mirrors
    /// `Escrow::release_milestone`). Only the initializer signs; the
    /// milestone must be dual-confirmed (`MilestoneNotConfirmed`
    /// otherwise) and every earlier milestone settled. Returns
    /// `(taker_payout, fee)` so the real build can size the taker's
    /// transfer and the protocol fee (AV-17). The AV-04 quorum gate
    /// applies exactly as for `release`. AV-16: the vault token
    /// account's mint must equal the bound `vault.mint` (`MintMismatch`
    /// otherwise); `None` on the native-SOL path (no mint bound).
    pub fn release_milestone(ctx: Context<ReleaseMilestone>, index: u8) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let (payout, fee) = escrow
            .release_milestone(
                ctx.accounts.initializer.key().to_bytes(),
                index,
                vault_token_mint(&ctx.accounts.vault_token_account),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Transfer of `payout` lamports/tokens to `ctx.accounts.taker`
        // and `fee` to the protocol fee account goes here once real
        // token accounts are wired up.
        // AV-18: `payout + fee` is the gross tranche; the final tranche
        // carries to == Released.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::MilestoneReleased,
            from,
            escrow.state() as u8,
            payout + fee,
            fee,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
        );
        Ok((payout, fee))
    }

    /// Skip a milestone by mutual agreement (AV-15; mirrors
    /// `Escrow::skip_milestone`). Either the initializer or the taker
    /// signs; the skip executes (tranche refunded to the initializer)
    /// only after BOTH parties approved — a dual-signature skip.
    /// Strictly in-order and idempotent per party.
    pub fn skip_milestone(ctx: Context<SkipMilestone>, index: u8) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let settled_before = escrow.milestone_settled(index as usize);
        let tranche = escrow
            .milestone_plan()
            .and_then(|p| p.amount_at(index as usize))
            .unwrap_or(0);
        escrow
            .skip_milestone(ctx.accounts.authority.key().to_bytes(), index)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flip the party's skip-approval bit in `vault.milestone_flags`
        // (and the skipped bit plus `vault.skipped` once dual-approved)
        // in the real build.
        // AV-18: emit only when the skip executed (both approvals
        // present; mirrors `IndexedEscrow::skip_milestone`); a lone
        // approval emits nothing. The skipped tranche is the
        // initializer's refund.
        if !settled_before && escrow.milestone_settled(index as usize) {
            let state = escrow.state() as u8;
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::MilestoneSkipped,
                state,
                state,
                0,
                0,
                tranche,
                Clock::get()?.unix_timestamp as u64,
                None,
            );
        }
        Ok(())
    }

    /// Bind one SPL token mint to the escrow (AV-16; mirrors
    /// `escrow_state::parse_mint_address` + `Escrow::with_mint`).
    /// `Uninitialized` only, like `initialize_quorum`: the token scope is
    /// fixed before funds move. The `mint` param is the base58 SPL mint
    /// address; it must decode to exactly 32 bytes (`InvalidMint`
    /// otherwise — empty string, non-alphabet characters, or a value
    /// that is not 32 bytes), and the zero address is rejected (it is
    /// well-formed but not a real mint). After this, the fund-moving
    /// instructions (`release` / `cancel` / `cancel_expired` / `claim` /
    /// `release_milestone` / `resolve`) require the vault token
    /// account's mint to equal this address (`MintMismatch` otherwise).
    /// Without a bound mint the escrow is the native-SOL path and those
    /// instructions take no token mint.
    pub fn initialize_mint(ctx: Context<InitializeMint>, mint: String) -> Result<()> {
        let bytes =
            escrow_state::parse_mint_address(&mint).map_err(|e| escrow_error(e))?;
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_mint(bytes).map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full mint region
        // (33 bytes, zeroed when `None`), so the address is written in
        // place — no realloc needed in the real build.
        Ok(())
    }

    /// Opt in to a protocol fee on taker payouts (AV-17; mirrors
    /// `Escrow::with_protocol_fee`). `Uninitialized` only, like
    /// `initialize_quorum`: the fee rate is fixed before funds move.
    /// The rate is in basis points (`fee_bps <= 10_000`;
    /// `InvalidProtocolFee` otherwise); `0` means no fee (the default).
    /// After this, every taker payout (`release` / `claim` /
    /// `release_milestone` / the taker's share of `resolve`) splits
    /// into a net payout and a protocol fee routed to the protocol fee
    /// account; the fee accumulates in `vault.fees_paid`.
    pub fn initialize_protocol_fee(ctx: Context<InitializeProtocolFee>, fee_bps: u16) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_protocol_fee(fee_bps)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.fee_bps` is always present (2 bytes, zeroed by
        // default), so the rate is written in place — no realloc needed
        // in the real build.
        Ok(())
    }

    /// Opt in to an expiry grace period (AV-21; mirrors
    /// `Escrow::with_grace_period`). `Uninitialized` only, like
    /// `initialize_quorum`: the grace period is fixed before funds move.
    /// After this, `cancel_expired` requires the clock to have passed
    /// `expires_at + grace_period` (`NotExpired` otherwise), so a keeper
    /// whose off-chain clock runs ahead of the cluster clock cannot
    /// submit a premature cancel. `grace_period == 0` means no grace
    /// (the default). `expires_at + grace_period` overflowing `u64` is
    /// `InvalidGracePeriod` — in particular a grace period cannot be
    /// combined with the no-timeout convention (`expires_at ==
    /// u64::MAX`).
    pub fn initialize_grace_period(ctx: Context<InitializeGracePeriod>, grace_period: u64) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_grace_period(grace_period)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.grace_period` is always present (8 bytes, zeroed by
        // default), so the period is written in place — no realloc needed
        // in the real build.
        Ok(())
    }

    /// Declare the refund address whitelist (AV-23; mirrors
    /// `Escrow::with_refund_address`): after this, `cancel` /
    /// `cancel_expired` only refund to `refund_to`
    /// (`RefundAddressMismatch` otherwise) — a phishing frontend cannot
    /// redirect the refund. `Uninitialized` only; the zero address is
    /// rejected.
    pub fn initialize_refund_address(
        ctx: Context<InitializeRefundAddress>,
        refund_to: Pubkey,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_refund_address(refund_to.to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.refund_to` is always present (33 bytes, zeroed by
        // default), so the address is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Opt in to an anti-griefing penalty on taker-initiated expiry
    /// cancellation (AV-24; mirrors `Escrow::with_penalty_bps`).
    /// `Uninitialized` only, like `initialize_quorum`: the rate is fixed
    /// before funds move. The rate is in basis points (`penalty_bps <=
    /// 10_000`; `InvalidPenalty` otherwise); `0` means no penalty (the
    /// default). After this, a *taker-initiated* `cancel_expired` splits
    /// the remainder into a refund (to the whitelisted destination) and
    /// a penalty routed to the initializer as griefing compensation;
    /// initializer-initiated cancels and the arbiter's `resolve` never
    /// carry it.
    pub fn initialize_penalty(ctx: Context<InitializePenalty>, penalty_bps: u16) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_penalty_bps(penalty_bps)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.penalty_bps` is always present (2 bytes, zeroed by
        // default), so the rate is written in place — no realloc needed
        // in the real build.
        Ok(())
    }
}

// --- Account structs (skeleton: field layout finalized during real build) ---

#[account]
pub struct Vault {
    pub initializer: Pubkey,
    pub taker: Pubkey,
    pub amount: u64,
    /// Cumulative amount released via `release` so far (AV-11): partial
    /// releases accumulate here; always `<= amount`. Layout position
    /// matches `escrow_state::VAULT_FIELDS`.
    pub released: u64,
    /// Unix timestamp after which either party may cancel the escrow.
    pub expires_at: u64,
    // The authoritative state lives in `escrow_state::EscrowState`;
    // persisted here as a byte until the real build wires the enum.
    pub state: u8,
    /// Optional N-of-M attestor quorum gating `release`; mirrors
    /// `escrow_state::QuorumPolicy`. `None` for a plain two-party escrow.
    /// The account always reserves the full quorum region
    /// (`escrow_state::QUORUM_POLICY_LEN` bytes, zeroed when `None`) so
    /// `initialize_quorum` writes the policy in place without reallocating.
    /// Full serialized layout: `escrow_state::VAULT_FIELDS`.
    pub quorum: Option<Quorum>,
    /// AV-12: dual-signature activation bitmask (bit 0 initializer, bit 1
    /// taker, bit 2 dual-sig required); mirrors `escrow_state`'s
    /// `activation` field. Always present (one byte, zeroed for plain
    /// escrows). Layout position matches `escrow_state::VAULT_FIELDS`.
    pub activation: u8,
    /// AV-13: optional linear vesting schedule gating `claim`; mirrors
    /// `escrow_state::VestingSchedule`. `None` for an escrow with no
    /// vesting. The account always reserves the full 17-byte region
    /// (1-byte discriminant + start/end u64, zeroed when `None`) so
    /// `initialize_vesting` writes the schedule in place without
    /// reallocating. Full serialized layout: `escrow_state::VAULT_FIELDS`.
    pub vesting: Option<Vesting>,
    /// AV-14: optional dispute arbiter; mirrors the `arbiter` field of
    /// `escrow_state::Escrow`. `None` for an escrow with no arbitration.
    /// The account always reserves the full 33-byte region (1-byte
    /// discriminant + 32-byte key, zeroed when `None`) so
    /// `initialize_arbiter` writes the key in place without reallocating.
    /// Layout position matches `escrow_state::VAULT_FIELDS` (appended
    /// last, after `vesting`).
    pub arbiter: Option<Pubkey>,
    /// AV-15: optional milestone tranche plan; mirrors
    /// `escrow_state::MilestonePlan`. `None` for an escrow with no
    /// milestone schedule. The account always reserves the full 66-byte
    /// region (1-byte discriminant + eight tranche u64s + count byte,
    /// zeroed when `None`) so `initialize_milestones` writes the plan in
    /// place without reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `arbiter`).
    pub milestones: Option<MilestonePlan>,
    /// AV-15: per-milestone confirmation bitmap (six bits per milestone:
    /// the two parties' release-path confirmations, the released bit,
    /// the two parties' skip approvals, the skipped bit); mirrors
    /// `escrow_state`'s `milestone_flags`. Always present (one u64,
    /// zeroed for escrows without a milestone plan). Layout position
    /// matches `escrow_state::VAULT_FIELDS`.
    pub milestone_flags: u64,
    /// AV-15: cumulative amount skipped by mutual agreement; mirrors
    /// `escrow_state`'s `skipped`. Skipped tranches join the refundable
    /// remainder, not the taker-payout `released` counter. Always present
    /// (one u64, zeroed when nothing was skipped). Layout position
    /// matches `escrow_state::VAULT_FIELDS`.
    pub skipped: u64,
    /// AV-16: optional SPL token mint this escrow is bound to; mirrors
    /// `escrow_state`'s `mint`. `None` for a native-SOL escrow. The
    /// account always reserves the full 33-byte region (1-byte
    /// discriminant + 32-byte address, zeroed when `None`) so
    /// `initialize_mint` writes the address in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `skipped`).
    pub mint: Option<Pubkey>,
    /// AV-17: protocol fee rate in basis points (0-10000); mirrors
    /// `escrow_state`'s `fee_bps`. Always present (one u16, zeroed when
    /// no fee is configured). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `mint`).
    pub fee_bps: u16,
    /// AV-17: cumulative protocol fee charged across payouts; mirrors
    /// `escrow_state`'s `fees_paid`. Always present (one u64, zeroed
    /// when no fee was charged). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `fee_bps`).
    pub fees_paid: u64,
    /// AV-21: expiry grace period in seconds; mirrors `escrow_state`'s
    /// `grace_period`. Always present (one u64, zeroed when no grace
    /// period is configured). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `fees_paid`).
    pub grace_period: u64,
    /// AV-22: 32-byte commitment to the off-chain dispute evidence
    /// attached at `escalate`; mirrors `escrow_state`'s `evidence_hash`.
    /// `None` when no evidence was attached. The account always reserves
    /// the full 33-byte region (1-byte discriminant + 32-byte
    /// commitment, zeroed when `None`) so `escalate` writes the hash in
    /// place without reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `grace_period`).
    pub evidence_hash: Option<[u8; 32]>,
    /// AV-23: opt-in refund address whitelist; mirrors
    /// `escrow_state`'s `refund_to`. `None` for an escrow with no
    /// whitelist (refunds go to the initializer). The account always
    /// reserves the full 33-byte region (1-byte discriminant + 32-byte
    /// address, zeroed when `None`) so `initialize_refund_address`
    /// writes the address in place without reallocating. Layout position
    /// matches `escrow_state::VAULT_FIELDS` (appended last, after
    /// `evidence_hash`).
    pub refund_to: Option<Pubkey>,
    /// AV-24: anti-griefing penalty rate in basis points; mirrors
    /// `escrow_state`'s `penalty_bps`. `0` for an escrow with no penalty
    /// configured. Always present (2 bytes, zeroed by default) so
    /// `initialize_penalty` writes the rate in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `refund_to`).
    pub penalty_bps: u16,
}

/// Skeleton mirror of `escrow_state::VestingSchedule`: the linear unlock
/// window `[start, end)` in Unix seconds. See the state machine docs for
/// the claim semantics. Serialized size is pinned by the AV-10/AV-13
/// tests (17 bytes: 1-byte `Option` discriminant + two u64s).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct Vesting {
    pub start: u64,
    pub end: u64,
}

/// Skeleton mirror of `escrow_state::QuorumPolicy`: up to 8 registered
/// attestor pubkeys, the N-of-M threshold, and a u64 approval bitmask.
/// See the state machine docs for the release-gating semantics.
/// Serialized size is pinned by `escrow_state::QUORUM_POLICY_LEN`
/// (266 bytes); the AV-10 tests assert it against a manual encoding.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct Quorum {
    pub attestors: [Pubkey; 8],
    pub registered: u8,
    pub threshold: u8,
    pub approvals: u64,
}

/// Skeleton mirror of `escrow_state::MilestonePlan`: up to
/// `escrow_state::MAX_MILESTONES` tranche amounts in release order plus
/// the tranche count. See the state machine docs for the confirmation /
/// release / skip semantics. Serialized size is pinned by
/// `escrow_state::MILESTONE_PLAN_LEN` (65 bytes); the AV-10/AV-15 tests
/// assert it against a manual encoding.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct MilestonePlan {
    pub amounts: [u64; 8],
    pub count: u8,
}

/// AV-18: on-chain indexer event, the `emit!` mirror of
/// `escrow_state::EscrowEvent`.
///
/// Every state transition emits one of these, so an off-chain indexer
/// can subscribe to state changes in per-vault `seq` order instead of
/// polling account data. Field-for-field mirror of the state-machine
/// event: `kind` / vault identity / `seq` / `from_state` → `to_state` /
/// fund movements / `at`. States are the
/// `escrow_state::EscrowState` discriminants as `u8`; amounts are the
/// gross taker payout, the protocol fee slice, and the initializer
/// refund (zeroed when the kind moves nothing — see
/// `escrow_state::EventAmounts`).
#[event]
pub struct EscrowVaultEvent {
    pub kind: EscrowVaultEventKind,
    /// The vault account: the on-chain escrow identity (the
    /// `IndexedEscrow` wrapper's caller-supplied `escrow_id` off-chain).
    pub vault: Pubkey,
    /// Per-vault monotonic sequence (0 = `initialize`); the real build
    /// persists this counter in the Vault account (`read_event_seq`), so
    /// replays stay ordered even across transactions.
    pub seq: u64,
    pub from_state: u8,
    pub to_state: u8,
    /// Gross amount moved to the taker before the protocol-fee split.
    pub payout: u64,
    /// Protocol fee (AV-17) sliced from `payout`.
    pub fee: u64,
    /// Amount returned to the initializer (cancel / cancel_expired
    /// remainder, `resolve`'s initializer share, skipped tranche).
    pub refund: u64,
    /// Unix seconds from the clock sysvar at emission.
    pub at: u64,
    /// AV-22: dispute-evidence commitment carried by the `Escalated`
    /// and `Resolved` events (`None` for every other kind); mirrors
    /// `escrow_state::EscrowEvent::evidence_hash`, so an off-chain
    /// indexer learns the evidence reference from the event stream
    /// without a second account read.
    pub evidence_hash: Option<[u8; 32]>,
}

/// AV-18: on-chain mirror of `escrow_state::EscrowEventKind`, mapped by
/// `escrow_event_kind` exactly like `escrow_error` maps
/// `escrow_state::EscrowError` onto `ErrorCode`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum EscrowVaultEventKind {
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

/// AV-18: map `escrow_state::EscrowEventKind` onto the on-chain
/// `EscrowVaultEventKind`, paralleling `escrow_error`.
fn escrow_event_kind(kind: escrow_state::EscrowEventKind) -> EscrowVaultEventKind {
    match kind {
        escrow_state::EscrowEventKind::Initialized => EscrowVaultEventKind::Initialized,
        escrow_state::EscrowEventKind::Activated => EscrowVaultEventKind::Activated,
        escrow_state::EscrowEventKind::Funded => EscrowVaultEventKind::Funded,
        escrow_state::EscrowEventKind::Released => EscrowVaultEventKind::Released,
        escrow_state::EscrowEventKind::Cancelled => EscrowVaultEventKind::Cancelled,
        escrow_state::EscrowEventKind::ExpiredCancelled => {
            EscrowVaultEventKind::ExpiredCancelled
        }
        escrow_state::EscrowEventKind::Attested => EscrowVaultEventKind::Attested,
        escrow_state::EscrowEventKind::Claimed => EscrowVaultEventKind::Claimed,
        escrow_state::EscrowEventKind::Escalated => EscrowVaultEventKind::Escalated,
        escrow_state::EscrowEventKind::Resolved => EscrowVaultEventKind::Resolved,
        escrow_state::EscrowEventKind::MilestoneConfirmed => {
            EscrowVaultEventKind::MilestoneConfirmed
        }
        escrow_state::EscrowEventKind::MilestoneReleased => {
            EscrowVaultEventKind::MilestoneReleased
        }
        escrow_state::EscrowEventKind::MilestoneSkipped => {
            EscrowVaultEventKind::MilestoneSkipped
        }
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    // Full vault space: 8-byte discriminator + 532-byte payload = 540
    // bytes (see `escrow_state::VAULT_SPACE`; AV-12 added the 1-byte
    // activation bitmask, AV-13 the 17-byte vesting region, AV-14 the
    // 33-byte arbiter region, AV-15 the 66-byte milestone plan + the
    // 8-byte confirmation bitmap + the 8-byte skipped counter, AV-16 the
    // 33-byte mint region, AV-17 the 2-byte fee rate + the 8-byte
    // cumulative fee counter).
    // The payer must fund at least the rent-exempt minimum for this space
    // — `escrow_state::check_vault_rent_exempt` is the pure-logic mirror of
    // that check (on-chain: `Rent::get()?.is_exempt(...)`); with mainnet
    // rent parameters the minimum is 4_649_280 lamports.
    #[account(init, payer = initializer, space = escrow_state::VAULT_SPACE)]
    pub vault: Account<'info, Vault>,
    pub taker: SystemAccount<'info>,
    #[account(mut)]
    pub initializer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Fund<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct Release<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: beneficiary of the release; receives the funds.
    pub taker: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account. The real build reads this
    /// account's `mint` and the state machine requires it to equal the
    /// bound `vault.mint` (`MintMismatch` otherwise). Unused on the
    /// native-SOL path — the state machine then requires `None`.
    pub vault_token_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Cancel<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
    /// CHECK: the refund destination account. AV-23: the state machine
    /// pins it against the escrow's refund policy (the whitelisted
    /// address, or the initializer with no whitelist) — a phishing
    /// frontend cannot redirect the refund by swapping this account.
    /// The real build transfers the refund to this account after the
    /// state machine's `RefundAddressMismatch` check passes.
    pub refund_to: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CancelExpired<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker; the state machine enforces
    /// the either-party rule. A constraint in the real build additionally
    /// asserts `authority.key() == vault.initializer || authority.key() == vault.taker`.
    pub authority: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the expiry comparison.
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
    /// CHECK: the refund destination account. AV-23: the state machine
    /// pins it against the escrow's refund policy — even when the taker
    /// is the caller, the refund goes to the declared address, never to
    /// the caller. The real build transfers the refund to this account
    /// after the state machine's `RefundAddressMismatch` check passes.
    pub refund_to: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InitializeQuorum<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer configures the quorum; the state machine
    /// rejects re-configuration once the escrow is funded.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct Attest<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Must be one of the registered attestors; the state machine
    /// rejects anyone else with `Unauthorized`.
    pub attestor: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateQuorum<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// First governance signer: must equal the escrow's initializer.
    /// Both parties must sign — one alone is `Unauthorized`.
    pub initializer: Signer<'info>,
    /// Second governance signer: must equal the escrow's taker.
    pub taker: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeDualSig<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into dual-signature activation; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct Activate<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker; the state machine enforces
    /// the either-party rule and the per-party idempotency. A constraint
    /// in the real build additionally asserts `authority.key() ==
    /// vault.initializer || authority.key() == vault.taker`.
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeVesting<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer fixes the unlock curve; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the taker may pull the vested stream; the state machine
    /// rejects anyone else with `Unauthorized`.
    pub taker: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the vesting curve (never an
    /// instruction param).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InitializeArbiter<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into arbitration; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct Escalate<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker; the state machine enforces
    /// the either-party rule. A constraint in the real build additionally
    /// asserts `authority.key() == vault.initializer || authority.key() ==
    /// vault.taker`.
    pub authority: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the dispute-window check
    /// (never an instruction param — a caller-supplied timestamp could
    /// rewind past the window).
    pub clock: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Resolve<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Must equal the configured arbiter; the state machine rejects
    /// anyone else with `Unauthorized`. A constraint in the real build
    /// additionally asserts `arbiter.key() == vault.arbiter`.
    pub arbiter: Signer<'info>,
    /// CHECK: beneficiary of the taker's share of the split.
    pub taker: AccountInfo<'info>,
    /// CHECK: beneficiary of the initializer's refund share of the split.
    pub initializer: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InitializeMilestones<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer fixes the tranche schedule; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ConfirmMilestone<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker; the state machine enforces
    /// the either-party rule and the per-party idempotency. A constraint
    /// in the real build additionally asserts `authority.key() ==
    /// vault.initializer || authority.key() == vault.taker`.
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReleaseMilestone<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer drives tranche releases; the state machine
    /// enforces the dual-confirmation gate.
    pub initializer: Signer<'info>,
    /// CHECK: beneficiary of the tranche; receives the funds.
    pub taker: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InitializeRefundAddress<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the refund whitelist; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializePenalty<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the anti-griefing penalty rate;
    /// the state machine rejects re-configuration once the escrow
    /// leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct SkipMilestone<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker; the state machine records one
    /// party's skip approval per call and executes the skip only once
    /// both approved. A constraint in the real build additionally asserts
    /// `authority.key() == vault.initializer || authority.key() ==
    /// vault.taker`.
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeMint<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer binds the token mint; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeProtocolFee<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer configures the protocol fee; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeGracePeriod<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer configures the grace period; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`.
    pub initializer: Signer<'info>,
}

// --- Helpers (finalized during the real Anchor build) ---

fn read_escrow(_vault: &Account<Vault>) -> escrow_state::Escrow {
    unimplemented!("deserialize Vault account into escrow_state::Escrow")
}

fn read_clock_unix_timestamp(_clock: &AccountInfo) -> u64 {
    unimplemented!("read Clock::get()?.unix_timestamp as u64 in the real build")
}

/// Read the vault's SPL token account mint for the state machine's
/// `MintMismatch` check (AV-16). Returns `None` on the native-SOL path
/// (no mint bound, no token accounts) — the state machine then requires
/// `vault.mint` to be `None` too.
fn vault_token_mint(_token_account: &AccountInfo) -> Option<[u8; 32]> {
    unimplemented!("read the SPL token account's mint in the real build; None on the native-SOL path")
}

fn write_escrow(_vault: &mut Account<Vault>, _escrow: &escrow_state::Escrow) {
    unimplemented!("serialize escrow_state::Escrow back into the Vault account")
}

/// AV-18: build and `emit!` the indexer event for one state transition,
/// mirroring `escrow_state::EscrowEvent`.
///
/// `from_state` is the vault's state before the transition, `to_state`
/// after; `payout` / `fee` / `refund` carry the fund movements (zeroed
/// when the kind moves nothing); `at` is the clock sysvar's unix
/// timestamp — the on-chain source of the caller-supplied `at` the
/// `IndexedEscrow` wrapper takes off-chain. `seq` is the vault's
/// persisted per-escrow event counter (`read_event_seq`).
/// `evidence_hash` (AV-22) is the dispute-evidence commitment carried by
/// the `Escalated` and `Resolved` events (`None` for every other kind),
/// mirroring `escrow_state::EscrowEvent::evidence_hash`.
fn emit_transition(
    vault: &Account<Vault>,
    kind: escrow_state::EscrowEventKind,
    from_state: u8,
    to_state: u8,
    payout: u64,
    fee: u64,
    refund: u64,
    at: u64,
    evidence_hash: Option<[u8; 32]>,
) {
    emit!(EscrowVaultEvent {
        kind: escrow_event_kind(kind),
        vault: vault.key(),
        seq: read_event_seq(vault),
        from_state,
        to_state,
        payout,
        fee,
        refund,
        at,
        evidence_hash,
    });
}

/// AV-18: read the vault's persisted per-escrow event sequence counter.
/// The real build stores it in the Vault account (appended after
/// `fees_paid`; `VAULT_SPACE` grows 540 → 548) and increments it on
/// every emission, so `seq` stays monotonic across transactions.
fn read_event_seq(_vault: &Account<Vault>) -> u64 {
    unimplemented!("read the vault's persisted event_seq in the real build")
}

fn escrow_error(e: escrow_state::EscrowError) -> Error {
    // One program error per EscrowError variant, so on-chain failures
    // surface the exact `escrow_state` reason (code 100–117) to clients.
    match e {
        escrow_state::EscrowError::Unauthorized => error!(ErrorCode::Unauthorized),
        escrow_state::EscrowError::InvalidStateTransition => {
            error!(ErrorCode::InvalidStateTransition)
        }
        escrow_state::EscrowError::AmountMismatch => error!(ErrorCode::AmountMismatch),
        escrow_state::EscrowError::NotExpired => error!(ErrorCode::NotExpired),
        escrow_state::EscrowError::InvalidQuorum => error!(ErrorCode::InvalidQuorum),
        escrow_state::EscrowError::QuorumNotReached => error!(ErrorCode::QuorumNotReached),
        escrow_state::EscrowError::ReleaseExceedsLocked => {
            error!(ErrorCode::ReleaseExceedsLocked)
        }
        escrow_state::EscrowError::InvalidVesting => error!(ErrorCode::InvalidVesting),
        escrow_state::EscrowError::InvalidArbiter => error!(ErrorCode::InvalidArbiter),
        escrow_state::EscrowError::DisputeWindowClosed => {
            error!(ErrorCode::DisputeWindowClosed)
        }
        escrow_state::EscrowError::InvalidMilestones => error!(ErrorCode::InvalidMilestones),
        escrow_state::EscrowError::MilestoneNotConfirmed => {
            error!(ErrorCode::MilestoneNotConfirmed)
        }
        escrow_state::EscrowError::InvalidMint => error!(ErrorCode::InvalidMint),
        escrow_state::EscrowError::MintMismatch => error!(ErrorCode::MintMismatch),
        escrow_state::EscrowError::InvalidProtocolFee => error!(ErrorCode::InvalidProtocolFee),
        escrow_state::EscrowError::InvalidGracePeriod => error!(ErrorCode::InvalidGracePeriod),
        escrow_state::EscrowError::RefundAddressMismatch => {
            error!(ErrorCode::RefundAddressMismatch)
        },
        escrow_state::EscrowError::InvalidPenalty => error!(ErrorCode::InvalidPenalty),
    }
}

#[error_code]
pub enum ErrorCode {
    #[msg("Caller is not the authority for this transition")]
    Unauthorized,
    #[msg("Transition not allowed from the current state")]
    InvalidStateTransition,
    #[msg("Escrow amount must be greater than zero")]
    AmountMismatch,
    #[msg("cancel_expired called before expires_at")]
    NotExpired,
    #[msg("Invalid quorum policy or no quorum configured")]
    InvalidQuorum,
    #[msg("Release quorum threshold not reached yet")]
    QuorumNotReached,
    #[msg("Cumulative release amount exceeds the locked amount")]
    ReleaseExceedsLocked,
    #[msg("Invalid vesting schedule (start >= end) or claim with no vesting configured")]
    InvalidVesting,
    #[msg("Invalid arbiter (zero key) or no arbiter configured for escalate/resolve")]
    InvalidArbiter,
    #[msg("Dispute window closed: escalate called at or after expires_at")]
    DisputeWindowClosed,
    #[msg("Invalid milestone plan (empty/too many/zero tranche, tranche sum != locked amount), milestone operation with no plan, or release/claim with a milestone plan attached")]
    InvalidMilestones,
    #[msg("release_milestone called before both parties confirmed the milestone")]
    MilestoneNotConfirmed,
    #[msg("Invalid SPL mint address (not base58 / not 32 bytes) or the zero address")]
    InvalidMint,
    #[msg("Token account mint does not match the escrow's bound mint")]
    MintMismatch,
    #[msg("Invalid protocol fee rate: fee_bps must be 0-10000 (basis points)")]
    InvalidProtocolFee,
    #[msg("Invalid grace period: expires_at + grace_period overflows u64 (no grace on a no-timeout escrow)")]
    InvalidGracePeriod,
    #[msg("Refund destination does not match the escrow's refund policy (whitelisted address, or the initializer with no whitelist)")]
    RefundAddressMismatch,
    #[msg("Invalid anti-griefing penalty rate: penalty_bps must be 0-10000 (basis points)")]
    InvalidPenalty,
}
