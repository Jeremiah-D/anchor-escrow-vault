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
//! the tested logic. The optional weighted attestor quorum
//! (`initialize_quorum` / `attest`) gates `release` exactly as the state
//! machine does; the optional linear vesting schedule
//! (`initialize_vesting` / `claim`) lets
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
//! The terminal-state vault close (`close_vault`) reclaims the
//! rent-exempt deposit: once the escrow is `Cancelled`, `Released` or
//! `Settled`, the initializer may close the vault account (Anchor
//! `close` constraint) and recover the lamports it has carried since
//! `initialize` — the escrow moves to `Closed`, the deepest terminal.
//!
//! Reentrancy (AV-36): every fund-moving instruction runs under the
//! state machine's reentrancy guard — `Escrow::release_via_cpi` arms a
//! runtime lock around the injected executor (here: the real
//! `cpi_invoke_target` below), and every fund-moving transition
//! rejects a nested entry with `ReentrantCall` before its authority
//! check. A hostile CPI target that invokes the escrow program again
//! mid-instruction therefore fails closed, and the rejection is
//! visible to indexers as a `ReentryRejected` event.
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
            None,
            None,
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
            None,
            None,
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
        // AV-27: the timelock gate reads the Solana clock sysvar — never
        // an instruction param, so the initializer cannot fast-forward
        // the lock they configured.
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let (payout, fee) = escrow
            .release(
                ctx.accounts.initializer.key().to_bytes(),
                now,
                amount,
                vault_token_mint(&ctx.accounts.vault_token_account),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_payout` (`PayoutKind::Release`) —
        // the transfer instruction bytes are built and validated by
        // `escrow_state::cpi::payout_plan` (amounts/recipients pinned
        // against the state machine); the real build executes the
        // validated plan once the token accounts are wired up.
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
            None,
            None,
            None,
        );
        Ok((payout, fee))
    }

    /// Release `amount` routed through a third-party program via CPI
    /// (AV-35): the taker's payout flows into the target program's
    /// instruction — a DEX swap, a lending-protocol deposit — instead of
    /// moving straight to the taker wallet. The target program is
    /// `ctx.remaining_accounts[0]`; `ctx.remaining_accounts[1..]` are
    /// the target instruction's accounts in its expected order;
    /// `cpi_data` is the target instruction's opaque data. The state
    /// machine (`escrow_state::Escrow::release_via_cpi`) runs the exact
    /// `release` gates, validates the invocation shape, and — on
    /// executor failure — rolls the whole release back, mirroring the
    /// chain's CPI atomicity. The protocol fee still settles to the fee
    /// account through the normal payout path. Returns
    /// `(taker_payout, fee)`; the CPI audit (`cpi_target` +
    /// `cpi_accounts_hash`) rides on the `Released` event.
    pub fn release_via_cpi(
        ctx: Context<ReleaseViaCpi>,
        amount: u64,
        cpi_data: Vec<u8>,
    ) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-27: the timelock gate reads the Solana clock sysvar — never
        // an instruction param.
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        // Build the third-party invocation from the remaining accounts:
        // [0] is the target program, [1..] its instruction accounts.
        let invocation = cpi_invocation_from_remaining_accounts(
            ctx.remaining_accounts,
            cpi_data,
        )?;
        let (payout, fee, receipt) = escrow
            .release_via_cpi(
                ctx.accounts.initializer.key().to_bytes(),
                now,
                amount,
                vault_token_mint(&ctx.accounts.vault_token_account),
                &invocation,
                // The execution seam: the real build invokes the target
                // program here via `cpi_invoke_target` below. A failed
                // invoke aborts the transaction, so no state change
                // persists — the state machine's rollback models exactly
                // this. AV-36: the state machine arms its reentrancy
                // lock around this closure (see
                // `escrow_state::Escrow::release_via_cpi`), so a hostile
                // target that CPIs back into this program mid-invoke is
                // rejected with `ReentrantCall` (`ErrorCode::ReentrantCall`)
                // before its authority check — the outer release is
                // unaffected and the rejection emits a `ReentryRejected`
                // indexer event.
                |inv| cpi_invoke_target(&ctx, inv),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `payout + fee` is the gross amount (== the `amount`
        // param); partial releases carry from == to == Funded, the
        // closing one to == Released. AV-35: the Released event carries
        // the CPI audit so the indexer pins the authorized instruction.
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
            None,
            Some(receipt.cpi_target),
            Some(receipt.accounts_hash),
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
        // AV-31: settle via `cpi_settle_refund` (`RefundKind::Cancel`) —
        // `escrow_state::cpi::refund_plan` builds and validates the
        // refund transfer bytes against the AV-23-pinned `refund_to`;
        // the real build executes the validated plan once the token
        // accounts are wired up.
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
            None,
            None,
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
        // AV-31: settle via `cpi_settle_refund` (`RefundKind::CancelExpired`) —
        // `escrow_state::cpi::refund_plan` builds and validates the
        // transfer bytes: `refund` to the AV-23-pinned `refund_to`,
        // `penalty` (non-zero only on a taker-initiated cancel, AV-24)
        // to the initializer. The real build executes the validated
        // plan once the token accounts are wired up.
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
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Attach a weighted attestor quorum to the release path
    /// (`Uninitialized` only; mirrors `Escrow::with_quorum`). After
    /// this, `release` additionally requires the accumulated weight of
    /// distinct attestations to reach `threshold`; the refund paths
    /// (`cancel` / `cancel_expired`) stay quorum-free by design.
    pub fn initialize_quorum(
        ctx: Context<InitializeQuorum>,
        attestors: Vec<Pubkey>,
        weights: Vec<u64>,
        threshold: u64,
    ) -> Result<()> {
        let keys: Vec<[u8; 32]> = attestors.iter().map(|k| k.to_bytes()).collect();
        let policy =
            escrow_state::QuorumPolicy::new(&keys, &weights, threshold).map_err(|e| escrow_error(e))?;
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
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Adjust the quorum's weight-sum threshold by dual-signed
    /// governance (AV-25; mirrors `Escrow::update_quorum`). Both the
    /// initializer and the taker must sign — one party alone cannot
    /// weaken the gate. Allowed on `Uninitialized` or `Funded` escrows;
    /// `0` or above the total registered weight is `InvalidQuorum`, as
    /// is calling with no quorum configured. The attestor set, their
    /// weights, and existing attestations are untouched — only the
    /// threshold moves, in place, so the account needs no realloc.
    /// Emits `QuorumUpdated` when the threshold actually changes (a
    /// no-op re-affirmation emits nothing), mirroring
    /// `IndexedEscrow::update_quorum`.
    pub fn update_quorum(ctx: Context<UpdateQuorum>, threshold: u64) -> Result<()> {
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
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Replace the quorum's attestor set by dual-signed governance
    /// (AV-39; mirrors `Escrow::update_attestors`). Both the
    /// initializer and the taker must sign — one party alone cannot
    /// reshape the electorate into sockpuppets (a unilateral weakening
    /// of the release gate). Allowed on `Uninitialized` or `Funded`
    /// escrows; no quorum configured, an empty set, more than 8 keys,
    /// a duplicate key, a weight/length mismatch, a zero weight, or a
    /// weight-sum threshold that no longer fits the new total weight is
    /// `InvalidQuorum`. The set compacts into the already-reserved 8
    /// slots in place, so the account needs no realloc. Approval bits
    /// remap by pubkey: retained attestors keep their votes (at the new
    /// weights), removed attestors lose theirs. Emits `AttestorsUpdated`
    /// when the set actually changes (a no-op same-set update emits
    /// nothing), mirroring `IndexedEscrow::update_attestors`.
    pub fn update_attestors(
        ctx: Context<UpdateAttestors>,
        attestors: Vec<Pubkey>,
        weights: Vec<u64>,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let set_before: Vec<([u8; 32], u64)> = escrow
            .quorum()
            .map(|q| {
                q.attestors()
                    .iter()
                    .zip(q.weights().iter())
                    .map(|(a, w)| (*a, *w))
                    .collect()
            })
            .unwrap_or_default();
        escrow
            .update_attestors(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
                &attestors
                    .iter()
                    .map(|a| a.to_bytes())
                    .collect::<Vec<[u8; 32]>>(),
                &weights,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Rewrite `vault.quorum.attestors` / `vault.quorum.weights` in the
        // real build (in place — the quorum region is always reserved),
        // with the approval bitmask remapped by pubkey exactly as the
        // state machine does.
        let set_after: Vec<([u8; 32], u64)> = escrow
            .quorum()
            .map(|q| {
                q.attestors()
                    .iter()
                    .zip(q.weights().iter())
                    .map(|(a, w)| (*a, *w))
                    .collect()
            })
            .unwrap_or_default();
        if set_after != set_before {
            let state = escrow.state() as u8;
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::AttestorsUpdated,
                state,
                state,
                0,
                0,
                0,
                Clock::get()?.unix_timestamp as u64,
                None,
                None,
                None,
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
                None,
                None,
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
        // AV-31: settle via `cpi_settle_payout` (`PayoutKind::Claim`) —
        // see `release`: `escrow_state::cpi::payout_plan` builds and
        // validates the transfer bytes, the real build executes them.
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
            None,
            None,
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
            None,
            None,
            None,
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
    /// AV-38: `rationale_hash` is the arbiter's optional 32-byte
    /// commitment to the off-chain rationale document behind the ruling
    /// (e.g. the SHA-256 of the written arbitration report), persisted
    /// on the vault (`vault.rationale_hash`) and carried by the
    /// `Resolved` event; `None` attaches no rationale (backward
    /// compatible). Never cleared — `Settled` keeps it as the audit
    /// trail of the arbitration, following the AV-22 `evidence_hash`
    /// convention.
    pub fn resolve(
        ctx: Context<Resolve>,
        taker_amount: u64,
        rationale_hash: Option<[u8; 32]>,
    ) -> Result<(u64, u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let (payout, fee, refund) = escrow
            .resolve(
                ctx.accounts.arbiter.key().to_bytes(),
                taker_amount,
                vault_token_mint(&ctx.accounts.vault_token_account),
                rationale_hash,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_resolve` —
        // `escrow_state::cpi::resolve_plan` builds and validates the
        // three-leg transfer bytes (taker payout / protocol fee /
        // initializer refund); the real build executes the validated
        // plan once the token accounts are wired up.
        // AV-18: `taker_amount` is the gross taker share
        // (`payout + fee`); the refund is never fee'd.
        // AV-22: the Resolved event carries the dispute evidence hash
        // the escrow still holds — the settlement references the
        // evidence the arbiter reviewed.
        // AV-38: the Resolved event carries the rationale-document
        // commitment the arbiter attached — the settlement references
        // the ruling it wrote.
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
            rationale_hash,
            None,
            None,
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
                None,
                None,
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
        // AV-27: the timelock gate reads the Solana clock sysvar (see
        // `release`).
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let (payout, fee) = escrow
            .release_milestone(
                ctx.accounts.initializer.key().to_bytes(),
                now,
                index,
                vault_token_mint(&ctx.accounts.vault_token_account),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_payout`
        // (`PayoutKind::MilestoneRelease`) — see `release`.
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
            None,
            None,
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
                None,
                None,
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

    /// Declare the timelock (AV-27; mirrors `Escrow::with_timelock`):
    /// after this, `release` / `claim` / `release_milestone` require the
    /// Solana clock to have passed `unlock_at` (`TimelockNotReached`
    /// otherwise). `unlock_at == 0` means no lock (the default).
    /// `Uninitialized` only. `cancel` / `cancel_expired` / `resolve` are
    /// deliberately NOT gated, so a misconfigured lock can never trap
    /// funds forever.
    pub fn initialize_timelock(ctx: Context<InitializeTimelock>, unlock_at: u64) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_timelock(unlock_at)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.timelock` is always present (8 bytes, zeroed by
        // default), so the timestamp is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Declare the token decimal metadata (AV-28; mirrors
    /// `Escrow::with_decimals`): the SPL mint's decimal places, used
    /// only to render human-readable amounts in the keeper report and
    /// the AV-26 snapshot export — it never gates a transition and never
    /// moves funds. `decimals > 18` is `InvalidDecimals` (the largest
    /// precision any SPL/EVM token convention needs; SPL mints declare
    /// at most 9). `decimals == 0` means no decimal metadata (the
    /// default — amounts render as bare integers). `Uninitialized` only.
    pub fn initialize_decimals(ctx: Context<InitializeDecimals>, decimals: u8) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_decimals(decimals)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.decimals` is always present (1 byte, zeroed by
        // default), so the precision is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Opt in to emergency timelock-unlock governance (AV-41; mirrors
    /// `Escrow::with_emergency_unlock`). `Uninitialized` only, like
    /// `initialize_quorum`. After this, `emergency_unlock` may clear the
    /// AV-27 timelock by mutual agreement.
    pub fn initialize_emergency_unlock(ctx: Context<InitializeEmergencyUnlock>) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_emergency_unlock().map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Sets the opt-in byte in `vault.emergency_unlock` in the real
        // build (always present, 1 byte, zeroed by default — no realloc).
        Ok(())
    }

    /// Declare the protocol-fee recipient (AV-44; mirrors
    /// `Escrow::with_fee_recipient`): after this, every fee leg the
    /// AV-17 fee rate charges must go to `fee_recipient`
    /// (`RecipientMismatch` on a swapped destination in the settlement
    /// plan) — a fee cannot be silently redirected. With no pinned
    /// recipient the fee legs route to the program-level fee account.
    /// `Uninitialized` only; the zero address is `InvalidFeeRecipient`.
    pub fn initialize_fee_recipient(
        ctx: Context<InitializeFeeRecipient>,
        fee_recipient: Pubkey,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_fee_recipient(fee_recipient.to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.fee_recipient` is always present (33 bytes, zeroed by
        // default), so the address is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Bind the emergency-pause authority (AV-46; mirrors
    /// `Escrow::with_pause_authority`): after this, the bound key may
    /// engage / release the circuit breaker via `pause` / `unpause`.
    /// `Uninitialized` only; the zero address is `InvalidPauseAuthority`.
    pub fn initialize_pause_authority(
        ctx: Context<InitializePauseAuthority>,
        pause_authority: Pubkey,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_pause_authority(pause_authority.to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.pause_authority` is always present (33 bytes, zeroed by
        // default), so the address is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Engage the emergency pause (AV-46; mirrors `Escrow::pause`).
    /// While paused, every state-changing transition fails with `Paused`
    /// (code 124) — the circuit breaker. Only the bound pause authority
    /// may call this (`Unauthorized` otherwise); without an opted-in
    /// authority the switch does not exist (`InvalidStateTransition`).
    /// Emits `Paused` (from == to == the current state).
    pub fn pause(ctx: Context<Pause>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        escrow
            .pause(ctx.accounts.pause_authority.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flips `vault.paused` in place in the real build (1 byte,
        // always present, zeroed by default).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Paused,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Release the emergency pause (AV-46; mirrors `Escrow::unpause`).
    /// Same authority rules as `pause`; unpausing a non-paused escrow is
    /// `InvalidStateTransition` (strict toggle). State-changing
    /// transitions work again. Emits `Unpaused` (from == to == the
    /// current state).
    pub fn unpause(ctx: Context<Unpause>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        escrow
            .unpause(ctx.accounts.pause_authority.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flips `vault.paused` back in place in the real build.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Unpaused,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Clear the AV-27 timelock by dual-signed emergency governance
    /// (AV-41; mirrors `Escrow::emergency_unlock`). Both the initializer
    /// and the taker must sign — one party alone is `Unauthorized`.
    /// `Funded` only, and only when the governance was opted in and an
    /// active timelock exists (`InvalidStateTransition` otherwise). The
    /// timelock clears to 0 immediately; state and amounts are
    /// untouched. Emits `EmergencyUnlock` (from == to == the current
    /// state), mirroring `IndexedEscrow::emergency_unlock`.
    pub fn emergency_unlock(ctx: Context<EmergencyUnlock>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        escrow
            .emergency_unlock(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Clears `vault.timelock` to 0 in the real build (in place — the
        // 8-byte region is always reserved).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::EmergencyUnlock,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Close the vault account and reclaim the rent-exempt deposit
    /// (`Cancelled | Released | Settled -> Closed`; mirrors
    /// `Escrow::close_vault`). Only the initializer may call this —
    /// the state machine checks authority before state validity
    /// (`Unauthorized` otherwise, so strangers learn nothing about
    /// state); only a terminal vault may be closed
    /// (`InvalidStateTransition` otherwise — `Disputed` is not a
    /// terminal state, and `Closed` is the deepest terminal, so a
    /// second close fails too).
    ///
    /// Solana rent economics: the vault account has carried the
    /// rent-exempt minimum for `escrow_state::VAULT_SPACE` since
    /// `initialize` (see `escrow_state::check_vault_rent_exempt`); once
    /// the escrow reached a terminal state the account serves no
    /// purpose, but the lamports stay locked until the account closes.
    /// The state machine returns the reclaimed amount
    /// (`escrow_state::vault_close_rent_reclaimed`); in the real build
    /// the account itself closes through Anchor's `close` constraint on
    /// `CloseVault` — the runtime transfers the account's lamports
    /// (including the rent-exempt deposit) to the initializer and zeroes
    /// the account, so no explicit system-program CPI is needed.
    /// AV-18: emits `VaultClosed` with `from` the terminal state and
    /// `to == Closed`. The real build's `EscrowVaultEvent` gains a
    /// `rent_reclaimed` amounts field mirroring
    /// `escrow_state::EventAmounts::rent_reclaimed` (carrying the
    /// returned amount); the skeleton's `emit_transition` keeps its
    /// current shape until the real build wires the event struct.
    pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // The reclaimed rent-exempt lamports
        // (`escrow_state::vault_close_rent_reclaimed`): the real build's
        // account-close transfers the account's lamports to
        // `accounts.initializer` via the `close` constraint on
        // `CloseVault` — the state machine moves no funds itself.
        let _rent = escrow
            .close_vault(ctx.accounts.initializer.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::VaultClosed,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
        );
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
    /// AV-27: timelock unlock timestamp; mirrors `escrow_state`'s
    /// `timelock`. `0` for an escrow with no timelock configured.
    /// Always present (8 bytes, zeroed by default) so
    /// `initialize_timelock` writes the timestamp in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `penalty_bps`).
    pub timelock: u64,
    /// AV-28: token decimal metadata; mirrors `escrow_state`'s
    /// `decimals` (the SPL mint's decimal places, `0` = no decimal
    /// metadata). Always present (1 byte, zeroed by default) so
    /// `initialize_decimals` writes the precision in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `timelock`).
    /// Display-only: it never gates a transition and never moves funds.
    pub decimals: u8,
    /// AV-38: 32-byte commitment to the arbiter's off-chain rationale
    /// document (e.g. the SHA-256 of the written ruling), attached at
    /// `resolve`; mirrors `escrow_state`'s `rationale_hash`. `None`
    /// when the arbiter supplied no rationale. The account always
    /// reserves the full 33-byte region (1-byte discriminant + 32-byte
    /// commitment, zeroed when `None`) so `resolve` writes the hash in
    /// place without reallocating; never cleared — it stays on the
    /// vault in `Settled` as the audit trail of the arbitration,
    /// following the AV-22 `evidence_hash` convention. Layout position
    /// matches `escrow_state::VAULT_FIELDS` (appended last, after
    /// `decimals`).
    pub rationale_hash: Option<[u8; 32]>,
    /// AV-41: emergency timelock-unlock governance opt-in; mirrors
    /// `escrow_state`'s `emergency_unlock`. `false` for an escrow without
    /// the governance capability. Always present (1 byte, zeroed by
    /// default) so `initialize_emergency_unlock` writes the flag in
    /// place without reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `rationale_hash`).
    pub emergency_unlock: bool,
    /// AV-44: opt-in protocol-fee recipient; mirrors
    /// `escrow_state`'s `fee_recipient`. `None` for an escrow with no
    /// pinned recipient (fee legs route to the program-level fee
    /// account). The account always reserves the full 33-byte region
    /// (1-byte discriminant + 32-byte address, zeroed when `None`) so
    /// `initialize_fee_recipient` writes the address in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `emergency_unlock`).
    pub fee_recipient: Option<Pubkey>,
    /// AV-46: opt-in emergency-pause authority; mirrors
    /// `escrow_state`'s `pause_authority`. `None` for an escrow with no
    /// pause switch. The account always reserves the full 33-byte region
    /// (1-byte discriminant + 32-byte address, zeroed when `None`) so
    /// `initialize_pause_authority` writes the address in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `fee_recipient`).
    pub pause_authority: Option<Pubkey>,
    /// AV-46: emergency pause flag; mirrors `escrow_state`'s `paused`.
    /// `false` for a live escrow. Always present (1 byte, zeroed by
    /// default) so `pause` / `unpause` flip it in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `pause_authority`).
    pub paused: bool,
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
/// Skeleton mirror of `escrow_state::QuorumPolicy`: up to
/// `escrow_state::MAX_ATTESTORS` attestor keys in slot order, the
/// parallel per-attestor vote weights (AV-45), the registered count,
/// the u64 weight-sum release threshold, and the approval bitmask.
/// See the state machine docs for the weighted attestation /
/// release-gate semantics. Serialized size is pinned by
/// `escrow_state::QUORUM_POLICY_LEN`; the AV-04/AV-45 tests assert it
/// against a manual encoding.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct Quorum {
    pub attestors: [Pubkey; 8],
    /// Per-attestor vote weight, in slot order (parallel to
    /// `attestors`); mirrors `escrow_state::QuorumPolicy` (AV-45).
    pub weights: [u64; 8],
    pub registered: u8,
    /// Weight-sum release threshold; mirrors
    /// `escrow_state::QuorumPolicy::threshold` (AV-45).
    pub threshold: u64,
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
    /// AV-38: the arbiter's rationale-document commitment carried by
    /// the `Resolved` event (`None` for every other kind); mirrors
    /// `escrow_state::EscrowEvent::rationale_hash`, so an off-chain
    /// indexer learns the ruling reference from the event stream
    /// without a second account read.
    pub rationale_hash: Option<[u8; 32]>,
    /// AV-35: the third-party program a CPI-routed release invoked
    /// (`release_via_cpi`); `None` on every other kind. Mirrors
    /// `escrow_state::EscrowEvent::cpi.target`.
    pub cpi_target: Option<Pubkey>,
    /// AV-35: SHA-256 over the canonical encoding of the exact
    /// instruction the CPI-routed release authorized (program id +
    /// accounts + data; see `escrow_state::cpi_accounts_hash`); `None`
    /// on every other kind. Mirrors
    /// `escrow_state::EscrowEvent::cpi.accounts_hash`.
    pub cpi_accounts_hash: Option<[u8; 32]>,
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
    /// AV-25: the quorum's attestation threshold changed by dual-signed
    /// governance (`Escrow::update_quorum`). Mirrors
    /// `escrow_state::EscrowEventKind::QuorumUpdated`.
    QuorumUpdated,
    /// AV-39: the quorum's attestor set changed by dual-signed
    /// governance (`Escrow::update_attestors`). Mirrors
    /// `escrow_state::EscrowEventKind::AttestorsUpdated`.
    AttestorsUpdated,
    /// AV-36: a fund-moving transition was rejected as a reentrant call
    /// (`EscrowError::ReentrantCall`). Mirrors
    /// `escrow_state::EscrowEventKind::ReentryRejected`.
    ReentryRejected,
    /// AV-46: the emergency pause was engaged (`Escrow::pause`).
    /// Mirrors `escrow_state::EscrowEventKind::Paused`.
    Paused,
    /// AV-46: the emergency pause was released (`Escrow::unpause`).
    /// Mirrors `escrow_state::EscrowEventKind::Unpaused`.
    Unpaused,
    /// AV-34: the vault account was closed by the initializer and its
    /// rent-exempt deposit reclaimed (`Cancelled | Released | Settled ->
    /// Closed`).
    VaultClosed,
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
        escrow_state::EscrowEventKind::QuorumUpdated => EscrowVaultEventKind::QuorumUpdated,
        escrow_state::EscrowEventKind::AttestorsUpdated => {
            EscrowVaultEventKind::AttestorsUpdated
        }
        escrow_state::EscrowEventKind::ReentryRejected => {
            EscrowVaultEventKind::ReentryRejected
        }
        escrow_state::EscrowEventKind::Paused => EscrowVaultEventKind::Paused,
        escrow_state::EscrowEventKind::Unpaused => EscrowVaultEventKind::Unpaused,
        escrow_state::EscrowEventKind::VaultClosed => EscrowVaultEventKind::VaultClosed,
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    // Full vault space: 8-byte discriminator + 755-byte payload = 763
    // bytes (see `escrow_state::VAULT_SPACE`; AV-12 added the 1-byte
    // activation bitmask, AV-13 the 17-byte vesting region, AV-14 the
    // 33-byte arbiter region, AV-15 the 66-byte milestone plan + the
    // 8-byte confirmation bitmap + the 8-byte skipped counter, AV-16 the
    // 33-byte mint region, AV-17 the 2-byte fee rate + the 8-byte
    // cumulative fee counter, AV-21 the 8-byte grace period, AV-22 the
    // 33-byte evidence hash region, AV-23 the 33-byte refund whitelist
    // region, AV-24 the 2-byte penalty rate, AV-27 the 8-byte timelock,
    // AV-28 the 1-byte decimals metadata, AV-38 the 33-byte rationale
    // hash region, AV-41 the 1-byte emergency-unlock flag, AV-44 the
    // 33-byte fee-recipient region, AV-45 the 64-byte quorum weight
    // array + the 7-byte wider weight-sum threshold).
    // The payer must fund at least the rent-exempt minimum for this space
    // — `escrow_state::check_vault_rent_exempt` is the pure-logic mirror of
    // that check (on-chain: `Rent::get()?.is_exempt(...)`); with mainnet
    // rent parameters the minimum is 6_201_360 lamports.
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
    /// CHECK: Solana clock sysvar, read for the AV-27 timelock gate
    /// (never an instruction param — a caller-supplied timestamp would
    /// let the initializer fast-forward the lock).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account. The real build reads this
    /// account's `mint` and the state machine requires it to equal the
    /// bound `vault.mint` (`MintMismatch` otherwise). Unused on the
    /// native-SOL path — the state machine then requires `None`.
    pub vault_token_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ReleaseViaCpi<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: beneficiary of the release on the plain path; on the
    /// CPI-routed path the payout flows into the target program's
    /// instruction instead. Kept as a named account so the IDL stays
    /// explicit about who the release is for.
    pub taker: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the AV-27 timelock gate
    /// (never an instruction param).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`).
    pub vault_token_account: AccountInfo<'info>,
    // The target program and its instruction accounts travel as
    // `remaining_accounts`: `[0]` is the third-party program id,
    // `[1..]` are the target instruction's accounts in its expected
    // order. Anchor validates nothing about them — the state machine
    // validates the invocation shape (`InvalidCpiTarget`) and the
    // `Released` event's CPI audit pins the exact authorized bytes.
    // AV-36: the real invoke below runs with the state machine's
    // reentrancy lock armed (see `escrow_state::Escrow::release_via_cpi`):
    // if the target program CPIs back into any fund-moving instruction
    // of this program mid-invoke, the nested entry is rejected with
    // `ErrorCode::ReentrantCall` and the outer release completes
    // normally. The lock is process-memory only — it is not part of
    // the vault account layout (`VAULT_FIELDS` unchanged).
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
pub struct UpdateAttestors<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// First governance signer: must equal the escrow's initializer.
    /// Both parties must sign — one alone is `Unauthorized`, so no
    /// party can unilaterally reshape the attestor electorate.
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
    /// CHECK: Solana clock sysvar, read for the AV-27 timelock gate
    /// (never an instruction param — see `Release`).
    pub clock: AccountInfo<'info>,
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
pub struct InitializeTimelock<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the timelock; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeDecimals<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the token decimal metadata; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeEmergencyUnlock<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into emergency timelock-unlock
    /// governance; the state machine rejects re-configuration once the
    /// escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeFeeRecipient<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer pins the protocol-fee recipient; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, and rejects the zero address.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializePauseAuthority<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer binds the emergency-pause authority; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, and rejects the zero address.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct Pause<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The bound pause authority; the state machine checks it against
    /// the opted-in address (`Unauthorized` for anyone else, and the
    /// switch must exist).
    pub pause_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Unpause<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The bound pause authority (same rules as `Pause`).
    pub pause_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct EmergencyUnlock<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// First governance signer: must equal the escrow's initializer.
    /// Both parties must sign — one alone is `Unauthorized`.
    pub initializer: Signer<'info>,
    /// Second governance signer: must equal the escrow's taker.
    pub taker: Signer<'info>,
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

#[derive(Accounts)]
pub struct CloseVault<'info> {
    /// The vault closes through Anchor's `close` constraint: the runtime
    /// transfers the account's lamports — including the rent-exempt
    /// deposit (`escrow_state::vault_close_rent_reclaimed`, the same
    /// figure `initialize` demanded via
    /// `escrow_state::check_vault_rent_exempt`) — to `initializer` and
    /// zeroes the account. `close` implies `mut`. In the real build this
    /// is the account-close CPI: no explicit system-program instruction
    /// is needed beyond the constraint.
    #[account(mut, close = initializer)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer closes the vault; the state machine
    /// additionally checks authority before state validity
    /// (`Unauthorized` otherwise). A constraint in the real build
    /// asserts `initializer.key() == vault.initializer`.
    #[account(mut)]
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
/// `rationale_hash` (AV-38) is the arbiter's rationale-document
/// commitment carried by the `Resolved` event (`None` for every other
/// kind), mirroring `escrow_state::EscrowEvent::rationale_hash`.
/// `cpi_target` / `cpi_accounts_hash` (AV-35) carry the CPI-routing
/// audit on a `Released` event whose payout flowed through a
/// third-party program (`None` on every other kind), mirroring
/// `escrow_state::EscrowEvent::cpi`.
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
    rationale_hash: Option<[u8; 32]>,
    cpi_target: Option<Pubkey>,
    cpi_accounts_hash: Option<[u8; 32]>,
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
        rationale_hash,
        cpi_target,
        cpi_accounts_hash,
    });
}

/// AV-18: read the vault's persisted per-escrow event sequence counter.
/// The real build stores it in the Vault account (appended after
/// `fees_paid`; `VAULT_SPACE` grows 540 → 548) and increments it on
/// every emission, so `seq` stays monotonic across transactions.
fn read_event_seq(_vault: &Account<Vault>) -> u64 {
    unimplemented!("read the vault's persisted event_seq in the real build")
}

/// AV-31: settlement CPI wiring (reference — not compiled by CI).
///
/// AV-35: third-party CPI invocation for `release_via_cpi` (reference —
/// not compiled by CI).
///
/// The target program id is `remaining_accounts[0]`; the rest are the
/// target instruction's accounts in its expected order. The state
/// machine validates the invocation shape (`InvalidCpiTarget`) before
/// settling; the real build then invokes the target program with the
/// vault PDA as signer:
///
/// ```ignore
/// let ix = anchor_lang::solana_program::instruction::Instruction {
///     program_id: invocation.program_id,
///     accounts: invocation.accounts.iter().map(|m| AccountMeta {
///         pubkey: m.pubkey,
///         is_signer: m.is_signer,
///         is_writable: m.is_writable,
///     }).collect(),
///     data: invocation.data.clone(),
/// };
/// // The vault PDA signs through `invoke_signed` with the vault seeds,
/// // exactly like the AV-31 settlement CPIs.
/// anchor_lang::solana_program::program::invoke_signed(
///     &ix,
///     &ctx.remaining_accounts,
///     &[&vault_seeds],
/// )?;
/// ```
///
/// A failed invoke aborts the transaction: no state change persists.
/// That is the on-chain atomicity the state machine's rollback
/// (`CpiExecutionFailed`) models in pure logic.
fn cpi_invocation_from_remaining_accounts(
    remaining: &[AccountInfo],
    data: Vec<u8>,
) -> Result<escrow_state::CpiInvocation> {
    let (program, accounts) = remaining.split_first().ok_or(error!(ErrorCode::InvalidCpiTarget))?;
    Ok(escrow_state::CpiInvocation {
        program_id: program.key().to_bytes(),
        accounts: accounts
            .iter()
            .map(|a| escrow_state::AccountMeta {
                pubkey: a.key().to_bytes(),
                is_signer: a.is_signer,
                is_writable: a.is_writable,
            })
            .collect(),
        data,
    })
}

/// AV-35: invoke the third-party program (reference — not compiled by
/// CI). The real build performs the `invoke_signed` sketched above,
/// with the vault PDA signing through the vault seeds. Any invoke
/// failure surfaces here and — via the state machine's executor seam —
/// rolls the whole release back (`CpiExecutionFailed`); the caller
/// observes the chain abort the transaction instead.
fn cpi_invoke_target(
    _ctx: &Context<ReleaseViaCpi>,
    _invocation: &escrow_state::CpiInvocation,
) -> std::result::Result<(), escrow_state::CpiError> {
    unimplemented!("invoke the target program via CPI with the vault PDA as signer in the real build")
}

/// AV-31: settlement CPI wiring (reference — not compiled by CI).
///
/// The fund-moving instructions (`release`, `claim`, `release_milestone`,
/// `cancel`, `cancel_expired`, `resolve`) compute amounts through the
/// pure-logic state machine and then move lamports/tokens with CPI calls.
/// The transfer *instruction bytes* are constructed and validated off-chain
/// by `escrow_state::cpi` (zero dependencies, fully unit-tested):
///
/// - `cpi::system_transfer` / `cpi::spl_token_transfer` assemble the exact
///   account metas and data bytes (System `Transfer` = u32 index 2 ||
///   u64 LE; SPL Token `Transfer` = u8 index 3 || u64 LE);
/// - `cpi::payout_plan` / `cpi::refund_plan` / `cpi::resolve_plan` take the
///   escrow *after* the transition plus the amounts the transition
///   returned, and reject tampered amounts (`SettlementMismatch`) and
///   swapped recipients (`RecipientMismatch`) before any instruction is
///   built.
///
/// The real build only *executes* a validated plan:
/// 1. assemble the `*Addrs` from the instruction's accounts (vault PDA /
///    vault token account as `source`, vault PDA as `vault_authority`,
///    taker/initializer/refund/fee accounts as the legs);
/// 2. call the matching `cpi::*_plan` — a `CpiError` maps to the program
///    error below and aborts before any lamport moves;
/// 3. execute each `TransferInstruction`: native-SOL legs via
///    `solana_program::program::invoke` against the System Program (the
///    vault PDA signs through `invoke_signed` with the vault seeds), SPL
///    legs via `anchor_spl::token::transfer` CPI.
///
/// Because the program never hand-rolls instruction bytes, the on-chain
/// code cannot drift from the byte layout pinned by the `escrow-state`
/// unit tests; the IDL mapping tests pin which instruction maps to which
/// plan kind.
fn cpi_settle_payout(
    _vault: &Account<Vault>,
    _escrow: &escrow_state::Escrow,
    _kind: escrow_state::PayoutKind,
    _payout: u64,
    _fee: u64,
) {
    unimplemented!(
        "real build: escrow_state::cpi::payout_plan, then one CPI per leg \
         (invoke/invoke_signed for native SOL, anchor_spl::token::transfer for SPL)"
    )
}

/// AV-31: reference wiring for `cancel` / `cancel_expired` settlements.
/// See [`cpi_settle_payout`] for the build-then-execute flow; the plan
/// kind is `cpi::RefundKind::Cancel` / `CancelExpired`, the refund leg
/// targets the AV-23-pinned `refund_to`, and the penalty leg (taker-
/// initiated expiry cancels only, AV-24) targets the initializer.
fn cpi_settle_refund(
    _vault: &Account<Vault>,
    _escrow: &escrow_state::Escrow,
    _kind: escrow_state::RefundKind,
    _refund: u64,
    _penalty: u64,
) {
    unimplemented!(
        "real build: escrow_state::cpi::refund_plan, then one CPI per leg \
         (invoke/invoke_signed for native SOL, anchor_spl::token::transfer for SPL)"
    )
}

/// AV-31: reference wiring for the `resolve` three-way split. The plan
/// kind is implicit (resolve is the only three-leg settlement): taker
/// payout leg, protocol-fee leg, initializer-refund leg — see
/// [`cpi_settle_payout`] for the build-then-execute flow.
fn cpi_settle_resolve(
    _vault: &Account<Vault>,
    _escrow: &escrow_state::Escrow,
    _taker_payout: u64,
    _fee: u64,
    _refund: u64,
) {
    unimplemented!(
        "real build: escrow_state::cpi::resolve_plan, then one CPI per leg \
         (invoke/invoke_signed for native SOL, anchor_spl::token::transfer for SPL)"
    )
}

fn escrow_error(e: escrow_state::EscrowError) -> Error {    // One program error per EscrowError variant, so on-chain failures
    // surface the exact `escrow_state` reason (code 100–118) to clients.
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
        escrow_state::EscrowError::TimelockNotReached => error!(ErrorCode::TimelockNotReached),
        escrow_state::EscrowError::InvalidDecimals => error!(ErrorCode::InvalidDecimals),
        escrow_state::EscrowError::InvalidCpiTarget => error!(ErrorCode::InvalidCpiTarget),
        escrow_state::EscrowError::CpiExecutionFailed => error!(ErrorCode::CpiExecutionFailed),
        escrow_state::EscrowError::ReentrantCall => error!(ErrorCode::ReentrantCall),
        escrow_state::EscrowError::InvalidFeeRecipient => error!(ErrorCode::InvalidFeeRecipient),
        escrow_state::EscrowError::Paused => error!(ErrorCode::Paused),
        escrow_state::EscrowError::InvalidPauseAuthority => error!(ErrorCode::InvalidPauseAuthority),
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
    #[msg("Timelock not reached: release/claim/release_milestone called before unlock_at")]
    TimelockNotReached,
    #[msg("Invalid token decimals: with_decimals decimals must be 0-18")]
    InvalidDecimals,
    #[msg("Invalid CPI target: release_via_cpi with a zero program id, an empty account list, or a zero account key")]
    InvalidCpiTarget,
    #[msg("CPI execution failed: the third-party invoke failed after the release gates passed; the whole release was rolled back")]
    CpiExecutionFailed,
    #[msg("Reentrant call rejected: a fund-moving transition was entered while the AV-36 reentrancy lock was held (nested entry from inside release_via_cpi's executor window)")]
    ReentrantCall,
    #[msg("Invalid protocol-fee recipient: with_fee_recipient with the zero address (a zero address can never be the legitimate fee destination)")]
    InvalidFeeRecipient,
    #[msg("Emergency pause engaged: a state-changing transition was attempted while the AV-46 pause flag is set; only the pause authority's unpause re-enables transitions")]
    Paused,
    #[msg("Invalid pause authority: with_pause_authority with the zero address (a zero address can never hold the emergency switch)")]
    InvalidPauseAuthority,
}
