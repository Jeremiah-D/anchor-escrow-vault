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
//! the taker pull the vested stream exactly as `Escrow::claim` defines.
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
        Ok(())
    }

    /// Lock funds into the vault (`Uninitialized -> Funded`).
    pub fn fund(ctx: Context<Fund>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        escrow
            .fund(ctx.accounts.initializer.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Release `amount` of the locked funds to the taker. Partial releases
    /// accumulate in `vault.released` and leave the escrow `Funded`; when
    /// the cumulative released total reaches the locked amount the escrow
    /// becomes `Released`. Cumulative releases must not exceed the locked
    /// amount (`ReleaseExceedsLocked`); `amount == 0` is `AmountMismatch`.
    /// The AV-04 quorum gate applies exactly as the state machine defines.
    pub fn release(ctx: Context<Release>, amount: u64) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        escrow
            .release(ctx.accounts.initializer.key().to_bytes(), amount)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Transfer of lamports/tokens to `ctx.accounts.taker` goes here
        // once real token accounts are wired up.
        Ok(())
    }

    /// Cancel the escrow and return funds (`Funded -> Cancelled`).
    pub fn cancel(ctx: Context<Cancel>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        escrow
            .cancel(ctx.accounts.initializer.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Cancel an expired escrow (`Funded -> Cancelled`). Either the
    /// initializer or the taker may call this once the clock (Solana
    /// clock sysvar in the real build) has passed `expires_at`.
    pub fn cancel_expired(ctx: Context<CancelExpired>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        escrow
            .cancel_expired(ctx.accounts.authority.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Refund of lamports/tokens to the initializer goes here
        // once real token accounts are wired up.
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
        escrow
            .attest(ctx.accounts.attestor.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flip the attestor's bit in `vault.quorum.approvals` in the real build.
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
        escrow
            .activate(ctx.accounts.authority.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flip the party's bit in `vault.activation` in the real build.
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
    /// curve). Returns the claimed amount so the real build can size the
    /// transfer of lamports/tokens to the taker. The AV-04 quorum gate
    /// applies exactly as for `release`.
    pub fn claim(ctx: Context<Claim>) -> Result<u64> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let claimed = escrow
            .claim(ctx.accounts.taker.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Transfer of `claimed` lamports/tokens to `ctx.accounts.taker`
        // goes here once real token accounts are wired up.
        Ok(claimed)
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

#[derive(Accounts)]
pub struct Initialize<'info> {
    // Full vault space: 8-byte discriminator + 374-byte payload = 382
    // bytes (see `escrow_state::VAULT_SPACE`; AV-12 added the 1-byte
    // activation bitmask, AV-13 the 17-byte vesting region).
    // The payer must fund at least the rent-exempt minimum for this space
    // — `escrow_state::check_vault_rent_exempt` is the pure-logic mirror of
    // that check (on-chain: `Rent::get()?.is_exempt(...)`); with mainnet
    // rent parameters the minimum is 3_549_600 lamports.
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
}

#[derive(Accounts)]
pub struct Cancel<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
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
}

// --- Helpers (finalized during the real Anchor build) ---

fn read_escrow(_vault: &Account<Vault>) -> escrow_state::Escrow {
    unimplemented!("deserialize Vault account into escrow_state::Escrow")
}

fn read_clock_unix_timestamp(_clock: &AccountInfo) -> u64 {
    unimplemented!("read Clock::get()?.unix_timestamp as u64 in the real build")
}

fn write_escrow(_vault: &mut Account<Vault>, _escrow: &escrow_state::Escrow) {
    unimplemented!("serialize escrow_state::Escrow back into the Vault account")
}

fn escrow_error(e: escrow_state::EscrowError) -> Error {
    // One program error per EscrowError variant, so on-chain failures
    // surface the exact `escrow_state` reason (code 100–107) to clients.
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
}
