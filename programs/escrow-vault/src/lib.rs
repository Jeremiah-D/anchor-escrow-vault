//! Anchor program skeleton for the escrow vault.
//!
//! NOTE: This file is not compiled by CI. Building it requires the
//! Solana/Anchor toolchain (`anchor-lang`), which is intentionally kept out
//! of the workspace. It shows how the dependency-free state machine in
//! `escrow-state` maps onto Anchor instructions: each instruction converts
//! the on-chain account into `escrow_state::Escrow`, runs the transition,
//! and writes it back. State and authority rules live in one place —
//! the `escrow-state` crate — so the on-chain program cannot drift from
//! the tested logic.
//!
//! To compile for real: `anchor build` with the Solana toolchain installed.

use anchor_lang::prelude::*;

// Program ID placeholder — replace with the real deployed program address.
declare_id!("EscrowVault1111111111111111111111111111111111");

#[program]
pub mod escrow_vault {
    use super::*;

    /// Create the vault account and record initializer / taker / amount.
    pub fn initialize(ctx: Context<Initialize>, amount: u64) -> Result<()> {
        let escrow = escrow_state::Escrow::initialize(
            ctx.accounts.initializer.key().to_bytes(),
            ctx.accounts.taker.key().to_bytes(),
            amount,
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

    /// Release locked funds to the taker (`Funded -> Released`).
    pub fn release(ctx: Context<Release>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        escrow
            .release(ctx.accounts.initializer.key().to_bytes())
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
}

// --- Account structs (skeleton: field layout finalized during real build) ---

#[account]
pub struct Vault {
    pub initializer: Pubkey,
    pub taker: Pubkey,
    pub amount: u64,
    // The authoritative state lives in `escrow_state::EscrowState`;
    // persisted here as a byte until the real build wires the enum.
    pub state: u8,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = initializer, space = 8 + 32 + 32 + 8 + 1)]
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

// --- Helpers (finalized during the real Anchor build) ---

fn read_escrow(_vault: &Account<Vault>) -> escrow_state::Escrow {
    unimplemented!("deserialize Vault account into escrow_state::Escrow")
}

fn write_escrow(_vault: &mut Account<Vault>, _escrow: &escrow_state::Escrow) {
    unimplemented!("serialize escrow_state::Escrow back into the Vault account")
}

fn escrow_error(e: escrow_state::EscrowError) -> Error {
    // Map to custom program error codes in the real build.
    let _ = e;
    error!(ErrorCode::EscrowViolation)
}

#[error_code]
pub enum ErrorCode {
    #[msg("Escrow state machine rejected the operation")]
    EscrowViolation,
}
