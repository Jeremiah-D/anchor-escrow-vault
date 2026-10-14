//! Squads multisig authority adapter (AV-84).
//!
//! An escrow party (initializer, taker, arbiter, …) can be a multisig
//! vault PDA instead of an EOA: the threshold vote happens inside the
//! external multisig program, which then signs with the vault PDA. The
//! escrow side stays **zero-trust** — it never calls into the multisig
//! program and never interprets the threshold. Every authority check
//! ([`Escrow::require_initializer`], `require_taker`, …) compares the
//! signer's key against the recorded party key; a multisig vault PDA
//! passes exactly like an EOA key, because the Squads program
//! guarantees the PDA only signs once its threshold voted. The
//! `threshold` recorded here is read-only metadata for keepers and
//! indexers (how many votes the external multisig needs), never a
//! check gate.
//!
//! [`Escrow::with_multisig_authority`] binds the adapter at setup
//! (`Uninitialized` only): the multisig program id plus the authority
//! PDA it must sign with. This module additionally ships the Squads v4
//! integration helpers a keeper needs to *propose* a well-formed
//! escrow instruction to the multisig:
//!
//! - [`squads_v4_multisig_seeds`] / [`squads_v4_vault_seeds`]: the PDA
//!   seed assembly for the multisig account and its vault (the
//!   authority PDA). Run [`crate::pda::find_program_address`] over
//!   these seeds — the crate's unified derivation tool (AV-92:
//!   hand-rolled Solana `create_program_address` /
//!   `find_program_address`, zero dependencies) — instead of each
//!   caller hand-rolling its own bump search.
//! - [`assemble_multisig_escrow_call`]: builds the [`CpiInvocation`]
//!   the multisig's vault transaction executes against the escrow
//!   program.
//! - [`validate_multisig_escrow_call`]: shape validation before the
//!   proposal goes out — the invocation must target the expected
//!   escrow program, be well-formed, and carry the bound authority
//!   PDA as a signer, so a malformed or mis-targeted proposal is
//!   caught off-chain instead of failing on-chain after votes are
//!   cast.
//!
//! [`CpiInvocation`]: super::CpiInvocation
//! [`Escrow::with_multisig_authority`]: super::Escrow::with_multisig_authority
//! [`Escrow::require_initializer`]: super::Escrow::require_initializer

use super::cpi::{AccountMeta, Pubkey};
use super::cpi_call::validate_cpi_invocation;
use super::EscrowError;

/// Squads Protocol v4 multisig program id (Solana mainnet):
/// `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`.
///
/// Hardcoded as decoded bytes — the crate is dependency-free, so the
/// base58 form lives only in this doc comment (and is round-tripped
/// by `multisig_tests::squads_v4_program_id_matches_base58` via the
/// test-only base58 encoder).
pub const SQUADS_V4_PROGRAM_ID: Pubkey = [
    0x06, 0x81, 0xc4, 0xce, 0x47, 0xe2, 0x23, 0x68, 0xb8, 0xb1, 0x55, 0x5e, 0xc8, 0x87, 0xaf, 0x09,
    0x2e, 0xfc, 0x7e, 0xfb, 0xb6, 0x6c, 0xa3, 0xf5, 0x2f, 0xbf, 0x68, 0xd4, 0xac, 0x9c, 0xb7, 0xa8,
];

/// Serialized length of [`MultisigAuthority`]: the 32-byte multisig
/// program id, the 32-byte authority PDA, and the u16 threshold.
pub const MULTISIG_AUTHORITY_LEN: usize = 32 + 32 + 2;

/// A bound multisig authority (AV-84): which external multisig program
/// owns the threshold vote, which PDA must sign, and the threshold
/// metadata (read-only pass-through — the escrow never enforces it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultisigAuthority {
    /// The multisig program (e.g. [`SQUADS_V4_PROGRAM_ID`]).
    pub program_id: Pubkey,
    /// The vault PDA that signs once the threshold votes. This is the
    /// key the escrow's authority checks compare against.
    pub authority: Pubkey,
    /// How many member votes the external multisig requires.
    /// Informational only — enforced by the multisig program, never
    /// by the escrow.
    pub threshold: u16,
}

impl MultisigAuthority {
    /// Build, validating the binding. A zero program id or authority
    /// is [`EscrowError::InvalidMultisigAuthority`] — neither can ever
    /// sign — as is a zero threshold (a 0-of-N multisig authorizes
    /// nothing and signals a misconfigured binding).
    pub fn new(
        program_id: Pubkey,
        authority: Pubkey,
        threshold: u16,
    ) -> Result<Self, EscrowError> {
        if program_id == [0u8; 32] || authority == [0u8; 32] {
            return Err(EscrowError::InvalidMultisigAuthority);
        }
        if threshold == 0 {
            return Err(EscrowError::InvalidMultisigAuthority);
        }
        Ok(Self {
            program_id,
            authority,
            threshold,
        })
    }
}

/// Seed assembly for a Squads v4 multisig account PDA: `["multisig",
/// create_key]`. The `create_key` is the signer key the squad was
/// created with (see the Squads v4 program's PDA derivation).
/// Derive the address with [`crate::pda::find_program_address`]
/// (AV-92) — the unified tool; do not hand-roll a bump search.
pub fn squads_v4_multisig_seeds(create_key: &Pubkey) -> Vec<Vec<u8>> {
    vec![b"multisig".to_vec(), create_key.to_vec()]
}

/// Seed assembly for a Squads v4 vault PDA (the authority that signs
/// once the threshold votes): `["multisig", multisig, "vault",
/// vault_index]`. `vault_index` is the u8 vault number (vault 0 on the
/// default plan). Derive the address with
/// [`crate::pda::find_program_address`] (AV-92) — the unified tool;
/// do not hand-roll a bump search.
pub fn squads_v4_vault_seeds(multisig: &Pubkey, vault_index: u8) -> Vec<Vec<u8>> {
    vec![
        b"multisig".to_vec(),
        multisig.to_vec(),
        b"vault".to_vec(),
        vec![vault_index],
    ]
}

/// Assemble the inner instruction a multisig vault transaction
/// executes against the escrow program (AV-84): the escrow program id
/// as target, the authority PDA prepended as a signer (the vault PDA
/// signs the vault transaction once the threshold votes), then the
/// instruction's own accounts in the escrow program's expected order,
/// plus the opaque instruction data (discriminator + args).
///
/// The caller owns the account flags for `rest_accounts`; the
/// authority is marked signer + writable — the common case for the
/// escrow's state-changing instructions, whose authority both signs
/// and pays. Adjust the flags when the instruction needs otherwise.
pub fn assemble_multisig_escrow_call(
    escrow_program_id: Pubkey,
    authority: Pubkey,
    rest_accounts: Vec<AccountMeta>,
    data: Vec<u8>,
) -> super::CpiInvocation {
    let mut accounts = Vec::with_capacity(rest_accounts.len() + 1);
    accounts.push(AccountMeta {
        pubkey: authority,
        is_signer: true,
        is_writable: true,
    });
    accounts.extend(rest_accounts);
    super::CpiInvocation {
        program_id: escrow_program_id,
        accounts,
        data,
    }
}

/// Validate a multisig-proposed escrow instruction before it goes to
/// the multisig for voting (AV-84): the invocation must be
/// well-formed ([`EscrowError::InvalidCpiTarget`] on a zero program
/// id, an empty account list, or a zero account key — same shape rule
/// as [`Escrow::release_via_cpi`]), must target the expected escrow
/// program id (a mis-targeted proposal would execute against the
/// wrong program after votes are cast), and must carry the bound
/// authority PDA as a signer (otherwise the multisig's execution
/// could not authorize the escrow transition).
///
/// [`EscrowError::InvalidCpiTarget`]: super::EscrowError::InvalidCpiTarget
/// [`Escrow::release_via_cpi`]: super::Escrow::release_via_cpi
pub fn validate_multisig_escrow_call(
    inv: &super::CpiInvocation,
    escrow_program_id: &Pubkey,
    bound: &MultisigAuthority,
) -> Result<(), EscrowError> {
    validate_cpi_invocation(inv)?;
    if &inv.program_id != escrow_program_id {
        return Err(EscrowError::InvalidCpiTarget);
    }
    let authority_signs = inv
        .accounts
        .iter()
        .any(|a| a.is_signer && a.pubkey == bound.authority);
    if !authority_signs {
        return Err(EscrowError::InvalidMultisigAuthority);
    }
    Ok(())
}
