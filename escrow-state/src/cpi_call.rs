//! CPI-routed release: optional third-party program invocation (AV-35).
//!
//! A release normally settles by moving funds straight to the taker
//! (see [`cpi::payout_plan`]). Sometimes the taker's payout should flow
//! *through* another on-chain program instead — a DEX swap, a lending
//! protocol deposit, a streaming-payment splitter — so the escrow's
//! release becomes one leg of a larger composed transaction. This
//! module is the pure-logic half of that: it models the third-party
//! invocation as data ([`CpiInvocation`]), validates its shape before
//! the state machine settles anything, and produces the audit record
//! ([`CpiReceipt`]) the release returns on success.
//!
//! Funds never move inside this crate — movement happens through Solana
//! CPI calls built by the program (or assembled off-chain by a keeper).
//! What the state machine guarantees is the *authorization* boundary:
//!
//! 1. The exact same gates as [`Escrow::release`] run first (authority,
//!    state, mint, milestone plan, quorum, timelock, amount) — a
//!    CPI-routed release is a release, not a bypass.
//! 2. The invocation shape is validated after the gates, before
//!    settlement: a zero program id, an empty account list, or a zero
//!    account key is [`EscrowError::InvalidCpiTarget`], and the release
//!    is rolled back — mirroring `cancel`'s authority → state → mint →
//!    refund-input check order.
//! 3. The state machine hands the validated invocation to an injected
//!    executor — the seam where the Anchor layer plugs the real
//!    `invoke`. If the executor reports failure, the whole release
//!    rolls back: `released`, `fees_paid` and `state` are restored to
//!    their pre-call values and the error is
//!    [`EscrowError::CpiExecutionFailed`]. On-chain this rollback is
//!    what a failed CPI already does — the transaction aborts and no
//!    state change persists — so the pure-logic model mirrors the
//!    chain's atomicity instead of inventing its own.
//! 4. On success the caller gets [`CpiReceipt`]: the target program id,
//!    the SHA-256 `accounts_hash` over the canonical encoding of the
//!    invocation (program id + accounts + data), and the
//!    `(payout, fee)` the invocation is authorized to move. The
//!    receipt — and the `Released` indexer's `cpi` audit field — is the
//!    audit trail: given the receipt, anyone re-derives the hash and
//!    confirms the release authorized exactly this instruction and no
//!    other.
//!
//! The protocol fee (AV-17) is *not* routed through the target program:
//! it settles to the protocol fee account through the normal payout
//! path, so fee accounting stays identical whether or not a release is
//! CPI-routed.
//!
//! [`Escrow::release`]: super::Escrow::release
//! [`EscrowError::InvalidCpiTarget`]: super::EscrowError::InvalidCpiTarget
//! [`EscrowError::CpiExecutionFailed`]: super::EscrowError::CpiExecutionFailed
//! [`cpi::payout_plan`]: super::cpi::payout_plan

use super::cpi::{AccountMeta, Pubkey};
use super::{sha256, EscrowError};

/// One inner instruction for the third-party program: the program to
/// invoke, the accounts it may read or write, and its opaque
/// instruction data. On-chain this is what the vault PDA submits via
/// CPI with the vault seeds as the signer; off-chain it is the value
/// a keeper assembles and the [`cpi_accounts_hash`] pins for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpiInvocation {
    /// The third-party program invoked (e.g. a DEX or lending program).
    /// The zero address is never a real program.
    pub program_id: Pubkey,
    /// The instruction's account list, in the target program's expected
    /// order. Every key must be non-zero — a zero key is a malformed
    /// invocation, not a default.
    pub accounts: Vec<AccountMeta>,
    /// Opaque instruction data for the target program. May be empty —
    /// some instructions take no data.
    pub data: Vec<u8>,
}

/// Audit record for a CPI-routed release, returned by
/// [`Escrow::release_via_cpi`] on success and carried on the
/// `Released` indexer event's `cpi` field (see
/// [`CpiRouteAudit`](super::events::CpiRouteAudit)).
///
/// [`Escrow::release_via_cpi`]: super::Escrow::release_via_cpi
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpiReceipt {
    /// The invoked third-party program.
    pub cpi_target: Pubkey,
    /// SHA-256 over the canonical encoding of the authorized
    /// invocation (see [`cpi_accounts_hash`]).
    pub accounts_hash: [u8; 32],
    /// The taker's net payout the invocation is authorized to move
    /// (gross `amount` minus the protocol fee).
    pub payout: u64,
    /// The protocol fee sliced from the payout (settled to the fee
    /// account through the normal path, not through the CPI).
    pub fee: u64,
}

/// SHA-256 over the canonical encoding of a [`CpiInvocation`]:
/// `program_id || u64LE(accounts.len) || per account (pubkey ||
/// is_signer as u8 || is_writable as u8) || u64LE(data.len) || data`.
///
/// The hash is the audit commitment: the release authorizes exactly
/// the bytes hashed here, and an indexer (or a multisig signer)
/// re-derives it from the proposed instruction to confirm nothing was
/// swapped — a changed account, flag, or data byte changes the hash.
pub fn cpi_accounts_hash(inv: &CpiInvocation) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&inv.program_id);
    bytes.extend_from_slice(&(inv.accounts.len() as u64).to_le_bytes());
    for a in &inv.accounts {
        bytes.extend_from_slice(&a.pubkey);
        bytes.push(a.is_signer as u8);
        bytes.push(a.is_writable as u8);
    }
    bytes.extend_from_slice(&(inv.data.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&inv.data);
    sha256(&bytes)
}

/// Validate the invocation shape: the state machine authorizes an
/// instruction, so a malformed one must fail before any fund movement.
/// A zero program id, an empty account list, or a zero account key is
/// [`EscrowError::InvalidCpiTarget`].
///
/// [`EscrowError::InvalidCpiTarget`]: super::EscrowError::InvalidCpiTarget
pub(crate) fn validate_cpi_invocation(inv: &CpiInvocation) -> Result<(), EscrowError> {
    if inv.program_id == [0u8; 32] {
        return Err(EscrowError::InvalidCpiTarget);
    }
    if inv.accounts.is_empty() {
        return Err(EscrowError::InvalidCpiTarget);
    }
    for a in &inv.accounts {
        if a.pubkey == [0u8; 32] {
            return Err(EscrowError::InvalidCpiTarget);
        }
    }
    Ok(())
}

/// Build the audit receipt for a successful CPI-routed release.
pub(crate) fn cpi_receipt(inv: &CpiInvocation, payout: u64, fee: u64) -> CpiReceipt {
    CpiReceipt {
        cpi_target: inv.program_id,
        accounts_hash: cpi_accounts_hash(inv),
        payout,
        fee,
    }
}

#[cfg(test)]
mod cpi_call_tests {
    use super::*;
    use crate::cpi::CpiError;

    fn key(n: u8) -> Pubkey {
        [n; 32]
    }

    fn invocation() -> CpiInvocation {
        CpiInvocation {
            program_id: key(0xD1),
            accounts: vec![
                AccountMeta { pubkey: key(1), is_signer: true, is_writable: true },
                AccountMeta { pubkey: key(2), is_signer: false, is_writable: true },
            ],
            data: vec![9, 9, 9],
        }
    }

    #[test]
    fn valid_invocation_passes_shape_validation() {
        assert!(validate_cpi_invocation(&invocation()).is_ok());
        // Empty data is fine — some target instructions take no data.
        let mut inv = invocation();
        inv.data.clear();
        assert!(validate_cpi_invocation(&inv).is_ok());
    }

    #[test]
    fn malformed_invocations_are_invalid_cpi_target() {
        let mut inv = invocation();
        inv.program_id = [0u8; 32];
        assert_eq!(validate_cpi_invocation(&inv), Err(EscrowError::InvalidCpiTarget));
        let mut inv = invocation();
        inv.accounts.clear();
        assert_eq!(validate_cpi_invocation(&inv), Err(EscrowError::InvalidCpiTarget));
        let mut inv = invocation();
        inv.accounts[1].pubkey = [0u8; 32];
        assert_eq!(validate_cpi_invocation(&inv), Err(EscrowError::InvalidCpiTarget));
    }

    #[test]
    fn accounts_hash_is_stable_and_sensitive_to_every_byte() {
        let inv = invocation();
        let h1 = cpi_accounts_hash(&inv);
        assert_eq!(h1, cpi_accounts_hash(&invocation()));
        // Any change — program, account key, flag, data — changes the hash.
        let mut inv2 = invocation();
        inv2.program_id = key(0xD2);
        assert_ne!(cpi_accounts_hash(&inv2), h1);
        let mut inv2 = invocation();
        inv2.accounts[0].pubkey = key(3);
        assert_ne!(cpi_accounts_hash(&inv2), h1);
        let mut inv2 = invocation();
        inv2.accounts[0].is_signer = false;
        assert_ne!(cpi_accounts_hash(&inv2), h1);
        let mut inv2 = invocation();
        inv2.accounts[0].is_writable = false;
        assert_ne!(cpi_accounts_hash(&inv2), h1);
        let mut inv2 = invocation();
        inv2.data.push(0);
        assert_ne!(cpi_accounts_hash(&inv2), h1);
        // Account *order* matters: it is the target program's account order.
        let mut inv2 = invocation();
        inv2.accounts.swap(0, 1);
        assert_ne!(cpi_accounts_hash(&inv2), h1);
    }

    #[test]
    fn cpi_error_stays_constructible_for_executors() {
        // The executor seam speaks CpiError; a failing executor's error
        // is what the state machine maps to CpiExecutionFailed.
        let err = CpiError::ZeroAddress;
        assert_eq!(err, CpiError::ZeroAddress);
    }
}
