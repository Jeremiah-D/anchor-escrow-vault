//! Token-2022 confidential transfer awareness (AV-168).
//!
//! Mints carrying the Token-2022 confidential-transfer extension keep
//! per-account balances as ElGamal ciphertexts with a *pending* and an
//! *available* bucket. Moving money out of such an account is a
//! two-step dance the token program enforces on-chain:
//!
//! 1. [`confidential_apply_pending_balance`] (`ApplyPendingBalance`,
//!    instruction 14) settles the pending bucket into the available
//!    bucket;
//! 2. [`confidential_withdraw`] (`Withdraw`, instruction 8) moves the
//!    now-available amount to the destination.
//!
//! Withdrawing without applying first leaves the pending amount
//! stranded — the on-chain program rejects it, and this module
//! refuses to even *build* that sequence: the
//! [`ConfidentialSettlementSequence`] builder carries the
//! applied/not-applied state and fails with
//! [`CpiError::ConfidentialPendingNotApplied`] instead of emitting a
//! doomed instruction.
//!
//! Three layers:
//!
//! 1. **Extension detection** — [`ConfidentialTransferMint`] describes
//!    the mint's confidential-transfer extension; a
//!    [`MintDescriptor`](crate::cpi::MintDescriptor) carrying it on the
//!    legacy SPL Token program fails validation with
//!    [`CpiError::IncompatibleTokenExtension`] (the AV-166 gate,
//!    extended).
//! 2. **Instruction builders + sequencing** — byte-pinned
//!    `ApplyPendingBalance` / `Withdraw` constructors and the
//!    apply-before-withdraw [`ConfidentialSettlementSequence`]; the
//!    [`confidential_payout_plan`] wires the sequence into a
//!    [`SettlementPlan`](crate::cpi::SettlementPlan) for the
//!    `release` / `claim` settlement path.
//! 3. **ElGamal balance math** — the pure-logic side of the
//!    decryptable-available-balance query: [`ElGamalCiphertext`]
//!    encryption, the additive homomorphism ([`elgamal_add`]), and the
//!    [`ConfidentialBalanceQuery`] trait, implemented by
//!    [`ElgamalDecryptor`] with a caller-held secret key. The crate
//!    never sees, stores, or transmits the key — the caller
//!    constructs the decryptor. Decryption ends in a baby-step
//!    giant-step discrete log over `[0, 2^32)` (see
//!    `ed25519::dlog_base_g`).
//!
//! # Honest deviations from on-chain
//!
//! - On-chain confidential transfers use the Ristretto encoding of
//!   the Ed25519 curve group; this crate models the identical group
//!   algebra on compressed Edwards25519 points (see the AV-168
//!   section in `ed25519.rs`). The discrete-log problem, the
//!   commitment equation, and the homomorphism are unchanged — only
//!   the point encoding differs. Nothing here is wire-compatible
//!   with on-chain confidential accounts.
//! - The crate's ElGamal key is `(s·G, s·H)` (64 bytes): the handle
//!   equation `D = r·(s·H)` needs the secret's multiple of the
//!   second generator, which a single `s·G` point cannot provide.
//!   The Pedersen commitment `amount·G + opening·H` stays binding
//!   because `H`'s discrete log base `G` is unknown (see
//!   [`elgamal_generator_h`](crate::ed25519::elgamal_generator_h)).
//! - The bounded-range discrete log covers `[0, 2^32)` — the same
//!   bound the on-chain SDK's `decrypt_u32` uses. Amounts at or above
//!   2^32 fail with [`ConfidentialError::DecryptionOutOfRange`],
//!   never with a wrong number.
//! - The `Withdraw` zero-knowledge proofs (equality + range) are
//!   produced by the wallet off-chain; this module takes the proof
//!   instruction *offsets* as caller inputs and pins them into the
//!   instruction data, but never fabricates proofs.

use std::sync::OnceLock;

use crate::cpi::{
    token_program_kind, AccountMeta, CpiError, PayoutAddrs, PayoutKind, Pubkey, SettlementPlan,
    TokenProgram, TransferInstruction,
};
use crate::ed25519::{
    dlog_base_g, elgamal_generator_h, elgamal_point_add, elgamal_point_sub, elgamal_scalar_inverse,
    elgamal_scalar_mul, elgamal_scalar_mul_base,
};
use crate::{Escrow, EscrowState};

// ---------------------------------------------------------------------------
// Mint-level extension detection.
// ---------------------------------------------------------------------------

/// The Token-2022 confidential-transfer extension as declared on a
/// mint: the on-chain `ConfidentialTransferMint` (`authority`,
/// `auto_approve_new_accounts`, `auditor_elgamal_pubkey`).
///
/// The auditor pubkey is carried opaque (32-byte on-chain Ristretto
/// encoding) — the pure-logic layer never interprets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfidentialTransferMint {
    /// Optional authority that can reconfigure the extension.
    pub authority: Option<Pubkey>,
    /// Whether new confidential token accounts are auto-approved.
    pub auto_approve_new_accounts: bool,
    /// Optional auditor ElGamal pubkey (opaque on-chain encoding).
    pub auditor_elgamal_pubkey: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Instruction builders (byte layouts pinned by tests).
// ---------------------------------------------------------------------------

/// Token-2022 confidential-transfer `Withdraw` instruction index.
pub const CONFIDENTIAL_TRANSFER_WITHDRAW_IX: u8 = 8;

/// Token-2022 confidential-transfer `ApplyPendingBalance` instruction index.
pub const CONFIDENTIAL_TRANSFER_APPLY_PENDING_BALANCE_IX: u8 = 14;

/// Pinned data length of the `Withdraw` instruction this module builds:
/// `u8 ix || u64 amount LE || u8 decimals || [u8; 16]
/// new_decryptable_available_balance || i8 equality_proof_offset || i8
/// range_proof_offset`.
pub const CONFIDENTIAL_TRANSFER_WITHDRAW_DATA_LEN: usize = 28;

/// Require the named program to be Token-2022: confidential
/// transfers are a Token-2022 extension, so the legacy SPL Token
/// program fails with [`CpiError::IncompatibleTokenExtension`] and an
/// unknown program with [`CpiError::UnsupportedTokenProgram`].
fn require_token_2022(token_program: Pubkey) -> Result<(), CpiError> {
    match token_program_kind(token_program)? {
        TokenProgram::Token2022 => Ok(()),
        TokenProgram::SplToken => Err(CpiError::IncompatibleTokenExtension),
    }
}

fn require_nonzero(key: &Pubkey) -> Result<(), CpiError> {
    if *key == [0u8; 32] {
        return Err(CpiError::ZeroAddress);
    }
    Ok(())
}

/// Build a Token-2022 confidential-transfer `ApplyPendingBalance`
/// (instruction 14): settles `account`'s pending balance into its
/// available balance.
///
/// Data layout (canonical): a single byte, `14`. Accounts: the
/// confidential token account (writable). The actual settlement
/// happens on-chain; this is the off-chain mirror the keeper submits.
pub fn confidential_apply_pending_balance(
    token_program: Pubkey,
    account: Pubkey,
) -> Result<TransferInstruction, CpiError> {
    require_token_2022(token_program)?;
    require_nonzero(&account)?;
    Ok(TransferInstruction {
        program_id: token_program,
        accounts: vec![AccountMeta {
            pubkey: account,
            is_signer: false,
            is_writable: true,
        }],
        data: vec![CONFIDENTIAL_TRANSFER_APPLY_PENDING_BALANCE_IX],
    })
}

/// Build a Token-2022 confidential-transfer `Withdraw` (instruction 8).
///
/// Data layout (canonical, 28 bytes): `u8` index `8`, `u64` amount
/// (little-endian), `u8` decimals, the 16-byte
/// `new_decryptable_available_balance` (the AES-sealed available
/// balance *after* this withdrawal — sealed by the wallet off-chain,
/// carried opaque here), and the two `i8` zero-knowledge proof
/// instruction offsets (the proofs themselves ride as separate
/// instructions in the same transaction; this module pins the
/// offsets but never fabricates proofs).
///
/// Accounts: source (writable), mint (read-only), destination
/// (writable), authority (signer). The decimals must fit the
/// on-chain ceiling (≤ 9, same as `TransferChecked`).
pub fn confidential_withdraw(
    token_program: Pubkey,
    source: Pubkey,
    mint: Pubkey,
    destination: Pubkey,
    authority: Pubkey,
    amount: u64,
    decimals: u8,
    new_decryptable_available_balance: [u8; 16],
    equality_proof_offset: i8,
    range_proof_offset: i8,
) -> Result<TransferInstruction, CpiError> {
    require_token_2022(token_program)?;
    require_nonzero(&source)?;
    require_nonzero(&mint)?;
    require_nonzero(&destination)?;
    require_nonzero(&authority)?;
    if amount == 0 {
        return Err(CpiError::ZeroAmount);
    }
    if decimals > 9 {
        return Err(CpiError::InvalidDecimals);
    }
    let mut data = Vec::with_capacity(CONFIDENTIAL_TRANSFER_WITHDRAW_DATA_LEN);
    data.push(CONFIDENTIAL_TRANSFER_WITHDRAW_IX);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    data.extend_from_slice(&new_decryptable_available_balance);
    data.push(equality_proof_offset as u8);
    data.push(range_proof_offset as u8);
    debug_assert_eq!(data.len(), CONFIDENTIAL_TRANSFER_WITHDRAW_DATA_LEN);
    Ok(TransferInstruction {
        program_id: token_program,
        accounts: vec![
            AccountMeta { pubkey: source, is_signer: false, is_writable: true },
            AccountMeta { pubkey: mint, is_signer: false, is_writable: false },
            AccountMeta { pubkey: destination, is_signer: false, is_writable: true },
            AccountMeta { pubkey: authority, is_signer: true, is_writable: false },
        ],
        data,
    })
}

// ---------------------------------------------------------------------------
// Apply-before-withdraw sequencing.
// ---------------------------------------------------------------------------

/// A confidential settlement that cannot be built out of order.
///
/// The builder starts *unapplied*: [`withdraw`](Self::withdraw) before
/// [`apply_pending_balance`](Self::apply_pending_balance) fails with
/// [`CpiError::ConfidentialPendingNotApplied`], and a second
/// [`apply_pending_balance`](Self::apply_pending_balance) fails with
/// [`CpiError::ConfidentialAlreadyApplied`]. The emitted instruction
/// vector is always `[]`, `[ApplyPendingBalance]`, or
/// `[ApplyPendingBalance, Withdraw, ..]` — a withdraw never leads.
#[derive(Debug, Clone)]
pub struct ConfidentialSettlementSequence {
    token_program: Pubkey,
    source: Pubkey,
    mint: Pubkey,
    destination: Pubkey,
    authority: Pubkey,
    applied: bool,
    instructions: Vec<TransferInstruction>,
}

impl ConfidentialSettlementSequence {
    /// Start a confidential settlement out of `source` (the vault's
    /// confidential token account) into `destination`, signed by
    /// `authority` (the vault PDA). The token program must be
    /// Token-2022.
    pub fn new(
        token_program: Pubkey,
        source: Pubkey,
        mint: Pubkey,
        destination: Pubkey,
        authority: Pubkey,
    ) -> Result<Self, CpiError> {
        require_token_2022(token_program)?;
        require_nonzero(&source)?;
        require_nonzero(&mint)?;
        require_nonzero(&destination)?;
        require_nonzero(&authority)?;
        Ok(ConfidentialSettlementSequence {
            token_program,
            source,
            mint,
            destination,
            authority,
            applied: false,
            instructions: Vec::new(),
        })
    }

    /// Emit `ApplyPendingBalance`: settle the pending bucket into the
    /// available bucket. Exactly-once — a second call is a caller bug.
    pub fn apply_pending_balance(&mut self) -> Result<(), CpiError> {
        if self.applied {
            return Err(CpiError::ConfidentialAlreadyApplied);
        }
        self.instructions.push(confidential_apply_pending_balance(
            self.token_program,
            self.source,
        )?);
        self.applied = true;
        Ok(())
    }

    /// Emit `Withdraw` — only after the pending balance was applied.
    /// The zero-knowledge proof offsets and the sealed
    /// `new_decryptable_available_balance` are caller-supplied (the
    /// wallet produces them off-chain).
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        &mut self,
        amount: u64,
        decimals: u8,
        new_decryptable_available_balance: [u8; 16],
        equality_proof_offset: i8,
        range_proof_offset: i8,
    ) -> Result<(), CpiError> {
        if !self.applied {
            return Err(CpiError::ConfidentialPendingNotApplied);
        }
        self.instructions.push(confidential_withdraw(
            self.token_program,
            self.source,
            self.mint,
            self.destination,
            self.authority,
            amount,
            decimals,
            new_decryptable_available_balance,
            equality_proof_offset,
            range_proof_offset,
        )?);
        Ok(())
    }

    /// Whether the pending balance was applied.
    pub fn pending_applied(&self) -> bool {
        self.applied
    }

    /// The built instructions, in emission order.
    pub fn instructions(self) -> Vec<TransferInstruction> {
        self.instructions
    }
}

// ---------------------------------------------------------------------------
// ElGamal balance math (pure logic).
// ---------------------------------------------------------------------------

/// Failures from ElGamal encryption / decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidentialError {
    /// A point argument did not decode (off-curve or non-canonical).
    InvalidPoint,
    /// The secret key is zero mod `L` (no inverse exists).
    InvalidSecret,
    /// The encryption randomness is zero mod `L` (degenerate
    /// ciphertext — the caller must supply fresh nonzero randomness).
    InvalidRandomness,
    /// The decrypted amount is outside the `[0, 2^32)` discrete-log
    /// bound — reported, never silently wrapped.
    DecryptionOutOfRange,
}

/// A 64-byte ElGamal ciphertext: the Pedersen `commitment`
/// (`amount·G + opening·H`, 32 bytes) followed by the decrypt
/// `handle` (`opening·(s·H)`, 32 bytes) — the on-chain
/// `EncryptedBalance` wire shape (64 bytes), modeled over
/// compressed Edwards25519 points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    /// `amount·G + opening·H`.
    pub commitment: [u8; 32],
    /// `opening·(s·H)` — recoverable to `opening·H` with the secret.
    pub handle: [u8; 32],
}

impl ElGamalCiphertext {
    /// The 64-byte wire encoding: commitment || handle.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.commitment);
        out[32..].copy_from_slice(&self.handle);
        out
    }

    /// Decode the 64-byte wire encoding.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut commitment = [0u8; 32];
        let mut handle = [0u8; 32];
        commitment.copy_from_slice(&bytes[..32]);
        handle.copy_from_slice(&bytes[32..]);
        ElGamalCiphertext { commitment, handle }
    }
}

/// An ElGamal public key: `(s·G, s·H)`.
///
/// Two points because the handle equation needs the secret's multiple
/// of the second generator `H` — a single `s·G` point cannot provide
/// it (documented deviation from the on-chain 32-byte encoding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElGamalPubkey {
    /// `s·G`.
    pub g_part: [u8; 32],
    /// `s·H`.
    pub h_part: [u8; 32],
}

/// An ElGamal keypair. The secret is held by the caller — this crate
/// provides key generation for wallets/tests and never persists or
/// transmits the secret.
#[derive(Debug, Clone)]
pub struct ElGamalKeypair {
    secret: [u8; 32],
    pubkey: ElGamalPubkey,
}

impl ElGamalKeypair {
    /// Generate a keypair from 32 bytes of caller-supplied randomness
    /// (use a CSPRNG). `None` when the randomness is zero mod `L`.
    pub fn generate(randomness: [u8; 32]) -> Option<Self> {
        // Reject the zero scalar: it has no inverse and yields a
        // degenerate key.
        elgamal_scalar_inverse(&randomness)?;
        let g = elgamal_generator_h();
        let g_part = elgamal_scalar_mul_base(&randomness);
        let h_part = elgamal_scalar_mul(&g, &randomness)?;
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&randomness);
        Some(ElGamalKeypair {
            secret,
            pubkey: ElGamalPubkey { g_part, h_part },
        })
    }

    /// The public key `(s·G, s·H)`.
    pub fn public_key(&self) -> ElGamalPubkey {
        self.pubkey
    }

    /// Build the decryptor holding this keypair's secret. Moving the
    /// secret into the decryptor keeps it out of any wider struct.
    pub fn decryptor(self) -> ElgamalDecryptor {
        ElgamalDecryptor { secret: self.secret }
    }
}

fn scalar32_from_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&v.to_le_bytes());
    out
}

/// The compressed identity point (cached): `0·G`.
fn identity_point() -> [u8; 32] {
    static IDENTITY: OnceLock<[u8; 32]> = OnceLock::new();
    *IDENTITY.get_or_init(|| elgamal_scalar_mul_base(&[0u8; 32]))
}

/// Encrypt `amount` for `pubkey` with caller-supplied `randomness`
/// (the Pedersen opening — fresh nonzero randomness per encryption).
///
/// Returns `None` on an undecodable pubkey or degenerate (zero)
/// randomness.
pub fn elgamal_encrypt(
    amount: u64,
    pubkey: &ElGamalPubkey,
    randomness: [u8; 32],
) -> Option<ElGamalCiphertext> {
    let h = elgamal_generator_h();
    // amount·G
    let amount_g = elgamal_scalar_mul_base(&scalar32_from_u64(amount));
    // opening·H — the identity check rejects zero randomness.
    let opening_h = elgamal_scalar_mul(&h, &randomness)?;
    if opening_h == identity_point() {
        return None;
    }
    let commitment = elgamal_point_add(&amount_g, &opening_h)?;
    // opening·(s·H)
    let handle = elgamal_scalar_mul(&pubkey.h_part, &randomness)?;
    Some(ElGamalCiphertext { commitment, handle })
}

/// Add two ciphertexts component-wise. The sum decrypts to the sum
/// of the amounts (same key) — the additive homomorphism the
/// pending-balance aggregation relies on. `None` on undecodable
/// points.
pub fn elgamal_add(a: &ElGamalCiphertext, b: &ElGamalCiphertext) -> Option<ElGamalCiphertext> {
    Some(ElGamalCiphertext {
        commitment: elgamal_point_add(&a.commitment, &b.commitment)?,
        handle: elgamal_point_add(&a.handle, &b.handle)?,
    })
}

/// Holds the ElGamal secret key for balance queries. Constructed by
/// the key holder — the crate never sees the key except inside this
/// decryptor.
#[derive(Debug, Clone)]
pub struct ElgamalDecryptor {
    secret: [u8; 32],
}

impl ElgamalDecryptor {
    /// Wrap a caller-held 32-byte secret key.
    pub fn new(secret: [u8; 32]) -> Self {
        ElgamalDecryptor { secret }
    }

    /// Decrypt a ciphertext: `M = commitment − s⁻¹·handle`
    /// (`s⁻¹·(opening·s·H) = opening·H`), then the bounded-range
    /// discrete log of `M` base `G` (baby-step giant-step over
    /// `[0, 2^32)` — see `ed25519::dlog_base_g`).
    pub fn decrypt(&self, ciphertext: &ElGamalCiphertext) -> Result<u64, ConfidentialError> {
        let s_inv = elgamal_scalar_inverse(&self.secret).ok_or(ConfidentialError::InvalidSecret)?;
        // s⁻¹·handle = opening·H
        let opening_h =
            elgamal_scalar_mul(&ciphertext.handle, &s_inv).ok_or(ConfidentialError::InvalidPoint)?;
        // M = amount·G
        let m_point =
            elgamal_point_sub(&ciphertext.commitment, &opening_h).ok_or(ConfidentialError::InvalidPoint)?;
        dlog_base_g(&m_point).ok_or(ConfidentialError::DecryptionOutOfRange)
    }
}

/// The decryptable-available-balance query abstraction: given the
/// account's confidential balances, return the available amount as a
/// plain integer. The decryption key stays with the caller — the
/// implementor holds it, the trait only describes the query.
pub trait ConfidentialBalanceQuery {
    /// Query the available balance of a confidential token account.
    fn available_balance(
        &self,
        balance: &ConfidentialAccountBalance,
    ) -> Result<u64, ConfidentialError>;
}

impl ConfidentialBalanceQuery for ElgamalDecryptor {
    fn available_balance(
        &self,
        balance: &ConfidentialAccountBalance,
    ) -> Result<u64, ConfidentialError> {
        self.decrypt(&balance.available)
    }
}

/// A confidential token account's balances: the three ElGamal
/// buckets plus the AES-sealed decryptable balance (16 bytes, sealed
/// by the wallet — carried opaque here) and the pending-balance
/// credit counters the apply flow settles against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfidentialAccountBalance {
    /// Pending incoming transfers (low 32 bits), ElGamal-encrypted.
    pub pending_lo: ElGamalCiphertext,
    /// Pending incoming transfers (high 32 bits), ElGamal-encrypted.
    pub pending_hi: ElGamalCiphertext,
    /// Settled balance available for withdrawal, ElGamal-encrypted.
    pub available: ElGamalCiphertext,
    /// AES-sealed available balance (wallet-side; opaque here).
    pub decryptable_available: [u8; 16],
    /// Credits applied to the pending bucket so far.
    pub pending_balance_credit_counter: u64,
    /// Protocol cap on pending credits (DoS bound).
    pub maximum_pending_balance_credit_counter: u64,
    /// Credits the account expects to have applied.
    pub expected_pending_balance_credit_counter: u64,
    /// Credits actually applied.
    pub actual_pending_balance_credit_counter: u64,
}

// ---------------------------------------------------------------------------
// Confidential settlement plans for release / claim.
// ---------------------------------------------------------------------------

/// Caller-supplied parameters for the confidential `Withdraw` leg of
/// a payout plan: the wallet seals `new_decryptable_available_balance`
/// and produces the zero-knowledge proofs whose instruction offsets
/// ride the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfidentialPayoutParams {
    /// Decimals the withdrawn amount is denominated in (≤ 9).
    pub decimals: u8,
    /// The AES-sealed available balance after this withdrawal
    /// (wallet-sealed, opaque here).
    pub new_decryptable_available_balance: [u8; 16],
    /// Offset of the equality-proof instruction in the transaction.
    pub equality_proof_offset: i8,
    /// Offset of the range-proof instruction in the transaction.
    pub range_proof_offset: i8,
}

/// Build the settlement plan for a `release` / `claim` payout out of
/// a confidential-transfer-enabled Token-2022 mint.
///
/// The taker payout leg is the explicit `ApplyPendingBalance →
/// Withdraw` sequence — a withdraw without the apply is refused at
/// construction, mirroring the on-chain rule. The protocol-fee leg
/// settles through the standard token leg (the fee recipient is a
/// plain account, not a confidential one).
///
/// Consistency checks (mirroring
/// [`payout_plan`](crate::cpi::payout_plan)): the escrow is `Funded`
/// or `Released`; `payout + fee` cannot exceed the recorded released
/// total; the taker matches; the transfer-hook context matches the
/// escrow's declared hook. The token program must be Token-2022 — a
/// confidential plan on the legacy SPL path, or with no program
/// named, fails with [`CpiError::IncompatibleTokenExtension`].
pub fn confidential_payout_plan(
    kind: PayoutKind,
    escrow: &Escrow,
    addrs: &PayoutAddrs,
    payout: u64,
    fee: u64,
    params: &ConfidentialPayoutParams,
) -> Result<SettlementPlan, CpiError> {
    let _ = kind; // The money movement is identical for all payout
    // kinds; the kind is carried for audit clarity at the call site.
    match escrow.state() {
        EscrowState::Funded | EscrowState::Released => {}
        _ => return Err(CpiError::UnexpectedState),
    }
    // A confidential settlement without a named Token-2022 program is
    // a caller bug — failed loud, never silently downgraded to the
    // plain-transfer plan.
    let token_program = match addrs.token_program {
        Some(id) => id,
        None => return Err(CpiError::IncompatibleTokenExtension),
    };
    require_token_2022(token_program)?;
    let gross = payout.checked_add(fee).ok_or(CpiError::ArithmeticOverflow)?;
    if gross == 0 {
        return Err(CpiError::ZeroAmount);
    }
    if gross > escrow.released_amount() {
        return Err(CpiError::SettlementMismatch);
    }
    if addrs.taker != escrow.taker() {
        return Err(CpiError::RecipientMismatch);
    }
    require_nonzero(&addrs.source)?;
    require_nonzero(&addrs.vault_authority)?;

    let mut transfers = Vec::with_capacity(3);
    if payout > 0 {
        let mint = escrow.mint().ok_or(CpiError::SettlementMismatch)?;
        let mut sequence = ConfidentialSettlementSequence::new(
            token_program,
            addrs.source,
            mint,
            addrs.taker_leg,
            addrs.vault_authority,
        )?;
        sequence.apply_pending_balance()?;
        sequence.withdraw(
            payout,
            params.decimals,
            params.new_decryptable_available_balance,
            params.equality_proof_offset,
            params.range_proof_offset,
        )?;
        transfers.extend(sequence.instructions());
    }
    // The fee leg settles to a plain account via the standard token
    // leg (with the AV-44 pinned-recipient check).
    crate::cpi::push_fee_leg(
        escrow,
        addrs.source,
        addrs.vault_authority,
        addrs.fee_leg,
        fee,
        addrs.token_program,
        &mut transfers,
    )?;
    let (transfer_hook_program, transfer_hook_accounts) =
        crate::cpi::check_transfer_hook(escrow, &addrs.transfer_hook)?;
    Ok(SettlementPlan {
        transfers,
        transfer_hook_program,
        transfer_hook_accounts,
    })
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod confidential_tests {
    use super::*;
    use crate::cpi::{spl_token_program_id, token_2022_program_id};

    fn key(byte: u8) -> Pubkey {
        [byte; 32]
    }

    fn t22() -> Pubkey {
        token_2022_program_id()
    }

    fn test_keypair() -> ElGamalKeypair {
        ElGamalKeypair::generate([0x42; 32]).expect("nonzero test randomness")
    }

    fn ct_mint_config() -> ConfidentialTransferMint {
        ConfidentialTransferMint {
            authority: Some(key(5)),
            auto_approve_new_accounts: true,
            auditor_elgamal_pubkey: None,
        }
    }

    // --- extension detection -------------------------------------------------

    #[test]
    fn mint_extension_gate_rejects_legacy_spl_token() {
        let d = crate::cpi::MintDescriptor {
            mint: key(7),
            token_program: spl_token_program_id(),
            decimals: 6,
            transfer_fee: None,
            metadata: None,
            confidential_transfer: Some(ct_mint_config()),
        };
        assert_eq!(
            d.validate(),
            Err(CpiError::IncompatibleTokenExtension),
            "confidential-transfer is a Token-2022 extension"
        );
    }

    #[test]
    fn mint_extension_gate_accepts_token_2022() {
        let d = crate::cpi::MintDescriptor {
            mint: key(7),
            token_program: t22(),
            decimals: 6,
            transfer_fee: None,
            metadata: None,
            confidential_transfer: Some(ct_mint_config()),
        };
        let v = d.validate().expect("T22 confidential mint validates");
        assert_eq!(v.program, TokenProgram::Token2022);
    }

    // --- instruction byte layouts -------------------------------------------

    #[test]
    fn apply_pending_balance_layout_is_pinned() {
        let ix = confidential_apply_pending_balance(t22(), key(11)).unwrap();
        assert_eq!(ix.program_id, t22());
        assert_eq!(ix.data, vec![14u8]);
        assert_eq!(
            ix.accounts,
            vec![AccountMeta {
                pubkey: key(11),
                is_signer: false,
                is_writable: true
            }]
        );
    }

    #[test]
    fn builders_reject_non_token_2022_programs() {
        assert_eq!(
            confidential_apply_pending_balance(spl_token_program_id(), key(11)),
            Err(CpiError::IncompatibleTokenExtension)
        );
        assert_eq!(
            confidential_withdraw(
                spl_token_program_id(),
                key(11),
                key(7),
                key(12),
                key(10),
                100,
                6,
                [0xAB; 16],
                1,
                2
            ),
            Err(CpiError::IncompatibleTokenExtension)
        );
        // Unknown program ids fail at dispatch, before the extension gate.
        assert_eq!(
            confidential_apply_pending_balance(key(99), key(11)),
            Err(CpiError::UnsupportedTokenProgram)
        );
    }

    #[test]
    fn withdraw_layout_is_pinned() {
        let ix = confidential_withdraw(
            t22(),
            key(11),
            key(7),
            key(12),
            key(10),
            1_500_000,
            6,
            [0xAB; 16],
            1,
            2,
        )
        .unwrap();
        assert_eq!(ix.program_id, t22());
        assert_eq!(ix.data.len(), CONFIDENTIAL_TRANSFER_WITHDRAW_DATA_LEN);
        // u8 ix || u64 amount LE || u8 decimals || [u8;16] sealed || i8 || i8
        let mut expected = vec![8u8];
        expected.extend_from_slice(&1_500_000u64.to_le_bytes());
        expected.push(6);
        expected.extend_from_slice(&[0xABu8; 16]);
        expected.push(1);
        expected.push(2);
        assert_eq!(ix.data, expected);
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta { pubkey: key(11), is_signer: false, is_writable: true },
                AccountMeta { pubkey: key(7), is_signer: false, is_writable: false },
                AccountMeta { pubkey: key(12), is_signer: false, is_writable: true },
                AccountMeta { pubkey: key(10), is_signer: true, is_writable: false },
            ]
        );
        assert_eq!(ix.confidential_withdraw_amount(), Some(1_500_000));
        // The generic amount() decoder covers the withdraw layout too,
        // so settlement-plan totals reconcile.
        assert_eq!(ix.amount(), Some(1_500_000));
    }

    #[test]
    fn withdraw_validates_amount_and_decimals() {
        let base = || {
            confidential_withdraw(
                t22(),
                key(11),
                key(7),
                key(12),
                key(10),
                100,
                6,
                [0; 16],
                0,
                0,
            )
        };
        assert!(base().is_ok());
        assert_eq!(
            confidential_withdraw(t22(), key(11), key(7), key(12), key(10), 0, 6, [0; 16], 0, 0),
            Err(CpiError::ZeroAmount)
        );
        assert_eq!(
            confidential_withdraw(
                t22(),
                key(11),
                key(7),
                key(12),
                key(10),
                100,
                10,
                [0; 16],
                0,
                0
            ),
            Err(CpiError::InvalidDecimals)
        );
    }

    // --- sequencing ----------------------------------------------------------

    #[test]
    fn sequence_refuses_withdraw_before_apply() {
        let mut seq =
            ConfidentialSettlementSequence::new(t22(), key(11), key(7), key(12), key(10)).unwrap();
        assert!(!seq.pending_applied());
        assert_eq!(
            seq.withdraw(100, 6, [0; 16], 0, 0),
            Err(CpiError::ConfidentialPendingNotApplied),
            "withdrawing before the pending balance is applied is refused"
        );
    }

    #[test]
    fn sequence_refuses_double_apply() {
        let mut seq =
            ConfidentialSettlementSequence::new(t22(), key(11), key(7), key(12), key(10)).unwrap();
        seq.apply_pending_balance().unwrap();
        assert_eq!(
            seq.apply_pending_balance(),
            Err(CpiError::ConfidentialAlreadyApplied)
        );
    }

    #[test]
    fn sequence_emits_apply_then_withdraw() {
        let mut seq =
            ConfidentialSettlementSequence::new(t22(), key(11), key(7), key(12), key(10)).unwrap();
        seq.apply_pending_balance().unwrap();
        assert!(seq.pending_applied());
        seq.withdraw(250_000, 6, [0xAB; 16], 1, 2).unwrap();
        let ixs = seq.instructions();
        assert_eq!(ixs.len(), 2);
        assert_eq!(ixs[0].data, vec![14u8], "apply leads");
        assert_eq!(
            ixs[1].confidential_withdraw_amount(),
            Some(250_000),
            "withdraw follows"
        );
    }

    // --- ElGamal math --------------------------------------------------------

    #[test]
    fn generator_h_is_deterministic_and_nontrivial() {
        let h1 = elgamal_generator_h();
        let h2 = elgamal_generator_h();
        assert_eq!(h1, h2, "H derivation is deterministic");
        assert_ne!(
            h1,
            elgamal_scalar_mul_base(&scalar32_from_u64(1)),
            "H is not G"
        );
        assert_ne!(h1, identity_point(), "H is not the identity");
    }

    #[test]
    fn elgamal_encrypt_decrypt_roundtrip() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        let decryptor = kp.decryptor();
        // NOTE: each encryption uses fresh randomness; decryption
        // must not depend on it.
        for (amount, randomness) in [
            (0u64, [0x01; 32]),
            (1, [0x02; 32]),
            (42, [0x03; 32]),
            (1_000_000, [0x04; 32]),
            (u32::MAX as u64, [0x05; 32]),
        ] {
            let ct =
                elgamal_encrypt(amount, &pubkey, randomness).expect("valid encryption inputs");
            assert_eq!(
                decryptor.decrypt(&ct),
                Ok(amount),
                "roundtrip failed for amount {amount}"
            );
        }
    }

    #[test]
    fn elgamal_homomorphic_addition_decrypts_to_sum() {
        let kp = test_keypair();
        let pubkey = ElGamalKeypair::generate([0x42; 32]).unwrap().public_key();
        let decryptor = kp.decryptor();
        let a = elgamal_encrypt(700_000, &pubkey, [0x11; 32]).unwrap();
        let b = elgamal_encrypt(300_000, &pubkey, [0x22; 32]).unwrap();
        let sum = elgamal_add(&a, &b).expect("points add");
        assert_eq!(decryptor.decrypt(&sum), Ok(1_000_000));
    }

    #[test]
    fn elgamal_rejects_bad_inputs() {
        let kp = test_keypair();
        let pubkey = kp.public_key();
        // Zero randomness is degenerate.
        assert_eq!(elgamal_encrypt(100, &pubkey, [0u8; 32]), None);
        // An undecodable pubkey point fails.
        let bad_pubkey = ElGamalPubkey { g_part: pubkey.g_part, h_part: [0xFF; 32] };
        assert_eq!(elgamal_encrypt(100, &bad_pubkey, [0x01; 32]), None);
        // Zero secret has no inverse.
        let bad_decryptor = ElgamalDecryptor::new([0u8; 32]);
        let ct = elgamal_encrypt(100, &pubkey, [0x01; 32]).unwrap();
        assert_eq!(bad_decryptor.decrypt(&ct), Err(ConfidentialError::InvalidSecret));
        // Zero-randomness keypair generation is refused.
        assert!(ElGamalKeypair::generate([0u8; 32]).is_none());
    }

    #[test]
    fn elgamal_wrong_key_does_not_recover_amount() {
        let pubkey = ElGamalKeypair::generate([0x42; 32]).unwrap().public_key();
        let ct = elgamal_encrypt(999_999, &pubkey, [0x01; 32]).unwrap();
        let wrong = ElgamalDecryptor::new([0x77; 32]);
        // A wrong key either fails the range check or yields a
        // different amount — never the true one.
        assert_ne!(wrong.decrypt(&ct), Ok(999_999));
    }

    #[test]
    fn balance_query_via_trait() {
        let kp = test_keypair();
        let pubkey = ElGamalKeypair::generate([0x42; 32]).unwrap().public_key();
        let decryptor = kp.decryptor();
        let balance = ConfidentialAccountBalance {
            pending_lo: elgamal_encrypt(10, &pubkey, [0x31; 32]).unwrap(),
            pending_hi: elgamal_encrypt(0, &pubkey, [0x32; 32]).unwrap(),
            available: elgamal_encrypt(5_000_000, &pubkey, [0x33; 32]).unwrap(),
            decryptable_available: [0xAA; 16],
            pending_balance_credit_counter: 2,
            maximum_pending_balance_credit_counter: 100,
            expected_pending_balance_credit_counter: 2,
            actual_pending_balance_credit_counter: 2,
        };
        let q: &dyn ConfidentialBalanceQuery = &decryptor;
        assert_eq!(q.available_balance(&balance), Ok(5_000_000));
    }

    #[test]
    fn ciphertext_wire_encoding_roundtrips() {
        let pubkey = test_keypair().public_key();
        let ct = elgamal_encrypt(123, &pubkey, [0x09; 32]).unwrap();
        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), 64);
        assert_eq!(ElGamalCiphertext::from_bytes(&bytes), ct);
    }

    // --- confidential payout plans ------------------------------------------

    fn funded_confidential_escrow() -> (Escrow, u64, u64, Pubkey) {
        let init = key(1);
        let taker = key(2);
        let mint = key(7);
        let mut e = Escrow::initialize(init, taker, 1_000_000, u64::MAX)
            .unwrap()
            .with_mint(mint)
            .unwrap();
        e.fund(init, 1).unwrap();
        let (payout, fee) = e.release(init, 0, 1_000_000, Some(mint), taker).unwrap();
        assert_eq!(fee, 0);
        (e, payout, fee, mint)
    }

    fn confidential_addrs() -> PayoutAddrs {
        PayoutAddrs {
            source: key(11),
            vault_authority: key(10),
            taker: key(2),
            taker_leg: key(12),
            fee_leg: key(9),
            transfer_hook: None,
            token_program: Some(t22()),
        }
    }

    fn test_params() -> ConfidentialPayoutParams {
        ConfidentialPayoutParams {
            decimals: 6,
            new_decryptable_available_balance: [0xAB; 16],
            equality_proof_offset: 1,
            range_proof_offset: 2,
        }
    }

    #[test]
    fn confidential_payout_plan_builds_apply_withdraw_sequence() {
        let (e, payout, fee, _mint) = funded_confidential_escrow();
        let plan = confidential_payout_plan(
            PayoutKind::Release,
            &e,
            &confidential_addrs(),
            payout,
            fee,
            &test_params(),
        )
        .unwrap();
        assert_eq!(plan.transfers.len(), 2, "apply + withdraw, no fee leg");
        assert_eq!(plan.transfers[0].data, vec![14u8]);
        assert_eq!(plan.transfers[0].program_id, t22());
        let wd = &plan.transfers[1];
        assert_eq!(wd.confidential_withdraw_amount(), Some(payout));
        assert_eq!(wd.accounts[0].pubkey, key(11)); // vault token account
        assert_eq!(wd.accounts[2].pubkey, key(12)); // taker's token account
        assert_eq!(wd.accounts[3].pubkey, key(10)); // vault PDA authority
        assert_eq!(plan.total_amount(), payout);
    }

    #[test]
    fn confidential_payout_plan_rejects_bad_inputs() {
        let (e, payout, fee, _mint) = funded_confidential_escrow();
        let params = test_params();
        // Legacy SPL Token program: the confidential extension does not exist there.
        let mut spl_addrs = confidential_addrs();
        spl_addrs.token_program = Some(spl_token_program_id());
        assert_eq!(
            confidential_payout_plan(PayoutKind::Release, &e, &spl_addrs, payout, fee, &params),
            Err(CpiError::IncompatibleTokenExtension)
        );
        // No program named: never silently downgrade to the plain plan.
        let mut none_addrs = confidential_addrs();
        none_addrs.token_program = None;
        assert_eq!(
            confidential_payout_plan(PayoutKind::Release, &e, &none_addrs, payout, fee, &params),
            Err(CpiError::IncompatibleTokenExtension)
        );
        // Swapped taker.
        let mut bad_taker = confidential_addrs();
        bad_taker.taker = key(77);
        assert_eq!(
            confidential_payout_plan(PayoutKind::Release, &e, &bad_taker, payout, fee, &params),
            Err(CpiError::RecipientMismatch)
        );
        // Wrong escrow state.
        let init = key(1);
        let taker = key(2);
        let mut fresh = Escrow::initialize(init, taker, 1_000_000, u64::MAX).unwrap();
        fresh.fund(init, 1).unwrap();
        fresh.cancel(init, None, init, 2).unwrap();
        assert_eq!(
            confidential_payout_plan(
                PayoutKind::Release,
                &fresh,
                &confidential_addrs(),
                payout,
                fee,
                &params
            ),
            Err(CpiError::UnexpectedState)
        );
    }
}
