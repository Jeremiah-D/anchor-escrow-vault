//! Off-chain CPI transfer instruction construction (AV-31).
//!
//! The fund-moving transitions (`release`, `claim`, `release_milestone`,
//! `cancel`, `cancel_expired`, `resolve`) compute *amounts* in the
//! dependency-free state machine, but the actual movement of lamports /
//! tokens happens through Solana CPI calls built by the program (or by an
//! off-chain keeper assembling transactions). This module builds those
//! transfer instructions with zero dependencies and validates them against
//! the state machine's settlement results, so a malformed instruction —
//! wrong amount, wrong destination, wrong program — is caught before it
//! ever reaches the chain.
//!
//! Two layers:
//!
//! 1. **Instruction constructors** ([`system_transfer`],
//!    [`spl_token_transfer`]) assemble the exact account metas and data
//!    bytes of a System Program `Transfer` (instruction index 2, 12-byte
//!    data) and an SPL Token `Transfer` (instruction index 3, 9-byte
//!    data). The byte layouts are pinned by unit tests.
//! 2. **Settlement plans** ([`payout_plan`], [`refund_plan`],
//!    [`resolve_plan`]) take an [`Escrow`] *after* a transition plus the
//!    amounts that transition returned, and verify the plan against the
//!    machine: the moved totals cannot exceed what the machine recorded,
//!    recipients are pinned against the escrow's taker / initializer /
//!    refund policy, and the mint path (native SOL vs SPL token) follows
//!    the escrow's bound mint. A tampered amount or a swapped destination
//!    fails with [`CpiError`] instead of producing an instruction.
//!
//! The Anchor skeleton (`programs/escrow-vault/src/program.rs`) mirrors
//! these constructors in its CPI calls; the IDL mapping tests pin the
//! correspondence, so the on-chain code cannot drift from this tested
//! byte layout.

use std::sync::OnceLock;

use super::{parse_mint_address, Escrow, EscrowState};

/// A 32-byte Solana public key.
pub type Pubkey = [u8; 32];

/// One account in a transfer instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// A fully assembled transfer instruction: program + accounts + data.
/// This is the off-chain mirror of what the program submits via CPI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferInstruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

impl TransferInstruction {
    /// Amount carried by this instruction, decoded from its data bytes.
    /// System transfers encode a u64 at bytes 4..12; SPL token transfers
    /// encode a u64 at bytes 1..9.
    pub fn amount(&self) -> Option<u64> {
        let bytes: [u8; 8] = if self.program_id == system_program_id() {
            self.data.get(4..12)?.try_into().ok()?
        } else if self.program_id == spl_token_program_id() {
            self.data.get(1..9)?.try_into().ok()?
        } else {
            return None;
        };
        Some(u64::from_le_bytes(bytes))
    }
}

/// The System Program: `11111111111111111111111111111111`.
pub fn system_program_id() -> Pubkey {
    [0u8; 32]
}

/// The SPL Token Program (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`),
/// decoded with the same base58 decoder that validates mint addresses
/// (AV-16) — one decoder, one tested code path.
pub fn spl_token_program_id() -> Pubkey {
    static TOKEN_PROGRAM: OnceLock<Pubkey> = OnceLock::new();
    *TOKEN_PROGRAM.get_or_init(|| {
        parse_mint_address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            .expect("hardcoded SPL token program id must decode")
    })
}

/// Errors from instruction construction and settlement-plan validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpiError {
    /// A transfer leg would move zero lamports/tokens.
    ZeroAmount,
    /// Source and destination of a transfer are the same account.
    SelfTransfer,
    /// An address that must be meaningful is the zero address.
    ZeroAddress,
    /// u64 addition of settlement amounts overflowed.
    ArithmeticOverflow,
    /// The plan's amounts do not reconcile with what the state machine
    /// recorded (tampered payout/fee/refund, or a plan built from stale
    /// transition results).
    SettlementMismatch,
    /// A recipient does not match the escrow's taker / initializer /
    /// refund policy — a swapped destination is rejected, not built.
    RecipientMismatch,
    /// The escrow is not in a state that produces this settlement
    /// (e.g. a release plan for a `Cancelled` escrow).
    UnexpectedState,
}

fn require_nonzero(key: &Pubkey) -> Result<(), CpiError> {
    if *key == [0u8; 32] {
        return Err(CpiError::ZeroAddress);
    }
    Ok(())
}

/// Build a System Program transfer: `from` (signer, writable) sends
/// `lamports` to `to` (writable).
///
/// Data layout (canonical): `u32` instruction index `2` (little-endian)
/// followed by the `u64` lamport amount (little-endian) — 12 bytes total.
pub fn system_transfer(from: Pubkey, to: Pubkey, lamports: u64) -> Result<TransferInstruction, CpiError> {
    if lamports == 0 {
        return Err(CpiError::ZeroAmount);
    }
    require_nonzero(&from)?;
    require_nonzero(&to)?;
    if from == to {
        return Err(CpiError::SelfTransfer);
    }
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Ok(TransferInstruction {
        program_id: system_program_id(),
        accounts: vec![
            AccountMeta { pubkey: from, is_signer: true, is_writable: true },
            AccountMeta { pubkey: to, is_signer: false, is_writable: true },
        ],
        data,
    })
}

/// Build an SPL Token `Transfer`: `authority` (signer) moves `amount`
/// tokens of `mint` from `source` to `destination`.
///
/// Data layout (canonical): `u8` instruction index `3` followed by the
/// `u64` token amount (little-endian) — 9 bytes total. This is the plain
/// `Transfer`, not `TransferChecked`: the escrow's decimals metadata
/// (AV-28) lives off-chain, and the mint binding is enforced by the
/// state machine (`MintMismatch`), not re-checked here.
pub fn spl_token_transfer(
    source: Pubkey,
    mint: Pubkey,
    destination: Pubkey,
    authority: Pubkey,
    amount: u64,
) -> Result<TransferInstruction, CpiError> {
    if amount == 0 {
        return Err(CpiError::ZeroAmount);
    }
    require_nonzero(&source)?;
    require_nonzero(&mint)?;
    require_nonzero(&destination)?;
    require_nonzero(&authority)?;
    if source == destination {
        return Err(CpiError::SelfTransfer);
    }
    let mut data = Vec::with_capacity(9);
    data.push(3u8);
    data.extend_from_slice(&amount.to_le_bytes());
    Ok(TransferInstruction {
        program_id: spl_token_program_id(),
        accounts: vec![
            AccountMeta { pubkey: source, is_signer: false, is_writable: true },
            AccountMeta { pubkey: mint, is_signer: false, is_writable: false },
            AccountMeta { pubkey: destination, is_signer: false, is_writable: true },
            AccountMeta { pubkey: authority, is_signer: true, is_writable: false },
        ],
        data,
    })
}

/// Which taker-payout transition this plan settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayoutKind {
    Release,
    Claim,
    MilestoneRelease,
}

/// Addresses for a taker-payout settlement (`release` / `claim` /
/// `release_milestone`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutAddrs {
    /// Source of funds: the vault PDA on the native-SOL path, the vault's
    /// SPL token account on the token path.
    pub source: Pubkey,
    /// Authority signing the transfer: the vault PDA on both paths
    /// (on-chain: `invoke_signed` with the vault seeds).
    pub vault_authority: Pubkey,
    /// Taker identity, pinned against `escrow.taker()`.
    pub taker: Pubkey,
    /// Payout destination: the taker wallet (native) or the taker's SPL
    /// token account (token path).
    pub taker_leg: Pubkey,
    /// Protocol-fee destination. `fee == 0` emits no fee leg; `fee > 0`
    /// with a zero address is rejected.
    pub fee_leg: Pubkey,
}

/// Which refund transition this plan settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundKind {
    Cancel,
    CancelExpired,
}

/// Addresses for a refund settlement (`cancel` / `cancel_expired`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefundAddrs {
    /// Source of funds: the vault PDA (native) or vault token account (SPL).
    pub source: Pubkey,
    /// Authority signing the transfer: the vault PDA (both paths).
    pub vault_authority: Pubkey,
    /// Initializer identity, pinned against `escrow.initializer()`.
    /// Receives the anti-griefing penalty on taker-initiated expiry
    /// cancels (AV-24).
    pub initializer: Pubkey,
    /// Refund identity, pinned against `escrow.refund_recipient()` (the
    /// AV-23 whitelist, or the initializer with no whitelist).
    pub refund_to: Pubkey,
    /// Refund destination account.
    pub refund_leg: Pubkey,
    /// Penalty destination account (`penalty == 0` → no leg emitted).
    pub penalty_leg: Pubkey,
}

/// Addresses for a dispute-arbitration settlement (`resolve`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveAddrs {
    /// Source of funds: the vault PDA (native) or vault token account (SPL).
    pub source: Pubkey,
    /// Authority signing the transfer: the vault PDA (both paths).
    pub vault_authority: Pubkey,
    /// Taker identity, pinned against `escrow.taker()`.
    pub taker: Pubkey,
    /// Taker-payout destination account.
    pub taker_leg: Pubkey,
    /// Protocol-fee destination account (`fee == 0` → no leg emitted).
    pub fee_leg: Pubkey,
    /// Initializer identity, pinned against `escrow.initializer()`.
    pub initializer: Pubkey,
    /// Initializer-refund destination account.
    pub refund_leg: Pubkey,
}

/// A validated settlement: the transfer instructions to submit, in order.
/// Amounts and recipients were checked against the state machine when the
/// plan was built — executing the plan cannot move anything the machine
/// did not authorize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementPlan {
    pub transfers: Vec<TransferInstruction>,
}

impl SettlementPlan {
    /// Sum of the amounts carried by every transfer in the plan.
    pub fn total_amount(&self) -> u64 {
        self.transfers.iter().filter_map(|t| t.amount()).sum()
    }
}

/// Choose the transfer constructor from the escrow's mint binding:
/// native SOL → System Program, bound mint → SPL Token.
fn leg(
    escrow: &Escrow,
    source: Pubkey,
    vault_authority: Pubkey,
    destination: Pubkey,
    amount: u64,
) -> Result<TransferInstruction, CpiError> {
    match escrow.mint() {
        None => {
            // Native path: the vault PDA holds lamports directly, so the
            // source *is* the signing authority.
            if source != vault_authority {
                return Err(CpiError::SettlementMismatch);
            }
            system_transfer(source, destination, amount)
        }
        Some(mint) => spl_token_transfer(source, mint, destination, vault_authority, amount),
    }
}

fn push_fee_leg(
    escrow: &Escrow,
    source: Pubkey,
    vault_authority: Pubkey,
    fee_leg: Pubkey,
    fee: u64,
    transfers: &mut Vec<TransferInstruction>,
) -> Result<(), CpiError> {
    if fee == 0 {
        return Ok(());
    }
    require_nonzero(&fee_leg)?;
    transfers.push(leg(escrow, source, vault_authority, fee_leg, fee)?);
    Ok(())
}

/// Build the transfers for a taker payout after `release` / `claim` /
/// `release_milestone` returned `(payout, fee)`.
///
/// Consistency checks against the state machine:
/// - the escrow is `Funded` (partial payout) or `Released` (full payout);
/// - `payout + fee` cannot exceed `escrow.released_amount()` — the machine
///   accumulates the gross of every payout, so a plan moving more than the
///   recorded total is built from tampered or stale results;
/// - `addrs.taker` equals the escrow's taker; on the native path the payout
///   must go straight to the taker wallet (`taker_leg == taker`);
/// - the transfer program follows the escrow's mint binding.
pub fn payout_plan(
    kind: PayoutKind,
    escrow: &Escrow,
    addrs: &PayoutAddrs,
    payout: u64,
    fee: u64,
) -> Result<SettlementPlan, CpiError> {
    let _ = kind; // The money movement is identical for all payout kinds;
    // the kind is carried for audit clarity at the call site.
    match escrow.state() {
        EscrowState::Funded | EscrowState::Released => {}
        _ => return Err(CpiError::UnexpectedState),
    }
    let gross = payout.checked_add(fee).ok_or(CpiError::ArithmeticOverflow)?;
    if gross == 0 {
        return Err(CpiError::ZeroAmount);
    }
    // The machine recorded at least this payout's gross as released —
    // anything more means the amounts did not come from this escrow's
    // transition results.
    if gross > escrow.released_amount() {
        return Err(CpiError::SettlementMismatch);
    }
    if addrs.taker != escrow.taker() {
        return Err(CpiError::RecipientMismatch);
    }
    require_nonzero(&addrs.source)?;
    require_nonzero(&addrs.vault_authority)?;
    if escrow.mint().is_none() && addrs.taker_leg != addrs.taker {
        // Native path: the payout goes to the taker wallet itself. A
        // different destination would bypass the taker pin above.
        return Err(CpiError::RecipientMismatch);
    }

    let mut transfers = Vec::with_capacity(2);
    if payout > 0 {
        transfers.push(leg(escrow, addrs.source, addrs.vault_authority, addrs.taker_leg, payout)?);
    }
    push_fee_leg(escrow, addrs.source, addrs.vault_authority, addrs.fee_leg, fee, &mut transfers)?;
    Ok(SettlementPlan { transfers })
}

/// Build the transfers for a refund after `cancel` (refund amount
/// `= amount - released`, no penalty) or `cancel_expired` (returns
/// `(refund, penalty)`).
///
/// Consistency checks:
/// - the escrow is `Cancelled`;
/// - `refund + penalty` equals the pre-transition remainder
///   (`amount - released_amount()` — `cancel`/`cancel_expired` never touch
///   the `released` counter, so the remainder is still readable);
/// - `addrs.initializer` / `addrs.refund_to` match the escrow's
///   initializer and refund policy (AV-23 whitelist pinning);
/// - on the native path the refund goes to the pinned `refund_to` address
///   and the penalty (taker-initiated expiry cancels, AV-24) to the
///   initializer.
pub fn refund_plan(
    kind: RefundKind,
    escrow: &Escrow,
    addrs: &RefundAddrs,
    refund: u64,
    penalty: u64,
) -> Result<SettlementPlan, CpiError> {
    let _ = kind;
    match escrow.state() {
        EscrowState::Cancelled => {}
        _ => return Err(CpiError::UnexpectedState),
    }
    let total = refund.checked_add(penalty).ok_or(CpiError::ArithmeticOverflow)?;
    if total == 0 {
        return Err(CpiError::ZeroAmount);
    }
    let remainder = escrow.amount().saturating_sub(escrow.released_amount());
    if total != remainder {
        return Err(CpiError::SettlementMismatch);
    }
    if addrs.initializer != escrow.initializer() {
        return Err(CpiError::RecipientMismatch);
    }
    if addrs.refund_to != escrow.refund_recipient() {
        return Err(CpiError::RecipientMismatch);
    }
    require_nonzero(&addrs.source)?;
    require_nonzero(&addrs.vault_authority)?;
    if escrow.mint().is_none() {
        if addrs.refund_leg != addrs.refund_to {
            return Err(CpiError::RecipientMismatch);
        }
        if penalty > 0 && addrs.penalty_leg != addrs.initializer {
            // The anti-griefing penalty compensates the initializer for
            // the taker's deliberate expiry drag (AV-24) — it must land
            // on the initializer, not an arbitrary account.
            return Err(CpiError::RecipientMismatch);
        }
    }

    let mut transfers = Vec::with_capacity(2);
    transfers.push(leg(escrow, addrs.source, addrs.vault_authority, addrs.refund_leg, refund)?);
    if penalty > 0 {
        require_nonzero(&addrs.penalty_leg)?;
        // Note: on the native path with no refund whitelist, the refund
        // and the penalty both land on the initializer wallet — two legs
        // to the same account are valid; each leg's amount is pinned
        // above, so nothing merges silently.
        transfers.push(leg(escrow, addrs.source, addrs.vault_authority, addrs.penalty_leg, penalty)?);
    }
    Ok(SettlementPlan { transfers })
}

/// Build the transfers for a dispute settlement after `resolve` returned
/// `(taker_payout, fee, refund)`.
///
/// Consistency checks:
/// - the escrow is `Settled`;
/// - `taker_payout + fee` cannot exceed `released_amount()` (the taker's
///   share enters the `released` counter, AV-14/AV-17);
/// - `refund` equals the post-settlement remainder
///   (`amount - released_amount()`);
/// - taker / initializer identities pinned; native-path legs go to the
///   pinned wallets.
pub fn resolve_plan(
    escrow: &Escrow,
    addrs: &ResolveAddrs,
    taker_payout: u64,
    fee: u64,
    refund: u64,
) -> Result<SettlementPlan, CpiError> {
    match escrow.state() {
        EscrowState::Settled => {}
        _ => return Err(CpiError::UnexpectedState),
    }
    let taker_gross = taker_payout.checked_add(fee).ok_or(CpiError::ArithmeticOverflow)?;
    if taker_gross == 0 && refund == 0 {
        return Err(CpiError::ZeroAmount);
    }
    if taker_gross > escrow.released_amount() {
        return Err(CpiError::SettlementMismatch);
    }
    let remainder = escrow.amount().saturating_sub(escrow.released_amount());
    if refund != remainder {
        return Err(CpiError::SettlementMismatch);
    }
    if addrs.taker != escrow.taker() {
        return Err(CpiError::RecipientMismatch);
    }
    if addrs.initializer != escrow.initializer() {
        return Err(CpiError::RecipientMismatch);
    }
    require_nonzero(&addrs.source)?;
    require_nonzero(&addrs.vault_authority)?;
    if escrow.mint().is_none() {
        if taker_gross > 0 && addrs.taker_leg != addrs.taker {
            return Err(CpiError::RecipientMismatch);
        }
        if addrs.refund_leg != addrs.initializer {
            return Err(CpiError::RecipientMismatch);
        }
    }

    let mut transfers = Vec::with_capacity(3);
    if taker_payout > 0 {
        transfers.push(leg(escrow, addrs.source, addrs.vault_authority, addrs.taker_leg, taker_payout)?);
    }
    push_fee_leg(escrow, addrs.source, addrs.vault_authority, addrs.fee_leg, fee, &mut transfers)?;
    if refund > 0 {
        transfers.push(leg(escrow, addrs.source, addrs.vault_authority, addrs.refund_leg, refund)?);
    }
    Ok(SettlementPlan { transfers })
}

#[cfg(test)]
mod cpi_tests {
    use super::*;
    use crate::{Escrow, EscrowError, VestingSchedule};

    fn key(n: u8) -> Pubkey {
        [n; 32]
    }

    fn funded_escrow(amount: u64) -> Escrow {
        let init = key(1);
        let taker = key(2);
        let mut e = Escrow::initialize(init, taker, amount, u64::MAX).unwrap();
        e.fund(init).unwrap();
        assert_eq!(e.state(), EscrowState::Funded);
        e
    }

    fn payout_addrs_native() -> PayoutAddrs {
        PayoutAddrs {
            source: key(10),         // vault PDA
            vault_authority: key(10), // native path: the PDA holds the lamports
            taker: key(2),
            taker_leg: key(2),       // native path: straight to the taker wallet
            fee_leg: key(9),
        }
    }

    // --- instruction byte layouts -------------------------------------------------

    #[test]
    fn system_transfer_layout_is_pinned() {
        let ix = system_transfer(key(10), key(2), 1_500_000).unwrap();
        assert_eq!(ix.program_id, [0u8; 32]);
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta { pubkey: key(10), is_signer: true, is_writable: true },
                AccountMeta { pubkey: key(2), is_signer: false, is_writable: true },
            ]
        );
        // u32 index 2 LE || u64 amount LE
        let mut expected = vec![2u8, 0, 0, 0];
        expected.extend_from_slice(&1_500_000u64.to_le_bytes());
        assert_eq!(ix.data, expected);
        assert_eq!(ix.amount(), Some(1_500_000));
    }

    #[test]
    fn spl_token_transfer_layout_is_pinned() {
        let mint = key(7);
        let ix = spl_token_transfer(key(11), mint, key(12), key(10), 42_000).unwrap();
        assert_eq!(ix.program_id, spl_token_program_id());
        assert_ne!(ix.program_id, system_program_id());
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta { pubkey: key(11), is_signer: false, is_writable: true },
                AccountMeta { pubkey: mint, is_signer: false, is_writable: false },
                AccountMeta { pubkey: key(12), is_signer: false, is_writable: true },
                AccountMeta { pubkey: key(10), is_signer: true, is_writable: false },
            ]
        );
        // u8 index 3 || u64 amount LE
        let mut expected = vec![3u8];
        expected.extend_from_slice(&42_000u64.to_le_bytes());
        assert_eq!(ix.data, expected);
        assert_eq!(ix.amount(), Some(42_000));
    }

    #[test]
    fn token_program_id_decodes_to_32_nonzero_bytes() {
        let id = spl_token_program_id();
        assert_eq!(id.len(), 32);
        assert_ne!(id, [0u8; 32]);
        // Deterministic: the OnceLock caches the same decode.
        assert_eq!(spl_token_program_id(), id);
    }

    #[test]
    fn transfer_constructors_reject_garbage() {
        assert_eq!(system_transfer(key(1), key(2), 0), Err(CpiError::ZeroAmount));
        assert_eq!(system_transfer(key(1), key(1), 5), Err(CpiError::SelfTransfer));
        assert_eq!(system_transfer([0u8; 32], key(2), 5), Err(CpiError::ZeroAddress));
        assert_eq!(system_transfer(key(1), [0u8; 32], 5), Err(CpiError::ZeroAddress));
        assert_eq!(spl_token_transfer(key(1), key(7), key(2), key(3), 0), Err(CpiError::ZeroAmount));
        assert_eq!(
            spl_token_transfer(key(1), key(7), key(1), key(3), 5),
            Err(CpiError::SelfTransfer)
        );
        assert_eq!(
            spl_token_transfer(key(1), [0u8; 32], key(2), key(3), 5),
            Err(CpiError::ZeroAddress)
        );
    }

    // --- payout plans ---------------------------------------------------------------

    #[test]
    fn release_plan_native_matches_state_machine() {
        let init = key(1);
        let mut e = Escrow::initialize(init, key(2), 1_000_000, u64::MAX)
            .unwrap()
            .with_protocol_fee(100)
            .unwrap();
        e.fund(init).unwrap();
        // Protocol fee: 1% → fee 5_000 on a 500_000 release.
        let (payout, fee) = e.release(init, 0, 500_000, None).unwrap();
        assert_eq!((payout, fee), (495_000, 5_000));

        let plan = payout_plan(PayoutKind::Release, &e, &payout_addrs_native(), payout, fee).unwrap();
        assert_eq!(plan.transfers.len(), 2);
        assert_eq!(plan.transfers[0].amount(), Some(495_000));
        assert_eq!(plan.transfers[0].accounts[1].pubkey, key(2)); // taker
        assert_eq!(plan.transfers[1].amount(), Some(5_000));
        assert_eq!(plan.transfers[1].accounts[1].pubkey, key(9)); // fee account
        assert_eq!(plan.total_amount(), 500_000);
        // Every leg is a system transfer on the native path.
        assert!(plan.transfers.iter().all(|t| t.program_id == system_program_id()));
    }

    #[test]
    fn release_plan_omits_zero_fee_leg() {
        let mut e = funded_escrow(1_000_000);
        let (payout, fee) = e.release(key(1), 0, 1_000_000, None).unwrap();
        assert_eq!(fee, 0);
        let plan = payout_plan(PayoutKind::Release, &e, &payout_addrs_native(), payout, fee).unwrap();
        assert_eq!(plan.transfers.len(), 1);
        assert_eq!(plan.transfers[0].amount(), Some(1_000_000));
    }

    #[test]
    fn release_plan_rejects_tampered_amounts() {
        let mut e = funded_escrow(1_000_000);
        let (payout, fee) = e.release(key(1), 0, 400_000, None).unwrap();
        // Attacker inflates the payout by 1: gross exceeds released_amount().
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &payout_addrs_native(), payout + 1, fee),
            Err(CpiError::SettlementMismatch)
        );
        // Stale results from a *different* escrow: released is 0 here.
        let fresh = funded_escrow(1_000_000);
        assert_eq!(
            payout_plan(PayoutKind::Release, &fresh, &payout_addrs_native(), payout, fee),
            Err(CpiError::SettlementMismatch)
        );
    }

    #[test]
    fn release_plan_rejects_swapped_recipient() {
        let mut e = funded_escrow(1_000_000);
        let (payout, fee) = e.release(key(1), 0, 1_000_000, None).unwrap();
        let mut addrs = payout_addrs_native();
        addrs.taker = key(77); // not the escrow's taker
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee),
            Err(CpiError::RecipientMismatch)
        );
        let mut addrs = payout_addrs_native();
        addrs.taker_leg = key(78); // native path must pay the taker wallet
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee),
            Err(CpiError::RecipientMismatch)
        );
    }

    #[test]
    fn release_plan_rejects_wrong_state() {
        // A cancelled escrow never produces a payout plan, even if the
        // amounts would otherwise reconcile.
        let mut e = funded_escrow(1_000_000);
        e.cancel(key(1), None, key(1)).unwrap();
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &payout_addrs_native(), 1_000_000, 0),
            Err(CpiError::UnexpectedState)
        );
    }

    #[test]
    fn claim_plan_vesting_payout() {
        let init = key(1);
        let taker = key(2);
        let mut e = Escrow::initialize(init, taker, 1_000_000, u64::MAX)
            .unwrap()
            .with_vesting(VestingSchedule::new(1000, 2000).unwrap())
            .unwrap();
        e.fund(init).unwrap();
        // Half vested at t=1500.
        let (payout, fee) = e.claim(taker, 1500, None).unwrap();
        assert_eq!((payout, fee), (500_000, 0));
        let plan = payout_plan(PayoutKind::Claim, &e, &payout_addrs_native(), payout, fee).unwrap();
        assert_eq!(plan.transfers.len(), 1);
        assert_eq!(plan.transfers[0].amount(), Some(500_000));
    }

    #[test]
    fn payout_plan_token_path_uses_spl_transfer_with_bound_mint() {
        let init = key(1);
        let taker = key(2);
        // Any 32-byte address works as a mint; reuse the decoded token
        // program id bytes so the test needs no external fixtures.
        let mint = spl_token_program_id();
        let mut e = Escrow::initialize(init, taker, 1_000_000, u64::MAX)
            .unwrap()
            .with_mint(mint)
            .unwrap();
        e.fund(init).unwrap();
        let (payout, fee) = e.release(init, 0, 1_000_000, Some(mint)).unwrap();
        assert_eq!(fee, 0);

        let addrs = PayoutAddrs {
            source: key(11),          // vault token account
            vault_authority: key(10), // vault PDA signs via seeds
            taker,
            taker_leg: key(12), // taker's associated token account
            fee_leg: key(9),
        };
        let plan = payout_plan(PayoutKind::Release, &e, &addrs, payout, fee).unwrap();
        assert_eq!(plan.transfers.len(), 1);
        let ix = &plan.transfers[0];
        assert_eq!(ix.program_id, spl_token_program_id());
        assert_eq!(ix.accounts[1].pubkey, mint); // the bound mint, not a caller-supplied one
        assert_eq!(ix.accounts[3].pubkey, key(10)); // vault PDA authority
        assert_eq!(ix.amount(), Some(1_000_000));
    }

    // --- refund plans ---------------------------------------------------------------

    #[test]
    fn cancel_plan_refunds_to_initializer() {
        let mut e = funded_escrow(1_000_000);
        e.cancel(key(1), None, key(1)).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        let addrs = RefundAddrs {
            source: key(10),
            vault_authority: key(10),
            initializer: key(1),
            refund_to: key(1),
            refund_leg: key(1),
            penalty_leg: key(1),
        };
        let plan = refund_plan(RefundKind::Cancel, &e, &addrs, 1_000_000, 0).unwrap();
        assert_eq!(plan.transfers.len(), 1);
        assert_eq!(plan.transfers[0].amount(), Some(1_000_000));
        assert_eq!(plan.transfers[0].accounts[1].pubkey, key(1));
    }

    #[test]
    fn cancel_expired_plan_splits_refund_and_penalty() {
        let init = key(1);
        let taker = key(2);
        // 2% anti-griefing penalty on taker-initiated expiry cancel.
        let mut e = Escrow::initialize(init, taker, 1_000_000, 1000)
            .unwrap()
            .with_penalty_bps(200)
            .unwrap();
        e.fund(init).unwrap();
        let (refund, penalty) = e.cancel_expired(taker, 1000, None, init).unwrap();
        assert!(penalty > 0 && refund + penalty == 1_000_000);
        let addrs = RefundAddrs {
            source: key(10),
            vault_authority: key(10),
            initializer: init,
            refund_to: init,
            refund_leg: init,
            penalty_leg: init,
        };
        let plan = refund_plan(RefundKind::CancelExpired, &e, &addrs, refund, penalty).unwrap();
        assert_eq!(plan.transfers.len(), 2);
        assert_eq!(plan.transfers[0].amount(), Some(refund));
        assert_eq!(plan.transfers[1].amount(), Some(penalty));
        assert_eq!(plan.total_amount(), 1_000_000);
    }

    #[test]
    fn refund_plan_rejects_tampered_totals_and_recipients() {
        let mut e = funded_escrow(1_000_000);
        e.cancel(key(1), None, key(1)).unwrap();
        let addrs = RefundAddrs {
            source: key(10),
            vault_authority: key(10),
            initializer: key(1),
            refund_to: key(1),
            refund_leg: key(1),
            penalty_leg: key(1),
        };
        // Inflated refund: total != amount - released.
        assert_eq!(
            refund_plan(RefundKind::Cancel, &e, &addrs, 1_000_001, 0),
            Err(CpiError::SettlementMismatch)
        );
        // Refund to a non-whitelisted address.
        let mut bad = addrs.clone();
        bad.refund_to = key(77);
        assert_eq!(
            refund_plan(RefundKind::Cancel, &e, &bad, 1_000_000, 0),
            Err(CpiError::RecipientMismatch)
        );
        // Plan for a non-cancelled escrow.
        let live = funded_escrow(1_000_000);
        assert_eq!(
            refund_plan(RefundKind::Cancel, &live, &addrs, 1_000_000, 0),
            Err(CpiError::UnexpectedState)
        );
    }

    // --- resolve plans ----------------------------------------------------------------

    #[test]
    fn resolve_plan_splits_three_ways() {
        let init = key(1);
        let taker = key(2);
        let arbiter = key(5);
        let mut e = Escrow::initialize(init, taker, 1_000_000, u64::MAX)
            .unwrap()
            .with_arbiter(arbiter)
            .unwrap();
        e.fund(init).unwrap();
        e.escalate(taker, 0, None).unwrap();
        let (taker_payout, fee, refund) = e.resolve(arbiter, 600_000, None, None).unwrap();
        assert_eq!(fee, 0);
        assert_eq!(taker_payout + refund, 1_000_000);
        let addrs = ResolveAddrs {
            source: key(10),
            vault_authority: key(10),
            taker,
            taker_leg: taker,
            fee_leg: key(9),
            initializer: init,
            refund_leg: init,
        };
        let plan = resolve_plan(&e, &addrs, taker_payout, fee, refund).unwrap();
        assert_eq!(plan.transfers.len(), 2); // no fee leg at 0 bps
        assert_eq!(plan.transfers[0].amount(), Some(taker_payout));
        assert_eq!(plan.transfers[1].amount(), Some(refund));
        assert_eq!(plan.total_amount(), 1_000_000);
        // Tampered refund is caught against amount - released.
        assert_eq!(
            resolve_plan(&e, &addrs, taker_payout, fee, refund + 1),
            Err(CpiError::SettlementMismatch)
        );
    }

    #[test]
    fn resolve_plan_with_protocol_fee_emits_three_legs() {
        let init = key(1);
        let taker = key(2);
        let arbiter = key(5);
        let mut e = Escrow::initialize(init, taker, 1_000_000, u64::MAX)
            .unwrap()
            .with_arbiter(arbiter)
            .unwrap()
            .with_protocol_fee(100)
            .unwrap();
        e.fund(init).unwrap();
        e.escalate(taker, 0, None).unwrap();
        let (taker_payout, fee, refund) = e.resolve(arbiter, 600_000, None, None).unwrap();
        assert!(fee > 0);
        let addrs = ResolveAddrs {
            source: key(10),
            vault_authority: key(10),
            taker,
            taker_leg: taker,
            fee_leg: key(9),
            initializer: init,
            refund_leg: init,
        };
        let plan = resolve_plan(&e, &addrs, taker_payout, fee, refund).unwrap();
        assert_eq!(plan.transfers.len(), 3);
        assert_eq!(plan.total_amount(), 1_000_000);
    }
}
