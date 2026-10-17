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
    /// refund / fee-recipient policy — a swapped destination is
    /// rejected, not built.
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

/// The Token-2022 transfer-hook execution context a settlement plan
/// is built for (AV-99).
///
/// Token-2022 invokes the hook program itself during the transfer —
/// the vault program only passes the extra accounts through — so
/// this is a *compatibility annotation*, not an execution proof:
/// [`payout_plan`] and its siblings check the named `program`
/// against the escrow's declared [`Escrow::transfer_hook`], and the
/// plan carries the `extra_accounts` so the on-chain CPI context can
/// include them. Pure logic never asserts the hook actually ran
/// on-chain (see the field docs on [`Escrow::transfer_hook`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferHookPlan {
    /// The hook program this settlement executes under. Must equal
    /// the escrow's declared hook program — a mismatch fails the
    /// plan with [`CpiError::SettlementMismatch`].
    pub program: Pubkey,
    /// Extra accounts the hook program needs (hook-specific; Token-2022
    /// derives them per its interface). Annotated on the plan, not
    /// validated — they are chain state the pure-logic machine cannot
    /// check.
    pub extra_accounts: Vec<AccountMeta>,
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
    /// with a zero address is rejected. When the escrow pins a fee
    /// recipient (AV-44), the address must equal it.
    pub fee_leg: Pubkey,
    /// Token-2022 transfer-hook execution context (AV-99). `None`
    /// when the escrow declares no hook; `Some` must name the
    /// declared hook program when it does (mismatch →
    /// [`CpiError::SettlementMismatch`]).
    pub transfer_hook: Option<TransferHookPlan>,
}

/// Which refund transition this plan settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundKind {
    Cancel,
    CancelExpired,
    /// AV-109: the dead-man's switch reclaim — the refund sink is the
    /// configured heir, not `escrow.refund_recipient()` (the AV-23
    /// whitelist / initializer). Pins against
    /// `escrow.deadman_heir()` instead.
    DeadmanClaim,
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
    /// Refund identity: pinned against `escrow.refund_recipient()` (the
    /// AV-23 whitelist, or the initializer with no whitelist) for
    /// [`RefundKind::Cancel`] / [`RefundKind::CancelExpired`] — and
    /// against the configured dead-man's switch heir for
    /// [`RefundKind::DeadmanClaim`] (AV-109: the heir is the refund
    /// sink, never the refund policy).
    pub refund_to: Pubkey,
    /// Refund destination account.
    pub refund_leg: Pubkey,
    /// Penalty destination account (`penalty == 0` → no leg emitted).
    pub penalty_leg: Pubkey,
    /// Token-2022 transfer-hook execution context (AV-99). Same
    /// semantics as [`PayoutAddrs::transfer_hook`].
    pub transfer_hook: Option<TransferHookPlan>,
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
    /// Pinned against the escrow's fee recipient when one is configured
    /// (AV-44).
    pub fee_leg: Pubkey,
    /// Initializer identity, pinned against `escrow.initializer()`.
    pub initializer: Pubkey,
    /// Initializer-refund destination account.
    pub refund_leg: Pubkey,
    /// Token-2022 transfer-hook execution context (AV-99). Same
    /// semantics as [`PayoutAddrs::transfer_hook`].
    pub transfer_hook: Option<TransferHookPlan>,
}

/// A validated settlement: the transfer instructions to submit, in order.
/// Amounts and recipients were checked against the state machine when the
/// plan was built — executing the plan cannot move anything the machine
/// did not authorize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementPlan {
    pub transfers: Vec<TransferInstruction>,
    /// The Token-2022 transfer-hook program this settlement executes
    /// under (AV-99): `Some` exactly when the escrow declared a hook
    /// and the plan's hook context matched it. The on-chain CPI
    /// context must include [`Self::transfer_hook_accounts`] when
    /// this is `Some`.
    pub transfer_hook_program: Option<Pubkey>,
    /// Extra accounts the hook program needs (AV-99), annotated from
    /// the plan's hook context — chain state the pure-logic machine
    /// annotates but never validates.
    pub transfer_hook_accounts: Vec<AccountMeta>,
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
    // AV-44: when the escrow pins a protocol-fee recipient, the plan's
    // fee leg must point at it — a swapped destination is rejected, not
    // built. With no pinned recipient any nonzero address stands (the
    // program-level fee account, backward compatible).
    if let Some(recipient) = escrow.fee_recipient() {
        if fee_leg != recipient {
            return Err(CpiError::RecipientMismatch);
        }
    }
    transfers.push(leg(escrow, source, vault_authority, fee_leg, fee)?);
    Ok(())
}

/// Check the plan's Token-2022 transfer-hook context against the
/// escrow's declared hook binding (AV-99), and return the annotation
/// for the [`SettlementPlan`].
///
/// The gate is exact-equality in both directions:
/// - escrow declares a hook, plan names the same program → the hook
///   program and its extra accounts ride the plan;
/// - escrow declares a hook, plan names nothing or a different program
///   → [`CpiError::SettlementMismatch`] (a plan that would silently
///   drop or swap the hook is never built);
/// - escrow declares no hook, plan names one →
///   [`CpiError::SettlementMismatch`] (the plan claims hook execution
///   the escrow never authorized).
///
/// Pure logic never asserts the hook actually ran on-chain — that is
/// Token-2022's job during the transfer. This gate only guarantees
/// the plan and the declaration agree.
fn check_transfer_hook(
    escrow: &Escrow,
    hook: &Option<TransferHookPlan>,
) -> Result<(Option<Pubkey>, Vec<AccountMeta>), CpiError> {
    match (escrow.transfer_hook(), hook) {
        (None, None) => Ok((None, Vec::new())),
        (Some(declared), Some(plan)) if plan.program == declared => Ok((
            Some(declared),
            plan.extra_accounts.clone(),
        )),
        _ => Err(CpiError::SettlementMismatch),
    }
}

/// Build the transfers for a taker payout after `release` / `claim` /
/// `release_milestone` returned `(payout, fee)`.
///
/// AV-108: this plan is single-recipient by construction — it covers
/// the plain-`release` payout shape, not the multi-leg
/// `release_payout_split` (whose per-recipient legs the Anchor
/// `release_payout_split` handler wires as `remaining_accounts`
/// directly). A payout-split escrow and CPI routing are mutually
/// exclusive: `release_via_cpi` delegates to `release`, which refuses
/// a split-configured escrow with
/// [`super::EscrowError::InvalidPayoutSplit`] (code 167) — never a
/// silent single-leg payout of a declared split.
///
/// Consistency checks against the state machine:
/// - the escrow is `Funded` (partial payout) or `Released` (full payout);
/// - `payout + fee` cannot exceed `escrow.released_amount()` — the machine
///   accumulates the gross of every payout, so a plan moving more than the
///   recorded total is built from tampered or stale results;
/// - `addrs.taker` equals the escrow's taker; on the native path the payout
///   must go straight to the taker wallet (`taker_leg == taker`);
/// - `addrs.fee_leg` equals the escrow's pinned fee recipient when one
///   is configured (AV-44);
/// - the transfer program follows the escrow's mint binding;
/// - AV-99: the plan's transfer-hook context matches the escrow's
///   declared hook binding exactly (mismatch →
///   [`CpiError::SettlementMismatch`); the plan annotates the hook
///   program and its extra accounts.
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
    if escrow.mint().is_none() && !escrow.payout_recipient_allowed(addrs.taker_leg) {
        // Native path: the payout goes to the policy-approved
        // destination — the taker, or an AV-49 allowlist member. A
        // different destination would bypass the payout pin above.
        return Err(CpiError::RecipientMismatch);
    }

    let mut transfers = Vec::with_capacity(2);
    if payout > 0 {
        transfers.push(leg(escrow, addrs.source, addrs.vault_authority, addrs.taker_leg, payout)?);
    }
    push_fee_leg(escrow, addrs.source, addrs.vault_authority, addrs.fee_leg, fee, &mut transfers)?;
    // AV-99: the hook gate runs after every other check — a plan that
    // fails amount/recipient validation never reaches hook annotation.
    let (transfer_hook_program, transfer_hook_accounts) =
        check_transfer_hook(escrow, &addrs.transfer_hook)?;
    Ok(SettlementPlan {
        transfers,
        transfer_hook_program,
        transfer_hook_accounts,
    })
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
///   initializer;
/// - AV-99: the plan's transfer-hook context matches the escrow's
///   declared hook binding exactly (mismatch →
///   [`CpiError::SettlementMismatch`); the plan annotates the hook
///   program and its extra accounts.
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
    match kind {
        RefundKind::Cancel | RefundKind::CancelExpired => {
            if addrs.refund_to != escrow.refund_recipient() {
                return Err(CpiError::RecipientMismatch);
            }
        }
        // AV-109: the heir's inactivity reclaim routes to the
        // configured heir — deliberately not the refund policy.
        // Pinning `refund_recipient()` here would either reject the
        // heir or, worse, let a plan pay the initializer the heir's
        // funds. A deadman reclaim carries no anti-griefing penalty
        // (the heir is never the taker), so `penalty` must be zero.
        RefundKind::DeadmanClaim => {
            let heir = escrow.deadman_heir().ok_or(CpiError::RecipientMismatch)?;
            if addrs.refund_to != heir {
                return Err(CpiError::RecipientMismatch);
            }
            if penalty != 0 {
                return Err(CpiError::SettlementMismatch);
            }
        }
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
    // AV-99: hook gate after every other check, like `payout_plan`.
    let (transfer_hook_program, transfer_hook_accounts) =
        check_transfer_hook(escrow, &addrs.transfer_hook)?;
    Ok(SettlementPlan {
        transfers,
        transfer_hook_program,
        transfer_hook_accounts,
    })
}

/// Build the transfers for a dispute settlement after `resolve` returned
/// `(taker_payout, fee, refund)`.
///
/// Consistency checks:
/// - the escrow is `Settled`;
/// - `taker_payout + fee` cannot exceed `released_amount()` plus the
///   cumulative taker-attributed yield (`interest_paid`, AV-107/AV-119:
///   the taker's share of a dispute settlement's yield claim rides the
///   taker payout, so the gross legitimately exceeds the released
///   principal by at most the yield ever paid to the taker);
/// - `refund` cannot exceed the post-settlement remainder
///   (`amount - released_amount()`) plus the cumulative
///   initializer-attributed dispute yield (`dispute_interest`, AV-119:
///   the initializer's share of the yield claim rides the refund);
/// - taker / initializer identities pinned; native-path legs go to the
///   pinned wallets;
/// - `addrs.fee_leg` equals the escrow's pinned fee recipient when one
///   is configured (AV-44);
/// - AV-99: the plan's transfer-hook context matches the escrow's
///   declared hook binding exactly (mismatch →
///   [`CpiError::SettlementMismatch`); the plan annotates the hook
///   program and its extra accounts.
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
    // AV-119: the taker's gross may exceed the released principal by
    // the yield attributed to the taker — bounded above by the
    // cumulative `interest_paid` sink (sound upper bound: it includes
    // this settlement's taker share plus any earlier harvests, all of
    // which legitimately went to the taker).
    let taker_ceiling = escrow
        .released_amount()
        .checked_add(escrow.interest_paid())
        .ok_or(CpiError::ArithmeticOverflow)?;
    if taker_gross > taker_ceiling {
        return Err(CpiError::SettlementMismatch);
    }
    let remainder = escrow.amount().saturating_sub(escrow.released_amount());
    // AV-119: the refund may exceed the principal remainder by the
    // yield attributed to the initializer — bounded above by the
    // cumulative `dispute_interest` sink (sound upper bound, same
    // reasoning as the taker leg).
    let refund_ceiling = remainder
        .checked_add(escrow.dispute_interest())
        .ok_or(CpiError::ArithmeticOverflow)?;
    if refund > refund_ceiling {
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
        // Native path: the taker leg goes to the policy-approved
        // destination (taker or AV-49 allowlist member); the refund leg
        // still goes to the initializer.
        if taker_gross > 0 && !escrow.payout_recipient_allowed(addrs.taker_leg) {
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
    // AV-99: hook gate after every other check, like `payout_plan`.
    let (transfer_hook_program, transfer_hook_accounts) =
        check_transfer_hook(escrow, &addrs.transfer_hook)?;
    Ok(SettlementPlan {
        transfers,
        transfer_hook_program,
        transfer_hook_accounts,
    })
}

#[cfg(test)]
mod cpi_tests {
    use super::*;

    const FUND_AT: u64 = 1_700_000_000;
    use crate::{Escrow, EscrowError, VestingSchedule};

    fn key(n: u8) -> Pubkey {
        [n; 32]
    }

    fn funded_escrow(amount: u64) -> Escrow {
        let init = key(1);
        let taker = key(2);
        let mut e = Escrow::initialize(init, taker, amount, u64::MAX).unwrap();
        e.fund(init, FUND_AT).unwrap();
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
            transfer_hook: None,
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
        e.fund(init, FUND_AT).unwrap();
        // Protocol fee: 1% → fee 5_000 on a 500_000 release.
        let (payout, fee) = e.release(init, 0, 500_000, None, key(2)).unwrap();
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
        let (payout, fee) = e.release(key(1), 0, 1_000_000, None, key(2)).unwrap();
        assert_eq!(fee, 0);
        let plan = payout_plan(PayoutKind::Release, &e, &payout_addrs_native(), payout, fee).unwrap();
        assert_eq!(plan.transfers.len(), 1);
        assert_eq!(plan.transfers[0].amount(), Some(1_000_000));
    }

    #[test]
    fn release_plan_rejects_tampered_amounts() {
        let mut e = funded_escrow(1_000_000);
        let (payout, fee) = e.release(key(1), 0, 400_000, None, key(2)).unwrap();
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
        let (payout, fee) = e.release(key(1), 0, 1_000_000, None, key(2)).unwrap();
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
        e.fund(init, FUND_AT).unwrap();
        // Half vested at t=1500.
        let (payout, fee) = e.claim(taker, 1500, None, key(2)).unwrap();
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
        e.fund(init, FUND_AT).unwrap();
        let (payout, fee) = e.release(init, 0, 1_000_000, Some(mint), key(2)).unwrap();
        assert_eq!(fee, 0);

        let addrs = PayoutAddrs {
            source: key(11),          // vault token account
            vault_authority: key(10), // vault PDA signs via seeds
            taker,
            taker_leg: key(12), // taker's associated token account
            fee_leg: key(9),
            transfer_hook: None,
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
            transfer_hook: None,
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
        e.fund(init, FUND_AT).unwrap();
        let (refund, penalty) = e.cancel_expired(taker, 1000, None, init).unwrap();
        assert!(penalty > 0 && refund + penalty == 1_000_000);
        let addrs = RefundAddrs {
            source: key(10),
            vault_authority: key(10),
            initializer: init,
            refund_to: init,
            refund_leg: init,
            penalty_leg: init,
            transfer_hook: None,
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
            transfer_hook: None,
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

    // --- AV-109: deadman-claim refund plans -----------------------------------------

    fn deadman_escrow() -> Escrow {
        let heir = key(9);
        let mut e = Escrow::initialize(key(1), key(2), 1_000_000, 2_000_000_000)
            .unwrap()
            .with_deadman_switch(86_400, heir)
            .unwrap();
        e.fund(key(1), FUND_AT).unwrap();
        e
    }

    #[test]
    fn deadman_claim_plan_pays_the_heir() {
        let mut e = deadman_escrow();
        let paid = e.claim_deadman(key(9), FUND_AT + 86_400).unwrap();
        assert_eq!(paid, 1_000_000);
        assert_eq!(e.state(), EscrowState::Cancelled);
        let addrs = RefundAddrs {
            source: key(10),
            vault_authority: key(10),
            initializer: key(1),
            // The refund sink is the heir — not the initializer, not the
            // AV-23 refund policy.
            refund_to: key(9),
            refund_leg: key(9),
            penalty_leg: key(9),
            transfer_hook: None,
        };
        let plan = refund_plan(RefundKind::DeadmanClaim, &e, &addrs, 1_000_000, 0).unwrap();
        assert_eq!(plan.transfers.len(), 1);
        assert_eq!(plan.transfers[0].amount(), Some(1_000_000));
        assert_eq!(plan.transfers[0].accounts[1].pubkey, key(9));
    }

    #[test]
    fn deadman_claim_plan_rejects_misrouted_recipients() {
        let mut e = deadman_escrow();
        e.claim_deadman(key(9), FUND_AT + 86_400).unwrap();
        let addrs = RefundAddrs {
            source: key(10),
            vault_authority: key(10),
            initializer: key(1),
            refund_to: key(9),
            refund_leg: key(9),
            penalty_leg: key(9),
            transfer_hook: None,
        };
        // Routing the heir's funds to the initializer: rejected — this
        // is exactly the misroute the heir pin exists to prevent.
        let mut to_init = addrs.clone();
        to_init.refund_to = key(1);
        to_init.refund_leg = key(1);
        assert_eq!(
            refund_plan(RefundKind::DeadmanClaim, &e, &to_init, 1_000_000, 0),
            Err(CpiError::RecipientMismatch)
        );
        // A penalty on a deadman reclaim: the state machine never
        // produces one (the heir is never the taker).
        assert_eq!(
            refund_plan(RefundKind::DeadmanClaim, &e, &addrs, 999_999, 1),
            Err(CpiError::SettlementMismatch)
        );
        // No switch configured: no heir to pin.
        let mut plain = funded_escrow(1_000_000);
        plain.cancel(key(1), None, key(1)).unwrap();
        assert_eq!(
            refund_plan(RefundKind::DeadmanClaim, &plain, &addrs, 1_000_000, 0),
            Err(CpiError::RecipientMismatch)
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
        e.fund(init, FUND_AT).unwrap();
        e.escalate(taker, 0, None, None, 0).unwrap();
        let (taker_payout, fee, refund) = e.resolve(arbiter, 600_000, 0, None, None, key(2)).unwrap();
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
            transfer_hook: None,
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

    // AV-119: the CPI plan must accept the dispute-interest triple —
    // the taker leg carries the taker's yield share and the refund leg
    // carries the initializer's yield share, so both legitimately exceed
    // their principal-only bounds.
    #[test]
    fn resolve_plan_accepts_dispute_interest_legs() {
        let init = key(1);
        let taker = key(2);
        let arbiter = key(5);
        let mut e = Escrow::initialize(init, taker, 1_000_000, u64::MAX)
            .unwrap()
            .with_arbiter(arbiter)
            .unwrap()
            .with_interest(500) // 5% p.a.
            .unwrap();
        e.fund(init, FUND_AT).unwrap();
        // 36.5 days to the dispute: 5_000 of yield; one full dispute year
        // adds 50_000 more — total claim 55_000.
        let disputed_at = FUND_AT + 3_153_600;
        e.escalate(taker, disputed_at, None, None, 0).unwrap();
        // Partial ruling: 600k to the taker, 400k refunded.
        let (taker_payout, fee, refund) = e
            .resolve(arbiter, 600_000, disputed_at + 31_536_000, None, None, key(2))
            .unwrap();
        assert_eq!(fee, 0);
        assert_eq!(e.interest_paid(), 33_000, "taker's 60% of the claim");
        assert_eq!(
            e.dispute_interest(),
            22_000,
            "initializer's 40% of the claim"
        );
        assert_eq!(taker_payout, 600_000 + 33_000);
        assert_eq!(refund, 400_000 + 22_000);
        let addrs = ResolveAddrs {
            source: key(10),
            vault_authority: key(10),
            taker,
            taker_leg: taker,
            fee_leg: key(9),
            initializer: init,
            refund_leg: init,
            transfer_hook: None,
        };
        // Both legs exceed their principal-only bounds (600k / 400k)
        // and must still validate.
        let plan = resolve_plan(&e, &addrs, taker_payout, fee, refund).unwrap();
        assert_eq!(plan.total_amount(), 1_000_000 + 55_000);
        // But an inflated leg beyond the yield sinks is still caught.
        assert_eq!(
            resolve_plan(&e, &addrs, taker_payout, fee, refund + 1),
            Err(CpiError::SettlementMismatch)
        );
        assert_eq!(
            resolve_plan(&e, &addrs, taker_payout + 1, fee, refund),
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
        e.fund(init, FUND_AT).unwrap();
        e.escalate(taker, 0, None, None, 0).unwrap();
        let (taker_payout, fee, refund) = e.resolve(arbiter, 600_000, 0, None, None, key(2)).unwrap();
        assert!(fee > 0);
        let addrs = ResolveAddrs {
            source: key(10),
            vault_authority: key(10),
            taker,
            taker_leg: taker,
            fee_leg: key(9),
            initializer: init,
            refund_leg: init,
            transfer_hook: None,
        };
        let plan = resolve_plan(&e, &addrs, taker_payout, fee, refund).unwrap();
        assert_eq!(plan.transfers.len(), 3);
        assert_eq!(plan.total_amount(), 1_000_000);
    }

    // --- AV-44: fee-recipient pinning ------------------------------------------

    #[test]
    fn fee_recipient_pin_rejects_swapped_fee_leg() {
        let init = key(1);
        let recipient = key(7);
        let mut e = Escrow::initialize(init, key(2), 1_000_000, u64::MAX)
            .unwrap()
            .with_protocol_fee(100)
            .unwrap()
            .with_fee_recipient(recipient)
            .unwrap();
        e.fund(init, FUND_AT).unwrap();
        // Protocol fee: 1% → fee 5_000 on a 500_000 release.
        let (payout, fee) = e.release(init, 0, 500_000, None, key(2)).unwrap();
        assert_eq!((payout, fee), (495_000, 5_000));

        // A swapped fee destination is rejected, not built.
        let mut addrs = payout_addrs_native();
        addrs.fee_leg = key(8);
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee),
            Err(CpiError::RecipientMismatch)
        );
        // The pinned recipient builds, and the fee leg points at it.
        addrs.fee_leg = recipient;
        let plan = payout_plan(PayoutKind::Release, &e, &addrs, payout, fee).unwrap();
        assert_eq!(plan.transfers.len(), 2);
        assert_eq!(plan.transfers[1].amount(), Some(5_000));
        assert_eq!(plan.transfers[1].accounts[1].pubkey, recipient);
    }

    #[test]
    fn fee_recipient_pin_applies_to_resolve_plan() {
        let init = key(1);
        let taker = key(2);
        let arbiter = key(5);
        let recipient = key(7);
        let mut e = Escrow::initialize(init, taker, 1_000_000, u64::MAX)
            .unwrap()
            .with_arbiter(arbiter)
            .unwrap()
            .with_protocol_fee(200) // 2%
            .unwrap()
            .with_fee_recipient(recipient)
            .unwrap();
        e.fund(init, FUND_AT).unwrap();
        e.escalate(taker, 0, None, None, 0).unwrap();
        let (taker_payout, fee, refund) = e.resolve(arbiter, 600_000, 0, None, None, key(2)).unwrap();
        // 2% of 600_000 = 12_000 fee; the initializer is refunded the rest.
        assert_eq!((taker_payout, fee, refund), (588_000, 12_000, 400_000));

        let mut addrs = ResolveAddrs {
            source: key(10),
            vault_authority: key(10),
            taker,
            taker_leg: taker,
            fee_leg: key(8), // swapped
            initializer: init,
            refund_leg: init,
            transfer_hook: None,
        };
        assert_eq!(
            resolve_plan(&e, &addrs, taker_payout, fee, refund),
            Err(CpiError::RecipientMismatch)
        );
        addrs.fee_leg = recipient;
        let plan = resolve_plan(&e, &addrs, taker_payout, fee, refund).unwrap();
        assert_eq!(plan.transfers.len(), 3); // taker leg + fee leg + refund leg
        assert!(plan
            .transfers
            .iter()
            .any(|t| t.accounts[1].pubkey == recipient && t.amount() == Some(12_000)));
        assert_eq!(plan.total_amount(), 1_000_000);
    }

    #[test]
    fn no_fee_recipient_keeps_program_level_fee_leg() {
        // Backward compatibility: with no pinned recipient any nonzero
        // fee_leg stands (the program-level fee account).
        let init = key(1);
        let mut e = Escrow::initialize(init, key(2), 1_000_000, u64::MAX)
            .unwrap()
            .with_protocol_fee(100)
            .unwrap();
        e.fund(init, FUND_AT).unwrap();
        let (payout, fee) = e.release(init, 0, 500_000, None, key(2)).unwrap();
        let plan = payout_plan(PayoutKind::Release, &e, &payout_addrs_native(), payout, fee).unwrap();
        assert_eq!(plan.transfers.len(), 2);
        assert_eq!(plan.transfers[1].accounts[1].pubkey, key(9));
    }

    // --- AV-99: Token-2022 transfer-hook compatibility ---------------------------

    #[test]
    fn transfer_hook_builder_matrix() {
        let hook = [0x77; 32];
        let mint = [0xD0; 32];
        // Happy path: Uninitialized + mint bound + nonzero program id.
        let e = Escrow::initialize(key(1), key(2), 1_000_000, u64::MAX)
            .unwrap()
            .with_mint(mint)
            .unwrap()
            .with_transfer_hook(hook)
            .unwrap();
        assert_eq!(e.transfer_hook(), Some(hook));
        // Zero program id: a hook that is nowhere cannot be pinned.
        assert_eq!(
            Escrow::initialize(key(1), key(2), 1_000_000, u64::MAX)
                .unwrap()
                .with_mint(mint)
                .unwrap()
                .with_transfer_hook([0u8; 32]),
            Err(EscrowError::InvalidTransferHook)
        );
        // No mint bound: a transfer hook is a Token-2022 concept,
        // meaningless on the native-SOL path.
        assert_eq!(
            Escrow::initialize(key(1), key(2), 1_000_000, u64::MAX)
                .unwrap()
                .with_transfer_hook(hook),
            Err(EscrowError::InvalidTransferHook)
        );
        // Builder is Uninitialized-only.
        let mut funded = Escrow::initialize(key(1), key(2), 1_000_000, u64::MAX)
            .unwrap()
            .with_mint(mint)
            .unwrap();
        funded.fund(key(1), FUND_AT).unwrap();
        assert_eq!(
            funded.with_transfer_hook(hook),
            Err(EscrowError::InvalidStateTransition)
        );
        // The new error code is pinned (never renumbered).
        assert_eq!(EscrowError::InvalidTransferHook.code(), 157);
    }

    fn hook_escrow() -> (Escrow, Pubkey) {
        let hook = [0x77; 32];
        let mint = [0xD0; 32];
        let mut e = Escrow::initialize(key(1), key(2), 1_000_000, u64::MAX)
            .unwrap()
            .with_mint(mint)
            .unwrap()
            .with_transfer_hook(hook)
            .unwrap();
        e.fund(key(1), FUND_AT).unwrap();
        (e, hook)
    }

    fn hook_plan(hook: Pubkey) -> TransferHookPlan {
        TransferHookPlan {
            program: hook,
            extra_accounts: vec![
                AccountMeta { pubkey: key(20), is_signer: false, is_writable: true },
                AccountMeta { pubkey: key(21), is_signer: false, is_writable: false },
            ],
        }
    }

    fn hook_payout_addrs(hook: Pubkey) -> PayoutAddrs {
        PayoutAddrs {
            source: key(11),
            vault_authority: key(10),
            taker: key(2),
            taker_leg: key(12),
            fee_leg: key(9),
            transfer_hook: Some(hook_plan(hook)),
        }
    }

    #[test]
    fn matching_hook_plan_annotates_program_and_extra_accounts() {
        let (mut e, hook) = hook_escrow();
        let mint = [0xD0; 32];
        let (payout, fee) = e.release(key(1), 0, 1_000_000, Some(mint), key(2)).unwrap();
        let plan = payout_plan(PayoutKind::Release, &e, &hook_payout_addrs(hook), payout, fee).unwrap();
        assert_eq!(plan.transfer_hook_program, Some(hook));
        assert_eq!(plan.transfer_hook_accounts.len(), 2);
        assert_eq!(plan.transfer_hook_accounts[0].pubkey, key(20));
        assert_eq!(plan.transfer_hook_accounts[1].pubkey, key(21));
        // The money movement itself is unchanged: one SPL-token leg.
        assert_eq!(plan.transfers.len(), 1);
        assert_eq!(plan.transfers[0].program_id, spl_token_program_id());
    }

    #[test]
    fn hook_mismatch_matrix_fails_closed() {
        let (mut e, hook) = hook_escrow();
        let mint = [0xD0; 32];
        let (payout, fee) = e.release(key(1), 0, 1_000_000, Some(mint), key(2)).unwrap();
        // Escrow declares a hook, plan names none → SettlementMismatch.
        let mut addrs = hook_payout_addrs(hook);
        addrs.transfer_hook = None;
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee),
            Err(CpiError::SettlementMismatch)
        );
        // Escrow declares a hook, plan names a different program →
        // SettlementMismatch (a swapped hook is never built).
        let mut addrs = hook_payout_addrs([0x78; 32]);
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee),
            Err(CpiError::SettlementMismatch)
        );
        // Escrow declares no hook, plan names one → SettlementMismatch
        // (the plan claims hook execution the escrow never authorized).
        let mut e2 = funded_escrow(1_000_000);
        let (payout2, fee2) = e2.release(key(1), 0, 1_000_000, None, key(2)).unwrap();
        let mut addrs2 = payout_addrs_native();
        addrs2.transfer_hook = Some(hook_plan(hook));
        assert_eq!(
            payout_plan(PayoutKind::Release, &e2, &addrs2, payout2, fee2),
            Err(CpiError::SettlementMismatch)
        );
        // No hook on either side → clean plan, empty annotation.
        let addrs3 = payout_addrs_native();
        let plan = payout_plan(PayoutKind::Release, &e2, &addrs3, payout2, fee2).unwrap();
        assert_eq!(plan.transfer_hook_program, None);
        assert!(plan.transfer_hook_accounts.is_empty());
    }

    #[test]
    fn hook_gate_applies_to_refund_and_resolve_plans() {
        let hook = [0x77; 32];
        let mint = [0xD0; 32];
        // Refund plan with a declared hook.
        let mut e = Escrow::initialize(key(1), key(2), 1_000_000, 1_000_000)
            .unwrap()
            .with_mint(mint)
            .unwrap()
            .with_transfer_hook(hook)
            .unwrap();
        e.fund(key(1), FUND_AT).unwrap();
        e.cancel(key(1), Some(mint), key(1)).unwrap();
        let mut raddrs = RefundAddrs {
            source: key(11),
            vault_authority: key(10),
            initializer: key(1),
            refund_to: key(1),
            refund_leg: key(1),
            penalty_leg: key(1),
            transfer_hook: Some(hook_plan(hook)),
        };
        let plan = refund_plan(RefundKind::Cancel, &e, &raddrs, 1_000_000, 0).unwrap();
        assert_eq!(plan.transfer_hook_program, Some(hook));
        raddrs.transfer_hook = Some(hook_plan([0x78; 32]));
        assert_eq!(
            refund_plan(RefundKind::Cancel, &e, &raddrs, 1_000_000, 0),
            Err(CpiError::SettlementMismatch)
        );
    }

    #[test]
    fn transfer_hook_persists_in_serialized_tail() {
        // The hook program id rides the vault account layout just
        // before the AV-100 streaming-fee region (33 bytes:
        // discriminant + program id), appended after the auction
        // region — earlier offsets unchanged.
        let hook = [0x77; 32];
        let e = Escrow::initialize(key(1), key(2), 1_000_000, u64::MAX)
            .unwrap()
            .with_mint([0xD0; 32])
            .unwrap()
            .with_transfer_hook(hook)
            .unwrap();
        let bytes = crate::account_space_tests::encode_escrow(&e);
        assert_eq!(bytes.len(), crate::ESCROW_BODY_LEN);
        let hook_at =
            crate::ESCROW_BODY_LEN - crate::CLAIM_COOLDOWN_TAIL_LEN - crate::COUNTER_OFFER_TAIL_LEN - crate::DISPUTE_INTEREST_LEN - crate::PRICE_GATE_LEN - crate::PENALTY_ESCALATION_TAIL_LEN - crate::COMPOUND_INTEREST_TAIL_LEN - crate::SLOT_TIMELOCK_TAIL_LEN - crate::RELEASE_COOLING_TAIL_LEN - crate::FUNDING_TAIL_LEN - crate::RENT_TOP_UP_LEN - crate::DEADMAN_REGION_LEN - crate::PAYOUT_SPLIT_LEN - crate::INTEREST_REGION_LEN - crate::POOL_REGION_LEN - crate::SWAP_LINK_REGION_LEN - crate::APPEAL_BOND_REGION_LEN - crate::DELEGATION_REGION_LEN - crate::STREAMING_FEE_REGION_LEN - 33;
        assert_eq!(bytes[hook_at], 1, "Some discriminant");
        assert_eq!(&bytes[hook_at + 1..hook_at + 33], &hook);
        // A hook-less escrow zero-fills the region.
        let plain = Escrow::initialize(key(1), key(2), 1_000_000, u64::MAX).unwrap();
        let bytes = crate::account_space_tests::encode_escrow(&plain);
        assert_eq!(&bytes[hook_at..hook_at + 33], &[0u8; 33]);
        // The streaming-fee region trails the hook region, zeroed by
        // default; the appeal-bond region trails it, and the AV-104
        // delegation region is the new tail.
        assert_eq!(
            &bytes[crate::ESCROW_BODY_LEN
                - crate::PRICE_GATE_LEN - crate::PENALTY_ESCALATION_TAIL_LEN - crate::COMPOUND_INTEREST_TAIL_LEN - crate::SLOT_TIMELOCK_TAIL_LEN - crate::APPEAL_BOND_REGION_LEN
                - crate::DELEGATION_REGION_LEN
                - crate::STREAMING_FEE_REGION_LEN..crate::ESCROW_BODY_LEN
                - crate::PRICE_GATE_LEN - crate::PENALTY_ESCALATION_TAIL_LEN - crate::COMPOUND_INTEREST_TAIL_LEN - crate::SLOT_TIMELOCK_TAIL_LEN - crate::APPEAL_BOND_REGION_LEN
                - crate::DELEGATION_REGION_LEN],
            &[0u8; 16]
        );
        assert_eq!(
            &bytes[crate::ESCROW_BODY_LEN
                - crate::PRICE_GATE_LEN - crate::PENALTY_ESCALATION_TAIL_LEN - crate::COMPOUND_INTEREST_TAIL_LEN - crate::SLOT_TIMELOCK_TAIL_LEN - crate::SWAP_LINK_REGION_LEN
                - crate::DELEGATION_REGION_LEN
                - crate::STREAMING_FEE_REGION_LEN
                - crate::APPEAL_BOND_REGION_LEN
                ..crate::ESCROW_BODY_LEN
                    - crate::PRICE_GATE_LEN - crate::PENALTY_ESCALATION_TAIL_LEN - crate::COMPOUND_INTEREST_TAIL_LEN - crate::SLOT_TIMELOCK_TAIL_LEN - crate::SWAP_LINK_REGION_LEN
                    - crate::DELEGATION_REGION_LEN
                    - crate::STREAMING_FEE_REGION_LEN],
            &[0u8; 16]
        );
    }
}
