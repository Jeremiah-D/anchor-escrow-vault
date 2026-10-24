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
//!
//! AV-166 adds the Token-2022 mint path: [`token_transfer_checked`]
//! builds the `TransferChecked` instruction (index 12, shared by both
//! token programs) for Token-2022 mints, [`token_program_kind`]
//! auto-dispatches a program id to its [`TokenProgram`] kind, and
//! [`MintDescriptor`] carries the extension awareness — the
//! transfer-fee schedule ([`TransferFeeSchedule::net_amount`] computes
//! the actual-to-arrive net under withheld fees), the mint decimals,
//! and the metadata extension as a read-only view ([`TokenMetadata`]).
//! Settlement plans take an optional `token_program` on their address
//! structs: `None` keeps the legacy SPL `Transfer` behavior
//! byte-identical; `Some` must name a known token program.

use std::sync::OnceLock;

use super::{parse_mint_address, Escrow, EscrowState};
use crate::confidential::{ConfidentialTransferMint, CONFIDENTIAL_TRANSFER_WITHDRAW_IX};

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
    /// System transfers encode a u64 at bytes 4..12; token-program
    /// transfers encode a u64 at bytes 1..9 — for the plain `Transfer`
    /// (index 3), `TransferChecked` (index 12, AV-166), and the
    /// Token-2022 confidential `Withdraw` (index 8 with the pinned
    /// 28-byte layout, AV-168) — on either the SPL Token program or
    /// Token-2022. An unknown program or instruction index decodes to
    /// `None`.
    pub fn amount(&self) -> Option<u64> {
        let bytes: [u8; 8] = if self.program_id == system_program_id() {
            self.data.get(4..12)?.try_into().ok()?
        } else if self.program_id == spl_token_program_id()
            || self.program_id == token_2022_program_id()
        {
            // The token transfer layouts carry the u64 amount at
            // bytes 1..9; anything else is not a transfer this module
            // built.
            match self.data.first() {
                Some(3) | Some(&TRANSFER_CHECKED_IX) => {
                    self.data.get(1..9)?.try_into().ok()?
                }
                // AV-168: the confidential Withdraw pins a 28-byte
                // layout with the amount at bytes 1..9.
                Some(&CONFIDENTIAL_TRANSFER_WITHDRAW_IX) if self.data.len() == 28 => {
                    self.data.get(1..9)?.try_into().ok()?
                }
                _ => return None,
            }
        } else {
            return None;
        };
        Some(u64::from_le_bytes(bytes))
    }

    /// Decimals asserted by a `TransferChecked` instruction (index 12 on
    /// either token program, AV-166); `None` for anything else.
    pub fn transfer_checked_decimals(&self) -> Option<u8> {
        if (self.program_id == spl_token_program_id()
            || self.program_id == token_2022_program_id())
            && self.data.first() == Some(&TRANSFER_CHECKED_IX)
        {
            self.data.get(9).copied()
        } else {
            None
        }
    }

    /// Amount carried by a Token-2022 confidential-transfer `Withdraw`
    /// (index 8, AV-168): the `u64` at bytes 1..9 of the 28-byte
    /// layout. Equivalent to [`amount`](Self::amount) for this
    /// instruction — the dedicated accessor pins the layout
    /// explicitly, mirroring
    /// [`transfer_checked_decimals`](Self::transfer_checked_decimals).
    /// `None` for anything else.
    pub fn confidential_withdraw_amount(&self) -> Option<u64> {
        if self.program_id == token_2022_program_id()
            && self.data.first() == Some(&CONFIDENTIAL_TRANSFER_WITHDRAW_IX)
            && self.data.len() == 28
        {
            self.data.get(1..9)?.try_into().ok().map(u64::from_le_bytes)
        } else {
            None
        }
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
    /// AV-132: the caller's slippage floor exceeds the quoted payout —
    /// the plan is never built, so the executor never runs. The
    /// off-chain counterpart of
    /// [`super::EscrowError::SlippageExceeded`]: the plan gate rejects
    /// before execution, the state machine rejects after it.
    SlippageExceeded,
    /// AV-166: the named token program is neither the SPL Token program
    /// nor Token-2022 — the CPI layer pins layouts for exactly those
    /// two, so an instruction for anything else is never built. Also
    /// raised when a token program is named on the native-SOL path
    /// (there is no token program there).
    UnsupportedTokenProgram,
    /// AV-166: decimals out of range — above the AV-28 ceiling (18) on
    /// a mint binding, or above 9 on a `TransferChecked` (on-chain mints
    /// carry at most 9 decimals).
    InvalidDecimals,
    /// AV-166: a transfer-fee schedule that cannot exist on-chain —
    /// `basis_points > 10_000` (more than 100%).
    InvalidTransferFee,
    /// AV-166: a Token-2022 extension declared on the legacy SPL Token
    /// program — transfer fees and the metadata extension are
    /// Token-2022 concepts and meaningless there.
    IncompatibleTokenExtension,
    /// AV-168: a confidential `Withdraw` was sequenced before
    /// `ApplyPendingBalance` — withdrawing from a confidential
    /// account whose pending balance was never applied would strand
    /// the pending amount, so the sequence builder refuses to emit
    /// the instruction instead of building a doomed transaction.
    ConfidentialPendingNotApplied,
    /// AV-168: `ApplyPendingBalance` was sequenced twice on the same
    /// confidential settlement — the second apply is a caller bug
    /// (the pending balance is already settled), failed loud instead
    /// of emitting a duplicate instruction.
    ConfidentialAlreadyApplied,
    /// AV-172: the callee's post-execution return data does not match
    /// the declared return layout — wrong attesting program, wrong
    /// discriminant, truncated payload, or an attested amount
    /// different from the planned settlement amount. The settlement
    /// is rejected *after* execution: a CPI that "succeeded" but
    /// delivered the wrong amount never settles. The execution-after
    /// counterpart to the AV-132 slippage pre-check
    /// ([`CpiError::SlippageExceeded`], which rejects before
    /// execution); see [`super::cpi_return::verify_cpi_return_data`]
    /// and the Anchor skeleton's `cpi_verify_return_data`.
    CpiReturnDataMismatch,
    /// AV-172: no return data was observed and the missing-data policy
    /// is
    /// [`MissingReturnDataPolicy::FailClosed`](super::cpi_return::MissingReturnDataPolicy)
    /// (the default) — a program that attests nothing proves nothing,
    /// so the settlement fails instead of proceeding unverified.
    CpiReturnDataMissing,
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

// ---------------------------------------------------------------------------
// AV-166: Token-2022 `TransferChecked` + extension awareness.
// ---------------------------------------------------------------------------

/// The Token-2022 program
/// (`TokenzQdBNbLqP5VEhdk8jV5pPdibZ5gLL8X26sFEY`), decoded with the same
/// base58 decoder as the SPL Token program id — one decoder, one tested
/// code path.
pub fn token_2022_program_id() -> Pubkey {
    static TOKEN_2022_PROGRAM: OnceLock<Pubkey> = OnceLock::new();
    *TOKEN_2022_PROGRAM.get_or_init(|| {
        parse_mint_address("TokenzQdBNbLqP5VEhdk8jV5pPdibZ5gLL8X26sFEY")
            .expect("hardcoded Token-2022 program id must decode")
    })
}

/// Which token program owns a mint: the legacy SPL Token program or
/// Token-2022. Native SOL is not a token program — there is no mint to
/// own — so the system program id (or any other unknown program id)
/// does not map to a kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenProgram {
    /// Legacy SPL Token
    /// (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`).
    SplToken,
    /// Token-2022 (`TokenzQdBNbLqP5VEhdk8jV5pPdibZ5gLL8X26sFEY`).
    Token2022,
}

/// Auto-dispatch a token program id to its [`TokenProgram`] kind — the
/// AV-166 routing rule: the plan's `token_program` (or a keeper's mint
/// binding) names the program, and this decides which transfer
/// instruction the CPI layer builds. Anything that is not one of the
/// two known token programs fails with
/// [`CpiError::UnsupportedTokenProgram`] instead of building an
/// instruction for a program whose layout this module does not pin.
pub fn token_program_kind(program_id: Pubkey) -> Result<TokenProgram, CpiError> {
    if program_id == spl_token_program_id() {
        Ok(TokenProgram::SplToken)
    } else if program_id == token_2022_program_id() {
        Ok(TokenProgram::Token2022)
    } else {
        Err(CpiError::UnsupportedTokenProgram)
    }
}

/// SPL Token / Token-2022 `TransferChecked` instruction index: `12`.
/// Both programs define the checked transfer at the same index with
/// the same layout, so one builder serves both.
pub const TRANSFER_CHECKED_IX: u8 = 12;

/// Build a `TransferChecked`: `authority` (signer) moves `amount` base
/// units of `mint` from `source` to `destination`, asserting the
/// amount's `decimals`.
///
/// Data layout (canonical): `u8` index `12` || `u64` amount (LE) || `u8`
/// decimals — 10 bytes. Accounts: source (writable), mint (readonly),
/// destination (writable), authority (signer) — the same meta order as
/// the plain `Transfer`.
///
/// Why checked: the plain [`spl_token_transfer`] moves raw base units
/// and trusts the caller to know the mint's decimals; `TransferChecked`
/// has the token program verify `decimals` against the mint account
/// on-chain, so a decimals mismatch between the escrow's AV-28
/// metadata and the real mint fails the transaction instead of moving
/// a mis-scaled amount. On-chain mints carry at most 9 decimals, so
/// `decimals > 9` is [`CpiError::InvalidDecimals`] here — an escrow
/// whose AV-28 decimals exceed 9 cannot settle through a real token
/// mint, and the plan fails loud instead of building bytes the token
/// program would reject.
pub fn token_transfer_checked(
    token_program: Pubkey,
    source: Pubkey,
    mint: Pubkey,
    destination: Pubkey,
    authority: Pubkey,
    amount: u64,
    decimals: u8,
) -> Result<TransferInstruction, CpiError> {
    // The layout is pinned per program — an unknown program never gets
    // an instruction, even if the caller "knows" it speaks
    // TransferChecked.
    token_program_kind(token_program)?;
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
    if decimals > 9 {
        return Err(CpiError::InvalidDecimals);
    }
    let mut data = Vec::with_capacity(10);
    data.push(TRANSFER_CHECKED_IX);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
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

/// A Token-2022 transfer-fee extension schedule, resolved by the caller
/// from the mint's TLV extension data (the epoch fee pair collapsed to
/// the active schedule — pure logic works on the resolved numbers,
/// never on chain state).
///
/// The fee is withheld *by the Token-2022 program* during the transfer:
/// the settlement instruction still moves the gross `amount`, but the
/// destination receives `amount − fee` and the fee accrues to the
/// mint's configured fee vault. [`TransferFeeSchedule::net_amount`]
/// computes what the taker actually receives, so the keeper can
/// reconcile gross (what the plan moved, pinned by the state machine)
/// against net (what landed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferFeeSchedule {
    /// Fee in basis points (hundredths of a percent): `100` = 1%.
    pub basis_points: u16,
    /// Maximum fee withheld per transfer, in base units.
    pub maximum_fee: u64,
}

impl TransferFeeSchedule {
    /// Validate the schedule: at most 100% (`basis_points <= 10_000`).
    /// The on-chain program rejects anything higher; the mirror fails
    /// loud instead of computing fees for a schedule that cannot exist.
    pub fn validate(&self) -> Result<(), CpiError> {
        if self.basis_points > 10_000 {
            return Err(CpiError::InvalidTransferFee);
        }
        Ok(())
    }

    /// Fee withheld from a transfer of `amount` base units: the ceiling
    /// of `amount * basis_points / 10_000`, capped at `maximum_fee` —
    /// the on-chain `calculate_fee` rule, computed in u128 so a
    /// `u64::MAX` transfer cannot overflow the intermediate. Callers
    /// should [`validate`](Self::validate) first; on an unvalidated
    /// schedule the cap still bounds the result.
    pub fn withheld_fee(&self, amount: u64) -> u64 {
        let raw = (amount as u128 * self.basis_points as u128 + 9_999) / 10_000;
        raw.min(self.maximum_fee as u128).min(amount as u128) as u64
    }

    /// What the destination actually receives: `amount − withheld_fee`.
    /// Infallible — the withheld fee never exceeds `amount` (see
    /// [`withheld_fee`](Self::withheld_fee)).
    pub fn net_amount(&self, amount: u64) -> u64 {
        amount - self.withheld_fee(amount)
    }
}

/// A Token-2022 metadata extension, as a **read-only view**.
///
/// The settlement layer never writes metadata — it only reads what the
/// mint declares (name / symbol / uri for operator display and
/// reconciliation labels). The struct therefore exposes getters only:
/// there is no setter, no `&mut` API, and construction happens once
/// through [`TokenMetadata::read`]. Cloning the view is the only way to
/// carry it; mutating it is impossible by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenMetadata {
    update_authority: Option<Pubkey>,
    mint: Pubkey,
    name: String,
    symbol: String,
    uri: String,
    additional: Vec<(String, String)>,
}

impl TokenMetadata {
    /// Read the metadata the mint declares. This is the single
    /// construction point — the "read" in read-only.
    pub fn read(
        update_authority: Option<Pubkey>,
        mint: Pubkey,
        name: String,
        symbol: String,
        uri: String,
        additional: Vec<(String, String)>,
    ) -> Self {
        Self { update_authority, mint, name, symbol, uri, additional }
    }

    /// The metadata update authority, if the mint sets one.
    pub fn update_authority(&self) -> Option<Pubkey> {
        self.update_authority
    }

    /// The mint this metadata describes.
    pub fn mint(&self) -> Pubkey {
        self.mint
    }

    /// The token name, as declared.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The token symbol, as declared.
    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    /// The off-chain metadata URI, as declared.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Additional key/value metadata pairs, as declared.
    pub fn additional_metadata(&self) -> &[(String, String)] {
        &self.additional
    }
}

/// The off-chain mint binding a settlement is built for: which mint,
/// which token program owns it, how many decimals the amounts are
/// denominated in, and the Token-2022 extensions the CPI layer is
/// aware of.
///
/// The caller assembles this from on-chain mint-account data (the
/// program id from the account owner, the decimals and TLV extensions
/// from the account data) plus the escrow's AV-28 decimals for the
/// cross-check. [`MintDescriptor::validate`] is the fail-loud gate:
/// unknown token programs, extension/program mismatches (transfer fees
/// and metadata are Token-2022 concepts — meaningless on the legacy SPL
/// program), and out-of-range decimals never reach instruction
/// construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintDescriptor {
    /// The mint account.
    pub mint: Pubkey,
    /// The program owning the mint account: the SPL Token or the
    /// Token-2022 program id.
    pub token_program: Pubkey,
    /// Decimals the settlement amounts are denominated in. Checked
    /// against the AV-28 ceiling (18) here; the `TransferChecked` path
    /// additionally requires `<= 9` (the on-chain mint maximum).
    pub decimals: u8,
    /// Token-2022 transfer-fee extension schedule, if the mint carries
    /// it. `Some` on the legacy SPL program is rejected — the extension
    /// does not exist there.
    pub transfer_fee: Option<TransferFeeSchedule>,
    /// Token-2022 metadata extension, read-only. Same program gate as
    /// the transfer fee.
    pub metadata: Option<TokenMetadata>,
    /// AV-168: Token-2022 confidential-transfer extension. Same
    /// program gate as the transfer fee and metadata — a legacy SPL
    /// Token mint carrying it fails validation.
    pub confidential_transfer: Option<ConfidentialTransferMint>,
}

impl MintDescriptor {
    /// Validate the binding, returning the [`ValidatedMint`] the
    /// instruction builders accept.
    pub fn validate(&self) -> Result<ValidatedMint, CpiError> {
        require_nonzero(&self.mint)?;
        let program = token_program_kind(self.token_program)?;
        if self.decimals > 18 {
            return Err(CpiError::InvalidDecimals);
        }
        match program {
            TokenProgram::SplToken => {
                // Transfer fees, the metadata extension, and the
                // confidential-transfer extension are Token-2022
                // concepts — a legacy SPL mint carrying any of them is
                // a caller bug, failed loud.
                if self.transfer_fee.is_some()
                    || self.metadata.is_some()
                    || self.confidential_transfer.is_some()
                {
                    return Err(CpiError::IncompatibleTokenExtension);
                }
            }
            TokenProgram::Token2022 => {
                if let Some(fee) = &self.transfer_fee {
                    fee.validate()?;
                }
                if self.decimals > 9 {
                    return Err(CpiError::InvalidDecimals);
                }
            }
        }
        Ok(ValidatedMint {
            mint: self.mint,
            program,
            program_id: self.token_program,
            decimals: self.decimals,
        })
    }
}

/// A [`MintDescriptor`] that passed [`MintDescriptor::validate`]: the
/// token program is known, the decimals are in range, and the
/// extensions are consistent with the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedMint {
    /// The mint account.
    pub mint: Pubkey,
    /// The token program kind that owns the mint.
    pub program: TokenProgram,
    /// The token program id (the SPL Token or Token-2022 program id).
    pub program_id: Pubkey,
    /// Decimals the settlement amounts are denominated in (`<= 9` on
    /// the Token-2022 path).
    pub decimals: u8,
}

/// Build the token transfer for a validated mint binding — the AV-166
/// auto-dispatch: legacy SPL Token mints keep the plain `Transfer`
/// (whose decimals live off-chain per AV-28), Token-2022 mints get
/// `TransferChecked` with the binding's decimals (verified on-chain
/// against the mint account).
pub fn token_leg(
    binding: &ValidatedMint,
    source: Pubkey,
    destination: Pubkey,
    authority: Pubkey,
    amount: u64,
) -> Result<TransferInstruction, CpiError> {
    match binding.program {
        TokenProgram::SplToken => {
            spl_token_transfer(source, binding.mint, destination, authority, amount)
        }
        TokenProgram::Token2022 => token_transfer_checked(
            binding.program_id,
            source,
            binding.mint,
            destination,
            authority,
            amount,
            binding.decimals,
        ),
    }
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
    /// AV-166: the token program owning the escrow's mint. `None` keeps
    /// the pre-AV-166 behavior — a bound mint settles through the legacy
    /// SPL Token program with the plain `Transfer` (decimals live
    /// off-chain per AV-28). `Some(id)` must be the SPL Token or the
    /// Token-2022 program id ([`token_program_kind`] auto-dispatches):
    /// Token-2022 mints settle through `TransferChecked` with the
    /// escrow's AV-28 decimals, verified on-chain against the mint.
    /// Naming a token program on the native-SOL path (or an unknown
    /// program id anywhere) fails with
    /// [`CpiError::UnsupportedTokenProgram`] — the plan is never built
    /// for a program whose layout this module does not pin.
    pub token_program: Option<Pubkey>,
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
    /// AV-166: the token program owning the escrow's mint. Same
    /// semantics as [`PayoutAddrs::token_program`].
    pub token_program: Option<Pubkey>,
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
    /// AV-166: the token program owning the escrow's mint. Same
    /// semantics as [`PayoutAddrs::token_program`].
    pub token_program: Option<Pubkey>,
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
/// native SOL → System Program, bound mint → the token program named
/// by `token_program` (AV-166): `None` keeps the legacy SPL Token
/// plain-`Transfer` behavior; `Some` auto-dispatches SPL Token vs
/// Token-2022 via [`token_program_kind`].
pub(crate) fn leg(
    escrow: &Escrow,
    source: Pubkey,
    vault_authority: Pubkey,
    destination: Pubkey,
    amount: u64,
    token_program: Option<Pubkey>,
) -> Result<TransferInstruction, CpiError> {
    match escrow.mint() {
        None => {
            // Native path: the vault PDA holds lamports directly, so the
            // source *is* the signing authority — and there is no token
            // program to name. A named program here is a caller bug,
            // failed loud instead of silently ignored.
            if token_program.is_some() {
                return Err(CpiError::UnsupportedTokenProgram);
            }
            if source != vault_authority {
                return Err(CpiError::SettlementMismatch);
            }
            system_transfer(source, destination, amount)
        }
        Some(mint) => {
            // AV-166 auto-dispatch: no program named → the legacy SPL
            // Token path (the pre-AV-166 behavior, byte-identical); a
            // named program must be a known token program.
            let kind = match token_program {
                None => TokenProgram::SplToken,
                Some(id) => token_program_kind(id)?,
            };
            match kind {
                TokenProgram::SplToken => {
                    spl_token_transfer(source, mint, destination, vault_authority, amount)
                }
                TokenProgram::Token2022 => token_transfer_checked(
                    token_2022_program_id(),
                    source,
                    mint,
                    destination,
                    vault_authority,
                    amount,
                    escrow.decimals(),
                ),
            }
        }
    }
}

pub(crate) fn push_fee_leg(
    escrow: &Escrow,
    source: Pubkey,
    vault_authority: Pubkey,
    fee_leg: Pubkey,
    fee: u64,
    token_program: Option<Pubkey>,
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
    transfers.push(leg(escrow, source, vault_authority, fee_leg, fee, token_program)?);
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
pub(crate) fn check_transfer_hook(
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
/// - AV-166: `addrs.token_program` auto-dispatches the mint path —
///   `None` keeps the legacy SPL Token plain `Transfer`; the
///   Token-2022 program id routes through `TransferChecked` with the
///   escrow's AV-28 decimals; an unknown program (or any program named
///   on the native-SOL path) fails with
///   [`CpiError::UnsupportedTokenProgram`];
/// - AV-99: the plan's transfer-hook context matches the escrow's
///   declared hook binding exactly (mismatch →
///   [`CpiError::SettlementMismatch`); the plan annotates the hook
///   program and its extra accounts.
/// - AV-132: when `min_payout` is `Some`, the slippage floor must not
///   exceed the quoted `payout` — a floor above the quote fails the
///   plan with [`CpiError::SlippageExceeded`] *before* the executor
///   ever runs, so a keeper never submits a CPI whose own quote
///   already violates the floor. `None` disables the check (the
///   pre-AV-132 behavior).
pub fn payout_plan(
    kind: PayoutKind,
    escrow: &Escrow,
    addrs: &PayoutAddrs,
    payout: u64,
    fee: u64,
    min_payout: Option<u64>,
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
    // AV-132: the slippage pre-check runs with the other amount
    // validations — a floor the quote cannot satisfy is a plan
    // construction error, not an execution outcome. It sits after the
    // machine-reconciliation check so a tampered payout still reports
    // SettlementMismatch first.
    if let Some(floor) = min_payout {
        if floor > payout {
            return Err(CpiError::SlippageExceeded);
        }
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
        transfers.push(leg(
            escrow,
            addrs.source,
            addrs.vault_authority,
            addrs.taker_leg,
            payout,
            addrs.token_program,
        )?);
    }
    push_fee_leg(
        escrow,
        addrs.source,
        addrs.vault_authority,
        addrs.fee_leg,
        fee,
        addrs.token_program,
        &mut transfers,
    )?;
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
    transfers.push(leg(
        escrow,
        addrs.source,
        addrs.vault_authority,
        addrs.refund_leg,
        refund,
        addrs.token_program,
    )?);
    if penalty > 0 {
        require_nonzero(&addrs.penalty_leg)?;
        // Note: on the native path with no refund whitelist, the refund
        // and the penalty both land on the initializer wallet — two legs
        // to the same account are valid; each leg's amount is pinned
        // above, so nothing merges silently.
        transfers.push(leg(
            escrow,
            addrs.source,
            addrs.vault_authority,
            addrs.penalty_leg,
            penalty,
            addrs.token_program,
        )?);
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
        transfers.push(leg(
            escrow,
            addrs.source,
            addrs.vault_authority,
            addrs.taker_leg,
            taker_payout,
            addrs.token_program,
        )?);
    }
    push_fee_leg(
        escrow,
        addrs.source,
        addrs.vault_authority,
        addrs.fee_leg,
        fee,
        addrs.token_program,
        &mut transfers,
    )?;
    if refund > 0 {
        transfers.push(leg(
            escrow,
            addrs.source,
            addrs.vault_authority,
            addrs.refund_leg,
            refund,
            addrs.token_program,
        )?);
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
            token_program: None,
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

        let plan = payout_plan(PayoutKind::Release, &e, &payout_addrs_native(), payout, fee, None).unwrap();
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
        let plan = payout_plan(PayoutKind::Release, &e, &payout_addrs_native(), payout, fee, None).unwrap();
        assert_eq!(plan.transfers.len(), 1);
        assert_eq!(plan.transfers[0].amount(), Some(1_000_000));
    }

    #[test]
    fn release_plan_rejects_tampered_amounts() {
        let mut e = funded_escrow(1_000_000);
        let (payout, fee) = e.release(key(1), 0, 400_000, None, key(2)).unwrap();
        // Attacker inflates the payout by 1: gross exceeds released_amount().
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &payout_addrs_native(), payout + 1, fee, None),
            Err(CpiError::SettlementMismatch)
        );
        // Stale results from a *different* escrow: released is 0 here.
        let fresh = funded_escrow(1_000_000);
        assert_eq!(
            payout_plan(PayoutKind::Release, &fresh, &payout_addrs_native(), payout, fee, None),
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
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee, None),
            Err(CpiError::RecipientMismatch)
        );
        let mut addrs = payout_addrs_native();
        addrs.taker_leg = key(78); // native path must pay the taker wallet
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee, None),
            Err(CpiError::RecipientMismatch)
        );
    }

    #[test]
    fn release_plan_rejects_wrong_state() {
        // A cancelled escrow never produces a payout plan, even if the
        // amounts would otherwise reconcile.
        let mut e = funded_escrow(1_000_000);
        e.cancel(key(1), None, key(1), 0).unwrap();
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &payout_addrs_native(), 1_000_000, 0, None),
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
        let plan = payout_plan(PayoutKind::Claim, &e, &payout_addrs_native(), payout, fee, None).unwrap();
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
            token_program: None,
        };
        let plan = payout_plan(PayoutKind::Release, &e, &addrs, payout, fee, None).unwrap();
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
        e.cancel(key(1), None, key(1), 0).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        let addrs = RefundAddrs {
            source: key(10),
            vault_authority: key(10),
            initializer: key(1),
            refund_to: key(1),
            refund_leg: key(1),
            penalty_leg: key(1),
            transfer_hook: None,
            token_program: None,
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
        let (refund, _, penalty) = e.cancel_expired(taker, 1000, None, init).unwrap();
        assert!(penalty > 0 && refund + penalty == 1_000_000);
        let addrs = RefundAddrs {
            source: key(10),
            vault_authority: key(10),
            initializer: init,
            refund_to: init,
            refund_leg: init,
            penalty_leg: init,
            transfer_hook: None,
            token_program: None,
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
        e.cancel(key(1), None, key(1), 0).unwrap();
        let addrs = RefundAddrs {
            source: key(10),
            vault_authority: key(10),
            initializer: key(1),
            refund_to: key(1),
            refund_leg: key(1),
            penalty_leg: key(1),
            transfer_hook: None,
            token_program: None,
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
            token_program: None,
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
            token_program: None,
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
        plain.cancel(key(1), None, key(1), 0).unwrap();
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
        e.escalate(taker, 0, e.remaining_amount(), None, None, 0).unwrap();
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
            token_program: None,
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
        e.escalate(taker, disputed_at, e.remaining_amount(), None, None, 0).unwrap();
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
            token_program: None,
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
        e.escalate(taker, 0, e.remaining_amount(), None, None, 0).unwrap();
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
            token_program: None,
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
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee, None),
            Err(CpiError::RecipientMismatch)
        );
        // The pinned recipient builds, and the fee leg points at it.
        addrs.fee_leg = recipient;
        let plan = payout_plan(PayoutKind::Release, &e, &addrs, payout, fee, None).unwrap();
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
        e.escalate(taker, 0, e.remaining_amount(), None, None, 0).unwrap();
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
            token_program: None,
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
        let plan = payout_plan(PayoutKind::Release, &e, &payout_addrs_native(), payout, fee, None).unwrap();
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
            token_program: None,
        }
    }

    #[test]
    fn matching_hook_plan_annotates_program_and_extra_accounts() {
        let (mut e, hook) = hook_escrow();
        let mint = [0xD0; 32];
        let (payout, fee) = e.release(key(1), 0, 1_000_000, Some(mint), key(2)).unwrap();
        let plan = payout_plan(PayoutKind::Release, &e, &hook_payout_addrs(hook), payout, fee, None).unwrap();
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
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee, None),
            Err(CpiError::SettlementMismatch)
        );
        // Escrow declares a hook, plan names a different program →
        // SettlementMismatch (a swapped hook is never built).
        let mut addrs = hook_payout_addrs([0x78; 32]);
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee, None),
            Err(CpiError::SettlementMismatch)
        );
        // Escrow declares no hook, plan names one → SettlementMismatch
        // (the plan claims hook execution the escrow never authorized).
        let mut e2 = funded_escrow(1_000_000);
        let (payout2, fee2) = e2.release(key(1), 0, 1_000_000, None, key(2)).unwrap();
        let mut addrs2 = payout_addrs_native();
        addrs2.transfer_hook = Some(hook_plan(hook));
        assert_eq!(
            payout_plan(PayoutKind::Release, &e2, &addrs2, payout2, fee2, None),
            Err(CpiError::SettlementMismatch)
        );
        // No hook on either side → clean plan, empty annotation.
        let addrs3 = payout_addrs_native();
        let plan = payout_plan(PayoutKind::Release, &e2, &addrs3, payout2, fee2, None).unwrap();
        assert_eq!(plan.transfer_hook_program, None);
        assert!(plan.transfer_hook_accounts.is_empty());
    }

    // ---------- AV-132: payout_plan slippage pre-check ----------
    //
    // The plan gate rejects before the executor ever runs: a min_payout
    // floor above the quoted payout fails plan construction with
    // CpiError::SlippageExceeded, so a keeper never submits a CPI whose
    // own quote already violates the floor.

    #[test]
    fn slippage_floor_above_quote_rejects_the_plan() {
        let mut e = funded_escrow(1_000_000);
        let (payout, fee) = e.release(key(1), 0, 1_000_000, None, key(2)).unwrap();
        assert_eq!((payout, fee), (1_000_000, 0));
        // Floor above the quote: the plan is never built.
        assert_eq!(
            payout_plan(
                PayoutKind::Release,
                &e,
                &payout_addrs_native(),
                payout,
                fee,
                Some(1_000_001)
            ),
            Err(CpiError::SlippageExceeded)
        );
        // Floor at the quote: the boundary passes.
        let plan = payout_plan(
            PayoutKind::Release,
            &e,
            &payout_addrs_native(),
            payout,
            fee,
            Some(1_000_000),
        )
        .unwrap();
        assert_eq!(plan.transfers.len(), 1);
        // Floor below the quote: passes.
        let plan = payout_plan(
            PayoutKind::Release,
            &e,
            &payout_addrs_native(),
            payout,
            fee,
            Some(990_000),
        )
        .unwrap();
        assert_eq!(plan.transfers.len(), 1);
        // None: the pre-AV-132 behavior, no floor.
        let plan =
            payout_plan(PayoutKind::Release, &e, &payout_addrs_native(), payout, fee, None)
                .unwrap();
        assert_eq!(plan.transfers.len(), 1);
    }

    #[test]
    fn slippage_precheck_runs_with_the_amount_validations() {
        // A floor above the quote fails even when every other check
        // passes — and a tampered payout still fails as
        // SettlementMismatch first (amount validation precedes the
        // slippage gate).
        let mut e = funded_escrow(1_000_000);
        let (payout, fee) = e.release(key(1), 0, 1_000_000, None, key(2)).unwrap();
        assert_eq!(
            payout_plan(
                PayoutKind::Release,
                &e,
                &payout_addrs_native(),
                payout + 1,
                fee,
                Some(payout + 2)
            ),
            Err(CpiError::SettlementMismatch)
        );
        // Zero floor on a zero payout: the ZeroAmount gate still fires
        // (the slippage check cannot bless an empty plan).
        let mut e2 = funded_escrow(1_000_000);
        assert_eq!(
            payout_plan(PayoutKind::Release, &e2, &payout_addrs_native(), 0, 0, Some(0)),
            Err(CpiError::ZeroAmount)
        );
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
        e.cancel(key(1), Some(mint), key(1), 0).unwrap();
        let mut raddrs = RefundAddrs {
            source: key(11),
            vault_authority: key(10),
            initializer: key(1),
            refund_to: key(1),
            refund_leg: key(1),
            penalty_leg: key(1),
            transfer_hook: Some(hook_plan(hook)),
            token_program: None,
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
            crate::ESCROW_BODY_LEN - crate::CLAIMANT_ROSTER_TAIL_LEN - crate::VESTING_PAUSE_TAIL_LEN - crate::MINT_ALLOWLIST_TAIL_LEN - crate::GOVERNANCE_DELAY_TAIL_LEN - crate::GOVERNANCE_PROPOSAL_TAIL_LEN - crate::TAKER_LOCKED_TAIL_LEN - crate::RENT_SWEEP_TAIL_LEN - crate::ARBITER_FEE_TAIL_LEN - crate::DISPUTED_AMOUNT_TAIL_LEN - crate::AUTO_UNPAUSE_TAIL_LEN - crate::AMOUNT_BOUNDS_TAIL_LEN - crate::DUAL_CONTROL_TAIL_LEN - crate::TWAP_GATE_LEN - crate::REFUNDED_TAIL_LEN - crate::SLASH_LADDER_TAIL_LEN - crate::CLAIM_COOLDOWN_TAIL_LEN - crate::COUNTER_OFFER_TAIL_LEN - crate::RELEASE_INTENT_TAIL_LEN - crate::KEEPER_BOUNTY_TAIL_LEN - crate::DISPUTE_INTEREST_LEN - crate::PRICE_GATE_LEN - crate::PENALTY_ESCALATION_TAIL_LEN - crate::COMPOUND_INTEREST_TAIL_LEN - crate::SLOT_TIMELOCK_TAIL_LEN - crate::RELEASE_COOLING_TAIL_LEN - crate::FUNDING_TAIL_LEN - crate::RENT_TOP_UP_LEN - crate::DEADMAN_REGION_LEN - crate::PAYOUT_SPLIT_LEN - crate::INTEREST_REGION_LEN - crate::POOL_REGION_LEN - crate::SWAP_LINK_REGION_LEN - crate::APPEAL_BOND_REGION_LEN - crate::DELEGATION_REGION_LEN - crate::STREAMING_FEE_REGION_LEN - 33 - crate::FEES_WITHDRAWN_TAIL_LEN - (1 + crate::TIERED_QUORUM_LEN) - 43 - crate::SOCIAL_RECOVERY_TAIL_LEN - crate::JURY_PANEL_SIZE_TAIL_LEN - crate::DELIVERY_TAIL_LEN; // AV-191 + AV-195/AV-196
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
                 - crate::TWAP_GATE_LEN - crate::REFUNDED_TAIL_LEN - crate::SLASH_LADDER_TAIL_LEN - crate::PRICE_GATE_LEN - crate::PENALTY_ESCALATION_TAIL_LEN - crate::COMPOUND_INTEREST_TAIL_LEN - crate::SLOT_TIMELOCK_TAIL_LEN - crate::APPEAL_BOND_REGION_LEN
                - crate::DELEGATION_REGION_LEN
                - crate::STREAMING_FEE_REGION_LEN..crate::ESCROW_BODY_LEN
                 - crate::TWAP_GATE_LEN - crate::REFUNDED_TAIL_LEN - crate::SLASH_LADDER_TAIL_LEN - crate::PRICE_GATE_LEN - crate::PENALTY_ESCALATION_TAIL_LEN - crate::COMPOUND_INTEREST_TAIL_LEN - crate::SLOT_TIMELOCK_TAIL_LEN - crate::APPEAL_BOND_REGION_LEN
                - crate::DELEGATION_REGION_LEN],
            &[0u8; 16]
        );
        assert_eq!(
            &bytes[crate::ESCROW_BODY_LEN
                 - crate::TWAP_GATE_LEN - crate::REFUNDED_TAIL_LEN - crate::SLASH_LADDER_TAIL_LEN - crate::PRICE_GATE_LEN - crate::PENALTY_ESCALATION_TAIL_LEN - crate::COMPOUND_INTEREST_TAIL_LEN - crate::SLOT_TIMELOCK_TAIL_LEN - crate::SWAP_LINK_REGION_LEN
                - crate::DELEGATION_REGION_LEN
                - crate::STREAMING_FEE_REGION_LEN
                - crate::APPEAL_BOND_REGION_LEN
                ..crate::ESCROW_BODY_LEN
                     - crate::TWAP_GATE_LEN - crate::REFUNDED_TAIL_LEN - crate::SLASH_LADDER_TAIL_LEN - crate::PRICE_GATE_LEN - crate::PENALTY_ESCALATION_TAIL_LEN - crate::COMPOUND_INTEREST_TAIL_LEN - crate::SLOT_TIMELOCK_TAIL_LEN - crate::SWAP_LINK_REGION_LEN
                    - crate::DELEGATION_REGION_LEN
                    - crate::STREAMING_FEE_REGION_LEN],
            &[0u8; 16]
        );
    }
    // --- AV-166: Token-2022 TransferChecked + extension awareness -------

    #[test]
    fn token_2022_program_id_decodes_and_differs_from_spl() {
        let t22 = token_2022_program_id();
        assert_eq!(t22.len(), 32);
        assert_ne!(t22, [0u8; 32]);
        assert_ne!(t22, spl_token_program_id());
        assert_ne!(t22, system_program_id());
        // Deterministic: the OnceLock caches the same decode.
        assert_eq!(token_2022_program_id(), t22);
    }

    #[test]
    fn token_program_kind_dispatches_and_rejects_unknown() {
        assert_eq!(
            token_program_kind(spl_token_program_id()),
            Ok(TokenProgram::SplToken)
        );
        assert_eq!(
            token_program_kind(token_2022_program_id()),
            Ok(TokenProgram::Token2022)
        );
        // Native SOL is not a token program; neither is a random key.
        assert_eq!(
            token_program_kind(system_program_id()),
            Err(CpiError::UnsupportedTokenProgram)
        );
        assert_eq!(
            token_program_kind(key(77)),
            Err(CpiError::UnsupportedTokenProgram)
        );
    }

    #[test]
    fn transfer_checked_layout_is_pinned() {
        let mint = key(7);
        let ix = token_transfer_checked(
            token_2022_program_id(),
            key(11),
            mint,
            key(12),
            key(10),
            42_000,
            6,
        )
        .unwrap();
        assert_eq!(ix.program_id, token_2022_program_id());
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta { pubkey: key(11), is_signer: false, is_writable: true },
                AccountMeta { pubkey: mint, is_signer: false, is_writable: false },
                AccountMeta { pubkey: key(12), is_signer: false, is_writable: true },
                AccountMeta { pubkey: key(10), is_signer: true, is_writable: false },
            ]
        );
        // u8 index 12 || u64 amount LE || u8 decimals — 10 bytes.
        let mut expected = vec![12u8];
        expected.extend_from_slice(&42_000u64.to_le_bytes());
        expected.push(6);
        assert_eq!(ix.data, expected);
        assert_eq!(ix.amount(), Some(42_000));
        assert_eq!(ix.transfer_checked_decimals(), Some(6));
    }

    #[test]
    fn transfer_checked_serves_both_token_programs() {
        // Both token programs define TransferChecked at index 12 with
        // the same layout — the builder is program-agnostic past the
        // kind check.
        let mint = key(7);
        let ix = token_transfer_checked(
            spl_token_program_id(),
            key(11),
            mint,
            key(12),
            key(10),
            1_000,
            9,
        )
        .unwrap();
        assert_eq!(ix.program_id, spl_token_program_id());
        assert_eq!(ix.data[0], TRANSFER_CHECKED_IX);
        assert_eq!(ix.transfer_checked_decimals(), Some(9));
        assert_eq!(ix.amount(), Some(1_000));
    }

    #[test]
    fn transfer_checked_rejects_garbage() {
        let mint = key(7);
        let t22 = token_2022_program_id();
        // Zero amount.
        assert_eq!(
            token_transfer_checked(t22, key(11), mint, key(12), key(10), 0, 6),
            Err(CpiError::ZeroAmount)
        );
        // On-chain mints carry at most 9 decimals.
        assert_eq!(
            token_transfer_checked(t22, key(11), mint, key(12), key(10), 5, 10),
            Err(CpiError::InvalidDecimals)
        );
        assert_eq!(
            token_transfer_checked(t22, key(11), mint, key(12), key(10), 5, 19),
            Err(CpiError::InvalidDecimals)
        );
        // Unknown program: no instruction, even a "compatible" one.
        assert_eq!(
            token_transfer_checked(key(77), key(11), mint, key(12), key(10), 5, 6),
            Err(CpiError::UnsupportedTokenProgram)
        );
        // Native SOL is not a token program.
        assert_eq!(
            token_transfer_checked(
                system_program_id(),
                key(11),
                mint,
                key(12),
                key(10),
                5,
                6
            ),
            Err(CpiError::UnsupportedTokenProgram)
        );
        assert_eq!(
            token_transfer_checked(t22, key(11), mint, key(11), key(10), 5, 6),
            Err(CpiError::SelfTransfer)
        );
        assert_eq!(
            token_transfer_checked(t22, [0u8; 32], mint, key(12), key(10), 5, 6),
            Err(CpiError::ZeroAddress)
        );
        // The plain Transfer (index 3) is not a checked transfer.
        let plain =
            spl_token_transfer(key(11), mint, key(12), key(10), 5).unwrap();
        assert_eq!(plain.transfer_checked_decimals(), None);
        assert_eq!(plain.amount(), Some(5));
        let sys = system_transfer(key(11), key(12), 5).unwrap();
        assert_eq!(sys.transfer_checked_decimals(), None);
    }

    #[test]
    fn amount_decode_rejects_unknown_token_instruction() {
        // A token-program instruction that is neither Transfer nor
        // TransferChecked is not a transfer this module built.
        let ix = TransferInstruction {
            program_id: spl_token_program_id(),
            accounts: vec![],
            data: vec![9u8, 1, 2, 3, 4, 5, 6, 7, 8],
        };
        assert_eq!(ix.amount(), None);
    }

    #[test]
    fn transfer_fee_schedule_math_matches_onchain_rule() {
        let fee = TransferFeeSchedule { basis_points: 100, maximum_fee: 50_000 };
        fee.validate().unwrap();
        // 1% of 1_000_000, under the cap.
        assert_eq!(fee.withheld_fee(1_000_000), 10_000);
        assert_eq!(fee.net_amount(1_000_000), 990_000);
        // Ceiling: a fractional raw fee rounds up.
        let tiny = TransferFeeSchedule { basis_points: 1, maximum_fee: u64::MAX };
        assert_eq!(tiny.withheld_fee(1), 1, "ceil(1 * 1 / 10000) = 1");
        assert_eq!(tiny.net_amount(1), 0);
        // The cap binds before the percentage does.
        let capped = TransferFeeSchedule { basis_points: 10_000, maximum_fee: 50 };
        assert_eq!(capped.withheld_fee(1_000_000), 50);
        assert_eq!(capped.net_amount(1_000_000), 999_950);
        // u64::MAX cannot overflow the u128 intermediate.
        let max = TransferFeeSchedule { basis_points: 10_000, maximum_fee: u64::MAX };
        assert_eq!(max.withheld_fee(u64::MAX), u64::MAX);
        assert_eq!(max.net_amount(u64::MAX), 0);
        // More than 100% cannot exist on-chain.
        let bad = TransferFeeSchedule { basis_points: 10_001, maximum_fee: 0 };
        assert_eq!(bad.validate(), Err(CpiError::InvalidTransferFee));
    }

    #[test]
    fn token_metadata_is_read_only_by_construction() {
        let mint = key(7);
        let meta = TokenMetadata::read(
            Some(key(3)),
            mint,
            "Wrapped Test".to_string(),
            "WTST".to_string(),
            "https://example.com/meta.json".to_string(),
            vec![("color".to_string(), "blue".to_string())],
        );
        assert_eq!(meta.update_authority(), Some(key(3)));
        assert_eq!(meta.mint(), mint);
        assert_eq!(meta.name(), "Wrapped Test");
        assert_eq!(meta.symbol(), "WTST");
        assert_eq!(meta.uri(), "https://example.com/meta.json");
        assert_eq!(
            meta.additional_metadata(),
            &[("color".to_string(), "blue".to_string())]
        );
        // Clone carries the view; there is no setter to mutate it.
        assert_eq!(meta.clone(), meta);
    }

    fn t22_descriptor() -> MintDescriptor {
        MintDescriptor {
            mint: key(7),
            token_program: token_2022_program_id(),
            decimals: 6,
            transfer_fee: Some(TransferFeeSchedule {
                basis_points: 100,
                maximum_fee: 50_000,
            }),
            metadata: Some(TokenMetadata::read(
                None,
                key(7),
                "T".to_string(),
                "T".to_string(),
                "u".to_string(),
                vec![],
            )),
            confidential_transfer: None,
        }
    }

    #[test]
    fn mint_descriptor_validate_gates_programs_and_extensions() {
        // Full Token-2022 binding validates.
        let ok = t22_descriptor().validate().unwrap();
        assert_eq!(ok.program, TokenProgram::Token2022);
        assert_eq!(ok.program_id, token_2022_program_id());
        assert_eq!(ok.decimals, 6);
        assert_eq!(ok.mint, key(7));
        // Legacy SPL binding validates with no extensions.
        let spl = MintDescriptor {
            mint: key(7),
            token_program: spl_token_program_id(),
            decimals: 9,
            transfer_fee: None,
            metadata: None,
            confidential_transfer: None,
        }
        .validate()
        .unwrap();
        assert_eq!(spl.program, TokenProgram::SplToken);
        // Unknown program: never.
        let mut bad = t22_descriptor();
        bad.token_program = key(77);
        assert_eq!(
            bad.validate(),
            Err(CpiError::UnsupportedTokenProgram)
        );
        // Transfer-fee and metadata are Token-2022 concepts — rejected
        // on the legacy SPL program.
        let mut bad = t22_descriptor();
        bad.token_program = spl_token_program_id();
        assert_eq!(
            bad.validate(),
            Err(CpiError::IncompatibleTokenExtension)
        );
        let mut bad = t22_descriptor();
        bad.token_program = spl_token_program_id();
        bad.transfer_fee = None;
        assert_eq!(
            bad.validate(),
            Err(CpiError::IncompatibleTokenExtension)
        );
        // Bad fee schedule fails even on Token-2022.
        let mut bad = t22_descriptor();
        bad.transfer_fee = Some(TransferFeeSchedule {
            basis_points: 10_001,
            maximum_fee: 0,
        });
        assert_eq!(bad.validate(), Err(CpiError::InvalidTransferFee));
        // Decimals above the AV-28 ceiling: no binding.
        let mut bad = t22_descriptor();
        bad.decimals = 19;
        assert_eq!(bad.validate(), Err(CpiError::InvalidDecimals));
        // Token-2022 path additionally requires on-chain-plausible
        // decimals (<= 9).
        let mut bad = t22_descriptor();
        bad.decimals = 12;
        assert_eq!(bad.validate(), Err(CpiError::InvalidDecimals));
        // Zero mint: no binding.
        let mut bad = t22_descriptor();
        bad.mint = [0u8; 32];
        assert_eq!(bad.validate(), Err(CpiError::ZeroAddress));
    }

    #[test]
    fn token_leg_auto_dispatches_by_program() {
        let spl = MintDescriptor {
            mint: key(7),
            token_program: spl_token_program_id(),
            decimals: 9,
            transfer_fee: None,
            metadata: None,
            confidential_transfer: None,
        }
        .validate()
        .unwrap();
        let ix = token_leg(&spl, key(11), key(12), key(10), 5_000).unwrap();
        // Legacy SPL keeps the plain Transfer (index 3).
        assert_eq!(ix.program_id, spl_token_program_id());
        assert_eq!(ix.data[0], 3u8);
        assert_eq!(ix.amount(), Some(5_000));
        assert_eq!(ix.transfer_checked_decimals(), None);

        let t22 = t22_descriptor().validate().unwrap();
        let ix = token_leg(&t22, key(11), key(12), key(10), 5_000).unwrap();
        assert_eq!(ix.program_id, token_2022_program_id());
        assert_eq!(ix.data[0], TRANSFER_CHECKED_IX);
        assert_eq!(ix.amount(), Some(5_000));
        assert_eq!(ix.transfer_checked_decimals(), Some(6));
    }

    fn payout_addrs_token2022() -> PayoutAddrs {
        PayoutAddrs {
            source: key(11),
            vault_authority: key(10),
            taker: key(2),
            taker_leg: key(12),
            fee_leg: key(9),
            transfer_hook: None,
            token_program: Some(token_2022_program_id()),
        }
    }

    fn token2022_escrow() -> Escrow {
        let mut e = Escrow::initialize(key(1), key(2), 1_000_000, u64::MAX)
            .unwrap()
            .with_mint(key(7))
            .unwrap()
            .with_decimals(6)
            .unwrap();
        e.fund(key(1), FUND_AT).unwrap();
        e
    }

    #[test]
    fn payout_plan_token2022_uses_transfer_checked() {
        let mut e = token2022_escrow();
        let (payout, fee) = e.release(key(1), 0, 1_000_000, Some(key(7)), key(2)).unwrap();
        assert_eq!(fee, 0);
        let plan =
            payout_plan(PayoutKind::Release, &e, &payout_addrs_token2022(), payout, fee, None)
                .unwrap();
        assert_eq!(plan.transfers.len(), 1);
        let ix = &plan.transfers[0];
        assert_eq!(ix.program_id, token_2022_program_id());
        assert_eq!(ix.data[0], TRANSFER_CHECKED_IX);
        // The escrow's AV-28 decimals ride the checked transfer.
        assert_eq!(ix.transfer_checked_decimals(), Some(6));
        assert_eq!(ix.amount(), Some(1_000_000));
        assert_eq!(ix.accounts[1].pubkey, key(7)); // the bound mint
        assert_eq!(ix.accounts[3].pubkey, key(10)); // vault PDA authority
        assert_eq!(plan.total_amount(), 1_000_000);
    }

    #[test]
    fn payout_plan_rejects_unknown_token_program() {
        let mut e = token2022_escrow();
        let (payout, fee) = e.release(key(1), 0, 1_000_000, Some(key(7)), key(2)).unwrap();
        let mut addrs = payout_addrs_token2022();
        addrs.token_program = Some(key(77));
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee, None),
            Err(CpiError::UnsupportedTokenProgram)
        );
        // The SPL Token program id is accepted on a mint-bound escrow
        // and keeps the plain Transfer.
        addrs.token_program = Some(spl_token_program_id());
        let plan =
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee, None).unwrap();
        assert_eq!(plan.transfers[0].program_id, spl_token_program_id());
        assert_eq!(plan.transfers[0].data[0], 3u8);
    }

    #[test]
    fn native_path_rejects_any_token_program() {
        let mut e = funded_escrow(1_000_000);
        let (payout, fee) = e.release(key(1), 0, 1_000_000, None, key(2)).unwrap();
        let mut addrs = payout_addrs_native();
        addrs.token_program = Some(token_2022_program_id());
        assert_eq!(
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee, None),
            Err(CpiError::UnsupportedTokenProgram)
        );
        // None keeps the native system transfer.
        addrs.token_program = None;
        let plan =
            payout_plan(PayoutKind::Release, &e, &addrs, payout, fee, None).unwrap();
        assert_eq!(plan.transfers[0].program_id, system_program_id());
    }

    #[test]
    fn transfer_fee_net_reconciles_against_plan_gross() {
        // The keeper-side reconciliation story: the settlement plan
        // moves the gross the state machine recorded; the transfer-fee
        // schedule says what the taker actually receives.
        let mut e = token2022_escrow();
        let (payout, fee) = e.release(key(1), 0, 1_000_000, Some(key(7)), key(2)).unwrap();
        let plan =
            payout_plan(PayoutKind::Release, &e, &payout_addrs_token2022(), payout, fee, None)
                .unwrap();
        let schedule = TransferFeeSchedule { basis_points: 100, maximum_fee: 50_000 };
        let gross = plan.total_amount();
        assert_eq!(gross, 1_000_000);
        // 1% withheld by the Token-2022 program during the transfer.
        assert_eq!(schedule.net_amount(gross), 990_000);
        // The plan itself still pins the gross — it never silently
        // shrinks to the net.
        assert_eq!(plan.transfers[0].amount(), Some(gross));
    }

}
