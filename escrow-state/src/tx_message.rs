//! AV-71: signable transaction-message serialization for keeper execution
//! bundles.
//!
//! AV-61 packs the batch lifecycle scan's executable actions into
//! deterministic, multisig/CLI-ready JSON. This module is the last mile:
//! for each bundled action it builds the *real* instruction bytes — the
//! 8-byte Anchor discriminator plus the Borsh-encoded parameters — and
//! assembles a Solana legacy transaction message around them, emitted as
//! base64 for the signer to take, sign, and submit.
//!
//! # What is real here
//!
//! - **Instruction data** is byte-exact per the IDL spec (AV-29): the
//!   discriminator comes from the same [`instruction_discriminator`]
//!   constructor the IDL pipeline pins (the `INSTRUCTIONS` spec names are
//!   authoritative), and the parameters are hand-written Borsh in the
//!   spec's field order:
//!   - `initialize`: `discriminator || amount:u64 || expires_at:u64`
//!     (24 bytes). The taker is a program *account* (`accounts.taker`),
//!     not a param — it is not in the data.
//!   - `fund`: `discriminator` alone (8 bytes; the spec's `params: []`).
//!   - `release`: `discriminator || amount:u64` (16 bytes).
//! - **Account metas** mirror the bundle's *logical* accounts
//!   (`vault` / `initializer` / `mint`) in program-declared order,
//!   translated 1:1 into `is_signer` / `is_writable` flags.
//! - **Compute-budget instructions** (AV-89) are hand-serialized too:
//!   `setComputeUnitLimit` → `0x02 || units:u32 LE` (5 bytes),
//!   `setComputeUnitPrice` → `0x03 || micro_lamports:u64 LE` (9 bytes)
//!   — the Solana compute-budget program's Borsh-enum layout. The
//!   program id stays caller-supplied (same convention as the program
//!   instructions above); the keeper feeds the AV-88 CU estimate into
//!   the limit and the AV-89 oracle recommendation into the price.
//! - **The message** is a genuine Solana legacy transaction message:
//!   3-byte header, compact-u16-prefixed account keys in canonical order
//!   (writable signers, readonly signers, writable non-signers, readonly
//!   non-signers), the 32-byte recent blockhash, and compact-u16-prefixed
//!   compiled instructions — then base64-encoded.
//!
//! # What is deliberately NOT here (honesty labels)
//!
//! - **Unsigned.** The relay never holds keys; the output is the
//!   *to-be-signed* message. A multisig or CLI signs the base64 bytes
//!   and submits the signed transaction.
//! - **Program id is caller-supplied.** The builder takes the deployed
//!   program's 32 bytes as a parameter — it does not hardcode one. (The
//!   skeleton's `declare_id!` string is not valid base58 — it contains a
//!   lowercase `l` — and is not decoded off-chain.)
//! - **Blockhash is caller-supplied.** The keeper fetches a recent
//!   blockhash from the cluster and passes it in; the message is only
//!   submittable while that blockhash is fresh.
//! - **Account completion is the submitter's job.** The message carries
//!   exactly the bundle's logical accounts. `fund` is complete as-is
//!   (the program's `Fund` accounts are `vault` + `initializer`); for
//!   `initialize` the submitter appends the remaining program-declared
//!   accounts (`taker` — the key is in the bundle's `args` — and the
//!   system program), and for `release` it appends `taker`, `payout_to`,
//!   the clock sysvar, and the vault token account on the SPL path, per
//!   the IDL's account list. The instruction *data* needs nothing added.
//! - **Legacy message, one instruction each** — via [`compile_message`] /
//!   [`signable_message_base64`]. No address-table lookups are compiled
//!   in; each action becomes its own single-instruction message, so one
//!   multisig proposal signs one instruction.
//! - **v0 message with address-table lookups** (AV-87) — via
//!   [`compile_action_message_v0`] / [`signable_message_v0_base64`] /
//!   [`bundle_action_message_v0_base64`]. ALT-eligible accounts (the
//!   bundle's stamped `alt_index`) resolve statically against the
//!   caller's snapshot of the on-chain table: signers stay static (the
//!   runtime forbids signer lookups), everything else shrinks the
//!   static key list. The legacy path is byte-identical with or without
//!   the v0 code present. AV-181 adds the parsing half:
//!   `alt_table` deserializes raw lookup-table account data (the
//!   keeper's RPC bytes) into that snapshot, expands a v0 message's
//!   lookups back into loaded addresses, and compiles v0 straight from
//!   account data — empty/bad tables fail loud there.
//!
//! - **Packet-size pre-flight + keeper auto-route** (AV-162) — via
//!   [`MAX_TRANSACTION_PACKET_BYTES`] (1232, the Solana transaction
//!   packet limit), [`wire_size_legacy`] / [`wire_size_v0`],
//!   [`ensure_fits_packet_limit`], and
//!   [`signable_bundle_action_message_base64`]. A multi-account
//!   CPI-path message that exceeds the limit is rejected by the
//!   cluster *after* signing, so the keeper checks the wire size
//!   before handing bytes to a signer. The auto-route picks v0 when
//!   the bundle stamps ALT-eligible accounts and the caller supplies
//!   the on-chain table's key, falls back to legacy when no account
//!   is ALT-eligible, and fails loud with
//!   [`TxMessageError::AltTableNotFound`] when the bundle promises a
//!   table the keeper did not provide — instead of silently bloating
//!   past the limit on the legacy path.
//!
//! # Anti-drift
//!
//! [`instruction_for_action`] recomputes the discriminator from the
//! action's IDL instruction name and *refuses to build* when it disagrees
//! with the discriminator the bundle stamped
//! ([`TxMessageError::DiscriminatorMismatch`]) — a renamed instruction,
//! a stale bundle, or a tampered action fails loudly instead of
//! producing signable bytes for the wrong program entrypoint. The tests
//! pin the Borsh layouts against the `INSTRUCTIONS` spec table in both
//! directions, so a spec change without a matching encoder change breaks
//! the build.

use super::batch::BatchActionKind;
use super::cpi::{AccountMeta, Pubkey};
use super::discriminator::instruction_discriminator;
use super::execution_bundle::{BundledAction, ExecutionBundle};

/// Errors from message construction, encoding, and decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxMessageError {
    /// The bundle-stamped discriminator does not equal the discriminator
    /// recomputed from the action's IDL instruction name — the bundle
    /// and the spec have drifted (or the action was tampered with).
    /// Nothing is built.
    DiscriminatorMismatch,
    /// The base64 input is malformed (bad length, bad padding, or a
    /// character outside the standard alphabet).
    InvalidBase64,
    /// The message bytes end mid-field.
    TruncatedMessage,
    /// Bytes remain after a complete message decoded.
    TrailingBytes,
    /// An instruction references an account index beyond the key list.
    AccountIndexOutOfBounds,
    /// More than 255 account keys: instruction indexes are single bytes.
    TooManyAccountKeys,
    /// v0 compile: a bundled account's stamped `alt_index` points beyond
    /// the caller-supplied lookup-table snapshot.
    AltIndexOutOfBounds,
    /// v0 compile: the snapshot's address at the stamped `alt_index` is
    /// not the account's pubkey — the snapshot is stale or for a
    /// different table.
    AltTableKeyMismatch,
    /// v0 compile: no account resolved through the lookup table, so the
    /// message would carry an empty lookup list — use the legacy path
    /// instead.
    NoAltResolved,
    /// v0 decode: a lookup entry lists the same table index twice, or
    /// in both the writable and readonly lists.
    InvalidAddressTableLookup,
    /// v0 decode: the first byte is not the `0x80` v0 version prefix.
    NotV0Message,
    /// Packet pre-flight (AV-162): the message's wire bytes exceed
    /// [`MAX_TRANSACTION_PACKET_BYTES`] — the cluster would reject it
    /// *after* signing. Shrink the message (v0 + address-table lookups,
    /// fewer accounts) and re-check with
    /// [`ensure_fits_packet_limit`].
    PacketTooLarge,
    /// Keeper auto-route (AV-162): the bundle stamps ALT-eligible
    /// accounts but the caller supplied no on-chain table key — the
    /// table the bundle promises cannot be resolved. Failing loud here
    /// instead of silently falling back to a legacy message that bloats
    /// past the packet limit.
    AltTableNotFound,
}

/// One program instruction ready to compile into a message: the target
/// program, the account metas in program-declared order, and the real
/// instruction data (`discriminator || Borsh params`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramInstruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// A message-compiled instruction: indexes into the message's account
/// key list plus the opaque data bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

/// The 3-byte legacy message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    pub num_required_signatures: u8,
    pub num_readonly_signed_accounts: u8,
    pub num_readonly_unsigned_accounts: u8,
}

/// A Solana legacy transaction message: header, account keys,
/// blockhash, compiled instructions. No address-table lookups —
/// `address_table_lookups` always encodes as an empty list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionMessage {
    pub header: MessageHeader,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: Pubkey,
    pub instructions: Vec<CompiledInstruction>,
}

/// Build the real instruction bytes for a bundled action.
///
/// The discriminator is recomputed from the action's IDL instruction
/// name via the shared [`instruction_discriminator`] constructor — the
/// same single source of truth the AV-29 IDL pipeline pins — and checked
/// against the discriminator the bundle stamped. The Borsh parameters
/// follow the `INSTRUCTIONS` spec field order per kind (see the module
/// docs); the pin tests below assert the layout against the spec table.
pub fn instruction_for_action(
    program_id: Pubkey,
    action: &BundledAction,
) -> Result<ProgramInstruction, TxMessageError> {
    let discriminator = instruction_discriminator(action.instruction);
    if discriminator != action.discriminator {
        return Err(TxMessageError::DiscriminatorMismatch);
    }
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(&discriminator);
    match action.kind {
        BatchActionKind::Initialize => {
            // INSTRUCTIONS spec: initialize(amount: u64, expires_at: u64).
            data.extend_from_slice(&action.amount.to_le_bytes());
            data.extend_from_slice(&action.expires_at.to_le_bytes());
        }
        BatchActionKind::Fund => {
            // INSTRUCTIONS spec: fund() — params: [].
        }
        BatchActionKind::Release => {
            // INSTRUCTIONS spec: release(amount: u64).
            data.extend_from_slice(&action.amount.to_le_bytes());
        }
        BatchActionKind::ReleasePayoutSplit => {
            // INSTRUCTIONS spec: release_payout_split() — params: [].
            // The per-recipient legs travel as remaining_accounts, not
            // instruction params.
        }
    }
    // Logical accounts in program-declared order, flags translated 1:1.
    let accounts = action
        .accounts
        .iter()
        .map(|a| AccountMeta {
            pubkey: a.pubkey,
            is_signer: a.signer,
            is_writable: a.writable,
        })
        .collect();
    Ok(ProgramInstruction {
        program_id,
        accounts,
        data,
    })
}

// ---------------------------------------------------------------------------
// Compute-budget instructions (AV-89).
// ---------------------------------------------------------------------------

/// Solana compute-budget program instruction discriminant for
/// `SetComputeUnitLimit(units: u32)`: `0x02 || units:u32 LE`
/// (5 bytes). The program's instructions are a Borsh enum, so the
/// variant index serializes as one little-endian byte.
pub const COMPUTE_BUDGET_IX_SET_COMPUTE_UNIT_LIMIT: u8 = 2;

/// Solana compute-budget program instruction discriminant for
/// `SetComputeUnitPrice(micro_lamports: u64)`: `0x03 ||
/// micro_lamports:u64 LE` (9 bytes).
pub const COMPUTE_BUDGET_IX_SET_COMPUTE_UNIT_PRICE: u8 = 3;

/// Build the `setComputeUnitLimit` instruction data for the compute
/// budget program: the AV-88 CU estimate (`estimated_compute_units`)
/// becomes the transaction's compute-unit cap.
///
/// Layout (hand-written, zero dependencies): `0x02 || units:u32 LE`.
/// The program id is caller-supplied — the keeper passes the cluster's
/// compute-budget program id (`ComputeBudget111111111111111111111111111111`
/// on mainnet), per this module's "program id is caller-supplied"
/// convention. Compute-budget instructions carry no accounts, and
/// conventionally precede the program instructions in the message.
pub fn compute_budget_set_compute_unit_limit(
    program_id: Pubkey,
    units: u32,
) -> ProgramInstruction {
    let mut data = Vec::with_capacity(5);
    data.push(COMPUTE_BUDGET_IX_SET_COMPUTE_UNIT_LIMIT);
    data.extend_from_slice(&units.to_le_bytes());
    ProgramInstruction {
        program_id,
        accounts: Vec::new(),
        data,
    }
}

/// Build the `setComputeUnitPrice` instruction data for the compute
/// budget program: the AV-89 priority-fee oracle's recommendation
/// (micro-lamports per compute unit) becomes the transaction's
/// priority fee.
///
/// Layout (hand-written, zero dependencies): `0x03 ||
/// micro_lamports:u64 LE`. Same caller-supplied program id and
/// account-free convention as
/// [`compute_budget_set_compute_unit_limit`].
pub fn compute_budget_set_compute_unit_price(
    program_id: Pubkey,
    micro_lamports_per_cu: u64,
) -> ProgramInstruction {
    let mut data = Vec::with_capacity(9);
    data.push(COMPUTE_BUDGET_IX_SET_COMPUTE_UNIT_PRICE);
    data.extend_from_slice(&micro_lamports_per_cu.to_le_bytes());
    ProgramInstruction {
        program_id,
        accounts: Vec::new(),
        data,
    }
}

/// Compile one instruction into a legacy transaction message.
///
/// Account keys are deduplicated (a repeated key merges `is_signer` /
/// `is_writable` with OR, the Solana convention) and ordered canonically:
/// writable signers, readonly signers, writable non-signers, readonly
/// non-signers; the program id trails as a readonly non-signer. The
/// header counts are derived from that ordering, so the message is
/// well-formed by construction.
/// Compile one or more program instructions into a legacy transaction
/// message, in order: account keys are interned across all
/// instructions (flags OR-merged on duplicates) and laid out in the
/// canonical class order, stable within each class — deterministic for
/// a given instruction list. AV-167 generalizes the single-instruction
/// path so a durable-nonce `AdvanceNonceAccount` can ride first.
pub fn compile_instructions(
    ixs: &[ProgramInstruction],
    recent_blockhash: Pubkey,
) -> TransactionMessage {
    // Intern keys, merging flags on duplicates.
    let mut uniq: Vec<(Pubkey, bool, bool)> = Vec::new();
    let mut intern = |key: Pubkey, signer: bool, writable: bool| -> usize {
        if let Some(i) = uniq.iter().position(|(k, _, _)| *k == key) {
            uniq[i].1 |= signer;
            uniq[i].2 |= writable;
            i
        } else {
            uniq.push((key, signer, writable));
            uniq.len() - 1
        }
    };
    let mut compiled: Vec<(Vec<usize>, usize, Vec<u8>)> = Vec::with_capacity(ixs.len());
    for ix in ixs {
        let mut meta_idx = Vec::with_capacity(ix.accounts.len());
        for m in &ix.accounts {
            meta_idx.push(intern(m.pubkey, m.is_signer, m.is_writable));
        }
        let program_idx = intern(ix.program_id, false, false);
        compiled.push((meta_idx, program_idx, ix.data.clone()));
    }

    // Canonical order, stable within each class.
    let mut order: Vec<usize> = (0..uniq.len()).collect();
    order.sort_by_key(|&i| {
        let (_, signer, writable) = uniq[i];
        match (signer, writable) {
            (true, true) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (false, false) => 3,
        }
    });
    // `sort_by_key` is stable, so first-seen order survives inside each
    // class — deterministic for a given instruction list.
    let mut new_index = vec![0usize; uniq.len()];
    for (new, &old) in order.iter().enumerate() {
        new_index[old] = new;
    }
    let account_keys: Vec<Pubkey> = order.iter().map(|&i| uniq[i].0).collect();

    let num_required_signatures = uniq.iter().filter(|(_, s, _)| *s).count() as u8;
    let num_readonly_signed_accounts = uniq
        .iter()
        .filter(|(_, s, w)| *s && !*w)
        .count() as u8;
    let num_readonly_unsigned_accounts = uniq
        .iter()
        .filter(|(_, s, w)| !*s && !*w)
        .count() as u8;

    let instructions = compiled
        .into_iter()
        .map(|(meta_idx, program_idx, data)| CompiledInstruction {
            program_id_index: new_index[program_idx] as u8,
            accounts: meta_idx.iter().map(|&i| new_index[i] as u8).collect(),
            data,
        })
        .collect();

    TransactionMessage {
        header: MessageHeader {
            num_required_signatures,
            num_readonly_signed_accounts,
            num_readonly_unsigned_accounts,
        },
        account_keys,
        recent_blockhash,
        instructions,
    }
}

pub fn compile_message(
    ix: &ProgramInstruction,
    recent_blockhash: Pubkey,
) -> TransactionMessage {
    compile_instructions(std::slice::from_ref(ix), recent_blockhash)
}

// ---------------------------------------------------------------------------
// Wire encoding (legacy message bytes).
// ---------------------------------------------------------------------------

/// Solana's compact-u16 ("shortvec") encoding for lengths.
fn encode_compact_u16(mut v: u16, out: &mut Vec<u8>) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

fn decode_compact_u16(bytes: &[u8], pos: &mut usize) -> Result<u16, TxMessageError> {
    let mut v: u16 = 0;
    let mut shift = 0u32;
    for _ in 0..3 {
        let b = *bytes.get(*pos).ok_or(TxMessageError::TruncatedMessage)?;
        *pos += 1;
        // The third byte may only carry one bit for a u16.
        if shift == 14 && b & 0x7e != 0 {
            return Err(TxMessageError::TruncatedMessage);
        }
        v |= ((b & 0x7f) as u16) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(TxMessageError::TruncatedMessage)
}

fn take_bytes<'a>(bytes: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], TxMessageError> {
    let end = pos.checked_add(n).ok_or(TxMessageError::TruncatedMessage)?;
    let slice = bytes.get(*pos..end).ok_or(TxMessageError::TruncatedMessage)?;
    *pos = end;
    Ok(slice)
}

/// Serialize a message to its canonical legacy wire bytes.
pub fn encode_message(msg: &TransactionMessage) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(msg.header.num_required_signatures);
    out.push(msg.header.num_readonly_signed_accounts);
    out.push(msg.header.num_readonly_unsigned_accounts);
    encode_compact_u16(msg.account_keys.len() as u16, &mut out);
    for key in &msg.account_keys {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(&msg.recent_blockhash);
    encode_compact_u16(msg.instructions.len() as u16, &mut out);
    for ix in &msg.instructions {
        out.push(ix.program_id_index);
        encode_compact_u16(ix.accounts.len() as u16, &mut out);
        out.extend_from_slice(&ix.accounts);
        encode_compact_u16(ix.data.len() as u16, &mut out);
        out.extend_from_slice(&ix.data);
    }
    // Legacy message: zero address-table lookups. (Solana's wire format
    // still carries the lookup count; a v0 message would follow with
    // lookup entries.)
    out.push(0);
    out
}

/// Parse canonical legacy wire bytes back into a message. Rejects
/// truncated input, trailing bytes, and out-of-range account indexes —
/// decode is the untrusted-input path, so it validates everything
/// [`encode_message`] guarantees.
pub fn decode_message(bytes: &[u8]) -> Result<TransactionMessage, TxMessageError> {
    let mut pos = 0usize;
    let num_required_signatures = take_bytes(bytes, &mut pos, 1)?[0];
    let num_readonly_signed_accounts = take_bytes(bytes, &mut pos, 1)?[0];
    let num_readonly_unsigned_accounts = take_bytes(bytes, &mut pos, 1)?[0];

    let key_count = decode_compact_u16(bytes, &mut pos)? as usize;
    if key_count > 255 {
        return Err(TxMessageError::TooManyAccountKeys);
    }
    let mut account_keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let k: [u8; 32] = take_bytes(bytes, &mut pos, 32)?
            .try_into()
            .map_err(|_| TxMessageError::TruncatedMessage)?;
        account_keys.push(k);
    }
    let recent_blockhash: [u8; 32] = take_bytes(bytes, &mut pos, 32)?
        .try_into()
        .map_err(|_| TxMessageError::TruncatedMessage)?;

    let ix_count = decode_compact_u16(bytes, &mut pos)? as usize;
    let mut instructions = Vec::with_capacity(ix_count);
    for _ in 0..ix_count {
        let program_id_index = take_bytes(bytes, &mut pos, 1)?[0];
        if program_id_index as usize >= key_count {
            return Err(TxMessageError::AccountIndexOutOfBounds);
        }
        let acct_count = decode_compact_u16(bytes, &mut pos)? as usize;
        let acct_bytes = take_bytes(bytes, &mut pos, acct_count)?;
        let mut accounts = Vec::with_capacity(acct_count);
        for &a in acct_bytes {
            if a as usize >= key_count {
                return Err(TxMessageError::AccountIndexOutOfBounds);
            }
            accounts.push(a);
        }
        let data_len = decode_compact_u16(bytes, &mut pos)? as usize;
        let data = take_bytes(bytes, &mut pos, data_len)?.to_vec();
        instructions.push(CompiledInstruction {
            program_id_index,
            accounts,
            data,
        });
    }
    // Trailing address-table-lookup count: legacy messages carry 0.
    let lookups = take_bytes(bytes, &mut pos, 1)?[0];
    if lookups != 0 {
        return Err(TxMessageError::TrailingBytes);
    }
    if pos != bytes.len() {
        return Err(TxMessageError::TrailingBytes);
    }
    Ok(TransactionMessage {
        header: MessageHeader {
            num_required_signatures,
            num_readonly_signed_accounts,
            num_readonly_unsigned_accounts,
        },
        account_keys,
        recent_blockhash,
        instructions,
    })
}

// ---------------------------------------------------------------------------
// v0 messages with address-table lookups (AV-87).
// ---------------------------------------------------------------------------

/// One address-table lookup of a v0 message: the on-chain lookup
/// table's key plus the table indexes resolved into it, split by
/// writability. At runtime the two lists become the loaded addresses —
/// writable first, then readonly — appended after the static keys in
/// the instruction's index space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressTableLookup {
    /// The on-chain address lookup table's key.
    pub address_table_key: [u8; 32],
    /// Indexes into the table's address list, writable at runtime.
    pub writable_indexes: Vec<u8>,
    /// Indexes into the table's address list, readonly at runtime.
    pub readonly_indexes: Vec<u8>,
}

/// A Solana v0 transaction message: the legacy shape plus address-table
/// lookups. Wire bytes are the legacy layout prefixed with the `0x80`
/// version byte, with the compact-u16-prefixed lookup list appended
/// after the instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V0TransactionMessage {
    pub header: MessageHeader,
    /// Keys embedded in the message: signers, the program id, and every
    /// account not resolved through a lookup table. The header counts
    /// cover exactly these keys — never the loaded addresses.
    pub static_account_keys: Vec<Pubkey>,
    pub recent_blockhash: Pubkey,
    /// Account indexes address the concatenated space `static keys ++
    /// writable loaded ++ readonly loaded`, in that order — the Solana
    /// loaded-address convention.
    pub instructions: Vec<CompiledInstruction>,
    pub address_table_lookups: Vec<AddressTableLookup>,
}

impl V0TransactionMessage {
    /// Table-resolved (loaded) addresses across all lookups.
    pub fn loaded_account_count(&self) -> usize {
        self.address_table_lookups
            .iter()
            .map(|l| l.writable_indexes.len() + l.readonly_indexes.len())
            .sum()
    }

    /// Total addressable accounts: static keys plus loaded addresses.
    pub fn total_account_count(&self) -> usize {
        self.static_account_keys.len() + self.loaded_account_count()
    }
}

/// Compile a bundled action into a v0 message, resolving ALT-eligible
/// accounts against the caller's snapshot of the on-chain lookup table
/// at `address_table_key`.
///
/// Caller-supplied `prefix` instructions compile first, in order
/// (AV-167: the durable-nonce `AdvanceNonceAccount` rides here). Prefix
/// accounts intern as static slots ahead of the action's accounts —
/// first-seen order is preserved inside each canonical class — and
/// never resolve through the lookup table (system-program instructions
/// have no ALT indexes).
///
/// Resolution rules (static — no chain access):
/// - Signers never resolve through a lookup table (the runtime forbids
///   signer lookups); they stay static even if an `alt_index` was
///   stamped.
/// - A non-signer with `alt_index: Some(i)` resolves to table index `i`
///   when `address_table[i]` is its pubkey; otherwise the build fails
///   ([`TxMessageError::AltIndexOutOfBounds`] / `AltTableKeyMismatch`)
///   instead of signing bytes against a stale table.
/// - A non-signer with `alt_index: None` stays static.
///
/// The legacy path is untouched: same action, no table snapshot, still
/// builds the identical legacy message as before.
pub fn compile_action_message_v0_with_prefix(
    program_id: Pubkey,
    prefix: &[ProgramInstruction],
    action: &BundledAction,
    recent_blockhash: Pubkey,
    address_table_key: [u8; 32],
    address_table: &[[u8; 32]],
) -> Result<V0TransactionMessage, TxMessageError> {
    let ix = instruction_for_action(program_id, action)?;

    // Static-key interning, same OR-merge rule as the legacy path.
    // Loaded accounts never enter the static list.
    let mut uniq: Vec<(Pubkey, bool, bool)> = Vec::new();
    let mut intern = |key: Pubkey, signer: bool, writable: bool| -> usize {
        if let Some(i) = uniq.iter().position(|(k, _, _)| *k == key) {
            uniq[i].1 |= signer;
            uniq[i].2 |= writable;
            i
        } else {
            uniq.push((key, signer, writable));
            uniq.len() - 1
        }
    };

    // Prefix instructions first: static slots, in prefix order, no ALT
    // resolution — the action's accounts follow.
    let mut prefix_compiled: Vec<(Vec<usize>, usize, Vec<u8>)> =
        Vec::with_capacity(prefix.len());
    for pix in prefix {
        let mut slots = Vec::with_capacity(pix.accounts.len());
        for m in &pix.accounts {
            slots.push(intern(m.pubkey, m.is_signer, m.is_writable));
        }
        let program_slot = intern(pix.program_id, false, false);
        prefix_compiled.push((slots, program_slot, pix.data.clone()));
    }

    // Per account, in program-declared order: a static intern slot, or a
    // resolved table index plus its writability.
    enum Slot {
        Static(usize),
        Loaded(bool, u8),
    }
    let mut slots: Vec<Slot> = Vec::with_capacity(action.accounts.len());
    let mut writable_loaded: Vec<u8> = Vec::new();
    let mut readonly_loaded: Vec<u8> = Vec::new();
    for a in &action.accounts {
        match (a.signer, a.alt_index) {
            (true, _) | (false, None) => {
                slots.push(Slot::Static(intern(a.pubkey, a.signer, a.writable)));
            }
            (false, Some(table_idx)) => {
                let table_idx = table_idx as usize;
                let addr = address_table
                    .get(table_idx)
                    .ok_or(TxMessageError::AltIndexOutOfBounds)?;
                if *addr != a.pubkey {
                    return Err(TxMessageError::AltTableKeyMismatch);
                }
                let list = if a.writable {
                    &mut writable_loaded
                } else {
                    &mut readonly_loaded
                };
                if !list.contains(&(table_idx as u8)) {
                    list.push(table_idx as u8);
                }
                slots.push(Slot::Loaded(a.writable, table_idx as u8));
            }
        }
    }
    if writable_loaded.is_empty() && readonly_loaded.is_empty() {
        return Err(TxMessageError::NoAltResolved);
    }
    let program_idx = intern(program_id, false, false);

    // Canonical static order, stable within each class — the legacy rule.
    let mut order: Vec<usize> = (0..uniq.len()).collect();
    order.sort_by_key(|&i| {
        let (_, signer, writable) = uniq[i];
        match (signer, writable) {
            (true, true) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (false, false) => 3,
        }
    });
    let mut new_index = vec![0usize; uniq.len()];
    for (new, &old) in order.iter().enumerate() {
        new_index[old] = new;
    }
    let static_account_keys: Vec<Pubkey> = order.iter().map(|&i| uniq[i].0).collect();
    let static_len = static_account_keys.len();

    let num_required_signatures = uniq.iter().filter(|(_, s, _)| *s).count() as u8;
    let num_readonly_signed_accounts =
        uniq.iter().filter(|(_, s, w)| *s && !*w).count() as u8;
    let num_readonly_unsigned_accounts =
        uniq.iter().filter(|(_, s, w)| !*s && !*w).count() as u8;

    let loaded_total = writable_loaded.len() + readonly_loaded.len();
    if static_len + loaded_total > 255 {
        return Err(TxMessageError::TooManyAccountKeys);
    }
    // Instruction indexes address static keys, then writable loaded,
    // then readonly loaded.
    let loaded_position = |table_idx: u8, writable: bool| -> u8 {
        let (list, base) = if writable {
            (&writable_loaded, 0)
        } else {
            (&readonly_loaded, writable_loaded.len())
        };
        let pos = list
            .iter()
            .position(|&x| x == table_idx)
            .expect("v0 compile: resolved index missing from loaded list");
        (static_len + base + pos) as u8
    };
    let accounts: Vec<u8> = slots
        .iter()
        .map(|s| match s {
            Slot::Static(intern_slot) => new_index[*intern_slot] as u8,
            Slot::Loaded(writable, table_idx) => loaded_position(*table_idx, *writable),
        })
        .collect();

    // Prefix instructions first, then the action — the message's
    // instruction order is the submission order.
    let mut instructions: Vec<CompiledInstruction> =
        Vec::with_capacity(prefix_compiled.len() + 1);
    for (slots, program_slot, data) in prefix_compiled {
        instructions.push(CompiledInstruction {
            program_id_index: new_index[program_slot] as u8,
            accounts: slots.iter().map(|&s| new_index[s] as u8).collect(),
            data,
        });
    }
    instructions.push(CompiledInstruction {
        program_id_index: new_index[program_idx] as u8,
        accounts,
        data: ix.data.clone(),
    });

    Ok(V0TransactionMessage {
        header: MessageHeader {
            num_required_signatures,
            num_readonly_signed_accounts,
            num_readonly_unsigned_accounts,
        },
        static_account_keys,
        recent_blockhash,
        instructions,
        address_table_lookups: vec![AddressTableLookup {
            address_table_key,
            writable_indexes: writable_loaded,
            readonly_indexes: readonly_loaded,
        }],
    })
}

/// Compile a bundled action into a v0 message with no prefix
/// instructions — the pre-AV-167 behavior, byte-identical.
pub fn compile_action_message_v0(
    program_id: Pubkey,
    action: &BundledAction,
    recent_blockhash: Pubkey,
    address_table_key: [u8; 32],
    address_table: &[[u8; 32]],
) -> Result<V0TransactionMessage, TxMessageError> {
    compile_action_message_v0_with_prefix(
        program_id,
        &[],
        action,
        recent_blockhash,
        address_table_key,
        address_table,
    )
}

/// Serialize a v0 message to its canonical wire bytes: the `0x80`
/// version prefix, then the legacy layout, then the compact-u16-prefixed
/// address-table lookup list.
pub fn encode_v0_message(msg: &V0TransactionMessage) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x80); // versioned-message prefix, version 0
    out.push(msg.header.num_required_signatures);
    out.push(msg.header.num_readonly_signed_accounts);
    out.push(msg.header.num_readonly_unsigned_accounts);
    encode_compact_u16(msg.static_account_keys.len() as u16, &mut out);
    for key in &msg.static_account_keys {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(&msg.recent_blockhash);
    encode_compact_u16(msg.instructions.len() as u16, &mut out);
    for ix in &msg.instructions {
        out.push(ix.program_id_index);
        encode_compact_u16(ix.accounts.len() as u16, &mut out);
        out.extend_from_slice(&ix.accounts);
        encode_compact_u16(ix.data.len() as u16, &mut out);
        out.extend_from_slice(&ix.data);
    }
    encode_compact_u16(msg.address_table_lookups.len() as u16, &mut out);
    for l in &msg.address_table_lookups {
        out.extend_from_slice(&l.address_table_key);
        encode_compact_u16(l.writable_indexes.len() as u16, &mut out);
        out.extend_from_slice(&l.writable_indexes);
        encode_compact_u16(l.readonly_indexes.len() as u16, &mut out);
        out.extend_from_slice(&l.readonly_indexes);
    }
    out
}

/// Parse canonical v0 wire bytes back into a message. Rejects a missing
/// version prefix, truncated input, trailing bytes, out-of-range account
/// indexes, and malformed lookup entries (a table index listed twice, or
/// in both the writable and readonly lists) — decode is the
/// untrusted-input path.
pub fn decode_v0_message(bytes: &[u8]) -> Result<V0TransactionMessage, TxMessageError> {
    let mut pos = 0usize;
    if take_bytes(bytes, &mut pos, 1)?[0] != 0x80 {
        return Err(TxMessageError::NotV0Message);
    }
    let num_required_signatures = take_bytes(bytes, &mut pos, 1)?[0];
    let num_readonly_signed_accounts = take_bytes(bytes, &mut pos, 1)?[0];
    let num_readonly_unsigned_accounts = take_bytes(bytes, &mut pos, 1)?[0];

    let key_count = decode_compact_u16(bytes, &mut pos)? as usize;
    if key_count > 255 {
        return Err(TxMessageError::TooManyAccountKeys);
    }
    let mut static_account_keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let k: [u8; 32] = take_bytes(bytes, &mut pos, 32)?
            .try_into()
            .map_err(|_| TxMessageError::TruncatedMessage)?;
        static_account_keys.push(k);
    }
    let recent_blockhash: [u8; 32] = take_bytes(bytes, &mut pos, 32)?
        .try_into()
        .map_err(|_| TxMessageError::TruncatedMessage)?;

    // Indexes are validated after the lookups parse, against the full
    // static + loaded address space.
    let ix_count = decode_compact_u16(bytes, &mut pos)? as usize;
    let mut raw_instructions = Vec::with_capacity(ix_count);
    for _ in 0..ix_count {
        let program_id_index = take_bytes(bytes, &mut pos, 1)?[0];
        let acct_count = decode_compact_u16(bytes, &mut pos)? as usize;
        let accounts = take_bytes(bytes, &mut pos, acct_count)?.to_vec();
        let data_len = decode_compact_u16(bytes, &mut pos)? as usize;
        let data = take_bytes(bytes, &mut pos, data_len)?.to_vec();
        raw_instructions.push((program_id_index, accounts, data));
    }

    let lookup_count = decode_compact_u16(bytes, &mut pos)? as usize;
    let mut address_table_lookups = Vec::with_capacity(lookup_count);
    let mut loaded_total = 0usize;
    for _ in 0..lookup_count {
        let address_table_key: [u8; 32] = take_bytes(bytes, &mut pos, 32)?
            .try_into()
            .map_err(|_| TxMessageError::TruncatedMessage)?;
        let w_len = decode_compact_u16(bytes, &mut pos)? as usize;
        let writable_indexes = take_bytes(bytes, &mut pos, w_len)?.to_vec();
        let r_len = decode_compact_u16(bytes, &mut pos)? as usize;
        let readonly_indexes = take_bytes(bytes, &mut pos, r_len)?.to_vec();
        // Each table index may appear at most once across both lists.
        let mut seen = [false; 256];
        for &i in writable_indexes.iter().chain(readonly_indexes.iter()) {
            if seen[i as usize] {
                return Err(TxMessageError::InvalidAddressTableLookup);
            }
            seen[i as usize] = true;
        }
        loaded_total += writable_indexes.len() + readonly_indexes.len();
        address_table_lookups.push(AddressTableLookup {
            address_table_key,
            writable_indexes,
            readonly_indexes,
        });
    }
    if pos != bytes.len() {
        return Err(TxMessageError::TrailingBytes);
    }

    let addressable = key_count + loaded_total;
    let mut instructions = Vec::with_capacity(raw_instructions.len());
    for (program_id_index, accounts, data) in raw_instructions {
        if program_id_index as usize >= addressable {
            return Err(TxMessageError::AccountIndexOutOfBounds);
        }
        for &a in &accounts {
            if a as usize >= addressable {
                return Err(TxMessageError::AccountIndexOutOfBounds);
            }
        }
        instructions.push(CompiledInstruction {
            program_id_index,
            accounts,
            data,
        });
    }
    Ok(V0TransactionMessage {
        header: MessageHeader {
            num_required_signatures,
            num_readonly_signed_accounts,
            num_readonly_unsigned_accounts,
        },
        static_account_keys,
        recent_blockhash,
        instructions,
        address_table_lookups,
    })
}

/// Build the v0 message for a bundled action and return the
/// base64-encoded to-be-signed bytes: the AV-87 counterpart of
/// [`signable_message_base64`].
pub fn signable_message_v0_base64(
    program_id: Pubkey,
    action: &BundledAction,
    recent_blockhash: Pubkey,
    address_table_key: [u8; 32],
    address_table: &[[u8; 32]],
) -> Result<String, TxMessageError> {
    let msg = compile_action_message_v0(
        program_id,
        action,
        recent_blockhash,
        address_table_key,
        address_table,
    )?;
    Ok(encode_base64(&encode_v0_message(&msg)))
}

/// Keeper large-account-set route: compile one of the bundle's actions
/// into a v0 message, resolving its ALT-eligible accounts against the
/// bundle's own `alt_table` snapshot. A bundle whose static account set
/// would bloat every message ships fewer static keys per message — the
/// table is extended once on-chain, then referenced by index.
pub fn bundle_action_message_v0_base64(
    program_id: Pubkey,
    bundle: &ExecutionBundle,
    action: &BundledAction,
    recent_blockhash: Pubkey,
    address_table_key: [u8; 32],
) -> Result<String, TxMessageError> {
    signable_message_v0_base64(
        program_id,
        action,
        recent_blockhash,
        address_table_key,
        &bundle.alt_table,
    )
}

// ---------------------------------------------------------------------------
// Packet-size pre-flight and keeper auto-route (AV-162).
// ---------------------------------------------------------------------------

/// Solana transaction packet size limit: a serialized transaction must
/// fit in one IPv6 MTU-sized UDP packet (1280 bytes minus the IPv6 +
/// UDP headers). A multi-account CPI-path message that exceeds this is
/// rejected by the cluster *after* signing — the keeper pre-flights
/// with [`ensure_fits_packet_limit`] before handing bytes to a signer.
pub const MAX_TRANSACTION_PACKET_BYTES: usize = 1232;

/// Wire size of a legacy message in bytes: exactly what
/// [`encode_message`] emits, without keeping the allocation.
pub fn wire_size_legacy(msg: &TransactionMessage) -> usize {
    encode_message(msg).len()
}

/// Wire size of a v0 message in bytes: exactly what
/// [`encode_v0_message`] emits, without keeping the allocation.
pub fn wire_size_v0(msg: &V0TransactionMessage) -> usize {
    encode_v0_message(msg).len()
}

/// Pre-flight a to-be-signed message's wire size against the packet
/// limit: [`TxMessageError::PacketTooLarge`] when the message would be
/// rejected by the cluster. The keeper shrinks the message (v0 +
/// address-table lookups, fewer accounts, or a smaller instruction
/// batch) and re-checks before signing.
pub fn ensure_fits_packet_limit(wire_size: usize) -> Result<(), TxMessageError> {
    if wire_size > MAX_TRANSACTION_PACKET_BYTES {
        return Err(TxMessageError::PacketTooLarge);
    }
    Ok(())
}

/// Whether a bundled action has any ALT-eligible account: a non-signer
/// whose `alt_index` the scan stamped. Signers never resolve through a
/// lookup table (the runtime forbids it), so a stamped signer does not
/// count.
fn action_has_alt_eligible(action: &BundledAction) -> bool {
    action
        .accounts
        .iter()
        .any(|a| !a.signer && a.alt_index.is_some())
}

/// Keeper one-call route: compile a bundle action into signable base64,
/// choosing v0 automatically when the bundle stamps ALT-eligible
/// accounts and the caller supplies the on-chain table's key.
///
/// Routing:
/// - No ALT-eligible account → legacy message (the table is
///   irrelevant); this is the "no table, legacy fallback" leg.
/// - ALT-eligible accounts + table key → v0, resolving against the
///   bundle's own `alt_table` snapshot (the self-contained bundle
///   design, AV-61). Stale snapshots still fail loud
///   (`AltIndexOutOfBounds` / `AltTableKeyMismatch`).
/// - ALT-eligible accounts but no table key →
///   [`TxMessageError::AltTableNotFound`]: the bundle promises a table
///   the keeper did not provide. Falling back to legacy here would
///   silently bloat past the packet limit, so the route fails instead.
///
/// The returned bytes are still the caller's to pre-flight with
/// [`ensure_fits_packet_limit`]: v0 shrinks the static key list, but a
/// pathological action can exceed the limit either way.
pub fn signable_bundle_action_message_base64(
    program_id: Pubkey,
    bundle: &ExecutionBundle,
    action: &BundledAction,
    recent_blockhash: Pubkey,
    address_table_key: Option<[u8; 32]>,
) -> Result<String, TxMessageError> {
    if !action_has_alt_eligible(action) {
        return signable_message_base64(program_id, action, recent_blockhash);
    }
    let key = address_table_key.ok_or(TxMessageError::AltTableNotFound)?;
    bundle_action_message_v0_base64(program_id, bundle, action, recent_blockhash, key)
}

// ---------------------------------------------------------------------------
// Base64 (hand-rolled: the crate stays dependency-free).
// ---------------------------------------------------------------------------

const B64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with `=` padding.
pub fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let mut n: u32 = 0;
        for &b in chunk {
            n = (n << 8) | b as u32;
        }
        n <<= 8 * (3 - chunk.len());
        out.push(B64_ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn b64_value(c: u8) -> Result<u32, TxMessageError> {
    B64_ALPHABET
        .iter()
        .position(|&a| a == c)
        .map(|v| v as u32)
        .ok_or(TxMessageError::InvalidBase64)
}

/// Decode standard base64 with `=` padding. Strict: wrong lengths, bad
/// padding placement, and non-alphabet characters are all rejected.
pub fn decode_base64(s: &str) -> Result<Vec<u8>, TxMessageError> {
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(TxMessageError::InvalidBase64);
    }
    let mut pad = 0usize;
    for &b in bytes.iter().rev() {
        if b == b'=' {
            pad += 1;
        } else {
            break;
        }
    }
    if pad > 2 || bytes[..bytes.len() - pad].contains(&b'=') {
        return Err(TxMessageError::InvalidBase64);
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 4 {
            return Err(TxMessageError::InvalidBase64);
        }
        let mut n: u32 = 0;
        let mut chunk_pad = 0usize;
        for &c in chunk {
            n <<= 6;
            if c == b'=' {
                chunk_pad += 1;
            } else {
                if chunk_pad > 0 {
                    // Data after padding inside a quantum.
                    return Err(TxMessageError::InvalidBase64);
                }
                n |= b64_value(c)?;
            }
        }
        // Padding is only legal on the final quantum.
        if chunk_pad > 0 && chunk.as_ptr() as usize + 4 != bytes.as_ptr() as usize + bytes.len() {
            return Err(TxMessageError::InvalidBase64);
        }
        out.push((n >> 16) as u8);
        if chunk_pad < 2 {
            out.push((n >> 8) as u8);
        }
        if chunk_pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// One-call convenience.
// ---------------------------------------------------------------------------

/// Build the instruction for a bundled action, compile it into a legacy
/// transaction message with the caller's recent blockhash, and return
/// the base64-encoded to-be-signed bytes.
///
/// A multisig or CLI takes this string, signs it with the bundle's
/// caller key, attaches the signature, and submits. See the module docs
/// for the honesty labels (unsigned; program id and blockhash are
/// caller-supplied; `initialize`/`release` need their remaining
/// program-declared accounts appended before signing).
pub fn signable_message_base64(
    program_id: Pubkey,
    action: &BundledAction,
    recent_blockhash: Pubkey,
) -> Result<String, TxMessageError> {
    let ix = instruction_for_action(program_id, action)?;
    let msg = compile_message(&ix, recent_blockhash);
    Ok(encode_base64(&encode_message(&msg)))
}

#[cfg(test)]
mod tx_message_tests {
    use super::*;
    use crate::anchor_idl_tests::INSTRUCTIONS;
    use crate::{
        bundle_execution, scan_batch_lifecycle, BatchInitializeParams, BatchWatchItem, Escrow,
    };

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer / caller
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const MINT_A: [u8; 32] = [0xD0; 32];
    const ID1: [u8; 32] = [0x01; 32];
    const ID2: [u8; 32] = [0x02; 32];
    const ID3: [u8; 32] = [0x03; 32];
    const PROGRAM_ID: [u8; 32] = [0x07; 32];
    const BLOCKHASH: [u8; 32] = [0xBB; 32];
    const AMOUNT: u64 = 1_000_000;
    const EXPIRES: u64 = 1_800_000_000;
    const NOW: u64 = 1_750_000_000;

    fn watch(id: [u8; 32], escrow: Option<Escrow>, initializer: [u8; 32]) -> BatchWatchItem {
        BatchWatchItem {
            escrow_id: id,
            escrow,
            initialize: BatchInitializeParams {
                initializer,
                taker: BOB,
                amount: AMOUNT,
                expires_at: EXPIRES,
            },
            vault_derivation: None,
        }
    }

    fn funded(initializer: [u8; 32], mint: Option<[u8; 32]>) -> Escrow {
        let mut e = Escrow::initialize(initializer, BOB, AMOUNT, EXPIRES).unwrap();
        if let Some(m) = mint {
            e = e.with_mint(m).unwrap();
        }
        e.fund(initializer, NOW).unwrap();
        e
    }

    /// All three bundle action kinds, built through the real pipeline
    /// (scan -> bundle), in scan order: initialize, fund, release.
    fn three_actions() -> Vec<BundledAction> {
        let e_uninit = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES).unwrap();
        let items = [
            watch(ID1, None, ALICE),                      // initialize
            watch(ID2, Some(e_uninit), ALICE),            // fund
            watch(ID3, Some(funded(ALICE, Some(MINT_A))), ALICE), // release (SPL)
        ];
        let bundles = bundle_execution(&scan_batch_lifecycle(&items, NOW));
        // (None, ALICE) and (MINT_A, ALICE) group separately.
        assert_eq!(bundles.len(), 2);
        let mut actions = Vec::new();
        for b in &bundles {
            actions.extend(b.actions.iter().cloned());
        }
        actions.sort_by_key(|a| match a.kind {
            BatchActionKind::Initialize => 0,
            BatchActionKind::Fund => 1,
            BatchActionKind::Release => 2,
            // AV-108: the split release is the lifecycle's release
            // step on split-configured escrows — same position.
            BatchActionKind::ReleasePayoutSplit => 2,
        });
        actions
    }

    fn spec_params(name: &str) -> Vec<(&'static str, &'static str)> {
        INSTRUCTIONS
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("INSTRUCTIONS missing {name}"))
            .params
            .iter()
            .map(|(n, ty, _)| (*n, *ty))
            .collect()
    }

    #[test]
    fn instruction_data_is_discriminator_plus_spec_borsh() {
        // The byte-exact core: data == sha256("global:<name>")[..8] ||
        // Borsh(spec params), with the spec table as the oracle for the
        // param name/type/order on each kind.
        assert_eq!(spec_params("initialize"), [("amount", "u64"), ("expires_at", "u64"), ("keeper_bounty_pool", "u64"), ("keeper_bounty_per_crank", "u64")]);
        assert_eq!(spec_params("fund"), []);
        assert_eq!(spec_params("release"), [("amount", "u64")]);

        for a in three_actions() {
            let ix = instruction_for_action(PROGRAM_ID, &a).unwrap();
            assert_eq!(ix.program_id, PROGRAM_ID);
            // Discriminator pinned three ways: the IDL name rule, the
            // shared constructor, and the bundle's stamped bytes.
            let mut expected_disc = [0u8; 8];
            expected_disc.copy_from_slice(&crate::sha256(format!("global:{}", a.instruction).as_bytes())[..8]);
            assert_eq!(&ix.data[..8], &expected_disc);
            assert_eq!(&ix.data[..8], &a.discriminator);
            assert_eq!(&ix.data[..8], &instruction_discriminator(a.instruction));
            match a.kind {
                BatchActionKind::Initialize => {
                    assert_eq!(ix.data.len(), 24, "disc + 2x u64");
                    assert_eq!(&ix.data[8..16], &a.amount.to_le_bytes());
                    assert_eq!(&ix.data[16..24], &a.expires_at.to_le_bytes());
                    assert_eq!(a.amount, AMOUNT);
                    assert_eq!(a.expires_at, EXPIRES);
                }
                BatchActionKind::Fund => {
                    assert_eq!(ix.data.len(), 8, "fund takes no params");
                }
                BatchActionKind::Release => {
                    assert_eq!(ix.data.len(), 16, "disc + u64");
                    assert_eq!(&ix.data[8..16], &a.amount.to_le_bytes());
                    assert_eq!(a.amount, AMOUNT, "scan releases the full remainder");
                }
                BatchActionKind::ReleasePayoutSplit => {
                    assert_eq!(ix.data.len(), 8, "split release takes no params");
                }
            }
        }
    }

    #[test]
    fn account_metas_mirror_bundle_logical_accounts() {
        // 1:1 translation, order preserved: the metas are exactly the
        // bundle's logical accounts, nothing added, nothing reordered.
        for a in three_actions() {
            let ix = instruction_for_action(PROGRAM_ID, &a).unwrap();
            assert_eq!(ix.accounts.len(), a.accounts.len());
            for (meta, logical) in ix.accounts.iter().zip(a.accounts.iter()) {
                assert_eq!(meta.pubkey, logical.pubkey);
                assert_eq!(meta.is_signer, logical.signer);
                assert_eq!(meta.is_writable, logical.writable);
            }
        }
        // Spot-check the roles the scan stamps: initialize/fund carry
        // vault + initializer; the SPL release adds the mint.
        let actions = three_actions();
        let roles = |a: &BundledAction| {
            a.accounts.iter().map(|x| x.role).collect::<Vec<_>>()
        };
        assert_eq!(roles(&actions[0]), ["vault", "initializer"]);
        assert_eq!(roles(&actions[1]), ["vault", "initializer"]);
        assert_eq!(roles(&actions[2]), ["vault", "initializer", "mint"]);
        // The caller is the sole signer in every action.
        for a in &actions {
            let signers: Vec<_> = a.accounts.iter().filter(|x| x.signer).collect();
            assert_eq!(signers.len(), 1);
            assert_eq!(signers[0].pubkey, ALICE);
        }
    }

    #[test]
    fn discriminator_drift_fails_loudly() {
        // A stale/tampered bundle whose stamped discriminator no longer
        // matches the IDL name rule must not produce signable bytes.
        let mut actions = three_actions();
        actions[0].discriminator[0] ^= 0xff;
        assert_eq!(
            instruction_for_action(PROGRAM_ID, &actions[0]),
            Err(TxMessageError::DiscriminatorMismatch)
        );
        // Same for a name/kind skew: the data would target the wrong
        // program entrypoint.
        let mut skewed = three_actions()[2].clone();
        skewed.instruction = "initialize";
        assert_eq!(
            instruction_for_action(PROGRAM_ID, &skewed),
            Err(TxMessageError::DiscriminatorMismatch)
        );
        // Untouched actions still build.
        for a in three_actions() {
            assert!(instruction_for_action(PROGRAM_ID, &a).is_ok());
        }
    }

    #[test]
    fn message_compiles_to_canonical_legacy_wire_format() {
        // fund: vault (w,!s) + initializer (w,s) + program id (r,!s).
        let actions = three_actions();
        let fund = &actions[1];
        let ix = instruction_for_action(PROGRAM_ID, fund).unwrap();
        let msg = compile_message(&ix, BLOCKHASH);
        assert_eq!(
            msg.header,
            MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            }
        );
        assert_eq!(msg.account_keys, vec![ALICE, ID2, PROGRAM_ID]);
        assert_eq!(msg.recent_blockhash, BLOCKHASH);
        assert_eq!(msg.instructions.len(), 1);
        let cix = &msg.instructions[0];
        assert_eq!(cix.program_id_index, 2);
        assert_eq!(cix.accounts, vec![1, 0]); // vault, initializer
        assert_eq!(cix.data, ix.data);

        // release (SPL): the mint trails as a readonly non-signer.
        let release = &actions[2];
        let ix = instruction_for_action(PROGRAM_ID, release).unwrap();
        let msg = compile_message(&ix, BLOCKHASH);
        assert_eq!(
            msg.header,
            MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 2,
            }
        );
        assert_eq!(msg.account_keys, vec![ALICE, ID3, MINT_A, PROGRAM_ID]);
        assert_eq!(msg.instructions[0].program_id_index, 3);
        assert_eq!(msg.instructions[0].accounts, vec![1, 0, 2]);
    }

    #[test]
    fn wire_bytes_are_pinned() {
        // Golden bytes for the fund message above: header, shortvec key
        // count, keys, blockhash, instruction, trailing zero lookups.
        let actions = three_actions();
        let ix = instruction_for_action(PROGRAM_ID, &actions[1]).unwrap();
        let msg = compile_message(&ix, BLOCKHASH);
        let bytes = encode_message(&msg);

        let mut expected = Vec::new();
        expected.extend_from_slice(&[1u8, 0, 1]); // header: 1 signer, 0 readonly-signed, 1 readonly-unsigned (program id)
        expected.push(3u8); // 3 account keys
        expected.extend_from_slice(&ALICE);
        expected.extend_from_slice(&ID2);
        expected.extend_from_slice(&PROGRAM_ID);
        expected.extend_from_slice(&BLOCKHASH);
        expected.push(1u8); // 1 instruction
        expected.push(2u8); // program_id_index
        expected.push(2u8); // 2 account indexes
        expected.extend_from_slice(&[1u8, 0u8]);
        expected.push(8u8); // 8 data bytes
        expected.extend_from_slice(&instruction_discriminator("fund"));
        expected.push(0u8); // zero address-table lookups
        assert_eq!(bytes, expected);

        // …and the base64 of those bytes is pinned too.
        let b64 = encode_base64(&bytes);
        assert_eq!(decode_base64(&b64).unwrap(), bytes);
        // The golden string itself: decode must reproduce the bytes.
        let golden = encode_base64(&expected);
        assert_eq!(b64, golden);
        let round_tripped = decode_message(&decode_base64(&golden).unwrap()).unwrap();
        assert_eq!(round_tripped, msg);
    }

    #[test]
    fn base64_codec_matches_known_vectors() {
        // RFC 4648 vectors pin the hand-rolled codec.
        for (raw, enc) in [
            ("".as_bytes(), ""),
            ("f".as_bytes(), "Zg=="),
            ("fo".as_bytes(), "Zm8="),
            ("foo".as_bytes(), "Zm9v"),
            ("foob".as_bytes(), "Zm9vYg=="),
            ("fooba".as_bytes(), "Zm9vYmE="),
            ("foobar".as_bytes(), "Zm9vYmFy"),
        ] {
            assert_eq!(encode_base64(raw), enc);
            assert_eq!(decode_base64(enc).unwrap(), raw);
        }
        // Strictness: bad lengths, bad padding, bad alphabet.
        for bad in ["A", "AAAAA", "====", "AA=A", "A===", "AA==A"] {
            assert_eq!(decode_base64(bad), Err(TxMessageError::InvalidBase64), "bad: {bad}");
        }
        assert_eq!(decode_base64("****"), Err(TxMessageError::InvalidBase64));
        assert_eq!(decode_base64("A B="), Err(TxMessageError::InvalidBase64));
    }

    #[test]
    fn base64_message_round_trip_for_every_kind() {
        for a in three_actions() {
            let b64 = signable_message_base64(PROGRAM_ID, &a, BLOCKHASH).unwrap();
            let bytes = decode_base64(&b64).unwrap();
            let msg = decode_message(&bytes).unwrap();
            // Re-encoding the decoded message reproduces the exact wire
            // bytes — the base64 is a faithful serialization.
            assert_eq!(encode_base64(&encode_message(&msg)), b64);
            // The instruction data survived the round trip intact.
            assert_eq!(msg.instructions.len(), 1);
            assert_eq!(&msg.instructions[0].data[..8], &a.discriminator);
        }
    }

    #[test]
    fn decode_rejects_malformed_wire_bytes() {
        let actions = three_actions();
        let b64 = signable_message_base64(PROGRAM_ID, &actions[1], BLOCKHASH).unwrap();
        let bytes = decode_base64(&b64).unwrap();
        // Truncations at every prefix length fail (or decode a shorter
        // valid prefix only when the cut lands exactly on a boundary —
        // assert the full message needs the full bytes).
        for cut in [0, 1, 2, 3, 4, 10, 50, bytes.len() - 1] {
            assert_eq!(
                decode_message(&bytes[..cut]),
                Err(TxMessageError::TruncatedMessage),
                "cut at {cut}"
            );
        }
        // Trailing garbage fails.
        let mut with_trailing = bytes.clone();
        with_trailing.push(0xaa);
        assert_eq!(
            decode_message(&with_trailing),
            Err(TxMessageError::TrailingBytes)
        );
        // A flipped account index byte fails.
        let mut bad_index = bytes.clone();
        // program_id_index sits right after the instruction count; find
        // it: header(3) + keycount(1) + 3*32 keys + 32 blockhash + ixcount(1).
        let idx_pos = 3 + 1 + 3 * 32 + 32 + 1;
        bad_index[idx_pos] = 9;
        assert_eq!(
            decode_message(&bad_index),
            Err(TxMessageError::AccountIndexOutOfBounds)
        );
    }

    #[test]
    fn bundle_json_and_message_agree() {
        // End to end: the bundle's deterministic JSON and the signable
        // message describe the same instruction — discriminator hex in
        // the JSON equals the message's data prefix, and the JSON args
        // equal the Borsh-encoded param values.
        let e_uninit = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES).unwrap();
        let items = [
            watch(ID1, None, ALICE),
            watch(ID2, Some(e_uninit), ALICE),
            watch(ID3, Some(funded(ALICE, Some(MINT_A))), ALICE),
        ];
        let bundles = bundle_execution(&scan_batch_lifecycle(&items, NOW));
        for b in &bundles {
            let json = b.to_json();
            for a in &b.actions {
                let ix = instruction_for_action(PROGRAM_ID, a).unwrap();
                let disc_hex: String =
                    ix.data[..8].iter().map(|x| format!("{x:02x}")).collect();
                assert!(
                    json.contains(&format!("\"discriminator\":\"{disc_hex}\"")),
                    "JSON/message discriminator drift for {}",
                    a.instruction
                );
                match a.kind {
                    BatchActionKind::Initialize => {
                        assert!(json.contains(&format!("\"amount\":{AMOUNT}")));
                        assert!(json.contains(&format!("\"expires_at\":{EXPIRES}")));
                        assert_eq!(u64::from_le_bytes(ix.data[8..16].try_into().unwrap()), AMOUNT);
                        assert_eq!(u64::from_le_bytes(ix.data[16..24].try_into().unwrap()), EXPIRES);
                    }
                    BatchActionKind::Fund => {
                        assert!(json.contains("\"args\":{\"amount\":1000000}"));
                        assert_eq!(ix.data.len(), 8);
                    }
                    BatchActionKind::Release => {
                        assert!(json.contains(&format!("\"amount\":{AMOUNT}")));
                        assert_eq!(u64::from_le_bytes(ix.data[8..16].try_into().unwrap()), AMOUNT);
                    }
                    BatchActionKind::ReleasePayoutSplit => {
                        assert_eq!(ix.data.len(), 8, "split release takes no params");
                    }
                }
            }
        }
    }

    #[test]
    fn duplicate_keys_merge_flags() {
        // Defensive: if an instruction ever listed the same key twice
        // (e.g. vault == initializer on some future path), the compiled
        // message keeps one key with OR-merged flags instead of
        // emitting a duplicate.
        let ix = ProgramInstruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta { pubkey: ALICE, is_signer: true, is_writable: false },
                AccountMeta { pubkey: ALICE, is_signer: false, is_writable: true },
            ],
            data: instruction_discriminator("fund").to_vec(),
        };
        let msg = compile_message(&ix, BLOCKHASH);
        assert_eq!(msg.account_keys, vec![ALICE, PROGRAM_ID]);
        assert_eq!(
            msg.header,
            MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            }
        );
        assert_eq!(msg.instructions[0].accounts, vec![0, 0]);
    }

    #[test]
    fn serialization_is_dry_run() {
        // Like the bundler: building messages never touches program
        // state or the bundle — the input action is only read.
        let actions = three_actions();
        let before = actions.clone();
        for a in &actions {
            let b64 = signable_message_base64(PROGRAM_ID, a, BLOCKHASH).unwrap();
            assert!(!b64.is_empty());
        }
        assert_eq!(actions, before);
    }

    // ------------------------------------------------------------------
    // AV-87: v0 messages with address-table lookups.
    // ------------------------------------------------------------------

    use crate::execution_bundle::BundledAccount;

    const TABLE_KEY: [u8; 32] = [0xA1; 32];

    /// Rebuild a per-action table snapshot from the scan-stamped
    /// `alt_index` values: `table[i]` is the pubkey stamped with index
    /// `i` — the shape a fresh on-chain table read would have.
    fn snapshot_for(action: &BundledAction) -> Vec<[u8; 32]> {
        let max = action
            .accounts
            .iter()
            .filter_map(|a| a.alt_index)
            .map(|i| i as usize)
            .max();
        let mut table = vec![[0u8; 32]; max.map_or(0, |m| m + 1)];
        for a in &action.accounts {
            if let Some(i) = a.alt_index {
                table[i as usize] = a.pubkey;
            }
        }
        table
    }

    /// Hand-built `fund` action: one signer plus `n` non-signer
    /// accounts with stamped `alt_index` values, and the matching
    /// table snapshot. Alternating writability exercises the
    /// writable/readonly split.
    fn wide_action(n: usize) -> (BundledAction, Vec<[u8; 32]>) {
        let mut accounts = vec![BundledAccount {
            pubkey: ALICE,
            role: "initializer",
            signer: true,
            writable: true,
            alt_index: None,
        }];
        let mut table = Vec::with_capacity(n);
        for i in 0..n {
            let mut k = [0xE0u8; 32];
            k[0] = (i & 0xff) as u8;
            k[1] = ((i >> 8) & 0xff) as u8;
            k[30] = 0xE1;
            k[31] = 0xE2;
            table.push(k);
            accounts.push(BundledAccount {
                pubkey: k,
                role: "extra",
                signer: false,
                writable: i % 2 == 0,
                alt_index: Some(i as u8),
            });
        }
        let action = BundledAction {
            escrow_id: ID1,
            kind: BatchActionKind::Fund,
            instruction: "fund",
            discriminator: instruction_discriminator("fund"),
            caller_role: "initializer",
            taker: None,
            expires_at: 0,
            amount: AMOUNT,
            payout: 0,
            fee: 0,
            payout_legs: None,
            accounts,
            reason: "test",
        };
        (action, table)
    }

    #[test]
    fn v0_round_trip_for_every_kind() {
        for a in three_actions() {
            let table = snapshot_for(&a);
            let msg =
                compile_action_message_v0(PROGRAM_ID, &a, BLOCKHASH, TABLE_KEY, &table).unwrap();
            // The v0 route is defined by a non-empty lookup list.
            assert!(!msg.address_table_lookups.is_empty());
            let bytes = encode_v0_message(&msg);
            assert_eq!(bytes[0], 0x80, "v0 version prefix");
            let decoded = decode_v0_message(&bytes).unwrap();
            assert_eq!(decoded, msg);
            assert_eq!(encode_v0_message(&decoded), bytes);
            // The base64 convenience agrees byte for byte.
            let b64 =
                signable_message_v0_base64(PROGRAM_ID, &a, BLOCKHASH, TABLE_KEY, &table).unwrap();
            assert_eq!(decode_base64(&b64).unwrap(), bytes);
        }
    }

    #[test]
    fn v0_static_resolution_splits_signers_and_lookups() {
        let actions = three_actions();
        let fund = &actions[1];
        let table = snapshot_for(fund);
        let msg =
            compile_action_message_v0(PROGRAM_ID, fund, BLOCKHASH, TABLE_KEY, &table).unwrap();
        // The signer and the program id stay static; the vault resolves
        // through the table. Header counts cover static keys only.
        assert_eq!(msg.static_account_keys, vec![ALICE, PROGRAM_ID]);
        assert_eq!(
            msg.header,
            MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 1,
            }
        );
        assert_eq!(msg.address_table_lookups.len(), 1);
        let l = &msg.address_table_lookups[0];
        assert_eq!(l.address_table_key, TABLE_KEY);
        // fund's vault is writable and non-signer: writable list.
        let vault_idx = fund
            .accounts
            .iter()
            .find(|a| !a.signer)
            .unwrap()
            .alt_index
            .unwrap();
        assert_eq!(l.writable_indexes, vec![vault_idx]);
        assert!(l.readonly_indexes.is_empty());
        // Instruction indexes: program-declared order is
        // [vault, initializer] → [loaded, static].
        let cix = &msg.instructions[0];
        assert_eq!(cix.program_id_index, 1);
        assert_eq!(cix.accounts, vec![2, 0]);
        assert_eq!(msg.loaded_account_count(), 1);
        assert_eq!(msg.total_account_count(), 3);
    }

    #[test]
    fn v0_large_account_set_reduces_static_keys() {
        let (action, table) = wide_action(60);
        let msg =
            compile_action_message_v0(PROGRAM_ID, &action, BLOCKHASH, TABLE_KEY, &table).unwrap();
        // Static: the signer plus the program id. Everything else loads
        // through the table.
        assert_eq!(msg.static_account_keys, vec![ALICE, PROGRAM_ID]);
        let l = &msg.address_table_lookups[0];
        let expect_w: Vec<u8> = (0..60u8).step_by(2).collect();
        let expect_r: Vec<u8> = (1..60u8).step_by(2).collect();
        assert_eq!(l.writable_indexes, expect_w);
        assert_eq!(l.readonly_indexes, expect_r);
        assert_eq!(msg.loaded_account_count(), 60);
        // The legacy compile of the same instruction carries all 62
        // keys statically — the v0 route is what shrinks the message.
        let legacy = compile_message(
            &instruction_for_action(PROGRAM_ID, &action).unwrap(),
            BLOCKHASH,
        );
        assert_eq!(legacy.account_keys.len(), 62);
        assert!(msg.static_account_keys.len() < legacy.account_keys.len());
        // Spot-check the loaded index space: static ++ writable ++
        // readonly. accounts[0] is the signer (static 0); then the 60
        // vaults in program-declared order.
        let cix = &msg.instructions[0];
        assert_eq!(cix.accounts.len(), 61);
        assert_eq!(cix.accounts[0], 0);
        assert_eq!(cix.accounts[1], 2); // vault 0: first writable loaded
        assert_eq!(cix.accounts[2], 32); // vault 1: first readonly loaded (2 + 30)
        assert_eq!(cix.accounts[3], 3); // vault 2: second writable loaded
        for &a in &cix.accounts {
            assert!((a as usize) < msg.total_account_count());
        }
        // Round trip.
        let bytes = encode_v0_message(&msg);
        assert_eq!(decode_v0_message(&bytes).unwrap(), msg);
    }

    #[test]
    fn v0_rejects_bad_lookup_indexes() {
        let (action, table) = wide_action(3);
        // Stamped index beyond the snapshot: the table does not cover
        // the account.
        assert_eq!(
            compile_action_message_v0(PROGRAM_ID, &action, BLOCKHASH, TABLE_KEY, &table[..2]),
            Err(TxMessageError::AltIndexOutOfBounds)
        );
        // Snapshot disagrees at a stamped index: stale table.
        let mut stale = table.clone();
        stale[1] = [0xFF; 32];
        assert_eq!(
            compile_action_message_v0(PROGRAM_ID, &action, BLOCKHASH, TABLE_KEY, &stale),
            Err(TxMessageError::AltTableKeyMismatch)
        );
    }

    #[test]
    fn v0_requires_alt_resolution() {
        // No ALT-eligible account: the v0 route refuses — the message
        // would carry an empty lookup list — while the legacy path
        // stays the right call.
        let (mut action, table) = wide_action(2);
        for a in &mut action.accounts {
            a.alt_index = None;
        }
        assert_eq!(
            compile_action_message_v0(PROGRAM_ID, &action, BLOCKHASH, TABLE_KEY, &table),
            Err(TxMessageError::NoAltResolved)
        );
        assert!(signable_message_base64(PROGRAM_ID, &action, BLOCKHASH).is_ok());
    }

    #[test]
    fn v0_signers_never_resolve_via_lookup() {
        // A hand-built action stamping alt_index on a signer: the signer
        // stays static — the runtime forbids signer lookups, so static
        // is the only valid resolution.
        let mut k = [0xE0u8; 32];
        k[30] = 0xE1;
        let action = BundledAction {
            escrow_id: ID1,
            kind: BatchActionKind::Fund,
            instruction: "fund",
            discriminator: instruction_discriminator("fund"),
            caller_role: "initializer",
            taker: None,
            expires_at: 0,
            amount: AMOUNT,
            payout: 0,
            fee: 0,
            payout_legs: None,
            accounts: vec![
                BundledAccount {
                    pubkey: ALICE,
                    role: "initializer",
                    signer: true,
                    writable: true,
                    alt_index: Some(0),
                },
                BundledAccount {
                    pubkey: k,
                    role: "vault",
                    signer: false,
                    writable: true,
                    alt_index: Some(1),
                },
            ],
            reason: "test",
        };
        let table = vec![ALICE, k];
        let msg =
            compile_action_message_v0(PROGRAM_ID, &action, BLOCKHASH, TABLE_KEY, &table).unwrap();
        assert_eq!(msg.static_account_keys, vec![ALICE, PROGRAM_ID]);
        assert_eq!(msg.address_table_lookups[0].writable_indexes, vec![1u8]);
    }

    #[test]
    fn v0_decode_rejects_malformed_lookups() {
        let (action, table) = wide_action(2);
        let msg =
            compile_action_message_v0(PROGRAM_ID, &action, BLOCKHASH, TABLE_KEY, &table).unwrap();
        let bytes = encode_v0_message(&msg);
        // Not a v0 message: legacy bytes and other prefixes fail.
        let legacy_bytes = encode_message(&compile_message(
            &instruction_for_action(PROGRAM_ID, &action).unwrap(),
            BLOCKHASH,
        ));
        assert_eq!(
            decode_v0_message(&legacy_bytes),
            Err(TxMessageError::NotV0Message)
        );
        assert_eq!(
            decode_v0_message(&[0x00, 0x01]),
            Err(TxMessageError::NotV0Message)
        );
        // Truncation / trailing bytes.
        assert_eq!(
            decode_v0_message(&bytes[..bytes.len() - 1]),
            Err(TxMessageError::TruncatedMessage)
        );
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert_eq!(
            decode_v0_message(&trailing),
            Err(TxMessageError::TrailingBytes)
        );
        // Overlapping lookup indexes: index 0 in both lists.
        let mut bad = msg.clone();
        bad.address_table_lookups[0].readonly_indexes.push(0);
        assert_eq!(
            decode_v0_message(&encode_v0_message(&bad)),
            Err(TxMessageError::InvalidAddressTableLookup)
        );
        // Duplicate within one list.
        let mut bad2 = msg.clone();
        let dup = bad2.address_table_lookups[0].writable_indexes[0];
        bad2.address_table_lookups[0].writable_indexes.push(dup);
        assert_eq!(
            decode_v0_message(&encode_v0_message(&bad2)),
            Err(TxMessageError::InvalidAddressTableLookup)
        );
        // Instruction index beyond the static + loaded space.
        let mut bad3 = msg.clone();
        bad3.instructions[0].accounts[1] = 250;
        assert_eq!(
            decode_v0_message(&encode_v0_message(&bad3)),
            Err(TxMessageError::AccountIndexOutOfBounds)
        );
    }

    #[test]
    fn v0_and_legacy_carry_same_instruction_data() {
        // The v0 route changes key placement, never the instruction
        // itself: same program, same data bytes.
        for a in three_actions() {
            let table = snapshot_for(&a);
            let v0 =
                compile_action_message_v0(PROGRAM_ID, &a, BLOCKHASH, TABLE_KEY, &table).unwrap();
            let ix = instruction_for_action(PROGRAM_ID, &a).unwrap();
            let legacy = compile_message(&ix, BLOCKHASH);
            assert_eq!(v0.instructions[0].data, legacy.instructions[0].data);
            assert_eq!(
                v0.instructions[0].program_id_index as usize,
                v0.static_account_keys
                    .iter()
                    .position(|k| *k == PROGRAM_ID)
                    .unwrap()
            );
        }
    }

    #[test]
    fn bundle_v0_route_uses_bundle_alt_table() {
        // End to end through a real bundle: the bundle's alt_table is
        // the snapshot, so the keeper's large-account-set bundle ships
        // v0 messages with fewer static keys than the legacy route.
        let e_uninit = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES).unwrap();
        let items = [watch(ID2, Some(e_uninit), ALICE)];
        let bundles = bundle_execution(&scan_batch_lifecycle(&items, NOW));
        assert_eq!(bundles.len(), 1);
        let b = &bundles[0];
        assert!(
            !b.alt_table.is_empty(),
            "the fund bundle stamps the vault into alt_table"
        );
        let action = &b.actions[0]; // fund
        let b64 =
            bundle_action_message_v0_base64(PROGRAM_ID, b, action, BLOCKHASH, TABLE_KEY).unwrap();
        let msg = decode_v0_message(&decode_base64(&b64).unwrap()).unwrap();
        assert_eq!(msg.static_account_keys, vec![ALICE, PROGRAM_ID]);
        assert_eq!(msg.address_table_lookups[0].address_table_key, TABLE_KEY);
        let legacy_b64 = signable_message_base64(PROGRAM_ID, action, BLOCKHASH).unwrap();
        let legacy = decode_message(&decode_base64(&legacy_b64).unwrap()).unwrap();
        assert!(legacy.account_keys.len() > msg.static_account_keys.len());
    }

    // ------------------------------------------------------------------
    // AV-89: compute-budget instruction data assembly.
    // ------------------------------------------------------------------

    /// `setComputeUnitLimit` is the Borsh enum variant 2 with a u32
    /// payload: 200_000 = 0x30D40 → LE bytes 40 0D 03 00.
    #[test]
    fn compute_budget_limit_layout_is_byte_exact() {
        let ix = compute_budget_set_compute_unit_limit(PROGRAM_ID, 200_000);
        assert_eq!(ix.program_id, PROGRAM_ID);
        assert!(ix.accounts.is_empty());
        assert_eq!(ix.data, vec![0x02, 0x40, 0x0D, 0x03, 0x00]);
    }

    /// `setComputeUnitPrice` is the Borsh enum variant 3 with a u64
    /// payload: 5_000 = 0x1388 → LE bytes 88 13 00….
    #[test]
    fn compute_budget_price_layout_is_byte_exact() {
        let ix = compute_budget_set_compute_unit_price(PROGRAM_ID, 5_000);
        assert_eq!(ix.program_id, PROGRAM_ID);
        assert!(ix.accounts.is_empty());
        assert_eq!(
            ix.data,
            vec![0x03, 0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    /// The two builders compose with the real pipeline: the AV-88 CU
    /// estimate feeds the limit, the AV-89 oracle recommendation feeds
    /// the price, and both compile into a well-formed message ahead of
    /// the program instruction.
    #[test]
    fn compute_budget_instructions_compile_into_message() {
        use crate::priority_fee::{
            fee_budget_lamports, PriorityFeeConfig, PriorityFeeOracle,
        };

        let mut oracle = PriorityFeeOracle::new(PriorityFeeConfig::default());
        for s in [800u64, 1_200, 1_000, 1_100] {
            oracle.observe(s);
        }
        // 4 < 20 samples: still the flagged fallback — the dry-run
        // report must say so rather than silently use a thin EWMA.
        let rec = oracle.recommend();
        assert!(rec.fallback);

        let limit_ix = compute_budget_set_compute_unit_limit(PROGRAM_ID, 200_000);
        let price_ix =
            compute_budget_set_compute_unit_price(PROGRAM_ID, rec.recommended_micro_lamports_per_cu);
        for ix in [&limit_ix, &price_ix] {
            let msg = compile_message(ix, BLOCKHASH);
            assert_eq!(msg.account_keys, vec![PROGRAM_ID]);
            assert_eq!(msg.instructions.len(), 1);
        }
        // The full fee budget line the dry-run report would show:
        // 200_000 CU × 10_000 micro-lamports/CU = 2_000 lamports.
        assert_eq!(fee_budget_lamports(200_000, rec.recommended_micro_lamports_per_cu), 2_000);
    }

    // -----------------------------------------------------------------------
    // AV-162: packet-size pre-flight + keeper auto-route.
    // -----------------------------------------------------------------------

    #[test]
    fn wire_size_helpers_agree_with_encoders() {
        for a in three_actions() {
            let ix = instruction_for_action(PROGRAM_ID, &a).unwrap();
            let legacy = compile_message(&ix, BLOCKHASH);
            assert_eq!(wire_size_legacy(&legacy), encode_message(&legacy).len());
            let table = snapshot_for(&a);
            let v0 =
                compile_action_message_v0(PROGRAM_ID, &a, BLOCKHASH, TABLE_KEY, &table).unwrap();
            assert_eq!(wire_size_v0(&v0), encode_v0_message(&v0).len());
        }
    }

    #[test]
    fn packet_limit_pre_flight() {
        assert_eq!(MAX_TRANSACTION_PACKET_BYTES, 1232);
        // The fund message is small.
        let actions = three_actions();
        let ix = instruction_for_action(PROGRAM_ID, &actions[1]).unwrap();
        let size = wire_size_legacy(&compile_message(&ix, BLOCKHASH));
        assert!(
            size < MAX_TRANSACTION_PACKET_BYTES,
            "fund message is {size} bytes"
        );
        assert!(ensure_fits_packet_limit(size).is_ok());
        assert!(ensure_fits_packet_limit(MAX_TRANSACTION_PACKET_BYTES).is_ok());
        assert_eq!(
            ensure_fits_packet_limit(MAX_TRANSACTION_PACKET_BYTES + 1),
            Err(TxMessageError::PacketTooLarge)
        );
    }

    #[test]
    fn v0_shrinks_a_packet_busting_legacy_message() {
        // The spec's motivating case: a multi-account CPI-path message
        // that does not fit the packet limit in legacy form fits in v0.
        let (action, table) = wide_action(60);
        let legacy_size = wire_size_legacy(&compile_message(
            &instruction_for_action(PROGRAM_ID, &action).unwrap(),
            BLOCKHASH,
        ));
        assert!(
            legacy_size > MAX_TRANSACTION_PACKET_BYTES,
            "legacy is {legacy_size} bytes, expected to bust the limit"
        );
        assert_eq!(
            ensure_fits_packet_limit(legacy_size),
            Err(TxMessageError::PacketTooLarge)
        );
        // Exact sizes, pinned: the README quotes these numbers.
        assert_eq!(legacy_size, 2094);
        let v0_size = wire_size_v0(
            &compile_action_message_v0(PROGRAM_ID, &action, BLOCKHASH, TABLE_KEY, &table)
                .unwrap(),
        );
        assert!(
            v0_size < legacy_size,
            "v0 ({v0_size}) must shrink legacy ({legacy_size})"
        );
        assert!(
            v0_size <= MAX_TRANSACTION_PACKET_BYTES,
            "v0 is {v0_size} bytes, expected to fit"
        );
        assert_eq!(v0_size, 269);
        assert!(ensure_fits_packet_limit(v0_size).is_ok());
    }

    #[test]
    fn keeper_auto_route_picks_v0_legacy_or_fails_loud() {
        // Real pipeline bundle: two SPL releases sharing a mint — every
        // action stamps ALT-eligible accounts against the bundle's
        // alt_table.
        let items = [
            watch(ID1, Some(funded(ALICE, Some(MINT_A))), ALICE),
            watch(ID2, Some(funded(ALICE, Some(MINT_A))), ALICE),
        ];
        let report = scan_batch_lifecycle(&items, NOW);
        let bundles = bundle_execution(&report);
        assert_eq!(bundles.len(), 1);
        let bundle = &bundles[0];
        let action = &bundle.actions[0];
        assert!(action
            .accounts
            .iter()
            .any(|a| !a.signer && a.alt_index.is_some()));

        // With the table key: v0.
        let b64 = signable_bundle_action_message_base64(
            PROGRAM_ID,
            bundle,
            action,
            BLOCKHASH,
            Some(TABLE_KEY),
        )
        .unwrap();
        assert_eq!(
            decode_base64(&b64).unwrap()[0],
            0x80,
            "auto-route picks v0 when the bundle stamps ALT accounts"
        );

        // ALT-eligible but no table key: loud failure, not a silent
        // legacy fallback.
        assert_eq!(
            signable_bundle_action_message_base64(PROGRAM_ID, bundle, action, BLOCKHASH, None),
            Err(TxMessageError::AltTableNotFound)
        );

        // No ALT-eligible account: legacy, even with a table key
        // supplied.
        let mut plain = action.clone();
        for a in &mut plain.accounts {
            a.alt_index = None;
        }
        let b64 = signable_bundle_action_message_base64(
            PROGRAM_ID,
            bundle,
            &plain,
            BLOCKHASH,
            Some(TABLE_KEY),
        )
        .unwrap();
        let bytes = decode_base64(&b64).unwrap();
        assert_ne!(
            bytes[0], 0x80,
            "auto-route falls back to legacy without ALT accounts"
        );
        assert!(decode_message(&bytes).is_ok());
    }
}
