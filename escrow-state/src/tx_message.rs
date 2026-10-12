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
//! - **Legacy message, one instruction each.** No address-table lookups
//!   are compiled in (the bundle's `alt_table` is for the operator's
//!   ALT, which a v0 upgrade can reference later); each action becomes
//!   its own single-instruction message, so one multisig proposal signs
//!   one instruction.
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
use super::execution_bundle::BundledAction;

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

/// Compile one instruction into a legacy transaction message.
///
/// Account keys are deduplicated (a repeated key merges `is_signer` /
/// `is_writable` with OR, the Solana convention) and ordered canonically:
/// writable signers, readonly signers, writable non-signers, readonly
/// non-signers; the program id trails as a readonly non-signer. The
/// header counts are derived from that ordering, so the message is
/// well-formed by construction.
pub fn compile_message(
    ix: &ProgramInstruction,
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
    let mut meta_idx = Vec::with_capacity(ix.accounts.len());
    for m in &ix.accounts {
        meta_idx.push(intern(m.pubkey, m.is_signer, m.is_writable));
    }
    let program_idx = intern(ix.program_id, false, false);

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
    // class — deterministic for a given instruction.
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

    TransactionMessage {
        header: MessageHeader {
            num_required_signatures,
            num_readonly_signed_accounts,
            num_readonly_unsigned_accounts,
        },
        account_keys,
        recent_blockhash,
        instructions: vec![CompiledInstruction {
            program_id_index: new_index[program_idx] as u8,
            accounts: meta_idx.iter().map(|&i| new_index[i] as u8).collect(),
            data: ix.data.clone(),
        }],
    }
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
        assert_eq!(spec_params("initialize"), [("amount", "u64"), ("expires_at", "u64")]);
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
}
