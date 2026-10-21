//! AV-167: durable-nonce transaction support for keeper execution bundles.
//!
//! The [`crate::tx_message`] builders assemble transactions against a
//! *recent blockhash*, which expires after ~150 slots: a bundle signed
//! now must be submitted almost immediately. A **durable nonce** is the
//! long-lived alternative — a nonce account (owned by the System
//! Program) whose stored blockhash value plays the blockhash role. The
//! transaction stays valid until someone advances the nonce account,
//! so the keeper (or a multisig) can sign a bundle offline now and
//! submit it hours or days later.
//!
//! Three pieces, all pure logic and dependency-free:
//!
//! 1. **Nonce-account parsing** ([`parse_nonce_account`]): the 80-byte
//!    nonce-account layout (`u32` version \|\| `u32` state \|\| authority
//!    pubkey \|\| stored blockhash \|\| `u64` lamports-per-signature),
//!    decoded from raw account data the caller fetched — an
//!    uninitialized state or an unknown version fails loud.
//! 2. **The advance instruction** ([`advance_nonce_instruction`]): the
//!    System Program `AdvanceNonceAccount` (index 4), the mandatory
//!    **first** instruction of a durable-nonce transaction. It binds
//!    the transaction to the nonce: the runtime checks the message's
//!    blockhash slot against the account's stored value, then advances
//!    the stored value — consuming the nonce.
//! 3. **Message assembly** ([`compile_message_with_nonce`] for legacy
//!    messages, [`compile_action_message_v0_with_nonce`] for the
//!    ALT v0 route): the advance instruction first, then the bundle's
//!    action, with the message's blockhash slot set to the nonce value.
//!
//! [`DurableNonceSession`] is the offline-signing session: sign against
//! [`DurableNonceSession::expected_blockhash`], then re-check the
//! account at submit time with
//! [`DurableNonceSession::check_fresh`] — a moved nonce
//! ([`DurableNonceError::NonceChanged`]) or a changed authority
//! ([`DurableNonceError::AuthorityMismatch`]) refuses the submit before
//! it can burn a signature round-trip on a blockhash the runtime would
//! reject.
//!
//! Design notes:
//! - The nonce authority must sign the transaction — the advance
//!   instruction marks it a signer, so the compiled message's header
//!   counts it. A session signed by anyone else fails the authority
//!   check at build time, not at submission.
//! - Pure logic never asserts the nonce account is actually
//!   system-owned or rent-exempt — that is chain state the machine
//!   cannot check. It only parses and binds what the caller fetched.
//! - The v0 + durable-nonce combination is the keeper's long-lived,
//!   large-account-set route (AV-87 ALT resolution still applies to
//!   the action's accounts; the advance instruction's accounts stay
//!   static).

use std::sync::OnceLock;

use super::cpi::{system_program_id, AccountMeta, Pubkey};
use super::execution_bundle::BundledAction;
use super::parse_mint_address;
use super::tx_message::{
    compile_action_message_v0_with_prefix, compile_instructions, encode_base64, encode_message,
    encode_v0_message, instruction_for_action, ProgramInstruction, TransactionMessage,
    TxMessageError, V0TransactionMessage,
};

/// Errors from nonce-account parsing, advance-instruction assembly, and
/// durable-nonce message construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableNonceError {
    /// The nonce-account data is shorter than the 80-byte nonce layout.
    TruncatedAccount,
    /// The nonce-account data is longer than the 80-byte nonce layout.
    TrailingBytes,
    /// The account holds no live nonce (`state == 0`, uninitialized).
    UninitializedNonce,
    /// The account's version or state field is not a known discriminant.
    InvalidVersion,
    /// The expected authority does not match the nonce account's
    /// authority.
    AuthorityMismatch,
    /// A required address is the zero address.
    ZeroAddress,
    /// The submit-time nonce value differs from the value the bundle
    /// was signed against — the nonce advanced (was consumed) or was
    /// reassigned after signing. Never submit: the signature cannot
    /// verify against the moved value.
    NonceChanged,
    /// Wraps a message-construction failure from `tx_message`.
    Message(TxMessageError),
}

/// A Solana nonce account is exactly 80 bytes: `u32` version (LE) \|\|
/// `u32` state (LE) \|\| authority `Pubkey` \|\| stored blockhash
/// (`Pubkey`) \|\| `u64` lamports-per-signature (LE). Version `1` is
/// `Versions::Current` (`0` is the legacy wrapper — same inner layout);
/// state `1` is `State::Initialized` carrying the durable nonce value.
pub const NONCE_ACCOUNT_LEN: usize = 80;

/// `Versions::Current` version discriminant.
pub const NONCE_VERSION_CURRENT: u32 = 1;

/// `Versions::Legacy` version discriminant — same inner state layout.
pub const NONCE_VERSION_LEGACY: u32 = 0;

/// `State::Initialized` state discriminant: the account carries a live
/// durable nonce value.
pub const NONCE_STATE_INITIALIZED: u32 = 1;

/// System Program instruction index for `AdvanceNonceAccount`.
pub const ADVANCE_NONCE_IX: u32 = 4;

/// The parsed durable-nonce account: the address it was read from, the
/// authority that may advance it, and the stored blockhash — the
/// durable nonce value that goes in the transaction message's
/// blockhash slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceAccount {
    /// The nonce account's address (caller-supplied — the parsed data
    /// does not carry it).
    pub address: Pubkey,
    /// The nonce authority: the only key that may advance this nonce,
    /// and a required signer of any transaction spending it.
    pub authority: Pubkey,
    /// The stored blockhash — the durable nonce value. Goes in the
    /// message's blockhash slot.
    pub blockhash: Pubkey,
    /// Lamports charged per signature when this nonce is spent.
    pub lamports_per_signature: u64,
}

/// Parse raw nonce-account data into a [`NonceAccount`].
///
/// `address` is the account the data was read from — the parse binds
/// the parsed values to that address so a submit-time re-read can be
/// compared field by field ([`DurableNonceSession::check_fresh`]).
pub fn parse_nonce_account(
    address: Pubkey,
    data: &[u8],
) -> Result<NonceAccount, DurableNonceError> {
    if data.len() < NONCE_ACCOUNT_LEN {
        return Err(DurableNonceError::TruncatedAccount);
    }
    if data.len() > NONCE_ACCOUNT_LEN {
        return Err(DurableNonceError::TrailingBytes);
    }
    let mut version_bytes = [0u8; 4];
    version_bytes.copy_from_slice(&data[0..4]);
    match u32::from_le_bytes(version_bytes) {
        NONCE_VERSION_CURRENT | NONCE_VERSION_LEGACY => {}
        _ => return Err(DurableNonceError::InvalidVersion),
    }
    let mut state_bytes = [0u8; 4];
    state_bytes.copy_from_slice(&data[4..8]);
    match u32::from_le_bytes(state_bytes) {
        0 => return Err(DurableNonceError::UninitializedNonce),
        NONCE_STATE_INITIALIZED => {}
        _ => return Err(DurableNonceError::InvalidVersion),
    }
    let mut authority = [0u8; 32];
    authority.copy_from_slice(&data[8..40]);
    let mut blockhash = [0u8; 32];
    blockhash.copy_from_slice(&data[40..72]);
    let mut fee_bytes = [0u8; 8];
    fee_bytes.copy_from_slice(&data[72..80]);
    Ok(NonceAccount {
        address,
        authority,
        blockhash,
        lamports_per_signature: u64::from_le_bytes(fee_bytes),
    })
}

/// The recent-blockhashes sysvar
/// (`SysvarRecentB1ockHashes11111111111111111111`) — the second account
/// of `AdvanceNonceAccount`.
pub fn recent_blockhashes_sysvar_id() -> Pubkey {
    static SYSVAR: OnceLock<Pubkey> = OnceLock::new();
    *SYSVAR.get_or_init(|| {
        parse_mint_address("SysvarRecentB1ockHashes11111111111111111111")
            .expect("hardcoded recent-blockhashes sysvar id must decode")
    })
}

/// Build the `AdvanceNonceAccount` instruction (System Program, index
/// 4, no data beyond the index): the mandatory **first** instruction of
/// a durable-nonce transaction.
///
/// Accounts: the nonce account (writable), the recent-blockhashes
/// sysvar (readonly), the nonce authority (signer). `authority` must
/// equal `nonce.authority` — a transaction spending someone else's
/// nonce is refused here, not at submission.
pub fn advance_nonce_instruction(
    nonce: &NonceAccount,
    authority: Pubkey,
) -> Result<ProgramInstruction, DurableNonceError> {
    if authority != nonce.authority {
        return Err(DurableNonceError::AuthorityMismatch);
    }
    if nonce.address == [0u8; 32] || authority == [0u8; 32] {
        return Err(DurableNonceError::ZeroAddress);
    }
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&ADVANCE_NONCE_IX.to_le_bytes());
    Ok(ProgramInstruction {
        program_id: system_program_id(),
        accounts: vec![
            AccountMeta {
                pubkey: nonce.address,
                is_signer: false,
                is_writable: true,
            },
            AccountMeta {
                pubkey: recent_blockhashes_sysvar_id(),
                is_signer: false,
                is_writable: false,
            },
            AccountMeta {
                pubkey: authority,
                is_signer: true,
                is_writable: false,
            },
        ],
        data,
    })
}

/// An offline-signing session over a durable nonce: the keeper (or
/// multisig) signs a transaction whose blockhash slot carries
/// `nonce.blockhash` instead of a recent blockhash. The signature stays
/// valid until someone advances the nonce account — no 150-slot expiry
/// — so the bundle can be signed now and submitted much later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableNonceSession {
    /// The nonce account the session was opened against.
    pub nonce: NonceAccount,
}

impl DurableNonceSession {
    /// Open a session against a parsed nonce account.
    pub fn new(nonce: NonceAccount) -> Self {
        Self { nonce }
    }

    /// The blockhash-slot value the session signs against — the nonce
    /// value at signing time.
    pub fn expected_blockhash(&self) -> Pubkey {
        self.nonce.blockhash
    }

    /// Re-parse the nonce account at submit time and verify nothing
    /// moved since signing: the same authority, the same stored
    /// blockhash. A moved nonce ([`DurableNonceError::NonceChanged`])
    /// or a changed authority
    /// ([`DurableNonceError::AuthorityMismatch`]) refuses the submit —
    /// the signature cannot verify against the new value, so
    /// submitting would burn the signature round-trip.
    pub fn check_fresh(&self, account_data: &[u8]) -> Result<(), DurableNonceError> {
        let current = parse_nonce_account(self.nonce.address, account_data)?;
        if current.authority != self.nonce.authority {
            return Err(DurableNonceError::AuthorityMismatch);
        }
        if current.blockhash != self.nonce.blockhash {
            return Err(DurableNonceError::NonceChanged);
        }
        Ok(())
    }
}

/// Compile one program instruction into a legacy durable-nonce message:
/// the `AdvanceNonceAccount` instruction first, then `ix`, with the
/// message's blockhash slot set to the nonce value.
///
/// The advance instruction is what binds the transaction to the nonce —
/// without it the runtime would treat the slot as a (long-expired)
/// recent blockhash and reject the transaction.
pub fn compile_message_with_nonce(
    ix: &ProgramInstruction,
    nonce: &NonceAccount,
) -> Result<TransactionMessage, DurableNonceError> {
    let advance = advance_nonce_instruction(nonce, nonce.authority)?;
    Ok(compile_instructions(&[advance, ix.clone()], nonce.blockhash))
}

/// Signable base64 for a bundled action under a durable nonce (legacy
/// message): the offline-signing artifact — encode once, sign offline,
/// submit while [`DurableNonceSession::check_fresh`] still passes.
pub fn signable_action_message_with_nonce_base64(
    program_id: Pubkey,
    action: &BundledAction,
    nonce: &NonceAccount,
) -> Result<String, DurableNonceError> {
    let ix =
        instruction_for_action(program_id, action).map_err(DurableNonceError::Message)?;
    let msg = compile_message_with_nonce(&ix, nonce)?;
    Ok(encode_base64(&encode_message(&msg)))
}

/// Compile a bundled action into a v0 durable-nonce message: the
/// `AdvanceNonceAccount` prefix first, then the action (with its AV-87
/// ALT resolution — the advance instruction's accounts stay static),
/// the blockhash slot set to the nonce value.
///
/// The v0 + durable-nonce combination is the keeper's long-lived,
/// large-account-set route: one address-table setup per bundle, one
/// signature that stays valid until the nonce advances.
pub fn compile_action_message_v0_with_nonce(
    program_id: Pubkey,
    action: &BundledAction,
    nonce: &NonceAccount,
    address_table_key: [u8; 32],
    address_table: &[[u8; 32]],
) -> Result<V0TransactionMessage, DurableNonceError> {
    let advance = advance_nonce_instruction(nonce, nonce.authority)?;
    compile_action_message_v0_with_prefix(
        program_id,
        &[advance],
        action,
        nonce.blockhash,
        address_table_key,
        address_table,
    )
    .map_err(DurableNonceError::Message)
}

/// Signable base64 for the v0 durable-nonce message — the offline
/// artifact for the keeper's long-lived bundle route.
pub fn signable_action_message_v0_with_nonce_base64(
    program_id: Pubkey,
    action: &BundledAction,
    nonce: &NonceAccount,
    address_table_key: [u8; 32],
    address_table: &[[u8; 32]],
) -> Result<String, DurableNonceError> {
    let msg = compile_action_message_v0_with_nonce(
        program_id,
        action,
        nonce,
        address_table_key,
        address_table,
    )?;
    Ok(encode_base64(&encode_v0_message(&msg)))
}

#[cfg(test)]
mod durable_nonce_tests {
    use super::*;
    use crate::execution_bundle::BundledAccount;
    use crate::tx_message::{decode_base64, decode_message, decode_v0_message};
    use crate::{BatchActionKind, Escrow};

    const NONCE_ADDR: [u8; 32] = [0xC0; 32];
    const AUTHORITY: [u8; 32] = [0xA1; 32];
    const NONCE_VALUE: [u8; 32] = [0x0B; 32];

    fn key(n: u8) -> Pubkey {
        [n; 32]
    }

    /// Hand-built 80-byte nonce-account fixture: version 1
    /// (`Versions::Current`), state 1 (`State::Initialized`), the
    /// authority, the stored blockhash, 5000 lamports per signature.
    fn nonce_fixture(blockhash: Pubkey) -> Vec<u8> {
        let mut data = Vec::with_capacity(NONCE_ACCOUNT_LEN);
        data.extend_from_slice(&NONCE_VERSION_CURRENT.to_le_bytes());
        data.extend_from_slice(&NONCE_STATE_INITIALIZED.to_le_bytes());
        data.extend_from_slice(&AUTHORITY);
        data.extend_from_slice(&blockhash);
        data.extend_from_slice(&5_000u64.to_le_bytes());
        data
    }

    fn parsed_nonce() -> NonceAccount {
        parse_nonce_account(NONCE_ADDR, &nonce_fixture(NONCE_VALUE)).unwrap()
    }

    #[test]
    fn parse_nonce_account_reads_the_layout() {
        let nonce = parsed_nonce();
        assert_eq!(nonce.address, NONCE_ADDR);
        assert_eq!(nonce.authority, AUTHORITY);
        assert_eq!(nonce.blockhash, NONCE_VALUE);
        assert_eq!(nonce.lamports_per_signature, 5_000);
        assert_eq!(nonce_fixture(NONCE_VALUE).len(), NONCE_ACCOUNT_LEN);
    }

    #[test]
    fn parse_rejects_bad_account_data() {
        // Short.
        let mut short = nonce_fixture(NONCE_VALUE);
        short.pop();
        assert_eq!(
            parse_nonce_account(NONCE_ADDR, &short),
            Err(DurableNonceError::TruncatedAccount)
        );
        assert_eq!(
            parse_nonce_account(NONCE_ADDR, &[]),
            Err(DurableNonceError::TruncatedAccount)
        );
        // Long.
        let mut long = nonce_fixture(NONCE_VALUE);
        long.push(0);
        assert_eq!(
            parse_nonce_account(NONCE_ADDR, &long),
            Err(DurableNonceError::TrailingBytes)
        );
        // Uninitialized state.
        let mut uninit = nonce_fixture(NONCE_VALUE);
        uninit[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_nonce_account(NONCE_ADDR, &uninit),
            Err(DurableNonceError::UninitializedNonce)
        );
        // Unknown version.
        let mut weird = nonce_fixture(NONCE_VALUE);
        weird[0..4].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(
            parse_nonce_account(NONCE_ADDR, &weird),
            Err(DurableNonceError::InvalidVersion)
        );
        // Unknown state discriminant.
        let mut weird_state = nonce_fixture(NONCE_VALUE);
        weird_state[4..8].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(
            parse_nonce_account(NONCE_ADDR, &weird_state),
            Err(DurableNonceError::InvalidVersion)
        );
    }

    #[test]
    fn recent_blockhashes_sysvar_decodes() {
        let id = recent_blockhashes_sysvar_id();
        assert_eq!(id.len(), 32);
        assert_ne!(id, [0u8; 32]);
        assert_ne!(id, system_program_id());
        assert_eq!(recent_blockhashes_sysvar_id(), id);
    }

    #[test]
    fn advance_nonce_instruction_layout_is_pinned() {
        let nonce = parsed_nonce();
        let ix = advance_nonce_instruction(&nonce, AUTHORITY).unwrap();
        assert_eq!(ix.program_id, system_program_id());
        // u32 index 4, LE — no other data.
        assert_eq!(ix.data, 4u32.to_le_bytes());
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta {
                    pubkey: NONCE_ADDR,
                    is_signer: false,
                    is_writable: true
                },
                AccountMeta {
                    pubkey: recent_blockhashes_sysvar_id(),
                    is_signer: false,
                    is_writable: false
                },
                AccountMeta {
                    pubkey: AUTHORITY,
                    is_signer: true,
                    is_writable: false
                },
            ]
        );
    }

    #[test]
    fn advance_nonce_rejects_wrong_authority_and_zero_addresses() {
        let nonce = parsed_nonce();
        // Spending someone else's nonce: refused at build time.
        assert_eq!(
            advance_nonce_instruction(&nonce, key(9)),
            Err(DurableNonceError::AuthorityMismatch)
        );
        let mut zero_addr = nonce;
        zero_addr.address = [0u8; 32];
        assert_eq!(
            advance_nonce_instruction(&zero_addr, AUTHORITY),
            Err(DurableNonceError::ZeroAddress)
        );
        // A zero authority argument never matches a real account
        // authority — the mismatch fires before the zero check.
        assert_eq!(
            advance_nonce_instruction(&nonce, [0u8; 32]),
            Err(DurableNonceError::AuthorityMismatch)
        );
    }

    #[test]
    fn legacy_message_binds_nonce_first_and_in_blockhash_slot() {
        let nonce = parsed_nonce();
        let program_id = key(7);
        let action_ix = ProgramInstruction {
            program_id,
            accounts: vec![AccountMeta {
                pubkey: AUTHORITY,
                is_signer: true,
                is_writable: true,
            }],
            data: vec![1, 2, 3],
        };
        let msg = compile_message_with_nonce(&action_ix, &nonce).unwrap();
        // The nonce value — not a recent blockhash — is in the
        // blockhash slot.
        assert_eq!(msg.recent_blockhash, NONCE_VALUE);
        assert_eq!(msg.recent_blockhash, nonce.blockhash);
        // Two instructions, advance first.
        assert_eq!(msg.instructions.len(), 2);
        let advance = &msg.instructions[0];
        assert_eq!(
            msg.account_keys[advance.program_id_index as usize],
            system_program_id()
        );
        assert_eq!(advance.data, 4u32.to_le_bytes());
        // The action rides second, untouched.
        let action = &msg.instructions[1];
        assert_eq!(
            msg.account_keys[action.program_id_index as usize],
            program_id
        );
        assert_eq!(action.data, vec![1, 2, 3]);
        // The nonce authority is a signer of the whole transaction.
        assert!(msg.header.num_required_signatures >= 1);
        let signer_keys =
            &msg.account_keys[..msg.header.num_required_signatures as usize];
        assert!(signer_keys.contains(&AUTHORITY));
        // Wire round-trip: decode is the untrusted-input path.
        let bytes = encode_message(&msg);
        assert_eq!(decode_message(&bytes).unwrap(), msg);
    }

    #[test]
    fn session_freshness_detects_moved_nonce_and_authority() {
        let nonce = parsed_nonce();
        let session = DurableNonceSession::new(nonce);
        assert_eq!(session.expected_blockhash(), NONCE_VALUE);
        // Unchanged account: fresh.
        session.check_fresh(&nonce_fixture(NONCE_VALUE)).unwrap();
        // The nonce advanced (someone else spent it): refuse.
        let advanced = nonce_fixture(key(0xDD));
        assert_eq!(
            session.check_fresh(&advanced),
            Err(DurableNonceError::NonceChanged)
        );
        // The authority was reassigned: refuse.
        let mut reassigned = nonce_fixture(NONCE_VALUE);
        reassigned[8..40].copy_from_slice(&key(0xEE));
        assert_eq!(
            session.check_fresh(&reassigned),
            Err(DurableNonceError::AuthorityMismatch)
        );
        // Garbage account data: the parse fails first.
        assert_eq!(
            session.check_fresh(&[]),
            Err(DurableNonceError::TruncatedAccount)
        );
    }

    fn fund_action_with_alt() -> (BundledAction, Vec<[u8; 32]>) {
        // One signer plus two ALT-eligible non-signers, with the
        // matching table snapshot — the v0 path needs at least one
        // resolved lookup.
        let table = vec![key(0xE1), key(0xE2)];
        let action = BundledAction {
            escrow_id: key(1),
            kind: BatchActionKind::Fund,
            instruction: "fund",
            discriminator: crate::discriminator::instruction_discriminator("fund"),
            caller_role: "initializer",
            taker: None,
            expires_at: 0,
            amount: 1_000_000,
            payout: 0,
            fee: 0,
            payout_legs: None,
            accounts: vec![
                BundledAccount {
                    pubkey: AUTHORITY,
                    role: "initializer",
                    signer: true,
                    writable: true,
                    alt_index: None,
                },
                BundledAccount {
                    pubkey: key(0xE1),
                    role: "vault",
                    signer: false,
                    writable: true,
                    alt_index: Some(0),
                },
                BundledAccount {
                    pubkey: key(0xE2),
                    role: "mint",
                    signer: false,
                    writable: false,
                    alt_index: Some(1),
                },
            ],
            reason: "test",
        };
        (action, table)
    }

    #[test]
    fn v0_message_with_nonce_prefixes_advance_and_resolves_alt() {
        let nonce = parsed_nonce();
        let (action, table) = fund_action_with_alt();
        let program_id = key(7);
        let msg = compile_action_message_v0_with_nonce(
            program_id,
            &action,
            &nonce,
            key(0x77),
            &table,
        )
        .unwrap();
        // v0 version marker + the nonce in the blockhash slot.
        assert_eq!(msg.recent_blockhash, NONCE_VALUE);
        assert_eq!(encode_v0_message(&msg)[0], 0x80);
        // Two instructions: advance first, the action second.
        assert_eq!(msg.instructions.len(), 2);
        let advance = &msg.instructions[0];
        assert_eq!(
            msg.static_account_keys[advance.program_id_index as usize],
            system_program_id()
        );
        assert_eq!(advance.data, 4u32.to_le_bytes());
        // The action's accounts still resolve through the table.
        assert_eq!(msg.address_table_lookups.len(), 1);
        let lookup = &msg.address_table_lookups[0];
        assert_eq!(lookup.writable_indexes, vec![0]);
        assert_eq!(lookup.readonly_indexes, vec![1]);
        // The nonce authority is a static signer (signers never
        // resolve through a table).
        assert!(msg.static_account_keys.contains(&AUTHORITY));
        // Wire round-trip.
        let bytes = encode_v0_message(&msg);
        assert_eq!(decode_v0_message(&bytes).unwrap(), msg);
        // The base64 convenience agrees byte for byte.
        let b64 = signable_action_message_v0_with_nonce_base64(
            program_id,
            &action,
            &nonce,
            key(0x77),
            &table,
        )
        .unwrap();
        assert_eq!(decode_base64(&b64).unwrap(), bytes);
    }

    #[test]
    fn legacy_signable_base64_carries_nonce_blockhash() {
        let nonce = parsed_nonce();
        let (action, _) = fund_action_with_alt();
        let program_id = key(7);
        let b64 =
            signable_action_message_with_nonce_base64(program_id, &action, &nonce)
                .unwrap();
        let bytes = decode_base64(&b64).unwrap();
        let msg = decode_message(&bytes).unwrap();
        assert_eq!(msg.recent_blockhash, NONCE_VALUE);
        assert_eq!(msg.instructions.len(), 2);
        assert_eq!(msg.instructions[0].data, 4u32.to_le_bytes());
    }

    #[test]
    fn nonce_session_survives_escrow_free_round_trip() {
        // The session is pure data — it copies, compares, and carries
        // no escrow state. Sanity: an Escrow builds fine alongside.
        let mut e = Escrow::initialize(key(1), key(2), 1_000_000, u64::MAX).unwrap();
        e.fund(key(1), 1_700_000_000).unwrap();
        let session = DurableNonceSession::new(parsed_nonce());
        assert_eq!(session, DurableNonceSession::new(parsed_nonce()));
        assert_ne!(session.nonce.blockhash, [0u8; 32]);
    }
}
