//! AV-181: on-chain Address Lookup Table (ALT) account parsing.
//!
//! AV-87's v0 message compiler resolves ALT-eligible accounts against a
//! caller-supplied *snapshot* (`&[[u8; 32]]`) of the on-chain table's
//! addresses. This module closes the gap between "raw account data the
//! keeper fetched from RPC" and that snapshot: it deserializes a lookup
//! table account's data bytes per the real on-chain layout, expands a
//! v0 message's `address_table_lookups` back into loaded addresses, and
//! compiles a v0 message straight from account-data bytes.
//!
//! # Real on-chain layout (pinned from `solana-program` 2.0.23
//! `address_lookup_table::state`)
//!
//! - bytes `0..4`: bincode `ProgramState` variant index (`u32` LE):
//!   `0` = `Uninitialized` (rejected —
//!   [`AltTableError::UninitializedAccount`]), `1` =
//!   `LookupTable`.
//! - bytes `4..56`: bincode `LookupTableMeta`: `deactivation_slot: u64`
//!   (`4..12`), `last_extended_slot: u64` (`12..20`),
//!   `last_extended_slot_start_index: u8` (`20`),
//!   `authority: Option<Pubkey>` — 1-byte tag (`21`; `0` = `None`,
//!   `1` = `Some`) + 32 bytes when `Some` (`22..54`),
//!   `_padding: u16` (`54..56`, ignored). 56 bytes total with an
//!   authority, 24 + zero-fill without — the source pins
//!   `LOOKUP_TABLE_META_SIZE = 56` and asserts the bincode size is 56
//!   with an authority / 24 without in `test_lookup_table_meta_size`.
//! - bytes `56..`: raw addresses, 32 bytes each, **no length prefix**
//!   (the source casts the tail with bytemuck — it must be a multiple
//!   of 32, else `InvalidAccountData`).
//!
//! # Honesty labels
//!
//! - **No chain access.** The keeper fetches the account data via RPC;
//!   this module only parses bytes. Freshness of the snapshot is the
//!   caller's job (a stale table fails the v0 build with
//!   [`TxMessageError::AltTableKeyMismatch`] instead of signing
//!   against the wrong table).
//! - **Off-chain activation check is conservative.**
//!   [`LookupTableMeta::is_active`] on-chain needs the `SlotHashes`
//!   sysvar: a table with a finite `deactivation_slot` stays usable
//!   through a cool-down. Off-chain we only report "fully active"
//!   (`deactivation_slot == u64::MAX`); any finite deactivation slot
//!   is "not guaranteed active" — the keeper should only feed active
//!   tables here.
//! - **Empty tables fail loud.** A 56-byte account carries zero
//!   addresses: valid on-chain, useless for lookups —
//!   [`ParsedLookupTable::deserialize`] returns
//!   [`AltTableError::EmptyTable`] rather than a table that can
//!   resolve nothing.
//! - **Zero new dependencies** — the hand-rolled bincode mirror keeps
//!   the crate dependency-free.
//!
//! [`TxMessageError::AltTableKeyMismatch`]: super::TxMessageError::AltTableKeyMismatch

use super::execution_bundle::BundledAction;
use super::tx_message::{
    compile_action_message_v0, TxMessageError, V0TransactionMessage,
};

/// Serialized size of lookup table metadata: `ProgramState` variant
/// (`u32`) + `LookupTableMeta` bincode fields. Pinned against the
/// Solana source (`LOOKUP_TABLE_META_SIZE`).
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

/// Maximum addresses a lookup table can hold. Pinned against the
/// Solana source (`LOOKUP_TABLE_MAX_ADDRESSES`).
pub const LOOKUP_TABLE_MAX_ADDRESSES: usize = 256;

/// Errors from lookup-table account parsing, lookup resolution, and
/// table-backed v0 compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AltTableError {
    /// Account data is shorter than [`LOOKUP_TABLE_META_SIZE`].
    AccountDataTooShort,
    /// `ProgramState` variant `0`: the account was never initialized.
    UninitializedAccount,
    /// `ProgramState` variant index is neither `0` nor `1`.
    UnknownProgramState,
    /// The `authority: Option<Pubkey>` tag byte is neither `0` nor `1`.
    BadAuthorityTag,
    /// The address tail past [`LOOKUP_TABLE_META_SIZE`] is not a
    /// multiple of 32 bytes.
    AddressDataNotMultipleOf32,
    /// The account carries zero addresses: valid on-chain, useless for
    /// lookups — fail loud instead of resolving nothing.
    EmptyTable,
    /// More addresses than [`LOOKUP_TABLE_MAX_ADDRESSES`].
    TooManyAddresses,
    /// A lookup index is beyond the table's address list.
    LookupIndexOutOfBounds,
    /// No parsed table matches a v0 lookup's `address_table_key`.
    UnknownTableKey,
    /// The account data parsed, but v0 compilation failed (stale
    /// snapshot, no ALT-eligible account, ...).
    MessageBuild(TxMessageError),
}

/// The deserialized `LookupTableMeta`: the table's authority and slot
/// bookkeeping, per the real on-chain layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AltTableMeta {
    /// Slot the table was deactivated at; `u64::MAX` while active.
    pub deactivation_slot: u64,
    /// Slot the table was last extended.
    pub last_extended_slot: u64,
    /// Start index of the last extension within `last_extended_slot`.
    pub last_extended_slot_start_index: u8,
    /// Authority that must sign table modifications.
    pub authority: Option<[u8; 32]>,
}

/// A deserialized address lookup table account: meta plus the address
/// list, in on-chain order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLookupTable {
    pub meta: AltTableMeta,
    pub addresses: Vec<[u8; 32]>,
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64_le(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

impl ParsedLookupTable {
    /// Deserialize raw lookup-table account data per the real on-chain
    /// layout (see the module docs). Fails loud on short data, an
    /// uninitialized/unknown program state, a bad authority tag,
    /// misaligned address bytes, an empty table, or an over-full one.
    pub fn deserialize(data: &[u8]) -> Result<Self, AltTableError> {
        if data.len() < LOOKUP_TABLE_META_SIZE {
            return Err(AltTableError::AccountDataTooShort);
        }
        // bincode `ProgramState` variant index (`u32` LE).
        match read_u32_le(&data[0..4]) {
            0 => return Err(AltTableError::UninitializedAccount),
            1 => {}
            _ => return Err(AltTableError::UnknownProgramState),
        }
        // bincode `LookupTableMeta` fields, in declaration order.
        let deactivation_slot = read_u64_le(&data[4..12]);
        let last_extended_slot = read_u64_le(&data[12..20]);
        let last_extended_slot_start_index = data[20];
        let authority = match data[21] {
            0 => None,
            1 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&data[22..54]);
                Some(key)
            }
            _ => return Err(AltTableError::BadAuthorityTag),
        };
        // bytes 54..56 are the `_padding: u16` — ignored, like on-chain.
        let raw = &data[LOOKUP_TABLE_META_SIZE..];
        if raw.len() % 32 != 0 {
            return Err(AltTableError::AddressDataNotMultipleOf32);
        }
        let mut addresses = Vec::with_capacity(raw.len() / 32);
        for chunk in raw.chunks_exact(32) {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(chunk);
            addresses.push(addr);
        }
        if addresses.is_empty() {
            return Err(AltTableError::EmptyTable);
        }
        if addresses.len() > LOOKUP_TABLE_MAX_ADDRESSES {
            return Err(AltTableError::TooManyAddresses);
        }
        Ok(ParsedLookupTable {
            meta: AltTableMeta {
                deactivation_slot,
                last_extended_slot,
                last_extended_slot_start_index,
                authority,
            },
            addresses,
        })
    }

    /// Whether the table is fully active for lookups. Conservative
    /// off-chain mirror: only `deactivation_slot == u64::MAX` counts —
    /// a finite deactivation slot may still be inside the on-chain
    /// cool-down, which needs the `SlotHashes` sysvar to evaluate (see
    /// the module docs).
    pub fn is_active(&self) -> bool {
        self.meta.deactivation_slot == u64::MAX
    }

    /// The table's address list, in on-chain order.
    pub fn addresses(&self) -> &[[u8; 32]] {
        &self.addresses
    }

    /// Resolve one table index to its address (`None` when out of
    /// range).
    pub fn address_at(&self, index: u8) -> Option<[u8; 32]> {
        self.addresses.get(index as usize).copied()
    }

    /// Resolve a list of table indexes to addresses, failing on the
    /// first out-of-range index — the off-chain mirror of the
    /// runtime's `AddressLookupTable::lookup` (without the
    /// slot-hashes-gated active-length rule, which needs chain state).
    pub fn lookup(&self, indexes: &[u8]) -> Result<Vec<[u8; 32]>, AltTableError> {
        indexes
            .iter()
            .map(|&i| self.address_at(i).ok_or(AltTableError::LookupIndexOutOfBounds))
            .collect()
    }
}

/// One resolved loaded address of a v0 message: which table it came
/// from, the address itself, and its writability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadedAddress {
    /// The lookup table's key this address was loaded from.
    pub table_key: [u8; 32],
    pub address: [u8; 32],
    pub writable: bool,
}

/// Expand a v0 message's `address_table_lookups` into loaded addresses
/// against parsed tables. Output order follows the runtime's
/// loaded-address convention: per lookup, writable indexes first, then
/// readonly — the same order
/// [`compile_action_message_v0`](super::tx_message::compile_action_message_v0)
/// assigns instruction indexes in.
pub fn resolve_v0_lookups(
    msg: &V0TransactionMessage,
    tables: &[([u8; 32], &ParsedLookupTable)],
) -> Result<Vec<LoadedAddress>, AltTableError> {
    let mut out = Vec::with_capacity(msg.loaded_account_count());
    for lookup in &msg.address_table_lookups {
        let table = tables
            .iter()
            .find(|(key, _)| *key == lookup.address_table_key)
            .map(|(_, t)| *t)
            .ok_or(AltTableError::UnknownTableKey)?;
        for &i in &lookup.writable_indexes {
            out.push(LoadedAddress {
                table_key: lookup.address_table_key,
                address: table.address_at(i).ok_or(AltTableError::LookupIndexOutOfBounds)?,
                writable: true,
            });
        }
        for &i in &lookup.readonly_indexes {
            out.push(LoadedAddress {
                table_key: lookup.address_table_key,
                address: table.address_at(i).ok_or(AltTableError::LookupIndexOutOfBounds)?,
                writable: false,
            });
        }
    }
    Ok(out)
}

/// Compile a bundled action into a v0 message, deserializing the
/// lookup table from raw on-chain account data first. One call from
/// "RPC account bytes" to "compilable v0 message": empty/bad tables
/// fail here ([`AltTableError`]), stale snapshots fail in the build
/// ([`TxMessageError`]) — nothing is ever signed against bytes the
/// parser could not vouch for.
pub fn compile_v0_from_account_data(
    program_id: [u8; 32],
    action: &BundledAction,
    recent_blockhash: [u8; 32],
    address_table_key: [u8; 32],
    account_data: &[u8],
) -> Result<V0TransactionMessage, AltTableError> {
    let table = ParsedLookupTable::deserialize(account_data)?;
    compile_action_message_v0(
        program_id,
        action,
        recent_blockhash,
        address_table_key,
        table.addresses(),
    )
    .map_err(AltTableError::MessageBuild)
}

#[cfg(test)]
mod alt_table_tests {
    use super::*;
    use crate::discriminator::instruction_discriminator;
    use crate::execution_bundle::BundledAccount;
    use crate::tx_message::{decode_v0_message, encode_v0_message};
    use crate::{BatchActionKind, Escrow};

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const PROGRAM_ID: [u8; 32] = [0x07; 32];
    const BLOCKHASH: [u8; 32] = [0xCC; 32];
    const TABLE_KEY: [u8; 32] = [0x71; 32];

    /// Serialize a lookup-table account per the real on-chain layout
    /// (the off-chain mirror of `AddressLookupTable::serialize_for_tests`):
    /// bincode `ProgramState::LookupTable(meta)` into the first 56
    /// bytes (zero-filled), then the raw addresses.
    fn serialize_table(
        deactivation_slot: u64,
        last_extended_slot: u64,
        start_index: u8,
        authority: Option<[u8; 32]>,
        addresses: &[[u8; 32]],
    ) -> Vec<u8> {
        let mut data = vec![0u8; LOOKUP_TABLE_META_SIZE];
        // bincode enum variant index: 1 = LookupTable.
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..12].copy_from_slice(&deactivation_slot.to_le_bytes());
        data[12..20].copy_from_slice(&last_extended_slot.to_le_bytes());
        data[20] = start_index;
        match authority {
            None => {
                data[21] = 0;
                // _padding u16 at 54..56 stays zero — like
                // `overwrite_meta_data`'s zero-fill.
            }
            Some(key) => {
                data[21] = 1;
                data[22..54].copy_from_slice(&key);
            }
        }
        for a in addresses {
            data.extend_from_slice(a);
        }
        data
    }

    fn addr(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn meta_layout_matches_solana_vectors() {
        // The Solana source's `test_lookup_table_meta_size` pins:
        // Some(authority) -> 56 bytes, None -> 24 bytes.
        let with_auth = serialize_table(u64::MAX, 0, 0, Some(addr(0xA1)), &[addr(1)]);
        assert_eq!(with_auth.len(), 56 + 32);
        let t = ParsedLookupTable::deserialize(&with_auth).unwrap();
        assert_eq!(t.meta.deactivation_slot, u64::MAX);
        assert_eq!(t.meta.last_extended_slot, 0);
        assert_eq!(t.meta.last_extended_slot_start_index, 0);
        assert_eq!(t.meta.authority, Some(addr(0xA1)));
        assert_eq!(t.addresses(), &[addr(1)]);

        let no_auth = serialize_table(42, 7, 3, None, &[addr(2), addr(3)]);
        // 24-byte bincode meta + 32 zero-fill bytes + 2 addresses.
        assert_eq!(no_auth.len(), 56 + 64);
        let t = ParsedLookupTable::deserialize(&no_auth).unwrap();
        assert_eq!(t.meta.deactivation_slot, 42);
        assert_eq!(t.meta.last_extended_slot, 7);
        assert_eq!(t.meta.last_extended_slot_start_index, 3);
        assert_eq!(t.meta.authority, None);
        assert_eq!(t.addresses(), &[addr(2), addr(3)]);
    }

    #[test]
    fn uninitialized_account_rejected() {
        // bincode variant 0 = ProgramState::Uninitialized.
        let mut data = serialize_table(u64::MAX, 0, 0, None, &[addr(1)]);
        data[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            ParsedLookupTable::deserialize(&data),
            Err(AltTableError::UninitializedAccount)
        );
    }

    #[test]
    fn unknown_program_state_rejected() {
        let mut data = serialize_table(u64::MAX, 0, 0, None, &[addr(1)]);
        data[0..4].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            ParsedLookupTable::deserialize(&data),
            Err(AltTableError::UnknownProgramState)
        );
    }

    #[test]
    fn short_data_rejected() {
        let data = vec![0u8; LOOKUP_TABLE_META_SIZE - 1];
        assert_eq!(
            ParsedLookupTable::deserialize(&data),
            Err(AltTableError::AccountDataTooShort)
        );
        assert_eq!(
            ParsedLookupTable::deserialize(&[]),
            Err(AltTableError::AccountDataTooShort)
        );
    }

    #[test]
    fn misaligned_address_tail_rejected() {
        let data = serialize_table(u64::MAX, 0, 0, None, &[addr(1)]);
        let mut bad = data.clone();
        bad.extend_from_slice(&[0u8; 31]); // 32 + 31: not a multiple of 32
        assert_eq!(
            ParsedLookupTable::deserialize(&bad),
            Err(AltTableError::AddressDataNotMultipleOf32)
        );
    }

    #[test]
    fn empty_table_fails_loud() {
        // A 56-byte account is valid on-chain but carries zero
        // addresses — useless for lookups, so we fail loud.
        let data = serialize_table(u64::MAX, 0, 0, None, &[]);
        assert_eq!(data.len(), LOOKUP_TABLE_META_SIZE);
        assert_eq!(
            ParsedLookupTable::deserialize(&data),
            Err(AltTableError::EmptyTable)
        );
    }

    #[test]
    fn too_many_addresses_rejected() {
        let addrs: Vec<[u8; 32]> = (0..=255u8).map(|b| [b.wrapping_add(1); 32]).collect();
        assert_eq!(addrs.len(), 256);
        let data = serialize_table(u64::MAX, 0, 0, None, &addrs);
        assert!(ParsedLookupTable::deserialize(&data).is_ok());
        let mut over = addrs.clone();
        over.push([0xFF; 32]);
        let data = serialize_table(u64::MAX, 0, 0, None, &over);
        assert_eq!(
            ParsedLookupTable::deserialize(&data),
            Err(AltTableError::TooManyAddresses)
        );
    }

    #[test]
    fn bad_authority_tag_rejected() {
        let mut data = serialize_table(u64::MAX, 0, 0, Some(addr(0xA1)), &[addr(1)]);
        data[21] = 2;
        assert_eq!(
            ParsedLookupTable::deserialize(&data),
            Err(AltTableError::BadAuthorityTag)
        );
    }

    #[test]
    fn is_active_conservative_rule() {
        let active = serialize_table(u64::MAX, 0, 0, None, &[addr(1)]);
        assert!(ParsedLookupTable::deserialize(&active).unwrap().is_active());
        // A finite deactivation slot is "not guaranteed active"
        // off-chain even if the on-chain cool-down has not elapsed.
        let deactivating = serialize_table(1_000_000, 0, 0, None, &[addr(1)]);
        assert!(!ParsedLookupTable::deserialize(&deactivating).unwrap().is_active());
    }

    #[test]
    fn lookup_resolves_indexes() {
        let data = serialize_table(u64::MAX, 0, 0, None, &[addr(1), addr(2), addr(3)]);
        let t = ParsedLookupTable::deserialize(&data).unwrap();
        assert_eq!(t.address_at(0), Some(addr(1)));
        assert_eq!(t.address_at(2), Some(addr(3)));
        assert_eq!(t.address_at(3), None);
        assert_eq!(t.lookup(&[2, 0]), Ok(vec![addr(3), addr(1)]));
        assert_eq!(
            t.lookup(&[0, 9]),
            Err(AltTableError::LookupIndexOutOfBounds)
        );
    }

    /// A bundled `fund` action whose non-signer accounts resolve
    /// through the table: `vault` (writable) and `mint` (readonly)
    /// carry `alt_index`; the initializer signer stays static.
    fn alt_fund_action(vault: [u8; 32], mint: [u8; 32]) -> BundledAction {
        BundledAction {
            escrow_id: [0xE0; 32],
            kind: BatchActionKind::Fund,
            instruction: "fund",
            discriminator: instruction_discriminator("fund"),
            caller_role: "initializer",
            taker: None,
            expires_at: 0,
            amount: 1_000_000,
            payout: 0,
            fee: 0,
            payout_legs: None,
            accounts: vec![
                BundledAccount {
                    pubkey: vault,
                    role: "vault",
                    signer: false,
                    writable: true,
                    alt_index: Some(0),
                },
                BundledAccount {
                    pubkey: ALICE,
                    role: "initializer",
                    signer: true,
                    writable: true,
                    alt_index: None,
                },
                BundledAccount {
                    pubkey: mint,
                    role: "mint",
                    signer: false,
                    writable: false,
                    alt_index: Some(1),
                },
            ],
            reason: "unfunded",
        }
    }

    #[test]
    fn resolve_v0_lookups_expands_loaded_addresses() {
        let vault = addr(0x51);
        let mint = addr(0x11);
        let data = serialize_table(u64::MAX, 100, 0, Some(ALICE), &[vault, mint]);
        let table = ParsedLookupTable::deserialize(&data).unwrap();

        let msg = compile_v0_from_account_data(
            PROGRAM_ID,
            &alt_fund_action(vault, mint),
            BLOCKHASH,
            TABLE_KEY,
            &data,
        )
        .unwrap();
        // Static keys shrank: vault + mint left the static list.
        assert!(!msg.static_account_keys.contains(&vault));
        assert!(!msg.static_account_keys.contains(&mint));
        assert!(msg.static_account_keys.contains(&ALICE));
        assert!(msg.static_account_keys.contains(&PROGRAM_ID));
        assert_eq!(msg.address_table_lookups.len(), 1);
        assert_eq!(msg.address_table_lookups[0].writable_indexes, vec![0]);
        assert_eq!(msg.address_table_lookups[0].readonly_indexes, vec![1]);

        // Wire round-trip, then expand.
        let decoded = decode_v0_message(&encode_v0_message(&msg)).unwrap();
        let loaded = resolve_v0_lookups(&decoded, &[(TABLE_KEY, &table)]).unwrap();
        assert_eq!(
            loaded,
            vec![
                LoadedAddress {
                    table_key: TABLE_KEY,
                    address: vault,
                    writable: true,
                },
                LoadedAddress {
                    table_key: TABLE_KEY,
                    address: mint,
                    writable: false,
                },
            ]
        );
    }

    #[test]
    fn resolve_v0_lookups_unknown_table_fails_loud() {
        let vault = addr(0x21);
        let mint = addr(0x22);
        let data = serialize_table(u64::MAX, 0, 0, None, &[vault, mint]);
        let table = ParsedLookupTable::deserialize(&data).unwrap();
        let msg = compile_v0_from_account_data(
            PROGRAM_ID,
            &alt_fund_action(vault, mint),
            BLOCKHASH,
            TABLE_KEY,
            &data,
        )
        .unwrap();
        // A different table key: the message names a table we did not
        // parse.
        assert_eq!(
            resolve_v0_lookups(&msg, &[([0x99; 32], &table)]),
            Err(AltTableError::UnknownTableKey)
        );
        // A tampered message whose lookup index exceeds the table.
        let mut tampered = msg.clone();
        tampered.address_table_lookups[0].writable_indexes = vec![7];
        assert_eq!(
            resolve_v0_lookups(&tampered, &[(TABLE_KEY, &table)]),
            Err(AltTableError::LookupIndexOutOfBounds)
        );
    }

    #[test]
    fn bad_table_data_fails_compile_loud() {
        // Empty table bytes: parse fails before any message is built.
        let empty = serialize_table(u64::MAX, 0, 0, None, &[]);
        let action = alt_fund_action(addr(0x31), addr(0x32));
        assert_eq!(
            compile_v0_from_account_data(PROGRAM_ID, &action, BLOCKHASH, TABLE_KEY, &empty),
            Err(AltTableError::EmptyTable)
        );
        // Short data: same fail-loud path.
        assert_eq!(
            compile_v0_from_account_data(PROGRAM_ID, &action, BLOCKHASH, TABLE_KEY, &[0u8; 10]),
            Err(AltTableError::AccountDataTooShort)
        );
    }

    #[test]
    fn stale_snapshot_still_fails_in_build() {
        // The table parses, but the stamped alt_index points at a
        // different address: the build refuses (AltTableKeyMismatch
        // via MessageBuild) instead of signing against the wrong table.
        let data = serialize_table(u64::MAX, 0, 0, None, &[addr(0x41), addr(0x42)]);
        let action = alt_fund_action(addr(0x41), addr(0x43)); // mint mismatch
        assert_eq!(
            compile_v0_from_account_data(PROGRAM_ID, &action, BLOCKHASH, TABLE_KEY, &data),
            Err(AltTableError::MessageBuild(TxMessageError::AltTableKeyMismatch))
        );
    }

    #[test]
    fn escrow_sanity_unused() {
        // Keeps the Escrow import honest if refactored: the action
        // builder above mirrors the real `fund` account set.
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, 2_000_000_000).unwrap();
        assert_eq!(e.amount(), 1_000_000);
    }
}
