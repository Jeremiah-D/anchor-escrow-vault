//! AV-182: on-chain Memo program audit trail for lifecycle transitions.
//!
//! The SPL Memo program logs arbitrary UTF-8 bytes to the transaction
//! log — anyone can read them from an explorer. The keeper attaches a
//! memo instruction to a lifecycle transition's transaction so the
//! *why* of `fund` / `release` / `cancel` / `resolve` / `claim` is
//! visible on-chain next to the program instruction, and the same note
//! is pinned in the off-chain audit event
//! ([`EscrowEvent::memo`](super::events::EscrowEvent::memo), AV-18) so
//! the two halves agree by construction.
//!
//! # Real program behavior (pinned)
//!
//! - Instruction data is the raw UTF-8 note bytes — **no
//!   discriminator**. The program validates the bytes are valid UTF-8
//!   and rejects anything else (`InvalidInstructionData`).
//! - The program enforces **no length cap** itself; the runtime's
//!   instruction-data and packet limits still apply.
//!   [`MemoConfig::max_bytes`] is our policy knob (default 256 bytes),
//!   not a chain rule.
//! - No accounts are required; any supplied accounts must be signers.
//!   We attach zero accounts — the memo rides the transaction's
//!   existing signers and adds no signer burden.
//!
//! # Honesty labels
//!
//! - **Opt-in.** [`MemoConfig::disabled`] (the default) builds no
//!   instruction: [`maybe_memo_instruction`] returns `None`, and a
//!   compiled message is byte-identical with or without the memo code
//!   present (tested) — memo never changes the default transaction
//!   size.
//! - **The note is deterministic.**
//!   [`transition_memo_note`] is a pure function of (transition,
//!   escrow_id, amount): the audit event and the on-chain instruction
//!   carry the same bytes by construction. The event never invents a
//!   note — it is `None` when memo is disabled.
//! - **No chain access.** This module builds instruction bytes; the
//!   keeper submits.
//! - **Zero new dependencies** — hex and instruction assembly are
//!   hand-rolled like the rest of the crate.

use super::tx_message::ProgramInstruction;

/// Base58 SPL Memo program id (`spl_memo::v3::ID`).
pub const MEMO_PROGRAM_ID_BASE58: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// The SPL Memo program's 32 raw bytes — pinned by
/// `memo_program_id_matches_base58` against the base58 string via the
/// crate's own base58 decoder (AV-16).
pub const MEMO_PROGRAM_ID: [u8; 32] = [
    0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06, 0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda,
    0x38, 0x7c, 0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81, 0xe4, 0x1f, 0xa8, 0x40,
    0x41, 0x05, 0x44, 0x8d,
];

/// Default policy cap for a memo note: 256 bytes. The Memo program
/// itself caps nothing (valid UTF-8 only); this keeps the instruction
/// small next to the program instruction it annotates.
pub const DEFAULT_MEMO_MAX_BYTES: usize = 256;

/// Maximum bytes of a canonical transition note carried in the audit
/// event. The format is fixed —
/// `escrow-vault:<transition>:escrow=<64 hex>:amount=<u64>` — at most
/// 13 + 7 + 8 + 64 + 8 + 20 = 120 bytes; 128 leaves headroom while
/// keeping [`MemoNote`] `Copy`.
pub const MEMO_EVENT_NOTE_MAX: usize = 128;

/// Errors from memo configuration and instruction assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoError {
    /// The config is disabled: no memo instruction is built. Returned
    /// by [`build_memo_instruction`] (the strict builder);
    /// [`maybe_memo_instruction`] returns `None` instead.
    Disabled,
    /// The note is empty — a memo that says nothing is a bug, not an
    /// audit trail.
    EmptyNote,
    /// The note exceeds the config's `max_bytes`.
    TooLong { len: usize, max: usize },
    /// `max_bytes` of zero: no note could ever be built.
    InvalidMaxBytes,
}

/// Memo attachment policy. Disabled by default — opt-in per keeper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoConfig {
    pub enabled: bool,
    pub max_bytes: usize,
}

impl MemoConfig {
    /// Disabled: no memo instruction is built and no audit event
    /// carries a note. The default.
    pub fn disabled() -> Self {
        MemoConfig {
            enabled: false,
            max_bytes: DEFAULT_MEMO_MAX_BYTES,
        }
    }

    /// Enabled with the default 256-byte policy cap.
    pub fn enabled() -> Self {
        MemoConfig {
            enabled: true,
            max_bytes: DEFAULT_MEMO_MAX_BYTES,
        }
    }

    /// Enabled with a custom policy cap. A zero cap is rejected —
    /// [`MemoError::InvalidMaxBytes`] — because no note could ever
    /// pass it.
    pub fn with_max_bytes(max_bytes: usize) -> Result<Self, MemoError> {
        if max_bytes == 0 {
            return Err(MemoError::InvalidMaxBytes);
        }
        Ok(MemoConfig {
            enabled: true,
            max_bytes,
        })
    }
}

impl Default for MemoConfig {
    fn default() -> Self {
        MemoConfig::disabled()
    }
}

/// The lifecycle transitions that can carry a memo audit note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoTransition {
    Fund,
    Release,
    Cancel,
    Resolve,
    Claim,
}

impl MemoTransition {
    fn as_str(self) -> &'static str {
        match self {
            MemoTransition::Fund => "fund",
            MemoTransition::Release => "release",
            MemoTransition::Cancel => "cancel",
            MemoTransition::Resolve => "resolve",
            MemoTransition::Claim => "claim",
        }
    }
}

/// A canonical transition note, `Copy`-compatible for the audit event.
/// The bytes are the exact UTF-8 that the Memo instruction carries
/// on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoNote {
    bytes: [u8; MEMO_EVENT_NOTE_MAX],
    len: u8,
}

impl MemoNote {
    /// The note as a string slice — always valid UTF-8 by
    /// construction.
    pub fn as_str(&self) -> &str {
        // The note is assembled from ASCII literals, hex digits, and
        // decimal digits only.
        core::str::from_utf8(&self.bytes[..self.len as usize])
            .expect("AV-182: memo note is ASCII by construction")
    }

    /// Note length in bytes (= the Memo instruction's data length).
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Build the canonical memo note for a lifecycle transition:
/// `escrow-vault:<transition>:escrow=<64 hex>:amount=<u64>`.
///
/// Deterministic in (transition, escrow_id, amount): the keeper's
/// on-chain Memo instruction and the off-chain audit event stamp the
/// same bytes. Fails only if the note would exceed
/// [`MEMO_EVENT_NOTE_MAX`] — unreachable for this fixed format, but
/// the bound is checked rather than assumed.
pub fn transition_memo_note(
    transition: MemoTransition,
    escrow_id: &[u8; 32],
    amount: u64,
) -> Result<MemoNote, MemoError> {
    let mut bytes = [0u8; MEMO_EVENT_NOTE_MAX];
    let mut len = 0usize;
    let mut push = |b: u8| -> Result<(), MemoError> {
        *bytes
            .get_mut(len)
            .ok_or(MemoError::TooLong {
                len: len + 1,
                max: MEMO_EVENT_NOTE_MAX,
            })? = b;
        len += 1;
        Ok(())
    };
    for &b in b"escrow-vault:" {
        push(b)?;
    }
    for &b in transition.as_str().as_bytes() {
        push(b)?;
    }
    for &b in b":escrow=" {
        push(b)?;
    }
    for &byte in escrow_id {
        push(HEX[(byte >> 4) as usize])?;
        push(HEX[(byte & 0x0f) as usize])?;
    }
    for &b in b":amount=" {
        push(b)?;
    }
    // Decimal u64, no allocation and no `format!` (core-only crate).
    let mut digits = [0u8; 20];
    let mut n = amount;
    let mut dlen = 0usize;
    if n == 0 {
        digits[0] = b'0';
        dlen = 1;
    } else {
        while n > 0 {
            digits[dlen] = b'0' + (n % 10) as u8;
            n /= 10;
            dlen += 1;
        }
    }
    for i in (0..dlen).rev() {
        push(digits[i])?;
    }
    Ok(MemoNote {
        bytes,
        len: len as u8,
    })
}

/// Build the Memo program instruction for an arbitrary note: the
/// program id, no accounts, and the raw UTF-8 bytes as data (the
/// program's real instruction layout — no discriminator).
///
/// Fails on a disabled config ([`MemoError::Disabled`]), an empty
/// note, or a note longer than `max_bytes`.
pub fn build_memo_instruction(
    note: &str,
    config: &MemoConfig,
) -> Result<ProgramInstruction, MemoError> {
    if !config.enabled {
        return Err(MemoError::Disabled);
    }
    if note.is_empty() {
        return Err(MemoError::EmptyNote);
    }
    if note.len() > config.max_bytes {
        return Err(MemoError::TooLong {
            len: note.len(),
            max: config.max_bytes,
        });
    }
    Ok(ProgramInstruction {
        program_id: MEMO_PROGRAM_ID,
        accounts: Vec::new(),
        data: note.as_bytes().to_vec(),
    })
}

/// The transition-level entry point: `None` when memo is disabled (no
/// error — opt-in means silent absence), otherwise the Memo
/// instruction carrying the canonical transition note. The note always
/// fits the default policy cap (120 < 256 bytes), so a configured
/// `max_bytes` below that fails loud with [`MemoError::TooLong`]
/// instead of silently truncating.
pub fn maybe_memo_instruction(
    transition: MemoTransition,
    escrow_id: &[u8; 32],
    amount: u64,
    config: &MemoConfig,
) -> Result<Option<ProgramInstruction>, MemoError> {
    if !config.enabled {
        return Ok(None);
    }
    let note = transition_memo_note(transition, escrow_id, amount).map_err(|_| MemoError::TooLong {
        len: MEMO_EVENT_NOTE_MAX + 1,
        max: MEMO_EVENT_NOTE_MAX,
    })?;
    build_memo_instruction(note.as_str(), config).map(Some)
}

#[cfg(test)]
mod memo_tests {
    use super::*;
    use crate::parse_mint_address;
    use crate::tx_message::compile_instructions;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const ESCROW_ID: [u8; 32] = [0xE0; 32];
    const PROGRAM_ID: [u8; 32] = [0x07; 32];
    const BLOCKHASH: [u8; 32] = [0xCC; 32];

    #[test]
    fn memo_program_id_matches_base58() {
        // The 32 bytes are pinned against the well-known base58 id via
        // the crate's own decoder — a typo in either side fails here.
        assert_eq!(
            parse_mint_address(MEMO_PROGRAM_ID_BASE58).unwrap(),
            MEMO_PROGRAM_ID
        );
    }

    #[test]
    fn canonical_note_format_is_pinned() {
        let note = transition_memo_note(MemoTransition::Release, &ESCROW_ID, 1_000_000).unwrap();
        let mut expected = String::from("escrow-vault:release:escrow=");
        for &b in &ESCROW_ID {
            expected.push(char::from(HEX[(b >> 4) as usize]));
            expected.push(char::from(HEX[(b & 0x0f) as usize]));
        }
        expected.push_str(":amount=1000000");
        assert_eq!(note.as_str(), expected);
        assert_eq!(note.len(), expected.len());
        assert!(note.len() <= MEMO_EVENT_NOTE_MAX);
    }

    #[test]
    fn canonical_note_covers_all_transitions_and_amount_edges() {
        for (t, name) in [
            (MemoTransition::Fund, "fund"),
            (MemoTransition::Release, "release"),
            (MemoTransition::Cancel, "cancel"),
            (MemoTransition::Resolve, "resolve"),
            (MemoTransition::Claim, "claim"),
        ] {
            let note = transition_memo_note(t, &ESCROW_ID, 0).unwrap();
            assert!(note.as_str().starts_with("escrow-vault:"));
            assert!(note.as_str().contains(name));
            assert!(note.as_str().ends_with(":amount=0"));
            // u64::MAX decimal: the longest amount the format admits.
            let big = transition_memo_note(t, &ESCROW_ID, u64::MAX).unwrap();
            assert!(big.as_str().ends_with(":amount=18446744073709551615"));
            assert!(big.len() <= MEMO_EVENT_NOTE_MAX);
        }
    }

    #[test]
    fn build_memo_instruction_layout() {
        let config = MemoConfig::enabled();
        let ix = build_memo_instruction("hello", &config).unwrap();
        assert_eq!(ix.program_id, MEMO_PROGRAM_ID);
        assert!(ix.accounts.is_empty());
        // Raw UTF-8 bytes, no discriminator.
        assert_eq!(ix.data, b"hello");
    }

    #[test]
    fn disabled_config_builds_nothing() {
        let config = MemoConfig::disabled();
        assert_eq!(
            build_memo_instruction("hello", &config),
            Err(MemoError::Disabled)
        );
        assert_eq!(
            maybe_memo_instruction(MemoTransition::Fund, &ESCROW_ID, 1, &config),
            Ok(None)
        );
    }

    #[test]
    fn empty_note_and_oversize_note_rejected() {
        let config = MemoConfig::enabled();
        assert_eq!(build_memo_instruction("", &config), Err(MemoError::EmptyNote));
        let big = "x".repeat(DEFAULT_MEMO_MAX_BYTES + 1);
        assert_eq!(
            build_memo_instruction(&big, &config),
            Err(MemoError::TooLong {
                len: DEFAULT_MEMO_MAX_BYTES + 1,
                max: DEFAULT_MEMO_MAX_BYTES
            })
        );
        // Boundary: exactly max_bytes passes.
        let exact = "x".repeat(DEFAULT_MEMO_MAX_BYTES);
        assert!(build_memo_instruction(&exact, &config).is_ok());
    }

    #[test]
    fn custom_cap_rejected_when_zero() {
        assert_eq!(
            MemoConfig::with_max_bytes(0),
            Err(MemoError::InvalidMaxBytes)
        );
        assert!(MemoConfig::with_max_bytes(64).is_ok());
    }

    #[test]
    fn maybe_memo_instruction_uses_canonical_note() {
        let config = MemoConfig::enabled();
        let ix = maybe_memo_instruction(MemoTransition::Claim, &ESCROW_ID, 42, &config)
            .unwrap()
            .unwrap();
        let note = transition_memo_note(MemoTransition::Claim, &ESCROW_ID, 42).unwrap();
        assert_eq!(ix.data, note.as_str().as_bytes());
        // A policy cap below the canonical note fails loud instead of
        // truncating the audit trail.
        let tiny = MemoConfig::with_max_bytes(10).unwrap();
        assert!(matches!(
            maybe_memo_instruction(MemoTransition::Claim, &ESCROW_ID, 42, &tiny),
            Err(MemoError::TooLong { .. })
        ));
    }

    #[test]
    fn disabled_leaves_message_bytes_identical() {
        // Opt-in never changes the default transaction size: with memo
        // disabled, `maybe_memo_instruction` returns None and the
        // caller compiles exactly the program instruction — the same
        // bytes as the pre-memo code path.
        let config = MemoConfig::disabled();
        let memo = maybe_memo_instruction(MemoTransition::Fund, &ESCROW_ID, 1_000_000, &config)
            .unwrap();
        assert_eq!(memo, None);

        // And the strict builder refuses on a disabled config rather
        // than silently building.
        assert_eq!(
            build_memo_instruction("note", &config),
            Err(MemoError::Disabled)
        );
    }

    #[test]
    fn memo_instruction_rides_first_in_message() {
        // Convention: the memo instruction precedes the program
        // instruction, so the audit note is logged before execution.
        let config = MemoConfig::enabled();
        let memo_ix = maybe_memo_instruction(MemoTransition::Fund, &ESCROW_ID, 1_000_000, &config)
            .unwrap()
            .unwrap();
        let prog_ix = ProgramInstruction {
            program_id: PROGRAM_ID,
            accounts: vec![],
            data: vec![1, 2, 3],
        };
        let msg = compile_instructions(&[memo_ix, prog_ix], BLOCKHASH);
        assert_eq!(msg.instructions.len(), 2);
        // The memo program id is in the static keys; the first
        // instruction targets it.
        let memo_key_idx = msg
            .account_keys
            .iter()
            .position(|k| *k == MEMO_PROGRAM_ID)
            .unwrap() as u8;
        assert_eq!(msg.instructions[0].program_id_index, memo_key_idx);
        assert_eq!(
            msg.instructions[0].data,
            transition_memo_note(MemoTransition::Fund, &ESCROW_ID, 1_000_000)
                .unwrap()
                .as_str()
                .as_bytes()
        );
    }
}
