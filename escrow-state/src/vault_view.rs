//! AV-151: zero-copy hot-field view over raw vault account bytes.
//!
//! A `Vault` account spans [`VAULT_SPACE`](crate::VAULT_SPACE) bytes
//! (6,262 — just over 6 KiB). The full
//! [`decode_vault_account`](crate::decode_vault_account)
//! structural decode walks every field, which costs memory and — on-chain,
//! via the program — compute units on paths that only need a handful of
//! hot fields: the keeper's expiry sweeps, the indexer's state filters,
//! the CU estimator's per-vault pre-checks.
//!
//! [`VaultView`] is the cheap alternative: a read-only byte-slice view
//! that reads the hot fields — `initializer`, `taker`, `amount` (the
//! locked principal), `released`, `expires_at`, and the `state`
//! discriminant — at fixed [`VAULT_FIELDS`](crate::VAULT_FIELDS) offsets
//! with zero allocation. Reads never panic: short or truncated inputs
//! surface as [`VaultViewError`], never a trap.
//!
//! Offsets are pinned by test against [`VAULT_FIELDS`](crate::VAULT_FIELDS)
//! itself: appending a new field to the table (the crate's convention)
//! cannot move an earlier field, so any drift between the pinned
//! constants and the table-derived offsets fails the test suite.
//!
//! The view is deliberately account-discriminator agnostic: it reads *a*
//! [`VAULT_FIELDS`](crate::VAULT_FIELDS) payload, not necessarily a
//! `Vault` account. Callers that need the 8-byte account-type check
//! should use [`decode_vault_account`](crate::decode_vault_account)
//! instead. Overlong input is accepted — trailing bytes are simply never
//! read (unlike `decode_vault_account`, which rejects them).

use super::{
    discriminator::state_from_discriminant, EscrowState, ANCHOR_DISCRIMINATOR_LEN, PUBKEY_LEN,
    VAULT_SPACE,
};

/// Byte offset of the `initializer` pubkey, relative to the start of the
/// account data (i.e. past the 8-byte Anchor discriminator).
pub const INITIALIZER_OFFSET: usize = ANCHOR_DISCRIMINATOR_LEN; // 8
/// Byte offset of the `taker` pubkey.
pub const TAKER_OFFSET: usize = INITIALIZER_OFFSET + PUBKEY_LEN; // 40
/// Byte offset of the `amount` u64 (the locked principal).
pub const AMOUNT_OFFSET: usize = TAKER_OFFSET + PUBKEY_LEN; // 72
/// Byte offset of the `released` u64 (cumulative released amount, AV-11).
pub const RELEASED_OFFSET: usize = AMOUNT_OFFSET + 8; // 80
/// Byte offset of the `expires_at` u64 (unix timestamp).
pub const EXPIRES_AT_OFFSET: usize = RELEASED_OFFSET + 8; // 88
/// Byte offset of the `state` discriminant byte (`EscrowState` Borsh
/// discriminant).
pub const STATE_OFFSET: usize = EXPIRES_AT_OFFSET + 8; // 96
/// One past the last hot-field byte: the view only ever touches
/// `[0, HOT_FIELDS_END)`.
pub const HOT_FIELDS_END: usize = STATE_OFFSET + 1; // 97

/// Errors from [`VaultView`] reads. Every failure mode is a value — the
/// view never panics, mirroring the panic-free guarantee of
/// [`decode_vault_account`](crate::decode_vault_account).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultViewError {
    /// Fewer than [`VAULT_SPACE`](crate::VAULT_SPACE) bytes were handed
    /// to [`VaultView::new`] (possibly an uninitialized or foreign
    /// account).
    TooShort { expected: usize, got: usize },
    /// A fixed-offset read would run past the end of the buffer. In
    /// practice unreachable through [`VaultView::new`] (it enforces the
    /// lower bound up front); kept so every byte access stays
    /// bounds-checked by construction.
    Truncated { offset: usize, len: usize },
    /// The `state` byte is not a known [`EscrowState`] discriminant.
    InvalidStateDiscriminant(u8),
}

impl core::fmt::Display for VaultViewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            VaultViewError::TooShort { expected, got } => {
                write!(f, "vault bytes too short: expected at least {expected}, got {got}")
            }
            VaultViewError::Truncated { offset, len } => {
                write!(f, "read of {len} bytes at offset {offset} runs past the buffer end")
            }
            VaultViewError::InvalidStateDiscriminant(d) => {
                write!(f, "unknown EscrowState discriminant: {d}")
            }
        }
    }
}

impl std::error::Error for VaultViewError {}

/// Read-only zero-copy view over a vault account's hot fields.
///
/// Construct with [`VaultView::new`] (bounds-checked up front), then read
/// fields directly from the byte offsets — no allocation, no full Borsh
/// walk. Byte slices borrow the input; integers are decoded little-endian
/// per the Borsh layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultView<'a> {
    bytes: &'a [u8],
}

impl<'a> VaultView<'a> {
    /// Borrow `bytes` as a hot-field view. Requires at least
    /// [`VAULT_SPACE`](crate::VAULT_SPACE) bytes; overlong input is
    /// accepted and the tail is ignored.
    pub fn new(bytes: &'a [u8]) -> Result<Self, VaultViewError> {
        if bytes.len() < VAULT_SPACE {
            return Err(VaultViewError::TooShort {
                expected: VAULT_SPACE,
                got: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }

    /// Raw underlying bytes (the full account data handed to [`new`]).
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    fn slice_at(&self, offset: usize, len: usize) -> Result<&'a [u8], VaultViewError> {
        self.bytes
            .get(offset..offset + len)
            .ok_or(VaultViewError::Truncated { offset, len })
    }

    fn u64_at(&self, offset: usize) -> Result<u64, VaultViewError> {
        let s = self.slice_at(offset, 8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(s);
        Ok(u64::from_le_bytes(buf))
    }

    /// The `initializer` pubkey, as a borrowed 32-byte slice.
    pub fn initializer(&self) -> Result<&'a [u8], VaultViewError> {
        self.slice_at(INITIALIZER_OFFSET, PUBKEY_LEN)
    }

    /// The `taker` pubkey, as a borrowed 32-byte slice.
    pub fn taker(&self) -> Result<&'a [u8], VaultViewError> {
        self.slice_at(TAKER_OFFSET, PUBKEY_LEN)
    }

    /// The `amount` u64 — the locked principal.
    pub fn amount(&self) -> Result<u64, VaultViewError> {
        self.u64_at(AMOUNT_OFFSET)
    }

    /// The `released` u64 — cumulative amount released so far (AV-11).
    pub fn released(&self) -> Result<u64, VaultViewError> {
        self.u64_at(RELEASED_OFFSET)
    }

    /// The `expires_at` u64 — unix timestamp of the expiry.
    pub fn expires_at(&self) -> Result<u64, VaultViewError> {
        self.u64_at(EXPIRES_AT_OFFSET)
    }

    /// The raw `state` discriminant byte, before [`EscrowState`] mapping.
    pub fn state_discriminant(&self) -> Result<u8, VaultViewError> {
        // `slice_at` guarantees a 1-byte slice, so `[0]` cannot panic.
        Ok(self.slice_at(STATE_OFFSET, 1)?[0])
    }

    /// The typed [`EscrowState`], mapped from the `state` discriminant
    /// byte via the same table as
    /// [`decode_vault_account`](crate::decode_vault_account).
    pub fn state(&self) -> Result<EscrowState, VaultViewError> {
        let d = self.state_discriminant()?;
        state_from_discriminant(d).map_err(|_| VaultViewError::InvalidStateDiscriminant(d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account_space_tests::encode_escrow, decode_vault_account, vault_account_discriminator,
        Escrow, ESCROW_BODY_LEN, VAULT_FIELDS,
    };

    // AV-03/AV-08 convention: xorshift64*, deterministic, zero
    // dependencies, fixed seed.
    struct FuzzRng(u64);

    impl FuzzRng {
        fn new(seed: u64) -> Self {
            // Never zero: xorshift with a zero state never advances.
            Self(seed | 1)
        }

        fn next(&mut self) -> u64 {
            // xorshift64*
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn next_bytes(&mut self, buf: &mut [u8]) {
            let mut i = 0;
            while i < buf.len() {
                let w = self.next().to_le_bytes();
                let n = (buf.len() - i).min(8);
                buf[i..i + n].copy_from_slice(&w[..n]);
                i += n;
            }
        }

        fn below(&mut self, n: u64) -> u64 {
            debug_assert!(n > 0);
            self.next() % n
        }
    }

    fn base_account_bytes() -> Vec<u8> {
        let e = Escrow::initialize([0xAA; 32], [0xBB; 32], 3_000, 1_800_000_000).unwrap();
        let mut out = vault_account_discriminator().to_vec();
        out.extend_from_slice(&encode_escrow(&e));
        out
    }

    #[test]
    fn hot_field_offsets_agree_with_vault_fields() {
        // Derive each hot field's offset by accumulating VAULT_FIELDS
        // lens past the 8-byte discriminator; any layout drift between
        // the table and the pinned constants fails here.
        fn derived_offset(name: &str) -> usize {
            let mut off = ANCHOR_DISCRIMINATOR_LEN;
            for (fname, _ty, len) in VAULT_FIELDS.iter() {
                if *fname == name {
                    return off;
                }
                off += len;
            }
            panic!("{name} not found in VAULT_FIELDS");
        }
        assert_eq!(INITIALIZER_OFFSET, derived_offset("initializer"));
        assert_eq!(TAKER_OFFSET, derived_offset("taker"));
        assert_eq!(AMOUNT_OFFSET, derived_offset("amount"));
        assert_eq!(RELEASED_OFFSET, derived_offset("released"));
        assert_eq!(EXPIRES_AT_OFFSET, derived_offset("expires_at"));
        assert_eq!(STATE_OFFSET, derived_offset("state"));
        // Absolute tripwire values, so a field reorder fails loudly too.
        assert_eq!(
            (
                INITIALIZER_OFFSET,
                TAKER_OFFSET,
                AMOUNT_OFFSET,
                RELEASED_OFFSET,
                EXPIRES_AT_OFFSET,
                STATE_OFFSET
            ),
            (8, 40, 72, 80, 88, 96)
        );
        assert_eq!(HOT_FIELDS_END, 97);
        // The account is exactly discriminator + the VAULT_FIELDS body.
        assert_eq!(VAULT_SPACE, ANCHOR_DISCRIMINATOR_LEN + ESCROW_BODY_LEN);
    }

    #[test]
    fn view_rejects_short_input_without_panic() {
        assert_eq!(
            VaultView::new(&[]),
            Err(VaultViewError::TooShort {
                expected: VAULT_SPACE,
                got: 0
            })
        );
        let one_short = vec![0u8; VAULT_SPACE - 1];
        assert_eq!(
            VaultView::new(&one_short),
            Err(VaultViewError::TooShort {
                expected: VAULT_SPACE,
                got: VAULT_SPACE - 1
            })
        );
        // The error is human-readable.
        let msg = format!("{}", VaultViewError::TooShort { expected: VAULT_SPACE, got: 3 });
        assert!(msg.contains('3'), "unexpected message: {msg}");
        let msg = format!("{}", VaultViewError::InvalidStateDiscriminant(200));
        assert!(msg.contains("200"), "unexpected message: {msg}");
    }

    #[test]
    fn view_accepts_overlong_input_and_ignores_tail() {
        let mut bytes = base_account_bytes();
        bytes.extend_from_slice(&[0x5A; 64]);
        let view = VaultView::new(&bytes).unwrap();
        assert_eq!(view.amount().unwrap(), 3_000);
        assert_eq!(view.as_bytes().len(), VAULT_SPACE + 64);
    }

    #[test]
    fn state_mapping_matches_full_decode_for_every_discriminant() {
        // Sweep the whole u8 domain: view and full decode must agree on
        // Ok vs Err and on the typed state, so the view's discriminant
        // table can never drift from decode_vault_account's.
        let base = base_account_bytes();
        for d in 0u8..=u8::MAX {
            let mut bytes = base.clone();
            bytes[STATE_OFFSET] = d;
            let view = VaultView::new(&bytes).unwrap();
            match decode_vault_account(&bytes) {
                Ok(escrow) => {
                    assert_eq!(view.state_discriminant().unwrap(), d, "discriminant {d}");
                    assert_eq!(view.state().unwrap(), escrow.state(), "state {d}");
                }
                Err(_) => {
                    assert!(d > 10, "decode rejected valid discriminant {d}");
                    assert!(
                        matches!(
                            view.state(),
                            Err(VaultViewError::InvalidStateDiscriminant(x)) if x == d
                        ),
                        "view must reject discriminant {d} like the decoder"
                    );
                }
            }
        }
    }

    #[test]
    fn view_agrees_with_full_decode_on_randomized_hot_fields() {
        // Equivalence fuzz: randomize every hot field (the rest of the
        // 6,262-byte account stays byte-identical), then read both paths —
        // the full structural decode and the zero-copy view must agree.
        let mut rng = FuzzRng::new(0x9E3779B97F4A7C15);
        for i in 0..512 {
            let mut bytes = base_account_bytes();
            rng.next_bytes(&mut bytes[INITIALIZER_OFFSET..TAKER_OFFSET]);
            rng.next_bytes(&mut bytes[TAKER_OFFSET..AMOUNT_OFFSET]);
            bytes[AMOUNT_OFFSET..RELEASED_OFFSET].copy_from_slice(&rng.next().to_le_bytes());
            bytes[RELEASED_OFFSET..EXPIRES_AT_OFFSET].copy_from_slice(&rng.next().to_le_bytes());
            bytes[EXPIRES_AT_OFFSET..STATE_OFFSET].copy_from_slice(&rng.next().to_le_bytes());
            bytes[STATE_OFFSET] = rng.below(11) as u8;
            let escrow = decode_vault_account(&bytes)
                .unwrap_or_else(|err| panic!("iter {i}: structurally valid bytes must decode: {err:?}"));
            let view = VaultView::new(&bytes).unwrap();
            assert_eq!(view.initializer().unwrap(), &escrow.initializer()[..], "iter {i} initializer");
            assert_eq!(view.taker().unwrap(), &escrow.taker()[..], "iter {i} taker");
            assert_eq!(view.amount().unwrap(), escrow.amount(), "iter {i} amount");
            assert_eq!(view.released().unwrap(), escrow.released_amount(), "iter {i} released");
            assert_eq!(view.expires_at().unwrap(), escrow.expires_at(), "iter {i} expires_at");
            assert_eq!(
                view.state_discriminant().unwrap(),
                bytes[STATE_OFFSET],
                "iter {i} state discriminant"
            );
            assert_eq!(view.state().unwrap(), escrow.state(), "iter {i} state");
        }
    }
}
