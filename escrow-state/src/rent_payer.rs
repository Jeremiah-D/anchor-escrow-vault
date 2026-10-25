//! Rent payer (AV-222).
//!
//! AV-34's `close_vault` retires the vault account and reclaims the
//! rent-exempt deposit — but it always handed that deposit back to
//! the initializer, because the Anchor `close` constraint pays the
//! account's lamports to a single destination and the initializer was
//! the only destination the state machine knew. An escrow whose rent
//! was actually funded by someone else — a sponsor, a marketplace
//! operator, a relayer that paid the account-creation rent on the
//! initializer's behalf — had no way to say so: the sponsor's
//! deposit silently became the initializer's on close.
//!
//! This module adds that destination: an opt-in, `Uninitialized`-only
//! rent payer, bound before funding and persisted as the vault's
//! last tail field. On close, the rent-exempt deposit goes to the
//! rent payer when one is bound, and to the initializer otherwise
//! (backward compatible — every existing vault closes exactly as
//! before). The close authority does not change: only the
//! initializer may call `close_vault` (AV-34), so naming a rent
//! payer never lets a stranger close the vault — it only changes
//! who the close pays.
//!
//! - [`RENT_PAYER_TAIL_LEN`]: the serialized tail — the 1-byte
//!   `Option` discriminant plus the 32-byte payer key, zeroed when
//!   no payer is bound.
//! - [`rent_recipient`]: the close-time recipient — the bound payer,
//!   or the initializer when none is bound. The single function
//!   both [`Escrow::close_vault`] and the batch-close report read,
//!   so a single-vault close and a batch close can never disagree
//!   about who gets the rent.
//!
//! Orthogonal to:
//!
//! - AV-34 (the close itself: this item changes the close's
//!   recipient, it never changes who may close or which states are
//!   closeable);
//! - AV-110 (anyone may *top up* rent: the top-up caller funds the
//!   vault, they do not become the rent payer — the payer is bound
//!   once, at setup, by the initializer);
//! - AV-139 (the unclaimed-rent sweep: when nobody closes within the
//!   grace period, the sweep still pays its caller-specified
//!   treasury, not the rent payer — the sweep is the fallback for a
//!   close that never happened, and it keeps its own destination).
//!
//! Pure logic, zero dependencies: the escrow owns the storage (one
//! `Option` payer, appended to the vault layout after the AV-220
//! partial-funding flag); this module owns only the tail length and
//! the recipient resolution.

/// Serialized length of the rent-payer tail: the 1-byte `Option`
/// discriminant plus the 32-byte payer key.
pub const RENT_PAYER_TAIL_LEN: usize = 1 + 32;

/// The rent-exempt deposit's recipient on close (AV-222): the bound
/// rent payer when one is configured, otherwise the initializer
/// (the AV-34 default). A zero payer can never be bound — the
/// builder refuses it with [`crate::EscrowError::InvalidRentPayer`]
/// — so `Some` here is always a real key, never a placeholder.
pub fn rent_recipient(
    rent_payer: Option<[u8; 32]>,
    initializer: [u8; 32],
) -> [u8; 32] {
    rent_payer.unwrap_or(initializer)
}

#[cfg(test)]
mod rent_payer_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const CAROL: [u8; 32] = [0xDD; 32];

    #[test]
    fn recipient_defaults_to_initializer_without_payer() {
        assert_eq!(rent_recipient(None, ALICE), ALICE);
    }

    #[test]
    fn recipient_uses_bound_payer_when_set() {
        assert_eq!(rent_recipient(Some(CAROL), ALICE), CAROL);
    }

    #[test]
    fn builder_defaults_to_initializer_and_binds_payer() {
        let plain =
            crate::Escrow::initialize(ALICE, [0xBB; 32], 1_000_000, 1_800_000_000)
                .unwrap();
        assert_eq!(plain.rent_payer(), None);
        assert_eq!(plain.rent_recipient(), ALICE);
        let bound = crate::Escrow::initialize(ALICE, [0xBB; 32], 1_000_000, 1_800_000_000)
            .unwrap()
            .with_rent_payer(CAROL)
            .unwrap();
        assert_eq!(bound.rent_payer(), Some(CAROL));
        assert_eq!(bound.rent_recipient(), CAROL);
    }

    #[test]
    fn builder_rejects_zero_payer_and_non_uninitialized() {
        let err = crate::Escrow::initialize(ALICE, [0xBB; 32], 1_000_000, 1_800_000_000)
            .unwrap()
            .with_rent_payer([0u8; 32])
            .unwrap_err();
        assert_eq!(err, crate::EscrowError::InvalidRentPayer);
        assert_eq!(err.code(), 352);
        let mut funded =
            crate::Escrow::initialize(ALICE, [0xBB; 32], 1_000_000, 1_800_000_000)
                .unwrap();
        funded.fund(ALICE, 1_800_000_000 - 3_600).unwrap();
        assert_eq!(
            funded.with_rent_payer(CAROL).unwrap_err(),
            crate::EscrowError::InvalidStateTransition
        );
    }
}
