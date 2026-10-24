//! Authority delegation (AV-104): a bounded operator grant.
//!
//! The [`Escrow`](crate::Escrow) owner (the initializer or the taker)
//! may delegate a *subset* of their transition rights to an operator
//! key — e.g. a hot wallet or a keeper bot that funds, releases, or
//! cancels on their behalf. The grant is a fixed 53-byte region at
//! the end of the vault layout (`Option<Delegation>`: 1-byte
//! discriminant + 32-byte operator key + u32 scope bitmap + u64
//! spend cap + u64 spent, AV-208), so every earlier field offset
//! stays stable.
//!
//! Semantics (enforced in [`Escrow`](crate::Escrow)):
//! - the grantor must be the initializer or the taker themselves;
//! - the operator key must be non-zero;
//! - the scope bitmap must be non-empty and a subset of
//!   [`DELEGATION_SCOPE_MASK`] — unknown bits are rejected, so a
//!   future scope can never smuggle a broader grant into an old
//!   bitmap;
//! - a later grant overwrites the previous one (single slot); either
//!   party may overwrite or revoke;
//! - a party rotation (`rotate_initializer` / `rotate_taker`) clears
//!   the grant — a stale operator must never inherit authority over
//!   the new counterparty;
//! - an operator outside their scope fails with the existing
//!   [`EscrowError::Unauthorized`](crate::EscrowError::Unauthorized):
//!   only *new* failure modes (zero key, bad bitmap, bad state, no
//!   grant to revoke) use the new [`InvalidDelegation`
//!   code](crate::EscrowError::InvalidDelegation).
//!
//! Check order on every delegation-gated path is pause → reentrancy →
//! authority → state, and *inside* the authority check the parties
//! come first: the initializer/taker themselves authorize before the
//! delegation slot is even consulted, so an operator learns nothing
//! the parties don't already know.

/// Scope bit: the operator may fund the escrow
/// ([`Escrow::fund`](crate::Escrow::fund)).
pub const DELEGATION_SCOPE_FUND: u32 = 1 << 0;
/// Scope bit: the operator may run release paths
/// ([`Escrow::release`](crate::Escrow::release)).
pub const DELEGATION_SCOPE_RELEASE: u32 = 1 << 1;
/// Scope bit: the operator may run cancel paths
/// ([`Escrow::cancel`](crate::Escrow::cancel) /
/// [`Escrow::cancel_expired`](crate::Escrow::cancel_expired)).
pub const DELEGATION_SCOPE_CANCEL: u32 = 1 << 2;

/// All scope bits this version understands. Any bit outside this mask
/// is rejected by [`validate_delegation_scopes`].
pub const DELEGATION_SCOPE_MASK: u32 =
    DELEGATION_SCOPE_FUND | DELEGATION_SCOPE_RELEASE | DELEGATION_SCOPE_CANCEL;

/// Serialized length of the delegation region in `VAULT_FIELDS`:
/// `Option<Delegation>` = 1-byte Borsh discriminant + 32-byte operator
/// key + 4-byte scope bitmap + 8-byte spend cap (AV-208) + 8-byte
/// spent counter (AV-208). The region is always reserved (zeroed
/// when `None`) so grants are written in place — same treatment as
/// `arbiter` / `mint` / `refund_to`.
pub const DELEGATION_LEN: usize = 1 + 32 + 4 + 8 + 8;
/// True when `scopes` is a legal grant bitmap: non-empty and a subset
/// of [`DELEGATION_SCOPE_MASK`].
pub fn validate_delegation_scopes(scopes: u32) -> bool {
    scopes != 0 && (scopes & !DELEGATION_SCOPE_MASK) == 0
}

/// The persisted operator grant. `delegate` is the operator's pubkey,
/// `scopes` a bitmap of [`DELEGATION_SCOPE_FUND`] /
/// [`DELEGATION_SCOPE_RELEASE`] / [`DELEGATION_SCOPE_CANCEL`].
/// `spend_cap` (AV-208) bounds the operator's cumulative release
/// volume: `0` means uncapped (the AV-104 grant), a positive cap
/// refuses any operator release that would push `spent` past it.
/// `spent` accumulates only operator-settled gross release amounts —
/// party releases never touch it — and resets whenever the grant is
/// overwritten or revoked, so a cap is always per live grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delegation {
    delegate: [u8; 32],
    scopes: u32,
    spend_cap: u64,
    spent: u64,
}

impl Delegation {
    /// Build an uncapped grant. The bitmap is *not* validated here —
    /// the state machine's grant path validates before persisting,
    /// keeping construction infallible for the decoder.
    pub fn new(delegate: [u8; 32], scopes: u32) -> Self {
        Self {
            delegate,
            scopes,
            spend_cap: 0,
            spent: 0,
        }
    }

    /// Build a spend-capped grant (AV-208). The cap is *not*
    /// validated here — the grant path rejects a zero cap, keeping
    /// construction infallible for the decoder.
    pub fn new_with_spend_cap(delegate: [u8; 32], scopes: u32, spend_cap: u64) -> Self {
        Self {
            delegate,
            scopes,
            spend_cap,
            spent: 0,
        }
    }

    /// Build a grant with its spent counter already populated — the
    /// decoder's constructor; the grant path never builds a grant
    /// with spent already counted (a fresh grant always starts at 0).
    pub fn new_full(delegate: [u8; 32], scopes: u32, spend_cap: u64, spent: u64) -> Self {
        Self {
            delegate,
            scopes,
            spend_cap,
            spent,
        }
    }

    /// The operator's pubkey.
    pub fn delegate(self) -> [u8; 32] {
        self.delegate
    }

    /// The granted scope bitmap.
    pub fn scopes(self) -> u32 {
        self.scopes
    }

    /// The cumulative operator-release cap (`0` = uncapped).
    pub fn spend_cap(self) -> u64 {
        self.spend_cap
    }

    /// Gross release volume this grant's operator has settled.
    pub fn spent(self) -> u64 {
        self.spent
    }

    /// True when the grant covers `scope` (exactly one of the
    /// `DELEGATION_SCOPE_*` bits).
    pub fn covers(self, scope: u32) -> bool {
        debug_assert!(
            scope != 0 && (scope & (scope - 1)) == 0 && (scope & DELEGATION_SCOPE_MASK) != 0,
            "covers: scope must be one valid bit"
        );
        (self.scopes & scope) != 0
    }
}

/// The authority role a caller holds on an escrow (AV-104) — what
/// [`Escrow::effective_role`](crate::Escrow::effective_role) reports.
/// The parties are never downgraded: a party that also holds an
/// operator grant still reports as the party, because the party check
/// precedes the delegation check on every gated path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegatedRole {
    /// The escrow's initializer — full authority.
    Initializer,
    /// The escrow's taker — party authority on taker-gated paths.
    Taker,
    /// A delegated operator, carrying the grant's scope bitmap
    /// ([`DELEGATION_SCOPE_FUND`] / [`DELEGATION_SCOPE_RELEASE`] /
    /// [`DELEGATION_SCOPE_CANCEL`]).
    Operator(u32),
}
