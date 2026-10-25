//! AV-187: NFT escrow — single-edition mint custody.
//!
//! An NFT is not a fungible amount: escrow semantics for one must not
//! inherit amount arithmetic. The fungible [`Escrow`](crate::Escrow) path
//! models divisible balances — partial release, milestones, fee legs,
//! vesting schedules. All of that is *disabled* for NFTs by
//! construction: this module's [`NftEscrow`] transfers the whole piece
//! or nothing (`amount()` is structurally `1`), and there is no
//! partial-release / milestone path to misuse.
//!
//! The escrow lifecycle needs three off-chain observations the Anchor
//! program reads from the mint account before `initialize`:
//!
//! 1. **Is it really an NFT?** [`NftMintDescriptor`] carries the
//!    caller-observed `supply` and `decimals`. [`check_nft_mint`]
//!    asserts `supply == 1 && decimals == 0` — anything else fails
//!    *closed* ([`EscrowError::InvalidNftMint`], code 256). A
//!    semi-fungible edition (`supply > 1`) or a decimal mint routed
//!    through this path is a counterfeit-escrow bug, not a supported
//!    use case.
//! 2. **Which collection?** The optional verified-collection mint.
//!    An opt-in [`CollectionAllowlist`] gate binds the escrow to
//!    approved collections at release; a gated release on a mint whose
//!    collection is unknown or unlisted fails closed
//!    ([`EscrowError::CollectionNotAllowlisted`], code 257).
//! 3. **Who moves it?** The initializer authorizes release/cancel; a
//!    stranger learns nothing (the fixed check order is
//!    authority → state → collection gate).
//!
//! This crate is pure logic: the descriptor is caller-observed mint
//! state (the Anchor program reads the mint account), exactly the
//! [`mint_safety`](crate::mint_safety) AV-184 pattern. Orthogonal to
//! the fungible path: [`NftEscrow`] shares the [`EscrowError`] type and
//! the audit-JSON vocabulary, but none of the amount machinery.

use crate::EscrowError;

/// The amount an NFT escrow moves: exactly one piece. There is no
/// partial-release / milestone / fee-leg path — the type has no amount
/// field to split.
pub const NFT_PIECE_AMOUNT: u64 = 1;

/// Maximum collections in a [`CollectionAllowlist`]. Fixed-size so the
/// gate stays heap-free and `Copy` like the rest of the crate.
pub const MAX_COLLECTION_ALLOWLIST: usize = 8;

/// Caller-observed mint state for an NFT escrow, read from the mint
/// account before `initialize`. `Copy` and heap-free like the rest of
/// the state machine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NftMintDescriptor {
    /// The mint being escrowed (binds the report to the mint).
    pub mint: [u8; 32],
    /// Observed total supply. An NFT has `supply == 1`.
    pub supply: u64,
    /// Observed decimals. An NFT has `decimals == 0`.
    pub decimals: u8,
    /// The verified collection mint, if the caller observed one
    /// (`None` = unverified / no collection on the mint).
    pub collection: Option<[u8; 32]>,
}

/// The outcome of [`check_nft_mint`]: the mint is a single-edition NFT
/// and the collection observation is pinned to the report. Never
/// fails — the denial is [`NftMintReport::require_nft`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NftMintReport {
    mint: [u8; 32],
    collection: Option<[u8; 32]>,
}

impl NftMintReport {
    /// The mint this report covers.
    pub fn mint(&self) -> [u8; 32] {
        self.mint
    }

    /// The caller-observed verified collection (`None` when the mint
    /// carries none / the caller observed none).
    pub fn collection(&self) -> Option<[u8; 32]> {
        self.collection
    }

    /// `true` — a report only exists for a verified NFT (the check is
    /// fail-closed at construction).
    pub fn is_nft(&self) -> bool {
        true
    }

    /// Audit-event JSON for the gate decision (hand-written, names are a
    /// fixed alphabet and the mint is hex):
    /// `{"event":"nft_mint_checked","mint":"<64hex>","decision":"allow",
    /// "supply":<u64>,"decimals":<u8>,"collection":"<64hex>"|null}`.
    pub fn audit_json(&self, supply: u64, decimals: u8) -> String {
        let mut s = String::from("{\"event\":\"nft_mint_checked\",\"mint\":\"");
        s.push_str(&hex64(&self.mint));
        s.push_str("\",\"decision\":\"allow\",\"supply\":");
        s.push_str(&supply.to_string());
        s.push_str(",\"decimals\":");
        s.push_str(&decimals.to_string());
        s.push_str(",\"collection\":");
        match self.collection {
            Some(c) => {
                s.push('"');
                s.push_str(&hex64(&c));
                s.push('"');
            }
            None => s.push_str("null"),
        }
        s.push('}');
        s
    }
}

/// The escrow gate for an NFT mint: `supply == 1 && decimals == 0` or
/// the mint is refused. Fail-closed — the escrow must not be created
/// on a fungible or semi-fungible mint.
pub fn check_nft_mint(desc: &NftMintDescriptor) -> Result<NftMintReport, EscrowError> {
    if desc.supply != 1 || desc.decimals != 0 {
        return Err(EscrowError::InvalidNftMint);
    }
    Ok(NftMintReport {
        mint: desc.mint,
        collection: desc.collection,
    })
}

/// Opt-in collection allowlist: approved verified-collection mints a
/// gated [`NftEscrow`] may release. Fixed-size (`Copy`, no heap) —
/// `add` is idempotent, `remove` swap-removes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CollectionAllowlist {
    mints: [[u8; 32]; MAX_COLLECTION_ALLOWLIST],
    len: u8,
}

impl CollectionAllowlist {
    /// Empty allowlist — matches nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of allowlisted collections.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// `true` when no collections are allowlisted.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Add a collection mint. Idempotent; returns `false` when the
    /// allowlist is full and the mint is not already present.
    pub fn add(&mut self, collection: [u8; 32]) -> bool {
        if self.contains(&collection) {
            return true;
        }
        if (self.len as usize) >= MAX_COLLECTION_ALLOWLIST {
            return false;
        }
        self.mints[self.len as usize] = collection;
        self.len += 1;
        true
    }

    /// Remove a collection mint. `true` when it was present.
    pub fn remove(&mut self, collection: &[u8; 32]) -> bool {
        let mut i = 0;
        while i < self.len as usize {
            if &self.mints[i] == collection {
                let last = self.len as usize - 1;
                self.mints[i] = self.mints[last];
                self.mints[last] = [0u8; 32];
                self.len -= 1;
                return true;
            }
            i += 1;
        }
        false
    }

    /// `true` when the collection mint is allowlisted.
    pub fn contains(&self, collection: &[u8; 32]) -> bool {
        self.mints[..self.len as usize]
            .iter()
            .any(|m| m == collection)
    }
}

/// NFT escrow lifecycle: `Created` → `Released` (whole piece) or
/// `Created` → `Cancelled`. `Copy`, heap-free.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NftEscrowState {
    /// The escrow exists and the piece is locked.
    #[default]
    Created,
    /// The piece moved to the taker (whole piece — `amount == 1`).
    Released,
    /// The piece was returned / the escrow was voided.
    Cancelled,
}

impl NftEscrowState {
    fn name(&self) -> &'static str {
        match self {
            NftEscrowState::Created => "created",
            NftEscrowState::Released => "released",
            NftEscrowState::Cancelled => "cancelled",
        }
    }
}

/// An NFT escrow over one verified single-edition mint.
///
/// Construct with [`NftEscrow::new`]; the mint is already gate-checked
/// there (a non-NFT mint never produces an escrow). `release`
/// transfers the *whole piece* — there is no amount parameter to
/// misuse. An optional [`CollectionAllowlist`] gate (via
/// [`NftEscrow::with_collection_allowlist`]) restricts release to
/// approved collections; ungated escrows skip the collection check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NftEscrow {
    initializer: [u8; 32],
    mint: [u8; 32],
    collection: Option<[u8; 32]>,
    state: NftEscrowState,
    collection_gate: Option<CollectionAllowlist>,
}

impl NftEscrow {
    /// Create the escrow. Fail-closed on a non-NFT mint: `supply != 1`
    /// or `decimals != 0` returns [`EscrowError::InvalidNftMint`] and
    /// no escrow is produced.
    pub fn new(initializer: [u8; 32], desc: &NftMintDescriptor) -> Result<Self, EscrowError> {
        let report = check_nft_mint(desc)?;
        Ok(NftEscrow {
            initializer,
            mint: report.mint(),
            collection: report.collection(),
            state: NftEscrowState::Created,
            collection_gate: None,
        })
    }

    /// Opt into the collection gate: a subsequent [`NftEscrow::release`]
    /// only succeeds when the escrow's observed collection is in the
    /// allowlist. Builder — only meaningful in `Created`.
    pub fn with_collection_allowlist(mut self, allowlist: CollectionAllowlist) -> Self {
        self.collection_gate = Some(allowlist);
        self
    }

    /// The initializer.
    pub fn initializer(&self) -> [u8; 32] {
        self.initializer
    }

    /// The escrowed mint.
    pub fn mint(&self) -> [u8; 32] {
        self.mint
    }

    /// The caller-observed collection.
    pub fn collection(&self) -> Option<[u8; 32]> {
        self.collection
    }

    /// Current lifecycle state.
    pub fn state(&self) -> NftEscrowState {
        self.state
    }

    /// The escrowed amount: always [`NFT_PIECE_AMOUNT`] (1). Structural
    /// — there is no path that moves a fraction.
    pub fn amount(&self) -> u64 {
        NFT_PIECE_AMOUNT
    }

    /// Release the whole piece. Check order: authority → state →
    /// collection gate. Returns the transferred amount (always `1`)
    /// for exact transfer sizing by the Anchor layer.
    pub fn release(&mut self, authority: [u8; 32]) -> Result<u64, EscrowError> {
        if authority != self.initializer {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != NftEscrowState::Created {
            return Err(EscrowError::InvalidStateTransition);
        }
        if let Some(gate) = &self.collection_gate {
            match self.collection {
                Some(c) if gate.contains(&c) => {}
                _ => return Err(EscrowError::CollectionNotAllowlisted),
            }
        }
        self.state = NftEscrowState::Released;
        Ok(NFT_PIECE_AMOUNT)
    }

    /// Cancel the escrow before release. Check order: authority →
    /// state. The collection gate never blocks a cancel — gating must
    /// never trap the piece.
    pub fn cancel(&mut self, authority: [u8; 32]) -> Result<(), EscrowError> {
        if authority != self.initializer {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != NftEscrowState::Created {
            return Err(EscrowError::InvalidStateTransition);
        }
        self.state = NftEscrowState::Cancelled;
        Ok(())
    }

    /// Audit-event JSON for a lifecycle transition (hand-written):
    /// `{"event":"nft_escrow_released"|"nft_escrow_cancelled",
    /// "mint":"<64hex>","state":"<name>"}`.
    pub fn audit_json(&self, event: &str) -> String {
        let mut s = String::from("{\"event\":\"");
        s.push_str(event);
        s.push_str("\",\"mint\":\"");
        s.push_str(&hex64(&self.mint));
        s.push_str("\",\"state\":\"");
        s.push_str(self.state.name());
        s.push_str("\"}");
        s
    }
}

fn hex64(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes.iter() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> [u8; 32] {
        [0xA1; 32]
    }
    fn bob() -> [u8; 32] {
        [0xB0; 32]
    }
    fn nft_desc() -> NftMintDescriptor {
        NftMintDescriptor {
            mint: [0x11; 32],
            supply: 1,
            decimals: 0,
            collection: Some([0xCC; 32]),
        }
    }

    #[test]
    fn single_edition_mint_passes_gate() {
        let r = check_nft_mint(&nft_desc()).unwrap();
        assert!(r.is_nft());
        assert_eq!(r.mint(), [0x11; 32]);
        assert_eq!(r.collection(), Some([0xCC; 32]));
        let j = r.audit_json(1, 0);
        assert!(j.contains("\"event\":\"nft_mint_checked\""));
        assert!(j.contains("\"supply\":1"));
        assert!(j.contains(&"cc".repeat(32)));
    }

    #[test]
    fn fungible_mint_fails_closed() {
        // supply > 1: a semi-fungible edition routed through the NFT
        // path is refused, not coerced.
        let mut d = nft_desc();
        d.supply = 10;
        let err = check_nft_mint(&d).unwrap_err();
        assert_eq!(err, EscrowError::InvalidNftMint);
        assert_eq!(err.code(), 256);
    }

    #[test]
    fn decimal_mint_fails_closed() {
        let mut d = nft_desc();
        d.decimals = 9;
        assert_eq!(
            check_nft_mint(&d).unwrap_err(),
            EscrowError::InvalidNftMint
        );
    }

    #[test]
    fn collection_is_optional() {
        let mut d = nft_desc();
        d.collection = None;
        let r = check_nft_mint(&d).unwrap();
        assert_eq!(r.collection(), None);
        assert!(r.audit_json(1, 0).contains("\"collection\":null"));
    }

    #[test]
    fn allowlist_add_is_idempotent_and_bounded() {
        let mut a = CollectionAllowlist::new();
        assert!(a.is_empty());
        assert!(a.add([0x01; 32]));
        assert!(a.add([0x01; 32])); // idempotent
        assert_eq!(a.len(), 1);
        assert!(a.contains(&[0x01; 32]));
        assert!(!a.contains(&[0x02; 32]));
        assert!(a.remove(&[0x01; 32]));
        assert!(!a.remove(&[0x01; 32]));
        assert!(a.is_empty());

        // Capacity bound: exactly MAX entries fit.
        for i in 0..MAX_COLLECTION_ALLOWLIST {
            assert!(a.add([i as u8; 32]));
        }
        assert_eq!(a.len(), MAX_COLLECTION_ALLOWLIST);
        assert!(!a.add([0xFF; 32]));
    }

    #[test]
    fn new_refuses_non_nft_mint() {
        let mut d = nft_desc();
        d.supply = 0; // burned / uninitialized mint
        assert_eq!(
            NftEscrow::new(alice(), &d).unwrap_err(),
            EscrowError::InvalidNftMint
        );
    }

    #[test]
    fn release_moves_whole_piece() {
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        assert_eq!(e.amount(), 1);
        assert_eq!(e.state(), NftEscrowState::Created);
        let moved = e.release(alice()).unwrap();
        assert_eq!(moved, NFT_PIECE_AMOUNT);
        assert_eq!(e.state(), NftEscrowState::Released);
        let j = e.audit_json("nft_escrow_released");
        assert!(j.contains("\"state\":\"released\""));
    }

    #[test]
    fn release_is_single_use() {
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        e.release(alice()).unwrap();
        assert_eq!(
            e.release(alice()).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
    }

    #[test]
    fn stranger_learns_nothing() {
        // Authority is checked before state and the gate: a stranger
        // gets Unauthorized even on a terminal escrow.
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        assert_eq!(e.release(bob()).unwrap_err(), EscrowError::Unauthorized);
        assert_eq!(e.cancel(bob()).unwrap_err(), EscrowError::Unauthorized);
        e.release(alice()).unwrap();
        assert_eq!(e.cancel(bob()).unwrap_err(), EscrowError::Unauthorized);
    }

    #[test]
    fn cancel_before_release_needs_initializer() {
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        e.cancel(alice()).unwrap();
        assert_eq!(e.state(), NftEscrowState::Cancelled);
        assert_eq!(
            e.release(alice()).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        let j = e.audit_json("nft_escrow_cancelled");
        assert!(j.contains("\"state\":\"cancelled\""));
    }

    #[test]
    fn gated_release_requires_allowlisted_collection() {
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        e.release(alice()).unwrap();

        // Same escrow shape, different collection: denied.
        let mut other = nft_desc();
        other.collection = Some([0xDD; 32]);
        let mut e2 = NftEscrow::new(alice(), &other)
            .unwrap()
            .with_collection_allowlist(gate);
        let err = e2.release(alice()).unwrap_err();
        assert_eq!(err, EscrowError::CollectionNotAllowlisted);
        assert_eq!(err.code(), 257);
        // The gate fails closed: an unobserved collection on a gated
        // escrow cannot be verified, so it cannot release.
        let mut no_coll = nft_desc();
        no_coll.collection = None;
        let mut e3 = NftEscrow::new(alice(), &no_coll)
            .unwrap()
            .with_collection_allowlist(gate);
        assert_eq!(
            e3.release(alice()).unwrap_err(),
            EscrowError::CollectionNotAllowlisted
        );
    }

    #[test]
    fn gate_never_blocks_cancel() {
        // Gating must never trap the piece: cancel works on a gated
        // escrow whose collection would fail release.
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        let mut other = nft_desc();
        other.collection = Some([0xDD; 32]);
        let mut e = NftEscrow::new(alice(), &other)
            .unwrap()
            .with_collection_allowlist(gate);
        e.cancel(alice()).unwrap();
        assert_eq!(e.state(), NftEscrowState::Cancelled);
    }

    #[test]
    fn ungated_escrow_skips_collection_check() {
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        e.release(alice()).unwrap();
        assert_eq!(e.state(), NftEscrowState::Released);
    }

    #[test]
    fn error_codes_pinned() {
        // Never renumber: the Anchor layer assigns one program error
        // per variant and off-chain clients match on these numbers.
        assert_eq!(EscrowError::InvalidNftMint.code(), 256);
        assert_eq!(EscrowError::CollectionNotAllowlisted.code(), 257);
        for e in [
            EscrowError::InvalidNftMint,
            EscrowError::CollectionNotAllowlisted,
        ] {
            assert!(EscrowError::all().contains(&e));
        }
        // Count covers the whole table; AV-190 bumps it to 171.
        assert_eq!(EscrowError::all().len(), 247); // AV-195: +7 social-recovery errors, AV-196: +6 jury-sortition errors, AV-197: +5 payment-channel errors; AV-209: +4; AV-214: +6; AV-215: +1; AV-217: +3; AV-218: +2; AV-220: +1; AV-225: +1
    }
}
