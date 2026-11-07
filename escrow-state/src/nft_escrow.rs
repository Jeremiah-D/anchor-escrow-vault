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

    /// The initializer — fixed at construction, revisable only
    /// by [`NftEscrow::amend_nft_initializer`] while `Created`.
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

    /// The collection gate, if one is installed (`None` = ungated).
    pub fn collection_gate(&self) -> Option<CollectionAllowlist> {
        self.collection_gate
    }

    /// Revise the collection allowlist on a `Created` escrow
    /// (AV-284 — Solana NFT-escrow risk control): the initializer
    /// alone authorizes the change (the single-party authority
    /// precedent of `release`/`cancel` — `NftEscrow` has no taker
    /// dual-signature). Check order is authority → state, mirroring
    /// `release`/`cancel`, so a stranger learns nothing about the
    /// gate from the error alone.
    ///
    /// Why: the gate is fixed at build time
    /// ([`NftEscrow::with_collection_allowlist`]), but a collection
    /// can be compromised, delisted, or newly verified — a gate that
    /// cannot be revised would either strand the piece behind a dead
    /// collection or force a fresh escrow (and a fresh custody
    /// transfer) for a legitimate new collection. Only a `Created`
    /// escrow may revise: a `Released`/`Cancelled` escrow is
    /// terminal, so revising it could never govern a future release.
    ///
    /// An empty list clears the gate back to `None` (the AV-157 /
    /// AV-276 empty-clears precedent): after clearing, release no
    /// longer checks collections at all. A non-empty list is built
    /// with [`CollectionAllowlist::new`] + `add` per entry, reusing
    /// the build-time path exactly — duplicates collapse
    /// idempotently, and more than [`MAX_COLLECTION_ALLOWLIST`]
    /// distinct collections fail closed with
    /// [`EscrowError::InvalidCollectionAllowlist`] (code 358),
    /// leaving the original gate untouched, because the new table
    /// is validated before any write. Set equality is
    /// order-independent (`contains` membership, not slot order):
    /// re-affirming the current set in any order is a no-op that
    /// writes nothing, and clearing an already-ungated escrow is
    /// likewise a no-op. Only `collection_gate` changes — the
    /// mint, the observed collection, and the state are untouched —
    /// and `cancel` stays ungated throughout (the standing
    /// invariant that gating must never trap the piece). The new
    /// table governs from the next `release`, which reads the live
    /// gate; a release already executed is unaffected. There is no
    /// event layer on `NftEscrow`, so no event is emitted for the
    /// revision or its no-op. Orthogonal to
    /// [`NftEscrow::with_collection_allowlist`] (that installs the
    /// gate at build time, this revises it while `Created`) and to
    /// AV-276 (that is the fungible settlement-mint allowlist,
    /// this is the NFT collection allowlist).
    pub fn update_collection_allowlist(
        &mut self,
        authority: [u8; 32],
        collections: &[[u8; 32]],
    ) -> Result<(), EscrowError> {
        if authority != self.initializer {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != NftEscrowState::Created {
            return Err(EscrowError::InvalidStateTransition);
        }
        if collections.is_empty() {
            // Empty clears back to ungated; already-ungated is a no-op.
            self.collection_gate = None;
            return Ok(());
        }
        // Build first: over-capacity fails closed, original gate intact.
        let mut built = CollectionAllowlist::new();
        for c in collections {
            if !built.add(*c) {
                return Err(EscrowError::InvalidCollectionAllowlist);
            }
        }
        // Set-equality no-op (order-independent): re-affirming the
        // current set writes nothing.
        if let Some(gate) = &self.collection_gate {
            if gate.len() == built.len()
                && collections.iter().all(|c| gate.contains(c))
            {
                return Ok(());
            }
        }
        self.collection_gate = Some(built);
        Ok(())
    }

    /// Rotate the initializer on a `Created` escrow (AV-368 —
    /// Solana NFT-escrow custody): the current initializer alone
    /// authorizes the change (the single-party authority
    /// precedent of `release`/`cancel` — `NftEscrow` has no
    /// taker dual-signature). Check order is authority → state
    /// → value, mirroring
    /// [`NftEscrow::update_collection_allowlist`], so a stranger
    /// learns nothing about the escrow's state from the error
    /// alone.
    ///
    /// Why: the initializer is fixed at construction
    /// ([`NftEscrow::new`]), but the initializer's key may be
    /// compromised, or the custodian may move from a hot wallet
    /// to cold storage — with no rotation path the only exits
    /// are `release` and `cancel`, both of which only the live
    /// initializer may call, so a stolen key can release the
    /// piece to itself or cancel the escrow, and a lost key
    /// strands the piece permanently (no in-module rescue, only
    /// a fresh escrow and a fresh custody transfer). Only a
    /// `Created` escrow may rotate: a `Released`/`Cancelled`
    /// escrow is terminal, so rotating it could never govern a
    /// future release ([`EscrowError::InvalidStateTransition`],
    /// code 101). The new initializer fails closed on a zero
    /// address ([`EscrowError::InvalidNftMint`], code 256, and
    /// the current initializer is untouched) — a deliberate
    /// asymmetry with `new`, which does not validate the
    /// initializer: a rotation must never empty custody into
    /// "nobody can release or cancel" while the piece stays
    /// locked. Re-affirming the current initializer is a no-op
    /// that writes nothing. Only `initializer` changes — the
    /// mint, the observed collection, the gate, and the state
    /// are untouched — and the new initializer governs from the
    /// next call: `release` / `cancel` /
    /// `update_collection_allowlist` all read the live
    /// initializer, so the old initializer loses all three
    /// powers at once. A piece already released or cancelled is
    /// unaffected (the terminal-state gate). A successful
    /// rotation is recorded for the indexer as
    /// [`Self::initializer_audit_json`] (a string event name,
    /// no numeric event ID — `NftEscrow` has no
    /// `EscrowEventKind` layer); a failed rotation and a no-op
    /// write no audit. An initializer who has lost their key
    /// cannot rotate: the current initializer must sign,
    /// exactly like the pauser rotation (AV-355) — key loss is
    /// not recoverable here. Orthogonal to
    /// [`NftEscrow::new`] (that installs the initializer at
    /// build time, this rotates it while `Created`) and to
    /// `update_collection_allowlist` (that revises the gate,
    /// this rotates the custodian).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller who is not the current initializer,
    /// ([`EscrowError::InvalidStateTransition`], code 101) once
    /// the escrow is `Released` or `Cancelled`, and
    /// ([`EscrowError::InvalidNftMint`], code 256) for a zero
    /// new initializer — either way the current initializer is
    /// untouched.
    pub fn amend_nft_initializer(
        &mut self,
        authority: [u8; 32],
        new_initializer: [u8; 32],
    ) -> Result<(), EscrowError> {
        if authority != self.initializer {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != NftEscrowState::Created {
            return Err(EscrowError::InvalidStateTransition);
        }
        if new_initializer == [0u8; 32] {
            return Err(EscrowError::InvalidNftMint);
        }
        if new_initializer == self.initializer {
            return Ok(());
        }
        self.initializer = new_initializer;
        Ok(())
    }

    /// Audit-event JSON for an initializer rotation (hand-written,
    /// no serde — same convention as the sealed-bid / multi-unit
    /// `seller_audit_json`): `{"event":"nft_initializer_amended",
    /// "previous_initializer":"<64hex>","initializer":"<64hex>"}`.
    /// NFT audit events carry string event names, not numeric
    /// event IDs, so no new event number is registered for the
    /// rotation — the event name is the identity. Call only after
    /// a successful rotation; a failed rotation or a no-op writes
    /// no audit.
    pub fn initializer_audit_json(&self, previous_initializer: [u8; 32]) -> String {
        let mut s = String::from("{\"event\":\"nft_initializer_amended\",\"previous_initializer\":\"");
        s.push_str(&hex64(&previous_initializer));
        s.push_str("\",\"initializer\":\"");
        s.push_str(&hex64(&self.initializer));
        s.push_str("\"}");
        s
    }

    /// Revise the observed collection on a `Created` escrow (AV-370 —
    /// Solana NFT-escrow custody): the current initializer alone
    /// authorizes the change (the single-party authority precedent
    /// of `release`/`cancel` — `NftEscrow` has no taker
    /// dual-signature). Check order is authority → state → value
    /// → no-op, mirroring [`NftEscrow::amend_nft_initializer`], so a
    /// stranger learns nothing about the escrow's state from the
    /// error alone.
    ///
    /// Why: the collection is fixed at construction
    /// ([`NftEscrow::new`] observes it from the mint descriptor),
    /// but an NFT can migrate collections on-chain (Metaplex
    /// `set_and_verify_collection`, or the collection authority
    /// re-verifying under a new collection) — with no revision path
    /// the escrow keeps the stale collection, so `release` either
    /// passes on a dead collection (if the old one is still in the
    /// allowlist, the gate is checking a fact that no longer holds)
    /// or refuses a legitimate release (if the new collection was
    /// never recorded, code 257), and the only exit is `cancel`
    /// (which abandons the whole escrow and forces a rebuild with a
    /// fresh custody transfer). Only a `Created` escrow may revise:
    /// a `Released`/`Cancelled` escrow is terminal, so revising it
    /// could never govern a future release
    /// ([`EscrowError::InvalidStateTransition`], code 101). A zero
    /// collection key (`Some([0u8; 32])`) fails closed with
    /// [`EscrowError::InvalidNftMint`] (code 256) — a zero key is not
    /// a real collection. Re-affirming the current collection
    /// (including `None` over `None`) is a no-op that writes
    /// nothing. Only `collection` changes — the initializer, the
    /// mint, the gate, and the state are untouched — and the new
    /// collection governs from the next `release`, which reads the
    /// live value; `cancel` stays ungated throughout (the standing
    /// invariant that gating must never trap the piece).
    ///
    /// The gate check is fail-closed *at revision time*, not at
    /// release time: with a gate installed, the new `Some(c)` must
    /// be a gate member, and `None` (unverified) is likewise
    /// refused — otherwise the revision would push the next
    /// `release` straight into [`EscrowError::CollectionNotAllowlisted`]
    /// (code 257). A refused revision leaves the original collection
    /// untouched; to clear the collection, first clear or swap the
    /// gate with [`NftEscrow::update_collection_allowlist`]. A
    /// successful revision is recorded for the indexer as
    /// [`Self::collection_audit_json`] (a string event name, no
    /// numeric event ID — `NftEscrow` has no `EscrowEventKind`
    /// layer); a failed revision and a no-op write no audit. The
    /// revision takes the caller's value as observed — re-verifying
    /// it on-chain is the caller's job, this escrow is an off-chain
    /// state machine. Orthogonal to [`NftEscrow::new`] (that
    /// observes the collection at build time, this revises it while
    /// `Created`), to `update_collection_allowlist` (that revises
    /// the gate table, this revises the fact the gate checks — the
    /// table and the checked fact are the two halves of one gate),
    /// and to `amend_nft_initializer` (same file, different field).
    ///
    /// Refused ([`EscrowError::Unauthorized`], code 100) for a
    /// caller who is not the current initializer,
    /// ([`EscrowError::InvalidStateTransition`], code 101) once
    /// the escrow is `Released` or `Cancelled`,
    /// ([`EscrowError::InvalidNftMint`], code 256) for a zero new
    /// collection key, and
    /// ([`EscrowError::CollectionNotAllowlisted`], code 257) when
    /// a gate is installed and the new collection is not in it
    /// (or is `None`) — either way the current collection is
    /// untouched.
    pub fn amend_nft_collection(
        &mut self,
        authority: [u8; 32],
        new_collection: Option<[u8; 32]>,
    ) -> Result<(), EscrowError> {
        if authority != self.initializer {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != NftEscrowState::Created {
            return Err(EscrowError::InvalidStateTransition);
        }
        if let Some(c) = new_collection {
            if c == [0u8; 32] {
                return Err(EscrowError::InvalidNftMint);
            }
        }
        // Fail-closed at revision time: a gated escrow must keep a
        // collection the gate will accept, or the next release is
        // doomed to 257. Checked before the no-op so re-affirming a
        // collection the gate no longer holds is refused, not
        // silently kept.
        if let Some(gate) = &self.collection_gate {
            match new_collection {
                Some(c) if gate.contains(&c) => {}
                _ => return Err(EscrowError::CollectionNotAllowlisted),
            }
        }
        if new_collection == self.collection {
            return Ok(());
        }
        self.collection = new_collection;
        Ok(())
    }

    /// Audit-event JSON for a collection revision (hand-written,
    /// no serde — same convention as [`Self::initializer_audit_json`]):
    /// `{"event":"nft_collection_amended","previous_collection":
    /// "<64hex>"|null,"collection":"<64hex>"|null}` — `None` renders
    /// as bare `null`. NFT audit events carry string event names,
    /// not numeric event IDs, so no new event number is registered
    /// for the revision — the event name is the identity. Call only
    /// after a successful revision; a failed revision or a no-op
    /// writes no audit.
    pub fn collection_audit_json(&self, previous_collection: Option<[u8; 32]>) -> String {
        let mut s = String::from("{\"event\":\"nft_collection_amended\",\"previous_collection\":");
        match previous_collection {
            Some(c) => {
                s.push('"');
                s.push_str(&hex64(&c));
                s.push('"');
            }
            None => s.push_str("null"),
        }
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
    fn carol() -> [u8; 32] {
        [0xC4; 32]
    }
    fn dave() -> [u8; 32] {
        [0xD4; 32]
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
        assert_eq!(EscrowError::InvalidCollectionAllowlist.code(), 358);
        for e in [
            EscrowError::InvalidNftMint,
            EscrowError::CollectionNotAllowlisted,
            EscrowError::InvalidCollectionAllowlist,
        ] {
            assert!(EscrowError::all().contains(&e));
        }
        // Count covers the whole table; AV-190 bumps it to 171.
        assert_eq!(EscrowError::all().len(), 253); // AV-195: +7 social-recovery errors, AV-196: +6 jury-sortition errors, AV-197: +5 payment-channel errors; AV-209: +4; AV-214: +6; AV-215: +1; AV-217: +3; AV-218: +2; AV-220: +1; AV-225: +1; AV-228: +1; AV-266: +1; AV-284: +1; AV-287: +1 auto-unpause-at error; AV-337: +1 governance-proposal-expired error; AV-342: +1 distribution-claims-started error
    }

    #[test]
    fn revised_gate_governs_next_release() {
        // Gated on CC: revise to DD and the CC piece can no longer
        // release; revise back to CC and it releases.
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        e.update_collection_allowlist(alice(), &[[0xDD; 32]])
            .unwrap();
        assert_eq!(
            e.release(alice()).unwrap_err(),
            EscrowError::CollectionNotAllowlisted
        );
        e.update_collection_allowlist(alice(), &[[0xCC; 32]])
            .unwrap();
        e.release(alice()).unwrap();
        assert_eq!(e.state(), NftEscrowState::Released);
    }

    #[test]
    fn revision_can_install_a_gate_on_ungated_escrow() {
        // Ungated escrows release freely; installing a gate that
        // excludes the observed collection blocks the next release.
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        assert_eq!(e.collection_gate(), None);
        e.update_collection_allowlist(alice(), &[[0xDD; 32]])
            .unwrap();
        assert_eq!(
            e.release(alice()).unwrap_err(),
            EscrowError::CollectionNotAllowlisted
        );
    }

    #[test]
    fn revision_empty_clears_gate() {
        let mut gate = CollectionAllowlist::new();
        gate.add([0xDD; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        assert_eq!(
            e.release(alice()).unwrap_err(),
            EscrowError::CollectionNotAllowlisted
        );
        e.update_collection_allowlist(alice(), &[]).unwrap();
        assert_eq!(e.collection_gate(), None);
        e.release(alice()).unwrap();
    }

    #[test]
    fn revision_rejects_stranger_and_terminal_states() {
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        // Authority before state: a stranger on a terminal escrow
        // still gets Unauthorized, not a state error.
        assert_eq!(
            e.update_collection_allowlist(bob(), &[[0xDD; 32]])
                .unwrap_err(),
            EscrowError::Unauthorized
        );
        e.release(alice()).unwrap();
        assert_eq!(
            e.update_collection_allowlist(bob(), &[[0xDD; 32]])
                .unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(
            e.update_collection_allowlist(alice(), &[[0xDD; 32]])
                .unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        let mut c = NftEscrow::new(alice(), &nft_desc()).unwrap();
        c.cancel(alice()).unwrap();
        assert_eq!(
            c.update_collection_allowlist(alice(), &[[0xDD; 32]])
                .unwrap_err(),
            EscrowError::InvalidStateTransition
        );
    }

    #[test]
    fn revision_over_capacity_fails_closed() {
        // Nine distinct collections exceed MAX (8): the error is the
        // new code 358 and the original gate is untouched.
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        let mut over: [[u8; 32]; 9] = [[0u8; 32]; 9];
        for (i, slot) in over.iter_mut().enumerate() {
            *slot = [i as u8 + 1; 32];
        }
        let err = e
            .update_collection_allowlist(alice(), &over)
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidCollectionAllowlist);
        assert_eq!(err.code(), 358);
        // Original gate intact: the CC piece still releases.
        e.release(alice()).unwrap();
    }

    #[test]
    fn revision_same_set_in_any_order_is_noop() {
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        gate.add([0xDD; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        // Reordered re-affirmation: succeeds, gate unchanged, and
        // duplicates in the input collapse idempotently.
        e.update_collection_allowlist(alice(), &[[0xDD; 32], [0xCC; 32], [0xCC; 32]])
            .unwrap();
        assert_eq!(e.collection_gate(), Some(gate));
        e.release(alice()).unwrap();
        // Clearing an already-ungated escrow is also a no-op.
        let mut u = NftEscrow::new(alice(), &nft_desc()).unwrap();
        u.update_collection_allowlist(alice(), &[]).unwrap();
        assert_eq!(u.collection_gate(), None);
    }

    #[test]
    fn revision_changes_only_the_gate() {
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        e.update_collection_allowlist(alice(), &[[0xDD; 32], [0xEE; 32]])
            .unwrap();
        assert_eq!(e.mint(), [0x11; 32]);
        assert_eq!(e.collection(), Some([0xCC; 32]));
        assert_eq!(e.state(), NftEscrowState::Created);
        assert_eq!(e.initializer(), alice());
        // Cancel stays ungated after a revision.
        e.cancel(alice()).unwrap();
        assert_eq!(e.state(), NftEscrowState::Cancelled);
    }

    #[test]
    fn amend_nft_initializer_moves_the_live_initializer() {
        // AV-368: the revised initializer governs the next call,
        // and nothing else moves.
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        e.amend_nft_initializer(alice(), carol()).unwrap();
        assert_eq!(e.initializer(), carol());
        assert_eq!(e.mint(), [0x11; 32]);
        assert_eq!(e.collection(), Some([0xCC; 32]));
        assert_eq!(e.state(), NftEscrowState::Created);
        assert_eq!(e.collection_gate(), None);
        // The old initializer is refused at the release gate, the
        // new initializer releases the whole piece.
        assert_eq!(
            e.release(alice()).unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(e.release(carol()).unwrap(), NFT_PIECE_AMOUNT);
        assert_eq!(e.state(), NftEscrowState::Released);
    }

    #[test]
    fn amend_nft_initializer_old_initializer_loses_governance() {
        // AV-368: rotation revokes the old initializer's three
        // powers at once — release, cancel, and gate revision.
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        e.amend_nft_initializer(alice(), carol()).unwrap();
        assert_eq!(
            e.release(alice()).unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(
            e.cancel(alice()).unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(
            e.update_collection_allowlist(alice(), &[[0xDD; 32]])
                .unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(e.initializer(), carol());
        assert_eq!(e.state(), NftEscrowState::Created);
    }

    #[test]
    fn amend_nft_initializer_new_initializer_can_govern() {
        // AV-368: the new initializer keeps governing — a gate
        // revision succeeds under it, and the revised gate governs
        // the next release; a second escrow cancels under it.
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        e.amend_nft_initializer(alice(), carol()).unwrap();
        e.update_collection_allowlist(carol(), &[[0xDD; 32]])
            .unwrap();
        assert_eq!(
            e.release(carol()).unwrap_err(),
            EscrowError::CollectionNotAllowlisted
        );
        e.update_collection_allowlist(carol(), &[[0xCC; 32]])
            .unwrap();
        e.release(carol()).unwrap();
        assert_eq!(e.state(), NftEscrowState::Released);

        let mut c = NftEscrow::new(alice(), &nft_desc()).unwrap();
        c.amend_nft_initializer(alice(), carol()).unwrap();
        c.cancel(carol()).unwrap();
        assert_eq!(c.state(), NftEscrowState::Cancelled);
    }

    #[test]
    fn amend_nft_initializer_rejects_stranger_and_terminal_states() {
        // AV-368: authority is checked before state — a stranger
        // on a terminal escrow still gets Unauthorized, not a
        // state error — and the initializer is untouched either
        // way.
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        let err = e
            .amend_nft_initializer(bob(), carol())
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        assert_eq!(e.initializer(), alice());
        e.release(alice()).unwrap();
        assert_eq!(
            e.amend_nft_initializer(bob(), carol()).unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(
            e.amend_nft_initializer(alice(), carol()).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        assert_eq!(e.initializer(), alice());
        let mut c = NftEscrow::new(alice(), &nft_desc()).unwrap();
        c.cancel(alice()).unwrap();
        assert_eq!(
            c.amend_nft_initializer(alice(), carol()).unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        assert_eq!(c.initializer(), alice());
    }

    #[test]
    fn amend_nft_initializer_rejects_zero_initializer() {
        // AV-368: a zero new initializer fails closed with
        // InvalidNftMint (256) — custody must never be emptied
        // while the piece stays locked — and the current
        // initializer is untouched.
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        let err = e
            .amend_nft_initializer(alice(), [0u8; 32])
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidNftMint);
        assert_eq!(err.code(), 256);
        assert_eq!(e.initializer(), alice());
        // Still releasable by the affirmed initializer.
        e.release(alice()).unwrap();
    }

    #[test]
    fn amend_nft_initializer_reaffirmation_is_noop() {
        // AV-368: re-affirming the current initializer succeeds
        // and changes nothing — and it writes no audit (the
        // audit JSON below records previous == initializer).
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        e.amend_nft_initializer(alice(), alice()).unwrap();
        assert_eq!(e.initializer(), alice());
        assert_eq!(
            e.initializer_audit_json(alice()),
            format!(
                "{{\"event\":\"nft_initializer_amended\",\"previous_initializer\":\"{}\",\"initializer\":\"{}\"}}",
                "a1".repeat(32),
                "a1".repeat(32)
            )
        );
        e.release(alice()).unwrap();
    }

    #[test]
    fn amend_nft_initializer_audit_json() {
        // AV-368: the audit JSON names the event and both keys in
        // hex, exactly — the event name is the identity, no
        // numeric event ID is registered.
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        e.amend_nft_initializer(alice(), carol()).unwrap();
        let j = e.initializer_audit_json(alice());
        assert!(j.contains("\"event\":\"nft_initializer_amended\""));
        assert!(j.contains("\"previous_initializer\":\""));
        assert!(j.contains("\"initializer\":\""));
        assert_eq!(
            j,
            format!(
                "{{\"event\":\"nft_initializer_amended\",\"previous_initializer\":\"{}\",\"initializer\":\"{}\"}}",
                "a1".repeat(32),
                "c4".repeat(32)
            )
        );
        // A second rotation audits the new previous key.
        e.amend_nft_initializer(carol(), dave()).unwrap();
        assert_eq!(
            e.initializer_audit_json(carol()),
            format!(
                "{{\"event\":\"nft_initializer_amended\",\"previous_initializer\":\"{}\",\"initializer\":\"{}\"}}",
                "c4".repeat(32),
                "d4".repeat(32)
            )
        );
    }

    #[test]
    fn amend_nft_initializer_failed_rotation_writes_no_audit() {
        // AV-368: a failed rotation leaves the initializer
        // untouched, so an audit rendered against it records no
        // rotation — previous and current are the same key.
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        let _ = e.amend_nft_initializer(alice(), [0u8; 32]);
        assert_eq!(e.initializer(), alice());
        assert_eq!(
            e.initializer_audit_json(alice()),
            format!(
                "{{\"event\":\"nft_initializer_amended\",\"previous_initializer\":\"{}\",\"initializer\":\"{}\"}}",
                "a1".repeat(32),
                "a1".repeat(32)
            )
        );
        let _ = e.amend_nft_initializer(bob(), carol());
        assert_eq!(e.initializer(), alice());
        assert_eq!(
            e.initializer_audit_json(alice()),
            format!(
                "{{\"event\":\"nft_initializer_amended\",\"previous_initializer\":\"{}\",\"initializer\":\"{}\"}}",
                "a1".repeat(32),
                "a1".repeat(32)
            )
        );
    }

    // --- AV-370: amend_nft_collection --------------------------------

    #[test]
    fn amend_nft_collection_moves_the_observed_collection() {
        // AV-370: the revised collection governs the next call,
        // and nothing else moves.
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        e.amend_nft_collection(alice(), Some([0xDD; 32])).unwrap();
        assert_eq!(e.collection(), Some([0xDD; 32]));
        assert_eq!(e.initializer(), alice());
        assert_eq!(e.mint(), [0x11; 32]);
        assert_eq!(e.state(), NftEscrowState::Created);
        assert_eq!(e.collection_gate(), None);
        // Ungated: release still passes under the new collection.
        assert_eq!(e.release(alice()).unwrap(), NFT_PIECE_AMOUNT);
        assert_eq!(e.state(), NftEscrowState::Released);
    }

    #[test]
    fn amend_nft_collection_rejects_stranger_and_terminal_states() {
        // AV-370: authority is checked before state — a stranger
        // on a terminal escrow still gets Unauthorized, not a
        // state error — and the collection is untouched either way.
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        let err = e
            .amend_nft_collection(bob(), Some([0xDD; 32]))
            .unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);
        assert_eq!(err.code(), 100);
        assert_eq!(e.collection(), Some([0xCC; 32]));
        e.release(alice()).unwrap();
        assert_eq!(
            e.amend_nft_collection(bob(), Some([0xDD; 32]))
                .unwrap_err(),
            EscrowError::Unauthorized
        );
        assert_eq!(
            e.amend_nft_collection(alice(), Some([0xDD; 32]))
                .unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        assert_eq!(e.collection(), Some([0xCC; 32]));
        let mut c = NftEscrow::new(alice(), &nft_desc()).unwrap();
        c.cancel(alice()).unwrap();
        assert_eq!(
            c.amend_nft_collection(alice(), Some([0xDD; 32]))
                .unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        assert_eq!(c.collection(), Some([0xCC; 32]));
    }

    #[test]
    fn amend_nft_collection_rejects_zero_collection() {
        // AV-370: a zero collection key fails closed with
        // InvalidNftMint (256) — a zero key is not a real
        // collection — and the current collection is untouched.
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        let err = e
            .amend_nft_collection(alice(), Some([0u8; 32]))
            .unwrap_err();
        assert_eq!(err, EscrowError::InvalidNftMint);
        assert_eq!(err.code(), 256);
        assert_eq!(e.collection(), Some([0xCC; 32]));
        // Still releasable under the affirmed collection.
        e.release(alice()).unwrap();
    }

    #[test]
    fn amend_nft_collection_reaffirmation_is_noop() {
        // AV-370: re-affirming the current collection succeeds and
        // changes nothing — including `None` over `None`.
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        e.amend_nft_collection(alice(), Some([0xCC; 32])).unwrap();
        assert_eq!(e.collection(), Some([0xCC; 32]));
        assert_eq!(
            e.collection_audit_json(Some([0xCC; 32])),
            format!(
                "{{\"event\":\"nft_collection_amended\",\"previous_collection\":\"{}\",\"collection\":\"{}\"}}",
                "cc".repeat(32),
                "cc".repeat(32)
            )
        );
        e.release(alice()).unwrap();

        let mut desc = nft_desc();
        desc.collection = None;
        let mut u = NftEscrow::new(alice(), &desc).unwrap();
        assert_eq!(u.collection(), None);
        u.amend_nft_collection(alice(), None).unwrap();
        assert_eq!(u.collection(), None);
        u.cancel(alice()).unwrap();
    }

    #[test]
    fn amend_nft_collection_gated_revision_inside_gate_releases() {
        // AV-370: with a gate installed, a revision into the gate
        // succeeds, and the next release passes under the new
        // collection.
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        gate.add([0xDD; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        e.amend_nft_collection(alice(), Some([0xDD; 32])).unwrap();
        assert_eq!(e.collection(), Some([0xDD; 32]));
        assert_eq!(e.release(alice()).unwrap(), NFT_PIECE_AMOUNT);
        assert_eq!(e.state(), NftEscrowState::Released);
    }

    #[test]
    fn amend_nft_collection_gated_revision_outside_gate_is_refused() {
        // AV-370: fail-closed at revision time — a new collection
        // outside the gate is refused with 257 and the original
        // collection is untouched, so the next release still
        // passes under it.
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        let err = e
            .amend_nft_collection(alice(), Some([0xDD; 32]))
            .unwrap_err();
        assert_eq!(err, EscrowError::CollectionNotAllowlisted);
        assert_eq!(err.code(), 257);
        assert_eq!(e.collection(), Some([0xCC; 32]));
        e.release(alice()).unwrap();
    }

    #[test]
    fn amend_nft_collection_gated_none_is_refused() {
        // AV-370: with a gate installed, clearing the collection
        // to `None` (unverified) is refused with 257 — otherwise
        // the revision would push the next release straight into
        // 257. To clear the collection, clear or swap the gate
        // first (AV-284).
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        let err = e.amend_nft_collection(alice(), None).unwrap_err();
        assert_eq!(err, EscrowError::CollectionNotAllowlisted);
        assert_eq!(err.code(), 257);
        assert_eq!(e.collection(), Some([0xCC; 32]));
        e.release(alice()).unwrap();
    }

    #[test]
    fn amend_nft_collection_release_judges_new_collection() {
        // AV-370: `release` reads the live collection — after the
        // revision the old collection no longer governs. Gate
        // {CC, DD}, collection CC → revise to DD → shrink the gate
        // to {CC}: the release is refused even though the *old*
        // collection would have passed.
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        gate.add([0xDD; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        e.amend_nft_collection(alice(), Some([0xDD; 32])).unwrap();
        e.update_collection_allowlist(alice(), &[[0xCC; 32]])
            .unwrap();
        assert_eq!(
            e.release(alice()).unwrap_err(),
            EscrowError::CollectionNotAllowlisted
        );
        assert_eq!(e.state(), NftEscrowState::Created);
    }

    #[test]
    fn amend_nft_collection_does_not_gate_cancel() {
        // AV-370: the revision never traps the piece — `cancel`
        // stays ungated after a revision, gated or not.
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        gate.add([0xDD; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        e.amend_nft_collection(alice(), Some([0xDD; 32])).unwrap();
        e.cancel(alice()).unwrap();
        assert_eq!(e.state(), NftEscrowState::Cancelled);
    }

    #[test]
    fn amend_nft_collection_audit_json() {
        // AV-370: the audit JSON names the event and both
        // collections in hex, exactly — `None` renders as bare
        // `null`. The event name is the identity, no numeric
        // event ID is registered.
        let mut e = NftEscrow::new(alice(), &nft_desc()).unwrap();
        e.amend_nft_collection(alice(), Some([0xDD; 32])).unwrap();
        assert_eq!(
            e.collection_audit_json(Some([0xCC; 32])),
            format!(
                "{{\"event\":\"nft_collection_amended\",\"previous_collection\":\"{}\",\"collection\":\"{}\"}}",
                "cc".repeat(32),
                "dd".repeat(32)
            )
        );
        // `None` as the previous collection renders as bare null.
        let mut desc = nft_desc();
        desc.collection = None;
        let mut u = NftEscrow::new(alice(), &desc).unwrap();
        u.amend_nft_collection(alice(), Some([0xDD; 32])).unwrap();
        assert_eq!(
            u.collection_audit_json(None),
            format!(
                "{{\"event\":\"nft_collection_amended\",\"previous_collection\":null,\"collection\":\"{}\"}}",
                "dd".repeat(32)
            )
        );
        // Revising back to `None` (ungated) audits the hex
        // previous against a null current.
        u.amend_nft_collection(alice(), None).unwrap();
        assert_eq!(
            u.collection_audit_json(Some([0xDD; 32])),
            format!(
                "{{\"event\":\"nft_collection_amended\",\"previous_collection\":\"{}\",\"collection\":null}}",
                "dd".repeat(32)
            )
        );
    }

    #[test]
    fn amend_nft_collection_failed_revision_writes_no_audit() {
        // AV-370: a failed revision leaves the collection
        // untouched, so an audit rendered against it records no
        // revision — previous and current are the same key.
        let mut gate = CollectionAllowlist::new();
        gate.add([0xCC; 32]);
        let mut e = NftEscrow::new(alice(), &nft_desc())
            .unwrap()
            .with_collection_allowlist(gate);
        let _ = e.amend_nft_collection(alice(), Some([0xDD; 32]));
        assert_eq!(e.collection(), Some([0xCC; 32]));
        assert_eq!(
            e.collection_audit_json(Some([0xCC; 32])),
            format!(
                "{{\"event\":\"nft_collection_amended\",\"previous_collection\":\"{}\",\"collection\":\"{}\"}}",
                "cc".repeat(32),
                "cc".repeat(32)
            )
        );
        let _ = e.amend_nft_collection(bob(), Some([0xDD; 32]));
        assert_eq!(e.collection(), Some([0xCC; 32]));
        assert_eq!(
            e.collection_audit_json(Some([0xCC; 32])),
            format!(
                "{{\"event\":\"nft_collection_amended\",\"previous_collection\":\"{}\",\"collection\":\"{}\"}}",
                "cc".repeat(32),
                "cc".repeat(32)
            )
        );
    }
}
