//! AV-138: off-chain multi-dimensional escrow index (`EscrowIndex`).
//!
//! A keeper bot watches hundreds or thousands of vaults and re-scans the
//! same watch list every few slots. The keeper scans
//! ([`crate::keeper::scan_keeper_actions`] (AV-20),
//! [`crate::expiry_watch::scan_expiry_warnings`] (AV-136),
//! [`crate::keeper::scan_closeable`] (AV-40)) each filter on a small set
//! of dimensions — the escrow's [`EscrowState`], its bound SPL mint (or
//! native SOL), and its `expires_at` deadline. Walking the whole watch
//! list for every scan is O(n) per scan with a constant that grows as
//! the fleet does; worse, several scans only care about one slice of
//! the fleet (terminal vaults for the close sweep, soon-expiring
//! `Funded` vaults for the expiry warnings).
//!
//! `EscrowIndex` keeps the watch list's [`WatchedEscrow`] snapshots in
//! insertion (watch) order and maintains three inverted indexes over
//! them, updated incrementally on [`EscrowIndex::insert`],
//! [`EscrowIndex::update`] and [`EscrowIndex::remove`]:
//!
//! - `state`: one bucket per [`EscrowState`] discriminant — the
//!   close sweep reads only the terminal buckets, the expiry scan
//!   reads only `Funded`/`Activated`.
//! - `mint`: one bucket per bound mint (`None` = native SOL) — a
//!   per-token operator scans only its own mint's vaults.
//! - `expires_at`: a `BTreeMap` deadline index — the expiry scan
//!   reads only the `(now, now + window]` range instead of testing
//!   every vault's deadline.
//!
//! Every query returns candidates in index order — insertion order until
//! the first removal, after which `swap_remove` may relocate the last
//! entry (see [`EscrowIndex::iter`]). The order is deterministic for a
//! given op sequence, so an indexed scan over the index's own iteration
//! emits byte-identical output to a slice scan over that same order —
//! the index prunes *which* snapshots are visited, never the order
//! they are visited in (see [`EscrowIndex::candidates_for_state`]).
//!
//! Consistency: [`EscrowIndex::verify_consistency`] rebuilds the three
//! dimensions from the backing store and reconciles them against the
//! live index, naming the first divergence. The indexed keeper scans
//! run it under `debug_assertions`, and the test suite drives random
//! insert/update/remove sequences through it — a keeper that mutates
//! the index across slots gets a loud failure instead of a silently
//! pruned scan.
//!
//! Purely off-chain and read-only from the chain's perspective:
//! the index holds snapshots, never touches accounts, emits no events
//! and reads no clock. `std` only, no new dependencies.

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound::{Excluded, Included};

use crate::keeper::WatchedEscrow;
use crate::EscrowState;

/// Number of [`EscrowState`] variants. Discriminants are `0..=10`;
/// the mapping below is exhaustive, so a future variant fails to
/// compile here instead of silently landing in the wrong bucket.
const STATE_COUNT: usize = 11;

/// Bucket index for an [`EscrowState`]. Exhaustive on purpose: adding
/// a variant to [`EscrowState`] must extend this table, or the index
/// would mis-file the new state's vaults.
const fn state_index(state: EscrowState) -> usize {
    match state {
        EscrowState::Uninitialized => 0,
        EscrowState::Funded => 1,
        EscrowState::Released => 2,
        EscrowState::Cancelled => 3,
        EscrowState::Activated => 4,
        EscrowState::Disputed => 5,
        EscrowState::Settled => 6,
        EscrowState::Closed => 7,
        EscrowState::Split => 8,
        EscrowState::Declined => 9,
        EscrowState::CounterOffered => 10,
    }
}

/// The three indexed dimensions of one entry: state bucket, mint
/// bucket key, expiry bucket key. All `Copy`, so index maintenance
/// never borrows the backing store across a mutation.
fn bucket_keys(entry: &WatchedEscrow) -> (usize, Option<[u8; 32]>, u64) {
    let e = &entry.escrow;
    (state_index(e.state()), e.mint(), e.expires_at())
}

/// Remove one position from a bucket vec. Positions are unique within
/// a bucket (each entry appears exactly once per dimension).
fn remove_from_bucket(bucket: &mut Vec<usize>, pos: usize) {
    if let Some(i) = bucket.iter().position(|&p| p == pos) {
        bucket.swap_remove(i);
    }
}

/// A keeper's watch list with incremental multi-dimensional indexes.
///
/// Backing store is insertion-ordered [`WatchedEscrow`] snapshots; the
/// three inverted indexes hold positions into that store. All
/// mutations keep every dimension in sync — see
/// [`EscrowIndex::verify_consistency`].
#[derive(Debug, Clone, Default)]
pub struct EscrowIndex {
    entries: Vec<WatchedEscrow>,
    id_pos: HashMap<[u8; 32], usize>,
    by_state: [Vec<usize>; STATE_COUNT],
    by_mint: HashMap<Option<[u8; 32]>, Vec<usize>>,
    by_expiry: BTreeMap<u64, Vec<usize>>,
}

impl EscrowIndex {
    /// Empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an index from a watch-list slice, keeping the slice's
    /// order. A duplicated `escrow_id` keeps its *first* occurrence —
    /// the index keys entries by id, and a watch list with duplicate
    /// ids is already ambiguous for the keeper.
    pub fn from_watched(watched: &[WatchedEscrow]) -> Self {
        let mut index = Self::new();
        for w in watched {
            index.insert(*w);
        }
        index
    }

    /// Number of watched escrows in the index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the index watches nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up one watched escrow by id.
    pub fn get(&self, escrow_id: &[u8; 32]) -> Option<&WatchedEscrow> {
        self.id_pos.get(escrow_id).map(|&pos| &self.entries[pos])
    }

    /// Iterate every watched escrow in index order: insertion order
    /// until the first removal, after which `swap_remove` relocates the
    /// last entry into the freed slot. The order is deterministic for a
    /// given insert/update/remove sequence — that determinism (not the
    /// original insertion order) is what the indexed scans rely on.
    pub fn iter(&self) -> impl Iterator<Item = &WatchedEscrow> {
        self.entries.iter()
    }

    /// Insert a new watched escrow. Returns `false` (and inserts
    /// nothing) when the id is already watched — use
    /// [`EscrowIndex::update`] to refresh a known entry.
    pub fn insert(&mut self, entry: WatchedEscrow) -> bool {
        if self.id_pos.contains_key(&entry.escrow_id) {
            return false;
        }
        let pos = self.entries.len();
        self.id_pos.insert(entry.escrow_id, pos);
        self.entries.push(entry);
        self.index_pos(pos);
        true
    }

    /// Replace the snapshot for a watched id, re-filing it in every
    /// dimension (a state transition moves the entry between state
    /// buckets; a re-mint or an `extend_expiry` moves the mint/expiry
    /// buckets). Returns `false` when the id is not watched.
    pub fn update(&mut self, entry: WatchedEscrow) -> bool {
        let pos = match self.id_pos.get(&entry.escrow_id) {
            Some(&p) => p,
            None => return false,
        };
        let old_keys = bucket_keys(&self.entries[pos]);
        self.unindex_pos(pos, old_keys);
        self.entries[pos] = entry;
        self.index_pos(pos);
        true
    }

    /// Stop watching an escrow. Returns the removed snapshot, or
    /// `None` when the id was not watched. The backing store uses
    /// `swap_remove`, so a removal may relocate the last entry — its
    /// id mapping and every bucket reference are rewritten to the new
    /// position as part of the same call.
    pub fn remove(&mut self, escrow_id: &[u8; 32]) -> Option<WatchedEscrow> {
        let pos = self.id_pos.remove(escrow_id)?;
        let last = self.entries.len() - 1;
        let removed_keys = bucket_keys(&self.entries[pos]);
        // The entry that will slide into `pos`, if any — captured
        // before the swap so its old position (`last`) can be
        // unindexed afterwards.
        let moved = if pos == last {
            None
        } else {
            let e = &self.entries[last];
            Some((e.escrow_id, bucket_keys(e)))
        };
        self.unindex_pos(pos, removed_keys);
        let removed = self.entries.swap_remove(pos);
        if let Some((moved_id, moved_keys)) = moved {
            self.unindex_pos(last, moved_keys);
            self.id_pos.insert(moved_id, pos);
            self.index_pos(pos);
        }
        Some(removed)
    }

    /// All watched escrows currently in `state`, in index order. The
    /// close sweep reads only the terminal buckets; the merge-pair
    /// pass reads only `Funded`.
    pub fn candidates_for_state(&self, state: EscrowState) -> Vec<&WatchedEscrow> {
        self.ordered_refs(&self.by_state[state_index(state)])
    }

    /// All watched escrows bound to `mint` (`None` = native SOL), in
    /// index order. A per-token operator scans only its own mint's
    /// vaults instead of the whole fleet.
    pub fn candidates_for_mint(&self, mint: Option<[u8; 32]>) -> Vec<&WatchedEscrow> {
        match self.by_mint.get(&mint) {
            Some(bucket) => self.ordered_refs(bucket),
            None => Vec::new(),
        }
    }

    /// All watched escrows with `after < expires_at <= up_to`, in
    /// index order. The expiry-warning scan calls this with
    /// `after = now` and `up_to = now.saturating_add(warn_window_secs)`
    /// — the same `(now, now + window]` window the slice scan tests
    /// per escrow, so already-expired vaults stay the AV-20
    /// `cancel_expired` scan's property and are never double-listed.
    pub fn expiring_in(&self, after: u64, up_to: u64) -> Vec<&WatchedEscrow> {
        let mut positions = Vec::new();
        for (_, bucket) in self.by_expiry.range((Excluded(after), Included(up_to))) {
            positions.extend_from_slice(bucket);
        }
        self.ordered_refs(&positions)
    }

    /// Rebuild every dimension from the backing store and reconcile
    /// against the live index, naming the first divergence. A keeper
    /// mutating the index across slots calls this (or relies on the
    /// indexed scans' `debug_assertions`) to catch a missed bucket
    /// update before it silently prunes a scan.
    pub fn verify_consistency(&self) -> Result<(), String> {
        if self.id_pos.len() != self.entries.len() {
            return Err(format!(
                "id map holds {} ids for {} entries",
                self.id_pos.len(),
                self.entries.len()
            ));
        }
        for (pos, e) in self.entries.iter().enumerate() {
            match self.id_pos.get(&e.escrow_id) {
                Some(&p) if p == pos => {}
                _ => {
                    return Err(format!(
                        "id map disagrees with backing store at position {}",
                        pos
                    ))
                }
            }
        }
        let rebuilt = Self::from_watched(&self.entries);
        for si in 0..STATE_COUNT {
            let mut live = self.bucket_ids(&self.by_state[si]);
            let mut fresh = rebuilt.bucket_ids(&rebuilt.by_state[si]);
            live.sort_unstable();
            fresh.sort_unstable();
            if live != fresh {
                return Err(format!("state bucket {} diverged from rebuild", si));
            }
        }
        let mut live_keys: Vec<Option<[u8; 32]>> = self.by_mint.keys().copied().collect();
        let mut fresh_keys: Vec<Option<[u8; 32]>> = rebuilt.by_mint.keys().copied().collect();
        live_keys.sort();
        fresh_keys.sort();
        if live_keys != fresh_keys {
            return Err("mint bucket key set diverged from rebuild".to_string());
        }
        for key in live_keys {
            let mut live = self.bucket_ids(&self.by_mint[&key]);
            let mut fresh = rebuilt.bucket_ids(&rebuilt.by_mint[&key]);
            live.sort_unstable();
            fresh.sort_unstable();
            if live != fresh {
                return Err("a mint bucket diverged from rebuild".to_string());
            }
        }
        let mut live_exp: Vec<u64> = self.by_expiry.keys().copied().collect();
        let mut fresh_exp: Vec<u64> = rebuilt.by_expiry.keys().copied().collect();
        live_exp.sort_unstable();
        fresh_exp.sort_unstable();
        if live_exp != fresh_exp {
            return Err("expiry bucket key set diverged from rebuild".to_string());
        }
        for exp in live_exp {
            let mut live = self.bucket_ids(&self.by_expiry[&exp]);
            let mut fresh = rebuilt.bucket_ids(&rebuilt.by_expiry[&exp]);
            live.sort_unstable();
            fresh.sort_unstable();
            if live != fresh {
                return Err("an expiry bucket diverged from rebuild".to_string());
            }
        }
        Ok(())
    }

    /// File `pos` in all three dimensions.
    fn index_pos(&mut self, pos: usize) {
        let (si, mint, expiry) = bucket_keys(&self.entries[pos]);
        self.by_state[si].push(pos);
        self.by_mint.entry(mint).or_default().push(pos);
        self.by_expiry.entry(expiry).or_default().push(pos);
    }

    /// Remove `pos` from all three dimensions, given the entry's keys
    /// (the caller reads them before any mutation). Emptied mint/expiry
    /// buckets are dropped so the key sets stay tight.
    fn unindex_pos(&mut self, pos: usize, keys: (usize, Option<[u8; 32]>, u64)) {
        let (si, mint, expiry) = keys;
        remove_from_bucket(&mut self.by_state[si], pos);
        let mint_empty = match self.by_mint.get_mut(&mint) {
            Some(bucket) => {
                remove_from_bucket(bucket, pos);
                bucket.is_empty()
            }
            None => false,
        };
        if mint_empty {
            self.by_mint.remove(&mint);
        }
        let expiry_empty = match self.by_expiry.get_mut(&expiry) {
            Some(bucket) => {
                remove_from_bucket(bucket, pos);
                bucket.is_empty()
            }
            None => false,
        };
        if expiry_empty {
            self.by_expiry.remove(&expiry);
        }
    }

    /// Bucket positions as entry references, in index order. Bucket
    /// vecs are append-ordered but `swap_remove` on unindex can
    /// reorder them, so queries sort by position — every query sees
    /// one deterministic order.
    fn ordered_refs(&self, positions: &[usize]) -> Vec<&WatchedEscrow> {
        let mut sorted: Vec<usize> = positions.to_vec();
        sorted.sort_unstable();
        sorted.into_iter().map(|p| &self.entries[p]).collect()
    }

    /// The `escrow_id`s behind a bucket's positions.
    fn bucket_ids(&self, bucket: &[usize]) -> Vec<[u8; 32]> {
        bucket.iter().map(|&p| self.entries[p].escrow_id).collect()
    }
}

#[cfg(test)]
mod index_tests {
    use super::*;
    use crate::keeper::{scan_keeper_actions, scan_keeper_actions_indexed};
    use crate::expiry_watch::{scan_expiry_warnings, scan_expiry_warnings_indexed};
    use crate::{Escrow, EscrowState};

    const ALICE: [u8; 32] = [1; 32];
    const BOB: [u8; 32] = [2; 32];
    const MINT_A: [u8; 32] = [9; 32];
    const MINT_B: [u8; 32] = [8; 32];
    const NOW: u64 = 1_700_000_000;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn watch(id: u8, escrow: Escrow) -> WatchedEscrow {
        WatchedEscrow {
            escrow_id: key(id),
            escrow,
            reference: None,
            vault_derivation: None,
            pending_intent: None,
        }
    }

    fn funded(id: u8, expires_at: u64) -> WatchedEscrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, expires_at).unwrap();
        e.fund(ALICE, NOW - 100).unwrap();
        watch(id, e)
    }

    fn funded_with_mint(id: u8, expires_at: u64, mint: [u8; 32]) -> WatchedEscrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, expires_at)
            .unwrap()
            .with_mint(mint)
            .unwrap();
        e.fund(ALICE, NOW - 100).unwrap();
        watch(id, e)
    }

    fn uninitialized(id: u8, expires_at: u64) -> WatchedEscrow {
        watch(
            id,
            Escrow::initialize(ALICE, BOB, 1_000_000, expires_at).unwrap(),
        )
    }

    fn uninitialized_with_mint(id: u8, expires_at: u64, mint: [u8; 32]) -> WatchedEscrow {
        watch(
            id,
            Escrow::initialize(ALICE, BOB, 1_000_000, expires_at)
                .unwrap()
                .with_mint(mint)
                .unwrap(),
        )
    }

    fn cancelled(id: u8, expires_at: u64) -> WatchedEscrow {
        let mut w = funded(id, expires_at);
        w.escrow.cancel(ALICE, None, ALICE, 0).unwrap();
        w
    }

    fn cancelled_with_mint(id: u8, expires_at: u64, mint: [u8; 32]) -> WatchedEscrow {
        let mut w = funded_with_mint(id, expires_at, mint);
        w.escrow.cancel(ALICE, Some(mint), ALICE, 0).unwrap();
        w
    }

    fn ids(entries: &[&WatchedEscrow]) -> Vec<[u8; 32]> {
        entries.iter().map(|w| w.escrow_id).collect()
    }

    #[test]
    fn insert_rejects_duplicate_ids() {
        let mut index = EscrowIndex::new();
        assert!(index.insert(funded(1, NOW + 100)));
        assert!(!index.insert(funded(1, NOW + 200)));
        assert_eq!(index.len(), 1);
        assert_eq!(index.get(&key(1)).unwrap().escrow.expires_at(), NOW + 100);
        assert!(index.verify_consistency().is_ok());
    }

    #[test]
    fn state_mint_and_expiry_buckets_file_entries() {
        let mut index = EscrowIndex::new();
        index.insert(funded(1, NOW + 100));
        index.insert(funded_with_mint(2, NOW + 200, MINT_A));
        index.insert(uninitialized_with_mint(3, NOW + 300, MINT_A));
        index.insert(cancelled(4, NOW + 400));

        assert_eq!(
            ids(&index.candidates_for_state(EscrowState::Funded)),
            vec![key(1), key(2)]
        );
        assert_eq!(
            ids(&index.candidates_for_state(EscrowState::Uninitialized)),
            vec![key(3)]
        );
        assert_eq!(
            ids(&index.candidates_for_state(EscrowState::Cancelled)),
            vec![key(4)]
        );
        assert_eq!(
            ids(&index.candidates_for_state(EscrowState::Disputed)),
            Vec::<[u8; 32]>::new()
        );
        assert_eq!(
            ids(&index.candidates_for_mint(Some(MINT_A))),
            vec![key(2), key(3)]
        );
        assert_eq!(
            ids(&index.candidates_for_mint(None)),
            vec![key(1), key(4)]
        );
        assert_eq!(
            ids(&index.candidates_for_mint(Some(MINT_B))),
            Vec::<[u8; 32]>::new()
        );
        // (after, up_to]: excludes `after` itself, includes `up_to`.
        assert_eq!(
            ids(&index.expiring_in(NOW + 100, NOW + 300)),
            vec![key(2), key(3)]
        );
        assert_eq!(ids(&index.expiring_in(NOW, NOW + 100)), vec![key(1)]);
        assert!(index.verify_consistency().is_ok());
    }

    #[test]
    fn update_refiles_across_dimensions() {
        let mut index = EscrowIndex::new();
        index.insert(funded(1, NOW + 100));
        // Same id, new state + mint + deadline: every bucket moves.
        let w = cancelled_with_mint(1, NOW + 500, MINT_B);
        assert!(index.update(w));

        assert_eq!(
            ids(&index.candidates_for_state(EscrowState::Funded)),
            Vec::<[u8; 32]>::new()
        );
        assert_eq!(
            ids(&index.candidates_for_state(EscrowState::Cancelled)),
            vec![key(1)]
        );
        assert_eq!(
            ids(&index.candidates_for_mint(Some(MINT_B))),
            vec![key(1)]
        );
        assert_eq!(
            ids(&index.candidates_for_mint(None)),
            Vec::<[u8; 32]>::new()
        );
        assert_eq!(ids(&index.expiring_in(NOW, NOW + 500)), vec![key(1)]);
        assert!(!index.update(funded(9, NOW + 1)));
        assert!(index.verify_consistency().is_ok());
    }

    #[test]
    fn remove_keeps_every_dimension_in_sync() {
        let mut index = EscrowIndex::new();
        for id in 1..=5u8 {
            index.insert(funded_with_mint(id, NOW + u64::from(id) * 10, MINT_A));
        }
        // Remove the middle entry: the last entry slides into its slot.
        let removed = index.remove(&key(3)).unwrap();
        assert_eq!(removed.escrow_id, key(3));
        assert_eq!(index.len(), 4);
        assert!(index.get(&key(3)).is_none());
        // The slid entry (id 5) is still fully indexed under its id.
        assert_eq!(index.get(&key(5)).unwrap().escrow_id, key(5));
        // Backing-store order after the swap_remove: id 5 slid into id 3's slot.
        assert_eq!(
            ids(&index.candidates_for_state(EscrowState::Funded)),
            vec![key(1), key(2), key(5), key(4)]
        );
        assert_eq!(
            ids(&index.candidates_for_mint(Some(MINT_A))),
            vec![key(1), key(2), key(5), key(4)]
        );
        assert_eq!(ids(&index.expiring_in(NOW, NOW + 100)), vec![key(1), key(2), key(5), key(4)]);
        // Remove the new last entry, then drain the rest.
        assert!(index.remove(&key(5)).is_some());
        assert!(index.remove(&key(1)).is_some());
        assert!(index.remove(&key(2)).is_some());
        assert!(index.remove(&key(4)).is_some());
        assert!(index.is_empty());
        assert!(index.remove(&key(4)).is_none());
        assert!(index.verify_consistency().is_ok());
    }

    #[test]
    fn watch_order_survives_removals() {
        let mut index = EscrowIndex::new();
        for id in [3u8, 1, 4, 1, 5, 9, 2, 6] {
            // Duplicate id 1 keeps its first occurrence.
            index.insert(funded(id, NOW + u64::from(id)));
        }
        index.remove(&key(9));
        index.remove(&key(3));
        let order: Vec<[u8; 32]> = index.iter().map(|w| w.escrow_id).collect();
        // swap_remove relocations: 6 slid into 9's slot, then 2 into 3's.
        assert_eq!(order, vec![key(2), key(1), key(4), key(5), key(6)]);
        // Queries also report in index order, not bucket-append order.
        assert_eq!(
            ids(&index.candidates_for_state(EscrowState::Funded)),
            order
        );
        assert!(index.verify_consistency().is_ok());
    }

    /// Deterministic xorshift64* — the crate stays dependency-free, so
    /// the randomized index tests roll their own RNG like the fuzz
    /// suites elsewhere in the crate.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
    }

    #[test]
    fn random_op_sequences_stay_consistent() {
        for seed in [7u64, 1234, 999983] {
            let mut rng = Rng(seed);
            let mut index = EscrowIndex::new();
            let mut live_ids: Vec<u8> = Vec::new();
            for _ in 0..300 {
                let id = (rng.next() % 24) as u8;
                match rng.next() % 4 {
                    0 => {
                        // Insert (duplicates rejected).
                        let w = if rng.next() % 2 == 0 {
                            funded_with_mint(id, NOW + rng.next() % 10_000, MINT_A)
                        } else {
                            funded(id, NOW + rng.next() % 10_000)
                        };
                        if index.insert(w) {
                            live_ids.push(id);
                        }
                    }
                    1 => {
                        // Update: new state/mint/expiry for a live id.
                        if live_ids.is_empty() {
                            continue;
                        }
                        let pick = live_ids[(rng.next() as usize) % live_ids.len()];
                        let w = match rng.next() % 3 {
                            0 => funded(pick, NOW + rng.next() % 10_000),
                            1 => cancelled(pick, NOW + rng.next() % 10_000),
                            _ => uninitialized_with_mint(pick, NOW + rng.next() % 10_000, MINT_B),
                        };
                        assert!(index.update(w));
                    }
                    2 => {
                        // Remove (unknown ids are no-ops).
                        let gone = index.remove(&key(id));
                        assert_eq!(gone.is_some(), live_ids.contains(&id));
                        live_ids.retain(|&x| x != id);
                    }
                    _ => {
                        // Read-only queries must agree with a rebuild.
                        assert!(index.verify_consistency().is_ok());
                    }
                }
            }
            assert!(index.verify_consistency().is_ok());
            // Rebuild reconciliation: an index rebuilt from the final
            // backing store answers every dimension identically.
            let rebuilt = EscrowIndex::from_watched(
                &index.iter().copied().collect::<Vec<_>>(),
            );
            for state in [
                EscrowState::Uninitialized,
                EscrowState::Funded,
                EscrowState::Cancelled,
            ] {
                assert_eq!(
                    ids(&index.candidates_for_state(state)),
                    ids(&rebuilt.candidates_for_state(state)),
                    "state bucket {:?} diverged after rebuild (seed {})",
                    state,
                    seed
                );
            }
            assert_eq!(
                ids(&index.candidates_for_mint(Some(MINT_A))),
                ids(&rebuilt.candidates_for_mint(Some(MINT_A))),
            );
            assert_eq!(
                ids(&index.expiring_in(NOW, NOW + 5_000)),
                ids(&rebuilt.expiring_in(NOW, NOW + 5_000)),
            );
        }
    }

    fn mixed_watch_list() -> Vec<WatchedEscrow> {
        vec![
            funded(1, NOW + 3600),
            funded_with_mint(2, NOW + 100, MINT_A),
            uninitialized(3, NOW + 7200),
            cancelled(4, NOW + 50),
            funded(5, NOW - 10), // already expired: AV-20's property
            funded_with_mint(6, NOW + 200, MINT_B),
            funded(7, NOW + 3600),
            cancelled(8, NOW + 9999),
        ]
    }

    #[test]
    fn indexed_keeper_scan_matches_slice_scan() {
        let watched = mixed_watch_list();
        let index = EscrowIndex::from_watched(&watched);
        let via_slice = scan_keeper_actions(&watched, NOW);
        let via_index = scan_keeper_actions_indexed(&index, NOW);
        assert_eq!(via_slice, via_index);
        // Pruning actually happened: the merge-pair pass only saw the
        // Funded bucket, not the whole list.
        assert_eq!(index.candidates_for_state(EscrowState::Funded).len(), 5);
        assert_eq!(index.len(), 8);
    }

    #[test]
    fn indexed_expiry_scan_matches_slice_scan() {
        let watched = mixed_watch_list();
        let index = EscrowIndex::from_watched(&watched);
        for window in [60u64, 500, 10_000] {
            let via_slice = scan_expiry_warnings(&watched, NOW, window);
            let via_index = scan_expiry_warnings_indexed(&index, NOW, window);
            assert_eq!(via_slice, via_index, "window {}s diverged", window);
        }
    }

    #[test]
    fn indexed_scans_agree_after_mutations() {
        let watched = mixed_watch_list();
        let mut index = EscrowIndex::from_watched(&watched);
        // A cancel moves entry 2 out of the Funded bucket; a removal
        // drops entry 4; a fresh insert adds an expiry warning.
        assert!(index.update(cancelled_with_mint(2, NOW + 100, MINT_A)));
        assert!(index.remove(&key(4)).is_some());
        assert!(index.insert(funded_with_mint(9, NOW + 30, MINT_A)));

        let live: Vec<WatchedEscrow> = index.iter().copied().collect();
        assert_eq!(
            scan_keeper_actions(&live, NOW),
            scan_keeper_actions_indexed(&index, NOW)
        );
        assert_eq!(
            scan_expiry_warnings(&live, NOW, 500),
            scan_expiry_warnings_indexed(&index, NOW, 500)
        );
        assert!(index.verify_consistency().is_ok());
    }
}
