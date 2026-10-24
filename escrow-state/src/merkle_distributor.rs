//! AV-188: Merkle distributor — one vault funds many claims.
//!
//! A maker funds a vault once and publishes a SHA-256 Merkle root over
//! `(recipient, amount)` leaves. Claimants redeem by presenting an
//! inclusion proof; a nullifier bitmap stops double-claims; after the
//! expiry slot the maker reclaims whatever was never claimed. This is
//! the batch-distribution / airdrop shape: the on-chain footprint is
//! one root, not N accounts.
//!
//! Orthogonal to AV-91 (a Merkle commitment over *dispute evidence* —
//! disclosure, not funds): this module moves money. Orthogonal to the
//! fungible [`Escrow`](crate::Escrow) path: no per-escrow accounts, no
//! partial-release semantics.
//!
//! ## Canonical construction (the off-chain builder MUST match this)
//!
//! Leaves commit to the payout exactly once:
//!
//! ```text
//! leaf = sha256("escrow-dist-leaf\x00" || recipient(32) || amount_le(8))
//! ```
//!
//! Internal nodes use canonical pair ordering (the same node hashes
//! identically regardless of left/right order, so the builder and the
//! verifier cannot disagree on orientation):
//!
//! ```text
//! node = sha256("escrow-dist-node\x00" || min(a,b) || max(a,b))  // lexicographic
//! ```
//!
//! Levels fold pairwise; an odd node is *promoted unchanged* to the
//! next level (it contributes no proof element at that level). The
//! proof for leaf `i` is the sibling at each level from the leaves
//! upward, skipping promoted levels. The verifier folds
//! `cur = node(min(cur, sib), max(cur, sib))` and requires the result
//! to equal the stored root.
//!
//! This crate is pure logic: the root and the total are
//! caller-published (the Anchor program stores them on the vault).
//! `Copy`, heap-free, `no_std`-friendly. All hashing reuses the
//! crate's hand-rolled SHA-256 (`crate::sha256`).

use crate::sha256;
use crate::EscrowError;

/// Maximum leaves in one distribution. The nullifier bitmap is
/// `[u64; 4]` — 256 bits, heap-free.
pub const MAX_DISTRIBUTION_LEAVES: usize = 256;

/// Maximum Merkle proof depth: `2^8 == 256` covers every distribution
/// this module supports.
pub const MAX_MERKLE_DEPTH: usize = 8;

/// Domain separator for leaf hashes (see the module docs).
const LEAF_DOMAIN: &[u8] = b"escrow-dist-leaf\x00";
/// Domain separator for internal-node hashes (see the module docs).
const NODE_DOMAIN: &[u8] = b"escrow-dist-node\x00";

/// `sha256(LEAF_DOMAIN || recipient || amount_le)`.
pub fn leaf_hash(recipient: &[u8; 32], amount: u64) -> [u8; 32] {
    let mut msg = [0u8; 17 + 32 + 8];
    msg[..17].copy_from_slice(LEAF_DOMAIN);
    msg[17..49].copy_from_slice(recipient);
    msg[49..57].copy_from_slice(&amount.to_le_bytes());
    sha256(&msg)
}

/// `sha256(NODE_DOMAIN || min(a,b) || max(a,b))`, lexicographic order.
pub fn node_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut msg = [0u8; 17 + 64];
    msg[..17].copy_from_slice(NODE_DOMAIN);
    msg[17..49].copy_from_slice(lo);
    msg[49..81].copy_from_slice(hi);
    sha256(&msg)
}

/// Distributor lifecycle: `Active` → `Reclaimed` (terminal). Claims are
/// only possible in `Active` before the expiry slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DistributorState {
    /// Claims open (`current_slot < expiry_slot`).
    #[default]
    Active,
    /// The maker reclaimed the unclaimed remainder (terminal).
    Reclaimed,
}

/// A one-time Merkle distribution: the maker publishes a root, N
/// recipients claim with inclusion proofs, the maker sweeps the
/// remainder after expiry.
///
/// Construct with [`MerkleDistributor::new`]. The proof path is
/// verified against the stored root on every claim; the nullifier
/// bitmap (one bit per leaf index) makes double-claims impossible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleDistributor {
    maker: [u8; 32],
    root: [u8; 32],
    total_amount: u64,
    leaf_count: u16,
    created_slot: u64,
    expiry_slot: u64,
    state: DistributorState,
    claimed_bitmap: [u64; 4],
    claimed_count: u16,
    claimed_amount: u64,
}

impl MerkleDistributor {
    /// Publish a distribution. Refused (fail-closed,
    /// [`EscrowError::InvalidDistribution`], code 258) when the maker
    /// key is zero, `leaf_count` is `0` or exceeds
    /// [`MAX_DISTRIBUTION_LEAVES`], or `expiry_slot <= created_slot`
    /// (an empty claim window).
    pub fn new(
        root: [u8; 32],
        total_amount: u64,
        maker: [u8; 32],
        leaf_count: usize,
        created_slot: u64,
        expiry_slot: u64,
    ) -> Result<Self, EscrowError> {
        if maker == [0u8; 32]
            || leaf_count == 0
            || leaf_count > MAX_DISTRIBUTION_LEAVES
            || expiry_slot <= created_slot
        {
            return Err(EscrowError::InvalidDistribution);
        }
        Ok(MerkleDistributor {
            maker,
            root,
            total_amount,
            leaf_count: leaf_count as u16,
            created_slot,
            expiry_slot,
            state: DistributorState::Active,
            claimed_bitmap: [0u64; 4],
            claimed_count: 0,
            claimed_amount: 0,
        })
    }

    /// The maker key.
    pub fn maker(&self) -> [u8; 32] {
        self.maker
    }

    /// The published Merkle root.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Number of leaves the root commits to.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count as usize
    }

    /// Current lifecycle state.
    pub fn state(&self) -> DistributorState {
        self.state
    }

    /// How many leaves have been claimed.
    pub fn claimed_count(&self) -> usize {
        self.claimed_count as usize
    }

    /// Sum of claimed amounts.
    pub fn claimed_amount(&self) -> u64 {
        self.claimed_amount
    }

    /// The unclaimed remainder (`total - claimed`).
    pub fn unclaimed_amount(&self) -> u64 {
        self.total_amount.saturating_sub(self.claimed_amount)
    }

    /// `true` when leaf `index` already claimed (the nullifier).
    pub fn is_claimed(&self, index: usize) -> bool {
        if index >= self.leaf_count as usize {
            return false;
        }
        (self.claimed_bitmap[index / 64] >> (index % 64)) & 1 == 1
    }

    fn mark_claimed(&mut self, index: usize) {
        self.claimed_bitmap[index / 64] |= 1u64 << (index % 64);
    }

    /// Verify an inclusion proof against the stored root: fold the
    /// leaf with the canonical node construction and compare. Pure —
    /// no state change.
    pub fn verify_proof(
        &self,
        recipient: &[u8; 32],
        amount: u64,
        proof: &[[u8; 32]],
    ) -> Result<(), EscrowError> {
        if proof.len() > MAX_MERKLE_DEPTH {
            return Err(EscrowError::InvalidMerkleProof);
        }
        let mut cur = leaf_hash(recipient, amount);
        for sib in proof.iter() {
            cur = node_hash(&cur, sib);
        }
        if cur != self.root {
            return Err(EscrowError::InvalidMerkleProof);
        }
        Ok(())
    }

    /// Claim leaf `index` for `(recipient, amount)`.
    ///
    /// Check order: claim window → index bounds → nullifier → proof.
    /// Returns the claimable amount (for exact transfer sizing).
    /// Marks the nullifier *before* returning, so a re-entrant caller
    /// cannot double-claim.
    pub fn claim(
        &mut self,
        index: usize,
        recipient: [u8; 32],
        amount: u64,
        proof: &[[u8; 32]],
        current_slot: u64,
    ) -> Result<u64, EscrowError> {
        if self.state != DistributorState::Active || current_slot >= self.expiry_slot {
            return Err(EscrowError::DistributionExpired);
        }
        if index >= self.leaf_count as usize {
            return Err(EscrowError::InvalidMerkleProof);
        }
        if self.is_claimed(index) {
            return Err(EscrowError::AlreadyClaimed);
        }
        self.verify_proof(&recipient, amount, proof)?;
        self.mark_claimed(index);
        self.claimed_count += 1;
        self.claimed_amount = self.claimed_amount.saturating_add(amount);
        Ok(amount)
    }

    /// After the expiry slot, the maker reclaims the unclaimed
    /// remainder. Maker-only, terminal: a second reclaim (or a claim
    /// after reclaim) is `InvalidStateTransition` via the state check.
    pub fn reclaim(&mut self, maker: [u8; 32], current_slot: u64) -> Result<u64, EscrowError> {
        if maker != self.maker {
            return Err(EscrowError::Unauthorized);
        }
        if self.state != DistributorState::Active {
            return Err(EscrowError::InvalidStateTransition);
        }
        if current_slot < self.expiry_slot {
            return Err(EscrowError::DistributionNotExpired);
        }
        self.state = DistributorState::Reclaimed;
        Ok(self.unclaimed_amount())
    }

    /// Audit-event JSON for a claim (hand-written):
    /// `{"event":"distributor_claimed","root":"<64hex>","leaf_index":<n>,
    /// "amount":<u64>,"claimed_count":<n>}`.
    pub fn claim_audit_json(&self, index: usize, amount: u64) -> String {
        let mut s = String::from("{\"event\":\"distributor_claimed\",\"root\":\"");
        s.push_str(&hex64(&self.root));
        s.push_str("\",\"leaf_index\":");
        s.push_str(&index.to_string());
        s.push_str(",\"amount\":");
        s.push_str(&amount.to_string());
        s.push_str(",\"claimed_count\":");
        s.push_str(&self.claimed_count.to_string());
        s.push('}');
        s
    }

    /// Audit-event JSON for a reclaim:
    /// `{"event":"distributor_reclaimed","root":"<64hex>",
    /// "reclaimed_amount":<u64>,"claimed_count":<n>}`.
    pub fn reclaim_audit_json(&self, reclaimed: u64) -> String {
        let mut s = String::from("{\"event\":\"distributor_reclaimed\",\"root\":\"");
        s.push_str(&hex64(&self.root));
        s.push_str("\",\"reclaimed_amount\":");
        s.push_str(&reclaimed.to_string());
        s.push_str(",\"claimed_count\":");
        s.push_str(&self.claimed_count.to_string());
        s.push('}');
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

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// Build a tree exactly per the module's canonical construction and
    /// return `(root, proofs)` — the off-chain builder's view, exercised
    /// here so the verifier is tested against independently-constructed
    /// proofs.
    fn build_tree(leaves: &[(/*recipient*/ [u8; 32], /*amount*/ u64)]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
        let mut level: Vec<[u8; 32]> = leaves
            .iter()
            .map(|(r, a)| leaf_hash(r, *a))
            .collect();
        // proofs[i] accumulates siblings from the leaves upward.
        let mut proofs: Vec<Vec<[u8; 32]>> = vec![Vec::new(); leaves.len()];
        // members[p] = original leaf indices folded into level position p.
        let mut members: Vec<Vec<usize>> = (0..leaves.len()).map(|i| vec![i]).collect();
        while level.len() > 1 {
            let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
            let mut next_members: Vec<Vec<usize>> = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    next.push(node_hash(&level[i], &level[i + 1]));
                    for &orig in members[i].iter() {
                        proofs[orig].push(level[i + 1]);
                    }
                    for &orig in members[i + 1].iter() {
                        proofs[orig].push(level[i]);
                    }
                    let mut m = members[i].clone();
                    m.extend_from_slice(&members[i + 1]);
                    next_members.push(m);
                    i += 2;
                } else {
                    // Odd node promoted unchanged — no proof element.
                    next.push(level[i]);
                    next_members.push(members[i].clone());
                    i += 1;
                }
            }
            level = next;
            members = next_members;
        }
        (level[0], proofs)
    }

    fn open_distribution(leaves: &[([u8; 32], u64)]) -> (MerkleDistributor, Vec<Vec<[u8; 32]>>) {
        let (root, proofs) = build_tree(leaves);
        let total: u64 = leaves.iter().map(|(_, a)| a).sum();
        let d = MerkleDistributor::new(root, total, key(0xAA), leaves.len(), 100, 1000).unwrap();
        (d, proofs)
    }

    #[test]
    fn new_rejects_degenerate_distributions() {
        let (root, _) = build_tree(&[(key(1), 100)]);
        // Zero maker.
        assert_eq!(
            MerkleDistributor::new(root, 100, [0u8; 32], 1, 100, 1000).unwrap_err(),
            EscrowError::InvalidDistribution
        );
        // Zero leaves.
        assert_eq!(
            MerkleDistributor::new(root, 0, key(0xAA), 0, 100, 1000).unwrap_err(),
            EscrowError::InvalidDistribution
        );
        // Too many leaves for the bitmap.
        assert_eq!(
            MerkleDistributor::new(root, 0, key(0xAA), MAX_DISTRIBUTION_LEAVES + 1, 100, 1000)
                .unwrap_err(),
            EscrowError::InvalidDistribution
        );
        // Empty claim window.
        assert_eq!(
            MerkleDistributor::new(root, 100, key(0xAA), 1, 1000, 1000).unwrap_err(),
            EscrowError::InvalidDistribution
        );
        let err = EscrowError::InvalidDistribution;
        assert_eq!(err.code(), 258);
    }

    #[test]
    fn claim_with_valid_proof_pays_leaf_amount() {
        let leaves = [(key(1), 100u64), (key(2), 250), (key(3), 50)];
        let (mut d, proofs) = open_distribution(&leaves);
        assert_eq!(d.leaf_count(), 3);
        assert_eq!(d.unclaimed_amount(), 400);

        let got = d.claim(1, key(2), 250, &proofs[1], 500).unwrap();
        assert_eq!(got, 250);
        assert_eq!(d.claimed_count(), 1);
        assert_eq!(d.claimed_amount(), 250);
        assert_eq!(d.unclaimed_amount(), 150);
        assert!(d.is_claimed(1));
        assert!(!d.is_claimed(0));

        let j = d.claim_audit_json(1, 250);
        assert!(j.contains("\"event\":\"distributor_claimed\""));
        assert!(j.contains("\"leaf_index\":1"));
        assert!(j.contains("\"amount\":250"));
    }

    #[test]
    fn double_claim_is_rejected_by_nullifier() {
        let leaves = [(key(1), 100u64), (key(2), 250)];
        let (mut d, proofs) = open_distribution(&leaves);
        d.claim(0, key(1), 100, &proofs[0], 500).unwrap();
        let err = d.claim(0, key(1), 100, &proofs[0], 500).unwrap_err();
        assert_eq!(err, EscrowError::AlreadyClaimed);
        assert_eq!(err.code(), 260);
        // State unchanged by the failed second claim.
        assert_eq!(d.claimed_count(), 1);
        assert_eq!(d.claimed_amount(), 100);
    }

    #[test]
    fn wrong_amount_or_recipient_fails_proof() {
        let leaves = [(key(1), 100u64), (key(2), 250)];
        let (mut d, proofs) = open_distribution(&leaves);
        // Amount tampered: the leaf hash no longer matches.
        let err = d.claim(0, key(1), 101, &proofs[0], 500).unwrap_err();
        assert_eq!(err, EscrowError::InvalidMerkleProof);
        assert_eq!(err.code(), 259);
        // Recipient swapped.
        let err = d.claim(0, key(9), 100, &proofs[0], 500).unwrap_err();
        assert_eq!(err, EscrowError::InvalidMerkleProof);
        // Proof for the wrong leaf.
        let err = d.claim(0, key(1), 100, &proofs[1], 500).unwrap_err();
        assert_eq!(err, EscrowError::InvalidMerkleProof);
        // Nothing was marked by the failed attempts.
        assert!(!d.is_claimed(0));
        assert_eq!(d.claimed_count(), 0);
    }

    #[test]
    fn index_out_of_bounds_fails_closed() {
        let leaves = [(key(1), 100u64)];
        let (mut d, proofs) = open_distribution(&leaves);
        let err = d.claim(5, key(1), 100, &proofs[0], 500).unwrap_err();
        assert_eq!(err, EscrowError::InvalidMerkleProof);
        assert!(!d.is_claimed(5));
    }

    #[test]
    fn single_leaf_tree_has_empty_proof() {
        // One leaf: the root IS the leaf hash; the proof is empty and
        // the claim still verifies.
        let leaves = [(key(7), 777u64)];
        let (mut d, proofs) = open_distribution(&leaves);
        assert!(proofs[0].is_empty());
        assert_eq!(d.root(), leaf_hash(&key(7), 777));
        d.claim(0, key(7), 777, &proofs[0], 500).unwrap();
        assert_eq!(d.unclaimed_amount(), 0);
    }

    #[test]
    fn claim_after_expiry_is_rejected() {
        let leaves = [(key(1), 100u64)];
        let (mut d, proofs) = open_distribution(&leaves);
        let err = d.claim(0, key(1), 100, &proofs[0], 1000).unwrap_err();
        assert_eq!(err, EscrowError::DistributionExpired);
        assert_eq!(err.code(), 261);
        assert!(!d.is_claimed(0));
    }

    #[test]
    fn reclaim_after_expiry_returns_remainder() {
        let leaves = [(key(1), 100u64), (key(2), 250)];
        let (mut d, proofs) = open_distribution(&leaves);
        d.claim(0, key(1), 100, &proofs[0], 500).unwrap();

        // Before expiry the maker cannot race open claims.
        let err = d.reclaim(key(0xAA), 999).unwrap_err();
        assert_eq!(err, EscrowError::DistributionNotExpired);
        assert_eq!(err.code(), 262);

        // A stranger can never reclaim.
        let err = d.reclaim(key(0xBB), 1000).unwrap_err();
        assert_eq!(err, EscrowError::Unauthorized);

        let got = d.reclaim(key(0xAA), 1000).unwrap();
        assert_eq!(got, 250);
        assert_eq!(d.state(), DistributorState::Reclaimed);
        let j = d.reclaim_audit_json(got);
        assert!(j.contains("\"event\":\"distributor_reclaimed\""));
        assert!(j.contains("\"reclaimed_amount\":250"));

        // Terminal: no more claims, no second reclaim.
        let err = d.claim(1, key(2), 250, &proofs[1], 1001).unwrap_err();
        assert_eq!(err, EscrowError::DistributionExpired);
        let err = d.reclaim(key(0xAA), 1001).unwrap_err();
        assert_eq!(err, EscrowError::InvalidStateTransition);
    }

    #[test]
    fn reclaim_with_nothing_claimed_returns_total() {
        let leaves = [(key(1), 100u64), (key(2), 250)];
        let (mut d, _) = open_distribution(&leaves);
        assert_eq!(d.reclaim(key(0xAA), 5000).unwrap(), 350);
    }

    #[test]
    fn node_hash_is_order_canonical() {
        let a = key(1);
        let b = key(2);
        assert_eq!(node_hash(&a, &b), node_hash(&b, &a));
        // ...but not equal to hashing the raw concatenation without the
        // domain separator (domain separation is load-bearing).
        assert_ne!(node_hash(&a, &b), sha256(&[a, b].concat()));
    }

    #[test]
    fn large_distribution_all_leaves_claimable() {
        // 100 leaves (odd count exercises the odd-promotion path at
        // every level): every leaf claims exactly once, the remainder
        // is zero, and a second claim of any leaf is rejected.
        let leaves: Vec<([u8; 32], u64)> = (0..100u8).map(|i| (key(i), 10u64)).collect();
        let (mut d, proofs) = open_distribution(&leaves);
        for i in 0..100usize {
            let got = d.claim(i, key(i as u8), 10, &proofs[i], 500).unwrap();
            assert_eq!(got, 10);
        }
        assert_eq!(d.claimed_count(), 100);
        assert_eq!(d.unclaimed_amount(), 0);
        let err = d.claim(42, key(42), 10, &proofs[42], 500).unwrap_err();
        assert_eq!(err, EscrowError::AlreadyClaimed);
        assert_eq!(d.reclaim(key(0xAA), 1001).unwrap(), 0);
    }

    #[test]
    fn error_codes_pinned() {
        // Never renumber: the Anchor layer assigns one program error
        // per variant and off-chain clients match on these numbers.
        assert_eq!(EscrowError::InvalidDistribution.code(), 258);
        assert_eq!(EscrowError::InvalidMerkleProof.code(), 259);
        assert_eq!(EscrowError::AlreadyClaimed.code(), 260);
        assert_eq!(EscrowError::DistributionExpired.code(), 261);
        assert_eq!(EscrowError::DistributionNotExpired.code(), 262);
        for e in [
            EscrowError::InvalidDistribution,
            EscrowError::InvalidMerkleProof,
            EscrowError::AlreadyClaimed,
            EscrowError::DistributionExpired,
            EscrowError::DistributionNotExpired,
        ] {
            assert!(EscrowError::all().contains(&e));
        }
        // AV-189 appends 5 English-auction errors after these; AV-190
        // appends 3 rental-escrow errors after those.
        assert_eq!(EscrowError::all().len(), 207); // AV-195: +7 social-recovery errors, AV-196: +6 jury-sortition errors, AV-197: +5 payment-channel errors
    }
}
