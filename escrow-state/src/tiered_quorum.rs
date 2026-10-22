//! AV-178: amount-tiered attestor quorum — the release amount selects the
//! attestor weight threshold.
//!
//! A [`TieredQuorum`] wraps the AV-04 [`QuorumPolicy`] (the weighted
//! attestor registry and its accumulated votes) with a configurable tier
//! table: a release amount falls into exactly one tier, and that tier's
//! weight-sum threshold is what the release must reach. Small releases
//! clear with a light quorum (e.g. 1-of-N weight), large releases demand
//! the full panel (N-of-N weight) — the payment-risk pattern: low-value
//! payouts stay fast while high-value payouts harden into multi-sig
//! (Solana governance / payment risk control).
//!
//! Design notes:
//!
//! - The tier table is *config*, fixed before funding like the wrapped
//!   policy ([`Escrow::with_tiered_quorum`](crate::Escrow::with_tiered_quorum)
//!   is `Uninitialized`-only). Attestations keep accumulating on the
//!   wrapped AV-04 policy across transactions, exactly as before; only
//!   the *required* threshold varies with the release amount.
//! - Tier ceilings must be strictly increasing and the top tier is
//!   open-ended (`u64::MAX`), so every amount lands in exactly one tier —
//!   there is no "falls through the table" case.
//! - Thresholds must be non-decreasing with the amount (monotonicity,
//!   enforced at construction): a larger release can never demand less
//!   attestor weight than a smaller one. Each threshold must also be a
//!   reachable weight sum (`1..=total_weight` of the wrapped policy).
//! - The type is fixed-size and `Copy` (no heap), so it persists in the
//!   vault account tail like the other optional config. The release
//!   guard chain keeps its order — authority, then state, then the
//!   tiered-quorum gate — the tiered check sits exactly where the plain
//!   quorum check sat.
//! - A tiered quorum and a plain AV-04 quorum are mutually exclusive on
//!   one escrow ([`Escrow::with_quorum`](crate::Escrow::with_quorum)
//!   refuses a tiered escrow and vice versa); [`Escrow::attest`] routes
//!   votes to whichever is configured.

use super::{EscrowError, QuorumPolicy, QUORUM_POLICY_LEN};

/// Maximum number of amount tiers in a [`TieredQuorum`]. Fixed-size so
/// the type stays heap-free and `Copy`, like [`QuorumPolicy`] itself.
pub const MAX_TIERS: usize = 4;

/// Serialized length of a [`TieredQuorum`]: the wrapped AV-04
/// [`QuorumPolicy`] bytes, then the `MAX_TIERS` tier slots (an 8-byte
/// amount ceiling plus an 8-byte weight threshold each), then the live
/// tier-count byte.
pub const TIERED_QUORUM_LEN: usize = QUORUM_POLICY_LEN + MAX_TIERS * 16 + 1;

/// One amount tier: a release of `amount <= max_amount` must reach the
/// `threshold` attestor-weight sum. Tiers are ordered by ascending
/// `max_amount`; the top tier's `max_amount` is `u64::MAX` so every
/// amount lands in exactly one tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tier {
    /// Inclusive amount ceiling of this tier, in base units.
    pub max_amount: u64,
    /// Weight-sum threshold for releases landing in this tier. Must be
    /// non-decreasing across tiers (validated at construction).
    pub threshold: u64,
}

/// Amount-tiered wrapper around the AV-04 [`QuorumPolicy`].
///
/// The wrapped policy owns the attestor registry and the accumulated
/// votes; the tier table only selects *which* weight-sum threshold a
/// given release amount must reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TieredQuorum {
    // `pub(crate)`: the structural decoder (`discriminator`) rebuilds
    // the value field-by-field like it does for the AV-04 policy; the
    // public interface stays the accessors below plus `TieredQuorum::new`.
    pub(crate) base: QuorumPolicy,
    pub(crate) tiers: [Tier; MAX_TIERS],
    pub(crate) tier_count: u8,
}

impl TieredQuorum {
    /// Build a tiered quorum over `base` with the given tier table.
    ///
    /// Rejects with [`EscrowError::InvalidQuorum`] when the table is
    /// empty or longer than [`MAX_TIERS`], the amount ceilings are not
    /// strictly increasing, the top tier is not open-ended
    /// (`u64::MAX`), the thresholds are not non-decreasing with the
    /// amount, or any threshold is zero or larger than the wrapped
    /// policy's total attestor weight (an unreachable threshold would
    /// lock funds behind an unsatisfiable gate).
    pub fn new(base: QuorumPolicy, tiers: &[Tier]) -> Result<Self, EscrowError> {
        if tiers.is_empty() || tiers.len() > MAX_TIERS {
            return Err(EscrowError::InvalidQuorum);
        }
        let total_weight = base.total_weight();
        let mut prev_ceiling: Option<u64> = None;
        let mut prev_threshold: u64 = 0;
        for tier in tiers {
            // Strictly increasing ceilings: the tiers partition the
            // amount line with no gaps and no overlaps.
            if let Some(prev) = prev_ceiling {
                if tier.max_amount <= prev {
                    return Err(EscrowError::InvalidQuorum);
                }
            }
            // Monotonicity: a larger release never demands less
            // attestor weight than a smaller one.
            if tier.threshold < prev_threshold {
                return Err(EscrowError::InvalidQuorum);
            }
            // Reachability: the threshold is a weight sum over the
            // wrapped policy's registered attestors, so it must lie in
            // `1..=total_weight` — checked in u64, no wrapping.
            if tier.threshold == 0 || tier.threshold > total_weight {
                return Err(EscrowError::InvalidQuorum);
            }
            prev_ceiling = Some(tier.max_amount);
            prev_threshold = tier.threshold;
        }
        // Open-ended top tier: no amount falls through the table.
        if prev_ceiling != Some(u64::MAX) {
            return Err(EscrowError::InvalidQuorum);
        }
        let mut table = [Tier { max_amount: 0, threshold: 0 }; MAX_TIERS];
        table[..tiers.len()].copy_from_slice(tiers);
        Ok(Self {
            base,
            tiers: table,
            tier_count: tiers.len() as u8,
        })
    }

    /// The weight-sum threshold a release of `amount` must reach: the
    /// first tier whose ceiling covers the amount.
    ///
    /// Panic-free on any in-memory value (AV-32): the live tier count
    /// is clamped to [`MAX_TIERS`], and a value with no live tier
    /// degrades to the wrapped policy's own threshold (fail-closed).
    pub fn threshold_for(&self, amount: u64) -> u64 {
        let live = self.live_tier_count();
        for tier in &self.tiers[..live] {
            if amount <= tier.max_amount {
                return tier.threshold;
            }
        }
        // Unreachable for well-formed values (the top tier is
        // open-ended, `u64::MAX`): degrade to the strictest live tier.
        debug_assert!(live > 0, "tiered quorum: no live tiers");
        if live == 0 {
            return self.base.threshold();
        }
        self.tiers[live - 1].threshold
    }

    /// True once the wrapped policy's accumulated attestor weight
    /// reaches the tier threshold for `amount`.
    pub fn is_satisfied_for(&self, amount: u64) -> bool {
        self.base.approved_weight() >= self.threshold_for(amount)
    }

    /// Record an attestation on the wrapped AV-04 policy. Idempotent:
    /// repeat attestations by the same attestor count once; callers
    /// outside the registered set get `Unauthorized` — the exact
    /// [`QuorumPolicy::attest`] semantics, since this delegates to it.
    pub fn attest(&mut self, attestor: [u8; 32]) -> Result<(), EscrowError> {
        self.base.attest(attestor)
    }

    /// The wrapped AV-04 policy: the attestor registry and the
    /// accumulated votes.
    pub fn base(&self) -> &QuorumPolicy {
        &self.base
    }

    /// The configured tier table, in ascending ceiling order.
    pub fn tiers(&self) -> &[Tier] {
        &self.tiers[..self.live_tier_count()]
    }

    /// Number of configured tiers.
    pub fn tier_count(&self) -> u8 {
        self.tier_count
    }

    /// Live tier slots, clamped to [`MAX_TIERS`] so a corrupt
    /// in-memory count can never make an accessor read past the
    /// fixed table (AV-32 panic-free guarantee).
    fn live_tier_count(&self) -> usize {
        (self.tier_count as usize).min(MAX_TIERS)
    }

    /// Borsh-order byte encoding used by the vault test mirror
    /// (`encode_escrow` in the crate's account-space tests): the wrapped
    /// policy's bytes (the exact AV-45 field order), then the tier
    /// slots, then the tier-count byte. Exactly [`TIERED_QUORUM_LEN`]
    /// bytes — the `1 + TIERED_QUORUM_LEN` vault tail adds the `Option`
    /// discriminant on top.
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        for attestor in self.base.attestors.iter() {
            out.extend_from_slice(attestor);
        }
        for weight in self.base.weights.iter() {
            out.extend_from_slice(&weight.to_le_bytes());
        }
        out.push(self.base.registered);
        out.extend_from_slice(&self.base.threshold.to_le_bytes());
        out.extend_from_slice(&self.base.approvals.to_le_bytes());
        for tier in self.tiers.iter() {
            out.extend_from_slice(&tier.max_amount.to_le_bytes());
            out.extend_from_slice(&tier.threshold.to_le_bytes());
        }
        out.push(self.tier_count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attestor(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn base_policy() -> QuorumPolicy {
        // 3 attestors, weight 1 each: total weight 3.
        QuorumPolicy::new(&[attestor(1), attestor(2), attestor(3)], &[1, 1, 1], 1).unwrap()
    }

    fn two_tiers() -> Vec<Tier> {
        vec![
            Tier { max_amount: 1_000, threshold: 1 },
            Tier { max_amount: u64::MAX, threshold: 3 },
        ]
    }

    #[test]
    fn threshold_for_selects_tier_by_amount() {
        let tq = TieredQuorum::new(base_policy(), &two_tiers()).unwrap();
        assert_eq!(tq.threshold_for(0), 1);
        assert_eq!(tq.threshold_for(1_000), 1);
        assert_eq!(tq.threshold_for(1_001), 3);
        assert_eq!(tq.threshold_for(u64::MAX), 3);
    }

    #[test]
    fn is_satisfied_for_uses_tier_threshold() {
        let mut tq = TieredQuorum::new(base_policy(), &two_tiers()).unwrap();
        // No votes: nothing is satisfied.
        assert!(!tq.is_satisfied_for(100));
        assert!(!tq.is_satisfied_for(5_000));
        // One attestor (weight 1): the small tier clears, the large tier
        // still waits for the full panel.
        tq.attest(attestor(1)).unwrap();
        assert!(tq.is_satisfied_for(100));
        assert!(!tq.is_satisfied_for(5_000));
        // Full panel: every tier clears.
        tq.attest(attestor(2)).unwrap();
        tq.attest(attestor(3)).unwrap();
        assert!(tq.is_satisfied_for(100));
        assert!(tq.is_satisfied_for(5_000));
    }

    #[test]
    fn attest_delegates_base_semantics() {
        let mut tq = TieredQuorum::new(base_policy(), &two_tiers()).unwrap();
        // Idempotent: the repeat vote counts once.
        tq.attest(attestor(1)).unwrap();
        tq.attest(attestor(1)).unwrap();
        assert_eq!(tq.base().approval_count(), 1);
        // Unknown attestor is Unauthorized.
        assert_eq!(tq.attest(attestor(9)), Err(EscrowError::Unauthorized));
    }

    #[test]
    fn rejects_empty_and_oversized_tables() {
        assert_eq!(
            TieredQuorum::new(base_policy(), &[]),
            Err(EscrowError::InvalidQuorum)
        );
        let five = vec![Tier { max_amount: u64::MAX, threshold: 1 }; 5];
        assert_eq!(
            TieredQuorum::new(base_policy(), &five),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn rejects_non_increasing_ceilings() {
        // Equal ceilings overlap.
        let dup = vec![
            Tier { max_amount: 1_000, threshold: 1 },
            Tier { max_amount: 1_000, threshold: 2 },
            Tier { max_amount: u64::MAX, threshold: 3 },
        ];
        assert_eq!(
            TieredQuorum::new(base_policy(), &dup),
            Err(EscrowError::InvalidQuorum)
        );
        // Decreasing ceilings leave a gap.
        let gap = vec![
            Tier { max_amount: 2_000, threshold: 1 },
            Tier { max_amount: 1_000, threshold: 2 },
            Tier { max_amount: u64::MAX, threshold: 3 },
        ];
        assert_eq!(
            TieredQuorum::new(base_policy(), &gap),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn rejects_non_monotonic_thresholds() {
        // A larger release demanding less weight is a downgrade attack
        // on the risk model.
        let decreasing = vec![
            Tier { max_amount: 1_000, threshold: 2 },
            Tier { max_amount: u64::MAX, threshold: 1 },
        ];
        assert_eq!(
            TieredQuorum::new(base_policy(), &decreasing),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn rejects_unreachable_thresholds() {
        // Zero threshold: vacuous gate.
        let zero = vec![
            Tier { max_amount: 1_000, threshold: 0 },
            Tier { max_amount: u64::MAX, threshold: 3 },
        ];
        assert_eq!(
            TieredQuorum::new(base_policy(), &zero),
            Err(EscrowError::InvalidQuorum)
        );
        // Above the total registered weight: unsatisfiable, funds would
        // lock forever.
        let too_high = vec![
            Tier { max_amount: 1_000, threshold: 1 },
            Tier { max_amount: u64::MAX, threshold: 4 },
        ];
        assert_eq!(
            TieredQuorum::new(base_policy(), &too_high),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn rejects_table_without_open_ended_top_tier() {
        // An amount above the top ceiling would fall through the table.
        let capped = vec![
            Tier { max_amount: 1_000, threshold: 1 },
            Tier { max_amount: 2_000, threshold: 3 },
        ];
        assert_eq!(
            TieredQuorum::new(base_policy(), &capped),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn single_tier_open_ended_is_valid() {
        let one = vec![Tier { max_amount: u64::MAX, threshold: 2 }];
        let tq = TieredQuorum::new(base_policy(), &one).unwrap();
        assert_eq!(tq.tier_count(), 1);
        assert_eq!(tq.threshold_for(0), 2);
        assert_eq!(tq.threshold_for(u64::MAX), 2);
    }

    #[test]
    fn encode_into_is_tiered_quorum_len_bytes() {
        let tq = TieredQuorum::new(base_policy(), &two_tiers()).unwrap();
        let mut out = Vec::new();
        tq.encode_into(&mut out);
        assert_eq!(out.len(), TIERED_QUORUM_LEN);
        // Tail layout: tier slots then the tier-count byte.
        let tail = &out[QUORUM_POLICY_LEN..];
        assert_eq!(u64::from_le_bytes(tail[0..8].try_into().unwrap()), 1_000);
        assert_eq!(u64::from_le_bytes(tail[8..16].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_le_bytes(tail[16..24].try_into().unwrap()),
            u64::MAX
        );
        assert_eq!(u64::from_le_bytes(tail[24..32].try_into().unwrap()), 3);
        assert_eq!(tail[MAX_TIERS * 16], 2);
    }
}
