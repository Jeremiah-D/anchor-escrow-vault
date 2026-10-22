//! AV-183: governance-token-weighted voting — attestor weights derived
//! from a frozen token-balance snapshot.
//!
//! A [`TokenWeightSnapshot`] builds a [`QuorumPolicy`] whose per-attestor
//! weights are governance token balances read at a fixed chain slot,
//! with the release threshold expressed in basis points (e.g. 6667 for
//! a two-thirds supermajority). The snapshot is frozen at construction:
//! [`Escrow::with_token_weighted_voting`](crate::Escrow::with_token_weighted_voting)
//! is `Uninitialized`-only, and no API mutates a weight afterwards — so
//! a flash loan taken after the snapshot cannot inflate anyone's voting
//! power. That is the whole defense: weights are never re-read from
//! token accounts, they are fixed numbers in the escrow config.
//!
//! Relation to the existing quorum machinery: AV-04/AV-45 already made
//! [`QuorumPolicy`] weight-based (per-attestor `u64` weights, a
//! weight-sum threshold); AV-178 wrapped it with amount tiers. This
//! module does not change the gating — it changes where the weights
//! come from: token balances with a frozen snapshot, instead of
//! operator-chosen constants. The release gate stays
//! [`QuorumPolicy::is_satisfied`] (weight sum `>=` threshold), so
//! `release` needs no modification.
//!
//! Orthogonal to [`TieredQuorum`](super::TieredQuorum) (AV-178, the
//! amount dimension): this module is the weight-source dimension. One
//! escrow uses one release gate — the builders are mutually exclusive.
//!
//! Audit: the snapshot exports to canonical JSON via
//! [`TokenWeightSnapshot::to_json`] (every attestor, its frozen
//! balance-weight, the bps threshold, the snapshot slot) for the
//! off-chain governance audit trail. On-chain, the derived policy's
//! frozen weights ride the escrow's quorum slot and are disclosed to
//! indexers through the existing quorum snapshot (`threshold`,
//! `total_weight`, `approved_weight`).

use super::{EscrowError, QuorumPolicy, MAX_ATTESTORS};

/// Basis-points denominator for [`TokenWeightSnapshot`] thresholds:
/// 10_000 bps = unanimity, 6667 ≈ two-thirds.
pub const BPS_DENOMINATOR: u16 = 10_000;

/// Governance-token-weighted voting configuration: a frozen weight
/// snapshot plus its provenance.
///
/// The snapshot is `Copy` and immutable — freezing is structural, not a
/// runtime check: there is no API that changes a weight after
/// construction, and the escrow builder only accepts the snapshot on an
/// `Uninitialized` escrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenWeightSnapshot {
    policy: QuorumPolicy,
    /// Release threshold in basis points of the total frozen weight.
    threshold_bps: u16,
    /// Chain slot the balances were read at — the snapshot's provenance
    /// for the off-chain audit trail.
    snapshot_slot: u64,
}

impl TokenWeightSnapshot {
    /// Freeze a token-balance weight snapshot.
    ///
    /// `attestors` and `balances` are parallel slices: attestor `i`
    /// votes with weight `balances[i]`, the governance token balance
    /// read at `snapshot_slot`. The release threshold is
    /// `ceil(threshold_bps / 10_000 * total)`.
    ///
    /// Rejects with [`EscrowError::InvalidQuorum`] when `threshold_bps`
    /// is 0 or above 10_000, the lists are empty or longer than
    /// [`MAX_ATTESTORS`], their lengths mismatch, a key is duplicated or
    /// zero, any balance is zero (a zero-balance attestor has no voting
    /// power — registering one is always a misconfiguration), or the
    /// balances' sum overflows the `u64` weight domain.
    pub fn new(
        attestors: &[[u8; 32]],
        balances: &[u64],
        threshold_bps: u16,
        snapshot_slot: u64,
    ) -> Result<Self, EscrowError> {
        if threshold_bps == 0 || threshold_bps > BPS_DENOMINATOR {
            return Err(EscrowError::InvalidQuorum);
        }
        if attestors.is_empty() || attestors.len() > MAX_ATTESTORS {
            return Err(EscrowError::InvalidQuorum);
        }
        if balances.len() != attestors.len() {
            return Err(EscrowError::InvalidQuorum);
        }
        // Accumulate in u128 (checked): the frozen total must fit the
        // u64 weight domain, so an unrepresentable voting supply is
        // rejected up front rather than wrapping mid-tally.
        let mut total: u128 = 0;
        for (i, (attestor, balance)) in attestors.iter().zip(balances.iter()).enumerate() {
            if attestors[..i].contains(attestor) {
                return Err(EscrowError::InvalidQuorum);
            }
            if *attestor == [0u8; 32] {
                return Err(EscrowError::InvalidQuorum);
            }
            if *balance == 0 {
                return Err(EscrowError::InvalidQuorum);
            }
            total = total
                .checked_add(*balance as u128)
                .ok_or(EscrowError::InvalidQuorum)?;
        }
        let total_weight =
            u64::try_from(total).map_err(|_| EscrowError::InvalidQuorum)?;
        // Ceiling division in u128: the threshold always lands in
        // `1..=total_weight` (reachable — a snapshot can never lock
        // funds behind an unsatisfiable gate), and 10_000 bps is
        // exactly unanimity.
        let threshold = (threshold_bps as u128 * total + (BPS_DENOMINATOR as u128 - 1))
            / BPS_DENOMINATOR as u128;
        let threshold = u64::try_from(threshold).map_err(|_| EscrowError::InvalidQuorum)?;
        debug_assert!((1..=total_weight).contains(&threshold));
        let policy = QuorumPolicy::new(attestors, balances, threshold)?;
        Ok(Self {
            policy,
            threshold_bps,
            snapshot_slot,
        })
    }

    /// The derived voting policy: frozen balance weights with the
    /// bps-derived weight-sum threshold. Stored in the escrow's quorum
    /// slot by `Escrow::with_token_weighted_voting`.
    pub fn policy(&self) -> QuorumPolicy {
        self.policy
    }

    /// Release threshold in basis points (e.g. 6667 ≈ two-thirds).
    pub fn threshold_bps(&self) -> u16 {
        self.threshold_bps
    }

    /// Chain slot the balances were read at.
    pub fn snapshot_slot(&self) -> u64 {
        self.snapshot_slot
    }

    /// Total frozen voting weight (the balances' sum).
    pub fn total_weight(&self) -> u64 {
        self.policy.total_weight()
    }

    /// The derived weight-sum release threshold.
    pub fn threshold(&self) -> u64 {
        self.policy.threshold()
    }

    /// Frozen weight of one attestor, `None` when unregistered.
    pub fn weight_of(&self, attestor: [u8; 32]) -> Option<u64> {
        let idx = self
            .policy
            .attestors()
            .iter()
            .position(|a| *a == attestor)?;
        Some(self.policy.weights()[idx])
    }

    /// Canonical JSON export of the frozen snapshot for the off-chain
    /// governance audit trail: the bps threshold, the snapshot slot,
    /// the derived weight-sum threshold, and every attestor with its
    /// frozen balance-weight. Hand-written, zero-dependency, fixed
    /// field order, lowercase hex keys.
    pub fn to_json(&self) -> String {
        let mut s = String::from("{\"threshold_bps\":");
        s.push_str(&self.threshold_bps.to_string());
        s.push_str(",\"snapshot_slot\":");
        s.push_str(&self.snapshot_slot.to_string());
        s.push_str(",\"threshold\":");
        s.push_str(&self.threshold().to_string());
        s.push_str(",\"total_weight\":");
        s.push_str(&self.total_weight().to_string());
        s.push_str(",\"attestors\":[");
        let attestors = self.policy.attestors();
        let weights = self.policy.weights();
        for i in 0..self.policy.registered_count() as usize {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"key\":\"");
            s.push_str(&hex32(&attestors[i]));
            s.push_str("\",\"weight\":");
            s.push_str(&weights[i].to_string());
            s.push('}');
        }
        s.push_str("]}");
        s
    }
}

/// Render 32 bytes as 64 lowercase hex characters.
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attestor(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn three_way() -> TokenWeightSnapshot {
        // Balances 100/200/300: total 600, 2/3 bps (6667) -> threshold 401.
        TokenWeightSnapshot::new(
            &[attestor(1), attestor(2), attestor(3)],
            &[100, 200, 300],
            6667,
            42,
        )
        .unwrap()
    }

    #[test]
    fn two_thirds_bps_threshold_uses_ceiling() {
        let snap = three_way();
        // 6667/10000 * 600 = 400.02 -> ceil 401.
        assert_eq!(snap.threshold(), 401);
        assert_eq!(snap.total_weight(), 600);
        assert_eq!(snap.threshold_bps(), 6667);
        assert_eq!(snap.snapshot_slot(), 42);
    }

    #[test]
    fn unanimity_bps_means_total_weight() {
        let snap =
            TokenWeightSnapshot::new(&[attestor(1), attestor(2)], &[100, 200], 10_000, 7)
                .unwrap();
        assert_eq!(snap.threshold(), 300);
    }

    #[test]
    fn one_bps_rounds_up_to_one() {
        let snap =
            TokenWeightSnapshot::new(&[attestor(1)], &[1_000_000], 1, 7).unwrap();
        // 1/10000 * 1_000_000 = 100 exactly.
        assert_eq!(snap.threshold(), 100);
        let snap =
            TokenWeightSnapshot::new(&[attestor(1)], &[9999], 1, 7).unwrap();
        // 0.9999 -> ceil 1: a positive bps always admits some release.
        assert_eq!(snap.threshold(), 1);
    }

    #[test]
    fn weight_of_returns_frozen_balances() {
        let snap = three_way();
        assert_eq!(snap.weight_of(attestor(1)), Some(100));
        assert_eq!(snap.weight_of(attestor(2)), Some(200));
        assert_eq!(snap.weight_of(attestor(3)), Some(300));
        assert_eq!(snap.weight_of(attestor(9)), None);
    }

    #[test]
    fn rejects_zero_bps() {
        assert_eq!(
            TokenWeightSnapshot::new(&[attestor(1)], &[100], 0, 1),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn rejects_bps_above_10000() {
        assert_eq!(
            TokenWeightSnapshot::new(&[attestor(1)], &[100], 10_001, 1),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn rejects_empty_and_oversized_sets() {
        assert_eq!(
            TokenWeightSnapshot::new(&[], &[], 5000, 1),
            Err(EscrowError::InvalidQuorum)
        );
        let many = vec![[7u8; 32]; MAX_ATTESTORS + 1];
        let bals = vec![1u64; MAX_ATTESTORS + 1];
        assert_eq!(
            TokenWeightSnapshot::new(&many, &bals, 5000, 1),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn rejects_length_mismatch() {
        assert_eq!(
            TokenWeightSnapshot::new(&[attestor(1), attestor(2)], &[100], 5000, 1),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn rejects_duplicate_and_zero_keys() {
        assert_eq!(
            TokenWeightSnapshot::new(&[attestor(1), attestor(1)], &[100, 100], 5000, 1),
            Err(EscrowError::InvalidQuorum)
        );
        assert_eq!(
            TokenWeightSnapshot::new(&[[0u8; 32]], &[100], 5000, 1),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn rejects_zero_balance() {
        // A zero-balance attestor has no voting power: registering one
        // is a misconfiguration, not a valid weight.
        assert_eq!(
            TokenWeightSnapshot::new(&[attestor(1), attestor(2)], &[100, 0], 5000, 1),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn rejects_weight_domain_overflow() {
        assert_eq!(
            TokenWeightSnapshot::new(&[attestor(1), attestor(2)], &[u64::MAX, u64::MAX], 5000, 1),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn to_json_is_canonical() {
        let snap = TokenWeightSnapshot::new(&[attestor(1)], &[100], 5000, 9).unwrap();
        let key = "01".repeat(32);
        assert_eq!(
            snap.to_json(),
            format!(
                "{{\"threshold_bps\":5000,\"snapshot_slot\":9,\"threshold\":50,\
                 \"total_weight\":100,\"attestors\":[{{\"key\":\"{key}\",\"weight\":100}}]}}"
            )
        );
    }

    #[test]
    fn snapshot_is_copy_and_frozen() {
        // Freezing is structural: the snapshot is Copy and exposes no
        // weight mutation — a flash loan after the snapshot cannot
        // change anyone's voting power.
        let snap = three_way();
        let dup = snap;
        assert_eq!(snap, dup);
        assert_eq!(snap.weight_of(attestor(1)), Some(100));
    }

    // ---- Escrow integration: the builder and the release gate ----

    use crate::{Escrow, Tier, TieredQuorum};

    const ALICE: [u8; 32] = [0xA1; 32];
    const BOB: [u8; 32] = [0xB0; 32];
    const EXPIRES: u64 = 1_800_000_000;

    #[test]
    fn builder_rejects_non_uninitialized() {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES).unwrap();
        e.fund(ALICE, EXPIRES - 3_600).unwrap();
        assert_eq!(
            e.with_token_weighted_voting(three_way()),
            Err(EscrowError::InvalidStateTransition)
        );
    }

    #[test]
    fn builder_rejects_existing_quorum_modes() {
        // A plain quorum already attached.
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES)
            .unwrap()
            .with_quorum(QuorumPolicy::new(&[attestor(1)], &[1], 1).unwrap())
            .unwrap();
        assert_eq!(
            e.with_token_weighted_voting(three_way()),
            Err(EscrowError::InvalidQuorum)
        );
        // A tiered quorum already attached.
        let tiered = TieredQuorum::new(
            QuorumPolicy::new(&[attestor(1)], &[1], 1).unwrap(),
            &[Tier {
                max_amount: u64::MAX,
                threshold: 1,
            }],
        )
        .unwrap();
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES)
            .unwrap()
            .with_tiered_quorum(tiered)
            .unwrap();
        assert_eq!(
            e.with_token_weighted_voting(three_way()),
            Err(EscrowError::InvalidQuorum)
        );
    }

    #[test]
    fn two_thirds_weighted_release_gate() {
        // Balances 100/200/300, threshold 401: attestor(3) alone (300)
        // is not enough; attestor(3) + attestor(1) (400) still misses
        // the ceiling; attestor(2) (200) pushes it over.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES)
            .unwrap()
            .with_token_weighted_voting(three_way())
            .unwrap();
        e.fund(ALICE, EXPIRES - 3_600).unwrap();
        e.attest(attestor(3)).unwrap();
        assert_eq!(
            e.release(ALICE, EXPIRES - 100, 1_000_000, None, BOB),
            Err(EscrowError::QuorumNotReached)
        );
        e.attest(attestor(1)).unwrap();
        // Duplicate attest is idempotent: still 400, still unsatisfied.
        e.attest(attestor(1)).unwrap();
        assert_eq!(
            e.release(ALICE, EXPIRES - 100, 1_000_000, None, BOB),
            Err(EscrowError::QuorumNotReached)
        );
        e.attest(attestor(2)).unwrap();
        let (payout, _fee) = e.release(ALICE, EXPIRES - 100, 1_000_000, None, BOB).unwrap();
        assert_eq!(payout, 1_000_000);
    }

    #[test]
    fn frozen_weights_visible_in_quorum_slot() {
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES)
            .unwrap()
            .with_token_weighted_voting(three_way())
            .unwrap();
        let q = e.quorum().expect("quorum slot carries the snapshot policy");
        assert_eq!(q.weights(), &[100, 200, 300]);
        assert_eq!(q.threshold(), 401);
        assert_eq!(q.total_weight(), 600);
    }
}
