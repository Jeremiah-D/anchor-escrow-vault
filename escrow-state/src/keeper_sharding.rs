//! AV-177: keeper task sharding — rendezvous-hash sharding of the
//! keeper watch list across fleet instances.
//!
//! The keeper scans ([`scan_keeper_actions`](super::keeper::scan_keeper_actions),
//! [`scan_batch_lifecycle`](super::batch::scan_batch_lifecycle)) are
//! dry-run by construction, so one keeper *can* scan the whole watch
//! list — but as the fleet and the vault count grow, every keeper
//! scanning everything wastes RPC budget and risks duplicate
//! submissions. This module shards the watch list deterministically
//! across the fleet: each keeper scans exactly its own vaults.
//!
//! It is deliberately orthogonal to the AV-37 batch lifecycle scan:
//! that module scans *one* keeper's watch list, this module decides
//! *which* watch list each keeper scans. It is also orthogonal to the
//! AV-176 leader election: the election decides *who may write*, this
//! module decides *who watches what*.
//!
//! # Components
//!
//! - [`ShardMap`]: the fleet roster plus the sharding function.
//!   [`ShardMap::assign`] maps one vault address to its keeper;
//!   [`ShardMap::shard_watch_list`] shards a whole watch list;
//!   [`ShardMap::update_members`] swaps the roster and reports the
//!   [`ShardDiff`] (added / removed members, moved vaults);
//!   [`ShardMap::report`] builds the per-member load report that the
//!   keeper reporting layer embeds.
//! - [`ShardAuditEntry`]: the structured audit — `MembershipChanged`
//!   with added / removed / moved counts. Bounded 64-entry ring,
//!   oldest evicts first (the AV-163 convention).
//!
//! # What is real here
//!
//! - **Rendezvous hashing (highest random weight).** Each vault is
//!   assigned to the member with the highest
//!   `weight(member, vault)`. The weights are deterministic given the
//!   member set and the vault address — every instance computes the
//!   same assignment independently, so the roster can either be
//!   distributed by the AV-176 leader or configured identically on
//!   every keeper.
//! - **Minimal disruption on membership changes.** Rendezvous hashing
//!   moves only what it must: removing a member reassigns exactly
//!   that member's vaults; adding a member moves vaults only *to* the
//!   new member. The `update_members` diff makes the moved set
//!   explicit (each [`ShardMove`] carries `from` and `to`).
//! - **Ties are impossible to observe nondeterministically.** Equal
//!   weights break toward the earliest member in roster order, and
//!   the roster is sorted at construction — caller argument order
//!   cannot change an assignment.
//!
//! # What is deliberately NOT here (honesty labels)
//!
//! - **The weight function is not cryptographic.** It is FNV-1a
//!   (64-bit) over the member/vault bytes with a splitmix64
//!   finalizer — deterministic and well-distributed, but not
//!   preimage-resistant. Assignment stability is the requirement,
//!   not unforgeability: sharding is a load-distribution mechanism,
//!   not a security boundary.
//! - **The map is off-chain state.** It is the operator's fleet
//!   roster, not an on-chain account: no slot sysvar, no account
//!   layout, no Anchor instruction in this round. The caller feeds
//!   the vault addresses (the keeper scans own the watch list).
//! - **The map never scans escrows itself.** `update_members` and
//!   `report` take the vault list as an argument — the registry does
//!   not fetch or store the watch list, it only shards the one it is
//!   given.
//! - **Empty roster means no assignments.** With zero members every
//!   vault is unassigned (`assign` returns `None`) — the operator
//!   must notice the empty report, the map will not invent a keeper.

use std::collections::VecDeque;

use super::EscrowError;

/// How many sharding audit entries are remembered: a bounded ring,
/// mirroring the AV-163 circuit-breaker convention (fixed-size tail,
/// oldest evicts first).
pub const MAX_SHARD_AUDIT_ENTRIES: usize = 64;

/// FNV-1a 64-bit: the non-cryptographic mixer behind the rendezvous
/// weights (see the module docs for why non-crypto is acceptable
/// here).
fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut h = OFFSET;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// splitmix64 finalizer: avalanches the FNV-1a output so nearby
/// inputs (sequential vault addresses) spread across the weight
/// space instead of clustering.
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

/// The rendezvous weight of `member` for `vault`: the highest weight
/// wins the vault. Deterministic given the inputs; every fleet
/// instance computes the identical value.
fn rendezvous_weight(member: &[u8; 32], vault: &[u8; 32]) -> u64 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(member);
    buf[32..].copy_from_slice(vault);
    splitmix64(fnv1a_64(&buf))
}

/// One vault's shard assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardAssignment {
    /// The vault address.
    pub vault: [u8; 32],
    /// The keeper that watches it.
    pub keeper: [u8; 32],
}

/// One vault that changed keepers on a membership update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardMove {
    /// The vault address.
    pub vault: [u8; 32],
    /// The keeper that watched it before the update.
    pub from: [u8; 32],
    /// The keeper that watches it after the update.
    pub to: [u8; 32],
}

/// The diff of a [`ShardMap::update_members`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardDiff {
    /// Members added by the update.
    pub added: Vec<[u8; 32]>,
    /// Members removed by the update.
    pub removed: Vec<[u8; 32]>,
    /// Vaults that changed keepers (`from` / `to` both set).
    pub moved: Vec<ShardMove>,
}

/// Per-member load, for the keeper report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberLoad {
    /// The keeper.
    pub keeper: [u8; 32],
    /// How many of the reported vaults it watches.
    pub vault_count: u32,
}

/// The shard report: per-member vault counts over a watch list. Built
/// to be embedded in the keeper reporting layer (the AV-20 /
/// AV-101 report family) — the report carries the *distribution*,
/// the [`ShardDiff`] from `update_members` carries the *change*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardReport {
    /// Unix timestamp the report was built at (caller-supplied).
    pub generated_at: u64,
    /// Per-member loads, in roster order. Members watching zero
    /// vaults are included with `vault_count: 0`.
    pub member_loads: Vec<MemberLoad>,
    /// Total vaults in the watch list (the loads sum to this).
    pub total_vaults: u32,
}

/// The sharding audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardAuditKind {
    /// The roster changed: members added / removed, vaults moved.
    MembershipChanged,
}

/// One structured sharding audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardAuditEntry {
    /// What happened.
    pub kind: ShardAuditKind,
    /// Unix timestamp of the event (caller-supplied).
    pub at: u64,
    /// Members added by the update.
    pub added: u32,
    /// Members removed by the update.
    pub removed: u32,
    /// Vaults that changed keepers.
    pub moved: u32,
}

/// The fleet roster and the rendezvous sharding function. The roster
/// is sorted at construction, so caller argument order never affects
/// an assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardMap {
    members: Vec<[u8; 32]>,
    audit: VecDeque<ShardAuditEntry>,
}

impl ShardMap {
    /// Build a shard map over `members`. Rejects the zero key and
    /// duplicates ([`EscrowError::InvalidShardMembership`]) — an
    /// unkeyed or ambiguous roster entry could never be a real
    /// keeper. Members are sorted into roster order.
    pub fn new(members: &[[u8; 32]]) -> Result<Self, EscrowError> {
        Self::validate_members(members)?;
        let mut sorted: Vec<[u8; 32]> = members.to_vec();
        sorted.sort_unstable();
        Ok(ShardMap {
            members: sorted,
            audit: VecDeque::with_capacity(MAX_SHARD_AUDIT_ENTRIES),
        })
    }

    fn validate_members(members: &[[u8; 32]]) -> Result<(), EscrowError> {
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(members.len());
        for m in members {
            if *m == [0u8; 32] || seen.contains(m) {
                return Err(EscrowError::InvalidShardMembership);
            }
            seen.push(*m);
        }
        Ok(())
    }

    fn push_audit(&mut self, entry: ShardAuditEntry) {
        if self.audit.len() == MAX_SHARD_AUDIT_ENTRIES {
            self.audit.pop_front();
        }
        self.audit.push_back(entry);
    }

    /// The roster, in sorted roster order.
    pub fn members(&self) -> &[[u8; 32]] {
        &self.members
    }

    /// Assign one vault to its keeper: the member with the highest
    /// rendezvous weight; ties break toward the earliest roster
    /// member. `None` when the roster is empty (no keeper to assign
    /// to — the operator must notice, the map will not invent one).
    pub fn assign(&self, vault: &[u8; 32]) -> Option<[u8; 32]> {
        let mut best: Option<([u8; 32], u64)> = None;
        for m in &self.members {
            let w = rendezvous_weight(m, vault);
            match best {
                Some((_, bw)) if bw >= w => {}
                _ => best = Some((*m, w)),
            }
        }
        best.map(|(m, _)| m)
    }

    /// Shard a whole watch list. Vaults are assigned independently —
    /// one vault's assignment never affects another's. The output
    /// order follows the input order.
    pub fn shard_watch_list(&self, vaults: &[[u8; 32]]) -> Vec<ShardAssignment> {
        vaults
            .iter()
            .filter_map(|v| self.assign(v).map(|keeper| ShardAssignment { vault: *v, keeper }))
            .collect()
    }

    /// Swap the roster: validate the new set, recompute assignments
    /// over `vaults`, and return the diff. Minimal disruption is a
    /// property of rendezvous hashing — the diff makes it auditable:
    /// removals move exactly the removed members' vaults, additions
    /// move vaults only *to* the new members.
    ///
    /// Appends a `MembershipChanged` audit entry. The new roster
    /// replaces the old one even when nothing moved.
    pub fn update_members(
        &mut self,
        new_members: &[[u8; 32]],
        vaults: &[[u8; 32]],
        now: u64,
    ) -> Result<ShardDiff, EscrowError> {
        Self::validate_members(new_members)?;
        let mut new_sorted: Vec<[u8; 32]> = new_members.to_vec();
        new_sorted.sort_unstable();
        let new_map = ShardMap {
            members: new_sorted,
            audit: VecDeque::with_capacity(MAX_SHARD_AUDIT_ENTRIES),
        };

        let added: Vec<[u8; 32]> = new_map
            .members
            .iter()
            .filter(|m| !self.members.contains(m))
            .copied()
            .collect();
        let removed: Vec<[u8; 32]> = self
            .members
            .iter()
            .filter(|m| !new_map.members.contains(m))
            .copied()
            .collect();
        // Per-vault diff over the full watch list: the zero key stands
        // for "no keeper", so the diff stays total even when a roster
        // is empty on either side.
        let mut moved = Vec::new();
        for vault in vaults {
            let old = self.assign(vault);
            let new = new_map.assign(vault);
            if old != new {
                moved.push(ShardMove {
                    vault: *vault,
                    from: old.unwrap_or([0u8; 32]),
                    to: new.unwrap_or([0u8; 32]),
                });
            }
        }

        self.members = new_map.members;
        self.push_audit(ShardAuditEntry {
            kind: ShardAuditKind::MembershipChanged,
            at: now,
            added: added.len() as u32,
            removed: removed.len() as u32,
            moved: moved.len() as u32,
        });
        Ok(ShardDiff { added, removed, moved })
    }

    /// Build the per-member load report over `vaults` — the
    /// distribution half of keeper reporting (the change half is the
    /// [`ShardDiff`]). Loads sum to `total_vaults`; every roster
    /// member appears, even at zero vaults.
    pub fn report(&self, vaults: &[[u8; 32]], now: u64) -> ShardReport {
        let assignments = self.shard_watch_list(vaults);
        let member_loads = self
            .members
            .iter()
            .map(|m| {
                let vault_count = assignments.iter().filter(|a| &a.keeper == m).count() as u32;
                MemberLoad {
                    keeper: *m,
                    vault_count,
                }
            })
            .collect();
        ShardReport {
            generated_at: now,
            member_loads,
            total_vaults: assignments.len() as u32,
        }
    }

    /// The sharding audit trail, oldest-first.
    pub fn audit(&self) -> Vec<ShardAuditEntry> {
        self.audit.iter().copied().collect()
    }
}

#[cfg(test)]
mod keeper_sharding_tests {
    use super::*;

    const KEEPER_A: [u8; 32] = [0xA1; 32];
    const KEEPER_B: [u8; 32] = [0xB2; 32];
    const KEEPER_C: [u8; 32] = [0xC3; 32];
    const KEEPER_D: [u8; 32] = [0xD4; 32];

    /// Deterministic vault addresses: the i-th byte of the j-th
    /// address is (i + j) mod 256 — no two addresses collide, no RNG
    /// in tests.
    fn vaults(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|j| {
                let mut v = [0u8; 32];
                for (i, b) in v.iter_mut().enumerate() {
                    *b = ((i + j) % 256) as u8;
                }
                v
            })
            .collect()
    }

    #[test]
    fn new_rejects_zero_key_and_duplicates() {
        assert_eq!(
            ShardMap::new(&[[0u8; 32], KEEPER_A]),
            Err(EscrowError::InvalidShardMembership)
        );
        assert_eq!(
            ShardMap::new(&[KEEPER_A, KEEPER_B, KEEPER_A]),
            Err(EscrowError::InvalidShardMembership)
        );
        // A failed construction leaves nothing behind to inspect —
        // the error is the whole contract.
    }

    #[test]
    fn new_sorts_members_into_roster_order() {
        let m = ShardMap::new(&[KEEPER_C, KEEPER_A, KEEPER_B]).unwrap();
        assert_eq!(m.members(), &[KEEPER_A, KEEPER_B, KEEPER_C]);
    }

    #[test]
    fn caller_argument_order_does_not_change_assignments() {
        let v = vaults(40);
        let m1 = ShardMap::new(&[KEEPER_A, KEEPER_B, KEEPER_C]).unwrap();
        let m2 = ShardMap::new(&[KEEPER_C, KEEPER_A, KEEPER_B]).unwrap();
        assert_eq!(m1.shard_watch_list(&v), m2.shard_watch_list(&v));
    }

    #[test]
    fn assign_is_deterministic_across_independent_maps() {
        let v = vaults(64);
        let m1 = ShardMap::new(&[KEEPER_A, KEEPER_B, KEEPER_C]).unwrap();
        let m2 = ShardMap::new(&[KEEPER_A, KEEPER_B, KEEPER_C]).unwrap();
        for vault in &v {
            assert_eq!(m1.assign(vault), m2.assign(vault));
        }
    }

    #[test]
    fn assign_pinned_against_independent_implementation() {
        // Computed with an independent Python implementation of
        // FNV-1a-64 + splitmix64 over member || vault (see the
        // module docs): the pin guards against silent changes to
        // the weight function, which would reshuffle every fleet.
        let m = ShardMap::new(&[KEEPER_A, KEEPER_B, KEEPER_C]).unwrap();
        let vault: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        assert_eq!(m.assign(&vault), Some(KEEPER_A));
    }

    #[test]
    fn empty_roster_assigns_nothing() {
        let m = ShardMap::new(&[]).unwrap();
        let v = vaults(8);
        assert_eq!(m.assign(&v[0]), None);
        assert!(m.shard_watch_list(&v).is_empty());
        let report = m.report(&v, 1_000);
        assert_eq!(report.total_vaults, 0);
        assert!(report.member_loads.is_empty());
    }

    #[test]
    fn single_member_gets_everything() {
        let m = ShardMap::new(&[KEEPER_A]).unwrap();
        let v = vaults(16);
        let assignments = m.shard_watch_list(&v);
        assert_eq!(assignments.len(), 16);
        assert!(assignments.iter().all(|a| a.keeper == KEEPER_A));
    }

    #[test]
    fn removal_moves_only_the_removed_members_vaults() {
        let v = vaults(96);
        let mut m = ShardMap::new(&[KEEPER_A, KEEPER_B, KEEPER_C]).unwrap();
        let before = m.shard_watch_list(&v);
        let diff = m
            .update_members(&[KEEPER_A, KEEPER_B], &v, 1_000)
            .unwrap();
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed, vec![KEEPER_C]);
        // Every moved vault was C's, and every one of C's vaults moved.
        let c_vaults: Vec<[u8; 32]> = before
            .iter()
            .filter(|a| a.keeper == KEEPER_C)
            .map(|a| a.vault)
            .collect();
        assert!(!c_vaults.is_empty());
        assert_eq!(diff.moved.len(), c_vaults.len());
        for mv in &diff.moved {
            assert_eq!(mv.from, KEEPER_C);
            assert!(c_vaults.contains(&mv.vault));
            assert!(mv.to == KEEPER_A || mv.to == KEEPER_B);
        }
        // Vaults that were A's or B's did not move.
        for a in before.iter().filter(|a| a.keeper != KEEPER_C) {
            assert_eq!(m.assign(&a.vault), Some(a.keeper));
        }
    }

    #[test]
    fn addition_moves_vaults_only_to_the_new_member() {
        let v = vaults(96);
        let mut m = ShardMap::new(&[KEEPER_A, KEEPER_B]).unwrap();
        let diff = m
            .update_members(&[KEEPER_A, KEEPER_B, KEEPER_D], &v, 1_000)
            .unwrap();
        assert_eq!(diff.added, vec![KEEPER_D]);
        assert!(diff.removed.is_empty());
        assert!(!diff.moved.is_empty());
        // Minimal disruption: every moved vault lands on D, and no
        // vault moves between A and B.
        for mv in &diff.moved {
            assert_eq!(mv.to, KEEPER_D);
            assert!(mv.from == KEEPER_A || mv.from == KEEPER_B);
        }
    }

    #[test]
    fn update_members_rejects_bad_roster_and_keeps_old() {
        let v = vaults(8);
        let mut m = ShardMap::new(&[KEEPER_A, KEEPER_B]).unwrap();
        assert_eq!(
            m.update_members(&[KEEPER_A, [0u8; 32]], &v, 1_000),
            Err(EscrowError::InvalidShardMembership)
        );
        assert_eq!(
            m.update_members(&[KEEPER_A, KEEPER_A], &v, 1_000),
            Err(EscrowError::InvalidShardMembership)
        );
        // The rejected update changed nothing.
        assert_eq!(m.members(), &[KEEPER_A, KEEPER_B]);
        assert!(m.audit().is_empty());
    }

    #[test]
    fn update_members_audit_records_the_change() {
        let v = vaults(48);
        let mut m = ShardMap::new(&[KEEPER_A, KEEPER_B]).unwrap();
        let diff = m
            .update_members(&[KEEPER_A, KEEPER_C], &v, 9_999)
            .unwrap();
        let audit = m.audit();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].kind, ShardAuditKind::MembershipChanged);
        assert_eq!(audit[0].at, 9_999);
        assert_eq!(audit[0].added, diff.added.len() as u32);
        assert_eq!(audit[0].removed, diff.removed.len() as u32);
        assert_eq!(audit[0].moved, diff.moved.len() as u32);
    }

    #[test]
    fn report_loads_sum_to_total_and_cover_all_members() {
        let v = vaults(64);
        let m = ShardMap::new(&[KEEPER_A, KEEPER_B, KEEPER_C]).unwrap();
        let report = m.report(&v, 5_000);
        assert_eq!(report.generated_at, 5_000);
        assert_eq!(report.total_vaults, 64);
        assert_eq!(report.member_loads.len(), 3);
        let sum: u32 = report.member_loads.iter().map(|l| l.vault_count).sum();
        assert_eq!(sum, 64);
        // Roster order is preserved in the report.
        assert_eq!(report.member_loads[0].keeper, KEEPER_A);
        assert_eq!(report.member_loads[1].keeper, KEEPER_B);
        assert_eq!(report.member_loads[2].keeper, KEEPER_C);
        // The distribution is roughly even (sanity, not strict: 64
        // vaults over 3 keepers, each within 12..32).
        for load in &report.member_loads {
            assert!(
                (12..=32).contains(&load.vault_count),
                "skewed load: {:?}",
                load
            );
        }
    }

    #[test]
    fn audit_ring_evicts_oldest() {
        let v = vaults(8);
        let mut m = ShardMap::new(&[KEEPER_A]).unwrap();
        for i in 0..(MAX_SHARD_AUDIT_ENTRIES + 5) {
            let members: Vec<[u8; 32]> = if i % 2 == 0 {
                vec![KEEPER_A, KEEPER_B]
            } else {
                vec![KEEPER_A]
            };
            m.update_members(&members, &v, i as u64).unwrap();
        }
        let audit = m.audit();
        assert_eq!(audit.len(), MAX_SHARD_AUDIT_ENTRIES);
        // 69 updates, oldest 5 evicted: the first surviving entry is
        // the update at=5.
        assert_eq!(audit[0].at, 5);
    }

    #[test]
    fn error_code_is_stable() {
        assert_eq!(EscrowError::InvalidShardMembership.code(), 241);
    }
}
