//! AV-176: keeper leader election — lease-based mutual leadership for
//! write operations across a keeper fleet.
//!
//! The keeper scans are dry-run by construction, so a fleet of keeper
//! bots can share the *read* work — but write operations (submitting
//! transactions) need exactly one writer at a time, or two keepers race
//! to submit the same crank and one of them burns priority fees on a
//! doomed transaction. This module is the mutual-leadership layer: a
//! lease election over the fleet where the winner holds a term and a
//! fencing token.
//!
//! It is deliberately orthogonal to the AV-165 keeper heartbeats: that
//! module reports *liveness* ("I am alive, here is what I did"), this
//! module decides *who may write* ("I hold the lease for term N").
//! A keeper typically runs both — heartbeat for liveness, election for
//! the write lock.
//!
//! # Components
//!
//! - [`ElectionConfig`]: the lease duration (`lease_ttl_secs`),
//!   validated on construction.
//! - [`KeeperElection`]: the election state. [`KeeperElection::acquire`]
//!   campaigns for leadership (wins when the seat is open, renews the
//!   lease idempotently when the caller already holds it, refuses with
//!   [`EscrowError::ElectionHeld`] when another keeper holds a live
//!   lease); [`KeeperElection::renew`] is the leader's heartbeat — it
//!   extends the lease but never campaigns (refuses with
//!   [`EscrowError::LeaseExpired`] once the lease lapsed, forcing an
//!   explicit re-`acquire`); [`KeeperElection::step_down`] is the
//!   voluntary resignation.
//! - [`ElectionGrant`]: what a successful `acquire` returns — the term,
//!   the fencing token, and the lease expiry.
//! - [`ElectionAuditEntry`]: the structured audit — `LeaderElected`
//!   (with the prior term, so failovers are visible), `LeaseRenewed`,
//!   and `LeaderSteppedDown`. Bounded 64-entry ring, oldest evicts
//!   first (the AV-163 convention).
//!
//! # What is real here
//!
//! - **Terms are strictly increasing.** Every successful campaign that
//!   finds the seat open (no leader, or the lease lapsed) bumps the
//!   term by one. Two leaders can never share a term.
//! - **Fencing tokens are strictly increasing with terms.** The new
//!   leader's token is the old token plus one. A writer stamps its
//!   write operations with the token it campaigned for; any write
//!   carrying an older token belongs to a deposed leader and must be
//!   rejected downstream — that is the anti-split-brain contract.
//! - **Lease expiry is computed from caller-supplied time.** `now >=
//!   lease_expires_at` means the lease has lapsed (exclusive end,
//!   same boundary convention as the AV-165 staleness rule). A lapsed
//!   lease is an open seat: the next `acquire` — by anyone, including
//!   the old leader — starts a new term. That is the automatic
//!   failover: no explicit revocation needed.
//! - **Re-acquiring while holding is an idempotent renew.** A keeper
//!   that already holds a live lease and calls `acquire` again gets
//!   its lease extended (same term, same token) — the campaign loop
//!   needs no special-casing, and no audit entry is recorded for the
//!   steady state (the ring keeps leadership *changes*, not noise).
//!
//! # What is deliberately NOT here (honesty labels)
//!
//! - **The election is off-chain state.** It is the operator's fleet
//!   coordination, not an on-chain account: no slot sysvar, no account
//!   layout, no Anchor instruction in this round. The caller feeds
//!   `now` — the crate has no clock.
//! - **The crate issues the fencing token; it does not enforce it.**
//!   Checking the token on the write path (rejecting writes stamped
//!   with a stale token) is the executor's job — the election module
//!   never sees a write, so it cannot check one. A token that nobody
//!   checks is just a number.
//! - **`renew` refuses to campaign on purpose.** A leader whose lease
//!   lapsed gets [`EscrowError::LeaseExpired`], not a silent
//!   re-election: the caller must notice the gap and `acquire` again
//!   (new term, new token). Silent self-promotion after a partition
//!   is exactly how split-brain starts.
//! - **No network, no consensus.** This is a single-writer lease, not
//!   Raft: every keeper must consult the *same* `KeeperElection`
//!   state (a shared operator service, or the AV-176 leader's own
//!   distribution). Two disjoint election states elect two leaders —
//!   the module cannot fix a partitioned coordinator.

use std::collections::VecDeque;

use super::EscrowError;

/// How many election audit entries are remembered: a bounded ring,
/// mirroring the AV-163 circuit-breaker convention (fixed-size tail,
/// oldest evicts first).
pub const MAX_ELECTION_AUDIT_ENTRIES: usize = 64;

/// Lease election configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectionConfig {
    /// Lease duration in seconds. The leader must `renew` (or
    /// re-`acquire`) before `now` reaches the lease expiry, or the
    /// seat opens for failover.
    pub lease_ttl_secs: u64,
}

impl ElectionConfig {
    /// Validate: a zero lease TTL would make every lease lapse
    /// instantly, so leadership could never be held.
    pub fn validate(&self) -> Result<(), EscrowError> {
        if self.lease_ttl_secs == 0 {
            return Err(EscrowError::InvalidElectionConfig);
        }
        Ok(())
    }
}

/// What a successful [`KeeperElection::acquire`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectionGrant {
    /// The term the caller now leads (strictly increasing across
    /// campaigns).
    pub term: u64,
    /// The fencing token for this term (strictly increasing across
    /// campaigns) — stamp write operations with it.
    pub fencing_token: u64,
    /// Unix timestamp at which the lease lapses unless renewed
    /// (`now >= lease_expires_at` is expired).
    pub lease_expires_at: u64,
}

/// The election audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElectionAuditKind {
    /// A campaign won leadership — `term` is the new term,
    /// `prior_term` the term it superseded (0 when the seat was
    /// never held), so failovers are visible in the audit.
    LeaderElected,
    /// The leader extended its lease via
    /// [`KeeperElection::renew`].
    LeaseRenewed,
    /// The leader voluntarily resigned via
    /// [`KeeperElection::step_down`] — the seat is open.
    LeaderSteppedDown,
}

/// One structured election audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectionAuditEntry {
    /// What happened.
    pub kind: ElectionAuditKind,
    /// The term this entry belongs to.
    pub term: u64,
    /// The superseded term (`LeaderElected` only; 0 for the first
    /// election; equals `term` for `LeaseRenewed` /
    /// `LeaderSteppedDown`).
    pub prior_term: u64,
    /// The leader (the campaign winner, the renewing leader, or the
    /// resigning leader).
    pub keeper: [u8; 32],
    /// Unix timestamp of the event (caller-supplied).
    pub at: u64,
    /// The fencing token current after this event.
    pub fencing_token: u64,
}

/// The lease election: terms, the current leader, the lease expiry,
/// the fencing token, and the bounded audit ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeeperElection {
    config: ElectionConfig,
    term: u64,
    fencing_token: u64,
    leader: Option<[u8; 32]>,
    lease_expires_at: u64,
    audit: VecDeque<ElectionAuditEntry>,
}

impl KeeperElection {
    /// Create an election with a validated config. No leader, term 0,
    /// fencing token 0 — the seat is open.
    pub fn new(config: ElectionConfig) -> Result<Self, EscrowError> {
        config.validate()?;
        Ok(KeeperElection {
            config,
            term: 0,
            fencing_token: 0,
            leader: None,
            lease_expires_at: 0,
            audit: VecDeque::with_capacity(MAX_ELECTION_AUDIT_ENTRIES),
        })
    }

    fn push_audit(&mut self, entry: ElectionAuditEntry) {
        if self.audit.len() == MAX_ELECTION_AUDIT_ENTRIES {
            self.audit.pop_front();
        }
        self.audit.push_back(entry);
    }

    /// Whether `keeper` holds a live lease at `now`: it is the
    /// recorded leader and `now` is before the lease expiry.
    fn live_leader(&self, now: u64) -> Option<[u8; 32]> {
        match self.leader {
            Some(l) if now < self.lease_expires_at => Some(l),
            _ => None,
        }
    }

    /// Campaign for leadership.
    ///
    /// Check order: candidate shape ([`EscrowError::InvalidElectionConfig`]
    /// — the zero key can never be a leader, mirroring the AV-165
    /// roster rule), then the seat state.
    ///
    /// - Seat open (no leader, or the lease lapsed at `now`): the
    ///   caller wins — term and fencing token each bump by one, the
    ///   lease runs `now + lease_ttl_secs`, and a `LeaderElected`
    ///   audit entry records the takeover (`prior_term` exposes the
    ///   failover).
    /// - Seat held by the caller: idempotent renew — same term and
    ///   token, the lease extended, no audit entry (steady state is
    ///   not an event).
    /// - Seat held by another keeper: [`EscrowError::ElectionHeld`].
    ///
    /// Term/token increments use saturating arithmetic: the crate is
    /// panic-free, and 2^64 campaigns is not a reachable state.
    pub fn acquire(
        &mut self,
        keeper: [u8; 32],
        now: u64,
    ) -> Result<ElectionGrant, EscrowError> {
        if keeper == [0u8; 32] {
            return Err(EscrowError::InvalidElectionConfig);
        }
        if let Some(live) = self.live_leader(now) {
            if live == keeper {
                self.lease_expires_at = now.saturating_add(self.config.lease_ttl_secs);
                return Ok(self.grant());
            }
            return Err(EscrowError::ElectionHeld);
        }
        let prior_term = self.term;
        self.term = self.term.saturating_add(1);
        self.fencing_token = self.fencing_token.saturating_add(1);
        self.leader = Some(keeper);
        self.lease_expires_at = now.saturating_add(self.config.lease_ttl_secs);
        self.push_audit(ElectionAuditEntry {
            kind: ElectionAuditKind::LeaderElected,
            term: self.term,
            prior_term,
            keeper,
            at: now,
            fencing_token: self.fencing_token,
        });
        Ok(self.grant())
    }

    /// The leader's heartbeat: extend the lease without campaigning.
    ///
    /// Check order: leadership ([`EscrowError::NotLeader`] — a
    /// non-leader, or nobody, cannot renew), then the lease
    /// ([`EscrowError::LeaseExpired`] — the seat already lapsed; the
    /// caller must `acquire` again and take a new term).
    ///
    /// A successful renew appends a `LeaseRenewed` audit entry.
    pub fn renew(&mut self, keeper: [u8; 32], now: u64) -> Result<(), EscrowError> {
        if self.leader != Some(keeper) {
            return Err(EscrowError::NotLeader);
        }
        if now >= self.lease_expires_at {
            return Err(EscrowError::LeaseExpired);
        }
        self.lease_expires_at = now.saturating_add(self.config.lease_ttl_secs);
        self.push_audit(ElectionAuditEntry {
            kind: ElectionAuditKind::LeaseRenewed,
            term: self.term,
            prior_term: self.term,
            keeper,
            at: now,
            fencing_token: self.fencing_token,
        });
        Ok(())
    }

    /// Voluntary resignation: the leader gives up the seat. The term
    /// and fencing token are *retained* (monotonicity is never
    /// rewound) — the next campaign starts a fresh term with a fresh
    /// token. A non-leader gets [`EscrowError::NotLeader`].
    ///
    /// Appends a `LeaderSteppedDown` audit entry.
    pub fn step_down(&mut self, keeper: [u8; 32], now: u64) -> Result<(), EscrowError> {
        if self.leader != Some(keeper) {
            return Err(EscrowError::NotLeader);
        }
        let term = self.term;
        let fencing_token = self.fencing_token;
        self.leader = None;
        self.lease_expires_at = 0;
        self.push_audit(ElectionAuditEntry {
            kind: ElectionAuditKind::LeaderSteppedDown,
            term,
            prior_term: term,
            keeper,
            at: now,
            fencing_token,
        });
        Ok(())
    }

    /// Whether `keeper` holds a live lease at `now`.
    pub fn is_leader(&self, keeper: [u8; 32], now: u64) -> bool {
        self.live_leader(now) == Some(keeper)
    }

    fn grant(&self) -> ElectionGrant {
        ElectionGrant {
            term: self.term,
            fencing_token: self.fencing_token,
            lease_expires_at: self.lease_expires_at,
        }
    }

    /// The current term (0 when the seat was never held).
    pub fn term(&self) -> u64 {
        self.term
    }

    /// The current fencing token (0 when the seat was never held).
    pub fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    /// The recorded leader, if any (a lapsed lease still records its
    /// last leader until the next campaign — use
    /// [`KeeperElection::is_leader`] for the live verdict).
    pub fn leader(&self) -> Option<[u8; 32]> {
        self.leader
    }

    /// The lease expiry (`now >= lease_expires_at` is expired).
    pub fn lease_expires_at(&self) -> u64 {
        self.lease_expires_at
    }

    /// The election audit trail, oldest-first.
    pub fn audit(&self) -> Vec<ElectionAuditEntry> {
        self.audit.iter().copied().collect()
    }
}

#[cfg(test)]
mod keeper_election_tests {
    use super::*;

    const KEEPER_A: [u8; 32] = [0xA1; 32];
    const KEEPER_B: [u8; 32] = [0xB2; 32];
    const KEEPER_C: [u8; 32] = [0xC3; 32];

    fn config() -> ElectionConfig {
        ElectionConfig { lease_ttl_secs: 30 }
    }

    fn election() -> KeeperElection {
        KeeperElection::new(config()).unwrap()
    }

    #[test]
    fn new_rejects_zero_lease_ttl() {
        assert_eq!(
            KeeperElection::new(ElectionConfig { lease_ttl_secs: 0 }),
            Err(EscrowError::InvalidElectionConfig)
        );
    }

    #[test]
    fn acquire_rejects_zero_keeper() {
        let mut e = election();
        assert_eq!(
            e.acquire([0u8; 32], 1_000),
            Err(EscrowError::InvalidElectionConfig)
        );
        // The failed campaign changed nothing: the seat is still open.
        assert_eq!(e.term(), 0);
        assert_eq!(e.leader(), None);
    }

    #[test]
    fn first_acquire_starts_term_one_with_fresh_token() {
        let mut e = election();
        let grant = e.acquire(KEEPER_A, 1_000).unwrap();
        assert_eq!(
            grant,
            ElectionGrant {
                term: 1,
                fencing_token: 1,
                lease_expires_at: 1_030,
            }
        );
        assert_eq!(e.term(), 1);
        assert_eq!(e.fencing_token(), 1);
        assert_eq!(e.leader(), Some(KEEPER_A));
        assert!(e.is_leader(KEEPER_A, 1_000));
        assert!(!e.is_leader(KEEPER_B, 1_000));
        // The audit exposes the takeover: prior term 0, new term 1.
        let audit = e.audit();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].kind, ElectionAuditKind::LeaderElected);
        assert_eq!(audit[0].term, 1);
        assert_eq!(audit[0].prior_term, 0);
        assert_eq!(audit[0].keeper, KEEPER_A);
        assert_eq!(audit[0].fencing_token, 1);
    }

    #[test]
    fn acquire_while_live_lease_held_by_other_is_refused() {
        let mut e = election();
        e.acquire(KEEPER_A, 1_000).unwrap();
        assert_eq!(e.acquire(KEEPER_B, 1_010), Err(EscrowError::ElectionHeld));
        // The refused campaign changed nothing.
        assert_eq!(e.term(), 1);
        assert_eq!(e.leader(), Some(KEEPER_A));
        assert_eq!(e.audit().len(), 1);
    }

    #[test]
    fn acquire_by_current_leader_renews_idempotently() {
        let mut e = election();
        e.acquire(KEEPER_A, 1_000).unwrap();
        let grant = e.acquire(KEEPER_A, 1_020).unwrap();
        // Same term and token — no new leadership, just an extended lease.
        assert_eq!(grant.term, 1);
        assert_eq!(grant.fencing_token, 1);
        assert_eq!(grant.lease_expires_at, 1_050);
        // Steady state is not an audit event.
        assert_eq!(e.audit().len(), 1);
    }

    #[test]
    fn lapsed_lease_opens_seat_for_failover_with_fencing_bump() {
        let mut e = election();
        let grant_a = e.acquire(KEEPER_A, 1_000).unwrap();
        // At exactly the expiry the lease has lapsed (exclusive end).
        assert!(!e.is_leader(KEEPER_A, 1_030));
        let grant_b = e.acquire(KEEPER_B, 1_030).unwrap();
        assert_eq!(grant_b.term, 2);
        // The fencing token bumped: any write stamped with A's token 1
        // is now stale and must be rejected downstream.
        assert!(grant_b.fencing_token > grant_a.fencing_token);
        assert_eq!(grant_b.fencing_token, 2);
        assert!(e.is_leader(KEEPER_B, 1_030));
        assert!(!e.is_leader(KEEPER_A, 1_030));
        // The audit shows the failover: prior term 1 -> term 2.
        let audit = e.audit();
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[1].kind, ElectionAuditKind::LeaderElected);
        assert_eq!(audit[1].prior_term, 1);
        assert_eq!(audit[1].term, 2);
        assert_eq!(audit[1].keeper, KEEPER_B);
    }

    #[test]
    fn old_leader_may_reacquire_after_lapse_but_gets_new_term() {
        let mut e = election();
        e.acquire(KEEPER_A, 1_000).unwrap();
        // A's own lease lapsed; A campaigns again and wins — but as a
        // *new* term with a *new* token, never a silent continuation.
        let grant = e.acquire(KEEPER_A, 1_031).unwrap();
        assert_eq!(grant.term, 2);
        assert_eq!(grant.fencing_token, 2);
    }

    #[test]
    fn renew_extends_lease_and_is_audited() {
        let mut e = election();
        e.acquire(KEEPER_A, 1_000).unwrap();
        e.renew(KEEPER_A, 1_020).unwrap();
        assert_eq!(e.lease_expires_at(), 1_050);
        assert!(e.is_leader(KEEPER_A, 1_040));
        let audit = e.audit();
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[1].kind, ElectionAuditKind::LeaseRenewed);
        assert_eq!(audit[1].term, 1);
        assert_eq!(audit[1].keeper, KEEPER_A);
    }

    #[test]
    fn renew_by_non_leader_is_refused() {
        let mut e = election();
        e.acquire(KEEPER_A, 1_000).unwrap();
        assert_eq!(e.renew(KEEPER_B, 1_010), Err(EscrowError::NotLeader));
        // Nobody holding the seat: also NotLeader, not a lease error.
        let mut e2 = election();
        assert_eq!(e2.renew(KEEPER_A, 1_010), Err(EscrowError::NotLeader));
    }

    #[test]
    fn renew_after_lapse_is_refused_and_forces_reacquire() {
        let mut e = election();
        e.acquire(KEEPER_A, 1_000).unwrap();
        // The lease lapsed at 1030: renew refuses instead of silently
        // re-electing — the caller must notice the gap.
        assert_eq!(e.renew(KEEPER_A, 1_030), Err(EscrowError::LeaseExpired));
        assert!(!e.is_leader(KEEPER_A, 1_030));
        // Re-acquire starts a new term (the gap is visible).
        let grant = e.acquire(KEEPER_A, 1_030).unwrap();
        assert_eq!(grant.term, 2);
        assert_eq!(grant.fencing_token, 2);
    }

    #[test]
    fn step_down_opens_seat_and_keeps_monotonicity() {
        let mut e = election();
        e.acquire(KEEPER_A, 1_000).unwrap();
        e.step_down(KEEPER_A, 1_010).unwrap();
        assert_eq!(e.leader(), None);
        assert!(!e.is_leader(KEEPER_A, 1_010));
        // Term and token are retained, never rewound.
        assert_eq!(e.term(), 1);
        assert_eq!(e.fencing_token(), 1);
        let audit = e.audit();
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[1].kind, ElectionAuditKind::LeaderSteppedDown);
        assert_eq!(audit[1].term, 1);
        // The next campaign continues the monotonic sequence.
        let grant = e.acquire(KEEPER_B, 1_010).unwrap();
        assert_eq!(grant.term, 2);
        assert_eq!(grant.fencing_token, 2);
    }

    #[test]
    fn step_down_by_non_leader_is_refused() {
        let mut e = election();
        e.acquire(KEEPER_A, 1_000).unwrap();
        assert_eq!(e.step_down(KEEPER_B, 1_010), Err(EscrowError::NotLeader));
        assert_eq!(e.leader(), Some(KEEPER_A));
        let mut e2 = election();
        assert_eq!(e2.step_down(KEEPER_A, 1_010), Err(EscrowError::NotLeader));
    }

    #[test]
    fn fencing_token_monotonic_across_many_takeovers() {
        let mut e = election();
        let keepers = [KEEPER_A, KEEPER_B, KEEPER_C];
        let mut last_token = 0;
        for (i, k) in keepers.iter().cycle().take(9).enumerate() {
            let now = 1_000 + (i as u64) * 31; // each lease lapses (ttl 30)
            let grant = e.acquire(*k, now).unwrap();
            assert_eq!(grant.term, (i + 1) as u64);
            assert!(grant.fencing_token > last_token);
            last_token = grant.fencing_token;
        }
        assert_eq!(last_token, 9);
    }

    #[test]
    fn lease_boundary_is_exclusive() {
        let mut e = election();
        e.acquire(KEEPER_A, 1_000).unwrap();
        assert!(e.is_leader(KEEPER_A, 1_029));
        assert!(!e.is_leader(KEEPER_A, 1_030));
        // Renew one second before expiry still works.
        let mut e2 = election();
        e2.acquire(KEEPER_A, 1_000).unwrap();
        assert!(e2.renew(KEEPER_A, 1_029).is_ok());
        assert_eq!(e2.lease_expires_at(), 1_059);
    }

    #[test]
    fn audit_ring_evicts_oldest() {
        let mut e = election();
        // Alternate acquire/step_down: each pair appends 2 entries.
        let keepers = [KEEPER_A, KEEPER_B];
        for i in 0..(MAX_ELECTION_AUDIT_ENTRIES + 10) {
            let k = keepers[i % 2];
            let now = 1_000 + (i as u64) * 1_000;
            e.acquire(k, now).unwrap();
            e.step_down(k, now + 1).unwrap();
        }
        let audit = e.audit();
        assert_eq!(audit.len(), MAX_ELECTION_AUDIT_ENTRIES);
        // Terms only move forward: the oldest surviving entry has a
        // term strictly greater than 1.
        assert!(audit[0].term > 1);
        for w in audit.windows(2) {
            assert!(w[1].term >= w[0].term);
        }
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(EscrowError::InvalidElectionConfig.code(), 237);
        assert_eq!(EscrowError::ElectionHeld.code(), 238);
        assert_eq!(EscrowError::NotLeader.code(), 239);
        assert_eq!(EscrowError::LeaseExpired.code(), 240);
    }
}
