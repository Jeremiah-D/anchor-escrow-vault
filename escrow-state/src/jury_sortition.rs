//! AV-196: Dispute jury sortition — deterministic verifiable random
//! selection of a juror panel from a staked registry.
//!
//! When an escrow is [`EscrowState::Disputed`](super::EscrowState::Disputed)
//! and the parties opted into jury settlement *instead of* the AV-14
//! single arbiter (the two are mutually exclusive —
//! [`EscrowError::JuryArbiterConflict`]), `K` jurors are drawn from the
//! staked [`JurorRegistry`] by deterministic sortition:
//!
//! ```text
//! seed = sha256(slot_hash || escrow_id)   // public — anyone recomputes
//! panel = Fisher-Yates(seed) over registration order, take K
//! ```
//!
//! The seed is public and the draw is pure: keepers, indexers, and the
//! counterparty can recompute the panel off-chain and verify it
//! ([`JuryPanel::verify`]) — no trusted dealer, no VRF oracle needed.
//! The slot hash is the Solana clock-sysvar slot hash the program
//! passes in; the escrow id binds the draw to one dispute (the same
//! slot hash draws different panels for different escrows).
//!
//! Panel members vote a taker-share in basis points; a strict majority
//! for one share is the [`JuryVerdict`], which replaces the arbiter's
//! `resolve`. The stake is the Sybil-resistance bond (slashable by the
//! program on provable misbehavior) — the draw itself is uniform over
//! registered jurors, which keeps the draw verifiable in O(K) without
//! stake-weighted sampling.
//!
//! Pure logic, `Copy`-friendly fixed arrays, heap-free,
//! `no_std`-friendly. The registry and the panel are standalone
//! structures the program keeps in PDAs; the verdict is applied through
//! the existing release/refund paths.

use crate::{sha256, Escrow, EscrowError, EscrowState};

/// Maximum jurors in a registry — the roster is a fixed array so the
/// crate stays heap-free. A 65th registration is refused fail-closed
/// ([`EscrowError::InvalidJurorRegistry`]).
pub const MAX_JURORS: usize = 64;

/// Serialized tail length of the AV-196 `jury_panel_size` vault field:
/// 1 byte (`0` = no jury — backward compatible).
pub const JURY_PANEL_SIZE_TAIL_LEN: usize = 1;

/// Basis points in a whole (100%).
pub const JURY_BPS_DENOMINATOR: u16 = 10_000;

/// A registered juror: the key and the slashable stake bond.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Juror {
    /// The juror's key.
    pub key: [u8; 32],
    /// The staked bond (slashable on provable misbehavior).
    pub stake: u64,
}

/// The staked juror registry. Registration order is the sortition
/// input order — deterministic given the same registry state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JurorRegistry {
    jurors: [Juror; MAX_JURORS],
    count: u8,
}

/// Deterministic PRNG for the sortition (splitmix64 — 64 bits of state,
/// no tables, `Copy`). Seeded from the draw seed; the draw must be
/// reproducible bit-for-bit by any verifier.
#[derive(Debug, Clone, Copy)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl JurorRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            jurors: [Juror { key: [0u8; 32], stake: 0 }; MAX_JURORS],
            count: 0,
        }
    }

    /// Register a juror with a stake bond. Fail-closed: the zero key,
    /// a zero stake, a duplicate key, or a full book is
    /// [`EscrowError::InvalidJurorRegistry`].
    pub fn register(&mut self, key: [u8; 32], stake: u64) -> Result<(), EscrowError> {
        if key == [0u8; 32] || stake == 0 {
            return Err(EscrowError::InvalidJurorRegistry);
        }
        if self.jurors[..self.count as usize].iter().any(|j| j.key == key) {
            return Err(EscrowError::InvalidJurorRegistry);
        }
        if self.count as usize >= MAX_JURORS {
            return Err(EscrowError::InvalidJurorRegistry);
        }
        self.jurors[self.count as usize] = Juror { key, stake };
        self.count += 1;
        Ok(())
    }

    /// Remove a juror (unstakes the bond off-chain). Unknown key is
    /// [`EscrowError::InvalidJurorRegistry`]. Swap-remove: O(1), and the
    /// draw stays deterministic for the registry state that remains.
    pub fn unregister(&mut self, key: [u8; 32]) -> Result<(), EscrowError> {
        let pos = self.jurors[..self.count as usize]
            .iter()
            .position(|j| j.key == key)
            .ok_or(EscrowError::InvalidJurorRegistry)?;
        let last = self.count as usize - 1;
        self.jurors[pos] = self.jurors[last];
        self.jurors[last] = Juror { key: [0u8; 32], stake: 0 };
        self.count -= 1;
        Ok(())
    }

    /// Registered juror count.
    pub fn len(&self) -> usize {
        self.count as usize
    }

    /// True when no juror is registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The juror at registration-order index `i`.
    pub fn juror(&self, i: usize) -> Option<Juror> {
        (i < self.count as usize).then_some(self.jurors[i])
    }

    /// Draw the jury panel for a disputed escrow. The panel size `K`
    /// comes from the escrow's [`Escrow::with_jury`] configuration —
    /// the draw and the setup agree on `K` by construction.
    ///
    /// Fail-closed: the escrow must be `Disputed`
    /// ([`EscrowError::InvalidStateTransition`] otherwise), must carry
    /// a jury configuration ([`EscrowError::InvalidJurySize`] when the
    /// escrow never opted into jury settlement), and must not carry
    /// the AV-14 single arbiter ([`EscrowError::JuryArbiterConflict`] —
    /// jury and single-arbiter settlement are mutually exclusive). The
    /// registry must hold at least `K` jurors
    /// ([`EscrowError::InvalidJurySize`]).
    ///
    /// The draw is `seed = sha256(slot_hash || escrow_id)` fed through
    /// a partial Fisher-Yates over registration order; the seed is
    /// published on the panel so the draw is verifiable.
    pub fn draw_panel(
        &self,
        escrow: &Escrow,
        escrow_id: [u8; 32],
        slot_hash: [u8; 32],
    ) -> Result<JuryPanel, EscrowError> {
        if escrow.state() != EscrowState::Disputed {
            return Err(EscrowError::InvalidStateTransition);
        }
        if escrow.arbiter().is_some() {
            return Err(EscrowError::JuryArbiterConflict);
        }
        let k = escrow.jury_panel_size();
        if k == 0 {
            return Err(EscrowError::InvalidJurySize);
        }
        let n = self.count as usize;
        let k = k as usize;
        if k > n {
            return Err(EscrowError::InvalidJurySize);
        }
        // The public seed: binds the slot randomness to this dispute.
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&slot_hash);
        preimage[32..].copy_from_slice(&escrow_id);
        let seed = sha256(&preimage);
        let mut rng = SplitMix64(u64::from_le_bytes(seed[..8].try_into().unwrap()));
        // Partial Fisher-Yates: order[0..n], then for i in (n-k)..n
        // swap i with a uniform j in [0, i]; the panel is order[n-k..n].
        let mut order: [usize; MAX_JURORS] = [0; MAX_JURORS];
        for (i, slot) in order.iter_mut().enumerate().take(n) {
            *slot = i;
        }
        for i in (n - k..n).rev() {
            let j = (rng.next() % (i as u64 + 1)) as usize;
            order.swap(i, j);
        }
        let mut members = [[0u8; 32]; MAX_JURORS];
        for (dst, src) in members.iter_mut().zip(order.iter().skip(n - k).take(k)) {
            *dst = self.jurors[*src].key;
        }
        Ok(JuryPanel {
            escrow_id,
            seed,
            members,
            member_count: k as u8,
            voters: [[0u8; 32]; MAX_JURORS],
            shares: [0u16; MAX_JURORS],
            vote_count: 0,
        })
    }
}

impl Default for JurorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The majority verdict: the taker-share the panel converged on, in
/// basis points (0 = full refund to the initializer, 10_000 = full
/// payout to the taker). The program applies it through the existing
/// release/refund paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JuryVerdict {
    /// Taker share in basis points.
    pub taker_share_bps: u16,
}

/// The drawn jury panel for one dispute: the members, the public seed,
/// and the votes cast so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JuryPanel {
    /// The dispute this panel was drawn for.
    pub escrow_id: [u8; 32],
    /// `sha256(slot_hash || escrow_id)` — public, so the draw is
    /// verifiable by recomputation.
    pub seed: [u8; 32],
    members: [[u8; 32]; MAX_JURORS],
    member_count: u8,
    voters: [[u8; 32]; MAX_JURORS],
    shares: [u16; MAX_JURORS],
    vote_count: u8,
}

impl JuryPanel {
    /// The drawn members, in draw order.
    pub fn members(&self) -> &[[u8; 32]] {
        &self.members[..self.member_count as usize]
    }

    /// Panel size.
    pub fn member_count(&self) -> u8 {
        self.member_count
    }

    /// Votes cast so far.
    pub fn vote_count(&self) -> u8 {
        self.vote_count
    }

    /// True for a drawn panel member.
    pub fn is_member(&self, key: [u8; 32]) -> bool {
        self.members().contains(&key)
    }

    /// Cast a juror's vote: the taker-share in basis points this juror
    /// endorses. One vote per member — a second vote is
    /// [`EscrowError::JuryDuplicateVote`]; a non-member is
    /// [`EscrowError::JuryNotPanelMember`]; a share above 10_000 bps is
    /// [`EscrowError::InvalidJuryVote`].
    pub fn cast_vote(
        &mut self,
        juror: [u8; 32],
        taker_share_bps: u16,
    ) -> Result<(), EscrowError> {
        if taker_share_bps > JURY_BPS_DENOMINATOR {
            return Err(EscrowError::InvalidJuryVote);
        }
        if !self.is_member(juror) {
            return Err(EscrowError::JuryNotPanelMember);
        }
        if self.voters[..self.vote_count as usize].contains(&juror) {
            return Err(EscrowError::JuryDuplicateVote);
        }
        let i = self.vote_count as usize;
        self.voters[i] = juror;
        self.shares[i] = taker_share_bps;
        self.vote_count += 1;
        Ok(())
    }

    /// Votes for one taker-share.
    pub fn tally(&self, taker_share_bps: u16) -> u32 {
        self.shares[..self.vote_count as usize]
            .iter()
            .filter(|s| **s == taker_share_bps)
            .count() as u32
    }

    /// The verdict, once a strict majority of the panel (> K/2) votes
    /// the *same* taker-share. Jurors deliberate off-chain to converge
    /// on one number; the panel records the converged outcome.
    pub fn verdict(&self) -> Option<JuryVerdict> {
        let majority = self.member_count as u32 / 2 + 1;
        // The winning share, if any, is among the cast votes.
        let mut seen = [0u16; MAX_JURORS];
        let mut seen_n = 0usize;
        for s in self.shares[..self.vote_count as usize].iter() {
            if !seen[..seen_n].contains(s) {
                seen[seen_n] = *s;
                seen_n += 1;
            }
        }
        for s in seen[..seen_n].iter() {
            if self.tally(*s) >= majority {
                return Some(JuryVerdict { taker_share_bps: *s });
            }
        }
        None
    }

    /// True once [`JuryPanel::verdict`] is `Some`.
    pub fn is_decided(&self) -> bool {
        self.verdict().is_some()
    }

    /// Recompute the draw and check it matches this panel — the
    /// verifiability half of sortition. Re-derives the seed from
    /// `slot_hash` and this panel's `escrow_id`, redraws from the
    /// registry, and compares the member sets.
    pub fn verify(
        &self,
        registry: &JurorRegistry,
        escrow: &Escrow,
        slot_hash: [u8; 32],
    ) -> bool {
        match registry.draw_panel(escrow, self.escrow_id, slot_hash) {
            Ok(redrawn) => redrawn.seed == self.seed && redrawn.members() == self.members(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod jury_sortition_tests {
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const ARB: [u8; 32] = [0xA9; 32];
    const ESCROW_ID: [u8; 32] = [0xE0; 32];
    const SLOT_HASH: [u8; 32] = [0x51; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn juror_key(i: u8) -> [u8; 32] {
        [i; 32]
    }

    fn registry_with(n: u8) -> JurorRegistry {
        let mut r = JurorRegistry::new();
        for i in 1..=n {
            r.register(juror_key(i), 1_000 * i as u64).unwrap();
        }
        r
    }

    fn disputed_escrow() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_jury(5)
            .unwrap();
        e.fund(ALICE, 1_700_000_000).unwrap();
        e.escalate(ALICE, 1_700_000_001, 1_000_000, None, None, 0).unwrap();
        assert_eq!(e.state(), EscrowState::Disputed);
        e
    }

    fn disputed_escrow_with_arbiter() -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter(ARB)
            .unwrap();
        e.fund(ALICE, 1_700_000_000).unwrap();
        e.escalate(ALICE, 1_700_000_001, 1_000_000, None, None, 0).unwrap();
        e
    }

    fn disputed_escrow_with_size(k: u8) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_jury(k)
            .unwrap();
        e.fund(ALICE, 1_700_000_000).unwrap();
        e.escalate(ALICE, 1_700_000_001, 1_000_000, None, None, 0).unwrap();
        assert_eq!(e.state(), EscrowState::Disputed);
        e
    }

    fn disputed_escrow_with_panel() -> Escrow {        // AV-65 panel mode: Disputed, but no jury and no single arbiter.
        let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_arbiter_panel(&[[0xA1; 32], [0xA2; 32]], 2)
            .unwrap();
        e.fund(ALICE, 1_700_000_000).unwrap();
        e.escalate(ALICE, 1_700_000_001, 1_000_000, None, None, 0).unwrap();
        assert_eq!(e.state(), EscrowState::Disputed);
        e
    }

    #[test]
    fn with_jury_is_fail_closed_and_mutually_exclusive() {
        // Zero or over-64 panel size.
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap().with_jury(0),
            Err(EscrowError::InvalidJurySize)
        );
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap().with_jury(65),
            Err(EscrowError::InvalidJurySize)
        );
        // Single arbiter first, then jury: refused.
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
                .unwrap()
                .with_arbiter(ARB)
                .unwrap()
                .with_jury(5),
            Err(EscrowError::JuryArbiterConflict)
        );
        // Jury first, then single arbiter: refused (either-or).
        assert_eq!(
            Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
                .unwrap()
                .with_jury(5)
                .unwrap()
                .with_arbiter(ARB),
            Err(EscrowError::JuryArbiterConflict)
        );
        // Uninitialized only.
        let live = disputed_escrow();
        assert_eq!(live.jury_panel_size(), 5);
        assert_eq!(
            live.with_jury(5),
            Err(EscrowError::InvalidStateTransition)
        );
        // Boundary-valid: 1 and 64.
        assert!(Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap().with_jury(1).is_ok());
        assert!(Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap().with_jury(64).is_ok());
    }

    #[test]
    fn register_is_fail_closed() {
        let mut r = JurorRegistry::new();
        assert_eq!(
            r.register([0u8; 32], 1_000),
            Err(EscrowError::InvalidJurorRegistry)
        );
        assert_eq!(
            r.register(juror_key(1), 0),
            Err(EscrowError::InvalidJurorRegistry)
        );
        r.register(juror_key(1), 1_000).unwrap();
        // Duplicate.
        assert_eq!(
            r.register(juror_key(1), 2_000),
            Err(EscrowError::InvalidJurorRegistry)
        );
        // Book full.
        let mut full = JurorRegistry::new();
        for i in 1..=MAX_JURORS as u8 {
            full.register(juror_key(i), 1).unwrap();
        }
        assert_eq!(
            full.register([0xFF; 32], 1),
            Err(EscrowError::InvalidJurorRegistry)
        );
        // Unregister unknown.
        assert_eq!(
            r.unregister([0xEE; 32]),
            Err(EscrowError::InvalidJurorRegistry)
        );
        // Unregister works and keeps the rest.
        r.register(juror_key(2), 2_000).unwrap();
        r.unregister(juror_key(1)).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r.juror(0).unwrap().key, juror_key(2));
    }

    #[test]
    fn draw_gates_state_arbiter_jury_and_registry_size() {
        let r = registry_with(10);
        let live = disputed_escrow();
        // Not disputed.
        let mut funded = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
        funded.fund(ALICE, 1_700_000_000).unwrap();
        assert_eq!(
            r.draw_panel(&funded, ESCROW_ID, SLOT_HASH),
            Err(EscrowError::InvalidStateTransition)
        );
        // Single arbiter configured: mutually exclusive with the jury.
        let with_arb = disputed_escrow_with_arbiter();
        assert_eq!(
            r.draw_panel(&with_arb, ESCROW_ID, SLOT_HASH),
            Err(EscrowError::JuryArbiterConflict)
        );
        // Disputed but no jury configured (panel mode): no panel size.
        let panel_mode = disputed_escrow_with_panel();
        assert_eq!(
            r.draw_panel(&panel_mode, ESCROW_ID, SLOT_HASH),
            Err(EscrowError::InvalidJurySize)
        );
        // Registry smaller than the configured jury size.
        let small = registry_with(3);
        assert_eq!(
            small.draw_panel(&live, ESCROW_ID, SLOT_HASH),
            Err(EscrowError::InvalidJurySize)
        );
        // Registry exactly the jury size draws everyone.
        let exact = registry_with(5);
        let full = exact.draw_panel(&live, ESCROW_ID, SLOT_HASH).unwrap();
        assert_eq!(full.member_count(), 5);
    }

    #[test]
    fn draw_is_deterministic_and_seed_is_public() {
        let r = registry_with(20);
        let live = disputed_escrow();
        let a = r.draw_panel(&live, ESCROW_ID, SLOT_HASH).unwrap();
        let b = r.draw_panel(&live, ESCROW_ID, SLOT_HASH).unwrap();
        assert_eq!(a.members(), b.members());
        assert_eq!(a.seed, b.seed);
        // The published seed is exactly sha256(slot_hash || escrow_id).
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&SLOT_HASH);
        preimage[32..].copy_from_slice(&ESCROW_ID);
        assert_eq!(a.seed, sha256(&preimage));
        // A different escrow id binds a different seed (deterministic).
        let c = r.draw_panel(&live, [0xE1; 32], SLOT_HASH).unwrap();
        assert_ne!(a.seed, c.seed);
    }

    #[test]
    fn verify_recomputes_the_draw() {
        let r = registry_with(20);
        let live = disputed_escrow();
        let panel = r.draw_panel(&live, ESCROW_ID, SLOT_HASH).unwrap();
        assert!(panel.verify(&r, &live, SLOT_HASH));
        // Wrong slot hash: the recomputed draw differs.
        assert!(!panel.verify(&r, &live, [0x52; 32]));
        // A tampered panel fails verification.
        let mut tampered = panel;
        tampered.members[0] = [0xFF; 32];
        assert!(!tampered.verify(&r, &live, SLOT_HASH));
    }

    #[test]
    fn cast_vote_rejects_bad_votes() {
        let r = registry_with(10);
        let live = disputed_escrow();
        let sized = disputed_escrow_with_size(3);
        let mut panel = r.draw_panel(&sized, ESCROW_ID, SLOT_HASH).unwrap();
        let member = panel.members()[0];
        // Non-member.
        assert_eq!(
            panel.cast_vote([0xEE; 32], 5_000),
            Err(EscrowError::JuryNotPanelMember)
        );
        // Share above 10_000 bps.
        assert_eq!(
            panel.cast_vote(member, 10_001),
            Err(EscrowError::InvalidJuryVote)
        );
        panel.cast_vote(member, 5_000).unwrap();
        // Double vote.
        assert_eq!(
            panel.cast_vote(member, 5_000),
            Err(EscrowError::JuryDuplicateVote)
        );
        assert_eq!(panel.vote_count(), 1);
    }

    #[test]
    fn verdict_needs_a_strict_majority_for_one_share() {
        let r = registry_with(10);
        let live = disputed_escrow();
        let mut panel = r.draw_panel(&live, ESCROW_ID, SLOT_HASH).unwrap();
        let m = panel.members().to_vec();
        // Two votes for 6_000: not a majority of 5.
        panel.cast_vote(m[0], 6_000).unwrap();
        panel.cast_vote(m[1], 6_000).unwrap();
        assert!(!panel.is_decided());
        assert_eq!(panel.verdict(), None);
        // A third vote for a *different* share: still no majority.
        panel.cast_vote(m[2], 4_000).unwrap();
        assert_eq!(panel.verdict(), None);
        // Two more for 6_000: 4 of 5 — decided.
        panel.cast_vote(m[3], 6_000).unwrap();
        panel.cast_vote(m[4], 6_000).unwrap();
        assert!(panel.is_decided());
        assert_eq!(
            panel.verdict(),
            Some(JuryVerdict { taker_share_bps: 6_000 })
        );
        assert_eq!(panel.tally(6_000), 4);
        assert_eq!(panel.tally(4_000), 1);
    }

    #[test]
    fn majority_boundary_on_even_panel() {
        let r = registry_with(10);
        let live = disputed_escrow();
        let sized = disputed_escrow_with_size(4);
        let mut panel = r.draw_panel(&sized, ESCROW_ID, SLOT_HASH).unwrap();
        let m = panel.members().to_vec();
        // 2 of 4 is not a strict majority.
        panel.cast_vote(m[0], 10_000).unwrap();
        panel.cast_vote(m[1], 10_000).unwrap();
        assert!(!panel.is_decided());
        panel.cast_vote(m[2], 10_000).unwrap();
        assert!(panel.is_decided());
    }

    #[test]
    fn error_codes_pinned() {
        // Never renumber: the Anchor layer assigns one program error
        // per variant and off-chain clients match on these numbers.
        assert_eq!(EscrowError::InvalidJurorRegistry.code(), 293);
        assert_eq!(EscrowError::InvalidJurySize.code(), 294);
        assert_eq!(EscrowError::JuryNotPanelMember.code(), 295);
        assert_eq!(EscrowError::JuryDuplicateVote.code(), 296);
        assert_eq!(EscrowError::InvalidJuryVote.code(), 297);
        assert_eq!(EscrowError::JuryArbiterConflict.code(), 298);
        for e in [
            EscrowError::InvalidJurorRegistry,
            EscrowError::InvalidJurySize,
            EscrowError::JuryNotPanelMember,
            EscrowError::JuryDuplicateVote,
            EscrowError::InvalidJuryVote,
            EscrowError::JuryArbiterConflict,
        ] {
            assert!(EscrowError::all().contains(&e));
        }
        // AV-196 appends 6 jury-sortition errors after AV-195's
        // RecoveryTimelockNotElapsed (292); AV-197 appends 5
        // payment-channel errors after AV-196's JuryArbiterConflict (298).
        assert_eq!(EscrowError::all().len(), 220); // AV-209: +4 winner-payment errors
    }
}
