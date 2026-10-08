//! Off-chain escrow state snapshot (AV-26): a point-in-time, read-only
//! view of an [`Escrow`] as canonical JSON, for keeper bots and indexers
//! that reconcile off-chain state against the chain.
//!
//! A keeper watching many vaults (see [`crate::scan_keeper_actions`]) or
//! an indexer feeding a database both need the same primitive: "what does
//! this escrow look like right now?" [`Escrow::snapshot`] answers that
//! with every raw field plus the derived quantities an operator actually
//! reasons about:
//!
//! - `remaining`: what `cancel` / `cancel_expired` would refund right now;
//! - `vested` / `claimable`: the streaming-payments position at the
//!   snapshot time (`vested` is the schedule's unlock, `claimable` is
//!   vested-minus-already-released, i.e. what `claim` would move);
//! - quorum progress: `approvals` of `threshold` (of `registered`), and
//!   whether the quorum is already satisfied for a `release`;
//! - milestone progress: per-tranche amounts with their confirmation and
//!   settlement bits, plus the index of the next unsettled tranche;
//! - `expiry_eligible`: whether the chain's `cancel_expired` gate passes
//!   at the snapshot time (grace period included — the same predicate the
//!   keeper scan uses, so a snapshot never disagrees with the scan).
//!
//! Like [`crate::KeeperReport::to_json`], [`EscrowSnapshot::to_json`]
//! hand-serializes (the crate is dependency-free): deterministic field
//! order, 32-byte keys as 64-char lowercase hex, `Option` fields as a hex
//! string or `null`. Two snapshots of equal state at equal `now` are
//! byte-identical, so indexers can hash or diff them directly.
//!
//! The snapshot is a pure read: it borrows the escrow, emits no events,
//! and advances no state — a dry run by construction.

use crate::{Escrow, EscrowState};

/// Render 32 bytes as 64 lowercase hex characters (same convention as
/// [`crate::keeper`]'s serializer).
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Canonical name for a lifecycle state in snapshot JSON.
fn state_name(state: EscrowState) -> &'static str {
    match state {
        EscrowState::Uninitialized => "uninitialized",
        EscrowState::Funded => "funded",
        EscrowState::Released => "released",
        EscrowState::Cancelled => "cancelled",
        EscrowState::Activated => "activated",
        EscrowState::Disputed => "disputed",
        EscrowState::Settled => "settled",
    }
}

/// Dual-signature activation progress (AV-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualSigSnapshot {
    /// Whether both parties must activate before funding.
    pub required: bool,
    /// Whether the initializer recorded its activation signature.
    pub initializer_activated: bool,
    /// Whether the taker recorded its activation signature.
    pub taker_activated: bool,
}

/// N-of-M quorum progress (AV-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumSnapshot {
    /// The M: registered attestors.
    pub registered: u8,
    /// The N: distinct approvals required.
    pub threshold: u8,
    /// Distinct attestors that have attested so far.
    pub approvals: u8,
    /// Whether `approvals >= threshold` — a `release` would pass the
    /// quorum gate right now.
    pub satisfied: bool,
}

/// Linear vesting schedule (AV-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VestingSnapshot {
    /// Unix seconds: unlock starts.
    pub start: u64,
    /// Unix seconds: fully unlocked.
    pub end: u64,
}

/// One milestone tranche (AV-15): the tranche amount plus its
/// confirmation and settlement bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MilestoneTrancheSnapshot {
    /// Tranche index, in release order.
    pub index: usize,
    /// Tranche amount.
    pub amount: u64,
    /// Both parties confirmed the release path.
    pub confirmed: bool,
    /// The tranche was released or skipped — terminal for this tranche.
    pub settled: bool,
}

/// Milestone plan progress (AV-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MilestoneSnapshot {
    /// Number of tranches.
    pub count: u8,
    /// Exact sum of the tranche amounts (`u128`: never wraps).
    pub total: u128,
    /// How many tranches are settled (released or skipped).
    pub settled: usize,
    /// How many tranches are confirmed for the release path.
    pub confirmed: usize,
    /// Index of the first unsettled tranche, or `None` when every
    /// tranche is settled.
    pub next: Option<usize>,
    /// Per-tranche detail, in release order.
    pub tranches: Vec<MilestoneTrancheSnapshot>,
}

/// Point-in-time, read-only view of an [`Escrow`]. Built by
/// [`Escrow::snapshot`]; serialized by [`EscrowSnapshot::to_json`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowSnapshot {
    /// The `now` (Unix seconds) the snapshot was taken at. All
    /// time-derived fields (`vested`, `claimable`, `expiry_eligible`)
    /// are evaluated at this clock.
    pub at: u64,
    /// The escrow initializer (refund recipient by default).
    pub initializer: [u8; 32],
    /// The escrow taker (payout recipient).
    pub taker: [u8; 32],
    /// Lifecycle state, as a canonical lowercase name.
    pub state: &'static str,
    /// Total amount ever locked.
    pub amount: u64,
    /// Cumulative amount released to the taker so far.
    pub released: u64,
    /// Amount still locked: `amount - released`. This is what `cancel` /
    /// `cancel_expired` refund (skipped milestone tranches join it).
    pub remaining: u64,
    /// Unix seconds after which either party may cancel via
    /// `cancel_expired` (grace period applies separately).
    pub expires_at: u64,
    /// AV-21 grace period in seconds: the chain requires
    /// `now >= expires_at + grace_period`.
    pub grace_period: u64,
    /// Whether the chain's `cancel_expired` expiry gate passes at
    /// [`EscrowSnapshot::at`]. Same predicate the keeper scan uses.
    pub expiry_eligible: bool,
    /// Dual-signature activation progress (AV-12).
    pub dual_sig: DualSigSnapshot,
    /// Quorum progress, or `None` for a plain two-party escrow (AV-04).
    pub quorum: Option<QuorumSnapshot>,
    /// Vesting schedule, or `None` when none is attached (AV-13).
    pub vesting: Option<VestingSnapshot>,
    /// Amount unlocked by the schedule at [`EscrowSnapshot::at`], or `0`
    /// when no vesting is configured.
    pub vested: u64,
    /// Amount the taker could `claim` right now: vested minus already
    /// released, saturating at zero. `0` without vesting.
    pub claimable: u64,
    /// Dispute arbiter, or `None` when none is attached (AV-14).
    pub arbiter: Option<[u8; 32]>,
    /// SPL token mint bound to this escrow, or `None` for native SOL
    /// (AV-16).
    pub mint: Option<[u8; 32]>,
    /// Protocol fee rate in basis points (AV-17).
    pub fee_bps: u16,
    /// Cumulative protocol fee charged across all payouts (AV-17).
    pub fees_paid: u64,
    /// Milestone plan progress, or `None` when none is attached
    /// (AV-15).
    pub milestones: Option<MilestoneSnapshot>,
    /// Cumulative amount skipped by mutual agreement (AV-15).
    pub skipped: u64,
    /// Dispute evidence commitment attached at `escalate`, or `None`
    /// when no evidence was supplied (AV-22).
    pub evidence_hash: Option<[u8; 32]>,
    /// Whitelisted refund destination, or `None` when no whitelist is
    /// configured (AV-23).
    pub refund_to: Option<[u8; 32]>,
    /// The address refunds actually go to: the whitelist when
    /// configured, else the initializer (AV-23).
    pub refund_recipient: [u8; 32],
    /// Anti-griefing penalty rate in basis points charged on
    /// taker-initiated `cancel_expired` (AV-24).
    pub penalty_bps: u16,
}

impl Escrow {
    /// Take a point-in-time, read-only snapshot of this escrow at `now`.
    /// Pure read: the escrow is borrowed, no state changes, no events —
    /// a keeper or indexer can call this on every watched escrow on
    /// every scan without side effects.
    pub fn snapshot(&self, now: u64) -> EscrowSnapshot {
        let milestones = self.milestone_plan().map(|plan| {
            let count = plan.count() as usize;
            let mut settled = 0usize;
            let mut confirmed = 0usize;
            let mut tranches = Vec::with_capacity(count);
            for i in 0..count {
                let is_settled = self.milestone_settled(i);
                let is_confirmed = self.milestone_confirmed(i);
                if is_settled {
                    settled += 1;
                }
                if is_confirmed {
                    confirmed += 1;
                }
                tranches.push(MilestoneTrancheSnapshot {
                    index: i,
                    // The plan guarantees `Some` for `i < count`.
                    amount: plan.amount_at(i).unwrap_or(0),
                    confirmed: is_confirmed,
                    settled: is_settled,
                });
            }
            MilestoneSnapshot {
                count: plan.count(),
                total: plan.total(),
                settled,
                confirmed,
                next: self.next_milestone(),
                tranches,
            }
        });
        EscrowSnapshot {
            at: now,
            initializer: self.initializer(),
            taker: self.taker(),
            state: state_name(self.state()),
            amount: self.amount(),
            released: self.released_amount(),
            remaining: self.remaining_amount(),
            expires_at: self.expires_at(),
            grace_period: self.grace_period(),
            expiry_eligible: self.is_expiry_eligible(now),
            dual_sig: DualSigSnapshot {
                required: self.dual_sig_required(),
                initializer_activated: self.initializer_activated(),
                taker_activated: self.taker_activated(),
            },
            quorum: self.quorum().map(|q| QuorumSnapshot {
                registered: q.registered_count(),
                threshold: q.threshold(),
                approvals: q.approval_count(),
                satisfied: q.is_satisfied(),
            }),
            vesting: self.vesting_schedule().map(|s| VestingSnapshot {
                start: s.start(),
                end: s.end(),
            }),
            vested: self.vested_amount(now),
            claimable: self.claimable_amount(now),
            arbiter: self.arbiter(),
            mint: self.mint(),
            fee_bps: self.fee_bps(),
            fees_paid: self.fees_paid(),
            milestones,
            skipped: self.skipped_amount(),
            evidence_hash: self.evidence_hash(),
            refund_to: self.refund_to(),
            refund_recipient: self.refund_recipient(),
            penalty_bps: self.penalty_bps(),
        }
    }
}

/// Write an `Option<[u8; 32]>` as a 64-char lowercase hex string or
/// `null`.
fn write_opt_hex(s: &mut String, value: Option<[u8; 32]>) {
    match value {
        Some(v) => {
            s.push('"');
            s.push_str(&hex32(&v));
            s.push('"');
        }
        None => s.push_str("null"),
    }
}

impl EscrowSnapshot {
    /// Hand-serialized canonical JSON (the crate is dependency-free).
    /// Deterministic field order; 32-byte keys are 64-char lowercase
    /// hex; absent options are `null`. Byte-identical for equal state at
    /// equal `at`, so indexers can hash or diff snapshots directly.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(1024);
        s.push_str("{\"at\":");
        s.push_str(&self.at.to_string());
        s.push_str(",\"initializer\":\"");
        s.push_str(&hex32(&self.initializer));
        s.push_str("\",\"taker\":\"");
        s.push_str(&hex32(&self.taker));
        s.push_str("\",\"state\":\"");
        s.push_str(self.state);
        s.push_str("\",\"amount\":");
        s.push_str(&self.amount.to_string());
        s.push_str(",\"released\":");
        s.push_str(&self.released.to_string());
        s.push_str(",\"remaining\":");
        s.push_str(&self.remaining.to_string());
        s.push_str(",\"expires_at\":");
        s.push_str(&self.expires_at.to_string());
        s.push_str(",\"grace_period\":");
        s.push_str(&self.grace_period.to_string());
        s.push_str(",\"expiry_eligible\":");
        s.push_str(if self.expiry_eligible { "true" } else { "false" });
        // AV-12: dual-signature activation progress.
        s.push_str(",\"dual_sig\":{\"required\":");
        s.push_str(if self.dual_sig.required { "true" } else { "false" });
        s.push_str(",\"initializer_activated\":");
        s.push_str(if self.dual_sig.initializer_activated {
            "true"
        } else {
            "false"
        });
        s.push_str(",\"taker_activated\":");
        s.push_str(if self.dual_sig.taker_activated {
            "true"
        } else {
            "false"
        });
        s.push('}');
        // AV-04: quorum progress.
        s.push_str(",\"quorum\":");
        match self.quorum {
            Some(q) => {
                s.push_str("{\"registered\":");
                s.push_str(&q.registered.to_string());
                s.push_str(",\"threshold\":");
                s.push_str(&q.threshold.to_string());
                s.push_str(",\"approvals\":");
                s.push_str(&q.approvals.to_string());
                s.push_str(",\"satisfied\":");
                s.push_str(if q.satisfied { "true" } else { "false" });
                s.push('}');
            }
            None => s.push_str("null"),
        }
        // AV-13: vesting schedule and its position at `at`.
        s.push_str(",\"vesting\":");
        match self.vesting {
            Some(v) => {
                s.push_str("{\"start\":");
                s.push_str(&v.start.to_string());
                s.push_str(",\"end\":");
                s.push_str(&v.end.to_string());
                s.push('}');
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"vested\":");
        s.push_str(&self.vested.to_string());
        s.push_str(",\"claimable\":");
        s.push_str(&self.claimable.to_string());
        s.push_str(",\"arbiter\":");
        write_opt_hex(&mut s, self.arbiter);
        s.push_str(",\"mint\":");
        write_opt_hex(&mut s, self.mint);
        s.push_str(",\"fee_bps\":");
        s.push_str(&self.fee_bps.to_string());
        s.push_str(",\"fees_paid\":");
        s.push_str(&self.fees_paid.to_string());
        // AV-15: milestone plan progress.
        s.push_str(",\"milestones\":");
        match &self.milestones {
            Some(m) => {
                s.push_str("{\"count\":");
                s.push_str(&m.count.to_string());
                s.push_str(",\"total\":");
                s.push_str(&m.total.to_string());
                s.push_str(",\"settled\":");
                s.push_str(&m.settled.to_string());
                s.push_str(",\"confirmed\":");
                s.push_str(&m.confirmed.to_string());
                s.push_str(",\"next\":");
                match m.next {
                    Some(n) => s.push_str(&n.to_string()),
                    None => s.push_str("null"),
                }
                s.push_str(",\"tranches\":[");
                for (i, t) in m.tranches.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str("{\"index\":");
                    s.push_str(&t.index.to_string());
                    s.push_str(",\"amount\":");
                    s.push_str(&t.amount.to_string());
                    s.push_str(",\"confirmed\":");
                    s.push_str(if t.confirmed { "true" } else { "false" });
                    s.push_str(",\"settled\":");
                    s.push_str(if t.settled { "true" } else { "false" });
                    s.push('}');
                }
                s.push_str("]}");
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"skipped\":");
        s.push_str(&self.skipped.to_string());
        s.push_str(",\"evidence_hash\":");
        write_opt_hex(&mut s, self.evidence_hash);
        s.push_str(",\"refund_to\":");
        write_opt_hex(&mut s, self.refund_to);
        s.push_str(",\"refund_recipient\":\"");
        s.push_str(&hex32(&self.refund_recipient));
        s.push_str("\",\"penalty_bps\":");
        s.push_str(&self.penalty_bps.to_string());
        s.push('}');
        s
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::{MilestonePlan, QuorumPolicy, VestingSchedule};

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const A1: [u8; 32] = [0xA1; 32]; // attestors
    const A2: [u8; 32] = [0xA2; 32];
    const A3: [u8; 32] = [0xA3; 32];
    const MINT: [u8; 32] = [0xD0; 32];
    const ARBITER: [u8; 32] = [0xA8; 32];
    const AMOUNT: u64 = 1_000_000;
    const VEST_START: u64 = 1_700_000_000;
    const VEST_END: u64 = 1_800_000_000;
    const MID: u64 = 1_750_000_000; // half-vested
    const NEVER: u64 = u64::MAX; // no timeout

    fn funded(amount: u64, expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, amount, expires_at).unwrap();
        e.fund(ALICE).unwrap();
        e
    }

    fn hex_of(byte: u8) -> String {
        format!("{:02x}", byte).repeat(32)
    }

    #[test]
    fn plain_funded_snapshot_json_is_pinned() {
        let snap = funded(AMOUNT, 0).snapshot(MID);
        let expected = format!(
            "{{\
             \"at\":1750000000,\
             \"initializer\":\"{init}\",\"taker\":\"{taker}\",\
             \"state\":\"funded\",\
             \"amount\":1000000,\"released\":0,\"remaining\":1000000,\
             \"expires_at\":0,\"grace_period\":0,\"expiry_eligible\":true,\
             \"dual_sig\":{{\"required\":false,\"initializer_activated\":false,\"taker_activated\":false}},\
             \"quorum\":null,\
             \"vesting\":null,\"vested\":0,\"claimable\":0,\
             \"arbiter\":null,\"mint\":null,\
             \"fee_bps\":0,\"fees_paid\":0,\
             \"milestones\":null,\
             \"skipped\":0,\
             \"evidence_hash\":null,\"refund_to\":null,\"refund_recipient\":\"{init}\",\
             \"penalty_bps\":0\
             }}",
            init = hex_of(0xAA),
            taker = hex_of(0xBB),
        );
        assert_eq!(snap.to_json(), expected);
    }

    #[test]
    fn snapshot_is_dry_run_and_deterministic() {
        let e = funded(AMOUNT, NEVER);
        let before = e;
        let a = e.snapshot(MID).to_json();
        let b = e.snapshot(MID).to_json();
        assert_eq!(a, b, "equal state at equal `at` must serialize byte-identically");
        // The escrow is untouched: bit-identical afterwards (Escrow is
        // Copy + PartialEq, so this is exact).
        assert_eq!(e, before, "snapshot must not mutate the escrow");
    }

    #[test]
    fn vesting_position_is_derived_at_snapshot_time() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap();
        e.fund(ALICE).unwrap();
        // Before the schedule starts: nothing vested.
        let snap = e.snapshot(VEST_START - 1);
        assert_eq!(snap.vested, 0);
        assert_eq!(snap.claimable, 0);
        assert_eq!(snap.vesting, Some(VestingSnapshot { start: VEST_START, end: VEST_END }));
        // Halfway: half vested, all claimable (nothing released yet).
        let snap = e.snapshot(MID);
        assert_eq!(snap.vested, 500_000);
        assert_eq!(snap.claimable, 500_000);
        // After the schedule ends: fully vested.
        let snap = e.snapshot(VEST_END + 1);
        assert_eq!(snap.vested, AMOUNT);
        assert_eq!(snap.claimable, AMOUNT);
        let json = snap.to_json();
        assert!(
            json.contains("\"vesting\":{\"start\":1700000000,\"end\":1800000000}"),
            "vesting window must serialize, got: {json}"
        );
        assert!(json.contains("\"vested\":1000000,\"claimable\":1000000"));
    }

    #[test]
    fn claimable_is_vested_minus_released() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap();
        e.fund(ALICE).unwrap();
        e.release(ALICE, 200_000, None).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.released, 200_000);
        assert_eq!(snap.remaining, 800_000);
        assert_eq!(snap.claimable, 300_000); // 500_000 vested - 200_000 released
    }

    #[test]
    fn quorum_progress_is_derived() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_quorum(QuorumPolicy::new(&[A1, A2, A3], 2).unwrap())
            .unwrap();
        e.fund(ALICE).unwrap();
        e.attest(A1).unwrap();
        let snap = e.snapshot(MID);
        let q = snap.quorum.expect("quorum must snapshot");
        assert_eq!(q.registered, 3);
        assert_eq!(q.threshold, 2);
        assert_eq!(q.approvals, 1);
        assert!(!q.satisfied);
        let json = snap.to_json();
        assert!(
            json.contains("\"quorum\":{\"registered\":3,\"threshold\":2,\"approvals\":1,\"satisfied\":false}"),
            "quorum progress must serialize, got: {json}"
        );
        // Satisfy it: the snapshot flips without any state transition.
        let mut e2 = e;
        e2.attest(A2).unwrap();
        let q2 = e2.snapshot(MID).quorum.expect("quorum must snapshot");
        assert!(q2.satisfied);
        assert_eq!(q2.approvals, 2);
    }

    #[test]
    fn milestone_progress_is_derived_per_tranche() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
            .unwrap();
        e.fund(ALICE).unwrap();
        // Both parties confirm tranche 0 for the release path.
        e.confirm_milestone(ALICE, 0).unwrap();
        e.confirm_milestone(BOB, 0).unwrap();
        let snap = e.snapshot(MID);
        let m = snap.milestones.as_ref().expect("plan must snapshot");
        assert_eq!(m.count, 2);
        assert_eq!(m.total, 1_000_000u128);
        assert_eq!(m.settled, 0);
        assert_eq!(m.confirmed, 1);
        assert_eq!(m.next, Some(0));
        assert_eq!(
            m.tranches[0],
            MilestoneTrancheSnapshot {
                index: 0,
                amount: 400_000,
                confirmed: true,
                settled: false,
            }
        );
        assert!(!m.tranches[1].confirmed);
        // Release tranche 0: it settles, tranche 1 becomes next. The
        // confirmation bits persist — they record that the tranche was
        // duly confirmed, even after settlement.
        e.release_milestone(ALICE, 0, None).unwrap();
        let snap = e.snapshot(MID);
        let m = snap.milestones.as_ref().expect("plan must snapshot");
        assert_eq!(m.settled, 1);
        assert_eq!(m.confirmed, 1);
        assert_eq!(m.next, Some(1));
        assert_eq!(snap.released, 400_000);
        assert_eq!(snap.remaining, 600_000);
        let json = snap.to_json();
        assert!(
            json.contains("\"milestones\":{\"count\":2,\"total\":1000000,\"settled\":1,\"confirmed\":1,\"next\":1,\"tranches\":[{\"index\":0,\"amount\":400000,\"confirmed\":true,\"settled\":true},{\"index\":1,\"amount\":600000,\"confirmed\":false,\"settled\":false}]}"),
            "milestone progress must serialize, got: {json}"
        );
    }

    #[test]
    fn expiry_eligible_honors_the_grace_period() {
        const GRACE: u64 = 300;
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, MID)
            .unwrap()
            .with_grace_period(GRACE)
            .unwrap();
        e.fund(ALICE).unwrap();
        assert!(!e.snapshot(MID).expiry_eligible);
        assert!(!e.snapshot(MID + GRACE - 1).expiry_eligible);
        assert!(e.snapshot(MID + GRACE).expiry_eligible);
        assert!(e.snapshot(MID).to_json().contains("\"expiry_eligible\":false"));
    }

    #[test]
    fn disputed_snapshot_carries_arbiter_and_evidence() {
        const EVIDENCE: [u8; 32] = [0xE1; 32];
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, NEVER)
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.fund(ALICE).unwrap();
        e.escalate(BOB, MID, Some(EVIDENCE)).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.state, "disputed");
        assert_eq!(snap.arbiter, Some(ARBITER));
        assert_eq!(snap.evidence_hash, Some(EVIDENCE));
        let json = snap.to_json();
        assert!(json.contains(&format!("\"arbiter\":\"{}\"", hex_of(0xA8))));
        assert!(json.contains(&format!("\"evidence_hash\":\"{}\"", hex_of(0xE1))));
    }

    #[test]
    fn full_configuration_snapshot() {
        // Every opt-in feature on one escrow: the snapshot must carry
        // each of them, and the derived fields must agree.
        const WHITELIST: [u8; 32] = [0xC4; 32];
        // A finite expiry (grace periods are rejected on no-timeout
        // escrows), placed after the snapshot time so the escrow is not
        // expiry-eligible at MID.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, VEST_END + 1_000)
            .unwrap()
            .with_dual_sig()
            .unwrap()
            .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
            .unwrap()
            .with_mint(MINT)
            .unwrap()
            .with_protocol_fee(100)
            .unwrap()
            .with_grace_period(60)
            .unwrap()
            .with_refund_address(WHITELIST)
            .unwrap()
            .with_penalty_bps(500)
            .unwrap();
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        e.fund(ALICE).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.state, "funded");
        assert!(snap.dual_sig.required);
        assert!(snap.dual_sig.initializer_activated);
        assert!(snap.dual_sig.taker_activated);
        assert_eq!(snap.mint, Some(MINT));
        assert_eq!(snap.fee_bps, 100);
        assert_eq!(snap.fees_paid, 0);
        assert_eq!(snap.grace_period, 60);
        assert_eq!(snap.refund_to, Some(WHITELIST));
        assert_eq!(snap.refund_recipient, WHITELIST);
        assert_eq!(snap.penalty_bps, 500);
        assert_eq!(snap.vested, 500_000);
        assert_eq!(snap.claimable, 500_000);
        assert!(!snap.expiry_eligible); // MID < expires_at + grace
        // A 1% fee'd claim: fees accumulate on the snapshot too.
        e.claim(BOB, MID, Some(MINT)).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.released, 500_000);
        assert_eq!(snap.fees_paid, 5_000); // 1% of 500_000
        assert_eq!(snap.remaining, 500_000);
        assert_eq!(snap.claimable, 0);
        let json = snap.to_json();
        assert!(json.contains(&format!("\"mint\":\"{}\"", hex_of(0xD0))));
        assert!(json.contains(&format!("\"refund_recipient\":\"{}\"", hex_of(0xC4))));
        assert!(json.contains("\"fee_bps\":100,\"fees_paid\":5000"));
        assert!(json.contains("\"penalty_bps\":500"));
    }

    #[test]
    fn terminal_states_snapshot_honestly() {
        let mut e = funded(AMOUNT, NEVER);
        e.release(ALICE, AMOUNT, None).unwrap();
        let snap = e.snapshot(MID);
        assert_eq!(snap.state, "released");
        assert_eq!(snap.released, AMOUNT);
        assert_eq!(snap.remaining, 0);
        assert_eq!(snap.claimable, 0);
    }

    #[test]
    fn uninitialized_snapshot() {
        let e = Escrow::initialize(ALICE, BOB, AMOUNT, MID).unwrap();
        let snap = e.snapshot(0);
        assert_eq!(snap.state, "uninitialized");
        assert_eq!(snap.remaining, AMOUNT);
        assert!(!snap.expiry_eligible);
    }
}
