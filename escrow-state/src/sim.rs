//! AV-30: deterministic off-chain concurrent simulation runner (test-only).
//!
//! Drives several escrows through pseudo-concurrent interleavings: every
//! step advances a shared clock, picks a random live escrow, and applies
//! either a state-valid operation or a deliberately-invalid probe. After
//! every step the runner asserts, for every escrow:
//!
//! - amount conservation: `deposited == paid_out + refunded + locked`;
//! - the protocol-fee bound: `fees_paid <= released`;
//! - probe operations fail with exactly the documented error, verifying
//!   the check order (authority -> state -> config -> amount) under
//!   interleaving.
//!
//! Seeded xorshift64*: every run is bit-reproducible (`sim_deterministic`
//! pins that), and CI runs the whole suite via `cargo test -p escrow-state`.
//! True OS-thread concurrency is deliberately out of scope: the transition
//! methods take `&mut self`, so the realistic concurrency model is a keeper
//! interleaving operations across escrows — exactly what this runner does.

use super::*;

// ---------------------------------------------------------------------------
// Deterministic RNG (xorshift64*, same construction as the other test-only
// generators in this crate).
// ---------------------------------------------------------------------------

struct SimRng(u64);

impl SimRng {
    fn new(seed: u64) -> Self {
        // SplitMix-style seed mixing + never-zero state.
        let mut z = seed
            .wrapping_add(0xBF58_476D_1CE4_E5B9)
            .wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        Self(z | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0);
        self.next() % n
    }

    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

// ---------------------------------------------------------------------------
// Simulated escrow: the state machine plus the off-chain accounting model.
// ---------------------------------------------------------------------------

const ALICE: [u8; 32] = [0xAA; 32];
const BOB: [u8; 32] = [0xBB; 32];
const MALLORY: [u8; 32] = [0xCC; 32];
const ARB: [u8; 32] = [0xA9; 32];
const MINT: [u8; 32] = [0xA5; 32];
const REFUND_TO: [u8; 32] = [0xB0; 32];
const EVIDENCE: [u8; 32] = [0xE8; 32];
const ATTESTOR_POOL: [[u8; 32]; 4] = [[0xA1; 32], [0xA2; 32], [0xA3; 32], [0xA4; 32]];
const NOW0: u64 = 1_700_000_000;

struct SimEscrow {
    escrow: Escrow,
    /// Total funded in.
    deposited: u128,
    /// Gross taker payouts (payout + fee legs).
    paid_out: u128,
    /// Refund legs (cancel / cancel_expired refund+penalty / resolve refund).
    refunded: u128,
    mint: Option<[u8; 32]>,
    dual_sig: bool,
    act_init: bool,
    act_taker: bool,
    attestors: Vec<[u8; 32]>,
    attested: u64, // bitmask over `attestors`
    has_vesting: bool,
    vest_start: u64,
    vest_end: u64,
    ms_amounts: Vec<u64>, // empty = no milestone plan
    ms_next: usize,
    ms_conf_init: bool,
    ms_conf_taker: bool,
    ms_release_path: bool, // vs skip path, chosen per tranche
    ms_skip_init: bool,
    ms_skip_taker: bool,
    arbiter: Option<[u8; 32]>,
    live: bool,
}

impl SimEscrow {
    fn gen(rng: &mut SimRng) -> Self {
        let amount = 3 + rng.below(10_000_000);
        let expires_at = NOW0 + 1 + rng.below(400_000);
        let mut e = Escrow::initialize(ALICE, BOB, amount, expires_at).unwrap();

        let dual_sig = rng.coin();
        if dual_sig {
            e = e.with_dual_sig().unwrap();
        }
        let attestors = if rng.below(2) == 0 {
            let n = 1 + rng.below(3) as usize;
            let threshold = 1 + rng.below(n as u64) as u8;
            e = e
                .with_quorum(QuorumPolicy::new(&ATTESTOR_POOL[..n], threshold).unwrap())
                .unwrap();
            ATTESTOR_POOL[..n].to_vec()
        } else {
            Vec::new()
        };
        // Milestones and vesting are mutually exclusive here: with a plan
        // attached the plain release/claim paths are InvalidMilestones, so
        // the valid-op picker stays total without consulting the plan.
        let (has_vesting, vest_start, vest_end, ms_amounts) = if rng.coin() {
            let k = 1 + rng.below(3);
            (false, 0, 0, split_amount(rng, amount, k))
        } else if rng.coin() {
            let start = NOW0 - rng.below(50_000);
            let end = NOW0 + 1 + rng.below(200_000);
            e = e.with_vesting(VestingSchedule::new(start, end).unwrap()).unwrap();
            (true, start, end, Vec::new())
        } else {
            (false, 0, 0, Vec::new())
        };
        let mint = if rng.coin() {
            e = e.with_mint(MINT).unwrap();
            Some(MINT)
        } else {
            None
        };
        if rng.coin() {
            e = e.with_protocol_fee(rng.below(1000) as u16).unwrap();
        }
        if rng.coin() {
            e = e.with_grace_period(rng.below(3600)).unwrap();
        }
        if rng.coin() {
            e = e.with_refund_address(REFUND_TO).unwrap();
        }
        if rng.coin() {
            e = e.with_penalty_bps(rng.below(500) as u16).unwrap();
        }
        // unlock_at in the past: the timelock gate is exercised by the
        // dedicated timelock tests; here payouts must stay reachable.
        if rng.coin() {
            e = e.with_timelock(NOW0 - 1 - rng.below(1000)).unwrap();
        }
        if rng.coin() {
            e = e.with_decimals(rng.below(19) as u8).unwrap();
        }
        let arbiter = if rng.coin() {
            e = e.with_arbiter(ARB).unwrap();
            Some(ARB)
        } else {
            None
        };
        if !ms_amounts.is_empty() {
            e = e
                .with_milestones(MilestonePlan::new(&ms_amounts).unwrap())
                .unwrap();
        }
        Self {
            escrow: e,
            deposited: 0,
            paid_out: 0,
            refunded: 0,
            mint,
            dual_sig,
            act_init: false,
            act_taker: false,
            attestors,
            attested: 0,
            has_vesting,
            vest_start,
            vest_end,
            ms_amounts,
            ms_next: 0,
            ms_conf_init: false,
            ms_conf_taker: false,
            ms_release_path: true,
            ms_skip_init: false,
            ms_skip_taker: false,
            arbiter,
            live: true,
        }
    }

    fn quorum_satisfied(&self) -> bool {
        match self.escrow.quorum() {
            None => true,
            Some(q) => q.is_satisfied(),
        }
    }

    /// Next unattested attestor index, if any.
    fn next_unattested(&self) -> Option<usize> {
        (0..self.attestors.len()).find(|i| self.attested & (1u64 << i) == 0)
    }

    fn vested_now(&self, now: u64) -> u64 {
        // Mirrors VestingSchedule::vested_amount for the model: the claim
        // test below asserts the state machine agrees exactly.
        let duration = self.vest_end - self.vest_start; // > 0 by construction
        let elapsed = now.saturating_sub(self.vest_start).min(duration);
        ((self.escrow.amount() as u128 * elapsed as u128) / duration as u128) as u64
    }

    fn check_invariants(&self, ctx: &str) {
        // Locked funds exist only once `fund` has run: `Activated` is the
        // pre-funding dual-sig state (nothing deposited yet), so it counts
        // zero here.
        let locked = match self.escrow.state() {
            EscrowState::Funded | EscrowState::Disputed => self.escrow.remaining_amount() as u128,
            _ => 0,
        };
        assert_eq!(
            self.deposited,
            self.paid_out + self.refunded + locked,
            "conservation broken [{ctx}]: deposited={} paid_out={} refunded={} locked={}",
            self.deposited,
            self.paid_out,
            self.refunded,
            locked
        );
        assert!(
            self.escrow.fees_paid() as u128 <= self.escrow.released_amount() as u128,
            "fee bound broken [{ctx}]"
        );
        assert!(
            self.escrow.released_amount() <= self.escrow.amount(),
            "released exceeds locked [{ctx}]"
        );
    }

    fn mark_terminal(&mut self) {
        if matches!(
            self.escrow.state(),
            EscrowState::Released | EscrowState::Cancelled | EscrowState::Settled
        ) {
            self.live = false;
        }
    }
}

/// Split `amount` into `k` positive parts summing to `amount`.
fn split_amount(rng: &mut SimRng, amount: u64, k: u64) -> Vec<u64> {
    debug_assert!(k >= 1 && amount >= k);
    let mut parts = Vec::with_capacity(k as usize);
    let mut remaining = amount;
    for i in 0..k - 1 {
        let min_reserve = k - 1 - i; // 1 per remaining part
        let part = 1 + rng.below(remaining - min_reserve);
        parts.push(part);
        remaining -= part;
    }
    parts.push(remaining);
    parts
}

// ---------------------------------------------------------------------------
// The runner: pseudo-concurrent interleaving across escrows.
// ---------------------------------------------------------------------------

/// A valid operation the picker offers only when its preconditions
/// provably hold — any `Err` from one of these is a state-machine bug.
enum ValidOp {
    Activate([u8; 32]),
    Fund,
    Attest(usize),
    Release(u64),
    Claim,
    UpdateQuorum(u8),
    Cancel,
    CancelExpired([u8; 32]),
    Escalate([u8; 32], Option<[u8; 32]>),
    Resolve(u64),
}

/// A deliberately-invalid operation and the exact error it must produce.
/// The error pins the documented check order under interleaving. The
/// closures capture nothing (they read everything off the `SimEscrow`),
/// so they coerce to fn pointers.
struct Probe {
    name: &'static str,
    run: fn(&mut SimEscrow, u64) -> Result<(), EscrowError>,
    expected: EscrowError,
}

struct Runner {
    rng: SimRng,
    now: u64,
    escrows: Vec<SimEscrow>,
    seed: u64,
}

impl Runner {
    fn new(seed: u64, n_escrows: usize) -> Self {
        let mut rng = SimRng::new(seed);
        let escrows = (0..n_escrows).map(|_| SimEscrow::gen(&mut rng)).collect();
        Self {
            rng,
            now: NOW0,
            escrows,
            seed,
        }
    }

    fn ctx(&self, step: usize, idx: usize) -> String {
        format!("seed={} step={step} escrow={idx}", self.seed)
    }

    fn run(mut self, steps: usize) -> u64 {
        for step in 0..steps {
            self.now += self.rng.below(2000);
            let live: Vec<usize> = self
                .escrows
                .iter()
                .enumerate()
                .filter(|(_, s)| s.live)
                .map(|(i, _)| i)
                .collect();
            if live.is_empty() {
                break;
            }
            let idx = live[self.rng.below(live.len() as u64) as usize];
            if self.rng.below(4) == 0 {
                self.probe_step(step, idx);
            } else {
                self.valid_step(step, idx);
            }
            for s in &self.escrows {
                s.check_invariants(&format!("seed={} step={step}", self.seed));
            }
        }
        self.digest()
    }

    fn digest(&self) -> u64 {
        let mut h = 0u64;
        for s in &self.escrows {
            h = h
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(s.deposited as u64)
                .wrapping_add((s.paid_out.wrapping_mul(3)) as u64)
                .wrapping_add((s.refunded.wrapping_mul(5)) as u64)
                .wrapping_add(s.escrow.state() as u64);
        }
        h.wrapping_add(self.now)
    }

    fn valid_step(&mut self, step: usize, idx: usize) {
        let ctx = self.ctx(step, idx);
        let op: Option<ValidOp> = {
            let s = &mut self.escrows[idx];
            let rng = &mut self.rng;
            let now = self.now;
            match s.escrow.state() {
                EscrowState::Uninitialized => {
                    if s.dual_sig {
                        if !s.act_init {
                            Some(ValidOp::Activate(ALICE))
                        } else if !s.act_taker {
                            Some(ValidOp::Activate(BOB))
                        } else {
                            Some(ValidOp::Fund)
                        }
                    } else {
                        Some(ValidOp::Fund)
                    }
                }
                EscrowState::Activated => Some(ValidOp::Fund),
                EscrowState::Funded => {
                    if let Some(i) = s.next_unattested() {
                        return self.apply(idx, ValidOp::Attest(i), &ctx);
                    }
                    if s.ms_next < s.ms_amounts.len() {
                        return self.milestone_step(idx, &ctx);
                    }
                    // No live milestone tranche here: either no plan, or
                    // the plan is exhausted (remaining tranches were all
                    // skipped — only exits remain valid).
                    let mut cands: Vec<ValidOp> = Vec::new();
                    let remaining = s.escrow.remaining_amount();
                    if s.ms_amounts.is_empty() && remaining > 0 {
                        if s.has_vesting {
                            let claimable =
                                s.vested_now(now).saturating_sub(s.escrow.released_amount());
                            if claimable > 0 {
                                cands.push(ValidOp::Claim);
                            }
                        } else {
                            cands.push(ValidOp::Release(1 + rng.below(remaining)));
                        }
                    }
                    // Exits are always available on a Funded escrow.
                    cands.push(ValidOp::Cancel);
                    if s.escrow.is_expiry_eligible(now) {
                        cands.push(ValidOp::CancelExpired(if rng.coin() { ALICE } else { BOB }));
                    }
                    if s.arbiter.is_some() && now < s.escrow.expires_at() {
                        let evidence = if rng.coin() { Some(EVIDENCE) } else { None };
                        cands.push(ValidOp::Escalate(if rng.coin() { ALICE } else { BOB }, evidence));
                    }
                    if s.escrow.quorum().is_some() && rng.below(10) == 0 {
                        let registered = s.escrow.quorum().unwrap().registered_count();
                        cands.push(ValidOp::UpdateQuorum(1 + rng.below(registered as u64) as u8));
                    }
                    let pick = rng.below(cands.len() as u64) as usize;
                    cands.into_iter().nth(pick)
                }
                EscrowState::Disputed => {
                    // remaining >= 1 in Disputed (a Funded escrow always
                    // has locked funds; escalate moves nothing).
                    let remaining = s.escrow.remaining_amount();
                    Some(ValidOp::Resolve(1 + rng.below(remaining)))
                }
                _ => None,
            }
        };
        if let Some(op) = op {
            self.apply(idx, op, &ctx);
        }
    }

    /// Milestone-path valid ops for the current tranche: dual-confirm then
    /// release, or dual-skip (the path is committed per tranche).
    fn milestone_step(&mut self, idx: usize, ctx: &str) {
        let now = self.now;
        let s = &mut self.escrows[idx];
        debug_assert!(s.ms_next < s.ms_amounts.len());
        if !s.ms_conf_init && !s.ms_skip_init {
            s.ms_release_path = self.rng.coin();
        }
        if s.ms_release_path {
            if !s.ms_conf_init {
                s.ms_conf_init = true;
                let r = s.escrow.confirm_milestone(ALICE, s.ms_next as u8);
                Self::expect_ok(r, "confirm_milestone(init)", ctx, idx);
            } else if !s.ms_conf_taker {
                s.ms_conf_taker = true;
                let r = s.escrow.confirm_milestone(BOB, s.ms_next as u8);
                Self::expect_ok(r, "confirm_milestone(taker)", ctx, idx);
            } else {
                let (payout, fee) = Self::expect_ok(
                    s.escrow.release_milestone(ALICE, now, s.ms_next as u8, s.mint),
                    "release_milestone",
                    ctx,
                    idx,
                );
                s.paid_out += (payout + fee) as u128;
                s.ms_next += 1;
                s.ms_conf_init = false;
                s.ms_conf_taker = false;
            }
        } else if !s.ms_skip_init {
            s.ms_skip_init = true;
            let r = s.escrow.skip_milestone(ALICE, s.ms_next as u8);
            Self::expect_ok(r, "skip_milestone(init)", ctx, idx);
        } else if !s.ms_skip_taker {
            s.ms_skip_taker = true;
            let r = s.escrow.skip_milestone(BOB, s.ms_next as u8);
            Self::expect_ok(r, "skip_milestone(taker)", ctx, idx);
            // The second skip approval executes the skip: the tranche
            // joins the refundable remainder (remaining_amount), so the
            // model moves nothing here — the refund is accounted at
            // cancel / cancel_expired via the remainder.
            s.ms_next += 1;
            s.ms_skip_init = false;
            s.ms_skip_taker = false;
        }
        s.mark_terminal();
    }

    fn apply(&mut self, idx: usize, op: ValidOp, ctx: &str) {
        let now = self.now;
        let s = &mut self.escrows[idx];
        match op {
            ValidOp::Activate(who) => {
                Self::expect_ok(s.escrow.activate(who), "activate", ctx, idx);
                if who == ALICE {
                    s.act_init = true;
                } else {
                    s.act_taker = true;
                }
            }
            ValidOp::Fund => {
                Self::expect_ok(s.escrow.fund(ALICE), "fund", ctx, idx);
                s.deposited += s.escrow.amount() as u128;
            }
            ValidOp::Attest(i) => {
                let key = s.attestors[i];
                Self::expect_ok(s.escrow.attest(key), "attest", ctx, idx);
                s.attested |= 1u64 << i;
            }
            ValidOp::Release(amount) => {
                let (payout, fee) = Self::expect_ok(
                    s.escrow.release(ALICE, now, amount, s.mint),
                    "release",
                    ctx,
                    idx,
                );
                assert_eq!(
                    payout + fee,
                    amount,
                    "release gross must equal the requested amount [{ctx}]"
                );
                s.paid_out += (payout + fee) as u128;
            }
            ValidOp::Claim => {
                let expected = s.vested_now(now).saturating_sub(s.escrow.released_amount());
                let (payout, fee) =
                    Self::expect_ok(s.escrow.claim(BOB, now, s.mint), "claim", ctx, idx);
                assert_eq!(
                    payout + fee,
                    expected,
                    "claim must release exactly the vested-but-unreleased amount [{ctx}]"
                );
                s.paid_out += (payout + fee) as u128;
            }
            ValidOp::UpdateQuorum(t) => {
                Self::expect_ok(s.escrow.update_quorum(ALICE, BOB, t), "update_quorum", ctx, idx);
            }
            ValidOp::Cancel => {
                let refund = s.escrow.remaining_amount();
                let to = s.escrow.refund_recipient();
                Self::expect_ok(s.escrow.cancel(ALICE, s.mint, to), "cancel", ctx, idx);
                s.refunded += refund as u128;
            }
            ValidOp::CancelExpired(who) => {
                let to = s.escrow.refund_recipient();
                let (refund, penalty) = Self::expect_ok(
                    s.escrow.cancel_expired(who, now, s.mint, to),
                    "cancel_expired",
                    ctx,
                    idx,
                );
                s.refunded += (refund + penalty) as u128;
            }
            ValidOp::Escalate(who, evidence) => {
                Self::expect_ok(s.escrow.escalate(who, now, evidence), "escalate", ctx, idx);
            }
            ValidOp::Resolve(taker_amount) => {
                let (payout, fee, refund) = Self::expect_ok(
                    s.escrow.resolve(ARB, taker_amount, s.mint),
                    "resolve",
                    ctx,
                    idx,
                );
                assert_eq!(
                    payout + fee,
                    taker_amount,
                    "resolve taker gross must equal taker_amount [{ctx}]"
                );
                s.paid_out += (payout + fee) as u128;
                s.refunded += refund as u128;
            }
        }
        s.mark_terminal();
    }

    fn expect_ok<T>(r: Result<T, EscrowError>, what: &str, ctx: &str, idx: usize) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("valid op {what} failed with {e:?} [{ctx} escrow={idx}]"),
        }
    }

    fn probe_step(&mut self, step: usize, idx: usize) {
        let ctx = self.ctx(step, idx);
        let now = self.now;
        // Candidate probes, each guarded by preconditions that provably
        // hold, mirroring the documented check order
        // (authority -> state -> config -> amount).
        let mut cands: Vec<Probe> = Vec::new();
        {
            let s = &self.escrows[idx];
            let live = s.live;
            let state = s.escrow.state();
            let remaining = s.escrow.remaining_amount();
            let quorum_some = s.escrow.quorum().is_some();
            let quorum_ok = s.quorum_satisfied();
            let eligible = s.escrow.is_expiry_eligible(now);
            let plain_path = s.ms_amounts.is_empty() && !s.has_vesting;

            // Authority is checked before state everywhere: a stranger
            // fails identically in every state.
            cands.push(Probe {
                name: "stranger release",
                run: |s, now| s.escrow.release(MALLORY, now, 1, s.mint).map(|_| ()),
                expected: EscrowError::Unauthorized,
            });
            cands.push(Probe {
                name: "stranger fund",
                run: |s, _| s.escrow.fund(MALLORY),
                expected: EscrowError::Unauthorized,
            });
            if live {
                cands.push(Probe {
                    name: "taker fund",
                    run: |s, _| s.escrow.fund(BOB),
                    expected: EscrowError::Unauthorized,
                });
            }
            match state {
                EscrowState::Uninitialized => cands.push(Probe {
                    name: "release before fund",
                    run: |s, now| s.escrow.release(ALICE, now, 1, s.mint).map(|_| ()),
                    expected: EscrowError::InvalidStateTransition,
                }),
                // fund from Activated is the valid dual-sig funding path, so
                // the double-fund probe only applies once funded.
                EscrowState::Funded => cands.push(Probe {
                    name: "double fund",
                    run: |s, _| s.escrow.fund(ALICE),
                    expected: EscrowError::InvalidStateTransition,
                }),
                _ => {}
            }
            if state == EscrowState::Funded {
                cands.push(Probe {
                    name: "taker cancel",
                    run: |s, _| s.escrow.cancel(BOB, s.mint, s.escrow.refund_recipient()),
                    expected: EscrowError::Unauthorized,
                });
                if !eligible {
                    cands.push(Probe {
                        name: "early cancel_expired",
                        run: |s, now| {
                            s.escrow
                                .cancel_expired(ALICE, now, s.mint, s.escrow.refund_recipient())
                                .map(|_| ())
                        },
                        expected: EscrowError::NotExpired,
                    });
                }
                // Reaching the amount/config checks requires the earlier
                // gates to pass: quorum satisfied, timelock in the past
                // (factory), mint matching (picker).
                if plain_path && quorum_ok && remaining > 0 {
                    cands.push(Probe {
                        name: "over release",
                        run: |s, now| {
                            let over = s.escrow.remaining_amount() + 1;
                            s.escrow.release(ALICE, now, over, s.mint).map(|_| ())
                        },
                        expected: EscrowError::ReleaseExceedsLocked,
                    });
                    cands.push(Probe {
                        name: "zero release",
                        run: |s, now| s.escrow.release(ALICE, now, 0, s.mint).map(|_| ()),
                        expected: EscrowError::AmountMismatch,
                    });
                    cands.push(Probe {
                        name: "claim without vesting",
                        run: |s, now| s.escrow.claim(BOB, now, s.mint).map(|_| ()),
                        expected: EscrowError::InvalidVesting,
                    });
                }
                if quorum_some {
                    cands.push(Probe {
                        name: "stranger attest",
                        run: |s, _| s.escrow.attest(MALLORY),
                        expected: EscrowError::Unauthorized,
                    });
                }
            }
            if state == EscrowState::Disputed {
                cands.push(Probe {
                    name: "stranger resolve",
                    run: |s, _| s.escrow.resolve(MALLORY, 0, s.mint).map(|_| ()),
                    expected: EscrowError::Unauthorized,
                });
            }
        }
        if cands.is_empty() {
            return;
        }
        let probe = &cands[self.rng.below(cands.len() as u64) as usize];
        let result = (probe.run)(&mut self.escrows[idx], now);
        match result {
            Err(e) if e == probe.expected => {}
            other => panic!(
                "probe '{}' expected {:?}, got {:?} [{}]",
                probe.name,
                probe.expected,
                other.map(|_| ()),
                ctx
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[test]
fn sim_interleavings() {
    // 16 seeds x 500 steps x 6 escrows: every step asserts conservation,
    // the fee bound, and check-order probes across the interleaving.
    for seed in 0..16 {
        Runner::new(seed, 6).run(500);
    }
}

#[test]
fn sim_single_deep() {
    // One escrow driven deep: long horizons cross expiries, vesting
    // curves, and every exit path.
    for seed in 0..4 {
        Runner::new(1000 + seed, 1).run(2000);
    }
}

#[test]
fn sim_deterministic() {
    // Same seed => identical run: the simulator is a pure function of
    // the seed, so failures are reproducible from the seed alone.
    let a = Runner::new(42, 6).run(500);
    let b = Runner::new(42, 6).run(500);
    assert_eq!(a, b, "simulator must be deterministic in the seed");
    let c = Runner::new(43, 6).run(500);
    assert_ne!(a, c, "different seeds should diverge (sanity)");
}
