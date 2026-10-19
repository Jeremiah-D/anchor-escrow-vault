//! Maker credit scoring (AV-142 — Solana/支付 fintech): off-chain
//! reputation for escrow initializers (makers), aggregated in
//! `escrow-state` and fed from the AV-138
//! [`EscrowIndex`](crate::EscrowIndex).
//!
//! Why off-chain: a credit score needs a sliding window over a maker's
//! past escrows (completion / cancellation / dispute-loss rates). The
//! vault account is fixed-layout and heap-free — it cannot cheaply
//! maintain per-maker history — so the scorebook lives off-chain in
//! the keeper/operator layer, exactly like the other off-chain
//! aggregations (`EscrowIndex`, `EscrowAggregateView`). The chain sees
//! only the *consequence* of a score: a protocol-fee discount applied
//! through the AV-66 [`FeeSchedule`](crate::FeeSchedule) tier ladder.
//!
//! Score (0–1000, integer math, no floats):
//! ```text
//! score = (600*completed + 300*(total - dispute_lost) + 100*(total - cancelled)) / total
//! ```
//! Completion dominates (600‰), a clean dispute record is next
//! (300‰ — losing a dispute as maker is the strongest negative
//! signal), and a cancellation-free history is the tiebreak (100‰).
//! A maker with no recorded history scores a neutral 500 and earns no
//! discount: trust is earned, not granted.
//!
//! Fee linkage (MAX_FEE_TIERS): a scored maker gets *tier steps* — the
//! effective fee rate for a payout drops down the schedule's
//! rate-ranked ladder (cheapest live tier first) by 0/1/2 steps, so a
//! 900+ maker on a 250/100/25 bps ladder pays the 25 bps floor where a
//! newcomer on the 100 bps tier pays 100. [`MakerScorebook::fee_tier_bps`]
//! implements the shift; [`FeeSchedule::bps_for`] stays the
//! unshifted base rate.
//!
//! Misconduct: a recorded [`MakerOutcome::DisputeLost`] starts a
//! 7-day cooldown ([`MAKER_COOLDOWN_SECS`]) during which the maker
//! earns no discount, and the loss is already priced into the 300‰
//! clean-record term.
//!
//! Query surface: [`MakerScorebook::score`] for one maker,
//! [`MakerScorebook::snapshot`] for a score-sorted leaderboard, and
//! [`EscrowIndex::record_terminal_outcomes`](crate::EscrowIndex::record_terminal_outcomes)
//! to feed terminal escrows from the index (idempotent per escrow id).

use std::collections::{HashMap, HashSet, VecDeque};

use crate::{EscrowState, FeeSchedule, FeeTier, MAX_FEE_TIERS};

/// Sliding window: at most this many recent scored escrows per maker
/// feed the score. Older history ages out — a maker who reformed
/// their cancellation habit is not punished forever, and a maker who
/// went rogue loses their earned discount as good outcomes evict the
/// bad ones.
pub const SCORE_WINDOW: usize = 32;

/// Cooldown after a dispute loss: 7 days with no fee discount. The
/// score itself still reflects the loss (the 300‰ clean-record term),
/// the cooldown is the additional deterrent.
pub const MAKER_COOLDOWN_SECS: u64 = 7 * 24 * 60 * 60;

/// Score bands for tier-step discounts.
pub const ELITE_SCORE: u16 = 900;
pub const TRUSTED_SCORE: u16 = 750;

/// Weight terms in the score formula (promille of 1000).
const W_COMPLETION: u64 = 600;
const W_CLEAN_RECORD: u64 = 300;
const W_RELIABILITY: u64 = 100;

/// How one escrow ended for its maker. The maker is the escrow's
/// initializer — the party putting funds in and choosing the taker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MakerOutcome {
    /// Taker was paid in full: the escrow did its job.
    Completed,
    /// Unwound without payout (`Cancelled` / `Declined`).
    Cancelled,
    /// Arbitration ended in the maker's favor.
    DisputeWon,
    /// Arbitration ended against the maker: misconduct signal, starts
    /// the cooldown.
    DisputeLost,
}

/// The computed score for one maker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MakerScore {
    /// The maker (initializer pubkey).
    pub maker: [u8; 32],
    /// 0–1000; 500 when the maker has no recorded history.
    pub score_bps: u16,
    /// Scored escrows inside the sliding window.
    pub total: u64,
    pub completed: u64,
    pub cancelled: u64,
    pub dispute_won: u64,
    pub dispute_lost: u64,
    /// True while a dispute-loss cooldown is active at `now`.
    pub in_cooldown: bool,
}

/// One row of the score leaderboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MakerScoreSnapshot {
    pub maker: [u8; 32],
    pub score_bps: u16,
    pub scored_total: u64,
    /// `completed / total` in basis points.
    pub completion_rate_bps: u16,
    pub in_cooldown: bool,
    /// Tier steps this maker currently earns (0 when in cooldown).
    pub discount_steps: u8,
}

/// Per-maker rolling record.
#[derive(Debug, Clone, Default)]
struct MakerRecord {
    /// `(escrow_id, outcome)` in record order; capped at
    /// [`SCORE_WINDOW`] — oldest evicted first.
    outcomes: VecDeque<([u8; 32], MakerOutcome)>,
    /// Escrow ids already scored: `record` is idempotent per id, so
    /// re-feeding the same index is harmless.
    seen: HashSet<[u8; 32]>,
    /// Unix timestamp until which no discount is earned (set by a
    /// dispute loss).
    cooldown_until: u64,
}

/// Off-chain maker credit scorebook (AV-142).
#[derive(Debug, Clone, Default)]
pub struct MakerScorebook {
    records: HashMap<[u8; 32], MakerRecord>,
}

impl MakerScorebook {
    /// Empty scorebook.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one escrow outcome for `maker`. Returns `true` when the
    /// escrow id was new (the score changed); `false` when the id was
    /// already scored — re-feeding is a no-op.
    pub fn record(
        &mut self,
        maker: [u8; 32],
        escrow_id: [u8; 32],
        outcome: MakerOutcome,
        at: u64,
    ) -> bool {
        let rec = self.records.entry(maker).or_default();
        if !rec.seen.insert(escrow_id) {
            return false;
        }
        rec.outcomes.push_back((escrow_id, outcome));
        while rec.outcomes.len() > SCORE_WINDOW {
            if let Some((old_id, _)) = rec.outcomes.pop_front() {
                rec.seen.remove(&old_id);
            }
        }
        if outcome == MakerOutcome::DisputeLost {
            rec.cooldown_until = rec.cooldown_until.max(at.saturating_add(MAKER_COOLDOWN_SECS));
        }
        true
    }

    /// The score for `maker` at `now`. Unknown makers score the
    /// neutral 500 — no discount until history accrues.
    pub fn score(&self, maker: [u8; 32], now: u64) -> MakerScore {
        let mut s = MakerScore {
            maker,
            score_bps: 500,
            total: 0,
            completed: 0,
            cancelled: 0,
            dispute_won: 0,
            dispute_lost: 0,
            in_cooldown: false,
        };
        let Some(rec) = self.records.get(&maker) else {
            return s;
        };
        for &(_, o) in rec.outcomes.iter() {
            s.total += 1;
            match o {
                MakerOutcome::Completed => s.completed += 1,
                MakerOutcome::Cancelled => s.cancelled += 1,
                MakerOutcome::DisputeWon => s.dispute_won += 1,
                MakerOutcome::DisputeLost => s.dispute_lost += 1,
            }
        }
        if s.total > 0 {
            let t = s.total;
            s.score_bps = ((W_COMPLETION * s.completed
                + W_CLEAN_RECORD * (t - s.dispute_lost)
                + W_RELIABILITY * (t - s.cancelled))
                / t)
                .min(1000) as u16;
        }
        s.in_cooldown = now < rec.cooldown_until;
        s
    }

    /// Tier steps a score earns: 2 at [`ELITE_SCORE`]+, 1 at
    /// [`TRUSTED_SCORE`]+, 0 otherwise — and always 0 while in
    /// cooldown, however high the score.
    pub fn discount_steps(score_bps: u16, in_cooldown: bool) -> u8 {
        if in_cooldown {
            return 0;
        }
        if score_bps >= ELITE_SCORE {
            2
        } else if score_bps >= TRUSTED_SCORE {
            1
        } else {
            0
        }
    }

    /// The protocol-fee rate for `maker` on a `amount` payout under
    /// `schedule`: the base tier's rate shifted *down the rate
    /// ladder* by the maker's earned tier steps. Tiers are sorted by
    /// rate ascending (the cheapest live rate first); the effective
    /// rate is the rate `steps` positions cheaper than the base rate,
    /// floored at the cheapest tier. On the conventional AV-66 ladder
    /// (250/100/25 bps) an elite maker on the 100 bps tier pays the
    /// 25 bps floor.
    ///
    /// Below the schedule's first floor the rate stays 0 — the same
    /// conservative reading as
    /// [`FeeSchedule::bps_for`](crate::FeeSchedule::bps_for).
    ///
    /// Panic-free: only reads `tiers[..tier_count]` (the schedule
    /// enforces `tier_count <= `[`MAX_FEE_TIERS`]); the rate ladder is
    /// built on the stack (at most 8 entries).
    pub fn fee_tier_bps(
        &self,
        schedule: &FeeSchedule,
        amount: u64,
        maker: [u8; 32],
        now: u64,
    ) -> u16 {
        let base = schedule.bps_for(amount);
        if base == 0 {
            return 0;
        }
        let s = self.score(maker, now);
        let steps = Self::discount_steps(s.score_bps, s.in_cooldown) as usize;
        // Rate-ranked ladder: cheapest live tier rate first.
        let live = (schedule.tier_count as usize).min(MAX_FEE_TIERS);
        let mut rates = [u16::MAX; MAX_FEE_TIERS];
        for (i, tier) in schedule.tiers[..live].iter().enumerate() {
            rates[i] = tier.bps;
        }
        rates[..live].sort_unstable();
        let mut ladder = [u16::MAX; MAX_FEE_TIERS];
        let mut n = 0;
        for &r in rates[..live].iter() {
            if n == 0 || ladder[n - 1] != r {
                ladder[n] = r;
                n += 1;
            }
        }
        let pos = ladder[..n]
            .iter()
            .position(|&r| r == base)
            .unwrap_or(n - 1);
        ladder[pos.saturating_sub(steps)]
    }

    /// Score-sorted leaderboard (highest score first), one snapshot
    /// per scored maker. Ties break by maker key for determinism.
    pub fn snapshot(&self, now: u64) -> Vec<MakerScoreSnapshot> {
        let mut rows: Vec<MakerScoreSnapshot> = self
            .records
            .keys()
            .map(|&maker| {
                let s = self.score(maker, now);
                MakerScoreSnapshot {
                    maker,
                    score_bps: s.score_bps,
                    scored_total: s.total,
                    completion_rate_bps: if s.total > 0 {
                        ((s.completed * 10_000) / s.total) as u16
                    } else {
                        0
                    },
                    in_cooldown: s.in_cooldown,
                    discount_steps: Self::discount_steps(s.score_bps, s.in_cooldown),
                }
            })
            .collect();
        rows.sort_by(|a, b| {
            b.score_bps
                .cmp(&a.score_bps)
                .then_with(|| a.maker.cmp(&b.maker))
        });
        rows
    }
}

impl crate::EscrowIndex {
    /// Feed every terminal escrow in the index into `book` (AV-142):
    /// `Released` → [`MakerOutcome::Completed`],
    /// `Cancelled`/`Declined` → [`MakerOutcome::Cancelled`], with the
    /// escrow's initializer as maker and its index id as the
    /// idempotence key. `Settled` is *not* fed — a state snapshot
    /// does not record which side the arbiter favored, so the outcome
    /// is only honest via an explicit
    /// [`MakerScorebook::record`] call at resolve time. Returns the
    /// number of newly scored escrows.
    pub fn record_terminal_outcomes(
        &self,
        book: &mut MakerScorebook,
        now: u64,
    ) -> usize {
        let mut scored = 0;
        for w in self.iter() {
            let outcome = match w.escrow.state() {
                EscrowState::Released => Some(MakerOutcome::Completed),
                EscrowState::Cancelled | EscrowState::Declined => {
                    Some(MakerOutcome::Cancelled)
                }
                _ => None,
            };
            if let Some(o) = outcome {
                if book.record(w.escrow.initializer(), w.escrow_id, o, now) {
                    scored += 1;
                }
            }
        }
        scored
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maker(i: u8) -> [u8; 32] {
        [i; 32]
    }
    fn escrow_id(i: u8) -> [u8; 32] {
        let mut id = [0xA0; 32];
        id[0] = i;
        id
    }

    #[test]
    fn neutral_score_for_unknown_maker() {
        let book = MakerScorebook::new();
        let s = book.score(maker(1), 1_000);
        assert_eq!(s.score_bps, 500);
        assert_eq!(s.total, 0);
        assert!(!s.in_cooldown);
    }

    #[test]
    fn perfect_record_scores_1000_and_earns_two_steps() {
        let mut book = MakerScorebook::new();
        for i in 0..10 {
            assert!(book.record(maker(1), escrow_id(i), MakerOutcome::Completed, 1_000));
        }
        let s = book.score(maker(1), 1_000);
        assert_eq!(s.score_bps, 1000);
        assert_eq!(MakerScorebook::discount_steps(s.score_bps, s.in_cooldown), 2);
    }

    #[test]
    fn all_cancelled_scores_300_no_discount() {
        let mut book = MakerScorebook::new();
        for i in 0..5 {
            book.record(maker(2), escrow_id(i), MakerOutcome::Cancelled, 1_000);
        }
        let s = book.score(maker(2), 1_000);
        // (0 + 300*5 + 0) / 5
        assert_eq!(s.score_bps, 300);
        assert_eq!(MakerScorebook::discount_steps(s.score_bps, s.in_cooldown), 0);
    }

    #[test]
    fn dispute_loss_scores_100_and_starts_cooldown() {
        let mut book = MakerScorebook::new();
        book.record(maker(3), escrow_id(1), MakerOutcome::DisputeLost, 1_000);
        let s = book.score(maker(3), 1_000);
        // (0 + 0 + 100*1) / 1
        assert_eq!(s.score_bps, 100);
        assert!(s.in_cooldown);
        assert_eq!(MakerScorebook::discount_steps(s.score_bps, s.in_cooldown), 0);
        // Cooldown expires after 7 days.
        let s2 = book.score(maker(3), 1_000 + MAKER_COOLDOWN_SECS);
        assert!(!s2.in_cooldown);
    }

    #[test]
    fn cooldown_kills_discount_even_for_elite_maker() {
        let mut book = MakerScorebook::new();
        for i in 0..20 {
            book.record(maker(4), escrow_id(i), MakerOutcome::Completed, 1_000);
        }
        // One dispute loss: still a high score (19/20 completions) but cooling down.
        book.record(maker(4), escrow_id(100), MakerOutcome::DisputeLost, 2_000);
        let s = book.score(maker(4), 2_000);
        assert!(s.score_bps >= TRUSTED_SCORE);
        assert!(s.in_cooldown);
        assert_eq!(MakerScorebook::discount_steps(s.score_bps, s.in_cooldown), 0);
    }

    #[test]
    fn record_is_idempotent_per_escrow_id() {
        let mut book = MakerScorebook::new();
        assert!(book.record(maker(5), escrow_id(1), MakerOutcome::Completed, 1_000));
        assert!(!book.record(maker(5), escrow_id(1), MakerOutcome::Cancelled, 1_000));
        let s = book.score(maker(5), 1_000);
        assert_eq!(s.total, 1);
        assert_eq!(s.completed, 1);
        assert_eq!(s.score_bps, 1000);
    }

    #[test]
    fn sliding_window_evicts_oldest_first() {
        let mut book = MakerScorebook::new();
        // Fill the window with bad history, then push it out with good history.
        for i in 0..SCORE_WINDOW {
            book.record(maker(6), escrow_id(i as u8), MakerOutcome::Cancelled, 1_000);
        }
        assert_eq!(book.score(maker(6), 1_000).score_bps, 300);
        for i in 0..SCORE_WINDOW {
            let mut id = escrow_id(i as u8);
            id[31] = 0xB0;
            book.record(maker(6), id, MakerOutcome::Completed, 1_000);
        }
        let s = book.score(maker(6), 1_000);
        assert_eq!(s.total, SCORE_WINDOW as u64);
        assert_eq!(s.score_bps, 1000);
    }

    /// Build the test fee ladder directly: 250 bps under 1 SOL,
    /// 100 bps from 1 SOL, 25 bps from 100 SOL. Tiers are stored
    /// strictly ascending, the invariant
    /// [`Escrow::with_fee_schedule`](crate::Escrow::with_fee_schedule)
    /// enforces at configuration time.
    fn ladder() -> FeeSchedule {
        let mut s = FeeSchedule::default();
        s.tier_count = 3;
        s.tiers[0] = FeeTier {
            min_amount: 0,
            bps: 250,
        };
        s.tiers[1] = FeeTier {
            min_amount: 1_000_000_000,
            bps: 100,
        };
        s.tiers[2] = FeeTier {
            min_amount: 100_000_000_000,
            bps: 25,
        };
        s
    }

    fn first_floor_at(min_amount: u64) -> FeeSchedule {
        let mut s = FeeSchedule::default();
        s.tier_count = 1;
        s.tiers[0] = FeeTier {
            min_amount,
            bps: 100,
        };
        s
    }

    #[test]
    fn fee_tier_bps_shifts_down_the_ladder_for_elite_makers() {
        let mut book = MakerScorebook::new();
        for i in 0..12 {
            book.record(maker(7), escrow_id(i), MakerOutcome::Completed, 1_000);
        }
        let schedule = ladder();
        // Newcomer on 100 bps tier pays 100.
        assert_eq!(book.fee_tier_bps(&schedule, 5_000_000_000, maker(8), 1_000), 100);
        // Elite maker (score 1000) steps down two tiers to the 25 bps floor.
        assert_eq!(book.fee_tier_bps(&schedule, 5_000_000_000, maker(7), 1_000), 25);
        // Below the first floor stays fee-free for everyone.
        let empty_top = first_floor_at(1_000_000_000);
        assert_eq!(book.fee_tier_bps(&empty_top, 500, maker(7), 1_000), 0);
        // Unconfigured schedule: bps_for is 0, shifted read agrees.
        let unconfigured = FeeSchedule::default();
        assert_eq!(book.fee_tier_bps(&unconfigured, 5_000_000_000, maker(7), 1_000), 0);
    }

    #[test]
    fn trusted_band_earns_one_step() {
        let mut book = MakerScorebook::new();
        // 8 completed, 2 cancelled: (4800 + 3000 + 800)/10 = 860 → 1 step.
        for i in 0..8 {
            book.record(maker(9), escrow_id(i), MakerOutcome::Completed, 1_000);
        }
        for i in 8..10 {
            book.record(maker(9), escrow_id(i), MakerOutcome::Cancelled, 1_000);
        }
        let s = book.score(maker(9), 1_000);
        assert_eq!(s.score_bps, 860);
        assert_eq!(MakerScorebook::discount_steps(s.score_bps, s.in_cooldown), 1);
        let schedule = ladder();
        assert_eq!(book.fee_tier_bps(&schedule, 5_000_000_000, maker(9), 1_000), 25);
    }

    #[test]
    fn index_feeds_terminal_outcomes() {
        use crate::{Escrow, EscrowIndex, WatchedEscrow};

        let mut book = MakerScorebook::new();
        let m = maker(10);
        let mut e = Escrow::initialize(m, maker(11), 1_000, 10_000).unwrap();
        e.fund(m, 100).unwrap();
        e.release(m, 200, 1_000, None, maker(11)).unwrap();
        assert_eq!(e.state(), EscrowState::Released);

        let mut index = EscrowIndex::new();
        assert!(index.insert(WatchedEscrow {
            escrow_id: escrow_id(1),
            escrow: e,
            reference: None,
            vault_derivation: None,
            pending_intent: None,
        }));
        assert_eq!(index.record_terminal_outcomes(&mut book, 300), 1);
        // Re-feeding the same index is a no-op (idempotent per escrow id).
        assert_eq!(index.record_terminal_outcomes(&mut book, 300), 0);
        assert_eq!(book.score(m, 300).score_bps, 1000);
    }

    #[test]
    fn snapshot_is_score_sorted() {
        let mut book = MakerScorebook::new();
        book.record(maker(1), escrow_id(1), MakerOutcome::Cancelled, 1_000);
        for i in 0..5 {
            book.record(maker(2), escrow_id(10 + i), MakerOutcome::Completed, 1_000);
        }
        let rows = book.snapshot(1_000);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].maker, maker(2));
        assert_eq!(rows[0].score_bps, 1000);
        assert_eq!(rows[0].discount_steps, 2);
        assert_eq!(rows[1].maker, maker(1));
        assert_eq!(rows[1].completion_rate_bps, 0);
    }
}
