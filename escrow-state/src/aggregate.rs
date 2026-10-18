//! Escrow aggregate statistics view (AV-78).
//!
//! An off-chain, read-only rollup over a fleet of watched escrows for
//! keeper/operator dashboards: per-state counts, an amount histogram,
//! average escrow durations, and total locked value. Pure reads — no
//! chain writes, no state mutation, no events emitted.
//!
//! Two constructors serve the two fidelity levels the crate offers:
//!
//! * [`EscrowAggregateView::from_indexed`] takes `&[IndexedEscrow]`.
//!   The indexed wrapper carries the full event history
//!   ([`crate::IndexedEscrow::events`]), so completed escrow durations
//!   are measured honestly: first event (`Initialized`) to the terminal
//!   event, averaged over escrows currently in a terminal state.
//! * [`EscrowAggregateView::from_watched`] takes `&[WatchedEscrow]`
//!   (the keeper scan input). Plain snapshots carry no event history,
//!   so completed durations are unavailable there — the corresponding
//!   fields are `None`, documented, never fabricated. Both constructors
//!   report the average *open* duration (`now - fund_at`) over escrows
//!   that currently hold funds (`Funded`/`Disputed`); `fund_at` is
//!   always recorded by [`crate::Escrow::fund`].
//!
//! [`EscrowAggregateView::to_json`] hand-serializes the view in the
//! crate's deterministic JSON convention (see `keeper.rs`), so the
//! aggregate result can be exported next to the per-escrow snapshots.

use crate::events::IndexedEscrow;
use crate::keeper::WatchedEscrow;
use crate::snapshot::state_name;
use crate::EscrowState;

/// One per-state count row. All eight lifecycle states are always
/// present, in `EscrowState` declaration order, so the report shape is
/// fixed regardless of the fleet mix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateCount {
    /// The lifecycle state.
    pub state: EscrowState,
    /// How many watched escrows are in this state.
    pub count: usize,
}

/// One amount-histogram bucket. Boundaries are fixed powers of ten in
/// the escrow's smallest unit (lamports / base units); the last bucket
/// is open-ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmountBucket {
    /// Human label, e.g. `"1k-10k"`.
    pub label: &'static str,
    /// Inclusive lower bound.
    pub min_inclusive: u64,
    /// Exclusive upper bound; `None` for the open-ended top bucket.
    pub max_exclusive: Option<u64>,
    /// How many watched escrows fall in this bucket.
    pub count: usize,
}

/// Fixed amount buckets, ascending. Eight buckets keep the histogram
/// compact while spanning dust to whale.
const AMOUNT_BUCKETS: [(&str, u64, Option<u64>); 8] = [
    ("0-1k", 0, Some(1_000)),
    ("1k-10k", 1_000, Some(10_000)),
    ("10k-100k", 10_000, Some(100_000)),
    ("100k-1m", 100_000, Some(1_000_000)),
    ("1m-10m", 1_000_000, Some(10_000_000)),
    ("10m-100m", 10_000_000, Some(100_000_000)),
    ("100m-1b", 100_000_000, Some(1_000_000_000)),
    ("1b+", 1_000_000_000, None),
];

/// States in which an escrow's fund movement is finished: the duration
/// from creation to the terminal event is a completed measurement.
/// AV-81: a split parent's funds were re-homed into the child escrows —
/// its own fund movement is finished, so `Split` counts as terminal.
fn is_terminal(state: EscrowState) -> bool {
    matches!(
        state,
        EscrowState::Released
            | EscrowState::Cancelled
            | EscrowState::Settled
            | EscrowState::Split
            | EscrowState::Closed
    )
}

/// States in which funds are currently held by the escrow.
fn is_funded_open(state: EscrowState) -> bool {
    matches!(state, EscrowState::Funded | EscrowState::Disputed)
}

/// All lifecycle states in declaration order — the fixed row order of
/// `state_counts`.
const ALL_STATES: [EscrowState; 9] = [
    EscrowState::Uninitialized,
    EscrowState::Funded,
    EscrowState::Released,
    EscrowState::Cancelled,
    EscrowState::Activated,
    EscrowState::Disputed,
    EscrowState::Settled,
    EscrowState::Closed,
    EscrowState::Split,
];

/// Read-only aggregate statistics over a fleet of watched escrows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowAggregateView {
    /// Number of escrows scanned.
    pub escrow_count: usize,
    /// Per-state counts, all nine states in declaration order.
    pub state_counts: [StateCount; 9],
    /// Amount histogram over escrow `amount` (gross locked at setup).
    pub amount_histogram: [AmountBucket; 8],
    /// Average completed escrow duration in seconds: first event to
    /// terminal event, over escrows in a terminal state. `None` when no
    /// terminal escrow carries an event history (always `None` for
    /// [`Self::from_watched`], which has no event timestamps to measure
    /// from — never fabricated).
    pub avg_completed_duration_secs: Option<u64>,
    /// How many terminal escrows contributed to the completed-duration
    /// average.
    pub completed_durations_sampled: usize,
    /// Average open duration in seconds (`now - fund_at`) over escrows
    /// currently holding funds (`Funded`/`Disputed`). `None` when the
    /// fleet holds no funds.
    pub avg_open_duration_secs: Option<u64>,
    /// How many funded escrows contributed to the open-duration average.
    pub open_durations_sampled: usize,
    /// Sum of [`crate::Escrow::remaining_amount`] over the fleet, in the
    /// smallest unit. `u128` because a fleet sum can exceed `u64::MAX`.
    pub total_locked: u128,
    // Scratch accumulators for the duration averages. They are private
    // and never serialized (to_json never reads them).
    completed_sum: u128,
    open_sum: u128,
}

impl EscrowAggregateView {
    /// Aggregate over indexed escrows: full fidelity, including
    /// completed durations from the event history.
    pub fn from_indexed(escrows: &[IndexedEscrow], now: u64) -> Self {
        let mut view = Self::empty();
        view.escrow_count = escrows.len();
        for ix in escrows {
            let e = ix.inner();
            view.count_one(e.state(), e.amount(), e.remaining_amount() as u128);
            if is_funded_open(e.state()) {
                view.sample_open(e.fund_at(), now);
            }
            if is_terminal(e.state()) {
                // Completed duration: creation (`Initialized`, seq 0)
                // to the terminal event. The indexed wrapper keeps the
                // full off-chain history; a missing history means we
                // cannot measure, so the escrow is skipped — never
                // guessed.
                if let (Some(first), Some(last)) = (ix.events().first(), ix.events().last()) {
                    let duration = last.at.saturating_sub(first.at);
                    view.completed_sum = view.completed_sum.saturating_add(duration as u128);
                    view.completed_durations_sampled += 1;
                }
            }
        }
        view.finalize()
    }

    /// Aggregate over keeper watch snapshots: state counts, histogram,
    /// and locked totals are exact; completed durations are unavailable
    /// (plain snapshots carry no event history) and stay `None`.
    pub fn from_watched(watched: &[WatchedEscrow], now: u64) -> Self {
        let mut view = Self::empty();
        view.escrow_count = watched.len();
        for w in watched {
            let e = &w.escrow;
            view.count_one(e.state(), e.amount(), e.remaining_amount() as u128);
            if is_funded_open(e.state()) {
                view.sample_open(e.fund_at(), now);
            }
        }
        view.finalize()
    }

    fn empty() -> Self {
        Self {
            escrow_count: 0,
            state_counts: ALL_STATES.map(|state| StateCount { state, count: 0 }),
            amount_histogram: AMOUNT_BUCKETS
                .map(|(label, min_inclusive, max_exclusive)| AmountBucket {
                    label,
                    min_inclusive,
                    max_exclusive,
                    count: 0,
                }),
            avg_completed_duration_secs: None,
            completed_durations_sampled: 0,
            avg_open_duration_secs: None,
            open_durations_sampled: 0,
            total_locked: 0,
            completed_sum: 0,
            open_sum: 0,
        }
    }

    /// Accumulator fields below are scratch space for averaging; they
    /// are not part of the public report shape.
    fn count_one(&mut self, state: EscrowState, amount: u64, remaining: u128) {
        if let Some(row) = self.state_counts.iter_mut().find(|r| r.state == state) {
            row.count += 1;
        }
        for bucket in self.amount_histogram.iter_mut() {
            let in_bucket = amount >= bucket.min_inclusive
                && bucket.max_exclusive.is_none_or(|max| amount < max);
            if in_bucket {
                bucket.count += 1;
                break;
            }
        }
        self.total_locked = self.total_locked.saturating_add(remaining);
    }

    fn sample_open(&mut self, fund_at: u64, now: u64) {
        // fund_at is 0 only when never funded; open states always went
        // through fund(), so a zero here is defensive, not expected.
        let age = now.saturating_sub(fund_at);
        self.open_sum = self.open_sum.saturating_add(age as u128);
        self.open_durations_sampled += 1;
    }

    fn finalize(mut self) -> Self {
        if self.completed_durations_sampled > 0 {
            self.avg_completed_duration_secs = Some(
                (self.completed_sum / self.completed_durations_sampled as u128) as u64,
            );
        }
        if self.open_durations_sampled > 0 {
            self.avg_open_duration_secs =
                Some((self.open_sum / self.open_durations_sampled as u128) as u64);
        }
        self
    }

    /// Hand-serialized JSON in the crate's deterministic convention
    /// (field order fixed, `total_locked` as a decimal string because it
    /// can exceed JSON-safe integer range).
    ///
    /// ```json
    /// {"escrow_count":3,
    ///  "state_counts":[{"state":"funded","count":2},{"state":"released","count":1},...],
    ///  "amount_histogram":[{"bucket":"1k-10k","min_inclusive":1000,"max_exclusive":10000,"count":2},...],
    ///  "avg_completed_duration_secs":86400,"completed_durations_sampled":1,
    ///  "avg_open_duration_secs":3600,"open_durations_sampled":2,
    ///  "total_locked":"2500000"}
    /// ```
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(512);
        s.push_str("{\"escrow_count\":");
        s.push_str(&self.escrow_count.to_string());
        s.push_str(",\"state_counts\":[");
        for (i, row) in self.state_counts.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"state\":\"");
            s.push_str(state_name(row.state));
            s.push_str("\",\"count\":");
            s.push_str(&row.count.to_string());
            s.push('}');
        }
        s.push_str("],\"amount_histogram\":[");
        for (i, b) in self.amount_histogram.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"bucket\":\"");
            s.push_str(b.label);
            s.push_str("\",\"min_inclusive\":");
            s.push_str(&b.min_inclusive.to_string());
            s.push_str(",\"max_exclusive\":");
            match b.max_exclusive {
                Some(max) => s.push_str(&max.to_string()),
                None => s.push_str("null"),
            }
            s.push_str(",\"count\":");
            s.push_str(&b.count.to_string());
            s.push('}');
        }
        s.push_str("],\"avg_completed_duration_secs\":");
        match self.avg_completed_duration_secs {
            Some(v) => s.push_str(&v.to_string()),
            None => s.push_str("null"),
        }
        s.push_str(",\"completed_durations_sampled\":");
        s.push_str(&self.completed_durations_sampled.to_string());
        s.push_str(",\"avg_open_duration_secs\":");
        match self.avg_open_duration_secs {
            Some(v) => s.push_str(&v.to_string()),
            None => s.push_str("null"),
        }
        s.push_str(",\"open_durations_sampled\":");
        s.push_str(&self.open_durations_sampled.to_string());
        s.push_str(",\"total_locked\":\"");
        s.push_str(&self.total_locked.to_string());
        s.push_str("\"}");
        s
    }
}

// Scratch accumulators live as private struct fields (see above); no
// extra impl block needed.

#[cfg(test)]
#[cfg(test)]
mod aggregate_tests {
    use super::*;
    use crate::keeper::WatchedEscrow;
    use crate::{Escrow, IndexedEscrow};

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// A funded escrow as a plain snapshot: built through the indexed
    /// wrapper (so the construction path is realistic), then unwrapped.
    /// `Escrow` is `Copy`, so `*ix.inner()` is a plain value copy.
    fn funded_escrow(id: u8, amount: u64, created_at: u64, funded_at: u64) -> Escrow {
        let mut ix =
            IndexedEscrow::initialize(key(1), key(2), amount, u64::MAX, [id; 32], created_at)
                .expect("initialize");
        ix.fund(key(1), funded_at).expect("fund");
        *ix.inner()
    }

    fn watched(escrow: Escrow, id: u8) -> WatchedEscrow {
        WatchedEscrow {
            escrow_id: [id; 32],
            escrow,
            reference: None,
            vault_derivation: None,
            pending_intent: None,
        }
    }

    #[test]
    fn state_counts_cover_all_states_in_order() {
        let view = EscrowAggregateView::from_watched(&[], 1_000_000);
        assert_eq!(view.escrow_count, 0);
        assert_eq!(view.state_counts.len(), 9);
        let names: Vec<&str> = view
            .state_counts
            .iter()
            .map(|r| state_name(r.state))
            .collect();
        assert_eq!(
            names,
            vec![
                "uninitialized",
                "funded",
                "released",
                "cancelled",
                "activated",
                "disputed",
                "settled",
                "closed",
                "split"
            ]
        );
        assert!(view.state_counts.iter().all(|r| r.count == 0));
        assert_eq!(view.avg_completed_duration_secs, None);
        assert_eq!(view.avg_open_duration_secs, None);
        assert_eq!(view.total_locked, 0);
    }

    #[test]
    fn mixed_fleet_counts_histogram_and_open_duration() {
        let now = 1_000_000u64;
        let w = vec![
            watched(funded_escrow(1, 500, 998_900, 999_000), 1), // 0-1k bucket
            watched(funded_escrow(2, 5_000, 997_900, 998_000), 2), // 1k-10k
            watched(funded_escrow(3, 5_000_000, 989_900, 990_000), 3), // 1m-10m
        ];
        let view = EscrowAggregateView::from_watched(&w, now);
        assert_eq!(view.escrow_count, 3);

        let funded = view
            .state_counts
            .iter()
            .find(|r| r.state == EscrowState::Funded)
            .unwrap();
        assert_eq!(funded.count, 3);

        let bucket = |label: &str| {
            view.amount_histogram
                .iter()
                .find(|b| b.label == label)
                .unwrap()
                .count
        };
        assert_eq!(bucket("0-1k"), 1);
        assert_eq!(bucket("1k-10k"), 1);
        assert_eq!(bucket("1m-10m"), 1);
        assert_eq!(bucket("1b+"), 0);

        // Open durations: (1000 + 2000 + 10000) / 3 = 4333 (integer div).
        assert_eq!(view.open_durations_sampled, 3);
        assert_eq!(view.avg_open_duration_secs, Some(4333));
        // No event history on the watched path: completed stays None,
        // never fabricated.
        assert_eq!(view.avg_completed_duration_secs, None);
        assert_eq!(view.completed_durations_sampled, 0);
        // All funded, nothing released: locked == full amounts.
        assert_eq!(view.total_locked, 500 + 5_000 + 5_000_000);
    }

    #[test]
    fn completed_duration_measured_from_event_history() {
        // Released escrow: initialized at t=100, released at t=1100.
        let mut ix =
            IndexedEscrow::initialize(key(1), key(2), 2_000, u64::MAX, [9; 32], 100)
                .expect("initialize");
        ix.fund(key(1), 200).expect("fund");
        ix.release(key(1), 2_000, None, key(2), 1100)
            .expect("release");
        // Disputed escrow stays open: contributes to open, not completed.
        let mut d =
            IndexedEscrow::initialize(key(1), key(2), 3_000, 9_999_999, [8; 32], 500)
                .expect("initialize")
                .with_arbiter(key(3))
                .expect("with_arbiter");
        d.fund(key(1), 600).expect("fund");
        d.escalate(key(1), 700, d.inner().remaining_amount(), None, None, 0).expect("escalate");

        let view = EscrowAggregateView::from_indexed(&[ix, d], 2_000);
        assert_eq!(view.escrow_count, 2);
        assert_eq!(view.completed_durations_sampled, 1);
        assert_eq!(view.avg_completed_duration_secs, Some(1000));
        // Open: disputed escrow funded at 600, now 2000 -> 1400.
        assert_eq!(view.open_durations_sampled, 1);
        assert_eq!(view.avg_open_duration_secs, Some(1400));
        // Released escrow holds nothing; disputed holds all.
        assert_eq!(view.total_locked, 3_000);

        let released = view
            .state_counts
            .iter()
            .find(|r| r.state == EscrowState::Released)
            .unwrap();
        assert_eq!(released.count, 1);
        let disputed = view
            .state_counts
            .iter()
            .find(|r| r.state == EscrowState::Disputed)
            .unwrap();
        assert_eq!(disputed.count, 1);
    }

    #[test]
    fn split_parent_counts_as_terminal_with_completed_duration() {
        // AV-81: a split parent is terminal — its fund movement is
        // finished (re-homed into the children), so the creation ->
        // EscrowSplit duration is a completed measurement.
        let mut ix =
            IndexedEscrow::initialize(key(1), key(2), 1_000_000, u64::MAX, [9; 32], 100)
                .expect("initialize");
        ix.fund(key(1), 200).expect("fund");
        ix.split_escrow(
            key(1),
            key(2),
            &[600_000, 400_000],
            crate::SplitConfig::default(),
            1100,
        )
        .expect("split");
        let view = EscrowAggregateView::from_indexed(&[ix], 2_000);
        assert_eq!(view.escrow_count, 1);
        let split = view
            .state_counts
            .iter()
            .find(|r| r.state == EscrowState::Split)
            .unwrap();
        assert_eq!(split.count, 1);
        assert_eq!(view.completed_durations_sampled, 1);
        assert_eq!(view.avg_completed_duration_secs, Some(1000));
        assert_eq!(view.open_durations_sampled, 0);
        // The parent's remainder is preserved for audit.
        assert_eq!(view.total_locked, 1_000_000);
    }

    #[test]
    fn empty_fleet_has_no_durations() {
        let view = EscrowAggregateView::from_indexed(&[], 10_000);
        assert_eq!(view.avg_completed_duration_secs, None);
        assert_eq!(view.avg_open_duration_secs, None);
        assert_eq!(view.total_locked, 0);
        assert_eq!(view.escrow_count, 0);
    }

    #[test]
    fn json_shape_is_deterministic() {
        let now = 1_000_000u64;
        let w = vec![watched(funded_escrow(1, 1_500, 998_900, 999_000), 1)];
        let view = EscrowAggregateView::from_watched(&w, now);
        let j = view.to_json();
        assert!(j.starts_with("{\"escrow_count\":1,\"state_counts\":[{\"state\":\"uninitialized\",\"count\":0},{\"state\":\"funded\",\"count\":1},"));
        assert!(j.contains("\"bucket\":\"1k-10k\",\"min_inclusive\":1000,\"max_exclusive\":10000,\"count\":1"));
        assert!(j.contains("\"bucket\":\"1b+\",\"min_inclusive\":1000000000,\"max_exclusive\":null,\"count\":0"));
        assert!(j.contains("\"avg_completed_duration_secs\":null"));
        assert!(j.contains("\"avg_open_duration_secs\":1000"));
        assert!(j.ends_with("\"total_locked\":\"1500\"}"));
        // Deterministic: same input, byte-identical output.
        assert_eq!(j, view.to_json());
    }

    #[test]
    fn keeper_scan_wrapper_matches_from_watched() {
        let now = 2_000_000u64;
        let w = vec![
            watched(funded_escrow(1, 700, 1_998_900, 1_999_000), 1),
            watched(funded_escrow(2, 2_000_000_000, 1_997_900, 1_998_000), 2),
        ];
        let via_keeper = crate::keeper::scan_aggregate_view(&w, now);
        let direct = EscrowAggregateView::from_watched(&w, now);
        assert_eq!(via_keeper, direct);
        assert_eq!(via_keeper.escrow_count, 2);
    }
}
