//! AV-89: priority-fee oracle — keeper-side recent-prioritization-fees
//! EWMA estimator (pure logic, zero dependencies).
//!
//! The keeper report (AV-20) and the bundle dry-run report (AV-61)
//! preview *what* the keeper would execute; AV-88 added the compute
//! cost line (`total_estimated_cu`). This module adds the missing price
//! line: a recommended priority fee in micro-lamports per compute unit,
//! estimated from the recent prioritization-fee samples the keeper feeds
//! in (e.g. from the cluster's `getRecentPrioritizationFees` RPC).
//!
//! # What is real here
//!
//! - **The EWMA math is exact.** The smoothing recurrence, the
//!   sample-count bookkeeping, and the ceil-up recommendation are
//!   pinned by tests — the estimator does exactly what its doc comment
//!   says.
//! - **The fallback flag is honest.** A recommendation built from fewer
//!   samples than the configured window is the configured fixed value
//!   with `confidence: Low` and `fallback: true` — downstream can never
//!   mistake it for a measurement.
//! - **The fee-budget combination is exact.** [`fee_budget_lamports`]
//!   multiplies the AV-88 CU estimate by the recommended
//!   micro-lamports/CU with a u128 intermediate (no overflow) and
//!   rounds *up* to whole lamports.
//!
//! # What is deliberately NOT here (honesty labels)
//!
//! - **Heuristic, not an inclusion guarantee.** The oracle estimates
//!   the *mean recent price* of priority fees; it knows nothing about
//!   inclusion probability, leader-schedule congestion, or the fee
//!   distribution's tail. A `High`-confidence recommendation can still
//!   stall in a sudden congestion spike.
//! - **The feed is the operator's job.** The oracle only consumes
//!   samples — fetching them (RPC polling cadence, slot-window
//!   selection, outlier filtering) is keeper wiring outside this
//!   crate.
//! - **Defaults are starting points, not production tuning.** The
//!   default window, decay, and fallback value are reasonable seeds;
//!   an operator must calibrate them against their own recent-fee
//!   feed before sizing real transactions.
//!
//! # Math
//!
//! With smoothing factor `α ∈ (0, 1]` and samples `x₁…xₙ` (observed
//! oldest-first):
//!
//! ```text
//! ewma₁ = x₁
//! ewmaₙ = α·xₙ + (1 − α)·ewmaₙ₋₁
//! ```
//!
//! An EWMA (rather than a plain windowed mean) is the right shape for
//! fee feeds: it smooths single-sample spikes while tracking regime
//! changes, and it needs O(1) state — no sample ring buffer — which
//! keeps the keeper's hot path allocation-free. `α` is the
//! responsiveness knob: `α = 1` tracks the latest sample exactly,
//! smaller `α` trusts history more.
//!
//! The recommendation is `⌈ewma⌉`: rounding *up* so the suggested
//! price never sits below the estimated mean — a fee exactly at the
//! mean can stall in a rising-fee regime, and the ceil costs at most
//! one micro-lamport per compute unit.
//!
//! Confidence is a pure function of the sample count: `n ≥ window` →
//! `High` (the window has "filled" — the EWMA has absorbed a full
//! window's worth of observations); otherwise `Low`, and the oracle
//! emits the configured conservative fixed value with `fallback:
//! true` instead of the EWMA.

/// Fallback recommendation (micro-lamports per compute unit) used
/// while the oracle has seen fewer samples than its window. A
/// conservative starting point — calibrate against the operator's own
/// recent-fee feed before production use.
pub const DEFAULT_FALLBACK_MICRO_LAMPORTS_PER_CU: u64 = 10_000;

/// Default minimum samples before the EWMA is trusted.
pub const DEFAULT_WINDOW: usize = 20;

/// Default EWMA smoothing factor: each new sample moves the estimate
/// 30% of the way toward itself.
pub const DEFAULT_ALPHA: f64 = 0.3;

/// Micro-lamports per lamport: the fee-budget divisor.
pub const MICRO_LAMPORTS_PER_LAMPORT: u64 = 1_000_000;

/// Configuration for [`PriorityFeeOracle`]. `window` and `alpha` are
/// the EWMA parameters (see the module docs); `fallback_…` is the
/// conservative fixed recommendation emitted while `samples < window`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PriorityFeeConfig {
    /// Minimum samples before the EWMA is trusted (`confidence:
    /// High`). Must be `>= 1`.
    pub window: usize,
    /// EWMA smoothing factor, `(0, 1]`. Higher = more weight on the
    /// latest sample.
    pub alpha: f64,
    /// Conservative fixed recommendation (micro-lamports/CU) used
    /// while `samples < window`, flagged `fallback: true`.
    pub fallback_micro_lamports_per_cu: u64,
}

/// Why a [`PriorityFeeConfig`] was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityFeeConfigError {
    /// `window` was zero — the confidence gate needs at least one
    /// sample.
    InvalidWindow,
    /// `alpha` was outside `(0, 1]` (including NaN).
    InvalidAlpha,
}

impl PriorityFeeConfig {
    /// Build a config, validating the EWMA parameters. `fallback…`
    /// needs no validation — any fixed value, including zero, is a
    /// deliberate operator choice.
    pub fn new(
        window: usize,
        alpha: f64,
        fallback_micro_lamports_per_cu: u64,
    ) -> Result<Self, PriorityFeeConfigError> {
        if window == 0 {
            return Err(PriorityFeeConfigError::InvalidWindow);
        }
        // NaN fails both comparisons, so it is rejected too.
        if !(alpha > 0.0 && alpha <= 1.0) {
            return Err(PriorityFeeConfigError::InvalidAlpha);
        }
        Ok(Self {
            window,
            alpha,
            fallback_micro_lamports_per_cu,
        })
    }
}

impl Default for PriorityFeeConfig {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            alpha: DEFAULT_ALPHA,
            fallback_micro_lamports_per_cu: DEFAULT_FALLBACK_MICRO_LAMPORTS_PER_CU,
        }
    }
}

/// How much the oracle trusts its own recommendation: a pure function
/// of the sample count (`samples >= window` → [`Confidence::High`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// The window filled — the EWMA absorbed a full window's worth of
    /// observations.
    High,
    /// Fewer samples than the window — the recommendation is the
    /// configured fallback value, flagged as such.
    Low,
}

impl Confidence {
    /// JSON rendering: `"high"` / `"low"`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::High => "high",
            Confidence::Low => "low",
        }
    }
}

/// One oracle output: the recommended priority fee plus how much to
/// trust it. Rendered into the bundle dry-run report by
/// [`ExecutionBundle::to_json`](super::execution_bundle::ExecutionBundle::to_json).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorityFeeRecommendation {
    /// Recommended priority fee, micro-lamports per compute unit:
    /// `⌈ewma⌉` at [`Confidence::High`], the configured fallback value
    /// at [`Confidence::Low`].
    pub recommended_micro_lamports_per_cu: u64,
    /// Sample-count-derived trust level.
    pub confidence: Confidence,
    /// `true` when the recommendation is the configured fallback
    /// value, not the EWMA — never mistaken for a measurement.
    pub fallback: bool,
}

impl PriorityFeeRecommendation {
    /// Hand-serialized JSON (the crate is dependency-free).
    /// Deterministic field order:
    /// `{"micro_lamports_per_cu":N,"confidence":"high","fallback":false}`.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(80);
        s.push_str("{\"micro_lamports_per_cu\":");
        s.push_str(&self.recommended_micro_lamports_per_cu.to_string());
        s.push_str(",\"confidence\":\"");
        s.push_str(self.confidence.as_str());
        s.push_str("\",\"fallback\":");
        s.push_str(if self.fallback { "true" } else { "false" });
        s.push('}');
        s
    }

    /// AV-88 combination: the full fee budget in lamports for a batch
    /// estimated at `estimated_cu` compute units — `⌈cu ×
    /// micro_lamports_per_cu / 1_000_000⌉`. See
    /// [`fee_budget_lamports`].
    pub fn fee_budget_lamports(&self, estimated_cu: u64) -> u64 {
        fee_budget_lamports(estimated_cu, self.recommended_micro_lamports_per_cu)
    }
}

/// Keeper-side EWMA estimator over recent prioritization-fee samples
/// (micro-lamports per compute unit, observed oldest-first).
/// Allocation-free after construction: O(1) state, no sample buffer.
#[derive(Debug, Clone, PartialEq)]
pub struct PriorityFeeOracle {
    config: PriorityFeeConfig,
    samples: usize,
    /// `None` before the first observation.
    ewma: Option<f64>,
}

impl PriorityFeeOracle {
    /// New oracle with the given configuration.
    pub fn new(config: PriorityFeeConfig) -> Self {
        Self {
            config,
            samples: 0,
            ewma: None,
        }
    }

    /// The oracle's configuration.
    pub fn config(&self) -> &PriorityFeeConfig {
        &self.config
    }

    /// How many samples have been observed.
    pub fn sample_count(&self) -> usize {
        self.samples
    }

    /// Feed one recent-prioritization-fee sample (micro-lamports/CU).
    /// The first sample initializes the EWMA; later samples apply
    /// `ewma = α·x + (1 − α)·ewma`.
    pub fn observe(&mut self, micro_lamports_per_cu: u64) {
        let x = micro_lamports_per_cu as f64;
        self.ewma = Some(match self.ewma {
            None => x,
            Some(prev) => self.config.alpha * x + (1.0 - self.config.alpha) * prev,
        });
        self.samples = self.samples.saturating_add(1);
    }

    /// The current recommendation. `samples >= window` → the
    /// ceil-rounded EWMA at [`Confidence::High`]; otherwise the
    /// configured fallback value at [`Confidence::Low`] with
    /// `fallback: true`.
    pub fn recommend(&self) -> PriorityFeeRecommendation {
        if self.samples >= self.config.window {
            // `window >= 1` is validated, so `samples >= window`
            // implies at least one observation and `ewma` is `Some`.
            // The expect guards a hand-built config that bypassed
            // `PriorityFeeConfig::new`.
            let ewma = self
                .ewma
                .expect("AV-89: samples >= window >= 1 implies an observed EWMA");
            // `as u64` saturates on overflow — a fee estimate above
            // u64::MAX micro-lamports/CU is not a real fee regime.
            PriorityFeeRecommendation {
                recommended_micro_lamports_per_cu: ewma.ceil() as u64,
                confidence: Confidence::High,
                fallback: false,
            }
        } else {
            PriorityFeeRecommendation {
                recommended_micro_lamports_per_cu: self.config.fallback_micro_lamports_per_cu,
                confidence: Confidence::Low,
                fallback: true,
            }
        }
    }

    /// Forget all samples — e.g. when the keeper switches fee-feed
    /// source and the old EWMA no longer describes the new feed.
    pub fn reset(&mut self) {
        self.samples = 0;
        self.ewma = None;
    }
}

/// Full fee budget in lamports: the AV-88 compute-unit estimate times
/// a priority-fee recommendation, `⌈cu × micro_lamports_per_cu /
/// 1_000_000⌉`.
///
/// The product is computed in u128 (a u64×u64 product can overflow)
/// and the final lamport count saturates instead of wrapping. Rounds
/// *up*: a budget that rounds down could underfund the transaction's
/// fee by a lamport.
pub fn fee_budget_lamports(estimated_cu: u64, micro_lamports_per_cu: u64) -> u64 {
    let total_micro = estimated_cu as u128 * micro_lamports_per_cu as u128;
    let divisor = MICRO_LAMPORTS_PER_LAMPORT as u128;
    // Ceiling division: round up any fractional lamport so the budget
    // never underfunds the fee by a lamport.
    let lamports = total_micro / divisor + u128::from(!total_micro.is_multiple_of(divisor));
    u64::try_from(lamports).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod priority_fee_tests {
    use super::*;

    fn config(window: usize, alpha: f64, fallback: u64) -> PriorityFeeConfig {
        PriorityFeeConfig::new(window, alpha, fallback).expect("test config valid")
    }

    #[test]
    fn config_validation_rejects_bad_window_and_alpha() {
        assert_eq!(
            PriorityFeeConfig::new(0, 0.3, 1_000),
            Err(PriorityFeeConfigError::InvalidWindow)
        );
        for bad_alpha in [0.0, -0.1, 1.000_000_1, 2.0, f64::NAN, f64::INFINITY] {
            assert_eq!(
                PriorityFeeConfig::new(5, bad_alpha, 1_000),
                Err(PriorityFeeConfigError::InvalidAlpha),
                "alpha {bad_alpha} should be rejected"
            );
        }
        // Boundary alphas are valid.
        assert!(PriorityFeeConfig::new(1, 1.0, 0).is_ok());
        assert!(PriorityFeeConfig::new(1, f64::MIN_POSITIVE, 0).is_ok());
    }

    #[test]
    fn zero_samples_falls_back_and_flags() {
        let oracle = PriorityFeeOracle::new(config(3, 0.5, 7_500));
        let rec = oracle.recommend();
        assert_eq!(rec.recommended_micro_lamports_per_cu, 7_500);
        assert_eq!(rec.confidence, Confidence::Low);
        assert!(rec.fallback);
    }

    #[test]
    fn low_sample_count_falls_back_until_window_fills() {
        let mut oracle = PriorityFeeOracle::new(config(3, 0.5, 9_000));
        oracle.observe(100);
        oracle.observe(200);
        let rec = oracle.recommend();
        assert_eq!(rec.confidence, Confidence::Low);
        assert!(rec.fallback);
        assert_eq!(rec.recommended_micro_lamports_per_cu, 9_000);
        // The third sample fills the window: ewma = 100 → 150 → 225.
        oracle.observe(300);
        let rec = oracle.recommend();
        assert_eq!(rec.confidence, Confidence::High);
        assert!(!rec.fallback);
        assert_eq!(rec.recommended_micro_lamports_per_cu, 225);
    }

    #[test]
    fn ewma_applies_alpha_weighting() {
        // α = 0.5, samples [1000, 2000]:
        // ewma₁ = 1000; ewma₂ = 0.5·2000 + 0.5·1000 = 1500.
        let mut oracle = PriorityFeeOracle::new(config(2, 0.5, 0));
        oracle.observe(1_000);
        oracle.observe(2_000);
        assert_eq!(oracle.recommend().recommended_micro_lamports_per_cu, 1_500);
        // α = 1 tracks the latest sample exactly.
        let mut oracle = PriorityFeeOracle::new(config(2, 1.0, 0));
        oracle.observe(1_000);
        oracle.observe(2_000);
        assert_eq!(oracle.recommend().recommended_micro_lamports_per_cu, 2_000);
    }

    #[test]
    fn recommendation_rounds_up_never_down() {
        // α = 0.5, samples [1, 2]: ewma = 1.5 → ⌈1.5⌉ = 2, not 1.
        let mut oracle = PriorityFeeOracle::new(config(2, 0.5, 0));
        oracle.observe(1);
        oracle.observe(2);
        assert_eq!(oracle.recommend().recommended_micro_lamports_per_cu, 2);
    }

    #[test]
    fn reset_forgets_samples_and_restores_fallback() {
        let mut oracle = PriorityFeeOracle::new(config(1, 0.5, 4_000));
        oracle.observe(123);
        assert_eq!(oracle.recommend().confidence, Confidence::High);
        assert_eq!(oracle.sample_count(), 1);
        oracle.reset();
        assert_eq!(oracle.sample_count(), 0);
        let rec = oracle.recommend();
        assert_eq!(rec.confidence, Confidence::Low);
        assert!(rec.fallback);
        assert_eq!(rec.recommended_micro_lamports_per_cu, 4_000);
    }

    #[test]
    fn fee_budget_lamports_math() {
        // 13_814 CU (AV-88 cancel_expired example) × 1_000
        // micro-lamports/CU = 13_814_000 micro-lamports = 13.814
        // lamports → ⌈13.814⌉ = 14.
        assert_eq!(fee_budget_lamports(13_814, 1_000), 14);
        // Exact division does not round up: 1_000_000 CU × 1
        // micro-lamport/CU = exactly 1 lamport.
        assert_eq!(fee_budget_lamports(1_000_000, 1), 1);
        // Zero on either side is zero.
        assert_eq!(fee_budget_lamports(0, 1_000_000), 0);
        assert_eq!(fee_budget_lamports(1_400_000, 0), 0);
        // The u64×u64 product overflows u64 — the u128 intermediate
        // keeps it exact, and the lamport count saturates.
        assert_eq!(fee_budget_lamports(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn recommendation_fee_budget_combines_with_av88() {
        // End-to-end shape: the oracle's recommendation feeds the
        // AV-88 CU estimate into one fee-budget number.
        let mut oracle = PriorityFeeOracle::new(config(1, 1.0, 0));
        oracle.observe(2_500);
        let rec = oracle.recommend();
        // 26_392 CU (AV-88 resolve example) × 2_500 micro = 65_980_000
        // micro = 65.98 lamports → 66.
        assert_eq!(rec.fee_budget_lamports(26_392), 66);
    }

    #[test]
    fn recommendation_json_shape() {
        let rec = PriorityFeeRecommendation {
            recommended_micro_lamports_per_cu: 1_200,
            confidence: Confidence::High,
            fallback: false,
        };
        assert_eq!(
            rec.to_json(),
            "{\"micro_lamports_per_cu\":1200,\"confidence\":\"high\",\"fallback\":false}"
        );
        let fb = PriorityFeeRecommendation {
            recommended_micro_lamports_per_cu: 10_000,
            confidence: Confidence::Low,
            fallback: true,
        };
        assert_eq!(
            fb.to_json(),
            "{\"micro_lamports_per_cu\":10000,\"confidence\":\"low\",\"fallback\":true}"
        );
    }
}
