//! AV-193: Pyth / Switchboard oracle adapters — concrete
//! [`PriceFeed`](crate::PriceFeed) implementations for the AV-113
//! price gate.
//!
//! AV-113 defined the pluggable `PriceFeed` trait (the *framework*);
//! this module supplies real oracle *integrations* that turn on-chain
//! oracle account data into validated [`PriceQuote`](crate::PriceQuote)s:
//!
//! - [`PythPriceFeed`]: parses a Pyth v2 price account's raw bytes —
//!   header validation (magic / version / account type), exponent
//!   scaling, aggregate price/confidence/status decoding, and
//!   staleness checking against the account's publish timestamp.
//! - [`SwitchboardPriceFeed`]: validates a decoded Switchboard v2
//!   aggregator round (result decimal, oracle-result quorum, round
//!   timestamp) and normalizes the `SwitchboardDecimal` fixed point.
//!
//! Both adapters are fail-closed: any validation failure is an
//! [`EscrowError`], never a silent default. Quote units are normalized
//! to [`ORACLE_QUOTE_DECIMALS`] decimals (8 — i.e. 10⁻⁸ of the price
//! currency, so a $1,234.56 price quotes as `123_456_000_000`), so the
//! two oracles are directly comparable by the AV-113 gate.
//!
//! On the Switchboard parsing boundary: the packed
//! `AggregatorAccountData` struct is decoded by the Anchor program
//! with the upstream `switchboard-v2` crate (zero-copy) — this module
//! deliberately does *not* re-implement its byte layout; it owns the
//! validation (staleness, quorum, scale, positivity), the fixed-point
//! normalization, and the `PriceFeed` impl over the decoded round.
//! `Copy`, heap-free, `no_std`-friendly.

use crate::{EscrowError, PriceFeed, PriceQuote};

/// Quote units: prices are normalized to this many decimals (10⁻⁸ of
/// the price currency). Pyth exponents and Switchboard decimal scales
/// are both converted into this fixed scale so the AV-113 gate can
/// compare quotes across oracles.
pub const ORACLE_QUOTE_DECIMALS: u32 = 8;

/// Basis-point denominator for [`OracleValidationParams::max_conf_bps`].
pub const CONF_BPS_DENOMINATOR: u64 = 10_000;

/// Validation policy shared by both adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OracleValidationParams {
    /// Maximum accepted age of the oracle's publish timestamp, in
    /// seconds. Older quotes are rejected with
    /// [`EscrowError::OraclePriceStale`].
    pub max_age_secs: u64,
    /// Maximum accepted confidence-interval width, in basis points of
    /// the price (e.g. `200` = 2%). A wider interval is rejected with
    /// [`EscrowError::OraclePriceUnreliable`] — the quote exists but
    /// the oracle itself says it is too uncertain to act on.
    pub max_conf_bps: u64,
}

/// Which oracle a quote came from (audit tagging).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleSource {
    Pyth,
    Switchboard,
}

impl OracleSource {
    fn as_str(self) -> &'static str {
        match self {
            OracleSource::Pyth => "pyth",
            OracleSource::Switchboard => "switchboard",
        }
    }
}

// ---------------------------------------------------------------------------
// Pyth v2 price account
// ---------------------------------------------------------------------------

/// Pyth v2 price account magic (`0xa1b2c3d4`), bytes 0..4.
pub const PYTH_MAGIC: u32 = 0xa1b2c3d4;
/// Pyth program version carried by price accounts (bytes 4..8).
pub const PYTH_VERSION: u32 = 2;
/// Pyth account type for price accounts (bytes 8..12).
pub const PYTH_ATYPE_PRICE: u32 = 2;
/// Pyth price type for spot prices (bytes 16..20).
pub const PYTH_PTYPE_PRICE: u32 = 1;
/// Pyth aggregate status "trading" (bytes 224..228 of the account).
pub const PYTH_STATUS_TRADING: u32 = 1;

/// Minimum account length the parser touches: through the aggregate
/// `PriceInfo` (bytes 208..240). Component prices past byte 240 are
/// intentionally ignored — the aggregate is the consensus value.
pub const PYTH_MIN_ACCOUNT_LEN: usize = 240;

/// Byte offsets into a Pyth v2 price account (pyth-client `Price`
/// struct, `#[repr(C)]`):
///
/// ```text
/// 0..4    magic: u32            0xa1b2c3d4
/// 4..8    ver: u32              2
/// 8..12   atype: u32            2 (price)
/// 12..16  size: u32
/// 16..20  ptype: u32            1 (price)
/// 20..24  expo: i32             10^expo scales the price
/// 24..32  num / num_qt: u32s
/// 32..48  last_slot / valid_slot: u64s
/// 48..96  ema_price / ema_confidence: 24-byte Emas
/// 96..104 timestamp: i64        unix time of the current aggregate
/// 104..112 min_publishers / message_sent / max_latency / flags: u8s,
///         feed_index: u32
/// 112..176 prod / next: [u8; 32]
/// 176..208 prev_slot / prev_price / prev_conf / prev_timestamp
/// 208..216 agg.price: i64
/// 216..224 agg.conf: u64
/// 224..228 agg.status: u32      1 = trading
/// 228..232 agg.corp_act: u32
/// 232..240 agg.pub_slot: u64
/// ```
pub mod pyth_offsets {
    pub const MAGIC: usize = 0;
    pub const VER: usize = 4;
    pub const ATYPE: usize = 8;
    pub const PTYPE: usize = 16;
    pub const EXPO: usize = 20;
    pub const TIMESTAMP: usize = 96;
    pub const AGG_PRICE: usize = 208;
    pub const AGG_CONF: usize = 216;
    pub const AGG_STATUS: usize = 224;
    pub const AGG_PUB_SLOT: usize = 232;
}

/// A validated Pyth v2 price quote, ready for the AV-113 gate.
/// Construct with [`PythPriceFeed::from_account_data`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PythPriceFeed {
    /// Normalized price in [`ORACLE_QUOTE_DECIMALS`] decimals.
    price: u64,
    /// The account's publish timestamp (unix seconds).
    observed_at: u64,
    /// The account's aggregate publish slot.
    pub_slot: u64,
}

impl PythPriceFeed {
    /// Parse and validate a Pyth v2 price account.
    ///
    /// Fail-closed mapping:
    /// - account shorter than [`PYTH_MIN_ACCOUNT_LEN`], or a header
    ///   mismatch (`magic` / `ver` / `atype` / `ptype`), or an exponent
    ///   outside `[-18, 0]` → [`EscrowError::InvalidOracleAccount`]
    ///   (code 279);
    /// - publish timestamp missing/non-positive, in the future, or
    ///   older than `params.max_age_secs` → [`EscrowError::OraclePriceStale`]
    ///   (code 280);
    /// - non-positive aggregate price, non-trading status, confidence
    ///   wider than `params.max_conf_bps` of the price, or a
    ///   normalization overflow / round-to-zero →
    ///   [`EscrowError::OraclePriceUnreliable`] (code 281).
    ///
    /// The exponent is normalized into [`ORACLE_QUOTE_DECIMALS`]
    /// decimals: with `shift = expo + 8`, a non-negative shift
    /// multiplies by `10^shift` (checked), a negative shift divides by
    /// `10^-shift` rounding down (a zero result is rejected — a price
    /// that rounds to zero is not actionable).
    pub fn from_account_data(
        account: &[u8],
        now: u64,
        params: OracleValidationParams,
    ) -> Result<Self, EscrowError> {
        use pyth_offsets::*;
        if account.len() < PYTH_MIN_ACCOUNT_LEN {
            return Err(EscrowError::InvalidOracleAccount);
        }
        let u32_at = |off: usize| u32::from_le_bytes(account[off..off + 4].try_into().unwrap());
        let u64_at = |off: usize| u64::from_le_bytes(account[off..off + 8].try_into().unwrap());
        let i64_at = |off: usize| i64::from_le_bytes(account[off..off + 8].try_into().unwrap());
        if u32_at(MAGIC) != PYTH_MAGIC
            || u32_at(VER) != PYTH_VERSION
            || u32_at(ATYPE) != PYTH_ATYPE_PRICE
            || u32_at(PTYPE) != PYTH_PTYPE_PRICE
        {
            return Err(EscrowError::InvalidOracleAccount);
        }
        let expo = i32::from_le_bytes(account[EXPO..EXPO + 4].try_into().unwrap());
        if expo > 0 || expo < -18 {
            return Err(EscrowError::InvalidOracleAccount);
        }
        let price_raw = i64_at(AGG_PRICE);
        if price_raw <= 0 {
            return Err(EscrowError::OraclePriceUnreliable);
        }
        if u32_at(AGG_STATUS) != PYTH_STATUS_TRADING {
            return Err(EscrowError::OraclePriceUnreliable);
        }
        let conf = u64_at(AGG_CONF);
        let price_u64 = price_raw as u64;
        // Confidence wider than max_conf_bps of the price: the oracle
        // itself flags the quote as too uncertain. u128 math avoids
        // overflow on the multiply.
        if (conf as u128) * (CONF_BPS_DENOMINATOR as u128)
            > (price_u64 as u128) * (params.max_conf_bps as u128)
        {
            return Err(EscrowError::OraclePriceUnreliable);
        }
        let timestamp = i64_at(TIMESTAMP);
        if timestamp <= 0 {
            return Err(EscrowError::OraclePriceStale);
        }
        let observed_at = timestamp as u64;
        if observed_at > now || now - observed_at > params.max_age_secs {
            return Err(EscrowError::OraclePriceStale);
        }
        let shift = expo + ORACLE_QUOTE_DECIMALS as i32; // in [-10, 8]
        let price = if shift >= 0 {
            price_u64
                .checked_mul(10u64.pow(shift as u32))
                .ok_or(EscrowError::OraclePriceUnreliable)?
        } else {
            let q = price_u64 / 10u64.pow((-shift) as u32);
            if q == 0 {
                return Err(EscrowError::OraclePriceUnreliable);
            }
            q
        };
        Ok(PythPriceFeed {
            price,
            observed_at,
            pub_slot: u64_at(AGG_PUB_SLOT),
        })
    }

    /// Normalized price in [`ORACLE_QUOTE_DECIMALS`] decimals.
    pub fn price(&self) -> u64 {
        self.price
    }

    /// The account's publish timestamp (unix seconds).
    pub fn observed_at(&self) -> u64 {
        self.observed_at
    }

    /// The aggregate's publish slot.
    pub fn pub_slot(&self) -> u64 {
        self.pub_slot
    }
}

impl PriceFeed for PythPriceFeed {
    fn quote(&self) -> Option<PriceQuote> {
        Some(PriceQuote {
            price: self.price,
            observed_at: self.observed_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Switchboard v2 aggregator round
// ---------------------------------------------------------------------------

/// A decoded Switchboard v2 aggregator round, as the Anchor program
/// hands it to this adapter after zero-copy decoding the packed
/// `AggregatorAccountData` with the upstream `switchboard-v2` crate.
///
/// `result_mantissa` / `result_scale` are the `SwitchboardDecimal` of
/// `latest_confirmed_round.result` (value = `mantissa * 10^-scale`);
/// `round_open_timestamp` is `latest_confirmed_round.round_open_timestamp`;
/// `num_success` is `latest_confirmed_round.num_success`; and
/// `min_oracle_results` is the aggregator's configured quorum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwitchboardRound {
    pub result_mantissa: i128,
    pub result_scale: u32,
    pub round_open_timestamp: i64,
    pub num_success: i32,
    pub min_oracle_results: u32,
}

/// A validated Switchboard v2 quote, ready for the AV-113 gate.
/// Construct with [`SwitchboardPriceFeed::from_round`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwitchboardPriceFeed {
    /// Normalized price in [`ORACLE_QUOTE_DECIMALS`] decimals.
    price: u64,
    /// The round's open timestamp (unix seconds).
    observed_at: u64,
    /// Oracle successes backing the round.
    num_success: i32,
}

impl SwitchboardPriceFeed {
    /// Validate a decoded Switchboard round and normalize its decimal
    /// into [`ORACLE_QUOTE_DECIMALS`] decimals.
    ///
    /// Fail-closed mapping:
    /// - non-positive result, a scale that cannot normalize without
    ///   overflow, a result that normalizes to zero, or oracle-result
    ///   quorum not met (`num_success < min_oracle_results`, or a zero
    ///   quorum config) → [`EscrowError::OraclePriceUnreliable`]
    ///   (code 281);
    /// - round timestamp missing/non-positive, in the future, or older
    ///   than `params.max_age_secs` →
    ///   [`EscrowError::OraclePriceStale`] (code 280).
    ///
    /// Note: Switchboard carries no confidence interval on the round
    /// result, so `params.max_conf_bps` is unused here (kept in the
    /// shared params struct so one policy object configures both
    /// oracles).
    pub fn from_round(
        round: SwitchboardRound,
        now: u64,
        params: OracleValidationParams,
    ) -> Result<Self, EscrowError> {
        if round.result_mantissa <= 0 {
            return Err(EscrowError::OraclePriceUnreliable);
        }
        if round.min_oracle_results == 0
            || round.num_success < 0
            || (round.num_success as u32) < round.min_oracle_results
        {
            return Err(EscrowError::OraclePriceUnreliable);
        }
        if round.round_open_timestamp <= 0 {
            return Err(EscrowError::OraclePriceStale);
        }
        let observed_at = round.round_open_timestamp as u64;
        if observed_at > now || now - observed_at > params.max_age_secs {
            return Err(EscrowError::OraclePriceStale);
        }
        // Normalize mantissa * 10^-scale into 10^-8 units.
        let price_i128 = if round.result_scale >= ORACLE_QUOTE_DECIMALS {
            let divisor = pow10_i128(round.result_scale - ORACLE_QUOTE_DECIMALS)
                .ok_or(EscrowError::OraclePriceUnreliable)?;
            round.result_mantissa / divisor
        } else {
            let multiplier = pow10_i128(ORACLE_QUOTE_DECIMALS - round.result_scale)
                .ok_or(EscrowError::OraclePriceUnreliable)?;
            round
                .result_mantissa
                .checked_mul(multiplier)
                .ok_or(EscrowError::OraclePriceUnreliable)?
        };
        if price_i128 <= 0 || price_i128 > u64::MAX as i128 {
            return Err(EscrowError::OraclePriceUnreliable);
        }
        Ok(SwitchboardPriceFeed {
            price: price_i128 as u64,
            observed_at,
            num_success: round.num_success,
        })
    }

    /// Normalized price in [`ORACLE_QUOTE_DECIMALS`] decimals.
    pub fn price(&self) -> u64 {
        self.price
    }

    /// The round's open timestamp (unix seconds).
    pub fn observed_at(&self) -> u64 {
        self.observed_at
    }

    /// Oracle successes backing the round.
    pub fn num_success(&self) -> i32 {
        self.num_success
    }
}

impl PriceFeed for SwitchboardPriceFeed {
    fn quote(&self) -> Option<PriceQuote> {
        Some(PriceQuote {
            price: self.price,
            observed_at: self.observed_at,
        })
    }
}

/// `10^exp` as `i128`, or `None` on overflow.
fn pow10_i128(exp: u32) -> Option<i128> {
    let mut acc: i128 = 1;
    for _ in 0..exp {
        acc = acc.checked_mul(10)?;
    }
    Some(acc)
}

/// Audit-event JSON for an oracle quote (hand-written):
/// `{"event":"oracle_quote","source":"pyth|switchboard","price":
/// <u64>,"observed_at":<u64>}`.
pub fn oracle_audit_json(source: OracleSource, price: u64, observed_at: u64) -> String {
    let mut s = String::from("{\"event\":\"oracle_quote\",\"source\":\"");
    s.push_str(source.as_str());
    s.push_str("\",\"price\":");
    s.push_str(&price.to_string());
    s.push_str(",\"observed_at\":");
    s.push_str(&observed_at.to_string());
    s.push('}');
    s
}

#[cfg(test)]
mod oracle_adapter_tests {
    use super::*;
    use pyth_offsets::*;

    fn params() -> OracleValidationParams {
        OracleValidationParams {
            max_age_secs: 120,
            max_conf_bps: 200, // 2%
        }
    }

    /// Build a synthetic Pyth v2 price account following the real
    /// `#[repr(C)]` layout pinned in [`pyth_offsets`].
    fn pyth_account(expo: i32, price: i64, conf: u64, status: u32, timestamp: i64) -> Vec<u8> {
        let mut a = vec![0u8; 512];
        a[MAGIC..MAGIC + 4].copy_from_slice(&PYTH_MAGIC.to_le_bytes());
        a[VER..VER + 4].copy_from_slice(&PYTH_VERSION.to_le_bytes());
        a[ATYPE..ATYPE + 4].copy_from_slice(&PYTH_ATYPE_PRICE.to_le_bytes());
        a[PTYPE..PTYPE + 4].copy_from_slice(&PYTH_PTYPE_PRICE.to_le_bytes());
        a[EXPO..EXPO + 4].copy_from_slice(&expo.to_le_bytes());
        a[TIMESTAMP..TIMESTAMP + 8].copy_from_slice(&timestamp.to_le_bytes());
        a[AGG_PRICE..AGG_PRICE + 8].copy_from_slice(&price.to_le_bytes());
        a[AGG_CONF..AGG_CONF + 8].copy_from_slice(&conf.to_le_bytes());
        a[AGG_STATUS..AGG_STATUS + 4].copy_from_slice(&status.to_le_bytes());
        a[AGG_PUB_SLOT..AGG_PUB_SLOT + 8].copy_from_slice(&1_000_000u64.to_le_bytes());
        a
    }

    fn switchboard_round() -> SwitchboardRound {
        SwitchboardRound {
            result_mantissa: 1_234_560_000, // $12.3456 at scale 8
            result_scale: 8,
            round_open_timestamp: 1_700_000_000,
            num_success: 5,
            min_oracle_results: 3,
        }
    }

    #[test]
    fn pyth_parses_valid_account() {
        // BTC-ish: 97_500.00 at expo -8 -> 9_750_000_000_000 raw.
        let now = 1_700_000_100;
        let a = pyth_account(-8, 9_750_000_000_000, 1_000_000_000, PYTH_STATUS_TRADING, 1_700_000_050);
        let f = PythPriceFeed::from_account_data(&a, now, params()).unwrap();
        // expo -8 == 8 quote decimals: no scaling.
        assert_eq!(f.price(), 9_750_000_000_000);
        assert_eq!(f.observed_at(), 1_700_000_050);
        assert_eq!(f.pub_slot(), 1_000_000);
        let q = PriceFeed::quote(&f).unwrap();
        assert_eq!(q.price, 9_750_000_000_000);
        assert_eq!(q.observed_at, 1_700_000_050);
    }

    #[test]
    fn pyth_exponent_scaling() {
        let now = 1_700_000_100;
        // expo -6: $25.00 raw 25_000000 -> 2_500_000_000 in 8 decimals.
        let a = pyth_account(-6, 25_000_000, 10_000, PYTH_STATUS_TRADING, 1_700_000_050);
        let f = PythPriceFeed::from_account_data(&a, now, params()).unwrap();
        assert_eq!(f.price(), 2_500_000_000);
        // expo -9: $100.00 raw 100_000_000_000 -> 10_000_000_000 (rounds down).
        let a = pyth_account(-9, 100_000_000_000, 10_000, PYTH_STATUS_TRADING, 1_700_000_050);
        let f = PythPriceFeed::from_account_data(&a, now, params()).unwrap();
        assert_eq!(f.price(), 10_000_000_000);
        // expo 0: $7 raw 7 -> 700_000_000 (conf 0: 2% of 7 rounds down).
        let a = pyth_account(0, 7, 0, PYTH_STATUS_TRADING, 1_700_000_050);
        let f = PythPriceFeed::from_account_data(&a, now, params()).unwrap();
        assert_eq!(f.price(), 700_000_000);
    }

    #[test]
    fn pyth_rejects_bad_header() {
        let now = 1_700_000_100;
        let good = || pyth_account(-8, 9_750_000_000_000, 1_000_000_000, PYTH_STATUS_TRADING, 1_700_000_050);
        // Too short.
        assert_eq!(
            PythPriceFeed::from_account_data(&good()[..239], now, params()).unwrap_err(),
            EscrowError::InvalidOracleAccount
        );
        // Bad magic.
        let mut a = good();
        a[MAGIC..MAGIC + 4].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        assert_eq!(
            PythPriceFeed::from_account_data(&a, now, params()).unwrap_err(),
            EscrowError::InvalidOracleAccount
        );
        // Bad version / account type / price type.
        for off in [VER, ATYPE, PTYPE] {
            let mut a = good();
            a[off..off + 4].copy_from_slice(&9u32.to_le_bytes());
            assert_eq!(
                PythPriceFeed::from_account_data(&a, now, params()).unwrap_err(),
                EscrowError::InvalidOracleAccount,
                "offset {off}"
            );
        }
        // Exponent out of the supported range.
        let a = pyth_account(2, 100, 1, PYTH_STATUS_TRADING, 1_700_000_050);
        assert_eq!(
            PythPriceFeed::from_account_data(&a, now, params()).unwrap_err(),
            EscrowError::InvalidOracleAccount
        );
        let a = pyth_account(-19, 100, 1, PYTH_STATUS_TRADING, 1_700_000_050);
        assert_eq!(
            PythPriceFeed::from_account_data(&a, now, params()).unwrap_err(),
            EscrowError::InvalidOracleAccount
        );
        assert_eq!(EscrowError::InvalidOracleAccount.code(), 279);
    }

    #[test]
    fn pyth_rejects_stale_quotes() {
        // Older than max_age_secs.
        let a = pyth_account(-8, 9_750_000_000_000, 1_000_000_000, PYTH_STATUS_TRADING, 1_700_000_000);
        let err = PythPriceFeed::from_account_data(&a, 1_700_000_121, params()).unwrap_err();
        assert_eq!(err, EscrowError::OraclePriceStale);
        // Exactly at the boundary is still fresh.
        PythPriceFeed::from_account_data(&a, 1_700_000_120, params()).unwrap();
        // Missing timestamp.
        let a = pyth_account(-8, 9_750_000_000_000, 1_000_000_000, PYTH_STATUS_TRADING, 0);
        let err = PythPriceFeed::from_account_data(&a, 1_700_000_100, params()).unwrap_err();
        assert_eq!(err, EscrowError::OraclePriceStale);
        // Timestamp in the future.
        let a = pyth_account(-8, 9_750_000_000_000, 1_000_000_000, PYTH_STATUS_TRADING, 1_700_000_200);
        let err = PythPriceFeed::from_account_data(&a, 1_700_000_100, params()).unwrap_err();
        assert_eq!(err, EscrowError::OraclePriceStale);
        assert_eq!(err.code(), 280);
    }

    #[test]
    fn pyth_rejects_unreliable_quotes() {
        let now = 1_700_000_100;
        // Non-trading status (0 = unknown).
        let a = pyth_account(-8, 9_750_000_000_000, 1_000_000_000, 0, 1_700_000_050);
        assert_eq!(
            PythPriceFeed::from_account_data(&a, now, params()).unwrap_err(),
            EscrowError::OraclePriceUnreliable
        );
        // Non-positive price.
        let a = pyth_account(-8, 0, 1_000_000_000, PYTH_STATUS_TRADING, 1_700_000_050);
        assert_eq!(
            PythPriceFeed::from_account_data(&a, now, params()).unwrap_err(),
            EscrowError::OraclePriceUnreliable
        );
        let a = pyth_account(-8, -5, 1_000_000_000, PYTH_STATUS_TRADING, 1_700_000_050);
        assert_eq!(
            PythPriceFeed::from_account_data(&a, now, params()).unwrap_err(),
            EscrowError::OraclePriceUnreliable
        );
        // Confidence wider than 2% of the price.
        let a = pyth_account(-8, 9_750_000_000_000, 300_000_000_000, PYTH_STATUS_TRADING, 1_700_000_050);
        assert_eq!(
            PythPriceFeed::from_account_data(&a, now, params()).unwrap_err(),
            EscrowError::OraclePriceUnreliable
        );
        // Confidence exactly at the boundary passes.
        let a = pyth_account(-8, 9_750_000_000_000, 195_000_000_000, PYTH_STATUS_TRADING, 1_700_000_050);
        PythPriceFeed::from_account_data(&a, now, params()).unwrap();
        // Normalization overflow: expo 0 with a huge price.
        let a = pyth_account(0, i64::MAX, 1, PYTH_STATUS_TRADING, 1_700_000_050);
        assert_eq!(
            PythPriceFeed::from_account_data(&a, now, params()).unwrap_err(),
            EscrowError::OraclePriceUnreliable
        );
        assert_eq!(EscrowError::OraclePriceUnreliable.code(), 281);
    }

    #[test]
    fn switchboard_validates_round_and_scales_decimal() {
        let now = 1_700_000_100;
        let f = SwitchboardPriceFeed::from_round(switchboard_round(), now, params()).unwrap();
        // scale 8 == 8 quote decimals: no scaling.
        assert_eq!(f.price(), 1_234_560_000);
        assert_eq!(f.observed_at(), 1_700_000_000);
        assert_eq!(f.num_success(), 5);
        let q = PriceFeed::quote(&f).unwrap();
        assert_eq!(q.price, 1_234_560_000);
        // scale 9: $12.3456 -> 1_234_560_000 (divides by 10).
        let r = SwitchboardRound { result_scale: 9, result_mantissa: 12_345_600_000, ..switchboard_round() };
        let f = SwitchboardPriceFeed::from_round(r, now, params()).unwrap();
        assert_eq!(f.price(), 1_234_560_000);
        // scale 6: multiplies by 100.
        let r = SwitchboardRound { result_scale: 6, result_mantissa: 12_345_600, ..switchboard_round() };
        let f = SwitchboardPriceFeed::from_round(r, now, params()).unwrap();
        assert_eq!(f.price(), 1_234_560_000);
    }

    #[test]
    fn switchboard_rejects_bad_rounds() {
        let now = 1_700_000_100;
        // Non-positive result.
        let r = SwitchboardRound { result_mantissa: 0, ..switchboard_round() };
        assert_eq!(
            SwitchboardPriceFeed::from_round(r, now, params()).unwrap_err(),
            EscrowError::OraclePriceUnreliable
        );
        let r = SwitchboardRound { result_mantissa: -10, ..switchboard_round() };
        assert_eq!(
            SwitchboardPriceFeed::from_round(r, now, params()).unwrap_err(),
            EscrowError::OraclePriceUnreliable
        );
        // Quorum not met.
        let r = SwitchboardRound { num_success: 2, ..switchboard_round() };
        assert_eq!(
            SwitchboardPriceFeed::from_round(r, now, params()).unwrap_err(),
            EscrowError::OraclePriceUnreliable
        );
        let r = SwitchboardRound { min_oracle_results: 0, ..switchboard_round() };
        assert_eq!(
            SwitchboardPriceFeed::from_round(r, now, params()).unwrap_err(),
            EscrowError::OraclePriceUnreliable
        );
        // Stale round.
        let r = switchboard_round();
        let err = SwitchboardPriceFeed::from_round(r, 1_700_000_121, params()).unwrap_err();
        assert_eq!(err, EscrowError::OraclePriceStale);
        // Normalization overflow.
        let r = SwitchboardRound { result_scale: 0, result_mantissa: i128::MAX, ..switchboard_round() };
        assert_eq!(
            SwitchboardPriceFeed::from_round(r, now, params()).unwrap_err(),
            EscrowError::OraclePriceUnreliable
        );
    }

    #[test]
    fn feeds_drive_the_av113_gate() {
        // End-to-end: an adapter quote passes the AV-113 price gate
        // when it clears the target, fails when it does not.
        use crate::{Escrow, PriceDirection, PriceGate};
        let now = 1_700_000_100;
        let a = pyth_account(-8, 9_750_000_000_000, 1_000_000_000, PYTH_STATUS_TRADING, 1_700_000_050);
        let feed = PythPriceFeed::from_account_data(&a, now, params()).unwrap();
        let mk = |target: u64| {
            Escrow::initialize([0xAA; 32], [0xBB; 32], 1_000_000, 1_800_000_000)
                .unwrap()
                .with_price_gate(PriceGate {
                    direction: PriceDirection::AtOrAbove,
                    target,
                    max_staleness_secs: 300,
                })
                .unwrap()
        };
        mk(9_000_000_000_000).require_price_gate(&feed, now).unwrap();
        assert_eq!(
            mk(10_000_000_000_000).require_price_gate(&feed, now).unwrap_err(),
            EscrowError::PriceGateNotSatisfied
        );
    }

    #[test]
    fn audit_json_tags_the_source() {
        let j = oracle_audit_json(OracleSource::Pyth, 9_750_000_000_000, 1_700_000_050);
        assert!(j.contains("\"event\":\"oracle_quote\""));
        assert!(j.contains("\"source\":\"pyth\""));
        assert!(j.contains("\"price\":9750000000000"));
        let j = oracle_audit_json(OracleSource::Switchboard, 1_234_560_000, 1_700_000_000);
        assert!(j.contains("\"source\":\"switchboard\""));
    }

    #[test]
    fn error_codes_pinned() {
        // Never renumber: the Anchor layer assigns one program error
        // per variant and off-chain clients match on these numbers.
        assert_eq!(EscrowError::InvalidOracleAccount.code(), 279);
        assert_eq!(EscrowError::OraclePriceStale.code(), 280);
        assert_eq!(EscrowError::OraclePriceUnreliable.code(), 281);
        for e in [
            EscrowError::InvalidOracleAccount,
            EscrowError::OraclePriceStale,
            EscrowError::OraclePriceUnreliable,
        ] {
            assert!(EscrowError::all().contains(&e));
        }
        // AV-193 appends 3 oracle-adapter errors after AV-192's
        // SealedBidBookFull (278).
        assert_eq!(EscrowError::all().len(), 207); // AV-195: +7, AV-196: +6, AV-197: +5
    }
}
