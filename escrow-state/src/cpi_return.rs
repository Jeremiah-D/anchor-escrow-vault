//! AV-172: post-CPI return-data verification (off-chain, zero dependencies).
//!
//! Solana programs can attest up to 1024 bytes through
//! `set_return_data`, and the runtime hands the *caller*
//! `(program_id, data)` via `get_return_data` after a CPI. A
//! settlement CPI whose instruction "succeeded" may still have
//! delivered the wrong amount — a hostile or buggy callee — so this
//! module checks the callee's own post-execution attestation against
//! the return layout the settlement declared
//! ([`ReturnDataExpectation`]).
//!
//! This is the execution-*after* counterpart to two earlier gates:
//!
//! - [`CpiAllowlist`](super::CpiAllowlist) decides *who* may be called —
//!   the program-id gate, before anything runs;
//! - the AV-132 slippage pre-check ([`CpiError::SlippageExceeded`])
//!   rejects a plan whose quoted payout is already below the caller's
//!   floor — the plan gate, before execution.
//!
//! This module runs *after* execution: the instruction succeeded, now
//! prove the money actually arrived. The executor — the on-chain
//! program's post-invoke check, or an off-chain keeper settling through
//! [`payout_plan`](super::payout_plan) and friends — declares the
//! expected return layout up front, then calls
//! [`verify_cpi_return_data`] with what the runtime handed back.
//!
//! Missing return data is a policy choice, not an automatic pass:
//! [`MissingReturnDataPolicy::FailClosed`] (the default) rejects — a
//! program that attests nothing proves nothing — while
//! [`MissingReturnDataPolicy::Warn`] records a warning attestation and
//! proceeds, for legacy targets that predate `set_return_data`. The
//! Anchor skeleton's `cpi_verify_return_data` documents the on-chain
//! wiring (`get_return_data` after the invoke); the attestation rides
//! the settlement event's
//! [`CpiRouteAudit::return_data`](super::CpiRouteAudit::return_data)
//! for the indexer.

use super::cpi::{CpiError, Pubkey};

/// The Solana runtime's return-data cap: `set_return_data` stores at
/// most 1024 bytes. Anything longer could not have come from
/// `get_return_data` and is rejected as
/// [`CpiError::CpiReturnDataMismatch`].
pub const MAX_RETURN_DATA_LEN: usize = 1024;

/// What the runtime hands back after a CPI: the program that set the
/// return data and the data itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpiReturnData<'a> {
    /// The program whose `set_return_data` produced this payload —
    /// must equal the CPI target, or the attestation is about some
    /// other call.
    pub program_id: Pubkey,
    /// The raw return-data bytes.
    pub data: &'a [u8],
}

/// The return layout a settlement CPI is expected to produce: a
/// one-byte discriminant identifying the attestation shape, with the
/// little-endian u64 amount the callee claims it delivered at
/// `amount_offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReturnDataExpectation {
    /// Expected first byte of the return-data payload.
    pub discriminant: u8,
    /// Byte offset of the LE u64 amount field, measured from the start
    /// of the payload (greater than 1 when the layout carries header
    /// fields after the discriminant).
    pub amount_offset: usize,
    /// The planned amount the settlement was supposed to deliver —
    /// the number the attested amount is compared against.
    pub expected_amount: u64,
}

impl ReturnDataExpectation {
    /// Declare the expected return layout. Infallible by design: an
    /// expectation no payload can satisfy (e.g. an `amount_offset`
    /// past the end of any observed data) simply never verifies —
    /// [`verify_cpi_return_data`] reports
    /// [`CpiError::CpiReturnDataMismatch`], it does not need a
    /// separate caller-bug error.
    pub fn new(discriminant: u8, amount_offset: usize, expected_amount: u64) -> Self {
        Self {
            discriminant,
            amount_offset,
            expected_amount,
        }
    }
}

/// What to do when a settlement CPI returns no return data at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MissingReturnDataPolicy {
    /// Reject: a program that attests nothing proves nothing. The
    /// settlement fails with [`CpiError::CpiReturnDataMissing`].
    #[default]
    FailClosed,
    /// Proceed with a warning attestation: for legacy targets that
    /// predate `set_return_data`. The caller MUST record the warning
    /// — the money moved unverified.
    Warn,
}

/// The outcome of [`verify_cpi_return_data`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnDataVerification {
    /// The callee attested exactly the planned amount.
    Matched {
        /// The attested amount (== the expectation's `expected_amount`).
        amount: u64,
    },
    /// No return data was observed; accepted under the `Warn` policy.
    /// The settlement is *unverified* — record the warning.
    AcceptedWithWarning,
}

/// Verify a settlement CPI's post-execution return data.
///
/// Checks, in order:
/// 1. some return data was observed (else the missing-data policy
///    decides);
/// 2. the payload fits the on-chain 1024-byte cap;
/// 3. the attesting program is the CPI target (a return from any other
///    program is the confused-deputy shape — it attests nothing about
///    this settlement);
/// 4. the discriminant matches the declared layout;
/// 5. the payload is long enough to hold the amount field;
/// 6. the attested LE u64 amount equals the planned amount.
///
/// Any failure is [`CpiError::CpiReturnDataMismatch`], except missing
/// data under [`MissingReturnDataPolicy::FailClosed`], which is
/// [`CpiError::CpiReturnDataMissing`].
pub fn verify_cpi_return_data(
    target: Pubkey,
    expectation: &ReturnDataExpectation,
    observed: Option<CpiReturnData<'_>>,
    missing_policy: MissingReturnDataPolicy,
) -> Result<ReturnDataVerification, CpiError> {
    let observed = match observed {
        Some(o) => o,
        None => {
            return match missing_policy {
                MissingReturnDataPolicy::FailClosed => Err(CpiError::CpiReturnDataMissing),
                MissingReturnDataPolicy::Warn => Ok(ReturnDataVerification::AcceptedWithWarning),
            };
        }
    };
    if observed.data.len() > MAX_RETURN_DATA_LEN {
        return Err(CpiError::CpiReturnDataMismatch);
    }
    if observed.program_id != target {
        return Err(CpiError::CpiReturnDataMismatch);
    }
    let data = observed.data;
    if data.is_empty() || data[0] != expectation.discriminant {
        return Err(CpiError::CpiReturnDataMismatch);
    }
    let end = expectation.amount_offset.saturating_add(8);
    if data.len() < end {
        return Err(CpiError::CpiReturnDataMismatch);
    }
    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&data[expectation.amount_offset..end]);
    let amount = u64::from_le_bytes(amount_bytes);
    if amount != expectation.expected_amount {
        return Err(CpiError::CpiReturnDataMismatch);
    }
    Ok(ReturnDataVerification::Matched { amount })
}

/// The return-data attestation carried by
/// [`CpiRouteAudit::return_data`](super::CpiRouteAudit::return_data) on
/// the settlement event — the indexer's proof that the post-execution
/// check ran and what it concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpiReturnDataAudit {
    /// The planned amount the settlement was supposed to deliver.
    pub expected_amount: u64,
    /// The amount the callee attested via return data. Equals
    /// `expected_amount` on the verified path; `0` when the absence
    /// of return data was accepted under the `Warn` policy — nothing
    /// was attested.
    pub attested_amount: u64,
    /// True when the missing-data `Warn` policy accepted the absence
    /// of return data: the money moved unverified.
    pub accepted_without_attestation: bool,
}

impl CpiReturnDataAudit {
    /// Build the audit record from a verification outcome. A mismatch
    /// never reaches this constructor — it aborts the settlement
    /// instead, so the audit log only ever records verified or
    /// warn-accepted settlements.
    pub fn from_verification(
        expectation: &ReturnDataExpectation,
        verification: ReturnDataVerification,
    ) -> Self {
        match verification {
            ReturnDataVerification::Matched { amount } => Self {
                expected_amount: expectation.expected_amount,
                attested_amount: amount,
                accepted_without_attestation: false,
            },
            ReturnDataVerification::AcceptedWithWarning => Self {
                expected_amount: expectation.expected_amount,
                attested_amount: 0,
                accepted_without_attestation: true,
            },
        }
    }
}

#[cfg(test)]
mod cpi_return_tests {
    use super::*;

    const TARGET: Pubkey = [7u8; 32];
    const OTHER: Pubkey = [9u8; 32];

    /// Build a payload: discriminant, `header_len` header bytes, then
    /// the LE u64 amount.
    fn payload(discriminant: u8, header_len: usize, amount: u64) -> Vec<u8> {
        let mut v = vec![discriminant];
        v.extend(std::iter::repeat(0xAA).take(header_len));
        v.extend_from_slice(&amount.to_le_bytes());
        v
    }

    fn observed<'a>(program_id: Pubkey, data: &'a [u8]) -> Option<CpiReturnData<'a>> {
        Some(CpiReturnData { program_id, data })
    }

    #[test]
    fn matched_happy_path_with_header_offset() {
        // Layout: discriminant 0x01, 3 header bytes, amount at offset 4.
        let data = payload(0x01, 3, 500_000);
        let exp = ReturnDataExpectation::new(0x01, 4, 500_000);
        assert_eq!(
            verify_cpi_return_data(TARGET, &exp, observed(TARGET, &data), MissingReturnDataPolicy::FailClosed),
            Ok(ReturnDataVerification::Matched { amount: 500_000 })
        );
    }

    #[test]
    fn amount_mismatch_rejects() {
        let data = payload(0x01, 3, 499_999);
        let exp = ReturnDataExpectation::new(0x01, 4, 500_000);
        assert_eq!(
            verify_cpi_return_data(TARGET, &exp, observed(TARGET, &data), MissingReturnDataPolicy::FailClosed),
            Err(CpiError::CpiReturnDataMismatch)
        );
    }

    #[test]
    fn wrong_discriminant_rejects() {
        let data = payload(0x02, 3, 500_000);
        let exp = ReturnDataExpectation::new(0x01, 4, 500_000);
        assert_eq!(
            verify_cpi_return_data(TARGET, &exp, observed(TARGET, &data), MissingReturnDataPolicy::FailClosed),
            Err(CpiError::CpiReturnDataMismatch)
        );
    }

    #[test]
    fn truncated_payload_rejects() {
        // Discriminant present but the amount field is cut off.
        let data = payload(0x01, 3, 500_000);
        let truncated = &data[..data.len() - 2];
        let exp = ReturnDataExpectation::new(0x01, 4, 500_000);
        assert_eq!(
            verify_cpi_return_data(TARGET, &exp, observed(TARGET, truncated), MissingReturnDataPolicy::FailClosed),
            Err(CpiError::CpiReturnDataMismatch)
        );
    }

    #[test]
    fn empty_payload_rejects() {
        let exp = ReturnDataExpectation::new(0x01, 4, 500_000);
        assert_eq!(
            verify_cpi_return_data(TARGET, &exp, observed(TARGET, &[]), MissingReturnDataPolicy::FailClosed),
            Err(CpiError::CpiReturnDataMismatch)
        );
    }

    #[test]
    fn return_from_wrong_program_rejects() {
        // Same bytes, attested by a different program: the
        // confused-deputy shape. Must not verify.
        let data = payload(0x01, 3, 500_000);
        let exp = ReturnDataExpectation::new(0x01, 4, 500_000);
        assert_eq!(
            verify_cpi_return_data(TARGET, &exp, observed(OTHER, &data), MissingReturnDataPolicy::FailClosed),
            Err(CpiError::CpiReturnDataMismatch)
        );
    }

    #[test]
    fn oversized_payload_rejects() {
        // Longer than the on-chain 1024-byte cap: could not have come
        // from get_return_data.
        let mut data = payload(0x01, 3, 500_000);
        data.extend(std::iter::repeat(0u8).take(MAX_RETURN_DATA_LEN));
        let exp = ReturnDataExpectation::new(0x01, 4, 500_000);
        assert_eq!(
            verify_cpi_return_data(TARGET, &exp, observed(TARGET, &data), MissingReturnDataPolicy::FailClosed),
            Err(CpiError::CpiReturnDataMismatch)
        );
    }

    #[test]
    fn missing_return_data_fail_closed_by_default() {
        let exp = ReturnDataExpectation::new(0x01, 4, 500_000);
        // Default policy is FailClosed.
        assert_eq!(MissingReturnDataPolicy::default(), MissingReturnDataPolicy::FailClosed);
        assert_eq!(
            verify_cpi_return_data(TARGET, &exp, None, MissingReturnDataPolicy::default()),
            Err(CpiError::CpiReturnDataMissing)
        );
        assert_eq!(
            verify_cpi_return_data(TARGET, &exp, None, MissingReturnDataPolicy::FailClosed),
            Err(CpiError::CpiReturnDataMissing)
        );
    }

    #[test]
    fn missing_return_data_warn_accepts_with_warning() {
        let exp = ReturnDataExpectation::new(0x01, 4, 500_000);
        assert_eq!(
            verify_cpi_return_data(TARGET, &exp, None, MissingReturnDataPolicy::Warn),
            Ok(ReturnDataVerification::AcceptedWithWarning)
        );
    }

    #[test]
    fn warn_policy_does_not_excuse_bad_data() {
        // Warn only covers *missing* data; present-but-wrong data
        // still mismatches.
        let data = payload(0x01, 3, 1);
        let exp = ReturnDataExpectation::new(0x01, 4, 500_000);
        assert_eq!(
            verify_cpi_return_data(TARGET, &exp, observed(TARGET, &data), MissingReturnDataPolicy::Warn),
            Err(CpiError::CpiReturnDataMismatch)
        );
    }

    #[test]
    fn amount_field_at_exact_end_verifies() {
        // Boundary: amount occupies the last 8 bytes exactly.
        let data = payload(0x01, 0, 42);
        let exp = ReturnDataExpectation::new(0x01, 1, 42);
        assert_eq!(
            verify_cpi_return_data(TARGET, &exp, observed(TARGET, &data), MissingReturnDataPolicy::FailClosed),
            Ok(ReturnDataVerification::Matched { amount: 42 })
        );
    }

    #[test]
    fn audit_record_from_matched_verification() {
        let exp = ReturnDataExpectation::new(0x01, 4, 500_000);
        let audit = CpiReturnDataAudit::from_verification(
            &exp,
            ReturnDataVerification::Matched { amount: 500_000 },
        );
        assert_eq!(audit.expected_amount, 500_000);
        assert_eq!(audit.attested_amount, 500_000);
        assert!(!audit.accepted_without_attestation);
    }

    #[test]
    fn audit_record_from_warn_acceptance() {
        let exp = ReturnDataExpectation::new(0x01, 4, 500_000);
        let audit = CpiReturnDataAudit::from_verification(
            &exp,
            ReturnDataVerification::AcceptedWithWarning,
        );
        assert_eq!(audit.expected_amount, 500_000);
        assert_eq!(audit.attested_amount, 0);
        assert!(audit.accepted_without_attestation);
    }
}
