//! RPC commitment levels for off-chain reads (AV-171).
//!
//! The keeper talks to Solana RPC for everything it cannot read from
//! vault accounts: lifecycle scans over program accounts, oracle price
//! reads, and bundle-landing confirmations. Every RPC read carries a
//! *commitment level* — how final the observed data is — and treating
//! a `processed`-level observation as settled truth is a dirty read:
//! the slot can be orphaned and the "observed" state never happened.
//!
//! This module makes the commitment explicit:
//!
//! - [`CommitmentLevel`]: `Processed < Confirmed < Finalized` (the
//!   Solana RPC vocabulary), ordered so levels compare directly.
//! - [`ReadOperation`] + [`required_commitment`]: the risk-tiered
//!   table. Monitoring-class reads ([`ReadOperation::KeeperLifecycleScan`],
//!   [`ReadOperation::PriceRead`]) require `Confirmed` — lower
//!   latency, and the next tick's re-scan repairs an orphaned
//!   observation before anything is built on it. Anything that gates
//!   or confirms settlement ([`ReadOperation::PreSettlementCheck`],
//!   [`ReadOperation::BundleLandingConfirmation`]) requires
//!   `Finalized`.
//! - [`read_with_commitment`]: performs the injectable read until the
//!   observed commitment meets the requirement or the attempt budget
//!   runs out. A read that never reaches the required level is an
//!   explicit [`CommitmentError::CommitmentNotMet`] — the function has
//!   no downgrade path: it never returns a value observed below the
//!   required commitment.
//! - [`CommitmentAudit`]: every call — success or failure — yields a
//!   structured audit event carrying the operation, the required and
//!   best-observed levels, and the attempt count, for the keeper's
//!   audit sink (the AV-36 convention: failed security-relevant calls
//!   are still audited).
//!
//! # The no-silent-downgrade rule
//!
//! This is the module's iron rule, mirroring the AV-169 no-fallback
//! rule: when the RPC cannot serve the required commitment, the read
//! FAILS. Falling back to a lower commitment would let the keeper act
//! on orphanable state — e.g. listing an escrow as executable from a
//! `processed` scan, or reporting a bundle landed from a `confirmed`
//! observation that a reorg later un-lands. A caller that wants a
//! lower commitment says so explicitly by choosing a different
//! [`ReadOperation`] (or its own required level via
//! [`check_commitment`]) — the downgrade is then a visible,
//! deliberate decision, never a silent one.
//!
//! # Keeper adoption
//!
//! The keeper wraps each RPC call in
//! [`read_with_commitment`], e.g. the AV-20 lifecycle scan passes
//! [`ReadOperation::KeeperLifecycleScan`], the AV-169 bundle-relay
//! landing poll passes
//! [`ReadOperation::BundleLandingConfirmation`], and feeds
//! [`CommitmentAudit::to_json`] to its audit sink next to the AV-18
//! indexer events. The read closure owns transport and pacing; this
//! module only enforces the commitment contract.

/// How final an RPC observation is. Declaration order IS the strength
/// order: `Processed < Confirmed < Finalized`, so levels compare with
/// the derived `Ord`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommitmentLevel {
    /// The node's latest processed slot — may still be orphaned.
    Processed,
    /// Voted on by a supermajority — orphan risk is negligible, but
    /// not zero.
    Confirmed,
    /// Rooted by a supermajority — cannot be rolled back.
    Finalized,
}

impl CommitmentLevel {
    /// The Solana RPC name (`"processed"` / `"confirmed"` /
    /// `"finalized"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            CommitmentLevel::Processed => "processed",
            CommitmentLevel::Confirmed => "confirmed",
            CommitmentLevel::Finalized => "finalized",
        }
    }

    /// `true` when `self` is at least as final as `required`.
    pub fn satisfies(&self, required: CommitmentLevel) -> bool {
        *self >= required
    }
}

/// Off-chain read operations, tiered by the risk of acting on a dirty
/// (orphanable) observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadOperation {
    /// Keeper lifecycle scan (AV-20): which escrows have an executable
    /// action right now. Monitoring-class: `confirmed` keeps scan
    /// latency low, and the next tick's re-scan repairs an orphaned
    /// listing before any transaction is built on it.
    KeeperLifecycleScan,
    /// Oracle price reads (AV-113 / AV-128 gates): quote history for
    /// TWAP evaluation. Monitoring-class like the scan; a
    /// settlement-time gate re-checks at `Finalized` before the keeper
    /// signs anything (see `PreSettlementCheck`).
    PriceRead,
    /// The final read before the keeper builds or signs a settlement
    /// transaction: the escrow state the settlement depends on must be
    /// rooted, or the transaction may execute against rolled-back
    /// state.
    PreSettlementCheck,
    /// "Did the bundle land?" — reporting a bundle as landed from an
    /// orphanable observation would mark a settlement complete that
    /// never happened.
    BundleLandingConfirmation,
}

impl ReadOperation {
    /// Lowercase name for logs and audit events.
    pub fn as_str(&self) -> &'static str {
        match self {
            ReadOperation::KeeperLifecycleScan => "keeper_lifecycle_scan",
            ReadOperation::PriceRead => "price_read",
            ReadOperation::PreSettlementCheck => "pre_settlement_check",
            ReadOperation::BundleLandingConfirmation => "bundle_landing_confirmation",
        }
    }
}

/// The commitment level an operation's reads must reach: monitoring
/// reads accept `Confirmed` (lower latency), settlement-gating and
/// settlement-confirming reads require `Finalized`.
pub fn required_commitment(op: ReadOperation) -> CommitmentLevel {
    match op {
        ReadOperation::KeeperLifecycleScan | ReadOperation::PriceRead => CommitmentLevel::Confirmed,
        ReadOperation::PreSettlementCheck | ReadOperation::BundleLandingConfirmation => {
            CommitmentLevel::Finalized
        }
    }
}

/// One RPC read's result paired with the commitment it was observed
/// at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedRead<T> {
    /// The read's value.
    pub value: T,
    /// The commitment the RPC served it at.
    pub commitment: CommitmentLevel,
}

/// The pure gate: does this observation satisfy the requirement?
/// Returns the mismatch explicitly — no silent downgrade, ever.
pub fn check_commitment(
    observed: CommitmentLevel,
    required: CommitmentLevel,
) -> Result<(), CommitmentMismatch> {
    if observed.satisfies(required) {
        Ok(())
    } else {
        Err(CommitmentMismatch { required, observed })
    }
}

/// An observation below the required commitment, returned explicitly
/// by [`check_commitment`] instead of being silently accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentMismatch {
    /// The commitment the operation required.
    pub required: CommitmentLevel,
    /// The commitment the read actually reached.
    pub observed: CommitmentLevel,
}

/// Explicit failures from commitment-gated reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitmentError<E> {
    /// The read never reached the required commitment within the
    /// attempt budget. The value is NOT returned — there is no
    /// downgrade path.
    CommitmentNotMet {
        /// The commitment the operation required.
        required: CommitmentLevel,
        /// The best commitment any attempt reached (`None` when no
        /// attempt completed a read).
        best_observed: Option<CommitmentLevel>,
        /// Attempts consumed.
        attempts: u32,
    },
    /// The underlying read failed. Surfaced as-is, never swallowed: a
    /// transport failure must not look like a commitment failure.
    ReadFailed(E),
    /// `max_attempts == 0`: the waiter was given no budget at all.
    InvalidPolicy,
}

/// The structured audit event every commitment-gated read produces —
/// success or failure — for the keeper's audit sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitmentAudit {
    /// The operation that was read for.
    pub operation: ReadOperation,
    /// The commitment the operation required.
    pub required: CommitmentLevel,
    /// The best commitment any attempt reached (`None` when no read
    /// completed — e.g. `InvalidPolicy` or an immediate transport
    /// failure).
    pub best_observed: Option<CommitmentLevel>,
    /// Attempts consumed.
    pub attempts: u32,
    /// Whether a value at the required commitment was returned.
    pub met: bool,
}

impl CommitmentAudit {
    /// The audit-event JSON: `{"event":"commitment_read",
    /// "operation":<name>,"required":<level>,"best_observed":<level|null>,
    /// "attempts":n,"met":bool}`. Hand-written, zero dependencies —
    /// the keeper's audit pipeline ingests these next to the AV-18
    /// indexer events.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(160);
        s.push_str("{\"event\":\"commitment_read\",\"operation\":\"");
        s.push_str(self.operation.as_str());
        s.push_str("\",\"required\":\"");
        s.push_str(self.required.as_str());
        s.push_str("\",\"best_observed\":");
        match self.best_observed {
            Some(level) => {
                s.push('"');
                s.push_str(level.as_str());
                s.push('"');
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"attempts\":");
        s.push_str(&self.attempts.to_string());
        s.push_str(",\"met\":");
        s.push_str(&self.met.to_string());
        s.push('}');
        s
    }
}

/// Perform `read` until it returns a value observed at (or above)
/// the operation's required commitment, or the attempt budget runs
/// out.
///
/// Always returns the [`CommitmentAudit`] alongside the result, so
/// the keeper feeds its audit sink on both paths. The read is
/// injectable and synchronous: the caller owns transport and pacing —
/// this function performs at most `max_attempts` immediate attempts
/// and never sleeps.
///
/// A read that never reaches the required commitment is an explicit
/// [`CommitmentError::CommitmentNotMet`]: the value is not returned,
/// and there is no fallback to a lower commitment.
pub fn read_with_commitment<T, E, F>(
    operation: ReadOperation,
    mut read: F,
    max_attempts: u32,
) -> (Result<T, CommitmentError<E>>, CommitmentAudit)
where
    F: FnMut() -> Result<CommittedRead<T>, E>,
{
    let required = required_commitment(operation);
    let mut audit = CommitmentAudit {
        operation,
        required,
        best_observed: None,
        attempts: 0,
        met: false,
    };
    if max_attempts == 0 {
        return (Err(CommitmentError::InvalidPolicy), audit);
    }
    for _ in 0..max_attempts {
        audit.attempts += 1;
        match read() {
            Err(e) => return (Err(CommitmentError::ReadFailed(e)), audit),
            Ok(cr) => {
                if audit.best_observed.map_or(true, |best| cr.commitment > best) {
                    audit.best_observed = Some(cr.commitment);
                }
                if cr.commitment.satisfies(required) {
                    audit.met = true;
                    return (Ok(cr.value), audit);
                }
            }
        }
    }
    (
        Err(CommitmentError::CommitmentNotMet {
            required,
            best_observed: audit.best_observed,
            attempts: audit.attempts,
        }),
        audit,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted read: yields the queued `(value, commitment)` pairs
    /// in order, then panics if over-consumed (a test bug, not a
    /// waiter bug — the waiter must stop at `max_attempts`).
    fn scripted(
        script: Vec<(u32, CommitmentLevel)>,
    ) -> impl FnMut() -> Result<CommittedRead<u32>, &'static str> {
        let mut it = script.into_iter();
        move || {
            let (value, commitment) = it.next().expect("waiter over-consumed the script");
            Ok(CommittedRead { value, commitment })
        }
    }

    #[test]
    fn risk_table_tiers_by_settlement_risk() {
        // Monitoring-class reads: confirmed keeps latency low.
        assert_eq!(
            required_commitment(ReadOperation::KeeperLifecycleScan),
            CommitmentLevel::Confirmed
        );
        assert_eq!(
            required_commitment(ReadOperation::PriceRead),
            CommitmentLevel::Confirmed
        );
        // Settlement-gating and settlement-confirming reads: finalized.
        assert_eq!(
            required_commitment(ReadOperation::PreSettlementCheck),
            CommitmentLevel::Finalized
        );
        assert_eq!(
            required_commitment(ReadOperation::BundleLandingConfirmation),
            CommitmentLevel::Finalized
        );
    }

    #[test]
    fn commitment_levels_compare_by_finality() {
        assert!(CommitmentLevel::Processed < CommitmentLevel::Confirmed);
        assert!(CommitmentLevel::Confirmed < CommitmentLevel::Finalized);
        assert!(CommitmentLevel::Finalized.satisfies(CommitmentLevel::Finalized));
        assert!(CommitmentLevel::Finalized.satisfies(CommitmentLevel::Processed));
        assert!(!CommitmentLevel::Processed.satisfies(CommitmentLevel::Confirmed));
        assert_eq!(CommitmentLevel::Processed.as_str(), "processed");
        assert_eq!(CommitmentLevel::Confirmed.as_str(), "confirmed");
        assert_eq!(CommitmentLevel::Finalized.as_str(), "finalized");
    }

    #[test]
    fn first_attempt_meeting_returns_immediately() {
        let (result, audit) = read_with_commitment(
            ReadOperation::BundleLandingConfirmation,
            scripted(vec![(7, CommitmentLevel::Finalized)]),
            3,
        );
        assert_eq!(result, Ok(7));
        assert_eq!(audit.attempts, 1);
        assert!(audit.met);
        assert_eq!(audit.best_observed, Some(CommitmentLevel::Finalized));
        assert_eq!(audit.required, CommitmentLevel::Finalized);
    }

    #[test]
    fn waiter_retries_until_commitment_met() {
        let (result, audit) = read_with_commitment(
            ReadOperation::KeeperLifecycleScan,
            scripted(vec![
                (1, CommitmentLevel::Processed),
                (2, CommitmentLevel::Confirmed),
            ]),
            3,
        );
        // The processed observation is NOT returned — only the
        // confirmed one is.
        assert_eq!(result, Ok(2));
        assert_eq!(audit.attempts, 2);
        assert!(audit.met);
        assert_eq!(audit.best_observed, Some(CommitmentLevel::Confirmed));
    }

    #[test]
    fn exhausted_budget_is_an_explicit_failure() {
        let (result, audit) = read_with_commitment(
            ReadOperation::PreSettlementCheck,
            scripted(vec![
                (1, CommitmentLevel::Processed),
                (2, CommitmentLevel::Processed),
                // The waiter must stop here: budget is 2.
            ]),
            2,
        );
        assert_eq!(
            result,
            Err(CommitmentError::CommitmentNotMet {
                required: CommitmentLevel::Finalized,
                best_observed: Some(CommitmentLevel::Processed),
                attempts: 2,
            })
        );
        assert_eq!(audit.attempts, 2);
        assert!(!audit.met);
        assert_eq!(audit.best_observed, Some(CommitmentLevel::Processed));
    }

    #[test]
    fn no_silent_downgrade_ever() {
        // Five processed reads against a finalized requirement: the
        // waiter must fail, never hand back the processed value.
        let (result, _) = read_with_commitment(
            ReadOperation::BundleLandingConfirmation,
            scripted(vec![(9, CommitmentLevel::Processed); 5]),
            5,
        );
        assert!(matches!(
            result,
            Err(CommitmentError::CommitmentNotMet { .. })
        ));
    }

    #[test]
    fn transport_failure_surfaced_not_swallowed() {
        let (result, audit) = read_with_commitment(
            ReadOperation::PriceRead,
            || -> Result<CommittedRead<u32>, &'static str> { Err("connection reset") },
            3,
        );
        assert_eq!(result, Err(CommitmentError::ReadFailed("connection reset")));
        // The waiter does not retry a transport failure as if it were
        // a commitment miss: it surfaces immediately.
        assert_eq!(audit.attempts, 1);
        assert!(!audit.met);
        assert_eq!(audit.best_observed, None);
    }

    #[test]
    fn zero_budget_is_invalid_policy() {
        let (result, audit) = read_with_commitment(
            ReadOperation::PriceRead,
            scripted(vec![(1, CommitmentLevel::Finalized)]),
            0,
        );
        assert_eq!(result, Err(CommitmentError::InvalidPolicy));
        assert_eq!(audit.attempts, 0);
        assert!(!audit.met);
    }

    #[test]
    fn best_observed_tracks_max_across_attempts() {
        let (result, audit) = read_with_commitment(
            ReadOperation::PreSettlementCheck,
            scripted(vec![
                (1, CommitmentLevel::Confirmed),
                (2, CommitmentLevel::Processed),
            ]),
            2,
        );
        assert!(matches!(
            result,
            Err(CommitmentError::CommitmentNotMet { .. })
        ));
        // The later, weaker observation does not drag the best down.
        assert_eq!(audit.best_observed, Some(CommitmentLevel::Confirmed));
    }

    #[test]
    fn check_commitment_gate() {
        assert!(check_commitment(
            CommitmentLevel::Confirmed,
            CommitmentLevel::Confirmed
        )
        .is_ok());
        assert!(check_commitment(
            CommitmentLevel::Finalized,
            CommitmentLevel::Confirmed
        )
        .is_ok());
        assert_eq!(
            check_commitment(CommitmentLevel::Processed, CommitmentLevel::Finalized).unwrap_err(),
            CommitmentMismatch {
                required: CommitmentLevel::Finalized,
                observed: CommitmentLevel::Processed,
            }
        );
    }

    #[test]
    fn audit_json_shape() {
        let audit = CommitmentAudit {
            operation: ReadOperation::KeeperLifecycleScan,
            required: CommitmentLevel::Confirmed,
            best_observed: Some(CommitmentLevel::Confirmed),
            attempts: 2,
            met: true,
        };
        assert_eq!(
            audit.to_json(),
            "{\"event\":\"commitment_read\",\"operation\":\"keeper_lifecycle_scan\",\
             \"required\":\"confirmed\",\"best_observed\":\"confirmed\",\
             \"attempts\":2,\"met\":true}"
        );
        let failed = CommitmentAudit {
            operation: ReadOperation::BundleLandingConfirmation,
            required: CommitmentLevel::Finalized,
            best_observed: None,
            attempts: 0,
            met: false,
        };
        assert_eq!(
            failed.to_json(),
            "{\"event\":\"commitment_read\",\"operation\":\"bundle_landing_confirmation\",\
             \"required\":\"finalized\",\"best_observed\":null,\
             \"attempts\":0,\"met\":false}"
        );
    }
}
