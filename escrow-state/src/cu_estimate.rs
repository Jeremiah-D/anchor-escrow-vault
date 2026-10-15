//! AV-88: compute-unit budget estimation for keeper execution plans.
//!
//! The keeper report (AV-20) and the execution plan (AV-33) are dry-run
//! previews — an operator (or multisig) approves them *before* any
//! signature is produced. This module adds the missing cost dimension
//! to that preview: a heuristic compute-unit estimate per instruction,
//! aggregated per batch, with an over-limit warning when a batch cannot
//! fit one transaction.
//!
//! # What is real here
//!
//! - **The account count and data-byte count are real.** They come from
//!   the planned instruction's account list and from the instruction's
//!   Borsh layout per the AV-29 IDL spec (8-byte discriminator plus the
//!   spec's params) — the tests pin both against their sources.
//! - **The budget ceiling is real.** [`CU_MAX_PER_TRANSACTION`] is
//!   Solana's compute-budget cap per transaction (1.4M CU); a batch
//!   estimated above it genuinely cannot execute as one transaction.
//!
//! # What is deliberately NOT here (honesty labels)
//!
//! - **Heuristic, not measured.** The per-kind base costs are planning
//!   numbers that rank instruction complexity (a `resolve` with split
//!   math and rationale handling costs more than a `file_appeal` that
//!   moves no funds); they are *not* on-chain measurements. Calibrate
//!   against `simulateTransaction` before sizing production batches —
//!   the estimator tells the operator *whether to look closer*, not the
//!   exact units a transaction will consume.
//! - **One signature per instruction.** The model charges a single
//!   signature verification per instruction (the batch's caller key).
//!   Multisig-routed calls (AV-84) verify more signatures on-chain; the
//!   estimate is a lower bound there.
//!
//! # Single source of truth
//!
//! [`INSTRUCTION_CU_TABLE`] is the only place per-instruction costs
//! live. [`estimate_instruction_cu`] is the only arithmetic. The tests
//! pin every row: the data-byte column against the `INSTRUCTIONS` IDL
//! spec table, the base column against hardcoded values, and the table
//! against full coverage of every keeper instruction kind — a new
//! instruction without a cost row fails the build instead of silently
//! estimating zero.

/// Hard compute-budget ceiling per Solana transaction. A batch whose
/// estimate exceeds this cannot fit one transaction — the operator must
/// split it across transactions (or shrink the batch).
pub const CU_MAX_PER_TRANSACTION: u64 = 1_400_000;

/// Heuristic cost of one signature verification (secp256k1), per the
/// documented syscall cost. Charged once per instruction for the
/// batch's caller key.
pub const CU_PER_SIGNATURE: u64 = 3_000;

/// Heuristic marginal cost per account meta: account loading plus the
/// owner/program checks Anchor performs during account validation.
pub const CU_PER_ACCOUNT: u64 = 250;

/// Heuristic marginal cost per instruction-data byte (Borsh decoding).
pub const CU_PER_DATA_BYTE: u64 = 8;

/// Per-instruction cost table: `(instruction name, base CU,
/// instruction-data bytes)`.
///
/// - `base` ranks the kind's state-machine work: Anchor dispatch plus
///   the transition's checks and writes. A `file_appeal` (window check,
///   no funds move) is cheapest; `resolve` (split math, rationale
///   commitment, two-way payout) is dearest.
/// - `data bytes` is the 8-byte discriminator plus the Borsh-encoded
///   params per the AV-29 IDL spec — pinned against `INSTRUCTIONS` by
///   the tests, so a spec change without a table update breaks the
///   build.
pub const INSTRUCTION_CU_TABLE: &[(&str, u64, usize)] = &[
    ("cancel_expired", 10_000, 8),
    ("crank_expired", 10_000, 8),
    ("claim", 14_000, 8),
    // taker_amount:u64 + rationale_hash:Option<[u8; 32]> → 8 + 8 + 33.
    ("resolve", 22_000, 49),
    // taker_amount:u64 + rationale_hash:Option<[u8; 32]> → 8 + 8 + 33.
    ("submit_panel_judgment", 18_000, 49),
    // period_index:u8 → 8 + 1.
    ("release_period", 16_000, 9),
    // amount:u64 → 8 + 8.
    ("slash", 18_000, 16),
    ("file_appeal", 6_000, 8),
    // uphold:bool → 8 + 1.
    ("review_appeal", 14_000, 9),
    // AV-103: no params → 8 + 0; a permissionless sweep like
    // crank_expired.
    ("expire_appeal", 10_000, 8),
    // AV-106: beneficiary:Pubkey + amount:u64 → 8 + 32 + 8; a
    // fund-moving payout with authority + recipient gates, ranked
    // with slash.
    ("pool_payout", 18_000, 48),
];

/// Base cost for `instruction`, or `None` when the table has no row —
/// callers treat that as a build-time coverage failure, never as zero.
pub fn instruction_cu_base(instruction: &str) -> Option<u64> {
    INSTRUCTION_CU_TABLE
        .iter()
        .find(|(name, _, _)| *name == instruction)
        .map(|(_, base, _)| *base)
}

/// Instruction-data byte count for `instruction`, or `None` when the
/// table has no row.
pub fn instruction_data_bytes(instruction: &str) -> Option<usize> {
    INSTRUCTION_CU_TABLE
        .iter()
        .find(|(name, _, _)| *name == instruction)
        .map(|(_, _, bytes)| *bytes)
}

/// Heuristic compute-unit estimate for one instruction: the kind's base
/// cost plus per-signature, per-account, and per-data-byte charges.
/// Saturates instead of wrapping. Returns `None` for an instruction
/// with no cost-table row.
pub fn estimate_instruction_cu(
    instruction: &str,
    account_count: usize,
    signer_count: usize,
) -> Option<u64> {
    let (base, data_bytes) = INSTRUCTION_CU_TABLE
        .iter()
        .find(|(name, _, _)| *name == instruction)
        .map(|(_, base, bytes)| (*base, *bytes))?;
    Some(
        base.saturating_add(CU_PER_SIGNATURE.saturating_mul(signer_count as u64))
            .saturating_add(CU_PER_ACCOUNT.saturating_mul(account_count as u64))
            .saturating_add(CU_PER_DATA_BYTE.saturating_mul(data_bytes as u64)),
    )
}

/// Over-limit warning: the estimate cannot fit one transaction's
/// compute budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputeBudgetWarning {
    /// The batch's estimated compute units.
    pub estimated_cu: u64,
    /// The per-transaction ceiling ([`CU_MAX_PER_TRANSACTION`]).
    pub limit_cu: u64,
    /// How far over the ceiling the estimate lands.
    pub over_by_cu: u64,
}

/// Warn when `estimated_cu` exceeds one transaction's compute budget;
/// `None` when it fits.
pub fn check_compute_budget(estimated_cu: u64) -> Option<ComputeBudgetWarning> {
    if estimated_cu > CU_MAX_PER_TRANSACTION {
        Some(ComputeBudgetWarning {
            estimated_cu,
            limit_cu: CU_MAX_PER_TRANSACTION,
            over_by_cu: estimated_cu - CU_MAX_PER_TRANSACTION,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod cu_estimate_tests {
    use super::*;
    use crate::anchor_idl_tests::INSTRUCTIONS;
    use crate::keeper::KeeperActionKind;

    /// Every keeper instruction kind the planner can emit must have a
    /// cost row — a new kind without one fails here instead of
    /// estimating zero downstream.
    #[test]
    fn cu_table_covers_every_keeper_action_kind() {
        let kinds = [
            KeeperActionKind::CancelExpired,
            KeeperActionKind::CrankExpired,
            KeeperActionKind::Claim,
            KeeperActionKind::Resolve,
            KeeperActionKind::PanelJudgment,
            KeeperActionKind::ReleasePeriod,
            KeeperActionKind::Slash,
            KeeperActionKind::FileAppeal,
            KeeperActionKind::ReviewAppeal,
            KeeperActionKind::ExpireAppeal,
            KeeperActionKind::PoolPayout,
        ];
        assert_eq!(kinds.len(), INSTRUCTION_CU_TABLE.len());
        for k in kinds {
            let name = k.as_str();
            assert!(
                instruction_cu_base(name).is_some(),
                "CU table missing row for {name}"
            );
            assert!(
                instruction_data_bytes(name).is_some(),
                "CU table missing data bytes for {name}"
            );
            assert!(
                estimate_instruction_cu(name, 3, 1).is_some(),
                "CU estimate missing for {name}"
            );
        }
    }

    /// Borsh byte size of the IDL param types that appear on keeper
    /// instructions. A new param type fails loudly — add its size
    /// deliberately, don't guess.
    fn borsh_param_size(ty: &str) -> usize {
        match ty {
            "u64" => 8,
            "u32" => 4,
            "u16" => 2,
            "u8" | "bool" => 1,
            "Pubkey" | "[u8; 32]" => 32,
            "Option<[u8; 32]>" => 33, // 1-byte tag + 32 bytes
            other => panic!("AV-88: add Borsh size for new keeper param type {other}"),
        }
    }

    /// The data-byte column is derived from the IDL spec, not
    /// hand-typed: 8-byte discriminator plus the spec's Borsh params.
    /// A spec param change without a table update breaks this test.
    #[test]
    fn data_bytes_match_idl_spec() {
        for (name, _, data_bytes) in INSTRUCTION_CU_TABLE {
            let spec = INSTRUCTIONS
                .iter()
                .find(|s| s.name == *name)
                .unwrap_or_else(|| panic!("INSTRUCTIONS spec missing {name}"));
            let mut expected = 8usize; // Anchor discriminator
            for (_, ty, _) in spec.params {
                expected += borsh_param_size(ty);
            }
            assert_eq!(
                *data_bytes, expected,
                "CU table data bytes drifted from IDL spec for {name}"
            );
        }
    }

    /// The base-cost column is pinned: deliberate re-tuning updates this
    /// test, accidental edits break it.
    #[test]
    fn base_costs_are_pinned() {
        let expected: &[(&str, u64)] = &[
            ("cancel_expired", 10_000),
            ("crank_expired", 10_000),
            ("claim", 14_000),
            ("resolve", 22_000),
            ("submit_panel_judgment", 18_000),
            ("release_period", 16_000),
            ("slash", 18_000),
            ("file_appeal", 6_000),
            ("review_appeal", 14_000),
            ("expire_appeal", 10_000),
            ("pool_payout", 18_000),
        ];
        for (name, base) in expected {
            assert_eq!(instruction_cu_base(name), Some(*base), "base drift for {name}");
        }
    }

    #[test]
    fn estimate_math_is_base_plus_per_unit_charges() {
        // cancel_expired, 3 accounts, 1 signer:
        // 10_000 + 1×3_000 + 3×250 + 8×8 = 13_814.
        assert_eq!(
            estimate_instruction_cu("cancel_expired", 3, 1),
            Some(13_814)
        );
        // resolve, 4 accounts, 1 signer:
        // 22_000 + 3_000 + 4×250 + 49×8 = 26_392.
        assert_eq!(estimate_instruction_cu("resolve", 4, 1), Some(26_392));
        // Zero accounts/signers still charges the base + data bytes.
        assert_eq!(
            estimate_instruction_cu("file_appeal", 0, 0),
            Some(6_000 + 8 * 8)
        );
        // Unknown instruction: no silent zero.
        assert_eq!(estimate_instruction_cu("nope", 3, 1), None);
    }

    #[test]
    fn budget_warning_fires_only_over_limit() {
        assert_eq!(check_compute_budget(0), None);
        assert_eq!(check_compute_budget(CU_MAX_PER_TRANSACTION), None);
        assert_eq!(
            check_compute_budget(CU_MAX_PER_TRANSACTION + 1),
            Some(ComputeBudgetWarning {
                estimated_cu: CU_MAX_PER_TRANSACTION + 1,
                limit_cu: CU_MAX_PER_TRANSACTION,
                over_by_cu: 1,
            })
        );
    }
}
