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
//! live. [`estimate_instruction_cu`] is the arithmetic for fixed-size
//! instructions. The tests pin every row: the data-byte column against
//! the `INSTRUCTIONS` IDL spec table, the base column against hardcoded
//! values, and the table against full coverage of every keeper
//! instruction kind — a new instruction without a cost row fails the
//! build instead of silently estimating zero.
//!
//! Variable-N instructions are the documented exception: `release_many`
//! (AV-141) settles a caller-chosen number of legs, so a fixed row
//! cannot honestly express its cost. The table row pins the N=1 case
//! (the smallest valid batch — 85 data bytes, the 16_000 base as the
//! dispatch overhead plus one per-leg marginal), and
//! [`estimate_release_many_cu`] takes the leg count for the honest
//! linear model; the tests pin both the N=1 row and the per-leg growth
//! formula.

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
    // AV-109: no params → 8 + 0; the heir's inactivity reclaim is a
    // fund-moving unwind like cancel_expired/crank_expired, ranked
    // with them.
    ("claim_deadman", 10_000, 8),
    // AV-110: lamports:u64 → 8 + 8; a permissionless single-counter
    // write that moves no escrow funds — cheaper than the
    // fund-moving unwinds, ranked with the cheap config writes.
    ("top_up_rent", 8_000, 16),
    // AV-111: tranche_amount:u64 → 8 + 8; a deposit inflow with the
    // full guard chain (pause, reentrancy, FUND-scoped authority,
    // plan presence, state, tranche budget, overfund cap) plus
    // counter writes — ranked with the fund-moving unwinds.
    ("fund_tranche", 12_000, 16),
    // AV-112: cooling_secs:u64 → 8 + 8; a pre-fund config write
    // (one u64) with the builder guard chain — cheaper than the
    // fund-moving unwinds, ranked with the cheap config writes.
    ("initialize_release_cooling", 8_000, 16),
    // AV-112: no params → 8; a single-timestamp governance write
    // that moves no escrow funds — ranked with the cheap config
    // writes, like top_up_rent.
    ("announce_release", 8_000, 8),
    // AV-112: no params → 8; clearing one timestamp, no fund
    // movement — ranked with the cheap config writes.
    ("veto_release", 8_000, 8),
    // AV-114: no params → 8 + 0; a two-account consolidation with the
    // full guard chain (pause × 2, initializer authority, Funded × 2,
    // term compatibility, u128-checked accumulation) — ranked with
    // claim, the other initializer/taker fund-moving call.
    ("merge_escrows", 14_000, 8),
    // AV-141: legs: Vec<ReleaseLeg> + mint: Option<Pubkey> → 8 + 4 +
    // 40×N + 33. The row pins the N=1 case (8 + 4 + 40 + 33 = 85) —
    // the smallest valid batch. Compute units grow linearly with the
    // leg count (each leg runs one full `release` guard chain plus
    // settlement writes, across the two phases' shadow + real passes),
    // so the base is the N=1 total: the fixed dispatch overhead
    // (RELEASE_MANY_DISPATCH_CU — Anchor dispatch, account decoding,
    // the leg/vault count cross-check, the two-phase snapshot
    // allocation) plus one per-leg marginal (RELEASE_MANY_PER_LEG_CU —
    // one full release guard chain + settlement writes, ranked with
    // the fund-moving claim/merge_escrows band). A fixed row cannot
    // honestly express linear growth: use `estimate_release_many_cu`
    // for the leg-count-parameterized estimate. Heuristic planning
    // numbers, not measurements — see the module honesty notes.
    ("release_many", 16_000, 85),
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

/// AV-141: fixed dispatch overhead of `release_many`: Anchor dispatch,
/// account decoding, the leg/vault count cross-check and the two-phase
/// snapshot allocation. Heuristic planning number, not a measurement —
/// see the module honesty notes.
pub const RELEASE_MANY_DISPATCH_CU: u64 = 4_000;

/// AV-141: marginal compute per `release_many` leg: one full `release`
/// guard chain plus settlement writes, ranked with the fund-moving
/// claim/merge_escrows band. Heuristic planning number, not a
/// measurement.
pub const RELEASE_MANY_PER_LEG_CU: u64 = 12_000;

/// AV-141: Borsh data bytes of one `release_many` leg — amount:u64 (8)
/// + payout_to:Pubkey (32).
pub const RELEASE_MANY_LEG_DATA_BYTES: usize = 40;

/// AV-141: instruction-data bytes of `release_many` for `n_legs` legs:
/// the 8-byte discriminator, the 4-byte vec length prefix, N×40 for
/// the legs, and 33 for mint: Option<Pubkey> (1-byte tag + 32 bytes).
pub fn release_many_data_bytes(n_legs: usize) -> usize {
    8 + 4
        + RELEASE_MANY_LEG_DATA_BYTES.saturating_mul(n_legs)
        + 33
}

/// AV-141: heuristic compute-unit estimate for `release_many` with
/// `n_legs` legs.
///
/// A fixed table row cannot honestly express linear growth, so the
/// `INSTRUCTION_CU_TABLE` row pins the N=1 case (the smallest valid
/// batch) and this dedicated estimator takes the leg count: the
/// dispatch overhead plus one per-leg marginal per leg, plus the usual
/// per-signature / per-account / per-data-byte charges (the data bytes
/// themselves grow with N — see [`release_many_data_bytes`]). `None`
/// for a zero-leg batch, which names no vaults and cannot execute.
///
/// Like [`estimate_instruction_cu`], a heuristic planning number, not
/// a measurement — calibrate against `simulateTransaction` before
/// sizing production batches.
pub fn estimate_release_many_cu(
    n_legs: usize,
    account_count: usize,
    signer_count: usize,
) -> Option<u64> {
    if n_legs == 0 {
        return None;
    }
    Some(
        RELEASE_MANY_DISPATCH_CU
            .saturating_add(RELEASE_MANY_PER_LEG_CU.saturating_mul(n_legs as u64))
            .saturating_add(CU_PER_SIGNATURE.saturating_mul(signer_count as u64))
            .saturating_add(CU_PER_ACCOUNT.saturating_mul(account_count as u64))
            .saturating_add(
                CU_PER_DATA_BYTE.saturating_mul(release_many_data_bytes(n_legs) as u64),
            ),
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
            KeeperActionKind::ClaimDeadman,
        ];
        assert_eq!(kinds.len(), 12, "keeper action kind count drift");
        // The table may carry rows beyond the keeper kinds (AV-110:
        // `top_up_rent` is permissionless and keeper-executable but is
        // reported through `scan_rent_health`'s `TopUpAction`, not as a
        // `KeeperActionKind`) — every keeper kind must have a row, the
        // converse is not required.
        assert!(
            INSTRUCTION_CU_TABLE.len() >= kinds.len(),
            "CU table lost keeper-kind coverage"
        );
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
            // AV-141: 1-byte tag + 32 bytes, like Option<[u8; 32]> —
            // the fleet-wide mint binding rides as a real pubkey.
            "Option<Pubkey>" => 33,
            // AV-141: the N=1 minimum-case pin — 4-byte vec length
            // prefix + one leg (amount u64 + payout_to Pubkey); the
            // variable-N formula lives in `release_many_data_bytes`.
            "Vec<ReleaseLeg>" => 4 + 40,
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
            ("claim_deadman", 10_000),
            ("top_up_rent", 8_000),
            ("fund_tranche", 12_000),
            ("initialize_release_cooling", 8_000),
            ("announce_release", 8_000),
            ("veto_release", 8_000),
            // AV-141: the N=1 total — dispatch overhead plus one
            // per-leg marginal (RELEASE_MANY_DISPATCH_CU +
            // RELEASE_MANY_PER_LEG_CU).
            ("release_many", 16_000),
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

    /// AV-141: the `release_many` cost model is honestly linear in the
    /// leg count — a fixed table row pins the N=1 case and the
    /// dedicated estimator carries the leg count.
    #[test]
    fn release_many_cu_model_is_linear_in_leg_count() {
        // The data-byte formula: 8 (discriminator) + 4 (vec length
        // prefix) + N×40 (legs) + 33 (mint: Option<Pubkey>).
        assert_eq!(release_many_data_bytes(0), 8 + 4 + 33);
        assert_eq!(release_many_data_bytes(1), 85);
        assert_eq!(release_many_data_bytes(5), 8 + 4 + 5 * 40 + 33);
        assert_eq!(RELEASE_MANY_LEG_DATA_BYTES, 40);
        // The table row pins the N=1 case — data bytes and the base as
        // dispatch overhead plus one per-leg marginal.
        assert_eq!(
            instruction_data_bytes("release_many"),
            Some(release_many_data_bytes(1))
        );
        assert_eq!(
            instruction_cu_base("release_many"),
            Some(RELEASE_MANY_DISPATCH_CU + RELEASE_MANY_PER_LEG_CU)
        );
        assert_eq!(RELEASE_MANY_DISPATCH_CU + RELEASE_MANY_PER_LEG_CU, 16_000);
        // The dedicated estimator agrees with the table row on the N=1
        // case — the two cost sources cannot drift apart. Pinned
        // explicitly: 4_000 + 12_000 + 1×3_000 + 3×250 + 85×8 = 20_430.
        assert_eq!(estimate_release_many_cu(1, 3, 1), Some(20_430));
        assert_eq!(
            estimate_release_many_cu(1, 3, 1),
            estimate_instruction_cu("release_many", 3, 1)
        );
        // Linear growth: each extra leg adds one per-leg marginal plus
        // its 40 data bytes — the honest scaling law, pinned.
        let per_leg_step = RELEASE_MANY_PER_LEG_CU + CU_PER_DATA_BYTE * 40;
        assert_eq!(per_leg_step, 12_320);
        for n in 1..8usize {
            let a = estimate_release_many_cu(n, 3, 1).unwrap();
            let b = estimate_release_many_cu(n + 1, 3, 1).unwrap();
            assert_eq!(b - a, per_leg_step, "non-linear step at N={n}");
        }
        // A zero-leg batch names no vaults and cannot execute — no
        // silent zero estimate.
        assert_eq!(estimate_release_many_cu(0, 3, 1), None);
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
