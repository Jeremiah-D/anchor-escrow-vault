//! Penalty insurance pool (AV-106 — Solana payment risk / taker-default
//! economics).
//!
//! The problem: a slash pays the penalty to the initializer's account
//! ([`Escrow::slash`](super::Escrow::slash)), and a rejected appeal
//! forfeits the taker's bond to the initializer
//! ([`Escrow::review_appeal`](super::Escrow::review_appeal) /
//! [`Escrow::expire_appeal`](super::Escrow::expire_appeal)). The
//! initializer therefore *profits* from declaring the taker in
//! default — even wrongfully. The penalty is supposed to price the
//! taker's non-performance, not to be a revenue line for the party
//! that unilaterally triggers it.
//!
//! The pool fixes the incentive: when the escrow opts in via
//! [`Escrow::with_insurance_pool`](super::Escrow::with_insurance_pool),
//! slashed penalties and forfeited appeal bonds accrue in a neutral
//! per-escrow pool instead of flowing to the initializer. The pool is
//! neutral custody — neither party can touch it alone. The only
//! outflow is [`Escrow::pool_payout`](super::Escrow::pool_payout),
//! authorized by the arbiter (the AV-14 neutral role) or the bound
//! multisig authority PDA (AV-84 — the PDA signs only after its
//! threshold voted, so the escrow stays zero-trust and never
//! interprets the threshold itself).
//!
//! # Accounting
//!
//! Five persisted counters (all zero unless the pool is opted in):
//!
//! - `insurance_pool`: the opt-in flag.
//! - `pool_paid`: the pool balance — slashed penalties and forfeited
//!   bonds credit it, overturn restitution and authorized payouts
//!   debit it.
//! - `pool_slashed`: the principal currently held in the pool (slash
//!   moves principal out of the lockup into the pool; an overturn
//!   reverses it). Never reduced by `pool_payout` — the paid-out
//!   principal stays excluded from the releasable lockup, and the
//!   payout is booked in `pool_payout_paid`. Drives
//!   [`Escrow::remaining_amount`] —
//!   `amount - released - penalty_paid - pool_slashed` — so the
//!   releasable lockup, the release caps, and the keeper scans all
//!   exclude pooled principal automatically.
//! - `pool_inflow`: cumulative credits (slash-to-pool +
//!   bond-forfeit-to-pool), never decreases — the keeper's inflow
//!   line.
//! - `pool_payout_paid`: cumulative *authorized* payouts, never
//!   decreases. Overturn restitution is not booked here — it rides
//!   `released` like every other taker payout (the AV-86 precedent),
//!   so the keeper's outflow line is `pool_inflow - pool_paid` and the
//!   conservation identity keeps one term per sink.
//!
//! The conservation identity becomes
//! `inflow == locked + released + refunded + penalty_paid +
//! appeal_bond_paid + pool_paid + pool_payout_paid`, where `locked`
//! is [`Escrow::remaining_amount`] and `inflow` counts the
//! taker-locked appeal bond on top of the principal (the AV-103
//! convention). `pool_payout_paid` is its own sink — a payout leaves
//! the vault to an authorized beneficiary, so it cannot ride
//! `released` (that counter is principal-sourced taker payouts;
//! mixing pool-sourced funds into it would corrupt
//! `remaining_amount`'s `amount - released` arithmetic — the same
//! reason AV-82 kept `penalty_paid` separate from `released`).
//! Each opt-in term is zero when its feature is off, so the identity
//! collapses to the pre-AV-106 form for plain escrows.
//!
//! A non-empty pool blocks [`Escrow::close_vault`] — closing would
//! hand the neutralized penalties to the initializer with the rent
//! reclaim, resurrecting the exact incentive the pool removes. Drain
//! via `pool_payout` first. A pool with no arbiter and no multisig
//! binding can never pay out: pair `with_insurance_pool` with
//! `with_arbiter` or `with_multisig_authority`.
//!
//! [`Escrow::remaining_amount`]: super::Escrow::remaining_amount
//! [`Escrow::close_vault`]: super::Escrow::close_vault

use super::cpi::Pubkey;
use super::discriminator::instruction_discriminator;
use super::{CpiInvocation, Escrow, EscrowError, MultisigAuthority};

/// Validate an off-chain pool-payout proposal before it goes to the
/// multisig for voting (AV-106): combines
/// [`validate_multisig_escrow_call`](super::validate_multisig_escrow_call)
/// with a discriminator pin — the proposed instruction must actually
/// *be* a `pool_payout` call (`sha256("global:pool_payout")[..8]`),
/// so a multisig is never asked to sign a differently-shaped
/// instruction against the escrow program. Escrows without a multisig
/// binding (arbiter-authorized payouts) need no proposal validation:
/// the arbiter signs the payout directly, and the state machine's
/// key-equality check is the whole authorization.
///
/// [`EscrowError::InvalidPoolPayout`] when the escrow has no pool
/// opted in, has no multisig binding, or the proposal fails the
/// AV-84 shape validation / discriminator pin.
pub fn validate_pool_payout_proposal(
    inv: &CpiInvocation,
    escrow_program_id: &Pubkey,
    escrow: &Escrow,
) -> Result<(), EscrowError> {
    if !escrow.insurance_pool() {
        return Err(EscrowError::InvalidPoolPayout);
    }
    let bound: MultisigAuthority = escrow
        .multisig_authority()
        .ok_or(EscrowError::InvalidPoolPayout)?;
    super::validate_multisig_escrow_call(inv, escrow_program_id, &bound)?;
    // The proposal must target the pool-payout entrypoint — a
    // same-shape call to any other instruction is rejected before
    // votes are cast.
    let disc = instruction_discriminator("pool_payout");
    if inv.data.len() < 8 || inv.data[..8] != disc {
        return Err(EscrowError::InvalidPoolPayout);
    }
    Ok(())
}

// ---------- AV-106: penalty insurance pool ----------

#[cfg(test)]
mod insurance_tests {
    use super::super::keeper::{scan_keeper_actions, KeeperActionKind, WatchedEscrow};
    use super::*;
    use crate::{AppealOutcome, EscrowState};
    use crate::multisig::assemble_multisig_escrow_call;

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const CAROL: [u8; 32] = [0xCC; 32]; // arbiter
    const BENEFICIARY: [u8; 32] = [0xD0; 32];
    const PENALTY: [u8; 32] = [0xDD; 32];
    const M1: [u8; 32] = [0x11; 32];
    const M2: [u8; 32] = [0x22; 32];
    const M3: [u8; 32] = [0x33; 32];
    const MULTISIG_PROGRAM: [u8; 32] = [0xE4; 32];
    const MULTISIG_PDA: [u8; 32] = [0xE5; 32];
    const ESCROW_PROGRAM: [u8; 32] = [0xF0; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;
    const T0: u64 = 1_700_000_000;
    const DEADLINE: u64 = T0 + 86_400;
    const WINDOW: u64 = 7 * 86_400; // 7 days.
    const AMOUNT: u64 = 1_000_000;
    const SLASHED: u64 = 200_000;
    const BOND: u64 = 50_000;

    fn pooled_uninitialized() -> Escrow {
        // The payout fixture: single arbiter + multisig. (The single
        // arbiter and the arbiter panel are mutually exclusive,
        // last-wins — the appeal fixture below carries the panel
        // instead.)
        Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_slash_terms(PENALTY, DEADLINE)
            .unwrap()
            .with_appeal_window(WINDOW)
            .unwrap()
            .with_arbiter(CAROL)
            .unwrap()
            .with_multisig_authority(MULTISIG_PROGRAM, MULTISIG_PDA, 2)
            .unwrap()
            .with_insurance_pool()
            .unwrap()
    }

    fn pooled_panel_uninitialized() -> Escrow {
        // The appeal fixture: arbiter panel + appeal bond + multisig.
        // `file_appeal` requires the panel (a filed appeal must be
        // resolvable); pool payouts on this fixture go through the
        // multisig authority.
        Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_slash_terms(PENALTY, DEADLINE)
            .unwrap()
            .with_appeal_window(WINDOW)
            .unwrap()
            .with_appeal_bond(BOND)
            .unwrap()
            .with_arbiter_panel(&[M1, M2, M3], 2)
            .unwrap()
            .with_multisig_authority(MULTISIG_PROGRAM, MULTISIG_PDA, 2)
            .unwrap()
            .with_insurance_pool()
            .unwrap()
    }

    fn pooled_slashed() -> Escrow {
        let mut e = pooled_uninitialized();
        e.fund(ALICE, T0).unwrap();
        e.slash(ALICE, SLASHED, None, DEADLINE).unwrap();
        e
    }

    fn pooled_panel_slashed() -> Escrow {
        let mut e = pooled_panel_uninitialized();
        e.fund(ALICE, T0).unwrap();
        e.slash(ALICE, SLASHED, None, DEADLINE).unwrap();
        e
    }

    fn watch(id: [u8; 32], escrow: Escrow) -> WatchedEscrow {
        WatchedEscrow {
            escrow_id: id,
            escrow,
            reference: None,
            vault_derivation: None,
        }
    }

    /// The extended conservation identity (AV-106): every unit of value
    /// that entered the vault — the principal plus the total appeal
    /// bond the taker ever locked — is accounted in exactly one sink
    /// counter. `bond_ever_locked` is the scenario's total taker-locked
    /// bond (0 when no appeal was filed). A bond refunded to the taker
    /// on overturn leaves the vault off-ledger (the AV-103 convention),
    /// so the identity is asserted only where the bond is still
    /// accounted: in flight (`appeal_bond_paid`), or forfeited into the
    /// pool (`pool_paid`).
    fn assert_pool_conservation(e: &Escrow, bond_ever_locked: u64) {
        let inflow = AMOUNT as u128 + bond_ever_locked as u128;
        let sinks = e.remaining_amount() as u128
            + e.released_amount() as u128
            + e.penalty_paid() as u128
            + e.appeal_bond_paid() as u128
            + e.pool_paid() as u128
            + e.pool_payout_paid() as u128;
        assert_eq!(inflow, sinks, "extended conservation identity");
    }

    #[test]
    fn opt_in_builder_sets_the_flag() {
        let e = pooled_uninitialized();
        assert!(e.insurance_pool(), "opt-in flag set");
        assert_eq!(e.pool_paid(), 0);
        assert_eq!(e.pool_slashed(), 0);
        assert_eq!(e.pool_inflow(), 0);
        assert_eq!(e.pool_payout_paid(), 0);
        // The default stays off — a plain escrow keeps the pre-AV-106
        // slash-to-initializer behavior.
        let plain = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT).unwrap();
        assert!(!plain.insurance_pool(), "pool is opt-in, not default");
    }

    #[test]
    fn opt_in_is_uninitialized_only() {
        // The &mut form mirrors the Anchor handler.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_slash_terms(PENALTY, DEADLINE)
            .unwrap();
        e.initialize_insurance_pool().unwrap();
        assert!(e.insurance_pool());
        // Re-opting in is idempotent, not an error.
        e.initialize_insurance_pool().unwrap();
        // A live escrow cannot opt in after funds moved.
        let mut live = pooled_uninitialized();
        live.fund(ALICE, T0).unwrap();
        assert_eq!(
            live.with_insurance_pool().unwrap_err(),
            EscrowError::InvalidStateTransition
        );
        assert_eq!(
            live.initialize_insurance_pool().unwrap_err(),
            EscrowError::InvalidStateTransition
        );
    }

    #[test]
    fn opt_in_fails_fast_when_paused() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_pause_authority(ALICE)
            .unwrap();
        e.fund(ALICE, T0).unwrap();
        e.pause(ALICE).unwrap();
        // The pause guard fires before the state gate.
        assert_eq!(
            e.with_insurance_pool().unwrap_err(),
            EscrowError::Paused
        );
    }

    #[test]
    fn slash_routes_to_the_pool_when_opted_in() {
        let e = pooled_slashed();
        // The slash principal sits in the pool, not in penalty_paid —
        // the initializer cannot profit from declaring the default.
        assert_eq!(e.penalty_paid(), 0, "no penalty flows to initializer");
        assert_eq!(e.pool_paid(), SLASHED);
        assert_eq!(e.pool_slashed(), SLASHED);
        assert_eq!(e.pool_inflow(), SLASHED);
        assert_eq!(e.pool_payout_paid(), 0);
        assert_pool_conservation(&e, 0);
    }

    #[test]
    fn slash_without_opt_in_keeps_the_old_behavior() {
        // Control: no pool, the slash still pays the penalty account.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_slash_terms(PENALTY, DEADLINE)
            .unwrap()
            .with_appeal_window(WINDOW)
            .unwrap()
            .with_arbiter_panel(&[M1, M2, M3], 2)
            .unwrap();
        e.fund(ALICE, T0).unwrap();
        e.slash(ALICE, SLASHED, None, DEADLINE).unwrap();
        assert_eq!(e.penalty_paid(), SLASHED);
        assert_eq!(e.pool_paid(), 0);
        assert_eq!(e.pool_slashed(), 0);
        assert_eq!(e.pool_inflow(), 0);
    }

    #[test]
    fn remaining_amount_excludes_the_pooled_slash() {
        let e = pooled_slashed();
        assert_eq!(e.remaining_amount(), AMOUNT - SLASHED);
        // A release is capped at the post-slash remainder, like the
        // AV-82 penalty_paid cap.
        let mut e2 = pooled_slashed();
        assert_eq!(
            e2.release(ALICE, T0 + 1, AMOUNT - SLASHED + 1, None, BOB)
                .unwrap_err(),
            EscrowError::ReleaseExceedsLocked
        );
        e2.release(ALICE, T0 + 1, AMOUNT - SLASHED, None, BOB)
            .unwrap();
        assert_eq!(e2.remaining_amount(), 0);
        assert_pool_conservation(&e2, 0);
    }

    #[test]
    fn second_slash_rejected_after_a_pool_slash() {
        let mut e = pooled_slashed();
        assert_eq!(
            e.slash(ALICE, SLASHED, None, DEADLINE).unwrap_err(),
            EscrowError::SlashNotEligible
        );
        // The keeper agrees: no second slash is listed.
        let report = scan_keeper_actions(&[watch([0x01; 32], e)], DEADLINE);
        assert!(
            report
                .actions
                .iter()
                .all(|a| a.kind != KeeperActionKind::Slash),
            "a pooled slash counts as slashed"
        );
    }

    #[test]
    fn bond_forfeit_routes_to_pool_on_uphold() {
        let mut e = pooled_panel_slashed();
        e.file_appeal(BOB, DEADLINE + 1).unwrap();
        assert_eq!(e.appeal_bond_paid(), BOND);
        assert_pool_conservation(&e, BOND);
        // Two panel votes uphold: the forfeited bond credits the pool,
        // not the initializer.
        assert_eq!(e.review_appeal(M1, true).unwrap(), None);
        let outcome = e.review_appeal(M2, true).unwrap().unwrap();
        assert_eq!(outcome.0, AppealOutcome::Upheld);
        assert_eq!(e.appeal_bond_paid(), 0);
        assert_eq!(e.pool_paid(), SLASHED + BOND);
        assert_eq!(e.pool_slashed(), SLASHED, "slash still appealable-held");
        assert_eq!(e.pool_inflow(), SLASHED + BOND);
        // The forfeited bond stays on the vault's books (in the pool),
        // so it remains part of inflow after resolution.
        assert_pool_conservation(&e, BOND);
    }

    #[test]
    fn bond_forfeit_routes_to_pool_on_expiry() {
        let mut e = pooled_panel_slashed();
        e.file_appeal(BOB, DEADLINE + 1).unwrap();
        let forfeited = e.expire_appeal(ALICE, DEADLINE + WINDOW + 1).unwrap();
        assert_eq!(forfeited, BOND, "returned for transfer sizing");
        assert_eq!(e.appeal_bond_paid(), 0);
        assert_eq!(e.pool_paid(), SLASHED + BOND);
        assert_eq!(e.pool_inflow(), SLASHED + BOND);
        assert_pool_conservation(&e, BOND);
    }

    #[test]
    fn overturn_restores_the_slash_from_the_pool() {
        let mut e = pooled_panel_slashed();
        e.file_appeal(BOB, DEADLINE + 1).unwrap();
        assert_eq!(e.review_appeal(M1, false).unwrap(), None);
        let outcome = e.review_appeal(M2, false).unwrap().unwrap();
        assert_eq!(outcome.0, AppealOutcome::Overturned);
        // Restitution leaves the pool and rides `released` (the AV-86
        // precedent); the bond refunds to the taker in full, off-ledger
        // like every AV-103 bond refund.
        assert_eq!(e.pool_paid(), 0);
        assert_eq!(e.pool_slashed(), 0);
        assert_eq!(e.pool_inflow(), SLASHED, "inflow never debited");
        assert_eq!(e.released_amount(), SLASHED);
        assert_eq!(e.appeal_bond_paid(), 0);
        assert_eq!(e.remaining_amount(), AMOUNT - SLASHED);
    }

    #[test]
    fn pool_payout_by_arbiter_after_the_appeal_window() {
        let mut e = pooled_slashed();
        // No appeal filed; past the appeal deadline the pooled slash is
        // no longer encumbered.
        assert!(!e.is_pool_payout_eligible(DEADLINE));
        assert!(e.is_pool_payout_eligible(DEADLINE + WINDOW));
        let paid = e
            .pool_payout(CAROL, BOB, 50_000, None, DEADLINE + WINDOW)
            .unwrap();
        assert_eq!(paid, 50_000);
        assert_eq!(e.pool_paid(), SLASHED - 50_000);
        // The payout never shrinks the lockup exclusion: the paid-out
        // principal stays out of `remaining_amount`, and the payout is
        // booked in `pool_payout_paid` (one sink per fund, so the
        // conservation identity below holds).
        assert_eq!(e.pool_slashed(), SLASHED);
        assert_eq!(e.pool_payout_paid(), 50_000);
        assert_eq!(e.pool_outflow(), 50_000);
        // Outflow is inflow minus balance.
        assert_eq!(e.pool_outflow(), e.pool_inflow() - e.pool_paid());
        assert_pool_conservation(&e, 0);
        // The rest drains in a second payout.
        e.pool_payout(CAROL, BOB, SLASHED - 50_000, None, DEADLINE + WINDOW)
            .unwrap();
        assert_eq!(e.pool_paid(), 0);
        assert_eq!(e.pool_payout_paid(), SLASHED);
        assert_pool_conservation(&e, 0);
    }

    #[test]
    fn pool_payout_by_multisig_authority() {
        let mut e = pooled_slashed();
        let paid = e
            .pool_payout(MULTISIG_PDA, BOB, SLASHED, None, DEADLINE + WINDOW)
            .unwrap();
        assert_eq!(paid, SLASHED);
        assert_eq!(e.pool_payout_paid(), SLASHED);
    }

    #[test]
    fn pool_payout_enforces_the_bound_mint() {
        const MINT: [u8; 32] = [0x77; 32];
        // A token-bound escrow's pool only exits through the bound
        // mint (AV-16), like every other fund-moving transition.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_slash_terms(PENALTY, DEADLINE)
            .unwrap()
            .with_appeal_window(WINDOW)
            .unwrap()
            .with_arbiter(CAROL)
            .unwrap()
            .with_mint(MINT)
            .unwrap()
            .with_insurance_pool()
            .unwrap();
        e.fund(ALICE, T0).unwrap();
        e.slash(ALICE, SLASHED, Some(MINT), DEADLINE).unwrap();
        assert_eq!(
            e.pool_payout(CAROL, BOB, 1_000, None, DEADLINE + WINDOW)
                .unwrap_err(),
            EscrowError::MintMismatch,
            "native-path payout on a token-bound pool is refused"
        );
        assert_eq!(
            e.pool_payout(CAROL, BOB, 1_000, Some([0x78; 32]), DEADLINE + WINDOW)
                .unwrap_err(),
            EscrowError::MintMismatch,
            "wrong-mint payout on a token-bound pool is refused"
        );
        let paid = e
            .pool_payout(CAROL, BOB, 1_000, Some(MINT), DEADLINE + WINDOW)
            .unwrap();
        assert_eq!(paid, 1_000);
        assert_eq!(e.pool_payout_paid(), 1_000);
        // The native path stays the only path for an unbound escrow.
        let mut plain = pooled_slashed();
        assert_eq!(
            plain
                .pool_payout(CAROL, BOB, 1_000, Some(MINT), DEADLINE + WINDOW)
                .unwrap_err(),
            EscrowError::MintMismatch
        );
    }

    #[test]
    fn pool_payout_rejects_unauthorized_caller() {
        let mut e = pooled_slashed();
        // Neither party can touch the pool alone — the initializer
        // especially (that is the perverse incentive the pool removes).
        for caller in [ALICE, BOB, [0x99; 32]] {
            assert_eq!(
                e.pool_payout(caller, BOB, 1, None, DEADLINE + WINDOW)
                    .unwrap_err(),
                EscrowError::InvalidPoolPayout,
                "unauthorized caller must be rejected"
            );
        }
        assert_eq!(e.pool_paid(), SLASHED, "no mutation on refusal");
    }

    #[test]
    fn pool_payout_rejects_zero_and_over_balance_amounts() {
        let mut e = pooled_slashed();
        assert_eq!(
            e.pool_payout(CAROL, BOB, 0, None, DEADLINE + WINDOW)
                .unwrap_err(),
            EscrowError::InvalidPoolPayout
        );
        assert_eq!(
            e.pool_payout(CAROL, BOB, SLASHED + 1, None, DEADLINE + WINDOW)
                .unwrap_err(),
            EscrowError::InvalidPoolPayout
        );
        // The beneficiary still passes the AV-49/AV-96 recipient gate.
        assert_eq!(
            e.pool_payout(CAROL, BENEFICIARY, 1, None, DEADLINE + WINDOW)
                .unwrap_err(),
            EscrowError::PayoutNotAllowlisted
        );
    }

    #[test]
    fn pool_payout_blocked_while_the_slash_is_encumbered() {
        // A filed appeal encumbers the pool — even an authorized
        // drainer is refused (the multisig authority here, since the
        // appeal fixture carries the panel instead of a single
        // arbiter).
        let mut e = pooled_panel_slashed();
        e.file_appeal(BOB, DEADLINE + 1).unwrap();
        assert!(!e.is_pool_payout_eligible(DEADLINE + 1));
        assert_eq!(
            e.pool_payout(MULTISIG_PDA, BOB, 1, None, DEADLINE + 1)
                .unwrap_err(),
            EscrowError::InvalidPoolPayout
        );
        // And a pooled slash is encumbered until the appeal window
        // lapses, even with no appeal filed.
        let mut e2 = pooled_slashed();
        assert!(!e2.is_pool_payout_eligible(DEADLINE + WINDOW - 1));
        assert_eq!(
            e2.pool_payout(CAROL, BOB, 1, None, DEADLINE + WINDOW - 1)
                .unwrap_err(),
            EscrowError::InvalidPoolPayout
        );
    }

    #[test]
    fn pool_payout_fails_fast_when_paused() {
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_pause_authority(ALICE)
            .unwrap()
            .with_slash_terms(PENALTY, DEADLINE)
            .unwrap()
            .with_appeal_window(WINDOW)
            .unwrap()
            .with_arbiter(CAROL)
            .unwrap()
            .with_insurance_pool()
            .unwrap();
        e.fund(ALICE, T0).unwrap();
        e.slash(ALICE, SLASHED, None, DEADLINE).unwrap();
        e.pause(ALICE).unwrap();
        // The pause guard fires before the authorization check.
        assert_eq!(
            e.pool_payout([0x99; 32], BOB, 1, None, DEADLINE + WINDOW)
                .unwrap_err(),
            EscrowError::Paused
        );
    }

    #[test]
    fn pool_payout_requires_a_pool_and_funded_state() {
        // No pool opted in: refused even for the arbiter.
        let mut e = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_arbiter(CAROL)
            .unwrap();
        e.fund(ALICE, T0).unwrap();
        assert_eq!(
            e.pool_payout(CAROL, BOB, 1, None, T0 + 1).unwrap_err(),
            EscrowError::InvalidPoolPayout
        );
        // Non-Funded state: a Released escrow with a leftover pool.
        let mut e2 = pooled_slashed();
        e2.release(ALICE, T0 + 1, AMOUNT - SLASHED, None, BOB)
            .unwrap();
        assert_eq!(e2.state(), EscrowState::Released);
        assert_eq!(
            e2.pool_payout(CAROL, BOB, 1, None, DEADLINE + WINDOW)
                .unwrap_err(),
            EscrowError::InvalidPoolPayout
        );
    }

    #[test]
    fn close_vault_blocked_with_a_non_empty_pool() {
        // The documented flow: drain the pool while Funded, then the
        // normal release + close path works.
        let mut e = pooled_slashed();
        e.pool_payout(CAROL, BOB, SLASHED, None, DEADLINE + WINDOW)
            .unwrap();
        e.release(ALICE, T0 + 1, AMOUNT - SLASHED, None, BOB)
            .unwrap();
        let rent = e.close_vault(ALICE).unwrap();
        assert!(rent > 0, "rent reclaimed");
        // Releasing first leaves a non-empty pool behind: closing would
        // hand the neutralized penalties to the initializer with the
        // rent reclaim, so it is refused — drain first.
        let mut e2 = pooled_slashed();
        e2.release(ALICE, T0 + 1, AMOUNT - SLASHED, None, BOB)
            .unwrap();
        assert_eq!(e2.state(), EscrowState::Released);
        assert_eq!(
            e2.close_vault(ALICE).unwrap_err(),
            EscrowError::InvalidPoolPayout
        );
    }

    #[test]
    fn keeper_lists_pool_payout_when_eligible() {
        let e = pooled_slashed();
        let report =
            scan_keeper_actions(&[watch([0x01; 32], e)], DEADLINE + WINDOW);
        // One action per authorized drainer: the arbiter and the
        // bound multisig PDA.
        let payouts: Vec<_> = report
            .actions
            .iter()
            .filter(|a| a.kind == KeeperActionKind::PoolPayout)
            .collect();
        assert_eq!(payouts.len(), 2);
        assert_eq!(payouts[0].caller_role, "arbiter");
        assert_eq!(payouts[0].caller, CAROL);
        assert_eq!(payouts[1].caller_role, "multisig_authority");
        assert_eq!(payouts[1].caller, MULTISIG_PDA);
        assert_eq!(payouts[0].amount, SLASHED, "the balance is the ceiling");
        assert_eq!(payouts[0].refund_to, None, "no pinned destination");
        // The fleet-wide pool lines ride the report.
        assert_eq!(report.pool_balance, SLASHED);
        assert_eq!(report.pool_inflow, SLASHED);
        assert_eq!(report.pool_outflow, 0);
        let json = report.to_json();
        assert!(json.contains("\"pool_balance\":200000"));
        assert!(json.contains("\"pool_inflow\":200000"));
        assert!(json.contains("\"pool_outflow\":0"));
    }

    #[test]
    fn keeper_pool_lines_aggregate_across_escrows() {
        let mut e1 = pooled_slashed();
        e1.pool_payout(CAROL, BOB, 50_000, None, DEADLINE + WINDOW)
            .unwrap();
        let e2 = pooled_slashed();
        let report = scan_keeper_actions(
            &[watch([0x01; 32], e1), watch([0x02; 32], e2)],
            DEADLINE + WINDOW,
        );
        assert_eq!(report.pool_balance, SLASHED - 50_000 + SLASHED);
        assert_eq!(report.pool_inflow, SLASHED + SLASHED);
        assert_eq!(report.pool_outflow, 50_000, "inflow - balance");
        // A plain escrow contributes nothing.
        let mut plain = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_slash_terms(PENALTY, DEADLINE)
            .unwrap();
        plain.fund(ALICE, T0).unwrap();
        let report2 = scan_keeper_actions(
            &[watch([0x01; 32], e2), watch([0x03; 32], plain)],
            DEADLINE + WINDOW,
        );
        assert_eq!(report2.pool_balance, SLASHED);
        assert_eq!(report2.pool_inflow, SLASHED);
        assert_eq!(report2.pool_outflow, 0);
    }

    #[test]
    fn keeper_lists_no_payout_while_encumbered() {
        let mut e = pooled_panel_slashed();
        e.file_appeal(BOB, DEADLINE + 1).unwrap();
        let report =
            scan_keeper_actions(&[watch([0x01; 32], e)], DEADLINE + 1);
        assert!(
            report
                .actions
                .iter()
                .all(|a| a.kind != KeeperActionKind::PoolPayout),
            "an encumbered pool is never listed"
        );
        // The balance lines still report — the keeper watches the pool
        // even when it cannot drain it.
        assert_eq!(report.pool_balance, SLASHED);
        assert_eq!(report.pool_inflow, SLASHED);
    }

    #[test]
    fn validate_pool_payout_proposal_pins_the_discriminator() {
        let e = pooled_uninitialized();
        // A well-formed pool_payout proposal validates.
        let mut data = instruction_discriminator("pool_payout").to_vec();
        data.extend_from_slice(&BENEFICIARY);
        data.extend_from_slice(&1_000u64.to_le_bytes());
        let inv =
            assemble_multisig_escrow_call(ESCROW_PROGRAM, MULTISIG_PDA, vec![], data);
        validate_pool_payout_proposal(&inv, &ESCROW_PROGRAM, &e).unwrap();
        // The IDL discriminator matches the state machine's pin.
        assert_eq!(
            instruction_discriminator("pool_payout"),
            [96, 126, 156, 222, 124, 179, 148, 159],
            "matches escrow_vault.json"
        );
        // A same-shape call to another instruction is rejected before
        // votes are cast.
        let mut bad = instruction_discriminator("release").to_vec();
        bad.extend_from_slice(&[0u8; 40]);
        let inv_bad =
            assemble_multisig_escrow_call(ESCROW_PROGRAM, MULTISIG_PDA, vec![], bad);
        assert_eq!(
            validate_pool_payout_proposal(&inv_bad, &ESCROW_PROGRAM, &e)
                .unwrap_err(),
            EscrowError::InvalidPoolPayout
        );
    }

    #[test]
    fn validate_pool_payout_proposal_rejects_unbound_escrows() {
        let mut data = instruction_discriminator("pool_payout").to_vec();
        data.extend_from_slice(&[0u8; 40]);
        let inv =
            assemble_multisig_escrow_call(ESCROW_PROGRAM, MULTISIG_PDA, vec![], data);
        // No pool opted in.
        let plain = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_multisig_authority(MULTISIG_PROGRAM, MULTISIG_PDA, 2)
            .unwrap();
        assert_eq!(
            validate_pool_payout_proposal(&inv, &ESCROW_PROGRAM, &plain)
                .unwrap_err(),
            EscrowError::InvalidPoolPayout
        );
        // Pool opted in but no multisig binding: arbiter-authorized
        // payouts need no proposal validation.
        let arbiter_only = Escrow::initialize(ALICE, BOB, AMOUNT, EXPIRES_AT)
            .unwrap()
            .with_arbiter(CAROL)
            .unwrap()
            .with_insurance_pool()
            .unwrap();
        assert_eq!(
            validate_pool_payout_proposal(&inv, &ESCROW_PROGRAM, &arbiter_only)
                .unwrap_err(),
            EscrowError::InvalidPoolPayout
        );
    }

    #[test]
    fn snapshot_exports_the_pool_fields() {
        let mut e = pooled_slashed();
        e.pool_payout(CAROL, BOB, 50_000, None, DEADLINE + WINDOW)
            .unwrap();
        let snap = e.snapshot(DEADLINE + WINDOW);
        assert!(snap.insurance_pool);
        assert_eq!(snap.pool_paid, SLASHED - 50_000);
        // The lockup exclusion survives the payout (see the module
        // docs): only overturn restitution reverses `pool_slashed`.
        assert_eq!(snap.pool_slashed, SLASHED);
        assert_eq!(snap.pool_inflow, SLASHED);
        assert_eq!(snap.pool_outflow, 50_000);
        assert_eq!(snap.pool_payout_paid, 50_000);
        assert!(snap.pool_payout_eligible);
        let json = snap.to_json();
        assert!(json.contains("\"insurance_pool\":true"));
        assert!(json.contains("\"pool_payout_paid\":50000"));
    }

    #[test]
    fn extended_conservation_holds_across_the_full_lifecycle() {
        // slash -> bond forfeit on uphold -> partial payout (via the
        // multisig authority — the appeal fixture carries the panel).
        let mut e = pooled_panel_slashed();
        e.file_appeal(BOB, DEADLINE + 1).unwrap();
        e.review_appeal(M1, true).unwrap();
        e.review_appeal(M2, true).unwrap();
        assert_pool_conservation(&e, BOND);
        e.pool_payout(MULTISIG_PDA, BOB, 100_000, None, DEADLINE + WINDOW)
            .unwrap();
        assert_pool_conservation(&e, BOND);
        assert_eq!(e.appeal_bond_paid(), 0, "bond resolved into the pool");
    }
}
