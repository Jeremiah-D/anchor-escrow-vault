//! Funding chains (AV-223): one-way sequential funding — A → B.
//!
//! A chain links one upstream escrow A to one downstream escrow B so
//! that A's settlement funds B in order: when A releases, the taker
//! payout is diverted to B up to B's remaining funding need, and any
//! remainder follows A's normal release path to A's taker. This is
//! the one-way counterpart to AV-105's bilateral atomic swap
//! (`link_swap` settles two mirrored legs as one unit; a chain funds
//! one downstream leg from one upstream settlement, never the reverse).
//!
//! Design:
//! - The link is established only while A is `Uninitialized`
//!   (linking is a pre-fund setup step, like the AV-105 link and the
//!   `with_*` builders): [`link_chain`] records B's escrow id on A
//!   (`Escrow::chain_link`). The link is one-way — B carries no
//!   back-link, and B's own settlement paths are untouched.
//! - The downstream must opt into installment funding
//!   ([`Escrow::with_partial_funding`], AV-220): chain deposits
//!   accumulate in B's `funded_total` via the AV-220 accumulation
//!   math, so B stays `Uninitialized` while under-funded (pending
//!   funding) and flips to `Funded` exactly when the installments
//!   sum to B's declared amount. A downstream that funds single-shot
//!   (plain `fund`) cannot receive installments —
//!   [`release_chain`] refuses it with
//!   [`EscrowError::InvalidPartialFunding`] before A releases
//!   anything, so a mismatched downstream never strands a release.
//! - The funding leg reuses the `fund` check order (AV-223):
//!   pause, then reentrancy, then the partial-funding gate, the
//!   fundable-state gate, and the amount math — the same gates
//!   [`Escrow::fund_partial`] applies, minus its FUND-authority
//!   check: a chain deposit is pre-authorized by the link itself
//!   (established by A's party at [`link_chain`] time), and the
//!   release leg already passed A's own release authority inside
//!   [`Escrow::release`]. Re-checking B's initializer key here would
//!   demand a signature the chain settlement does not have.
//! - A live chain link makes A settle only through
//!   [`release_chain`]: a plain [`Escrow::release`] on a live-linked
//!   A refuses with [`EscrowError::ChainLinkActive`] (the AV-105
//!   single-side refusal, applied one-way). The link persists
//!   through A's terminal states as the audit trail — except when A
//!   itself terminates by cancel / expiry / dispute settlement:
//!   those paths *break* the chain (clear `chain_link`, see the
//!   `Escrow::cancel` / `expire_cancel_locked` / `resolve` notes)
//!   and no B funding ever happens for them. The break is audited
//!   as [`EscrowEventKind::ChainBroken`] by the indexer layer (see
//!   `events::IndexedEscrow::emit_chain_broken`).
//! - [`release_chain`] is atomic via the AV-105 dry-run pattern: a
//!   dry run on copies (link stripped on A's copy) computes the
//!   diversion and funds B's copy; any failure returns with both
//!   originals untouched. The real run then repeats the identical
//!   calls, which cannot fail after a passing dry run.
//! - A downstream that is already full (`Funded`, funded_total ==
//!   amount) or terminal settles nothing into B: the diversion is
//!   zero and the whole payout follows A's normal release path.
//!   Mint compatibility between the two legs is the Anchor layer's
//!   job (it moves the actual tokens); this pure-logic layer tracks
//!   amounts only, like the swap pair ops.
//!
//! [`Escrow::release`]: super::Escrow::release
//! [`Escrow::fund_partial`]: super::Escrow::fund_partial
//! [`Escrow::with_partial_funding`]: super::Escrow::with_partial_funding
//! [`EscrowEventKind::ChainBroken`]: super::EscrowEventKind::ChainBroken

use super::{partial_fund, Escrow, EscrowError, EscrowState};

/// Serialized length of the chain-link region in `VAULT_FIELDS`:
/// `Option<[u8; 32]>` = 1-byte Borsh discriminant + the 32-byte
/// downstream escrow id. The region is always reserved (zeroed when
/// `None`) so `link_chain` writes in place — same treatment as
/// `swap_link` / `arbiter` / `mint` / `refund_to` / `rent_payer`.
pub const CHAIN_LINK_REGION_LEN: usize = 1 + 32;

/// Outcome of [`release_chain`]: the split of A's taker payout
/// between A's taker and the downstream funding leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainRelease {
    /// What A's taker actually receives: the release payout minus
    /// the diverted funding leg (the full payout when B took nothing).
    pub taker_payout: u64,
    /// What landed in B's `funded_total` this call (`0` when B was
    /// already full or terminal).
    pub downstream_funding: u64,
    /// B's cumulative `funded_total` after this call.
    pub downstream_funded_total: u64,
    /// B's state after this call (`Funded` exactly when the chain
    /// completed B's funding).
    pub downstream_state: EscrowState,
}

/// True when `caller` is one of the two parties of the escrow — the
/// pair-op authority gate, mirroring `swap::is_party`. AV-104
/// operators are deliberately *not* consulted: chain ops are
/// party-only.
fn is_party(escrow: &Escrow, caller: [u8; 32]) -> bool {
    let (initializer, taker) = (escrow.initializer(), escrow.taker());
    caller == initializer || caller == taker
}

/// Link escrow A to downstream escrow B as a funding chain (AV-223).
///
/// On success `a.chain_link == Some(escrow_id_b)`. Gate order: pause
/// on A, then party authority, then state, then existing links, then
/// ids — mirroring [`link_swap`](super::link_swap) minus the mirrored
/// parties / mirrored amounts (a chain is one-way, so B's parties and
/// amount are not A's business at link time).
///
/// Rejections: [`EscrowError::Paused`] (A paused),
/// [`EscrowError::Unauthorized`] (caller is neither party of A),
/// [`EscrowError::InvalidStateTransition`] (A not `Uninitialized`),
/// [`EscrowError::ChainLinkActive`] (A already chain-linked),
/// [`EscrowError::SwapLinkActive`] (A already live swap-linked — one
/// escrow, one settlement linkage), [`EscrowError::InvalidChainLink`]
/// (zero or duplicate ids).
pub fn link_chain(
    a: &mut Escrow,
    caller: [u8; 32],
    escrow_id_a: [u8; 32],
    escrow_id_b: [u8; 32],
) -> Result<(), EscrowError> {
    // AV-46: pause guard first — a paused escrow fails fast, before
    // the authority check.
    a.require_not_paused()?;
    // Party-only: the chain diverts A's settlement, so only A's
    // parties may establish it; an AV-104 operator is Unauthorized.
    if !is_party(a, caller) {
        return Err(EscrowError::Unauthorized);
    }
    // Linking is a pre-fund setup step, like the `with_*` builders.
    if a.state() != EscrowState::Uninitialized {
        return Err(EscrowError::InvalidStateTransition);
    }
    // No double link: one chain per escrow, and there is no unlink —
    // the link persists as the audit trail once A settles, and only
    // A's own terminal cancel / expiry / dispute paths break it.
    if a.chain_link().is_some() {
        return Err(EscrowError::ChainLinkActive);
    }
    // A live swap-linked escrow settles only through the pair path —
    // it cannot also divert its settlement down a chain.
    a.require_no_live_swap_link()?;
    // Partner ids are caller-supplied (the escrow has no id field): a
    // zero id is a link to nowhere, a duplicate id is a self-link.
    if escrow_id_a == [0u8; 32] || escrow_id_b == [0u8; 32] || escrow_id_a == escrow_id_b {
        return Err(EscrowError::InvalidChainLink);
    }
    a.chain_link = Some(escrow_id_b);
    Ok(())
}

/// Break A's chain link (AV-223): clears `chain_link` and returns the
/// downstream id it held (`None` when A was unlinked). Called by the
/// terminal cancel / expiry / dispute paths on A — a broken chain
/// never funds B — and by the Anchor layer when it observes a break.
/// The break itself is audited as `ChainBroken` by the indexer layer.
pub fn break_chain(a: &mut Escrow) -> Option<[u8; 32]> {
    a.chain_link.take()
}

/// Fund the downstream leg of a chain (AV-223): the `fund_partial`
/// state effects without its FUND-authority check (see the module
/// docs — the link is the authorization). Check order mirrors
/// `fund_partial`: scheduled auto-recovery, pause, reentrancy,
/// partial-funding gate, fundable state, amount math.
fn apply_chain_funding(b: &mut Escrow, deposit: u64, now: u64) -> Result<u64, EscrowError> {
    // AV-133: scheduled auto-recovery first, like `fund_partial`.
    b.try_auto_unpause(now);
    b.require_not_paused()?;
    b.require_not_reentrant()?;
    if !b.partial_funding() {
        return Err(EscrowError::InvalidPartialFunding);
    }
    match b.state() {
        EscrowState::Uninitialized if !b.dual_sig_required() => {}
        EscrowState::Activated => {}
        _ => return Err(EscrowError::InvalidStateTransition),
    }
    let new_funded = partial_fund(b.funded_total(), deposit, b.amount())?;
    b.funded_total = new_funded;
    if new_funded == b.amount() {
        b.state = EscrowState::Funded;
        // Anchor the clocks exactly like `fund` (AV-64/AV-107).
        b.fund_at = now;
        b.interest_accrual_base = now;
    }
    b.touch_deadman_clock(now);
    Ok(new_funded)
}

/// Release A and divert the taker payout into B up to B's remaining
/// funding need (AV-223).
///
/// `caller` must be a party of A (the pair gate); the release itself
/// runs under A's initializer, mirroring `release_swap` (each leg
/// settles under its own initializer). `payout_to` is A's taker
/// destination for the remainder — the Anchor layer sends
/// `taker_payout` there and `downstream_funding` to B's vault.
///
/// Returns [`ChainRelease`]: the taker remainder, the funded leg,
/// and B's post-call funding state. A downstream that is already
/// full or terminal takes `0` and the whole payout goes to A's taker;
/// a downstream that is not partial-funding refuses the whole call
/// with `InvalidPartialFunding` (dry-run atomicity: A releases
/// nothing). A missing or mismatched link is `InvalidChainLink`.
#[allow(clippy::too_many_arguments)]
pub fn release_chain(
    a: &mut Escrow,
    b: &mut Escrow,
    caller: [u8; 32],
    escrow_id_a: [u8; 32],
    escrow_id_b: [u8; 32],
    now: u64,
    amount: u64,
    mint: Option<[u8; 32]>,
    payout_to: [u8; 32],
) -> Result<ChainRelease, EscrowError> {
    a.require_not_paused()?;
    b.require_not_paused()?;
    // Party-only: an AV-104 operator is Unauthorized — the delegation
    // slot is never consulted on pair ops.
    if !is_party(a, caller) {
        return Err(EscrowError::Unauthorized);
    }
    // The link must name exactly this downstream: a missing link or
    // a link to another escrow is a mislabeled chain.
    match a.chain_link() {
        Some(link) if link == escrow_id_b => {}
        _ => return Err(EscrowError::InvalidChainLink),
    }
    if escrow_id_a == [0u8; 32] || escrow_id_b == [0u8; 32] || escrow_id_a == escrow_id_b {
        return Err(EscrowError::InvalidChainLink);
    }
    let auth_a = a.initializer();
    // Phase 1 — dry run on copies with the link stripped (the
    // single-side refusal trips on a live link, so the copy runs
    // link-free). `Escrow` is `Copy`, so the originals are untouched
    // whatever the dry run decides.
    let mut dry_a = *a;
    let mut dry_b = *b;
    dry_a.chain_link = None;
    let (payout, _fee) = dry_a.release(auth_a, now, amount, mint, payout_to)?;
    // The diversion: only a partial-funding downstream in a fundable
    // state with room left takes funds; a full or terminal downstream
    // takes zero (its whole payout follows A's normal path). A
    // downstream in a fundable state that never opted into
    // partial funding cannot receive installments at all — refusing
    // the whole call here (dry-run atomicity: A releases nothing)
    // instead of silently settling everything to A's taker.
    let fundable = (dry_b.state() == EscrowState::Uninitialized && !dry_b.dual_sig_required())
        || dry_b.state() == EscrowState::Activated;
    if fundable && !dry_b.partial_funding() {
        return Err(EscrowError::InvalidPartialFunding);
    }
    let remaining = if fundable && dry_b.partial_funding() && dry_b.funded_total() < dry_b.amount() {
        dry_b.amount() - dry_b.funded_total()
    } else {
        0
    };
    let diversion = payout.min(remaining);
    if diversion > 0 {
        apply_chain_funding(&mut dry_b, diversion, now)?;
    }
    // Phase 2 — the real run: the dry run passed on identical inputs
    // and identical state, so these calls cannot fail; the link is
    // taken and restored around the release (it persists as the audit
    // trail — enforcement applies only to non-terminal states, and a
    // partially-released A keeps its chain for the next release).
    let link = a.chain_link.take();
    let real = a.release(auth_a, now, amount, mint, payout_to);
    a.chain_link = link;
    let (real_payout, _real_fee) = real?;
    debug_assert_eq!(real_payout, payout);
    if diversion > 0 {
        apply_chain_funding(b, diversion, now)?;
    }
    Ok(ChainRelease {
        taker_payout: real_payout - diversion,
        downstream_funding: diversion,
        downstream_funded_total: b.funded_total(),
        downstream_state: b.state(),
    })
}

#[cfg(test)]
mod chain_tests {
    use super::super::{link_swap, Escrow};
    use super::*;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const CAROL: [u8; 32] = [0xCC; 32];
    const DAVE: [u8; 32] = [0xDD; 32];
    const MALLORY: [u8; 32] = [0xEE; 32];
    const ID_A: [u8; 32] = [0xA1; 32];
    const ID_B: [u8; 32] = [0xB2; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;
    const T0: u64 = 1_700_000_000;

    /// A is ALICE→BOB of 1_000; B is CAROL→DAVE of `b_amount` with
    /// partial funding enabled, unlinked and unfunded.
    fn setup(b_amount: u64) -> (Escrow, Escrow) {
        let a = Escrow::initialize(ALICE, BOB, 1_000, EXPIRES_AT).unwrap();
        let b = Escrow::initialize(CAROL, DAVE, b_amount, EXPIRES_AT)
            .unwrap()
            .with_partial_funding()
            .unwrap();
        (a, b)
    }

    fn linked_funded_a(b_amount: u64) -> (Escrow, Escrow) {
        let (mut a, b) = setup(b_amount);
        link_chain(&mut a, ALICE, ID_A, ID_B).unwrap();
        a.fund(ALICE, T0).unwrap();
        (a, b)
    }

    #[test]
    fn link_chain_records_the_downstream_id() {
        let (mut a, _b) = setup(600);
        link_chain(&mut a, BOB, ID_A, ID_B).unwrap();
        assert_eq!(a.chain_link(), Some(ID_B));
    }

    #[test]
    fn link_chain_rejects_stranger_non_uninitialized_double_and_bad_ids() {
        let (mut a, _b) = setup(600);
        assert_eq!(
            link_chain(&mut a, MALLORY, ID_A, ID_B),
            Err(EscrowError::Unauthorized)
        );
        assert_eq!(a.chain_link(), None);
        a.fund(ALICE, T0).unwrap();
        assert_eq!(
            link_chain(&mut a, ALICE, ID_A, ID_B),
            Err(EscrowError::InvalidStateTransition)
        );
        let (mut c, _d) = setup(600);
        link_chain(&mut c, ALICE, ID_A, ID_B).unwrap();
        assert_eq!(
            link_chain(&mut c, ALICE, ID_A, ID_B),
            Err(EscrowError::ChainLinkActive)
        );
        let (mut e, _f) = setup(600);
        assert_eq!(
            link_chain(&mut e, ALICE, [0u8; 32], ID_B),
            Err(EscrowError::InvalidChainLink)
        );
        assert_eq!(
            link_chain(&mut e, ALICE, ID_A, ID_A),
            Err(EscrowError::InvalidChainLink)
        );
    }

    #[test]
    fn link_chain_rejects_a_live_swap_link() {
        let mut a = Escrow::initialize(ALICE, BOB, 1_000, EXPIRES_AT).unwrap();
        let mut b = Escrow::initialize(BOB, ALICE, 1_000, EXPIRES_AT).unwrap();
        link_swap(&mut a, &mut b, ALICE, ID_A, ID_B, 1_000, 1_000).unwrap();
        assert_eq!(
            link_chain(&mut a, ALICE, ID_A, ID_B),
            Err(EscrowError::SwapLinkActive)
        );
    }

    #[test]
    fn plain_release_refuses_a_live_chain_link() {
        let (mut a, _b) = linked_funded_a(600);
        assert_eq!(
            a.release(ALICE, T0, 1_000, None, BOB),
            Err(EscrowError::ChainLinkActive)
        );
    }

    #[test]
    fn release_chain_funds_the_downstream_to_completion() {
        let (mut a, mut b) = linked_funded_a(600);
        let out = release_chain(&mut a, &mut b, ALICE, ID_A, ID_B, T0, 1_000, None, BOB).unwrap();
        assert_eq!(out.downstream_funding, 600);
        assert_eq!(out.taker_payout, 400);
        assert_eq!(out.downstream_funded_total, 600);
        assert_eq!(out.downstream_state, EscrowState::Funded);
        assert_eq!(b.funded_total(), 600);
        assert_eq!(b.state(), EscrowState::Funded);
        // The chain link persists as the audit trail after settlement.
        assert_eq!(a.chain_link(), Some(ID_B));
    }

    #[test]
    fn release_chain_accumulates_a_partial_downstream_installment() {
        let (mut a, mut b) = linked_funded_a(1_500);
        let out = release_chain(&mut a, &mut b, ALICE, ID_A, ID_B, T0, 1_000, None, BOB).unwrap();
        assert_eq!(out.downstream_funding, 1_000);
        assert_eq!(out.taker_payout, 0);
        assert_eq!(out.downstream_funded_total, 1_000);
        // Under-funded: still pending funding, not Funded.
        assert_eq!(out.downstream_state, EscrowState::Uninitialized);
        assert_eq!(b.state(), EscrowState::Uninitialized);
        // A second upstream settlement completes it.
        let mut a2 = Escrow::initialize(ALICE, BOB, 500, EXPIRES_AT).unwrap();
        link_chain(&mut a2, ALICE, ID_A, ID_B).unwrap();
        a2.fund(ALICE, T0).unwrap();
        let out2 = release_chain(&mut a2, &mut b, ALICE, ID_A, ID_B, T0, 500, None, BOB).unwrap();
        assert_eq!(out2.downstream_funding, 500);
        assert_eq!(out2.downstream_state, EscrowState::Funded);
    }

    #[test]
    fn release_chain_diverts_only_the_remaining_need() {
        let (mut a, mut b) = linked_funded_a(600);
        b.fund_partial(CAROL, 500, T0).unwrap();
        let out = release_chain(&mut a, &mut b, ALICE, ID_A, ID_B, T0, 400, None, BOB).unwrap();
        assert_eq!(out.downstream_funding, 100);
        assert_eq!(out.taker_payout, 300);
        assert_eq!(out.downstream_state, EscrowState::Funded);
    }

    #[test]
    fn release_chain_skips_a_full_or_terminal_downstream() {
        // Full: B already funded to completion by its own installments.
        let (mut a, mut b) = linked_funded_a(600);
        b.fund_partial(CAROL, 600, T0).unwrap();
        assert_eq!(b.state(), EscrowState::Funded);
        let out = release_chain(&mut a, &mut b, ALICE, ID_A, ID_B, T0, 1_000, None, BOB).unwrap();
        assert_eq!(out.downstream_funding, 0);
        assert_eq!(out.taker_payout, 1_000);
        assert_eq!(out.downstream_funded_total, 600);
        // Terminal: B cancelled after its own funding is impossible
        // here (cancel needs Funded); use a fresh cancelled B instead.
        let (mut a2, mut b2) = linked_funded_a(600);
        b2.fund_partial(CAROL, 600, T0).unwrap();
        b2.cancel(CAROL, None, CAROL, T0).unwrap();
        assert!(b2.state().is_terminal());
        let out2 = release_chain(&mut a2, &mut b2, ALICE, ID_A, ID_B, T0, 1_000, None, BOB).unwrap();
        assert_eq!(out2.downstream_funding, 0);
        assert_eq!(out2.taker_payout, 1_000);
    }

    #[test]
    fn release_chain_refuses_a_non_partial_downstream_atomically() {
        let mut a = Escrow::initialize(ALICE, BOB, 1_000, EXPIRES_AT).unwrap();
        let mut b = Escrow::initialize(CAROL, DAVE, 600, EXPIRES_AT).unwrap();
        link_chain(&mut a, ALICE, ID_A, ID_B).unwrap();
        a.fund(ALICE, T0).unwrap();
        assert_eq!(
            release_chain(&mut a, &mut b, ALICE, ID_A, ID_B, T0, 1_000, None, BOB),
            Err(EscrowError::InvalidPartialFunding)
        );
        // Atomicity: A released nothing, B took nothing.
        assert_eq!(a.state(), EscrowState::Funded);
        assert_eq!(b.funded_total(), 0);
    }

    #[test]
    fn release_chain_rejects_a_missing_or_mismatched_link() {
        let (mut a, mut b) = linked_funded_a(600);
        assert_eq!(
            release_chain(&mut a, &mut b, ALICE, ID_A, [0xC3; 32], T0, 1_000, None, BOB),
            Err(EscrowError::InvalidChainLink)
        );
        let (mut c, mut d) = linked_funded_a(600);
        c.chain_link = None;
        assert_eq!(
            release_chain(&mut c, &mut d, ALICE, ID_A, ID_B, T0, 1_000, None, BOB),
            Err(EscrowError::InvalidChainLink)
        );
        // Strangers cannot drive the pair op.
        let (mut e, mut f) = linked_funded_a(600);
        assert_eq!(
            release_chain(&mut e, &mut f, MALLORY, ID_A, ID_B, T0, 1_000, None, BOB),
            Err(EscrowError::Unauthorized)
        );
    }

    #[test]
    fn cancel_breaks_the_chain_and_funds_nothing_downstream() {
        let (mut a, mut b) = linked_funded_a(600);
        let (init_refund, _taker_refund) = a.cancel(ALICE, None, ALICE, T0).unwrap();
        assert_eq!(init_refund, 1_000);
        assert_eq!(a.state(), EscrowState::Cancelled);
        assert_eq!(a.chain_link(), None);
        assert_eq!(b.funded_total(), 0);
        // The broken chain can no longer drive a release.
        assert_eq!(
            release_chain(&mut a, &mut b, ALICE, ID_A, ID_B, T0, 1_000, None, BOB),
            Err(EscrowError::InvalidChainLink)
        );
    }

    #[test]
    fn break_chain_returns_the_downstream_id_and_clears() {
        let (mut a, _b) = setup(600);
        assert_eq!(break_chain(&mut a), None);
        link_chain(&mut a, ALICE, ID_A, ID_B).unwrap();
        assert_eq!(break_chain(&mut a), Some(ID_B));
        assert_eq!(a.chain_link(), None);
    }
}
