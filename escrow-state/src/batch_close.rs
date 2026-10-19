//! AV-79: batch vault close — dual-party bound, filtered, failure-isolated.
//!
//! [`crate::keeper::scan_closeable`] (AV-40) *plans* closes: a dry-run
//! list of executable `close_vault` calls per initializer. This module
//! *executes* the close across many vaults in one call:
//!
//! - a [`CloseVaultsFilter`] selects vaults by state, expiry and
//!   amount range (non-matching vaults are *skipped*, reported with a
//!   machine-readable reason — skipping is an operator filter
//!   decision, not a vault rejection);
//! - dual-party binding: every vault must name the same initializer
//!   *and* taker the batch was submitted for. A vault naming a
//!   different taker fails that item with
//!   [`EscrowError::Unauthorized`] (the inner [`Escrow::close_vault`]
//!   only checks the initializer, so the taker leg is checked here
//!   first); the batch never aborts;
//! - per-vault failure isolation: one vault's rejection is recorded in
//!   the [`CloseVaultsReport`] while the rest of the batch still
//!   closes — the operator fixes the failed items and re-runs;
//! - the rent-exempt deposit is summed across the batch with
//!   [`crate::vault_close_rent_reclaimed`] per close — never a
//!   hardcoded figure;
//! - the indexed variant ([`close_indexed_vaults`]) emits one
//!   [`crate::EscrowEventKind::VaultClosed`] per closed vault (exactly
//!   the AV-34 emission) plus a single batch-level
//!   [`crate::EscrowEventKind::VaultsBatchClosed`] summary.
//!
//! # Pause gate (AV-46)
//!
//! The pause check is per-vault, not batch-wide: each vault runs the
//! exact [`Escrow::close_vault`] gates (AV-34) — `require_not_paused`
//! first, then the reentrancy guard, the initializer check, and the
//! terminal-state gate. A paused vault fails with
//! [`EscrowError::Paused`] and lands in the report's `failed` list
//! while the remaining vaults still close. There is deliberately no
//! batch-level pause flag: a fleet has no single circuit breaker in
//! this crate — each vault carries its own.
//!
//! # On-chain note
//!
//! The batch runs off-chain against the pure-logic state machine.
//! On-chain, each close is one `close_vault` instruction the
//! initializer submits (Anchor `close` constraint); the rent the
//! report sums is the mainnet rent-exempt minimum the program reads
//! from the rent sysvar at close time
//! ([`crate::vault_close_rent_reclaimed`] is the off-chain mirror of
//! that figure). **No new on-chain instruction is added here** —
//! `programs/escrow-vault/src/program.rs` is a placeholder skeleton
//! (see the README's "What's a skeleton") and gains no batch
//! instruction in this change.

use crate::{Escrow, EscrowError, EscrowState, IndexedEscrow, VaultDerivation};

/// Render 32 bytes as 64 lowercase hex characters (AV-92: for the
/// `vault_address` report fields).
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Append `"vault_address":<hex|null>` after an already-written
/// `"index":N` field.
fn push_vault_address_json(s: &mut String, vault_address: Option<[u8; 32]>) {
    s.push_str(",\"vault_address\":");
    match vault_address {
        Some(v) => {
            s.push('"');
            s.push_str(&hex32(&v));
            s.push('"');
        }
        None => s.push_str("null"),
    }
}

/// Which vaults a [`close_vaults`] / [`close_indexed_vaults`] batch
/// attempts to close. Every leg is optional: an unset leg does not
/// filter. Vaults failing any set leg are *skipped* (reported, never
/// failed) — skipping is an operator filter decision, not a vault
/// rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseVaultsFilter<'a> {
    /// Only vaults currently in one of these states are eligible.
    /// `None` = any state — the per-vault terminal-state gate inside
    /// [`Escrow::close_vault`] still applies: a `Disputed` or
    /// already-`Closed` vault that matched the filter fails with
    /// [`EscrowError::InvalidStateTransition`] and is reported as
    /// *failed*, not skipped (the vault matched the filter but the
    /// chain would reject the close).
    pub states: Option<&'a [EscrowState]>,
    /// Only vaults with `expires_at` strictly before this cutoff are
    /// eligible — i.e. vaults that expired before the cutoff. `None` =
    /// no expiry filter. Callers typically pass the batch's `now`.
    pub expired_before: Option<u64>,
    /// Only vaults locking at least this amount are eligible.
    /// `None` = no lower bound.
    pub min_amount: Option<u64>,
    /// Only vaults locking at most this amount are eligible.
    /// `None` = no upper bound.
    pub max_amount: Option<u64>,
}

impl<'a> CloseVaultsFilter<'a> {
    /// Accept every vault: no leg filters. Per-vault gates
    /// (dual-party binding, pause, terminal state) still apply.
    pub fn any() -> Self {
        Self {
            states: None,
            expired_before: None,
            min_amount: None,
            max_amount: None,
        }
    }

    /// The machine-readable skip reason for `escrow`, or `None` when
    /// every set leg matches: `"filter_state"`, `"filter_expiry"`,
    /// `"filter_min_amount"`, or `"filter_max_amount"` — evaluated in
    /// that order, first mismatch wins.
    fn skip_reason(&self, escrow: &Escrow) -> Option<&'static str> {
        if let Some(states) = self.states {
            if !states.contains(&escrow.state()) {
                return Some("filter_state");
            }
        }
        if let Some(cutoff) = self.expired_before {
            if escrow.expires_at() >= cutoff {
                return Some("filter_expiry");
            }
        }
        if let Some(min) = self.min_amount {
            if escrow.amount() < min {
                return Some("filter_min_amount");
            }
        }
        if let Some(max) = self.max_amount {
            if escrow.amount() > max {
                return Some("filter_max_amount");
            }
        }
        None
    }
}

/// One vault the batch close watches: the live escrow plus the
/// opt-in PDA derivation inputs. The batch mutates the escrow
/// (dry-run is [`crate::keeper::scan_closeable`]'s job); the seeds
/// only feed the report's precomputed vault addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseWatchItem {
    /// The live escrow to close.
    pub escrow: Escrow,
    /// AV-92: opt-in PDA derivation inputs for this vault (see
    /// [`VaultDerivation`]). Recorded via
    /// [`CloseWatchItem::with_vault_seeds`]; the report attaches the
    /// derived address to the item's entry as `vault_address`.
    /// `None` when the operator did not record seeds. Real Solana
    /// PDAs never store their seeds on-chain, so this stays
    /// off-chain by design.
    pub vault_derivation: Option<VaultDerivation>,
}

impl CloseWatchItem {
    /// Wrap a live escrow with no recorded seeds.
    pub fn new(escrow: Escrow) -> Self {
        Self {
            escrow,
            vault_derivation: None,
        }
    }

    /// Opt-in builder recording the vault's PDA derivation inputs
    /// (seeds + program id). Validates the seeds against the Solana
    /// `create_program_address` limits
    /// ([`EscrowError::InvalidVaultSeeds`] on violation).
    pub fn with_vault_seeds(
        mut self,
        seeds: &[&[u8]],
        program_id: &[u8; 32],
    ) -> Result<Self, EscrowError> {
        self.vault_derivation = Some(VaultDerivation::new(seeds, program_id)?);
        Ok(self)
    }

    /// The canonical vault PDA derived from the recorded seeds, or
    /// `None` when no seeds were recorded.
    pub fn vault_address(&self) -> Option<[u8; 32]> {
        self.vault_derivation.and_then(|d| d.address())
    }
}

/// One vault the batch closed: its input index, the terminal state it
/// closed from, and the rent-exempt lamports reclaimed
/// ([`crate::vault_close_rent_reclaimed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultClosedItem {
    pub index: usize,
    pub from: EscrowState,
    pub rent_reclaimed: u64,
    /// AV-92: the canonical vault PDA precomputed from the watch
    /// item's recorded seeds ([`CloseWatchItem::with_vault_seeds`]),
    /// or the recorded vault PDA for the indexed variant. `None`
    /// when the input carried no seeds. Informational.
    pub vault_address: Option<[u8; 32]>,
}

/// One vault the batch skipped: it did not match the
/// [`CloseVaultsFilter`]. `reason` is one of `"filter_state"`,
/// `"filter_expiry"`, `"filter_min_amount"`, `"filter_max_amount"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultSkippedItem {
    pub index: usize,
    pub reason: &'static str,
    /// AV-92: the precomputed vault PDA, as on [`VaultClosedItem`].
    pub vault_address: Option<[u8; 32]>,
}

/// One vault the batch attempted but could not close: the
/// [`EscrowError`] the attempt returned — [`EscrowError::Unauthorized`]
/// (initializer or taker mismatch), [`EscrowError::Paused`] (AV-46),
/// or [`EscrowError::InvalidStateTransition`] (non-terminal state,
/// e.g. `Disputed` or already `Closed`). The batch continued with the
/// remaining vaults; the operator fixes the item and re-runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultFailedItem {
    pub index: usize,
    pub error: EscrowError,
    /// AV-92: the precomputed vault PDA, as on [`VaultClosedItem`].
    pub vault_address: Option<[u8; 32]>,
}

/// The batch-close result: per-item outcomes in input order plus the
/// Σ rent-exempt lamports reclaimed. Deterministic JSON via
/// [`CloseVaultsReport::to_json`] (the crate is dependency-free).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseVaultsReport {
    /// How many vaults the batch scanned.
    pub scanned: usize,
    /// Vaults actually closed, in input order.
    pub closed: Vec<VaultClosedItem>,
    /// Vaults skipped by the filter, in input order.
    pub skipped: Vec<VaultSkippedItem>,
    /// Vaults the batch attempted but could not close, in input order.
    pub failed: Vec<VaultFailedItem>,
    /// Σ rent-exempt lamports reclaimed across the closed vaults —
    /// accumulated with `checked_add` from each close's
    /// [`crate::vault_close_rent_reclaimed`] return, never a
    /// hardcoded figure.
    pub total_rent_reclaimed: u64,
}

impl CloseVaultsReport {
    fn new(scanned: usize) -> Self {
        Self {
            scanned,
            closed: Vec::new(),
            skipped: Vec::new(),
            failed: Vec::new(),
            total_rent_reclaimed: 0,
        }
    }

    /// Number of vaults actually closed.
    pub fn closed_count(&self) -> usize {
        self.closed.len()
    }

    /// Number of vaults skipped by the filter.
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    /// Number of vaults the batch attempted but could not close.
    pub fn failed_count(&self) -> usize {
        self.failed.len()
    }

    /// Hand-serialized JSON (the crate is dependency-free).
    /// Deterministic field order; items stay in input order.
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(
            128 + self.closed.len() * 140 + self.skipped.len() * 112 + self.failed.len() * 132,
        );
        s.push_str("{\"scanned\":");
        s.push_str(&self.scanned.to_string());
        s.push_str(",\"closed\":[");
        for (i, item) in self.closed.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"index\":");
            s.push_str(&item.index.to_string());
            // AV-92: the precomputed vault PDA (hex) or null.
            push_vault_address_json(&mut s, item.vault_address);
            s.push_str(",\"from\":\"");
            s.push_str(&format!("{:?}", item.from).to_lowercase());
            s.push_str("\",\"rent_reclaimed\":");
            s.push_str(&item.rent_reclaimed.to_string());
            s.push('}');
        }
        s.push_str("],\"skipped\":[");
        for (i, item) in self.skipped.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"index\":");
            s.push_str(&item.index.to_string());
            push_vault_address_json(&mut s, item.vault_address);
            s.push_str(",\"reason\":\"");
            s.push_str(item.reason);
            s.push_str("\"}");
        }
        s.push_str("],\"failed\":[");
        for (i, item) in self.failed.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"index\":");
            s.push_str(&item.index.to_string());
            push_vault_address_json(&mut s, item.vault_address);
            s.push_str(",\"error\":\"");
            s.push_str(&format!("{:?}", item.error));
            s.push_str("\",\"code\":");
            s.push_str(&item.error.code().to_string());
            s.push('}');
        }
        s.push_str("],\"total_rent_reclaimed\":");
        s.push_str(&self.total_rent_reclaimed.to_string());
        s.push('}');
        s
    }
}

/// Close many vaults in one batch: for each vault that matches
/// `filter` and names the given `initializer` *and* `taker`, run the
/// exact [`Escrow::close_vault`] gates (AV-34: pause → reentrancy →
/// initializer authority → terminal-state gate) and reclaim the
/// rent-exempt deposit ([`crate::vault_close_rent_reclaimed`]).
///
/// Failure isolation: any single vault's rejection — filter mismatch
/// (skipped), taker mismatch or inner-gate failure (failed) — is
/// recorded in the [`CloseVaultsReport`] and the batch continues with
/// the next vault. The input slice order is preserved in the report.
///
/// Use [`close_indexed_vaults`] when the caller wants the AV-34
/// `VaultClosed` events per vault plus the batch-level
/// `VaultsBatchClosed` summary; this pure-logic variant emits nothing.
pub fn close_vaults(
    watched: &mut [CloseWatchItem],
    initializer: [u8; 32],
    taker: [u8; 32],
    filter: &CloseVaultsFilter<'_>,
) -> CloseVaultsReport {
    let mut report = CloseVaultsReport::new(watched.len());
    for (index, item) in watched.iter_mut().enumerate() {
        // Copy out first: `escrow` mutably borrows the item below.
        let vault_address = item.vault_address();
        let escrow = &mut item.escrow;
        if let Some(reason) = filter.skip_reason(escrow) {
            report.skipped.push(VaultSkippedItem {
                index,
                reason,
                vault_address,
            });
            continue;
        }
        // Dual-party binding: the taker leg is checked here (the
        // inner `close_vault` only checks the initializer), before
        // the state-changing call, so a taker mismatch reports
        // `Unauthorized` without touching the vault.
        if escrow.taker() != taker {
            report.failed.push(VaultFailedItem {
                index,
                error: EscrowError::Unauthorized,
                vault_address,
            });
            continue;
        }
        let from = escrow.state();
        match escrow.close_vault(initializer) {
            Ok(rent) => {
                // `rent` is `vault_close_rent_reclaimed()` by
                // construction (AV-34 returns the main formula, never
                // a constant); the Σ still accumulates with
                // `checked_add` — a defensive belt against any future
                // per-close variance.
                report.total_rent_reclaimed = report
                    .total_rent_reclaimed
                    .checked_add(rent)
                    .expect("AV-79: total rent overflowed u64");
                report.closed.push(VaultClosedItem {
                    index,
                    from,
                    rent_reclaimed: rent,
                    vault_address,
                });
            }
            Err(error) => {
                report.failed.push(VaultFailedItem {
                    index,
                    error,
                    vault_address,
                });
            }
        }
    }
    report
}

/// Close many vaults in one batch with event logging: the same
/// per-vault semantics as [`close_vaults`], but each close runs
/// through [`IndexedEscrow::close_vault`] so the AV-34 `VaultClosed`
/// event lands in that vault's log. After the loop, a single
/// [`crate::EscrowEventKind::VaultsBatchClosed`] summary is recorded
/// on the *first* closed vault's log (`from == to == Closed`,
/// `amounts.rent_reclaimed` = the batch Σ, actor = the initializer)
/// — or no summary at all when the batch closed nothing (the no-op
/// rule).
///
/// `at` is the batch's Unix-seconds timestamp, used for every event
/// the batch emits.
pub fn close_indexed_vaults(
    escrows: &mut [IndexedEscrow],
    initializer: [u8; 32],
    taker: [u8; 32],
    filter: &CloseVaultsFilter<'_>,
    at: u64,
) -> CloseVaultsReport {
    let mut report = CloseVaultsReport::new(escrows.len());
    for (index, escrow) in escrows.iter_mut().enumerate() {
        let inner = escrow.inner();
        // AV-92: the indexed input records the vault PDA as
        // `escrow_id` (vault-PDA convention), so the report carries it
        // directly — no seeds needed, the vault already exists.
        let vault_address = Some(escrow.escrow_id());
        if let Some(reason) = filter.skip_reason(inner) {
            report.skipped.push(VaultSkippedItem {
                index,
                reason,
                vault_address,
            });
            continue;
        }
        if inner.taker() != taker {
            report.failed.push(VaultFailedItem {
                index,
                error: EscrowError::Unauthorized,
                vault_address,
            });
            continue;
        }
        let from = inner.state();
        match escrow.close_vault(initializer, at) {
            Ok(rent) => {
                report.total_rent_reclaimed = report
                    .total_rent_reclaimed
                    .checked_add(rent)
                    .expect("AV-79: total rent overflowed u64");
                report.closed.push(VaultClosedItem {
                    index,
                    from,
                    rent_reclaimed: rent,
                    vault_address,
                });
            }
            Err(error) => {
                report.failed.push(VaultFailedItem {
                    index,
                    error,
                    vault_address,
                });
            }
        }
    }
    // The batch summary rides the first closed vault's log, in `seq`
    // order after its `VaultClosed`. Zero closes → no summary event.
    if let Some(first) = report.closed.first() {
        let index = first.index;
        let total = report.total_rent_reclaimed;
        escrows[index].record_vaults_batch_closed(total, at, initializer);
    }
    report
}

#[cfg(test)]
mod batch_close_tests {
    use super::*;
    use crate::{vault_close_rent_reclaimed, EscrowEventKind};

    const ALICE: [u8; 32] = [0xAA; 32]; // initializer
    const BOB: [u8; 32] = [0xBB; 32]; // taker
    const MALLORY: [u8; 32] = [0xCC; 32]; // stranger
    const ID1: [u8; 32] = [0x01; 32];
    const NOW: u64 = 1_750_000_000;
    const EXPIRED: u64 = 1_700_000_000; // before NOW
    const FUTURE: u64 = 1_800_000_000; // after NOW

    fn cancelled(amount: u64, expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, amount, expires_at).unwrap();
        e.fund(ALICE, NOW).unwrap();
        e.cancel(ALICE, None, ALICE, 0).unwrap();
        assert_eq!(e.state(), EscrowState::Cancelled);
        e
    }

    fn released(amount: u64, expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, amount, expires_at).unwrap();
        e.fund(ALICE, NOW).unwrap();
        e.release(ALICE, NOW, amount, None, BOB).unwrap();
        assert_eq!(e.state(), EscrowState::Released);
        e
    }

    fn funded(amount: u64, expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, amount, expires_at).unwrap();
        e.fund(ALICE, NOW).unwrap();
        e
    }

    fn indexed(escrow: Escrow, id: [u8; 32]) -> IndexedEscrow {
        // Rebuild an IndexedEscrow around a pre-transitioned inner
        // escrow: the wrapper's `inner` is private, so replay the
        // transitions through the indexed API instead. `at` values are
        // arbitrary but ordered.
        let mut ix = IndexedEscrow::initialize(ALICE, BOB, escrow.amount(), escrow.expires_at(), id, NOW - 3).unwrap();
        ix.fund(ALICE, NOW - 2).unwrap();
        match escrow.state() {
            EscrowState::Cancelled => {
                ix.cancel(ALICE, None, ALICE, NOW - 1).unwrap();
            }
            EscrowState::Released => {
                ix.release(ALICE, escrow.amount(), None, BOB, NOW - 1)
                    .unwrap();
            }
            EscrowState::Funded => {}
            other => panic!("test helper cannot replay {other:?}"),
        }
        assert_eq!(ix.inner().state(), escrow.state());
        ix
    }

    #[test]
    fn closes_every_terminal_state_and_sums_rent_from_the_main_formula() {
        let mut vaults = vec![
            CloseWatchItem::new(cancelled(1_000_000, FUTURE)),
            CloseWatchItem::new(released(2_000_000, FUTURE)),
            CloseWatchItem::new(cancelled(500_000, EXPIRED)),
        ];
        let report = close_vaults(&mut vaults, ALICE, BOB, &CloseVaultsFilter::any());
        assert_eq!(report.scanned, 3);
        assert_eq!(report.closed_count(), 3);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 0);
        assert_eq!(report.closed[0].from, EscrowState::Cancelled);
        assert_eq!(report.closed[1].from, EscrowState::Released);
        assert!(vaults.iter().all(|w| w.escrow.state() == EscrowState::Closed));
        // Rent is the main formula per close — never a hardcoded
        // figure; the Σ is exactly closes × formula.
        let per_close = vault_close_rent_reclaimed();
        assert!(per_close > 0);
        assert!(report.closed.iter().all(|c| c.rent_reclaimed == per_close));
        assert_eq!(report.total_rent_reclaimed, 3 * per_close);
    }

    #[test]
    fn taker_mismatch_fails_isolated_with_unauthorized() {
        // Item 0 names MALLORY as taker instead of BOB.
        let mut stranger = Escrow::initialize(ALICE, MALLORY, 1_000_000, FUTURE).unwrap();
        stranger.fund(ALICE, NOW).unwrap();
        stranger.cancel(ALICE, None, ALICE, 0).unwrap();
        let mut vaults = vec![CloseWatchItem::new(stranger), CloseWatchItem::new(cancelled(1_000_000, FUTURE))];
        let report = close_vaults(&mut vaults, ALICE, BOB, &CloseVaultsFilter::any());
        // Item 0: Unauthorized, vault untouched.
        assert_eq!(report.failed_count(), 1);
        assert_eq!(report.failed[0].index, 0);
        assert_eq!(report.failed[0].error, EscrowError::Unauthorized);
        assert_eq!(vaults[0].escrow.state(), EscrowState::Cancelled);
        // Item 1 still closed: failure isolation.
        assert_eq!(report.closed_count(), 1);
        assert_eq!(report.closed[0].index, 1);
        assert_eq!(vaults[1].escrow.state(), EscrowState::Closed);
    }

    #[test]
    fn wrong_initializer_fails_with_unauthorized() {
        let mut vaults = vec![CloseWatchItem::new(cancelled(1_000_000, FUTURE)), CloseWatchItem::new(released(1_000_000, FUTURE))];
        let report = close_vaults(&mut vaults, MALLORY, BOB, &CloseVaultsFilter::any());
        assert_eq!(report.closed_count(), 0);
        assert_eq!(report.failed_count(), 2);
        assert!(report
            .failed
            .iter()
            .all(|f| f.error == EscrowError::Unauthorized));
        assert!(vaults.iter().all(|w| w.escrow.state() != EscrowState::Closed));
    }

    #[test]
    fn non_terminal_and_disputed_vaults_fail_with_invalid_state_transition() {
        // A Disputed vault: the arbitration is still live.
        let mut e = IndexedEscrow::initialize(ALICE, BOB, 1_000_000, FUTURE, ID1, NOW - 3)
            .unwrap()
            .with_arbiter([0xA8; 32])
            .unwrap();
        e.fund(ALICE, NOW - 2).unwrap();
        e.escalate(ALICE, NOW - 1, e.inner().remaining_amount(), None, None, 0).unwrap();
        assert_eq!(e.inner().state(), EscrowState::Disputed);
        let mut vaults = vec![
            CloseWatchItem::new(funded(1_000_000, FUTURE)), // Funded: not terminal
            CloseWatchItem::new(*e.inner()),               // Disputed: arbitration live
            CloseWatchItem::new(cancelled(1_000_000, FUTURE)),
        ];
        let report = close_vaults(&mut vaults, ALICE, BOB, &CloseVaultsFilter::any());
        assert_eq!(report.failed_count(), 2);
        assert_eq!(report.failed[0].index, 0);
        assert_eq!(report.failed[1].index, 1);
        assert!(report
            .failed
            .iter()
            .all(|f| f.error == EscrowError::InvalidStateTransition));
        // The third vault still closed — isolation across gate kinds.
        assert_eq!(report.closed_count(), 1);
        assert_eq!(report.closed[0].index, 2);
    }

    #[test]
    fn paused_vault_fails_with_paused_while_rest_close() {
        // Pause is per-vault (AV-46): the paused vault fails fast and
        // is reported; the batch does not abort.
        let mut paused = Escrow::initialize(ALICE, BOB, 1_000_000, FUTURE)
            .unwrap()
            .with_pause_authority(ALICE)
            .unwrap();
        paused.fund(ALICE, NOW).unwrap();
        paused.cancel(ALICE, None, ALICE, 0).unwrap();
        paused.pause(ALICE, None).unwrap();
        let mut vaults = vec![CloseWatchItem::new(paused), CloseWatchItem::new(cancelled(1_000_000, FUTURE))];
        let report = close_vaults(&mut vaults, ALICE, BOB, &CloseVaultsFilter::any());
        assert_eq!(report.failed_count(), 1);
        assert_eq!(report.failed[0].index, 0);
        assert_eq!(report.failed[0].error, EscrowError::Paused);
        assert_eq!(vaults[0].escrow.state(), EscrowState::Cancelled);
        assert_eq!(report.closed_count(), 1);
        assert_eq!(vaults[1].escrow.state(), EscrowState::Closed);
    }

    #[test]
    fn filter_state_skips_non_matching_vaults() {
        let mut vaults = vec![
            CloseWatchItem::new(cancelled(1_000_000, FUTURE)),
            CloseWatchItem::new(released(1_000_000, FUTURE)),
            CloseWatchItem::new(funded(1_000_000, FUTURE)),
        ];
        let filter = CloseVaultsFilter {
            states: Some(&[EscrowState::Cancelled]),
            ..CloseVaultsFilter::any()
        };
        let report = close_vaults(&mut vaults, ALICE, BOB, &filter);
        assert_eq!(report.closed_count(), 1);
        assert_eq!(report.closed[0].index, 0);
        assert_eq!(report.skipped_count(), 2);
        assert_eq!(report.skipped[0].index, 1);
        assert_eq!(report.skipped[0].reason, "filter_state");
        assert_eq!(report.skipped[1].index, 2);
        assert_eq!(report.skipped[1].reason, "filter_state");
        // Skipped vaults are untouched.
        assert_eq!(vaults[1].escrow.state(), EscrowState::Released);
        assert_eq!(vaults[2].escrow.state(), EscrowState::Funded);
    }

    #[test]
    fn filter_expiry_selects_vaults_expired_before_cutoff() {
        let mut vaults = vec![
            CloseWatchItem::new(cancelled(1_000_000, EXPIRED)),
            CloseWatchItem::new(cancelled(1_000_000, FUTURE)),
            CloseWatchItem::new(cancelled(1_000_000, NOW)), // expires exactly at NOW: not < NOW
        ];
        let filter = CloseVaultsFilter {
            expired_before: Some(NOW),
            ..CloseVaultsFilter::any()
        };
        let report = close_vaults(&mut vaults, ALICE, BOB, &filter);
        assert_eq!(report.closed_count(), 1);
        assert_eq!(report.closed[0].index, 0);
        assert_eq!(report.skipped_count(), 2);
        assert!(report.skipped.iter().all(|s| s.reason == "filter_expiry"));
    }

    #[test]
    fn filter_amount_range_selects_by_locked_amount() {
        let mut vaults = vec![
            CloseWatchItem::new(cancelled(100, FUTURE)),
            CloseWatchItem::new(cancelled(1_000_000, FUTURE)),
            CloseWatchItem::new(cancelled(100_000_000, FUTURE)),
        ];
        let filter = CloseVaultsFilter {
            min_amount: Some(1_000),
            max_amount: Some(10_000_000),
            ..CloseVaultsFilter::any()
        };
        let report = close_vaults(&mut vaults, ALICE, BOB, &filter);
        assert_eq!(report.closed_count(), 1);
        assert_eq!(report.closed[0].index, 1);
        assert_eq!(report.skipped_count(), 2);
        assert_eq!(report.skipped[0].reason, "filter_min_amount");
        assert_eq!(report.skipped[1].reason, "filter_max_amount");
        assert_eq!(report.total_rent_reclaimed, vault_close_rent_reclaimed());
    }

    #[test]
    fn indexed_batch_emits_per_vault_closed_plus_one_summary() {
        let mut vaults = vec![
            indexed(cancelled(1_000_000, FUTURE), [0x11; 32]),
            indexed(released(2_000_000, FUTURE), [0x22; 32]),
            indexed(funded(3_000_000, FUTURE), [0x33; 32]), // skipped by filter
        ];
        let filter = CloseVaultsFilter {
            states: Some(&[EscrowState::Cancelled, EscrowState::Released]),
            ..CloseVaultsFilter::any()
        };
        let report = close_indexed_vaults(&mut vaults, ALICE, BOB, &filter, NOW);
        assert_eq!(report.closed_count(), 2);
        assert_eq!(report.skipped_count(), 1);
        assert_eq!(report.failed_count(), 0);
        let per_close = vault_close_rent_reclaimed();
        assert_eq!(report.total_rent_reclaimed, 2 * per_close);
        // Each closed vault carries the AV-34 VaultClosed event: vault 0
        // has VaultClosed second-to-last (the batch summary lands
        // after it, see below); vault 1 has it last.
        let kinds0: Vec<EscrowEventKind> =
            vaults[0].events().iter().map(|e| e.kind).collect();
        assert_eq!(kinds0[kinds0.len() - 2], EscrowEventKind::VaultClosed);
        assert_eq!(
            kinds0[kinds0.len() - 1],
            EscrowEventKind::VaultsBatchClosed,
            "summary lands after the vault's own VaultClosed, in seq order"
        );
        let kinds1: Vec<EscrowEventKind> =
            vaults[1].events().iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds1[kinds1.len() - 1],
            EscrowEventKind::VaultClosed,
            "vault 1"
        );
        for (i, expected_from) in [(0usize, EscrowState::Cancelled), (1, EscrowState::Released)] {
            let closed = vaults[i]
                .events()
                .iter()
                .find(|e| e.kind == EscrowEventKind::VaultClosed)
                .unwrap();
            assert_eq!(closed.from, expected_from);
            assert_eq!(closed.to, EscrowState::Closed);
            assert_eq!(closed.amounts.rent_reclaimed, per_close);
        }
        // The skipped vault's log is untouched by the batch.
        assert!(vaults[2]
            .events()
            .iter()
            .all(|e| e.kind != EscrowEventKind::VaultClosed));
        // One batch summary on the FIRST closed vault's log, after its
        // VaultClosed (seq order), carrying the Σ rent.
        let summary: Vec<_> = vaults[0]
            .events()
            .iter()
            .filter(|e| e.kind == EscrowEventKind::VaultsBatchClosed)
            .collect();
        assert_eq!(summary.len(), 1);
        let s = summary[0];
        assert_eq!(s.from, EscrowState::Closed);
        assert_eq!(s.to, EscrowState::Closed);
        assert_eq!(s.amounts.rent_reclaimed, 2 * per_close);
        assert_eq!(s.amounts.payout, 0);
        assert_eq!(s.amounts.fee, 0);
        assert_eq!(s.amounts.refund, 0);
        assert_eq!(s.amounts.penalty, 0);
        assert_eq!(s.at, NOW);
        // No summary on the second closed vault's log — exactly one.
        assert!(vaults[1]
            .events()
            .iter()
            .all(|e| e.kind != EscrowEventKind::VaultsBatchClosed));
    }

    #[test]
    fn indexed_batch_that_closes_nothing_emits_no_summary() {
        let mut vaults = vec![indexed(funded(1_000_000, FUTURE), [0x11; 32])];
        let report = close_indexed_vaults(&mut vaults, ALICE, BOB, &CloseVaultsFilter::any(), NOW);
        assert_eq!(report.closed_count(), 0);
        assert_eq!(report.failed_count(), 1); // Funded: InvalidStateTransition
        assert!(vaults[0]
            .events()
            .iter()
            .all(|e| e.kind != EscrowEventKind::VaultsBatchClosed));
    }

    #[test]
    fn report_json_shape_is_deterministic() {
        // Item 0 names MALLORY as taker (batch taker is BOB) →
        // Unauthorized; item 1 is Funded → InvalidStateTransition;
        // item 2 closes.
        let mut stranger = Escrow::initialize(ALICE, MALLORY, 1_000_000, FUTURE).unwrap();
        stranger.fund(ALICE, NOW).unwrap();
        stranger.cancel(ALICE, None, ALICE, 0).unwrap();
        let mut vaults = vec![
            CloseWatchItem::new(stranger),
            CloseWatchItem::new(funded(2_000_000, FUTURE)),
            CloseWatchItem::new(released(3_000_000, FUTURE)),
        ];
        let report = close_vaults(&mut vaults, ALICE, BOB, &CloseVaultsFilter::any());
        assert_eq!(report.closed_count(), 1);
        assert_eq!(report.failed_count(), 2);
        let json = report.to_json();
        let per_close = vault_close_rent_reclaimed();
        let expected = format!(
            "{{\"scanned\":3,\"closed\":[{{\"index\":2,\"vault_address\":null,\"from\":\"released\",\"rent_reclaimed\":{per_close}}}],\"skipped\":[],\"failed\":[{{\"index\":0,\"vault_address\":null,\"error\":\"Unauthorized\",\"code\":{}}},{{\"index\":1,\"vault_address\":null,\"error\":\"InvalidStateTransition\",\"code\":{}}}],\"total_rent_reclaimed\":{per_close}}}",
            EscrowError::Unauthorized.code(),
            EscrowError::InvalidStateTransition.code(),
        );
        assert_eq!(json, expected);
    }

    #[test]
    fn vault_address_attached_to_close_report() {
        // AV-92: with recorded seeds the closed entry carries the
        // precomputed vault PDA; the indexed variant carries the
        // recorded vault PDA (escrow_id) directly.
        let program_id = [0x07; 32];
        let seeds: &[&[u8]] = &[b"vault", &ALICE];
        let expected = crate::find_program_address(seeds, &program_id)
            .map(|(addr, _)| addr)
            .unwrap();
        let mut vaults = vec![
            CloseWatchItem::new(cancelled(1_000_000, FUTURE))
                .with_vault_seeds(seeds, &program_id)
                .unwrap(),
            CloseWatchItem::new(cancelled(2_000_000, FUTURE)),
        ];
        let report = close_vaults(&mut vaults, ALICE, BOB, &CloseVaultsFilter::any());
        assert_eq!(report.closed.len(), 2);
        assert_eq!(report.closed[0].vault_address, Some(expected));
        assert_eq!(report.closed[1].vault_address, None);
        let json = report.to_json();
        assert!(
            json.contains(&format!("\"vault_address\":\"{}\"", hex32(&expected))),
            "vault_address hex missing: {json}"
        );
        assert!(json.contains("\"vault_address\":null"));

        // Indexed variant: escrow_id is the vault PDA by convention.
        let mut indexed_vaults = vec![indexed(cancelled(1_000_000, FUTURE), ID1)];
        let report = close_indexed_vaults(
            &mut indexed_vaults,
            ALICE,
            BOB,
            &CloseVaultsFilter::any(),
            NOW,
        );
        assert_eq!(report.closed.len(), 1);
        assert_eq!(report.closed[0].vault_address, Some(ID1));
    }

    #[test]
    fn new_event_kind_pins_discriminant_40_and_name() {
        assert_eq!(EscrowEventKind::VaultsBatchClosed.discriminant(), 40);
        assert_eq!(EscrowEventKind::VaultsBatchClosed.name(), "vaults_batch_closed");
        // `discriminant` is pub(crate); the round trip is asserted in
        // lib.rs's pinned table — here just the name mapping.
    }
}
