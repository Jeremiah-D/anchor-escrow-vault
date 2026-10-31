# anchor-escrow-vault

> **Portfolio reconstruction** — a Solana/Anchor escrow-vault project built to
> demonstrate on-chain state-machine and authority engineering. This is a
> learning reconstruction, not employer production code.

## Inspiration

My documented escrow experience is in Solidity/Foundry. From a public
professional profile:

> "Designed multi-sig escrow smart contracts (Solidity / Foundry) with
> deterministic release conditions and an attestor quorum"

This repo ports the same escrow state machine to the Solana/Anchor stack as
a reconstruction exercise: the same lifecycle (initialize → fund →
release/cancel), the same authority checks, the same amount invariants.

## Honest scope

- **What's real:** the `escrow-state` crate is a dependency-free Rust state
  machine (`Uninitialized → Funded → Released/Cancelled`, plus the
  opt-in `Activated` step for dual-signature escrows) with initializer
  authority checks and amount invariants, fully covered by unit tests.
  `IndexedEscrow` (`escrow-state/src/events.rs`) is an event-logging
  adapter over it: every state transition records one typed
  `EscrowEvent` (see "Indexer events" below), so an off-chain indexer
  can subscribe to state changes in per-escrow `seq` order.
- **What's a skeleton:** `programs/escrow-vault/src/program.rs` is an Anchor program source
  file showing how the instructions (`initialize`, `fund`, `release`,
  `cancel`, `cancel_expired`, `initialize_quorum`, `attest`,
  `initialize_dual_sig`, `activate`, `initialize_vesting`, `claim`,
  `initialize_arbiter`, `escalate`, `resolve`, `initialize_milestones`,
  `confirm_milestone`, `release_milestone`, `skip_milestone`,
  `initialize_mint`) would wrap the
  `escrow-state` logic on-chain. It is **not
  compiled here** — a full on-chain build and test requires the Solana/Anchor
  toolchain. The compilable `escrow-vault` cargo package only ships
  `#[ignore]`d integration test stubs (`tests/local_validator.rs`) that
  drive the instruction → state machine mapping through `escrow-state`;
  they need a local `solana-test-validator` and are skipped by CI.
- **What CI does:** it runs `cargo test -p escrow-state` only. The
  `escrow-vault` integration stubs are `#[ignore]`d (see below) and never
  run in CI.

No unverified claims are made about deployments, audits, or performance.

## Layout

```
escrow-state/               # pure-Rust state machine, zero dependencies
  src/lib.rs                # Escrow, EscrowState, EscrowError + unit tests
  src/events.rs             # AV-18: IndexedEscrow event-logging wrapper + EscrowEvent types + event_tests
  src/event_sourcing.rs     # AV-94: event-sourced materialized fund view — per-escrow (locked, released, refunded) fold + fleet aggregate, strict seq continuity
  src/batch_close.rs        # AV-79: batch vault close — dual-party bound, filtered, failure-isolated (off-chain execution; no new on-chain instruction)
programs/escrow-vault/      # Anchor program skeleton (on-chain part not in cargo build)
  src/program.rs            # instructions wrapping escrow-state (needs anchor-lang)
  Cargo.toml                # `escrow-vault` package: local-validator test stubs only
  tests/local_validator.rs  # #[ignore]d integration stubs (need local validator)
Anchor.toml                 # Anchor project config (devnet placeholder)
.github/workflows/ci.yml    # CI: cargo test -p escrow-state
```

## State machine

| Transition                                  | From           | To        | Authority              |
|---------------------------------------------|----------------|-----------|------------------------|
| `initialize(initializer, taker, amount, expires_at)` | — | `Uninitialized` | anyone (amount > 0) |
| `initialize_arbiter(arbiter)`               | `Uninitialized`| `Uninitialized` | initializer (once, before funding; zero key rejected; mutually exclusive with `initialize_arbiter_panel` — last-wins in both directions) |
| `initialize_slash_terms(penalty_account, slash_deadline)` (AV-82) | `Uninitialized`| `Uninitialized` | initializer (once, before funding; the zero penalty account is rejected — the penalty sink must be a real identity, `SlashNotEligible` code 143; mutually exclusive with the AV-126 slash ladder — configuring either when the other is set is `InvalidSlashLadder`, code 184) |
| `with_slash_ladder(penalty_account, rungs)` (AV-126) | `Uninitialized`| `Uninitialized` | initializer (once, before funding; the opt-in tiered default-penalty ("slash ladder") built on the AV-82 single-level slash — `rungs` is a list of 1–8 `(deadline_secs, bps)` pairs with strictly ascending deadlines, strictly ascending bps, no zero-bps rung, and no bps above 10_000 (`InvalidSlashLadder`, code 184, otherwise); the zero penalty account is rejected (`InvalidSlashLadder`); mutually exclusive with `with_slash_terms` — configuring either when the other is set is `InvalidSlashLadder`, code 184) |
| `initialize_arbiter_panel(members, threshold)` (AV-65) | `Uninitialized`| `Uninitialized` | initializer (once, before funding; opt-in multisig arbitration: 1–8 member keys, threshold 1..=N, zero/duplicate keys rejected as `InvalidArbiterPanel`, code 136; mutually exclusive with the single arbiter — last-wins in both directions; `rotate_arbiter` is `InvalidStateTransition` in panel mode) |
| `escalate(authority, now, evidence_hash, evidence_root, evidence_leaves)` (AV-91) | `Funded`       | `Disputed` | initializer **or** taker, only when `now < expires_at` (locks `release`/`cancel`/`cancel_expired`/`claim`); `evidence_hash` is the optional 32-byte off-chain-evidence commitment, persisted; `evidence_root` is the optional SHA-256 Merkle root over the evidence-document set and `evidence_leaves` the committed leaf count (`0` iff the root is `None`, `1..=64` iff `Some` — `InvalidEvidenceProof`, code 148, on a count that does not describe the root); the root/leaves/zeroed disclosure bitmap are persisted and never cleared; refused with `AuctionNotActive` (code 156) while an AV-97 Dutch-auction window is live — price discovery and arbitration are mutually exclusive settlement paths |
| `resolve(authority, taker_amount, rationale_hash)` | `Disputed`     | `Settled` | arbiter only; atomic split of the remainder (taker payout / initializer refund); `rationale_hash` is the optional 32-byte commitment to the arbiter's off-chain rationale document, persisted in `Settled` (never cleared); AV-119: the dispute window `[disputed_at, resolved_at]` (resolved_at from the clock sysvar) accrues interest on the locked remainder at the AV-107 rate, and the whole outstanding yield claim splits pro-rata by `taker_amount / remaining` — the taker's share rides the taker payout (into `interest_paid`), the initializer's share rides the refund (into `dispute_interest`); on a compound-interest escrow the yield folds into the principal instead (AV-117 mutual exclusion); **disabled in panel mode** (`PanelResolveDisabled`, code 137 — the panel's multisig judgment is the only settlement path once a panel is configured) |
| `submit_panel_judgment(member, taker_amount, rationale_hash)` (AV-65) | `Disputed` | `Disputed` (vote recorded) / `Settled` (M matching votes) | panel member only (`Unauthorized` for a stranger); one effective vote per member — a re-vote overwrites the earlier vote (the `PanelJudgment` event keeps the audit trail); the first M votes agreeing on the same `(taker_amount, rationale_hash)` pair settle the escrow automatically (`Settled`, settlement identical to `resolve` — fee slices the taker's share, gross lands in the `released` counter, the initializer is refunded the remainder; AV-119: the settling vote's time is the dispute window's `resolved_at`, and the yield attribution follows the same pro-rata rule via the shared helper); non-matching votes stay recorded for audit; the settling vote emits `PanelResolved` after its `PanelJudgment`; `InvalidArbiterPanel` (code 136) with no panel configured |
| `initialize_blind_panel(members, threshold, reveal_window_secs)` (AV-137) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; opt-in blind commit-reveal panel voting: 1–8 member keys, threshold 1..=N, `reveal_window_secs` non-zero; same validation as `initialize_arbiter_panel` plus the window; mutually exclusive with the single arbiter — last-wins in both directions; the 995-byte panel region is always reserved so the opt-in writes in place) |
| `submit_judgment_commit(member, commitment)` (AV-137) | `Disputed` | `Disputed` (commit recorded) | panel member only (`Unauthorized` for a stranger); `commitment = SHA-256(taker_amount \|\| rationale_hash \|\| salt)` — the judgment stays hidden; zero commitment is `BlindInvalidCommitment` (code 199); a second commit before the reveal overwrites the first (last-wins, window restarts); the commit binds to the escrow's `disputed_at` snapshot; emits `JudgmentCommitted` |
| `reveal_judgment(member, taker_amount, rationale_hash, salt)` (AV-137) | `Disputed` | `Disputed` (vote recorded) / `Settled` (M matching reveals) | panel member only; the recomputed commitment must match (`BlindCommitMismatch`, code 200); each commit reveals once (`BlindDuplicateReveal`, code 201; `BlindNoCommit`, code 204 with no commit); late reveals rejected (`BlindRevealWindowClosed`, code 202); stale snapshots auto-invalidated (`BlindCommitStale`, code 203); the revealed vote settles exactly like `submit_panel_judgment` (mint/payout-policy/fee/interest identical via the shared helper); plain `submit_panel_judgment` is rejected in blind mode (`BlindVoteMustReveal`, code 205); emits `JudgmentRevealed` per reveal and `PanelResolved` on the settling reveal |
| `initialize_default_judgment(deadline_secs, default_taker_amount)` (AV-55) | `Uninitialized` | `Uninitialized` | initializer (once, before funding — and only after `initialize_arbiter`; the arbiter must be configured first); declares the fallback split applied when the arbiter never resolves: `deadline_secs` seconds in `Disputed` before the judgment becomes triggerable (must be non-zero — `DefaultJudgmentNotDue` otherwise), `default_taker_amount` the taker's share of the remainder (must be ≤ the locked amount — `ReleaseExceedsLocked` otherwise); the initializer proposes the terms, the taker must still countersign (dual-signed agreement) |
| `confirm_default_judgment()` (AV-55) | `Uninitialized` / `Funded` | — (no state change; sets the confirmation bit) | **taker only** (`Unauthorized` for a stranger or the initializer); no judgment configured is `DefaultJudgmentNotDue`; idempotent (re-confirming is `Ok`) |
| `trigger_default_judgment(caller, now, payout_to)` (AV-55) | `Disputed` | `Settled` | **initializer or taker** (either party — a liveness backstop, not a power grant); only once `now >= disputed_at + deadline_secs` (the judgment's due time, `DefaultJudgmentNotDue` otherwise); settles on the pre-agreed split — fee slices the taker's share like `resolve`, quorum/vesting/timelock do *not* gate (same as `resolve`); AV-119: `now` doubles as the dispute window's `resolved_at`, and the yield attribution follows the same pro-rata rule as `resolve` via the shared helper; the arbiter's `resolve` is unchanged and keeps priority — after the deadline either the arbiter resolves or a party triggers, first writer wins; in AV-65 panel mode the default judgment stays available (same deadline rules) and races the panel's M-vote settlement instead; emits `DefaultJudgment` |
| `initialize_evidence_deadline(deadline_secs)` (AV-68) | `Uninitialized` | `Uninitialized` | initializer (once, before funding — and only after the arbiter/panel is configured, `InvalidArbiter` otherwise); declares the window the escalating party gets to disclose the dispute evidence, measured from `disputed_at`; must be non-zero (`InvalidEvidenceDeadline`, code 138, otherwise) |
| `submit_evidence(authority, evidence_hash, now)` (AV-68) | `Disputed` | `Disputed` (commitment recorded) | **escalating party only** (the party `escalate` recorded — a stranger or the counterparty is `Unauthorized`); overwrites any previously attached hash (a within-deadline submission may always refine the bundle); at or past the disclosure deadline the submission is rejected (`EvidenceDisclosureLate`, code 139) — the deadline is a hard bar, so a missed deadline locks in the judgment-time adverse inference; with no deadline configured disclosure is accepted at any time while `Disputed`; emits `EvidenceSubmitted` |
| `file_evidence(authority, doc_hash, leaf_index, proof, now)` (AV-91) | `Disputed` | `Disputed` (bitmap bit flipped) | **escalating party only** (mirrors `submit_evidence`); discloses one document against the committed Merkle root — `proof` must carry exactly the siblings the tree shape demands (leaf = `H(0x00 \|\| doc)`, node = `H(0x01 \|\| left \|\| right)`, odd-layer last node promotes unchanged); `InvalidEvidenceProof` (code 148) on no committed root, a past-end leaf index, a wrong-length proof, or a non-verifying proof; the AV-68 deadline bar applies (`EvidenceDisclosureLate` past the window); re-filing is an idempotent no-op; emits `EvidenceFiled` |
| `update_panel_threshold(initializer, taker, new_threshold)` (AV-69) | `Uninitialized` | `Uninitialized` | **dual-signed** — the initializer AND the taker must both sign (one party alone, or a stranger pair, is `Unauthorized`); retunes the arbiter panel's M-of-N judgment threshold, 1 ≤ M ≤ N (`InvalidArbiterPanel`, code 136, for 0, above N, or no panel configured); a panel must be configured — there is no threshold to retune on a single-arbiter escrow; `Uninitialized` only — the threshold must be settled before the dispute starts, so an in-flight arbitration tallies under stable rules; the retune rewrites only the threshold — cast votes and the `voted` bitmask survive, counting continues under the new M; retuning to the current threshold is an idempotent no-op; emits `PanelThresholdChanged` only on an actual change |
| `initialize_subscription(period_secs, periods, per_period)` (AV-56) | `Uninitialized` | `Uninitialized` | initializer (once, before funding — mutually exclusive with `initialize_milestones`; declares the periodic release schedule, back-scheduled from `expires_at`: period `i` is due at `expires_at - (periods-1-i) * period_secs`; validation — `period_secs` non-zero, `periods` in 1..=64, `per_period` non-zero, `periods * per_period` == locked amount (in u128), `expires_at != u64::MAX`, and the schedule must fit the lifetime — is `InvalidSubscription` otherwise) |
| `release_period(period_index)` (AV-56) | `Funded` | `Funded` (partial) / `Released` (last period) | initializer only (the initializer's push path); strictly in-order (`period_index` must equal the next due period — skip-ahead and replay are `PeriodNotDue`) and due-date gated (`now >= due_at(period_index)` — `PeriodNotDue` otherwise); quorum satisfied when configured (`QuorumNotReached`), the timelock gate when a lock is configured (`now >= unlock_at` (AV-27) or `now >= fund_at + secs` (AV-64); `TimelockNotReached` — the timelock gates every taker payout path); `MintMismatch` / `PayoutNotAllowlisted` guard the fund movement like `release`; the protocol fee slices the period (`payout + fee == per_period`); vesting claim composes (not blocked); emits `SubscriptionPeriodReleased` |
| `crank_release_period(caller, now)` (AV-160) | `Funded` | `Funded` (partial) / `Released` (last period) | **anyone** — permissionless subscription-period crank (the subscription analogue of the AV-48 `crank_expired` Solana crank pattern): any key may release the next *due* subscription period when the initializer's push path is idle, no counterparty signature needed, so a keeper bot that is party to nothing keeps the schedule liveness-safe; anti-MEV — the payout is pinned to the taker (the state machine asserts the pin internally, the Anchor layer asserts the transfer account matches) and the caller receives zero (deliberately no keeper bounty on this crank); releases exactly `subscription_next` (`PeriodNotDue` when nothing is due); every other gate mirrors `release_period` (`Funded`, schedule required, due timing, `MintMismatch`, `QuorumNotReached`, `TimelockNotReached`, fee slices the period `payout + fee == per_period`); emits `SubscriptionPeriodReleased` with the cranker's key as caller |
| `initialize_milestones(milestones)`          | `Uninitialized`| `Uninitialized` | initializer (once, before funding; tranche amounts must sum to the locked amount) |
| `confirm_milestone(authority, index)`        | `Funded`       | — (no state change) | initializer **or** taker (in order; a milestone is confirmed once *both* parties confirmed) |
| `release_milestone(authority, now, index)`        | `Funded`       | `Funded` (partial) / `Released` (final tranche) | initializer; milestone dual-confirmed (+ quorum satisfied when configured; the timelock gate when a lock is configured — `now >= unlock_at` (AV-27) or `now >= fund_at + secs` (AV-64) — `TimelockNotReached` otherwise) |
| `release_milestone_partial(authority, now, index, amount)` (AV-229) | `Funded` | `Funded` (partial slice) / `Released` (final slice of the final tranche) | initializer; milestone dual-confirmed (+ quorum satisfied when configured, priced on the slice's own amount; the timelock gate when a lock is configured); `amount` must be positive and no larger than the tranche's unclaimed remainder (`ReleaseExceedsLocked` otherwise, fail-closed — a refused slice settles nothing and charges no fee); slices accumulate into `released` / `fees_paid` / `penalty_paid` exactly like full releases and the per-tranche ledger `milestone_partial_claimed_at()` records the claimed gross, so a full `release_milestone` on a partially claimed tranche settles only the remainder and never re-pays a slice; the tranche stays the next milestone until the slices sum to the full tranche, when the released bit is set; the AV-206 late penalty prices the slice's own amount and the AV-225 claim deadline gates the slice like a full claim — past the deadline the slice is rejected with `MilestoneClaimExpired` and only the unclaimed remainder returns to remainder (already-claimed slices stay paid); emits `MilestonePartiallyClaimed` (discriminant 93) with the slice's gross in payout and the protocol fee in fee |
| `skip_milestone(authority, index)`           | `Funded`       | — (no state change) | initializer **or** taker, **both** must approve (dual-sig skip; skipped tranche refunded to the initializer) |
| `unskip_milestone(initializer, taker, index)` (AV-232) | `Funded` | — (no state change; restores the tranche to the claimable schedule) | **both** parties must sign (dual-signature governance — one party alone cannot resurrect a tranche the other agreed to refund); the tranche must currently be skipped, every earlier tranche settled (so the restored tranche becomes the earliest unsettled one), and no later tranche settled (a skip followed by a later settlement is final — restoration is last-settled-first-restored); the `SKIPPED_BIT` and both skip-approval bits clear and the tranche amount leaves the skipped pool (checked, fail-closed, zero-write on refusal); per-tranche confirmations survive (they accept the deliverable, not the settlement); a released or never-skipped tranche is `InvalidStateTransition`; emits `MilestoneUnskipped` (discriminant 96), all amounts zero |
| `adjust_milestone_amounts(initializer, taker, new_amounts)` (AV-70) | `Uninitialized`/`Activated`/`Funded` | — (no state change; rewrites the tranche table) | **both** the initializer and the taker must sign (dual-signature governance — one party alone or a stranger pair is `Unauthorized`); terminal states and `Disputed` are `InvalidStateTransition`; rejected once any tranche settled (`released > 0` or `skipped > 0`); new amounts must have the plan's tranche count, be all positive, and sum to exactly the locked amount; per-tranche confirmations survive (they accept the deliverable, not the amount); protocol fees charge on the new amounts at release time (still floored by `fee_cap`); emits `MilestonesAdjusted` only on an actual change |
| `amend_milestones(initializer, taker, new_amounts)` (AV-155) | `Uninitialized`/`Funded` | — (no state change; rewrites the tranche table) | **both** parties must sign (dual-signature governance); terminal states and `Disputed` are `InvalidStateTransition`; confirmed or settled tranches keep their exact amounts (`InvalidMilestoneAmendment` on reprice); new amounts must have the plan's tranche count, be all positive, and sum to exactly the locked amount; unconfirmed tranches may be repriced mid-flight; in-place rewrite (no realloc); emits `MilestonesAmended` only on an actual change |
| `reallocate_milestones(initializer, taker, new_amounts)` (AV-224) | `Uninitialized`/`Funded` | — (no state change; rewrites the tranche table) | **both** parties must sign (dual-signature governance); terminal states and `Disputed` are `InvalidStateTransition`; confirmed or settled tranches keep their exact amounts (`InvalidMilestoneAmendment` on reprice); new amounts must have the plan's tranche count and sum to exactly the locked amount; unlike `amend_milestones`, an unconfirmed tranche may be repriced to zero — cleared, not deleted (the plan keeps its tranche count and the in-order sequence still walks the zero slot); the refundable remainder is unchanged (repricing without rerouting, the mirror of `skip_milestone`'s rerouting without repricing); later releases price from the live plan, already-released/skipped amounts are untouched; in-place rewrite (no realloc); emits `MilestonesReallocated` (discriminant 89) only on an actual change, carrying the before/after tranche tables on the event |
| `with_milestone_claim_deadline(tranche, deadline_secs)` (AV-225) | `Uninitialized` | — (no state change; attaches a per-tranche claim deadline) | opt-in, per-tranche, `Uninitialized`-only (after `with_milestones`; a plan is required, tranche in range, a zero deadline is `InvalidMilestones`); `deadline_secs` is an absolute unix timestamp in seconds, mirroring AV-206 `due_at`; claiming exactly at the deadline is on time, strictly after is expired; a vested (dual-confirmed, past the unlock gate, next in order) tranche claimed after its deadline is rejected with `MilestoneClaimExpired` (code 355) and the tranche amount automatically returns to remainder (`skipped += tranche`, same conservation backstop as `skip_milestone`) — the initializer reclaims it via the normal cancel path, nothing is forfeited; an unconfirmed tranche past its deadline still fails `MilestoneNotConfirmed` and nothing moves; claim semantics before the deadline unchanged; orthogonal to skip (an active action, this is time-expiry auto-return), to AV-51 vesting cliff (the cliff governs unlock time, this governs the claim window), and to AV-224 reallocation (amounts, not claim time); emits `MilestoneClaimExpired` (discriminant 90) carrying the tranche index and the returned amount |
| `append_milestone_tranche(initializer, taker, amount)` (AV-226) | `Funded` | — (no state change; appends one tranche at the end of the plan) | **both** parties must sign (dual-signature governance); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; a plan is required (`InvalidMilestones` without one); the new tranche is carved from the skipped remainder only — `amount` must be positive and must not exceed `skipped_amount()` (`InvalidMilestoneAmendment` otherwise, including at `MAX_MILESTONES` = 8 tranches); the locked amount is unchanged and the skipped remainder decreases by exactly the new amount, so `released + skipped + unsettled` still equals the locked amount; existing tranches keep position and amount, confirmed/settled tranches are untouched, and the appended tranche settles last in order once dual-confirmed; it carries no AV-206 due date and no AV-225 claim deadline; in-place rewrite (no realloc, no rent change — the tranche table is already reserved to 8); emits `MilestoneTrancheAppended` (discriminant 91), all amounts zero |
| `with_funding_start(start_at)` (AV-228) | `Uninitialized` | — (no state change; attaches the funding start window) | opt-in, `Uninitialized`-only; `start_at` is an absolute unix timestamp in seconds, mirroring AV-206 `due_at`; `0` means no window (funding ungated, the with_timelock sentinel convention); while `now < funding_start`, `fund` and `fund_with_slot` refuse with `FundingNotStarted` (code 356) and nothing moves — no state change, no anchor advances; funding exactly at `funding_start` is on time; after the window opens funding semantics are unchanged; orthogonal to `expires_at` (this opens funding, that closes the deal), to the AV-27 slot timelock (that gates release time, this gates funding time), and to AV-59 `extend_expiry` (that moves the deadline, this fixes the start); deliberately not applied to `fund_tranche` / `fund_partial` (those own their own schedules); no indexer event (pre-fund configuration) |
| `adjust_period_amounts(initializer, taker, new_amounts)` (AV-73) | `Uninitialized`/`Activated`/`Funded` | — (no state change; rewrites the per-period table) | **both** the initializer and the taker must sign (dual-signature governance — one party alone or a stranger pair is `Unauthorized`); terminal states and `Disputed` are `InvalidStateTransition`; released periods lock their recorded amounts (the re-split must reaffirm them — `InvalidSubscription` otherwise); new amounts must have the schedule's period count, be all positive, and sum to exactly the locked amount; protocol fees charge on the new amounts at release time (still floored by `fee_cap`); the keeper's `ReleasePeriod` action prices from the live table; emits `SubscriptionAmountsAdjusted` only on an actual change |
| `migrate_schema()` (AV-75; AV-85: chain) | any | — (no state change; stamps the schema version) | initializer **only** (`Unauthorized` otherwise, checked before state validity); a paused escrow fails fast (`Paused`); the gate is a catch-up gate (AV-82: `schema_version < SCHEMA_VERSION` runs — an already-current vault refuses the second call and an unknown future version refuses loudly instead of skipping forward, `InvalidSchemaMigration`, code 140, either way); AV-85: the catch-up is now an explicit N → M step chain — each step re-validates the conservation invariants over the field set it carries (`released <= amount`, `released + skipped <= amount`, `fees_paid <= released`, milestone tranche sum `== amount`, plus `released + penalty_paid <= amount` from the 1 → 2 step on) and any failing step rolls the chain back to the pre-chain snapshot (zero partial migration) — a corrupt vault is refused, never migrated; emits one `SchemaMigrated` per applied step (from == to == the current state, each carrying its from → to versions), always on success; the read-only `migrate_dry_run` previews the step/field plan with zero write impact |
| `initialize_mint(mint)`                     | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `mint` is the base58 SPL mint address — must decode to 32 bytes, zero address rejected) |
| `initialize_mint_allowlist(mints)` (AV-157) | `Uninitialized`| `Uninitialized` | initializer (once, before funding; up to 8 base58 SPL mint addresses — empty list disables the allowlist; `with_mint` thereafter rejects unlisted mints with `MintNotAllowlisted`, code 217) |
| `initialize_governance_delay(delay_secs)` (AV-158) | `Uninitialized`| `Uninitialized` | initializer (once, before funding; the opt-in delay window in seconds for the four dual-signed config changes — `0` is `InvalidGovernanceDelay`, code 220; once set, `update_quorum` / `update_attestors` / `rotate_taker` / `update_payout_allowlist` move only through the propose → delay → execute/cancel protocol) |
| `propose_governance(action)` (AV-158) | any | — (no state change; stages the action) | initializer **or** taker (`Unauthorized` otherwise); records the action + proposer + timestamp; re-proposing replaces a live proposal and restarts the delay clock; a paused escrow fails fast (`Paused`); emits `GovernanceProposed` |
| `execute_governance()` (AV-158) | any | — (applies the staged config change) | initializer **or** taker (`Unauthorized` otherwise); runs only when `now >= proposed_at + governance_delay_secs` (`GovernanceDelayNotElapsed`, code 218, otherwise) and a proposal is live (`GovernanceActionNotProposed`, code 219, otherwise); a paused escrow fails fast (`Paused`); clears the proposal on success; emits `GovernanceExecuted` |
| `cancel_governance()` (AV-158) | any | — (no state change; clears the staged action) | initializer **or** taker (`Unauthorized` otherwise); requires a live proposal (`GovernanceActionNotProposed`, code 219, otherwise); works even while paused (the defensive veto); emits `GovernanceCancelled` |
| `initialize_protocol_fee(fee_bps)`           | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `fee_bps` in 0–10000 basis points; the fee slices every taker payout into net payout + protocol fee; the AV-63 fee cap can floor it per payout) |
| `amend_protocol_fee(initializer, taker, fee_bps, fee_cap)` (AV-233) | `Funded` | — (no state change; rewrites the flat rate and the per-payout cap) | **both** parties must sign (dual-signature governance — one party alone cannot raise the fee on the other's payouts); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; `fee_bps > 10_000` is `InvalidProtocolFee`; a configured tiered schedule rejects the amendment outright (the flat rate and the schedule are mutually exclusive — accepting a flat rate there would silently discard it, and `protocol_fee_for` prices from the schedule whenever one is configured); rate and cap are set atomically and a failed amendment leaves both untouched; only later taker payouts reprice (the new rate floored by the new cap) — `fees_paid` and already-charged fees are never repriced; amendment does not require a pre-existing fee (both parties signing makes a first-time rate a renegotiation, not a surprise cut); the fee recipient is untouched (AV-67 owns the destination, this owns the rate); emits `ProtocolFeeAmended` (discriminant 97), all amounts zero |
| `initialize_fee_cap(max_fee_cents)`           | `Uninitialized`| `Uninitialized` | initializer (once, before funding; absolute per-payout fee ceiling in lamports — the effective fee is `min(bps fee, fee_cap)`; `0` means uncapped; no new error code) |
| `initialize_fee_schedule(tiers)` (AV-66)     | `Uninitialized`| `Uninitialized` | initializer (once, before funding; opt-in volume-priced fee tiers as `(min_amount, bps)` pairs — the fee for a gross payout uses the rate of the highest tier with `min_amount <= amount`, still floored by the AV-63 cap; 1–8 tiers, each `bps` 0–10000, floors strictly ascending; mutually exclusive with the flat rate — fail-fast `InvalidProtocolFee`, code 114, in either direction) |
| `initialize_fee_recipient(fee_recipient)`    | `Uninitialized`| `Uninitialized` | initializer (once, before funding; pins the destination of every fee leg — the settlement builders reject a `fee_leg` that does not equal it; zero address is `InvalidFeeRecipient`; with no pin the fee goes to the program-level fee account) |
| `initialize_pause_authority(pause_authority)` | `Uninitialized`| `Uninitialized` | initializer (once, before funding; binds the key allowed to engage/release the emergency pause; zero address is `InvalidPauseAuthority`) |
| `pause(authority, auto_unpause_at)` (AV-133)   | any            | — (no state change; sets the pause flag) | the bound pause authority only (`Unauthorized` otherwise; `InvalidStateTransition` with no authority bound or when already paused); `auto_unpause_at: Option<u64>` — `Some(t)` arms a scheduled auto-recovery at Unix time `t`, `None` = manual `unpause` only (old semantics); while paused, every clock-bearing state-changing path runs `try_auto_unpause(now)` before the `Paused` gate — at `now >= t` the vault auto-recovers (no authority signature, emits `Unpaused{auto:true}`); emits `Paused` |
| `unpause()`                                   | any            | — (no state change; clears the pause flag) | the bound pause authority only (same rules as `pause`; `InvalidStateTransition` when not paused); emits `Unpaused` |
| `amend_auto_unpause_at(authority, new_at, now)` (AV-287) | any (paused only) | — (no state change; rewrites the scheduled auto-recovery timestamp, or clears it) | the bound pause authority only (`Unauthorized` for a wrong key; `InvalidStateTransition` with no authority bound, when not paused, or when paused with no schedule — a manual pause has no table to revise and a schedule can only be built by `pause`, never installed by revision); an already-expired schedule (`now >= t`) is `InvalidStateTransition` (the matured promise belongs to the next clock-bearing transition's `try_auto_unpause`, which still consumes it afterwards — the revision never consumes it); a new `Some(t)` at or before `now` is `InvalidAutoUnpauseAt` (code 359); an explicit `None` clears the schedule, turning the pause manual (only `unpause` releases it from then on); re-affirming the current moment is a no-op (writes nothing, emits nothing); the pause flag and the pause authority are never touched — the revision never lifts the freeze; the AV-158 governance-delay protocol does not apply (the pause path is an emergency operation, and `pause`/`unpause` themselves are immediate); the new schedule governs from the next clock-bearing transition (`try_auto_unpause` reads the live schedule); emits `AutoUnpauseAtAmended` (discriminant 149), all amounts zero |
| `rotate_pause_authority(new_authority)`       | any (post-`Uninitialized`) | — (no state change; rewrites the bound pause authority) | the escrow authority (initializer) only — a stranger/taker is `Unauthorized`; `InvalidStateTransition` on `Uninitialized` or with no authority bound; zero address is `InvalidPauseAuthority`; works while paused (key-loss escape hatch); emits `PauseAuthorityRotated` only on an actual change |
| `rotate_taker(new_taker)`                   | `Uninitialized`/`Activated`/`Funded` | — (no state change; rewrites the taker) | **both** the initializer and the *current* taker must sign (dual-signature governance — one party alone or a stranger pair is `Unauthorized`); terminal states and `Disputed` are `InvalidStateTransition` (no live counterparty left; arbitration in flight adjudicates the taker's identity); zero address is `InvalidTaker`; amount / released / attest records / milestone state all preserved; emits `TakerRotated` only on an actual change |
| `rotate_initializer(new_initializer)`      | `Uninitialized`/`Activated`/`Funded` | — (no state change; rewrites the initializer) | **both** the *current* initializer and the taker must sign (dual-signature governance — the mirror of `rotate_taker`; degenerate initializer == taker self-escrow authorizes with one key passed twice); terminal states and `Disputed` are `InvalidStateTransition` (arbitration in flight adjudicates the initializer's identity — the refund goes to the initializer); zero address is `InvalidInitializer`; on an actual change the initializer's activation signature bit is cleared (the new key never signed activation); the AV-23 whitelist pins the refund destination when configured, otherwise refunds resolve to the new initializer (keeper/snapshot follow automatically); emits `InitializerRotated` only on an actual change |
| `rotate_arbiter(new_arbiter)`                | `Uninitialized`/`Activated`/`Funded` | — (no state change; rewrites the arbiter) | **both** the *current* initializer and the *current* taker must sign (dual-signature governance — the mirror of `rotate_initializer` for the arbitration role; the arbiter itself does not sign, so a lost arbiter key cannot block its own replacement; degenerate initializer == taker self-escrow authorizes with one key passed twice); terminal states and `Disputed` are `InvalidStateTransition` (no live dispute path left to referee, and arbitration in flight must settle with the referee that heard it); a configured panel is `InvalidStateTransition` too (single-arbiter governance only — rotate the panel via `initialize_arbiter_panel`); no arbiter configured or the zero address is `InvalidArbiter`; the activation bitmask is untouched (it tracks only the initializer and taker); the keeper's `resolve` listing and the snapshot export read the live arbiter field (follow automatically); emits `ArbiterRotated` only on an actual change |
| `rotate_milestone_verifier(initializer, taker, new_verifier)` (AV-234) | `Funded` | — (no state change; rewrites the milestone verifier) | **both** parties must sign (dual-signature governance — one party alone cannot swap the gatekeeper on the other's milestones); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; no verifier configured, the zero address, or a rotation to the current verifier are all `InvalidMilestoneVerifier` (code 323) — rotation never creates the gate (`with_milestone_verifier` is the `Uninitialized`-only initial set) and a no-change rotation is rejected, not silently accepted; every failure leaves the stored verifier untouched; unused attestations signed by the old verifier stop verifying the moment the key changes (attestation checks read the live key) while attestations signed by the new verifier verify, and already-settled tranches are untouched; orthogonal to `rotate_arbiter` / `rotate_taker` (different roles); emits `MilestoneVerifierRotated` (discriminant 98), all amounts zero |
| `rotate_dual_control_checker(initializer, taker, new_checker)` (AV-263) | `Funded` | — (no state change; rewrites the dual-control checker key) | **both** parties must sign (dual-signature governance — one party alone cannot swap the approver on the other's release; the checker itself does not sign, so a lost checker key cannot block its own replacement, the `rotate_arbiter` reasoning); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow that already opted into dual control may rotate — a never-opted-in escrow is `InvalidDualControl` (fail-closed: post-funding installation would turn a single-step release into a two-step protocol the taker never funded under); a zero `new_checker` is `InvalidDualControl` (the builder's gate, unchanged — a zero key can never be a legitimate checker); a live dual-control intent blocks the rotation with `DualControlIntentExists` (the intent stores no checker key and `confirm_release` authenticates against the live checker, so rotating mid-flight would hand an unseen declaration to a checker who never saw it — confirm, cancel, or let it expire first); a paused escrow fails fast (`Paused`); rotating to the current checker is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); the 33-byte checker region is already resident, so the rotation rewrites it in place with no layout change; the two-step protocol reads the checker live, so the new checker governs from the next `initiate` / `confirm` cycle with no approval-power transfer ever in flight, while a declaration already settled keeps the checker it settled under; orthogonal to the `with_dual_control` builder (`Uninitialized`-only initial configuration), to `rotate_arbiter` / `rotate_milestone_verifier` (those are other roles, this item is the dual-control checker) and to `initiate_release` / `confirm_release` (those are the two-step protocol itself, this item is the checker's identity); emits `DualControlCheckerRotated` (discriminant 126), all amounts zero, except for the no-op re-affirmation |
| `rotate_credential_issuer(initializer, taker, new_issuer)` (AV-264) | `Funded` | — (no state change; rewrites the credential-gate issuer key) | **both** parties must sign (dual-signature governance — one party alone cannot swap the compliance issuer on the other's release; the issuer itself does not sign, so a lost issuer key cannot block its own replacement, the `rotate_arbiter` reasoning); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow that already bound a credential gate may rotate — a never-bound escrow is `CredentialGateNotBound` (fail-closed: post-funding installation would add a release qualification the taker never funded under); a zero `new_issuer` is `InvalidCredentialIssuer` (the builder's gate, unchanged — a zero key can never be a legitimate issuer); a paused escrow fails fast (`Paused`); rotating to the current issuer is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); the 32-byte issuer region is already resident, so the rotation rewrites it in place with no layout change; the credential gate reads the issuer live, so the new issuer governs from the next `release_with_credential` — and a credential minted by the old issuer stops verifying the moment the rotation lands, even if never used, and must be re-signed by the new issuer — while a release already settled keeps the issuer it settled under; orthogonal to the `with_credential_gate` builder (`Uninitialized`-only initial binding) and to AV-212 (that is the credential-gate mechanism itself, this item is the issuer's identity); emits `CredentialIssuerRotated` (discriminant 127), all amounts zero, except for the no-op re-affirmation |
| `amend_deadman_inactivity(initializer, taker, inactivity_secs)` (AV-265) | `Funded` | — (no state change; rewrites the dead-man's switch inactivity threshold) | **both** parties must sign (dual-signature governance — one party alone cannot move the recovery clock on the other's funds; the heir itself does not sign, so a lost heir key cannot block its own threshold's revision, the `rotate_arbiter` reasoning); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow whose switch is already configured (non-zero threshold *and* a set heir) may revise — an unconfigured escrow is `InvalidDeadmanConfig` (fail-closed: post-funding installation would add a recovery path the taker never funded under); a zero `inactivity_secs` is `InvalidDeadmanConfig` (the builder's gate, unchanged — a zero threshold would make the switch claimable immediately); a paused escrow fails fast (`Paused`); revising to the current threshold is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `deadman_inactivity_secs` changes — `deadman_heir` and `deadman_last_activity` are untouched, since the revision takes no clock parameter and never resets the inactivity timer; the eligibility gate reads the threshold live, so the new threshold governs from the next `claim_deadman` — tightening can make an already-idle escrow eligible at once (the elapsed time is re-judged, not restated) while loosening can revoke an already-satisfied but unexecuted eligibility, and a claim already settled keeps the threshold it settled under; orthogonal to the `with_deadman_switch` builder (`Uninitialized`-only initial configuration) and to AV-109 (that is the dead-man's switch mechanism itself, this item is its threshold); emits `DeadmanInactivityAmended` (discriminant 128), all amounts zero, except for the no-op re-affirmation |
| `amend_keeper_bounty_per_crank(initializer, taker, per_crank)` (AV-266) | `Funded` | — (no state change; rewrites the keeper-bounty per-crank amount) | **both** parties must sign (dual-signature governance — one party alone cannot reprice the keeper incentive on the other's funds); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow with a non-zero `keeper_bounty_per_crank` may revise — an escrow with a zero per-crank amount is `InvalidKeeperBounty` (code 357, fail-closed: post-funding installation would add a bounty the taker never funded under, and this covers the `with_keeper_bounty(pool, 0)` disabled shape too); a zero `per_crank` is a legal revision that closes future payouts (the builder's 0-means-no-bounty semantics, unchanged), and closing is final through this path (a closed escrow reads as unconfigured, so reopening is refused fail-closed); a paused escrow fails fast (`Paused`); revising to the current amount is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `keeper_bounty_per_crank` changes — `keeper_bounty_pool` is untouched (the pool is a consumable balance, the revision never tops it up) and bounty already paid is untouched, so an exhausted pool still pays `0` after any revision and the revision itself never revives the bounty; the payout path reads the amount live (`keeper_bounty_payable() = min(per_crank, pool)` at payment time), so the new amount governs from the next `crank_expired` — raising it raises the next payout up to the pool, lowering it lowers the next payout, and a crank already settled keeps the amount it settled under; orthogonal to AV-124 (that is the bounty mechanism itself, this item is its per-crank amount) and to AV-48 (that is `crank_expired` itself, this item is the amount); emits `KeeperBountyPerCrankAmended` (discriminant 129), all amounts zero, except for the no-op re-affirmation |
| `amend_slash_deadline(initializer, taker, deadline)` (AV-267) | `Funded` | — (no state change; rewrites the flat slash terms' deadline) | **both** parties must sign (dual-signature governance — one party alone cannot move the default penalty's trigger on the other's funds); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow carrying flat slash terms may revise — an escrow with no terms is `SlashNotEligible` (fail-closed: post-funding installation would add a penalty clause the taker never funded under); a ladder escrow is `InvalidSlashLadder` (its deadlines live in the rung table and belong to `amend_slash_ladder`, so a flat revision here would create a second competing deadline); an escrow whose one-shot slash already executed (`penalty_paid > 0`, or `pool_slashed > 0` on the AV-106 insurance-pool path) is `SlashNotEligible` (the one-shot is consumed, so a revised deadline has no slash left to govern); a zero `deadline` is legal and means immediately slashable (the builder's semantics, unchanged); a paused escrow fails fast (`Paused`); revising to the current deadline is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `slash_terms.slash_deadline` changes — `penalty_account` and `penalty_paid` already banked are untouched (a revision never restates a settled penalty); the slash path reads the deadline live (`now >= slash_deadline`), so the new deadline governs from the next eligibility check — tightening can make an unexecuted default slashable at once while loosening can defer an already-satisfied but unexecuted eligibility, and a slash already settled keeps the deadline it settled under; orthogonal to AV-82 (that is the slash mechanism itself, this item is its deadline) and to AV-237 (that is the ladder-table revision, this item is the flat deadline); emits `SlashDeadlineAmended` (discriminant 130), all amounts zero, except for the no-op re-affirmation |
| `amend_amount_bounds(initializer, taker, min_amount, max_amount)` (AV-268) | `Funded` | — (no state change; rewrites `min_funding_amount` / `max_funding_amount` in place) | **both** parties must sign (dual-signature governance — one party alone cannot move the deposit window on the other's funds); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow already carrying a window may revise — an escrow with no window is `InvalidAmountBounds` (code 196, fail-closed: post-funding installation would add a deposit gate the taker never funded under, so a window can never be installed after funding); the whole pair is replaced at once (no partial revision) and `min_amount > max_amount` is `InvalidAmountBounds` (the `with_amount_bounds` gate, unchanged) leaving the original window untouched; a paused escrow fails fast (`Paused`); revising to the current window is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only the window fields change — `funded_total` and the funding plan's total and tranche budget are untouched (the window caps each tranche, it never reschedules the plan); the tranche path reads the live window at each `fund_tranche` call, so the new window governs from the next deposit while tranches already funded keep the window they funded under; orthogonal to `with_amount_bounds` (that is the `Uninitialized`-only initial set, this item is the post-funding revision), to `update_release_cap` (that is the single-release ceiling, this item is the funding window), and to the funding plan itself (that is the tranche schedule, this item is the per-tranche amount window); emits `AmountBoundsAmended` (discriminant 131), all amounts zero, except for the no-op re-affirmation |
| `amend_milestone_late_penalty_bps(initializer, taker, bps)` (AV-269) | `Funded` | — (no state change; rewrites `milestone_late_penalty_bps` in place) | **both** parties must sign (dual-signature governance — one party alone cannot move the lateness price on the other's funds); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow that already has a milestone due-date table may revise — it must carry a milestone plan and every tranche must already have a due date attached (a stored `0` means never attached, the AV-206 sentinel), otherwise `InvalidMilestones` (code 110, fail-closed: post-funding installation would add a forfeiture term the taker never funded under, so penalty semantics can never be installed on a table-less escrow after funding); the new rate reuses `validate_late_penalty_bps` (the `with_late_penalty_bps` gate, unchanged) — above 10_000 bps is `InvalidPenalty` leaving the original rate untouched, and `0` is legal (it switches future late penalties off); a paused escrow fails fast (`Paused`); revising to the current rate is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `milestone_late_penalty_bps` changes — the `milestone_due_dates` table is untouched and `penalty_paid` already banked is never restated (a settled tranche keeps the rate it settled under); the release path reads the live rate at release time (`late_penalty_for`), so the new rate governs from the next `release_milestone` late pricing while settled tranches are never recalculated; orthogonal to `with_late_penalty_bps` (that is the `Uninitialized`-only initial set, this item is the post-funding revision), to `amend_milestone_due_dates` (that is the deadline table, this item is the rate priced against it), to `amend_late_delivery_penalty_bps` (that is the delivery-confirmation late penalty, priced after this one), and to `amend_penalty_bps` (that is the generic expiry penalty rate, not the milestone lateness price); emits `MilestoneLatePenaltyBpsAmended` (discriminant 132), all amounts zero, except for the no-op re-affirmation |
| `amend_funding_plan_max_tranches(initializer, taker, max_tranches)` (AV-270) | `Funded` | — (no state change; rewrites the funding plan's `max_tranches` in place) | **both** parties must sign (dual-signature governance — one party alone cannot move the tranche budget on the other's funds); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow already carrying a funding plan may revise — an escrow with no plan is `InvalidFundingPlan` (code 173, fail-closed: post-funding installation would add a staged-deposit schedule the taker never funded under, so a tranched plan can never be installed after funding); the new budget reuses the `FundingPlan::new` gate, unchanged — `0` is `InvalidFundingPlan`, and a budget below `tranches_used` is refused with the same error (shrinking below the consumed count would un-consume a funded tranche), leaving the original plan untouched; a paused escrow fails fast (`Paused`); revising to the current budget is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `max_tranches` changes — `total_amount` stays pinned to the escrow's `amount` (the plan total is fixed at initial set and a post-funding total revision has no semantics) and `funded_total` and `tranches_used` are untouched (the plan is rebuilt with `FundingPlan::from_parts` preserving the consumed count); the tranche path reads the live budget at each `fund_tranche` call, so raising it opens further tranches and shrinking it to `tranches_used` exhausts the plan exactly like natural exhaustion (the next tranche is `FundingTranchesExhausted`, code 172) while tranches already funded keep the budget they funded under; orthogonal to `with_funding_plan` (that is the `Uninitialized`-only initial set, this item is the post-funding revision) and to `amend_amount_bounds` (that is the per-tranche amount window, this item is the tranche budget); emits `FundingPlanMaxTranchesAmended` (discriminant 133), all amounts zero, except for the no-op re-affirmation |
| `rotate_deadman_heir(initializer, taker, new_heir)` (AV-271) | `Funded` | — (no state change; rewrites `deadman_heir` in place) | **both** parties must sign (dual-signature governance — one party alone cannot redirect the inactivity recovery on the other's funds; the heir itself does not sign, so a lost heir key never blocks its own replacement, paralleling `rotate_dual_control_checker`); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow whose dead-man's switch is already configured (`is_deadman_configured`: non-zero threshold and a set heir) may rotate — an unconfigured escrow is `InvalidDeadmanConfig` (code 168, fail-closed: post-funding installation would add a recovery path the taker never funded under, so a switch can never be installed after funding); a zero `new_heir` is `InvalidDeadmanConfig` (the `with_deadman_switch` gate, unchanged) leaving the original heir untouched; a paused escrow fails fast (`Paused`); rotating to the current heir is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `deadman_heir` changes — `deadman_inactivity_secs` and `deadman_last_activity` are untouched (the rotation takes no clock and never resets the inactivity timer, so the elapsed time since the last real activity is preserved and re-judged against the same threshold under the new heir); the claim path reads the live heir at each `claim_deadman` call, so the new heir governs from the next claim — the old heir is `Unauthorized` at once while the new heir may claim once the inactivity period has elapsed, and a claim already settled keeps the heir it settled under; orthogonal to `with_deadman_switch` (that is the `Uninitialized`-only initial set, this item is the post-funding rotation) and to `amend_deadman_inactivity` (that is the inactivity threshold, this item is the heir); emits `DeadmanHeirRotated` (discriminant 134), all amounts zero, except for the no-op re-affirmation |
| `rotate_slash_penalty_account(initializer, taker, new_penalty_account)` (AV-272) | `Funded` | — (no state change; rewrites `slash_terms.penalty_account` in place) | **both** parties must sign (dual-signature governance — one party alone cannot redirect the default penalty on the other's funds); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow carrying flat slash terms may rotate — an escrow with no terms is `SlashNotEligible` (code 143, fail-closed: post-funding installation would add a penalty clause the taker never funded under, so terms can never be installed after funding); a ladder escrow is `InvalidSlashLadder` (code 184, its penalty account lives in the independent ladder structure and belongs to a future ladder-specific rotation, so a flat rotation here would create a second competing penalty account); an insurance-pool escrow is `SlashNotEligible` (its slash routes to the neutral pool custody, so the flat `penalty_account` is a dead field and rotating it has no semantics); an escrow whose one-shot slash already executed (`penalty_paid > 0`, or `pool_slashed > 0` on the AV-106 insurance-pool path) is `SlashNotEligible` (the one-shot is consumed, so a rotated account has no slash left to govern); a zero `new_penalty_account` is `SlashNotEligible` (the `with_slash_terms` gate, unchanged) leaving the original account untouched; a paused escrow fails fast (`Paused`); rotating to the current account is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `slash_terms.penalty_account` changes — `slash_deadline` and `penalty_paid` already banked are untouched (a rotation never restates a settled penalty); the Anchor layer transfers the next slash to the live `penalty_account` read from the terms, so a default penalized after the rotation pays the new account while the pool path is unaffected and a slash already settled keeps the account it settled under; orthogonal to `with_slash_terms` (that is the `Uninitialized`-only initial set, this item is the post-funding rotation), to `amend_slash_deadline` (that is the flat deadline, this item is the recipient account) and to `amend_slash_ladder` (that is the ladder table, this item is the flat account); emits `SlashPenaltyAccountRotated` (discriminant 135), all amounts zero, except for the no-op re-affirmation |
| `amend_fee_cap(initializer, taker, fee_cap)` (AV-273) | `Funded` | — (no state change; rewrites `fee_cap` in place) | **both** parties must sign (dual-signature governance — one party alone cannot move the fee ceiling on the other's payouts); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow already carrying a ceiling may revise — an uncapped escrow is `InvalidProtocolFee` (code 114, fail-closed: post-funding installation would add a fee term the taker never funded under, so a ceiling can never be installed after funding); any `u64` is a legal new ceiling and `0` is legal (it removes the cap outright, so later bps fees are no longer floored — and the removal is one-way post-funding, since a cap-less escrow fails the same gate on any later amendment); a paused escrow fails fast (`Paused`); revising to the current ceiling is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `fee_cap` changes — `fee_bps`, `fee_schedule` and `fees_paid` / `fees_withdrawn` are untouched and fees already charged are never restated; `protocol_fee_for` reads the live ceiling at every pricing (`min(bps fee, cap)`), so the new ceiling governs the next taker payout on all five funding paths (`release` / `claim` / `release_milestone` / `resolve`-taker / `release_period`) and the keeper / batch previews that call it directly, on flat-rate and tiered-schedule escrows alike; orthogonal to `with_fee_cap` (that is the `Uninitialized`-only initial set, this item is the post-funding revision), to `amend_protocol_fee` (that is the flat rate, this item is the absolute ceiling), to `amend_fee_schedule` (that is the tier table, this item is the ceiling that floors it) and to `rotate_fee_recipient` (that is the fee destination, this item is the ceiling); emits `FeeCapAmended` (discriminant 136), all amounts zero, except for the no-op re-affirmation |
| `rotate_slash_ladder_penalty_account(initializer, taker, new_penalty_account)` (AV-274) | `Funded` | — (no state change; rewrites `slash_ladder.penalty_account` in place) | **both** parties must sign (dual-signature governance — one party alone cannot redirect the ladder default penalty on the other's funds); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow carrying a ladder may rotate — an escrow with no ladder (plain, or flat-terms) is `InvalidSlashLadder` (code 184, fail-closed: post-funding installation would add a penalty clause the taker never funded under, so a ladder can never be installed after funding, and a flat escrow's account belongs to the AV-272 path); an insurance-pool escrow is `SlashNotEligible` (code 143, its slash routes to the neutral pool custody, so the ladder `penalty_account` is a dead field and rotating it has no semantics); a zero `new_penalty_account` is `InvalidSlashLadder` (the `with_slash_ladder` gate, unchanged) leaving the original account untouched; a paused escrow fails fast (`Paused`); rotating to the current account is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `slash_ladder.penalty_account` changes — the rung table, `rung_count` and the consumption cursor are untouched (the cursor is deliberately not reset) and `penalty_paid` / `pool_slashed` already banked are never restated (a rotation never rewrites a settled penalty); unlike AV-272's one-shot, an already-slashed ladder stays rotatable, since the ladder is the repeated-slash path and the top rung is reused once exhausted, so a rotated account still governs real future enforcement; the Anchor layer transfers the next ladder slash to the live `penalty_account` read from the ladder, so a default penalized after the rotation pays the new account while the pool path is unaffected and a slash already settled keeps the account it settled under; orthogonal to `with_slash_ladder` (that is the `Uninitialized`-only initial set, this item is the post-funding rotation), to `rotate_slash_penalty_account` (AV-272, that is the flat account, this item is the ladder account) and to `amend_slash_ladder` (that is the ladder table, which expressly preserves `old.penalty_account`, this item is the recipient account); emits `SlashLadderPenaltyAccountRotated` (discriminant 137), all amounts zero, except for the no-op re-affirmation |
| `rotate_social_recovery_guardian(initializer, taker, old_guardian, new_guardian)` (AV-275) | `Funded` | — (no state change; rewrites one `recovery.guardians` slot in place) | **both** parties must sign (dual-signature governance — one party alone cannot redirect the lost-key recovery on the other's funds; the guardian being replaced does not sign, so a lost guardian key never blocks its own replacement, paralleling `rotate_deadman_heir`); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow with a configured social-recovery policy may rotate — an unconfigured escrow is `RecoveryNotConfigured` (code 287, fail-closed: post-funding installation would add a recovery path the taker never funded under, so a policy can never be installed after funding); a pending recovery request is `RecoveryRequestPending` (code 289, the approval bitmap is indexed by slot, so swapping a slot would re-attribute already-cast approval votes); an unknown `old_guardian` is `RecoveryNotGuardian` (code 288); a zero `new_guardian`, or one duplicating another slot, is `InvalidSocialRecovery` (code 286, the `SocialRecovery::new` gate, unchanged) leaving the original guardian untouched; a paused escrow fails fast (`Paused`); rotating to the current guardian is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only that one slot changes — `guardian_count`, `threshold` and `timelock_secs` are untouched and `pending` stays empty; the recovery path compares against the live slot guardian at each `request_recovery` / `approve_recovery` call, so the new guardian governs from the next request — the old guardian is `RecoveryNotGuardian` at once while the new guardian may open and approve, and a request already settled keeps the guardians it settled under; orthogonal to `with_social_recovery` (that is the `Uninitialized`-only initial set, this item is the post-funding rotation), to AV-195 (that is the recovery mechanism itself, this item is one of its guardians) and to `rotate_initializer` (that is the parties themselves, not guardians); emits `SocialRecoveryGuardianRotated` (discriminant 138), all amounts zero, except for the no-op re-affirmation |
| `update_settlement_mint_allowlist(initializer, taker, mints)` (AV-276) | `Funded` | — (no state change; rewrites `settlement_mint_allowlist` in place) | on a dual-sig escrow **both** parties must sign (dual-signature governance — one party alone cannot reshape which currencies the other's share may settle in, paralleling `update_payout_allowlist`); on a plain escrow the initializer alone authorizes; `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); on a delay-opted-in escrow the direct call is refused (`GovernanceActionNotProposed` — the allowlist moves only through the AV-158 propose/execute protocol, mirroring `update_payout_allowlist_impl`); an empty list clears back to `None` (the AV-157 convention); a non-empty list is validated by `SettlementMintAllowlist::new` (more than 8 entries, a zero address, or a duplicate is `InvalidSettlementMintAllowlist`, code 349, leaving the original list untouched); unlike the scalar amends, setting, replacing, or clearing are all allowed under governance — no 'already configured' gate (an escrow that never configured a list may set its first one here); a paused escrow fails fast (`Paused`); revising to the current list is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `settlement_mint_allowlist` changes — the bound `settlement_mint` and any settled release already made are untouched, and plain `release` is unaffected; the new list governs from the next `release_with_settlement_rate` (that path reads the live list before rate verification and conversion pricing, so a mint removed here is refused at once while a mint added here settles from the next quote); orthogonal to `with_settlement_mint_allowlist` (that is the `Uninitialized`-only initial set, this item is the post-funding revision), to AV-218 (that is the allowlist mechanism itself, this item is the list's revision) and to `update_payout_allowlist` / `update_cpi_allowlist` (those are the taker-payout and CPI-target allowlists, this item is the settlement-currency allowlist); emits `SettlementMintAllowlistUpdated` (discriminant 139), all amounts zero, except for the no-op re-affirmation |
| `amend_dutch_auction_reserve_bps(initializer, taker, new_reserve_bps, now)` (AV-277) | `Funded` | — (no state change; rewrites `auction.reserve_bps` in place) | **both** parties must sign (dual-signature governance — one party alone cannot move the floor on the other's share, paralleling `amend_fee_cap`); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow already carrying an auction may revise — an auction-less escrow is `InvalidAuctionParams` (code 155, fail-closed: post-funding installation would add a pricing curve the taker never funded under, so an auction can never be installed after funding); only before the window opens (`now < start_at`) may the floor move — at the open, live, or after the close the revision is `AuctionNotActive` (code 156, changing the floor mid-window would re-price claims already in flight, and the original floor stands for claims already priced); the new floor reuses the `DutchAuction::new` gate (`> 10_000` is `InvalidAuctionParams`, code 155, leaving the original floor untouched); a paused escrow fails fast (`Paused`); revising to the current floor is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `reserve_bps` changes — `start_at` and `end_at` are untouched, so the window does not move (and the `escalate` mutual exclusion and `is_live` semantics are unchanged); the new floor governs from the next `claim` (`payout_cap` reads the live auction at every call, `max(linear, reserve_floor)`, so a claim after the amendment prices against the new floor while a claim already settled keeps the cap it settled under); orthogonal to `with_dutch_auction` (that is the `Uninitialized`-only initial set, this item is the post-funding revision) and to AV-97 (that is the auction mechanism itself, this item is the floor's revision); emits `DutchAuctionReserveBpsAmended` (discriminant 140), all amounts zero, except for the no-op re-affirmation |
| `amend_dutch_auction_window(initializer, taker, new_start_at, new_end_at, now)` (AV-288) | `Funded` | — (no state change; rewrites `auction.start_at`/`end_at` in place) | **both** parties must sign (dual-signature governance — one party alone cannot move the window on the other's share, paralleling `amend_dutch_auction_reserve_bps`); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow already carrying an auction may revise — an auction-less escrow is `InvalidAuctionParams` (code 155, fail-closed: post-funding installation would add a pricing curve the taker never funded under, so an auction can never be installed after funding); only before the window opens may the window move — both `now <` the current `start_at` and `now <` the new `start_at` must hold, else `AuctionNotActive` (code 156: a window that already opened would re-price claims already in flight, and a new window that already opened would rewrite the `escalate` mutual exclusion mid-flight, so the whole window freezes once either side opens); the new window reuses the `DutchAuction::new` gate (`new_start_at >= new_end_at` is `InvalidAuctionParams`, code 155, leaving the original window untouched, with the current reserve floor carried along for re-validation); a paused escrow fails fast (`Paused`); on a governance-delay-opted-in escrow the direct call is refused (`GovernanceActionNotProposed`) — the window moves only through the propose/execute protocol, with no new proposal variant (AV-281 precedent); revising to the current window is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `start_at`/`end_at` change — `reserve_bps` is untouched, so the window and the floor stay orthogonal (the floor moves via AV-277, the window here); the new window governs from the next `claim` (`payout_cap` reads the live auction at every call — `is_live` and the linear decay both follow the new window — so a claim after the amendment prices against the new window while a claim already settled keeps the cap it settled under, and the `escalate` mutual exclusion follows the new window the same way); orthogonal to `with_dutch_auction` (that is the `Uninitialized`-only initial set, this item is the post-funding revision) and to AV-277 (that is the floor, this item is the window); emits `DutchAuctionWindowAmended` (discriminant 150), all amounts zero, except for the no-op re-affirmation |
| `amend_subscription_period_secs(initializer, taker, new_period_secs)` (AV-289) | `Funded` | — (no state change; rewrites `subscription.period_secs` in place) | **both** parties must sign (dual-signature governance — one party alone cannot move the cadence on the other's share, paralleling `amend_dutch_auction_window`); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow with a subscription plan already configured may revise — an unconfigured escrow is `InvalidSubscription` (code 130, fail-closed: post-funding installation would add a payout schedule the taker never funded under, so a plan can never be installed after funding); the new period reuses the `with_subscription` gates (a zero period is `InvalidSubscription`, code 130, and if `(periods - 1) * new_period_secs > expires_at` the plan would overflow the escrow lifetime, so the revision is refused with the same error, leaving the original period untouched); a paused escrow fails fast (`Paused`); on a governance-delay-opted-in escrow the direct call is refused (`GovernanceActionNotProposed`) — the cadence moves only through the propose/execute protocol, with no new proposal variant (AV-281 precedent); revising to the current period is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `subscription.period_secs` changes — `periods`, `per_period`, the amount conservation (`periods * per_period == amount`, the period count being independent of cadence), `subscription_next` and `subscription_released` are untouched (already-released periods are history only); the new period takes effect from the next claim (`subscription_period_due_at` / `SubscriptionSchedule::due_at` read the live `period_secs`, so due dates of unreleased periods move with the new cadence when computed backwards from `expires_at`, with the last period pinned to `expires_at`, while a period already released keeps the due date it released under); orthogonal to `with_subscription` (that is the `Uninitialized`-only initial set, this item is the post-funding revision) and to AV-73 (that is the per-period amount redistribution, this item is the cadence); emits `SubscriptionPeriodSecsAmended` (discriminant 151), all amounts zero, except for the no-op re-affirmation |
| `amend_vesting_curve(initializer, taker, curve, now)` (AV-290) | `Funded` | — (no state change; rewrites `vesting_curve` in place) | **both** parties must sign (dual-signature governance — one party alone cannot rewrite the unlock timeline on the other's share, paralleling `amend_vesting_schedule`); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow with a curve already configured may revise — a curve-less escrow is `InvalidVesting` (fail-closed: post-funding installation would price the unlock under a shape the taker never funded under, so a curve can never be installed after funding); the new curve's tier window must fall inside the live schedule's `[start, end]` (the `with_vesting_curve` attach gate, judged against the live schedule, via `InvalidVestingCurve`, code 147, leaving the original curve untouched); the anti-clawback floor mirrors `amend_vesting_schedule` (the new curve priced at `now` over the live schedule must vest at least what the taker already claimed, via `InvalidVesting`, with the AV-51 cliff gating inside the pricing); a paused escrow fails fast (`Paused`); on a governance-delay-opted-in escrow the direct call is refused (`GovernanceActionNotProposed`) — the curve moves only through the propose/execute protocol, with no new proposal variant (AV-281 precedent); revising to the current curve is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `vesting_curve` changes — the linear schedule table, the cliff, and the locked amount are untouched, so the new shape governs from the next `claim` (`claim`/`claimable_amount` price through the live curve at every call, while an amount already claimed keeps the shape it settled under); orthogonal to `with_vesting_curve` (that is the `Uninitialized`-only initial set, this item is the post-funding revision) and to `amend_vesting_schedule` (that is the linear table, this item is the shape); emits `VestingCurveAmended` (discriminant 152), all amounts zero, except for the no-op re-affirmation |
| `amend_payout_split_shares(initializer, taker, new_shares, now)` (AV-293) | `Funded` | — (no state change; rewrites the split share amounts in place) | **both** parties must sign (dual-signature governance — one party alone cannot rewrite the distribution of the other's share, paralleling `amend_vesting_curve`); a due pause schedule lifts first (`try_auto_unpause`) and a paused escrow fails fast (`Paused`); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow with a split table already configured may revise — a table-less escrow is `InvalidPayoutSplit` (code 167, fail-closed: post-funding installation would add a distribution the taker never funded under, so a table can never be installed after funding); only a table whose recipients are all within `{initializer, taker}` may move — a table naming any third-party recipient is `InvalidPayoutSplit` (a third party's share is not the two signers' to dispose of by dual signature alone); a milestone plan or a subscription schedule owns the release path, so an escrow carrying either is refused with `InvalidMilestones` / `InvalidSubscription` (mirroring `release_payout_split`: on such an escrow the table never settles, so revising it would be meaningless); `released` must still be zero — a partially settled escrow (a vesting claim already pulled part of the lockup while the state stays `Funded`) is `InvalidPayoutSplit`, since rebalancing over an amount that already moved would restate settled funds; the new table reuses the `PayoutSplit::new` gates (non-empty, at most 8 entries, no zero recipient, no zero share, no duplicate recipient, and a Σ that equals the locked amount exactly, via `InvalidPayoutSplit`, code 167, leaving the original table untouched); only the shares move — the new table's recipients, in table order, must equal the current table's recipients exactly, since swapping a recipient would redirect funds and even reordering would move the flooring dust's first-leg landing (`InvalidPayoutSplit`); on a governance-delay-opted-in escrow the direct call is refused (`GovernanceActionNotProposed`) — the shares move only through the propose/execute protocol, with no new proposal variant (AV-281 precedent); revising to the current shares is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only the share amounts change — the recipient set and order, the locked amount, and the state are untouched, so the new shares govern from the next `release_payout_split` (which reads the live table at every call: the net legs prorate over the live shares, so a release after the amendment pays the new split while a release already settled keeps the shares it settled under); orthogonal to `with_payout_split` (that is the `Uninitialized`-only initial set, this item is the post-funding revision) and to `release_payout_split` (that is the settlement, this item is the rebalance); emits `PayoutSplitSharesAmended` (discriminant 153), all amounts zero, except for the no-op re-affirmation |
| `amend_social_recovery_threshold(initializer, taker, new_threshold)` (AV-278) | `Funded` | — (no state change; rewrites `recovery.threshold` in place) | on a dual-sig escrow **both** parties must sign (dual-signature governance — one party alone cannot move the lost-key quorum on the other's funds, paralleling `update_settlement_mint_allowlist`); on a plain escrow the initializer alone authorizes (the AV-276 signature gate); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow with a configured social-recovery policy may amend — an unconfigured escrow is `RecoveryNotConfigured` (code 287, fail-closed: post-funding installation would add a recovery path the taker never funded under, so a policy can never be installed after funding); a pending recovery request is `RecoveryRequestPending` (code 289, in-flight requests count under the old threshold, so changing it would reinterpret already-cast approval votes); the new threshold reuses the `SocialRecovery::new` gate (`1..=guardian_count`, otherwise `InvalidSocialRecovery`, code 286) leaving the original threshold untouched; a paused escrow fails fast (`Paused`); amending to the current threshold is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only the threshold changes — `guardians`, `guardian_count` and `timelock_secs` are untouched and `pending` stays empty; the new threshold governs from the next `request_recovery` — the recovery path compares the live approval count against the live threshold at each `execute_recovery`, so a request opened after the amendment arms and executes under the new threshold while a request already settled keeps the threshold it settled under; orthogonal to AV-275 (that is the guardian slots, this item is the threshold) and to `with_social_recovery` (that is the `Uninitialized`-only initial set, this item is the post-funding revision); emits `SocialRecoveryThresholdAmended` (discriminant 141), all amounts zero, except for the no-op re-affirmation |
| `amend_social_recovery_timelock(initializer, taker, new_timelock_secs)` (AV-279) | `Funded` | — (no state change; rewrites `recovery.timelock_secs` in place) | on a dual-sig escrow **both** parties must sign (dual-signature governance — one party alone cannot move the lost-key veto window on the other's funds, paralleling `update_settlement_mint_allowlist`); on a plain escrow the initializer alone authorizes (the AV-276 signature gate); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only an escrow with a configured social-recovery policy may amend — an unconfigured escrow is `RecoveryNotConfigured` (code 287, fail-closed: post-funding installation would add a recovery path the taker never funded under, so a policy can never be installed after funding); a pending recovery request is `RecoveryRequestPending` (code 289, the in-flight request's veto window already started under the old timelock, so changing it would re-time the remaining wait); the new timelock reuses the `SocialRecovery::new` gate (any value is valid, including zero — the veto window is then only the approval latency, the initializer opting out of the delay deliberately — so no value is refused by the gate); a paused escrow fails fast (`Paused`); amending to the current timelock is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only the timelock changes — `guardians`, `guardian_count` and `threshold` are untouched and `pending` stays empty; the new timelock governs from the next `request_recovery` — the recovery path compares the live timelock against the request's opening timestamp at each `execute_recovery`, so a request opened after the amendment arms and executes under the new veto window while a request already settled keeps the window it settled under; orthogonal to AV-278 (that is the threshold, this item is the veto window) and to `with_social_recovery` (that is the `Uninitialized`-only initial set, this item is the post-funding revision); emits `SocialRecoveryTimelockAmended` (discriminant 142), all amounts zero, except for the no-op re-affirmation |
| `update_tiered_quorum(initializer, taker, tiers)` (AV-280) | `Funded` | — (no state change; rewrites `tiered_quorum.tiers`/`tier_count` in place) | **both** parties must sign (unconditional dual-signature governance — the tier table is quorum policy, so the `update_quorum` rule applies, not the conditional AV-276 gate: one party alone cannot reshape the release gate on the other's funds); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial table); only an escrow with a configured tiered quorum may amend — an unconfigured escrow is `InvalidQuorum` (fail-closed: post-funding installation would add a tiered gate the taker never funded under, so a tiered table can never be installed after funding), and a plain-quorum escrow is refused the same way (its threshold moves through `update_quorum`, not here); the new table reuses the `TieredQuorum::new` gate (empty table, more than `MAX_TIERS` tiers, non-strictly-increasing ceilings, a top tier that is not open-ended (`u64::MAX`), non-decreasing-threshold violations, or a threshold outside `1..=total_weight` of the wrapped policy are all `InvalidQuorum`) leaving the original table untouched; a paused escrow fails fast (`Paused`); a delay-opted-in escrow refuses the direct call (`GovernanceActionNotProposed`, the AV-158 routing gate — the table moves only through the propose/execute protocol, staging no new proposal variant, paralleling AV-276); replacing with the identical table is a no-op (succeeds, writes nothing, emits no event, paralleling `update_quorum`); only the tier table changes — the wrapped base policy (attestor registry, weights, accumulated attestations) is reused verbatim, so in-flight attestations are re-judged under the new thresholds at the next release (`require_release_quorum` reads the live table through `is_satisfied_for`), while a release already settled keeps the table it settled under; orthogonal to `update_quorum` (that is the plain threshold, this item is the tier table) and to `update_attestors` (that is the attestor set, this item is the tier table) and to `with_tiered_quorum` (that is the `Uninitialized`-only initial table, this item is the post-funding revision); emits `TieredQuorumUpdated` (discriminant 143), all amounts zero, except for the no-op re-affirmation |
| `amend_jury_panel_size(initializer, taker, new_panel_size)` (AV-281) | `Funded` | — (no state change; rewrites `jury_panel_size` in place) | **both** parties must sign (dual-signature governance — one party alone cannot resize the dispute panel on the other's share, paralleling `update_quorum`); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial size; the draw has not happened yet, since `draw_panel` runs only on a `Disputed` escrow, so there is no in-flight panel to re-draw); only an escrow already carrying a jury may amend — an unconfigured escrow is `InvalidJurySize` (code 294, fail-closed: post-funding installation would add a settlement mechanism the taker never funded under, so a jury can never be installed after funding); an escrow with a bound single arbiter is `JuryArbiterConflict` (code 298, mirroring `draw_panel`'s mutual-exclusion gate, checked before configuration so an arbiter-settled escrow reports the conflict rather than the missing jury); the new size reuses the `with_jury` gate (`1..=MAX_JURORS`, otherwise `InvalidJurySize`, code 294) leaving the original size untouched, and the registry's size-vs-registration check stays at draw time (`k > n` is `InvalidJurySize` there — a size above today's registration count may become drawable as jurors register); a paused escrow fails fast (`Paused`); a delay-opted-in escrow refuses the direct call (`GovernanceActionNotProposed`, the AV-158 routing gate — the size moves only through the propose/execute protocol, staging no new proposal variant, paralleling AV-280); amending to the current size is a no-op (succeeds, writes nothing, emits no event, paralleling `update_quorum`); only the size changes — the arbiter slot, the arbiter panel and the juror registry are untouched; the new size governs from the next dispute draw (`draw_panel` reads the live `jury_panel_size` at every call, so a panel drawn after the amendment seats the new size while no panel is ever re-drawn in flight); orthogonal to `with_jury` (that is the `Uninitialized`-only initial set, this item is the post-funding revision) and to `rotate_arbiter` (that is the single-arbiter slot, this item is the jury size); emits `JuryPanelSizeAmended` (discriminant 144), all amounts zero, except for the no-op re-affirmation |
| `amend_event_capacity(initializer, taker, new_capacity)` (AV-282) | `Funded` | — (no state change; rewrites `event_capacity` in place) | **both** parties must sign (dual-signature governance — one party alone cannot resize the audit window on the other's history, paralleling `update_quorum`); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial capacity); only a ring that has not wrapped may amend — while the ring is still filling (`event_count < event_capacity`, head still 0, slots `0..event_count` valid in order) a new capacity keeps every retained entry readable, but once the ring is full (`event_count == event_capacity`) the head has started advancing modulo the old capacity, so a new capacity would re-interpret the head modulo a different modulus and scramble the window — the amendment is `InvalidStateTransition` (fail-closed: the capacity is frozen once the ring wraps, and the refusal precedes even the no-op check, so a re-affirmation on a wrapped ring is refused rather than silently succeeding); the new capacity reuses the `with_event_capacity` gate (`1..=MAX_EVENT_HISTORY`, otherwise `InvalidEventCapacity`, code 132) and must also be at least `event_count` — a smaller capacity would drop retained entries, so it is `InvalidEventCapacity` too — leaving the original capacity untouched; a paused escrow fails fast (`Paused`); a delay-opted-in escrow refuses the direct call (`GovernanceActionNotProposed`, the AV-158 routing gate — the capacity moves only through the propose/execute protocol, staging no new proposal variant, paralleling AV-281); amending to the current capacity is a no-op (succeeds, writes nothing, emits no event, paralleling `update_quorum`); only the capacity changes — the slots, the head, the count and the total are untouched, so the retained entries survive verbatim, and the new capacity governs from the next `record_history` call (`record_history` and `event_history` both read the live capacity at every call, so a ring amended while filling keeps filling under the new bound and wraps modulo the new capacity once it fills); orthogonal to `with_event_capacity` (that is the `Uninitialized`-only initial set, this item is the post-funding revision); emits `EventCapacityAmended` (discriminant 145), all amounts zero, except for the no-op re-affirmation |
| `update_arbiter_panel_members(initializer, taker, members)` (AV-283) | `Funded` | — (no state change; rewrites `members`/`n` in place) | **both** parties must sign (dual-signature governance — one party alone cannot reshape the adjudication electorate, paralleling `update_quorum`); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial roster); only an escrow with a configured panel may amend — an unconfigured escrow is `InvalidArbiterPanel` fail-closed (post-funding installation would add a settlement mechanism the taker never funded under; single-arbiter mode revises through `rotate_arbiter`); the new list reuses the `ArbiterPanel::new` gate against the current threshold (empty, over `MAX_PANEL_MEMBERS`, zero key, duplicate, or a new count below the current threshold is `InvalidArbiterPanel`), leaving the original roster untouched; a paused escrow fails fast (`Paused`); a delay-opted-in escrow refuses the direct call (`GovernanceActionNotProposed`, the AV-158 routing gate — the roster moves only through the propose/execute protocol, staging no new proposal variant, paralleling AV-281); re-affirming the identical list in the identical slot order is a no-op (succeeds, writes nothing, emits no event, paralleling `update_quorum`), while a reordering IS a revision (slot order is vote identity); only the members and the count change — the threshold, the blind mode and the reveal window are carried over verbatim (the fresh builder value defaults to plain voting and is never stored whole, or blind mode would silently reset), and the vote state is necessarily zero on a `Funded` escrow (no dispute in flight), so preserving the panel struct is exactly a no-reset; the new roster governs from the next dispute (`escalate` then `submit_panel_judgment` checks membership against the live list, so a removed member is refused and a seated member votes); orthogonal to `update_panel_threshold` (that is the `Uninitialized`-only threshold move, this item is the post-funding roster revision), to `amend_jury_panel_size` (that is the jury size, this item is the arbiter panel roster), and to AV-65 (that is the panel mechanism itself, this item is its roster revision); emits `ArbiterPanelMembersUpdated` (discriminant 146), all amounts zero, except for the no-op re-affirmation |
| `rotate_fee_recipient(new_recipient)`         | `Uninitialized`/`Activated`/`Funded` | — (no state change; rewrites the fee recipient) | **both** the *current* initializer and the *current* taker must sign (dual-signature governance — the mirror of `rotate_arbiter` for the fee-destination role; the fee recipient itself does not sign, so a lost fee-recipient key cannot block its own replacement; degenerate initializer == taker self-escrow authorizes with one key passed twice); terminal states and `Disputed` are `InvalidStateTransition` (no future fee leg left to redirect, and the dispute settlement builders pin the fee leg to the configured recipient); no fee recipient configured or the zero address is `InvalidFeeRecipient` (code 123); the activation bitmask is untouched (it tracks only the initializer and taker); the keeper's fee listings and the snapshot export read the live `fee_recipient` field (follow automatically); emits `FeeRecipientRotated` only on an actual change |
| `withdraw_protocol_fees(authority, amount)` | `Uninitialized`/`Activated`/`Funded`/`Disputed` (all non-terminal) | — (no state change; accumulates into `fees_withdrawn`) | authority must be the pinned `fee_recipient` or the initializer (`Unauthorized` otherwise); terminal states incl. `Closed` are `InvalidStateTransition`; paused is `Paused`; reentrancy-guarded (`ReentrantCall`); amount `0` or `> fees_paid - fees_withdrawn` is `AmountMismatch`; recipient is the pinned `fee_recipient` or the program-level fee account; emits `FeeWithdrawn` (fee == withdrawn, refund == remaining withdrawable) |
| `delegate_authority(caller, delegate, scopes)` (AV-104) | `Uninitialized`/`Funded` | — (no state change; writes the operator grant) | **initializer or taker** (party power — a stranger, or the operator themselves, is `Unauthorized`, so grants never sub-delegate); the zero operator key, an empty scope bitmap, or scope bits outside the mask (`1` fund / `2` release / `4` cancel) is `InvalidDelegation` (code 160); terminal states and `Disputed` are `InvalidStateTransition`; a later grant overwrites the earlier one (single slot); `rotate_initializer` / `rotate_taker` clear the grant (fail-closed — the new party never inherits the old party's operator); emits `DelegationGranted` only on an actual change (an identical re-grant is a no-op success that emits nothing) |
| `revoke_delegation(caller)` (AV-104)         | `Uninitialized`/`Funded` | — (no state change; clears the operator grant) | **either** party may revoke — the initializer can cut off a taker-appointed operator and vice versa; a stranger is `Unauthorized`; no live grant is `InvalidDelegation` (code 160); emits `DelegationRevoked` |
| `amend_delegation_spend_cap(caller, new_cap)` (AV-295) | `Uninitialized`/`Funded` | — (no state change; rewrites `spend_cap` in place) | **either** party may revise (the same party power as granting and renewing — a stranger or the operator themselves is `Unauthorized`); a paused escrow fails fast (`Paused`); no live grant is `InvalidDelegation` (code 160); the new cap must be `0` (uncapped, the AV-208 storage meaning) or at least the live `spent` — a cap below the volume already settled is `InvalidDelegation` fail-closed, leaving the original cap untouched (no retroactive breach); revising to the current cap is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `spend_cap` changes — the operator, scopes, `spent` and expiry window are untouched, so the new bound governs from the next operator release (`record_operator_release` reads the live cap at every call, so a release after the amendment is judged against the new bound while a release already settled keeps the cap it settled under); orthogonal to `renew_delegation` (that is the expiry window, this item is the cap) and to AV-104 (that is the grant mechanism itself, this item is the cap revision); emits no event |
| `amend_delegation_scopes(caller, new_scopes)` (AV-296) | `Uninitialized`/`Funded` | — (no state change; rewrites `scopes` in place) | **either** party may revise (the same party power as granting, renewing and revising the cap — a stranger or the operator themselves is `Unauthorized`); a paused escrow fails fast (`Paused`); no live grant is `InvalidDelegation` (code 160); the new bitmap must pass `validate_delegation_scopes` (non-empty, within `DELEGATION_SCOPE_MASK` — an empty bitmap or unknown bits are `InvalidDelegation` fail-closed, leaving the original bitmap untouched); revising to the current bitmap is a no-op (succeeds, writes nothing, emits no event, paralleling `rotate_arbiter`); only `scopes` changes — the operator, spend cap, `spent` and expiry window are untouched, so the new bitmap governs from the next operator call (`require_scoped_authority` reads the live bitmap on every `fund` / `release` / `cancel` call, so narrowing revokes a power at once while widening grants it at once, and a call already settled is never re-judged); orthogonal to `amend_delegation_spend_cap` (that is the volume bound, this item is the scope bitmap) and to AV-104 (that is the grant mechanism itself, this item is the scope revision); emits no event |
| `rotate_delegation_delegate(caller, new_delegate)` (AV-301) | `Uninitialized`/`Funded` | — (no state change; rewrites `delegate` in place) | **either** party may rotate (the same party power as granting, renewing and revising the cap and scopes — a stranger or the operator themselves is `Unauthorized`); a paused escrow fails fast (`Paused`); no live grant is `InvalidDelegation` (code 160); the new delegate must be a non-zero key (a zero key is `InvalidDelegation` fail-closed, leaving the original delegate untouched); rotating to the current delegate is a no-op (succeeds, writes nothing, emits no event, paralleling the capped re-grant no-op); only `delegate` changes — the scopes, spend cap, `spent` and expiry window are untouched, and `spent` is never cleared (the rotation is an identity change, not a re-authorization — reusing the `delegate_authority` re-grant path would reset `spent` to `0` and launder the settled volume out of the cap, so the cap keeps binding the grant's cumulative volume under the new operator); the new operator is effective from the next operator call and the old operator loses power at once (`require_scoped_authority` reads the live delegate on every `fund` / `release` / `cancel` call, and a call already settled is never re-judged); orthogonal to `renew_delegation` (that is the expiry window, this item is the operator identity), to `amend_delegation_spend_cap` (that is the volume bound, this item is the identity), to `amend_delegation_scopes` (that is the scope bitmap, this item is the identity) and to AV-104 (that is the grant mechanism itself, this item is the identity rotation); emits no event |
| `link_swap(caller, escrow_id_a, escrow_id_b, amount_a, amount_b)` (AV-105) | `Uninitialized` (both legs) | — (no state change; writes each vault's counterparty id) | **one of the two parties** (an AV-104 operator is `Unauthorized`); mirrored parties required (`InvalidSwapParties` code 161 — zero/duplicate counterparty id is the same code); leg amounts must equal the locked amounts (`InvalidSwapAmounts` code 162); already-linked is `SwapLinkActive` (code 163); on-chain requires *both* parties as signers; emits `SwapLinked` on each vault |
| `release_swap(caller, escrow_id_a, escrow_id_b, amount_a, amount_b)` (AV-105) | `Funded` (both legs, cross-link matched) | `Funded` (partial) / `Released` (cumulative full), per leg | **party-only** — an AV-104 operator is `Unauthorized`; each leg runs under *its own* initializer (on-chain requires both parties as signers); two-phase atomic — either leg failing returns the single-side error with both escrows untouched and zero events; emits `Released` A→B |
| `cancel_swap(caller, escrow_id_a, escrow_id_b)` (AV-105) | `Funded` (both legs, cross-link matched) | `Cancelled` (both legs) | caller must be the initializer of at least one leg (party-only — a stranger or AV-104 operator is `Unauthorized`; on-chain requires both parties as signers); two-phase atomic like `release_swap`; emits `Cancelled` A→B |
| `cancel_swap_expired(caller, escrow_id_a, escrow_id_b)` (AV-105) | `Funded` (both legs, cross-link matched, *both* expiry-eligible) | `Cancelled` (both legs) | either party (an AV-104 operator is `Unauthorized`); *both* legs must be expiry-eligible or the whole call refuses with `NotExpired` (no partial expiry); per-leg authority is the caller (AV-24 penalty keys per leg); emits `ExpiredCancelled` A→B |
| `initialize_quorum(attestors, weights, threshold)` | `Uninitialized`| `Uninitialized` | initializer (once, before funding) |
| `with_token_weighted_voting(snapshot)` (AV-183) | `Uninitialized`| `Uninitialized` | initializer (once, before funding); the snapshot's frozen token-balance weights land in the quorum slot — `release` needs a `threshold_bps`/10_000 weighted supermajority; mutually exclusive with plain/tiered quorum (`InvalidQuorum`); see "Token-weighted voting (AV-183)" |
| `initialize_dual_sig()`                     | `Uninitialized`| `Uninitialized` | initializer (once, before funding) |
| `initialize_extension(max_extension_secs)` | `Uninitialized`| `Uninitialized` | initializer (once, before funding); zero bound is `InvalidExpiryExtension`; persists the extension budget (`max_extension_secs`, `extension_count` starts 0) |
| `extend_expiry(new_expires_at)`             | `Uninitialized`/`Funded` | — (no state change; pushes `expires_at` back) | initializer **only** (`Unauthorized` otherwise, checked before state validity); `Activated`/`Disputed`/terminal states are `InvalidStateTransition`; new deadline must be strictly later and each increment ≤ the bound (saturating counter); extending at/past keeper-eligibility (`now >= expires_at + grace_period`) is `InvalidExpiryExtension`; emits `ExpiryExtended` (old/new deadline, count) |
| `attest(attestor)`                          | `Uninitialized`/`Activated`/`Funded` | — (no state change) | registered attestor |
| `update_quorum(initializer, taker, threshold)` | `Uninitialized`/`Funded` | — (no state change) | **both** parties must sign (dual-signature governance); `0` or `> total weight` is `InvalidQuorum` |
| `update_attestors(initializer, taker, attestors)` | `Uninitialized`/`Funded` | — (no state change) | **both** parties must sign (dual-signature governance; no party can unilaterally reshape the electorate); empty set / `> 8` / duplicates / new set smaller than the unchanged threshold is `InvalidQuorum`; approval bits remap by pubkey (retained votes survive, removed voters' bits cleared); emits `AttestorsUpdated` on a real set change, nothing on a no-op |
| `replace_attestor(initializer, taker, slot, new_attestor)` (AV-154) | `Uninitialized`/`Funded` | — (no state change) | **both** parties must sign (dual-signature governance); no quorum is `InvalidQuorum`; unoccupied slot or zero replacement key is `AttestorSlotInvalid`; a key already voting at another slot is `InvalidQuorum` (one key, one vote); the slot keeps its weight (key replaced in place, no realloc); the rotated slot's approval bit is **cleared** (unlike `update_attestors` — the old key may be compromised, so its vote must not transfer); same-key rotation is a no-op; emits `AttestorReplaced` on a real key change |
| `activate(authority)`                       | `Uninitialized`| `Uninitialized` (one party) / `Activated` (both parties) | initializer **or** taker (dual-sig escrows only) |
| `initialize_vesting(start, end, cliff)`     | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `start < end`; `cliff` 0 = no cliff, else `cliff <= end`) |
| `claim(authority, now)`                     | `Funded`       | `Funded` (partial) / `Released` (fully vested) | taker only, only when `now` has vested more than already released (+ quorum satisfied when configured; the timelock gate when a lock is configured — `now >= unlock_at` (AV-27) or `now >= fund_at + secs` (AV-64) — `TimelockNotReached` otherwise); with an AV-97 Dutch auction attached, `claim` prices through the descending auction cap inside `[start_at, end_at]` instead of the vesting curve (`AuctionNotActive`, code 156, outside the window) — the gross lands in the same `released` counter and the initializer reclaims the remainder via `cancel` / `cancel_partial` |
| `amend_vesting_schedule(initializer, taker, schedule, now)` (AV-230) | `Funded` | — (no state change; rewrites the linear unlock table) | **both** parties must sign (dual-signature governance — one party alone or a stranger pair is `Unauthorized`); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; a schedule must already be configured (`InvalidVesting` on a schedule-less escrow — amendment never creates one, `with_vesting` stays `Uninitialized`-only); only the still-unvested part may be reshaped — the new schedule's vested amount at `now` must be at least the amount already claimed (`released`, the counter `claim` accumulates), otherwise `InvalidVesting` (fail-closed, no retroactive clawback; a failed amendment leaves the schedule untouched); the new schedule itself must be a valid `VestingSchedule` (construction already rejects `start >= end` and `cliff_at > end`); an attached AV-90 curve keeps pricing against the new window and an AV-150 vesting pause keeps applying to the amended schedule; emits `VestingScheduleAmended` (discriminant 94), all amounts zero |
| `amend_milestone_due_dates(initializer, taker, due_at[], now)` (AV-231) | `Funded` | — (no state change; rewrites the per-tranche deadline table) | **both** parties must sign (dual-signature governance — one party alone or a stranger pair is `Unauthorized`); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; a plan with an attached deadline table must already exist (`InvalidMilestones` on a plan-less or table-less escrow — amendment never creates a table, `with_milestone_due_dates` stays `Uninitialized`-only); the submitted table's length must equal the tranche count; only unsettled tranches move — a released or skipped tranche keeps its original `due_at` verbatim whatever the caller submits for that slot; every new due for an unsettled tranche must be non-zero and no earlier than `now` (a past due would ambush the tranche with an instant-late AV-206 penalty); the final table (retained settled dues plus new unsettled dues) must be strictly increasing; a failed amendment leaves the table untouched; the AV-206 penalty rate and AV-225 claim deadlines are untouched; emits `MilestoneDueDatesAmended` (discriminant 95), all amounts zero |
| `decline_escrow(authority, now)` (AV-122) | `Funded` | `Declined` | taker only, only before any claim (`released == 0` — a taker who already claimed accepted the deal); terminal for fund movements — only `close_vault` retires the vault; resets the deadman clock; emits `Declined` |
| `propose_counter_offer(authority, amount, expiry, now)` (AV-122) | `Funded` | `CounterOffered` | taker only, only before any claim; `amount` must be nonzero and `expiry` in the future (`InvalidCounterOffer`, code 180, otherwise); stores the offer — fund movements and `escalate` frozen until the initializer answers; resets the deadman clock; emits `CounterOfferProposed` |
| `accept_counter_offer(authority, now)` (AV-122) | `CounterOffered` | `Funded` | initializer only; atomically re-sets `amount`/`expires_at` to the offered terms (terms-only — no funds move); resets the deadman clock; emits `CounterOfferAccepted` |
| `reject_counter_offer(authority, now)` (AV-122) | `CounterOffered` | `Funded` | initializer only; drops the offer, terms unchanged; resets the deadman clock; emits `CounterOfferRejected` |
| `amend_counter_offer(authority, amount, expiry, now)` (AV-285) | `CounterOffered` | `CounterOffered` | taker only (the offer is the proposer's — initializer/stranger is `Unauthorized`, checked before state validity); `Funded` or terminal states are `InvalidStateTransition` (no live offer to revise); new terms reuse the propose gates (`amount` nonzero, `expiry` in the future, nothing released — `InvalidCounterOffer` otherwise, original offer untouched); a paused escrow fails fast (`Paused`, with a due auto-recovery schedule lifting first, AV-133); only `counter_offer` moves — the escrow's `amount`/`expires_at` and state are untouched until the initializer answers, and the next accept re-prices under the amended terms; re-affirming the identical terms is a no-op (writes nothing, emits nothing); emits `CounterOfferAmended` (discriminant 147), all amounts zero |
| `initialize_dutch_auction(start_at, end_at, reserve_bps)` (AV-97) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; the descending-price settlement window: `start_at < end_at`, `reserve_bps` in 0–10000 — `InvalidAuctionParams`, code 155, otherwise); the taker's pull path becomes the auction cap `max(amount * (end_at - now) / (end_at - start_at), amount * reserve_bps / 10000)` inside the window — early claimers keep more, the `reserve_bps` floor is the initializer's guaranteed keep; mutually exclusive with the AV-13/AV-90 unlock paths (last-wins) and with dispute arbitration while the window is live (`escalate` is refused with `AuctionNotActive`, code 156) |
| `fund(authority, now)`                      | `Uninitialized` (plain) / `Activated` (dual-sig) | `Funded`  | initializer (`now` <- clock sysvar, recorded as `fund_at` — the origin the AV-64 relative timelock measures from); AV-104: a live FUND-scoped operator may call for the initializer instead (same checks, operator pays nothing — delegation covers transition rights only); AV-134: with a funding window configured, the deposit must sit inside `[min_funding_amount, max_funding_amount]` (`AmountOutOfBounds`, code 197, otherwise) |
| `with_dual_control(checker)` (AV-130)               | `Uninitialized`| `Uninitialized` | initializer (once, before funding; binds the checker key for the maker-checker release protocol — a zero `checker` key is `InvalidDualControl`, code 188) |
| `initiate_release(authority, now, amount, mint, payout_to, intent_ttl_secs)` (AV-130) | `Funded` | `Funded` (no state change; freezes the declaration) | initializer or their RELEASE-scoped operator (`Unauthorized` otherwise); pause → reentrancy → dual-control configured (`InvalidDualControl`, code 188, when never opted in) → authority → state → no live intent (`DualControlIntentExists`, code 189) → declaration shape (`amount == 0`, `intent_ttl_secs == 0`, or an overflowing expiry is `InvalidDualControl`, code 188); emits `DualControlInitiated` |
| `confirm_release(checker, now)` (AV-130)        | `Funded`       | `Funded` (partial) / `Released` (cumulative full) | the bound checker only — the maker cannot self-approve (`Unauthorized` otherwise); the declaration must be live (`DualControlNotInitiated`, code 190, when none) and fresh (`now < intent_expires_at` — a stale declaration is cleared and fails with `DualControlExpired`, code 191); settles through the exact `release` engine with the authority pinned to the initializer (fee, released-accounting, terminal-state logic identical to `release`); the declaration is consumed on success; emits `DualControlConfirmed` |
| `cancel_release(caller, now)` (AV-130)          | `Funded`       | `Funded` (no state change; clears the declaration) | initializer **or** the bound checker (either party — a stranger is `Unauthorized`); no live declaration is `DualControlNotInitiated`, code 190; moves no funds; emits `DualControlCancelled` |
| `release(authority, now, amount, payout_to)` (AV-49)                 | `Funded`       | `Funded` (partial) / `Released` (cumulative full) | initializer (+ quorum satisfied when configured; the timelock gate when a lock is configured — `now >= unlock_at` (AV-27) or `now >= fund_at + secs` (AV-64) — `TimelockNotReached` otherwise); AV-104: a live RELEASE-scoped operator may call for the initializer instead (all other gates identical; delegation covers transition rights only); cumulative releases ≤ locked amount; `payout_to` must satisfy the payout policy — the taker, or a member of the payout allowlist when one is configured (`PayoutNotAllowlisted` otherwise); AV-130: on a dual-control escrow direct `release` is `DualControlRequired` (code 192) — payouts leave only via `initiate_release` + `confirm_release` |
| `release_via_intent(intent, signature, now, now_slot, mint)` (AV-123) | `Funded` | `Funded` (partial) / `Released` (cumulative full) | **gasless / meta-transaction release** — any relayer (permissionless) may submit; the initializer's Ed25519 signature over the canonical `ReleaseIntent{escrow, amount, payout_to, nonce, expiry_slot}` bytes (prefixed with the `b"ESCROW-RELEASE-v1"` domain separator, verified with the hand-rolled RFC 8032 verifier from AV-101) is the authority; check order — pause → signature (`InvalidReleaseIntent`, code 181 — deliberately not `Unauthorized`: the submitter is permissionless, the signature is the authorization) → nonce strictly increasing against the persisted `last_intent_nonce` watermark (`IntentNonceReused`, code 182 — replays are dead) → expiry (`now_slot >= expiry_slot` is `IntentExpired`, code 183) → the full `release` guard chain (reentrancy / state / mint / payout-policy / funding-complete / quorum / timelock) with the initializer as authority; `payout_to` is pinned against the AV-49 payout policy like `release`; `released` accumulates the gross; the intent's `escrow` field binds the signature to the vault (the Anchor handler reconstructs the intent with the vault account's own key, so a signed intent cannot be retargeted at another vault); emits `ReleaseViaIntent` |
| `release_split(authority, now, amount, recipients, bps)` (AV-93) | `Funded` | `Funded` (partial) / `Released` (cumulative full) | initializer; the check order mirrors `release` — authority → state → mint → the share-table shape (non-empty, ≤ 8 recipients, no zero address, no zero weight, weights summing to exactly 10_000 bps — `InvalidReleaseSplit`, code 150, otherwise) → every recipient pinned against the AV-49 payout policy (`PayoutNotAllowlisted` otherwise; with no allowlist only the taker passes, so a multi-recipient split is the allowlist's declared distribution set) → milestones / subscription / quorum / timelock gates → amount math (`AmountMismatch` on 0, `ReleaseExceedsLocked` past the remainder); the AV-17 protocol fee is charged on the gross amount first, then the net splits — each leg `floor(net * bps / 10_000)`, the dust landing on the first recipient, so the legs sum to the net exactly; `released` accumulates the gross, so the conservation invariant is untouched; returns the `(recipient, net_share)` legs (sizing the program's transfers) plus the fee; emits `ReleasedSplit` with the legs stamped on the event |
| `slash(authority, amount)` (AV-82) | `Funded` | `Funded` (no state change — the escrow stays live, the taker can still earn the remainder) | initializer **or** the configured arbiter (the neutral enforcer — one party's griefing cannot burn the other's stake); `now` <- clock sysvar; requires the AV-82 slash terms (`Uninitialized`-time opt-in), `now >= slash_deadline`, and the amount ≤ the slashable remainder (`amount - released - penalty_paid`); single-level slashes are **one-shot** (a second slash is `SlashNotEligible`); `Disputed` is locked (`SlashNotEligible` — arbitration owns the funds) and milestone/subscription-scheduled escrows reject slash (the schedule owns the release path); on a dual-sig escrow both activation bits must be set; the slashed amount moves to the fixed penalty account and accumulates in `penalty_paid` (never in `released` — the audit trail distinguishes a default penalty from a taker payout); emits `Slashed` (`amounts.penalty` = the slashed amount); AV-126: on a ladder escrow (`Uninitialized`-time `with_slash_ladder` opt-in) the one-shot gate is bypassed — the ladder IS the repeated-slash path: each slash consumes the current rung, capped per slash at `floor(slashable_remainder * rung_bps / 10_000)` computed in u128 (`SlashNotEligible` above the cap); the `slash_ladder_index` cursor advances by one after each successful slash and stays pinned at the top rung once the last rung is consumed (further slashes are still allowed at the top rung's bps, never escalating further); every other guard (authority, `Funded`, the `Disputed` lock, no swap link, no milestone/subscription schedule, dual-sig bits, pause, mint match, amount > 0) still applies; the AV-107 interest settle and the AV-86 appeal-window stamping run per slash (each slash is a separate enforcement) and the AV-106 insurance-pool routing applies per slash; the `Slashed` event carries `slash_ladder_index` = the actually-consumed rung |
| `initialize_basket(legs)` (AV-95) | `Uninitialized` | `Uninitialized` | initializer (once, before funding); `legs` is 1–8 `(mint, amount)` pairs — non-empty, no zero mint, no zero amount, no duplicate mint (one leg per mint), Σ fitting in `u64` (`InvalidBasket`, code 152, otherwise); the escrow-level `amount` becomes the Σ over the legs, so fleet aggregation, snapshots and the event fold keep their single-amount semantics |
| `release_basket(authority, now, mint)` (AV-95b) | `Funded` | `Funded` (legs remain) / `Released` (last leg) | initializer; the check order mirrors `release` — authority → basket presence (a plain escrow has no legs to settle — `InvalidBasket`, code 152) → `Funded` → leg lookup (a mint outside the leg table is `InvalidBasket`) → quorum → timelock; the AV-17 protocol fee is charged on the leg's gross remainder; the leg's `released` accumulates the gross and the escrow-level `released` accumulates the Σ (a re-settled leg is `AmountMismatch`); the payout goes to the taker; emits `BasketReleased` per settled leg |
| `cancel_basket(authority, mint)` (AV-95b) | `Funded` | `Funded` (legs remain) / `Cancelled` (last leg) | initializer; the check order mirrors `cancel` — authority → basket presence → `Funded` → leg lookup; quorum / timelock do NOT gate this path; the refund goes to the escrow's own AV-23 refund policy (no caller-chosen destination); no fee, no penalty; the leg's `released` accumulates the remainder and the escrow-level `released` accumulates the Σ; emits `BasketCancelled` per settled leg |
| `cancel_expired_basket(authority, now, mint)` (AV-95b) | `Funded` | `Funded` (legs remain) / `Cancelled` (last leg) | initializer **or** taker once `now >= expires_at + grace_period` (`NotExpired` otherwise); the AV-24 anti-griefing penalty applies to the leg's remainder on a taker-initiated cancel only (routed to the initializer); emits `BasketExpiredCancelled` per settled leg |
| `release_basket_all(authority, now, payout_to)` (AV-95c) | `Funded` | `Released` | initializer; settles **every** unsettled leg in one atomic transition — the basket twin of `release` for the whole table at once; the check order mirrors `release_basket` — authority → basket presence → `Funded` → the AV-49 payout-policy pin on `payout_to` (one destination means one check *is* the per-leg application — `PayoutNotAllowlisted` otherwise) → quorum → timelock; the AV-17 protocol fee is charged on each leg's remainder independently (floored per leg, no dust carried across legs); **atomic** — every gate and every leg's fee math runs before any mutation, so any leg failure rolls the whole settlement back; legs with a zero remainder are skipped (`AmountMismatch` when none); each leg's `released` accumulates its gross and the escrow-level `released` accumulates the Σ; returns the `BasketSettlement` (per-leg `(mint, payout_to, net)` in leg-table order + Σ fee); emits one `BasketReleased` with Σ amounts (the event-sourced fold books it bit-identically to the per-leg sequence) |
| `cancel_basket_all(authority)` (AV-95c) | `Funded` | `Cancelled` | initializer; refunds **every** unsettled leg in one atomic transition — the basket twin of `cancel`; the check order mirrors `cancel_basket` — authority → basket presence → `Funded`; quorum / timelock do NOT gate this path; the refund goes to the escrow's own AV-23 refund policy (no caller-chosen destination); no fee, no penalty; **atomic** — every leg's remainder math runs before any mutation; legs with a zero remainder are skipped (`AmountMismatch` when none); returns the `BasketSettlement` (`fee == 0`, `penalty == 0`); emits one `BasketCancelled` with the Σ refund |
| `initialize_timelock(unlock_at)`            | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `unlock_at` is the Unix timestamp before which no taker payout may leave; `0` = no lock) |
| `initialize_relative_timelock(secs)` (AV-64) | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `secs` is the duration in seconds after *funding* before which no taker payout may leave; `0` = no lock; mutually exclusive with the AV-27 absolute timelock — both nonzero is `InvalidTimelock`, code 135) |
| `initialize_emergency_unlock()`             | `Uninitialized`| `Uninitialized` | initializer (once, before funding; opts into dual-signed emergency timelock-unlock governance) |
| `emergency_unlock(initializer, taker)`       | `Funded`       | `Funded` (no state change) | **both** parties must sign (dual-signature governance; one party alone is `Unauthorized`); requires the opt-in and an active timelock (`InvalidStateTransition` otherwise); clears the timelock (`timelock`, or the AV-64 relative lock) to `0` so payouts become immediately eligible — state and amounts untouched; emits `EmergencyUnlock` |
| `initialize_decimals(decimals)`             | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `decimals` is the SPL mint's decimal places — SPL mints declare at most 9, `> 18` is rejected; `0` = no decimal metadata; display-only, never gates a transition or moves funds) |
| `cancel(authority, refund_to)`               | `Funded`       | `Cancelled` | initializer; AV-104: a live CANCEL-scoped operator may call for the initializer instead (the `refund_to` pin is unchanged — delegation never reroutes funds); `refund_to` must equal the whitelisted address (or the initializer with no whitelist) — `RefundAddressMismatch` otherwise |
| `cancel_expired(authority, now, refund_to)`  | `Funded`       | `Cancelled` | initializer **or** taker, only when `now >= expires_at + grace_period` (opt-in via `with_grace_period`, `0` by default); AV-104: a live CANCEL-scoped operator may also call (either party's grant — the refund routing is unchanged); the refund still goes to the whitelisted address even when the taker calls; returns `(refund, penalty)` — a taker-initiated cancel with `penalty_bps > 0` slices an anti-griefing penalty for the initializer (see below) |
| `cancel_partial(authority, amount, refund_to)` (AV-60) | `Funded` | `Funded` (no state change) | initializer; Funded-only; the initializer's counterpart to AV-11's partial release — reclaims a tranche of the lockup instead of streaming it to the taker; `amount == 0` is `AmountMismatch`, `amount` above the still-locked remainder is `ReleaseExceedsLocked`; the `released` counter is untouched and the locked total shrinks; `refund_to` must equal the whitelisted address (or the initializer with no whitelist) — `RefundAddressMismatch` otherwise; quorum / timelock / vesting do **not** gate it (same as `cancel`); emits `PartiallyCancelled`; returns the refunded amount |
| `partial_refund(authority, amount, refund_to)` (AV-127) | `Funded` | `Funded` (no state change) | initializer-only (no delegation scope); Funded-only; the audited counterpart to AV-60's `cancel_partial` — reclaims a tranche of the lockup and accumulates it in the persisted `refunded` counter (`refunded_amount()`), so the refund audit trail survives serialization; `amount == 0` is `AmountMismatch`, `amount` above the still-locked remainder is the dedicated `PartialRefundExceedsLocked` (code 185); the `released` counter is untouched and the locked total shrinks; `refund_to` must equal the whitelisted address (or the initializer with no whitelist) — `RefundAddressMismatch` otherwise; quorum / timelock / vesting do **not** gate it (same as `cancel`); emits `PartialRefunded`; returns the refunded amount |
| `initialize_twap_gate(window_slots, target, direction, max_staleness_secs)` (AV-128) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; the TWAP window, target, direction and staleness bound — `window_slots == 0` or `target == 0` is `InvalidTwapGate` code 187; the 26-byte tail region is always reserved so the gate writes in place; once configured `release` / `claim` route to the twap-gated entry points, which also enforce the AV-113 single-point gate when both are configured) |
| `crank_expired(caller, now)` (AV-48) | `Funded` | `Cancelled` | **anyone** — permissionless crank (Solana crank pattern), only when `now >= expires_at + grace_period`; no counterparty signature needed, so a keeper bot that is party to nothing can sweep timed-out vaults; the refund follows the same pinned refund policy (whitelisted address, or the initializer) — anti-MEV; AV-124: when the initializer opted into the keeper bounty, the crank additionally pays `min(keeper_bounty_per_crank, keeper_bounty_pool)` (saturating) to the caller — without the bounty the cranker receives nothing; returns `(refund, penalty, bounty)`; a taker cranker still pays the anti-griefing penalty; rejected with `Paused` while the escrow is paused |
| `initialize_payout_allowlist(allowlist)` (AV-49) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; 1–4 live payout-destination addresses; empty / over-long / zero-address input is `InvalidPayoutAllowlist`); the payout policy gates every fund-moving transition's `payout_to` |
| `update_payout_allowlist(initializer, taker, allowlist)` (AV-49) | `Uninitialized` / `Funded` | same (no state change) | dual-signature governance — both initializer and taker on a dual-sig escrow, initializer alone on a plain escrow (`Unauthorized` otherwise); empty clears the allowlist (back to taker-only payouts); emits `PayoutAllowlistUpdated` only on an actual change |
| `initialize_payout_denylist(addrs)` (AV-96) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; 1–4 live addresses — empty / over-long / zero-address input is `InvalidPayoutDenylist`, code 154); deny takes precedence over the AV-49 allowlist — a destination on both lists is rejected with `PayoutDenied` (code 153) |
| `update_payout_denylist(initializer, addrs)` (AV-96) | `Uninitialized` / `Funded` | same (no state change) | initializer-signature-alone governance (the denylist is the initializer's compliance veto, not a bilateral fund route — unlike the allowlist's dual-signature reshape); pause-guarded, terminal states frozen; empty clears the veto (back to `None`); emits `DenylistUpdated` (kind 51) only on an actual change |
| `initialize_cpi_allowlist(allowlist)` (AV-83) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; 1–8 live target-program ids; empty list leaves the allowlist unset — any target allowed; over-long / zero-address input is `InvalidCpiAllowlist`); when configured, `release_via_cpi` may only invoke a listed target program — `InvalidCpiTarget` (code 120) with full rollback otherwise |
| `update_cpi_allowlist(initializer, taker, allowlist)` (AV-83) | `Uninitialized` / `Funded` | same (no state change) | **always dual-signed** — both initializer and taker even on a plain escrow (stricter than AV-49 by design: the allowlist guards a privileged execution path); `Uninitialized`/`Funded` only; empty list clears the allowlist (back to any-target-allowed); emits `CpiAllowlistUpdated` only on an actual change |
| `initialize_multisig_authority(multisig_authority)` (AV-84) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; binds the external multisig program id, the vault PDA that must sign, and the u16 threshold metadata; zero program id / zero authority / zero threshold is `InvalidMultisigAuthority`); immutable once set — the binding is load-bearing for every later authority check; read-only pass-through, never a check gate (zero-trust) |
| `initialize_appeal_window(window_secs)` (AV-86) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; the opt-in slash-appeal window in seconds; `0` is rejected — a zero-second window would give the taker no chance to appeal, `InvalidAppealWindow` code 146); no window configured means slashes are final (backward compatible); emits no event (pre-fund configuration) |
| `initialize_appeal_bond(bond)` (AV-103) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; the opt-in appeal bond in lamports/base-token units the taker must lock when filing a slash appeal; `0` is rejected — a zero bond is a no-op, `InvalidAppealBond` code 158; the no-bond default keeps filing free, backward compatible); order-independent of `initialize_appeal_window` — a bond without a window is inert; emits no event (pre-fund configuration) |
| `file_appeal(taker)` (AV-86) | `Funded` | `Funded` (no state change — filing records the challenge, and locks the configured AV-103 appeal bond) | taker **only** (`Unauthorized` otherwise, checked before state validity); requires an executed slash (`penalty_paid > 0`), a configured window, no appeal filed or resolved yet (one appeal per slash), `now <= appeal_deadline` (a lapsed window is a hard procedural bar), and a configured arbiter panel to review it — any missing gate is `InvalidAppealWindow` (or `InvalidArbiterPanel` for the missing panel); when a bond was configured via `initialize_appeal_bond`, filing locks it automatically into the independent `appeal_bond_paid` counter (never mixed into `released`/`penalty_paid`, never part of the claimable/release base while pending); returns the locked bond (`0` when none) so the transfer can be sized; `now` <- clock sysvar; emits `AppealFiled` (amounts zero) |
| `review_appeal(member, uphold)` (AV-86) | `Funded` | `Funded` (no state change) | panel member **only** (`Unauthorized` otherwise); one effective vote per member (a re-vote overwrites); the first side to reach the panel threshold resolves — `uphold` keeps the penalty (`Upheld`) and forfeits the locked appeal bond to the initializer (AV-103, the anti-malicious-appeal-delay rule), `overturn` refunds the penalty to the taker (`penalty_paid` → `0`, accumulated in `released` so the conservation invariant stays exact) and refunds the locked bond in full, no fee (never mixed into `released`); a non-resolving vote emits nothing; the resolving vote emits `AppealResolved` (on overturn `payout` = refunded penalty + refunded bond; on uphold `penalty` = forfeited bond); returns `(outcome, penalty_refunded, bond_moved)` — `0` == upheld, `1` == overturned — so both transfers can be sized |
| `expire_appeal(caller)` (AV-103) | `Funded` | `Funded` (appeal → `Expired`, terminal) | **permissionless** — anyone may crank a lapsed appeal (no authority check; the caller only acts as the event actor); requires a `Filed` appeal and `now > appeal_deadline` (`InvalidAppealWindow` when never filed or already resolved, `AppealExpiryNotDue` code 159 when the window has not lapsed yet); the slash stands (like an upheld appeal) and the locked appeal bond — if any — is forfeited to the initializer; returns the forfeited bond (`0` when none) so the transfer can be sized; `now` <- clock sysvar; emits `AppealExpired` (`penalty` = the forfeited bond) |
| `initialize_interest(rate_bps)` (AV-107) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; the annual interest rate in basis points on the locked principal — `rate_bps` in 0–10000, `InvalidInterestRate` code 165 above; `0` disables the yield, backward compatible; the 26-byte tail region is always reserved so the rate writes in place) |
| `claim_interest()` (AV-107) | `Funded` | `Funded` (no state change) | taker **only** (`Unauthorized` otherwise, checked before state validity); `now` <- clock sysvar settles the lazy interest clock first, so the harvest is exact to the second; no rate configured is `InterestNotEnabled` (code 166) — a configured-but-unearned escrow returns `Ok(0)`; returns the interest paid and accumulates `interest_paid` (never `released`); emits no event (counter/snapshot-observable) |
| `initialize_payout_split(shares)` (AV-108) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; the fixed 1–8 `(recipient, amount)` distribution table — empty / over-8 / zero-address / duplicate-recipient / zero-share / Σ != amount is `InvalidPayoutSplit` code 167; the 321-byte tail region is always reserved so the table writes in place; once configured the table owns the release destination) |
| `release_payout_split()` (AV-108) | `Funded` | `Released` | initializer, taker, **or** their RELEASE-scoped operator (AV-104); `now` <- clock sysvar (never a param); reuses the exact `release` gate order (pause → reentrancy → scoped authority → Funded → swap-link → mint → per-recipient payout-policy pin → milestones/subscription → quorum → timelock); no table configured is `InvalidPayoutSplit` (code 167); the protocol fee is charged once on the gross, then the net is prorated per leg (`floor(share_i * net / amount)`, dust to the first leg); `released` accumulates the gross; returns the per-recipient `(recipient, net_payout)` legs; emits `ReleasedSplit` (reused event) |
| `initialize_deadman_switch(inactivity_secs, heir)` (AV-109) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; the inactivity threshold in seconds and the heir — the only key `claim_deadman` accepts; `inactivity_secs == 0` or the zero address is `InvalidDeadmanConfig`, code 168; the 49-byte tail region is always reserved so the config writes in place — no realloc; emits no event, pre-fund configuration) |
| `claim_deadman(heir, now)` (AV-109) | `Funded` | `Cancelled` | **the configured heir only** (`Unauthorized` otherwise — the heir is deliberately *not* required to be either party, the orthogonality point with `cancel_expired`); only once `now - deadman_last_activity >= inactivity_secs` (saturating; exactly-equal counts as elapsed — `DeadmanNotElapsed`, code 169, before the window lapses); unconfigured switch is `InvalidDeadmanConfig` (code 168); the pause gate and the AV-105 swap-link refusal apply; `now` <- clock sysvar (never an instruction param); the unsettled AV-107 interest claim is voided like `cancel`; returns the remaining locked amount (refund-family unwind — `released` untouched, the remainder preserved for audit like `cancel`'s); emits `DeadmanClaimed` |
| `top_up_rent(caller, lamports)` (AV-110) | any except `Closed` | unchanged (no state change) | **permissionless** — anyone may top up (the initializer, the taker, the keeper bot, or a stranger; no authority check, the caller only acts as the event actor); `Closed` is `InvalidStateTransition` (no account left to keep rent-exempt); `lamports == 0` is `InvalidRentTopUp` (code 170); deliberately *not* pause-gated (pausing freezes fund movement, not operational hygiene) and no reentrancy guard (no escrow funds move); accumulates `rent_topped_up_total` only — the state byte and the amount conservation identity are untouched (a top-up is pure lamport bookkeeping on the vault account); emits `RentToppedUp` (`from == to ==` the current state; the topped-up lamports ride the event's `rent_reclaimed` amount field) |
| `initialize_funding_plan(total_amount, max_tranches)` (AV-111) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; the cumulative funding target — must equal the escrow's declared `amount` (`AmountMismatch` otherwise) — and the tranche budget, at least 1 (`InvalidFundingPlan`, code 173, on zero); attaching the plan moves the deposit path from `fund` to `fund_tranche`) |
| `fund_tranche(authority, tranche_amount, now)` (AV-111) | `Uninitialized` (non-dual-sig) / `Activated` / `Funded` | `Funded` (first tranche; later tranches re-enter `Funded`) | initializer or their FUND-scoped operator (AV-104); `now` <- clock sysvar (never a param); full check sequence — pause → reentrancy → FUND-scoped authority → plan presence (`InvalidFundingPlan`, code 173, when no plan is attached) → state → positive amount (`AmountMismatch` on zero) → AV-134 funding window (`AmountOutOfBounds`, code 197, when the tranche sits outside the configured bounds) → tranche budget (`FundingTranchesExhausted`, code 172, when spent) → overfund cap (`AmountMismatch`); each call accumulates `funded_total` and consumes one tranche slot; the first call anchors `fund_at` / the interest clock / the deadman clock exactly like `fund`; emits `TrancheFunded` (`from == to ==` the state after the call; no amount — the fold seeds the lockup with the deal size at `Funded`) |
| `fund_taker(taker, amount, now)` (AV-148) | `Funded` (or `Activated` on a dual-sig escrow) | `Funded` (unchanged — additive funding on a live escrow) | taker only (a stranger or the initializer is `Unauthorized`; AV-104 delegation does not extend to the taker's leg); `now` <- clock sysvar (never a param); full check sequence — pause (`Paused`) → reentrancy (`ReentrantCall`) → taker authority → state (`InvalidStateTransition` unless `Funded`/`Activated`) → config (a milestone plan or subscription schedule refuses the counter-fund — `InvalidMilestones` / `InvalidSubscription`) → positive amount (`AmountMismatch` on zero or wrapping accumulate); each call accumulates `taker_locked` and touches the deadman clock; emits `TakerFunded` (discriminant 76; `from == to ==` the state after the call; no amount — the fold seeds the lockup with the bilateral total at `Funded`) |
| `initialize_claimants(shares)` (AV-149) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; opt-in multi-taker pull roster — 1–8 `(claimant, share_bps)` legs; empty / over-8 / zero-address / zero-share / duplicate-claimant / Σ != 10_000 bps is `InvalidClaimantShares`, code 211); once attached, each claimant pulls their own share via `claim_share` (the roster does not gate the bilateral release/claim paths — it is a pull roster, not a release lock) |
| `claim_share(claimant)` (AV-149) | `Funded` | `Funded` (or `Released` once the last leg is pulled) | the claiming claimant only — `authority` must equal `claimant` (`Unauthorized` otherwise; one claimant cannot pull another's share); `now` <- clock sysvar (never a param); full check sequence — pause (`Paused`) → reentrancy (`ReentrantCall`) → authority → state (`InvalidStateTransition` unless `Funded`) → roster (not a roster leg is `ClaimantNotInRoster`, code 209) → bitmask (already-pulled leg is `ClaimantAlreadyClaimed`, code 210); the leg's gross is its bps share of the current locked remainder (`released` accumulates the gross, AV-17 fee deducted on top); the last unclaimed leg takes the whole remainder (dust-absorbing), so the final pull moves `Funded` -> `Released`; emits `ShareClaimed` (discriminant 77) |
| `amend_claimant_roster(initializer, new_legs)` (AV-227) | `Funded` | `Funded` (unchanged — rewrites the pull roster, moves no funds) | initializer only (`Unauthorized` otherwise); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; a roster must already be configured (`InvalidClaimantShares` on a roster-less escrow — amendment never creates a roster, `with_claimants` stays `Uninitialized`-only); the caller passes the new unclaimed legs as `(claimant, weight)` pairs — claimed legs are implicitly preserved with address, share and claimed bit locked, an unclaimed leg is removed by omitting it; the new table must be non-empty, fit 8 legs with the claimed ones, and contain no zero address, zero weight, duplicate, or already-claimed address (`InvalidClaimantShares`, code 211, on any violation, and a failed amendment leaves the roster untouched); the claimed legs pin their slice and the unclaimed pool (`10_000` minus claimed shares) is re-cut by weight with largest-remainder apportionment, so the Σ is exactly `10_000` bps; later `claim_share` pulls price against the new shares and still settle to exactly the locked amount; in-place rewrite (no realloc, no rent change — the roster region is already reserved); emits `ClaimantRosterAmended` (discriminant 92), all amounts zero |
| `pause_vesting()` (AV-150) | `Funded` | `Funded` (unchanged — a schedule-config flip, not a lifecycle move) | initializer only (`Unauthorized` for the taker or a stranger; AV-46 global pause is checked first); `now` <- clock sysvar (never a param); full check sequence — auto-unpause (AV-133) → pause (`Paused`) → authority → state (`InvalidStateTransition` unless `Funded`) → vesting attached (schedule-less is `InvalidVesting`) → not already paused (re-pause is `VestingAlreadyPaused`, code 213); stamps `paused_at` = now; while paused, the taker's schedule-priced `claim` is refused (`VestingPaused`, code 212) but the initializer's `release` push path and the roster 's `claim_share` stay open; emits `VestingPaused` (discriminant 78) |
| `resume_vesting()` (AV-150) | `Funded` | `Funded` (unchanged — a schedule-config flip, not a lifecycle move) | initializer only (`Unauthorized` otherwise); `now` <- clock sysvar (never a param); full check sequence — auto-unpause (AV-133) → pause (`Paused`) → authority → state (`InvalidStateTransition` unless `Funded`) → paused (live schedule is `VestingNotPaused`, code 214) → clock sane (`now < paused_at` is `InvalidVesting`); shifts the schedule's start/end/cliff_at forward by `now - paused_at` so the taker loses no unlock time (unlock duration unchanged), then clears the marker; emits `VestingResumed` (discriminant 79) |
| `initialize_amount_bounds(min_amount, max_amount)` (AV-134) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; opt-in deposit guardrails — `min_amount > max_amount` is `InvalidAmountBounds`, code 196); once attached, `fund` and each `fund_tranche` deposit must sit inside the window (`AmountOutOfBounds`, code 197, otherwise); with no bounds configured both deposit paths keep their existing semantics |
| `initialize_arbiter_fee(flat_lamports, fee_bps)` (AV-135) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; opt-in arbiter compensation — `fee_bps > 10_000` is `InvalidArbiterFee`, code 198); once attached, every dispute settlement (`resolve`, the panel settling vote, the AV-55 default judgment) deducts the fee from the taker's adjudicated share and routes it to the arbiter (deduction order: AV-17 protocol fee, AV-100 streaming fee, then the arbiter fee); with no fee configured the settlement paths keep their existing semantics |
| `amend_arbiter_fee(initializer, taker, flat_lamports, fee_bps)` (AV-235) | `Funded` | — (no state change; rewrites the arbiter fee legs) | **both** parties must sign (dual-signature governance — one party alone cannot raise the fee on the other's adjudicated share); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; `fee_bps > 10_000` is `InvalidArbiterFee` (code 198); both legs are set atomically in one call and a failed amendment leaves both untouched (the valid flat leg in a bad-bps call does not move); the zero convention matches the builder (a `0` leg clears that leg, `(0, 0)` disables the fee); only disputes arising after the amendment price at the new rate (`arbiter_fee_for` reads the live fields) while already-settled disputes keep the fee deducted at their own settlement (`resolve` is terminal, so no settled dispute is repriced) and the amendment itself charges nothing; orthogonal to AV-233's protocol-fee amendment (different field, different rate, different deduction order); emits `ArbiterFeeAmended` (discriminant 99), all amounts zero |
| `amend_appeal_window(initializer, taker, window_secs)` (AV-236) | `Funded` | — (no state change; rewrites the slash-appeal window) | **both** parties must sign (dual-signature governance — one party alone cannot shorten or lengthen the other's appeal time); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; a zero window is `InvalidAppealWindow` (code 146, the same rejection as the builder — a zero-second window makes an appeal expire on arrival); a paused escrow fails fast (`Paused`); only slashes executed after the amendment stamp their appeal deadline from the new window (`slash` reads the live field at slash time) while an already-stamped deadline — a filed appeal under review, or a slash awaiting filing — keeps its original window, so the amendment never shortens or extends a live appeal; orthogonal to the `with_appeal_window` builder (`Uninitialized`-only initial configuration) and to AV-235's arbiter-fee amendment (different field, different governance consequence); emits `AppealWindowAmended` (discriminant 100), all amounts zero |
| `amend_appeal_bond(initializer, taker, bond)` (AV-238) | `Funded` | — (no state change; rewrites the slash-appeal bond) | **both** parties must sign (dual-signature governance — one party alone cannot raise or lower the other's appeal stake); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; a zero bond is `InvalidAppealBond` (code 158, the same rejection as the builder — a zero bond is a no-op, and the no-bond default already covers free filing); a paused escrow fails fast (`Paused`); only appeals filed after the amendment lock the new bond (`file_appeal` copies the live field into `appeal_bond_paid` at filing) while an already-locked bond — a filed appeal under review — keeps its original amount, so the amendment never tops up or refunds a live appeal; orthogonal to the `with_appeal_bond` builder (`Uninitialized`-only initial configuration) and to AV-236's appeal-window amendment (different field, different governance consequence); emits `AppealBondAmended` (discriminant 102), all amounts zero |
| `amend_grace_period(initializer, taker, grace_secs)` (AV-240) | `Funded` | — (no state change; rewrites the expiry grace period) | **both** parties must sign (dual-signature governance — one party alone cannot lengthen or shorten the other's expiry buffer); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; `expires_at + grace_secs` overflowing `u64` is `InvalidGracePeriod` (code 115, the same rejection as the builder); a paused escrow fails fast (`Paused`); zero is valid and removes the grace (the builder's default); only expiry determinations after the amendment follow the new value (`is_expiry_eligible` and `cancel_expired` read the live field at call time) while already-executed determinations are history; orthogonal to the `with_grace_period` builder (`Uninitialized`-only initial configuration) and to AV-238's appeal-bond amendment (different field, different governance consequence); emits `GracePeriodAmended` (discriminant 103), all amounts zero |
| `amend_evidence_deadline(initializer, taker, deadline_secs)` (AV-241) | `Funded` | — (no state change; rewrites the dispute-evidence disclosure deadline) | **both** parties must sign (dual-signature governance — one party alone cannot lengthen or shorten the other's disclosure bar); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (so a live dispute's computed due date can never move — a live dispute is `Disputed`, not `Funded`); no arbitration mechanism configured is `InvalidArbiter` (code 108, the same pre-check as the builder); a zero deadline is `InvalidEvidenceDeadline` (code 138, the same rejection as the builder); a paused escrow fails fast (`Paused`); only disputes escalated after the amendment measure their window from the new value (`evidence_due_at` computes `disputed_at + evidence_deadline_secs` live) while a live dispute's due date is untouched; orthogonal to the `with_evidence_deadline` builder (`Uninitialized`-only initial configuration) and to AV-240's grace-period amendment (different field, different governance consequence); emits `EvidenceDeadlineAmended` (discriminant 104), all amounts zero |
| `amend_arbitration_deadline(initializer, taker, deadline_secs)` (AV-242) | `Funded` | — (no state change; rewrites the pre-agreed arbitration default judgment's deadline) | **both** parties must sign (dual-signature governance — one party alone cannot lengthen or shorten the other's fallback window); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (so a live dispute's trigger window can never move — a live dispute is `Disputed`, not `Funded`); no default judgment configured is `DefaultJudgmentNotDue` (code 129, the same rejection as the builder); a zero deadline is the same `DefaultJudgmentNotDue` (code 129, the builder's rejection); a paused escrow fails fast (`Paused`); only `deadline_secs` changes — `default_taker_amount` and `default_confirmed` are untouched; only disputes escalated after the amendment measure their window from the new value (`trigger_default_judgment` reads `default_judgment.deadline_secs` live) while a live dispute's trigger window is untouched; orthogonal to the `with_arbitration_deadline` builder (`Uninitialized`-only initial configuration) and to AV-241's evidence-deadline amendment (different deadline, different governance consequence); emits `ArbitrationDeadlineAmended` (discriminant 105), all amounts zero |
| `amend_default_judgment(initializer, taker, deadline_secs, default_taker_amount)` (AV-286) | `Funded` | — (no state change; rewrites the pre-agreed arbitration default judgment's terms and resets the confirmation) | **both** parties must sign (dual-signature governance — one party alone cannot re-price the fallback split after the other party funded under the old terms); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (so a live dispute's fallback can never move — a live dispute is `Disputed`, not `Funded`); no default judgment configured is `DefaultJudgmentNotDue` (code 129, the same rejection as the builder — post-funding installation is refused fail-closed); the new terms reuse the builder gates (a zero deadline is the same `DefaultJudgmentNotDue`, a taker share above the locked amount is `ReleaseExceedsLocked`); a paused escrow fails fast (`Paused`); on a governance-delay-opted-in escrow the direct call is refused (`GovernanceActionNotProposed` — the terms move only through the AV-158 propose/execute protocol, no new proposal variant staged, mirroring AV-281–AV-283); only `default_judgment{deadline_secs, default_taker_amount}` changes and `default_confirmed` resets to `false` (the old confirmation covered the old terms only — the new terms need a fresh taker countersign before `trigger_default_judgment` can fire on them, and until then the trigger fails `DefaultJudgmentNotDue`); re-affirming the identical terms is a no-op (writes nothing, resets nothing, emits nothing — the standing confirmation keeps covering the terms); a dispute escalated after the amendment measures its window from the new terms (`trigger_default_judgment` reads the terms and the confirmation live) while a live dispute's fallback is untouched; orthogonal to AV-242's deadline-only amendment (which leaves `default_confirmed` untouched); emits `DefaultJudgmentAmended` (discriminant 148), all amounts zero |
| `amend_claim_cooldown(initializer, taker, slots)` (AV-243) | `Funded` | — (no state change; rewrites the per-taker claim cooldown) | **both** parties must sign (dual-signature governance — one party alone cannot tighten or loosen the other's claim throttle); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); a paused escrow fails fast (`Paused`); no configuration precondition — an unconfigured escrow simply gains a cooldown; `0` is legal (disables the cooldown, the builder's zero sentinel); only `claim_cooldown_slots` changes — `last_claim_slot` is untouched, so the next claim's eligibility is recomputed live from the new value (`claim_cooldown_eligible_at` computes `last_claim_slot + claim_cooldown_slots` at call time) while a taker who never claimed stays eligible for the first claim; the vesting claim gate stacks unchanged through the same `claim_cooldown_gated` path; orthogonal to the `with_claim_cooldown` builder (`Uninitialized`-only initial configuration) and to AV-242's arbitration-deadline amendment (different field, different governance consequence); emits `ClaimCooldownAmended` (discriminant 106), all amounts zero |
| `amend_delivery_deadline(initializer, taker, deadline_at)` (AV-244) | `Funded` | — (no state change; rewrites the delivery-confirmation deadline) | **both** parties must sign (dual-signature governance — one party alone cannot move the other's confirmation bar); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; a zero deadline is `AmountMismatch` (the builder's rejection — storage uses `0` for "no deadline attached", so this item cannot cancel a deadline); a paused escrow fails fast (`Paused`); only `delivery_deadline_at` changes — `late_delivery_penalty_bps` and `delivery_late` are untouched; only confirmations after the amendment are judged against the new value (`confirm_delivery_at` reads the live field) while an already-confirmed delivery keeps its first-won stamp; an escrow with no deadline gains one on first amendment; orthogonal to the `with_delivery_deadline` builder (`Uninitialized`-only initial configuration), to AV-245's penalty-rate amendment (a different field) and to AV-211's post-confirmation inspection window (the window runs from the confirmation, this deadline bounds the confirmation itself); emits `DeliveryDeadlineAmended` (discriminant 107), all amounts zero |
| `amend_late_delivery_penalty_bps(initializer, taker, bps)` (AV-245) | `Funded` | — (no state change; rewrites the late-delivery penalty rate) | **both** parties must sign (dual-signature governance — one party alone cannot reprice the other's late penalty); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; a rate above 10_000 bps is `InvalidPenalty` (the AV-206 validator); `0` is legal (no late penalty from here on, the builder's zero semantics); a paused escrow fails fast (`Paused`); only `late_delivery_penalty_bps` changes — `delivery_deadline_at` and `delivery_late` are untouched; a late-stamped but not-yet-released delivery reprices at the amended rate (`release` and `release_milestone` share the live-rate helper) while amounts already released and `penalty_paid` already banked are never restated (no refunds); orthogonal to the `with_late_delivery_penalty_bps` builder (`Uninitialized`-only initial configuration), to AV-244's deadline amendment (the moment, not the rate) and to AV-206's per-tranche milestone penalty (a different penalty, priced first); emits `LateDeliveryPenaltyAmended` (discriminant 108), all amounts zero |
| `amend_release_cooling(initializer, taker, cooling_secs)` (AV-246) | `Funded` | — (no state change; rewrites the release cooling window) | **both** parties must sign (dual-signature governance — one party alone cannot lengthen or shorten the other's veto window); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); no value rejection — any `u64` is a legal window (the gate adds with `saturating_add`) and `0` is legal (cooling off, the builder's zero semantics); a paused escrow fails fast (`Paused`); no configuration precondition — an unconfigured escrow gains a window on first amendment; only `release_cooling_secs` changes — `release_intent_at` is untouched, so a live announced intent is re-measured against the new window (`is_release_cooling_eligible` reads the live field) while a vetoed intent stays vetoed (veto clears the intent; this item writes the window only); orthogonal to the `with_release_cooling` builder (`Uninitialized`-only initial configuration), to AV-112's announce/veto (the intent lifecycle — this item is the window length) and to AV-244's delivery deadline (a different gate); emits `ReleaseCoolingAmended` (discriminant 109), all amounts zero |
| `amend_milestone_claim_deadline(initializer, taker, tranche, deadline_secs)` (AV-247) | `Funded` | — (no state change; rewrites one tranche's claim deadline) | **both** parties must sign (dual-signature governance — one party alone cannot move the other's claim window); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); no plan attached, or a tranche at or past the plan's count, is `InvalidMilestones` (the builder's plan-shape rejection); `0` is legal and clears the tranche's deadline (the "never attached" sentinel — unlike the builder, which rejects `0`); a paused escrow fails fast (`Paused`); only `milestone_claim_deadlines[tranche]` changes — plan amounts, due dates, other tranches' deadlines and settled amounts are untouched; the claim gate reads the deadline live (`release_milestone` consults `milestone_claim_deadline_at` at claim time) so extending rescues a tranche that would have expired, shortening expires it sooner, and clearing removes the gate, while already-claimed or skipped tranches keep their settlements and an unconfirmed tranche still needs its confirmations first (confirmation gate runs before the deadline gate); orthogonal to the `with_milestone_claim_deadline` builder (`Uninitialized`-only initial configuration), to `amend_milestone_due_dates` (due dates, not claim deadlines) and to AV-225's claim-deadline mechanism itself (this item is the post-funding revision); emits `MilestoneClaimDeadlineAmended` (discriminant 110), all amounts zero |
| `amend_max_extension_secs(initializer, taker, max_extension_secs)` (AV-248) | `Funded` | — (no state change; rewrites the per-extension expiry-increase cap) | **both** parties must sign (dual-signature governance — one party alone cannot loosen or tighten the other's extension bound); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); no value rejection — any `u64` is a legal cap and `0` is legal (it closes future extensions, the `extend_expiry` zero-cap rejection — unlike the builder, which rejects a zero bound); a paused escrow fails fast (`Paused`); only `max_extension_secs` changes — `expires_at` and `extension_count` are untouched, so extensions already made keep their deadline moves and their count; the next extension is judged against the live cap (`extend_expiry` reads the field at call time), so tightening rejects increments that fit the old bound, loosening admits increments the old bound refused, and closing refuses every increment; orthogonal to the `with_max_extension_secs` builder (`Uninitialized`-only initial configuration), to AV-59's extension mechanism itself (this item is the post-funding revision of its bound) and to AV-240's grace-period amendment (a different window); emits `MaxExtensionAmended` (discriminant 111), all amounts zero |
| `amend_timelock(initializer, taker, unlock_at)` (AV-249) | `Funded` | — (no state change; rewrites the absolute timelock) | **both** parties must sign (dual-signature governance — one party alone cannot push out or pull in the other's unlock moment); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); a nonzero `unlock_at` beside a configured relative or slot lock is `InvalidTimelock` (the builder's one-clock rule); `0` is legal and cancels the absolute lock (the builder's "no lock" sentinel, a no-op beside a relative or slot lock); a paused escrow fails fast (`Paused`); only `timelock` changes — `relative_timelock_secs` and `slot_timelock_slots` are untouched, and amounts already released are never restated; the payout gates read the lock live (`is_unlock_eligible` consults the field at call time), so lengthening pushes a payout out, shortening pulls it in, and clearing unlocks immediately, while the unilateral exits and the arbiter's `resolve` stay ungated; orthogonal to the `with_timelock` builder (`Uninitialized`-only initial configuration), to AV-27's timelock gate itself (this item is the post-funding revision) and to AV-64/AV-116's relative and slot locks (different clocks); emits `TimelockAmended` (discriminant 112), all amounts zero |
| `amend_relative_timelock(initializer, taker, secs)` (AV-250) | `Funded` | — (no state change; rewrites the relative timelock window) | **both** parties must sign (dual-signature governance — one party alone cannot push out or pull in the other's unlock moment); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); a nonzero `secs` beside a configured absolute or slot lock is `InvalidTimelock` (the builder's one-clock rule); `0` is legal and cancels the relative lock (the builder's "no lock" sentinel, a no-op beside an absolute or slot lock); a paused escrow fails fast (`Paused`); only `relative_timelock_secs` changes — `timelock` and `slot_timelock_slots` are untouched, `fund_at` (the lock's anchor) never moves, and amounts already released are never restated; the payout gates read the window live (`is_unlock_eligible` consults the field at call time against the unchanged anchor), so lengthening pushes a payout out, shortening pulls it in, and clearing unlocks immediately, while the unilateral exits and the arbiter's `resolve` stay ungated; orthogonal to the `with_relative_timelock` builder (`Uninitialized`-only initial configuration), to AV-64's relative-lock gate itself (this item is the post-funding revision) and to AV-249/AV-116's absolute and slot locks (different clocks); emits `RelativeTimelockAmended` (discriminant 113), all amounts zero |
| `amend_slot_timelock(initializer, taker, slots)` (AV-251) | `Funded` | — (no state change; rewrites the slot timelock window) | **both** parties must sign (dual-signature governance — one party alone cannot push out or pull in the other's unlock slot); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); a nonzero `slots` beside a configured absolute or relative lock is `InvalidTimelock` (the builder's one-clock rule); `0` is legal and cancels the slot lock (the builder's "no lock" sentinel, a no-op beside an absolute or relative lock); a paused escrow fails fast (`Paused`); only `slot_timelock_slots` changes — `timelock` and `relative_timelock_secs` are untouched, `fund_slot` (the lock's anchor) never moves, and amounts already released are never restated; the slot gates read the window live (`slot_unlock_slot` is `fund_slot + slots`, saturating, so a near-`u64::MAX` anchor plus a long lock never wraps into an early unlock), so lengthening pushes a payout out, shortening pulls it in, and clearing unlocks immediately, while the unilateral exits and the arbiter's `resolve` stay ungated; on a tranched-funding escrow the anchor is `0`, so the lock opens at slot `slots` itself (AV-116 semantics); orthogonal to the `with_slot_timelock` builder (`Uninitialized`-only initial configuration), to AV-116's slot-lock gate itself (this item is the post-funding revision) and to AV-249/AV-250's absolute and relative locks (different clocks); emits `SlotTimelockAmended` (discriminant 114), all amounts zero |
| `amend_rent_sweep_grace(initializer, taker, grace_secs)` (AV-252) | `Funded` | — (no state change; rewrites the unclaimed-rent sweep grace period) | **both** parties must sign (dual-signature governance — one party alone cannot push out or pull in the other's sweep horizon); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); any `u64` is legal and `0` is legal (it restores the 30-day default, the builder's `0` semantics, not "sweep immediately"); a paused escrow fails fast (`Paused`); only `rent_sweep_grace_secs` changes — `terminal_at` is never restated, and a terminal or `Closed` vault cannot be amended, so a sweep already performed is never undone; the sweep gate reads the grace live (`is_rent_sweep_eligible` consults `effective_rent_sweep_grace_secs` at sweep time against the unchanged terminal stamp), so lengthening pushes a sweep out, shortening pulls it in, and clearing to `0` restores the 30-day horizon; orthogonal to the `with_rent_sweep_grace_secs` builder (`Uninitialized`-only initial configuration), to AV-139's sweep mechanism itself (this item is the post-funding revision) and to AV-249/AV-250/AV-251's timelock revisions (different gates); emits `RentSweepGraceAmended` (discriminant 115), all amounts zero |
| `amend_fee_schedule(initializer, taker, tiers)` (AV-253) | `Funded` | — (no state change; rewrites the tiered protocol-fee schedule) | **both** parties must sign (dual-signature governance — one party alone cannot reprice the other's fee tiers); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); a nonzero flat `fee_bps` refuses the schedule (mutual exclusion, fail-fast not last-wins, paralleling AV-233's refusal the other way); empty or over-8 tier lists, a tier `bps > 10_000`, or `min_amount` floors not strictly ascending are `InvalidProtocolFee` (the builder's validation, unchanged); a paused escrow fails fast (`Paused`); only `fee_schedule` changes — `fee_bps` and `fee_cap` are untouched (the cap still floors the new schedule's bps fee at computation time) and `fees_paid` / `fees_withdrawn` are untouched (no refunds); the 81-byte schedule region is always resident, so the revision rewrites it in place with the tail slots zeroed and no reallocation; later taker payouts price live through `protocol_fee_for` (highest tier whose `min_amount <= amount`), so a payout reprices at the new tier the moment the amendment lands; orthogonal to the `with_fee_schedule` builder (`Uninitialized`-only initial configuration) and to AV-233's `amend_protocol_fee` (flat rate vs tier schedule, mutually exclusive); emits `FeeScheduleAmended` (discriminant 116), all amounts zero |
| `amend_streaming_fee(initializer, taker, rate)` (AV-254) | `Funded` | — (no state change; rewrites the streaming fee rate in lamports per second) | **both** parties must sign (dual-signature governance — one party alone cannot reprice the other's streaming fee); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); any `u64` is legal and `0` is legal (it disables further accrual, the builder's `0` semantics, not a refund); a paused escrow fails fast (`Paused`); only `streaming_fee_rate` changes — `fund_at` is never restated and `streaming_fees_accrued` / `fees_paid` are never rewritten, so a rate cut can never claw back fees already charged; the charge gate reads the rate live (`charge_streaming_fee` recomputes `theoretical = rate × (accrue_upto − fund_at)` at every payout and bills only the saturating excess over accrued), so raising the rate bills the difference on the next settlement and lowering it bills nothing new; orthogonal to the `with_streaming_fee` builder (`Uninitialized`-only initial configuration), to AV-100's accrual mechanism itself (this item is the post-funding revision) and to AV-233/AV-253's flat/tiered payout fees (this is the per-second streaming rate); emits `StreamingFeeRateAmended` (discriminant 117), all amounts zero |
| `amend_rent_payer(initializer, taker, new_payer)` (AV-255) | `Funded` | — (no state change; rewrites the bound rent payer) | **both** parties must sign (dual-signature governance — one party alone cannot re-point the other's rent); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); a zero payer is `InvalidRentPayer` (the builder's gate, unchanged — a bound payer must be a real key); a paused escrow fails fast (`Paused`); re-affirming the current payer is a no-op (succeeds, writes nothing, emits no event, paralleling `amend_milestones`); only `rent_payer` changes — the close authority is untouched (only the initializer may call `close_vault`), no closed state is touched, and no rent is recomputed (the payer field is already resident, rewritten in place, no layout change); there is deliberately no unbind-to-`None` path (an unbound escrow keeps the initializer-reclaims default); `close_vault` reads the recipient live through `rent_recipient`, so a close after the amendment pays the new payer while a close before it paid the old one; orthogonal to the `with_rent_payer` builder (`Uninitialized`-only initial configuration) and to AV-34's close itself (this item is the close's payee); emits `RentPayerAmended` (discriminant 118), all amounts zero, except for the no-op re-affirmation |
| `amend_referrer(initializer, taker, referrer, referral_bps)` (AV-256) | `Funded` | — (no state change; rewrites the bound referrer and its revenue-share rate) | **both** parties must sign (dual-signature governance — one party alone cannot re-point the other's referral); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); a zero referrer or a rate above `MAX_REFERRAL_BPS` (2000) is `InvalidReferral` (the builder's gates, unchanged); a paused escrow fails fast (`Paused`); re-affirming the current (referrer, rate) pair is a no-op (succeeds, writes nothing, emits no event, paralleling `amend_rent_payer`); only `referrer`/`referral_bps` change — `referral_paid` is never rewritten, so a rate cut can never claw back referral already charged; there is deliberately no unbind-to-`None` path (an unbound escrow keeps the no-referrer default); the release gate reads the binding live through `referral_for`, so a release after the amendment charges the new referrer at the new rate while a release before it charged the old one; orthogonal to the `with_referrer` builder (`Uninitialized`-only initial configuration) and to AV-191's referral mechanism itself (this item is the post-funding revision); emits `ReferrerAmended` (discriminant 119), all amounts zero, except for the no-op re-affirmation |
| `amend_penalty_escalation(initializer, taker, rate_bps_per_day, cap_bps)` (AV-257) | `Funded` | — (no state change; rewrites the penalty escalation schedule) | **both** parties must sign (dual-signature governance — one party alone cannot retune the other's delay meter); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); a rate or cap above `10_000` is `InvalidPenalty` (the builder's gate, unchanged — the rate can never exceed 100%); a paused escrow fails fast (`Paused`); re-affirming the current (rate, cap) pair is a no-op (succeeds, writes nothing, emits no event, paralleling `amend_referrer`); only `penalty_escalation_rate_bps`/`penalty_escalation_cap_bps` change — the AV-24 base `penalty_bps` is never restated and the meter origin (`expires_at` + grace) never moves; the cancel gate reads the schedule live through `effective_penalty_bps`, so a cancel after the amendment prices from the new schedule while a cancel before it priced from the old one; orthogonal to the `with_penalty_escalation` builder (`Uninitialized`-only initial configuration) and to AV-115's escalation mechanism itself (this item is the post-funding revision); emits `PenaltyEscalationAmended` (discriminant 120), all amounts zero, except for the no-op re-affirmation |
| `amend_refund_address(initializer, taker, new_refund_to)` (AV-258) | `Funded` | — (no state change; rewrites the whitelisted refund address) | **both** parties must sign (dual-signature governance — one party alone cannot re-point the other's refund); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); a zero address is `RefundAddressMismatch` (the builder's gate, unchanged — a zero key can never be a legitimate refund destination); a paused escrow fails fast (`Paused`); re-affirming the current effective recipient (the whitelist when set, else the initializer) is a no-op (succeeds, writes nothing, emits no event, paralleling `amend_referrer`); only `refund_to` changes — the initializer/taker identities are never restated and no settled refund is ever rewritten; there is deliberately no unbind-to-`None` path (callers that want the default route pass the initializer's key); the cancel paths read the address live through `refund_recipient` (`refund_to.unwrap_or(initializer)`) and `require_refund_recipient` checks the live address, so a cancel after the amendment routes to the new address while a cancel before it routed to the old one; orthogonal to the `with_refund_address` builder (`Uninitialized`-only initial configuration), to `update_payout_allowlist` (that is the taker-payout direction, this item is the initializer-refund direction) and to `rotate_fee_recipient` (that is the protocol-fee recipient, this item is the refund address); emits `RefundAddressAmended` (discriminant 121), all amounts zero, except for the no-op re-affirmation |
| `amend_penalty_bps(initializer, taker, penalty_bps)` (AV-259) | `Funded` | — (no state change; rewrites the base anti-griefing penalty rate) | **both** parties must sign (dual-signature governance — one party alone cannot retune the other's delay meter); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); a rate above `10_000` is `InvalidPenalty` (the builder's gate, unchanged — the rate can never exceed 100%); `0` is legal (it switches the penalty off, the builder's `0` semantics, not a refund); a paused escrow fails fast (`Paused`); re-affirming the current rate is a no-op (succeeds, writes nothing, emits no event, paralleling `amend_penalty_escalation`); only `penalty_bps` changes — the AV-115 escalation rate/cap are never restated and the meter origin (`expires_at` + grace) never moves; the cancel gate reads the base rate live through `effective_penalty_bps` (with the escalation headroom recomputed as `cap − new base`), so a cancel after the amendment prices from the new rate while a cancel before it priced from the old one; orthogonal to the `with_penalty_bps` builder (`Uninitialized`-only initial configuration), to AV-257 (that is the escalation schedule, this item is the base rate) and to AV-216 (that is the late-delivery penalty, this item is the expiry-cancel penalty); emits `BasePenaltyAmended` (discriminant 122), all amounts zero, except for the no-op re-affirmation |
| `amend_interest_rate(initializer, taker, rate_bps)` (AV-260) | `Funded` | — (no state change; rewrites the interest rate in basis points) | **both** parties must sign (dual-signature governance — one party alone cannot retune the other's yield); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set; the dispute window settles at the frozen rate, so a mid-dispute retune would rewrite the adjudicated yield); a rate above `10_000` is `InvalidInterestRate` (the builder's gate, unchanged — the rate can never exceed 100% APR); `0` is legal (it pauses all future accrual, the builder's `0` semantics, not a forfeiture — and because `settle_interest` returns early at rate 0 without advancing `interest_accrual_base`, a paused window is repriced at the resumed rate on the next settlement, never skipped); a paused escrow fails fast (`Paused`); re-affirming the current rate is a no-op (succeeds, writes nothing, emits no event, paralleling `amend_penalty_bps`); only `interest_rate_bps` changes — `interest_accrued`/`interest_paid`/`interest_compounded`/`interest_accrual_base` are never restated, so a rate cut can never claw back yield already accrued, and in compound mode the folded yield stays principal with the next accrual pricing the grown principal at the new rate; the accrual clock reads the rate live through `settle_interest`, so a new rate prices the next slice the moment the amendment lands; orthogonal to the `with_interest` builder (`Uninitialized`-only initial configuration), to AV-107 (that is the accrual mechanism itself, this item is the rate) and to AV-117 (that is the compounding mode, this item is the rate); emits `InterestRateAmended` (discriminant 123), all amounts zero, except for the no-op re-affirmation |
| `amend_price_gate(initializer, taker, gate)` (AV-261) | `Funded` | — (no state change; rewrites the oracle price gate wholesale) | **both** parties must sign (dual-signature governance — one party alone cannot retune the other's market condition); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only a gate already configured may be revised — an ungated escrow is `InvalidPriceGate` (fail-closed: post-funding installation would add a release restriction the taker never funded under); there is deliberately no clearing path (the signature takes a `PriceGate` by value, never an `Option`, so a configured gate cannot be removed to `None`); a `target == 0` is `InvalidPriceGate` (the builder's gate, unchanged — a zero threshold can never be a deliberate policy); a paused escrow fails fast (`Paused`); re-affirming the current gate is a no-op (succeeds, writes nothing, emits no event, paralleling `amend_interest_rate`); the revision replaces the gate wholesale — `direction`, `target` and `max_staleness_secs` together, never partially; the 18-byte gate region is already resident, so the revision rewrites it in place with no layout change; the gated payout paths read the gate live through `require_price_gate`, so a new gate governs the next `release_price_gated` / `claim_price_gated` the moment the amendment lands, while a payout already settled keeps the gate it settled under, and the gated routing itself never changes; orthogonal to the `with_price_gate` builder (`Uninitialized`-only initial configuration), to AV-113 (that is the gate mechanism itself, this item is its parameters) and to AV-128 (that is the TWAP gate — a separate gate struct and region, untouched by this revision); emits `PriceGateAmended` (discriminant 124), all amounts zero, except for the no-op re-affirmation |
| `amend_twap_gate(initializer, taker, gate)` (AV-262) | `Funded` | — (no state change; rewrites the TWAP price gate wholesale) | **both** parties must sign (dual-signature governance — one party alone cannot retune the other's market condition); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition` (the builder owns the initial set); only a gate already configured may be revised — a TWAP-ungated escrow is `InvalidTwapGate` (fail-closed: post-funding installation would add a release restriction the taker never funded under); there is deliberately no clearing path (the signature takes a `TwapGate` by value, never an `Option`, so a configured gate cannot be removed to `None`); a `window_slots == 0` or `target == 0` is `InvalidTwapGate` (the builders' gate, unchanged — a zero window is a single-point gate in disguise and a zero threshold can never be a deliberate policy); a paused escrow fails fast (`Paused`); re-affirming the current gate is a no-op (succeeds, writes nothing, emits no event, paralleling `amend_price_gate`); the revision replaces the gate wholesale — `direction`, `target`, `window_slots` and `max_staleness_secs` together, never partially; the 26-byte gate region is already resident, so the revision rewrites it in place with no layout change; the gated payout paths read the gate live through `require_twap_gate`, so a new gate governs the next `release_twap_gated` / `claim_twap_gated` the moment the amendment lands — including the full-window history coverage requirement — while a payout already settled keeps the gate it settled under, and the gated routing itself never changes; orthogonal to the `with_twap_gate` / `with_twap_gate_and_staleness` builders (`Uninitialized`-only initial configuration), to AV-128 (that is the TWAP gate mechanism itself, this item is its parameters) and to AV-261 (that is the single-point gate — a separate gate struct and region, untouched by this revision); emits `TwapGateAmended` (discriminant 125), all amounts zero, except for the no-op re-affirmation |
| `amend_slash_ladder(initializer, taker, new_rungs, now)` (AV-237) | `Funded` | — (no state change; rewrites the slash ladder's future rungs) | **both** parties must sign (dual-signature governance — one party alone cannot reprice the other's default penalty); `Uninitialized`, terminal states and `Disputed` are `InvalidStateTransition`; no ladder configured is `InvalidSlashLadder`; the first `consumed` rungs (the cursor is the next rung's index) must equal the old ladder rung-by-rung, the new table must hold at least `consumed` rungs and at most 8, the whole table must stay strictly ascending in deadline and bps with each bps ≤ 10_000, and every future rung's deadline must not predate `now` (no backdating into eligibility) — every violation is `InvalidSlashLadder` (code 184) and leaves the escrow untouched; the penalty account, the penalty already paid, and the consumption cursor are untouched, so the next slash prices from the new rung at the same cursor; a corrupt cursor past the old rung count saturates rather than indexing out of bounds; orthogonal to the `with_slash_ladder` builder (`Uninitialized`-only initial configuration) and to AV-126 (consumption/cursor semantics, unchanged); emits `SlashLadderAmended` (discriminant 101), all amounts zero |
| `with_release_cooling(cooling_secs)` (AV-112) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; builder-style like the other `with_*` opt-ins); `cooling_secs = 0` means unconfigured — `release` is ungated, exactly like AV-21's grace-period convention |
| `announce_release(authority, now)` (AV-112) | `Funded` | `Funded` | initializer or taker (either party, no delegation); full check sequence — pause → authority → state; stamps `release_intent_at = now` (re-announce overwrites — idempotent); touches the AV-109 deadman clock (party liveness); emits `ReleaseIntentAnnounced` |
| `veto_release(caller, now)` (AV-112) | any non-`Closed` | unchanged | initializer or taker (either party); full check sequence — pause → authority → state; clears `release_intent_at`; no intent is a no-op success; touches the deadman clock; emits `ReleaseIntentVetoed` |
| `initialize_reference(reference)` (AV-53) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; the 32-byte off-chain correlation id — order id / invoice hash; any 32 bytes accepted — read-only pass-through: never read by a check gate, never cleared, never affects amount conservation) |
| `split_escrow(initializer, taker, amounts, vesting, quorum, dual_sig, milestones)` (AV-81) | `Funded` | `Split` (new terminal state) | **both** the initializer and the taker must sign (dual-signature governance — one party alone or a stranger pair is `Unauthorized`; degenerate initializer == taker self-escrow authorizes with one key passed twice); `Disputed` is `InvalidStateTransition` (arbitration in flight adjudicates the locked funds) and every terminal state rejects a re-split; the amount table must be non-empty, hold at most 16 entries, contain no zero entry, and sum in `u128` to exactly the parent's remaining lockup (`InvalidSplit`, code 142, otherwise — a partial release before the split shrinks the splittable pool); each child is born `Funded` with the parent's initializer / taker / `expires_at` and the explicitly inherited config — vesting / quorum / dual-sig / per-child milestones are *not* inherited unless named (default-inert, anti-misconfiguration); child *i*'s escrow ID derives as `H(parent_id \|\| i)` (SHA-256, `u64` little-endian index); every gate and child build runs before the parent's state flips (a failed child build leaves the parent in `Funded` — no half-split); emits `EscrowSplit` (`Funded -> Split`, `amounts.payout` = Σ child amounts, the `(child_id, amount)` roster rides the event) |
| `close_vault(authority)`                    | `Cancelled` / `Released` / `Settled` / `Split` (AV-81) | `Closed` | initializer **only** (`Unauthorized` otherwise, checked before state validity); reclaims the rent-exempt deposit — `Disputed` cannot be closed, `Closed` is the deepest terminal (no transition leaves it); a split parent's funds were re-homed into the children, so its vault carries nothing but the rent deposit — closeable like the other terminals |
| `close_vaults(escrows, initializer, taker, filter)` (AV-79) | `Cancelled` / `Released` / `Settled` / `Split` (per vault) | `Closed` (per closed vault) | **off-chain batch** — no new on-chain instruction (each close is one `close_vault` instruction the initializer submits; the Anchor skeleton is unchanged). Every vault must name the same initializer **and** taker (dual-party binding; a mismatch fails that item with `Unauthorized`); `CloseVaultsFilter` selects by state / `expires_at` cutoff / amount range (non-matching vaults are *skipped*, reported — not failed); per-vault failure isolation — one vault's rejection never aborts the batch, and a paused vault fails with `Paused` (AV-46, per-vault gate inherited from `close_vault`); the rent-exempt deposit is summed across the batch via `vault_close_rent_reclaimed()` (never hardcoded); the indexed variant emits one `VaultClosed` per closed vault plus a single `VaultsBatchClosed` summary on the first closed vault's log |
| `release_and_close(authority, now, payout_to)` (AV-50) | `Funded` | `Closed` (via `Released`) | initializer; releases the **full remaining lockup** to the taker and closes the vault in the **same instruction** — one signature instead of two; the payout policy, quorum, timelock and mint gates all apply as on `release`; either leg failing aborts the whole instruction (state/counters/events roll back); emits `Released` then `VaultClosed` in that order; returns `(taker_payout, fee, rent_reclaimed)` |

Rules: the initializer drives `fund`/`release`/`cancel`; any other caller
gets `Unauthorized` (checked before state validity). An escrow that has
timed out (`now >= expires_at + grace_period`) may instead be cancelled by
*either* party via `cancel_expired`, so a stalled counterparty cannot lock
funds forever; calling it early gets `NotExpired`. The opt-in grace period
(`with_grace_period`, seconds, `0` by default) absorbs clock drift between
an off-chain keeper and the Solana cluster — without it a keeper whose
clock runs ahead would submit `cancel_expired` the moment *its* clock
passes `expires_at`, only for the chain to reject it. Pass `u64::MAX` as
`expires_at` for no timeout (a grace period cannot be combined with it:
`InvalidGracePeriod`, code 115). Any illegal transition (e.g. releasing
twice, releasing before funding) gets `InvalidStateTransition`; zero
amounts get `AmountMismatch`; `release`/`cancel`/`cancel_expired` preserve
`amount` exactly (refund
accounting).

**Refund address whitelist (anti-phishing).** An escrow can declare a
refund address (`with_refund_address`, opt-in on `Uninitialized`; the zero
address is rejected). After that, `cancel` / `cancel_expired` take the
refund destination explicitly and the state machine pins it against the
whitelist (`RefundAddressMismatch`, code 116, otherwise) — the refund can
only ever go to the declared address, so a phishing frontend cannot
redirect it by swapping the destination account in the cancel instruction.
With no whitelist the policy is "refund to the initializer" (backward
compatible), and even a taker-initiated `cancel_expired` refunds to the
declared address, never to the caller: the caller authorizes the cancel,
the whitelist authorizes the destination. The whitelist covers the
unilateral refund paths only; the arbiter's `resolve` split keeps its
existing semantics by design.

**Anti-griefing penalty (taker-initiated expiry cancel).** An escrow can
opt into a penalty rate (`with_penalty_bps`, basis points, `0`–`10000`,
`0` by default) charged when the *taker* calls `cancel_expired` — the
taker dragging the deal to expiry otherwise locks the initializer's
capital for free. The cancel returns `(refund, penalty)` with
`refund + penalty == remaining`: the refund goes to the whitelisted
destination, the penalty (`floor(remaining * penalty_bps / 10000)`,
computed in `u128` so it cannot overflow) is routed to the initializer
as griefing compensation. An initializer-initiated `cancel_expired`
returns `(remaining, 0)` — the initializer pays no penalty to reclaim
their own funds — and neither `cancel` nor the arbiter's `resolve`
carry one. With a refund whitelist pointing elsewhere, the penalty
still routes to the initializer personally: the compensation follows
the harmed party, not the refund address. `InvalidPenalty`, code 117,
rejects rates above 10_000.

**Penalty escalation (time-weighted anti-griefing).** An escrow can
additionally opt into time-weighted escalation of the penalty
(`with_penalty_escalation(rate_bps_per_day, cap_bps)`, both in basis
points, `0`–`10000`, once, before funding; a `0` rate — the default —
disables escalation and keeps the fixed AV-24 rate). The effective
rate starts at `penalty_bps` and grows by `rate_bps_per_day` for every
whole day elapsed past the expiry gate (`expires_at + grace_period`),
capped at `cap_bps`: `effective = min(penalty_bps + rate_bps_per_day ×
days_late, cap_bps)`, and the cancel charges `floor(remaining ×
effective / 10000)` (u128 math, no overflow). A cancel within the
first 24 hours past the gate still pays exactly the AV-24 rate; the
cap never *reduces* the base rate — a `cap_bps` below `penalty_bps`
degrades to the fixed rate. The basket `cancel_expired_basket` path
escalates identically. The keeper report discloses the escalated
penalty estimate (`penalty_estimate`) on `cancel_expired` /
`crank_expired` actions so operators watch the meter grow, and the
state snapshot exposes the schedule (`penalty_escalation_rate_bps` /
`penalty_escalation_cap_bps`) for indexers.

**Timelock.** An escrow can opt into a timelock (`with_timelock(unlock_at)`,
once, before funding; `unlock_at` is a Unix timestamp, `0` = no lock). After
that, every taker payout path — `release`, `claim`, and `release_milestone`
— requires `now >= unlock_at` (`TimelockNotReached`, code 118, otherwise),
where `now` comes from the Solana clock sysvar, never from an instruction
param (a caller-supplied timestamp would let the initializer fast-forward
the lock they configured). The lock gates only *payouts*: `cancel`,
`cancel_expired`, and the arbiter's `resolve` are deliberately not gated, so
a misconfigured or abandoned timelock can never trap funds forever — after
`expires_at` either party still walks the `cancel_expired` path, and a live
dispute still settles via arbitration. The keeper report lists a `claim`
action only once the timelock is unlocked, and the state snapshot exposes
`unlock_at` / `unlock_eligible` for indexers.

**Relative timelock.** An escrow can instead opt into a *relative* timelock
(`with_relative_timelock(secs)`, once, before funding; `secs` is a duration
in seconds, `0` = no lock). After that, every taker payout path — `release`,
`claim`, and `release_milestone` — requires `now >= fund_at + secs`
(`TimelockNotReached`, code 118, otherwise), where `fund_at` is the clock
`fund` recorded: the lock is anchored at funding, not at a fixed
wall-clock timestamp — the right shape when the deal's clock starts when
the money lands (e.g. "payouts unlock 30 days after funding", negotiated
before anyone knows the funding date). The two locks are mutually exclusive
— one clock per escrow: configuring both is `InvalidTimelock`, code 135, in
either builder order (the zero sentinels stay order-independent no-ops).
Like the absolute lock, the relative lock gates only *payouts*: `cancel`,
`cancel_expired`, and the arbiter's `resolve` are deliberately not gated, so
a misconfigured lock can never trap funds forever. The dual-signed
`emergency_unlock` clears the relative lock exactly like the absolute one.
The snapshot exposes `relative_timelock_secs` / `fund_at` for indexers, so
they compute the same unlock time the chain enforces.

**Slot-based relative timelock.** An escrow can instead opt into a
*slot-based* relative timelock (`with_slot_timelock(slots)`, once, before
funding; `slots` is a duration in slots, `0` = no lock). After that, every
taker payout path — `release`, `claim`, and `release_milestone` — requires
`slot >= fund_slot + slots` (`TimelockNotReached`, code 118, otherwise),
where `fund_slot` is the clock sysvar's slot `fund` recorded and `slot` is
the sysvar's slot at the payout call (never an instruction param — a
caller-supplied slot would let the initializer fast-forward the lock they
configured). The lock is measured in slots, not seconds: chain slot
progression is the one clock no validator can skew, so a slot lock is
immune to the wall-clock drift the second-based locks inherit from
`unix_timestamp`. The three locks are mutually exclusive — one clock per
escrow: a nonzero slot lock together with either second-based lock is
`InvalidTimelock`, code 135, in either builder order. Like the other locks,
the slot lock gates only *payouts*: `cancel`, `cancel_expired`, and the
arbiter's `resolve` are deliberately not gated. The pure-logic side takes
a pluggable `SlotClock` (tests inject a deterministic `StaticSlotClock`);
the snapshot exposes `slot_timelock_slots` / `fund_slot` and the keeper
report discloses the unlock slot (`slot_unlock_at`) so operators compare
it against the chain tip.

**Per-taker claim cooldown.** An escrow can opt into a *claim cooldown*
(`with_claim_cooldown(slots)`, once, before funding; `slots` is the minimum
slot distance between two taker `claim` calls, `0` = no cooldown). After
that, the taker's second and later claims require `slot >= last_claim_slot
+ slots` (`InvalidClaimCooldown`, code 179, inside the window), where
`last_claim_slot` is the clock sysvar's slot the previous successful claim
recorded and `slot` is the sysvar's slot at the claim call (never an
instruction param — a caller-supplied slot would let the taker
fast-forward the cooldown). The first claim is always eligible. The
cooldown is measured in slots, the same slot semantics as the AV-116 slot
timelock — the point is anti-spam: a taker cannot machine-gun `claim`
instructions to grief the initializer with priority-fee bidding wars. The
keeper's cooldown scan (`scan_claim_cooldown`) reports claims stuck inside
the window as blocked with reason `claim_cooldown` and the eligible slot,
so operators see exactly when the next claim unlocks. The snapshot exposes
`claim_cooldown_slots` / `last_claim_slot` for indexers.

**Taker decline + counter-offer negotiation.** Before any claim, the taker
can walk away (`decline_escrow`, taker-only) — the escrow moves to the
terminal `Declined` state and the initializer retires the vault via
`close_vault` to reclaim the rent. Alternatively the taker can propose new
deal terms (`propose_counter_offer`, taker-only, params `amount` +
`expiry`): a zero amount or a non-future expiry is `InvalidCounterOffer`
(code 180), otherwise the offer is stored and the escrow moves to
`CounterOffered`. While the offer is live, fund movements and `escalate`
are frozen — the initializer must answer: `accept_counter_offer`
(initializer-only) atomically re-sets `amount`/`expires_at` to the offered
terms and returns to `Funded`, or `reject_counter_offer` (initializer-only)
drops the offer and returns to `Funded` with the original terms. The
four transitions emit `Declined` / `CounterOfferProposed` /
`CounterOfferAccepted` / `CounterOfferRejected` (discriminants 62–65). The
taker may also revise their own live offer in flight
(`amend_counter_offer`, AV-285, taker-only, `CounterOffered`-only): the
new terms reuse the propose gates and only the stored offer moves — the
deal amount, expiry, and state are untouched, so the initializer still
answers via accept or reject, and the next accept re-prices under the
amended terms; a paused escrow fails fast, and re-affirming the identical
terms is a silent no-op. The revision emits `CounterOfferAmended`
(discriminant 147), all amounts zero. The
negotiation is orthogonal to the AV-103 appeal bond and the dispute flow —
a `CounterOffered` escrow cannot be disputed.

**Compound-interest accrual.** An interest-bearing escrow can opt into
*compound* mode (`with_compound_interest()`, once, before funding). When
on, the accrued yield folds into the principal at every claim/settlement
— `release`, `claim`, `release_milestone`, and the dispute settlements —
instead of being paid out as a separate yield leg: `amount +=
interest_accrued`, `interest_compounded += interest_accrued`, the claim
zeroes, and the next accrual prices the grown principal (interest earns
interest, computed in `u128` with a `checked_add` backstop — a wrapping
principal is a hard failure, never a wrap). The mode is mutually exclusive
with the standalone harvest: `claim_interest` on a compound escrow is
`CompoundInterestActive`, code 178 — a separate harvest would double-count
yield earmarked for the principal. The cumulative folded yield lives in
`interest_compounded`, so the extended conservation identity
(`inflow + yield == locked + released + refunded + interest_paid +
dispute_interest`, with `yield == interest_accrued + interest_paid +
interest_compounded + dispute_interest`) stays
exact, and the snapshot exposes `compound_interest` / `interest_compounded`
for indexers. Builder order is irrelevant: opting in before `with_interest`
is accepted but inert while the rate is zero (nothing to compound).

**Dispute-interest attribution.** When a dispute settles, the locked funds
kept earning while arbitration ran: the dispute window
`[disputed_at, resolved_at]` accrues interest on the locked remainder at
the AV-107 rate (`resolved_at` comes from the clock sysvar — never an
instruction param, like `release_milestone`'s `now`). The *entire*
outstanding yield claim — the frozen pre-dispute claim plus the window
accrual — is then attributed to the ruling's winner, pro-rata by the
taker's principal share `taker_amount / remaining`: a taker full win takes
interest + principal (the pre-AV-119 behavior, unchanged), an initializer
full win refunds the whole claim with the principal, and a partial ruling
splits it (`taker_share = total * taker_amount / remaining`, floor
division; the initializer takes the remainder, so no lamport is created
or destroyed). The taker's share rides the taker payout into
`interest_paid` (fee-free, the AV-107 taker sink — its meaning is
unchanged); the initializer's share rides the refund into the new
`dispute_interest` audit sink, extending the conservation identity to
`inflow + yield == locked + released + refunded + interest_paid +
dispute_interest` (with `yield == interest_accrued + interest_paid +
interest_compounded + dispute_interest`). All three settlement paths —
`resolve`, the panel's settling vote, and `trigger_default_judgment` —
run the same shared helper, so the attribution cannot fork between them;
on a compound-interest escrow the yield folds into the principal instead
(the AV-117 mutual exclusion, `CompoundInterestActive` code 178) and both
legs are zero. The settlement events keep recording the principal legs —
the yield attribution stays observable via the counters and the snapshot
(`dispute_interest` is exported there).

**Emergency timelock unlock.** An escrow can additionally opt into
dual-signed emergency governance (`with_emergency_unlock()`, once, before
funding). When both parties agree the lock has outlived its purpose — a
renegotiated deal, a wrong `unlock_at`, counterparties who both want out
early — `emergency_unlock(initializer, taker)` clears the timelock
immediately: both the initializer and the taker must sign (one party alone
is `Unauthorized`), the escrow must be `Funded`, the governance must be
opted in, and an active timelock must exist (`InvalidStateTransition`
otherwise). The timelock clears to `0`, so `release` / `claim` /
`release_milestone` become immediately eligible — state and amounts are
untouched, and the `EmergencyUnlock` event (from == to == the current
state) records the governance decision for indexers. Check order is
authority → state → governance config, so a stranger learns nothing about
the escrow's configuration from the error alone.

**Token decimals.** An escrow can declare its SPL mint's decimal places
(`with_decimals(decimals)`, once, before funding; SPL mints declare at most
9, and `decimals > 18` is rejected as `InvalidDecimals`, code 119 —
`decimals == 0` means no metadata, the default). The metadata never gates a
transition and never moves funds: it only renders human-readable amounts —
`Escrow::display_amount()` (`1_000_000` raw units at 6 decimals →
`"1.000000"`), the keeper report's per-action `display_amount`, and the
state snapshot's `decimals` / `display_*` fields. Raw fields stay untouched,
so indexers keep diffing numbers while payment operators read whole tokens.

**Partial release (staged payouts).** `release(authority, now, amount)` releases
in tranches: each call adds to a cumulative `released` counter and leaves
the escrow `Funded`; when the cumulative total reaches the locked amount
the escrow moves to `Released`. Cumulative releases must never exceed the
locked amount (`ReleaseExceedsLocked`, code 106); a zero-amount release is
`AmountMismatch`. `released_amount()` / `remaining_amount()` expose the
progress, and `cancel` / `cancel_expired` after partial releases refund
only the remainder while `released_amount()` stays preserved for audit.

**Partial cancel (initializer tranche refund, AV-60).** `cancel_partial(authority, amount, refund_to)` is the
initializer's counterpart to partial release: it walks the lockup back to the
initializer in tranches instead of streaming it to the taker. The escrow stays
`Funded` at the reduced lockup; `released_amount()` is untouched; the refund
follows the whitelist pin below. `amount == 0` is `AmountMismatch`; an
`amount` above the still-locked remainder is `ReleaseExceedsLocked`. Like
`cancel`, quorum / timelock / vesting do not gate it, and the indexer sees one
`PartiallyCancelled` event per call.

**Attestor quorum (weighted release gate, AV-45).** An escrow can be created with an
optional quorum policy (`QuorumPolicy::new(attestors, weights, threshold)`,
up to 8 attestors, heap-free bitmask): `initialize_quorum` attaches it once,
before funding; registered attestors record idempotent attestations via
`attest` in `Uninitialized` or `Funded`. Each attestor carries a vote
weight, and `release` then additionally requires the *accumulated weight*
of distinct attestations to reach the weight-sum `threshold`, else
`QuorumNotReached` — a heavy voter (e.g. an arbiter) can meet the threshold
alone while light voters must combine. Check order is authority → state →
quorum, so strangers learn nothing about attestation progress. Deliberately,
the quorum gates *release only*: `cancel` and `cancel_expired` stay ungated
so attestors cannot grief funds into a lockup by withholding approval.
Without a quorum the escrow behaves exactly as the plain two-party machine
above. Zero weights, weight/length mismatches, weight-domain overflow, and
a threshold of `0` or above the total weight are all `InvalidQuorum`.

**Quorum threshold governance (dual-signed).** The quorum threshold is
fixed before funding — but attestors can go dark (a lost key, an
unresponsive oracle), which would lock the funds behind an unreachable
threshold forever. `update_quorum(initializer, taker, threshold)` lets
*both* parties move the weight-sum threshold together, on an
`Uninitialized` or `Funded` escrow: lower it to restore liveness, or raise
it by mutual agreement when they want a stricter gate. One party alone gets
`Unauthorized` — the gate can never be weakened unilaterally. The attestor
set, their weights, and recorded votes are untouched; only the threshold
moves, in place, so the account layout never changes. If the new threshold
is at or below the current approved weight, `release` becomes legal
immediately — that is the intended unlock. `0`, above the total registered
weight, or no quorum configured is `InvalidQuorum`; the change emits a
`QuorumUpdated` indexer event (no-op re-affirmations emit nothing).

**Attestor set governance (dual-signed).** The quorum's *electorate*
moves by the same dual-signed mechanism: `update_attestors(initializer,
taker, attestors, weights)` replaces the registered attestor set — and
their vote weights — on an `Uninitialized` or `Funded` escrow, when both
parties agree. A registered attestor can go rogue (a compromised oracle
key) or dark — without this, its vote or veto would outlive its
trustworthiness forever. One party alone gets `Unauthorized`: swapping the
electorate for sockpuppets would be a unilateral weakening of the release
gate, so the set can only be reshaped by mutual agreement, exactly like the
AV-25 threshold move. The attestor array is a fixed 8-slot reservation,
so add/remove compacts into the slots in place — the account layout
never changes, rent is untouched. Recorded votes follow their pubkeys,
not their slots: approval bits remap to the new indices, so a retained
attestor keeps its vote (counted at its *new* weight) and a removed
attestor's bit is cleared (a stale bit would otherwise be misattributed to
whatever key lands in the compacted slot, crediting the wrong voter). The
weight-sum threshold is unchanged by a set swap — if the old threshold no
longer fits the new total weight that is `InvalidQuorum`, so move the
threshold first (AV-25) and then the set. Empty sets, more than 8 keys,
duplicates, weight/length mismatches, and zero weights are `InvalidQuorum`
too. Passing the identical set with identical weights succeeds as a no-op;
a real set change emits an `AttestorsUpdated` indexer event (no-op updates
emit nothing, mirroring `update_quorum`).

**Attestor key rotation (AV-154).** When a registered attestor's key is
compromised or lost, the two parties can rotate it in place with
`replace_attestor(initializer, taker, slot, new_attestor)` — dual-signed
governance on `Uninitialized`/`Funded`, the same check order as
`update_quorum` (authority → state → slot → key). The slot keeps its vote
weight (only the key changes, so the threshold still fits — no threshold
move needed) and the 8-slot reservation is untouched (no realloc, no rent
change). The critical difference from `update_attestors`: the rotated
slot's recorded approval is **cleared** — a compromised key's vote must not
transfer to its replacement, so the new key starts counting from zero.
This is the key-compromise response (rotate the key, don't lower the
threshold): the electorate's voting power is unchanged but the suspect key
loses its vote immediately. An unoccupied slot or a zero replacement key is
`AttestorSlotInvalid`; a key already voting at another slot is
`InvalidQuorum` (one key, one vote). Rotating to the already-registered key
is a no-op success (the vote is preserved); a real rotation emits an
`AttestorReplaced` indexer event.

**Dual-signature activation (multisig escrow).** An escrow can require
*two* signatures to activate (`with_dual_sig`, opt-in on `Uninitialized`,
like the quorum builder): each party — initializer and taker — records
their approval with `activate`, and only when *both* bits are set does the
escrow move `Uninitialized → Activated`, unlocking `fund`. One signature
can create the escrow but never fund it. `activate` is idempotent per
party and rejects strangers with `Unauthorized` (checked before state
validity); on a plain escrow, or once already `Activated`, it is
`InvalidStateTransition`. Activation progress is a persisted 1-byte
bitmask (bit 0 initializer, bit 1 taker, bit 2 requirement), so it
survives serialization; `attest` is allowed in `Activated` too, so
attestors can vote between activation and funding. Composes with the
quorum builder: activation gates `fund`, quorum gates `release`.

**Streaming release (linear vesting).** An escrow can attach a vesting
schedule (`VestingSchedule::new(start, end)`, opt-in on `Uninitialized`,
like the quorum builder): the locked amount unlocks linearly between
`start` and `end`, and the taker pulls the vested-but-unreleased portion
at any time with `claim(authority, now)` — the streaming-payments
pattern (salary streams, linear token unlocks). AV-51 adds an optional
**cliff** (`with_vesting_cliff(start, end, cliff_at)`): before the cliff
nothing unlocks, and at/after the cliff the linear curve from `start`
applies unchanged — the cliff gates unlocking, it does not rebase the
curve, so there is no unlock jump at the cliff. `claim` before the cliff
computes a zero claimable and reports `AmountMismatch` (no extra gate —
the zero falls out of the curve), and the keeper's claim scan inherits
the gate through the same computation. `cliff_at > end` is
`InvalidVesting` (funds that could never vest); a cliff at or before
`start` is the no-cliff schedule. `claim` returns the
claimed amount so the program can size the transfer; claims accumulate in
the same `released` counter as `release`, so conservation and audit stay
unified, and the escrow moves to `Released` once everything is out. Only
the taker may claim (`Unauthorized` otherwise); `claim` needs `Funded`
state and a configured schedule (`InvalidVesting` when `start >= end` or
no schedule), and a configured quorum gates `claim` exactly like
`release` — otherwise the taker could bypass attestation. Claiming with
nothing newly vested is `AmountMismatch` (paralleling zero-amount
release). The initializer keeps the `release` push path and may release
ahead of the curve; the schedule itself is fixed at funding except through the dual-signed amendment below, and
`cancel` / `cancel_expired` still refund the unreleased remainder.

**Vesting schedule amendment (AV-230).** A timeline fixed at funding cannot follow a deal whose unlock window changes — a cliff moves, the vesting window stretches. `amend_vesting_schedule(initializer, taker, schedule, now)` (`Funded`-only, dual-signed) revises the linear table mid-deal: only the still-unvested part may be reshaped, because the new schedule must vest at least the amount already claimed at `now` (`released`, the counter `claim` accumulates) — a revision that vested less would rewrite a settled deal backwards, so it fails with `InvalidVesting` and the schedule is untouched. A schedule-less escrow has nothing to amend (amendment never creates a schedule), and the new table itself must be a valid `VestingSchedule` (its constructors already reject inverted windows and cliffs past the end). An attached non-linear curve keeps pricing against the new window, and a vesting pause keeps applying to the amended schedule (a later resume shifts the new window). Later `claim` pulls price against the amended table. The `VestingScheduleAmended` event (discriminant 94) carries no amounts; the amended schedule is read from the vault.
**Milestone due-date amendment (AV-231).** A settlement calendar fixed at funding cannot follow a deal whose deliverables slip — a milestone moves, its deadline must move with it, without reopening the amounts. `amend_milestone_due_dates(initializer, taker, due_at[], now)` (`Funded`-only, dual-signed) revises the AV-206 deadline table mid-deal: only unsettled tranches move, because a released or skipped tranche keeps its original `due_at` verbatim (its deadline already priced any late penalty at release time), and the submitted table must match the tranche count. Every new due for an unsettled tranche must be no earlier than `now` — a deadline moved into the past would make the tranche instantly late and ambush it with a penalty on the next release — and the final table, retained settled dues plus new unsettled dues, must stay strictly increasing, so a moved deadline can never overtake its predecessor. A table-less escrow has nothing to amend (amendment never creates a table), a failed amendment leaves the table untouched, and the AV-206 penalty rate and AV-225 claim deadlines are untouched. Later `release_milestone` calls price late penalties against the amended dates. The `MilestoneDueDatesAmended` event (discriminant 95) carries no amounts; the amended table is read from the vault.

**Protocol-fee amendment (AV-233).** A fee fixed at funding cannot follow a deal whose economics change — a larger deal may justify a lower rate, a smaller one a higher one. `amend_protocol_fee(initializer, taker, fee_bps, fee_cap)` (`Funded`-only, dual-signed) revises the flat rate and the per-payout cap atomically mid-deal: only later taker payouts reprice, because `protocol_fee_for` reads the live fields, while `fees_paid` and every fee already charged are never repriced. A rate past 100% fails with `InvalidProtocolFee`, and a tiered-schedule escrow refuses the amendment outright — the flat rate and the schedule are mutually exclusive, and pricing from the schedule whenever one is configured means a flat amendment there would be silently discarded. A failed amendment leaves rate and cap untouched, and the fee recipient is untouched (AV-67 owns the destination, this owns the rate). The `ProtocolFeeAmended` event (discriminant 97) carries no amounts; the amended rate and cap are read from the vault.

**Non-linear vesting unlock curves (AV-90).** The AV-13 linear unlock is
a degenerate case: an escrow may instead attach a vesting curve
(`with_vesting_curve(schedule, curve)`, opt-in on `Uninitialized`, fixed
before funds move like the schedule itself). A curve is a tier table —
up to 8 tiers, each a `(at, unlocked_bps)` pair with strictly increasing
timestamps inside `[start, end]` and strictly increasing cumulative basis
points, the final tier exactly 10,000 (funds that could never vest are a
configuration error, `InvalidVestingCurve`). The unlock at any timestamp
is the last tier whose `at` has passed: a step function, so unlocking
jumps at the tiers and holds flat between them — the cliff semantics
(AV-51) survive untouched because the curve prices the curve value and
the cliff gates it orthogonally. Two constructors: `VestingCurve::stepped`
takes the tier table verbatim (milestone unlocks, cliff-then-lumpsum —
a single tier at `end` is a pure end-cliff), and
`VestingCurve::exponential(start, end, steps, growth_bps)` generates a
geometric schedule in exact integer math (positive growth back-loads,
negative front-loads, zero is the uniform stepwise analogue of linear;
the final tier is pinned to exactly 10,000 bps so rounding can never
strand dust). All pricing is `u128`-exact, clamped past `end`, monotone,
and never exceeds the locked amount. `claimable_amount` — and therefore
the keeper's claim listing — prices through the curve, so a keeper bot
lists the curve's value (a 25%-first-tier curve lists 250,000 at the
midpoint where the linear schedule would list 500,000); `claim` pays the
curved amount and accumulates into the same `released` counter, keeping
the inflow == released + refunded conservation law intact. Attaching a
plain schedule with `with_vesting` clears a previously set curve back to
linear. The 82-byte region (1-byte `Option` discriminant + 81-byte tier
region) is appended last in the vault layout, keeping every earlier
offset stable. Anchor surface: the `initialize_vesting_curve`
instruction (`start`, `end`, `cliff`, `tiers: Vec<VestingTier>`) and the
`Vault.vesting_curve` field, both pinned in the generated IDL.

**Dispute arbitration (escrowed payments with a judge).** An escrow can
name an arbiter (`with_arbiter`, opt-in on `Uninitialized`, like the
quorum builder; the zero key is rejected since `resolve` authenticates
against it). While `Funded`, *either* party may `escalate(authority, now,
dispute_amount, …)` into `Disputed` — the dispute window is the escrow's
live window (`now < expires_at`; at/after expiry the unilateral
`cancel_expired` path is the way out, so `escalate` reports
`DisputeWindowClosed`). The dispute is a **partial-amount** dispute:
`dispute_amount` names the contested slice of the lockup and must lie in
`[1, remaining_amount()]`, otherwise `escalate` fails with
`InvalidDisputeAmount` (code 193); it is persisted as `disputed_amount`
and never cleared (the audit trail of what was under arbitration, in the
`evidence_hash`/`rationale_hash` tradition). While `Disputed`, only the
contested pool is locked — the **undisputed remainder stays movable**:
`release` and `claim` still work from `Disputed`, capped at
`remaining - disputed_amount`. A `release` that names into the locked
pool fails with `DisputedAmountLocked` (code 194); a `release` past the
whole lockup keeps the old `ReleaseExceedsLocked`; a `claim` is silently
capped (its "take what's available" pull semantics — it errors only when
the whole pull would come from the locked pool). `cancel`,
`cancel_expired` and `attest` stay locked with `InvalidStateTransition`
while the arbitration is live. The arbiter then `resolve`s with a single
atomic split of the *disputed* pool — `taker_amount` to the taker (it must
be `<= disputed_amount`, else `ReleaseExceedsLocked`), the rest of the
disputed pool refunded to the initializer — moving the escrow to the
terminal `Settled` state and returning `(taker_payout,
initializer_refund)` so the program can size both transfers. The refund
formula is unchanged — `(remaining - taker_amount)` — because the
undisputed remainder naturally rides the refund back to the initializer,
so nothing strands; partial releases or capped claims made while
`Disputed` are honored (the split applies to the adjudicated pool only,
and dispute interest accrues on `disputed_amount`, not the whole
`remaining`). The taker's share accumulates in the shared `released`
counter while `remaining_amount()` preserves the initializer's refund for
audit, exactly like `cancel`'s refund accounting. The panel settling vote
and the AV-55 default judgment adjudicate the same disputed pool, so all
three settlement paths agree. Deliberately, a configured quorum does *not*
gate `resolve` (the arbiter is the resolution mechanism — attestors must
not veto the settlement), and vesting does not gate it either (the
dispute exists precisely because the schedule is contested; a `claim`
while `Disputed` is capped at the undisputed remainder rather than
locked). The escalating party may attach a 32-byte **dispute evidence
hash** (`escalate(authority, now, dispute_amount, evidence_hash)`) — a commitment to the
off-chain evidence (e.g. the SHA-256 of an IPFS CID holding chat logs,
delivery photos, or an oracle report) — persisted on the escrow so the
arbiter and indexers can read it without trusting the escalator to
re-supply it; `None` attaches no evidence (backward compatible). The hash
is never cleared: it survives `resolve` into `Settled` as the audit trail
of what the arbiter reviewed, and both the `Escalated` and `Resolved`
indexer events carry it. The arbiter may attach a 32-byte **rationale
hash** (`resolve(…, rationale_hash)`) — a commitment to the off-chain
rationale document behind the ruling (e.g. the SHA-256 of the written
arbitration report) — persisted on the escrow in `Settled` so the parties
and indexers can verify what the ruling referenced; `None` attaches no
rationale (backward compatible). Like the evidence hash, it is never
cleared, and the `Resolved` indexer event carries it.

**Arbitration default judgment (AV-55).** An escalated escrow can stall
when the arbiter goes silent or becomes unreachable — without a fallback
the funds sit in `Disputed` forever, every unilateral exit locked and
the arbiter not coming back. The default judgment is a liveness backstop
the parties negotiate *while they still trust each other* (before
funding): the initializer declares the fallback split
(`with_arbitration_deadline(deadline_secs, default_taker_amount)` /
`initialize_default_judgment`, `Uninitialized` only and only after
`with_arbiter` — the judgment is a fallback *for* arbitration), and the
taker countersigns it (`confirm_default_judgment`, taker only) — one
party alone cannot dictate the fallback terms. The deadline must be
non-zero (`DefaultJudgmentNotDue` otherwise — a zero deadline would fire
before the arbiter had any chance to rule) and the taker share must not
exceed the locked amount (`ReleaseExceedsLocked` otherwise).
`escalate` records the dispute timestamp `disputed_at`, and once
`now >= disputed_at + deadline_secs` *either* party may
`trigger_default_judgment` to settle `Disputed -> Settled` on the
pre-agreed split — the keeper/operator flow needs no arbiter signature,
so a bot watching the clock can sweep a deadlocked arbitration. The
arbiter's `resolve` is unchanged and keeps priority: after the deadline
it is a race between the arbiter's ruling and the parties' trigger,
first writer wins. The settlement mirrors `resolve` exactly — the
protocol fee slices the taker's share (the `released` counter keeps the
gross, the initializer's refund is never fee'd) — and quorum, vesting
and timelock do *not* gate it (same as `resolve`, so a misconfigured
lock can never trap disputed funds). Unconfigured, unconfirmed, or
early triggers fail with the new `DefaultJudgmentNotDue` (code 129).
The `DefaultJudgment` indexer event carries the `Resolved` amounts shape
(gross taker share / fee / initializer refund) plus the dispute evidence
hash the escrow still holds; the rationale commitment is `None` (no
arbiter ruled). New vault fields (appended last): `disputed_at` (u64),
`default_judgment` (17 bytes: 1-byte discriminant + 16-byte judgment),
`default_confirmed` (bool) — 26 bytes, so the full vault is now 994
bytes / 7,809,120 lamports rent-exempt.

**Arbiter panel multisig judgment (AV-65).** A single arbiter is a
single point of failure — a compromised or bribed key rules alone. The
opt-in panel replaces the single arbiter with an N-member committee and
an M-of-N threshold (`with_arbiter_panel(members, threshold)` /
`initialize_arbiter_panel`, `Uninitialized` only, like the other
`with_*` builders; 1–8 member keys, threshold 1..=N, zero/duplicate
keys rejected as `InvalidArbiterPanel`, code 136). The panel and the
single arbiter are mutually exclusive — last-wins in both directions,
so an escrow always has exactly one arbitration mechanism configured
(or none). After `escalate` moves the escrow to `Disputed`, each member
submits one judgment (`submit_panel_judgment(member, taker_amount,
rationale_hash)`, member-signed — a stranger is `Unauthorized`); each
member has exactly one *effective* vote, and a re-vote overwrites the
earlier vote (the `PanelJudgment` event keeps the full audit trail).
The first M votes that agree on the same `(taker_amount,
rationale_hash)` pair settle the escrow automatically to `Settled` —
first-to-M wins, no coordinator needed — with settlement semantics
identical to `resolve`: the protocol fee slices the taker's share
(the AV-63 fee cap applies), the gross lands in the shared `released`
counter, the initializer is refunded the remainder, and the winning
vote's `rationale_hash` is persisted like the arbiter's. Non-matching
votes stay recorded on the panel for audit (dissent is evidence, not an
error). In panel mode the single-arbiter `resolve` is disabled
(`PanelResolveDisabled`, code 137), and `rotate_arbiter` is
`InvalidStateTransition` (the panel is its own governance — rotate it
via `with_arbiter_panel`). The AV-55 arbitration deadline / default
judgment stays available in panel mode with the same rules, racing the
panel's M-vote settlement. Quorum does not gate the panel (AV-14
convention: the arbiter *is* the resolution mechanism). The keeper's
dispute listing never shows a single-arbiter `resolve` for panel-mode
escrows — one `submit_panel_judgment` action per member instead
(`caller_role: "panel_member"`) — and the snapshot/IDL exports carry
the panel (members, threshold, current votes). New vault field
(appended last): `arbiter_panel` (`Option<ArbiterPanel>`, 595 bytes:
1-byte discriminant + N u8 + M u8 + 8×32-byte member keys +
8×(u64 taker_amount + 1+32-byte rationale) votes + u64 voted bitmask)
— the full vault is now 2811 bytes / 20,511,120 lamports rent-exempt.

**Blind panel voting — commit-reveal (AV-137).** A plain panel vote is
visible the moment it lands, so a later voter can copy the emerging
majority (herding) or race to cast the M-th vote on a judgment they
never independently reached (front-running). The opt-in blind mode
(`with_blind_panel(members, threshold, reveal_window_secs)` /
`initialize_blind_panel`, `Uninitialized` only, `reveal_window_secs`
non-zero) keeps every judgment hidden until the reveal: each member
first commits `SHA-256(taker_amount || rationale_hash || salt)` via
`submit_judgment_commit` (member-signed, `Disputed` only; a zero
commitment is `BlindInvalidCommitment`, code 199 — no preimage could
ever reveal against it), then reveals the preimage via
`reveal_judgment` inside their own window (`committed_at +
reveal_window_secs`; a late reveal is `BlindRevealWindowClosed`, code
202 — a slow member cannot stall the arbitration, and the AV-55
default judgment remains the fallback). The reveal recomputes the
hash and rejects a mismatch (`BlindCommitMismatch`, code 200); each
commit reveals exactly once (`BlindDuplicateReveal`, code 201; commit
again to change the judgment — last-wins, and the window restarts).
The commit binds to the escrow's `disputed_at` snapshot: a reveal
after the dispute moved on is auto-invalidated (`BlindCommitStale`,
code 203, and the stale commit is cleared). In blind mode plain
`submit_panel_judgment` is rejected (`BlindVoteMustReveal`, code
205) — votes enter the tally only through the reveal, which settles
via the shared helper, so the AV-65 threshold semantics, the mint
check, the payout policy, and the fee/interest settlement are
identical to the plain path (a dedicated test pins
blind-settles-identically-to-plain). `IndexedEscrow` emits
`JudgmentCommitted` per commit and `JudgmentRevealed` per reveal
(plus `PanelResolved` on the M-th matching reveal). The blind-vote
region (blind flag + reveal window + 8 commitments + 8 commit
timestamps + 8 dispute snapshots + revealed bitmask, 401 bytes) is
appended to the `arbiter_panel` region, which grows 595 → 995
bytes; see "Account space & rent" for the new vault totals.

**Evidence-disclosure deadline (AV-68).** Arbitration stalls when the
escalating party never produces the evidence their claim rests on —
the arbiter (or panel) is left ruling on assertions, and the
counterparty cannot rebut what was never disclosed. The opt-in
deadline is a procedural bar the parties negotiate *while they still
trust each other* (before funding):
`with_evidence_deadline(deadline_secs)` / `initialize_evidence_deadline`
(`Uninitialized` only, like the other `with_*` builders; the arbiter —
or the AV-65 panel — must already be configured, `InvalidArbiter`
otherwise; a zero deadline is `InvalidEvidenceDeadline`, code 138 — a
deadline of zero seconds would lapse the moment the dispute starts).
`escalate` records *who* escalated (`escalated_by`) alongside
`disputed_at`, and the disclosure window is measured from
`disputed_at` — the escalating party always gets the full window
regardless of when the dispute started. Disclosure is the escalating
party's duty: only the recorded escalator may call
`submit_evidence(authority, evidence_hash, now)` (a stranger or the
counterparty is `Unauthorized`) — the 32-byte commitment overwrites
any previously attached hash, so a within-deadline submission may
always refine the evidence bundle. Evidence attached at `escalate`
(AV-22) satisfies the deadline immediately. The deadline is a **hard
bar**: once `now >= disputed_at + deadline_secs` with no evidence on
record, disclosure is rejected (`EvidenceDisclosureLate`, code 139) —
a missed deadline locks in the adverse inference instead of accepting
a last-minute disclosure. At judgment time the crate exposes
`evidence_status(now)` (`Submitted` / `Pending` / `Defaulted`) and
`evidence_defaulted(now)`; the three settlement paths (`resolve`,
`submit_panel_judgment`'s M-th vote, `trigger_default_judgment`)
stamp the signal onto their settlement events (`evidence_defaulted`),
so the arbiter, the panel members, and indexers apply the
absent-evidence weight *against the escalating party* — i.e. the
inference favors the other party. The crate deliberately does not
invent a split for the arbiter: the bias is a tamper-proof procedural
record, and the hard enforcement is the deadline itself. The
`EvidenceSubmitted` indexer event (`from == to == Disputed`) carries
each disclosure. New vault fields (appended last):
`evidence_deadline_secs` (u64) + `escalated_by`
(`Option<Pubkey>`, 33 bytes) — 41 bytes, so the full vault is now 2941
bytes / 21,360,240 lamports rent-exempt. AV-73 appends the 512-byte
live per-period amount table (`subscription_amounts`: 64 `u64` slots),
so the full vault is now 3453 bytes / 24,923,760 lamports rent-exempt.
AV-75 appends the 1-byte schema version (`schema_version`), so the full
vault is now 3454 bytes / 24,930,720 lamports rent-exempt.
AV-82 appends the 41-byte opt-in slash terms (`slash_terms`: 1-byte
`Option` discriminant + 32-byte penalty account + 8-byte slash deadline)
and the 8-byte cumulative slashed amount (`penalty_paid`), so the full
vault is now 3503 bytes / 25,271,760 lamports rent-exempt. Like the
quorum region, the slash-terms region is always reserved (zeroed when
`None`), so `initialize_slash_terms` writes the terms in place — the
account never needs a realloc. The schema revision bumps to 2, and the
`migrate_schema` gate becomes a catch-up gate (`schema_version <
SCHEMA_VERSION`) so a v0 vault is never stranded by the intermediate
v1 revision.

**Dispute-evidence Merkle commitment (AV-91).** The AV-22 single
`evidence_hash` covers one document; real disputes rest on many. AV-91
lets the escalating party commit to the *whole* evidence set up front:
`escalate` takes an optional `evidence_root` (SHA-256 Merkle root over
the document set) plus `evidence_leaves` (`0` iff the root is `None`,
`1..=64` iff `Some` — a count that does not describe the root is
`InvalidEvidenceProof`, code 148). Documents are then disclosed one by
one with `file_evidence(authority, doc_hash, leaf_index, proof, now)`:
the escalating party reveals a document hash plus its Merkle inclusion
proof, and the vault flips that leaf's bit in the disclosure bitmap.
The proof shape is pinned — leaf = `H(0x00 || doc)`, inner node =
`H(0x01 || left || right)` (domain separation against second-preimage
attacks), the last node of an odd-width layer promotes unchanged — and
a short, long, or non-verifying proof is `InvalidEvidenceProof`.
Guards mirror `submit_evidence`: pause guard first, escalator-only
authority (`Unauthorized` otherwise), `Disputed`-only, and the same
AV-68 deadline bar (`EvidenceDisclosureLate` past the window).
Re-filing a disclosed document is an idempotent no-op. The arbiter
panel verifies disclosure *completeness* before judgment:
`evidence_disclosure()` returns `(disclosed, total)`, and undisclosed
documents are honestly deducted in the judgment weight — a party cannot
win by committing to evidence it never shows. The root, leaf count and
bitmap are never cleared, so a `Settled` escrow keeps the full audit
trail. Indexer surface: the `EvidenceFiled` event (`from == to ==
Disputed`, discriminant 46) carries the root on `Escalated` and every
filing; the three settlement events stamp the `(disclosed, total)`
progress; keeper `resolve` / `submit_panel_judgment` actions surface
it for the arbiter dashboard; the snapshot exports `evidence_root`
and `evidence_disclosure`. New vault fields (appended last):
`evidence_root` (`Option<[u8; 32]>`, 33 bytes) + `evidence_leaves`
(u8) + `evidence_disclosed` (u64, 8 bytes) — 42 bytes at the time,
bringing the layout to 3978 bytes (the layout has since grown to
5077 bytes / 5085 with the discriminator — see the account-space
paragraph below). Anchor
surface: `escalate` gains the two params, plus the new
`file_evidence` instruction (`doc_hash`, `leaf_index`,
`proof: Vec<[u8; 32]>`) and the three `Vault` fields, all pinned in
the generated IDL.

**Migration chain, dry-run, atomic rollback (AV-85).** The catch-up is
now an explicit N → M step chain: a v0 vault walks `0 → 1 → 2`, each
step re-validating the conservation invariants over the field set it
carries (the slash-region check applies from the `1 → 2` step on — a
true v0 account has no slash region to judge). Any failing step rolls
the chain back to the pre-chain snapshot: a migration never leaves a
half-migrated vault behind. One `SchemaMigrated` event is emitted per
applied step, each carrying its `from → to` versions, so the event
history records the whole chain. `migrate_dry_run` runs the full
pre-flight read-only and returns the step/field plan (which fields
each bump appends, with byte widths) — zero write impact, so the
operator signs with the plan in hand. The keeper's
`scan_schema_migrations` dry-runs the chain across a watch list and
reports each stale vault's version path, changed fields, and
readiness (`"paused"` / `"corrupt"` when blocked); the snapshot's
`migration_pending` flag surfaces the same signal per vault.

**Panel threshold governance (AV-69).** The right M-of-N is not always
obvious at setup — a 2-of-3 panel may prove too slow (one member goes
quiet) or too lax (the parties want stronger consensus before a
dispute can settle). `update_panel_threshold(initializer, taker,
new_threshold)` retunes the panel's judgment threshold *before the
dispute starts*: **dual-signed** (the initializer AND the taker must
both authorize — one party alone must never be able to lower the bar
toward a friendly minority or raise it to deadlock the panel),
`Uninitialized` only (the threshold must be settled before the dispute,
so an in-flight arbitration tallies under stable rules), and the new M
must satisfy 1..=N — the same validation as the
`with_arbiter_panel` builder, reusing `InvalidArbiterPanel` (code 136)
for 0, above N, or no panel configured (there is no threshold to
retune on a single-arbiter escrow). The retune rewrites only the
threshold: cast votes and the `voted` bitmask survive, and counting
continues under the new M — the panel's judgment history is
append-only. Retuning to the current threshold is an idempotent no-op.
The `PanelThresholdChanged` indexer event (`from == to ==
Uninitialized`) fires only on an actual change — the event is the
ordering signal, the new M is read from the vault. The snapshot export
carries the retuned threshold, the IDL JSON carries the new
instruction, and no vault layout change is needed (the threshold
already lives in the persisted panel region).

**Subscription release (AV-56).** A subscription is the clock-driven
counterpart to the milestone tranche plan (AV-15): the initializer may
opt in on `Uninitialized` (`with_subscription(period_secs, periods,
per_period)` / `initialize_subscription`, mutually exclusive with
`with_milestones` — an escrow carries at most one release schedule) and
the locked amount then pays out in `periods` equal tranches of
`per_period`, one per `period_secs` seconds, released by the
initializer's push (`release_period(period_index)`). The schedule is
**back-scheduled** from `expires_at`: period `i` (0-based) is due at
`expires_at - (periods - 1 - i) * period_secs`, so the last period is
always due exactly at expiry and the whole schedule completes inside the
escrow's lifetime. That pinning is deliberate — a forward-scheduled plan
could strand its final periods past expiry behind a payout path that can
never legally run, while here everything not yet due at expiry is exactly
the refundable remainder: what became due pays out to the taker via
`release_period`, what never became due stays refundable via
`cancel_expired`. The validation list is the natural corollary —
`period_secs` non-zero, `periods` in 1..=64 (the released bitmap is a
u64), `per_period` non-zero, `periods * per_period` == the locked amount
(summed in u128), `expires_at != u64::MAX` (back-scheduling needs a
bounded lifetime), and the schedule must fit the lifetime — anything
else is `InvalidSubscription`. Release is strictly in order: the
`period_index` must equal the next due period (`PeriodNotDue` for
skip-ahead or replay) and `now >= due_at(period_index)` (`PeriodNotDue`
for an early call). A late-funded escrow simply finds its early periods
immediately due — catch-up, not an error: no period is owed twice or
skipped, only released early, still in order. All the familiar release
gates ride along: quorum (`QuorumNotReached`), the timelock
(`TimelockNotReached` — every taker payout path), `MintMismatch` and the
payout policy (`PayoutNotAllowlisted`), and the AV-17 protocol fee slices
each period (`payout + fee == per_period`); the last period moves `Funded
-> Released`, and each release emits `SubscriptionPeriodReleased` (`from
== Funded`, `to == Funded` — or `Released` on the last period; payout =
gross per-period amount, fee, refund = 0). Keeper flow: the keeper scans
for the next due period and submits `release_period` for it,
initializer-signed — no keeper can skip ahead or double-release. AV-160 adds the permissionless `crank_release_period` crank: any keeper may release the next due period (payout pinned to the taker, cranker receives zero) when the initializer's push path is idle — the keeper lists it alongside `release_period` as a `CrankReleasePeriod` action (`caller_role: "anyone"`). Vesting
plays along rather than blocking: the tranche accumulates in the shared
`released` counter, so a taker-pull `claim` composes on the same
schedule, and the `checked_add` backstop (`ReleaseExceedsLocked`) keeps
the counter from outrunning the lockup even when vesting drew first.
New vault fields (appended last): `subscription` (18 bytes: 1-byte
discriminant + 17-byte schedule), `subscription_next` (u8),
`subscription_released` (u64 bitmask) — 27 bytes, so the full vault is
now 2184 bytes / 16,091,520 lamports rent-exempt.

**Reference memo (off-chain correlation).** The initializer may bind an
opt-in 32-byte **reference memo** (`with_reference` /
`initialize_reference(reference)` on `Uninitialized`, e.g. an order id or
invoice hash from the operator's off-chain system). The state machine
treats it as read-only pass-through: no check gate reads it, no
transition ever clears or rewrites it, and it never affects amount
conservation — it exists so off-chain systems can reconcile. The memo is
persisted in the vault account (appended last, 33 bytes), carried on
*every* indexer event (read from the escrow at emit time), on every
keeper-report action (as lowercase hex in the report JSON), and in the
snapshot export — so an indexer or keeper bot can join each escrow back
to the off-chain record it settles without a second account read.
`None` attaches no memo (backward compatible).

**Milestone tranche release (staged settlement).** An escrow can declare a
milestone plan at creation (`MilestonePlan::new(amounts)`, opt-in on
`Uninitialized` via `with_milestones`, like the quorum builder): the
locked amount is split into at most 8 ordered tranches — the staged
settlement pattern (construction tranches, grant disbursements, gated
unlocks; Solana stream/milestone payments). The tranche amounts must sum
to *exactly* the locked amount: the plan is the *complete* release
schedule. The sum is accumulated in `u128`, which cannot wrap for 8
`u64` tranches — a wrapping `u64` sum could alias a wrong total onto the
locked amount (e.g. two `u64::MAX` tranches wrapping to `u64::MAX - 1`)
and wrongly accept a plan that over- or under-covers the lockup.

Each tranche releases only after *both* parties confirmed its milestone:
`confirm_milestone(authority, index)` records one party's acceptance
(either party may confirm; strangers get `Unauthorized`), and the
milestone is confirmed once both confirmed — each confirmation is a
separate signature, reusing the dual-signature concept from activation.
Confirmations, releases, and skips are all strictly in-order (only the
first unsettled milestone is actionable), and confirming is idempotent
per party. `release_milestone(authority, index)` is the initializer's
push path (like `release`): it returns the tranche amount so the program
can size the transfer, accumulates it in the shared `released` counter
(conservation and audit stay unified with `release` / `claim` /
`resolve`), and moves the escrow to `Released` once everything is out.
Releasing before dual confirmation is `MilestoneNotConfirmed`; a
configured quorum gates `release_milestone` exactly like `release` /
`claim` (the quorum guards every release path), while the two parties own
milestone acceptance.

Skipping a milestone requires a dual signature: `skip_milestone` records
one party's skip approval per call, and the skip executes only once
*both* parties approved. The skipped tranche is *not* paid out — it joins
the refundable remainder (`skipped_amount()` tracks it for audit;
`remaining_amount()` includes it), so the initializer is refunded, never
the taker. Skipping never closes the escrow: later tranches continue, and
`cancel` / `cancel_expired` refund whatever remains. A milestone one
party confirmed and the other skip-approved stays unsettled until both
parties align on one path — neither path completes on a single party's
word.

Unskipping is the inverse: `unskip_milestone` (AV-232) restores a skipped
tranche to the claimable schedule when both parties change their minds
before anything else settles — instead of forcing the deal to cancel and
re-lock. Restoration is last-settled-first-restored: the tranche must
currently be skipped, every earlier tranche must be settled (so the
restored tranche becomes the earliest unsettled one, preserving in-order
settlement), and no later tranche may be settled (a skip followed by a
later settlement is final). On success the skip bits clear and the tranche
amount leaves the skipped pool; a refused restoration writes nothing, and
per-tranche confirmations survive (they accept the deliverable, not the
settlement), so an already-confirmed tranche can release immediately after
restoration. The `MilestoneUnskipped` event (discriminant 96) carries no
amounts; the restored tranche is read from the vault.

Design choice, documented deliberately: once a plan is attached, plain
`release` and `claim` return `InvalidMilestones` — the plan and the
vesting curve are *alternative* release schedules, not composable ones.
Arbitrary or time-based pulls would release funds outside the tranche
plan and break per-tranche accounting; the refund paths stay available,
and `resolve` overrides the plan by design (unsettled tranches are part
of the split remainder), like it overrides vesting. Confirmation progress
is persisted in a 6-bits-per-milestone bitmap in the vault account (see
the layout table), so it survives serialization.

**Milestone due dates and late penalties (AV-206).** A plan gives
tranches no calendar: a tranche released a year late settles exactly
like one released on time. `with_milestone_due_dates(due_at)` (after
`with_milestones`, `Uninitialized`-only) attaches one strictly
increasing deadline per tranche, and `with_late_penalty_bps(bps)`
(0–10_000 bps, `InvalidPenalty` above) prices lateness: a
`release_milestone` after its tranche's deadline settles as
`released += tranche - penalty` with `penalty_paid += penalty`
(`floor(tranche * bps / 10_000)`), so `released + penalty_paid +
skipped + remaining == amount` with the conservation formula
untouched, and the escrow closes exactly when `released +
penalty_paid == amount` (the pre-AV-206 close test is that test with
`penalty_paid == 0`). Releasing exactly at `due_at` is on time, not
late. The protocol fee slices the *net* tranche (never the forfeited
slice), while the AV-205 per-call cap still binds the *gross* tranche.
A rate without deadlines prices nothing (no tranche has a deadline to
miss), and deadlines without a rate price nothing — the two builders
compose, neither implies the other. This reuses the AV-82
`penalty_paid` sink safely because `slash` refuses
milestone-scheduled escrows: on a milestone escrow that counter can
only ever hold late penalties. Note the scope boundary: this item is
the state machine (`escrow-state`) — the Anchor instruction that
attaches deadlines at vault creation and the on-chain routing of the
penalty slice are follow-up Anchor work, not claimed here.

**Milestone tranche claim deadline (AV-225).** A plan gives tranches no
claim window: a vested tranche could sit unclaimed forever while the
escrow stays `Funded`. `with_milestone_claim_deadline(tranche,
deadline_secs)` (after `with_milestones`, `Uninitialized`-only, opt-in
per tranche) attaches one absolute unix-timestamp deadline per tranche
— `0` means no deadline, exactly as AV-206 due dates. A tranche that is
vested but still unclaimed strictly after its deadline cannot be
claimed: `release_milestone` rejects the claim with
`MilestoneClaimExpired` (code 355) and the tranche amount automatically
returns to remainder (the skip path's `skipped += tranche`, same
conservation backstop), so the initializer reclaims it through the
normal cancel path — nothing is forfeited. Claiming exactly at the
deadline is on time; claim semantics before the deadline are unchanged.
An unconfirmed tranche past its deadline still fails
`MilestoneNotConfirmed` and nothing moves — expiry only fires on a
vested tranche. The escrow stays `Funded`, later tranches continue, and
all three release paths (`release_milestone`,
`release_milestone_verified`, `release_milestone_slot_gated`) share the
check. The `MilestoneClaimExpired` event (discriminant 90) carries the
tranche index and the returned amount. Orthogonal to milestone skip (an
active action, this is time-expiry auto-return), to AV-51 vesting cliff
(the cliff governs unlock time, this governs the claim window), and to
AV-224 reallocation (amounts, not claim time).

Vault tail +64 bytes (BODY 8188 → 8252, SPACE 8196 → 8260, no-quorum
7706 → 7770); IDL regenerated, including the new field and error code
355 `MilestoneClaimExpired`. (Solana: payment settlement.)

**Milestone tranche append (AV-226).** A plan is the complete release schedule, so a new deliverable cannot be invented from nothing — but a tranche the parties already returned to remainder can be re-scheduled. `append_milestone_tranche(initializer, taker, amount)` (`Funded`-only, dual-signed) appends one tranche at the end of the plan, carved from the skipped remainder: the amount must be positive and no larger than `skipped_amount()` (skipped tranches and AV-225-expired tranches), otherwise `InvalidMilestoneAmendment`. The locked amount is unchanged, the skipped remainder decreases by exactly the new amount, existing tranches keep their positions and amounts, confirmed or settled tranches are untouched, and the appended tranche — unconfirmed, with no due date and no claim deadline — settles last in order once dual-confirmed. A Funded escrow with no skipped remainder cannot append at all: there is nothing to carve from. The `MilestoneTrancheAppended` event (discriminant 91) carries no amounts; the appended tranche is read from the vault's plan tail. Orthogonal to AV-224 reallocation (amounts, not count) and to AV-225 deadlines (per-tranche config; the appended tranche simply has none).

**Milestone tranche partial claim (AV-229).** A tranche that pays out all-or-nothing cannot follow work that lands in slices — a construction tranche drawn against verified progress, a grant disbursed as deliverables arrive. `release_milestone_partial(authority, now, index, amount)` (`Funded`-only, initializer-only) settles exactly `amount` of a dual-confirmed, next-in-order tranche, under the same gates as a full release (mint binding, payout policy, quorum priced on the slice's amount, timelock, delivery confirmation, per-call cap on the slice). The slice must be positive and no larger than the tranche's unclaimed remainder (`ReleaseExceedsLocked` otherwise); it accumulates into the shared `released` / `fees_paid` / `penalty_paid` counters, so escrow-wide conservation is untouched, and the per-tranche ledger (`milestone_partial_claimed_at()`, persisted as a vault tail field) records the claimed gross. The tranche stays unsettled — still the next milestone — until the slices sum to the full tranche, when the released bit is set; a full `release_milestone` on a partially claimed tranche settles exactly the remainder, so the two paths compose without double-paying a slice. The AV-206 late penalty prices the slice's own amount, and the AV-225 claim deadline gates the slice like a full claim, except that past the deadline only the unclaimed remainder returns to remainder — slices settled before the deadline stay paid. The `MilestonePartiallyClaimed` event (discriminant 93) carries the slice's gross in payout and the protocol fee in fee, like `MilestoneReleased`; a verifier-bound escrow refuses the plain partial path with `MilestoneVerifierRequired`, like the plain full path.

No vault layout change (the tranche table is already reserved to `MAX_MILESTONES`, the count byte and skipped counter already exist); no IDL change (no new instruction, error, or persisted field). (Solana: payment settlement.)

**Funding start window (AV-228).** A deal that must not take funds before its announced open — a sale that starts at a fixed unix time — opts in via `with_funding_start(start_at)` (`Uninitialized`-only; `0` means no window, funding ungated exactly like a pre-AV-228 escrow). While `now < funding_start`, `fund` and `fund_with_slot` refuse with `FundingNotStarted` (code 356) and nothing moves: neither the state nor any anchor (`fund_at`, `fund_slot`, `funded_total`, the interest clock) advances, so a rejected early funding is indistinguishable from no funding attempt at all. Funding exactly at `funding_start` is on time, and after the window opens funding semantics are unchanged — the window is a gate, not a schedule: it never moves `expires_at`, never re-prices anything, and never gates any other transition. Orthogonal to `expires_at` (this opens funding, that closes the deal — a window that opens after `expires_at` simply never funds, it does not extend anything), to the AV-27 slot timelock (that gates release time, this gates funding time), and to AV-59 `extend_expiry` (that moves the deadline, this fixes the start — extending the deadline never moves the window). Deliberately not applied to `fund_tranche` / `fund_partial`, whose own schedules own those deposit paths.

Vault tail +8 bytes (BODY 8252 → 8260, SPACE 8260 → 8268, no-quorum 7770 → 7778); IDL regenerated, including the new field and error code 356 `FundingNotStarted`. (Solana: payment settlement.)

**Vote-escrow locks (AV-207).** Time-weighted governance voting
power, as a pure-logic sidecar (`escrow-state/src/vote_escrow.rs`,
no vault layout change). `VoteEscrowLock::lock(amount, start,
duration)` opens a lock whose voting power decays linearly:
`power(now) = amount * remaining / duration`, computed in `u128`
so even a `u64::MAX` lock stays exact, floored so a lock never
reports more power than it holds. Power is full at `start` and zero
at maturity. `extend_to(new_end)` only ever lengthens — a new end
at or before the current end, or at or before `now`, is
`InvalidVoteLock` (code 317), so a lock can never be shortened out
of its commitment. `early_exit(now)` closes a live lock early and
prices the exit as `(refund, penalty)` with `penalty = floor(amount
* remaining / duration)`; a mature lock exits penalty-free, and a
second exit is refused. The penalty is returned for the caller to
route to the AV-106 insurance pool — the module moves no lamports,
it only prices the exit. Orthogonal to AV-170 staking (yield, not
votes) and AV-183 frozen snapshots (a snapshot reads weights at a
slot; this lock generates a decaying weight over time).

**Milestone tranche re-split (AV-70).** Before any settlement, the
initializer and taker may jointly re-balance the tranche amounts via
`adjust_milestone_amounts(initializer, taker, new_amounts)` — e.g.
front-load a deliverable that grew, or back-load one that shrank —
without cancelling and re-creating the escrow (which would strand
quorum votes, attestations, and activation state). Both parties must
sign (dual-signature governance, one party alone is `Unauthorized`);
`Uninitialized`, `Activated`, or `Funded` only — the terminal states
and `Disputed` (arbitration in flight) are `InvalidStateTransition`.
Once any tranche settled (`released > 0` or `skipped > 0`) the amounts
on chain are already partially consumed and the re-split is rejected.
The new amounts must have exactly the plan's tranche count (re-split,
not restructure), be all positive, and sum to *exactly* the locked
amount (accumulated in `u128`, like `with_milestones`). The rewrite is
in place — no account realloc, no rent change. Per-tranche
confirmations / skip approvals survive (they accept the deliverable,
not the amount, and the adjustment itself carries both signatures).
Protocol fees charge on the new amounts at release time via
`protocol_fee_for` (still floored by `fee_cap`), and the indexer sees
one `MilestonesAdjusted` event on an actual change.

**Milestone tranche renegotiation (AV-155).** The mid-flight twin of the
AV-70 re-split: `amend_milestones(initializer, taker, new_amounts)` lets
the two parties reprice the tranche amounts *after* the plan is live —
even once other tranches have settled — as long as every confirmed or
settled tranche keeps its exact amount. A confirmed tranche is locked
because the dual confirmation accepted the declared amount (repricing it
would rewrite the accepted deal); a settled tranche is locked because
funds already moved at its amount. Only the still-unconfirmed tranches
may move, so a deal can be renegotiated tranche-by-tranche as
deliverables change — e.g. with plan `[300k, 300k, 400k]` and tranche 0
released, `[300k, 400k, 300k]` front-loads the next deliverable while the
settled 300k stays put. Both parties must sign (dual-signature
governance); `Uninitialized` or `Funded` only. The new amounts must have
exactly the plan's tranche count, be all positive, and sum to *exactly*
the locked amount (`InvalidMilestoneAmendment` otherwise; no plan
attached is `InvalidMilestones`). The rewrite is in place — no realloc,
no rent change; fees charge on the new amounts at release time. The
indexer sees one `MilestonesAmended` event on an actual change. Orthogonal
to `skip_milestone`: skipping reroutes a tranche to the refund without
changing its amount; amending reprices unconfirmed tranches without
rerouting them.

**Subscription per-period re-split (AV-73).** The subscription twin of
the AV-70 milestone re-split: before any release, the initializer and
taker may jointly re-balance the per-period payout amounts via
`adjust_period_amounts(initializer, taker, new_amounts)` — e.g.
front-load a period whose costs grew — without cancelling and
re-creating the escrow. Both parties must sign (dual-signature
governance, one party alone is `Unauthorized`); `Uninitialized`,
`Activated`, or `Funded` only — the terminal states and `Disputed`
(arbitration in flight) are `InvalidStateTransition`. Released periods
lock their recorded amounts: the re-split must reaffirm them
(`InvalidSubscription` otherwise), so on-chain payout history is never
rewritten. The new amounts must have exactly the schedule's period
count (re-split, not restructure), be all positive, and sum to *exactly*
the locked amount (accumulated in `u128`, like `with_subscription`).
The rewrite is in place — the 64-slot `subscription_amounts` table is
always reserved, so no account realloc, no rent change. Protocol fees
charge on the new amounts at release time via `protocol_fee_for`
(still floored by `fee_cap`), the keeper's `ReleasePeriod` action
prices from the live table, and the indexer sees one
`SubscriptionAmountsAdjusted` event on an actual change (a no-op
re-affirmation emits nothing).

**SPL token mint binding (token-scoped escrows).** An escrow can bind one
SPL token mint at creation (`initialize_mint(mint)`, opt-in on
`Uninitialized`, like the quorum builder): the `mint` param is the base58
mint address, decoded by a handwritten base58 decoder (the crate is
dependency-free, so no `bs58` crate) into 32 raw bytes. Empty strings,
non-alphabet characters, and encodings that do not decode to exactly 32
bytes are `InvalidMint` (code 112); the zero address is well-formed but
rejected too — it is not a real mint (paralleling the arbiter's zero-key
rejection). Without a bound mint the escrow is the native-SOL path and
behaves exactly as before.

Once bound, every fund-moving transition — `release`, `cancel`,
`cancel_expired`, `claim`, `release_milestone`, `resolve` — takes the
vault token account's mint and requires it to equal the bound address;
any mismatch is `MintMismatch` (code 113), and the failed call leaves
state and amounts untouched like every other rejection. `None` vs `Some`
mismatches as well: a bound escrow never exits through the native-SOL
path, and a SOL escrow never exits through a token mint — so the wrong
token type can never be moved out of (or refunded from) the vault. The
binding is a persisted 33-byte region in the vault account (see the
layout table), appended last so every earlier field offset stays stable.

**Protocol fee (basis points).** An escrow can opt in to a protocol fee
at creation (`initialize_protocol_fee(fee_bps)`, opt-in on
`Uninitialized`, like the quorum builder): the rate is in basis points
and must be `0`–`10_000` (`InvalidProtocolFee`, code 114, otherwise);
`0` is a valid "no fee" rate (the default), so plain escrows pay takers
in full — the pre-AV-17 behavior. The rate is fixed before funding and
immutable afterwards, like every other `with_*` builder.

The fee is charged on every taker payout — `release`, `claim`,
`release_milestone`, and the taker's share of `resolve` — as
`floor(gross_payout × fee_bps / 10_000)`, floored by the AV-63 absolute
fee ceiling when one is configured (the effective fee is `min(bps fee,
fee_cap)`), computed in `u128` so the
multiplication can never overflow (the quotient is always `<=` the gross,
so the downcast is exact). Floor rounding means dust payouts may carry a
zero fee: the protocol never rounds *up* into the taker's pocket. Each
payout returns `(taker_payout, fee)` (`resolve` returns
`(taker_payout, fee, initializer_refund)`), so the program can route each
leg to its destination (taker account / protocol fee account /
initializer). The fee always slices the gross payout: `taker_payout + fee
== gross` for every payout, and the cumulative `fees_paid` counter is a
routing slice of the gross `released` counter — so the conservation
invariant (`inflow == locked + released + refunded`, pinned by the
model-based fuzz test) is untouched by fees, and the AV-63 ceiling keeps
that guarantee by construction (a capped fee is always `<=` the uncapped
bps fee `<=` the gross). Refunds (`cancel`,
`cancel_expired`), the initializer's `resolve` share, and skipped
milestones are never fee'd: only value the taker receives carries a fee.
The rate (`fee_bps`, 2 bytes) and the cumulative counter (`fees_paid`,
8 bytes) are persisted in the vault account (see the layout table),
appended last so every earlier field offset stays stable; with the fee
region the full vault is 692 bytes and needs **5,707,200 lamports** to be
rent-exempt on mainnet. (AV-45 grows the quorum region by 71 bytes — 64 for
the per-attestor weight array plus 7 for the wider u64 weight-sum threshold —
so the full vault is now 763 bytes and needs **6,201,360 lamports**. AV-46
appends the 33-byte pause-authority region plus the 1-byte pause flag (34
bytes), so the full vault is now 927 bytes and needs **7,342,800 lamports**.
AV-51 adds the 8-byte vesting `cliff_at` timestamp to the vesting region
(the schedule goes from 17 to 25 bytes), so the full vault is now **935
bytes** and needs **7,398,480 lamports**. AV-53 appends the 33-byte
off-chain reference memo region (1-byte discriminant + 32-byte
correlation id), so the full vault is now **968 bytes** and needs
**7,628,160 lamports**. AV-55 appends the 8-byte dispute timestamp
`disputed_at` (zeroed when the escrow was never disputed), the 17-byte
default-judgment region (1-byte discriminant + 16-byte judgment,
zeroed when no default judgment is configured), and the 1-byte taker
confirmation bit (26 bytes), so the full vault is now **994 bytes** and
needs **7,809,120 lamports**. AV-56 appends the 18-byte subscription
schedule region (1-byte discriminant + 17-byte schedule, zeroed when no
schedule is attached), the 1-byte next-period index, and the 8-byte
per-period released bitmap (27 bytes), so the full vault is now **1021
bytes** and needs **7,997,040 lamports**. AV-57 appends the per-escrow
event-history ring buffer: the 1-byte ring head (write cursor), the
8-byte monotonic event total, the 1-byte valid-entry count, the 1-byte
configured capacity (1–64, default 64), and the 64 fixed 18-byte slots
(kind u8 + at u64 + actor tag u8 + 8-byte actor summary) — 1163 bytes,
always reserved at the 64-entry ceiling so a smaller capacity never
needs a realloc — so the full vault is now **2184 bytes** and needs
**16,091,520 lamports**. AV-59 appends the 8-byte extension bound
`max_extension_secs` (zeroed when extension is not enabled) and the
8-byte extension counter `extension_count` (zeroed when never
extended) — 16 bytes, so the full vault is now **2200 bytes** and
needs **16,202,880 lamports**. AV-63 appends the 8-byte absolute
protocol-fee ceiling `fee_cap` (zeroed = uncapped when no ceiling is
configured) — 8 bytes, so the full vault is now **2208 bytes** and
needs **16,258,560 lamports**.) AV-66 appends the 81-byte tiered
protocol-fee schedule region (1-byte live-tier count + 8 fixed 10-byte
tier slots), so the full vault is now **2892 bytes** and needs
**21,074,880 lamports**. AV-68 appends the 41-byte evidence-deadline
region (8-byte `evidence_deadline_secs` + 33-byte `escalated_by`), so
the full vault is now **2941 bytes** and needs **21,360,240
lamports**. AV-73 appends the 512-byte live per-period amount table, so
the full vault is now **3453 bytes** and needs **24,923,760
lamports**. AV-75 appends the 1-byte schema version, so the full vault
is now **3454 bytes** and needs **24,930,720 lamports**. AV-82 appends
the 49-byte slash region (41-byte `slash_terms` + 8-byte `penalty_paid`),
so the full vault is now **3503 bytes** and needs **25,271,760
lamports**.

**Tiered protocol fee (AV-66).** An escrow can opt in to volume-priced
fees at creation (`initialize_fee_schedule(tiers)`, opt-in on
`Uninitialized`, like the flat-rate builder): `tiers` is the
amount-to-rate ladder as `(min_amount, bps)` pairs — 1 to 8 tiers,
each `bps` in `0`–`10_000`, the `min_amount` floors strictly ascending
(`InvalidProtocolFee`, code 114, otherwise — the same code the flat
rate uses, so no error code is added). The fee for a gross payout uses
the rate of the highest tier with `min_amount <= amount`, computed as
`floor(gross_payout × tier_bps / 10_000)` in `u128` (no overflow), then
still floored by the AV-63 absolute ceiling when one is configured —
so the keeper / batch / settlement-plan previews, which call the same
`protocol_fee_for` computation point, preview exactly what the chain
charges on every taker-payout path (`release`, `claim`,
`release_milestone`, the taker's share of `resolve`,
`release_period`, and the AV-65 panel's auto-settlement). The flat rate
and the schedule are mutually exclusive — fail-fast, never silent
last-wins: configuring a schedule with a nonzero `fee_bps` already set,
or a later `initialize_protocol_fee` on a scheduled escrow (even with
`fee_bps == 0`), is `InvalidProtocolFee`, because a silently dropped
rate would misroute protocol revenue. With no schedule configured
(`tier_count == 0`) the fee falls back to the flat rate — the
pre-AV-66 behavior is unchanged, and the `fees_paid <= released`
conservation invariant holds by construction (a tiered fee is always
`<=` the gross payout). The schedule is exported in the AV-26
snapshot JSON (`"fee_schedule"`, `null` when unconfigured).

**Fee recipient pin (AV-44).** An escrow can additionally pin *where* the
fee goes (`initialize_fee_recipient(fee_recipient)`, opt-in on
`Uninitialized`, like every other `with_*` builder): after this, every fee
leg the AV-17 rate charges must go to the pinned address. With no pinned
recipient the fee legs route to the program-level fee account (the
pre-AV-44 behavior). The zero address is rejected (`InvalidFeeRecipient`,
code 123) — it can never be the legitimate fee destination, paralleling
the AV-23 refund-whitelist policy — and the pin is immutable once the
escrow leaves `Uninitialized`, like the fee rate itself. The settlement
builders enforce the pin: `payout_plan` / `resolve_plan` reject a `fee_leg`
that does not equal the pinned address (`RecipientMismatch`), so a
malicious client cannot silently redirect the fee; a zero fee still emits
no fee leg (dust payouts carry no fee, floor-rounded). The recipient is a
persisted 33-byte region in the vault account (see the layout table),
appended last so every earlier field offset stays stable, and is exported
in the AV-26 snapshot JSON (`"fee_recipient"`, `null` when unpinned).

**Absolute fee ceiling (AV-63).** An escrow can additionally cap the
*size* of the AV-17 fee (`initialize_fee_cap(max_fee_cents)`, opt-in on
`Uninitialized`, like every other `with_*` builder): after the bps rate
computes the fee for a payout, the ceiling floors it — the effective fee
is `min(floor(gross_payout × fee_bps / 10_000), fee_cap)`. A pure bps rate
grows without bound on whale-sized payouts (10 bps of a 9-figure
settlement is a 6-figure fee); pinning a ceiling at `initialize` time
makes the maximum per-payout fee a term of the escrow itself — a
consumer-protection-style cap the taker can read on-chain before
activating — while small payouts stay on the fair bps rate (the cap only
binds when the bps fee would exceed it). `0` is valid and means
"uncapped" (the default, backward compatible): a zero *fee* is expressed
via `fee_bps == 0`, so the sentinel cannot be confused with a fee waiver —
this mirrors the AV-27 timelock (`0` = no lock) and the AV-51 cliff (`0` =
no cliff) conventions. There is deliberately **no new error code**: a
zero cap is a legitimate choice, and the builder is order-independent
with `with_protocol_fee` (the ceiling applies at fee-computation time,
so either call order gives the same effective fees). The cap applies
inside `protocol_fee_for` — the one fee-computation point — so every
taker-payout path (`release`, `claim`, `release_milestone`, the taker's
share of `resolve`, and `release_period`) charges the capped fee, and the
keeper / batch / settlement-plan previews that call `protocol_fee_for`
preview the same number the chain will charge. Events keep their shape:
the payout events already report `(payout, fee)`, and the capped fee
flows through automatically. The ceiling is a persisted 8-byte region in
the vault account (see the layout table), appended last so every earlier
field offset stays stable, and is exported in the AV-26 snapshot JSON
(`"fee_cap"`, `0` when uncapped).

**Emergency pause (AV-46).** An escrow can bind an emergency-pause
authority (`initialize_pause_authority(pause_authority)`, opt-in on
`Uninitialized`, like every other `with_*` builder; the zero address is
rejected — `InvalidPauseAuthority`, code 125 — since a zero address can
never hold the switch). The bound key may then engage the circuit breaker
(`pause`) and release it (`unpause`); both are strict toggles (pausing a
paused escrow, or unpausing a live one, is `InvalidStateTransition`), and
only the bound authority may call them (`Unauthorized` otherwise; with no
authority bound the switch does not exist). While the pause is engaged,
*every* state-changing transition — `fund`, `release`, `claim`, `attest`,
`resolve`, `cancel`, the milestone and governance paths — fails fast with
`Paused` (code 124), checked before the authority and reentrancy guards so
a paused escrow reveals nothing about its configuration. Queries are
unaffected: snapshots and keeper scans read a paused escrow normally.
The authority (33-byte `Option<Pubkey>` region) and the flag (1 byte,
always present) are persisted in the vault account, appended last so every
earlier field offset stays stable (see the layout table). The flips emit
`Paused` / `Unpaused` indexer events (`from == to ==` the current state,
like `EmergencyUnlock`). Why: when an exploit is suspected — a
compromised attestor set, a downstream bug draining through
`release_via_cpi` — the operator needs one transaction that freezes every
state-changing path faster than upgrading the program. The authority is
typically a multisig or a governance program, so no single key can grief
the escrow by pausing it forever.

**Pause-authority rotation (AV-47).** The escrow authority (initializer) may
hand the pause switch to a new key at any time after initialization
(`rotate_pause_authority(new_authority)`); the old key stops working
immediately. Check order is authority → state → config: a stranger (or the
taker) is `Unauthorized`, rotation on an `Uninitialized` escrow or with no
authority bound is `InvalidStateTransition`, and the zero address is
`InvalidPauseAuthority`. Rotation is deliberately *not* gated by the pause
itself — it is the key-loss escape hatch, so it must work while paused
(rotate, then `unpause` with the fresh key); rotating to the already-bound
key is an idempotent no-op. An actual change emits the
`PauseAuthorityRotated` indexer event (`from == to ==` the current state).
The 33-byte authority region is rewritten in place — no layout or rent
change.

**Taker rotation (AV-52).** The initializer and the *current* taker may
jointly rotate the payout counterparty (`rotate_taker(new_taker)`) — the
counterparty-change scenario: a lost or compromised taker key, an invoice
reassigned to a new contractor, a payroll stream moved to a new wallet.
Both parties must sign (one alone, or a stranger pair, is
`Unauthorized`); the taker side is authenticated against the *current*
taker, so the old key consents to its own replacement. Only
`Uninitialized` / `Activated` / `Funded` — the terminal states have no
live counterparty left to rotate, and `Disputed` is excluded because
arbitration is in flight (the arbiter's `resolve` pays `taker_amount` to
the taker, so rotating mid-dispute would let a party swap in a fresh key
to dodge the ruling). Check order is authority → state → config: the
zero address is `InvalidTaker`. Only the taker field changes — amount,
released progress, attest records, milestone state, quorum, vesting are
all preserved (the 32-byte region is rewritten in place: no layout or
rent change). Unlike the pause-authority rotation, this one *is* gated by
the pause (`Paused`) — it is a config transition, not the key-loss escape
hatch. Rotating to the current taker is an idempotent no-op; an actual
change emits the `TakerRotated` indexer event (`from == to ==` the
current state). The keeper's claim listing and the snapshot export read
the live taker field, so both follow the rotation automatically.

**Initializer rotation (AV-58).** The *current* initializer and the taker
may jointly rotate the funding authority (`rotate_initializer(new_initializer)`)
— the mirror of taker rotation: a lost or compromised initializer key, a
treasury wallet migration, an operator key rollover. Both parties must
sign (one alone, or a stranger pair, is `Unauthorized`); the initializer
side is authenticated against the *current* initializer, so the old key
consents to its own replacement, and the degenerate initializer == taker
self-escrow authorizes with one key passed twice (like AV-12 activation).
Only `Uninitialized` / `Activated` / `Funded` — the terminal states have
no live escrow left to re-key, and `Disputed` is excluded because
arbitration is in flight (the arbiter's `resolve` pays the refund to the
initializer, so rotating mid-dispute would let a party swap in a fresh
key to dodge the ruling). Check order is authority → state → config: the
zero address is `InvalidInitializer`. On an actual change the
initializer's activation signature bit is cleared — the new key never
signed activation, so on a dual-sig `Uninitialized` escrow it must call
`activate` again before funding (the one deliberate asymmetry with taker
rotation: the taker bit records a vote, the initializer bit is the
funding-policy gate). Refunds follow automatically: the AV-23 whitelist
pins the destination when configured, otherwise refunds resolve to the
*current* initializer — the keeper's `cancel_expired` listing and the
snapshot export read the live field, so both follow the rotation with no
extra writes. Unlike the pause-authority rotation, this one *is* gated by
the pause (`Paused`) — it is a config transition, not the key-loss escape
hatch. Rotating to the current initializer is an idempotent no-op (the
activation bit untouched); an actual change emits the
`InitializerRotated` indexer event (`from == to ==` the current state).
The 32-byte initializer region is rewritten in place — no layout or rent
change.

**Arbiter rotation (AV-62).** The *current* initializer and the *current*
taker may jointly rotate the dispute arbiter (`rotate_arbiter(new_arbiter)`)
— the mirror of initializer rotation for the arbitration role: a lost or
compromised arbiter key, an arbitration provider migration, an operator
key rollover. Both parties must sign (one alone, or a stranger pair, is
`Unauthorized`); the initializer/taker sides are authenticated against
the *current* keys, so the old keys consent to the referee's replacement,
and the degenerate initializer == taker self-escrow authorizes with one
key passed twice (like AV-12 activation). The arbiter itself does not
sign — rotation is the two parties' governance, not an arbiter power, so
a lost arbiter key cannot block its own replacement. Only `Uninitialized`
/ `Activated` / `Funded` — the terminal states have no live dispute path
left to referee, and `Disputed` is excluded because arbitration is in
flight (never swap the referee mid-arbitration — the dispute must settle
first). Check order is authority → state → config: with no arbiter
configured there is nothing to rotate, and the zero address is rejected —
both are `InvalidArbiter` (code 108, the arbiter-config error, matching
`with_arbiter`'s zero-key rejection). Unlike initializer rotation there
is no activation bit to clear — the bitmask tracks only the initializer
and taker, so it is untouched on both the no-op and the actual change.
Unlike the pause-authority rotation, this one *is* gated by the pause
(`Paused`) — it is a config transition, not the key-loss escape hatch.
Rotating to the current arbiter is an idempotent no-op; an actual change
emits the `ArbiterRotated` indexer event (`from == to ==` the current
state). The 32-byte arbiter region is rewritten in place — no layout or
rent change. The keeper's `resolve` listing names the live arbiter as the
caller (so an arbiter-operated keeper bot follows the rotation
automatically) and the snapshot export carries the new arbiter — both
read the live field, no extra writes.

**Fee-recipient rotation (AV-67).** The *current* initializer and the
*current* taker may jointly rotate the protocol-fee recipient
(`rotate_fee_recipient(new_recipient)`) — the mirror of arbiter
rotation for the fee-destination role: a lost or compromised treasury
key, a fee-collection migration to a new treasury wallet. Both parties
must sign (one alone, or a stranger pair, is `Unauthorized`); the
degenerate initializer == taker self-escrow authorizes with one key
passed twice (like AV-12 activation). The fee recipient itself does not
sign — rotation is the two parties' governance, not a treasury power, so
a lost fee-recipient key cannot block its own replacement. Only
`Uninitialized` / `Activated` / `Funded` — the terminal states have no
future fee leg left to redirect, and `Disputed` is excluded because the
dispute settlement builders pin the fee leg to the configured recipient
(never swap the destination mid-dispute — the dispute must settle
first). Check order is authority → state → config: with no fee recipient
configured there is nothing to rotate, and the zero address is rejected —
both are `InvalidFeeRecipient` (code 123, the fee-recipient-config error,
matching `with_fee_recipient`'s zero-address rejection). Unlike
initializer rotation there is no activation bit to clear — the bitmask
tracks only the initializer and taker, so it is untouched on both the
no-op and the actual change. Unlike the pause-authority rotation, this one
*is* gated by the pause (`Paused`) — it is a config transition, not the
key-loss escape hatch. Rotating to the current recipient is an idempotent
no-op; an actual change emits the `FeeRecipientRotated` indexer event
(`from == to ==` the current state). The `Option<Pubkey>` fee_recipient
region (33 bytes) is rewritten in place — no layout or rent change. The
keeper's fee listings and the snapshot export read the live field, so
both follow the rotation with no extra writes.

**Expiry extension (AV-59).** An escrow with a hard deadline can outlive
its usefulness when both sides still want the deal: the initializer may
declare, at setup, a bounded extension budget
(`initialize_extension(max_extension_secs)`, `Uninitialized`-only — the
bound is part of the deal's DNA, so a zero budget is
`InvalidExpiryExtension`) and later push the deadline back
(`extend_expiry(new_expires_at)`), one bound-check per step:
`new_expires_at` must be strictly later than the current `expires_at`,
and each extension's increment (`new − old`) must fit inside the
remaining budget (`max_extension_secs`, saturating counter so a hostile
increment never overflows). `Activated` is deliberately excluded: a
dual-sig-activated escrow is a committed deal, and the initializer may
not rewrite its terms alone — only `Uninitialized` (no counterparty
committed yet) and `Funded` (no dual-sig committed) extend. The
AV-21 grace semantics carry over unchanged: the deadline is already
eligible for keeper cancellation once `now >= expires_at + grace_period`,
so an extension *at or past* that point is `InvalidExpiryExtension`
(the keeper has a live claim on the escrow) — a real-world "extend
before the keeper cranks it" workflow. Gated by the pause (`Paused`) like
every config transition; an actual extension emits the `ExpiryExtended`
indexer event (`from == to ==` the current state, carrying old/new
deadlines and the count). The keeper's `cancel_expired` listing and the
snapshot export read the live `expires_at`, so both follow extensions
automatically. New vault fields (appended last): `max_extension_secs`
(u64), `extension_count` (u64) — 16 bytes, so the full vault is now
2200 bytes / 16,202,880 lamports rent-exempt. AV-63 appends
`fee_cap` (u64) — 8 bytes, so the full vault is now 2208 bytes /
16,258,560 lamports rent-exempt. AV-64 appends `relative_timelock_secs`
(u64) and `fund_at` (u64) — 16 bytes, so the full vault is now 2216 bytes /
16,369,920 lamports rent-exempt. AV-65 appends `arbiter_panel`
(`Option<ArbiterPanel>`) — 595 bytes, so the full vault is now 2811 bytes /
20,511,120 lamports rent-exempt. AV-66 appends `fee_schedule`
(`FeeSchedule`: 1-byte live-tier count + 8 fixed 10-byte tier slots) —
81 bytes, so the full vault is now 2892 bytes / 21,074,880 lamports
rent-exempt.

**Error codes** (stable, never renumbered; the Anchor program maps one
program error per variant):

| Error | Code | Trigger |
|-------|------|---------|
| `Unauthorized` | 100 | caller is not the transition authority (checked before state validity) |
| `InvalidStateTransition` | 101 | transition illegal from the current state (double fund, release before fund, …) |
| `AmountMismatch` | 102 | `initialize` with `amount == 0`; `release` / `cancel_partial` / `partial_refund` with `amount == 0` |
| `NotExpired` | 103 | `cancel_expired` with `now < expires_at + grace_period` |
| `InvalidQuorum` | 104 | bad quorum policy config, or `attest` with no quorum configured |
| `QuorumNotReached` | 105 | `release` before the quorum threshold is reached |
| `ReleaseExceedsLocked` | 106 | cumulative `release` amounts exceeding the locked amount; `cancel_partial` with `amount` above the still-locked remainder |
| `InvalidVesting` | 107 | bad vesting schedule (`start >= end`, or `cliff_at > end` since AV-51), or `claim` with no vesting configured |
| `InvalidArbiter` | 108 | `with_arbiter` with the zero key, `escalate`/`resolve` with no arbiter configured, or `rotate_arbiter` with no arbiter configured / with the zero key |
| `DisputeWindowClosed` | 109 | `escalate` with `now >= expires_at` (past the dispute window) |
| `InvalidMilestones` | 110 | bad milestone plan (empty list, > 8 tranches, zero-amount tranche, tranche sum ≠ locked amount), milestone op with no plan attached, out-of-range milestone index, or `release`/`claim` with a milestone plan attached |
| `MilestoneNotConfirmed` | 111 | `release_milestone` before both parties confirmed the milestone |
| `InvalidMint` | 112 | bad mint address (empty, non-base58, or not 32 bytes), or `with_mint` with the zero address |
| `MintMismatch` | 113 | exit-path token mint ≠ the escrow's bound mint (`None` vs `Some` mismatches too) |
| `InvalidProtocolFee` | 114 | `with_protocol_fee` with `fee_bps` > 10_000 (not a valid basis-point rate); `with_fee_schedule` with an empty / over-long tier list, a tier `bps` > 10_000, or non-strictly-ascending `min_amount` floors; the flat-rate / tier-schedule mutual-exclusion conflict in either direction (AV-66) |
| `InvalidGracePeriod` | 115 | `with_grace_period` where `expires_at + grace_period` would overflow `u64` (grace on a no-timeout escrow) |
| `RefundAddressMismatch` | 116 | `cancel`/`cancel_expired` with a refund destination ≠ the whitelisted address (or ≠ the initializer with no whitelist), or `with_refund_address` with the zero address |
| `InvalidPenalty` | 117 | `with_penalty_bps` with `penalty_bps` > 10_000 (not a valid basis-point rate) |
| `TimelockNotReached` | 118 | `release`/`claim`/`release_milestone` while `now < unlock_at` (AV-27 absolute timelock) or `now < fund_at + secs` (AV-64 relative timelock); `cancel`/`cancel_expired`/`resolve` are never gated |
| `InvalidDecimals` | 119 | `with_decimals` with `decimals` > 18 (not a valid token precision) |
| `InvalidCpiTarget` | 120 | `release_via_cpi` with a zero program id, an empty account list, or a zero account key (malformed third-party invocation); since AV-83, also a target program not on the configured CPI allowlist (fail-closed, full rollback) |
| `CpiExecutionFailed` | 121 | `release_via_cpi` whose injected CPI executor reported failure after the gates passed (whole release rolled back) |
| `ReentrantCall` | 122 | a fund-moving transition entered while the AV-36 reentrancy lock was held (nested entry from inside `release_via_cpi`'s executor window) |
| `InvalidFeeRecipient` | 123 | `with_fee_recipient` with the zero address (a zero address can never be the legitimate protocol-fee destination), or `rotate_fee_recipient` with no fee recipient configured / with the zero address |
| `Paused` | 124 | any state-changing transition while the AV-46 emergency pause is engaged (`fund`/`release`/`claim`/`attest`/`resolve`/`cancel`/milestone/governance paths) |
| `InvalidPauseAuthority` | 125 | `with_pause_authority` / `rotate_pause_authority` with the zero address (a zero address can never hold the emergency switch) |
| `InvalidPayoutAllowlist` | 126 | `with_payout_allowlist` / `update_payout_allowlist` with an empty list, more than 4 addresses, or a zero address (the AV-49 allowlist must be 1-4 live payout destinations) |
| `PayoutNotAllowlisted` | 127 | a payout transition (`release` / `claim` / `resolve` / `release_milestone` / `release_via_cpi` / `release_split` — AV-93 checks every recipient) naming a `payout_to` that is neither the taker nor a member of the payout allowlist |
| `InvalidTaker` | 128 | `rotate_taker` with the zero address (a zero address can never be the legitimate payout counterparty) |
| `DefaultJudgmentNotDue` | 129 | `trigger_default_judgment` with no default judgment configured, the taker never confirmed the split, or the arbitration deadline not yet passed; `with_arbitration_deadline` with a zero deadline |
| `InvalidSubscription` | 130 | `adjust_period_amounts` on an escrow with no schedule, with a wrong-length / zero / sum-mismatched amount list, or rewriting a released period's recorded amount; `with_subscription` with a zero `period_secs`, zero or over-long `periods`, a zero `per_period`, per-period amounts that do not sum to the locked amount, a `u64::MAX` expiry (back-scheduling needs a bounded lifetime), a schedule that does not fit inside the escrow's lifetime, or on a non-`Uninitialized` escrow; `with_milestones` after a subscription (mutually exclusive release schedules); any subscription operation on an escrow with no schedule attached; or plain `release` on an escrow with a subscription (the schedule owns the release path) |
| `PeriodNotDue` | 131 | `release_period` with a `period_index` that is not the next due period (skipping ahead or replaying a released period), or with `now` before that period's back-scheduled due timestamp; periods release strictly in order, one at a time, each only once due |
| `InvalidEventCapacity` | 132 | `with_event_capacity` with `capacity == 0` or `capacity > 64` (the event-history ring holds 1..=64 entries) |
| `InvalidInitializer` | 133 | `rotate_initializer` with the zero address (a zero address can never be the legitimate initializer) |
| `InvalidExpiryExtension` | 134 | `initialize_extension` with a zero bound or on a non-`Uninitialized` escrow; `extend_expiry` with a deadline that is not later than the current one, whose increment exceeds the remaining budget, on an `Activated`/`Disputed`/terminal escrow, or when the deadline is already keeper-eligible (`now >= expires_at + grace_period`) |
| `InvalidTimelock` | 135 | `with_timelock` with a nonzero `unlock_at` while a nonzero relative timelock is configured, or `with_relative_timelock` with a nonzero `secs` while a nonzero absolute timelock is configured (one clock per escrow) |
| `InvalidArbiterPanel` | 136 | `with_arbiter_panel` with an empty member list, more than 8 members, a zero threshold, a threshold above the member count, a zero member key, or a duplicate member; `submit_panel_judgment` with no panel configured; `update_panel_threshold` (AV-69) with no panel configured or a new threshold outside 1..=N |
| `PanelResolveDisabled` | 137 | `resolve` called on a panel-mode escrow — the panel's multisig judgment (`submit_panel_judgment`) is the only settlement path once a panel is configured |
| `InvalidEvidenceDeadline` | 138 | `with_evidence_deadline` with a zero deadline — a zero-second deadline would lapse the moment the dispute starts |
| `EvidenceDisclosureLate` | 139 | `submit_evidence` at or past the disclosure deadline without evidence on record — a missed deadline locks in the judgment-time adverse inference |
| `InvalidSchemaMigration` | 140 | `migrate_schema` by a non-initializer, on a vault already at the current schema version (one-time), on a vault at an unknown future version (no skipping), or on a vault whose carried-over fields violate the conservation invariants — a corrupt vault is refused, never migrated |
| `InvalidSplit` | 142 | `split_escrow` (AV-81) with an empty amount table, more than 16 children, a zero child amount, an amount table whose `u128` sum differs from the parent's remaining lockup, or a per-child milestone-plan list whose length mismatches the amount table |
| `SlashNotEligible` | 143 | `initialize_slash_terms` (AV-82) with the zero penalty account; `slash` (AV-82) with no slash terms configured, before the slash deadline, on an already-slashed single-level escrow (one-shot), with an amount above the slashable remainder, on a ladder escrow (AV-126) above the current rung's bps cap, on a dual-sig escrow lacking both activation bits, on a `Disputed` escrow (arbitration owns the funds), or on a milestone/subscription-scheduled escrow (the schedule owns the release path) |
| `InvalidCpiAllowlist` | 144 | `with_cpi_allowlist` / `update_cpi_allowlist` (AV-83) with more than 8 program ids or a zero program id; `update_cpi_allowlist` without both signatures, on a paused escrow, on a `Released`/`Cancelled`/`Expired` vault, or with no allowlist configured |
| `InvalidMultisigAuthority` | 145 | `with_multisig_authority` (AV-84) with a zero multisig program id, a zero authority PDA, or a zero threshold; `validate_multisig_escrow_call` on a proposed vault-transaction instruction that does not carry the bound authority PDA as a signer |
| `InvalidAppealWindow` | 146 | `with_appeal_window` (AV-86) with a zero window; `file_appeal` (AV-86) with no slash executed, no window configured, an already-filed or already-resolved appeal, or a lapsed window; `review_appeal` (AV-86) voting on a never-filed or already-resolved appeal |
| `TemplateOverrideRejected` | 141 | `apply_template` (AV-77) with an override naming a field the preset did not declare overridable (unknown name, or a field from a different preset's review), a value of the wrong `OverrideValue` type, or the same field twice |
| `InvalidVestingCurve` | 147 | `VestingCurve::stepped` (AV-90) with an empty/oversized tier table, a tier outside `[start, end]`, non-monotone timestamps or unlock fractions, bps above 10_000, or a final tier below full unlock; `VestingCurve::exponential` with zero/too many steps, a non-positive or overflowing growth ratio, or a window shorter than the step count; `with_vesting_curve` with a curve whose tier window does not match the schedule |
| `InvalidEvidenceProof` | 148 | `escalate` (AV-91) with a leaf count that does not describe the committed root (`None` root with nonzero leaves, `Some` root with zero or more than 64 leaves); `file_evidence` (AV-91) with no committed root, a leaf index past the committed leaves, a proof whose length does not match the tree shape, or a proof that does not verify against the committed root |
| `InvalidVaultSeeds` | 149 | `VaultSeeds::new` / `derive_vault_address` (AV-92) with more than 16 seeds or a seed longer than 32 bytes (the Solana `create_program_address` limits) |
| `InvalidReleaseSplit` | 150 | `release_split` (AV-93) with an empty share table, more than 8 recipients, a zero recipient address, a zero bps weight, or a weight table whose sum differs from 10_000 bps (a per-recipient payout-policy violation is `PayoutNotAllowlisted`, not this code) |
| `GapInEventStream` | 151 | `MaterializedView::apply` (AV-94) with a missing `seq` (gap), an out-of-order or duplicate `seq`, or events for a different `escrow_id` than the view folds |
| `InvalidBasket` | 152 | `BasketLegs::new` (AV-95) with an empty leg table, more than 8 legs, a zero mint, a zero leg amount, a duplicate mint, or a leg-amount sum overflowing `u64`; `release_basket` / `cancel_basket` / `cancel_expired_basket` on an escrow with no basket, or with a mint outside the leg table |
| `PayoutDenied` | 153 | any payout transition (AV-96) whose `payout_to` is on the escrow's payout denylist — deny takes precedence over the AV-49 allowlist |
| `InvalidPayoutDenylist` | 154 | `PayoutDenylist::new` (AV-96) with an empty list, more than 4 addresses, or a zero address |
| `InvalidAuctionParams` | 155 | `with_dutch_auction` (AV-97) with `start_at >= end_at` (a zero-length window would divide by zero in the descending-price math) or `reserve_bps > 10_000` (not a valid basis-point floor) |
| `AuctionNotActive` | 156 | `claim` on an auction-mode escrow outside the `[start_at, end_at]` window, or `escalate` while the auction window is live (price discovery and arbitration are mutually exclusive settlement paths) |
| `InvalidTransferHook` | 157 | `with_transfer_hook` / `initialize_transfer_hook` (AV-99) with the zero program id, on a non-`Uninitialized` escrow, or before `with_mint` bound a mint (a transfer hook is a Token-2022 concept, meaningless on the native-SOL path) |
| `InvalidAppealBond` | 158 | `with_appeal_bond` / `initialize_appeal_bond` (AV-103) with a zero bond (a zero bond is a no-op — the no-bond default already covers free filing) |
| `AppealExpiryNotDue` | 159 | `expire_appeal` (AV-103) with `now <= appeal_deadline` — the permissionless sweep only runs once the window has actually lapsed |
| `InvalidDelegation` | 160 | `delegate_authority` (AV-104) with a non-party grantor, a zero operator key, an empty scope bitmap, scope bits outside the mask, or on a non-`Uninitialized`/non-`Funded` escrow; or `revoke_delegation` with no grant to revoke (an operator calling outside their scope is the pre-existing `Unauthorized`, not this code) |
| `InvalidSwapParties` | 161 | `link_swap` (AV-105) with a zero or duplicate counterparty escrow id, or with non-mirrored parties (`a.initializer != b.taker` or `a.taker != b.initializer`); also a pair settlement whose cross-link does not match the claimed pair |
| `InvalidSwapAmounts` | 162 | `link_swap` (AV-105) with a leg amount disagreeing with that leg's locked amount |
| `SwapLinkActive` | 163 | `link_swap` on an already-linked escrow; any fund-moving *single-side* transition on a live-linked non-terminal escrow (see the refusal list in the AV-105 section); or a pair op on an unlinked escrow (`None` link is this code, not a parties mismatch) |
| `InvalidPoolPayout` | 164 | `pool_payout` (AV-106) with no pool opted in, by a non-arbiter/non-multisig caller, a zero or over-balance amount, a denied/non-allowlisted beneficiary, on a non-`Funded` escrow, or while the pool is encumbered by a live appeal; or `close_vault` with a non-empty pool |
| `InvalidInterestRate` | 165 | `with_interest` / `initialize_interest` (AV-107) with `rate_bps > 10000` — above 100% APR; `amend_interest_rate` (AV-260) with `rate_bps > 10000` |
| `InterestNotEnabled` | 166 | `claim_interest` (AV-107) on an escrow with no interest rate configured (`interest_rate_bps == 0`) |
| `InvalidPayoutSplit` | 167 | `with_payout_split` / `initialize_payout_split` (AV-108) with an empty table, a zero recipient, a duplicate recipient, a zero share, more than 8 shares, or a share total != amount; `release` / `release_via_cpi` on a split-configured escrow; `release_payout_split` with no table configured |
| `InvalidDeadmanConfig` | 168 | `with_deadman_switch` / `initialize_deadman_switch` (AV-109) with `inactivity_secs == 0` or a zero-address heir, or after funding; `claim_deadman` (AV-109) on an escrow with no dead-man's switch configured |
| `DeadmanNotElapsed` | 169 | `claim_deadman` (AV-109) before `now - deadman_last_activity >= inactivity_secs` — exactly-equal counts as elapsed |
| `InvalidRentTopUp` | 170 | `top_up_rent` (AV-110) with `lamports == 0`, or the cumulative `rent_topped_up_total` counter overflowing `u64` |
| `FundingIncomplete` | 171 | `release` / `claim` / `release_milestone` (AV-111) on a tranched-funding escrow before `funded_total` reaches the plan's `total_amount` |
| `FundingTranchesExhausted` | 172 | `fund_tranche` (AV-111) when the plan's tranche budget is spent |
| `InvalidFundingPlan` | 173 | `with_funding_plan` (AV-111) with `max_tranches == 0`; `fund_tranche` with no plan attached; `fund` on a plan escrow |
| `ReleaseCoolingNotElapsed` | 174 | `release` (AV-112) while cooling is configured and no live intent exists, or before `intent_at + cooling_secs` (stacked after the AV-27 timelock gate) |
| `PriceGateNotSatisfied` | 175 | `release_price_gated` / `claim_price_gated` (AV-113) with a configured gate when the oracle is dark, the quote is stale (`now - observed_at > max_staleness_secs`), or the price misses the gate's direction condition |
| `InvalidPriceGate` | 176 | `with_price_gate` / `initialize_price_gate` (AV-113) with `target == 0`, or a vault-account decode hitting an out-of-range direction byte; `amend_price_gate` (AV-261) on an ungated escrow or with `target == 0` |
| `MergeIncompatible` | 177 | `merge_escrows` (AV-114) with different parties, mismatched vesting/vesting-curve/milestones/fee_bps/quorum/dual-sig/mint/timelock terms, or an amount counter that would overflow |
| `CompoundInterestActive` | 178 | fund-moving transitions while the AV-117 compound-interest tail is live and uncompounded |
| `InvalidClaimCooldown` | 179 | `claim` (AV-121) while the claim-cooldown tail has not elapsed since the last claim |
| `InvalidCounterOffer` | 180 | `propose_counter_offer` (AV-122) with a zero amount or a non-future expiry |
| `InvalidReleaseIntent` | 181 | `release_via_intent` (AV-123) with an Ed25519 signature that does not verify against the initializer key over the canonical intent bytes (bad signature, wrong key, wrong domain, or a retargeted `escrow` field); deliberately not `Unauthorized` — the relayer is permissionless, the signature is the authorization |
| `IntentNonceReused` | 182 | `release_via_intent` (AV-123) with a `nonce` not strictly greater than the persisted `last_intent_nonce` watermark (replay) |
| `IntentExpired` | 183 | `release_via_intent` (AV-123) with `now_slot >= expiry_slot` |
| `InvalidSlashLadder` | 184 | `with_slash_ladder` (AV-126) with an empty or over-8 rung table, a zero-bps rung, a bps above 10_000, non-ascending deadlines or bps, the zero penalty account, or when the AV-82 `with_slash_terms` are already configured (and configuring the slash terms when a ladder is already set is the same error) |
| `PartialRefundExceedsLocked` | 185 | `partial_refund` (AV-127) with `amount` above the still-locked remainder |
| `TwapGateNotSatisfied` | 186 | `release_twap_gated` / `claim_twap_gated` (AV-128) with a configured gate when the oracle is dark, the latest quote is stale, the history does not cover the full TWAP window, or the time-weighted average misses the gate's direction condition |
| `InvalidTwapGate` | 187 | `with_twap_gate` / `initialize_twap_gate` (AV-128) with `window_slots == 0` or `target == 0`, or a vault-account decode hitting an out-of-range direction byte; `amend_twap_gate` (AV-262) on a TWAP-ungated escrow or with `window_slots == 0` or `target == 0` |
| `SlippageExceeded` | 195 | `release_via_cpi` (AV-132) whose executor-reported post-execution taker-leg amount came back below the `min_payout` floor — the whole release rolled back (same atomicity as `CpiExecutionFailed`) |
| `InvalidAmountBounds` | 196 | `with_amount_bounds` / `initialize_amount_bounds` (AV-134) with `min_amount > max_amount` — an inverted funding window |
| `AmountOutOfBounds` | 197 | `fund` / `fund_tranche` (AV-134) with a deposit below `min_funding_amount` or above `max_funding_amount` — the deposit is rejected before any state moves |
| `InvalidArbiterFee` | 198 | `with_arbiter_fee` / `initialize_arbiter_fee` (AV-135) with `fee_bps > 10_000` — an invalid arbiter fee schedule |
| `BlindInvalidCommitment` | 199 | `submit_judgment_commit` (AV-137) with a zero commitment — no preimage can ever reveal against it |
| `BlindCommitMismatch` | 200 | `reveal_judgment` (AV-137) whose recomputed `SHA-256(taker_amount \|\| rationale_hash \|\| salt)` does not match the stored commitment |
| `BlindDuplicateReveal` | 201 | `reveal_judgment` (AV-137) for a commit that was already revealed — each commit reveals exactly once |
| `BlindRevealWindowClosed` | 202 | `reveal_judgment` (AV-137) after `committed_at + reveal_window_secs` lapsed |
| `BlindCommitStale` | 203 | `reveal_judgment` (AV-137) whose commit no longer matches the escrow's dispute snapshot — auto-invalidated |
| `BlindNoCommit` | 204 | `reveal_judgment` (AV-137) with no active commitment from this member |
| `BlindVoteMustReveal` | 205 | `submit_panel_judgment` on a blind-mode panel (AV-137) — direct votes are disabled, vote via commit + reveal |
| `SweepGraceNotElapsed` | 206 | `sweep_unclaimed_rent` (AV-139) on a terminal vault still inside its unclaimed-rent grace period |
| `NettingIncompatible` | 207 | `net_escrows` (AV-140) on two legs that are not opposite-direction mirrors of the same counterparty pair, with different SPL mint bindings, or whose larger leg's `released + netted` would overflow `u64` |
| `LegsCountMismatch` | 208 | batch settlement (AV-141) where the leg count does not match the vault count |
| `ClaimantNotInRoster` | 209 | `claim_share` (AV-149) by a caller who is not a roster leg |
| `ClaimantAlreadyClaimed` | 210 | `claim_share` (AV-149) on an already-pulled leg (claimed bitmask bit set) |
| `InvalidClaimantShares` | 211 | `initialize_claimants` (AV-149) with a malformed share table (empty, over-8, zero-address, zero-share, duplicate, or Σ != 10_000 bps) |
| `VestingPaused` | 212 | `claim` (AV-150) while the vesting unlock clock is paused — the taker's schedule-priced pull is frozen until `resume_vesting` |
| `VestingAlreadyPaused` | 213 | `pause_vesting` (AV-150) on an already-paused schedule — the pause is a strict toggle, so a second stamp is refused rather than silently re-stamping `paused_at` |
| `VestingNotPaused` | 214 | `resume_vesting` (AV-150) on a live (unpaused) schedule |
| `AttestorSlotInvalid` | 215 | `replace_attestor` (AV-154) with an out-of-range slot (no registered attestor occupies it) or a zero replacement key |
| `InvalidMilestoneAmendment` | 216 | `amend_milestones` (AV-155) repricing a confirmed/settled tranche, wrong tranche count, zero amount, or sum ≠ locked amount |
| `MintNotAllowlisted` | 217 | `with_mint` (AV-157) with a token mint not on the escrow's mint allowlist |
| `GovernanceDelayNotElapsed` | 218 | `execute_governance` (AV-158) on a live proposal whose delay window has not elapsed |
| `GovernanceActionNotProposed` | 219 | `execute_governance` / `cancel_governance` (AV-158) with no live proposal, or a direct dual-signed config change on a delay-opted-in escrow |
| `InvalidGovernanceDelay` | 220 | `with_governance_delay` (AV-158) with a zero window |
| `InvalidSponsorPolicy` | 225 | `SponsorPolicy::new` (AV-164) with an empty or over-long allowlist, a zero sponsor key, a duplicate key, or an inverted window |
| `SponsorNotAllowed` | 226 | `SponsorPolicy::authorize` (AV-164) for a sponsor not in the policy allowlist |
| `SponsorWindowInactive` | 227 | `SponsorPolicy::authorize` (AV-164) while the policy's effective window is not active |
| `SponsorAmountExceedsPerTxCap` | 228 | `SponsorPolicy::authorize` (AV-164) with an amount above the per-transaction lamport cap |
| `SponsorCumulativeCapExceeded` | 229 | `SponsorPolicy::authorize` (AV-164) that would push the sponsor's booked cumulative spend over the cumulative cap |
| `SponsorBudgetExhausted` | 230 | `SponsorBudget::deduct` (AV-164) with insufficient budget balance — nothing booked, nothing audited |
| `InvalidHeartbeatConfig` | 231 | `HeartbeatRegistry::new` (AV-165) with zero `expected_interval_slots` or zero `max_missed_beats`, or `register` with the zero key |
| `KeeperNotRegistered` | 232 | `HeartbeatRegistry::heartbeat` / `claim` (AV-165) for a keeper (or standby) not on the fleet roster |
| `HeartbeatSignatureInvalid` | 233 | `HeartbeatRegistry::heartbeat` (AV-165) with an Ed25519 signature that does not verify against the registered keeper key |
| `KeeperHealthy` | 234 | `HeartbeatRegistry::claim` (AV-165) on a keeper that is not unhealthy — its escrow set is not claimable |
| `ClaimConflict` | 235 | `HeartbeatRegistry::claim` (AV-165) on an already-claimed escrow set — first-come-first-served, the lost race is audited |
| `InvalidClaim` | 236 | `HeartbeatRegistry::claim` (AV-165) with a zero standby key, a self-claim, or a claimed set over `MAX_CLAIMED_ESCROWS` |
| `InvalidElectionConfig` | 237 | `KeeperElection::new` (AV-176) with zero `lease_ttl_secs`, or `acquire` with the zero key |
| `ElectionHeld` | 238 | `KeeperElection::acquire` (AV-176) while another keeper holds a live lease |
| `NotLeader` | 239 | `KeeperElection::renew` / `step_down` (AV-176) by a caller that is not the recorded leader |
| `LeaseExpired` | 240 | `KeeperElection::renew` (AV-176) after the lease lapsed — re-acquire for a new term |
| `InvalidShardMembership` | 241 | `ShardMap::new` / `update_members` (AV-177) with a zero member key or a duplicate member |
| `InvalidUpgradeAuthority` | 242 | `UpgradeAuthority::new` / `propose_handover` (AV-179) with a zero authority key, or a handover proposing the key already in effect |
| `UpgradeHandoverPending` | 243 | `UpgradeAuthority::propose_handover` (AV-179) while a handover proposal is already live |
| `NoUpgradeHandoverPending` | 244 | `UpgradeAuthority::confirm_handover` / `cancel_handover` (AV-179) with no live handover proposal |
| `UpgradeHandoverDelayNotElapsed` | 245 | `UpgradeAuthority::confirm_handover` (AV-179) before `proposed_at + handover_delay_secs` |
| `InvalidFreezeAuthority` | 246 | `ManagedFreezeAuthority::new` / `set_freeze_authority` (AV-180) with a zero token account or freeze authority key, or a rotation to the key already bound |
| `TokenAccountAlreadyFrozen` | 247 | `ManagedFreezeAuthority::freeze` (AV-180) on an already-frozen token account |
| `TokenAccountNotFrozen` | 248 | `ManagedFreezeAuthority::thaw` (AV-180) on a token account that is not frozen |
| `EscrowFrozen` | 249 | `ManagedFreezeAuthority::require_unfrozen` (AV-180) while the managed token account is frozen |
| `UnsafeMint` | 250 | `Escrow::check_mint_safety` (AV-184) on a mint carrying an escrow-hostile Token-2022 extension — fail-closed |
| `InvalidHtlcLock` | 251 | `HtlcLock::new` (AV-186) with a zero maker/taker key, a zero amount, or an expiry slot at or before the creation slot |
| `HtlcInvalidPreimage` | 252 | `HtlcLock::claim` (AV-186) with an empty preimage or one longer than `MAX_HTLC_PREIMAGE_LEN` — never hashed |
| `HtlcHashlockMismatch` | 253 | `HtlcLock::claim` (AV-186) with a preimage whose SHA-256 digest does not equal the lock's hashlock |
| `HtlcClaimExpired` | 254 | `HtlcLock::claim` (AV-186) at `current_slot >= expiry_slot` — the taker's claim window is closed |
| `HtlcRefundNotExpired` | 255 | `HtlcLock::refund` (AV-186) at `current_slot < expiry_slot` — the taker's claim window is still open |
| `InvalidNftMint` | 256 | `check_nft_mint` / `NftEscrow::new` (AV-187) on a mint with `supply != 1` or `decimals != 0` — fail-closed |
| `CollectionNotAllowlisted` | 257 | `NftEscrow::release` (AV-187) on a collection-gated escrow whose observed collection is unknown or not allowlisted — fail-closed |
| `InvalidDistribution` | 258 | `MerkleDistributor::new` (AV-188) with a zero maker key, zero or over-capacity leaf count, or `expiry_slot <= created_slot` |
| `InvalidMerkleProof` | 259 | `MerkleDistributor::claim` / `verify_proof` (AV-188) with an inclusion proof that does not recompute the published root |
| `AlreadyClaimed` | 260 | `MerkleDistributor::claim` (AV-188) on a leaf whose nullifier bit is already set |
| `DistributionExpired` | 261 | `MerkleDistributor::claim` (AV-188) at `current_slot >= expiry_slot` — the claim window is closed |
| `DistributionNotExpired` | 262 | `MerkleDistributor::reclaim` (AV-188) at `current_slot < expiry_slot` — open claims are still live |
| `InvalidEnglishAuction` | 263 | `EnglishAuction::new` (AV-189) with a zero seller key, `start_slot >= end_slot`, a zero `min_increment`, or a degenerate anti-sniping config |
| `EnglishAuctionBidTooLow` | 264 | `EnglishAuction::place_bid` (AV-189) below `highest_bid + min_increment` — the opening bid must clear `min_increment` |
| `EnglishAuctionNotLive` | 265 | `EnglishAuction::place_bid` (AV-189) outside the live window (`current_slot >= end_slot`, strict end) or on a terminal auction |
| `EnglishAuctionSettleTooEarly` | 266 | `EnglishAuction::settle` (AV-189) at `current_slot < end_slot` — the bidding window has not closed |
| `EnglishAuctionNotCancellable` | 267 | `EnglishAuction::cancel` (AV-189) after a bid landed, on a terminal auction, or after the window lapsed |
| `InvalidRentalTerms` | 268 | `RentalEscrow::new` (AV-190) with a zero owner/renter key, owner == renter, a zero rent amount, `term_end_slot <= term_start_slot`, a zero `slots_per_day`, or a late-fee rate/cap above 10_000 bps |
| `RentalNotActive` | 269 | `RentalEscrow::return_asset` (AV-190) on a rental already in a terminal state |
| `RentalCancelNotAllowed` | 270 | `RentalEscrow::cancel` (AV-190) after `term_start_slot` or on a terminal rental |
| `InvalidSealedBid` | 272 | `SealedBidAuction::new` (AV-192) with a zero seller key, `commit_start_slot >= reveal_start_slot`, or `reveal_start_slot >= end_slot`; also `commit_bid` with a zero bidder key or zero commitment; also `amend_sealed_bid_reveal_start_slot` (AV-303) outside the `new()` window or at/before `current_slot`; also `amend_sealed_bid_commit_start_slot` (AV-304) outside the `new()` window or at/before `current_slot`; also `amend_sealed_bid_end_slot` (AV-305) at/before `reveal_start_slot` |
| `SealedBidNotLive` | 273 | Sealed-bid commit/reveal (AV-192) outside its phase or on a terminal auction; also `amend_sealed_bid_min_bid` (AV-302) and `amend_sealed_bid_reveal_start_slot` (AV-303) once the reveal has started or on a terminal auction; also `amend_sealed_bid_commit_start_slot` (AV-304) once the commit window has opened or on a terminal auction; also `amend_sealed_bid_end_slot` (AV-305) once the reveal has started or on a terminal auction |
| `SealedBidDuplicateCommit` | 274 | `SealedBidAuction::commit_bid` (AV-192) from a bidder that already committed |
| `SealedBidRevealMismatch` | 275 | `SealedBidAuction::reveal_bid` (AV-192) whose `SHA-256(bid \|\| nonce \|\| bidder)` does not equal the stored commitment |
| `SealedBidSettleTooEarly` | 276 | `SealedBidAuction::settle` (AV-192) at `current_slot < end_slot` |
| `SealedBidNotCancellable` | 277 | `SealedBidAuction::cancel` (AV-192) after the first commitment, on a terminal auction, or past the commit phase |
| `SealedBidBookFull` | 278 | `SealedBidAuction::commit_bid` (AV-192) past `MAX_SEALED_BIDS` (64) commitments |
| `InvalidOracleAccount` | 279 | `PythPriceFeed::from_account_data` (AV-193) with a short account, header mismatch, or exponent outside `[-18, 0]` |
| `OraclePriceStale` | 280 | Oracle publish timestamp (AV-193) missing, in the future, or older than `max_age_secs` |
| `OraclePriceUnreliable` | 281 | Non-trading aggregate status, non-positive price, confidence wider than `max_conf_bps`, normalization failure, or unmet Switchboard oracle-result quorum (AV-193) |
| `InvalidBidDeposit` | 282 | `BidDepositAuction::new` (AV-194) with a zero auction id / zero seller key / zero deposit amount; also `register` with a zero bidder key or a duplicate registration, `settle`/`settle_sealed` on the wrong auction kind, a settle whose winner's deposit is no longer locked, `settle_sealed` whose winner never revealed, or a forfeit of an already-terminal deposit |
| `BidDepositNotRegistered` | 283 | Bid-deposit (AV-194) operation naming a bidder that never registered a deposit |
| `BidDepositAlreadySettled` | 284 | Bid-deposit (AV-194) register / reveal / forfeit / settle after the book was settled |
| `BidDepositBookFull` | 285 | `BidDepositAuction::register` (AV-194) past `MAX_BID_DEPOSITS` (64) deposits |

**Amount conservation** is pinned by a model-based fuzz test: 24
deterministic seeds × 48 random operations over 6 escrows assert
`inflow == locked + released + refunded + penalty_paid + appeal_bond_paid`
after every operation (AV-103: the taker-locked appeal bond counts in the
inflow on top of the principal), with
`amount`/`expires_at` immutable and failed operations state-preserving
(the fuzz drives full, partial, over-limit, and zero-amount releases, so
`locked` is recomputed as the unreleased remainder of `Funded` escrows
and `released` accumulates partial payouts). AV-107 extends the identity
with the interest sink: `interest_paid` joins the outflow side as its own
term (`inflow + yield == locked + released + refunded + interest_paid +
dispute_interest`), so principal (`released`) and yield (`interest_paid` /
`dispute_interest`) stay
separately auditable — the interest tests assert it across
accrue → harvest → release lifecycles. Property-based tests
(hand-rolled generator, boundary-biased amounts
`0 / 1 / u64::MAX-1 / u64::MAX` and boundary timestamps) additionally pin
per-case invariants: initialize amount dichotomy, amount preservation
across all four legal lifecycles, the `cancel_expired` edge (`now >=
expires_at + grace_period`), and quorum idempotency under random attestation order.

## Lifecycle walkthrough (sequence)

Who talks to the state machine: the caller supplies every input (authority
key, `now` timestamp); the escrow holds only its own state.

**A. Happy path — release.** Initializer funds, then releases to the taker:

```
initializer            escrow                 state
   |  fund(alice)         |                      |
   |--------------------->|  Uninitialized→Funded  |
   |  release(alice, amount)  |                   |
   |--------------------->|  Funded→Released       |
   |                      |  (payout: amount,      |
   |                      |   unchanged, to taker)  |
```

**B. Quorum-gated release.** Attestors vote (usually before funding); the
threshold gate applies only to `release`:

```
initializer   attestors          escrow                 state
   |  initialize_quorum([a1,a2,a3], 2)  |                   |
   |---------------------------------->| (policy fixed)    |
   |              attest(a1), attest(a2)  |                 |
   |              --------------------->| (approvals 1→2)   |
   |  fund(alice)  |                     |                   |
   |---------------------------------->| Uninitialized→Funded|
   |  release(alice, amount)              |                   |
   |---------------------------------->| Funded→Released     |
   |              (quorum 2-of-3 satisfied → gate passes)    |
   |  release(alice, amount)  // before threshold reached → Err(QuorumNotReached),
   |                  // state stays Funded
```

**C. Cancel.** Initializer refunds before release:

```
initializer            escrow                 state
   |  fund(alice)         |                      |
   |--------------------->|  Uninitialized→Funded  |
   |  cancel(alice)       |                      |
   |--------------------->|  Funded→Cancelled      |
   |                      |  (refund: amount,       |
   |                      |   unchanged, to initializer) |
```

**D. Expired — either party can cancel.** Taker cancels a timed-out
escrow the initializer abandoned:

```
initializer    taker            escrow                 state
   |  fund(alice)   |              |                      |
   |----------------------------->|  Uninitialized→Funded  |
   |  (silence — never releases/cancels)                    |
   |               cancel_expired(bob, now)  |              |
   |               -------------------------->|  now>=expires_at? |
   |               |             Funded→Cancelled (refund to      |
   |               |             initializer, amount unchanged)    |
   |               cancel_expired(bob, early)  // now<expires_at → Err(NotExpired),
   |                                          // state stays Funded
```

**E. Partial release — staged payout.** The initializer releases in
tranches; the escrow stays `Funded` until the cumulative total reaches
the locked amount:

```
initializer            escrow                 state
   |  fund(alice)         |                      |
   |--------------------->|  Uninitialized→Funded  |
   |  release(alice, 400_000)  |                   |
   |--------------------->|  released=400_000,     |
   |                      |  remaining=600_000,    |
   |                      |  stays Funded          |
   |  release(alice, 600_001)  // → Err(ReleaseExceedsLocked),
   |                      |   // state + released unchanged
   |  release(alice, 600_000)  |                   |
   |--------------------->|  released=1_000_000,   |
   |                      |  Funded→Released       |
```

`released_amount()` / `remaining_amount()` report the progress at every
step (here: 400_000 / 600_000 after the first tranche), and a later
`cancel` refunds only the remainder while `released_amount()` stays
preserved for audit.

**F. Dual-signature activation.** Both parties must sign before funding;
one signature alone changes nothing fundable:

```
initializer    taker            escrow                 state
   |  initialize_dual_sig()  |  |                      |
   |----------------------------->| (requirement fixed,  |
   |                             |  still Uninitialized) |
   |  activate(alice)  |          |                      |
   |----------------------------->|  (initializer bit;    |
   |                             |   stays Uninitialized)|
   |  fund(alice)  // → Err(InvalidStateTransition):      |
   |              // one signature cannot fund            |
   |               activate(bob)  |                      |
   |               -------------------------->|  Uninitialized→Activated |
   |  fund(alice)  |                          |           |
   |------------------------------------------>|  Activated→Funded      |
```

**G. Streaming release — taker pulls the vested stream.** The unlock
curve is fixed before funding; the taker claims whatever newly vested
since the last claim:

```
initializer    taker            escrow                 state
   |  initialize_vesting(t0, t1)  |  |                 |
   |-------------------------------->| (curve fixed,    |
   |                               |  still Uninitialized)|
   |  fund(alice)   |              |                      |
   |----------------------------->|  Uninitialized→Funded  |
   |               claim(bob, t0+(t1-t0)/2)  |            |
   |               -------------------------->|  vested=amount/2,|
   |                                          |  released=amount/2,|
   |                                          |  stays Funded      |
   |  release(alice, amount/4)  |             |           |
   |----------------------------->|  (initializer push   |
   |                             |   ahead of the curve)  |
   |               claim(bob, t1) |                      |
   |               -------------------------->|  vested=amount,  |
   |                                          |  released=amount,  |
   |                                          |  Funded→Released   |
```

**H. Disputed — arbitration locks the exits, the arbiter splits the
remainder.** Either party escalates inside the dispute window; every
unilateral exit is then frozen until the arbiter rules:

```
initializer    taker         arbiter            escrow                 state
   |  initialize_arbiter(judge)  |  |                              |
   |-------------------------------->| (arbiter fixed,             |
   |                                |  still Uninitialized)         |
   |  fund(alice)   |              |  |                            |
   |----------------------------->|  Uninitialized→Funded          |
   |               escalate(bob, now<expires_at)  |                  |
   |               ------------------------------>|  Funded→Disputed |
   |  release(alice, …)  // → Err(InvalidStateTransition):         |
   |                    // exits locked while Disputed             |
   |               cancel_expired(bob, late)  // → Err(InvalidStateTransition), |
   |                                         // even after expiry  |
   |                             resolve(judge, 600_000)  |         |
   |                             ------------------------>|  Disputed→Settled, |
   |                                                      |  taker←600_000,   |
   |                                                      |  initializer←400_000 |
```

**I. Milestone tranches — dual-confirmed releases, dual-signed skip.**
The tranche schedule is fixed before funding; each tranche releases after
both parties confirmed its milestone, in order. Skipping needs both
parties' approval and refunds the tranche to the initializer:

```
initializer    taker            escrow                 state
   |  initialize_milestones([400_000, 600_000])  |      |
   |-------------------------------------------->|  (plan fixed,    |
   |                                           |  still Uninitialized)|
   |  fund(alice)   |              |                      |
   |----------------------------->|  Uninitialized→Funded  |
   |  confirm_milestone(alice, 0)  |                      |
   |----------------------------->|  (initializer bit)     |
   |               confirm_milestone(bob, 0)  |            |
   |               -------------------------->|  milestone 0     |
   |                                          |  confirmed (dual) |
   |  release_milestone(alice, 0)  |           |           |
   |----------------------------->|  released=400_000,    |
   |                             |  stays Funded          |
   |  release_milestone(alice, 1)  // → Err(MilestoneNotConfirmed):
   |                             // milestone 1 unconfirmed
   |  skip_milestone(alice, 1)  |             |           |
   |----------------------------->|  (one approval:      |
   |                             |   nothing executes)    |
   |               skip_milestone(bob, 1)  |              |
   |               -------------------------->|  milestone 1     |
   |                                          |  skipped:        |
   |                                          |  skipped=600_000,|
   |                                          |  released=400_000,|
   |                                          |  stays Funded     |
```

After the skip, `remaining_amount()` is 600_000 (amount − released; the
skipped tranche stays in the refundable remainder), and a later `cancel`
refunds it while `released_amount()` / `skipped_amount()` stay preserved
for audit.

**J. Token-scoped escrow — mint binding and mismatch.** The mint is bound
before funding; every fund-moving call then carries the vault token
account's mint, and a mismatch fails closed:

```
initializer            escrow                 state
   |  initialize_mint("TokenkegQfe…")  |      |
   |---------------------------------->|  (mint bound,      |
   |                                 |  still Uninitialized)|
   |  fund(alice)         |                      |
   |--------------------->|  Uninitialized→Funded  |
   |  release(alice, amount, Some(WRONG_MINT))    |
   |---------------------------------->|  → Err(MintMismatch),
   |                                 |  state + released unchanged
   |  release(alice, amount, None)  // → Err(MintMismatch):
   |                             // bound escrow, SOL path refused
   |  release(alice, amount, Some(BOUND_MINT))    |
   |---------------------------------->|  Funded→Released     |
```

**K. Emergency timelock unlock — dual-signed early clearing.** The
governance is opted in before funding; both parties must sign, and the
call clears the timelock (absolute or AV-64 relative) without moving state or funds:

```
initializer    taker            escrow                 state
   |  initialize_emergency_unlock()  |  |             |
   |---------------------------------->|  (governance   |
   |                                   |   fixed, still |
   |                                   |   Uninitialized)|
   |  fund(alice)  |                     |              |
   |---------------------------------->| Uninitialized→Funded |
   |  emergency_unlock(alice)  // only the initializer → Err(Unauthorized),
   |                          // timelock intact, state unchanged
   |               emergency_unlock(alice, bob)  |       |
   |               ---------------------------->|  (timelock  |
   |                                           |   cleared → |
   |                                           |   0; stays  |
   |                                           |   Funded;   |
   |                                           |   Emergency |
   |                                           |   Unlock    |
   |                                           |   emitted)  |
   |  release(alice, amount, early)  |                       |
   |---------------------------------->| Funded→Released       |
```

**L. Default penalty — slash the defaulting taker.** The penalty clause
is opted in before funding: the penalty account (the sink that receives
slashed funds) and the deadline after which the default is enforceable.
If the deadline passes with the escrow still `Funded`, the initializer —
or the configured arbiter as the neutral enforcer — slashes once:

```
initializer    arbiter          escrow                 state
   |  initialize_slash_terms(penalty, t0+30d)  |       |
   |------------------------------------------>|  (terms fixed,  |
   |                                           |   still Uninitialized)
   |  fund(alice)  |                          |              |
   |------------------------------------------>| Uninitialized→Funded |
   |  slash(alice, amount/5, t0+10d)  // before the deadline → |
   |                                 // Err(SlashNotEligible), |
   |                                 // penalty_paid unchanged |
   |  slash(alice, amount/5, t0+31d)  |                       |
   |------------------------------------------>|  penalty_paid=  |
   |                                           |  amount/5, stays |
   |                                           |  Funded; Escrow  |
   |                                           |  Slashed emitted |
   |  slash(alice, amount/5, t0+32d)  // second slash →         |
   |                                 // Err(SlashNotEligible):  |
   |                                 // one-shot                |
   |               slash(carol, amount/5, t0+31d)  |            |
   |               ----------------------------->|  (arbiter as   |
   |                                            |   neutral      |
   |                                            |   enforcer —   |
   |                                            |   but already  |
   |                                            |   slashed →    |
   |                                            |   Err(SlashNotEligible))
   |  release(alice, amount, bob)  // → Err(ReleaseExceedsLocked):
   |                             // capped at amount − released − penalty_paid
   |  release(alice, 4*amount/5, bob)  |                      |
   |------------------------------------------>|  Funded→Released |
```

The slashed amount never touches `released` — the audit trail keeps the
default penalty and the taker payout in separate buckets, and the
conservation invariant becomes `amount == released + penalty_paid +
remaining`. A `Disputed` escrow rejects slash (arbitration owns the
funds), and milestone/subscription-scheduled escrows reject it too (the
schedule owns the release path).

Note that `attest` never changes `EscrowState` itself (it only grows the
quorum's approval bitmask), and the failed-call invariant holds on every
path above: any `Err(...)` return leaves the state — and `amount` and the
`released` counter — exactly untouched (pinned by the
permission/fuzz/property tests).

**M. Slash appeal window — the taker contests the penalty.** The appeal
clause is opted in before funding alongside the slash terms: the window
in seconds during which the taker may appeal an executed slash. Without
a window, slashes are final (backward compatible). When the initializer
or arbiter slashes, the window's deadline is stamped as
`slash_now + window_secs`; inside it, the taker files one appeal and
the arbiter panel reviews it — uphold keeps the penalty, overturn
refunds it to the taker (a restitution, no fee):

```
initializer      taker           panel member      escrow
   |  initialize_appeal_window(7d)  |                |       |
   |------------------------------------------>|  (window fixed, |
   |                                           |   still Uninitialized)
   |  initialize_slash_terms(penalty, t0+30d)  |       |
   |------------------------------------------>|               |
   |  fund(alice)  |                          |              |
   |------------------------------------------>| Uninitialized→Funded |
   |  slash(alice, amount/5, t0+31d)  |                       |
   |------------------------------------------>|  penalty_paid=  |
   |                                           |  amount/5, stays |
   |                                           |  Funded; appeal  |
   |                                           |  deadline =      |
   |                                           |  slash_now + 7d  |
   |               file_appeal(bob)  |                       |
   |               ---------------------------->|  appeal filed;   |
   |                                            |  AppealFiled     |
   |                                            |  emitted         |
   |                                review_appeal(carol, false)    |
   |                                ---------------------------->|
   |                                            |  vote recorded;|
   |                                            |  ballot open — |
   |                                            |  no event yet  |
   |                                review_appeal(dave, false)     |
   |                                ---------------------------->|
   |                                            |  threshold met:|
   |                                            |  Overturned;   |
   |                                            |  penalty_paid  |
   |                                            |  → 0, released |
   |                                            |  += amount/5;  |
   |                                            |  AppealResolved|
   |                                            |  emitted       |
   |               file_appeal(bob)  // second filing →          |
   |                                 // Err(InvalidAppealWindow):|
   |                                 // one appeal per slash    |
```

The appeal is a procedural safeguard, not a second negotiation: the
window gates the *filing* (a lapsed window is a hard bar), the panel's
threshold gates the *resolution*, and the ballot is terminal — a
resolved appeal rejects further votes, so the recorded votes stay as
the audit trail of how the panel decided.

**Appeal bond (AV-103) — the taker stakes on the challenge.** The
initializer may additionally opt in to a bond (before funding, alongside
the window): when the taker files, the configured bond is locked into
an independent `appeal_bond_paid` counter — never mixed into
`released` or `penalty_paid`, never part of the claimable/release
base while the appeal is pending (the conservation invariant becomes
`inflow == locked + released + refunded + penalty_paid +
appeal_bond_paid`, with the locked bond counted in the inflow). The
bond is a cost the taker pays for a frivolous appeal, not a price the
panel can negotiate with:

- **Overturn** — the bond is refunded to the taker in full, no fee
  (never into `released`); `AppealResolved` carries the full
  restitution in `payout` (penalty + bond).
- **Upheld** — the bond is forfeited to the initializer
  (`AppealResolved` carries it in `amounts.penalty`).
- **Window expires unresolved** — the slash stands as if upheld; the
  bond is forfeited to the initializer via the permissionless
  `expire_appeal` sweep (anyone may crank a lapsed appeal — the
  keeper surfaces it as `ExpireAppeal`), which emits `AppealExpired`
  and returns the forfeited amount so the transfer can be sized. A
  sweep attempt before the deadline is `AppealExpiryNotDue` (code
  159).

No bond configured means filing stays free (backward compatible) —
`file_appeal` then returns `0`, and both loss paths transfer nothing.

**N. Multi-taker share claiming — the roster pulls its legs.** The
initializer declares a 2-of-2 split before funding; each claimant
pulls their own leg, and the last pull clears the vault:

```
initializer      claimant1      claimant2        escrow
   |  initialize_claimants([(c1,5000),(c2,5000)])  |        |
   |-------------------------------------------->| (roster fixed, |
   |                                             |  still Uninitialized)
   |  fund(alice)  |              |              |              |
   |-------------------------------------------->| Uninitialized→Funded |
   |               claim_share(c1)  |            |              |
   |               ---------------------------->|  c1 pulls 50% |
   |                                            |  (bit 0 set;  |
   |                                            |  stays Funded)|
   |               claim_share(c1)  // replay →                 |
   |                              // Err(ClaimantAlreadyClaimed)|
   |                              claim_share(c2)  |           |
   |                              ---------------->| c2 takes  |
   |                                            |  the rest;   |
   |                                            |  Funded→     |
   |                                            |  Released    |
```

### Vesting pause / resume (AV-150)

The initializer freezes a streaming-payments schedule mid-flight and
restarts it later; the pause never moves the state byte.

```
initializer      taker          escrow
   |  pause_vesting()  |            |
   |------------------->| (paused_at = now; |
   |                    |  still Funded)    |
   |               claim()  |               |
   |               -------->| Err(VestingPaused) |
   |  resume_vesting()  |            |
   |------------------->| (start/end/cliff_at += |
   |                    |  now - paused_at;      |
   |                    |  still Funded)         |
   |               claim()  |               |
   |               -------->| vested amount for |
   |                         | the shifted window |
```

The schedule's start, end and cliff shift forward by the paused
duration, so the unlock duration — and the taker's eventual payout —
is unchanged. The freeze is scoped to the taker's schedule-priced
`claim`: the initializer's `release` push path, the roster's
`claim_share`, and `cancel`/`cancel_expired` refunds are unaffected
(by design — a pause halts the unlock clock, not the escrow).

### Delayed governance (AV-158)

The four dual-signed config changes — `update_quorum`,
`update_attestors`, `rotate_taker`, `update_payout_allowlist` — can
opt in to a propose → delay → execute/cancel protocol via
`initialize_governance_delay(delay_secs)`. The delay is a
flash-governance defense: if an attestor goes dark, a malicious
threshold change cannot take effect immediately.

```
initializer      taker          escrow
   |  propose_governance(UpdateQuorum{1})  |
   |------------------------------------->| (proposal live;
   |                    |  proposed_at = now)
   |  execute_governance()  |              |
   |----------------------->| Err(GovernanceDelayNotElapsed)
   |                    |                   |
   |  ... delay elapses ... |               |
   |                    |                   |
   |               cancel_governance()       |
   |               ------------------->| (either party may
   |                    |  veto; proposal cleared)
   |  execute_governance()  |              |
   |----------------------->| (threshold = 1;
   |                         |  proposal cleared)
```

Either party may propose, execute (once the delay elapses), or
cancel (the defensive veto — works even while paused). Re-proposing
replaces a live proposal and restarts the delay clock. The delay
gates **config changes only** — fund flows (`release`, `claim`,
`cancel`, etc.) are never delayed. On a delay-opted-in escrow, the
direct dual-signed calls refuse with `GovernanceActionNotProposed`
(code 219); escrows without the opt-in keep the immediate
dual-signed governance (backward compatible).

## Indexer events (AV-18)

Every state transition of the escrow state machine emits one typed
`EscrowEvent` through the `IndexedEscrow` adapter
(`escrow-state/src/events.rs`) — no existing `Escrow` signature changed,
and the crate stays dependency-free. A chain indexer subscribes to state
changes in per-escrow `seq` order instead of polling account data.

**Event shape.** Each event carries:

| field | meaning |
|-------|---------|
| `kind` | `EscrowEventKind`: `Initialized`, `Activated`, `Funded`, `Released`, `Cancelled`, `ExpiredCancelled`, `ExpiredCranked` (AV-48), `KeeperBountyPaid` (AV-124), `Attested`, `QuorumUpdated`, `AttestorsUpdated`, `Claimed`, `ShareClaimed` (AV-149), `VestingPaused` (AV-150), `VestingResumed` (AV-150), `AttestorReplaced` (AV-154), `MilestonesAmended` (AV-155), `Escalated`, `Resolved`, `MilestoneConfirmed`, `MilestoneReleased`, `MilestoneSkipped`, `MilestonesAdjusted` (AV-70), `EmergencyUnlock`, `VaultClosed`, `TakerRotated` (AV-52), `ArbiterRotated` (AV-62), `PartiallyCancelled` (AV-60), `PanelJudgment` (AV-65), `PanelResolved` (AV-65), `EvidenceSubmitted` (AV-68), `PanelThresholdChanged` (AV-69), `SubscriptionAmountsAdjusted` (AV-73), `SchemaMigrated` (AV-75), `BundlePartiallyExecuted` (AV-76), `TemplateApplied` (AV-77), `EscrowSplit` (AV-81), `Slashed` (AV-82), `CpiAllowlistUpdated` (AV-83), `AppealFiled` (AV-86), `AppealResolved` (AV-86), `EvidenceFiled` (AV-91), `ReleasedSplit` (AV-93), `Declined` (AV-122), `CounterOfferProposed` (AV-122), `CounterOfferAccepted` (AV-122), `CounterOfferRejected` (AV-122) |
| `escrow_id` | caller-supplied 32-byte escrow identity (on-chain: the vault PDA public key) |
| `seq` | per-escrow monotonic sequence; `0` is the `Initialized` event |
| `from` → `to` | `EscrowState` before and after the call |
| `amounts` | one struct for every kind: `payout` (gross taker amount before the fee split), `fee` (AV-17 protocol fee), `refund` (initializer's refund), `penalty` (AV-24 anti-griefing penalty on a taker-initiated `cancel_expired` / taker crank), `rent_reclaimed` (AV-34 rent-exempt deposit reclaimed on `VaultClosed`); zeroed when the kind moves no such value |
| `at` | caller-supplied Unix-seconds timestamp (`cancel_expired` / `crank_expired` / `escalate` / `claim` reuse their `now`) |
| `caller` | AV-48: the permissionless crank caller's key, carried by `ExpiredCranked` (and by `KeeperBountyPaid`, AV-124) only (`None` on every other kind) |
| `evidence_defaulted` | AV-68: whether the escalating party's evidence disclosure had defaulted at judgment time — `true` only on the settlement kinds (`Resolved`, `DefaultJudgment`, `PanelResolved`) when a disclosure deadline was configured, it had lapsed at the event's `at` timestamp, and no evidence was on record; the judgment-time adverse-inference signal biasing the absent-evidence weight toward the non-escalating party (`false` on every other kind) |
| `slash_ladder_index` | AV-126: the actually-consumed rung carried by the `Slashed` event — `None` on single-level slashes and every other kind |

**Emission rule.** Exactly one event per *successful* call that changes
externally-observable state; failed calls emit nothing, and neither do
successful calls that change nothing observable:

- `with_*` builders are configuration, not transitions — no events.
- `activate` emits only when it flips `Uninitialized → Activated`; a
  single party's signature emits nothing.
- `attest` emits when it records a *new* attestation (the quorum's
  approval count grows) — quorum progress is what an indexer watches to
  know when the release gate opens; duplicate votes emit nothing.
- `update_quorum` emits `QuorumUpdated` when the threshold actually
  changes (`from == to ==` the current state, all amounts zero) — the
  event is the ordering signal that the release gate moved, the new
  threshold is read from the vault; a no-op re-affirmation emits
  nothing.
- `update_attestors` emits `AttestorsUpdated` when the attestor set
  actually changes (`from == to ==` the current state, all amounts
  zero) — the ordering signal that the release gate's electorate
  changed, the new set is read from the vault (approval bits are
  remapped by pubkey: retained votes survive, removed voters' bits are
  cleared); a no-op same-set update emits nothing.
- `update_panel_threshold` emits `PanelThresholdChanged` when the
  panel's M-of-N threshold actually changes (`from == to ==
  Uninitialized`, all amounts zero) — the ordering signal that the
  judgment rule moved, the new M is read from the vault; cast votes
  are untouched by the retune (the panel's judgment history is
  append-only); a no-op retune to the current threshold emits
  nothing.
- `confirm_milestone` emits when the milestone becomes fully confirmed
  (the completing vote); the first party's confirmation alone emits
  nothing, paralleling `activate`.
- `skip_milestone` emits only when the skip executes (both approvals
  present); a lone approval emits nothing.
- Partial `release` / `claim` calls emit with `from == to == Funded` so
  the payout stream is complete in `seq` order; the closing payout has
  `to == Released`.
- `cancel_expired` emits `ExpiredCancelled` with the exact
  `(refund, penalty)` split in `amounts` (AV-24): a taker-initiated
  cancel carries the penalty earmarked for the initializer, an
  initializer-initiated cancel carries `penalty == 0`.
- `crank_expired` emits `ExpiredCranked` with the crank caller's key in
  `caller` (AV-48); when the vault opted into the keeper bounty, the
  state machine additionally emits `KeeperBountyPaid` (`from == to ==
  Cancelled` — the unwind is already final; AV-124) carrying the paid
  bounty in `amounts.payout`, the caller in `caller`, and the
  post-debit pool in `bounty_pool_remaining`. A zero-bounty crank emits
  `ExpiredCranked` alone.
- `cancel_partial` (AV-60) emits `PartiallyCancelled` with
  `from == to == Funded` and `amounts.refund` carrying the refunded
  tranche — the refund stream's mirror of a partial `Released` event.
- `partial_refund` (AV-127) emits `PartialRefunded` with
  `from == to == Funded` and `amounts.refund` carrying the refunded
  tranche — like `PartiallyCancelled`, but the tranche also
  accumulates in the vault's persisted `refunded` counter.
- `close_vault` emits `VaultClosed` with `from` the terminal state the
  escrow was in (`Cancelled` / `Released` / `Settled` / `Split` — AV-81)
  and `to == Closed`; `amounts.rent_reclaimed` carries the reclaimed
  rent-exempt deposit (AV-34), every other amount is zero.
- `split_escrow` (AV-81) emits `EscrowSplit` on the parent's log
  (`from == Funded`, `to == Split`; `amounts.payout` is the Σ child
  amounts — the gross re-locked into the children — every other amount
  zero; the `(child_id, amount)` roster rides the event's
  `split_children` field, so the whole split family is re-derivable
  from the one event). Each child gets its own log — `Initialized`,
  then `Funded` (and `Activated` between them when the children inherit
  dual-signature activation) — under its derived escrow ID.
- `close_indexed_vaults` (AV-79) emits one `VaultClosed` per vault it
  actually closes (exactly the AV-34 emission), then a single
  `VaultsBatchClosed` summary on the first closed vault's log (`from ==
  to == Closed` — a composition summary, not a lifecycle move;
  `amounts.rent_reclaimed` is the Σ rent-exempt lamports the batch
  reclaimed). A batch that closes nothing emits no summary event.
- `release_and_close` (AV-50) emits `Released` (`from == Funded`,
  `to == Released`, gross payout + fee) and then `VaultClosed`
  (`from == Released`, `to == Closed`, `rent_reclaimed`) in that fixed
  order — one payout-then-close pair per instruction.
- `release_split` (AV-93) emits `ReleasedSplit` (`from == Funded`,
  `to == Funded` on a partial split, `to == Released` on the closing
  one — the same lifecycle shape as `Released`; `amounts.payout` is the
  gross amount, `amounts.fee` the AV-17 protocol fee charged on the
  gross before the split; the per-recipient `(recipient, net_share)`
  legs ride the event's `release_split` field in table order — the first
  leg carries the bps-floor dust, so an indexer re-derives the exact
  transfer sizes from the one event).
- `release_via_intent` (AV-123) emits `ReleaseViaIntent` (`from ==
  Funded`, `to == Funded` on a partial release, `to == Released` on the
  closing one — the same lifecycle shape as `Released`; `amounts.payout`
  is the gross amount, `amounts.fee` the AV-17 protocol fee; the intent's
  `nonce` and `expiry_slot` ride the event's intent fields, and the
  event's actor is the initializer — the permissionless relayer never
  appears in the audit trail, the signed intent is the authorization).
- `release_basket` / `cancel_basket` / `cancel_expired_basket` (AV-95b)
  emit `BasketReleased` / `BasketCancelled` / `BasketExpiredCancelled`
  per settled leg (`from == Funded`, `to == Funded` while legs remain,
  `to == Released` / `Cancelled` on the last leg; amounts follow the
  `Released` / `Cancelled` / `ExpiredCancelled` shapes per leg).
- `release_basket_all` / `cancel_basket_all` (AV-95c) emit a **single**
  `BasketReleased` / `BasketCancelled` for the atomic all-legs
  settlement (`from == Funded`, `to == Released` / `Cancelled`;
  `amounts.payout` = Σ leg gross, `amounts.fee` = Σ protocol fee /
  `amounts.refund` = Σ remainder) — the event-sourced fold (AV-94)
  books the one Σ event bit-identically to the per-leg sequence it
  replaces, so indexers need no special case.
- `submit_panel_judgment` (AV-65) emits `PanelJudgment` for every
  recorded vote (`from == to == Disputed`, zeroed amounts — a vote is
  a judgment, not a payout); the vote that reaches the M-vote
  threshold additionally emits `PanelResolved` immediately after
  (`from == Disputed`, `to == Settled`, `amounts` carrying the
  `Resolved` shape — gross taker payout / fee / initializer refund —
  plus the winning vote's rationale hash).
- `drain_events()` takes the recorded events and clears the log; the
  sequence counter keeps running, so a resuming indexer never sees
  duplicates.

**Materialized fund view (AV-94).** `escrow-state/src/event_sourcing.rs`
folds an `EscrowEvent` stream into the per-escrow fund triple
(`locked`, `released`, `refunded`) that keeper/indexer tooling consumes,
plus the fleet aggregate (`fold_fleet`). Every event kind maps to a
`(Δlocked, Δreleased, Δrefunded)` delta: taker payouts book the gross
(the AV-17 fee is internal routing — `released` matches the state
machine's `released` counter bit-for-bit), dispute settlements split
into taker `released` / initializer `refunded`, `EscrowSplit` re-locks
sideways, and the AV-82 slash books nothing (the penalty has no leg in
the triple — it stays parked inside `locked`, so the fold's `locked` is
`remaining_amount() + penalty_paid()`). `apply` enforces strict `seq`
continuity — a gap, an out-of-order or duplicate `seq`, or a foreign
`escrow_id` stops the fold with `GapInEventStream` (code 151); the valid
prefix stays applied and the caller backfills from `next_seq`. Two
constructors: `replay` (genesis fold from an explicit funded amount —
the `Funded` event carries none) and `from_snapshot` (snapshot base at
`snapshot_seq` + incremental `apply`; a genesis replay and a
snapshot+incremental run agree bit-for-bit). Pure logic, zero
dependencies.

**Anchor `emit!` mapping.** `programs/escrow-vault/src/program.rs` mirrors
each kind: `EscrowVaultEvent` (`#[event]`) is the on-chain mirror of
`EscrowEvent`, `EscrowVaultEventKind` the mirror of `EscrowEventKind`
(mapped by `escrow_event_kind`, paralleling the `escrow_error` →
`ErrorCode` mapping), and every transition instruction calls
`emit_transition` after a successful state change — with the same
conditional-emission rules (`activate`, `attest`, `confirm_milestone`,
`skip_milestone` only emit when the observable change completes). `at`
comes from the clock sysvar; `seq` is the vault's persisted per-escrow
counter (the real build appends it to the `Vault` account, growing
`VAULT_SPACE` 540 → 548).

**Per-escrow event history (AV-57).** The off-chain event log is not
the only record: every successful transition the `IndexedEscrow`
adapter emits also lands in a fixed **ring buffer persisted in the
vault account** — the on-chain audit trail. Each escrow retains its
most recent N records; each record is the event `kind`, the `at`
timestamp, and the actor's 8-byte summary (the first 8 bytes of the
actor's pubkey — a digest, not the full address, so the account stays
lean). `None` actors are honest omissions: dual-signed governance
transitions record no single actor (the actor is the signature pair,
not one key), and reentrancy rejections record none (the nested call
fails before the authority check, so the hostile actor is unknown).

- **Capacity:** N is configurable 1–64 via `with_event_capacity`
  (`Uninitialized` only, like every other `with_*` builder; default
  64). The account always reserves all 64 slots (18 bytes each: kind
  u8 + at u64 + actor tag u8 + 8-byte summary), so a smaller capacity
  never needs a realloc — entries past it stay zeroed.
- **Wrap:** while the buffer is filling, records land in order; once
  full, the oldest entry is overwritten and the head advances. The
  `event_total` counter is monotonic regardless — it never decreases —
  so `total − count` tells an indexer exactly how many records aged
  out of the window.
- **Reads:** `escrow.event_history()` returns the retained window
  oldest-first; the AV-26 snapshot export carries the full window
  (`capacity` / `total` / `count` / `entries`) so one snapshot read
  gives an indexer everything.
- **Emission rule:** the ring follows the same rule as the event log —
  exactly one record per successful transition, none for failed ones
  (the AV-36 `ReentryRejected` exception aside, which records with no
  actor).

New vault fields (appended last): `event_head` (u8), `event_total`
(u64), `event_count` (u8), `event_capacity` (u8), `event_slots`
(64 × 18 bytes) — 1163 bytes, so the full vault is now 2184 bytes /
16,091,520 lamports rent-exempt (see [Account space &
rent](#account-space--rent)).

### Event CSV export (AV-74)

The typed log also renders as deterministic CSV
(`escrow-state/src/event_csv.rs`: `events_to_csv` /
`csv_to_events`) — the data-analysis / audit-ingest complement to the
AV-26 snapshot JSON export. One row per event, fixed column order, a
header row, LF line endings, and hand-written RFC 4180 escaping (the
crate stays dependency-free):

```text
kind,seq,at,actor,payout,fee,refund,penalty,rent_reclaimed
initialized,0,1700000000,1d1d…1d,0,0,0,0,0
released,2,1700000002,1d1d…1d,400000,4000,0,0,0
```

- `kind` is the canonical snake_case event name (`released`,
  `milestone_confirmed`, …); `seq` / `at` / amounts are decimal
  `u64`; `amounts` is expanded in place (`payout` = gross taker
  amount, `fee` = AV-17 protocol fee, `refund`, `penalty`,
  `rent_reclaimed`).
- **Actor provenance.** `EscrowEvent` carries no dedicated actor
  field, and the log never invents one — the only per-escrow identity
  every event carries is `escrow_id` (32 bytes; on-chain, the vault
  PDA public key). The `actor` column is that identity as 64 lowercase
  hex (the snapshot serializer's convention), so the column answers
  "which escrow did this event come from", not "who signed this
  transition".
- **A projection, not a full serialization.** Only the nine columns
  round-trip. `csv_to_events` reconstructs the carried fields exactly
  and fills the rest with documented zero-values (`from == to ==
  Uninitialized` as the explicit "not carried" marker; `None` for
  `evidence_hash` / `rationale_hash` / `cpi` / `caller` / `reference`;
  `evidence_defaulted = false`). `events_to_csv(csv_to_events(csv))`
  is byte-identical to the input for any exporter-written CSV, and
  the parser never panics — malformed input (bad header, wrong field
  count, unknown kind, non-decimal integer, non-hex actor,
  unterminated quote) maps to a precise `CsvError`.

## Keeper report (AV-20)

A keeper bot watches many vaults and needs the executable call list, not
raw account data. `escrow-state/src/keeper.rs` scans a batch of
`WatchedEscrow { escrow_id, escrow }` snapshots at a given `now` and
returns a `KeeperReport` of immediately executable calls:

| action | listed when | caller | `amount` |
|--------|-------------|--------|----------|
| `cancel_expired(authority, now, mint, refund_to)` | `Funded`, `now >= expires_at + grace_period` (grace-aware: the keeper never lists a call the chain would reject as `NotExpired`), remainder > 0 | initializer (canonical; the taker may also call) | refundable remainder (never fee'd) |
| `crank_expired(caller, now, mint)` (AV-48) | `Funded`, `now >= expires_at + grace_period`, remainder > 0, **not paused** (the crank fails on a paused escrow, so it is only listed when executable) | `"anyone"` — permissionless; the keeper substitutes its own key (serialized as the zero key) | refundable remainder (never fee'd); the refund goes to the same pinned `refund_to` as the party path — the cranker receives nothing (anti-MEV) unless the vault opted into the AV-124 keeper bounty, in which case the action carries `bounty_lamports = min(per_crank, pool)` and a `bounty_unprofitable` flag (true when the bounty does not cover the estimated `crank_expired` execution cost) |
| `crank_release_period(caller, now, mint)` (AV-160) | `Funded`, attached schedule, next period due at scan time (`now >= due_at`), **not paused** (the crank fails on a paused escrow, so it is only listed when executable) | `"anyone"` — permissionless; the keeper substitutes its own key (serialized as the zero key) | live per-period amount (`payout + fee == per_period`); the payout goes to the pinned taker — the cranker receives zero (anti-MEV, no keeper bounty on this crank) |
| `claim(taker, now, mint)` | `Funded`, vesting attached, no milestone plan, vested − released > 0, quorum satisfied if configured, timelock unlocked (`now >= unlock_at` (AV-27) / `now >= fund_at + secs` (AV-64)) | taker | gross vested-but-unreleased (`payout + fee == amount`) |
| `resolve(arbiter, taker_amount, mint, rationale_hash)` (AV-38) | `Disputed`, arbiter configured, remainder > 0 | arbiter | remaining locked amount the arbiter's split divides (the split itself and the rationale-document commitment are the arbiter's call-time judgment) |
| `submit_panel_judgment(member, taker_amount, mint, rationale_hash)` (AV-65) | `Disputed`, panel configured, remainder > 0 — one action **per panel member** | panel member (`caller_role: "panel_member"`) | remaining locked amount the member's voted split divides (the split and the rationale commitment are the member's call-time judgment; the panel settles itself once M votes agree) |
| `close_vault(authority)` (AV-40) | `Cancelled` / `Released` / `Settled` / `Split` — the terminal states AV-34's `close_vault` accepts (`Split` since AV-81). `Disputed` is never listed (the arbitration is still live; the vault account is the arbiter's audit surface) and `Closed` is never listed (the rent is already reclaimed) — the scan lists only calls the chain would accept | initializer (the only key `close_vault` accepts — AV-34 checks authority before state) | `rent_reclaimed`: the mainnet rent-exempt minimum for the current `VAULT_SPACE` (via `vault_close_rent_reclaimed()`, never a hardcoded figure) |
| `slash(authority, amount)` (AV-82) | `Funded` with slash terms configured, `now >= slash_deadline`, slashable remainder > 0, and (dual-sig escrows) both activation bits set — one action for the initializer, plus one for the configured arbiter as the neutral enforcer; never listed on `Disputed` (arbitration owns the funds), milestone/subscription-scheduled, or already-slashed escrows | initializer / arbiter (per action) | the slashable remainder (`amount - released - penalty_paid`) |
| `expire_appeal(caller)` (AV-103) | `Funded` with a `Filed` appeal and `now > appeal_deadline` (window lapsed, unresolved — the keeper never lists a call the chain would reject as `AppealExpiryNotDue`) | `\"anyone\"` — permissionless; the forfeited bond routes to the initializer, never the cranker (anti-MEV) | the locked appeal bond (`appeal_bond_paid`; `0` when no bond was configured) — forfeited to the initializer |

Only *executable* calls are listed: a vesting claim behind an unsatisfied
quorum is withheld (the call would fail), a claim behind a locked timelock
is withheld (`TimelockNotReached`), and a milestone-plan escrow
never lists `claim` (the plan owns the release schedule). A `Disputed`
escrow lists exactly the `resolve` action — its unilateral exits stay
locked, so nothing else is listed — letting an arbiter-operated keeper bot
learn which disputes await its ruling. A panel-mode `Disputed` escrow
lists one `submit_panel_judgment` action per panel member and never the
single-arbiter `resolve` (which the panel disables — `PanelResolveDisabled`).
Each action
carries the exact instruction arguments — `caller`, `mint` (the bound SPL
mint, or `null` on the native-SOL path), and `refund_to` (the refund
destination for `cancel_expired` — the whitelisted address when
configured, else the initializer; `null` for `claim`, `resolve`, and `slash` — the penalty account is fixed in the slash terms (AV-82), not a refund destination) — so the keeper can
build the `cancel_expired` / `claim` / `resolve` / `slash` instruction directly. The scan is a pure read
over `&Escrow` snapshots: dry-run by construction, zero side effects,
deterministic output in input order. `KeeperReport::to_json()` emits
hand-serialized JSON (the crate stays dependency-free; keys are 64-char
lowercase hex). Every action also carries `decimals` (the escrow's token
decimal metadata, `0` when none is declared) and `display_amount` — the
same `amount` rendered in human units (`500000` at 6 decimals →
`"0.500000"`); the instruction itself always moves the raw `amount`.
Opt-in Jito tip (AV-98): `KeeperReport::with_jito_tip(lamports,
recipient)` annotates the report with the operator's intended tip —
`"jito_tip":{"lamports":N,"recipient":"…"}` (`null` when unstamped) —
so the dry-run preview shows the tip line. The report only carries the
amount + recipient; the tip instruction itself is assembled when the
execution bundle is stamped (the payer is the operator's key, not any
single action's caller), and the tip always comes out of the operator's
own pocket, never out of escrowed funds.
Gasless-intent annotation (AV-123): a `WatchedEscrow` may carry a
`pending_intent` (`SignedReleaseIntent` — the initializer's signed
`ReleaseIntent` awaiting relay). When the intent's signature verifies
against the escrow's initializer key and its nonce is fresh (strictly
greater than the persisted `last_intent_nonce`), the scan annotates the
report with an `intent_releases` entry — `escrow_id`, the intent's
`amount` / `payout_to` / `nonce` / `expiry_slot`, and
`signature_valid: true` — so the keeper's dry-run preview shows the
gasless release awaiting relay. The annotation discloses the intent's
claimed expiry without evaluating it against the clock (the chain
rejects an expired intent at submission time with `IntentExpired`); it
is an annotation, not an executable action — the relay path is the
`release_via_intent` instruction, not the keeper's call list.

```json
{"at":1750000000,"scanned":1,"actions":[
  {"escrow_id":"...","vault_address":"...","action":"claim","caller":"...","caller_role":"taker",
   "mint":null,"refund_to":null,"amount":500000,"decimals":6,
   "display_amount":"0.500000","reason":"vesting_unlocked"}
]}
```

`vault_address` (AV-92) is the vault PDA precomputed from the watch
entry's recorded seeds (`WatchedEscrow::with_vault_seeds`) — hex when
seeds are known, `null` otherwise; informational, never an instruction
input.

## Protocol-fee collection scan (AV-174)

Protocol fees accrue into each escrow's `fees_paid` counter as releases
happen; the protocol side extracts them with
`withdraw_protocol_fees(authority, amount)` (see the state-machine
table — authority is the pinned `fee_recipient` or the initializer,
terminal states and paused vaults are rejected, over-withdrawal is
`AmountMismatch`, and `fees_withdrawn` tracks the cumulative extracted
amount so `fees_withdrawn <= fees_paid` always holds). The keeper gets a
dry-run `scan_fee_collection(watched)` report listing every watched
vault with `withdrawable_fees() > 0`, each entry carrying the exact
executable call — `escrow_id`, `state`, `caller` (the pinned fee
recipient, else the initializer), `recipient` (the pinned fee recipient,
or `null` when the escrow uses the program-level fee account), and
`amount` (`fees_paid - fees_withdrawn`) — sorted by `escrow_id`
ascending, plus `total_withdrawable`. Terminal, paused, and
reentrancy-locked vaults are skipped (the chain would reject those
calls — the `scan_unclaimed_rent` executable-only rule).
`FeeCollectionReport::to_json()` emits hand-serialized JSON (fixed field
order, 64-char lowercase hex keys, dependency-free like every other
keeper report). The scan is pure: it reads `&Escrow` snapshots only and
never withdraws.

## Pyth / Switchboard oracle adapters (AV-193)

`escrow-state/src/oracle_adapter.rs` — concrete `PriceFeed`
implementations for the AV-113 price gate (AV-113 defined the
framework; these are the real oracle integrations). Both adapters are
fail-closed and normalize quotes to 8 decimals (`ORACLE_QUOTE_DECIMALS`),
so Pyth and Switchboard quotes are directly comparable by the gate.

- **Pyth v2 price account parsing**: validates the account header
  (`magic` 0xa1b2c3d4, `ver` 2, `atype` 2, `ptype` 1 — offsets pinned
  against the pyth-client `Price` `#[repr(C)]` layout), then decodes
  the aggregate `PriceInfo` (price, confidence, status, publish slot)
  and the publish timestamp. The exponent is normalized into 8
  decimals (`expo` in `[-18, 0]`; anything else cannot scale safely).
- **Fail-closed validation**: a short account or header mismatch is
  `InvalidOracleAccount`; a missing/future/older-than-`max_age_secs`
  publish timestamp is `OraclePriceStale`; a non-trading aggregate
  status, a non-positive price, a confidence interval wider than
  `max_conf_bps` of the price, or a normalization overflow is
  `OraclePriceUnreliable`. A stale or unreliable quote never gates a
  payout — it fails before the AV-113 comparison runs.
- **Switchboard v2 round validation**: the packed
  `AggregatorAccountData` is decoded by the Anchor program with the
  upstream `switchboard-v2` crate (zero-copy) — this module
  deliberately does not re-implement its byte layout. The adapter
  validates the decoded round: positive `SwitchboardDecimal` result,
  oracle-result quorum (`num_success >= min_oracle_results`), round
  timestamp freshness, and checked fixed-point normalization of
  `mantissa * 10^-scale` into 8 decimals.

New error codes (never renumbered): `InvalidOracleAccount` (279),
`OraclePriceStale` (280), `OraclePriceUnreliable` (281). Pure logic:
no Vault layout change, no `VAULT_SPACE` bump. Orthogonal to AV-113
(the `PriceFeed` framework) and AV-128 (TWAP gate — a different
manipulation-resistance strategy over the same quotes). (Solana/DeFi:
oracle integrations.)

## Sealed-bid auction (AV-192)

`escrow-state/src/sealed_bid.rs` — commit-reveal dark auction: bidders
lock hidden bids, then disclose them. During the commit phase each
bidder submits `SHA-256(bid || nonce || bidder)`; during the reveal
phase they disclose `(bid, nonce)` and the commitment is verified. The
highest *validly revealed* bid wins first-price — nobody learns a
rival's bid until the reveal phase, so there is no bid shading or
last-second sniping on price.

- **Binding commitments**: the bidder key is part of the preimage, so
  a commitment cannot be copied and revealed by a different bidder. A
  reveal whose preimage does not verify is rejected; an unrevealed
  commitment simply drops out of contention (it never blocks
  settlement). Reveals are idempotent for the same `(bid, nonce)`.
- **First-price settlement, deterministic ties**: the highest validly
  revealed bid wins; ties break to the earliest reveal slot — no
  randomness needed on-chain. Settlement is permissionless once the
  reveal window closes and terminal.
- **Minimum bid**: the seller's public floor (`0` disables it). Valid
  reveals below it are recorded but cannot win; if the best valid bid
  is under the floor the outcome is `ReserveNotMet`. With no reveals at
  all the outcome is `NoBids`. One commitment per bidder (a second
  commitment is refused — replacing it would let a bidder narrow the
  field after seeing the commitment count), max 64 commitments.
- **Minimum-bid revision** (AV-302): `amend_sealed_bid_min_bid()` lets
  the seller move the public floor before the reveal window opens
  (`current_slot < reveal_start_slot`) — including to `0`, which cancels
  the floor. Commitments are hashes, so no bidder's position is
  invalidated by the change; the new floor governs from the next
  `settle` (reveals below it cannot win, and under Vickrey the price
  is clamped up to the live floor). Seller-only (`Unauthorized` for
  anyone else); refused with `SealedBidNotLive` once the reveal has
  started or the auction is terminal; amending to the current floor is
  a no-op. The revision is audited as `sealed_bid_min_bid_amended`
  (hand-written JSON, same convention as the commit/reveal/settle
  audit events — string event names, no numeric event ID).
- **Reveal-start revision** (AV-303): `amend_sealed_bid_reveal_start_slot()`
  lets the seller move the reveal window's opening slot before the
  reveal starts (`current_slot < reveal_start_slot`) — earlier
  shortens the commit window, later extends it. The new start reuses
  the `new()` window gate (`commit_start_slot < new_reveal_start_slot
  < end_slot`) and must be after `current_slot`, so a commit window
  remains after the revision; otherwise `InvalidSealedBid`. Commitments
  are hashes, so no bidder's position is invalidated; the new start
  governs from the next `phase()` evaluation (`reveal_bid` still
  requires `phase() == Reveal`). Seller-only (`Unauthorized` for
  anyone else); refused with `SealedBidNotLive` once the reveal has
  started or the auction is terminal; amending to the current start is
  a no-op. Only `reveal_start_slot` changes. Audited as
  `sealed_bid_reveal_start_slot_amended` (hand-written JSON, string
  event name, no numeric event ID).
- **Commit-start revision** (AV-304): `amend_sealed_bid_commit_start_slot()`
  lets the seller move the commit window's opening slot before the
  commit starts (`current_slot < commit_start_slot`) — earlier widens
  the commit window, later narrows it. The new start reuses the
  `new()` window gate (`new_commit_start_slot < reveal_start_slot`)
  and must be after `current_slot`, so a commit window remains after
  the revision; otherwise `InvalidSealedBid`. The gate guarantees no
  commitment exists yet (`commit_bid` requires `phase() == Commit`),
  so no bidder's announced game is rewritten. The new start governs
  from the next `phase()` evaluation. Seller-only (`Unauthorized` for
  anyone else); refused with `SealedBidNotLive` once the commit window
  has opened or the auction is terminal; amending to the current start
  is a no-op. Only `commit_start_slot` changes. Audited as
  `sealed_bid_commit_start_slot_amended` (hand-written JSON, string
  event name, no numeric event ID).
- **End-slot revision** (AV-305): `amend_sealed_bid_end_slot()` lets
  the seller move the reveal window's closing slot before the reveal
  starts (`current_slot < reveal_start_slot`) — earlier shortens the
  reveal window, later extends it. The new end reuses the `new()`
  window gate (`reveal_start_slot < new_end_slot`); otherwise
  `InvalidSealedBid`. The liveness gate already guarantees the new end
  is after `current_slot`, so a reveal window always remains.
  Commitments are hashes and revealed bids are plaintext amounts, so
  no bidder's position is invalidated; the new end governs from the
  next `phase()` / `settle` evaluation (`settle` still requires
  `current_slot >= end_slot`). Seller-only (`Unauthorized` for anyone
  else); refused with `SealedBidNotLive` once the reveal has started
  or the auction is terminal; amending to the current end is a no-op.
  Only `end_slot` changes. Audited as `sealed_bid_end_slot_amended`
  (hand-written JSON, string event name, no numeric event ID).
- **Cancel**: seller-only, before the first commitment and while the
  commit phase is still open; a lapsed or committed auction is settled,
  not cancelled.
- **Vickrey (second-price) mode** (AV-200): `with_vickrey()` opts the
  auction into second-price settlement — the highest validly revealed
  bid still wins (ties to the earliest reveal), but the winner pays the
  *second-highest* revealed bid, so revealing your true value is the
  dominant strategy. With a single revealer the winner pays their own
  bid; the price is clamped up to the minimum bid so the seller never
  receives less than the public floor. The pricing rule is locked
  before the first commitment lands (`SealedBidPricingLocked`, code
  313) — rewriting the rules after bidders entered would be a
  bait-and-switch. `Sold.winning_bid` is the price *paid*, and the
  settlement audit JSON records `"pricing":"first_price|vickrey"`.

New error codes (never renumbered): `InvalidSealedBid` (272),
`SealedBidNotLive` (273), `SealedBidDuplicateCommit` (274),
`SealedBidRevealMismatch` (275), `SealedBidSettleTooEarly` (276),
`SealedBidNotCancellable` (277), `SealedBidBookFull` (278),
`SealedBidPricingLocked` (313). Pure logic:
no Vault layout change, no `VAULT_SPACE` bump. Orthogonal to AV-189
English (ascending, open bids), AV-97 Dutch (descending price), AV-137
(commit-reveal for arbitration votes — the preimage there binds a
judgment, here a bid), and AV-194 (opt-in bid deposits with no-reveal
confiscation — this module tracks commitments, not funds). (Solana:
auction primitives.)

## Multi-unit uniform-price auction (AV-199)

`escrow-state/src/multi_unit.rs` — the seller auctions N homogeneous
shares and every bidder bids a per-unit price for exactly one share.
Commitments reuse the AV-192 format `SHA-256(bid || nonce || bidder)`,
so the commit/reveal machinery (phases, binding commitments,
idempotent reveals) behaves exactly like the sealed-bid auction — the
pricing rule is what changes.

- **Uniform price**: every winner pays the same clearing price — the
  marginal price. Valid revealed bids sort descending (ties to the
  earliest reveal slot); the clearing price is the Nth bid when demand
  covers supply, or the lowest winning bid when undersubscribed.
- **Pro-rata at the margin**: bidders tied *at* the clearing price
  split the remaining shares proportionally (`remaining / tied` as a
  rational — shares are fungible, so fractions are fine). Bidders above
  the clearing price take one full share each; bidders below it get
  nothing. Undersubscribed: every valid bidder takes one full share
  and the unsold shares return to the seller.
- **Minimum bid**: the seller's public per-unit floor (`0` disables
  it). Valid reveals below it are recorded but cannot win; with no
  valid bid the outcome is `NoSale`. One commitment per bidder, max 64
  commitments (a full book is not live for new commitments).

New error codes (never renumbered): `InvalidMultiUnit` (309),
`MultiUnitNotLive` (310), `MultiUnitDuplicateCommit` (311),
`MultiUnitRevealMismatch` (312). Pure logic: no Vault layout change,
no `VAULT_SPACE` bump. Orthogonal to AV-192 (single-item,
first-price — one winner takes all) and to AV-194 (opt-in bid
deposits — this module tracks commitments, not funds). (Solana:
auction mechanism design.)

## Bid deposits (AV-194)

Auctions can carry an opt-in flat bid deposit — English (AV-189),
Dutch (AV-97) or sealed-bid (AV-192). Every bidder locks the deposit
at bid time (`BidDepositAuction::register`, one deposit per bidder,
max 64); at settlement the winner's deposit is applied toward the
purchase price and every honest loser's deposit is refunded in full.
Two confiscation paths: sealed-bid bidders that never reveal lose the
deposit on `settle_sealed` (no-reveal confiscation — the sealed-bid
module tracks commitments, not funds, so the confiscation lands
here), and the seller may `forfeit` a locked deposit before settlement
for misbehavior outside the auction rules (e.g. a winner that ghosts a
malicious no-sale). Settlement is permissionless once the auction
closes; pre-settlement seller forfeits stand; a custody invariant
holds at every step — `locked + applied + refunded + forfeited` always
equals `deposit_count * deposit_amount`, funds are only reclassified,
never created or destroyed.

New error codes (never renumbered): `InvalidBidDeposit` (282),
`BidDepositNotRegistered` (283), `BidDepositAlreadySettled` (284),
`BidDepositBookFull` (285). Pure logic: no Vault layout change, no
`VAULT_SPACE` bump. Orthogonal to AV-103 (the taker's appeal bond on a
slashed escrow — a dispute collateral, not an auction bid bond) and to
the auction modules themselves (they price the asset and pick the
winner; this module moves the deposits once the program reports the
outcome). (Solana: auction wind-down.)

## Milestone verifier attestation (AV-210)

`release_milestone` used to trust only internal confirmation: both
parties confirmed the milestone, so the initializer could release it.
A milestone that represents third-party acceptance — a build
delivered, an audit passed, a shipment inspected — needs an outside
voice neither party can forge. `with_milestone_verifier`
(`escrow-state/src/milestone_verifier.rs`) binds one verifier pubkey,
`Uninitialized`-only, and once bound the plain `release_milestone`
path refuses with `MilestoneVerifierRequired`: the gated path cannot
be bypassed by simply not mentioning the verifier (the dual-control
precedent). Releases then go through `release_milestone_verified`
with one Ed25519 attestation over a domain-separated message binding
the vault account key, the milestone index, the tranche hash
(SHA-256 of vault, index and live plan amount, so the signature
covers the deal terms, not just an ordinal) and the attestation's
own expiry; a release at `now > expires_at` is
`MilestoneAttestationExpired`, a binding or signature mismatch is
`MilestoneAttestationInvalid`, and a replay for an already-released
milestone is the explicit `MilestoneAttestationReplay` — replay
protection is structural (releases are strictly in-order and each
tranche settles at most once), so no nonce is needed. The verified
path delegates to the same settlement code, so fee, cap, timelock,
quorum and late-penalty gates all still run, and a failed
attestation settles nothing and charges no fee.

New error codes (never renumbered): `InvalidMilestoneVerifier`
(323), `MilestoneVerifierRequired` (324),
`MilestoneVerifierNotBound` (325), `MilestoneAttestationInvalid`
(326), `MilestoneAttestationExpired` (327),
`MilestoneAttestationReplay` (328). Vault layout: one 32-byte
`milestone_verifier` field appended at the tail (`BODY` 7747→7779,
`SPACE` 7755→7787, no-quorum 7265→7297, IDL regenerated).
Orthogonal to AV-101 (keeper report signatures never gate a
release) and AV-203 (the taker's own delivery confirmation, not a
third party). Boundary: the Anchor instruction that accepts the
attestation on chain (passing the vault account key and attestation
bytes through to `release_milestone_verified`) is follow-up work —
the pure-logic gate here is complete and tested, and no such
instruction is claimed. (Solana: third-party milestone acceptance.)

**Milestone verifier rotation (AV-234).** A verifier key fixed at
funding cannot follow a key that is compromised, lost, or handed to
a new auditor — and cancelling and re-locking to swap it would
strand milestone progress. `rotate_milestone_verifier(initializer,
taker, new_verifier)` (`Funded`-only, dual-signed) is the
post-funding revision path; `with_milestone_verifier` stays
`Uninitialized`-only as the initial set. The zero address and a
rotation to the current verifier are both rejected with
`InvalidMilestoneVerifier` (323), and an unbound escrow has nothing
to rotate (rotation never creates the gate) — every failure leaves
the stored verifier untouched. Rotation semantics fall out of the
gate itself: attestation verification reads the stored key and
attestations carry no stored state, so unused attestations signed by
the old verifier stop verifying the moment the key changes, while
attestations signed by the new verifier verify; already-settled
tranches are untouched. Orthogonal to `rotate_arbiter` /
`rotate_taker` (different roles: dispute settler, payout
counterparty, delivery attester). The `MilestoneVerifierRotated`
event (discriminant 98) carries no amounts; the new verifier is read
from the vault. (Solana: milestone fulfillment governance.)

## Winner payment window (AV-209)

`SealedBidAuction::settle` only ranks — it names a winner and never
asks whether that winner actually pays. `WinnerPaymentWindow`
(`escrow-state/src/winner_payment.rs`) is the settlement
follow-through: the current winner has `window_slots` slots to pay
(`mark_paid` locks the sale); missing the window (`expire`) forfeits
that winner and promotes the next validly revealed bidder in settle
order (bid descending, ties to the earliest reveal slot — the same
comparator settle uses, via `rank_revealed_bidders`), with a fresh
window. Promotion walks the whole ranking; when every ranked bidder
has defaulted the window is `Exhausted` — a no-sale the seller can act
on, not a silent hang. A payment at or after the deadline is refused
(the caller must `expire` first, so the successor, not a late payer,
owns the sale), and a non-winner caller is refused before any window
check. Funds never move here: `forfeit_deposits` maps each recorded
defaulter onto AV-194's seller-authorized `BidDepositAuction::forfeit`
after validating the whole book up front, so a bad book fails closed
with zero partial confiscation; re-running after a successful
forfeiture fails closed instead of double-counting.

New error codes (never renumbered): `WinnerPaymentNotDue` (319),
`WinnerPaymentNotCurrentWinner` (320), `WinnerPaymentWindowExpired`
(321), `WinnerPaymentInvalidWindow` (322). Pure logic: no Vault
layout change, no `VAULT_SPACE` bump. Orthogonal to AV-194 itself
(which confiscates for unrevealed or no-sale bidders at settle time — a
defaulting winner has revealed and won, so AV-194's settle path would
refund, not forfeit, them) and to AV-189 English (open ascending bids:
the winner is public and the next bid is known without a ranking
walk). (Solana: auction settlement assurance.)

## Settlement-mint conversion (AV-217)

An escrow locks one mint (AV-16) but may settle in another.
`with_settlement_mint` (`escrow-state/src/lib.rs`,
`Uninitialized`-only, non-zero key) binds the payout
denomination, and `release_with_settlement_rate` settles the
exact plain-`release` guard chain with the returned legs
redenominated at a dual-signed rate. The rate quote
(`escrow-state/src/settlement_mint.rs`) carries the settlement
mint, a rational rate (`numerator` / `denominator`, settle
units per funded unit), an expiry, and one Ed25519 signature
from each party over the canonical message; the gate verifies
expiry first, the mint binding second, a zero denominator
third, and both signatures last (the AV-210 check order). The
rate may be sourced from an AV-193 oracle feed quote off
chain — the gate verifies the parties' signatures over that
quote, so an oracle quote the parties never signed settles
nothing.

- Conversion is `floor(funded * numerator / denominator)` in
  `u128`, floored per leg: the taker payout, the protocol fee
  leg (the AV-191 referral share rides inside it), and the
  late-delivery penalty leg (AV-216, zero when no late
  confirmation was recorded) each convert independently. The
  dust (under one settle unit per leg) stays with the vault;
  the funded counters (`released`, `penalty_paid`) still move
  in funded units, so funded-unit conservation remains the
  audited identity and the settle-unit legs are transfer
  sizings, not a second ledger.
- Fail-closed, before any settlement runs: no settlement mint
  bound (`SettlementMintNotBound`, 346), an expired quote
  (`SettlementRateExpired`, 348 — exactly at `expires_at` is
  still valid, the AV-206 convention), a quote for the wrong
  mint, a zero denominator, or either signature failing
  (`SettlementRateInvalid`, 347). A refused settled release
  moves nothing and charges no fee. The quote is reusable
  within its validity window (a rate quote, not a one-time
  voucher) and is re-verified on every call.
- Plain `release` is untouched: binding a settlement mint
  changes nothing for the funded-unit path, and the settled
  path runs the same guard chain — a dual-control escrow
  still refuses the direct path, a credential-gated escrow
  still requires its credential path, and a delivery-gated
  escrow still requires its confirmation. The AV-16 mint
  allowlist deliberately does not apply to the settlement mint
  (it governs the funded mint); the dual-signed attestation is
  the counterfeit protection for this mint.

Vault tail +32 bytes (BODY 7831 → 7863, SPACE 7839 → 7871,
no-quorum 7349 → 7381); IDL regenerated. Orthogonal to
AV-113 / AV-193 (the price gate decides whether a payout may
happen at all — this item decides what currency and amount it
settles in), to AV-16 (the funded mint is not rebound, the
payout is redenominated), and to AV-206 / AV-216 (lateness
prices in funded units first; the settled path converts the
priced legs, never reprices them). Boundary: a settled
`release_milestone` variant and an on-chain oracle-verified
rate path are follow-up work — no such paths are claimed, and
no Anchor instruction for the settled path is claimed.
(Solana: cross-mint settlement.)

## Settlement-mint allowlist (AV-218)

AV-217 settles in any attested mint; this item adds the
initializer's own gate on top. `with_settlement_mint_allowlist`
(`escrow-state/src/lib.rs`, `Uninitialized`-only) installs an
opt-in list of at most 8 settlement mints
(`escrow-state/src/settlement_allowlist.rs`); an empty slice
means "allowlist off" (`None`, the AV-157 convention), and a
non-empty list rejects a zero address, a duplicate, or more
than 8 entries (`InvalidSettlementMintAllowlist`, 349).
`release_with_settlement_rate` then checks the attestation's
settlement mint against the list *before* rate verification or
conversion pricing: a quote for a non-allowlisted mint is
refused with `SettlementMintNotAllowlisted` (350) even when
perfectly signed — and even when unsigned, since the policy
check precedes signature verification. No allowlist configured
means AV-217 semantics unchanged, and plain `release` never
consults the list (no conversion, no settlement mint to gate).

- The gate checks the attestation's mint, not the bound mint,
  and that is sufficient rather than sloppy: verification
  already requires the attestation's mint to equal the bound
  mint, so a quote passing both checks is necessarily for an
  allowlisted *and* bound mint. The builder deliberately does
  not check the bound mint against the list — the release-time
  gate is the single enforcement point, so a list excluding
  the bound mint simply means no settled release can pass, a
  policy the initializer chose and can read back, not a
  config error.
- Orthogonal to AV-217 (the conversion itself — this gates
  which mints it may settle in, never repricing a leg), to
  AV-16 (the funded-mint binding — this constrains the payout
  denomination, and the AV-16 allowlist still does not apply
  here), and to AV-49 (the payout-address allowlist — that
  gates *where* the payout goes, this gates *what asset* it is
  paid in; a settled release must pass both when both are
  configured).

Vault tail +258 bytes (BODY 7863 → 8121, SPACE 7871 → 8129,
no-quorum 7381 → 7639); IDL regenerated. (Solana:
cross-mint settlement risk control.)

## Mutual cancel by dual-party agreement (AV-219)

The unilateral exits leave one gap: a taker who wants out
before expiry has no honest path — the initializer's `cancel`
is not theirs to call, and `cancel_expired` is not yet
eligible. `mutual_cancel` (`escrow-state/src/lib.rs`,
backed by `escrow-state/src/mutual_cancel.rs`) closes it:
a `Funded -> Cancelled` transition that requires both
parties' signatures, carried as a `MutualCancelAgreement`
whose sides are `Option` keys so absence is expressible. A
missing party or a stranger key on either side is
`Unauthorized`, checked before the state gate, so a stranger
never learns whether an escrow is `Funded` from the error
alone; a non-`Funded` state (including `Disputed`, which
settles through `resolve`, not through an agreed exit) is
`InvalidStateTransition`. One party alone is refused, not
upgraded — the initializer signing alone is the unilateral
cancel wearing a mutual-cancel name — and an AV-104
CANCEL-scoped operator does not satisfy either side:
termination by agreement is a personal act of both parties,
while the delegated initializer who wants out unilaterally
still has `cancel`.

Settlement is the AV-148 bilateral unwind, same as `cancel`:
the remainder returns leg by leg, the initializer's leg to
the AV-23 refund policy destination (the whitelisted address
when configured, otherwise the initializer — the call takes
no `refund_to`, so no caller can redirect the refund by
naming a destination), the taker's leg back to the taker,
with no AV-24 penalty, since a cancel both parties signed
is not griefing. On a plain single-funded escrow the taker's
leg is zero, so the entire remainder returns to the
initializer through the AV-23 destination.

- Orthogonal to `cancel` (one signature, one party's
  decision), to `cancel_expired` / `crank_expired`
  (time-triggered — this item needs no expiry and refuses
  nothing for being early), to AV-130 (maker-checker on the
  release intent — this item terminates, it never pays the
  taker), and to AV-52 (taker rotation — the rotated taker
  is simply the taker whose agreement counts).

No vault layout change (the agreement is a call-time fact,
not stored state), no new error code, no IDL change, and
no Anchor instruction is claimed for this path. (Solana:
mutual termination.)

## Partial funding in installments (AV-220)

The single-shot `fund` leaves one gap: an initializer who
cannot post the whole deal size at once has no honest path —
the AV-111 funding plan moves the escrow to `Funded` on the
first tranche, so the taker can be paid from a half-funded
vault before the rest arrives. `with_partial_funding`
(`escrow-state/src/lib.rs`, backed by
`escrow-state/src/partial_funding.rs`) closes it: the
opt-in is `Uninitialized`-only, and installments posted
through `fund_partial` accumulate in `funded_total` while
the state stays `Uninitialized` until the installments sum
to `amount` — only the last installment flips the escrow
to `Funded` and anchors the funding clocks. The locked
amount itself never moves, so milestones, vesting, and fees
keep pricing off `amount`.

- Accumulation runs in `u128`, so the sum can never wrap:
  a zero deposit and any deposit that would push the total
  past `amount` are clean `AmountMismatch` refusals, never
  wraparounds. `fund` refuses a partial-funding escrow
  with the new `InvalidPartialFunding` (code 351,
  appended, never renumbered), and the AV-111 plan and
  partial funding are mutually exclusive in either order —
  the two deposit paths cannot both own one escrow.
- While short of the total, `release` refuses (every payout
  path's state gate already says no to a pre-`Funded`
  escrow), and `cancel_expired` — once the AV-21 expiry
  gate passes — refunds exactly the deposited total, never
  the declared amount: funds that never arrived are never
  refunded. A partial escrow with nothing deposited has
  nothing to unwind and stays `InvalidStateTransition`.
- Orthogonal to AV-11 (staged release — this item stages
  the deposit, not the payout), to AV-95 (the multi-asset
  basket — this item funds one asset in several calls), and
  to AV-111 (the plan funds `Funded`-first; this item
  funds `Funded`-last).

Vault tail +1 byte (BODY 8121 → 8122, SPACE 8129 → 8130,
no-quorum 7639 → 7640); IDL regenerated, including the new
error code. (Solana: staged funding.)

## Keeper expired-vault scan (AV-221)

The AV-20 keeper scan already lists executable
`cancel_expired` calls, but an operator who wants to know
*which vaults are past their time and how much is at stake*
has to read that action list sideways. `scan_expired_vaults`
(`escrow-state/src/keeper.rs`, exported from
`escrow-state/src/lib.rs`) is the report counterpart: it
scans a watch list and returns an `ExpiredVaultReport` —
every `Funded` vault whose AV-21 expiry gate has passed
(`now >= expires_at + grace_period`, grace honored, so the
chain would never reject the listing as `NotExpired`),
with the overdue duration and the initializer/taker leg
split of the refundable remainder.

- Report only: the scan takes snapshots, mutates nothing,
  and signs nothing — execution still goes through
  `cancel_expired` / `crank_expired`, which keep enforcing
  the pause, reentrancy, authority, mint, and refund
  gates. A vault with nothing refundable is not a
  candidate; a taker-initiated cancel's AV-24 penalty is
  not pre-charged into the preview legs.
- Orthogonal to AV-40 (which scans terminal states for
  `close_vault`) and to AV-80 (which scans `Closed`
  vaults holding only the rent-exempt minimum): this item
  covers the live `Funded` vaults whose time has run out.

No vault layout change, no new error code, no IDL change,
and no Anchor instruction is claimed for this path.
(Solana: keeper automation.)

## Rent payer (AV-222)

`close_vault` always paid the rent-exempt deposit back to
the initializer — the only destination the state machine
knew. A vault whose rent was actually funded by someone
else (a sponsor, a marketplace operator, a relayer that
paid the account-creation rent on the initializer's
behalf) had no way to say so: the sponsor's deposit
silently became the initializer's on close.
`with_rent_payer` (`escrow-state/src/lib.rs`, backed by
`escrow-state/src/rent_payer.rs`) closes it: the opt-in
is `Uninitialized`-only, so the close-time destination is
fixed before any funds move and can never be re-pointed
mid-life, and a zero payer is refused with the new
`InvalidRentPayer` (code 352, appended, never
renumbered) — a bound payer must be a real key, or the
close would have nowhere to send the rent.

- The close authority does not change: only the
  initializer may call `close_vault` (AV-34), so naming a
  payer never lets a stranger close the vault — it only
  changes who the close pays. With no payer bound, the
  destination stays the initializer, so every existing
  vault closes exactly as before. The batch-close report
  carries the destination per vault (`rent_recipient` on
  each closed item), so a single-vault close and a batch
  close can never disagree about who gets the rent.
- Orthogonal to AV-34 (the close itself — this item
  changes the close's recipient, never who may close or
  which states are closeable), to AV-110 (anyone may top
  up rent, but the top-up caller does not become the rent
  payer — the payer is bound once, at setup, by the
  initializer), and to AV-139 (the unclaimed-rent sweep
  still pays its caller-specified treasury: the sweep is
  the fallback for a close that never happened, and it
  keeps its own destination).

Vault tail +33 bytes (BODY 8122 → 8155, SPACE 8130 →
8163, no-quorum 7640 → 7673); IDL regenerated, including
the new field and error code. (Solana: rent economics.)

## Funding chain (AV-223)

`link_swap` (AV-105) settles two vaults atomically, in
both directions, at one moment — but a staged release
has no shape: a milestone payout from vault A that is
supposed to seed vault B (a supplier paid in tranches,
each tranche funding the next leg) could only be moved
by hand between the two releases, with nothing linking
them. `link_chain` (`escrow-state/src/chain.rs`) closes
it: the opt-in is `Uninitialized`-only, so the downstream
vault is fixed before any funds move, and the link is
one-way — A funds B, B carries no back-link. When A
releases, an agreed amount is diverted to B first: B's
`funded_amount` accumulates across installments, under-full
stays pending-funding, and the installment that fills B
flips it to Funded at that moment; whatever A releases
beyond B's remaining need follows A's normal release
path to the taker.

- The diversion reuses the `fund` check order (pause,
  reentrancy, amount) and B's partial-funding gate: a
  downstream that does not accept installments refuses
  the whole release atomically — A releases nothing,
  rather than settling everything to the taker and
  silently dropping the chain. A downstream that is
  already Funded or terminal takes nothing, and the
  excess follows A's normal path. A plain single-side
  `release` on a live chain-linked A is refused with the
  new `ChainLinkActive` (code 353, appended, never
  renumbered), so the chain can never be bypassed by
  releasing A outside it.
- A terminal upstream breaks the chain instead of
  funding it: cancel, expiry, deadman claim, and
  dispute-final settlement all clear the link and audit
  `chain_broken`, so a cancelled A never funds B.
  Orthogonal to AV-105 (bilateral atomic swap vs.
  one-way sequential funding) and to AV-220 (B's
  installment accounting — the chain only deposits
  into it, it does not change how B counts).

Vault tail +33 bytes (BODY 8155 → 8188, SPACE 8163 →
8196, no-quorum 7673 → 7706); IDL regenerated,
including the new field and error codes 353
`ChainLinkActive`, 354 `InvalidChainLink`.
(Solana: payment settlement.)

## Delivery-confirmation deadline (AV-216)

AV-203 lets the taker confirm receipt but gives the
confirmation no calendar: a confirmation a year late settles
exactly like one made on time. This item prices lateness.
`with_delivery_deadline` (`escrow-state/src/lib.rs`,
`Uninitialized`-only) attaches one unix timestamp, and
`with_late_delivery_penalty_bps` attaches a 0–10_000 bps rate;
the timed `confirm_delivery_at` records `delivery_late` when
the first confirmation lands strictly after the deadline
(confirming exactly at the deadline is on time, the AV-206
rule). A late-confirmed `release` / `release_milestone` then
settles `released += gross - penalty`,
`penalty_paid += penalty`, `taker_payout = net - fee +
interest`, so `released + penalty_paid + remaining == amount`
with the conservation formula untouched.

- Lateness is recorded at confirmation time, never recomputed
  at release time: a taker who confirmed on time but settles
  late (the initializer's own delay) prices zero, by
  construction. The timeless `confirm_delivery` records no
  lateness — without a timestamp there is nothing to compare
  against the deadline — and a second confirmation never
  rewrites the first (first confirmation wins, in both
  directions). The indexed wrapper routes through the timed
  path with its event timestamp as the confirmation time.
- Fees slice the net, caps bind the gross: the protocol fee,
  the AV-191 referral share, and the AV-100 streaming fee all
  cut value the taker actually receives, while the AV-205
  per-call cap, the AV-208 operator spend cap, and the lockup
  cap still check the gross — checking the net against the
  pre-penalty cap would let a release settle gross value past
  the lockup. On `release_milestone` the AV-216 penalty stacks
  on the post-AV-206 net tranche (AV-206 first, then this one).
- A rate without a deadline prices nothing, and a deadline
  without a rate prices nothing — the two builders compose,
  neither implies the other. The unilateral exits (`cancel`,
  `cancel_expired`) and the arbiter's `resolve` are not gated
  and not priced: a late confirmation prices payouts, never
  traps funds (the AV-203 non-gating rule, extended to the
  price). A zero deadline is `AmountMismatch` (0 in storage
  always means "never attached", the AV-206 sentinel); a rate
  above 10_000 bps is `InvalidPenalty` (the AV-206 validator).
  No new error code.

Vault tail +11 bytes (BODY 7820 → 7831, SPACE 7828 → 7839,
no-quorum 7338 → 7349); IDL regenerated. Orthogonal to AV-206
(per-tranche milestone due dates — this is the whole-deal
delivery confirmation, and the two penalties stack), to AV-211
(the post-confirmation inspection window — this deadline
bounds the confirmation itself), and to AV-190 (rental
use-right overdue rent — a different deal shape, a different
clock). Boundary: the Anchor instruction accepting a deadline
on chain is follow-up work — no such instruction is claimed.
(Solana: delivery performance.)

## Time-bounded delegation (AV-215)

An AV-104 operator grant may carry an opt-in expiry, set at
grant time. `delegate_authority_with_expiry`
(`escrow-state/src/lib.rs`) bounds the grant to a window: while
`now < expires_at` the operator acts exactly like an AV-104
operator; once `now >= expires_at` every operator operation —
fund, release and cancel alike — is refused with
`DelegationExpired`, checked inside the authority gate before
scope and before state, so a lapsed operator learns nothing
beyond the refusal. The parties are never gated: expiry binds
the operator alone.

- Expiry deactivates, it never clears: the grant and its
  `spent` counter survive the lapse, so `renew_delegation`
  reactivates the same grant with its history intact (a lapsed
  window is a pause, not a death), and revocation still works on
  a lapsed grant. A capped-out history stays history whether or
  not the window is still open.
- No stale windows: a plain or capped re-grant, a revocation, or
  a party rotation clears the expiry with the grant, so a fresh
  grant is never silently time-bounded by its predecessor. The
  expiry lives in its own appended tail field (9 bytes), not in
  the AV-104 delegation region, so no earlier field offset
  moves.
- A `0` expiry is `InvalidDelegation`, not "no expiry": `0` in
  storage always means "never expires", so a bounded grant is
  never ambiguous with an AV-104 grant (the AV-208 zero-cap
  convention).

New error code (never renumbered): `DelegationExpired` (345);
vault tail +9 bytes (BODY 7820, SPACE 7828, no-quorum 7338);
IDL regenerated. Orthogonal to AV-104 (scope plus spend cap —
this item is the time window) and to AV-208 (the cap binds
volume, the window binds time; the two compose through the same
grant slot). Boundary: the Anchor instruction accepting an
expiry on chain is follow-up work — no such instruction is
claimed. (Solana: delegation governance.)

## Option escrow (AV-214)

A fixed-strike, expiry-bound call option over a locked
underlying amount. `OptionEscrow`
(`escrow-state/src/option_escrow.rs`) is a pure-logic sidecar:
the seller locks an underlying, the buyer pays a premium up
front for the right — not the obligation — to buy that
underlying at a fixed strike before an expiry timestamp.
Exercise (buyer only, strictly before expiry, paying exactly
the strike) sends the underlying to the buyer and the strike
plus the premium to the seller; expiry (at or after expiry,
unexercised) leaves the premium with the seller and returns
the underlying to the seller — an unexercised option expiring
worthless is a normal terminal outcome, not an error. The
boundary is exact: at the expiry instant itself exercise is
already closed and expiry already open, so no timestamp is
both exercisable and expirable. Check order mirrors the HTLC
claim (buyer, then state, then timelock, then payment), so a
stranger learns nothing about the option's state from the
error they get.

- The premium is non-refundable in every outcome: it bought
  the right, and the right was held. A wrong strike payment is
  `OptionStrikeMismatch`, not `AmountMismatch` (that code means
  "initialize with amount == 0"); a settled option reports
  `OptionAlreadySettled` before any timestamp or payment
  question is asked.
- The module moves no funds itself: like the HTLC claim it
  verifies the terms and returns the settlement legs for
  transfer sizing, and the premium's custody before
  construction is the caller's job.
- **Revising the strike (AV-294)**: `amend_option_strike`
  revises the strike on an `Active` option, authorized by
  seller + buyer together — the strike is a bilateral price
  term, so a unilateral rewrite would let one side reprice
  the other's bargain alone. The new strike reuses the
  construction gate (a zero strike fails closed with
  `InvalidOptionTerms`, code 339, and the current strike is
  untouched); an exercised option is `OptionAlreadySettled`
  (code 343) and an expired option is `OptionExpired` (code
  341). Re-affirming the current strike is a no-op. Only
  `strike` changes, and `exercise` reads the live strike, so
  the new strike governs the next exercise — an exercise
  already settled keeps the strike it settled under. No
  event is emitted — `OptionEscrow` has no event layer.
  (Solana: option governance.)
- **Revising the expiry (AV-299)**: `amend_option_expiry`
  revises the expiry on an `Active` option, authorized by
  seller + buyer together — the expiry is a bilateral time
  term, so a unilateral rewrite would let one side re-time
  the other's exercise window alone. The new expiry reuses
  the construction gate (it must be positive — 0 is "no
  expiry", a perpetual, a different instrument — and strictly
  later than `now`, `InvalidOptionTerms`, code 339, either
  way, and the current expiry is untouched); an exercised
  option is `OptionAlreadySettled` (code 343) and an expired
  option is `OptionExpired` (code 341). Re-affirming the
  current expiry is a no-op, provided it is still in the
  future. Only `expiry` changes, and `exercise` / `expire`
  read the live expiry, so the new expiry governs the next
  exercise or expiry — a settlement already made keeps the
  expiry it settled under. Unlike a strike revision, a
  dual-signed expiry revision to a future point reopens a
  lapsed-but-not-yet-expired window — that is the point of
  the dual signature; shortening to a point still above
  `now` moves the window too, never below it. No event is
  emitted — `OptionEscrow` has no event layer.
  (Solana: option governance.)

New error codes (never renumbered): `InvalidOptionTerms`
(339), `OptionNotBuyer` (340), `OptionExpired` (341),
`OptionNotExpired` (342), `OptionAlreadySettled` (343),
`OptionStrikeMismatch` (344); no layout change, no
`VAULT_SPACE` bump, no IDL regeneration. Orthogonal to
AV-113 (a price gate that permits a release when a market
condition holds — no holder choice, no strike), AV-97 (a
Dutch auction that discovers a price — the strike here is
fixed at construction, never bid) and AV-186 (an HTLC: a
hashlock plus a timelock where the claim secret, not a
payment, unlocks the funds). Boundary: the Anchor
instruction that locks the underlying, collects the premium
and settles these legs on chain is follow-up work — no such
instruction is claimed. (Solana: option primitive.)

## Denylist-gated release (AV-213)

A release-time denylist for compliance lists that arrive after the
escrow was initialized. `DenylistGate`
(`escrow-state/src/denylist_gate.rs`) is a pure-logic sidecar the
release caller consults before any other release gate: denied
recipients plus denied settlement / intermediate mints, recipient
first, then mint, both denying with `PayoutDenied` (the code AV-96
already assigned to a denylist denial — no new error code, no IDL
regeneration, no vault layout change).

- The recipient leg overlaps AV-96 in effect but differs in source:
  AV-96 is the escrow's own persisted, initializer-governed veto;
  this gate is the caller's release-time list (a sanctions list
  refreshed after initialization). `Escrow::check_denylist_gate`
  checks the stored list first, then the supplied gate — never a
  choice between them.
- The mint leg is new: no mint denylist exists anywhere in the
  crate (AV-157's mint allowlist is its mirror image, and AV-96
  names recipients, never mints). `check_mints` denies a basket /
  swap release as a whole when any leg mint is denied, so a denied
  asset cannot be laundered through the clean legs.
- Deny beats allow: a recipient on both the AV-49 allowlist and a
  denylist is still denied, and a mint can be AV-157-allowlisted
  and still denied here — the AV-96 precedence, extended to mints.
  A denied mint is not `MintNotAllowlisted` (that code means "not
  on the allowlist", a different gate with a different remedy);
  callers that need the leg for an operator report read it from
  `denied_target` before calling `check_release`.
- Boundary: the gate is supplied per release, not stored on the
  Vault, so there is no layout or rent change; the Anchor
  instruction passing the program's release-time compliance list
  through this gate before `release` is follow-up work — no such
  instruction is claimed. (Solana: compliance-gated escrow.)

## Credential-gated release (AV-212)

`release` used to trust only internal authority: the initializer
(or their RELEASE-scoped operator) could release, with the payout
destination pinned by the allowlist. A release that must only reach
a compliance-cleared taker — a KYC'd counterparty, a licensed
custodian, a sanctions-screened recipient — needs an outside voice
neither party can forge. `with_credential_gate`
(`escrow-state/src/credential_gate.rs`) binds one issuer pubkey,
`Uninitialized`-only, and once bound the plain `release` path
refuses with `CredentialGateRequired`: the gated path cannot be
bypassed by simply not mentioning the credential (the dual-control
precedent). Releases then go through `release_with_credential`
with one Ed25519 credential over a domain-separated message
binding the taker and the credential's own expiry, plus the
issuer's revocation verdict passed in as a query callback — a
credential never carries its own "not revoked" flag, since that
would be a claim the holder asserts about themselves; a revoked
credential is `CredentialRevoked` whatever its signature says.
A release at `now > expires_at` is `CredentialExpired`, a taker
mismatch or signature failure is `CredentialInvalid`, and the
credentialed path on an unbound escrow is
`CredentialGateNotBound`. The verified path delegates to the
same settlement code, so fee, cap, timelock, quorum and
payout-allowlist gates all still run, and a failed credential
settles nothing and charges no fee. Replay needs no nonce: a full
release is terminal, so a replayed credential can never settle a
second release.

New error codes (never renumbered): `InvalidCredentialIssuer`
(333), `CredentialGateRequired` (334), `CredentialGateNotBound`
(335), `CredentialInvalid` (336), `CredentialExpired` (337),
`CredentialRevoked` (338); vault tail +32 bytes (BODY 7811,
SPACE 7819, no-quorum 7329); IDL regenerated. Orthogonal to
AV-210 (a third party attesting a delivery fact for one
milestone, not a taker's qualification), AV-113/AV-128 (oracle
price, not identity) and AV-104 (operation-right delegation,
which still cannot release to an uncredentialed taker).
Boundary: the Anchor instruction accepting the credential on
chain (passing the revocation-registry verdict through) is
follow-up work — no such instruction is claimed. (Solana:
compliance-gated escrow.)

## Delivery inspection period (AV-211)

`confirm_delivery` (AV-203) opens the payout paths immediately: a
taker who confirms and then discovers the delivery is defective has
no on-escrow way to hold the release. `InspectionPeriod`
(`escrow-state/src/inspection.rs`) is the post-confirmation
inspection window anchored to the delivery confirmation itself
(`confirmed_at` + `inspection_secs`, seconds): inside the window the
taker — and only the taker — may `dispute` to freeze the release
(a stranger is refused before any window check); at or after the
deadline, `settle` releases automatically, so no second `release`
call is needed and no party can stall a quiet deal by never calling
again. Settling early is `InspectionNotDue` (the window runs its full
course); disputing at or after the deadline is
`InspectionWindowExpired` (the caller must `settle` instead); a
disputed window never auto-releases — `settle` on it fails closed
and the freeze stands until an arbiter resolves it (AV-14), with no
un-dispute path. The deadline second belongs to the next phase (the
AV-206 convention): a dispute exactly at `expires_at` is already
late, a settle exactly at `expires_at` already releases.

New error codes (never renumbered): `InspectionInvalidWindow`
(329), `InspectionNotTaker` (330), `InspectionWindowExpired` (331),
`InspectionNotDue` (332). Pure logic: no Vault layout change, no
`VAULT_SPACE` bump (IDL regenerated for the 4 new errors only).
Orthogonal to AV-112 (release-intent cooling: announced intent,
either party may veto, plain `release` only, never an automatic
release — this window is taker-only, anchored to delivery
confirmation, and does auto-release on quiet expiry), to AV-14 (the
dispute window anchored to escrow expiry, escalatable by either
party), and to AV-210 (a third party's attestation, not the taker's
own silence). Boundary: `settle` returns the release *decision*;
the actual payout stays the Anchor program's job, and the Anchor
instruction wiring the window to `confirm_delivery` is follow-up
work — no such instruction is claimed. (Solana: delivery
inspection.)

## Referrer revenue share (AV-191)

Escrows can carry an optional referrer: `with_referrer(referrer, bps)`
pins a 32-byte referrer address and a basis-points rate (cap 2000 =
20%, `InvalidReferral` on zero-address or over-cap) at initialization.
On every release path, `referral_for(gross)` computes the floor share
via u128 math and folds it into the returned fee so
`payout + fee == gross` still holds — the `Released` event, preview,
and CPI plan are untouched. The share accumulates in a dedicated
`referral_paid` counter (never mixed into `fees_paid`), and CPI
rollback snapshots restore it alongside the other counters.

## Vault config drift detection (AV-175)

Operators roll out vault fleets from one approved configuration; a
vault whose on-chain config no longer matches the template is
mis-provisioned or tampered with and must not be funded.
`escrow-state/src/config_drift.rs` decodes a vault account's
operational config — `fee_bps`, `fee_schedule`, `fee_cap`,
`fee_recipient`, `payout_allowlist`, quorum threshold, `mint`,
`timelock`, `relative_timelock_secs` — via `decode_vault_account`
(the `vault_view` decode convention) and diffs it field-by-field
against an `ExpectedVaultConfig` template, producing `{field,
expected, actual}` drift entries in fixed field order
(`diff_config`; empty means clean). Values render canonically
(decimal integers, 64-char lowercase hex pubkeys, `"none"` for absent
optionals) so the report is deterministic without a serializer. The
keeper entry point `scan_config_drift(watched, expected)` lists only
drifted vaults (sorted by `escrow_id`, with `total_drifts`) plus a
`to_json()` report — dry-run, zero side effects. This is operational
config drift, orthogonal to the AV-29 IDL byte-layout pipeline (which
guards offsets/discriminators) and to the AV-143 template library
(which blueprints *new* escrows — this monitors *deployed* ones).

## Initialize-config assembly validator (AV-161)

A keeper or UI assembles the initialize config off-chain (typically
from JSON) before driving the chain's `initialize` + builder sequence.
`escrow_state::validate_initialize_config(&InitConfig)` checks every
cross-field constraint the individual builders cannot see in one pure
pass — no state reads, no state writes, no events — so a misassembled
config fails fast off-chain instead of burning a transaction:

- the three release plans (milestones / vesting / subscription) are
  mutually exclusive at the config layer (one escrow, one release
  story), and the set plan's amounts cover the locked amount exactly
  (`periods * per_period == amount` for subscriptions);
- the quorum threshold is reachable (`1 <= threshold <= total attestor
  weight`, at most 8 attestors);
- the protocol fee is a valid basis-point rate (`fee_bps <= 10_000`);
- the time fields are mutually consistent (ordered vesting window with
  the cliff inside it, vesting completing no later than expiry, the
  timelock not outliving the escrow, the subscription schedule fitting
  the lifetime);
- configured allowlists are non-empty and well-formed (mint: 1–8
  addresses, payout: 1–4, no zero addresses).

Each check mirrors the corresponding chain-side builder's validation
(error variant included), so a config that passes here assembles
cleanly on-chain. Keeper usage: validate the assembled `InitConfig`
right after JSON deserialization, before building the `initialize`
transaction.

## Expiry-warning scan (AV-136)

The keeper report (AV-20) lists *already-expired* escrows. Its
complement, `escrow-state/src/expiry_watch.rs`, fires *before* the
deadline — while the operator can still act. `scan_expiry_warnings`
takes the same `WatchedEscrow` watch list plus a `warn_window_secs`
and returns an `ExpiryWarningReport`: one warning per `Funded` /
`Activated` escrow with `now < expires_at <= now + warn_window_secs`
(`Disputed` escrows belong to the arbitration path, terminal states
need no warning, and expired escrows stay with AV-20's
`cancel_expired` scan — never double-listed).

Each warning carries an executable checklist trimmed by state and
configuration, reusing the AV-59 `extend_expiry` semantics:

| checklist action | listed when | `executable_now` |
|------------------|-------------|------------------|
| `extend_expiry` | `Funded` (on `Activated` it is listed as not-executable: AV-59's state gate accepts only `Uninitialized` / `Funded`) | true iff extension was enabled (`with_max_extension_secs`) and the escrow is not yet expiry-eligible; the detail names the per-call increment bound |
| `cancel_expired` | always (either party) | false inside the window by construction — the detail names the exact eligibility instant `expires_at + grace_period` and the refundable remainder |
| `claim` | vesting schedule attached | false — the schedule unlock is evaluated at call time |

The scan is pure (dry-run: no mutation, no events, no clock) and
deterministic (warnings sorted by `(expires_at, escrow_id)`,
hand-serialized JSON). Edge-triggering lives in the caller-held
`ExpiryWarningLedger::filter_new`: the same escrow warns exactly once
per deadline, and a renewed deadline (via `extend_expiry`) produces a
new `warning_key` (`hex(escrow_id):expires_at`) so the warning re-arms
automatically.

```json
{"at":999000,"warn_window_secs":86400,"scanned":1,"warnings":[
 {"escrow_id":"...","state":"Funded","expires_at":1000000,"expires_in_secs":1000,
  "remaining_amount":1000000,"extension_count":0,"max_extension_secs":86400,
  "warning_key":"...:1000000",
  "checklist":[{"action":"extend_expiry","caller":"initializer","executable_now":true,"detail":"..."},
               {"action":"cancel_expired","caller":"initializer_or_taker","executable_now":false,"detail":"..."}]}]}
```

## Off-chain escrow index (AV-138)

A keeper bot watches hundreds or thousands of vaults and re-scans the
same watch list every few slots. `escrow-state/src/index.rs` keeps the
`WatchedEscrow` snapshots in one `EscrowIndex` and maintains three
inverted indexes over them, updated incrementally on `insert` /
`update` / `remove`:

| dimension | bucket | prunes |
|-----------|--------|--------|
| `state` | one bucket per `EscrowState` discriminant | close sweep reads only terminal buckets; merge-pair pass reads only `Funded` |
| `mint` | one bucket per bound mint (`None` = native SOL) | a per-token operator scans only its own mint's vaults |
| `expires_at` | `BTreeMap` deadline index | expiry scan reads only the `(now, now + window]` range |

The indexed twins — `scan_keeper_actions_indexed` (AV-20's logic) and
`scan_expiry_warnings_indexed` (AV-136's logic) — run the identical
per-escrow code over the index's candidates, so their output is
byte-identical to the slice scans for the same snapshots (pinned by
equivalence tests). The slice-based entry points are unchanged, so
existing callers keep working; a keeper that re-scans across slots
builds the index once and reuses it.

`EscrowIndex::verify_consistency` rebuilds every dimension from the
backing store and reconciles it against the live index, naming the
first divergence — the indexed scans run it under `debug_assertions`,
and the test suite drives randomized insert/update/remove sequences
through it. A keeper mutating the index across slots gets a loud
failure instead of a silently pruned scan.

Purely off-chain: snapshots only, no mutation of chain state, no
events, no clock. `std` only, no new dependencies.

## Maker credit scoring (AV-142)

`escrow-state/src/maker_score.rs` keeps an off-chain credit score per
escrow initializer (maker), aggregated in the keeper layer — the vault
account is fixed-layout and cannot cheaply maintain per-maker
history, so the score lives next to the AV-138 index, not on-chain.

`MakerScorebook::record(maker, escrow_id, outcome, at)` scores one
terminal escrow per maker (idempotent per escrow id, so re-feeding a
watch list is harmless); each maker keeps a sliding window of the
last 32 scored escrows (`SCORE_WINDOW`). The score is integer math,
0–1000:

```text
score = (600*completed + 300*(total - dispute_lost) + 100*(total - cancelled)) / total
```

Completion dominates (600‰), a clean dispute record is next (300‰ —
losing a dispute as maker is the strongest negative signal), and a
cancellation-free history is the tiebreak (100‰). A maker with no
history scores a neutral 500 and earns nothing: trust is earned, not
granted.

The score feeds the AV-66 protocol-fee schedule: 900+ earns two tier
steps, 750+ earns one — `MakerScorebook::fee_tier_bps` drops the
payout's rate down the schedule's rate-ranked ladder (cheapest live
rate first), so a 900+ maker on a 250/100/25 bps ladder pays the 25
bps floor where a newcomer on the 100 bps tier pays 100. A recorded
dispute loss starts a 7-day cooldown (`MAKER_COOLDOWN_SECS`) with no
discount, on top of the score penalty.

`EscrowIndex::record_terminal_outcomes` feeds terminal escrows from
the index (`Released` → completed, `Cancelled`/`Declined` →
cancelled). `Settled` is deliberately *not* fed — a state snapshot
does not record which side the arbiter favored, so the honest call is
an explicit `record` at resolve time. `MakerScorebook::snapshot`
returns a score-sorted leaderboard for operator dashboards.

## Keeper report signing (AV-101)

Keeper reports are consumed by offline signers (multisig CLIs, keeper
operators) — a report tampered with after the scan must not verify.
`escrow-state/src/report_signing.rs` wraps any keeper report's canonical
JSON in a signed envelope:

```json
{"report":{...},"signature":{"public_key":"...","signature":"..."}}
```

- The signature is Ed25519 (RFC 8032), computed over the report's
  canonical `to_json()` bytes — the exact same bytes the unsigned
  report emits. Hand-rolled in `escrow-state/src/ed25519.rs`
  (SHA-512 + field/scalar arithmetic over the existing `pda.rs` field
  backend); zero dependencies, verified byte-for-byte against OpenSSL
  (`openssl pkey -in seed -sign`) on two independent test vectors.
- All seven keeper report types implement `SignableReport`:
  `KeeperReport`, `CloseReport`, `MilestoneReport`,
  `StaleVaultReport`, `BatchReport`, `ExecutionBundle`,
  `EscrowAggregateView` — `report.to_signed_json(&key)` signs,
  `verify_signed_report_json(&envelope)` verifies without a JSON
  parser (the envelope splits by fixed layout).
- Opt-in and backward compatible: without a key, `to_json()` output
  is byte-identical; signing only *wraps* the canonical bytes.
  Tampering with the report or the signature (or verifying under the
  wrong key) fails closed; malformed envelopes are rejected without
  panicking.

## Ed25519 batch verification (AV-153)

Keeper report/intent batches verified one signature at a time pay
two scalar multiplications per signature. `batch_verify` in
`escrow-state/src/ed25519.rs` (re-exported from the crate root)
verifies a whole batch with the RFC 8032 batch equation
`(Σ zᵢ·Sᵢ)·G = Σ zᵢ·Rᵢ + Σ zᵢ·hᵢ·Aᵢ`, reusing the hand-rolled point
operations from AV-101 — one combined multi-scalar multiplication
instead of 2·n:

```rust
let items = vec![BatchVerifyItem {
    public_key: key.public_key(),
    message: &report_bytes,
    signature,
}];
let failures: Vec<usize> = batch_verify(&items); // empty on full success
```

Each blinding scalar is derived deterministically as
`zᵢ = SHA-512("escrow-av153-batch:" ‖ i ‖ Rᵢ ‖ Aᵢ ‖ Mᵢ) mod L`
(zero maps to 1): no RNG is needed (the crate stays
zero-dependency) and batches are reproducible; soundness comes from
the batch equation itself — a forged item satisfies the aggregated
equation only with negligible probability, exactly as with random
`zᵢ` chosen after the batch is fixed. A failed batch equation cannot
say *which* item failed, so the fallback is exact per-item RFC 8032
verification: the result is always identical to running `verify` on
every item (pinned by a randomized equivalence property test —
12 rounds of random batch sizes and random signature/message/key
corruptions — plus targeted single/multiple/malformed-input cases),
never short-circuit-masked.

## Aggregate statistics view (AV-78)

`escrow-state/src/aggregate.rs` rolls a watched fleet up into one
read-only report for keeper/operator dashboards — per-state counts
(all eight lifecycle states, fixed shape), an amount histogram (eight
fixed power-of-ten buckets in the smallest unit), average escrow
durations, and total locked value. Pure reads: no chain writes, no
state mutation, no events emitted.

```rust
let view = scan_aggregate_view(&watched, now); // keeper query over &[WatchedEscrow]
let view = EscrowAggregateView::from_indexed(&indexed, now); // full fidelity over &[IndexedEscrow]
let json = view.to_json(); // deterministic hand-serialized JSON
```

Two duration metrics, each honest about its data source:

- `avg_completed_duration_secs` — first event (`Initialized`) to the
  terminal event, averaged over escrows in a terminal state
  (`Released`/`Cancelled`/`Settled`/`Closed`). Only the
  `from_indexed` path can measure it: `IndexedEscrow` carries the full
  event history. On the keeper `WatchedEscrow` path the field stays
  `null` — plain snapshots have no event timestamps, and the view
  never fabricates one.
- `avg_open_duration_secs` — `now - fund_at` averaged over escrows
  currently holding funds (`Funded`/`Disputed`); `fund_at` is always
  recorded by `fund()`.

`total_locked` sums `remaining_amount()` over the fleet as a `u128`
(serialized as a decimal string — a fleet sum can exceed JSON-safe
integer range). `EscrowAggregateView::to_json()` follows the crate's
deterministic JSON convention, so the aggregate result exports next to
the per-escrow snapshots.

## Close sweep (AV-40)

Terminal-state vaults (`Cancelled` / `Released` / `Settled` / `Split` — AV-81) have
served their purpose, but their rent-exempt deposits stay locked until
the vault account is closed — stranding them forever if nobody sweeps.
`scan_closeable(watched)` is the second keeper scan: it walks the same
watch list and emits the executable `close_vault` call list for
terminal-state vaults, grouped per initializer signer into
`CloseBatch`es with a per-batch `total_reclaimed` lamports summary.
Like the AV-20 scan it lists only *executable* calls — `Disputed`
(the arbitration is still live, and the vault account is the arbiter's
audit surface) and already-`Closed` vaults are skipped, never listed,
as are the pre-terminal states (`Uninitialized` / `Funded` /
`Activated`). Each action names the initializer as the canonical
caller (AV-34 restricts `close_vault` to the initializer, checked
before state validity — the only key the chain accepts) and carries
`rent_reclaimed`: the mainnet rent-exempt minimum for the *current*
`VAULT_SPACE`, computed via `vault_close_rent_reclaimed()` rather
than a hardcoded figure, so the estimate tracks the account layout as
it grows. The scan carries no `now` (closing has no time gate) and is
dry-run by construction: a pure read over `&Escrow` snapshots, zero
side effects. `CloseReport::to_json()` emits hand-serialized JSON in
the same deterministic style (64-char lowercase hex keys, fixed field
order; batches in first-seen caller order, actions in input order):

```json
{"scanned":2,"batches":[
  {"caller":"...","total_reclaimed":12876000,"actions":[
    {"escrow_id":"...","action":"close_vault","caller":"...",
     "caller_role":"initializer","rent_reclaimed":7342800,
     "reason":"released"}
  ]}
]}
```

`scan_closeable` *plans* the sweep; `close_vaults` (AV-79, in
`escrow-state/src/batch_close.rs`) *executes* it: the operator feeds
the same watch list through a `CloseVaultsFilter` (state / expiry /
amount range) and the batch runs the exact AV-34 `close_vault` gates
per vault — initializer **and** taker must match (dual-party binding),
failures are isolated per vault (paused / disputed / stranger vaults
are reported, never abort the batch), and the Σ rent-exempt reclaim
comes from the same `vault_close_rent_reclaimed()` formula. Off-chain
execution only; no new on-chain instruction.

## Stale-vault rent sweep (AV-80)

`scan_closeable` plans *every* terminal close; `scan_stale_vaults`
finds the vaults nobody bothered to sweep: terminal-state vaults
(`Cancelled` / `Released` / `Settled` / `Split` — AV-34's exact close gate, paused
vaults excluded) whose measured on-chain balance is *exactly* the
rent-exempt minimum — the account has served its purpose and carries
nothing but the rent deposit. `Disputed` (audit surface, the chain
rejects the close), already-`Closed` (rent reclaimed, account gone),
and pre-terminal states are never listed; a terminal vault holding more
or less than the rent figure is skipped too (user funds still present,
or the AV-43 rent-health underfunded case — the sweep never misprices a
reclaim). Like the other scans it is a pure read over
`&WatchedEscrowWithBalance` snapshots: dry-run by construction, zero
side effects, no `now` (closing has no time gate).

Two outputs, both per-initializer grouped (first-seen caller order,
deterministic JSON, hand-serialized — the crate stays dependency-free):

- **Dry-run preview** — `StaleVaultReport::to_json()`: per-caller
  `total_reclaimed` Σ (accumulated with `checked_add`, the AV-79
  convention) over the caller's close actions.
- **To-be-signed bundle** — `stale_vault_signable_message(program_id,
  action, blockhash)` / `StaleVaultBatch::to_bundle_json(...)`: the
  real `close_vault` instruction bytes (the 8-byte discriminator
  recomputed from the IDL name via the same constructor the AV-29 IDL
  pipeline pins — the spec's `params: []`, so the data is the
  discriminator alone) plus the program-declared account metas (`vault`
  writable/non-signer, `initializer` writable/signer), compiled into a
  genuine Solana legacy transaction message with the AV-71 machinery
  and emitted as base64. `close_vault` needs the *initializer's*
  signature, and the keeper must not sign for it — an offline signer or
  multisig takes the bundle, signs each single-instruction message, and
  submits. Program id and blockhash are caller-supplied (the AV-71
  honesty labels apply).

```json
{"scanned":2,"required_lamports":6201360,"batches":[
  {"caller":"...","total_reclaimed":6201360,"actions":[
    {"escrow_id":"...","action":"close_vault","caller":"...",
     "caller_role":"initializer","vault_lamports":6201360,
     "rent_reclaimed":6201360,"expires_at":1700000000,
     "reason":"cancelled"}
  ]}
]}
```

`scan_milestones(watched, now)` (AV-42) is the third keeper scan: it
walks the same watch list and, per escrow carrying an AV-15 milestone
plan in `Funded` state, emits the milestone tranche's executable call
list. Each party's missing `confirm_milestone` approval and each
party's missing `skip_milestone` approval is listed as its own action
— skipping is dual-signed on-chain (each party records their approval
in a separate call, executing only when both are present), so the
scan never invents a combined call the chain has no instruction for.
Once every gate passes, the initializer's `release_milestone` becomes
executable. Every action carries the exact arguments the keeper needs:
`escrow_id`, `index`, `caller` (+ `caller_role`), `mint`, and the
tranche amount split (`tranche`, `fee`, `taker_payout` — the AV-17
protocol-fee preview, `0` on confirm/skip actions which move no
funds). Tranches that are not yet executable go into `blocked` with a
machine-readable reason: `"unconfirmed"`, `"quorum_not_satisfied"`,
`"timelock_not_reached"`, or `"prerequisite"` (an earlier tranche is
still unsettled — settlement is strictly in-order). Like the other
scans it is a dry-run over `&Escrow` snapshots — no mutation, no
events, no clock; escrows without a milestone plan, not in `Funded`,
or fully settled contribute nothing — and `MilestoneReport::to_json()`
emits hand-serialized JSON in the same deterministic style (AV-33
conventions: fixed field order, 64-char lowercase hex keys, `mint` as
hex or `null`).

**Keeper milestone bundle execution (AV-76).** The scan is read-only;
`execute_milestone_bundle(indexed, escrow_id, actions, subset,
payout_to, at)` in `escrow-state/src/keeper.rs` is the write side —
the keeper-side executor that turns a bundle of `ReleaseMilestone`
actions into real tranche releases on an `IndexedEscrow`. It composes
the existing `release_milestone` instruction (already in the
`INSTRUCTIONS` spec / IDL), so no new on-chain instruction or IDL
entry exists. The keeper passes an optional milestone-index subset to
release only the tranches it wants settled now: unselected tranches
stay pending and the vault stays `Funded`. A subset equal to the full
configured index set — or no subset at all — is a full execution and
may settle the vault; any *proper* subset additionally emits a
trailing `BundlePartiallyExecuted` event (discriminant 38) after the
per-tranche `MilestoneReleased` events, carrying the executed
tranches' gross + fee totals (`from == to == Funded`, no actor — the
bundle is a keeper composition, and each tranche's own event already
names its signer). The return value reports `executed` / `remaining`
indices and whether the vault settled. Atomicity is the AV-61 bundle
shape applied to keeper execution: the subset runs all-or-nothing on a
clone, in ascending index order, and any tranche failure (an
unconfirmed milestone, a misjudged gate) returns the error with the
caller's escrow untouched — zero events leaked, state identical.
Invalid bundles (empty, mixed escrow ids, confirm/skip actions,
missing plan, empty/duplicate/out-of-range/dangling subset indices)
are `InvalidMilestones` (code 110) — the existing variant is reused,
no new error code.

## Schema-migration keeper scan (AV-85)

`scan_schema_migrations(watched)` is the migration-awareness keeper
scan: it walks the watch list and dry-runs the AV-85 migration chain
(`Escrow::migrate_dry_run`) for every vault below `SCHEMA_VERSION`.
Each `SchemaMigrationAction` names the initializer as the canonical
caller (the only key the chain accepts), the `from → to` version path,
the changed-fields list flattened in step order (name / type / bytes
per field), and the dry-run verdict: `ready` actions are executable
`migrate_schema` calls for the initializer to sign; blocked actions
name the machine-readable reason — `"paused"` (a paused escrow fails
fast) or `"corrupt"` (a carried-over field violates the conservation
invariants — the vault needs repair, never a migration signature).
Current vaults are skipped: there is no no-op migration to list.
Dry-run by construction — a pure read over `&Escrow` snapshots, zero
side effects, no `now`. `SchemaMigrationReport::to_json()` emits the
dry-run preview in the same deterministic hand-serialized style:

```json
{"scanned":2,"actions":[
  {"escrow_id":"...","action":"migrate_schema","caller":"...",
   "caller_role":"initializer","from_version":0,"to_version":2,
   "new_fields":[{"name":"schema_version","type":"u8","bytes":1},
                 {"name":"slash_terms","type":"Option<SlashTerms>","bytes":41},
                 {"name":"penalty_paid","type":"u64","bytes":8}],
   "ready":true,"block_reason":null,"reference":null}
]}
```

## State snapshot (AV-26)

Keeper bots and indexers need one more primitive than the call list: *"what
does this escrow look like right now?"* `escrow.snapshot(now)` answers with
a point-in-time, read-only `EscrowSnapshot` — every raw field plus the
derived quantities an operator reasons about — serialized by
`EscrowSnapshot::to_json()` as canonical hand-written JSON (dependency-free,
deterministic field order, 64-char lowercase hex keys). Two snapshots of
equal state at equal `now` are byte-identical, so indexers can hash or diff
them directly. The snapshot is a pure read: no state changes, no events.

Raw fields: `initializer`, `taker`, `state` (`uninitialized` / `activated` /
`funded` / `released` / `cancelled` / `disputed` / `settled`), `amount`,
`decimals` (AV-28; `0` = no decimal metadata declared), `released`,
`expires_at`, `grace_period`, `dual_sig`
(`required` / `initializer_activated` / `taker_activated`), `fee_bps`,
`fees_paid`, `fee_recipient` (AV-44; hex or `null`), `fee_cap` (AV-63;
`0` = uncapped), `skipped`, `penalty_bps`, `unlock_at` (AV-27; `0` = no
timelock), `relative_timelock_secs` (AV-64; `0` = no relative lock),
`fund_at` (AV-64; `0` = never funded), plus the optional `quorum`,
`vesting`, `arbiter`, `mint`, `evidence_hash`, `rationale_hash` (AV-38;
hex or `null`), `reference` (AV-53; hex or `null`), `refund_to` (hex or
`null`), `arbiter_panel` (AV-65; `null` when no panel is configured —
otherwise `n`, `threshold`, the 64-char hex member keys, and the
recorded `votes`: per-member `taker_amount` plus the optional hex
`rationale_hash`), `slash_terms` (AV-82; `null` when no slash clause is
configured — otherwise the 64-char hex `penalty_account` and the
`slash_deadline`), `penalty_paid` (AV-82; cumulative slashed amount,
`0` = never slashed), and `slash_eligible` (AV-82; the keeper's slash
predicate at `at` — same predicate the scan uses, so a snapshot never
disagrees with the scan)
and the effective `refund_recipient` (whitelist when configured, else the
initializer) — plus the retained on-chain event history (AV-57):
`event_history` (the valid ring window, oldest-first — `kind` /
`at` / `actor` per entry), `event_capacity`, and the monotonic
`event_total`.

Derived at the snapshot time (`at`): `remaining` (`amount − released`:
what `cancel` / `cancel_expired` would refund, skipped tranches included),
`vested` / `claimable` (schedule unlock vs. vested-minus-released — what
`claim` would move), quorum progress (`registered` / `threshold` /
`approvals` / `satisfied`), milestone progress (per-tranche
`amount` / `confirmed` / `settled`, counts, and the `next` unsettled
tranche), `expiry_eligible` (the chain's `cancel_expired` gate at `at`,
grace included — the same predicate the keeper scan uses, so a snapshot
never disagrees with the scan), and `unlock_eligible` (the timelock
gate at `at` — absolute (AV-27) and relative (AV-64) — the same predicate the keeper scan uses for `claim`).

Human-readable companions (AV-28): alongside every raw amount the
snapshot renders a `display_*` string in whole-token units —
`display_amount`, `display_released`, `display_remaining`,
`display_vested`, `display_claimable`, `display_fees_paid`,
`display_skipped`, and per-tranche `display_amount` — formatted with the
escrow's `decimals` (`1000000` at 6 decimals → `"1.000000"`; `0` decimals
renders the bare integer). Raw fields stay untouched, so indexers keep
diffing numbers while operators read whole tokens.

```json
{"at":1750000000,"initializer":"...","taker":"...","state":"funded","schema_version":2,"migration_pending":false,
 "amount":1000000,"decimals":6,"display_amount":"1.000000",
 "released":0,"display_released":"0.000000",
 "remaining":1000000,"display_remaining":"1.000000",
 "expires_at":0,"grace_period":0,"expiry_eligible":true,
 "dual_sig":{"required":false,"initializer_activated":false,"taker_activated":false},
 "quorum":null,"vesting":null,"vested":0,"display_vested":"0.000000",
 "claimable":0,"display_claimable":"0.000000",
 "arbiter":null,"mint":null,"fee_bps":0,"fees_paid":0,"display_fees_paid":"0.000000","fee_recipient":null,"fee_cap":0,
 "milestones":null,"skipped":0,"display_skipped":"0.000000",
 "evidence_hash":null,"evidence_deadline_secs":0,"escalated_by":null,"rationale_hash":null,"refund_to":null,"refund_recipient":"...",
 "penalty_bps":0,"unlock_at":0,"unlock_eligible":true,"relative_timelock_secs":0,"fund_at":1700000000,"payout_allowlist":null,"reference":null,
 "slash_terms":null,"penalty_paid":0,"slash_eligible":false, "event_history":{"capacity":64,"total":0,"count":0,"entries":[]}}
```

## State attestation (AV-125)

Honest scope note first: this is a **purely off-chain protocol**. There is
no Anchor instruction, no IDL entry, no account-layout change, and no rent
change — the vault layout table below is untouched. An attestation never
executes on-chain; it is a signed claim about chain state that a keeper
relays and anyone can check.

The problem it solves: a keeper or indexer that forges vault state — e.g.
reports a vault as `Funded` when the chain says `Cancelled` — is normally
undetectable off-chain. `escrow.attest_state(escrow_id, slot, signing_key)`
has the *initializer* sign a canonical `StateSummary` (state discriminant /
`amount` / `released` / `refunded` / `penalty_paid` / `schema_version` /
`slot`) with their Ed25519 key (the same authority the AV-123 release-intent
channel trusts, signed with the hand-rolled RFC 8032 signer from AV-101),
producing a `StateAttestation{escrow_id, summary, signature}` envelope.
Keepers verify the detached signature against the initializer's public key —
`verify_state_attestation` needs no chain access, and the domain separator
`b"ESCROW-STATE-ATTEST-v1"` keeps the signature from verifying as any other
envelope in this crate (release intent, keeper report, multisig ballot).

The encoding is fixed-field-order, little-endian integers, no length
prefixes — 64 bytes per summary, byte-identical for equal state at equal
slot — so a keeper holding only snapshots can recompute the exact signed
bytes via `EscrowSnapshot::attestation_summary(slot)` and verify offline.
`slot` must come from the chain clock (the AV-27 rule: measured on-chain,
never an instruction param), so a stale attestation is detectable by
construction. The `refunded` leg is derived, not persisted — this crate keeps
no cumulative refunded counter (only the event-sourced `FundsTriple`
rebuilds it from the log, never fabricated): on `Cancelled` / `Settled` /
`Closed` it is the audit-preserved remainder (the initializer's refund), `0`
elsewhere. The call is a pure read: it emits no events and mutates nothing.

## Account space & rent

The `Vault` account layout is pinned in `escrow-state` (`VAULT_FIELDS`;
Borsh field order) and asserted three ways by the AV-10 tests — hardcoded
byte math, a test-only manual Borsh encoder against a real `Escrow`, and a
two-way consistency check against the IDL parameter table:

| field         | type              | bytes |
|---------------|-------------------|-------|
| discriminator | Anchor prefix     | 8     |
| initializer   | Pubkey            | 32    |
| taker         | Pubkey            | 32    |
| amount        | u64               | 8     |
| released      | u64               | 8     |
| expires_at    | u64               | 8     |
| state         | u8 (discriminant) | 1     |
| quorum        | Option<Quorum>    | 338   |
| activation    | u8 (bitmask)      | 1     |
| vesting       | Option<VestingSchedule> | 25 |
| arbiter       | Option<Pubkey>    | 33    |
| milestones    | Option<MilestonePlan> | 66 |
| milestone_flags | u64 (bitmask)   | 8     |
| skipped       | u64               | 8     |
| mint          | Option<Pubkey>    | 33    |
| fee_bps       | u16               | 2     |
| fees_paid     | u64               | 8     |
| grace_period  | u64               | 8     |
| evidence_hash | Option<[u8; 32]>  | 33    |
| refund_to     | Option<Pubkey>    | 33    |
| penalty_bps   | u16               | 2     |
| timelock      | u64               | 8     |
| decimals      | u8                | 1     |
| rationale_hash | Option<[u8; 32]> | 33    |
| emergency_unlock | bool           | 1     |
| fee_recipient | Option<Pubkey> | 33    |
| pause_authority | Option<Pubkey> | 33  |
| paused        | bool              | 1     |
| payout_allowlist | Option<PayoutAllowlist> | 130 |
| reference | Option<[u8; 32]> | 33 |
| disputed_at | u64 | 8 |
| default_judgment | Option<DefaultJudgment> | 17 |
| default_confirmed | bool | 1 |
| subscription | Option<SubscriptionSchedule> | 18 |
| subscription_next | u8 | 1 |
| subscription_released | u64 | 8 |
| event_head | u8 | 1 |
| event_total | u64 | 8 |
| event_count | u8 | 1 |
| event_capacity | u8 | 1 |
| event_slots | [EventHistorySlot; 64] | 1152 |
| max_extension_secs | u64 | 8 |
| extension_count | u64 | 8 |
| fee_cap | u64 | 8 |
| relative_timelock_secs | u64 | 8 |
| fund_at | u64 | 8 |
| arbiter_panel | Option<ArbiterPanel> | 996 |
| fee_schedule | FeeSchedule | 81 |
| evidence_deadline_secs | u64 | 8 |
| escalated_by | Option<Pubkey> | 33 |
| subscription_amounts | [u64; 64] | 512 |
| schema_version | u8 | 1 |
| slash_terms | Option<SlashTerms> | 41 |
| penalty_paid | u64 | 8 |
| cpi_allowlist | Option<CpiAllowlist> | 258 |
| multisig_authority | Option<MultisigAuthority> | 67 |
| appeal_window_secs | u64 | 8 |
| appeal_deadline | u64 | 8 |
| appeal_state | u8 (enum discriminant) | 1 |
| appeal_ballot | AppealBallot | 9 |
| vesting_curve | Option<VestingCurve> | 82 |
| evidence_root | Option<[u8; 32]> | 33 |
| evidence_leaves | u8 | 1 |
| evidence_disclosed | u64 | 8 |
| basket | Option<BasketLegs> | 386 |
| payout_denylist | Option<PayoutDenylist> | 130 |
| auction | Option<DutchAuction> | 19 |
| transfer_hook | Option<[u8; 32]> | 33 |
| streaming_fee_rate | u64 | 8 |
| streaming_fees_accrued | u64 | 8 |
| appeal_bond | u64 | 8 |
| appeal_bond_paid | u64 | 8 |
| delegation | Option<Delegation> | 37 |
| swap_link | Option<[u8; 32]> | 33 |
| insurance_pool | bool | 1 |
| pool_paid | u64 | 8 |
| pool_slashed | u64 | 8 |
| pool_inflow | u64 | 8 |
| pool_payout_paid | u64 | 8 |
| interest_rate_bps | u16 | 2 |
| interest_accrual_base | u64 | 8 |
| interest_accrued | u64 | 8 |
| interest_paid | u64 | 8 |
| payout_split | PayoutSplit (u8 count + 8×[u8;32] recipients + 8×u64 amounts) | 321 |
| deadman_inactivity_secs | u64 | 8 |
| deadman_heir | Option<Pubkey> | 33 |
| deadman_last_activity | u64 | 8 |
| rent_topped_up_total | u64 | 8 |
| funded_total | u64 | 8 |
| funding_plan | Option<FundingPlan> (1-byte discriminant + total_amount u64 + max_tranches u8 + tranches_used u8) | 11 |
| release_cooling_secs | u64 | 8 |
| release_intent_at | Option<u64> (1-byte discriminant + 8-byte stamp) | 9 |
| price_gate | Option<PriceGate> (1-byte discriminant + 1-byte direction + 8-byte target + 8-byte max_staleness_secs) | 18 |
| penalty_escalation_rate_bps | u16 | 2 |
| penalty_escalation_cap_bps | u16 | 2 |
| slot_timelock_slots | u64 | 8 |
| fund_slot | u64 | 8 |
| compound_interest | bool | 1 |
| interest_compounded | u64 | 8 |
| dispute_interest | u64 | 8 |
| claim_cooldown_slots | u64 | 8 |
| last_claim_slot | Option<u64> (1-byte discriminant + 8-byte slot) | 9 |
| counter_offer | Option<CounterOffer> (1-byte discriminant + 8-byte amount + 8-byte expiry) | 17 |
| last_intent_nonce | u64 | 8 |
| keeper_bounty_pool | u64 | 8 |
| keeper_bounty_per_crank | u64 | 8 |
| slash_ladder | Option<SlashLadder> (1-byte discriminant + 113-byte region: 32-byte penalty account + 8 fixed 10-byte (deadline u64, bps u16) rung slots + 1 rung-count byte) | 114 |
| slash_ladder_index | u8 | 1 |
| refunded | u64 | 8 |
| twap_gate | Option<TwapGate> (1-byte discriminant + 1-byte direction + 8-byte target + 8-byte window_slots + 8-byte max_staleness_secs) | 26 |
| dual_control_checker | Option<Pubkey> (1-byte discriminant + 32-byte checker key) | 33 |
| dual_control_intent | Option<DualControlIntent> (1-byte discriminant + 89-byte intent region) | 90 |
| disputed_amount | u64 | 8 |
| auto_unpause_at | Option<u64> (1-byte discriminant + 8-byte timestamp) | 9 |
| min_funding_amount | Option<u64> (1-byte discriminant + 8-byte bound) | 9 |
| max_funding_amount | Option<u64> (1-byte discriminant + 8-byte bound) | 9 |
| arbiter_fee_flat | Option<u64> (1-byte discriminant + 8-byte flat lamport slice) | 9 |
| arbiter_fee_bps | Option<u16> (1-byte discriminant + 2-byte bps rate) | 3 |
| **total**     |                   | **5545** |

The quorum region is always reserved (zeroed when `None`), so
`initialize_quorum` writes the policy in place — the account never needs a
realloc. AV-45: the 338-byte quorum region is the 1-byte `Option`
discriminant plus the 337-byte weighted policy — eight attestor keys
(256), eight per-attestor u64 weights (64), the registered count (1),
the u64 weight-sum threshold (8), and the approval bitmask (8). The 1-byte
activation bitmask (AV-12) is likewise always present
(zeroed for plain escrows), as is the 25-byte vesting region (AV-13:
1-byte discriminant + `start`/`end` u64, zeroed when no schedule is
attached; AV-51 appends the `cliff_at` u64), the 33-byte arbiter region (AV-14: 1-byte discriminant +
32-byte key, zeroed when no arbiter is configured) — and the 66-byte
milestone plan region (AV-15: 1-byte discriminant + eight tranche u64s +
count byte, zeroed when no plan is attached), the 8-byte confirmation
bitmap (six bits per milestone: the two parties' release-path
confirmations, the released bit, the two parties' skip approvals, the
skipped bit), and the 8-byte skipped counter — and the 33-byte mint
binding (AV-16: 1-byte discriminant + 32-byte address, zeroed when no
mint is bound) — all appended after the
earlier fields, so every earlier field offset stays stable. The 2-byte
protocol fee rate `fee_bps` (AV-17, zeroed when no fee is configured) and
the 8-byte cumulative fee counter `fees_paid` (AV-17, zeroed when no fee
was charged) follow the same always-present, appended-last treatment, as
does the 8-byte expiry grace period `grace_period` (AV-21, zeroed when no
grace period is configured) — and the 33-byte dispute evidence hash region
(AV-22: 1-byte discriminant + 32-byte commitment, zeroed when no evidence
is attached) — and the 33-byte refund whitelist region (AV-23: 1-byte
discriminant + 32-byte address, zeroed when no whitelist is configured)
— and the 2-byte anti-griefing penalty rate `penalty_bps` (AV-24, zeroed
when no penalty is configured) — and the 8-byte timelock unlock timestamp
`timelock` (AV-27, zeroed when no timelock is configured) — and the 1-byte
token decimal metadata `decimals` (AV-28, zeroed when no decimal metadata
is declared) — and the 33-byte arbiter's rationale-document hash region
(AV-38: 1-byte discriminant + 32-byte commitment, zeroed when the arbiter
attached no rationale) — and the 1-byte emergency timelock-unlock
governance opt-in `emergency_unlock` (AV-41, zeroed when the feature is
off) — and the 33-byte protocol-fee recipient region (AV-44: 1-byte
discriminant + 32-byte address, zeroed when no recipient is bound) — and
the 33-byte off-chain reference memo region (AV-53: 1-byte discriminant
+ 32-byte correlation id, zeroed when no memo is attached) — and the
8-byte dispute timestamp `disputed_at` (AV-55, zeroed when the escrow
was never disputed) — and the 17-byte default-judgment region (AV-55:
1-byte discriminant + 16-byte judgment, zeroed when no default
judgment is configured) — and the 1-byte taker confirmation bit
(AV-55, zeroed when the split is unconfirmed) — and the 18-byte
subscription schedule region (AV-56: 1-byte discriminant + 17-byte
schedule, zeroed when no schedule is attached) — and the 1-byte
next-period index (AV-56, zeroed when no schedule is attached,
advanced strictly in order by `release_period`) — and the 8-byte
per-period released bitmap (AV-56, zeroed when no schedule is
attached; the `period_index` param selects which bit flips) — and the
1-byte event-history ring head (AV-57, zeroed when no events were
recorded) — and the 8-byte monotonic event total (AV-57, zeroed when
no events were recorded, never decreases) — and the 1-byte
valid-entry count (AV-57, zeroed when no events were recorded) — and
the 1-byte configured ring capacity (AV-57, 64 by default) — and the
1152-byte event slots (AV-57: 64 × 18-byte kind/at/actor entries,
zeroed when no events were recorded; always reserved at the 64-entry
ceiling so a smaller configured capacity never needs a realloc) — and
the 8-byte extension bound (AV-59: zeroed when extension is not enabled)
— and the 8-byte extension counter (AV-59: zeroed when never extended) —
and the 8-byte absolute protocol-fee ceiling (AV-63: zeroed = uncapped
when no ceiling is configured) — and the 8-byte relative timelock duration
(AV-64: zeroed when no relative timelock is configured) — and the 8-byte
funding timestamp (AV-64: zeroed when the escrow was never funded) —
and the 996-byte arbiter panel region (AV-65: 1-byte `Option`
discriminant + 995-byte panel — 594-byte AV-65 vote region + 401-byte
AV-137 blind-vote region, zeroed when no panel is configured) —
and the 81-byte tiered protocol-fee schedule region (AV-66: 1-byte
live-tier count + 8 fixed 10-byte tier slots, zeroed when no schedule
is configured) — and the 8-byte dispute-evidence disclosure deadline
(AV-68: zeroed when no deadline is configured) — and the 33-byte
escalating-party region (AV-68: 1-byte discriminant + 32-byte key,
zeroed when the escrow was never disputed) — and the 258-byte CPI
target-program allowlist region (AV-83: 1-byte live-program count + 8
32-byte program ids, zeroed when no allowlist is configured) — and the
67-byte multisig authority region (AV-84: 1-byte discriminant + 32-byte
multisig program id + 32-byte authority PDA + u16 threshold, zeroed when
no multisig binding is configured) — and the 8-byte slash-appeal window
(AV-86: zeroed when no window is configured) — and the 8-byte
slash-appeal deadline (AV-86: zeroed when no appeal is in flight) — and
the 1-byte appeal state discriminant (AV-86: `None` when no appeal is in
flight) — and the 9-byte appeal ballot (AV-86: 1-byte vote count +
8-byte tally bitmap, zeroed when no appeal is in flight) — and the
82-byte vesting unlock-curve region (AV-90: 1-byte discriminant + 81-byte
tier region — 1-byte tier count + eight fixed 10-byte timestamp/bps
slots — zeroed when the escrow uses the plain AV-13 linear unlock) —
and the 33-byte dispute-evidence Merkle-root region (AV-91: 1-byte
discriminant + 32-byte root, zeroed when no multi-doc evidence was
committed) — and the 1-byte committed evidence leaf count (AV-91:
zeroed when no root was committed) — and the 8-byte
evidence-disclosure bitmap (AV-91: one bit per committed document,
zeroed when the root is committed) — and the 386-byte basket-leg
table region (AV-95: 1-byte discriminant + 1-byte live-leg count +
eight fixed 48-byte (mint, amount, released) slots, zeroed when no
basket is configured) — and the 130-byte payout-denylist region
(AV-96: 1-byte discriminant + 129-byte list — 4×32-byte addresses +
1-byte count — zeroed when no denylist is configured) — and the
19-byte Dutch-auction region (AV-97: 1-byte discriminant + 18-byte
terms — `start_at` + `end_at` (u64) + `reserve_bps` (u16) — zeroed
when no auction is configured) — and the 16-byte appeal-bond tail
region (AV-103: `appeal_bond` + `appeal_bond_paid` (u64 each), zeroed
when no bond was configured) — and the 37-byte delegation region
(AV-104: 1-byte discriminant + 32-byte operator key + 4-byte scope
bitmap, zeroed when no grant is live) — and the 33-byte swap-link
region (AV-105: 1-byte discriminant + 32-byte counterparty escrow id,
zeroed when the escrow is not linked into a swap pair) — and the
49-byte dead-man's switch tail region (AV-109: `deadman_inactivity_secs`
(u64, zeroed when the switch is not configured) + `deadman_heir`
(Option<Pubkey>: 1-byte discriminant + 32-byte heir, zeroed when no
heir is named) + `deadman_last_activity` (u64, zeroed when the escrow
was never funded) — and the 8-byte rent top-up tail region (AV-110:
`rent_topped_up_total` (u64, zeroed when no top-up was ever made)) —
and the 19-byte tranched-funding tail region (AV-111:
`funded_total` (u64, zeroed until the first deposit) +
`funding_plan` (Option<FundingPlan>: 1-byte discriminant + 10-byte
plan payload — `total_amount` u64 + `max_tranches` u8 +
`tranches_used` u8, `None` when no plan is attached)) — and the
17-byte release-cooling tail region (AV-112:
`release_cooling_secs` (u64, 0 = unconfigured) +
`release_intent_at` (Option<u64>: 1-byte discriminant + 8-byte
stamp, `None` when no intent is live)) — and the 16-byte
keeper-bounty tail region (AV-124: `keeper_bounty_pool` +
`keeper_bounty_per_crank` (u64 each), zeroed when the vault never
opted into the keeper bounty) — and the 115-byte tiered-slash-ladder
tail region (AV-126: `slash_ladder` (Option<SlashLadder>: 1-byte
discriminant + 113-byte region — 32-byte penalty account + 8 fixed
10-byte (deadline u64, bps u16) rung slots + 1 rung-count byte,
zeroed when no ladder is configured) + the 1-byte
`slash_ladder_index` rung cursor, zeroed when no ladder is
configured).
`escrow-state` exposes `VAULT_SPACE` (5954) and
`VAULT_SPACE_NO_QUORUM` (5464) for the Anchor `space =` constraint, plus a
pure-logic rent-exemption check mirroring `Rent::minimum_balance`. With
mainnet rent parameters the full vault needs **42,330,720 lamports** to be
rent-exempt (`check_vault_rent_exempt` asserts the exact boundary).

### Terminal-state rent reclamation (AV-34)

A vault account must carry the rent-exempt minimum for as long as the
escrow lives — but once the escrow reaches a terminal state, the account
serves no purpose and the lamports would stay locked forever if the
account were never closed. `close_vault` lets the initializer reclaim
the deposit:

- **Gate:** only the initializer may close (`Unauthorized` otherwise,
  checked before state validity); only `Cancelled`, `Released` and
  `Settled` may be closed. `Disputed` is deliberately *not* closable —
  the arbitration is still live and the vault is the arbiter's audit
  surface.
- **Effect:** the escrow moves to the new `Closed` state (discriminant
  7, appended after `Settled` so discriminants 0–6 stay stable for
  already-serialized vaults) — the deepest terminal: every transition,
  and a second `close_vault`, is `InvalidStateTransition` from there.
  No vault field is added or moved by the close itself (`VAULT_SPACE`
  stays 3503 — the AV-38 rationale-hash, AV-44 fee-recipient, AV-45
  weighted-quorum, AV-46 pause-switch, AV-49 payout-allowlist, AV-51
  vesting-cliff, AV-53 reference-memo, AV-55 default-judgment,
  AV-56 subscription, AV-57 event-history, AV-59 extension, AV-63
  fee-cap, AV-64 relative-timelock, AV-65 arbiter-panel, AV-66
  fee-schedule, AV-68 evidence-deadline, AV-73 per-period-table, AV-75
  schema-version, and AV-82 slash-region growth is accounted in the
  layout table above); the state
  byte simply carries the new discriminant.
- **Rent:** the returned value is `escrow_state::vault_close_rent_reclaimed()`
  — the mainnet rent-exempt minimum for `VAULT_SPACE` (**25,271,760
  lamports**, the same figure `initialize` demanded), carried in the
  `VaultClosed` indexer event's `rent_reclaimed` amount. On-chain the
  real build closes the account with Anchor's `close` constraint and the
  runtime transfers the account's lamports to the initializer.

### Combined release + close (AV-50)

`release_and_close` merges the final payout and the account close into
one instruction: `Funded -> Released -> Closed`. The release always
covers the **full remaining lockup** — only a full release reaches the
`Released` terminal state `close_vault` accepts — and every `release`
gate (initializer authority, payout policy, quorum, timelock, mint
binding) applies exactly as on a plain `release`. If either leg fails,
the whole instruction aborts with zero side effects (state, counters
and the event log all roll back). The initializer signs once instead
of twice, and the rent-exempt deposit returns together with the
payout. The indexer sees the fixed `Released` → `VaultClosed` event
pair; the vault layout is untouched (`VAULT_SPACE` stays 2819).

## IDL pipeline (AV-29)

`programs/escrow-vault/idl/escrow_vault.json` is a checked-in Anchor IDL
for the program: every instruction (name, `sha256("global:<name>")[..8]`
discriminator, args), the `Vault` account with per-field Borsh byte
offsets, the `QuorumPolicy`/`VestingSchedule`/`MilestonePlan`/`PanelVote`/`ArbiterPanel` subtypes,
and the error code table.

The Anchor/Solana BPF toolchain is unavailable in this environment, so
the file is *generated*, not hand-written: `escrow-state/src/idl_json.rs`
(a test-only pipeline) renders it deterministically from the single
sources of truth — `VAULT_FIELDS` for the account layout, the
`INSTRUCTIONS` spec table for instruction name/args, `EscrowError` for
error codes. Regenerate with:

```bash
UPDATE_IDL=1 cargo test -p escrow-state idl_json
```

Without the variable, CI fails on any byte-level drift between the
generator and the checked-in file. The pipeline tests pin the IDL in
both directions: instruction name/args against the spec table,
discriminators against FIPS-pinned SHA-256 vectors, and — the point of
the item — every account field's IDL name/type/offset against the real
bytes of the hand-written Borsh encoder (`encode_escrow`) for a
fully-configured escrow, including the dispute path's `evidence_hash`
and `rationale_hash` regions. The `"offset"` on each field is a pipeline extension (byte
offset into the account data *including* the 8-byte Anchor
discriminator); Anchor tooling ignores unknown JSON fields. When the
Anchor toolchain is available, `anchor build` output should replace
this file — the pinning tests then guard the real artifact instead.

## IDL semver breaking-change gate (AV-152)

Generation from sources can still *intentionally* change the IDL
between releases — a removed instruction, a reordered account field,
a reused error code — and each of those silently breaks off-chain
clients (indexers, the keeper CLI, SDKs) at the wire level.
`escrow-state/src/idl_compat.rs` (a test-only pipeline, like AV-29)
diffs the checked-in IDL against the last release's baseline
(`programs/escrow-vault/idl/escrow_vault.baseline.json`) and
classifies every change:

- **breaking**: instruction removed; instruction arg
  added/removed/renamed/type-changed/reordered (args are positional
  Borsh); account or named-type field removed/renamed/type-changed/
  reordered; a *required* (non-`Option`) field added; named type
  removed; error removed; error code changed or reused.
- **non-breaking**: instruction added; `Option<…>` field added (the
  vault's opt-in convention — zeroed when unset); named type added;
  error code added; version bump.

The diff works on a semantic model parsed by a hand-rolled
zero-dependency JSON parser, so reformatting the IDL never reports
as a change. CI gate: every breaking change needs an explicit entry
in `BREAKING_CHANGE_ALLOWLIST` (stable keys like
`instruction_removed:release`), otherwise the `idl_semver_gate`
test fails. When cutting a release, refresh the baseline:

```bash
cp programs/escrow-vault/idl/escrow_vault.json \
   programs/escrow-vault/idl/escrow_vault.baseline.json
```

## Concurrent simulation runner (AV-30)

`escrow-state/src/sim.rs` (test-only) is a deterministic off-chain
simulation runner: each run interleaves random operations across several
randomly-configured escrows (dual-sig, quorum, vesting, milestones, mint,
fees, grace, penalties, timelock, decimals, arbiter — seeded, so every
configuration is reproducible), advancing a shared clock so expiries and
vesting curves are crossed mid-run. Every step asserts amount conservation
(`deposited == paid_out + refunded + locked`), the protocol-fee bound
(`fees_paid <= released`), and — via deliberately-invalid probes — the
exact error for each illegal operation, pinning the documented check order
(authority → state → config → amount) under interleaving. Three tests run
it: 16 seeds × 500 steps × 6 escrows, a single escrow driven 2000 steps
deep, and a determinism pin (same seed ⇒ identical run, so any failure is
reproducible from the seed alone). It runs in CI with the rest of
`cargo test -p escrow-state`.

## Settlement CPI construction (AV-31)

`escrow-state/src/cpi.rs` builds the transfer instructions that move
settled funds — with zero dependencies and fully offline-testable:

- **Instruction constructors**: `system_transfer(from, to, lamports)`
  assembles a System Program `Transfer` (u32 index `2` || u64 LE, 12
  bytes); `spl_token_transfer(source, mint, destination, authority,
  amount)` assembles an SPL Token `Transfer` (u8 index `3` || u64 LE, 9
  bytes). The byte layouts are pinned by unit tests, and the SPL Token
  program id is decoded from its canonical base58 address with the same
  decoder that validates mint addresses (AV-16).
- **Settlement plans**: `payout_plan` (release / claim / milestone
  release), `refund_plan` (cancel / cancel_expired), and `resolve_plan`
  take the escrow *after* the transition plus the amounts the transition
  returned, and validate the plan against the machine before any
  instruction is built: moved totals cannot exceed what the machine
  recorded (`SettlementMismatch` on tampered or stale amounts),
  recipients are pinned against the escrow's taker / initializer / refund
  policy (`RecipientMismatch` on a swapped destination — the AV-23
  anti-phishing pin), and the transfer program follows the escrow's mint
  binding (native SOL vs SPL token).

The Anchor skeleton (`programs/escrow-vault/src/program.rs`,
`cpi_settle_payout` / `cpi_settle_refund` / `cpi_settle_resolve`) mirrors
these constructors: the real build assembles the addresses, calls the
matching `cpi::*_plan`, and executes each validated leg (native legs via
`invoke`/`invoke_signed` with the vault seeds, SPL legs via
`anchor_spl::token::transfer`). Because the program never hand-rolls
instruction bytes, the on-chain code cannot drift from the tested layout.

### Token-2022 settlement (AV-166)

A mint-bound escrow can name its token program on the settlement
addresses (`token_program: Some(...)`): `None` keeps the legacy SPL
Token plain `Transfer` behavior byte-identical, while the Token-2022
program id auto-dispatches to `TransferChecked` (index `12`, shared by
both token programs) with the escrow's AV-28 decimals asserted on-chain
against the mint account — a decimals mismatch fails the transaction
instead of moving a mis-scaled amount. An unknown program id (or any
program named on the native-SOL path) fails the plan with
`UnsupportedTokenProgram`: the module pins layouts for exactly the two
token programs and never builds an instruction for anything else.

`MintDescriptor` is the off-chain mint binding with extension
awareness: the transfer-fee schedule (`TransferFeeSchedule::net_amount`
computes what the taker actually receives — the settlement instruction
still moves the gross the state machine recorded, the Token-2022
program withholds the fee during the transfer, so the keeper reconciles
gross vs net), the mint decimals, and the metadata extension as a
read-only view (`TokenMetadata` exposes getters only — the settlement
layer never writes metadata). Declaring a Token-2022 extension on the
legacy SPL program fails loud (`IncompatibleTokenExtension`), as does a
fee schedule above 100% (`InvalidTransferFee`). The Anchor skeleton
needs no changes: this is purely the CPI layer.

### Token-2022 confidential transfers (AV-168)

Mints carrying the confidential-transfer extension keep per-account
balances as ElGamal ciphertexts with a *pending* and an *available*
bucket, and paying out of one is a two-step dance:
`ApplyPendingBalance` (instruction `14`) settles pending into
available, then `Withdraw` (instruction `8`, 28-byte layout: index,
`u64` amount, `u8` decimals, the 16-byte wallet-sealed
`new_decryptable_available_balance`, and the two `i8` zero-knowledge
proof instruction offsets — the proofs ride separately in the
transaction, this module pins the offsets but never fabricates
proofs) moves the settled amount out. Withdrawing without applying
first strands the pending amount on-chain, so the
`ConfidentialSettlementSequence` builder refuses to even construct
that order: withdraw-before-apply fails with
`ConfidentialPendingNotApplied`, double-apply with
`ConfidentialAlreadyApplied`. `confidential_payout_plan` wires the
sequence into the `release`/`claim` settlement plan (the fee leg
settles through the standard token leg — the fee recipient is a
plain account), with the same machine-reconciliation checks as the
plain plan. The decryptable-available-balance query is the
`ConfidentialBalanceQuery` trait, implemented by `ElgamalDecryptor`
with a caller-held secret key — the crate never sees, stores, or
transmits it. Honest scope: the ElGamal math is modeled over
compressed Edwards25519 points (same group algebra as the on-chain
Ristretto encoding, not wire-compatible), the public key is
`(s·G, s·H)` (64 bytes — the handle equation needs the secret's
multiple of the second generator), and the bounded-range discrete
log covers `[0, 2^32)` (amounts above fail
`DecryptionOutOfRange`, never silently wrapped). 17 tests;
`cargo test -p escrow-state` green.

### CPI return-data verification (AV-172)

A settlement CPI whose instruction "succeeded" may still have delivered
the wrong amount — a hostile or buggy callee. AV-172 adds the
execution-*after* gate: after the CPI runs, the callee's
`set_return_data` attestation is checked against the return layout the
settlement declared up front.

`escrow-state/src/cpi_return.rs` (pure logic, zero dependencies):
`ReturnDataExpectation { discriminant, amount_offset, expected_amount }`
declares the layout (one-byte discriminant + LE u64 amount field at
`amount_offset`); `verify_cpi_return_data(target, expectation,
observed, missing_policy)` checks, in order: return data was observed
(else the missing-data policy decides), the payload fits the on-chain
1024-byte cap, the attesting program *is* the CPI target (a return from
any other program is the confused-deputy shape), the discriminant
matches, the payload holds the amount field, and the attested amount
equals the planned amount. Amount mismatch is the explicit
`CpiError::CpiReturnDataMismatch`; missing data under the default
`FailClosed` policy is `CpiError::CpiReturnDataMissing` — a program that
attests nothing proves nothing. The `Warn` policy accepts the absence
for legacy targets that predate `set_return_data`, but records a
warning attestation: the money moved unverified. On success the
attestation rides the settlement event's `CpiRouteAudit::return_data`
(`CpiReturnDataAudit { expected_amount, attested_amount,
accepted_without_attestation }`) for the indexer.

This complements the two earlier gates rather than replacing either:
`CpiAllowlist` (AV-83) decides *who* may be called (before anything
runs), the AV-132 slippage pre-check rejects a plan whose quoted payout
is already below the caller's floor (before execution) — and this check
runs *after* execution, proving the money actually arrived. The Anchor
skeleton's `cpi_verify_return_data` documents the on-chain wiring
(`get_return_data` after the invoke; mismatch/missing map to program
errors and abort). 13 tests; `cargo test -p escrow-state` green.

## CPI-routed release (AV-35)

`escrow-state/src/cpi_call.rs` models the release path where the taker's
payout flows *through* a third-party program — a DEX swap, a lending
deposit — instead of moving straight to the taker wallet, so one release
becomes a leg of a larger composed transaction:

- **Invocation as data**: `CpiInvocation { program_id, accounts,
  data }` is the inner instruction the vault authorizes. The Anchor
  skeleton's `release_via_cpi(amount, min_payout, cpi_data)` instruction builds it
  from `remaining_accounts` (`[0]` = target program, `[1..]` its
  instruction accounts) via `cpi_invocation_from_remaining_accounts`;
  `cpi_invoke_target` is the stub where the real build performs the
  `invoke_signed` with the vault PDA as signer.
- **Same gates, then validation**: `Escrow::release_via_cpi` runs the
  exact `release` gates (authority, state, mint, milestone plan,
  quorum, timelock, amount — a CPI-routed release is a release, not a
  bypass), then validates the invocation shape (`InvalidCpiTarget`,
  code 120: zero program id, empty account list, or zero account key),
  then the AV-83 fail-closed target-program allowlist check (an
  off-list target is `InvalidCpiTarget` with full rollback when an
  allowlist is configured).
- **Atomicity**: the state machine hands the validated invocation to an
  injected executor (the seam where the Anchor layer plugs the real
  `invoke`). If the executor reports failure, the whole release rolls
  back — `released`, `fees_paid` and `state` restored — and the error
  is `CpiExecutionFailed` (code 121). On-chain a failed CPI aborts the
  transaction and no state change persists; the pure-logic model
  mirrors that atomicity. Nothing observable changes on failure: no
  event fires, no counter moves.
- **Slippage protection (AV-132)**: `release_via_cpi` takes a
  `min_payout` floor — the executor returns the *actual*
  post-execution taker-leg amount (a DEX swap's output tokens, a
  lending protocol's receipt value), and an actual below the floor
  rolls the whole release back with `SlippageExceeded` (code 195):
  same snapshot restore as `CpiExecutionFailed`, no receipt, no event.
  `min_payout == 0` disables the floor (the pre-AV-132 semantics).
  Two more layers guard the quote: `cpi::payout_plan` takes an optional
  `min_payout` and refuses to build the plan when the floor exceeds
  the quoted payout (`CpiError::SlippageExceeded` — the executor never
  runs on a quote that already violates the floor), and the keeper's
  `CpiQuote` locks the off-chain estimate at bundle-signing time
  (deriving the floor from a max-slippage bps tolerance) and asserts
  the execution against the locked quote afterwards — a deviation
  beyond the floor, or a stale quote, is rejected off-chain even when
  the chain accepted the floor.
- **Reentrancy guard (AV-36)**: the state machine arms a runtime
  reentrancy lock around the injected executor — the one point where
  untrusted code runs while a transition is mid-flight. Every
  fund-moving transition (`fund`, `release`, `release_via_cpi`,
  `release_milestone`, `claim`, `cancel`, `cancel_expired`, `resolve`,
  `close_vault`) checks the lock first, before its authority check
  (Solidity `nonReentrant`-style), and a nested entry fails with
  `ReentrantCall` (code 122) regardless of its arguments. The lock is
  cleared on both executor outcomes, so a failed executor never wedges
  the escrow; it is process-memory only — not serialized, not part of
  the vault account layout (`VAULT_FIELDS` unchanged). A blocked
  reentry emits a `ReentryRejected` indexer event (`from == to ==` the
  current state, zero amounts) — the deliberate exception to the
  "failed calls emit nothing" rule, because a hostile CPI target
  attempting to re-enter the program mid-instruction is a security
  signal the indexer must see. The Anchor skeleton documents the same
  constraint on its `ReleaseViaCpi` context: the real `invoke` runs
  under the armed lock. Covered by a deterministic seeded fuzz (32
  seeds × random escrow configs × hostile executor bursts asserting
  every reentrant call is rejected and the outer release is
  bit-identical to a benign control run).
- **Audit**: success returns `CpiReceipt { cpi_target, accounts_hash,
  payout, fee }`, where `accounts_hash` is the SHA-256 over the
  canonical invocation encoding (program id + accounts with
  signer/writable flags + data). The `Released` indexer event carries
  the same audit (`EscrowEvent.cpi`, mirrored on-chain as
  `EscrowVaultEvent.cpi_target` / `cpi_accounts_hash`), so an indexer
  re-derives the hash and confirms the release authorized exactly this
  instruction. The protocol fee still settles through the normal payout
  path — to the pinned `fee_recipient` when one is configured (AV-44),
  else to the program-level fee account — so fee accounting is identical
  with or without CPI routing.

## Account discriminators & panic-free decoding (AV-32)

`escrow-state/src/discriminator.rs` is the defensive half of reading
on-chain bytes — for indexers, keeper tooling, and anyone else parsing
vault accounts without trusting them:

- **Discriminator registry**: `PROGRAM_ACCOUNT_NAMES` is the single
  source of truth for the program side's `#[account]` types (today just
  `Vault`). Tests pin it against
  `programs/escrow-vault/src/program.rs` via `include_str!` (a new
  account type fails the build until registered) and assert global
  uniqueness: no account discriminator
  (`sha256("account:<Name>")[..8]`) collides with another account's or
  with any instruction's (`sha256("global:<name>")[..8]`) — a collision
  would let one account's bytes masquerade as another's.
- **Panic-free decoding**: `decode_vault_account` turns raw account data
  back into an `Escrow` with every read bounds-checked
  (`checked_add` + `get`), so fuzzed / mutated / truncated / overlong
  byte streams can only return `Ok` / `Err` — never trap. Check order:
  exact `VAULT_SPACE` length first (truncated and overlong both rejected,
  matching Anchor's `try_from_slice`), then the discriminator, then the
  structural field decode (bad `state` / `Option` discriminants are
  `Err`, not UB). The decode is structural like Anchor's
  `try_deserialize` — it reports what's on chain rather than
  re-litigating domain invariants.
- The crate's hand-rolled SHA-256 moved to the crate root as a shared
  `pub(crate)` primitive so this module, the AV-33 planner, and the
  test-only IDL pipeline (AV-29) all use one implementation.

## Zero-copy vault hot-field view (AV-151)

`escrow-state/src/vault_view.rs` is the performance complement to the
AV-32 decoder: for the keeper/indexer hot paths that only need a handful
of fields, the full structural decode of a 6,262-byte `Vault` account is
wasted work. `VaultView` borrows the raw account bytes and reads the hot
fields — `initializer`, `taker`, `amount` (locked principal), `released`,
`expires_at`, and the `state` discriminant — at fixed `VAULT_FIELDS`
offsets (bytes 8/40/72/80/88/96) with zero allocation and no Borsh walk.

- **Never panics**: short inputs return `VaultViewError::TooShort`,
  out-of-range reads return `VaultViewError::Truncated`, and unknown
  `state` discriminants return
  `VaultViewError::InvalidStateDiscriminant` — values, not traps.
- **Offset pinning**: the test suite derives every hot-field offset by
  accumulating `VAULT_FIELDS` lens and asserts equality with the pinned
  constants (plus absolute tripwire values), so any layout drift fails
  the build.
- **Equivalence fuzzing**: a deterministic xorshift64* fuzz (512 cases)
  randomizes every hot field on real encoded account bytes and asserts
  the view and the full `decode_vault_account` path agree on all six
  fields; a separate sweep over the whole `u8` domain asserts the
  view's `EscrowState` mapping matches the decoder's for valid (0–10)
  and invalid (11–255) discriminants alike.
- The view is intentionally discriminator-agnostic: it reads a
  `VAULT_FIELDS` payload, not necessarily a `Vault` account — callers
  that need the 8-byte account-type check keep using AV-32's decoder.
  (No performance numbers are claimed here: the design goal is avoiding
  the full decode on scan paths; the guarantee is byte-level
  equivalence, verified by the fuzz above.)

## Batch settlement execution plan (AV-33)

`escrow-state/src/execution_plan.rs` turns the keeper report (AV-20)
into executable work: `plan_execution` groups the report's actions into
**atomicity batches** keyed by `(mint, caller)` and serializes the
multisig/CLI-ready instruction list as JSON.

- **Batching**: one signing key authorizes the whole batch (single
  multisig proposal / CLI run), and the token path is uniform inside a
  batch (all native-SOL or all the same SPL mint). Across batches, vault
  account sets are disjoint by construction — a failing batch is retried
  alone and never invalidates another.
- **Instructions**: each carries the real Anchor instruction
  discriminator (`sha256("global:<name>")[..8]`, same constructor the
  IDL pipeline pins) and logical accounts as `(pubkey, role, signer,
  writable)` triples (`vault` / `authority` / `refund_to` / `mint`).
  Roles are logical on purpose — the submitter maps them to concrete
  accounts (system program, token program, ATAs); the crate never
  invents addresses it cannot derive.
- **Determinism**: batches sort by `(mint, caller)` (native-SOL first),
  instructions keep scan order, batch ids are positional — the same
  report always yields byte-identical JSON.
- **Compute-unit budget estimation (AV-88)**:
  `escrow-state/src/cu_estimate.rs` holds the single source of truth —
  a per-instruction cost table (base CU per kind + per-signature /
  per-account / per-data-byte charges; data bytes pinned against the
  IDL spec). `PlannedInstruction::estimated_compute_units`,
  `ExecutionBatch::estimated_compute_units` (bundle-level aggregation),
  and `compute_budget_warning` flag batches that cannot fit one
  transaction's 1.4M CU budget; the keeper report passes the same
  estimate through (`estimated_cu` per action, `total_estimated_cu` on
  the report). Heuristic planning numbers, not measured on-chain costs
  — calibrate against `simulateTransaction` for production sizing.

## Batch lifecycle scan (AV-37)

`escrow-state/src/batch.rs` is the proactive half of the keeper story:
where the keeper report (AV-20) covers the *reactive* exits
(`cancel_expired` / `claim`) and the execution plan (AV-33) batches
them, `scan_batch_lifecycle` covers the *proactive* lifecycle — one
scan emitting the executable `initialize → fund → release` call list
for a whole fleet of escrows.

- **Input**: a watch list where each item is either a not-yet-created
  vault (with its `initialize` parameters) or a live escrow snapshot.
  Each item gets exactly one outcome: an executable action
  (`initialize` / `fund` / full `release` of the remainder, with exact
  arguments and logical accounts), `Blocked { reason }`
  (`invalid_amount`, `awaiting_activation`, `quorum_not_satisfied`,
  `timelock_not_reached`, `milestone_plan_attached`,
  `nothing_to_release`, `disputed`), or `Done` for terminal states.
  A `release` action carries the gross `amount` plus the `payout`/`fee`
  split (`protocol_fee_for`); `initialize` carries `taker`/`expires_at`.
- **Partial-failure isolation**: the scan is pure reads — one item's
  outcome can never affect another's. A blocked item is reported inline
  with its machine-readable reason while every executable item still
  gets its action; the operator runs the executable calls, fixes the
  blocked items, and re-scans. No abort, no shared state.
- **ALT support**: the report builds `alt_table` — the deduped set of
  every non-signer account referenced by any action, in first-seen
  order, capped at 256 (the on-chain Address Lookup Table limit).
  Signers are excluded by construction (they can never live in a
  lookup table). Each account carries `alt_index` into the table (or
  `None`), so the operator creates/extends the ALT once and references
  accounts by index in every transaction — the standard fleet pattern
  for batch `initialize` runs where dozens of vault PDAs would
  otherwise bloat every transaction.
- **Dry-run**: like the keeper report — no events, no clock, no
  mutation. Amounts are as of the scan; execute, then re-scan.

## Vault PDA derivation (AV-92)

Every vault account is a Solana program-derived address (PDA). The
canonical derivation, hand-rolled in `escrow-state/src/pda.rs` (zero
dependencies — the crate never gains one):

```
address = sha256(seeds.. ++ [bump] ++ program_id ++ "ProgramDerivedAddress")
```

- **Seeds / bump / domain**: seeds are concatenated in order, then the
  bump byte travels as the *last* seed, then the 32-byte program id,
  then the literal domain separator `"ProgramDerivedAddress"` —
  byte-for-byte Solana's `create_program_address` layout (the crate's
  hand-written SHA-256 is pinned by the Anchor discriminator vectors,
  and a test re-derives the layout independently so any drift fails
  loudly). The reference seed convention is `[b"escrow-vault",
  initializer]` (see the `Initialize` accounts struct in
  `programs/escrow-vault/src/program.rs` and the AV-173 seed-domain
  registry below); each seed is ≤ 32 bytes,
  at most 16 seeds — violations are `InvalidVaultSeeds` (code 149).
- **Bump search**: `find_vault_bump` scans bumps 255 → 0 and returns
  the first whose derived address is *off* the ed25519 curve
  (Solana's `find_program_address` semantics). The off-curve check is
  hand-written Edwards decompression over hand-rolled field
  arithmetic (`p = 2²⁵⁵ − 19`): `y < p` gate, then `x² = (y²−1) /
  (d·y²+1)` with the `p ≡ 5 (mod 8)` square root, re-verified against
  the curve equation. `find_program_address` returns
  `(address, bump)`; the old multisig "caller runs its own
  `find_program_address`" convention (AV-84) now resolves to this
  unified tool.
- **Seeds live off-chain**: real Solana PDAs never store their seeds
  on-chain, and the vault layout is rent-critical (`VAULT_FIELDS` is
  the single source of truth) — so seeds are recorded on the watch
  structs, never in `Escrow`: `WatchedEscrow::with_vault_seeds(seeds,
  program_id)`, `BatchWatchItem::with_vault_seeds`, and
  `CloseWatchItem::with_vault_seeds` (all validate; all `Copy`).
- **`vault_address` in reports**: where seeds are recorded, the
  reports attach the precomputed vault PDA as `vault_address`
  (64-char lowercase hex in JSON, `null` otherwise) — on
  `KeeperAction`, on `BatchLifecycleAction` (for `initialize` this is
  the address the vault *will* have — the fleet bring-up
  cross-check), and on every `CloseVaultsReport` entry (the indexed
  close variant carries the recorded vault PDA directly).

### Application seed-domain registry (AV-173)

`"ProgramDerivedAddress"` stops cross-*program* PDA collisions; it says
nothing about collisions *within* this program — a vault PDA and a
config PDA are both valid PDAs, and tooling that parses "the PDA for X"
from a bare seed list could silently confuse the two.
`escrow-state/src/seed_domain.rs` adds the application layer: every PDA
the program owns lives in exactly one `SeedDomain`
(`Vault`/`Config`/`State`/`Nonce`/`Keeper`), the domain's canonical
prefix (`b"escrow-vault"`, `b"escrow-config"`, `b"escrow-state"`,
`b"escrow-nonce"`, `b"escrow-keeper"`) is the *first* seed of every
derivation in that domain, and the prefix table is the single source of
truth (no prefix is a prefix of another — pinned by test, so a seed
list parses into at most one domain).

Canonical derivation paths (`derive_domain_address`,
`derive_vault_pda`, `derive_config_pda`) prepend the prefix themselves,
so the first seed is a registered prefix by construction, not by caller
discipline; `classify_seeds` explicitly rejects any raw seed list whose
first seed is not registered — unregistered domains and bare ad-hoc
seeds (like the pre-AV-173 `b"vault"` convention) fail with
`InvalidVaultSeeds` instead of deriving a lookalike address. Same
suffix seeds under different domains always derive different addresses
(test-pinned), so a vault PDA can never be parsed as a config PDA. The
Anchor skeleton's `seeds = [...]` constraints align to the canonical
prefixes. 13 tests; `cargo test -p escrow-state` green.

## Keeper execution bundles (AV-61)

`escrow-state/src/execution_bundle.rs` is the last off-chain step
before submission: it packs the batch scan's (AV-37) flat call list
into per-signing-session **execution bundles** a multisig or CLI can
consume directly.

- **Grouping key**: `(mint, caller)` — the AV-33 convention. One
  signing key authorizes the whole bundle (one multisig proposal, one
  CLI run with one keypair), and the token path is uniform inside it
  (all native-SOL or all the same SPL mint). Bundles are ordered
  deterministically — native-SOL first, then by mint, then by caller —
  and actions keep the report's scan order inside a bundle.
- **Real discriminators**: every action carries the Anchor
  instruction discriminator (`sha256("global:<name>")[..8]`) computed
  by the same constructor the IDL pipeline pins. The program-side IDL
  names are authoritative: `Initialize → "initialize"`,
  `Fund → "fund"`, `Release → "release"` (checked at implementation —
  no drift between the batch kinds and the IDL instruction names).
- **JSON shape**: each bundle is self-contained —
  `{"bundle_id","mint","caller","caller_role","actions","jito_tip","action_count",
  "alt_table","at","scanned","estimated_priority_fee"}`. Actions carry `escrow_id`,
  `instruction`, `discriminator` (16-char hex), `args` (per-kind:
  `initialize` → `taker`/`amount`/`expires_at`; `fund` → `amount`
  only, since the program takes no instruction args; `release` →
  `amount` plus the expected `payout`/`fee` split), `accounts` with
  `signer`/`writable` flags and `alt_index`, and `reason`. The bundle
  embeds the scan's `alt_table` verbatim, so one ALT creation covers
  every transaction.
- **Failure isolation**: vault sets are disjoint across bundles — a
  failing bundle is retried alone, the others stand. Dry-run by
  construction: the bundler only reads the report.
- **Opt-in Jito tip (AV-98)**: `ExecutionBundle::with_jito_tip(lamports,
  recipient)` stamps a tip onto the bundle for Jito bundle submission.
  The tip instruction is built with the AV-31 `system_transfer` byte
  constructor (`caller → recipient`, 12-byte transfer encoding) and
  renders in the JSON after the `actions` array — `"jito_tip":
  {"lamports":N,"recipient":"…","instruction":{"program_id":"…",
  "accounts":[…],"data":"…"}}` (`null` when unstamped). Jito
  convention: the tip instruction goes **last** in the transaction, after
  every escrow instruction, so a partially executed transaction never pays
  the tip without doing the work. Range-checked: zero amount, zero
  recipient, zero payer, or recipient == caller all return
  `TipConfigError` and leave the bundle untouched. The tip is bundle
  overhead, not an escrow action — `action_count` excludes it — and it is
  paid by the bundle's signing caller (the operator), never from escrowed
  funds. The keeper report annotates the intended tip amount + recipient
  (`KeeperReport::with_jito_tip`) so the dry-run preview shows the tip
  line before any instruction is built.
- **Relation to AV-33**: the same idea as the batch settlement
  execution plan, applied to the proactive lifecycle line instead of
  the keeper report's reactive exits. Same grouping, same
  discriminator rule, same deterministic hand-serialized JSON.
- **Bundle simulation (AV-102)**: `simulate_bundle(bundle, watched,
  at)` dry-runs a bundle before submission — each action executes in
  bundle order on a per-escrow `IndexedEscrow` clone seeded from the
  keeper's snapshots (`IndexedEscrow::wrap` converts plain `Escrow`
  snapshots; `initialize` actions create a fresh vault and need no
  snapshot). The caller's snapshots are never mutated and no events
  leak (AV-76 atomicity convention: everything happens on the clone).
  Each `SimulatedAction` predicts the post-state, `released`,
  `payout`/`fee`, and the events the action would emit; the first
  gate rejection stops the simulation with the exact `EscrowError`
  and its stable numeric code, and later actions are marked
  `skipped` (`bundle_aborted`) — a real submission would abort the
  whole transaction there. `BundleSimulation::to_json()` renders the
  keeper's dry-run report (`all_ok` green light, per-action
  `executed`/`failed`/`skipped` with `error:{name,code}`).

## Private bundle-relay submission (AV-169)

Submitting a keeper execution bundle to the public mempool
broadcasts the settlement intent to every watcher — including MEV
searchers. `escrow-state/src/bundle_relay.rs` submits the bundle to
a **private block-engine relay** (e.g. Jito) instead. The
`BundleRelay` trait models the relay as an injectable dependency
(`submit` / `status`); `BundleRelaySubmitter` orchestrates:

- **Tip bidding**: the AV-98 `JitoTipConfig` rides the submission —
  the tip instruction is already the bundle's last instruction, and
  the config tells the relay what the bundle bids for auction
  ordering.
- **Replay protection**: submissions key on the `BundleId`
  (SHA-256 of the bundle bytes). Resubmitting a pending bundle
  returns the cached receipt without touching the relay again;
  resubmitting an already-landed bundle fails with
  `RelayError::AlreadyLanded` — a landed bundle is never
  resubmitted, so no duplicate on-chain execution. A bundle the
  relay reports failed is dropped from tracking, so the operator can
  retry it deliberately.
- **No mempool fallback, by construction**: when the relay is
  unavailable the submission fails with `RelayError::Unavailable`
  and the adapter has no mempool handle, flag, or fallback branch —
  a silent fallback would broadcast the exact intent the private
  relay was chosen to protect. An operator-approved fallback, if
  ever wanted, lives outside the adapter where the decision is
  visible.
- **Landing observations as audit events**: each status poll that
  resolves a bundle yields a `RelayObservation` (landed/failed, the
  landing slot, `landed_slot − submitted_slot` confirmation
  latency) rendered as hand-written JSON for the keeper's audit
  sink, next to the AV-18 indexer events. `RelayStats` tracks the
  landing rate in basis points and the mean confirmation latency —
  the two numbers the operator watches. 12 tests;
  `cargo test -p escrow-state` green.

## Release preview (AV-159)

`Escrow::preview_release(authority, now, amount, mint, payout_to)`
is the keeper's pre-execution sizing tool: it runs the exact
`release` guard chain and settlement math on a discarded shadow
clone and returns the `{payout, fee, refund}` split the real call
would produce — zero state change, zero events.

```rust
let preview = escrow.preview_release(ALICE, now, amount, None, BOB)?;
println!("payout: {}, fee: {}, refund: {}", preview.payout, preview.fee, preview.refund);
assert_eq!(preview.payout + preview.fee + preview.refund, escrow.lockup_total());
```

Use it before assembling `release` / `claim` /
`release_milestone` / CPI calls to size transfers, validate that a
planned amount passes every gate (authority → state → mint
allowlist → quorum → timelock → amount), and confirm the fee split —
without touching the escrow. This complements
`cpi::payout_plan` (post-hoc consistency validation):
`preview_release` is for pre-execution measurement,
`payout_plan` for post-execution verification.

## Signable transaction messages (AV-71)

`escrow-state/src/tx_message.rs` is the last mile after the AV-61
bundle JSON: for each bundled action it builds the **real instruction
bytes** and assembles a Solana legacy transaction message, emitted as
base64 for a multisig or CLI to sign and submit.

- **Real instruction data**: `discriminator || Borsh params` per the
  IDL spec — `initialize` → `amount:u64 || expires_at:u64` (24 bytes),
  `fund` → discriminator only (the spec's `params: []`), `release` →
  `amount:u64` (16 bytes). The discriminator is recomputed from the
  action's IDL instruction name with the same constructor the IDL
  pipeline pins, and the builder *refuses* when it disagrees with the
  bundle's stamped discriminator (`DiscriminatorMismatch`) — a renamed
  instruction or stale bundle fails loudly instead of producing signable
  bytes for the wrong entrypoint. The taker is a program *account*, not
  a param, so it is not in the data.
- **Real message bytes**: canonical legacy wire format — 3-byte header,
  compact-u16-prefixed account keys in canonical order (writable
  signers, readonly signers, writable non-signers, readonly non-signers;
  duplicates merge flags), the 32-byte recent blockhash, and
  compact-u16-prefixed compiled instructions — then base64-encoded with
  a hand-rolled codec (the crate stays dependency-free). One action
  becomes one single-instruction message; decode rejects truncated
  input, trailing bytes, and out-of-range account indexes.
- **Off-chain and unsigned by design**: the relay never holds keys —
  the output is the *to-be-signed* message. The program id and the
  recent blockhash are caller-supplied (the skeleton's `declare_id!`
  string is not valid base58 and is never decoded off-chain; the keeper
  fetches a fresh blockhash from the cluster).
- **Account completion is the submitter's job**: the message carries
  exactly the bundle's logical accounts (`vault`/`initializer`/`mint`).
  `fund` is complete as-is; for `initialize` the submitter appends the
  remaining program-declared accounts (`taker` — the key is in the
  bundle's `args` — and the system program), and for `release` it
  appends `taker`, `payout_to`, the clock sysvar, and the vault token
  account on the SPL path. The instruction *data* needs nothing added.
- **v0 messages with address-table lookups (AV-87)**:
  `compile_action_message_v0` / `signable_message_v0_base64` /
  `bundle_action_message_v0_base64` resolve ALT-eligible accounts
  (the bundle's stamped `alt_index`) statically against the caller's
  snapshot of the on-chain table: signers stay static (the runtime
  forbids signer lookups), everything else shrinks the static key
  list — a large-account-set bundle ships fewer static keys per
  message. Wire bytes are the legacy layout prefixed with the `0x80`
  version byte plus the lookup list; a stale snapshot (index out of
  range, key mismatch) fails the build instead of signing against the
  wrong table, and decode rejects malformed lookup entries. The legacy
  path is byte-identical with or without the v0 code present.
- **Packet-size pre-flight + keeper auto-route (AV-162)**:
  `MAX_TRANSACTION_PACKET_BYTES` (1232 — a serialized Solana transaction
  must fit one IPv6 MTU-sized UDP packet), `wire_size_legacy` /
  `wire_size_v0`, and `ensure_fits_packet_limit` let the keeper check a
  to-be-signed message *before* handing it to a signer — the cluster
  rejects an oversized message only after signing, so an unchecked
  multi-account CPI-path message burns a signature round-trip. The demo
  case is pinned in the tests: a 60-account CPI-path message is 2094
  bytes in legacy form (rejected) and 269 bytes in v0 (accepted).
  `signable_bundle_action_message_base64` is the keeper one-call route:
  it picks v0 automatically when the bundle stamps ALT-eligible
  accounts and the caller supplies the on-chain table's key, falls back
  to legacy when no account is ALT-eligible, and fails loud with
  `AltTableNotFound` when the bundle promises a table the keeper did
  not provide — instead of silently bloating past the limit on the
  legacy path.
- **Pinning**: the tests assert the data bytes against the
  `INSTRUCTIONS` spec table (param name/type/order per kind), the
  account metas 1:1 against the bundle's logical accounts, the wire
  bytes against a golden vector, base64 against RFC 4648 vectors, and
  bundle-JSON ↔ message agreement end to end.

### Address lookup table account parsing (AV-181)

`escrow-state/src/alt_table.rs` is the parsing half of the AV-87 v0
path: it turns the raw account-data bytes the keeper fetched from RPC
into the address snapshot the v0 compiler takes.

- **Real on-chain layout**: `ProgramState` variant index (`u32` LE;
  `0` = uninitialized, rejected) + bincode `LookupTableMeta`
  (`deactivation_slot` / `last_extended_slot` / `start_index` /
  `authority: Option<Pubkey>` + `u16` padding = 56 bytes,
  `LOOKUP_TABLE_META_SIZE`) + raw 32-byte addresses with no length
  prefix — pinned against the `solana-program` 2.0.23
  `address_lookup_table::state` source, including its
  `test_lookup_table_meta_size` vectors (56 bytes with an authority,
  24 + zero-fill without).
- **Fail loud**: short data, uninitialized/unknown program state, bad
  authority tag, misaligned address tail, over-full tables (> 256
  addresses), and *empty* tables (a 56-byte account is valid on-chain
  but resolves nothing) all return `AltTableError` — never a table
  that silently resolves nothing.
- **Lookup expansion**: `resolve_v0_lookups` expands a decoded v0
  message's `address_table_lookups` back into loaded addresses
  (writable first, then readonly — the runtime's ordering), failing on
  unknown table keys or out-of-range indexes, so an auditor can verify
  exactly what a signed message will load.
- **One-call compile**: `compile_v0_from_account_data` goes from RPC
  account bytes straight to a compiled v0 message; parse failures and
  stale snapshots (`AltTableKeyMismatch`) both fail before any bytes
  are signed.
- **Honest activation check**: on-chain, a finite `deactivation_slot`
  stays usable through a slot-hash cool-down that needs the
  `SlotHashes` sysvar; off-chain `is_active()` only reports fully
  active (`deactivation_slot == u64::MAX`) — the keeper should only
  feed active tables here.

### Memo program audit trail (AV-182)

`escrow-state/src/memo.rs` attaches an on-chain audit note to a
lifecycle transition's transaction via the SPL Memo program
(`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`) — anyone can read the
note from an explorer next to the program instruction.

- **Real program behavior**: instruction data is the raw UTF-8 note
  bytes (no discriminator); the program validates UTF-8 and enforces
  no length cap itself (the runtime's instruction-data/packet limits
  still apply). `MemoConfig.max_bytes` (default 256) is our policy
  knob, not a chain rule. Zero accounts attached — the memo rides the
  transaction's existing signers.
- **Canonical note**: `transition_memo_note` is a pure function of
  (transition, escrow_id, amount) —
  `escrow-vault:<transition>:escrow=<64 hex>:amount=<u64>` — covering
  `fund` / `release` / `cancel` / `resolve` / `claim`.
- **Audit event agreement**: `IndexedEscrow::with_memo_config` opts in;
  the five transition emitters stamp the same note on
  `EscrowEvent.memo`, so the on-chain log and the off-chain event
  agree by construction. The event never invents a note — `None` when
  disabled.
- **Opt-in, zero default-size impact**: a disabled config builds no
  instruction and leaves compiled messages byte-identical (tested);
  an empty note or an over-cap note fails loud (`EmptyNote` /
  `TooLong`) instead of silently truncating the audit trail.

### Durable-nonce transactions (AV-167)

`escrow-state/src/durable_nonce.rs` frees keeper bundles from the
~150-slot recent-blockhash expiry: a **durable nonce** account's stored
blockhash plays the blockhash role, so a bundle signed offline now
stays submittable until the nonce account is advanced.

- **Nonce-account parsing**: `parse_nonce_account(address, data)`
  decodes the 80-byte layout (`u32` version \|\| `u32` state \|\|
  authority \|\| stored blockhash \|\| `u64` lamports-per-signature);
  uninitialized accounts and unknown version/state discriminants fail
  loud (`UninitializedNonce` / `InvalidVersion`).
- **Advance instruction**: `advance_nonce_instruction` builds the
  System Program `AdvanceNonceAccount` (index `4`, 4-byte data) with
  the nonce account (writable), the recent-blockhashes sysvar, and the
  nonce authority (signer) — spending someone else's nonce is refused
  at build time (`AuthorityMismatch`).
- **Message assembly**: `compile_message_with_nonce` (legacy) and
  `compile_action_message_v0_with_nonce` (ALT v0, AV-87) put the
  advance instruction first and the nonce value in the blockhash slot;
  `signable_action_message_with_nonce_base64` /
  `signable_action_message_v0_with_nonce_base64` emit the
  offline-signing artifact. The nonce authority is a signer of the
  whole transaction; prefix accounts never resolve through lookup
  tables.
- **Submit-time freshness**: `DurableNonceSession::check_fresh`
  re-parses the account before submission and refuses a moved nonce
  (`NonceChanged`) or a changed authority (`AuthorityMismatch`) —
  submitting against an advanced nonce would burn the signature
  round-trip on a blockhash the runtime rejects.

## Priority-fee oracle (AV-89)

`escrow-state/src/priority_fee.rs` closes the cost loop the AV-88 CU
estimate opened: the keeper now gets a **recommended priority fee in
micro-lamports per compute unit**, estimated from the recent
prioritization-fee samples it feeds in (e.g. from the cluster's
`getRecentPrioritizationFees` RPC).

- **EWMA estimator, configurable**: `PriorityFeeOracle` smooths samples
  with `ewmaₙ = α·xₙ + (1−α)·ewmaₙ₋₁` — O(1) state, no sample buffer.
  `window` (minimum trusted samples) and `alpha` (decay /
  responsiveness) are operator-tunable via `PriorityFeeConfig`
  (validated: `window ≥ 1`, `α ∈ (0, 1]`); defaults are starting
  points, not production tuning.
- **Recommendation + confidence**: `recommend()` returns
  `⌈ewma⌉` (rounded *up*, so the suggestion never sits below the
  estimated mean) with `confidence: High` once `samples ≥ window`.
  Below the window it emits the configured conservative fixed value
  with `confidence: Low` and `fallback: true` — downstream can never
  mistake a fallback for a measurement.
- **Compute-budget passthrough** (`tx_message.rs`):
  `compute_budget_set_compute_unit_limit` (`0x02 || units:u32 LE`) and
  `compute_budget_set_compute_unit_price` (`0x03 || micro_lamports:u64
  LE`) hand-serialize the Solana compute-budget program's Borsh-enum
  layout, byte-exact and pinned by tests. The program id stays
  caller-supplied (same convention as the program instructions); the
  keeper feeds the AV-88 CU estimate into the limit and the oracle
  recommendation into the price, ahead of the program instructions in
  the message.
- **Bundle dry-run passthrough**: `ExecutionBundle::with_priority_fee`
  stamps the oracle's recommendation onto the bundle; the dry-run JSON
  carries it as `"estimated_priority_fee":
  {"micro_lamports_per_cu":N,"confidence":"high","fallback":false}`
  (or `null` when unstamped) — the fee line paired with the AV-88 CU
  passthrough.
- **Full fee budget**: `fee_budget_lamports(estimated_cu,
  micro_lamports_per_cu)` combines the AV-88 estimate with the
  recommendation — `⌈cu × micro / 1_000_000⌉` lamports, u128
  intermediate (no overflow), saturating.
- **Honest limitations**: the oracle estimates the *mean recent price*,
  not inclusion probability — a `High`-confidence recommendation can
  still stall in a sudden congestion spike. Fetching and cleaning the
  fee feed (polling cadence, slot window, outlier filtering) is keeper
  wiring outside this crate, and the defaults must be calibrated
  against the operator's own feed before sizing real transactions.

## Payout destination allowlist (AV-49)

A taker payout is only as safe as its destination. `release`, `claim`,
`resolve`, `release_milestone`, and `release_via_cpi` all take an explicit
`payout_to` destination, and the state machine enforces a payout policy on
it: without an allowlist the destination must be the taker (backward
compatible); with one configured via `with_payout_allowlist` (1–4 live
addresses, set at initialize time) or `update_payout_allowlist` (dual-sig
governance once funded), the destination must be a member —
`PayoutNotAllowlisted` (code 127) otherwise. The anti-phishing rationale:
a compromised frontend cannot redirect a payout to an attacker address
when the escrow pins its destinations on-chain. The settlement-plan
builders (`cpi::payout_plan` / `resolve_plan`) enforce the same policy on
the native-SOL leg, so an allowlisted destination does not trip
`RecipientMismatch`. AV-93's `release_split` checks *every* recipient
against the same policy (in table order): with no allowlist configured
only the taker passes, so a multi-recipient split is the allowlist's
declared distribution set. The 130-byte region is always reserved in the vault
layout (1-byte discriminant + 4×32-byte addresses + 1-byte count), so the
opt-in writes in place without reallocating.

## CPI target-program allowlist (AV-83)

A payout *path* is as attackable as its destination. `release_via_cpi`
invokes an arbitrary third-party program, so a compromised frontend could
steer the release through a hostile program even when the *destination* is
pinned by AV-49. The CPI allowlist closes that hole: configured via
`with_cpi_allowlist` (1–8 program ids, set at initialize time) or
`update_cpi_allowlist` once funded, it restricts `release_via_cpi` to the
listed target programs. The check is fail-closed — it runs after shape
validation and before the invocation, and an off-list target is rejected
with `InvalidCpiTarget` (code 120) with full rollback, exactly as if the
invoke had failed. Unlike the payout allowlist, updates are *always*
dual-signed (both parties even on a plain escrow): the allowlist guards a
privileged execution path, so it carries the strictest governance in the
vault. An empty update clears the list (back to any-target-allowed), and
`CpiAllowlistUpdated` (event kind 43) is emitted only on an actual change.
The 258-byte region is always reserved in the vault layout (1-byte count +
8×32-byte program ids), so the opt-in writes in place without reallocating.

## Payout destination denylist (AV-96)

The allowlist says where funds *may* go; the denylist says where they
*may not* — the initializer's compliance veto. Configured via
`with_denylist` (1–4 live addresses, set at initialize time) or
`update_payout_denylist` once funded, it is checked **before** the
allowlist on every payout path (`release`, `release_split`, `claim`,
`resolve`, the basket settlement): a denied destination fails with
`PayoutDenied` (code 153) even when it is also allowlisted — deny
beats allow, deliberately, so a sanctions hit cannot be smuggled
through the allowlist. Governance is the initializer's signature
alone (unlike `update_payout_allowlist`'s dual-signature reshape):
the veto must be raisable while funds are locked, so updates are
valid on `Uninitialized` / `Funded` but never from a terminal state,
and a paused escrow fails fast (`Paused`). An empty update clears
the veto (back to `None`); `DenylistUpdated` (event kind 51,
`payout_denylist_updated`) is emitted only on an actual change. The
130-byte region is always reserved in the vault layout (1-byte
discriminant + 4×32-byte addresses + 1-byte count, zeroed when
`None`), so the opt-in writes in place without reallocating.

## Dutch auction settlement (AV-97)

The vesting curve pays *more* over time; the Dutch auction pays
*less* — the taker's incentive is to settle early, before the price
decays. An auction escrow is configured via
`with_dutch_auction(start_at, end_at, reserve_bps)` (or the
`initialize_dutch_auction` instruction), `Uninitialized` only:
`start_at < end_at` is the descending-price window in Unix seconds
and `reserve_bps` (0–10_000) the initializer's guaranteed keep at
the window's end — `InvalidAuctionParams` (code 155) on
`start_at >= end_at` (a zero-length window would divide by zero in
the descending math) or a floor above 10_000. Once funded, the
taker's `claim` inside `[start_at, end_at]` settles at the
descending cap `max(amount * (end_at - now) / (end_at - start_at),
amount * reserve_bps / 10_000)`, computed in `u128` so it cannot
overflow: the full `amount` at `start_at`, sliding linearly down to
the `reserve_bps` floor at `end_at`. `claim` outside the window
fails with `AuctionNotActive` (code 156), and the initializer
reclaims whatever the taker left via `cancel` / `cancel_partial`.
The auction and the AV-13/AV-90 unlock paths are mutually
exclusive (last-wins on the builder), and `escalate` is refused
with `AuctionNotActive` while the window is live — price discovery
and arbitration are mutually exclusive settlement paths (design
comment on `Escrow::escalate`). The gross lands in the same
`released` counter as every other pull path (the AV-11
conservation convention), the protocol fee slices the gross, and
the 19-byte region is always reserved in the vault layout (1-byte
discriminant + 18-byte terms, zeroed when `None`), so the opt-in
writes in place without reallocating.

## Token-2022 transfer hooks (AV-99)

SPL Token-2022 mints can carry a transfer hook — a program that
runs on every transfer. An escrow over such a mint declares the
hook program via `with_transfer_hook(program_id)` (or the
`initialize_transfer_hook` instruction), `Uninitialized` only and
only *after* `with_mint` bound the mint: a hook is a Token-2022
concept, meaningless on the native-SOL path, so declaring one with
no mint bound — or with the zero program id — is
`InvalidTransferHook` (code 157, pinned, never renumbered). The
33-byte region is always reserved in the vault layout (1-byte
discriminant + 32-byte program id, zeroed when `None`), so the
binding writes in place without reallocating, and every earlier
field keeps its offset. The pure-Rust settlement plans
(`cpi::payout_plan` / `refund_plan` / `resolve_plan`) then gate on
the binding: the caller's hook context must name exactly the
declared program (`SettlementMismatch` on any mismatch — declared
but unnamed, unnamed but claimed, or a different program), and the
plan annotates the hook program plus its extra accounts so the
CPI builder can append them to the transfer instruction. The plans
never assert on-chain hook execution — only that the declared
binding and the plan agree. Indexers see the binding in the state
snapshot (`"transfer_hook"` as 64-char hex or `null`).

## Streaming fee on funded time (AV-100)

A flat bps fee prices the *size* of a payout; the streaming fee
prices *time* — compensation for capital locked while the deal
sits funded. An escrow opts in via
`with_streaming_fee(rate)` (or the `initialize_streaming_fee`
instruction), `Uninitialized` only: `rate` is lamports (or
base-token units) per second of funded time, and any u64 is legal
(`0`, the default, disables the fee — like `fee_bps` — so no new
error code exists; the u128 accrual math cannot overflow).
Accrual starts at `fund_at` and runs only while the escrow is
`Funded`: a dispute freezes the clock at `disputed_at`, so the
taker never pays for arbitration time. Every taker payout
(`release` / `release_split` / `claim` / `release_milestone` /
`release_period` / `release_basket` / the taker's share of
`resolve` / `submit_panel_judgment` / `trigger_default_judgment`)
deducts the newly accrued slice —
`rate * (accrue_upto - fund_at) - streaming_fees_accrued`
(saturating), capped at the payout's post-bps-fee remainder so the
fee never eats principal — and routes it to the fee leg. The
deduction order is fixed: the AV-17 bps fee slices the gross
first, the streaming fee slices the remainder, and the returned
`fee` folds both together (no new return shape). The charged
amount accumulates in both `streaming_fees_accrued` (the running
tab, so a later payout never re-bills time an earlier one already
billed — and on a basket escrow the tab is shared across legs)
and the unified `fees_paid` counter. Refunds (`cancel` /
`cancel_expired`) never carry the streaming fee: only
taker-received value is feeable, the AV-17 rule extended. The
16-byte region (8-byte rate + 8-byte accrued counter) is always
reserved in the vault layout, appended after the AV-99 hook
region, so the opt-in writes in place without reallocating; the
snapshot exports both fields.

## Delegated authority (AV-104)

The initializer or the taker may lend a bounded slice of their
transition rights to an operator — the Solana "approve a delegate"
pattern applied to escrow authority (e.g. a bot that funds vaults for
the initializer, or a taker-side service that cancels expired escrows,
without holding the party key). `delegate_authority(caller, delegate,
scopes)` writes the grant (`Uninitialized` / `Funded` only); the scope
bitmap is `1` = fund, `2` = release, `4` = cancel — a non-empty subset
of the mask (zero operator key, empty bitmap, or bits outside the mask
is `InvalidDelegation`, code 160). Only the two parties may grant or
revoke — a stranger is `Unauthorized`, and the operator cannot
sub-delegate; `revoke_delegation(caller)` may be called by either party
(the initializer can cut off a taker-appointed operator and vice
versa), and no live grant is `InvalidDelegation`. One grant slot: a
later grant overwrites the earlier one, and `rotate_initializer` /
`rotate_taker` clear the grant (fail-closed — the new party never
inherits the old party's operator).

The delegation check runs at the authority checkpoint, after the party
themselves: `fund` / `release` / `cancel` / `cancel_expired` now accept
"caller is the party, or caller is the live operator whose scope
covers this path" (a paused escrow still fails fast with `Paused`, and
the state/config checks run unchanged after authority). An operator
calling outside their scope is the pre-existing `Unauthorized` — no
new code. The pause (AV-46) authority is deliberately outside the
delegation surface: the emergency brake stays party-only. The grant
itself is `Some((operator, scopes))` in a 37-byte always-reserved tail
region (1-byte discriminant + 32-byte operator key + 4-byte scope
bitmap, zeroed when `None`), so grant/revoke write in place with no
realloc; the snapshot exports it as `{"operator": <hex>, "scopes": n}`
or `null`, and the `DelegationGranted` / `DelegationRevoked` events
(53/54) carry from == to == the current state. Coverage is explicit:
only the four core paths (`fund`, `release`, `cancel`,
`cancel_expired`) honor the operator — milestone/subscription/claim
payout paths, dispute and arbitration governance, and the basket
settlements stay party-only. IDL: `delegate_authority(delegate:
Pubkey, scopes: u32)` and `revoke_delegation()` with discriminators
`sha256("global:delegate_authority")[..8]` /
`sha256("global:revoke_delegation")[..8]`; the Anchor `Vault` gains
`delegation: Option<Delegation>`, and `ErrorCode::InvalidDelegation`
maps code 160.

## Atomic swap (AV-105)

Two escrows linked as a swap pair: leg A is X→Y, leg B is Y→X.
`link_swap(a, b, caller, escrow_id_a, escrow_id_b, amount_a,
amount_b)` links the pair — both vaults must be `Uninitialized`
(`InvalidStateTransition` otherwise); the parties must be *mirrored*
(`a.initializer == b.taker && a.taker == b.initializer`, else
`InvalidSwapParties`, code 161 — a zero or duplicate counterparty id
is the same code); the asserted amounts must equal each leg's locked
amount (`InvalidSwapAmounts`, code 162); a double link is
`SwapLinkActive` (code 163). Only one of the two parties may link —
an AV-104 operator is `Unauthorized` (the delegation slot is never
consulted, and pair ops deliberately sit outside the four
operator-honoring core paths). The check order is pause → caller
(party-only) → state → link → params.

Pair settlement is atomic by construction: `release_swap` /
`cancel_swap` / `cancel_swap_expired` run the two legs' checks on
copies with the links stripped *before* touching either original —
any failure (a leg's timelock not reached, one leg not expiry-eligible,
a broken cross-link) returns the single-side error and both escrows
are byte-identical to before the call, so no partial settlement is
ever observable. The event layer mirrors the atomicity: the
`IndexedEscrow` pair wrappers emit nothing on failure, and on success
emit in deterministic A→B order (`SwapLinked`, then per-leg
`Released` / `Cancelled` / `ExpiredCancelled`). Each leg runs under
*its own* initializer's authority (release) or per-leg initializer /
caller authority (cancel / cancel_expired — the AV-24 penalty keys
per leg exactly as the single-side path charges it); the on-chain
instruction requires *both* parties as signers. The link is stored on
both sides as the counterparty's 32-byte escrow id in a 33-byte
always-reserved tail region (zeroed when unlinked), and there is no
unlink: the link persists through the terminal states as the audit
trail. The enforcement applies only to non-terminal states — once
both legs are `Released` / `Cancelled`, the surviving link is inert
(`is_terminal` covers `Released`, `Cancelled`, `Settled`, `Split`, and
`Closed`).

The single-side refusal: every fund-moving single-side transition
refuses with `SwapLinkActive` (code 163) while the escrow is live-linked
and non-terminal — `release`, `release_via_cpi`, `release_split`,
`release_milestone`, `release_period`, `release_basket`,
`release_basket_all`, `cancel`, `cancel_partial`, `cancel_expired`
(and the `crank_expired` sweep, which runs the same locked path),
`cancel_basket`, `cancel_basket_all`, `cancel_expired_basket`, `claim`,
`slash`, `resolve`, `trigger_default_judgment`, `split_escrow`. The
refusal is checked right after the state check, so a paused escrow
still reports `Paused` (code 124) first. Deliberately exempt:
`fund` (the link is established pre-fund), `close_vault`,
pause/unpause, delegation, and the key rotations — none of them move
funds along the settlement path the link guards.

`cancel_swap_expired` is all-or-nothing by expiry too: *both* legs
must be expiry-eligible or the whole call refuses with `NotExpired`
— no partial expiry. The event kind `SwapLinked` is 55; the IDL
instructions are `link_swap(escrow_id_a, escrow_id_b, amount_a,
amount_b)`, `release_swap(escrow_id_a, escrow_id_b, amount_a,
amount_b)` → `(payout_a, fee_a, payout_b, fee_b)`,
`cancel_swap(escrow_id_a, escrow_id_b)`, and
`cancel_swap_expired(escrow_id_a, escrow_id_b)` → `(refund_a,
penalty_a, refund_b, penalty_b)`, each with discriminator
`sha256("global:<name>")[..8]`; the Anchor `Vault` gains
`swap_link: Option<[u8; 32]>`, and
`ErrorCode::InvalidSwapParties` / `InvalidSwapAmounts` /
`SwapLinkActive` map codes 161/162/163. Account layout grows by the
33-byte region: body 4607 → **4640**, `VAULT_SPACE` 4615 → **4648**,
`VAULT_SPACE_NO_QUORUM` 4125 → **4158**, rent-exempt 33,011,280 →
**33,240,960** lamports.

## Penalty insurance pool (AV-106)

The problem: a slash pays the penalty to the initializer, and a
rejected appeal forfeits the taker's bond to the initializer — so the
initializer *profits* from declaring the taker in default, even
wrongfully. The penalty is supposed to price non-performance, not to
be a revenue line for the party that unilaterally triggers it.

The pool fixes the incentive, opt-in via `with_insurance_pool()`
(`Uninitialized`-only; the default stays the pre-AV-106
slash-to-initializer behavior). Slashed penalties and forfeited
appeal bonds accrue in a neutral per-escrow pool instead of flowing
to the initializer. The pool is neutral custody — neither party can
touch it alone. The only outflow is `pool_payout(authority,
beneficiary, amount, mint, now)`, authorized by the arbiter (the
AV-14 neutral role) or the bound multisig authority PDA (AV-84 —
the PDA signs only after its threshold voted, so the escrow stays
zero-trust and never interprets the threshold itself).

Five persisted counters (all zero unless opted in): `insurance_pool`
(the flag), `pool_paid` (the balance — credits on slash/forfeit,
debits on payout and overturn restitution), `pool_slashed` (the slash
principal held in the pool, driving `remaining_amount =
amount - released - penalty_paid - pool_slashed` so the releasable
lockup excludes pooled principal), `pool_inflow` (cumulative
credits, never debited — the keeper's inflow line), and
`pool_payout_paid` (cumulative authorized payouts, never debited).

The accounting rule that matters: a payout debits *only* `pool_paid`
and accumulates `pool_payout_paid` — it never reduces `pool_slashed`.
The slashed principal left the releasable lockup when the slash
landed; paying it out of the pool must not grow the lockup back
(that would double-count the same funds in `remaining_amount` and
let the taker release money that already left the vault). Only an
overturned appeal reverses `pool_slashed`, and that returns principal
to the lockup through `released` (the AV-86 precedent). The
conservation identity becomes `inflow == locked + released +
refunded + penalty_paid + appeal_bond_paid + pool_paid +
pool_payout_paid` — one term per sink — and the pool tests assert it
across slash → forfeit → partial payout lifecycles.

Gates on `pool_payout`: the escrow must be `Funded`, the pool
opted-in and non-empty, the amount non-zero and within the balance,
the beneficiary through the AV-49/AV-96 recipient gate, the mint
through the AV-16 binding (`MintMismatch` otherwise), and the pool
unencumbered — no filed appeal, no appealable pooled slash
(`InvalidPoolPayout` otherwise; the pool must stay able to make the
taker whole while an appeal is live). A non-empty pool blocks
`close_vault` (`InvalidPoolPayout`) — closing would hand the
neutralized penalties to the initializer with the rent reclaim,
resurrecting the exact incentive the pool removes; drain via
`pool_payout` first. A pool with no arbiter and no multisig binding
can never pay out: pair `with_insurance_pool` with `with_arbiter` or
`with_multisig_authority`. Overturn restitution is not booked in
`pool_payout_paid` — it rides `released` like every other taker
payout — so the keeper's outflow line is `pool_inflow - pool_paid`.

The keeper report carries the pool lines (`pool_balance`,
`pool_inflow`, `pool_outflow`) and lists a `PoolPayout` action per
authorized drainer (arbiter + bound multisig PDA) once eligible; the
CU table prices `pool_payout` at 18,000 base CU (8 + 32 + 8 = 48 data
bytes: discriminator + beneficiary + amount), and the state snapshot
exports all five counters. Account layout grows by the 33-byte pool
region (flag + four u64 counters): body 4640 → **4673**,
`VAULT_SPACE` 4648 → **4681**, `VAULT_SPACE_NO_QUORUM` 4158 →
**4191**, rent-exempt 33,240,960 → **33,470,640** lamports.

## Interest-bearing escrow (AV-107)

The problem: escrow locks the initializer's capital for the deal's
whole lifetime, and the taker waits for settlement — neither side earns
anything on the locked funds. In payment fintech (and DeFi-style Solana
programs generally) idle escrowed capital is expected to work: a
lending-protocol deployment, a staking yield, or simply a time-value
sweetener the initializer offers to win the deal.

The fix, opt-in via `with_interest(rate_bps)` (`Uninitialized`-only;
the default stays the pre-AV-107 non-interest behavior): the locked
principal accrues interest at `rate_bps` APR — `locked * rate_bps *
elapsed_secs / (10_000 * 31_536_000)` — computed in `u128`, so even a
`u64::MAX` principal at 100% APR for a century cannot overflow (the
test pins the saturation). Accrual is lazy: there is no per-block tick
and no hidden clock — every fund-moving transition settles the clock
from an explicit `now`, advancing `interest_accrual_base` (anchored at
`fund_at`) and growing the outstanding claim in `interest_accrued`. The
accrual base is `remaining_amount` — the principal still locked — so a
partial release or slash shrinks future accrual and released funds stop
earning.

The taker harvests the yield two ways: `claim_interest(authority, now)`
— taker-only (`Unauthorized` for anyone else, mirroring `claim`'s
strict check, so a compromised operator cannot divert the yield
stream), `Funded → Funded`, no state change — or bundled with a taker
payout (`release`, `claim`, the milestone/period/basket legs, and the
taker's share of the three dispute settlements). A dispute freezes the
pre-dispute clock at `disputed_at` (AV-55); AV-119 additionally accrues
the dispute window `[disputed_at, resolved_at]` on the locked remainder,
and the settlement attributes the whole outstanding claim pro-rata by
`taker_amount / remaining` — the taker's share into `interest_paid`,
the initializer's share into the new `dispute_interest` sink (a taker
full win keeps the pre-AV-119 behavior; an initializer full win refunds
the whole claim). `cancel` / `cancel_expired` void the
outstanding claim — a cancelled deal unwinds to the pre-deal state, so
no yield is owed on funds that never settled (`interest_paid` is
untouched, so the forfeiture stays distinguishable from a payout in the
audit trail).

The accounting rule that matters: `interest_paid` is the new sink in
the extended conservation identity — `inflow + yield == locked +
released + refunded + interest_paid + dispute_interest`, one term per
sink: the taker's share of a dispute settlement's yield lands in
`interest_paid`, the initializer's share in `dispute_interest`. Interest
never leaks into `released`: principal and yield stay separately
auditable, and the tests assert the identity across accrue → harvest →
release lifecycles. Three deliberate non-couplings: the yield leg is
fee-free (the AV-17 protocol fee and the AV-100 streaming fee slice the
*principal* payout only), the AV-49 payout allowlist has nothing to pin
on `claim_interest` (there is no destination param to redirect — the
harvest always routes to the taker), and `cancel_partial`'s principal
reduction takes effect on the accrual base at the next settlement
(`cancel` takes no `now`, so the base lags by at most one settlement
window — documented, bounded, and negligible).

Gates on `claim_interest`: the escrow must be `Funded`
(`InvalidStateTransition` otherwise), the caller must be the taker
(`Unauthorized` otherwise, checked before state validity), and a rate
must be configured (`InterestNotEnabled`, code 166, when
`interest_rate_bps == 0` — distinct from a zero harvest, which returns
`Ok(0)`). `with_interest` with `rate_bps > 10_000` is
`InvalidInterestRate` (code 165). The Anchor skeleton gains the
`initialize_interest(rate_bps)` and `claim_interest` handlers (the
latter reads `now` from the clock sysvar, never an instruction param),
the four `Vault` fields, and the two `ErrorCode` mappings; the state
snapshot exports the rate, the outstanding claim, and the paid counter.
Account layout grows by the 26-byte interest tail (2-byte rate +
accrual base + accrued claim + paid counter): body 4673 → **4699**,
`VAULT_SPACE` 4681 → **4707**, `VAULT_SPACE_NO_QUORUM` 4191 →
**4217**, rent-exempt 33,470,640 → **33,651,600** lamports.

## Multi-recipient payout split (AV-108)

The problem: a single escrow often settles to several parties — a
marketplace sale splits between seller, referrer, and platform; a
payroll escrow fans out to the team. The AV-93 `release_split`
instruction splits by per-call basis-point weights, but the weights
are caller-supplied at release time: the initializer cannot lock in
the distribution up front, and there is no on-chain record of who was
promised what.

The fix, opt-in via `with_payout_split(shares)` (`Uninitialized`-only):
the initializer declares a fixed table of 1–8 `(recipient, amount)`
shares whose Σ must equal the escrow amount exactly (u128
accumulation, no overflow). The table is persisted in a 321-byte tail
region (1-byte live count + eight 32-byte recipient slots + eight
8-byte share slots, zero-filled) and owns the release destination:
once configured, plain `release` and `release_via_cpi` become
`InvalidPayoutSplit` (code 167) — the full lockup settles through
`release_payout_split` only, which reuses the exact `release` gate
order (pause → reentrancy → scoped RELEASE authority → Funded →
swap-link → mint → per-recipient payout-policy pin → milestones /
subscription → quorum → timelock). The AV-96 denylist is always
checked per recipient (`PayoutDenied`); the AV-49 allowlist, when
configured, must contain every split recipient
(`PayoutNotAllowlisted`). Fees follow AV-17: the protocol fee is
charged once on the gross amount, then the net is prorated per leg as
`floor(share_i * net / amount)` (u128 math) with the rounding dust
(≤7 lamports) landing on the first recipient — Σ legs + fee ==
amount, and `released` accumulates the gross amount so the
conservation identity is untouched. The Anchor skeleton gains the
`initialize_payout_split(shares)` and `release_payout_split` handlers
(the latter reads `now` from the clock sysvar and returns the
per-recipient legs for transfer sizing), the `PayoutSplit` /
`PayoutSplitShare` structs, the `Vault.payout_split` field, and the
`ErrorCode::InvalidPayoutSplit` mapping; the keeper release action
emits per-recipient legs, and the snapshot exports the table.
Account layout grows by the 321-byte split tail: body 4699 →
**5020**, `VAULT_SPACE` 4707 → **5028**,
`VAULT_SPACE_NO_QUORUM` 4217 → **4538**, rent-exempt 33,651,600 →
**35,885,760** lamports (AV-109 later grows the layout by a further
49 bytes: body 5020 → **5069**, `VAULT_SPACE` 5028 → **5077**,
`VAULT_SPACE_NO_QUORUM` 4538 → **4587**, rent-exempt 35,885,760 →
**36,226,800** lamports — see the dead-man's switch section).

## Dead-man's switch (AV-109)

The problem: an escrow with no absolute `expires_at` (`u64::MAX` —
"no timeout") and no live counterparty is a tombstone. `cancel`
needs the initializer; `cancel_expired` needs an expiry to lapse;
both refund to the initializer or the whitelisted address. A dormant
deal — both parties walked away, or one party lost their keys —
strands the locked funds forever, in a vault nobody can close (the
rent-exempt deposit goes with it).

The fix, opt-in via `with_deadman_switch(inactivity_secs, heir)`
(`Uninitialized`-only): the initializer declares an *inactivity*
threshold in seconds and a single heir. Once the threshold elapses
with no state transition, the heir — and only the heir — may
`claim_deadman(heir, now)` the remaining locked funds
(`Funded -> Cancelled`). The heir is deliberately *not* required to
be either party: the switch is orthogonal to `cancel_expired`
(absolute `expires_at` clock, either party may cancel; the switch
uses the *relative* inactivity clock and only the heir may claim).
Both may be configured on the same escrow; neither gates the other —
whichever fires first wins, and the second call finds a terminal
escrow and is `InvalidStateTransition`.

The inactivity clock is `deadman_last_activity`: `fund` anchors it
at funding time, and every *successful* state transition that takes a
`now` parameter resets it (`release` and the whole release family,
`claim`, `claim_interest`, `slash`, `pool_payout`, `cancel_expired`,
`escalate`, `file_appeal`, `expire_appeal`, `extend_expiry`,
`split_escrow`, …) — the window measures funded time since the last
real activity. A deliberate boundary, stated honestly: transitions
*without* a clock parameter — `activate`, `cancel`, `attest`,
`pause`/`unpause`, the `rotate_*` rotations, `review_appeal`,
`update_quorum`, the allowlist/denylist updaters, `close_vault`, the
panel judgments — do **not** reset the clock. Widening their
signatures to take a clock just for the switch would be breaking
churn on long-stable APIs, and most of them are governance or config
moves rather than fund activity.

`claim_deadman` runs the familiar gate order: pause (AV-46) →
reentrancy (AV-36) → the switch config (`InvalidDeadmanConfig`,
code 168, when never configured — checked before the caller so a
misconfigured switch reports the config error, not an auth error) →
the heir check (`Unauthorized` — the heir key must sign; strangers,
the initializer, and the taker all fail unless they *are* the heir) →
`Funded` (`InvalidStateTransition`) → the live AV-105 swap-link
refusal (a linked escrow settles only through the pair path) → the
inactivity gate `now - deadman_last_activity >= inactivity_secs`
(saturating, so a clock far in the past cannot underflow;
exactly-equal counts as elapsed; `DeadmanNotElapsed`, code 169,
otherwise). Effects mirror the cancel family: the outstanding
unsettled interest claim is voided (no yield is owed on funds that
never settled — AV-107), the remaining locked amount routes to the
heir, the state moves to `Cancelled`, and `released` is untouched —
a deadman reclaim is a refund-family unwind, not a taker payout, so
the conservation identity keeps them distinct and the remainder is
preserved for audit exactly like `cancel`'s. The activity clock is
stamped with `now` on the way out for a consistent audit trail.

The Anchor skeleton gains `initialize_deadman_switch(inactivity_secs,
heir)` and `claim_deadman` (the latter reads `now` from the clock
sysvar, never an instruction param), the two `ClaimDeadman` /
`InitializeDeadmanSwitch` account structs, the three `Vault` tail
fields, and the two `ErrorCode` mappings (168/169). The event kind
`DeadmanClaimed` is 56 (appended after `SwapLinked`, 0–55 stable);
the event-sourced fold books the reclaim like `Cancelled` (`refund`
= the heir's payout); the keeper lists one `claim_deadman` action
per eligible escrow — `caller_role` `"heir"`, `refund_to` the heir —
and only when the call would succeed (paused, swap-linked and
zero-remainder escrows are withheld); the snapshot exports the
threshold, the heir, the clock, and the live `deadman_eligible`
predicate (the same predicate the keeper scan uses, so a snapshot
never disagrees with the scan). Account layout grows by the 49-byte
deadman tail (8-byte threshold + 33-byte `Option<Pubkey>` heir +
8-byte activity clock, zeroed when unconfigured): body 5020 →
**5069**, `VAULT_SPACE` 5028 → **5077**,
`VAULT_SPACE_NO_QUORUM` 4538 → **4587**, rent-exempt 35,885,760 →
**36,226,800** lamports (AV-110 later grows the layout by a further
8 bytes: body 5069 → **5077**, `VAULT_SPACE` 5077 → **5085**,
`VAULT_SPACE_NO_QUORUM` 4587 → **4595**, rent-exempt 36,226,800 →
**36,282,480** lamports — see the permissionless rent top-up section;
AV-111 then grows it by a further 19 bytes: body 5077 → **5096**,
`VAULT_SPACE` 5085 → **5104**, `VAULT_SPACE_NO_QUORUM` 4595 →
**4614**, rent-exempt 36,282,480 → **36,414,720** lamports — see the
tranched funding section; AV-112 then grows it by a further 17
bytes: body 5096 → **5113**, `VAULT_SPACE` 5104 → **5121**,
`VAULT_SPACE_NO_QUORUM` 4614 → **4631**, rent-exempt 36,414,720 →
**36,533,040** lamports — see the release-cooling section).

**Walkthrough — the heir reclaims a dormant vault.** The initializer
names a recovery heir at setup; both parties go silent; a year
passes; the heir sweeps the funds:

```
initializer        taker          heir           escrow
   |  initialize_deadman_switch(1yr, heir)  |                |
   |-------------------------------------->|  (switch armed, |
   |                                         still Uninitialized)
   |  fund(alice, t0)  |                   |                |
   |-------------------------------------->| Uninitialized→Funded;
   |                                         clock = t0
   |               |     // …silence: no clock-bearing        |
   |               |     // transition for a full year       |
   |                                 claim_deadman(heir, t0+1yr-1)   |
   |                                 ---------------------->|
   |                                          | Err(DeadmanNotElapsed):
   |                                          | one second early, escrow
   |                                          | untouched, stays Funded
   |                                 claim_deadman(heir, t0+1yr)     |
   |                                 ---------------------->|
   |                                          | Funded→Cancelled;
   |                                          | remainder → heir;
   |                                          | DeadmanClaimed emitted
```

Had the initializer instead released half at `t0 + 30d`, the clock
would have reset to `t0 + 30d` and the heir's window would measure
from there — activity, not the funding date, is what the switch
watches.

## Permissionless rent top-up (AV-110)

The problem: a Solana account that drops below the rent-exempt
minimum starts being charged rent — and a vault whose layout grew
across upgrades (each appended tail region raises the exempt
minimum) can drift underfunded without anyone noticing. The AV-43
keeper scan (`scan_rent_health`) already *reports* underfunded
vaults with the exact top-up amount; AV-110 adds the on-chain
instruction that actually moves the lamports.

`top_up_rent(caller, lamports)` is permissionless: the initializer,
the taker, the keeper bot, or a complete stranger may call it, in
any state except `Closed` (`InvalidStateTransition` — a closed vault
no longer exists). It accumulates `lamports` into the new
`rent_topped_up_total` vault counter and changes nothing else: the
state byte is untouched, and the amount conservation identity is
untouched — a top-up is pure lamport bookkeeping on the vault
*account*, not on the escrow lockup.

Two deliberate non-gates: the call is *not* pause-gated (pausing
freezes fund movement, not operational hygiene — refusing top-ups
while paused could let a paused vault drift into rent collection),
and it carries no reentrancy guard (it moves no escrow funds and
touches exactly one counter). `lamports == 0` is `InvalidRentTopUp`
(code 170) — a top-up must move a positive amount.

The `IndexedEscrow` wrapper emits `RentToppedUp` (`from == to ==`
the current state; the topped-up lamports ride the event's
`rent_reclaimed` amount field — the rent-balance leg, direction read
from the kind); the event-sourced fold books it as zero (rent sits
outside the lockup, like a close's `rent_reclaimed`). The Anchor
skeleton gains the `top_up_rent` handler, the `TopUpRent` accounts
struct (vault + permissionless caller signer + clock sysvar for the
event's `at`), and the `InvalidRentTopUp` error mapping (code 170);
the snapshot exports the counter so indexers can reconcile top-up
events against the vault. Account layout grows by the 8-byte
counter: body 5069 → **5077**, `VAULT_SPACE` 5077 → **5085**,
`VAULT_SPACE_NO_QUORUM` 4587 → **4595**, rent-exempt 36,226,800 →
**36,282,480** lamports. The event kind `RentToppedUp` is 57
(appended after `DeadmanClaimed`, 0–56 stable).

**Walkthrough — the keeper keeps a vault rent-exempt.** The vault's
layout grew; the keeper scan flags it 6,960 lamports short:

```
keeper            stranger          vault
   |  scan_rent_health → top_up 6,960 lamports   |
   |-------------------------------------------->|
   |                  |  top_up_rent(anyone, 6960)|
   |                  |------------------------->|
   |                  |   | rent_topped_up_total |
   |                  |   | = 6,960; state still |
   |                  |   | Funded; RentToppedUp |
   |                  |   | emitted              |
```

## Tranched funding (AV-111)

The problem: some deals are funded in stages — a construction
escrow draws against milestones, a payroll escrow funds as headcount
ramps — but a classic escrow takes its whole amount in one `fund`
call. AV-111 adds an opt-in funding plan: the initializer declares
the schedule up front, then deposits in tranches.

`with_funding_plan(total_amount, max_tranches)` is a builder on an
`Uninitialized` escrow (like the other `with_*` opt-ins).
`total_amount` must be positive *and equal the escrow's declared
`amount` (`AmountMismatch` otherwise): the plan *schedules* the
deposit of the deal size, it never redefines it — so milestones,
vesting curves, and fees keep pricing off `amount`, and the deal the
taker signed is the deal that gets funded. `max_tranches` must be at
least 1 (`InvalidFundingPlan`, code 173, on zero). Attaching a plan
moves the deposit path from `fund` to `fund_tranche` — `fund` on a
plan escrow is `InvalidFundingPlan`, so a single-shot deposit cannot
silently bypass the tranche schedule.

`fund_tranche(authority, tranche_amount, now)` runs the full check
sequence — pause → reentrancy → FUND-scoped authority (AV-104: the
initializer or their operator) → plan presence (`InvalidFundingPlan`
when no plan is attached — use `fund`) → state (`Uninitialized`
non-dual-sig / `Activated` / `Funded`) → positive amount → tranche
budget (`FundingTranchesExhausted`, code 172, when the budget is
spent) → overfund cap (`AmountMismatch`). Each call accumulates
`funded_total` and consumes one tranche slot; the first call moves
`Uninitialized` → `Funded` (`Activated` → `Funded` for dual-sig)
and anchors `fund_at` / the interest clock / the deadman clock
exactly like `fund`.

Two money rules keep partial funding honest. First, taker payouts
wait for full funding: `release`, `claim`, and `release_milestone`
refuse with `FundingIncomplete` (code 171) until `funded_total`
reaches the plan target — the taker is paid the full deal, never a
partial deposit. Second, every fund-movement cap keys off the
actually-deposited `funded_total`, never the declared `amount`
(`remaining_amount`, the release-path caps, the slashable base) —
so no path can ever move money that never arrived, and the
conservation identity extends cleanly to
`funded_total == locked + released + refunded …`. `cancel` /
`cancel_expired` refund the deposited remainder automatically;
`cancel_partial` walks the plan back with the refund (shrinking
`amount`, `funded_total`, and the plan target together, so
`total_amount == amount` is preserved). Interest accrues on
`remaining_amount`, so it prices the deposited principal.

The `IndexedEscrow` wrapper emits `TrancheFunded` (`from == to ==`
the state after the call; the event carries no amount — the tranche
is the fold seed's inflow leg, so the fold seeds the lockup with the
deal size at `Funded`, exactly like `Funded` itself). The keeper scan
lists one `fund_tranche` action per incomplete plan (with the live
`funded_total` / `total_amount` / `tranches_used` / `max_tranches`
passed through as `funding_progress` for the operator's dashboard),
withheld while paused. The Anchor skeleton gains the
`initialize_funding_plan` and `fund_tranche` handlers plus accounts
structs and the three error mappings (codes 171–173); the snapshot
exports the funding counters. Account layout grows by the 19-byte
tail (`funded_total` u64 + `Option<FundingPlan>` region): body 5077
→ **5096**, `VAULT_SPACE` 5085 → **5104**,
`VAULT_SPACE_NO_QUORUM` 4595 → **4614**, rent-exempt 36,282,480 →
**36,414,720** lamports. The event kind `TrancheFunded` is 58
(appended after `RentToppedUp`, 0–57 stable).

**Walkthrough — three tranches fund a build.** The initializer plans
1,000,000 lamports in up to 3 tranches; the taker waits:

```
initializer                    vault
   | with_funding_plan(1_000_000, 3) |
   |-------------------------------->|
   | fund_tranche(400_000) → Funded    |
   |-------------------------------->|
   | fund_tranche(400_000) → Funded    |
   |-------------------------------->|
   | release(…) → FundingIncomplete    |
   |<--------------------------------|
   | fund_tranche(200_000) → complete  |
   |-------------------------------->|
   | release(…) → taker paid           |
   |<--------------------------------|
```

## Release cooling with veto (AV-112)

The problem: once a quorum or dual signature approves a release,
nothing stops one party from racing the payout through before the
other side can react — the classic "approved, then rug-pulled"
governance failure. AV-112 adds an opt-in cooling window between the
*intent* to release and the release itself, with a veto either party
can pull inside the window.

`with_release_cooling(cooling_secs)` is a builder on an
`Uninitialized` escrow (like the other `with_*` opt-ins).
`cooling_secs = 0` means unconfigured — `release` is ungated,
exactly like AV-21's grace-period convention.

`announce_release(authority, now)` records the intent: the check
sequence is pause → authority → state (`Funded`), and the caller
must be the initializer or the taker themselves — no delegation
(mirroring `delegate_authority`'s party-only rule). It stamps
`release_intent_at = now`; re-announcing overwrites the stamp, so
the call is idempotent. `veto_release(caller, now)` clears the
intent; with no live intent it is a no-op success. Both touch the
AV-109 deadman clock (they are party-liveness signals) and both
emit indexer events (`ReleaseIntentAnnounced` / `ReleaseIntentVetoed`,
emitted only on an actual change).

`release` gains a second gate, stacked *after* the AV-27 fixed
timelock: when cooling is configured, the release is refused with
`ReleaseCoolingNotElapsed` (code 174) unless an intent is live and
`now >= intent_at + cooling_secs` (`saturating_add` — no overflow
path). The two gates are orthogonal and compose: a release must
clear both the timelock and the cooling window. `release_via_cpi`
inherits the gate (it delegates to `release`); `release_milestone`
and `claim` are out of scope — only plain `release` is gated.
Neither announce nor veto moves funds, so the conservation
identity is untouched.

The `IndexedEscrow` wrapper emits `ReleaseIntentAnnounced` (59) and
`ReleaseIntentVetoed` (60) — appended after `TrancheFunded` (58),
0–58 stable. The keeper reads the intent through the same truth
source (`is_release_cooling_eligible`) that gates `release`, and
the snapshot exports `release_cooling_secs` / `release_intent_at`
/ `release_cooling_eligible`. The Anchor skeleton gains the
`initialize_release_cooling`, `announce_release`, and `veto_release`
handlers plus accounts structs and the error mapping (code 174).
Account layout grows by the 17-byte tail (`release_cooling_secs`
u64 + `release_intent_at` Option<u64>): body 5096 → **5113**,
`VAULT_SPACE` 5104 → **5121**, `VAULT_SPACE_NO_QUORUM` 4614 →
**4631**, rent-exempt 36,414,720 → **36,533,040** lamports.

**Walkthrough — the veto that stopped a rug-pull.** The initializer
configures a 1-hour cooling window; the taker announces a release
at noon, planning to sweep the funds before the initializer
notices:

```
initializer                  taker                      vault
   | with_release_cooling(3600)    |                       |
   |------------------------------>|---------------------->|
   |                               | announce_release(noon)|
   |                               |---------------------->|
   | veto_release(12:30)           |                       |
   |------------------------------>|---------------------->|
   |                               | release(12:45) →      |
   |                               |   ReleaseCoolingNotElapsed
   |                               |<----------------------|
```

## Oracle price-gated release (AV-113)

The problem: an escrow's release is priced at signing time, but
crypto prices move — a taker who locked in 200 USDC/SOL watches SOL
crash and releases anyway, or the initializer wants the payout to
happen only once the collateral leg is worth enough to cover the
invoice. AV-113 adds an opt-in oracle price gate: release (and
claim) proceeds only when a fresh oracle quote satisfies a
directional price condition.

`with_price_gate(direction, target, max_staleness_secs)` is a
builder on an `Uninitialized` escrow (like the other `with_*`
opt-ins); `target == 0` is rejected with `InvalidPriceGate` (code
176). The gate is a `PriceGate` — `AtOrAbove` / `AtOrBelow` plus the
target price and the maximum quote age in seconds — and lives in an
18-byte tail region of the vault account (1-byte `Option`
discriminant + 17 bytes: direction, target, staleness bound).

`release_price_gated(authority, now, amount, payout_to, recipient,
feed)` and `claim_price_gated(...)` are the gated entries. The gate
is evaluated *first*, before the release/claim guard chains: the
oracle input is the most failure-prone external dependency, and the
gate's existence is public in the vault bytes anyway, so no
information leaks by checking it up front. With no gate attached
both degrade to plain `release` / `claim`; plain `release` /
`claim` stay ungated for backward compatibility. A missing quote
(dark oracle), a stale quote (`now - observed_at >
max_staleness_secs`, `saturating_sub` — no underflow path), or a
price on the wrong side of the target (boundaries inclusive) all
refuse with `PriceGateNotSatisfied` (code 175). The gate stacks
*after* the AV-27 fixed timelock and composes with the AV-112
cooling window: a release must clear all three. The on-chain
skeleton reads the quote from the first remaining account
(16-byte price ++ observed_at; missing/short account → code 175);
no new event kind — the standard `Released` / `Claimed` fire, the
gate is a check like the timelock, not a new transition. Account
layout grows by the 18-byte tail: body 5113 → **5131**,
`VAULT_SPACE` 5121 → **5139**, `VAULT_SPACE_NO_QUORUM` 4631 →
**4649**, rent-exempt 36,533,040 → **36,658,320** lamports.

**Walkthrough — the release that waited for the price.** The
initializer gates the escrow at 200 USDC/SOL with a 5-minute
staleness bound; at noon SOL trades at 190 and the taker tries to
release:

```
initializer              taker                    oracle
   | with_price_gate(AtOrAbove, 200, 300)             |
   |-------------------->|                            |
   |                     | release_price_gated(noon)  |
   |                     |   quote = 190 (fresh)      |
   |                     |--------------------------->|
   |                     |   PriceGateNotSatisfied    |
   |                     |<---------------------------|
   |                     | release_price_gated(14:00) |
   |                     |   quote = 205 (fresh)      |
   |                     |--------------------------->|
   |                     |   Released                 |
   |                     |<---------------------------|
```

## TWAP price-gated release (AV-128)

The problem: AV-113's single-point gate asks "is the price *now*
above the target" — answerable by one flash-manipulated observation.
A taker (or an attacker who compromised the oracle for a single
block) can spike the price for one slot, release, and leave. AV-128
adds the manipulation-resistant complement: release (and claim)
proceeds only when the *time-weighted average price* over a
configured slot window satisfies a directional condition. A single
manipulated block moves the average by at most `price_delta * 1 /
window_slots` — briefly spiking the oracle cannot unlock the payout.

`with_twap_gate(window_slots, target, direction)` is a builder on an
`Uninitialized` escrow (like the other `with_*` opt-ins);
`with_twap_gate_and_staleness(...)` sets an explicit staleness bound
(default 300s). `window_slots == 0` or `target == 0` is rejected with
`InvalidTwapGate` (code 187) — a zero window is a single-point gate
in disguise (use AV-113's `PriceGate`), and a zero threshold is never
a deliberate policy. The gate is a `TwapGate` — `AtOrAbove` /
`AtOrBelow` plus the target, the window in slots, and the maximum
quote age — and lives in a 26-byte tail region of the vault account
(1-byte `Option` discriminant + 25 bytes: direction, target, window,
staleness bound), appended last so every earlier field offset stays
stable.

`release_twap_gated(authority, now, now_slot, amount, payout_to,
feed)` and `claim_twap_gated(...)` are the gated entries. The TWAP
gate is evaluated *first*, before the release/claim guard chains
(pause → authority → state → mint → payout destination →
milestone/subscription/payout-split ownership → quorum → timelock →
vesting → amount math): the oracle history is the most
failure-prone external input, and the gate's existence is public in
the vault bytes anyway, so no information leaks by checking it up
front. The evaluation:

1. the feed must yield a latest quote (dark oracle →
   `TwapGateNotSatisfied`, code 186);
2. the latest quote must be fresh (`now - observed_at <=
   max_staleness_secs`, the AV-113 staleness rule reused unchanged);
3. the feed's history must cover the full `[now_slot -
   window_slots, now_slot]` window — the price at the window's left
   edge must be known, otherwise the average cannot be trusted — and
   the time-weighted average over it must sit on the gate's side of
   the target.

One code (186) for all four failure modes, mirroring AV-113: the
caller learns the gate blocked, never which sub-condition tripped.
The TWAP itself is computed in `u128` (`price * slots`, durations
summing to exactly `window_slots` under full coverage) and floored
to `u64` — no overflow, no precision loss that matters for a
threshold comparison.

The `PriceFeed` trait gains `price_history()` (AV-128): historical
`(slot, price)` samples, any order (the state machine sorts). The
default impl degrades gracefully — a single-point feed reports its
latest quote as one sample at slot 0 ("this price has held since
genesis"), so existing implementors (`StaticPriceFeed`, the Anchor
`QuoteFeed`) keep working unchanged, and a single-point feed behaves
as a constant-price history. Deterministic tests use the new
`ScriptedPriceFeed` with a scripted history.

Check-order composition: when an AV-113 single-point `PriceGate` is
*also* configured, the twap-gated entry points enforce both (TWAP
first, then the single-point gate) — the two gates are
complementary, and a payout must satisfy each configured condition.
The Anchor `release` / `claim` handlers route to the twap-gated
entry points when `twap_gate` is `Some` (taking precedence over the
price gate), reading the slot from the clock sysvar and the history
from the oracle account (16-byte quote ++ 16-byte `(slot, price)`
samples; missing/short account → code 186). No new event kind — the
standard `Released` / `Claimed` fire, the gate is a check like the
timelock, not a new transition. The keeper scan does *not* list
TWAP-gated escrows for claim/release (the off-chain scan cannot
evaluate the oracle history); the gate terms ride the snapshot so
keepers can decide whether to service the escrow.

Account layout grows by the 26-byte tail: body 5349 → **5375**,
`VAULT_SPACE` 5357 → **5383**, `VAULT_SPACE_NO_QUORUM` 4867 →
**4893**, rent-exempt 38,175,600 → **38,356,560** lamports
(no-quorum: 34,765,200 → **34,946,160**).

**Walkthrough — the spike that couldn't unlock.** The initializer
sets `with_twap_gate(100, 100_000, AtOrAbove)`. For 99 slots SOL
trades at 90,000; at slot 100 an attacker spikes the oracle to
1,000,000 and the taker tries to release:

```
TWAP = (90,000 × 99 + 1,000,000 × 1) / 100 = 99,100 < 100,000
→ TwapGateNotSatisfied. The spike moved the average by only 910.
```

A sustained move — 50 slots at 90,000 then 50 slots at 120,000 —
gives TWAP = 105,000 ≥ 100,000, and the release proceeds. The gate
rewards genuine price moves and ignores flash spikes.

## Dual control (maker-checker) release (AV-130)

The problem: every release path so far is a one-signature action —
whoever holds the initializer key (or a `RELEASE`-scoped delegation)
can drain the vault alone. A stolen initializer key is a stolen
vault. AV-130 adds the classic treasury control: **maker-checker** —
the initializer (the *maker*) declares each payout, and a second,
distinct key (the *checker*) must approve it before anything settles.
One key compromised is never enough; two must conspire (or the honest
holder of the other key must fail to act).

`with_dual_control(checker)` is an opt-in builder on an
`Uninitialized` escrow (like the other `with_*` opt-ins). The
checker's identity is fixed before any funds move; a zero `checker`
key is `InvalidDualControl` (code 188), re-configuring a live escrow
is `InvalidStateTransition`, and a paused escrow fails fast
(`Paused`). The binding lives in two tail regions appended last to
the vault account (123 bytes total, every earlier field offset
stable): `dual_control_checker` (1-byte `Option` discriminant +
32-byte key) and `dual_control_intent` (1-byte discriminant +
89-byte frozen declaration — 8-byte amount, 1-byte mint-`Option`
discriminant + 32-byte mint, 32-byte payout destination, 8-byte
declaration clock, 8-byte expiry clock).

The protocol is two steps:

1. **`initiate_release(authority, now, amount, mint, payout_to,
   intent_ttl_secs)`** — the maker freezes the *exact* payout into
   the vault: `{amount, mint, payout_to, initiated_at: now,
   intent_expires_at: now + intent_ttl_secs}`. The authority is the
   initializer or their `RELEASE`-scoped operator (the payout
   destination is pinned by the declaration, so an operator cannot
   redirect funds). Check order is pause → reentrancy → dual-control
   configured → authority → `Funded` state → no live intent →
   declaration shape (`amount == 0`, `intent_ttl_secs == 0`, or an
   overflowing expiry is `InvalidDualControl`, code 188; redeclaring
   over a live intent is `DualControlIntentExists`, code 189). The
   escrow state stays `Funded` — the declaration is a pending intent,
   not a lifecycle move — and no funds move. Emits
   `DualControlInitiated`.
2. **`confirm_release(checker, now)`** — the checker approves the
   live declaration and it settles. `checker` must equal the bound
   key (`Unauthorized` otherwise — the maker cannot self-approve,
   and neither can a stranger); a stale declaration (`now >=
   intent_expires_at`) is cleared and the call fails with
   `DualControlExpired` (code 191). The frozen
   `{amount, mint, payout_to}` then settles through the *exact*
   `release` settlement engine — fee, released-accounting, and
   terminal-state logic are reused verbatim, not reimplemented
   (code 192 never reaches the engine on the unapproved path). On
   success the declaration is consumed (cleared); a failed settlement
   leaves it live for a retry. Emits `DualControlConfirmed` with the
   release amounts shape.
3. **`cancel_release(caller, now)`** — either party aborts a live
   declaration: the initializer retracting their own, or the checker
   refusing to approve it. A stranger is `Unauthorized`; no live
   declaration is `DualControlNotInitiated` (code 190). Cancelling
   clears the intent and moves no funds. Emits `DualControlCancelled`.

The core semantic change: on a dual-control escrow, **direct
`release` is refused with `DualControlRequired` (code 192)** — and
every path routed through it (`release_via_cpi`, the gasless
`release_via_intent`) inherits the gate, so there is no one-signature
bypass. The check sits in the shared internal `release_impl`, which
`confirm_release` enters with `via_dual_control = true` and the
authority pinned to the initializer (the AV-123 `release_via_intent`
precedent: the authority semantics is "in whose name the release
settles"). The payout-split-owned path `release_payout_split` is
deliberately separate and ungated — a split table owns the release
destination by construction, so dual-control and payout-split are
not combined.

Single-key-compromise properties (pinned by tests): a stolen
initializer key can only *declare* intents — `confirm_release` with
the maker's key is `Unauthorized`, and direct `release` is
`DualControlRequired`, so the attacker can never settle. A stolen
checker key cannot *declare* (`initiate_release` is `Unauthorized`
for non-initializers), so there is nothing hostile to approve —
though a checker-side compromise can refuse to approve, which is why
the maker can always `cancel_release` and re-declare. An honest
checker who spots a hostile declaration from a compromised maker key
aborts it with `cancel_release`.

Layout growth: the vault body grows from 5375 to 5498 bytes (+123),
`VAULT_SPACE_NO_QUORUM` from 4893 to 5016, `VAULT_SPACE` from 5383
to 5506, and the close-time rent reclamation from 38_356_560 to
39_212_640 lamports (`(128 + VAULT_SPACE) * 3480 * 2`). The state
machine's `EscrowState` enum gains no new variant — the two-step
protocol reuses `Funded`, so discriminants stay stable.

## Partial-amount dispute arbitration (AV-131)

The problem: every dispute so far locked the *entire* lockup — a
1-lamport grievance could freeze a million-lamport escrow for the whole
deliberation, and neither party could touch the uncontested funds.
AV-131 makes the dispute a **partial-amount** dispute: `escalate` takes a
`dispute_amount` naming the contested slice of the lockup (`1..=
remaining_amount()`, else `InvalidDisputeAmount`, code 193), persisted as
`disputed_amount` and never cleared. While `Disputed`, only the
contested pool is locked — `release` and `claim` still move the
undisputed remainder (`remaining - disputed_amount`); a `release` that
names into the locked pool fails with `DisputedAmountLocked` (code 194),
and a `claim` is silently capped at the remainder (its take-what's-there
pull semantics). `resolve`, the panel settling vote, and the AV-55
default judgment all adjudicate the same disputed pool (`taker_amount <=
disputed_amount`, else `ReleaseExceedsLocked`); dispute interest accrues
on the disputed pool, and the refund formula is unchanged —
`(remaining - taker_amount)` — because the undisputed remainder
naturally rides the refund back to the initializer, so no lamport
strands.

Layout growth: the vault body grows from 5498 to 5506 bytes (+8),
`VAULT_SPACE_NO_QUORUM` from 5016 to 5024, `VAULT_SPACE` from 5506 to
5514, and the close-time rent reclamation from 39_212_640 to 39_268_320
lamports (`(128 + VAULT_SPACE) * 3480 * 2`). The state machine's
`EscrowState` enum gains no new variant — partial disputes reuse
`Disputed`, so discriminants stay stable.

## Escrow merge (AV-114)

The problem: an initializer who funds per-invoice escrows ends up
with a fleet of small `Funded` vaults — settling each one separately
costs a transaction per escrow. AV-114 adds `merge_escrows`: two
`Funded` escrows with the same parties and identical settlement
terms collapse into one, so dust escrows consolidate instead of
settling piecemeal.

`merge_escrows(source, authority)` is initializer-only
(`Unauthorized` otherwise); both escrows must be `Funded`
(`InvalidStateTransition` otherwise). Compatibility is checked term
by term — vesting schedule, vesting curve, milestone plan, fee bps,
quorum policy, the dual-sig-required bit, mint, and timelock must
all match, else `MergeIncompatible` (code 177). Accumulation is
u128-checked: `amount`, `released`, `skipped`, and `fees_paid` each
sum, and a sum that would overflow `u64` refuses the merge rather
than wrapping. `expires_at` becomes the earlier of the two
deadlines — the merged escrow keeps the tighter expiry, so no
deadline is silently extended. The source moves to `Cancelled` with
`released := amount` ("released-into-merge" accounting): the
source's locked funds conceptually release into the survivor, so
the per-escrow conservation identity holds on both sides.

The `IndexedEscrow` wrapper emits `EscrowsMerged` (61) on the
survivor (`from == to == Funded`, the merged-in remainder in the
payout leg) and `Cancelled` on the source. The event-sourced fold
treats the merge as its only inflow: the survivor's `locked` grows
by the merged-in amount while the source's drops to zero, so fleet
rollups keep counting the consolidated funds. The keeper lists one
`merge_escrows` action per compatible pair per scan — the lower
`escrow_id` survives, the higher rides `merge_source`; expiry-eligible
escrows keep their cancel path instead of a merge. The Anchor
skeleton gains the `merge_escrows` handler (two vault accounts) plus
the error mapping (code 177). No new persisted fields — the account
layout is untouched.

**Walkthrough — consolidating two invoices.** The initializer funded
1,000,000 for invoice A and 500,000 for invoice B, same taker, same
terms:

```
initializer              vault A (1M)          vault B (500k)
   | merge_escrows(B)        |                       |
   |------------------------>|---------------------->|
   |                         | amount = 1,500,000    |
   |                         | EscrowsMerged         |
   |                         |                       | Cancelled
   |                         |                       | (released := 500k)
```

## Bilateral netting (AV-140)

The problem: two parties who trade repeatedly end up with
opposite-direction escrows — Alice locks 1M for Bob on one leg,
Bob locks 700K for Alice on the other. Settling each leg gross
moves 1.7M across chains; payment clearing instead *nets* the
mutual obligations: 700K offsets bilaterally and only the 300K
residual ever needs to move. AV-140 adds `net_escrows` for exactly
that: two `Funded` opposite-direction legs of the same
counterparty pair net without any transfer.

`net_escrows(other, authority)` accepts *either* party as
authority (`Unauthorized` for a stranger — nobody force-settles
anyone else's legs). Both legs must be `Funded`
(`InvalidStateTransition` otherwise — `Disputed` is refused
outright, with no carve-out: the offset extinguishes the *whole*
locked position, including the contested pool the arbiter owns).
The legs must be opposite-direction mirrors
(`self.initializer == other.taker` and `self.taker ==
other.initializer`) with identical SPL mint bindings, else
`NettingIncompatible` (code 207). A paused leg fails fast
(`Paused`, both sides checked).

The netting math: `netted = min(locked_a, locked_b)`. The smaller
leg settles to `Released` with `released := amount`
("released-into-netting" accounting — the mirror of
`merge_escrows`' "released-into-merge": the netted-away obligation
is booked as released at zero payout, so the per-leg conservation
identity still holds). The larger leg's `released` grows by
`netted` (u128-checked — on plain escrows `released + locked <=
amount` makes an overflow unreachable, so the check is
defense-in-depth) and its lockup shrinks by the same, with
`netted + new_locked == old_locked` pinned by a conservation
assert. On an exact mutual offset the larger leg's lockup hits
zero and it settles to `Released` too — both obligations
extinguish with no transfer. The call returns a
`NettingSettlement` receipt (`netted`, `larger_new_locked`,
`larger_new_released`, `smaller_released`).

The `IndexedEscrow` wrapper emits `EscrowsNetted` (75) on the
larger leg (`from == to == Funded`, the netted amount in the
payout leg — payout-shaped like the merged-in leg of
`EscrowsMerged`) and `Released` on the smaller leg with a zero
payout — the honest record that the offset moved no funds. The
event-sourced fold books the larger leg exactly like a release
and moves the smaller leg's whole remaining lockup sideways into
`released`, so the materialized view stays bit-identical with the
state machine on both legs. The Anchor skeleton gains the
`net_escrows` handler (two vault accounts) plus the error mapping
(code 207). No new persisted fields — the account layout is
untouched.

**Walkthrough — netting two opposite legs.** Alice funded
1,000,000 for Bob; Bob funded 700,000 for Alice, same mint:

```
alice                  vault A (1M)          vault B (700k)
   | net_escrows(B)        |                       |
   |---------------------->|---------------------->|
   |                       | locked = 300,000      |
   |                       | EscrowsNetted (700k)  |
   |                       |                       | Released
   |                       |                       | (released := 700k,
   |                       |                       |  zero payout)
```

## Atomic batch release (AV-141)

The problem: one initializer's fleet — payroll vaults, market-maker
legs, a distributor's outstanding payouts — settles one token across
many escrows. Releasing them one transaction at a time costs N
signatures and N transaction fees and leaves N chances for a partial
settlement to strand the fleet half-paid. AV-141 adds
`Escrow::release_many`: one instruction atomically releases N escrows.

`release_many(escrows, authority, now, legs, mint)` takes one
`ReleaseLeg { amount, payout_to }` per escrow, in escrow order, plus a
single instruction-level `mint` (the fleet shares a token — the
backend-engineering reality of a payroll or market-maker run; `None`
on the native-SOL path). Every leg reuses the exact `release` check
order — authority, the dual-control routing gate, state, the
swap-link guard, funding completeness, the mint binding, the payout
destination, the milestone plan, the subscription schedule, the
payout-split table, quorum, the timelock, then the amount checks — so
there is no gate drift: a leg that would fail a standalone `release`
fails the batch with the identical error. `legs.len()` must equal the
escrow count; a shape mismatch is the caller's bug, refused with
`LegsCountMismatch` (code 208) before any leg is touched. One
authority key drives the whole batch: a leg owned by another
initializer fails `Unauthorized`, and a leg bound to a different mint
fails `MintMismatch` — strangers cannot force-settle anyone's vaults,
one leg at a time or N.

Two-phase atomicity makes the batch all-or-nothing. Phase 1 is a
dry-run shadow validation: every leg runs `release` on a `Clone` of
its escrow, and the first failure returns that leg's error with the
real escrows untouched — zero side effects, by construction. Phase 2
executes on the real escrows with a defensive whole-batch snapshot
taken first: phase 1 ran the identical transitions on bit-identical
state with identical inputs, so a phase-2 failure is unreachable in
the pure model, and the snapshot/restore is defense-in-depth against
future refactors that introduce non-determinism. The call returns the
per-leg `(taker_payout, fee)` detail in leg order — the same shape as
`release` — so the caller can size each leg's transfer.

The `IndexedEscrow` wrapper mirrors it with one `Released` indexer
event per successful leg, in leg order (`from == Funded`, `to ==
Funded` on a partial leg, `to == Released` on the closing one;
amounts follow the `Released` shape) — exactly the per-leg event
sequence a series of standalone `release` calls would have produced,
so the event-sourced fold needs no new logic. A failed batch emits
nothing on any leg: inner state, the event stream, and the seq
counters all restore bit-identically.

Compute units grow linearly with the leg count — each leg runs one
full `release` guard chain plus settlement writes — so the CU table
is honest about it instead of pretending one row fits all N: the
`INSTRUCTION_CU_TABLE` row pins the N=1 case (85 data bytes: 8-byte
discriminator + 4-byte vec length + one 40-byte leg + 33-byte mint
option; 16_000 base = 4_000 dispatch overhead + 12_000 per-leg
marginal, heuristic planning numbers, not measurements), and
`estimate_release_many_cu` takes the leg count for the real estimate
(each extra leg: +12_000 CU + 40 data bytes). Size production batches
against `simulateTransaction`, not the heuristic.

No new persisted fields — the account layout is untouched.

**Walkthrough — settling a three-vault payroll fleet.** The
initializer's three vaults lock 1,000,000 / 600,000 / 300,000 for two
takers; one instruction releases all three:

```
initializer        vault 1 (1M)    vault 2 (600k)    vault 3 (300k)
   | release_many      |                 |                 |
   | legs=[1M,250k,300k], mint=None      |                 |
   |------------------>|---------------->|---------------->|
   |                   | Released (1M)   | Released (250k) | Released (300k)
   |                   | to == Released  | to == Funded    | to == Released
```

If vault 2's leg named 600,001 (over the locked amount), phase 1
returns `ReleaseExceedsLocked` and all three vaults — states,
counters, event streams — stay exactly as they were: no partial
payroll.

## Basket escrow (AV-95)

One escrow, up to 8 SPL mints: a basket escrow locks a per-mint leg
table (`mint`, `amount`, `released` per leg) instead of a single
amount — the initializer's multi-mint payout (a single escrow settling
USDC + USDT + wSOL legs instead of N escrows). The leg table is built
by `initialize_basket` / `with_basket` (1–8 legs, no zero mint, no zero
amount, no duplicate mint, Σ fitting in `u64` — `InvalidBasket`, code
152, otherwise) and lives in a 386-byte tail region of the vault
account that is always reserved, so attaching a basket never
reallocates. The escrow-level `amount` is the Σ over the legs, so fleet
aggregation, snapshots, keeper scans and the event-sourced fold keep
their single-amount semantics.

Settlement comes in two granularities. The per-leg path (AV-95b —
`release_basket` / `cancel_basket` / `cancel_expired_basket`) settles
one leg per call, named by its SPL mint; the escrow moves to the
terminal state when the settled leg is the last unsettled one. The
atomic path (AV-95c — `release_basket_all` / `cancel_basket_all`)
settles every unsettled leg in one transition: every gate and every
leg's fee math runs before any mutation, so a failure on any leg rolls
the whole settlement back and nothing observable changes (on-chain a
failed instruction aborts the transaction; the pure-logic model mirrors
that atomicity). The AV-49 payout-policy pin applies per leg — for the
atomic release, one `payout_to` for every leg means one check *is* the
per-leg application — and the AV-17 protocol fee is charged per leg,
floored per leg, so no dust is carried across legs. Each leg's
`released` counter accumulates its settled remainder and the
escrow-level `released` accumulates the Σ, so the conservation
invariant `inflow == locked + released + refunded` holds leg-by-leg and
in aggregate. The atomic calls return a `BasketSettlement` — the
settled legs' `(mint, recipient, net_amount)` in leg-table order plus
the Σ fee — sized for the program's per-mint transfers, and emit a
single `BasketReleased` / `BasketCancelled` event carrying the Σ
amounts (bit-identical in the event fold to the per-leg sequence).

## Configuration templates (AV-72)

The `with_*` builders compose freely, but freedom is also a footgun: an
absolute timelock *and* a relative timelock together, a timelock that
unlocks after expiry (so the initializer can always front-run the taker's
payout with `cancel_expired`), or a milestone plan whose tranches don't
sum to the lockup are all legal builder sequences that only fail deep in a
transition — or worse, encode an intent the parties didn't have.
`escrow-state/src/templates.rs` encodes the four canonical compositions as
one-call constructors with template-level combination validation:

| Template | Composition |
|---|---|
| `Auction` | plain escrow + optional timelock + grace period — the classic auction-deposit / simple timelocked pattern |
| `MilestonePlan` | escrow + milestone tranches + optional dual-sig/quorum — deliverable-gated release |
| `Subscription` | escrow + subscription cadence — clock-driven periodic payouts |
| `ArbitratedDispute` | escrow + arbiter + optional evidence deadline — dispute-arbitrated settlement |

`EscrowTemplate::validate()` is a pure dry-run; `build()` validates
first, then composes the builders in dependency order (the arbiter binds
before the evidence deadline, which requires a bound arbitration
mechanism). Either a fully-configured escrow or a `TemplateError` — never
a half-built one. Combination rules: absolute vs relative timelock are
mutually exclusive (`ConflictingTimelocks`); a timelock unlocking at or
after `expires_at` is rejected (`TimelockPastExpiry`); `dual_sig` and
`quorum` *compose* (activation gates `fund`, the quorum gates `release` —
the test matrix drives the full lifecycle through both gates); milestone
tranche sums and subscription cadences are checked before any builder
runs. Templates are client-side only: they produce a plain `Escrow`, so
the vault layout, IDL, and Anchor program are untouched.

### Governance presets with declared override surfaces (AV-77)

AV-72 templates are free-form — every field is settable. A governance
preset (`TemplatePreset`) is the stricter sibling: the four canonical
compositions with audited default parameters plus a *declared override
surface* — the only field names `apply_template` accepts. Each preset
declares its surface up front (e.g. the auction preset allows `amount`,
`expires_at`, `dual_sig`, the timelocks, `mint`, and `grace_period_secs`,
but not `quorum` — adding attestor governance changes the preset's trust
shape; the arbitrated-dispute preset *does* declare `quorum`, since the
panel composition is its reviewed governance shape).

`TemplatePreset::apply_template(overrides)` takes per-field overrides as
`(name, OverrideValue)` pairs: an unknown name, a field declared by a
different preset, a mistyped value, or a repeated field is rejected with
`EscrowError::TemplateOverrideRejected` (code 141 — the preset's audited
shape is never silently widened). After the overrides apply, the
effective template re-runs the *full* AV-72 invariant validation —
conservation (tranche sums, subscription cadence, non-zero amount),
mutual exclusion (one clock per escrow), timelock-vs-expiry — and then
`build`, so builder-level thresholds (quorum policy, evidence deadline)
still gate; template rejections project onto the closest `EscrowError`.

`IndexedEscrow::apply_template` is the event-emitting entry point: it
stands up the escrow and records `Initialized` (seq 0) followed by
`TemplateApplied` (seq 1, `from == to ==` the current state — a
configuration application, not a lifecycle move), carrying the SHA-256 of
the effective parameters' canonical encoding
(`EscrowTemplate::params_hash`, golden-pinned in tests) so indexers and
auditors can verify exactly which parameters took effect. Like the AV-72
templates, presets are client-side composition: the vault layout and the
Anchor program are untouched.

## Escrow template library (AV-143)

AV-72 templates are one-shot composition helpers — not named, not
stored, not versioned. `escrow-state/src/template_library.rs` is the
registry on top of them: a `TemplateLibrary` where an
`EscrowBlueprint` packs amount, mint, release plan (milestone
tranches / subscription cadence / arbitrated dispute), timelocks,
quorum, the AV-66 fee tier ladder, and the AV-13/AV-90 vesting
curve under a name.

`publish` validates the blueprint by instantiating a probe escrow
(dummy parties — the validation is shape-based) and then stores it
as the next immutable version (`version = count + 1`): the library
can never hold a template `from_template` would fail to build.
`from_template(name, version, initializer, taker, now)` — `version ==
None` takes the latest — builds the AV-72 composition, applies the
fee ladder and vesting through the state machine's own builders, and
bumps the version's `use_count` / `last_used_at`. Instantiated escrows
lock the blueprint's version: publishing v2 does not change escrows
already created from v1. Every blueprint audits its creator,
creation time, version, and use count, so operators can see which
template versions are actually originating escrows.

## Protocol-fee revenue history (AV-144)

Which fee types earned, on which vaults, on which days — the
keeper/indexer revenue view. `escrow-state/src/fee_history.rs`
defines `FeeHistoryView`, a fold cursor over one escrow's
`IndexedEscrow` event stream that books every fee leg into
per-(vault, day) totals split by `FeeType`: `release` (AV-17 bps on
taker releases), `claim` (AV-17 bps on vesting claims), `resolve`
(AV-17 bps on dispute settlements), `streaming` (AV-100, folded into
the payout's `fee` leg and recovered per event as
`fee - protocol_fee_for(gross)`), and `arbiter` (AV-135, the separate
`arbiter_fee` leg on resolve-family settlements — never part of
`fees_paid`).

The per-kind classification (`fee_kind`) is exhaustive over
`EscrowEventKind` — a future variant fails to compile until its fee
semantics are decided, the `fund_delta` convention from
`event_sourcing.rs`. Days are Unix days (`at / 86_400`, UTC) in a
`BTreeMap`, so the deterministic JSON export
(`FeeHistoryView::to_json`, hand-written per the keeper.rs
convention) lists days ascending. `reconcile` cross-checks the fold
against the state machine's counters
(`release+claim+resolve+streaming == fees_paid()`,
`streaming == streaming_fees_accrued()`) — bit-identical on a
genesis replay. `from_snapshot` seeds the `streaming` base from the
snapshot's sub-counter (the snapshot.rs pass-through) and counts the
other types from the snapshot point on, the `MaterializedView`
`refunded = 0` precedent. `scan_fee_history` rolls per-vault views
into a fleet `FeeHistoryReport` (gappy vaults are listed in
`skipped`, never silently partial).

## Multi-bundle merge submission (AV-145)

AV-61 packs one batch report into per-`(mint, caller)` execution
bundles, but a keeper submitting a whole fleet would sign each bundle
separately. `escrow-state/src/bundle_merge.rs` merges several
`ExecutionBundle`s into `MergeSession`s — one multisig proposal / CLI
signing session each:

- Bundles sort by `(mint, caller)` (native-SOL first); actions keep
  bundle order.
- Every action gets an AV-88 compute-unit estimate; actions
  accumulate into a session until the next action would exceed the
  1.4M `CU_MAX_PER_TRANSACTION`, at which point a new session starts
  — the automatic split. (This needed CU rows for the lifecycle
  instructions — `initialize`/`fund`/`release`/`release_payout_split`
  — added to `INSTRUCTION_CU_TABLE` with the AV-88 heuristic ranking.)
- Each session builds one cross-bundle deduped ALT table (the
  batch.rs AV-37 convention: non-signers, first-seen order, cap 256)
  and remaps every action's `alt_index` into it.
- `MergeSession::signable_messages` compiles every action into a
  signable v0 message (base64, AV-71) against the merged table;
  `to_json` / `to_json_with_messages` render the deterministic
  submission packet carrying the merged bundle references.

Dry-run by construction: the merge only reads its input.

## Batch claim sweep (AV-146)

A keeper servicing a large vesting fleet needs one pass that sweeps
every ready `claim` — not one bundle per vault. `plan_claim_sweep`
(`escrow-state/src/claim_sweep.rs`) walks the same watch list as the
AV-20 keeper scan and packs exactly the vaults the scan would list
for `claim` (the `claim_action_for` single truth source — the sweep
never lists a claim the scan would not) into sweeps:

- Vaults sort by `escrow_id` (deterministic); each vault's claim
  carries its AV-88 compute-unit estimate, and vaults accumulate into
  a sweep until the next claim would exceed the 1.4M
  `CU_MAX_PER_TRANSACTION` — then a new sweep starts (the AV-145
  automatic split; a vault alone over budget keeps its own sweep,
  flagged `over_budget`, never dropped).
- Each sweep builds one cross-vault deduped ALT table (the batch.rs
  AV-37 convention: non-signers, first-seen order, cap 256) and
  remaps every item's `alt_index` into it.
- Every watched vault appears in the report's `results`: `swept`
  (with the `sweep_id`), `skipped` (machine-readable reason —
  `no_vesting_schedule` / `milestone_plan_attached` /
  `nothing_claimable` / `quorum_not_satisfied` / `timelock_locked`,
  the keeper predicate's conjuncts in check order), or `failed`
  (`cu_estimate_unavailable` — defensive per-vault isolation, the
  AV-88 table covers every keeper instruction kind).
- `ClaimSweepReport::to_json()` renders hand-serialized deterministic
  JSON: per-sweep items (action, `estimated_cu`, instruction
  accounts with `alt_index`), the merged `alt_table`, and the
  per-vault results list sorted by `escrow_id`.

Dry-run by construction: the plan only reads `&Escrow` snapshots —
no events, no clock access beyond the caller-supplied `now`, nothing
mutates. Amounts are as of the scan; the operator submits the sweeps,
then re-scans.

## Keeper watchtower (AV-147)

`scan_watchtower` (`escrow-state/src/watchtower.rs`) is the standing
off-chain monitor over the fleet's `IndexedEscrow` vaults — one pass,
three fleet-health alert classes for the conditions an operator pages
on:

- `expiry_soon`: a `Funded` vault whose deadline is inside the warning
  window (`"warning"`; `"critical"` inside the tighter tier) — the
  operator can still extend, release, or claim before the taker's
  cancel window opens. No-timeout vaults (`expires_at == u64::MAX`)
  and already-expired vaults never alert: the former have no
  deadline, the latter are the AV-20 keeper scan's `cancel_expired`
  territory.
- `arbitration_pending`: a `Disputed` vault open longer than the
  pending threshold — the arbiter or panel has not ruled.
- `rent_unclaimed`: a terminal vault (the AV-34 `close_vault` gate:
  `Cancelled` / `Released` / `Settled` / `Split` / `Declined`) whose
  rent-exempt deposit has sat unclaimed longer than the threshold,
  carrying the idle lamports (the same
  `vault_close_rent_reclaimed()` figure the AV-40 close scan
  reports). `Closed` vaults never alert (reclaimed); `Disputed`
  vaults never alert (the arbitration is still live).

This is the monitor, not the executor: the AV-136 expiry scan is the
per-vault edge-triggered operator warning with its re-arm ledger and
executable checklist; the AV-40/AV-139 scans plan the executable
close/sweep calls. The watchtower only raises the alert and names the
advisory remedy (`extend_expiry` / `resolve` / `close_vault`) — the
operator picks the executable path. Thresholds are
caller-configurable via `WatchtowerConfig` with conservative
defaults (3-day expiry warning / 12-hour critical, 7-day
arbitration-pending, 14-day rent-unclaimed); `validate()` fail-fasts
on nonsense before any alert is evaluated. `WatchtowerReport::to_json()`
renders hand-serialized deterministic JSON — alerts sorted by (kind,
`escrow_id`) — so two scans of the same watch list at the same `now`
are byte-identical. Dry-run by construction: pure reads, no events,
no clock access beyond the caller-supplied `now`.

## Keeper bounty for permissionless crank (AV-124)

The AV-48 permissionless crank ("the cranker receives nothing") made
timed-out vaults sweepable by any keeper, but it paid the keeper nothing —
a keeper running on real infrastructure (RPC, compute, transaction fees)
cranked at a loss. AV-124 adds an opt-in keeper bounty funded by the
initializer at vault creation:

- `initialize` accepts `keeper_bounty_pool` and `keeper_bounty_per_crank`
  (lamports). `Escrow::with_keeper_bounty(pool, per_crank)` applies them
  builder-style (Uninitialized-only, like `with_quorum` / `with_vesting`).
  `0` / `0` (the default) leaves the bounty disabled and keeps the AV-48
  unpaid-crank semantics — the pool is a bookkeeping number on the vault,
  not an on-chain transfer.
- A successful `crank_expired` pays `min(per_crank, pool)` to the caller
  (saturating — a pool smaller than the configured rate pays out the
  remainder) and debits the pool with `saturating_sub`. The return type is
  `(refund, penalty, bounty)`, following the `release` convention of
  returning payout-shaped tuples so the Anchor layer can size the
  lamport transfer; the Anchor `crank_expired` handler emits
  `KeeperBountyPaid` (`from == to == Cancelled`, `amounts.payout` is the
  bounty, `caller` is the cranker) when the bounty is non-zero.
- The bounty is paid only on the success path, after the unwind is final
  (the state is already `Cancelled` and all guards passed) — a failed
  guard debits nothing. When the pool is empty, `bounty == 0` and the
  crank falls back to the unpaid AV-48 behavior automatically.
- The bounty pool is additional inflow outside the principal (the AV-103
  appeal-bond precedent): the event-sourcing fold books
  `KeeperBountyPaid` as a no-op, so the `(locked, released, refunded)`
  triple is untouched by the payout.
- `scan_keeper_actions` annotates every crank action with
  `bounty_lamports` (the same `keeper_bounty_payable` the state machine
  pays) and a `bounty_unprofitable` flag. The flag compares the bounty
  against the estimated `crank_expired` execution cost: the crate's
  `cu_estimate` instruction estimate priced at the 10,000
  micro-lamports-per-CU planning assumption plus the 5,000-lamport base
  signature fee — for the canonical 3-account crank (vault + authority +
  refund_to, no mint, 1 signer) that is 13,814 CU → ⌈138.14⌉ = 139
  lamports priority fee + 5,000 = **5,139 lamports**. A bounty below the
  estimate is flagged unprofitable — the keeper may still crank at a
  loss (e.g. to clear its own watch list), but it does so informed.
- Orthogonal to the AV-103 appeal bond, the AV-122 dispute state machine,
  and AV-123 gasless intents: the check order (pause → reentrancy → …
  → expiry) is unchanged, and the bounty settles only after the state
  is final.

## Run the tests

```bash
cargo test -p escrow-state
```

Requires a stable Rust toolchain (`rustup toolchain install stable`).

**Configuration matrix (AV-19).** `combination_matrix_tests` in
`escrow-state/src/lib.rs` deterministically enumerates all 2⁶ = 64
combinations of the opt-in axes (dual_sig × quorum × vesting × milestones
× mint × protocol_fee — no RNG) and drives every combination through its
taker-payout path to `Released` and through `cancel_expired` to
`Cancelled`, asserting the conservation invariant
(`inflow == locked + released + refunded`) and the fee bound
(`fees_paid <= released`) throughout; a coverage self-test pins that the
enumeration hits every pairwise and triplewise value assignment, and
focused probes on the maximal configuration verify the documented check
orders, builder immutability after funding, and builder-order
irrelevance.

## Scheduled pause auto-recovery (AV-133)

`pause(authority, auto_unpause_at: Option<u64>)` — `Some(t)` arms a
scheduled auto-recovery at Unix timestamp `t`; `None` keeps the manual
`unpause` semantics. While paused, every clock-bearing state-changing
path runs `try_auto_unpause(now)` before the AV-46 `Paused` gate: at
`now >= t` the vault auto-recovers internally (no authority signature
consumed) and emits `Unpaused{auto:true}` (the `auto_unpause` flag on
the event). The schedule is consumed on fire; a manual `unpause`
clears it. Keeper reports list armed vaults with their exact recovery
timestamps (`pending_auto_unpause`).

Amending the recovery schedule while paused (AV-287): the bound pause authority may revise the armed recovery moment in place (`amend_auto_unpause_at`, pause-exclusive) — a fix that needs another day, or one that lands early, should not force an unpause-and-repause cycle that drops the emergency freeze in between. Only the schedule moves: the pause stays engaged and the authority is untouched. `Some(t)` arms a new moment (which must lie in the future — `InvalidAutoUnpauseAt`, code 359, otherwise) and an explicit `None` clears the schedule back to a manual pause. A manual pause has no table to revise, and an already-expired schedule is refused rather than rewritten — the matured promise still belongs to the next clock-bearing transition. The governance-delay protocol does not apply here: pause operations are emergency operations, not governance configuration changes. The `AutoUnpauseAtAmended` event (discriminant 149) carries no amounts; the amended schedule is read from the vault. No layout change: the schedule is an existing field. (Solana: pause governance.)

## Program-level circuit breaker (AV-163)

`escrow-state/src/circuit_breaker.rs` — the program-wide kill switch,
orthogonal to the AV-46 per-escrow pause. AV-46 freezes one escrow by
its opted-in pause authority; this freezes the whole program by an
independent pauser role (a security key / multisig — not any escrow's
initializer or taker, which are per-escrow roles and mean nothing at
program scope).

- **The switch**: `ProgramCircuitBreaker::new(pauser)` binds the pauser
  (the zero key is rejected — an unbound breaker is a silent footgun).
  `pause(pauser, now)` / `unpause(pauser, now)` toggle it; the toggle is
  strict like AV-46 (a second pause is `ProgramAlreadyPaused`, code 222;
  unpausing a running program is `ProgramNotPaused`, code 223) and the
  check order is the same: pauser authority (`InvalidPauser`, code 224)
  first, then toggle state.
- **The halt**: `require_running()` is the guard the program calls at
  the top of every state-changing instruction handler except
  `unpause_program` and `close_vault` (rent reclamation must stay
  available — the breaker never bricks funds). While engaged it returns
  `ProgramPaused` (code 221): fail fast, before any state is touched.
- **Structured audit**: every successful toggle appends a
  `CircuitAuditEntry` (`ProgramPaused` / `ProgramResumed` with the actor
  and the timestamp) to a bounded 32-entry ring — the program-level
  event log, oldest evicts first.
- **Anchor surface**: `pause_program` / `unpause_program` instructions
  (IDL discriminators `sha256("global:pause_program")[..8]` /
  `sha256("global:unpause_program")[..8]`, pinned by the IDL pipeline),
  the `CircuitBreaker` on-chain account mirror, and the four new error
  codes (221–224) mapped one-per-variant in the skeleton's `ErrorCode`
  enum. Adding instructions + errors is non-breaking under the AV-152
  semver gate, so the baseline is untouched.

Honest scope: the breaker does not reach into `Escrow` methods —
per-escrow transitions are unchanged; the program consults the guard at
the instruction boundary. There is no pauser rotation in this round
(the AV-47 per-escrow rotation exists; program-level rotation is a
governance action for a later item).

Layout growth: the vault body grows from 5506 to 5515 bytes (+9:
1-byte discriminant + 8-byte timestamp), `VAULT_SPACE_NO_QUORUM` from
5024 to 5033, `VAULT_SPACE` from 5514 to 5523, and the close-time rent
reclamation from 39_268_320 to 39_330_960 lamports
(`(128 + VAULT_SPACE) * 3480 * 2`).

## Tx fee-payer sponsorship (AV-164)

`escrow-state/src/sponsor.rs` — the policy layer over the
meta-transaction pattern. A release intent (AV-123) is signed by the
initializer, but the fee payer is whoever submits the transaction; this
module decides which fee payers an escrow trusts, how much fee spend
each trusted sponsor may incur, and how the operator's own fee budget
is spent. Orthogonal to the intent's relayer semantics: the intent
authorizes *what* happens (a release of a fixed amount to a fixed
destination); this module authorizes *who may pay the fee* and *how
much*.

- **The policy**: `SponsorPolicy::new(allowed, per_tx_cap,
  cumulative_cap, window_start, window_end)` — an allowlist of at most
  16 sponsor keys (zero keys and duplicates are rejected), a
  per-transaction lamport cap, a per-sponsor cumulative cap, and an
  effective window. `per_tx_cap == 0` / `cumulative_cap == 0` mean
  *unlimited*; `window_start == window_end == 0` means always active.
- **The gate**: `authorize(sponsor, amount, now)` checks in the
  crate's check order — allowlisted (`SponsorNotAllowed`, code 226)
  first, then window (`SponsorWindowInactive`, code 227), then per-tx
  cap (`SponsorAmountExceedsPerTxCap`, code 228), then cumulative cap
  (`SponsorCumulativeCapExceeded`, code 229). On success the amount is
  booked against the sponsor's cumulative usage (always tracked, even
  when the cap is unlimited, so `used_by` stays an honest spend
  meter); failed calls book nothing. Bad configuration fails at
  construction (`InvalidSponsorPolicy`, code 225).
- **The budget**: `SponsorBudget` is the keeper's fee-budget
  accounting. `fund` tops it up; `deduct(amount, sponsor, escrow,
  at)` spends it — a short deduct fails with `SponsorBudgetExhausted`
  (code 230) and changes nothing. Every successful deduct appends a
  `SponsorAuditEntry` (sponsor key + lamports + escrow + timestamp) to
  a bounded 64-entry ring, oldest evicts first — the sponsorship audit
  trail.

Honest scope: policy enforcement is off-chain — the fee payer is a
transaction-level property the program cannot compel; the keeper's bot
enforces the policy before submitting. The budget holds no lamports;
it is an accounting abstraction over the keeper's fee wallet, and the
audit records the *intent* to spend for reconciliation against actual
wallet balances. Cumulative usage is per-policy-instance (per escrow)
and does not persist across restarts. The Anchor skeleton maps the six
new error codes (225–230) one-per-variant; adding errors is
non-breaking under the AV-152 semver gate, so the baseline is
untouched.

## Keeper fleet liveness (AV-165)

`escrow-state/src/keeper_heartbeat.rs` — the liveness layer for a
fleet of keeper bots. The keeper scans are dry-run by construction, so
many bots can share the work — but a dead keeper silently drops its
escrow set. Keepers prove they are alive with Ed25519-signed
heartbeats; a missed-beat detector marks keepers that go quiet; a
standby keeper can claim an unhealthy keeper's escrow set. Orthogonal
to the AV-118 push notifications: that module *announces* actions,
this module *detects dead operators and reassigns their work*.

- **The heartbeat**: `Heartbeat { keeper, slot, at, last_action }`
  (last action is a compact status code: idle / cancel-expired /
  claim / rent-top-up / other), signed over canonical bytes prefixed
  with `KEEPER-HEARTBEAT-v1` — the domain-separation convention from
  AV-123, so a signature minted for any other envelope can never
  verify as a heartbeat. Every heartbeat is verified against the
  registered keeper key before any state moves (`HeartbeatSignatureInvalid`,
  code 233, on forgery or tampering).
- **The detector**: `HeartbeatRegistry::scan(current_slot, now)`
  marks a keeper unhealthy when `missed = (current_slot - last_slot)
  / expected_interval_slots >= max_missed_beats` *or* the slot
  staleness passes `stale_slot_threshold` — deterministic given the
  slot numbers. Transitions are edge-triggered (`HeartbeatMissed`
  audit, reported once). A stale heartbeat (`slot <= last_slot`) is
  an idempotent no-op: a delayed duplicate can neither rewind the
  record nor revive an unhealthy keeper.
- **The takeover**: `claim(standby, target, escrow_ids, now,
  current_slot)` — check order: claim shape (`InvalidClaim`, code
  236: zero standby, self-claim, over-long set), roster membership
  (both parties registered: `KeeperNotRegistered`, code 232), target
  health (`KeeperHealthy`, code 234: only unhealthy keepers are
  claimable — computed on the spot, so no scan needs to have run),
  then the first-come-first-served gate. The first standby wins; a
  lost race gets `ClaimConflict` (code 235) *and* a `ClaimConflict`
  audit entry (the AV-36 convention: the failed security-relevant
  call is still audited). A win appends `TakeoverClaimed` with the
  claimed escrow ids.
- **The recovery**: a fresh heartbeat from a claimed keeper revokes
  the claim (`ClaimRevoked` audit) — the original keeper is back, so
  the standby stands down. No split-brain.

Honest scope: the registry is off-chain fleet state, not an on-chain
account — the caller feeds `current_slot` / `now` (the crate has no
clock), and the escrow set is caller-supplied (capped at 256 per
claim). The detector only marks; the operator (or automation) decides
which standby claims which set. The Anchor skeleton maps the six new
error codes (231–236) one-per-variant; adding errors is non-breaking
under the AV-152 semver gate.

## Keeper leader election (AV-176)

`escrow-state/src/keeper_election.rs` — lease-based mutual leadership
for write operations across the keeper fleet. The keeper scans are
dry-run, so many bots can share the *read* work — but submitting
transactions needs exactly one writer, or two keepers race the same
crank and one burns priority fees on a doomed transaction. Orthogonal
to the AV-165 heartbeats: that module reports *liveness*, this module
decides *who may write*.

- **The campaign**: `acquire(keeper, now)` — the seat is open when no
  leader is recorded or the lease lapsed (`now >= lease_expires_at`,
  exclusive end). The winner takes term+1 and fencing-token+1 and a
  fresh `now + lease_ttl_secs` lease (`LeaderElected` audit, with the
  prior term so failovers are visible). Campaigning while holding a
  live lease is an idempotent renew (same term/token, extended lease,
  no audit noise); campaigning against another keeper's live lease is
  `ElectionHeld` (code 238).
- **The heartbeat**: `renew(keeper, now)` extends the lease but never
  campaigns — after a lapse it returns `LeaseExpired` (code 240)
  instead of silently re-electing, forcing an explicit re-`acquire`
  (new term, new token). Renewing as a non-leader is `NotLeader`
  (code 239).
- **The resignation**: `step_down(keeper, now)` opens the seat
  voluntarily; term and token are retained (monotonicity is never
  rewound), so the next campaign continues the sequence.
- **The fencing contract**: the new leader's token is strictly greater
  than every previous token. Writers stamp operations with their
  token; a write carrying a stale token belongs to a deposed leader
  and must be rejected downstream — the crate *issues* the token, the
  executor *enforces* it (a token nobody checks is just a number).

Honest scope: off-chain coordination state, not an on-chain account —
the caller feeds `now` (the crate has no clock). This is a
single-writer lease, not Raft: every keeper must consult the *same*
election state. The Anchor skeleton maps the four new error codes
(237–240) one-per-variant; adding errors is non-breaking under the
AV-152 semver gate.

## Keeper task sharding (AV-177)

`escrow-state/src/keeper_sharding.rs` — rendezvous-hash sharding of the
keeper watch list across fleet instances. One keeper *can* scan the
whole watch list, but as the fleet and vault count grow, every keeper
scanning everything wastes RPC budget and risks duplicate submissions.
Each vault is assigned to the member with the highest deterministic
`weight(member, vault)`; every instance computes the same assignment
independently, so the roster is either configured identically on every
keeper or distributed by the AV-176 leader. Orthogonal to the AV-37
batch lifecycle scan (that module scans *one* keeper's watch list;
this module decides *which* list each keeper scans) and to the AV-176
election (that module decides *who may write*; this module decides
*who watches what*).

- **The assignment**: `assign(vault)` → the winning keeper (ties break
  toward the earliest roster member; the roster is sorted at
  construction so caller argument order never matters).
  `shard_watch_list(vaults)` shards a whole list in input order. An
  empty roster assigns nothing (`None`) — the operator must notice
  the empty report; the map will not invent a keeper.
- **The membership change**: `update_members(new_members, vaults,
  now)` validates the new roster (`InvalidShardMembership`, code 241:
  zero key or duplicate), recomputes assignments, and returns the
  `ShardDiff` — added/removed members plus every moved vault with
  `from`/`to` (the zero key stands for "no keeper", so the diff stays
  total when a roster is empty on either side). Minimal disruption is
  a property of rendezvous hashing: removing a member moves exactly
  that member's vaults; adding a member moves vaults only *to* the new
  member. A `MembershipChanged` audit entry records the counts.
- **The report**: `report(vaults, now)` builds per-member vault counts
  (loads sum to the total; every member appears, even at zero) —
  built to be embedded in the keeper reporting layer alongside the
  `ShardDiff` change data.

Honest scope: the weight function is FNV-1a-64 with a splitmix64
finalizer — deterministic and well-distributed, but not
cryptographic; sharding is load distribution, not a security
boundary. Off-chain state, no on-chain account; the caller supplies
the vault list (the keeper scans own the watch list). The Anchor
skeleton maps the new error code (241) one-per-variant; adding errors
is non-breaking under the AV-152 semver gate.

## Funding amount bounds (AV-134)

`with_amount_bounds(min_amount, max_amount)` (`initialize_amount_bounds`
on the Anchor layer) is an `Uninitialized`-only opt-in builder for
deposit guardrails — the payment-fintech answer to fat-fingered or
mispriced transfers. `min_amount > max_amount` is `InvalidAmountBounds`
(code 196): an inverted window can never be a deliberate policy.

Once attached, `fund` rejects a deposit outside the window with
`AmountOutOfBounds` (code 197), checked after authority / plan / state
on the deposit itself; each `fund_tranche` call is gated on the tranche
amount the same way (the AV-111 plan still owns the tranche schedule —
the bounds cap each tranche, and the plan's overfund cap still applies).
A rejected deposit moves nothing: state, `funded_total` and the clocks
are untouched. With no bounds configured both deposit paths keep their
existing semantics (backward compatible). The bounds persist in the
vault tail (`min_funding_amount` / `max_funding_amount`, 9 bytes each),
ride the snapshot export, and are listed per vault in keeper reports
(`funding_bounds`).

Layout growth: the vault body grows from 5515 to 5533 bytes (+18: two
1-byte `Option` discriminants + two 8-byte bounds),
`VAULT_SPACE_NO_QUORUM` from 5033 to 5051, `VAULT_SPACE` from 5523 to
5541, and the close-time rent reclamation from 39_330_960 to 39_456_240
lamports (`(128 + VAULT_SPACE) * 3480 * 2`).

## Arbiter adjudication fee (AV-135)

The problem: arbitration is skilled labor, but nothing in the vault paid
for it — the arbiter settled disputes for free, which invites free-riding
(arbiters decline hard cases) or off-protocol side payments (opaque and
unenforceable). AV-135 makes the fee a first-class, opt-in term:
`with_arbiter_fee(flat_lamports, fee_bps)` (or the
`initialize_arbiter_fee` instruction) attaches a two-leg fee schedule
before funding — a fixed lamport slice, a basis-point rate on the
adjudicated share, or both (`fee_bps > 10_000` is `InvalidArbiterFee`,
code 198; `(0, 0)` disables the fee). Like the arbiter binding itself,
the terms are `Uninitialized`-only — reconfiguring a live escrow is
`InvalidStateTransition`.

At settlement, the fee is deducted from the taker's adjudicated share
and routed to the arbiter on all three dispute paths: `resolve`, the
panel settling vote, and the AV-55 default judgment. The charge is
`flat_lamports + floor(net_taker_share * fee_bps / 10_000)`, computed in
`u128` (no overflow: `u64::MAX * 10_000 < u128::MAX`) and capped at the
share, so the payout can never go negative. Deduction order is fixed and
documented: **AV-17 protocol fee first, AV-100 streaming fee second, the
arbiter fee last** — each fee slices the remainder of the previous one,
and the initializer's refund is never fee'd. With no fee configured the
three paths settle exactly as before (zero behavior change, backward
compatible).

The fee rides the settlement events (`Resolved`, `DefaultJudgment`,
`PanelResolved`) in `EventAmounts.arbiter_fee`, the keeper report
(`arbiter_fee` on the `Resolve` / `PanelJudgment` actions), and the
state snapshot — so indexers and arbiter bots see the arbitration
economics before and after the ruling.

**Arbiter fee amendment (AV-235).** A fee fixed at funding cannot
follow arbitration economics that change mid-deal — the dispute
grows more complex than the original flat leg priced, or the parties
agree the arbiter should cost less. `amend_arbiter_fee(initializer,
taker, flat_lamports, fee_bps)` (`Funded`-only, dual-signed) is the
post-funding revision path; `with_arbiter_fee` stays
`Uninitialized`-only as the initial set. Both legs are set
atomically in one call (no call moves the flat leg without the bps
leg), the zero convention matches the builder (a `0` leg clears that
leg, so `(0, 0)` disables the fee), and `fee_bps > 10_000` is
`InvalidArbiterFee` (198) — every failure leaves both legs untouched.
Only disputes arising after the amendment price at the new rate,
because `arbiter_fee_for` reads the live fields, while a dispute
already settled keeps the fee deducted at its own settlement
(`resolve` is terminal, so no settled dispute can ever be repriced)
and the amendment itself charges nothing. Orthogonal to AV-233's
protocol-fee amendment (that moves the fee on taker payouts; this
moves the fee on adjudicated shares — different field, different
rate, different deduction order). The `ArbiterFeeAmended` event
(discriminant 99) carries no amounts; the amended legs are read from
the vault. (Solana: dispute fee governance.)

Amending the appeal window after funding (AV-236): both parties may renegotiate how long the taker gets to appeal a future slash, without redeploying or refunding the escrow — the window set before funding may prove too short (a taker travelling when a slash lands) or too long (a legitimate slash stalled for a week). Dual-signed governance (`amend_appeal_window`, `Funded`-only); a zero window is `InvalidAppealWindow` (code 146). Only slashes executed after the amendment stamp their appeal deadline from the new window, while an already-stamped deadline keeps its original window, so no live appeal is ever shortened or extended. The `AppealWindowAmended` event (discriminant 100) carries no amounts; the amended window is read from the vault. No layout change: the window is an existing field. (Solana: dispute-appeal governance.)

Amending the appeal bond after funding (AV-238): both parties may renegotiate what the taker must lock when filing a future slash appeal, without redeploying or refunding the escrow — the bond set before funding may prove too low to deter a frivolous appeal once a real slash lands, or so high it prices a legitimate appeal out of reach. Dual-signed governance (`amend_appeal_bond`, `Funded`-only); a zero bond is `InvalidAppealBond` (code 158). Only appeals filed after the amendment lock the new bond, while an already-locked bond keeps its original amount, so no live appeal is ever topped up or refunded. The `AppealBondAmended` event (discriminant 102) carries no amounts; the amended bond is read from the vault. No layout change: the bond is an existing field. (Solana: dispute-appeal governance.)

Amending the expiry grace period after funding (AV-240): both parties may renegotiate how long past `expires_at` the escrow waits before it becomes expiry-eligible, without redeploying or refunding the escrow — the skew the parties actually face can grow or shrink after funding. Dual-signed governance (`amend_grace_period`, `Funded`-only); `expires_at + grace_secs` overflowing `u64` is `InvalidGracePeriod` (code 115). Amending to zero removes the grace. Only expiry determinations after the amendment follow the new value, while already-executed determinations are history. The `GracePeriodAmended` event (discriminant 103) carries no amounts; the amended grace period is read from the vault. No layout change: the grace period is an existing field. (Solana: operations governance.)

Amending the evidence deadline after funding (AV-241): both parties may renegotiate how long the escalating party gets — measured from `disputed_at` — to disclose the dispute evidence, without redeploying or refunding the escrow — a complex claim can need a longer window than the optimistic one negotiated at setup, or a fast-moving dispute can make a long window an invitation to stall. Dual-signed governance (`amend_evidence_deadline`, `Funded`-only); no arbitration mechanism configured is `InvalidArbiter` (code 108) and a zero deadline is `InvalidEvidenceDeadline` (code 138). A live dispute can never be amended — it is `Disputed`, not `Funded` — so its computed due date is untouched, while a dispute escalated after the amendment measures its window from the new value. The `EvidenceDeadlineAmended` event (discriminant 104) carries no amounts; the amended deadline is read from the vault. No layout change: the deadline is an existing field. (Solana: arbitration-discipline governance.)
Amending the arbitration deadline after funding (AV-242): both parties may renegotiate how long the arbiter gets — measured from `disputed_at` — before either party may trigger the pre-agreed fallback split, without redeploying or refunding the escrow — a complex claim can need a longer ruling window than the optimistic one negotiated at setup, or a fast-moving dispute can make a long window an invitation to stall. Dual-signed governance (`amend_arbitration_deadline`, `Funded`-only); no default judgment configured is `DefaultJudgmentNotDue` (code 129) and a zero deadline is the same `DefaultJudgmentNotDue` (code 129, the builder's rejection). Only `deadline_secs` changes — `default_taker_amount` and `default_confirmed` are untouched. A live dispute can never be amended — it is `Disputed`, not `Funded` — so its trigger window is untouched, while a dispute escalated after the amendment measures its window from the new value (`trigger_default_judgment` reads the deadline live). The `ArbitrationDeadlineAmended` event (discriminant 105) carries no amounts; the amended deadline is read from the vault. No layout change: the deadline is an existing field. (Solana: arbitration-discipline governance.)
Amending the default judgment terms after funding (AV-286): both parties may renegotiate the whole fallback — deadline and split together — without redeploying or refunding the escrow — the fallback negotiated before funding may prove too generous, too tight, or too short-windowed once the deal is live. Dual-signed governance (`amend_default_judgment`, `Funded`-only); no default judgment configured is `DefaultJudgmentNotDue` (code 129, the builder's rejection — post-funding installation is refused fail-closed) and the new terms reuse the builder gates (a zero deadline is the same `DefaultJudgmentNotDue`, a taker share above the lockup is `ReleaseExceedsLocked`). Only the terms change — and `default_confirmed` resets to `false`: the old confirmation countersigned the old terms, so the revised fallback needs a fresh taker countersign before `trigger_default_judgment` can fire on it, and until then the trigger fails `DefaultJudgmentNotDue`. A live dispute can never be amended — it is `Disputed`, not `Funded` — so its fallback is untouched, while a dispute escalated after the amendment measures its window from the new terms. Re-affirming the identical terms is a silent no-op that resets nothing. This differs from AV-242's deadline-only amendment precisely in the confirmation reset: AV-242 moves one field and preserves the confirmation, AV-286 moves both terms and therefore voids it. The `DefaultJudgmentAmended` event (discriminant 148) carries no amounts; the amended terms are read from the vault. No layout change: the terms and the confirmation bit are existing fields. (Solana: arbitration-fallback governance.)
Amending the claim cooldown after funding (AV-243): both parties may renegotiate the minimum slot distance between two taker claims, without redeploying or refunding the escrow — a fast-settling escrow can find a long cooldown an unnecessary drag, or a vesting escrow can find a short cooldown an invitation to drip claims slot by slot. Dual-signed governance (`amend_claim_cooldown`, `Funded`-only); no configuration precondition — an unconfigured escrow simply gains a cooldown — and `0` is legal (disables the cooldown, the builder's zero sentinel). Only `claim_cooldown_slots` changes — `last_claim_slot` is untouched, so the next claim's eligibility is recomputed live from the new value, while a taker who never claimed stays eligible for the first claim; the vesting claim gate stacks unchanged through the same `claim_cooldown_gated` path. The `ClaimCooldownAmended` event (discriminant 106) carries no amounts; the amended cooldown is read from the vault. No layout change: the cooldown is an existing field. (Solana: payment-fintech claim throttling.)
Amending the delivery-confirmation deadline after funding (AV-244): both parties may renegotiate the timestamp by which the taker must confirm receipt, without redeploying or refunding the escrow — a deadline set before funding assumes a delivery pace the parties may no longer face, and a slipped schedule can make the original date either impossibly tight or meaninglessly loose. Dual-signed governance (`amend_delivery_deadline`, `Funded`-only); a zero deadline is `AmountMismatch` (the builder's rejection — `0` is the "no deadline" sentinel, so there is no cancel-deadline path in this item). Only `delivery_deadline_at` changes — the penalty rate and the late flag are untouched. Confirmations after the amendment are judged against the new value (`confirm_delivery_at` reads the live field), while a delivery already confirmed keeps its first-won stamp, so moving the deadline can neither rewrite nor wash clean a recorded lateness; an escrow with no deadline gains one on first amendment. The `DeliveryDeadlineAmended` event (discriminant 107) carries no amounts; the amended deadline is read from the vault. No layout change: the deadline is an existing field. (Solana: delivery-performance governance.)
Amending the late-delivery penalty rate after funding (AV-245): both parties may renegotiate the rate sliced off a late-confirmed payout, without redeploying or refunding the escrow — a long-delayed delivery can make the original rate look trivial, or a barely-late one can make it look punitive. Dual-signed governance (`amend_late_delivery_penalty_bps`, `Funded`-only); a rate above 10_000 bps is `InvalidPenalty` (the AV-206 validator) and `0` is legal (no late penalty from here on). Only `late_delivery_penalty_bps` changes — the deadline and the late flag are untouched. A late-stamped but not-yet-released delivery reprices at the amended rate (`release` and `release_milestone` share the live-rate helper), while amounts already released and penalties already banked are never restated. The `LateDeliveryPenaltyAmended` event (discriminant 108) carries no amounts; the amended rate is read from the vault. No layout change: the rate is an existing field. (Solana: delivery-performance governance.)
Amending the release cooling window after funding (AV-246): both parties may renegotiate how long an announced release intent must age before `release` may settle, without redeploying or refunding the escrow — a fast-moving deal can make a long cooling window an invitation to stall, or a contested one can make a short window no veto at all. Dual-signed governance (`amend_release_cooling`, `Funded`-only); no value rejection — any `u64` is a legal window and `0` is legal (cooling off). Only `release_cooling_secs` changes — the intent timestamp is untouched, so a live announced intent is re-measured against the new window, while a vetoed intent stays vetoed. An unconfigured escrow gains a window on first amendment. The `ReleaseCoolingAmended` event (discriminant 109) carries no amounts; the amended window is read from the vault. No layout change: the window is an existing field. (Solana: release governance anti-front-running.)
Amending one milestone tranche's claim deadline after funding (AV-247): both parties may renegotiate the timestamp by which a single tranche must be claimed, without redeploying or refunding the escrow — a slipped confirmation can make the original deadline impossibly tight, or a fast-settling tranche can make it meaninglessly loose. Dual-signed governance (`amend_milestone_claim_deadline`, `Funded`-only); no plan or an out-of-range tranche is `InvalidMilestones`, and `0` is legal (it cancels the tranche's deadline). Only that tranche's deadline changes — amounts, due dates, other tranches and settled amounts are untouched. The claim gate reads the deadline live, so extending rescues a tranche that would have expired and shortening expires it sooner, while claimed or skipped tranches keep their settlements and an unconfirmed tranche still needs its confirmations first. The `MilestoneClaimDeadlineAmended` event (discriminant 110) carries no amounts; the amended deadline is read from the vault. No layout change: the deadline is an existing field. (Solana: milestone claim governance.)
Amending the per-extension expiry-increase cap after funding (AV-248): both parties may renegotiate the bound a single extension may move the deadline, without redeploying or refunding the escrow — a slipped schedule can make the original bound impossibly tight, or a fast-moving deal can make it meaninglessly loose. Dual-signed governance (`amend_max_extension_secs`, `Funded`-only); no value rejection — any `u64` is a legal cap and `0` is legal (it closes future extensions). Only `max_extension_secs` changes — the deadline and the extension count are untouched, so extensions already made keep their moves and their count, and the next extension is judged against the live cap. The `MaxExtensionAmended` event (discriminant 111) carries no amounts; the amended cap is read from the vault. No layout change: the cap is an existing field. (Solana: expiry-extension governance.)
Amending the absolute timelock after funding (AV-249): both parties may renegotiate the timestamp before which taker payouts stay locked, without redeploying or refunding the escrow — a slipped schedule can make the original lock trap funds past their need, or a fast-moving deal can make it meaningless. Dual-signed governance (`amend_timelock`, `Funded`-only); a nonzero unlock beside a configured relative or slot lock is `InvalidTimelock` (the builder's one-clock rule), and `0` is legal (it cancels the absolute lock). Only `timelock` changes — the relative and slot locks are untouched, and amounts already released are never restated. The payout gates read the lock live, so lengthening pushes a payout out, shortening pulls it in, and clearing unlocks immediately. The `TimelockAmended` event (discriminant 112) carries no amounts; the amended lock is read from the vault. No layout change: the lock is an existing field. (Solana: timelock governance.)
Amending the relative timelock after funding (AV-250): both parties may renegotiate the seconds-long window, measured from funding, before which taker payouts stay locked, without redeploying or refunding the escrow — a slipped schedule can make the original window trap funds past their need, or a fast-moving deal can make it meaningless. Dual-signed governance (`amend_relative_timelock`, `Funded`-only); a nonzero window beside a configured absolute or slot lock is `InvalidTimelock` (the builder's one-clock rule), and `0` is legal (it cancels the relative lock). Only `relative_timelock_secs` changes — the absolute and slot locks are untouched, the `fund_at` anchor never moves, and amounts already released are never restated. The payout gates read the window live against the unchanged anchor, so lengthening pushes a payout out, shortening pulls it in, and clearing unlocks immediately. The `RelativeTimelockAmended` event (discriminant 113) carries no amounts; the amended window is read from the vault. No layout change: the window is an existing field. (Solana: timelock governance.)
Amending the slot timelock after funding (AV-251): both parties may renegotiate the slot-count window, measured from the funding slot, before which taker payouts stay locked, without redeploying or refunding the escrow — a slipped schedule can make the original window trap funds past their need, or a fast-moving deal can make it meaningless. Dual-signed governance (`amend_slot_timelock`, `Funded`-only); a nonzero window beside a configured absolute or relative lock is `InvalidTimelock` (the builder's one-clock rule), and `0` is legal (it cancels the slot lock). Only `slot_timelock_slots` changes — the absolute and relative locks are untouched, the `fund_slot` anchor never moves, and amounts already released are never restated. The slot gates read the window live (`fund_slot + slots`, saturating, so a near-`u64::MAX` anchor plus a long lock never wraps into an early unlock), so lengthening pushes a payout out, shortening pulls it in, and clearing unlocks immediately. The `SlotTimelockAmended` event (discriminant 114) carries no amounts; the amended window is read from the vault. No layout change: the window is an existing field. (Solana: timelock governance.)
Amending the unclaimed-rent sweep grace period after funding (AV-252): both parties may renegotiate how long a terminal vault's rent may sit unclaimed before the sweep becomes callable, without redeploying or refunding the escrow — a slow claim can make a short grace sweep rent the initializer still intends to reclaim, or a fast one can make a long grace trap rent for a month. Dual-signed governance (`amend_rent_sweep_grace`, `Funded`-only); any `u64` is legal and `0` is legal (it restores the 30-day default). Only `rent_sweep_grace_secs` changes — `terminal_at` is never restated, and a terminal or closed vault cannot be amended, so a sweep already performed is never undone. The sweep gate reads the grace live against the unchanged terminal stamp, so lengthening pushes a sweep out, shortening pulls it in, and clearing to `0` restores the 30-day horizon. The `RentSweepGraceAmended` event (discriminant 115) carries no amounts; the amended grace is read from the vault. No layout change: the grace is an existing field. (Solana: rent sweep governance.)
Amending the tiered protocol-fee schedule after funding (AV-253): both parties may renegotiate what later taker payouts cost by amount tier, without redeploying or refunding the escrow — a deal that grows may justify a lower top-tier rate, or a deal that shrinks a higher one. Dual-signed governance (`amend_fee_schedule`, `Funded`-only); a nonzero flat rate refuses the schedule (mutual exclusion, fail-fast), and the builder's tier validation applies unchanged (non-empty, at most 8 tiers, each `bps <= 10_000`, floors strictly ascending). Only `fee_schedule` changes — the flat rate and the cap are untouched, and fees already charged or withdrawn are never restated. Later payouts price live from the amended schedule, so a payout reprices at the new tier the moment the amendment lands. The `FeeScheduleAmended` event (discriminant 116) carries no amounts; the amended schedule is read from the vault. No layout change: the 81-byte schedule region is always resident and rewritten in place. (Solana: fee governance / payment fintech.)
Amending the streaming fee rate after funding (AV-254): both parties may renegotiate what later payouts cost per second of funded time, without redeploying or refunding the escrow — a deal that stretches may justify a lower per-second rate, or a deal that accelerates a higher one. Dual-signed governance (`amend_streaming_fee`, `Funded`-only); any `u64` is legal and `0` is legal (it disables further accrual, the builder's `0` semantics, not a refund). Only `streaming_fee_rate` changes — `fund_at` is never restated and fees already charged are never clawed back. The charge gate reads the rate live against the unchanged `fund_at` anchor, so raising the rate bills the difference on the next settlement and lowering it bills nothing new. The `StreamingFeeRateAmended` event (discriminant 117) carries no amounts; the amended rate is read from the vault. No layout change: the rate is an existing field. (Solana: fee governance / payment fintech.)
Amending the bound rent payer after funding (AV-255): both parties may renegotiate who receives the rent-exempt deposit on close, without redeploying or refunding the escrow — a payer that can no longer receive may need replacing, or a new custodian may take over the vault's rent. Dual-signed governance (`amend_rent_payer`, `Funded`-only); a zero payer is refused (`InvalidRentPayer`, the builder's gate), and re-affirming the current payer is a no-op that emits no event. Only `rent_payer` changes — the close authority is untouched, no closed state is touched, and no rent is recomputed. The close reads the recipient live through the amended payer, so a close after the amendment pays the new payer while a close before it paid the old one. There is deliberately no unbind-to-`None` path: an unbound escrow keeps the initializer-reclaims default. The `RentPayerAmended` event (discriminant 118) carries no amounts; the amended payer is read from the vault. No layout change: the payer field is already resident and rewritten in place. (Solana: rent economics governance.)
Amending the bound referrer after funding (AV-256): both parties may renegotiate who receives the referral share on later releases and at what rate, without redeploying or refunding the escrow — a referrer that can no longer receive may need replacing, or a deal that grows may justify a lower rate. Dual-signed governance (`amend_referrer`, `Funded`-only); a zero referrer or a rate above the 20% cap is refused (`InvalidReferral`, the builder's gates), and re-affirming the current pair is a no-op that emits no event. Only `referrer`/`referral_bps` change — referral already charged is never clawed back. The release gate reads the binding live, so a release after the amendment charges the new referrer at the new rate while a release before it charged the old one. There is deliberately no unbind-to-`None` path: an unbound escrow keeps the no-referrer default. The `ReferrerAmended` event (discriminant 119) carries no amounts; the amended binding is read from the vault. No layout change: the referrer fields are already resident and rewritten in place. (Solana: referral-revenue governance / payment fintech.)
Amending the penalty escalation schedule after funding (AV-257): both parties may renegotiate how fast the anti-griefing penalty grows per day past expiry and where it caps, without redeploying or refunding the escrow — a meter that proves too lenient may need steepening, or a cap that makes late performance pointless may need lowering. Dual-signed governance (`amend_penalty_escalation`, `Funded`-only); a rate or cap above 100% is refused (`InvalidPenalty`, the builder's gate), and re-affirming the current pair is a no-op that emits no event. Only the escalation rate/cap change — the base penalty rate is untouched and the meter origin never moves. The cancel gate reads the schedule live, so a cancel after the amendment prices from the new schedule while a cancel before it priced from the old one. The `PenaltyEscalationAmended` event (discriminant 120) carries no amounts; the amended schedule is read from the vault. No layout change: the escalation fields are already resident and rewritten in place. (Solana: penalty governance / payment fintech risk.)
Amending the refund address after funding (AV-258): both parties may renegotiate where a unilateral refund goes, without redeploying or refunding the escrow — a whitelisted address that can no longer receive may need replacing, or an escrow that never set one may need its first binding. Dual-signed governance (`amend_refund_address`, `Funded`-only); a zero address is refused (`RefundAddressMismatch`, the builder's gate), and re-affirming the current effective recipient is a no-op that emits no event. Only `refund_to` changes — the initializer/taker identities are never restated and no settled refund is ever rewritten. The cancel paths read the address live, so a cancel after the amendment routes to the new address while a cancel before it routed to the old one. There is deliberately no unbind-to-`None` path: callers that want the default route pass the initializer's key. The `RefundAddressAmended` event (discriminant 121) carries no amounts; the amended address is read from the vault. No layout change: the refund address field is already resident and rewritten in place. (Solana: refund-routing governance / payment fintech.)
Amending the base penalty rate after funding (AV-259): both parties may renegotiate what dragging a deal to expiry costs, without redeploying or refunding the escrow — a rate that proves too lenient may need steepening, or a rate that makes late performance pointless may need cutting to zero. Dual-signed governance (`amend_penalty_bps`, `Funded`-only); a rate above 100% is refused (`InvalidPenalty`, the builder's gate), `0` is legal (it switches the penalty off), and re-affirming the current rate is a no-op that emits no event. Only `penalty_bps` changes — the escalation schedule and the meter origin never move, and the escalation headroom is recomputed live as `cap − new base`. The cancel gate reads the base rate live, so a cancel after the amendment prices from the new rate while a cancel before it priced from the old one. The `BasePenaltyAmended` event (discriminant 122) carries no amounts; the amended rate is read from the vault. No layout change: the base rate field is already resident and rewritten in place. (Solana: penalty governance / payment fintech risk.)
Amending the interest rate after funding (AV-260): both parties may renegotiate what the locked principal earns, without redeploying or refunding the escrow — a rate that proves too generous may need cutting, or a rate that no longer compensates the taker may need raising. Dual-signed governance (`amend_interest_rate`, `Funded`-only); a rate above 100% APR is refused (`InvalidInterestRate`, the builder's gate), `0` is legal (it pauses all future accrual), a `Disputed` escrow is refused (the dispute window settles at the frozen rate), and re-affirming the current rate is a no-op that emits no event. Only `interest_rate_bps` changes — already-accrued yield is never clawed back, and in compound mode the folded yield stays principal with the next accrual pricing the grown principal at the new rate. The accrual clock reads the rate live, so a new rate prices the next slice the moment the amendment lands. Pinned pause semantics: `settle_interest` returns early at rate 0 without advancing `interest_accrual_base`, so a paused window is repriced at the resumed rate on the next settlement, never skipped. The `InterestRateAmended` event (discriminant 123) carries no amounts; the amended rate is read from the vault. No layout change: the rate field is already resident and rewritten in place. (Solana: yield governance.)
Amending the oracle price gate after funding (AV-261): both parties may renegotiate the market condition a payout waits on, without redeploying or refunding the escrow — a floor that proves too strict may need lowering, or a ceiling that no longer reflects the market may need moving. Dual-signed governance (`amend_price_gate`, `Funded`-only); only a gate already configured may be revised — an ungated escrow is refused fail-closed (`InvalidPriceGate`, post-funding installation would add a restriction the taker never funded under), there is deliberately no clearing path (the signature takes a `PriceGate` by value, never an `Option`), a zero target is refused (`InvalidPriceGate`, the builder's gate), and re-affirming the current gate is a no-op that emits no event. The revision replaces the gate wholesale — direction, target and staleness bound together, never partially — and the 18-byte gate region is rewritten in place with no layout change. The gated payout paths read the gate live, so a new gate governs the next gated payout the moment the amendment lands, while a payout already settled keeps the gate it settled under; the TWAP gate is untouched. The `PriceGateAmended` event (discriminant 124) carries no amounts; the amended gate is read from the vault. (Solana: oracle-gate governance / DeFi conditional settlement.)
Amending the TWAP price gate after funding (AV-262): both parties may renegotiate the averaged market condition a payout waits on, without redeploying or refunding the escrow — a window that proves too slow to react may need shortening, or a threshold that no longer reflects the market may need moving. Dual-signed governance (`amend_twap_gate`, `Funded`-only); only a gate already configured may be revised — a TWAP-ungated escrow is refused fail-closed (`InvalidTwapGate`, post-funding installation would add a restriction the taker never funded under), there is deliberately no clearing path (the signature takes a `TwapGate` by value, never an `Option`), a zero window or zero target is refused (`InvalidTwapGate`, the builders' gate), and re-affirming the current gate is a no-op that emits no event. The revision replaces the gate wholesale — direction, target, window and staleness bound together, never partially — and the 26-byte gate region is rewritten in place with no layout change. The gated payout paths read the gate live, so a new gate governs the next gated payout the moment the amendment lands — including the full-window history coverage requirement, so a shorter window can pass on history the old window could not cover — while a payout already settled keeps the gate it settled under; the single-point gate is untouched. The `TwapGateAmended` event (discriminant 125) carries no amounts; the amended gate is read from the vault. (Solana: oracle-gate governance / DeFi conditional settlement.)
Rotating the dual-control checker after funding (AV-263): both parties may replace the approver of the maker-checker release protocol, without redeploying or refunding the escrow — a checker key that is lost, compromised, or moved to a new wallet must not freeze every payout behind an approval nobody can give. Dual-signed governance (`rotate_dual_control_checker`, `Funded`-only); only an escrow that already opted into dual control may rotate — a never-opted-in escrow is refused fail-closed (`InvalidDualControl`, post-funding installation would turn a single-step release into a two-step protocol the taker never funded under), a zero checker is refused (`InvalidDualControl`, the builder's gate), a live declaration blocks the rotation (`DualControlIntentExists` — the intent stores no checker key and confirmation authenticates against the live checker, so rotating mid-flight would hand an unseen declaration to a checker who never saw it), and re-affirming the current checker is a no-op that emits no event. The 33-byte checker region is rewritten in place with no layout change. The two-step protocol reads the checker live, so the new checker governs from the next initiate/confirm cycle with no approval-power transfer ever in flight, while a declaration already settled keeps the checker it settled under. The `DualControlCheckerRotated` event (discriminant 126) carries no amounts; the new checker is read from the vault. (Solana: maker-checker governance.)
Rotating the credential-gate issuer after funding (AV-264): both parties may replace the compliance issuer whose credentials qualify the taker for release, without redeploying or refunding the escrow — an issuer key that is lost, compromised, or moved to a new wallet must not freeze every payout behind a credential nobody can mint. Dual-signed governance (`rotate_credential_issuer`, `Funded`-only); only an escrow that already bound a credential gate may rotate — a never-bound escrow is refused fail-closed (`CredentialGateNotBound`, post-funding installation would add a qualification the taker never funded under), a zero issuer is refused (`InvalidCredentialIssuer`, the builder's gate), and re-affirming the current issuer is a no-op that emits no event. The 32-byte issuer region is rewritten in place with no layout change. The gate reads the issuer live, so the new issuer governs from the next credentialed release — and a credential minted by the old issuer stops verifying the moment the rotation lands, even if never used, and must be re-signed by the new issuer — while a release already settled keeps the issuer it settled under. The `CredentialIssuerRotated` event (discriminant 127) carries no amounts; the new issuer is read from the vault. (Solana: compliance-custody governance.)
Revising the dead-man's switch inactivity threshold after funding (AV-265): both parties may renegotiate how long an escrow must sit idle before the heir may reclaim it, without redeploying or refunding the escrow — a threshold that proves too short may let the heir in while the parties are merely slow, or one that proves too long may strand funds past any reasonable dormancy. Dual-signed governance (`amend_deadman_inactivity`, `Funded`-only); only an escrow whose switch is already configured may revise — an unconfigured escrow is refused fail-closed (`InvalidDeadmanConfig`, post-funding installation would add a recovery path the taker never funded under), a zero threshold is refused (`InvalidDeadmanConfig`, the builder's gate), and re-affirming the current threshold is a no-op that emits no event. Only the threshold changes — the heir and the activity clock are untouched, since the revision takes no clock parameter and never resets the timer. The eligibility gate reads the threshold live, so the new threshold governs from the next claim: tightening can make an already-idle escrow eligible at once (the elapsed time is re-judged, not restated) while loosening can revoke an already-satisfied but unexecuted eligibility, and a claim already settled keeps the threshold it settled under. The `DeadmanInactivityAmended` event (discriminant 128) carries no amounts; the new threshold is read from the vault. (Solana: dormancy-recovery governance.)
Revising the keeper-bounty per-crank amount after funding (AV-266): both parties may reprice the incentive that pays a permissionless keeper to crank an expired escrow, without redeploying or refunding the escrow — a per-crank amount that proves too low may leave timed-out vaults uncranked, or one that proves too high may overpay for a sweep anyone would have run. Dual-signed governance (`amend_keeper_bounty_per_crank`, `Funded`-only); only an escrow with a non-zero per-crank amount may revise — an escrow with a zero per-crank amount is refused fail-closed (`InvalidKeeperBounty`, code 357, post-funding installation would add a bounty the taker never funded under), and re-affirming the current amount is a no-op that emits no event. A zero amount is a legal revision that closes future payouts (the builder's 0-means-no-bounty semantics), and closing is final through this path — a closed escrow reads as unconfigured, so reopening is refused fail-closed rather than installed. Only the per-crank amount changes — the pool is untouched (a consumable balance, never topped up by a revision) and bounty already paid is untouched, so an exhausted pool still pays `0` after any revision and the revision itself never revives the bounty. The payout path reads the amount live (`keeper_bounty_payable() = min(per_crank, pool)` at payment time), so the new amount governs from the next `crank_expired` — raising it raises the next payout up to the pool, lowering it lowers the next payout, and a crank already settled keeps the amount it settled under. The `KeeperBountyPerCrankAmended` event (discriminant 129) carries no amounts; the new amount is read from the vault. (Solana: keeper bounty governance.)
Revising the flat slash deadline after funding (AV-267): both parties may renegotiate when a taker's default becomes slashable, without redeploying or refunding the escrow — a deadline that proves too early may penalize a merely slow performer, or one that proves too late may leave a genuine default unenforced for months. Dual-signed governance (`amend_slash_deadline`, `Funded`-only); only an escrow carrying flat slash terms may revise — an escrow with no terms is refused fail-closed (`SlashNotEligible`, post-funding installation would add a penalty clause the taker never funded under), a ladder escrow is refused with `InvalidSlashLadder` (its deadlines live in the rung table and belong to `amend_slash_ladder`), an escrow whose one-shot slash already executed is refused (`SlashNotEligible` — `penalty_paid > 0`, or `pool_slashed > 0` on the AV-106 insurance-pool path, where the penalty lands in the pool), and re-affirming the current deadline is a no-op that emits no event. A zero deadline is a legal revision meaning immediately slashable. Only the deadline changes — the penalty account and any penalty already banked are untouched, since a revision never restates a settled penalty. The slash path reads the deadline live, so the new deadline governs from the next eligibility check: tightening can make an unexecuted default slashable at once while loosening can defer an already-satisfied but unexecuted eligibility, and a slash already settled keeps the deadline it settled under. The `SlashDeadlineAmended` event (discriminant 130) carries no amounts; the new deadline is read from the vault. (Solana: payment risk control.)
Revising the funding amount window after funding (AV-268): both parties may renegotiate the deposit guardrails after the first tranche lands, without redeploying or refunding the escrow — a window that proves too tight may block the remaining tranches, or one that proves too loose may admit a mispriced deposit the parties no longer want. Dual-signed governance (`amend_amount_bounds`, `Funded`-only); only an escrow already carrying a window may revise — an escrow with no window is refused fail-closed (`InvalidAmountBounds`, code 196, post-funding installation would add a deposit gate the taker never funded under), the whole pair is replaced at once (no partial revision) and an inverted window is refused with `InvalidAmountBounds` leaving the original window untouched, and re-affirming the current window is a no-op that emits no event. Only the window fields change — `funded_total` and the funding plan's total and tranche budget are untouched, since the window caps each tranche rather than rescheduling the plan. The tranche path reads the live window at each deposit, so the new window governs from the next `fund_tranche` call while tranches already funded keep the window they funded under. The `AmountBoundsAmended` event (discriminant 131) carries no amounts; the new window is read from the vault. (Solana: 注资治理.)
Revising the milestone late-penalty rate after funding (AV-269): both parties may renegotiate what a late milestone costs, without redeploying or refunding the escrow — a rate that proves too lenient may need steepening, or one that makes late performance pointless may need cutting to zero. Dual-signed governance (`amend_milestone_late_penalty_bps`, `Funded`-only); only an escrow that already has a milestone due-date table may revise — a plan-less or table-less escrow is refused fail-closed (`InvalidMilestones`, code 110, post-funding installation would add a forfeiture term the taker never funded under, so penalty semantics can never be installed on a table-less escrow after funding), a rate above 100% is refused (`InvalidPenalty`, the builder's gate, leaving the original rate untouched), `0` is legal (it switches future late penalties off), and re-affirming the current rate is a no-op that emits no event. Only the rate changes — the due-date table is untouched and penalty already banked is never restated, since a settled tranche keeps the rate it settled under. The release path reads the rate live, so the new rate governs from the next `release_milestone` late pricing — raising it raises the next late tranche's forfeiture, lowering it lowers it, and cutting it to zero pays the next late tranche in full. The `MilestoneLatePenaltyBpsAmended` event (discriminant 132) carries no amounts; the new rate is read from the vault. No layout change: the rate field is already resident and rewritten in place. (Solana: milestone fulfillment governance.)
Revising the funding plan's tranche budget after funding (AV-270): both parties may renegotiate how many staged deposits the plan allows, without redeploying or refunding the escrow — a budget that proves too tight may strand the remaining funding, or one that proves too loose may admit deposits the parties no longer want to schedule. Dual-signed governance (`amend_funding_plan_max_tranches`, `Funded`-only); only an escrow already carrying a funding plan may revise — an escrow with no plan is refused fail-closed (`InvalidFundingPlan`, code 173, post-funding installation would add a staged-deposit schedule the taker never funded under), the new budget reuses the `FundingPlan::new` gate (`0` is refused) and a budget below `tranches_used` is refused with the same error leaving the original plan untouched, and re-affirming the current budget is a no-op that emits no event. Only `max_tranches` changes — the plan total stays pinned to the escrow's amount and `funded_total` and `tranches_used` are untouched, since the plan is rebuilt preserving the consumed count. The tranche path reads the live budget at each deposit, so the new budget governs from the next `fund_tranche` call — raising it opens further tranches, shrinking it to the consumed count exhausts the plan exactly like natural exhaustion (`FundingTranchesExhausted`, code 172) — while tranches already funded keep the budget they funded under. The `FundingPlanMaxTranchesAmended` event (discriminant 133) carries no amounts; the new budget is read from the vault. No layout change: the plan bytes are already resident and rewritten in place. (Solana: 注资治理.)

Rotating the dead-man's switch heir after funding (AV-271): both parties may redirect an escrow's inactivity recovery to a new heir, without redeploying or refunding the escrow — the designated heir's key may be lost, compromised, or simply belong to someone no longer trusted to receive the funds. Dual-signed governance (`rotate_deadman_heir`, `Funded`-only); the heir itself does not sign, so a lost heir key never blocks its own replacement. Only an escrow whose switch is already configured may rotate — an unconfigured escrow is refused fail-closed (`InvalidDeadmanConfig`, code 168, post-funding installation would add a recovery path the taker never funded under), a zero heir is refused with the same error leaving the original heir untouched, and re-affirming the current heir is a no-op that emits no event. Only `deadman_heir` changes — the inactivity threshold and the last-activity clock are untouched, since the rotation takes no clock and never resets the timer. The claim path reads the live heir at each call, so the new heir governs from the next `claim_deadman` — the old heir is refused at once while the new heir may claim once the inactivity period has elapsed — while a claim already settled keeps the heir it settled under. The `DeadmanHeirRotated` event (discriminant 134) carries no amounts; the new heir is read from the vault. No layout change: the heir field is already resident and rewritten in place. (Solana: 非活跃回收治理.)

Rotating the flat slash penalty account after funding (AV-272): both parties may redirect a default penalty to a new recipient account, without redeploying or refunding the escrow — the original penalty account's key may be lost, or the parties may agree the penalty should land somewhere else. Dual-signed governance (`rotate_slash_penalty_account`, `Funded`-only). Only an escrow carrying flat slash terms may rotate — an escrow with no terms is refused fail-closed (`SlashNotEligible`, code 143, post-funding installation would add a penalty clause the taker never funded under), a ladder escrow is refused with `InvalidSlashLadder` (code 184, its penalty account lives in the independent ladder structure), an insurance-pool escrow is refused with `SlashNotEligible` (its slash routes to the neutral pool custody, so the flat account is a dead field), an escrow whose one-shot slash already executed is refused with the same error, a zero account is refused leaving the original untouched, and re-affirming the current account is a no-op that emits no event. Only `slash_terms.penalty_account` changes — the deadline and `penalty_paid` already banked are untouched, since a rotation never restates a settled penalty. The Anchor layer transfers the next slash to the live account read from the terms, so a default penalized after the rotation pays the new account while the pool path is unaffected, and a slash already settled keeps the account it settled under. The `SlashPenaltyAccountRotated` event (discriminant 135) carries no amounts; the new account is read from the vault. No layout change: the terms region is already resident and rewritten in place. (Solana: 支付风控.)
Amending the protocol-fee ceiling after funding (AV-273): both parties may renegotiate the maximum fee a single taker payout can carry, without redeploying or refunding the escrow — a ceiling that proves too tight may need raising for whale-sized payouts, or one that proves too loose may need cutting to protect the taker. Dual-signed governance (`amend_fee_cap`, `Funded`-only); only an escrow already carrying a ceiling may revise — an uncapped escrow is refused fail-closed (`InvalidProtocolFee`, code 114, post-funding installation would add a fee term the taker never funded under), any `u64` is a legal new ceiling and `0` is legal (it removes the cap outright, so later bps fees are no longer floored — and the removal is one-way post-funding, since a cap-less escrow fails the same gate on any later amendment), and re-affirming the current ceiling is a no-op that emits no event. Only `fee_cap` changes — the rate, the tier schedule and fees already charged or withdrawn are never restated. The fee computation reads the ceiling live, so a new ceiling governs the next taker payout on every funding path while a payout already settled keeps the fee it settled under. The `FeeCapAmended` event (discriminant 136) carries no amounts; the amended ceiling is read from the vault. No layout change: the ceiling field is already resident and rewritten in place. (Solana: 费用治理.)
Rotating the ladder slash penalty account after funding (AV-274): both parties may redirect a tiered default penalty to a new recipient account, without redeploying or refunding the escrow — the original penalty account's key may be lost, or the parties may agree the penalty should land somewhere else. Dual-signed governance (`rotate_slash_ladder_penalty_account`, `Funded`-only). Only an escrow carrying a ladder may rotate — an escrow with no ladder (plain, or flat-terms) is refused fail-closed (`InvalidSlashLadder`, code 184, post-funding installation would add a penalty clause the taker never funded under, and a flat escrow's account belongs to the AV-272 path), an insurance-pool escrow is refused with `SlashNotEligible` (its slash routes to the neutral pool custody, so the ladder account is a dead field), a zero account is refused leaving the original untouched, and re-affirming the current account is a no-op that emits no event. Only `slash_ladder.penalty_account` changes — the rung table, the rung count and the consumption cursor are untouched (the cursor is deliberately not reset), and `penalty_paid` / `pool_slashed` already banked are never restated. Unlike the flat one-shot, an already-slashed ladder stays rotatable, since the ladder is the repeated-slash path and the top rung is reused once exhausted. The Anchor layer transfers the next ladder slash to the live account read from the ladder, so a default penalized after the rotation pays the new account while the pool path is unaffected, and a slash already settled keeps the account it settled under. The `SlashLadderPenaltyAccountRotated` event (discriminant 137) carries no amounts; the new account is read from the vault. No layout change: the ladder region is already resident and rewritten in place. (Solana: 支付风控.)

Rotating a social-recovery guardian after funding (AV-275): both parties may replace one guardian of an escrow's lost-key recovery policy, without redeploying or refunding the escrow — a guardian key that is lost, compromised, or moved to a new wallet must not freeze the recovery the policy exists to provide. Dual-signed governance (`rotate_social_recovery_guardian`, `Funded`-only); the guardian being replaced does not sign, so a lost guardian key never blocks its own replacement. Only an escrow with a configured policy may rotate — an unconfigured escrow is refused fail-closed (`RecoveryNotConfigured`, code 287, post-funding installation would add a recovery path the taker never funded under), a pending recovery request refuses the rotation (`RecoveryRequestPending`, code 289, since the approval bitmap is indexed by slot and swapping a slot would re-attribute already-cast votes), a zero or duplicate new guardian is refused via the `SocialRecovery::new` gate (`InvalidSocialRecovery`, code 286) leaving the original guardian untouched, and re-affirming the current guardian is a no-op that emits no event. Only that one slot changes — the guardian count, threshold and timelock are untouched, and the pending request stays empty. The recovery path compares against the live slot guardian at each call, so the new guardian governs from the next `request_recovery` / `approve_recovery` — the old guardian is refused at once while the new guardian may open and approve — while a request already settled keeps the guardians it settled under. The `SocialRecoveryGuardianRotated` event (discriminant 138) carries no amounts; the new guardian is read from the vault. No layout change: the policy region is already resident and rewritten in place. (Solana: lost-key recovery governance.)

Revising the settlement-mint allowlist after funding (AV-276): both parties may change which currencies a funded escrow may settle in, without redeploying or refunding the escrow — a mint may be delisted, or a new stablecoin adopted, mid-deal. Dual-signature governance on a dual-sig escrow (`update_settlement_mint_allowlist`, `Funded`-only, paralleling `update_payout_allowlist`); on a plain escrow the initializer alone authorizes. An empty list clears back to no restriction (the AV-157 convention), a non-empty list passes the `SettlementMintAllowlist::new` gate (more than 8 entries, a zero address, or a duplicate is `InvalidSettlementMintAllowlist`, code 349, leaving the original list untouched), and unlike the scalar amends, setting, replacing, or clearing are all allowed under governance — no 'already configured' gate. On a delay-opted-in escrow the direct call is refused (`GovernanceActionNotProposed`, the AV-158 routing gate), and re-affirming the current list is a no-op that emits no event. Only the allowlist changes — the bound settlement mint and any settled release already made are untouched, and plain `release` is unaffected. The settled-release path reads the live list before rate verification and conversion pricing, so a mint removed here is refused at once while a mint added here settles from the next quote. The `SettlementMintAllowlistUpdated` event (discriminant 139) carries no amounts; the new list is read from the vault. No layout change: the allowlist region is already resident and rewritten in place. (Solana: 跨币种结算风控.)

Revising a Dutch auction's reserve floor after funding (AV-277): both parties may re-agree the initializer's guaranteed keep before the window opens, without redeploying or refunding the escrow — a floor that proves too low to protect the initializer, or too high to leave the taker any pull incentive. Dual-signed governance (`amend_dutch_auction_reserve_bps`, `Funded`-only, paralleling `amend_fee_cap`); only an escrow already carrying an auction may revise — an auction-less escrow is refused fail-closed (`InvalidAuctionParams`, code 155, post-funding installation would add a pricing curve the taker never funded under), and only before the window opens (`now < start_at`) may the floor move — at the open, live, or after the close the revision is refused (`AuctionNotActive`, code 156, since changing the floor mid-window would re-price claims already in flight). The new floor reuses the `DutchAuction::new` gate (above 10_000 is `InvalidAuctionParams`, leaving the original floor untouched), and re-affirming the current floor is a no-op that emits no event. Only `reserve_bps` changes — the window does not move, so the `escalate` mutual exclusion and `is_live` semantics are unchanged. Claim prices through the live floor at every call, so a claim after the amendment prices against the new floor while a claim already settled keeps the cap it settled under. The `DutchAuctionReserveBpsAmended` event (discriminant 140) carries no amounts; the new floor is read from the vault. No layout change: the auction region is already resident and rewritten in place. (Solana: 拍卖治理.)

Revising a Dutch auction's window after funding (AV-288): both parties may move the sale window before it opens — a launch slipped, or the market moved — without cancelling and re-locking the escrow. Dual-signed governance (`amend_dutch_auction_window`, `Funded`-only, paralleling `amend_dutch_auction_reserve_bps`); only an escrow already carrying an auction may revise — an auction-less escrow is refused fail-closed (`InvalidAuctionParams`, code 155), and only before the window opens may the window move — both `now <` the current `start_at` and `now <` the new `start_at` must hold, else `AuctionNotActive` (code 156), since a window that already opened would re-price claims already in flight and a new window that already opened would rewrite the `escalate` mutual exclusion mid-flight. The new window reuses the `DutchAuction::new` gate (an inverted window is `InvalidAuctionParams`, leaving the original untouched, with the current reserve floor carried along for re-validation), and re-affirming the current window is a no-op that emits no event. Only `start_at`/`end_at` change — the floor is untouched, so the window and the floor stay orthogonal (the floor moves via AV-277). On a governance-delay-opted-in escrow the direct call is refused — the window moves only through the propose/execute protocol, with no new proposal variant (AV-281 precedent). Claim prices through the live window at every call, so a claim after the amendment prices against the new window while a claim already settled keeps the cap it settled under. The `DutchAuctionWindowAmended` event (discriminant 150) carries no amounts; the new window is read from the vault. No layout change: the auction region is already resident and rewritten in place. (Solana: 拍卖治理.)
Revising a subscription's period cadence after funding (AV-289): both parties may stretch or compress the payout cadence — a subscription that was monthly becomes fortnightly, or vice versa — without cancelling and re-locking the escrow. Dual-signed governance (`amend_subscription_period_secs`, `Funded`-only, paralleling `amend_dutch_auction_window`); only an escrow with a subscription plan already configured may revise — an unconfigured escrow is refused fail-closed (`InvalidSubscription`, code 130), and the new period reuses the `with_subscription` gates (a zero period is `InvalidSubscription`, and a period whose `(periods - 1) * new_period_secs` would overflow the escrow lifetime is refused with the same error, leaving the original period untouched). Re-affirming the current period is a no-op that emits no event. Only `subscription.period_secs` changes — the period count, the per-period amount, the amount conservation, the next-period cursor and the released bitmap are untouched, so already-released periods are history only. On a governance-delay-opted-in escrow the direct call is refused — the cadence moves only through the propose/execute protocol, with no new proposal variant (AV-281 precedent). Due dates of unreleased periods move with the new cadence at the next `subscription_period_due_at` call, back-scheduled from `expires_at` with the last period pinned to expiry, while a period already released keeps the due date it released under. The `SubscriptionPeriodSecsAmended` event (discriminant 151) carries no amounts; the new cadence is read from the vault. No layout change: the schedule region is already resident and rewritten in place. (Solana: subscription cadence governance.)
Revising a vesting unlock curve's shape after funding (AV-290): both parties may reshape a non-linear unlock curve — a back-loaded team unlock that proves too steep, or a front-loaded one that proves too generous — without cancelling and re-locking the escrow. Dual-signed governance (`amend_vesting_curve`, `Funded`-only, paralleling `amend_vesting_schedule`); only an escrow with a curve already configured may revise — a curve-less escrow is refused fail-closed (`InvalidVesting`, post-funding installation would price the unlock under a shape the taker never funded under, and `with_vesting_curve` stays `Uninitialized`-only). The new curve's tier window must fall inside the live schedule's `[start, end]` (the same gate `with_vesting_curve` applies at attach time, judged against the live schedule, via `InvalidVestingCurve`, code 147), and the anti-clawback floor mirrors `amend_vesting_schedule`: the new curve priced at `now` over the live schedule must vest at least what the taker already claimed, otherwise the amendment would claw back unlocked funds (`InvalidVesting`, with the AV-51 cliff gating inside the pricing). Re-affirming the current curve is a no-op that emits no event. Only `vesting_curve` changes — the linear schedule table, the cliff, and the locked amount are untouched, so the new shape governs from the next `claim` (`claim` and `claimable_amount` price through the live curve at every call, while an amount already claimed keeps the shape it settled under). On a governance-delay-opted-in escrow the direct call is refused — the curve moves only through the propose/execute protocol, with no new proposal variant (AV-281 precedent). The `VestingCurveAmended` event (discriminant 152) carries no amounts; the new shape is read from the vault. No layout change: the curve region is already resident and rewritten in place. (Solana: vesting governance.)
Revising a payout-split's shares after funding (AV-293): both parties may rebalance a declared distribution — a revenue share that shifts, a payroll weight that moves — without cancelling and re-locking the escrow. Dual-signed governance (`amend_payout_split_shares`, `Funded`-only, paralleling `amend_vesting_curve`); a due pause schedule lifts first (`try_auto_unpause`) and a paused escrow fails fast (`Paused`). Only an escrow with a split table already configured may revise — a table-less escrow is refused fail-closed (`InvalidPayoutSplit`, code 167, post-funding installation would add a distribution the taker never funded under, and `with_payout_split` stays `Uninitialized`-only). Only a table whose recipients are all within `{initializer, taker}` may move — a table naming any third-party recipient is refused with the same error, since a third party's share is not the two signers' to dispose of by dual signature alone. A milestone plan or a subscription schedule owns the release path, so an escrow carrying either is refused (`InvalidMilestones` / `InvalidSubscription`, mirroring `release_payout_split`: on such an escrow the table never settles, so revising it would be meaningless). `released` must still be zero — a partially settled escrow, where a vesting claim already pulled part of the lockup while the state stays `Funded`, is refused (`InvalidPayoutSplit`), since rebalancing over an amount that already moved would restate settled funds. The new table reuses the `PayoutSplit::new` gates (non-empty, at most 8 entries, no zero recipient, no zero share, no duplicate recipient, and a Σ that equals the locked amount exactly), leaving the original table untouched on refusal. Only the shares move — the new table's recipients, in table order, must equal the current table's recipients exactly, since swapping a recipient would redirect funds and even reordering would move the flooring dust's first-leg landing. Re-affirming the current shares is a no-op that emits no event. Only the share amounts change — the recipient set and order, the locked amount, and the state are untouched, so the new shares govern from the next `release_payout_split` (which reads the live table at every call: the net legs prorate over the live shares, so a release after the amendment pays the new split while a release already settled keeps the shares it settled under). On a governance-delay-opted-in escrow the direct call is refused — the shares move only through the propose/execute protocol, with no new proposal variant (AV-281 precedent). The `PayoutSplitSharesAmended` event (discriminant 153) carries no amounts; the new shares are read from the vault. No layout change: the split region is already resident and rewritten in place. (Solana: split governance.)

Amending the social-recovery approval threshold after funding (AV-278): both parties may re-agree how many guardians must approve a lost-key recovery, without redeploying or refunding the escrow — a threshold that proves too easy for guardians to meet, or too hard once a guardian key is lost. Governed post-funding amendment (`amend_social_recovery_threshold`, `Funded`-only) under the AV-276 signature gate: both parties sign on a dual-sig escrow, the initializer alone on a plain escrow. Only an escrow with a configured policy may amend — an unconfigured escrow is refused fail-closed (`RecoveryNotConfigured`, code 287, post-funding installation would add a recovery path the taker never funded under), a pending recovery request refuses the amendment (`RecoveryRequestPending`, code 289, since in-flight requests count under the old threshold and changing it would reinterpret already-cast votes), and the new threshold reuses the `SocialRecovery::new` gate (`1..=guardian_count`, otherwise `InvalidSocialRecovery`, code 286) leaving the original threshold untouched, while re-affirming the current threshold is a no-op that emits no event. Only the threshold changes — the guardians, the guardian count and the timelock are untouched, and the pending request stays empty. The new threshold governs from the next `request_recovery`, so a request opened after the amendment arms and executes under the new threshold while a request already settled keeps the threshold it settled under. The `SocialRecoveryThresholdAmended` event (discriminant 141) carries no amounts; the new threshold is read from the vault. No layout change: the policy region is already resident and rewritten in place. (Solana: key-loss recovery governance.)
Replacing the tiered quorum's tier table after funding (AV-280): both parties may re-agree how much attestor weight each release band needs, without redeploying or refunding the escrow — a small band that once needed one attestor may deserve two once the escrow's contents grow, or a large band's full-panel demand may prove unworkable when an attestor goes dark. Governed post-funding amendment (`update_tiered_quorum`, `Funded`-only) under unconditional dual-signature governance: both parties sign, whether or not the escrow opted into dual-sig activation, since the tier table is quorum policy like the `update_quorum` threshold. Only an escrow with a configured tiered quorum may amend — an unconfigured escrow is refused fail-closed (`InvalidQuorum`, post-funding installation would add a gate the taker never funded under), a plain-quorum escrow is refused the same way (its threshold moves through `update_quorum`), and the new table reuses the `TieredQuorum::new` gate (empty table, more than `MAX_TIERS` tiers, non-strictly-increasing ceilings, a top tier that is not open-ended (`u64::MAX`), non-decreasing-threshold violations, or a threshold outside `1..=total_weight` are all `InvalidQuorum`) leaving the original table untouched, while re-affirming the current table is a no-op that emits no event. A delay-opted-in escrow refuses the direct call (`GovernanceActionNotProposed`, the AV-158 routing gate). Only the tier table changes — the wrapped base policy (attestor registry, weights, accumulated attestations) is reused verbatim, so in-flight attestations are re-judged under the new thresholds at the next release while a release already settled keeps the table it settled under. The `TieredQuorumUpdated` event (discriminant 143) carries no amounts; the new table is read from the vault. No layout change: the tiered region is already resident and rewritten in place. (Solana: quorum governance.)
Revising the dispute jury size after funding (AV-281): both parties may re-agree how many jurors seat a dispute panel, without redeploying or refunding the escrow — a panel of five that once looked robust may prove too slow to convene once jurors go dark, or a panel of three too thin once the escrow's contents grow. Governed post-funding amendment (`amend_jury_panel_size`, `Funded`-only) under dual-signature governance: both parties sign. Only an escrow already carrying a jury may amend — an unconfigured escrow is refused fail-closed (`InvalidJurySize`, code 294, post-funding installation would add a settlement mechanism the taker never funded under), an escrow with a bound single arbiter is refused (`JuryArbiterConflict`, code 298, mirroring `draw_panel`'s mutual-exclusion gate, checked before configuration), and the new size reuses the `with_jury` gate (`1..=MAX_JURORS`, otherwise `InvalidJurySize`) leaving the original size untouched, while re-affirming the current size is a no-op that emits no event. A delay-opted-in escrow refuses the direct call (`GovernanceActionNotProposed`, the AV-158 routing gate). Only the size changes — the arbiter slot, the arbiter panel and the juror registry are untouched. The draw has not happened yet (`Funded`-only, and `draw_panel` runs only on a `Disputed` escrow), so there is no in-flight panel to re-draw, and the new size governs from the next dispute draw, since `draw_panel` reads the live size at every call. The `JuryPanelSizeAmended` event (discriminant 144) carries no amounts; the new size is read from the vault. No layout change: the jury region is already resident and rewritten in place. (Solana: dispute jury governance.)
Revising the event-history ring capacity after funding (AV-282): both parties may re-agree how many recent events the vault retains, without redeploying or refunding the escrow — a capacity of 64 that once looked generous may prove too narrow once an escrow accumulates governance revisions, or a capacity of 8 too wide once indexers only ever read the last few entries. Governed post-funding amendment (`amend_event_capacity`, `Funded`-only) under dual-signature governance: both parties sign. Only a ring that has not wrapped may amend — while the ring is still filling, a new capacity keeps every retained entry readable, but once the ring is full the head has started advancing modulo the old capacity, so a new capacity would scramble the retained window and the amendment is refused fail-closed (`InvalidStateTransition`, and the refusal precedes even the no-op check). The new capacity reuses the `with_event_capacity` gate (`1..=MAX_EVENT_HISTORY`, otherwise `InvalidEventCapacity`, code 132) and must also cover every retained entry (`new_capacity >= event_count`, otherwise `InvalidEventCapacity`), leaving the original capacity untouched, while re-affirming the current capacity on a filling ring is a no-op that emits no event. A delay-opted-in escrow refuses the direct call (`GovernanceActionNotProposed`, the AV-158 routing gate). Only the capacity changes — the slots, the head, the count and the total are untouched, so the retained entries survive verbatim, and the new capacity governs from the next `record_history` call, since both `record_history` and `event_history` read the live capacity at every call. The `EventCapacityAmended` event (discriminant 145) carries no amounts; the new capacity is read from the vault. No layout change: the capacity region is already resident and rewritten in place. (Solana: event history governance.)
Amending the social-recovery veto-window timelock after funding (AV-279): both parties may re-agree how long the original key has to veto a lost-key recovery, without redeploying or refunding the escrow — a veto window that proves too short to catch a malicious rotation, or too long once the key is truly lost. Governed post-funding amendment (`amend_social_recovery_timelock`, `Funded`-only) under the AV-276 signature gate: both parties sign on a dual-sig escrow, the initializer alone on a plain escrow. Only an escrow with a configured policy may amend — an unconfigured escrow is refused fail-closed (`RecoveryNotConfigured`, code 287, post-funding installation would add a recovery path the taker never funded under), a pending recovery request refuses the amendment (`RecoveryRequestPending`, code 289, since the in-flight request's veto window already started under the old timelock and changing it would re-time the remaining wait), and the new timelock reuses the `SocialRecovery::new` gate (any value is valid, including zero — the veto window is then only the approval latency, the initializer opting out of the delay deliberately), while re-affirming the current timelock is a no-op that emits no event. Only the timelock changes — the guardians, the guardian count and the threshold are untouched, and the pending request stays empty. The new timelock governs from the next `request_recovery`, so a request opened after the amendment arms and executes under the new veto window while a request already settled keeps the window it settled under. The `SocialRecoveryTimelockAmended` event (discriminant 142) carries no amounts; the new timelock is read from the vault. No layout change: the policy region is already resident and rewritten in place. (Solana: key-loss recovery governance.)

Revising the arbiter panel roster after funding (AV-283): both parties may re-agree who sits on the dispute panel, without redeploying or refunding the escrow — a member key can be compromised, lost, or rotated out of service, and a panel that cannot seat a replacement would stall every future dispute on a dead key. Governed post-funding amendment (`update_arbiter_panel_members`, `Funded`-only) under dual-signature governance: both parties sign, since one party alone reshaping the electorate would be a unilateral weakening of the adjudication gate. Only an escrow with a configured panel may amend — an unconfigured escrow fails closed (`InvalidArbiterPanel`), and single-arbiter mode revises through `rotate_arbiter`. The new list reuses the `ArbiterPanel::new` gate against the current threshold (empty, over-long, zero-key, duplicate, or below-threshold lists are `InvalidArbiterPanel`), leaving the original roster untouched. A delay-opted-in escrow refuses the direct call (`GovernanceActionNotProposed`, the AV-158 routing gate). Only the members and the count change — the threshold, the blind mode and the reveal window are carried over verbatim, and the vote state is necessarily zero on a `Funded` escrow, so preserving the panel struct is exactly a no-reset. Re-affirming the identical list in the identical slot order is a no-op that emits no event, while a reordering is a revision because slot order is vote identity. The new roster governs from the next dispute, since `submit_panel_judgment` checks membership against the live list. The `ArbiterPanelMembersUpdated` event (discriminant 146) carries no amounts; the new roster is read from the vault. No layout change: the panel region is already resident and rewritten in place. (Solana: dispute arbitration governance.)

Amending the slash ladder after funding (AV-237): both parties may retune the penalty schedule for the defaults still ahead, without redeploying or refunding the escrow — an early rung may prove too lenient to deter a second miss, or a top rung so harsh it makes late performance pointless. Dual-signed governance (`amend_slash_ladder`, `Funded`-only); the consumed prefix is immutable rung-by-rung (the cursor is the next rung's index), the new table must stay strictly ascending in deadline and bps with each bps at most 10_000, and no future rung may be backdated before `now`. The penalty account, the penalty already paid, and the cursor are untouched, so the next slash prices from the new rung at the same cursor. The `SlashLadderAmended` event (discriminant 101) carries no amounts; the amended ladder is read from the vault. No layout change: the ladder is an existing field. (Solana: escalating-penalty governance.)

Layout growth: the vault body grows from 5533 to 5545 bytes (+12: the
9-byte flat slice + the 3-byte bps rate), `VAULT_SPACE_NO_QUORUM` from
5051 to 5063, `VAULT_SPACE` from 5541 to 5553, and the close-time rent
reclamation from 39_456_240 to 39_539_760 lamports
(`(128 + VAULT_SPACE) * 3480 * 2`).

## Unclaimed-rent sweep (AV-139)

The problem: a vault that settles into a terminal state (`Cancelled`,
`Released`, `Settled`, `Split`, `Declined`) keeps its rent-exempt
balance locked forever if nobody calls `close_vault` — the initializer
may have lost their keys, or the rent simply isn't worth their time.
The lamports sit idle, unusable by anyone, while the protocol could
have recycled them into its treasury.

AV-139 adds a permissionless sweep: after a configurable grace period
(default 30 days) following the terminal transition, **anyone** may call
`sweep_unclaimed_rent(caller, now)` to close the vault and send the
rent-exempt lamports to the treasury. Only the rent moves — escrowed
funds were already paid out or refunded by the terminal transition, and
the sweep never touches them. The vault moves to `Closed`, the deepest
terminal state.

Two new vault fields (appended last, borsh order): `terminal_at` (u64,
stamped from the clock sysvar on every transition into a closeable
terminal state; 0 = never terminal) and `rent_sweep_grace_secs` (u64,
0 = the 30-day default). The grace is configured via
`with_rent_sweep_grace_secs(secs)` (or the
`initialize_rent_sweep_grace` instruction), `Uninitialized`-only like
every other opt-in — reconfiguring a live escrow is
`InvalidStateTransition`.

## AV-148: bilateral taker counter-fund

A new vault field (appended last, borsh order): `taker_locked` (u64,
the taker's bilateral counter-fund accumulator; 0 until the taker
posts collateral). The taker posts via `fund_taker(taker, amount)`
— taker-only, `Funded` (or `Activated` on a dual-sig escrow),
positive amounts only. Each call accumulates into `taker_locked`;
the state byte does not move.

**Bilateral settlement.** Releases draw from the merged lockup
(`amount + taker_locked`), spending the initializer's leg first;
the `released` counter accumulates the gross payout (fees still ride
the existing path). `cancel` / `cancel_expired` refund each party
from their own leg — the initializer reclaims `amount`, the taker
reclaims `taker_locked` ("dual original-route refund"). The
conservation invariant is `inflow == released + refunded +
remaining` on the bilateral totals, covered by the model fuzz.

**Layout growth.** `VAULT_SPACE` 5970 → **5978** (+8 bytes);
`VAULT_SPACE_NO_QUORUM` 5480 → **5488**; mainnet rent-exempt minimum
42,442,080 → **42,497,760** lamports ((128 + 5978) × 3480 × 2).

## AV-149: multi-taker share claiming

An opt-in pull roster for multi-taker escrows — up to 8 claimants
split the locked funds by basis points, each pulling their own share
with a bitmask replay guard. A new vault field (appended last, borsh
order): `claimants` (`Option<ClaimantRoster>` — 1-byte discriminant +
274-byte region: 1-byte live count + eight 32-byte claimant slots +
eight 2-byte share slots + 1-byte claimed bitmask; `None` on a plain
bilateral escrow, zeroed when unconfigured).

The initializer declares the roster via
`initialize_claimants(shares)` — `Uninitialized` only, 1–8
`(claimant, share_bps)` legs; empty / over-8 / zero-address /
zero-share / duplicate-claimant / Σ != 10_000 bps is
`InvalidClaimantShares` (code 211).

**Pull.** Each claimant calls `claim_share(claimant)` — `Funded`
only. The check order is authority (`authority == claimant`,
`Unauthorized` otherwise — one claimant cannot pull another's leg) →
state (`InvalidStateTransition` unless `Funded`) → roster (not a leg
is `ClaimantNotInRoster`, code 209) → bitmask (already-pulled leg is
`ClaimantAlreadyClaimed`, code 210). A milestone plan refuses the
pull (`InvalidMilestones`); dispute pro-rata stays bilateral-only
(the roster never participates in dispute settlement).

The leg's gross is its bps share of the current locked remainder
(`floor(remaining × bps / unclaimed_bps)` in u128); `released`
accumulates the gross and the AV-17 protocol fee is charged on top,
so the conservation invariant `inflow == released + refunded +
remaining` holds on the multi-taker totals. The last unclaimed leg
takes the whole remainder (dust-absorbing), so the final pull moves
`Funded` → `Released`. Emits `ShareClaimed` (discriminant 77); the
indexer fold books the gross like `Claimed`, and the fee history
maps the fee to `FeeType::Claim`.

**Claimant roster amendment (AV-227).** A roster fixed at funding cannot follow a deal whose beneficiaries change — a contributor leaves, a new one joins, weights shift. `amend_claimant_roster(initializer, new_legs)` (`Funded`-only, initializer-only) revises the pull table mid-deal: the caller passes the new unclaimed legs as `(claimant, weight)` pairs, claimed legs are preserved with address, share, and claimed bit exactly locked (a pulled leg can never be repriced or pulled twice), and the unclaimed pool — `10_000` bps minus the claimed shares — is re-cut by weight with largest-remainder apportionment, so the roster Σ is exactly `10_000` bps again. Empty tables, zero addresses, zero weights, duplicates, already-claimed addresses, and over-8 tables are `InvalidClaimantShares` (code 211), and a failed amendment leaves the roster untouched. Later `claim_share` pulls price against the new shares and still settle to exactly the locked amount. Orthogonal to `with_claimants` (creation, `Uninitialized`-only) and to `release_payout_split` (a one-shot push split of the AV-108 table; this rewrites the AV-149 pull table). The `ClaimantRosterAmended` event (discriminant 92) carries no amounts; the amended roster is read from the vault.

No vault layout change (the roster region is already reserved); no IDL change (no new instruction, error, or persisted field). (Solana: payment profit-sharing.)

**Layout growth.** `VAULT_SPACE` 5978 → **6253** (+275 bytes:
1-byte `Option` discriminant + 274-byte roster region);
`VAULT_SPACE_NO_QUORUM` 5488 → **5763**; mainnet rent-exempt minimum
42,497,760 → **44,411,760** lamports ((128 + 6253) × 3480 × 2).

**Layout growth (AV-150).** `VAULT_SPACE` 6253 → **6262** (+9 bytes:
1-byte `Option` discriminant + 8-byte `paused_at` timestamp, the
vesting-pause tail appended last after `claimants`);
`VAULT_SPACE_NO_QUORUM` 5763 → **5772**; mainnet rent-exempt minimum
44,411,760 → **44,474,400** lamports ((128 + 6262) × 3480 × 2).

Eligibility is `is_rent_sweep_eligible(now)`: terminal state, grace
elapsed since `terminal_at`, not paused, no reentrancy lock, empty
pool (the AV-106 guard). A premature sweep is `SweepGraceNotElapsed`
(code 206). The keeper gets a dry-run `scan_unclaimed_rent(watched,
now)` report listing sweepable vaults sorted by `terminal_at`
(oldest first), and the sweep emits the `RentSwept` indexer event
(from = the terminal state, to = `Closed`, the swept lamports in
`rent_reclaimed`).

Layout growth: the vault body grows from 5946 to 5962 bytes (+16: the
two u64 fields), `VAULT_SPACE_NO_QUORUM` from 5464 to 5480,
`VAULT_SPACE` from 5954 to 5970, and the close-time rent reclamation
from 42_330_720 to 42_442_080 lamports
(`(128 + VAULT_SPACE) * 3480 * 2`).

## Native SOL stake delegation (AV-170)

A funded escrow locks SOL in the vault account where it sits idle. When
the initializer opts in at fund time, the keeper delegates the locked
SOL to a stake account bound to a chosen vote account, so the escrow
earns staking rewards while the funds stay locked. The stake leg is
modeled as a pure-logic sidecar (`StakeDelegation`) bound to the
escrow — the escrow state machine is untouched (no new vault fields,
no layout change), because the stake account lives outside the vault.

**Lifecycle.** `delegate_at_fund` (Funded only; the opt-in key must
equal the escrow's initializer) snapshots the escrow's full amount as
the delegated principal and binds the `(stake_account, vote_account)`
pair. The stake state machine runs `Delegated → Active →
Deactivating → Deactivated` on the keeper's epoch observations: warmup
completes at `activation_epoch = delegation_epoch + 1`, deactivation
cools down until `deactivation_epoch = current_epoch + 1`; early
observations are `NotYetActive` / `NotYetDeactivated`, and a
never-activated stake cannot begin deactivation.

**Settlement.** `settle(taker_payout, current_stake_balance)` computes
the entitlement split for one keeper-authorized taker payout (the
amount the escrow state machine already approved): principal always
settles — a pending deactivation never blocks the principal leg;
rewards settle only once `Deactivated` (while `Active` /
`Deactivating` they are reported as pending and keep earning); the
taker's reward share is `floor(rewards × reward_split_bps / 10_000)`
with the dust remainder to the initializer. A balance observed below
the remaining principal is an explicit `BalanceBelowPrincipal`
failure — the module never fabricates lamports. After the transfers
land, the keeper calls `record_principal_release` so the sidecar's
books stay exact.

## RPC commitment levels for off-chain reads (AV-171)

Every keeper RPC read carries a commitment level — how final the
observed data is — and treating a `processed` observation as settled
truth is a dirty read. `CommitmentLevel` models the Solana RPC
vocabulary (`Processed < Confirmed < Finalized`), and
`required_commitment` tiers operations by risk: the keeper lifecycle
scan and oracle price reads require `Confirmed` (monitoring-class:
lower latency, the next tick's re-scan repairs an orphaned
observation), while the pre-settlement check and bundle-landing
confirmation require `Finalized`.

`read_with_commitment` performs the injectable read until the
observed commitment meets the requirement or the attempt budget runs
out. The iron rule is **no silent downgrade**: a read that never
reaches the required level is an explicit `CommitmentNotMet` — the
value is never returned at a lower commitment. Transport failures
surface as `ReadFailed`, never disguised as commitment misses. Every
call, success or failure, yields a `CommitmentAudit` event
(`commitment_read` JSON carrying the operation, the required and
best-observed levels, and the attempt count) for the keeper's audit
sink.

### Local-validator integration stubs

`tests/local_validator.rs` under `programs/escrow-vault/` holds Anchor
integration test stubs for the full instruction flows
(`initialize → fund → release`, the quorum `attest → release` path, and
failure paths like unauthorized release). They are all `#[ignore]`d, so CI
skips them. To run them locally:

```bash
solana-test-validator            # in another terminal
cargo test -p escrow-vault -- --ignored
```

Each stub first probes `127.0.0.1:8899`; if no validator is reachable it
fails with an explicit message rather than pretending to pass. The stubs
use only the existing `escrow-state` dependency — no new crates.

## Amount-tiered attestor quorum (AV-178)

`escrow-state/src/tiered_quorum.rs` — the release amount selects the
attestor weight threshold. A `TieredQuorum` wraps the AV-04
`QuorumPolicy` (the weighted attestor registry and its accumulated
votes) with a configurable tier table: a release of `amount <=
max_amount` must reach that tier's weight-sum threshold. Small releases
clear with a light quorum (e.g. 1-of-N weight), large releases demand
the full panel (N-of-N weight) — the payment-risk pattern: low-value
payouts stay fast while high-value payouts harden into multi-sig
(Solana governance / payment risk control).

- **The table**: `TieredQuorum::new(base, tiers)` validates the table —
  1–4 tiers, strictly increasing amount ceilings, an open-ended top
  tier (`u64::MAX`, so no amount falls through), non-decreasing
  thresholds with the amount (a larger release can never demand less
  weight — monotonicity), and every threshold inside
  `1..=total_weight` (an unreachable threshold would lock funds behind
  an unsatisfiable gate). Violations are `InvalidQuorum` (code 104),
  the same family as the AV-04 policy errors.
- **The gate**: `Escrow::with_tiered_quorum` is `Uninitialized`-only and
  mutually exclusive with `with_quorum` (`InvalidQuorum` when the other
  is already attached). `Escrow::attest` routes votes to the wrapped
  policy, so attestations keep accumulating across transactions exactly
  as before. Every taker payout path (`release`, `release_split`,
  `release_payout_split`, `claim`, `release_milestone`,
  `release_period_locked`, `release_basket`, `release_basket_all`)
  checks the tier threshold for its release amount via
  `require_release_quorum`, in the exact position the plain quorum check
  held — authority, then state, then quorum — so the check order is
  unchanged. `QuorumNotReached` on failure, like the plain gate.
- **The layout**: the tiered policy persists in the vault tail
  (`1 + TIERED_QUORUM_LEN` bytes: the `Option` discriminant, the
  wrapped policy bytes, the tier slots, the tier-count byte), appended
  last so every earlier field offset stays stable. The structural
  decoder (`decode_vault_account`) rebuilds it field-by-field and
  rejects an out-of-range tier count (`InvalidTieredQuorumLen`) rather
  than decoding a value the accessors cannot safely read (AV-32
  panic-free guarantee).

## Token-weighted voting (AV-183)

`escrow-state/src/weighted_voting.rs` — attestor weights derived from
governance token balances, frozen at a snapshot slot. A
`TokenWeightSnapshot` wraps the AV-04 `QuorumPolicy` (the weighted
attestor registry and its accumulated votes): attestor `i` votes with
weight `balances[i]`, the governance token balance read at
`snapshot_slot`, and the release threshold is `ceil(threshold_bps /
10_000 * total_weight)` — e.g. 6667 for a two-thirds supermajority,
10_000 for unanimity.

- **The flash-loan defense**: the snapshot is frozen at construction.
  `Escrow::with_token_weighted_voting` is `Uninitialized`-only, and no
  API mutates a weight afterwards — weights are never re-read from
  token accounts, they are fixed numbers in the escrow config, so a
  flash loan taken after the snapshot cannot inflate anyone's voting
  power. Freezing is structural, not a runtime check.
- **Validation** (`InvalidQuorum`, code 104, the AV-04 family): bps
  outside `1..=10_000`, empty or `> 8` attestors, length mismatch,
  duplicate or zero keys, zero balances (a zero-balance attestor has no
  voting power — registering one is always a misconfiguration), or a
  balances sum overflowing the `u64` weight domain. The ceiling
  division keeps the threshold inside `1..=total_weight`, so a snapshot
  can never lock funds behind an unsatisfiable gate.
- **The gate**: the snapshot's derived policy lands in the escrow's
  quorum slot, so `attest` and every taker payout path work unchanged —
  only the weight source differs. Mutually exclusive with a plain or
  tiered quorum. Orthogonal to AV-178 (the amount dimension): this
  module is the weight-source dimension.
- **Audit**: `TokenWeightSnapshot::to_json` exports the frozen snapshot
  (bps threshold, snapshot slot, derived weight-sum threshold, every
  attestor with its frozen balance-weight) as canonical JSON for the
  off-chain governance audit trail. On-chain, the frozen weights ride
  the quorum slot and are disclosed to indexers through the existing
  quorum snapshot (`threshold`, `total_weight`, `approved_weight`).
- **No layout change**: the derived policy reuses the existing quorum
  account region, so `VAULT_FIELDS` / `VAULT_SPACE` / rent are
  untouched.

## Token-2022 extension safety gate (AV-184)

`escrow-state/src/mint_safety.rs` — a pre-flight check over a mint's
Token-2022 extensions, run *before* `initialize` / `fund`
(`Escrow::check_mint_safety`). Some extensions are escrow-hostile and
fail the gate closed (`EscrowError::UnsafeMint`, code 250):

- `DefaultAccountState::Frozen` — every taker token account lands
  frozen; the payout can never move without the mint's freeze authority.
- `NonTransferable` — the taker can never move the payout at all.
- a 100% `TransferFeeConfig` — every transfer is fully confiscated as
  fee (a partial fee is tolerated and merely observed).
- an *undisclosed* `PermanentDelegate` — the delegate can burn or
  force-transfer escrowed funds at will. A delegate the initializer
  disclosed out of band (e.g. in the escrow terms) is accepted.

Safe extensions never deny: `ConfidentialTransfer` (transfer modeling
lives in `confidential.rs` instruction 8 — orthogonal to this gate) and
`TransferHook` (hook execution modeled in `cpi.rs` — orthogonal). The
check is pure observation (`check_mint_safety` never fails); the
fail-closed decision is `MintSafetyReport::require_allowed`, and every
result renders as audit-event JSON (`MintSafetyReport::audit_json`,
hand-written like `bundle_relay`'s lifecycle events) so indexers see
the gate decision. The gate is intentionally not persisted on the
vault: the mint bound via `with_mint` is the on-chain anchor, and the
check runs before the escrow exists (Solana security / backend
engineering: hostile-mint circuit breaker).

## EVM release authorization via secp256k1 (AV-185)

`escrow-state/src/secp256k1.rs` — hand-rolled Keccak-256 (the Ethereum
variant) and secp256k1 (base-field arithmetic, Jacobian point
operations, ECDSA public-key recovery), zero dependencies, for the
cross-chain release-authorization envelope: the taker binds an EVM
wallet (`bind_evm_taker`) to their escrow identity, and that wallet's
signature then authorizes a `release` — the Ethereum signer never needs
a Solana key.

- **The envelope**: `release_authorization_hash` is
  `keccak256(domain || escrow_id || taker || evm_address || amount_le
  || nonce_le)`; `verify_release_authorization` recovers the signer
  address from `(hash, r, s, v)` and compares it to the bound address.
  The authorization is single-use by construction — a signature for a
  different amount, nonce, or escrow is a different message and fails.
  `personal_sign_hash` covers the EIP-191 wallet-signing path
  (`"\x19Ethereum Signed Message:\n" || len || message`).
- **Fail-closed**: `v` must be `27`/`28`, `r`/`s` must be in
  `1..n`, the zero address can never be bound, and any malformed input
  recovers to `None` / verifies as `false` — never a panic.
- **Correctness pins** (independent ground truth, no self-generated
  vectors): Keccak-256 against `pycryptodome` (empty, `"hello"`,
  multi-block inputs); `2*G` and full sign→recover vectors against
  `python-ecdsa` (RFC 6979 deterministic signatures); the recovered
  address must equal the independently derived Ethereum address.
- **Threat model**: like `ed25519.rs`, this is cross-chain tooling,
  not consensus — no constant-time claims (double-and-add scalar
  multiplication). Orthogonal to `ed25519.rs` (ed25519 for keeper
  reports; this module is secp256k1/EVM). (Solana cross-chain /
  backend engineering: EVM-signed escrow release.)

## HTLC hash-time-locked release (AV-186)

`escrow-state/src/htlc.rs` — the hashed time-lock contract (HTLC)
primitive for cross-chain atomic swaps, pure logic with zero
dependencies. The maker locks funds behind `SHA-256(preimage)` (the
*hashlock*) and a slot deadline (the *timelock*): the taker claims by
revealing the preimage before the deadline; the maker refunds after
it. The same hashlock on both chains makes the two legs
settle-or-refund together — atomicity without a trusted relayer.

- **The double lock**: `HtlcLock::claim` requires `sha256(preimage) ==
  hashlock && current_slot < expiry_slot`. The check order is
  authority → state → timelock → preimage shape → hashlock, mirroring
  the state machine's fail-closed ordering (a stranger gets
  `Unauthorized` and learns nothing about the lock). `claim` and
  `refund` return the locked amount for exact transfer sizing, and
  both exits move the lock to a terminal state (`Claimed` /
  `Refunded`) — double-claim and double-refund are
  `InvalidStateTransition`.
- **The preimage is never stored**: the lock carries only the digest,
  and `claim` compares `sha256(preimage)` against it in memory (XOR-
  accumulated, no per-byte oracle). There is no field, log line, or
  serialization path that retains the preimage after the call
  returns. `verify_htlc_preimage` is the stateless check for
  off-chain keepers and wallets; `can_claim` simulates a claim
  without moving state.
- **Boundary semantics**: the taker's window is `current_slot <
  expiry_slot` (strict — claiming *at* the expiry slot fails with
  `HtlcClaimExpired`, codes 251–255); the maker's refund window is
  `current_slot >= expiry_slot` (inclusive — refunding *at* expiry
  succeeds). The maker cannot race the taker's open window
  (`HtlcRefundNotExpired`).
- **Orthogonality**: AV-185's `release_authorization_hash` unlocks
  with an EVM *signature* — this unlocks with a hash *preimage*;
  AV-137's commit-reveal hides an arbitration *vote* — this hides the
  *payment secret*; the SLOT_TIMELOCK releases on slot expiry alone
  — this adds the hash condition on top. Pure logic: no Vault layout
  change, no `VAULT_SPACE` bump (the layout pin tests still hold).
  (Solana: cross-chain atomic-swap primitive / backend engineering.)

## NFT escrow (AV-187)

`escrow-state/src/nft_escrow.rs` — single-edition mint custody. An
NFT is not a fungible amount, so its escrow must not inherit amount
arithmetic: `NftEscrow` transfers the whole piece or nothing
(`amount()` is structurally `1` — there is no partial-release,
milestone, fee-leg, or vesting path to misuse), and it is orthogonal
to the fungible `Escrow` path (shared `EscrowError` type and
audit-JSON vocabulary, none of the amount machinery).

- **The mint gate**: before `initialize`, the initializer reads the
  mint account into an `NftMintDescriptor` (the AV-184
  `mint_safety.rs` pattern — caller-observed state, pure logic) and
  `check_nft_mint` asserts `supply == 1 && decimals == 0`. Anything
  else fails *closed* (`InvalidNftMint`, code 256): a semi-fungible
  edition or a decimal mint routed through the NFT path is a
  counterfeit-escrow bug, not a supported use case.
- **Collection allowlist**: `with_collection_allowlist` opts into a
  release gate over the observed verified-collection mint
  (`CollectionNotAllowlisted`, code 257). The gate fails closed — a
  gated escrow whose collection is unobserved cannot be verified, so
  it cannot release — and it never blocks `cancel`: gating must never
  trap the piece.
- **Check order** is authority → state → collection gate, so a
  stranger learns nothing about the escrow's state or its collection.
- **Revising the gate (AV-284)**: `update_collection_allowlist`
  revises the collection gate on a `Created` escrow, authorized by
  the initializer alone (the single-party precedent of
  `release`/`cancel` — there is no taker dual-signature on
  `NftEscrow`). An empty list clears the gate back to ungated; a
  non-empty list is rebuilt through the same `new` + `add` path as
  build time, and more than 8 distinct collections fail closed
  (`InvalidCollectionAllowlist`, code 358) with the original gate
  untouched. Re-affirming the current set in any order is a no-op,
  only the gate changes (mint, observed collection, and state are
  untouched), `cancel` stays ungated, and the new table governs
  from the next `release`. No event is emitted — `NftEscrow` has no
  event layer.

New error codes (never renumbered): `InvalidNftMint` (256),
`CollectionNotAllowlisted` (257), `InvalidCollectionAllowlist`
(358). Pure logic: no Vault layout change,
no `VAULT_SPACE` bump (the layout pin tests still hold). (Solana: NFT
custody.)

## Merkle distributor (AV-188)

`escrow-state/src/merkle_distributor.rs` — one vault funds many
claims. The maker funds once and publishes a SHA-256 Merkle root over
`(recipient, amount)` leaves; claimants redeem by presenting an
inclusion proof; a nullifier bitmap stops double-claims; after the
expiry slot the maker reclaims whatever was never claimed. This is the
batch-distribution / airdrop shape: the on-chain footprint is one
root, not N accounts.

- **Canonical construction** (the off-chain builder must match it
  exactly): `leaf = sha256("escrow-dist-leaf\x00" || recipient(32) ||
  amount_le(8))`; internal nodes use canonical pair ordering,
  `node = sha256("escrow-dist-node\x00" || min(a,b) || max(a,b))`, so
  builder and verifier cannot disagree on orientation; an odd node is
  promoted unchanged and contributes no proof element. The verifier
  folds the proof against the stored root — a tampered amount,
  recipient, or proof fails with `InvalidMerkleProof` (259).
- **Double-claim is impossible**: one nullifier bit per leaf index
  (`[u64; 4]`, 256 leaves max, heap-free) is set before the claim
  returns, so a re-entrant caller cannot re-enter; a second claim is
  `AlreadyClaimed` (260).
- **No racing**: the claim window is `current_slot < expiry_slot`
  (strict — claiming *at* expiry fails with `DistributionExpired`,
  code 261); the maker's reclaim window is `current_slot >=
  expiry_slot` (inclusive), and reclaiming early is
  `DistributionNotExpired` (262). Reclaim is maker-only and terminal.

New error codes (never renumbered): `InvalidDistribution` (258),
`InvalidMerkleProof` (259), `AlreadyClaimed` (260),
`DistributionExpired` (261), `DistributionNotExpired` (262). Pure
logic: no Vault layout change, no `VAULT_SPACE` bump. (Solana /
payments fintech: batch distribution / airdrops.)

## English auction (AV-189)

`escrow-state/src/english_auction.rs` — ascending-bid settlement:
bidders compete upward, every bid must beat the current highest by at
least the minimum increment, and the seller's reserve price decides
whether the sale happens at all.

- **Ascending bids, minimum raise**: the minimum legal bid is
  `highest_bid + min_increment`; the opening bid must itself clear
  `min_increment`, so the increment doubles as the minimum opening
  bid. A bid at the closing slot (`current_slot >= end_slot`) is too
  late — the end is strict.
- **Anti-sniping**: a bid landing inside the tail window pushes the
  close out by the configured extension (bounded by a maximum number
  of extensions, `MAX_SNIPE_EXTENSIONS` = 64, so a bidding war cannot
  postpone settlement forever). The bid receipt reports whether the
  bid extended the close and the new end slot.
- **Reserve price**: the seller's floor, set at construction. If the
  highest bid never reaches it, settlement returns `ReserveNotMet`
  and every bidder is refunded in full; with no bids at all the
  outcome is `NoBids`. The reserve is inclusive — a winning bid
  exactly at the reserve sells.
- **Reserve revision** (AV-306): before the first bid the seller may
  revise the floor with `amend_english_auction_reserve_price` —
  seller-only (`Unauthorized`, code 100), and refused with
  `InvalidEnglishAuction` (code 263) once a bid has landed or the
  auction is terminal, so terms bidders already accepted are never
  rewritten. Any `u64` is legal, including `0` (cancels the reserve);
  re-affirming the current floor is a no-op. Only `reserve_price`
  changes; `settle` reads the live value, so a highest bid below the
  new floor is judged `ReserveNotMet`. `reserve_price_audit_json`
  records the previous and new floor (string event name
  `english_auction_reserve_price_amended`, no new event code).
- **Minimum-increment revision** (AV-307): before the first bid the
  seller may revise the minimum raise with
  `amend_english_auction_min_increment` — seller-only
  (`Unauthorized`, code 100), and refused with
  `InvalidEnglishAuction` (code 263) once a bid has landed or the
  auction is terminal, so terms bidders already accepted are never
  rewritten. The new value must be greater than `0` (a zero
  increment would let bids creep by nothing); re-affirming the
  current increment is a no-op. Only `min_increment` changes;
  `place_bid` reads the live value, so the opening bid must clear
  the new increment and every later bid must beat the highest by
  it. `min_increment_audit_json` records the previous and new
  increment (string event name
  `english_auction_min_increment_amended`, no new event code).
- **Refunds are exact**: `place_bid` returns a `BidReceipt` naming the
  outbid leader and their amount, so the program refunds the full
  previous bid atomically; `settle` is permissionless after the close
  and terminal. The seller may `cancel` only before the first bid.
- **Buy-it-now** (AV-201): `with_buyout(price)` sets an opt-in buyout
  price — any legal bid at or above it settles the auction immediately
  at exactly that price (the bid is capped), skipping the remaining
  window and any anti-sniping extension. The receipt reports
  `buyout: true` with the outbid leader for the exact full refund (the
  AV-194 deposit path reuses these fields unchanged). Fail-closed
  config: a price below `min_increment` could never trigger, and a
  price below a nonzero reserve would sell under the seller's floor —
  both are refused; the price locks before the first bid
  (`EnglishAuctionBuyoutLocked`, code 314). `buyout_audit_json`
  records the winner, price, and refunded leader.

New error codes (never renumbered): `InvalidEnglishAuction` (263),
`EnglishAuctionBidTooLow` (264), `EnglishAuctionNotLive` (265),
`EnglishAuctionSettleTooEarly` (266),
`EnglishAuctionNotCancellable` (267),
`EnglishAuctionBuyoutLocked` (314). Pure logic: no Vault layout
change, no `VAULT_SPACE` bump. Orthogonal to AV-97 (Dutch auction,
descending price). (Solana: auction primitives.)

## Rental escrow (AV-190)

`escrow-state/src/rental_escrow.rs` — time-boxed custody of an
asset. The renter pays rent and receives *temporary custody* (use,
not ownership) of the asset for the lease term; when the term
expires, custody returns to the owner automatically.

- **Use-right time box**: the asset is held by the escrow program
  while the renter has use of it — it never transfers ownership, so
  the term end is a custody handoff, not a sale. `asset_id` is the
  caller's placeholder for whatever the program holds (an NFT mint,
  a token account, …), exactly like AV-187's `MintDescriptor`
  observer pattern.
- **Overdue pricing, opt-in**: `LateFeeTerms` charges basis points
  per overdue day (any partial day counts as a full day), capped at
  `cap_bps` of the rent amount. `None` opts out — overdue returns
  are then free but still recorded as late (`ReturnedLate` only
  applies with a schedule).
- **Clean edges**: returning exactly at `term_end_slot` is on time
  (the end is inclusive); an early return is clean; the renter can
  never re-return and the owner can only cancel before the term
  starts — after that the asset must be returned, not cancelled.
- **Fail-closed terms**: zero owner/renter keys, a self-lease, zero
  rent, an empty term, a zero `slots_per_day`, or a rate/cap above
  10_000 bps are all refused at construction.
- **Revising the late fee (AV-291)**: `amend_late_fee` revises the
  schedule on an `Active` rental, authorized by owner + renter
  together — the late fee is a bilateral economic term, so a
  unilateral rewrite would let one side reprice the other's overdue
  cost alone. The new terms reuse the construction gate (a rate/cap
  above 10_000 bps fails closed with `InvalidRentalTerms`, code 268,
  and the current schedule is untouched); an explicit `None` clears
  back to opt-out, and re-affirming the current schedule is a no-op.
  Only `late_fee` changes, and `late_fee_due` / `return_asset` read
  the live schedule, so the new terms govern from the next billing —
  a fee already settled by a return is never restated. No event is
  emitted — `RentalEscrow` has no event layer.
- **Extending the term (AV-292)**: `extend_term_end` moves the term
  end on an `Active` rental, authorized by owner + renter together —
  the term is a bilateral use-right window. Extension only, never
  shrinkage: the new end must lie strictly past the current end (an
  equal-value call is an invalid extension, not a re-affirmation),
  and an already-overdue rental cannot extend at all — its fee has
  already accrued against the old window, so extending it would
  retroactively erase overdue days (both refusals are
  `InvalidRentalTerms`, code 268, with the window untouched). Only
  `term_end_slot` changes — the rent amount is not repriced, since
  the same total rent covers the longer window — and `is_in_term` /
  `is_overdue` / `late_fee_due` / `return_asset` read the live
  window, so the new window governs from the revision. No event is
  emitted — `RentalEscrow` has no event layer.

New error codes (never renumbered): `InvalidRentalTerms` (268),
`RentalNotActive` (269), `RentalCancelNotAllowed` (270). Pure logic:
no Vault layout change, no `VAULT_SPACE` bump. Orthogonal to AV-187
NFT escrow (ownership transfer) and AV-13 vesting (linear release).
(Solana: leasing primitives.)

## Program upgrade-authority handover (AV-179)

`escrow-state/src/upgrade_authority.rs` — the two-step propose/accept
handover for the program's BPF-loader upgrade authority, with an
opt-in handover delay and keeper drift alerts (Solana governance /
backend engineering).

On Solana, `set_upgrade_authority` is a single instruction: whoever
holds the upgrade authority can reassign it in one transaction,
irreversibly and silently. A fat-fingered key or a compromised
authority bricks the program's upgradability in one shot, and no
on-chain record explains who moved the authority or why.
`UpgradeAuthority` is the executable spec of the safe handover:

- **Two-step**: the current authority *proposes* a successor
  (`propose_handover`); the *proposed* key must *accept*
  (`confirm_handover`). The current authority can never silently hand
  the program to a key nobody controls — the recipient opts in (the
  Ownable2Step shape, adapted to program governance).
- **Delay**: `handover_delay_secs` (bound at construction) forces a
  cooling period between proposal and acceptance; a rushed or coerced
  handover cannot complete inside the window. The clock is injected
  (`now: u64`), so the policy is fully testable off-chain.
- **Structured audit**: propose / confirm / cancel append an
  `UpgradeAuditEntry` (kind, timestamp, actor, successor) to a bounded
  32-entry ring — the AV-163 circuit-breaker convention (fixed-size
  tail, oldest evicts first).
- **Keeper drift scan**: `scan_upgrade_authority_drift` diffs the live
  authority against the operator-approved template and raises a drift
  alert — the AV-175 config-drift vocabulary for program governance. A
  drifted authority is either a completed handover the operator did not
  approve or a tampered program account.

New error codes (never renumbered): `InvalidUpgradeAuthority` (242),
`UpgradeHandoverPending` (243), `NoUpgradeHandoverPending` (244),
`UpgradeHandoverDelayNotElapsed` (245). Check order mirrors AV-163
(authority first, then validity, then state).

## SPL freeze/thaw authority custody (AV-180)

`escrow-state/src/freeze_authority.rs` — the escrow program's SPL
freeze switch over managed token accounts: the payments-risk tool for
tainted funds (Solana / payments risk control).

The program is the freeze authority of the vaults' SPL token accounts
(bound at token-account initialization — the program, not a user key,
holds the freeze switch). `ManagedFreezeAuthority` is the executable
spec of that custody, one struct per managed token account:

- **Strict toggle**: `freeze` / `thaw` flip only through the bound
  freeze authority; freezing a frozen account (or thawing an unfrozen
  one) is a loud refuse (`TokenAccountAlreadyFrozen` /
  `TokenAccountNotFrozen`), never a silent no-op — the AV-163 toggle
  semantics.
- **The settlement lock**: `require_unfrozen` is the guard the program
  calls at the top of `release` / `cancel` / `claim` — while the token
  account is frozen, no settlement moves funds (`EscrowFrozen`, fail
  fast before any state is touched). The account is immobilized in
  place, not drained: freezing is the investigate-then-decide tool, not
  the verdict. Orthogonal to the AV-46 per-escrow pause (an
  escrow-level switch) and the AV-163 program breaker (a program-wide
  halt) — this is the token-account-level freeze, the finest-grained
  stop in the stack.
- **Authority rotation with audit**: `set_freeze_authority` rotates the
  bound key (only the current authority; the successor must be a live,
  distinct key); every freeze / thaw / rotation appends a
  `FreezeAuditEntry` to the bounded 32-entry ring. Rotating the
  authority never thaws the account — the freeze survives custody
  changes.

New error codes (never renumbered): `InvalidFreezeAuthority` (246),
`TokenAccountAlreadyFrozen` (247), `TokenAccountNotFrozen` (248),
`EscrowFrozen` (249). Off-chain executable spec only: real
`FreezeAccount` / `ThawAccount` are token-program CPIs the on-chain
program issues after this custody check (the AV-163 honesty contract).

## Social recovery for lost initializer keys (AV-195)

`escrow-state/src/social_recovery.rs` — the key-loss escape hatch for
escrows whose initializer lost their key: an M-of-N guardian policy
that rotates the initializer to a fresh key after a timelock (Solana /
wallet recovery UX).

The initializer configures the policy (`configure_social_recovery`:
1–8 guardian keys, threshold 1..=N, timelock in seconds; zero or
duplicate guardians rejected as `InvalidRecoveryPolicy`, code 286;
threshold above the guardian count is `InvalidRecoveryThreshold`,
code 287). A guardian opens a recovery request naming the new
authority (`request_recovery`; one live request at a time —
`RecoveryAlreadyPending`, code 288); other guardians approve
(`approve_recovery`; the requester counts as the first approval;
double-approval is `RecoveryAlreadyApproved`, code 289). Once the
threshold is met AND the timelock has elapsed since the request opened,
anyone can execute (`execute_recovery` — the permissionless crank;
`RecoveryThresholdNotMet`, code 290, or `RecoveryTimelockNotElapsed`,
code 291, before that). The current initializer can veto at any time
before execution (`veto_recovery`; a stranger's veto is
`RecoveryVetoDenied`, code 292).

The policy persists in the vault account (the 309-byte
`SocialRecovery` tail: 8 guardian slots + count + threshold +
timelock + the flattened pending request). Executing rewrites the
initializer region in place — the escrow itself (amount, taker, state)
is untouched. Approvals are never withdrawn (no take-backs: the
timelock + veto is the safety, not revocation).

Layout growth: the vault body grows from 7345 to 7654 bytes (+309:
the 309-byte social-recovery tail), `VAULT_SPACE_NO_QUORUM` from 6863
to 7172, `VAULT_SPACE` from 7353 to 7662, and the close-time rent
reclamation from 52_067_760 to 54_218_400 lamports
(`(128 + VAULT_SPACE) * 3480 * 2`).

## Dispute jury sortition (AV-196)

`escrow-state/src/jury_sortition.rs` — the decentralized dispute
resolution path: a staked juror registry with deterministic,
verifiable sortition into dispute panels (Solana / DAO governance).

The program (or DAO) maintains a `JurorRegistry` of staked jurors
(`register_juror`: non-zero stake, live key; duplicate or zero-stake
is `InvalidJuror`, code 293). When an escrow escalates with jury mode
enabled (`configure_jury`: panel size 1–8, odd sizes recommended for
clean majorities; `InvalidJuryPanelSize`, code 294), the panel is drawn
by deterministic sortition: `seed = SHA-256(slot_hash || escrow_id)`,
jurors sorted by `SHA-256(seed || juror_key)` — anyone can recompute
the draw from the public seed, no trusted dealer. The initializer's
AV-14 single arbiter and the jury are mutually exclusive (configuring
either when the other is set is `JuryArbiterConflict`, code 295, both
directions).

Each drawn juror votes once (`cast_vote`: the juror's taker-amount
ballot; double-vote is `JuryDoubleVote`, code 296); when every panel
seat has voted, the median ballot is the verdict (`tally`: strict
majority of the panel size; `JuryQuorumNotMet`, code 297, before
that). The verdict settles exactly like an arbiter's `resolve` (fee
slices, pro-rata splits). A juror who never votes can be slashed
after the vote window (`slash_absent_juror`).

The panel size persists as the 1-byte `jury_panel_size` tail on the
vault (`0` = no jury); the registry and panel live in program PDAs
(off-chain executable spec here). Sortition is seed-public and
replayable: the same `(slot_hash, escrow_id)` always draws the same
panel.

Layout growth: the vault body grows from 7654 to 7655 bytes (+1: the
jury panel-size byte), `VAULT_SPACE_NO_QUORUM` from 7172 to 7173,
`VAULT_SPACE` from 7662 to 7663, and the close-time rent reclamation
from 54_218_400 to 54_225_360 lamports (`(128 + VAULT_SPACE) * 3480 *
2`).

## Bidirectional payment channel (AV-197)

`escrow-state/src/payment_channel.rs` — a Lightning-style
bidirectional payment channel over escrow-locked funds (Solana / L2
real-time systems).

The channel state machine is independent of the main escrow machine:
a `PaymentChannel` is a standalone structure the program keeps in its
own PDA (off-chain executable spec here), so there is **no vault
layout growth** and no rent math changes in this item.

Lifecycle: `open` (two distinct non-zero parties, `total > 0`,
`challenge_period`) → `fund(split_a)` commits the initial split and
moves `Unfunded → Open` → off-chain `apply_update` (both parties
co-sign each state) → settlement is either `close_cooperative`
(dual-signed final state, instant) or `close_unilateral` (one party
submits the latest co-signed state, challenge window opens;
`dispute` with a newer co-signed state replaces it and restarts the
window; `finalize` settles once the window elapses).

Safety properties (all pinned by tests):

- Every signed payload binds the channel identity
  (`party_a || party_b || total`) in its canonical bytes
  (`PAYMENT-CHANNEL-v1` domain), so a signature minted for one channel
  can never be replayed on another — even between the same parties.
- A state is valid only when **both** parties signed it; the
  unilateral path is unilateral only in submission. A submitter can
  never settle on a state the counterparty did not co-sign.
- Nonce is strictly monotonic (`apply_update` requires exactly
  `nonce + 1`; close/dispute require `nonce > current`) — the replay
  protection.
- Conservation is checked in `u128`: every split must sum to `total`
  exactly (`ChannelBalanceMismatch`, code 303); no update can mint or
  burn lamports.
- Check order is authority-first: a stranger's
  `close_unilateral`/`dispute` is `Unauthorized` (code 100) before any
  state is examined.

New error codes 299–303: `InvalidChannelConfig`,
`InvalidChannelState`, `InvalidChannelSignature`, `StaleChannelNonce`,
`ChannelBalanceMismatch`. `finalize` on an unelapsed window and
`dispute` after expiry are `InvalidChannelState` (code 300) — the
window state, not a new error, decides which call is legal.

## Payment streams (AV-198)

`escrow-state/src/stream.rs` — a Sablier-style per-second payment
stream (Solana real-time finance: salary streams, per-second
settlement).

A `PaymentStream` pays a recipient continuously at a fixed
`rate_per_sec`: the earned amount grows with every passing second
(`earned = rate × elapsed`, all computed in `u128` so it cannot
overflow, then capped at the funded total) and the recipient may
withdraw any earned-but-unwithdrawn amount at any time. The
initializer funds the stream up front (`total = rate_per_sec ×
duration_secs`, refused at construction if the product does not fit
`u64`) and may cancel at any time: earned-so-far routes to the
recipient, the unearned remainder returns to the initializer,
terminally. An optional `cliff_secs` gates the first payout — before
`start_ts + cliff_secs` the earned amount reports `0` (the cliff
delays payout, it does not consume the stream: accrual runs from
`start_ts`). The initializer may also `pause`/`resume`; paused
intervals are tracked and permanently excluded from accrual.

- Continuous release, not tranches: this is per-second accrual,
  orthogonal to AV-13 vesting (one lump sum that unlocks whole at
  expiry) and to AV-197 bidirectional channels (both parties co-sign
  off-chain state — here release is unilateral, no signatures).
- Idempotent withdrawals: a zero-earn withdraw is `Ok(0)`, not an
  error; withdrawing the full total flips the stream to `Exhausted`
  automatically. Any op on a `Cancelled`/`Exhausted` stream is
  `StreamNotActive` (code 306).
- Check order is authority-first: a non-recipient `stream_withdraw`
  and a non-initializer `stream_cancel`/`pause`/`resume` are
  `StreamUnauthorized` (code 305) before any state is examined.
- Recipient transfer (AV-202): the *current* recipient may hand the
  whole stream to a new recipient with `transfer_recipient(caller,
  new_recipient)` — the payroll-to-new-wallet scenario (lost recipient
  key, invoice reassigned to a new contractor). The initializer may
  cancel but may *not* reassign. The stream survives: rate, schedule,
  initializer, withdrawn total, paused intervals and state are
  untouched; the new recipient inherits the earned-but-unwithdrawn
  balance and keeps accruing, and the old key loses all rights (it is
  a stranger afterwards). Orthogonal to `stream_cancel` (terminal) —
  this is a *continuing* transfer, not a termination. Check order is
  authority → state → config: a zero `new_recipient` is `InvalidStream`
  (code 304); transferring to the current recipient is an idempotent
  no-op. Emits the `stream_recipient_transferred` audit event
  (`PaymentStream::transfer_audit_json`, hand-written JSON, no new
  error codes — 304–308 unchanged).
- Rate renegotiation (AV-204): `update_stream_rate(initializer,
  recipient, new_rate, now)` reprices the stream mid-flight, but only
  when *both* parties sign — either party absent, or a stranger in
  either slot, is `StreamUnauthorized` (code 305). Only future accrual
  changes: the amount earned under the old rate is checkpointed at
  change time (chained across successive changes, so a second
  renegotiation never reprices the first period) and the funded total
  still caps everything — a rate increase reaches the cap sooner, it
  never pays more than was funded. Zero and `u64`-overflowing
  (`new_rate × duration_secs`) rates are `InvalidStream` (code 304);
  changing to the current rate is an idempotent no-op; terminal
  streams are `StreamNotActive` (code 306); a change while paused is
  legal and applies from resume. The cliff interplay is deliberate:
  the checkpoint stores the *ungated* accrued amount, so a pre-cliff
  change does not erase pre-change accrual (it stays gated until the
  cliff elapses). Emits the `stream_rate_updated` audit event
  (`PaymentStream::rate_update_audit_json`, hand-written JSON, no new
  error codes — 304–308 unchanged). Keeper scanning reads the stream
  through `rate_per_sec()`, so it sees the new rate with no separate
  integration: there is no stored/scanned stream state in `keeper.rs`
  or `snapshot.rs` to pass through (both only mention streams in
  unrelated prose), and the Anchor IDL carries no standalone-stream
  instructions, so neither file changes in this item.
- Cliff renegotiation (AV-297): `amend_stream_cliff_secs(initializer,
  recipient, new_cliff_secs)` moves the first-payout gate mid-flight,
  but only when *both* parties sign — either party absent, or a
  stranger in either slot, is `StreamUnauthorized` (code 305). Only
  future payouts change: the cliff gates payout, not accrual, so
  moving it never reprices anything and needs no checkpoint — the
  checkpoint stores the *ungated* accrued amount, and `earned` /
  `stream_withdraw` read the live cliff on every call. Raising the
  cliff past `now` re-gates the stream (a withdraw then returns `0`
  until the new cliff elapses, never a clawback of what was already
  withdrawn); lowering it releases the gated accrual at once. The new
  cliff reuses the `create_stream` gate (`new_cliff_secs <=
  duration_secs`, else `InvalidStream` (code 304), the original cliff
  untouched); changing to the current cliff is an idempotent no-op;
  terminal streams are `StreamNotActive` (code 306); a change while
  paused is legal and applies from resume. Emits the
  `stream_cliff_updated` audit event
  (`PaymentStream::cliff_update_audit_json`, hand-written JSON, no new
  error codes — 304–308 unchanged). `earned()` reads the live cliff on
  every call, so any consumer of `earned()` sees the new gate with no
  separate integration — same as the rate change, there is no
  stored/scanned stream state in `keeper.rs` or `snapshot.rs` to pass
  through (both only mention streams in unrelated prose), and the
  Anchor IDL carries no standalone-stream instructions. Orthogonal to `update_stream_rate`
  (that is the per-second price, this item is the first-payout gate)
  and to `stream_cancel` / `pause` (those are lifecycle, this item is
  a parameter revision).
- Duration renegotiation (AV-298): `amend_stream_duration_secs(initializer,
  recipient, new_duration_secs, now)` moves the accrual window's end
  (`end_ts = start_ts + duration_secs`) mid-flight, but only when
  *both* parties sign — either party absent, or a stranger in either
  slot, is `StreamUnauthorized` (code 305). The amount already earned
  is checkpointed at `now` (exactly like `update_stream_rate`), so
  `earned(now)` is identical immediately before and after the change:
  lengthening lets accrual run longer, shortening caps it earlier, and
  shortening below the seconds already accrued freezes the earned
  amount — it never falls back, and nothing already withdrawn is
  clawed back. The new duration reuses the `create_stream` gate (it
  must be non-zero and at least the live `cliff_secs`, else
  `InvalidStream` (code 304), the original duration untouched);
  changing to the current duration is an idempotent no-op; terminal
  streams are `StreamNotActive` (code 306); a change while paused is
  legal and applies from resume. `total_funded` never moves:
  lengthening creates no new funding obligation and shortening refunds
  nothing already funded — any on-chain funding difference is the
  caller's to settle, the state machine moves no funds. Emits the
  `stream_duration_updated` audit event
  (`PaymentStream::duration_update_audit_json`, hand-written JSON, no new
  error codes — 304–308 unchanged). `earned()` / `stream_withdraw`
  read the live duration on every call, so any consumer sees the new
  window with no separate integration — same as the rate and cliff
  changes, there is no stored/scanned stream state in `keeper.rs` or
  `snapshot.rs` to pass through, and the Anchor IDL carries no
  standalone-stream instructions. Orthogonal to `update_stream_rate`
  (that is the per-second price, this item is the window length), to
  `amend_stream_cliff_secs` (that is the first-payout gate, this item
  is the window length), and to `stream_cancel` (that is lifecycle,
  this item is a parameter revision).
- Start renegotiation (AV-300): `amend_stream_start_ts(initializer,
  recipient, new_start_ts, now)` moves the accrual window's start
  (`end_ts = start_ts + duration_secs` shifts with it) mid-flight,
  but only when *both* parties sign — either party absent, or a
  stranger in either slot, is `StreamUnauthorized` (code 305). Only a
  stream that has not started yet may move its start: `now` must be
  before the live `start_ts` and the new start must be after `now`,
  else `InvalidStream` (code 304), the original start untouched — a
  revision only moves a future start moment, it never backdates the
  stream open. The window slides, it does not stretch: `duration_secs`
  and `total_funded` (`rate × duration`, independent of start) never
  move, and no checkpoint is needed — with no history the checkpoint
  is `(0, 0)` and `earned` / `stream_withdraw` read the live start on
  every call, so the new start takes effect from the next evaluation.
  A stream with any accrual or withdrawal history — a non-`(0, 0)`
  checkpoint pair or a non-zero `withdrawn` — is refused outright,
  fail-closed: changing the start after accrual began would rewrite
  accrued history, and the gate blocks bypassing the `now < start_ts`
  check by pre-setting a checkpoint with a future `now`. Changing to
  the current start is an idempotent no-op; terminal streams are
  `StreamNotActive` (code 306); a change while paused is legal and
  applies from resume. Emits the `stream_start_updated` audit event
  (`PaymentStream::start_update_audit_json`, hand-written JSON, no new
  error codes — 304–308 unchanged). `earned()` / `stream_withdraw`
  read the live start on every call, so any consumer sees the new
  window with no separate integration — same as the rate, cliff, and
  duration changes, there is no stored/scanned stream state in
  `keeper.rs` or `snapshot.rs` to pass through, and the Anchor IDL
  carries no standalone-stream instructions. Orthogonal to
  `update_stream_rate` (that is the per-second price, this item is the
  window start), to `amend_stream_cliff_secs` (that is the
  first-payout gate, this item is the window start), to
  `amend_stream_duration_secs` (that is the window length, this item
  is the window start), and to `stream_cancel` (that is lifecycle,
  this item is a parameter revision).

New error codes 304–308: `InvalidStream`, `StreamUnauthorized`,
`StreamNotActive`, `StreamAlreadyPaused`, `StreamNotPaused`. Pure
logic, standalone module like AV-192 — no vault layout change, no
rent math changes in this item.

## Delivery confirmation gate (AV-203)

Opt-in taker-side receipt confirmation for payouts. The initializer
opts in at construction with `with_delivery_confirmation`
(`Uninitialized`-only; `InvalidStateTransition` afterwards), and the
taker then calls `confirm_delivery()` once the goods or service have
actually arrived. Until that confirmation lands, `release`,
`release_milestone`, and `claim` are all refused with the new error
`DeliveryNotConfirmed` (code 315) — the check sits last, just before
fee charging, so a refused payout moves nothing and charges nothing.
Check order on every gated path is authority → state → … →
delivery-confirmation, and `confirm_delivery` itself is taker-only
(`Unauthorized` otherwise) in `Funded` or `Disputed` state; repeating
it is an idempotent no-op.

Deliberately ungated, so a taker who refuses to confirm can never
trap funds forever: initializer `cancel` / `cancel_expired` and
arbiter `resolve` all still settle without any confirmation, and
disputes stay arbitrable. Orthogonal to AV-130 (authority-side
maker-checker dual control): AV-130 gates *who* may authorize a
release, AV-203 gates *whether the taker has confirmed receipt*.

The indexer emits `DeliveryConfirmed` exactly once, on the first
transition (repeats emit nothing, failures emit nothing). Layout:
two appended vault tail bytes (`delivery_confirmation`,
`delivery_confirmed`), so `ESCROW_BODY_LEN` grows 7655 → 7657 and
`VAULT_SPACE` 7663 → 7665 (rent-exempt 54_225_360 → 54_239_280
lamports); earlier field offsets are untouched.

## Per-call release cap (AV-205)

Opt-in ceiling on how much a single payout call may move. The
initializer opts in at construction with `with_max_release_per_call`
(`Uninitialized`-only; a zero cap is `AmountMismatch`, because `0`
in storage always means "no cap"). While a non-zero cap is set, a
single `release`, `release_milestone`, `claim`, `release_split`,
or `release_payout_split` call whose gross amount exceeds the cap
is refused with the new error `ReleaseExceedsCap` (code 316) — the
check sits just before fee charging (second-to-last, right before
the AV-203 delivery gate on the three gated paths), so a refused
payout moves nothing and charges nothing.

The cap is per call, not cumulative: a deal larger than the cap
still settles in several capped calls, while a fat-fingered amount
or a stolen key can never drain the lockup in one move. For
`release_split` the cap binds the gross split total, so splitting
a too-large call across recipients never evades it; for `claim`
a pull larger than the cap refuses outright rather than paying a
capped slice. The AV-108 table path is capped identically —
otherwise the cap would be trivially bypassable through the
declared table. Deliberately out of scope: `claim_share` (roster
shares are pre-declared at setup), `release_period` (scheduled
period amounts), and the arbiter's `resolve` (not an initializer
payout) — the cap gates initializer/taker payout calls, not every
fund movement.

Combination with AV-130 dual control runs both ways: a
`initiate_release` declaration above the cap never becomes a live
intent (`ReleaseExceedsCap` at declaration), and `confirm_release`
re-checks the live cap through `release_impl` at settlement, so a
cap lowered after declaration still refuses the confirm while the
intent stays live for a retry. The cap itself changes only by
initializer+taker dual signature via `update_release_cap`
(`Funded` or `Disputed`; either party alone is `Unauthorized`):
it can be raised or lowered, but never removed — a live cap of
`0` is rejected, so `0` in storage always means "never opted in".

Layout: one appended vault tail u64 (`max_release_per_call`), so
`ESCROW_BODY_LEN` grows 7657 → 7665 and `VAULT_SPACE` 7665 → 7673
(rent-exempt 54_239_280 → 54_294_960 lamports); earlier field
offsets are untouched. No new indexer event: the cap is a config
value readable from the vault account, and cap changes are not
settlements.

## Delegation spend cap (AV-208)

The AV-104 operator grant bounds *which* transitions an operator
may run, but not *how much* they may move — a stolen hot wallet
with RELEASE scope could drain the lockup one legal call at a
time. `delegate_authority_with_spend_cap(caller, delegate, scopes,
spend_cap)` adds a cumulative volume bound to the grant: every
operator-settled gross release (`release` through `release_impl`,
and the AV-108 table path `release_payout_split`) accumulates into
the grant's `spent` counter, and a release that would push `spent`
past the cap is refused with `SpendCapExceeded` (code 318) and
consumes nothing. The cap binds gross amounts (the AV-205
convention), sits after every other gate so refused releases never
consume cap, and never auto-revokes the grant — a capped-out
operator keeps their scope for non-release paths until a party
revokes or overwrites. Party releases never count toward the cap;
a zero cap is `InvalidDelegation` (`0` in storage always means
"never capped", so a capped grant is never ambiguous with an
AV-104 grant); re-granting the identical triple is a no-op that
keeps the live `spent`, while overwriting with a new cap resets it;
rotation clears the grant, cap and counter together. Paths an
operator cannot drive (`release_split`, `release_milestone`,
`claim`) need no accounting — their authority gates already refuse
operators.

Layout: the delegation region grows 37 → 53 bytes (u64 spend cap
+ u64 spent), so `ESCROW_BODY_LEN` grows 7731 → 7747,
`VAULT_SPACE` 7739 → 7755 (rent-exempt 54_754_320 → 54_865_680
lamports), and the no-quorum space 7249 → 7265; fields after the
delegation region shift by 16 bytes, earlier offsets are
untouched. Note the scope boundary: this item is the state machine
(`escrow-state`) plus the regenerated IDL — the Anchor instruction
that grants a capped delegation on-chain is follow-up Anchor work,
not claimed here (the program's `escrow_error` mapping is already
stale for several recent variants and is not repaired in this
round).

## Delegation spend-cap revision (AV-295)

A capped grant's bound is no longer frozen at grant time.
`amend_delegation_spend_cap(caller, new_cap)` revises the live
grant's spend cap in place: either party may move it — up, down,
or to `0` (uncapped, the AV-208 storage meaning) — and the
operator spend path reads the live cap on every release, so the
new bound governs from the next operator release onward while a
release already settled keeps the cap it settled under. The
fail-closed floor is the settled volume itself: a new cap below
the live `spent` is `InvalidDelegation` (code 160) and leaves the
original cap untouched, so a revision can never retroactively
declare settled operator volume over-cap; exactly at `spent` is
allowed, and the next operator release is then refused until the
cap moves again. Only the cap moves — the operator, the scopes,
`spent` and the expiry window are untouched, and revising to the
current cap is a no-op success. Check order mirrors
`renew_delegation` (pause → party authority → `Uninitialized` /
`Funded` state → config), a stranger or the operator themselves
is `Unauthorized`, and no live grant is `InvalidDelegation`.
No new event: like renewal, the amendment emits nothing — the
`IndexedEscrow` wrapper needs no new emission — and no layout
change: the cap already lives in the AV-208 delegation region,
so no field offset moves. Orthogonal to `renew_delegation` (that
is the expiry window, this item is the cap) and to AV-104 (that
is the grant mechanism itself, this item is the cap revision).
Boundary: the Anchor instruction accepting a cap revision on
chain is follow-up work — no such instruction is claimed.
(Solana: delegation governance.)

## Delegation scope revision (AV-296)

A grant's powers are no longer frozen at grant time.
`amend_delegation_scopes(caller, new_scopes)` revises the live
grant's scope bitmap in place: either party may narrow or widen it
— dropping the release bit to cut an operator off from payouts, or
adding the fund bit to let the same operator fund — and the operator
paths read the live bitmap on every call, so the new powers govern
from the next operator call onward while a call already settled is
never re-judged. The fail-closed gate is the bitmap itself: only a
bitmap `validate_delegation_scopes` accepts (non-empty, within
`DELEGATION_SCOPE_MASK`) may land — an empty bitmap or unknown bits
are `InvalidDelegation` (code 160) and leave the original bitmap
untouched, so a revision can never smuggle a broader grant into an
old bitmap or silently empty one. Only the scopes move — the
operator, the spend cap, `spent` and the expiry window are untouched,
and revising to the current bitmap is a no-op success. Check order
mirrors the cap revision (pause → party authority →
`Uninitialized` / `Funded` state → config), a stranger or the
operator themselves is `Unauthorized`, and no live grant is
`InvalidDelegation`. No new event: like renewal and the cap revision,
the amendment emits nothing — the `IndexedEscrow` wrapper needs no
new emission — and no layout change: the bitmap already lives in the
AV-104 delegation region, so no field offset moves. Orthogonal to
`amend_delegation_spend_cap` (that is the volume bound, this item is
the scope bitmap) and to AV-104 (that is the grant mechanism itself,
this item is the scope revision). Boundary: the Anchor instruction
accepting a scope revision on chain is follow-up work — no such
instruction is claimed. (Solana: delegation governance.)

## Delegation operator rotation (AV-301)

A grant's operator is no longer frozen at grant time.
`rotate_delegation_delegate(caller, new_delegate)` swaps the live
grant's delegate key in place: either party may cut off a
compromised hot wallet with one rotation — no re-grant, no new grant
to configure — and the operator paths read the live delegate on
every call, so the new operator is effective from the next operator
call and the old operator loses power at once, while a call already
settled is never re-judged. The fail-closed gate is the new key
itself: a zero key is `InvalidDelegation` (code 160) and leaves the
original delegate untouched, and no live grant is
`InvalidDelegation`. Only the delegate moves — the scopes, the spend
cap, `spent` and the expiry window are untouched, and `spent` is
never cleared. That last point is the whole item: a rotation is an
identity change, not a re-authorization, and reusing the
`delegate_authority` re-grant path would reset `spent` to `0`,
laundering the settled volume out of the cap — so the delegate
field is rewritten in place and the cap keeps binding the grant's
cumulative volume, never one operator's personal volume. Rotating to
the current delegate is a no-op success. Check order mirrors the
scope revision (pause → party authority → `Uninitialized` /
`Funded` state → config), a stranger or the operator themselves is
`Unauthorized`, and no layout change: the delegate already lives in
the AV-104 delegation region, so no field offset moves. No new
event: like renewal and the cap and scope revisions, the rotation
emits nothing — the `IndexedEscrow` wrapper needs no new emission.
Orthogonal to `renew_delegation` (that is the expiry window, this
item is the operator identity), to `amend_delegation_spend_cap`
(that is the volume bound, this item is the identity), to
`amend_delegation_scopes` (that is the scope bitmap, this item is
the identity) and to AV-104 (that is the grant mechanism itself,
this item is the identity rotation). Boundary: the Anchor
instruction accepting a delegate rotation on chain is follow-up work
— no such instruction is claimed. (Solana: delegation governance.)
