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
| `initialize_arbiter_panel(members, threshold)` (AV-65) | `Uninitialized`| `Uninitialized` | initializer (once, before funding; opt-in multisig arbitration: 1–8 member keys, threshold 1..=N, zero/duplicate keys rejected as `InvalidArbiterPanel`, code 136; mutually exclusive with the single arbiter — last-wins in both directions; `rotate_arbiter` is `InvalidStateTransition` in panel mode) |
| `escalate(authority, now, evidence_hash)`   | `Funded`       | `Disputed` | initializer **or** taker, only when `now < expires_at` (locks `release`/`cancel`/`cancel_expired`/`claim`); `evidence_hash` is the optional 32-byte off-chain-evidence commitment, persisted |
| `resolve(authority, taker_amount, rationale_hash)` | `Disputed`     | `Settled` | arbiter only; atomic split of the remainder (taker payout / initializer refund); `rationale_hash` is the optional 32-byte commitment to the arbiter's off-chain rationale document, persisted in `Settled` (never cleared); **disabled in panel mode** (`PanelResolveDisabled`, code 137 — the panel's multisig judgment is the only settlement path once a panel is configured) |
| `submit_panel_judgment(member, taker_amount, rationale_hash)` (AV-65) | `Disputed` | `Disputed` (vote recorded) / `Settled` (M matching votes) | panel member only (`Unauthorized` for a stranger); one effective vote per member — a re-vote overwrites the earlier vote (the `PanelJudgment` event keeps the audit trail); the first M votes agreeing on the same `(taker_amount, rationale_hash)` pair settle the escrow automatically (`Settled`, settlement identical to `resolve` — fee slices the taker's share, gross lands in the `released` counter, the initializer is refunded the remainder); non-matching votes stay recorded for audit; the settling vote emits `PanelResolved` after its `PanelJudgment`; `InvalidArbiterPanel` (code 136) with no panel configured |
| `initialize_default_judgment(deadline_secs, default_taker_amount)` (AV-55) | `Uninitialized` | `Uninitialized` | initializer (once, before funding — and only after `initialize_arbiter`; the arbiter must be configured first); declares the fallback split applied when the arbiter never resolves: `deadline_secs` seconds in `Disputed` before the judgment becomes triggerable (must be non-zero — `DefaultJudgmentNotDue` otherwise), `default_taker_amount` the taker's share of the remainder (must be ≤ the locked amount — `ReleaseExceedsLocked` otherwise); the initializer proposes the terms, the taker must still countersign (dual-signed agreement) |
| `confirm_default_judgment()` (AV-55) | `Uninitialized` / `Funded` | — (no state change; sets the confirmation bit) | **taker only** (`Unauthorized` for a stranger or the initializer); no judgment configured is `DefaultJudgmentNotDue`; idempotent (re-confirming is `Ok`) |
| `trigger_default_judgment(caller, now, payout_to)` (AV-55) | `Disputed` | `Settled` | **initializer or taker** (either party — a liveness backstop, not a power grant); only once `now >= disputed_at + deadline_secs` (the judgment's due time, `DefaultJudgmentNotDue` otherwise); settles on the pre-agreed split — fee slices the taker's share like `resolve`, quorum/vesting/timelock do *not* gate (same as `resolve`); the arbiter's `resolve` is unchanged and keeps priority — after the deadline either the arbiter resolves or a party triggers, first writer wins; in AV-65 panel mode the default judgment stays available (same deadline rules) and races the panel's M-vote settlement instead; emits `DefaultJudgment` |
| `initialize_evidence_deadline(deadline_secs)` (AV-68) | `Uninitialized` | `Uninitialized` | initializer (once, before funding — and only after the arbiter/panel is configured, `InvalidArbiter` otherwise); declares the window the escalating party gets to disclose the dispute evidence, measured from `disputed_at`; must be non-zero (`InvalidEvidenceDeadline`, code 138, otherwise) |
| `submit_evidence(authority, evidence_hash, now)` (AV-68) | `Disputed` | `Disputed` (commitment recorded) | **escalating party only** (the party `escalate` recorded — a stranger or the counterparty is `Unauthorized`); overwrites any previously attached hash (a within-deadline submission may always refine the bundle); at or past the disclosure deadline the submission is rejected (`EvidenceDisclosureLate`, code 139) — the deadline is a hard bar, so a missed deadline locks in the judgment-time adverse inference; with no deadline configured disclosure is accepted at any time while `Disputed`; emits `EvidenceSubmitted` |
| `update_panel_threshold(initializer, taker, new_threshold)` (AV-69) | `Uninitialized` | `Uninitialized` | **dual-signed** — the initializer AND the taker must both sign (one party alone, or a stranger pair, is `Unauthorized`); retunes the arbiter panel's M-of-N judgment threshold, 1 ≤ M ≤ N (`InvalidArbiterPanel`, code 136, for 0, above N, or no panel configured); a panel must be configured — there is no threshold to retune on a single-arbiter escrow; `Uninitialized` only — the threshold must be settled before the dispute starts, so an in-flight arbitration tallies under stable rules; the retune rewrites only the threshold — cast votes and the `voted` bitmask survive, counting continues under the new M; retuning to the current threshold is an idempotent no-op; emits `PanelThresholdChanged` only on an actual change |
| `initialize_subscription(period_secs, periods, per_period)` (AV-56) | `Uninitialized` | `Uninitialized` | initializer (once, before funding — mutually exclusive with `initialize_milestones`; declares the periodic release schedule, back-scheduled from `expires_at`: period `i` is due at `expires_at - (periods-1-i) * period_secs`; validation — `period_secs` non-zero, `periods` in 1..=64, `per_period` non-zero, `periods * per_period` == locked amount (in u128), `expires_at != u64::MAX`, and the schedule must fit the lifetime — is `InvalidSubscription` otherwise) |
| `release_period(period_index)` (AV-56) | `Funded` | `Funded` (partial) / `Released` (last period) | initializer only (the initializer's push path); strictly in-order (`period_index` must equal the next due period — skip-ahead and replay are `PeriodNotDue`) and due-date gated (`now >= due_at(period_index)` — `PeriodNotDue` otherwise); quorum satisfied when configured (`QuorumNotReached`), the timelock gate when a lock is configured (`now >= unlock_at` (AV-27) or `now >= fund_at + secs` (AV-64); `TimelockNotReached` — the timelock gates every taker payout path); `MintMismatch` / `PayoutNotAllowlisted` guard the fund movement like `release`; the protocol fee slices the period (`payout + fee == per_period`); vesting claim composes (not blocked); emits `SubscriptionPeriodReleased` |
| `initialize_milestones(milestones)`          | `Uninitialized`| `Uninitialized` | initializer (once, before funding; tranche amounts must sum to the locked amount) |
| `confirm_milestone(authority, index)`        | `Funded`       | — (no state change) | initializer **or** taker (in order; a milestone is confirmed once *both* parties confirmed) |
| `release_milestone(authority, now, index)`        | `Funded`       | `Funded` (partial) / `Released` (final tranche) | initializer; milestone dual-confirmed (+ quorum satisfied when configured; the timelock gate when a lock is configured — `now >= unlock_at` (AV-27) or `now >= fund_at + secs` (AV-64) — `TimelockNotReached` otherwise) |
| `skip_milestone(authority, index)`           | `Funded`       | — (no state change) | initializer **or** taker, **both** must approve (dual-sig skip; skipped tranche refunded to the initializer) |
| `adjust_milestone_amounts(initializer, taker, new_amounts)` (AV-70) | `Uninitialized`/`Activated`/`Funded` | — (no state change; rewrites the tranche table) | **both** the initializer and the taker must sign (dual-signature governance — one party alone or a stranger pair is `Unauthorized`); terminal states and `Disputed` are `InvalidStateTransition`; rejected once any tranche settled (`released > 0` or `skipped > 0`); new amounts must have the plan's tranche count, be all positive, and sum to exactly the locked amount; per-tranche confirmations survive (they accept the deliverable, not the amount); protocol fees charge on the new amounts at release time (still floored by `fee_cap`); emits `MilestonesAdjusted` only on an actual change |
| `adjust_period_amounts(initializer, taker, new_amounts)` (AV-73) | `Uninitialized`/`Activated`/`Funded` | — (no state change; rewrites the per-period table) | **both** the initializer and the taker must sign (dual-signature governance — one party alone or a stranger pair is `Unauthorized`); terminal states and `Disputed` are `InvalidStateTransition`; released periods lock their recorded amounts (the re-split must reaffirm them — `InvalidSubscription` otherwise); new amounts must have the schedule's period count, be all positive, and sum to exactly the locked amount; protocol fees charge on the new amounts at release time (still floored by `fee_cap`); the keeper's `ReleasePeriod` action prices from the live table; emits `SubscriptionAmountsAdjusted` only on an actual change |
| `migrate_schema()` (AV-75) | any | — (no state change; stamps the schema version) | initializer **only** (`Unauthorized` otherwise, checked before state validity); a paused escrow fails fast (`Paused`); only `schema_version + 1 == SCHEMA_VERSION` steps — an already-current vault refuses the second call and an unknown future version refuses loudly instead of skipping forward (`InvalidSchemaMigration`, code 140, either way); the carried-over fields are re-validated before the stamp (`released <= amount`, `released + skipped <= amount`, `fees_paid <= released`, milestone tranche sum `== amount`) — a corrupt vault is refused, never migrated; emits `SchemaMigrated` (from == to == the current state), always on success |
| `initialize_mint(mint)`                     | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `mint` is the base58 SPL mint address — must decode to 32 bytes, zero address rejected) |
| `initialize_protocol_fee(fee_bps)`           | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `fee_bps` in 0–10000 basis points; the fee slices every taker payout into net payout + protocol fee; the AV-63 fee cap can floor it per payout) |
| `initialize_fee_cap(max_fee_cents)`           | `Uninitialized`| `Uninitialized` | initializer (once, before funding; absolute per-payout fee ceiling in lamports — the effective fee is `min(bps fee, fee_cap)`; `0` means uncapped; no new error code) |
| `initialize_fee_schedule(tiers)` (AV-66)     | `Uninitialized`| `Uninitialized` | initializer (once, before funding; opt-in volume-priced fee tiers as `(min_amount, bps)` pairs — the fee for a gross payout uses the rate of the highest tier with `min_amount <= amount`, still floored by the AV-63 cap; 1–8 tiers, each `bps` 0–10000, floors strictly ascending; mutually exclusive with the flat rate — fail-fast `InvalidProtocolFee`, code 114, in either direction) |
| `initialize_fee_recipient(fee_recipient)`    | `Uninitialized`| `Uninitialized` | initializer (once, before funding; pins the destination of every fee leg — the settlement builders reject a `fee_leg` that does not equal it; zero address is `InvalidFeeRecipient`; with no pin the fee goes to the program-level fee account) |
| `initialize_pause_authority(pause_authority)` | `Uninitialized`| `Uninitialized` | initializer (once, before funding; binds the key allowed to engage/release the emergency pause; zero address is `InvalidPauseAuthority`) |
| `pause()`                                     | any            | — (no state change; sets the pause flag) | the bound pause authority only (`Unauthorized` otherwise; `InvalidStateTransition` with no authority bound or when already paused); emits `Paused` |
| `unpause()`                                   | any            | — (no state change; clears the pause flag) | the bound pause authority only (same rules as `pause`; `InvalidStateTransition` when not paused); emits `Unpaused` |
| `rotate_pause_authority(new_authority)`       | any (post-`Uninitialized`) | — (no state change; rewrites the bound pause authority) | the escrow authority (initializer) only — a stranger/taker is `Unauthorized`; `InvalidStateTransition` on `Uninitialized` or with no authority bound; zero address is `InvalidPauseAuthority`; works while paused (key-loss escape hatch); emits `PauseAuthorityRotated` only on an actual change |
| `rotate_taker(new_taker)`                   | `Uninitialized`/`Activated`/`Funded` | — (no state change; rewrites the taker) | **both** the initializer and the *current* taker must sign (dual-signature governance — one party alone or a stranger pair is `Unauthorized`); terminal states and `Disputed` are `InvalidStateTransition` (no live counterparty left; arbitration in flight adjudicates the taker's identity); zero address is `InvalidTaker`; amount / released / attest records / milestone state all preserved; emits `TakerRotated` only on an actual change |
| `rotate_initializer(new_initializer)`      | `Uninitialized`/`Activated`/`Funded` | — (no state change; rewrites the initializer) | **both** the *current* initializer and the taker must sign (dual-signature governance — the mirror of `rotate_taker`; degenerate initializer == taker self-escrow authorizes with one key passed twice); terminal states and `Disputed` are `InvalidStateTransition` (arbitration in flight adjudicates the initializer's identity — the refund goes to the initializer); zero address is `InvalidInitializer`; on an actual change the initializer's activation signature bit is cleared (the new key never signed activation); the AV-23 whitelist pins the refund destination when configured, otherwise refunds resolve to the new initializer (keeper/snapshot follow automatically); emits `InitializerRotated` only on an actual change |
| `rotate_arbiter(new_arbiter)`                | `Uninitialized`/`Activated`/`Funded` | — (no state change; rewrites the arbiter) | **both** the *current* initializer and the *current* taker must sign (dual-signature governance — the mirror of `rotate_initializer` for the arbitration role; the arbiter itself does not sign, so a lost arbiter key cannot block its own replacement; degenerate initializer == taker self-escrow authorizes with one key passed twice); terminal states and `Disputed` are `InvalidStateTransition` (no live dispute path left to referee, and arbitration in flight must settle with the referee that heard it); a configured panel is `InvalidStateTransition` too (single-arbiter governance only — rotate the panel via `initialize_arbiter_panel`); no arbiter configured or the zero address is `InvalidArbiter`; the activation bitmask is untouched (it tracks only the initializer and taker); the keeper's `resolve` listing and the snapshot export read the live arbiter field (follow automatically); emits `ArbiterRotated` only on an actual change |
| `rotate_fee_recipient(new_recipient)`         | `Uninitialized`/`Activated`/`Funded` | — (no state change; rewrites the fee recipient) | **both** the *current* initializer and the *current* taker must sign (dual-signature governance — the mirror of `rotate_arbiter` for the fee-destination role; the fee recipient itself does not sign, so a lost fee-recipient key cannot block its own replacement; degenerate initializer == taker self-escrow authorizes with one key passed twice); terminal states and `Disputed` are `InvalidStateTransition` (no future fee leg left to redirect, and the dispute settlement builders pin the fee leg to the configured recipient); no fee recipient configured or the zero address is `InvalidFeeRecipient` (code 123); the activation bitmask is untouched (it tracks only the initializer and taker); the keeper's fee listings and the snapshot export read the live `fee_recipient` field (follow automatically); emits `FeeRecipientRotated` only on an actual change |
| `initialize_quorum(attestors, weights, threshold)` | `Uninitialized`| `Uninitialized` | initializer (once, before funding) |
| `initialize_dual_sig()`                     | `Uninitialized`| `Uninitialized` | initializer (once, before funding) |
| `initialize_extension(max_extension_secs)` | `Uninitialized`| `Uninitialized` | initializer (once, before funding); zero bound is `InvalidExpiryExtension`; persists the extension budget (`max_extension_secs`, `extension_count` starts 0) |
| `extend_expiry(new_expires_at)`             | `Uninitialized`/`Funded` | — (no state change; pushes `expires_at` back) | initializer **only** (`Unauthorized` otherwise, checked before state validity); `Activated`/`Disputed`/terminal states are `InvalidStateTransition`; new deadline must be strictly later and each increment ≤ the bound (saturating counter); extending at/past keeper-eligibility (`now >= expires_at + grace_period`) is `InvalidExpiryExtension`; emits `ExpiryExtended` (old/new deadline, count) |
| `attest(attestor)`                          | `Uninitialized`/`Activated`/`Funded` | — (no state change) | registered attestor |
| `update_quorum(initializer, taker, threshold)` | `Uninitialized`/`Funded` | — (no state change) | **both** parties must sign (dual-signature governance); `0` or `> total weight` is `InvalidQuorum` |
| `update_attestors(initializer, taker, attestors)` | `Uninitialized`/`Funded` | — (no state change) | **both** parties must sign (dual-signature governance; no party can unilaterally reshape the electorate); empty set / `> 8` / duplicates / new set smaller than the unchanged threshold is `InvalidQuorum`; approval bits remap by pubkey (retained votes survive, removed voters' bits cleared); emits `AttestorsUpdated` on a real set change, nothing on a no-op |
| `activate(authority)`                       | `Uninitialized`| `Uninitialized` (one party) / `Activated` (both parties) | initializer **or** taker (dual-sig escrows only) |
| `initialize_vesting(start, end, cliff)`     | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `start < end`; `cliff` 0 = no cliff, else `cliff <= end`) |
| `claim(authority, now)`                     | `Funded`       | `Funded` (partial) / `Released` (fully vested) | taker only, only when `now` has vested more than already released (+ quorum satisfied when configured; the timelock gate when a lock is configured — `now >= unlock_at` (AV-27) or `now >= fund_at + secs` (AV-64) — `TimelockNotReached` otherwise) |
| `fund(authority, now)`                      | `Uninitialized` (plain) / `Activated` (dual-sig) | `Funded`  | initializer (`now` <- clock sysvar, recorded as `fund_at` — the origin the AV-64 relative timelock measures from) |
| `release(authority, now, amount, payout_to)` (AV-49)                 | `Funded`       | `Funded` (partial) / `Released` (cumulative full) | initializer (+ quorum satisfied when configured; the timelock gate when a lock is configured — `now >= unlock_at` (AV-27) or `now >= fund_at + secs` (AV-64) — `TimelockNotReached` otherwise); cumulative releases ≤ locked amount; `payout_to` must satisfy the payout policy — the taker, or a member of the payout allowlist when one is configured (`PayoutNotAllowlisted` otherwise) |
| `initialize_timelock(unlock_at)`            | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `unlock_at` is the Unix timestamp before which no taker payout may leave; `0` = no lock) |
| `initialize_relative_timelock(secs)` (AV-64) | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `secs` is the duration in seconds after *funding* before which no taker payout may leave; `0` = no lock; mutually exclusive with the AV-27 absolute timelock — both nonzero is `InvalidTimelock`, code 135) |
| `initialize_emergency_unlock()`             | `Uninitialized`| `Uninitialized` | initializer (once, before funding; opts into dual-signed emergency timelock-unlock governance) |
| `emergency_unlock(initializer, taker)`       | `Funded`       | `Funded` (no state change) | **both** parties must sign (dual-signature governance; one party alone is `Unauthorized`); requires the opt-in and an active timelock (`InvalidStateTransition` otherwise); clears the timelock (`timelock`, or the AV-64 relative lock) to `0` so payouts become immediately eligible — state and amounts untouched; emits `EmergencyUnlock` |
| `initialize_decimals(decimals)`             | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `decimals` is the SPL mint's decimal places — SPL mints declare at most 9, `> 18` is rejected; `0` = no decimal metadata; display-only, never gates a transition or moves funds) |
| `cancel(authority, refund_to)`               | `Funded`       | `Cancelled` | initializer; `refund_to` must equal the whitelisted address (or the initializer with no whitelist) — `RefundAddressMismatch` otherwise |
| `cancel_expired(authority, now, refund_to)`  | `Funded`       | `Cancelled` | initializer **or** taker, only when `now >= expires_at + grace_period` (opt-in via `with_grace_period`, `0` by default); the refund still goes to the whitelisted address even when the taker calls; returns `(refund, penalty)` — a taker-initiated cancel with `penalty_bps > 0` slices an anti-griefing penalty for the initializer (see below) |
| `cancel_partial(authority, amount, refund_to)` (AV-60) | `Funded` | `Funded` (no state change) | initializer; Funded-only; the initializer's counterpart to AV-11's partial release — reclaims a tranche of the lockup instead of streaming it to the taker; `amount == 0` is `AmountMismatch`, `amount` above the still-locked remainder is `ReleaseExceedsLocked`; the `released` counter is untouched and the locked total shrinks; `refund_to` must equal the whitelisted address (or the initializer with no whitelist) — `RefundAddressMismatch` otherwise; quorum / timelock / vesting do **not** gate it (same as `cancel`); emits `PartiallyCancelled`; returns the refunded amount |
| `crank_expired(caller, now)` (AV-48) | `Funded` | `Cancelled` | **anyone** — permissionless crank (Solana crank pattern), only when `now >= expires_at + grace_period`; no counterparty signature needed, so a keeper bot that is party to nothing can sweep timed-out vaults; the refund follows the same pinned refund policy (whitelisted address, or the initializer) — the cranker receives nothing (anti-MEV); a taker cranker still pays the anti-griefing penalty; rejected with `Paused` while the escrow is paused |
| `initialize_payout_allowlist(allowlist)` (AV-49) | `Uninitialized` | `Uninitialized` | initializer (once, before funding; 1–4 live payout-destination addresses; empty / over-long / zero-address input is `InvalidPayoutAllowlist`); the payout policy gates every fund-moving transition's `payout_to` |
| `update_payout_allowlist(initializer, taker, allowlist)` (AV-49) | `Uninitialized` / `Funded` | same (no state change) | dual-signature governance — both initializer and taker on a dual-sig escrow, initializer alone on a plain escrow (`Unauthorized` otherwise); empty clears the allowlist (back to taker-only payouts); emits `PayoutAllowlistUpdated` only on an actual change |
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
ahead of the curve; the schedule itself is immutable once set, and
`cancel` / `cancel_expired` still refund the unreleased remainder.

**Dispute arbitration (escrowed payments with a judge).** An escrow can
name an arbiter (`with_arbiter`, opt-in on `Uninitialized`, like the
quorum builder; the zero key is rejected since `resolve` authenticates
against it). While `Funded`, *either* party may `escalate(authority, now)`
into `Disputed` — the dispute window is the escrow's live window
(`now < expires_at`; at/after expiry the unilateral `cancel_expired` path
is the way out, so `escalate` reports `DisputeWindowClosed`). While
`Disputed`, every unilateral exit is locked: `release`, `cancel`,
`cancel_expired`, and `claim` all return `InvalidStateTransition`, so
neither party can move funds mid-deliberation. The arbiter then
`resolve`s with a single atomic split of the *remaining* locked funds —
`taker_amount` to the taker, the rest refunded to the initializer —
moving the escrow to the terminal `Settled` state and returning
`(taker_payout, initializer_refund)` so the program can size both
transfers. Partial releases made before the dispute are honored (the
split applies to the remainder); the taker's share accumulates in the
shared `released` counter while `remaining_amount()` preserves the
initializer's refund for audit, exactly like `cancel`'s refund
accounting. Deliberately, a configured quorum does *not* gate `resolve`
(the arbiter is the resolution mechanism — attestors must not veto the
settlement), and vesting does not gate it either (the dispute exists
precisely because the schedule is contested; `claim` stays locked while
`Disputed`). The escalating party may attach a 32-byte **dispute evidence
hash** (`escalate(authority, now, evidence_hash)`) — a commitment to the
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
initializer-signed — no keeper can skip ahead or double-release. Vesting
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

Design choice, documented deliberately: once a plan is attached, plain
`release` and `claim` return `InvalidMilestones` — the plan and the
vesting curve are *alternative* release schedules, not composable ones.
Arbitrary or time-based pulls would release funds outside the tranche
plan and break per-tranche accounting; the refund paths stay available,
and `resolve` overrides the plan by design (unsettled tranches are part
of the split remainder), like it overrides vesting. Confirmation progress
is persisted in a 6-bits-per-milestone bitmap in the vault account (see
the layout table), so it survives serialization.

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
is now **3454 bytes** and needs **24,930,720 lamports**.

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
| `AmountMismatch` | 102 | `initialize` with `amount == 0`; `release` / `cancel_partial` with `amount == 0` |
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
| `InvalidCpiTarget` | 120 | `release_via_cpi` with a zero program id, an empty account list, or a zero account key (malformed third-party invocation) |
| `CpiExecutionFailed` | 121 | `release_via_cpi` whose injected CPI executor reported failure after the gates passed (whole release rolled back) |
| `ReentrantCall` | 122 | a fund-moving transition entered while the AV-36 reentrancy lock was held (nested entry from inside `release_via_cpi`'s executor window) |
| `InvalidFeeRecipient` | 123 | `with_fee_recipient` with the zero address (a zero address can never be the legitimate protocol-fee destination), or `rotate_fee_recipient` with no fee recipient configured / with the zero address |
| `Paused` | 124 | any state-changing transition while the AV-46 emergency pause is engaged (`fund`/`release`/`claim`/`attest`/`resolve`/`cancel`/milestone/governance paths) |
| `InvalidPauseAuthority` | 125 | `with_pause_authority` / `rotate_pause_authority` with the zero address (a zero address can never hold the emergency switch) |
| `InvalidPayoutAllowlist` | 126 | `with_payout_allowlist` / `update_payout_allowlist` with an empty list, more than 4 addresses, or a zero address (the AV-49 allowlist must be 1-4 live payout destinations) |
| `PayoutNotAllowlisted` | 127 | a payout transition (`release` / `claim` / `resolve` / `release_milestone` / `release_via_cpi`) naming a `payout_to` that is neither the taker nor a member of the payout allowlist |
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

**Amount conservation** is pinned by a model-based fuzz test: 24
deterministic seeds × 48 random operations over 6 escrows assert
`inflow == locked + released + refunded` after every operation, with
`amount`/`expires_at` immutable and failed operations state-preserving
(the fuzz drives full, partial, over-limit, and zero-amount releases, so
`locked` is recomputed as the unreleased remainder of `Funded` escrows
and `released` accumulates partial payouts). Property-based tests
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

Note that `attest` never changes `EscrowState` itself (it only grows the
quorum's approval bitmask), and the failed-call invariant holds on every
path above: any `Err(...)` return leaves the state — and `amount` and the
`released` counter — exactly untouched (pinned by the
permission/fuzz/property tests).

## Indexer events (AV-18)

Every state transition of the escrow state machine emits one typed
`EscrowEvent` through the `IndexedEscrow` adapter
(`escrow-state/src/events.rs`) — no existing `Escrow` signature changed,
and the crate stays dependency-free. A chain indexer subscribes to state
changes in per-escrow `seq` order instead of polling account data.

**Event shape.** Each event carries:

| field | meaning |
|-------|---------|
| `kind` | `EscrowEventKind`: `Initialized`, `Activated`, `Funded`, `Released`, `Cancelled`, `ExpiredCancelled`, `ExpiredCranked` (AV-48), `Attested`, `QuorumUpdated`, `AttestorsUpdated`, `Claimed`, `Escalated`, `Resolved`, `MilestoneConfirmed`, `MilestoneReleased`, `MilestoneSkipped`, `MilestonesAdjusted` (AV-70), `EmergencyUnlock`, `VaultClosed`, `TakerRotated` (AV-52), `ArbiterRotated` (AV-62), `PartiallyCancelled` (AV-60), `PanelJudgment` (AV-65), `PanelResolved` (AV-65), `EvidenceSubmitted` (AV-68), `PanelThresholdChanged` (AV-69), `SubscriptionAmountsAdjusted` (AV-73), `SchemaMigrated` (AV-75), `BundlePartiallyExecuted` (AV-76), `TemplateApplied` (AV-77), `EscrowSplit` (AV-81) |
| `escrow_id` | caller-supplied 32-byte escrow identity (on-chain: the vault PDA public key) |
| `seq` | per-escrow monotonic sequence; `0` is the `Initialized` event |
| `from` → `to` | `EscrowState` before and after the call |
| `amounts` | one struct for every kind: `payout` (gross taker amount before the fee split), `fee` (AV-17 protocol fee), `refund` (initializer's refund), `penalty` (AV-24 anti-griefing penalty on a taker-initiated `cancel_expired` / taker crank), `rent_reclaimed` (AV-34 rent-exempt deposit reclaimed on `VaultClosed`); zeroed when the kind moves no such value |
| `at` | caller-supplied Unix-seconds timestamp (`cancel_expired` / `crank_expired` / `escalate` / `claim` reuse their `now`) |
| `caller` | AV-48: the permissionless crank caller's key, carried by `ExpiredCranked` only (`None` on every other kind) |
| `evidence_defaulted` | AV-68: whether the escalating party's evidence disclosure had defaulted at judgment time — `true` only on the settlement kinds (`Resolved`, `DefaultJudgment`, `PanelResolved`) when a disclosure deadline was configured, it had lapsed at the event's `at` timestamp, and no evidence was on record; the judgment-time adverse-inference signal biasing the absent-evidence weight toward the non-escalating party (`false` on every other kind) |

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
- `cancel_partial` (AV-60) emits `PartiallyCancelled` with
  `from == to == Funded` and `amounts.refund` carrying the refunded
  tranche — the refund stream's mirror of a partial `Released` event.
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
| `crank_expired(caller, now, mint)` (AV-48) | `Funded`, `now >= expires_at + grace_period`, remainder > 0, **not paused** (the crank fails on a paused escrow, so it is only listed when executable) | `"anyone"` — permissionless; the keeper substitutes its own key (serialized as the zero key) | refundable remainder (never fee'd); the refund goes to the same pinned `refund_to` as the party path — the cranker receives nothing |
| `claim(taker, now, mint)` | `Funded`, vesting attached, no milestone plan, vested − released > 0, quorum satisfied if configured, timelock unlocked (`now >= unlock_at` (AV-27) / `now >= fund_at + secs` (AV-64)) | taker | gross vested-but-unreleased (`payout + fee == amount`) |
| `resolve(arbiter, taker_amount, mint, rationale_hash)` (AV-38) | `Disputed`, arbiter configured, remainder > 0 | arbiter | remaining locked amount the arbiter's split divides (the split itself and the rationale-document commitment are the arbiter's call-time judgment) |
| `submit_panel_judgment(member, taker_amount, mint, rationale_hash)` (AV-65) | `Disputed`, panel configured, remainder > 0 — one action **per panel member** | panel member (`caller_role: "panel_member"`) | remaining locked amount the member's voted split divides (the split and the rationale commitment are the member's call-time judgment; the panel settles itself once M votes agree) |
| `close_vault(authority)` (AV-40) | `Cancelled` / `Released` / `Settled` / `Split` — the terminal states AV-34's `close_vault` accepts (`Split` since AV-81). `Disputed` is never listed (the arbitration is still live; the vault account is the arbiter's audit surface) and `Closed` is never listed (the rent is already reclaimed) — the scan lists only calls the chain would accept | initializer (the only key `close_vault` accepts — AV-34 checks authority before state) | `rent_reclaimed`: the mainnet rent-exempt minimum for the current `VAULT_SPACE` (via `vault_close_rent_reclaimed()`, never a hardcoded figure) |

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
configured, else the initializer; `null` for `claim` and `resolve`) — so the keeper can
build the `cancel_expired` / `claim` / `resolve` instruction directly. The scan is a pure read
over `&Escrow` snapshots: dry-run by construction, zero side effects,
deterministic output in input order. `KeeperReport::to_json()` emits
hand-serialized JSON (the crate stays dependency-free; keys are 64-char
lowercase hex). Every action also carries `decimals` (the escrow's token
decimal metadata, `0` when none is declared) and `display_amount` — the
same `amount` rendered in human units (`500000` at 6 decimals →
`"0.500000"`); the instruction itself always moves the raw `amount`.

```json
{"at":1750000000,"scanned":1,"actions":[
  {"escrow_id":"...","action":"claim","caller":"...","caller_role":"taker",
   "mint":null,"refund_to":null,"amount":500000,"decimals":6,
   "display_amount":"0.500000","reason":"vesting_unlocked"}
]}
```

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
`rationale_hash`)
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
{"at":1750000000,"initializer":"...","taker":"...","state":"funded","schema_version":1,
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
 "event_history":{"capacity":64,"total":0,"count":0,"entries":[]}}
```

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
| arbiter_panel | Option<ArbiterPanel> | 595 |
| fee_schedule | FeeSchedule | 81 |
| evidence_deadline_secs | u64 | 8 |
| escalated_by | Option<Pubkey> | 33 |
| subscription_amounts | [u64; 64] | 512 |
| schema_version | u8 | 1 |
| **total**     |                   | **3446** |

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
and the 595-byte arbiter panel region (AV-65: 1-byte `Option`
discriminant + 594-byte panel, zeroed when no panel is configured) —
and the 81-byte tiered protocol-fee schedule region (AV-66: 1-byte
live-tier count + 8 fixed 10-byte tier slots, zeroed when no schedule
is configured) — and the 8-byte dispute-evidence disclosure deadline
(AV-68: zeroed when no deadline is configured) — and the 33-byte
escalating-party region (AV-68: 1-byte discriminant + 32-byte key,
zeroed when the escrow was never disputed).
`escrow-state` exposes `VAULT_SPACE` (3454) and
`VAULT_SPACE_NO_QUORUM` (2964) for the Anchor `space =` constraint, plus a
pure-logic rent-exemption check mirroring `Rent::minimum_balance`. With
mainnet rent parameters the full vault needs **24,930,720 lamports** to be
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
  stays 3454 — the AV-38 rationale-hash, AV-44 fee-recipient, AV-45
  weighted-quorum, AV-46 pause-switch, AV-49 payout-allowlist, AV-51
  vesting-cliff, AV-53 reference-memo, AV-55 default-judgment,
  AV-56 subscription, AV-57 event-history, AV-59 extension, AV-63
  fee-cap, AV-64 relative-timelock, AV-65 arbiter-panel, AV-66
  fee-schedule, AV-68 evidence-deadline, AV-73 per-period-table, and
  AV-75 schema-version growth is accounted in the
  layout table above); the state
  byte simply carries the new discriminant.
- **Rent:** the returned value is `escrow_state::vault_close_rent_reclaimed()`
  — the mainnet rent-exempt minimum for `VAULT_SPACE` (**24,930,720
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

## CPI-routed release (AV-35)

`escrow-state/src/cpi_call.rs` models the release path where the taker's
payout flows *through* a third-party program — a DEX swap, a lending
deposit — instead of moving straight to the taker wallet, so one release
becomes a leg of a larger composed transaction:

- **Invocation as data**: `CpiInvocation { program_id, accounts,
  data }` is the inner instruction the vault authorizes. The Anchor
  skeleton's `release_via_cpi(amount, cpi_data)` instruction builds it
  from `remaining_accounts` (`[0]` = target program, `[1..]` its
  instruction accounts) via `cpi_invocation_from_remaining_accounts`;
  `cpi_invoke_target` is the stub where the real build performs the
  `invoke_signed` with the vault PDA as signer.
- **Same gates, then validation**: `Escrow::release_via_cpi` runs the
  exact `release` gates (authority, state, mint, milestone plan,
  quorum, timelock, amount — a CPI-routed release is a release, not a
  bypass), then validates the invocation shape (`InvalidCpiTarget`,
  code 120: zero program id, empty account list, or zero account key).
- **Atomicity**: the state machine hands the validated invocation to an
  injected executor (the seam where the Anchor layer plugs the real
  `invoke`). If the executor reports failure, the whole release rolls
  back — `released`, `fees_paid` and `state` restored — and the error
  is `CpiExecutionFailed` (code 121). On-chain a failed CPI aborts the
  transaction and no state change persists; the pure-logic model
  mirrors that atomicity. Nothing observable changes on failure: no
  event fires, no counter moves.
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
  `{"bundle_id","mint","caller","caller_role","actions","action_count",
  "alt_table","at","scanned"}`. Actions carry `escrow_id`,
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
- **Relation to AV-33**: the same idea as the batch settlement
  execution plan, applied to the proactive lifecycle line instead of
  the keeper report's reactive exits. Same grouping, same
  discriminator rule, same deterministic hand-serialized JSON.

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
  No address-table lookups are compiled in (legacy message); the
  bundle's `alt_table` stays the operator's ALT material for a later v0
  upgrade.
- **Pinning**: the tests assert the data bytes against the
  `INSTRUCTIONS` spec table (param name/type/order per kind), the
  account metas 1:1 against the bundle's logical accounts, the wire
  bytes against a golden vector, base64 against RFC 4648 vectors, and
  bundle-JSON ↔ message agreement end to end.

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
`RecipientMismatch`. The 130-byte region is always reserved in the vault
layout (1-byte discriminant + 4×32-byte addresses + 1-byte count), so the
opt-in writes in place without reallocating.

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
