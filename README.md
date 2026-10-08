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
| `initialize_arbiter(arbiter)`               | `Uninitialized`| `Uninitialized` | initializer (once, before funding; zero key rejected) |
| `escalate(authority, now)`                   | `Funded`       | `Disputed` | initializer **or** taker, only when `now < expires_at` (locks `release`/`cancel`/`cancel_expired`/`claim`) |
| `resolve(authority, taker_amount)`           | `Disputed`     | `Settled` | arbiter only; atomic split of the remainder (taker payout / initializer refund) |
| `initialize_milestones(milestones)`          | `Uninitialized`| `Uninitialized` | initializer (once, before funding; tranche amounts must sum to the locked amount) |
| `confirm_milestone(authority, index)`        | `Funded`       | — (no state change) | initializer **or** taker (in order; a milestone is confirmed once *both* parties confirmed) |
| `release_milestone(authority, index)`        | `Funded`       | `Funded` (partial) / `Released` (final tranche) | initializer; milestone dual-confirmed (+ quorum satisfied when configured) |
| `skip_milestone(authority, index)`           | `Funded`       | — (no state change) | initializer **or** taker, **both** must approve (dual-sig skip; skipped tranche refunded to the initializer) |
| `initialize_mint(mint)`                     | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `mint` is the base58 SPL mint address — must decode to 32 bytes, zero address rejected) |
| `initialize_protocol_fee(fee_bps)`           | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `fee_bps` in 0–10000 basis points; the fee slices every taker payout into net payout + protocol fee) |
| `initialize_quorum(attestors, threshold)`    | `Uninitialized`| `Uninitialized` | initializer (once, before funding) |
| `initialize_dual_sig()`                     | `Uninitialized`| `Uninitialized` | initializer (once, before funding) |
| `attest(attestor)`                          | `Uninitialized`/`Activated`/`Funded` | — (no state change) | registered attestor |
| `activate(authority)`                       | `Uninitialized`| `Uninitialized` (one party) / `Activated` (both parties) | initializer **or** taker (dual-sig escrows only) |
| `initialize_vesting(start, end)`            | `Uninitialized`| `Uninitialized` | initializer (once, before funding; `start < end`) |
| `claim(authority, now)`                     | `Funded`       | `Funded` (partial) / `Released` (fully vested) | taker only, only when `now` has vested more than already released (+ quorum satisfied when configured) |
| `fund(authority)`                           | `Uninitialized` (plain) / `Activated` (dual-sig) | `Funded`  | initializer            |
| `release(authority, amount)`                 | `Funded`       | `Funded` (partial) / `Released` (cumulative full) | initializer (+ quorum satisfied when configured); cumulative releases ≤ locked amount |
| `cancel(authority)`                         | `Funded`       | `Cancelled` | initializer          |
| `cancel_expired(authority, now)`            | `Funded`       | `Cancelled` | initializer **or** taker, only when `now >= expires_at` |

Rules: the initializer drives `fund`/`release`/`cancel`; any other caller
gets `Unauthorized` (checked before state validity). An escrow that has
timed out (`now >= expires_at`) may instead be cancelled by *either* party
via `cancel_expired`, so a stalled counterparty cannot lock funds forever;
calling it early gets `NotExpired`. Pass `u64::MAX` as `expires_at` for no
timeout. Any illegal transition (e.g. releasing twice, releasing before
funding) gets `InvalidStateTransition`; zero amounts get `AmountMismatch`;
`release`/`cancel`/`cancel_expired` preserve `amount` exactly (refund
accounting).

**Partial release (staged payouts).** `release(authority, amount)` releases
in tranches: each call adds to a cumulative `released` counter and leaves
the escrow `Funded`; when the cumulative total reaches the locked amount
the escrow moves to `Released`. Cumulative releases must never exceed the
locked amount (`ReleaseExceedsLocked`, code 106); a zero-amount release is
`AmountMismatch`. `released_amount()` / `remaining_amount()` expose the
progress, and `cancel` / `cancel_expired` after partial releases refund
only the remainder while `released_amount()` stays preserved for audit.

**Attestor quorum (N-of-M release gate).** An escrow can be created with an
optional quorum policy (`QuorumPolicy::new(attestors, threshold)`, up to 8
attestors, heap-free bitmask): `initialize_quorum` attaches it once, before
funding; registered attestors record idempotent attestations via `attest`
in `Uninitialized` or `Funded`. `release` then additionally requires
`threshold` distinct attestations, else `QuorumNotReached`. Check order is
authority → state → quorum, so strangers learn nothing about attestation
progress. Deliberately, the quorum gates *release only*: `cancel` and
`cancel_expired` stay ungated so attestors cannot grief funds into a lockup
by withholding approval. Without a quorum the escrow behaves exactly as the
plain two-party machine above.

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
pattern (salary streams, linear token unlocks). `claim` returns the
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
`Disputed`).

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
`floor(gross_payout × fee_bps / 10_000)`, computed in `u128` so the
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
model-based fuzz test) is untouched by fees. Refunds (`cancel`,
`cancel_expired`), the initializer's `resolve` share, and skipped
milestones are never fee'd: only value the taker receives carries a fee.
The rate (`fee_bps`, 2 bytes) and the cumulative counter (`fees_paid`,
8 bytes) are persisted in the vault account (see the layout table),
appended last so every earlier field offset stays stable; with the fee
region the full vault is 540 bytes and needs **4,649,280 lamports** to be
rent-exempt on mainnet.

**Error codes** (stable, never renumbered; the Anchor program maps one
program error per variant):

| Error | Code | Trigger |
|-------|------|---------|
| `Unauthorized` | 100 | caller is not the transition authority (checked before state validity) |
| `InvalidStateTransition` | 101 | transition illegal from the current state (double fund, release before fund, …) |
| `AmountMismatch` | 102 | `initialize` with `amount == 0` |
| `NotExpired` | 103 | `cancel_expired` with `now < expires_at` |
| `InvalidQuorum` | 104 | bad quorum policy config, or `attest` with no quorum configured |
| `QuorumNotReached` | 105 | `release` before the quorum threshold is reached |
| `ReleaseExceedsLocked` | 106 | cumulative `release` amounts exceeding the locked amount |
| `InvalidVesting` | 107 | bad vesting schedule (`start >= end`), or `claim` with no vesting configured |
| `InvalidArbiter` | 108 | `with_arbiter` with the zero key, or `escalate`/`resolve` with no arbiter configured |
| `DisputeWindowClosed` | 109 | `escalate` with `now >= expires_at` (past the dispute window) |
| `InvalidMilestones` | 110 | bad milestone plan (empty list, > 8 tranches, zero-amount tranche, tranche sum ≠ locked amount), milestone op with no plan attached, out-of-range milestone index, or `release`/`claim` with a milestone plan attached |
| `MilestoneNotConfirmed` | 111 | `release_milestone` before both parties confirmed the milestone |
| `InvalidMint` | 112 | bad mint address (empty, non-base58, or not 32 bytes), or `with_mint` with the zero address |
| `MintMismatch` | 113 | exit-path token mint ≠ the escrow's bound mint (`None` vs `Some` mismatches too) |
| `InvalidProtocolFee` | 114 | `with_protocol_fee` with `fee_bps` > 10_000 (not a valid basis-point rate) |

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
expires_at`), and quorum idempotency under random attestation order.

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
| `kind` | `EscrowEventKind`: `Initialized`, `Activated`, `Funded`, `Released`, `Cancelled`, `ExpiredCancelled`, `Attested`, `Claimed`, `Escalated`, `Resolved`, `MilestoneConfirmed`, `MilestoneReleased`, `MilestoneSkipped` |
| `escrow_id` | caller-supplied 32-byte escrow identity (on-chain: the vault PDA public key) |
| `seq` | per-escrow monotonic sequence; `0` is the `Initialized` event |
| `from` → `to` | `EscrowState` before and after the call |
| `amounts` | one struct for every kind: `payout` (gross taker amount before the fee split), `fee` (AV-17 protocol fee), `refund` (initializer's refund); zeroed when the kind moves no such value |
| `at` | caller-supplied Unix-seconds timestamp (`cancel_expired` / `escalate` / `claim` reuse their `now`) |

**Emission rule.** Exactly one event per *successful* call that changes
externally-observable state; failed calls emit nothing, and neither do
successful calls that change nothing observable:

- `with_*` builders are configuration, not transitions — no events.
- `activate` emits only when it flips `Uninitialized → Activated`; a
  single party's signature emits nothing.
- `attest` emits when it records a *new* attestation (the quorum's
  approval count grows) — quorum progress is what an indexer watches to
  know when the release gate opens; duplicate votes emit nothing.
- `confirm_milestone` emits when the milestone becomes fully confirmed
  (the completing vote); the first party's confirmation alone emits
  nothing, paralleling `activate`.
- `skip_milestone` emits only when the skip executes (both approvals
  present); a lone approval emits nothing.
- Partial `release` / `claim` calls emit with `from == to == Funded` so
  the payout stream is complete in `seq` order; the closing payout has
  `to == Released`.
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

## Keeper report (AV-20)

A keeper bot watches many vaults and needs the executable call list, not
raw account data. `escrow-state/src/keeper.rs` scans a batch of
`WatchedEscrow { escrow_id, escrow }` snapshots at a given `now` and
returns a `KeeperReport` of immediately executable calls:

| action | listed when | caller | `amount` |
|--------|-------------|--------|----------|
| `cancel_expired(authority, now, mint)` | `Funded`, `now >= expires_at`, remainder > 0 | initializer (canonical; the taker may also call) | refundable remainder (never fee'd) |
| `claim(taker, now, mint)` | `Funded`, vesting attached, no milestone plan, vested − released > 0, quorum satisfied if configured | taker | gross vested-but-unreleased (`payout + fee == amount`) |

Only *executable* calls are listed: a vesting claim behind an unsatisfied
quorum is withheld (the call would fail), and a milestone-plan escrow
never lists `claim` (the plan owns the release schedule). Each action
carries the exact instruction arguments — `caller`, `mint` (the bound SPL
mint, or `null` on the native-SOL path) — so the keeper can build the
`cancel_expired` / `claim` instruction directly. The scan is a pure read
over `&Escrow` snapshots: dry-run by construction, zero side effects,
deterministic output in input order. `KeeperReport::to_json()` emits
hand-serialized JSON (the crate stays dependency-free; keys are 64-char
lowercase hex).

```json
{"at":1750000000,"scanned":1,"actions":[
  {"escrow_id":"...","action":"claim","caller":"...","caller_role":"taker",
   "mint":null,"amount":500000,"reason":"vesting_unlocked"}
]}
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
| quorum        | Option<Quorum>    | 267   |
| activation    | u8 (bitmask)      | 1     |
| vesting       | Option<VestingSchedule> | 17 |
| arbiter       | Option<Pubkey>    | 33    |
| milestones    | Option<MilestonePlan> | 66 |
| milestone_flags | u64 (bitmask)   | 8     |
| skipped       | u64               | 8     |
| mint          | Option<Pubkey>    | 33    |
| fee_bps       | u16               | 2     |
| fees_paid     | u64               | 8     |
| **total**     |                   | **540** |

The quorum region is always reserved (zeroed when `None`), so
`initialize_quorum` writes the policy in place — the account never needs a
realloc. The 1-byte activation bitmask (AV-12) is likewise always present
(zeroed for plain escrows), as is the 17-byte vesting region (AV-13:
1-byte discriminant + `start`/`end` u64, zeroed when no schedule is
attached), the 33-byte arbiter region (AV-14: 1-byte discriminant +
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
was charged) follow the same always-present, appended-last treatment.
`escrow-state` exposes `VAULT_SPACE` (540) and
`VAULT_SPACE_NO_QUORUM` (129) for the Anchor `space =` constraint, plus a
pure-logic rent-exemption check mirroring `Rent::minimum_balance`. With
mainnet rent parameters the full vault needs **4,649,280 lamports** to be
rent-exempt (`check_vault_rent_exempt` asserts the exact boundary).

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
