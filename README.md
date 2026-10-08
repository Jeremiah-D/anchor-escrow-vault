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
- **What's a skeleton:** `programs/escrow-vault/src/program.rs` is an Anchor program source
  file showing how the instructions (`initialize`, `fund`, `release`,
  `cancel`, `cancel_expired`, `initialize_quorum`, `attest`,
  `initialize_dual_sig`, `activate`, `initialize_vesting`, `claim`) would wrap the
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

Note that `attest` never changes `EscrowState` itself (it only grows the
quorum's approval bitmask), and the failed-call invariant holds on every
path above: any `Err(...)` return leaves the state — and `amount` and the
`released` counter — exactly untouched (pinned by the
permission/fuzz/property tests).

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
| **total**     |                   | **415** |

The quorum region is always reserved (zeroed when `None`), so
`initialize_quorum` writes the policy in place — the account never needs a
realloc. The 1-byte activation bitmask (AV-12) is likewise always present
(zeroed for plain escrows), as is the 17-byte vesting region (AV-13:
1-byte discriminant + `start`/`end` u64, zeroed when no schedule is
attached), and the 33-byte arbiter region (AV-14: 1-byte discriminant +
32-byte key, zeroed when no arbiter is configured) — all appended after
the earlier fields, so every earlier field offset stays stable.
`escrow-state` exposes `VAULT_SPACE` (415) and
`VAULT_SPACE_NO_QUORUM` (101) for the Anchor `space =` constraint, plus a
pure-logic rent-exemption check mirroring `Rent::minimum_balance`. With
mainnet rent parameters the full vault needs **3,779,280 lamports** to be
rent-exempt (`check_vault_rent_exempt` asserts the exact boundary).

## Run the tests

```bash
cargo test -p escrow-state
```

Requires a stable Rust toolchain (`rustup toolchain install stable`).

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
