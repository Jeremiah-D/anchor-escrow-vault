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
  machine (`Uninitialized → Funded → Released/Cancelled`) with initializer
  authority checks and amount invariants, fully covered by unit tests.
- **What's a skeleton:** `programs/escrow-vault` is an Anchor program source
  file showing how the instructions (`initialize`, `fund`, `release`,
  `cancel`, `cancel_expired`, `initialize_quorum`, `attest`) would wrap the
  `escrow-state` logic on-chain. It is **not
  compiled here** — a full on-chain build and test requires the Solana/Anchor
  toolchain.
- **What CI does:** it runs `cargo test -p escrow-state` only.

No unverified claims are made about deployments, audits, or performance.

## Layout

```
escrow-state/               # pure-Rust state machine, zero dependencies
  src/lib.rs                # Escrow, EscrowState, EscrowError + unit tests
programs/escrow-vault/      # Anchor program skeleton (not in cargo workspace)
  src/lib.rs                # instructions wrapping escrow-state
Anchor.toml                 # Anchor project config (devnet placeholder)
.github/workflows/ci.yml    # CI: cargo test -p escrow-state
```

## State machine

| Transition                                  | From           | To        | Authority              |
|---------------------------------------------|----------------|-----------|------------------------|
| `initialize(initializer, taker, amount, expires_at)` | — | `Uninitialized` | anyone (amount > 0) |
| `initialize_quorum(attestors, threshold)`    | `Uninitialized`| `Uninitialized` | initializer (once, before funding) |
| `attest(attestor)`                          | `Uninitialized`/`Funded` | — (no state change) | registered attestor |
| `fund(authority)`                           | `Uninitialized`| `Funded`  | initializer            |
| `release(authority)`                        | `Funded`       | `Released`| initializer (+ quorum satisfied when configured) |
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

**Amount conservation** is pinned by a model-based fuzz test: 24
deterministic seeds × 48 random operations over 6 escrows assert
`inflow == locked + released + refunded` after every operation, with
`amount`/`expires_at` immutable and failed operations state-preserving.

## Run the tests

```bash
cargo test -p escrow-state
```

Requires a stable Rust toolchain (`rustup toolchain install stable`).
