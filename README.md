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
  `cancel`) would wrap the `escrow-state` logic on-chain. It is **not
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

| Transition                | From           | To        | Authority   |
|---------------------------|----------------|-----------|-------------|
| `initialize(initializer, taker, amount)` | — | `Uninitialized` | anyone (amount > 0) |
| `fund(authority)`         | `Uninitialized`| `Funded`  | initializer |
| `release(authority)`      | `Funded`       | `Released`| initializer |
| `cancel(authority)`       | `Funded`       | `Cancelled` | initializer |

Rules: only the initializer can drive transitions; any other caller gets
`Unauthorized`; any illegal transition (e.g. releasing twice, releasing
before funding) gets `InvalidStateTransition`; zero amounts get
`AmountMismatch`; `release`/`cancel` preserve `amount` exactly.

## Run the tests

```bash
cargo test -p escrow-state
```

Requires a stable Rust toolchain (`rustup toolchain install stable`).
