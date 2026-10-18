//! Anchor program skeleton for the escrow vault.
//!
//! NOTE: This file is not compiled by CI. Building it requires the
//! Solana/Anchor toolchain (`anchor-lang`), which is intentionally kept out
//! of the workspace. It is excluded from the `escrow-vault` cargo package
//! (that package only ships the ignored integration test stubs in
//! `tests/`); it is kept here as the reference Anchor implementation.
//! It shows how the dependency-free state machine in
//! `escrow-state` maps onto Anchor instructions: each instruction converts
//! the on-chain account into `escrow_state::Escrow`, runs the transition,
//! and writes it back. State and authority rules live in one place —
//! the `escrow-state` crate — so the on-chain program cannot drift from
//! the tested logic. The optional weighted attestor quorum
//! (`initialize_quorum` / `attest`) gates `release` exactly as the state
//! machine does; the optional linear vesting schedule
//! (`initialize_vesting` / `claim`) lets
//! the taker pull the vested stream exactly as `Escrow::claim` defines;
//! the optional dispute arbiter (`initialize_arbiter` / `escalate` /
//! `resolve`) settles contested escrows with one atomic split exactly as
//! `Escrow::escalate` / `Escrow::resolve` define; the optional milestone
//! tranche plan (`initialize_milestones` / `confirm_milestone` /
//! `release_milestone` / `skip_milestone`) releases the lockup in
//! dual-confirmed tranches exactly as `Escrow::with_milestones` and
//! friends define; the optional SPL token mint binding (`initialize_mint`)
//! scopes the escrow to one token mint exactly as `Escrow::with_mint`
//! defines, with every fund-moving instruction verifying the vault token
//! account's mint against the bound address (`MintMismatch` otherwise);
//! the optional protocol fee (`initialize_protocol_fee`) routes a
//! basis-point slice of every taker payout to the protocol fee account
//! exactly as `Escrow::with_protocol_fee` / `protocol_fee_for` define;
//! every state transition emits a typed indexer event (`emit!`, AV-18)
//! mirroring `escrow_state::EscrowEvent`, with a per-vault monotonic
//! `seq` so an off-chain indexer can subscribe to state changes in
//! order instead of polling account data.
//!
//! The terminal-state vault close (`close_vault`) reclaims the
//! rent-exempt deposit: once the escrow is `Cancelled`, `Released` or
//! `Settled`, the initializer may close the vault account (Anchor
//! `close` constraint) and recover the lamports it has carried since
//! `initialize` — the escrow moves to `Closed`, the deepest terminal.
//! `release_and_close` (AV-50) merges the final payout and the close
//! into one signature (`Funded -> Released -> Closed`), emitting the
//! fixed `Released` then `VaultClosed` event pair.
//!
//! Reentrancy (AV-36): every fund-moving instruction runs under the
//! state machine's reentrancy guard — `Escrow::release_via_cpi` arms a
//! runtime lock around the injected executor (here: the real
//! `cpi_invoke_target` below), and every fund-moving transition
//! rejects a nested entry with `ReentrantCall` before its authority
//! check. A hostile CPI target that invokes the escrow program again
//! mid-instruction therefore fails closed, and the rejection is
//! visible to indexers as a `ReentryRejected` event.
//!
//! To compile for real: `anchor build` with the Solana toolchain installed.

use anchor_lang::prelude::*;

// Program ID placeholder — replace with the real deployed program address.
declare_id!("EscrowVault1111111111111111111111111111111111");

#[program]
pub mod escrow_vault {
    use super::*;

    /// Create the vault account and record initializer / taker / amount /
    /// expiry. Pass `u64::MAX` as `expires_at` for no timeout.
    /// AV-124: `keeper_bounty_pool` / `keeper_bounty_per_crank` are the
    /// opt-in keeper-bounty terms (lamports) — the pre-funded bounty
    /// pool plus the fixed per-crank bounty (see
    /// `escrow_state::Escrow::with_keeper_bounty`). `0` / `0` (the
    /// default) leaves the bounty disabled and keeps the AV-48
    /// unpaid-crank semantics.
    pub fn initialize(
        ctx: Context<Initialize>,
        amount: u64,
        expires_at: u64,
        keeper_bounty_pool: u64,
        keeper_bounty_per_crank: u64,
    ) -> Result<()> {
        let escrow = escrow_state::Escrow::initialize(
            ctx.accounts.initializer.key().to_bytes(),
            ctx.accounts.taker.key().to_bytes(),
            amount,
            expires_at,
        )
        .map_err(|e| escrow_error(e))?
        // AV-124: the bounty terms are fixed at vault creation, like
        // the other `with_*` builders — `0` / `0` is a no-op by the
        // `keeper_bounty_enabled` predicate.
        .with_keeper_bounty(keeper_bounty_pool, keeper_bounty_per_crank)
        .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: the constructor has no prior state — from == to ==
        // Uninitialized by the same convention as `IndexedEscrow`.
        let state = escrow_state::EscrowState::Uninitialized as u8;
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Initialized,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Create a multi-mint basket vault (AV-95b; the basket twin of
    /// `initialize`). `legs` is the (mint, amount) leg table —
    /// non-empty, at most `escrow_state::MAX_BASKET_LEGS` (8) legs, no
    /// zero mint, no zero amount, no duplicate mint, and a leg-amount
    /// Σ that fits in `u64` (every violation is `InvalidBasket`, code
    /// 152). The vault account is created with the basket region
    /// reserved in place (386 bytes, always reserved — see AV-95a), so
    /// the legs are written without reallocating; the escrow-level
    /// `amount` is the Σ over the legs.
    pub fn initialize_basket(
        ctx: Context<InitializeBasket>,
        legs: Vec<BasketLegArg>,
        expires_at: u64,
    ) -> Result<()> {
        let leg_tuples: Vec<([u8; 32], u64)> = legs
            .iter()
            .map(|l| (l.mint.to_bytes(), l.amount))
            .collect();
        let escrow = escrow_state::Escrow::initialize_basket(
            ctx.accounts.initializer.key().to_bytes(),
            ctx.accounts.taker.key().to_bytes(),
            &leg_tuples,
            expires_at,
        )
        .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: the constructor has no prior state — from == to ==
        // Uninitialized by the same convention as
        // `IndexedEscrow::initialize_basket`.
        let state = escrow_state::EscrowState::Uninitialized as u8;
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Initialized,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Lock funds into the vault (`Uninitialized -> Funded`).
    /// AV-64: the funding timestamp is read from the Solana clock
    /// sysvar (never an instruction param) and recorded as
    /// `vault.fund_at` — the origin the relative timelock measures
    /// from.
    pub fn fund(ctx: Context<Fund>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-64: `fund_at` anchors the relative timelock at funding
        // time — the clock sysvar, like the AV-27 gate's `now`.
        let now = Clock::get()?.unix_timestamp as u64;
        // AV-116: `fund_slot` anchors the slot-based relative timelock
        // at the funding slot — the clock sysvar's `slot`, never an
        // instruction param (a caller-supplied slot would let the
        // initializer fast-forward the lock they configured).
        let slot = Clock::get()?.slot;
        escrow
            .fund_with_slot(ctx.accounts.initializer.key().to_bytes(), now, slot)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: one indexer event per state transition (mirrors
        // `IndexedEscrow::fund`).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Funded,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Release `amount` of the locked funds to the taker. Partial releases
    /// accumulate in `vault.released` and leave the escrow `Funded`; when
    /// the cumulative released total reaches the locked amount the escrow
    /// becomes `Released`. Cumulative releases must not exceed the locked
    /// amount (`ReleaseExceedsLocked`); `amount == 0` is `AmountMismatch`.
    /// The AV-04 quorum gate applies exactly as the state machine defines.
    /// Returns `(taker_payout, fee)`: the taker's net payout and the
    /// protocol fee (AV-17), so the real build can transfer each to its
    /// destination (taker account / protocol fee account).
    /// AV-16: the vault token account's mint must equal the bound
    /// `vault.mint` (`MintMismatch` otherwise); `None` on the native-SOL
    /// path (no mint bound).
    pub fn release(ctx: Context<Release>, amount: u64) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-27: the timelock gate reads the Solana clock sysvar — never
        // an instruction param, so the initializer cannot fast-forward
        // the lock they configured.
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        // AV-116: the slot-based relative timelock gates the payout on
        // the clock sysvar's slot — never an instruction param, same
        // rule. Evaluated before the AV-113 price-gate routing so the
        // two gates compose; a no-op when no slot lock is configured.
        let slot = Clock::get()?.slot;
        if !escrow.is_slot_unlock_eligible(slot) {
            return Err(escrow_error(escrow_state::EscrowError::TimelockNotReached));
        }
        // AV-128: when a TWAP gate is configured, the release routes
        // through the twap-gated entry point and the oracle account
        // (first remaining account) feeds the quote history — the
        // program passes it through to the state machine. The
        // twap-gated entry point also enforces the AV-113 single-point
        // gate when both are configured, so the TWAP gate takes
        // precedence in routing.
        // AV-113: when only a price gate is configured, the release
        // routes through the price-gated entry point and the oracle
        // account (first remaining account) feeds the quote — the
        // program passes it through to the state machine. Ungated
        // escrows take the plain path exactly as before.
        let (payout, fee) = if escrow.twap_gate().is_some() {
            let quote = read_oracle_quote(ctx.remaining_accounts)?;
            let history = read_oracle_history(ctx.remaining_accounts)?;
            let feed = TwapFeed { quote, history };
            let slot = Clock::get()?.slot;
            escrow
                .release_twap_gated(
                    ctx.accounts.initializer.key().to_bytes(),
                    now,
                    slot,
                    amount,
                    vault_token_mint(&ctx.accounts.vault_token_account),
                    ctx.accounts.payout_to.key().to_bytes(),
                    &feed,
                )
                .map_err(|e| escrow_error(e))?
        } else if escrow.price_gate().is_some() {
            let quote = read_oracle_quote(ctx.remaining_accounts)?;
            let feed = QuoteFeed(quote);
            escrow
                .release_price_gated(
                    ctx.accounts.initializer.key().to_bytes(),
                    now,
                    amount,
                    vault_token_mint(&ctx.accounts.vault_token_account),
                    ctx.accounts.payout_to.key().to_bytes(),
                    &feed,
                )
                .map_err(|e| escrow_error(e))?
        } else {
            escrow
                .release(
                    ctx.accounts.initializer.key().to_bytes(),
                    now,
                    amount,
                    vault_token_mint(&ctx.accounts.vault_token_account),
                    ctx.accounts.payout_to.key().to_bytes(),
                )
                .map_err(|e| escrow_error(e))?
        };
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_payout` (`PayoutKind::Release`) —
        // the transfer instruction bytes are built and validated by
        // `escrow_state::cpi::payout_plan` (amounts/recipients pinned
        // against the state machine); the real build executes the
        // validated plan once the token accounts are wired up.
        // AV-18: `payout + fee` is the gross amount (== the `amount`
        // param); partial releases carry from == to == Funded, the
        // closing one to == Released.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Released,
            from,
            escrow.state() as u8,
            payout + fee,
            fee,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok((payout, fee))
    }

    /// Gasless release via the initializer's off-chain Ed25519 intent
    /// (AV-123 — the Solana meta-transaction pattern, payment fintech:
    /// the paymaster model). The relayer (`ctx.accounts.relayer`,
    /// any fee payer) submits the initializer's intent (`amount`,
    /// `payout_to`, `nonce`, `expiry_slot`) plus the 64-byte Ed25519
    /// signature over the intent's canonical bytes
    /// (`ESCROW-RELEASE-v1` domain).
    ///
    /// Double insurance on the authorization:
    ///
    /// 1. The transaction must carry an Ed25519 precompile program
    ///    instruction (`Ed25519Program1111111111111111111111111111111111`),
    ///    verified by introspecting the Instructions sysvar — the
    ///    Solana-native check that the runtime executed the
    ///    signature verification as part of this transaction
    ///    (`Ed25519ProgramInstructionMissing` when absent).
    /// 2. The state machine re-verifies the detached signature
    ///    against the escrow's initializer key over the canonical
    ///    intent bytes (`InvalidReleaseIntent`, code 181, on
    ///    failure) — the self-contained check that needs no
    ///    precompile.
    ///
    /// Either check failing aborts before any state moves. The
    /// nonce (`IntentNonceReused`, code 182) and expiry (`IntentExpired`,
    /// code 183) gates follow, then the entire `release` guard chain
    /// runs with the authority pinned to the initializer — a gasless
    /// release is a release, never a bypass. Only success advances
    /// `last_intent_nonce`.
    ///
    /// The vault account is *not* a signer and the initializer does
    /// not sign this transaction: that is the point — the
    /// initializer's authorization rides the intent, not the signer
    /// set. Emits `ReleaseViaIntent` with the gross amount and the
    /// fee (actor == the initializer, never the relayer).
    pub fn release_via_intent(
        ctx: Context<ReleaseViaIntent>,
        amount: u64,
        payout_to: Pubkey,
        nonce: u64,
        expiry_slot: u64,
        signature: Vec<u8>,
    ) -> Result<(u64, u64)> {
        // AV-123 (1): the Ed25519 precompile program must have
        // executed in this transaction — introspect the Instructions
        // sysvar for its program id. The runtime pre-verifies the
        // signature; this pins the precompile's presence to the
        // transaction the intent rides in.
        assert_ed25519_precompile_present(&ctx.accounts.instructions)?;
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        // AV-123: the expiry gate reads the clock sysvar's slot —
        // never an instruction param, so a relayer cannot
        // fast-forward an intent's life (the AV-27 rule).
        let slot = Clock::get()?.slot;
        let intent = escrow_state::ReleaseIntent::new(
            ctx.accounts.vault.key().to_bytes(),
            amount,
            payout_to.to_bytes(),
            nonce,
            expiry_slot,
        );
        let sig: [u8; 64] = signature
            .try_into()
            .map_err(|_| escrow_error(escrow_state::EscrowError::InvalidReleaseIntent))?;
        let (payout, fee) = escrow
            .release_via_intent(&intent, &sig, now, slot, vault_token_mint(&ctx.accounts.vault_token_account))
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_payout` (`PayoutKind::Release`) —
        // like `release`, the real build executes the validated plan
        // once the token accounts are wired up.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::ReleaseViaIntent,
            from,
            escrow.state() as u8,
            payout + fee,
            fee,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok((payout, fee))
    }

    /// Release `amount` split across several recipients by basis-point
    /// weights (AV-93 — Solana / payment fintech: the initializer's
    /// multi-party payout — a revenue share, a creator royalty split,
    /// a payroll run — settled in one transition instead of N partial
    /// `release` calls). The state machine
    /// (`escrow_state::Escrow::release_split`) runs the exact `release`
    /// gates, validates the share table (`InvalidReleaseSplit`, code
    /// 150 — empty / over-long / zero address / zero weight / weight
    /// sum != 10_000), pins every recipient against the AV-49 payout
    /// policy (`PayoutNotAllowlisted` otherwise), charges the AV-17
    /// protocol fee on the gross amount first, then splits the net —
    /// each leg is `floor(net * bps / 10_000)` with the dust landing on
    /// the first recipient, so the legs sum to the net exactly.
    /// `released` accumulates the gross amount, so the conservation
    /// invariant is untouched by the split.
    /// `recipients` / `bps` are parallel instruction params (in payout
    /// order); the real build transfers leg `i` to
    /// `ctx.remaining_accounts[i]` — asserted here to key-match the
    /// params' recipients order (the state machine validated the set,
    /// the skeleton pins the account wiring). Returns `(legs, fee)`:
    /// the per-recipient `(recipient, net_share)` legs in table order
    /// so the real build can size each transfer, plus the protocol fee
    /// (to the fee account). Emits `ReleasedSplit` with the gross
    /// amount and the fee; the real build stamps the legs on the event
    /// (mirroring `IndexedEscrow::release_split`'s roster stamp), so
    /// indexers read the exact transfer sizes from the log.
    pub fn release_split(
        ctx: Context<ReleaseSplit>,
        amount: u64,
        recipients: Vec<Pubkey>,
        bps: Vec<u16>,
    ) -> Result<(Vec<([u8; 32], u64)>, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-27: the timelock gate reads the Solana clock sysvar — never
        // an instruction param.
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        // The legs travel as remaining_accounts in recipients order —
        // the real build's transfer sizing; pin the wiring against the
        // validated params (a swapped recipient account fails closed).
        require!(
            recipients.len() == bps.len(),
            ErrorCode::InvalidReleaseSplit
        );
        require!(
            ctx.remaining_accounts.len() == recipients.len(),
            ErrorCode::InvalidReleaseSplit
        );
        for (account, recipient) in ctx.remaining_accounts.iter().zip(recipients.iter()) {
            require_keys_eq!(account.key(), *recipient, ErrorCode::InvalidReleaseSplit);
        }
        let shares: Vec<([u8; 32], u16)> = recipients
            .iter()
            .zip(bps.iter())
            .map(|(r, b)| (r.to_bytes(), *b))
            .collect();
        let (legs, fee) = escrow
            .release_split(
                ctx.accounts.initializer.key().to_bytes(),
                now,
                amount,
                vault_token_mint(&ctx.accounts.vault_token_account),
                &shares,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `payout` (the gross `amount`) + `fee`; partial splits
        // carry from == to == Funded, the closing one to == Released.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::ReleasedSplit,
            from,
            escrow.state() as u8,
            amount,
            fee,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok((legs, fee))
    }

    /// Release `amount` routed through a third-party program via CPI
    /// (AV-35): the taker's payout flows into the target program's
    /// instruction — a DEX swap, a lending-protocol deposit — instead of
    /// moving straight to the taker wallet. The target program is
    /// `ctx.remaining_accounts[0]`; `ctx.remaining_accounts[1..]` are
    /// the target instruction's accounts in its expected order;
    /// `cpi_data` is the target instruction's opaque data. The state
    /// machine (`escrow_state::Escrow::release_via_cpi`) runs the exact
    /// `release` gates, validates the invocation shape, and — on
    /// executor failure — rolls the whole release back, mirroring the
    /// chain's CPI atomicity. The protocol fee still settles to the fee
    /// account through the normal payout path. AV-132: `min_payout` is
    /// the slippage floor — the executor reports the actual
    /// post-execution taker-leg amount and an actual below the floor
    /// rolls back with `SlippageExceeded` (code 195); `0` disables the
    /// floor. Returns `(taker_payout, fee)`; the CPI audit
    /// (`cpi_target` + `cpi_accounts_hash`) rides on the `Released`
    /// event.
    pub fn release_via_cpi(
        ctx: Context<ReleaseViaCpi>,
        amount: u64,
        min_payout: u64,
        cpi_data: Vec<u8>,
    ) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-27: the timelock gate reads the Solana clock sysvar — never
        // an instruction param.
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        // Build the third-party invocation from the remaining accounts:
        // [0] is the target program, [1..] its instruction accounts.
        let invocation = cpi_invocation_from_remaining_accounts(
            ctx.remaining_accounts,
            cpi_data,
        )?;
        let (payout, fee, receipt) = escrow
            .release_via_cpi(
                ctx.accounts.initializer.key().to_bytes(),
                now,
                amount,
                vault_token_mint(&ctx.accounts.vault_token_account),
                ctx.accounts.payout_to.key().to_bytes(),
                min_payout,
                &invocation,
                // The execution seam: the real build invokes the target
                // program here via `cpi_invoke_target` below and returns
                // the actual post-execution taker-leg amount (the DEX
                // swap's output tokens, measured as the taker-leg
                // account's balance delta across the invoke). A failed
                // invoke aborts the transaction, so no state change
                // persists — the state machine's rollback models exactly
                // this. AV-132: an actual below `min_payout` rolls the
                // release back with `SlippageExceeded`
                // (`ErrorCode::SlippageExceeded`) — same atomicity, no
                // receipt, no event. AV-36: the state machine arms its
                // reentrancy lock around this closure (see
                // `escrow_state::Escrow::release_via_cpi`), so a hostile
                // target that CPIs back into this program mid-invoke is
                // rejected with `ReentrantCall` (`ErrorCode::ReentrantCall`)
                // before its authority check — the outer release is
                // unaffected and the rejection emits a `ReentryRejected`
                // indexer event.
                // AV-83: when the escrow carries a CPI target allowlist,
                // the state machine's fail-closed allowlist check runs
                // after shape validation and before the invocation — an
                // off-list target is rejected with `InvalidCpiTarget`
                // (code 120) with full rollback, exactly as a failed
                // invoke aborts the transaction.
                |inv| cpi_invoke_target(&ctx, inv),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `payout + fee` is the gross amount (== the `amount`
        // param); partial releases carry from == to == Funded, the
        // closing one to == Released. AV-35: the Released event carries
        // the CPI audit so the indexer pins the authorized instruction.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Released,
            from,
            escrow.state() as u8,
            payout + fee,
            fee,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            Some(receipt.cpi_target),
            Some(receipt.accounts_hash),
            None,
        );
        Ok((payout, fee))
    }

    /// Cancel the escrow and return funds (`Funded -> Cancelled`).
    /// AV-16: the vault token account's mint must equal the bound
    /// `vault.mint` (`MintMismatch` otherwise); `None` on the native-SOL
    /// path (no mint bound).
    /// AV-23: the refund goes to `accounts.refund_to`, pinned by the
    /// state machine against the escrow's refund policy (the whitelisted
    /// address, or the initializer with no whitelist;
    /// `RefundAddressMismatch` otherwise) — a phishing frontend cannot
    /// redirect the refund by swapping the destination account.
    pub fn cancel(ctx: Context<Cancel>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        escrow
            .cancel(
                ctx.accounts.initializer.key().to_bytes(),
                vault_token_mint(&ctx.accounts.vault_token_account),
                ctx.accounts.refund_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_refund` (`RefundKind::Cancel`) —
        // `escrow_state::cpi::refund_plan` builds and validates the
        // refund transfer bytes against the AV-23-pinned `refund_to`;
        // the real build executes the validated plan once the token
        // accounts are wired up.
        // AV-18: the refund is the remainder after any partial releases.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Cancelled,
            from,
            escrow.state() as u8,
            0,
            0,
            escrow.remaining_amount(),
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Cancel an expired escrow (`Funded -> Cancelled`). Either the
    /// initializer or the taker may call this once the clock (Solana
    /// clock sysvar in the real build) has passed `expires_at` plus the
    /// opt-in grace period (`initialize_grace_period`; `NotExpired`
    /// otherwise) — the grace period absorbs keeper/cluster clock drift
    /// so a keeper cannot submit a premature cancel.
    /// AV-16: the vault token account's mint must equal the bound
    /// `vault.mint` (`MintMismatch` otherwise); `None` on the native-SOL
    /// path (no mint bound).
    /// AV-23: the refund goes to `accounts.refund_to`, pinned by the
    /// state machine against the escrow's refund policy — even when the
    /// taker is the caller, the refund goes to the declared address,
    /// never to the caller (`RefundAddressMismatch` otherwise).
    /// AV-24: on a *taker-initiated* cancel the state machine returns
    /// the `(refund, penalty)` split — the penalty is routed to the
    /// initializer as griefing compensation (a separate transfer in the
    /// real build); initializer-initiated cancels return
    /// `(remaining, 0)`.
    pub fn cancel_expired(ctx: Context<CancelExpired>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        let (refund, _penalty) = escrow
            .cancel_expired(
                ctx.accounts.authority.key().to_bytes(),
                now,
                vault_token_mint(&ctx.accounts.vault_token_account),
                ctx.accounts.refund_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_refund` (`RefundKind::CancelExpired`) —
        // `escrow_state::cpi::refund_plan` builds and validates the
        // transfer bytes: `refund` to the AV-23-pinned `refund_to`,
        // `penalty` (non-zero only on a taker-initiated cancel, AV-24)
        // to the initializer. The real build executes the validated
        // plan once the token accounts are wired up.
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::cancel_expired`. The real build's
        // `EscrowVaultEvent` gains a `penalty` amounts field mirroring
        // `escrow_state::EventAmounts::penalty`; the skeleton's
        // `emit_transition` keeps its current shape until the real
        // build wires the event struct.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::ExpiredCancelled,
            from,
            escrow.state() as u8,
            0,
            0,
            refund,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Partially cancel the escrow and refund a tranche to the
    /// initializer (`Funded -> Funded`, AV-60) — the initializer's
    /// counterpart to AV-11's partial release. `amount` is the
    /// instruction param; the escrow stays live at the reduced lockup,
    /// and the `released` counter is untouched.
    /// AV-16: the vault token account's mint must equal the bound
    /// `vault.mint` (`MintMismatch` otherwise); `None` on the native-SOL
    /// path (no mint bound).
    /// AV-23: the refund goes to `accounts.refund_to`, pinned by the
    /// state machine against the escrow's refund policy (the whitelisted
    /// address, or the initializer with no whitelist;
    /// `RefundAddressMismatch` otherwise).
    /// Amount rules reuse the AV-11 semantics: `amount == 0` is
    /// `AmountMismatch`, `amount` above the still-locked remainder is
    /// `ReleaseExceedsLocked`. Like `cancel`, quorum / timelock / vesting
    /// do not gate this path.
    pub fn cancel_partial(ctx: Context<CancelPartial>, amount: u64) -> Result<u64> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let refund = escrow
            .cancel_partial(
                ctx.accounts.initializer.key().to_bytes(),
                amount,
                vault_token_mint(&ctx.accounts.vault_token_account),
                ctx.accounts.refund_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_refund` (`RefundKind::Cancel`) —
        // `escrow_state::cpi::refund_plan` builds and validates the
        // refund transfer bytes against the AV-23-pinned `refund_to`;
        // the real build executes the validated plan once the token
        // accounts are wired up.
        // AV-18: `from == to == Funded`; `refund` carries the
        // partially-cancelled tranche, mirroring
        // `IndexedEscrow::cancel_partial`.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::PartiallyCancelled,
            from,
            escrow.state() as u8,
            0,
            0,
            refund,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(refund)
    }

    /// Partially refund the escrow and return a tranche to the
    /// initializer (`Funded -> Funded`, AV-127) — the audited
    /// counterpart to AV-60's `cancel_partial`. `amount` is the
    /// instruction param; the escrow stays live at the reduced lockup,
    /// the `released` counter is untouched, and the refunded tranche
    /// accumulates in the vault's persisted `refunded` counter (see
    /// `escrow_state::Escrow::refunded_amount`).
    /// AV-16: the vault token account's mint must equal the bound
    /// `vault.mint` (`MintMismatch` otherwise); `None` on the native-SOL
    /// path (no mint bound).
    /// AV-23: the refund goes to `accounts.refund_to`, pinned by the
    /// state machine against the escrow's refund policy (the whitelisted
    /// address, or the initializer with no whitelist;
    /// `RefundAddressMismatch` otherwise).
    /// Amount rules: `amount == 0` is `AmountMismatch`, `amount` above
    /// the still-locked remainder is the dedicated
    /// `PartialRefundExceedsLocked` (code 185). Initializer-only (no
    /// delegation scope); Funded-only. Like `cancel`, quorum / timelock /
    /// vesting do not gate this path.
    pub fn partial_refund(ctx: Context<PartialRefund>, amount: u64) -> Result<u64> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let refund = escrow
            .partial_refund(
                ctx.accounts.initializer.key().to_bytes(),
                amount,
                vault_token_mint(&ctx.accounts.vault_token_account),
                ctx.accounts.refund_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_refund` (`RefundKind::Cancel`) —
        // `escrow_state::cpi::refund_plan` builds and validates the
        // refund transfer bytes against the AV-23-pinned `refund_to`;
        // the real build executes the validated plan once the token
        // accounts are wired up.
        // AV-18: `from == to == Funded`; `refund` carries the
        // partially-refunded tranche, mirroring
        // `IndexedEscrow::partial_refund`.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::PartialRefunded,
            from,
            escrow.state() as u8,
            0,
            0,
            refund,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(refund)
    }

    /// Permissionless expiry crank (AV-48 — Solana crank pattern;
    /// mirrors `Escrow::crank_expired`). ANY signer may execute the
    /// expiry cancel on a `Funded` escrow once the clock (Solana clock
    /// sysvar) has passed `expires_at` plus the opt-in grace period —
    /// no counterparty signature required, so a keeper bot that is
    /// party to nothing can sweep timed-out vaults.
    ///
    /// Anti-MEV by construction: the caller authorizes nothing about
    /// the funds. `accounts.refund_to` is asserted here against the
    /// vault's pinned refund policy (the AV-23 whitelist address when
    /// configured, otherwise the initializer — the state machine pins
    /// it internally too). AV-124: when the initializer opted into the
    /// keeper bounty, the cranker additionally receives
    /// `min(keeper_bounty_per_crank, keeper_bounty_pool)` (saturating)
    /// — without the bounty the cranker receives nothing (the AV-48
    /// behavior). AV-24: a taker cranker still pays the anti-griefing
    /// penalty to the initializer; every other caller returns
    /// `(remaining, 0, bounty)`.
    /// A paused escrow rejects with `Paused` (AV-46).
    pub fn crank_expired(ctx: Context<CrankExpired>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        // The state machine pins the refund destination internally
        // (AV-48); the skeleton additionally asserts the transfer
        // target account matches the pinned policy, so a swapped
        // account fails closed before any state changes.
        let expected_refund_to = match ctx.accounts.vault.refund_to {
            Some(addr) => addr,
            None => ctx.accounts.vault.initializer,
        };
        require!(
            ctx.accounts.refund_to.key() == expected_refund_to,
            ErrorCode::RefundAddressMismatch
        );
        let from = escrow.state() as u8;
        let (refund, _penalty, bounty) = escrow
            .crank_expired(
                ctx.accounts.cranker.key().to_bytes(),
                now,
                vault_token_mint(&ctx.accounts.vault_token_account),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_refund` (`RefundKind::CancelExpired`) —
        // `escrow_state::cpi::refund_plan` builds and validates the
        // transfer bytes: `refund` to the pinned `refund_to`, `penalty`
        // (non-zero only when the cranker is the taker, AV-24) to the
        // initializer. The real build executes the validated plan once
        // the token accounts are wired up.
        // AV-124: the real build additionally transfers `bounty`
        // lamports from the vault to the cranker, sized by the
        // returned triple — the state machine already debited the
        // pool, so the transfer cannot overpay.
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::crank_expired`; the `caller` field carries the
        // crank signer's key so the indexer sees who cranked without a
        // second account read.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::ExpiredCranked,
            from,
            escrow.state() as u8,
            0,
            0,
            refund,
            now,
            None,
            None,
            None,
            None,
            Some(ctx.accounts.cranker.key()),
        );
        // AV-124: a bounty-paying crank emits `KeeperBountyPaid`
        // (`from == to == Cancelled` — the unwind is already final),
        // mirroring `IndexedEscrow::crank_expired`; a zero-bounty crank
        // emits `ExpiredCranked` alone.
        if bounty > 0 {
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::KeeperBountyPaid,
                escrow.state() as u8,
                escrow.state() as u8,
                bounty,
                0,
                0,
                now,
                None,
                None,
                None,
                None,
                Some(ctx.accounts.cranker.key()),
            );
        }
        Ok(())
    }
    /// (`Uninitialized` only; mirrors `Escrow::with_quorum`). After
    /// this, `release` additionally requires the accumulated weight of
    /// distinct attestations to reach `threshold`; the refund paths
    /// (`cancel` / `cancel_expired`) stay quorum-free by design.
    pub fn initialize_quorum(
        ctx: Context<InitializeQuorum>,
        attestors: Vec<Pubkey>,
        weights: Vec<u64>,
        threshold: u64,
    ) -> Result<()> {
        let keys: Vec<[u8; 32]> = attestors.iter().map(|k| k.to_bytes()).collect();
        let policy =
            escrow_state::QuorumPolicy::new(&keys, &weights, threshold).map_err(|e| escrow_error(e))?;
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_quorum(policy).map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full quorum region
        // (`escrow_state::QUORUM_POLICY_LEN`), so the policy is written in
        // place — no realloc needed in the real build.
        Ok(())
    }

    /// Record an attestation from a registered attestor (mirrors
    /// `Escrow::attest`). Idempotent; callers outside the registered set
    /// get `Unauthorized`.
    pub fn attest(ctx: Context<Attest>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let approvals_before = escrow
            .quorum()
            .map(|q| q.approval_count())
            .unwrap_or(0);
        escrow
            .attest(ctx.accounts.attestor.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flip the attestor's bit in `vault.quorum.approvals` in the real build.
        // AV-18: emit only for a *new* attestation (mirrors
        // `IndexedEscrow::attest`); idempotent duplicates emit nothing.
        // from == to == the current state — the quorum bitmask, not the
        // lifecycle state, is what changed.
        let approvals_after = escrow.quorum().map(|q| q.approval_count()).unwrap_or(0);
        if approvals_after > approvals_before {
            let state = escrow.state() as u8;
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Attested,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Adjust the quorum's weight-sum threshold by dual-signed
    /// governance (AV-25; mirrors `Escrow::update_quorum`). Both the
    /// initializer and the taker must sign — one party alone cannot
    /// weaken the gate. Allowed on `Uninitialized` or `Funded` escrows;
    /// `0` or above the total registered weight is `InvalidQuorum`, as
    /// is calling with no quorum configured. The attestor set, their
    /// weights, and existing attestations are untouched — only the
    /// threshold moves, in place, so the account needs no realloc.
    /// Emits `QuorumUpdated` when the threshold actually changes (a
    /// no-op re-affirmation emits nothing), mirroring
    /// `IndexedEscrow::update_quorum`.
    pub fn update_quorum(ctx: Context<UpdateQuorum>, threshold: u64) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let threshold_before = escrow.quorum().map(|q| q.threshold()).unwrap_or(0);
        escrow
            .update_quorum(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
                threshold,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Write the new threshold into `vault.quorum.threshold` in the
        // real build (in place — the quorum region is always reserved).
        let threshold_after = escrow.quorum().map(|q| q.threshold()).unwrap_or(0);
        if threshold_after != threshold_before {
            let state = escrow.state() as u8;
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::QuorumUpdated,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Replace the quorum's attestor set by dual-signed governance
    /// (AV-39; mirrors `Escrow::update_attestors`). Both the
    /// initializer and the taker must sign — one party alone cannot
    /// reshape the electorate into sockpuppets (a unilateral weakening
    /// of the release gate). Allowed on `Uninitialized` or `Funded`
    /// escrows; no quorum configured, an empty set, more than 8 keys,
    /// a duplicate key, a weight/length mismatch, a zero weight, or a
    /// weight-sum threshold that no longer fits the new total weight is
    /// `InvalidQuorum`. The set compacts into the already-reserved 8
    /// slots in place, so the account needs no realloc. Approval bits
    /// remap by pubkey: retained attestors keep their votes (at the new
    /// weights), removed attestors lose theirs. Emits `AttestorsUpdated`
    /// when the set actually changes (a no-op same-set update emits
    /// nothing), mirroring `IndexedEscrow::update_attestors`.
    pub fn update_attestors(
        ctx: Context<UpdateAttestors>,
        attestors: Vec<Pubkey>,
        weights: Vec<u64>,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let set_before: Vec<([u8; 32], u64)> = escrow
            .quorum()
            .map(|q| {
                q.attestors()
                    .iter()
                    .zip(q.weights().iter())
                    .map(|(a, w)| (*a, *w))
                    .collect()
            })
            .unwrap_or_default();
        escrow
            .update_attestors(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
                &attestors
                    .iter()
                    .map(|a| a.to_bytes())
                    .collect::<Vec<[u8; 32]>>(),
                &weights,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Rewrite `vault.quorum.attestors` / `vault.quorum.weights` in the
        // real build (in place — the quorum region is always reserved),
        // with the approval bitmask remapped by pubkey exactly as the
        // state machine does.
        let set_after: Vec<([u8; 32], u64)> = escrow
            .quorum()
            .map(|q| {
                q.attestors()
                    .iter()
                    .zip(q.weights().iter())
                    .map(|(a, w)| (*a, *w))
                    .collect()
            })
            .unwrap_or_default();
        if set_after != set_before {
            let state = escrow.state() as u8;
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::AttestorsUpdated,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Opt in to dual-signature activation (AV-12; mirrors
    /// `Escrow::with_dual_sig`). `Uninitialized` only, like
    /// `initialize_quorum`. After this, `fund` requires the escrow to be
    /// `Activated`: a single signature can create the escrow but never
    /// fund it.
    pub fn initialize_dual_sig(ctx: Context<InitializeDualSig>) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_dual_sig().map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Sets the required-bit in `vault.activation` in the real build.
        Ok(())
    }

    /// Record one party's activation signature (AV-12; mirrors
    /// `Escrow::activate`). Either the initializer or the taker signs;
    /// idempotent per party. When both bits are set the escrow moves
    /// `Uninitialized -> Activated`, unlocking `fund`. A stranger's
    /// signature is `Unauthorized`.
    pub fn activate(ctx: Context<Activate>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        escrow
            .activate(ctx.accounts.authority.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flip the party's bit in `vault.activation` in the real build.
        // AV-18: emit only when the call actually transitioned the escrow
        // (mirrors `IndexedEscrow::activate`); a single party's signature
        // emits nothing.
        let to = escrow.state() as u8;
        if to != from {
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Activated,
            from,
            to,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Attach a linear vesting schedule (AV-13; mirrors
    /// `VestingSchedule::new` + `Escrow::with_vesting`), with an optional
    /// cliff (AV-51). `cliff == 0` means no cliff (the plain AV-13 curve,
    /// `cliff_at = start`); a nonzero `cliff` gates all unlocking until
    /// that timestamp — before it nothing vests, at/after it the linear
    /// curve from `start` applies (the cliff gates unlocking, it does not
    /// rebase the curve). `Uninitialized` only, like `initialize_quorum`:
    /// the unlock curve is fixed before funds move. `start >= end` or
    /// `cliff > end` is `InvalidVesting`. The instruction discriminator
    /// is unchanged (name-derived: a new param does not rename the
    /// instruction).
    pub fn initialize_vesting(
        ctx: Context<InitializeVesting>,
        start: u64,
        end: u64,
        cliff: u64,
    ) -> Result<()> {
        let schedule = escrow_state::VestingSchedule::new_with_cliff(
            start,
            end,
            if cliff == 0 { start } else { cliff },
        )
        .map_err(|e| escrow_error(e))?;
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_vesting(schedule).map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full vesting region
        // (1 + 24 bytes, zeroed when `None`), so the schedule is written
        // in place — no realloc needed in the real build.
        Ok(())
    }

    /// Attach a vesting schedule with a non-linear unlock curve (AV-90;
    /// mirrors `VestingCurve::stepped` + `Escrow::with_vesting_curve`).
    /// The `tiers` replace the AV-13 linear interpolation between
    /// `start` and `end` (see `escrow_state::VestingCurve::stepped` for
    /// the validation: strictly increasing timestamps within
    /// `[start, end]`, strictly increasing bps, final tier 10_000).
    /// `cliff == 0` means no cliff (`cliff_at = start`); a nonzero
    /// `cliff` gates all unlocking until that timestamp, orthogonally
    /// to the curve. `Uninitialized` only, like `initialize_vesting`:
    /// the unlock timeline is fixed before funds move. The vault
    /// account already reserves the full curve region (1 + 81 bytes,
    /// zeroed when `None`), so the curve is written in place — no
    /// realloc needed in the real build.
    pub fn initialize_vesting_curve(
        ctx: Context<InitializeVestingCurve>,
        start: u64,
        end: u64,
        cliff: u64,
        tiers: Vec<VestingTier>,
    ) -> Result<()> {
        let schedule = escrow_state::VestingSchedule::new_with_cliff(
            start,
            end,
            if cliff == 0 { start } else { cliff },
        )
        .map_err(|e| escrow_error(e))?;
        let tier_tuples: Vec<(u64, u16)> =
            tiers.iter().map(|t| (t.at, t.unlocked_bps)).collect();
        let curve =
            escrow_state::VestingCurve::stepped(&tier_tuples, start, end)
                .map_err(|e| escrow_error(e))?;
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_vesting_curve(schedule, curve)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Opt in to Dutch-auction settlement (AV-97; mirrors
    /// `Escrow::with_dutch_auction`). `Uninitialized` only, like
    /// `initialize_vesting`: the window and the reserve floor are
    /// fixed before funds move. Once funded, the taker's `claim`
    /// prices through the descending auction cap inside `[start_at,
    /// end_at]` (`AuctionNotActive`, code 156, outside the window);
    /// the initializer reclaims the remainder via `cancel` /
    /// `cancel_partial`. `start_at >= end_at` or `reserve_bps >
    /// 10_000` is `InvalidAuctionParams` (code 155). The auction and
    /// the AV-13/AV-90 unlock paths are mutually exclusive,
    /// last-wins. The vault account already reserves the full
    /// auction region (1 + 18 bytes, zeroed when `None`), so the
    /// terms are written in place — no realloc needed in the real
    /// build. Emits no event (pre-fund configuration, like
    /// `initialize_vesting`).
    pub fn initialize_dutch_auction(
        ctx: Context<InitializeDutchAuction>,
        start_at: u64,
        end_at: u64,
        reserve_bps: u16,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_dutch_auction(start_at, end_at, reserve_bps)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Declare the Token-2022 transfer-hook program this escrow's
    /// token transfers execute under (AV-99; mirrors
    /// `Escrow::with_transfer_hook`). `Uninitialized` only, like
    /// `initialize_mint`: the hook binding is fixed before funds
    /// move. Must come after `initialize_mint` bound a mint — a
    /// transfer hook is a Token-2022 concept, meaningless on the
    /// native-SOL path (`InvalidTransferHook`, code 157, when no mint
    /// is bound); the zero program id is likewise rejected. After
    /// this, the CPI settlement builders
    /// (`escrow_state::cpi::payout_plan` and siblings) require the
    /// caller's hook context to name exactly this program
    /// (`SettlementMismatch` otherwise) and annotate the plan with
    /// the hook's extra accounts. The vault account already reserves
    /// the full hook region (33 bytes, zeroed when `None`), so the
    /// binding is written in place — no realloc needed in the real
    /// build. Emits no event (pre-fund configuration, like
    /// `initialize_mint`).
    pub fn initialize_transfer_hook(
        ctx: Context<InitializeTransferHook>,
        program_id: [u8; 32],
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_transfer_hook(program_id)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Opt in to a streaming fee on funded time (AV-100; mirrors
    /// `Escrow::with_streaming_fee`). `Uninitialized` only, like
    /// `initialize_transfer_hook`: the rate is fixed before funds
    /// move. Any u64 rate is legal (`0` disables the fee). After
    /// this, every taker payout deducts the newly accrued slice
    /// (`rate * (accrue_upto - fund_at) - streaming_fees_accrued`,
    /// saturating, capped at the payout's post-bps-fee remainder)
    /// into the fee leg, folding into the returned `fee` alongside
    /// the AV-17 bps fee; accrual freezes at `disputed_at` once
    /// disputed. The vault account already reserves the 16-byte
    /// region (zeroed when no fee is configured), so the rate is
    /// written in place — no realloc needed in the real build.
    /// Emits no event (pre-fund configuration, like
    /// `initialize_transfer_hook`).
    pub fn initialize_streaming_fee(ctx: Context<InitializeStreamingFee>, rate: u64) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_streaming_fee(rate)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Opt the vault into interest-bearing escrow (AV-107; mirrors
    /// `Escrow::with_interest`). Uninitialized-only, initializer-only.
    /// `rate_bps` is the annual rate in basis points (0–10000) on the
    /// locked principal; above 10000 is `InvalidInterestRate` (code
    /// 165). The 26-byte tail region is already reserved in the vault
    /// account (zeroed when no interest is configured), so the rate
    /// is written in place — no realloc needed in the real build.
    /// Emits no event (pre-fund configuration, like
    /// `initialize_streaming_fee`).
    pub fn initialize_interest(
        ctx: Context<InitializeInterest>,
        rate_bps: u16,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_interest(rate_bps)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Opt in to compound-interest mode (AV-117; mirrors
    /// `Escrow::with_compound_interest`). `Uninitialized` only, like
    /// `initialize_interest`. After this, the accrued yield compounds
    /// into the principal at every claim/settlement instead of being
    /// paid out as a separate yield leg — and the standalone
    /// `claim_interest` harvest is refused (`CompoundInterestActive`,
    /// code 178). Inert while no interest rate is configured.
    pub fn initialize_compound_interest(ctx: Context<InitializeCompoundInterest>) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_compound_interest()
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.compound_interest` is always present (1 byte, zeroed
        // by default), so the flag is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Claim the vested-but-unreleased portion (AV-13; mirrors
    /// `Escrow::claim`). Only the taker may call this; `now` comes from
    /// the Solana clock sysvar (never an instruction param — a
    /// caller-supplied timestamp would let anyone fast-forward the unlock
    /// curve). Returns `(taker_payout, fee)` so the real build can size
    /// the taker's transfer and the protocol fee (AV-17). The AV-04
    /// quorum gate applies exactly as for `release`. AV-16: the vault
    /// token account's mint must equal the bound `vault.mint`
    /// (`MintMismatch` otherwise); `None` on the native-SOL path (no
    /// mint bound).
    pub fn claim(ctx: Context<Claim>) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        // AV-116: the slot-based relative timelock gates the payout on
        // the clock sysvar's slot — never an instruction param, same
        // rule as the AV-27 gate. Evaluated before the AV-113
        // price-gate routing so the two gates compose; a no-op when no
        // slot lock is configured.
        let slot = Clock::get()?.slot;
        if !escrow.is_slot_unlock_eligible(slot) {
            return Err(escrow_error(escrow_state::EscrowError::TimelockNotReached));
        }
        // AV-121: the per-taker claim cooldown gates the payout on
        // the clock sysvar's slot — never an instruction param, same
        // rule as the AV-116 slot lock. Evaluated after the
        // slot-timelock gate so the two gates compose; a no-op when
        // no cooldown is configured, and the taker's first claim is
        // always eligible.
        if !escrow.is_claim_cooldown_eligible(slot) {
            return Err(escrow_error(escrow_state::EscrowError::InvalidClaimCooldown));
        }
        // AV-128: like `release` — a configured TWAP gate routes the
        // taker's pull through the twap-gated entry point, fed by the
        // oracle account's quote history (see `read_oracle_history`).
        // The TWAP gate takes precedence over the AV-113 price gate.
        // AV-113: like `release` — a configured price gate routes the
        // taker's pull through the gated entry point, fed by the
        // oracle account's quote (see `read_oracle_quote`).
        let (payout, fee) = if escrow.twap_gate().is_some() {
            let quote = read_oracle_quote(ctx.remaining_accounts)?;
            let history = read_oracle_history(ctx.remaining_accounts)?;
            let feed = TwapFeed { quote, history };
            let slot = Clock::get()?.slot;
            escrow
                .claim_twap_gated(
                    ctx.accounts.taker.key().to_bytes(),
                    now,
                    slot,
                    vault_token_mint(&ctx.accounts.vault_token_account),
                    ctx.accounts.payout_to.key().to_bytes(),
                    &feed,
                )
                .map_err(|e| escrow_error(e))?
        } else if escrow.price_gate().is_some() {
            let quote = read_oracle_quote(ctx.remaining_accounts)?;
            let feed = QuoteFeed(quote);
            escrow
                .claim_price_gated(
                    ctx.accounts.taker.key().to_bytes(),
                    now,
                    vault_token_mint(&ctx.accounts.vault_token_account),
                    ctx.accounts.payout_to.key().to_bytes(),
                    &feed,
                )
                .map_err(|e| escrow_error(e))?
        } else {
            escrow
                .claim(
                    ctx.accounts.taker.key().to_bytes(),
                    now,
                    vault_token_mint(&ctx.accounts.vault_token_account),
                    ctx.accounts.payout_to.key().to_bytes(),
                )
                .map_err(|e| escrow_error(e))?
        };
        // AV-121: anchor the cooldown window at this claim's slot —
        // the next claim is eligible at `slot +
        // claim_cooldown_slots`. Written in place (`vault.last_claim_slot`
        // is always present, 9 bytes, `None`-zeroed by default).
        escrow.record_claim_slot(slot);
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_payout` (`PayoutKind::Claim`) —
        // see `release`: `escrow_state::cpi::payout_plan` builds and
        // validates the transfer bytes, the real build executes them.
        // AV-18: `payout + fee` is the gross claimable; `now` doubles as
        // the event's `at`, mirroring `IndexedEscrow::claim`.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Claimed,
            from,
            escrow.state() as u8,
            payout + fee,
            fee,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok((payout, fee))
    }

    /// The taker declines the escrow before any claim (AV-122;
    /// mirrors `Escrow::decline_escrow`). Taker-only; `now` comes
    /// from the Solana clock sysvar (never an instruction param).
    /// Moves to Declined (terminal for fund movements — only
    /// `close_vault` retires the vault) and resets the deadman clock.
    pub fn decline_escrow(ctx: Context<DeclineEscrow>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        escrow
            .decline_escrow(ctx.accounts.taker.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::decline_escrow`.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Declined,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// The taker proposes a counter-offer: new amount + expiry terms
    /// (AV-122; mirrors `Escrow::propose_counter_offer`). Taker-only;
    /// `now` comes from the Solana clock sysvar (never an instruction
    /// param). Stores the offer and moves to CounterOffered (fund
    /// movements frozen until the initializer answers); resets the
    /// deadman clock.
    pub fn propose_counter_offer(
        ctx: Context<ProposeCounterOffer>,
        amount: u64,
        expiry: u64,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        escrow
            .propose_counter_offer(
                ctx.accounts.taker.key().to_bytes(),
                amount,
                expiry,
                now,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::propose_counter_offer` (the proposed amount
        // rides `amounts.payout`).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::CounterOfferProposed,
            from,
            escrow.state() as u8,
            amount,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// The initializer accepts the taker's live counter-offer (AV-122;
    /// mirrors `Escrow::accept_counter_offer`). `now` comes from the
    /// Solana clock sysvar (never an instruction param). Atomically
    /// re-sets amount/expiry to the offered terms and returns to
    /// Funded; resets the deadman clock.
    pub fn accept_counter_offer(ctx: Context<AcceptCounterOffer>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        escrow
            .accept_counter_offer(ctx.accounts.initializer.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::accept_counter_offer`.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::CounterOfferAccepted,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// The initializer rejects the taker's live counter-offer
    /// (AV-122; mirrors `Escrow::reject_counter_offer`). `now` comes
    /// from the Solana clock sysvar (never an instruction param).
    /// Drops the offer, terms unchanged, returns to Funded; resets
    /// the deadman clock.
    pub fn reject_counter_offer(ctx: Context<RejectCounterOffer>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        escrow
            .reject_counter_offer(ctx.accounts.initializer.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::reject_counter_offer`.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::CounterOfferRejected,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }
    /// (AV-107; mirrors `Escrow::claim_interest`). Taker-only; `now`
    /// comes from the Solana clock sysvar (never an instruction param
    /// — a caller-supplied timestamp would let anyone fast-forward
    /// the yield clock). Returns the interest paid so the real build
    /// can size the taker's yield transfer. No rate configured is
    /// `InterestNotEnabled` (code 166). The yield always routes to the
    /// taker — there is no destination param to redirect, so the
    /// AV-49 allowlist has nothing to pin (unlike `claim`, whose
    /// `payout_to` is caller-chosen). `vault.interest_paid`
    /// accumulates the payout in place; the real build funds the
    /// transfer from the vault's yield holdings.
    pub fn claim_interest(ctx: Context<ClaimInterest>) -> Result<u64> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let paid = escrow
            .claim_interest(ctx.accounts.taker.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(paid)
    }

    /// Declare the multi-recipient payout-split table (AV-108; mirrors
    /// `Escrow::with_payout_split`). `Uninitialized` only, like
    /// `initialize_interest`: the distribution is fixed before funds
    /// move. Takes 1–8 `(recipient, amount)` shares; empty / over-8 /
    /// zero-address / duplicate-recipient / zero-share input, or a
    /// share Σ != the escrow amount, is `InvalidPayoutSplit` (code
    /// 167). The vault account already reserves the full 321-byte
    /// split tail (1-byte live count + eight 32-byte recipient slots
    /// + eight 8-byte share slots, zeroed when unconfigured), so the
    /// table is written in place — no realloc needed in the real
    /// build. Emits no event (pre-fund configuration).
    pub fn initialize_payout_split(
        ctx: Context<InitializePayoutSplit>,
        shares: Vec<PayoutSplitShare>,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let table: Vec<([u8; 32], u64)> = shares
            .iter()
            .map(|s| (s.recipient, s.amount))
            .collect();
        let escrow = escrow
            .with_payout_split(&table)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Opt in to the dead-man's switch (AV-109; mirrors
    /// `Escrow::with_deadman_switch`). `Uninitialized` only, like
    /// `initialize_payout_split`: the inactivity threshold and the
    /// heir are fixed before funds move. `inactivity_secs == 0` or a
    /// zero heir address is `InvalidDeadmanConfig` (code 168). The
    /// vault account already reserves the full 49-byte deadman tail
    /// (8-byte threshold + 33-byte `Option<Pubkey>` heir + 8-byte
    /// activity clock, zeroed when unconfigured), so the config is
    /// written in place — no realloc needed in the real build. Emits
    /// no event (pre-fund configuration).
    pub fn initialize_deadman_switch(
        ctx: Context<InitializeDeadmanSwitch>,
        inactivity_secs: u64,
        heir: Pubkey,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_deadman_switch(inactivity_secs, heir.to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Settle the full lockup across the declared split recipients
    /// (AV-108; mirrors `Escrow::release_payout_split`). The
    /// initializer (or their RELEASE-scoped operator, AV-104) calls
    /// with the clock sysvar; `now` is never an instruction param.
    /// Reuses the exact `release` check order (pause → reentrancy →
    /// scoped authority → Funded → swap-link → mint → per-recipient
    /// payout-policy pin → milestones/subscription → quorum →
    /// timelock) and splits the post-fee net per leg as
    /// `floor(share_i * net / amount)` with the rounding dust on the
    /// first recipient. Returns the per-recipient `(recipient,
    /// net_payout)` legs so the real build can size each transfer and
    /// the protocol fee (AV-17). No table configured is
    /// `InvalidPayoutSplit` (code 167). The per-leg transfers ride
    /// `remaining_accounts` in table order (like `ReleaseSplit`'s leg
    /// wiring); the real build executes them via
    /// `escrow_state::cpi::payout_plan` per leg.
    pub fn release_payout_split(ctx: Context<ReleasePayoutSplit>) -> Result<Vec<([u8; 32], u64)>> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        let legs = escrow
            .release_payout_split(
                ctx.accounts.authority.key().to_bytes(),
                now,
                vault_token_mint(&ctx.accounts.vault_token_account),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::ReleasedSplit,
            from,
            escrow.state() as u8,
            escrow.released_amount(),
            escrow.fees_paid(),
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(legs)
    }

    /// Claim the remaining locked funds via the dead-man's switch
    /// (AV-109; mirrors `Escrow::claim_deadman`). The configured heir
    /// — and only the heir — calls with the clock sysvar; `now` is
    /// never an instruction param. `Funded -> Cancelled`: the full
    /// remaining locked amount routes to the heir. The heir is
    /// deliberately not required to be either party (the
    /// orthogonality point with `cancel_expired`, where either party
    /// may cancel on the absolute `expires_at` clock). Unconfigured
    /// switch is `InvalidDeadmanConfig` (code 168); the inactivity
    /// gate not yet lapsed is `DeadmanNotElapsed` (code 169). The
    /// outstanding unsettled interest claim is voided like `cancel`.
    /// Returns the heir's payout so the real build can size the
    /// transfer.
    pub fn claim_deadman(ctx: Context<ClaimDeadman>) -> Result<u64> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        let heir_payout = escrow
            .claim_deadman(ctx.accounts.heir.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`; `refund` carries
        // the heir's payout (the Cancelled shape — the heir is the
        // refund sink here, not the initializer); `caller` is the
        // heir.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::DeadmanClaimed,
            from,
            escrow.state() as u8,
            0,
            0,
            heir_payout,
            now,
            None,
            None,
            None,
            None,
            Some(ctx.accounts.heir.key()),
        );
        Ok(heir_payout)
    }

    /// Top up the vault account's lamport balance so it stays
    /// rent-exempt (AV-110; mirrors `Escrow::top_up_rent`).
    /// Permissionless: the initializer, the taker, the keeper bot or a
    /// stranger may call — the state machine takes the caller only as
    /// the event actor and runs no authority check. Any state except
    /// `Closed` (`InvalidStateTransition` on a closed vault); `lamports
    /// == 0` is `InvalidRentTopUp` (code 170). The state byte is
    /// untouched and the amount conservation identity is untouched —
    /// the real build transfers `lamports` from the caller's wallet
    /// into the vault account alongside the state-machine call; the
    /// `rent_topped_up_total` counter is the on-chain receipt.
    pub fn top_up_rent(ctx: Context<TopUpRent>, lamports: u64) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        escrow
            .top_up_rent(ctx.accounts.caller.key().to_bytes(), lamports)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`; the on-chain event
        // shape carries no rent leg (payout/fee/refund stay zero) —
        // the topped-up lamports are visible in the vault account's
        // lamport balance and the `rent_topped_up_total` counter, and
        // the off-chain `IndexedEscrow` event rides them in its
        // `rent_reclaimed` amount field. `caller` is the topping-up
        // key.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::RentToppedUp,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            Some(ctx.accounts.caller.key()),
        );
        Ok(())
    }

    /// Opt in to tranched funding (AV-111; mirrors
    /// `Escrow::with_funding_plan`). `Uninitialized` only, like the
    /// other `initialize_*` opt-ins: the funding schedule is fixed
    /// before any funds move. `total_amount` must be positive and
    /// equal the escrow's declared amount (`AmountMismatch`
    /// otherwise); `max_tranches` must be at least 1
    /// (`InvalidFundingPlan`, code 173, on zero). Attaching the plan
    /// moves the deposit path from `fund` to `fund_tranche`.
    pub fn initialize_funding_plan(
        ctx: Context<InitializeFundingPlan>,
        total_amount: u64,
        max_tranches: u8,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        escrow
            .with_funding_plan(total_amount, max_tranches)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // No indexer event: pre-fund configuration, like the other
        // `initialize_*` opt-ins.
        Ok(())
    }

    /// Deposit one funding tranche (AV-111; mirrors
    /// `Escrow::fund_tranche`). The initializer or their FUND-scoped
    /// operator (AV-104 delegation) calls this up to `max_tranches`
    /// times; each call accumulates `tranche_amount` into
    /// `funded_total` and consumes one tranche slot. Full check
    /// sequence — pause → reentrancy → FUND-scoped authority → plan
    /// presence (`InvalidFundingPlan`, code 173, when no plan is
    /// attached) → state → positive amount → tranche budget
    /// (`FundingTranchesExhausted`, code 172) → overfund cap
    /// (`AmountMismatch`). The first call moves `Uninitialized` →
    /// `Funded` (`Activated` → `Funded` for dual-sig) and anchors the
    /// clocks exactly like `fund`.
    pub fn fund_tranche(ctx: Context<FundTranche>, tranche_amount: u64) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        escrow
            .fund_tranche(
                ctx.accounts.authority.key().to_bytes(),
                tranche_amount,
                now,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`; the on-chain event
        // carries no amount leg — the tranche is the fold seed's
        // inflow leg, so the fold seeds the lockup with the deal size
        // at `Funded` (the off-chain `IndexedEscrow` event carries
        // `EventAmounts::none`, exactly like `Funded` itself).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::TrancheFunded,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            Some(ctx.accounts.authority.key()),
        );
        Ok(())
    }

    /// Opt in to a release cooling period (AV-112; mirrors
    /// `Escrow::with_release_cooling`). `Uninitialized` only, like the
    /// other `initialize_*` opt-ins: the window is fixed before any
    /// funds move. `cooling_secs == 0` means no cooling (unconfigured,
    /// backward compatible); any other value arms the announce ->
    /// wait -> release flow (`release` then needs a live announced
    /// intent whose window has elapsed).
    pub fn initialize_release_cooling(
        ctx: Context<InitializeReleaseCooling>,
        cooling_secs: u64,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        escrow
            .with_release_cooling(cooling_secs)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // No indexer event: pre-fund configuration, like the other
        // `initialize_*` opt-ins.
        Ok(())
    }

    /// Announce a release intent (AV-112; mirrors
    /// `Escrow::announce_release`). Either party (the initializer or
    /// the taker — a stranger or an AV-104 operator is `Unauthorized`)
    /// records `release_intent_at = now`, starting the cooling window;
    /// `release` then requires `now >= intent_at + cooling_secs`.
    /// Re-announcing overwrites the timestamp (idempotent — the window
    /// restarts) and resets the AV-109 dead-man's switch activity
    /// clock.
    pub fn announce_release(ctx: Context<AnnounceRelease>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        let before = escrow.release_intent_at();
        escrow
            .announce_release(ctx.accounts.authority.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Emit only on an actual change — a same-timestamp re-announce
        // is a silent idempotent no-op (mirrors the off-chain
        // `IndexedEscrow` wrapper).
        if escrow.release_intent_at() != before {
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::ReleaseIntentAnnounced,
                from,
                escrow.state() as u8,
                0,
                0,
                0,
                now,
                None,
                None,
                None,
                None,
                Some(ctx.accounts.authority.key()),
            );
        }
        Ok(())
    }

    /// Veto a live release intent (AV-112; mirrors
    /// `Escrow::veto_release`). Either party (the initializer or the
    /// taker) clears `release_intent_at`, cancelling the announced
    /// release — after a veto, `release` is `ReleaseCoolingNotElapsed`
    /// again until a fresh `announce_release` restarts the window. No
    /// live intent is a no-op success (nothing cleared, nothing
    /// emitted).
    pub fn veto_release(ctx: Context<VetoRelease>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        let had_intent = escrow.release_intent_at().is_some();
        escrow
            .veto_release(ctx.accounts.authority.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Emit only when an intent was actually cleared — the
        // no-intent no-op stays silent (mirrors the off-chain
        // `IndexedEscrow` wrapper).
        if had_intent {
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::ReleaseIntentVetoed,
                from,
                escrow.state() as u8,
                0,
                0,
                0,
                now,
                None,
                None,
                None,
                None,
                Some(ctx.accounts.authority.key()),
            );
        }
        Ok(())
    }

    /// Attach an oracle price gate (AV-113; mirrors
    /// `Escrow::with_price_gate`). `Uninitialized` only — the market
    /// condition is fixed before any funds move, like the other
    /// `initialize_*` opt-ins. `target == 0` is `InvalidPriceGate`
    /// (code 176): a zero threshold is never a deliberate policy.
    /// Once configured, `release` / `claim` route to the gated entry
    /// points and require the oracle account's quote (see
    /// `read_oracle_quote`).
    pub fn initialize_price_gate(
        ctx: Context<InitializePriceGate>,
        direction: u8,
        target: u64,
        max_staleness_secs: u64,
    ) -> Result<()> {
        let direction = match direction {
            0 => escrow_state::PriceDirection::AtOrAbove,
            1 => escrow_state::PriceDirection::AtOrBelow,
            _ => {
                return Err(escrow_error(
                    escrow_state::EscrowError::InvalidPriceGate,
                ))
            }
        };
        let mut escrow = read_escrow(&ctx.accounts.vault);
        escrow
            .with_price_gate(escrow_state::PriceGate {
                direction,
                target,
                max_staleness_secs,
            })
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // No indexer event: pre-fund configuration, like the other
        // `initialize_*` opt-ins.
        Ok(())
    }

    /// Attach a TWAP price gate (AV-128; mirrors
    /// `Escrow::with_twap_gate`). `Uninitialized` only — the window,
    /// target and direction are fixed before any funds move, like the
    /// other `initialize_*` opt-ins. `window_slots == 0` or `target ==
    /// 0` is `InvalidTwapGate` (code 187): a zero window is a
    /// single-point gate in disguise, and a zero threshold is never a
    /// deliberate policy. Once configured, `release` / `claim` route
    /// to the twap-gated entry points and require the oracle account's
    /// quote history (see `read_oracle_history`).
    pub fn initialize_twap_gate(
        ctx: Context<InitializeTwapGate>,
        window_slots: u64,
        target: u64,
        direction: u8,
        max_staleness_secs: u64,
    ) -> Result<()> {
        let direction = match direction {
            0 => escrow_state::PriceDirection::AtOrAbove,
            1 => escrow_state::PriceDirection::AtOrBelow,
            _ => {
                return Err(escrow_error(
                    escrow_state::EscrowError::InvalidTwapGate,
                ))
            }
        };
        let mut escrow = read_escrow(&ctx.accounts.vault);
        escrow
            .with_twap_gate_and_staleness(
                window_slots,
                target,
                direction,
                max_staleness_secs,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // No indexer event: pre-fund configuration, like the other
        // `initialize_*` opt-ins.
        Ok(())
    }

    /// Opt into dual-control (maker-checker) release governance
    /// (AV-130; mirrors `Escrow::with_dual_control`). The initializer
    /// binds the checker's key while the escrow is `Uninitialized` —
    /// the checker's identity is fixed before any funds move, like
    /// the other `initialize_*` opt-ins. A zero `checker` key is
    /// `InvalidDualControl` (code 188); re-configuring a live escrow
    /// is `InvalidStateTransition`; a paused escrow fails fast
    /// (`Paused`). Once set, direct `release` (and every path routed
    /// through it) becomes `DualControlRequired` (code 192) — payouts
    /// leave only via the two-step `initiate_release` +
    /// `confirm_release` protocol.
    pub fn initialize_dual_control(
        ctx: Context<InitializeDualControl>,
        checker: Pubkey,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_dual_control(checker.to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full dual-control
        // region (`escrow_state::DUAL_CONTROL_TAIL_LEN`), so the
        // checker key is written in place — no realloc needed in the
        // real build. No indexer event: pre-fund configuration, like
        // the other `initialize_*` opt-ins.
        Ok(())
    }

    /// Fix the funding amount window (AV-134; mirrors
    /// `Escrow::with_amount_bounds`). The initializer bounds every
    /// deposit: `fund` and each `fund_tranche` call reject amounts
    /// outside `[min_amount, max_amount]` with `AmountOutOfBounds`
    /// (code 197); `min_amount > max_amount` is `InvalidAmountBounds`
    /// (code 196).
    pub fn initialize_amount_bounds(
        ctx: Context<InitializeAmountBounds>,
        min_amount: u64,
        max_amount: u64,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_amount_bounds(min_amount, max_amount)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full amount-bounds
        // region (`escrow_state::AMOUNT_BOUNDS_TAIL_LEN`), so the
        // bounds are written in place — no realloc needed in the real
        // build. No indexer event: pre-fund configuration, like the
        // other `initialize_*` opt-ins.
        Ok(())
    }

    /// Fix the arbiter adjudication fee (AV-135; mirrors
    /// `Escrow::with_arbiter_fee`). The initializer prices the
    /// arbitration up front: every dispute settlement (`resolve`,
    /// the panel's settling vote, `trigger_default_judgment`)
    /// deducts `flat_lamports` plus `floor(net_share * fee_bps /
    /// 10_000)` from the taker's adjudicated share (deduction order:
    /// AV-17 protocol fee, AV-100 streaming fee, AV-135 arbiter fee)
    /// and routes the fee to the arbiter; the initializer's refund is
    /// never fee'd. `fee_bps > 10_000` is `InvalidArbiterFee` (code
    /// 198); `(0, 0)` disables the fee (backward compatible).
    pub fn initialize_arbiter_fee(
        ctx: Context<InitializeArbiterFee>,
        flat_lamports: u64,
        fee_bps: u16,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_arbiter_fee(flat_lamports, fee_bps)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full arbiter-fee
        // region (`escrow_state::ARBITER_FEE_TAIL_LEN`), so the fee
        // terms are written in place — no realloc needed in the real
        // build. No indexer event: pre-fund configuration, like the
        // other `initialize_*` opt-ins.
        Ok(())
    }

    /// Declare a release for checker approval (AV-130; mirrors
    /// `Escrow::initiate_release` — the *maker* half of the
    /// maker-checker protocol). The initializer (or their
    /// `RELEASE`-scoped operator) freezes the exact payout
    /// `{amount, mint, payout_to}` plus the declaration clock into the
    /// vault; the escrow state stays `Funded`. Check order is pause →
    /// reentrancy → dual-control configured (`InvalidDualControl`,
    /// code 188) → authority (`Unauthorized`) → state (`Funded` only)
    /// → no live intent (`DualControlIntentExists`, code 189) →
    /// declaration shape (`amount == 0`, `intent_ttl_secs == 0`, or an
    /// overflowing `intent_expires_at` is `InvalidDualControl`, code
    /// 188). The checker settles the declaration with
    /// `confirm_release`; either party aborts it with
    /// `cancel_release`.
    pub fn initiate_release(
        ctx: Context<InitiateRelease>,
        amount: u64,
        mint: Option<Pubkey>,
        payout_to: Pubkey,
        intent_ttl_secs: u64,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-27: the declaration clock reads the Solana clock sysvar —
        // never an instruction param, so the maker cannot fast-forward
        // the declaration's life.
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        escrow
            .initiate_release(
                ctx.accounts.authority.key().to_bytes(),
                now,
                amount,
                mint.map(|m| m.to_bytes()),
                payout_to.to_bytes(),
                intent_ttl_secs,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `from == to ==` the current state — the declaration
        // is a pending intent, not a lifecycle move; the event carries
        // no amounts (the declaration moves no funds).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::DualControlInitiated,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Approve the live dual-control declaration and settle it
    /// (AV-130; mirrors `Escrow::confirm_release` — the *checker* half
    /// of the maker-checker protocol). `ctx.accounts.checker` must
    /// equal the bound checker key (`Unauthorized` otherwise — the
    /// maker cannot self-approve, and neither can a stranger); a stale
    /// declaration (`now >= intent_expires_at`) is cleared and the
    /// call fails with `DualControlExpired` (code 191). The frozen
    /// `{amount, mint, payout_to}` then settles through the exact
    /// `release` settlement engine with the authority pinned to the
    /// initializer (the AV-123 `release_via_intent` precedent) — a
    /// checker-approved release moves funds bit-identically to a
    /// direct one. Returns `(taker_payout, fee)` so the real build can
    /// size both transfers.
    pub fn confirm_release(ctx: Context<ConfirmRelease>) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-27: the freshness clock reads the Solana clock sysvar —
        // never an instruction param, so the checker cannot
        // fast-forward the declaration's life.
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let (payout, fee) = escrow
            .confirm_release(ctx.accounts.checker.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_payout` (`PayoutKind::Release`) —
        // the transfer instruction bytes are built and validated by
        // `escrow_state::cpi::payout_plan`; the real build executes the
        // validated plan once the token accounts are wired up. AV-18:
        // `payout + fee` is the gross declared amount; a partial
        // declaration carries from == to == Funded, the closing one to
        // == Released.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::DualControlConfirmed,
            from,
            escrow.state() as u8,
            payout + fee,
            fee,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok((payout, fee))
    }

    /// Abort the live dual-control declaration (AV-130; mirrors
    /// `Escrow::cancel_release`). Either the initializer (the maker —
    /// retracting their own declaration) or the bound checker
    /// (refusing to approve it) may cancel; a stranger is
    /// `Unauthorized`. `DualControlNotInitiated` (code 190) when no
    /// declaration is live. Cancelling clears the intent and moves no
    /// funds; the escrow stays `Funded`.
    pub fn cancel_release(ctx: Context<CancelRelease>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        escrow
            .cancel_release(ctx.accounts.caller.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `from == to ==` the current state; the abort moves no
        // funds — the AV-112 `ReleaseIntentVetoed` shape.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::DualControlCancelled,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }
    /// `Escrow::merge_escrows`). Both vaults must be `Funded` with the
    /// same parties and identical settlement terms
    /// (`MergeIncompatible`, code 177, otherwise); only the
    /// initializer may merge (`Unauthorized` otherwise). The target
    /// absorbs the source's locked amount (u128-checked); the source
    /// vault moves to `Cancelled` with `released := amount`. Emits
    /// `EscrowsMerged` on the target vault and `Cancelled` on the
    /// source vault, mirroring the off-chain `IndexedEscrow` wrapper.
    pub fn merge_escrows(ctx: Context<MergeEscrows>) -> Result<()> {
        let mut target = read_escrow(&ctx.accounts.vault);
        let mut source = read_escrow(&ctx.accounts.source_vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let authority = ctx.accounts.authority.key().to_bytes();
        // The survivor's lockup grows by the source's pre-merge
        // remainder (not the deal size — see the off-chain
        // `IndexedEscrow::merge_escrows`).
        let merged_in = source.remaining_amount();
        let source_from = source.state() as u8;
        target
            .merge_escrows(&mut source, authority)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &target);
        write_escrow(&mut ctx.accounts.source_vault, &source);
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::EscrowsMerged,
            escrow_state::EscrowState::Funded as u8,
            escrow_state::EscrowState::Funded as u8,
            merged_in,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            Some(ctx.accounts.authority.key()),
        );
        emit_transition(
            &ctx.accounts.source_vault,
            escrow_state::EscrowEventKind::Cancelled,
            source_from,
            escrow_state::EscrowState::Cancelled as u8,
            0,
            0,
            source.remaining_amount(),
            now,
            None,
            None,
            None,
            None,
            Some(ctx.accounts.authority.key()),
        );
        Ok(())
    }

    /// Opt in to dispute arbitration (AV-14; mirrors
    /// `Escrow::with_arbiter`). `Uninitialized` only, like
    /// `initialize_quorum`: the arbiter's identity is fixed before funds
    /// move. The zero key is `InvalidArbiter` — the arbiter must be a real
    /// identity, since `resolve` authenticates against it.
    pub fn initialize_arbiter(ctx: Context<InitializeArbiter>, arbiter: Pubkey) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_arbiter(arbiter.to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full arbiter region
        // (33 bytes, zeroed when `None`), so the key is written in place
        // — no realloc needed in the real build.
        Ok(())
    }

    /// Opt in to the arbiter-panel multisig judgment (AV-65; mirrors
    /// `Escrow::with_arbiter_panel`): replace the single dispute
    /// arbiter with an N-member panel and an M-vote judgment threshold.
    /// `Uninitialized` only, like `initialize_arbiter`: the committee
    /// is fixed before funds move. Mutually exclusive with the single
    /// arbiter — last-wins in both directions: configuring the panel
    /// clears any single arbiter set earlier, and a later
    /// `initialize_arbiter` clears the panel. Empty / over-long /
    /// zero-address / duplicate member input, a zero threshold, or a
    /// threshold above the member count is `InvalidArbiterPanel` (code
    /// 136). The vault account already reserves the full 595-byte panel
    /// region (1-byte discriminant + 594-byte panel, zeroed when
    /// `None`), so the committee is written in place — no realloc
    /// needed in the real build. Emits no event (pre-fund
    /// configuration).
    pub fn initialize_arbiter_panel(
        ctx: Context<InitializeArbiterPanel>,
        members: Vec<Pubkey>,
        threshold: u8,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let member_keys: Vec<[u8; 32]> = members.iter().map(|m| m.to_bytes()).collect();
        let escrow = escrow
            .with_arbiter_panel(&member_keys, threshold)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Opt in to blind (commit-reveal) panel voting (AV-137; mirrors
    /// `Escrow::with_blind_panel`): the panel tallies judgments exactly
    /// like `initialize_arbiter_panel`, except members vote in two
    /// phases — `submit_judgment_commit`, then `reveal_judgment` inside
    /// their reveal window — so no member can front-run or herd on a
    /// visible vote. `Uninitialized` only; mutually exclusive with the
    /// single arbiter (last-wins). `reveal_window_secs` must be
    /// non-zero (`InvalidArbiterPanel` otherwise).
    pub fn initialize_blind_panel(
        ctx: Context<InitializeBlindPanel>,
        members: Vec<Pubkey>,
        threshold: u8,
        reveal_window_secs: u64,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let member_keys: Vec<[u8; 32]> = members.iter().map(|m| m.to_bytes()).collect();
        let escrow = escrow
            .with_blind_panel(&member_keys, threshold, reveal_window_secs)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full 995-byte panel
        // region (zeroed when `None`), so the opt-in writes in place —
        // no realloc needed in the real build.
        Ok(())
    }

    /// Escalate the escrow into arbitration (AV-14; mirrors
    /// `Escrow::escalate`): `Funded -> Disputed`. Either the initializer
    /// or the taker signs; `now` comes from the Solana clock sysvar (never
    /// an instruction param — a caller-supplied timestamp could rewind
    /// past the dispute window). While `Disputed`, every unilateral exit
    /// (`release` / `cancel` / `cancel_expired` / `claim`) is locked.
    /// AV-22: `evidence_hash` is the optional 32-byte commitment to the
    /// off-chain dispute evidence (e.g. the SHA-256 of an IPFS CID),
    /// persisted on the vault so the arbiter and indexers can read it.
    /// AV-91: `evidence_root` is the optional SHA-256 Merkle root over
    /// the dispute-evidence document set (the multi-doc
    /// alternative/supplement to `evidence_hash`), and
    /// `evidence_leaves` is the committed leaf count (`0` when the
    /// root is `None`, `1..=64` otherwise — `InvalidEvidenceProof` on
    /// a count that does not describe the root). Both are persisted
    /// and never cleared; the disclosure bitmap starts zeroed.
    /// AV-131: `dispute_amount` is the contested lamport amount —
    /// `1..=remaining_amount` (`InvalidDisputeAmount` otherwise). While
    /// the vault is `Disputed`, the undisputed remainder stays
    /// releasable/claimable; only the disputed pool is locked, and
    /// `resolve` adjudicates that pool alone.
    pub fn escalate(
        ctx: Context<Escalate>,
        dispute_amount: u64,
        evidence_hash: Option<[u8; 32]>,
        evidence_root: Option<[u8; 32]>,
        evidence_leaves: u8,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        escrow
            .escalate(
                ctx.accounts.authority.key().to_bytes(),
                now,
                dispute_amount,
                evidence_hash,
                evidence_root,
                evidence_leaves,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::escalate`. AV-22: the Escalated event carries
        // the attached evidence hash. AV-91: it also carries the
        // committed Merkle root (stamped from the vault).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Escalated,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            evidence_hash,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Disclose one dispute-evidence document against the committed
    /// Merkle root (AV-91; mirrors `Escrow::file_evidence`). The
    /// escalating party reveals `doc_hash` at `leaf_index` together
    /// with the Merkle inclusion `proof`; the vault flips that leaf's
    /// bit in the disclosure bitmap. `now` comes from the clock sysvar
    /// (the AV-68 disclosure deadline is measured against chain time).
    /// Emits the `EvidenceFiled` indexer event carrying the committed
    /// root. Re-filing a disclosed document is an idempotent no-op.
    pub fn file_evidence(
        ctx: Context<FileEvidence>,
        doc_hash: [u8; 32],
        leaf_index: u8,
        proof: Vec<[u8; 32]>,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        let proof_refs: Vec<[u8; 32]> = proof;
        escrow
            .file_evidence(
                ctx.accounts.authority.key().to_bytes(),
                doc_hash,
                leaf_index,
                &proof_refs,
                now,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::file_evidence`. The EvidenceFiled event
        // carries the committed root (stamped from the vault).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::EvidenceFiled,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Disclose (or replace) the dispute-evidence commitment while
    /// `Disputed` (AV-68; mirrors `Escrow::submit_evidence`): the
    /// escalating party supplies the 32-byte commitment to the
    /// off-chain evidence, overwriting any previously attached hash.
    /// Only the escalating party signs (`Unauthorized` otherwise);
    /// `Disputed` only (`InvalidStateTransition` otherwise); at or
    /// past the disclosure deadline the submission is rejected
    /// (`EvidenceDisclosureLate`, code 139) — the deadline is a hard
    /// bar, so a missed deadline locks in the judgment-time adverse
    /// inference (the settlement events carry `evidence_defaulted`).
    pub fn submit_evidence(ctx: Context<SubmitEvidence>, evidence_hash: [u8; 32]) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        escrow
            .submit_evidence(
                ctx.accounts.authority.key().to_bytes(),
                evidence_hash,
                now,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::submit_evidence`. AV-68: the EvidenceSubmitted
        // event carries the disclosed commitment in its evidence slot.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::EvidenceSubmitted,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            Some(evidence_hash),
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Retune the arbiter panel's judgment threshold by dual-signed
    /// governance (AV-69; mirrors `Escrow::update_panel_threshold`):
    /// the initializer AND the taker jointly set the M-of-N threshold
    /// (1..=N), `Uninitialized` only. The retune rewrites only the
    /// threshold — cast votes and the voted bitmask survive, and
    /// counting continues under the new M. Retuning to the current
    /// threshold is an idempotent no-op (no event). Mirrors
    /// `EscrowEventKind::PanelThresholdChanged`, emitted only on an
    /// actual change.
    pub fn update_panel_threshold(
        ctx: Context<UpdatePanelThreshold>,
        new_threshold: u8,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let threshold_before = escrow.arbiter_panel().map(|p| p.threshold);
        escrow
            .update_panel_threshold(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
                new_threshold,
            )
            .map_err(|e| escrow_error(e))?;
        let threshold_after = escrow.arbiter_panel().map(|p| p.threshold);
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-69: the PanelThresholdChanged event fires only on an
        // actual change, paralleling `rotate_fee_recipient`'s no-op
        // rule; `now` doubles as the event's `at`.
        if threshold_before != threshold_after {
            let now = read_clock_unix_timestamp(&ctx.accounts.clock);
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::PanelThresholdChanged,
                from,
                escrow.state() as u8,
                0,
                0,
                0,
                now,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Settle a disputed escrow (AV-14; mirrors `Escrow::resolve`):
    /// `Disputed -> Settled`. Only the configured arbiter signs;
    /// `taker_amount` is the taker's share of the remaining locked funds
    /// (the initializer is refunded the rest) in one atomic settlement.
    /// Returns `(taker_payout, fee, initializer_refund)` so the real
    /// build can size all three transfers: the protocol fee (AV-17)
    /// slices the taker's share, the refund is never fee'd. The quorum
    /// gate does not apply: the arbiter is the resolution mechanism.
    /// AV-16: the vault token account's mint must equal the bound
    /// `vault.mint` (`MintMismatch` otherwise); `None` on the
    /// native-SOL path (no mint bound).
    /// AV-38: `rationale_hash` is the arbiter's optional 32-byte
    /// commitment to the off-chain rationale document behind the ruling
    /// (e.g. the SHA-256 of the written arbitration report), persisted
    /// on the vault (`vault.rationale_hash`) and carried by the
    /// `Resolved` event; `None` attaches no rationale (backward
    /// compatible). Never cleared — `Settled` keeps it as the audit
    /// trail of the arbitration, following the AV-22 `evidence_hash`
    /// convention.
    /// AV-119: the dispute window `[disputed_at, resolved_at]`
    /// accrues interest on the locked remainder at the AV-107 rate,
    /// and the settlement attributes the whole outstanding yield claim
    /// pro-rata by `taker_amount / remaining` — the taker's share rides
    /// the taker payout (into `interest_paid`), the initializer's share
    /// rides the refund (into `dispute_interest`); `resolved_at` comes
    /// from the clock sysvar (never an instruction param, like
    /// `release_milestone`'s `now`). On a compound-interest escrow the
    /// yield folds into the principal instead (AV-117 mutual
    /// exclusion).
    pub fn resolve(
        ctx: Context<Resolve>,
        taker_amount: u64,
        rationale_hash: Option<[u8; 32]>,
    ) -> Result<(u64, u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-119: the settlement time doubles as the dispute window's
        // end — the clock sysvar, never an instruction param (the
        // `release_milestone` convention). Capture the pre-settlement
        // remainder so the event records the principal legs (the
        // AV-107 convention: the yield legs ride the transfers and stay
        // observable via the `interest_paid` / `dispute_interest`
        // counters and the snapshot).
        let resolved_at = Clock::get()?.unix_timestamp as u64;
        let remaining = escrow.remaining_amount();
        let (payout, fee, refund) = escrow
            .resolve(
                ctx.accounts.arbiter.key().to_bytes(),
                taker_amount,
                resolved_at,
                vault_token_mint(&ctx.accounts.vault_token_account),
                rationale_hash,
                ctx.accounts.payout_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_resolve` —
        // `escrow_state::cpi::resolve_plan` builds and validates the
        // three-leg transfer bytes (taker payout / protocol fee /
        // initializer refund); the real build executes the validated
        // plan once the token accounts are wired up.
        // AV-18: `taker_amount` is the gross taker share
        // (`payout + fee`); the refund is never fee'd.
        // AV-22: the Resolved event carries the dispute evidence hash
        // the escrow still holds — the settlement references the
        // evidence the arbiter reviewed.
        // AV-38: the Resolved event carries the rationale-document
        // commitment the arbiter attached — the settlement references
        // the ruling it wrote.
        // AV-68: the Resolved event carries `evidence_defaulted` when
        // the disclosure deadline lapsed undisclosed — the
        // judgment-time adverse-inference signal favoring the
        // non-escalating party (computed by `emit_transition` from the
        // vault's escrow at emit time).
        // AV-119: the event records the principal legs — the refund leg
        // is the principal refund (the initializer's dispute-interest
        // share rides the transfer, tracked in `dispute_interest`).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Resolved,
            from,
            escrow.state() as u8,
            taker_amount,
            fee,
            remaining.saturating_sub(taker_amount),
            resolved_at,
            escrow.evidence_hash(),
            rationale_hash,
            None,
            None,
            None,
        );
        Ok((payout, fee, refund))
    }

    /// Submit one panel member's judgment (AV-65; mirrors
    /// `Escrow::submit_panel_judgment`): `Disputed -> Disputed` per
    /// vote, `Disputed -> Settled` once the M-th matching vote arrives.
    /// Only a panel member signs — the state machine rejects strangers
    /// with `Unauthorized` and non-`Disputed` escrows with
    /// `InvalidStateTransition`; no panel configured is
    /// `InvalidArbiterPanel` (code 136). Each member holds one effective
    /// vote: re-voting overwrites the previous vote in place (the
    /// overwritten vote stays in the event log as the audit trail).
    /// The first `(taker_amount, rationale_hash)` pair to collect M
    /// matching current votes settles the escrow automatically with
    /// `resolve` semantics (the fee slices the taker's share, the
    /// `released` counter keeps the gross, the initializer's refund is
    /// never fee'd); the settling vote checks the mint and the payout
    /// policy before mutating state, like `resolve`. Returns
    /// `(taker_payout, fee, initializer_refund)` on the settling vote
    /// so the real build can size all three transfers, `None`
    /// otherwise. Emits `PanelJudgment` per submission and
    /// `PanelResolved` on the settling vote (the vote event first, then
    /// the settlement), mirroring
    /// `IndexedEscrow::submit_panel_judgment`.
    pub fn submit_panel_judgment(
        ctx: Context<SubmitPanelJudgment>,
        taker_amount: u64,
        rationale_hash: Option<[u8; 32]>,
    ) -> Result<Option<(u64, u64, u64)>> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::submit_panel_judgment`. AV-119: it also
        // doubles as the settling vote's settlement time — the dispute
        // window accrues to it inside `submit_panel_judgment` (the
        // clock sysvar, never an instruction param). Capture the
        // pre-settlement remainder so the `PanelResolved` event records
        // the principal legs (the AV-107 convention — see `resolve`).
        let now = Clock::get()?.unix_timestamp as u64;
        let remaining = escrow.remaining_amount();
        let settled = escrow
            .submit_panel_judgment(
                ctx.accounts.member.key().to_bytes(),
                taker_amount,
                now,
                vault_token_mint(&ctx.accounts.vault_token_account),
                rationale_hash,
                ctx.accounts.payout_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::submit_panel_judgment`. Every submission
        // emits PanelJudgment (the vote is the audit trail); the
        // settling vote additionally emits PanelResolved with the
        // `Resolved` amounts shape.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::PanelJudgment,
            from,
            escrow.state() as u8,
            taker_amount,
            0,
            0,
            now,
            None,
            rationale_hash,
            None,
            None,
            Some(ctx.accounts.member.key()),
        );
        if let Some((_payout, fee, _refund)) = settled {
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::PanelResolved,
                from,
                escrow.state() as u8,
                taker_amount,
                fee,
                remaining.saturating_sub(taker_amount),
                now,
                escrow.evidence_hash(),
                rationale_hash,
                None,
                None,
                Some(ctx.accounts.member.key()),
            );
        }
        Ok(settled)
    }

    /// Commit one panel member's blind judgment (AV-137; mirrors
    /// `Escrow::submit_judgment_commit`): records the
    /// `SHA-256(taker_amount || rationale_hash || salt)` commitment
    /// without revealing the judgment. `Disputed` only; only a panel
    /// member signs. A zero commitment is `BlindInvalidCommitment`; a
    /// second commit before the reveal overwrites the first
    /// (last-wins, window restarts). Emits `JudgmentCommitted`.
    pub fn submit_judgment_commit(
        ctx: Context<SubmitPanelJudgment>,
        commitment: [u8; 32],
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = Clock::get()?.unix_timestamp as u64;
        let from = escrow.state() as u8;
        escrow
            .submit_judgment_commit(ctx.accounts.member.key().to_bytes(), commitment, now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::submit_judgment_commit`.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::JudgmentCommitted,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            Some(ctx.accounts.member.key()),
        );
        Ok(())
    }

    /// Reveal one panel member's blind judgment (AV-137; mirrors
    /// `Escrow::reveal_judgment`): the recomputed
    /// `SHA-256(taker_amount || rationale_hash || salt)` must match the
    /// stored commitment, then the revealed vote enters the panel tally
    /// exactly like a plain vote — the M-th matching reveal settles
    /// with `resolve` semantics. `now` comes from the Solana clock
    /// sysvar (never an instruction param). Only a panel member signs;
    /// the state machine rejects strangers with `Unauthorized`,
    /// non-`Disputed` escrows with `InvalidStateTransition`, late
    /// reveals with `BlindRevealWindowClosed`, and mismatched preimages
    /// with `BlindCommitMismatch`. Emits `JudgmentRevealed` per reveal
    /// and `PanelResolved` on the settling reveal (mirroring
    /// `IndexedEscrow::reveal_judgment`).
    pub fn reveal_judgment(
        ctx: Context<SubmitPanelJudgment>,
        taker_amount: u64,
        rationale_hash: Option<[u8; 32]>,
        salt: [u8; 32],
    ) -> Result<Option<(u64, u64, u64)>> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::reveal_judgment`. AV-119: it also doubles as
        // the settling reveal's settlement time. Capture the
        // pre-settlement remainder so the `PanelResolved` event records
        // the principal legs (the AV-107 convention — see `resolve`).
        let now = Clock::get()?.unix_timestamp as u64;
        let remaining = escrow.remaining_amount();
        let settled = escrow
            .reveal_judgment(
                ctx.accounts.member.key().to_bytes(),
                taker_amount,
                rationale_hash,
                salt,
                now,
                now,
                vault_token_mint(&ctx.accounts.vault_token_account),
                ctx.accounts.payout_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::JudgmentRevealed,
            from,
            escrow.state() as u8,
            taker_amount,
            0,
            0,
            now,
            None,
            rationale_hash,
            None,
            None,
            Some(ctx.accounts.member.key()),
        );
        if let Some((_payout, fee, _refund)) = settled {
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::PanelResolved,
                from,
                escrow.state() as u8,
                taker_amount,
                fee,
                remaining.saturating_sub(taker_amount),
                now,
                escrow.evidence_hash(),
                rationale_hash,
                None,
                None,
                Some(ctx.accounts.member.key()),
            );
        }
        Ok(settled)
    }

    /// Opt in to the arbitration default judgment (AV-55; mirrors
    /// `Escrow::with_arbitration_deadline`): declare the fallback split
    /// applied when a live dispute outlives its arbitration deadline
    /// and the arbiter never resolves. `Uninitialized` only, like
    /// `initialize_arbiter`: the fallback terms are fixed before funds
    /// move. The arbiter must already be configured (`with_arbiter`
    /// first — `InvalidArbiter` otherwise); the deadline must be
    /// non-zero (`DefaultJudgmentNotDue` otherwise); the taker share
    /// must not exceed the locked amount (`ReleaseExceedsLocked`
    /// otherwise). The initializer proposes the terms here; the taker
    /// must still countersign via `confirm_default_judgment` before the
    /// judgment can ever be triggered.
    pub fn initialize_default_judgment(
        ctx: Context<InitializeDefaultJudgment>,
        deadline_secs: u64,
        default_taker_amount: u64,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_arbitration_deadline(deadline_secs, default_taker_amount)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full default-judgment
        // region (17 bytes, zeroed when `None`), so the judgment is
        // written in place — no realloc needed in the real build.
        Ok(())
    }

    /// The taker countersigns the pre-agreed default judgment (AV-55;
    /// mirrors `Escrow::confirm_default_judgment`), completing the
    /// dual-signed agreement. Only the taker signs — a stranger or the
    /// initializer is `Unauthorized`. `Uninitialized` / `Funded` only;
    /// no judgment configured is `DefaultJudgmentNotDue`; confirming an
    /// already-confirmed judgment is an idempotent no-op.
    pub fn confirm_default_judgment(ctx: Context<ConfirmDefaultJudgment>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        escrow
            .confirm_default_judgment(ctx.accounts.taker.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Trigger the pre-agreed arbitration default judgment (AV-55;
    /// mirrors `Escrow::trigger_default_judgment`): `Disputed ->
    /// Settled`. Either party signs once the dispute has outlived the
    /// arbitration deadline (`now >= disputed_at + deadline_secs`,
    /// `now` from the Solana clock sysvar — never an instruction param);
    /// the escrow settles on the fallback split instead of staying
    /// locked forever. The arbiter's `resolve` is unchanged and keeps
    /// priority — after the deadline either the arbiter resolves or a
    /// party triggers; first writer wins. Returns `(taker_payout, fee,
    /// initializer_refund)` so the real build can size all three
    /// transfers: the protocol fee (AV-17) slices the taker's share,
    /// the refund is never fee'd. The quorum gate does not apply, the
    /// vesting schedule is overridden, and the timelock does not gate —
    /// exactly like `resolve`. `MintMismatch` and
    /// `PayoutNotAllowlisted` guard the fund movement like `resolve`.
    pub fn trigger_default_judgment(
        ctx: Context<TriggerDefaultJudgment>,
    ) -> Result<(u64, u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        // AV-119: the inner settlement already ran the dispute-window
        // yield through the shared helper with `now` as `resolved_at`.
        // Capture the pre-settlement remainder and the pre-agreed taker
        // amount so the event records the principal legs (the AV-107
        // convention — see `resolve`).
        let remaining = escrow.remaining_amount();
        let taker_amount = escrow
            .default_judgment()
            .map(|j| j.default_taker_amount)
            .unwrap_or(0);
        let (payout, fee, refund) = escrow
            .trigger_default_judgment(
                ctx.accounts.caller.key().to_bytes(),
                now,
                vault_token_mint(&ctx.accounts.vault_token_account),
                ctx.accounts.payout_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-18: the taker's share is the gross (`payout + fee`); the
        // refund is never fee'd. AV-22: the DefaultJudgment event
        // carries the dispute evidence hash the escrow still holds —
        // the fallback settlement references the evidence the (absent)
        // arbiter never reviewed; rationale is None (no arbiter ruled).
        // AV-119: the refund leg is the principal refund (the
        // initializer's dispute-interest share rides the transfer,
        // tracked in `dispute_interest`).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::DefaultJudgment,
            from,
            escrow.state() as u8,
            payout + fee,
            fee,
            remaining.saturating_sub(taker_amount),
            now,
            escrow.evidence_hash(),
            None,
            None,
            None,
            None,
        );
        Ok((payout, fee, refund))
    }

    /// Attach a milestone tranche plan (AV-15; mirrors
    /// `MilestonePlan::new` + `Escrow::with_milestones`). `Uninitialized`
    /// only, like `initialize_quorum`: the tranche schedule is fixed
    /// before funds move. The tranche amounts must sum to exactly the
    /// locked amount (checked in u128, so the sum can never wrap); once
    /// attached, the plan owns the release schedule — plain `release` and
    /// `claim` become `InvalidMilestones`.
    pub fn initialize_milestones(
        ctx: Context<InitializeMilestones>,
        milestones: Vec<u64>,
    ) -> Result<()> {
        let plan =
            escrow_state::MilestonePlan::new(&milestones).map_err(|e| escrow_error(e))?;
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_milestones(plan).map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full milestone region
        // (1 + 65 bytes, zeroed when `None`), so the plan is written in
        // place — no realloc needed in the real build.
        Ok(())
    }

    /// Confirm a milestone for the release path (AV-15; mirrors
    /// `Escrow::confirm_milestone`). Either the initializer or the taker
    /// signs; each confirmation is a separate signature and the milestone
    /// is confirmed only once BOTH parties confirmed (dual-signature
    /// acceptance). Strictly in-order and idempotent per party.
    pub fn confirm_milestone(ctx: Context<ConfirmMilestone>, index: u8) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let confirmed_before = escrow.milestone_confirmed(index as usize);
        escrow
            .confirm_milestone(ctx.accounts.authority.key().to_bytes(), index)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flip the party's confirmation bit in `vault.milestone_flags` in
        // the real build.
        // AV-18: emit only when the milestone became fully confirmed
        // (mirrors `IndexedEscrow::confirm_milestone`); the first party's
        // confirmation alone emits nothing.
        if !confirmed_before && escrow.milestone_confirmed(index as usize) {
            let state = escrow.state() as u8;
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::MilestoneConfirmed,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Release a milestone's tranche to the taker (AV-15; mirrors
    /// `Escrow::release_milestone`). Only the initializer signs; the
    /// milestone must be dual-confirmed (`MilestoneNotConfirmed`
    /// otherwise) and every earlier milestone settled. Returns
    /// `(taker_payout, fee)` so the real build can size the taker's
    /// transfer and the protocol fee (AV-17). The AV-04 quorum gate
    /// applies exactly as for `release`. AV-16: the vault token
    /// account's mint must equal the bound `vault.mint` (`MintMismatch`
    /// otherwise); `None` on the native-SOL path (no mint bound).
    pub fn release_milestone(ctx: Context<ReleaseMilestone>, index: u8) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-27: the timelock gate reads the Solana clock sysvar (see
        // `release`).
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        // AV-116: the slot-based relative timelock gates the payout on
        // the clock sysvar's slot — never an instruction param, same
        // rule; a no-op when no slot lock is configured.
        let slot = Clock::get()?.slot;
        if !escrow.is_slot_unlock_eligible(slot) {
            return Err(escrow_error(escrow_state::EscrowError::TimelockNotReached));
        }
        let (payout, fee) = escrow
            .release_milestone(
                ctx.accounts.initializer.key().to_bytes(),
                now,
                index,
                vault_token_mint(&ctx.accounts.vault_token_account),
                ctx.accounts.payout_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_payout`
        // (`PayoutKind::MilestoneRelease`) — see `release`.
        // AV-18: `payout + fee` is the gross tranche; the final tranche
        // carries to == Released.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::MilestoneReleased,
            from,
            escrow.state() as u8,
            payout + fee,
            fee,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok((payout, fee))
    }

    /// Skip a milestone by mutual agreement (AV-15; mirrors
    /// `Escrow::skip_milestone`). Either the initializer or the taker
    /// signs; the skip executes (tranche refunded to the initializer)
    /// only after BOTH parties approved — a dual-signature skip.
    /// Strictly in-order and idempotent per party.
    pub fn skip_milestone(ctx: Context<SkipMilestone>, index: u8) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let settled_before = escrow.milestone_settled(index as usize);
        let tranche = escrow
            .milestone_plan()
            .and_then(|p| p.amount_at(index as usize))
            .unwrap_or(0);
        escrow
            .skip_milestone(ctx.accounts.authority.key().to_bytes(), index)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flip the party's skip-approval bit in `vault.milestone_flags`
        // (and the skipped bit plus `vault.skipped` once dual-approved)
        // in the real build.
        // AV-18: emit only when the skip executed (both approvals
        // present; mirrors `IndexedEscrow::skip_milestone`); a lone
        // approval emits nothing. The skipped tranche is the
        // initializer's refund.
        if !settled_before && escrow.milestone_settled(index as usize) {
            let state = escrow.state() as u8;
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::MilestoneSkipped,
            state,
            state,
            0,
            0,
            tranche,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Attach a periodic subscription release schedule (AV-56; mirrors
    /// `Escrow::with_subscription`). `Uninitialized` only, like
    /// `initialize_milestones`: the release cadence is fixed before
    /// funds move. The locked amount is split into `periods` equal
    /// tranches of `per_period`, one per `period_secs` seconds,
    /// back-scheduled from `expires_at` — period `i` (0-based) is due
    /// at `expires_at - (periods - 1 - i) * period_secs`, so the last
    /// period is always due exactly at expiry and the schedule
    /// completes within the escrow's lifetime. Validation:
    /// `period_secs` non-zero, `periods` in 1..=64 (the released bitmap
    /// is a u64), `per_period` non-zero, `periods * per_period` (in
    /// u128) == the locked amount, `expires_at != u64::MAX`
    /// (back-scheduling needs a bounded lifetime), and the schedule
    /// must fit inside the lifetime. Mutually exclusive with the
    /// milestone plan (`InvalidSubscription` if one is attached) — an
    /// escrow carries at most one release schedule.
    pub fn initialize_subscription(
        ctx: Context<InitializeSubscription>,
        period_secs: u64,
        periods: u8,
        per_period: u64,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_subscription(period_secs, periods, per_period)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full subscription
        // region (18 bytes, zeroed when `None`), so the schedule is
        // written in place — no realloc needed in the real build.
        Ok(())
    }

    /// Release one due subscription period to the taker (AV-56; mirrors
    /// `Escrow::release_period`). Only the initializer signs — like
    /// `release`, period release is the initializer's push path. The
    /// `period_index` must equal the next due period (`PeriodNotDue`
    /// for skip-ahead or replay: periods release strictly in order,
    /// each exactly once) and the period must be due (`now >= due_at`,
    /// read from the Solana clock sysvar — never an instruction
    /// param). Returns `(taker_payout, fee)` so the real build can size
    /// the taker's transfer and the protocol fee (AV-17): the fee
    /// slices the period (`payout + fee == per_period`). `Funded` only;
    /// the schedule must be attached (`InvalidSubscription`); the
    /// AV-04 quorum gate applies exactly as for `release`
    /// (`QuorumNotReached`); the AV-27 timelock gates every taker
    /// payout path (`TimelockNotReached` while `now < unlock_at`);
    /// `MintMismatch` and `PayoutNotAllowlisted` guard the fund
    /// movement like `release`. The tranche accumulates in the shared
    /// `released` counter, so a vesting `claim` composes (not blocked).
    /// The last period moves `Funded -> Released`. Emits
    /// `SubscriptionPeriodReleased` (`from == Funded`, `to == Funded`
    /// — or `Released` on the last period; payout = gross per-period
    /// amount, fee, refund = 0).
    pub fn release_period(ctx: Context<ReleasePeriod>, period_index: u8) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-27: the timelock gate reads the Solana clock sysvar (see
        // `release`).
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let (payout, fee) = escrow
            .release_period(
                ctx.accounts.initializer.key().to_bytes(),
                now,
                period_index,
                vault_token_mint(&ctx.accounts.vault_token_account),
                ctx.accounts.payout_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_payout` — see `release` (the
        // period payout settles as one payout + one fee leg).
        // AV-18: `payout + fee` is the gross period; the final period
        // carries to == Released.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::SubscriptionPeriodReleased,
            from,
            escrow.state() as u8,
            payout + fee,
            fee,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok((payout, fee))
    }

    /// Bind one SPL token mint to the escrow (AV-16; mirrors
    /// `escrow_state::parse_mint_address` + `Escrow::with_mint`).
    /// `Uninitialized` only, like `initialize_quorum`: the token scope is
    /// fixed before funds move. The `mint` param is the base58 SPL mint
    /// address; it must decode to exactly 32 bytes (`InvalidMint`
    /// otherwise — empty string, non-alphabet characters, or a value
    /// that is not 32 bytes), and the zero address is rejected (it is
    /// well-formed but not a real mint). After this, the fund-moving
    /// instructions (`release` / `cancel` / `cancel_expired` / `claim` /
    /// `release_milestone` / `resolve`) require the vault token
    /// account's mint to equal this address (`MintMismatch` otherwise).
    /// Without a bound mint the escrow is the native-SOL path and those
    /// instructions take no token mint.
    pub fn initialize_mint(ctx: Context<InitializeMint>, mint: String) -> Result<()> {
        let bytes =
            escrow_state::parse_mint_address(&mint).map_err(|e| escrow_error(e))?;
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_mint(bytes).map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // The vault account already reserves the full mint region
        // (33 bytes, zeroed when `None`), so the address is written in
        // place — no realloc needed in the real build.
        Ok(())
    }

    /// Opt in to a protocol fee on taker payouts (AV-17; mirrors
    /// `Escrow::with_protocol_fee`). `Uninitialized` only, like
    /// `initialize_quorum`: the fee rate is fixed before funds move.
    /// The rate is in basis points (`fee_bps <= 10_000`;
    /// `InvalidProtocolFee` otherwise); `0` means no fee (the default).
    /// AV-66: mutually exclusive with the tiered fee schedule —
    /// `initialize_protocol_fee` on an escrow with a configured
    /// schedule is `InvalidProtocolFee` (fail-fast, never silent
    /// last-wins). After this, every taker payout (`release` / `claim` /
    /// `release_milestone` / the taker's share of `resolve`) splits
    /// into a net payout and a protocol fee routed to the protocol fee
    /// account; the fee accumulates in `vault.fees_paid`.
    pub fn initialize_protocol_fee(ctx: Context<InitializeProtocolFee>, fee_bps: u16) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_protocol_fee(fee_bps)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.fee_bps` is always present (2 bytes, zeroed by
        // default), so the rate is written in place — no realloc needed
        // in the real build.
        Ok(())
    }

    /// Opt in to an expiry grace period (AV-21; mirrors
    /// `Escrow::with_grace_period`). `Uninitialized` only, like
    /// `initialize_quorum`: the grace period is fixed before funds move.
    /// After this, `cancel_expired` requires the clock to have passed
    /// `expires_at + grace_period` (`NotExpired` otherwise), so a keeper
    /// whose off-chain clock runs ahead of the cluster clock cannot
    /// submit a premature cancel. `grace_period == 0` means no grace
    /// (the default). `expires_at + grace_period` overflowing `u64` is
    /// `InvalidGracePeriod` — in particular a grace period cannot be
    /// combined with the no-timeout convention (`expires_at ==
    /// u64::MAX`).
    pub fn initialize_grace_period(ctx: Context<InitializeGracePeriod>, grace_period: u64) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_grace_period(grace_period)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.grace_period` is always present (8 bytes, zeroed by
        // default), so the period is written in place — no realloc needed
        // in the real build.
        Ok(())
    }

    /// Declare the dispute-evidence disclosure deadline (AV-68; mirrors
    /// `Escrow::with_evidence_deadline`): seconds in `Disputed` after
    /// which the escalating party's evidence disclosure defaults
    /// (measured from `disputed_at`, recorded by `escalate`). `Uninitialized`
    /// only; the arbiter (or panel) must already be configured
    /// (`InvalidArbiter` otherwise); a zero deadline is
    /// `InvalidEvidenceDeadline` (code 138).
    pub fn initialize_evidence_deadline(
        ctx: Context<InitializeEvidenceDeadline>,
        deadline_secs: u64,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_evidence_deadline(deadline_secs)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.evidence_deadline_secs` is always present (8 bytes,
        // zeroed by default), so the deadline is written in place — no
        // realloc needed in the real build.
        Ok(())
    }

    /// Declare the refund address whitelist (AV-23; mirrors
    /// `Escrow::with_refund_address`): after this, `cancel` /
    /// `cancel_expired` only refund to `refund_to`
    /// (`RefundAddressMismatch` otherwise) — a phishing frontend cannot
    /// redirect the refund. `Uninitialized` only; the zero address is
    /// rejected.
    pub fn initialize_refund_address(
        ctx: Context<InitializeRefundAddress>,
        refund_to: Pubkey,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_refund_address(refund_to.to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.refund_to` is always present (33 bytes, zeroed by
        // default), so the address is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Opt in to an anti-griefing penalty on taker-initiated expiry
    /// cancellation (AV-24; mirrors `Escrow::with_penalty_bps`).
    /// `Uninitialized` only, like `initialize_quorum`: the rate is fixed
    /// before funds move. The rate is in basis points (`penalty_bps <=
    /// 10_000`; `InvalidPenalty` otherwise); `0` means no penalty (the
    /// default). After this, a *taker-initiated* `cancel_expired` splits
    /// the remainder into a refund (to the whitelisted destination) and
    /// a penalty routed to the initializer as griefing compensation;
    /// initializer-initiated cancels and the arbiter's `resolve` never
    /// carry it.
    pub fn initialize_penalty(ctx: Context<InitializePenalty>, penalty_bps: u16) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_penalty_bps(penalty_bps)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.penalty_bps` is always present (2 bytes, zeroed by
        // default), so the rate is written in place — no realloc needed
        // in the real build.
        Ok(())
    }

    /// Opt in to time-weighted escalation of the anti-griefing penalty
    /// (AV-115; mirrors `Escrow::with_penalty_escalation`).
    /// `Uninitialized` only, like `initialize_penalty`: the schedule is
    /// fixed before funds move. Both params are basis points
    /// (`rate_bps_per_day <= 10_000`, `cap_bps <= 10_000`;
    /// `InvalidPenalty` otherwise); `rate_bps_per_day == 0` disables
    /// escalation (pure AV-24 behavior). After this, a
    /// *taker-initiated* `cancel_expired` charges
    /// `floor(remaining * min(penalty_bps + rate_bps_per_day * whole
    /// days past the expiry gate, cap_bps) / 10_000)` to the
    /// initializer as griefing compensation.
    pub fn initialize_penalty_escalation(
        ctx: Context<InitializePenaltyEscalation>,
        rate_bps_per_day: u16,
        cap_bps: u16,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_penalty_escalation(rate_bps_per_day, cap_bps)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.penalty_escalation_rate_bps` /
        // `vault.penalty_escalation_cap_bps` are always present (2
        // bytes each, zeroed by default), so the schedule is written
        // in place — no realloc needed in the real build.
        Ok(())
    }

    /// Declare the timelock (AV-27; mirrors `Escrow::with_timelock`):
    /// after this, `release` / `claim` / `release_milestone` require the
    /// Solana clock to have passed `unlock_at` (`TimelockNotReached`
    /// otherwise). `unlock_at == 0` means no lock (the default).
    /// `Uninitialized` only. `cancel` / `cancel_expired` / `resolve` are
    /// deliberately NOT gated, so a misconfigured lock can never trap
    /// funds forever.
    pub fn initialize_timelock(ctx: Context<InitializeTimelock>, unlock_at: u64) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_timelock(unlock_at)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.timelock` is always present (8 bytes, zeroed by
        // default), so the timestamp is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Declare the relative timelock (AV-64; mirrors
    /// `Escrow::with_relative_timelock`): after this, `release` /
    /// `claim` / `release_milestone` require the Solana clock to have
    /// passed `fund_at + secs` (`TimelockNotReached` otherwise), where
    /// `fund_at` is the clock `fund` recorded. `secs == 0` means no
    /// lock (the default). Mutually exclusive with the AV-27 absolute
    /// timelock — a nonzero `secs` together with a nonzero `unlock_at`
    /// is `InvalidTimelock` (code 135), in either builder order.
    /// `Uninitialized` only. `cancel` / `cancel_expired` / `resolve` are
    /// deliberately NOT gated, so a misconfigured lock can never trap
    /// funds forever.
    pub fn initialize_relative_timelock(
        ctx: Context<InitializeRelativeTimelock>,
        secs: u64,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_relative_timelock(secs)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.relative_timelock_secs` is always present (8 bytes,
        // zeroed by default), so the duration is written in place — no
        // realloc needed in the real build.
        Ok(())
    }

    /// Declare the slot-based relative timelock (AV-116; mirrors
    /// `Escrow::with_slot_timelock`): after this, `release` / `claim` /
    /// `release_milestone` require the Solana slot to have passed
    /// `fund_slot + slots` (`TimelockNotReached` otherwise), where
    /// `fund_slot` is the clock sysvar's slot `fund` recorded.
    /// `slots == 0` means no lock (the default). Slot-measured, so the
    /// lock is immune to validator wall-clock drift. Mutually exclusive
    /// with the AV-27 absolute timelock and the AV-64 second-relative
    /// timelock — a nonzero `slots` together with either is
    /// `InvalidTimelock` (code 135), in either builder order.
    /// `Uninitialized` only. `cancel` / `cancel_expired` / `resolve` are
    /// deliberately NOT gated, so a misconfigured lock can never trap
    /// funds forever.
    pub fn initialize_slot_timelock(
        ctx: Context<InitializeSlotTimelock>,
        slots: u64,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_slot_timelock(slots)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.slot_timelock_slots` is always present (8 bytes,
        // zeroed by default), so the duration is written in place — no
        // realloc needed in the real build.
        Ok(())
    }

    /// Opt in to the per-taker claim cooldown (AV-121; mirrors
    /// `Escrow::with_claim_cooldown`). `Uninitialized` only, like
    /// `initialize_slot_timelock`: the minimum slot distance between
    /// two taker `claim` calls is fixed before funds move. After
    /// this, the taker's second and later claims require `slot >=
    /// last_claim_slot + slots` (`InvalidClaimCooldown`, code 179,
    /// inside the window) — the cooldown is measured in Solana
    /// slots, the same slot semantics as AV-116. The first claim is
    /// always eligible. Emits no event (pre-fund configuration, like
    /// `initialize_slot_timelock`).
    pub fn initialize_claim_cooldown(
        ctx: Context<InitializeClaimCooldown>,
        slots: u64,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_claim_cooldown(slots)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.claim_cooldown_slots` is always present (8 bytes,
        // zeroed by default), so the duration is written in place — no
        // realloc needed in the real build.
        Ok(())
    }

    /// Declare the token decimal metadata (AV-28; mirrors
    /// `Escrow::with_decimals`): the SPL mint's decimal places, used
    /// only to render human-readable amounts in the keeper report and
    /// the AV-26 snapshot export — it never gates a transition and never
    /// moves funds. `decimals > 18` is `InvalidDecimals` (the largest
    /// precision any SPL/EVM token convention needs; SPL mints declare
    /// at most 9). `decimals == 0` means no decimal metadata (the
    /// default — amounts render as bare integers). `Uninitialized` only.
    pub fn initialize_decimals(ctx: Context<InitializeDecimals>, decimals: u8) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_decimals(decimals)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.decimals` is always present (1 byte, zeroed by
        // default), so the precision is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Opt in to emergency timelock-unlock governance (AV-41; mirrors
    /// `Escrow::with_emergency_unlock`). `Uninitialized` only, like
    /// `initialize_quorum`. After this, `emergency_unlock` may clear the
    /// AV-27 timelock by mutual agreement.
    pub fn initialize_emergency_unlock(ctx: Context<InitializeEmergencyUnlock>) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_emergency_unlock().map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Sets the opt-in byte in `vault.emergency_unlock` in the real
        // build (always present, 1 byte, zeroed by default — no realloc).
        Ok(())
    }

    /// Declare the protocol-fee recipient (AV-44; mirrors
    /// `Escrow::with_fee_recipient`): after this, every fee leg the
    /// AV-17 fee rate charges must go to `fee_recipient`
    /// (`RecipientMismatch` on a swapped destination in the settlement
    /// plan) — a fee cannot be silently redirected. With no pinned
    /// recipient the fee legs route to the program-level fee account.
    /// `Uninitialized` only; the zero address is `InvalidFeeRecipient`.
    pub fn initialize_fee_recipient(
        ctx: Context<InitializeFeeRecipient>,
        fee_recipient: Pubkey,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_fee_recipient(fee_recipient.to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.fee_recipient` is always present (33 bytes, zeroed by
        // default), so the address is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Bind the emergency-pause authority (AV-46; mirrors
    /// `Escrow::with_pause_authority`): after this, the bound key may
    /// engage / release the circuit breaker via `pause` / `unpause`.
    /// `Uninitialized` only; the zero address is `InvalidPauseAuthority`.
    pub fn initialize_pause_authority(
        ctx: Context<InitializePauseAuthority>,
        pause_authority: Pubkey,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_pause_authority(pause_authority.to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.pause_authority` is always present (33 bytes, zeroed by
        // default), so the address is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Engage the emergency pause (AV-46; mirrors `Escrow::pause`).
    /// While paused, every state-changing transition fails with `Paused`
    /// (code 124) — the circuit breaker. Only the bound pause authority
    /// may call this (`Unauthorized` otherwise); without an opted-in
    /// authority the switch does not exist (`InvalidStateTransition`).
    /// Emits `Paused` (from == to == the current state).
    pub fn pause(ctx: Context<Pause>, auto_unpause_at: Option<u64>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        escrow
            .pause(ctx.accounts.pause_authority.key().to_bytes(), auto_unpause_at)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flips `vault.paused` in place in the real build (1 byte,
        // always present, zeroed by default). AV-133: the
        // `auto_unpause_at` schedule is persisted in the vault tail
        // (9 bytes: 1-byte discriminant + 8-byte timestamp).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Paused,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Set the payout destination allowlist (AV-49; mirrors
    /// `Escrow::with_payout_allowlist`). Only the initializer signs, and
    /// only while the escrow is `Uninitialized` — the allowlist is a
    /// funding-time policy, like the quorum or vesting schedule. 1–4
    /// live addresses; empty / over-long / zero-address input is
    /// `InvalidPayoutAllowlist` (code 126). The 130-byte region is
    /// always present (zeroed when `None`), so this writes in place —
    /// no realloc in the real build. Emits no event (pre-fund
    /// configuration, like `with_pause_authority`).
    pub fn initialize_payout_allowlist(
        ctx: Context<InitializePayoutAllowlist>,
        allowlist: Vec<Pubkey>,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let addrs: Vec<[u8; 32]> = allowlist.iter().map(|k| k.to_bytes()).collect();
        let escrow = escrow
            .with_payout_allowlist(&addrs)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.payout_allowlist` is always present (130 bytes, zeroed
        // by default), so the list is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Update the payout destination allowlist (AV-49; mirrors
    /// `Escrow::update_payout_allowlist`). Dual-signature governance:
    /// on a dual-sig escrow both initializer and taker sign; on a plain
    /// escrow the initializer alone. An empty list clears the allowlist
    /// (back to taker-only payouts). `Uninitialized` / `Funded` only;
    /// `InvalidPayoutAllowlist` (code 126) on over-long / zero-address
    /// input. Emits `PayoutAllowlistUpdated` (from == to == the current
    /// state).
    pub fn update_payout_allowlist(
        ctx: Context<UpdatePayoutAllowlist>,
        allowlist: Vec<Pubkey>,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        let before = escrow.payout_allowlist();
        let addrs: Vec<[u8; 32]> = allowlist.iter().map(|k| k.to_bytes()).collect();
        escrow
            .update_payout_allowlist(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
                &addrs,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Rewrites `vault.payout_allowlist` in place in the real build
        // (130 bytes, always present, zeroed when None) — no realloc.
        // Emits only on an actual change; a same-list no-op stays
        // silent (mirrors `rotate_pause_authority`).
        if escrow.payout_allowlist() != before {
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::PayoutAllowlistUpdated,
                state,
                state,
                0,
                0,
                0,
                Clock::get()?.unix_timestamp as u64,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Set the payout destination denylist (AV-96; mirrors
    /// `Escrow::with_denylist`). Only the initializer signs, and only
    /// while the escrow is `Uninitialized` — the denylist is a
    /// funding-time compliance veto, like the quorum or vesting
    /// schedule. 1–4 live addresses; empty / over-long / zero-address
    /// input is `InvalidPayoutDenylist` (code 154). The 130-byte
    /// region is always present (zeroed when `None`), so this writes
    /// in place — no realloc in the real build. Deny takes precedence
    /// over the AV-49 allowlist: a destination on both lists is
    /// rejected with `PayoutDenied` (code 153). Emits no event
    /// (pre-fund configuration, like `with_pause_authority`).
    pub fn initialize_payout_denylist(
        ctx: Context<InitializePayoutDenylist>,
        denylist: Vec<Pubkey>,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let addrs: Vec<[u8; 32]> = denylist.iter().map(|k| k.to_bytes()).collect();
        let escrow = escrow
            .with_denylist(&addrs)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.payout_denylist` is always present (130 bytes, zeroed
        // by default), so the list is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Update the payout destination denylist (AV-96; mirrors
    /// `Escrow::update_payout_denylist`). Initializer-signature-alone
    /// governance (unlike `update_payout_allowlist`'s dual-signature
    /// reshape): the denylist is the initializer's compliance veto,
    /// not a bilateral fund route. An empty list clears the veto
    /// (back to `None`). `Uninitialized` / `Funded` only — the veto
    /// must be raisable while funds are locked, but never from a
    /// terminal state. `InvalidPayoutDenylist` (code 154) on
    /// over-long / zero-address input. Emits `DenylistUpdated`
    /// (from == to == the current state) only on an actual change; a
    /// same-list no-op stays silent.
    pub fn update_payout_denylist(
        ctx: Context<UpdatePayoutDenylist>,
        denylist: Vec<Pubkey>,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        let before = escrow.payout_denylist();
        let addrs: Vec<[u8; 32]> = denylist.iter().map(|k| k.to_bytes()).collect();
        escrow
            .update_payout_denylist(
                ctx.accounts.initializer.key().to_bytes(),
                &addrs,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Rewrites `vault.payout_denylist` in place in the real build
        // (130 bytes, always present, zeroed when None) — no realloc.
        if escrow.payout_denylist() != before {
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::DenylistUpdated,
                state,
                state,
                0,
                0,
                0,
                Clock::get()?.unix_timestamp as u64,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Initialize the opt-in CPI target-program allowlist (AV-83;
    /// mirrors `Escrow::with_cpi_allowlist`): the only programs
    /// `release_via_cpi` may invoke when the list is configured. An
    /// empty list leaves the allowlist unset (any target allowed —
    /// the default). `Uninitialized` only, like
    /// `initialize_payout_allowlist`: the CPI policy is fixed before
    /// funds move. Over-long / zero-address input is
    /// `InvalidCpiAllowlist` (code 144). The vault account already
    /// reserves the full 258-byte region (1-byte count + 8 32-byte
    /// program ids, zeroed when `None`), so the list is written in
    /// place — no realloc needed in the real build. Emits no event
    /// (pre-fund configuration).
    pub fn initialize_cpi_allowlist(
        ctx: Context<InitializeCpiAllowlist>,
        allowlist: Vec<Pubkey>,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let addrs: Vec<[u8; 32]> = allowlist.iter().map(|k| k.to_bytes()).collect();
        let escrow = escrow
            .with_cpi_allowlist(&addrs)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Update the CPI target-program allowlist (AV-83; mirrors
    /// `Escrow::update_cpi_allowlist`). Unlike the payout allowlist,
    /// this update is always dual-signed — both initializer and taker
    /// sign even on a plain escrow, since the allowlist guards a
    /// privileged execution path (a stricter rule than AV-49 by
    /// design). `Uninitialized` / `Funded` only; an empty list clears
    /// the allowlist (back to any-target-allowed). `InvalidCpiAllowlist`
    /// (code 144) on over-long / zero-address input. Emits
    /// `CpiAllowlistUpdated` (from == to == the current state).
    pub fn update_cpi_allowlist(
        ctx: Context<UpdateCpiAllowlist>,
        allowlist: Vec<Pubkey>,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        let before = escrow.cpi_allowlist();
        let addrs: Vec<[u8; 32]> = allowlist.iter().map(|k| k.to_bytes()).collect();
        escrow
            .update_cpi_allowlist(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
                &addrs,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Emits only on an actual change; a same-list no-op stays
        // silent (mirrors `update_payout_allowlist`).
        if escrow.cpi_allowlist() != before {
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::CpiAllowlistUpdated,
                state,
                state,
                0,
                0,
                0,
                Clock::get()?.unix_timestamp as u64,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Bind an external multisig as an escrow authority (AV-84; mirrors
    /// `Escrow::with_multisig_authority`): records the multisig program
    /// id, the vault PDA that must sign, and the threshold metadata.
    /// `Uninitialized` only, like `initialize_cpi_allowlist` — the
    /// binding is immutable once set. A zero multisig program id, a
    /// zero authority PDA, or a zero threshold is
    /// `InvalidMultisigAuthority` (code 145). The vault account
    /// already reserves the full 67-byte region (1-byte discriminant +
    /// 66-byte record, zeroed when `None`), so the binding is written
    /// in place — no realloc needed in the real build. Emits no event
    /// (pre-fund configuration).
    ///
    /// Zero-trust: the escrow program never calls into the multisig
    /// program and never enforces the threshold — the external program
    /// owns the vote. The escrow's authority checks keep comparing
    /// signer keys exactly as for an EOA; when the initializer *is*
    /// the vault PDA, the PDA's signature authorizes it. The threshold
    /// is read-only metadata for keepers (see
    /// `escrow_state::KeeperAction::multisig_authority`) and indexers.
    pub fn initialize_multisig_authority(
        ctx: Context<InitializeMultisigAuthority>,
        multisig_authority: MultisigAuthority,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_multisig_authority(
                multisig_authority.program_id.to_bytes(),
                multisig_authority.authority.to_bytes(),
                multisig_authority.threshold,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Bind the opt-in 32-byte off-chain reference memo (AV-53; mirrors
    /// `Escrow::with_reference`): an order id, invoice hash, or any
    /// other 32-byte correlation id from the operator's off-chain
    /// system. `Uninitialized` only; any 32 bytes are accepted — the
    /// field is read-only pass-through (never read by a check gate,
    /// never cleared), so there is nothing to validate and no new
    /// error variant. Emits no event (pre-fund configuration); every
    /// later `EscrowVaultEvent` carries the memo in its `reference`
    /// field for off-chain reconciliation.
    pub fn initialize_reference(
        ctx: Context<InitializeReference>,
        reference: Pubkey,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow.with_reference(reference.to_bytes());
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.reference` is always present (33 bytes, zeroed by
        // default), so the memo is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Release the emergency pause (AV-46; mirrors `Escrow::unpause`).
    /// Same authority rules as `pause`; unpausing a non-paused escrow is
    /// `InvalidStateTransition` (strict toggle). State-changing
    /// transitions work again. Emits `Unpaused` (from == to == the
    /// current state).
    pub fn unpause(ctx: Context<Unpause>) -> Result<()> {        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        escrow
            .unpause(ctx.accounts.pause_authority.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Flips `vault.paused` back in place in the real build.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Unpaused,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Rotate the emergency-pause authority by owner governance (AV-47;
    /// mirrors `Escrow::rotate_pause_authority`). Only the initializer
    /// signs — the *escrow* authority, not the pause key, so a lost pause
    /// key cannot block rotation. Deliberately NOT gated by the pause
    /// itself: rotation is the key-loss escape hatch and must work while
    /// paused (rotate, then `unpause` with the fresh key). The old key
    /// stops working immediately; rotating to the bound key is an
    /// idempotent no-op. Emits `PauseAuthorityRotated` only on an actual
    /// change (from == to == the current state).
    pub fn rotate_pause_authority(
        ctx: Context<RotatePauseAuthority>,
        new_authority: Pubkey,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        let before = escrow.pause_authority();
        escrow
            .rotate_pause_authority(
                ctx.accounts.initializer.key().to_bytes(),
                new_authority.to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Rewrites `vault.pause_authority` in place in the real build
        // (33 bytes, always present, zeroed when None) — no realloc.
        if escrow.pause_authority() != before {
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::PauseAuthorityRotated,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Rotate the taker (payout counterparty) by dual-signed governance
    /// (AV-52; mirrors `Escrow::rotate_taker`). Both the initializer and
    /// the *current* taker must sign — one party alone (or a stranger
    /// pair) is `Unauthorized`. Only `Uninitialized` / `Activated` /
    /// `Funded`: the terminal states and `Disputed` are
    /// `InvalidStateTransition` (no live counterparty left to rotate,
    /// and arbitration in flight adjudicates the taker's identity). The
    /// zero address is `InvalidTaker` (code 128). A paused escrow fails
    /// fast (`Paused`) — rotation is a config transition, not the pause
    /// key-loss escape hatch. Only the taker field changes (amount,
    /// released progress, attest records, milestone state all preserved);
    /// rotating to the current taker is an idempotent no-op. Emits
    /// `TakerRotated` only on an actual change (from == to == the
    /// current state), mirroring `IndexedEscrow::rotate_taker`.
    pub fn rotate_taker(ctx: Context<RotateTaker>, new_taker: Pubkey) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        let before = escrow.taker();
        escrow
            .rotate_taker(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.old_taker.key().to_bytes(),
                new_taker.to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Rewrites `vault.taker` in place in the real build (32 bytes,
        // always present) — no realloc, no rent change.
        if escrow.taker() != before {
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::TakerRotated,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Rotate the initializer (funding authority) by dual-signed
    /// governance (AV-58; mirrors `Escrow::rotate_initializer`). Both
    /// the *current* initializer and the taker must sign — one party
    /// alone (or a stranger pair) is `Unauthorized`; the degenerate
    /// initializer == taker self-escrow authorizes with one key passed
    /// twice, like AV-12 activation. Only `Uninitialized` / `Activated`
    /// / `Funded`: the terminal states and `Disputed` are
    /// `InvalidStateTransition` (no live escrow left to re-key, and
    /// arbitration in flight adjudicates the initializer's identity —
    /// it pays the refund to the initializer). The zero address is
    /// `InvalidInitializer` (code 133). A paused escrow fails fast
    /// (`Paused`) — rotation is a config transition, not the pause
    /// key-loss escape hatch. On an actual change the initializer's
    /// activation bit is cleared (the new key never signed activation);
    /// rotating to the current initializer is an idempotent no-op.
    /// Refunds follow automatically: the AV-23 whitelist pins the
    /// destination when configured, else refunds resolve to the new
    /// initializer. Emits `InitializerRotated` only on an actual change
    /// (from == to == the current state), mirroring
    /// `IndexedEscrow::rotate_initializer`.
    pub fn rotate_initializer(
        ctx: Context<RotateInitializer>,
        new_initializer: Pubkey,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        let before = escrow.initializer();
        escrow
            .rotate_initializer(
                ctx.accounts.old_initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
                new_initializer.to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Rewrites `vault.initializer` in place in the real build (32
        // bytes, always present) — no realloc, no rent change.
        if escrow.initializer() != before {
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::InitializerRotated,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Rotate the dispute arbiter by dual-signed governance (AV-62;
    /// mirrors `Escrow::rotate_arbiter`). Both the *current* initializer
    /// and the *current* taker must sign — one party alone (or a stranger
    /// pair) is `Unauthorized`; the arbiter itself does not sign (a lost
    /// arbiter key must not block its own replacement); the degenerate
    /// initializer == taker self-escrow authorizes with one key passed
    /// twice, like AV-12 activation. Only `Uninitialized` / `Activated`
    /// / `Funded`: the terminal states and `Disputed` are
    /// `InvalidStateTransition` (no live dispute path left to referee,
    /// and arbitration in flight must settle with the referee that heard
    /// it). A paused escrow fails fast (`Paused`) — rotation is a config
    /// transition, not the pause key-loss escape hatch. With no arbiter
    /// configured there is nothing to rotate (`InvalidArbiter`, code
    /// 108, the arbiter-config error); the zero address is likewise
    /// `InvalidArbiter`. Rotating to the current arbiter is an
    /// idempotent no-op (the activation bitmask is untouched — it tracks
    /// only the initializer and taker). The keeper's `resolve` listing
    /// and the snapshot export read the live arbiter field, so both
    /// follow the rotation automatically. Emits `ArbiterRotated` only on
    /// an actual change (from == to == the current state), mirroring
    /// `IndexedEscrow::rotate_arbiter`.
    pub fn rotate_arbiter(
        ctx: Context<RotateArbiter>,
        new_arbiter: Pubkey,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        let before = escrow.arbiter();
        escrow
            .rotate_arbiter(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
                new_arbiter.to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Rewrites `vault.arbiter` in place in the real build (33 bytes,
        // always present, zeroed when None) — no realloc, no rent change.
        if escrow.arbiter() != before {
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::ArbiterRotated,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Rotate the protocol-fee recipient by dual-signed governance
    /// (AV-67; mirrors `Escrow::rotate_fee_recipient`). Both the
    /// *current* initializer and the *current* taker must sign — one
    /// party alone (or a stranger pair) is `Unauthorized`; the fee
    /// recipient itself does not sign (a lost fee-recipient key must
    /// not block its own replacement); the degenerate initializer ==
    /// taker self-escrow authorizes with one key passed twice, like
    /// AV-12 activation. Only `Uninitialized` / `Activated` /
    /// `Funded`: the terminal states have no future fee leg left to
    /// redirect, and `Disputed` is `InvalidStateTransition` (the
    /// dispute settlement builders pin the fee leg to the configured
    /// recipient — it must not move mid-dispute). A paused escrow fails
    /// fast (`Paused`) — rotation is a config transition, not the
    /// pause key-loss escape hatch. With no fee recipient configured
    /// there is nothing to rotate (`InvalidFeeRecipient`, code 123,
    /// the fee-recipient-config error); the zero address is likewise
    /// `InvalidFeeRecipient`. Rotating to the current recipient is an
    /// idempotent no-op (the activation bitmask is untouched — it
    /// tracks only the initializer and taker). The keeper's fee
    /// listings and the snapshot export read the live fee_recipient
    /// field, so both follow the rotation automatically. Emits
    /// `FeeRecipientRotated` only on an actual change (from == to ==
    /// the current state), mirroring
    /// `IndexedEscrow::rotate_fee_recipient`.
    pub fn rotate_fee_recipient(
        ctx: Context<RotateFeeRecipient>,
        new_recipient: Pubkey,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        let before = escrow.fee_recipient();
        escrow
            .rotate_fee_recipient(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
                new_recipient.to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Rewrites `vault.fee_recipient` in place in the real build (33
        // bytes, always present, zeroed when None) — no realloc, no
        // rent change.
        if escrow.fee_recipient() != before {
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::FeeRecipientRotated,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Re-split the milestone tranche amounts by dual-signed governance
    /// (AV-70; mirrors `Escrow::adjust_milestone_amounts`). Both the
    /// *current* initializer and the *current* taker must sign — one
    /// party alone (or a stranger pair) is `Unauthorized`; the
    /// degenerate initializer == taker self-escrow authorizes with one
    /// key passed twice, like AV-12 activation. Only `Uninitialized` /
    /// `Activated` / `Funded`: the terminal states have no live
    /// tranches left to re-split, and `Disputed` is
    /// `InvalidStateTransition` (arbitration in flight adjudicates the
    /// tranches). Once any tranche settled (`released > 0` or
    /// `skipped > 0`) the re-split is rejected — the amounts on chain
    /// are already partially consumed. The new amounts must have
    /// exactly the plan's tranche count, be all positive, and sum to
    /// exactly the locked amount (`InvalidMilestones` otherwise). A
    /// paused escrow fails fast (`Paused`). The rewrite is in place
    /// (the tranche table is always reserved) — no realloc, no rent
    /// change. Protocol fees charge on the new amounts at release time
    /// via `protocol_fee_for` (still floored by `fee_cap`). Emits
    /// `MilestonesAdjusted` only on an actual change (a no-op
    /// re-affirmation emits nothing), mirroring
    /// `IndexedEscrow::adjust_milestone_amounts`.
    pub fn adjust_milestone_amounts(
        ctx: Context<AdjustMilestoneAmounts>,
        new_amounts: Vec<u64>,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        let before: Vec<u64> = escrow
            .milestone_plan()
            .map(|p| (0..p.count()).map(|i| p.amount_at(i as usize).unwrap_or(0)).collect())
            .unwrap_or_default();
        escrow
            .adjust_milestone_amounts(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
                &new_amounts,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Rewrites the `vault.milestones.amounts` table in place (the
        // 8-slot region is always reserved, zeroed when no plan) — no
        // realloc, no rent change.
        let after: Vec<u64> = escrow
            .milestone_plan()
            .map(|p| (0..p.count()).map(|i| p.amount_at(i as usize).unwrap_or(0)).collect())
            .unwrap_or_default();
        if after != before {
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::MilestonesAdjusted,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Re-split the subscription per-period amounts by dual-signed
    /// governance (AV-73; mirrors `Escrow::adjust_period_amounts`). Both
    /// the *current* initializer and the *current* taker must sign —
    /// one party alone (or a stranger pair) is `Unauthorized`; the
    /// degenerate initializer == taker self-escrow authorizes with one
    /// key passed twice, like AV-12 activation. Only `Uninitialized` /
    /// `Activated` / `Funded`: the terminal states have no live periods
    /// left to re-split, and `Disputed` is `InvalidStateTransition`
    /// (arbitration in flight adjudicates the payouts). Released periods
    /// lock their recorded amounts — the re-split must reaffirm them
    /// (`InvalidSubscription` otherwise), so on-chain payout history is
    /// never rewritten. The new amounts must have exactly the
    /// schedule's period count, be all positive, and sum to exactly the
    /// locked amount (`InvalidSubscription` otherwise). A paused escrow
    /// fails fast (`Paused`). The rewrite is in place (the 64-slot
    /// table is always reserved) — no realloc, no rent change. Protocol
    /// fees charge on the new amounts at release time via
    /// `protocol_fee_for` (still floored by `fee_cap`). Emits
    /// `SubscriptionAmountsAdjusted` only on an actual change (a no-op
    /// re-affirmation emits nothing), mirroring
    /// `IndexedEscrow::adjust_period_amounts`.
    pub fn adjust_period_amounts(
        ctx: Context<AdjustPeriodAmounts>,
        new_amounts: Vec<u64>,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        let before: Vec<u64> = escrow
            .subscription_schedule()
            .map(|s| {
                (0..s.periods)
                    .map(|i| escrow.subscription_period_amount(i).unwrap_or(0))
                    .collect()
            })
            .unwrap_or_default();
        escrow
            .adjust_period_amounts(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
                &new_amounts,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Rewrites the `vault.subscription_amounts` table in place (the
        // 64-slot region is always reserved, zeroed when no schedule) —
        // no realloc, no rent change.
        let after: Vec<u64> = escrow
            .subscription_schedule()
            .map(|s| {
                (0..s.periods)
                    .map(|i| escrow.subscription_period_amount(i).unwrap_or(0))
                    .collect()
            })
            .unwrap_or_default();
        if after != before {
            emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::SubscriptionAmountsAdjusted,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        }
        Ok(())
    }

    /// Opt in to bounded expiry extension at setup time (AV-59;
    /// mirrors `Escrow::with_max_extension_secs`). `Uninitialized`
    /// only — the extension policy is fixed before any funds move. A
    /// zero bound is `InvalidExpiryExtension` (code 134): leave the
    /// field at its default 0 (extension disabled) instead. The
    /// 16-byte region is always reserved, so the opt-in writes in
    /// place — no realloc, no rent change. Emits no event (pre-fund
    /// configuration).
    pub fn initialize_extension(
        ctx: Context<InitializeExtension>,
        max_extension_secs: u64,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        escrow
            .with_max_extension_secs(max_extension_secs)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Opt in to an absolute protocol-fee ceiling at setup time (AV-63;
    /// mirrors `Escrow::with_fee_cap`). `Uninitialized` only — the
    /// ceiling is fixed before any funds move, like every other
    /// `with_*` builder. After this, the effective fee per payout is
    /// `min(bps fee, fee_cap)`: whale-sized payouts stop growing the
    /// protocol's fee leg without bound. A zero cap is valid and means
    /// "uncapped" (the default) — no new error code: a zero *fee* is
    /// expressed via `fee_bps == 0`, so the sentinel cannot be confused
    /// with a fee waiver, paralleling the AV-27 timelock and AV-51
    /// cliff conventions. The 8-byte `vault.fee_cap` region is always
    /// present (zeroed = uncapped), so the opt-in writes in place —
    /// no realloc, no rent change. Emits no event (pre-fund
    /// configuration).
    pub fn initialize_fee_cap(
        ctx: Context<InitializeFeeCap>,
        max_fee_cents: u64,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_fee_cap(max_fee_cents)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.fee_cap` is always present (8 bytes, zeroed = uncapped
        // by default), so the ceiling is written in place — no realloc
        // needed in the real build.
        Ok(())
    }

    /// Opt in to the tiered protocol-fee schedule (AV-66; mirrors
    /// `Escrow::with_fee_schedule`): replaces the flat bps rate with a
    /// volume-priced tier ladder — `tiers` is the amount-to-rate ladder
    /// as `(min_amount, bps)` pairs, and the fee for a gross payout
    /// uses the rate of the highest tier with `min_amount <= amount`
    /// (still floored by the AV-63 `fee_cap` when one is set).
    /// `Uninitialized` only, like every other `with_*` builder; the
    /// ladder is fixed before funds move. Mutually exclusive with the
    /// flat rate — fail-fast, not last-wins: a nonzero `fee_bps`
    /// already set, an empty or over-long ladder, a tier `bps >
    /// 10_000`, or non-strictly-ascending `min_amount` floors is
    /// `InvalidProtocolFee` (code 114 — a rate configuration must
    /// never silently drop another). The 81-byte `vault.fee_schedule`
    /// region is always present (zeroed = no schedule when
    /// `tier_count == 0`), so the opt-in writes in place — no realloc,
    /// no rent change. Emits no event (pre-fund configuration).
    pub fn initialize_fee_schedule(ctx: Context<InitializeFeeSchedule>, tiers: Vec<FeeTier>) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let ladder: Vec<(u64, u16)> = tiers.iter().map(|t| (t.min_amount, t.bps)).collect();
        let escrow = escrow
            .with_fee_schedule(&ladder)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // `vault.fee_schedule` is always present (81 bytes, zeroed = no
        // schedule by default), so the ladder is written in place — no
        // realloc needed in the real build.
        Ok(())
    }

    /// Extend the expiry deadline in place (AV-59; mirrors
    /// `Escrow::extend_expiry`). A unilateral initializer power:
    /// extension only lengthens the taker's window, so no
    /// counterparty signature is needed. Only `Uninitialized` /
    /// `Funded` — `Activated` is deliberately excluded (a dual-sig
    /// escrow both parties activated has jointly committed to its
    /// terms), terminal states and `Disputed` are
    /// `InvalidStateTransition`. The extension must be opted in
    /// (`max_extension_secs > 0`), the escrow must not already be
    /// expiry-eligible (an expired escrow exits via `cancel_expired`),
    /// the deadline must move strictly forward, and the single
    /// increment must not exceed `max_extension_secs` —
    /// `InvalidExpiryExtension` (code 134) for any violation. A
    /// paused escrow fails fast (`Paused`). On success
    /// `extension_count` increments (saturating). Emits
    /// `ExpiryExtended` (from == to == the current state).
    pub fn extend_expiry(ctx: Context<ExtendExpiry>, new_expires_at: u64) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        escrow
            .extend_expiry(
                ctx.accounts.initializer.key().to_bytes(),
                new_expires_at,
                Clock::get()?.unix_timestamp as u64,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::ExpiryExtended,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Migrate the vault's persisted schema to the current revision
    /// (AV-75; AV-85: the one-shot catch-up is now the explicit N → M
    /// step chain — mirrors `Escrow::migrate_schema`). A unilateral
    /// initializer power: on-chain, a program upgrade appends new vault
    /// fields and the account is realloc'd with the new region
    /// zero-filled — the initializer runs this exactly once to carry
    /// the vault onto the new layout, stepping through every
    /// intermediate version in order. Only `schema_version <
    /// SCHEMA_VERSION` runs: an already-current vault refuses the
    /// second call, and an unknown future version refuses loudly
    /// instead of skipping forward (`InvalidSchemaMigration`, code 140,
    /// either way). Each step re-validates the conservation invariants
    /// over the field set it carries (`released <= amount`, `released
    /// + skipped <= amount`, `fees_paid <= released`, milestone tranche
    /// sum `== amount`, plus `released + penalty_paid <= amount` from
    /// the 1 → 2 step on) — a corrupt vault is refused, never migrated;
    /// any failing step rolls the chain back to the pre-chain snapshot
    /// (zero partial migration). A paused escrow fails fast (`Paused`).
    /// Emits one `SchemaMigrated` per applied step (from == to == the
    /// current state) — always on success, since a successful migration
    /// always steps the version; the real build stamps each event with
    /// its step's from → to versions (mirroring
    /// `escrow_state::EscrowEvent::schema_versions`).
    pub fn migrate_schema(ctx: Context<MigrateSchema>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        // AV-85: run the N → M step chain and emit one SchemaMigrated
        // per applied step, so the on-chain event stream records every
        // from → to version pair — mirroring
        // `IndexedEscrow::migrate_schema`. (The skeleton's
        // `emit_transition` carries no per-step versions; the real
        // build stamps them like `EscrowEvent::schema_versions`.)
        let steps = escrow
            .migrate_schema_steps(ctx.accounts.initializer.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        let at = Clock::get()?.unix_timestamp as u64;
        for _step in steps {
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::SchemaMigrated,
                state,
                state,
                0,
                0,
                0,
                at,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Opt in to the default-penalty (slash) clause (AV-82; mirrors
    /// `Escrow::with_slash_terms`). `Uninitialized` only, like
    /// `initialize_arbiter`: the penalty account and the deadline are
    /// fixed before funds move. The zero penalty account is
    /// `SlashNotEligible` (code 143) — the penalty sink must be a real
    /// identity, since `slash` routes funds to it. The vault account
    /// already reserves the full 41-byte slash-terms region (1-byte
    /// discriminant + 40-byte terms, zeroed when `None`), so the terms
    /// are written in place — no realloc needed in the real build.
    /// Emits no event (pre-fund configuration).
    pub fn initialize_slash_terms(
        ctx: Context<InitializeSlashTerms>,
        penalty_account: Pubkey,
        slash_deadline: u64,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_slash_terms(penalty_account.to_bytes(), slash_deadline)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Opt in to the tiered default-penalty (slash) ladder (AV-126;
    /// mirrors `Escrow::with_slash_ladder`). `Uninitialized` only,
    /// like `initialize_slash_terms`: the penalty account and the
    /// rung table are fixed before funds move. The 114-byte
    /// slash-ladder region (1-byte discriminant + 113-byte ladder)
    /// is always reserved on the vault account, so the ladder writes
    /// in place — no realloc needed in the real build. Emits no
    /// event (pre-fund configuration). Validation failures are
    /// `InvalidSlashLadder` (code 184) — empty or over-long rung
    /// table, a zero bps rung, bps above 10_000, non-strictly
    /// ascending deadlines or bps, a zero penalty account, or an
    /// escrow that already carries single-level slash terms
    /// (mutually exclusive).
    pub fn initialize_slash_ladder(
        ctx: Context<InitializeSlashLadder>,
        penalty_account: Pubkey,
        rungs: Vec<SlashRungArg>,
    ) -> Result<()> {
        let rung_tuples: Vec<(u64, u16)> = rungs
            .iter()
            .map(|r| (r.deadline, r.bps))
            .collect();
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_slash_ladder(penalty_account.to_bytes(), &rung_tuples)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Slash the defaulting taker (AV-82; mirrors `Escrow::slash`):
    /// `Funded -> Funded` — the escrow stays live, the taker can still
    /// earn the remainder by performing late. The initializer or the
    /// configured arbiter signs (`authority`); `now` comes from the
    /// Solana clock sysvar (never an instruction param — the default
    /// must be measured on chain time). The slashed `amount` moves to
    /// the penalty account fixed in the slash terms — the real build
    /// constrains `penalty_account.key()` to equal the terms' penalty
    /// account (a phishing frontend cannot redirect the penalty by
    /// swapping the account); the state machine accumulates the amount
    /// in `penalty_paid`, never in `released`. Returns the slashed
    /// amount so the real build can size the transfer. Emits
    /// `EscrowSlashed` (from == to == `Funded`), mirroring
    /// `IndexedEscrow::slash` — the skeleton's `emit_transition`
    /// carries payout/fee/refund only, so the real build stamps
    /// `amounts.penalty = slashed` on the event (see
    /// `escrow_state::EventAmounts::slashed`). For a ladder escrow
    /// the pin below uses the ladder's penalty account (terms and
    /// ladder are mutually exclusive, so exactly one is present);
    /// repeated slashes are allowed for ladder escrows, each
    /// consuming the current rung. The real build must also stamp
    /// the consumed rung index on `EscrowSlashed`: the state
    /// machine's `IndexedEscrow::slash` stamps `slash_ladder_index`
    /// on the event, but the skeleton's `emit_transition` carries
    /// payout/fee/refund only — read
    /// `escrow.slash_ladder_index()` after the slash and stamp the
    /// event field itself.
    pub fn slash(ctx: Context<Slash>, amount: u64) -> Result<u64> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        // AV-82 / AV-126: the penalty destination is fixed at setup
        // — either the single-level terms or the ladder (mutually
        // exclusive, enforced by the state machine's constructors);
        // the skeleton's state machine takes no destination param,
        // so the account constraint is enforced here, before the
        // state machine runs. AV-106: when the insurance pool is
        // opted in the slash routes to the pool (no penalty-account
        // transfer), so the pin is skipped.
        let penalty_account = escrow
            .slash_terms()
            .map(|t| t.penalty_account)
            .or_else(|| escrow.slash_ladder().map(|l| l.penalty_account))
            .ok_or(error!(ErrorCode::SlashNotEligible))?;
        if !escrow.insurance_pool()
            && ctx.accounts.penalty_account.key().to_bytes() != penalty_account
        {
            return Err(error!(ErrorCode::SlashNotEligible));
        }
        let slashed = escrow
            .slash(
                ctx.accounts.authority.key().to_bytes(),
                amount,
                vault_token_mint(&ctx.accounts.vault_token_account),
                now,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Slashed,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            Some(ctx.accounts.authority.key()),
        );
        Ok(slashed)
    }

    /// Opt in to the slash-appeal window (AV-86; mirrors
    /// `Escrow::with_appeal_window`). `Uninitialized` only, like
    /// `initialize_slash_terms`: the window is fixed before funds move.
    /// A zero window is `InvalidAppealWindow` (code 146) — a
    /// zero-second window would give the taker no chance to appeal.
    /// Emits no event (pre-fund configuration).
    pub fn initialize_appeal_window(
        ctx: Context<InitializeAppealWindow>,
        window_secs: u64,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_appeal_window(window_secs)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// Opt in to the appeal bond (AV-103; mirrors
    /// `Escrow::with_appeal_bond`): the amount the taker must lock when
    /// filing a slash appeal. `Uninitialized` only, like
    /// `initialize_appeal_window` — the bond is fixed before funds
    /// move. A zero bond is `InvalidAppealBond` (code 158) — a zero
    /// bond is a no-op; the no-bond default already covers free filing.
    /// Emits no event (pre-fund configuration).
    pub fn initialize_appeal_bond(
        ctx: Context<InitializeAppealBond>,
        bond: u64,
    ) -> Result<()> {
        let escrow = read_escrow(&ctx.accounts.vault);
        let escrow = escrow
            .with_appeal_bond(bond)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(())
    }

    /// File an appeal against the executed slash (AV-86; mirrors
    /// `Escrow::file_appeal`): `Funded -> Funded` — filing records the
    /// taker's challenge and opens the arbiter panel's review (and,
    /// AV-103, locks the configured appeal bond — the real build
    /// transfers it from the taker into the vault). The taker signs —
    /// only the slashed party may contest the penalty.
    /// `now` comes from the Solana clock sysvar (never an instruction
    /// param — a caller-supplied timestamp could rewind back inside
    /// the window). The state machine enforces the full eligibility
    /// gate (taker-only, panel configured, slash executed, window
    /// configured and open, one appeal per slash). Emits `AppealFiled`
    /// (from == to == `Funded`, amounts zero), mirroring
    /// `IndexedEscrow::file_appeal`.
    pub fn file_appeal(ctx: Context<FileAppeal>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let from = escrow.state() as u8;
        escrow
            .file_appeal(ctx.accounts.taker.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::AppealFiled,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            Some(ctx.accounts.taker.key()),
        );
        Ok(())
    }

    /// Cast a panel member's review vote on the filed slash appeal
    /// (AV-86; mirrors `Escrow::review_appeal`): `uphold == true`
    /// keeps the penalty, `uphold == false` overturns it and refunds
    /// the penalty to the taker. The member signs; the state machine
    /// enforces one-effective-vote-per-member and resolves when either
    /// side reaches the panel threshold (the AV-65 tally precedent).
    /// A non-resolving vote emits nothing (the ballot is still open);
    /// the M-th matching vote emits `AppealResolved` (from == to ==
    /// `Funded`; on overturn the taker's full restitution — refunded
    /// penalty plus refunded appeal bond (AV-103) — rides `payout`,
    /// zero on uphold), mirroring `IndexedEscrow::review_appeal`.
    /// Returns the resolution as `(outcome, penalty_refunded,
    /// bond_moved)` — `outcome` 0 == upheld, 1 == overturned;
    /// `bond_moved` is the forfeited bond on uphold and the refunded
    /// bond on overturn (`0` when no bond was configured) — so the
    /// real build can size both transfers; `None` while the ballot is
    /// open. (The skeleton emitter has no `penalty` slot, so an
    /// uphold forfeiture rides the vault state here; the real build's
    /// `AppealResolved` event carries it in `amounts.penalty`.)
    pub fn review_appeal(ctx: Context<ReviewAppeal>, uphold: bool) -> Result<Option<(u8, u64, u64)>> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let resolved = escrow
            .review_appeal(ctx.accounts.member.key().to_bytes(), uphold)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        if let Some((outcome, penalty_refunded, bond_moved)) = resolved {
            // AV-103: on overturn the taker's full restitution
            // (penalty + refunded bond) rides `payout`; on uphold the
            // forfeited bond has no emitter slot here — it rides the
            // vault state (the real build carries it in
            // `amounts.penalty`).
            let payout = if matches!(outcome, escrow_state::AppealOutcome::Overturned) {
                penalty_refunded.saturating_add(bond_moved)
            } else {
                0
            };
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::AppealResolved,
                from,
                escrow.state() as u8,
                payout,
                0,
                0,
                now,
                None,
                None,
                None,
                None,
                Some(ctx.accounts.member.key()),
            );
            Ok(Some((outcome as u8, penalty_refunded, bond_moved)))
        } else {
            Ok(None)
        }
    }

    /// Sweep a filed slash appeal whose window lapsed unresolved
    /// (AV-103; mirrors `Escrow::expire_appeal`): `Funded -> Funded` —
    /// the appeal moves terminally to `Expired`, the slash stands, and
    /// the locked appeal bond (if any) is forfeited to the initializer
    /// (the anti-malicious-appeal-delay rule). AV-106: when the
    /// insurance pool is opted in the forfeit credits the pool
    /// instead — the bond stays in the vault, no initializer
    /// transfer. Permissionless, like `crank_expired`: anyone may
    /// crank a lapsed appeal — the caller signs only as the event
    /// actor; the forfeited bond routes to the initializer (or the
    /// pool), never the caller. `now` comes from the Solana clock
    /// sysvar (never an instruction param). Emits `AppealExpired`
    /// (from == to == `Funded`), mirroring
    /// `IndexedEscrow::expire_appeal`. Returns the forfeited bond (`0`
    /// when no bond was locked) so the real build can size the
    /// transfer to the initializer (zero when pool-routed).
    pub fn expire_appeal(ctx: Context<ExpireAppeal>) -> Result<u64> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let forfeited = escrow
            .expire_appeal(ctx.accounts.caller.key().to_bytes(), now)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::AppealExpired,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            now,
            None,
            None,
            None,
            None,
            Some(ctx.accounts.caller.key()),
        );
        Ok(forfeited)
    }

    /// Clear the AV-27 timelock by dual-signed emergency governance
    /// (AV-41; mirrors `Escrow::emergency_unlock`). Both the initializer
    /// and the taker must sign — one party alone is `Unauthorized`.
    /// `Funded` only, and only when the governance was opted in and an
    /// active timelock exists (`InvalidStateTransition` otherwise). The
    /// timelock clears to 0 immediately; state and amounts are
    /// untouched. Emits `EmergencyUnlock` (from == to == the current
    /// state), mirroring `IndexedEscrow::emergency_unlock`.
    pub fn emergency_unlock(ctx: Context<EmergencyUnlock>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        escrow
            .emergency_unlock(
                ctx.accounts.initializer.key().to_bytes(),
                ctx.accounts.taker.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Clears `vault.timelock` to 0 in the real build (in place — the
        // 8-byte region is always reserved).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::EmergencyUnlock,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Close the vault account and reclaim the rent-exempt deposit
    /// (`Cancelled | Released | Settled -> Closed`; mirrors
    /// `Escrow::close_vault`). Only the initializer may call this —
    /// the state machine checks authority before state validity
    /// (`Unauthorized` otherwise, so strangers learn nothing about
    /// state); only a terminal vault may be closed
    /// (`InvalidStateTransition` otherwise — `Disputed` is not a
    /// terminal state, and `Closed` is the deepest terminal, so a
    /// second close fails too).
    ///
    /// Solana rent economics: the vault account has carried the
    /// rent-exempt minimum for `escrow_state::VAULT_SPACE` since
    /// `initialize` (see `escrow_state::check_vault_rent_exempt`); once
    /// the escrow reached a terminal state the account serves no
    /// purpose, but the lamports stay locked until the account closes.
    /// The state machine returns the reclaimed amount
    /// (`escrow_state::vault_close_rent_reclaimed`); in the real build
    /// the account itself closes through Anchor's `close` constraint on
    /// `CloseVault` — the runtime transfers the account's lamports
    /// (including the rent-exempt deposit) to the initializer and zeroes
    /// the account, so no explicit system-program CPI is needed.
    /// AV-18: emits `VaultClosed` with `from` the terminal state and
    /// `to == Closed`. The real build's `EscrowVaultEvent` gains a
    /// `rent_reclaimed` amounts field mirroring
    /// `escrow_state::EventAmounts::rent_reclaimed` (carrying the
    /// returned amount); the skeleton's `emit_transition` keeps its
    /// current shape until the real build wires the event struct.
    pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // The reclaimed rent-exempt lamports
        // (`escrow_state::vault_close_rent_reclaimed`): the real build's
        // account-close transfers the account's lamports to
        // `accounts.initializer` via the `close` constraint on
        // `CloseVault` — the state machine moves no funds itself.
        let _rent = escrow
            .close_vault(ctx.accounts.initializer.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::VaultClosed,
            from,
            escrow.state() as u8,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Release the full remaining lockup to the taker and close the
    /// vault account in the same atomic instruction (AV-50; mirrors
    /// `Escrow::release_and_close`). One signature instead of two —
    /// the initializer saves a signature fee — and the rent-exempt
    /// deposit returns to the initializer together with the payout.
    ///
    /// The state machine runs the exact `release` gates for the full
    /// remainder (authority, state, mint binding, payout policy AV-49,
    /// milestone plan, quorum, timelock AV-27, amount math), then
    /// `close_vault`'s (AV-34: initializer-only, terminal-state gate);
    /// either leg failing rolls the whole call back — on-chain the
    /// failed instruction aborts the transaction, so no state change
    /// persists. Returns `(taker_payout, fee, rent_reclaimed)` so the
    /// real build can size the payout, fee and account-close transfers.
    /// AV-16: the vault token account's mint must equal the bound
    /// `vault.mint` (`MintMismatch` otherwise); `None` on the native-SOL
    /// path.
    pub fn release_and_close(ctx: Context<ReleaseAndClose>) -> Result<(u64, u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-27: the timelock gate reads the Solana clock sysvar — never
        // an instruction param, so the initializer cannot fast-forward
        // the lock they configured.
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let (payout, fee, rent) = escrow
            .release_and_close(
                ctx.accounts.initializer.key().to_bytes(),
                now,
                vault_token_mint(&ctx.accounts.vault_token_account),
                ctx.accounts.payout_to.key().to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_payout` (`PayoutKind::Release`)
        // for the (payout, fee) legs — the same validated plan `release`
        // uses — then the `close` constraint on `ReleaseAndClose`
        // transfers the account's remaining lamports (the rent-exempt
        // deposit, `rent` lamports) to `accounts.initializer` and zeroes
        // the account.
        // AV-18: two events in fixed order — `Released` (from == Funded,
        // to == Released, gross payout + fee) then `VaultClosed`
        // (from == Released, to == Closed, rent_reclaimed) — mirroring
        // `escrow_state::IndexedEscrow::release_and_close`.
        let at = Clock::get()?.unix_timestamp as u64;
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::Released,
            from,
            escrow_state::EscrowState::Released as u8,
            payout + fee,
            fee,
            0,
            at,
            None,
            None,
            None,
            None,
            None,
        );
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::VaultClosed,
            escrow_state::EscrowState::Released as u8,
            escrow.state() as u8,
            0,
            0,
            0,
            at,
            None,
            None,
            None,
            None,
            None,
        );
        Ok((payout, fee, rent))
    }

    /// Settle one basket leg to the taker (AV-95b; mirrors
    /// `Escrow::release_basket`). The leg is named by its SPL token
    /// account's mint — the real build reads
    /// `vault_token_account.mint` and the state machine requires it to
    /// be one of the basket's legs (`InvalidBasket`, code 152,
    /// otherwise — including on a plain non-basket escrow, which has
    /// no legs to settle).
    ///
    /// One leg (one SPL mint) settles per call: `Funded -> Funded`
    /// while legs remain, `Funded -> Released` on the last leg. The
    /// check order mirrors `release` (authority -> basket presence ->
    /// Funded -> leg lookup -> quorum -> timelock AV-27); the AV-17
    /// protocol fee is charged on the leg's gross remainder.
    /// Returns `(payout, fee)` so the real build can size the leg's
    /// token transfer to the taker and the fee transfer.
    pub fn release_basket(ctx: Context<ReleaseBasket>) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-27: the timelock gate reads the Solana clock sysvar — never
        // an instruction param, so the initializer cannot fast-forward
        // the lock they configured.
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let (payout, fee) = escrow
            .release_basket(
                ctx.accounts.initializer.key().to_bytes(),
                now,
                vault_token_mint(&ctx.accounts.vault_token_account),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_payout` (`PayoutKind::Release`)
        // — the real build transfers the leg's net payout to the
        // taker's token account for this leg's mint and the fee to the
        // fee account, once the token accounts are wired up.
        // AV-18: one `BasketReleased` event per settled leg (`now`
        // doubles as the event's `at`), mirroring
        // `escrow_state::IndexedEscrow::release_basket`.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::BasketReleased,
            from,
            escrow.state() as u8,
            payout + fee,
            fee,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok((payout, fee))
    }

    /// Refund one basket leg to the escrow's refund recipient (AV-95b;
    /// mirrors `Escrow::cancel_basket`). The leg is named by its SPL
    /// token account's mint (see `release_basket`).
    ///
    /// One leg settles per call: `Funded -> Funded` while legs remain,
    /// `Funded -> Cancelled` on the last leg. The check order mirrors
    /// `cancel` (authority -> basket presence -> Funded -> leg
    /// lookup); quorum / timelock do not gate this path — the
    /// initializer reclaims their own funds. No fee, no penalty.
    /// Unlike `cancel`, this instruction takes no caller-chosen
    /// refund destination: the real build transfers the leg's
    /// remainder to the escrow's own AV-23 refund policy (the
    /// whitelisted address, or the initializer). Returns the refunded
    /// leg remainder so the real build can size the token transfer.
    pub fn cancel_basket(ctx: Context<CancelBasket>) -> Result<u64> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let refunded = escrow
            .cancel_basket(
                ctx.accounts.initializer.key().to_bytes(),
                vault_token_mint(&ctx.accounts.vault_token_account),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_refund` (`RefundKind::Cancel`) —
        // the real build transfers the leg's remainder to the refund
        // recipient account once the token accounts are wired up.
        // AV-18: one `BasketCancelled` event per settled leg, mirroring
        // `escrow_state::IndexedEscrow::cancel_basket`.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::BasketCancelled,
            from,
            escrow.state() as u8,
            0,
            0,
            refunded,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(refunded)
    }

    /// Refund one basket leg after expiry (AV-95b; mirrors
    /// `Escrow::cancel_expired_basket`). Either the initializer or the
    /// taker may call once the expiry gate passes (`now >= expires_at
    /// + grace_period`); the leg is named by its SPL token account's
    /// mint (see `release_basket`).
    ///
    /// One leg settles per call: `Funded -> Funded` while legs remain,
    /// `Funded -> Cancelled` on the last leg. The check order mirrors
    /// `cancel_expired` (authority -> basket presence -> Funded -> leg
    /// lookup -> expiry gate). The AV-24 anti-griefing penalty applies
    /// to the leg's remainder on a *taker-initiated* cancel (routed to
    /// the initializer); an initializer-initiated cancel pays no
    /// penalty. Returns `(refund, penalty)` so the real build can size
    /// both transfers.
    pub fn cancel_expired_basket(ctx: Context<CancelExpiredBasket>) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let (refund, penalty) = escrow
            .cancel_expired_basket(
                ctx.accounts.authority.key().to_bytes(),
                now,
                vault_token_mint(&ctx.accounts.vault_token_account),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_refund`
        // (`RefundKind::CancelExpired`) — the real build transfers the
        // leg's net refund to the refund recipient and the AV-24
        // penalty (non-zero only on a taker-initiated cancel) to the
        // initializer, once the token accounts are wired up.
        // AV-18: `now` doubles as the event's `at`, mirroring
        // `IndexedEscrow::cancel_expired_basket`. The real build's
        // `EscrowVaultEvent` gains a `penalty` amounts field mirroring
        // `escrow_state::EventAmounts::penalty`; the skeleton's
        // `emit_transition` keeps its current shape until the real
        // build wires the event struct (the `cancel_expired`
        // precedent).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::BasketExpiredCancelled,
            from,
            escrow.state() as u8,
            0,
            0,
            refund,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok((refund, penalty))
    }

    /// Release every unsettled basket leg atomically to `payout_to`
    /// (AV-95c; mirrors `escrow_state::Escrow::release_basket_all`).
    /// `Funded -> Released` in one transition: the whole multi-mint
    /// table settles at once instead of N per-leg calls.
    ///
    /// The check order mirrors `release_basket` (authority -> basket
    /// presence -> Funded -> AV-49 payout pin on `payout_to`
    /// (`PayoutNotAllowlisted`, code 127) -> quorum -> timelock
    /// AV-27); the AV-17 protocol fee is charged per leg (floored per
    /// leg, no dust carried across legs). Atomic — any leg failure
    /// rolls the whole settlement back. Legs with a zero remainder
    /// are skipped (`AmountMismatch` when none).
    /// Returns `(total_net, total_fee)` — the Σ net payout and the Σ
    /// protocol fee — so the real build can size the per-mint
    /// transfers (the per-leg `(mint, payout_to, net)` table comes
    /// from the state machine's `BasketSettlement`).
    pub fn release_basket_all(
        ctx: Context<ReleaseBasketAll>,
        payout_to: Pubkey,
    ) -> Result<(u64, u64)> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        // AV-27: the timelock gate reads the Solana clock sysvar — never
        // an instruction param, so the initializer cannot fast-forward
        // the lock they configured.
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let settlement = escrow
            .release_basket_all(
                ctx.accounts.initializer.key().to_bytes(),
                now,
                payout_to.to_bytes(),
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_payout` (`PayoutKind::Release`)
        // — the real build transfers each leg's net payout to
        // `payout_to`'s token account for that leg's mint and the Σ fee
        // to the fee account, once the token accounts are wired up.
        // AV-18: one `BasketReleased` event with Σ amounts (`now`
        // doubles as the event's `at`), mirroring
        // `escrow_state::IndexedEscrow::release_basket_all`.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::BasketReleased,
            from,
            escrow.state() as u8,
            settlement.total_gross(),
            settlement.fee,
            0,
            now,
            None,
            None,
            None,
            None,
            None,
        );
        Ok((settlement.total_net(), settlement.fee))
    }

    /// Refund every unsettled basket leg to the escrow's refund
    /// recipient (AV-95c; mirrors
    /// `escrow_state::Escrow::cancel_basket_all`). `Funded ->
    /// Cancelled` in one transition.
    ///
    /// The check order mirrors `cancel_basket` (authority -> basket
    /// presence -> Funded); quorum / timelock do not gate this path —
    /// the initializer reclaims their own funds. No fee, no penalty.
    /// Unlike `cancel`, this instruction takes no caller-chosen
    /// refund destination: the real build transfers each leg's
    /// remainder to the escrow's own AV-23 refund policy (the
    /// whitelisted address, or the initializer). Atomic — any leg
    /// failure rolls the whole cancel back; legs with a zero
    /// remainder are skipped (`AmountMismatch` when none).
    /// Returns the Σ refunded remainder so the real build can size
    /// the per-mint refund transfers.
    pub fn cancel_basket_all(ctx: Context<CancelBasketAll>) -> Result<u64> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let from = escrow.state() as u8;
        let settlement = escrow
            .cancel_basket_all(ctx.accounts.initializer.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // AV-31: settle via `cpi_settle_refund` (`RefundKind::Cancel`) —
        // the real build transfers each leg's remainder to the refund
        // recipient account once the token accounts are wired up.
        // AV-18: one `BasketCancelled` event with the Σ refund,
        // mirroring `escrow_state::IndexedEscrow::cancel_basket_all`.
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::BasketCancelled,
            from,
            escrow.state() as u8,
            0,
            0,
            settlement.total_net(),
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(settlement.total_net())
    }

    /// Grant a bounded slice of the caller's authority to an operator
    /// (AV-104; mirrors `Escrow::delegate_authority` — the Solana
    /// "approve a delegate" pattern for transition rights). Only the
    /// initializer or the taker may grant: a stranger is
    /// `Unauthorized`, and the operator cannot sub-delegate (the grant
    /// is a party power). `Uninitialized` / `Funded` only
    /// (`InvalidStateTransition` otherwise); the zero operator key, an
    /// empty scope bitmap, or scope bits outside
    /// `escrow_state::DELEGATION_SCOPE_MASK` are `InvalidDelegation`
    /// (code 160). The grant overwrites any previous grant (single
    /// slot) and writes the 37-byte region in place — no realloc in
    /// the real build. Emits `DelegationGranted` (from == to == the
    /// current state) on an actual change; an identical re-grant is a
    /// no-op success that emits nothing (the handler re-reads the
    /// vault after the transition and skips the emit when the grant
    /// is unchanged, mirroring `update_payout_allowlist`).
    pub fn delegate_authority(
        ctx: Context<DelegateAuthority>,
        delegate: Pubkey,
        scopes: u32,
    ) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        let before = escrow.delegation();
        escrow
            .delegate_authority(
                ctx.accounts.caller.key().to_bytes(),
                delegate.to_bytes(),
                scopes,
            )
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Writes `vault.delegation` in place in the real build
        // (37 bytes, always reserved, zeroed when `None`).
        if escrow.delegation() != before {
            emit_transition(
                &ctx.accounts.vault,
                escrow_state::EscrowEventKind::DelegationGranted,
                state,
                state,
                0,
                0,
                0,
                Clock::get()?.unix_timestamp as u64,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Revoke the live operator grant (AV-104; mirrors
    /// `Escrow::revoke_delegation`). Either party may revoke — the
    /// initializer can cut off a taker-appointed operator and vice
    /// versa. `Uninitialized` / `Funded` only; no live grant is
    /// `InvalidDelegation` (code 160). Clears the 37-byte delegation
    /// region in place. Emits `DelegationRevoked` (from == to == the
    /// current state).
    pub fn revoke_delegation(ctx: Context<RevokeDelegation>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let state = escrow.state() as u8;
        escrow
            .revoke_delegation(ctx.accounts.caller.key().to_bytes())
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Clears `vault.delegation` to `None` in the real build
        // (in place — the 37-byte region is always reserved).
        emit_transition(
            &ctx.accounts.vault,
            escrow_state::EscrowEventKind::DelegationRevoked,
            state,
            state,
            0,
            0,
            0,
            Clock::get()?.unix_timestamp as u64,
            None,
            None,
            None,
            None,
            None,
        );
        Ok(())
    }

    /// Link two escrows as an atomic swap pair (AV-105; mirrors
    /// `escrow_state::link_swap`). Leg A is the X→Y leg, leg B the
    /// Y→X leg; on success each vault's `swap_link` records the
    /// counterparty's id. Both vaults must be `Uninitialized`
    /// (`InvalidStateTransition` otherwise); the parties must be
    /// mirrored and the asserted amounts must equal the locked
    /// amounts (`InvalidSwapParties` code 161 / `InvalidSwapAmounts`
    /// code 162 otherwise). Party-only: the caller must be one of the
    /// two parties — an AV-104 operator is `Unauthorized` (the
    /// delegation slot is never consulted). The real build requires
    /// *both* parties as signers. Writes each vault's 33-byte
    /// swap_link region in place. Emits `SwapLinked` on each vault
    /// (from == to == Uninitialized).
    pub fn link_swap(
        ctx: Context<LinkSwap>,
        escrow_id_a: [u8; 32],
        escrow_id_b: [u8; 32],
        amount_a: u64,
        amount_b: u64,
    ) -> Result<()> {
        let mut escrow_a = read_escrow(&ctx.accounts.vault_a);
        let mut escrow_b = read_escrow(&ctx.accounts.vault_b);
        let state = escrow_a.state() as u8;
        escrow_state::link_swap(
            &mut escrow_a,
            &mut escrow_b,
            ctx.accounts.caller.key().to_bytes(),
            escrow_id_a,
            escrow_id_b,
            amount_a,
            amount_b,
        )
        .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault_a, &escrow_a);
        write_escrow(&mut ctx.accounts.vault_b, &escrow_b);
        // Writes `vault.swap_link` in place in the real build
        // (33 bytes, always reserved, zeroed when `None`).
        let at = Clock::get()?.unix_timestamp as u64;
        for vault in [&ctx.accounts.vault_a, &ctx.accounts.vault_b] {
            emit_transition(
                vault,
                escrow_state::EscrowEventKind::SwapLinked,
                state,
                state,
                0,
                0,
                0,
                at,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Release both legs of a linked swap pair atomically (AV-105;
    /// mirrors `escrow_state::release_swap`). Either leg failing
    /// rolls the whole release back (the two-phase run emits nothing
    /// on failure). Party-only — an AV-104 operator is
    /// `Unauthorized`; the real build requires *both* parties as
    /// signers and each leg runs under its own initializer. `now`
    /// comes from the clock sysvar (never an instruction param).
    /// Emits `Released` on each vault (from Funded; partial releases
    /// carry from == to == Funded). Returns
    /// `(payout_a, fee_a, payout_b, fee_b)`.
    pub fn release_swap(
        ctx: Context<ReleaseSwap>,
        escrow_id_a: [u8; 32],
        escrow_id_b: [u8; 32],
        amount_a: u64,
        amount_b: u64,
    ) -> Result<(u64, u64, u64, u64)> {
        let mut escrow_a = read_escrow(&ctx.accounts.vault_a);
        let mut escrow_b = read_escrow(&ctx.accounts.vault_b);
        // AV-27: the timelock gate reads the Solana clock sysvar —
        // never an instruction param.
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let (payout_a, fee_a, payout_b, fee_b) = escrow_state::release_swap(
            &mut escrow_a,
            &mut escrow_b,
            ctx.accounts.caller.key().to_bytes(),
            escrow_id_a,
            escrow_id_b,
            now,
            amount_a,
            vault_token_mint(&ctx.accounts.vault_token_account_a),
            ctx.accounts.payout_to_a.key().to_bytes(),
            amount_b,
            vault_token_mint(&ctx.accounts.vault_token_account_b),
            ctx.accounts.payout_to_b.key().to_bytes(),
        )
        .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault_a, &escrow_a);
        write_escrow(&mut ctx.accounts.vault_b, &escrow_b);
        // AV-18: `payout + fee` is the gross amount per leg; the
        // closing release carries to == Released.
        let at = Clock::get()?.unix_timestamp as u64;
        emit_transition(
            &ctx.accounts.vault_a,
            escrow_state::EscrowEventKind::Released,
            escrow_state::EscrowState::Funded as u8,
            escrow_a.state() as u8,
            payout_a + fee_a,
            fee_a,
            0,
            at,
            None,
            None,
            None,
            None,
            None,
        );
        emit_transition(
            &ctx.accounts.vault_b,
            escrow_state::EscrowEventKind::Released,
            escrow_state::EscrowState::Funded as u8,
            escrow_b.state() as u8,
            payout_b + fee_b,
            fee_b,
            0,
            at,
            None,
            None,
            None,
            None,
            None,
        );
        Ok((payout_a, fee_a, payout_b, fee_b))
    }

    /// Cancel both legs of a linked swap pair atomically (AV-105;
    /// mirrors `escrow_state::cancel_swap`): one party's cancel
    /// triggers the pair-wide cancel. The caller must be the
    /// initializer of at least one leg (party-only — a stranger or an
    /// AV-104 operator is `Unauthorized`); the real build requires
    /// *both* parties as signers and each leg runs under its own
    /// initializer. Emits `Cancelled` on each vault (from Funded to
    /// Cancelled).
    pub fn cancel_swap(
        ctx: Context<CancelSwap>,
        escrow_id_a: [u8; 32],
        escrow_id_b: [u8; 32],
    ) -> Result<()> {
        let mut escrow_a = read_escrow(&ctx.accounts.vault_a);
        let mut escrow_b = read_escrow(&ctx.accounts.vault_b);
        escrow_state::cancel_swap(
            &mut escrow_a,
            &mut escrow_b,
            ctx.accounts.caller.key().to_bytes(),
            escrow_id_a,
            escrow_id_b,
            vault_token_mint(&ctx.accounts.vault_token_account_a),
            ctx.accounts.refund_to_a.key().to_bytes(),
            vault_token_mint(&ctx.accounts.vault_token_account_b),
            ctx.accounts.refund_to_b.key().to_bytes(),
        )
        .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault_a, &escrow_a);
        write_escrow(&mut ctx.accounts.vault_b, &escrow_b);
        let at = Clock::get()?.unix_timestamp as u64;
        for vault in [&ctx.accounts.vault_a, &ctx.accounts.vault_b] {
            emit_transition(
                vault,
                escrow_state::EscrowEventKind::Cancelled,
                escrow_state::EscrowState::Funded as u8,
                escrow_state::EscrowState::Cancelled as u8,
                0,
                0,
                0,
                at,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Ok(())
    }

    /// Cancel both legs of a linked swap pair on expiry (AV-105;
    /// mirrors `escrow_state::cancel_swap_expired`). Atomic refusal:
    /// *both* legs must be expiry-eligible or the whole call fails
    /// with `NotExpired` — no partial expiry. Either party may call
    /// (the single-side path allows either party); an AV-104 operator
    /// is `Unauthorized`. The real build requires *both* parties as
    /// signers and each leg runs under the caller, so the AV-24
    /// anti-griefing penalty keys per leg exactly as the single-side
    /// path charges it. `now` comes from the clock sysvar. Emits
    /// `ExpiredCancelled` on each vault. Returns
    /// `(refund_a, penalty_a, refund_b, penalty_b)`.
    pub fn cancel_swap_expired(
        ctx: Context<CancelSwapExpired>,
        escrow_id_a: [u8; 32],
        escrow_id_b: [u8; 32],
    ) -> Result<(u64, u64, u64, u64)> {
        let mut escrow_a = read_escrow(&ctx.accounts.vault_a);
        let mut escrow_b = read_escrow(&ctx.accounts.vault_b);
        let now = read_clock_unix_timestamp(&ctx.accounts.clock);
        let (refund_a, penalty_a, refund_b, penalty_b) = escrow_state::cancel_swap_expired(
            &mut escrow_a,
            &mut escrow_b,
            ctx.accounts.caller.key().to_bytes(),
            escrow_id_a,
            escrow_id_b,
            now,
            vault_token_mint(&ctx.accounts.vault_token_account_a),
            ctx.accounts.refund_to_a.key().to_bytes(),
            vault_token_mint(&ctx.accounts.vault_token_account_b),
            ctx.accounts.refund_to_b.key().to_bytes(),
        )
        .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault_a, &escrow_a);
        write_escrow(&mut ctx.accounts.vault_b, &escrow_b);
        let at = Clock::get()?.unix_timestamp as u64;
        for vault in [&ctx.accounts.vault_a, &ctx.accounts.vault_b] {
            emit_transition(
                vault,
                escrow_state::EscrowEventKind::ExpiredCancelled,
                escrow_state::EscrowState::Funded as u8,
                escrow_state::EscrowState::Cancelled as u8,
                0,
                0,
                0,
                at,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Ok((refund_a, penalty_a, refund_b, penalty_b))
    }

    /// Opt the vault into the penalty insurance pool (AV-106;
    /// mirrors `escrow_state::initialize_insurance_pool`).
    /// Uninitialized-only, party-only (initializer). No params;
    /// sets `vault.insurance_pool` in place in the real build.
    pub fn initialize_insurance_pool(ctx: Context<InitializeInsurancePool>) -> Result<()> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        escrow_state::initialize_insurance_pool(&mut escrow)
            .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        // Writes `vault.insurance_pool` in place in the real build
        // (1 byte, always reserved, zeroed when `false`).
        Ok(())
    }

    /// Pay out from the insurance pool to an authorized beneficiary
    /// (AV-106; mirrors `escrow_state::pool_payout`). Caller must be
    /// the arbiter or the bound multisig PDA; the beneficiary passes
    /// the AV-49/AV-96 recipient gate. The pool must not be
    /// encumbered by a live appeal. `now` comes from the clock
    /// sysvar (never an instruction param). In the real build the
    /// vault token account transfers `amount` to the beneficiary's
    /// token account and `vault.pool_payout_paid` accumulates the
    /// payout in place.
    pub fn pool_payout(
        ctx: Context<PoolPayout>,
        beneficiary: [u8; 32],
        amount: u64,
    ) -> Result<u64> {
        let mut escrow = read_escrow(&ctx.accounts.vault);
        let now = Clock::get()?.unix_timestamp as u64;
        let paid = escrow_state::pool_payout(
            &mut escrow,
            ctx.accounts.authority.key().to_bytes(),
            beneficiary,
            amount,
            vault_token_mint(&ctx.accounts.vault_token_account),
            now,
        )
        .map_err(|e| escrow_error(e))?;
        write_escrow(&mut ctx.accounts.vault, &escrow);
        Ok(paid)
    }
}

// --- Account structs (skeleton: field layout finalized during real build) ---

#[account]
pub struct Vault {
    pub initializer: Pubkey,
    pub taker: Pubkey,
    pub amount: u64,
    /// Cumulative amount released via `release` so far (AV-11): partial
    /// releases accumulate here; always `<= amount`. Layout position
    /// matches `escrow_state::VAULT_FIELDS`.
    pub released: u64,
    /// Unix timestamp after which either party may cancel the escrow.
    pub expires_at: u64,
    // The authoritative state lives in `escrow_state::EscrowState`;
    // persisted here as a byte until the real build wires the enum.
    pub state: u8,
    /// Optional N-of-M attestor quorum gating `release`; mirrors
    /// `escrow_state::QuorumPolicy`. `None` for a plain two-party escrow.
    /// The account always reserves the full quorum region
    /// (`escrow_state::QUORUM_POLICY_LEN` bytes, zeroed when `None`) so
    /// `initialize_quorum` writes the policy in place without reallocating.
    /// Full serialized layout: `escrow_state::VAULT_FIELDS`.
    pub quorum: Option<Quorum>,
    /// AV-12: dual-signature activation bitmask (bit 0 initializer, bit 1
    /// taker, bit 2 dual-sig required); mirrors `escrow_state`'s
    /// `activation` field. Always present (one byte, zeroed for plain
    /// escrows). Layout position matches `escrow_state::VAULT_FIELDS`.
    pub activation: u8,
    /// AV-13: optional linear vesting schedule gating `claim`; mirrors
    /// `escrow_state::VestingSchedule`. `None` for an escrow with no
    /// vesting. The account always reserves the full 17-byte region
    /// (1-byte discriminant + start/end u64, zeroed when `None`) so
    /// `initialize_vesting` writes the schedule in place without
    /// reallocating. Full serialized layout: `escrow_state::VAULT_FIELDS`.
    pub vesting: Option<Vesting>,
    /// AV-14: optional dispute arbiter; mirrors the `arbiter` field of
    /// `escrow_state::Escrow`. `None` for an escrow with no arbitration.
    /// The account always reserves the full 33-byte region (1-byte
    /// discriminant + 32-byte key, zeroed when `None`) so
    /// `initialize_arbiter` writes the key in place without reallocating.
    /// Layout position matches `escrow_state::VAULT_FIELDS` (appended
    /// last, after `vesting`).
    pub arbiter: Option<Pubkey>,
    /// AV-15: optional milestone tranche plan; mirrors
    /// `escrow_state::MilestonePlan`. `None` for an escrow with no
    /// milestone schedule. The account always reserves the full 66-byte
    /// region (1-byte discriminant + eight tranche u64s + count byte,
    /// zeroed when `None`) so `initialize_milestones` writes the plan in
    /// place without reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `arbiter`).
    pub milestones: Option<MilestonePlan>,
    /// AV-15: per-milestone confirmation bitmap (six bits per milestone:
    /// the two parties' release-path confirmations, the released bit,
    /// the two parties' skip approvals, the skipped bit); mirrors
    /// `escrow_state`'s `milestone_flags`. Always present (one u64,
    /// zeroed for escrows without a milestone plan). Layout position
    /// matches `escrow_state::VAULT_FIELDS`.
    pub milestone_flags: u64,
    /// AV-15: cumulative amount skipped by mutual agreement; mirrors
    /// `escrow_state`'s `skipped`. Skipped tranches join the refundable
    /// remainder, not the taker-payout `released` counter. Always present
    /// (one u64, zeroed when nothing was skipped). Layout position
    /// matches `escrow_state::VAULT_FIELDS`.
    pub skipped: u64,
    /// AV-16: optional SPL token mint this escrow is bound to; mirrors
    /// `escrow_state`'s `mint`. `None` for a native-SOL escrow. The
    /// account always reserves the full 33-byte region (1-byte
    /// discriminant + 32-byte address, zeroed when `None`) so
    /// `initialize_mint` writes the address in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `skipped`).
    pub mint: Option<Pubkey>,
    /// AV-17: protocol fee rate in basis points (0-10000); mirrors
    /// `escrow_state`'s `fee_bps`. Always present (one u16, zeroed when
    /// no fee is configured). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `mint`).
    pub fee_bps: u16,
    /// AV-17: cumulative protocol fee charged across payouts; mirrors
    /// `escrow_state`'s `fees_paid`. Always present (one u64, zeroed
    /// when no fee was charged). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `fee_bps`).
    pub fees_paid: u64,
    /// AV-21: expiry grace period in seconds; mirrors `escrow_state`'s
    /// `grace_period`. Always present (one u64, zeroed when no grace
    /// period is configured). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `fees_paid`).
    pub grace_period: u64,
    /// AV-22: 32-byte commitment to the off-chain dispute evidence
    /// attached at `escalate`; mirrors `escrow_state`'s `evidence_hash`.
    /// `None` when no evidence was attached. The account always reserves
    /// the full 33-byte region (1-byte discriminant + 32-byte
    /// commitment, zeroed when `None`) so `escalate` writes the hash in
    /// place without reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `grace_period`).
    pub evidence_hash: Option<[u8; 32]>,
    /// AV-23: opt-in refund address whitelist; mirrors
    /// `escrow_state`'s `refund_to`. `None` for an escrow with no
    /// whitelist (refunds go to the initializer). The account always
    /// reserves the full 33-byte region (1-byte discriminant + 32-byte
    /// address, zeroed when `None`) so `initialize_refund_address`
    /// writes the address in place without reallocating. Layout position
    /// matches `escrow_state::VAULT_FIELDS` (appended last, after
    /// `evidence_hash`).
    pub refund_to: Option<Pubkey>,
    /// AV-24: anti-griefing penalty rate in basis points; mirrors
    /// `escrow_state`'s `penalty_bps`. `0` for an escrow with no penalty
    /// configured. Always present (2 bytes, zeroed by default) so
    /// `initialize_penalty` writes the rate in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `refund_to`).
    pub penalty_bps: u16,
    /// AV-27: timelock unlock timestamp; mirrors `escrow_state`'s
    /// `timelock`. `0` for an escrow with no timelock configured.
    /// Always present (8 bytes, zeroed by default) so
    /// `initialize_timelock` writes the timestamp in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `penalty_bps`).
    pub timelock: u64,
    /// AV-28: token decimal metadata; mirrors `escrow_state`'s
    /// `decimals` (the SPL mint's decimal places, `0` = no decimal
    /// metadata). Always present (1 byte, zeroed by default) so
    /// `initialize_decimals` writes the precision in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `timelock`).
    /// Display-only: it never gates a transition and never moves funds.
    pub decimals: u8,
    /// AV-38: 32-byte commitment to the arbiter's off-chain rationale
    /// document (e.g. the SHA-256 of the written ruling), attached at
    /// `resolve`; mirrors `escrow_state`'s `rationale_hash`. `None`
    /// when the arbiter supplied no rationale. The account always
    /// reserves the full 33-byte region (1-byte discriminant + 32-byte
    /// commitment, zeroed when `None`) so `resolve` writes the hash in
    /// place without reallocating; never cleared — it stays on the
    /// vault in `Settled` as the audit trail of the arbitration,
    /// following the AV-22 `evidence_hash` convention. Layout position
    /// matches `escrow_state::VAULT_FIELDS` (appended last, after
    /// `decimals`).
    pub rationale_hash: Option<[u8; 32]>,
    /// AV-41: emergency timelock-unlock governance opt-in; mirrors
    /// `escrow_state`'s `emergency_unlock`. `false` for an escrow without
    /// the governance capability. Always present (1 byte, zeroed by
    /// default) so `initialize_emergency_unlock` writes the flag in
    /// place without reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `rationale_hash`).
    pub emergency_unlock: bool,
    /// AV-44: opt-in protocol-fee recipient; mirrors
    /// `escrow_state`'s `fee_recipient`. `None` for an escrow with no
    /// pinned recipient (fee legs route to the program-level fee
    /// account). The account always reserves the full 33-byte region
    /// (1-byte discriminant + 32-byte address, zeroed when `None`) so
    /// `initialize_fee_recipient` writes the address in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `emergency_unlock`).
    pub fee_recipient: Option<Pubkey>,
    /// AV-46: opt-in emergency-pause authority; mirrors
    /// `escrow_state`'s `pause_authority`. `None` for an escrow with no
    /// pause switch. The account always reserves the full 33-byte region
    /// (1-byte discriminant + 32-byte address, zeroed when `None`) so
    /// `initialize_pause_authority` writes the address in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `fee_recipient`).
    pub pause_authority: Option<Pubkey>,
    /// AV-46: emergency pause flag; mirrors `escrow_state`'s `paused`.
    /// `false` for a live escrow. Always present (1 byte, zeroed by
    /// default) so `pause` / `unpause` flip it in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `pause_authority`).
    pub paused: bool,
    /// AV-49: payout destination allowlist; mirrors
    /// `escrow_state::PayoutAllowlist`. `None` for an escrow with no
    /// allowlist (payouts go to the taker). The account always reserves
    /// the full 130-byte region (1-byte discriminant + 4×32-byte
    /// addresses + 1-byte count, zeroed when `None`) so
    /// `initialize_payout_allowlist` / `update_payout_allowlist` write
    /// the list in place without reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `paused`).
    pub payout_allowlist: Option<PayoutAllowlist>,
    /// AV-53: opt-in 32-byte off-chain reference memo (e.g. order id /
    /// invoice hash); mirrors `escrow_state`'s `reference`. `None` for
    /// an escrow with no attached memo. The account always reserves the
    /// full 33-byte region (1-byte discriminant + 32-byte correlation
    /// id, zeroed when `None`) so `initialize_reference` writes it in
    /// place without reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `payout_allowlist`). Read-only pass-through: no check gate
    /// reads it, no transition clears it — it only feeds the
    /// `EscrowVaultEvent::reference` indexer field, the keeper report
    /// and the snapshot export for off-chain reconciliation.
    pub reference: Option<[u8; 32]>,
    /// AV-55: Unix timestamp at which the escrow entered `Disputed`,
    /// recorded by `escalate`; mirrors `escrow_state`'s `disputed_at`.
    /// The pre-agreed default judgment's deadline is measured from this
    /// timestamp (`trigger_default_judgment` fires once `now >=
    /// disputed_at + deadline_secs`). Always present (8 bytes, zeroed
    /// when the escrow was never disputed). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `reference`).
    pub disputed_at: u64,
    /// AV-55: the dual-signed pre-agreed arbitration default judgment;
    /// mirrors `escrow_state`'s `default_judgment`. `None` for an escrow
    /// with no configured judgment. The account always reserves the
    /// full 17-byte region (1-byte discriminant + 16-byte judgment,
    /// zeroed when `None`) so `initialize_default_judgment` writes it
    /// in place without reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `disputed_at`).
    pub default_judgment: Option<DefaultJudgment>,
    /// AV-55: whether the taker confirmed the pre-agreed split via
    /// `confirm_default_judgment`; mirrors `escrow_state`'s
    /// `default_confirmed`. Always present (1 byte, zeroed when
    /// unconfirmed). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `default_judgment`).
    pub default_confirmed: bool,
    /// AV-56: the periodic (subscription-style) release schedule;
    /// mirrors `escrow_state`'s `subscription`. `None` for an escrow
    /// with no schedule attached. The account always reserves the full
    /// 18-byte region (1-byte discriminant + 17-byte schedule, zeroed
    /// when `None`) so `initialize_subscription` writes it in place
    /// without reallocating. Mutually exclusive with the milestone
    /// tranche plan (AV-15) — an escrow carries at most one release
    /// schedule. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `default_confirmed`).
    pub subscription: Option<SubscriptionSchedule>,
    /// AV-56: the index of the next subscription period due for
    /// release; mirrors `escrow_state`'s `subscription_next`. Always
    /// present (1 byte, zeroed when no schedule is attached), advanced
    /// strictly in order by `release_period` — the `period_index`
    /// param must equal this counter, so skipping ahead or replaying a
    /// released period is impossible. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `subscription`).
    pub subscription_next: u8,
    /// AV-56: the per-period released bitmap — bit `i` is set once
    /// period `i` has paid out; mirrors `escrow_state`'s
    /// `subscription_released`. Always present (8 bytes, zeroed when
    /// no schedule is attached); the `release_period` `period_index`
    /// param selects which bit flips, so the bitmap and the in-order
    /// counter double-guard the each-period-releases-once rule.
    /// Layout position matches `escrow_state::VAULT_FIELDS`
    /// (appended last, after `subscription_next`).
    pub subscription_released: u64,
    /// AV-57: event-history ring-buffer write cursor — the index of
    /// the oldest entry once the buffer is full (and the slot the
    /// next record overwrites); mirrors `escrow_state`'s
    /// `event_head`. Always present (1 byte, zeroed when no events
    /// were recorded). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `subscription_released`).
    pub event_head: u8,
    /// AV-57: monotonic total of events ever recorded on this vault —
    /// never decreases, even as the ring overwrites the oldest
    /// entries, so an indexer can detect history loss; mirrors
    /// `escrow_state`'s `event_total`. Always present (8 bytes,
    /// zeroed when no events were recorded). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `event_head`).
    pub event_total: u64,
    /// AV-57: number of valid entries currently in the ring
    /// (`<= event_capacity`); mirrors `escrow_state`'s
    /// `event_count`. Always present (1 byte, zeroed when no events
    /// were recorded). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `event_total`).
    pub event_count: u8,
    /// AV-57: configured ring capacity (1..=64, default 64); mirrors
    /// `escrow_state`'s `event_capacity`. The account always reserves
    /// all 64 slots, so a smaller capacity never needs a realloc.
    /// Always present (1 byte). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `event_count`).
    pub event_capacity: u8,
    /// AV-57: the 64 fixed event-history slots in slot order; mirrors
    /// `escrow_state`'s `event_slots`. Each slot is kind u8 + at u64 +
    /// actor tag u8 + actor summary 8 bytes (18 bytes); slots past
    /// the configured capacity stay zeroed. Always present (1152
    /// bytes). Layout position matches `escrow_state::VAULT_FIELDS`
    /// (appended last, after `event_capacity`).
    pub event_slots: [EventHistorySlot; 64],
    /// AV-59: per-extension expiry-increase bound in seconds; mirrors
    /// `escrow_state`'s `max_extension_secs`. Always present (8 bytes,
    /// zeroed when extension is not enabled). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `event_slots`).
    pub max_extension_secs: u64,
    /// AV-59: monotonic count of executed expiry extensions; mirrors
    /// `escrow_state`'s `extension_count`. Always present (8 bytes,
    /// zeroed when never extended). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `max_extension_secs`).
    pub extension_count: u64,
    /// AV-63: absolute protocol-fee ceiling in lamports; mirrors
    /// `escrow_state`'s `fee_cap`. `0` for an escrow with no cap
    /// configured (uncapped — a zero *fee* is expressed via
    /// `fee_bps == 0`). Always present (8 bytes, zeroed by default) so
    /// `initialize_fee_cap` writes the ceiling in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `extension_count`).
    pub fee_cap: u64,
    /// AV-64: relative timelock duration in seconds; mirrors
    /// `escrow_state`'s `relative_timelock_secs`. `0` for an escrow
    /// with no relative timelock configured. Always present (8 bytes,
    /// zeroed by default) so `initialize_relative_timelock` writes the
    /// duration in place without reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `fee_cap`).
    pub relative_timelock_secs: u64,
    /// AV-64: Unix timestamp at which the escrow was funded, recorded
    /// by `fund` from the Solana clock sysvar; mirrors
    /// `escrow_state`'s `fund_at`. The origin the relative timelock is
    /// measured from: payouts unlock at `fund_at +
    /// relative_timelock_secs`. Always present (8 bytes, zeroed when
    /// the escrow was never funded). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `relative_timelock_secs`).
    pub fund_at: u64,
    /// AV-65: opt-in arbiter panel; mirrors `escrow_state`'s
    /// `arbiter_panel`. `None` for an escrow with no panel configured
    /// (single-arbiter mode or no arbitration). The account always
    /// reserves the full 595-byte region (1-byte discriminant +
    /// 594-byte panel: member count + threshold + 8 member keys + 8
    /// vote slots + voted bitmask, zeroed when `None`) so
    /// `initialize_arbiter_panel` writes the committee in place without
    /// reallocating. Mutually exclusive with the single arbiter
    /// (`arbiter`) — last-wins in both directions. Layout position
    /// matches `escrow_state::VAULT_FIELDS` (appended last, after
    /// `fund_at`).
    pub arbiter_panel: Option<ArbiterPanel>,
    /// AV-66: opt-in tiered protocol-fee schedule; mirrors
    /// `escrow_state`'s `fee_schedule`. The account always reserves
    /// the full 81-byte region (1-byte live-tier count + 8 fixed
    /// 10-byte tier slots, zeroed — `tier_count == 0` — when no
    /// schedule is configured) so `initialize_fee_schedule` writes
    /// the ladder in place without reallocating. Mutually exclusive
    /// with the flat rate (`fee_bps`) — fail-fast in both directions.
    /// Layout position matches `escrow_state::VAULT_FIELDS` (appended
    /// last, after `arbiter_panel`).
    pub fee_schedule: FeeSchedule,
    /// AV-75: schema version of the persisted layout; mirrors
    /// `escrow_state`'s `schema_version`. New vaults are born at
    /// `escrow_state::Escrow::SCHEMA_VERSION`; a vault written before
    /// AV-75 reads `0` until the initializer runs `migrate_schema`.
    /// Always present (1 byte). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `fee_schedule`).
    pub schema_version: u8,
    /// AV-82: opt-in default-penalty (slash) terms; mirrors
    /// `escrow_state::SlashTerms`. `None` for an escrow with no slash
    /// clause. The account always reserves the full 41-byte region
    /// (1-byte discriminant + 32-byte penalty account + u64 slash
    /// deadline, zeroed when `None`) so `initialize_slash_terms`
    /// writes the terms in place without reallocating. Layout position
    /// matches `escrow_state::VAULT_FIELDS` (appended after
    /// `schema_version` — v2 layout).
    pub slash_terms: Option<SlashTerms>,
    /// AV-82: cumulative amount slashed to the penalty account via
    /// `slash`; mirrors `escrow_state`'s `penalty_paid`. Kept separate
    /// from `released` — the audit trail distinguishes a default
    /// penalty from a taker payout. Always present (8 bytes, zeroed
    /// when never slashed). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last).
    pub penalty_paid: u64,
    /// AV-83: opt-in CPI target-program allowlist; mirrors
    /// `escrow_state`'s `cpi_allowlist`. `None` for an escrow that
    /// allows any target program in `release_via_cpi`. The account
    /// always reserves the full 258-byte region (1-byte count + 8
    /// 32-byte program ids, zeroed when `None`) so
    /// `initialize_cpi_allowlist` writes it in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `penalty_paid`). Fail-closed: `release_via_cpi` rejects a
    /// target program not on the list with `InvalidCpiTarget` (code
    /// 120), with full rollback — a phishing frontend cannot steer
    /// the payout through a hostile program by swapping the target.
    pub cpi_allowlist: Option<CpiAllowlist>,
    /// AV-84: opt-in multisig authority binding; mirrors
    /// `escrow_state`'s `multisig_authority`. `None` for an escrow
    /// with no multisig binding. The account always reserves the full
    /// 67-byte region (1-byte discriminant + 32-byte multisig program
    /// id + 32-byte authority PDA + u16 threshold, zeroed when `None`)
    /// so `initialize_multisig_authority` writes it in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `cpi_allowlist`). Read-only pass-through: no check gate reads
    /// it — the escrow's authority checks compare signer keys exactly
    /// as for an EOA, and the external multisig program guarantees the
    /// PDA only signs once its threshold voted (zero-trust).
    pub multisig_authority: Option<MultisigAuthority>,
    /// AV-90: opt-in non-linear vesting unlock curve; mirrors
    /// `escrow_state`'s `vesting_curve`. `None` for the plain AV-13
    /// linear unlock. The account always reserves the full 82-byte
    /// region (1-byte discriminant + 81-byte tier region, zeroed when
    /// `None`) so `initialize_vesting_curve` writes it in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `multisig_authority`).
    pub vesting_curve: Option<VestingCurve>,
    /// AV-91: the SHA-256 Merkle root over the dispute-evidence
    /// document set committed at `escalate`; mirrors
    /// `escrow_state`'s `evidence_root`. `None` when no multi-doc
    /// evidence was committed (the plain AV-22 single-hash path).
    /// Never cleared. The account always reserves the full 33-byte
    /// region (1-byte discriminant + 32-byte root, zeroed when `None`)
    /// so `escalate` writes it in place without reallocating. Layout
    /// position matches `escrow_state::VAULT_FIELDS` (appended last,
    /// after `vesting_curve`).
    pub evidence_root: Option<[u8; 32]>,
    /// AV-91: the leaf count the committed evidence Merkle tree was
    /// built over; mirrors `escrow_state`'s `evidence_leaves` (`0`
    /// when `evidence_root` is `None`, `1..=64` otherwise). Never
    /// cleared. Layout position matches `escrow_state::VAULT_FIELDS`
    /// (appended last, after `evidence_root`).
    pub evidence_leaves: u8,
    /// AV-91: the evidence-disclosure bitmap; mirrors
    /// `escrow_state`'s `evidence_disclosed` — bit `i` flips once the
    /// document at leaf index `i` is disclosed via `file_evidence`
    /// with a valid Merkle inclusion proof. Never cleared. Layout
    /// position matches `escrow_state::VAULT_FIELDS` (appended last,
    /// after `evidence_leaves`).
    pub evidence_disclosed: u64,
    /// AV-96: opt-in payout destination denylist (the initializer's
    /// compliance veto); mirrors `escrow_state`'s `payout_denylist`.
    /// `None` for an escrow with no veto. The account always reserves
    /// the full 130-byte region (1-byte discriminant + 4×32-byte
    /// addresses + 1-byte count, zeroed when `None`) so
    /// `initialize_payout_denylist` / `update_payout_denylist` write
    /// the list in place without reallocating. Deny takes precedence
    /// over the AV-49 allowlist: a destination on both lists is
    /// rejected with `PayoutDenied` (code 153). Layout position
    /// matches `escrow_state::VAULT_FIELDS` (appended last, after
    /// `evidence_disclosed`).
    pub payout_denylist: Option<PayoutDenylist>,
    /// AV-97: opt-in Dutch-auction settlement terms (the
    /// descending-price pull path for the taker); mirrors
    /// `escrow_state`'s `auction`. `None` for an escrow with no
    /// auction. The account always reserves the full 19-byte region
    /// (1-byte discriminant + 18-byte terms, zeroed when `None`) so
    /// `initialize_dutch_auction` writes the terms in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `payout_denylist`).
    pub auction: Option<DutchAuction>,
    /// AV-99: opt-in Token-2022 transfer-hook program (mirrors
    /// `escrow_state`'s `transfer_hook`); `None` for an escrow with
    /// no hook. The account always reserves the full 33-byte region
    /// (1-byte discriminant + 32-byte program id, zeroed when `None`)
    /// so `initialize_transfer_hook` writes the binding in place
    /// without reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after `auction`).
    pub transfer_hook: Option<[u8; 32]>,
    /// AV-100: streaming fee rate in lamports per second of funded
    /// time (mirrors `escrow_state`'s `streaming_fee_rate`); `0`
    /// disables the fee. The account always reserves the 8 bytes so
    /// `initialize_streaming_fee` writes in place without
    /// reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `transfer_hook`).
    pub streaming_fee_rate: u64,
    /// AV-100: cumulative streaming fee already charged (mirrors
    /// `escrow_state`'s `streaming_fees_accrued`); the 8 bytes ride
    /// the same always-reserved region as `streaming_fee_rate`.
    pub streaming_fees_accrued: u64,
    /// AV-104: the delegated operator grant (mirrors
    /// `escrow_state`'s `delegation`); `None` when no grant is live.
    /// The account always reserves the full 37-byte region (1-byte
    /// discriminant + 32-byte operator key + 4-byte scope bitmap,
    /// zeroed when `None`) so `delegate_authority` /
    /// `revoke_delegation` write in place without reallocating.
    /// Layout position matches `escrow_state::VAULT_FIELDS`
    /// (appended last, after `appeal_bond_paid`).
    pub delegation: Option<Delegation>,
    /// AV-105: the atomic-swap counterparty's escrow id (mirrors
    /// `escrow_state`'s `swap_link`); `None` when the escrow is not
    /// linked into a swap pair. The account always reserves the full
    /// 33-byte region (1-byte discriminant + 32-byte counterparty
    /// id, zeroed when `None`) so `link_swap` writes in place
    /// without reallocating. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `delegation`). There is no unlink: the link persists through
    /// the terminal states as the audit trail.
    pub swap_link: Option<[u8; 32]>,
    /// AV-106: opt-in penalty insurance pool (mirrors
    /// `escrow_state`'s `insurance_pool`); false unless the
    /// initializer called `initialize_insurance_pool` while
    /// Uninitialized.
    pub insurance_pool: bool,
    /// AV-106: current pool balance (mirrors `escrow_state`'s
    /// `pool_paid`).
    pub pool_paid: u64,
    /// AV-106: slash principal currently held by the pool and still
    /// appealable (mirrors `escrow_state`'s `pool_slashed`).
    pub pool_slashed: u64,
    /// AV-106: cumulative pool inflow (mirrors `escrow_state`'s
    /// `pool_inflow`); never debited.
    pub pool_inflow: u64,
    /// AV-106: cumulative authorized pool payouts (mirrors
    /// `escrow_state`'s `pool_payout_paid`); the outflow sink.
    pub pool_payout_paid: u64,
    /// AV-107: opt-in annual interest rate in basis points (mirrors
    /// `escrow_state`'s `interest_rate_bps`); `0` unless the
    /// initializer called `initialize_interest` while `Uninitialized`.
    /// Layout position matches `escrow_state::VAULT_FIELDS`
    /// (appended last, after the insurance-pool region).
    pub interest_rate_bps: u16,
    /// AV-107: Unix timestamp up to which interest has been settled
    /// (mirrors `escrow_state`'s `interest_accrual_base`); anchored
    /// at `fund_at` by `fund`.
    pub interest_accrual_base: u64,
    /// AV-107: outstanding accrued interest — the taker's unsettled
    /// yield claim (mirrors `escrow_state`'s `interest_accrued`).
    pub interest_accrued: u64,
    /// AV-107: cumulative interest paid out to the taker (mirrors
    /// `escrow_state`'s `interest_paid`); the new sink in the
    /// extended conservation identity — never mixed into `released`.
    pub interest_paid: u64,
    /// AV-108: the opt-in multi-recipient payout-split table (mirrors
    /// `escrow_state`'s `payout_split`); zeroed unless the initializer
    /// called `initialize_payout_split` while `Uninitialized`.
    /// Layout position matches `escrow_state::VAULT_FIELDS`
    /// (appended last, after the interest tail).
    pub payout_split: PayoutSplit,
    /// AV-109: the dead-man's switch inactivity threshold in seconds
    /// (mirrors `escrow_state`'s `deadman_inactivity_secs`); zero
    /// unless the initializer called `initialize_deadman_switch`
    /// while `Uninitialized`. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after the
    /// payout-split tail).
    pub deadman_inactivity_secs: u64,
    /// AV-109: the dead-man's switch heir (mirrors `escrow_state`'s
    /// `deadman_heir`); `None` unless the switch is configured. The
    /// heir is not required to be either party.
    pub deadman_heir: Option<Pubkey>,
    /// AV-109: the dead-man's switch activity clock (mirrors
    /// `escrow_state`'s `deadman_last_activity`) — the `now` of the
    /// most recent successful clock-bearing transition.
    pub deadman_last_activity: u64,
    /// AV-112: opt-in release cooling window in seconds (mirrors
    /// `escrow_state`'s `release_cooling_secs`); `0` unless the
    /// initializer called `initialize_release_cooling` while
    /// `Uninitialized`. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after the
    /// dead-man's switch tail).
    pub release_cooling_secs: u64,
    /// AV-112: Unix timestamp of the most recent `announce_release`
    /// (mirrors `escrow_state`'s `release_intent_at`); `None` when no
    /// intent is live (never announced, or vetoed via
    /// `veto_release`). Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `release_cooling_secs`).
    pub release_intent_at: Option<u64>,
    /// AV-126: the opt-in tiered default-penalty ladder (mirrors
    /// `escrow_state`'s `slash_ladder`); `None` for escrows without a
    /// ladder. The account always reserves the full 114-byte region —
    /// 1-byte discriminant + 113-byte ladder (32-byte penalty account
    /// + 8 fixed 10-byte (deadline u64, bps u16) rung slots +
    /// rung-count byte), zeroed when `None` — so
    /// `initialize_slash_ladder` writes in place. Layout position
    /// matches `escrow_state::VAULT_FIELDS` (appended last).
    pub slash_ladder: Option<SlashLadder>,
    /// AV-126: the consumed-rung cursor (mirrors `escrow_state`'s
    /// `slash_ladder_index`), 1 byte, zeroed when no rung consumed;
    /// each slash consumes the current rung. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `slash_ladder`).
    pub slash_ladder_index: u8,
    /// AV-127: cumulative amount refunded via `partial_refund`
    /// (mirrors `escrow_state`'s `refunded`), 8 bytes, zeroed when no
    /// partial refund was ever executed. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `slash_ladder_index`).
    pub refunded: u64,
    /// AV-130: the opt-in dual-control (maker-checker) release checker
    /// (mirrors `escrow_state`'s `dual_control_checker`); `None` for
    /// escrows that never opted in via `initialize_dual_control`.
    /// Layout position matches `escrow_state::VAULT_FIELDS`
    /// (appended last, after `refunded`).
    pub dual_control_checker: Option<Pubkey>,
    /// AV-130: the live maker-checker release declaration (mirrors
    /// `escrow_state`'s `dual_control_intent`); `None` when no release
    /// is awaiting checker approval. Layout position matches
    /// `escrow_state::VAULT_FIELDS` (appended last, after
    /// `dual_control_checker`).
    pub dual_control_intent: Option<DualControlIntentMirror>,
    /// AV-131: the contested lamport amount, persisted by `escalate`
    /// (mirrors `escrow_state`'s `disputed_amount`); `0` when the vault
    /// was never disputed, and never cleared afterwards — the audit
    /// trail of how much was under arbitration. Layout position
    /// matches `escrow_state::VAULT_FIELDS` (appended last, after
    /// `dual_control_intent`).
    pub disputed_amount: u64,
}

/// Skeleton mirror of `escrow_state::DualControlIntent` (AV-130): the
/// frozen maker-checker release declaration — the exact payout the
/// initializer (the *maker*) declared for the checker to review. The
/// checker settles it with `confirm_release`, or either party aborts
/// it with `cancel_release`. Serialized size is pinned by
/// `escrow_state::DUAL_CONTROL_INTENT_LEN` (89 bytes: 8-byte amount +
/// 1-byte mint `Option` discriminant + 32-byte mint + 32-byte payout
/// destination + 8-byte initiated clock + 8-byte expiry clock); on the
/// vault it rides a 1-byte `Option` discriminant.
#[derive(
    AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, Debug, PartialEq, Eq,
)]
pub struct DualControlIntentMirror {
    /// The gross release amount the checker is asked to approve.
    pub amount: u64,
    /// The token-mint binding of the intended payout (`None` =
    /// native SOL), pinned exactly like `release`'s mint.
    pub mint: Option<Pubkey>,
    /// The taker payout destination the checker is asked to approve.
    pub payout_to: Pubkey,
    /// `initiate_release`'s `now` — the declaration clock.
    pub initiated_at: u64,
    /// `initiated_at + intent_ttl_secs` — the declaration's expiry.
    pub intent_expires_at: u64,
}

/// Skeleton mirror of `escrow_state::PayoutSplit`: the opt-in
/// multi-recipient payout-split table (AV-108) — the initializer's
/// declared distribution of the locked amount across 1–8 fixed
/// recipients. The share Σ is pinned to the escrow amount at
/// declaration; the table owns the release destination, so plain
/// `release` / `release_via_cpi` become `InvalidPayoutSplit` (code
/// 167) once it is configured and the full lockup settles through
/// `release_payout_split` only.
#[derive(
    AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, Debug, PartialEq, Eq,
)]
pub struct PayoutSplit {
    /// Number of live shares (1–8); `0` means no table configured.
    pub split_count: u8,
    /// Fixed recipient slots; unused slots are zero-filled.
    pub recipients: [[u8; 32]; 8],
    /// Fixed share-amount slots (lamports); unused slots are zero.
    pub amounts: [u64; 8],
}

/// Skeleton mirror of `escrow_state::PayoutSplitShare`: one
/// (recipient, amount) leg of the `initialize_payout_split` table.
#[derive(
    AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, Debug, PartialEq, Eq,
)]
pub struct PayoutSplitShare {
    /// The leg's recipient (never the zero address).
    pub recipient: [u8; 32],
    /// The leg's fixed share (lamports, never zero).
    pub amount: u64,
}

/// Skeleton mirror of `escrow_state::SlashTerms`: the opt-in
/// default-penalty (slash) clause (AV-82) — the penalty sink that
/// receives slashed funds plus the Unix-seconds deadline after which
/// `slash` becomes eligible. Serialized size is pinned by
/// `escrow_state::SLASH_TERMS_LEN` (40 bytes: 32-byte penalty account
/// + u64 slash deadline); on the vault it rides a 1-byte `Option`
/// discriminant.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct SlashTerms {
    pub penalty_account: Pubkey,
    pub slash_deadline: u64,
}

/// Skeleton mirror of `escrow_state::SlashRung`: one tier of the
/// AV-126 default-penalty ladder — the Unix-seconds deadline after
/// which this rung becomes the active slash tier, plus the per-slash
/// cap in basis points of the slashable remainder.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct SlashRung {
    pub deadline: u64,
    pub bps: u16,
}

/// Skeleton mirror of `escrow_state::SlashLadder`: the opt-in tiered
/// default-penalty ladder (AV-126) — the penalty sink plus up to 8
/// strictly-ascending (deadline, bps) rungs;
/// `rungs[rung_count..]` are zero-filled. Serialized size is pinned
/// by `escrow_state::SLASH_LADDER_LEN` (113 bytes: 32-byte penalty
/// account + 8 fixed 10-byte rung slots + rung-count byte); on the
/// vault it rides a 1-byte `Option` discriminant.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct SlashLadder {
    pub penalty_account: Pubkey,
    pub rungs: [SlashRung; 8],
    pub rung_count: u8,
}

/// Skeleton mirror of one `escrow_state::SlashRung` as an instruction
/// argument (AV-126): the `initialize_slash_ladder` handler converts
/// `Vec<SlashRungArg>` to the `Vec<(u64, u16)>` the state machine's
/// [`escrow_state::Escrow::with_slash_ladder`] validates.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct SlashRungArg {
    pub deadline: u64,
    pub bps: u16,
}

/// Skeleton mirror of one `escrow_state::BasketLeg` as an instruction
/// argument (AV-95b): the SPL mint plus the amount to lock in that
/// mint. The `initialize_basket` handler converts
/// `Vec<BasketLegArg>` to the `Vec<([u8; 32], u64)>` the state
/// machine's [`escrow_state::BasketLegs::new`] validates.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct BasketLegArg {
    pub mint: Pubkey,
    pub amount: u64,
}

/// Skeleton mirror of `escrow_state::VestingSchedule`: the linear unlock
/// window `[start, end)` in Unix seconds, with an optional cliff
/// (AV-51): before `cliff_at` nothing unlocks, at/after it the linear
/// curve from `start` applies. See the state machine docs for the claim
/// semantics. Serialized size is pinned by the AV-10/AV-13/AV-51 tests
/// (25 bytes: 1-byte `Option` discriminant + three u64s).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct Vesting {
    pub start: u64,
    pub end: u64,
    /// AV-51: cliff timestamp before which zero unlocks; equals `start`
    /// for the no-cliff schedule.
    pub cliff_at: u64,
}

/// Skeleton mirror of `escrow_state::VestingCurve` (AV-90): the
/// non-linear unlock curve replacing the AV-13 linear shape. Up to 8
/// tiers; tier `i` unlocks a cumulative `unlocked_bps / 10_000` of the
/// locked amount at Unix timestamp `at`. Serialized size is pinned by
/// `escrow_state::VESTING_CURVE_LEN` (82 bytes: 1-byte `Option`
/// discriminant + 1-byte tier count + eight fixed 10-byte tier slots).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct VestingTier {
    /// Unix timestamp at which this tier's unlock fraction applies.
    pub at: u64,
    /// Cumulative unlocked basis points at `at` (final tier: 10_000).
    pub unlocked_bps: u16,
}

/// Skeleton mirror of `escrow_state::VestingCurve` (AV-90).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct VestingCurve {
    pub tiers: [VestingTier; 8],
    pub count: u8,
}

/// Skeleton mirror of `escrow_state::QuorumPolicy`: up to 8 registered
/// attestor pubkeys, the N-of-M threshold, and a u64 approval bitmask.
/// See the state machine docs for the release-gating semantics.
/// Serialized size is pinned by `escrow_state::QUORUM_POLICY_LEN`
/// (266 bytes); the AV-10 tests assert it against a manual encoding.
/// Skeleton mirror of `escrow_state::QuorumPolicy`: up to
/// `escrow_state::MAX_ATTESTORS` attestor keys in slot order, the
/// parallel per-attestor vote weights (AV-45), the registered count,
/// the u64 weight-sum release threshold, and the approval bitmask.
/// See the state machine docs for the weighted attestation /
/// release-gate semantics. Serialized size is pinned by
/// `escrow_state::QUORUM_POLICY_LEN`; the AV-04/AV-45 tests assert it
/// against a manual encoding.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct Quorum {
    pub attestors: [Pubkey; 8],
    /// Per-attestor vote weight, in slot order (parallel to
    /// `attestors`); mirrors `escrow_state::QuorumPolicy` (AV-45).
    pub weights: [u64; 8],
    pub registered: u8,
    /// Weight-sum release threshold; mirrors
    /// `escrow_state::QuorumPolicy::threshold` (AV-45).
    pub threshold: u64,
    pub approvals: u64,
}

/// Skeleton mirror of `escrow_state::MilestonePlan`: up to
/// `escrow_state::MAX_MILESTONES` tranche amounts in release order plus
/// the tranche count. See the state machine docs for the confirmation /
/// release / skip semantics. Serialized size is pinned by
/// `escrow_state::MILESTONE_PLAN_LEN` (65 bytes); the AV-10/AV-15 tests
/// assert it against a manual encoding.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct MilestonePlan {
    pub amounts: [u64; 8],
    pub count: u8,
}

/// AV-49: skeleton mirror of `escrow_state::PayoutAllowlist`: up to 4
/// payout-destination pubkeys in slot order plus the live count.
/// Serialized size is pinned by `escrow_state::PAYOUT_ALLOWLIST_LEN`
/// (129 bytes: 4×32-byte addresses + 1-byte count).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct PayoutAllowlist {
    pub addrs: [Pubkey; 4],
    pub len: u8,
}

/// AV-96: skeleton mirror of `escrow_state::PayoutDenylist`: up to 4
/// denied payout-destination pubkeys in slot order plus the live
/// count. Same wire shape as [`PayoutAllowlist`]; serialized size is
/// pinned by `escrow_state::PAYOUT_DENYLIST_LEN` (129 bytes: 4×32-byte
/// addresses + 1-byte count). Deny takes precedence over the
/// allowlist — a destination on both lists is `PayoutDenied`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct PayoutDenylist {
    pub addrs: [Pubkey; 4],
    pub len: u8,
}

/// AV-97: skeleton mirror of `escrow_state::DutchAuction`: the
/// opt-in descending-price settlement terms — the Unix-seconds
/// window `[start_at, end_at]` during which the taker's `claim`
/// prices through the descending cap, plus the `reserve_bps` floor
/// (0–10_000 basis points) guaranteeing the initializer's minimum
/// keep at `end_at`. Serialized size is pinned by
/// `escrow_state::DUTCH_AUCTION_LEN` (18 bytes: two u64 timestamps +
/// one u16 floor); on the vault it rides a 1-byte `Option`
/// discriminant.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct DutchAuction {
    pub start_at: u64,
    pub end_at: u64,
    pub reserve_bps: u16,
}

/// AV-104: skeleton mirror of `escrow_state::Delegation`: the
/// delegated operator's key plus the u32 scope bitmap (`1` = fund,
/// `2` = release, `4` = cancel — see
/// `escrow_state::DELEGATION_SCOPE_*`). Serialized size is pinned by
/// `escrow_state::DELEGATION_LEN` (37 bytes: 1-byte `Option`
/// discriminant + 32-byte operator key + 4-byte scope bitmap);
/// `None` when no grant is live.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct Delegation {
    pub delegate: Pubkey,
    pub scopes: u32,
}

/// AV-83: skeleton mirror of `escrow_state::CpiAllowlist`: up to 8
/// allowed target-program ids in slot order plus the live count.
/// Serialized size is pinned by `escrow_state::CPI_ALLOWLIST_LEN`
/// (258 bytes: 8×32-byte program ids + 1-byte count).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct CpiAllowlist {
    pub addrs: [Pubkey; 8],
    pub len: u8,
}

/// AV-84: skeleton mirror of `escrow_state::MultisigAuthority`: the
/// external multisig program id, the vault PDA that must sign, and the
/// u16 threshold metadata (informational only — enforced by the
/// multisig program, never by the escrow). Serialized size is pinned
/// by `escrow_state::MULTISIG_AUTHORITY_LEN` (66 bytes: 32-byte program
/// id + 32-byte authority + u16 threshold).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct MultisigAuthority {
    pub program_id: Pubkey,
    pub authority: Pubkey,
    pub threshold: u16,
}

/// AV-55: skeleton mirror of `escrow_state::DefaultJudgment`: the
/// pre-agreed arbitration default judgment — the deadline (seconds in
/// `Disputed` after which the judgment becomes triggerable, measured
/// from `Vault::disputed_at`) and the taker's share of the remaining
/// locked funds under the fallback split (the initializer is refunded
/// the rest). See the state machine docs for the dual-signed
/// agreement / trigger semantics. Serialized size is pinned by
/// `escrow_state::DEFAULT_JUDGMENT_LEN` (16 bytes: two u64s).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct DefaultJudgment {
    /// Seconds in `Disputed` after which the default judgment becomes
    /// triggerable; mirrors `escrow_state::DefaultJudgment::deadline_secs`.
    pub deadline_secs: u64,
    /// The taker's share of the remaining locked funds under the
    /// default judgment; mirrors
    /// `escrow_state::DefaultJudgment::default_taker_amount`.
    pub default_taker_amount: u64,
}

/// AV-65: skeleton mirror of `escrow_state::PanelVote`: one panel
/// member's current effective judgment vote — the voted taker share of
/// the remaining locked funds plus the member's optional
/// rationale-document commitment. Serialized size is pinned by
/// `escrow_state::PANEL_VOTE_LEN` (41 bytes: u64 + 1-byte option tag +
/// 32-byte rationale).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct PanelVote {
    /// The taker's share of the remaining locked funds this vote
    /// awards; mirrors `escrow_state::PanelVote::taker_amount`.
    pub taker_amount: u64,
    /// The member's optional commitment to the off-chain rationale
    /// document behind this vote; mirrors
    /// `escrow_state::PanelVote::rationale_hash`.
    pub rationale_hash: Option<[u8; 32]>,
}

/// AV-65: skeleton mirror of `escrow_state::ArbiterPanel`: the opt-in
/// N-member arbitration committee with its M-vote judgment threshold.
/// See the state machine docs for the multisig judgment / auto-settle
/// semantics. Serialized size is pinned by
/// `escrow_state::ARBITER_PANEL_LEN` (594 bytes: member count + threshold
/// + 8 member keys + 8 vote slots + voted bitmask).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct ArbiterPanel {
    /// How many members sit on the panel (1..=8); mirrors
    /// `escrow_state::ArbiterPanel::n`.
    pub n: u8,
    /// How many matching votes settle the dispute (1..=n); mirrors
    /// `escrow_state::ArbiterPanel::threshold`.
    pub threshold: u8,
    /// The member keys in slot order; mirrors
    /// `escrow_state::ArbiterPanel::members`.
    pub members: [Pubkey; 8],
    /// The current effective vote per member, in slot order; mirrors
    /// `escrow_state::ArbiterPanel::votes`.
    pub votes: [PanelVote; 8],
    /// Bitmask of members who have voted; mirrors
    /// `escrow_state::ArbiterPanel::voted`.
    pub voted: u64,
}

/// AV-66: skeleton mirror of `escrow_state::FeeTier`: one tier of the
/// opt-in protocol-fee schedule — the payout floor it applies from
/// and the basis-point rate for that bracket. Serialized size is
/// pinned by `escrow_state::FEE_TIER_LEN` (10 bytes: min_amount u64 +
/// bps u16).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct FeeTier {
    /// The smallest gross payout (in lamports) this tier applies to;
    /// mirrors `escrow_state::FeeTier::min_amount`.
    pub min_amount: u64,
    /// The protocol-fee rate for payouts in this tier, in basis
    /// points; mirrors `escrow_state::FeeTier::bps`.
    pub bps: u16,
}

/// AV-66: skeleton mirror of `escrow_state::FeeSchedule`: the opt-in
/// tiered protocol-fee schedule (volume pricing instead of the flat
/// bps rate). Serialized size is pinned by
/// `escrow_state::FEE_SCHEDULE_LEN` (81 bytes: the 1-byte live-tier
/// count plus the 8 fixed 10-byte tier slots; zeroed — `tier_count ==
/// 0` — when no schedule is configured).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct FeeSchedule {
    /// How many tier slots are live (`0..=8`); `0` means no schedule;
    /// mirrors `escrow_state::FeeSchedule::tier_count`.
    pub tier_count: u8,
    /// The tiers in slot order (strictly ascending floors); mirrors
    /// `escrow_state::FeeSchedule::tiers`.
    pub tiers: [FeeTier; 8],
}

/// AV-56: skeleton mirror of `escrow_state::SubscriptionSchedule`: the
/// periodic (subscription-style) release schedule — the locked amount
/// is paid to the taker in `periods` equal tranches of `per_period`,
/// one per `period_secs` seconds. A per-period alternative to the
/// milestone tranche plan (AV-15): milestones are driven by deliverable
/// confirmation, subscriptions by the clock — so the two are mutually
/// exclusive and an escrow carries at most one release schedule. Periods
/// are back-scheduled from the escrow's `expires_at` (period `i` is due
/// at `expires_at - (periods - 1 - i) * period_secs`), so the schedule
/// always completes within the escrow's lifetime; see the state machine
/// docs for the validation / release semantics. Serialized size is
/// pinned by `escrow_state::SUBSCRIPTION_SCHEDULE_LEN` (17 bytes).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct SubscriptionSchedule {
    /// Seconds between period due dates (the schedule's cadence),
    /// non-zero; mirrors
    /// `escrow_state::SubscriptionSchedule::period_secs`.
    pub period_secs: u64,
    /// How many periods the lockup is split into (`1..=64` — the
    /// per-period released bitmap is a u64); mirrors
    /// `escrow_state::SubscriptionSchedule::periods`.
    pub periods: u8,
    /// The taker's payout per period; `periods * per_period` equals the
    /// locked amount. Mirrors
    /// `escrow_state::SubscriptionSchedule::per_period`.
    pub per_period: u64,
}

/// AV-57: skeleton mirror of `escrow_state::EventHistorySlot`: one
/// fixed-size event-history ring slot — the event-kind discriminant
/// (u8, `escrow_state::EscrowEventKind` declaration order), the
/// caller-supplied Unix-seconds timestamp (u64), and the actor summary
/// (the first 8 bytes of the transition actor's pubkey, `None` when
/// the event carries no single actor). Serialized size is pinned by
/// `escrow_state::EVENT_HISTORY_SLOT_LEN` (18 bytes).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct EventHistorySlot {
    /// The transition's event-kind discriminant; mirrors
    /// `escrow_state::EventHistorySlot::kind`.
    pub kind: u8,
    /// Caller-supplied Unix-seconds timestamp of the transition;
    /// mirrors `escrow_state::EventHistorySlot::at`.
    pub at: u64,
    /// First 8 bytes of the actor's pubkey, or `None` when the event
    /// carries no single actor; mirrors
    /// `escrow_state::EventHistorySlot::actor`.
    pub actor: Option<[u8; 8]>,
}

/// AV-18: on-chain indexer event, the `emit!` mirror of
/// `escrow_state::EscrowEvent`.
///
/// Every state transition emits one of these, so an off-chain indexer
/// can subscribe to state changes in per-vault `seq` order instead of
/// polling account data. Field-for-field mirror of the state-machine
/// event: `kind` / vault identity / `seq` / `from_state` → `to_state` /
/// fund movements / `at`. States are the
/// `escrow_state::EscrowState` discriminants as `u8`; amounts are the
/// gross taker payout, the protocol fee slice, and the initializer
/// refund (zeroed when the kind moves nothing — see
/// `escrow_state::EventAmounts`).
#[event]
pub struct EscrowVaultEvent {
    pub kind: EscrowVaultEventKind,
    /// The vault account: the on-chain escrow identity (the
    /// `IndexedEscrow` wrapper's caller-supplied `escrow_id` off-chain).
    pub vault: Pubkey,
    /// Per-vault monotonic sequence (0 = `initialize`); the real build
    /// persists this counter in the Vault account (`read_event_seq`), so
    /// replays stay ordered even across transactions.
    pub seq: u64,
    pub from_state: u8,
    pub to_state: u8,
    /// Gross amount moved to the taker before the protocol-fee split.
    pub payout: u64,
    /// Protocol fee (AV-17) sliced from `payout`.
    pub fee: u64,
    /// Amount returned to the initializer (cancel / cancel_expired
    /// remainder, `resolve`'s initializer share, skipped tranche).
    pub refund: u64,
    /// Unix seconds from the clock sysvar at emission.
    pub at: u64,
    /// AV-22: dispute-evidence commitment carried by the `Escalated`
    /// and `Resolved` events (`None` for every other kind); mirrors
    /// `escrow_state::EscrowEvent::evidence_hash`, so an off-chain
    /// indexer learns the evidence reference from the event stream
    /// without a second account read.
    pub evidence_hash: Option<[u8; 32]>,
    /// AV-68: whether the escalating party's evidence disclosure had
    /// defaulted at judgment time — `true` only on the settlement
    /// kinds (`Resolved`, `DefaultJudgment`, `PanelResolved`) when a
    /// disclosure deadline was configured, it had lapsed at the
    /// event's `at` timestamp, and no evidence was on record. Mirrors
    /// `escrow_state::EscrowEvent::evidence_defaulted`: the
    /// judgment-time adverse-inference signal, biasing the
    /// absent-evidence weight toward the non-escalating party.
    /// Read from the vault's escrow at emit time, like `reference`.
    pub evidence_defaulted: bool,
    /// AV-38: the arbiter's rationale-document commitment carried by
    /// the `Resolved` event (`None` for every other kind); mirrors
    /// `escrow_state::EscrowEvent::rationale_hash`, so an off-chain
    /// indexer learns the ruling reference from the event stream
    /// without a second account read.
    pub rationale_hash: Option<[u8; 32]>,
    /// AV-35: the third-party program a CPI-routed release invoked
    /// (`release_via_cpi`); `None` on every other kind. Mirrors
    /// `escrow_state::EscrowEvent::cpi.target`.
    pub cpi_target: Option<Pubkey>,
    /// AV-35: SHA-256 over the canonical encoding of the exact
    /// instruction the CPI-routed release authorized (program id +
    /// accounts + data; see `escrow_state::cpi_accounts_hash`); `None`
    /// on every other kind. Mirrors
    /// `escrow_state::EscrowEvent::cpi.accounts_hash`.
    pub cpi_accounts_hash: Option<[u8; 32]>,
    /// AV-48: the permissionless crank caller's key, carried by the
    /// `ExpiredCranked` event (`None` on every other kind). Mirrors
    /// `escrow_state::EscrowEvent::caller`, so an off-chain indexer
    /// learns who cranked the escrow from the event stream without a
    /// second account read.
    pub caller: Option<Pubkey>,
    /// AV-53: the opt-in 32-byte off-chain reference memo, carried by
    /// *every* event kind (`None` when the escrow carries no memo).
    /// Mirrors `escrow_state::EscrowEvent::reference`, so an off-chain
    /// indexer can join every event back to the operator's
    /// order/invoice record without a second account read.
    /// Read-only pass-through: the event never invents a reference.
    pub reference: Option<[u8; 32]>,
}

/// AV-18: on-chain mirror of `escrow_state::EscrowEventKind`, mapped by
/// `escrow_event_kind` exactly like `escrow_error` maps
/// `escrow_state::EscrowError` onto `ErrorCode`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum EscrowVaultEventKind {
    Initialized,
    Activated,
    Funded,
    Released,
    Cancelled,
    ExpiredCancelled,
    /// AV-48: an expired escrow was cancelled through the permissionless
    /// crank (`Escrow::crank_expired`). Mirrors
    /// `escrow_state::EscrowEventKind::ExpiredCranked`; the event's
    /// `caller` field carries the crank caller's key.
    ExpiredCranked,
    Attested,
    Claimed,
    Escalated,
    Resolved,
    MilestoneConfirmed,
    MilestoneReleased,
    MilestoneSkipped,
    /// AV-25: the quorum's attestation threshold changed by dual-signed
    /// governance (`Escrow::update_quorum`). Mirrors
    /// `escrow_state::EscrowEventKind::QuorumUpdated`.
    QuorumUpdated,
    /// AV-39: the quorum's attestor set changed by dual-signed
    /// governance (`Escrow::update_attestors`). Mirrors
    /// `escrow_state::EscrowEventKind::AttestorsUpdated`.
    AttestorsUpdated,
    /// AV-36: a fund-moving transition was rejected as a reentrant call
    /// (`EscrowError::ReentrantCall`). Mirrors
    /// `escrow_state::EscrowEventKind::ReentryRejected`.
    ReentryRejected,
    /// AV-46: the emergency pause was engaged (`Escrow::pause`).
    /// Mirrors `escrow_state::EscrowEventKind::Paused`.
    Paused,
    /// AV-46: the emergency pause was released (`Escrow::unpause`).
    /// Mirrors `escrow_state::EscrowEventKind::Unpaused`.
    Unpaused,
    /// AV-47: the emergency-pause authority was rotated by owner
    /// governance (`Escrow::rotate_pause_authority`). Mirrors
    /// `escrow_state::EscrowEventKind::PauseAuthorityRotated`.
    PauseAuthorityRotated,
    /// AV-34: the vault account was closed by the initializer and its
    /// rent-exempt deposit reclaimed (`Cancelled | Released | Settled ->
    /// Closed`).
    VaultClosed,
    /// AV-55: a deadlocked dispute was settled on the pre-agreed
    /// fallback split (`Escrow::trigger_default_judgment`).
    /// `from == Disputed`, `to == Settled` — the same lifecycle move as
    /// `Resolved`, but executed by either party after the arbitration
    /// deadline instead of by the arbiter. Amounts follow the `Resolved`
    /// shape; the dispute evidence hash the escrow still holds rides the
    /// event; the rationale-document commitment is `None` (no arbiter
    /// ruled). Mirrors `escrow_state::EscrowEventKind::DefaultJudgment`.
    DefaultJudgment,
    /// AV-56: one subscription period released to the taker
    /// (`Escrow::release_period`). `from == Funded`, `to == Funded` —
    /// or `Released` on the last period. Amounts follow the
    /// `MilestoneReleased` shape (gross per-period amount / fee /
    /// refund = 0); periods release strictly in order, each only once
    /// due. Mirrors
    /// `escrow_state::EscrowEventKind::SubscriptionPeriodReleased`.
    SubscriptionPeriodReleased,
    /// AV-49: the payout destination allowlist was updated by owner
    /// governance (`Escrow::update_payout_allowlist`). Mirrors
    /// `escrow_state::EscrowEventKind::PayoutAllowlistUpdated`.
    PayoutAllowlistUpdated,
    /// AV-52: the taker (payout counterparty) was rotated by
    /// dual-signed governance (`Escrow::rotate_taker`). Mirrors
    /// `escrow_state::EscrowEventKind::TakerRotated`.
    TakerRotated,
    /// AV-58: the initializer (funding authority) was rotated by
    /// dual-signed governance (`Escrow::rotate_initializer`). Mirrors
    /// `escrow_state::EscrowEventKind::InitializerRotated`.
    InitializerRotated,
    /// AV-59: the expiry deadline was extended by the initializer
    /// (`Escrow::extend_expiry`). Mirrors
    /// `escrow_state::EscrowEventKind::ExpiryExtended`.
    ExpiryExtended,
    /// AV-60: the initializer partially cancelled the escrow
    /// (`Escrow::cancel_partial`) — a tranche of the lockup refunded
    /// while the escrow stays `Funded`. `from == to == Funded`;
    /// `amounts.refund` carries the partially-cancelled tranche.
    /// Mirrors `escrow_state::EscrowEventKind::PartiallyCancelled`.
    PartiallyCancelled,
    /// AV-62: the dispute arbiter was rotated by dual-signed
    /// governance (`Escrow::rotate_arbiter`). Mirrors
    /// `escrow_state::EscrowEventKind::ArbiterRotated`.
    ArbiterRotated,
    /// AV-68: the escalating party disclosed (or replaced) the
    /// dispute-evidence commitment (`Escrow::submit_evidence`).
    /// `from == to == Disputed`; the disclosed commitment rides the
    /// event's evidence slot. Mirrors
    /// `escrow_state::EscrowEventKind::EvidenceSubmitted`.
    EvidenceSubmitted,
    /// AV-69: the arbiter panel's judgment threshold was retuned by
    /// dual-signed governance (`Escrow::update_panel_threshold`).
    /// `from == to == Uninitialized`; emitted only on an actual
    /// change. Mirrors
    /// `escrow_state::EscrowEventKind::PanelThresholdChanged`.
    PanelThresholdChanged,
    /// AV-70: the milestone tranche amounts were re-split by
    /// dual-signed governance (`Escrow::adjust_milestone_amounts`).
    /// `from == to ==` the current state; emitted only on an actual
    /// change. Mirrors
    /// `escrow_state::EscrowEventKind::MilestonesAdjusted`.
    MilestonesAdjusted,
    /// AV-73: the subscription per-period amounts were re-split by
    /// dual-signed governance (`Escrow::adjust_period_amounts`).
    /// `from == to ==` the current state; emitted only on an actual
    /// change. Mirrors
    /// `escrow_state::EscrowEventKind::SubscriptionAmountsAdjusted`.
    SubscriptionAmountsAdjusted,
    /// AV-75: the vault's persisted schema was migrated by initializer
    /// governance (`Escrow::migrate_schema`). `from == to ==` the
    /// current state; always emitted on success (a successful migration
    /// always steps the version — no no-op case). AV-85: the migration
    /// is an N → M step chain and the program emits one event per
    /// applied step, so the stream records every from → to version
    /// pair. Mirrors
    /// `escrow_state::EscrowEventKind::SchemaMigrated`.
    SchemaMigrated,
    /// AV-93: the locked funds were released split across several
    /// recipients by basis-point weights (`Escrow::release_split`).
    /// `from == Funded`, `to == Funded` on a partial split, `to ==
    /// Released` on the closing one. Amounts follow the `Released`
    /// shape (gross amount, AV-17 protocol fee); the per-recipient
    /// `(recipient, net_share)` legs ride the event's `release_split`
    /// field in table order — the first leg carries the bps-floor dust.
    /// Mirrors `escrow_state::EscrowEventKind::ReleasedSplit`.
    ReleasedSplit,
    /// AV-112: a release intent was announced by either party
    /// (`Escrow::announce_release`). `from == to ==` the current
    /// state; emitted only on an actual change. Mirrors
    /// `escrow_state::EscrowEventKind::ReleaseIntentAnnounced`.
    ReleaseIntentAnnounced,
    /// AV-112: a live release intent was vetoed by either party
    /// (`Escrow::veto_release`). `from == to ==` the current state;
    /// emitted only when an intent was actually cleared. Mirrors
    /// `escrow_state::EscrowEventKind::ReleaseIntentVetoed`.
    ReleaseIntentVetoed,
    /// AV-130: a dual-control (maker-checker) release declaration was
    /// frozen (`Escrow::initiate_release`). `from == to ==` the
    /// current state; the declaration is a pending intent, not a
    /// lifecycle move. Mirrors
    /// `escrow_state::EscrowEventKind::DualControlInitiated`.
    DualControlInitiated,
    /// AV-130: the checker approved the live dual-control declaration
    /// and it settled (`Escrow::confirm_release`). Mirrors
    /// `escrow_state::EscrowEventKind::DualControlConfirmed`.
    DualControlConfirmed,
    /// AV-130: the live dual-control declaration was aborted
    /// (`Escrow::cancel_release`). `from == to ==` the current state.
    /// Mirrors
    /// `escrow_state::EscrowEventKind::DualControlCancelled`.
    DualControlCancelled,
}

/// AV-18: map `escrow_state::EscrowEventKind` onto the on-chain
/// `EscrowVaultEventKind`, paralleling `escrow_error`.
fn escrow_event_kind(kind: escrow_state::EscrowEventKind) -> EscrowVaultEventKind {
    match kind {
        escrow_state::EscrowEventKind::Initialized => EscrowVaultEventKind::Initialized,
        escrow_state::EscrowEventKind::Activated => EscrowVaultEventKind::Activated,
        escrow_state::EscrowEventKind::Funded => EscrowVaultEventKind::Funded,
        escrow_state::EscrowEventKind::Released => EscrowVaultEventKind::Released,
        escrow_state::EscrowEventKind::Cancelled => EscrowVaultEventKind::Cancelled,
        escrow_state::EscrowEventKind::ExpiredCancelled => {
            EscrowVaultEventKind::ExpiredCancelled
        }
        escrow_state::EscrowEventKind::ExpiredCranked => EscrowVaultEventKind::ExpiredCranked,
        escrow_state::EscrowEventKind::Attested => EscrowVaultEventKind::Attested,
        escrow_state::EscrowEventKind::Claimed => EscrowVaultEventKind::Claimed,
        escrow_state::EscrowEventKind::Escalated => EscrowVaultEventKind::Escalated,
        escrow_state::EscrowEventKind::Resolved => EscrowVaultEventKind::Resolved,
        escrow_state::EscrowEventKind::MilestoneConfirmed => {
            EscrowVaultEventKind::MilestoneConfirmed
        }
        escrow_state::EscrowEventKind::MilestoneReleased => {
            EscrowVaultEventKind::MilestoneReleased
        }
        escrow_state::EscrowEventKind::MilestoneSkipped => {
            EscrowVaultEventKind::MilestoneSkipped
        }
        escrow_state::EscrowEventKind::QuorumUpdated => EscrowVaultEventKind::QuorumUpdated,
        escrow_state::EscrowEventKind::AttestorsUpdated => {
            EscrowVaultEventKind::AttestorsUpdated
        }
        escrow_state::EscrowEventKind::ReentryRejected => {
            EscrowVaultEventKind::ReentryRejected
        }
        escrow_state::EscrowEventKind::Paused => EscrowVaultEventKind::Paused,
        escrow_state::EscrowEventKind::Unpaused => EscrowVaultEventKind::Unpaused,
        escrow_state::EscrowEventKind::PauseAuthorityRotated => {
            EscrowVaultEventKind::PauseAuthorityRotated
        }
        escrow_state::EscrowEventKind::VaultClosed => EscrowVaultEventKind::VaultClosed,
        escrow_state::EscrowEventKind::DefaultJudgment => {
            EscrowVaultEventKind::DefaultJudgment
        }
        escrow_state::EscrowEventKind::SubscriptionPeriodReleased => {
            EscrowVaultEventKind::SubscriptionPeriodReleased
        }
        // AV-49 / AV-52: pre-existing gaps — the skeleton mapped every
        // emitted kind except these two; the one-event-per-kind
        // convention (AV-18) requires them.
        escrow_state::EscrowEventKind::PayoutAllowlistUpdated => {
            EscrowVaultEventKind::PayoutAllowlistUpdated
        }
        escrow_state::EscrowEventKind::TakerRotated => EscrowVaultEventKind::TakerRotated,
        escrow_state::EscrowEventKind::InitializerRotated => {
            EscrowVaultEventKind::InitializerRotated
        }
        escrow_state::EscrowEventKind::ExpiryExtended => {
            EscrowVaultEventKind::ExpiryExtended
        }
        escrow_state::EscrowEventKind::PartiallyCancelled => {
            EscrowVaultEventKind::PartiallyCancelled
        }
        escrow_state::EscrowEventKind::ArbiterRotated => {
            EscrowVaultEventKind::ArbiterRotated
        }
        escrow_state::EscrowEventKind::EvidenceSubmitted => {
            EscrowVaultEventKind::EvidenceSubmitted
        }
        escrow_state::EscrowEventKind::PanelThresholdChanged => {
            EscrowVaultEventKind::PanelThresholdChanged
        }
        escrow_state::EscrowEventKind::MilestonesAdjusted => {
            EscrowVaultEventKind::MilestonesAdjusted
        }
        escrow_state::EscrowEventKind::SubscriptionAmountsAdjusted => {
            EscrowVaultEventKind::SubscriptionAmountsAdjusted
        }
        escrow_state::EscrowEventKind::SchemaMigrated => {
            EscrowVaultEventKind::SchemaMigrated
        }
        escrow_state::EscrowEventKind::ReleasedSplit => {
            EscrowVaultEventKind::ReleasedSplit
        }
        escrow_state::EscrowEventKind::ReleaseIntentAnnounced => {
            EscrowVaultEventKind::ReleaseIntentAnnounced
        }
        escrow_state::EscrowEventKind::ReleaseIntentVetoed => {
            EscrowVaultEventKind::ReleaseIntentVetoed
        }
        // AV-130: the maker-checker declaration lifecycle.
        escrow_state::EscrowEventKind::DualControlInitiated => {
            EscrowVaultEventKind::DualControlInitiated
        }
        escrow_state::EscrowEventKind::DualControlConfirmed => {
            EscrowVaultEventKind::DualControlConfirmed
        }
        escrow_state::EscrowEventKind::DualControlCancelled => {
            EscrowVaultEventKind::DualControlCancelled
        }
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    // AV-92: vault PDA derivation. The real build constrains this
    // account as a program-derived address:
    //
    //     #[account(
    //         init, payer = initializer, space = escrow_state::VAULT_SPACE,
    //         seeds = [b"vault", initializer.key().as_ref()],
    //         bump,
    //     )]
    //
    // i.e. `find_program_address([b"vault", initializer], program_id)`:
    // the canonical address is
    // `sha256(seeds.. ++ [bump] ++ program_id ++ "ProgramDerivedAddress")`
    // with the bump scanned 255 → 0 for the first off-curve candidate
    // (Solana's `create_program_address` / `find_program_address`
    // semantics). The seeds are chosen at initialize time and recorded
    // off-chain — PDAs never store their seeds on-chain — so the
    // keeper/batch/close watch structs carry them
    // (`WatchedEscrow::with_vault_seeds`, `BatchWatchItem`,
    // `CloseWatchItem`) and the reports attach the precomputed
    // `vault_address`. The off-chain derivation itself is
    // `escrow_state::pda` (hand-rolled, zero dependencies):
    // `find_program_address` / `derive_vault_address` /
    // `find_vault_bump` / `is_on_ed25519_curve`. Every later
    // instruction takes the vault PDA as a plain account and the
    // program signs via `invoke_signed` with `&[b"vault",
    // initializer.key().as_ref(), &[bump]]`.
    //
    // Full vault space: 8-byte discriminator + 2216-byte payload = 2224
    // bytes (see `escrow_state::VAULT_SPACE`; AV-12 added the 1-byte
    // activation bitmask, AV-13 the 17-byte vesting region, AV-14 the
    // 33-byte arbiter region, AV-15 the 66-byte milestone plan + the
    // 8-byte confirmation bitmap + the 8-byte skipped counter, AV-16 the
    // 33-byte mint region, AV-17 the 2-byte fee rate + the 8-byte
    // cumulative fee counter, AV-21 the 8-byte grace period, AV-22 the
    // 33-byte evidence hash region, AV-23 the 33-byte refund whitelist
    // region, AV-24 the 2-byte penalty rate, AV-27 the 8-byte timelock,
    // AV-28 the 1-byte decimals metadata, AV-38 the 33-byte rationale
    // hash region, AV-41 the 1-byte emergency-unlock flag, AV-44 the
    // 33-byte fee-recipient region, AV-45 the 64-byte quorum weight
    // array + the 7-byte wider weight-sum threshold, AV-49 the 130-byte
    // payout-allowlist region, AV-53 the 33-byte reference-memo region,
    // AV-55 the 8-byte dispute timestamp + the 17-byte default-judgment
    // region + the 1-byte confirmation bit, AV-56 the 18-byte
    // subscription-schedule region + the 1-byte next-period index + the
    // 8-byte per-period released bitmap, AV-57 the 1-byte event ring
    // head + the 8-byte monotonic event total + the 1-byte valid-entry
    // count + the 1-byte configured capacity + the 1152-byte event
    // slots, AV-59 the 8-byte extension bound + the 8-byte extension
    // counter, AV-63 the 8-byte absolute protocol-fee ceiling, AV-64
    // the 8-byte relative timelock duration + the 8-byte funding
    // timestamp, AV-68 the 8-byte evidence-disclosure deadline + the
    // 33-byte escalating-party region).
    // The payer must fund at least the rent-exempt minimum for this space
    // — `escrow_state::check_vault_rent_exempt` is the pure-logic mirror of
    // that check (on-chain: `Rent::get()?.is_exempt(...)`); with mainnet
    // rent parameters the minimum is 16_369_920 lamports.
    #[account(init, payer = initializer, space = escrow_state::VAULT_SPACE)]
    pub vault: Account<'info, Vault>,
    pub taker: SystemAccount<'info>,
    #[account(mut)]
    pub initializer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

/// AV-95b: the basket twin of [`Initialize`] — creates the vault
/// account for a multi-mint basket escrow. Same account shape as
/// `Initialize` (the basket region is reserved in place at account
/// creation, so no realloc is needed); the leg table arrives as the
/// `initialize_basket` instruction's `legs` param, not as accounts.
#[derive(Accounts)]
pub struct InitializeBasket<'info> {
    #[account(init, payer = initializer, space = escrow_state::VAULT_SPACE)]
    pub vault: Account<'info, Vault>,
    pub taker: SystemAccount<'info>,
    #[account(mut)]
    pub initializer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Fund<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct Release<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: beneficiary of the release; receives the funds.
    pub taker: AccountInfo<'info>,
    /// CHECK: explicit payout destination (AV-49). The state machine
    /// requires it to satisfy the escrow's payout policy: the taker,
    /// or a member of the payout allowlist when one is configured
    /// (`PayoutNotAllowlisted`, code 127, otherwise). Passed as an
    /// account (not a param) so the IDL names the destination.
    pub payout_to: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the AV-27 timelock gate
    /// (never an instruction param — a caller-supplied timestamp would
    /// let the initializer fast-forward the lock).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account. The real build reads this
    /// account's `mint` and the state machine requires it to equal the
    /// bound `vault.mint` (`MintMismatch` otherwise). Unused on the
    /// native-SOL path — the state machine then requires `None`.
    pub vault_token_account: AccountInfo<'info>,
}

/// AV-123: gasless release via a signed Ed25519 intent. The relayer
/// is any fee payer — the initializer's authorization rides the
/// intent's signature, not the transaction's signer set, so the
/// initializer is deliberately *not* a signer account here.
#[derive(Accounts)]
pub struct ReleaseViaIntent<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: the relayer submitting the intent — any fee payer, no
    /// authority check (the initializer's authorization is the
    /// intent's Ed25519 signature, verified by the state machine).
    pub relayer: AccountInfo<'info>,
    /// CHECK: beneficiary of the release; receives the funds.
    pub taker: AccountInfo<'info>,
    /// CHECK: explicit payout destination (AV-49) — bound by the
    /// intent's signature and pinned by the state machine against
    /// the escrow's payout policy (`PayoutNotAllowlisted`, code 127,
    /// otherwise).
    pub payout_to: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar — the AV-27 timelock gate and the
    /// AV-123 intent-expiry gate both read it (never instruction
    /// params, so a relayer cannot fast-forward an intent's life).
    pub clock: AccountInfo<'info>,
    /// CHECK: the Instructions sysvar — introspected for the Ed25519
    /// precompile program instruction (the on-chain double-insurance
    /// for the state machine's own signature check).
    pub instructions: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account. The real build reads this
    /// account's `mint` and the state machine requires it to equal the
    /// bound `vault.mint` (`MintMismatch` otherwise). Unused on the
    /// native-SOL path — the state machine then requires `None`.
    pub vault_token_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ReleaseSplit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: beneficiary of the release on the plain path (kept as a
    /// named account so the IDL stays explicit about who the release is
    /// for, like `Release`).
    pub taker: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the AV-27 timelock gate
    /// (never an instruction param — a caller-supplied timestamp would
    /// let the initializer fast-forward the lock).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account. The real build reads this
    /// account's `mint` and the state machine requires it to equal the
    /// bound `vault.mint` (`MintMismatch` otherwise). Unused on the
    /// native-SOL path — the state machine then requires `None`.
    pub vault_token_account: AccountInfo<'info>,
    // The per-recipient payout destinations travel as
    // `remaining_accounts` in the `recipients` param order: leg `i`
    // transfers to `remaining_accounts[i]`. The handler asserts the
    // account keys match the validated params (a swapped recipient
    // account fails closed with `InvalidReleaseSplit`), and the state
    // machine pins every recipient against the AV-49 payout policy —
    // the taker, or a member of the payout allowlist when one is
    // configured (`PayoutNotAllowlisted`, code 127, otherwise).
}

#[derive(Accounts)]
pub struct ReleaseViaCpi<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: beneficiary of the release on the plain path; on the
    /// CPI-routed path the payout flows into the target program's
    /// instruction instead. Kept as a named account so the IDL stays
    /// explicit about who the release is for.
    pub taker: AccountInfo<'info>,
    /// CHECK: explicit payout destination (AV-49; see `Release`). The
    /// state machine enforces the payout policy on it.
    pub payout_to: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the AV-27 timelock gate
    /// (never an instruction param).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`).
    pub vault_token_account: AccountInfo<'info>,
    // The target program and its instruction accounts travel as
    // `remaining_accounts`: `[0]` is the third-party program id,
    // `[1..]` are the target instruction's accounts in its expected
    // order. Anchor validates nothing about them — the state machine
    // validates the invocation shape (`InvalidCpiTarget`) and the
    // `Released` event's CPI audit pins the exact authorized bytes.
    // AV-36: the real invoke below runs with the state machine's
    // reentrancy lock armed (see `escrow_state::Escrow::release_via_cpi`):
    // if the target program CPIs back into any fund-moving instruction
    // of this program mid-invoke, the nested entry is rejected with
    // `ErrorCode::ReentrantCall` and the outer release completes
    // normally. The lock is process-memory only — it is not part of
    // the vault account layout (`VAULT_FIELDS` unchanged).
}

#[derive(Accounts)]
pub struct Cancel<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
    /// CHECK: the refund destination account. AV-23: the state machine
    /// pins it against the escrow's refund policy (the whitelisted
    /// address, or the initializer with no whitelist) — a phishing
    /// frontend cannot redirect the refund by swapping this account.
    /// The real build transfers the refund to this account after the
    /// state machine's `RefundAddressMismatch` check passes.
    pub refund_to: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CancelExpired<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker; the state machine enforces
    /// the either-party rule. A constraint in the real build additionally
    /// asserts `authority.key() == vault.initializer || authority.key() == vault.taker`.
    pub authority: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the expiry comparison.
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
    /// CHECK: the refund destination account. AV-23: the state machine
    /// pins it against the escrow's refund policy — even when the taker
    /// is the caller, the refund goes to the declared address, never to
    /// the caller. The real build transfers the refund to this account
    /// after the state machine's `RefundAddressMismatch` check passes.
    pub refund_to: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ReleaseBasket<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: beneficiary of the leg release (the taker); the real
    /// build transfers the leg's net payout to this leg's token
    /// account. Kept as a named account so the IDL stays explicit
    /// about who the release is for, like `Release`.
    pub taker: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the AV-27 timelock gate
    /// (never an instruction param — a caller-supplied timestamp would
    /// let the initializer fast-forward the lock).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account *for the leg being
    /// settled*. The real build reads this account's `mint` and the
    /// state machine requires it to be one of the basket's legs
    /// (`InvalidBasket`, code 152, otherwise — a basket escrow has no
    /// single bound mint, and there is no native-SOL path: every leg
    /// carries a real mint).
    pub vault_token_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CancelBasket<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: the vault's SPL token account *for the leg being
    /// refunded* (see `ReleaseBasket`). The real build reads its
    /// `mint` for the state machine's leg lookup (`InvalidBasket`,
    /// code 152, on a mint outside the leg table).
    pub vault_token_account: AccountInfo<'info>,
    /// CHECK: the refund destination account. AV-23: unlike `Cancel`,
    /// this instruction takes no caller-chosen destination — the real
    /// build transfers the leg's remainder to the escrow's own refund
    /// policy (the whitelisted address, or the initializer with no
    /// whitelist), which the state machine resolves, so the
    /// anti-phishing pin holds by construction.
    pub refund_to: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CancelExpiredBasket<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker; the state machine enforces
    /// the either-party rule. A constraint in the real build additionally
    /// asserts `authority.key() == vault.initializer || authority.key() == vault.taker`.
    pub authority: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the expiry comparison.
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account *for the leg being
    /// refunded* (see `ReleaseBasket`). The real build reads its
    /// `mint` for the state machine's leg lookup (`InvalidBasket`,
    /// code 152, on a mint outside the leg table).
    pub vault_token_account: AccountInfo<'info>,
    /// CHECK: the refund destination account (see `CancelBasket`).
    /// AV-23: the real build transfers the leg's net refund here; the
    /// AV-24 penalty (non-zero only on a taker-initiated cancel) goes
    /// to the initializer.
    pub refund_to: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ReleaseBasketAll<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: the single payout destination every unsettled leg pays.
    /// AV-49: the state machine pins it against the escrow's payout
    /// policy (`PayoutNotAllowlisted`, code 127, on a denied
    /// destination) before any leg moves. The real build transfers
    /// each leg's net payout to this destination's token account for
    /// that leg's mint; the per-leg token accounts ride
    /// `remaining_accounts` in leg-table order (mirroring the
    /// `BasketSettlement` the state machine returns).
    pub payout_to: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the AV-27 timelock gate
    /// (never an instruction param — a caller-supplied timestamp would
    /// let the initializer fast-forward the lock).
    pub clock: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CancelBasketAll<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: the refund destination account. AV-23: unlike `Cancel`,
    /// this instruction takes no caller-chosen destination — the real
    /// build transfers every leg's remainder to the escrow's own
    /// refund policy (the whitelisted address, or the initializer with
    /// no whitelist), which the state machine resolves, so the
    /// anti-phishing pin holds by construction.
    pub refund_to: AccountInfo<'info>,
}

/// AV-104: grant a bounded slice of the caller's authority to an
/// operator (mirrors `Escrow::delegate_authority`).
#[derive(Accounts)]
pub struct DelegateAuthority<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker; the state machine enforces
    /// the party-only rule (a stranger — or the operator themselves —
    /// is `Unauthorized`, so grants never sub-delegate). A constraint
    /// in the real build additionally asserts `caller.key() ==
    /// vault.initializer || caller.key() == vault.taker`.
    pub caller: Signer<'info>,
}

/// AV-104: revoke the live operator grant (mirrors
/// `Escrow::revoke_delegation`).
#[derive(Accounts)]
pub struct RevokeDelegation<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker may revoke (the state
    /// machine enforces the party-only rule); a stranger is
    /// `Unauthorized`.
    pub caller: Signer<'info>,
}

/// AV-105: link two escrows as an atomic swap pair (mirrors
/// `escrow_state::link_swap`).
#[derive(Accounts)]
pub struct LinkSwap<'info> {
    #[account(mut)]
    pub vault_a: Account<'info, Vault>,
    #[account(mut)]
    pub vault_b: Account<'info, Vault>,
    /// One of the two parties; the state machine enforces the
    /// party-only rule (an AV-104 operator is `Unauthorized`). The
    /// real build additionally requires the counterparty as a second
    /// signer — the instruction is dual-party.
    pub caller: Signer<'info>,
    /// CHECK: the counterparty's signature — the on-chain instruction
    /// requires both parties as signers (the pure-logic layer models
    /// this dual-party authorization).
    pub counterparty: Signer<'info>,
}

/// AV-105: release both legs of a linked swap pair atomically
/// (mirrors `escrow_state::release_swap`).
#[derive(Accounts)]
pub struct ReleaseSwap<'info> {
    #[account(mut)]
    pub vault_a: Account<'info, Vault>,
    #[account(mut)]
    pub vault_b: Account<'info, Vault>,
    /// One of the two parties (party-only — an AV-104 operator is
    /// `Unauthorized`); the real build requires both parties as
    /// signers and each leg runs under its own initializer.
    pub caller: Signer<'info>,
    /// CHECK: the counterparty's signature (see `LinkSwap`).
    pub counterparty: Signer<'info>,
    /// CHECK: explicit payout destination of leg A (AV-49 — pinned
    /// against leg A's payout policy).
    pub payout_to_a: AccountInfo<'info>,
    /// CHECK: explicit payout destination of leg B.
    pub payout_to_b: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the AV-27 timelock gate
    /// (never an instruction param).
    pub clock: AccountInfo<'info>,
    /// CHECK: leg A's vault SPL token account (see `Release`).
    pub vault_token_account_a: AccountInfo<'info>,
    /// CHECK: leg B's vault SPL token account (see `Release`).
    pub vault_token_account_b: AccountInfo<'info>,
}

/// AV-106: opt the vault into the penalty insurance pool (mirrors
/// `escrow_state::initialize_insurance_pool`).
#[derive(Accounts)]
pub struct InitializeInsurancePool<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The initializer; the state machine enforces the party-only
    /// Uninitialized-only rule.
    pub initializer: Signer<'info>,
}

/// AV-106: pay out from the insurance pool (mirrors
/// `escrow_state::pool_payout`).
#[derive(Accounts)]
pub struct PoolPayout<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The arbiter or the bound multisig PDA; the state machine
    /// enforces the authorization (a stranger is `InvalidPoolPayout`).
    pub authority: Signer<'info>,
    /// CHECK: the payout destination. The state machine pins it
    /// against the AV-49/AV-96 recipient gate (allowlist/denylist) —
    /// a phishing frontend cannot redirect the payout by swapping
    /// this account. The real build transfers `amount` to this
    /// account's token account after the state machine's checks pass.
    pub beneficiary: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check and transfers `amount` out of it.
    pub vault_token_account: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the appeal-window
    /// encumbrance check (never an instruction param).
    pub clock: AccountInfo<'info>,
}

/// AV-105: cancel both legs of a linked swap pair atomically
/// (mirrors `escrow_state::cancel_swap`).
#[derive(Accounts)]
pub struct CancelSwap<'info> {
    #[account(mut)]
    pub vault_a: Account<'info, Vault>,
    #[account(mut)]
    pub vault_b: Account<'info, Vault>,
    /// The initializer of at least one leg (party-only — a stranger
    /// or an AV-104 operator is `Unauthorized`); the real build
    /// requires both parties as signers.
    pub caller: Signer<'info>,
    /// CHECK: the counterparty's signature (see `LinkSwap`).
    pub counterparty: Signer<'info>,
    /// CHECK: leg A's refund destination (AV-23 — pinned against leg
    /// A's refund policy).
    pub refund_to_a: AccountInfo<'info>,
    /// CHECK: leg B's refund destination.
    pub refund_to_b: AccountInfo<'info>,
    /// CHECK: leg A's vault SPL token account (see `Release`).
    pub vault_token_account_a: AccountInfo<'info>,
    /// CHECK: leg B's vault SPL token account (see `Release`).
    pub vault_token_account_b: AccountInfo<'info>,
}

/// AV-105: cancel both legs of a linked swap pair on expiry (mirrors
/// `escrow_state::cancel_swap_expired`).
#[derive(Accounts)]
pub struct CancelSwapExpired<'info> {
    #[account(mut)]
    pub vault_a: Account<'info, Vault>,
    #[account(mut)]
    pub vault_b: Account<'info, Vault>,
    /// Either party (the single-side path allows either party); an
    /// AV-104 operator is `Unauthorized`. The real build requires
    /// both parties as signers.
    pub caller: Signer<'info>,
    /// CHECK: the counterparty's signature (see `LinkSwap`).
    pub counterparty: Signer<'info>,
    /// CHECK: leg A's refund destination (AV-23).
    pub refund_to_a: AccountInfo<'info>,
    /// CHECK: leg B's refund destination.
    pub refund_to_b: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the expiry gate (never an
    /// instruction param).
    pub clock: AccountInfo<'info>,
    /// CHECK: leg A's vault SPL token account (see `Release`).
    pub vault_token_account_a: AccountInfo<'info>,
    /// CHECK: leg B's vault SPL token account (see `Release`).
    pub vault_token_account_b: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CancelPartial<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
    /// CHECK: the refund destination account. AV-23: the state machine
    /// pins it against the escrow's refund policy (the whitelisted
    /// address, or the initializer with no whitelist) — a phishing
    /// frontend cannot redirect the refund by swapping this account.
    /// The real build transfers the partially-cancelled tranche to this
    /// account after the state machine's `RefundAddressMismatch` check
    /// passes.
    pub refund_to: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct PartialRefund<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
    /// CHECK: the refund destination account. AV-23: the state machine
    /// pins it against the escrow's refund policy (the whitelisted
    /// address, or the initializer with no whitelist) — a phishing
    /// frontend cannot redirect the refund by swapping this account.
    /// The real build transfers the partially-refunded tranche to this
    /// account after the state machine's `RefundAddressMismatch` check
    /// passes.
    pub refund_to: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct CrankExpired<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// AV-48: ANY key may sign — no party-membership check. The state
    /// machine enforces the permissionless crank; the cranker receives
    /// nothing (anti-MEV).
    pub cranker: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the expiry comparison.
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
    /// CHECK: the refund destination account. AV-48: the handler
    /// asserts this equals the vault's pinned refund policy (the AV-23
    /// whitelist address when configured, otherwise the initializer) —
    /// the state machine pins it internally too, so a swapped account
    /// fails closed. The real build transfers the refund to this
    /// account.
    pub refund_to: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InitializeQuorum<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer configures the quorum; the state machine
    /// rejects re-configuration once the escrow is funded.
    pub initializer: Signer<'info>,
}

/// AV-130: accounts for `initialize_dual_control` — the initializer
/// binds the maker's checker key while the escrow is `Uninitialized`.
#[derive(Accounts)]
pub struct InitializeDualControl<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into dual control; the state machine
    /// rejects re-configuration once the escrow is funded.
    pub initializer: Signer<'info>,
}

/// AV-134: accounts for `initialize_amount_bounds` — the initializer
/// fixes the funding amount window while the escrow is
/// `Uninitialized`.
#[derive(Accounts)]
pub struct InitializeAmountBounds<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into funding bounds; the state
    /// machine rejects re-configuration once the escrow is funded.
    pub initializer: Signer<'info>,
}

/// AV-135: accounts for `initialize_arbiter_fee` — the initializer
/// fixes the arbiter adjudication fee while the escrow is
/// `Uninitialized`.
#[derive(Accounts)]
pub struct InitializeArbiterFee<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into the arbiter fee; the state
    /// machine rejects re-configuration once the escrow is funded.
    pub initializer: Signer<'info>,
}

/// AV-130: accounts for `initiate_release` — the maker freezes the
/// release declaration into the vault.
#[derive(Accounts)]
pub struct InitiateRelease<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The declaration authority: the initializer, or their
    /// `RELEASE`-scoped operator. The payout destination is pinned by
    /// the state machine, so an operator cannot redirect funds.
    pub authority: Signer<'info>,
    /// The declaration clock (the AV-27 rule: the state machine reads
    /// the clock, never an instruction param).
    pub clock: Sysvar<'info, Clock>,
}

/// AV-130: accounts for `confirm_release` — the checker approves the
/// live declaration and it settles.
#[derive(Accounts)]
pub struct ConfirmRelease<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Must equal the bound checker key — the state machine rejects
    /// anyone else with `Unauthorized`.
    pub checker: Signer<'info>,
    /// The freshness clock (the AV-27 rule).
    pub clock: Sysvar<'info, Clock>,
}

/// AV-130: accounts for `cancel_release` — either party aborts the
/// live declaration.
#[derive(Accounts)]
pub struct CancelRelease<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The initializer (the maker, retracting) or the bound checker
    /// (refusing); the state machine rejects a stranger with
    /// `Unauthorized`.
    pub caller: Signer<'info>,
    /// The abort clock (the AV-27 rule).
    pub clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
pub struct Attest<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Must be one of the registered attestors; the state machine
    /// rejects anyone else with `Unauthorized`.
    pub attestor: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateQuorum<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// First governance signer: must equal the escrow's initializer.
    /// Both parties must sign — one alone is `Unauthorized`.
    pub initializer: Signer<'info>,
    /// Second governance signer: must equal the escrow's taker.
    pub taker: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateAttestors<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// First governance signer: must equal the escrow's initializer.
    /// Both parties must sign — one alone is `Unauthorized`, so no
    /// party can unilaterally reshape the attestor electorate.
    pub initializer: Signer<'info>,
    /// Second governance signer: must equal the escrow's taker.
    pub taker: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeDualSig<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into dual-signature activation; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct Activate<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker; the state machine enforces
    /// the either-party rule and the per-party idempotency. A constraint
    /// in the real build additionally asserts `authority.key() ==
    /// vault.initializer || authority.key() == vault.taker`.
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeVesting<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer fixes the unlock curve; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

/// AV-90: accounts for `initialize_vesting_curve` — same shape as
/// `InitializeVesting`: only the initializer fixes the unlock curve.
#[derive(Accounts)]
pub struct InitializeVestingCurve<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer fixes the unlock curve; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

/// AV-97: accounts for `initialize_dutch_auction` — same shape as
/// `InitializeVesting`: only the initializer fixes the auction terms.
#[derive(Accounts)]
pub struct InitializeDutchAuction<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer fixes the auction window and reserve
    /// floor; the state machine rejects re-configuration once the
    /// escrow leaves `Uninitialized`, and rejects `start_at >=
    /// end_at` / `reserve_bps > 10_000` (`InvalidAuctionParams`, code
    /// 155).
    pub initializer: Signer<'info>,
}

/// AV-99: accounts for `initialize_transfer_hook` — same shape as
/// `InitializeMint`: only the initializer declares the hook binding.
#[derive(Accounts)]
pub struct InitializeTransferHook<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the transfer-hook program; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, the zero program id, and a declaration before
    /// `initialize_mint` bound a mint (`InvalidTransferHook`, code
    /// 157).
    pub initializer: Signer<'info>,
}

/// AV-100: accounts for `initialize_streaming_fee` — same shape as
/// `InitializeTransferHook`: only the initializer fixes the rate.
#[derive(Accounts)]
pub struct InitializeStreamingFee<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer fixes the streaming-fee rate; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized` (`InvalidStateTransition`). Any u64 rate is
    /// legal — `0` disables the fee.
    pub initializer: Signer<'info>,
}

/// AV-107: accounts for `initialize_interest` — same shape as
/// `InitializeStreamingFee`: only the initializer fixes the rate.
#[derive(Accounts)]
pub struct InitializeInterest<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer fixes the interest rate; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized` (`InvalidStateTransition`). `rate_bps` above
    /// 10000 is `InvalidInterestRate` (code 165); `0` disables the
    /// yield.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeCompoundInterest<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts in to compound-interest mode; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized` (`InvalidStateTransition`).
    pub initializer: Signer<'info>,
}

/// AV-107: accounts for `claim_interest` — the taker harvests the
/// accrued yield; the clock is read from the sysvar (never an
/// instruction param).
#[derive(Accounts)]
pub struct ClaimInterest<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the taker may harvest the yield; the state machine
    /// rejects anyone else with `Unauthorized`.
    pub taker: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the lazy interest
    /// settlement (never an instruction param).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Claim`). The real
    /// build funds the yield transfer from the vault's holdings;
    /// unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

/// AV-108: accounts for `initialize_payout_split` — same shape as
/// `InitializeInterest`: only the initializer declares the table.
#[derive(Accounts)]
pub struct InitializePayoutSplit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the split table; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized` (`InvalidStateTransition`). A bad table is
    /// `InvalidPayoutSplit` (code 167).
    pub initializer: Signer<'info>,
}

/// AV-108: accounts for `release_payout_split` — the per-leg payout
/// accounts ride `remaining_accounts` in table order, mirroring
/// `ReleaseSplit`'s leg wiring.
#[derive(Accounts)]
pub struct ReleasePayoutSplit<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The initializer, the taker, or their RELEASE-scoped operator
    /// (AV-104); the state machine enforces the scope
    /// (`Unauthorized` otherwise).
    pub authority: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the timelock/quorum
    /// gates (never an instruction param).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build funds the per-leg transfers from the vault's holdings;
    /// unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

/// AV-109: accounts for `initialize_deadman_switch` — same shape as
/// `InitializePayoutSplit`: only the initializer declares the switch.
#[derive(Accounts)]
pub struct InitializeDeadmanSwitch<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the dead-man's switch; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized` (`InvalidStateTransition`). A zero threshold or
    /// zero heir is `InvalidDeadmanConfig` (code 168).
    pub initializer: Signer<'info>,
}

/// AV-109: accounts for `claim_deadman` — the heir claims the
/// remaining locked funds after the inactivity window lapses.
#[derive(Accounts)]
pub struct ClaimDeadman<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The configured heir — the only key `claim_deadman` accepts
    /// (`Unauthorized` otherwise); the state machine pins it against
    /// the vault's declared heir. The heir is not required to be
    /// either party.
    pub heir: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the inactivity gate
    /// (never an instruction param).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build funds the heir's transfer from the vault's holdings;
    /// unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

/// AV-110: accounts for `top_up_rent` — anyone tops up the vault's
/// lamport balance so it stays rent-exempt.
#[derive(Accounts)]
pub struct TopUpRent<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The topping-up caller — permissionless, so any signer works;
    /// the state machine records it only as the event actor. The
    /// real build transfers `lamports` from this key's wallet into
    /// the vault account.
    pub caller: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the event's `at`
    /// (never an instruction param).
    pub clock: AccountInfo<'info>,
}

/// AV-111: accounts for `initialize_funding_plan` — the initializer
/// opts the escrow into tranched funding before any funds move.
#[derive(Accounts)]
pub struct InitializeFundingPlan<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer may fix the funding schedule; the state
    /// machine runs the `Uninitialized`-only builder check.
    pub initializer: Signer<'info>,
}

/// AV-111: accounts for `fund_tranche` — the initializer (or their
/// FUND-scoped operator) deposits one funding tranche.
#[derive(Accounts)]
pub struct FundTranche<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The funding authority — the initializer or their FUND-scoped
    /// operator (AV-104 delegation); the state machine checks the
    /// scope. The real build transfers `tranche_amount` from this
    /// key's wallet / token account into the vault.
    pub authority: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for `now`/`at` (never
    /// instruction params).
    pub clock: AccountInfo<'info>,
}

/// AV-112: accounts for `initialize_release_cooling` — the
/// initializer opts the escrow into the release cooling window
/// before any funds move.
#[derive(Accounts)]
pub struct InitializeReleaseCooling<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer may fix the release governance; the state
    /// machine runs the `Uninitialized`-only builder check.
    pub initializer: Signer<'info>,
}

/// AV-112: accounts for `announce_release` / `veto_release` — either
/// party records or cancels the release intent.
#[derive(Accounts)]
pub struct AnnounceRelease<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The announcing party — the initializer or the taker (party
    /// power: a stranger or an AV-104 operator is `Unauthorized` in
    /// the state machine).
    pub authority: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for `now`/`at` (never
    /// instruction params).
    pub clock: AccountInfo<'info>,
}

/// AV-112: accounts for `veto_release` — either party cancels the
/// live release intent.
#[derive(Accounts)]
pub struct VetoRelease<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The vetoing party — the initializer or the taker (party power:
    /// a stranger or an AV-104 operator is `Unauthorized` in the
    /// state machine).
    pub authority: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for `now`/`at` (never
    /// instruction params).
    pub clock: AccountInfo<'info>,
}

/// AV-113: accounts for `initialize_price_gate` — the initializer
/// fixes the oracle price-gate terms before funding.
#[derive(Accounts)]
pub struct InitializePriceGate<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer may fix the release governance; the state
    /// machine runs the `Uninitialized`-only builder check.
    pub initializer: Signer<'info>,
}

/// AV-128: accounts for `initialize_twap_gate` — the initializer
/// fixes the TWAP price-gate terms before funding.
#[derive(Accounts)]
pub struct InitializeTwapGate<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer may fix the release governance; the state
    /// machine runs the `Uninitialized`-only builder check.
    pub initializer: Signer<'info>,
}

/// AV-114: accounts for `merge_escrows` — the surviving target vault
/// and the absorbed source vault, plus the initializer signer (the
/// only authority that may merge) and the clock sysvar for the event
/// timestamps.
#[derive(Accounts)]
pub struct MergeEscrows<'info> {
    /// The surviving vault: absorbs the source's locked amount.
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The absorbed vault: moves to `Cancelled` with
    /// `released := amount`.
    #[account(mut)]
    pub source_vault: Account<'info, Vault>,
    /// Only the initializer may consolidate escrows; the state
    /// machine rejects anyone else with `Unauthorized`.
    pub authority: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the event `at` timestamps
    /// (never an instruction param).
    pub clock: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the taker may pull the vested stream; the state machine
    /// rejects anyone else with `Unauthorized`.
    pub taker: Signer<'info>,
    /// CHECK: explicit payout destination (AV-49; see `Release`). The
    /// state machine enforces the payout policy on it.
    pub payout_to: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the vesting curve (never an
    /// instruction param).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

/// AV-122: accounts for `decline_escrow` — the taker walks away
/// before any claim.
#[derive(Accounts)]
pub struct DeclineEscrow<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the taker may decline; the state machine rejects anyone
    /// else with `Unauthorized`.
    pub taker: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the deadman reset (never
    /// an instruction param).
    pub clock: AccountInfo<'info>,
}

/// AV-122: accounts for `propose_counter_offer` — the taker proposes
/// new amount/expiry terms.
#[derive(Accounts)]
pub struct ProposeCounterOffer<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the taker may propose; the state machine rejects anyone
    /// else with `Unauthorized`.
    pub taker: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the offer-expiry check
    /// and the deadman reset (never an instruction param).
    pub clock: AccountInfo<'info>,
}

/// AV-122: accounts for `accept_counter_offer` — the initializer
/// accepts the live counter-offer.
#[derive(Accounts)]
pub struct AcceptCounterOffer<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer may accept; the state machine rejects
    /// anyone else with `Unauthorized`.
    pub initializer: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the deadman reset (never
    /// an instruction param).
    pub clock: AccountInfo<'info>,
}

/// AV-122: accounts for `reject_counter_offer` — the initializer
/// rejects the live counter-offer.
#[derive(Accounts)]
pub struct RejectCounterOffer<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer may reject; the state machine rejects
    /// anyone else with `Unauthorized`.
    pub initializer: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the deadman reset (never
    /// an instruction param).
    pub clock: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InitializeDefaultJudgment<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer proposes the fallback terms; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, and the taker must still countersign via
    /// `confirm_default_judgment` before the judgment can be triggered.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ConfirmDefaultJudgment<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the taker completes the dual-signed agreement; the state
    /// machine rejects anyone else with `Unauthorized`. A constraint in
    /// the real build additionally asserts `taker.key() ==
    /// vault.taker`.
    pub taker: Signer<'info>,
}

#[derive(Accounts)]
pub struct TriggerDefaultJudgment<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker — the trigger is a liveness
    /// backstop, not a power grant. The state machine enforces the
    /// either-party rule; a constraint in the real build additionally
    /// asserts `caller.key() == vault.initializer || caller.key() ==
    /// vault.taker`.
    pub caller: Signer<'info>,
    /// CHECK: beneficiary of the taker's share of the fallback split.
    pub taker: AccountInfo<'info>,
    /// CHECK: explicit payout destination for the taker's share (AV-49;
    /// see `Release`). The state machine enforces the payout policy on
    /// it.
    pub payout_to: AccountInfo<'info>,
    /// CHECK: beneficiary of the initializer's refund share of the
    /// fallback split.
    pub initializer: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the arbitration-deadline
    /// check (never an instruction param — a caller-supplied timestamp
    /// could fast-forward the deadline).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InitializeArbiter<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into arbitration; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

/// AV-65: opt in to the arbiter-panel multisig judgment at initialize
/// time (replaces the single arbiter).
#[derive(Accounts)]
pub struct InitializeArbiterPanel<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into panel arbitration; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`. Mutually exclusive with the single arbiter —
    /// last-wins in both directions.
    pub initializer: Signer<'info>,
}

/// AV-137: opt in to blind (commit-reveal) panel voting at initialize
/// time (mirrors `Escrow::with_blind_panel`).
#[derive(Accounts)]
pub struct InitializeBlindPanel<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into blind panel arbitration; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`. Mutually exclusive with the single arbiter —
    /// last-wins in both directions.
    pub initializer: Signer<'info>,
}

/// AV-82: opt in to the default-penalty (slash) clause at initialize
/// time.
#[derive(Accounts)]
pub struct InitializeSlashTerms<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into the slash clause; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`.
    pub initializer: Signer<'info>,
}

/// AV-126: opt in to the tiered default-penalty (slash) ladder at
/// initialize time (mirrors `Escrow::with_slash_ladder`).
#[derive(Accounts)]
pub struct InitializeSlashLadder<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into the slash ladder; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`.
    pub initializer: Signer<'info>,
}

/// AV-82: slash the defaulting taker.
#[derive(Accounts)]
pub struct Slash<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The initializer, or the configured arbiter as the neutral
    /// enforcer; the state machine enforces the either-key rule. A
    /// constraint in the real build additionally asserts
    /// `authority.key() == vault.initializer || Some(authority.key())
    /// == vault.arbiter`.
    pub authority: Signer<'info>,
    /// CHECK: the penalty sink — the real build constrains
    /// `penalty_account.key()` to equal the slash terms' penalty
    /// account, so the destination cannot be swapped.
    pub penalty_account: AccountInfo<'info>,
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

/// AV-86: opt into the slash-appeal window (pre-fund configuration).
#[derive(Accounts)]
pub struct InitializeAppealWindow<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer fixes the appeal window; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

/// AV-86: the taker files an appeal against the executed slash.
#[derive(Accounts)]
pub struct FileAppeal<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Must equal the escrow's taker; the state machine rejects anyone
    /// else with `Unauthorized` (checked before state validity, so a
    /// stranger learns nothing about the slash). A constraint in the
    /// real build additionally asserts `taker.key() == vault.taker`.
    pub taker: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the appeal-window check
    /// (never an instruction param — a caller-supplied timestamp could
    /// rewind back inside the window).
    pub clock: AccountInfo<'info>,
}

/// AV-86: one panel member casts their review vote on the filed appeal.
#[derive(Accounts)]
pub struct ReviewAppeal<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Must be one of the panel's member keys; the state machine
    /// rejects anyone else with `Unauthorized`. A constraint in the
    /// real build additionally asserts the key is a panel member.
    pub member: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the event's `at` timestamp.
    pub clock: AccountInfo<'info>,
}

/// AV-103: opt into the appeal bond (pre-fund configuration).
#[derive(Accounts)]
pub struct InitializeAppealBond<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer fixes the appeal bond; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

/// AV-103: permissionless sweep of a filed appeal whose window lapsed
/// unresolved.
#[derive(Accounts)]
pub struct ExpireAppeal<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Anyone may crank a lapsed appeal (the state machine performs no
    /// authority check); the forfeited bond routes to the initializer,
    /// never the caller.
    pub caller: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the window-lapse check
    /// (never an instruction param).
    pub clock: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Escalate<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker; the state machine enforces
    /// the either-party rule. A constraint in the real build additionally
    /// asserts `authority.key() == vault.initializer || authority.key() ==
    /// vault.taker`.
    pub authority: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the dispute-window check
    /// (never an instruction param — a caller-supplied timestamp could
    /// rewind past the window).
    pub clock: AccountInfo<'info>,
}

/// AV-91: accounts for `file_evidence` — same shape as `Escalate`:
/// only the recorded escalator may file (the state machine enforces
/// it), and the clock sysvar supplies `now` for the AV-68 disclosure
/// deadline check.
#[derive(Accounts)]
pub struct FileEvidence<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The recorded escalating party; the state machine rejects anyone
    /// else with `Unauthorized`, mirroring `SubmitEvidence`.
    pub authority: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the disclosure-deadline
    /// check (never an instruction param).
    pub clock: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct SubmitEvidence<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Must equal the escalating party recorded by `escalate`; the
    /// state machine rejects anyone else with `Unauthorized`. A
    /// constraint in the real build additionally asserts
    /// `authority.key() == vault.escalated_by`.
    pub authority: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the disclosure-deadline
    /// check (never an instruction param — a caller-supplied timestamp
    /// could rewind past the deadline).
    pub clock: AccountInfo<'info>,
}

/// Accounts for AV-69 `update_panel_threshold`: the vault plus both
/// parties as signers (dual-signed governance — one party alone must
/// never be able to lower the bar toward a friendly minority or raise
/// it to deadlock the panel). The state machine rejects a stranger
/// pair with `Unauthorized`; a constraint in the real build
/// additionally asserts `initializer.key() == vault.initializer` and
/// `taker.key() == vault.taker`.
#[derive(Accounts)]
pub struct UpdatePanelThreshold<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
    pub taker: Signer<'info>,
    /// CHECK: Solana clock sysvar, read for the event's `at` timestamp.
    pub clock: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Resolve<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Must equal the configured arbiter; the state machine rejects
    /// anyone else with `Unauthorized`. A constraint in the real build
    /// additionally asserts `arbiter.key() == vault.arbiter`.
    pub arbiter: Signer<'info>,
    /// CHECK: beneficiary of the taker's share of the split.
    pub taker: AccountInfo<'info>,
    /// CHECK: explicit payout destination for the taker's share (AV-49;
    /// see `Release`). The state machine enforces the payout policy on
    /// it.
    pub payout_to: AccountInfo<'info>,
    /// CHECK: beneficiary of the initializer's refund share of the split.
    pub initializer: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

/// AV-65: one panel member submits their judgment on a disputed escrow.
#[derive(Accounts)]
pub struct SubmitPanelJudgment<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Must be one of the panel's member keys; the state machine
    /// rejects anyone else with `Unauthorized`. A constraint in the real
    /// build additionally asserts the key is a panel member.
    pub member: Signer<'info>,
    /// CHECK: beneficiary of the taker's share of the split (on the
    /// settling vote).
    pub taker: AccountInfo<'info>,
    /// CHECK: explicit payout destination for the taker's share (AV-49;
    /// see `Resolve`). The state machine enforces the payout policy on
    /// it — checked only on the settling vote.
    pub payout_to: AccountInfo<'info>,
    /// CHECK: beneficiary of the initializer's refund share of the split
    /// (on the settling vote).
    pub initializer: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InitializeMilestones<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer fixes the tranche schedule; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ConfirmMilestone<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker; the state machine enforces
    /// the either-party rule and the per-party idempotency. A constraint
    /// in the real build additionally asserts `authority.key() ==
    /// vault.initializer || authority.key() == vault.taker`.
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReleaseMilestone<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer drives tranche releases; the state machine
    /// enforces the dual-confirmation gate.
    pub initializer: Signer<'info>,
    /// CHECK: beneficiary of the tranche; receives the funds.
    pub taker: AccountInfo<'info>,
    /// CHECK: explicit payout destination (AV-49; see `Release`). The
    /// state machine enforces the payout policy on it.
    pub payout_to: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the AV-27 timelock gate
    /// (never an instruction param — see `Release`).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

/// AV-56: declare the periodic subscription release schedule
/// (periods / cadence / per-period amount as instruction params).
#[derive(Accounts)]
pub struct InitializeSubscription<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the release schedule; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized` (and rejects a schedule when a milestone plan
    /// is already attached — the two are mutually exclusive).
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReleasePeriod<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer drives period releases; the state machine
    /// enforces the in-order, due-date, quorum and timelock gates.
    pub initializer: Signer<'info>,
    /// CHECK: beneficiary of the period tranche; receives the funds.
    pub taker: AccountInfo<'info>,
    /// CHECK: explicit payout destination (AV-49; see `Release`). The
    /// state machine enforces the payout policy on it.
    pub payout_to: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the period due-date check
    /// (and the AV-27 timelock gate) — never an instruction param
    /// (see `Release`).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account (see `Release`). The real
    /// build reads its `mint` for the state machine's `MintMismatch`
    /// check; unused on the native-SOL path.
    pub vault_token_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct InitializeRefundAddress<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the refund whitelist; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializePenalty<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the anti-griefing penalty rate;
    /// the state machine rejects re-configuration once the escrow
    /// leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializePenaltyEscalation<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the penalty escalation schedule;
    /// the state machine rejects re-configuration once the escrow
    /// leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeTimelock<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the timelock; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeRelativeTimelock<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the relative timelock; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, and rejects a nonzero duration together with a
    /// nonzero AV-27 absolute timelock (`InvalidTimelock`).
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeSlotTimelock<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the slot-based relative timelock;
    /// the state machine rejects re-configuration once the escrow
    /// leaves `Uninitialized`, and rejects a nonzero slot duration
    /// together with a nonzero AV-27 absolute timelock or AV-64
    /// relative timelock (`InvalidTimelock`).
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeClaimCooldown<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into the per-taker claim cooldown;
    /// the state machine rejects re-configuration once the escrow
    /// leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeDecimals<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer declares the token decimal metadata; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeEmergencyUnlock<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer opts into emergency timelock-unlock
    /// governance; the state machine rejects re-configuration once the
    /// escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeFeeRecipient<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer pins the protocol-fee recipient; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, and rejects the zero address.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializePauseAuthority<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer binds the emergency-pause authority; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, and rejects the zero address.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct Pause<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The bound pause authority; the state machine checks it against
    /// the opted-in address (`Unauthorized` for anyone else, and the
    /// switch must exist).
    pub pause_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Unpause<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The bound pause authority (same rules as `Pause`).
    pub pause_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct RotatePauseAuthority<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The escrow authority (initializer) — rotation is an
    /// owner-governance power, so the *escrow* authority signs, not the
    /// pause key. A stranger (or the taker) is `Unauthorized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct RotateTaker<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// First governance signer: must equal the escrow's initializer.
    /// Both parties must sign — one alone (or a stranger pair) is
    /// `Unauthorized`.
    pub initializer: Signer<'info>,
    /// Second governance signer: must equal the escrow's *current*
    /// taker. The old key consents to its own replacement, so a stolen
    /// new key cannot self-install. A constraint in the real build
    /// additionally asserts `old_taker.key() == vault.taker`.
    pub old_taker: Signer<'info>,
}

#[derive(Accounts)]
pub struct RotateInitializer<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// First governance signer: must equal the escrow's *current*
    /// initializer. The old key consents to its own replacement, so a
    /// stolen new key cannot self-install. A constraint in the real
    /// build additionally asserts `old_initializer.key() ==
    /// vault.initializer`.
    pub old_initializer: Signer<'info>,
    /// Second governance signer: must equal the escrow's taker. Both
    /// parties must sign — one alone (or a stranger pair) is
    /// `Unauthorized`; the degenerate initializer == taker self-escrow
    /// authorizes with one key passed twice, like AV-12 activation.
    pub taker: Signer<'info>,
}

#[derive(Accounts)]
pub struct RotateArbiter<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// First governance signer: must equal the escrow's *current*
    /// initializer. Both parties must sign — one alone (or a stranger
    /// pair) is `Unauthorized`; the degenerate initializer == taker
    /// self-escrow authorizes with one key passed twice, like AV-12
    /// activation.
    pub initializer: Signer<'info>,
    /// Second governance signer: must equal the escrow's *current*
    /// taker. The arbiter itself does not sign: rotation is the two
    /// parties' governance, not an arbiter power — a lost arbiter key
    /// must not block its own replacement.
    pub taker: Signer<'info>,
}

#[derive(Accounts)]
pub struct RotateFeeRecipient<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// First governance signer: must equal the escrow's *current*
    /// initializer. Both parties must sign — one alone (or a stranger
    /// pair) is `Unauthorized`; the degenerate initializer == taker
    /// self-escrow authorizes with one key passed twice, like AV-12
    /// activation.
    pub initializer: Signer<'info>,
    /// Second governance signer: must equal the escrow's *current*
    /// taker. The fee recipient itself does not sign: rotation is the
    /// two parties' governance, not a treasury power — a lost
    /// fee-recipient key must not block its own replacement.
    pub taker: Signer<'info>,
}

#[derive(Accounts)]
/// AV-70: accounts for `adjust_milestone_amounts` — the dual-signed
/// milestone tranche re-split.
pub struct AdjustMilestoneAmounts<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// First governance signer: must equal the escrow's *current*
    /// initializer. Both parties must sign — one alone (or a stranger
    /// pair) is `Unauthorized`; the degenerate initializer == taker
    /// self-escrow authorizes with one key passed twice, like AV-12
    /// activation.
    pub initializer: Signer<'info>,
    /// Second governance signer: must equal the escrow's *current*
    /// taker.
    pub taker: Signer<'info>,
}

#[derive(Accounts)]
/// AV-73: accounts for `adjust_period_amounts` — the dual-signed
/// subscription per-period re-split.
pub struct AdjustPeriodAmounts<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// First governance signer: must equal the escrow's *current*
    /// initializer. Both parties must sign — one alone (or a stranger
    /// pair) is `Unauthorized`; the degenerate initializer == taker
    /// self-escrow authorizes with one key passed twice, like AV-12
    /// activation.
    pub initializer: Signer<'info>,
    /// Second governance signer: must equal the escrow's *current*
    /// taker.
    pub taker: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeExtension<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer sets the setup-time extension policy; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, and rejects a zero bound (`InvalidExpiryExtension`,
    /// code 134).
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeFeeCap<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer sets the setup-time fee ceiling; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`. A zero cap is valid — it means "uncapped" (no
    /// error, unlike the extension bound above).
    pub initializer: Signer<'info>,
}

/// AV-66: opt in to the tiered protocol-fee schedule at initialize
/// time (volume-priced rates instead of the flat bps rate).
#[derive(Accounts)]
pub struct InitializeFeeSchedule<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer sets the setup-time fee ladder; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, and rejects a ladder that conflicts with the
    /// flat rate or is malformed (`InvalidProtocolFee`, code 114).
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ExtendExpiry<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// The initializer extends unilaterally — extension only
    /// lengthens the taker's window, so no counterparty signature is
    /// needed. A stranger is `Unauthorized`.
    pub initializer: Signer<'info>,
}

/// AV-75: accounts for `migrate_schema` — the vault plus the
/// initializer as the single signer. The state machine rejects a
/// non-initializer with `Unauthorized`; a constraint in the real build
/// additionally asserts `initializer.key() == vault.initializer`.
/// Migration is bookkeeping, not economics: one call steps the schema
/// version exactly once (N → N+1), refusing an already-current vault
/// and an unknown future version (`InvalidSchemaMigration`, code 140).
#[derive(Accounts)]
pub struct MigrateSchema<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializePayoutAllowlist<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer sets the funding-time payout policy; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, and rejects empty / over-long / zero-address
    /// input (`InvalidPayoutAllowlist`, code 126).
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdatePayoutAllowlist<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Dual-signature governance: on a dual-sig escrow both initializer
    /// and taker sign; on a plain escrow the initializer alone (the
    /// state machine enforces this — a stranger is `Unauthorized`).
    pub initializer: Signer<'info>,
    pub taker: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializePayoutDenylist<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer sets the funding-time compliance veto; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, and rejects empty / over-long / zero-address
    /// input (`InvalidPayoutDenylist`, code 154).
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdatePayoutDenylist<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Initializer-signature-alone governance: the denylist is the
    /// initializer's compliance veto, not a bilateral fund route — the
    /// state machine enforces the initializer check and rejects
    /// strangers (`Unauthorized`), terminal states
    /// (`InvalidStateTransition`), and paused escrows (`Paused`).
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeCpiAllowlist<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer sets the funding-time CPI policy; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, and rejects empty / over-long / zero-address
    /// input (`InvalidCpiAllowlist`, code 144).
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateCpiAllowlist<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Always dual-signed: both initializer and taker sign even on a
    /// plain escrow — the CPI allowlist guards a privileged execution
    /// path, so it carries a stricter rule than AV-49 by design (the
    /// state machine enforces this — a stranger is `Unauthorized`).
    pub initializer: Signer<'info>,
    pub taker: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeMultisigAuthority<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer binds the multisig authority; the state
    /// machine rejects binding once the escrow leaves `Uninitialized`,
    /// and rejects a zero multisig program id, a zero authority PDA,
    /// or a zero threshold (`InvalidMultisigAuthority`, code 145).
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeReference<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer binds the off-chain reference memo; the
    /// state machine rejects binding once the escrow leaves
    /// `Uninitialized`. Any 32 bytes are accepted — the memo is
    /// read-only pass-through, never validated.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct EmergencyUnlock<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// First governance signer: must equal the escrow's initializer.
    /// Both parties must sign — one alone is `Unauthorized`.
    pub initializer: Signer<'info>,
    /// Second governance signer: must equal the escrow's taker.
    pub taker: Signer<'info>,
}

#[derive(Accounts)]
pub struct SkipMilestone<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Either the initializer or the taker; the state machine records one
    /// party's skip approval per call and executes the skip only once
    /// both approved. A constraint in the real build additionally asserts
    /// `authority.key() == vault.initializer || authority.key() ==
    /// vault.taker`.
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeMint<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer binds the token mint; the state machine
    /// rejects re-configuration once the escrow leaves `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeProtocolFee<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer configures the protocol fee; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeGracePeriod<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer configures the grace period; the state
    /// machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeEvidenceDeadline<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer configures the disclosure deadline; the
    /// state machine rejects re-configuration once the escrow leaves
    /// `Uninitialized`, and requires the arbiter (or panel) to be
    /// configured first.
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseVault<'info> {
    /// The vault closes through Anchor's `close` constraint: the runtime
    /// transfers the account's lamports — including the rent-exempt
    /// deposit (`escrow_state::vault_close_rent_reclaimed`, the same
    /// figure `initialize` demanded via
    /// `escrow_state::check_vault_rent_exempt`) — to `initializer` and
    /// zeroes the account. `close` implies `mut`. In the real build this
    /// is the account-close CPI: no explicit system-program instruction
    /// is needed beyond the constraint.
    #[account(mut, close = initializer)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer closes the vault; the state machine
    /// additionally checks authority before state validity
    /// (`Unauthorized` otherwise). A constraint in the real build
    /// asserts `initializer.key() == vault.initializer`.
    #[account(mut)]
    pub initializer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReleaseAndClose<'info> {
    /// AV-50: the vault closes through Anchor's `close` constraint in
    /// the same instruction that settles the payout — the runtime
    /// transfers the account's lamports, including the rent-exempt
    /// deposit (`escrow_state::vault_close_rent_reclaimed`, the same
    /// figure `initialize` demanded via
    /// `escrow_state::check_vault_rent_exempt`), to `initializer` and
    /// zeroes the account. `close` implies `mut`. Combines `Release`'s
    /// settlement accounts with `CloseVault`'s close: one signature
    /// instead of two.
    #[account(mut, close = initializer)]
    pub vault: Account<'info, Vault>,
    /// Only the initializer releases and closes; the state machine
    /// checks authority before state validity (`Unauthorized`
    /// otherwise, so strangers learn nothing about state). A constraint
    /// in the real build asserts `initializer.key() == vault.initializer`.
    #[account(mut)]
    pub initializer: Signer<'info>,
    /// CHECK: beneficiary of the release; receives the funds.
    pub taker: AccountInfo<'info>,
    /// CHECK: explicit payout destination (AV-49). The state machine
    /// requires it to satisfy the escrow's payout policy: the taker,
    /// or a member of the payout allowlist when one is configured
    /// (`PayoutNotAllowlisted`, code 127, otherwise). Passed as an
    /// account (not a param) so the IDL names the destination.
    pub payout_to: AccountInfo<'info>,
    /// CHECK: Solana clock sysvar, read for the AV-27 timelock gate
    /// (never an instruction param — a caller-supplied timestamp would
    /// let the initializer fast-forward the lock).
    pub clock: AccountInfo<'info>,
    /// CHECK: the vault's SPL token account. The real build reads this
    /// account's `mint` and the state machine requires it to equal the
    /// bound `vault.mint` (`MintMismatch` otherwise). Unused on the
    /// native-SOL path — the state machine then requires `None`.
    pub vault_token_account: AccountInfo<'info>,
}

// --- Helpers (finalized during the real Anchor build) ---

fn read_escrow(_vault: &Account<Vault>) -> escrow_state::Escrow {
    unimplemented!("deserialize Vault account into escrow_state::Escrow")
}

fn read_clock_unix_timestamp(_clock: &AccountInfo) -> u64 {
    unimplemented!("read Clock::get()?.unix_timestamp as u64 in the real build")
}

/// Read the vault's SPL token account mint for the state machine's
/// `MintMismatch` check (AV-16). Returns `None` on the native-SOL path
/// (no mint bound, no token accounts) — the state machine then requires
/// `vault.mint` to be `None` too.
fn vault_token_mint(_token_account: &AccountInfo) -> Option<[u8; 32]> {
    unimplemented!("read the SPL token account's mint in the real build; None on the native-SOL path")
}

/// AV-113: read the oracle price quote for a price-gated `release` /
/// `claim`. The oracle account travels as the first remaining account;
/// its data carries the 16-byte quote (`price` u64 LE ++ `observed_at`
/// u64 LE — the keeper writes the oracle's latest observation there).
/// A missing account or short data is `PriceGateNotSatisfied` — a dark
/// oracle fails the gate, never passes silently.
fn read_oracle_quote(remaining: &[AccountInfo]) -> Result<escrow_state::PriceQuote> {
    let account = remaining.first().ok_or_else(|| {
        escrow_error(escrow_state::EscrowError::PriceGateNotSatisfied)
    })?;
    let data = account.try_borrow_data()?;
    if data.len() < 16 {
        return Err(escrow_error(
            escrow_state::EscrowError::PriceGateNotSatisfied,
        ));
    }
    let price = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let observed_at = u64::from_le_bytes(data[8..16].try_into().unwrap());
    Ok(escrow_state::PriceQuote { price, observed_at })
}

/// AV-113: the [`escrow_state::PriceFeed`] adapter for a single
/// already-read quote — the program reads the oracle account once
/// (`read_oracle_quote`) and feeds the fixed observation to the
/// state machine's gated entry points.
struct QuoteFeed(escrow_state::PriceQuote);

impl escrow_state::PriceFeed for QuoteFeed {
    fn quote(&self) -> Option<escrow_state::PriceQuote> {
        Some(self.0)
    }
}

/// AV-128: read the oracle price history for a TWAP-gated `release` /
/// `claim`. The oracle account travels as the first remaining account;
/// after the 16-byte quote (`price` u64 LE ++ `observed_at` u64 LE —
/// see `read_oracle_quote`), each 16-byte chunk is one [`PriceSample`]
/// (`slot` u64 LE ++ `price` u64 LE, any order). A missing account or
/// short quote is `TwapGateNotSatisfied` — a dark oracle fails the
/// gate, never passes silently. A trailing partial chunk is ignored
/// (the keeper pads the account; the state machine clamps samples to
/// the window anyway).
fn read_oracle_history(
    remaining: &[AccountInfo],
) -> Result<Vec<escrow_state::PriceSample>> {
    let account = remaining.first().ok_or_else(|| {
        escrow_error(escrow_state::EscrowError::TwapGateNotSatisfied)
    })?;
    let data = account.try_borrow_data()?;
    if data.len() < 16 {
        return Err(escrow_error(
            escrow_state::EscrowError::TwapGateNotSatisfied,
        ));
    }
    let mut history = Vec::new();
    let mut offset = 16;
    while offset + 16 <= data.len() {
        let slot = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        let price = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());
        history.push(escrow_state::PriceSample { slot, price });
        offset += 16;
    }
    Ok(history)
}

/// AV-128: the [`escrow_state::PriceFeed`] adapter for a TWAP gate —
/// the program reads the oracle account once (`read_oracle_quote` +
/// `read_oracle_history`) and feeds the fixed quote and history to
/// the state machine's twap-gated entry points.
struct TwapFeed {
    quote: escrow_state::PriceQuote,
    history: Vec<escrow_state::PriceSample>,
}

impl escrow_state::PriceFeed for TwapFeed {
    fn quote(&self) -> Option<escrow_state::PriceQuote> {
        Some(self.quote)
    }

    fn price_history(&self) -> Vec<escrow_state::PriceSample> {
        self.history.clone()
    }
}

fn write_escrow(_vault: &mut Account<Vault>, _escrow: &escrow_state::Escrow) {
    unimplemented!("serialize escrow_state::Escrow back into the Vault account")
}

/// AV-18: build and `emit!` the indexer event for one state transition,
/// mirroring `escrow_state::EscrowEvent`.
///
/// `from_state` is the vault's state before the transition, `to_state`
/// after; `payout` / `fee` / `refund` carry the fund movements (zeroed
/// when the kind moves nothing); `at` is the clock sysvar's unix
/// timestamp — the on-chain source of the caller-supplied `at` the
/// `IndexedEscrow` wrapper takes off-chain. `seq` is the vault's
/// persisted per-escrow event counter (`read_event_seq`).
/// `evidence_hash` (AV-22) is the dispute-evidence commitment carried by
/// the `Escalated` and `Resolved` events (`None` for every other kind),
/// mirroring `escrow_state::EscrowEvent::evidence_hash`.
/// `rationale_hash` (AV-38) is the arbiter's rationale-document
/// commitment carried by the `Resolved` event (`None` for every other
/// kind), mirroring `escrow_state::EscrowEvent::rationale_hash`.
/// `cpi_target` / `cpi_accounts_hash` (AV-35) carry the CPI-routing
/// audit on a `Released` event whose payout flowed through a
/// third-party program (`None` on every other kind), mirroring
/// `escrow_state::EscrowEvent::cpi`.
fn emit_transition(
    vault: &Account<Vault>,
    kind: escrow_state::EscrowEventKind,
    from_state: u8,
    to_state: u8,
    payout: u64,
    fee: u64,
    refund: u64,
    at: u64,
    evidence_hash: Option<[u8; 32]>,
    rationale_hash: Option<[u8; 32]>,
    cpi_target: Option<Pubkey>,
    cpi_accounts_hash: Option<[u8; 32]>,
    caller: Option<Pubkey>,
) {
    // AV-68: the judgment-time adverse-inference signal rides the
    // settlement kinds — read from the vault's escrow at emit time
    // (mirroring `IndexedEscrow`), so the event stream always agrees
    // with the account.
    let evidence_defaulted = matches!(
        kind,
        escrow_state::EscrowEventKind::Resolved
            | escrow_state::EscrowEventKind::DefaultJudgment
            | escrow_state::EscrowEventKind::PanelResolved
    ) && read_escrow(vault).evidence_defaulted(at);
    emit!(EscrowVaultEvent {
        kind: escrow_event_kind(kind),
        vault: vault.key(),
        seq: read_event_seq(vault),
        from_state,
        to_state,
        payout,
        fee,
        refund,
        at,
        evidence_hash,
        evidence_defaulted,
        rationale_hash,
        cpi_target,
        cpi_accounts_hash,
        caller,
        // AV-53: the off-chain reference memo rides every event — read
        // from the vault's escrow at emit time, so the event stream
        // always agrees with the account.
        reference: read_escrow(vault).reference(),
    });
}

/// AV-18: read the vault's persisted per-escrow event sequence counter.
/// The real build stores it in the Vault account (appended after
/// `fees_paid`; `VAULT_SPACE` grows 540 → 548) and increments it on
/// every emission, so `seq` stays monotonic across transactions.
fn read_event_seq(_vault: &Account<Vault>) -> u64 {
    unimplemented!("read the vault's persisted event_seq in the real build")
}

/// AV-31: settlement CPI wiring (reference — not compiled by CI).
///
/// AV-35: third-party CPI invocation for `release_via_cpi` (reference —
/// not compiled by CI).
///
/// The target program id is `remaining_accounts[0]`; the rest are the
/// target instruction's accounts in its expected order. The state
/// machine validates the invocation shape (`InvalidCpiTarget`) before
/// settling; the real build then invokes the target program with the
/// vault PDA as signer:
///
/// ```ignore
/// let ix = anchor_lang::solana_program::instruction::Instruction {
///     program_id: invocation.program_id,
///     accounts: invocation.accounts.iter().map(|m| AccountMeta {
///         pubkey: m.pubkey,
///         is_signer: m.is_signer,
///         is_writable: m.is_writable,
///     }).collect(),
///     data: invocation.data.clone(),
/// };
/// // The vault PDA signs through `invoke_signed` with the vault seeds,
/// // exactly like the AV-31 settlement CPIs.
/// anchor_lang::solana_program::program::invoke_signed(
///     &ix,
///     &ctx.remaining_accounts,
///     &[&vault_seeds],
/// )?;
/// ```
///
/// A failed invoke aborts the transaction: no state change persists.
/// That is the on-chain atomicity the state machine's rollback
/// (`CpiExecutionFailed`) models in pure logic.
fn cpi_invocation_from_remaining_accounts(
    remaining: &[AccountInfo],
    data: Vec<u8>,
) -> Result<escrow_state::CpiInvocation> {
    let (program, accounts) = remaining.split_first().ok_or(error!(ErrorCode::InvalidCpiTarget))?;
    Ok(escrow_state::CpiInvocation {
        program_id: program.key().to_bytes(),
        accounts: accounts
            .iter()
            .map(|a| escrow_state::AccountMeta {
                pubkey: a.key().to_bytes(),
                is_signer: a.is_signer,
                is_writable: a.is_writable,
            })
            .collect(),
        data,
    })
}

/// AV-35: invoke the third-party program (reference — not compiled by
/// CI). The real build performs the `invoke_signed` sketched above,
/// with the vault PDA signing through the vault seeds. Any invoke
/// failure surfaces here and — via the state machine's executor seam —
/// rolls the whole release back (`CpiExecutionFailed`); the caller
/// observes the chain abort the transaction instead.
fn cpi_invoke_target(
    _ctx: &Context<ReleaseViaCpi>,
    _invocation: &escrow_state::CpiInvocation,
) -> std::result::Result<u64, escrow_state::CpiError> {
    unimplemented!("invoke the target program via CPI with the vault PDA as signer in the real build; return the actual post-execution taker-leg amount (the taker-leg account's balance delta across the invoke) so the state machine can enforce the AV-132 min_payout slippage floor")
}

/// AV-31: settlement CPI wiring (reference — not compiled by CI).
///
/// The fund-moving instructions (`release`, `claim`, `release_milestone`,
/// `cancel`, `cancel_expired`, `resolve`) compute amounts through the
/// pure-logic state machine and then move lamports/tokens with CPI calls.
/// The transfer *instruction bytes* are constructed and validated off-chain
/// by `escrow_state::cpi` (zero dependencies, fully unit-tested):
///
/// - `cpi::system_transfer` / `cpi::spl_token_transfer` assemble the exact
///   account metas and data bytes (System `Transfer` = u32 index 2 ||
///   u64 LE; SPL Token `Transfer` = u8 index 3 || u64 LE);
/// - `cpi::payout_plan` / `cpi::refund_plan` / `cpi::resolve_plan` take the
///   escrow *after* the transition plus the amounts the transition
///   returned, and reject tampered amounts (`SettlementMismatch`) and
///   swapped recipients (`RecipientMismatch`) before any instruction is
///   built.
///
/// The real build only *executes* a validated plan:
/// 1. assemble the `*Addrs` from the instruction's accounts (vault PDA /
///    vault token account as `source`, vault PDA as `vault_authority`,
///    taker/initializer/refund/fee accounts as the legs);
/// 2. call the matching `cpi::*_plan` — a `CpiError` maps to the program
///    error below and aborts before any lamport moves;
/// 3. execute each `TransferInstruction`: native-SOL legs via
///    `solana_program::program::invoke` against the System Program (the
///    vault PDA signs through `invoke_signed` with the vault seeds), SPL
///    legs via `anchor_spl::token::transfer` CPI.
///
/// Because the program never hand-rolls instruction bytes, the on-chain
/// code cannot drift from the byte layout pinned by the `escrow-state`
/// unit tests; the IDL mapping tests pin which instruction maps to which
/// plan kind.
fn cpi_settle_payout(
    _vault: &Account<Vault>,
    _escrow: &escrow_state::Escrow,
    _kind: escrow_state::PayoutKind,
    _payout: u64,
    _fee: u64,
) {
    unimplemented!(
        "real build: escrow_state::cpi::payout_plan, then one CPI per leg \
         (invoke/invoke_signed for native SOL, anchor_spl::token::transfer for SPL)"
    )
}

/// AV-31: reference wiring for `cancel` / `cancel_expired` settlements.
/// See [`cpi_settle_payout`] for the build-then-execute flow; the plan
/// kind is `cpi::RefundKind::Cancel` / `CancelExpired`, the refund leg
/// targets the AV-23-pinned `refund_to`, and the penalty leg (taker-
/// initiated expiry cancels only, AV-24) targets the initializer.
fn cpi_settle_refund(
    _vault: &Account<Vault>,
    _escrow: &escrow_state::Escrow,
    _kind: escrow_state::RefundKind,
    _refund: u64,
    _penalty: u64,
) {
    unimplemented!(
        "real build: escrow_state::cpi::refund_plan, then one CPI per leg \
         (invoke/invoke_signed for native SOL, anchor_spl::token::transfer for SPL)"
    )
}

/// AV-31: reference wiring for the `resolve` three-way split. The plan
/// kind is implicit (resolve is the only three-leg settlement): taker
/// payout leg, protocol-fee leg, initializer-refund leg — see
/// [`cpi_settle_payout`] for the build-then-execute flow.
fn cpi_settle_resolve(
    _vault: &Account<Vault>,
    _escrow: &escrow_state::Escrow,
    _taker_payout: u64,
    _fee: u64,
    _refund: u64,
) {
    unimplemented!(
        "real build: escrow_state::cpi::resolve_plan, then one CPI per leg \
         (invoke/invoke_signed for native SOL, anchor_spl::token::transfer for SPL)"
    )
}

fn escrow_error(e: escrow_state::EscrowError) -> Error {    // One program error per EscrowError variant, so on-chain failures
    // surface the exact `escrow_state` reason (code 100–150) to clients.
    match e {
        escrow_state::EscrowError::Unauthorized => error!(ErrorCode::Unauthorized),
        escrow_state::EscrowError::InvalidStateTransition => {
            error!(ErrorCode::InvalidStateTransition)
        }
        escrow_state::EscrowError::AmountMismatch => error!(ErrorCode::AmountMismatch),
        escrow_state::EscrowError::NotExpired => error!(ErrorCode::NotExpired),
        escrow_state::EscrowError::InvalidQuorum => error!(ErrorCode::InvalidQuorum),
        escrow_state::EscrowError::QuorumNotReached => error!(ErrorCode::QuorumNotReached),
        escrow_state::EscrowError::ReleaseExceedsLocked => {
            error!(ErrorCode::ReleaseExceedsLocked)
        }
        escrow_state::EscrowError::InvalidVesting => error!(ErrorCode::InvalidVesting),
        escrow_state::EscrowError::InvalidArbiter => error!(ErrorCode::InvalidArbiter),
        escrow_state::EscrowError::DisputeWindowClosed => {
            error!(ErrorCode::DisputeWindowClosed)
        }
        escrow_state::EscrowError::InvalidMilestones => error!(ErrorCode::InvalidMilestones),
        escrow_state::EscrowError::MilestoneNotConfirmed => {
            error!(ErrorCode::MilestoneNotConfirmed)
        }
        escrow_state::EscrowError::InvalidMint => error!(ErrorCode::InvalidMint),
        escrow_state::EscrowError::MintMismatch => error!(ErrorCode::MintMismatch),
        escrow_state::EscrowError::InvalidProtocolFee => error!(ErrorCode::InvalidProtocolFee),
        escrow_state::EscrowError::InvalidGracePeriod => error!(ErrorCode::InvalidGracePeriod),
        escrow_state::EscrowError::RefundAddressMismatch => {
            error!(ErrorCode::RefundAddressMismatch)
        },
        escrow_state::EscrowError::InvalidPenalty => error!(ErrorCode::InvalidPenalty),
        escrow_state::EscrowError::TimelockNotReached => error!(ErrorCode::TimelockNotReached),
        escrow_state::EscrowError::InvalidDecimals => error!(ErrorCode::InvalidDecimals),
        escrow_state::EscrowError::InvalidCpiTarget => error!(ErrorCode::InvalidCpiTarget),
        escrow_state::EscrowError::CpiExecutionFailed => error!(ErrorCode::CpiExecutionFailed),
        escrow_state::EscrowError::ReentrantCall => error!(ErrorCode::ReentrantCall),
        escrow_state::EscrowError::InvalidFeeRecipient => error!(ErrorCode::InvalidFeeRecipient),
        escrow_state::EscrowError::Paused => error!(ErrorCode::Paused),
        escrow_state::EscrowError::InvalidPauseAuthority => error!(ErrorCode::InvalidPauseAuthority),
        escrow_state::EscrowError::InvalidPayoutAllowlist => error!(ErrorCode::InvalidPayoutAllowlist),
        escrow_state::EscrowError::PayoutNotAllowlisted => error!(ErrorCode::PayoutNotAllowlisted),
        escrow_state::EscrowError::DefaultJudgmentNotDue => {
            error!(ErrorCode::DefaultJudgmentNotDue)
        }
        escrow_state::EscrowError::InvalidSubscription => {
            error!(ErrorCode::InvalidSubscription)
        }
        escrow_state::EscrowError::PeriodNotDue => error!(ErrorCode::PeriodNotDue),
        escrow_state::EscrowError::InvalidEventCapacity => {
            error!(ErrorCode::InvalidEventCapacity)
        }
        // AV-52: pre-existing gap — the skeleton mapped every variant
        // except InvalidTaker; the one-error-per-variant convention
        // (AV-06) requires it.
        escrow_state::EscrowError::InvalidTaker => error!(ErrorCode::InvalidTaker),
        escrow_state::EscrowError::InvalidInitializer => {
            error!(ErrorCode::InvalidInitializer)
        }
        escrow_state::EscrowError::InvalidExpiryExtension => {
            error!(ErrorCode::InvalidExpiryExtension)
        }
        escrow_state::EscrowError::InvalidTimelock => {
            error!(ErrorCode::InvalidTimelock)
        }
        escrow_state::EscrowError::InvalidArbiterPanel => {
            error!(ErrorCode::InvalidArbiterPanel)
        }
        escrow_state::EscrowError::PanelResolveDisabled => {
            error!(ErrorCode::PanelResolveDisabled)
        }
        escrow_state::EscrowError::InvalidEvidenceDeadline => {
            error!(ErrorCode::InvalidEvidenceDeadline)
        }
        escrow_state::EscrowError::EvidenceDisclosureLate => {
            error!(ErrorCode::EvidenceDisclosureLate)
        }
        escrow_state::EscrowError::InvalidSchemaMigration => {
            error!(ErrorCode::InvalidSchemaMigration)
        }
        escrow_state::EscrowError::TemplateOverrideRejected => {
            error!(ErrorCode::TemplateOverrideRejected)
        }
        escrow_state::EscrowError::SlashNotEligible => {
            error!(ErrorCode::SlashNotEligible)
        }
        escrow_state::EscrowError::InvalidCpiAllowlist => {
            error!(ErrorCode::InvalidCpiAllowlist)
        }
        escrow_state::EscrowError::InvalidMultisigAuthority => {
            error!(ErrorCode::InvalidMultisigAuthority)
        }
        escrow_state::EscrowError::InvalidAppealWindow => {
            error!(ErrorCode::InvalidAppealWindow)
        }
        escrow_state::EscrowError::InvalidVestingCurve => {
            error!(ErrorCode::InvalidVestingCurve)
        }
        escrow_state::EscrowError::InvalidEvidenceProof => {
            error!(ErrorCode::InvalidEvidenceProof)
        }
        escrow_state::EscrowError::InvalidReleaseSplit => {
            error!(ErrorCode::InvalidReleaseSplit)
        }
        escrow_state::EscrowError::GapInEventStream => {
            error!(ErrorCode::GapInEventStream)
        }
        escrow_state::EscrowError::InvalidBasket => {
            error!(ErrorCode::InvalidBasket)
        }
        escrow_state::EscrowError::PayoutDenied => {
            error!(ErrorCode::PayoutDenied)
        }
        escrow_state::EscrowError::InvalidPayoutDenylist => {
            error!(ErrorCode::InvalidPayoutDenylist)
        }
        escrow_state::EscrowError::InvalidAuctionParams => {
            error!(ErrorCode::InvalidAuctionParams)
        }
        escrow_state::EscrowError::AuctionNotActive => {
            error!(ErrorCode::AuctionNotActive)
        }
        escrow_state::EscrowError::InvalidTransferHook => {
            error!(ErrorCode::InvalidTransferHook)
        }
        escrow_state::EscrowError::InvalidAppealBond => {
            error!(ErrorCode::InvalidAppealBond)
        }
        escrow_state::EscrowError::AppealExpiryNotDue => {
            error!(ErrorCode::AppealExpiryNotDue)
        }
        // AV-104: appended, never renumbered.
        escrow_state::EscrowError::InvalidDelegation => {
            error!(ErrorCode::InvalidDelegation)
        }
        // AV-105: appended, never renumbered.
        escrow_state::EscrowError::InvalidSwapParties => {
            error!(ErrorCode::InvalidSwapParties)
        }
        escrow_state::EscrowError::InvalidSwapAmounts => {
            error!(ErrorCode::InvalidSwapAmounts)
        }
        escrow_state::EscrowError::SwapLinkActive => {
            error!(ErrorCode::SwapLinkActive)
        }
        escrow_state::EscrowError::InvalidPoolPayout => {
            error!(ErrorCode::InvalidPoolPayout)
        }
        escrow_state::EscrowError::InvalidInterestRate => {
            error!(ErrorCode::InvalidInterestRate)
        }
        escrow_state::EscrowError::InterestNotEnabled => {
            error!(ErrorCode::InterestNotEnabled)
        }
        escrow_state::EscrowError::InvalidPayoutSplit => {
            error!(ErrorCode::InvalidPayoutSplit)
        }
        // AV-109: appended, never renumbered.
        escrow_state::EscrowError::InvalidDeadmanConfig => {
            error!(ErrorCode::InvalidDeadmanConfig)
        }
        escrow_state::EscrowError::DeadmanNotElapsed => {
            error!(ErrorCode::DeadmanNotElapsed)
        }
        // AV-110: appended, never renumbered.
        escrow_state::EscrowError::InvalidRentTopUp => {
            error!(ErrorCode::InvalidRentTopUp)
        }
        escrow_state::EscrowError::FundingIncomplete => {
            error!(ErrorCode::FundingIncomplete)
        }
        escrow_state::EscrowError::FundingTranchesExhausted => {
            error!(ErrorCode::FundingTranchesExhausted)
        }
        escrow_state::EscrowError::InvalidFundingPlan => {
            error!(ErrorCode::InvalidFundingPlan)
        }
        escrow_state::EscrowError::ReleaseCoolingNotElapsed => {
            error!(ErrorCode::ReleaseCoolingNotElapsed)
        }
        escrow_state::EscrowError::PriceGateNotSatisfied => {
            error!(ErrorCode::PriceGateNotSatisfied)
        }
        escrow_state::EscrowError::InvalidPriceGate => {
            error!(ErrorCode::InvalidPriceGate)
        }
        escrow_state::EscrowError::MergeIncompatible => {
            error!(ErrorCode::MergeIncompatible)
        }
        escrow_state::EscrowError::InvalidReleaseIntent => {
            error!(ErrorCode::InvalidReleaseIntent)
        }
        escrow_state::EscrowError::IntentNonceReused => {
            error!(ErrorCode::IntentNonceReused)
        }
        escrow_state::EscrowError::IntentExpired => {
            error!(ErrorCode::IntentExpired)
        }
        escrow_state::EscrowError::InvalidSlashLadder => {
            error!(ErrorCode::InvalidSlashLadder)
        }
        // AV-130: appended, never renumbered.
        escrow_state::EscrowError::InvalidDualControl => {
            error!(ErrorCode::InvalidDualControl)
        }
        escrow_state::EscrowError::DualControlIntentExists => {
            error!(ErrorCode::DualControlIntentExists)
        }
        escrow_state::EscrowError::DualControlNotInitiated => {
            error!(ErrorCode::DualControlNotInitiated)
        }
        escrow_state::EscrowError::DualControlExpired => {
            error!(ErrorCode::DualControlExpired)
        }
        escrow_state::EscrowError::DualControlRequired => {
            error!(ErrorCode::DualControlRequired)
        }
        // AV-131: appended, never renumbered.
        escrow_state::EscrowError::InvalidDisputeAmount => {
            error!(ErrorCode::InvalidDisputeAmount)
        }
        escrow_state::EscrowError::DisputedAmountLocked => {
            error!(ErrorCode::DisputedAmountLocked)
        }
        // AV-132: appended, never renumbered.
        escrow_state::EscrowError::SlippageExceeded => {
            error!(ErrorCode::SlippageExceeded)
        }
        // AV-134: appended, never renumbered.
        escrow_state::EscrowError::InvalidAmountBounds => {
            error!(ErrorCode::InvalidAmountBounds)
        }
        escrow_state::EscrowError::AmountOutOfBounds => {
            error!(ErrorCode::AmountOutOfBounds)
        }
        // AV-135: appended, never renumbered.
        escrow_state::EscrowError::InvalidArbiterFee => {
            error!(ErrorCode::InvalidArbiterFee)
        }
        // AV-137: appended, never renumbered.
        escrow_state::EscrowError::BlindInvalidCommitment => {
            error!(ErrorCode::BlindInvalidCommitment)
        }
        // AV-137: appended, never renumbered.
        escrow_state::EscrowError::BlindCommitMismatch => {
            error!(ErrorCode::BlindCommitMismatch)
        }
        // AV-137: appended, never renumbered.
        escrow_state::EscrowError::BlindDuplicateReveal => {
            error!(ErrorCode::BlindDuplicateReveal)
        }
        // AV-137: appended, never renumbered.
        escrow_state::EscrowError::BlindRevealWindowClosed => {
            error!(ErrorCode::BlindRevealWindowClosed)
        }
        // AV-137: appended, never renumbered.
        escrow_state::EscrowError::BlindCommitStale => {
            error!(ErrorCode::BlindCommitStale)
        }
        // AV-137: appended, never renumbered.
        escrow_state::EscrowError::BlindNoCommit => {
            error!(ErrorCode::BlindNoCommit)
        }
        // AV-137: appended, never renumbered.
        escrow_state::EscrowError::BlindVoteMustReveal => {
            error!(ErrorCode::BlindVoteMustReveal)
        }
    }
}

/// AV-123: the Ed25519 precompile program id
/// (`Ed25519Program1111111111111111111111111111111111`) — the
/// Solana-native signature verification program. `release_via_intent`
/// requires its instruction to be present in the transaction: the
/// runtime executes the signature check, and this introspection pins
/// the precompile's presence to the transaction the intent rides in
/// (the second, self-contained check is the state machine's own
/// `verify_release_intent`, which needs no precompile).
const ED25519_PROGRAM_ID: &str = "Ed25519Program1111111111111111111111111111111111";

/// AV-123: assert the Ed25519 precompile program executed in this
/// transaction — the on-chain double-insurance for the state
/// machine's own signature check in `Escrow::release_via_intent`.
/// Introspects the Instructions sysvar for an instruction whose
/// program id is the Ed25519 precompile program. `get_instruction_relative`
/// walks the sysvar backwards from the current instruction
/// (`release_via_intent` itself sits at index 0); any load failure
/// or a scan with no precompile instruction is
/// `Ed25519ProgramInstructionMissing`.
fn assert_ed25519_precompile_present(instructions: &AccountInfo) -> Result<()> {
    let ed25519_program: Pubkey = ED25519_PROGRAM_ID
        .parse()
        .map_err(|_| error!(ErrorCode::Ed25519ProgramInstructionMissing))?;
    let mut idx: i16 = -1;
    loop {
        match anchor_lang::solana_program::sysvar::instructions::get_instruction_relative(
            idx,
            instructions,
        ) {
            Ok(ix) => {
                if ix.program_id == ed25519_program {
                    return Ok(());
                }
                idx -= 1;
            }
            Err(_) => break,
        }
    }
    Err(error!(ErrorCode::Ed25519ProgramInstructionMissing))
}

#[error_code]
pub enum ErrorCode {
    #[msg("Caller is not the authority for this transition")]
    Unauthorized,
    #[msg("Transition not allowed from the current state")]
    InvalidStateTransition,
    #[msg("Escrow amount must be greater than zero")]
    AmountMismatch,
    #[msg("cancel_expired called before expires_at")]
    NotExpired,
    #[msg("Invalid quorum policy or no quorum configured")]
    InvalidQuorum,
    #[msg("Release quorum threshold not reached yet")]
    QuorumNotReached,
    #[msg("Cumulative release amount exceeds the locked amount")]
    ReleaseExceedsLocked,
    #[msg("Invalid vesting schedule (start >= end) or claim with no vesting configured")]
    InvalidVesting,
    #[msg("Invalid arbiter (zero key) or no arbiter configured for escalate/resolve")]
    InvalidArbiter,
    #[msg("Dispute window closed: escalate called at or after expires_at")]
    DisputeWindowClosed,
    #[msg("Invalid milestone plan (empty/too many/zero tranche, tranche sum != locked amount), milestone operation with no plan, or release/claim with a milestone plan attached")]
    InvalidMilestones,
    #[msg("release_milestone called before both parties confirmed the milestone")]
    MilestoneNotConfirmed,
    #[msg("Invalid SPL mint address (not base58 / not 32 bytes) or the zero address")]
    InvalidMint,
    #[msg("Token account mint does not match the escrow's bound mint")]
    MintMismatch,
    #[msg("Invalid protocol fee configuration: fee_bps must be 0-10000 (basis points); a tiered fee schedule needs 1-8 tiers with bps 0-10000 and strictly ascending floors; the flat rate and the tiered schedule are mutually exclusive")]
    InvalidProtocolFee,
    #[msg("Invalid grace period: expires_at + grace_period overflows u64 (no grace on a no-timeout escrow)")]
    InvalidGracePeriod,
    #[msg("Refund destination does not match the escrow's refund policy (whitelisted address, or the initializer with no whitelist)")]
    RefundAddressMismatch,
    #[msg("Invalid anti-griefing penalty rate: penalty_bps must be 0-10000 (basis points)")]
    InvalidPenalty,
    #[msg("Timelock not reached: release/claim/release_milestone called before unlock_at")]
    TimelockNotReached,
    #[msg("Invalid token decimals: with_decimals decimals must be 0-18")]
    InvalidDecimals,
    #[msg("Invalid CPI target: release_via_cpi with a zero program id, an empty account list, or a zero account key")]
    InvalidCpiTarget,
    #[msg("CPI execution failed: the third-party invoke failed after the release gates passed; the whole release was rolled back")]
    CpiExecutionFailed,
    #[msg("Reentrant call rejected: a fund-moving transition was entered while the AV-36 reentrancy lock was held (nested entry from inside release_via_cpi's executor window)")]
    ReentrantCall,
    #[msg("Invalid protocol-fee recipient: with_fee_recipient with the zero address (a zero address can never be the legitimate fee destination)")]
    InvalidFeeRecipient,
    #[msg("Emergency pause engaged: a state-changing transition was attempted while the AV-46 pause flag is set; only the pause authority's unpause re-enables transitions")]
    Paused,
    #[msg("Invalid pause authority: with_pause_authority with the zero address (a zero address can never hold the emergency switch)")]
    InvalidPauseAuthority,
    #[msg("Invalid payout allowlist: with_payout_allowlist with an empty list, more than 4 addresses, or a zero address (the AV-49 allowlist must be 1-4 live payout destinations)")]
    InvalidPayoutAllowlist,
    #[msg("Payout destination not allowlisted: a payout transition named a payout_to that is neither the taker nor a member of the AV-49 payout destination allowlist")]
    PayoutNotAllowlisted,
    #[msg("Default judgment not due (AV-55): trigger_default_judgment with no default judgment configured, the taker never confirmed the split, or the arbitration deadline not yet passed; with_arbitration_deadline with a zero deadline")]
    DefaultJudgmentNotDue,
    #[msg("Invalid subscription schedule (AV-56): with_subscription with a zero period_secs, zero or over-long periods, a zero per_period, per-period amounts that do not sum to the locked amount, a u64::MAX expiry (back-scheduling needs a bounded lifetime), a schedule that does not fit inside the escrow's lifetime, or on a non-Uninitialized escrow; with_milestones after a subscription (mutually exclusive release schedules); any subscription operation with no schedule attached; or plain release on an escrow with a subscription (the schedule owns the release path)")]
    InvalidSubscription,
    #[msg("Subscription period not due (AV-56): release_period with a period_index that is not the next due period (skipping ahead or replaying a released period), or with now before that period's back-scheduled due timestamp; periods release strictly in order, one at a time, each only once due")]
    PeriodNotDue,
    #[msg("Invalid taker address (AV-52): rotate_taker with the zero address (a zero address can never be the legitimate payout counterparty)")]
    InvalidTaker,
    #[msg("Invalid event-history capacity (AV-57): with_event_capacity with capacity == 0 or capacity > 64")]
    InvalidEventCapacity,
    #[msg("Invalid initializer address (AV-58): rotate_initializer with the zero address (a zero address can never be the legitimate initializer)")]
    InvalidInitializer,
    #[msg("Invalid expiry extension (AV-59): extend_expiry with no extension bound configured, by a non-initializer, on a non-Uninitialized/Funded escrow, with a deadline that does not move forward, with a single increment above the bound, or on an already-expiry-eligible escrow; with_max_extension_secs with a zero bound")]
    InvalidExpiryExtension,
    #[msg("Invalid timelock (AV-64): with_timelock with a nonzero unlock_at while a nonzero relative timelock is configured, or with_relative_timelock with a nonzero secs while a nonzero absolute timelock is configured — one clock per escrow")]
    InvalidTimelock,
    #[msg("Invalid arbiter panel (AV-65): with_arbiter_panel with an empty member list, more than 8 members, a zero threshold, a threshold above the member count, a zero member key, or a duplicate member; or submit_panel_judgment with no panel configured")]
    InvalidArbiterPanel,
    #[msg("Single-arbiter settlement disabled (AV-65): resolve called on a panel-mode escrow — the panel's multisig judgment (submit_panel_judgment) is the only settlement path; the AV-55 default-judgment fallback is retained")]
    PanelResolveDisabled,
    #[msg("Invalid evidence-disclosure deadline (AV-68): with_evidence_deadline with a zero deadline — a zero-second deadline would lapse the moment the dispute starts")]
    InvalidEvidenceDeadline,
    #[msg("Evidence disclosure arrived too late (AV-68): submit_evidence at or past the disclosure deadline without evidence on record — a missed deadline locks in the judgment-time adverse inference")]
    EvidenceDisclosureLate,
    #[msg("Invalid schema migration (AV-75): migrate_schema by a non-initializer, on a vault already at the current schema version, on a vault at an unknown future version (no version skipping), or on a vault whose carried-over fields violate the conservation invariants")]
    InvalidSchemaMigration,
    #[msg("Rejected template override (AV-77): apply_template was given an override the preset did not declare overridable — an unknown field name, a field outside the preset's declared surface, a mistyped value, or a repeated field; the preset's audited shape is never silently widened")]
    TemplateOverrideRejected,
    #[msg("Slash not eligible (AV-82): slash with no slash terms configured, before the slash deadline, on an already-slashed escrow (one-shot), with an amount above the slashable remainder, on a dual-sig escrow lacking both activation bits, on a Disputed escrow (locked while arbitration owns the funds), or on a milestone/subscription-scheduled escrow; with_slash_terms with the zero penalty account")]
    SlashNotEligible,
    #[msg("Invalid CPI target-program allowlist (AV-83): with_cpi_allowlist / update_cpi_allowlist with more than 8 program ids or a zero address; update_cpi_allowlist by a non-dual signature, on a paused escrow, on a Released/Cancelled/Expired vault, or with no allowlist configured")]
    InvalidCpiAllowlist,
    #[msg("Invalid slash-appeal window (AV-86): with_appeal_window with a zero window — a zero-second window would give the taker no chance to appeal; file_appeal with no slash executed, no window configured, an already-filed or already-resolved appeal, or a lapsed window")]
    InvalidAppealWindow,
    #[msg("Invalid vesting unlock curve (AV-90): VestingCurve::stepped with an empty/oversized tier table, a tier outside [start, end], non-monotone timestamps or unlock fractions, bps above 10_000, or a final tier below full unlock; VestingCurve::exponential with zero/too many steps, a non-positive or overflowing growth ratio, or a window shorter than the step count; with_vesting_curve with a curve whose tier window does not match the schedule")]
    InvalidVestingCurve,
    #[msg("Invalid dispute-evidence Merkle commitment or proof (AV-91): escalate with a leaf count that does not describe the root (None root with nonzero leaves, Some root with zero or more than 64 leaves); file_evidence with no committed root, a leaf index past the committed leaves, a proof whose length does not match the tree shape, or a proof that does not verify against the committed root")]
    InvalidEvidenceProof,
    #[msg("Invalid release split (AV-93): release_split with an empty share table, more than 8 recipients, a zero recipient address, a zero bps weight, or a weight table whose sum differs from 10_000 bps; a per-recipient payout-policy violation is PayoutNotAllowlisted, not this code")]
    InvalidReleaseSplit,
    #[msg("Broken event-stream continuity (AV-94): MaterializedView::apply hit a missing seq (gap), an out-of-order or duplicate seq, or events for a different escrow_id than the view folds")]
    GapInEventStream,
    #[msg("Invalid multi-mint basket (AV-95): BasketLegs::new with an empty leg table, more than 8 legs, a zero mint, a zero leg amount, a duplicate mint, or a leg-amount sum overflowing u64; or release_basket / cancel_basket / cancel_expired_basket on an escrow with no basket configured, or with a mint outside the basket's leg table")]
    InvalidBasket,
    #[msg("Payout destination is denylisted (AV-96): the payout recipient is on the escrow's payout denylist — deny takes precedence over the AV-49 allowlist, so a destination on both lists is rejected with this code, not PayoutNotAllowlisted")]
    PayoutDenied,
    #[msg("Invalid payout denylist (AV-96): PayoutDenylist::new with an empty list, more than 4 addresses, or a zero address")]
    InvalidPayoutDenylist,
    #[msg("Invalid Dutch-auction terms (AV-97): with_dutch_auction with start_at >= end_at (a zero-length window would divide by zero in the descending-price math) or reserve_bps > 10_000 (not a valid basis-point floor)")]
    InvalidAuctionParams,
    #[msg("Dutch auction not active (AV-97): claim on an auction-mode escrow outside the [start_at, end_at] window, or escalate while the auction window is live (price discovery and arbitration are mutually exclusive settlement paths)")]
    AuctionNotActive,
    #[msg("Invalid Token-2022 transfer-hook declaration (AV-99): with_transfer_hook with the zero program id, on a non-Uninitialized escrow, or before with_mint bound a mint (a transfer hook is a Token-2022 concept, meaningless on the native-SOL path)")]
    InvalidTransferHook,
    #[msg("Invalid appeal-bond configuration (AV-103): with_appeal_bond with a zero bond (a zero bond is a no-op; the no-bond default already covers free filing)")]
    InvalidAppealBond,
    #[msg("The appeal window has not lapsed yet (AV-103): expire_appeal with now <= appeal_deadline — the sweep only runs once the window is actually over")]
    AppealExpiryNotDue,
    #[msg("Invalid authority-delegation request (AV-104): delegate_authority with a non-party grantor, a zero operator key, an empty scope bitmap, scope bits outside the mask, or on a non-Uninitialized/non-Funded escrow; or revoke_delegation with no grant to revoke")]
    InvalidDelegation,
    #[msg("Invalid atomic-swap pairing (AV-105): link_swap with a zero or duplicate counterparty escrow id or non-mirrored parties; or a pair settlement whose cross-link does not match the claimed pair")]
    InvalidSwapParties,
    #[msg("Invalid atomic-swap amounts (AV-105): link_swap with a leg amount disagreeing with the escrow's locked amount")]
    InvalidSwapAmounts,
    #[msg("Live swap link blocks a single-side move (AV-105): fund-moving single-side transition on a live-linked non-terminal escrow; link_swap on an already-linked escrow; or a pair op on an unlinked escrow")]
    SwapLinkActive,
    #[msg("Invalid insurance-pool payout (AV-106): pool_payout with no pool opted in, by a non-arbiter/non-multisig caller, a zero or over-balance amount, a denied/non-allowlisted beneficiary, on a non-Funded escrow, or while the pool is encumbered by a live appeal; or close_vault with a non-empty pool")]
    InvalidPoolPayout,
    #[msg("Invalid interest-rate configuration (AV-107): with_interest with rate_bps above 10000 — above 100% APR")]
    InvalidInterestRate,
    #[msg("Interest not enabled (AV-107): claim_interest on an escrow with no interest rate configured (interest_rate_bps == 0)")]
    InterestNotEnabled,
    #[msg("Invalid payout-split table (AV-108): with_payout_split with an empty table, a zero recipient, a duplicate recipient, a zero share, more than 8 shares, or a share total != amount; or release/release_via_cpi on a split-configured escrow")]
    InvalidPayoutSplit,
    #[msg("Invalid dead-man's switch configuration (AV-109): with_deadman_switch with inactivity_secs == 0 or a zero heir address; or claim_deadman on an escrow whose dead-man's switch was never configured")]
    InvalidDeadmanConfig,
    #[msg("Dead-man's switch inactivity window not elapsed (AV-109): claim_deadman before now - deadman_last_activity reaches deadman_inactivity_secs")]
    DeadmanNotElapsed,
    #[msg("Invalid rent top-up (AV-110): top_up_rent with lamports == 0, or the cumulative rent_topped_up_total counter overflowing u64")]
    InvalidRentTopUp,
    #[msg("Funding incomplete (AV-111): release/claim/release_milestone on a tranched-funding escrow before funded_total reaches the plan's total_amount")]
    FundingIncomplete,
    #[msg("Funding tranches exhausted (AV-111): fund_tranche when the plan's tranche budget is spent")]
    FundingTranchesExhausted,
    #[msg("Invalid funding plan (AV-111): with_funding_plan with max_tranches == 0; fund_tranche with no plan attached; fund on a plan escrow")]
    InvalidFundingPlan,
    #[msg("Release cooling window not elapsed (AV-112): release on a cooling-configured escrow with no live announced intent, or whose intent was announced less than release_cooling_secs ago")]
    ReleaseCoolingNotElapsed,
    #[msg("Oracle price gate not satisfied (AV-113): gated release/claim with no oracle quote, a stale quote, or a price on the wrong side of the target")]
    PriceGateNotSatisfied,
    #[msg("Invalid price gate (AV-113): with_price_gate with target == 0, or an out-of-range direction byte")]
    InvalidPriceGate,
    #[msg("Escrows incompatible for merge (AV-114): different parties, mismatched settlement terms, or an amount counter that would overflow")]
    MergeIncompatible,
    #[msg("Invalid gasless-release intent (AV-123): release_via_intent with a signature that does not verify against the initializer key over the intent's canonical bytes, or a malformed signature")]
    InvalidReleaseIntent,
    #[msg("Gasless-release intent nonce reused (AV-123): release_via_intent with intent.nonce <= last_intent_nonce — a replayed intent")]
    IntentNonceReused,
    #[msg("Gasless-release intent expired (AV-123): release_via_intent with now_slot >= intent.expiry_slot")]
    IntentExpired,
    #[msg("Ed25519 precompile program instruction missing (AV-123): release_via_intent requires the Ed25519 precompile program to have executed in this transaction — the on-chain double-insurance for the state machine's own signature check")]
    Ed25519ProgramInstructionMissing,
    #[msg("Invalid slash ladder (AV-126): with_slash_ladder with an empty or over-long rung table, a zero bps rung, bps above 10_000, non-strictly-ascending deadlines or bps, a zero penalty account, or on an escrow that already carries single-level slash terms (mutually exclusive)")]
    InvalidSlashLadder,
    #[msg("Invalid dual-control configuration or operation (AV-130): with_dual_control with the zero checker key; initiate_release with amount == 0, intent_ttl_secs == 0 or an overflowing intent expiry; or any dual-control transition on an escrow that never opted in via with_dual_control")]
    InvalidDualControl,
    #[msg("Dual-control intent already live (AV-130): initiate_release while a dual-control declaration is already pending — confirm or cancel it first")]
    DualControlIntentExists,
    #[msg("No dual-control intent live (AV-130): confirm_release / cancel_release with nothing to confirm or cancel")]
    DualControlNotInitiated,
    #[msg("Dual-control intent expired (AV-130): confirm_release with now >= the live declaration's intent_expires_at — the stale declaration is cleared and the release is refused")]
    DualControlExpired,
    #[msg("Dual-control release required (AV-130): direct release (or a path routed through it) on a dual-control escrow — payouts leave only via the two-step initiate_release + confirm_release protocol")]
    DualControlRequired,
    #[msg("Invalid dispute amount (AV-131): escalate with dispute_amount = 0 or above remaining_amount")]
    InvalidDisputeAmount,
    #[msg("Disputed amount locked (AV-131): release names an amount that reaches into the contested pool — release only the undisputed remainder or wait for resolve")]
    DisputedAmountLocked,
    #[msg("Slippage exceeded (AV-132): release_via_cpi post-execution taker-leg amount below the min_payout floor — the whole release rolled back")]
    SlippageExceeded,
    #[msg("Invalid amount bounds (AV-134): initialize_amount_bounds with min_amount > max_amount — an inverted funding window")]
    InvalidAmountBounds,
    #[msg("Amount out of bounds (AV-134): fund / fund_tranche deposit below min_funding_amount or above max_funding_amount")]
    AmountOutOfBounds,
    #[msg("Invalid arbiter fee (AV-135): initialize_arbiter_fee with fee_bps > 10_000 — a basis-point rate above 100%")]
    InvalidArbiterFee,
    #[msg("Blind invalid commitment (AV-137): submit_judgment_commit with a zero commitment — no preimage can ever reveal against it")]
    BlindInvalidCommitment,
    #[msg("Blind commitment mismatch (AV-137): reveal_judgment whose recomputed SHA-256(taker_amount || rationale_hash || salt) does not match the stored commitment")]
    BlindCommitMismatch,
    #[msg("Blind duplicate reveal (AV-137): reveal_judgment for a commit that was already revealed — each commit reveals exactly once")]
    BlindDuplicateReveal,
    #[msg("Blind reveal window closed (AV-137): reveal_judgment after committed_at + reveal_window_secs lapsed")]
    BlindRevealWindowClosed,
    #[msg("Blind commit stale (AV-137): reveal_judgment whose commit no longer matches the escrow's dispute snapshot — auto-invalidated")]
    BlindCommitStale,
    #[msg("Blind no commit (AV-137): reveal_judgment with no active commitment from this member")]
    BlindNoCommit,
    #[msg("Blind vote must reveal (AV-137): submit_panel_judgment on a blind-mode panel — direct votes are disabled, vote via commit + reveal")]
    BlindVoteMustReveal,
}
