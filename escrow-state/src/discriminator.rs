//! AV-32: Anchor account discriminators + panic-free vault account decoding.
//!
//! Two halves of the same defensive story — reading on-chain bytes without
//! trusting them:
//!
//! 1. **Discriminator registry.** Every program-side `#[account]` type has
//!    an 8-byte Anchor discriminator, `sha256("account:<Name>")[..8]`.
//!    [`PROGRAM_ACCOUNT_NAMES`] is the single source of truth for which
//!    account types the program side declares; the tests assert it covers
//!    every `#[account]` in `programs/escrow-vault/src/program.rs` (via
//!    `include_str!`, so adding an account type without updating the table
//!    fails the build) and that no account discriminator collides with any
//!    other account's or any instruction's (`sha256("global:<name>")[..8]`)
//!    — a collision would let one account's bytes masquerade as another's.
//! 2. **Panic-free decoding.** [`decode_vault_account`] turns raw account
//!    data (discriminator + [`VAULT_FIELDS`](crate::VAULT_FIELDS) Borsh
//!    body) back into an [`Escrow`](crate::Escrow). It never panics: every
//!    read is bounds-checked, so fuzzed / mutated / truncated / overlong
//!    byte streams can only produce `Ok` or `Err`, never a trap. This is
//!    the off-chain mirror of what the program must guarantee on-chain —
//!    an account-data parser that panics on adversarial input is a
//!    denial-of-service vector.
//!
//! Check order inside [`decode_vault_account`]: exact length first
//! ([`VAULT_SPACE`](crate::VAULT_SPACE), truncated and overlong both
//! rejected — matching Anchor's `try_from_slice`, which rejects trailing
//! bytes), then the discriminator, then the structural field decode.
//!
//! The decode is *structural*, mirroring Anchor's `try_deserialize`: it
//! validates discriminants and layout, not domain invariants. A decoded
//! escrow with `released > amount` or a vesting schedule with
//! `start >= end` decodes fine — those combinations can never be *written*
//! by the program (the transitions reject them), but the decoder reports
//! what's on chain rather than re-litigating it. Callers that need
//! invariants re-checked can run the state machine's own predicates over
//! the result.

use super::{
    sha256, AppealBallot, AppealState, ArbiterPanel, BasketLeg, BasketLegs, CpiAllowlist,
    DefaultJudgment, DutchAuction, Escrow, EscrowEventKind, EscrowState, EventHistorySlot, FeeSchedule, FeeTier,
    Delegation, MilestonePlan, MultisigAuthority, PanelVote, PayoutAllowlist, PayoutDenylist, QuorumPolicy,
    SlashTerms, SubscriptionSchedule, VestingCurve, VestingSchedule, ANCHOR_DISCRIMINATOR_LEN,
    APPEAL_BALLOT_LEN, ARBITER_PANEL_LEN, BASKET_LEGS_LEN, CPI_ALLOWLIST_LEN, DEFAULT_JUDGMENT_LEN,
    DELEGATION_LEN, DUTCH_AUCTION_LEN, ESCROW_BODY_LEN, FEE_SCHEDULE_LEN, FEE_TIER_LEN, MAX_ATTESTORS, MAX_BASKET_LEGS,
    MAX_CPI_ALLOWLIST, MAX_EVENT_HISTORY, MAX_FEE_TIERS, MAX_MILESTONES, MAX_PANEL_MEMBERS,
    MAX_PAYOUT_ALLOWLIST, MAX_PAYOUT_DENYLIST, MAX_SUBSCRIPTION_PERIODS, MAX_VESTING_CURVE_TIERS,
    MILESTONE_PLAN_LEN, MULTISIG_AUTHORITY_LEN, PANEL_VOTE_LEN, PAYOUT_ALLOWLIST_LEN,
    PAYOUT_DENYLIST_LEN, PUBKEY_LEN, QUORUM_POLICY_LEN, SLASH_TERMS_LEN, SUBSCRIPTION_SCHEDULE_LEN,
    VAULT_SPACE, VESTING_CURVE_LEN,
};

/// Program-side `#[account]` type names, in Anchor IDL order. The single
/// source of truth for the discriminator registry: the tests pin it
/// against `programs/escrow-vault/src/program.rs`, so a new account type
/// on the program side fails the build until it is registered here.
pub const PROGRAM_ACCOUNT_NAMES: &[&str] = &["Vault"];

/// Anchor account discriminator: `sha256("account:<name>")[..8]`.
/// The `account:` namespace is disjoint from the instruction `global:`
/// namespace by construction; the tests additionally assert no
/// accidental 8-byte collision between the two tables.
pub fn account_discriminator(account_name: &str) -> [u8; 8] {
    let digest = sha256(format!("account:{account_name}").as_bytes());
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&digest[..8]);
    disc
}

/// The discriminator every `Vault` account carries in its first 8 bytes.
pub fn vault_account_discriminator() -> [u8; 8] {
    account_discriminator("Vault")
}

/// Anchor instruction discriminator: `sha256("global:<name>")[..8]`.
/// `pub(crate)` so the execution-plan builder (AV-33) stamps real
/// instruction discriminators on the planned instructions; the IDL
/// pipeline (AV-29, test-only) reuses the same constructor.
pub(crate) fn instruction_discriminator(name: &str) -> [u8; 8] {
    let digest = sha256(format!("global:{name}").as_bytes());
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&digest[..8]);
    disc
}

/// Why [`decode_vault_account`] rejected the account data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountDecodeError {
    /// Fewer than [`VAULT_SPACE`](crate::VAULT_SPACE) bytes: the account
    /// data is truncated (possibly an uninitialized or foreign account).
    Truncated { expected: usize, got: usize },
    /// More than [`VAULT_SPACE`](crate::VAULT_SPACE) bytes: trailing
    /// bytes are rejected rather than silently ignored, matching Anchor's
    /// `try_from_slice` semantics.
    Overlong { expected: usize, got: usize },
    /// The leading 8 bytes are not the `Vault` account discriminator —
    /// the bytes belong to a different account type (or are garbage).
    BadDiscriminator { expected: [u8; 8], got: [u8; 8] },
    /// The `state` byte is not a known [`EscrowState`] discriminant
    /// (0–6). The mapping is pinned by test to declaration order.
    InvalidStateDiscriminant(u8),
    /// An `Option` discriminant byte is neither 0 nor 1. `field` names
    /// the [`VAULT_FIELDS`](crate::VAULT_FIELDS) field being decoded.
    InvalidOptionDiscriminant { field: &'static str, value: u8 },
    /// A present payout allowlist's entry count is outside `1..=4`
    /// ([`MAX_PAYOUT_ALLOWLIST`](crate::MAX_PAYOUT_ALLOWLIST)). The
    /// count byte is part of the field's layout — an out-of-range count
    /// would make [`PayoutAllowlist::as_slice`] panic, so the decoder
    /// rejects it rather than decoding a value the accessors cannot
    /// safely read (AV-49; AV-32 panic-free guarantee).
    InvalidPayoutAllowlistLen(u8),
    /// A present CPI target allowlist's entry count is outside `1..=8`
    /// ([`MAX_CPI_ALLOWLIST`](crate::MAX_CPI_ALLOWLIST)). The count
    /// byte is part of the field's layout — an out-of-range count
    /// would make [`CpiAllowlist::as_slice`](crate::CpiAllowlist::as_slice)
    /// panic, so the decoder rejects it rather than decoding a value
    /// the accessors cannot safely read (AV-83; AV-32 panic-free
    /// guarantee).
    InvalidCpiAllowlistLen(u8),
    /// A present multi-mint basket's leg count is outside `1..=8`
    /// ([`MAX_BASKET_LEGS`](crate::MAX_BASKET_LEGS)). The count byte
    /// is part of the field's layout — an out-of-range count would
    /// make [`BasketLegs::as_slice`](crate::BasketLegs::as_slice)
    /// read past the live slots, so the decoder rejects it rather
    /// than decoding a value the accessors cannot safely read
    /// (AV-95; AV-32 panic-free guarantee).
    InvalidBasketLegsLen(u8),
    /// A present payout denylist's entry count is outside `1..=4`
    /// ([`MAX_PAYOUT_DENYLIST`](crate::MAX_PAYOUT_DENYLIST)). The
    /// count byte is part of the field's layout — an out-of-range
    /// count would make
    /// [`PayoutDenylist::as_slice`](crate::PayoutDenylist::as_slice)
    /// read past the live slots, so the decoder rejects it rather
    /// than decoding a value the accessors cannot safely read
    /// (AV-96; AV-32 panic-free guarantee).
    InvalidPayoutDenylistLen(u8),
    /// An event-history slot's kind byte is not a known
    /// [`EscrowEventKind`] discriminant (0–52). The mapping is pinned
    /// by test to declaration order (AV-57).
    InvalidEventKindDiscriminant(u8),
    /// A present arbiter panel's member count is outside `1..=8`
    /// ([`MAX_PANEL_MEMBERS`](crate::MAX_PANEL_MEMBERS)) or its
    /// threshold is outside `1..=n`. The count bytes are part of the
    /// field's layout — an out-of-range count would make the panel
    /// accessors read past the live slots, so the decoder rejects it
    /// rather than decoding a value the accessors cannot safely read
    /// (AV-65; AV-32 panic-free guarantee).
    InvalidArbiterPanelLen { n: u8, threshold: u8 },
    /// A tiered protocol-fee schedule's live-tier count is outside
    /// `0..=8` ([`MAX_FEE_TIERS`](crate::MAX_FEE_TIERS)), a live tier's
    /// rate is above 10_000 basis points, or the tier floors are not
    /// strictly ascending. The count and tier bytes are part of the
    /// field's layout — an out-of-range count would make
    /// [`FeeSchedule::bps_for`](crate::FeeSchedule::bps_for) read past
    /// the live slots, so the decoder rejects it rather than decoding
    /// a value the accessors cannot safely read (AV-66; AV-32
    /// panic-free guarantee).
    InvalidFeeSchedule { tier_count: u8, tier: u8 },
    /// The appeal lifecycle byte is not a known
    /// [`AppealState`](crate::AppealState) discriminant (0–4). The
    /// mapping is pinned to declaration order (AV-86; AV-103 added
    /// `Expired`; AV-32 panic-free guarantee).
    InvalidAppealStateDiscriminant(u8),
    /// A present Dutch auction's terms violate the
    /// [`DutchAuction`](crate::DutchAuction) invariants
    /// (`start_at >= end_at`, or `reserve_bps > 10_000`). The terms
    /// are part of the field's layout — a degenerate window would
    /// make [`DutchAuction::payout_cap`](crate::DutchAuction::payout_cap)
    /// divide by zero, so the decoder rejects it rather than decoding
    /// a value the accessors cannot safely read (AV-97; AV-32
    /// panic-free guarantee).
    InvalidDutchAuctionTerms {
        start_at: u64,
        end_at: u64,
        reserve_bps: u16,
    },
}

/// Bounds-checked cursor over the account body. Every read is
/// `checked_add` + `get`, so no input — however adversarial — can trap;
/// the exact-length precheck in [`decode_vault_account`] makes overruns
/// unreachable in practice, and the checked reads keep them impossible
/// in principle.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn fail(&self) -> AccountDecodeError {
        // Unreachable after the exact-length precheck; reported as
        // truncation (the data ran out mid-field) rather than a trap.
        AccountDecodeError::Truncated {
            expected: VAULT_SPACE,
            got: self.data.len() + ANCHOR_DISCRIMINATOR_LEN,
        }
    }

    fn read(&mut self, n: usize) -> Result<&'a [u8], AccountDecodeError> {
        match self
            .pos
            .checked_add(n)
            .and_then(|end| self.data.get(self.pos..end))
        {
            Some(bytes) => {
                self.pos += n;
                Ok(bytes)
            }
            None => Err(self.fail()),
        }
    }

    fn skip(&mut self, n: usize) -> Result<(), AccountDecodeError> {
        self.read(n).map(|_| ())
    }

    fn u8(&mut self) -> Result<u8, AccountDecodeError> {
        Ok(self.read(1)?[0])
    }

    fn u16_le(&mut self) -> Result<u16, AccountDecodeError> {
        let b = self.read(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32_le(&mut self) -> Result<u32, AccountDecodeError> {
        let b = self.read(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64_le(&mut self) -> Result<u64, AccountDecodeError> {
        let b = self.read(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(u64::from_le_bytes(arr))
    }

    fn pubkey(&mut self) -> Result<[u8; 32], AccountDecodeError> {
        let b = self.read(PUBKEY_LEN)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(b);
        Ok(arr)
    }

    /// Borsh `Option` discriminant: 0 → absent (the reserved region is
    /// skipped by the caller), 1 → present, anything else is malformed.
    fn option_present(&mut self, field: &'static str) -> Result<bool, AccountDecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(AccountDecodeError::InvalidOptionDiscriminant {
                field,
                value: other,
            }),
        }
    }
}

/// Map a `state` byte to [`EscrowState`]. Declaration order is the
/// discriminant order (Borsh unit-enum); the test below pins every arm
/// so a reordered enum fails loudly instead of silently mis-decoding.
fn state_from_discriminant(d: u8) -> Result<EscrowState, AccountDecodeError> {
    match d {
        0 => Ok(EscrowState::Uninitialized),
        1 => Ok(EscrowState::Funded),
        2 => Ok(EscrowState::Released),
        3 => Ok(EscrowState::Cancelled),
        4 => Ok(EscrowState::Activated),
        5 => Ok(EscrowState::Disputed),
        6 => Ok(EscrowState::Settled),
        7 => Ok(EscrowState::Closed),
        // AV-81: appended after Closed — discriminants 0–7 stay stable.
        8 => Ok(EscrowState::Split),
        other => Err(AccountDecodeError::InvalidStateDiscriminant(other)),
    }
}

/// Decode raw `Vault` account data (8-byte discriminator +
/// [`ESCROW_BODY_LEN`](crate::ESCROW_BODY_LEN)-byte Borsh body, exactly
/// [`VAULT_SPACE`](crate::VAULT_SPACE) bytes) into an
/// [`Escrow`](crate::Escrow).
///
/// Never panics: truncated, overlong, wrong-discriminator, and
/// structurally malformed inputs all surface as [`AccountDecodeError`].
/// See the module docs for the check order and the structural-decode
/// contract.
pub fn decode_vault_account(data: &[u8]) -> Result<Escrow, AccountDecodeError> {
    if data.len() < VAULT_SPACE {
        return Err(AccountDecodeError::Truncated {
            expected: VAULT_SPACE,
            got: data.len(),
        });
    }
    if data.len() > VAULT_SPACE {
        return Err(AccountDecodeError::Overlong {
            expected: VAULT_SPACE,
            got: data.len(),
        });
    }
    let mut got_disc = [0u8; ANCHOR_DISCRIMINATOR_LEN];
    got_disc.copy_from_slice(&data[..ANCHOR_DISCRIMINATOR_LEN]);
    let expected_disc = vault_account_discriminator();
    if got_disc != expected_disc {
        return Err(AccountDecodeError::BadDiscriminator {
            expected: expected_disc,
            got: got_disc,
        });
    }

    let mut c = Cursor::new(&data[ANCHOR_DISCRIMINATOR_LEN..]);
    let initializer = c.pubkey()?;
    let taker = c.pubkey()?;
    let amount = c.u64_le()?;
    let released = c.u64_le()?;
    let expires_at = c.u64_le()?;
    let state = state_from_discriminant(c.u8()?)?;

    let quorum = if c.option_present("quorum")? {
        let mut attestors = [[0u8; 32]; MAX_ATTESTORS];
        for a in attestors.iter_mut() {
            *a = c.pubkey()?;
        }
        let mut weights = [0u64; MAX_ATTESTORS];
        for w in weights.iter_mut() {
            *w = c.u64_le()?;
        }
        let registered = c.u8()?;
        let threshold = c.u64_le()?;
        let approvals = c.u64_le()?;
        debug_assert_eq!(
            8 * PUBKEY_LEN + 8 * 8 + 1 + 8 + 8,
            QUORUM_POLICY_LEN,
            "quorum region drift vs QUORUM_POLICY_LEN"
        );
        Some(QuorumPolicy {
            attestors,
            weights,
            registered,
            threshold,
            approvals,
        })
    } else {
        c.skip(QUORUM_POLICY_LEN)?;
        None
    };

    let activation = c.u8()?;

    let vesting = if c.option_present("vesting")? {
        let start = c.u64_le()?;
        let end = c.u64_le()?;
        // AV-51: the cliff timestamp trails end (24-byte region).
        let cliff_at = c.u64_le()?;
        Some(VestingSchedule { start, end, cliff_at })
    } else {
        c.skip(24)?;
        None
    };

    let arbiter = if c.option_present("arbiter")? {
        Some(c.pubkey()?)
    } else {
        c.skip(PUBKEY_LEN)?;
        None
    };

    let milestones = if c.option_present("milestones")? {
        let mut amounts = [0u64; MAX_MILESTONES];
        for a in amounts.iter_mut() {
            *a = c.u64_le()?;
        }
        let count = c.u8()?;
        debug_assert_eq!(
            MAX_MILESTONES * 8 + 1,
            MILESTONE_PLAN_LEN,
            "milestone region drift vs MILESTONE_PLAN_LEN"
        );
        Some(MilestonePlan { amounts, count })
    } else {
        c.skip(MILESTONE_PLAN_LEN)?;
        None
    };
    let milestone_flags = c.u64_le()?;
    let skipped = c.u64_le()?;

    let mint = if c.option_present("mint")? {
        Some(c.pubkey()?)
    } else {
        c.skip(PUBKEY_LEN)?;
        None
    };
    let fee_bps = c.u16_le()?;
    let fees_paid = c.u64_le()?;
    let grace_period = c.u64_le()?;

    let evidence_hash = if c.option_present("evidence_hash")? {
        Some(c.pubkey()?)
    } else {
        c.skip(32)?;
        None
    };

    let refund_to = if c.option_present("refund_to")? {
        Some(c.pubkey()?)
    } else {
        c.skip(PUBKEY_LEN)?;
        None
    };
    let penalty_bps = c.u16_le()?;
    let timelock = c.u64_le()?;
    let decimals = c.u8()?;
    // AV-38: arbiter's rationale-document hash, always reserved like
    // `evidence_hash`: the `None` discriminant followed by a zeroed
    // 32-byte commitment, appended last so every earlier offset above
    // is unchanged.
    let rationale_hash = if c.option_present("rationale_hash")? {
        Some(c.pubkey()?)
    } else {
        c.skip(32)?;
        None
    };
    // AV-41: emergency timelock-unlock governance opt-in, always
    // present (zeroed when the feature is off); appended last so every
    // earlier offset above is unchanged.
    let emergency_unlock = c.u8()? != 0;
    // AV-44: protocol-fee recipient pin, always reserved like
    // `refund_to`: the `None` discriminant followed by a zeroed 32-byte
    // address, appended last so every earlier offset above is unchanged.
    let fee_recipient = if c.option_present("fee_recipient")? {
        Some(c.pubkey()?)
    } else {
        c.skip(32)?;
        None
    };
    // AV-46: emergency-pause authority, always reserved like
    // `fee_recipient`: the `None` discriminant followed by a zeroed
    // 32-byte address, appended last so every earlier offset above is
    // unchanged.
    let pause_authority = if c.option_present("pause_authority")? {
        Some(c.pubkey()?)
    } else {
        c.skip(32)?;
        None
    };
    // AV-46: emergency pause flag, always present (zeroed when the
    // escrow is not paused); appended last so every earlier offset
    // above is unchanged.
    let paused = c.u8()? != 0;
    // AV-49: payout destination allowlist, always reserved like
    // `refund_to`: the `None` discriminant followed by a zeroed
    // 4-address region and count byte, appended last so every earlier
    // offset above is unchanged. The count is validated `1..=4` — an
    // out-of-range count would make `PayoutAllowlist::as_slice` panic,
    // so the panic-free decoder rejects it (see
    // `InvalidPayoutAllowlistLen`).
    let payout_allowlist = if c.option_present("payout_allowlist")? {
        let mut addrs = [[0u8; 32]; MAX_PAYOUT_ALLOWLIST];
        for a in addrs.iter_mut() {
            *a = c.pubkey()?;
        }
        let len = c.u8()?;
        if len == 0 || len as usize > MAX_PAYOUT_ALLOWLIST {
            return Err(AccountDecodeError::InvalidPayoutAllowlistLen(len));
        }
        debug_assert_eq!(
            PAYOUT_ALLOWLIST_LEN,
            4 * 32 + 1,
            "allowlist region drift vs PAYOUT_ALLOWLIST_LEN"
        );
        Some(PayoutAllowlist { addrs, len })
    } else {
        c.skip(PAYOUT_ALLOWLIST_LEN)?;
        None
    };
    // AV-53: opt-in off-chain reference memo, always reserved like
    // `refund_to`: the `None` discriminant followed by a zeroed 32-byte
    // correlation id, appended last so every earlier offset above is
    // unchanged.
    let reference = if c.option_present("reference")? {
        Some(c.pubkey()?)
    } else {
        c.skip(32)?;
        None
    };
    // AV-55: dispute timestamp, always present (zeroed when the escrow
    // was never disputed); appended last so every earlier offset above
    // is unchanged.
    let disputed_at = c.u64_le()?;
    // AV-55: pre-agreed arbitration default judgment, always reserved
    // like `reference`: the `None` discriminant followed by a zeroed
    // 16-byte judgment, appended last so every earlier offset above is
    // unchanged.
    let default_judgment = if c.option_present("default_judgment")? {
        let deadline_secs = c.u64_le()?;
        let default_taker_amount = c.u64_le()?;
        debug_assert_eq!(
            DEFAULT_JUDGMENT_LEN, 16,
            "default-judgment region drift vs DEFAULT_JUDGMENT_LEN"
        );
        Some(DefaultJudgment {
            deadline_secs,
            default_taker_amount,
        })
    } else {
        c.skip(DEFAULT_JUDGMENT_LEN)?;
        None
    };
    // AV-55: taker's confirmation of the pre-agreed split, always
    // present (zeroed when unconfirmed); appended last so every earlier
    // offset above is unchanged.
    let default_confirmed = c.u8()? != 0;
    // AV-56: periodic subscription release schedule, always reserved
    // like `reference`: the `None` discriminant followed by a zeroed
    // 17-byte schedule, so `with_subscription` writes in place;
    // appended last so every earlier offset above is unchanged.
    let subscription = if c.option_present("subscription")? {
        let period_secs = c.u64_le()?;
        let periods = c.u8()?;
        let per_period = c.u64_le()?;
        debug_assert_eq!(
            SUBSCRIPTION_SCHEDULE_LEN, 17,
            "subscription region drift vs SUBSCRIPTION_SCHEDULE_LEN"
        );
        Some(SubscriptionSchedule {
            period_secs,
            periods,
            per_period,
        })
    } else {
        c.skip(SUBSCRIPTION_SCHEDULE_LEN)?;
        None
    };
    // AV-56: index of the next subscription period to release, always
    // present (zeroed when no schedule is attached); appended last so
    // every earlier offset above is unchanged.
    let subscription_next = c.u8()?;
    // AV-56: per-period released bitmap, always present (zeroed when no
    // schedule is attached); appended last so every earlier offset
    // above is unchanged.
    let subscription_released = c.u64_le()?;
    // AV-57: event-history ring buffer, always present (zeroed when no
    // events were recorded); appended last so every earlier offset
    // above is unchanged. The head is the write cursor (index of the
    // oldest entry once the buffer is full), total is the monotonic
    // event counter, count the valid entries, capacity the configured
    // ring size; the 64 slots follow in slot order, each kind u8 + at
    // u64 + actor tag u8 + actor summary 8 bytes.
    let event_head = c.u8()?;
    let event_total = c.u64_le()?;
    let event_count = c.u8()?;
    let event_capacity = c.u8()?;
    let mut event_slots = [EventHistorySlot::EMPTY; MAX_EVENT_HISTORY];
    for slot in event_slots.iter_mut() {
        let kind_byte = c.u8()?;
        let kind = EscrowEventKind::from_discriminant(kind_byte)
            .ok_or(AccountDecodeError::InvalidEventKindDiscriminant(kind_byte))?;
        let at = c.u64_le()?;
        let actor_present = c.option_present("event_slots.actor")?;
        let mut summary = [0u8; 8];
        if actor_present {
            summary.copy_from_slice(c.read(8)?);
        } else {
            c.skip(8)?;
        }
        *slot = EventHistorySlot {
            kind: kind.discriminant(),
            at,
            actor: actor_present.then_some(summary),
        };
    }
    // AV-59: the per-extension expiry-increase bound and the monotonic
    // extension counter, always present (zeroed when extension is not
    // enabled / never extended); appended last so every earlier offset
    // above is unchanged.
    let max_extension_secs = c.u64_le()?;
    let extension_count = c.u64_le()?;
    // AV-63: the absolute protocol-fee ceiling, always present (zeroed
    // = uncapped when no cap was configured); appended last so every
    // earlier offset above is unchanged.
    let fee_cap = c.u64_le()?;
    // AV-64: the relative timelock duration and the funding timestamp,
    // always present (zeroed when no relative lock is configured /
    // never funded); appended last so every earlier offset above is
    // unchanged.
    let relative_timelock_secs = c.u64_le()?;
    let fund_at = c.u64_le()?;
    // AV-65: opt-in arbiter panel, always reserved like `quorum`: the
    // `None` discriminant followed by the zeroed 594-byte panel
    // region, appended last so every earlier offset above is
    // unchanged. The member count / threshold are validated `n in
    // 1..=8`, `threshold in 1..=n` — an out-of-range count would make
    // the panel accessors read past the live slots, so the panic-free
    // decoder rejects it (paralleling the AV-49 allowlist-len
    // validation).
    let arbiter_panel = if c.option_present("arbiter_panel")? {
        let n = c.u8()?;
        let threshold = c.u8()?;
        if n == 0 || n as usize > MAX_PANEL_MEMBERS || threshold == 0 || threshold > n {
            return Err(AccountDecodeError::InvalidArbiterPanelLen { n, threshold });
        }
        let mut members = [[0u8; 32]; MAX_PANEL_MEMBERS];
        for m in members.iter_mut() {
            *m = c.pubkey()?;
        }
        let mut votes = [PanelVote {
            taker_amount: 0,
            rationale_hash: None,
        }; MAX_PANEL_MEMBERS];
        for v in votes.iter_mut() {
            let taker_amount = c.u64_le()?;
            let rationale_hash = if c.option_present("arbiter_panel.vote.rationale")? {
                Some(c.pubkey()?)
            } else {
                c.skip(32)?;
                None
            };
            *v = PanelVote {
                taker_amount,
                rationale_hash,
            };
        }
        let voted = c.u64_le()?;
        debug_assert_eq!(
            ARBITER_PANEL_LEN,
            1 + 1 + MAX_PANEL_MEMBERS * 32 + MAX_PANEL_MEMBERS * PANEL_VOTE_LEN + 8,
            "panel region drift vs ARBITER_PANEL_LEN"
        );
        Some(ArbiterPanel {
            n,
            threshold,
            members,
            votes,
            voted,
        })
    } else {
        c.skip(ARBITER_PANEL_LEN)?;
        None
    };
    // AV-66: the opt-in tiered protocol-fee schedule, always reserved
    // like the panel: the 1-byte live-tier count plus the 8 fixed
    // 10-byte tier slots, appended last so every earlier offset above
    // is unchanged. The count and the live tiers are validated —
    // `tier_count in 0..=8`, each live `bps <= 10_000`, the floors
    // strictly ascending — mirroring the AV-65 panel-count validation:
    // an out-of-range count would make the schedule accessors read
    // past the live slots, so the panic-free decoder rejects it.
    let tier_count = c.u8()?;
    if tier_count as usize > MAX_FEE_TIERS {
        return Err(AccountDecodeError::InvalidFeeSchedule {
            tier_count,
            tier: 0,
        });
    }
    let mut fee_tiers = [FeeTier::default(); MAX_FEE_TIERS];
    let mut prev_floor: Option<u64> = None;
    for (i, tier) in fee_tiers.iter_mut().enumerate() {
        let min_amount = c.u64_le()?;
        let bps = c.u16_le()?;
        if (i as u8) < tier_count {
            if bps > 10_000 {
                return Err(AccountDecodeError::InvalidFeeSchedule {
                    tier_count,
                    tier: i as u8,
                });
            }
            if let Some(prev) = prev_floor {
                if min_amount <= prev {
                    return Err(AccountDecodeError::InvalidFeeSchedule {
                        tier_count,
                        tier: i as u8,
                    });
                }
            }
            prev_floor = Some(min_amount);
            *tier = FeeTier { min_amount, bps };
        }
    }
    debug_assert_eq!(
        FEE_SCHEDULE_LEN,
        1 + MAX_FEE_TIERS * FEE_TIER_LEN,
        "schedule region drift vs FEE_SCHEDULE_LEN"
    );
    let fee_schedule = FeeSchedule {
        tier_count,
        tiers: fee_tiers,
    };
    // AV-68: the dispute-evidence disclosure deadline in seconds,
    // always present (zeroed when no deadline is configured), and the
    // escalating party, always reserved like `evidence_hash`: the
    // `None` discriminant followed by a zeroed 32-byte key. Appended
    // last so every earlier offset above is unchanged.
    let evidence_deadline_secs = c.u64_le()?;
    let escalated_by = if c.option_present("escalated_by")? {
        Some(c.pubkey()?)
    } else {
        c.skip(32)?;
        None
    };

    // AV-73: the live per-period payout amount table, always present
    // (64 x u64, zeroed when no schedule is attached). Appended last
    // so every earlier offset above is unchanged.
    let mut subscription_amounts = [0u64; MAX_SUBSCRIPTION_PERIODS as usize];
    for slot in subscription_amounts.iter_mut() {
        *slot = c.u64_le()?;
    }

    // AV-75: the schema version of the persisted layout, always
    // present. AV-82 appends `slash_terms` / `penalty_paid` after it
    // (v2 layout) — the field's own offset never moves again.
    let schema_version = c.u8()?;

    // AV-82: the opt-in slash terms, always reserved like
    // `escalated_by`: the `None` discriminant followed by a zeroed
    // 40-byte region (32-byte penalty account + u64 slash deadline).
    // Appended after `schema_version` so every earlier offset above is
    // unchanged.
    let slash_terms = if c.option_present("slash_terms")? {
        let penalty_account = c.pubkey()?;
        let slash_deadline = c.u64_le()?;
        Some(SlashTerms {
            penalty_account,
            slash_deadline,
        })
    } else {
        c.skip(SLASH_TERMS_LEN)?;
        None
    };
    // AV-82: the cumulative slashed amount, always present (zeroed
    // when never slashed). Appended last so every earlier offset above
    // is unchanged.
    let penalty_paid = c.u64_le()?;

    // AV-83: the opt-in CPI target allowlist, always reserved like
    // `payout_allowlist`: the `None` discriminant followed by a zeroed
    // 257-byte region (eight 32-byte program ids + count byte),
    // appended last so every earlier offset above is unchanged. The
    // count is validated `1..=8` — an out-of-range count would make
    // `CpiAllowlist::as_slice` panic, so the panic-free decoder
    // rejects it (see `InvalidCpiAllowlistLen`).
    let cpi_allowlist = if c.option_present("cpi_allowlist")? {
        let mut addrs = [[0u8; 32]; MAX_CPI_ALLOWLIST];
        for a in addrs.iter_mut() {
            *a = c.pubkey()?;
        }
        let len = c.u8()?;
        if len == 0 || len as usize > MAX_CPI_ALLOWLIST {
            return Err(AccountDecodeError::InvalidCpiAllowlistLen(len));
        }
        debug_assert_eq!(
            CPI_ALLOWLIST_LEN,
            8 * 32 + 1,
            "allowlist region drift vs CPI_ALLOWLIST_LEN"
        );
        Some(CpiAllowlist { addrs, len })
    } else {
        c.skip(CPI_ALLOWLIST_LEN)?;
        None
    };
    // AV-84: `multisig_authority`: the `None` discriminant followed by
    // a zeroed 66-byte region (32-byte multisig program id + 32-byte
    // authority PDA + u16 threshold), appended last so every earlier
    // offset above is unchanged. The threshold is a plain u16 — no
    // range validation needed; the discriminant itself is validated
    // by `option_present` (see `InvalidOptionDiscriminant`).
    let multisig_authority = if c.option_present("multisig_authority")? {
        let program_id = c.pubkey()?;
        let authority = c.pubkey()?;
        let threshold = c.u16_le()?;
        debug_assert_eq!(
            MULTISIG_AUTHORITY_LEN,
            32 + 32 + 2,
            "multisig region drift vs MULTISIG_AUTHORITY_LEN"
        );
        Some(MultisigAuthority {
            program_id,
            authority,
            threshold,
        })
    } else {
        c.skip(MULTISIG_AUTHORITY_LEN)?;
        None
    };

    // AV-86: the opt-in slash-appeal window in seconds, always present
    // (zeroed when no window is configured). Appended last so every
    // earlier offset above is unchanged.
    let appeal_window_secs = c.u64_le()?;
    // AV-86: the appeal deadline stamped by `slash`, always present
    // (zeroed when no slash was executed under a configured window).
    // Appended last so every earlier offset above is unchanged.
    let appeal_deadline = c.u64_le()?;
    // AV-86: the appeal lifecycle discriminant, always present. The
    // discriminant is validated 0–4 — an out-of-range value would
    // decode to a state the accessors cannot name, so the panic-free
    // decoder rejects it (see `InvalidAppealStateDiscriminant`).
    let appeal_state = match c.u8()? {
        0 => AppealState::None,
        1 => AppealState::Filed,
        2 => AppealState::Upheld,
        3 => AppealState::Overturned,
        4 => AppealState::Expired,
        other => return Err(AccountDecodeError::InvalidAppealStateDiscriminant(other)),
    };
    // AV-86: the panel's running appeal ballot, always present: the
    // 1-byte voter bitmask followed by the 8 fixed vote slots.
    // Appended last so every earlier offset above is unchanged. The
    // vote bytes are plain u8s — no range validation needed; only
    // slots in the `voted` mask carry a real vote.
    let appeal_voted = c.u8()?;
    let mut appeal_votes = [0u8; 8];
    for slot in appeal_votes.iter_mut() {
        *slot = c.u8()?;
    }
    let appeal_ballot = AppealBallot {
        voted: appeal_voted,
        votes: appeal_votes,
    };
    debug_assert_eq!(
        APPEAL_BALLOT_LEN,
        1 + 8,
        "appeal ballot region drift vs APPEAL_BALLOT_LEN"
    );
    // AV-90: the non-linear vesting unlock curve, always reserved like
    // `quorum`: the `None` discriminant followed by the zeroed curve
    // region. Structural decode only — the tier table's domain
    // invariants (monotone tiers, final 10_000 bps) are enforced by
    // the builders, not re-litigated here (see module docs).
    let vesting_curve = if c.option_present("vesting_curve")? {
        let count = c.u8()?;
        let mut tiers = [(0u64, 0u16); MAX_VESTING_CURVE_TIERS];
        for tier in tiers.iter_mut() {
            let at = c.u64_le()?;
            let bps = c.u16_le()?;
            *tier = (at, bps);
        }
        Some(VestingCurve { tiers, count })
    } else {
        c.skip(VESTING_CURVE_LEN)?;
        None
    };
    // AV-91: the dispute-evidence Merkle commitment, always reserved
    // like `vesting_curve`: the `None` discriminant followed by the
    // zeroed root region, then the leaf count byte and the 8-byte
    // disclosure bitmap. Structural decode only — the commitment
    // invariants (leaf count describes the root) are enforced by
    // `escalate`, not re-litigated here.
    let evidence_root = if c.option_present("evidence_root")? {
        let mut root = [0u8; 32];
        for byte in root.iter_mut() {
            *byte = c.u8()?;
        }
        Some(root)
    } else {
        c.skip(32)?;
        None
    };
    let evidence_leaves = c.u8()?;
    let evidence_disclosed = c.u64_le()?;
    // AV-95: the multi-mint basket leg table, always reserved like
    // `quorum`: the `None` discriminant followed by the zeroed leg
    // region, or the `Some` discriminant, the live leg-count byte,
    // and the eight fixed 48-byte leg slots (32-byte mint + u64
    // locked amount + u64 released-so-far). Structural decode only —
    // the table invariants are enforced by `BasketLegs::new`, not
    // re-litigated here.
    let basket = if c.option_present("basket")? {
        let len = c.u8()?;
        if len == 0 || len as usize > MAX_BASKET_LEGS {
            return Err(AccountDecodeError::InvalidBasketLegsLen(len));
        }
        let mut legs = [BasketLeg {
            mint: [0u8; 32],
            amount: 0,
            released: 0,
        }; MAX_BASKET_LEGS];
        for leg in legs.iter_mut() {
            let mut mint = [0u8; 32];
            for byte in mint.iter_mut() {
                *byte = c.u8()?;
            }
            let amount = c.u64_le()?;
            let released = c.u64_le()?;
            *leg = BasketLeg {
                mint,
                amount,
                released,
            };
        }
        Some(BasketLegs { legs, len })
    } else {
        c.skip(BASKET_LEGS_LEN)?;
        None
    };
    // AV-96: the payout destination denylist, always reserved like the
    // AV-49 payout allowlist: the `None` discriminant followed by the
    // zeroed address region, or the `Some` discriminant, four fixed
    // 32-byte addresses, and the live entry-count byte. Structural
    // decode only — the list invariants are enforced by
    // `PayoutDenylist::new`, not re-litigated here.
    let payout_denylist = if c.option_present("payout_denylist")? {
        let mut addrs = [[0u8; 32]; MAX_PAYOUT_DENYLIST];
        for a in addrs.iter_mut() {
            *a = c.pubkey()?;
        }
        let len = c.u8()?;
        if len == 0 || len as usize > MAX_PAYOUT_DENYLIST {
            return Err(AccountDecodeError::InvalidPayoutDenylistLen(len));
        }
        debug_assert_eq!(
            PAYOUT_DENYLIST_LEN,
            4 * 32 + 1,
            "denylist region drift vs PAYOUT_DENYLIST_LEN"
        );
        Some(PayoutDenylist { addrs, len })
    } else {
        c.skip(PAYOUT_DENYLIST_LEN)?;
        None
    };
    // AV-97: the Dutch-auction settlement terms, always reserved like
    // `payout_denylist`: the `None` discriminant followed by the
    // zeroed 18-byte terms, or the `Some` discriminant and the terms
    // (`start_at` u64, `end_at` u64, `reserve_bps` u16). Structural
    // decode only, with one panic-free guarantee: a window that
    // violates the `DutchAuction::new` invariants would make
    // `payout_cap` divide by zero or price a floor above the lockup,
    // so the decoder rejects it rather than decoding a value the
    // accessors cannot safely read (AV-32 panic-free guarantee).
    let auction = if c.option_present("auction")? {
        let start_at = c.u64_le()?;
        let end_at = c.u64_le()?;
        let reserve_bps = c.u16_le()?;
        debug_assert_eq!(
            DUTCH_AUCTION_LEN,
            18,
            "auction region drift vs DUTCH_AUCTION_LEN"
        );
        if start_at >= end_at || reserve_bps > 10_000 {
            return Err(AccountDecodeError::InvalidDutchAuctionTerms {
                start_at,
                end_at,
                reserve_bps,
            });
        }
        Some(DutchAuction {
            start_at,
            end_at,
            reserve_bps,
        })
    } else {
        c.skip(DUTCH_AUCTION_LEN)?;
        None
    };
    // AV-99: the Token-2022 transfer-hook program id, always reserved
    // like `mint`: the `None` discriminant followed by the zeroed
    // 32-byte program id, or the `Some` discriminant and the program
    // id. Structural decode only — the builder-time validity (nonzero
    // id, mint bound) is enforced by `with_transfer_hook`, not
    // re-checked here (decode is panic-free by the AV-32 guarantee).
    let transfer_hook = if c.option_present("transfer_hook")? {
        Some(c.pubkey()?)
    } else {
        c.skip(PUBKEY_LEN)?;
        None
    };
    // AV-100: the streaming-fee rate and accrued counter, always
    // reserved (8 + 8 bytes, zeroed when no streaming fee is
    // configured).
    let streaming_fee_rate = c.u64_le()?;
    let streaming_fees_accrued = c.u64_le()?;
    // AV-103: the opt-in appeal bond and the locked-bond counter,
    // always reserved (8 + 8 bytes, zeroed when no bond is configured
    // / no appeal is in flight).
    let appeal_bond = c.u64_le()?;
    let appeal_bond_paid = c.u64_le()?;
    // AV-104: the delegated operator grant, always reserved like
    // `refund_to`: the `None` discriminant followed by the zeroed
    // 36-byte grant region (32-byte operator key + u32 scope bitmap),
    // appended last so every earlier offset above is unchanged. The
    // bitmap is not validated here — an unknown bit is the grantor's
    // problem, not a decode failure (mirroring the bitmask fields
    // like `activation`); `Delegation::covers` rejects foreign bits
    // at use time.
    let delegation = if c.option_present("delegation")? {
        let delegate = c.pubkey()?;
        let scopes = c.u32_le()?;
        debug_assert_eq!(
            32 + 4,
            DELEGATION_LEN - 1,
            "delegation region drift vs DELEGATION_LEN"
        );
        Some(Delegation::new(delegate, scopes))
    } else {
        c.skip(DELEGATION_LEN - 1)?;
        None
    };

    debug_assert_eq!(
        c.pos, ESCROW_BODY_LEN,
        "decode consumed != ESCROW_BODY_LEN: layout drift"
    );

    Ok(Escrow {
        initializer,
        taker,
        amount,
        released,
        expires_at,
        state,
        quorum,
        activation,
        vesting,
        arbiter,
        milestones,
        milestone_flags,
        skipped,
        mint,
        fee_bps,
        fees_paid,
        grace_period,
        evidence_hash,
        refund_to,
        penalty_bps,
        timelock,
        decimals,
        rationale_hash,
        emergency_unlock,
        fee_recipient,
        pause_authority,
        paused,
        payout_allowlist,
        // AV-53: the off-chain reference memo is persisted — a decoded
        // escrow carries the same correlation id the initializer bound.
        reference,
        // AV-55: the dispute timestamp is persisted — a decoded escrow
        // carries the same deadline origin `escalate` recorded.
        disputed_at,
        // AV-55: the pre-agreed default judgment is persisted — a
        // decoded escrow carries the same fallback terms the parties
        // agreed at setup.
        default_judgment,
        // AV-55: the taker's confirmation bit is persisted — a decoded
        // escrow carries the same agreement state.
        default_confirmed,
        // AV-56: the subscription schedule is persisted — a decoded
        // escrow carries the same release cadence the initializer
        // bound at setup.
        subscription,
        // AV-56: the next-period counter and the per-period released
        // bitmap are persisted — a decoded escrow resumes the same
        // strictly-in-order release progress.
        subscription_next,
        subscription_released,
        // AV-57: the event-history ring is persisted — a decoded escrow
        // carries the same retained event window the transitions
        // recorded (head cursor, monotonic total, valid-entry count,
        // configured capacity, and the 64 slots).
        event_head,
        event_total,
        event_count,
        event_capacity,
        event_slots,
        // AV-59: the expiry-extension bound and counter are persisted —
        // a decoded escrow carries the same extension policy and
        // history the setup and the extensions recorded.
        max_extension_secs,
        extension_count,
        // AV-63: the protocol-fee ceiling is persisted — a decoded
        // escrow carries the same cap the setup recorded, so the fee
        // charged on-chain after a decode matches the fee charged
        // before serialization.
        fee_cap,
        // AV-64: the relative timelock duration and the funding
        // timestamp are persisted — a decoded escrow carries the same
        // lock and the same funding origin the setup and `fund`
        // recorded, so the payout gates decide identically after a
        // decode.
        relative_timelock_secs,
        fund_at,
        // AV-65: the arbiter panel is persisted — a decoded escrow
        // carries the same committee, threshold and votes the setup
        // and the panel judgments recorded, so the multisig tally
        // decides identically after a decode.
        arbiter_panel,
        // AV-66: the tiered protocol-fee schedule is persisted — a
        // decoded escrow carries the same rate ladder the setup
        // recorded, so the fee charged on-chain after a decode matches
        // the fee charged before serialization.
        fee_schedule,
        // AV-68: the dispute-evidence disclosure deadline and the
        // escalating party are persisted — a decoded escrow carries the
        // same deadline the setup recorded and the same escalator
        // `escalate` recorded, so the disclosure gate and the
        // judgment-time adverse inference decide identically after a
        // decode.
        evidence_deadline_secs,
        escalated_by,
        // AV-73: the live per-period amount table is persisted — a
        // decoded escrow carries the same per-period payouts the setup
        // and `adjust_period_amounts` recorded, so `release_period`
        // pays identically after a decode.
        subscription_amounts,
        // AV-75: the schema version is persisted — a decoded escrow
        // carries the same layout version the account was written
        // under, so `migrate_schema` sees the true pre-migration
        // version.
        schema_version,
        // AV-82: the slash terms are persisted — a decoded escrow
        // carries the same penalty account and deadline the setup
        // recorded, so `slash` decides identically after a decode.
        slash_terms,
        // AV-82: the cumulative slashed amount is persisted — a
        // decoded escrow carries the same one-shot penalty the
        // enforcement recorded, so the conservation invariant holds
        // across a decode.
        penalty_paid,
        // AV-83: the CPI target allowlist is persisted — a decoded
        // escrow enforces the same target pin as the live one.
        cpi_allowlist,
        // AV-84: the multisig authority binding is persisted — a
        // decoded escrow carries the same program id / authority PDA /
        // threshold metadata the setup recorded.
        multisig_authority,
        // AV-86: the slash-appeal window, deadline, lifecycle state and
        // panel ballot are persisted — a decoded escrow carries the
        // same appeal terms the setup recorded and the same appeal
        // progress `file_appeal` / `review_appeal` recorded, so the
        // appeal gates decide identically after a decode.
        appeal_window_secs,
        appeal_deadline,
        appeal_state,
        appeal_ballot,
        // AV-90: the non-linear unlock curve rides the decode so a
        // decoded escrow prices `vested_amount` / `claim` exactly like
        // the live one.
        vesting_curve,
        // AV-91: the evidence Merkle commitment rides the decode so a
        // decoded escrow verifies `file_evidence` proofs exactly like
        // the live one.
        evidence_root,
        evidence_leaves,
        evidence_disclosed,
        // AV-95: the multi-mint basket leg table rides the decode so a
        // decoded escrow carries the same leg table the live one had.
        basket,
        // AV-96: the payout denylist rides the decode so a decoded
        // escrow enforces the same payout veto the live one had.
        payout_denylist,
        // AV-97: the Dutch-auction terms ride the decode so a decoded
        // escrow prices `claim` through the same descending curve the
        // live one used.
        auction,
        // AV-99: the Token-2022 transfer-hook program id rides the
        // decode so a decoded escrow gates CPI settlement plans on
        // the same hook binding the live one declared.
        transfer_hook,
        // AV-100: the streaming-fee rate and accrued counter ride the
        // decode so a decoded escrow bills the same accrual the live
        // one would.
        streaming_fee_rate,
        streaming_fees_accrued,
        // AV-103: the opt-in appeal bond and the locked-bond counter
        // ride the decode so a decoded escrow enforces the same bond
        // the live one configured and locked.
        appeal_bond,
        appeal_bond_paid,
        // AV-104: the delegated operator grant is persisted — a decoded
        // escrow carries the same operator and scope bitmap the grant
        // recorded, so the delegated authority checks decide identically
        // after a decode.
        delegation,
        // AV-36: the reentrancy lock is runtime-only — decoded escrows
        // always start unlocked; the lock can only be armed inside
        // `release_via_cpi`'s executor window on a live `&mut Escrow`.
        reentrancy_lock: false,
    })
}

#[cfg(test)]
mod discriminator_tests {
    use super::*;
    use crate::account_space_tests::encode_escrow;
    use crate::anchor_idl_tests::INSTRUCTIONS;
    use std::collections::HashSet;

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const ARBITER: [u8; 32] = [0xA8; 32];
    const MINT: [u8; 32] = [0xD0; 32];
    const A1: [u8; 32] = [0xA1; 32];
    const A2: [u8; 32] = [0xA2; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    /// Full account bytes for `e`: discriminator + Borsh body, the exact
    /// input [`decode_vault_account`] expects.
    fn account_bytes(e: &Escrow) -> Vec<u8> {
        let mut out = Vec::with_capacity(VAULT_SPACE);
        out.extend_from_slice(&vault_account_discriminator());
        out.extend_from_slice(&encode_escrow(e));
        debug_assert_eq!(out.len(), VAULT_SPACE);
        out
    }

    fn funded(amount: u64, expires_at: u64) -> Escrow {
        let mut e = Escrow::initialize(ALICE, BOB, amount, expires_at).unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        e
    }

    #[test]
    fn state_discriminants_are_pinned_to_declaration_order() {
        // decode maps bytes -> EscrowState by these discriminants; a
        // reordered enum must fail here, not silently mis-decode.
        assert_eq!(EscrowState::Uninitialized as u8, 0);
        assert_eq!(EscrowState::Funded as u8, 1);
        assert_eq!(EscrowState::Released as u8, 2);
        assert_eq!(EscrowState::Cancelled as u8, 3);
        assert_eq!(EscrowState::Activated as u8, 4);
        assert_eq!(EscrowState::Disputed as u8, 5);
        assert_eq!(EscrowState::Settled as u8, 6);
        // AV-34: appended after Settled so discriminants 0–6 stay
        // stable for already-serialized vaults.
        assert_eq!(EscrowState::Closed as u8, 7);
        // AV-81: appended after Closed so discriminants 0–7 stay
        // stable for already-serialized vaults.
        assert_eq!(EscrowState::Split as u8, 8);
        assert_eq!(state_from_discriminant(8).unwrap(), EscrowState::Split);
    }

    #[test]
    fn account_names_cover_every_program_side_account_type() {
        // Anti-drift: the program side's `#[account]` structs must all be
        // registered in PROGRAM_ACCOUNT_NAMES.
        let src = include_str!("../../programs/escrow-vault/src/program.rs");
        let attr_count = src.matches("#[account]").count();
        assert_eq!(
            attr_count,
            PROGRAM_ACCOUNT_NAMES.len(),
            "program side declares {attr_count} #[account] types but the registry has {}",
            PROGRAM_ACCOUNT_NAMES.len()
        );
        for name in PROGRAM_ACCOUNT_NAMES {
            let decl = format!("#[account]\npub struct {name}");
            assert!(
                src.contains(&decl),
                "registered account {name} not found on the program side"
            );
        }
    }

    #[test]
    fn discriminators_are_globally_unique() {
        // No two account discriminators collide, and no account
        // discriminator collides with any instruction discriminator
        // (`account:` vs `global:` namespaces must stay disjoint in the
        // low 8 bytes too — a collision would let one account's bytes
        // masquerade as another's).
        let mut seen = HashSet::new();
        for name in PROGRAM_ACCOUNT_NAMES {
            let d = account_discriminator(name);
            assert!(
                seen.insert(d),
                "duplicate account discriminator for {name}"
            );
        }
        let mut ix_seen = HashSet::new();
        for spec in INSTRUCTIONS {
            let d = instruction_discriminator(spec.name);
            assert!(
                ix_seen.insert(d),
                "duplicate instruction discriminator for {}",
                spec.name
            );
            assert!(
                !seen.contains(&d),
                "instruction {} collides with an account discriminator",
                spec.name
            );
        }
        // The registry is non-trivial: Vault's discriminator is pinned so
        // a sha256 regression is caught here, not on-chain.
        let vault = vault_account_discriminator();
        assert_eq!(vault, account_discriminator("Vault"));
        assert_ne!(vault, [0u8; 8]);
    }

    #[test]
    fn decode_round_trips_plain_funded_escrow() {
        let e = funded(1_000_000, EXPIRES_AT);
        let decoded = decode_vault_account(&account_bytes(&e)).unwrap();
        assert_eq!(decoded, e);
    }

    #[test]
    fn decode_round_trips_fully_optioned_escrow() {
        // Every optional region `Some`, every scalar non-zero: the whole
        // field table must decode, not just the prefix.
        let mut e = Escrow::initialize(ALICE, BOB, 5_000_000, EXPIRES_AT)
            .unwrap()
            .with_quorum(QuorumPolicy::new(&[A1, A2], &[1, 1], 2).unwrap())
            .unwrap()
            .with_vesting(VestingSchedule::new(1_700_000_000, 1_900_000_000).unwrap())
            .unwrap()
            .with_mint(MINT)
            .unwrap()
            .with_protocol_fee(250)
            .unwrap()
            .with_grace_period(300)
            .unwrap()
            .with_refund_address(BOB)
            .unwrap()
            .with_penalty_bps(100)
            .unwrap()
            .with_timelock(1_750_000_000)
            .unwrap()
            .with_decimals(6)
            .unwrap();
        e.attest(A1).unwrap();
        e.attest(A2).unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        let decoded = decode_vault_account(&account_bytes(&e)).unwrap();
        assert_eq!(decoded, e);
        assert!(decoded.quorum().unwrap().is_satisfied());
        assert_eq!(decoded.mint(), Some(MINT));
    }

    #[test]
    fn decode_round_trips_dual_sig_milestones_and_dispute() {
        let mut e = Escrow::initialize(ALICE, BOB, 8_000_000, EXPIRES_AT)
            .unwrap()
            .with_dual_sig()
            .unwrap()
            .with_milestones(MilestonePlan::new(&[3_000_000, 5_000_000]).unwrap())
            .unwrap()
            .with_arbiter(ARBITER)
            .unwrap();
        e.activate(ALICE).unwrap();
        e.activate(BOB).unwrap();
        e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
        e.escalate(BOB, EXPIRES_AT - 1, Some([0xE0; 32]), None, 0).unwrap();
        assert_eq!(e.state(), EscrowState::Disputed);
        let decoded = decode_vault_account(&account_bytes(&e)).unwrap();
        assert_eq!(decoded, e);
        assert_eq!(decoded.evidence_hash(), Some([0xE0; 32]));
    }

    #[test]
    fn decode_round_trips_terminal_states() {
        let mut released = funded(1_000_000, EXPIRES_AT);
        released.release(ALICE, EXPIRES_AT + 1, 1_000_000, None, BOB).unwrap();
        let mut cancelled = funded(2_000_000, EXPIRES_AT);
        cancelled.cancel(ALICE, None, ALICE).unwrap();
        for e in [released, cancelled] {
            let decoded = decode_vault_account(&account_bytes(&e)).unwrap();
            assert_eq!(decoded, e);
        }
    }

    #[test]
    fn decode_rejects_truncated_and_overlong() {
        let bytes = account_bytes(&funded(1_000_000, EXPIRES_AT));
        for len in [0, 1, 7, 8, VAULT_SPACE - 1] {
            assert_eq!(
                decode_vault_account(&bytes[..len]),
                Err(AccountDecodeError::Truncated {
                    expected: VAULT_SPACE,
                    got: len
                }),
                "len {len}"
            );
        }
        let mut long = bytes.clone();
        long.push(0xFF);
        assert_eq!(
            decode_vault_account(&long),
            Err(AccountDecodeError::Overlong {
                expected: VAULT_SPACE,
                got: VAULT_SPACE + 1
            })
        );
    }

    #[test]
    fn decode_rejects_bad_discriminator() {
        let mut bytes = account_bytes(&funded(1_000_000, EXPIRES_AT));
        bytes[0] ^= 0xFF;
        let mut got = [0u8; 8];
        got.copy_from_slice(&bytes[..8]);
        assert_eq!(
            decode_vault_account(&bytes),
            Err(AccountDecodeError::BadDiscriminator {
                expected: vault_account_discriminator(),
                got
            })
        );
        // All-zero discriminator (e.g. a foreign / zeroed account).
        let mut zeroed = account_bytes(&funded(1_000_000, EXPIRES_AT));
        zeroed[..8].copy_from_slice(&[0u8; 8]);
        assert!(matches!(
            decode_vault_account(&zeroed),
            Err(AccountDecodeError::BadDiscriminator { .. })
        ));
    }

    #[test]
    fn decode_rejects_invalid_state_and_option_discriminants() {
        let base = account_bytes(&funded(1_000_000, EXPIRES_AT));
        // `state` sits at offset 8 + 32 + 32 + 8 + 8 + 8 = 96.
        let state_off = ANCHOR_DISCRIMINATOR_LEN + 32 + 32 + 8 + 8 + 8;
        // AV-34: discriminant 7 is now valid (`Closed`); AV-81:
        // discriminant 8 is now valid (`Split`); the first invalid
        // byte is 9.
        for bad in [9u8, 42, 255] {
            let mut b = base.clone();
            b[state_off] = bad;
            assert_eq!(
                decode_vault_account(&b),
                Err(AccountDecodeError::InvalidStateDiscriminant(bad)),
                "state byte {bad}"
            );
        }
        // AV-34: discriminant 7 decodes to the new terminal state.
        let mut closed = base.clone();
        closed[state_off] = 7;
        assert_eq!(
            decode_vault_account(&closed).unwrap().state(),
            EscrowState::Closed
        );
        // AV-81: discriminant 8 decodes to the split terminal state.
        let mut split = base.clone();
        split[state_off] = 8;
        assert_eq!(
            decode_vault_account(&split).unwrap().state(),
            EscrowState::Split
        );
        // `quorum` Option discriminant follows `state`: offset 97.
        let quorum_disc_off = state_off + 1;
        for bad in [2u8, 3, 255] {
            let mut b = base.clone();
            b[quorum_disc_off] = bad;
            assert_eq!(
                decode_vault_account(&b),
                Err(AccountDecodeError::InvalidOptionDiscriminant {
                    field: "quorum",
                    value: bad
                }),
                "quorum discriminant {bad}"
            );
        }
    }

    /// xorshift64*: the crate's zero-dependency RNG (same construction as
    /// the AV-03/AV-08 model fuzzers).
    fn rng_next(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    #[test]
    fn fuzz_random_and_mutated_buffers_never_panic() {
        // The security property: no byte stream, however adversarial,
        // may trap the decoder — every outcome is Ok or Err.
        let valid = account_bytes(&funded(1_000_000, EXPIRES_AT));
        let mut rng: u64 = 0x9E3779B97F4A7C15;
        let mut ok_count = 0u64;
        let mut err_count = 0u64;
        for i in 0..40_000u64 {
            let buf: Vec<u8> = if i % 3 == 0 {
                // Mutated valid encoding: flip 1-4 random bytes.
                let mut b = valid.clone();
                let flips = 1 + (rng_next(&mut rng) % 4) as usize;
                for _ in 0..flips {
                    let idx = (rng_next(&mut rng) % VAULT_SPACE as u64) as usize;
                    b[idx] ^= 1 << (rng_next(&mut rng) % 8);
                }
                b
            } else {
                // Fully random buffer, adversarial lengths included.
                let len = (rng_next(&mut rng) % (VAULT_SPACE as u64 + 65)) as usize;
                (0..len).map(|_| (rng_next(&mut rng) % 256) as u8).collect()
            };
            match decode_vault_account(&buf) {
                Ok(_) => ok_count += 1,
                Err(_) => err_count += 1,
            }
        }
        // Sanity: the campaign actually exercised both outcomes (mutated
        // valid encodings with a flipped discriminator-adjacent byte
        // still decode often; random buffers almost always fail).
        assert!(ok_count > 0, "fuzz never produced Ok — suspicious");
        assert!(err_count > 0, "fuzz never produced Err — suspicious");
    }

    #[test]
    fn fuzz_single_byte_mutation_sweep_never_panics() {
        // Exhaustive single-byte sweep over a valid encoding: flip every
        // byte position through a few hostile values. ~2k decodes.
        let valid = account_bytes(&funded(1_000_000, EXPIRES_AT));
        assert_eq!(valid.len(), VAULT_SPACE);
        for pos in 0..VAULT_SPACE {
            for &v in &[0x00u8, 0x01, 0x7F, 0x80, 0xFE, 0xFF] {
                let mut b = valid.clone();
                b[pos] = v;
                let _ = decode_vault_account(&b); // must not panic
            }
        }
    }
}
