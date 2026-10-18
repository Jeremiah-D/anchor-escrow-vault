//! AV-29: Anchor IDL JSON generation pipeline (test-only).
//!
//! `anchor build` would emit `target/idl/escrow_vault.json` from the
//! `#[program]` module in `programs/escrow-vault/src/program.rs`, but the
//! Anchor/Solana BPF toolchain is unavailable in this environment (and in
//! CI), so the checked-in `programs/escrow-vault/idl/escrow_vault.json` is
//! generated from the single sources of truth the pure-logic crate
//! already maintains:
//!
//! - the `Vault` account layout (name / type / byte offset) from
//!   [`VAULT_FIELDS`];
//! - the instruction name / args from the `INSTRUCTIONS` spec table in
//!   `anchor_idl_tests`;
//! - the error code / name table from [`EscrowError`].
//!
//! Regenerate with:
//!
//! ```bash
//! UPDATE_IDL=1 cargo test -p escrow-state idl_json
//! ```
//!
//! Without the variable, `idl_json_matches_checked_in` fails on any
//! byte-level drift between the generator and the checked-in file, so CI
//! pins the artifact. When the Anchor toolchain is available, `anchor
//! build` output should replace the checked-in file (the pinning tests
//! then guard the real artifact instead).
//!
//! The `"offset"` on each account field is a pipeline extension, not
//! part of the Anchor IDL schema: the byte offset of the field inside
//! the account data *including* the 8-byte Anchor discriminator,
//! computed from Borsh layout rules (sequential fields, no padding).
//! Anchor tooling ignores unknown JSON fields; the offsets exist so
//! indexers and the tests below can pin the IDL against the on-chain
//! bytes without re-deriving the layout.

use super::account_space_tests::encode_escrow;
use super::anchor_idl_tests::INSTRUCTIONS;
use super::*;

// SHA-256 and the Anchor discriminator constructors live at the crate
// root (`crate::sha256`) and in `crate::discriminator` so this
// test-only pipeline and production code (AV-32/AV-33) share one
// implementation. `sha256` arrives via `use super::*;` above.
use super::discriminator::instruction_discriminator;

// ---------------------------------------------------------------------------
// IDL type model.
// ---------------------------------------------------------------------------

/// Element type of a fixed-size IDL array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArrayElem {
    U8,
    U64,
    PublicKey,
    /// A named account subtype used as the array element (AV-57: the
    /// event-history slot). Renders as `{"defined": "<name>"}` — the
    /// Anchor IDL spelling for an array of structs.
    Defined(&'static str),
}

impl ArrayElem {
    fn borsh_len(self) -> usize {
        match self {
            ArrayElem::U8 => 1,
            ArrayElem::U64 => 8,
            ArrayElem::PublicKey => 32,
            ArrayElem::Defined(name) => {
                named_type_fields(name).iter().map(|(_, t)| t.borsh_len()).sum()
            }
        }
    }

    fn render(self, w: &mut Writer) {
        match self {
            ArrayElem::U8 => w.str_lit("u8"),
            ArrayElem::U64 => w.str_lit("u64"),
            ArrayElem::PublicKey => w.str_lit("publicKey"),
            // A named account subtype as the array element renders as
            // an object, not a string literal (the Anchor IDL spelling
            // for an array of structs).
            ArrayElem::Defined(name) => {
                w.buf.push_str("{\"defined\": ");
                w.str_lit(name);
                w.buf.push('}');
            }
        }
    }
}

/// An Anchor IDL type expression. Covers every type that appears in
/// `VAULT_FIELDS`, the named account subtypes, and the instruction args.
#[derive(Clone, Debug, PartialEq, Eq)]
enum IdlType {
    U8,
    U16,
    U32,
    U64,
    Bool,
    PublicKey,
    Str,
    Array(ArrayElem, usize),
    Vec(Box<IdlType>),
    Option(Box<IdlType>),
    Named(&'static str),
}

impl IdlType {
    /// Borsh serialized length. Panics on variable-length types, which
    /// never appear in account layout (offsets would be meaningless).
    fn borsh_len(&self) -> usize {
        match self {
            IdlType::U8 => 1,
            IdlType::U16 => 2,
            IdlType::U32 => 4,
            IdlType::U64 => 8,
            IdlType::Bool => 1,
            IdlType::PublicKey => 32,
            IdlType::Str => panic!("idl_json: variable-length type has no account offset"),
            IdlType::Array(elem, n) => elem.borsh_len() * n,
            IdlType::Vec(_) => panic!("idl_json: variable-length type has no account offset"),
            IdlType::Option(inner) => 1 + inner.borsh_len(),
            IdlType::Named(name) => named_type_fields(name)
                .iter()
                .map(|(_, t)| t.borsh_len())
                .sum(),
        }
    }

    fn render(&self, w: &mut Writer) {
        match self {
            IdlType::U8 => w.str_lit("u8"),
            IdlType::U16 => w.str_lit("u16"),
            IdlType::U32 => w.str_lit("u32"),
            IdlType::U64 => w.str_lit("u64"),
            IdlType::Bool => w.str_lit("bool"),
            IdlType::PublicKey => w.str_lit("publicKey"),
            IdlType::Str => w.str_lit("string"),
            IdlType::Array(elem, n) => {
                w.buf.push_str("{\"array\": [");
                elem.render(w);
                w.buf.push_str(&format!(", {n}]}}"));
            }
            IdlType::Vec(inner) => {
                w.buf.push_str("{\"vec\": ");
                inner.render(w);
                w.buf.push('}');
            }
            IdlType::Option(inner) => {
                w.buf.push_str("{\"option\": ");
                inner.render(w);
                w.buf.push('}');
            }
            IdlType::Named(name) => {
                w.buf.push_str("{\"defined\": ");
                w.str_lit(name);
                w.buf.push('}');
            }
        }
    }
}

/// Map a `VAULT_FIELDS` type string onto the IDL type model. Panics on
/// an unmapped string: adding a field with a new type spelling must
/// update this pipeline, not silently drift.
fn idl_type_of(vault_ty: &str) -> IdlType {
    match vault_ty {
        "Pubkey" => IdlType::PublicKey,
        "u64" => IdlType::U64,
        "u16" => IdlType::U16,
        "u8" => IdlType::U8,
        "u8 (enum discriminant)" => IdlType::U8,
        "u8 (bitmask)" => IdlType::U8,
        "u64 (bitmask)" => IdlType::U64,
        "bool" => IdlType::Bool,
        "Option<QuorumPolicy>" => IdlType::Option(Box::new(IdlType::Named("QuorumPolicy"))),
        "Option<VestingSchedule>" => IdlType::Option(Box::new(IdlType::Named("VestingSchedule"))),
        // AV-90: opt-in non-linear vesting unlock curve.
        "Option<VestingCurve>" => IdlType::Option(Box::new(IdlType::Named("VestingCurve"))),
        "Option<Pubkey>" => IdlType::Option(Box::new(IdlType::PublicKey)),
        "Option<MilestonePlan>" => IdlType::Option(Box::new(IdlType::Named("MilestonePlan"))),
        "Option<[u8; 32]>" => IdlType::Option(Box::new(IdlType::Array(ArrayElem::U8, 32))),
        "Option<PayoutAllowlist>" => IdlType::Option(Box::new(IdlType::Named("PayoutAllowlist"))),
        // AV-95: opt-in multi-mint basket leg table.
        "Option<BasketLegs>" => IdlType::Option(Box::new(IdlType::Named("BasketLegs"))),
        // AV-96: opt-in payout destination denylist (initializer's
        // compliance veto, deny beats the AV-49 allowlist).
        "Option<PayoutDenylist>" => IdlType::Option(Box::new(IdlType::Named("PayoutDenylist"))),
        // AV-97: opt-in Dutch-auction settlement terms (the
        // descending-price pull path for the taker).
        "Option<DutchAuction>" => IdlType::Option(Box::new(IdlType::Named("DutchAuction"))),
        // AV-104: the delegated operator grant (operator key + scope
        // bitmap; the `Option` discriminant rides the vault field).
        "Option<Delegation>" => IdlType::Option(Box::new(IdlType::Named("Delegation"))),
        // AV-83: opt-in CPI target-program allowlist.
        "Option<CpiAllowlist>" => IdlType::Option(Box::new(IdlType::Named("CpiAllowlist"))),
        // AV-84: opt-in multisig authority binding.
        "Option<MultisigAuthority>" => IdlType::Option(Box::new(IdlType::Named("MultisigAuthority"))),
        // AV-86: the panel's running ballot on a filed slash appeal
        // (always present, zeroed when no appeal is filed).
        "AppealBallot" => IdlType::Named("AppealBallot"),
        "Option<DefaultJudgment>" => IdlType::Option(Box::new(IdlType::Named("DefaultJudgment"))),
        // AV-65: opt-in arbiter panel.
        "Option<ArbiterPanel>" => IdlType::Option(Box::new(IdlType::Named("ArbiterPanel"))),
        // AV-66: opt-in tiered protocol-fee schedule (always present,
        // zeroed when unconfigured — `tier_count == 0`).
        "FeeSchedule" => IdlType::Named("FeeSchedule"),
        // AV-108: opt-in multi-recipient payout-split table (always
        // present, zeroed when unconfigured — `split_count == 0`).
        "PayoutSplit" => IdlType::Named("PayoutSplit"),
        // AV-82: opt-in default-penalty (slash) terms.
        "Option<SlashTerms>" => IdlType::Option(Box::new(IdlType::Named("SlashTerms"))),
        // AV-126: opt-in tiered default-penalty (slash) ladder (always
        // present, `None` when unconfigured; the `Option`
        // discriminant rides the vault field, not the named type).
        "Option<SlashLadder>" => IdlType::Option(Box::new(IdlType::Named("SlashLadder"))),
        // AV-56: periodic subscription release schedule.
        "Option<SubscriptionSchedule>" => IdlType::Option(Box::new(IdlType::Named("SubscriptionSchedule"))),
        // AV-111: opt-in tranched-funding plan (always present,
        // `None` when unconfigured).
        "Option<FundingPlan>" => IdlType::Option(Box::new(IdlType::Named("FundingPlan"))),
        // AV-112: the release-intent timestamp (always present,
        // `None` when no intent is live).
        "Option<u64>" => IdlType::Option(Box::new(IdlType::U64)),
        // AV-113: opt-in oracle price gate (always present, `None`
        // when unconfigured; the `Option` discriminant rides the
        // vault field, not the named type).
        "Option<PriceGate>" => IdlType::Option(Box::new(IdlType::Named("PriceGate"))),
        // AV-128: the opt-in TWAP price gate.
        "Option<TwapGate>" => IdlType::Option(Box::new(IdlType::Named("TwapGate"))),
        // AV-130: the opt-in dual-control (maker-checker) release
        // intent (the `Option` discriminant rides the vault field,
        // not the named type).
        "Option<DualControlIntent>" => {
            IdlType::Option(Box::new(IdlType::Named("DualControlIntent")))
        }
        // AV-122: the live counter-offer terms (always present,
        // `None` when no offer is live; the `Option` discriminant
        // rides the vault field, not the named type).
        "Option<CounterOffer>" => IdlType::Option(Box::new(IdlType::Named("CounterOffer"))),
        // AV-57: the 64 fixed event-history slots.
        "[EventHistorySlot; 64]" => IdlType::Array(ArrayElem::Defined("EventHistorySlot"), 64),
        // AV-73: the 64 live per-period amount slots.
        "[u64; MAX_SUBSCRIPTION_PERIODS]" => {
            IdlType::Array(ArrayElem::U64, MAX_SUBSCRIPTION_PERIODS as usize)
        }
        other => panic!("idl_json: unmapped VAULT_FIELDS type string: {other}"),
    }
}

/// Map an `INSTRUCTIONS` spec arg type string onto the IDL type model.
fn arg_idl_type(spec_ty: &str) -> IdlType {
    match spec_ty {
        "u64" => IdlType::U64,
        "u8" => IdlType::U8,
        "u16" => IdlType::U16,
        // AV-104: the delegate_authority instruction's scope bitmap.
        "u32" => IdlType::U32,
        "bool" => IdlType::Bool,
        "Pubkey" => IdlType::PublicKey,
        "String" => IdlType::Str,
        "Vec<Pubkey>" => IdlType::Vec(Box::new(IdlType::PublicKey)),
        "Vec<u64>" => IdlType::Vec(Box::new(IdlType::U64)),
        "Vec<u8>" => IdlType::Vec(Box::new(IdlType::U8)),
        // AV-93: the release_split instruction's per-recipient
        // basis-point weight table.
        "Vec<u16>" => IdlType::Vec(Box::new(IdlType::U16)),
        // AV-66: the tiered fee schedule's tier ladder instruction arg.
        "Vec<FeeTier>" => IdlType::Vec(Box::new(IdlType::Named("FeeTier"))),
        // AV-90: the non-linear vesting curve's tier table instruction arg.
        "Vec<VestingTier>" => IdlType::Vec(Box::new(IdlType::Named("VestingTier"))),
        // AV-91: the evidence-disclosure Merkle proof — a Vec of
        // 32-byte sibling hashes.
        "Vec<[u8; 32]>" => IdlType::Vec(Box::new(IdlType::Array(ArrayElem::U8, 32))),
        // AV-95b: the initialize_basket instruction's (mint, amount)
        // leg table.
        "Vec<BasketLeg>" => IdlType::Vec(Box::new(IdlType::Named("BasketLeg"))),
        // AV-108: the initialize_payout_split instruction's
        // (recipient, amount) share table.
        "Vec<PayoutSplitShare>" => {
            IdlType::Vec(Box::new(IdlType::Named("PayoutSplitShare")))
        }
        // AV-126: the initialize_slash_ladder instruction's
        // (deadline, bps) rung table.
        "Vec<SlashRung>" => IdlType::Vec(Box::new(IdlType::Named("SlashRung"))),
        "Option<[u8; 32]>" => IdlType::Option(Box::new(IdlType::Array(ArrayElem::U8, 32))),
        // AV-130: the initiate_release instruction's optional SPL mint
        // binding (a real pubkey, not raw bytes).
        "Option<Pubkey>" => IdlType::Option(Box::new(IdlType::PublicKey)),
        // AV-68: the dispute-evidence disclosure commitment
        // (non-optional — disclosure always carries a hash).
        "[u8; 32]" => IdlType::Array(ArrayElem::U8, 32),
        // AV-81: the split_escrow instruction's explicit-inheritance
        // params — optional configs, so `Option<...>`; the per-child
        // milestone plans are one optional plan list.
        // AV-84: the multisig authority binding instruction arg.
        "MultisigAuthority" => IdlType::Named("MultisigAuthority"),
        "Option<VestingSchedule>" => {
            IdlType::Option(Box::new(IdlType::Named("VestingSchedule")))
        }
        "Option<QuorumPolicy>" => {
            IdlType::Option(Box::new(IdlType::Named("QuorumPolicy")))
        }
        // AV-133: the scheduled auto-recovery timestamp for `pause`.
        "Option<u64>" => IdlType::Option(Box::new(IdlType::U64)),
        "Option<Vec<MilestonePlan>>" => IdlType::Option(Box::new(IdlType::Vec(Box::new(
            IdlType::Named("MilestonePlan"),
        )))),
        other => panic!("idl_json: unmapped instruction arg type string: {other}"),
    }
}

/// Fields of the named account subtypes, in Borsh order. Mirrors the
/// Rust structs field-for-field; `named_type_sizes_pin_constants` and
/// the byte-level offset test below nail any drift.
///
/// Returns an owned `Vec` (not `&'static`) because some field types —
/// e.g. AV-57's `Option<[u8; 8]>` actor — need a heap-allocated
/// `Box`, which cannot appear in a constant. This is test-only
/// pipeline code; the allocation is irrelevant.
fn named_type_fields(name: &str) -> Vec<(&'static str, IdlType)> {
    match name {
        // QuorumPolicy { attestors: [[u8; 32]; 8], weights: [u64; 8],
        //                registered: u8, threshold: u64, approvals: u64 }
        // (AV-45 weighted).
        "QuorumPolicy" => vec![
            ("attestors", IdlType::Array(ArrayElem::PublicKey, 8)),
            ("weights", IdlType::Array(ArrayElem::U64, 8)),
            ("registered", IdlType::U8),
            ("threshold", IdlType::U64),
            ("approvals", IdlType::U64),
        ],
        // VestingSchedule { start: u64, end: u64, cliff_at: u64 }
        // (AV-51: the cliff timestamp before which zero unlocks).
        "VestingSchedule" => vec![
            ("start", IdlType::U64),
            ("end", IdlType::U64),
            ("cliff_at", IdlType::U64),
        ],
        // VestingCurve { tiers: [(u64, u16); 8], count: u8 } (AV-90):
        // the fixed tier slots serialize as a named VestingTier array
        // (IDL has no tuple type), then the live tier-count byte.
        "VestingCurve" => vec![
            (
                "tiers",
                IdlType::Array(ArrayElem::Defined("VestingTier"), 8),
            ),
            ("count", IdlType::U8),
        ],
        // VestingTier { at: u64, unlocked_bps: u16 } (AV-90): one
        // unlock tier — the cumulative unlocked basis points at the
        // unlock timestamp.
        "VestingTier" => vec![
            ("at", IdlType::U64),
            ("unlocked_bps", IdlType::U16),
        ],
        // MilestonePlan { amounts: [u64; 8], count: u8 }.
        "MilestonePlan" => vec![
            ("amounts", IdlType::Array(ArrayElem::U64, 8)),
            ("count", IdlType::U8),
        ],
        // PayoutAllowlist { addrs: [[u8; 32]; 4], len: u8 } (AV-49).
        // The 4 payout keys serialize as 4 consecutive 32-byte pubkeys.
        "PayoutAllowlist" => vec![
            ("addrs", IdlType::Array(ArrayElem::PublicKey, 4)),
            ("len", IdlType::U8),
        ],
        // PayoutDenylist { addrs: [[u8; 32]; 4], len: u8 } (AV-96).
        // Same wire shape as the allowlist; the veto check runs before
        // the allowlist check in `require_payout_recipient`.
        "PayoutDenylist" => vec![
            ("addrs", IdlType::Array(ArrayElem::PublicKey, 4)),
            ("len", IdlType::U8),
        ],
        // DutchAuction { start_at: u64, end_at: u64, reserve_bps: u16 }
        // (AV-97): the descending-price settlement terms — 18 bytes.
        "DutchAuction" => vec![
            ("start_at", IdlType::U64),
            ("end_at", IdlType::U64),
            ("reserve_bps", IdlType::U16),
        ],
        // Delegation { delegate: Pubkey, scopes: u32 } (AV-104): the
        // operator grant — 36 bytes (the `Option` discriminant rides
        // the vault field, not the named type).
        "Delegation" => vec![
            ("delegate", IdlType::PublicKey),
            ("scopes", IdlType::U32),
        ],
        // BasketLeg { mint: Pubkey, amount: u64, released: u64 }
        // (AV-95): one leg of a multi-mint basket — 48 bytes.
        "BasketLeg" => vec![
            ("mint", IdlType::PublicKey),
            ("amount", IdlType::U64),
            ("released", IdlType::U64),
        ],
        // BasketLegs { legs: [BasketLeg; 8], len: u8 } (AV-95): the
        // multi-mint leg table — 385 bytes (the `Option` discriminant
        // rides the vault field, not the named type).
        "BasketLegs" => vec![
            (
                "legs",
                IdlType::Array(ArrayElem::Defined("BasketLeg"), MAX_BASKET_LEGS),
            ),
            ("len", IdlType::U8),
        ],
        // PayoutSplit { split_count: u8, recipients: [[u8; 32]; 8],
        // amounts: [u64; 8] } (AV-108): the multi-recipient
        // payout-split table — 321 bytes, always present in the vault
        // account (zeroed when unconfigured).
        "PayoutSplit" => vec![
            ("split_count", IdlType::U8),
            (
                "recipients",
                IdlType::Array(ArrayElem::PublicKey, MAX_RELEASE_SPLIT_RECIPIENTS),
            ),
            (
                "amounts",
                IdlType::Array(ArrayElem::U64, MAX_RELEASE_SPLIT_RECIPIENTS),
            ),
        ],
        // PayoutSplitShare { recipient: Pubkey, amount: u64 }
        // (AV-108): one entry of the initialize_payout_split
        // instruction's share table — 40 bytes.
        "PayoutSplitShare" => vec![
            ("recipient", IdlType::PublicKey),
            ("amount", IdlType::U64),
        ],
        // FundingPlan { total_amount: u64, max_tranches: u8,
        // tranches_used: u8 } (AV-111): the tranched-funding plan —
        // 10 bytes, always present in the vault account (inside the
        // `Option<FundingPlan>` region, `None` when unconfigured).
        "FundingPlan" => vec![
            ("total_amount", IdlType::U64),
            ("max_tranches", IdlType::U8),
            ("tranches_used", IdlType::U8),
        ],
        // PriceGate { direction: u8, target: u64, max_staleness_secs: u64 }
        // (AV-113): the oracle price-gate terms — 17 bytes (the `Option`
        // discriminant rides the vault field, not the named type).
        // `direction`: 0 = AtOrAbove, 1 = AtOrBelow (pinned by test).
        "PriceGate" => vec![
            ("direction", IdlType::U8),
            ("target", IdlType::U64),
            ("max_staleness_secs", IdlType::U64),
        ],
        // TwapGate { direction: u8, target: u64, window_slots: u64,
        // max_staleness_secs: u64 } (AV-128): the TWAP price-gate terms
        // — 25 bytes (the `Option` discriminant rides the vault field,
        // not the named type). `direction`: 0 = AtOrAbove, 1 =
        // AtOrBelow (pinned by test).
        "TwapGate" => vec![
            ("direction", IdlType::U8),
            ("target", IdlType::U64),
            ("window_slots", IdlType::U64),
            ("max_staleness_secs", IdlType::U64),
        ],
        // CounterOffer { amount: u64, expiry: u64 } (AV-122): the
        // taker's live counter-offer terms — 16 bytes (the `Option`
        // discriminant rides the vault field, not the named type).
        "CounterOffer" => vec![
            ("amount", IdlType::U64),
            ("expiry", IdlType::U64),
        ],
        // DualControlIntent { amount: u64, mint: Option<Pubkey>,
        // payout_to: Pubkey, initiated_at: u64,
        // intent_expires_at: u64 } (AV-130): the frozen maker-checker
        // release declaration — 89 bytes (the `Option` discriminant
        // rides the vault field, not the named type).
        "DualControlIntent" => vec![
            ("amount", IdlType::U64),
            (
                "mint",
                IdlType::Option(Box::new(IdlType::PublicKey)),
            ),
            ("payout_to", IdlType::PublicKey),
            ("initiated_at", IdlType::U64),
            ("intent_expires_at", IdlType::U64),
        ],
        // CpiAllowlist { addrs: [[u8; 32]; 8], len: u8 } (AV-83).
        // The 8 program ids serialize as 8 consecutive 32-byte pubkeys.
        "CpiAllowlist" => vec![
            ("addrs", IdlType::Array(ArrayElem::PublicKey, 8)),
            ("len", IdlType::U8),
        ],
        // MultisigAuthority { program_id: Pubkey, authority: Pubkey,
        // threshold: u16 } (AV-84).
        "MultisigAuthority" => vec![
            ("program_id", IdlType::PublicKey),
            ("authority", IdlType::PublicKey),
            ("threshold", IdlType::U16),
        ],
        // DefaultJudgment { deadline_secs: u64, default_taker_amount: u64 }
        // (AV-55: 16 bytes).
        "DefaultJudgment" => vec![
            ("deadline_secs", IdlType::U64),
            ("default_taker_amount", IdlType::U64),
        ],
        // SubscriptionSchedule { period_secs: u64, periods: u8,
        // per_period: u64 } (AV-56: 17 bytes).
        "SubscriptionSchedule" => vec![
            ("period_secs", IdlType::U64),
            ("periods", IdlType::U8),
            ("per_period", IdlType::U64),
        ],
        // EventHistorySlot { kind: u8, at: u64, actor: Option<[u8; 8]> }
        // (AV-57: 18 bytes — the actor is the first 8 bytes of the
        // transition actor's pubkey, `None` when the event carries no
        // single actor; Borsh `Option<[u8; 8]>` is tag + 8 bytes).
        "EventHistorySlot" => vec![
            ("kind", IdlType::U8),
            ("at", IdlType::U64),
            (
                "actor",
                IdlType::Option(Box::new(IdlType::Array(ArrayElem::U8, 8))),
            ),
        ],
        // PanelVote { taker_amount: u64, rationale_hash: Option<[u8; 32]> }
        // (AV-65: 41 bytes — Borsh `Option<[u8; 32]>` is tag + 32 bytes).
        "PanelVote" => vec![
            ("taker_amount", IdlType::U64),
            (
                "rationale_hash",
                IdlType::Option(Box::new(IdlType::Array(ArrayElem::U8, 32))),
            ),
        ],
        // ArbiterPanel { n: u8, threshold: u8, members: [[u8; 32]; 8],
        // votes: [PanelVote; 8], voted: u64 } (AV-65: 594 bytes).
        "ArbiterPanel" => vec![
            ("n", IdlType::U8),
            ("threshold", IdlType::U8),
            ("members", IdlType::Array(ArrayElem::PublicKey, 8)),
            ("votes", IdlType::Array(ArrayElem::Defined("PanelVote"), 8)),
            ("voted", IdlType::U64),
        ],
        // FeeTier { min_amount: u64, bps: u16 } (AV-66: 10 bytes).
        "FeeTier" => vec![("min_amount", IdlType::U64), ("bps", IdlType::U16)],
        // FeeSchedule { tier_count: u8, tiers: [FeeTier; 8] } (AV-66:
        // 81 bytes — the 1-byte live-tier count plus the 8 fixed
        // 10-byte tier slots; always present, zeroed when unconfigured).
        "FeeSchedule" => vec![
            ("tier_count", IdlType::U8),
            (
                "tiers",
                IdlType::Array(ArrayElem::Defined("FeeTier"), MAX_FEE_TIERS),
            ),
        ],
        // SlashTerms { penalty_account: Pubkey, slash_deadline: u64 }
        // (AV-82: 40 bytes — the penalty sink plus the default
        // deadline; wrapped in `Option` on the vault).
        "SlashTerms" => vec![
            ("penalty_account", IdlType::PublicKey),
            ("slash_deadline", IdlType::U64),
        ],
        // SlashRung { deadline: u64, bps: u16 } (AV-126: 10 bytes —
        // one escalation tier; the IDL has no tuple type, so the
        // rung is a named struct).
        "SlashRung" => vec![
            ("deadline", IdlType::U64),
            ("bps", IdlType::U16),
        ],
        // SlashLadder { penalty_account: Pubkey, rungs: [SlashRung;
        // 8], rung_count: u8 } (AV-126: 113 bytes — the penalty sink
        // plus the 8 fixed rung slots and the live rung-count byte;
        // wrapped in `Option` on the vault).
        "SlashLadder" => vec![
            ("penalty_account", IdlType::PublicKey),
            (
                "rungs",
                IdlType::Array(ArrayElem::Defined("SlashRung"), MAX_SLASH_LADDER_RUNGS),
            ),
            ("rung_count", IdlType::U8),
        ],
        // AppealBallot { voted: u8, votes: [u8; 8] } (AV-86: 9 bytes —
        // the voter bitmask plus the 8 fixed vote slots; always
        // present on the vault, zeroed when no appeal is filed).
        "AppealBallot" => vec![
            ("voted", IdlType::U8),
            ("votes", IdlType::Array(ArrayElem::U8, 8)),
        ],
        other => panic!("idl_json: unknown named type: {other}"),
    }
}

/// The `Vault` account fields as (name, IDL type), in Borsh order,
/// derived from [`VAULT_FIELDS`].
fn vault_idl_fields() -> Vec<(&'static str, IdlType)> {
    VAULT_FIELDS
        .iter()
        .map(|(name, ty, _)| (*name, idl_type_of(ty)))
        .collect()
}

/// (name, account-data byte offset, serialized length) for every `Vault`
/// field. Offsets include the 8-byte Anchor discriminator.
fn vault_field_offsets() -> Vec<(&'static str, usize, usize)> {
    let mut out = Vec::with_capacity(VAULT_FIELDS.len());
    let mut offset = ANCHOR_DISCRIMINATOR_LEN;
    for (name, ty) in vault_idl_fields() {
        let len = ty.borsh_len();
        out.push((name, offset, len));
        offset += len;
    }
    out
}

// ---------------------------------------------------------------------------
// Deterministic JSON rendering.
// ---------------------------------------------------------------------------

struct Writer {
    buf: String,
    indent: usize,
}

impl Writer {
    fn new() -> Self {
        Self {
            buf: String::new(),
            indent: 0,
        }
    }

    fn line(&mut self, s: &str) {
        for _ in 0..self.indent {
            self.buf.push_str("  ");
        }
        self.buf.push_str(s);
        self.buf.push('\n');
    }

    fn str_lit(&mut self, s: &str) {
        self.buf.push('"');
        for c in s.chars() {
            match c {
                '"' => self.buf.push_str("\\\""),
                '\\' => self.buf.push_str("\\\\"),
                '\n' => self.buf.push_str("\\n"),
                '\r' => self.buf.push_str("\\r"),
                '\t' => self.buf.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    self.buf.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => self.buf.push(c),
            }
        }
        self.buf.push('"');
    }

    fn key(&mut self, name: &str) {
        self.str_lit(name);
        self.buf.push_str(": ");
    }
}

/// One rendered IDL instruction: the unit the spec table pins against.
struct RenderedInstruction {
    name: &'static str,
    discriminator: [u8; 8],
    args: Vec<(&'static str, IdlType)>,
}

fn rendered_instructions() -> Vec<RenderedInstruction> {
    INSTRUCTIONS
        .iter()
        .map(|spec| RenderedInstruction {
            name: spec.name,
            discriminator: instruction_discriminator(spec.name),
            args: spec
                .params
                .iter()
                .map(|(name, ty, _)| (*name, arg_idl_type(ty)))
                .collect(),
        })
        .collect()
}

fn render_idl_json() -> String {
    let version = program_crate_version();
    let mut w = Writer::new();
    w.line("{");
    w.indent += 1;

    w.line(&format!("\"version\": \"{version}\","));
    w.line("\"name\": \"escrow_vault\",");

    // ---- instructions ----
    w.line("\"instructions\": [");
    w.indent += 1;
    let instructions = rendered_instructions();
    for (i, ix) in instructions.iter().enumerate() {
        w.line("{");
        w.indent += 1;
        w.buf.push_str(&"  ".repeat(w.indent));
        w.key("name");
        w.str_lit(ix.name);
        w.buf.push_str(",\n");
        w.buf.push_str(&"  ".repeat(w.indent));
        w.key("discriminator");
        w.buf.push('[');
        for (j, b) in ix.discriminator.iter().enumerate() {
            if j > 0 {
                w.buf.push_str(", ");
            }
            w.buf.push_str(&b.to_string());
        }
        w.buf.push_str("],\n");
        // Per-instruction account constraints live in
        // programs/escrow-vault/src/program.rs and are pinned by the
        // anchor_idl_tests spec (input_mapping), not by this pipeline:
        // the byte-layout surface this file guards is name/args.
        w.buf.push_str(&"  ".repeat(w.indent));
        w.buf.push_str("\"accounts\": [],\n");
        w.buf.push_str(&"  ".repeat(w.indent));
        w.buf.push_str("\"args\": [");
        if ix.args.is_empty() {
            w.buf.push_str("]");
        } else {
            w.buf.push('\n');
            w.indent += 1;
            for (k, (name, ty)) in ix.args.iter().enumerate() {
                w.buf.push_str(&"  ".repeat(w.indent));
                w.buf.push_str("{\"name\": ");
                w.str_lit(name);
                w.buf.push_str(", \"type\": ");
                ty.render(&mut w);
                w.buf.push('}');
                if k + 1 < ix.args.len() {
                    w.buf.push(',');
                }
                w.buf.push('\n');
            }
            w.indent -= 1;
            w.buf.push_str(&"  ".repeat(w.indent));
            w.buf.push(']');
        }
        w.buf.push('\n');
        w.indent -= 1;
        w.buf.push_str(&"  ".repeat(w.indent));
        w.buf.push('}');
        if i + 1 < instructions.len() {
            w.buf.push(',');
        }
        w.buf.push('\n');
    }
    w.indent -= 1;
    w.line("],");

    // ---- accounts ----
    w.line("\"accounts\": [");
    w.indent += 1;
    w.line("{");
    w.indent += 1;
    w.line("\"name\": \"Vault\",");
    w.line("\"type\": {");
    w.indent += 1;
    w.line("\"kind\": \"struct\",");
    w.line("\"fields\": [");
    w.indent += 1;
    let offsets = vault_field_offsets();
    for (i, (name, offset, _)) in offsets.iter().enumerate() {
        let ty = &vault_idl_fields()[i].1;
        w.buf.push_str(&"  ".repeat(w.indent));
        w.buf.push_str("{\"name\": ");
        w.str_lit(name);
        w.buf.push_str(", \"type\": ");
        ty.render(&mut w);
        w.buf.push_str(&format!(", \"offset\": {offset}}}"));
        if i + 1 < offsets.len() {
            w.buf.push(',');
        }
        w.buf.push('\n');
    }
    w.indent -= 1;
    w.line("]");
    w.indent -= 1;
    w.line("}");
    w.indent -= 1;
    w.line("}");
    w.indent -= 1;
    w.line("],");

    // ---- types ----
    w.line("\"types\": [");
    w.indent += 1;
    let type_names = [
        "QuorumPolicy",
        "VestingSchedule",
        "MilestonePlan",
        "PayoutAllowlist",
        "DefaultJudgment",
        "SubscriptionSchedule",
        "EventHistorySlot",
        "PanelVote",
        "ArbiterPanel",
        "FeeTier",
        "FeeSchedule",
        "SlashTerms",
        "CpiAllowlist",
        "MultisigAuthority",
        "AppealBallot",
        // AV-95: the multi-mint basket leg types.
        "BasketLeg",
        "BasketLegs",
        // AV-96: the payout destination denylist type.
        "PayoutDenylist",
        // AV-97: the Dutch-auction settlement terms type.
        "DutchAuction",
        // AV-104: the delegated operator grant type.
        "Delegation",
        // AV-108: the multi-recipient payout-split table type, plus
        // the initialize_payout_split instruction's share entry type.
        "PayoutSplit",
        "PayoutSplitShare",
        // AV-111: the tranched-funding plan type.
        "FundingPlan",
        // AV-113: the oracle price-gate terms type.
        "PriceGate",
        // AV-128: the TWAP price-gate terms type.
        "TwapGate",
        // AV-122: the taker's live counter-offer terms type.
        "CounterOffer",
        // AV-130: the frozen maker-checker release declaration type.
        "DualControlIntent",
    ];
    for (ti, type_name) in type_names.iter().enumerate() {
        w.line("{");
        w.indent += 1;
        w.buf.push_str(&"  ".repeat(w.indent));
        w.key("name");
        w.str_lit(type_name);
        w.buf.push_str(",\n");
        w.line("\"type\": {");
        w.indent += 1;
        w.line("\"kind\": \"struct\",");
        w.line("\"fields\": [");
        w.indent += 1;
        let fields = named_type_fields(type_name);
        let mut offset = 0usize;
        for (i, (name, ty)) in fields.iter().enumerate() {
            w.buf.push_str(&"  ".repeat(w.indent));
            w.buf.push_str("{\"name\": ");
            w.str_lit(name);
            w.buf.push_str(", \"type\": ");
            ty.render(&mut w);
            w.buf.push_str(&format!(", \"offset\": {offset}}}"));
            if i + 1 < fields.len() {
                w.buf.push(',');
            }
            w.buf.push('\n');
            offset += ty.borsh_len();
        }
        w.indent -= 1;
        w.line("]");
        w.indent -= 1;
        w.line("}");
        w.indent -= 1;
        w.buf.push_str(&"  ".repeat(w.indent));
        w.buf.push('}');
        if ti + 1 < type_names.len() {
            w.buf.push(',');
        }
        w.buf.push('\n');
    }
    w.indent -= 1;
    w.line("],");

    // ---- errors ----
    w.line("\"errors\": [");
    w.indent += 1;
    let errors = EscrowError::all();
    for (i, e) in errors.iter().enumerate() {
        w.buf.push_str(&"  ".repeat(w.indent));
        w.buf.push_str(&format!(
            "{{\"code\": {}, \"name\": ",
            e.code()
        ));
        w.str_lit(&format!("{e:?}"));
        w.buf.push('}');
        if i + 1 < errors.len() {
            w.buf.push(',');
        }
        w.buf.push('\n');
    }
    w.indent -= 1;
    w.line("],");

    // ---- metadata ----
    w.line("\"metadata\": {");
    w.indent += 1;
    w.buf.push_str(&"  ".repeat(w.indent));
    w.key("generator");
    w.str_lit("escrow-state idl_json pipeline (AV-29)");
    w.buf.push_str(",\n");
    w.buf.push_str(&"  ".repeat(w.indent));
    w.key("provenance");
    w.str_lit("generated from VAULT_FIELDS + INSTRUCTIONS spec + EscrowError; the Anchor toolchain is unavailable in this environment, so this file stands in for `anchor build` output until the toolchain can regenerate it");
    w.buf.push_str(",\n");
    w.buf.push_str(&"  ".repeat(w.indent));
    w.key("borsh_offsets");
    w.str_lit("field \"offset\" values are a pipeline extension: byte offsets into the account data INCLUDING the 8-byte Anchor discriminator, computed from Borsh layout (sequential fields, no padding); named-type offsets are relative to the start of the type");
    w.buf.push('\n');
    w.indent -= 1;
    w.line("}");

    w.indent -= 1;
    w.line("}");
    w.buf
}

/// Read the `version` from `programs/escrow-vault/Cargo.toml` so the
/// IDL version tracks the program crate. Panics when unparseable: a
/// silent fallback version would be worse than a loud failure.
fn program_crate_version() -> String {
    let manifest =
        std::fs::read_to_string("../programs/escrow-vault/Cargo.toml").expect("read program Cargo.toml");
    for line in manifest.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("version") {
            let rest = rest.trim().strip_prefix('=').expect("version assignment").trim();
            let version = rest.trim_matches('"');
            assert!(
                !version.is_empty() && version != "version",
                "unparseable version line: {line}"
            );
            return version.to_string();
        }
    }
    panic!("idl_json: no version found in programs/escrow-vault/Cargo.toml");
}

/// Path of the checked-in IDL, relative to the `escrow-state` crate dir
/// (cargo runs tests with the package root as cwd).
fn idl_json_path() -> std::path::PathBuf {
    std::path::PathBuf::from("../programs/escrow-vault/idl/escrow_vault.json")
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[test]
fn sha256_known_vectors() {
    // FIPS 180-4 test vectors pin the hand-rolled implementation, which
    // in turn pins every instruction discriminator below.
    let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn named_type_sizes_pin_constants() {
    // The named-type field tables above must serialize to exactly the
    // lengths the account-space math reserves.
    let size = |name: &str| {
        named_type_fields(name)
            .iter()
            .map(|(_, t)| t.borsh_len())
            .sum::<usize>()
    };
    assert_eq!(size("QuorumPolicy"), QUORUM_POLICY_LEN);
    // AV-51: the cliff_at u64 joins start/end.
    assert_eq!(size("VestingSchedule"), 24);
    // AV-90: 8 fixed (u64, u16) tier slots + the live tier-count byte.
    assert_eq!(size("VestingTier"), 10);
    assert_eq!(size("VestingCurve"), VESTING_CURVE_LEN);
    assert_eq!(size("VestingCurve"), 81);
    assert_eq!(size("MilestonePlan"), MILESTONE_PLAN_LEN);
    assert_eq!(size("PayoutAllowlist"), PAYOUT_ALLOWLIST_LEN);
    // AV-96: same wire shape as the allowlist (4 pubkeys + count byte).
    assert_eq!(size("PayoutDenylist"), PAYOUT_DENYLIST_LEN);
    // AV-97: start_at u64 + end_at u64 + reserve_bps u16.
    assert_eq!(size("DutchAuction"), DUTCH_AUCTION_LEN);
    assert_eq!(size("DutchAuction"), 18);
    // AV-104: 32-byte operator key + u32 scope bitmap (the `Option`
    // discriminant rides the vault field, not the named type).
    assert_eq!(size("Delegation"), DELEGATION_LEN - 1);
    assert_eq!(size("Delegation"), 36);
    // AV-83: eight 32-byte program ids + count byte.
    assert_eq!(size("CpiAllowlist"), CPI_ALLOWLIST_LEN);
    // AV-84: 32-byte multisig program id + 32-byte authority PDA + u16
    // threshold.
    assert_eq!(size("MultisigAuthority"), MULTISIG_AUTHORITY_LEN);
    // AV-55: deadline + taker share.
    assert_eq!(size("DefaultJudgment"), DEFAULT_JUDGMENT_LEN);
    assert_eq!(size("DefaultJudgment"), 16);
    // AV-56: period length + period count + per-period amount.
    assert_eq!(size("SubscriptionSchedule"), SUBSCRIPTION_SCHEDULE_LEN);
    assert_eq!(size("SubscriptionSchedule"), 17);
    // AV-57: kind discriminant + timestamp + actor option tag +
    // 8-byte actor summary.
    assert_eq!(size("EventHistorySlot"), EVENT_HISTORY_SLOT_LEN);
    assert_eq!(size("EventHistorySlot"), 18);
    // AV-65: taker amount + rationale option tag + 32-byte rationale.
    assert_eq!(size("PanelVote"), PANEL_VOTE_LEN);
    assert_eq!(size("PanelVote"), 41);
    // AV-65: member count + threshold + 8 member keys + 8 vote slots
    // + voted bitmask.
    assert_eq!(size("ArbiterPanel"), ARBITER_PANEL_LEN);
    assert_eq!(size("ArbiterPanel"), 594);
    // AV-66: min_amount u64 + bps u16.
    assert_eq!(size("FeeTier"), FEE_TIER_LEN);
    assert_eq!(size("FeeTier"), 10);
    // AV-66: live-tier count + 8 fixed tier slots.
    assert_eq!(size("FeeSchedule"), FEE_SCHEDULE_LEN);
    assert_eq!(size("FeeSchedule"), 81);
    // AV-82: penalty account + slash deadline.
    assert_eq!(size("SlashTerms"), SLASH_TERMS_LEN);
    assert_eq!(size("SlashTerms"), 40);
    // AV-126: deadline u64 + bps u16.
    assert_eq!(size("SlashRung"), 10);
    // AV-126: 32-byte penalty account + 8 fixed 10-byte rung slots +
    // the live rung-count byte.
    assert_eq!(size("SlashLadder"), SLASH_LADDER_LEN);
    assert_eq!(size("SlashLadder"), 113);
    // AV-86: voter bitmask + 8 vote slots.
    assert_eq!(size("AppealBallot"), APPEAL_BALLOT_LEN);
    assert_eq!(size("AppealBallot"), 9);
    // AV-95: 32-byte mint + u64 locked amount + u64 released-so-far.
    assert_eq!(size("BasketLeg"), BASKET_LEG_LEN);
    assert_eq!(size("BasketLeg"), 48);
    // AV-95: live leg-count byte + 8 fixed 48-byte leg slots.
    assert_eq!(size("BasketLegs"), BASKET_LEGS_LEN);
    assert_eq!(size("BasketLegs"), 385);
    // AV-111: total_amount u64 + max_tranches u8 + tranches_used u8
    // (the `Option` discriminant rides the vault field, not the
    // named type).
    assert_eq!(size("FundingPlan"), FUNDING_PLAN_LEN - 1);
    assert_eq!(size("FundingPlan"), 10);
    // AV-113: direction u8 + target u64 + max_staleness_secs u64 (the
    // `Option` discriminant rides the vault field, not the named
    // type).
    assert_eq!(size("PriceGate"), PRICE_GATE_LEN - 1);
    assert_eq!(size("PriceGate"), 17);
    // AV-128: the TWAP-gate terms — 25 bytes (the `Option`
    // discriminant rides the vault field, not the named type).
    assert_eq!(size("TwapGate"), TWAP_GATE_LEN - 1);
    assert_eq!(size("TwapGate"), 25);
    // AV-122: amount u64 + expiry u64 (the `Option` discriminant
    // rides the vault field, not the named type).
    assert_eq!(size("CounterOffer"), COUNTER_OFFER_LEN);
    assert_eq!(size("CounterOffer"), 16);
    // AV-130: amount u64 + mint option tag + 32-byte mint +
    // payout_to pubkey + initiated_at u64 + intent_expires_at u64
    // (the `Option` discriminant rides the vault field, not the
    // named type).
    assert_eq!(size("DualControlIntent"), DUAL_CONTROL_INTENT_LEN);
    assert_eq!(size("DualControlIntent"), 89);
}

#[test]
fn vault_offsets_cover_account_space() {
    let offsets = vault_field_offsets();
    assert_eq!(offsets.len(), VAULT_FIELDS.len());
    for (i, (name, offset, len)) in offsets.iter().enumerate() {
        assert_eq!(*name, VAULT_FIELDS[i].0, "field order drift");
        assert_eq!(*len, VAULT_FIELDS[i].2, "field length drift for {name}");
        let _ = offset;
    }
    let total: usize = offsets.iter().map(|(_, _, len)| len).sum();
    assert_eq!(total, ESCROW_BODY_LEN);
    assert_eq!(ANCHOR_DISCRIMINATOR_LEN + total, VAULT_SPACE);
}

#[test]
fn idl_instructions_pin_spec() {
    // Bidirectional: every INSTRUCTIONS spec entry appears in the
    // rendered IDL with identical name/args, and the IDL carries no
    // instruction the spec table does not know about.
    let rendered = rendered_instructions();
    assert_eq!(
        rendered.len(),
        INSTRUCTIONS.len(),
        "instruction count drift between INSTRUCTIONS spec and IDL"
    );
    for spec in INSTRUCTIONS {
        let r = rendered
            .iter()
            .find(|r| r.name == spec.name)
            .unwrap_or_else(|| panic!("IDL missing instruction {}", spec.name));
        let expected_args: Vec<(&str, IdlType)> = spec
            .params
            .iter()
            .map(|(name, ty, _)| (*name, arg_idl_type(ty)))
            .collect();
        assert_eq!(r.args, expected_args, "arg drift for instruction {}", spec.name);
        // The discriminator is recomputed from the Anchor rule here, so
        // a change to the hashing helper breaks this test loudly.
        assert_eq!(
            r.discriminator,
            instruction_discriminator(spec.name),
            "discriminator drift for instruction {}",
            spec.name
        );
        assert_eq!(
            &r.discriminator[..],
            &sha256(format!("global:{}", spec.name).as_bytes())[..8]
        );
    }
}

#[test]
fn idl_errors_pin_enum() {
    // Every EscrowError variant appears exactly once, with its stable code.
    let errors = EscrowError::all();
    let mut seen = std::collections::HashSet::new();
    for e in errors {
        let name = format!("{e:?}");
        assert!(seen.insert(name.clone()), "duplicate error variant {name}");
        assert!(
            (100..200).contains(&e.code()),
            "error code out of pinned range: {name} = {}",
            e.code()
        );
    }
    assert_eq!(errors.len(), 96, "error variant count drift");
    // Spot-pin the code table ends so a renumber breaks loudly.
    assert_eq!(EscrowError::Unauthorized.code(), 100);
    assert_eq!(EscrowError::CpiExecutionFailed.code(), 121);
    assert_eq!(EscrowError::ReentrantCall.code(), 122);
    assert_eq!(EscrowError::InvalidFeeRecipient.code(), 123);
    assert_eq!(EscrowError::Paused.code(), 124);
    assert_eq!(EscrowError::InvalidPauseAuthority.code(), 125);
    assert_eq!(EscrowError::InvalidPayoutAllowlist.code(), 126);
    assert_eq!(EscrowError::PayoutNotAllowlisted.code(), 127);
    assert_eq!(EscrowError::InvalidTaker.code(), 128);
    assert_eq!(EscrowError::DefaultJudgmentNotDue.code(), 129);
    assert_eq!(EscrowError::InvalidSubscription.code(), 130);
    assert_eq!(EscrowError::PeriodNotDue.code(), 131);
    assert_eq!(EscrowError::InvalidEventCapacity.code(), 132);
    assert_eq!(EscrowError::InvalidInitializer.code(), 133);
    assert_eq!(EscrowError::InvalidExpiryExtension.code(), 134);
    assert_eq!(EscrowError::InvalidTimelock.code(), 135);
    // AV-65: the new codes extend the table — never renumbered.
    assert_eq!(EscrowError::InvalidArbiterPanel.code(), 136);
    assert_eq!(EscrowError::PanelResolveDisabled.code(), 137);
    // AV-68: appended, never renumbered.
    assert_eq!(EscrowError::InvalidEvidenceDeadline.code(), 138);
    assert_eq!(EscrowError::EvidenceDisclosureLate.code(), 139);
    // AV-75: appended, never renumbered.
    assert_eq!(EscrowError::InvalidSchemaMigration.code(), 140);
    // AV-77: appended, never renumbered.
    assert_eq!(EscrowError::TemplateOverrideRejected.code(), 141);
    // AV-81: appended, never renumbered.
    assert_eq!(EscrowError::InvalidSplit.code(), 142);
    // AV-82: appended, never renumbered.
    assert_eq!(EscrowError::SlashNotEligible.code(), 143);
    // AV-83: appended, never renumbered.
    assert_eq!(EscrowError::InvalidCpiAllowlist.code(), 144);
    assert_eq!(EscrowError::InvalidMultisigAuthority.code(), 145);
    // AV-86: appended, never renumbered.
    assert_eq!(EscrowError::InvalidAppealWindow.code(), 146);
    // AV-90: appended, never renumbered.
    assert_eq!(EscrowError::InvalidVestingCurve.code(), 147);
    // AV-91: appended, never renumbered.
    assert_eq!(EscrowError::InvalidEvidenceProof.code(), 148);
    // AV-92: appended, never renumbered.
    assert_eq!(EscrowError::InvalidVaultSeeds.code(), 149);
    // AV-93: appended, never renumbered.
    assert_eq!(EscrowError::InvalidReleaseSplit.code(), 150);
    // AV-94: appended, never renumbered.
    assert_eq!(EscrowError::GapInEventStream.code(), 151);
    // AV-95: appended, never renumbered.
    assert_eq!(EscrowError::InvalidBasket.code(), 152);
    // AV-96: appended, never renumbered.
    assert_eq!(EscrowError::PayoutDenied.code(), 153);
    assert_eq!(EscrowError::InvalidPayoutDenylist.code(), 154);
    // AV-97: appended, never renumbered.
    assert_eq!(EscrowError::InvalidAuctionParams.code(), 155);
    assert_eq!(EscrowError::AuctionNotActive.code(), 156);
    // AV-99: appended, never renumbered.
    assert_eq!(EscrowError::InvalidTransferHook.code(), 157);
    // AV-103: appended, never renumbered.
    assert_eq!(EscrowError::InvalidAppealBond.code(), 158);
    assert_eq!(EscrowError::AppealExpiryNotDue.code(), 159);
    // AV-104: appended, never renumbered.
    assert_eq!(EscrowError::InvalidDelegation.code(), 160);
    // AV-105: appended, never renumbered.
    assert_eq!(EscrowError::InvalidSwapParties.code(), 161);
    assert_eq!(EscrowError::InvalidSwapAmounts.code(), 162);
    assert_eq!(EscrowError::SwapLinkActive.code(), 163);
    // AV-106: appended, never renumbered.
    assert_eq!(EscrowError::InvalidPoolPayout.code(), 164);
    // AV-107: appended, never renumbered.
    assert_eq!(EscrowError::InvalidInterestRate.code(), 165);
    assert_eq!(EscrowError::InterestNotEnabled.code(), 166);
    // AV-108: appended, never renumbered.
    assert_eq!(EscrowError::InvalidPayoutSplit.code(), 167);
    // AV-109: the dead-man's switch codes extend the table — never renumbered.
    assert_eq!(EscrowError::InvalidDeadmanConfig.code(), 168);
    assert_eq!(EscrowError::DeadmanNotElapsed.code(), 169);
    // AV-110: appended, never renumbered.
    assert_eq!(EscrowError::InvalidRentTopUp.code(), 170);
    // AV-111: appended, never renumbered.
    assert_eq!(EscrowError::FundingIncomplete.code(), 171);
    assert_eq!(EscrowError::FundingTranchesExhausted.code(), 172);
    assert_eq!(EscrowError::InvalidFundingPlan.code(), 173);
    // AV-112: appended, never renumbered.
    assert_eq!(EscrowError::ReleaseCoolingNotElapsed.code(), 174);
    // AV-113: appended, never renumbered.
    assert_eq!(EscrowError::PriceGateNotSatisfied.code(), 175);
    assert_eq!(EscrowError::InvalidPriceGate.code(), 176);
    // AV-117: appended, never renumbered.
    assert_eq!(EscrowError::CompoundInterestActive.code(), 178);
    // AV-121: appended, never renumbered.
    assert_eq!(EscrowError::InvalidClaimCooldown.code(), 179);
    // AV-122: appended, never renumbered.
    assert_eq!(EscrowError::InvalidCounterOffer.code(), 180);
    // AV-123: appended, never renumbered.
    assert_eq!(EscrowError::InvalidReleaseIntent.code(), 181);
    assert_eq!(EscrowError::IntentNonceReused.code(), 182);
    assert_eq!(EscrowError::IntentExpired.code(), 183);
    // AV-126: appended, never renumbered.
    assert_eq!(EscrowError::InvalidSlashLadder.code(), 184);
    // AV-127: appended, never renumbered.
    assert_eq!(EscrowError::PartialRefundExceedsLocked.code(), 185);
    // AV-128: appended, never renumbered.
    assert_eq!(EscrowError::TwapGateNotSatisfied.code(), 186);
    assert_eq!(EscrowError::InvalidTwapGate.code(), 187);
    // AV-130: appended, never renumbered.
    assert_eq!(EscrowError::InvalidDualControl.code(), 188);
    assert_eq!(EscrowError::DualControlIntentExists.code(), 189);
    assert_eq!(EscrowError::DualControlNotInitiated.code(), 190);
    assert_eq!(EscrowError::DualControlExpired.code(), 191);
    assert_eq!(EscrowError::DualControlRequired.code(), 192);
    // AV-131: appended, never renumbered.
    assert_eq!(EscrowError::InvalidDisputeAmount.code(), 193);
    assert_eq!(EscrowError::DisputedAmountLocked.code(), 194);
    // AV-132: appended, never renumbered.
    assert_eq!(EscrowError::SlippageExceeded.code(), 195);
}

#[test]
fn idl_json_matches_checked_in() {
    let rendered = render_idl_json();
    let path = idl_json_path();
    if std::env::var("UPDATE_IDL").is_ok() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create idl dir");
        }
        std::fs::write(&path, &rendered).expect("write IDL JSON");
        return;
    }
    let checked_in = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "checked-in IDL not found at {}; regenerate with UPDATE_IDL=1 cargo test -p escrow-state idl_json",
            path.display()
        )
    });
    assert_eq!(
        checked_in, rendered,
        "checked-in escrow_vault.json drifted from the generator; regenerate with UPDATE_IDL=1"
    );
}

// Byte-level pinning: the IDL field offsets must land on the exact bytes
// the hand-written Borsh encoder (`encode_escrow`) produces for a
// fully-configured escrow. This is the anti-drift nail AV-29 exists for:
// IDL name/type/offset on one side, real serialized bytes on the other.

const ALICE: [u8; 32] = [0xAA; 32];
const BOB: [u8; 32] = [0xBB; 32];
const ATTESTOR_1: [u8; 32] = [0xA1; 32];
const ATTESTOR_2: [u8; 32] = [0xA2; 32];
const ARB: [u8; 32] = [0xA9; 32];
const MINT: [u8; 32] = [0xA5; 32];
const REFUND: [u8; 32] = [0xB0; 32];
const EVIDENCE: [u8; 32] = [0xE8; 32];
const EXPIRES_AT: u64 = 1_800_000_000;
const VEST_START: u64 = 1_700_000_000;
const VEST_END: u64 = 1_900_000_000;

/// Slice of the encoded body for `name`, using the IDL-computed offset.
/// `encode_escrow` emits the body without the discriminator, so the
/// account-data offset is shifted back by 8.
fn body_field<'a>(bytes: &'a [u8], offsets: &[(&str, usize, usize)], name: &str) -> &'a [u8] {
    let (_, offset, len) = offsets
        .iter()
        .find(|(n, _, _)| *n == name)
        .copied()
        .unwrap_or_else(|| panic!("unknown field {name}"));
    &bytes[offset - ANCHOR_DISCRIMINATOR_LEN..offset - ANCHOR_DISCRIMINATOR_LEN + len]
}

fn u64_at(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().expect("u64 slice"))
}

fn max_config_funded_escrow() -> Escrow {
    let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
    e = e.with_dual_sig().unwrap();
    e = e
        .with_quorum(QuorumPolicy::new(&[ATTESTOR_1, ATTESTOR_2], &[1, 1], 2).unwrap())
        .unwrap();
    e = e
        .with_vesting(VestingSchedule::new(VEST_START, VEST_END).unwrap())
        .unwrap();
    e = e.with_mint(MINT).unwrap();
    e = e.with_protocol_fee(250).unwrap();
    e = e.with_grace_period(3600).unwrap();
    e = e.with_refund_address(REFUND).unwrap();
    e = e.with_penalty_bps(100).unwrap();
    e = e.with_timelock(VEST_START + 1).unwrap();
    e = e.with_decimals(6).unwrap();
    e = e.with_arbiter(ARB).unwrap();
    // AV-113: attach the oracle price gate so the new tail bytes are
    // pinned against the encoder below.
    e = e
        .with_price_gate(PriceGate {
            direction: PriceDirection::AtOrAbove,
            target: 100_000,
            max_staleness_secs: 300,
        })
        .unwrap();
    e = e
        .with_milestones(MilestonePlan::new(&[400_000, 600_000]).unwrap())
        .unwrap();
    e.activate(ALICE).unwrap();
    e.activate(BOB).unwrap();
    e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
    e.attest(ATTESTOR_1).unwrap();
    e.attest(ATTESTOR_2).unwrap();
    // Milestone 0: dual-confirm then release. Tranche 400_000 at 250 bps
    // => fee 10_000, taker payout 390_000, gross released 400_000.
    e.confirm_milestone(ALICE, 0).unwrap();
    e.confirm_milestone(BOB, 0).unwrap();
    let (payout, fee) = e
        .release_milestone(ALICE, EXPIRES_AT, 0, Some(MINT), BOB)
        .unwrap();
    assert_eq!((payout, fee), (390_000, 10_000));
    // Milestone 1: dual-skip => 600_000 joins the refundable remainder.
    e.skip_milestone(ALICE, 1).unwrap();
    e.skip_milestone(BOB, 1).unwrap();
    e
}

#[test]
fn idl_field_offsets_pin_borsh_encoder() {
    let e = max_config_funded_escrow();
    let enc = encode_escrow(&e);
    assert_eq!(enc.len(), ESCROW_BODY_LEN);
    let offsets = vault_field_offsets();

    assert_eq!(body_field(&enc, &offsets, "initializer"), &ALICE);
    assert_eq!(body_field(&enc, &offsets, "taker"), &BOB);
    assert_eq!(u64_at(body_field(&enc, &offsets, "amount")), 1_000_000);
    assert_eq!(u64_at(body_field(&enc, &offsets, "released")), 400_000);
    assert_eq!(u64_at(body_field(&enc, &offsets, "expires_at")), EXPIRES_AT);
    assert_eq!(body_field(&enc, &offsets, "state"), &[1u8]); // Funded

    // quorum: Some { attestors[8], weights[8], registered, threshold,
    // approvals } (AV-45 weighted).
    let q = body_field(&enc, &offsets, "quorum");
    assert_eq!(q[0], 1, "quorum discriminant");
    assert_eq!(&q[1..33], &ATTESTOR_1);
    assert_eq!(&q[33..65], &ATTESTOR_2);
    assert_eq!(&q[65..257], &[0u8; 192], "unused attestor slots zeroed");
    assert_eq!(u64_at(&q[257..265]), 1, "weight of attestor slot 0");
    assert_eq!(u64_at(&q[265..273]), 1, "weight of attestor slot 1");
    assert_eq!(&q[273..321], &[0u8; 48], "unused weight slots zeroed");
    assert_eq!(q[321], 2, "registered");
    assert_eq!(u64_at(&q[322..330]), 2, "weight-sum threshold");
    assert_eq!(u64_at(&q[330..338]), 0b11, "approvals bitmask");

    // activation: bit 0 initializer, bit 1 taker, bit 2 dual-sig required
    // (set by with_dual_sig) => 0b111.
    assert_eq!(body_field(&enc, &offsets, "activation"), &[0b111]);

    let v = body_field(&enc, &offsets, "vesting");
    assert_eq!(v[0], 1, "vesting discriminant");
    assert_eq!(u64_at(&v[1..9]), VEST_START);
    assert_eq!(u64_at(&v[9..17]), VEST_END);

    let a = body_field(&enc, &offsets, "arbiter");
    assert_eq!(a[0], 1, "arbiter discriminant");
    assert_eq!(&a[1..33], &ARB);

    let m = body_field(&enc, &offsets, "milestones");
    assert_eq!(m[0], 1, "milestones discriminant");
    assert_eq!(u64_at(&m[1..9]), 400_000);
    assert_eq!(u64_at(&m[9..17]), 600_000);
    assert_eq!(&m[17..65], &[0u8; 48], "unused tranche slots zeroed");
    assert_eq!(m[65], 2, "tranche count");

    // milestone_flags: bits index*6+{0,1,2} (init/taker confirm + released
    // of milestone 0) and index*6+{3,4,5} (init/taker skip approvals +
    // skipped of milestone 1) => bits 0,1,2 and 9,10,11.
    assert_eq!(
        u64_at(body_field(&enc, &offsets, "milestone_flags")),
        0b111_000000_111
    );
    assert_eq!(u64_at(body_field(&enc, &offsets, "skipped")), 600_000);

    let mint = body_field(&enc, &offsets, "mint");
    assert_eq!(mint[0], 1, "mint discriminant");
    assert_eq!(&mint[1..33], &MINT);

    assert_eq!(
        u16::from_le_bytes(
            body_field(&enc, &offsets, "fee_bps")
                .try_into()
                .expect("u16 slice")
        ),
        250
    );
    assert_eq!(u64_at(body_field(&enc, &offsets, "fees_paid")), 10_000);
    assert_eq!(u64_at(body_field(&enc, &offsets, "grace_period")), 3600);

    let ev = body_field(&enc, &offsets, "evidence_hash");
    assert_eq!(ev[0], 0, "no evidence attached");
    assert_eq!(&ev[1..33], &[0u8; 32]);

    let r = body_field(&enc, &offsets, "refund_to");
    assert_eq!(r[0], 1, "refund_to discriminant");
    assert_eq!(&r[1..33], &REFUND);

    assert_eq!(
        u16::from_le_bytes(
            body_field(&enc, &offsets, "penalty_bps")
                .try_into()
                .expect("u16 slice")
        ),
        100
    );
    assert_eq!(u64_at(body_field(&enc, &offsets, "timelock")), VEST_START + 1);
    assert_eq!(body_field(&enc, &offsets, "decimals"), &[6u8]);

    // AV-113: the price-gate tail lands on the IDL-computed offset —
    // the last field of the account: 1-byte discriminant + 1-byte
    // direction (0 = AtOrAbove) + 8-byte target + 8-byte staleness
    // bound.
    let pg = body_field(&enc, &offsets, "price_gate");
    assert_eq!(pg.len(), PRICE_GATE_LEN);
    assert_eq!(pg[0], 1, "price_gate discriminant");
    assert_eq!(pg[1], 0, "direction AtOrAbove");
    assert_eq!(u64_at(&pg[2..10]), 100_000, "target");
    assert_eq!(u64_at(&pg[10..18]), 300, "max_staleness_secs");
    let (_, pg_offset, pg_len) = offsets
        .iter()
        .find(|(n, _, _)| *n == "price_gate")
        .copied()
        .expect("price_gate in IDL offsets");
    assert_eq!(pg_len, PRICE_GATE_LEN);
    // AV-115 appended the escalation tail after price_gate, so the
    // gate no longer sits at the body's end. AV-116 appended the
    // slot-timelock tail after the escalation tail. AV-117 appended
    // the compound-interest tail after the slot-timelock tail. AV-119
    // appended the dispute-interest tail after the compound tail.
    // AV-124 appended the keeper-bounty tail after the intent tail,
    // so every earlier tail now sits 16 bytes further from the body's
    // end than at AV-123. AV-126 appended the slash-ladder tail after
    // the keeper-bounty tail, so every earlier tail now sits 115
    // bytes further from the body's end than at AV-124. AV-127
    // appended the 8-byte refunded counter after the slash-ladder
    // tail, so every earlier tail now sits 8 bytes further from the
    // body's end than at AV-126. AV-128 appended the 26-byte TWAP-gate
    // tail after the refunded counter, so every earlier tail now sits
    // a further 26 bytes from the body's end than at AV-127. AV-130
    // appended the 123-byte dual-control tail after the TWAP-gate
    // tail, so every earlier tail now sits a further 123 bytes from
    // the body's end than at AV-128. AV-131 appended the 8-byte
    // disputed-amount tail after the dual-control tail, so every
    // earlier tail now sits a further 8 bytes from the body's end
    // than at AV-130.
    assert_eq!(pg_offset, 8 + ESCROW_BODY_LEN - DISPUTED_AMOUNT_TAIL_LEN - AUTO_UNPAUSE_TAIL_LEN - DUAL_CONTROL_TAIL_LEN - TWAP_GATE_LEN - REFUNDED_TAIL_LEN - SLASH_LADDER_TAIL_LEN - CLAIM_COOLDOWN_TAIL_LEN - COUNTER_OFFER_TAIL_LEN - RELEASE_INTENT_TAIL_LEN - KEEPER_BOUNTY_TAIL_LEN - DISPUTE_INTEREST_LEN - PRICE_GATE_LEN - 4 - SLOT_TIMELOCK_TAIL_LEN - COMPOUND_INTEREST_TAIL_LEN);
    // AV-115: the escalation tail sits just before the AV-116 tail.
    let rate = body_field(&enc, &offsets, "penalty_escalation_rate_bps");
    assert_eq!(rate.len(), 2);
    let (_, rate_offset, _) = offsets
        .iter()
        .find(|(n, _, _)| *n == "penalty_escalation_rate_bps")
        .copied()
        .expect("penalty_escalation_rate_bps in IDL offsets");
    assert_eq!(rate_offset, 8 + ESCROW_BODY_LEN - DISPUTED_AMOUNT_TAIL_LEN - AUTO_UNPAUSE_TAIL_LEN - DUAL_CONTROL_TAIL_LEN - TWAP_GATE_LEN - REFUNDED_TAIL_LEN - SLASH_LADDER_TAIL_LEN - CLAIM_COOLDOWN_TAIL_LEN - COUNTER_OFFER_TAIL_LEN - RELEASE_INTENT_TAIL_LEN - KEEPER_BOUNTY_TAIL_LEN - DISPUTE_INTEREST_LEN - 4 - SLOT_TIMELOCK_TAIL_LEN - COMPOUND_INTEREST_TAIL_LEN);
    let cap = body_field(&enc, &offsets, "penalty_escalation_cap_bps");
    assert_eq!(cap.len(), 2);
    let (_, cap_offset, _) = offsets
        .iter()
        .find(|(n, _, _)| *n == "penalty_escalation_cap_bps")
        .copied()
        .expect("penalty_escalation_cap_bps in IDL offsets");
    assert_eq!(cap_offset, 8 + ESCROW_BODY_LEN - DISPUTED_AMOUNT_TAIL_LEN - AUTO_UNPAUSE_TAIL_LEN - DUAL_CONTROL_TAIL_LEN - TWAP_GATE_LEN - REFUNDED_TAIL_LEN - SLASH_LADDER_TAIL_LEN - CLAIM_COOLDOWN_TAIL_LEN - COUNTER_OFFER_TAIL_LEN - RELEASE_INTENT_TAIL_LEN - KEEPER_BOUNTY_TAIL_LEN - DISPUTE_INTEREST_LEN - 2 - SLOT_TIMELOCK_TAIL_LEN - COMPOUND_INTEREST_TAIL_LEN);
    // AV-116: the slot-timelock tail is the last 16 bytes of the body.
    let slots = body_field(&enc, &offsets, "slot_timelock_slots");
    assert_eq!(slots.len(), 8);
    let (_, slots_offset, _) = offsets
        .iter()
        .find(|(n, _, _)| *n == "slot_timelock_slots")
        .copied()
        .expect("slot_timelock_slots in IDL offsets");
    assert_eq!(slots_offset, 8 + ESCROW_BODY_LEN - DISPUTED_AMOUNT_TAIL_LEN - AUTO_UNPAUSE_TAIL_LEN - DUAL_CONTROL_TAIL_LEN - TWAP_GATE_LEN - REFUNDED_TAIL_LEN - SLASH_LADDER_TAIL_LEN - CLAIM_COOLDOWN_TAIL_LEN - COUNTER_OFFER_TAIL_LEN - RELEASE_INTENT_TAIL_LEN - KEEPER_BOUNTY_TAIL_LEN - DISPUTE_INTEREST_LEN - COMPOUND_INTEREST_TAIL_LEN - SLOT_TIMELOCK_TAIL_LEN);
    let fslot = body_field(&enc, &offsets, "fund_slot");
    assert_eq!(fslot.len(), 8);
    let (_, fslot_offset, _) = offsets
        .iter()
        .find(|(n, _, _)| *n == "fund_slot")
        .copied()
        .expect("fund_slot in IDL offsets");
    assert_eq!(fslot_offset, 8 + ESCROW_BODY_LEN - DISPUTED_AMOUNT_TAIL_LEN - AUTO_UNPAUSE_TAIL_LEN - DUAL_CONTROL_TAIL_LEN - TWAP_GATE_LEN - REFUNDED_TAIL_LEN - SLASH_LADDER_TAIL_LEN - CLAIM_COOLDOWN_TAIL_LEN - COUNTER_OFFER_TAIL_LEN - RELEASE_INTENT_TAIL_LEN - KEEPER_BOUNTY_TAIL_LEN - DISPUTE_INTEREST_LEN - COMPOUND_INTEREST_TAIL_LEN - 8);
    // AV-117: the compound-interest tail sits just before the AV-119
    // dispute-interest tail (the absolute tail).
    let (_, ci_offset, _) = offsets
        .iter()
        .find(|(n, _, _)| *n == "compound_interest")
        .copied()
        .expect("compound_interest in IDL offsets");
    assert_eq!(ci_offset, 8 + ESCROW_BODY_LEN - DISPUTED_AMOUNT_TAIL_LEN - AUTO_UNPAUSE_TAIL_LEN - DUAL_CONTROL_TAIL_LEN - TWAP_GATE_LEN - REFUNDED_TAIL_LEN - SLASH_LADDER_TAIL_LEN - CLAIM_COOLDOWN_TAIL_LEN - COUNTER_OFFER_TAIL_LEN - RELEASE_INTENT_TAIL_LEN - KEEPER_BOUNTY_TAIL_LEN - DISPUTE_INTEREST_LEN - COMPOUND_INTEREST_TAIL_LEN);
    let (_, ic_offset, _) = offsets
        .iter()
        .find(|(n, _, _)| *n == "interest_compounded")
        .copied()
        .expect("interest_compounded in IDL offsets");
    assert_eq!(ic_offset, 8 + ESCROW_BODY_LEN - DISPUTED_AMOUNT_TAIL_LEN - AUTO_UNPAUSE_TAIL_LEN - DUAL_CONTROL_TAIL_LEN - TWAP_GATE_LEN - REFUNDED_TAIL_LEN - SLASH_LADDER_TAIL_LEN - CLAIM_COOLDOWN_TAIL_LEN - COUNTER_OFFER_TAIL_LEN - RELEASE_INTENT_TAIL_LEN - KEEPER_BOUNTY_TAIL_LEN - DISPUTE_INTEREST_LEN - 8);
    // AV-119: the dispute-interest tail (no longer the absolute
    // tail since AV-121).
    let di = body_field(&enc, &offsets, "dispute_interest");
    assert_eq!(di.len(), 8);
    let (_, di_offset, _) = offsets
        .iter()
        .find(|(n, _, _)| *n == "dispute_interest")
        .copied()
        .expect("dispute_interest in IDL offsets");
    assert_eq!(di_offset, 8 + ESCROW_BODY_LEN - DISPUTED_AMOUNT_TAIL_LEN - AUTO_UNPAUSE_TAIL_LEN - DUAL_CONTROL_TAIL_LEN - TWAP_GATE_LEN - REFUNDED_TAIL_LEN - SLASH_LADDER_TAIL_LEN - CLAIM_COOLDOWN_TAIL_LEN - COUNTER_OFFER_TAIL_LEN - RELEASE_INTENT_TAIL_LEN - KEEPER_BOUNTY_TAIL_LEN - DISPUTE_INTEREST_LEN);
    // AV-121: the claim-cooldown tail (no longer the absolute tail
    // since AV-122) — the 8-byte opt-in duration plus the 9-byte
    // last-claim slot anchor.
    let ccd = body_field(&enc, &offsets, "claim_cooldown_slots");
    assert_eq!(ccd.len(), 8);
    let (_, ccd_offset, _) = offsets
        .iter()
        .find(|(n, _, _)| *n == "claim_cooldown_slots")
        .copied()
        .expect("claim_cooldown_slots in IDL offsets");
    assert_eq!(ccd_offset, 8 + ESCROW_BODY_LEN - DISPUTED_AMOUNT_TAIL_LEN - AUTO_UNPAUSE_TAIL_LEN - DUAL_CONTROL_TAIL_LEN - TWAP_GATE_LEN - REFUNDED_TAIL_LEN - SLASH_LADDER_TAIL_LEN - CLAIM_COOLDOWN_TAIL_LEN - COUNTER_OFFER_TAIL_LEN - RELEASE_INTENT_TAIL_LEN - KEEPER_BOUNTY_TAIL_LEN);
    let lcs = body_field(&enc, &offsets, "last_claim_slot");
    assert_eq!(lcs.len(), 9);
    let (_, lcs_offset, _) = offsets
        .iter()
        .find(|(n, _, _)| *n == "last_claim_slot")
        .copied()
        .expect("last_claim_slot in IDL offsets");
    assert_eq!(lcs_offset, 8 + ESCROW_BODY_LEN - DISPUTED_AMOUNT_TAIL_LEN - AUTO_UNPAUSE_TAIL_LEN - DUAL_CONTROL_TAIL_LEN - TWAP_GATE_LEN - REFUNDED_TAIL_LEN - SLASH_LADDER_TAIL_LEN - CLAIM_COOLDOWN_TAIL_LEN - COUNTER_OFFER_TAIL_LEN - RELEASE_INTENT_TAIL_LEN - KEEPER_BOUNTY_TAIL_LEN + 8);
    // AV-122: the counter-offer tail — the 1-byte `Option`
    // discriminant plus the 16-byte live terms — trails the AV-121
    // claim-cooldown tail (AV-124: the keeper-bounty tail is the new
    // absolute tail).
    let co = body_field(&enc, &offsets, "counter_offer");
    assert_eq!(co.len(), 17);
    let (_, co_offset, _) = offsets
        .iter()
        .find(|(n, _, _)| *n == "counter_offer")
        .copied()
        .expect("counter_offer in IDL offsets");
    assert_eq!(co_offset, 8 + ESCROW_BODY_LEN - DISPUTED_AMOUNT_TAIL_LEN - AUTO_UNPAUSE_TAIL_LEN - DUAL_CONTROL_TAIL_LEN - TWAP_GATE_LEN - REFUNDED_TAIL_LEN - SLASH_LADDER_TAIL_LEN - COUNTER_OFFER_TAIL_LEN - RELEASE_INTENT_TAIL_LEN - KEEPER_BOUNTY_TAIL_LEN);
    // AV-127: the refunded counter is the last 8 bytes of the body.
    let rf = body_field(&enc, &offsets, "refunded");
    assert_eq!(rf.len(), 8);
    let (_, rf_offset, _) = offsets
        .iter()
        .find(|(n, _, _)| *n == "refunded")
        .copied()
        .expect("refunded in IDL offsets");
    assert_eq!(rf_offset, 8 + ESCROW_BODY_LEN - DISPUTED_AMOUNT_TAIL_LEN - AUTO_UNPAUSE_TAIL_LEN - DUAL_CONTROL_TAIL_LEN - TWAP_GATE_LEN - REFUNDED_TAIL_LEN);
    assert_eq!(u64_at(rf), 0, "no partial refund on the max-config escrow");
}

#[test]
fn idl_field_offsets_pin_dispute_path() {
    // The dispute path exercises the tail fields the funded path leaves
    // zeroed: evidence_hash persisted on escalate, rationale_hash
    // persisted on resolve, Disputed/Settled discriminants through
    // resolve.
    const RATIONALE: [u8; 32] = [0xA1; 32];
    let mut e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT).unwrap();
    e = e.with_arbiter(ARB).unwrap();
    e.fund(ALICE, EXPIRES_AT - 3_600).unwrap();
    e.escalate(BOB, EXPIRES_AT - 100, e.remaining_amount(), Some(EVIDENCE), None, 0).unwrap();

    let enc = encode_escrow(&e);
    let offsets = vault_field_offsets();
    assert_eq!(body_field(&enc, &offsets, "state"), &[5u8]); // Disputed
    let ev = body_field(&enc, &offsets, "evidence_hash");
    assert_eq!(ev[0], 1, "evidence discriminant");
    assert_eq!(&ev[1..33], &EVIDENCE);

    let (payout, fee, refund) = e.resolve(ARB, 300_000, EXPIRES_AT - 100, None, Some(RATIONALE), BOB).unwrap();
    assert_eq!((payout, fee, refund), (300_000, 0, 700_000));
    let enc = encode_escrow(&e);
    assert_eq!(body_field(&enc, &offsets, "state"), &[6u8]); // Settled
    // Evidence survives settlement: the audit trail is never cleared.
    let ev = body_field(&enc, &offsets, "evidence_hash");
    assert_eq!(&ev[1..33], &EVIDENCE);
    // AV-38: the rationale hash lands on the IDL-computed tail offset —
    // no longer the last field of the account (AV-55 appends the
    // dispute timestamp + default judgment + confirmation bit after
    // it) — and earlier offsets are stable. AV-51 shifts the
    // post-vesting offsets +8 (8-byte discriminator + 687-byte body
    // prefix: the vesting schedule grew by cliff_at).
    let rh = body_field(&enc, &offsets, "rationale_hash");
    assert_eq!(rh[0], 1, "rationale discriminant");
    assert_eq!(&rh[1..33], &RATIONALE);
    let (_, rh_offset, rh_len) = offsets
        .iter()
        .find(|(n, _, _)| *n == "rationale_hash")
        .copied()
        .expect("rationale_hash in IDL offsets");
    assert_eq!((rh_offset, rh_len), (704, 33));
    assert_eq!(u64_at(body_field(&enc, &offsets, "released")), 300_000);
    // AV-55: the new tail fields land on the IDL-computed offsets after
    // `reference` (body offsets 960/968/985; +8 for the account-data
    // offsets below). The dispute timestamp was recorded by `escalate`
    // above; no default judgment is configured on this escrow.
    let (_, da_offset, da_len) = offsets
        .iter()
        .find(|(n, _, _)| *n == "disputed_at")
        .copied()
        .expect("disputed_at in IDL offsets");
    assert_eq!((da_offset, da_len), (968, 8));
    assert_eq!(
        u64_at(body_field(&enc, &offsets, "disputed_at")),
        EXPIRES_AT - 100,
        "escalate recorded the dispute timestamp"
    );
    let (_, dj_offset, dj_len) = offsets
        .iter()
        .find(|(n, _, _)| *n == "default_judgment")
        .copied()
        .expect("default_judgment in IDL offsets");
    assert_eq!((dj_offset, dj_len), (976, 17));
    let dj = body_field(&enc, &offsets, "default_judgment");
    assert_eq!(dj[0], 0, "default_judgment: None discriminant");
    assert_eq!(&dj[1..17], &[0u8; 16], "default_judgment: zeroed");
    let (_, dc_offset, dc_len) = offsets
        .iter()
        .find(|(n, _, _)| *n == "default_confirmed")
        .copied()
        .expect("default_confirmed in IDL offsets");
    assert_eq!((dc_offset, dc_len), (993, 1));
    assert_eq!(
        body_field(&enc, &offsets, "default_confirmed"),
        &[0u8],
        "default_confirmed: zeroed"
    );
}
