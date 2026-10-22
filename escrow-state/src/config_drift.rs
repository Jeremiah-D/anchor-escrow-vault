//! Chain-off vault configuration drift detection (AV-175 — Solana
//! ops / backend engineering).
//!
//! A vault's *operational* configuration — fee rate, fee schedule, fee
//! cap, fee recipient, payout allowlist, quorum threshold, bound mint,
//! timelocks — is fixed at `initialize` time and lives in the vault
//! account. Operators roll out fleets of vaults from one approved
//! configuration; a vault whose on-chain config no longer matches the
//! approved template is either mis-provisioned or was tampered with,
//! and should never be funded.
//!
//! This module decodes the on-chain config (via
//! [`decode_vault_account`](crate::decode_vault_account) — the
//! [`vault_view`](crate::vault_view) convention) and diffs it field by
//! field against an [`ExpectedVaultConfig`] template, producing a
//! per-field drift report (`{field, expected, actual}`).
//!
//! Relationship to AV-143
//! ([`template_library`](crate::template_library)): the template library
//! is a registry of blueprints for *instantiating new* escrows. This
//! module is the other side of the lifecycle: it monitors *deployed*
//! vaults' on-chain configuration for drift away from the approved
//! template. The two are orthogonal — a blueprint version pins what a
//! vault *should* look like; this scan reports what it *does* look
//! like.
//!
//! Relationship to AV-29 (IDL byte-layout pipeline): AV-29 guards the
//! *byte* layout (field offsets, discriminators). This module guards the
//! *operational* config values. A byte-layout drift breaks decoding; a
//! config drift breaks the operator's policy. Both are keeper-side,
//! dry-run, zero-side-effect scans.
//!
//! Pure and dependency-free: decoding reads bytes, diffing reads the
//! decoded [`Escrow`](crate::Escrow) — no mutation, no clock, no I/O.
//! The keeper entry point is
//! [`scan_config_drift`](crate::scan_config_drift).

use crate::{
    decode_vault_account, AccountDecodeError, Escrow, FeeSchedule, PayoutAllowlist,
};

/// Render 32 bytes as 64 lowercase hex characters (the keeper-report
/// convention — deterministic field order, lowercase hex keys).
fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes.iter() {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// The operator-approved vault configuration template (AV-175).
///
/// Every field is compared against the matching on-chain value; any
/// mismatch is a drift. `None` means "this feature must be absent"
/// (e.g. `fee_recipient: None` requires no pinned recipient).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedVaultConfig {
    /// Flat protocol-fee rate in basis points (`Escrow::fee_bps`).
    pub fee_bps: u16,
    /// Tiered fee schedule (`Escrow::fee_schedule`); `Default`
    /// (zero tiers) means no schedule.
    pub fee_schedule: FeeSchedule,
    /// Absolute per-payout fee ceiling (`Escrow::fee_cap`).
    pub fee_cap: u64,
    /// Pinned protocol-fee recipient (`Escrow::fee_recipient`).
    pub fee_recipient: Option<[u8; 32]>,
    /// Payout destination allowlist (`Escrow::payout_allowlist`).
    pub payout_allowlist: Option<PayoutAllowlist>,
    /// Quorum weight-sum threshold (`QuorumPolicy::threshold`);
    /// `None` means no quorum must be configured.
    pub quorum_threshold: Option<u64>,
    /// Bound SPL mint (`Escrow::mint`).
    pub mint: Option<[u8; 32]>,
    /// Timelock unlock timestamp (`Escrow::unlock_at`); `0` = none.
    pub timelock: u64,
    /// Relative timelock in seconds
    /// (`Escrow::relative_timelock_secs`); `0` = none.
    pub relative_timelock_secs: u64,
}

impl Default for ExpectedVaultConfig {
    fn default() -> Self {
        Self {
            fee_bps: 0,
            fee_schedule: FeeSchedule::default(),
            fee_cap: 0,
            fee_recipient: None,
            payout_allowlist: None,
            quorum_threshold: None,
            mint: None,
            timelock: 0,
            relative_timelock_secs: 0,
        }
    }
}

/// The on-chain configuration snapshot decoded from a vault account
/// (AV-175). Same shape as [`ExpectedVaultConfig`], minus the
/// template-vs-actual distinction — the diff is a pure field-by-field
/// comparison of the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultConfig {
    /// Flat protocol-fee rate in basis points.
    pub fee_bps: u16,
    /// Tiered fee schedule.
    pub fee_schedule: FeeSchedule,
    /// Absolute per-payout fee ceiling.
    pub fee_cap: u64,
    /// Pinned protocol-fee recipient.
    pub fee_recipient: Option<[u8; 32]>,
    /// Payout destination allowlist.
    pub payout_allowlist: Option<PayoutAllowlist>,
    /// Quorum weight-sum threshold; `None` when no quorum configured.
    pub quorum_threshold: Option<u64>,
    /// Bound SPL mint.
    pub mint: Option<[u8; 32]>,
    /// Timelock unlock timestamp; `0` = none.
    pub timelock: u64,
    /// Relative timelock in seconds; `0` = none.
    pub relative_timelock_secs: u64,
}

impl VaultConfig {
    /// Snapshot the operational config of a decoded escrow (AV-175).
    /// Pure read — the escrow is untouched.
    pub fn from_escrow(e: &Escrow) -> Self {
        Self {
            fee_bps: e.fee_bps(),
            fee_schedule: e.fee_schedule(),
            fee_cap: e.fee_cap(),
            fee_recipient: e.fee_recipient(),
            payout_allowlist: e.payout_allowlist(),
            quorum_threshold: e.quorum().map(|q| q.threshold()),
            mint: e.mint(),
            timelock: e.unlock_at(),
            relative_timelock_secs: e.relative_timelock_secs(),
        }
    }
}

/// Decode failures when reading a vault account's config (AV-175).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigDriftError {
    /// The bytes are not a decodable `Vault` account — truncated,
    /// overlong, wrong discriminator, or an unknown state byte. The
    /// inner error names the cause; a vault that cannot be decoded
    /// cannot be drift-checked.
    Undecodable(AccountDecodeError),
}

impl core::fmt::Display for ConfigDriftError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigDriftError::Undecodable(e) => {
                write!(f, "vault account not decodable: {e:?}")
            }
        }
    }
}

impl std::error::Error for ConfigDriftError {}

/// Decode a raw vault account's operational config (AV-175): the
/// [`vault_view`](crate::vault_view) convention — structural decode via
/// [`decode_vault_account`](crate::decode_vault_account), then snapshot
/// the config fields. Rejects undecodable bytes instead of guessing.
pub fn decode_vault_config(data: &[u8]) -> Result<VaultConfig, ConfigDriftError> {
    let escrow = decode_vault_account(data).map_err(ConfigDriftError::Undecodable)?;
    Ok(VaultConfig::from_escrow(&escrow))
}

/// One drifted field: `{field, expected, actual}` (AV-175). Values are
/// canonical strings — decimal for integers, 64-char lowercase hex for
/// pubkeys, `"none"` for absent optionals — so the JSON report is
/// deterministic without a serializer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDrift {
    /// The config field name, e.g. `"fee_bps"`.
    pub field: &'static str,
    /// The template's value, canonically rendered.
    pub expected: String,
    /// The on-chain value, canonically rendered.
    pub actual: String,
}

fn fmt_fee_schedule(s: &FeeSchedule) -> String {
    if !s.is_configured() {
        return "none".to_string();
    }
    let mut out = String::from("tiers[");
    for (i, t) in s.tiers[..s.tier_count as usize].iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("min_amount={} bps={}", t.min_amount, t.bps));
    }
    out.push(']');
    out
}

fn fmt_allowlist(a: &Option<PayoutAllowlist>) -> String {
    match a {
        None => "none".to_string(),
        Some(list) => {
            let mut out = String::from("addrs[");
            for (i, addr) in list.addrs[..list.len as usize].iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&hex32(addr));
            }
            out.push(']');
            out
        }
    }
}

fn fmt_opt_hex(v: &Option<[u8; 32]>) -> String {
    match v {
        None => "none".to_string(),
        Some(b) => hex32(b),
    }
}

/// Diff an on-chain config against the expected template (AV-175).
/// Returns one [`FieldDrift`] per mismatched field, in fixed field
/// order (the [`ExpectedVaultConfig`] declaration order) — deterministic
/// regardless of which fields drift. Empty means no drift.
pub fn diff_config(actual: &VaultConfig, expected: &ExpectedVaultConfig) -> Vec<FieldDrift> {
    let mut drifts = Vec::new();
    let mut push = |field: &'static str, expected: String, actual: String| {
        if expected != actual {
            drifts.push(FieldDrift {
                field,
                expected,
                actual,
            });
        }
    };
    push(
        "fee_bps",
        expected.fee_bps.to_string(),
        actual.fee_bps.to_string(),
    );
    push(
        "fee_schedule",
        fmt_fee_schedule(&expected.fee_schedule),
        fmt_fee_schedule(&actual.fee_schedule),
    );
    push(
        "fee_cap",
        expected.fee_cap.to_string(),
        actual.fee_cap.to_string(),
    );
    push(
        "fee_recipient",
        fmt_opt_hex(&expected.fee_recipient),
        fmt_opt_hex(&actual.fee_recipient),
    );
    push(
        "payout_allowlist",
        fmt_allowlist(&expected.payout_allowlist),
        fmt_allowlist(&actual.payout_allowlist),
    );
    push(
        "quorum_threshold",
        expected
            .quorum_threshold
            .map(|t| t.to_string())
            .unwrap_or_else(|| "none".to_string()),
        actual
            .quorum_threshold
            .map(|t| t.to_string())
            .unwrap_or_else(|| "none".to_string()),
    );
    push("mint", fmt_opt_hex(&expected.mint), fmt_opt_hex(&actual.mint));
    push(
        "timelock",
        expected.timelock.to_string(),
        actual.timelock.to_string(),
    );
    push(
        "relative_timelock_secs",
        expected.relative_timelock_secs.to_string(),
        actual.relative_timelock_secs.to_string(),
    );
    drifts
}

/// One drifted vault in a [`ConfigDriftReport`] (AV-175).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultDrift {
    /// Caller-supplied 32-byte escrow identity (see
    /// `WatchedEscrow::escrow_id`).
    pub escrow_id: [u8; 32],
    /// The drifted fields, in fixed field order.
    pub drifts: Vec<FieldDrift>,
}

/// The read-only result of a config-drift scan (AV-175).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDriftReport {
    /// Every watched vault with at least one drifted field, sorted by
    /// `escrow_id` ascending (deterministic).
    pub vaults: Vec<VaultDrift>,
    /// Total drifted fields across all listed vaults.
    pub total_drifts: u64,
}

impl ConfigDriftReport {
    /// Hand-serialized JSON (the crate stays dependency-free; keys are
    /// 64-char lowercase hex; fixed field order):
    /// `{"scanned":N,"drifted":M,"vaults":[{"escrow_id":"…","drifts":[` \
    /// `{"field":"…","expected":"…","actual":"…"}]}],"total_drifts":K}`.
    pub fn to_json(&self, scanned: usize) -> String {
        let mut s = String::with_capacity(64 + self.vaults.len() * 200);
        s.push_str("{\"scanned\":");
        s.push_str(&scanned.to_string());
        s.push_str(",\"drifted\":");
        s.push_str(&self.vaults.len().to_string());
        s.push_str(",\"vaults\":[");
        for (i, v) in self.vaults.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"escrow_id\":\"");
            s.push_str(&hex32(&v.escrow_id));
            s.push_str("\",\"drifts\":[");
            for (j, d) in v.drifts.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                s.push_str("{\"field\":\"");
                s.push_str(d.field);
                s.push_str("\",\"expected\":\"");
                s.push_str(&d.expected);
                s.push_str("\",\"actual\":\"");
                s.push_str(&d.actual);
                s.push_str("\"}");
            }
            s.push_str("]}");
        }
        s.push_str("],\"total_drifts\":");
        s.push_str(&self.total_drifts.to_string());
        s.push('}');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account_space_tests::encode_escrow, vault_account_discriminator, QuorumPolicy,
    };

    const ALICE: [u8; 32] = [0xAA; 32];
    const BOB: [u8; 32] = [0xBB; 32];
    const FEE_RECIPIENT: [u8; 32] = [0xFE; 32];
    const MINT: [u8; 32] = [0xD0; 32];
    const EXPIRES_AT: u64 = 1_800_000_000;

    fn configured_escrow() -> Escrow {
        // A fully-configured escrow: every drift-checked field set.
        // Note: with_protocol_fee and with_fee_schedule are mutually
        // exclusive (InvalidProtocolFee) — the schedule replaces the
        // flat rate, so fee_bps stays 0 here.
        let e = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_fee_schedule(&[(0, 250), (1_000_000, 100)])
            .unwrap()
            .with_fee_cap(50_000)
            .unwrap()
            .with_fee_recipient(FEE_RECIPIENT)
            .unwrap()
            .with_payout_allowlist(&[BOB])
            .unwrap()
            .with_mint(MINT)
            .unwrap()
            // Note: with_timelock and with_relative_timelock are
            // mutually exclusive (InvalidTimelock) — one clock per
            // escrow. The absolute timelock is covered by a dedicated
            // escrow in the timelock drift test below.
            .with_relative_timelock(7_200)
            .unwrap();
        let policy = QuorumPolicy::new(&[ALICE, BOB], &[1, 1], 2).unwrap();
        let e = e.with_quorum(policy).unwrap();
        e
    }

    fn template_for(e: &Escrow) -> ExpectedVaultConfig {
        let c = VaultConfig::from_escrow(e);
        ExpectedVaultConfig {
            fee_bps: c.fee_bps,
            fee_schedule: c.fee_schedule,
            fee_cap: c.fee_cap,
            fee_recipient: c.fee_recipient,
            payout_allowlist: c.payout_allowlist,
            quorum_threshold: c.quorum_threshold,
            mint: c.mint,
            timelock: c.timelock,
            relative_timelock_secs: c.relative_timelock_secs,
        }
    }

    fn vault_bytes(e: &Escrow) -> Vec<u8> {
        let mut out = vault_account_discriminator().to_vec();
        out.extend_from_slice(&encode_escrow(e));
        out
    }

    #[test]
    fn no_drift_when_config_matches_template() {
        let e = configured_escrow();
        let expected = template_for(&e);
        let actual = VaultConfig::from_escrow(&e);
        assert!(diff_config(&actual, &expected).is_empty());
    }

    #[test]
    fn each_field_drift_is_reported() {
        let e = configured_escrow();
        let base = template_for(&e);
        let actual = VaultConfig::from_escrow(&e);

        // fee_bps
        let mut t = base;
        t.fee_bps = 999;
        let d = diff_config(&actual, &t);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "fee_bps");
        assert_eq!(d[0].expected, "999");
        assert_eq!(d[0].actual, "0");

        // fee_cap
        let mut t = base;
        t.fee_cap = 1;
        let d = diff_config(&actual, &t);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "fee_cap");

        // fee_recipient: pinned vs none
        let mut t = base;
        t.fee_recipient = None;
        let d = diff_config(&actual, &t);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "fee_recipient");
        assert_eq!(d[0].expected, "none");
        assert_eq!(d[0].actual, hex32(&FEE_RECIPIENT));

        // quorum_threshold
        let mut t = base;
        t.quorum_threshold = Some(1);
        let d = diff_config(&actual, &t);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "quorum_threshold");
        assert_eq!(d[0].expected, "1");
        assert_eq!(d[0].actual, "2");

        // mint
        let mut t = base;
        t.mint = None;
        let d = diff_config(&actual, &t);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "mint");

        // timelock (absolute): a dedicated escrow, since the two
        // clocks are mutually exclusive builders.
        let e2 = Escrow::initialize(ALICE, BOB, 1_000_000, EXPIRES_AT)
            .unwrap()
            .with_timelock(EXPIRES_AT - 3_600)
            .unwrap();
        let actual2 = VaultConfig::from_escrow(&e2);
        let d = diff_config(&actual2, &ExpectedVaultConfig::default());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "timelock");
        assert_eq!(d[0].expected, "0");
        assert_eq!(d[0].actual, (EXPIRES_AT - 3_600).to_string());

        // relative_timelock_secs
        let mut t = base;
        t.relative_timelock_secs = 3_600;
        let d = diff_config(&actual, &t);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].field, "relative_timelock_secs");
        assert_eq!(d[0].expected, "3600");
        assert_eq!(d[0].actual, "7200");
    }

    #[test]
    fn fee_schedule_and_allowlist_drifts_render_canonically() {
        let e = configured_escrow();
        let actual = VaultConfig::from_escrow(&e);
        let mut t = template_for(&e);
        t.fee_schedule = FeeSchedule::default();
        t.payout_allowlist = None;
        let d = diff_config(&actual, &t);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].field, "fee_schedule");
        assert_eq!(d[0].expected, "none");
        assert!(d[0].actual.starts_with("tiers["));
        assert!(d[0].actual.contains("min_amount=0 bps=250"));
        assert!(d[0].actual.contains("min_amount=1000000 bps=100"));
        assert_eq!(d[1].field, "payout_allowlist");
        assert_eq!(d[1].expected, "none");
        assert!(d[1].actual.starts_with("addrs["));
    }

    #[test]
    fn drift_fields_come_in_fixed_order() {
        let e = configured_escrow();
        let actual = VaultConfig::from_escrow(&e);
        // Drift everything settable together: the report order must
        // follow the template declaration order, not the mutation
        // order. (The fixture escrow uses the fee schedule instead of
        // the flat fee_bps, and the relative instead of the absolute
        // timelock — the two pairs are mutually exclusive builders —
        // so fee_bps and timelock match the default template here and
        // do not drift; both are covered individually above.)
        let t = ExpectedVaultConfig::default();
        let d = diff_config(&actual, &t);
        let fields: Vec<&str> = d.iter().map(|x| x.field).collect();
        assert_eq!(
            fields,
            vec![
                "fee_schedule",
                "fee_cap",
                "fee_recipient",
                "payout_allowlist",
                "quorum_threshold",
                "mint",
                "relative_timelock_secs",
            ]
        );
    }

    #[test]
    fn decode_vault_config_round_trips_through_account_bytes() {
        let e = configured_escrow();
        let decoded = decode_vault_config(&vault_bytes(&e)).unwrap();
        assert_eq!(decoded, VaultConfig::from_escrow(&e));
        // And the decoded config matches its own template: no drift.
        assert!(diff_config(&decoded, &template_for(&e)).is_empty());
    }

    #[test]
    fn decode_rejects_undecodable_bytes() {
        // Truncated.
        assert!(matches!(
            decode_vault_config(&[0u8; 16]),
            Err(ConfigDriftError::Undecodable(_))
        ));
        // Wrong discriminator.
        let mut bad = vault_bytes(&configured_escrow());
        bad[0] ^= 0xFF;
        assert!(matches!(
            decode_vault_config(&bad),
            Err(ConfigDriftError::Undecodable(
                AccountDecodeError::BadDiscriminator { .. }
            ))
        ));
        // Overlong.
        let mut over = vault_bytes(&configured_escrow());
        over.push(0);
        assert!(matches!(
            decode_vault_config(&over),
            Err(ConfigDriftError::Undecodable(
                AccountDecodeError::Overlong { .. }
            ))
        ));
    }

    #[test]
    fn report_json_is_deterministic() {
        let e = configured_escrow();
        let actual = VaultConfig::from_escrow(&e);
        let mut t = template_for(&e);
        t.fee_bps = 999;
        let drifts = diff_config(&actual, &t);
        let report = ConfigDriftReport {
            vaults: vec![VaultDrift {
                escrow_id: [0x01; 32],
                drifts,
            }],
            total_drifts: 1,
        };
        let json = report.to_json(4);
        assert!(json.starts_with("{\"scanned\":4,\"drifted\":1,\"vaults\":[{\"escrow_id\":\""));
        assert!(json.contains("\"field\":\"fee_bps\",\"expected\":\"999\",\"actual\":\"0\""));
        assert!(json.ends_with("],\"total_drifts\":1}"));
        // Byte-identical on re-render.
        assert_eq!(json, report.to_json(4));
    }

    #[test]
    fn display_impls_are_human_readable() {
        let err = ConfigDriftError::Undecodable(AccountDecodeError::Truncated {
            expected: 6907,
            got: 3,
        });
        let msg = format!("{err}");
        assert!(msg.contains("not decodable"), "unexpected: {msg}");
    }
}
