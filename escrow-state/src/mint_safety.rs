//! AV-184: Token-2022 extension safety gate.
//!
//! Before `initialize` / `fund`, the initializer reads the SPL mint account
//! and runs its Token-2022 extensions through this gate. Some extensions
//! are escrow-hostile and fail the gate *closed* — the escrow must not be
//! created on such a mint:
//!
//! - `DefaultAccountState::Frozen` — every taker token account lands
//!   frozen; the payout can never move without the mint's freeze authority.
//! - `NonTransferable` — the taker can never move the payout at all.
//! - a 100% `TransferFeeConfig` — every transfer is fully confiscated as
//!   fee (a partial fee is tolerated and merely reported).
//! - an *undisclosed* `PermanentDelegate` — the delegate can burn or
//!   force-transfer escrowed funds at will. A delegate the initializer
//!   disclosed out of band (e.g. in the escrow terms) is accepted.
//!
//! Extensions that are safe for escrow are recorded but never deny:
//! `ConfidentialTransfer` (transfer modeling lives in
//! [`crate::confidential`] instruction 8 — orthogonal to this gate) and
//! `TransferHook` (hook execution modeled in [`crate::cpi`] — orthogonal).
//!
//! This crate is pure logic: the descriptor is caller-observed mint state
//! (the Anchor program reads the mint account). The check itself never
//! fails — it returns a [`MintSafetyReport`]; the fail-closed decision is
//! [`MintSafetyReport::require_allowed`] / [`Escrow::check_mint_safety`].
//! Every check result renders as an audit-event JSON record
//! ([`MintSafetyReport::audit_json`], hand-written like
//! `bundle_relay`'s lifecycle events) so indexers see the gate decision.

use crate::Escrow;
use crate::EscrowError;

/// Caller-observed Token-2022 extension state of a mint, read from the mint
/// account before `initialize` / `fund`. `Copy` and heap-free like the
/// rest of the state machine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MintExtensionDescriptor {
    /// The mint being checked (binds the report to the mint).
    pub mint: [u8; 32],
    /// The mint carries the `DefaultAccountState` extension set to `Frozen`.
    pub default_account_state_frozen: bool,
    /// The mint carries the `NonTransferable` extension.
    pub non_transferable: bool,
    /// The mint carries the `TransferFeeConfig` extension with this fee in
    /// basis points (`0..=10_000`). `None` = extension absent.
    pub transfer_fee_bps: Option<u16>,
    /// The mint carries the `PermanentDelegate` extension with this
    /// delegate. `None` = extension absent.
    pub permanent_delegate: Option<[u8; 32]>,
    /// The initializer disclosed the permanent delegate out of band (e.g.
    /// in the escrow terms). An undisclosed delegate is a fail-closed
    /// denial.
    pub permanent_delegate_disclosed: bool,
    /// The mint carries the `ConfidentialTransfer` extension (allowed;
    /// modeled by [`crate::confidential`], orthogonal to this gate).
    pub confidential_transfer: bool,
    /// The mint carries the `TransferHook` extension (allowed; hook
    /// execution modeled by [`crate::cpi`], orthogonal to this gate).
    pub transfer_hook: bool,
}

/// One escrow-hostile extension found on the mint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintSafetyFinding {
    /// `DefaultAccountState::Frozen` — taker accounts land frozen.
    DefaultAccountStateFrozen,
    /// `NonTransferable` — the payout can never move.
    NonTransferable,
    /// A 100% `TransferFeeConfig` — every transfer is confiscated.
    ConfiscatoryTransferFee { bps: u16 },
    /// A `PermanentDelegate` the initializer did not disclose.
    UndisclosedPermanentDelegate,
}

impl MintSafetyFinding {
    /// Stable snake_case name for audit JSON.
    pub fn name(&self) -> &'static str {
        match self {
            MintSafetyFinding::DefaultAccountStateFrozen => "default_account_state_frozen",
            MintSafetyFinding::NonTransferable => "non_transferable",
            MintSafetyFinding::ConfiscatoryTransferFee { .. } => "confiscatory_transfer_fee",
            MintSafetyFinding::UndisclosedPermanentDelegate => "undisclosed_permanent_delegate",
        }
    }
}

/// Fail-closed denial for [`check_mint_safety`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintSafetyError {
    /// `DefaultAccountState::Frozen` on the mint.
    DefaultAccountStateFrozen,
    /// `NonTransferable` on the mint.
    NonTransferable,
    /// A 100% `TransferFeeConfig` on the mint.
    ConfiscatoryTransferFee { bps: u16 },
    /// A `PermanentDelegate` the initializer did not disclose.
    UndisclosedPermanentDelegate,
}

impl From<MintSafetyFinding> for MintSafetyError {
    fn from(f: MintSafetyFinding) -> Self {
        match f {
            MintSafetyFinding::DefaultAccountStateFrozen => {
                MintSafetyError::DefaultAccountStateFrozen
            }
            MintSafetyFinding::NonTransferable => MintSafetyError::NonTransferable,
            MintSafetyFinding::ConfiscatoryTransferFee { bps } => {
                MintSafetyError::ConfiscatoryTransferFee { bps }
            }
            MintSafetyFinding::UndisclosedPermanentDelegate => {
                MintSafetyError::UndisclosedPermanentDelegate
            }
        }
    }
}

/// The outcome of [`check_mint_safety`]: every hostile extension found (in
/// check order), or none. Never fails — denial is explicit via
/// [`MintSafetyReport::denied`] / [`MintSafetyReport::require_allowed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MintSafetyReport {
    mint: [u8; 32],
    findings: [Option<MintSafetyFinding>; 4],
    finding_count: u8,
}

impl MintSafetyReport {
    /// The mint this report covers.
    pub fn mint(&self) -> [u8; 32] {
        self.mint
    }

    /// `true` when no hostile extension was found.
    pub fn allowed(&self) -> bool {
        self.finding_count == 0
    }

    /// Iterator over findings in check order.
    pub fn findings_iter(&self) -> impl Iterator<Item = MintSafetyFinding> + '_ {
        self.findings
            .iter()
            .take(self.finding_count as usize)
            .filter_map(|f| *f)
    }

    /// The first denial (check order), or `None` when allowed.
    pub fn denied(&self) -> Option<MintSafetyError> {
        self.findings_iter().next().map(MintSafetyError::from)
    }

    /// Fail-closed: `Ok(())` when allowed, the first denial otherwise.
    pub fn require_allowed(&self) -> Result<(), MintSafetyError> {
        match self.denied() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Audit-event JSON for the check result. Hand-written (string fields
    /// are JSON-escaped by construction — names are fixed alphabets, the
    /// mint is hex), mirroring `bundle_relay`'s lifecycle events:
    /// `{"event":"mint_safety_checked","mint":"<64hex>","decision":"allow"|"deny",
    /// "findings":[...],"denied":"<name>"|null,"checked_at":<u64>}`.
    pub fn audit_json(&self, checked_at: u64) -> String {
        let mut s = String::from("{\"event\":\"mint_safety_checked\",\"mint\":\"");
        s.push_str(&hex64(&self.mint));
        s.push_str("\",\"decision\":\"");
        s.push_str(if self.allowed() { "allow" } else { "deny" });
        s.push_str("\",\"findings\":[");
        let mut first = true;
        for f in self.findings_iter() {
            if !first {
                s.push(',');
            }
            first = false;
            s.push('"');
            s.push_str(f.name());
            s.push('"');
        }
        s.push_str("],\"denied\":");
        match self.denied() {
            Some(e) => {
                s.push('"');
                s.push_str(e.name());
                s.push('"');
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"checked_at\":");
        s.push_str(&checked_at.to_string());
        s.push('}');
        s
    }
}

impl MintSafetyError {
    /// Stable snake_case name for audit JSON (mirrors the finding names).
    pub fn name(&self) -> &'static str {
        match self {
            MintSafetyError::DefaultAccountStateFrozen => "default_account_state_frozen",
            MintSafetyError::NonTransferable => "non_transferable",
            MintSafetyError::ConfiscatoryTransferFee { .. } => "confiscatory_transfer_fee",
            MintSafetyError::UndisclosedPermanentDelegate => "undisclosed_permanent_delegate",
        }
    }
}

fn hex64(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes.iter() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Run the Token-2022 extension safety gate over a caller-observed mint
/// descriptor. Pure observation — never fails; inspect
/// [`MintSafetyReport::denied`] for the fail-closed decision.
///
/// Check order is fixed (frozen-default → non-transferable → fee →
/// delegate) so the first denial is deterministic.
pub fn check_mint_safety(desc: &MintExtensionDescriptor) -> MintSafetyReport {
    let mut findings: [Option<MintSafetyFinding>; 4] = [None; 4];
    let mut n: u8 = 0;
    let mut push = |f: MintSafetyFinding| {
        findings[n as usize] = Some(f);
        n += 1;
    };
    if desc.default_account_state_frozen {
        push(MintSafetyFinding::DefaultAccountStateFrozen);
    }
    if desc.non_transferable {
        push(MintSafetyFinding::NonTransferable);
    }
    if let Some(bps) = desc.transfer_fee_bps {
        if bps >= 10_000 {
            push(MintSafetyFinding::ConfiscatoryTransferFee { bps });
        }
    }
    if desc.permanent_delegate.is_some() && !desc.permanent_delegate_disclosed {
        push(MintSafetyFinding::UndisclosedPermanentDelegate);
    }
    MintSafetyReport {
        mint: desc.mint,
        findings,
        finding_count: n,
    }
}

impl Escrow {
    /// Pre-flight Token-2022 extension safety gate: call with the
    /// caller-observed [`MintExtensionDescriptor`] *before*
    /// [`Escrow::initialize`] / [`Escrow::fund`]. Fail-closed — any
    /// escrow-hostile extension is [`EscrowError::UnsafeMint`] (code 250).
    ///
    /// The check is intentionally not persisted on the vault: the mint
    /// bound via [`Escrow::with_mint`] is the on-chain anchor, and the
    /// gate runs before the escrow exists. Emit
    /// [`MintSafetyReport::audit_json`] for the audit trail on both
    /// outcomes.
    pub fn check_mint_safety(
        desc: &MintExtensionDescriptor,
    ) -> Result<MintSafetyReport, EscrowError> {
        let report = check_mint_safety(desc);
        match report.denied() {
            Some(_) => Err(EscrowError::UnsafeMint),
            None => Ok(report),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(mint: [u8; 32]) -> MintExtensionDescriptor {
        MintExtensionDescriptor {
            mint,
            ..MintExtensionDescriptor::default()
        }
    }

    #[test]
    fn clean_mint_is_allowed() {
        let r = check_mint_safety(&clean([0x11; 32]));
        assert!(r.allowed());
        assert_eq!(r.denied(), None);
        assert!(r.require_allowed().is_ok());
        assert_eq!(r.mint(), [0x11; 32]);
        assert_eq!(r.findings_iter().count(), 0);
    }

    #[test]
    fn frozen_default_account_state_denies() {
        let mut d = clean([0x22; 32]);
        d.default_account_state_frozen = true;
        let r = check_mint_safety(&d);
        assert!(!r.allowed());
        assert_eq!(r.denied(), Some(MintSafetyError::DefaultAccountStateFrozen));
        assert_eq!(
            r.require_allowed(),
            Err(MintSafetyError::DefaultAccountStateFrozen)
        );
    }

    #[test]
    fn non_transferable_denies() {
        let mut d = clean([0x33; 32]);
        d.non_transferable = true;
        let r = check_mint_safety(&d);
        assert_eq!(r.denied(), Some(MintSafetyError::NonTransferable));
    }

    #[test]
    fn confiscatory_fee_denies_but_partial_fee_passes() {
        let mut d = clean([0x44; 32]);
        d.transfer_fee_bps = Some(10_000);
        let r = check_mint_safety(&d);
        assert_eq!(
            r.denied(),
            Some(MintSafetyError::ConfiscatoryTransferFee { bps: 10_000 })
        );

        // A partial fee is tolerated (reported nowhere — it is not hostile).
        d.transfer_fee_bps = Some(500);
        let r = check_mint_safety(&d);
        assert!(r.allowed());
    }

    #[test]
    fn undisclosed_permanent_delegate_denies_disclosed_passes() {
        let mut d = clean([0x55; 32]);
        d.permanent_delegate = Some([0x99; 32]);
        d.permanent_delegate_disclosed = false;
        let r = check_mint_safety(&d);
        assert_eq!(
            r.denied(),
            Some(MintSafetyError::UndisclosedPermanentDelegate)
        );

        d.permanent_delegate_disclosed = true;
        let r = check_mint_safety(&d);
        assert!(r.allowed());
    }

    #[test]
    fn allowed_extensions_never_deny() {
        // ConfidentialTransfer (confidential.rs instruction 8) and
        // TransferHook (cpi.rs) are orthogonal to this gate.
        let mut d = clean([0x66; 32]);
        d.confidential_transfer = true;
        d.transfer_hook = true;
        let r = check_mint_safety(&d);
        assert!(r.allowed());
    }

    #[test]
    fn all_findings_collected_first_denial_wins() {
        let d = MintExtensionDescriptor {
            mint: [0x77; 32],
            default_account_state_frozen: true,
            non_transferable: true,
            transfer_fee_bps: Some(10_000),
            permanent_delegate: Some([0x99; 32]),
            permanent_delegate_disclosed: false,
            confidential_transfer: false,
            transfer_hook: false,
        };
        let r = check_mint_safety(&d);
        let names: Vec<&str> = r.findings_iter().map(|f| f.name()).collect();
        assert_eq!(
            names,
            vec![
                "default_account_state_frozen",
                "non_transferable",
                "confiscatory_transfer_fee",
                "undisclosed_permanent_delegate",
            ]
        );
        // Check order is fixed: the frozen default wins the denial.
        assert_eq!(r.denied(), Some(MintSafetyError::DefaultAccountStateFrozen));
    }

    #[test]
    fn audit_json_shapes() {
        let r = check_mint_safety(&clean([0xAB; 32]));
        let j = r.audit_json(1_700_000_000);
        assert!(j.contains("\"event\":\"mint_safety_checked\""));
        assert!(j.contains("\"decision\":\"allow\""));
        assert!(j.contains("\"denied\":null"));
        assert!(j.contains("\"checked_at\":1700000000"));
        assert!(j.contains(&"ab".repeat(32)));

        let mut d = clean([0xCD; 32]);
        d.non_transferable = true;
        d.permanent_delegate = Some([0x99; 32]);
        let j = check_mint_safety(&d).audit_json(42);
        assert!(j.contains("\"decision\":\"deny\""));
        assert!(j.contains("\"non_transferable\""));
        assert!(j.contains("\"undisclosed_permanent_delegate\""));
        assert!(j.contains("\"denied\":\"non_transferable\""));
    }

    #[test]
    fn escrow_preflight_maps_denial_to_unsafe_mint() {
        let mut d = clean([0xEF; 32]);
        d.default_account_state_frozen = true;
        let err = Escrow::check_mint_safety(&d).unwrap_err();
        assert_eq!(err, EscrowError::UnsafeMint);
        assert_eq!(err.code(), 250);

        let ok = Escrow::check_mint_safety(&clean([0xEF; 32])).unwrap();
        assert!(ok.allowed());
    }
}
