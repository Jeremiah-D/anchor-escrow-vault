//! Escrow template library (AV-143 — Solana): a named, versioned,
//! reusable registry of escrow blueprints.
//!
//! Relationship to AV-72: [`EscrowTemplate`](crate::EscrowTemplate) is
//! a client-side *composition helper* — a one-shot validated builder
//! for the four canonical escrow shapes. It is not named, not stored,
//! and not versioned. This module is the *library* on top of it: a
//! persistent registry where a blueprint packs amount, mint,
//! milestone plan, arbiter, fee tier ladder, and vesting curve under a
//! name; every publish mints a new immutable version; and
//! [`TemplateLibrary::from_template`] instantiates one call into a
//! fully-configured [`Escrow`] while bumping the version's use count.
//! Nothing here changes the vault account layout or the Anchor
//! program — like AV-72, the chain only ever sees the composed escrow.
//!
//! Audit: every blueprint records its creator, creation time, version,
//! and use count, so operators can see which template versions are
//! actually originating escrows.
//!
//! Retirement (AV-414): a published version found misconfigured
//! (wrong fee tier, currency, or mint) can be retired by its creator
//! — it stays in history but [`TemplateLibrary::from_template`] will
//! no longer instantiate it, and [`TemplateLibrary::latest`] skips
//! it. Retirement is one-way; corrections publish a new version.
//!
//! Off-chain by design: versioning and usage accounting are keeper/
//! operator state, exactly like the other off-chain registries in this
//! crate.

use std::collections::HashMap;

use crate::{
    Escrow, EscrowError, EscrowTemplate, KindParams, QuorumPolicy, TemplateError, TemplateKind,
    VestingCurve, VestingSchedule,
};

/// The release plan a blueprint packs, in owned form (the AV-72
/// [`KindParams`](crate::KindParams) is borrowed — the library owns
/// its blueprints).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlueprintPlan {
    /// Simple two-party escrow with an optional timelock.
    Auction {
        /// Expiry grace period in seconds (AV-21), `0` for none.
        grace_period_secs: u64,
    },
    /// Deliverable-gated milestone tranches (AV-15), in release order.
    MilestonePlan {
        tranches: Vec<u64>,
    },
    /// Clock-driven periodic payouts (AV-56).
    Subscription {
        period_secs: u64,
        periods: u8,
        per_period: u64,
    },
    /// Dispute-arbitrated escrow (AV-14).
    ArbitratedDispute {
        arbiter: [u8; 32],
        evidence_deadline_secs: Option<u64>,
    },
}

impl BlueprintPlan {
    fn kind(&self) -> TemplateKind {
        match self {
            BlueprintPlan::Auction { .. } => TemplateKind::Auction,
            BlueprintPlan::MilestonePlan { .. } => TemplateKind::MilestonePlan,
            BlueprintPlan::Subscription { .. } => TemplateKind::Subscription,
            BlueprintPlan::ArbitratedDispute { .. } => TemplateKind::ArbitratedDispute,
        }
    }

    fn kind_params(&self) -> KindParams<'_> {
        match self {
            BlueprintPlan::Auction { grace_period_secs } => KindParams::Auction {
                grace_period_secs: *grace_period_secs,
            },
            BlueprintPlan::MilestonePlan { tranches } => KindParams::MilestonePlan { tranches },
            BlueprintPlan::Subscription {
                period_secs,
                periods,
                per_period,
            } => KindParams::Subscription {
                period_secs: *period_secs,
                periods: *periods,
                per_period: *per_period,
            },
            BlueprintPlan::ArbitratedDispute {
                arbiter,
                evidence_deadline_secs,
            } => KindParams::ArbitratedDispute {
                arbiter: *arbiter,
                evidence_deadline_secs: *evidence_deadline_secs,
            },
        }
    }
}

/// One immutable version of a named escrow template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowBlueprint {
    /// Registry name, e.g. `"freelance-milestone-v1"`. Versions share
    /// the name; [`TemplateLibrary::publish`] assigns
    /// [`EscrowBlueprint::version`].
    pub name: String,
    /// 1-based version assigned at publish time. Immutable after.
    pub version: u32,
    /// The release plan.
    pub plan: BlueprintPlan,
    /// The locked amount in base units.
    pub amount: u64,
    /// Expiry is relative: `from_template` sets
    /// `expires_at = now + expires_in_secs`.
    pub expires_in_secs: u64,
    /// Optional SPL token mint binding (AV-16).
    pub mint: Option<[u8; 32]>,
    /// Absolute timelock (AV-27), mutually exclusive with
    /// `relative_timelock_secs`.
    pub timelock: Option<u64>,
    /// Relative timelock (AV-64), mutually exclusive with `timelock`.
    pub relative_timelock_secs: Option<u64>,
    /// Dual-signature activation (AV-12).
    pub dual_sig: bool,
    /// Optional weighted attestor quorum gating `release`.
    pub quorum: Option<QuorumPolicy>,
    /// Opt-in protocol-fee tier ladder (AV-66), as
    /// `(min_amount, bps)` pairs applied via
    /// [`Escrow::with_fee_schedule`]. Empty means the flat default.
    pub fee_tiers: Vec<(u64, u16)>,
    /// Opt-in vesting schedule + unlock curve (AV-13 / AV-90).
    pub vesting: Option<(VestingSchedule, VestingCurve)>,
    // --- audit (assigned / maintained by the library) ---
    /// Who published this version.
    pub creator: [u8; 32],
    /// Unix timestamp of publication.
    pub created_at: u64,
    /// How many escrows were instantiated from this version.
    pub use_count: u64,
    /// Last instantiation time, `None` when never used.
    pub last_used_at: Option<u64>,
    /// Whether this version was retired (AV-414): retired versions
    /// stay in history but can no longer be instantiated. One-way.
    pub retired: bool,
    /// Unix timestamp of retirement, `None` while live.
    pub retired_at: Option<u64>,
}

/// What the library can reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryError {
    /// No template published under this name.
    UnknownTemplate,
    /// The name exists but has no such version.
    UnknownVersion(u32),
    /// The blueprint fails AV-72 combination validation (or its fee
    /// tiers / vesting fail builder validation at publish time).
    InvalidBlueprint(TemplateError),
    /// The blueprint validated at publish but a builder rejected the
    /// instantiation anyway (defensive — unreachable for a published
    /// blueprint with honest inputs).
    InstantiationFailed(EscrowError),
    /// Only the version's recorded creator may retire it (AV-414).
    NotCreator,
    /// The version exists but was retired (AV-414) — it can no longer
    /// be instantiated; publish a new version to correct it.
    RetiredVersion(u32),
}

/// Named, versioned registry of escrow blueprints (AV-143).
#[derive(Debug, Clone, Default)]
pub struct TemplateLibrary {
    /// Name → versions in publish order (`versions[i].version ==
    /// i + 1`).
    templates: HashMap<String, Vec<EscrowBlueprint>>,
}

impl TemplateLibrary {
    /// Empty library.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a blueprint: validate it by instantiating a probe
    /// escrow (dummy parties — the validation is shape-based), then
    /// store it as the next immutable version under `blueprint.name`.
    /// Returns the assigned version. Rejects
    /// [`LibraryError::InvalidBlueprint`] when the configuration is
    /// not buildable, so the library can never hold a template that
    /// `from_template` would fail to instantiate.
    pub fn publish(
        &mut self,
        mut blueprint: EscrowBlueprint,
        creator: [u8; 32],
        at: u64,
    ) -> Result<u32, LibraryError> {
        Self::instantiate(&blueprint, [0x01; 32], [0x02; 32], at)
            .map_err(LibraryError::InvalidBlueprint)?;
        let entry = self.templates.entry(blueprint.name.clone()).or_default();
        let version = entry.len() as u32 + 1;
        blueprint.version = version;
        blueprint.creator = creator;
        blueprint.created_at = at;
        blueprint.use_count = 0;
        blueprint.last_used_at = None;
        blueprint.retired = false;
        blueprint.retired_at = None;
        entry.push(blueprint);
        Ok(version)
    }

    /// Retire one version (AV-414): the template registry's version
    /// governance — a published version found misconfigured (wrong
    /// fee tier, currency, or mint) is taken out of service without
    /// deleting history. Only the version's recorded creator may
    /// retire it (the trust model follows `publish`: caller-supplied
    /// identity, no signature check — this is an off-chain registry).
    /// Unknown name is [`LibraryError::UnknownTemplate`], unknown
    /// version is [`LibraryError::UnknownVersion`]. Retiring an
    /// already-retired version is a silent no-op. The retirement
    /// writes `retired` / `retired_at` only — `use_count` /
    /// `last_used_at` keep the version's history, and escrows already
    /// instantiated from the version are unaffected (they locked the
    /// blueprint at instantiation). One-way: there is no un-retire —
    /// corrections publish a new version.
    pub fn retire(
        &mut self,
        name: &str,
        version: u32,
        caller: [u8; 32],
        at: u64,
    ) -> Result<(), LibraryError> {
        let entry = self
            .templates
            .get_mut(name)
            .ok_or(LibraryError::UnknownTemplate)?;
        let bp = entry
            .iter_mut()
            .find(|b| b.version == version)
            .ok_or(LibraryError::UnknownVersion(version))?;
        if caller != bp.creator {
            return Err(LibraryError::NotCreator);
        }
        // Already retired: nothing to write.
        if bp.retired {
            return Ok(());
        }
        bp.retired = true;
        bp.retired_at = Some(at);
        Ok(())
    }

    /// Look up one version (1-based). `None` for an unknown name or
    /// version. A retired version is still returned: this is the
    /// read-only query, and the caller sees the `retired` flag.
    pub fn get(&self, name: &str, version: u32) -> Option<&EscrowBlueprint> {
        self.templates
            .get(name)?
            .iter()
            .find(|b| b.version == version)
    }

    /// The newest live (non-retired) version of a template, or `None`
    /// when unknown or every version is retired.
    pub fn latest(&self, name: &str) -> Option<&EscrowBlueprint> {
        self.latest_live(name)
    }

    /// The newest live (non-retired) version. Shared by
    /// [`latest`](Self::latest) and [`from_template`](Self::from_template)'s
    /// `None` branch so the two can never drift.
    fn latest_live(&self, name: &str) -> Option<&EscrowBlueprint> {
        self.templates.get(name)?.iter().rev().find(|b| !b.retired)
    }

    /// How many versions exist under `name`.
    pub fn version_count(&self, name: &str) -> usize {
        self.templates.get(name).map_or(0, Vec::len)
    }

    /// Every registered template name.
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.templates.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Instantiate a template into a fully-configured escrow in one
    /// call: build the AV-72 composition from the blueprint, apply the
    /// fee tier ladder and vesting curve, and bump the version's use
    /// count. `version == None` takes the latest live version
    /// (retired versions are skipped; all retired is
    /// [`LibraryError::UnknownTemplate`]). An explicit retired version
    /// is [`LibraryError::RetiredVersion`]. The instantiated escrow
    /// locks the blueprint's version — a later publish under the same
    /// name does not change already-created escrows.
    pub fn from_template(
        &mut self,
        name: &str,
        version: Option<u32>,
        initializer: [u8; 32],
        taker: [u8; 32],
        now: u64,
    ) -> Result<Escrow, LibraryError> {
        let (version, escrow) = {
            let entry = self
                .templates
                .get(name)
                .ok_or(LibraryError::UnknownTemplate)?;
            let bp = match version {
                Some(v) => {
                    let bp = entry
                        .iter()
                        .find(|b| b.version == v)
                        .ok_or(LibraryError::UnknownVersion(v))?;
                    if bp.retired {
                        return Err(LibraryError::RetiredVersion(v));
                    }
                    bp
                }
                None => self
                    .latest_live(name)
                    .ok_or(LibraryError::UnknownTemplate)?,
            };
            (
                bp.version,
                Self::instantiate(bp, initializer, taker, now)
                    .map_err(|e| LibraryError::InstantiationFailed(template_error_to_escrow(e)))?,
            )
        };
        let bp = self
            .templates
            .get_mut(name)
            .and_then(|e| e.iter_mut().find(|b| b.version == version))
            .expect("version resolved above");
        bp.use_count += 1;
        bp.last_used_at = Some(now);
        Ok(escrow)
    }

    /// Build the escrow a blueprint describes. The AV-72 template
    /// validates the *combination* (timelock conflicts, tranche sums,
    /// cadences); the fee ladder and vesting apply on top through the
    /// state machine's own builders, so a blueprint can only produce
    /// configurations the vault understands. Builder rejections after
    /// template validation surface as
    /// [`TemplateError::InvalidConfiguration`] — the variant's
    /// documented purpose.
    fn instantiate(
        bp: &EscrowBlueprint,
        initializer: [u8; 32],
        taker: [u8; 32],
        now: u64,
    ) -> Result<Escrow, TemplateError> {
        let template = EscrowTemplate {
            kind: bp.plan.kind(),
            initializer,
            taker,
            amount: bp.amount,
            expires_at: now.saturating_add(bp.expires_in_secs),
            dual_sig: bp.dual_sig,
            timelock: bp.timelock,
            relative_timelock_secs: bp.relative_timelock_secs,
            quorum: bp.quorum,
            mint: bp.mint,
            kind_params: bp.plan.kind_params(),
        };
        let mut escrow = template.build()?;
        if !bp.fee_tiers.is_empty() {
            escrow = escrow
                .with_fee_schedule(&bp.fee_tiers)
                .map_err(TemplateError::InvalidConfiguration)?;
        }
        if let Some((schedule, curve)) = bp.vesting {
            escrow = escrow
                .with_vesting_curve(schedule, curve)
                .map_err(TemplateError::InvalidConfiguration)?;
        }
        Ok(escrow)
    }
}

/// Project a [`TemplateError`] onto the program error surface for the
/// defensive [`LibraryError::InstantiationFailed`] path (same mapping
/// AV-72's `map_template_error` uses for its program-facing errors).
fn template_error_to_escrow(e: TemplateError) -> EscrowError {
    match e {
        TemplateError::InvalidConfiguration(inner) => inner,
        TemplateError::ZeroAmount => EscrowError::AmountMismatch,
        TemplateError::ConflictingTimelocks | TemplateError::TimelockPastExpiry => {
            EscrowError::InvalidTimelock
        }
        TemplateError::EmptyTranches | TemplateError::TrancheSumMismatch => {
            EscrowError::InvalidMilestones
        }
        TemplateError::InvalidSubscriptionParams => EscrowError::InvalidSubscription,
        TemplateError::MissingArbiter => EscrowError::InvalidArbiter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(i: u8) -> [u8; 32] {
        [i; 32]
    }

    fn milestone_blueprint(name: &str) -> EscrowBlueprint {
        EscrowBlueprint {
            name: name.to_string(),
            version: 0, // assigned by publish
            plan: BlueprintPlan::MilestonePlan {
                tranches: vec![400, 600],
            },
            amount: 1_000,
            expires_in_secs: 86_400,
            mint: None,
            timelock: None,
            relative_timelock_secs: None,
            dual_sig: false,
            quorum: None,
            fee_tiers: vec![(0, 100), (10_000, 25)],
            vesting: None,
            creator: [0; 32],
            created_at: 0,
            use_count: 0,
            last_used_at: None,
            retired: false,
            retired_at: None,
        }
    }

    #[test]
    fn publish_assigns_versions_and_validates() {
        let mut lib = TemplateLibrary::new();
        assert_eq!(lib.publish(milestone_blueprint("gig"), key(1), 1_000), Ok(1));
        assert_eq!(lib.publish(milestone_blueprint("gig"), key(1), 2_000), Ok(2));
        assert_eq!(lib.version_count("gig"), 2);
        let v1 = lib.get("gig", 1).unwrap();
        assert_eq!(v1.creator, key(1));
        assert_eq!(v1.created_at, 1_000);
        assert_eq!(v1.use_count, 0);
        assert_eq!(v1.last_used_at, None);
        assert_eq!(lib.latest("gig").unwrap().version, 2);
        assert_eq!(lib.names(), vec!["gig"]);
    }

    #[test]
    fn publish_rejects_unbuildable_blueprint() {
        let mut lib = TemplateLibrary::new();
        // Tranches do not sum to the amount: AV-72 rejects.
        let mut bad = milestone_blueprint("bad");
        bad.plan = BlueprintPlan::MilestonePlan {
            tranches: vec![400, 500],
        };
        assert!(matches!(
            lib.publish(bad, key(1), 1_000),
            Err(LibraryError::InvalidBlueprint(
                TemplateError::TrancheSumMismatch
            ))
        ));
        assert_eq!(lib.version_count("bad"), 0);
        // Conflicting timelocks: also rejected at publish.
        let mut bad2 = milestone_blueprint("bad2");
        bad2.timelock = Some(5_000);
        bad2.relative_timelock_secs = Some(60);
        assert!(matches!(
            lib.publish(bad2, key(1), 1_000),
            Err(LibraryError::InvalidBlueprint(
                TemplateError::ConflictingTimelocks
            ))
        ));
    }

    #[test]
    fn from_template_builds_and_audits_usage() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        let e = lib
            .from_template("gig", None, key(9), key(10), 5_000)
            .unwrap();
        assert_eq!(e.initializer(), key(9));
        assert_eq!(e.taker(), key(10));
        // expires_at = now + blueprint's relative expiry.
        assert_eq!(e.expires_at(), 5_000 + 86_400);
        // Fee ladder applied from the blueprint.
        assert_eq!(e.fee_schedule().bps_for(5_000), 100);
        assert_eq!(e.fee_schedule().bps_for(50_000), 25);
        let v1 = lib.get("gig", 1).unwrap();
        assert_eq!(v1.use_count, 1);
        assert_eq!(v1.last_used_at, Some(5_000));
        // Pinning a version keeps working after a new publish.
        lib.publish(milestone_blueprint("gig"), key(1), 6_000).unwrap();
        let old = lib.from_template("gig", Some(1), key(9), key(10), 7_000).unwrap();
        assert_eq!(old.expires_at(), 7_000 + 86_400);
        assert_eq!(lib.get("gig", 1).unwrap().use_count, 2);
        assert_eq!(lib.get("gig", 2).unwrap().use_count, 0);
    }

    #[test]
    fn unknown_template_and_version_errors() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        assert_eq!(
            lib.from_template("nope", None, key(1), key(2), 1_000),
            Err(LibraryError::UnknownTemplate)
        );
        assert_eq!(
            lib.from_template("gig", Some(7), key(1), key(2), 1_000),
            Err(LibraryError::UnknownVersion(7))
        );
        assert!(lib.get("gig", 7).is_none());
    }

    #[test]
    fn retire_rejects_non_creator_and_keeps_version_live() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        assert_eq!(
            lib.retire("gig", 1, key(9), 2_000),
            Err(LibraryError::NotCreator)
        );
        let v1 = lib.get("gig", 1).unwrap();
        assert!(!v1.retired);
        assert_eq!(v1.retired_at, None);
        // The version still instantiates.
        lib.from_template("gig", Some(1), key(9), key(10), 3_000)
            .unwrap();
    }

    #[test]
    fn retire_unknown_name_and_version() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        assert_eq!(
            lib.retire("nope", 1, key(1), 2_000),
            Err(LibraryError::UnknownTemplate)
        );
        assert_eq!(
            lib.retire("gig", 7, key(1), 2_000),
            Err(LibraryError::UnknownVersion(7))
        );
        assert!(!lib.get("gig", 1).unwrap().retired);
    }

    #[test]
    fn retire_latest_falls_back_to_previous_live_version() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        lib.publish(milestone_blueprint("gig"), key(1), 2_000).unwrap();
        lib.retire("gig", 2, key(1), 3_000).unwrap();
        // latest() skips the retired v2.
        assert_eq!(lib.latest("gig").unwrap().version, 1);
        // from_template(None) takes the newest live version.
        let e = lib
            .from_template("gig", None, key(9), key(10), 4_000)
            .unwrap();
        assert_eq!(lib.get("gig", 1).unwrap().use_count, 1);
        assert_eq!(lib.get("gig", 2).unwrap().use_count, 0);
        assert_eq!(e.expires_at(), 4_000 + 86_400);
    }

    #[test]
    fn retire_explicit_version_is_refused() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        lib.publish(milestone_blueprint("gig"), key(1), 2_000).unwrap();
        lib.retire("gig", 1, key(1), 3_000).unwrap();
        assert_eq!(
            lib.from_template("gig", Some(1), key(9), key(10), 4_000),
            Err(LibraryError::RetiredVersion(1))
        );
        // The live v2 still instantiates by pin and by latest.
        lib.from_template("gig", Some(2), key(9), key(10), 4_000)
            .unwrap();
        lib.from_template("gig", None, key(9), key(10), 5_000)
            .unwrap();
        assert_eq!(lib.get("gig", 2).unwrap().use_count, 2);
    }

    #[test]
    fn retire_all_versions_blocks_latest_and_none() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        lib.retire("gig", 1, key(1), 2_000).unwrap();
        assert!(lib.latest("gig").is_none());
        assert_eq!(
            lib.from_template("gig", None, key(9), key(10), 3_000),
            Err(LibraryError::UnknownTemplate)
        );
        // History is still queryable: counts and names include it.
        assert_eq!(lib.version_count("gig"), 1);
        assert_eq!(lib.names(), vec!["gig"]);
        let v1 = lib.get("gig", 1).unwrap();
        assert!(v1.retired);
        assert_eq!(v1.retired_at, Some(2_000));
    }

    #[test]
    fn retire_twice_is_a_silent_noop() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        lib.retire("gig", 1, key(1), 2_000).unwrap();
        lib.retire("gig", 1, key(1), 3_000).unwrap();
        // The first retirement timestamp stands: the second call
        // writes nothing.
        let v1 = lib.get("gig", 1).unwrap();
        assert!(v1.retired);
        assert_eq!(v1.retired_at, Some(2_000));
    }

    #[test]
    fn retire_keeps_usage_history_and_get_visible() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        lib.from_template("gig", None, key(9), key(10), 2_000)
            .unwrap();
        lib.retire("gig", 1, key(1), 3_000).unwrap();
        let v1 = lib.get("gig", 1).unwrap();
        assert!(v1.retired);
        assert_eq!(v1.retired_at, Some(3_000));
        // History is preserved, not wiped.
        assert_eq!(v1.use_count, 1);
        assert_eq!(v1.last_used_at, Some(2_000));
        assert_eq!(v1.creator, key(1));
        assert_eq!(v1.created_at, 1_000);
        assert_eq!(lib.version_count("gig"), 1);
    }

    #[test]
    fn retire_then_publish_new_version_still_works() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        lib.retire("gig", 1, key(1), 2_000).unwrap();
        // Corrections publish a new version; versions keep
        // self-incrementing and the new one is live.
        assert_eq!(lib.publish(milestone_blueprint("gig"), key(1), 3_000), Ok(2));
        let v2 = lib.get("gig", 2).unwrap();
        assert!(!v2.retired);
        assert_eq!(v2.retired_at, None);
        assert_eq!(lib.latest("gig").unwrap().version, 2);
        lib.from_template("gig", None, key(9), key(10), 4_000)
            .unwrap();
        assert_eq!(lib.get("gig", 2).unwrap().use_count, 1);
        // The retired v1 stays refused even after the new publish.
        assert_eq!(
            lib.from_template("gig", Some(1), key(9), key(10), 4_000),
            Err(LibraryError::RetiredVersion(1))
        );
    }

    #[test]
    fn retire_is_scoped_to_one_name() {
        let mut lib = TemplateLibrary::new();
        lib.publish(milestone_blueprint("gig"), key(1), 1_000).unwrap();
        lib.publish(milestone_blueprint("other"), key(2), 1_000)
            .unwrap();
        lib.retire("gig", 1, key(1), 2_000).unwrap();
        assert!(lib.get("gig", 1).unwrap().retired);
        assert!(!lib.get("other", 1).unwrap().retired);
        assert_eq!(lib.latest("other").unwrap().version, 1);
        lib.from_template("other", None, key(9), key(10), 3_000)
            .unwrap();
    }

    #[test]
    fn publish_resets_retired_flags_on_the_input() {
        let mut lib = TemplateLibrary::new();
        // A caller reusing a retired blueprint struct must not smuggle
        // the flags into the fresh version: publish owns them.
        let mut bp = milestone_blueprint("gig");
        bp.retired = true;
        bp.retired_at = Some(9_999);
        assert_eq!(lib.publish(bp, key(1), 1_000), Ok(1));
        let v1 = lib.get("gig", 1).unwrap();
        assert!(!v1.retired);
        assert_eq!(v1.retired_at, None);
    }

    #[test]
    fn arbitrated_blueprint_binds_arbiter() {
        let mut lib = TemplateLibrary::new();
        let mut bp = milestone_blueprint("dispute");
        bp.plan = BlueprintPlan::ArbitratedDispute {
            arbiter: key(42),
            evidence_deadline_secs: Some(3_600),
        };
        lib.publish(bp, key(1), 1_000).unwrap();
        let e = lib
            .from_template("dispute", None, key(9), key(10), 5_000)
            .unwrap();
        assert_eq!(e.arbiter(), Some(key(42)));
    }
}
